import type { Audit } from "./audit.js";
import { checkReadOnly, type Approvals } from "./policy/policy.js";
import type { HostMonitor } from "./health.js";
import { checkKubectl, runKubectl, splitArgs, withDefaults } from "./k8s/kubectl.js";
import { runSsh } from "./ssh/exec.js";
import type { Cluster, Host, Vault } from "./vault/store.js";

export interface Ctx {
  vault: Vault;
  audit: Audit;
  approvals: Approvals;
  /** Reachability tracker; offline hosts are hidden from MCP. Optional so tests can omit it. */
  monitor?: HostMonitor;
}

export function findHost(vault: Vault, ref: string): Host {
  const h = vault.d.hosts.find((x) => x.id === ref || x.name.toLowerCase() === ref.toLowerCase());
  if (!h) throw new Error(`unknown host "${ref}" (use list_hosts)`);
  return h;
}

export function findCluster(vault: Vault, ref: string): Cluster {
  const c = vault.d.clusters.find((x) => x.id === ref || x.name.toLowerCase() === ref.toLowerCase());
  if (!c) throw new Error(`unknown cluster "${ref}" (use list_clusters)`);
  return c;
}

export const shq = (s: string) => `'${s.replace(/'/g, `'\''`)}'`;

/** Policy -> (approval) -> ssh -> audit. Returns text for the model. */
export async function runCommand(ctx: Ctx, client: string, ref: string, command: string, timeoutSec = 30, action = "run_command") {
  const { vault, audit, approvals } = ctx;
  vault.touch();
  const host = findHost(vault, ref);
  if (ctx.monitor && !ctx.monitor.isOnline(host)) throw new Error(`host "${host.name}" is offline (use list_hosts for reachable hosts)`);
  const base = { client, host: host.name, action, command, mode: host.mode };

  if (host.mode === "read-only") {
    const r = checkReadOnly(command, host.allowlist);
    if (!r.ok) {
      audit.log({ ...base, outcome: "blocked: " + r.reason });
      throw new Error(`Blocked by read-only policy: ${r.reason}`);
    }
  } else if (host.mode === "approval") {
    const d = await approvals.request({ host: host.name, command, client }, vault.d.settings.approvalTimeoutSec);
    if (d !== "approved") {
      audit.log({ ...base, outcome: d });
      throw new Error(d === "denied" ? "Command was denied by the operator." : "Timed out waiting for operator approval.");
    }
  }

  const t0 = Date.now();
  try {
    const r = await runSsh(vault, host, command, Math.min(Math.max(timeoutSec, 1), 600));
    audit.log({ ...base, outcome: r.timedOut ? "timeout" : "ok", exitCode: r.exitCode, ms: Date.now() - t0 });
    return r;
  } catch (e) {
    audit.log({ ...base, outcome: "error: " + (e as Error).message, ms: Date.now() - t0 });
    throw e;
  }
}

/** kubectl on a stored cluster: same policy -> (approval) -> run -> audit flow as runCommand. `command` is a kubectl argument string. */
export async function runKube(ctx: Ctx, client: string, ref: string, command: string, manifest?: string, timeoutSec = 60, requestTimeoutSec?: number) {
  const { vault, audit, approvals } = ctx;
  vault.touch();
  const cluster = findCluster(vault, ref);
  const text = command.trim().replace(/^kubectl\s+/, "");
  const shown = "kubectl " + text;
  const base = { client, host: "k8s:" + cluster.name, action: "kubectl", command: shown, mode: cluster.mode };

  const args = splitArgs(text);
  const chk = checkKubectl(args, cluster.mode, manifest !== undefined);
  if (!chk.ok) {
    audit.log({ ...base, outcome: "blocked: " + chk.reason });
    throw new Error(`Blocked: ${chk.reason}`);
  }
  if (cluster.mode === "approval") {
    const cut = manifest !== undefined && manifest.length > 20_000;
    const preview = manifest === undefined ? shown : [shown, "--- manifest (stdin) ---", manifest.slice(0, 20_000) + (cut ? "\n... (truncated)" : "")].join("\n");
    const d = await approvals.request({ host: "k8s:" + cluster.name, command: preview, client }, vault.d.settings.approvalTimeoutSec);
    if (d !== "approved") {
      audit.log({ ...base, outcome: d });
      throw new Error(d === "denied" ? "Command was denied by the operator." : "Timed out waiting for operator approval.");
    }
  }

  const t0 = Date.now();
  try {
    const full = withDefaults(chk.parsed, { context: cluster.context, namespace: cluster.namespace, requestTimeoutSec });
    const r = await runKubectl(cluster.kubeconfig, full, { stdin: manifest, timeoutSec: Math.min(Math.max(timeoutSec, 1), 600), maxBytes: vault.d.settings.maxOutputBytes });
    audit.log({ ...base, outcome: r.timedOut ? "timeout" : "ok", exitCode: r.exitCode, ms: Date.now() - t0 });
    return r;
  } catch (e) {
    audit.log({ ...base, outcome: "error: " + (e as Error).message, ms: Date.now() - t0 });
    throw e;
  }
}

export function formatResult(r: Awaited<ReturnType<typeof runCommand>>): string {
  const parts = [`exit code: ${r.exitCode ?? "n/a"}${r.timedOut ? " (timed out)" : ""}${r.truncated ? " (output truncated)" : ""}`];
  if (r.stdout) parts.push("--- stdout ---\n" + r.stdout);
  if (r.stderr) parts.push("--- stderr ---\n" + r.stderr);
  return parts.join("\n");
}
