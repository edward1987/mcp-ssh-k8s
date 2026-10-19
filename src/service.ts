import type { Audit } from "./audit.js";
import { checkReadOnly, type Approvals } from "./policy/policy.js";
import { runSsh } from "./ssh/exec.js";
import type { Host, Vault } from "./vault/store.js";

export interface Ctx {
  vault: Vault;
  audit: Audit;
  approvals: Approvals;
}

export function findHost(vault: Vault, ref: string): Host {
  const h = vault.d.hosts.find((x) => x.id === ref || x.name.toLowerCase() === ref.toLowerCase());
  if (!h) throw new Error(`unknown host "${ref}" (use list_hosts)`);
  return h;
}

export const shq = (s: string) => `'${s.replace(/'/g, `'\''`)}'`;

/** Policy -> (approval) -> ssh -> audit. Returns text for the model. */
export async function runCommand(ctx: Ctx, client: string, ref: string, command: string, timeoutSec = 30, action = "run_command") {
  const { vault, audit, approvals } = ctx;
  vault.touch();
  const host = findHost(vault, ref);
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

export function formatResult(r: Awaited<ReturnType<typeof runCommand>>): string {
  const parts = [`exit code: ${r.exitCode ?? "n/a"}${r.timedOut ? " (timed out)" : ""}${r.truncated ? " (output truncated)" : ""}`];
  if (r.stdout) parts.push("--- stdout ---\n" + r.stdout);
  if (r.stderr) parts.push("--- stderr ---\n" + r.stderr);
  return parts.join("\n");
}
