import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse } from "yaml";
import type { ExecResult } from "../ssh/exec.js";
import type { Mode } from "../vault/store.js";

const emergencyStops = new Set<() => void>();
/** Best-effort synchronous cleanup before an integrity-triggered process exit. */
export function stopKubectlExecutions() { for (const stop of [...emergencyStops]) { try { stop(); } catch {} } }

// ---- kubeconfig upload ----

export interface KubeconfigInfo {
  contexts: string[];
  currentContext?: string;
  servers: string[];
  /** Always empty: executable credential helpers are forbidden on this multi-user server. */
  execCommands: string[];
}

/** Validate an uploaded kubeconfig and summarise it. Throws a readable error if it cannot work from the vault. */
export function inspectKubeconfig(text: string): KubeconfigInfo {
  let doc: any;
  try {
    doc = parse(text);
  } catch (e) {
    throw new Error("not valid YAML: " + (e as Error).message.split("\n")[0]);
  }
  if (!doc || typeof doc !== "object" || !Array.isArray(doc.clusters) || !Array.isArray(doc.contexts) || !Array.isArray(doc.users))
    throw new Error("not a kubeconfig (needs clusters, contexts and users)");
  if (!doc.contexts.length) throw new Error("kubeconfig has no contexts");

  // Only the file contents are stored, so paths to certs/keys on the original machine would break.
  const refs: string[] = [];
  for (const c of doc.clusters) {
    if (c?.cluster?.["certificate-authority"]) refs.push(`certificate-authority (${c.name})`);
    const endpoint = new URL(String(c?.cluster?.server ?? ""));
    if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.hash || endpoint.search) throw new Error("Kubernetes API servers must use HTTPS without URL credentials");
    if (c?.cluster?.["insecure-skip-tls-verify"]) throw new Error("Kubernetes TLS certificate verification cannot be disabled");
    if (c?.cluster?.["proxy-url"]) throw new Error("Kubeconfig proxy-url is not allowed on this server");
  }
  for (const u of doc.users) {
    if (u?.user?.exec || u?.user?.["auth-provider"]) throw new Error("Executable credential helpers (exec/auth-provider) are not allowed; use an embedded short-lived token or client certificate");
    for (const f of ["client-certificate", "client-key", "tokenFile", "token-file"]) if (u?.user?.[f]) refs.push(`${f} (${u.name})`);
  }
  if (refs.length)
    throw new Error(`kubeconfig references local files instead of embedding them: ${refs.join(", ")}. Export a self-contained one with: kubectl config view --raw --flatten`);

  return {
    contexts: doc.contexts.map((c: any) => String(c.name)),
    currentContext: doc["current-context"] ? String(doc["current-context"]) : undefined,
    servers: doc.clusters.map((c: any) => String(c?.cluster?.server ?? "")).filter(Boolean),
    execCommands: [],
  };
}

// ---- argument handling ----

/** Split like a POSIX shell (quotes and backslashes) but without ever running a shell. */
export function splitArgs(input: string): string[] {
  const out: string[] = [];
  let cur = "", has = false, q: "'" | '"' | null = null;
  for (let i = 0; i < input.length; i++) {
    const c = input[i];
    if (q === "'") {
      if (c === "'") q = null;
      else cur += c;
    } else if (q === '"') {
      if (c === '"') q = null;
      else if (c === "\\" && (input[i + 1] === '"' || input[i + 1] === "\\")) cur += input[++i];
      else cur += c;
    } else if (c === "'" || c === '"') {
      q = c;
      has = true;
    } else if (/\s/.test(c)) {
      if (cur || has) out.push(cur);
      cur = "";
      has = false;
    } else if (c === "\\" && i + 1 < input.length) {
      cur += input[++i];
    } else cur += c;
  }
  if (q) throw new Error("unterminated quote in arguments");
  if (cur || has) out.push(cur);
  return out;
}

const KNOWN_VERBS = new Set([
  "annotate", "api-resources", "api-versions", "apply", "auth", "autoscale", "certificate", "cluster-info", "cordon", "create", "debug", "delete",
  "describe", "diff", "drain", "events", "exec", "explain", "expose", "get", "label", "logs", "patch", "replace", "rollout", "run", "scale", "set",
  "taint", "top", "uncordon", "version", "wait",
]);
// Interactive/long-running, or able to read the operator's local files or credentials: never offered.
const NEVER_VERBS = new Set(["config", "proxy", "port-forward", "edit", "attach", "plugin", "cp", "kustomize", "completion", "alpha", "options", "help"]);
const READ_ONLY_VERBS = new Set(["get", "describe", "logs", "top", "version", "api-resources", "api-versions", "cluster-info", "explain", "events"]);

// Flags that would point kubectl at another cluster/identity than the one stored in the vault.
const IDENTITY_LONG = new Set([
  "kubeconfig", "token", "server", "certificate-authority", "client-certificate", "client-key", "insecure-skip-tls-verify", "username", "password",
  "as", "as-group", "as-uid", "cluster", "user", "context", "tls-server-name", "proxy-url", "cache-dir", "kuberc",
]);
// Flags that read local files on this PC.
const LOCAL_FILE_LONG = new Set(["from-file", "from-env-file", "patch-file", "kustomize", "output-directory", "profile", "profile-output"]);
const READ_ONLY_BLOCKED_LONG = new Set(["raw", "watch", "watch-only", "follow", "filename", "kustomize"]);

// kubectl's pflag normalizer accepts underscores as hyphens.
const flagName = (a: string) => (a.startsWith("--") ? a.slice(2).split("=")[0].replace(/_/g, "-") : undefined);

export interface Parsed {
  verb: string;
  head: string[]; // arguments before a literal "--"
  args: string[];
}

export function checkKubectl(args: string[], mode: Mode, hasStdin = false): { ok: true; parsed: Parsed } | { ok: false; reason: string } {
  const no = (reason: string) => ({ ok: false as const, reason });
  if (!args.length) return no("empty command");
  if (args.some(a => a.includes("\0"))) return no("NUL bytes are not allowed in arguments");
  const verb = args[0];
  if (verb.startsWith("-")) return no("start with a kubectl subcommand (get, describe, logs, ...); put flags after it");
  if (NEVER_VERBS.has(verb)) return no(`kubectl ${verb} is not available through MCP`);
  if (!KNOWN_VERBS.has(verb)) return no(`unknown kubectl subcommand: ${verb}`);
  // dump writes local files and collects broad cluster state, including pod logs.
  if (verb === "cluster-info" && args.includes("dump")) return no("cluster-info dump is not available through MCP");

  const dd = args.indexOf("--");
  const head = dd < 0 ? args : args.slice(0, dd);

  for (let i = 0; i < head.length; i++) {
    const a = head[i];
    const long = flagName(a);
    // A boolean bundle like -Ashttps://evil hides the global -s server override.
    // Only flags known to consume the entire attached value may have a short suffix.
    if (a.startsWith("-") && !a.startsWith("--") && a.length > 2 && !/^-[nolcvfsk]/.test(a)) return no("combined short flags are not allowed; pass each flag separately");
    if (long && IDENTITY_LONG.has(long)) return no(`--${long} is managed by the vault and cannot be set`);
    if (/^-s/.test(a) && !a.startsWith("--")) return no("-s (server override) is not allowed");
    if (long && LOCAL_FILE_LONG.has(long)) return no(`--${long} accesses local files and is not allowed`);
    if (/^-k/.test(a) && !a.startsWith("--")) return no("-k (kustomize directory) is not allowed");
    if (/(go-template-file|jsonpath-file|custom-columns-file)/.test(a)) return no("template files on this PC are not allowed");
    // Accept only explicit stdin: URL lists can smuggle local files and cause SSRF.
    const isF = a === "-f" || long === "filename" || (!a.startsWith("--") && /^-f./.test(a));
    if (isF) {
      const v = a === "-f" || (long === "filename" && !a.includes("=")) ? head[i + 1] : a.includes("=") ? a.slice(a.indexOf("=") + 1) : a.slice(2);
      if (v !== "-") return no('-f/--filename only accepts "-" (use the manifest parameter)');
      if (v === "-" && !hasStdin) return no('-f - needs the "manifest" parameter');
    }
  }
  if (hasStdin && !head.some((a, i) => (a === "-f" || a === "--filename") && head[i + 1] === "-") && !head.some((a) => a === "--filename=-" || a === "-f-" || a === "-f=-"))
    return no('"manifest" is only used with -f -');

  if (mode === "read-only") {
    if (hasStdin) return no("manifests are not accepted in read-only mode");
    let ok = READ_ONLY_VERBS.has(verb);
    if (verb === "auth") ok = ["can-i", "whoami"].includes(args[1]);
    if (verb === "rollout") ok = ["status", "history"].includes(args[1]);
    if (!ok) return no(`kubectl ${verb}${verb === "auth" || verb === "rollout" ? " " + (args[1] ?? "") : ""} is not allowed in read-only mode`);
    if (dd >= 0) return no('"--" is not allowed in read-only mode');
    for (const a of head.slice(1)) {
      const long = flagName(a);
      if (long && READ_ONLY_BLOCKED_LONG.has(long)) return no(`--${long} is not allowed in read-only mode`);
      if (!a.startsWith("-") && /(^|[,/])secrets?(\.|[,/]|$)/i.test(a)) return no("Secrets cannot be read in read-only mode");
      if (a === "-w" || a === "-f" || /^-f./.test(a)) return no(`${a} is not allowed in read-only mode (no follow/watch/file flags)`);
    }
  }
  return { ok: true, parsed: { verb, head, args } };
}

const hasNamespace = (head: string[]) => head.some((a) => a === "-n" || a === "-A" || a === "--all-namespaces" || /^(-n.|--namespace(=|$))/.test(a));

/** Flags injected right after the subcommand so they stay clear of a trailing `-- cmd` for exec/run. */
export function withDefaults(p: Parsed, opts: { context?: string; namespace?: string; requestTimeoutSec?: number }): string[] {
  const extra: string[] = [];
  if (opts.context) extra.push("--context", opts.context);
  if (opts.namespace && !hasNamespace(p.head)) extra.push("--namespace", opts.namespace);
  if (opts.requestTimeoutSec && !["logs", "exec", "run", "debug", "wait"].includes(p.verb)) extra.push(`--request-timeout=${opts.requestTimeoutSec}s`);
  return [p.args[0], ...extra, ...p.args.slice(1)];
}

// ---- execution ----

export function runKubectl(kubeconfig: string, args: string[], o: { stdin?: string; timeoutSec: number; maxBytes: number }): Promise<ExecResult> {
  // Revalidate stored configs too, including pre-upgrade imports and shared snapshots.
  inspectKubeconfig(kubeconfig);
  if (args.some(a => a.includes("\0"))) throw new Error("NUL bytes are not allowed in arguments");
  const dir = mkdtempSync(join(tmpdir(), "mcp-k8s-"));
  const cfgPath = join(dir, "config");
  let emergencyStop: (() => void) | undefined;
  const cleanup = () => { if (emergencyStop) emergencyStops.delete(emergencyStop); rmSync(dir, { recursive: true, force: true }); };
  return new Promise((resolve, reject) => {
    let out = "", err = "", truncated = false, timedOut = false;
    try {
      writeFileSync(cfgPath, kubeconfig, { mode: 0o600 });
    } catch (e) {
      cleanup();
      return reject(e);
    }
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(process.env.KUBECTL_PATH || "kubectl", ["--cache-dir", join(dir, "cache"), ...args], {
        env: kubectlEnvironment(dir, cfgPath),
        stdio: [o.stdin === undefined ? "ignore" : "pipe", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch (error) { cleanup(); reject(error); return; }
    emergencyStop = () => { try { child.kill('SIGKILL'); } finally { cleanup(); } };
    emergencyStops.add(emergencyStop);
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, o.timeoutSec * 1000);
    const add = (cur: string, chunk: Buffer) => {
      if (cur.length >= o.maxBytes) {
        truncated = true;
        return cur;
      }
      return cur + chunk.toString("utf8");
    };
    child.stdout!.on("data", (d: Buffer) => (out = add(out, d)));
    child.stderr!.on("data", (d: Buffer) => (err = add(err, d)));
    if (o.stdin !== undefined) {
      child.stdin!.on("error", () => {});
      child.stdin!.end(o.stdin);
    }
    child.on("error", (e: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      cleanup();
      reject(e.code === "ENOENT" ? new Error("kubectl not found on the server PC (install it or set KUBECTL_PATH)") : e);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      cleanup();
      resolve({
        stdout: out.slice(0, o.maxBytes),
        stderr: err.slice(0, o.maxBytes),
        exitCode: timedOut ? null : code,
        truncated: truncated || out.length > o.maxBytes || err.length > o.maxBytes,
        timedOut,
      });
    });
  });
}

/** Do not pass the application's environment secrets or host kube preferences to subprocesses. */
export function kubectlEnvironment(dir: string, cfgPath: string): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR,
    HOME: dir, USERPROFILE: dir, TMPDIR: dir, TMP: dir, TEMP: dir,
    KUBECONFIG: cfgPath, KUBECTL_KUBERC: "false", KUBERC: "off", LANG: "C.UTF-8",
  };
}
