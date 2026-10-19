import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse } from "yaml";
import type { ExecResult } from "../ssh/exec.js";
import type { Mode } from "../vault/store.js";

// ---- kubeconfig upload ----

export interface KubeconfigInfo {
  contexts: string[];
  currentContext?: string;
  servers: string[];
  /** Credential helpers the kubeconfig will run on this PC (EKS/GKE/AKS style); shown so the operator knows. */
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
  for (const c of doc.clusters) if (c?.cluster?.["certificate-authority"]) refs.push(`certificate-authority (${c.name})`);
  for (const u of doc.users) {
    for (const f of ["client-certificate", "client-key", "tokenFile"]) if (u?.user?.[f]) refs.push(`${f} (${u.name})`);
  }
  if (refs.length)
    throw new Error(`kubeconfig references local files instead of embedding them: ${refs.join(", ")}. Export a self-contained one with: kubectl config view --raw --flatten`);

  return {
    contexts: doc.contexts.map((c: any) => String(c.name)),
    currentContext: doc["current-context"] ? String(doc["current-context"]) : undefined,
    servers: doc.clusters.map((c: any) => String(c?.cluster?.server ?? "")).filter(Boolean),
    execCommands: [...new Set<string>(doc.users.map((u: any) => u?.user?.exec?.command).filter(Boolean).map(String))],
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
const LOCAL_FILE_LONG = new Set(["from-file", "from-env-file", "patch-file", "kustomize"]);
const READ_ONLY_BLOCKED_LONG = new Set(["raw", "watch", "watch-only", "follow", "filename", "kustomize"]);

const flagName = (a: string) => (a.startsWith("--") ? a.slice(2).split("=")[0] : undefined);

export interface Parsed {
  verb: string;
  head: string[]; // arguments before a literal "--"
  args: string[];
}

export function checkKubectl(args: string[], mode: Mode, hasStdin = false): { ok: true; parsed: Parsed } | { ok: false; reason: string } {
  const no = (reason: string) => ({ ok: false as const, reason });
  if (!args.length) return no("empty command");
  const verb = args[0];
  if (verb.startsWith("-")) return no("start with a kubectl subcommand (get, describe, logs, ...); put flags after it");
  if (NEVER_VERBS.has(verb)) return no(`kubectl ${verb} is not available through MCP`);
  if (!KNOWN_VERBS.has(verb)) return no(`unknown kubectl subcommand: ${verb}`);

  const dd = args.indexOf("--");
  const head = dd < 0 ? args : args.slice(0, dd);

  for (let i = 0; i < head.length; i++) {
    const a = head[i];
    const long = flagName(a);
    if (long && IDENTITY_LONG.has(long)) return no(`--${long} is managed by the vault and cannot be set`);
    if (/^-s/.test(a) && !a.startsWith("--")) return no("-s (server override) is not allowed");
    if (long && LOCAL_FILE_LONG.has(long)) return no(`--${long} reads local files and is not allowed`);
    if (/^-k/.test(a) && !a.startsWith("--")) return no("-k (kustomize directory) is not allowed");
    if (/(go-template-file|jsonpath-file|custom-columns-file)/.test(a)) return no("template files on this PC are not allowed");
    // -f is allowed only for stdin ("-") or a URL, never a path on this PC
    const isF = a === "-f" || long === "filename" || (!a.startsWith("--") && /^-f./.test(a));
    if (isF) {
      const v = a === "-f" || (long === "filename" && !a.includes("=")) ? head[i + 1] : a.includes("=") ? a.slice(a.indexOf("=") + 1) : a.slice(2);
      if (v !== "-" && !/^https?:\/\//.test(v ?? "")) return no('-f/--filename only accepts "-" (use the manifest parameter) or an http(s) URL');
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
  const dir = mkdtempSync(join(tmpdir(), "mcp-k8s-"));
  const cfgPath = join(dir, "config");
  const cleanup = () => rmSync(dir, { recursive: true, force: true });
  return new Promise((resolve, reject) => {
    let out = "", err = "", truncated = false, timedOut = false;
    try {
      writeFileSync(cfgPath, kubeconfig, { mode: 0o600 });
    } catch (e) {
      cleanup();
      return reject(e);
    }
    const child = spawn(process.env.KUBECTL_PATH || "kubectl", args, {
      env: { ...process.env, KUBECONFIG: cfgPath, KUBECACHEDIR: join(dir, "cache") },
      stdio: [o.stdin === undefined ? "ignore" : "pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
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
