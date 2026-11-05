import { randomUUID } from "node:crypto";
import { identityContext } from "../auth/context.js";
import { splitArgs } from "../k8s/kubectl.js";

export const DEFAULT_ALLOWLIST = [
  "ls", "cat", "head", "tail", "grep", "df", "du", "free", "uptime", "whoami", "id", "hostname",
  "uname", "date", "ps", "top -bn1", "ss", "netstat", "ip addr", "ip route", "lsblk", "stat", "wc",
  "systemctl status", "systemctl is-active", "systemctl list-units", "systemctl --failed", "journalctl",
  "last", "w",
  "docker ps", "docker logs", "docker images", "docker stats --no-stream", "docker inspect",
];

// Anything that could chain, redirect, substitute or smuggle a second command.
const FORBIDDEN = /[;&|<>`$(){}\\\n\r]/;
// Flags that turn otherwise-harmless allowlisted commands into writers/executors.
const DANGEROUS_FLAGS = /^(-exec|-delete|--output(?:=|$)|-o$|--follow-up|--vacuum)/;

export function checkReadOnly(command: string, allowlist: string[]): { ok: true } | { ok: false; reason: string } {
  const cmd = command.trim();
  if (!cmd) return { ok: false, reason: "empty command" };
  if (FORBIDDEN.test(cmd)) return { ok: false, reason: "shell metacharacters are not allowed in read-only mode" };
  let tokens: string[];
  try { tokens = splitArgs(cmd); } catch { return { ok: false, reason: "invalid quoting" }; }
  if (tokens.some(t => DANGEROUS_FLAGS.test(t))) return { ok: false, reason: "flag not allowed in read-only mode" };
  const no = () => ({ ok: false as const, reason: "mutating arguments are not allowed in read-only mode" });
  // Several inspection commands also contain setters. Prefix matching alone is insufficient.
  if (tokens[0] === "hostname" && tokens.slice(1).some(t => !/^(-[aAdfiIsvVy]|--(?:alias|all-fqdns|domain|fqdn|ip-address|all-ip-addresses|short|verbose|version|help))$/.test(t))) return no();
  if (tokens[0] === "date" && tokens.slice(1).some(t => !t.startsWith("+") && !/^(-[uRIV]|--(?:utc|universal|rfc-email|iso-8601(?:=.*)?|rfc-3339=.*|version|help))$/.test(t))) return no();
  if (tokens[0] === "uname" && tokens.slice(1).some(t => !/^(-[asnrvmpio]+|--(?:all|kernel-name|nodename|kernel-release|kernel-version|machine|processor|hardware-platform|operating-system|version|help))$/.test(t))) return no();
  if (tokens[0] === "ip" && tokens[2] !== undefined && !(tokens[1] === "addr" ? ["show", "list"] : ["show", "list", "get"]).includes(tokens[2])) return no();
  if (tokens[0] === "ss" && tokens.slice(1).some(t => /^--(?:kill|bpf|diag)(=|$)/.test(t) || /^-[^-]*[KDb]/.test(t))) return no();
  if (tokens[0] === "journalctl" && tokens.slice(1).some(t => /^--(?:rotate|flush|sync|relinquish-var|smart-relinquish-var|setup-keys|update-catalog|vacuum|root|directory|image)/.test(t))) return no();
  const allowed = [...DEFAULT_ALLOWLIST, ...allowlist].some((entry) => {
    const e = entry.trim().split(/\s+/);
    return e.length <= tokens.length && e.every((t, i) => t === tokens[i]);
  });
  return allowed ? { ok: true } : { ok: false, reason: `command not in allowlist: ${tokens[0]}` };
}

export interface Pending {
  id: string;
  host: string;
  command: string;
  client: string;
  userId?: string;
  clientId?: string;
  approvers?: string[];
  shareId?: string;
  created: number;
}

type Decision = "approved" | "denied" | "timeout";

/** Commands waiting for a human decision in the web UI. */
export class Approvals {
  private items = new Map<string, Pending & { resolve: (d: Decision) => void }>();

  list(): Pending[] {
    return [...this.items.values()].map(({ resolve: _r, ...p }) => p);
  }

  request(p: Omit<Pending, "id" | "created">, timeoutSec: number): Promise<Decision> {
    const id = randomUUID();
    return new Promise((resolve) => {
      const done = (d: Decision) => {
        clearTimeout(t);
        this.items.delete(id);
        resolve(d);
      };
      const t = setTimeout(() => done("timeout"), timeoutSec * 1000);
      const identity = identityContext.getStore();
      this.items.set(id, { ...p, userId: identity?.userId, clientId: identity?.clientId, id, created: Date.now(), resolve: done });
    });
  }

  decide(id: string, d: "approved" | "denied"): boolean {
    const it = this.items.get(id);
    if (!it) return false;
    it.resolve(d);
    return true;
  }

  denyShare(shareId: string) { for (const it of [...this.items.values()]) if (it.shareId === shareId) it.resolve("denied"); }

  denyUser(userId: string) { for (const it of [...this.items.values()]) if (it.userId === userId) it.resolve("denied"); }

  denyAll() {
    for (const it of [...this.items.values()]) it.resolve("denied");
  }
}
