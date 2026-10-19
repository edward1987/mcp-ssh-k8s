import { randomUUID } from "node:crypto";

export const DEFAULT_ALLOWLIST = [
  "ls", "cat", "head", "tail", "grep", "df", "du", "free", "uptime", "whoami", "id", "hostname",
  "uname", "date", "ps", "top -bn1", "ss", "netstat", "ip addr", "ip route", "lsblk", "stat", "wc",
  "systemctl status", "systemctl is-active", "systemctl list-units", "journalctl",
  "docker ps", "docker logs", "docker images", "docker stats --no-stream", "docker inspect",
];

// Anything that could chain, redirect, substitute or smuggle a second command.
const FORBIDDEN = /[;&|<>`$(){}\\\n\r]/;
// Flags that turn otherwise-harmless allowlisted commands into writers/executors.
const DANGEROUS_FLAGS = /(^|\s)(-exec|-delete|--output|-o\s|--follow-up|--vacuum)/;

export function checkReadOnly(command: string, allowlist: string[]): { ok: true } | { ok: false; reason: string } {
  const cmd = command.trim();
  if (!cmd) return { ok: false, reason: "empty command" };
  if (FORBIDDEN.test(cmd)) return { ok: false, reason: "shell metacharacters are not allowed in read-only mode" };
  if (DANGEROUS_FLAGS.test(cmd)) return { ok: false, reason: "flag not allowed in read-only mode" };
  const tokens = cmd.split(/\s+/);
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
      this.items.set(id, { ...p, id, created: Date.now(), resolve: done });
    });
  }

  decide(id: string, d: "approved" | "denied"): boolean {
    const it = this.items.get(id);
    if (!it) return false;
    it.resolve(d);
    return true;
  }

  denyAll() {
    for (const it of [...this.items.values()]) it.resolve("denied");
  }
}
