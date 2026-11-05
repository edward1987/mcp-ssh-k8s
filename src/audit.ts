import { identityContext } from "./auth/context.js";
import { appendFileSync, existsSync, mkdirSync, openSync, readSync, fstatSync, closeSync, chmodSync } from "node:fs";
import { dirname } from "node:path";

export interface AuditEntry {
  ts: string;
  userId?: string;
  clientId?: string;
  client: string;
  host: string;
  action: string;
  command?: string;
  mode?: string;
  outcome: string;
  exitCode?: number | null;
  ms?: number;
}

/** Best-effort redaction of common inline credentials; avoid putting secrets in commands. */
export function redactAudit(value: string): string {
  return value.replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g, "[REDACTED KEY]")
    .replace(/(\b(?:Bearer|Basic)\s+)\S+/gi, "$1[REDACTED]")
    .replace(/((?:--?|\b)(?:password|passwd|token|api[-_]?key|client[-_]?secret|secret|authorization)(?:\s*=\s*|\s+))('[^']*'|"[^"]*"|[^\s;&|]+)/gi, "$1[REDACTED]")
    .replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi, "$1[REDACTED]@")
    .slice(0, 20_000);
}

export class Audit {
  constructor(private path: string, private isolated = false) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    if (process.platform !== 'win32' && existsSync(path)) chmodSync(path, 0o600);
  }
  log(e: Omit<AuditEntry, "ts">) {
    const safe = Object.fromEntries(Object.entries(e).map(([key, value]) => [key, typeof value === 'string' ? redactAudit(value) : value]));
    appendFileSync(this.path, JSON.stringify({ ts: new Date().toISOString(), ...safe, userId: e.userId ?? identityContext.getStore()?.userId, clientId: e.clientId ?? identityContext.getStore()?.clientId }) + "\n", { mode: 0o600 });
  }
  tail(n = 200): AuditEntry[] {
    if (!existsSync(this.path)) return [];
    const fd = openSync(this.path, "r");
    let text: string, offset: number;
    try {
      const size = fstatSync(fd).size, length = Math.min(size, 4 * 1024 * 1024);
      offset = size - length;
      const buffer = Buffer.alloc(length);
      const bytes = readSync(fd, buffer, 0, length, offset);
      text = buffer.subarray(0, bytes).toString("utf8");
    } finally { closeSync(fd); }
    if (offset > 0) text = text.slice(text.indexOf("\n") + 1);
    const lines = text.trimEnd().split("\n").filter(Boolean).slice(-Math.min(1000, Math.max(1, n)));
    return lines.map((l) => JSON.parse(l)).filter((e: AuditEntry) => !this.isolated || e.userId === identityContext.getStore()?.userId).reverse();
  }
}
