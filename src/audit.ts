import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";

export interface AuditEntry {
  ts: string;
  client: string;
  host: string;
  action: string;
  command?: string;
  mode?: string;
  outcome: string;
  exitCode?: number | null;
  ms?: number;
}

export class Audit {
  constructor(private path: string) {
    mkdirSync(dirname(path), { recursive: true });
  }
  log(e: Omit<AuditEntry, "ts">) {
    appendFileSync(this.path, JSON.stringify({ ts: new Date().toISOString(), ...e }) + "\n");
  }
  tail(n = 200): AuditEntry[] {
    if (!existsSync(this.path)) return [];
    const lines = readFileSync(this.path, "utf8").trimEnd().split("\n").slice(-n);
    return lines.map((l) => JSON.parse(l)).reverse();
  }
}
