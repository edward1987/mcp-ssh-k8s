import { connect } from "node:net";
import type { Host, Vault } from "./vault/store.js";

export interface HostStatus {
  online: boolean;
  checkedAt: string;
  ms?: number;
  error?: string;
}

/** TCP reachability probe of host:port (no auth, so it never touches the vault's secrets). */
export function probe(host: string, port: number, timeoutMs = 4000): Promise<{ online: boolean; ms?: number; error?: string }> {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const s = connect({ host, port });
    const done = (r: { online: boolean; ms?: number; error?: string }) => {
      s.destroy();
      resolve(r);
    };
    s.setTimeout(timeoutMs, () => done({ online: false, error: "timeout" }));
    s.once("connect", () => done({ online: true, ms: Date.now() - t0 }));
    s.once("error", (e: NodeJS.ErrnoException) => done({ online: false, error: e.code ?? e.message }));
  });
}

/** Tracks which hosts are reachable. Offline hosts are hidden from / refused by the MCP endpoint. */
export class HostMonitor {
  private status = new Map<string, HostStatus>();
  private timer: NodeJS.Timeout | null = null;
  private running: Promise<void> | null = null;

  constructor(private vault: Vault, private intervalMs = 60_000) {}

  /** Unknown (never checked) counts as available, so hosts added after the last sweep still work. */
  isOnline(h: Host): boolean {
    return this.status.get(h.id)?.online ?? true;
  }
  get(h: Host): HostStatus | undefined {
    return this.status.get(h.id);
  }

  get checking() {
    return this.running !== null;
  }

  /** Check every host in parallel. Concurrent calls share one sweep. Callers that must not wait should not await it. */
  check(): Promise<void> {
    if (!this.vault.unlocked) return Promise.resolve();
    return (this.running ??= this.sweep().finally(() => (this.running = null)));
  }

  /** Each host's status is published as soon as its own probe finishes; nothing waits for the slowest one. */
  private async sweep() {
    const hosts = [...this.vault.d.hosts];
    const ids = new Set(hosts.map((h) => h.id));
    for (const id of this.status.keys()) if (!ids.has(id)) this.status.delete(id);
    let on = 0;
    const offline: string[] = [];
    await Promise.all(
      hosts.map(async (h) => {
        const r = await probe(h.hostname, h.port);
        if (!this.vault.unlocked) return; // locked meanwhile: don't repopulate cleared state
        this.status.set(h.id, { ...r, checkedAt: new Date().toISOString() });
        if (r.online) on++;
        else offline.push(h.name);
      }),
    );
    console.log(`host check: ${on}/${hosts.length} online${offline.length ? " (offline: " + offline.join(", ") + ")" : ""}`);
  }

  /** Run a sweep now and then periodically while the vault is unlocked. Safe to call repeatedly. */
  start() {
    void this.check().catch(() => {});
    if (this.timer) return;
    this.timer = setInterval(() => void this.check().catch(() => {}), this.intervalMs);
    this.timer.unref();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.status.clear();
  }
}
