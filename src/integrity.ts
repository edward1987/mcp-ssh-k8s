import { readFileSync, watch, type FSWatcher } from 'node:fs';
import { join } from 'node:path';
import { verifyIntegrity } from '../scripts/integrity.mjs';

export class IntegrityMonitor {
  private readonly baseline: string;
  private failed = false;
  private checkedAt = 0;
  private watcher?: FSWatcher;
  private timer?: NodeJS.Timeout;
  constructor(private root: string, private onFailure: () => void) { this.baseline = readFileSync(join(root, 'integrity.json'), 'utf8'); }
  private fail() {
    if (this.failed) return;
    this.failed = true;
    this.stop();
    this.onFailure();
  }
  start() {
    if (this.failed || this.watcher) return;
    try {
      this.watcher = watch(this.root, { recursive: true, persistent: false }, (_event, filename) => {
        if (filename === null) return this.fail();
        const path = String(filename).replace(/\\/g, '/');
        if (/^node_modules\/(?:\.bin|\.vite|\.vitest-cache)(?:\/|$)/.test(path)) return;
        if (/^(?:dist|web|node_modules|runtime)(?:\/|$)/.test(path) || /^(?:integrity\.(?:json|sig|pub)|package(?:-lock)?\.json|mcp-ssh-service\.exe|configure\.ps1|launch\.ps1|stop\.ps1)$/.test(path) || /^scripts(?:$|\/(?:start\.mjs|integrity\.mjs|bootstrap\.mjs|healthcheck\.mjs|termius_dump\.py)$)/.test(path)) this.fail();
      });
      this.watcher.on('error', () => this.fail());
      this.timer = setInterval(() => this.check(true), 5000);
      this.timer.unref();
      this.check(true);
    } catch { this.fail(); }
  }
  stop() { this.watcher?.close(); this.watcher = undefined; if (this.timer) clearInterval(this.timer); this.timer = undefined; }
  check(force = false) {
    if (this.failed) return false;
    if (!force && this.checkedAt && Date.now() - this.checkedAt < 5000) return true;
    this.checkedAt = Date.now();
    // The in-memory baseline cannot be replaced together with files after startup.
    let valid = false;
    try { valid = readFileSync(join(this.root, 'integrity.json'), 'utf8') === this.baseline && verifyIntegrity(this.root, this.baseline); } catch {}
    if (!valid) this.fail();
    return valid;
  }
}
