import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { Vault } from '../src/vault/store.js';
const dirs: string[] = [], vaults: Vault[] = [];
const vault = () => { const dir = mkdtempSync(join(tmpdir(), 'idle-lock-')); dirs.push(dir); const v = new Vault(join(dir, 'vault.json')); vaults.push(v); return v; };
afterEach(() => { for (const v of vaults.splice(0)) v.lock(); vi.useRealTimers(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
it('defaults to ten minutes and locks even when background status/data reads continue', async () => {
  const v = vault(); await v.create('idle lock test password');
  vi.useFakeTimers(); v.touch();
  expect(v.d.settings.autoLockMinutes).toBe(10);
  for (let i = 0; i < 9; i++) { vi.advanceTimersByTime(60000); expect(v.unlocked).toBe(true); void v.d; void v.idleExpiresAt; }
  vi.advanceTimersByTime(60000);
  expect(v.unlocked).toBe(false); expect(v.idleExpiresAt).toBeNull(); expect(() => v.d).toThrow('locked');
});
it('resets only the active vault and preserves configurable settings across unlock', async () => {
  const a = vault(), b = vault(); await a.create('idle lock test password'); await b.create('idle lock test password');
  a.d.settings.autoLockMinutes = 2; a.save();
  a.lock(); await a.unlock('idle lock test password'); expect(a.d.settings.autoLockMinutes).toBe(2);
  vi.useFakeTimers(); a.touch(); b.d.settings.autoLockMinutes = 2; b.touch();
  vi.advanceTimersByTime(90000); a.touch(); vi.advanceTimersByTime(30000);
  expect(a.unlocked).toBe(true); expect(b.unlocked).toBe(false);
  vi.advanceTimersByTime(90000); expect(a.unlocked).toBe(false);
});
it('enforces the deadline on access even before a delayed timer callback runs', async () => {
  const v = vault(); await v.create('idle lock test password');
  vi.useFakeTimers(); v.touch(); vi.setSystemTime(Date.now() + 600001);
  v.touch(); expect(v.unlocked).toBe(false);
});
