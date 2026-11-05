import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawn } from 'node:child_process';
import { IdentityStore } from '../src/auth/store.js';
import { WebTunnelManager, webOrigin } from '../src/tunnel/web.js';
vi.mock('node:child_process', async importOriginal => ({ ...await importOriginal<typeof import('node:child_process')>(), spawn: vi.fn() }));
let dir: string, store: IdentityStore, manager: WebTunnelManager;
const secret = 'a-valid-private-cloudflare-token-1234';
const configure = (autoStart = true) => manager.configure({ origin: 'https://mcp.example.com', token: secret, autoStart });
beforeEach(() => {
  vi.useFakeTimers(); vi.clearAllMocks();
  dir = mkdtempSync(join(tmpdir(), 'web-tunnel-')); store = new IdentityStore(dir);
  manager = new WebTunnelManager(store, dir, 'https://mcp.example.com', 7778);
});
afterEach(() => { manager.stop(); store.db.close(); rmSync(dir, { recursive: true, force: true }); vi.useRealTimers(); vi.unstubAllGlobals(); });
const installed = () => { mkdirSync(dirname(manager.binPath), { recursive: true }); writeFileSync(manager.binPath, 'test'); };
const child = () => { const c = Object.assign(new EventEmitter(), { stderr: new EventEmitter(), kill: vi.fn() }); vi.mocked(spawn).mockReturnValue(c as any); return c; };
it('accepts only HTTPS origins and encrypts tokens, retaining them on blank updates', () => {
  for (const invalid of ['http://host.com', 'https://user:pass@host.com', 'https://host.com/path', 'https://localhost', 'https://127.0.0.1', 'https://host.com/?x=1']) expect(() => webOrigin(invalid)).toThrow();
  configure(); expect(JSON.stringify(store.get('runtime', 'web-tunnel'))).not.toContain(secret);
  manager.configure({ origin: 'https://other.example.com', token: '', autoStart: false });
  expect(manager.status()).toMatchObject({ hasToken: true, autoStart: false, restartRequired: true });
  installed(); expect(() => manager.start()).toThrow(); expect(spawn).not.toHaveBeenCalled();
});
it('honors opt-out, starts with token in environment only, reconnects and cancels retries on stop', () => {
  configure(false); installed(); const c = child(); manager.autoStart(); expect(spawn).not.toHaveBeenCalled();
  configure(true); manager.autoStart();
  expect(spawn).toHaveBeenCalledWith(manager.binPath, ['tunnel', '--no-autoupdate', 'run'], expect.objectContaining({ windowsHide: true, env: expect.objectContaining({ TUNNEL_TOKEN: secret }) }));
  expect(JSON.stringify(vi.mocked(spawn).mock.calls[0][1])).not.toContain(secret);
  c.stderr.emit('data', Buffer.from('Registered tunnel connection'));
  expect(manager.status().connected).toBe(true);
  c.emit('exit', 1); expect(manager.status()).toMatchObject({ running: false, connected: false, reconnecting: true });
  const next = child(); vi.advanceTimersByTime(5000); expect(spawn).toHaveBeenCalledTimes(2);
  next.emit('error', new Error(secret)); next.emit('exit', 1);
  expect(manager.status().lastError).not.toContain(secret);
  manager.stop(); vi.advanceTimersByTime(10000); expect(spawn).toHaveBeenCalledTimes(2);
});
it('refuses missing binaries and reports failed autostart without crashing', () => {
  configure(); expect(() => manager.start()).toThrow(); manager.autoStart(); expect(manager.status().lastError).toBeTruthy();
});
it('blocks automatic connections when an environment override advertises a different MCP endpoint', () => {
  configure(); installed();
  manager = new WebTunnelManager(store, dir, 'https://mcp.example.com', 7778, 'https://another.example.com/mcp');
  expect(manager.status().restartRequired).toBe(true); manager.autoStart(); expect(spawn).not.toHaveBeenCalled();
});
it('installs official release binaries only after verifying their digest', async () => {
  const bytes = Buffer.from('verified test binary');
  const name = `cloudflared-${process.platform === 'win32' ? 'windows' : 'linux'}-${process.arch === 'arm64' ? 'arm64' : 'amd64'}${process.platform === 'win32' ? '.exe' : ''}`;
  const asset = { name, browser_download_url: 'https://github.com/cloudflare/cloudflared/releases/download/test/' + name, digest: 'sha256:' + createHash('sha256').update(bytes).digest('hex') };
  const fetchMock = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ assets: [asset] }))).mockResolvedValueOnce(new Response(bytes));
  vi.stubGlobal('fetch', fetchMock); await manager.install(); expect(existsSync(manager.binPath)).toBe(true);
  asset.digest = 'sha256:' + '0'.repeat(64);
  fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ assets: [asset] }))).mockResolvedValueOnce(new Response(bytes));
  await expect(manager.install()).rejects.toThrow('Checksum mismatch'); expect(manager.status().installing).toBe(false);
});
