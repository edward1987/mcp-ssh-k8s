import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createServer } from 'node:net';
import type { Server } from 'node:http';
import { IdentityStore, randomToken } from '../src/auth/store.js';
import { OAuthProvider } from '../src/auth/oauth.js';
import { VaultRegistry } from '../src/vault/registry.js';
import { sha256 } from '../src/vault/store.js';
import { startAdmin } from '../src/admin/server.js';
import { TunnelManager } from '../src/tunnel/manager.js';
import { WebTunnelManager } from '../src/tunnel/web.js';
import { CloudflareSetup } from '../src/tunnel/cloudflare.js';
import { Audit } from '../src/audit.js';
import { Approvals } from '../src/policy/policy.js';
import { setupHelper } from '../src/import/termiusLocal.js';

vi.mock('../src/import/termiusLocal.js', async importOriginal => ({
  ...await importOriginal<typeof import('../src/import/termiusLocal.js')>(),
  helperReady: () => false,
  setupHelper: vi.fn(async () => {}),
}));

let dir: string, base: string, server: Server, store: IdentityStore, registry: VaultRegistry, tunnel: TunnelManager;
const cookies: Record<string, string> = {};
beforeEach(async () => {
  vi.clearAllMocks();
  dir = mkdtempSync(join(tmpdir(), 'instance-admin-'));
  store = new IdentityStore(dir); registry = new VaultRegistry(dir, store);
  for (const id of ['admin', 'member']) {
    store.put('user', id, { id, name: id, role: id === 'admin' ? 'administrator' : 'member', disabled: false, password: 'test', secret: 'test', recovery: [], counter: -1 });
    const token = randomToken(); cookies[id] = 'identity=' + token;
    store.put('session', sha256(token), { id: sha256(token), userId: id, csrf: 'csrf-' + id, expires: Date.now() + 60000, idle: Date.now() + 60000 });
  }
  const reserve = createServer(); await new Promise<void>(r => reserve.listen(0, '127.0.0.1', r));
  const port = (reserve.address() as any).port; await new Promise<void>(r => reserve.close(() => r()));
  base = 'http://127.0.0.1:' + port;
  tunnel = new TunnelManager(registry.legacy, dir, 7778, store);
  const ctx = { identities: store, registry, vault: registry.facade(), approvals: new Approvals(), audit: new Audit(join(dir, 'audit.jsonl'), true) };
  server = startAdmin(ctx, port, resolve('web'), tunnel, { dataDir: dir, scriptsDir: resolve('scripts'), mcpPort: 7778, bridgePath: resolve('dist/mcp/stdio.js'), oauth: new OAuthProvider(store, new URL(base), new URL(base + '/mcp')) });
  if (!server.listening) await new Promise<void>(r => server.once('listening', r));
});
afterEach(async () => {
  server.closeAllConnections(); await new Promise<void>(r => server.close(() => r()));
  registry.lockAll(); store.db.close(); rmSync(dir, { recursive: true, force: true });
});
const request = (path: string, user = 'admin', body?: Record<string, string>, origin?: string) => fetch(base + path, {
  method: body ? 'POST' : 'GET', redirect: 'manual',
  headers: { Cookie: cookies[user] ?? '', ...(body ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}), ...(origin ? { Origin: origin } : {}) },
  body: body ? new URLSearchParams(body) : undefined,
});

it('rejects non-admin direct access to every infrastructure control without executing installers', async () => {
  const install = vi.spyOn(tunnel, 'install').mockResolvedValue(undefined);
  expect((await request('/identity/admin', 'anonymous')).status).toBe(401);
  expect((await request('/identity/admin', 'member')).status).toBe(403);
  expect((await request('/identity/admin/tls', 'member')).status).toBe(403);
  for (const path of ['tunnel/configure', 'tunnel/start', 'tunnel/stop', 'tunnel/install', 'software/termius', 'web-tunnel/configure', 'web-tunnel/start', 'web-tunnel/stop', 'web-tunnel/install', 'cloudflare/connect', 'cloudflare/provision']) {
    expect((await request('/identity/admin/' + path, 'member', { csrf: 'csrf-member', confirm: 'yes' })).status).toBe(403);
  }
  expect(install).not.toHaveBeenCalled(); expect(setupHelper).not.toHaveBeenCalled();
});

it('requires CSRF for Cloudflare operations, serializes setup and exposes the token creation link without credentials', async () => {
  let finish!: () => void;
  const provision = vi.spyOn(CloudflareSetup.prototype, 'provision').mockImplementation(() => new Promise<void>(r => { finish = r; }));
  const connect = vi.spyOn(CloudflareSetup.prototype, 'connect').mockResolvedValue(undefined);
  try {
    const body = { csrf: 'csrf-admin', zoneId: 'a'.repeat(32), subdomain: 'mcp', autoStart: 'yes' };
    expect((await request('/identity/admin/cloudflare/provision', 'admin', { ...body, csrf: 'wrong' })).status).toBe(403);
    expect((await request('/identity/admin/cloudflare/connect', 'admin', { secret: 'DO-NOT-LEAK' })).status).toBe(403);
    expect(provision).not.toHaveBeenCalled(); expect(connect).not.toHaveBeenCalled();
    expect((await request('/identity/admin/cloudflare/provision', 'admin', body)).status).toBe(302);
    expect(provision).toHaveBeenCalledWith({ zoneId: body.zoneId, subdomain: 'mcp', autoStart: true });
    expect((await request('/identity/admin/cloudflare/provision', 'admin', body)).status).toBe(409);
    expect((await request('/identity/admin/cloudflare/connect', 'admin', { csrf: 'csrf-admin', secret: 'DO-NOT-LEAK' })).status).toBe(409);
    expect((await request('/identity/admin/web-tunnel/configure', 'admin', { csrf: 'csrf-admin' })).status).toBe(409);
    const page = await (await request('/identity/admin')).text();
    expect(page).toContain('permissionGroupKeys='); expect(page).toContain('Creeaza si conecteaza'); expect(page).not.toContain('DO-NOT-LEAK');
    finish(); await new Promise<void>(r => setImmediate(r));
    expect(await (await request('/identity/admin')).text()).toContain('Cloudflare configurat');
  } finally { finish?.(); provision.mockRestore(); connect.mockRestore(); }
});

it('does not expose raw Cloudflare exceptions in administrator jobs', async () => {
  const connect = vi.spyOn(CloudflareSetup.prototype, 'connect').mockRejectedValue(new Error('PRIVATE-API-SECRET'));
  try {
    expect((await request('/identity/admin/cloudflare/connect', 'admin', { csrf: 'csrf-admin', secret: 'PRIVATE-API-SECRET' })).status).toBe(302);
    const page = await (await request('/identity/admin')).text();
    expect(page).toContain('Conectarea Cloudflare a esuat'); expect(page).not.toContain('PRIVATE-API-SECRET');
  } finally { connect.mockRestore(); }
});

it('manages Gemini and Claude web transport with locked vaults, CSRF and encrypted configuration', async () => {
  const path = '/identity/admin/web-tunnel/configure';
  const config = { csrf: 'csrf-admin', origin: 'https://mcp.example.com', token: 'private-cloudflare-token-with-enough-length', autoStart: 'yes' };
  expect((await request(path, 'admin', { ...config, csrf: 'wrong' })).status).toBe(403);
  expect((await request(path, 'admin', { ...config, origin: 'http://unsafe.example.com' })).status).toBe(400);
  expect((await request(path, 'admin', config)).status).toBe(302);
  expect(JSON.stringify(store.get('runtime', 'web-tunnel'))).not.toContain(config.token);
  const page = await (await request('/identity/admin')).text();
  expect(page).toContain('Gemini Web'); expect(page).toContain('Claude Web'); expect(page).toContain('Reporneste aplicatia'); expect(page).not.toContain(config.token);
  expect(registry.get('admin').unlocked).toBe(false);
  expect((await request('/identity/admin/web-tunnel/start', 'admin', { csrf: 'csrf-admin' })).status).toBe(400);
  expect((await request(path, 'admin', { ...config, token: '', autoStart: '' })).status).toBe(302);
  expect(store.get<any>('runtime', 'web-tunnel')?.autoStart).toBe(false);
});

it('protects and serializes installation of the web runtime', async () => {
  const install = vi.spyOn(WebTunnelManager.prototype, 'install').mockResolvedValue(undefined);
  try {
    const path = '/identity/admin/web-tunnel/install';
    expect((await request(path, 'admin', { csrf: 'csrf-admin' })).status).toBe(400);
    expect(install).not.toHaveBeenCalled();
    expect((await request(path, 'admin', { csrf: 'csrf-admin', confirm: 'yes' })).status).toBe(302);
    expect(install).toHaveBeenCalledOnce();
  } finally { install.mockRestore(); }
});

it('manages the encrypted instance configuration with all personal vaults locked', async () => {
  expect(registry.get('admin').unlocked).toBe(false);
  const page = await request('/identity/admin'); expect(page.status).toBe(200);
  expect(await page.text()).toContain('Componente instalate pe server / container');
  expect((await request('/identity/admin/tunnel/configure', 'admin', { csrf: 'csrf-admin', tunnelId: 'tunnel_test123', apiKey: 'RUNTIME-SECRET', autoStart: 'yes' })).status).toBe(302);
  expect(registry.get('admin').unlocked).toBe(false);
  expect(JSON.stringify(store.get('runtime', 'tunnel'))).not.toContain('RUNTIME-SECRET');
  const body = await (await request('/identity/admin')).text();
  expect(body).toContain('tunnel_test123'); expect(body).not.toContain('RUNTIME-SECRET');
  const start = vi.spyOn(tunnel, 'start').mockImplementation(() => {});
  expect((await request('/identity/admin/tunnel/start', 'admin', { csrf: 'csrf-admin' })).status).toBe(302);
  expect(start).toHaveBeenCalledOnce();
});

it('requires valid CSRF, origin and installation acknowledgement and serializes background jobs', async () => {
  let finish!: () => void;
  const install = vi.spyOn(tunnel, 'install').mockImplementation(() => new Promise<void>(r => { finish = r; }));
  const path = '/identity/admin/tunnel/install';
  expect((await request(path, 'admin', { confirm: 'yes' })).status).toBe(403);
  expect((await request(path, 'admin', { csrf: 'wrong', confirm: 'yes' })).status).toBe(403);
  expect((await request(path, 'admin', { csrf: 'csrf-admin', confirm: 'yes' }, 'https://untrusted.example')).status).toBe(403);
  expect((await request(path, 'admin', { csrf: 'csrf-admin' })).status).toBe(400);
  expect((await request(path)).status).toBe(404);
  expect(install).not.toHaveBeenCalled();
  try {
    expect((await request(path, 'admin', { csrf: 'csrf-admin', confirm: 'yes' }, base)).status).toBe(302);
    expect(install).toHaveBeenCalledOnce();
    expect((await request(path, 'admin', { csrf: 'csrf-admin', confirm: 'yes' })).status).toBe(409);
    expect((await request('/identity/admin/software/termius', 'admin', { csrf: 'csrf-admin', confirm: 'yes' })).status).toBe(409);
    expect(await (await request('/identity/admin')).text()).toContain('Instalare în curs');
    expect(setupHelper).not.toHaveBeenCalled();
  } finally { finish(); await new Promise<void>(r => setImmediate(r)); }
  expect(await (await request('/identity/admin')).text()).toContain('Instalare finalizată');
});

it('disables legacy installers and denies server-side filesystem imports to members', async () => {
  const install = vi.spyOn(tunnel, 'install').mockResolvedValue(undefined);
  for (const path of ['/api/tunnel', '/api/tunnel/install', '/api/import/termius-local/setup']) {
    expect((await request(path, 'admin', {})).status).toBe(410);
    expect((await request(path, 'member', {})).status).toBe(403);
  }
  expect((await request('/api/import/sshconfig', 'member', {})).status).toBe(403);
  expect(install).not.toHaveBeenCalled(); expect(setupHelper).not.toHaveBeenCalled();
});

it('reports failed background installations without exposing subprocess output or secrets', async () => {
  vi.spyOn(tunnel, 'install').mockRejectedValue(new Error('PRIVATE-SECRET from installer stderr'));
  expect((await request('/identity/admin/tunnel/install', 'admin', { csrf: 'csrf-admin', confirm: 'yes' })).status).toBe(302);
  const body = await (await request('/identity/admin')).text();
  expect(body).toContain('Instalarea a eșuat'); expect(body).not.toContain('PRIVATE-SECRET');
});

it('allows personal CSV imports but rejects a forged server key path before changing the vault', async () => {
  const setup = await fetch(base + '/api/setup', { method: 'POST', headers: { Cookie: cookies.member, 'Content-Type': 'application/json' }, body: JSON.stringify({ password: 'member master password' }) });
  expect(setup.status).toBe(200);
  const { csrf } = await setup.json() as any;
  const sid = setup.headers.get('set-cookie')!.split(';')[0];
  const commit = (hosts: unknown[]) => fetch(base + '/api/import/commit', { method: 'POST', headers: { Cookie: cookies.member + '; ' + sid, 'Content-Type': 'application/json', 'x-csrf-token': csrf }, body: JSON.stringify({ hosts }) });
  const csvHost = { name: 'Personal CSV host', hostname: '10.0.0.5', port: 22, user: 'deploy', password: 'personal-secret' };
  const denied = await commit([csvHost, { ...csvHost, name: 'Forged import', identityFile: join(dir, 'identity', 'identity.key') }]);
  expect(denied.status).toBe(400); expect(await denied.text()).toContain('requires an administrator');
  expect(registry.get('member').d.hosts).toEqual([]);
  expect((await commit([csvHost])).status).toBe(200);
  expect(registry.get('member').d.hosts[0].name).toBe('Personal CSV host');
});


it('redirects immediately while domains reload and refreshes progress until completion', async () => {
  let finish!: () => void;
  const connect = vi.spyOn(CloudflareSetup.prototype, 'connect').mockImplementation(() => new Promise<void>(resolve => { finish = resolve; }));
  try {
    const response = await request('/identity/admin/cloudflare/connect', 'admin', { csrf: 'csrf-admin', secret: 'synthetic-credential' });
    expect(response.status).toBe(302);
    const running = await request('/identity/admin');
    expect(running.headers.get('refresh')).toBe('3');
    expect(await running.text()).toContain('<progress');
    expect((await request('/identity/admin/cloudflare/connect', 'admin', { csrf: 'csrf-admin' })).status).toBe(409);
    finish(); await new Promise<void>(resolve => setImmediate(resolve));
    const completed = await request('/identity/admin');
    expect(completed.headers.get('refresh')).toBeNull();
    expect(await completed.text()).toContain('Cont Cloudflare conectat');
  } finally { finish?.(); connect.mockRestore(); }
});
