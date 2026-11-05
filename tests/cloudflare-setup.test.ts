import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { IdentityStore } from '../src/auth/store.js';
import { CloudflareSetup, CLOUDFLARE_TOKEN_URL } from '../src/tunnel/cloudflare.js';
import { cloudflarePanel } from '../src/admin/cloudflare.js';
import type { WebTunnelManager } from '../src/tunnel/web.js';

const zoneId = 'a'.repeat(32), accountId = 'b'.repeat(32), tunnelId = '11111111-2222-4333-8444-555555555555';
const secret = 'private-api-token-1234567890', runToken = 'private-runtime-token-1234567890';
const zone = { id: zoneId, name: 'example.com', status: 'active', account: { id: accountId, name: 'My account' } };
let dir: string, store: IdentityStore, setup: CloudflareSetup, api: ReturnType<typeof vi.fn>, web: any;
let dns: any[], tunnels: any[], fail: string, calls: { path: string; method: string; body: any; headers: any }[];
const response = (result: unknown) => new Response(JSON.stringify({ success: true, result }));
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'cf-setup-')); store = new IdentityStore(dir); dns = []; tunnels = []; fail = ''; calls = [];
  web = { mcpPort: 7778, validateActivation: vi.fn(), status: () => ({ installed: false }), install: vi.fn(async () => {}), configure: vi.fn(), activate: vi.fn(), start: vi.fn() };
  api = vi.fn(async (url: string, init: RequestInit) => {
    const u = new URL(url), path = u.pathname.replace('/client/v4', '');
    const method = init.method!, body = init.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ path, method, body, headers: init.headers });
    expect(u.origin).toBe('https://api.cloudflare.com'); expect(init.redirect).toBe('error');
    if (path.endsWith(fail) && fail) { fail = ''; return new Response('REMOTE-SECRET ' + secret, { status: 403 }); }
    if (path === '/zones') return response([zone]);
    if (path === '/zones/' + zoneId) return response(zone);
    if (path.endsWith('/dns_records')) {
      if (method === 'GET') return response(dns);
      dns.push({ ...body, id: 'dns1' }); return response(dns[0]);
    }
    if (path.endsWith('/cfd_tunnel')) {
      if (method === 'GET') return response(tunnels);
      tunnels.push({ id: tunnelId, name: body.name, remote_config: true }); return response(tunnels[0]);
    }
    if (path.endsWith('/configurations')) return response({});
    if (path.endsWith('/token')) return response(runToken);
    throw new Error('Unexpected route ' + path);
  });
  setup = new CloudflareSetup(store, web as WebTunnelManager, api as any);
});
afterEach(() => { store.db.close(); rmSync(dir, { recursive: true, force: true }); });
const connect = () => setup.connect({ secret, mode: 'token', email: '' });
const provision = (autoStart = true) => setup.provision({ zoneId, subdomain: 'mcp', autoStart });

it('links to the Cloudflare token template and encrypts credentials without exposing them in status', async () => {
  const url = new URL(CLOUDFLARE_TOKEN_URL);
  expect(url.origin).toBe('https://dash.cloudflare.com');
  expect(JSON.parse(url.searchParams.get('permissionGroupKeys')!)).toEqual([{ key: 'argotunnel', type: 'edit' }, { key: 'dns', type: 'edit' }, { key: 'zone', type: 'read' }]);
  await connect(); expect(setup.status().zones).toEqual([zone]);
  expect(JSON.stringify(store.get('runtime', 'cloudflare-api'))).not.toContain(secret);
  expect(JSON.stringify(setup.status())).not.toContain(secret);
  await setup.connect({ secret: '', mode: 'token', email: '' });
  expect(calls[1].headers.Authorization).toBe('Bearer ' + secret);
});
it('supports Global API Key only with email and sends the correct headers', async () => {
  await expect(setup.connect({ secret, mode: 'global', email: '' })).rejects.toThrow(); expect(api).not.toHaveBeenCalled();
  await setup.connect({ secret, mode: 'global', email: 'owner@example.com' });
  expect(calls[0].headers).toMatchObject({ 'X-Auth-Key': secret, 'X-Auth-Email': 'owner@example.com' });
  expect(calls[0].headers.Authorization).toBeUndefined();
});
it('creates the tunnel, configures only the MCP port and DNS, then activates OAuth and starts without restart', async () => {
  await connect(); await provision();
  expect(web.install).toHaveBeenCalledOnce();
  const config = calls.find(c => c.path.endsWith('/configurations'))!;
  expect(config.body).toEqual({ config: { ingress: [{ hostname: 'mcp.example.com', service: 'http://127.0.0.1:7778', originRequest: { httpHostHeader: 'mcp.example.com' } }, { service: 'http_status:404' }] } });
  expect(dns[0]).toMatchObject({ type: 'CNAME', content: tunnelId + '.cfargotunnel.com', proxied: true });
  expect(web.configure).toHaveBeenCalledWith({ origin: 'https://mcp.example.com', token: runToken, autoStart: true });
  expect(web.activate).toHaveBeenCalledOnce(); expect(web.start).toHaveBeenCalledOnce();
  expect(setup.status().managed?.tunnelId).toBe(tunnelId);
  expect(JSON.stringify(setup.status())).not.toContain(runToken);
  await provision(false);
  expect(calls.filter(c => c.path.endsWith('/cfd_tunnel') && c.method === 'POST')).toHaveLength(1);
  expect(calls.filter(c => c.path.endsWith('/dns_records') && c.method === 'POST')).toHaveLength(1);
  expect(web.configure).toHaveBeenLastCalledWith(expect.objectContaining({ autoStart: false }));
});
it('does not overwrite conflicting DNS or persist an unusable managed hostname', async () => {
  await connect(); dns = [{ type: 'A', content: '192.0.2.1', proxied: false }];
  await expect(provision()).rejects.toThrow('inregistrari DNS incompatibile');
  expect(calls.every(c => c.method === 'GET')).toBe(true); expect(web.install).not.toHaveBeenCalled();
  expect(setup.status().managed).toBeUndefined();
});
it('resumes partial setup after a DNS failure without duplicating tunnels or leaking API output', async () => {
  await connect(); fail = '/dns_records'; // Fail preflight first; no resource was changed.
  await expect(provision()).rejects.toThrow('Operatia Cloudflare'); expect(tunnels).toHaveLength(0);
  fail = '/token';
  await expect(provision()).rejects.toThrow('Operatia Cloudflare');
  expect(setup.status().managed?.tunnelId).toBe(tunnelId);
  expect(JSON.stringify(setup.status())).not.toContain(secret);
  await provision(); expect(tunnels).toHaveLength(1); expect(dns).toHaveLength(1);
});
it('recovers an ambiguous create response using its persisted unique tunnel name', async () => {
  await connect(); fail = '/configurations'; await expect(provision()).rejects.toThrow();
  const checkpoint = store.get<any>('runtime', 'cloudflare-managed'); delete checkpoint.tunnelId; store.put('runtime', 'cloudflare-managed', checkpoint);
  await provision(); expect(tunnels).toHaveLength(1); expect(setup.status().managed?.tunnelId).toBe(tunnelId);
});
it('rejects invalid targets and pinned OAuth URLs before any resource mutations', async () => {
  await connect();
  await expect(setup.provision({ zoneId: '../accounts', subdomain: 'mcp', autoStart: false })).rejects.toThrow();
  await expect(setup.provision({ zoneId, subdomain: 'foo.bar', autoStart: false })).rejects.toThrow();
  web.validateActivation.mockImplementation(() => { throw new Error('Pinned URL'); });
  await expect(provision()).rejects.toThrow('AUTH_URL');
  expect(calls.every(c => c.method === 'GET')).toBe(true); expect(web.install).not.toHaveBeenCalled();
});
it('serializes provisioning attempts and credential changes while a job is pending', async () => {
  await connect(); let finish!: () => void;
  web.install.mockImplementation(() => new Promise<void>(r => { finish = r; }));
  const pending = provision();
  for (let i = 0; i < 20 && !finish; i++) await new Promise<void>(r => setImmediate(r));
  expect(finish).toBeTypeOf('function');
  await expect(provision()).rejects.toThrow('deja in curs'); await expect(connect()).rejects.toThrow('deja in curs');
  finish(); await pending; expect(setup.busy).toBe(false);
});


it.each(['/dns_records', '/cfd_tunnel'])('rejects credentials lacking access to %s before saving or mutating resources', async (endpoint) => {
  fail = endpoint;
  await expect(connect()).rejects.toThrow(endpoint === '/dns_records' ? 'DNS / Edit' : 'Cloudflare Tunnel / Edit');
  expect(setup.status().hasCredential).toBe(false);
  expect(calls.every(c => c.method === 'GET')).toBe(true);
  expect(web.install).not.toHaveBeenCalled();
});
it('keeps the submitted form values while initial zone verification is pending', async () => {
  await connect();
  let finish!: () => void;
  const original = api.getMockImplementation()!;
  api.mockImplementation(async (...args: any[]) => {
    if (String(args[0]).endsWith('/zones/' + zoneId)) await new Promise<void>(resolve => { finish = resolve; });
    return original(...args as [string, RequestInit]);
  });
  const pending = setup.provision({ zoneId, subdomain: 'chosen', autoStart: false });
  expect(setup.status().draft).toEqual({ zoneId, subdomain: 'chosen', autoStart: false });
  expect(setup.status().busy).toBe(true);
  const html = cloudflarePanel(setup, 'csrf', true, true);
  expect(html).toContain('value="chosen"');
  expect(html).toContain(`value="${zoneId}" selected`);
  expect(html).not.toContain('value="yes" checked');
  expect(html).toContain('role="status"');
  expect(html).toContain('<progress');
  finish(); await pending;
});
