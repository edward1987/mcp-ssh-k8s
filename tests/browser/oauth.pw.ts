import { test, expect } from '@playwright/test';
import { createServer as createHttpServer, type Server } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { TOTP, Secret } from 'otpauth';
import { IdentityStore, randomToken } from '../../src/auth/store.js';
import { OAuthProvider } from '../../src/auth/oauth.js';
import { Vault, sha256 } from '../../src/vault/store.js';
import { Audit } from '../../src/audit.js';
import { Approvals } from '../../src/policy/policy.js';
import { startMcp } from '../../src/mcp/server.js';
import { startAdmin } from '../../src/admin/server.js';
import { TunnelManager } from '../../src/tunnel/manager.js';
import { VaultRegistry } from '../../src/vault/registry.js';
import { ShareBroker } from '../../src/vault/shares.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const dir = mkdtempSync(join(tmpdir(), 'oauth-browser-'));
const store = new IdentityStore(dir), vault = new Vault(join(dir, 'vault.json'));
const registry = new VaultRegistry(dir, store);
const servers: Server[] = [];
let provider: OAuthProvider, mcpBase: string, adminBase: string, callbackBase: string, userId: string;
const freePort = async () => {
  const server = createNetServer(); await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;
  await new Promise<void>(resolve => server.close(() => resolve())); return port;
};
const listening = async (server: Server) => { servers.push(server); if (!server.listening) await new Promise<void>(resolve => server.once('listening', resolve)); };
test.beforeAll(async () => {
  const invite = store.invite('oauth-user'), enrollment = store.enrollment(invite);
  await store.activate(invite, 'synthetic oauth test password', new TOTP({ secret: Secret.fromBase32(enrollment.secret) }).generate()); userId = enrollment.u.id;
  const mcpPort = await freePort(), adminPort = await freePort();
  mcpBase = `http://127.0.0.1:${mcpPort}`; adminBase = `http://127.0.0.1:${adminPort}`;
  provider = new OAuthProvider(store, new URL(mcpBase), new URL(mcpBase + '/mcp'));
  const ctx = { identities: store, registry, shares: new ShareBroker(store, registry), vault: registry.facade(), audit: new Audit(join(dir, 'audit.jsonl')), approvals: new Approvals() };
  await listening(startMcp(ctx, mcpPort, '127.0.0.1', provider, { adminPort }));
  await listening(startAdmin(ctx, adminPort, resolve('web'), new TunnelManager(vault, dir, mcpPort), { dataDir: dir, scriptsDir: resolve('scripts'), mcpPort, bridgePath: resolve('dist/mcp/stdio.js'), oauth: provider }));
  const callback = createHttpServer((req, res) => { res.setHeader('Content-Type', 'text/plain'); res.end(req.method === 'GET' ? 'OAuth callback received' : 'Unexpected method'); });
  callback.listen(0, '127.0.0.1'); await listening(callback);
  callbackBase = `http://127.0.0.1:${(callback.address() as { port: number }).port}`;
});
test.beforeEach(async ({ context }) => {
  const raw = randomToken(); store.put('session', sha256(raw), { id: sha256(raw), userId, csrf: 'synthetic-csrf', expires: Date.now() + 60000, idle: Date.now() + 60000 });
  await context.addCookies([{ name: 'identity', value: raw, url: mcpBase, httpOnly: true, sameSite: 'Lax' }]);
});
test.afterAll(async () => {
  for (const server of servers) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
  registry.lockAll(); vault.lock(); store.db.close(); rmSync(dir, { recursive: true, force: true });
});

for (const surface of ['mcp', 'admin'] as const) for (const allow of [true, false]) test(`${surface} consent ${allow ? 'approval' : 'denial'} reaches the client's other origin without a CSP violation`, async ({ page, context }) => {
  const redirect = callbackBase + '/callback?client=desktop', verifier = randomToken(), state = randomToken();
  const client = provider.clientsStore.registerClient({ redirect_uris: [redirect], client_name: 'Browser OAuth regression', token_endpoint_auth_method: 'none' });
  const query = new URLSearchParams({ client_id: client.client_id, redirect_uri: redirect, response_type: 'code', code_challenge_method: 'S256', code_challenge: Buffer.from(sha256(verifier), 'hex').toString('base64url'), scope: 'mcp:use', resource: provider.resource.href, state });
  const begin = await context.request.get(mcpBase + '/authorize?' + query, { maxRedirects: 0 }); expect(begin.status()).toBe(302);
  const pendingId = new URL(begin.headers().location).searchParams.get('request')!;
  const errors: string[] = [];
  page.on('console', message => { if (message.type() === 'error' && message.text().includes('form-action')) errors.push(message.text()); });
  await page.goto((surface === 'mcp' ? mcpBase : adminBase) + '/identity/consent?request=' + pendingId);
  await Promise.all([
    page.waitForURL(url => url.origin === callbackBase && url.pathname === '/callback', { timeout: 5000 }),
    page.getByRole('button', { name: allow ? /^Autorizeaz/ : /^Refuz/ }).click(),
  ]);
  expect(errors).toEqual([]);
  await expect(page.getByText('OAuth callback received')).toBeVisible();
  const result = new URL(page.url()); expect(result.searchParams.get('state')).toBe(state); expect(result.searchParams.get('client')).toBe('desktop');
  if (allow) {
    const exchange = await context.request.post(mcpBase + '/token', { form: { grant_type: 'authorization_code', client_id: client.client_id, code: result.searchParams.get('code')!, code_verifier: verifier, redirect_uri: redirect, resource: provider.resource.href } });
    expect(exchange.status()).toBe(200);
    const tokens = await exchange.json();
    expect((await provider.verifyAccessToken(tokens.access_token)).extra.userId).toBe(userId);
    const mcp = new Client({ name: 'oauth-action-discovery', version: '1' });
    try {
      await mcp.connect(new StreamableHTTPClientTransport(provider.resource, { requestInit: { headers: { Authorization: 'Bearer ' + tokens.access_token } } }));
      expect((await mcp.listTools()).tools).toHaveLength(11);
      const locked = await mcp.callTool({ name: 'list_hosts', arguments: {} });
      expect(locked.isError).toBe(true); expect(JSON.stringify(locked)).toContain(adminBase + '/');
      expect(registry.get(userId).unlocked).toBe(false);
    } finally { await mcp.close(); }
  } else { expect(result.searchParams.get('error')).toBe('access_denied'); expect(result.searchParams.has('code')).toBe(false); }
});

test('the OAuth account vault link and MCP root reach the configured admin UI with the same login', async ({ page, context }) => {
  const root = await context.request.get(mcpBase + '/?next=https://attacker.example', { maxRedirects: 0 });
  expect(root.status()).toBe(303); expect(root.headers().location).toBe(adminBase + '/');
  await page.goto(mcpBase + '/identity/');
  await page.getByRole('link', { name: 'Vault personal', exact: true }).click();
  await expect(page).toHaveURL(adminBase + '/');
  await expect(page.locator('#pw')).toBeVisible();
  const identity = await context.request.get(adminBase + '/identity/me');
  expect((await identity.json()).user.id).toBe(userId);
});

test('the callback exception is limited to one authenticated, active consent page and excludes paths/query input', async ({ context }) => {
  const redirect = callbackBase + '/callback;not-a-csp-directive?example=value';
  const client = provider.clientsStore.registerClient({ redirect_uris: [redirect, 'https://another-client.example/callback'], token_endpoint_auth_method: 'none' });
  let location = '';
  await provider.authorize(client, { redirectUri: redirect, codeChallenge: randomToken(), resource: provider.resource, scopes: ['mcp:use'] }, { redirect(value: string) { location = value; } } as any);
  const id = new URL(location).searchParams.get('request')!;
  for (const base of [mcpBase, adminBase]) {
    const consent = await context.request.get(base + '/identity/consent?request=' + id + '&redirect_uri=https://attacker.example');
    expect(consent.status()).toBe(200);
    const policy = consent.headers()['content-security-policy'];
    expect(policy.split(';').map(part => part.trim())).toContain(`form-action 'self' ${callbackBase}`);
    for (const input of ['another-client.example', 'attacker.example', 'not-a-csp-directive', 'example=value', '*']) expect(policy).not.toContain(input);
    const login = await context.request.get(base + '/identity/login');
    expect(login.headers()['content-security-policy']).toContain("form-action 'self';");
    expect(login.headers()['content-security-policy']).not.toContain(callbackBase);
    expect(login.headers()['content-security-policy']).toContain("default-src 'none'");
    // Neither the callback exception nor a valid request ID replaces CSRF/origin checks.
    expect((await context.request.post(base + '/identity/consent', { form: { request: id, allow: 'yes', csrf: 'wrong' }, maxRedirects: 0 })).status()).toBe(400);
    expect((await context.request.post(base + '/identity/consent', { headers: { Origin: 'https://attacker.example' }, form: { request: id, allow: 'yes', csrf: 'synthetic-csrf' }, maxRedirects: 0 })).status()).toBe(403);
    expect(store.get('pending', id)).toBeDefined();
  }
  const pending = store.get<any>('pending', id); store.put('pending', id, { ...pending, expires: 0 });
  const expired = await context.request.get(mcpBase + '/identity/consent?request=' + id);
  expect(expired.status()).toBe(400); expect(expired.headers()['content-security-policy']).not.toContain(callbackBase);
  await context.clearCookies();
  const anonymous = await context.request.get(mcpBase + '/identity/consent?request=' + id);
  expect(anonymous.status()).toBe(200); expect(anonymous.headers()['content-security-policy']).not.toContain(callbackBase);
});
