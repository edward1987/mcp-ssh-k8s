import { startAdmin } from '../src/admin/server.js';
import { TunnelManager } from '../src/tunnel/manager.js';
import { createServer } from 'node:net';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { Server } from 'node:http';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { TOTP, Secret } from 'otpauth';
import { IdentityStore, randomToken } from '../src/auth/store.js';
import { OAuthProvider } from '../src/auth/oauth.js';
import { identityContext } from '../src/auth/context.js';
import { Vault, sha256 } from '../src/vault/store.js';
import { Audit } from '../src/audit.js';
import { Approvals } from '../src/policy/policy.js';
import { runCommand, runKube } from '../src/service.js';
import { runHostSecurityAudit } from '../src/security.js';
import { startMcp } from '../src/mcp/server.js';
import { CLIENTS, clientSetup } from '../src/clients.js';
import { canonicalUrl } from '../src/auth/web.js';
const dir = mkdtempSync(join(tmpdir(), 'mcp-oauth-'));
const store = new IdentityStore(dir), vault = new Vault(join(dir, 'vault.json'));
const ctx = { identities: store, vault, audit: new Audit(join(dir, 'audit.jsonl')), approvals: new Approvals() };
const provider = new OAuthProvider(store, new URL('http://127.0.0.1:7778'), new URL('http://127.0.0.1:7778/mcp'));
let user: string, other: string, server: Server, endpoint: string, clientInfo: any;
const enroll = async (name: string) => {
  const invitation = store.invite(name), e = store.enrollment(invitation);
  const recovery = await store.activate(invitation, 'password with enough entropy', new TOTP({ secret: Secret.fromBase32(e.secret) }).generate());
  return { id: e.u.id, invitation, recovery };
};
const token = async (id: string) => {
  const verifier = randomToken(), challenge = Buffer.from(sha256(verifier), 'hex').toString('base64url');
  let redirect = '';
  await provider.authorize(clientInfo, { redirectUri: clientInfo.redirect_uris[0], codeChallenge: challenge, resource: provider.resource, scopes: ['mcp:use'], state: 'state' }, { redirect: (s: string) => { redirect = s; } } as any);
  const result = new URL(provider.consent(new URL(redirect).searchParams.get('request')!, id, true));
  return { tokens: await provider.exchangeAuthorizationCode(clientInfo, result.searchParams.get('code')!, verifier, clientInfo.redirect_uris[0], provider.resource), code: result.searchParams.get('code')!, verifier };
};
beforeAll(async () => {
  await vault.create('master password distinct');
  user = (await enroll('alice')).id; other = (await enroll('bob')).id;
  vault.d.hosts.push(...['h1', 'h2'].map(id => ({ id, name: id, hostname: 'invalid', port: 22, user: 'root', auth: 'password' as const, mode: 'approval' as const, allowlist: [] })));
  vault.d.clusters.push({ id: 'c1', name: 'c1', kubeconfig: '', mode: 'approval' });
  vault.d.checklist = [{ hostId: 'h1', addedAt: '' }, { hostId: 'h2', addedAt: '' }];
  store.put('grant', 'g1', { id: 'g1', subject: user, kind: 'user', type: 'host', resource: 'h1' });
  clientInfo = provider.clientsStore.registerClient({ redirect_uris: ['http://127.0.0.1/callback'], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] });
  const reservation = createServer();
  await new Promise<void>(r => reservation.listen(0, '127.0.0.1', r));
  const port = (reservation.address() as { port: number }).port;
  await new Promise<void>(r => reservation.close(() => r()));
  provider.issuer.port = String(port); provider.resource.port = String(port);
  server = startMcp(ctx, port, '127.0.0.1', provider);
  if (!server.listening) await new Promise<void>(r => server.once('listening', r));
  endpoint = `http://127.0.0.1:${(server.address() as { port: number }).port}/mcp`;
  provider.issuer.port = String((server.address() as { port: number }).port);
  provider.resource.port = provider.issuer.port;
});
afterAll(async () => { vault.lock(); if (server) await new Promise<void>(r => server.close(() => r())); store.db.close(); rmSync(dir, { recursive: true, force: true }); });
it('rejects anonymous and legacy credentials and publishes OAuth discovery', async () => {
  for (const bearer of ['', 'mcp_legacy']) {
    const r = await fetch(endpoint, { method: 'POST', headers: bearer ? { Authorization: 'Bearer ' + bearer } : {} });
    expect(r.status).toBe(401); expect(r.headers.get('www-authenticate')).toContain('resource_metadata');
  }
  expect((await fetch(endpoint.replace('/mcp', '/.well-known/oauth-protected-resource/mcp'))).status).toBe(200);
});
it('filters MCP hosts, checklist and clusters by individual identity', async () => {
  for (const [id, expected] of [[user, ['h1']], [other, []]] as const) {
    const { tokens } = await token(id), client = new Client({ name: 'test', version: '1' });
    await client.connect(new StreamableHTTPClientTransport(new URL(endpoint), { requestInit: { headers: { Authorization: `Bearer ${tokens.access_token}` } } }));
    const tools = await client.listTools(); expect(tools.tools[0]._meta?.securitySchemes).toBeTruthy();
    const result: any = await client.callTool({ name: 'list_hosts', arguments: {} });
    expect(JSON.parse(result.content[0].text).map((h: any) => h.name)).toEqual(expected);
    const checklist: any = await client.callTool({ name: 'get_security_checklist', arguments: {} });
    expect(JSON.parse(checklist.content[0].text).checklist_servers.map((h: any) => h.name)).toEqual(expected);
    const clusters: any = await client.callTool({ name: 'list_clusters', arguments: {} }); expect(JSON.parse(clusters.content[0].text)).toEqual([]);
    const denied: any = await client.callTool({ name: 'run_command', arguments: { host: 'h2', command: 'id' } }); expect(denied.isError).toBe(true);
    await client.close();
  }
});
it('guards services and security audit before network access even with operator label', async () => {
  await identityContext.run({ userId: other, clientId: 'operator' }, async () => {
    await expect(runCommand(ctx, 'operator', 'h1', 'id')).rejects.toThrow('Resource unavailable');
    await expect(runKube(ctx, 'operator', 'c1', 'get pods')).rejects.toThrow('Resource unavailable');
    await expect(runHostSecurityAudit(ctx, 'operator', 'h1')).rejects.toThrow('Resource unavailable');
  });
});
it('rechecks grants after approval', async () => {
  const result = identityContext.run({ userId: user, clientId: 'test' }, () => runCommand(ctx, 'test', 'h1', 'id'));
  const pending = ctx.approvals.list()[0]; store.del('grant', 'g1'); ctx.approvals.decide(pending.id, 'approved');
  await expect(result).rejects.toThrow('Resource unavailable');
  store.put('grant', 'g1', { id: 'g1', subject: user, kind: 'user', type: 'host', resource: 'h1' });
});
it('supports group grants and immediate removal', () => {
  store.put('group', 'team', { id: 'team', members: [other] });
  store.put('grant', 'gg', { id: 'gg', kind: 'group', subject: 'team', type: 'host', resource: 'h2' });
  expect(store.can({ userId: other, clientId: 'test' }, 'host', 'h2')).toBe(true);
  store.put('group', 'team', { id: 'team', members: [] }); expect(store.can({ userId: other, clientId: 'test' }, 'host', 'h2')).toBe(false);
});
it('rejects code replay, wrong audience and unsafe redirects', async () => {
  const r = await token(user);
  await expect(provider.exchangeAuthorizationCode(clientInfo, r.code, r.verifier, clientInfo.redirect_uris[0], provider.resource)).rejects.toThrow();
  await expect(provider.exchangeRefreshToken(clientInfo, r.tokens.refresh_token, undefined, new URL('https://wrong.example/mcp'))).rejects.toThrow();
  expect(() => provider.clientsStore.registerClient({ redirect_uris: ['http://evil.example/cb'] })).toThrow();
});
it('rotates refresh tokens and revokes the family on replay', async () => {
  const r = await token(user), rotated = await provider.exchangeRefreshToken(clientInfo, r.tokens.refresh_token, undefined, provider.resource);
  await expect(provider.exchangeRefreshToken(clientInfo, r.tokens.refresh_token, undefined, provider.resource)).rejects.toThrow('reused');
  await expect(provider.verifyAccessToken(rotated.access_token)).rejects.toThrow();
});
it('enforces expiry and disabled accounts', async () => {
  const r = await token(other), hash = sha256(r.tokens.access_token);
  store.put('access', hash, { ...store.get<any>('access', hash), expires: 0 }); await expect(provider.verifyAccessToken(r.tokens.access_token)).rejects.toThrow();
  const r2 = await token(other), u = store.user(other); store.put('user', u.id, { ...u, disabled: true });
  await expect(provider.verifyAccessToken(r2.tokens.access_token)).rejects.toThrow(); store.put('user', u.id, u);
});
it('requires MFA and consumes invitations and recovery codes once', async () => {
  const e = await enroll('carol'); expect(() => store.enrollment(e.invitation)).toThrow();
  await expect(store.login('carol', 'password with enough entropy', '000')).rejects.toThrow();
  await expect(store.login('carol', 'password with enough entropy', e.recovery[0])).resolves.toMatchObject({ id: e.id });
  await expect(store.login('carol', 'password with enough entropy', e.recovery[0])).rejects.toThrow();
});
it('persists identities and grants on reopen', () => { const second = new IdentityStore(dir); expect(second.user(user).name).toBe('alice'); expect(second.can({ userId: user, clientId: 'test' }, 'host', 'h1')).toBe(true); second.db.close(); });
it('generates OAuth configurations without workspace credentials', () => {
  for (const c of CLIENTS) {
    const config = clientSetup(c.id, 'secret-must-not-appear', { endpoint: 'https://example.com/mcp', nodePath: '/node', bridgePath: '/stdio.js' });
    expect(JSON.stringify(config)).not.toContain('secret-must-not-appear'); expect(JSON.stringify(config)).not.toContain('MCP_SSH_TOKEN');
  }
  expect(() => canonicalUrl('http://remote.example')).toThrow();
});

it('exchanges codes over HTTP with PKCE and rejects invalid bindings', async () => {
  const verifier = randomToken(), challenge = Buffer.from(sha256(verifier), 'hex').toString('base64url');
  const query = new URLSearchParams({ client_id: clientInfo.client_id, redirect_uri: clientInfo.redirect_uris[0], response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256', resource: provider.resource.href, scope: 'mcp:use', state: 'bound-state' });
  const begin = await fetch(new URL('/authorize?' + query, endpoint), { redirect: 'manual' }); expect(begin.status).toBe(302);
  const requestId = new URL(begin.headers.get('location')!).searchParams.get('request')!;
  const result = new URL(provider.consent(requestId, user, true)); expect(result.searchParams.get('state')).toBe('bound-state');
  const exchange = (codeVerifier: string) => fetch(new URL('/token', endpoint), { method: 'POST', body: new URLSearchParams({ grant_type: 'authorization_code', client_id: clientInfo.client_id, code: result.searchParams.get('code')!, code_verifier: codeVerifier, redirect_uri: clientInfo.redirect_uris[0], resource: provider.resource.href }) });
  expect((await exchange(randomToken())).status).toBe(400);
  const response = await exchange(verifier); expect(response.status).toBe(200);
  expect((await provider.verifyAccessToken((await response.json()).access_token)).extra.userId).toBe(user);
  expect((await exchange(verifier)).status).toBe(400);
});
it('requires session CSRF for consent and does not expose MFA secrets', async () => {
  const raw = randomToken(), id = sha256(raw);
  store.put('session', id, { id, userId: user, csrf: 'secret-csrf', expires: Date.now() + 100000, idle: Date.now() + 100000 });
  const me = await fetch(new URL('/identity/me', endpoint), { headers: { Cookie: 'identity=' + raw } });
  const data = await me.json(); expect(data.user.name).toBe('alice'); expect(data.user.secret).toBeUndefined();
  const denied = await fetch(new URL('/identity/consent', endpoint), { method: 'POST', headers: { Cookie: 'identity=' + raw }, body: new URLSearchParams({ request: 'anything', allow: 'yes', csrf: 'wrong' }) }); expect(denied.status).toBe(400);
  const badOrigin = await fetch(new URL('/identity/login', endpoint), { method: 'POST', headers: { Origin: 'https://evil.example' } }); expect(badOrigin.status).toBe(403);
  store.put('session', id, { id, userId: user, csrf: 'secret-csrf', expires: 0, idle: 0 });
  expect((await (await fetch(new URL('/identity/me', endpoint), { headers: { Cookie: 'identity=' + raw } })).json()).user).toBeNull();
});
it('relays MCP through the stdio bridge with individual OAuth and refresh', async () => {
  const { tokens } = await token(user);
  const home = join(dir, 'bridge-home'), cache = join(home, '.mcp-ssh', 'oauth'); mkdirSync(cache, { recursive: true });
  writeFileSync(join(cache, sha256(endpoint) + '.json'), JSON.stringify({ client: { ...clientInfo, issuer: provider.issuer.href }, tokens }));
  const hash = sha256(tokens.access_token); store.put('access', hash, { ...store.get<any>('access', hash), expires: 0 });
  const transport = new StdioClientTransport({ command: process.execPath, args: ['--import', 'tsx', resolve('src/mcp/stdio.ts')], cwd: resolve('.'), stderr: 'pipe', env: { USERPROFILE: home, HOME: home, MCP_SSH_URL: endpoint } });
  const client = new Client({ name: 'bridge-test', version: '1' });
  try {
    await client.connect(transport);
    const result: any = await client.callTool({ name: 'list_hosts', arguments: {} }); expect(JSON.parse(result.content[0].text).map((h: any) => h.name)).toEqual(['h1']);
  } finally { await client.close(); await transport.close(); }
}, 15000);
it('migrates global tokens with an encrypted backup and leaves restart locked', async () => {
  const path = join(dir, 'migration.json'), legacy = new Vault(path); await legacy.create('migration master password');
  legacy.d.tokens.push({ id: 'old', name: 'shared', hash: sha256('legacy'), created: '' }); legacy.save(); legacy.lock();
  const migrated = new Vault(path); await migrated.unlock('migration master password'); expect(migrated.d.tokens).toEqual([]); migrated.lock();
  expect(new Vault(path).unlocked).toBe(false);
});

it('bootstraps only locally and gates all vault APIs behind account login and vault unlock', async () => {
  const reservation = createServer(); await new Promise<void>(r => reservation.listen(0, '127.0.0.1', r));
  const port = (reservation.address() as { port: number }).port; await new Promise<void>(r => reservation.close(() => r()));
  const admin = startAdmin(ctx, port, resolve('web'), new TunnelManager(vault, dir, 0), { dataDir: dir, scriptsDir: resolve('scripts'), mcpPort: Number(provider.resource.port), bridgePath: resolve('src/mcp/stdio.ts'), oauth: provider });
  if (!admin.listening) await new Promise<void>(r => admin.once('listening', r));
  const url = `http://127.0.0.1:${port}`;
  const post = (path: string, body: unknown, cookie = '') => fetch(url + path, { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie }, body: JSON.stringify(body), redirect: 'manual' });
  try {
    expect((await fetch(url + '/api/status')).status).toBe(401);
    expect((await post('/api/unlock', { password: 'master password distinct' })).status).toBe(401);
    expect((await fetch(new URL('/identity/bootstrap', endpoint))).status).toBe(404);
    const response = await post('/identity/bootstrap', { master: 'master password distinct', name: 'admin' }); expect(response.status).toBe(302);
    const invitation = new URL(response.headers.get('location')!, url).searchParams.get('token')!, e = store.enrollment(invitation);
    const recovery = await store.activate(invitation, 'admin account password', new TOTP({ secret: Secret.fromBase32(e.secret) }).generate());
    expect((await post('/identity/bootstrap', { master: 'master password distinct', name: 'hijacker' })).status).toBe(400);
    const login = await post('/identity/login', { name: 'admin', password: 'admin account password', otp: recovery[0] }); expect(login.status).toBe(302);
    const identity = login.headers.get('set-cookie')!.split(';')[0];
    const status = await (await fetch(url + '/api/status', { headers: { Cookie: identity } })).json(); expect(status.unlocked).toBe(false);
    const unlocked = await post('/api/unlock', { password: 'master password distinct' }, identity); expect(unlocked.status).toBe(200);
    const sid = unlocked.headers.get('set-cookie')!.split(';')[0]; const cookie = identity + '; ' + sid;
    expect((await fetch(url + '/api/hosts', { headers: { Cookie: cookie } })).status).toBe(200);
    expect((await post('/api/tokens', {}, cookie)).status).toBe(410);
    expect((await post('/api/lock', {}, cookie)).status).toBe(403);
    const csrf = (await unlocked.json()).csrf;
    expect((await fetch(url + '/api/lock', { method: 'POST', headers: { Cookie: cookie, 'X-CSRF-Token': csrf } })).status).toBe(200);
    expect(vault.unlocked).toBe(false);
    expect((await fetch(new URL('/identity/me', endpoint), { headers: { Cookie: identity } })).status).toBe(200);
    const challenge = await fetch(endpoint, { method: 'POST' }); expect(challenge.status).toBe(401);
  } finally { await new Promise<void>(r => admin.close(() => r())); }
});
