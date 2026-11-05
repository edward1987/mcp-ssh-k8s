import { afterEach, expect, it, vi } from 'vitest';
import { createServer } from 'node:net';
import type { Server } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { IdentityStore, randomToken } from '../src/auth/store.js';
import { OAuthProvider } from '../src/auth/oauth.js';
import { VaultRegistry } from '../src/vault/registry.js';
import { ShareBroker } from '../src/vault/shares.js';
import { Vault, sha256 } from '../src/vault/store.js';
import { Audit } from '../src/audit.js';
import { Approvals } from '../src/policy/policy.js';
import { startMcp } from '../src/mcp/server.js';
import { runSsh } from '../src/ssh/exec.js';
import { runKubectl } from '../src/k8s/kubectl.js';
vi.mock('../src/ssh/exec.js', () => ({ runSsh: vi.fn() }));
vi.mock('../src/k8s/kubectl.js', async original => ({ ...await original<typeof import('../src/k8s/kubectl.js')>(), runKubectl: vi.fn() }));
const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => { for (const close of cleanup.splice(0)) await close(); vi.clearAllMocks(); });

for (const personal of [false, true]) it(`discovers authenticated tools with a locked ${personal ? 'personal' : 'legacy'} vault, without granting resource access`, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-discovery-')), store = new IdentityStore(dir);
  store.put('user', 'owner', { id: 'owner', name: 'test-owner', role: 'administrator', disabled: false, password: 'synthetic', secret: 'synthetic', recovery: [], counter: -1 });
  const registry = personal ? new VaultRegistry(dir, store) : undefined;
  const vault = registry ? registry.get('owner') : new Vault(join(dir, 'vault.json'));
  await vault.create('synthetic discovery vault password');
  vault.d.hosts.push({ id: 'private-host', name: 'PRIVATE-TARGET', hostname: '192.0.2.25', port: 22, user: 'root', auth: 'password', password: 'PRIVATE-PASSWORD', mode: 'free', allowlist: [] });
  vault.save(); vault.lock();
  const reserve = createServer(); await new Promise<void>(resolve => reserve.listen(0, '127.0.0.1', resolve));
  const port = (reserve.address() as { port: number }).port; await new Promise<void>(resolve => reserve.close(() => resolve()));
  const endpoint = `http://127.0.0.1:${port}/mcp`;
  const oauth = new OAuthProvider(store, new URL(new URL(endpoint).origin), new URL(endpoint));
  const ctx = { identities: store, registry, shares: registry ? new ShareBroker(store, registry) : undefined, vault: registry?.facade() ?? vault, audit: new Audit(join(dir, 'audit.jsonl')), approvals: new Approvals() };
  const server: Server = startMcp(ctx, port, '127.0.0.1', oauth);
  if (!server.listening) await new Promise<void>(resolve => server.once('listening', resolve));
  const client = new Client({ name: 'discovery-regression', version: '1' });
  cleanup.push(async () => { await client.close(); server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); registry?.lockAll(); vault.lock(); store.db.close(); rmSync(dir, { recursive: true, force: true }); });
  const registration = oauth.clientsStore.registerClient({ redirect_uris: ['http://127.0.0.1/callback'], token_endpoint_auth_method: 'none' });
  const verifier = randomToken(); let consent = '';
  await oauth.authorize(registration, { redirectUri: registration.redirect_uris[0], codeChallenge: Buffer.from(sha256(verifier), 'hex').toString('base64url'), resource: oauth.resource, scopes: ['mcp:use'] }, { redirect(value: string) { consent = value; } } as any);
  const callback = new URL(oauth.consent(new URL(consent).searchParams.get('request')!, 'owner', true));
  const tokens = await oauth.exchangeAuthorizationCode(registration, callback.searchParams.get('code')!, verifier, registration.redirect_uris[0], oauth.resource);
  // All requests here share one source IP, as they do behind the included gateway.
  for (let i = 0; i < 11; i++) {
    const failed = await fetch(endpoint, { method: 'POST', headers: { Authorization: 'Bearer invalid' } });
    expect(failed.status).toBe(i < 10 ? 401 : 429);
  }
  await client.connect(new StreamableHTTPClientTransport(new URL(endpoint), { requestInit: { headers: { Authorization: 'Bearer ' + tokens.access_token } } }));
  const catalog = await client.listTools(); expect(catalog.tools.length).toBe(personal ? 11 : 9);
  expect(JSON.stringify(catalog)).not.toMatch(/PRIVATE-TARGET|PRIVATE-PASSWORD|192\.0\.2\.25/);
  expect(vault.unlocked).toBe(false);
  const args: Record<string, Record<string, unknown>> = { run_command: { host: 'PRIVATE-TARGET', command: 'id' }, read_file: { host: 'PRIVATE-TARGET', path: '/etc/passwd' }, get_host_info: { host: 'PRIVATE-TARGET' }, run_security_check: { host: 'PRIVATE-TARGET' }, kubectl: { cluster: 'test-cluster', args: 'get pods' }, run_shared_operation: { share_id: 'test-share', command: 'id' } };
  for (const tool of catalog.tools) {
    const result = await client.callTool({ name: tool.name, arguments: args[tool.name] ?? {} });
    if (tool.name === 'get_vault_status') {
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({ locked: true, unlock_url: `http://127.0.0.1:7777/` });
      continue;
    }
    expect(result.isError, tool.name).toBe(true);
    expect(result.structuredContent).toMatchObject({ code: 'VAULT_LOCKED', locked: true, action: { type: 'open_url' } });
    expect(JSON.stringify(result), tool.name).toMatch(/vault.*locked/i);
    expect(JSON.stringify(result), tool.name).not.toMatch(/PRIVATE-PASSWORD|192\.0\.2\.25/);
  }
  expect(runSsh).not.toHaveBeenCalled(); expect(runKubectl).not.toHaveBeenCalled();
  await vault.unlock('synthetic discovery vault password');
  const touch = vi.spyOn(vault, 'touch');
  const deadline = vault.idleExpiresAt;
  expect((await client.callTool({ name: 'get_vault_status', arguments: {} })).structuredContent).toMatchObject({ locked: false, idle_timeout_minutes: 10, idle_expires_at: deadline });
  expect(touch).not.toHaveBeenCalled();
  expect((await client.callTool({ name: 'list_hosts', arguments: {} })).isError).toBe(false);
  expect(touch).toHaveBeenCalled();
  vault.lock(); expect((await client.listTools()).tools.length).toBe(catalog.tools.length);
  // Discovery does not bypass invalidation, even though it no longer needs decryption.
  await oauth.revokeToken(registration, { token: tokens.access_token });
  const denied = await fetch(endpoint, { method: 'POST', headers: { Authorization: 'Bearer ' + tokens.access_token, 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) });
  expect([401, 429]).toContain(denied.status);
});
