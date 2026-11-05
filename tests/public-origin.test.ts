import { expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { IdentityStore } from '../src/auth/store.js';
import { OAuthProvider } from '../src/auth/oauth.js';
import { Vault } from '../src/vault/store.js';
import { Audit } from '../src/audit.js';
import { Approvals } from '../src/policy/policy.js';
import { startMcp } from '../src/mcp/server.js';
import { WebTunnelManager } from '../src/tunnel/web.js';

it('activates the public origin without restarting discovery, registration or identity origin protection', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'public-origin-')), store = new IdentityStore(dir);
  const reservation = createServer(); await new Promise<void>(r => reservation.listen(0, '127.0.0.1', r));
  const port = (reservation.address() as { port: number }).port; await new Promise<void>(r => reservation.close(() => r()));
  const base = 'http://127.0.0.1:' + port;
  const provider = new OAuthProvider(store, new URL(base), new URL(base + '/mcp'));
  const ctx = { identities: store, vault: new Vault(join(dir, 'vault.json')), approvals: new Approvals(), audit: new Audit(join(dir, 'audit.jsonl')) };
  const server = startMcp(ctx, port, '127.0.0.1', provider);
  if (!server.listening) await new Promise<void>(r => server.once('listening', r));
  try {
    const metadata = async () => (await fetch(base + '/.well-known/oauth-authorization-server')).json() as Promise<any>;
    expect((await metadata()).issuer).toBe(base + '/');
    const manager = new WebTunnelManager(store, dir, base, port, provider.resource.href, origin => provider.setPublicOrigin(origin));
    manager.configure({ origin: 'https://mcp.example.com', token: 'synthetic-cloudflare-run-token', autoStart: false }); manager.activate();
    expect(manager.status().restartRequired).toBe(false);
    expect(await metadata()).toMatchObject({ issuer: 'https://mcp.example.com/', authorization_endpoint: 'https://mcp.example.com/authorize', token_endpoint: 'https://mcp.example.com/token', registration_endpoint: 'https://mcp.example.com/register' });
    expect(await (await fetch(base + '/.well-known/oauth-protected-resource/mcp')).json()).toMatchObject({ resource: 'https://mcp.example.com/mcp', authorization_servers: ['https://mcp.example.com/'] });
    const register = await fetch(base + '/register', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://mcp.example.com' }, body: JSON.stringify({ redirect_uris: ['https://client.example.com/callback'], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] }) });
    expect(register.status).toBe(201);
    const login = await fetch(base + '/identity/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: 'https://mcp.example.com' }, body: 'name=none&password=wrong&otp=000000' });
    expect(await login.text()).not.toContain('Invalid origin');
    expect((await fetch(base + '/identity/login', { method: 'POST', headers: { Origin: 'https://untrusted.example.com' } })).status).toBe(403);
  } finally { server.closeAllConnections(); await new Promise<void>(r => server.close(() => r())); store.db.close(); rmSync(dir, { recursive: true, force: true }); }
});
