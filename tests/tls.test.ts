import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, expect, it, vi } from 'vitest';
import { IdentityStore } from '../src/auth/store.js';
import { CloudflareTls, validateTlsConfig } from '../src/tls/cloudflare.js';
vi.mock('node:dns/promises', () => ({ Resolver: class { setServers() {} async resolveTxt() { return [['challenge-value']]; } } }));
vi.mock('acme-client', () => ({ directory: { letsencrypt: { staging: 'https://acme-staging.example', production: 'https://acme.example' } }, crypto: { createPrivateKey: async () => Buffer.from('account-key'), createCsr: async () => [Buffer.from('certificate-key'), Buffer.from('csr')] }, Client: class { async auto(options: any) { await options.challengeCreateFn({ identifier: { value: 'vault.example.com' } }, { type: 'dns-01' }, 'challenge-value'); throw new Error('ACME simulated rejection'); } } }));
const dir = mkdtempSync(join(tmpdir(), 'private-tls-')), store = new IdentityStore(dir);
afterAll(() => { store.db.close(); rmSync(dir, { recursive: true, force: true }); });
const config = { hostname: 'vault.example.com', privateIp: '10.0.0.8', zoneId: 'a'.repeat(32), email: 'admin@example.com', token: 'CF-SECRET', port: 443, staging: true };
it('requires a private bind address and valid zone and hostname', () => {
  expect(() => validateTlsConfig(config)).not.toThrow();
  for (const privateIp of ['0.0.0.0', '8.8.8.8', '127.0.0.1']) expect(() => validateTlsConfig({ ...config, privateIp })).toThrow();
  expect(() => validateTlsConfig({ ...config, hostname: 'https://evil.example/x' })).toThrow();
});
it('creates DNS-only private DNS and never overwrites conflicting records', async () => {
  const writes: any[] = [];
  const transport = vi.fn(async (url: any, init: any) => {
    if (init.method === 'POST') writes.push(JSON.parse(init.body));
    return new Response(JSON.stringify({ success: true, result: String(url).includes('dns_records') ? (init.method === 'GET' ? [] : { id: 'new' }) : { name: 'example.com' } }));
  }) as any;
  const tls = new CloudflareTls(store, transport); tls.configure(config); await tls.ensurePrivateDns();
  expect(writes).toEqual([{ type: 'A', name: config.hostname, content: config.privateIp, ttl: 300, proxied: false, comment: 'MCP SSH private VPN endpoint' }]);
  expect(JSON.stringify(tls.status())).not.toContain('CF-SECRET'); expect(JSON.stringify(store.get('runtime', 'tls-config'))).not.toContain('CF-SECRET');
  const conflict = new CloudflareTls(store, (async (url: any) => new Response(JSON.stringify({ success: true, result: String(url).includes('dns_records') ? [{ type: 'A', content: '8.8.8.8' }] : { name: 'example.com' } }))) as any);
  await expect(conflict.ensurePrivateDns()).rejects.toThrow('conflicts');
});
it('cleans up only its TXT challenge and preserves the previous certificate after ACME failure', async () => {
  const deleted: string[] = [];
  const transport = (async (url: any, init: any) => {
    if (init.method === 'DELETE') deleted.push(String(url));
    return new Response(JSON.stringify({ success: true, result: String(url).includes('dns_records') ? (init.method === 'GET' ? [{ type: 'A', content: config.privateIp }] : { id: 'owned-challenge' }) : { name: 'example.com' } }));
  }) as any;
  const tls = new CloudflareTls(store, transport); tls.configure(config);
  store.put('runtime', 'tls-certificate', { cert: 'previous certificate', hostname: config.hostname, staging: true, expires: 0 });
  await expect(tls.issue()).rejects.toThrow('Certificate issuance failed');
  expect(deleted).toHaveLength(1); expect(deleted[0]).toContain('/dns_records/owned-challenge');
  expect(store.get<any>('runtime', 'tls-certificate').cert).toBe('previous certificate'); expect(tls.busy).toBe(false);
});
