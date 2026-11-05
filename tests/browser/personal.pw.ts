import { test, expect } from '@playwright/test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createServer } from 'node:net';
import type { Server } from 'node:http';
import { VaultRegistry } from '../../src/vault/registry.js';
import { ShareBroker } from '../../src/vault/shares.js';
import { IdentityStore, randomToken } from '../../src/auth/store.js';
import { Vault, sha256 } from '../../src/vault/store.js';
import { identityContext } from '../../src/auth/context.js';
import { startAdmin } from '../../src/admin/server.js';
import { Audit } from '../../src/audit.js';
import { Approvals } from '../../src/policy/policy.js';
import { OAuthProvider } from '../../src/auth/oauth.js';
import { TunnelManager } from '../../src/tunnel/manager.js';
import { CloudflareTls } from '../../src/tls/cloudflare.js';
const dir = mkdtempSync(join(tmpdir(), 'personal-ui-')), store = new IdentityStore(dir), registry = new VaultRegistry(dir, store), shares = new ShareBroker(store, registry);
let base: string, server: Server;
test.beforeAll(async () => {
  for (const id of ['ana', 'mihai']) store.put('user', id, { id, name: id, role: id === 'ana' ? 'administrator' : 'member', disabled: false, password: 'test', secret: 'test', recovery: [], counter: -1 });
  await registry.get('ana').initialize('ana personal password');
  registry.get('ana').d.hosts.push({ id: 'private', name: 'Ana production', hostname: '10.0.0.8', port: 22, user: 'root', mode: 'free', auth: 'password', password: 'SSH-SECRET', allowlist: [] }); registry.get('ana').save();
  const reserve = createServer(); await new Promise<void>(r => reserve.listen(0, '127.0.0.1', r)); const port = (reserve.address() as any).port; await new Promise<void>(r => reserve.close(() => r())); base = 'http://127.0.0.1:' + port;
  const ctx = { registry, shares, identities: store, tls: new CloudflareTls(store), vault: registry.facade(), approvals: new Approvals(), audit: new Audit(join(dir, 'audit.jsonl'), true) };
  const oauth = new OAuthProvider(store, new URL(base), new URL(base + '/mcp'));
  server = startAdmin(ctx, port, resolve('web'), new TunnelManager(registry.legacy, dir, 7778, store), { dataDir: dir, scriptsDir: resolve('scripts'), mcpPort: 7778, bridgePath: resolve('dist/mcp/stdio.js'), oauth });
  if (!server.listening) await new Promise<void>(r => server.once('listening', r));
});
test.afterAll(async () => { registry.lockAll(); await new Promise<void>(r => server.close(() => r())); store.db.close(); rmSync(dir, { recursive: true, force: true }); });
async function login(context: import('@playwright/test').BrowserContext, owner: string) {
  const token = randomToken(); store.put('session', sha256(token), { id: sha256(token), userId: owner, csrf: randomToken(), expires: Date.now() + 28800000, idle: Date.now() + 1800000 });
  await context.addCookies([{ name: 'identity', value: token, url: base, httpOnly: true, sameSite: 'Lax' }]);
}
test('member creates a personal vault, saves recovery kit, sees only aliases and cannot see owner secrets', async ({ page, context }) => {
  await login(context, 'mihai'); await page.goto(base);
  await expect(page.getByRole('heading', { name: 'Creează vaultul personal' })).toBeVisible();
  await page.getByLabel('Parolă master', { exact: true }).fill('mihai personal password'); await page.getByRole('button', { name: 'Creează vaultul', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Salvează cheia de recuperare' })).toBeVisible(); expect((await page.locator('pre').textContent())!.length).toBeGreaterThan(30);
  await page.getByRole('button', { name: 'Am păstrat cheia în siguranță' }).click(); await expect(page.locator('.metrics')).toBeVisible();
  expect((await context.request.get(base + '/api/hosts')).status()).toBe(200); expect(await (await context.request.get(base + '/api/hosts')).json()).toEqual([]);
  await expect(page.locator('a[href="/identity/admin"]')).toHaveCount(0);
  await expect(page.locator('nav [data-t="chatgpt"]')).toHaveCount(0);
  await page.locator('nav [data-t="import"]').click();
  await expect(page.locator('#i-file')).toBeVisible();
  await expect(page.locator('#i-scan, #tl, #tl-setup')).toHaveCount(0);
  const s = shares.create('ana', { type: 'host', resource: 'private', recipient: 'mihai', alias: 'App status', policy: 'limited', operations: [{ id: 'status', name: 'Status', command: 'id' }], approvers: [], expires: Date.now() + 86400000 });
  registry.get('ana').lock(); await page.goto(base + '/identity/shares'); await expect(page.getByRole('heading', { name: 'App status' })).toBeVisible();
  expect(await page.content()).not.toMatch(/SSH-SECRET|10\.0\.0\.8|Ana production/);
  shares.revoke('ana', s.id); await page.reload(); await expect(page.getByRole('heading', { name: 'App status' })).toHaveCount(0);
});
test('TLS configuration UI is administrator-only', async ({ page, context }) => {
  await login(context, 'mihai'); expect((await context.request.get(base + '/identity/tls')).status()).toBe(400);
  await context.clearCookies(); await login(context, 'ana'); await page.goto(base + '/identity/tls');
  await expect(page.getByRole('heading', { name: 'HTTPS privat · Let’s Encrypt / Cloudflare' })).toBeVisible();
  await expect(page.getByLabel('IP privat VPN')).toBeVisible(); await expect(page.getByText(/DNS-only către IP privat/)).toBeVisible();
});

test('administrator can configure instance infrastructure from a locked vault on mobile', async ({ page, context }) => {
  registry.get('ana').lock(); await login(context, 'ana');
  await page.setViewportSize({ width: 390, height: 844 }); await page.goto(base);
  await page.getByRole('link', { name: 'Administrare instanță →', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Administrare instanță', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Componente instalate pe server / container' })).toBeVisible();
  await page.getByLabel('Tunnel ID', { exact: true }).fill('tunnel_locked123');
  await page.getByLabel('API key runtime', { exact: true }).fill('private-runtime-secret');
  await page.getByRole('button', { name: 'Salvează configurația' }).click();
  await expect(page.getByLabel('Tunnel ID', { exact: true })).toHaveValue('tunnel_locked123');
  expect(await page.content()).not.toContain('private-runtime-secret');
  expect(registry.get('ana').unlocked).toBe(false);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: 'test-results/instance-admin-mobile.png', fullPage: true });
  await page.getByRole('link', { name: 'Configurează HTTPS privat →' }).click();
  await expect(page.getByLabel('IP privat VPN')).toBeVisible();
});

test('Cloudflare setup exposes token creation, account domains and one-click provisioning on mobile', async ({ page, context }) => {
  const zoneId = 'a'.repeat(32);
  store.put('runtime', 'cloudflare-api', { mode: 'token', email: '', secret: store.seal('synthetic-api-secret-for-ui') });
  store.put('runtime', 'cloudflare-zones', [{ id: zoneId, name: 'example.com', status: 'active', account: { id: 'b'.repeat(32), name: 'My Cloudflare' } }]);
  try {
    await login(context, 'ana'); await page.setViewportSize({ width: 390, height: 844 }); await page.goto(base + '/identity/admin');
    const link = page.getByRole('link', { name: 'Creeaza API token Cloudflare' });
    await expect(link).toHaveAttribute('href', /dash\.cloudflare\.com\/profile\/api-tokens\?permissionGroupKeys=/);
    await expect(page.getByLabel('Domeniu Cloudflare')).toHaveValue(zoneId);
    await expect(page.getByLabel('Subdomeniu', { exact: true })).toHaveValue('mcp');
    await expect(page.getByRole('button', { name: 'Creeaza si conecteaza — 1 click', exact: true })).toBeEnabled();
    await expect(page.getByLabel('API token / API key Cloudflare')).toHaveValue('');
    expect(await page.content()).not.toContain('synthetic-api-secret-for-ui');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  } finally { store.del('runtime', 'cloudflare-api'); store.del('runtime', 'cloudflare-zones'); }
});

test('an existing empty personal vault can import old data without changing its recovery kit', async ({ page, context }) => {
  store.put('user', 'importer', { id: 'importer', name: 'importer', role: 'member', disabled: false, password: 'test', secret: 'test', recovery: [], counter: -1 });
  const kit = await registry.get('importer').initialize('personal master password'); registry.get('importer').lock();
  const old = new Vault(join(dir, 'vault.json')); await old.create('old master password');
  old.d.hosts.push({ id: 'old-host', name: 'My old host', hostname: '10.20.30.40', port: 22, user: 'deploy', mode: 'approval', auth: 'password', password: 'old-ssh-secret', allowlist: [] }); old.save(); old.lock();
  await login(context, 'importer'); await page.goto(base);
  await expect(page.getByRole('heading', { name: 'Vaultul vechi este disponibil' })).toBeVisible();
  await page.getByLabel('Parola master a vaultului vechi', { exact: true }).fill('old master password');
  await page.getByLabel('Parola master a vaultului personal existent', { exact: true }).fill('personal master password');
  await page.getByLabel('Confirm că vaultul vechi îmi aparține și îl import în acest cont.').check();
  await page.getByRole('button', { name: 'Importă vaultul vechi în contul meu', exact: true }).click();
  await expect(page.locator('.metrics')).toBeVisible();
  await expect(page.locator('#legacy-migration')).toHaveCount(0);
  await page.locator('nav [data-t="hosts"]').click(); await expect(page.getByText('My old host', { exact: true })).toBeVisible();
  expect(registry.get('importer').d.hosts[0].password).toBe('old-ssh-secret');
  registry.get('importer').lock(); await registry.get('importer').recover(kit, 'replacement master password');
  expect(registry.get('importer').d.hosts[0].name).toBe('My old host');
});


test('native forms show progress immediately and recover after back navigation', async ({ page, context }) => {
  await login(context, 'ana'); await page.goto(base + '/identity/admin');
  await page.evaluate(() => document.addEventListener('submit', event => event.preventDefault()));
  const form = page.locator('form[action="/identity/admin/cloudflare/connect"]');
  await form.locator('[name=secret]').fill('synthetic-secret-for-progress-test');
  await form.getByRole('button').click();
  await expect(form.locator('.operation-progress')).toBeVisible();
  await expect(form).toHaveAttribute('aria-busy', 'true');
  await expect(form.getByRole('progressbar')).toBeVisible();
  expect(await form.evaluate(el => new FormData(el as HTMLFormElement).get('secret'))).toBe('synthetic-secret-for-progress-test');
  await form.getByRole('button').click({ force: true });
  await expect(form.locator('.operation-progress')).toHaveCount(1);
  await page.evaluate(() => window.dispatchEvent(new Event('pageshow')));
  await expect(form.locator('.operation-progress')).toHaveCount(0);
  await expect(form).not.toHaveAttribute('aria-busy', 'true');
});
