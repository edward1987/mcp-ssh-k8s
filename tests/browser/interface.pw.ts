import { test, expect } from '@playwright/test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createServer } from 'node:net';
import type { Server } from 'node:http';
import { TOTP, Secret } from 'otpauth';
import { IdentityStore, randomToken } from '../../src/auth/store.js';
import { Vault, sha256 } from '../../src/vault/store.js';
import { OAuthProvider } from '../../src/auth/oauth.js';
import { startAdmin } from '../../src/admin/server.js';
import { Audit } from '../../src/audit.js';
import { Approvals } from '../../src/policy/policy.js';
import { TunnelManager } from '../../src/tunnel/manager.js';
const dir = mkdtempSync(join(tmpdir(), 'mcp-ui-'));
const store = new IdentityStore(dir), vault = new Vault(join(dir, 'vault.json'));
const approvals = new Approvals();
let server: Server, base: string, userId: string;
test.beforeAll(async () => {
  await vault.create('test master password only');
  vault.d.hosts.push(...['production-web', 'staging-api', '<img src=x onerror=alert(1)>'].map((name, i) => ({ id: 'h' + i, name, hostname: '10.10.0.' + (i + 1), port: 22, user: 'deploy', mode: i === 0 ? 'approval' as const : 'read-only' as const, auth: 'password' as const, allowlist: [], group: i === 0 ? 'Production' : 'Staging' })));
  vault.save();
  const invitation = store.invite('test-operator', 'administrator'), e = store.enrollment(invitation);
  await store.activate(invitation, 'test account password only', new TOTP({ secret: Secret.fromBase32(e.secret) }).generate()); userId = e.u.id;
  const reserve = createServer(); await new Promise<void>(r => reserve.listen(0, '127.0.0.1', r));
  const port = (reserve.address() as { port: number }).port; await new Promise<void>(r => reserve.close(() => r()));
  base = 'http://127.0.0.1:' + port;
  const provider = new OAuthProvider(store, new URL(base), new URL(base + '/mcp'));
  const ctx = { identities: store, vault, approvals, audit: new Audit(join(dir, 'audit.jsonl')) };
  server = startAdmin(ctx, port, resolve('web'), new TunnelManager(vault, dir, 7778), { dataDir: dir, scriptsDir: resolve('scripts'), mcpPort: 7778, bridgePath: resolve('dist/mcp/stdio.js'), oauth: provider });
  if (!server.listening) await new Promise<void>(r => server.once('listening', r));
});
test.afterAll(async () => { vault.lock(); if (server) await new Promise<void>(r => server.close(() => r())); store.db.close(); rmSync(dir, { recursive: true, force: true }); });
test.beforeEach(async ({ context }) => {
  const raw = randomToken(); store.put('session', sha256(raw), { id: sha256(raw), userId, csrf: 'test-csrf', expires: Date.now() + 28800000, idle: Date.now() + 1800000 });
  await context.addCookies([{ name: 'identity', value: raw, url: base, httpOnly: true, sameSite: 'Lax' }]);
});
async function unlock(page: import('@playwright/test').Page) {
  await page.goto(base);
  await page.getByLabel('Parolă master', { exact: true }).fill('test master password only');
  await page.getByRole('button', { name: 'Deblochează vaultul', exact: true }).click();
  await expect(page.locator('#page-title')).toHaveText('Privire de ansamblu');
  await expect(page.locator('.metrics')).toBeVisible();
}
test('native login form sends its same-origin Origin and completes MFA login', async ({ page, context }) => {
  await context.clearCookies();
  await page.goto(base + '/identity/login');
  const user = store.user(userId);
  const otp = new TOTP({ secret: Secret.fromBase32(store.open(user.secret!)) }).generate();
  await page.getByLabel('Utilizator', { exact: true }).fill(user.name);
  await page.getByLabel('Parolă', { exact: true }).fill('test account password only');
  await page.getByLabel('TOTP sau cod de recuperare').fill(otp);
  const request = page.waitForRequest(r => r.method() === 'POST' && r.url().endsWith('/identity/login'));
  await page.getByRole('button', { name: 'Autentificare securizată', exact: true }).click();
  expect((await request).headers().origin).toBe(base);
  await expect(page.getByRole('heading', { name: 'Conturi și acces', exact: true })).toBeVisible();
});
test('bootstrap accepts native form origins while null and foreign origins remain forbidden', async ({ page, context }) => {
  await page.goto(base + '/identity/bootstrap');
  await page.getByLabel('Parolă master (vault existent sau nou)').fill('unused in initialized fixture');
  await page.getByLabel('Nume administrator', { exact: true }).fill('must-not-create');
  const response = page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith('/identity/bootstrap'));
  await page.getByRole('button', { name: 'Continuă', exact: true }).click();
  // The fixture is already initialized: reach the bootstrap guard, not the origin rejection.
  expect((await response).status()).toBe(400);
  await expect(page.getByRole('heading', { name: 'Cerere respinsă' })).toBeVisible();
  for (const origin of ['null', 'https://untrusted.example']) {
    const denied = await context.request.post(base + '/identity/bootstrap', { headers: { Origin: origin }, data: {} });
    expect(denied.status()).toBe(403);
  }
  expect(store.all<any>('user').some(u => u.name === 'must-not-create')).toBe(false);
});
test('desktop navigation, filtering, escaping and CSP work without runtime errors', async ({ page }) => {
  const errors: string[] = []; page.on('pageerror', error => errors.push(error.message)); page.on('console', message => { if (/Content Security Policy|Refused to/.test(message.text())) errors.push(message.text()); });
  const external: string[] = []; page.on('request', request => { if (!request.url().startsWith(base)) external.push(request.url()); });
  await unlock(page);
  await page.screenshot({ path: 'test-results/overview-desktop.png', fullPage: true });
  await page.locator('nav [data-t=hosts]').click();
  await expect(page.locator('#host-count')).toHaveText('3 din 3 hosturi');
  await page.getByRole('searchbox', { name: 'Caută hosturi' }).fill('production');
  await expect(page.locator('#host-count')).toHaveText('1 din 3 hosturi');
  await expect(page.locator('#host-card-h1')).toBeHidden();
  await page.getByRole('searchbox', { name: 'Caută hosturi' }).fill('');
  await expect(page.locator('#host-card-h2')).toContainText('<img src=x onerror=alert(1)>');
  await expect(page.locator('#view img')).toHaveCount(0);
  await page.screenshot({ path: 'test-results/hosts-desktop.png', fullPage: true });
  await page.getByRole('button', { name: '+ Host nou', exact: true }).click();
  await expect(page.locator('#host-dialog')).toBeVisible();
  await page.screenshot({ path: 'test-results/host-dialog.png', fullPage: true });
  await page.locator('#dlg-close').click();
  for (const tab of ['checklist', 'k8s', 'keys', 'import', 'clients', 'approvals', 'audit', 'settings']) {
    await page.locator(`nav [data-t=${tab}]`).click();
    await expect(page.locator('#view')).not.toHaveAttribute('aria-busy', 'true');
    await expect(page.locator('.view-error')).toHaveCount(0);
  }
  await page.getByRole('button', { name: 'Schimbă tema' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  expect(errors).toEqual([]); expect(external).toEqual([]);
});
test('mobile menu and account management fit narrow screens', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 }); await unlock(page);
  await page.getByRole('button', { name: 'Deschide meniul' }).click();
  await page.locator('nav [data-t=hosts]').click();
  await expect(page.locator('#host-search')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.goto(base + '/identity/');
  await expect(page.getByRole('heading', { name: 'Conturi și acces', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Generează invitația' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: 'test-results/accounts-mobile.png', fullPage: true });
});
test('locking clears infrastructure from the DOM and requires the master password again', async ({ page }) => {
  await unlock(page); await page.locator('nav [data-t=hosts]').click();
  await expect(page.locator('#host-card-h0')).toBeVisible();
  await page.getByRole('button', { name: 'Blochează vaultul', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Vaultul este blocat' })).toBeVisible();
  await expect(page.locator('#host-card-h0')).toHaveCount(0);
  await expect(page.locator('#pw')).toHaveValue('');
});
test('operator approval requires review and cancellation sends no decision', async ({ page }) => {
  await unlock(page);
  const decision = approvals.request({ host: 'production-web', client: 'test-ai', command: 'systemctl restart app' }, 20);
  await page.locator('nav [data-t=approvals]').click();
  await page.getByRole('button', { name: 'Aprobă', exact: true }).click();
  await expect(page.locator('.confirm-dialog')).toContainText('systemctl restart app');
  await page.getByRole('button', { name: 'Anulează', exact: true }).click();
  expect(approvals.list()).toHaveLength(1);
  await page.getByRole('button', { name: 'Aprobă', exact: true }).click();
  await page.getByRole('button', { name: 'Confirmă', exact: true }).click();
  expect(await decision).toBe('approved');
});
test('configures the idle timeout in vault settings and rejects invalid values on the server', async ({ page, context }) => {
  await unlock(page);
  await page.locator('nav [data-t=settings]').click();
  const input = page.getByLabel('Blocare după inactivitate (minute)', { exact: true });
  await input.fill('2'); await page.locator('#s-save').click();
  await expect.poll(() => vault.d.settings.autoLockMinutes).toBe(2);
  const status = await (await context.request.get(base + '/api/status')).json();
  for (const value of ['bad', '-1', '1.5', '1441', 'Infinity']) {
    const response = await context.request.put(base + '/api/settings', { headers: { 'X-CSRF-Token': status.csrf }, data: { autoLockMinutes: value, maxOutputBytes: 65536, approvalTimeoutSec: 120 } });
    expect(response.status()).toBe(400); expect(vault.d.settings.autoLockMinutes).toBe(2);
  }
  await page.reload(); await page.locator('nav [data-t=settings]').click();
  await expect(input).toHaveValue('2');
  await input.fill('10'); await page.locator('#s-save').click();
  await expect.poll(() => vault.d.settings.autoLockMinutes).toBe(10);
});

test('background reads do not renew login or defeat vault auto-lock', async ({ page, context }) => {
  await unlock(page);
  const cookie = (await context.cookies()).find(c => c.name === 'identity')!;
  const hash = sha256(cookie.value), before = store.get<any>('session', hash).idle;
  vault.d.settings.autoLockMinutes = 0.01; vault.touch();
  for (let i = 0; i < 5; i++) expect((await context.request.get(base + '/api/hosts')).status()).toBe(200);
  expect(store.get<any>('session', hash).idle).toBe(before);
  await expect.poll(() => vault.unlocked, { timeout: 3000 }).toBe(false);
  expect((await context.request.get(base + '/api/hosts')).status()).toBe(401);
  store.put('session', hash, { ...store.get<any>('session', hash), idle: 0 });
  expect((await context.request.post(base + '/api/unlock', { data: { password: 'test master password only' } })).status()).toBe(401);
});


test('vault actions show progress during a slow request and recover after an error', async ({ page }) => {
  await unlock(page);
  await page.locator('nav [data-t="settings"]').click();
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  await page.route('**/api/settings', async route => {
    if (route.request().method() !== 'PUT') return route.continue();
    await gate;
    await route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'Synthetic save failure' }) });
  });
  const button = page.locator('#s-save');
  await button.click();
  try {
    await expect(button).toBeDisabled();
    await expect(page.locator('.operation-progress')).toBeVisible();
    await expect(button).toHaveAttribute('aria-busy', 'true');
  } finally { release(); }
  await expect(page.locator('.toast.error')).toContainText('Synthetic save failure');
  await expect(button).toBeEnabled();
  await expect(page.locator('.operation-progress')).toHaveCount(0);
});
