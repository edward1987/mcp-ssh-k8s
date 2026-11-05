import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, expect, it, vi } from 'vitest';
import { IdentityStore } from '../src/auth/store.js';
import { VaultRegistry } from '../src/vault/registry.js';
import { ShareBroker } from '../src/vault/shares.js';
import { identityContext, canAccess } from '../src/auth/context.js';
import { Approvals } from '../src/policy/policy.js';
import { Audit } from '../src/audit.js';
import { runSsh } from '../src/ssh/exec.js';
import { Vault } from '../src/vault/store.js';
vi.mock('../src/ssh/exec.js', () => ({ runSsh: vi.fn(async () => ({ stdout: 'ok', stderr: '', exitCode: 0, timedOut: false, truncated: false })) }));
const dir = mkdtempSync(join(tmpdir(), 'personal-vaults-'));
const store = new IdentityStore(dir), registry = new VaultRegistry(dir, store), broker = new ShareBroker(store, registry), approvals = new Approvals();
const ctx = { identities: store, registry, shares: broker, approvals, vault: registry.facade(), audit: new Audit(join(dir, 'audit.jsonl'), true) };
const as = <T>(userId: string, fn: () => T) => identityContext.run({ userId, clientId: 'test' }, fn);
let recovery: string;
beforeAll(async () => {
  for (const id of ['ana', 'mihai', 'admin', 'approver']) store.put('user', id, { id, name: id, role: id === 'admin' ? 'administrator' : 'member', disabled: false, password: 'test', secret: 'test', recovery: [], counter: -1 });
  recovery = await registry.get('ana').initialize('ana master password');
  await registry.get('mihai').initialize('mihai master password');
  await registry.get('admin').initialize('admin master password');
  registry.get('ana').d.hosts.push({ id: 'private-host', name: 'Ana secret', hostname: '10.55.1.2', port: 22, user: 'root', auth: 'password', password: 'SSH-SECRET', mode: 'free', allowlist: [] }); registry.get('ana').save();
  broker.onRevoke = id => approvals.denyShare(id); registry.onLock = id => approvals.denyUser(id);
});
afterAll(() => { registry.lockAll(); store.db.close(); rmSync(dir, { recursive: true, force: true }); });
const share = (policy: 'limited' | 'approval' | 'unrestricted' = 'limited') => broker.create('ana', { recipient: 'mihai', resource: 'private-host', type: 'host', alias: 'Application status', policy, operations: [{ id: 'status', name: 'Status', command: 'id' }], approvers: ['approver'], expires: Date.now() + 86400000 });
it('isolates personal data even from account administrators and binds facade to identity', () => {
  expect(as('mihai', () => ctx.vault.d.hosts)).toEqual([]);
  expect(as('admin', () => canAccess(ctx, 'host', 'private-host'))).toBe(false);
  expect(as('ana', () => canAccess(ctx, 'host', 'private-host'))).toBe(true);
  expect(() => ctx.vault.d).toThrow();
});
it('wraps a random vault secret and recovers without account-admin access', async () => {
  const vault = registry.get('ana'); vault.lock();
  await expect(vault.unlock('admin master password')).rejects.toThrow();
  const replacement = await vault.recover(recovery, 'new ana master password');
  expect(vault.d.hosts[0].password).toBe('SSH-SECRET');
  await expect(vault.recover(recovery, 'another master password')).rejects.toThrow();
  recovery = replacement;
  await vault.changePassword('new ana master password', 'ana master password');
  const record = store.get<any>('personal-vault', 'ana');
  expect(readFileSync(join(dir, 'vaults', record.id + '.json'), 'utf8')).not.toContain('SSH-SECRET');
});
it('publishes only aliases and named operations and executes fixed commands without owner being online', async () => {
  const s = share(); registry.get('ana').lock();
  const visible = as('mihai', () => broker.list('mihai'));
  expect(JSON.stringify(visible)).not.toMatch(/10\.55|SSH-SECRET|private-host/);
  const result = await as('mihai', () => broker.execute(ctx, 'mihai', s.id, 'status', 'rm -rf /'));
  expect(result.stdout).toBe('ok'); expect(vi.mocked(runSsh).mock.calls.at(-1)![2]).toBe('id');
  await expect(as('mihai', () => broker.execute(ctx, 'mihai', s.id, 'unknown', 'id'))).rejects.toThrow();
  expect(JSON.stringify(store.all('shared-secret'))).not.toMatch(/10\.55|SSH-SECRET/);
  await registry.get('ana').unlock('ana master password');
});
it('requires recipient vault unlock and prunes revoked references on next access', async () => {
  const s = share(); as('mihai', () => broker.list('mihai')); expect(registry.get('mihai').d.sharedRefs).toContain(s.id);
  registry.get('mihai').lock(); await expect(as('mihai', () => broker.execute(ctx, 'mihai', s.id, 'status', undefined))).rejects.toThrow('locked');
  await registry.get('mihai').unlock('mihai master password'); broker.revoke('ana', s.id);
  await expect(as('mihai', () => broker.execute(ctx, 'mihai', s.id, 'status', undefined))).rejects.toThrow('unavailable');
  as('mihai', () => broker.list('mihai')); expect(registry.get('mihai').d.sharedRefs).not.toContain(s.id);
});
it('propagates credential updates and denies expired shares before network use', async () => {
  const s = share('unrestricted'); registry.get('ana').d.hosts[0].hostname = '10.55.2.3'; registry.get('ana').save();
  await as('mihai', () => broker.execute(ctx, 'mihai', s.id, undefined, 'id'));
  expect(vi.mocked(runSsh).mock.calls.at(-1)![1].hostname).toBe('10.55.2.3');
  store.put('share', s.id, { ...s, expires: 0 });
  await expect(as('mihai', () => broker.execute(ctx, 'mihai', s.id, undefined, 'id'))).rejects.toThrow('unavailable');
});
it('revocation cancels approval and prevents execution', async () => {
  const s = share('approval'), count = vi.mocked(runSsh).mock.calls.length;
  const pending = as('mihai', () => broker.execute(ctx, 'mihai', s.id, undefined, 'id'));
  expect(approvals.list()[0].approvers).toEqual(['ana', 'approver']);
  broker.revoke('ana', s.id); await expect(pending).rejects.toThrow('not approved'); expect(vi.mocked(runSsh).mock.calls.length).toBe(count);
});
it('rejects self-approval designation and does not allow recipients to revoke others shares', () => {
  expect(() => broker.create('ana', { ...share(), approvers: ['mihai'] })).toThrow();
  const s = share(); expect(() => broker.revoke('mihai', s.id)).toThrow();
});
it('locks personal vault when account sessions are revoked', async () => {
  store.revokeUser('ana'); expect(registry.get('ana').unlocked).toBe(false); expect(registry.get('mihai').unlocked).toBe(true);
  await registry.get('ana').unlock('ana master password');
});
it('explicitly migrates a legacy vault to exactly one owner', async () => {
  const legacy = new Vault(join(dir, 'vault.json')); await legacy.create('legacy master password'); legacy.d.hosts.push({ ...registry.get('ana').d.hosts[0], id: 'legacy-host' }); legacy.save(); legacy.lock();
  const kit = await registry.migrate('approver', 'legacy master password', 'approver vault password'); expect(kit.length).toBeGreaterThan(30);
  expect(registry.get('approver').d.hosts[0].id).toBe('legacy-host');
  await expect(registry.migrate('ana', 'legacy master password', 'ana master password')).rejects.toThrow();
});
