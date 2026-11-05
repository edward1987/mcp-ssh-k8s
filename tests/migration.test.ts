import { afterEach, beforeEach, expect, it } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { IdentityStore } from '../src/auth/store.js';
import { Vault } from '../src/vault/store.js';
import { VaultRegistry } from '../src/vault/registry.js';

let dir: string, store: IdentityStore, registry: VaultRegistry;
beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'legacy-migration-')); store = new IdentityStore(dir); registry = new VaultRegistry(dir, store);
  for (const id of ['owner', 'other']) store.put('user', id, { id, name: id, role: 'member', password: 'test', secret: 'test', disabled: false, recovery: [], counter: -1 });
  const legacy = new Vault(join(dir, 'vault.json')); await legacy.create('legacy master password');
  legacy.d.hosts.push({ id: 'old-host', name: 'Old production', hostname: '10.0.0.8', port: 22, user: 'root', auth: 'key', keyId: 'old-key', mode: 'approval', allowlist: [] });
  legacy.d.keys.push({ id: 'old-key', name: 'Old SSH key', privateKey: 'PRIVATE-KEY' });
  legacy.d.knownHosts['old-host'] = 'pinned-fingerprint'; legacy.d.checklist.push({ hostId: 'old-host', addedAt: '2026-01-01', notes: 'Keep notes' });
  legacy.save(); legacy.lock();
});
afterEach(() => { registry.lockAll(); store.db.close(); rmSync(dir, { recursive: true, force: true }); });

it('imports into an existing empty vault, preserving its encryption envelope and recovery key', async () => {
  const vault = registry.get('owner'), kit = await vault.initialize('personal master password'); vault.lock();
  const id = store.get<any>('personal-vault', 'owner').id, envelopePath = join(dir, 'vaults', id + '.envelope.json');
  const envelope = readFileSync(envelopePath), original = readFileSync(join(dir, 'vault.json'));
  expect(await registry.migrate('owner', 'legacy master password', 'personal master password')).toBeUndefined();
  expect(readFileSync(envelopePath)).toEqual(envelope);
  expect(readFileSync(join(dir, 'vault.json'))).toEqual(original);
  expect(existsSync(join(dir, 'vault.json.pre-identity.bak'))).toBe(true);
  expect(existsSync(join(dir, 'vaults', id + '.json.pre-identity.bak'))).toBe(true);
  expect(vault.d.keys[0].privateKey).toBe('PRIVATE-KEY'); expect(vault.d.hosts[0].keyId).toBe('old-key');
  expect(vault.d.knownHosts['old-host']).toBe('pinned-fingerprint'); expect(vault.d.checklist[0].notes).toBe('Keep notes');
  vault.lock(); await vault.recover(kit, 'replacement master password'); expect(vault.d.hosts[0].id).toBe('old-host');
});

it('requires both passwords and relocks a previously locked vault when import fails', async () => {
  const vault = registry.get('owner'); await vault.initialize('personal master password'); vault.lock();
  await expect(registry.migrate('owner', 'wrong old password', 'personal master password')).rejects.toThrow();
  await expect(registry.migrate('owner', 'legacy master password', 'wrong personal password')).rejects.toThrow();
  expect(vault.unlocked).toBe(false); expect(store.get('migration', 'legacy')).toBeUndefined();
  await vault.unlock('personal master password');
  await expect(registry.migrate('owner', 'legacy master password', 'wrong personal password')).rejects.toThrow();
  expect(vault.d.hosts).toEqual([]); expect(vault.unlocked).toBe(true);
});

it('refuses to overwrite a populated personal vault and preserves both encrypted files', async () => {
  const vault = registry.get('owner'); await vault.initialize('personal master password');
  vault.d.keys.push({ id: 'personal-key', name: 'Personal key', privateKey: 'PERSONAL-KEY' }); vault.save(); vault.lock();
  const id = store.get<any>('personal-vault', 'owner').id, personalPath = join(dir, 'vaults', id + '.json');
  const personal = readFileSync(personalPath), original = readFileSync(join(dir, 'vault.json'));
  await expect(registry.migrate('owner', 'legacy master password', 'personal master password')).rejects.toThrow('conține deja date');
  expect(vault.unlocked).toBe(false); expect(readFileSync(personalPath)).toEqual(personal);
  expect(readFileSync(join(dir, 'vault.json'))).toEqual(original); expect(store.get('migration', 'legacy')).toBeUndefined();
});

it('assigns the old vault only once when two accounts attempt migration concurrently', async () => {
  const results = await Promise.allSettled([
    registry.migrate('owner', 'legacy master password', 'owner master password'),
    registry.migrate('other', 'legacy master password', 'other master password'),
  ]);
  expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(1);
  const assigned = store.get<any>('migration', 'legacy').owner;
  expect(registry.get(assigned).d.hosts[0].id).toBe('old-host');
  expect(registry.get(assigned === 'owner' ? 'other' : 'owner').exists).toBe(false);
});
