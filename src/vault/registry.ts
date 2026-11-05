import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { Vault, type VaultData } from './store.js';
import { deriveKey, encrypt, decrypt, newKdf, type VaultFile } from './crypto.js';
import { identityContext } from '../auth/context.js';
import type { IdentityStore } from '../auth/store.js';
import { protectCredentials } from '../auth/files.js';

type Envelope = { version: 1; password: VaultFile; recovery: VaultFile };
async function wrap(secret: string, password: string) {
  if (password.length < 12 || password.length > 1024) throw new Error('Vault password must contain 12–1024 characters');
  const kdf = newKdf(), key = await deriveKey(password, Buffer.from(kdf.salt, 'base64'), kdf);
  try { return encrypt(key, kdf, secret); } finally { key.fill(0); }
}
async function unwrap(file: VaultFile, password: string) {
  const key = await deriveKey(password.slice(0, 1024), Buffer.from(file.kdf.salt, 'base64'), file.kdf);
  try { return decrypt(key, file); } catch { throw new Error('Wrong vault password or recovery key'); } finally { key.fill(0); }
}
export class PersonalVault extends Vault {
  private initializing = false;
  constructor(path: string, private envelopePath: string) { super(path); }
  override get exists() { return existsSync(this.envelopePath); }
  private envelope(): Envelope { return JSON.parse(readFileSync(this.envelopePath, 'utf8')); }
  private storeEnvelope(e: Envelope) { writeFileSync(this.envelopePath + '.tmp', JSON.stringify(e), { mode: 0o600 }); renameSync(this.envelopePath + '.tmp', this.envelopePath); }
  async initialize(password: string) {
    if (this.exists || this.initializing) throw new Error('Vault already exists or initialization in progress');
    this.initializing = true;
    try {
    const secret = randomBytes(32).toString('base64url'), recovery = randomBytes(32).toString('base64url');
    const envelope: Envelope = { version: 1, password: await wrap(secret, password), recovery: await wrap(secret, recovery) };
    await super.create(secret); this.storeEnvelope(envelope); return recovery;
    } finally { this.initializing = false; }
  }
  override async create(password: string) { await this.initialize(password); }
  override async unlock(password: string) { await super.unlock(await unwrap(this.envelope().password, password)); }
  override async verifyPassword(password: string) { await unwrap(this.envelope().password, password); }
  override async changePassword(oldPassword: string, password: string) { const e = this.envelope(); const secret = await unwrap(e.password, oldPassword); e.password = await wrap(secret, password); this.storeEnvelope(e); }
  async recover(recovery: string, password: string) {
    const e = this.envelope(), secret = await unwrap(e.recovery, recovery);
    await super.verifyPassword(secret);
    const replacement = randomBytes(32).toString('base64url');
    e.password = await wrap(secret, password); e.recovery = await wrap(secret, replacement);
    this.storeEnvelope(e); await super.unlock(secret); return replacement;
  }
}
export class VaultRegistry {
  private vaults = new Map<string, PersonalVault>();
  private migrating = false;
  onSave?: (owner: string, data: VaultData) => void;
  onLock?: (owner: string) => void;
  readonly legacy: Vault;
  constructor(private dir: string, readonly identities: IdentityStore) {
    this.legacy = new Vault(join(dir, 'vault.json'));
    identities.onRevokeUser = owner => this.vaults.get(owner)?.lock();
    mkdirSync(join(dir, 'vaults'), { recursive: true }); protectCredentials(join(dir, 'vaults'), true);
  }
  get(owner: string) {
    this.identities.user(owner);
    let vault = this.vaults.get(owner);
    if (!vault) {
      let record = this.identities.get<{ id: string }>('personal-vault', owner);
      if (!record) { record = { id: Vault.newId() }; this.identities.put('personal-vault', owner, record); }
      const path = join(this.dir, 'vaults', record.id);
      vault = new PersonalVault(path + '.json', path + '.envelope.json');
      vault.onLock = () => this.onLock?.(owner);
      vault.onSave = () => this.onSave?.(owner, vault!.d);
      this.vaults.set(owner, vault);
    }
    return vault;
  }
  current() { const owner = identityContext.getStore()?.userId; if (!owner) throw new Error('Authenticated vault owner required'); return this.get(owner); }
  facade(): Vault {
    return new Proxy({} as Vault, { get: (_target, property) => { const vault = this.current(); const value = Reflect.get(vault, property, vault); return typeof value === 'function' ? value.bind(vault) : value; }, set: () => { throw new Error('Registry vault hooks are managed per owner'); } });
  }
  async migrate(owner: string, oldPassword: string, password: string) {
    this.identities.user(owner);
    if (this.migrating) throw new Error('Un import al vaultului vechi este deja în curs.');
    if (this.identities.get('migration', 'legacy')) throw new Error('Vaultul vechi a fost deja atribuit unui cont.');
    const source = new Vault(join(this.dir, 'vault.json')), vault = this.get(owner);
    const wasUnlocked = vault.unlocked;
    this.migrating = true;
    try {
      await source.unlock(oldPassword);
      const existing = vault.exists;
      if (existing) {
        // An account created before migration may already have an empty personal vault.
        // Verify its password even when it is unlocked; keep its envelope/recovery key.
        if (vault.unlocked) await vault.verifyPassword(password); else await vault.unlock(password);
        if (!vault.unlocked) await vault.unlock(password);
        const current = vault.d;
        if (current.hosts.length || current.keys.length || current.clusters.length || current.checklist.length || current.tokens.length || current.sharedRefs?.length || Object.keys(current.knownHosts).length || current.tunnel) {
          throw new Error('Vaultul personal conține deja date. Importul a fost oprit fără a le suprascrie.');
        }
      }
      source.backup();
      if (existing) vault.backup();
      const data = structuredClone(source.d);
      const tunnel = data.tunnel;
      delete data.tunnel; data.tokens = []; data.sharedRefs = [];
      const recovery = existing ? undefined : await vault.initialize(password);
      Object.assign(vault.d, data); vault.save(); vault.touch();
      if (tunnel?.apiKey && !this.identities.get('runtime', 'tunnel')) this.identities.put('runtime', 'tunnel', { ...tunnel, apiKey: this.identities.seal(tunnel.apiKey), token: '', tokenId: '', autoStart: false });
      this.identities.put('migration', 'legacy', { owner, at: new Date().toISOString() });
      // Old cross-user grants must never carry over to the personal-vault model.
      for (const grant of this.identities.all<{ id: string }>('grant')) this.identities.del('grant', grant.id);
      return recovery;
    } catch (error) {
      if (!wasUnlocked) vault.lock();
      throw error;
    } finally { source.lock(); this.migrating = false; }
  }
  lockAll() { for (const v of this.vaults.values()) v.lock(); }
}
