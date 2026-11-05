import { randomBytes } from 'node:crypto';
import { Vault, sha256, type VaultData } from './store.js';
import { encrypt, decrypt, newKdf, type VaultFile } from './crypto.js';
import type { IdentityStore } from '../auth/store.js';
import { identityContext } from '../auth/context.js';
import type { VaultRegistry } from './registry.js';
import type { Ctx } from '../service.js';
import { runCommand, runKube } from '../service.js';

export interface Share {
  id: string; owner: string; recipient: string; type: 'host' | 'cluster'; resource: string; alias: string;
  policy: 'limited' | 'approval' | 'unrestricted'; operations: { id: string; name: string; command: string }[];
  approvers: string[]; expires: number; revoked: boolean;
}
type Secret = { id: string; key: string; payload: VaultFile };
export class ShareBroker {
  onRevoke?: (id: string) => void;
  constructor(readonly store: IdentityStore, readonly registry: VaultRegistry) { registry.onSave = (owner, data) => this.sync(owner, data); }
  private resourceId(s: Share) { return `${s.owner}:${s.type}:${s.resource}`; }
  sync(owner: string, data: VaultData) {
    for (const s of this.store.all<Share>('share').filter(s => s.owner === owner && !s.revoked)) {
      const resource = (s.type === 'host' ? data.hosts : data.clusters).find(r => r.id === s.resource);
      if (!resource) { s.revoked = true; this.store.put('share', s.id, s); continue; }
      const id = this.resourceId(s), existing = this.store.get<Secret>('shared-secret', id);
      if (s.type === 'host' && data.knownHosts[resource.id]) this.store.put('shared-pin', id, data.knownHosts[resource.id]);
      const key = existing ? Buffer.from(this.store.open(existing.key), 'base64') : randomBytes(32);
      const snapshot: VaultData = { hosts: s.type === 'host' ? [structuredClone(resource) as any] : [], clusters: s.type === 'cluster' ? [structuredClone(resource) as any] : [], keys: s.type === 'host' ? data.keys.filter(k => k.id === (resource as any).keyId) : [], knownHosts: { [resource.id]: data.knownHosts[resource.id] }, tokens: [], checklist: [], settings: structuredClone(data.settings) };
      this.store.put('shared-secret', id, { id, key: this.store.seal(key.toString('base64')), payload: encrypt(key, newKdf(), JSON.stringify(snapshot)) }); key.fill(0);
    }
  }
  create(owner: string, input: Omit<Share, 'id' | 'owner' | 'revoked'>) {
    const vault = this.registry.get(owner); if (!vault.unlocked) throw new Error('Vault locked');
    this.store.user(input.recipient);
    if (input.recipient === owner || !['host', 'cluster'].includes(input.type) || !['limited', 'approval', 'unrestricted'].includes(input.policy) || !input.alias?.trim() || input.alias.length > 100 || !Number.isFinite(input.expires) || input.expires <= Date.now()) throw new Error('Invalid share');
    if (!Array.isArray(input.operations) || input.operations.some(o => !o.id || !o.name || !o.command || o.command.length > 10000) || new Set(input.operations.map(o => o.id)).size !== input.operations.length) throw new Error('Invalid operations');
    if (!(input.type === 'host' ? vault.d.hosts : vault.d.clusters).some(r => r.id === input.resource)) throw new Error('Resource unavailable');
    if (!Array.isArray(input.approvers) || input.approvers.includes(input.recipient)) throw new Error('Requester cannot approve');
    input.approvers.forEach(id => this.store.user(id));
    const share = { ...input, id: Vault.newId(), owner, revoked: false };
    this.store.put('share', share.id, share); this.sync(owner, vault.d); return share;
  }
  revoke(owner: string, id: string) { const s = this.store.get<Share>('share', id); if (!s || s.owner !== owner) throw new Error('Unavailable'); s.revoked = true; this.store.put('share', id, s); this.onRevoke?.(id); }
  private authorized(user: string, id: string) {
    this.store.user(user);
    if (!this.registry.get(user).unlocked) throw new Error('Vault locked');
    const principal = identityContext.getStore();
    if (principal?.sessionId) { const session = this.store.get<any>('session', principal.sessionId); if (!session || session.expires <= Date.now() || session.idle <= Date.now()) throw new Error('Unauthorized'); }
    if (principal?.token) { const t = this.store.get<any>('access', sha256(principal.token)); if (!t || t.userId !== user || t.expires <= Date.now()) throw new Error('Unauthorized'); }
    const s = this.store.get<Share>('share', id);
    if (!s || s.recipient !== user || s.revoked || s.expires <= Date.now()) throw new Error('Shared resource unavailable');
    this.store.user(s.owner); return s;
  }
  list(user: string) {
    const v = this.registry.get(user); if (!v.unlocked) throw new Error('Vault locked');
    const shares = this.store.all<Share>('share').filter(s => { try { this.authorized(user, s.id); return true; } catch { return false; } });
    const refs = shares.map(s => s.id); if (JSON.stringify(refs) !== JSON.stringify(v.d.sharedRefs)) { v.d.sharedRefs = refs; v.save(); }
    return shares.map(s => ({ id: s.id, alias: s.alias, type: s.type, policy: s.policy, expires: s.expires, operations: s.operations.map(o => ({ id: o.id, name: o.name })) }));
  }
  async execute(ctx: Ctx, user: string, id: string, operation: string | undefined, command: string | undefined, timeout = 60) {
    let s = this.authorized(user, id);
    const selected = s.operations.find(o => o.id === operation);
    const actual = s.policy === 'limited' ? selected?.command : command;
    if (!actual?.trim() || actual.length > 10000) throw new Error('Operation unavailable');
    const secret = this.store.get<Secret>('shared-secret', this.resourceId(s)); if (!secret) throw new Error('Shared resource unavailable');
    const key = Buffer.from(this.store.open(secret.key), 'base64'); let data: VaultData;
    try { data = JSON.parse(decrypt(key, secret.payload)); } finally { key.fill(0); }
    const resource = (s.type === 'host' ? data.hosts : data.clusters)[0];
    if (s.policy === 'approval' || resource.mode === 'approval') {
      const decision = await ctx.approvals.request({ host: s.alias, command: s.policy === 'limited' ? selected!.name : actual, client: identityContext.getStore()?.clientId ?? 'web', approvers: [s.owner, ...s.approvers], shareId: s.id }, 120);
      if (decision !== 'approved') throw new Error('Operation not approved');
    }
    const current = this.authorized(user, id);
    if (JSON.stringify(current) !== JSON.stringify(s)) throw new Error('Sharing policy changed; retry');
    // No further async work before execution: use the current synchronized connection.
    const latest = this.store.get<Secret>('shared-secret', this.resourceId(s))!;
    const latestKey = Buffer.from(this.store.open(latest.key), 'base64');
    try { data = JSON.parse(decrypt(latestKey, latest.payload)); } finally { latestKey.fill(0); }
    const target = (s.type === 'host' ? data.hosts : data.clusters)[0];
    const pin = this.store.get<string>('shared-pin', this.resourceId(s));
    if (s.type === 'host' && pin) data.knownHosts[target.id] = pin;
    if (target.mode !== resource.mode) throw new Error('Resource policy changed; retry');
    if (target.mode === 'approval') target.mode = 'free'; // This exact command was approved above.
    const executionVault = Object.create(Vault.prototype) as Vault;
    Object.defineProperty(executionVault, 'd', { get: () => data }); Object.defineProperty(executionVault, 'unlocked', { get: () => true });
    executionVault.touch = () => {};
    executionVault.save = () => {
      if (s.type !== 'host' || !data.knownHosts[target.id]) return;
      const current = this.store.get<string>('shared-pin', this.resourceId(s));
      if (current && current !== data.knownHosts[target.id]) throw new Error('Host identity changed');
      this.store.put('shared-pin', this.resourceId(s), data.knownHosts[target.id]);
    };
    const internal: Ctx = { vault: executionVault, audit: { log: () => {}, tail: () => [] } as any, approvals: ctx.approvals };
    try {
      const result = s.type === 'host' ? await runCommand(internal, 'share', target.id, actual, timeout) : await runKube(internal, 'share', target.id, actual, undefined, timeout);
      ctx.audit.log({ client: identityContext.getStore()?.clientId ?? 'web', userId: user, host: s.alias, action: 'shared-operation', outcome: result.timedOut ? 'timeout' : 'ok' });
      return result;
    } catch { throw new Error('Shared operation failed'); }
  }
}
