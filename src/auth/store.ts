import { protectCredentials } from "./files.js";
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { TOTP, Secret } from 'otpauth';
import { deriveKey, encrypt, decrypt, newKdf } from '../vault/crypto.js';
import { sha256 } from '../vault/store.js';

export const randomToken = () => randomBytes(32).toString('base64url');
export interface User { id: string; name: string; role: 'administrator' | 'member'; disabled: boolean; password?: string; salt?: string; secret?: string; recovery: string[]; counter: number }
export interface Principal { userId: string; clientId: string; token?: string; sessionId?: string; operator?: boolean }
export interface Grant { id: string; subject: string; kind: 'user' | 'group'; resource: string; type: 'host' | 'cluster' }
export class IdentityStore {
  onRevokeUser?: (id: string) => void;
  readonly db: DatabaseSync;
  private key: Buffer;
  constructor(dir: string) {
    dir = join(dir, "identity");
    mkdirSync(dir, { recursive: true });
    protectCredentials(dir, true);
    const keyPath = join(dir, 'identity.key');
    if (existsSync(join(dir, 'identity.sqlite')) && !existsSync(keyPath)) throw new Error('Identity encryption key is missing; restore it from backup');
    if (!existsSync(keyPath)) writeFileSync(keyPath, randomBytes(32), { mode: 0o600, flag: 'wx' });
    this.key = readFileSync(keyPath);
    if (this.key.length !== 32) throw new Error('Invalid identity encryption key');
    this.db = new DatabaseSync(join(dir, 'identity.sqlite'));
    protectCredentials(join(dir, 'identity.sqlite'));
    protectCredentials(keyPath);
    this.db.exec('PRAGMA journal_mode=DELETE; CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL, id TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(kind,id))');
  }
  get<T>(kind: string, id: string): T | undefined { const r = this.db.prepare('SELECT value FROM records WHERE kind=? AND id=?').get(kind, id); return r ? JSON.parse(String(r.value)) : undefined; }
  all<T>(kind: string): T[] { return this.db.prepare('SELECT value FROM records WHERE kind=?').all(kind).map(r => JSON.parse(String(r.value))); }
  put(kind: string, id: string, value: unknown) { this.db.prepare('INSERT OR REPLACE INTO records VALUES (?,?,?)').run(kind, id, JSON.stringify(value)); }
  del(kind: string, id: string) { this.db.prepare('DELETE FROM records WHERE kind=? AND id=?').run(kind, id); }
  seal(s: string) { return JSON.stringify(encrypt(this.key, newKdf(), s)); }
  open(s: string) { return decrypt(this.key, JSON.parse(s)); }
  user(id: string) { const u = this.get<User>('user', id); if (!u || u.disabled || !u.password || !u.secret) throw new Error('unauthorized'); return u; }
  invite(name: string, role: User['role'] = 'member', id: string = randomUUID()) {
    if (!name.trim() || name.length > 100 || this.all<User>('user').some(u => u.name.toLowerCase() === name.toLowerCase() && u.id !== id)) throw new Error('Invalid or duplicate username');
    this.revokeUser(id);
    const user: User = { id, name, role, disabled: false, recovery: [], counter: -1 };
    this.put('user', id, user);
    const token = randomToken(); const secret = new Secret({ size: 20 }).base32;
    this.put('invite', sha256(token), { id: sha256(token), userId: id, expires: Date.now() + 86400000, secret: this.seal(secret) });
    return token;
  }
  enrollment(token: string) {
    const i = this.get<{ userId: string; expires: number; secret: string }>('invite', sha256(token));
    if (!i || i.expires < Date.now()) throw new Error('Invalid invitation');
    const u = this.get<User>('user', i.userId)!;
    return { i, u, secret: this.open(i.secret) };
  }
  async activate(token: string, password: string, otp: string) {
    const { i, u, secret } = this.enrollment(token);
    if (password.length < 12 || password.length > 1024) throw new Error('Password must contain 12–1024 characters');
    const counter = this.checkOtp(secret, otp, -1);
    const salt = randomBytes(16); const hash = (await deriveKey(password, salt)).toString('hex');
    // Recheck after asynchronous password hashing to prevent invitation reuse.
    this.enrollment(token);
    const recovery = Array.from({ length: 10 }, randomToken);
    this.put('user', u.id, { ...u, salt: salt.toString('hex'), password: hash, secret: i.secret, counter: counter - 1, recovery: recovery.map(sha256) });
    this.del('invite', sha256(token)); return recovery;
  }
  checkOtp(secret: string, otp: string, last: number) {
    const totp = new TOTP({ secret: Secret.fromBase32(secret), algorithm: 'SHA1', digits: 6, period: 30 });
    const delta = totp.validate({ token: otp, window: 1 });
    const counter = Math.floor(Date.now() / 30000) + (delta ?? 0);
    if (delta === null || counter <= last) throw new Error('Invalid credentials');
    return counter;
  }
  async login(name: string, password: string, otp: string) {
    const candidate = this.all<User>('user').find(u => u.name === name);
    const hash = await deriveKey(password.slice(0, 1024), Buffer.from(candidate?.salt ?? '00000000000000000000000000000000', 'hex'));
    const u = candidate ? this.user(candidate.id) : undefined;
    if (!u || !timingSafeEqual(hash, Buffer.from(u.password!, 'hex'))) throw new Error('Invalid credentials');
    if (u.recovery.includes(sha256(otp))) { u.recovery = u.recovery.filter(x => x !== sha256(otp)); this.revokeUser(u.id); }
    else u.counter = this.checkOtp(this.open(u.secret!), otp, u.counter);
    this.put('user', u.id, u); return u;
  }
  revokeUser(id: string) {
    for (const kind of ['session', 'access', 'refresh', 'code', 'invite']) for (const r of this.all<any>(kind)) if (r.userId === id) this.del(kind, r.id ?? r.hash);
    this.onRevokeUser?.(id);
  }
  can(p: Principal, type: Grant['type'], resource: string): boolean {
    try {
      const u = this.user(p.userId);
      if (p.token) { const t = this.get<any>('access', sha256(p.token)); if (!t || t.expires < Date.now() || t.userId !== u.id || !t.scopes.includes('mcp:use')) return false; }
      if (u.role === 'administrator') return true;
      const groups = this.all<{ id: string; members: string[] }>('group').filter(g => g.members.includes(u.id)).map(g => g.id);
      return this.all<Grant>('grant').some(g => g.type === type && g.resource === resource && (g.kind === 'user' ? g.subject === u.id : groups.includes(g.subject)));
    } catch { return false; }
  }
  require(p: Principal, type: Grant['type'], resource: string) { if (!this.can(p, type, resource)) throw new Error('Resource unavailable'); }
}
