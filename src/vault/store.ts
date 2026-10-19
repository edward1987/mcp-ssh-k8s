import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { decrypt, deriveKey, encrypt, newKdf, type VaultFile } from "./crypto.js";

export type Mode = "read-only" | "approval" | "free";

export interface Host {
  id: string;
  name: string;
  hostname: string;
  port: number;
  user: string;
  auth: "key" | "password";
  keyId?: string;
  password?: string;
  mode: Mode;
  allowlist: string[]; // extra read-only command prefixes for this host
  group?: string;
  tags?: string[];
}

export interface Key {
  id: string;
  name: string;
  privateKey: string;
  passphrase?: string;
  publicKey?: string;
}

export interface Token {
  id: string;
  name: string;
  hash: string; // sha256 hex of the token
  created: string;
}

export interface VaultData {
  hosts: Host[];
  keys: Key[];
  tokens: Token[];
  knownHosts: Record<string, string>; // host id -> fingerprint
  settings: { autoLockMinutes: number; maxOutputBytes: number; approvalTimeoutSec: number };
  /** OpenAI Secure MCP Tunnel (ChatGPT). `token` is the raw bearer tunnel-client adds to calls to our MCP port. */
  tunnel?: { tunnelId: string; apiKey: string; token: string; tokenId: string; autoStart: boolean };
}

const empty = (): VaultData => ({
  hosts: [],
  keys: [],
  tokens: [],
  knownHosts: {},
  settings: { autoLockMinutes: 30, maxOutputBytes: 65536, approvalTimeoutSec: 120 },
});

export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

export class Vault {
  private key: Buffer | null = null;
  private kdf: VaultFile["kdf"] | null = null;
  private data: VaultData | null = null;
  private timer: NodeJS.Timeout | null = null;
  onLock?: () => void;

  constructor(private path: string) {}

  get exists() {
    return existsSync(this.path);
  }
  get unlocked() {
    return this.data !== null;
  }

  private require(): VaultData {
    if (!this.data) throw new Error("vault locked");
    return this.data;
  }
  get d(): VaultData {
    return this.require();
  }

  async create(password: string) {
    if (this.exists) throw new Error("vault already exists");
    if (password.length < 12) throw new Error("master password must be at least 12 characters");
    this.kdf = newKdf();
    this.key = await deriveKey(password, Buffer.from(this.kdf.salt, "base64"), this.kdf);
    this.data = empty();
    this.save();
    this.touch();
  }

  async unlock(password: string) {
    const f = JSON.parse(readFileSync(this.path, "utf8")) as VaultFile;
    const key = await deriveKey(password, Buffer.from(f.kdf.salt, "base64"), f.kdf);
    let plain: string;
    try {
      plain = decrypt(key, f);
    } catch {
      throw new Error("wrong password");
    }
    this.key = key;
    this.kdf = f.kdf;
    this.data = { ...empty(), ...JSON.parse(plain) };
    this.touch();
  }

  lock() {
    this.key?.fill(0);
    this.key = null;
    this.data = null;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.onLock?.();
  }

  /** Reset the idle auto-lock timer. */
  touch() {
    if (!this.data) return;
    if (this.timer) clearTimeout(this.timer);
    const min = this.data.settings.autoLockMinutes;
    if (min > 0) {
      this.timer = setTimeout(() => this.lock(), min * 60_000);
      this.timer.unref();
    }
  }

  save() {
    if (!this.key || !this.kdf || !this.data) throw new Error("vault locked");
    const out = encrypt(this.key, this.kdf, JSON.stringify(this.data));
    mkdirSync(dirname(this.path), { recursive: true });
    const tmp = this.path + ".tmp";
    writeFileSync(tmp, JSON.stringify(out), { mode: 0o600 });
    renameSync(tmp, this.path);
  }

  async changePassword(oldPw: string, newPw: string) {
    const f = JSON.parse(readFileSync(this.path, "utf8")) as VaultFile;
    const k = await deriveKey(oldPw, Buffer.from(f.kdf.salt, "base64"), f.kdf);
    try {
      decrypt(k, f);
    } catch {
      throw new Error("wrong password");
    }
    if (newPw.length < 12) throw new Error("master password must be at least 12 characters");
    this.kdf = newKdf();
    this.key = await deriveKey(newPw, Buffer.from(this.kdf.salt, "base64"), this.kdf);
    this.save();
  }

  // ---- tokens ----
  verifyToken(raw: string): Token | null {
    if (!this.data) return null;
    const h = Buffer.from(sha256(raw));
    for (const t of this.data.tokens) {
      const th = Buffer.from(t.hash);
      if (th.length === h.length && timingSafeEqual(th, h)) return t;
    }
    return null;
  }

  static newId = () => randomUUID();
}
