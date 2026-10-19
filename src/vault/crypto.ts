import { createCipheriv, createDecipheriv, randomBytes, scrypt } from "node:crypto";

export interface VaultFile {
  v: 1;
  kdf: { name: "scrypt"; N: number; r: number; p: number; salt: string };
  nonce: string;
  tag: string;
  ct: string;
}

const KDF = { N: 1 << 17, r: 8, p: 1 };

export function deriveKey(password: string, salt: Buffer, params = KDF): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    scrypt(password, salt, 32, { ...params, maxmem: 256 * 1024 * 1024 }, (e, k) => (e ? reject(e) : resolve(k))),
  );
}

export function newKdf() {
  return { name: "scrypt" as const, ...KDF, salt: randomBytes(16).toString("base64") };
}

// The header (kdf params) is bound as AAD so it cannot be swapped without detection.
function aad(kdf: VaultFile["kdf"]): Buffer {
  return Buffer.from(JSON.stringify(kdf));
}

export function encrypt(key: Buffer, kdf: VaultFile["kdf"], plaintext: string): VaultFile {
  const nonce = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, nonce);
  c.setAAD(aad(kdf));
  const ct = Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
  return {
    v: 1,
    kdf,
    nonce: nonce.toString("base64"),
    tag: c.getAuthTag().toString("base64"),
    ct: ct.toString("base64"),
  };
}

export function decrypt(key: Buffer, f: VaultFile): string {
  const d = createDecipheriv("aes-256-gcm", key, Buffer.from(f.nonce, "base64"));
  d.setAAD(aad(f.kdf));
  d.setAuthTag(Buffer.from(f.tag, "base64"));
  return Buffer.concat([d.update(Buffer.from(f.ct, "base64")), d.final()]).toString("utf8");
}
