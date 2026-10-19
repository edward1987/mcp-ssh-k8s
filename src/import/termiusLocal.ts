import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import nacl from "tweetnacl";

/**
 * Reads the Termius desktop app's local vault, offline, on the machine where it is installed (Windows).
 *
 * - Records live in Chromium IndexedDB (LevelDB). scripts/termius_dump.py (ccl_chromium_reader) dumps a read-only
 *   copy as JSON; every secret field is still ciphertext at that point.
 * - A field is   base64( 0x04 0x01 | nonce[24] | XSalsa20-Poly1305 )  (NaCl secretbox), decrypted here with the
 *   32-byte "localKey" from Windows Credential Manager (target "Termius/localKey").
 * - Model: host -> ssh_config (port, identity) -> ssh_identity (username, password, ssh_key) -> key (private_key);
 *   hosts inherit the ssh_config of their group when they have none.
 */

const CS = `
using System; using System.Runtime.InteropServices;
public class Cred {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct CREDENTIAL { public int Flags; public int Type; public string TargetName; public string Comment; public long LastWritten;
    public int CredentialBlobSize; public IntPtr CredentialBlob; public int Persist; public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName; }
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern bool CredReadW(string target, int type, int flags, out IntPtr cred);
  [DllImport("advapi32.dll")] public static extern void CredFree(IntPtr p);
  public static string Read(string t) {
    IntPtr p; if (!CredReadW(t, 1, 0, out p)) return "";
    var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
    var b = new byte[c.CredentialBlobSize]; Marshal.Copy(c.CredentialBlob, b, 0, b.Length); CredFree(p);
    return Convert.ToBase64String(b);
  }
}`;

/** Candidate 32-byte keys from Credential Manager (the blob is UTF-8 base64, possibly raw bytes). */
export function readLocalKeys(): Uint8Array[] {
  if (process.platform !== "win32") throw new Error("local Termius import is implemented for Windows only");
  const ps = `Add-Type -TypeDefinition @'\n${CS}\n'@\n[Cred]::Read('Termius/localKey')`;
  const r = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(ps, "utf16le").toString("base64")], {
    encoding: "utf8",
    windowsHide: true,
  });
  const blobB64 = (r.stdout ?? "").trim();
  if (!blobB64) throw new Error('Termius key not found in Windows Credential Manager (target "Termius/localKey"). Is Termius installed and signed in on this PC?');
  const blob = Buffer.from(blobB64, "base64");
  const out: Uint8Array[] = [];
  const asText = Buffer.from(blob.toString("utf8").trim(), "base64");
  if (asText.length === 32) out.push(new Uint8Array(asText));
  if (blob.length === 32) out.push(new Uint8Array(blob));
  if (!out.length) throw new Error("unexpected Termius key format in Credential Manager");
  return out;
}

export function decryptBlob(b64: string, keys: Uint8Array[]): string | null {
  const data = Buffer.from(b64, "base64");
  if (data.length < 42 || data[0] !== 4) return null; // 42 = header 2 + nonce 24 + MAC 16 (empty plaintext is valid)
  const nonce = new Uint8Array(data.subarray(2, 26));
  const box = new Uint8Array(data.subarray(26));
  for (const key of keys) {
    const plain = nacl.secretbox.open(box, nonce, key);
    if (plain) return Buffer.from(plain).toString("utf8");
  }
  return null;
}

// ---------- python helper (ccl_chromium_reader) ----------

const dataDirOf = (dataDir: string) => join(dataDir, "py");
const pyExe = (dataDir: string) => join(dataDirOf(dataDir), "Scripts", "python.exe");

export function termiusDbDir(): string | null {
  const base = process.env.APPDATA;
  const dir = base && join(base, "Termius", "IndexedDB", "file__0.indexeddb.leveldb");
  return dir && existsSync(dir) ? dir : null;
}

export function helperReady(dataDir: string) {
  const exe = pyExe(dataDir);
  if (!existsSync(exe)) return false;
  return spawnSync(exe, ["-c", "import ccl_chromium_reader"], { windowsHide: true }).status === 0;
}

/** Creates data/py (venv) and installs ccl_chromium_reader from GitHub (not on PyPI). */
export function setupHelper(dataDir: string) {
  const venv = dataDirOf(dataDir);
  if (!existsSync(pyExe(dataDir))) {
    const tries: [string, string[]][] = [["python", ["-m", "venv", venv]], ["py", ["-3", "-m", "venv", venv]]];
    let ok = false;
    for (const [cmd, args] of tries) if (spawnSync(cmd, args, { windowsHide: true }).status === 0) { ok = true; break; }
    if (!ok) throw new Error("Python 3 is required (python.exe not found in PATH)");
  }
  const r = spawnSync(pyExe(dataDir), ["-m", "pip", "install", "--quiet", "git+https://github.com/cclgroupltd/ccl_chromium_reader"], {
    windowsHide: true,
    encoding: "utf8",
    timeout: 300_000,
  });
  if (r.status !== 0) throw new Error("pip install failed (git and internet access are required): " + (r.stderr || "").slice(-400));
}

export type Dump = Record<string, Record<string, any>[]>;

export function runDump(dataDir: string, scriptPath: string): Dump {
  const r = spawnSync(pyExe(dataDir), [scriptPath], { encoding: "utf8", maxBuffer: 200 * 1024 * 1024, windowsHide: true, timeout: 120_000 });
  if (r.status !== 0) throw new Error("could not read the Termius database: " + (r.stderr || r.error?.message || "").slice(-400));
  return JSON.parse(r.stdout);
}

// ---------- model ----------

export interface TermiusKey {
  id: number;
  label: string;
  privateKey: string;
  passphrase?: string;
}
export interface TermiusHost {
  termiusId: number;
  name: string;
  address: string;
  port: number;
  user: string;
  password?: string;
  keyId?: number;
  group?: string;
}
export interface TermiusImport {
  hosts: TermiusHost[];
  keys: TermiusKey[];
  stats: Record<string, number>;
}

type Rec = Record<string, any>;

const live = (r: Rec) => !String(r.status ?? "").toUpperCase().includes("DELETE");

/** LevelDB keeps old versions of every record: keep the newest per id. */
function latest(list: Rec[] = []): Map<number, Rec> {
  const m = new Map<number, Rec>();
  for (const r of list) {
    const cur = m.get(r.id);
    if (!cur || String(r.updated_at ?? "") >= String(cur.updated_at ?? "")) m.set(r.id, r);
  }
  for (const [id, r] of m) if (!live(r)) m.delete(id);
  return m;
}

export function buildFromDump(dump: Dump, localKeys: Uint8Array[]): TermiusImport {
  const dec = (v: any): any => (typeof v === "string" && v.startsWith("BA") ? (decryptBlob(v, localKeys) ?? v) : v);
  const str = (v: any) => (typeof v === "string" ? v : "");

  const keyRecs = latest(dump.keys);
  const keys = new Map<number, TermiusKey>();
  for (const [id, r] of keyRecs) {
    const pk = str(dec(r.private_key));
    if (!pk.includes("PRIVATE KEY")) continue;
    keys.set(id, { id, label: str(dec(r.label)) || `termius key ${id}`, privateKey: pk, passphrase: str(dec(r.passphrase)) || undefined });
  }

  const identities = latest(dump.ssh_identities);
  const configs = latest(dump.ssh_configs);
  const groups = latest(dump.groups);
  const cfgIdentities = latest(dump.ssh_config_identities);

  const identityOf = (cfg?: Rec): Rec | undefined => {
    if (!cfg) return undefined;
    const direct = cfg.identity?.id != null ? identities.get(cfg.identity.id) : undefined;
    if (direct) return direct;
    for (const link of cfgIdentities.values()) if (link.ssh_config?.id === cfg.id && identities.get(link.identity?.id)) return identities.get(link.identity.id);
    return undefined;
  };

  const groupPath = (gid?: number): string | undefined => {
    const parts: string[] = [];
    for (let g = gid != null ? groups.get(gid) : undefined, n = 0; g && n < 20; n++) {
      parts.unshift(str(dec(g.label)));
      g = g.parent_group?.id != null ? groups.get(g.parent_group.id) : undefined;
    }
    return parts.length ? parts.join("/") : undefined;
  };

  // Config inherited from the nearest ancestor group that has one.
  const inheritedCfg = (gid?: number): Rec | undefined => {
    for (let g = gid != null ? groups.get(gid) : undefined, n = 0; g && n < 20; n++) {
      const cfg = g.ssh_config?.id != null ? configs.get(g.ssh_config.id) : undefined;
      if (cfg) return cfg;
      g = g.parent_group?.id != null ? groups.get(g.parent_group.id) : undefined;
    }
    return undefined;
  };

  const hosts: TermiusHost[] = [];
  const usedKeys = new Set<number>();
  for (const [id, h] of latest(dump.hosts)) {
    if (h.telnet_config?.id != null && h.ssh_config?.id == null) continue; // telnet only
    const address = str(dec(h.address)).trim();
    if (!address) continue;
    const own = h.ssh_config?.id != null ? configs.get(h.ssh_config.id) : undefined;
    const inh = inheritedCfg(h.group?.id);
    const ident = identityOf(own) ?? identityOf(inh);
    const keyId = ident?.ssh_key?.id != null && keys.has(ident.ssh_key.id) ? ident.ssh_key.id : undefined;
    if (keyId != null) usedKeys.add(keyId);
    hosts.push({
      termiusId: id,
      name: str(dec(h.label)).trim() || address,
      address,
      port: Number(own?.port ?? inh?.port) || 22,
      user: str(dec(ident?.username)),
      password: keyId == null ? str(dec(ident?.password)) || undefined : undefined,
      keyId,
      group: groupPath(h.group?.id),
    });
  }
  hosts.sort((a, b) => (a.group ?? "").localeCompare(b.group ?? "") || a.name.localeCompare(b.name));
  return {
    hosts,
    keys: [...keys.values()],
    stats: { hosts: hosts.length, keys: keys.size, usedKeys: usedKeys.size, groups: groups.size },
  };
}
