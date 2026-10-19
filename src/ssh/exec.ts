import ssh2, { type ConnectConfig } from "ssh2";

const { Client } = ssh2;
import { createHash } from "node:crypto";
import type { Host, Vault } from "../vault/store.js";

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  truncated: boolean;
  timedOut: boolean;
}

function connectConfig(vault: Vault, host: Host): ConnectConfig {
  const cfg: ConnectConfig = {
    host: host.hostname,
    port: host.port,
    username: host.user,
    readyTimeout: 15_000,
    keepaliveInterval: 10_000,
    // Trust-on-first-use: pin the fingerprint, refuse if it later changes.
    hostVerifier: (key: Buffer) => {
      const fp = "SHA256:" + createHash("sha256").update(key).digest("base64").replace(/=+$/, "");
      const known = vault.d.knownHosts[host.id];
      if (!known) {
        vault.d.knownHosts[host.id] = fp;
        vault.save();
        return true;
      }
      return known === fp;
    },
  };
  if (host.auth === "key") {
    const k = vault.d.keys.find((x) => x.id === host.keyId);
    if (!k) throw new Error(`key not found for host ${host.name}`);
    cfg.privateKey = k.privateKey;
    if (k.passphrase) cfg.passphrase = k.passphrase;
  } else {
    cfg.password = host.password;
  }
  return cfg;
}

export function runSsh(vault: Vault, host: Host, command: string, timeoutSec = 30): Promise<ExecResult> {
  const max = vault.d.settings.maxOutputBytes;
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let out = "", err = "", truncated = false, timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      conn.end();
    }, timeoutSec * 1000);
    const add = (cur: string, chunk: Buffer) => {
      if (cur.length >= max) {
        truncated = true;
        return cur;
      }
      return cur + chunk.toString("utf8");
    };
    conn
      .on("ready", () => {
        conn.exec(command, (e, stream) => {
          if (e) {
            clearTimeout(timer);
            conn.end();
            return reject(e);
          }
          stream
            .on("close", (code: number | null) => {
              clearTimeout(timer);
              conn.end();
              resolve({
                stdout: out.slice(0, max),
                stderr: err.slice(0, max),
                exitCode: timedOut ? null : code,
                truncated: truncated || out.length > max || err.length > max,
                timedOut,
              });
            })
            .on("data", (d: Buffer) => (out = add(out, d)));
          stream.stderr.on("data", (d: Buffer) => (err = add(err, d)));
        });
      })
      .on("error", (e) => {
        clearTimeout(timer);
        reject(e);
      })
      .on("close", () => {
        if (timedOut) resolve({ stdout: out, stderr: err, exitCode: null, truncated, timedOut });
      });
    try {
      conn.connect(connectConfig(vault, host));
    } catch (e) {
      clearTimeout(timer);
      reject(e);
    }
  });
}
