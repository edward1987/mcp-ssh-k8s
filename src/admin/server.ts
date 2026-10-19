import express from "express";
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import ssh2 from "ssh2";

const { utils } = ssh2;
import { parseSshConfig, type ImportedHost } from "../import/sshconfig.js";
import { parseTermiusCsv } from "../import/termius.js";
import { buildFromDump, helperReady, readLocalKeys, runDump, setupHelper, termiusDbDir, type TermiusImport } from "../import/termiusLocal.js";
import { inspectKubeconfig, runKubectl } from "../k8s/kubectl.js";
import { findHost, formatResult, type Ctx } from "../service.js";
import { runSsh } from "../ssh/exec.js";
import type { TunnelManager } from "../tunnel/manager.js";
import { normalizeKey } from "../vault/keys.js";
import { sha256, type Cluster, type Host, type Mode } from "../vault/store.js";

const MODES: Mode[] = ["read-only", "approval", "free"];

export function startAdmin(ctx: Ctx, port: number, webDir: string, tunnel: TunnelManager, opts: { dataDir: string; scriptsDir: string }) {
  const { vault, audit, approvals } = ctx;
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "5mb" }));

  const sessions = new Map<string, { csrf: string }>();
  vault.onLock = () => {
    sessions.clear();
    approvals.denyAll();
    tunnel.stop();
    ctx.monitor?.stop();
  };
  const allowedHosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  let loginFails = 0;
  let lockedUntil = 0;

  // DNS-rebinding / cross-origin protection: only loopback Host and same-origin requests.
  app.use((req, res, next) => {
    if (!allowedHosts.has(req.headers.host ?? "")) return void res.status(403).send("forbidden host");
    const origin = req.headers.origin;
    if (origin && !allowedHosts.has(origin.replace(/^https?:\/\//, ""))) return void res.status(403).send("forbidden origin");
    res.setHeader("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "no-store");
    next();
  });

  const cookie = (req: express.Request) => /(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.cookie ?? "")?.[1];
  const startSession = (res: express.Response) => {
    const sid = randomBytes(32).toString("hex");
    const csrf = randomBytes(24).toString("hex");
    sessions.set(sid, { csrf });
    res.setHeader("Set-Cookie", `sid=${sid}; HttpOnly; SameSite=Strict; Path=/`);
    return csrf;
  };
  const eq = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

  const auth: express.RequestHandler = (req, res, next) => {
    const s = sessions.get(cookie(req) ?? "");
    if (!s || !vault.unlocked) return void res.status(401).json({ error: "locked" });
    if (req.method !== "GET" && !eq(String(req.headers["x-csrf-token"] ?? ""), s.csrf))
      return void res.status(403).json({ error: "bad csrf token" });
    vault.touch();
    next();
  };

  const wrap =
    (fn: (req: express.Request, res: express.Response) => unknown | Promise<unknown>): express.RequestHandler =>
    async (req, res) => {
      try {
        res.json((await fn(req, res)) ?? { ok: true });
      } catch (e) {
        res.status(400).json({ error: (e as Error).message });
      }
    };

  // ---- session ----
  app.get("/api/status", (req, res) => {
    const s = sessions.get(cookie(req) ?? "");
    res.json({ exists: vault.exists, unlocked: vault.unlocked && !!s, csrf: vault.unlocked && s ? s.csrf : undefined });
  });
  app.post(
    "/api/setup",
    wrap(async (req, res) => {
      await vault.create(String(req.body.password ?? ""));
      ctx.monitor?.start();
      return { csrf: startSession(res) };
    }),
  );
  app.post(
    "/api/unlock",
    wrap(async (req, res) => {
      if (Date.now() < lockedUntil) throw new Error("too many attempts, wait a bit");
      try {
        // Already unlocked (e.g. the browser session expired): re-verify the password and open a new session.
        if (vault.unlocked) await vault.verifyPassword(String(req.body.password ?? ""));
        else await vault.unlock(String(req.body.password ?? ""));
      } catch (e) {
        if (++loginFails >= 5) {
          lockedUntil = Date.now() + 30_000;
          loginFails = 0;
        }
        throw e;
      }
      loginFails = 0;
      tunnel.autoStart();
      ctx.monitor?.start();
      return { csrf: startSession(res) };
    }),
  );
  app.post("/api/lock", auth, wrap(() => vault.lock()));

  // ---- hosts ----
  const publicHost = (h: Host) => {
    const k = vault.d.keys.find((x) => x.id === h.keyId);
    const st = ctx.monitor?.get(h);
    return {
      ...h,
      online: st?.online,
      checking: ctx.monitor?.checking,
      checkedAt: st?.checkedAt,
      latencyMs: st?.ms,
      offlineReason: st?.error,
      password: undefined,
      hasPassword: !!h.password,
      fingerprint: vault.d.knownHosts[h.id],
      keyName: k?.name,
      keyValid: k ? hasPrivatePart(k) : undefined,
      keyFingerprint: k?.publicKey ? "SHA256:" + createHash("sha256").update(Buffer.from(k.publicKey.split(" ")[1] ?? "", "base64")).digest("base64").replace(/=+$/, "") : undefined,
    };
  };
  const readHost = (b: any, old?: Host): Host => {
    if (!b.name || !b.hostname || !b.user) throw new Error("name, hostname and user are required");
    if (!MODES.includes(b.mode)) throw new Error("invalid mode");
    const authType = b.auth === "password" ? "password" : "key";
    if (authType === "key" && !vault.d.keys.some((k) => k.id === b.keyId)) throw new Error("select a key");
    const dup = vault.d.hosts.find((h) => h.name.toLowerCase() === String(b.name).toLowerCase() && h.id !== old?.id);
    if (dup) throw new Error("a host with this name already exists");
    return {
      id: old?.id ?? randomUUID(),
      name: String(b.name).trim(),
      hostname: String(b.hostname).trim(),
      port: Number(b.port) || 22,
      user: String(b.user).trim(),
      auth: authType,
      keyId: authType === "key" ? b.keyId : undefined,
      password: authType === "password" ? b.password || old?.password : undefined,
      mode: b.mode,
      allowlist: Array.isArray(b.allowlist) ? b.allowlist.map(String).filter(Boolean) : [],
      group: b.group || undefined,
      tags: Array.isArray(b.tags) ? b.tags : undefined,
    };
  };
  app.get("/api/hosts", auth, wrap(() => vault.d.hosts.map(publicHost)));
  app.post(
    "/api/hosts/mode",
    auth,
    wrap((req) => {
      if (!MODES.includes(req.body.mode)) throw new Error("invalid mode");
      const ids = new Set<string>(Array.isArray(req.body.ids) ? req.body.ids.map(String) : []);
      let n = 0;
      for (const h of vault.d.hosts) if (ids.has(h.id)) (h.mode = req.body.mode), n++;
      if (n) vault.save();
      return { updated: n };
    }),
  );
  app.post(
    "/api/hosts/check",
    auth,
    wrap(() => {
      void ctx.monitor?.check().catch(() => {}); // fire and forget; the UI picks up results as they arrive
      return { checking: true };
    }),
  );
  app.post(
    "/api/hosts",
    auth,
    wrap((req) => {
      const h = readHost(req.body);
      vault.d.hosts.push(h);
      vault.save();
      return publicHost(h);
    }),
  );
  app.put(
    "/api/hosts/:id",
    auth,
    wrap((req) => {
      const i = vault.d.hosts.findIndex((h) => h.id === req.params.id);
      if (i < 0) throw new Error("not found");
      const h = readHost(req.body, vault.d.hosts[i]);
      if (req.body.resetFingerprint) delete vault.d.knownHosts[h.id];
      vault.d.hosts[i] = h;
      vault.save();
      return publicHost(h);
    }),
  );
  app.delete(
    "/api/hosts/:id",
    auth,
    wrap((req) => {
      vault.d.hosts = vault.d.hosts.filter((h) => h.id !== req.params.id);
      delete vault.d.knownHosts[String(req.params.id)];
      vault.save();
    }),
  );
  app.post(
    "/api/hosts/:id/test",
    auth,
    wrap(async (req) => {
      const r = await runSsh(vault, findHost(vault, String(req.params.id)), "echo connected && whoami", 15);
      return { output: formatResult(r) };
    }),
  );

  // ---- keys ----
  /** Does the stored value actually contain a usable private key (older versions accepted public keys)? */
  const hasPrivatePart = (k: { privateKey: string; passphrase?: string }) => {
    const p = utils.parseKey(k.privateKey, k.passphrase || undefined);
    const one = Array.isArray(p) ? p[0] : p;
    return !(one instanceof Error) && one.getPrivatePEM() !== null;
  };
  const publicKey = (k: { id: string; name: string; publicKey?: string; passphrase?: string; privateKey: string }) => ({
    id: k.id,
    name: k.name,
    publicKey: k.publicKey,
    hasPassphrase: !!k.passphrase,
    valid: hasPrivatePart(k),
  });
  app.get("/api/keys", auth, wrap(() => vault.d.keys.map(publicKey)));
  const addKey = (name: string, privateKey: string, passphrase?: string) => {
    privateKey = normalizeKey(privateKey);
    const parsed = utils.parseKey(privateKey, passphrase || undefined);
    if (parsed instanceof Error) throw new Error("invalid key: " + parsed.message);
    const p = Array.isArray(parsed) ? parsed[0] : parsed;
    if (p.getPrivatePEM() === null)
      throw new Error("this is a PUBLIC key (or has no private part). Paste the private key: the file without .pub, starting with -----BEGIN ... PRIVATE KEY-----");
    const k = {
      id: randomUUID(),
      name,
      privateKey,
      passphrase: passphrase || undefined,
      publicKey: `${p.type} ${p.getPublicSSH().toString("base64")}`,
    };
    vault.d.keys.push(k);
    return k;
  };
  app.post(
    "/api/keys",
    auth,
    wrap((req) => {
      const k = addKey(String(req.body.name || "key"), String(req.body.privateKey ?? ""), req.body.passphrase);
      vault.save();
      return publicKey(k);
    }),
  );
  app.post(
    "/api/keys/generate",
    auth,
    wrap((req) => {
      const pair = utils.generateKeyPairSync("ed25519");
      const k = addKey(String(req.body.name || "generated"), pair.private);
      vault.save();
      return publicKey(k);
    }),
  );
  app.delete(
    "/api/keys/:id",
    auth,
    wrap((req) => {
      if (vault.d.hosts.some((h) => h.keyId === req.params.id)) throw new Error("key is used by a host");
      vault.d.keys = vault.d.keys.filter((k) => k.id !== req.params.id);
      vault.save();
    }),
  );

  // ---- Kubernetes clusters (kubeconfig uploads) ----
  const publicCluster = (c: Cluster) => {
    let info: ReturnType<typeof inspectKubeconfig> | undefined;
    try {
      info = inspectKubeconfig(c.kubeconfig);
    } catch {}
    return { id: c.id, name: c.name, context: c.context, namespace: c.namespace, mode: c.mode, group: c.group, info };
  };
  const readCluster = (b: any, old?: Cluster): Cluster => {
    const name = String(b.name ?? "").trim();
    if (!name) throw new Error("name is required");
    if (!MODES.includes(b.mode)) throw new Error("invalid mode");
    if (vault.d.clusters.some((c) => c.name.toLowerCase() === name.toLowerCase() && c.id !== old?.id)) throw new Error("a cluster with this name already exists");
    const kubeconfig = b.kubeconfig ? String(b.kubeconfig) : old?.kubeconfig;
    if (!kubeconfig) throw new Error("upload a kubeconfig file");
    const info = inspectKubeconfig(kubeconfig);
    const context = b.context ? String(b.context) : undefined;
    if (context && !info.contexts.includes(context)) throw new Error(`context "${context}" is not in the kubeconfig (${info.contexts.join(", ")})`);
    return { id: old?.id ?? randomUUID(), name, kubeconfig, context, namespace: b.namespace ? String(b.namespace).trim() : undefined, mode: b.mode, group: b.group || undefined };
  };
  app.get("/api/clusters", auth, wrap(() => vault.d.clusters.map(publicCluster)));
  app.post(
    "/api/clusters",
    auth,
    wrap((req) => {
      const c = readCluster(req.body);
      vault.d.clusters.push(c);
      vault.save();
      return publicCluster(c);
    }),
  );
  app.put(
    "/api/clusters/:id",
    auth,
    wrap((req) => {
      const i = vault.d.clusters.findIndex((c) => c.id === req.params.id);
      if (i < 0) throw new Error("not found");
      const c = readCluster(req.body, vault.d.clusters[i]);
      vault.d.clusters[i] = c;
      vault.save();
      return publicCluster(c);
    }),
  );
  app.delete(
    "/api/clusters/:id",
    auth,
    wrap((req) => {
      vault.d.clusters = vault.d.clusters.filter((c) => c.id !== req.params.id);
      vault.save();
    }),
  );
  app.post(
    "/api/clusters/:id/test",
    auth,
    wrap(async (req) => {
      const c = vault.d.clusters.find((x) => x.id === req.params.id);
      if (!c) throw new Error("not found");
      const args = ["get", ...(c.context ? ["--context", c.context] : []), "--request-timeout=15s", "--raw", "/version"];
      return { output: formatResult(await runKubectl(c.kubeconfig, args, { timeoutSec: 30, maxBytes: 20_000 })) };
    }),
  );

  // ---- MCP tokens (shown once) ----
  app.get("/api/tokens", auth, wrap(() => vault.d.tokens.map((t) => ({ id: t.id, name: t.name, created: t.created }))));
  app.post(
    "/api/tokens",
    auth,
    wrap((req) => {
      const raw = "mcp_" + randomBytes(32).toString("base64url");
      vault.d.tokens.push({ id: randomUUID(), name: String(req.body.name || "client"), hash: sha256(raw), created: new Date().toISOString() });
      vault.save();
      return { token: raw };
    }),
  );
  app.delete(
    "/api/tokens/:id",
    auth,
    wrap((req) => {
      vault.d.tokens = vault.d.tokens.filter((t) => t.id !== req.params.id);
      vault.save();
    }),
  );

  // ---- ChatGPT tunnel (OpenAI Secure MCP Tunnel) ----
  app.get("/api/tunnel", auth, wrap(() => tunnel.status()));
  app.put("/api/tunnel", auth, wrap((req) => tunnel.configure(req.body)));
  app.post("/api/tunnel/install", auth, wrap(() => tunnel.install()));
  app.post("/api/tunnel/start", auth, wrap(() => tunnel.start()));
  app.post("/api/tunnel/stop", auth, wrap(() => tunnel.stop()));
  // ---- approvals / audit / settings ----
  app.get("/api/approvals", auth, wrap(() => approvals.list()));
  app.post(
    "/api/approvals/:id/:d",
    auth,
    wrap((req) => {
      if (!approvals.decide(String(req.params.id), req.params.d === "approve" ? "approved" : "denied")) throw new Error("no longer pending");
    }),
  );
  app.get("/api/audit", auth, wrap(() => audit.tail(300)));
  app.get("/api/settings", auth, wrap(() => vault.d.settings));
  app.put(
    "/api/settings",
    auth,
    wrap((req) => {
      const s = req.body;
      vault.d.settings = {
        autoLockMinutes: Math.max(0, Number(s.autoLockMinutes) || 0),
        maxOutputBytes: Math.min(1_000_000, Math.max(1024, Number(s.maxOutputBytes) || 65536)),
        approvalTimeoutSec: Math.min(600, Math.max(10, Number(s.approvalTimeoutSec) || 120)),
      };
      vault.save();
      vault.touch();
    }),
  );
  app.post("/api/password", auth, wrap((req) => vault.changePassword(String(req.body.old), String(req.body.new))));

  // ---- import ----
  const expandHome = (p: string) => resolve(p.replace(/^~(?=$|[\\/])/, homedir()));
  app.post(
    "/api/import/sshconfig",
    auth,
    wrap((req) => {
      const path = req.body.path ? expandHome(String(req.body.path)) : join(homedir(), ".ssh", "config");
      let text = req.body.text as string | undefined;
      if (text === undefined) {
        if (!existsSync(path)) throw new Error(`file not found: ${path}`);
        text = readFileSync(path, "utf8");
      }
      const base = join(path, "..");
      return parseSshConfig(text).map((h) => {
        const idf = h.identityFile ? resolve(base, expandHome(h.identityFile)) : undefined;
        return { ...h, identityFile: idf, keyAvailable: !!idf && existsSync(idf) };
      });
    }),
  );
  app.post("/api/import/termius", auth, wrap((req) => parseTermiusCsv(String(req.body.text ?? ""))));
  app.post(
    "/api/import/commit",
    auth,
    wrap((req) => {
      const items: (ImportedHost & { keyPassphrase?: string })[] = req.body.hosts ?? [];
      const keyByPath = new Map<string, string>();
      let added = 0;
      const skipped: string[] = [];
      for (const it of items) {
        if (vault.d.hosts.some((h) => h.name.toLowerCase() === it.name.toLowerCase())) {
          skipped.push(it.name);
          continue;
        }
        let keyId: string | undefined;
        if (it.identityFile && existsSync(it.identityFile)) {
          keyId = keyByPath.get(it.identityFile);
          if (!keyId) {
            keyId = addKey(it.name + " key", readFileSync(it.identityFile, "utf8"), it.keyPassphrase).id;
            keyByPath.set(it.identityFile, keyId);
          }
        }
        vault.d.hosts.push({
          id: randomUUID(),
          name: it.name,
          hostname: it.hostname,
          port: it.port,
          user: it.user || "root",
          auth: keyId ? "key" : "password",
          keyId,
          password: keyId ? undefined : it.password,
          mode: "approval",
          allowlist: [],
          group: it.group,
          tags: it.tags,
        });
        added++;
      }
      vault.save();
      return { added, skipped };
    }),
  );

  // ---- Termius desktop (local, offline) import ----
  const tSessions = new Map<string, { data: TermiusImport; exp: number }>();
  const dataDir = opts.dataDir;
  app.get(
    "/api/import/termius-local/status",
    auth,
    wrap(() => ({
      supported: process.platform === "win32",
      termiusFound: !!termiusDbDir(),
      helperReady: process.platform === "win32" && helperReady(dataDir),
    })),
  );
  app.post("/api/import/termius-local/setup", auth, wrap(() => setupHelper(dataDir)));
  app.post(
    "/api/import/termius-local/scan",
    auth,
    wrap(() => {
      if (!termiusDbDir()) throw new Error("Termius desktop data not found on this PC (%APPDATA%/Termius)");
      if (!helperReady(dataDir)) throw new Error("run the one-time helper setup first");
      const data = buildFromDump(runDump(dataDir, join(opts.scriptsDir, "termius_dump.py")), readLocalKeys());
      const id = randomUUID();
      for (const [k, v] of tSessions) if (v.exp < Date.now()) tSessions.delete(k);
      tSessions.set(id, { data, exp: Date.now() + 10 * 60_000 });
      const keyLabel = new Map(data.keys.map((k) => [k.id, k.label]));
      // Secrets never leave the server: the browser only gets labels and flags.
      return {
        session: id,
        stats: data.stats,
        hosts: data.hosts.map((h) => ({
          id: h.termiusId,
          group: h.group,
          name: h.name,
          address: h.address,
          port: h.port,
          user: h.user,
          auth: h.keyId != null ? "key" : h.password ? "password" : "none",
          keyLabel: h.keyId != null ? keyLabel.get(h.keyId) : undefined,
          exists: vault.d.hosts.some((x) => x.hostname === h.address && x.port === h.port && x.user === h.user),
        })),
      };
    }),
  );
  app.post(
    "/api/import/termius-local/commit",
    auth,
    wrap((req) => {
      const s = tSessions.get(String(req.body.session));
      if (!s || s.exp < Date.now()) throw new Error("scan expired, scan again");
      const mode: Mode = MODES.includes(req.body.mode) ? req.body.mode : "approval";
      const want = new Set<number>((req.body.ids ?? []).map(Number));
      const keyMap = new Map<number, string>();
      const skipped: string[] = [];
      let added = 0, keysAdded = 0;
      const taken = new Set(vault.d.hosts.map((h) => h.name.toLowerCase()));
      for (const h of s.data.hosts) {
        if (!want.has(h.termiusId)) continue;
        if (vault.d.hosts.some((x) => x.hostname === h.address && x.port === h.port && x.user === h.user)) {
          skipped.push(h.name);
          continue;
        }
        let keyId: string | undefined;
        if (h.keyId != null) {
          keyId = keyMap.get(h.keyId);
          const k = s.data.keys.find((x) => x.id === h.keyId);
          if (!keyId && k) {
            try {
              keyId = addKey(`Termius: ${k.label}`, k.privateKey, k.passphrase).id;
              keyMap.set(h.keyId, keyId);
              keysAdded++;
            } catch {
              skipped.push(`${h.name} (key unreadable)`);
              continue;
            }
          }
        }
        let name = h.name;
        if (taken.has(name.toLowerCase())) name = `${h.name} (${h.user || "?"}@${h.address}${h.port === 22 ? "" : ":" + h.port})`;
        for (let i = 2; taken.has(name.toLowerCase()); i++) name = `${h.name} #${i}`;
        taken.add(name.toLowerCase());
        vault.d.hosts.push({
          id: randomUUID(),
          name,
          hostname: h.address,
          port: h.port,
          user: h.user || "root",
          auth: keyId ? "key" : "password",
          keyId,
          password: keyId ? undefined : h.password,
          mode,
          allowlist: [],
          group: h.group,
        });
        added++;
      }
      vault.save();
      tSessions.delete(String(req.body.session));
      return { added, keysAdded, skipped };
    }),
  );

  app.use(express.static(webDir));
  return app.listen(port, "127.0.0.1", () => console.log(`Admin UI      http://127.0.0.1:${port}  (local only)`));
}
