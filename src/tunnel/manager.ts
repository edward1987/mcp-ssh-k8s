import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { sha256, type Vault } from "../vault/store.js";

const REPO = "openai/tunnel-client";
const HEALTH_PORT = 7779;
const ID_RE = /^tunnel_[A-Za-z0-9]+$/;

/**
 * Runs OpenAI's `tunnel-client` (Secure MCP Tunnel) so ChatGPT can reach the local MCP port with no public listener.
 * ChatGPT connects with "no auth" through the OpenAI-hosted tunnel endpoint; tunnel-client adds our bearer token
 * (`--mcp.extra-headers`) to every request, so the token never leaves this machine.
 */
export class TunnelManager {
  private child: ChildProcess | null = null;
  private logs: string[] = [];
  private lastError = "";
  private installing = false;

  constructor(
    private vault: Vault,
    private dataDir: string,
    private mcpPort: number,
  ) {}

  private get binDir() {
    return join(this.dataDir, "bin");
  }
  private get binPath() {
    return join(this.binDir, process.platform === "win32" ? "tunnel-client-runtime.exe" : "tunnel-client-runtime");
  }
  private get versionFile() {
    return join(this.binDir, "VERSION");
  }

  private redact(line: string) {
    const key = this.vault.unlocked ? this.vault.d.tunnel?.apiKey : undefined;
    return (key ? line.split(key).join("[redacted]") : line).replace(/sk-[A-Za-z0-9_-]{6,}/g, "[redacted]");
  }

  private log(line: string) {
    this.logs.push(this.redact(line).replace(/\s+$/, ""));
    if (this.logs.length > 300) this.logs.shift();
  }

  get installed() {
    return existsSync(this.binPath);
  }

  async status() {
    const cfg = this.vault.d.tunnel;
    let ready: boolean | null = null;
    if (this.child) {
      try {
        const r = await fetch(`http://127.0.0.1:${HEALTH_PORT}/readyz`, { signal: AbortSignal.timeout(1500) });
        ready = r.ok;
      } catch {
        ready = false;
      }
    }
    return {
      installed: this.installed,
      version: this.installed && existsSync(this.versionFile) ? readFileSync(this.versionFile, "utf8").trim() : null,
      installing: this.installing,
      running: !!this.child,
      ready,
      pid: this.child?.pid,
      lastError: this.lastError,
      configured: !!cfg?.tunnelId && !!cfg?.apiKey,
      tunnelId: cfg?.tunnelId ?? "",
      hasApiKey: !!cfg?.apiKey,
      autoStart: cfg?.autoStart ?? false,
      mcpUrl: `http://127.0.0.1:${this.mcpPort}/mcp`,
      logs: this.logs.slice(-80),
    };
  }

  configure(b: { tunnelId?: string; apiKey?: string; autoStart?: boolean }) {
    const cur = this.vault.d.tunnel;
    const tunnelId = String(b.tunnelId ?? cur?.tunnelId ?? "").trim();
    if (!ID_RE.test(tunnelId)) throw new Error('tunnel id must look like "tunnel_0123abc..." (copy it from platform.openai.com > Tunnels)');
    const apiKey = String(b.apiKey || cur?.apiKey || "").trim();
    if (!apiKey) throw new Error("runtime API key is required");
    this.vault.d.tunnel = {
      tunnelId,
      apiKey,
      token: cur?.token ?? "",
      tokenId: cur?.tokenId ?? "",
      autoStart: b.autoStart ?? cur?.autoStart ?? false,
    };
    this.ensureToken();
    this.vault.save();
  }

  /** Dedicated MCP bearer token for tunnel-client; revoking it in the tokens tab cuts ChatGPT off. */
  private ensureToken() {
    const t = this.vault.d.tunnel!;
    if (t.token && this.vault.d.tokens.some((x) => x.id === t.tokenId)) return;
    t.token = "mcp_" + randomBytes(32).toString("base64url");
    t.tokenId = randomUUID();
    this.vault.d.tokens.push({ id: t.tokenId, name: "chatgpt-tunnel", hash: sha256(t.token), created: new Date().toISOString() });
  }

  async install() {
    if (this.installing) throw new Error("install already in progress");
    this.installing = true;
    try {
      const plat = { win32: "windows", darwin: "darwin", linux: "linux" }[process.platform as string];
      const arch = { x64: "amd64", arm64: "arm64" }[process.arch as string];
      if (!plat || !arch) throw new Error(`unsupported platform ${process.platform}/${process.arch}`);

      const rel = (await (await fetch(`https://api.github.com/repos/${REPO}/releases/latest`, { headers: { "User-Agent": "mcp-ssh" } })).json()) as any;
      const tag: string = rel.tag_name;
      if (!tag) throw new Error("could not read latest release");
      const zipName = `tunnel-client-runtime-${tag}-${plat}-${arch}.zip`;
      const asset = (n: string) => rel.assets.find((a: any) => a.name === n)?.browser_download_url as string | undefined;
      const zipUrl = asset(zipName), sumsUrl = asset("SHA256SUMS.txt");
      if (!zipUrl || !sumsUrl) throw new Error(`release ${tag} has no ${zipName}`);

      const sums = await (await fetch(sumsUrl)).text();
      const expected = sums.split("\n").map((l) => l.trim().split(/\s+\*?/)).find((p) => p[1] === zipName)?.[0];
      if (!expected) throw new Error("checksum for the archive not found in SHA256SUMS.txt");
      const buf = Buffer.from(await (await fetch(zipUrl)).arrayBuffer());
      if (createHash("sha256").update(buf).digest("hex") !== expected) throw new Error("checksum mismatch - download discarded");

      mkdirSync(this.binDir, { recursive: true });
      const tmp = join(this.binDir, "_extract");
      rmSync(tmp, { recursive: true, force: true });
      mkdirSync(tmp);
      const zipPath = join(tmp, zipName);
      writeFileSync(zipPath, buf);
      const x =
        process.platform === "linux"
          ? spawnSync("unzip", ["-oq", zipName], { cwd: tmp })
          : // Windows' bsdtar reads zips; a GNU tar earlier in PATH (Git Bash) does not, so use the system one by full path.
            spawnSync(process.platform === "win32" ? join(process.env.SystemRoot ?? "C:\Windows", "System32", "tar.exe") : "tar", ["-xf", zipName], { cwd: tmp });
      if (x.status !== 0) throw new Error("extract failed: " + (x.stderr?.toString() || x.error?.message));
      const exe = process.platform === "win32" ? "tunnel-client-runtime.exe" : "tunnel-client-runtime";
      if (!existsSync(join(tmp, exe))) throw new Error("archive did not contain " + exe);
      this.stop();
      rmSync(this.binPath, { force: true });
      writeFileSync(this.binPath, readFileSync(join(tmp, exe)));
      if (process.platform !== "win32") chmodSync(this.binPath, 0o755);
      writeFileSync(this.versionFile, tag);
      rmSync(tmp, { recursive: true, force: true });
      this.log(`installed tunnel-client ${tag} (sha256 verified)`);
    } finally {
      this.installing = false;
    }
  }

  start() {
    if (this.child) return;
    const cfg = this.vault.d.tunnel;
    if (!cfg?.tunnelId || !cfg.apiKey) throw new Error("configure the tunnel id and runtime API key first");
    if (!this.installed) throw new Error("tunnel-client is not installed yet");
    this.ensureToken();
    this.vault.save();
    this.lastError = "";
    const args = [
      "run",
      "--control-plane.tunnel-id", cfg.tunnelId,
      "--mcp.server-url", `url=http://127.0.0.1:${this.mcpPort}/mcp`,
      "--mcp.extra-headers", "Authorization: env:MCP_BEARER",
      "--health.listen-addr", `127.0.0.1:${HEALTH_PORT}`,
      "--log.format", "struct-text",
    ];
    const child = spawn(this.binPath, args, {
      env: { ...process.env, CONTROL_PLANE_API_KEY: cfg.apiKey, MCP_BEARER: `Bearer ${cfg.token}` },
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    this.child = child;
    this.log(`started tunnel-client pid ${child.pid}`);
    const onData = (d: Buffer) => {
      for (const line of d.toString().split("\n")) {
        if (!line.trim()) continue;
        this.log(line);
        const m = /(?:ERROR|WARN).*?error="?([^"]{0,200})/.exec(line);
        if (m && /invalid_api_key|unauthorized|403|404/i.test(m[1])) this.lastError = this.redact(m[1]);
      }
    };
    child.stdout!.on("data", onData);
    child.stderr!.on("data", onData);
    child.on("error", (e) => {
      this.lastError = e.message;
      this.child = null;
    });
    child.on("exit", (code) => {
      this.log(`tunnel-client exited (${code})`);
      if (this.child === child) this.child = null;
    });
  }

  stop() {
    if (!this.child) return;
    this.child.kill();
    this.child = null;
  }

  /** Called after the vault is unlocked. */
  autoStart() {
    if (this.vault.d.tunnel?.autoStart && this.installed) {
      try {
        this.start();
      } catch (e) {
        this.lastError = (e as Error).message;
      }
    }
  }
}
