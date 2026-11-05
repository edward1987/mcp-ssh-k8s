import { spawn, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { IdentityStore } from '../auth/store.js';

interface WebConfig { origin: string; token: string; autoStart: boolean }
export function webOrigin(value: unknown): string {
  if (typeof value !== 'string') throw new Error('HTTPS origin required');
  const u = new URL(value);
  if (u.protocol !== 'https:' || u.username || u.password || u.pathname !== '/' || u.search || u.hash || !u.hostname.includes('.') || /^(localhost|127\.|\[)/i.test(u.hostname)) throw new Error('Public HTTPS origin required');
  return u.origin;
}

/** One stable public MCP/OAuth endpoint, shared by Gemini Web and Claude Web. */
export class WebTunnelManager {
  private child?: ChildProcess;
  private retry?: ReturnType<typeof setTimeout>;
  private desired = false;
  private connected = false;
  private error = '';
  private installing = false;
  constructor(private store: IdentityStore, private dataDir: string, private activeOrigin: string, readonly mcpPort: number, private activeEndpoint = new URL('/mcp', activeOrigin).href, private onActivate?: (origin: string) => void) {}
  validateActivation(origin: string) {
    webOrigin(origin);
    if (!this.onActivate || (process.env.AUTH_URL && new URL(process.env.AUTH_URL).origin !== origin) || (process.env.MCP_PUBLIC_URL && new URL(process.env.MCP_PUBLIC_URL).href !== new URL('/mcp', origin).href)) throw new Error('Public URL is pinned by environment or activation is unavailable');
  }
  activate() {
    const origin = this.config?.origin;
    if (!origin) throw new Error('Configure the web tunnel first');
    this.validateActivation(origin);
    this.onActivate!(origin);
    this.activeOrigin = origin; this.activeEndpoint = new URL('/mcp', origin).href;
  }
  private get config() { return this.store.get<WebConfig>('runtime', 'web-tunnel'); }
  get binPath() { return join(this.dataDir, 'bin', process.platform === 'win32' ? 'cloudflared.exe' : 'cloudflared'); }
  status() {
    const c = this.config;
    return { installed: existsSync(this.binPath), installing: this.installing, running: !!this.child, connected: this.connected, reconnecting: !!this.retry, origin: c?.origin ?? '', hasToken: !!c?.token, autoStart: c?.autoStart ?? false, restartRequired: !!c && (c.origin !== this.activeOrigin || this.activeEndpoint !== new URL('/mcp', c.origin).href), lastError: this.error };
  }
  configure(input: { origin: unknown; token: unknown; autoStart: boolean }) {
    if (this.installing) throw new Error('Installer running');
    const origin = webOrigin(input.origin);
    if (typeof input.token !== 'string') throw new Error('Invalid token');
    const token = input.token.trim();
    if (token && (!/^[A-Za-z0-9_+/=-]+$/.test(token) || token.length < 20 || token.length > 8192)) throw new Error('Invalid tunnel token');
    const sealed = token ? this.store.seal(token) : this.config?.token;
    if (!sealed) throw new Error('Tunnel token required');
    this.stop();
    this.store.put('runtime', 'web-tunnel', { origin, token: sealed, autoStart: input.autoStart });
  }
  async install() {
    if (this.installing || this.desired) throw new Error('Stop the web tunnel before installing');
    this.installing = true;
    try {
      const platform = { win32: 'windows', linux: 'linux' }[process.platform as string];
      const arch = { x64: 'amd64', arm64: 'arm64' }[process.arch as string];
      if (!platform || !arch) throw new Error('Unsupported platform');
      const response = await fetch('https://api.github.com/repos/cloudflare/cloudflared/releases/latest', { headers: { 'User-Agent': 'mcp-ssh' }, signal: AbortSignal.timeout(30_000) });
      if (!response.ok) throw new Error('Release unavailable');
      const release = await response.json() as { assets: { name: string; browser_download_url: string; digest: string }[] };
      const asset = release.assets.find(a => a.name === `cloudflared-${platform}-${arch}${platform === 'windows' ? '.exe' : ''}`);
      if (!asset || !/^sha256:[a-f0-9]{64}$/.test(asset.digest) || !asset.browser_download_url.startsWith('https://github.com/cloudflare/cloudflared/releases/download/')) throw new Error('Verified binary unavailable');
      const download = await fetch(asset.browser_download_url, { signal: AbortSignal.timeout(180_000) });
      if (!download.ok) throw new Error('Download failed');
      const bytes = Buffer.from(await download.arrayBuffer());
      if ('sha256:' + createHash('sha256').update(bytes).digest('hex') !== asset.digest) throw new Error('Checksum mismatch');
      mkdirSync(join(this.dataDir, 'bin'), { recursive: true, mode: 0o700 });
      writeFileSync(this.binPath + '.new', bytes, { mode: 0o700 });
      renameSync(this.binPath + '.new', this.binPath);
      if (process.platform !== 'win32') chmodSync(this.binPath, 0o700);
    } finally { this.installing = false; }
  }
  start() {
    if (this.child || this.retry) return;
    const c = this.config;
    if (!c || this.status().restartRequired || !existsSync(this.binPath) || this.installing) throw new Error('Install, configure and restart the instance first');
    const token = this.store.open(c.token);
    this.desired = true; this.error = ''; this.connected = false;
    const child = spawn(this.binPath, ['tunnel', '--no-autoupdate', 'run'], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, TUNNEL_TOKEN: token } });
    this.child = child;
    // Never retain or display subprocess output: it may contain credentials.
    child.stderr!.on('data', (data: Buffer) => { if (this.child === child && data.toString().includes('Registered tunnel connection')) this.connected = true; });
    const ended = () => {
      if (this.child !== child) return;
      this.child = undefined; this.connected = false;
      this.error = 'Conexiunea s-a oprit. Verifica tokenul, ruta Cloudflare si accesul la Internet.';
      if (this.desired) { this.retry = setTimeout(() => { this.retry = undefined; try { this.start(); } catch { this.desired = false; } }, 5000); this.retry.unref(); }
    };
    child.once('error', ended); child.once('exit', ended);
  }
  stop() { this.desired = false; clearTimeout(this.retry); this.retry = undefined; const child = this.child; this.child = undefined; this.connected = false; child?.kill(); }
  autoStart() { if (this.config?.autoStart) { try { this.start(); } catch { this.error = 'Pornirea automata a esuat. Verifica instalarea si URL-ul public activ.'; } } }
}
