import { randomUUID } from 'node:crypto';
import type { IdentityStore } from '../auth/store.js';
import type { WebTunnelManager } from './web.js';

export const CLOUDFLARE_TOKEN_URL = 'https://dash.cloudflare.com/profile/api-tokens?' + new URLSearchParams({
  permissionGroupKeys: JSON.stringify([{ key: 'argotunnel', type: 'edit' }, { key: 'dns', type: 'edit' }, { key: 'zone', type: 'read' }]),
  accountId: '*', zoneId: 'all', name: 'MCP SSH Tunnel',
});
interface Credentials { secret: string; mode: 'token' | 'global'; email: string }
interface Zone { id: string; name: string; account: { id: string; name?: string }; status: string }
interface Managed { accountId: string; zoneId: string; hostname: string; name: string; tunnelId?: string; dnsId?: string; phase: string; error?: string }
const id = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{32}$/.test(v);
export class CloudflareSetupError extends Error {}
const SetupError = CloudflareSetupError;

/** API credential and managed resource checkpoints survive partial failures and restarts. */
export class CloudflareSetup {
  busy = false;
  constructor(private store: IdentityStore, private web: WebTunnelManager, private apiFetch: typeof fetch = fetch) {}
  status() {
    const c = this.store.get<Credentials>('runtime', 'cloudflare-api');
    return { hasCredential: !!c, mode: c?.mode ?? 'token', email: c?.email ?? '', zones: this.store.get<Zone[]>('runtime', 'cloudflare-zones') ?? [], draft: this.store.get<{ zoneId: string; subdomain: string; autoStart: boolean }>('runtime', 'cloudflare-draft'), managed: this.managed, busy: this.busy };
  }
  private get managed() { return this.store.get<Managed>('runtime', 'cloudflare-managed'); }
  private credentials() { const c = this.store.get<Credentials>('runtime', 'cloudflare-api'); if (!c) throw new SetupError('Salveaza mai intai credentialele Cloudflare.'); return { ...c, secret: this.store.open(c.secret) }; }
  private async api<T>(path: string, method = 'GET', body?: unknown, credentials = this.credentials()): Promise<{ result: T; result_info?: { total_pages?: number } }> {
    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (credentials.mode === 'global') { headers['X-Auth-Key'] = credentials.secret; headers['X-Auth-Email'] = credentials.email; }
      else headers.Authorization = 'Bearer ' + credentials.secret;
      const r = await this.apiFetch('https://api.cloudflare.com/client/v4' + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(30_000) });
      if (r.status === 401 || r.status === 403) {
        const permission = path.includes('dns_records') ? 'Zone / DNS / Edit' : path.includes('cfd_tunnel') ? 'Account / Cloudflare Tunnel / Edit' : 'Zone / Zone / Read';
        throw new SetupError(`Operatia Cloudflare a refuzat accesul (HTTP ${r.status}). Verifica credentialul si permisiunea ${permission} pentru contul sau domeniul ales.`);
      }
      const data = await r.json() as { success: boolean; result: T; result_info?: { total_pages?: number } };
      if (!r.ok || !data.success) throw new Error();
      return data;
    } catch (error) { if (error instanceof SetupError) throw error; throw new SetupError('Operatia Cloudflare a esuat. Verifica credentialele, permisiunile Tunnel Edit / DNS Edit / Zone Read si conexiunea la Internet. Resursele deja create sunt pastrate pentru reluare.'); }
  }
  async connect(input: { secret: unknown; mode: unknown; email: unknown }) {
    if (this.busy) throw new SetupError('Configurarea Cloudflare este deja in curs.');
    this.busy = true;
    try {
      const previous = this.credentialsIfPresent();
      if (typeof input.secret !== 'string' || !['token', 'global'].includes(String(input.mode))) throw new SetupError('Credentiale invalide.');
      const mode = input.mode as Credentials['mode'];
      const email = typeof input.email === 'string' ? input.email.trim() : '';
      const secret = input.secret.trim() || (previous?.mode === mode && (mode === 'token' || previous.email === email) ? previous.secret : '');
      if (!/^[A-Za-z0-9_=-]{20,8192}$/.test(secret) || (mode === 'global' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) throw new SetupError('Introdu un API token valid sau Global API Key si emailul contului.');
      const credentials = { mode, email, secret };
      const zones: Zone[] = [];
      for (let page = 1; ; page++) {
        const r = await this.api<Zone[]>('/zones?per_page=50&page=' + page, 'GET', undefined, credentials);
        if (!Array.isArray(r.result)) throw new SetupError('Lista zonelor Cloudflare este invalida.');
        zones.push(...r.result.filter(z => id(z.id) && id(z.account?.id) && z.status === 'active').map(z => ({ id: z.id, name: z.name, account: { id: z.account.id, name: z.account.name }, status: z.status })));
        if (page >= (r.result_info?.total_pages ?? 1)) break;
        if (page >= 100) throw new SetupError('Restrange tokenul la zonele necesare si incearca din nou.');
      }
      if (!zones.length) throw new SetupError('Tokenul nu are acces la nicio zona DNS activa. Adauga domeniul in Cloudflare si verifica Zone Read.');
      // Read-only probes: never create temporary DNS records or tunnels to test access.
      for (const accountId of new Set(zones.map(z => z.account.id))) {
        await this.api('/accounts/' + accountId + '/cfd_tunnel?per_page=1', 'GET', undefined, credentials);
      }
      for (const zone of zones) {
        await this.api('/zones/' + zone.id + '/dns_records?per_page=1', 'GET', undefined, credentials);
      }
      this.store.put('runtime', 'cloudflare-api', { ...credentials, secret: this.store.seal(secret) });
      this.store.put('runtime', 'cloudflare-zones', zones);
    } finally { this.busy = false; }
  }
  private credentialsIfPresent() { return this.store.get('runtime', 'cloudflare-api') ? this.credentials() : undefined; }
  async provision(input: { zoneId: unknown; subdomain: unknown; autoStart: boolean }) {
    if (this.busy) throw new SetupError('Configurarea Cloudflare este deja in curs.');
    this.busy = true;
    let managed: Managed | undefined;
    let durable = false;
    const checkpoint = (phase: string) => { managed!.phase = phase; managed!.error = undefined; this.store.put('runtime', 'cloudflare-managed', managed); durable = true; };
    try {
      if (!id(input.zoneId) || typeof input.subdomain !== 'string' || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(input.subdomain)) throw new SetupError('Alege o zona valida si un subdomeniu simplu, de exemplu mcp.');
      this.store.put('runtime', 'cloudflare-draft', input);
      const zone = (await this.api<Zone>('/zones/' + input.zoneId)).result;
      if (zone.id !== input.zoneId || !id(zone.account?.id) || zone.status !== 'active' || !/^[a-z0-9.-]+$/.test(zone.name)) throw new SetupError('Zona selectata nu este activa.');
      const hostname = input.subdomain + '.' + zone.name;
      try { this.web.validateActivation('https://' + hostname); } catch { throw new SetupError('AUTH_URL / MCP_PUBLIC_URL din mediu trebuie sa corespunda hostname-ului ales. Corecteaza-le si reporneste instanta inainte de configurare.'); }
      managed = this.managed;
      if (managed && (managed.zoneId !== zone.id || managed.hostname !== hostname || managed.accountId !== zone.account.id)) throw new SetupError('Instanta are deja o configurare administrata. Refoloseste zona si subdomeniul afisate pentru reluare; modificarea resurselor existente se face in Cloudflare.');
      managed ??= { accountId: zone.account.id, zoneId: zone.id, hostname, name: 'mcp-ssh-' + randomUUID(), phase: 'Verificare DNS' };
      await this.api('/accounts/' + managed.accountId + '/cfd_tunnel?per_page=1');
      const records = (await this.api<{ id: string; type: string; content: string; proxied: boolean }[]>('/zones/' + zone.id + '/dns_records?per_page=100&name=' + encodeURIComponent(hostname))).result;
      const target = managed.tunnelId ? managed.tunnelId + '.cfargotunnel.com' : '';
      if (records.length > 1 || records.some(r => r.type !== 'CNAME' || r.content !== target || !r.proxied)) throw new SetupError('Subdomeniul are deja inregistrari DNS incompatibile. Alege un subdomeniu liber; nu a fost suprascris niciun record.');
      checkpoint('Instalare cloudflared');
      if (!this.web.status().installed) await this.web.install();
      if (!managed.tunnelId) {
        checkpoint('Creare tunel');
        // Recover an ambiguous create timeout using our persisted, random instance-specific name.
        const candidates = (await this.api<{ id: string; name: string; remote_config: boolean }[]>('/accounts/' + managed.accountId + '/cfd_tunnel?is_deleted=false&name=' + encodeURIComponent(managed.name))).result.filter(t => t.name === managed!.name);
        if (candidates.length > 1 || candidates.some(t => !t.remote_config)) throw new SetupError('Tunelul rezervat are o configuratie incompatibila. Verifica tunelurile din Cloudflare.');
        const tunnel = candidates[0] ?? (await this.api<{ id: string }>('/accounts/' + managed.accountId + '/cfd_tunnel', 'POST', { name: managed.name, config_src: 'cloudflare' })).result;
        if (!/^[a-f0-9-]{36}$/.test(tunnel.id)) throw new SetupError('Cloudflare a returnat un ID de tunel invalid.');
        managed.tunnelId = tunnel.id; checkpoint('Tunel creat');
      }
      const path = '/accounts/' + managed.accountId + '/cfd_tunnel/' + managed.tunnelId;
      checkpoint('Configurare ruta HTTPS');
      await this.api(path + '/configurations', 'PUT', { config: { ingress: [{ hostname, service: `http://127.0.0.1:${this.web.mcpPort}`, originRequest: { httpHostHeader: hostname } }, { service: 'http_status:404' }] } });
      const token = (await this.api<string>(path + '/token')).result;
      if (typeof token !== 'string' || !/^[A-Za-z0-9_+/=-]{20,8192}$/.test(token)) throw new SetupError('Cloudflare nu a returnat un token de tunel valid.');
      checkpoint('Configurare DNS');
      if (!records.length) {
        const record = (await this.api<{ id: string }>('/zones/' + zone.id + '/dns_records', 'POST', { type: 'CNAME', name: hostname, content: managed.tunnelId + '.cfargotunnel.com', proxied: true, ttl: 1, comment: 'MCP SSH managed web tunnel' })).result;
        managed.dnsId = record.id;
      } else managed.dnsId = records[0].id;
      checkpoint('Activare OAuth si conectare');
      this.web.configure({ origin: 'https://' + hostname, token, autoStart: input.autoStart });
      this.web.activate();
      this.web.start();
      checkpoint('Configurat. Conectarea la Cloudflare este in curs; DNS si certificatul edge pot necesita propagare.');
    } catch (error) {
      const message = error instanceof SetupError ? error.message : 'Configurarea nu s-a finalizat. Verifica instalarea runtime-ului si reia operatia; resursele Cloudflare create sunt pastrate.';
      if (managed && durable) { managed.error = message; this.store.put('runtime', 'cloudflare-managed', managed); }
      throw new SetupError(message);
    } finally { this.busy = false; }
  }
}
