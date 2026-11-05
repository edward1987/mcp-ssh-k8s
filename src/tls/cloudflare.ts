import * as acme from 'acme-client';
import { X509Certificate, createPrivateKey } from 'node:crypto';
import { isIP } from 'node:net';
import { Resolver } from 'node:dns/promises';
import type { IdentityStore } from '../auth/store.js';

export interface TlsConfig { hostname: string; privateIp: string; zoneId: string; email: string; token: string; staging: boolean; port: number }
export function validateTlsConfig(c: TlsConfig) {
  const privateIp = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(c.privateIp) || /^f[cd][\da-f]{2}:/i.test(c.privateIp);
  if (!isIP(c.privateIp) || !privateIp || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/.test(c.hostname) || !c.hostname.includes('.') || c.hostname.includes('..') || c.hostname.length > 253 || !/^[a-f0-9]{32}$/.test(c.zoneId) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(c.email) || !c.token || /[\r\n]/.test(c.token) || !Number.isInteger(c.port) || c.port < 1 || c.port > 65535) throw new Error('Invalid private HTTPS configuration');
}
export class CloudflareTls {
  busy = false; lastError = ''; onCertificate?: () => void;
  constructor(readonly store: IdentityStore, private apiFetch: typeof fetch = fetch) {}
  config(): TlsConfig | undefined { const c = this.store.get<TlsConfig>('runtime', 'tls-config'); return c ? { ...c, token: this.store.open(c.token) } : undefined; }
  configure(c: TlsConfig) { if (this.busy) throw new Error('Certificate operation in progress'); validateTlsConfig(c); this.store.put('runtime', 'tls-config', { ...c, token: this.store.seal(c.token) }); }
  status() { const c = this.config(), cert = this.store.get<any>('runtime', 'tls-certificate'); return { configured: !!c, hostname: c?.hostname, privateIp: c?.privateIp, zoneId: c?.zoneId, email: c?.email, port: c?.port, staging: c?.staging, busy: this.busy, lastError: this.lastError, expires: cert?.expires, url: c ? `https://${c.hostname}${c.port === 443 ? '' : ':' + c.port}` : undefined }; }
  certificate() { const c = this.config(), r = this.store.get<any>('runtime', 'tls-certificate'); if (!r || !c || r.hostname !== c.hostname || r.staging !== c.staging || r.expires <= Date.now()) return undefined; return { key: this.store.open(r.key), cert: r.cert }; }
  private async api(path: string, method = 'GET', body?: unknown) {
    const c = this.config()!;
    const response = await this.apiFetch('https://api.cloudflare.com/client/v4/zones/' + c.zoneId + path, { method, headers: { Authorization: 'Bearer ' + c.token, 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30000), redirect: 'error' });
    const result = await response.json() as any;
    if (!response.ok || !result.success) throw new Error('Cloudflare DNS operation failed; check zone and token permissions'); return result.result;
  }
  async ensurePrivateDns() {
    const c = this.config(); if (!c) throw new Error('Configure TLS first');
    const zone = await this.api(''); if (c.hostname !== zone.name && !c.hostname.endsWith('.' + zone.name)) throw new Error('Hostname is outside selected zone');
    const records = await this.api('/dns_records?name=' + encodeURIComponent(c.hostname));
    const type = isIP(c.privateIp) === 4 ? 'A' : 'AAAA';
    if (records.some((r: any) => r.type === 'CNAME' || ((r.type === 'A' || r.type === 'AAAA') && (r.type !== type || r.content !== c.privateIp || r.proxied)))) throw new Error('Existing DNS conflicts; no record was overwritten');
    if (!records.some((r: any) => r.type === type && r.content === c.privateIp)) await this.api('/dns_records', 'POST', { type, name: c.hostname, content: c.privateIp, ttl: 300, proxied: false, comment: 'MCP SSH private VPN endpoint' });
  }
  async issue(force = false) {
    if (this.busy) throw new Error('Certificate operation in progress');
    const c = this.config(); if (!c) throw new Error('Configure TLS first');
    const prior = this.store.get<any>('runtime', 'tls-certificate');
    if (!force && prior?.hostname === c.hostname && prior.staging === c.staging && prior.expires > Date.now() + 30 * 86400000) return;
    this.busy = true; this.lastError = '';
    const txt: { id: string; name: string; value: string }[] = [];
    try {
      await this.ensurePrivateDns();
      const accountId = c.staging ? 'acme-staging' : 'acme-production';
      let account = this.store.get<string>('runtime', accountId);
      if (!account) { account = this.store.seal((await acme.crypto.createPrivateKey()).toString()); this.store.put('runtime', accountId, account); }
      const client = new acme.Client({ accountKey: this.store.open(account), directoryUrl: c.staging ? acme.directory.letsencrypt.staging : acme.directory.letsencrypt.production });
      const [key, csr] = await acme.crypto.createCsr({ commonName: c.hostname });
      const cert = await client.auto({ csr, email: c.email, termsOfServiceAgreed: true, challengePriority: ['dns-01'],
        challengeCreateFn: async (authz, challenge, value) => {
          if (challenge.type !== 'dns-01' || authz.identifier.value !== c.hostname) throw new Error('Unexpected ACME challenge');
          const name = '_acme-challenge.' + c.hostname;
          const record = await this.api('/dns_records', 'POST', { type: 'TXT', name, content: value, ttl: 60 }); txt.push({ id: record.id, name, value });
          const resolver = new Resolver(); resolver.setServers(['1.1.1.1', '8.8.8.8']);
          let propagated = false;
          for (let attempt = 0; attempt < 60; attempt++) { try { if ((await resolver.resolveTxt(name)).some(parts => parts.join('') === value)) { propagated = true; break; } } catch {} await new Promise(r => setTimeout(r, 5000)); }
          if (!propagated) throw new Error('DNS propagation timed out');
        }, challengeRemoveFn: async () => {},
      });
      const parsed = new X509Certificate(cert);
      if (!parsed.checkHost(c.hostname) || !parsed.checkPrivateKey(createPrivateKey(key))) throw new Error('Certificate identity mismatch');
      const expires = Date.parse(parsed.validTo);
      this.store.put('runtime', 'tls-certificate', { hostname: c.hostname, staging: c.staging, key: this.store.seal(key.toString()), cert, expires }); this.onCertificate?.();
    } catch { this.lastError = 'Certificate issuance failed. Check DNS permissions, propagation, CAA and ACME limits; the previous certificate was preserved.'; throw new Error(this.lastError); }
    finally { for (const record of txt) { try { await this.api('/dns_records/' + record.id, 'DELETE'); } catch { this.lastError += ' TXT cleanup requires administrator attention.'; } } this.busy = false; }
  }
  startRenewal() { const timer = setInterval(() => { void this.issue().catch(() => {}); }, 12 * 3600000); timer.unref(); return timer; }
}
