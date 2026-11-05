import { identityContext } from "./context.js";
import { readFileSync } from "node:fs";
import { identityDocument, accountPage } from "./ui.js";
import express from 'express';
import { randomUUID } from 'node:crypto';
import { TOTP, Secret } from 'otpauth';
import { IdentityStore, randomToken, type User, type Grant } from './store.js';
import type { OAuthProvider } from './oauth.js';
import type { Ctx } from '../service.js';
import { sha256 } from '../vault/store.js';
import { session } from './session.js';
export { session } from './session.js';
import { infrastructureRouter } from '../admin/infrastructure.js';
import type { TunnelManager } from '../tunnel/manager.js';
import type { WebTunnelManager } from '../tunnel/web.js';

const esc = (s: unknown) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
const IDENTITY_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'";
export function identityRouter(ctx: Ctx, provider: OAuthProvider, localAdmin = false, infrastructure?: { tunnel: TunnelManager; dataDir: string; webTunnel?: WebTunnelManager }) {
  const store = provider.store, router = express.Router();
  router.use(express.urlencoded({ extended: false, limit: '16kb' }), express.json({ limit: '16kb' }));
  router.use((req, _res, next) => { const s = session(store, req); if (s) identityContext.run({ userId: s.user.id, clientId: 'identity-ui', sessionId: s.id, operator: true }, next); else next(); });
  router.use((req, res, next) => {
    res.set({ 'Cache-Control': 'no-store', 'Content-Security-Policy': IDENTITY_CSP, 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'strict-origin' });
    if (req.method !== 'GET' && req.headers.origin && req.headers.origin !== provider.issuer.origin && !(localAdmin && req.headers.origin === `http://${req.headers.host}`)) return void res.status(403).send('Invalid origin');
    res.on('finish', () => { if (req.method === 'POST' && res.statusCode < 400) ctx.audit.log({ client: req.ip ?? '?', userId: session(store, req)?.user.id, host: '-', action: `identity ${req.path}`, outcome: String(res.statusCode) }); });
    next();
  });
  const attempts = new Map<string, { n: number; until: number }>();
  router.use((req, res, next) => {
    if (req.method === 'POST') {
      // The included gateway shares one loopback IP across users. Scope budgets to
      // the authenticated user, login name or invitation instead of that shared IP.
      const s = session(store, req);
      const subject = s ? `user:${s.user.id}` : req.path === '/login' ? `login:${String(req.body.name).toLowerCase()}` : req.path === '/activate' ? `invite:${String(req.body.token)}` : `anonymous:${req.path}:${req.ip ?? '?'}`;
      const key = sha256(subject), now = Date.now();
      for (const [id, entry] of attempts) if (entry.until <= now) attempts.delete(id);
      const a = attempts.get(key);
      if (a && a.n >= 15) return void res.status(429).send('Try again later');
      // Bound attacker-controlled keys without evicting existing account budgets.
      if (!a && attempts.size >= 10000) return void res.status(429).send('Try again later');
      attempts.set(key, { n: (a?.n ?? 0) + 1, until: a?.until ?? now + 60000 });
    }
    next();
  });
  router.get('/style.css', (_req, res) => { res.type('css').send(readFileSync(new URL('../../web/styles.css', import.meta.url), 'utf8')); });
  router.get('/progress.js', (_req, res) => { res.type('js').send(readFileSync(new URL('../../web/progress.js', import.meta.url), 'utf8')); });
  const page = (res: express.Response, title: string, body: string, wide = false) => res.type('html').send(identityDocument(title, body, wide));
  const field = (name: string, label: string, type = 'text', value = '') => type === 'hidden' ? `<input type="hidden" name="${name}" value="${esc(value)}">` : `<p><label>${esc(label)} <input required name="${name}" type="${type}" value="${esc(value)}" ${name === 'otp' ? 'autocomplete="one-time-code"' : name === 'name' ? 'autocomplete="username"' : type === 'password' ? 'autocomplete="current-password"' : ''}></label></p>`;
  const form = (action: string, body: string) => `<form method="post" action="${action}">${body}${action === '/identity/consent' ? '' : `<button class="p" type="submit">${action.endsWith('/login') ? 'Autentificare securizată' : action.endsWith('/activate') ? 'Activează contul și MFA' : 'Continuă'}</button>`}</form>`;
  const wrap = (fn: (req: express.Request, res: express.Response) => unknown) => (req: express.Request, res: express.Response, next: express.NextFunction) => { Promise.resolve().then(() => fn(req, res)).catch(() => { ctx.audit.log({ client: req.ip ?? '?', host: '-', action: 'identity', outcome: 'denied' }); res.status(400); page(res, 'Cerere respinsă', '<div class="card"><p>Verifică datele introduse, codul MFA sau valabilitatea invitației.</p><p><a href="/identity/">Înapoi la cont</a> · <a href="/identity/login">Autentificare</a></p></div>'); }); };
  const requireSession = (req: express.Request, admin = false) => { const s = session(store, req); if (!s || (admin && s.user.role !== 'administrator') || req.body.csrf !== s.csrf) throw new Error('unauthorized'); return session(store, req, true)!; };
  if (localAdmin && infrastructure) router.use('/admin', infrastructureRouter(ctx, provider, infrastructure.tunnel, infrastructure.dataDir, infrastructure.webTunnel));
  router.get(['/tls', '/admin/tls'], wrap((req, res) => {
    const s = session(store, req); if (!s || s.user.role !== 'administrator' || !ctx.tls) throw new Error('Unauthorized');
    const status = ctx.tls.status();
    if (status.busy) res.setHeader('Refresh', '3');
    page(res, 'HTTPS privat · Let’s Encrypt / Cloudflare', `<p><a href="/identity/admin">Administrare instanță</a></p><div class="security-banner">DNS-only către IP privat. Nu deschide porturi publice. Numele certificatului apare în Certificate Transparency; IP-ul privat va exista în DNS public.</div>${status.busy ? '<div class="operation-progress" role="status">Emiterea certificatului este in curs. Starea se actualizeaza automat.<progress aria-label="Emitere certificat"></progress></div>' : ''}<pre>${esc(JSON.stringify(status, null, 2))}</pre>` + form('/identity/admin/tls', field('csrf', '', 'hidden', s.csrf) + field('hostname', 'Hostname', 'text', status.hostname ?? '') + field('privateIp', 'IP privat VPN', 'text', status.privateIp ?? '') + field('zoneId', 'Cloudflare Zone ID', 'text', status.zoneId ?? '') + field('email', 'Email ACME', 'email', status.email ?? '') + field('token', 'Cloudflare API token — DNS Edit pentru zona aleasă', 'password') + '<label><input type="checkbox" name="staging" value="yes" checked> Staging (certificat de test, neacceptat de browsere)</label><label><input type="checkbox" required name="terms" value="yes"> Accept termenii Let’s Encrypt și publicarea DNS/CT.</label>') + form('/identity/admin/tls/issue', field('csrf', '', 'hidden', s.csrf)));
  }));
  router.post(['/tls', '/admin/tls'], wrap((req, res) => {
    requireSession(req, true); if (!ctx.tls || req.body.terms !== 'yes') throw new Error('Consent required');
    ctx.tls.configure({ hostname: String(req.body.hostname).toLowerCase(), privateIp: String(req.body.privateIp), zoneId: String(req.body.zoneId), email: String(req.body.email), token: String(req.body.token), port: 443, staging: req.body.staging === 'yes' }); res.redirect('/identity/admin/tls');
  }));
  router.post(['/tls/issue', '/admin/tls/issue'], wrap((req, res) => { requireSession(req, true); if (!ctx.tls) throw new Error('TLS unavailable'); void ctx.tls.issue().catch(() => {}); res.redirect('/identity/admin/tls'); }));
  router.get('/shares', wrap((req, res) => {
    const s = session(store, req); if (!s || !ctx.shares || !ctx.registry) throw new Error('Unavailable');
    const vault = ctx.registry.get(s.user.id), csrf = field('csrf', '', 'hidden', s.csrf);
    if (!vault.unlocked) return page(res, 'Partajări', '<p>Deblochează vaultul personal.</p><a href="/">Vault personal</a>');
    const options = (rows: {id: string; name: string}[]) => rows.map(r => `<option value="${esc(r.id)}">${esc(r.name)}</option>`).join('');
    const users = store.all<User>('user').filter(u => u.id !== s.user.id && u.password && !u.disabled);
    let body = '<p><a href="/">Vault personal</a></p><h2>Primite</h2>';
    for (const share of ctx.shares.list(s.user.id)) body += `<div class="card"><h3>${esc(share.alias)}</h3><p>${esc(share.policy)} · expiră ${esc(new Date(share.expires).toISOString())}</p>` + form('/identity/shares/run', csrf + field('id', '', 'hidden', share.id) + (share.policy === 'limited' ? `<label>Operație<select name="operation">${options(share.operations)}</select></label>` : field('command', 'Comandă'))) + '</div>';
    body += '<h2>Oferite</h2>';
    for (const share of store.all<any>('share').filter(x => x.owner === s.user.id)) body += `<div class="card"><b>${esc(share.alias)}</b><p>${esc(share.recipient)} · ${share.revoked ? 'revocat' : esc(new Date(share.expires).toISOString())}</p>` + form('/identity/shares/revoke', csrf + field('id', '', 'hidden', share.id)) + '</div>';
    body += '<h2>Partajare nouă</h2>' + form('/identity/shares/create', csrf + `<label>Resursă<select name="resource">${options([...vault.d.hosts.map(h => ({ id: 'host:' + h.id, name: 'SSH · ' + h.name })), ...vault.d.clusters.map(c => ({ id: 'cluster:' + c.id, name: 'Kubernetes · ' + c.name }))])}</select></label><label>Destinatar<select name="recipient">${options(users)}</select></label>` + field('alias', 'Alias vizibil destinatarului') + '<label>Politică<select name="policy"><option value="limited">Operații permise</option><option value="approval">Aprobare pentru fiecare comandă</option><option value="unrestricted">Fără restricții suplimentare (rezultatele pot dezvălui IP-uri)</option></select></label><label>Operații (Nume|comandă completă, o linie per operație)<textarea name="operations"></textarea></label>' + field('hours', 'Expiră după ore', 'number', '24') + `<label>Aprobatori suplimentari<select name="approvers" multiple>${options(users)}</select></label>`);
    page(res, 'Partajări temporare', body, true);
  }));
  router.post('/shares/create', wrap((req, res) => {
    const s = requireSession(req); if (!ctx.shares) throw new Error('Unavailable'); const [type, resource] = String(req.body.resource).split(':');
    ctx.shares.create(s.user.id, { recipient: String(req.body.recipient), type: type as any, resource, alias: String(req.body.alias), policy: req.body.policy, expires: Date.now() + Number(req.body.hours) * 3600000, approvers: [].concat(req.body.approvers ?? []), operations: String(req.body.operations ?? '').split('\n').filter(Boolean).map(line => { const split = line.indexOf('|'); if (split < 1) throw new Error('Invalid operation'); return { id: randomUUID(), name: line.slice(0, split).trim(), command: line.slice(split + 1).trim() }; }) }); res.redirect('/identity/shares');
  }));
  router.post('/shares/revoke', wrap((req, res) => { const s = requireSession(req); ctx.shares!.revoke(s.user.id, String(req.body.id)); res.redirect('/identity/shares'); }));
  router.post('/shares/run', wrap(async (req, res) => { const s = requireSession(req); const result = await ctx.shares!.execute(ctx, s.user.id, String(req.body.id), req.body.operation, req.body.command); page(res, 'Rezultat', `<pre>${esc(result.stdout)}${esc(result.stderr)}</pre><a href="/identity/shares">Partajări</a>`); }));
  router.get('/me', (req, res) => { const s = session(store, req); res.json({ user: s ? { id: s.user.id, name: s.user.name, role: s.user.role } : null }); });
  router.get('/login', (_req, res) => page(res, 'Autentificare', form('/identity/login', field('name', 'Utilizator') + field('password', 'Parolă', 'password') + field('otp', 'TOTP sau cod de recuperare')) + (localAdmin ? '<p><a href="/identity/bootstrap">Configurare inițială</a></p>' : '')));
  router.post('/login', wrap(async (req, res) => {
    const u = await store.login(String(req.body.name), String(req.body.password), String(req.body.otp));
    const raw = randomToken(); store.put('session', sha256(raw), { id: sha256(raw), userId: u.id, csrf: randomToken(), expires: Date.now() + 28800000, idle: Date.now() + 1800000 });
    res.setHeader('Set-Cookie', `identity=${raw}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800${provider.issuer.protocol === 'https:' ? '; Secure' : ''}`);
    ctx.audit.log({ client: u.id, userId: u.id, host: '-', action: 'login', outcome: 'ok' }); res.redirect('/identity/');
  }));
  if (localAdmin) {
    router.get('/bootstrap', (_req, res) => page(res, 'Primul administrator', form('/identity/bootstrap', field('master', 'Parolă master (vault existent sau nou)', 'password') + field('name', 'Nume administrator'))));
    router.post('/bootstrap', wrap(async (req, res) => {
      if (req.headers['x-mcp-private-gateway']) throw new Error('Bootstrap is loopback-only');
      if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress ?? '')) throw new Error('local only');
      if (store.all<User>('user').some(u => u.role === 'administrator' && u.password)) throw new Error('already initialized');
      const initialVault = ctx.registry?.legacy ?? ctx.vault;
      if (initialVault.exists) await initialVault.verifyPassword(String(req.body.master)); else await initialVault.create(String(req.body.master));
      // Checking again closes the race between concurrent bootstrap requests.
      if (store.all<User>('user').some(u => u.role === 'administrator' && u.password)) throw new Error('already initialized');
      initialVault.backup();
      const old = store.all<User>('user').find(u => u.role === 'administrator');
      const token = store.invite(String(req.body.name), 'administrator', old?.id);
      res.redirect('/identity/activate?token=' + token);
    }));
  }
  router.get('/activate', wrap((req, res) => {
    const token = String(req.query.token), { u, secret } = store.enrollment(token);
    const uri = new TOTP({ issuer: 'MCP SSH', label: u.name, secret: Secret.fromBase32(secret) }).toString();
    page(res, 'Activare cont și MFA', `<p>Adaugă cheia în aplicația TOTP: <code>${esc(secret)}</code></p><p><a href="${esc(uri)}">Deschide autentificatorul</a></p>` + form('/identity/activate', field('token', '', 'hidden', token) + field('password', 'Parolă nouă (minimum 12 caractere)', 'password') + field('otp', 'Cod TOTP')));
  }));
  router.post('/activate', wrap(async (req, res) => { const codes = await store.activate(String(req.body.token), String(req.body.password), String(req.body.otp)); page(res, 'Coduri de recuperare', `<p>Salvează aceste coduri. Fiecare poate fi folosit o singură dată.</p><pre>${codes.map(esc).join('\n')}</pre><a href="/identity/login">Autentificare</a>`); }));
  router.get('/consent', wrap((req, res) => {
    const s = session(store, req);
    if (!s) return page(res, 'Autentificare necesară', '<p>Autentifică-te, apoi revino la această pagină pentru autorizare.</p><a rel="noopener noreferrer" target="_blank" href="/identity/login">Autentificare</a>');
    const p = store.get<any>('pending', String(req.query.request)); if (!p || p.expires < Date.now()) throw new Error('expired');
    const c = store.get<any>('client', p.clientId);
    // Chromium applies form-action to the POST's OAuth redirect as well. Permit only
    // this pending request's callback origin, already validated by the OAuth handler.
    // Serialize an origin, never a client-controlled path/query into the CSP header.
    const redirectOrigin = canonicalUrl(new URL(p.redirectUri).origin).origin;
    res.setHeader('Content-Security-Policy', IDENTITY_CSP.replace("form-action 'self'", `form-action 'self' ${redirectOrigin}`));
    page(res, 'Autorizează clientul MCP', `<p>Cont: ${esc(s.user.name)}</p><p>Client: ${esc(c?.client_name ?? p.clientId)}</p><p>Redirect: ${esc(p.redirectUri)}</p><p>Permisiune: mcp:use — numai resursele atribuite contului tău.</p>` + form('/identity/consent', field('csrf', '', 'hidden', s.csrf) + field('request', '', 'hidden', p.id) + '<button name="allow" value="yes">Autorizează</button><button name="allow" value="no">Refuză</button>'));
  }));
  router.post('/consent', wrap((req, res) => { const s = requireSession(req); res.redirect(provider.consent(String(req.body.request), s.user.id, req.body.allow === 'yes')); }));
  router.get('/', wrap((req, res) => {
    const s = session(store, req); if (!s) return res.redirect('/identity/login');
    page(res, 'Conturi și acces', '<p><a href="/">Vault personal</a> · <a href="/identity/shares">Partajări</a>' + (s.user.role === 'administrator' ? ' · <a href="/identity/admin">Administrare instanță</a>' : '') + '</p>' + accountPage(ctx, store, s.user, s.csrf), true);
  }));
  router.post('/logout', wrap((req, res) => { const s = requireSession(req); store.del('session', s.id); res.setHeader('Set-Cookie', 'identity=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'); res.redirect('/identity/login'); }));
  router.post('/revoke', wrap((req, res) => { if (req.body.confirm !== 'yes') throw new Error('Confirmation required'); const s = requireSession(req); store.revokeUser(s.user.id); res.redirect('/identity/login'); }));
  router.post('/invite', wrap((req, res) => { requireSession(req, true); const token = store.invite(String(req.body.name), req.body.role === 'administrator' ? 'administrator' : 'member'); page(res, 'Invitație (24 ore)', `<a href="/identity/activate?token=${esc(token)}">${esc(new URL('/identity/activate?token=' + token, provider.issuer).href)}</a>`); }));
  router.post('/reset', wrap((req, res) => { if (req.body.confirm !== 'yes') throw new Error('Confirmation required'); const s = requireSession(req, true); const u = store.get<User>('user', String(req.body.id)); if (!u || u.id === s.user.id) throw new Error('Invalid target'); const token = store.invite(u.name, u.role, u.id); page(res, 'Resetare cont', `<a href="/identity/activate?token=${esc(token)}">${esc(new URL('/identity/activate?token=' + token, provider.issuer).href)}</a>`); }));
  router.post('/disable', wrap((req, res) => { if (req.body.confirm !== 'yes') throw new Error('Confirmation required'); const s = requireSession(req, true); const u = store.get<User>('user', String(req.body.id)); if (!u || u.id === s.user.id) throw new Error('Invalid target'); store.put('user', u.id, { ...u, disabled: true }); store.revokeUser(u.id); res.redirect('/identity/'); }));
  router.post('/group', wrap((req, res) => { requireSession(req, true); const id = String(req.body.id), members = (Array.isArray(req.body.members) ? req.body.members.map(String) : String(req.body.members ?? '').split(',')).map((x: string) => x.trim()).filter(Boolean); members.forEach((id: string) => store.user(id)); store.put('group', id, { id, members }); res.redirect('/identity/'); }));
  router.post('/grant', wrap((req, res) => { if (ctx.registry) throw new Error('Use owner-managed sharing'); requireSession(req, true); const target = String(req.body.target ?? '').split(':'); const resourceRef = String(req.body.resourceRef ?? '').split(':');
    if (target.length === 2) { req.body.kind = target[0]; req.body.subject = target[1]; }
    if (resourceRef.length === 2) { req.body.type = resourceRef[0]; req.body.resource = resourceRef[1]; }
    const g: Grant = { id: randomUUID(), kind: req.body.kind, subject: String(req.body.subject), type: req.body.type, resource: String(req.body.resource) }; if (!['user', 'group'].includes(g.kind) || !['host', 'cluster'].includes(g.type) || !store.get(g.kind, g.subject) || !(g.type === 'host' ? ctx.vault.d.hosts : ctx.vault.d.clusters).some(x => x.id === g.resource)) throw new Error('Invalid grant'); store.put('grant', g.id, g); res.redirect('/identity/'); }));
  router.post('/remove-grant', wrap((req, res) => { if (req.body.confirm !== 'yes') throw new Error('Confirmation required'); requireSession(req, true); store.del('grant', String(req.body.id)); res.redirect('/identity/'); }));
  return router;
}

export function canonicalUrl(value: string) {
  const u = new URL(value);
  if (u.username || u.password || u.search || u.hash || (u.protocol !== 'https:' && !(u.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname)))) throw new Error('Remote URLs require HTTPS');
  return u;
}
