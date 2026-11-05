import express from 'express';
import { identityDocument, escapeHtml as e } from '../auth/ui.js';
import { session } from '../auth/session.js';
import type { OAuthProvider } from '../auth/oauth.js';
import type { Ctx } from '../service.js';
import type { TunnelManager } from '../tunnel/manager.js';
import { helperReady, setupHelper } from '../import/termiusLocal.js';
import type { WebTunnelManager } from '../tunnel/web.js';
import { clientSetup } from '../clients.js';
import { CloudflareSetup, CloudflareSetupError } from '../tunnel/cloudflare.js';
import { cloudflarePanel } from './cloudflare.js';

/** Instance-wide controls. Deliberately independent of any personal vault. */
export function infrastructureRouter(ctx: Ctx, provider: OAuthProvider, tunnel: TunnelManager, dataDir: string, webTunnel?: WebTunnelManager) {
  const router = express.Router();
  const cloudflare = webTunnel ? new CloudflareSetup(provider.store, webTunnel) : undefined;
  const jobs = new Map<string, { state: 'running' | 'completed' | 'failed'; message: string }>();
  router.use((req, res, next) => {
    const s = session(provider.store, req);
    if (!s) return void res.status(401).send('Authentication required');
    if (s.user.role !== 'administrator') return void res.status(403).send('Administrator required');
    if (req.method !== 'GET' && req.method !== 'HEAD' && req.body?.csrf !== s.csrf) return void res.status(403).send('Invalid CSRF token');
    if (req.method !== 'GET' && req.method !== 'HEAD') session(provider.store, req, true);
    next();
  });
  const postForm = (csrf: string, action: string, label: string, fields = '', disabled = false) => `<form method="post" action="/identity/admin/${action}"><input type="hidden" name="csrf" value="${e(csrf)}">${fields}<button type="submit" ${disabled ? 'disabled' : ''}>${label}</button></form>`;
  router.get('/', async (req, res, next) => {
    try {
      const s = session(provider.store, req)!, status = await tunnel.status();
      const job = (id: string) => { const j = jobs.get(id); return j ? `<p role="status" class="${j.state === 'failed' ? 'bad' : 'mut'}">${e(j.message)}${j.state === 'running' ? '<progress aria-label="Operatie in curs"></progress>' : ''}</p>` : ''; };
      const busy = [...jobs.values()].some(j => j.state === 'running');
      const body = `<p><a href="/">Vaultul meu</a> · <a href="/identity/">Conturi și acces</a></p><div class="security-banner">Setări comune instanței. Instalările și tunelurile sunt disponibile numai administratorilor și nu depind de deblocarea unui vault personal.</div><div class="identity-grid"><div class="card"><h3>Tunel OpenAI comun</h3><p>Stare: <strong>${status.running ? status.ready ? 'Conectat' : 'Pornit, nepregătit' : 'Oprit'}</strong></p><p>Runtime: ${status.installed ? e(status.version || 'Instalat') : 'Neinstalat'}</p>${job('tunnel-install')}${postForm(s.csrf, 'tunnel/configure', 'Salvează configurația', `<label>Tunnel ID<input required name="tunnelId" value="${e(status.tunnelId)}" autocomplete="off"></label><label>API key runtime ${status.hasApiKey ? '(gol = păstrează cheia salvată)' : ''}<input name="apiKey" type="password" autocomplete="new-password"></label><label><input name="autoStart" type="checkbox" value="yes" ${status.autoStart ? 'checked' : ''}> Pornește automat cu instanța</label>`)}${postForm(s.csrf, 'tunnel/start', 'Pornește tunelul', '', status.running)}${postForm(s.csrf, 'tunnel/stop', 'Oprește tunelul', '', !status.running)}<p class="form-note">În ChatGPT: Connection → Tunnel, Authentication → OAuth. Fiecare utilizator se conectează cu propriul cont. Tunelul nu acordă acces la vaulturi.</p>${status.running && !status.ready ? '<div class="operation-progress" role="status">Conectare tunel OpenAI in curs. Starea se actualizeaza automat.<progress aria-label="Conectare tunel OpenAI"></progress></div>' : ''}${status.lastError ? `<p class="bad">${e(status.lastError)}</p>` : ''}</div><div class="card"><h3>HTTPS privat și DNS</h3><p>Certificate Let’s Encrypt prin DNS-01, DNS-only Cloudflare către IP-ul privat al serverului.</p><a class="button" href="/identity/admin/tls">Configurează HTTPS privat →</a><p class="form-note">Accesul prin VPN și firewallul sunt administrate separat. Nu este creat un Cloudflare Tunnel public.</p></div></div><h2>Componente instalate pe server / container</h2><div class="identity-grid"><div class="card"><h3>OpenAI tunnel-client</h3><p>Runtime oficial, descărcat și verificat SHA-256. Actualizarea poate opri tunelul existent.</p>${postForm(s.csrf, 'tunnel/install', status.installed ? 'Actualizează runtime-ul' : 'Instalează runtime-ul', '<label><input type="checkbox" name="confirm" value="yes" required> Confirm instalarea sau actualizarea componentei comune.</label>', busy || status.installing)}</div><div class="card"><h3>Ajutor pentru import Termius</h3><p>${process.platform === 'win32' ? helperReady(dataDir) ? 'Instalat în mediul Python izolat.' : 'Neinstalat. Necesită Python 3, git și acces la Internet.' : 'Importul Termius Desktop local este disponibil numai pe Windows.'}</p><p class="form-note">Instalează doar componenta ccl_chromium_reader în mediul izolat al aplicației. Nu modifică pachetele sistemului sau imaginea containerului.</p>${job('termius-install')}${process.platform === 'win32' ? postForm(s.csrf, 'software/termius', 'Instalează ajutorul Termius', '<label><input type="checkbox" name="confirm" value="yes" required> Confirm descărcarea și instalarea.</label>', busy) : ''}</div></div><p><a class="button" href="/identity/admin">Actualizează starea</a></p>`;
      const w = webTunnel?.status();
      const web = w ? `<h2>Gemini Web si Claude Web</h2><div class="card"><h3>Tunel HTTPS comun (Cloudflare)</h3><p>Stare: <strong>${w.connected ? 'Conectat la Cloudflare' : w.running ? 'Pornit, conectare in curs' : w.reconnecting ? 'Reconectare in curs' : 'Oprit'}</strong> · Runtime: ${w.installed ? 'Instalat' : 'Neinstalat'}</p><p>Ambele aplicatii folosesc acelasi endpoint MCP si OAuth individual. Nu este necesar un CLI Gemini sau Claude pe server.</p>${job('web-tunnel-install')}${postForm(s.csrf, 'web-tunnel/install', w.installed ? 'Actualizeaza cloudflared' : 'Instaleaza cloudflared', '<label><input required type="checkbox" name="confirm" value="yes"> Confirm descarcarea runtime-ului oficial Cloudflare, verificat SHA-256.</label>', busy || w.installing || w.running || w.reconnecting)}${postForm(s.csrf, 'web-tunnel/configure', 'Salveaza conexiunea web', `<label>URL public HTTPS<input required type="url" name="origin" placeholder="https://mcp.example.com" value="${e(w.origin)}"></label><label>Cloudflare Tunnel token ${w.hasToken ? '(gol = pastreaza tokenul salvat)' : ''}<input type="password" name="token" autocomplete="new-password"></label><label><input type="checkbox" name="autoStart" value="yes" ${w.autoStart ? 'checked' : ''}> Conecteaza automat la pornirea instantei</label>`)}${postForm(s.csrf, 'web-tunnel/start', 'Conecteaza Gemini / Claude Web', '', w.running || w.reconnecting || !w.installed || !w.hasToken || w.restartRequired)}${postForm(s.csrf, 'web-tunnel/stop', 'Deconecteaza tunelul web', '', !w.running && !w.reconnecting)}${w.restartRequired ? '<p role="status" class="bad">Reporneste aplicatia pentru activarea URL-ului public OAuth. AUTH_URL si MCP_PUBLIC_URL, daca sunt definite in mediu, trebuie sa corespunda acestui URL.</p>' : ''}${w.running && !w.connected || w.reconnecting ? '<div class="operation-progress" role="status">Conectare Cloudflare in curs. Starea se actualizeaza automat.<progress aria-label="Conectare Cloudflare"></progress></div>' : ''}${w.lastError ? `<p class="bad">${e(w.lastError)}</p>` : ''}<details><summary>Configurarea rutei Cloudflare</summary><ol><li>In Cloudflare Zero Trust creeaza un tunel Cloudflared administrat din dashboard si copiaza tokenul aici.</li><li>Adauga un public hostname identic cu URL-ul de mai sus, service HTTP catre <code>http://127.0.0.1:${webTunnel!.mcpPort}</code>. Nu indica portul admin. In container foloseste portul MCP din acelasi container.</li><li>Salveaza, reporneste aplicatia pentru noul URL OAuth, apoi conecteaza tunelul sau bifeaza pornirea automata.</li><li>Adauga endpointul MCP in fiecare aplicatie si confirma OAuth cu propriul cont. Un login Cloudflare Access interactiv in fata rutei impiedica accesul aplicatiilor.</li></ol><p>Tunelul publica portul MCP si paginile de autentificare prin HTTPS. Tokenul este criptat pe disc. Bifa porneste transportul; nu autentifica automat conturile Google sau Anthropic.</p></details><p class="form-note">Claude Remote Control sincronizeaza sesiuni Claude Code; nu este un tunel MCP pentru Claude Web. <a href="https://code.claude.com/docs/en/remote-control" target="_blank" rel="noreferrer">Documentatie Remote Control</a>.</p></div><div class="identity-grid">${['gemini-web', 'claude-web', 'gemini-cli', 'claude-cli'].map(id => { const c = clientSetup(id, '', { endpoint: provider.resource.href, nodePath: process.execPath, bridgePath: '' }); return `<div class="card"><h3>${e(c.name)}</h3><p>${e(c.instructions)}</p>${c.blocks.map(b => `<p>${e(b.title)}</p><pre>${e(b.content)}</pre>`).join('')}</div>`; }).join('')}</div><p><a href="https://developers.google.com/connected-apps/mcp/dev-mode/usage" target="_blank" rel="noreferrer">Configurare Gemini Web</a> · <a href="https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp" target="_blank" rel="noreferrer">Configurare Claude Web</a></p>` : '';
      if (busy || cloudflare?.busy || status.running && !status.ready || w?.running && !w.connected || w?.reconnecting) res.setHeader('Refresh', '3');
      res.type('html').send(identityDocument('Administrare instanță', (cloudflare ? cloudflarePanel(cloudflare, s.csrf, busy || cloudflare.busy, w?.autoStart ?? false) + job('cloudflare-connect') + job('cloudflare-provision') : '') + web + body, true));
    } catch (error) { next(error); }
  });
  router.post('/tunnel/configure', (req, res) => {
    try { if ([...jobs.values()].some(j => j.state === 'running')) throw new Error(); tunnel.configure({ tunnelId: req.body.tunnelId, apiKey: req.body.apiKey, autoStart: req.body.autoStart === 'yes' }); ctx.audit.log({ client: 'admin-ui', host: '-', action: 'tunnel-configure', outcome: 'ok' }); res.redirect('/identity/admin'); }
    catch { res.status(400).send('Tunnel configuration rejected'); }
  });
  for (const operation of ['start', 'stop'] as const) router.post('/tunnel/' + operation, (_req, res) => {
    try { if ([...jobs.values()].some(j => j.state === 'running')) throw new Error(); tunnel[operation](); ctx.audit.log({ client: 'admin-ui', host: '-', action: 'tunnel-' + operation, outcome: 'ok' }); res.redirect('/identity/admin'); }
    catch { res.status(400).send('Tunnel operation failed; review administrator status'); }
  });
  const install = (path: string, id: string, operation: () => Promise<unknown>) => router.post(path, (req, res) => {
    if (req.body.confirm !== 'yes') return void res.status(400).send('Installation acknowledgement required');
    if ([...jobs.values()].some(j => j.state === 'running')) return void res.status(409).send('An installation is already running');
    jobs.set(id, { state: 'running', message: 'Instalare în curs. Reîncarcă starea pentru rezultat.' });
    ctx.audit.log({ client: 'admin-ui', host: '-', action: id, outcome: 'started' });
    void Promise.resolve().then(operation).then(() => { jobs.set(id, { state: 'completed', message: 'Instalare finalizată.' }); ctx.audit.log({ client: 'admin-ui', host: '-', action: id, outcome: 'ok' }); }, () => { jobs.set(id, { state: 'failed', message: 'Instalarea a eșuat. Verifică dependențele și accesul la Internet.' }); ctx.audit.log({ client: 'admin-ui', host: '-', action: id, outcome: 'failed' }); });
    res.redirect('/identity/admin');
  });
  install('/tunnel/install', 'tunnel-install', () => tunnel.install());
  if (webTunnel) {
    router.post('/cloudflare/connect', (req, res) => {
      if ([...jobs.values()].some(j => j.state === 'running') || cloudflare!.busy) return void res.status(409).send('An operation is already running');
      jobs.set('cloudflare-connect', { state: 'running', message: 'Conectare Cloudflare si incarcare domenii in curs.' });
      void cloudflare!.connect({ secret: req.body.secret ?? '', mode: req.body.mode ?? 'token', email: req.body.email ?? '' }).then(() => {
        jobs.set('cloudflare-connect', { state: 'completed', message: 'Cont Cloudflare conectat. Alege domeniul si subdomeniul.' });
        ctx.audit.log({ client: 'admin-ui', host: '-', action: 'cloudflare-connect', outcome: 'ok' });
      }, (error: unknown) => {
        jobs.set('cloudflare-connect', { state: 'failed', message: error instanceof CloudflareSetupError ? error.message : 'Conectarea Cloudflare a esuat. Verifica credentialele si accesul la Internet.' });
        ctx.audit.log({ client: 'admin-ui', host: '-', action: 'cloudflare-connect', outcome: 'failed' });
      });
      res.redirect('/identity/admin');
    });
    router.post('/cloudflare/provision', (req, res) => {
      if ([...jobs.values()].some(j => j.state === 'running') || cloudflare!.busy) return void res.status(409).send('An operation is already running');
      jobs.set('cloudflare-provision', { state: 'running', message: 'Configurare Cloudflare in curs. Progresul se actualizeaza automat.' });
      const input = { zoneId: req.body.zoneId, subdomain: req.body.subdomain, autoStart: req.body.autoStart === 'yes' };
      ctx.audit.log({ client: 'admin-ui', host: '-', action: 'cloudflare-provision', outcome: 'started' });
      void cloudflare!.provision(input).then(() => {
        jobs.set('cloudflare-provision', { state: 'completed', message: 'Cloudflare configurat. Verifica starea conexiunii si adauga URL-ul MCP in Gemini / Claude.' });
        ctx.audit.log({ client: 'admin-ui', host: '-', action: 'cloudflare-provision', outcome: 'ok' });
      }, (error: unknown) => {
        jobs.set('cloudflare-provision', { state: 'failed', message: error instanceof CloudflareSetupError ? error.message : 'Configurarea Cloudflare nu s-a finalizat. Verifica etapa afisata, credentialele, DNS si variabilele AUTH_URL / MCP_PUBLIC_URL, apoi reia operatia.' });
        ctx.audit.log({ client: 'admin-ui', host: '-', action: 'cloudflare-provision', outcome: 'failed' });
      });
      res.redirect('/identity/admin');
    });
    install('/web-tunnel/install', 'web-tunnel-install', () => webTunnel.install());
    router.post('/web-tunnel/configure', (req, res) => {
      try {
        if ([...jobs.values()].some(j => j.state === 'running')) return void res.status(409).send('Installation running');
        webTunnel.configure({ origin: req.body.origin, token: req.body.token ?? '', autoStart: req.body.autoStart === 'yes' });
        ctx.audit.log({ client: 'admin-ui', host: '-', action: 'web-tunnel-configure', outcome: 'ok' });
        res.redirect('/identity/admin');
      } catch { res.status(400).send('Web tunnel configuration rejected; use a public HTTPS origin and a Cloudflare tunnel token'); }
    });
    for (const operation of ['start', 'stop'] as const) router.post('/web-tunnel/' + operation, (_req, res) => {
      try {
        if ([...jobs.values()].some(j => j.state === 'running')) return void res.status(409).send('Installation running');
        if (operation === 'start' && provider.resource.href !== new URL('/mcp', provider.issuer).href) throw new Error('OAuth origin mismatch');
        webTunnel[operation]();
        ctx.audit.log({ client: 'admin-ui', host: '-', action: 'web-tunnel-' + operation, outcome: 'ok' });
        res.redirect('/identity/admin');
      } catch { res.status(400).send('Web tunnel operation failed; review configuration and restart the instance if required'); }
    });
  }
  install('/software/termius', 'termius-install', async () => { if (process.platform !== 'win32') throw new Error('Unsupported platform'); await setupHelper(dataDir); });
  return router;
}
