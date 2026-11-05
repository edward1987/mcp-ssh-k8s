"use strict";
const $app = document.getElementById("app");
const { notify, confirmAction, decorate } = window.SecureUI;
let csrf = null, tab = "overview", poll = null, renderSeq = 0, navSeq = 0, viewAbort = new AbortController();
let identityUser = null, lastApprovals = '';
const selected = new Set(), pendingGets = new Map();
try { document.documentElement.dataset.theme = localStorage.getItem('mcp-theme') === 'light' ? 'light' : 'dark'; } catch {}
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
async function api(method, url, body, background = false) {
  const key = url + ':' + (background ? 'background' : navSeq);
  if (method === 'GET' && pendingGets.has(key)) return pendingGets.get(key);
  const request = (async () => {
    const r = await fetch(url, { method, credentials: 'same-origin', cache: 'no-store', signal: method === 'GET' && !background ? viewAbort.signal : undefined,
      headers: { 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (j.code === 'APPLICATION_INTEGRITY_FAILED') { clearSensitive(); entry('Integritatea aplicației nu a putut fi verificată', 'Nu introduce parole. Reinstalează aplicația dintr-o sursă de încredere.', ''); throw new Error(j.error); }
    if (r.status === 401) { clearSensitive(); void render(); throw new Error('locked'); }
    if (!r.ok) throw new Error(j.error || 'Cererea nu a putut fi finalizată.');
    return j;
  })();
  if (method === 'GET') { pendingGets.set(key, request); request.finally(() => { if (pendingGets.get(key) === request) pendingGets.delete(key); }).catch(() => {}); }
  return request;
}
function clearSensitive() {
  csrf = null; selected.clear(); pendingGets.clear(); clearTimeout(poll); viewAbort.abort(); viewAbort = new AbortController();
  document.dispatchEvent(new Event('security-lock'));
  document.querySelectorAll('dialog').forEach(d => d.remove());
  $app.replaceChildren();
}
const act = fn => async (...args) => {
  if (args[0]?.type === 'submit') args[0].preventDefault();
  const button = args[0]?.currentTarget instanceof HTMLButtonElement ? args[0].currentTarget : args[0]?.submitter instanceof HTMLButtonElement ? args[0].submitter : null;
  if (button?.disabled) return;
  if (button) { button.disabled = true; button.setAttribute('aria-busy', 'true'); }
  const finishProgress = window.OperationProgress.start(button?.closest('form, dialog, .card') || document.getElementById('view') || $app, button?.textContent.trim() || 'Procesare date');
  try { await fn(...args); decorate(); } catch (e) { if (e.name !== 'AbortError' && e.message !== 'locked') notify(e.message, true); }
  finally { finishProgress(); if (button?.isConnected) { button.disabled = false; button.removeAttribute('aria-busy'); } }
};
const val = id => document.getElementById(id).value;
const el = html => { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstChild; };
const navigation = [
  ['overview', '◈', 'Privire de ansamblu', 'Starea infrastructurii și evenimentele recente, într-un singur loc.'],
  ['hosts', '⌘', 'Hosturi SSH', 'Conexiuni, politici de execuție și disponibilitatea serverelor.'],
  ['checklist', '✓', 'Checklist securitate', 'Verificări și rezultate pentru serverele selectate.'],
  ['k8s', '⬡', 'Kubernetes', 'Clustere și politici pentru operațiile kubectl.'],
  ['keys', '⚿', 'Chei SSH', 'Credențiale stocate în vaultul criptat.'],
  ['import', '↗', 'Import', 'Adaugă infrastructura din configurațiile existente.'],
  ['clients', '⇄', 'Clienți AI', 'Conectare individuală prin OAuth și MFA.'],
  ['approvals', '◇', 'Aprobări', 'Examinează comenzile înainte de a permite execuția.'],
  ['audit', '≡', 'Jurnal de audit', 'Activitate, identități și rezultate verificabile.'],
  ['settings', '⚙', 'Setări', 'Blocare automată, limite și parola master.'],
];
function entry(title, description, actions = '') {
  $app.innerHTML = `<main class="entry"><div class="brand-mark" aria-hidden="true">›_</div><div class="eyebrow">MCP SSH · Control Center</div><h1>${esc(title)}</h1><p class="mut">${esc(description)}</p>${actions}<p class="entry-note">Acces individual · OAuth · MFA<br>Credențialele SSH rămân în vaultul criptat.</p></main>`;
}
async function updateBadges() {
  const [a, cl] = await Promise.all([api('GET', '/api/approvals', undefined, true), api('GET', '/api/checklist', undefined, true)]);
  const b = document.getElementById('badge-approvals'); if (b) b.textContent = a.length ? ` ${a.length}` : '';
  const c = document.getElementById('badge-checklist'); if (c) c.textContent = cl.length ? ` ${cl.length}` : '';
  document.title = (a.length ? `(${a.length}) ` : '') + 'MCP SSH · Control Center';
  return { approvals: a, checklist: cl };
}
async function switchTab(nextTab) {
  if (!navigation.some(n => n[0] === nextTab)) return;
  viewAbort.abort(); viewAbort = new AbortController(); tab = nextTab; const sequence = ++navSeq;
  $app.querySelector('.shell')?.classList.remove('nav-open');
  document.querySelectorAll('nav button').forEach(b => { b.classList.toggle('on', b.dataset.t === tab); b.setAttribute('aria-current', b.dataset.t === tab ? 'page' : 'false'); });
  const current = navigation.find(n => n[0] === tab);
  document.getElementById('page-title').textContent = current[2]; document.getElementById('page-description').textContent = current[3]; document.getElementById('breadcrumb-page').textContent = current[2];
  const view = document.getElementById('view'); view.setAttribute('aria-busy', 'true'); view.innerHTML = '<div class="loading" role="status" aria-label="Se încarcă"></div>';
  try { await views[tab](); if (sequence === navSeq) { decorate(view); view.focus({ preventScroll: true }); } }
  catch (error) { if (error.name !== 'AbortError' && error.message !== 'locked' && sequence === navSeq) { view.innerHTML = `<div class="view-error"><h3>Nu am putut încărca datele</h3><p>${esc(error.message)}</p><button id="retry-view">Încearcă din nou</button></div>`; document.getElementById('retry-view').onclick = () => switchTab(tab); } }
  finally { if (sequence === navSeq && view.isConnected) view.removeAttribute('aria-busy'); }
}
function schedulePoll() {
  clearTimeout(poll);
  poll = setTimeout(async () => {
    if (document.hidden || !csrf) return;
    try {
      const { approvals } = await updateBadges();
      const signature = JSON.stringify(approvals.map(a => a.id));
      // Never replace a focused approval button while the operator is deciding.
      if (tab === 'approvals' && signature !== lastApprovals && !(document.activeElement?.tagName === 'BUTTON' && document.getElementById('view')?.contains(document.activeElement))) { await views.approvals(); decorate(); }
      const state = document.getElementById('connection-state'); if (state) state.textContent = 'Vault deblocat';
    } catch (e) { if (e.message !== 'locked' && e.name !== 'AbortError') { const state = document.getElementById('connection-state'); if (state) state.textContent = 'Conexiune întreruptă'; } }
    if (csrf) schedulePoll();
  }, 8000);
}
async function render() {
  clearTimeout(poll); const sequence = ++renderSeq;
  try {
    const identity = await fetch('/identity/me', { cache: 'no-store', credentials: 'same-origin' }).then(r => r.json());
    if (sequence !== renderSeq) return;
    identityUser = identity.user;
    if (!identity.user) { clearSensitive(); entry('Administrare securizată', 'Autentifică-te cu propriul cont pentru a continua.', '<a class="button p" href="/identity/login">Autentificare cu MFA →</a><a class="button" href="/identity/bootstrap">Configurare inițială</a>'); return; }

    const response = await fetch('/api/status', { cache: 'no-store', credentials: 'same-origin' });
    if (response.status === 401) { clearSensitive(); entry('Sesiunea a expirat', 'Autentifică-te din nou pentru a accesa administrarea.', '<a class="button p" href="/identity/login">Autentificare</a>'); return; }
    const status = await response.json(); if (sequence !== renderSeq) return;
    if (!status.unlocked) { clearSensitive(); renderLogin(status.exists, status.legacyAvailable); return; }
    csrf = status.csrf;
    if (!document.getElementById('view')) {
      $app.innerHTML = `<div class="shell"><aside class="sidebar"><a class="brand" href="/"><span class="brand-mark" aria-hidden="true">›_</span><span><strong>MCP SSH</strong><small>Control Center</small></span></a><nav aria-label="Navigare principală"><span class="nav-label">Infrastructură</span>${navigation.map((n,i) => `${i === 6 ? '<span class="nav-label">Conectare și control</span>' : ''}<button data-t="${n[0]}"><span class="nav-symbol" aria-hidden="true">${n[1]}</span>${n[2]}<span id="badge-${n[0]}"></span></button>`).join('')}</nav><div class="sidebar-bottom">${identityUser.role === 'administrator' ? '<a class="button" href="/identity/admin">Administrare instanță ↗</a>' : ''}<a class="button" href="/identity/">Conturi și acces ↗</a><a class="button" href="/identity/shares">Partajări temporare ↗</a><button class="b d" id="lock">Blochează vaultul</button><span class="mut">Autentificare individuală<br>Permisiuni verificate pe server</span></div></aside><div class="workspace"><header class="topbar"><div class="row"><button class="mobile-toggle" id="menu-toggle" aria-label="Deschide meniul" aria-expanded="false">☰</button><span class="breadcrumb">Workspace / <strong id="breadcrumb-page"></strong></span></div><div class="top-actions"><span class="state" id="connection-state">Vault deblocat</span><span class="user-chip">${esc(identity.user.name)} · ${identity.user.role === 'administrator' ? 'Administrator conturi' : 'Utilizator'}</span><button id="theme-toggle" aria-label="Schimbă tema">◐</button></div></header><main class="content"><div class="page-intro"><div><div class="eyebrow">Administrare infrastructură</div><h1 id="page-title"></h1><p id="page-description"></p></div></div><section id="view" tabindex="-1" aria-label="Conținut pagină"></section></main></div></div>`;
      $app.querySelectorAll('nav button').forEach(b => b.onclick = () => switchTab(b.dataset.t));
      document.getElementById('lock').onclick = act(async () => { await api('POST', '/api/lock', {}); clearSensitive(); await render(); });
      document.getElementById('theme-toggle').onclick = () => { const theme = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light'; document.documentElement.dataset.theme = theme; try { localStorage.setItem('mcp-theme', theme); } catch {} };
      document.getElementById('menu-toggle').onclick = event => { const open = $app.querySelector('.shell').classList.toggle('nav-open'); event.currentTarget.setAttribute('aria-expanded', String(open)); };
    }
    document.getElementById('legacy-migration')?.remove();
    if (status.legacyAvailable) appendLegacyMigration(document.querySelector('.content'), status.exists);
    await switchTab(tab); if (sequence === renderSeq && csrf) schedulePoll();
  } catch (e) { if (sequence === renderSeq) { clearSensitive(); entry('Serviciu indisponibil', 'Verifică dacă aplicația rulează și reîncarcă pagina.', '<a class="button p" href="/">Reîncarcă</a>'); } }
}
function renderLogin(exists, legacyAvailable = false) {
  $app.innerHTML = `<form id="login" class="card"><a class="brand" href="/identity/"><span class="brand-mark" aria-hidden="true">›_</span><span><strong>MCP SSH</strong><small>Vault criptat</small></span></a><h2>${exists ? "Vaultul este blocat" : "Creează vaultul personal"}</h2><p class="mut">Ești autentificat ca ${esc(identityUser?.name)}. Introdu parola master pentru acces la infrastructură.</p><div class="security-banner"><strong>Parola master</strong> decriptează vaultul. Este separată de parola contului.</div><input type="text" name="username" value="mcp-ssh-vault" autocomplete="username" hidden><label for="pw">Parolă master</label><input required type="password" id="pw" name="password" autocomplete="current-password"><button type="submit" class="b p">${exists ? "Deblochează vaultul" : "Creează vaultul"}</button><span id="err" class="bad" role="alert"></span><p class="form-note"><a href="/identity/">Cont și sesiuni →</a>${identityUser?.role === 'administrator' ? ' · <a href="/identity/admin">Administrare instanță →</a>' : ''}</p></form>`;
  document.getElementById('login').onsubmit = async event => {
    event.preventDefault(); const button = event.submitter; button.disabled = true;
    const finishProgress = window.OperationProgress.start(event.currentTarget, button.textContent.trim());
    try { const result = await api('POST', exists ? '/api/unlock' : '/api/setup', { password: val('pw') }); document.getElementById('pw').value = ''; csrf = result.csrf;
      if (result.recoveryKey) { entry('Salvează cheia de recuperare', 'Fără parola master sau această cheie, datele nu pot fi recuperate.', `<pre>${esc(result.recoveryKey)}</pre><button id="recovery-saved" class="p">Am păstrat cheia în siguranță</button>`); document.getElementById('recovery-saved').onclick = () => render(); } else await render(); }
    catch (e) { const error = document.getElementById('err'); if (error) error.textContent = e.message; }
    finally { finishProgress(); if (button.isConnected) button.disabled = false; }
  };
  const recovery = document.createElement('div'); recovery.className = 'entry';
  recovery.innerHTML = `<details><summary>Recuperare vault personal</summary><label>Parolă master nouă<input type="password" id="recovery-password" autocomplete="new-password"></label><label>Cheie de recuperare<input type="password" id="recovery-secret"></label><button id="recover-vault">Recuperează</button><p class="bad" id="recovery-error" role="alert"></p></details>`; $app.append(recovery);
  document.getElementById('recover-vault').onclick = act(async () => { const result = await api('POST', '/api/recover', { password: val('recovery-password'), recovery: val('recovery-secret') }); entry('Salvează cheia de recuperare', 'Păstrează cheia separat de aplicație.', `<pre>${esc(result.recoveryKey)}</pre><button id="recovery-saved">Continuă</button>`); document.getElementById('recovery-saved').onclick = () => render(); });
  if (legacyAvailable) appendLegacyMigration($app, exists);
  document.getElementById('pw').focus();
}
function appendLegacyMigration(target, exists) {
  const panel = el(`<div class="card" id="legacy-migration"><h2>Vaultul vechi este disponibil</h2><p>Datele vechi sunt încă în <code>vault.json</code>. Nu au fost atribuite automat contului tău.</p><p class="form-note">${exists ? 'Poți importa în vaultul personal dacă este gol. Datele existente nu vor fi suprascrise; cheia sa de recuperare rămâne valabilă.' : 'Importul creează vaultul tău personal și păstrează o copie de siguranță a celui vechi.'}</p><form id="legacy-migration-form"><label for="legacy-password">Parola master a vaultului vechi</label><input required type="password" id="legacy-password" autocomplete="current-password"><label for="legacy-personal-password">${exists ? 'Parola master a vaultului personal existent' : 'Parolă master pentru noul vault personal'}</label><input required minlength="12" maxlength="1024" type="password" id="legacy-personal-password" autocomplete="${exists ? 'current-password' : 'new-password'}"><label><input required type="checkbox" name="confirm"> Confirm că vaultul vechi îmi aparține și îl import în acest cont.</label><button type="submit" class="p">Importă vaultul vechi în contul meu</button><p class="bad" id="migration-error" role="alert"></p></form></div>`);
  target.prepend(panel);
  panel.querySelector('form').onsubmit = act(async () => {
    const error = panel.querySelector('#migration-error'); error.textContent = '';
    try {
      const result = await api('POST', '/api/migrate', { oldPassword: val('legacy-password'), password: val('legacy-personal-password') });
      panel.querySelectorAll('input[type=password]').forEach(input => { input.value = ''; });
      if (result.recoveryKey) {
        entry('Salvează cheia de recuperare', 'Vaultul vechi a fost importat. Păstrează această cheie separat de aplicație.', `<pre>${esc(result.recoveryKey)}</pre><button id="recovery-saved">Deschide vaultul</button>`);
        document.getElementById('recovery-saved').onclick = () => render();
      } else {
        await render(); notify('Vaultul vechi a fost importat. Cheia de recuperare existentă rămâne valabilă.');
      }
    } catch (failure) { error.textContent = failure.message; }
  });
}

document.addEventListener('visibilitychange', () => { if (document.hidden) clearTimeout(poll); else if (csrf) { void api('GET', '/api/status', undefined, true).then(() => schedulePoll()).catch(() => {}); } });
let lastActivitySent = 0;
const recordInteraction = event => {
  if (!event.isTrusted || !csrf || document.hidden || event.target.closest?.('#lock') || Date.now() - lastActivitySent < 60000) return;
  lastActivitySent = Date.now();
  void api('POST', '/api/activity', {}).catch(() => {});
};
document.addEventListener('pointerdown', recordInteraction, { passive: true });
document.addEventListener('keydown', recordInteraction, { passive: true });
window.addEventListener('pageshow', event => { if (event.persisted) { clearSensitive(); void render(); } });
window.addEventListener('pagehide', () => clearSensitive());

// ---- views ----
const views = {
  async overview() {
    const [hosts, clusters, approvals, audit] = await Promise.all([
      api('GET', '/api/hosts'), api('GET', '/api/clusters'), api('GET', '/api/approvals'), api('GET', '/api/audit'),
    ]);
    const online = hosts.filter(h => h.online === true).length;
    const unrestricted = [...hosts, ...clusters].filter(r => r.mode === 'free').length;
    const metric = (label, value, note, warning = false) => `<div class="metric ${warning ? 'warning' : ''}"><span class="metric-label">${label}</span><strong class="metric-value">${value}</strong><span class="metric-note">${note}</span></div>`;
    document.getElementById('view').innerHTML = `<div class="metrics">${metric('Hosturi SSH', hosts.length, `${online} confirmate online`)}${metric('Clustere Kubernetes', clusters.length, 'Configurații în vault')}${metric('Aprobări în așteptare', approvals.length, 'Decizii ale operatorului', approvals.length > 0)}${metric('Resurse în modul FREE', unrestricted, 'Execuție fără aprobare', unrestricted > 0)}</div><div class="overview-grid"><div class="card"><div class="section-title"><h3>Activitate recentă</h3><button data-overview="audit">Vezi jurnalul →</button></div>${audit.slice(-7).reverse().map(r => `<div class="activity"><span class="activity-mark ${r.outcome === 'ok' ? '' : 'bad'}" aria-hidden="true"></span><div><strong>${esc(r.action)} · ${esc(r.host)}</strong><p>${esc(r.outcome)} · ${esc(r.userId || r.client)}<br>${esc(String(r.ts).replace('T', ' ').slice(0, 19))}</p></div></div>`).join('') || '<div class="empty-state">Evenimentele de administrare și execuție vor apărea aici.</div>'}</div><div><div class="card"><div class="section-title"><h3>Controale de acces</h3><span class="tag ok">Active</span></div><div class="security-item"><strong>Identitate individuală</strong><span>OAuth și MFA pentru fiecare cont.</span></div><div class="security-item"><strong>Acces explicit</strong><span>Hosturile și clusterele necesită permisiuni atribuite.</span></div><div class="security-item"><strong>Politici de execuție</strong><span>read-only, approval sau free, în funcție de resursă.</span></div><p><a href="/identity/">Gestionează conturile și permisiunile →</a></p></div><div class="card"><h3>Coada operatorului</h3><p class="mut">${approvals.length ? `${approvals.length} cereri așteaptă examinarea comenzii și a destinației.` : 'Nu există cereri de aprobare în așteptare.'}</p><button class="b ${approvals.length ? 'p' : ''}" data-overview="approvals">Deschide aprobările →</button></div></div></div>`;
    document.querySelectorAll('[data-overview]').forEach(b => b.onclick = () => switchTab(b.dataset.overview));
  },
  async hosts() {
    const dot = (h) => `<span data-dot="${esc(h.id)}">${h.online === undefined ? "" : h.online ? '<span class="ok" title="accesibil">●</span>' : `<b class="bad" title="${esc(h.offlineReason || "")}">●</b>`}</span>`;
    const [hosts, keys, checklist] = await Promise.all([api("GET", "/api/hosts"), api("GET", "/api/keys"), api("GET", "/api/checklist")]);
    const checkHostIds = new Set(checklist.map((c) => c.hostId));
    const v = document.getElementById("view");
    v.innerHTML = `<div class="row" data-layout="legacy-0"><h2>Hosturi</h2><div class="row"><button class="b" id="recheck">Verifică disponibilitatea</button><button class="b p" id="new">+ Host nou</button></div></div>
      <dialog id="host-dialog"></dialog>
      ${hosts.length ? `<div class="card row" id="bulk" data-layout="legacy-1">
        <label data-layout="legacy-2"><input type="checkbox" id="sel-all" data-layout="legacy-3"> toate</label>
        <select id="sel-group" data-layout="legacy-3"><option value="">selectează grup…</option>${[...new Set(hosts.map((h) => h.group).filter(Boolean))].map((g) => `<option>${esc(g)}</option>`).join("")}</select>
        <span class="mut" id="sel-n"></span>
        <span data-layout="legacy-4"></span>
        <button class="b" id="bulk-checklist">+ Adaugă în Checklist</button>
        <label data-layout="legacy-2">Mod: <select id="bulk-mode" data-layout="legacy-3"><option value="approval">approval</option><option value="read-only">read-only</option><option value="free">free</option></select></label>
        <button class="b p" id="bulk-go">Aplică mod</button></div>` : ""}
      ${hosts.length ? "" : '<p class="mut">Niciun host. Adaugă unul sau folosește Import.</p>'}
      ${hosts.map((h) => `<div class="card" id="host-card-${esc(h.id)}"><div class="row" data-layout="legacy-0">
        <div><input type="checkbox" class="sel" data-id="${esc(h.id)}" data-layout="legacy-3" ${selected.has(h.id) ? "checked" : ""}> ${dot(h)} <b>${esc(h.name)}</b>${h.online === false ? ' <span class="tag">offline – ascuns din MCP</span>' : ""} <span class="mut">${esc(h.user)}@${esc(h.hostname)}:${esc(h.port)}</span>
        <span class="tag">${esc(h.mode)}</span> <span class="tag">${h.auth === "key" ? "cheie" : "parolă"}</span>
        ${h.group ? `<span class="tag">${esc(h.group)}</span>` : ""}
        <span id="cl-tag-${esc(h.id)}">${checkHostIds.has(h.id) ? '<span class="tag ok">✓ Checklist</span>' : ""}</span>
        ${h.auth === "key" ? `<div data-layout="legacy-5">cheie: <b>${esc(h.keyName || "?")}</b> ${h.keyValid ? '<span class="ok">valid</span>' : '<b class="bad">INVALID (nu conține cheia privată)</b>'} <span class="mut">${esc(h.keyFingerprint || "")}</span></div>` : ""}
        <div class="mut" data-layout="legacy-5">${h.fingerprint ? "host key: " + esc(h.fingerprint) : "host key nefixat (se fixează la prima conectare)"}</div></div>
        <div class="row"><span id="cl-btn-${esc(h.id)}">${checkHostIds.has(h.id) ? `<button class="b" data-check-del="${esc(h.id)}">Scoate din Checklist</button>` : `<button class="b" data-check-add="${esc(h.id)}">+ Checklist</button>`}</span><button class="b" data-test="${esc(h.id)}">Test</button><button class="b" data-edit="${esc(h.id)}">Editează</button><button class="b d" data-del="${esc(h.id)}">Șterge</button></div></div>
        <pre class="hidden" id="out-${esc(h.id)}"></pre></div>`).join("")}`;
    document.getElementById("recheck").onclick = act(async () => {
      await api("POST", "/api/hosts/check", {});
      // results land per host while the sweep runs: refresh the dots a few times without blocking the page
      for (let i = 0; i < 5 && tab === "hosts"; i++) { await new Promise((r) => setTimeout(r, 1500)); if (tab === "hosts") await refreshDots(); }
    });
    const hostIds = hosts.map((h) => h.id);
    const syncSel = () => {
      for (const id of [...selected]) if (!hostIds.includes(id)) selected.delete(id);
      v.querySelectorAll(".sel").forEach((c) => (c.checked = selected.has(c.dataset.id)));
      const all = document.getElementById("sel-all");
      if (all) { all.checked = hostIds.length > 0 && selected.size === hostIds.length; all.indeterminate = selected.size > 0 && selected.size < hostIds.length; }
      const n = document.getElementById("sel-n"); if (n) n.textContent = selected.size ? `${selected.size} selectate` : "";
    };
    v.querySelectorAll(".sel").forEach((c) => (c.onchange = () => { c.checked ? selected.add(c.dataset.id) : selected.delete(c.dataset.id); syncSel(); }));
    if (hosts.length) {
      document.getElementById("sel-all").onchange = (e) => { selected.clear(); if (e.target.checked) hosts.filter(h => !document.getElementById('host-card-' + h.id)?.hidden).forEach(h => selected.add(h.id)); syncSel(); };
      document.getElementById("sel-group").onchange = (e) => {
        if (e.target.value) hosts.filter((h) => h.group === e.target.value).forEach((h) => selected.add(h.id));
        e.target.value = ""; syncSel();
      };
      const bClBulk = document.getElementById("bulk-checklist");
      if (bClBulk) bClBulk.onclick = act(async () => {
        if (!selected.size) throw new Error("Nu e selectat niciun host");
        await api("POST", "/api/checklist", { hostIds: [...selected] });
        for (const id of selected) updateChecklistUI(id, true);
        void updateBadges();
      });
      document.getElementById("bulk-go").onclick = act(async () => {
        if (!selected.size) throw new Error("Nu e selectat niciun host");
        const mode = val("bulk-mode");
        if (mode === "free" && !await confirmAction(`Setezi ${selected.size} hosturi pe FREE? AI-ul va rula orice comandă fără aprobare.`)) return;
        await api("POST", "/api/hosts/mode", { ids: [...selected], mode });
        render();
      });
      syncSel();
    }
    const toolbar = document.createElement('div'); toolbar.className = 'toolbar';
    toolbar.innerHTML = '<input type="search" id="host-search" placeholder="Caută host, adresă, utilizator sau grup…" aria-label="Caută hosturi"><select id="host-mode" aria-label="Filtrează după politică"><option value="">Toate politicile</option><option>read-only</option><option>approval</option><option>free</option></select><span class="mut tiny" id="host-count" role="status"></span>';
    document.getElementById('bulk')?.before(toolbar);
    if (!toolbar.isConnected) v.querySelector('dialog').after(toolbar);
    const filterHosts = () => {
      const query = val('host-search').toLocaleLowerCase('ro'), mode = val('host-mode'); let count = 0;
      hosts.forEach(h => { const card = document.getElementById('host-card-' + h.id); const visible = (!mode || h.mode === mode) && [h.name,h.hostname,h.user,h.group,...(h.tags || [])].join(' ').toLocaleLowerCase('ro').includes(query); if (card) card.hidden = !visible; if (visible) count++; });
      document.getElementById('host-count').textContent = `${count} din ${hosts.length} hosturi`;
    };
    document.getElementById('host-search').oninput = filterHosts; document.getElementById('host-mode').onchange = filterHosts; filterHosts();
    const refreshDots = async () => {
      for (const h of await api("GET", "/api/hosts")) {
        const d = document.querySelector(`[data-dot="${CSS.escape(h.id)}"]`);
        if (d) d.outerHTML = dot(h);
      }
    };
    const form = (h = {}) => {
      const dlg = document.getElementById("host-dialog");
      dlg.innerHTML = `
        <div class="row" data-layout="legacy-6">
          <h3 data-layout="legacy-2">${h.id ? `Editează Host: ${esc(h.name)}` : "Host nou"}</h3>
          <button class="b" id="dlg-close" type="button" data-layout="legacy-7">×</button>
        </div>
        <form id="f-host-form">
          <div class="grid">
            <div><label>Nume</label><input id="f-name" value="${esc(h.name)}" required></div>
            <div><label>Hostname / IP</label><input id="f-host" value="${esc(h.hostname)}" required></div>
            <div><label>Port</label><input id="f-port" type="number" value="${h.port || 22}"></div>
            <div><label>Utilizator</label><input id="f-user" value="${esc(h.user)}" required></div>
            <div><label>Autentificare</label><select id="f-auth"><option value="key">Cheie SSH</option><option value="password">Parolă</option></select></div>
            <div id="w-key"><label>Cheie</label><select id="f-key">${keys.map((k) => `<option value="${esc(k.id)}" ${k.id === h.keyId ? "selected" : ""}>${esc(k.name)}</option>`).join("")}</select></div>
            <div id="w-pw"><label>Parolă ${h.hasPassword ? "(lasă gol = neschimbată)" : ""}</label><input id="f-pw" type="password" autocomplete="new-password"></div>
            <div><label>Mod siguranță</label><select id="f-mode">
              <option value="approval">approval - aprobi fiecare comandă</option>
              <option value="read-only">read-only - doar comenzi din allowlist</option>
              <option value="free">free - AI-ul rulează orice</option></select></div>
            <div><label>Grup</label><input id="f-group" value="${esc(h.group)}"></div>
          </div>
          <label data-layout="legacy-8">Allowlist suplimentar read-only (un prefix de comandă pe linie, ex: <code>systemctl status</code>)</label>
          <textarea id="f-allow">${esc((h.allowlist || []).join("\n"))}</textarea>
          ${h.id ? `<label data-layout="legacy-9"><input type="checkbox" id="f-reset" data-layout="legacy-3"> Resetează host key fixat (după reinstalare server)</label>` : ""}
          <div class="row" data-layout="legacy-10">
            <button class="b" id="cancel" type="button">Anulează</button>
            <button class="b p" id="save" type="submit">Salvează</button>
          </div>
        </form>`;

      document.getElementById("f-auth").value = h.auth || "key";
      document.getElementById("f-mode").value = h.mode || "approval";

      const sync = () => {
        const k = val("f-auth") === "key";
        document.getElementById("w-key").classList.toggle("hidden", !k);
        document.getElementById("w-pw").classList.toggle("hidden", k);
      };
      document.getElementById("f-auth").onchange = sync;
      sync();

      const close = () => {
        dlg.close();
        dlg.innerHTML = "";
      };
      document.getElementById("cancel").onclick = close;
      document.getElementById("dlg-close").onclick = close;

      dlg.onclick = (e) => {
        if (e.target === dlg) close();
      };

      document.getElementById("f-host-form").onsubmit = act(async (e) => {
        e.preventDefault();
        const body = {
          name: val("f-name"),
          hostname: val("f-host"),
          port: Number(val("f-port")) || 22,
          user: val("f-user"),
          auth: val("f-auth"),
          keyId: document.getElementById("f-key")?.value || undefined,
          password: val("f-pw") || undefined,
          mode: val("f-mode"),
          group: val("f-group") || undefined,
          allowlist: val("f-allow").split("\n").map((s) => s.trim()).filter(Boolean),
          resetFingerprint: document.getElementById("f-reset")?.checked,
        };
        if (body.mode === 'free' && h.mode !== 'free' && !await confirmAction('Modul FREE permite execuția comenzilor fără aprobarea operatorului. Continui?', 'Schimbare politică de execuție')) return;
        if (body.resetFingerprint && !await confirmAction('La următoarea conexiune va fi acceptată o nouă identitate a serverului SSH. Verifică separat amprenta serverului înainte de resetare.', 'Resetează identitatea SSH')) return;
        await api(h.id ? "PUT" : "POST", h.id ? "/api/hosts/" + h.id : "/api/hosts", body);
        close();
        await views.hosts();
        void updateBadges();
      });

      decorate(dlg); dlg.showModal();
      setTimeout(() => document.getElementById("f-name")?.focus(), 50);
    };
    document.getElementById("new").onclick = () => form();
    const updateChecklistUI = (id, inList) => {
      checkHostIds[inList ? "add" : "delete"](id);
      const tag = document.getElementById(`cl-tag-${id}`);
      if (tag) tag.innerHTML = inList ? '<span class="tag ok">✓ Checklist</span>' : "";
      const btn = document.getElementById(`cl-btn-${id}`);
      if (btn) {
        btn.innerHTML = inList
          ? `<button class="b" data-check-del="${id}">Scoate din Checklist</button>`
          : `<button class="b" data-check-add="${id}">+ Checklist</button>`;
        bindCheckButtons(btn);
      }
    };
    const bindCheckButtons = (scope = v) => {
      scope.querySelectorAll("[data-check-add]").forEach((b) => (b.onclick = act(async () => {
        const id = b.dataset.checkAdd;
        await api("POST", "/api/checklist", { hostId: id });
        updateChecklistUI(id, true);
        void updateBadges();
      })));
      scope.querySelectorAll("[data-check-del]").forEach((b) => (b.onclick = act(async () => {
        const id = b.dataset.checkDel;
        await api("DELETE", `/api/checklist/${id}`);
        updateChecklistUI(id, false);
        void updateBadges();
      })));
    };
    bindCheckButtons();
    v.querySelectorAll("[data-edit]").forEach((b) => (b.onclick = () => {
      const target = hosts.find((h) => String(h.id) === String(b.dataset.edit));
      if (target) form(target);
    }));
    v.querySelectorAll("[data-del]").forEach((b) => (b.onclick = act(async () => {
      if (await confirmAction("Ștergi hostul?")) {
        await api("DELETE", "/api/hosts/" + b.dataset.del);
        await views.hosts();
        void updateBadges();
      }
    })));
    v.querySelectorAll("[data-test]").forEach((b) => (b.onclick = act(async () => {
      const o = document.getElementById("out-" + b.dataset.test); o.classList.remove("hidden"); o.textContent = "se conectează...";
      try { o.textContent = (await api("POST", `/api/hosts/${b.dataset.test}/test`, {})).output; } catch (e) { o.textContent = "Eroare: " + e.message; }
    })));
  },

  async checklist() {
    const dot = (h) => `<span data-dot="${esc(h.id)}">${h.online === undefined ? "" : h.online ? '<span class="ok" title="accesibil">●</span>' : `<b class="bad" title="${esc(h.offlineReason || "")}">●</b>`}</span>`;
    const [items, allHosts] = await Promise.all([
      api("GET", "/api/checklist"),
      api("GET", "/api/hosts"),
    ]);
    const v = document.getElementById("view");
    const itemHostIds = new Set(items.map((it) => it.hostId));
    const availableHosts = allHosts.filter((h) => !itemHostIds.has(h.id));

    const statusBadge = (s) => {
      if (s === "ok") return '<span class="tag ok" data-layout="legacy-11">● OK</span>';
      if (s === "warning") return '<span class="tag bad" data-layout="legacy-11">⚠️ Atenție</span>';
      if (s === "error") return '<span class="tag bad" data-layout="legacy-11">❌ Eroare</span>';
      return '<span class="tag mut">○ Never checked</span>';
    };

    v.innerHTML = `
      <div class="row" data-layout="legacy-0">
        <h2>Checklist Securitate (${items.length})</h2>
        <div class="row">
          <button class="b p" id="cl-open-add">+ Adaugă servere</button>
          ${items.length ? '<button class="b" id="cl-run-all">Verifică toate</button>' : ""}
          ${items.length ? '<button class="b d" id="cl-clear-all">Golește checklist</button>' : ""}
        </div>
      </div>

      <div class="card" data-layout="legacy-12">
        <b>Prompt pentru AI (Claude / ChatGPT / Agent):</b>
        <p class="mut" data-layout="legacy-13">
          AI-ul are acces la uneltele <code>get_security_checklist</code> și <code>run_security_check</code>.
          Când îi spui: <i>«fă un security check»</i>, el citește această listă și inspectează fiecare server (loguri auth.log / journalctl, login-uri eșuate, sesiuni active, porturi deschise ss, servicii picate systemd și disc).
        </p>
        <div class="row">
          <input id="ai-prompt-input" readonly value="Fă un security check pe serverele din checklist și verifică logurile de autentificare, tentativele eșuate, porturile deschise și serviciile." data-layout="legacy-4">
          <button class="b p" id="ai-prompt-copy">Copiază prompt</button>
        </div>
      </div>

      <div id="cl-form-container"></div>

      ${items.length ? "" : '<p class="mut">Checklist-ul este gol. Adaugă servere pentru a fi incluse în verificarea de securitate.</p>'}

      ${items.map((it) => {
        const h = it.host || {};
        return `
          <div class="card" id="cl-card-${esc(it.hostId)}">
            <div class="row" data-layout="legacy-14">
              <div data-layout="legacy-4">
                <div class="row" data-layout="legacy-15">
                  ${dot(h)}
                  <b>${esc(h.name)}</b>
                  ${h.online === false ? '<span class="tag bad">offline</span>' : ""}
                  <span class="mut">${esc(h.user)}@${esc(h.hostname)}:${esc(h.port)}</span>
                  <span class="tag">${esc(h.mode)}</span>
                  ${h.group ? `<span class="tag">${esc(h.group)}</span>` : ""}
                  ${statusBadge(it.lastStatus)}
                </div>

                ${it.lastSummary ? `<div data-layout="legacy-16"><b>Rezultat:</b> <span class="${it.lastStatus === 'warning' ? 'bad' : 'ok'}">${esc(it.lastSummary)}</span></div>` : ""}

                <div class="row mut" data-layout="legacy-17">
                  <span>Adăugat: ${esc(it.addedAt.replace("T", " ").slice(0, 16))}</span>
                  <span>Ultima verificare: ${it.lastChecked ? esc(it.lastChecked.replace("T", " ").slice(0, 19)) : "Niciodată"}</span>
                </div>

                ${it.notes ? `<div data-layout="legacy-18"><b>Notițe:</b> <span class="mut">${esc(it.notes)}</span></div>` : ""}
              </div>

              <div class="row" data-layout="legacy-15">
                <button class="b p" data-cl-check="${esc(it.hostId)}">Verifică acum</button>
                <button class="b" data-cl-note="${esc(it.hostId)}">Notițe</button>
                <button class="b d" data-cl-remove="${esc(it.hostId)}">Elimină</button>
              </div>
            </div>

            <pre class="hidden" id="cl-out-${esc(it.hostId)}" data-layout="legacy-19"></pre>
          </div>
        `;
      }).join("")}
    `;

    document.getElementById("ai-prompt-copy").onclick = () => {
      const inp = document.getElementById("ai-prompt-input");
      inp.select();
      navigator.clipboard.writeText(inp.value);
      const b = document.getElementById("ai-prompt-copy");
      b.textContent = "Copiat!";
      setTimeout(() => (b.textContent = "Copiază prompt"), 2000);
    };

    const drawAddForm = () => {
      const container = document.getElementById("cl-form-container");
      if (!availableHosts.length) {
        container.innerHTML = '<div class="card"><p class="mut">Toate hosturile configurate se află deja în checklist.</p><button class="b" id="cl-close-form">Închide</button></div>';
        document.getElementById("cl-close-form").onclick = () => (container.innerHTML = "");
        return;
      }
      container.innerHTML = `
        <div class="card">
          <h3>Adaugă servere în Checklist</h3>
          <p class="mut">Bifează serverele pe care dorești să le incluzi în checklist:</p>
          <div data-layout="legacy-20">
            ${availableHosts.map((h) => `
              <label data-layout="legacy-21">
                <input type="checkbox" class="cl-add-chk" value="${esc(h.id)}" data-layout="legacy-3">
                <b>${esc(h.name)}</b> <span class="mut">(${esc(h.user)}@${esc(h.hostname)})</span> <span class="tag">${esc(h.mode)}</span>
              </label>
            `).join("")}
          </div>
          <label>Notițe / Instrucțiuni specifice pentru AI (opțional):</label>
          <input id="cl-new-notes" placeholder="ex: verifică loguri nginx și auth.log">
          <p data-layout="legacy-22">
            <button class="b p" id="cl-submit-add">Adaugă în Checklist</button>
            <button class="b" id="cl-cancel-add">Anulează</button>
          </p>
        </div>
      `;
      document.getElementById("cl-cancel-add").onclick = () => (container.innerHTML = "");
      document.getElementById("cl-submit-add").onclick = act(async () => {
        const selectedIds = [...container.querySelectorAll(".cl-add-chk:checked")].map((c) => c.value);
        if (!selectedIds.length) throw new Error("Selectează cel puțin un server");
        const notes = val("cl-new-notes");
        await api("POST", "/api/checklist", { hostIds: selectedIds, notes: notes || undefined });
        await views.checklist();
        void updateBadges();
      });
    };

    document.getElementById("cl-open-add").onclick = () => drawAddForm();

    v.querySelectorAll("[data-cl-note]").forEach((b) => (b.onclick = act(async () => {
      const it = items.find((x) => x.hostId === b.dataset.clNote);
      const note = prompt("Notițe pentru acest server (instrucțiuni particulare pentru verificare):", it?.notes || "");
      if (note !== null) {
        await api("PUT", `/api/checklist/${b.dataset.clNote}`, { notes: note });
        await views.checklist();
      }
    })));

    v.querySelectorAll("[data-cl-remove]").forEach((b) => (b.onclick = act(async () => {
      if (await confirmAction("Elimini serverul din checklist?")) {
        const id = b.dataset.clRemove;
        await api("DELETE", `/api/checklist/${id}`);
        const card = document.getElementById("cl-card-" + id);
        if (card) {
          card.classList.add("fade-out");
          setTimeout(async () => {
            await views.checklist();
            void updateBadges();
          }, 200);
        } else {
          await views.checklist();
          void updateBadges();
        }
      }
    })));

    const runCheckOn = async (hostId) => {
      const out = document.getElementById("cl-out-" + hostId);
      if (out) {
        out.classList.remove("hidden");
        out.textContent = "⏳ Se execută verificarea de securitate (sistem, auth, ssh logs, porturi, servicii, resurse)...";
      }
      try {
        const res = await api("POST", `/api/checklist/${hostId}/check`, {});
        if (out) out.textContent = res.report;
        return res;
      } catch (e) {
        if (out) out.textContent = "Eroare: " + e.message;
        throw e;
      }
    };

    v.querySelectorAll("[data-cl-check]").forEach((b) => (b.onclick = act(async () => {
      b.disabled = true;
      try {
        await runCheckOn(b.dataset.clCheck);
      } finally {
        b.disabled = false;
      }
    })));

    const clClear = document.getElementById("cl-clear-all");
    if (clClear) {
      clClear.onclick = act(async () => {
        if (await confirmAction("Sigur vrei să golești întreg checklist-ul?")) {
          await api("POST", "/api/checklist/clear", {});
          await views.checklist();
          void updateBadges();
        }
      });
    }

    const clRunAll = document.getElementById("cl-run-all");
    if (clRunAll) {
      clRunAll.onclick = act(async () => {
        clRunAll.disabled = true;
        clRunAll.textContent = "Se verifică...";
        try {
          for (const it of items) {
            await runCheckOn(it.hostId).catch(() => {});
          }
          void updateBadges();
        } finally {
          clRunAll.disabled = false;
          clRunAll.textContent = "Verifică toate";
        }
      });
    }
  },

  async k8s() {
    const cl = await api("GET", "/api/clusters");
    const v = document.getElementById("view");
    v.innerHTML = `<div class="row" data-layout="legacy-0"><h2>Kubernetes</h2><button class="b p" id="new">+ Cluster nou</button></div>
      <p class="mut">Încarci fișierul kubeconfig (YAML); se stochează criptat în vault. AI-ul folosește uneltele <code>list_clusters</code> și <code>kubectl</code>. Același mod de siguranță ca la hosturi; în <b>read-only</b> nu poate citi Secrets, nu poate face watch/follow și rulează doar get/describe/logs/top/events etc.</p>
      <div id="form"></div>
      ${cl.length ? "" : '<p class="mut">Niciun cluster.</p>'}
      ${cl.map((c) => `<div class="card"><div class="row" data-layout="legacy-0"><div>
        <b>${esc(c.name)}</b> <span class="tag">${esc(c.mode)}</span> ${c.group ? `<span class="tag">${esc(c.group)}</span>` : ""}
        ${c.info ? `<div class="mut" data-layout="legacy-5">context: <b>${esc(c.context || c.info.currentContext || "?")}</b>${c.namespace ? ` · namespace: <b>${esc(c.namespace)}</b>` : ""} · ${esc(c.info.servers.join(", "))}</div>
        ${c.info.execCommands.length ? `<div data-layout="legacy-5" class="bad">rulează local pentru autentificare: ${esc(c.info.execCommands.join(", "))}</div>` : ""}` : '<b class="bad">kubeconfig ilizibil</b>'}</div>
        <div class="row"><button class="b" data-test="${esc(c.id)}">Test</button><button class="b" data-edit="${esc(c.id)}">Editează</button><button class="b d" data-del="${esc(c.id)}">Șterge</button></div></div>
        <pre class="hidden" id="out-${esc(c.id)}"></pre></div>`).join("")}`;
    const form = (c = {}) => {
      const f = document.getElementById("form");
      const ctxs = c.info?.contexts || [];
      f.innerHTML = `<div class="card"><div class="grid">
        <div><label>Nume</label><input id="c-name" value="${esc(c.name)}"></div>
        <div><label>Fișier kubeconfig ${c.id ? "(gol = neschimbat)" : ""}</label><input id="c-file" type="file"></div>
        <div><label>Context (gol = current-context)</label><input id="c-ctx" value="${esc(c.context)}" list="c-ctxs"><datalist id="c-ctxs">${ctxs.map((x) => `<option value="${esc(x)}">`).join("")}</datalist></div>
        <div><label>Namespace implicit (opțional)</label><input id="c-ns" value="${esc(c.namespace)}"></div>
        <div><label>Mod siguranță</label><select id="c-mode"><option value="approval">approval - aprobi fiecare comandă</option><option value="read-only">read-only - doar citire, fără Secrets</option><option value="free">free - AI-ul rulează orice</option></select></div>
        <div><label>Grup</label><input id="c-group" value="${esc(c.group)}"></div></div>
        <p><button class="b p" id="c-save">Salvează</button> <button class="b" id="c-cancel">Anulează</button></p></div>`;
      document.getElementById("c-mode").value = c.mode || "approval";
      const file = document.getElementById("c-file");
      file.onchange = () => { const n = document.getElementById("c-name"); if (!n.value && file.files[0]) n.value = file.files[0].name.replace(/\.(ya?ml|conf|config)$/i, ""); };
      document.getElementById("c-cancel").onclick = () => (f.innerHTML = "");
      document.getElementById("c-save").onclick = act(async () => {
        const body = { name: val("c-name"), context: val("c-ctx"), namespace: val("c-ns"), mode: val("c-mode"), group: val("c-group"), kubeconfig: file.files[0] ? await file.files[0].text() : undefined };
        if (body.mode === "free" && c.mode !== "free" && !await confirmAction("Mod FREE: AI-ul poate rula orice kubectl (inclusiv delete) fără aprobare. Continui?")) return;
        await api(c.id ? "PUT" : "POST", c.id ? "/api/clusters/" + c.id : "/api/clusters", body);
        render();
      });
    };
    document.getElementById("new").onclick = () => form();
    v.querySelectorAll("[data-edit]").forEach((b) => (b.onclick = () => form(cl.find((c) => c.id === b.dataset.edit))));
    v.querySelectorAll("[data-del]").forEach((b) => (b.onclick = act(async () => { if (await confirmAction("Ștergi clusterul?")) { await api("DELETE", "/api/clusters/" + b.dataset.del); render(); } })));
    v.querySelectorAll("[data-test]").forEach((b) => (b.onclick = act(async () => {
      const o = document.getElementById("out-" + b.dataset.test); o.classList.remove("hidden"); o.textContent = "se conectează...";
      try { o.textContent = (await api("POST", `/api/clusters/${b.dataset.test}/test`, {})).output; } catch (e) { o.textContent = "Eroare: " + e.message; }
    })));
  },

  async keys() {
    const keys = await api("GET", "/api/keys");
    document.getElementById("view").innerHTML = `<h2>Chei SSH</h2>
      ${keys.map((k) => `<div class="card"><div class="row" data-layout="legacy-0"><div><b>${esc(k.name)}</b> ${k.hasPassphrase ? '<span class="tag">passphrase</span>' : ""} ${k.valid ? "" : '<b class="bad">INVALID: conține doar cheia publică sau cheie ilizibilă. Șterge-o și adaug-o pe cea privată.</b>'}
        <pre>${esc(k.publicKey)}</pre></div><button class="b d" data-del="${esc(k.id)}">Șterge</button></div></div>`).join("") || '<p class="mut">Nicio cheie.</p>'}
      <div class="card"><h3>Adaugă cheie privată</h3>
        <label>Nume</label><input id="k-name"><label>Cheie privată (OpenSSH / PEM)</label><textarea id="k-priv"></textarea>
        <label>Passphrase (dacă are)</label><input id="k-pass" type="password">
        <p><button class="b p" id="k-add">Adaugă</button> <button class="b" id="k-gen">Generează ed25519 nouă</button></p>
        <p class="mut">Cheia privată nu mai poate fi citită înapoi din interfață; se stochează doar criptat.</p></div>`;
    document.getElementById("k-add").onclick = act(async () => { await api("POST", "/api/keys", { name: val("k-name"), privateKey: val("k-priv"), passphrase: val("k-pass") }); render(); });
    document.getElementById("k-gen").onclick = act(async () => { await api("POST", "/api/keys/generate", { name: val("k-name") || "generated" }); render(); });
    document.querySelectorAll("[data-del]").forEach((b) => (b.onclick = act(async () => { if (await confirmAction("Ștergi cheia?")) { await api("DELETE", "/api/keys/" + b.dataset.del); render(); } })));
  },

  async import() {
    const v = document.getElementById("view");
    const admin = identityUser?.role === 'administrator';
    v.innerHTML = `<h2>Import</h2>
      ${admin ? '<div class="card"><h3>Din ~/.ssh/config de pe server</h3><label>Cale (gol = ~/.ssh/config)</label><input id="i-path"><p><button class="b p" id="i-scan">Scanează</button></p></div>' : ''}
      <div class="card"><h3>Din Termius (CSV)</h3>
        <p class="mut">Termius nu exportă cheile private: după import, atașează cheile din tab-ul Chei și editează hosturile. Dacă ai parole în CSV, ele sunt criptate în vault.</p>
        <input type="file" id="i-file" accept=".csv,text/csv"></div>
      ${admin ? '<div class="card"><h3>Din aplicația Termius de pe server (automat)</h3><div id="tl"><span class="mut">se verifică...</span></div></div>' : ''}
      <div id="preview"></div>`;
    const preview = (hosts) => {
      const p = document.getElementById("preview");
      p.innerHTML = `<div class="card"><h3>Previzualizare (${hosts.length})</h3>
        <table><tr><th></th><th>Nume</th><th>Adresă</th><th>User</th><th>Cheie</th><th>Passphrase cheie</th></tr>
        ${hosts.map((h, i) => `<tr><td><input type="checkbox" data-layout="legacy-3" data-i="${i}" checked></td><td>${esc(h.name)}</td>
          <td>${esc(h.hostname)}:${esc(h.port)}</td><td>${esc(h.user)}</td>
          <td>${h.identityFile ? (h.keyAvailable === false ? `<span class="bad">lipsă</span> ` : "") + esc(h.identityFile) : h.password ? "parolă" : "-"}</td>
          <td>${h.keyAvailable ? `<input type="password" data-pp="${i}" placeholder="dacă e protejată">` : ""}</td></tr>
          ${h.note ? `<tr><td></td><td colspan="5" class="mut">${esc(h.note)}</td></tr>` : ""}`).join("")}</table>
        <p class="mut">Hosturile importate pornesc în modul <b>approval</b>.</p>
        <p><button class="b p" id="i-commit">Importă selecția</button></p></div>`;
      document.getElementById("i-commit").onclick = act(async () => {
        const sel = [...p.querySelectorAll("[data-i]")].filter((c) => c.checked).map((c) => {
          const i = +c.dataset.i; return { ...hosts[i], keyPassphrase: p.querySelector(`[data-pp="${i}"]`)?.value || undefined };
        });
        const r = await api("POST", "/api/import/commit", { hosts: sel });
        notify(`Importate: ${r.added}` + (r.skipped.length ? `\nSărite (nume existent): ${r.skipped.join(", ")}` : ""));
        tab = "hosts"; render();
      });
    };
    if (admin) document.getElementById("i-scan").onclick = act(async () => preview(await api("POST", "/api/import/sshconfig", { path: val("i-path") || undefined })));
    document.getElementById("i-file").onchange = act(async (e) => preview(await api("POST", "/api/import/termius", { text: await e.target.files[0].text() })));
    // ---- Termius desktop (local, automat) ----
    const tl = document.getElementById("tl");
    const tlDraw = async () => {
      const st = await api("GET", "/api/import/termius-local/status");
      if (!st.supported) return (tl.innerHTML = '<p class="mut">Disponibil doar pe Windows.</p>');
      if (!st.termiusFound) return (tl.innerHTML = '<p class="mut">Aplicația Termius desktop nu a fost găsită pe acest PC (datele ei sunt în %APPDATA%/Termius).</p>');
      tl.innerHTML = st.helperReady
        ? '<button class="b p" id="tl-scan">Scanează Termius</button> <span class="mut">Citește local, offline, hosturile, parolele și cheile. Nu trimite nimic nicăieri.</span>'
        : '<p class="mut">Componenta pentru import nu este instalată. Instalările se gestionează din administrarea instanței.</p><a class="button" href="/identity/admin">Administrare instanță →</a>';
      const scan = document.getElementById("tl-scan");
      if (scan) scan.onclick = act(async () => { scan.disabled = true; scan.textContent = "se citește..."; try { tlPreview(await api("POST", "/api/import/termius-local/scan", {})); } finally { scan.disabled = false; scan.textContent = "Scanează Termius"; } });
    };
    const tlPreview = (r) => {
      const p = document.getElementById("preview");
      const rows = r.hosts;
      const authLabel = (h) => (h.auth === "key" ? "cheie: " + esc(h.keyLabel || "") : h.auth === "password" ? "parolă" : '<span class="bad">fără credențiale</span>');
      p.innerHTML = `<div class="card"><h3>Termius: ${rows.length} hosturi, ${r.stats.keys} chei, ${r.stats.groups} grupuri</h3>
        <div class="row"><input id="tl-filter" placeholder="Caută..." data-layout="legacy-23">
          <button class="b" id="tl-all">Selectează tot</button><button class="b" id="tl-none">Nimic</button>
          <label data-layout="legacy-2">Mod siguranță: <select id="tl-mode" data-layout="legacy-3"><option value="approval">approval</option><option value="read-only">read-only</option><option value="free">free</option></select></label></div>
        <table id="tl-table"><tr><th></th><th>Grup</th><th>Nume</th><th>Adresă</th><th>User</th><th>Autentificare</th></tr>
        ${rows.map((h) => `<tr data-q="${esc((h.group + " " + h.name + " " + h.address + " " + h.user).toLowerCase())}"><td><input type="checkbox" data-layout="legacy-3" data-id="${esc(h.id)}" ${h.exists ? "" : "checked"}></td>
          <td>${esc(h.group || "")}</td><td>${esc(h.name)}${h.exists ? ' <span class="tag">există deja</span>' : ""}</td><td>${esc(h.address)}:${esc(h.port)}</td><td>${esc(h.user)}</td><td>${authLabel(h)}</td></tr>`).join("")}</table>
        <p class="mut">Cheile folosite de hosturile selectate se copiază criptat în vault. Hosturile pornesc în modul ales mai sus (recomandat: approval).</p>
        <p><button class="b p" id="tl-commit">Importă selecția</button></p></div>`;
      const visible = () => [...p.querySelectorAll("#tl-table tr[data-q]")].filter((tr) => !tr.hidden);
      document.getElementById("tl-filter").oninput = (e) => { const q = e.target.value.toLowerCase(); p.querySelectorAll("#tl-table tr[data-q]").forEach((tr) => (tr.hidden = !tr.dataset.q.includes(q))); };
      document.getElementById("tl-all").onclick = () => visible().forEach((tr) => (tr.querySelector("input").checked = true));
      document.getElementById("tl-none").onclick = () => visible().forEach((tr) => (tr.querySelector("input").checked = false));
      document.getElementById("tl-commit").onclick = act(async () => {
        const ids = [...p.querySelectorAll("[data-id]")].filter((c) => c.checked).map((c) => +c.dataset.id);
        if (!ids.length) throw new Error("nu ai selectat nimic");
        const out = await api("POST", "/api/import/termius-local/commit", { session: r.session, ids, mode: val("tl-mode") });
        notify(`Importate: ${out.added} hosturi, ${out.keysAdded} chei.` + (out.skipped.length ? `\nSărite (${out.skipped.length}): ${out.skipped.slice(0, 15).join(", ")}` : ""));
        tab = "hosts"; render();
      });
    };
    if (admin) await tlDraw();
  },

  async clients() {
    const data = await api("GET", "/api/clients");
    const view = document.getElementById("view");
    view.innerHTML = `<h2>Clienti AI - OAuth</h2><p>Fiecare utilizator conecteaza contul propriu prin OAuth si MFA.</p><select id="client-id">${data.clients.map(c => `<option value="${esc(c.id)}">${esc(c.name)}</option>`).join('')}</select><div id="client-setup"></div>`;
    const show = () => {
      const setup = data.clients.find(c => c.id === val('client-id'));
      document.getElementById('client-setup').innerHTML = `<p>${esc(setup.instructions)}</p>${setup.blocks.map(b => `<b>${esc(b.title)}</b><pre>${esc(b.content)}</pre>`).join('')}`;
    };
    document.getElementById('client-id').onchange = show; show();
  },

  async approvals() {
    const a = await api("GET", "/api/approvals");
    lastApprovals = JSON.stringify(a.map((x) => x.id));
    document.getElementById("view").innerHTML = `<h2>Aprobări în așteptare</h2>${a.length ? "" : '<p class="mut">Nimic de aprobat.</p>'}
      ${a.map((x) => `<div class="card"><div><b>${esc(x.host)}</b> <span class="mut">cerut de ${esc(x.userId || x.client)}</span><p class="form-note">Client: ${esc(x.clientId || x.client)} · ${esc(new Date(x.created).toLocaleString('ro-RO'))}</p></div><pre>${esc(x.command)}</pre>
        <button class="b p" data-ok="${esc(x.id)}">Aprobă</button> <button class="b d" data-no="${esc(x.id)}">Respinge</button></div>`).join("")}`;
    const decide = (id, d) => act(async () => {
      const request = a.find(x => x.id === id);
      if (d === 'approve' && !await confirmAction(`Destinație: ${request.host}\nSolicitant: ${request.userId || request.client}\n\n${request.command}`, 'Permiți execuția acestei comenzi?')) return;
      await api("POST", `/api/approvals/${encodeURIComponent(id)}/${d}`, {}); await views.approvals();
    });
    document.querySelectorAll("[data-ok]").forEach((b) => (b.onclick = decide(b.dataset.ok, "approve")));
    document.querySelectorAll("[data-no]").forEach((b) => (b.onclick = decide(b.dataset.no, "deny")));
  },

  async audit() {
    const rows = await api("GET", "/api/audit");
    document.getElementById("view").innerHTML = `<h2>Audit</h2><div class="row"><button class="b" id="rf">Reîncarcă</button></div>
      <table><tr><th>Timp</th><th>Client</th><th>Host</th><th>Comandă</th><th>Rezultat</th></tr>
      ${rows.map((r) => `<tr><td>${esc(r.ts.replace("T", " ").slice(0, 19))}</td><td>${esc(r.client)}</td><td>${esc(r.host)} <span class="tag">${esc(r.mode)}</span></td>
        <td><code>${esc(r.command)}</code></td><td class="${r.outcome === "ok" ? "ok" : "bad"}">${esc(r.outcome)}${r.exitCode != null ? " (" + r.exitCode + ")" : ""}</td></tr>`).join("")}</table>`;
    document.getElementById("rf").onclick = () => views.audit();
  },

  async settings() {
    const s = await api("GET", "/api/settings");
    const storage = await api("GET", "/api/storage");
    document.getElementById("view").innerHTML = `<h2>Setări</h2><div class="card"><div class="grid">
      <div><label for="s-lock">Blocare după inactivitate (minute)</label><input id="s-lock" type="number" min="0" max="1440" step="1" value="${esc(s.autoLockMinutes)}"><p class="mut">Doar pentru acest vault. Implicit: 10 minute. 0 dezactivează blocarea. Utilizarea interfeței și apelurile MCP resetează timpul; verificările automate de stare nu îl resetează.</p></div>
      <div><label>Limită output (bytes)</label><input id="s-out" type="number" value="${esc(s.maxOutputBytes)}"></div>
      <div><label>Timeout aprobare (secunde)</label><input id="s-ap" type="number" value="${esc(s.approvalTimeoutSec)}"></div></div>
      <p><button class="b p" id="s-save">Salvează</button></p></div>
      <div class="card"><h3>Date locale</h3><p>Folderul bazei de date: <code>${esc(storage.dataDir)}</code></p>
      <p class="mut">Vault-ul criptat, istoricul și componentele locale se păstrează aici. Folosește același folder când reinstalezi aplicația. După repornire, deblochează vault-ul cu parola master.</p></div>
      <div class="card"><h3>Schimbă parola master</h3><label>Parola veche</label><input id="p-old" type="password">
      <label>Parola nouă (min. 12)</label><input id="p-new" type="password"><p><button class="b" id="p-save">Schimbă</button></p></div>`;
    document.getElementById("s-save").onclick = act(async () => { await api("PUT", "/api/settings", { autoLockMinutes: val("s-lock"), maxOutputBytes: val("s-out"), approvalTimeoutSec: val("s-ap") }); notify("Salvat"); });
    document.getElementById("p-save").onclick = act(async () => { await api("POST", "/api/password", { old: val("p-old"), new: val("p-new") }); document.getElementById("p-old").value = ""; document.getElementById("p-new").value = ""; notify("Parola a fost schimbată"); });
  },
};

render();
