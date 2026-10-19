"use strict";
const $app = document.getElementById("app");
let csrf = null, tab = "hosts", poll = null;

// ---- helpers ----
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
async function api(method, url, body) {
  const r = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json", ...(csrf ? { "X-CSRF-Token": csrf } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (r.status === 401) { csrf = null; return render(); }
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}
const act = (fn) => async (...a) => { try { await fn(...a); } catch (e) { alert(e.message); } };
const val = (id) => document.getElementById(id).value;
const el = (html) => { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstChild; };

// ---- shell ----
async function render() {
  clearInterval(poll);
  const st = await fetch("/api/status").then((r) => r.json());
  if (st.unlocked) csrf = st.csrf;
  if (!st.unlocked) return renderLogin(st.exists);
  $app.innerHTML = `
    <header><h1>MCP SSH</h1>
      <nav>${["hosts", "keys", "import", "chatgpt", "tokens", "approvals", "audit", "settings"]
        .map((t) => `<button data-t="${t}" class="${t === tab ? "on" : ""}">${{ hosts: "Hosturi", keys: "Chei", import: "Import", chatgpt: "ChatGPT", tokens: "Tokenuri MCP", approvals: "Aprobări", audit: "Audit", settings: "Setări" }[t]}<span id="badge-${t}"></span></button>`).join("")}
      </nav><button class="b" id="lock">Blochează vault</button></header>
    <main id="view"></main>`;
  $app.querySelectorAll("nav button").forEach((b) => (b.onclick = () => { tab = b.dataset.t; render(); }));
  document.getElementById("lock").onclick = act(async () => { await api("POST", "/api/lock", {}); csrf = null; render(); });
  await views[tab]();
  poll = setInterval(act(async () => {
    const a = await api("GET", "/api/approvals");
    const b = document.getElementById("badge-approvals");
    if (b) b.textContent = a.length ? ` (${a.length})` : "";
    if (tab === "approvals" && JSON.stringify(a.map((x) => x.id)) !== window.__ap) { window.__ap = JSON.stringify(a.map((x) => x.id)); views.approvals(); }
  }), 2000);
}

function renderLogin(exists) {
  const ac = exists ? "current-password" : "new-password";
  $app.innerHTML = `<form id="login" class="card" autocomplete="on"><h2>${exists ? "Deblochează vault-ul" : "Creează vault-ul"}</h2>
    <p class="mut">${exists ? "Introdu parola master." : "Alege o parolă master (min. 12 caractere). Nu poate fi recuperată - fără ea datele sunt pierdute."}</p>
    <input type="text" name="username" value="mcp-ssh-vault" autocomplete="username" hidden>
    <label for="pw">Parolă master</label><input type="password" id="pw" name="password" autocomplete="${ac}">
    ${exists ? "" : `<label for="pw2">Repetă parola</label><input type="password" id="pw2" name="password2" autocomplete="new-password">`}
    <p><button type="submit" class="b p" id="go">${exists ? "Deblochează" : "Creează"}</button> <span id="err" class="bad"></span></p></form>`;
  document.getElementById("login").onsubmit = async (e) => {
    e.preventDefault();
    try {
      if (!exists && val("pw") !== val("pw2")) throw new Error("parolele nu coincid");
      const r = await api("POST", exists ? "/api/unlock" : "/api/setup", { password: val("pw") });
      csrf = r.csrf; render();
    } catch (err) { document.getElementById("err").textContent = err.message; }
  };
  setTimeout(() => document.getElementById("pw").focus(), 50);
}

// ---- views ----
const views = {
  async hosts() {
    const [hosts, keys] = await Promise.all([api("GET", "/api/hosts"), api("GET", "/api/keys")]);
    const v = document.getElementById("view");
    v.innerHTML = `<div class="row" style="justify-content:space-between"><h2>Hosturi</h2><button class="b p" id="new">+ Host nou</button></div>
      <div id="form"></div>
      ${hosts.length ? "" : '<p class="mut">Niciun host. Adaugă unul sau folosește Import.</p>'}
      ${hosts.map((h) => `<div class="card"><div class="row" style="justify-content:space-between">
        <div><b>${esc(h.name)}</b> <span class="mut">${esc(h.user)}@${esc(h.hostname)}:${h.port}</span>
        <span class="tag">${esc(h.mode)}</span> <span class="tag">${h.auth === "key" ? "cheie" : "parolă"}</span>
        ${h.group ? `<span class="tag">${esc(h.group)}</span>` : ""}
        ${h.auth === "key" ? `<div style="font-size:12px">cheie: <b>${esc(h.keyName || "?")}</b> ${h.keyValid ? '<span class="ok">valid</span>' : '<b class="bad">INVALID (nu conține cheia privată)</b>'} <span class="mut">${esc(h.keyFingerprint || "")}</span></div>` : ""}
        <div class="mut" style="font-size:12px">${h.fingerprint ? "host key: " + esc(h.fingerprint) : "host key nefixat (se fixează la prima conectare)"}</div></div>
        <div class="row"><button class="b" data-test="${h.id}">Test</button><button class="b" data-edit="${h.id}">Editează</button><button class="b d" data-del="${h.id}">Șterge</button></div></div>
        <pre class="hidden" id="out-${h.id}"></pre></div>`).join("")}`;
    const form = (h = {}) => {
      const f = document.getElementById("form");
      f.innerHTML = `<div class="card"><div class="grid">
        <div><label>Nume</label><input id="f-name" value="${esc(h.name)}"></div>
        <div><label>Hostname / IP</label><input id="f-host" value="${esc(h.hostname)}"></div>
        <div><label>Port</label><input id="f-port" type="number" value="${h.port || 22}"></div>
        <div><label>Utilizator</label><input id="f-user" value="${esc(h.user)}"></div>
        <div><label>Autentificare</label><select id="f-auth"><option value="key">Cheie SSH</option><option value="password">Parolă</option></select></div>
        <div id="w-key"><label>Cheie</label><select id="f-key">${keys.map((k) => `<option value="${k.id}" ${k.id === h.keyId ? "selected" : ""}>${esc(k.name)}</option>`).join("")}</select></div>
        <div id="w-pw"><label>Parolă ${h.hasPassword ? "(lasă gol = neschimbată)" : ""}</label><input id="f-pw" type="password" autocomplete="new-password"></div>
        <div><label>Mod siguranță</label><select id="f-mode">
          <option value="approval">approval - aprobi fiecare comandă</option>
          <option value="read-only">read-only - doar comenzi din allowlist</option>
          <option value="free">free - AI-ul rulează orice</option></select></div>
        <div><label>Grup</label><input id="f-group" value="${esc(h.group)}"></div></div>
        <label>Allowlist suplimentar read-only (un prefix de comandă pe linie, ex: <code>systemctl status</code>)</label>
        <textarea id="f-allow">${esc((h.allowlist || []).join("\n"))}</textarea>
        ${h.id ? `<label><input type="checkbox" id="f-reset" style="width:auto"> Resetează host key fixat (după reinstalare server)</label>` : ""}
        <p><button class="b p" id="save">Salvează</button> <button class="b" id="cancel">Anulează</button></p></div>`;
      document.getElementById("f-auth").value = h.auth || "key";
      document.getElementById("f-mode").value = h.mode || "approval";
      const sync = () => { const k = val("f-auth") === "key"; document.getElementById("w-key").classList.toggle("hidden", !k); document.getElementById("w-pw").classList.toggle("hidden", k); };
      document.getElementById("f-auth").onchange = sync; sync();
      document.getElementById("cancel").onclick = () => (f.innerHTML = "");
      document.getElementById("save").onclick = act(async () => {
        const body = { name: val("f-name"), hostname: val("f-host"), port: val("f-port"), user: val("f-user"), auth: val("f-auth"),
          keyId: document.getElementById("f-key")?.value, password: val("f-pw"), mode: val("f-mode"), group: val("f-group"),
          allowlist: val("f-allow").split("\n").map((s) => s.trim()).filter(Boolean), resetFingerprint: document.getElementById("f-reset")?.checked };
        await api(h.id ? "PUT" : "POST", h.id ? "/api/hosts/" + h.id : "/api/hosts", body);
        render();
      });
    };
    document.getElementById("new").onclick = () => form();
    v.querySelectorAll("[data-edit]").forEach((b) => (b.onclick = () => form(hosts.find((h) => h.id === b.dataset.edit))));
    v.querySelectorAll("[data-del]").forEach((b) => (b.onclick = act(async () => { if (confirm("Ștergi hostul?")) { await api("DELETE", "/api/hosts/" + b.dataset.del); render(); } })));
    v.querySelectorAll("[data-test]").forEach((b) => (b.onclick = async () => {
      const o = document.getElementById("out-" + b.dataset.test); o.classList.remove("hidden"); o.textContent = "se conectează...";
      try { o.textContent = (await api("POST", `/api/hosts/${b.dataset.test}/test`, {})).output; } catch (e) { o.textContent = "Eroare: " + e.message; }
    }));
  },

  async keys() {
    const keys = await api("GET", "/api/keys");
    document.getElementById("view").innerHTML = `<h2>Chei SSH</h2>
      ${keys.map((k) => `<div class="card"><div class="row" style="justify-content:space-between"><div><b>${esc(k.name)}</b> ${k.hasPassphrase ? '<span class="tag">passphrase</span>' : ""} ${k.valid ? "" : '<b class="bad">INVALID: conține doar cheia publică sau cheie ilizibilă. Șterge-o și adaug-o pe cea privată.</b>'}
        <pre>${esc(k.publicKey)}</pre></div><button class="b d" data-del="${k.id}">Șterge</button></div></div>`).join("") || '<p class="mut">Nicio cheie.</p>'}
      <div class="card"><h3>Adaugă cheie privată</h3>
        <label>Nume</label><input id="k-name"><label>Cheie privată (OpenSSH / PEM)</label><textarea id="k-priv"></textarea>
        <label>Passphrase (dacă are)</label><input id="k-pass" type="password">
        <p><button class="b p" id="k-add">Adaugă</button> <button class="b" id="k-gen">Generează ed25519 nouă</button></p>
        <p class="mut">Cheia privată nu mai poate fi citită înapoi din interfață; se stochează doar criptat.</p></div>`;
    document.getElementById("k-add").onclick = act(async () => { await api("POST", "/api/keys", { name: val("k-name"), privateKey: val("k-priv"), passphrase: val("k-pass") }); render(); });
    document.getElementById("k-gen").onclick = act(async () => { await api("POST", "/api/keys/generate", { name: val("k-name") || "generated" }); render(); });
    document.querySelectorAll("[data-del]").forEach((b) => (b.onclick = act(async () => { if (confirm("Ștergi cheia?")) { await api("DELETE", "/api/keys/" + b.dataset.del); render(); } })));
  },

  async import() {
    const v = document.getElementById("view");
    v.innerHTML = `<h2>Import</h2>
      <div class="card"><h3>Din ~/.ssh/config</h3><label>Cale (gol = ~/.ssh/config)</label><input id="i-path">
        <p><button class="b p" id="i-scan">Scanează</button></p></div>
      <div class="card"><h3>Din Termius (CSV)</h3>
        <p class="mut">Termius nu exportă cheile private: după import, atașează cheile din tab-ul Chei și editează hosturile. Dacă ai parole în CSV, ele sunt criptate în vault.</p>
        <input type="file" id="i-file" accept=".csv,text/csv"></div>
      <div id="preview"></div>`;
    const preview = (hosts) => {
      const p = document.getElementById("preview");
      p.innerHTML = `<div class="card"><h3>Previzualizare (${hosts.length})</h3>
        <table><tr><th></th><th>Nume</th><th>Adresă</th><th>User</th><th>Cheie</th><th>Passphrase cheie</th></tr>
        ${hosts.map((h, i) => `<tr><td><input type="checkbox" style="width:auto" data-i="${i}" checked></td><td>${esc(h.name)}</td>
          <td>${esc(h.hostname)}:${h.port}</td><td>${esc(h.user)}</td>
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
        alert(`Importate: ${r.added}` + (r.skipped.length ? `\nSărite (nume existent): ${r.skipped.join(", ")}` : ""));
        tab = "hosts"; render();
      });
    };
    document.getElementById("i-scan").onclick = act(async () => preview(await api("POST", "/api/import/sshconfig", { path: val("i-path") || undefined })));
    document.getElementById("i-file").onchange = act(async (e) => preview(await api("POST", "/api/import/termius", { text: await e.target.files[0].text() })));
  },

  async chatgpt() {
    const v = document.getElementById("view");
    const draw = async () => {
      const s = await api("GET", "/api/tunnel");
      const state = s.running ? (s.ready ? '<span class="ok">conectat</span>' : '<span class="bad">pornit, nepregătit</span>') : "oprit";
      v.innerHTML = `<h2>ChatGPT (OpenAI Secure MCP Tunnel)</h2>
        <p class="mut">Folosește tunelul oficial OpenAI: nimic nu e expus pe internet. ChatGPT vorbește cu OpenAI, iar <code>tunnel-client</code> (rulat de acest server) face apelurile spre portul MCP local, adăugând singur tokenul. Tokenul nu pleacă de pe acest PC.</p>
        <div class="card"><b>1. Client tunel:</b> ${s.installed ? `instalat (${esc(s.version)})` : "neinstalat"}
          <button class="b" id="tn-install" ${s.installing ? "disabled" : ""}>${s.installed ? "Actualizează" : "Descarcă și instalează"}</button>
          <div class="mut" style="font-size:12px">Descarcă release-ul oficial openai/tunnel-client de pe GitHub și verifică SHA-256.</div></div>
        <div class="card"><b>2. Date din platform.openai.com</b>
          <p class="mut" style="font-size:12px">Platform &gt; Tunnels: creează tunelul (Tunnels Read+Manage), asociază-l cu workspace-ul ChatGPT și copiază <i>tunnel id</i>. Creează o cheie API runtime cu permisiuni Tunnels Read+Use. Se stochează criptat în vault.</p>
          <div class="grid"><div><label>Tunnel ID</label><input id="tn-id" placeholder="tunnel_0123..." value="${esc(s.tunnelId)}"></div>
          <div><label>Cheie API runtime ${s.hasApiKey ? "(salvată; gol = neschimbată)" : ""}</label><input id="tn-key" type="password" autocomplete="new-password"></div></div>
          <label><input type="checkbox" id="tn-auto" style="width:auto" ${s.autoStart ? "checked" : ""}> Pornește automat tunelul după deblocarea vault-ului</label>
          <p><button class="b p" id="tn-save">Salvează</button></p></div>
        <div class="card"><b>3. Stare:</b> ${state} ${s.lastError ? `<span class="bad">${esc(s.lastError)}</span>` : ""}
          <p><button class="b p" id="tn-start" ${s.running ? "disabled" : ""}>Pornește</button> <button class="b" id="tn-stop" ${s.running ? "" : "disabled"}>Oprește</button>
          <button class="b" id="tn-refresh">Reîncarcă</button></p>
          <pre style="max-height:220px">${esc(s.logs.join("\n")) || "(fără loguri)"}</pre></div>
        <div class="card"><b>4. În ChatGPT</b>
          <ol><li>chatgpt.com/plugins &rarr; <b>+</b> &rarr; <i>Add custom MCP server</i></li>
          <li>Connection: <b>Tunnel</b> &rarr; alege tunelul (sau lipește tunnel id)</li>
          <li>Authentication: <b>No authentication</b> (autentificarea o face tunnel-client către serverul local)</li>
          <li>Confirmă avertismentul și <i>Create</i>; ChatGPT va descoperi uneltele <code>list_hosts</code>, <code>run_command</code>, <code>read_file</code>, <code>get_host_info</code>.</li></ol>
          <p class="mut" style="font-size:12px">Notă: ChatGPT nu acceptă chei API/Bearer personalizate, de aceea tokenul e injectat local. Revocarea tokenului <code>chatgpt-tunnel</code> din tab-ul Tokenuri taie accesul instant. Modurile de siguranță per host (approval/read-only) se aplică și aici.</p></div>`;
      const run = (id, fn) => (document.getElementById(id).onclick = act(async () => { await fn(); await draw(); }));
      run("tn-install", async () => { const b = document.getElementById("tn-install"); b.textContent = "se descarcă..."; b.disabled = true; await api("POST", "/api/tunnel/install", {}); });
      run("tn-save", () => api("PUT", "/api/tunnel", { tunnelId: val("tn-id"), apiKey: val("tn-key") || undefined, autoStart: document.getElementById("tn-auto").checked }));
      run("tn-start", () => api("POST", "/api/tunnel/start", {}));
      run("tn-stop", () => api("POST", "/api/tunnel/stop", {}));
      run("tn-refresh", async () => {});
    };
    await draw();
  },

  async tokens() {
    const t = await api("GET", "/api/tokens");
    const origin = location.origin.replace(/:\d+$/, ":7778");
    document.getElementById("view").innerHTML = `<h2>Tokenuri MCP</h2>
      <p class="mut">Endpoint MCP local: <code>${esc(origin)}/mcp</code> (Streamable HTTP, <code>Authorization: Bearer &lt;token&gt;</code>). Pentru ChatGPT/Claude web expune DOAR portul 7778 printr-un tunel (ex. <code>cloudflared tunnel --url http://127.0.0.1:7778</code>), niciodată 7777.</p>
      <div id="newtok"></div>
      ${t.map((x) => `<div class="card row" style="justify-content:space-between"><div><b>${esc(x.name)}</b> <span class="mut">creat ${esc(x.created)}</span></div><button class="b d" data-del="${x.id}">Revocă</button></div>`).join("")}
      <div class="card"><label>Nume client (ex. claude-desktop)</label><input id="t-name"><p><button class="b p" id="t-add">Generează token</button></p></div>`;
    document.getElementById("t-add").onclick = act(async () => {
      const r = await api("POST", "/api/tokens", { name: val("t-name") || "client" });
      document.getElementById("newtok").innerHTML = `<div class="card"><b>Token nou (se afișează o singură dată):</b><pre>${esc(r.token)}</pre>
        <p class="mut">Claude Code: <code>claude mcp add --transport http ssh ${esc(origin)}/mcp --header "Authorization: Bearer ${esc(r.token)}"</code></p></div>`;
      document.getElementById("t-name").value = "";
    });
    document.querySelectorAll("[data-del]").forEach((b) => (b.onclick = act(async () => { if (confirm("Revoci tokenul?")) { await api("DELETE", "/api/tokens/" + b.dataset.del); render(); } })));
  },

  async approvals() {
    const a = await api("GET", "/api/approvals");
    window.__ap = JSON.stringify(a.map((x) => x.id));
    document.getElementById("view").innerHTML = `<h2>Aprobări în așteptare</h2>${a.length ? "" : '<p class="mut">Nimic de aprobat.</p>'}
      ${a.map((x) => `<div class="card"><div><b>${esc(x.host)}</b> <span class="mut">cerut de ${esc(x.client)}</span></div><pre>${esc(x.command)}</pre>
        <button class="b p" data-ok="${x.id}">Aprobă</button> <button class="b d" data-no="${x.id}">Respinge</button></div>`).join("")}`;
    const decide = (id, d) => act(async () => { await api("POST", `/api/approvals/${id}/${d}`, {}); views.approvals(); });
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
    document.getElementById("view").innerHTML = `<h2>Setări</h2><div class="card"><div class="grid">
      <div><label>Auto-lock după (minute, 0 = niciodată)</label><input id="s-lock" type="number" value="${s.autoLockMinutes}"></div>
      <div><label>Limită output (bytes)</label><input id="s-out" type="number" value="${s.maxOutputBytes}"></div>
      <div><label>Timeout aprobare (secunde)</label><input id="s-ap" type="number" value="${s.approvalTimeoutSec}"></div></div>
      <p><button class="b p" id="s-save">Salvează</button></p></div>
      <div class="card"><h3>Schimbă parola master</h3><label>Parola veche</label><input id="p-old" type="password">
      <label>Parola nouă (min. 12)</label><input id="p-new" type="password"><p><button class="b" id="p-save">Schimbă</button></p></div>`;
    document.getElementById("s-save").onclick = act(async () => { await api("PUT", "/api/settings", { autoLockMinutes: val("s-lock"), maxOutputBytes: val("s-out"), approvalTimeoutSec: val("s-ap") }); alert("Salvat"); });
    document.getElementById("p-save").onclick = act(async () => { await api("POST", "/api/password", { old: val("p-old"), new: val("p-new") }); alert("Parola a fost schimbată"); });
  },
};

render();
