"use strict";
const $app = document.getElementById("app");
let csrf = null, tab = "hosts", poll = null, renderSeq = 0;
const selected = new Set(); // host ids ticked for bulk actions

// ---- helpers ----
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
async function api(method, url, body) {
  const r = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json", ...(csrf ? { "X-CSRF-Token": csrf } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (r.status === 401) { if (csrf) { csrf = null; render(); } throw new Error("locked"); }
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}
const act = (fn) => async (...a) => { try { await fn(...a); } catch (e) { if (e.message !== "locked") alert(e.message); } };
const val = (id) => document.getElementById(id).value;
const el = (html) => { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstChild; };

// ---- shell ----
async function updateBadges() {
  const [a, cl] = await Promise.all([
    api("GET", "/api/approvals").catch(() => []),
    api("GET", "/api/checklist").catch(() => []),
  ]);
  const bAp = document.getElementById("badge-approvals");
  if (bAp) bAp.textContent = a.length ? ` (${a.length})` : "";
  const bCl = document.getElementById("badge-checklist");
  if (bCl) bCl.textContent = cl.length ? ` (${cl.length})` : "";
  return { approvals: a, checklist: cl };
}

async function switchTab(newTab) {
  tab = newTab;
  document.querySelectorAll("nav button").forEach((b) => b.classList.toggle("on", b.dataset.t === tab));
  await views[tab]();
}

async function render() {
  clearInterval(poll);
  const seq = ++renderSeq;
  const st = await fetch("/api/status").then((r) => r.json());
  if (seq !== renderSeq) return; // a newer render took over
  if (st.unlocked) csrf = st.csrf;
  if (!st.unlocked) return renderLogin(st.exists);
  if (!document.getElementById("view")) {
    $app.innerHTML = `
      <header><h1>MCP SSH</h1>
        <nav>${["hosts", "checklist", "k8s", "keys", "import", "chatgpt", "tokens", "approvals", "audit", "settings"]
          .map((t) => `<button data-t="${t}" class="${t === tab ? "on" : ""}">${{ hosts: "Hosturi", checklist: "Checklist", k8s: "Kubernetes", keys: "Chei", import: "Import", chatgpt: "ChatGPT", tokens: "Tokenuri MCP", approvals: "Aprobări", audit: "Audit", settings: "Setări" }[t]}<span id="badge-${t}"></span></button>`).join("")}
        </nav><button class="b" id="lock">Blochează vault</button></header>
      <main id="view"></main>`;
    $app.querySelectorAll("nav button").forEach((b) => (b.onclick = () => switchTab(b.dataset.t)));
    document.getElementById("lock").onclick = act(async () => { await api("POST", "/api/lock", {}); csrf = null; render(); });
  } else {
    document.querySelectorAll("nav button").forEach((b) => b.classList.toggle("on", b.dataset.t === tab));
  }
  void updateBadges();
  await views[tab]();
  if (seq !== renderSeq) return;
  clearInterval(poll);
  poll = setInterval(act(async () => {
    const { approvals: a } = await updateBadges();
    if (tab === "approvals" && JSON.stringify(a.map((x) => x.id)) !== window.__ap) {
      window.__ap = JSON.stringify(a.map((x) => x.id));
      views.approvals();
    }
  }), 2000);
}

function renderLogin(exists) {
  if (document.getElementById("login")) return; // already showing: don't wipe what is being typed
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
    const dot = (h) => `<span data-dot="${h.id}">${h.online === undefined ? "" : h.online ? '<span class="ok" title="accesibil">●</span>' : `<b class="bad" title="${esc(h.offlineReason || "")}">●</b>`}</span>`;
    const [hosts, keys, checklist] = await Promise.all([api("GET", "/api/hosts"), api("GET", "/api/keys"), api("GET", "/api/checklist")]);
    const checkHostIds = new Set(checklist.map((c) => c.hostId));
    const v = document.getElementById("view");
    v.innerHTML = `<div class="row" style="justify-content:space-between"><h2>Hosturi</h2><div class="row"><button class="b" id="recheck">Verifică disponibilitatea</button><button class="b p" id="new">+ Host nou</button></div></div>
      <dialog id="host-dialog"></dialog>
      ${hosts.length ? `<div class="card row" id="bulk" style="gap:10px;flex-wrap:wrap">
        <label style="margin:0"><input type="checkbox" id="sel-all" style="width:auto"> toate</label>
        <select id="sel-group" style="width:auto"><option value="">selectează grup…</option>${[...new Set(hosts.map((h) => h.group).filter(Boolean))].map((g) => `<option>${esc(g)}</option>`).join("")}</select>
        <span class="mut" id="sel-n"></span>
        <span style="flex:1"></span>
        <button class="b" id="bulk-checklist">+ Adaugă în Checklist</button>
        <label style="margin:0">Mod: <select id="bulk-mode" style="width:auto"><option value="approval">approval</option><option value="read-only">read-only</option><option value="free">free</option></select></label>
        <button class="b p" id="bulk-go">Aplică mod</button></div>` : ""}
      ${hosts.length ? "" : '<p class="mut">Niciun host. Adaugă unul sau folosește Import.</p>'}
      ${hosts.map((h) => `<div class="card" id="host-card-${h.id}"><div class="row" style="justify-content:space-between">
        <div><input type="checkbox" class="sel" data-id="${h.id}" style="width:auto" ${selected.has(h.id) ? "checked" : ""}> ${dot(h)} <b>${esc(h.name)}</b>${h.online === false ? ' <span class="tag">offline – ascuns din MCP</span>' : ""} <span class="mut">${esc(h.user)}@${esc(h.hostname)}:${h.port}</span>
        <span class="tag">${esc(h.mode)}</span> <span class="tag">${h.auth === "key" ? "cheie" : "parolă"}</span>
        ${h.group ? `<span class="tag">${esc(h.group)}</span>` : ""}
        <span id="cl-tag-${h.id}">${checkHostIds.has(h.id) ? '<span class="tag ok">✓ Checklist</span>' : ""}</span>
        ${h.auth === "key" ? `<div style="font-size:12px">cheie: <b>${esc(h.keyName || "?")}</b> ${h.keyValid ? '<span class="ok">valid</span>' : '<b class="bad">INVALID (nu conține cheia privată)</b>'} <span class="mut">${esc(h.keyFingerprint || "")}</span></div>` : ""}
        <div class="mut" style="font-size:12px">${h.fingerprint ? "host key: " + esc(h.fingerprint) : "host key nefixat (se fixează la prima conectare)"}</div></div>
        <div class="row"><span id="cl-btn-${h.id}">${checkHostIds.has(h.id) ? `<button class="b" data-check-del="${h.id}">Scoate din Checklist</button>` : `<button class="b" data-check-add="${h.id}">+ Checklist</button>`}</span><button class="b" data-test="${h.id}">Test</button><button class="b" data-edit="${h.id}">Editează</button><button class="b d" data-del="${h.id}">Șterge</button></div></div>
        <pre class="hidden" id="out-${h.id}"></pre></div>`).join("")}`;
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
      document.getElementById("sel-all").onchange = (e) => { selected.clear(); if (e.target.checked) hostIds.forEach((id) => selected.add(id)); syncSel(); };
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
        if (mode === "free" && !confirm(`Setezi ${selected.size} hosturi pe FREE? AI-ul va rula orice comandă fără aprobare.`)) return;
        await api("POST", "/api/hosts/mode", { ids: [...selected], mode });
        render();
      });
      syncSel();
    }
    const refreshDots = async () => {
      for (const h of await api("GET", "/api/hosts")) {
        const d = document.querySelector(`[data-dot="${h.id}"]`);
        if (d) d.outerHTML = dot(h);
      }
    };
    const form = (h = {}) => {
      const dlg = document.getElementById("host-dialog");
      dlg.innerHTML = `
        <div class="row" style="justify-content:space-between;margin-bottom:12px">
          <h3 style="margin:0">${h.id ? `Editează Host: ${esc(h.name)}` : "Host nou"}</h3>
          <button class="b" id="dlg-close" type="button" style="padding:2px 8px;font-size:16px;line-height:1">×</button>
        </div>
        <form id="f-host-form">
          <div class="grid">
            <div><label>Nume</label><input id="f-name" value="${esc(h.name)}" required></div>
            <div><label>Hostname / IP</label><input id="f-host" value="${esc(h.hostname)}" required></div>
            <div><label>Port</label><input id="f-port" type="number" value="${h.port || 22}"></div>
            <div><label>Utilizator</label><input id="f-user" value="${esc(h.user)}" required></div>
            <div><label>Autentificare</label><select id="f-auth"><option value="key">Cheie SSH</option><option value="password">Parolă</option></select></div>
            <div id="w-key"><label>Cheie</label><select id="f-key">${keys.map((k) => `<option value="${k.id}" ${k.id === h.keyId ? "selected" : ""}>${esc(k.name)}</option>`).join("")}</select></div>
            <div id="w-pw"><label>Parolă ${h.hasPassword ? "(lasă gol = neschimbată)" : ""}</label><input id="f-pw" type="password" autocomplete="new-password"></div>
            <div><label>Mod siguranță</label><select id="f-mode">
              <option value="approval">approval - aprobi fiecare comandă</option>
              <option value="read-only">read-only - doar comenzi din allowlist</option>
              <option value="free">free - AI-ul rulează orice</option></select></div>
            <div><label>Grup</label><input id="f-group" value="${esc(h.group)}"></div>
          </div>
          <label style="margin-top:8px">Allowlist suplimentar read-only (un prefix de comandă pe linie, ex: <code>systemctl status</code>)</label>
          <textarea id="f-allow">${esc((h.allowlist || []).join("\n"))}</textarea>
          ${h.id ? `<label style="margin-top:6px"><input type="checkbox" id="f-reset" style="width:auto"> Resetează host key fixat (după reinstalare server)</label>` : ""}
          <div class="row" style="justify-content:flex-end;margin-top:16px;gap:8px">
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
        await api(h.id ? "PUT" : "POST", h.id ? "/api/hosts/" + h.id : "/api/hosts", body);
        close();
        await views.hosts();
        void updateBadges();
      });

      dlg.showModal();
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
      if (confirm("Ștergi hostul?")) {
        await api("DELETE", "/api/hosts/" + b.dataset.del);
        await views.hosts();
        void updateBadges();
      }
    })));
    v.querySelectorAll("[data-test]").forEach((b) => (b.onclick = async () => {
      const o = document.getElementById("out-" + b.dataset.test); o.classList.remove("hidden"); o.textContent = "se conectează...";
      try { o.textContent = (await api("POST", `/api/hosts/${b.dataset.test}/test`, {})).output; } catch (e) { o.textContent = "Eroare: " + e.message; }
    }));
  },

  async checklist() {
    const dot = (h) => `<span data-dot="${h.id}">${h.online === undefined ? "" : h.online ? '<span class="ok" title="accesibil">●</span>' : `<b class="bad" title="${esc(h.offlineReason || "")}">●</b>`}</span>`;
    const [items, allHosts] = await Promise.all([
      api("GET", "/api/checklist"),
      api("GET", "/api/hosts"),
    ]);
    const v = document.getElementById("view");
    const itemHostIds = new Set(items.map((it) => it.hostId));
    const availableHosts = allHosts.filter((h) => !itemHostIds.has(h.id));

    const statusBadge = (s) => {
      if (s === "ok") return '<span class="tag ok" style="font-weight:600">● OK</span>';
      if (s === "warning") return '<span class="tag bad" style="font-weight:600">⚠️ Atenție</span>';
      if (s === "error") return '<span class="tag bad" style="font-weight:600">❌ Eroare</span>';
      return '<span class="tag mut">○ Never checked</span>';
    };

    v.innerHTML = `
      <div class="row" style="justify-content:space-between">
        <h2>Checklist Securitate (${items.length})</h2>
        <div class="row">
          <button class="b p" id="cl-open-add">+ Adaugă servere</button>
          ${items.length ? '<button class="b" id="cl-run-all">Verifică toate</button>' : ""}
          ${items.length ? '<button class="b d" id="cl-clear-all">Golește checklist</button>' : ""}
        </div>
      </div>

      <div class="card" style="border-left:4px solid var(--acc)">
        <b>Prompt pentru AI (Claude / ChatGPT / Agent):</b>
        <p class="mut" style="margin:4px 0 8px">
          AI-ul are acces la uneltele <code>get_security_checklist</code> și <code>run_security_check</code>.
          Când îi spui: <i>«fă un security check»</i>, el citește această listă și inspectează fiecare server (loguri auth.log / journalctl, login-uri eșuate, sesiuni active, porturi deschise ss, servicii picate systemd și disc).
        </p>
        <div class="row">
          <input id="ai-prompt-input" readonly value="Fă un security check pe serverele din checklist și verifică logurile de autentificare, tentativele eșuate, porturile deschise și serviciile." style="flex:1">
          <button class="b p" id="ai-prompt-copy">Copiază prompt</button>
        </div>
      </div>

      <div id="cl-form-container"></div>

      ${items.length ? "" : '<p class="mut">Checklist-ul este gol. Adaugă servere pentru a fi incluse în verificarea de securitate.</p>'}

      ${items.map((it) => {
        const h = it.host || {};
        return `
          <div class="card" id="cl-card-${it.hostId}">
            <div class="row" style="justify-content:space-between;align-items:flex-start">
              <div style="flex:1">
                <div class="row" style="gap:6px">
                  ${dot(h)}
                  <b>${esc(h.name)}</b>
                  ${h.online === false ? '<span class="tag bad">offline</span>' : ""}
                  <span class="mut">${esc(h.user)}@${esc(h.hostname)}:${h.port}</span>
                  <span class="tag">${esc(h.mode)}</span>
                  ${h.group ? `<span class="tag">${esc(h.group)}</span>` : ""}
                  ${statusBadge(it.lastStatus)}
                </div>

                ${it.lastSummary ? `<div style="font-size:13px;margin-top:6px"><b>Rezultat:</b> <span class="${it.lastStatus === 'warning' ? 'bad' : 'ok'}">${esc(it.lastSummary)}</span></div>` : ""}

                <div class="row mut" style="font-size:12px;margin-top:4px;gap:12px">
                  <span>Adăugat: ${esc(it.addedAt.replace("T", " ").slice(0, 16))}</span>
                  <span>Ultima verificare: ${it.lastChecked ? esc(it.lastChecked.replace("T", " ").slice(0, 19)) : "Niciodată"}</span>
                </div>

                ${it.notes ? `<div style="font-size:12px;margin-top:4px"><b>Notițe:</b> <span class="mut">${esc(it.notes)}</span></div>` : ""}
              </div>

              <div class="row" style="gap:6px">
                <button class="b p" data-cl-check="${it.hostId}">Verifică acum</button>
                <button class="b" data-cl-note="${it.hostId}">Notițe</button>
                <button class="b d" data-cl-remove="${it.hostId}">Elimină</button>
              </div>
            </div>

            <pre class="hidden" id="cl-out-${it.hostId}" style="margin-top:10px;max-height:360px;overflow:auto"></pre>
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
          <div style="max-height:180px;overflow:auto;border:1px solid var(--line);border-radius:6px;padding:8px;margin-bottom:8px">
            ${availableHosts.map((h) => `
              <label style="display:flex;align-items:center;gap:8px;margin:4px 0;cursor:pointer">
                <input type="checkbox" class="cl-add-chk" value="${h.id}" style="width:auto">
                <b>${esc(h.name)}</b> <span class="mut">(${esc(h.user)}@${esc(h.hostname)})</span> <span class="tag">${esc(h.mode)}</span>
              </label>
            `).join("")}
          </div>
          <label>Notițe / Instrucțiuni specifice pentru AI (opțional):</label>
          <input id="cl-new-notes" placeholder="ex: verifică loguri nginx și auth.log">
          <p style="margin-top:10px">
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
      if (confirm("Elimini serverul din checklist?")) {
        const id = b.dataset.clRemove;
        await api("DELETE", `/api/checklist/${id}`);
        const card = document.getElementById("cl-card-" + id);
        if (card) {
          card.style.opacity = "0";
          card.style.transition = "opacity 0.2s ease";
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
        if (confirm("Sigur vrei să golești întreg checklist-ul?")) {
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
    v.innerHTML = `<div class="row" style="justify-content:space-between"><h2>Kubernetes</h2><button class="b p" id="new">+ Cluster nou</button></div>
      <p class="mut">Încarci fișierul kubeconfig (YAML); se stochează criptat în vault. AI-ul folosește uneltele <code>list_clusters</code> și <code>kubectl</code>. Același mod de siguranță ca la hosturi; în <b>read-only</b> nu poate citi Secrets, nu poate face watch/follow și rulează doar get/describe/logs/top/events etc.</p>
      <div id="form"></div>
      ${cl.length ? "" : '<p class="mut">Niciun cluster.</p>'}
      ${cl.map((c) => `<div class="card"><div class="row" style="justify-content:space-between"><div>
        <b>${esc(c.name)}</b> <span class="tag">${esc(c.mode)}</span> ${c.group ? `<span class="tag">${esc(c.group)}</span>` : ""}
        ${c.info ? `<div class="mut" style="font-size:12px">context: <b>${esc(c.context || c.info.currentContext || "?")}</b>${c.namespace ? ` · namespace: <b>${esc(c.namespace)}</b>` : ""} · ${esc(c.info.servers.join(", "))}</div>
        ${c.info.execCommands.length ? `<div style="font-size:12px" class="bad">rulează local pentru autentificare: ${esc(c.info.execCommands.join(", "))}</div>` : ""}` : '<b class="bad">kubeconfig ilizibil</b>'}</div>
        <div class="row"><button class="b" data-test="${c.id}">Test</button><button class="b" data-edit="${c.id}">Editează</button><button class="b d" data-del="${c.id}">Șterge</button></div></div>
        <pre class="hidden" id="out-${c.id}"></pre></div>`).join("")}`;
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
        if (body.mode === "free" && c.mode !== "free" && !confirm("Mod FREE: AI-ul poate rula orice kubectl (inclusiv delete) fără aprobare. Continui?")) return;
        await api(c.id ? "PUT" : "POST", c.id ? "/api/clusters/" + c.id : "/api/clusters", body);
        render();
      });
    };
    document.getElementById("new").onclick = () => form();
    v.querySelectorAll("[data-edit]").forEach((b) => (b.onclick = () => form(cl.find((c) => c.id === b.dataset.edit))));
    v.querySelectorAll("[data-del]").forEach((b) => (b.onclick = act(async () => { if (confirm("Ștergi clusterul?")) { await api("DELETE", "/api/clusters/" + b.dataset.del); render(); } })));
    v.querySelectorAll("[data-test]").forEach((b) => (b.onclick = async () => {
      const o = document.getElementById("out-" + b.dataset.test); o.classList.remove("hidden"); o.textContent = "se conectează...";
      try { o.textContent = (await api("POST", `/api/clusters/${b.dataset.test}/test`, {})).output; } catch (e) { o.textContent = "Eroare: " + e.message; }
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
      <div class="card"><h3>Din aplicația Termius de pe acest PC (automat)</h3><div id="tl"><span class="mut">se verifică...</span></div></div>
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
    // ---- Termius desktop (local, automat) ----
    const tl = document.getElementById("tl");
    const tlDraw = async () => {
      const st = await api("GET", "/api/import/termius-local/status");
      if (!st.supported) return (tl.innerHTML = '<p class="mut">Disponibil doar pe Windows.</p>');
      if (!st.termiusFound) return (tl.innerHTML = '<p class="mut">Aplicația Termius desktop nu a fost găsită pe acest PC (datele ei sunt în %APPDATA%/Termius).</p>');
      tl.innerHTML = st.helperReady
        ? '<button class="b p" id="tl-scan">Scanează Termius</button> <span class="mut">Citește local, offline, hosturile, parolele și cheile. Nu trimite nimic nicăieri.</span>'
        : '<p class="mut">Pas unic: instalez un mic ajutor Python (ccl_chromium_reader, din GitHub) într-un mediu izolat în <code>data/py</code>. Necesită Python 3, git și internet; durează ~1 minut.</p><button class="b p" id="tl-setup">Pregătește importul</button>';
      const setup = document.getElementById("tl-setup");
      if (setup) setup.onclick = act(async () => { setup.disabled = true; setup.textContent = "se instalează..."; try { await api("POST", "/api/import/termius-local/setup", {}); } finally { await tlDraw(); } });
      const scan = document.getElementById("tl-scan");
      if (scan) scan.onclick = act(async () => { scan.disabled = true; scan.textContent = "se citește..."; try { tlPreview(await api("POST", "/api/import/termius-local/scan", {})); } finally { scan.disabled = false; scan.textContent = "Scanează Termius"; } });
    };
    const tlPreview = (r) => {
      const p = document.getElementById("preview");
      const rows = r.hosts;
      const authLabel = (h) => (h.auth === "key" ? "cheie: " + esc(h.keyLabel || "") : h.auth === "password" ? "parolă" : '<span class="bad">fără credențiale</span>');
      p.innerHTML = `<div class="card"><h3>Termius: ${rows.length} hosturi, ${r.stats.keys} chei, ${r.stats.groups} grupuri</h3>
        <div class="row"><input id="tl-filter" placeholder="Caută..." style="max-width:260px">
          <button class="b" id="tl-all">Selectează tot</button><button class="b" id="tl-none">Nimic</button>
          <label style="margin:0">Mod siguranță: <select id="tl-mode" style="width:auto"><option value="approval">approval</option><option value="read-only">read-only</option><option value="free">free</option></select></label></div>
        <table id="tl-table"><tr><th></th><th>Grup</th><th>Nume</th><th>Adresă</th><th>User</th><th>Autentificare</th></tr>
        ${rows.map((h) => `<tr data-q="${esc((h.group + " " + h.name + " " + h.address + " " + h.user).toLowerCase())}"><td><input type="checkbox" style="width:auto" data-id="${h.id}" ${h.exists ? "" : "checked"}></td>
          <td>${esc(h.group || "")}</td><td>${esc(h.name)}${h.exists ? ' <span class="tag">există deja</span>' : ""}</td><td>${esc(h.address)}:${h.port}</td><td>${esc(h.user)}</td><td>${authLabel(h)}</td></tr>`).join("")}</table>
        <p class="mut">Cheile folosite de hosturile selectate se copiază criptat în vault. Hosturile pornesc în modul ales mai sus (recomandat: approval).</p>
        <p><button class="b p" id="tl-commit">Importă selecția</button></p></div>`;
      const visible = () => [...p.querySelectorAll("#tl-table tr[data-q]")].filter((tr) => tr.style.display !== "none");
      document.getElementById("tl-filter").oninput = (e) => { const q = e.target.value.toLowerCase(); p.querySelectorAll("#tl-table tr[data-q]").forEach((tr) => (tr.style.display = tr.dataset.q.includes(q) ? "" : "none")); };
      document.getElementById("tl-all").onclick = () => visible().forEach((tr) => (tr.querySelector("input").checked = true));
      document.getElementById("tl-none").onclick = () => visible().forEach((tr) => (tr.querySelector("input").checked = false));
      document.getElementById("tl-commit").onclick = act(async () => {
        const ids = [...p.querySelectorAll("[data-id]")].filter((c) => c.checked).map((c) => +c.dataset.id);
        if (!ids.length) throw new Error("nu ai selectat nimic");
        const out = await api("POST", "/api/import/termius-local/commit", { session: r.session, ids, mode: val("tl-mode") });
        alert(`Importate: ${out.added} hosturi, ${out.keysAdded} chei.` + (out.skipped.length ? `\nSărite (${out.skipped.length}): ${out.skipped.slice(0, 15).join(", ")}` : ""));
        tab = "hosts"; render();
      });
    };
    await tlDraw();
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
          <li>Confirmă avertismentul și <i>Create</i>; ChatGPT va descoperi uneltele <code>list_hosts</code>, <code>run_command</code>, <code>read_file</code>, <code>get_host_info</code>, <code>list_clusters</code>, <code>kubectl</code>.</li></ol>
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
