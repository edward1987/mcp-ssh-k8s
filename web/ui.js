"use strict";
window.SecureUI = (() => {
  let confirmOpen = false;
  function notify(message, error = false) {
    const area = document.getElementById('notifications');
    const item = document.createElement('div'); item.className = 'toast' + (error ? ' error' : ''); item.setAttribute('role', error ? 'alert' : 'status');
    const text = document.createElement('span'); text.textContent = message;
    const close = document.createElement('button'); close.textContent = '×'; close.setAttribute('aria-label', 'Închide notificarea'); close.onclick = () => item.remove();
    item.append(text, close); area.append(item);
    while (area.children.length > 4) area.firstChild.remove();
    setTimeout(() => item.remove(), error ? 12000 : 6000);
  }
  function confirmAction(message, title = 'Confirmă acțiunea') {
    if (confirmOpen) return Promise.resolve(false);
    confirmOpen = true;
    return new Promise(resolve => {
      const previous = document.activeElement;
      const dialog = document.createElement('dialog'); dialog.className = 'confirm-dialog'; dialog.setAttribute('aria-labelledby', 'confirm-title'); dialog.setAttribute('aria-describedby', 'confirm-description');
      const heading = document.createElement('h2'); heading.id = 'confirm-title'; heading.textContent = title;
      const content = document.createElement('p'); content.id = 'confirm-description'; content.textContent = message;
      const actions = document.createElement('div'); actions.className = 'dialog-actions';
      const cancel = document.createElement('button'); cancel.textContent = 'Anulează'; cancel.autofocus = true;
      const approve = document.createElement('button'); approve.className = 'd'; approve.textContent = 'Confirmă';
      const done = value => { dialog.close(); dialog.remove(); confirmOpen = false; previous?.focus(); resolve(value); };
      cancel.onclick = () => done(false); approve.onclick = () => done(true);
      dialog.oncancel = event => { event.preventDefault(); done(false); };
      document.addEventListener('security-lock', () => done(false), { once: true, signal: (() => { const c = new AbortController(); dialog.addEventListener('close', () => c.abort(), { once: true }); return c.signal; })() });
      actions.append(cancel, approve); dialog.append(heading, content, actions); document.body.append(dialog); dialog.showModal(); cancel.focus();
    });
  }
  function decorate(root = document) {
    root.querySelectorAll('.tag').forEach(tag => { const mode = tag.textContent.trim(); if (['free', 'approval', 'read-only'].includes(mode)) tag.dataset.mode = mode; });
    root.querySelectorAll('table').forEach(table => { if (table.parentElement.classList.contains('table-wrap')) return; const wrapper = document.createElement('div'); wrapper.className = 'table-wrap'; wrapper.tabIndex = 0; wrapper.setAttribute('role', 'region'); wrapper.setAttribute('aria-label', 'Tabel cu derulare orizontală'); table.before(wrapper); wrapper.append(table); });
    root.querySelectorAll('input:not([type=hidden]),select,textarea').forEach((input, index) => {
      if (!input.id) input.id = 'input-' + index + '-' + Math.random().toString(36).slice(2, 8);
      if (input.previousElementSibling?.tagName === 'LABEL') input.previousElementSibling.htmlFor = input.id;
      if (!input.labels?.length && !input.getAttribute('aria-label')) input.setAttribute('aria-label', input.placeholder || input.name || input.id);
      if (input.type === 'password' && !input.autocomplete) input.autocomplete = 'new-password';
    });
  }
  return { notify, confirmAction, decorate };
})();
