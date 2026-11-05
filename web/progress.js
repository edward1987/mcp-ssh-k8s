"use strict";
(() => {
  function start(container, label = 'Operatie in curs') {
    const status = document.createElement('div');
    status.className = 'operation-progress';
    status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
    const text = document.createElement('span'); text.textContent = label + ': se proceseaza...';
    const bar = document.createElement('progress'); bar.setAttribute('aria-label', label);
    status.append(text, bar); container.append(status);
    return () => status.remove();
  }
  window.OperationProgress = { start };
  const pending = new Map();
  document.addEventListener('submit', event => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || event.defaultPrevented || form.method.toLowerCase() !== 'post') return;
    if (pending.has(form)) { event.preventDefault(); return; }
    const finish = start(form, event.submitter?.textContent.trim() || 'Trimitere formular');
    form.setAttribute('aria-busy', 'true');
    // Preserve submitter name/value in the POST payload.
    const buttons = [...form.querySelectorAll('button, input[type=submit]')];
    buttons.forEach(button => button.setAttribute('aria-disabled', 'true'));
    pending.set(form, () => { finish(); form.removeAttribute('aria-busy'); buttons.forEach(button => button.removeAttribute('aria-disabled')); });
  });
  window.addEventListener('pageshow', () => { pending.forEach(finish => finish()); pending.clear(); });
})();
