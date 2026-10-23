// Модальное подтверждение на нативном <dialog>: ловушка фокуса, Escape и
// возврат фокуса на вызвавший элемент.

import { html, mount } from './dom.js';

export function confirmDialog({ title, message, confirm = 'Подтвердить', cancel = 'Отмена', danger = false }) {
  return new Promise((resolve) => {
    const opener = document.activeElement;
    const dlg = document.createElement('dialog');
    dlg.className = 'modal';
    dlg.setAttribute('aria-labelledby', 'dlg-title');
    mount(
      dlg,
      html`<form method="dialog">
        <div class="modal-body">
          <h2 id="dlg-title" class="section-title">${title}</h2>
          <p class="ink-2">${message}</p>
        </div>
        <div class="modal-actions">
          <button class="btn" value="cancel" autofocus>${cancel}</button>
          <button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" value="ok">${confirm}</button>
        </div>
      </form>`,
    );
    document.body.append(dlg);
    dlg.addEventListener('close', () => {
      resolve(dlg.returnValue === 'ok');
      dlg.remove();
      if (opener && opener.isConnected) opener.focus();
    });
    dlg.addEventListener('click', (e) => {
      if (e.target === dlg) dlg.close('cancel');
    });
    dlg.showModal();
  });
}

// Выпадающее меню: Escape и клик вне закрывают, стрелки перемещают фокус.
export function bindMenu(root) {
  const btn = root.querySelector('[data-menu-button]');
  const list = root.querySelector('[role="menu"]');
  if (!btn || !list) return () => {};
  const items = () => [...list.querySelectorAll('[role="menuitem"]')];
  const close = (focusButton = false) => {
    list.hidden = true;
    btn.setAttribute('aria-expanded', 'false');
    if (focusButton) btn.focus();
  };
  const open = () => {
    list.hidden = false;
    btn.setAttribute('aria-expanded', 'true');
    items()[0]?.focus();
  };
  const onBtn = () => (list.hidden ? open() : close());
  const onKey = (e) => {
    const all = items();
    const i = all.indexOf(document.activeElement);
    if (e.key === 'Escape') {
      e.preventDefault();
      close(true);
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      all[(i + 1) % all.length]?.focus();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      all[(i - 1 + all.length) % all.length]?.focus();
    } else if (e.key === 'Tab') close();
  };
  const onDoc = (e) => {
    if (!root.contains(e.target)) close();
  };
  const onPick = (e) => {
    if (e.target.closest('[role="menuitem"]')) close(true);
  };
  btn.addEventListener('click', onBtn);
  list.addEventListener('keydown', onKey);
  list.addEventListener('click', onPick);
  document.addEventListener('pointerdown', onDoc);
  return () => {
    btn.removeEventListener('click', onBtn);
    document.removeEventListener('pointerdown', onDoc);
  };
}
