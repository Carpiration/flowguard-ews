// Неблокирующие уведомления вместо alert(). Ошибки объявляются как role="alert".

import { html, mount } from './dom.js';
import { icon } from './icons.js';

const ICONS = { info: 'info', success: 'checkCircle', error: 'alert', warning: 'alert' };

export function toast(message, { type = 'info', action = null, timeout = 5200, title = '' } = {}) {
  const host = document.getElementById('toasts');
  if (!host) return () => {};
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.setAttribute('role', type === 'error' ? 'alert' : 'status');
  mount(
    el,
    html`${icon(ICONS[type] || 'info', 18)}
      <div>${title ? html`<strong>${title}</strong><br />` : ''}${message}</div>
      <div class="toast-actions">
        ${action ? html`<button class="btn btn-sm btn-ghost" data-act>${action.label}</button>` : ''}
        <button class="btn btn-sm btn-ghost btn-icon" data-close aria-label="Закрыть уведомление">${icon('x', 16)}</button>
      </div>`,
  );
  let timer = 0;
  const close = () => {
    clearTimeout(timer);
    if (!el.isConnected || el.classList.contains('is-leaving')) return;
    el.classList.add('is-leaving');
    el.addEventListener('animationend', () => el.remove(), { once: true });
    setTimeout(() => el.remove(), 400);
  };
  el.querySelector('[data-close]').addEventListener('click', close);
  if (action) {
    el.querySelector('[data-act]').addEventListener('click', () => {
      action.onClick();
      close();
    });
  }
  const arm = () => {
    if (timeout) timer = setTimeout(close, timeout);
  };
  el.addEventListener('mouseenter', () => clearTimeout(timer));
  el.addEventListener('mouseleave', arm);
  el.addEventListener('focusin', () => clearTimeout(timer));
  host.append(el);
  while (host.children.length > 4) host.firstElementChild.remove();
  arm();
  return close;
}
