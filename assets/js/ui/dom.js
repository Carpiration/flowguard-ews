// Шаблоны с обязательным экранированием: любые значения, кроме raw(),
// вставляются как текст. Это защищает от внедрения разметки через имена
// файлов, домены и прочие данные из анализируемых источников.

export class Raw {
  constructor(s) {
    this.s = s;
  }

  toString() {
    return this.s;
  }
}

export const raw = (s) => new Raw(String(s));

const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export function esc(v) {
  return String(v).replace(/[&<>"']/g, (c) => ESC[c]);
}

function render(v) {
  if (v === null || v === undefined || v === false) return '';
  if (v instanceof Raw) return v.s;
  if (Array.isArray(v)) return v.map(render).join('');
  return esc(v);
}

export function html(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) out += render(values[i]) + strings[i + 1];
  return new Raw(out);
}

export function mount(el, tpl) {
  el.innerHTML = tpl instanceof Raw ? tpl.s : esc(tpl);
  return el;
}

export const qs = (sel, root = document) => root.querySelector(sel);
export const qsa = (sel, root = document) => [...root.querySelectorAll(sel)];

// Делегирование событий: on(root, 'click', '[data-action]', (e, el) => …)
export function on(root, type, selector, handler, opts) {
  const fn = (e) => {
    const el = e.target.closest(selector);
    if (el && root.contains(el)) handler(e, el);
  };
  root.addEventListener(type, fn, opts);
  return () => root.removeEventListener(type, fn, opts);
}

export function debounce(fn, ms = 150) {
  let t = 0;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

export function reducedMotion() {
  const pref = document.documentElement.dataset.motion;
  if (pref === 'reduce') return true;
  if (pref === 'full') return false;
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

// Плавный счётчик для крупных чисел; при уменьшенном движении — сразу итог.
export function countUp(el, to, format, duration = 700) {
  if (!el) return;
  if (reducedMotion() || !Number.isFinite(to)) {
    el.textContent = format(to);
    return;
  }
  const start = performance.now();
  const step = (now) => {
    const k = Math.min(1, (now - start) / duration);
    const e = 1 - Math.pow(1 - k, 3);
    el.textContent = format(to * e);
    if (k < 1 && el.isConnected) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

export function uid(prefix = 'id') {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`;
}
