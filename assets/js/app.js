// Точка входа: каркас приложения, маршрутизация по hash (совместима с GitHub Pages),
// мобильное меню, переключатель темы и индикатор активного мониторинга.

import { html, mount, qs, qsa } from './ui/dom.js';
import { icon } from './ui/icons.js';
import { getSettings, saveSettings } from './ui/settings.js';
import { applyAppearance } from './ui/theme.js';

const ROUTES = [
  { path: '/', title: 'Обзор', load: () => import('./pages/home.js') },
  { path: '/analyze', title: 'Анализ файла', load: () => import('./pages/analyze.js') },
  { path: '/monitor', title: 'Мониторинг', load: () => import('./pages/monitor.js') },
  { path: '/reports', title: 'Отчёты', load: () => import('./pages/reports.js') },
  { path: '/reports/:id', title: 'Отчёт', nav: '/reports', load: () => import('./pages/report.js') },
  { path: '/lab', title: 'Оценка модели', load: () => import('./pages/lab.js') },
  { path: '/method', title: 'Методология', load: () => import('./pages/method.js') },
  { path: '/settings', title: 'Настройки', load: () => import('./pages/settings.js') },
];

function match(path) {
  for (const r of ROUTES) {
    const a = r.path.split('/');
    const b = path.split('/');
    if (a.length !== b.length) continue;
    const params = {};
    let ok = true;
    for (let i = 0; i < a.length; i++) {
      if (a[i].startsWith(':')) params[a[i].slice(1)] = decodeURIComponent(b[i]);
      else if (a[i] !== b[i]) {
        ok = false;
        break;
      }
    }
    if (ok) return { route: r, params };
  }
  return null;
}

const view = document.getElementById('view');
const crumb = qs('[data-crumb]');
let cleanup = null;
let token = 0;
let first = true;

export const ctx = {
  navigate(path) {
    location.hash = `#${path}`;
  },
  setTitle(title) {
    document.title = `${title} — FlowGuard`;
    crumb.textContent = title;
  },
};

function renderNotFound() {
  mount(
    view,
    html`<div class="empty"><div class="empty-icon">${icon('search', 22)}</div><h1 class="page-title" tabindex="-1">Раздел не найден</h1>
      <p>Проверьте адрес или вернитесь на главную страницу.</p><a class="btn btn-primary" href="#/">На главную</a></div>`,
  );
}

async function route() {
  const raw = location.hash.replace(/^#/, '') || '/';
  const path = raw.split('?')[0].replace(/\/+$/, '') || '/';
  const m = match(path);
  const my = ++token;
  closeDrawer(false);
  try {
    cleanup?.();
  } catch (err) {
    console.error(err);
  }
  cleanup = null;
  let mod = null;
  if (m) {
    try {
      mod = await m.route.load();
    } catch (err) {
      console.error(err);
    }
  }
  if (my !== token) return;
  view.classList.remove('view-enter');
  void view.offsetWidth;
  view.classList.add('view-enter');
  view.replaceChildren();
  const navPath = m ? m.route.nav || m.route.path : '';
  for (const a of qsa('.nav-link')) {
    if (a.dataset.route === navPath) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  if (!m) {
    ctx.setTitle('Не найдено');
    renderNotFound();
  } else if (!mod) {
    ctx.setTitle(m.route.title);
    mount(view, html`<div class="callout callout-error">${icon('alert', 18)}<div><strong>Раздел не загрузился.</strong> Проверьте соединение и обновите страницу.</div></div>`);
  } else {
    ctx.setTitle(m.route.title);
    try {
      const result = await mod.render(view, m.params, ctx);
      if (my !== token) {
        (typeof result === 'function' ? result : result?.destroy)?.call(result);
        return;
      }
      cleanup = typeof result === 'function' ? result : result?.destroy ? () => result.destroy() : null;
    } catch (err) {
      console.error(err);
      mount(view, html`<div class="callout callout-error">${icon('alert', 18)}<div><strong>Ошибка отображения раздела.</strong> ${err.message}</div></div>`);
    }
  }
  if (!first) {
    window.scrollTo({ top: 0 });
    qs('h1', view)?.focus({ preventScroll: true });
  }
  first = false;
}

// ---- мобильное меню с ловушкой фокуса ----
const sidebar = qs('#sidebar');
const backdrop = qs('[data-backdrop]');
const menuBtn = qs('[data-menu]');
const mobile = window.matchMedia('(max-width: 1023px)');

function focusables() {
  return qsa('a[href], button:not([disabled])', sidebar);
}

function openDrawer() {
  sidebar.classList.add('is-open');
  backdrop.hidden = false;
  requestAnimationFrame(() => backdrop.classList.add('is-open'));
  menuBtn.setAttribute('aria-expanded', 'true');
  menuBtn.setAttribute('aria-label', 'Закрыть меню');
  (qs('[aria-current="page"]', sidebar) || focusables()[0])?.focus();
}

function closeDrawer(returnFocus = true) {
  if (!sidebar.classList.contains('is-open')) return;
  sidebar.classList.remove('is-open');
  backdrop.classList.remove('is-open');
  setTimeout(() => {
    if (!sidebar.classList.contains('is-open')) backdrop.hidden = true;
  }, 260);
  menuBtn.setAttribute('aria-expanded', 'false');
  menuBtn.setAttribute('aria-label', 'Открыть меню');
  if (returnFocus) menuBtn.focus();
}

menuBtn.addEventListener('click', () => (sidebar.classList.contains('is-open') ? closeDrawer() : openDrawer()));
backdrop.addEventListener('click', () => closeDrawer());
document.addEventListener('keydown', (e) => {
  if (!sidebar.classList.contains('is-open') || !mobile.matches) return;
  if (e.key === 'Escape') {
    e.preventDefault();
    closeDrawer();
  } else if (e.key === 'Tab') {
    const f = focusables();
    const firstEl = f[0];
    const last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === firstEl) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      firstEl.focus();
    }
  }
});
mobile.addEventListener('change', () => {
  if (!mobile.matches) closeDrawer(false);
});

// ---- тема ----
const THEMES = ['system', 'light', 'dark'];
const THEME_META = { system: ['auto', 'системная'], light: ['sun', 'светлая'], dark: ['moon', 'тёмная'] };
const themeBtn = qs('[data-theme-toggle]');

function paintThemeButton() {
  const t = getSettings().theme;
  const [ic, name] = THEME_META[t] || THEME_META.system;
  themeBtn.replaceChildren();
  themeBtn.insertAdjacentHTML('beforeend', icon(ic, 18).s);
  themeBtn.setAttribute('aria-label', `Тема: ${name}. Переключить`);
  themeBtn.title = `Тема: ${name}`;
}

themeBtn.addEventListener('click', () => {
  const t = getSettings().theme;
  const next = THEMES[(THEMES.indexOf(t) + 1) % THEMES.length];
  applyAppearance(saveSettings({ theme: next }));
  paintThemeButton();
});
window.addEventListener('fg:settings', (e) => {
  applyAppearance(e.detail);
  paintThemeButton();
});

// ---- индикатор мониторинга ----
const pill = qs('[data-live-pill]');
const badge = qs('[data-live-badge]');
const LEVEL_VAR = { low: '--good', medium: '--warning', high: '--serious', critical: '--critical' };
window.addEventListener('fg:live', (e) => {
  const { running, risk, level, warming } = e.detail;
  pill.hidden = !running;
  badge.hidden = !running;
  if (!running) return;
  pill.style.setProperty('--b', `var(${LEVEL_VAR[level] || '--good'})`);
  qs('[data-live-text]', pill).textContent = warming ? 'Мониторинг: обучение' : `Мониторинг: риск ${Math.round(risk)}`;
});

// Тревога мониторинга, пока пользователь в другом разделе.
window.addEventListener('fg:live-alarm', (e) => {
  if (location.hash.startsWith('#/monitor')) return;
  import('./ui/toast.js').then(({ toast }) =>
    toast(`Мониторинг: ${e.detail.title}`, { type: 'error', title: 'Обнаружен инцидент', action: { label: 'Открыть', onClick: () => ctx.navigate('/monitor') } }),
  );
});

// ---- запуск ----
for (const el of qsa('[data-icon]')) el.innerHTML = icon(el.dataset.icon, Number(el.dataset.size) || 18).s;
applyAppearance();
paintThemeButton();
window.addEventListener('hashchange', route);
route();
