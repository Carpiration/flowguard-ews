// Тема и режим движения. Значение «system» следует настройкам ОС.

import { getSettings } from './settings.js';

const media = window.matchMedia('(prefers-color-scheme: dark)');
const listeners = new Set();

export function applyAppearance(settings = getSettings()) {
  const root = document.documentElement;
  if (settings.theme === 'light' || settings.theme === 'dark') root.dataset.theme = settings.theme;
  else delete root.dataset.theme;
  if (settings.motion === 'reduce' || settings.motion === 'full') root.dataset.motion = settings.motion;
  else delete root.dataset.motion;
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.content = isDark() ? '#0d0d0d' : '#f2f1ec';
  notify();
}

export function isDark() {
  const t = document.documentElement.dataset.theme;
  if (t === 'dark') return true;
  if (t === 'light') return false;
  return media.matches;
}

function notify() {
  for (const fn of listeners) fn(isDark());
}

// Графики подписываются, чтобы перерисоваться в цветах новой темы.
export function onThemeChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

media.addEventListener('change', () => {
  applyAppearance();
});
