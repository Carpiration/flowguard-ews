// Пользовательские настройки (хранятся в localStorage этого браузера).

import { DEFAULT_INTERNAL, parseCidr } from '../core/net.js';

const KEY = 'fg.settings.v1';

export const SENSITIVITY = {
  conservative: { label: 'Консервативная', value: 0.75, hint: 'Меньше ложных тревог, позже обнаружение' },
  balanced: { label: 'Сбалансированная', value: 1, hint: 'Рекомендуемый режим' },
  sensitive: { label: 'Повышенная', value: 1.35, hint: 'Раньше обнаружение, больше предупреждений' },
};

export const WINDOW_OPTIONS = [
  ['auto', 'Автоматически'],
  ['1', '1 с'],
  ['2', '2 с'],
  ['5', '5 с'],
  ['10', '10 с'],
  ['30', '30 с'],
  ['60', '1 мин'],
  ['300', '5 мин'],
];

export const DEFAULTS = Object.freeze({
  sensitivity: 'balanced',
  windowSize: 'auto',
  threshold: 50,
  internal: DEFAULT_INTERNAL.join('\n'),
  allow: '',
  theme: 'system',
  motion: 'system',
  autosave: true,
});

let cache = null;

export function getSettings() {
  if (cache) return cache;
  let stored = {};
  try {
    stored = JSON.parse(localStorage.getItem(KEY) || '{}');
  } catch {
    stored = {};
  }
  cache = { ...DEFAULTS, ...stored };
  return cache;
}

export function saveSettings(patch) {
  cache = { ...getSettings(), ...patch };
  try {
    localStorage.setItem(KEY, JSON.stringify(cache));
  } catch {
    /* хранилище недоступно (приватный режим) — настройки действуют до перезагрузки */
  }
  window.dispatchEvent(new CustomEvent('fg:settings', { detail: cache }));
  return cache;
}

export function resetSettings() {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* нет доступа к хранилищу */
  }
  cache = null;
  return saveSettings({});
}

export function splitList(text) {
  return String(text || '')
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function invalidCidrs(text) {
  return splitList(text).filter((c) => !parseCidr(c));
}

export function analysisOptions(overrides = {}) {
  const s = { ...getSettings(), ...overrides };
  const internal = splitList(s.internal).filter((c) => parseCidr(c));
  return {
    sensitivity: SENSITIVITY[s.sensitivity]?.value ?? 1,
    sensitivityId: s.sensitivity,
    windowSize: s.windowSize,
    threshold: Number(s.threshold) || 50,
    internal: internal.length ? internal : DEFAULT_INTERNAL,
    allow: splitList(s.allow),
  };
}
