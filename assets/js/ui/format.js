// Форматирование чисел, объёмов, длительностей и времени для русского интерфейса.

import { bytesText } from '../core/catalog.js';

const nf0 = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 0 });
const nf1 = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 1 });
const nf2 = new Intl.NumberFormat('ru-RU', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

export const fmtInt = (n) => (Number.isFinite(n) ? nf0.format(Math.round(n)) : '—');
export const fmt1 = (n) => (Number.isFinite(n) ? nf1.format(n) : '—');
export const fmt2 = (n) => (Number.isFinite(n) ? nf2.format(n) : '—');

export function fmtCompact(n) {
  if (!Number.isFinite(n)) return '—';
  const a = Math.abs(n);
  if (a < 10000) return nf0.format(n);
  if (a < 1e6) return `${nf1.format(n / 1e3)} тыс.`;
  if (a < 1e9) return `${nf1.format(n / 1e6)} млн`;
  return `${nf1.format(n / 1e9)} млрд`;
}

export function fmtAxis(n) {
  const a = Math.abs(n);
  if (a >= 1e9) return `${nf1.format(n / 1e9)}G`;
  if (a >= 1e6) return `${nf1.format(n / 1e6)}M`;
  if (a >= 1e3) return `${nf1.format(n / 1e3)}K`;
  return nf1.format(n);
}

export const fmtBytes = (b) => (Number.isFinite(b) ? bytesText(b) : '—');

export function fmtPct(x, digits = 0) {
  if (x === null || x === undefined || !Number.isFinite(x)) return '—';
  return `${new Intl.NumberFormat('ru-RU', { minimumFractionDigits: digits, maximumFractionDigits: digits }).format(x * 100)}%`;
}

export function fmtDuration(sec) {
  if (sec === null || sec === undefined || !Number.isFinite(sec)) return '—';
  if (sec < 1) return `${nf1.format(sec)} с`;
  if (sec < 59.5) return `${nf0.format(sec)} с`;
  const total = Math.round(sec);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h) return `${h} ч ${String(m).padStart(2, '0')} мин`;
  return s ? `${m} мин ${String(s).padStart(2, '0')} с` : `${m} мин`;
}

// Время события: абсолютное (часы:минуты:секунды по локальному времени)
// или относительно начала записи.
export function fmtClock(t, absolute, origin = 0) {
  if (!Number.isFinite(t)) return '—';
  if (absolute) {
    return new Date(t * 1000).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
  const d = Math.max(0, t - origin);
  const h = Math.floor(d / 3600);
  const m = Math.floor((d % 3600) / 60);
  const s = Math.floor(d % 60);
  return h ? `+${h}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}` : `+${m}:${String(s).padStart(2, '0')}`;
}

export function fmtDateTime(ms) {
  return new Date(ms).toLocaleString('ru-RU', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export function fmtDate(ms) {
  return new Date(ms).toLocaleDateString('ru-RU', { day: 'numeric', month: 'long', year: 'numeric' });
}

export function plural(n, one, few, many) {
  const a = Math.abs(n) % 100;
  const b = a % 10;
  if (a > 10 && a < 20) return many;
  if (b > 1 && b < 5) return few;
  if (b === 1) return one;
  return many;
}

export const countText = (n, one, few, many) => `${fmtInt(n)} ${plural(n, one, few, many)}`;
