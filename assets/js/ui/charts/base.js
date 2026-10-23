// Общие средства графиков: цвета из CSS-токенов, холст с учётом плотности
// пикселей, «круглые» деления шкал и подписи времени.

export function cssVar(name, el = document.documentElement) {
  return getComputedStyle(el).getPropertyValue(name).trim();
}

export function palette() {
  const v = (n) => cssVar(n);
  return {
    ink: v('--ink'),
    ink2: v('--ink-2'),
    ink3: v('--ink-3'),
    grid: v('--grid'),
    axis: v('--axis'),
    surface: v('--surface'),
    surface2: v('--surface-2'),
    surface3: v('--surface-3'),
    accent: v('--accent'),
    series: [1, 2, 3, 4, 5, 6, 7, 8].map((i) => v(`--series-${i}`)),
    good: v('--good'),
    warning: v('--warning'),
    serious: v('--serious'),
    critical: v('--critical'),
    font: v('--font-sans') || 'system-ui, sans-serif',
    mono: v('--font-mono') || 'ui-monospace, monospace',
  };
}

export const STATUS_BY_SEV = ['ink3', 'good', 'warning', 'serious', 'critical'];
export const STATUS_BY_LEVEL = { low: 'good', medium: 'warning', high: 'serious', critical: 'critical' };

export function withAlpha(color, a) {
  const c = color.trim();
  if (c.startsWith('#')) {
    let h = c.slice(1);
    if (h.length === 3) h = h.split('').map((x) => x + x).join('');
    const n = parseInt(h, 16);
    return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${a})`;
  }
  const m = c.match(/rgba?\(([^)]+)\)/);
  if (m) {
    const [r, g, b] = m[1].split(',').map((x) => parseFloat(x));
    return `rgba(${r}, ${g}, ${b}, ${a})`;
  }
  return c;
}

export function setupCanvas(canvas, width, height) {
  const dpr = Math.min(2, window.devicePixelRatio || 1);
  canvas.width = Math.max(1, Math.round(width * dpr));
  canvas.height = Math.max(1, Math.round(height * dpr));
  canvas.style.height = `${height}px`;
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return ctx;
}

export function niceStep(range, count = 4) {
  if (range <= 0) return 1;
  const raw = range / count;
  const p = Math.pow(10, Math.floor(Math.log10(raw)));
  const n = raw / p;
  const k = n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10;
  return k * p;
}

export function niceMax(max, count = 4) {
  if (max <= 0) return 1;
  const step = niceStep(max, count);
  return Math.ceil(max / step) * step;
}

const TIME_STEPS = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400];

export function timeTicks(t0, t1, maxTicks) {
  const span = t1 - t0;
  const step = TIME_STEPS.find((s) => span / s <= maxTicks) || 86400 * Math.ceil(span / 86400 / maxTicks);
  const out = [];
  for (let t = Math.ceil(t0 / step) * step; t <= t1; t += step) out.push(t);
  return out;
}

export function roundRect(ctx, x, y, w, h, r) {
  const rr = Math.min(r, w / 2, h / 2);
  ctx.beginPath();
  ctx.moveTo(x + rr, y);
  ctx.arcTo(x + w, y, x + w, y + h, rr);
  ctx.arcTo(x + w, y + h, x, y + h, rr);
  ctx.arcTo(x, y + h, x, y, rr);
  ctx.arcTo(x, y, x + w, y, rr);
  ctx.closePath();
}

// Наблюдение за размером контейнера с ограничением частоты перерисовки.
export function observeSize(el, fn) {
  let frame = 0;
  let lastW = -1;
  const ro = new ResizeObserver((entries) => {
    const w = Math.round(entries[0].contentRect.width);
    if (w === lastW) return;
    lastW = w;
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(() => fn(w));
  });
  ro.observe(el);
  return () => {
    cancelAnimationFrame(frame);
    ro.disconnect();
  };
}

export function positionTooltip(tip, container, x, y) {
  const cw = container.clientWidth;
  const tw = tip.offsetWidth;
  const th = tip.offsetHeight;
  let left = x + 14;
  if (left + tw > cw) left = x - tw - 14;
  left = Math.max(0, left);
  let top = y - th - 10;
  if (top < 0) top = y + 14;
  tip.style.left = `${left}px`;
  tip.style.top = `${top}px`;
}
