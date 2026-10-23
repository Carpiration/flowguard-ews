// Малые кратные: вклад каждого детектора (0…1) по времени. Ось времени
// совпадает с основной шкалой, наведение синхронизируется.

import { fmtPct } from '../format.js';
import { onThemeChange } from '../theme.js';
import { observeSize, palette, positionTooltip, setupCanvas, withAlpha } from './base.js';

export class SparkRows {
  constructor(container, { rows, t0, w, onHover, rowHeight = 38 }) {
    this.rows = rows;
    this.t0 = t0;
    this.w = w;
    this.onHover = onHover;
    this.rowHeight = rowHeight;
    this.hover = -1;
    this.root = document.createElement('div');
    this.root.className = 'chart';
    this.canvas = document.createElement('canvas');
    this.canvas.setAttribute('role', 'img');
    this.canvas.setAttribute('aria-label', `Вклад детекторов по времени: ${rows.map((r) => r.label).join(', ')}. Значения доступны в таблице временного ряда.`);
    this.tip = document.createElement('div');
    this.tip.className = 'tooltip';
    this.root.append(this.canvas, this.tip);
    container.append(this.root);
    this.width = container.clientWidth || 600;
    this.unobserve = observeSize(this.root, (wd) => {
      this.width = wd;
      this.draw();
    });
    this.untheme = onThemeChange(() => this.draw());
    this.canvas.addEventListener('pointermove', (e) => {
      const r = this.canvas.getBoundingClientRect();
      this.setHover(this.indexAt(e.clientX - r.left), true);
    });
    this.canvas.addEventListener('pointerleave', () => this.setHover(-1, true));
  }

  geom() {
    const pad = { l: 52, r: 14, t: 4 };
    return { pad, iw: Math.max(10, this.width - pad.l - pad.r), H: pad.t + this.rows.length * this.rowHeight + 2 };
  }

  xOf(t, g) {
    const T0 = this.t0[0];
    const T1 = this.t0[this.t0.length - 1] + this.w;
    return g.pad.l + ((t - T0) / Math.max(1e-9, T1 - T0)) * g.iw;
  }

  indexAt(px) {
    const g = this.geom();
    const n = this.t0.length;
    const T0 = this.t0[0];
    const T1 = this.t0[n - 1] + this.w;
    const t = T0 + ((px - g.pad.l) / g.iw) * (T1 - T0);
    return Math.max(0, Math.min(n - 1, Math.floor((t - T0) / this.w)));
  }

  draw() {
    const n = this.t0.length;
    if (!n || !this.width) return;
    const g = this.geom();
    const ctx = setupCanvas(this.canvas, this.width, g.H);
    const P = palette();
    ctx.clearRect(0, 0, this.width, g.H);
    ctx.font = `11px ${P.mono}`;
    ctx.textBaseline = 'top';
    this.rows.forEach((row, k) => {
      const top = g.pad.t + k * this.rowHeight;
      const h = this.rowHeight - 14;
      const base = top + 12 + h;
      ctx.strokeStyle = P.grid;
      ctx.beginPath();
      ctx.moveTo(g.pad.l, Math.round(base) + 0.5);
      ctx.lineTo(g.pad.l + g.iw, Math.round(base) + 0.5);
      ctx.stroke();
      ctx.fillStyle = P.ink2;
      ctx.textAlign = 'left';
      ctx.fillText(row.label, g.pad.l + 2, top);
      const color = P.series[row.slot ?? 0];
      const x = (i) => this.xOf(this.t0[i] + this.w / 2, g);
      const y = (v) => base - Math.min(1, Math.max(0, v)) * h;
      ctx.beginPath();
      ctx.moveTo(x(0), base);
      for (let i = 0; i < n; i++) ctx.lineTo(x(i), y(row.values[i]));
      ctx.lineTo(x(n - 1), base);
      ctx.closePath();
      ctx.fillStyle = withAlpha(color, 0.18);
      ctx.fill();
      ctx.beginPath();
      for (let i = 0; i < n; i++) (i ? ctx.lineTo : ctx.moveTo).call(ctx, x(i), y(row.values[i]));
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5;
      ctx.stroke();
    });
    if (this.hover >= 0) {
      const xh = Math.round(this.xOf(this.t0[this.hover] + this.w / 2, g)) + 0.5;
      ctx.strokeStyle = P.ink3;
      ctx.beginPath();
      ctx.moveTo(xh, g.pad.t);
      ctx.lineTo(xh, g.H);
      ctx.stroke();
      this.tip.innerHTML = this.rows
        .map((r) => `<div class="tooltip-row"><span class="tooltip-key"><i style="--c:var(--series-${(r.slot ?? 0) + 1})"></i>${r.label}</span><b>${fmtPct(r.values[this.hover])}</b></div>`)
        .join('');
      this.tip.classList.add('is-visible');
      positionTooltip(this.tip, this.root, xh, 20);
    } else this.tip.classList.remove('is-visible');
  }

  setHover(i, emit = false) {
    if (i === this.hover) return;
    this.hover = i;
    this.draw();
    if (emit) this.onHover?.(i);
  }

  destroy() {
    this.unobserve();
    this.untheme();
    this.root.remove();
  }
}
