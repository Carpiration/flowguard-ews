// Временная шкала: две панели с общей осью времени (интенсивность трафика и
// оценка риска 0–100), полоса состояний модели, отметки инцидентов и разметка атак.

import { reducedMotion } from '../dom.js';
import { fmtAxis, fmtClock, fmt1 } from '../format.js';
import { onThemeChange } from '../theme.js';
import { STATUS_BY_SEV, niceMax, niceStep, observeSize, palette, positionTooltip, setupCanvas, timeTicks, withAlpha } from './base.js';

const STATE_NAMES = ['Норма', 'Предупреждение', 'Тревога'];

export class TimelineChart {
  constructor(container, opts = {}) {
    this.opts = { height: 320, tau: 50, absolute: false, origin: 0, w: 1, animate: true, label: 'Временная шкала трафика и риска', ...opts };
    this.data = null;
    this.hover = -1;
    this.selected = -1;
    this.progress = 1;
    this.root = document.createElement('div');
    this.root.className = 'chart';
    this.root.tabIndex = 0;
    this.root.setAttribute('role', 'group');
    this.root.setAttribute('aria-roledescription', 'интерактивный график');
    this.root.setAttribute('aria-label', `${this.opts.label}. Стрелки влево и вправо — перемещение по окнам, Enter — подробности окна.`);
    this.canvas = document.createElement('canvas');
    this.canvas.setAttribute('aria-hidden', 'true');
    this.tip = document.createElement('div');
    this.tip.className = 'tooltip';
    this.live = document.createElement('div');
    this.live.className = 'sr-only';
    this.live.setAttribute('aria-live', 'polite');
    this.root.append(this.canvas, this.tip, this.live);
    container.append(this.root);
    this.width = container.clientWidth || 600;
    this.unobserve = observeSize(this.root, (w) => {
      this.width = w;
      this.draw();
    });
    this.untheme = onThemeChange(() => this.draw());
    this.bind();
  }

  setData(data, { animate = false } = {}) {
    this.data = data;
    if (this.hover >= data.t0.length) this.hover = -1;
    if (animate && this.opts.animate && !reducedMotion()) this.reveal();
    else {
      this.progress = 1;
      this.draw();
    }
  }

  reveal() {
    const start = performance.now();
    const dur = 900;
    cancelAnimationFrame(this.anim);
    const step = (now) => {
      const k = Math.min(1, (now - start) / dur);
      this.progress = 1 - Math.pow(1 - k, 3);
      this.draw();
      if (k < 1) this.anim = requestAnimationFrame(step);
    };
    this.progress = 0;
    this.anim = requestAnimationFrame(step);
  }

  layout() {
    const H = this.opts.height;
    const pad = { l: 52, r: 14, t: 12, b: 28 };
    const inner = H - pad.t - pad.b;
    const trafficH = Math.round((inner - 40) * 0.36);
    const riskTop = pad.t + trafficH + 22;
    const stripH = 6;
    const riskH = H - pad.b - riskTop - stripH - 10;
    return { H, pad, trafficH, riskTop, riskH, stripTop: riskTop + riskH + 8, stripH, iw: Math.max(10, this.width - pad.l - pad.r) };
  }

  xOf(t, L) {
    const d = this.data;
    const T0 = d.t0[0];
    const T1 = d.t0[d.t0.length - 1] + this.opts.w;
    return L.pad.l + ((t - T0) / Math.max(1e-9, T1 - T0)) * L.iw;
  }

  indexAt(px, L) {
    const d = this.data;
    const n = d.t0.length;
    if (!n) return -1;
    const T0 = d.t0[0];
    const T1 = d.t0[n - 1] + this.opts.w;
    const t = T0 + ((px - L.pad.l) / L.iw) * (T1 - T0);
    return Math.max(0, Math.min(n - 1, Math.floor((t - T0) / this.opts.w)));
  }

  draw() {
    const d = this.data;
    if (!d || !this.width) return;
    const L = this.layout();
    const ctx = setupCanvas(this.canvas, this.width, L.H);
    const P = palette();
    const n = d.t0.length;
    const w = this.opts.w;
    const { pad, iw } = L;
    ctx.clearRect(0, 0, this.width, L.H);
    ctx.font = `11px ${P.mono}`;
    ctx.textBaseline = 'middle';
    if (!n) {
      ctx.fillStyle = P.ink3;
      ctx.fillText('Нет данных', pad.l, L.H / 2);
      return;
    }
    const cx = (i) => this.xOf(d.t0[i] + w / 2, L);
    const right = pad.l + iw;

    // Разметка атак (если есть).
    if (d.attack) {
      ctx.fillStyle = withAlpha(P.ink, 0.07);
      for (let i = 0; i < n; i++) {
        if (!d.attack[i]) continue;
        let j = i;
        while (j + 1 < n && d.attack[j + 1]) j++;
        const x0 = this.xOf(d.t0[i], L);
        const x1 = this.xOf(d.t0[j] + w, L);
        ctx.fillRect(x0, pad.t, x1 - x0, L.trafficH);
        ctx.fillRect(x0, L.riskTop, x1 - x0, L.riskH);
        i = j;
      }
    }
    if (this.selected >= 0 && this.selected < n) {
      const x0 = this.xOf(d.t0[this.selected], L);
      ctx.fillStyle = withAlpha(P.accent, 0.14);
      ctx.fillRect(x0, pad.t, Math.max(2, this.xOf(d.t0[this.selected] + w, L) - x0), L.stripTop + L.stripH - pad.t);
    }

    // Панель трафика.
    const rate = d.pkts.map((p) => p / w);
    const ymax = niceMax(Math.max(1, ...rate), 3);
    const ystep = niceStep(ymax, 3);
    const yT = (v) => pad.t + L.trafficH - (v / ymax) * L.trafficH;
    ctx.strokeStyle = P.grid;
    ctx.lineWidth = 1;
    ctx.fillStyle = P.ink3;
    ctx.textAlign = 'right';
    for (let v = 0; v <= ymax + 1e-9; v += ystep) {
      const y = Math.round(yT(v)) + 0.5;
      ctx.beginPath();
      ctx.moveTo(pad.l, y);
      ctx.lineTo(right, y);
      ctx.stroke();
      ctx.fillText(fmtAxis(v), pad.l - 8, y);
    }
    ctx.textAlign = 'left';
    ctx.fillText('пакетов/с', pad.l + 4, pad.t + 2);

    ctx.save();
    ctx.beginPath();
    ctx.rect(pad.l, 0, iw * this.progress, L.H);
    ctx.clip();
    const series = P.series[0];
    ctx.beginPath();
    for (let i = 0; i < n; i++) (i ? ctx.lineTo : ctx.moveTo).call(ctx, cx(i), yT(rate[i]));
    ctx.lineTo(cx(n - 1), yT(0));
    ctx.lineTo(cx(0), yT(0));
    ctx.closePath();
    ctx.fillStyle = withAlpha(series, 0.12);
    ctx.fill();
    ctx.beginPath();
    for (let i = 0; i < n; i++) (i ? ctx.lineTo : ctx.moveTo).call(ctx, cx(i), yT(rate[i]));
    ctx.strokeStyle = series;
    ctx.lineWidth = n > 600 ? 1.25 : 2;
    ctx.lineJoin = 'round';
    ctx.stroke();
    ctx.restore();

    // Панель риска.
    const yR = (v) => L.riskTop + L.riskH - (v / 100) * L.riskH;
    ctx.fillStyle = P.ink3;
    ctx.textAlign = 'right';
    for (const v of [0, 25, 50, 75, 100]) {
      const y = Math.round(yR(v)) + 0.5;
      ctx.strokeStyle = P.grid;
      ctx.beginPath();
      ctx.moveTo(pad.l, y);
      ctx.lineTo(right, y);
      ctx.stroke();
      ctx.fillText(String(v), pad.l - 8, y);
    }
    ctx.textAlign = 'left';
    ctx.fillText('риск', pad.l + 4, L.riskTop - 8);
    const yt = Math.round(yR(this.opts.tau)) + 0.5;
    ctx.strokeStyle = P.critical;
    ctx.beginPath();
    ctx.moveTo(pad.l, yt);
    ctx.lineTo(right, yt);
    ctx.stroke();
    ctx.fillStyle = P.ink2;
    ctx.textAlign = 'right';
    ctx.fillText(`порог тревоги ${this.opts.tau}`, right - 4, yt - 8);

    ctx.save();
    ctx.beginPath();
    ctx.rect(pad.l, 0, iw * this.progress, L.H);
    ctx.clip();
    ctx.beginPath();
    for (let i = 0; i < n; i++) (i ? ctx.lineTo : ctx.moveTo).call(ctx, cx(i), yR(d.risk[i]));
    ctx.lineTo(cx(n - 1), yR(0));
    ctx.lineTo(cx(0), yR(0));
    ctx.closePath();
    ctx.fillStyle = withAlpha(P.ink, 0.06);
    ctx.fill();
    for (const cmp of d.compare || []) {
      if (cmp.hidden) continue;
      ctx.beginPath();
      for (let i = 0; i < n; i++) (i ? ctx.lineTo : ctx.moveTo).call(ctx, cx(i), yR(cmp.values[i]));
      ctx.strokeStyle = P.series[cmp.slot ?? 1];
      ctx.lineWidth = 2;
      ctx.stroke();
    }
    ctx.beginPath();
    for (let i = 0; i < n; i++) (i ? ctx.lineTo : ctx.moveTo).call(ctx, cx(i), yR(d.risk[i]));
    ctx.strokeStyle = P.ink;
    ctx.lineWidth = n > 600 ? 1.5 : 2;
    ctx.stroke();

    // Полоса состояний модели.
    for (let i = 0; i < n; i++) {
      const s = d.state[i];
      ctx.fillStyle = s === 2 ? P.critical : s === 1 ? P.warning : P.surface3;
      const x0 = this.xOf(d.t0[i], L);
      const x1 = this.xOf(d.t0[i] + w, L);
      ctx.fillRect(x0, L.stripTop, Math.max(1, x1 - x0 + 0.5), L.stripH);
    }

    // Отметки инцидентов в момент обнаружения.
    for (const m of d.markers || []) {
      const x = this.xOf(m.t, L);
      if (x < pad.l || x > right) continue;
      const y = L.riskTop + 6;
      ctx.beginPath();
      ctx.arc(x, y, 5, 0, Math.PI * 2);
      ctx.fillStyle = P.surface;
      ctx.fill();
      ctx.beginPath();
      ctx.arc(x, y, 3.5, 0, Math.PI * 2);
      ctx.fillStyle = P[STATUS_BY_SEV[m.sev]] || P.ink2;
      ctx.fill();
    }
    ctx.restore();

    // Ось времени.
    const T0 = d.t0[0];
    const T1 = d.t0[n - 1] + w;
    const ticks = timeTicks(T0, T1, Math.max(2, Math.floor(iw / 110)));
    ctx.fillStyle = P.ink3;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.strokeStyle = P.axis;
    for (const t of ticks) {
      const x = Math.round(this.xOf(t, L)) + 0.5;
      ctx.beginPath();
      ctx.moveTo(x, L.stripTop + L.stripH + 2);
      ctx.lineTo(x, L.stripTop + L.stripH + 6);
      ctx.stroke();
      const label = fmtClock(t, this.opts.absolute, this.opts.origin);
      const half = ctx.measureText(label).width / 2;
      const lx = Math.min(this.width - half - 2, Math.max(half + 2, x));
      ctx.fillText(label, lx, L.stripTop + L.stripH + 9);
    }

    // Перекрестие наведения.
    if (this.hover >= 0 && this.hover < n) {
      const i = this.hover;
      const x = Math.round(cx(i)) + 0.5;
      ctx.strokeStyle = P.ink3;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(x, pad.t);
      ctx.lineTo(x, L.stripTop + L.stripH);
      ctx.stroke();
      const dot = (y, c) => {
        ctx.beginPath();
        ctx.arc(x, y, 6, 0, Math.PI * 2);
        ctx.fillStyle = P.surface;
        ctx.fill();
        ctx.beginPath();
        ctx.arc(x, y, 4, 0, Math.PI * 2);
        ctx.fillStyle = c;
        ctx.fill();
      };
      dot(yT(rate[i]), series);
      dot(yR(d.risk[i]), P.ink);
      this.showTip(i, x, Math.min(yR(d.risk[i]), yT(rate[i])));
    } else {
      this.tip.classList.remove('is-visible');
    }
  }

  showTip(i, x, y) {
    const d = this.data;
    const w = this.opts.w;
    const custom = this.opts.tooltip?.(i);
    this.tip.innerHTML =
      custom ??
      `<div class="tooltip-title">${fmtClock(d.t0[i], this.opts.absolute, this.opts.origin)} — ${fmtClock(d.t0[i] + w, this.opts.absolute, this.opts.origin)}</div>
      <div class="tooltip-row"><span>Пакетов/с</span><b>${fmt1(d.pkts[i] / w)}</b></div>
      <div class="tooltip-row"><span>Риск</span><b>${fmt1(d.risk[i])}</b></div>
      <div class="tooltip-row"><span>Состояние</span><b>${STATE_NAMES[d.state[i]]}</b></div>`;
    this.tip.classList.add('is-visible');
    positionTooltip(this.tip, this.root, x, y);
  }

  setHover(i, { silent = false } = {}) {
    if (i === this.hover) return;
    this.hover = i;
    this.draw();
    if (!silent) this.opts.onHover?.(i);
  }

  select(i, { focus = false } = {}) {
    this.selected = i;
    this.draw();
    if (focus) this.root.focus();
  }

  announce(i) {
    const d = this.data;
    if (!d || i < 0) return;
    this.live.textContent = `Окно ${fmtClock(d.t0[i], this.opts.absolute, this.opts.origin)}: риск ${Math.round(d.risk[i])}, ${STATE_NAMES[d.state[i]]}, ${fmt1(d.pkts[i] / this.opts.w)} пакетов в секунду.`;
  }

  bind() {
    const local = (e) => {
      const r = this.canvas.getBoundingClientRect();
      return e.clientX - r.left;
    };
    this.canvas.addEventListener('pointermove', (e) => {
      if (!this.data) return;
      this.setHover(this.indexAt(local(e), this.layout()));
    });
    this.canvas.addEventListener('pointerleave', () => this.setHover(-1));
    this.canvas.addEventListener('click', (e) => {
      if (!this.data) return;
      const i = this.indexAt(local(e), this.layout());
      this.select(i);
      this.opts.onSelect?.(i);
    });
    this.root.addEventListener('keydown', (e) => {
      if (!this.data) return;
      const n = this.data.t0.length;
      let i = this.hover >= 0 ? this.hover : this.selected >= 0 ? this.selected : n - 1;
      if (e.key === 'ArrowRight') i = Math.min(n - 1, i + (e.shiftKey ? 10 : 1));
      else if (e.key === 'ArrowLeft') i = Math.max(0, i - (e.shiftKey ? 10 : 1));
      else if (e.key === 'Home') i = 0;
      else if (e.key === 'End') i = n - 1;
      else if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        this.select(i);
        this.opts.onSelect?.(i);
        return;
      } else if (e.key === 'Escape') {
        this.setHover(-1);
        return;
      } else return;
      e.preventDefault();
      this.setHover(i);
      this.announce(i);
    });
    this.root.addEventListener('blur', () => this.setHover(-1));
  }

  destroy() {
    cancelAnimationFrame(this.anim);
    this.unobserve();
    this.untheme();
    this.root.remove();
  }
}
