// Иллюстрация главной страницы: потоки пакетов, в одном из которых нарастает
// аномалия; модель выдаёт раннее предупреждение, затем тревогу.
// Останавливается вне экрана и в скрытой вкладке; при уменьшенном движении —
// статичный кадр.

import { reducedMotion } from '../dom.js';
import { onThemeChange } from '../theme.js';
import { palette, roundRect, setupCanvas, withAlpha } from './base.js';

const STORY = [
  { warn: 'CUSUM: накопление сдвига', alarm: 'Тревога: сканирование портов' },
  { warn: 'EWMA-z: рост исходящего объёма', alarm: 'Тревога: утечка данных' },
  { warn: 'Сигнатура: длинные DNS-имена', alarm: 'Тревога: DNS-туннель' },
  { warn: 'CUSUM: рост числа SYN', alarm: 'Тревога: SYN-флуд' },
];
const CYCLE = 11;

export class HeroField {
  constructor(canvas) {
    this.canvas = canvas;
    this.lanes = 9;
    this.parts = [];
    this.t = 0;
    this.cycle = 0;
    this.active = 3;
    this.running = false;
    this.visible = true;
    this.last = 0;
    this.seed = 7;
    this.resize();
    this.ro = new ResizeObserver(() => this.resize());
    this.ro.observe(canvas);
    this.io = new IntersectionObserver(([e]) => {
      this.visible = e.isIntersecting;
      this.sync();
    });
    this.io.observe(canvas);
    this.onVis = () => this.sync();
    document.addEventListener('visibilitychange', this.onVis);
    this.untheme = onThemeChange(() => this.colors());
    this.colors();
    // Потоки сразу заполнены частицами — первый кадр анимации не пустой.
    for (let i = 0; i < this.lanes; i++) {
      for (let k = 0; k < 7; k++) this.parts.push({ lane: i, x: this.rand() * this.w, v: 70 + this.rand() * 60, len: 8 + this.rand() * 10, hot: 0 });
    }
    this.sync();
  }

  rand() {
    this.seed = (this.seed * 16807) % 2147483647;
    return this.seed / 2147483647;
  }

  colors() {
    this.P = palette();
    if (!this.running) this.drawStatic();
  }

  resize() {
    this.w = this.canvas.clientWidth || 800;
    this.h = this.canvas.clientHeight || 230;
    this.ctx = setupCanvas(this.canvas, this.w, this.h);
    if (!this.running) this.drawStatic();
  }

  sync() {
    const should = this.visible && !document.hidden && !reducedMotion();
    if (should && !this.running) {
      this.running = true;
      this.last = performance.now();
      const loop = (now) => {
        if (!this.running) return;
        const dt = Math.min(0.05, (now - this.last) / 1000);
        this.last = now;
        this.step(dt);
        this.draw();
        this.raf = requestAnimationFrame(loop);
      };
      this.raf = requestAnimationFrame(loop);
    } else if (!should && this.running) {
      this.running = false;
      cancelAnimationFrame(this.raf);
    }
    if (!should) this.drawStatic();
  }

  laneY(i) {
    const top = 46;
    const usable = this.h - top - 18;
    return top + (usable / (this.lanes - 1)) * i;
  }

  // Фаза сценария: 0 — норма, 0..1 — нарастание аномалии.
  phase() {
    const c = this.t % CYCLE;
    if (c < 2) return { ramp: 0, warn: false, alarm: false, fade: 1 };
    if (c < 9) {
      const ramp = (c - 2) / 7;
      return { ramp, warn: ramp > 0.22, alarm: ramp > 0.62, fade: 1 };
    }
    return { ramp: 1, warn: true, alarm: true, fade: 1 - (c - 9) / 2 };
  }

  step(dt) {
    const prevCycle = Math.floor(this.t / CYCLE);
    this.t += dt;
    const cyc = Math.floor(this.t / CYCLE);
    if (cyc !== prevCycle) {
      this.cycle = (this.cycle + 1) % STORY.length;
      this.active = 1 + Math.floor(this.rand() * (this.lanes - 2));
    }
    const ph = this.phase();
    for (let i = 0; i < this.lanes; i++) {
      const hot = i === this.active ? ph.ramp * ph.fade : 0;
      const rate = 1.4 + hot * 16;
      if (this.rand() < rate * dt) {
        this.parts.push({ lane: i, x: -20, v: 70 + this.rand() * 60 + hot * 60, len: 8 + this.rand() * 10, hot });
      }
    }
    for (const p of this.parts) p.x += p.v * dt;
    this.parts = this.parts.filter((p) => p.x < this.w + 30);
  }

  drawFrame(ph, parts) {
    const { ctx, w, h } = this;
    const P = this.P;
    ctx.clearRect(0, 0, w, h);
    ctx.lineCap = 'round';
    for (let i = 0; i < this.lanes; i++) {
      const y = Math.round(this.laneY(i)) + 0.5;
      ctx.strokeStyle = withAlpha(P.ink, 0.06);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }
    for (const p of parts) {
      const y = this.laneY(p.lane);
      const hot = p.lane === this.active ? ph.ramp * ph.fade : 0;
      let color = withAlpha(P.ink2, 0.55);
      if (hot > 0.62) color = P.critical;
      else if (hot > 0.22) color = P.warning;
      else if (hot > 0.05) color = withAlpha(P.ink2, 0.8);
      ctx.strokeStyle = color;
      ctx.lineWidth = 2.5;
      ctx.beginPath();
      ctx.moveTo(p.x, y);
      ctx.lineTo(p.x + p.len, y);
      ctx.stroke();
    }
    const story = STORY[this.cycle];
    const y = this.laneY(this.active);
    const x = Math.round(w * 0.64);
    ctx.font = `600 11.5px ${P.mono}`;
    ctx.textBaseline = 'middle';
    const tag = (text, color, yy, alpha) => {
      ctx.globalAlpha = alpha;
      const tw = ctx.measureText(text).width + 18;
      const tx = Math.min(w - tw - 10, x + 14);
      roundRect(ctx, tx, yy - 11, tw, 22, 5);
      ctx.fillStyle = P.surface;
      ctx.fill();
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.fillStyle = P.ink;
      ctx.fillText(text, tx + 9, yy + 0.5);
      ctx.globalAlpha = 1;
    };
    if (ph.warn) {
      const a = ph.fade;
      ctx.globalAlpha = a;
      ctx.strokeStyle = ph.alarm ? P.critical : P.warning;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(x, 34);
      ctx.lineTo(x, h - 10);
      ctx.stroke();
      ctx.beginPath();
      ctx.arc(x, y, ph.alarm ? 9 : 6, 0, Math.PI * 2);
      ctx.stroke();
      ctx.globalAlpha = 1;
      tag(story.warn, P.warning, Math.max(46, y - 30), a * (ph.alarm ? 0.55 : 1));
      if (ph.alarm) tag(story.alarm, P.critical, Math.min(h - 18, y + 30), a);
    }
  }

  draw() {
    this.drawFrame(this.phase(), this.parts);
  }

  drawStatic() {
    if (!this.ctx || !this.P) return;
    const parts = [];
    let s = 3;
    const r = () => {
      s = (s * 16807) % 2147483647;
      return s / 2147483647;
    };
    for (let i = 0; i < this.lanes; i++) {
      const count = i === this.active ? 26 : 6;
      for (let k = 0; k < count; k++) parts.push({ lane: i, x: r() * this.w, len: 8 + r() * 10 });
    }
    this.drawFrame({ ramp: 0.8, warn: true, alarm: true, fade: 1 }, parts);
  }

  destroy() {
    this.running = false;
    cancelAnimationFrame(this.raf);
    this.ro.disconnect();
    this.io.disconnect();
    document.removeEventListener('visibilitychange', this.onVis);
    this.untheme();
  }
}
