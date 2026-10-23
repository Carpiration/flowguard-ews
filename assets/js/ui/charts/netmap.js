// Карта взаимодействий узлов для мониторинга: серверы в центре, рабочие станции
// на среднем кольце, внешние адреса — на внешнем. Пакеты показаны движущимися
// точками; узлы из недавних инцидентов подсвечены цветом важности.

import { reducedMotion } from '../dom.js';
import { onThemeChange } from '../theme.js';
import { STATUS_BY_SEV, observeSize, palette, positionTooltip, setupCanvas, withAlpha } from './base.js';

const MAX_EXTERNAL = 36;

export class NetMap {
  constructor(container, { height = 360 } = {}) {
    this.height = height;
    this.root = document.createElement('div');
    this.root.className = 'chart netmap';
    this.canvas = document.createElement('canvas');
    this.canvas.setAttribute('role', 'img');
    this.canvas.setAttribute('aria-label', 'Карта взаимодействий узлов сети в последнем окне');
    this.tip = document.createElement('div');
    this.tip.className = 'tooltip';
    this.root.append(this.canvas, this.tip);
    container.append(this.root);
    this.width = container.clientWidth || 600;
    this.nodes = new Map();
    this.edges = [];
    this.dots = [];
    this.hot = new Map();
    this.hover = null;
    this.unobserve = observeSize(this.root, (w) => {
      this.width = w;
      this.layout();
      this.draw();
    });
    this.untheme = onThemeChange(() => this.draw());
    this.canvas.addEventListener('pointermove', (e) => this.onMove(e));
    this.canvas.addEventListener('pointerleave', () => {
      this.hover = null;
      this.tip.classList.remove('is-visible');
    });
    this.last = performance.now();
    const loop = (now) => {
      const dt = Math.min(0.05, (now - this.last) / 1000);
      this.last = now;
      if (!document.hidden) {
        this.step(dt);
        this.draw();
      }
      this.raf = requestAnimationFrame(loop);
    };
    this.raf = requestAnimationFrame(loop);
  }

  // hosts: HostTable, pairs: [{s,d,pk,by}], hot: Map(id → важность)
  update(hosts, pairs, hot) {
    this.hosts = hosts;
    this.hot = hot;
    const ext = new Map();
    for (const p of pairs) {
      for (const id of [p.s, p.d]) {
        if (!hosts.internal[id]) ext.set(id, (ext.get(id) || 0) + p.pk);
      }
    }
    const keepExt = new Set([...ext.entries()].sort((a, b) => b[1] - a[1]).slice(0, MAX_EXTERNAL).map(([id]) => id));
    for (const id of hot.keys()) if (!hosts.internal[id]) keepExt.add(id);
    const visible = new Set();
    for (const p of pairs) {
      for (const id of [p.s, p.d]) if (hosts.internal[id] || keepExt.has(id)) visible.add(id);
    }
    for (const id of visible) {
      if (!this.nodes.has(id)) this.nodes.set(id, { id, x: this.width / 2, y: this.height / 2, tx: 0, ty: 0, pk: 0, seen: 0 });
    }
    for (const n of this.nodes.values()) {
      n.pk = 0;
      n.seen = visible.has(n.id) ? 4 : n.seen - 1;
    }
    for (const [id, n] of this.nodes) if (n.seen <= 0 && !hosts.internal[id]) this.nodes.delete(id);
    this.edges = pairs.filter((p) => this.nodes.has(p.s) && this.nodes.has(p.d));
    for (const e of this.edges) {
      this.nodes.get(e.s).pk += e.pk;
      this.nodes.get(e.d).pk += e.pk;
    }
    this.extOther = ext.size - [...ext.keys()].filter((id) => keepExt.has(id)).length;
    this.layout();
    if (!reducedMotion()) {
      for (const e of this.edges) {
        const count = Math.min(6, Math.ceil(Math.log2(1 + e.pk)));
        for (let k = 0; k < count; k++) this.dots.push({ e, p: -k * 0.18 - Math.random() * 0.2, v: 0.5 + Math.random() * 0.5 });
      }
      if (this.dots.length > 900) this.dots.splice(0, this.dots.length - 900);
    }
  }

  ring(id) {
    const name = this.hosts.name(id);
    if (!this.hosts.internal[id]) return 2;
    return /^10\.0\.0\./.test(name) || /\.(1|53)$/.test(name) ? 0 : 1;
  }

  layout() {
    if (!this.hosts) return;
    const cx = this.width / 2;
    const cy = this.height / 2 - 6;
    // Эллиптические кольца на всю площадь холста: серверы, рабочие станции, внешние узлы.
    const RX = Math.max(60, this.width / 2 - 56);
    const RY = Math.max(60, this.height / 2 - 34);
    const frac = [0.3, 0.64, 0.97];
    const groups = [[], [], []];
    for (const n of this.nodes.values()) groups[this.ring(n.id)].push(n);
    groups.forEach((g, k) => {
      g.sort((a, b) => this.hosts.name(a.id).localeCompare(this.hosts.name(b.id), 'en', { numeric: true }));
      g.forEach((n, i) => {
        const a = (i / Math.max(1, g.length)) * Math.PI * 2 - Math.PI / 2 + k * 0.35;
        const single = k === 0 && g.length === 1;
        n.tx = cx + (single ? 0 : Math.cos(a) * RX * frac[k]);
        n.ty = cy + (single ? 0 : Math.sin(a) * RY * frac[k]);
      });
    });
  }

  step(dt) {
    const k = reducedMotion() ? 1 : Math.min(1, dt * 6);
    for (const n of this.nodes.values()) {
      n.x += (n.tx - n.x) * k;
      n.y += (n.ty - n.y) * k;
    }
    for (const d of this.dots) d.p += d.v * dt * 1.4;
    this.dots = this.dots.filter((d) => d.p < 1);
  }

  draw() {
    if (!this.width) return;
    const ctx = setupCanvas(this.canvas, this.width, this.height);
    const P = palette();
    ctx.clearRect(0, 0, this.width, this.height);
    if (!this.hosts || !this.nodes.size) {
      ctx.fillStyle = P.ink3;
      ctx.font = `13px ${P.font}`;
      ctx.textAlign = 'center';
      ctx.fillText('Запустите мониторинг, чтобы увидеть взаимодействия узлов', this.width / 2, this.height / 2);
      return;
    }
    const maxPk = Math.max(1, ...this.edges.map((e) => e.pk));
    for (const e of this.edges) {
      const a = this.nodes.get(e.s);
      const b = this.nodes.get(e.d);
      const sev = Math.max(this.hot.get(e.s) || 0, this.hot.get(e.d) || 0);
      const hotEdge = sev >= 2 && this.hot.has(e.s) && this.hot.has(e.d);
      ctx.strokeStyle = hotEdge ? withAlpha(P[STATUS_BY_SEV[sev]], 0.55) : withAlpha(P.ink, 0.05 + 0.2 * Math.sqrt(e.pk / maxPk));
      ctx.lineWidth = hotEdge ? 1.5 : 1;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.stroke();
    }
    for (const d of this.dots) {
      if (d.p < 0) continue;
      const a = this.nodes.get(d.e.s);
      const b = this.nodes.get(d.e.d);
      if (!a || !b) continue;
      const sev = this.hot.get(d.e.s) || 0;
      ctx.fillStyle = sev >= 2 ? P[STATUS_BY_SEV[sev]] : P.series[0];
      ctx.beginPath();
      ctx.arc(a.x + (b.x - a.x) * d.p, a.y + (b.y - a.y) * d.p, 1.8, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.font = `10.5px ${P.mono}`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    for (const n of this.nodes.values()) {
      const ring = this.ring(n.id);
      const sev = this.hot.get(n.id) || 0;
      const r = ring === 0 ? 6 : 4 + Math.min(3, Math.log10(1 + n.pk));
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 2, 0, Math.PI * 2);
      ctx.fillStyle = P.surface;
      ctx.fill();
      ctx.beginPath();
      ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
      ctx.fillStyle = sev ? P[STATUS_BY_SEV[sev]] : ring === 2 ? P.ink3 : P.ink2;
      ctx.fill();
      if (sev >= 2) {
        ctx.strokeStyle = P[STATUS_BY_SEV[sev]];
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(n.x, n.y, r + 6, 0, Math.PI * 2);
        ctx.stroke();
      }
      if (ring === 0 || sev >= 2 || this.hover === n) {
        ctx.fillStyle = sev >= 2 ? P.ink : P.ink3;
        ctx.fillText(this.hosts.name(n.id), n.x, n.y + r + 6);
      }
    }
    ctx.textAlign = 'left';
    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = P.ink3;
    ctx.fillText(`внешние узлы${this.extOther > 0 ? ` (+${this.extOther} скрыто)` : ''}`, 10, this.height - 10);
  }

  onMove(e) {
    const r = this.canvas.getBoundingClientRect();
    const x = e.clientX - r.left;
    const y = e.clientY - r.top;
    let best = null;
    for (const n of this.nodes.values()) {
      const d = (n.x - x) ** 2 + (n.y - y) ** 2;
      if (d < 196 && (!best || d < best.d)) best = { n, d };
    }
    this.hover = best ? best.n : null;
    if (!best) {
      this.tip.classList.remove('is-visible');
      return;
    }
    const n = best.n;
    const sev = this.hot.get(n.id);
    this.tip.innerHTML = `<div class="tooltip-title">${this.hosts.name(n.id)}</div>
      <div class="tooltip-row"><span>Сеть</span><b>${this.hosts.internal[n.id] ? 'внутренняя' : 'внешняя'}</b></div>
      <div class="tooltip-row"><span>Пакетов в окне</span><b>${n.pk}</b></div>
      ${sev ? '<div class="tooltip-row"><span>Инцидент</span><b>участник</b></div>' : ''}`;
    this.tip.classList.add('is-visible');
    positionTooltip(this.tip, this.root, n.x, n.y);
  }

  destroy() {
    cancelAnimationFrame(this.raf);
    this.unobserve();
    this.untheme();
    this.root.remove();
  }
}
