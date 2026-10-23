// Небольшие графические элементы на SVG/HTML: индикатор риска, полосы,
// матрица ошибок, ROC-кривая.

import { LEVELS, levelOf } from '../../core/score.js';
import { html, raw, reducedMotion } from '../dom.js';
import { fmtPct, fmt2 } from '../format.js';
import { LEVEL_ICON, icon } from '../icons.js';
import { positionTooltip } from './base.js';

const LEVEL_VAR = { low: '--good', medium: '--warning', high: '--serious', critical: '--critical' };

// Полукруглый индикатор 0–100 с делениями на границах уровней.
export function gauge(value, { caption = '' } = {}) {
  const lvl = levelOf(value);
  const R = 100;
  const cx = 120;
  const cy = 118;
  const len = Math.PI * R;
  const arc = `M ${cx - R} ${cy} A ${R} ${R} 0 0 1 ${cx + R} ${cy}`;
  const ticks = [25, 50, 75]
    .map((v) => {
      const a = Math.PI * (1 - v / 100);
      const x1 = cx + Math.cos(a) * (R - 9);
      const y1 = cy - Math.sin(a) * (R - 9);
      const x2 = cx + Math.cos(a) * (R + 9);
      const y2 = cy - Math.sin(a) * (R + 9);
      const lx = cx + Math.cos(a) * (R + 22);
      const ly = cy - Math.sin(a) * (R + 22);
      return `<line class="gauge-tick" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}"/><text class="gauge-tick-label" x="${lx}" y="${ly}" text-anchor="middle" dominant-baseline="middle">${v}</text>`;
    })
    .join('');
  const offset = len * (1 - Math.min(100, Math.max(0, value)) / 100);
  return html`<div class="gauge" data-gauge="${offset}">
    <svg viewBox="0 -14 240 140" role="img" aria-label="Риск ${Math.round(value)} из 100, уровень ${lvl.name}">
      <path class="gauge-track" d="${arc}" />
      <path class="gauge-fill" d="${arc}" stroke="var(${LEVEL_VAR[lvl.id]})" stroke-dasharray="${len}" stroke-dashoffset="${len}" />
      ${raw(ticks)}
    </svg>
    <div class="gauge-center">
      <div class="gauge-value" data-count="${value}">${Math.round(value)}</div>
      <div class="gauge-caption">${levelBadge(lvl.id)} ${caption ? html`<span class="muted">${caption}</span>` : ''}</div>
    </div>
  </div>`;
}

// Запуск анимации индикаторов после вставки разметки в документ.
export function animateGauges(root) {
  for (const g of root.querySelectorAll('[data-gauge]')) {
    const fill = g.querySelector('.gauge-fill');
    const target = g.dataset.gauge;
    if (reducedMotion()) fill.style.strokeDashoffset = target;
    else requestAnimationFrame(() => requestAnimationFrame(() => (fill.style.strokeDashoffset = target)));
  }
}

export function levelBadge(levelId, text) {
  const lvl = LEVELS.find((l) => l.id === levelId) || LEVELS[0];
  return html`<span class="badge lvl-${lvl.id}">${icon(LEVEL_ICON[lvl.id], 14)}${text ?? lvl.name}</span>`;
}

// Горизонтальные полосы с подписанными значениями (всегда видимы — без подсказок).
export function barList(items, { slot = 1 } = {}) {
  const max = Math.max(1e-9, ...items.map((i) => i.value));
  return html`<ul class="bars">
    ${items.map(
      (it) => html`<li class="bar-row">
        <span class="bar-label" title="${it.label}">${it.label}</span>
        <span class="bar-track"><span class="bar-fill" style="--v:${(it.value / max).toFixed(4)};--c:var(--series-${it.slot ?? slot})"></span></span>
        <span class="bar-value">${it.display}</span>
      </li>`,
    )}
  </ul>`;
}

export function meters(items) {
  return items.map(
    (m) => html`<div class="meter">
      <span>${m.label}</span>
      <span class="meter-track" role="meter" aria-label="${m.label}" aria-valuemin="0" aria-valuemax="1" aria-valuenow="${m.value.toFixed(2)}"><span class="meter-fill" style="--v:${Math.min(1, Math.max(0, m.value)).toFixed(3)};--m:var(--series-${m.slot ?? 1})"></span></span>
      <span class="meter-value">${m.display ?? fmtPct(m.value)}</span>
    </div>`,
  );
}

export function confusionMatrix(m) {
  const total = Math.max(1, m.tp + m.fp + m.tn + m.fn);
  const cell = (v, label) => {
    const k = v / total;
    return html`<div class="matrix-cell ${k > 0.45 ? 'is-dark' : ''}" style="--v:${k.toFixed(3)}"><b>${v}</b><small>${label}</small></div>`;
  };
  return html`<div class="matrix" role="table" aria-label="Матрица ошибок по окнам">
    <div class="matrix-axis"></div>
    <div class="matrix-axis">Тревога</div>
    <div class="matrix-axis">Нет тревоги</div>
    <div class="matrix-axis">Атака</div>
    ${cell(m.tp, 'верно обнаружено')} ${cell(m.fn, 'пропущено')}
    <div class="matrix-axis">Норма</div>
    ${cell(m.fp, 'ложная тревога')} ${cell(m.tn, 'верно спокойно')}
  </div>`;
}

// ROC-кривые нескольких вариантов на одной оси (обе шкалы 0…1).
export function rocChart(container, series, { height = 300 } = {}) {
  const W = 420;
  const H = height;
  const pad = { l: 44, r: 12, t: 12, b: 40 };
  const iw = W - pad.l - pad.r;
  const ih = H - pad.t - pad.b;
  const X = (v) => pad.l + v * iw;
  const Y = (v) => pad.t + (1 - v) * ih;
  const grid = [0, 0.25, 0.5, 0.75, 1]
    .map((v) => `<line x1="${X(0)}" x2="${X(1)}" y1="${Y(v)}" y2="${Y(v)}" stroke="var(--grid)"/><text x="${X(0) - 8}" y="${Y(v)}" text-anchor="end" dominant-baseline="middle" class="gauge-tick-label">${v}</text>
      <line x1="${X(v)}" x2="${X(v)}" y1="${Y(0)}" y2="${Y(1)}" stroke="var(--grid)"/><text x="${X(v)}" y="${Y(0) + 16}" text-anchor="middle" class="gauge-tick-label">${v}</text>`)
    .join('');
  const visible = series.filter((s) => !s.hidden && s.points?.length);
  const lines = visible
    .map((s) => `<polyline fill="none" stroke="var(--series-${s.slot})" stroke-width="2" stroke-linejoin="round" points="${s.points.map((p) => `${X(p.fpr).toFixed(1)},${Y(p.tpr).toFixed(1)}`).join(' ')}"/>`)
    .join('');
  container.innerHTML = `<div class="chart"><svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="ROC-кривые: ${visible.map((s) => `${s.name}, AUC ${fmt2(s.auc)}`).join('; ')}">
    ${grid}
    <line x1="${X(0)}" y1="${Y(0)}" x2="${X(1)}" y2="${Y(1)}" stroke="var(--axis)"/>
    ${lines}
    <circle class="roc-dot" r="4.5" fill="var(--ink)" stroke="var(--surface)" stroke-width="2" style="display:none"/>
    <text x="${X(0.5)}" y="${H - 6}" text-anchor="middle" class="gauge-tick-label">Доля ложных срабатываний (FPR)</text>
    <text x="12" y="${Y(0.5)}" text-anchor="middle" class="gauge-tick-label" transform="rotate(-90 12 ${Y(0.5)})">Полнота (TPR)</text>
  </svg><div class="tooltip"></div></div>`;
  const svg = container.querySelector('svg');
  const dot = svg.querySelector('.roc-dot');
  const tip = container.querySelector('.tooltip');
  const root = container.querySelector('.chart');
  svg.addEventListener('pointermove', (e) => {
    const r = svg.getBoundingClientRect();
    const k = W / r.width;
    const px = (e.clientX - r.left) * k;
    const py = (e.clientY - r.top) * k;
    let best = null;
    for (const s of visible) {
      for (const p of s.points) {
        const d = (X(p.fpr) - px) ** 2 + (Y(p.tpr) - py) ** 2;
        if (!best || d < best.d) best = { d, p, s };
      }
    }
    if (!best || best.d > 900) {
      dot.style.display = 'none';
      tip.classList.remove('is-visible');
      return;
    }
    dot.style.display = '';
    dot.setAttribute('cx', X(best.p.fpr));
    dot.setAttribute('cy', Y(best.p.tpr));
    dot.setAttribute('fill', `var(--series-${best.s.slot})`);
    const thr = Number.isFinite(best.p.thr) ? fmt2(best.p.thr) : '—';
    tip.innerHTML = `<div class="tooltip-title">${best.s.name}</div>
      <div class="tooltip-row"><span>Порог</span><b>${thr}</b></div>
      <div class="tooltip-row"><span>Полнота (TPR)</span><b>${fmtPct(best.p.tpr, 1)}</b></div>
      <div class="tooltip-row"><span>Ложные (FPR)</span><b>${fmtPct(best.p.fpr, 1)}</b></div>`;
    tip.classList.add('is-visible');
    positionTooltip(tip, root, X(best.p.fpr) / k, Y(best.p.tpr) / k);
  });
  svg.addEventListener('pointerleave', () => {
    dot.style.display = 'none';
    tip.classList.remove('is-visible');
  });
}
