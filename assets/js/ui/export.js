// Экспорт отчётов: JSON (полный), CSV (инциденты и временной ряд, UTF-8 с BOM
// и разделителем «;» для Excel в русской локали), автономный HTML и печать в PDF.

import { SEVERITY } from '../core/catalog.js';
import { FEATURES } from '../core/features.js';
import { LEVELS } from '../core/score.js';
import { esc } from './dom.js';
import { fmtBytes, fmtClock, fmtDateTime, fmtDuration, fmtInt, fmtPct } from './format.js';

export function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function slug(report) {
  const base = (report.source?.name || 'report').replace(/\.[a-z0-9]+$/i, '').replace(/[^\p{L}\p{N}]+/gu, '-').replace(/^-|-$/g, '').slice(0, 40) || 'report';
  const d = new Date(report.createdAt);
  const stamp = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}-${String(d.getHours()).padStart(2, '0')}${String(d.getMinutes()).padStart(2, '0')}`;
  return `flowguard-${base}-${stamp}`;
}

function csv(rows) {
  const cell = (v) => {
    if (v === null || v === undefined) return '';
    const s = typeof v === 'number' ? String(v).replace('.', ',') : String(v);
    return /[;"\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return `﻿${rows.map((r) => r.map(cell).join(';')).join('\r\n')}\r\n`;
}

const isoTime = (t, abs) => (abs ? new Date(t * 1000).toISOString() : t.toFixed(3));

export function exportJSON(report) {
  downloadBlob(new Blob([JSON.stringify(report)], { type: 'application/json' }), `${slug(report)}.json`);
}

export function exportIncidentsCSV(report) {
  const abs = report.stats.absoluteTime;
  const rows = [['№', 'Тип', 'Важность', 'Уверенность', 'Источник', 'Получатель', 'Порт', 'Начало', 'Обнаружено', 'Последняя активность', 'MITRE ATT&CK', 'Описание']];
  report.incidents.forEach((i, k) =>
    rows.push([k + 1, i.name, SEVERITY[i.sev].name, Math.round(i.peak * 100) / 100, i.src || 'множество', i.dst || 'множество', i.port || '', isoTime(i.tStart, abs), isoTime(i.tDetect, abs), isoTime(i.tLast, abs), i.mitre, i.description]),
  );
  downloadBlob(new Blob([csv(rows)], { type: 'text/csv;charset=utf-8' }), `${slug(report)}-incidents.csv`);
}

export function exportTimelineCSV(report) {
  const abs = report.stats.absoluteTime;
  const tl = report.timeline;
  const head = ['Начало окна', 'Риск', 'Состояние', 'EWMA-z', 'CUSUM', 'Isolation Forest', 'Сигнатуры', ...FEATURES.map((f) => f.name)];
  if (tl.attack) head.push('Разметка: атака');
  const states = ['норма', 'предупреждение', 'тревога'];
  const rows = [head];
  tl.t0.forEach((t, i) => {
    const row = [isoTime(t, abs), tl.risk[i], states[tl.state[i]], tl.base[i], tl.cusum[i], tl.iforest[i], tl.patterns[i], ...(report.detail?.f[i] || [])];
    if (tl.attack) row.push(tl.attack[i]);
    rows.push(row);
  });
  downloadBlob(new Blob([csv(rows)], { type: 'text/csv;charset=utf-8' }), `${slug(report)}-timeline.csv`);
}

function riskSvg(report) {
  const r = report.timeline.risk;
  if (r.length < 2) return '';
  const W = 760;
  const H = 160;
  const pts = r.map((v, i) => `${((i / (r.length - 1)) * W).toFixed(1)},${(H - (v / 100) * H).toFixed(1)}`).join(' ');
  const tau = H - (report.params.threshold / 100) * H;
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Риск по времени, шкала 0–100">
    <rect width="${W}" height="${H}" fill="#f6f6f4"/>
    <line x1="0" x2="${W}" y1="${tau}" y2="${tau}" stroke="#d03b3b" stroke-width="1"/>
    <polyline points="${pts}" fill="none" stroke="#2a78d6" stroke-width="2" stroke-linejoin="round"/>
  </svg>`;
}

export function exportHTML(report) {
  const abs = report.stats.absoluteTime;
  const o = report.stats.tStart;
  const lvl = LEVELS.find((l) => l.id === report.risk.level);
  const incRows = report.incidents
    .map(
      (i, k) => `<tr><td>${k + 1}</td><td>${esc(i.name)}</td><td>${esc(SEVERITY[i.sev].name)}</td><td>${fmtPct(i.peak)}</td>
      <td>${esc(i.src || 'множество')}</td><td>${esc(i.dst || 'множество')}${i.port ? `:${i.port}` : ''}</td>
      <td>${esc(fmtClock(i.tDetect, abs, o))}</td><td>${esc(i.description)}</td></tr>`,
    )
    .join('');
  const hostRows = report.hosts
    .slice(0, 25)
    .map((h) => `<tr><td>${esc(h.ip)}</td><td>${h.internal ? 'внутренний' : 'внешний'}</td><td>${fmtInt(h.pkOut + h.pkIn)}</td><td>${esc(fmtBytes(h.byOut))}</td><td>${esc(fmtBytes(h.byIn))}</td><td>${h.incidents}</td></tr>`)
    .join('');
  const ev = report.evaluation;
  const evalBlock = ev
    ? `<h2>Оценка по разметке источника</h2><table><tr><th>Точность</th><th>Полнота</th><th>F1</th><th>ROC-AUC</th><th>Доля ложных</th></tr>
       <tr><td>${fmtPct(ev.precision, 1)}</td><td>${fmtPct(ev.recall, 1)}</td><td>${fmtPct(ev.f1, 1)}</td><td>${ev.auc?.toFixed(3) ?? '—'}</td><td>${fmtPct(ev.fpr, 1)}</td></tr></table>`
    : '';
  const page = `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Отчёт FlowGuard — ${esc(report.source?.name || '')}</title>
<style>
body{font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;color:#0b0b0b;background:#fff;max-width:1000px;margin:32px auto;padding:0 16px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 10px}.muted{color:#52514e}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #e1e0d9;vertical-align:top}
th{color:#52514e;font-weight:600}.kpi{display:flex;flex-wrap:wrap;gap:24px;margin:20px 0}.kpi div{min-width:140px}.kpi b{display:block;font-size:24px}
.note{padding:10px 12px;border:1px solid #e1e0d9;border-radius:6px;background:#f6f6f4;font-size:13px}
</style></head><body>
<p class="muted">FlowGuard ${esc(report.version)} · модель раннего выявления рисков</p>
<h1>${esc(report.source?.name || 'Отчёт')}</h1>
<p class="muted">Сформирован ${esc(fmtDateTime(report.createdAt))} · ${esc(report.source?.format || '')} · окно ${report.params.windowSize} с</p>
<div class="kpi">
<div><span class="muted">Пиковый риск</span><b>${Math.round(report.risk.peak)} / 100</b>${esc(lvl?.name || '')}</div>
<div><span class="muted">Инциденты</span><b>${report.incidents.length}</b></div>
<div><span class="muted">Пакеты</span><b>${fmtInt(report.stats.packets)}</b></div>
<div><span class="muted">Объём</span><b>${esc(fmtBytes(report.stats.bytes))}</b></div>
<div><span class="muted">Длительность</span><b>${esc(fmtDuration(report.stats.duration))}</b></div>
<div><span class="muted">Узлы</span><b>${fmtInt(report.stats.hosts)}</b></div>
</div>
<h2>Динамика риска</h2>${riskSvg(report)}
<p class="muted">Линия порога тревоги — ${report.params.threshold}.</p>
<h2>Инциденты</h2>${report.incidents.length ? `<table><tr><th>№</th><th>Тип</th><th>Важность</th><th>Уверенность</th><th>Источник</th><th>Получатель</th><th>Обнаружено</th><th>Описание</th></tr>${incRows}</table>` : '<p>Инциденты не обнаружены.</p>'}
${evalBlock}
<h2>Наиболее активные узлы</h2><table><tr><th>Адрес</th><th>Сеть</th><th>Пакеты</th><th>Отправлено</th><th>Получено</th><th>Инциденты</th></tr>${hostRows}</table>
${report.notes.length ? `<h2>Примечания</h2><div class="note">${report.notes.map(esc).join('<br>')}</div>` : ''}
</body></html>`;
  downloadBlob(new Blob([page], { type: 'text/html;charset=utf-8' }), `${slug(report)}.html`);
}

export function printReport() {
  window.print();
}
