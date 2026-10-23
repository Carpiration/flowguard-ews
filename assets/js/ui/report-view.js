// Представление отчёта анализа: сводка риска, временная шкала, вклад детекторов,
// инциденты с доказательствами, детали окна, узлы, протоколы и оценка качества.

import { SEVERITY, THREATS } from '../core/catalog.js';
import { FEATURES } from '../core/features.js';
import { PARAMS, levelOf } from '../core/score.js';
import { TimelineChart } from './charts/timeline.js';
import { SparkRows } from './charts/sparkrows.js';
import { animateGauges, barList, confusionMatrix, gauge, levelBadge, meters, rocChart } from './charts/widgets.js';
import { countUp, html, mount, on, qs, qsa, raw } from './dom.js';
import { countText, fmt1, fmt2, fmtBytes, fmtClock, fmtCompact, fmtDuration, fmtInt, fmtPct } from './format.js';
import { SEV_ICON, icon } from './icons.js';

const STATE_NAMES = ['Норма', 'Предупреждение', 'Тревога'];
const STATE_LEVEL = ['low', 'medium', 'critical'];

export function sevBadge(sev) {
  return html`<span class="badge sev-${sev}">${icon(SEV_ICON[sev], 14)}${SEVERITY[sev].name}</span>`;
}

const EVIDENCE = {
  ports: ['Портов назначения', (v) => fmtInt(v)],
  probes: ['Попыток обращения', (v) => fmtInt(v)],
  unanswered: ['Без установления соединения', (v) => fmtPct(v)],
  hosts: ['Опрошено узлов', (v) => fmtInt(v)],
  method: ['Метод', (v) => v],
  rate: ['Интенсивность', (v, inc) => (inc.type === 'exfil' ? `${fmtBytes(v)}/с` : `${fmtInt(v)} /с`)],
  sources: ['Источников', (v) => fmtInt(v)],
  share: ['Доля трафика окна', (v) => fmtPct(v)],
  attempts: ['Попыток за 60 с', (v) => fmtInt(v)],
  perMin: ['Попыток в минуту', (v) => fmtInt(v)],
  bytes: ['Передано за 60 с', (v) => fmtBytes(v)],
  ratio: ['Исходящий / входящий', (v) => `${fmt1(v)}×`],
  period: ['Период', (v) => `${fmt1(v)} с`],
  jitter: ['Разброс интервалов', (v) => fmtPct(v, 1)],
  count: ['Соединений в серии', (v) => fmtInt(v)],
  domain: ['Домен', (v) => v],
  queries: ['DNS-запросов за 60 с', (v) => fmtInt(v)],
  avgLen: ['Средняя длина поддомена', (v) => `${fmt1(v)} симв.`],
  entropy: ['Энтропия поддомена', (v) => `${fmt2(v)} бит`],
  unique: ['Уникальных имён', (v) => fmtPct(v)],
  packets: ['Пакетов', (v) => fmtInt(v)],
};

export function incidentItem(inc, report, { open = false } = {}) {
  const abs = report.stats.absoluteTime;
  const o = report.stats.tStart;
  const t = THREATS[inc.type];
  const route = html`<span class="host">${inc.src || 'множество источников'}</span>
    ${icon('arrowRight', 14)}
    <span class="host">${inc.dst || 'множество узлов'}${inc.port ? `:${inc.port}` : ''}</span>
    ${inc.service ? html`<span class="tag">${inc.service}</span>` : ''}`;
  const ev = Object.entries(inc.evidence || {})
    .filter(([k]) => EVIDENCE[k])
    .map(([k, v]) => html`<div><dt>${EVIDENCE[k][0]}</dt><dd>${EVIDENCE[k][1](v, inc)}</dd></div>`);
  return html`<details class="incident sev-${inc.sev}" data-inc="${inc.id}" ${open ? 'open' : ''}>
    <summary>
      <div>
        <div class="incident-title">${sevBadge(inc.sev)} <span>${inc.name}</span> <span class="tag" title="MITRE ATT&CK">${inc.mitre}</span></div>
        <div class="incident-route">${route}</div>
      </div>
      <div class="incident-meta">
        <span class="nowrap">${icon('clock', 13)} ${fmtClock(inc.tDetect, abs, o)}</span>
        <span class="conf nowrap" title="Уверенность детектора">уверенность <span class="conf-bar"><i style="--v:${inc.peak}"></i></span> ${fmtPct(inc.peak)}</span>
        <span class="incident-chevron" aria-hidden="true">${icon('chevDown', 16)}</span>
      </div>
    </summary>
    <div class="incident-body">
      <p class="incident-desc">${inc.description}</p>
      <dl class="kv">
        <div><dt>Начало активности</dt><dd>${fmtClock(inc.tStart, abs, o)}</dd></div>
        <div><dt>Обнаружено</dt><dd>${fmtClock(inc.tDetect, abs, o)} <span class="muted">(+${fmtDuration(Math.max(0, inc.tDetect - inc.tStart))})</span></dd></div>
        <div><dt>Последняя активность</dt><dd>${fmtClock(inc.tLast, abs, o)}</dd></div>
        <div><dt>Окон с признаками</dt><dd>${fmtInt(inc.windows)}</dd></div>
        ${ev}
      </dl>
      <div>
        <h4 class="panel-title" style="margin-bottom:6px">Рекомендации</h4>
        <ol class="advice">${t.advice.map((a) => html`<li>${a}</li>`)}</ol>
      </div>
      <div class="row no-print">
        <button class="btn btn-sm" data-action="show-time" data-t="${inc.tDetect}">${icon('chart', 15)} Показать на графике</button>
      </div>
    </div>
  </details>`;
}

function statTile(label, valueTpl, sub = '') {
  return html`<div class="stat"><span class="stat-label">${label}</span><span class="stat-value">${valueTpl}</span>${sub ? html`<span class="stat-sub">${sub}</span>` : ''}</div>`;
}

function sortRows(rows, key, dir) {
  const k = dir === 'ascending' ? 1 : -1;
  return [...rows].sort((a, b) => {
    const va = a[key];
    const vb = b[key];
    if (typeof va === 'string') return va.localeCompare(vb, 'ru', { numeric: true }) * k;
    return (va - vb) * k;
  });
}

const HOST_COLS = [
  ['ip', 'Адрес', false],
  ['packets', 'Пакеты', true],
  ['byOut', 'Отправлено', true],
  ['byIn', 'Получено', true],
  ['peers', 'Собеседники', true],
  ['incidents', 'Инциденты', true],
];

export function renderReport(container, report, opts = {}) {
  const abs = report.stats.absoluteTime;
  const o = report.stats.tStart;
  const tl = report.timeline;
  const w = report.params.windowSize;
  const n = tl.t0.length;
  const cleanups = [];
  const state = {
    sev: 0,
    incLimit: 30,
    hostSort: { key: 'packets', dir: 'descending' },
    hostQuery: '',
    hostPage: 0,
    view: 'chart',
    tablePage: 0,
    selected: -1,
  };
  const hosts = report.hosts.map((h) => ({ ...h, packets: h.pkOut + h.pkIn }));
  const sevCounts = [0, 0, 0, 0, 0];
  for (const i of report.incidents) sevCounts[i.sev]++;
  const peakIdx = tl.risk.length ? tl.risk.indexOf(Math.max(...tl.risk)) : -1;
  const alarmTime = report.risk.alarmWindows * w;
  const leads = report.risk.leadTimes || [];
  const leadPositive = leads.filter((x) => x > 0);
  const lvl = levelOf(report.risk.peak);

  const notes = report.notes.length
    ? html`<div class="callout callout-warning reveal" style="--i:0">${icon('info', 18)}<div>${report.notes.map((nn) => html`<div>${nn}</div>`)}</div></div>`
    : '';

  const summaryText = report.incidents.length
    ? `Обнаружено ${countText(report.incidents.length, 'событие', 'события', 'событий')} безопасности; пик риска — ${fmtClock(report.risk.peakAt, abs, o)}.`
    : report.risk.peak >= 25
      ? 'Сигнатуры атак не сработали, но статистические детекторы отметили отклонения от нормы.'
      : 'Существенных отклонений от нормального поведения сети не выявлено.';

  mount(
    container,
    html`<div class="stack">
      ${notes}
      <div class="grid reveal" style="--i:1;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr))">
        <section class="panel" aria-labelledby="risk-h">
          <div class="panel-head"><div><h2 class="panel-title" id="risk-h">Пиковый риск</h2><p class="panel-sub">Шкала 0–100, порог тревоги ${report.params.threshold}</p></div></div>
          <div class="panel-body">${gauge(report.risk.peak)}<p class="muted" style="margin-top:14px;text-align:center;font-size:14px">${summaryText}</p></div>
        </section>
        <section class="panel" style="grid-column:span 2;min-width:min(100%,300px)" aria-label="Ключевые показатели">
          <div class="stat-row" style="grid-template-columns:repeat(auto-fit,minmax(min(100%,180px),1fr))">
            ${statTile(
              'Инциденты',
              html`<span data-countup="${report.incidents.length}" data-format="int">${fmtInt(report.incidents.length)}</span>`,
              sevCounts[4] + sevCounts[3] ? `${sevCounts[4]} критич. · ${sevCounts[3]} высоких · ${sevCounts[2]} средних` : 'высокой важности нет',
            )}
            ${statTile('Время в тревоге', fmtDuration(alarmTime), `${countText(report.risk.episodes, 'эпизод', 'эпизода', 'эпизодов')} тревоги`)}
            ${statTile(
              'Раннее предупреждение',
              leadPositive.length ? html`за ${fmtDuration(leadPositive.reduce((a, b) => a + b, 0) / leadPositive.length)}` : '—',
              leadPositive.length ? 'в среднем до перехода в тревогу' : leads.length ? 'тревога возникла без фазы предупреждения' : 'тревог не было',
            )}
          </div>
          <div class="stat-row" style="grid-template-columns:repeat(auto-fit,minmax(min(100%,180px),1fr));border-top:1px solid var(--line)">
            ${statTile(report.stats.flowMode ? 'Записи потоков' : 'Пакеты', html`<span data-countup="${report.stats.packets}" data-format="compact">${fmtCompact(report.stats.packets)}</span>`, fmtBytes(report.stats.bytes))}
            ${statTile('Длительность', fmtDuration(report.stats.duration), `${fmtInt(n)} окон по ${w} с`)}
            ${statTile('Узлы', html`<span data-countup="${report.stats.hosts}" data-format="int">${fmtInt(report.stats.hosts)}</span>`, `${fmtInt(report.stats.internalHosts)} внутренних · ${fmtInt(report.stats.externalHosts)} внешних`)}
          </div>
        </section>
      </div>

      <section class="panel reveal" style="--i:2" aria-labelledby="tl-h">
        <div class="panel-head">
          <div><h2 class="panel-title" id="tl-h">Динамика трафика и риска</h2><p class="panel-sub">Наведите или используйте стрелки; щелчок или Enter открывает детали окна</p></div>
          <div class="segmented" role="group" aria-label="Представление">
            <button type="button" data-view="chart" aria-pressed="true">${icon('chart', 15)} График</button>
            <button type="button" data-view="table" aria-pressed="false">${icon('table', 15)} Таблица</button>
          </div>
        </div>
        <div class="panel-body">
          <div class="legend" style="margin-bottom:10px">
            <span class="legend-item"><i class="legend-swatch area" style="--c:var(--series-1)"></i>Пакетов в секунду</span>
            <span class="legend-item"><i class="legend-swatch" style="--c:var(--ink)"></i>Оценка риска</span>
            <span class="legend-item"><i class="legend-swatch" style="--c:var(--critical);height:1px"></i>Порог тревоги</span>
            <span class="legend-item"><i class="legend-swatch band" style="--c:var(--warning)"></i>Предупреждение</span>
            <span class="legend-item"><i class="legend-swatch band" style="--c:var(--critical)"></i>Тревога</span>
            <span class="legend-item"><i class="legend-swatch dot" style="--c:var(--serious)"></i>Обнаружение инцидента</span>
            ${tl.attack ? html`<span class="legend-item"><i class="legend-swatch band" style="--c:color-mix(in srgb, var(--ink) 14%, transparent)"></i>Атака по разметке</span>` : ''}
          </div>
          <div data-slot="timeline"></div>
          <div data-slot="table" hidden></div>
          <h3 class="panel-title" style="margin:18px 0 6px">Вклад детекторов</h3>
          <div data-slot="sparks"></div>
        </div>
      </section>

      <div class="split">
        <section class="panel reveal" style="--i:3" aria-labelledby="inc-h">
          <div class="panel-head">
            <div><h2 class="panel-title" id="inc-h">Инциденты</h2><p class="panel-sub">Сработавшие поведенческие сигнатуры с доказательствами</p></div>
            <div class="row" role="group" aria-label="Фильтр по важности" data-slot="sev-filter"></div>
          </div>
          <div class="panel-body flush"><div class="incident-list" data-slot="incidents"></div></div>
        </section>
        <section class="panel reveal sticky-panel" style="--i:4" aria-labelledby="win-h" data-slot="window"></section>
      </div>

      <section class="panel reveal" style="--i:5" aria-labelledby="hosts-h">
        <div class="panel-head"><div><h2 class="panel-title" id="hosts-h">Узлы</h2><p class="panel-sub">${fmtInt(report.stats.hosts)} адресов; показаны самые активные и участники инцидентов</p></div></div>
        <div class="panel-body flush">
          <div class="table-tools">
            <label class="search">${icon('search', 16)}<span class="sr-only">Поиск по адресу</span><input class="input" type="search" placeholder="Поиск по адресу" data-slot="host-q" autocomplete="off" /></label>
            <span class="muted" data-slot="host-count" aria-live="polite"></span>
          </div>
          <div class="table-wrap" tabindex="0" aria-label="Таблица узлов, прокручивается по горизонтали"><table class="data" data-slot="hosts"></table></div>
          <div class="pager" data-slot="host-pager"></div>
        </div>
      </section>

      <div class="grid cols-3 reveal" style="--i:6">
        <section class="panel"><div class="panel-head"><h2 class="panel-title">Протоколы</h2></div><div class="panel-body">${barList(
          report.protocols.map((p) => ({ label: p.name, value: p.pk, display: `${fmtPct(p.pk / Math.max(1, report.stats.packets))} · ${fmtBytes(p.by)}` })),
        )}</div></section>
        <section class="panel"><div class="panel-head"><h2 class="panel-title">Службы назначения</h2></div><div class="panel-body">${
          report.services.length
            ? barList(report.services.map((s) => ({ label: `${s.name}${s.name !== String(s.port) ? ` · ${s.port}` : ''}`, value: s.conns, display: fmtCompact(s.conns) })))
            : html`<p class="muted">Нет данных о соединениях.</p>`
        }</div></section>
        <section class="panel"><div class="panel-head"><h2 class="panel-title">Крупнейшие потоки</h2></div><div class="panel-body">${barList(
          report.flows.slice(0, 8).map((f) => ({ label: `${f.src} → ${f.dst}`, value: f.by, display: fmtBytes(f.by) })),
        )}</div></section>
      </div>

      ${report.evaluation ? html`<section class="panel reveal" style="--i:7" aria-labelledby="eval-h" data-slot="eval"></section>` : ''}

      <p class="muted reveal" style="--i:8;font-size:13px">
        Модель FlowGuard ${report.version}: окно ${w} с, чувствительность ×${fmt2(report.params.sensitivity)}, обучение базовой линии — первые ${fmtDuration(report.params.warmup)}.
        Детекторы: EWMA-z (вес ${PARAMS.wBase}), CUSUM (k = ${PARAMS.cusumK}, h = ${PARAMS.cusumH}), Isolation Forest (100 деревьев), поведенческие сигнатуры.
      </p>
    </div>`,
  );

  animateGauges(container);
  for (const el of qsa('[data-countup]', container)) {
    const fmt = el.dataset.format === 'compact' ? fmtCompact : fmtInt;
    countUp(el, Number(el.dataset.countup), fmt);
  }

  // ---- временная шкала и детекторы ----
  const markers = report.incidents.map((i) => ({ t: i.tDetect, sev: i.sev }));
  const tooltip = (i) => {
    const top = (report.detail?.top[i] || []).map((k) => FEATURES[k].short).join(', ');
    return `<div class="tooltip-title">${fmtClock(tl.t0[i], abs, o)} — ${fmtClock(tl.t0[i] + w, abs, o)}</div>
      <div class="tooltip-row"><span class="tooltip-key"><i style="--c:var(--series-1)"></i>Пакетов/с</span><b>${fmt1(tl.pkts[i] / w)}</b></div>
      <div class="tooltip-row"><span class="tooltip-key"><i style="--c:var(--ink)"></i>Риск</span><b>${fmt1(tl.risk[i])}</b></div>
      <div class="tooltip-row"><span>Состояние</span><b>${STATE_NAMES[tl.state[i]]}</b></div>
      ${top ? `<div class="tooltip-row"><span>Отклонения</span><b>${top}</b></div>` : ''}
      ${tl.attack?.[i] ? '<div class="tooltip-row"><span>Разметка</span><b>атака</b></div>' : ''}`;
  };
  let sparks = null;
  const chart = new TimelineChart(qs('[data-slot="timeline"]', container), {
    height: 340,
    tau: report.params.threshold,
    absolute: abs,
    origin: o,
    w,
    tooltip,
    onHover: (i) => sparks?.setHover(i),
    onSelect: (i) => selectWindow(i),
  });
  chart.setData({ t0: tl.t0, pkts: tl.pkts, risk: tl.risk, state: tl.state, attack: tl.attack, markers, compare: opts.compare || null }, { animate: true });
  cleanups.push(() => chart.destroy());
  sparks = new SparkRows(qs('[data-slot="sparks"]', container), {
    t0: tl.t0,
    w,
    rows: [
      { label: 'EWMA-z: отклонение от базовой линии', values: tl.base, slot: 0 },
      { label: 'CUSUM: накопленный сдвиг', values: tl.cusum, slot: 2 },
      { label: 'Isolation Forest: многомерная аномальность', values: tl.iforest, slot: 6 },
      { label: 'Поведенческие сигнатуры', values: tl.patterns, slot: 1 },
    ],
    onHover: (i) => chart.setHover(i, { silent: true }),
  });
  sparks.draw();
  cleanups.push(() => sparks.destroy());

  function renderTable() {
    const slot = qs('[data-slot="table"]', container);
    const size = 50;
    const pages = Math.max(1, Math.ceil(n / size));
    state.tablePage = Math.min(state.tablePage, pages - 1);
    const from = state.tablePage * size;
    const rows = [];
    for (let i = from; i < Math.min(n, from + size); i++) {
      rows.push(html`<tr class="${i === state.selected ? 'is-selected' : ''}">
        <td class="nowrap">${fmtClock(tl.t0[i], abs, o)}</td>
        <td class="r">${fmt1(tl.pkts[i] / w)}</td>
        <td class="r">${fmtBytes(tl.bytes[i])}</td>
        <td class="r">${fmt1(tl.risk[i])}</td>
        <td>${levelBadge(STATE_LEVEL[tl.state[i]], STATE_NAMES[tl.state[i]])}</td>
        <td>${(report.detail?.top[i] || []).map((k) => FEATURES[k].short).join(', ') || '—'}</td>
        <td><button class="btn btn-sm btn-ghost" data-action="pick-window" data-i="${i}">Детали</button></td>
      </tr>`);
    }
    mount(
      slot,
      html`<div class="table-wrap" tabindex="0" aria-label="Таблица окон"><table class="data">
          <thead><tr><th>Начало окна</th><th class="r">Пакетов/с</th><th class="r">Объём</th><th class="r">Риск</th><th>Состояние</th><th>Главные отклонения</th><th><span class="sr-only">Действие</span></th></tr></thead>
          <tbody>${rows}</tbody></table></div>
        <div class="pager"><span>Окна ${fmtInt(from + 1)}–${fmtInt(Math.min(n, from + size))} из ${fmtInt(n)}</span>
          <span class="row"><button class="btn btn-sm" data-action="tpage" data-d="-1" ${state.tablePage === 0 ? 'disabled' : ''}>Назад</button>
          <button class="btn btn-sm" data-action="tpage" data-d="1" ${state.tablePage >= pages - 1 ? 'disabled' : ''}>Вперёд</button></span></div>`,
    );
  }

  // ---- детали окна ----
  function selectWindow(i, { scroll = false } = {}) {
    if (i < 0 || i >= n) return;
    state.selected = i;
    chart.select(i);
    const slot = qs('[data-slot="window"]', container);
    const z = report.detail?.z[i] || [];
    const f = report.detail?.f[i] || [];
    const hits = new Set(report.detail?.hits[i] || []);
    const active = report.incidents.filter((inc) => hits.has(inc.id));
    const zRows = FEATURES.map((feat, k) => ({ feat, k, z: z[k] ?? 0, v: f[k] ?? 0 })).sort((a, b) => b.z - a.z);
    const onset = PARAMS.zOnset / report.params.sensitivity;
    const fmtVal = (feat, v) => (feat.unit === 'bytes' ? fmtBytes(v) : feat.unit === 'bits' ? `${fmt2(v)} бит` : fmtInt(v));
    mount(
      slot,
      html`<div class="panel-head">
          <div><h2 class="panel-title" id="win-h">Окно ${fmtClock(tl.t0[i], abs, o)} — ${fmtClock(tl.t0[i] + w, abs, o)}</h2>
          <p class="panel-sub">${i === peakIdx ? 'Окно пикового риска · ' : ''}${tl.warm[i] ? 'период обучения базовой линии' : `окно ${fmtInt(i + 1)} из ${fmtInt(n)}`}</p></div>
          ${levelBadge(STATE_LEVEL[tl.state[i]], `${STATE_NAMES[tl.state[i]]} · ${Math.round(tl.risk[i])}`)}
        </div>
        <div class="panel-body stack">
          <div>
            <h3 class="field-label" style="margin-bottom:8px">Сигналы детекторов</h3>
            ${meters([
              { label: 'EWMA-z', value: tl.base[i], slot: 1 },
              { label: 'CUSUM', value: tl.cusum[i], slot: 3 },
              { label: 'Isolation Forest', value: tl.iforest[i], slot: 7 },
              { label: 'Сигнатуры', value: tl.patterns[i], slot: 2 },
            ])}
          </div>
          <div>
            <h3 class="field-label" style="margin-bottom:8px">Признаки окна и отклонение от нормы (z)</h3>
            <ul class="bars">${zRows.map(
              (r) => html`<li class="bar-row" title="${r.feat.name}">
                <span class="bar-label">${r.feat.short}</span>
                <span class="bar-track"><span class="bar-fill" style="--v:${Math.min(1, Math.max(0, r.z) / 10).toFixed(3)};--c:${r.z >= onset ? 'var(--serious)' : 'var(--series-1)'}"></span></span>
                <span class="bar-value">${fmtVal(r.feat, r.v)} · z ${fmt1(r.z)}</span>
              </li>`,
            )}</ul>
            <p class="hint" style="margin-top:8px">Оранжевым отмечены признаки выше порога z = ${fmt1(onset)}.</p>
          </div>
          <div>
            <h3 class="field-label" style="margin-bottom:8px">Активные сигнатуры</h3>
            ${active.length
              ? html`<ul class="bars">${active.map((a) => html`<li class="row">${sevBadge(a.sev)} <a href="#" data-action="open-inc" data-id="${a.id}">${a.name}</a></li>`)}</ul>`
              : html`<p class="muted">В этом окне сигнатуры не срабатывали.</p>`}
          </div>
        </div>`,
    );
    if (state.view === 'table') renderTable();
    if (scroll) slot.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // ---- инциденты ----
  function renderSevFilter() {
    const opts2 = [
      [0, `Все · ${report.incidents.length}`],
      [4, `Критические · ${sevCounts[4]}`],
      [3, `Высокие · ${sevCounts[3]}`],
      [2, `Средние · ${sevCounts[2]}`],
    ].filter(([s, _], k) => k === 0 || sevCounts[s] > 0);
    mount(
      qs('[data-slot="sev-filter"]', container),
      html`${opts2.map(([s, label]) => html`<button type="button" class="chip chip-btn" data-action="sev" data-sev="${s}" aria-pressed="${state.sev === s}">${label}</button>`)}`,
    );
  }

  function renderIncidents() {
    const list = report.incidents.filter((i) => !state.sev || i.sev === state.sev);
    const slot = qs('[data-slot="incidents"]', container);
    if (!list.length) {
      mount(
        slot,
        html`<div class="empty"><div class="empty-icon">${icon('shield', 22)}</div><h3>Инцидентов нет</h3>
          <p>Поведенческие сигнатуры не сработали. ${report.risk.peak >= 25 ? 'Статистические отклонения показаны на графике и в деталях окна.' : ''}</p></div>`,
      );
      return;
    }
    const shown = list.slice(0, state.incLimit);
    mount(
      slot,
      html`${shown.map((inc, k) => incidentItem(inc, report, { open: k === 0 && state.sev === 0 && list.length < 40 }))}
        ${list.length > shown.length ? html`<div class="pager"><span>Показано ${shown.length} из ${list.length}</span><button class="btn btn-sm" data-action="more-inc">Показать ещё</button></div>` : ''}`,
    );
  }

  // ---- узлы ----
  function renderHosts() {
    const q = state.hostQuery.trim().toLowerCase();
    let rows = q ? hosts.filter((h) => h.ip.toLowerCase().includes(q)) : hosts;
    rows = sortRows(rows, state.hostSort.key, state.hostSort.dir);
    const size = 20;
    const pages = Math.max(1, Math.ceil(rows.length / size));
    state.hostPage = Math.min(state.hostPage, pages - 1);
    const from = state.hostPage * size;
    const page = rows.slice(from, from + size);
    const head = HOST_COLS.map(([key, label, num]) => {
      const sorted = state.hostSort.key === key;
      return html`<th class="${num ? 'r' : ''}" ${sorted ? raw(`aria-sort="${state.hostSort.dir}"`) : ''}><button class="sort-btn" data-action="sort" data-key="${key}">${label}${icon('sort', 13)}</button></th>`;
    });
    mount(
      qs('[data-slot="hosts"]', container),
      html`<thead><tr>${head}</tr></thead><tbody>
        ${page.length
          ? page.map(
              (h) => html`<tr>
              <td><span class="host">${h.ip}</span><span class="side-tag ${h.internal ? '' : 'ext'}">${h.internal ? 'внутр.' : 'внешн.'}</span></td>
              <td class="r">${fmtInt(h.packets)}</td>
              <td class="r">${fmtBytes(h.byOut)}</td>
              <td class="r">${fmtBytes(h.byIn)}</td>
              <td class="r">${fmtInt(h.peers)}</td>
              <td class="r">${h.incidents ? html`<span class="badge sev-${h.sev}"><span class="badge-dot"></span>${h.incidents}</span>` : html`<span class="muted">—</span>`}</td>
            </tr>`,
            )
          : html`<tr><td colspan="6" class="muted">Ничего не найдено по запросу «${state.hostQuery}».</td></tr>`}
      </tbody>`,
    );
    qs('[data-slot="host-count"]', container).textContent = q ? `Найдено: ${fmtInt(rows.length)}` : '';
    mount(
      qs('[data-slot="host-pager"]', container),
      html`<span>${rows.length ? `${fmtInt(from + 1)}–${fmtInt(Math.min(rows.length, from + size))} из ${fmtInt(rows.length)}` : '0 записей'}</span>
        <span class="row"><button class="btn btn-sm" data-action="hpage" data-d="-1" ${state.hostPage === 0 ? 'disabled' : ''}>Назад</button>
        <button class="btn btn-sm" data-action="hpage" data-d="1" ${state.hostPage >= pages - 1 ? 'disabled' : ''}>Вперёд</button></span>`,
    );
  }

  // ---- оценка по разметке ----
  function renderEval() {
    const ev = report.evaluation;
    const slot = qs('[data-slot="eval"]', container);
    if (!ev || !slot) return;
    mount(
      slot,
      html`<div class="panel-head"><div><h2 class="panel-title" id="eval-h">Качество обнаружения по разметке источника</h2>
          <p class="panel-sub">Окно считается атакой, если содержит размеченные записи; ${fmtInt(ev.excluded)} окон сразу после атак исключены из оценки</p></div></div>
        <div class="stat-row" style="border-top:1px solid var(--line);border-bottom:1px solid var(--line);margin-top:14px">
          ${statTile('Точность (precision)', fmtPct(ev.precision, 1), `при пороге ${ev.threshold}`)}
          ${statTile('Полнота (recall)', fmtPct(ev.recall, 1), `${fmtInt(ev.positives)} окон атаки`)}
          ${statTile('F1-мера', fmtPct(ev.f1, 1), `статический порог: ${fmtPct(ev.staticMetrics?.f1, 1)}`)}
          ${statTile('ROC-AUC', ev.auc === null ? '—' : fmt2(ev.auc), `статический порог: ${ev.staticAuc === null ? '—' : fmt2(ev.staticAuc)}`)}
        </div>
        <div class="panel-body grid cols-2">
          <div><h3 class="field-label" style="margin-bottom:8px">Матрица ошибок</h3>${confusionMatrix(ev)}</div>
          <div>
            <h3 class="field-label" style="margin-bottom:8px">ROC-кривая</h3>
            <div class="legend" style="margin-bottom:6px"><span class="legend-item"><i class="legend-swatch" style="--c:var(--series-1)"></i>FlowGuard</span><span class="legend-item"><i class="legend-swatch" style="--c:var(--series-2)"></i>Статический порог μ+3σ</span></div>
            <div data-slot="roc"></div>
          </div>
        </div>
        ${ev.perLabel?.length
          ? html`<div class="table-wrap"><table class="data"><thead><tr><th>Метка атаки</th><th>Начало</th><th>Обнаружена</th><th class="r">Задержка</th></tr></thead><tbody>
            ${ev.perLabel.map((p) => html`<tr><td>${p.name}</td><td>${fmtClock(p.start, abs, o)}</td><td>${p.detected ? levelBadge('low', 'да') : levelBadge('critical', 'нет')}</td><td class="r">${p.detected ? fmtDuration(p.delay) : '—'}</td></tr>`)}
          </tbody></table></div>`
          : ''}`,
    );
    rocChart(qs('[data-slot="roc"]', slot), [
      { name: 'FlowGuard', points: ev.roc, auc: ev.auc, slot: 1 },
      { name: 'Статический порог', points: ev.staticRoc || [], auc: ev.staticAuc, slot: 2 },
    ]);
  }

  renderSevFilter();
  renderIncidents();
  renderHosts();
  renderEval();
  selectWindow(peakIdx >= 0 ? peakIdx : 0);

  const onQuery = (e) => {
    state.hostQuery = e.target.value;
    state.hostPage = 0;
    renderHosts();
  };
  qs('[data-slot="host-q"]', container).addEventListener('input', onQuery);

  const nearestWindow = (t) => Math.max(0, Math.min(n - 1, Math.floor((t - tl.t0[0]) / w)));
  cleanups.push(
    on(container, 'click', '[data-action]', (e, el) => {
      const a = el.dataset.action;
      if (a === 'sev') {
        state.sev = Number(el.dataset.sev);
        state.incLimit = 30;
        renderSevFilter();
        renderIncidents();
      } else if (a === 'more-inc') {
        state.incLimit += 50;
        renderIncidents();
      } else if (a === 'sort') {
        const key = el.dataset.key;
        state.hostSort = { key, dir: state.hostSort.key === key && state.hostSort.dir === 'descending' ? 'ascending' : 'descending' };
        renderHosts();
        qs(`[data-action="sort"][data-key="${key}"]`, container)?.focus();
      } else if (a === 'hpage') {
        state.hostPage += Number(el.dataset.d);
        renderHosts();
      } else if (a === 'tpage') {
        state.tablePage += Number(el.dataset.d);
        renderTable();
      } else if (a === 'pick-window') {
        selectWindow(Number(el.dataset.i), { scroll: true });
      } else if (a === 'show-time') {
        const i = nearestWindow(Number(el.dataset.t) - w / 2);
        if (state.view !== 'chart') setView('chart');
        selectWindow(i);
        chart.root.scrollIntoView({ behavior: 'smooth', block: 'center' });
        chart.select(i, { focus: true });
      } else if (a === 'open-inc') {
        e.preventDefault();
        const id = el.dataset.id;
        state.sev = 0;
        state.incLimit = Math.max(state.incLimit, report.incidents.length);
        renderSevFilter();
        renderIncidents();
        const d = qs(`[data-inc="${id}"]`, container);
        if (d) {
          d.open = true;
          d.scrollIntoView({ behavior: 'smooth', block: 'center' });
          d.querySelector('summary').focus();
        }
      }
    }),
  );

  function setView(v) {
    state.view = v;
    for (const b of qsa('[data-view]', container)) b.setAttribute('aria-pressed', String(b.dataset.view === v));
    qs('[data-slot="timeline"]', container).hidden = v !== 'chart';
    qs('[data-slot="table"]', container).hidden = v !== 'table';
    if (v === 'table') {
      state.tablePage = state.selected >= 0 ? Math.floor(state.selected / 50) : 0;
      renderTable();
    } else chart.draw();
  }
  cleanups.push(on(container, 'click', '[data-view]', (_, el) => setView(el.dataset.view)));

  return {
    chart,
    destroy() {
      for (const c of cleanups) c();
    },
  };
}

export function reportSubtitle(report) {
  const parts = [report.source?.format, fmtDuration(report.stats.duration), `${fmtCompact(report.stats.packets)} ${report.stats.flowMode ? 'записей' : 'пакетов'}`];
  if (report.source?.size) parts.push(fmtBytes(report.source.size));
  return parts.filter(Boolean).join(' · ');
}

export { levelBadge };
