import { FEATURES } from '../core/features.js';
import { levelOf } from '../core/score.js';
import { SCENARIOS } from '../core/simulate.js';
import { NetMap } from '../ui/charts/netmap.js';
import { TimelineChart } from '../ui/charts/timeline.js';
import { gauge, levelBadge, meters } from '../ui/charts/widgets.js';
import { html, mount, on, qs, reducedMotion } from '../ui/dom.js';
import { fmt1, fmtClock, fmtDuration, fmtInt } from '../ui/format.js';
import { icon } from '../ui/icons.js';
import { LIVE_DURATION, LIVE_WINDOW, live } from '../ui/live-service.js';
import { sevBadge } from '../ui/report-view.js';
import { saveReport } from '../ui/store.js';
import { toast } from '../ui/toast.js';

const VISIBLE = 150;
const INJECT_ICON = { sweep: 'target', portscan: 'radar', bruteforce: 'key', beacon: 'repeat', dnstunnel: 'globe', exfil: 'upload', synflood: 'zap' };
const LEVEL_VAR = { low: '--good', medium: '--warning', high: '--serious', critical: '--critical' };
const SPEEDS = [1, 2, 5, 10];

function feedItem(ev) {
  const cls = ev.kind === 'incident' ? `sev-${ev.sev}` : ev.kind === 'state' ? (ev.state === 'alarm' ? 'lvl-critical' : ev.state === 'warning' ? 'lvl-medium' : 'lvl-low') : '';
  const ic = { incident: 'alert', state: 'pulse', inject: 'bolt', model: 'flask', info: 'info' }[ev.kind] || 'info';
  return html`<li class="feed-item ${cls}" style="--bw:var(--surface-2)">
    <span class="badge ${cls}" style="padding:0 6px">${icon(ic, 14)}</span>
    <div>
      <div class="row" style="justify-content:space-between;gap:8px"><span class="feed-title">${ev.title}</span><span class="feed-time">${fmtClock(ev.at, true)}</span></div>
      <div class="feed-text">${ev.kind === 'incident' ? html`${sevBadge(ev.sev)} ` : ''}${ev.text}</div>
    </div>
  </li>`;
}

export async function render(view, _params, ctx) {
  const cleanups = [];
  let chart = null;
  let map = null;

  mount(
    view,
    html`<div class="page-head">
        <div><p class="eyebrow">Мониторинг · симуляция</p><h1 class="page-title" tabindex="-1">Мониторинг в реальном времени</h1>
          <p class="lead">Поток трафика офисной сети обрабатывается окнами по ${LIVE_WINDOW} с теми же детекторами, что и при анализе файлов. Внедрите атаку и посмотрите, как модель
          переходит от нормы к раннему предупреждению и тревоге.</p></div>
      </div>
      <div class="callout" style="margin-bottom:16px">${icon('info', 18)}<div><strong>Почему симуляция.</strong> Браузер не может читать сетевой интерфейс, поэтому источник здесь —
        генератор трафика с разметкой атак. Для реальных данных сохраните захват (Wireshark, tcpdump) и откройте его в разделе <a href="#/analyze">«Анализ файла»</a>.</div></div>

      <section class="panel" aria-label="Управление мониторингом">
        <div class="control-bar">
          <div class="btn-group" data-controls></div>
          <div class="segmented" role="group" aria-label="Скорость времени">${SPEEDS.map((s) => html`<button type="button" data-speed="${s}" aria-pressed="${live.speed === s}">×${s}</button>`)}</div>
          <span class="spacer"></span>
          <span class="muted" data-clock aria-live="off"></span>
        </div>
      </section>

      <div class="live-grid" style="margin-top:16px">
        <div class="stack">
          <section class="panel" aria-labelledby="lv-h">
            <div class="panel-head"><div><h2 class="panel-title" id="lv-h">Трафик и риск</h2><p class="panel-sub">Последние ${fmtDuration(VISIBLE * LIVE_WINDOW)}; серые полосы — внедрённые атаки</p></div>
              <div class="legend">
                <span class="legend-item"><i class="legend-swatch area" style="--c:var(--series-1)"></i>Пакетов/с</span>
                <span class="legend-item"><i class="legend-swatch" style="--c:var(--ink)"></i>Риск</span>
                <span class="legend-item"><i class="legend-swatch band" style="--c:var(--warning)"></i>Предупреждение</span>
                <span class="legend-item"><i class="legend-swatch band" style="--c:var(--critical)"></i>Тревога</span>
              </div>
            </div>
            <div class="panel-body" data-chart></div>
            <div class="status-strip" data-strip></div>
          </section>
          <section class="panel" aria-labelledby="inj-h">
            <div class="panel-head"><div><h2 class="panel-title" id="inj-h">Внедрить атаку</h2><p class="panel-sub" data-inj-hint></p></div></div>
            <div class="panel-body"><div class="inject-grid" data-inject></div></div>
          </section>
          <section class="panel" aria-labelledby="map-h">
            <div class="panel-head"><div><h2 class="panel-title" id="map-h">Карта взаимодействий</h2><p class="panel-sub">Серверы в центре, рабочие станции — среднее кольцо, внешние адреса — внешнее</p></div></div>
            <div class="panel-body" data-map></div>
          </section>
        </div>
        <div class="stack">
          <section class="panel" aria-labelledby="cur-h">
            <div class="panel-head"><h2 class="panel-title" id="cur-h">Текущая оценка</h2><span data-state-badge></span></div>
            <div class="panel-body stack" data-current></div>
          </section>
          <section class="panel" aria-labelledby="feed-h">
            <div class="panel-head"><h2 class="panel-title" id="feed-h">Журнал событий</h2><span class="muted" data-feed-count></span></div>
            <div class="panel-body flush"><ul class="feed" data-feed aria-live="polite" aria-relevant="additions"></ul></div>
          </section>
        </div>
      </div>`,
  );

  chart = new TimelineChart(qs('[data-chart]', view), { height: 300, tau: 50, absolute: true, w: LIVE_WINDOW, animate: false, label: 'Трафик и риск в реальном времени' });
  map = new NetMap(qs('[data-map]', view), { height: 360 });
  cleanups.push(() => chart.destroy(), () => map.destroy());

  function renderControls() {
    const s = live.state;
    mount(
      qs('[data-controls]', view),
      s === 'idle'
        ? html`<button class="btn btn-primary" type="button" data-act="start">${icon('play', 16)} Запустить мониторинг</button>`
        : html`${s === 'running'
              ? html`<button class="btn" type="button" data-act="pause">${icon('pause', 16)} Пауза</button>`
              : html`<button class="btn btn-primary" type="button" data-act="resume">${icon('play', 16)} Продолжить</button>`}
            <button class="btn" type="button" data-act="stop">${icon('stop', 16)} Остановить и сохранить</button>
            <button class="btn btn-ghost" type="button" data-act="discard">Сбросить</button>`,
    );
    for (const b of view.querySelectorAll('[data-speed]')) b.setAttribute('aria-pressed', String(Number(b.dataset.speed) === live.speed));
  }

  function renderInject() {
    const ready = live.state === 'running' && !live.warming;
    const activeTypes = new Set(live.running ? live.activeScenarios().map((s) => s.type) : []);
    qs('[data-inj-hint]', view).textContent =
      live.state === 'idle' ? 'Сначала запустите мониторинг' : live.warming ? 'Дождитесь окончания обучения базовой линии' : live.state === 'paused' ? 'Мониторинг на паузе' : 'Атака начнётся в следующем окне';
    mount(
      qs('[data-inject]', view),
      html`${Object.entries(SCENARIOS).map(([type, sc]) => {
        const act = live.running ? live.activeScenarios().find((s) => s.type === type) : null;
        return html`<button class="inject ${activeTypes.has(type) ? 'is-active' : ''}" type="button" data-inject-type="${type}" ${ready && !activeTypes.has(type) ? '' : 'disabled'}>
          <span class="threat-icon">${icon(INJECT_ICON[type], 18)}</span>
          <span><b>${sc.short}</b><small>${act ? `идёт · осталось ${fmtDuration(act.left)}` : `${fmtDuration(LIVE_DURATION[type])}`}</small></span>
        </button>`;
      })}`,
    );
  }

  function renderCurrent() {
    const cur = live.current;
    const slot = qs('[data-current]', view);
    if (!live.running || !cur) {
      mount(slot, html`<div class="empty" style="padding:24px 8px"><div class="empty-icon">${icon('pulse', 22)}</div><p>Оценка появится после запуска.</p></div>`);
      qs('[data-state-badge]', view).replaceChildren();
      return;
    }
    let g = qs('[data-gauge]', slot);
    if (!g) {
      mount(
        slot,
        html`${gauge(cur.risk)}
          <div data-meters></div>
          <div><h3 class="field-label" style="margin-bottom:6px">Главные отклонения окна</h3><p class="ink-2" data-top></p></div>`,
      );
      g = qs('[data-gauge]', slot);
    }
    const lvl = levelOf(cur.risk);
    const len = Math.PI * 100;
    const fill = g.querySelector('.gauge-fill');
    fill.style.strokeDashoffset = String(len * (1 - Math.min(100, cur.risk) / 100));
    fill.setAttribute('stroke', `var(${LEVEL_VAR[lvl.id]})`);
    g.querySelector('.gauge-value').textContent = Math.round(cur.risk);
    g.querySelector('svg').setAttribute('aria-label', `Текущий риск ${Math.round(cur.risk)} из 100, уровень ${lvl.name}`);
    mount(g.querySelector('.gauge-caption'), levelBadge(lvl.id));
    mount(
      qs('[data-meters]', slot),
      html`${meters([
        { label: 'EWMA-z', value: cur.sBase, slot: 1 },
        { label: 'CUSUM', value: cur.sCusum, slot: 3 },
        { label: 'Isolation Forest', value: cur.sIf, slot: 7, display: live.forest ? undefined : 'обуч.' },
        { label: 'Сигнатуры', value: cur.P, slot: 2 },
      ])}`,
    );
    qs('[data-top]', slot).textContent = cur.warming ? 'Идёт обучение базовой линии.' : cur.top.length ? cur.top.map((k) => `${FEATURES[k].name} (z ${fmt1(cur.z[k])})`).join('; ') : 'Все признаки в пределах нормы.';
    const names = { normal: 'Норма', warning: 'Предупреждение', alarm: 'Тревога' };
    mount(qs('[data-state-badge]', view), levelBadge(cur.state === 'alarm' ? 'critical' : cur.state === 'warning' ? 'medium' : 'low', cur.warming ? 'Обучение' : names[cur.state]));
  }

  function renderStrip() {
    const W = live.win;
    const cur = live.current;
    const n = W?.t0.length || 0;
    const rate = n ? W.pkts[n - 1] / LIVE_WINDOW : 0;
    const alarms = n ? W.state.filter((s) => s === 2).length * LIVE_WINDOW : 0;
    mount(
      qs('[data-strip]', view),
      html`<div class="stat"><span class="stat-label">Пакетов в секунду</span><span class="stat-value">${live.running ? fmt1(rate) : '—'}</span></div>
        <div class="stat"><span class="stat-label">Источников в окне</span><span class="stat-value">${live.running && cur ? fmtInt(cur.hosts) : '—'}</span></div>
        <div class="stat"><span class="stat-label">Инцидентов</span><span class="stat-value">${live.running ? fmtInt(live.patterns.incidents.length) : '—'}</span></div>
        <div class="stat"><span class="stat-label">Время в тревоге</span><span class="stat-value">${live.running ? fmtDuration(alarms) : '—'}</span></div>`,
    );
  }

  function renderClock() {
    const el = qs('[data-clock]', view);
    if (!live.running) {
      el.textContent = 'Остановлен';
      return;
    }
    const warm = live.warming ? ` · обучение ${Math.min(live.win.t0.length, live.warmN)}/${live.warmN} окон` : '';
    el.textContent = `Модельное время ${fmtClock(live.current ? live.current.t1 : 0, true)} · ${fmtDuration(live.simTime)}${warm}${live.state === 'paused' ? ' · пауза' : ''}`;
  }

  function renderChart() {
    const W = live.win;
    if (!live.running || !W || !W.t0.length) {
      chart.setData({ t0: [], pkts: [], risk: [], state: [] });
      return;
    }
    const from = Math.max(0, W.t0.length - VISIBLE);
    const sl = (a) => a.slice(from);
    const t0 = sl(W.t0);
    const incs = live.patterns.incidents.filter((i) => i.tDetect >= t0[0]).map((i) => ({ t: i.tDetect, sev: i.sev }));
    chart.setData({ t0, pkts: sl(W.pkts), risk: sl(W.risk), state: sl(W.state), attack: sl(W.attack), markers: incs });
  }

  function renderFeed() {
    const list = live.running || live.events?.length ? live.events || [] : [];
    const slot = qs('[data-feed]', view);
    qs('[data-feed-count]', view).textContent = list.length ? `${list.length}` : '';
    if (!list.length) {
      mount(slot, html`<li class="empty" style="padding:28px 16px"><p>События появятся после запуска.</p></li>`);
      return;
    }
    mount(slot, html`${list.slice(0, 40).map(feedItem)}`);
  }

  function renderAll() {
    renderControls();
    renderInject();
    renderCurrent();
    renderStrip();
    renderClock();
    renderChart();
    renderFeed();
    if (live.running && live.hosts) map.update(live.hosts, live.lastPairs, live.hotHosts());
  }

  const onWindow = () => {
    renderCurrent();
    renderStrip();
    renderClock();
    renderChart();
    renderInject();
    map.update(live.hosts, live.lastPairs, live.hotHosts());
  };
  const onState = () => renderAll();
  const onEvent = (e) => {
    const slot = qs('[data-feed]', view);
    if (slot.querySelector('.empty')) slot.replaceChildren();
    slot.insertAdjacentHTML('afterbegin', feedItem(e.detail).s);
    while (slot.children.length > 40) slot.lastElementChild.remove();
    qs('[data-feed-count]', view).textContent = String(live.events.length);
    if (reducedMotion()) slot.firstElementChild.style.animation = 'none';
  };
  live.addEventListener('window', onWindow);
  live.addEventListener('state', onState);
  live.addEventListener('event', onEvent);
  cleanups.push(() => {
    live.removeEventListener('window', onWindow);
    live.removeEventListener('state', onState);
    live.removeEventListener('event', onEvent);
  });

  cleanups.push(
    on(view, 'click', '[data-act]', async (_, el) => {
      const act = el.dataset.act;
      if (act === 'start') {
        live.start({ speed: live.speed });
      } else if (act === 'pause') live.pause();
      else if (act === 'resume') live.resume();
      else if (act === 'discard') {
        live.stop();
        toast('Сеанс сброшен без сохранения.');
      } else if (act === 'stop') {
        const report = live.stop();
        if (!report) {
          toast('Сеанс слишком короткий для отчёта.', { type: 'warning' });
          return;
        }
        try {
          await saveReport(report);
          toast('Сеанс мониторинга сохранён.', { type: 'success', action: { label: 'Открыть отчёт', onClick: () => ctx.navigate(`/reports/${report.id}`) } });
        } catch {
          toast('Не удалось сохранить отчёт: хранилище браузера недоступно.', { type: 'error' });
        }
      }
      qs('[data-controls] button', view)?.focus();
    }),
    on(view, 'click', '[data-speed]', (_, el) => {
      live.setSpeed(Number(el.dataset.speed));
      renderControls();
    }),
    on(view, 'click', '[data-inject-type]', (_, el) => {
      const rec = live.inject(el.dataset.injectType);
      if (rec) renderInject();
    }),
  );

  renderAll();
  return () => cleanups.forEach((c) => c());
}
