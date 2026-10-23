import { confusion, metrics } from '../core/evaluate.js';
import { DEFAULT_SCHEDULE, SCENARIOS } from '../core/simulate.js';
import { TimelineChart } from '../ui/charts/timeline.js';
import { confusionMatrix, rocChart } from '../ui/charts/widgets.js';
import { html, mount, on, qs } from '../ui/dom.js';
import { downloadBlob } from '../ui/export.js';
import { fmt1, fmt2, fmtClock, fmtDuration, fmtPct } from '../ui/format.js';
import { icon } from '../ui/icons.js';
import { runJob } from '../ui/jobs.js';
import { SENSITIVITY, getSettings } from '../ui/settings.js';
import { saveReport } from '../ui/store.js';
import { toast } from '../ui/toast.js';

// Цвета вариантов закреплены за вариантом (не за позицией в списке).
const SLOT = { full: 1, static: 2, ewma: 3, cusum: 4, iforest: 7, patterns: 5 };
const DURATIONS = [
  [600, '10 минут'],
  [1200, '20 минут'],
  [1800, '30 минут'],
];

let lastResult = null;
let lastForm = null;

function scaledSchedule(duration, types) {
  const k = duration / 1200;
  return DEFAULT_SCHEDULE.filter((s) => types.includes(s.type)).map((s) => ({ type: s.type, t0: Math.round(s.t0 * k) }));
}

const pm = (v, f) => (v.sd !== null && v.sd !== undefined ? html`${f(v.mean)} <small>± ${f(v.sd)}</small>` : f(v.mean));

export async function render(view, _params, ctx) {
  const cleanups = [];
  const form = lastForm || {
    seed: 42,
    duration: 1200,
    runs: 3,
    sensitivity: getSettings().sensitivity,
    types: DEFAULT_SCHEDULE.map((s) => s.type),
  };
  let job = null;
  let chart = null;
  const hidden = new Set(['ewma', 'cusum']);

  mount(
    view,
    html`<div class="page-head">
        <div><p class="eyebrow">Экспериментальная оценка</p><h1 class="page-title" tabindex="-1">Оценка модели</h1>
          <p class="lead">Модель проверяется на синтетическом трафике офисной сети с известной разметкой атак. Сравниваются ансамбль FlowGuard,
          классический порог μ+3σ и каждый детектор по отдельности (абляция).</p></div>
      </div>
      <section class="panel" aria-labelledby="exp-h">
        <div class="panel-head"><div><h2 class="panel-title" id="exp-h">Параметры эксперимента</h2><p class="panel-sub">Одинаковый seed воспроизводит одинаковые данные и результаты</p></div></div>
        <form class="panel-body stack" data-form novalidate>
          <div class="form-grid">
            <label class="field"><span>Seed генератора</span><input class="input mono" type="number" name="seed" min="1" max="2147483646" step="1" value="${form.seed}" required aria-describedby="seed-err" /><span class="field-error" id="seed-err" hidden>Целое число от 1 до 2 147 483 646</span></label>
            <label class="field"><span>Длительность записи</span><select class="select" name="duration">${DURATIONS.map(([v, l]) => html`<option value="${v}" ${form.duration === v ? 'selected' : ''}>${l}</option>`)}</select></label>
            <label class="field"><span>Повторов (разные seed)</span><select class="select" name="runs">${[1, 3, 5, 10].map((v) => html`<option value="${v}" ${form.runs === v ? 'selected' : ''}>${v}</option>`)}</select></label>
            <label class="field"><span>Чувствительность</span><select class="select" name="sensitivity">${Object.entries(SENSITIVITY).map(([v, s]) => html`<option value="${v}" ${form.sensitivity === v ? 'selected' : ''}>${s.label}</option>`)}</select></label>
          </div>
          <fieldset style="border:0;padding:0;margin:0">
            <legend class="field-label" style="margin-bottom:8px">Сценарии атак</legend>
            <div class="form-grid" style="grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:4px 16px">
              ${DEFAULT_SCHEDULE.map(
                (s) => html`<label class="check"><input type="checkbox" name="types" value="${s.type}" ${form.types.includes(s.type) ? 'checked' : ''} /><span>${SCENARIOS[s.type].name}<br /><span class="muted" style="font-size:12.5px">${fmtDuration(SCENARIOS[s.type].duration)}</span></span></label>`,
              )}
            </div>
          </fieldset>
          <div class="row">
            <button class="btn btn-primary" type="submit" data-run>${icon('play', 16)} Запустить эксперимент</button>
            <span class="muted" data-status aria-live="polite"></span>
          </div>
        </form>
      </section>
      <div class="callout" style="margin-top:16px">${icon('info', 18)}<div><strong>Как читать результаты.</strong> Синтетические данные построены по известным
        закономерностям атак, поэтому метрики здесь оптимистичнее, чем на реальной сети. Для независимой проверки загрузите размеченный набор
        (например, CSV из CICIDS2017 или UNSW-NB15) на странице <a href="#/analyze">«Анализ файла»</a> — отчёт посчитает те же метрики по вашей разметке.</div></div>
      <div data-results></div>`,
  );

  const formEl = qs('[data-form]', view);
  const status = qs('[data-status]', view);

  function readForm() {
    const fd = new FormData(formEl);
    const seed = Number(fd.get('seed'));
    const valid = Number.isInteger(seed) && seed >= 1 && seed <= 2147483646;
    const seedInput = formEl.elements.seed;
    seedInput.setAttribute('aria-invalid', String(!valid));
    qs('#seed-err', view).hidden = valid;
    if (!valid) {
      seedInput.focus();
      return null;
    }
    return {
      seed,
      duration: Number(fd.get('duration')),
      runs: Number(fd.get('runs')),
      sensitivity: String(fd.get('sensitivity')),
      types: fd.getAll('types').map(String),
    };
  }

  formEl.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (job) return;
    const f = readForm();
    if (!f) return;
    lastForm = f;
    const btn = qs('[data-run]', view);
    btn.disabled = true;
    status.textContent = 'Генерация данных…';
    const stageNames = { generate: 'Генерация данных', features: 'Признаки и сигнатуры', model: 'Детекторы и метрики', report: 'Формирование отчёта' };
    const run = runJob(
      'lab',
      {
        options: {
          seed: f.seed,
          duration: f.duration,
          runs: f.runs,
          sensitivity: SENSITIVITY[f.sensitivity].value,
          threshold: Number(getSettings().threshold) || 50,
          schedule: scaledSchedule(f.duration, f.types),
        },
      },
      (stage, v) => {
        status.textContent = `${stageNames[stage] || stage}… ${fmtPct(Math.min(1, v || 0))}`;
      },
    );
    job = run.job;
    try {
      const res = await run.promise;
      lastResult = res;
      const full = res.summary.full;
      const st = res.summary.static;
      try {
        localStorage.setItem(
          'fg.lastLab',
          JSON.stringify({ f1: full.f1.mean, auc: full.auc.mean, staticF1: st.f1.mean, staticAuc: st.auc.mean, delay: full.delay.mean, runs: res.params.runs, at: Date.now() }),
        );
      } catch {
        /* нет доступа к хранилищу */
      }
      if (!view.isConnected) return;
      status.textContent = `Готово: ${res.params.runs} прогон(а), окно ${res.params.windowSize} с.`;
      showResults(res, true);
    } catch (err) {
      if (view.isConnected) status.textContent = err.cancelled ? 'Эксперимент отменён.' : '';
      if (!err.cancelled) toast(err.message, { type: 'error' });
    } finally {
      job = null;
      if (btn.isConnected) btn.disabled = false;
    }
  });

  function showResults(res, focus = false) {
    chart?.destroy();
    const slot = qs('[data-results]', view);
    const S = res.summary;
    const first = res.first;
    const rep = res.report;
    const abs = rep.stats.absoluteTime;
    const o = rep.stats.tStart;
    const multi = res.params.runs > 1;
    const delta = (a, b, better = 'higher', f = fmtPct) => {
      if (a === null || b === null) return '';
      const good = better === 'higher' ? a >= b : a <= b;
      return html`<span class="${good ? 'delta-good' : 'delta-bad'}">${better === 'higher' ? (a >= b ? '▲' : '▼') : a <= b ? '▼' : '▲'}</span> порог μ+3σ: ${f(b)}`;
    };
    mount(
      slot,
      html`<section class="section" aria-labelledby="res-h">
        <div class="section-head"><h2 class="section-title" id="res-h" tabindex="-1">Результаты</h2>
          <div class="btn-group">
            <button class="btn btn-sm" type="button" data-save>${icon('reports', 15)} Сохранить прогон как отчёт</button>
            <button class="btn btn-sm" type="button" data-export-csv>${icon('table', 15)} Таблица CSV</button>
            <button class="btn btn-sm" type="button" data-export-json>${icon('code', 15)} JSON</button>
          </div>
        </div>
        <div class="panel reveal">
          <div class="stat-row">
            <div class="stat"><span class="stat-label">F1-мера ансамбля</span><span class="stat-value">${pm(S.full.f1, (x) => fmtPct(x, 1))}</span><span class="stat-sub">${delta(S.full.f1.mean, S.static.f1.mean, 'higher', (x) => fmtPct(x, 1))}</span></div>
            <div class="stat"><span class="stat-label">ROC-AUC</span><span class="stat-value">${pm(S.full.auc, fmt2)}</span><span class="stat-sub">${delta(S.full.auc.mean, S.static.auc.mean, 'higher', fmt2)}</span></div>
            <div class="stat"><span class="stat-label">Средняя задержка обнаружения</span><span class="stat-value">${fmtDuration(S.full.delay.mean)}</span><span class="stat-sub">${delta(S.full.delay.mean, S.static.delay.mean, 'lower', fmtDuration)}</span></div>
            <div class="stat"><span class="stat-label">Обнаружено сценариев</span><span class="stat-value">${fmtPct(S.full.detectionRate.mean)}</span><span class="stat-sub">${delta(S.full.detectionRate.mean, S.static.detectionRate.mean)}</span></div>
            <div class="stat"><span class="stat-label">Ложных тревог в час</span><span class="stat-value">${fmt1(S.full.falsePerHour.mean)}</span><span class="stat-sub">${delta(S.full.falsePerHour.mean, S.static.falsePerHour.mean, 'lower', fmt1)}</span></div>
          </div>
          <div class="panel-foot">${multi ? `Среднее ± стандартное отклонение по ${res.params.runs} прогонам (seed ${res.runs.map((r) => r.seed).join(', ')}).` : `Один прогон, seed ${res.params.seed}.`}
            Окно ${res.params.windowSize} с; ${res.params.buffer} с после каждой атаки исключены из оценки по окнам.</div>
        </div>

        <div class="grid cols-2" style="margin-top:16px">
          <section class="panel reveal" style="--i:1" aria-labelledby="roc-h">
            <div class="panel-head"><div><h3 class="panel-title" id="roc-h">ROC-кривые (прогон 1)</h3><p class="panel-sub">Нажмите на элемент легенды, чтобы скрыть или показать вариант</p></div></div>
            <div class="panel-body">
              <div class="legend" style="margin-bottom:8px" data-roc-legend></div>
              <div data-roc></div>
            </div>
          </section>
          <section class="panel reveal" style="--i:2" aria-labelledby="thr-h">
            <div class="panel-head"><div><h3 class="panel-title" id="thr-h">Порог тревоги</h3><p class="panel-sub">Компромисс полноты и ложных срабатываний (прогон 1)</p></div>
              <label class="sr-only" for="var-sel">Вариант</label>
              <select class="select" id="var-sel" data-variant style="width:auto;min-height:34px">${res.variants.map((v) => html`<option value="${v.id}">${v.name}</option>`)}</select>
            </div>
            <div class="panel-body stack">
              <label class="field"><span>Порог: <b data-tau-val>${res.params.threshold}</b></span>
                <input class="range" type="range" min="1" max="99" step="1" value="${res.params.threshold}" data-tau aria-describedby="tau-hint" /></label>
              <p class="hint" id="tau-hint">Окно считается тревожным, если оценка не ниже порога.</p>
              <div data-tau-metrics></div>
            </div>
          </section>
        </div>

        <section class="panel reveal" style="--i:3;margin-top:16px" aria-labelledby="abl-h">
          <div class="panel-head"><div><h3 class="panel-title" id="abl-h">Абляция и сравнение подходов</h3><p class="panel-sub">Вклад каждого детектора и сравнение с классическим пороговым методом${multi ? ' (среднее по прогонам)' : ''}</p></div></div>
          <div class="panel-body flush"><div class="table-wrap" tabindex="0" aria-label="Таблица сравнения вариантов"><table class="data">
            <thead><tr><th>Вариант</th><th class="r">Точность</th><th class="r">Полнота</th><th class="r">F1</th><th class="r">ROC-AUC</th><th class="r">Задержка</th><th class="r">Обнаружено</th><th class="r">Ложных/ч</th></tr></thead>
            <tbody>${res.variants.map(
              (v) => html`<tr>
                <td><span class="legend-item"><i class="legend-swatch" style="--c:var(--series-${SLOT[v.id]})"></i><strong>${v.name}</strong></span></td>
                <td class="r">${fmtPct(S[v.id].precision.mean, 1)}</td><td class="r">${fmtPct(S[v.id].recall.mean, 1)}</td>
                <td class="r"><strong>${fmtPct(S[v.id].f1.mean, 1)}</strong></td><td class="r">${fmt2(S[v.id].auc.mean)}</td>
                <td class="r">${fmtDuration(S[v.id].delay.mean)}</td><td class="r">${fmtPct(S[v.id].detectionRate.mean)}</td><td class="r">${fmt1(S[v.id].falsePerHour.mean)}</td>
              </tr>`,
            )}</tbody></table></div></div>
        </section>

        <section class="panel reveal" style="--i:4;margin-top:16px" aria-labelledby="sc-h">
          <div class="panel-head"><div><h3 class="panel-title" id="sc-h">Задержка обнаружения по сценариям (прогон 1)</h3><p class="panel-sub">Время от начала атаки до первого сигнала. «Сигнатура» — сработал детектор именно этого типа атаки</p></div></div>
          <div class="panel-body flush"><div class="table-wrap" tabindex="0" aria-label="Таблица задержек по сценариям"><table class="data">
            <thead><tr><th>Сценарий</th><th>Начало</th><th class="r">Предупреждение</th><th class="r">Сигнатура</th><th class="r">Тревога: ансамбль</th><th class="r">Порог μ+3σ</th><th class="r">Только CUSUM</th><th class="r">Только IF</th></tr></thead>
            <tbody>${res.scenarios.map(
              (s) => html`<tr>
                <td><strong>${s.name}</strong><br /><span class="muted host">${s.attacker} → ${s.target}</span></td>
                <td class="nowrap">${fmtClock(s.t0, abs, o)}</td>
                <td class="r">${s.warnDelay === null ? '—' : fmtDuration(s.warnDelay)}</td>
                <td class="r">${s.typed.detected ? html`${fmtDuration(s.typed.delay)}` : html`<span class="muted">нет</span>`}</td>
                ${['full', 'static', 'cusum', 'iforest'].map((k) => html`<td class="r">${s.delays[k] === null ? html`<span class="delta-bad">пропуск</span>` : fmtDuration(s.delays[k])}</td>`)}
              </tr>`,
            )}</tbody></table></div></div>
        </section>

        <section class="panel reveal" style="--i:5;margin-top:16px" aria-labelledby="lt-h">
          <div class="panel-head"><div><h3 class="panel-title" id="lt-h">Риск во времени: ансамбль против порога μ+3σ (прогон 1)</h3><p class="panel-sub">Серые полосы — периоды атак по разметке</p></div></div>
          <div class="panel-body">
            <div class="legend" style="margin-bottom:10px">
              <span class="legend-item"><i class="legend-swatch area" style="--c:var(--series-1)"></i>Пакетов в секунду</span>
              <span class="legend-item"><i class="legend-swatch" style="--c:var(--ink)"></i>Риск ансамбля</span>
              <span class="legend-item"><i class="legend-swatch" style="--c:var(--series-2)"></i>Оценка порога μ+3σ</span>
              <span class="legend-item"><i class="legend-swatch band" style="--c:color-mix(in srgb, var(--ink) 14%, transparent)"></i>Атака по разметке</span>
              <span class="legend-item"><i class="legend-swatch band" style="--c:var(--warning)"></i>Предупреждение</span>
              <span class="legend-item"><i class="legend-swatch band" style="--c:var(--critical)"></i>Тревога</span>
            </div>
            <div data-lab-timeline></div>
          </div>
        </section>
      </section>`,
    );

    const renderRoc = () => {
      mount(
        qs('[data-roc-legend]', slot),
        html`${res.variants.map(
          (v) => html`<button type="button" class="legend-item legend-toggle" data-roc-toggle="${v.id}" aria-pressed="${!hidden.has(v.id)}"><i class="legend-swatch" style="--c:var(--series-${SLOT[v.id]})"></i>${v.name} · ${fmt2(first.metrics[v.id].auc)}</button>`,
        )}`,
      );
      rocChart(
        qs('[data-roc]', slot),
        res.variants.map((v) => ({ name: v.name, points: first.roc[v.id], auc: first.metrics[v.id].auc, slot: SLOT[v.id], hidden: hidden.has(v.id) })),
      );
    };
    renderRoc();

    showTau();

    chart = new TimelineChart(qs('[data-lab-timeline]', slot), {
      height: 320,
      tau: res.params.threshold,
      absolute: abs,
      origin: o,
      w: res.params.windowSize,
      label: 'Риск ансамбля и оценка статического порога во времени',
    });
    chart.setData(
      {
        t0: rep.timeline.t0,
        pkts: rep.timeline.pkts,
        risk: rep.timeline.risk,
        state: rep.timeline.state,
        attack: rep.timeline.attack,
        markers: rep.incidents.map((i) => ({ t: i.tDetect, sev: i.sev })),
        compare: [{ name: 'Порог μ+3σ', values: first.scores.static, slot: 1 }],
      },
      { animate: true },
    );

    if (focus) qs('#res-h', slot).focus();
  }

  cleanups.push(
    on(view, 'click', '[data-roc-toggle]', (_, el) => {
      const id = el.dataset.rocToggle;
      if (hidden.has(id)) hidden.delete(id);
      else hidden.add(id);
      const res = lastResult;
      el.setAttribute('aria-pressed', String(!hidden.has(id)));
      rocChart(
        qs('[data-roc]', view),
        res.variants.map((v) => ({ name: v.name, points: res.first.roc[v.id], auc: res.first.metrics[v.id].auc, slot: SLOT[v.id], hidden: hidden.has(v.id) })),
      );
    }),
    on(view, 'input', '[data-tau]', () => showTau()),
    on(view, 'change', '[data-variant]', () => showTau()),
    on(view, 'click', '[data-save]', async (_, el) => {
      el.disabled = true;
      try {
        const r = { ...lastResult.report };
        await saveReport(r);
        toast('Прогон сохранён как отчёт.', { type: 'success', action: { label: 'Открыть', onClick: () => ctx.navigate(`/reports/${r.id}`) } });
      } catch (err) {
        toast(`Не удалось сохранить: ${err.message}`, { type: 'error' });
        el.disabled = false;
      }
    }),
    on(view, 'click', '[data-export-json]', () => {
      const { report, ...rest } = lastResult;
      downloadBlob(new Blob([JSON.stringify({ ...rest, incidents: report.incidents })], { type: 'application/json' }), `flowguard-lab-seed${lastResult.params.seed}.json`);
    }),
    on(view, 'click', '[data-export-csv]', () => {
      const S = lastResult.summary;
      const num = (x) => (x === null || x === undefined ? '' : String(Math.round(x * 10000) / 10000).replace('.', ','));
      const rows = [['Вариант', 'Точность', 'Полнота', 'F1', 'F1 ст.откл.', 'ROC-AUC', 'Задержка, с', 'Обнаружено сценариев', 'Ложных тревог в час']];
      for (const v of lastResult.variants) {
        const s = S[v.id];
        rows.push([v.name, num(s.precision.mean), num(s.recall.mean), num(s.f1.mean), num(s.f1.sd), num(s.auc.mean), num(s.delay.mean), num(s.detectionRate.mean), num(s.falsePerHour.mean)]);
      }
      const text = `﻿${rows.map((r) => r.join(';')).join('\r\n')}\r\n`;
      downloadBlob(new Blob([text], { type: 'text/csv;charset=utf-8' }), `flowguard-lab-seed${lastResult.params.seed}.csv`);
    }),
  );

  function showTau() {
    const slot = qs('[data-results]', view);
    const res = lastResult;
    if (!res) return;
    const tau = Number(qs('[data-tau]', slot).value);
    const id = qs('[data-variant]', slot).value;
    qs('[data-tau-val]', slot).textContent = tau;
    const m = metrics(confusion(res.first.scores[id], res.first.labels, tau, res.first.mask));
    mount(
      qs('[data-tau-metrics]', slot),
      html`<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:8px">
          ${[['Точность', fmtPct(m.precision, 1)], ['Полнота', fmtPct(m.recall, 1)], ['F1', fmtPct(m.f1, 1)], ['Доля ложных', fmtPct(m.fpr, 1)]].map(
            ([l, v]) => html`<div class="kv" style="display:block"><div><dt>${l}</dt><dd>${v}</dd></div></div>`,
          )}
        </div>
        ${confusionMatrix(m)}`,
    );
  }

  if (lastResult) showResults(lastResult);

  return () => {
    cleanups.forEach((c) => c());
    chart?.destroy();
    job?.cancel();
  };
}
