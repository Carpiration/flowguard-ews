import { MAX_FILE_SIZE } from '../core/ingest.js';
import { SCENARIOS } from '../core/simulate.js';
import { html, mount, on, qs } from '../ui/dom.js';
import { bindExportMenu, exportMenu } from '../ui/export-menu.js';
import { downloadBlob } from '../ui/export.js';
import { fmtBytes, fmtPct } from '../ui/format.js';
import { icon } from '../ui/icons.js';
import { runJob } from '../ui/jobs.js';
import { renderReport, reportSubtitle } from '../ui/report-view.js';
import { SENSITIVITY, WINDOW_OPTIONS, analysisOptions, getSettings } from '../ui/settings.js';
import { saveReport } from '../ui/store.js';
import { toast } from '../ui/toast.js';

const ACCEPT = '.pcap,.pcapng,.cap,.dmp,.csv,.tsv,.json,.ndjson,.jsonl,.log,.txt';

export const SYNTHETIC = [
  { id: 'office', icon: 'layers', name: 'Офисная сеть: 7 сценариев атак', desc: '20 минут, разметка — все типы угроз и оценка качества', sample: { seed: 42, duration: 1200 } },
  {
    id: 'slow',
    icon: 'radar',
    name: 'Медленное сканирование и утечка',
    desc: '10 минут — нарастающие атаки, проверка раннего обнаружения',
    sample: { seed: 7, duration: 600, schedule: [{ type: 'portscan', t0: 200 }, { type: 'exfil', t0: 420 }] },
  },
  { id: 'clean', icon: 'shield', name: 'Только нормальный трафик', desc: '10 минут без атак — проверка ложных тревог', sample: { seed: 11, duration: 600, schedule: [] } },
];

export const SAMPLE_FILES = [
  { file: 'office-attacks.pcap', icon: 'file', desc: 'PCAP · сканирование портов, подбор SSH, утечка' },
  { file: 'covert-channels.pcapng', icon: 'repeat', desc: 'PCAPNG · C2-маяк и DNS-туннель' },
  { file: 'zeek-conn-labeled.csv', icon: 'table', desc: 'Zeek conn.log в CSV, с разметкой атак' },
  { file: 'suricata-eve.ndjson', icon: 'code', desc: 'Suricata EVE (NDJSON) · утечка данных' },
  { file: 'tcpdump-scan.txt', icon: 'pulse', desc: 'Текстовый вывод tcpdump -n · сканирование' },
];

const STAGES = [
  ['read', 'Чтение и разбор источника'],
  ['features', 'Признаки временных окон и сигнатуры'],
  ['model', 'Обучение Isolation Forest и детекторы'],
  ['report', 'Формирование отчёта'],
];

// Последний результат сохраняется на время сеанса: при возврате на страницу он снова показывается.
let last = null;
let active = null;

export async function render(view, _params, ctx) {
  const cleanups = [];
  let opts = { windowSize: getSettings().windowSize, sensitivity: getSettings().sensitivity };

  const head = (title, lead, actions = '') => html`<div class="page-head">
      <div><p class="eyebrow">Анализ записи трафика</p><h1 class="page-title" tabindex="-1">${title}</h1>${lead ? html`<p class="lead">${lead}</p>` : ''}</div>
      ${actions ? html`<div class="btn-group no-print">${actions}</div>` : ''}
    </div>`;

  function showIdle(error = null) {
    cleanups.splice(0).forEach((c) => c());
    mount(
      view,
      html`${head('Анализ файла', 'Загрузите захват трафика или журнал сетевых потоков. Файл обрабатывается в фоновом потоке этого браузера и никуда не отправляется.')}
      ${error
        ? html`<div class="callout callout-error" role="alert" style="margin-bottom:16px">${icon('alert', 18)}<div><strong>Не удалось проанализировать «${error.name}».</strong> ${error.message}</div></div>`
        : ''}
      <div class="split">
        <div class="stack">
          <div class="dropzone reveal" role="button" tabindex="0" data-drop aria-describedby="drop-hint">
            <div class="dropzone-icon">${icon('upload', 26)}</div>
            <div class="dropzone-title">Перетащите файл сюда или выберите на устройстве</div>
            <p class="muted" id="drop-hint">До 2 ГБ. Формат определяется по содержимому файла.</p>
            <div class="formats">${['PCAP', 'PCAPNG', 'CSV', 'JSON / NDJSON', 'tcpdump -n'].map((f) => html`<span class="chip">${f}</span>`)}</div>
            <span class="btn btn-primary" aria-hidden="true">${icon('file', 16)} Выбрать файл</span>
            <input type="file" accept="${ACCEPT}" hidden data-input />
          </div>
          <section class="panel reveal" style="--i:1" aria-labelledby="opt-h">
            <div class="panel-head"><h2 class="panel-title" id="opt-h">Параметры анализа</h2><a class="section-note" href="#/settings">Внутренние сети и исключения</a></div>
            <div class="panel-body form-grid">
              <label class="field"><span>Размер окна</span>
                <select class="select" data-opt="windowSize">${WINDOW_OPTIONS.map(([v, l]) => html`<option value="${v}" ${String(opts.windowSize) === v ? 'selected' : ''}>${l}</option>`)}</select>
                <small>Автоматически: ~300 окон на запись</small></label>
              <label class="field"><span>Чувствительность</span>
                <select class="select" data-opt="sensitivity">${Object.entries(SENSITIVITY).map(([v, s]) => html`<option value="${v}" ${opts.sensitivity === v ? 'selected' : ''}>${s.label}</option>`)}</select>
                <small data-sens-hint>${SENSITIVITY[opts.sensitivity]?.hint}</small></label>
            </div>
          </section>
        </div>
        <section class="panel reveal" style="--i:2" aria-labelledby="samples-h">
          <div class="panel-head"><div><h2 class="panel-title" id="samples-h">Попробовать без своих данных</h2><p class="panel-sub">Сгенерированные наборы с известной разметкой атак</p></div></div>
          <div class="panel-body" style="padding-top:8px">
            <div class="sample-list">
              ${SYNTHETIC.map(
                (s) => html`<button class="sample" type="button" data-synthetic="${s.id}">
                  <span class="sample-icon">${icon(s.icon, 18)}</span>
                  <span><span class="sample-name">${s.name}</span><br /><span class="sample-desc">${s.desc}</span></span>
                  <span class="sample-go">${icon('arrowRight', 18)}</span>
                </button>`,
              )}
            </div>
            <h3 class="field-label" style="margin:18px 0 6px">Файлы-примеры разных форматов</h3>
            <div class="sample-list">
              ${SAMPLE_FILES.map(
                (s) => html`<div class="sample" style="cursor:default">
                  <span class="sample-icon">${icon(s.icon, 18)}</span>
                  <span style="min-width:0"><span class="sample-name mono">${s.file}</span><br /><span class="sample-desc">${s.desc}</span></span>
                  <span class="row" style="flex-wrap:nowrap">
                    <a class="btn btn-sm btn-ghost btn-icon" href="samples/${s.file}" download aria-label="Скачать ${s.file}" title="Скачать">${icon('download', 16)}</a>
                    <button class="btn btn-sm" type="button" data-sample-file="${s.file}">Анализ</button>
                  </span>
                </div>`,
              )}
            </div>
            <p class="hint" style="margin-top:12px">Нужен свой PCAP для экспериментов? <button class="btn btn-sm btn-ghost" type="button" data-gen-pcap>${icon('download', 14)} Сгенерировать PCAP (20 мин, 7 атак)</button></p>
          </div>
        </section>
      </div>`,
    );

    const drop = qs('[data-drop]', view);
    const input = qs('[data-input]', view);
    const pick = () => input.click();
    drop.addEventListener('click', pick);
    drop.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        pick();
      }
    });
    input.addEventListener('change', () => {
      if (input.files[0]) startFile(input.files[0]);
    });
    let depth = 0;
    drop.addEventListener('dragenter', (e) => {
      e.preventDefault();
      depth++;
      drop.classList.add('is-over');
    });
    drop.addEventListener('dragover', (e) => e.preventDefault());
    drop.addEventListener('dragleave', () => {
      if (--depth <= 0) {
        depth = 0;
        drop.classList.remove('is-over');
      }
    });
    drop.addEventListener('drop', (e) => {
      e.preventDefault();
      depth = 0;
      drop.classList.remove('is-over');
      const f = e.dataTransfer.files[0];
      if (f) startFile(f);
    });
    cleanups.push(
      on(view, 'change', '[data-opt]', (_, el) => {
        opts = { ...opts, [el.dataset.opt]: el.value };
        if (el.dataset.opt === 'sensitivity') qs('[data-sens-hint]', view).textContent = SENSITIVITY[el.value]?.hint || '';
      }),
      on(view, 'click', '[data-synthetic]', (_, el) => {
        const s = SYNTHETIC.find((x) => x.id === el.dataset.synthetic);
        start('analyzeSample', { sample: { ...s.sample, name: s.name } }, s.name);
      }),
      on(view, 'click', '[data-sample-file]', async (_, el) => {
        const name = el.dataset.sampleFile;
        el.disabled = true;
        try {
          const res = await fetch(`samples/${name}`);
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          startFile(new File([await res.blob()], name));
        } catch (err) {
          el.disabled = false;
          toast(`Не удалось загрузить пример: ${err.message}`, { type: 'error' });
        }
      }),
      on(view, 'click', '[data-gen-pcap]', async (_, el) => {
        el.disabled = true;
        try {
          const { promise } = runJob('samplePcap', { sample: { seed: 42, duration: 1200 } });
          downloadBlob(await promise, 'flowguard-office-7-attacks.pcap');
          toast('PCAP сформирован: 20 минут трафика, 7 атак. Его можно открыть в Wireshark.', { type: 'success' });
        } catch (err) {
          toast(err.message, { type: 'error' });
        } finally {
          if (el.isConnected) el.disabled = false;
        }
      }),
    );
  }

  function startFile(file) {
    if (file.size > MAX_FILE_SIZE) {
      showIdle({ name: file.name, message: 'Файл больше 2 ГБ. Разделите захват на части, например: editcap -c 1000000 big.pcap part.pcap' });
      return;
    }
    start('analyzeFile', { file }, file.name, fmtBytes(file.size));
  }

  function start(type, payload, name, sizeText = '') {
    cleanups.splice(0).forEach((c) => c());
    const options = analysisOptions({ windowSize: opts.windowSize, sensitivity: opts.sensitivity });
    mount(
      view,
      html`${head(name, sizeText ? `Размер ${sizeText}` : 'Синтетический набор с разметкой')}
      <section class="panel" aria-labelledby="prog-h" style="max-width:640px">
        <div class="panel-head"><h2 class="panel-title" id="prog-h">Идёт анализ</h2><span class="muted mono" data-pct aria-hidden="true">0%</span></div>
        <div class="panel-body">
          <div class="progress" role="progressbar" aria-label="Ход анализа" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><i style="--v:0"></i></div>
          <ol class="stages">${STAGES.map(([id, label]) => html`<li class="stage" data-stage="${id}"><span class="stage-mark">${icon('check', 12)}</span>${label}</li>`)}</ol>
          <p class="sr-only" aria-live="polite" data-live></p>
          <div class="row" style="margin-top:18px"><button class="btn" type="button" data-cancel>${icon('x', 16)} Отменить</button></div>
        </div>
      </section>`,
    );
    const bar = qs('.progress', view);
    const pct = qs('[data-pct]', view);
    const live = qs('[data-live]', view);
    const weights = { read: [0, 0.55], features: [0.55, 0.85], model: [0.85, 0.95], report: [0.95, 1] };
    let lastStage = '';
    const onProgress = (stage, value) => {
      const [a, b] = weights[stage] || [0, 1];
      const total = a + (b - a) * Math.min(1, Math.max(0, value || 0));
      bar.querySelector('i').style.setProperty('--v', total.toFixed(3));
      bar.setAttribute('aria-valuenow', String(Math.round(total * 100)));
      pct.textContent = fmtPct(total);
      if (stage !== lastStage) {
        lastStage = stage;
        let reached = false;
        for (const [id, label] of STAGES) {
          const li = qs(`[data-stage="${id}"]`, view);
          if (!li) continue;
          if (id === stage) {
            reached = true;
            li.className = 'stage is-active';
            live.textContent = `${label}…`;
          } else li.className = reached ? 'stage' : 'stage is-done';
        }
      }
    };
    onProgress('read', 0);
    const { job, promise } = runJob(type, { ...payload, options }, onProgress);
    active = job;
    qs('[data-cancel]', view).addEventListener('click', () => job.cancel());
    promise
      .then(async (report) => {
        if (active !== job) return;
        active = null;
        last = report;
        if (getSettings().autosave) {
          try {
            await saveReport(report);
            report.saved = true;
            toast('Отчёт сохранён в разделе «Отчёты».', { type: 'success', action: { label: 'Открыть', onClick: () => ctx.navigate(`/reports/${report.id}`) } });
          } catch {
            toast('Отчёт построен, но не сохранён: хранилище браузера недоступно.', { type: 'warning' });
          }
        }
        if (view.isConnected) showResult(report, true);
      })
      .catch((err) => {
        if (active !== job) return;
        active = null;
        if (!view.isConnected) return;
        if (err.cancelled) {
          showIdle();
          toast('Анализ отменён.');
        } else showIdle({ name, message: err.userFacing ? err.message : `Внутренняя ошибка: ${err.message}` });
        qs('h1', view)?.focus();
      });
  }

  function showResult(report, fresh = false) {
    cleanups.splice(0).forEach((c) => c());
    mount(
      view,
      html`${head(
        report.source?.name || 'Результат анализа',
        reportSubtitle(report),
        html`<button class="btn" type="button" data-new>${icon('upload', 16)} Новый анализ</button>${exportMenu()}${report.saved ? html`<a class="btn btn-ghost" href="#/reports/${report.id}">${icon('reports', 16)} В отчётах</a>` : ''}`,
      )}<div data-report></div>`,
    );
    const rv = renderReport(qs('[data-report]', view), report);
    cleanups.push(() => rv.destroy(), bindExportMenu(view, () => report));
    qs('[data-new]', view).addEventListener('click', () => {
      last = null;
      showIdle();
      qs('h1', view)?.focus();
    });
    if (fresh) qs('h1', view)?.focus();
  }

  if (last) showResult(last);
  else showIdle();

  return () => {
    cleanups.splice(0).forEach((c) => c());
    if (active) {
      active.cancel();
      active = null;
    }
  };
}

export { SCENARIOS };
