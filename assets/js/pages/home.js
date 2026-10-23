import { THREATS } from '../core/catalog.js';
import { FEATURES } from '../core/features.js';
import { HeroField } from '../ui/charts/hero.js';
import { levelBadge } from '../ui/charts/widgets.js';
import { html, mount, qs } from '../ui/dom.js';
import { fmt2, fmtDateTime, fmtDuration, fmtPct } from '../ui/format.js';
import { icon } from '../ui/icons.js';
import { sevBadge } from '../ui/report-view.js';
import { listMeta } from '../ui/store.js';

export const KIND_NAMES = { file: 'Файл', sample: 'Демо-набор', live: 'Мониторинг', lab: 'Лаборатория' };

export function lastLab() {
  try {
    return JSON.parse(localStorage.getItem('fg.lastLab') || 'null');
  } catch {
    return null;
  }
}

export async function render(view) {
  const threats = Object.entries(THREATS).filter(([id]) => id !== 'flood');
  mount(
    view,
    html`<section class="hero reveal" aria-labelledby="hero-title">
        <div class="hero-grid">
          <div>
            <p class="eyebrow">Модель раннего выявления рисков</p>
            <h1 class="hero-title" id="hero-title" tabindex="-1">Риск виден <em>раньше</em>, чем атака достигает пика</h1>
            <p class="hero-lead">
              FlowGuard разбивает сетевой трафик на временные окна, сравнивает их с адаптивной нормой и объединяет четыре
              детектора в объяснимую оценку риска 0–100. Медленные атаки замечаются по накоплению малых отклонений — до того,
              как их увидит классический пороговый метод.
            </p>
            <div class="hero-actions">
              <a class="btn btn-primary btn-lg" href="#/analyze">${icon('file', 18)} Проанализировать файл</a>
              <a class="btn btn-lg" href="#/monitor">${icon('pulse', 18)} Запустить мониторинг</a>
              <a class="btn btn-ghost btn-lg" href="#/lab">${icon('flask', 18)} Оценка модели</a>
            </div>
          </div>
          <dl class="hero-facts">
            <div class="hero-fact"><dt>Детекторы</dt><dd>EWMA-z · CUSUM · Isolation Forest · поведенческие сигнатуры</dd></div>
            <div class="hero-fact"><dt>Источники</dt><dd>PCAP, PCAPNG, CSV (Wireshark, Zeek, CICIDS, UNSW-NB15), JSON/NDJSON, tcpdump</dd></div>
            <div class="hero-fact"><dt>Конфиденциальность</dt><dd>Вычисления в браузере — файлы не передаются на сервер</dd></div>
          </dl>
        </div>
        <div class="hero-canvas-wrap">
          <canvas class="hero-canvas" aria-label="Иллюстрация: в одном из потоков трафика нарастает аномалия, модель сначала выдаёт предупреждение, затем тревогу" role="img"></canvas>
          <div class="hero-legend" aria-hidden="true">
            <span class="legend-item"><i class="legend-swatch dot" style="--c:var(--ink-3)"></i>норма</span>
            <span class="legend-item"><i class="legend-swatch dot" style="--c:var(--warning)"></i>раннее предупреждение</span>
            <span class="legend-item"><i class="legend-swatch dot" style="--c:var(--critical)"></i>тревога</span>
          </div>
        </div>
      </section>

      <section class="section" aria-labelledby="how-h">
        <div class="section-head"><h2 class="section-title" id="how-h">Как работает модель</h2><a class="section-note" href="#/method">Подробная методология ${icon('arrowRight', 14)}</a></div>
        <div class="panel pipeline reveal" style="--i:1">
          <div class="pipe-step"><h3>Разбор источника</h3><p>Пакеты и потоки читаются потоково в фоновом потоке; формат определяется по сигнатуре, а не по расширению.</p></div>
          <div class="pipe-step"><h3>Признаки окна</h3><p>${FEATURES.length} признаков на окно: объём, источники, порты, попытки соединения, DNS, исходящий трафик, энтропия портов.</p></div>
          <div class="pipe-step"><h3>Ансамбль детекторов</h3><p>Отклонение от адаптивной нормы, накопленный сдвиг CUSUM, Isolation Forest и сигнатуры поведения атакующего.</p></div>
          <div class="pipe-step"><h3>Риск и объяснение</h3><p>Оценка 0–100 с фазой раннего предупреждения, доказательствами, MITRE ATT&CK и рекомендациями.</p></div>
        </div>
      </section>

      <div class="section split">
        <section aria-labelledby="threats-h">
          <div class="section-head"><h2 class="section-title" id="threats-h">Что обнаруживает</h2><span class="section-note">Сигнатуры с привязкой к MITRE ATT&CK</span></div>
          <div class="panel reveal" style="--i:2">
            <ul class="threat-list">
              ${threats.map(
                ([, t]) => html`<li class="threat">
                  <span class="threat-icon">${icon(t.icon, 18)}</span>
                  <span><span class="threat-name">${t.name}</span><br /><span class="threat-meta">MITRE ${t.mitre}</span></span>
                  ${sevBadge(t.sev)}
                </li>`,
              )}
            </ul>
          </div>
        </section>
        <div class="stack">
          <section aria-labelledby="recent-h">
            <div class="section-head"><h2 class="section-title" id="recent-h">Последние отчёты</h2><a class="section-note" href="#/reports">Все отчёты</a></div>
            <div class="panel reveal" style="--i:3" data-slot="recent"><div class="panel-body muted">Загрузка…</div></div>
          </section>
          <section aria-labelledby="lab-h">
            <div class="section-head"><h2 class="section-title" id="lab-h">Качество модели</h2></div>
            <div class="panel reveal" style="--i:4" data-slot="lab"></div>
          </section>
        </div>
      </div>`,
  );

  const hero = new HeroField(qs('.hero-canvas', view));

  const lab = lastLab();
  mount(
    qs('[data-slot="lab"]', view),
    lab
      ? html`<div class="stat-row">
            <div class="stat"><span class="stat-label">F1 ансамбля</span><span class="stat-value">${fmtPct(lab.f1, 1)}</span><span class="stat-sub">порог μ+3σ: ${fmtPct(lab.staticF1, 1)}</span></div>
            <div class="stat"><span class="stat-label">ROC-AUC</span><span class="stat-value">${fmt2(lab.auc)}</span><span class="stat-sub">порог μ+3σ: ${fmt2(lab.staticAuc)}</span></div>
          </div>
          <div class="panel-foot">Средняя задержка обнаружения ${fmtDuration(lab.delay)} · ${lab.runs} прогон(а) · ${fmtDateTime(lab.at)} · <a href="#/lab">открыть лабораторию</a></div>`
      : html`<div class="panel-body stack">
          <p class="ink-2">Запустите эксперимент на размеченных синтетических данных: точность, полнота, ROC-AUC, задержка обнаружения и сравнение с классическим порогом.</p>
          <div><a class="btn" href="#/lab">${icon('flask', 16)} Открыть лабораторию</a></div>
        </div>`,
  );

  try {
    const items = (await listMeta()).slice(0, 5);
    if (!view.isConnected) return () => hero.destroy();
    mount(
      qs('[data-slot="recent"]', view),
      items.length
        ? html`${items.map(
            (m) => html`<a class="report-link" href="#/reports/${encodeURIComponent(m.id)}">
              ${levelBadge(m.level, String(Math.round(m.risk)))}
              <span style="min-width:0"><span class="report-name">${m.name}</span><br /><span class="muted" style="font-size:12.5px">${KIND_NAMES[m.kind] || ''} · ${fmtDateTime(m.createdAt)} · инцидентов: ${m.incidents}</span></span>
              <span class="sample-go">${icon('chevRight', 18)}</span>
            </a>`,
          )}`
        : html`<div class="empty"><div class="empty-icon">${icon('reports', 22)}</div><h3>Отчётов пока нет</h3><p>Проанализируйте файл или демонстрационный набор — отчёт сохранится здесь.</p><a class="btn btn-primary" href="#/analyze">Начать анализ</a></div>`,
    );
  } catch {
    mount(qs('[data-slot="recent"]', view), html`<div class="panel-body muted">Хранилище отчётов недоступно в этом браузере.</div>`);
  }

  return () => hero.destroy();
}
