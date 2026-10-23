import { levelBadge } from '../ui/charts/widgets.js';
import { confirmDialog } from '../ui/dialog.js';
import { debounce, html, mount, on, qs, qsa } from '../ui/dom.js';
import { downloadBlob } from '../ui/export.js';
import { countText, fmtCompact, fmtDateTime, fmtDuration } from '../ui/format.js';
import { icon } from '../ui/icons.js';
import { deleteReports, getReport, isReport, listMeta, saveReport, storeState } from '../ui/store.js';
import { toast } from '../ui/toast.js';
import { KIND_NAMES } from './home.js';

const KINDS = [
  ['all', 'Все'],
  ['file', 'Файлы'],
  ['sample', 'Демо-наборы'],
  ['live', 'Мониторинг'],
  ['lab', 'Лаборатория'],
];
const SORTS = [
  ['new', 'Сначала новые'],
  ['old', 'Сначала старые'],
  ['risk', 'По риску'],
  ['inc', 'По числу инцидентов'],
];

export async function render(view) {
  const st = { q: '', kind: 'all', level: 'all', sort: 'new', selected: new Set(), page: 0 };
  let items = [];
  const cleanups = [];

  mount(
    view,
    html`<div class="page-head">
        <div><p class="eyebrow">Журнал</p><h1 class="page-title" tabindex="-1">Отчёты</h1>
          <p class="lead">Результаты анализа файлов, сеансов мониторинга и экспериментов. Отчёты хранятся в этом браузере; для переноса используйте экспорт и импорт JSON.</p></div>
        <div class="btn-group">
          <label class="btn">${icon('import', 16)} Импорт JSON<input type="file" accept=".json,application/json" hidden data-import multiple /></label>
          <a class="btn btn-primary" href="#/analyze">${icon('file', 16)} Новый анализ</a>
        </div>
      </div>
      ${storeState.persistent ? '' : html`<div class="callout callout-warning" style="margin-bottom:16px">${icon('alert', 18)}<div><strong>Хранилище браузера недоступно.</strong> Отчёты сохранятся только до закрытия вкладки — экспортируйте нужные.</div></div>`}
      <section class="panel" aria-label="Список отчётов">
        <div class="panel-body" style="padding-bottom:12px">
          <div class="row" style="gap:12px;justify-content:space-between">
            <label class="search" style="max-width:380px">${icon('search', 16)}<span class="sr-only">Поиск по названию</span><input class="input" type="search" placeholder="Поиск по названию" data-q autocomplete="off" /></label>
            <div class="row">
              <label class="sr-only" for="lvl">Уровень риска</label>
              <select class="select" id="lvl" data-level style="width:auto;min-height:36px">
                <option value="all">Любой риск</option><option value="critical">Критический</option><option value="high">Высокий</option><option value="medium">Умеренный</option><option value="low">Низкий</option>
              </select>
              <label class="sr-only" for="srt">Сортировка</label>
              <select class="select" id="srt" data-sort style="width:auto;min-height:36px">${SORTS.map(([v, l]) => html`<option value="${v}">${l}</option>`)}</select>
            </div>
          </div>
          <div class="row" role="group" aria-label="Тип источника" style="margin-top:12px" data-kinds></div>
        </div>
        <div class="table-tools" data-bulk hidden></div>
        <div data-list></div>
      </section>`,
  );

  function filtered() {
    const q = st.q.trim().toLowerCase();
    let list = items.filter((m) => (st.kind === 'all' || m.kind === st.kind) && (st.level === 'all' || m.level === st.level) && (!q || m.name.toLowerCase().includes(q)));
    const by = { new: (a, b) => b.createdAt - a.createdAt, old: (a, b) => a.createdAt - b.createdAt, risk: (a, b) => b.risk - a.risk, inc: (a, b) => b.incidents - a.incidents }[st.sort];
    return list.sort(by);
  }

  function renderKinds() {
    mount(
      qs('[data-kinds]', view),
      html`${KINDS.map(([v, l]) => {
        const n = v === 'all' ? items.length : items.filter((m) => m.kind === v).length;
        return v === 'all' || n ? html`<button class="chip chip-btn" type="button" data-kind="${v}" aria-pressed="${st.kind === v}">${l} · ${n}</button>` : '';
      })}`,
    );
  }

  function renderBulk() {
    const bulk = qs('[data-bulk]', view);
    bulk.hidden = st.selected.size === 0;
    mount(
      bulk,
      html`<span><strong>${countText(st.selected.size, 'отчёт выбран', 'отчёта выбрано', 'отчётов выбрано')}</strong></span>
        <button class="btn btn-sm" type="button" data-bulk-export>${icon('download', 15)} Экспорт JSON</button>
        <button class="btn btn-sm btn-danger" type="button" data-bulk-delete>${icon('trash', 15)} Удалить</button>
        <button class="btn btn-sm btn-ghost" type="button" data-bulk-clear>Снять выделение</button>`,
    );
  }

  function renderList() {
    const list = filtered();
    const slot = qs('[data-list]', view);
    if (!items.length) {
      mount(
        slot,
        html`<div class="empty"><div class="empty-icon">${icon('reports', 22)}</div><h3>Отчётов пока нет</h3>
          <p>Проанализируйте файл, демонстрационный набор или запустите мониторинг — отчёт появится здесь.</p>
          <div class="row" style="justify-content:center"><a class="btn btn-primary" href="#/analyze">Анализ файла</a><a class="btn" href="#/monitor">Мониторинг</a></div></div>`,
      );
      return;
    }
    if (!list.length) {
      mount(slot, html`<div class="empty"><div class="empty-icon">${icon('filter', 22)}</div><h3>Ничего не найдено</h3><p>Измените запрос или фильтры.</p><button class="btn" type="button" data-reset>Сбросить фильтры</button></div>`);
      return;
    }
    const size = 25;
    const pages = Math.ceil(list.length / size);
    st.page = Math.min(st.page, pages - 1);
    const page = list.slice(st.page * size, st.page * size + size);
    const allChecked = page.every((m) => st.selected.has(m.id));
    mount(
      slot,
      html`<div class="table-wrap" tabindex="0" aria-label="Таблица отчётов"><table class="data">
        <thead><tr>
          <th style="width:44px"><input type="checkbox" data-check-all aria-label="Выбрать все на странице" ${allChecked ? 'checked' : ''} /></th>
          <th>Название</th><th>Источник</th><th>Риск</th><th class="r">Инциденты</th><th class="r">Объём</th><th class="r">Длительность</th><th>Создан</th>
        </tr></thead>
        <tbody>${page.map(
          (m) => html`<tr>
            <td><input type="checkbox" data-check="${m.id}" aria-label="Выбрать «${m.name}»" ${st.selected.has(m.id) ? 'checked' : ''} /></td>
            <td style="max-width:360px"><a href="#/reports/${encodeURIComponent(m.id)}" style="font-weight:600">${m.name}</a>${m.labelled ? html` <span class="tag">разметка</span>` : ''}</td>
            <td class="nowrap">${KIND_NAMES[m.kind] || m.kind}<br /><span class="muted" style="font-size:12px">${m.format}</span></td>
            <td>${levelBadge(m.level, String(Math.round(m.risk)))}</td>
            <td class="r">${m.incidents}</td>
            <td class="r">${fmtCompact(m.packets)}</td>
            <td class="r">${fmtDuration(m.duration)}</td>
            <td class="nowrap">${fmtDateTime(m.createdAt)}</td>
          </tr>`,
        )}</tbody></table></div>
        <div class="pager"><span>${countText(list.length, 'отчёт', 'отчёта', 'отчётов')}</span>
          ${pages > 1
            ? html`<span class="row"><button class="btn btn-sm" type="button" data-page="-1" ${st.page === 0 ? 'disabled' : ''}>Назад</button><span>${st.page + 1} / ${pages}</span><button class="btn btn-sm" type="button" data-page="1" ${st.page >= pages - 1 ? 'disabled' : ''}>Вперёд</button></span>`
            : ''}</div>`,
    );
  }

  async function reload() {
    items = await listMeta();
    for (const id of [...st.selected]) if (!items.some((m) => m.id === id)) st.selected.delete(id);
    if (!view.isConnected) return;
    renderKinds();
    renderList();
    renderBulk();
  }

  const onQ = debounce((v) => {
    st.q = v;
    st.page = 0;
    renderList();
  }, 120);
  qs('[data-q]', view).addEventListener('input', (e) => onQ(e.target.value));
  qs('[data-level]', view).addEventListener('change', (e) => {
    st.level = e.target.value;
    st.page = 0;
    renderList();
  });
  qs('[data-sort]', view).addEventListener('change', (e) => {
    st.sort = e.target.value;
    renderList();
  });
  qs('[data-import]', view).addEventListener('change', async (e) => {
    let ok = 0;
    let bad = 0;
    for (const f of e.target.files) {
      try {
        const data = JSON.parse(await f.text());
        const list = Array.isArray(data) ? data : [data];
        for (const r of list) {
          if (isReport(r)) {
            await saveReport(r);
            ok++;
          } else bad++;
        }
      } catch {
        bad++;
      }
    }
    e.target.value = '';
    toast(ok ? `Импортировано: ${countText(ok, 'отчёт', 'отчёта', 'отчётов')}${bad ? `; не распознано: ${bad}` : ''}.` : 'Файл не содержит отчётов FlowGuard.', { type: ok ? 'success' : 'error' });
    reload();
  });

  cleanups.push(
    on(view, 'click', '[data-kind]', (_, el) => {
      st.kind = el.dataset.kind;
      st.page = 0;
      renderKinds();
      renderList();
    }),
    on(view, 'click', '[data-page]', (_, el) => {
      st.page += Number(el.dataset.page);
      renderList();
      qs('[data-list]', view).scrollIntoView({ block: 'start', behavior: 'smooth' });
    }),
    on(view, 'click', '[data-reset]', () => {
      st.q = '';
      st.kind = 'all';
      st.level = 'all';
      qs('[data-q]', view).value = '';
      qs('[data-level]', view).value = 'all';
      renderKinds();
      renderList();
    }),
    on(view, 'change', '[data-check]', (_, el) => {
      if (el.checked) st.selected.add(el.dataset.check);
      else st.selected.delete(el.dataset.check);
      renderBulk();
      const all = qs('[data-check-all]', view);
      if (all) all.checked = qsa('[data-check]', view).every((c) => c.checked);
    }),
    on(view, 'change', '[data-check-all]', (_, el) => {
      for (const c of qsa('[data-check]', view)) {
        c.checked = el.checked;
        if (el.checked) st.selected.add(c.dataset.check);
        else st.selected.delete(c.dataset.check);
      }
      renderBulk();
    }),
    on(view, 'click', '[data-bulk-clear]', () => {
      st.selected.clear();
      renderList();
      renderBulk();
    }),
    on(view, 'click', '[data-bulk-export]', async () => {
      const reports = (await Promise.all([...st.selected].map((id) => getReport(id)))).filter(Boolean);
      downloadBlob(new Blob([JSON.stringify(reports)], { type: 'application/json' }), `flowguard-reports-${reports.length}.json`);
    }),
    on(view, 'click', '[data-bulk-delete]', async () => {
      const n = st.selected.size;
      const ok = await confirmDialog({
        title: `Удалить ${countText(n, 'отчёт', 'отчёта', 'отчётов')}?`,
        message: 'Удаление необратимо: отчёты хранятся только в этом браузере. При необходимости сначала экспортируйте их в JSON.',
        confirm: 'Удалить',
        danger: true,
      });
      if (!ok) return;
      await deleteReports([...st.selected]);
      st.selected.clear();
      toast(`Удалено: ${countText(n, 'отчёт', 'отчёта', 'отчётов')}.`, { type: 'success' });
      reload();
    }),
  );

  await reload();
  return () => cleanups.forEach((c) => c());
}
