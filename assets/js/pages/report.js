import { confirmDialog } from '../ui/dialog.js';
import { html, mount, qs } from '../ui/dom.js';
import { bindExportMenu, exportMenu } from '../ui/export-menu.js';
import { fmtDateTime } from '../ui/format.js';
import { icon } from '../ui/icons.js';
import { renderReport, reportSubtitle } from '../ui/report-view.js';
import { deleteReports, getReport } from '../ui/store.js';
import { toast } from '../ui/toast.js';
import { KIND_NAMES } from './home.js';

export async function render(view, params, ctx) {
  mount(view, html`<p class="muted">Загрузка отчёта…</p>`);
  let report = null;
  try {
    report = await getReport(params.id);
  } catch {
    report = null;
  }
  if (!view.isConnected) return null;
  if (!report) {
    ctx.setTitle('Отчёт не найден');
    mount(
      view,
      html`<div class="empty"><div class="empty-icon">${icon('reports', 22)}</div><h1 class="page-title" tabindex="-1">Отчёт не найден</h1>
        <p>Возможно, он удалён или сохранён в другом браузере: отчёты хранятся локально на устройстве.</p>
        <a class="btn btn-primary" href="#/reports">${icon('arrowLeft', 16)} К списку отчётов</a></div>`,
    );
    return null;
  }
  ctx.setTitle(report.source?.name || 'Отчёт');
  mount(
    view,
    html`<div class="page-head">
        <div>
          <p class="eyebrow">${KIND_NAMES[report.source?.kind] || 'Отчёт'} · ${fmtDateTime(report.createdAt)}</p>
          <h1 class="page-title" tabindex="-1">${report.source?.name || 'Отчёт'}</h1>
          <p class="lead">${reportSubtitle(report)}</p>
        </div>
        <div class="btn-group no-print">
          <a class="btn btn-ghost" href="#/reports">${icon('arrowLeft', 16)} Все отчёты</a>
          ${exportMenu()}
          <button class="btn btn-danger" type="button" data-delete>${icon('trash', 16)} Удалить</button>
        </div>
      </div>
      <div data-report></div>`,
  );
  const rv = renderReport(qs('[data-report]', view), report);
  const unbind = bindExportMenu(view, () => report);
  qs('[data-delete]', view).addEventListener('click', async () => {
    const ok = await confirmDialog({
      title: 'Удалить отчёт?',
      message: `Отчёт «${report.source?.name}» будет удалён из хранилища этого браузера без возможности восстановления. Перед удалением его можно экспортировать в JSON.`,
      confirm: 'Удалить',
      danger: true,
    });
    if (!ok) return;
    await deleteReports([report.id]);
    toast('Отчёт удалён.', { type: 'success' });
    ctx.navigate('/reports');
  });
  return () => {
    rv.destroy();
    unbind();
  };
}
