// Общее меню экспорта отчёта для страниц анализа, отчёта и лаборатории.

import { bindMenu } from './dialog.js';
import { html } from './dom.js';
import { exportHTML, exportIncidentsCSV, exportJSON, exportTimelineCSV, printReport } from './export.js';
import { icon } from './icons.js';
import { toast } from './toast.js';

export function exportMenu() {
  return html`<div class="menu" data-export-menu>
    <button class="btn" type="button" data-menu-button aria-haspopup="menu" aria-expanded="false">${icon('download', 16)} Экспорт ${icon('chevDown', 14)}</button>
    <div class="menu-list" role="menu" hidden>
      <button class="menu-item" role="menuitem" type="button" data-export="pdf">${icon('printer', 16)} Печать / PDF <small>A4</small></button>
      <button class="menu-item" role="menuitem" type="button" data-export="html">${icon('file', 16)} Отчёт HTML <small>автономный</small></button>
      <button class="menu-item" role="menuitem" type="button" data-export="csv-inc">${icon('table', 16)} Инциденты CSV <small>Excel</small></button>
      <button class="menu-item" role="menuitem" type="button" data-export="csv-tl">${icon('table', 16)} Временной ряд CSV <small>окна</small></button>
      <button class="menu-item" role="menuitem" type="button" data-export="json">${icon('code', 16)} Полный отчёт JSON <small>импорт</small></button>
    </div>
  </div>`;
}

export function bindExportMenu(root, getReport) {
  const el = root.querySelector('[data-export-menu]');
  if (!el) return () => {};
  const unbind = bindMenu(el);
  const onClick = (e) => {
    const b = e.target.closest('[data-export]');
    if (!b) return;
    const report = getReport();
    try {
      ({ json: exportJSON, html: exportHTML, 'csv-inc': exportIncidentsCSV, 'csv-tl': exportTimelineCSV, pdf: () => printReport() })[b.dataset.export](report);
      if (b.dataset.export !== 'pdf') toast('Файл сформирован и сохраняется браузером.', { type: 'success', timeout: 3000 });
    } catch (err) {
      toast(`Не удалось выполнить экспорт: ${err.message}`, { type: 'error' });
    }
  };
  el.addEventListener('click', onClick);
  return () => {
    unbind();
    el.removeEventListener('click', onClick);
  };
}
