import { isIp } from '../core/net.js';
import { confirmDialog } from '../ui/dialog.js';
import { html, mount, on, qs } from '../ui/dom.js';
import { icon } from '../ui/icons.js';
import { DEFAULTS, SENSITIVITY, WINDOW_OPTIONS, getSettings, invalidCidrs, resetSettings, saveSettings, splitList } from '../ui/settings.js';
import { clearAll, storeState } from '../ui/store.js';
import { toast } from '../ui/toast.js';

const THEME_OPTS = [
  ['system', 'Как в системе'],
  ['light', 'Светлая'],
  ['dark', 'Тёмная'],
];
const MOTION_OPTS = [
  ['system', 'Как в системе'],
  ['reduce', 'Уменьшить движение'],
  ['full', 'Полная анимация'],
];

export async function render(view) {
  const draw = () => {
    const s = getSettings();
    mount(
      view,
      html`<div class="page-head"><div><p class="eyebrow">Параметры</p><h1 class="page-title" tabindex="-1">Настройки</h1>
        <p class="lead">Настройки хранятся в этом браузере и применяются к новым анализам и сеансам мониторинга.</p></div></div>
      <div class="stack" style="max-width:880px">
        <form class="panel" data-analysis novalidate aria-labelledby="an-h">
          <div class="panel-head"><div><h2 class="panel-title" id="an-h">Модель и анализ</h2><p class="panel-sub">Значения по умолчанию для анализа файлов и мониторинга</p></div></div>
          <div class="panel-body stack">
            <fieldset style="border:0;margin:0;padding:0">
              <legend class="field-label" style="margin-bottom:8px">Чувствительность</legend>
              <div class="grid cols-3">${Object.entries(SENSITIVITY).map(
                ([v, o]) => html`<label class="check panel" style="padding:12px;box-shadow:none"><input type="radio" name="sensitivity" value="${v}" ${s.sensitivity === v ? 'checked' : ''} />
                  <span><strong>${o.label}</strong> <span class="tag">×${o.value}</span><br /><span class="muted" style="font-size:13px">${o.hint}</span></span></label>`,
              )}</div>
            </fieldset>
            <div class="form-grid">
              <label class="field"><span>Размер окна по умолчанию</span>
                <select class="select" name="windowSize">${WINDOW_OPTIONS.map(([v, l]) => html`<option value="${v}" ${String(s.windowSize) === v ? 'selected' : ''}>${l}</option>`)}</select></label>
              <label class="field"><span>Порог тревоги (риск)</span>
                <input class="input" type="number" name="threshold" min="30" max="90" step="1" value="${s.threshold}" aria-describedby="thr-hint thr-err" />
                <small id="thr-hint">От 30 до 90; по умолчанию ${DEFAULTS.threshold}</small><span class="field-error" id="thr-err" hidden></span></label>
            </div>
            <label class="field"><span>Внутренние сети (CIDR)</span>
              <textarea class="textarea" name="internal" rows="4" spellcheck="false" aria-describedby="int-hint int-err">${s.internal}</textarea>
              <small id="int-hint">По одной подсети в строке. Трафик из них наружу учитывается как исходящий (утечки, маяки).</small><span class="field-error" id="int-err" hidden></span></label>
            <label class="field"><span>Исключения: доверенные адреса</span>
              <textarea class="textarea" name="allow" rows="3" spellcheck="false" placeholder="10.0.0.2&#10;192.168.1.50" aria-describedby="al-hint al-err">${s.allow}</textarea>
              <small id="al-hint">Сканеры уязвимостей, системы мониторинга, серверы резервного копирования — для них не создаются инциденты.</small><span class="field-error" id="al-err" hidden></span></label>
            <label class="check"><input type="checkbox" name="autosave" ${s.autosave ? 'checked' : ''} /><span>Автоматически сохранять результаты анализа файлов в «Отчёты»</span></label>
          </div>
          <div class="panel-foot row" style="justify-content:space-between"><span data-saved aria-live="polite"></span>
            <span class="row"><button class="btn" type="button" data-reset>Сбросить к умолчаниям</button><button class="btn btn-primary" type="submit">${icon('check', 16)} Сохранить</button></span></div>
        </form>

        <section class="panel" aria-labelledby="ap-h">
          <div class="panel-head"><div><h2 class="panel-title" id="ap-h">Оформление</h2><p class="panel-sub">Применяется сразу</p></div></div>
          <div class="panel-body grid cols-2">
            <fieldset style="border:0;margin:0;padding:0"><legend class="field-label" style="margin-bottom:6px">Тема</legend>
              ${THEME_OPTS.map(([v, l]) => html`<label class="check"><input type="radio" name="theme" value="${v}" data-appearance ${s.theme === v ? 'checked' : ''} /><span>${l}</span></label>`)}</fieldset>
            <fieldset style="border:0;margin:0;padding:0"><legend class="field-label" style="margin-bottom:6px">Анимация</legend>
              ${MOTION_OPTS.map(([v, l]) => html`<label class="check"><input type="radio" name="motion" value="${v}" data-appearance ${s.motion === v ? 'checked' : ''} /><span>${l}</span></label>`)}</fieldset>
          </div>
        </section>

        <section class="panel" aria-labelledby="dt-h">
          <div class="panel-head"><div><h2 class="panel-title" id="dt-h">Данные</h2><p class="panel-sub">${storeState.persistent ? 'Отчёты хранятся в IndexedDB этого браузера' : 'Хранилище недоступно — отчёты живут до закрытия вкладки'}</p></div></div>
          <div class="panel-body row" style="justify-content:space-between">
            <p class="ink-2" style="max-width:56ch">Удаление необратимо. Нужные отчёты можно предварительно экспортировать в JSON в разделе «Отчёты».</p>
            <button class="btn btn-danger" type="button" data-clear>${icon('trash', 16)} Удалить все отчёты</button>
          </div>
        </section>
      </div>`,
    );
  };
  draw();

  const setError = (name, msg) => {
    const map = { threshold: 'thr-err', internal: 'int-err', allow: 'al-err' };
    const err = qs(`#${map[name]}`, view);
    const field = qs(`[name="${name}"]`, view);
    err.hidden = !msg;
    err.textContent = msg || '';
    field.setAttribute('aria-invalid', String(Boolean(msg)));
    return Boolean(msg);
  };

  const onSubmit = (e) => {
    if (!e.target.matches('[data-analysis]')) return;
    e.preventDefault();
    const f = e.target;
    const threshold = Number(f.threshold.value);
    const bad = invalidCidrs(f.internal.value);
    const badIps = splitList(f.allow.value).filter((x) => !isIp(x));
    const errors = [
      setError('threshold', Number.isInteger(threshold) && threshold >= 30 && threshold <= 90 ? '' : 'Введите целое число от 30 до 90.'),
      setError('internal', bad.length ? `Не распознаны: ${bad.slice(0, 4).join(', ')}. Пример: 10.0.0.0/8` : splitList(f.internal.value).length ? '' : 'Укажите хотя бы одну подсеть.'),
      setError('allow', badIps.length ? `Не IP-адреса: ${badIps.slice(0, 4).join(', ')}` : ''),
    ];
    if (errors.some(Boolean)) {
      f.querySelector('[aria-invalid="true"]')?.focus();
      return;
    }
    saveSettings({
      sensitivity: f.sensitivity.value,
      windowSize: f.windowSize.value,
      threshold,
      internal: f.internal.value.trim(),
      allow: f.allow.value.trim(),
      autosave: f.autosave.checked,
    });
    qs('[data-saved]', view).textContent = 'Сохранено.';
    toast('Настройки сохранены.', { type: 'success', timeout: 2500 });
  };
  view.addEventListener('submit', onSubmit);

  const offs = [
    on(view, 'change', '[data-appearance]', (_, el) => saveSettings({ [el.name]: el.value })),
    on(view, 'click', '[data-reset]', async () => {
      const ok = await confirmDialog({ title: 'Сбросить настройки?', message: 'Чувствительность, окна, сети, исключения и оформление вернутся к значениям по умолчанию.', confirm: 'Сбросить' });
      if (!ok) return;
      resetSettings();
      draw();
      toast('Настройки сброшены.', { type: 'success' });
      qs('h1', view).focus();
    }),
    on(view, 'click', '[data-clear]', async () => {
      const ok = await confirmDialog({ title: 'Удалить все отчёты?', message: 'Все отчёты, сохранённые в этом браузере, будут удалены без возможности восстановления.', confirm: 'Удалить все', danger: true });
      if (!ok) return;
      await clearAll();
      toast('Все отчёты удалены.', { type: 'success' });
    }),
  ];

  return () => {
    view.removeEventListener('submit', onSubmit);
    offs.forEach((o) => o());
  };
}
