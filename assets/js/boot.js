// Применяет сохранённую тему до первой отрисовки, чтобы не было вспышки.
(function () {
  try {
    var s = JSON.parse(localStorage.getItem('fg.settings.v1') || '{}');
    var root = document.documentElement;
    if (s.theme === 'light' || s.theme === 'dark') root.setAttribute('data-theme', s.theme);
    if (s.motion === 'reduce' || s.motion === 'full') root.setAttribute('data-motion', s.motion);
  } catch (e) {
    /* хранилище недоступно — используется тема системы */
  }
})();
