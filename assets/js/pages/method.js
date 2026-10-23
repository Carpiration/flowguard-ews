import { THREATS } from '../core/catalog.js';
import { FEATURES } from '../core/features.js';
import { LEVELS, PARAMS } from '../core/score.js';
import { html, mount, qsa, raw } from '../ui/dom.js';
import { fmt2 } from '../ui/format.js';

// Число с десятичной запятой, без лишних нулей.
const dec = (x) => String(x).replace('.', ',');

const FEATURE_DESC = {
  pkts: 'Число пакетов (для потоков — сумма пакетов в записях) за окно',
  bytes: 'Суммарный объём трафика, байт',
  srcs: 'Число различных адресов-источников',
  dsts: 'Число различных адресов назначения',
  ports: 'Число различных портов назначения среди попыток обращения',
  conns: 'TCP SYN без ACK или новые записи потоков — попытки установить соединение',
  rst: 'Пакеты с флагом RST: отказы и сбросы соединений',
  icmp: 'Сообщения ICMP и ICMPv6',
  dns: 'DNS-запросы (разбор DNS или поле query источника)',
  ext: 'Объём, переданный из внутренних сетей во внешние',
  newp: 'Пары «источник → получатель», ранее не встречавшиеся в записи',
  ent: 'Энтропия Шеннона распределения портов назначения, бит',
  avg: 'Средний размер пакета, байт',
};

const SIGNATURES = [
  ['portscan', '≥ 15 разных портов одного узла за 60 с; ≥ 30% попыток без SYN-ACK (или ≥ 60 портов)'],
  ['sweep', '≥ 12 узлов за 60 с: ICMP echo, SYN без ответа или SYN к внутренним узлам'],
  ['synflood', '≥ 80 SYN/с на узел, ≥ 40% без ответа; много источников — распределённая атака'],
  ['flood', '≥ 400 пакетов/с на узел от ≥ 10 источников и ≥ 50% всех пакетов окна'],
  ['bruteforce', '≥ 12 попыток соединения к службе аутентификации (SSH, RDP, SMB, СУБД…) за 60 с'],
  ['exfil', '≥ 3 МБ из внутренней сети на внешний адрес за 60 с при отношении исходящий/входящий ≥ 3'],
  ['beacon', '≥ 8 соединений к одному адресу и порту; медианный период 2 с – 1 ч; коэффициент вариации интервалов ≤ 0,1'],
  ['dnstunnel', '≥ 25 запросов к домену за 60 с; ≥ 60% уникальных имён; длина поддомена ≥ 20 или энтропия ≥ 3,5 бит'],
  ['susport', '≥ 3 пакетов к порту, связанному с бэкдорами, IRC-ботнетами или Tor'],
];

const SECTIONS = [
  ['task', 'Постановка задачи'],
  ['pipeline', 'Конвейер обработки'],
  ['features', 'Признаки окна'],
  ['ewma', 'Адаптивная норма (EWMA)'],
  ['cusum', 'Раннее предупреждение (CUSUM)'],
  ['iforest', 'Isolation Forest'],
  ['signatures', 'Поведенческие сигнатуры'],
  ['fusion', 'Оценка риска'],
  ['evaluation', 'Методика оценки'],
  ['limits', 'Ограничения и развитие'],
  ['refs', 'Литература'],
];

function pipelineSvg() {
  const box = (x, y, w, h, title, sub, accent = false) => `
    <g>
      <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="8" fill="${accent ? 'var(--accent-wash)' : 'var(--surface-2)'}" stroke="${accent ? 'var(--accent)' : 'var(--line-strong)'}"/>
      <text x="${x + w / 2}" y="${y + h / 2 - (sub ? 7 : 0)}" text-anchor="middle" dominant-baseline="middle" font-size="13" font-weight="600" fill="var(--ink)">${title}</text>
      ${sub ? `<text x="${x + w / 2}" y="${y + h / 2 + 11}" text-anchor="middle" dominant-baseline="middle" font-size="10.5" fill="var(--ink-3)" font-family="var(--font-mono)">${sub}</text>` : ''}
    </g>`;
  const arrow = (x1, y1, x2, y2) => `<path d="M${x1} ${y1} L${x2} ${y2}" stroke="var(--ink-3)" stroke-width="1.5" marker-end="url(#arr)" fill="none"/>`;
  const det = [
    ['EWMA-z', 'отклонение от нормы'],
    ['CUSUM', 'накопленный сдвиг'],
    ['Isolation Forest', 'многомерная аномалия'],
    ['Сигнатуры', 'поведение атакующего'],
  ];
  return `<svg viewBox="0 0 900 250" width="100%" role="img" aria-label="Схема: источник, разбор, окна признаков, четыре детектора, слияние в оценку риска, инциденты и отчёт" style="min-width:640px;font-family:var(--font-sans)">
    <defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="var(--ink-3)"/></marker></defs>
    ${box(10, 95, 110, 60, 'Источник', 'PCAP · CSV · JSON')}
    ${arrow(120, 125, 148, 125)}
    ${box(150, 95, 120, 60, 'Окна признаков', '13 признаков / окно')}
    ${arrow(270, 125, 300, 125)}
    ${det.map(([t, s], i) => box(302, 12 + i * 58, 190, 48, t, s)).join('')}
    ${det.map((_, i) => arrow(492, 36 + i * 58, 548, 125)).join('')}
    ${box(550, 95, 140, 60, 'Слияние', 'R = 0…100', true)}
    ${arrow(690, 125, 718, 125)}
    ${box(720, 60, 170, 50, 'Состояние', 'норма → предупр. → тревога')}
    ${box(720, 140, 170, 50, 'Инциденты', 'доказательства · ATT&CK')}
  </svg>`;
}

export async function render(view) {
  const P = PARAMS;
  mount(
    view,
    html`<div class="page-head"><div><p class="eyebrow">Модель</p><h1 class="page-title" tabindex="-1">Методология</h1>
      <p class="lead">Как FlowGuard превращает сетевой трафик в раннюю оценку риска: признаки, детекторы, слияние сигналов и методика проверки качества.
      Числа на этой странице берутся из кода модели и совпадают с реализацией.</p></div></div>
    <div class="doc">
      <nav class="toc" aria-label="Содержание">${SECTIONS.map(([id, t]) => html`<a href="#/method" data-to="${id}">${t}</a>`)}</nav>
      <article class="prose">
        <section id="task">
          <h2>Постановка задачи</h2>
          <p>Цель — <strong>раннее выявление рисков</strong>: сообщить оператору о развивающейся атаке до того, как она достигнет пика и нанесёт ущерб.
          Риск понимается как оценка вероятности того, что наблюдаемое поведение сети связано с вредоносной активностью, с учётом её важности.</p>
          <p>Требования к модели:</p>
          <ul>
            <li><strong>работа без разметки</strong> — норма изучается по самому трафику, обучающая выборка атак не требуется;</li>
            <li><strong>причинность</strong> — решение в момент окна принимается только по прошлым данным, поэтому задержка обнаружения честная;</li>
            <li><strong>объяснимость</strong> — каждый сигнал сопровождается признаками, доказательствами и рекомендациями;</li>
            <li><strong>малое число ложных тревог</strong> — фаза «предупреждение» отделена от «тревоги».</li>
          </ul>
        </section>

        <section id="pipeline">
          <h2>Конвейер обработки</h2>
          <figure class="figure"><div class="table-wrap" style="border:0">${raw(pipelineSvg())}</div>
            <figcaption>Рис. 1. Один и тот же конвейер используется для анализа файлов и мониторинга, поэтому формулы офлайн- и онлайн-режимов совпадают.</figcaption></figure>
          <p>Источник читается потоково в фоновом потоке браузера. Формат определяется по сигнатуре файла. Каждая запись переводится в событие
          (время, адреса, порты, протокол, флаги TCP, длина, имя DNS-запроса). События группируются во временные окна длиной <em>w</em>;
          по умолчанию <em>w</em> подбирается так, чтобы запись разбивалась примерно на 300 окон (1 с … 1 ч).</p>
        </section>

        <section id="features">
          <h2>Признаки окна</h2>
          <p>Для каждого окна вычисляется вектор из ${FEATURES.length} признаков. Для детекторов счётчики переводятся в логарифмическую шкалу
          <code>x = ln(1 + f)</code>, так как распределения сетевого трафика тяжелохвостые.</p>
          <div class="table-wrap"><table class="data"><thead><tr><th>Признак</th><th>Описание</th></tr></thead><tbody>
            ${FEATURES.map((f) => html`<tr><td class="nowrap"><strong>${f.name}</strong></td><td>${FEATURE_DESC[f.id]}</td></tr>`)}
          </tbody></table></div>
          <p>Помимо глобального вектора, для каждой пары «источник → получатель» хранятся попытки соединения, порты, ответы SYN-ACK, обращения к службам
          аутентификации, DNS-статистика и начала соединений — их используют поведенческие сигнатуры.</p>
        </section>

        <section id="ewma">
          <h2>Адаптивная норма (EWMA)</h2>
          <p>Первые окна (около 2 минут, не меньше 6 и не больше 30 окон) служат периодом обучения: начальная норма задаётся робастно —
          медианой и масштабированным MAD. Далее среднее и дисперсия каждого признака обновляются экспоненциально:</p>
          <div class="formula">μₜ = μₜ₋₁ + α·(xₜ − μₜ₋₁)<br />σ²ₜ = (1 − α)·(σ²ₜ₋₁ + α·(xₜ − μₜ₋₁)²),   α = 2 / (N + 1),   N = clamp(300 / w, 12, 120)
            <small>Если окно подозрительно (max z ≥ 3,5 или CUSUM превысил h), норма обучается в 10 раз медленнее: атака не «впитывается» в норму, но устойчивые изменения сети учитываются.</small></div>
          <div class="formula">zᵢ = (xᵢ − μᵢ) / max(σᵢ, σ_min),   σ_min = max(0,12; 1/√(λ + 1)),   λ = e^μ − 1
            <small>Нижняя граница σ соответствует пуассоновскому шуму счётчика: единичные события на «тихом» признаке не дают огромных z.</small></div>
          <div class="formula">s_base = 1 − exp(−max(0, z_max − z₀) / 2,5),   z₀ = ${dec(P.zOnset)} / чувствительность</div>
        </section>

        <section id="cusum">
          <h2>Раннее предупреждение (CUSUM)</h2>
          <p>Медленно нарастающая атака (сканирование «по чуть-чуть», постепенная выгрузка данных) может долго не превышать порог в каждом отдельном окне.
          Кумулятивная сумма Пейджа накапливает небольшие устойчивые отклонения и сигнализирует раньше:</p>
          <div class="formula">Sₜ = min(${dec(P.cusumCap)}·h, max(0, Sₜ₋₁ + clamp(zₜ, −3, 4) − k)),   k = ${dec(P.cusumK)},   h = ${dec(P.cusumH)} / чувствительность<br />s_cusum = max по признакам (Sₜ / h)
            <small>CUSUM считается для 10 счётчиков (пакеты, объём, адресаты, порты, соединения, RST, ICMP, DNS, исходящий объём, новые пары). При s_cusum ≥ 0,5 модель переходит в состояние «предупреждение», даже если риск ещё ниже порога тревоги.</small></div>
        </section>

        <section id="iforest">
          <h2>Isolation Forest</h2>
          <p>Многомерный детектор ловит необычные сочетания признаков, каждый из которых по отдельности выглядит нормально.
          Строится 100 случайных деревьев на подвыборках по 256 окон; аномальные точки изолируются быстрее:</p>
          <div class="formula">s(x) = 2^(−E[h(x)] / c(ψ)),   c(n) = 2·(ln(n − 1) + 0,5772) − 2·(n − 1)/n</div>
          <p>Метод предполагает, что аномалий мало. Чтобы атаки не загрязняли обучение, лес обучается на «вероятно нормальных» окнах:
          предварительный проход без леса отбирает окна с риском ниже уровня предупреждения. Оценка нормируется робастно по этим же окнам
          (<code>z_if = (s − медиана) / (1,4826·MAD)</code>), затем <code>s_if = clamp((z_if − ${dec(P.ifOnset)}) / ${dec(P.ifRange)}, 0, 1)</code>.
          В мониторинге лес переобучается каждые 90 окон.</p>
        </section>

        <section id="signatures">
          <h2>Поведенческие сигнатуры</h2>
          <p>Сигнатуры описывают поведение атакующего, а не конкретные порты: обращение к порту 443 или 53 само по себе риск не повышает.
          Проверка выполняется в скользящем горизонте 60 с; повторные срабатывания одного типа для одной пары узлов объединяются в инцидент.</p>
          <div class="table-wrap"><table class="data"><thead><tr><th>Угроза</th><th>Условие (чувствительность 1,0)</th><th>Важность</th><th>ATT&CK</th></tr></thead><tbody>
            ${SIGNATURES.map(([id, cond]) => html`<tr><td><strong>${THREATS[id].name}</strong></td><td>${cond}</td><td>${THREATS[id].sev}</td><td class="nowrap">${THREATS[id].mitre}</td></tr>`)}
          </tbody></table></div>
          <p>Пороги делятся на коэффициент чувствительности (0,75 / 1,0 / 1,35). Узлы из списка исключений в настройках не порождают инцидентов.</p>
        </section>

        <section id="fusion">
          <h2>Оценка риска</h2>
          <p>Статистические детекторы объединяются «шумовым ИЛИ» и нормируются к максимуму, сигнатуры — с весами важности:</p>
          <div class="formula">A = [1 − (1 − ${dec(P.wBase)}·s_base)(1 − ${dec(P.wCusum)}·s_cusum)(1 − ${dec(P.wIf)}·s_if)] / A_max<br />
            P = 1 − ∏ (1 − v_важн · уверенность),   v = (${P.sevWeight.slice(1).map(fmt2).join('; ')})<br />
            R_raw = 100 · (1 − (1 − P)·(1 − ${dec(P.lambda)}·A))<br />
            Rₜ = max(R_raw, Rₜ₋₁ · 0,5^(w / ${P.halfLife}))
            <small>Сглаживание даёт быстрый рост и медленный спад риска (полураспад ${P.halfLife} с). Только статистика без сигнатур может дать до ${Math.round(P.lambda * 100)} баллов.</small></div>
          <div class="table-wrap"><table class="data"><thead><tr><th>Уровень</th><th>Диапазон</th><th>Состояние модели</th></tr></thead><tbody>
            ${LEVELS.map((l, i) => html`<tr><td><strong>${l.name}</strong></td><td>${l.min} – ${LEVELS[i + 1] ? LEVELS[i + 1].min - 1 : 100}</td><td>${l.min >= 50 ? 'Тревога (по умолчанию порог 50)' : l.min >= 25 ? 'Предупреждение' : 'Норма (или предупреждение по CUSUM)'}</td></tr>`)}
          </tbody></table></div>
          <p><strong>Время упреждения</strong> — интервал между переходом в «предупреждение» и началом тревоги в том же эпизоде.</p>
        </section>

        <section id="evaluation">
          <h2>Методика оценки</h2>
          <p>Оценка выполняется на уровне окон: окно положительное, если содержит хотя бы одну размеченную запись атаки. Окна в течение 30 с после
          окончания атаки исключаются: сглаженный риск затухает постепенно, и их нельзя честно считать ложными срабатываниями.</p>
          <ul>
            <li>Точность = TP / (TP + FP), полнота = TP / (TP + FN), F1 — их гармоническое среднее, доля ложных = FP / (FP + TN);</li>
            <li>ROC-AUC — площадь под ROC-кривой по всем порогам (метод трапеций);</li>
            <li>задержка обнаружения — от начала атаки до закрытия первого окна с риском не ниже порога;</li>
            <li>ложные тревоги в час — непрерывные эпизоды тревоги, не пересекающиеся ни с одной атакой.</li>
          </ul>
          <p>Для сравнения используются: классический статический порог «среднее + 3σ» по числу пакетов и объёму, оценённый на том же
          периоде обучения, и каждый детектор по отдельности (абляция). Синтетический генератор моделирует офисную сеть из 20 рабочих станций
          и серверов с суточной вариацией нагрузки и легитимными событиями, похожими на атаки (обновления ПО, резервное копирование, сеансы администратора).
          Внешние адреса взяты из документационных диапазонов RFC 5737.</p>
        </section>

        <section id="limits">
          <h2>Ограничения и развитие</h2>
          <ul>
            <li>Пороги сигнатур эвристические; для конкретной сети их следует калибровать на её трафике.</li>
            <li>Метрики на синтетических данных оптимистичнее реальных; независимая проверка — на размеченных наборах (CICIDS2017, UNSW-NB15).</li>
            <li>Анализируются заголовки и метаданные; содержимое зашифрованного трафика не используется.</li>
            <li>Браузер не может захватывать трафик с сетевой карты: мониторинг работает на генераторе, реальные данные анализируются из файлов.</li>
            <li>Файлы обрабатываются в памяти вкладки; для очень больших захватов возможна нехватка памяти.</li>
          </ul>
          <p>Направления развития: локальный агент захвата с передачей окон по WebSocket, базовые линии по отдельным узлам и с учётом
          суточной сезонности, калибровка весов слияния на размеченных данных, корреляция инцидентов в цепочки атак.</p>
        </section>

        <section id="refs">
          <h2>Литература</h2>
          <ol class="ref-list">
            <li>Liu F. T., Ting K. M., Zhou Z.-H. Isolation Forest // Proc. 8th IEEE International Conference on Data Mining (ICDM). 2008. P. 413–422.</li>
            <li>Page E. S. Continuous Inspection Schemes // Biometrika. 1954. Vol. 41, № 1/2. P. 100–115.</li>
            <li>Roberts S. W. Control Chart Tests Based on Geometric Moving Averages // Technometrics. 1959. Vol. 1, № 3. P. 239–250.</li>
            <li>Chandola V., Banerjee A., Kumar V. Anomaly Detection: A Survey // ACM Computing Surveys. 2009. Vol. 41, № 3.</li>
            <li>Sharafaldin I., Lashkari A. H., Ghorbani A. A. Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization // ICISSP. 2018.</li>
            <li>Moustafa N., Slay J. UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems // MilCIS. 2015.</li>
            <li>Scarfone K., Mell P. Guide to Intrusion Detection and Prevention Systems (IDPS). NIST SP 800-94. 2007.</li>
            <li>MITRE ATT&CK — база знаний о тактиках и техниках злоумышленников: <a href="https://attack.mitre.org/" rel="noopener">attack.mitre.org</a>.</li>
          </ol>
        </section>
      </article>
    </div>`,
  );

  // Навигация по содержанию без изменения hash-маршрута.
  const links = qsa('[data-to]', view);
  const onClick = (e) => {
    const a = e.target.closest('[data-to]');
    if (!a) return;
    e.preventDefault();
    const target = view.querySelector(`#${a.dataset.to}`);
    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    target.querySelector('h2').setAttribute('tabindex', '-1');
    target.querySelector('h2').focus({ preventScroll: true });
  };
  view.addEventListener('click', onClick);
  const io = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        for (const l of links) l.classList.toggle('is-active', l.dataset.to === e.target.id);
      }
    },
    { rootMargin: '-80px 0px -65% 0px' },
  );
  for (const s of qsa('.prose section', view)) io.observe(s);
  return () => {
    io.disconnect();
    view.removeEventListener('click', onClick);
  };
}
