// Каталог типов угроз: название, важность, соответствие MITRE ATT&CK,
// текст объяснения по собранным доказательствам и рекомендации оператору.

import { serviceName } from './ports.js';

export const SEVERITY = [
  null,
  { id: 'low', name: 'Низкая' },
  { id: 'medium', name: 'Средняя' },
  { id: 'high', name: 'Высокая' },
  { id: 'critical', name: 'Критическая' },
];

const nf = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 1 });
const n0 = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 0 });

export function bytesText(b) {
  if (b < 1024) return `${n0.format(b)} Б`;
  if (b < 1024 ** 2) return `${nf.format(b / 1024)} КБ`;
  if (b < 1024 ** 3) return `${nf.format(b / 1024 ** 2)} МБ`;
  return `${nf.format(b / 1024 ** 3)} ГБ`;
}

const pct = (x) => `${n0.format(x * 100)}%`;

export const THREATS = {
  portscan: {
    name: 'Сканирование портов',
    sev: 3,
    mitre: 'T1046',
    icon: 'radar',
    describe: (e, src, dst) =>
      `${src} обратился к ${n0.format(e.ports)} портам узла ${dst} за последние 60 с; ${pct(e.unanswered)} попыток не привели к установлению соединения.`,
    advice: [
      'Проверить, относится ли источник к разрешённым сканерам уязвимостей.',
      'Если нет — изолировать источник и проверить его на компрометацию.',
      'Сверить открытые на целевом узле службы с утверждённым перечнем.',
    ],
  },
  sweep: {
    name: 'Разведка сети',
    sev: 2,
    mitre: 'T1018',
    icon: 'target',
    describe: (e, src) => `${src} опросил ${n0.format(e.hosts)} разных узлов за 60 с (метод: ${e.method}).`,
    advice: [
      'Определить владельца источника и цель опроса узлов.',
      'Проверить источник на признаки бокового перемещения.',
      'Ограничить ICMP и широковещательные обращения между сегментами.',
    ],
  },
  synflood: {
    name: 'SYN-флуд',
    sev: 4,
    mitre: 'T1498',
    icon: 'zap',
    describe: (e, src, dst) =>
      `Узел ${dst} получает ${n0.format(e.rate)} запросов SYN в секунду от ${e.sources > 1 ? `${n0.format(e.sources)} источников` : src}; ${pct(e.unanswered)} остаются без ответа.`,
    advice: [
      'Включить SYN cookies и ограничение частоты на периметре.',
      'Связаться с провайдером или сервисом защиты от DDoS.',
      'Проверить доступность сервиса и очередь соединений.',
    ],
  },
  flood: {
    name: 'Объёмная DDoS-атака',
    sev: 4,
    mitre: 'T1498',
    icon: 'zap',
    describe: (e, _src, dst) =>
      `На узел ${dst} приходится ${pct(e.share)} всех пакетов окна: ${n0.format(e.rate)} пакетов/с от ${n0.format(e.sources)} источников.`,
    advice: [
      'Применить фильтрацию и ограничение частоты для целевого адреса.',
      'Подключить очистку трафика у провайдера.',
      'Проверить, не используется ли сервис для отражения или усиления атаки.',
    ],
  },
  bruteforce: {
    name: 'Подбор учётных данных',
    sev: 3,
    mitre: 'T1110',
    icon: 'key',
    describe: (e, src, dst, port) =>
      `${src} выполнил ${n0.format(e.attempts)} попыток подключения к службе ${serviceName(port)} на ${dst} за 60 с (≈${n0.format(e.perMin)} в минуту).`,
    advice: [
      'Проверить журналы аутентификации целевой службы на неудачные входы.',
      'Заблокировать источник; включить блокировку после серии неудач и MFA.',
      'Убедиться, что служба не опубликована наружу без необходимости.',
    ],
  },
  exfil: {
    name: 'Возможная утечка данных',
    sev: 4,
    mitre: 'T1041, T1567',
    icon: 'upload',
    describe: (e, src, dst) =>
      `${src} передал ${bytesText(e.bytes)} на внешний адрес ${dst} за 60 с (≈${bytesText(e.rate)}/с); исходящий объём в ${n0.format(e.ratio)} раз больше входящего.`,
    advice: [
      'Определить процесс и учётную запись, инициировавшие передачу.',
      'Проверить репутацию получателя и легитимность выгрузки.',
      'При подтверждении — разорвать соединение и начать процедуру реагирования.',
    ],
  },
  beacon: {
    name: 'Периодические обращения (C2-маяк)',
    sev: 3,
    mitre: 'T1071',
    icon: 'repeat',
    describe: (e, src, dst, port) =>
      `${src} подключается к ${dst}:${port} каждые ${nf.format(e.period)} с с разбросом ${pct(e.jitter)} (${n0.format(e.count)} соединений) — характерно для канала управления вредоносного ПО.`,
    advice: [
      'Проверить репутацию внешнего адреса и домена.',
      'Найти на узле-источнике процесс, создающий соединения.',
      'Если обращения легитимны (обновления, телеметрия) — добавить адрес в список исключений.',
    ],
  },
  dnstunnel: {
    name: 'DNS-туннелирование',
    sev: 3,
    mitre: 'T1071.004',
    icon: 'globe',
    describe: (e, src) =>
      `${src} отправил ${n0.format(e.queries)} DNS-запросов к домену ${e.domain}: средняя длина поддомена ${nf.format(e.avgLen)} символов, энтропия ${nf.format(e.entropy)} бит/символ, уникальных имён ${pct(e.unique)}.`,
    advice: [
      'Заблокировать домен на DNS-резолвере.',
      'Проверить узел-источник на наличие туннелирующего ПО.',
      'Разрешить внешние DNS-запросы только через корпоративные резолверы.',
    ],
  },
  susport: {
    name: 'Нетипичный порт',
    sev: 2,
    mitre: 'T1571',
    icon: 'plug',
    describe: (e, src, dst, port) =>
      `${src} обращается к ${dst} на порт ${port} (${serviceName(port)}) — ${n0.format(e.packets)} пакетов. Порт часто используется бэкдорами и ботнетами.`,
    advice: [
      'Проверить, какое приложение использует этот порт.',
      'Заблокировать порт на межсетевом экране, если он не нужен.',
    ],
  },
};

export function describeIncident(inc, hostName) {
  const t = THREATS[inc.type];
  const src = inc.src >= 0 ? hostName(inc.src) : 'множество источников';
  const dst = inc.dst >= 0 ? hostName(inc.dst) : 'множество узлов';
  return t.describe(inc.evidence, src, dst, inc.port);
}
