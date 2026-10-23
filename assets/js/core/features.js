// Агрегация событий во временные окна: глобальный вектор признаков окна и
// статистика пар «источник → получатель», которую используют поведенческие детекторы.

import { baseDomain, entropy } from './net.js';
import { AUTH_PORTS, PERIODIC_OK, SUSPICIOUS_PORTS } from './ports.js';
import { FLOW_ORIG, PROTO, TCPF } from './trace.js';

export const FEATURES = [
  { id: 'pkts', name: 'Пакеты', short: 'Пакеты', unit: 'count' },
  { id: 'bytes', name: 'Объём трафика', short: 'Объём', unit: 'bytes' },
  { id: 'srcs', name: 'Активные источники', short: 'Источники', unit: 'count' },
  { id: 'dsts', name: 'Адресаты', short: 'Адресаты', unit: 'count' },
  { id: 'ports', name: 'Уникальные порты назначения', short: 'Порты', unit: 'count' },
  { id: 'conns', name: 'Попытки соединения', short: 'Соединения', unit: 'count' },
  { id: 'rst', name: 'Сбросы соединений (RST)', short: 'RST', unit: 'count' },
  { id: 'icmp', name: 'ICMP-сообщения', short: 'ICMP', unit: 'count' },
  { id: 'dns', name: 'DNS-запросы', short: 'DNS', unit: 'count' },
  { id: 'ext', name: 'Исходящий объём во внешние сети', short: 'Наружу', unit: 'bytes' },
  { id: 'newp', name: 'Новые пары узлов', short: 'Новые пары', unit: 'count' },
  { id: 'ent', name: 'Энтропия портов назначения', short: 'Энтропия', unit: 'bits' },
  { id: 'avg', name: 'Средний размер пакета', short: 'Размер', unit: 'bytes' },
];

export const NF = FEATURES.length;
export const FX = Object.freeze({
  PKTS: 0, BYTES: 1, SRCS: 2, DSTS: 3, PORTS: 4, CONNS: 5, RST: 6, ICMP: 7, DNS: 8, EXT: 9, NEWP: 10, ENT: 11, AVG: 12,
});

const PAIR_MUL = 67108864; // 2^26: ключ пары помещается в безопасное целое
export const pairKey = (s, d) => s * PAIR_MUL + d;
const MAX_SET = 4096;

export class PairStat {
  constructor(src, dst) {
    this.src = src;
    this.dst = dst;
    this.pk = 0;
    this.by = 0;
    this.probes = 0; // попытки обращения: SYN без ACK, UDP-запрос, ICMP echo, начало потока
    this.syn = 0; // TCP SYN без ACK
    this.synack = 0; // TCP SYN+ACK (ответ на попытку)
    this.rst = 0;
    this.echo = 0;
    this.sus = 0;
    this.susPort = 0;
    this.ports = null;
    this.auth = null;
    this.tFirst = Infinity;
  }
}

export class WindowAgg {
  constructor(i, t0, t1) {
    this.i = i;
    this.t0 = t0;
    this.t1 = t1;
    this.f = new Float64Array(NF);
    this.pairs = new Map();
    this.dns = null;
    this.starts = [];
    this.attack = 0;
    this.labels = null;
    this.srcSet = new Set();
    this.dstSet = new Set();
    this.portCounts = new Map();
  }

  finalize() {
    const f = this.f;
    f[FX.SRCS] = this.srcSet.size;
    f[FX.DSTS] = this.dstSet.size;
    f[FX.PORTS] = this.portCounts.size;
    let total = 0;
    for (const c of this.portCounts.values()) total += c;
    let h = 0;
    for (const c of this.portCounts.values()) {
      const p = c / total;
      h -= p * Math.log2(p);
    }
    f[FX.ENT] = h;
    f[FX.AVG] = f[FX.PKTS] ? f[FX.BYTES] / f[FX.PKTS] : 0;
    this.srcSet = null;
    this.dstSet = null;
    this.portCounts = null;
  }
}

export class WindowAccumulator {
  constructor({ windowSize, hosts, flowMode = false, onWindow }) {
    this.w = windowSize;
    this.hosts = hosts;
    this.flowMode = flowMode;
    this.onWindow = onWindow;
    this.cur = null;
    this.origin = 0;
    this.seenPairs = new Set();
    this.udpLast = new Map();
  }

  start(t) {
    this.origin = t;
    this.cur = new WindowAgg(0, t, t + this.w);
  }

  advanceToIndex(k) {
    while (this.cur.i < k) {
      const done = this.cur;
      done.finalize();
      this.onWindow(done);
      const i = done.i + 1;
      this.cur = new WindowAgg(i, this.origin + i * this.w, this.origin + (i + 1) * this.w);
      if (i % 200 === 0) this.prune(this.cur.t0);
    }
  }

  // Закрывает все окна, конец которых не позже t (для потокового режима).
  advanceTo(t) {
    if (this.cur === null) this.start(t);
    const k = Math.floor((t - this.origin) / this.w);
    if (k > this.cur.i) this.advanceToIndex(k);
  }

  prune(now) {
    for (const [k, last] of this.udpLast) if (now - last > 300) this.udpLast.delete(k);
  }

  add(t, src, dst, sp, dp, proto, len, flags, n, q, label) {
    if (this.cur === null) this.start(t);
    const k = Math.floor((t - this.origin) / this.w);
    if (k > this.cur.i) this.advanceToIndex(k);
    const a = this.cur;
    const f = a.f;
    f[FX.PKTS] += n;
    f[FX.BYTES] += len;
    a.srcSet.add(src);
    a.dstSet.add(dst);
    const key = pairKey(src, dst);
    let ps = a.pairs.get(key);
    if (!ps) {
      ps = new PairStat(src, dst);
      a.pairs.set(key, ps);
      if (!this.seenPairs.has(key)) {
        this.seenPairs.add(key);
        f[FX.NEWP]++;
      }
    }
    if (t < ps.tFirst) ps.tFirst = t;
    ps.pk += n;
    ps.by += len;
    const intS = this.hosts.internal[src];
    const intD = this.hosts.internal[dst];
    if (intS && !intD) f[FX.EXT] += len;

    const orig = (flags & FLOW_ORIG) !== 0;
    let probe = false;
    if (proto === PROTO.TCP) {
      const syn = flags & TCPF.SYN;
      const ack = flags & TCPF.ACK;
      if (syn && !ack) {
        ps.syn += n;
        probe = true;
      } else if (syn && ack) {
        ps.synack += n;
      }
      if (flags & TCPF.RST) {
        ps.rst += n;
        f[FX.RST] += n;
      }
      if (this.flowMode ? orig : syn && !ack) f[FX.CONNS] += this.flowMode ? 1 : n;
    } else if (proto === PROTO.UDP) {
      // Ответ сервера (порт службы → эфемерный порт) не является попыткой обращения.
      probe = !(sp > 0 && sp < 1024 && dp >= 1024);
    } else if (proto === PROTO.ICMP) {
      f[FX.ICMP] += n;
      if (!this.flowMode && flags === 8) {
        ps.echo += n;
        probe = true;
      }
    }
    if (this.flowMode) {
      probe = orig;
      if (orig && proto === PROTO.ICMP) ps.echo += 1;
      if (orig && proto === PROTO.UDP) f[FX.CONNS] += 1;
    }
    if (probe) {
      const pc = this.flowMode ? 1 : n;
      ps.probes += pc;
      if (proto !== PROTO.ICMP) {
        if (!ps.ports) ps.ports = new Set();
        if (ps.ports.size < MAX_SET) ps.ports.add(dp);
        a.portCounts.set(dp, (a.portCounts.get(dp) || 0) + pc);
        if (proto === PROTO.TCP && AUTH_PORTS.has(dp)) {
          if (!ps.auth) ps.auth = new Map();
          ps.auth.set(dp, (ps.auth.get(dp) || 0) + pc);
        }
      }
    }
    if (SUSPICIOUS_PORTS.has(dp)) {
      ps.sus += n;
      ps.susPort = dp;
    }
    if (q) {
      f[FX.DNS] += n;
      const { base, sub } = baseDomain(q);
      if (!a.dns) a.dns = new Map();
      let byBase = a.dns.get(src);
      if (!byBase) a.dns.set(src, (byBase = new Map()));
      let st = byBase.get(base);
      if (!st) byBase.set(base, (st = { n: 0, len: 0, ent: 0, subs: new Set(), dst }));
      st.n += n;
      st.len += sub.length * n;
      st.ent += entropy(sub) * n;
      if (st.subs.size < MAX_SET) st.subs.add(sub);
    }
    // Начала соединений изнутри наружу — материал для поиска периодических маяков.
    if (intS && !intD && (proto === PROTO.TCP || proto === PROTO.UDP) && !PERIODIC_OK.has(dp)) {
      let start;
      if (this.flowMode) start = orig;
      else if (proto === PROTO.TCP) start = (flags & TCPF.SYN) !== 0 && (flags & TCPF.ACK) === 0;
      else {
        const uk = `${key}:${dp}`;
        const last = this.udpLast.get(uk);
        start = last === undefined || t - last > 2;
        this.udpLast.set(uk, t);
      }
      if (start) a.starts.push(src, dst, dp, t);
    }
    if (label) {
      a.attack += n;
      if (!a.labels) a.labels = new Set();
      a.labels.add(label);
    }
  }

  // tEnd — время последнего события: последнее окно, заполненное меньше чем на 60%,
  // помечается как неполное (его счётчики несопоставимы с полными окнами).
  flush(tEnd = Infinity) {
    if (this.cur) {
      const cur = this.cur;
      cur.partial = cur.i > 0 && tEnd - cur.t0 < 0.6 * this.w;
      cur.finalize();
      this.onWindow(cur);
      this.cur = null;
    }
  }
}
