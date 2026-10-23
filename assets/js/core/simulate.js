// Генератор сетевого трафика офисной сети с размеченными сценариями атак.
// Используется для оценки модели (известна «истина»), демонстрационных наборов
// и режима мониторинга. Адреса внешних узлов взяты из документационных
// диапазонов RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

import { Rng } from './prng.js';
import { PROTO, TCPF, TraceBuilder } from './trace.js';

const { SYN, ACK, FIN, RST, PSH } = TCPF;

export const SCENARIOS = {
  sweep: { name: 'Разведка сети (ping-сканирование)', short: 'Разведка', duration: 60, expect: ['sweep'] },
  portscan: { name: 'Медленное сканирование портов', short: 'Сканирование', duration: 150, expect: ['portscan'] },
  bruteforce: { name: 'Подбор пароля SSH', short: 'Подбор пароля', duration: 120, expect: ['bruteforce'] },
  beacon: { name: 'C2-маяк вредоносного ПО', short: 'C2-маяк', duration: 400, expect: ['beacon'] },
  dnstunnel: { name: 'DNS-туннелирование', short: 'DNS-туннель', duration: 100, expect: ['dnstunnel'] },
  exfil: { name: 'Утечка данных наружу', short: 'Утечка', duration: 120, expect: ['exfil'] },
  synflood: { name: 'SYN-флуд (DDoS)', short: 'SYN-флуд', duration: 80, expect: ['synflood', 'flood'] },
};

export const DEFAULT_SCHEDULE = [
  { type: 'sweep', t0: 210 },
  { type: 'portscan', t0: 320 },
  { type: 'bruteforce', t0: 540 },
  { type: 'beacon', t0: 600 },
  { type: 'dnstunnel', t0: 720 },
  { type: 'exfil', t0: 860 },
  { type: 'synflood', t0: 1060 },
];

export const BASE_TIME = Date.UTC(2026, 9, 1, 7, 0, 0) / 1000;

const BENIGN_DOMAINS = [
  'example.com', 'example.net', 'example.org', 'portal.example', 'mail.example', 'cdn.example',
  'docs.example', 'news.example', 'video.example', 'maps.example', 'cloud.example', 'search.example',
];
const SUBS = ['www', 'api', 'cdn', 'img', 'static', 'login', 'mail', 'assets', 'app', 'files'];
const B32 = 'abcdefghijklmnopqrstuvwxyz234567';

class Heap {
  constructor() {
    this.a = [];
  }

  get size() {
    return this.a.length;
  }

  push(p) {
    const a = this.a;
    a.push(p);
    let i = a.length - 1;
    while (i > 0) {
      const j = (i - 1) >> 1;
      if (a[j].t <= a[i].t) break;
      [a[i], a[j]] = [a[j], a[i]];
      i = j;
    }
  }

  peek() {
    return this.a[0];
  }

  pop() {
    const a = this.a;
    const top = a[0];
    const last = a.pop();
    if (a.length) {
      a[0] = last;
      let i = 0;
      for (;;) {
        const l = 2 * i + 1;
        const r = l + 1;
        let m = i;
        if (l < a.length && a[l].t < a[m].t) m = l;
        if (r < a.length && a[r].t < a[m].t) m = r;
        if (m === i) break;
        [a[i], a[m]] = [a[m], a[i]];
        i = m;
      }
    }
    return top;
  }
}

export class TrafficSimulator {
  constructor({ seed = 42, workstations = 20, intensity = 1 } = {}) {
    this.rng = new Rng(seed);
    this.intensity = intensity;
    this.ws = Array.from({ length: workstations }, (_, i) => `10.0.1.${10 + i}`);
    this.srv = { gw: '10.0.0.1', mon: '10.0.0.2', portal: '10.0.0.5', files: '10.0.0.10', dns: '10.0.0.53' };
    const prefixes = ['203.0.113', '198.51.100', '192.0.2'];
    this.ext = Array.from({ length: 36 }, (_, i) => `${prefixes[i % 3]}.${20 + ((i * 7) % 150)}`);
    this.actors = { insider: '10.0.1.66', brute: '203.0.113.77', c2: '203.0.113.45', drop: '198.51.100.200', beaconHost: '10.0.1.17', tunnelHost: '10.0.1.31', leakHost: '10.0.1.23' };
    this.alive = new Set([...this.ws, ...Object.values(this.srv), this.actors.insider]);
    this.heap = new Heap();
    this.streams = [];
    this.scenarios = [];
    this.phase = this.rng.range(0, Math.PI * 2);
    this.walk = 0;
    this.nextNtp = new Map([...this.ws, this.srv.portal, this.srv.files].map((h) => [h, this.rng.range(0, 64)]));
    this.nextMon = 0;
  }

  eph() {
    return 49152 + this.rng.int(0, 16000);
  }

  pkt(t, s, d, sp, dp, pr, len, fl, lab = null, q = null) {
    this.heap.push({ t, s, d, sp, dp, pr, len, fl, q, lab });
  }

  modulation(t) {
    this.walk = Math.max(-0.25, Math.min(0.25, this.walk + this.rng.normal(0, 0.01)));
    return Math.max(0.3, 1 + 0.3 * Math.sin((2 * Math.PI * t) / 900 + this.phase) + this.walk);
  }

  // ---- примитивы протоколов ----

  dns(t, c, name, lab = null, respLen = null) {
    const sp = this.eph();
    this.pkt(t, c, this.srv.dns, sp, 53, PROTO.UDP, 70 + name.length, 0, lab, name);
    this.pkt(t + this.rng.range(0.001, 0.02), this.srv.dns, c, 53, sp, PROTO.UDP, respLen ?? this.rng.int(100, 260), 0, lab);
  }

  tcp(t, c, s, dport, { req = 400, resp = 8000, rtt = 0.03, lab = null, open = true, think = 0.05 } = {}) {
    const cp = this.eph();
    const P = (dt, a, b, ap, bp, fl, len) => this.pkt(t + dt, a, b, ap, bp, PROTO.TCP, len, fl, lab);
    P(0, c, s, cp, dport, SYN, 66);
    if (!open) {
      P(rtt, s, c, dport, cp, RST | ACK, 54);
      return;
    }
    P(rtt, s, c, dport, cp, SYN | ACK, 66);
    let x = rtt * 1.5;
    P(x, c, s, cp, dport, ACK, 54);
    for (let left = req; left > 0; left -= 1400) {
      x += 0.0003;
      P(x, c, s, cp, dport, PSH | ACK, 54 + Math.min(1400, left));
    }
    x += rtt;
    let k = 0;
    for (let left = resp; left > 0; left -= 1448) {
      x += (rtt / 8) * this.rng.range(0.5, 1.5);
      P(x, s, c, dport, cp, k % 4 === 3 ? PSH | ACK : ACK, 66 + Math.min(1448, left));
      if (++k % 2 === 0) P(x + 0.0002, c, s, cp, dport, ACK, 54);
    }
    x += think * this.rng.range(0.2, 2);
    P(x, c, s, cp, dport, FIN | ACK, 54);
    P(x + rtt, s, c, dport, cp, FIN | ACK, 54);
    P(x + rtt * 1.5, c, s, cp, dport, ACK, 54);
  }

  // Длительная передача с заданной скоростью (байт/с) от a к b; ответные ACK от b.
  stream({ t0, t1, a, b, dport, rate, lab = null }) {
    const cp = this.eph();
    this.tcp(t0, a, b, dport, { req: 600, resp: 4000, rtt: 0.04, lab });
    this.streams.push({ t0: t0 + 0.3, t1, a, b, cp, dport, rate, lab, acc: 0, k: 0 });
  }

  stepStreams(a0, a1) {
    this.streams = this.streams.filter((st) => {
      if (st.t1 <= a0) return false;
      const from = Math.max(a0, st.t0);
      const to = Math.min(a1, st.t1);
      if (to <= from) return true;
      const dt = to - from;
      st.acc += st.rate((from + to) / 2) * dt;
      const count = Math.floor(st.acc / 1460);
      st.acc -= count * 1460;
      for (let i = 0; i < count; i++) {
        const t = from + (dt * (i + this.rng.float())) / count;
        this.pkt(t, st.a, st.b, st.cp, st.dport, PROTO.TCP, 1514, ACK, st.lab);
        if (++st.k % 2 === 0) this.pkt(t + 0.02, st.b, st.a, st.dport, st.cp, PROTO.TCP, 54, ACK, st.lab);
      }
      return true;
    });
  }

  // ---- фоновый трафик ----

  background(t0, t1) {
    const r = this.rng;
    const dt = t1 - t0;
    const m = this.modulation(t0) * this.intensity;
    const n = this.ws.length;
    const at = () => t0 + r.float() * dt;

    for (let k = r.poisson(n * 0.07 * m * dt); k > 0; k--) {
      const t = at();
      const c = r.pick(this.ws);
      const sIdx = r.int(0, this.ext.length - 1);
      if (r.chance(0.65)) this.dns(t - 0.03, c, `${r.pick(SUBS)}.${BENIGN_DOMAINS[sIdx % BENIGN_DOMAINS.length]}`);
      const resp = Math.round(Math.exp(r.normal(9.6, 1.1)));
      this.tcp(t, c, this.ext[sIdx], r.chance(0.9) ? 443 : 80, { req: r.int(200, 1400), resp: Math.min(resp, 1.5e6), rtt: r.range(0.015, 0.08) });
    }
    for (let k = r.poisson(n * 0.015 * m * dt); k > 0; k--) {
      this.tcp(at(), r.pick(this.ws), this.srv.portal, 443, { req: r.int(300, 2000), resp: r.int(2000, 60000), rtt: r.range(0.0005, 0.002) });
    }
    for (let k = r.poisson(n * 0.006 * m * dt); k > 0; k--) {
      this.tcp(at(), r.pick(this.ws), this.srv.files, 445, { req: r.int(500, 20000), resp: r.int(20000, 400000), rtt: r.range(0.0005, 0.002), think: 1 });
    }
    for (let k = r.poisson(n * 0.02 * m * dt); k > 0; k--) {
      this.dns(at(), r.pick(this.ws), `${r.pick(SUBS)}.${r.pick(BENIGN_DOMAINS)}`);
    }
    for (const [h, next] of this.nextNtp) {
      if (next >= t0 && next < t1) {
        const sp = this.eph();
        this.pkt(next, h, this.srv.gw, sp, 123, PROTO.UDP, 90, 0);
        this.pkt(next + 0.001, this.srv.gw, h, 123, sp, PROTO.UDP, 90, 0);
        this.nextNtp.set(h, next + 64 + r.range(-1, 1));
      } else if (next < t0) {
        this.nextNtp.set(h, t0 + r.range(0, 64));
      }
    }
    while (this.nextMon < t1) {
      if (this.nextMon >= t0) {
        for (const s of [this.srv.gw, this.srv.portal, this.srv.files, this.srv.dns]) {
          this.pkt(this.nextMon, this.srv.mon, s, 0, 0, PROTO.ICMP, 74, 8);
          this.pkt(this.nextMon + 0.0007, s, this.srv.mon, 0, 0, PROTO.ICMP, 74, 0);
        }
      }
      this.nextMon += 10;
    }
    // Редкие легитимные события, похожие на атаки: обновление ПО, сеанс администратора, резервная копия.
    if (r.chance(0.0015 * dt)) {
      const dur = r.range(20, 50);
      const size = r.range(4e6, 15e6);
      const c = r.pick(this.ws);
      const server = this.ext[r.int(0, this.ext.length - 1)];
      this.dns(t0, c, 'update.example.net');
      this.stream({ t0: t0 + 0.1, t1: t0 + dur, a: server, b: c, dport: 443, rate: () => size / dur });
    }
    if (r.chance(0.0015 * dt)) {
      const c = this.ws[0];
      const start = at();
      for (let i = 0; i < 3; i++) this.tcp(start + i * r.range(20, 60), c, this.srv.portal, 22, { req: 3000, resp: 9000, rtt: 0.001, think: 5 });
    }
    if (r.chance(0.0008 * dt)) {
      this.stream({ t0, t1: t0 + 40, a: this.srv.files, b: '203.0.113.10', dport: 443, rate: () => 1.2e6 / 40 });
    }
  }

  // ---- сценарии атак ----

  addScenario(type, t0, duration = SCENARIOS[type].duration) {
    const r = this.rng;
    const t1 = t0 + duration;
    const A = this.actors;
    const ramp = (t, frac) => Math.min(1, Math.max(0, (t - t0) / (duration * frac)));
    const lab = type;
    let truth = { type, name: SCENARIOS[type].name, t0, t1 };
    let step;
    switch (type) {
      case 'sweep': {
        const targets = r.shuffle([...Array.from({ length: 60 }, (_, i) => `10.0.0.${i + 1}`), ...Array.from({ length: 60 }, (_, i) => `10.0.1.${i + 1}`)]);
        let idx = 0;
        step = (a, b) => {
          for (let k = r.poisson(2.5 * (b - a)); k > 0; k--) {
            const t = a + r.float() * (b - a);
            const d = targets[idx++ % targets.length];
            this.pkt(t, A.insider, d, 0, 0, PROTO.ICMP, 74, 8, lab);
            if (this.alive.has(d)) this.pkt(t + 0.0008, d, A.insider, 0, 0, PROTO.ICMP, 74, 0, lab);
          }
        };
        truth = { ...truth, attacker: A.insider, target: '10.0.0.0/23' };
        break;
      }
      case 'portscan': {
        const ports = r.shuffle([...Array.from({ length: 1024 }, (_, i) => i + 1), 1433, 3306, 3389, 5432, 5900, 8080, 8443]);
        const open = new Set([22, 80, 139, 445, 3389]);
        let idx = 0;
        const target = this.srv.files;
        step = (a, b) => {
          const rate = 0.1 + 7.9 * ramp((a + b) / 2, 0.8);
          for (let k = r.poisson(rate * (b - a)); k > 0; k--) {
            const t = a + r.float() * (b - a);
            const p = ports[idx++ % ports.length];
            const sp = this.eph();
            this.pkt(t, A.insider, target, sp, p, PROTO.TCP, 58, SYN, lab);
            if (open.has(p)) {
              this.pkt(t + 0.0006, target, A.insider, p, sp, PROTO.TCP, 58, SYN | ACK, lab);
              this.pkt(t + 0.0009, A.insider, target, sp, p, PROTO.TCP, 54, RST, lab);
            } else {
              this.pkt(t + 0.0006, target, A.insider, p, sp, PROTO.TCP, 54, RST | ACK, lab);
            }
          }
        };
        truth = { ...truth, attacker: A.insider, target };
        break;
      }
      case 'bruteforce': {
        let next = t0;
        step = (a, b) => {
          while (next < b) {
            if (next >= a) this.tcp(next, A.brute, this.srv.portal, 22, { req: 900, resp: 1600, rtt: 0.045, lab, think: 0.2 });
            next += r.range(0.5, 0.9);
          }
        };
        truth = { ...truth, attacker: A.brute, target: this.srv.portal };
        break;
      }
      case 'beacon': {
        let next = t0;
        step = (a, b) => {
          while (next < b) {
            if (next >= a) {
              if (r.chance(0.3)) this.dns(next - 0.05, A.beaconHost, 'telemetry.cdn-update.example', lab);
              this.tcp(next, A.beaconHost, A.c2, 8443, { req: 260, resp: 190, rtt: 0.06, lab, think: 0.1 });
            }
            next += 20 + r.range(-0.3, 0.3);
          }
        };
        truth = { ...truth, attacker: A.c2, target: A.beaconHost };
        break;
      }
      case 'dnstunnel': {
        let seq = 0;
        step = (a, b) => {
          for (let k = r.poisson(5 * (b - a)); k > 0; k--) {
            let chunk = '';
            const len = r.int(30, 48);
            for (let i = 0; i < len; i++) chunk += B32[r.int(0, 31)];
            this.dns(a + r.float() * (b - a), A.tunnelHost, `${chunk}.${(seq++).toString(16)}.t.cdnsync.example`, lab, r.int(200, 420));
          }
        };
        truth = { ...truth, attacker: A.tunnelHost, target: 'cdnsync.example' };
        break;
      }
      case 'exfil': {
        this.dns(t0 - 0.1, A.leakHost, 'upload.share-files.example', lab);
        this.stream({ t0, t1, a: A.leakHost, b: A.drop, dport: 443, lab, rate: (t) => 20e3 + 580e3 * ramp(t, 0.8) });
        step = () => {};
        truth = { ...truth, attacker: A.leakHost, target: A.drop };
        break;
      }
      case 'synflood': {
        const pre = ['203.0.113', '198.51.100', '192.0.2'];
        const target = this.srv.portal;
        step = (a, b) => {
          const g = ramp((a + b) / 2, 0.4);
          const rate = 10 + 790 * g;
          const answer = Math.max(0.08, 0.9 - 0.82 * g);
          for (let k = r.poisson(rate * (b - a)); k > 0; k--) {
            const t = a + r.float() * (b - a);
            const s = `${r.pick(pre)}.${r.int(1, 254)}`;
            const sp = r.int(1024, 65535);
            this.pkt(t, s, target, sp, 443, PROTO.TCP, 60, SYN, lab);
            if (r.chance(answer)) this.pkt(t + 0.0005, target, s, 443, sp, PROTO.TCP, 60, SYN | ACK, lab);
          }
        };
        truth = { ...truth, attacker: 'подменённые адреса', target };
        break;
      }
      default:
        throw new Error(`Неизвестный сценарий: ${type}`);
    }
    this.scenarios.push({ t0, t1, step });
    return truth;
  }

  step(t0, t1, emit) {
    this.background(t0, t1);
    this.scenarios = this.scenarios.filter((sc) => {
      const a = Math.max(t0, sc.t0);
      const b = Math.min(t1, sc.t1);
      if (b > a) sc.step(a, b);
      return sc.t1 > t1;
    });
    this.stepStreams(t0, t1);
    while (this.heap.size && this.heap.peek().t < t1) emit(this.heap.pop());
  }

  drain(emit, until = Infinity) {
    while (this.heap.size && this.heap.peek().t < until) emit(this.heap.pop());
  }
}

export function generateDataset({ seed = 42, duration = 1200, schedule = DEFAULT_SCHEDULE, workstations = 20 } = {}) {
  const sim = new TrafficSimulator({ seed, workstations });
  const truth = schedule.filter((s) => s.t0 < duration).map((s) => sim.addScenario(s.type, s.t0, s.duration));
  const builder = new TraceBuilder();
  builder.labelled = true;
  const emit = (p) => {
    if (p.t < 0 || p.t >= duration) return;
    builder.push(BASE_TIME + p.t, p.s, p.d, p.sp, p.dp, p.pr, p.len, p.fl, 1, p.q, p.lab);
  };
  for (let t = 0; t < duration; t += 1) sim.step(t, Math.min(duration, t + 1), emit);
  sim.drain(emit, duration);
  return {
    trace: builder.finish(),
    truth: truth.map((s) => ({ ...s, t0: BASE_TIME + s.t0, t1: BASE_TIME + Math.min(s.t1, duration) })),
  };
}
