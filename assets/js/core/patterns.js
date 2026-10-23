// Поведенческие детекторы. Работают причинно: в момент закрытия окна используют
// только данные этого окна и предыдущих в горизонте 60 с, поэтому время
// срабатывания совпадает с моментом, когда оператор мог бы получить сигнал.

import { THREATS } from './catalog.js';
import { FX, pairKey } from './features.js';

const clamp = (x, a = 0, b = 1) => Math.min(b, Math.max(a, x));

function median(arr) {
  const s = [...arr].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

const round = (x, d = 2) => Math.round(x * 10 ** d) / 10 ** d;

// Коэффициент вариации интервалов: у случайных (пуассоновских) обращений ≈ 1,
// у программного маяка — единицы процентов.
function intervalCv(iv) {
  const mean = iv.reduce((a, b) => a + b, 0) / iv.length;
  const variance = iv.reduce((s, x) => s + (x - mean) ** 2, 0) / Math.max(1, iv.length - 1);
  return Math.sqrt(variance) / mean;
}

export class PatternDetector {
  constructor({ windowSize, sensitivity = 1, hosts, allow = null }) {
    this.w = windowSize;
    this.s = sensitivity;
    this.hosts = hosts;
    this.allow = allow || new Set();
    this.horizon = Math.max(60, windowSize);
    this.H = Math.max(1, Math.round(this.horizon / windowSize));
    this.hist = [];
    this.incidents = [];
    this.open = new Map();
    this.beacons = new Map();
    this.processed = 0;
  }

  process(agg) {
    agg.bySrc = new Map();
    for (const ps of agg.pairs.values()) {
      let list = agg.bySrc.get(ps.src);
      if (!list) agg.bySrc.set(ps.src, (list = []));
      list.push(ps);
    }
    this.hist.push(agg);
    if (this.hist.length > this.H) {
      const old = this.hist.shift();
      old.pairs = null;
      old.bySrc = null;
      old.dns = null;
    }
    const hits = new Map();
    const emit = (type, src, dst, port, conf, evidence, extraKey = '') => {
      if ((src >= 0 && this.allow.has(src)) || (dst >= 0 && this.allow.has(dst))) return;
      const key = `${type}|${src}|${dst}|${port}|${extraKey}`;
      let inc = this.open.get(key);
      const gapLimit = Math.max(this.horizon, 2 * this.w, (evidence.period || 0) * 2.5);
      if (inc && agg.t0 - inc.tLast > gapLimit) inc = null;
      const tStart = evidence.tStart ?? agg.t0;
      if (!inc) {
        inc = {
          id: this.incidents.length,
          type,
          sev: THREATS[type].sev,
          src,
          dst,
          port,
          tStart,
          tDetect: agg.t1,
          tLast: agg.t1,
          conf,
          peak: conf,
          windows: 0,
          evidence: {},
        };
        this.incidents.push(inc);
        this.open.set(key, inc);
      }
      inc.tLast = agg.t1;
      inc.windows++;
      inc.conf = conf;
      inc.peak = Math.max(inc.peak, conf);
      inc.tStart = Math.min(inc.tStart, tStart);
      for (const [k, v] of Object.entries(evidence)) {
        if (k === 'tStart') continue;
        inc.evidence[k] = typeof v === 'number' && typeof inc.evidence[k] === 'number' ? Math.max(inc.evidence[k], v) : v;
      }
      const prev = hits.get(inc.id);
      if (prev === undefined || conf > prev) hits.set(inc.id, conf);
    };

    this.detectScan(agg, emit);
    this.detectSweep(agg, emit);
    this.detectFlood(agg, emit);
    this.detectBrute(agg, emit);
    this.detectExfil(agg, emit);
    this.detectDnsTunnel(agg, emit);
    this.detectSuspiciousPorts(agg, emit);
    this.detectBeacons(agg, emit);

    if (++this.processed % 500 === 0) this.prune(agg.t1);
    return [...hits].map(([id, conf]) => ({ id, sev: this.incidents[id].sev, conf }));
  }

  prune(now) {
    for (const [k, b] of this.beacons) if (now - b.times[b.times.length - 1] > 3600) this.beacons.delete(k);
    for (const [k, inc] of this.open) if (now - inc.tLast > 3600) this.open.delete(k);
  }

  span() {
    return Math.min(this.horizon, this.hist.length * this.w);
  }

  detectScan(agg, emit) {
    const thr = 15 / this.s;
    const big = 60 / this.s;
    for (const [key, ps] of agg.pairs) {
      if (!ps.ports) continue;
      let bound = 0;
      for (const h of this.hist) {
        const q = h.pairs.get(key);
        if (q && q.ports) bound += q.ports.size;
      }
      if (bound < thr) continue;
      const ports = new Set();
      const rk = pairKey(ps.dst, ps.src);
      let syn = 0;
      let synack = 0;
      let probes = 0;
      let tStart = agg.t0;
      for (const h of this.hist) {
        const q = h.pairs.get(key);
        if (q && q.ports) {
          for (const p of q.ports) ports.add(p);
          syn += q.syn;
          probes += q.probes;
          if (q.tFirst < tStart) tStart = q.tFirst;
        }
        const r = h.pairs.get(rk);
        if (r) synack += r.synack;
      }
      if (ports.size < thr) continue;
      const unanswered = syn > 0 ? clamp(1 - synack / syn) : 0.5;
      if (unanswered < 0.3 && ports.size < big) continue;
      const conf = clamp(0.45 + 0.35 * Math.min(1, ports.size / big) + 0.2 * unanswered, 0, 0.98);
      emit('portscan', ps.src, ps.dst, 0, conf, { ports: ports.size, probes, unanswered: round(unanswered), tStart });
    }
  }

  detectSweep(agg, emit) {
    const thr = 12 / this.s;
    for (const [src, list] of agg.bySrc) {
      if (!list.some((ps) => ps.probes)) continue;
      let bound = 0;
      for (const h of this.hist) bound += h.bySrc?.get(src)?.length || 0;
      if (bound < thr) continue;
      const echo = new Set();
      const unans = new Set();
      const internal = new Set();
      const srcInternal = this.hosts.internal[src];
      let tStart = agg.t0;
      for (const h of this.hist) {
        const l = h.bySrc?.get(src);
        if (!l) continue;
        for (const ps of l) {
          if (!ps.probes) continue;
          if (ps.tFirst < tStart) tStart = ps.tFirst;
          if (ps.echo) echo.add(ps.dst);
          if (ps.syn) {
            const r = h.pairs.get(pairKey(ps.dst, ps.src));
            if (!r || r.synack === 0) unans.add(ps.dst);
            if (srcInternal && this.hosts.internal[ps.dst]) internal.add(ps.dst);
          }
        }
      }
      const n = Math.max(echo.size, unans.size, internal.size);
      if (n < thr) continue;
      const method = echo.size === n ? 'ICMP echo' : unans.size === n ? 'TCP SYN без ответа' : 'TCP SYN к внутренним узлам';
      const conf = clamp(0.4 + 0.5 * Math.min(1, n / (40 / this.s)), 0, 0.95);
      emit('sweep', src, -1, 0, conf, { hosts: n, method, tStart });
    }
  }

  detectFlood(agg, emit) {
    const thrSyn = 80 / this.s;
    const thrPk = 400 / this.s;
    const inbound = new Map();
    const synackOut = new Map();
    for (const ps of agg.pairs.values()) {
      if (ps.synack) synackOut.set(ps.src, (synackOut.get(ps.src) || 0) + ps.synack);
      let d = inbound.get(ps.dst);
      if (!d) inbound.set(ps.dst, (d = { syn: 0, pk: 0, srcs: 0, ports: 0, one: ps.src }));
      d.syn += ps.syn;
      d.pk += ps.pk;
      d.srcs++;
      d.ports += ps.ports ? ps.ports.size : 0;
    }
    const total = agg.f[FX.PKTS] || 1;
    for (const [dst, d] of inbound) {
      const synRate = d.syn / this.w;
      // Много разных портов при одном источнике — это сканирование, а не флуд.
      const scanLike = d.srcs < 5 && d.ports > 20 && d.ports > 0.5 * d.syn;
      if (synRate >= thrSyn && !scanLike) {
        const unanswered = clamp(1 - (synackOut.get(dst) || 0) / d.syn);
        if (unanswered >= 0.4) {
          const conf = clamp(0.5 + 0.3 * Math.min(1, synRate / (4 * thrSyn)) + 0.2 * unanswered, 0, 0.99);
          emit('synflood', d.srcs > 1 ? -1 : d.one, dst, 0, conf, { rate: synRate, sources: d.srcs, unanswered: round(unanswered) });
          continue;
        }
      }
      const pkRate = d.pk / this.w;
      if (pkRate >= thrPk && d.srcs >= 10 && d.pk / total >= 0.5) {
        const conf = clamp(0.5 + 0.4 * Math.min(1, pkRate / (4 * thrPk)), 0, 0.97);
        emit('flood', -1, dst, 0, conf, { rate: pkRate, sources: d.srcs, share: round(d.pk / total) });
      }
    }
  }

  detectBrute(agg, emit) {
    const thr = 12 / this.s;
    for (const [key, ps] of agg.pairs) {
      if (!ps.auth) continue;
      for (const dp of ps.auth.keys()) {
        let attempts = 0;
        let ports = 0;
        let tStart = agg.t0;
        for (const h of this.hist) {
          const q = h.pairs.get(key);
          if (!q || !q.auth) continue;
          attempts += q.auth.get(dp) || 0;
          ports = Math.max(ports, q.ports ? q.ports.size : 0);
          if (q.tFirst < tStart) tStart = q.tFirst;
        }
        if (attempts < thr || ports >= 15 / this.s) continue;
        const conf = clamp(0.45 + 0.45 * Math.min(1, attempts / (50 / this.s)), 0, 0.97);
        emit('bruteforce', ps.src, ps.dst, dp, conf, { attempts, perMin: (attempts * 60) / this.span(), tStart });
      }
    }
  }

  detectExfil(agg, emit) {
    const thr = 3e6 / this.s;
    for (const [key, ps] of agg.pairs) {
      if (!this.hosts.internal[ps.src] || this.hosts.internal[ps.dst]) continue;
      let out = 0;
      let inn = 0;
      let tStart = agg.t0;
      const rk = pairKey(ps.dst, ps.src);
      for (const h of this.hist) {
        const q = h.pairs.get(key);
        if (q) {
          out += q.by;
          if (q.tFirst < tStart) tStart = q.tFirst;
        }
        const r = h.pairs.get(rk);
        if (r) inn += r.by;
      }
      if (out < thr) continue;
      const ratio = out / (inn + 1);
      if (ratio < 3) continue;
      const conf = clamp(0.5 + 0.35 * Math.min(1, Math.log10(out / thr + 1) / Math.log10(11)) + (ratio >= 10 ? 0.1 : 0), 0, 0.98);
      emit('exfil', ps.src, ps.dst, 0, conf, { bytes: out, ratio, rate: out / this.span(), tStart });
    }
  }

  detectDnsTunnel(agg, emit) {
    if (!agg.dns) return;
    const thrN = 25 / this.s;
    for (const [src, byBase] of agg.dns) {
      for (const [base, cur] of byBase) {
        let n = 0;
        let len = 0;
        let ent = 0;
        const subs = new Set();
        for (const h of this.hist) {
          const st = h.dns?.get(src)?.get(base);
          if (!st) continue;
          n += st.n;
          len += st.len;
          ent += st.ent;
          for (const s of st.subs) if (subs.size < 4096) subs.add(s);
        }
        if (n < thrN) continue;
        const avgLen = len / n;
        const avgEnt = ent / n;
        const unique = Math.min(1, subs.size / n);
        if (unique < 0.6 || (avgLen < 20 && avgEnt < 3.5)) continue;
        const conf = clamp(0.45 + 0.25 * Math.min(1, n / (100 / this.s)) + 0.25 * clamp((avgLen - 15) / 30), 0, 0.97);
        emit('dnstunnel', src, cur.dst, 53, conf, { domain: base, queries: n, avgLen: round(avgLen, 1), entropy: round(avgEnt), unique: round(unique) }, base);
      }
    }
  }

  detectSuspiciousPorts(agg, emit) {
    for (const [key, ps] of agg.pairs) {
      if (!ps.sus) continue;
      let packets = 0;
      for (const h of this.hist) {
        const q = h.pairs.get(key);
        if (q) packets += q.sus;
      }
      if (packets < 3) continue;
      emit('susport', ps.src, ps.dst, ps.susPort, 0.55, { packets, tStart: ps.tFirst });
    }
  }

  detectBeacons(agg, emit) {
    const st = agg.starts;
    if (!st.length) return;
    const thrCv = 0.1 * this.s;
    const touched = new Set();
    for (let i = 0; i < st.length; i += 4) {
      const src = st[i];
      const dst = st[i + 1];
      const dp = st[i + 2];
      const t = st[i + 3];
      const key = `${src}>${dst}:${dp}`;
      let b = this.beacons.get(key);
      if (!b) {
        if (this.beacons.size > 200000) continue;
        this.beacons.set(key, (b = { src, dst, dp, times: [] }));
      }
      const last = b.times[b.times.length - 1];
      if (last !== undefined && t - last < 0.5) continue;
      b.times.push(t);
      if (b.times.length > 24) b.times.shift();
      touched.add(b);
    }
    for (const b of touched) {
      // Не менее 8 соединений (7 интервалов): у случайных обращений вероятность
      // столь же регулярной последовательности пренебрежимо мала (порядка 10⁻⁵).
      if (b.times.length < 8) continue;
      let iv = [];
      for (let k = 1; k < b.times.length; k++) iv.push(b.times[k] - b.times[k - 1]);
      const m = median(iv);
      if (m < 2 || m > 3600) continue;
      // При 10+ соединениях допускается один выброс (пропущенный или повторный сеанс).
      if (iv.length >= 9) {
        let worst = 0;
        iv.forEach((x, k) => {
          if (Math.abs(x - m) > Math.abs(iv[worst] - m)) worst = k;
        });
        iv = iv.filter((_, k) => k !== worst);
      }
      const cv = intervalCv(iv);
      if (cv > thrCv) continue;
      const n = b.times.length;
      const conf = clamp(0.45 + 0.25 * Math.min(1, (n - 7) / 10) + 0.3 * (1 - cv / thrCv), 0.3, 0.97);
      emit('beacon', b.src, b.dst, b.dp, conf, { period: round(m, 1), jitter: round(cv, 3), count: n, tStart: b.times[0] });
    }
  }
}
