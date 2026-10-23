// Сеанс мониторинга в реальном времени. Источник — генератор трафика (браузер
// не имеет доступа к сетевому интерфейсу); обработка — те же классы, что и в
// пакетном анализе: окна признаков, сигнатуры, EWMA/CUSUM, Isolation Forest.
// Сеанс продолжается при переходе между разделами приложения.

import { evaluateWindows, MODEL_VERSION, newId, summarizeRisk } from '../core/analyze.js';
import { THREATS, describeIncident } from '../core/catalog.js';
import { FEATURES, FX, WindowAccumulator, pairKey } from '../core/features.js';
import { IsolationForest } from '../core/iforest.js';
import { makeInternalMatcher } from '../core/net.js';
import { PatternDetector } from '../core/patterns.js';
import { serviceName } from '../core/ports.js';
import { ScoreEngine, levelOf, transform, warmupWindows } from '../core/score.js';
import { BASE_TIME, SCENARIOS, TrafficSimulator } from '../core/simulate.js';
import { HostTable, PROTO_NAMES } from '../core/trace.js';
import { analysisOptions } from './settings.js';

export const LIVE_WINDOW = 2;
const TICK_MS = 250;
const KEEP = 3600;
const WARM_SPEED = 8;

export const LIVE_DURATION = { sweep: 45, portscan: 100, bruteforce: 70, beacon: 260, dnstunnel: 70, exfil: 90, synflood: 50 };

class LiveService extends EventTarget {
  constructor() {
    super();
    this.state = 'idle';
    this.speed = 1;
  }

  get running() {
    return this.state === 'running' || this.state === 'paused';
  }

  start({ speed = this.speed } = {}) {
    if (this.running) return;
    const opts = analysisOptions();
    this.opts = opts;
    this.speed = speed;
    this.seed = (Date.now() % 2147483000) + 1;
    this.sim = new TrafficSimulator({ seed: this.seed });
    this.hosts = new HostTable(makeInternalMatcher(opts.internal));
    const allow = new Set(opts.allow.map((a) => this.hosts.id(a)));
    this.patterns = new PatternDetector({ windowSize: LIVE_WINDOW, sensitivity: opts.sensitivity, hosts: this.hosts, allow });
    this.engine = new ScoreEngine({ windowSize: LIVE_WINDOW, sensitivity: opts.sensitivity, threshold: opts.threshold });
    this.acc = new WindowAccumulator({ windowSize: LIVE_WINDOW, hosts: this.hosts, onWindow: (agg) => this.onWindow(agg) });
    this.acc.start(BASE_TIME);
    this.simTime = 0;
    this.forest = null;
    this.trainX = [];
    this.sinceFit = 0;
    this.win = { t0: [], pkts: [], bytes: [], risk: [], state: [], base: [], cusum: [], iforest: [], patterns: [], warm: [], attack: [], f: [], z: [], top: [], hits: [], labels: [] };
    this.events = [];
    this.truth = [];
    this.seenIncidents = 0;
    this.lastState = 'normal';
    this.readyLogged = false;
    this.lastPairs = [];
    this.totals = { packets: 0, bytes: 0, proto: PROTO_NAMES.map(() => ({ pk: 0, by: 0 })), host: new Map(), pairs: new Map(), services: new Map() };
    this.warmN = warmupWindows(LIVE_WINDOW);
    this.startedAt = Date.now();
    this.state = 'running';
    this.timer = setInterval(() => this.tick(), TICK_MS);
    this.log({ kind: 'info', title: 'Мониторинг запущен', text: `Обучение базовой линии: первые ${this.warmN * LIVE_WINDOW} с трафика (ускоренно).` });
    this.emit();
  }

  pause() {
    if (this.state !== 'running') return;
    this.state = 'paused';
    clearInterval(this.timer);
    this.emit();
  }

  resume() {
    if (this.state !== 'paused') return;
    this.state = 'running';
    this.timer = setInterval(() => this.tick(), TICK_MS);
    this.emit();
  }

  setSpeed(speed) {
    this.speed = speed;
    this.emit();
  }

  stop() {
    if (!this.running) return null;
    clearInterval(this.timer);
    const report = this.win.t0.length >= 3 ? this.buildReport() : null;
    this.state = 'idle';
    this.sim = null;
    this.emit();
    return report;
  }

  get warming() {
    return Boolean(this.engine && !this.engine.ready);
  }

  inject(type) {
    if (this.state !== 'running' || this.warming) return null;
    const dur = LIVE_DURATION[type] || SCENARIOS[type].duration;
    const t0 = this.simTime + 0.5;
    const truth = this.sim.addScenario(type, t0, dur);
    const rec = { ...truth, t0: BASE_TIME + truth.t0, t1: BASE_TIME + truth.t1 };
    this.truth.push(rec);
    this.log({ kind: 'inject', title: `Внедрена атака: ${SCENARIOS[type].name}`, text: `${truth.attacker} → ${truth.target}, длительность ${dur} с.`, t: rec.t0 });
    this.emit();
    return rec;
  }

  activeScenarios() {
    const now = BASE_TIME + this.simTime;
    return this.truth.filter((s) => s.t1 > now).map((s) => ({ ...s, left: s.t1 - now }));
  }

  tick() {
    const speed = this.warming ? WARM_SPEED : this.speed;
    const dt = (TICK_MS / 1000) * speed;
    const from = this.simTime;
    const to = from + dt;
    const T = this.totals;
    this.sim.step(from, to, (p) => {
      const s = this.hosts.id(p.s);
      const d = this.hosts.id(p.d);
      this.acc.add(BASE_TIME + p.t, s, d, p.sp, p.dp, p.pr, p.len, p.fl, 1, p.q, p.lab);
      T.packets++;
      T.bytes += p.len;
      T.proto[p.pr].pk++;
      T.proto[p.pr].by += p.len;
      const hs = T.host.get(s) || T.host.set(s, [0, 0, 0, 0]).get(s);
      hs[0]++;
      hs[2] += p.len;
      const hd = T.host.get(d) || T.host.set(d, [0, 0, 0, 0]).get(d);
      hd[1]++;
      hd[3] += p.len;
      const key = pairKey(s, d);
      const pe = T.pairs.get(key);
      if (pe) {
        pe[0]++;
        pe[1] += p.len;
      } else if (T.pairs.size < 50000) T.pairs.set(key, [1, p.len, s, d]);
      if ((p.fl & 18) === 2 || (p.pr === 2 && !(p.sp > 0 && p.sp < 1024 && p.dp >= 1024))) T.services.set(p.dp, (T.services.get(p.dp) || 0) + 1);
    });
    this.simTime = to;
    this.acc.advanceTo(BASE_TIME + to);
  }

  onWindow(agg) {
    const hits = this.patterns.process(agg);
    const x = transform(agg.f);
    const z = this.forest ? this.forest.zscore(x) : null;
    const r = this.engine.process(agg.f, z, hits);
    if (!r.warming && r.risk < 25) {
      this.trainX.push(x);
      if (this.trainX.length > 400) this.trainX.shift();
    }
    this.sinceFit++;
    if (this.engine.ready && ((!this.forest && this.trainX.length >= 30) || (this.forest && this.sinceFit >= 90 && this.trainX.length >= 30))) {
      this.forest = new IsolationForest({ trees: 80, sampleSize: 128, seed: this.seed }).fit(this.trainX);
      this.sinceFit = 0;
      this.log({ kind: 'model', title: 'Isolation Forest обучен', text: `${this.trainX.length} окон нормального трафика, 80 деревьев.` });
    }
    const W = this.win;
    const code = r.state === 'alarm' ? 2 : r.state === 'warning' ? 1 : 0;
    W.t0.push(agg.t0);
    W.pkts.push(agg.f[FX.PKTS]);
    W.bytes.push(agg.f[FX.BYTES]);
    W.risk.push(Math.round(r.risk * 10) / 10);
    W.state.push(code);
    W.base.push(r.sBase);
    W.cusum.push(r.sCusum);
    W.iforest.push(r.sIf);
    W.patterns.push(r.P);
    W.warm.push(r.warming ? 1 : 0);
    W.attack.push(agg.attack > 0 ? 1 : 0);
    W.labels.push(agg.labels ? [...agg.labels] : null);
    W.f.push(Array.from(agg.f, (v) => Math.round(v * 100) / 100));
    W.z.push(Array.from(r.z, (v) => Math.round(v * 100) / 100));
    W.top.push(r.top);
    W.hits.push(hits.map((h) => h.id));
    if (W.t0.length > KEEP) for (const k of Object.keys(W)) W[k].shift();

    if (this.engine.ready && !this.readyLogged) {
      this.readyLogged = true;
      this.log({ kind: 'model', title: 'Базовая линия обучена', text: 'Можно внедрять атаки: модель сравнивает трафик с изученной нормой.' });
    }
    const incs = this.patterns.incidents;
    for (let i = this.seenIncidents; i < incs.length; i++) {
      const inc = incs[i];
      this.log({ kind: 'incident', sev: inc.sev, title: THREATS[inc.type].name, text: describeIncident(inc, (id) => this.hosts.name(id)), t: inc.tDetect, incident: inc.id });
      if (inc.sev >= 3) window.dispatchEvent(new CustomEvent('fg:live-alarm', { detail: { title: THREATS[inc.type].name } }));
    }
    this.seenIncidents = incs.length;
    if (r.state !== this.lastState) {
      const names = { normal: 'Норма', warning: 'Раннее предупреждение', alarm: 'Тревога' };
      const top = r.top.map((k) => FEATURES[k].short).join(', ');
      this.log({ kind: 'state', state: r.state, title: `Состояние: ${names[r.state]}`, text: `Риск ${Math.round(r.risk)}${top ? `; отклонения: ${top}` : ''}.`, t: agg.t1 });
      this.lastState = r.state;
    }
    this.lastPairs = [...agg.pairs.values()]
      .sort((a, b) => b.pk - a.pk)
      .slice(0, 90)
      .map((p) => ({ s: p.src, d: p.dst, pk: p.pk, by: p.by }));
    this.current = { ...r, t0: agg.t0, t1: agg.t1, pkts: agg.f[FX.PKTS], hosts: agg.f[FX.SRCS] };
    this.emit('window');
  }

  log(ev) {
    this.events.unshift({ id: newId(), at: ev.t ?? BASE_TIME + (this.simTime || 0), ...ev });
    if (this.events.length > 80) this.events.pop();
    this.dispatchEvent(new CustomEvent('event', { detail: this.events[0] }));
  }

  // Узлы, участвующие в недавних инцидентах (для подсветки на карте).
  hotHosts(horizon = 30) {
    const now = BASE_TIME + this.simTime;
    const hot = new Map();
    for (const inc of this.patterns?.incidents || []) {
      if (now - inc.tLast > horizon) continue;
      for (const h of [inc.src, inc.dst]) if (h >= 0) hot.set(h, Math.max(hot.get(h) || 0, inc.sev));
    }
    return hot;
  }

  emit(type = 'state') {
    this.dispatchEvent(new CustomEvent(type));
    const risk = this.current?.risk || 0;
    window.dispatchEvent(new CustomEvent('fg:live', { detail: { running: this.running, risk, level: levelOf(risk).id, warming: this.warming } }));
  }

  buildReport() {
    const W = this.win;
    const n = W.t0.length;
    const hostName = (id) => this.hosts.name(id);
    const windows = W.t0.map((t0, i) => ({ t0, t1: t0 + LIVE_WINDOW, f: W.f[i], attack: W.attack[i], labels: W.labels[i] }));
    const results = W.risk.map((risk, i) => ({ risk, state: ['normal', 'warning', 'alarm'][W.state[i]] }));
    const tau = this.opts.threshold;
    const incidents = this.patterns.incidents.map((inc) => ({
      id: inc.id,
      type: inc.type,
      name: THREATS[inc.type].name,
      sev: inc.sev,
      mitre: THREATS[inc.type].mitre,
      conf: Math.round(inc.conf * 100) / 100,
      peak: Math.round(inc.peak * 100) / 100,
      src: inc.src >= 0 ? hostName(inc.src) : null,
      dst: inc.dst >= 0 ? hostName(inc.dst) : null,
      port: inc.port || null,
      service: inc.port ? serviceName(inc.port) : null,
      tStart: inc.tStart,
      tDetect: inc.tDetect,
      tLast: inc.tLast,
      windows: inc.windows,
      evidence: inc.evidence,
      description: describeIncident(inc, hostName),
    }));
    const T = this.totals;
    const involvement = new Map();
    for (const i of incidents) for (const h of [i.src, i.dst]) if (h) involvement.set(h, Math.max(involvement.get(h) || 0, i.sev));
    const peers = new Map();
    for (const [, , s, d] of T.pairs.values()) {
      peers.set(s, (peers.get(s) || 0) + 1);
      peers.set(d, (peers.get(d) || 0) + 1);
    }
    const hosts = [...T.host.entries()]
      .sort((a, b) => b[1][2] + b[1][3] - (a[1][2] + a[1][3]))
      .slice(0, 300)
      .map(([id, h]) => {
        const ip = hostName(id);
        return { ip, internal: Boolean(this.hosts.internal[id]), pkOut: h[0], pkIn: h[1], byOut: h[2], byIn: h[3], peers: peers.get(id) || 0, incidents: incidents.filter((i) => i.src === ip || i.dst === ip).length, sev: involvement.get(ip) || 0 };
      });
    const internalHosts = this.hosts.internal.reduce((s, v) => s + v, 0);
    const prepLike = { windows, w: LIVE_WINDOW };
    const labelled = W.attack.some(Boolean);
    return {
      version: MODEL_VERSION,
      id: newId(),
      createdAt: Date.now(),
      source: { name: `Сеанс мониторинга ${new Date(this.startedAt).toLocaleString('ru-RU', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })}`, kind: 'live', format: 'Симуляция в браузере', size: 0 },
      params: { windowSize: LIVE_WINDOW, sensitivity: this.opts.sensitivity, threshold: tau, warmup: this.warmN * LIVE_WINDOW },
      stats: {
        records: T.packets,
        packets: T.packets,
        bytes: T.bytes,
        duration: this.simTime,
        tStart: W.t0[0],
        tEnd: W.t0[n - 1] + LIVE_WINDOW,
        absoluteTime: true,
        hosts: this.hosts.size,
        internalHosts,
        externalHosts: this.hosts.size - internalHosts,
        pairs: T.pairs.size,
        flowMode: false,
        labelled,
        windows: n,
      },
      risk: summarizeRisk(results, windows, tau),
      timeline: {
        t0: W.t0,
        pkts: W.pkts,
        bytes: W.bytes,
        risk: W.risk,
        base: W.base.map((v) => Math.round(v * 1000) / 1000),
        cusum: W.cusum.map((v) => Math.round(v * 1000) / 1000),
        iforest: W.iforest.map((v) => Math.round(v * 1000) / 1000),
        patterns: W.patterns.map((v) => Math.round(v * 1000) / 1000),
        state: W.state,
        warm: W.warm,
        attack: labelled ? W.attack : null,
      },
      detail: { f: W.f, z: W.z, top: W.top, hits: W.hits },
      features: FEATURES.map((f) => f.id),
      incidents,
      hosts,
      protocols: T.proto.map((p, i) => ({ name: PROTO_NAMES[i], pk: p.pk, by: p.by })).filter((p) => p.pk > 0),
      services: [...T.services.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12).map(([port, conns]) => ({ port, name: serviceName(port), conns, proto: '' })),
      flows: [...T.pairs.values()].sort((a, b) => b[1] - a[1]).slice(0, 25).map(([pk, by, s, d]) => ({ src: hostName(s), dst: hostName(d), pk, by })),
      evaluation: labelled ? evaluateWindows(prepLike, results, tau) : null,
      notes: ['Сеанс построен на сгенерированном трафике: браузер не имеет доступа к сетевому интерфейсу.', ...(labelled ? ['Атаки внедрены вручную; разметка окон известна, поэтому рассчитаны метрики качества.'] : [])],
    };
  }
}

export const live = new LiveService();
