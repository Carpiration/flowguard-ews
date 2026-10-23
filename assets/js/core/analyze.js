// Пакетный конвейер анализа: трасса → окна признаков и поведенческие сигнатуры
// (проход 1) → Isolation Forest и статистические детекторы (проход 2) → отчёт.
// Онлайн-мониторинг использует те же классы, поэтому формулы офлайн- и
// live-режима совпадают.

import { THREATS, describeIncident } from './catalog.js';
import { confusion, episodes, metrics, roc } from './evaluate.js';
import { FEATURES, FX, WindowAccumulator, pairKey } from './features.js';
import { IsolationForest } from './iforest.js';
import { PatternDetector } from './patterns.js';
import { serviceName } from './ports.js';
import { ALL_COMPONENTS, ScoreEngine, StaticThreshold, levelOf, transform, warmupWindows } from './score.js';
import { FLOW_ORIG, PROTO, PROTO_NAMES, TCPF } from './trace.js';

export const MODEL_VERSION = '2.0.0';
const WINDOW_CANDIDATES = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 1800, 3600];
const PAIR_CAP = 300000;
const POST_ATTACK_BUFFER = 30;

export function chooseWindowSize(duration, requested = 'auto') {
  if (requested !== 'auto' && Number(requested) > 0) {
    let w = Number(requested);
    while (duration / w > 3000) w *= 2;
    return w;
  }
  for (const w of WINDOW_CANDIDATES) if (duration / w <= 300) return w;
  return 3600 * Math.ceil(duration / 3600 / 300);
}

export function newId() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  return `r-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

export function prepare(trace, { windowSize = 'auto', sensitivity = 1, allow = [], onProgress } = {}) {
  const n = trace.length;
  const t = trace.t;
  let sorted = true;
  let tMin = Infinity;
  let tMax = -Infinity;
  for (let i = 0; i < n; i++) {
    const v = t[i];
    if (v < tMin) tMin = v;
    if (v > tMax) tMax = v;
    if (i && v < t[i - 1]) sorted = false;
  }
  let order = null;
  if (!sorted) {
    order = new Uint32Array(n);
    for (let i = 0; i < n; i++) order[i] = i;
    order.sort((a, b) => t[a] - t[b]);
  }
  const duration = Math.max(tMax - tMin, 1e-6);
  const w = chooseWindowSize(duration, windowSize);
  const hosts = trace.hosts;
  const allowIds = new Set();
  for (const a of allow) {
    const id = hosts.index.get(String(a).trim());
    if (id !== undefined) allowIds.add(id);
  }
  const patterns = new PatternDetector({ windowSize: w, sensitivity, hosts, allow: allowIds });
  const windows = [];
  const acc = new WindowAccumulator({
    windowSize: w,
    hosts,
    flowMode: trace.flowMode,
    onWindow: (agg) => {
      const hits = patterns.process(agg);
      if (agg.partial) return;
      windows.push({ t0: agg.t0, t1: agg.t1, f: agg.f, attack: agg.attack, labels: agg.labels ? [...agg.labels] : null, hits });
    },
  });

  const H = hosts.size;
  const hs = { pkOut: new Float64Array(H), pkIn: new Float64Array(H), byOut: new Float64Array(H), byIn: new Float64Array(H) };
  const proto = PROTO_NAMES.map(() => ({ pk: 0, by: 0 }));
  const services = new Map();
  const pairs = new Map();
  let packets = 0;
  let bytes = 0;
  const { src, dst, sp, dp, flags, len, q, label, strings, labels } = trace;
  const pr = trace.proto;
  const cnt = trace.n;
  const step = Math.max(1, Math.floor(n / 40));
  for (let j = 0; j < n; j++) {
    const i = order ? order[j] : j;
    const s = src[i];
    const d = dst[i];
    const c = cnt[i];
    const l = len[i];
    const p = pr[i];
    const fl = flags[i];
    acc.add(t[i], s, d, sp[i], dp[i], p, l, fl, c, q[i] >= 0 ? strings[q[i]] : null, label[i] >= 0 ? labels[label[i]] : null);
    packets += c;
    bytes += l;
    hs.pkOut[s] += c;
    hs.byOut[s] += l;
    hs.pkIn[d] += c;
    hs.byIn[d] += l;
    proto[p].pk += c;
    proto[p].by += l;
    let request;
    if (trace.flowMode) request = (fl & FLOW_ORIG) !== 0;
    else if (p === PROTO.TCP) request = (fl & TCPF.SYN) !== 0 && (fl & TCPF.ACK) === 0;
    else if (p === PROTO.UDP) request = !(sp[i] > 0 && sp[i] < 1024 && dp[i] >= 1024);
    else request = false;
    if (request && p !== PROTO.ICMP) {
      let sv = services.get(dp[i]);
      if (!sv) services.set(dp[i], (sv = { conns: 0, proto: p }));
      sv.conns += trace.flowMode ? 1 : c;
    }
    const key = pairKey(s, d);
    const pe = pairs.get(key);
    if (pe) {
      pe[0] += c;
      pe[1] += l;
    } else if (pairs.size < PAIR_CAP) pairs.set(key, [c, l, s, d]);
    if (j % step === 0) onProgress?.('features', j / n);
  }
  acc.flush(tMax);
  return { trace, w, duration, tMin, tMax, windows, patterns, hs, proto, services, pairs, packets, bytes, sensitivity };
}

// Isolation Forest предполагает, что аномалий мало. Чтобы атаки не загрязняли
// обучение, лес обучается на «вероятно нормальных» окнах: предварительный проход
// без леса отбирает окна с риском ниже уровня предупреждения.
export function fitForest(prep, seed = 7, { sensitivity = prep.sensitivity ?? 1 } = {}) {
  prep.X = prep.windows.map((win) => transform(win.f));
  if (prep.X.length < 16) return null;
  const pre = scoreWindows(prep, { sensitivity, components: { baseline: true, cusum: true, iforest: false, patterns: true } });
  let train = prep.X.filter((_, i) => pre[i].risk < 25);
  if (train.length < 16) train = prep.X;
  prep.forestTrain = train.length;
  return new IsolationForest({ trees: 100, sampleSize: 256, seed }).fit(train);
}

export function scoreWindows(prep, { sensitivity = 1, threshold = 50, components = ALL_COMPONENTS, forest = null } = {}) {
  const engine = new ScoreEngine({ windowSize: prep.w, sensitivity, threshold, components });
  return prep.windows.map((win, k) => engine.process(win.f, forest ? forest.zscore(prep.X[k]) : null, win.hits));
}

export function staticScores(prep) {
  const st = new StaticThreshold({ windowSize: prep.w });
  return prep.windows.map((win) => st.process(win.f));
}

export function analyzeTrace(trace, opts = {}) {
  const { onProgress } = opts;
  const prep = prepare(trace, opts);
  onProgress?.('model', 0.2);
  const forest = fitForest(prep, opts.seed ?? 7);
  onProgress?.('model', 0.6);
  const results = scoreWindows(prep, { ...opts, forest });
  onProgress?.('report', 0.9);
  return buildReport(prep, results, opts);
}

// Окна сразу после атаки исключаются из оценки: сглаженный риск затухает
// постепенно, и такие окна нельзя честно считать ложными срабатываниями.
export function postAttackMask(windows, labels, buffer = POST_ATTACK_BUFFER) {
  const mask = new Array(windows.length).fill(true);
  let lastPosEnd = -Infinity;
  for (let i = 0; i < windows.length; i++) {
    if (labels[i]) lastPosEnd = windows[i].t1;
    else if (windows[i].t0 < lastPosEnd + buffer) mask[i] = false;
  }
  return mask;
}

const r1 = (x) => Math.round(x * 10) / 10;
const r2 = (x) => Math.round(x * 100) / 100;
const r3 = (x) => Math.round(x * 1000) / 1000;

export function summarizeRisk(results, windows, threshold) {
  let peak = 0;
  let peakAt = null;
  let sum = 0;
  let alarm = 0;
  let warning = 0;
  for (let i = 0; i < results.length; i++) {
    const r = results[i].risk;
    sum += r;
    if (r > peak) {
      peak = r;
      peakAt = windows[i].t1;
    }
    if (results[i].state === 'alarm') alarm++;
    else if (results[i].state === 'warning') warning++;
  }
  const eps = episodes(results.map((r) => r.risk), windows.map((w) => w.t0), windows.map((w) => w.t1), threshold);
  // Время упреждения: насколько раньше тревоги модель перешла в «Предупреждение».
  // Учитываются только эпизоды, которым предшествовала норма: затухающий «хвост»
  // предыдущей тревоги не считается ранним предупреждением.
  const leads = [];
  for (const ep of eps) {
    let i = ep.from - 1;
    while (i >= 0 && results[i].state === 'warning') i--;
    if (i >= 0 && results[i].state === 'alarm') continue;
    leads.push(ep.start - windows[i + 1].t0);
  }
  const firstWarn = results.findIndex((r) => r.state !== 'normal');
  return {
    peak: r1(peak),
    peakAt,
    level: levelOf(peak).id,
    mean: r1(results.length ? sum / results.length : 0),
    current: r1(results.length ? results[results.length - 1].risk : 0),
    alarmWindows: alarm,
    warningWindows: warning,
    episodes: eps.length,
    firstWarning: firstWarn >= 0 ? windows[firstWarn].t1 : null,
    firstAlarm: eps.length ? windows[eps[0].from].t1 : null,
    leadTimes: leads.map(r1),
  };
}

export function buildReport(prep, results, { sensitivity = 1, threshold = 50 } = {}) {
  const { windows, w, trace, patterns, hs } = prep;
  const hosts = trace.hosts;
  const hostName = (id) => hosts.name(id);

  const incidents = patterns.incidents
    .slice()
    .sort((a, b) => b.sev * b.peak - a.sev * a.peak)
    .slice(0, 1000)
    .sort((a, b) => a.tDetect - b.tDetect)
    .map((inc) => ({
      id: inc.id,
      type: inc.type,
      name: THREATS[inc.type].name,
      sev: inc.sev,
      mitre: THREATS[inc.type].mitre,
      conf: r2(inc.conf),
      peak: r2(inc.peak),
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

  const involvement = new Map();
  for (const inc of incidents) {
    for (const h of [inc.src, inc.dst]) {
      if (!h) continue;
      const cur = involvement.get(h) || { count: 0, sev: 0 };
      cur.count++;
      cur.sev = Math.max(cur.sev, inc.sev);
      involvement.set(h, cur);
    }
  }
  const peers = new Uint32Array(hosts.size);
  for (const pe of prep.pairs.values()) {
    peers[pe[2]]++;
    peers[pe[3]]++;
  }
  const hostIds = [...Array(hosts.size).keys()]
    .sort((a, b) => hs.byOut[b] + hs.byIn[b] - (hs.byOut[a] + hs.byIn[a]))
    .slice(0, 300);
  const hostRows = hostIds.map((id) => {
    const name = hostName(id);
    const inv = involvement.get(name);
    return {
      ip: name,
      internal: Boolean(hosts.internal[id]),
      pkOut: hs.pkOut[id],
      pkIn: hs.pkIn[id],
      byOut: hs.byOut[id],
      byIn: hs.byIn[id],
      peers: peers[id],
      incidents: inv ? inv.count : 0,
      sev: inv ? inv.sev : 0,
    };
  });
  for (const [name, inv] of involvement) {
    if (hostRows.some((h) => h.ip === name)) continue;
    const id = hosts.index.get(name);
    if (id === undefined) continue;
    hostRows.push({ ip: name, internal: Boolean(hosts.internal[id]), pkOut: hs.pkOut[id], pkIn: hs.pkIn[id], byOut: hs.byOut[id], byIn: hs.byIn[id], peers: peers[id], incidents: inv.count, sev: inv.sev });
  }

  const flows = [...prep.pairs.values()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 25)
    .map(([pk, by, s, d]) => ({ src: hostName(s), dst: hostName(d), pk, by }));

  const services = [...prep.services.entries()]
    .sort((a, b) => b[1].conns - a[1].conns)
    .slice(0, 12)
    .map(([port, sv]) => ({ port, name: serviceName(port), conns: sv.conns, proto: PROTO_NAMES[sv.proto] }));

  const internalHosts = hosts.internal.reduce((s, v) => s + v, 0);
  const notes = [...trace.notes];
  if (windows.length < 20) notes.push(`Окон анализа мало (${windows.length}): статистические детекторы менее надёжны, чем на длинных записях.`);
  if (trace.flowMode) notes.push('Источник содержит сетевые потоки: признаки рассчитаны по записям потоков, а не по отдельным пакетам.');
  if (prep.pairs.size >= PAIR_CAP) notes.push('Пар узлов слишком много: таблица потоков построена по первым 300 000 парам.');

  const report = {
    version: MODEL_VERSION,
    id: newId(),
    createdAt: Date.now(),
    source: null,
    params: { windowSize: w, sensitivity, threshold, warmup: warmupWindows(w) * w },
    stats: {
      records: trace.length,
      packets: prep.packets,
      bytes: prep.bytes,
      duration: prep.duration,
      tStart: prep.tMin,
      tEnd: prep.tMax,
      absoluteTime: prep.tMin > 1e8 && !trace.syntheticTime,
      hosts: hosts.size,
      internalHosts,
      externalHosts: hosts.size - internalHosts,
      pairs: prep.pairs.size,
      flowMode: trace.flowMode,
      labelled: trace.labelled,
      windows: windows.length,
    },
    risk: summarizeRisk(results, windows, threshold),
    timeline: {
      t0: windows.map((x) => x.t0),
      pkts: windows.map((x) => x.f[FX.PKTS]),
      bytes: windows.map((x) => x.f[FX.BYTES]),
      risk: results.map((r) => r1(r.risk)),
      base: results.map((r) => r3(r.sBase)),
      cusum: results.map((r) => r3(r.sCusum)),
      iforest: results.map((r) => r3(r.sIf)),
      patterns: results.map((r) => r3(r.P)),
      state: results.map((r) => (r.state === 'alarm' ? 2 : r.state === 'warning' ? 1 : 0)),
      warm: results.map((r) => (r.warming ? 1 : 0)),
      attack: trace.labelled ? windows.map((x) => (x.attack > 0 ? 1 : 0)) : null,
    },
    detail: {
      f: windows.map((x) => Array.from(x.f, r2)),
      z: results.map((r) => Array.from(r.z, r2)),
      top: results.map((r) => r.top),
      hits: windows.map((x) => x.hits.map((h) => h.id)),
    },
    features: FEATURES.map((f) => f.id),
    incidents,
    hosts: hostRows,
    protocols: prep.proto.map((p, i) => ({ name: PROTO_NAMES[i], pk: p.pk, by: p.by })).filter((p) => p.pk > 0),
    services,
    flows,
    evaluation: trace.labelled ? evaluateWindows(prep, results, threshold) : null,
    notes,
  };
  return report;
}

export function evaluateWindows(prep, results, threshold) {
  const { windows } = prep;
  const labels = windows.map((x) => (x.attack > 0 ? 1 : 0));
  const mask = postAttackMask(windows, labels);
  const scores = results.map((r) => r.risk);
  const st = staticScores(prep);
  const m = metrics(confusion(scores, labels, threshold, mask));
  const rc = roc(scores, labels, mask);
  const rs = roc(st, labels, mask);
  const names = new Map();
  windows.forEach((x, i) => {
    for (const l of x.labels || []) if (!names.has(l)) names.set(l, i);
  });
  const perLabel = [...names].map(([name, first]) => {
    const t0 = windows[first].t0;
    let det = -1;
    for (let i = first; i < windows.length; i++) {
      if (!windows[i].labels?.includes(name)) continue;
      if (scores[i] >= threshold) {
        det = i;
        break;
      }
    }
    return { name, start: t0, detected: det >= 0, delay: det >= 0 ? windows[det].t1 - t0 : null };
  });
  return {
    threshold,
    ...m,
    auc: rc.auc,
    roc: rc.points,
    staticAuc: rs.auc,
    staticRoc: rs.points,
    staticMetrics: metrics(confusion(st, labels, 50, mask)),
    positives: rc.positives,
    negatives: rc.negatives,
    excluded: mask.filter((x) => !x).length,
    perLabel,
  };
}
