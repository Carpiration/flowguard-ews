// Экспериментальная оценка модели на размеченных синтетических данных:
// метрики по окнам, ROC-AUC, задержка обнаружения каждого сценария, частота
// ложных тревог, сравнение с классическим порогом и абляция компонентов.

import { buildReport, fitForest, postAttackMask, prepare, scoreWindows, staticScores } from './analyze.js';
import { confusion, episodes, mean, metrics, roc, sd } from './evaluate.js';
import { ALL_COMPONENTS } from './score.js';
import { DEFAULT_SCHEDULE, SCENARIOS, generateDataset } from './simulate.js';

export const VARIANTS = [
  { id: 'full', name: 'Ансамбль FlowGuard', components: ALL_COMPONENTS },
  { id: 'static', name: 'Статический порог μ+3σ', components: null },
  { id: 'ewma', name: 'Только EWMA-z', components: { baseline: true } },
  { id: 'cusum', name: 'Только CUSUM', components: { cusum: true } },
  { id: 'iforest', name: 'Только Isolation Forest', components: { iforest: true } },
  { id: 'patterns', name: 'Только поведенческие сигнатуры', components: { patterns: true } },
];

const NONE = { baseline: false, cusum: false, iforest: false, patterns: false };
const BUFFER = 30;

function detectionDelay(sc, prep, scores, tau) {
  for (let i = 0; i < prep.windows.length; i++) {
    const win = prep.windows[i];
    if (win.t1 <= sc.t0) continue;
    if (win.t0 > sc.t1 + BUFFER) break;
    if (!win.labels?.includes(sc.type) && win.t0 < sc.t1) continue;
    if (scores[i] >= tau) return Math.max(0, win.t1 - sc.t0);
  }
  return null;
}

function firstState(sc, prep, results, minState) {
  for (let i = 0; i < prep.windows.length; i++) {
    const win = prep.windows[i];
    if (win.t1 <= sc.t0 || !win.labels?.includes(sc.type)) continue;
    if (win.t0 > sc.t1) break;
    const s = results[i].state;
    if ((minState === 'warning' && s !== 'normal') || s === 'alarm') return Math.max(0, win.t1 - sc.t0);
  }
  return null;
}

export function runLab(options = {}, onProgress) {
  const { seed = 42, duration = 1200, schedule = DEFAULT_SCHEDULE, sensitivity = 1, threshold = 50, runs = 1 } = options;
  const perRun = [];
  let first = null;
  for (let r = 0; r < runs; r++) {
    const runSeed = seed + r * 7919;
    onProgress?.('generate', r / runs);
    const { trace, truth } = generateDataset({ seed: runSeed, duration, schedule });
    onProgress?.('features', (r + 0.3) / runs);
    const prep = prepare(trace, { sensitivity });
    const forest = fitForest(prep, runSeed);
    onProgress?.('model', (r + 0.6) / runs);
    const labels = prep.windows.map((w) => (w.attack > 0 ? 1 : 0));
    const mask = postAttackMask(prep.windows, labels, BUFFER);
    const t0s = prep.windows.map((w) => w.t0);
    const t1s = prep.windows.map((w) => w.t1);
    const variants = {};
    let fullResults = null;
    for (const v of VARIANTS) {
      let scores;
      let results = null;
      if (!v.components) scores = staticScores(prep);
      else {
        results = scoreWindows(prep, { sensitivity, threshold, components: { ...NONE, ...v.components }, forest });
        scores = results.map((x) => x.risk);
        if (v.id === 'full') fullResults = results;
      }
      const m = metrics(confusion(scores, labels, threshold, mask));
      const rc = roc(scores, labels, mask);
      const delays = truth.map((sc) => detectionDelay(sc, prep, scores, threshold));
      const eps = episodes(scores, t0s, t1s, threshold);
      const falseEpisodes = eps.filter((e) => !truth.some((sc) => e.start < sc.t1 + BUFFER && e.end > sc.t0)).length;
      variants[v.id] = {
        metrics: m,
        auc: rc.auc,
        roc: rc.points,
        delays,
        detected: delays.filter((d) => d !== null).length,
        falsePerHour: falseEpisodes / (duration / 3600),
        scores: scores.map((x) => Math.round(x * 10) / 10),
      };
    }
    const typed = truth.map((sc) => {
      const expect = SCENARIOS[sc.type].expect;
      const inc = prep.patterns.incidents
        .filter((i) => expect.includes(i.type) && i.tDetect >= sc.t0 && i.tDetect <= sc.t1 + BUFFER)
        .sort((a, b) => a.tDetect - b.tDetect)[0];
      return inc ? { detected: true, delay: inc.tDetect - sc.t0, conf: inc.peak, type: inc.type } : { detected: false };
    });
    const warn = truth.map((sc) => firstState(sc, prep, fullResults, 'warning'));
    perRun.push({ seed: runSeed, truth, variants, typed, warn });
    if (r === 0) first = { prep, fullResults, labels, mask, truth };
    // Освобождаем крупные структуры прогона, кроме первого.
    if (r > 0) prep.windows = null;
  }

  const summary = {};
  for (const v of VARIANTS) {
    const rows = perRun.map((p) => p.variants[v.id]);
    const pick = (fn) => rows.map(fn);
    const meanDelays = rows.map((row) => mean(row.delays));
    summary[v.id] = {
      precision: { mean: mean(pick((x) => x.metrics.precision)), sd: sd(pick((x) => x.metrics.precision)) },
      recall: { mean: mean(pick((x) => x.metrics.recall)), sd: sd(pick((x) => x.metrics.recall)) },
      f1: { mean: mean(pick((x) => x.metrics.f1)), sd: sd(pick((x) => x.metrics.f1)) },
      fpr: { mean: mean(pick((x) => x.metrics.fpr)), sd: sd(pick((x) => x.metrics.fpr)) },
      auc: { mean: mean(pick((x) => x.auc)), sd: sd(pick((x) => x.auc)) },
      delay: { mean: mean(meanDelays), sd: sd(meanDelays) },
      detectionRate: { mean: mean(rows.map((x) => x.detected / x.delays.length)), sd: sd(rows.map((x) => x.detected / x.delays.length)) },
      falsePerHour: { mean: mean(pick((x) => x.falsePerHour)), sd: sd(pick((x) => x.falsePerHour)) },
    };
  }

  const run0 = perRun[0];
  const scenarios = run0.truth.map((sc, i) => ({
    type: sc.type,
    name: sc.name,
    t0: sc.t0,
    t1: sc.t1,
    attacker: sc.attacker,
    target: sc.target,
    typed: run0.typed[i],
    warnDelay: run0.warn[i],
    delays: Object.fromEntries(VARIANTS.map((v) => [v.id, run0.variants[v.id].delays[i]])),
  }));

  onProgress?.('report', 0.95);
  const report = buildReport(first.prep, first.fullResults, { sensitivity, threshold });
  report.source = { name: `Лаборатория: seed ${seed}, ${Math.round(duration / 60)} мин`, kind: 'lab', format: 'Синтетический набор' };

  return {
    params: { seed, duration, sensitivity, threshold, runs, buffer: BUFFER, windowSize: first.prep.w, schedule },
    variants: VARIANTS.map(({ id, name }) => ({ id, name })),
    summary,
    scenarios,
    runs: perRun.map((p) => ({ seed: p.seed, f1: p.variants.full.metrics.f1, auc: p.variants.full.auc, staticF1: p.variants.static.metrics.f1, staticAuc: p.variants.static.auc })),
    first: {
      labels: first.labels,
      mask: first.mask,
      t0: first.prep.windows.map((w) => w.t0),
      t1: first.prep.windows.map((w) => w.t1),
      scores: Object.fromEntries(VARIANTS.map((v) => [v.id, run0.variants[v.id].scores])),
      roc: Object.fromEntries(VARIANTS.map((v) => [v.id, run0.variants[v.id].roc])),
      metrics: Object.fromEntries(VARIANTS.map((v) => [v.id, { ...run0.variants[v.id].metrics, auc: run0.variants[v.id].auc, falsePerHour: run0.variants[v.id].falsePerHour, detected: run0.variants[v.id].detected }])),
    },
    report,
  };
}
