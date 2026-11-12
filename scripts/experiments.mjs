// Воспроизводимые эксперименты для пояснительной записки.
//   node scripts/experiments.mjs [--real <каталог с размеченными CSV>] [--out docs/experiments/results.json]
// 1) основной эксперимент: 5 прогонов, все варианты + абляция «без одного детектора»;
// 2) чувствительность к порогу тревоги и размеру окна;
// 3) производительность разбора и анализа на записях разной длительности;
// 4) (по желанию) проверка на внешних размеченных наборах по вариантам модели.

import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { analyzeTrace, fitForest, postAttackMask, prepare, scoreWindows, staticScores } from '../assets/js/core/analyze.js';
import { confusion, metrics, roc } from '../assets/js/core/evaluate.js';
import { ingestBlob } from '../assets/js/core/ingest.js';
import { LOO_VARIANTS, VARIANTS, runLab } from '../assets/js/core/lab.js';
import { writePcap } from '../assets/js/core/pcap-writer.js';
import { generateDataset } from '../assets/js/core/simulate.js';

const args = process.argv.slice(2);
const opt = (name, def = null) => (args.includes(name) ? args[args.indexOf(name) + 1] : def);
const outPath = opt('--out', 'docs/experiments/results.json');
const realDir = opt('--real');
const r3 = (x) => (x === null || x === undefined || !Number.isFinite(x) ? null : Math.round(x * 1000) / 1000);
const result = { generated: new Date().toISOString(), node: process.version };

// 1. Основной эксперимент
{
  const lab = runLab({ seed: 42, duration: 1200, runs: 5, loo: true });
  result.main = {
    params: { seed: 42, durationSec: 1200, runs: 5, threshold: 50, windowSec: lab.params.windowSize, bufferSec: lab.params.buffer },
    variants: lab.variants.map((v) => {
      const s = lab.summary[v.id];
      return {
        id: v.id, name: v.name,
        precision: r3(s.precision.mean), recall: r3(s.recall.mean), f1: r3(s.f1.mean), f1sd: r3(s.f1.sd),
        fpr: r3(s.fpr.mean), auc: r3(s.auc.mean), delaySec: r3(s.delay.mean), detectionRate: r3(s.detectionRate.mean), falsePerHour: r3(s.falsePerHour.mean),
      };
    }),
    early: { meanLeadSec: r3(lab.early.mean), sdLeadSec: r3(lab.early.sd), shareEarlier: r3(lab.early.share), scenarios: lab.early.n },
    scenarios: lab.scenarios.map((s) => ({ type: s.type, name: s.name, durationSec: Math.round(s.t1 - s.t0), warnSec: s.warnDelay, fullSec: s.delays.full, staticSec: s.delays.static, signatureSec: s.typed.detected ? Math.round(s.typed.delay) : null })),
  };
  console.log('main done');
}

// 2. Чувствительность
{
  const thr = [];
  for (const threshold of [30, 40, 50, 60, 70]) {
    const s = runLab({ seed: 42, duration: 1200, runs: 5, threshold }).summary.full;
    thr.push({ threshold, precision: r3(s.precision.mean), recall: r3(s.recall.mean), f1: r3(s.f1.mean), delaySec: r3(s.delay.mean), detectionRate: r3(s.detectionRate.mean), falsePerHour: r3(s.falsePerHour.mean) });
  }
  const win = [];
  for (const windowSize of [2, 5, 10, 15, 30]) {
    const lab = runLab({ seed: 42, duration: 1200, runs: 5, windowSize });
    const s = lab.summary.full;
    const b = lab.summary.static;
    win.push({ windowSec: windowSize, f1: r3(s.f1.mean), auc: r3(s.auc.mean), delaySec: r3(s.delay.mean), detectionRate: r3(s.detectionRate.mean), falsePerHour: r3(s.falsePerHour.mean), staticF1: r3(b.f1.mean), staticDelaySec: r3(b.delay.mean) });
  }
  const sens = [];
  for (const sensitivity of [0.7, 1, 1.4]) {
    const s = runLab({ seed: 42, duration: 1200, runs: 5, sensitivity }).summary.full;
    sens.push({ sensitivity, precision: r3(s.precision.mean), recall: r3(s.recall.mean), f1: r3(s.f1.mean), delaySec: r3(s.delay.mean), falsePerHour: r3(s.falsePerHour.mean) });
  }
  result.sensitivity = { threshold: thr, window: win, sensitivity: sens };
  console.log('sensitivity done');
}

// 3. Производительность (PCAP → разбор → модель)
{
  const perf = [];
  for (const minutes of [10, 20, 60, 120]) {
    const { trace } = generateDataset({ seed: 42, duration: minutes * 60 });
    const blob = writePcap(trace);
    const size = blob.size ?? blob.byteLength;
    const b = blob instanceof Blob ? blob : new Blob([blob]);
    const t0 = performance.now();
    const ing = await ingestBlob(b);
    const t1 = performance.now();
    analyzeTrace(ing.trace);
    const t2 = performance.now();
    const total = (t2 - t0) / 1000;
    perf.push({ minutes, packets: ing.trace.length, sizeMb: r3(size / 1048576), parseSec: r3((t1 - t0) / 1000), modelSec: r3((t2 - t1) / 1000), packetsPerSec: Math.round(ing.trace.length / total) });
  }
  result.performance = perf;
  console.log('performance done');
}

// 4. Внешние размеченные наборы
if (realDir) {
  const NONE = { baseline: false, cusum: false, iforest: false, patterns: false };
  const files = (await readdir(realDir)).filter((f) => /\.(csv|json|ndjson|log|pcap|pcapng)$/i.test(f)).sort();
  result.real = [];
  for (const f of files) {
    const { trace } = await ingestBlob(new Blob([await readFile(join(realDir, f))]));
    const prep = prepare(trace, {});
    const forest = fitForest(prep, 7);
    const labels = prep.windows.map((w) => (w.attack > 0 ? 1 : 0));
    const mask = postAttackMask(prep.windows, labels, 30);
    const row = { file: f, records: trace.length, durationH: r3(prep.duration / 3600), windowSec: prep.w, windows: prep.windows.length, attackWindows: labels.filter(Boolean).length, variants: [] };
    for (const v of [...VARIANTS, ...LOO_VARIANTS]) {
      const scores = v.components ? scoreWindows(prep, { components: { ...NONE, ...v.components }, forest }).map((x) => x.risk) : staticScores(prep);
      const m = metrics(confusion(scores, labels, 50, mask));
      row.variants.push({ id: v.id, name: v.name, precision: r3(m.precision), recall: r3(m.recall), f1: r3(m.f1), fpr: r3(m.fpr), auc: r3(roc(scores, labels, mask).auc), tp: m.tp, fp: m.fp, fn: m.fn, tn: m.tn });
    }
    const types = {};
    for (const i of prep.patterns.incidents) types[i.type] = (types[i.type] || 0) + 1;
    row.incidents = types;
    result.real.push(row);
  }
  console.log('real done');
}

await writeFile(outPath, `${JSON.stringify(result, null, 2)}\n`);
console.log(`Результаты записаны в ${outPath}`);
