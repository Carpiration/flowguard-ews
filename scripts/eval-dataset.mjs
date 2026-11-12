// Проверка модели на внешнем размеченном файле (CSV/JSON/PCAP) из командной строки.
// Пример: node scripts/eval-dataset.mjs path/to/conn.log.labeled.csv [--window 60] [--json]
// Печатает метрики по окнам для ансамбля и для статического порога μ+3σ,
// найденные инциденты и задержку обнаружения по меткам набора.

import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { analyzeTrace } from '../assets/js/core/analyze.js';
import { ingestBlob } from '../assets/js/core/ingest.js';

const args = process.argv.slice(2);
const json = args.includes('--json');
const wi = args.indexOf('--window');
const windowSize = wi >= 0 ? Number(args[wi + 1]) : 'auto';
const files = args.filter((a, i) => !a.startsWith('--') && (wi < 0 || i !== wi + 1));
if (!files.length) {
  console.error('Укажите путь к файлу. Пример: node scripts/eval-dataset.mjs data.csv');
  process.exit(2);
}

const f3 = (x) => (x === null || x === undefined ? '—' : x.toFixed(3));
const out = [];
for (const path of files) {
  const buf = await readFile(path);
  const t0 = performance.now();
  const { trace, format } = await ingestBlob(new Blob([buf]));
  const t1 = performance.now();
  const report = analyzeTrace(trace, { windowSize });
  const t2 = performance.now();
  const ev = report.evaluation;
  const types = {};
  for (const inc of report.incidents) types[inc.type] = (types[inc.type] || 0) + 1;
  const row = {
    file: basename(path),
    format,
    records: trace.length,
    durationH: report.summary?.duration ? report.summary.duration / 3600 : null,
    window: report.params?.windowSize ?? report.windowSize ?? null,
    windows: report.series?.t?.length ?? null,
    peak: report.risk.peak,
    incidents: report.incidents.length,
    types,
    parseMs: Math.round(t1 - t0),
    modelMs: Math.round(t2 - t1),
    evaluation: ev
      ? {
          positives: ev.positives, negatives: ev.negatives, tp: ev.tp, fp: ev.fp, fn: ev.fn, tn: ev.tn,
          precision: ev.precision, recall: ev.recall, f1: ev.f1, fpr: ev.fpr, auc: ev.auc,
          staticAuc: ev.staticAuc, staticF1: ev.staticMetrics?.f1 ?? null, staticRecall: ev.staticMetrics?.recall ?? null,
          staticPrecision: ev.staticMetrics?.precision ?? null, perLabel: ev.perLabel,
        }
      : null,
  };
  out.push(row);
  if (json) continue;
  console.log(`\n== ${row.file} (${format}) — записей ${row.records}, пик риска ${row.peak}, инцидентов ${row.incidents}`);
  console.log(`   типы: ${Object.entries(types).map(([k, v]) => `${k}×${v}`).join(', ') || 'нет'}; разбор ${row.parseMs} мс, модель ${row.modelMs} мс`);
  if (ev) {
    console.log(`   окна: атака ${ev.positives}, норма ${ev.negatives}; TP ${ev.tp} FP ${ev.fp} FN ${ev.fn} TN ${ev.tn}`);
    console.log(`   ансамбль: P ${f3(ev.precision)} R ${f3(ev.recall)} F1 ${f3(ev.f1)} FPR ${f3(ev.fpr)} AUC ${f3(ev.auc)}`);
    console.log(`   μ+3σ:     P ${f3(ev.staticMetrics?.precision)} R ${f3(ev.staticMetrics?.recall)} F1 ${f3(ev.staticMetrics?.f1)} AUC ${f3(ev.staticAuc)}`);
    for (const l of ev.perLabel) console.log(`   метка «${l.name}»: ${l.detected ? `обнаружена, задержка ${Math.round(l.delay)} с` : 'не обнаружена'}`);
  } else console.log('   разметки нет: метрики не считаются');
}
if (json) console.log(JSON.stringify(out, null, 2));
