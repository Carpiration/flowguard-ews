// Сквозная проверка на файлах из samples/, созданных независимым
// генератором scripts/make_samples.py.

import { analyzeTrace } from '../assets/js/core/analyze.js';
import { ingestBlob } from '../assets/js/core/ingest.js';
import { assert, equal, loadSample, setFile, test } from './harness.js';

setFile('samples');

async function analyze(name) {
  const blob = await loadSample(name);
  const { trace, format } = await ingestBlob(blob);
  return { format, trace, report: analyzeTrace(trace) };
}

function expectTypes(report, list) {
  const found = new Set(report.incidents.map((i) => i.type));
  for (const t of list) assert(found.has(t), `не обнаружено «${t}»; найдено: ${[...found].join(', ') || 'ничего'}`);
}

test('office-attacks.pcap: сканирование, подбор пароля, утечка', async () => {
  const { format, report } = await analyze('office-attacks.pcap');
  equal(format, 'pcap');
  expectTypes(report, ['portscan', 'bruteforce', 'exfil']);
  assert(report.risk.peak >= 75, `пиковый риск ${report.risk.peak}`);
});

test('covert-channels.pcapng: C2-маяк и DNS-туннель (наносекундные метки)', async () => {
  const { format, trace, report } = await analyze('covert-channels.pcapng');
  equal(format, 'pcapng');
  assert(trace.t[0] > 1.7e9 && trace.t[0] < 1.9e9, `время первого пакета ${trace.t[0]}`);
  expectTypes(report, ['beacon', 'dnstunnel']);
});

test('tcpdump-scan.txt: сканирование по текстовому выводу', async () => {
  const { format, report } = await analyze('tcpdump-scan.txt');
  equal(format, 'tcpdump');
  expectTypes(report, ['portscan']);
});

test('zeek-conn-labeled.csv: потоки с разметкой и оценкой качества', async () => {
  const { format, trace, report } = await analyze('zeek-conn-labeled.csv');
  equal(format, 'csv');
  assert(trace.flowMode && trace.labelled, 'потоки с разметкой');
  expectTypes(report, ['portscan', 'bruteforce']);
  assert(report.evaluation && report.evaluation.auc > 0.8, `AUC ${report.evaluation?.auc}`);
});

test('suricata-eve.ndjson: утечка по записям потоков', async () => {
  const { format, report } = await analyze('suricata-eve.ndjson');
  equal(format, 'json');
  expectTypes(report, ['exfil']);
});
