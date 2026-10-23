import { analyzeTrace, chooseWindowSize } from '../assets/js/core/analyze.js';
import { confusion, metrics, roc } from '../assets/js/core/evaluate.js';
import { IsolationForest } from '../assets/js/core/iforest.js';
import { detectFormat, ingestBlob } from '../assets/js/core/ingest.js';
import { baseDomain, entropy, expandIPv6, formatIPv6, makeInternalMatcher, parseIPv4 } from '../assets/js/core/net.js';
import { parseFlags, parseTime } from '../assets/js/core/parse-text.js';
import { writePcap } from '../assets/js/core/pcap-writer.js';
import { Rng } from '../assets/js/core/prng.js';
import { ScoreEngine } from '../assets/js/core/score.js';
import { generateDataset } from '../assets/js/core/simulate.js';
import { PROTO, TCPF, TraceBuilder } from '../assets/js/core/trace.js';
import { assert, equal, near, rejects, setFile, test } from './harness.js';

setFile('core');

const types = (report) => new Set(report.incidents.map((i) => i.type));

// Фоновый «шум»: 8 рабочих станций обращаются к внешним HTTPS-серверам.
function background(b, rng, t0, t1, rate = 6) {
  for (let t = t0; t < t1; t += rng.exp(rate)) {
    const c = `10.0.1.${rng.int(10, 17)}`;
    const s = `203.0.113.${rng.int(1, 30)}`;
    const cp = rng.int(49152, 65000);
    b.push(t, c, s, cp, 443, PROTO.TCP, 66, TCPF.SYN);
    b.push(t + 0.02, s, c, 443, cp, PROTO.TCP, 66, TCPF.SYN | TCPF.ACK);
    for (let k = 0; k < rng.int(2, 8); k++) b.push(t + 0.03 + k * 0.01, s, c, 443, cp, PROTO.TCP, 1514, TCPF.ACK);
    b.push(t + 0.2, c, s, cp, 443, PROTO.TCP, 54, TCPF.FIN | TCPF.ACK);
  }
}

test('IPv4/IPv6 и внутренние подсети', () => {
  equal(parseIPv4('10.1.2.3'), 167838211);
  equal(parseIPv4('256.1.1.1'), null);
  equal(expandIPv6('2001:db8::1'), '20010db8000000000000000000000001');
  const b = new Uint8Array(16);
  b[0] = 0x20;
  b[1] = 0x01;
  b[2] = 0x0d;
  b[3] = 0xb8;
  b[15] = 1;
  equal(formatIPv6(b, 0), '2001:db8::1');
  const isInt = makeInternalMatcher(['10.0.0.0/8', '192.168.0.0/16', 'fd00::/8']);
  assert(isInt('10.20.30.40'));
  assert(isInt('192.168.1.1'));
  assert(!isInt('8.8.8.8'));
  assert(isInt('224.0.0.251'), 'multicast — локальный');
  assert(isInt('fd12::1'));
  assert(!isInt('2001:db8::1'));
});

test('базовый домен и энтропия', () => {
  const { base, sub } = baseDomain('a1b2.c3.tunnel.example');
  equal(base, 'tunnel.example');
  equal(sub, 'a1b2.c3');
  near(entropy('aaaa'), 0, 1e-9);
  near(entropy('abcd'), 2, 1e-9);
});

test('разбор времени и флагов TCP', () => {
  equal(parseTime('1700000000.5'), 1700000000.5);
  equal(parseTime('1700000000500'), 1700000000.5);
  equal(parseTime('2024-01-02T03:04:05.250Z'), Date.UTC(2024, 0, 2, 3, 4, 5) / 1000 + 0.25);
  equal(parseTime('2024-01-02 03:04:05+0300'), Date.UTC(2024, 0, 2, 0, 4, 5) / 1000);
  equal(parseTime('7/7/2017 8:59'), Date.UTC(2017, 6, 7, 8, 59) / 1000);
  equal(parseFlags('SA'), TCPF.SYN | TCPF.ACK);
  equal(parseFlags('[SYN, ACK]'), TCPF.SYN | TCPF.ACK);
  equal(parseFlags('0x012'), TCPF.SYN | TCPF.ACK);
  equal(parseFlags('S.'), TCPF.SYN | TCPF.ACK);
});

test('PCAP: запись и обратный разбор сохраняют поля', async () => {
  const b = new TraceBuilder();
  b.push(1000.25, '10.0.0.1', '203.0.113.5', 50000, 443, PROTO.TCP, 1514, TCPF.SYN);
  b.push(1000.5, '10.0.0.1', '10.0.0.53', 50001, 53, PROTO.UDP, 90, 0, 1, 'www.example.com');
  b.push(1001, '10.0.0.1', '10.0.0.2', 0, 0, PROTO.ICMP, 74, 8);
  const blob = writePcap(b.finish());
  const { trace, format } = await ingestBlob(blob);
  equal(format, 'pcap');
  equal(trace.length, 3);
  near(trace.t[0], 1000.25, 1e-6);
  equal(trace.hosts.name(trace.dst[0]), '203.0.113.5');
  equal(trace.dp[0], 443);
  equal(trace.flags[0], TCPF.SYN);
  equal(trace.len[0], 1514);
  equal(trace.strings[trace.q[1]], 'www.example.com');
  equal(trace.proto[2], PROTO.ICMP);
  equal(trace.flags[2], 8);
});

test('CSV в стиле Wireshark: порты, флаги и DNS из Info', async () => {
  const csv = [
    '"No.","Time","Source","Destination","Protocol","Length","Info"',
    '"1","0.000","10.0.0.5","10.0.0.9","TCP","66","51000 → 22 [SYN] Seq=0 Win=64240"',
    '"2","0.001","10.0.0.9","10.0.0.5","TCP","66","22 → 51000 [SYN, ACK] Seq=0 Ack=1"',
    '"3","0.010","10.0.0.5","10.0.0.53","DNS","80","Standard query 0x1a2b A files.example.org"',
  ].join('\n');
  const { trace, format } = await ingestBlob(new Blob([csv]));
  equal(format, 'csv');
  equal(trace.length, 3);
  equal(trace.dp[0], 22);
  equal(trace.flags[1], TCPF.SYN | TCPF.ACK);
  equal(trace.strings[trace.q[2]], 'files.example.org');
  equal(trace.proto[2], PROTO.UDP);
});

test('CSV потоков CICIDS: зеркальные записи и метки', async () => {
  const csv = [
    ' Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Total Fwd Packets, Total Backward Packets,Total Length of Fwd Packets, Total Length of Bwd Packets, Label',
    '192.168.10.5,50000,192.168.10.50,22,6,7/7/2017 9:00,10,8,1200,3400,SSH-Patator',
    '192.168.10.5,50001,192.168.10.50,80,6,7/7/2017 9:00,3,0,180,0,BENIGN',
  ].join('\n');
  const { trace } = await ingestBlob(new Blob([csv]));
  assert(trace.flowMode, 'режим потоков');
  assert(trace.labelled, 'есть разметка');
  equal(trace.length, 3, 'поток с ответом даёт две записи');
  equal(trace.n[0], 10);
  equal(trace.len[1], 3400);
  equal(trace.labels[trace.label[0]], 'SSH-Patator');
  equal(trace.label[2], -1, 'BENIGN — нормальная запись');
});

test('NDJSON Suricata EVE и Zeek conn.log', async () => {
  const lines = [
    JSON.stringify({ timestamp: '2024-03-01T10:00:00.000000+0000', event_type: 'flow', src_ip: '10.0.0.7', src_port: 51515, dest_ip: '198.51.100.9', dest_port: 443, proto: 'TCP', flow: { pkts_toserver: 12, pkts_toclient: 10, bytes_toserver: 3000, bytes_toclient: 9000 } }),
    JSON.stringify({ ts: 1709287201.5, 'id.orig_h': '10.0.0.8', 'id.orig_p': 50000, 'id.resp_h': '10.0.0.9', 'id.resp_p': 445, proto: 'tcp', conn_state: 'S0', orig_pkts: 1, orig_bytes: 0, resp_pkts: 0, resp_bytes: 0 }),
  ].join('\n');
  const { trace, format } = await ingestBlob(new Blob([lines]));
  equal(format, 'json');
  equal(trace.length, 3);
  equal(trace.hosts.name(trace.dst[0]), '198.51.100.9');
  equal(trace.flags[2] & 0xff, TCPF.SYN, 'S0 — попытка без ответа');
});

test('вывод tcpdump -n', async () => {
  const txt = [
    '12:00:01.000001 IP 10.0.0.5.51000 > 10.0.0.9.22: Flags [S], seq 1, win 64240, length 0',
    '12:00:01.000300 IP 10.0.0.9.22 > 10.0.0.5.51000: Flags [S.], seq 2, ack 2, win 65160, length 0',
    '12:00:01.100000 IP 10.0.0.5.53000 > 10.0.0.53.53: 4242+ A? www.example.com. (33)',
    '12:00:02.000000 IP 10.0.0.5 > 10.0.0.1: ICMP echo request, id 1, seq 1, length 64',
  ].join('\n');
  const { trace, format } = await ingestBlob(new Blob([txt]));
  equal(format, 'tcpdump');
  equal(trace.length, 4);
  equal(trace.flags[1], TCPF.SYN | TCPF.ACK);
  equal(trace.strings[trace.q[2]], 'www.example.com');
  equal(trace.flags[3], 8);
});

test('формат определяется по содержимому; сжатые файлы отклоняются', async () => {
  equal(detectFormat(new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1])), 'pcap');
  equal(detectFormat(new Uint8Array([0x0a, 0x0d, 0x0d, 0x0a])), 'pcapng');
  await rejects(() => ingestBlob(new Blob([new Uint8Array([0x1f, 0x8b, 8, 0, 0, 0])])), /gzip/, 'gzip');
  await rejects(() => ingestBlob(new Blob(['просто текст без структуры'])), /формат/, 'неизвестный текст');
});

test('Isolation Forest: выброс получает более высокую оценку', () => {
  const rng = new Rng(3);
  const X = Array.from({ length: 300 }, () => Float64Array.from([rng.normal(0, 1), rng.normal(0, 1), rng.normal(5, 0.5)]));
  const f = new IsolationForest({ trees: 100, seed: 1 }).fit(X);
  const inlier = f.score(Float64Array.from([0, 0, 5]));
  const outlier = f.score(Float64Array.from([6, -6, 9]));
  assert(outlier > 0.6, `оценка выброса ${outlier}`);
  assert(inlier < 0.5, `оценка нормы ${inlier}`);
});

test('CUSUM накапливает малый устойчивый сдвиг раньше, чем z-оценка превышает порог', () => {
  const eng = new ScoreEngine({ windowSize: 5 });
  const f = (pk) => {
    const x = new Float64Array(13);
    x[0] = pk;
    x[1] = pk * 600;
    return x;
  };
  const rng = new Rng(9);
  for (let i = 0; i < 60; i++) eng.process(f(Math.max(1, Math.round(rng.normal(300, 15)))), null, []);
  let firstWarn = -1;
  let firstBaseAlarm = -1;
  for (let i = 0; i < 40; i++) {
    const r = eng.process(f(Math.round(300 * (1 + 0.012 * i))), null, []);
    if (firstWarn < 0 && r.sCusum >= 0.5) firstWarn = i;
    if (firstBaseAlarm < 0 && r.sBase >= 0.5) firstBaseAlarm = i;
  }
  assert(firstWarn >= 0, 'CUSUM должен сработать на нарастающем сдвиге');
  assert(firstBaseAlarm < 0 || firstWarn < firstBaseAlarm, `CUSUM ${firstWarn} раньше z ${firstBaseAlarm}`);
});

test('метрики и ROC-AUC', () => {
  const m = metrics(confusion([90, 80, 10, 60, 5], [1, 1, 0, 0, 0], 50));
  equal(m.tp, 2);
  equal(m.fp, 1);
  near(m.precision, 2 / 3, 1e-9);
  near(m.recall, 1, 1e-9);
  const r = roc([0.9, 0.8, 0.7, 0.1], [1, 1, 0, 0]);
  near(r.auc, 1, 1e-9);
  const r2 = roc([0.1, 0.2, 0.8, 0.9], [1, 1, 0, 0]);
  near(r2.auc, 0, 1e-9);
});

test('выбор размера окна', () => {
  equal(chooseWindowSize(1200), 5);
  equal(chooseWindowSize(60), 1);
  equal(chooseWindowSize(86400), 300);
  equal(chooseWindowSize(1200, 1), 1);
});

test('фоновый трафик без атак не даёт инцидентов высокой важности', () => {
  const b = new TraceBuilder();
  background(b, new Rng(5), 0, 900);
  const report = analyzeTrace(b.finish());
  const serious = report.incidents.filter((i) => i.sev >= 3);
  equal(serious.length, 0, `инциденты: ${[...types(report)].join(', ')}`);
  assert(report.risk.peak < 50, `пиковый риск ${report.risk.peak}`);
});

test('сигнатуры: сканирование, подбор пароля, DNS-туннель, маяк, утечка', () => {
  const rng = new Rng(11);
  const b = new TraceBuilder();
  background(b, rng, 0, 900);
  for (let i = 0; i < 200; i++) b.push(200 + i * 0.4, '10.0.1.66', '10.0.0.10', 40000 + i, 1 + i, PROTO.TCP, 58, TCPF.SYN);
  for (let i = 0; i < 60; i++) {
    const t = 400 + i * 0.8;
    b.push(t, '203.0.113.77', '10.0.0.5', 41000 + i, 22, PROTO.TCP, 66, TCPF.SYN);
    b.push(t + 0.04, '10.0.0.5', '203.0.113.77', 22, 41000 + i, PROTO.TCP, 66, TCPF.SYN | TCPF.ACK);
  }
  for (let i = 0; i < 150; i++) {
    let s = '';
    for (let k = 0; k < 36; k++) s += 'abcdefghijklmnopqrstuvwxyz234567'[rng.int(0, 31)];
    b.push(500 + i * 0.2, '10.0.1.31', '10.0.0.53', 50000 + i, 53, PROTO.UDP, 120, 0, 1, `${s}.${i}.t.tunnel.example`);
  }
  for (let i = 0; i < 12; i++) b.push(300 + i * 30 + rng.range(-0.2, 0.2), '10.0.1.17', '203.0.113.45', 52000 + i, 8443, PROTO.TCP, 66, TCPF.SYN);
  for (let i = 0; i < 4000; i++) b.push(700 + i * 0.015, '10.0.1.23', '198.51.100.200', 53000, 443, PROTO.TCP, 1514, TCPF.ACK);
  const report = analyzeTrace(b.finish());
  const found = types(report);
  for (const t of ['portscan', 'bruteforce', 'dnstunnel', 'beacon', 'exfil']) assert(found.has(t), `не обнаружено: ${t}; найдено: ${[...found].join(', ')}`);
  assert(report.risk.peak >= 75, `пиковый риск ${report.risk.peak}`);
  const scan = report.incidents.find((i) => i.type === 'portscan');
  equal(scan.src, '10.0.1.66');
  assert(scan.tDetect - 200 <= 60, `задержка обнаружения сканирования ${scan.tDetect - 200} с`);
});

test('сквозной сценарий: синтетический набор с разметкой', () => {
  const { trace, truth } = generateDataset({ seed: 7, duration: 600, schedule: [{ type: 'portscan', t0: 200 }, { type: 'exfil', t0: 400 }] });
  equal(truth.length, 2);
  const report = analyzeTrace(trace);
  const found = types(report);
  assert(found.has('portscan') && found.has('exfil'), `найдено: ${[...found].join(', ')}`);
  assert(report.evaluation, 'есть оценка по разметке');
  assert(report.evaluation.auc > 0.85, `AUC ${report.evaluation.auc}`);
  assert(report.evaluation.recall > 0.6, `полнота ${report.evaluation.recall}`);
});
