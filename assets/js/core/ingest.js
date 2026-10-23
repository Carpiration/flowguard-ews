// Определение формата по содержимому (сигнатурам), а не по расширению,
// и загрузка источника в колоночную трассу.

import { FormatError } from './errors.js';
import { BlobReader, parsePcap, parsePcapng } from './parse-pcap.js';
import { TCPDUMP_RE, detectDelimiter, parseCsv, parseJson, parseTcpdump, splitCsvLine } from './parse-text.js';
import { TraceBuilder } from './trace.js';

export const FORMAT_NAMES = {
  pcap: 'PCAP',
  pcapng: 'PCAPNG',
  csv: 'CSV',
  json: 'JSON / NDJSON',
  tcpdump: 'Текст tcpdump',
};

export const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024;

export function detectFormat(head) {
  if (head.length >= 4) {
    const m = ((head[0] << 24) | (head[1] << 16) | (head[2] << 8) | head[3]) >>> 0;
    if (m === 0xa1b2c3d4 || m === 0xd4c3b2a1 || m === 0xa1b23c4d || m === 0x4d3cb2a1) return 'pcap';
    if (m === 0x0a0d0d0a) return 'pcapng';
    if (head[0] === 0x1f && head[1] === 0x8b) {
      throw new FormatError('Файл сжат gzip. Распакуйте его и загрузите исходный PCAP, CSV или JSON.');
    }
    if (m === 0x504b0304) throw new FormatError('Это ZIP-архив. Распакуйте его и загрузите файл с данными.');
  }
  let zeros = 0;
  const sample = Math.min(head.length, 4096);
  for (let i = 0; i < sample; i++) if (head[i] === 0) zeros++;
  if (zeros > sample * 0.01) throw new FormatError('Двоичный файл неизвестного формата. Поддерживаются PCAP, PCAPNG, CSV, JSON и вывод tcpdump.');
  const text = new TextDecoder('utf-8').decode(head).replace(/^﻿/, '');
  const trimmed = text.trimStart();
  if (trimmed[0] === '{' || trimmed[0] === '[') return 'json';
  const lines = trimmed.split(/\r?\n/).filter((l) => l.trim());
  if (!lines.length) throw new FormatError('Файл пуст.');
  if (lines.slice(0, 5).some((l) => TCPDUMP_RE.test(l))) return 'tcpdump';
  const d = detectDelimiter(lines[0]);
  if (splitCsvLine(lines[0], d).length >= 3) return 'csv';
  throw new FormatError('Не удалось распознать формат. Поддерживаются PCAP, PCAPNG, CSV, JSON/NDJSON и вывод tcpdump -n.');
}

export async function ingestBlob(blob, { internal } = {}, onProgress) {
  if (!blob.size) throw new FormatError('Файл пуст.');
  if (blob.size > MAX_FILE_SIZE) throw new FormatError('Файл больше 2 ГБ. Разделите захват на части (например, editcap -c).');
  const head = new Uint8Array(await blob.slice(0, 65536).arrayBuffer());
  const format = detectFormat(head);
  const builder = new TraceBuilder({ internal });
  switch (format) {
    case 'pcap':
      await parsePcap(new BlobReader(blob), builder, onProgress);
      break;
    case 'pcapng':
      await parsePcapng(new BlobReader(blob), builder, onProgress);
      break;
    case 'csv':
      await parseCsv(blob, builder, onProgress);
      break;
    case 'json':
      await parseJson(blob, builder, onProgress);
      break;
    case 'tcpdump':
      await parseTcpdump(blob, builder, onProgress);
      break;
    default:
      throw new FormatError('Неизвестный формат.');
  }
  if (builder.length === 0) {
    throw new FormatError(
      builder.skipped
        ? `Не найдено ни одной сетевой записи с IP-адресами (пропущено ${builder.skipped}).`
        : 'В файле нет сетевых записей.',
    );
  }
  if (builder.skipped) builder.notes.push(`Пропущено нераспознанных записей: ${builder.skipped}.`);
  return { trace: builder.finish(), format };
}
