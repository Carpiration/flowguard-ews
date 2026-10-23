// Фоновый поток анализа: интерфейс остаётся отзывчивым даже на больших файлах.

import { analyzeTrace } from '../core/analyze.js';
import { FormatError } from '../core/errors.js';
import { FORMAT_NAMES, ingestBlob } from '../core/ingest.js';
import { runLab } from '../core/lab.js';
import { writePcap } from '../core/pcap-writer.js';
import { generateDataset } from '../core/simulate.js';

function post(id, kind, data) {
  self.postMessage({ id, kind, ...data });
}

self.onmessage = async (e) => {
  const { id, type, payload } = e.data;
  const progress = (stage, value) => post(id, 'progress', { stage, value });
  try {
    if (type === 'analyzeFile') {
      const { file, options } = payload;
      progress('read', 0);
      const { trace, format } = await ingestBlob(file, options, (v) => progress('read', v));
      progress('features', 0);
      const report = analyzeTrace(trace, { ...options, onProgress: progress });
      report.source = { name: file.name, size: file.size, format: FORMAT_NAMES[format], kind: payload.kind || 'file' };
      post(id, 'result', { data: report });
    } else if (type === 'analyzeSample') {
      const { sample, options } = payload;
      progress('read', 0.1);
      const { trace } = generateDataset(sample);
      progress('features', 0);
      const report = analyzeTrace(trace, { ...options, onProgress: progress });
      report.source = { name: sample.name, size: 0, format: 'Синтетический набор', kind: 'sample' };
      post(id, 'result', { data: report });
    } else if (type === 'lab') {
      const result = runLab(payload.options, progress);
      post(id, 'result', { data: result });
    } else if (type === 'samplePcap') {
      const { trace } = generateDataset(payload.sample);
      post(id, 'result', { data: writePcap(trace) });
    } else {
      throw new Error(`Неизвестная задача: ${type}`);
    }
  } catch (err) {
    const message = err instanceof FormatError ? err.message : `Внутренняя ошибка анализа: ${err?.message || err}`;
    post(id, 'error', { message, format: err instanceof FormatError });
  }
};
