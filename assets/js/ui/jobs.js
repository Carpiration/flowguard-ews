// Клиент фонового потока анализа. Каждая задача — отдельный Worker:
// отмена мгновенно завершает поток и освобождает память.

export class Job {
  constructor() {
    this.worker = null;
    this.cancelled = false;
  }

  run(type, payload, onProgress = () => {}) {
    this.worker = new Worker(new URL('../workers/analysis.worker.js', import.meta.url), { type: 'module' });
    const id = 1;
    return new Promise((resolve, reject) => {
      this.reject = reject;
      this.worker.onmessage = (e) => {
        const msg = e.data;
        if (msg.id !== id) return;
        if (msg.kind === 'progress') onProgress(msg.stage, msg.value);
        else if (msg.kind === 'result') {
          resolve(msg.data);
          this.dispose();
        } else if (msg.kind === 'error') {
          const err = new Error(msg.message);
          err.userFacing = true;
          reject(err);
          this.dispose();
        }
      };
      this.worker.onerror = (e) => {
        e.preventDefault?.();
        const err = new Error('Фоновый поток анализа аварийно завершился. Возможно, не хватило памяти для этого файла.');
        err.userFacing = true;
        reject(err);
        this.dispose();
      };
      this.worker.postMessage({ id, type, payload });
    });
  }

  cancel() {
    if (!this.worker) return;
    this.cancelled = true;
    const err = new Error('Анализ отменён.');
    err.cancelled = true;
    this.reject?.(err);
    this.dispose();
  }

  dispose() {
    this.worker?.terminate();
    this.worker = null;
  }
}

export function runJob(type, payload, onProgress) {
  const job = new Job();
  const promise = job.run(type, payload, onProgress);
  return { job, promise };
}
