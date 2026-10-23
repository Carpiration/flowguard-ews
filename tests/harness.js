// Минимальный тестовый каркас без зависимостей: работает и в браузере
// (tests/index.html), и в Node (tests/run-node.mjs, используется в CI).

const registry = [];
let currentFile = '';

export function setFile(name) {
  currentFile = name;
}

export function test(name, fn) {
  registry.push({ file: currentFile, name, fn });
}

export function assert(cond, msg = 'условие не выполнено') {
  if (!cond) throw new Error(msg);
}

export function equal(actual, expected, msg = '') {
  if (actual !== expected) throw new Error(`${msg ? `${msg}: ` : ''}ожидалось ${JSON.stringify(expected)}, получено ${JSON.stringify(actual)}`);
}

export function near(actual, expected, eps, msg = '') {
  if (Math.abs(actual - expected) > eps) throw new Error(`${msg ? `${msg}: ` : ''}ожидалось ${expected}±${eps}, получено ${actual}`);
}

export async function rejects(fn, pattern, msg = '') {
  try {
    await fn();
  } catch (err) {
    if (pattern && !pattern.test(err.message)) throw new Error(`${msg}: неожиданная ошибка «${err.message}»`);
    return;
  }
  throw new Error(`${msg || 'ожидалась ошибка'}`);
}

export async function loadSample(name) {
  if (typeof window === 'undefined') {
    const fs = await import('node:fs/promises');
    const url = new URL(`../samples/${name}`, import.meta.url);
    return new Blob([await fs.readFile(url)]);
  }
  const res = await fetch(new URL(`../samples/${name}`, import.meta.url));
  if (!res.ok) throw new Error(`Не удалось загрузить samples/${name}`);
  return res.blob();
}

export async function runAll(onResult = () => {}) {
  const results = [];
  for (const t of registry) {
    const started = performance.now();
    try {
      await t.fn();
      const r = { ...t, ok: true, ms: performance.now() - started };
      results.push(r);
      onResult(r);
    } catch (err) {
      const r = { ...t, ok: false, error: err, ms: performance.now() - started };
      results.push(r);
      onResult(r);
    }
  }
  return results;
}
