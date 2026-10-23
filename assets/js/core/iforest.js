// Isolation Forest (Liu, Ting, Zhou, 2008): аномальные точки изолируются
// случайными разбиениями быстрее нормальных, поэтому средняя длина пути до листа меньше.

import { Rng } from './prng.js';

const EULER = 0.5772156649015329;

export function cFactor(n) {
  if (n > 2) return 2 * (Math.log(n - 1) + EULER) - (2 * (n - 1)) / n;
  if (n === 2) return 1;
  return 0;
}

export class IsolationForest {
  constructor({ trees = 100, sampleSize = 256, seed = 1 } = {}) {
    this.treeCount = trees;
    this.sampleSize = sampleSize;
    this.rng = new Rng(seed);
    this.trees = [];
    this.psi = 0;
  }

  fit(X) {
    const n = X.length;
    if (!n) throw new Error('IsolationForest: пустая обучающая выборка');
    this.dim = X[0].length;
    this.psi = Math.min(this.sampleSize, n);
    const limit = Math.ceil(Math.log2(Math.max(2, this.psi)));
    this.trees = [];
    const idx = Array.from({ length: n }, (_, i) => i);
    for (let t = 0; t < this.treeCount; t++) {
      // Подвыборка без возвращения (частичное перемешивание Фишера — Йетса).
      for (let i = 0; i < this.psi; i++) {
        const j = i + Math.floor(this.rng.next() * (n - i));
        [idx[i], idx[j]] = [idx[j], idx[i]];
      }
      const sample = idx.slice(0, this.psi).map((i) => X[i]);
      this.trees.push(this.build(sample, 0, limit));
    }
    this.calibrate(X);
    return this;
  }

  // Робастная нормировка по обучающей выборке: z = (s − медиана) / (1,4826·MAD).
  // Так оценка не зависит от того, насколько «разнообразен» нормальный трафик.
  calibrate(X) {
    const s = X.map((x) => this.score(x)).sort((a, b) => a - b);
    const med = s[s.length >> 1];
    const dev = s.map((v) => Math.abs(v - med)).sort((a, b) => a - b);
    this.median = med;
    this.scale = Math.max(1.4826 * dev[dev.length >> 1], 0.01);
  }

  zscore(x) {
    return (this.score(x) - this.median) / this.scale;
  }

  build(rows, depth, limit) {
    if (depth >= limit || rows.length <= 1) return { size: rows.length };
    const candidates = [];
    const mins = new Float64Array(this.dim);
    const maxs = new Float64Array(this.dim);
    for (let d = 0; d < this.dim; d++) {
      let lo = Infinity;
      let hi = -Infinity;
      for (const r of rows) {
        if (r[d] < lo) lo = r[d];
        if (r[d] > hi) hi = r[d];
      }
      mins[d] = lo;
      maxs[d] = hi;
      if (hi > lo) candidates.push(d);
    }
    if (!candidates.length) return { size: rows.length };
    const f = candidates[Math.floor(this.rng.next() * candidates.length)];
    const v = mins[f] + this.rng.next() * (maxs[f] - mins[f]);
    const left = [];
    const right = [];
    for (const r of rows) (r[f] < v ? left : right).push(r);
    return { f, v, l: this.build(left, depth + 1, limit), r: this.build(right, depth + 1, limit) };
  }

  pathLength(x, node, depth) {
    while (node.f !== undefined) {
      node = x[node.f] < node.v ? node.l : node.r;
      depth++;
    }
    return depth + cFactor(node.size);
  }

  // Оценка аномальности s(x) = 2^(-E[h(x)] / c(ψ)) ∈ (0, 1); ≈0,5 и ниже — норма.
  score(x) {
    if (!this.trees.length) return 0.5;
    let sum = 0;
    for (const tree of this.trees) sum += this.pathLength(x, tree, 0);
    const mean = sum / this.trees.length;
    return Math.pow(2, -mean / cFactor(this.psi));
  }
}
