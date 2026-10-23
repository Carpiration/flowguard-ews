// Статистические детекторы и слияние сигналов в оценку риска.
//
//  1. Адаптивная базовая линия (EWMA) → робастные z-оценки по каждому признаку.
//  2. CUSUM — накопление малых устойчивых сдвигов: даёт раннее предупреждение
//     для медленно нарастающих атак, которые не превышают порог в одном окне.
//  3. Isolation Forest — многомерная аномальность вектора признаков окна.
//  4. Поведенческие сигнатуры (patterns.js) с важностью и уверенностью.
//
// Итог: R = 100 · (1 − (1 − P) · (1 − λ·A)), где A — нормированное «шумовое ИЛИ»
// статистических детекторов, P — «шумовое ИЛИ» сработавших сигнатур.
// Затем риск сглаживается: R_t = max(R_raw, R_{t−1}·d) — быстрый рост, медленный спад.

import { FX, NF } from './features.js';

export const LEVELS = [
  { id: 'low', name: 'Низкий', min: 0 },
  { id: 'medium', name: 'Умеренный', min: 25 },
  { id: 'high', name: 'Высокий', min: 50 },
  { id: 'critical', name: 'Критический', min: 75 },
];

export function levelOf(risk) {
  let level = LEVELS[0];
  for (const l of LEVELS) if (risk >= l.min) level = l;
  return level;
}

export const STATES = {
  normal: 'Норма',
  warning: 'Предупреждение',
  alarm: 'Тревога',
};

export const ALL_COMPONENTS = Object.freeze({ baseline: true, cusum: true, iforest: true, patterns: true });

export const PARAMS = Object.freeze({
  wBase: 0.55,
  wCusum: 0.4,
  wIf: 0.5,
  lambda: 0.8,
  sevWeight: [0, 0.3, 0.55, 0.8, 0.95],
  cusumK: 0.8,
  cusumH: 7,
  // Верхняя граница накопления (в долях h): ограничивает «память» CUSUM после окончания атаки.
  cusumCap: 1.2,
  zOnset: 3,
  ifOnset: 3,
  ifRange: 4,
  halfLife: 20,
  warningRisk: 25,
});

const CUSUM_FEATURES = [FX.PKTS, FX.BYTES, FX.DSTS, FX.PORTS, FX.CONNS, FX.RST, FX.ICMP, FX.DNS, FX.EXT, FX.NEWP];
const clamp = (x, a = 0, b = 1) => Math.min(b, Math.max(a, x));

function median(arr) {
  const s = [...arr].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

// Счётчики переводятся в логарифмическую шкалу: распределения трафика тяжелохвостые.
export function transform(f) {
  const x = new Float64Array(NF);
  for (let i = 0; i < NF; i++) x[i] = i === FX.ENT ? f[i] : Math.log1p(f[i]);
  return x;
}

export function warmupWindows(windowSize) {
  return Math.round(clamp(120 / windowSize, 6, 30));
}

export class ScoreEngine {
  constructor({ windowSize, sensitivity = 1, threshold = 50, components = ALL_COMPONENTS }) {
    this.w = windowSize;
    this.s = sensitivity;
    this.tau = threshold;
    this.c = components;
    this.warmN = warmupWindows(windowSize);
    this.alpha = 2 / (Math.round(clamp(300 / windowSize, 12, 120)) + 1);
    this.decay = Math.pow(0.5, windowSize / PARAMS.halfLife);
    this.z0 = PARAMS.zOnset / sensitivity;
    this.h = PARAMS.cusumH / sensitivity;
    this.ifOnset = PARAMS.ifOnset / sensitivity;
    this.warm = [];
    this.ready = false;
    this.mu = null;
    this.var = null;
    this.S = new Float64Array(NF);
    this.prevRisk = 0;
    let rest = 1;
    if (components.baseline) rest *= 1 - PARAMS.wBase;
    if (components.cusum) rest *= 1 - PARAMS.wCusum;
    if (components.iforest) rest *= 1 - PARAMS.wIf;
    this.maxA = 1 - rest;
  }

  // Нижняя граница σ: для счётчиков — пуассоновский шум в лог-шкале (≈1/√λ),
  // чтобы единичные события на «тихом» признаке не давали огромных z.
  sigmaFloor(i) {
    if (i === FX.ENT) return 0.25;
    if (i === FX.AVG) return 0.15;
    const lambda = Math.expm1(Math.max(0, this.mu[i]));
    return Math.max(0.12, Math.sqrt(1 / (lambda + 1)));
  }

  initFromWarm() {
    this.mu = new Float64Array(NF);
    this.var = new Float64Array(NF);
    for (let i = 0; i < NF; i++) {
      const col = this.warm.map((x) => x[i]);
      const med = median(col);
      const sd = 1.4826 * median(col.map((v) => Math.abs(v - med)));
      this.mu[i] = med;
      this.var[i] = sd * sd;
    }
  }

  zscores(x) {
    const z = new Float64Array(NF);
    for (let i = 0; i < NF; i++) {
      const sd = Math.max(Math.sqrt(this.var[i]), this.sigmaFloor(i));
      z[i] = (x[i] - this.mu[i]) / sd;
    }
    return z;
  }

  process(f, ifScore, hits) {
    const x = transform(f);
    let z = new Float64Array(NF);
    let warmFactor = 1;
    const wasReady = this.ready;
    if (!this.ready) {
      this.warm.push(x);
      if (this.warm.length >= 4) {
        this.initFromWarm();
        z = this.zscores(x);
      }
      warmFactor = this.warm.length / this.warmN;
      if (this.warm.length >= this.warmN) {
        this.ready = true;
        this.warm = null;
      }
    } else {
      z = this.zscores(x);
    }

    let zmax = 0;
    const zp = new Float64Array(NF);
    for (let i = 0; i < NF; i++) {
      // Средний размер пакета: отклонение в обе стороны, но с половинным весом и
      // только при достаточном числе пакетов — иначе среднее статистически ненадёжно.
      if (i === FX.AVG) zp[i] = f[FX.PKTS] >= 30 ? Math.abs(z[i]) * 0.5 : 0;
      else zp[i] = Math.max(0, z[i]);
      if (zp[i] > zmax) zmax = zp[i];
    }
    const sBase = this.c.baseline ? 1 - Math.exp(-Math.max(0, zmax - this.z0) / 2.5) : 0;

    let cus = 0;
    if (wasReady) {
      for (const i of CUSUM_FEATURES) {
        const zc = clamp(z[i], -3, 4);
        this.S[i] = Math.min(PARAMS.cusumCap * this.h, Math.max(0, this.S[i] + zc - PARAMS.cusumK));
        if (this.S[i] > cus) cus = this.S[i];
      }
    }
    const sCusum = this.c.cusum ? clamp(cus / this.h) : 0;
    // ifScore — нормированная оценка Isolation Forest (робастная z-оценка).
    const sIf = this.c.iforest && ifScore != null ? clamp((ifScore - this.ifOnset) / PARAMS.ifRange) : 0;

    let prodA = 1;
    if (this.c.baseline) prodA *= 1 - PARAMS.wBase * sBase;
    if (this.c.cusum) prodA *= 1 - PARAMS.wCusum * sCusum;
    if (this.c.iforest) prodA *= 1 - PARAMS.wIf * sIf;
    const A = this.maxA > 0 ? ((1 - prodA) / this.maxA) * warmFactor : 0;

    let prodP = 1;
    if (this.c.patterns && hits) for (const hit of hits) prodP *= 1 - PARAMS.sevWeight[hit.sev] * hit.conf;
    const P = 1 - prodP;
    const lambda = this.c.patterns ? PARAMS.lambda : 1;
    const raw = 100 * (1 - (1 - P) * (1 - lambda * A));
    const risk = Math.max(raw, this.prevRisk * this.decay);
    this.prevRisk = risk;

    if (wasReady) {
      // Во время подозрения базовая линия обучается в 10 раз медленнее,
      // чтобы атака не «впитывалась» в норму, но устойчивые изменения сети учитывались.
      const suspicious = zmax >= 3.5 || cus >= this.h;
      const a = suspicious ? this.alpha * 0.1 : this.alpha;
      for (let i = 0; i < NF; i++) {
        const d = x[i] - this.mu[i];
        this.mu[i] += a * d;
        this.var[i] = (1 - a) * (this.var[i] + a * d * d);
      }
    }

    const state = risk >= this.tau ? 'alarm' : risk >= PARAMS.warningRisk || sCusum >= 0.5 ? 'warning' : 'normal';
    const top = [...zp.keys()].filter((i) => zp[i] >= 2).sort((a, b) => zp[b] - zp[a]).slice(0, 3);
    return { z, zmax, top, sBase, sCusum, sIf, ifScore, A, P, raw, risk, state, warming: !wasReady };
  }
}

// Классический подход для сравнения: порог «среднее + 3σ» по числу пакетов и
// объёму, параметры оцениваются на том же периоде обучения.
export class StaticThreshold {
  constructor({ windowSize }) {
    this.warmN = warmupWindows(windowSize);
    this.vals = [];
    this.stats = null;
  }

  process(f) {
    if (!this.stats) {
      this.vals.push([f[FX.PKTS], f[FX.BYTES]]);
      if (this.vals.length >= this.warmN) {
        const m = [0, 1].map((k) => this.vals.reduce((s, v) => s + v[k], 0) / this.vals.length);
        const sd = [0, 1].map((k) => Math.sqrt(this.vals.reduce((s, v) => s + (v[k] - m[k]) ** 2, 0) / this.vals.length));
        this.stats = { m, sd };
      }
      return 0;
    }
    const { m, sd } = this.stats;
    const z = Math.max((f[FX.PKTS] - m[0]) / Math.max(sd[0], 1), (f[FX.BYTES] - m[1]) / Math.max(sd[1], 1));
    return 100 * clamp(z / 6);
  }
}
