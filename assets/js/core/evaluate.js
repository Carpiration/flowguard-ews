// Метрики качества обнаружения на уровне окон и событий.

export function confusion(scores, labels, tau, mask = null) {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (let i = 0; i < scores.length; i++) {
    if (mask && !mask[i]) continue;
    const pos = scores[i] >= tau;
    if (labels[i]) pos ? tp++ : fn++;
    else pos ? fp++ : tn++;
  }
  return { tp, fp, tn, fn };
}

const div = (a, b) => (b > 0 ? a / b : null);

export function metrics(c) {
  const precision = div(c.tp, c.tp + c.fp);
  const recall = div(c.tp, c.tp + c.fn);
  const f1 = precision !== null && recall !== null && precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : null;
  return {
    ...c,
    precision,
    recall,
    f1,
    fpr: div(c.fp, c.fp + c.tn),
    accuracy: div(c.tp + c.tn, c.tp + c.tn + c.fp + c.fn),
  };
}

// ROC-кривая по всем порогам; AUC — площадь по методу трапеций.
export function roc(scores, labels, mask = null) {
  const items = [];
  let P = 0;
  let N = 0;
  for (let i = 0; i < scores.length; i++) {
    if (mask && !mask[i]) continue;
    items.push([scores[i], labels[i] ? 1 : 0]);
    labels[i] ? P++ : N++;
  }
  if (!P || !N) return { points: [], auc: null, positives: P, negatives: N };
  items.sort((a, b) => b[0] - a[0]);
  const points = [{ fpr: 0, tpr: 0, thr: Infinity }];
  let tp = 0;
  let fp = 0;
  let auc = 0;
  for (let i = 0; i < items.length; ) {
    const thr = items[i][0];
    while (i < items.length && items[i][0] === thr) {
      items[i][1] ? tp++ : fp++;
      i++;
    }
    const prev = points[points.length - 1];
    const pt = { fpr: fp / N, tpr: tp / P, thr };
    auc += ((pt.fpr - prev.fpr) * (pt.tpr + prev.tpr)) / 2;
    points.push(pt);
  }
  return { points: thin(points, 240), auc, positives: P, negatives: N };
}

function thin(points, max) {
  if (points.length <= max) return points;
  const step = (points.length - 1) / (max - 1);
  const out = [];
  for (let i = 0; i < max; i++) out.push(points[Math.round(i * step)]);
  return out;
}

// Непрерывные участки, где оценка не ниже порога.
export function episodes(scores, t0s, t1s, tau) {
  const out = [];
  let cur = null;
  for (let i = 0; i < scores.length; i++) {
    if (scores[i] >= tau) {
      if (!cur) cur = { start: t0s[i], end: t1s[i], peak: scores[i], from: i, to: i };
      cur.end = t1s[i];
      cur.to = i;
      cur.peak = Math.max(cur.peak, scores[i]);
    } else if (cur) {
      out.push(cur);
      cur = null;
    }
  }
  if (cur) out.push(cur);
  return out;
}

export function mean(arr) {
  const v = arr.filter((x) => x !== null && Number.isFinite(x));
  return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null;
}

export function sd(arr) {
  const v = arr.filter((x) => x !== null && Number.isFinite(x));
  if (v.length < 2) return null;
  const m = mean(v);
  return Math.sqrt(v.reduce((s, x) => s + (x - m) ** 2, 0) / (v.length - 1));
}
