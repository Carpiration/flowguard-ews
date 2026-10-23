// Работа с адресами: разбор IPv4/IPv6, проверка принадлежности внутренней сети,
// базовый домен и энтропия строки для анализа DNS.

export const DEFAULT_INTERNAL = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'];

export function parseIPv4(s) {
  if (typeof s !== 'string') return null;
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const v = Number(part);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

export function formatIPv4(n) {
  return `${n >>> 24}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
}

export function formatIPv6(b, o) {
  const g = new Array(8);
  for (let i = 0; i < 8; i++) g[i] = (b[o + 2 * i] << 8) | b[o + 2 * i + 1];
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff) {
    return `::ffff:${b[o + 12]}.${b[o + 13]}.${b[o + 14]}.${b[o + 15]}`;
  }
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (g[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  if (bestLen < 2) bestStart = -1;
  const hex = (x) => x.toString(16);
  if (bestStart < 0) return g.map(hex).join(':');
  const head = g.slice(0, bestStart).map(hex).join(':');
  const tail = g.slice(bestStart + bestLen).map(hex).join(':');
  return `${head}::${tail}`;
}

// Возвращает 32 шестнадцатеричных символа полного IPv6-адреса или null.
export function expandIPv6(s) {
  if (typeof s !== 'string' || !s.includes(':')) return null;
  let str = s.toLowerCase().split('%')[0];
  const v4 = str.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const n = parseIPv4(v4[1]);
    if (n === null) return null;
    str = str.slice(0, -v4[1].length) + `${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const halves = str.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
  const groups = [...left, ...new Array(missing).fill('0'), ...right];
  if (groups.some((x) => !/^[0-9a-f]{1,4}$/.test(x))) return null;
  return groups.map((x) => x.padStart(4, '0')).join('');
}

export function isIp(s) {
  return parseIPv4(s) !== null || expandIPv6(s) !== null;
}

export function parseCidr(text) {
  const [addr, bitsText] = String(text).trim().split('/');
  const v4 = parseIPv4(addr);
  if (v4 !== null) {
    const bits = bitsText === undefined ? 32 : Number(bitsText);
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return { v: 4, base: (v4 & mask) >>> 0, mask };
  }
  const v6 = expandIPv6(addr);
  if (v6 !== null) {
    const bits = bitsText === undefined ? 128 : Number(bitsText);
    if (!Number.isInteger(bits) || bits < 0 || bits > 128) return null;
    return { v: 6, bits, hex: v6 };
  }
  return null;
}

function hexPrefixMatch(hex, rule) {
  const full = Math.floor(rule.bits / 4);
  if (hex.slice(0, full) !== rule.hex.slice(0, full)) return false;
  const rest = rule.bits % 4;
  if (!rest) return true;
  const mask = (0xf << (4 - rest)) & 0xf;
  return (parseInt(hex[full], 16) & mask) === (parseInt(rule.hex[full], 16) & mask);
}

// Внутренними считаются заданные подсети, а также служебные адреса
// (loopback, link-local, multicast, broadcast): трафик к ним не уходит во внешнюю сеть.
export function makeInternalMatcher(cidrs = DEFAULT_INTERNAL) {
  const rules = cidrs.map(parseCidr).filter(Boolean);
  const v4 = rules.filter((r) => r.v === 4);
  const v6 = rules.filter((r) => r.v === 6);
  return (ip) => {
    const n = parseIPv4(ip);
    if (n !== null) {
      if (n >>> 28 === 14 || n === 0xffffffff || n === 0) return true;
      if (n >>> 16 === 0xa9fe || n >>> 24 === 127) return true;
      return v4.some((r) => ((n & r.mask) >>> 0) === r.base);
    }
    const hex = expandIPv6(ip);
    if (hex === null) return false;
    if (hex === '00000000000000000000000000000001') return true;
    if (hex.startsWith('fe8') || hex.startsWith('fe9') || hex.startsWith('fea') || hex.startsWith('feb')) return true;
    if (hex.startsWith('ff')) return true;
    return v6.some((r) => hexPrefixMatch(hex, r));
  };
}

export function baseDomain(qname) {
  const labels = qname.split('.').filter(Boolean);
  if (labels.length <= 2) return { base: labels.join('.'), sub: '' };
  return { base: labels.slice(-2).join('.'), sub: labels.slice(0, -2).join('.') };
}

// Энтропия Шеннона, бит на символ.
export function entropy(str) {
  if (!str) return 0;
  const counts = new Map();
  for (const ch of str) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  const n = str.length;
  for (const c of counts.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}
