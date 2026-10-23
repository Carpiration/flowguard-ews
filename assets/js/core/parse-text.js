// Разбор текстовых источников: CSV (Wireshark, Zeek, CICIDS, UNSW-NB15 и
// произвольные таблицы пакетов/потоков), JSON/NDJSON (Zeek, Suricata EVE, ECS)
// и текстовый вывод tcpdump. Поля сопоставляются по набору синонимов.

import { FormatError } from './errors.js';
import { FLOW_ORIG, PROTO, TCPF } from './trace.js';

export const norm = (k) => String(k).toLowerCase().replace(/[^a-z0-9]/g, '');

const ALIASES = {
  t: ['timestamp', 'time', 'ts', 'datetime', 'date', 'starttime', 'stime', 'frametimeepoch', 'frametime', 'flowstart', 'firstseen', 'start'],
  src: ['src', 'srcip', 'source', 'sourceip', 'saddr', 'srcaddr', 'idorigh', 'origh', 'ipsrc', 'sourceaddress', 'srcipaddr', 'srcaddress', 'clientip'],
  dst: ['dst', 'dstip', 'destination', 'destinationip', 'daddr', 'dstaddr', 'idresph', 'resph', 'ipdst', 'destip', 'destinationaddress', 'dstipaddr', 'dstaddress', 'serverip'],
  sp: ['sport', 'srcport', 'sourceport', 'idorigp', 'origp', 'tcpsrcport', 'udpsrcport', 'spt', 'srcpt'],
  dp: ['dport', 'dstport', 'destinationport', 'idrespp', 'respp', 'tcpdstport', 'udpdstport', 'destport', 'dpt', 'dsport', 'dstpt'],
  proto: ['protocol', 'proto', 'ipproto', 'protocolname', 'transport', 'l4proto'],
  len: ['length', 'len', 'bytes', 'size', 'framelen', 'iplen', 'totbytes', 'totalbytes', 'byts', 'octets', 'networkbytes'],
  pkts: ['packets', 'pkts', 'npackets', 'totalpackets', 'totpkts', 'networkpackets'],
  origBytes: ['origbytes', 'origipbytes', 'totallengthoffwdpackets', 'totlenfwdpkts', 'flowbytestoserver', 'srcbytes', 'sbytes', 'sourcebytes', 'fwdbytes'],
  respBytes: ['respbytes', 'respipbytes', 'totallengthofbwdpackets', 'totlenbwdpkts', 'flowbytestoclient', 'dstbytes', 'dbytes', 'destinationbytes', 'bwdbytes'],
  origPkts: ['origpkts', 'totalfwdpackets', 'totfwdpkts', 'flowpktstoserver', 'spkts', 'srcpkts', 'sourcepackets', 'fwdpkts'],
  respPkts: ['resppkts', 'totalbackwardpackets', 'totbwdpkts', 'flowpktstoclient', 'dpkts', 'dstpkts', 'destinationpackets', 'bwdpkts'],
  flags: ['flags', 'tcpflags', 'tcpflagsstr', 'flag'],
  state: ['connstate', 'state', 'flowstate', 'tcpstate'],
  q: ['query', 'dnsquery', 'qname', 'dnsqryname', 'dnsrrname', 'dnsquestionname', 'dnsname'],
  label: ['label', 'attack', 'class', 'groundtruth', 'ismalicious', 'malicious', 'target'],
  attackCat: ['attackcat', 'attacktype', 'category', 'attackcategory', 'subcategory'],
  info: ['info'],
};

const BENIGN = new Set(['', '0', 'benign', 'normal', '-', 'false', 'none', 'no', 'background', 'legitimate', 'clean']);

export function normalizeLabel(v) {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  return BENIGN.has(s.toLowerCase()) ? null : s;
}

function buildMapping(keys) {
  const normalized = keys.map(norm);
  const m = {};
  for (const [field, list] of Object.entries(ALIASES)) {
    for (const alias of list) {
      const idx = normalized.indexOf(alias);
      if (idx >= 0) {
        m[field] = keys[idx];
        break;
      }
    }
  }
  m.flow = m.origBytes !== undefined || m.respBytes !== undefined || m.origPkts !== undefined || m.respPkts !== undefined || m.pkts !== undefined;
  m.hasLabel = m.label !== undefined || m.attackCat !== undefined;
  return m;
}

// ---- значения полей ----

export function parseTime(v) {
  if (v === undefined || v === null) return NaN;
  if (typeof v === 'number') return v > 1e14 ? v / 1e6 : v > 1e11 ? v / 1000 : v;
  const s = String(v).trim();
  if (!s) return NaN;
  if (/^-?\d+(\.\d+)?$/.test(s)) return parseTime(Number(s));
  let m = s.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{1,2}):(\d{2}):(\d{2})(?:[.,](\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$/i);
  if (m) {
    let t = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) / 1000;
    if (m[7]) t += Number(`0.${m[7]}`);
    if (m[8] && m[8].toUpperCase() !== 'Z') {
      const sign = m[8][0] === '-' ? -1 : 1;
      const digits = m[8].slice(1).replace(':', '');
      t -= sign * (Number(digits.slice(0, 2)) * 3600 + Number(digits.slice(2)) * 60);
    }
    return t;
  }
  m = s.match(/^(\d{1,2})[./](\d{1,2})[./](\d{4})[ T](\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?\s*(AM|PM)?$/i);
  if (m) {
    let h = +m[4];
    if (m[8]) {
      const pm = m[8].toUpperCase() === 'PM';
      if (pm && h < 12) h += 12;
      if (!pm && h === 12) h = 0;
    }
    let t = Date.UTC(+m[3], +m[2] - 1, +m[1], h, +m[5], m[6] ? +m[6] : 0) / 1000;
    if (m[7]) t += Number(`0.${m[7]}`);
    return t;
  }
  m = s.match(/^(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))?$/);
  if (m) return +m[1] * 3600 + +m[2] * 60 + +m[3] + (m[4] ? Number(`0.${m[4]}`) : 0);
  const d = Date.parse(s);
  return Number.isNaN(d) ? NaN : d / 1000;
}

function toNum(v) {
  if (v === undefined || v === null || v === '') return 0;
  const n = typeof v === 'number' ? v : Number(String(v).trim().replace(',', '.'));
  return Number.isFinite(n) && n > 0 ? n : 0;
}

function toPort(v) {
  if (v === undefined || v === null || v === '') return 0;
  let s = String(v).trim();
  if (s.startsWith('0x')) return parseInt(s, 16) & 0xffff;
  const n = Number(s);
  return Number.isInteger(n) && n >= 0 && n <= 65535 ? n : 0;
}

const UDP_APPS = /^(dns|mdns|llmnr|nbns|nbdgm|quic|ntp|ssdp|dhcp|dhcpv6|bootp|snmp|syslog|tftp|udp|rtp|rtcp|stun|cldap|wsd|coap|sip)/;
const TCP_APPS = /^(tcp|tls|ssl|http|ssh|sshv2|ftp|smtp|imap|pop|smb|smb2|rdp|telnet|ldap|mysql|pgsql|tds|vnc|irc|bgp|kerberos|msrpc|dcerpc|nfs)/;

export function parseProto(v) {
  if (v === undefined || v === null) return PROTO.OTHER;
  const s = String(v).trim().toLowerCase();
  if (s === '6' || s === 'tcp') return PROTO.TCP;
  if (s === '17' || s === 'udp') return PROTO.UDP;
  if (s === '1' || s === '58' || s.startsWith('icmp') || s === 'ipv6-icmp') return PROTO.ICMP;
  if (UDP_APPS.test(s)) return PROTO.UDP;
  if (TCP_APPS.test(s)) return PROTO.TCP;
  return PROTO.OTHER;
}

const FLAG_WORDS = { SYN: TCPF.SYN, ACK: TCPF.ACK, FIN: TCPF.FIN, RST: TCPF.RST, PSH: TCPF.PSH, URG: TCPF.URG };
const FLAG_CHARS = { S: TCPF.SYN, A: TCPF.ACK, '.': TCPF.ACK, F: TCPF.FIN, R: TCPF.RST, P: TCPF.PSH, U: TCPF.URG };

export function parseFlags(v) {
  if (v === undefined || v === null || v === '') return 0;
  if (typeof v === 'number') return v & 0x3f;
  const s = String(v).trim().toUpperCase();
  if (/^0X[0-9A-F]+$/.test(s)) return parseInt(s, 16) & 0x3f;
  if (/^\d+$/.test(s)) return Number(s) & 0x3f;
  let f = 0;
  const words = s.match(/[A-Z]{3}/g);
  if (words && words.some((w) => FLAG_WORDS[w])) {
    for (const w of words) f |= FLAG_WORDS[w] || 0;
    return f;
  }
  for (const ch of s) f |= FLAG_CHARS[ch] || 0;
  return f;
}

// Состояния соединений Zeek/UNSW без ответа сервера рассматриваются как
// неотвеченные попытки (SYN без ACK).
const UNANSWERED_STATES = new Set(['S0', 'REJ', 'SH', 'SHR', 'RSTOS0', 'OTH', 'INT', 'REQ', 'NEW']);

const INFO_PORTS = /^\s*(\d{1,5})\s*(?:→|->|>)\s*(\d{1,5})\b/;
const INFO_FLAGS = /\[([A-Z, ]+)\]/;
const INFO_DNS = /Standard query 0x[0-9a-f]+\s+[A-Z]+\s+([^\s,]+)/i;

function emitRow(builder, m, get, rowIndex, ctx) {
  let t;
  if (m.t !== undefined) {
    t = parseTime(get(m.t));
    if (!Number.isFinite(t)) {
      builder.skipped++;
      return;
    }
  } else {
    t = rowIndex * 0.001;
    ctx.syntheticTime = true;
  }
  const src = String(get(m.src) ?? '').trim() || 'неизвестный-источник';
  const dst = String(get(m.dst) ?? '').trim() || 'неизвестный-получатель';
  let sp = toPort(get(m.sp));
  let dp = toPort(get(m.dp));
  let proto = parseProto(get(m.proto));
  let flags = m.flags !== undefined ? parseFlags(get(m.flags)) : 0;
  let q = m.q !== undefined ? String(get(m.q) ?? '').trim().toLowerCase().replace(/\.$/, '') || null : null;
  if (q === '-') q = null;
  if (m.info !== undefined) {
    const info = String(get(m.info) ?? '');
    const pm = info.match(INFO_PORTS);
    if (pm && !sp && !dp) {
      sp = Number(pm[1]);
      dp = Number(pm[2]);
    }
    const fm = info.match(INFO_FLAGS);
    if (fm && !flags) flags = parseFlags(fm[1]);
    const dm = info.match(INFO_DNS);
    if (dm && !/response/i.test(info) && !q) q = dm[1].toLowerCase();
  }
  if (proto === PROTO.OTHER && (sp || dp)) proto = flags ? PROTO.TCP : PROTO.OTHER;
  if (q && proto === PROTO.OTHER) proto = PROTO.UDP;
  let label = null;
  if (m.hasLabel) {
    const cat = m.attackCat !== undefined ? normalizeLabel(get(m.attackCat)) : null;
    const lab = m.label !== undefined ? normalizeLabel(get(m.label)) : null;
    label = cat || lab;
    if (label && /^(1|true|yes|attack|malicious)$/i.test(label)) label = cat || 'атака';
  }

  if (!m.flow) {
    builder.push(t, src, dst, sp, dp, proto, toNum(get(m.len)), flags, 1, q, label);
    return;
  }
  // Сетевой поток: запись инициатора и, если был ответ, зеркальная запись ответа.
  let ob = m.origBytes !== undefined ? toNum(get(m.origBytes)) : 0;
  let rb = m.respBytes !== undefined ? toNum(get(m.respBytes)) : 0;
  let op = m.origPkts !== undefined ? toNum(get(m.origPkts)) : 0;
  let rp = m.respPkts !== undefined ? toNum(get(m.respPkts)) : 0;
  if (m.origBytes === undefined && m.respBytes === undefined) ob = toNum(get(m.len));
  if (m.origPkts === undefined && m.respPkts === undefined) op = toNum(get(m.pkts));
  if (!op) op = ob ? Math.max(1, Math.round(ob / 800)) : 1;
  const state = m.state !== undefined ? String(get(m.state) ?? '').trim().toUpperCase() : '';
  const answered = state ? !UNANSWERED_STATES.has(state) : rp > 0 || rb > 0;
  const of = proto === PROTO.TCP ? (answered ? TCPF.SYN | TCPF.ACK : TCPF.SYN) : 0;
  builder.push(t, src, dst, sp, dp, proto, ob, of | FLOW_ORIG, Math.round(op), q, label);
  if (rp > 0 || rb > 0) {
    const rf = proto === PROTO.TCP ? (answered ? TCPF.SYN | TCPF.ACK : TCPF.RST | TCPF.ACK) : 0;
    builder.push(t, dst, src, dp, sp, proto, rb, rf, Math.max(1, Math.round(rp)), null, label);
  }
}

// ---- построчное чтение ----

export async function forEachLines(blob, onLines, onProgress, chunkSize = 4 << 20) {
  const decoder = new TextDecoder('utf-8');
  let carry = '';
  let offset = 0;
  let first = true;
  while (offset < blob.size) {
    const buf = await blob.slice(offset, offset + chunkSize).arrayBuffer();
    offset += buf.byteLength;
    let text = carry + decoder.decode(buf, { stream: offset < blob.size });
    if (first) {
      text = text.replace(/^﻿/, '');
      first = false;
    }
    const lines = text.split(/\r?\n/);
    carry = lines.pop();
    if (onLines(lines) === false) return;
    onProgress?.(offset / blob.size);
  }
  carry += decoder.decode();
  if (carry) onLines([carry]);
}

export function detectDelimiter(line) {
  const candidates = [',', ';', '\t', '|'];
  let best = ',';
  let bestCount = 0;
  for (const c of candidates) {
    const count = splitCsvLine(line, c).length;
    if (count > bestCount) {
      best = c;
      bestCount = count;
    }
  }
  return best;
}

export function splitCsvLine(line, d) {
  const out = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"') {
        if (line[i + 1] === '"') {
          cur += '"';
          i++;
        } else quoted = false;
      } else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === d) {
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  out.push(cur);
  return out;
}

function finishContext(builder, m, ctx) {
  builder.flowMode = Boolean(m?.flow);
  builder.labelled = Boolean(m?.hasLabel);
  if (ctx.syntheticTime) {
    builder.syntheticTime = true;
    builder.notes.push('В источнике нет поля времени: записи упорядочены по номеру строки (1 запись = 1 мс).');
  }
  if (m && m.src === undefined) builder.notes.push('Не найдено поле адреса источника: анализ поведения узлов ограничен.');
}

export async function parseCsv(blob, builder, onProgress) {
  let header = null;
  let delim = ',';
  let m = null;
  let colIdx = null;
  let cells = [];
  let row = 0;
  const ctx = {};
  const get = (key) => (key === undefined ? undefined : cells[colIdx.get(key)]);
  await forEachLines(
    blob,
    (lines) => {
      for (const line of lines) {
        if (!line.trim()) continue;
        if (!header) {
          delim = detectDelimiter(line);
          header = splitCsvLine(line, delim).map((h) => h.trim());
          m = buildMapping(header);
          if (m.src === undefined && m.dst === undefined && m.t === undefined) {
            throw new FormatError('В CSV не найдены столбцы времени и адресов. Ожидаются, например: time, src, dst, sport, dport, protocol, length.');
          }
          colIdx = new Map();
          header.forEach((h, i) => {
            if (!colIdx.has(h)) colIdx.set(h, i);
          });
          continue;
        }
        cells = splitCsvLine(line, delim);
        emitRow(builder, m, get, row++, ctx);
      }
    },
    onProgress,
  );
  if (!header) throw new FormatError('CSV-файл пуст.');
  finishContext(builder, m, ctx);
}

function flatten(obj, prefix = '', out = {}, depth = 0) {
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    const key = prefix + norm(k);
    if (v && typeof v === 'object' && !Array.isArray(v) && depth < 4) flatten(v, key, out, depth + 1);
    else out[key] = v;
  }
  return out;
}

function makeJsonEmitter(builder) {
  const cache = new Map();
  const ctx = {};
  let row = 0;
  let last = null;
  let anyFlow = false;
  let anyLabel = false;
  return {
    emit(obj) {
      if (!obj || typeof obj !== 'object') {
        builder.skipped++;
        return;
      }
      const flat = flatten(obj);
      const keys = Object.keys(flat);
      const sig = keys.join('|');
      let m = cache.get(sig);
      if (!m) {
        m = buildMapping(keys);
        if (cache.size < 64) cache.set(sig, m);
      }
      if (m.src === undefined && m.dst === undefined) {
        builder.skipped++;
        return;
      }
      last = m;
      anyFlow ||= m.flow;
      anyLabel ||= m.hasLabel;
      emitRow(builder, m, (k) => (k === undefined ? undefined : flat[k]), row++, ctx);
    },
    finish() {
      // В одном NDJSON могут чередоваться потоки и события (например, flow и dns в Suricata).
      finishContext(builder, last && { ...last, flow: anyFlow, hasLabel: anyLabel }, ctx);
    },
  };
}

const ARRAY_KEYS = ['packets', 'records', 'data', 'events', 'flows', 'items', 'rows', 'connections'];

export async function parseJson(blob, builder, onProgress) {
  const head = (await blob.slice(0, 4096).text()).replace(/^﻿/, '').trimStart();
  const em = makeJsonEmitter(builder);
  const LIMIT = 300 * 1024 * 1024;
  if (head[0] === '[' || head[0] === '{') {
    if (head[0] === '[' && blob.size > LIMIT) {
      throw new FormatError('JSON-массив больше 300 МБ. Сохраните данные в формате NDJSON (одна запись в строке).');
    }
    if (blob.size <= LIMIT) {
      let data;
      let parsed = false;
      try {
        data = JSON.parse((await blob.text()).replace(/^﻿/, ''));
        parsed = true;
      } catch (err) {
        if (head[0] === '[') throw new FormatError(`Некорректный JSON: ${err.message}`);
      }
      if (parsed) {
        let arr = Array.isArray(data) ? data : null;
        if (!arr && data && typeof data === 'object') {
          const key = ARRAY_KEYS.find((k) => Array.isArray(data[k]));
          arr = key ? data[key] : [data];
        }
        const total = arr.length || 1;
        arr.forEach((o, i) => {
          em.emit(o);
          if (i % 50000 === 0) onProgress?.(i / total);
        });
        em.finish();
        return;
      }
    }
  }
  await forEachLines(
    blob,
    (lines) => {
      for (const line of lines) {
        const s = line.trim();
        if (!s) continue;
        try {
          em.emit(JSON.parse(s));
        } catch {
          builder.skipped++;
        }
      }
    },
    onProgress,
  );
  em.finish();
}

// ---- tcpdump ----

export const TCPDUMP_RE = /^(?:(\d{4}-\d{2}-\d{2})\s+)?(\d{1,2}:\d{2}:\d{2}(?:\.\d+)?|\d{9,}(?:\.\d+)?)\s+(IP6?)\s+(\S+)\s+>\s+(\S+?):\s?(.*)$/;
const SERVICE_NAMES = { http: 80, https: 443, domain: 53, ssh: 22, ftp: 21, smtp: 25, telnet: 23, ntp: 123, 'microsoft-ds': 445, 'ms-wbt-server': 3389, mysql: 3306, imap: 143, pop3: 110, ldap: 389, bootps: 67, bootpc: 68, netbios: 137, snmp: 161 };
const DNS_Q = /^\d+\+?(?:\s+\[[^\]]*\])?\s+(?:A|AAAA|TXT|MX|CNAME|NS|PTR|SRV|ANY|SOA|HTTPS|SVCB|NULL)\?\s+(\S+)/;

function splitHostPort(s, v6) {
  if (v6) {
    const i = s.lastIndexOf('.');
    if (i > s.lastIndexOf(':')) return [s.slice(0, i), s.slice(i + 1)];
    return [s, ''];
  }
  const parts = s.split('.');
  if (parts.length === 5) return [parts.slice(0, 4).join('.'), parts[4]];
  return [s, ''];
}

function portOf(s) {
  if (!s) return 0;
  if (/^\d+$/.test(s)) return Number(s) & 0xffff;
  return SERVICE_NAMES[s] || 0;
}

export async function parseTcpdump(blob, builder, onProgress) {
  let dayOffset = 0;
  let lastTime = -Infinity;
  await forEachLines(
    blob,
    (lines) => {
      for (const line of lines) {
        const m = line.match(TCPDUMP_RE);
        if (!m) {
          if (line.trim()) builder.skipped++;
          continue;
        }
        let t = m[1] ? parseTime(`${m[1]} ${m[2]}`) : parseTime(m[2]);
        if (!m[1] && m[2].includes(':')) {
          if (t + dayOffset < lastTime - 3600) dayOffset += 86400;
          t += dayOffset;
        }
        lastTime = t;
        const v6 = m[3] === 'IP6';
        const [src, sps] = splitHostPort(m[4], v6);
        const [dst, dps] = splitHostPort(m[5], v6);
        const rest = m[6];
        const sp = portOf(sps);
        const dp = portOf(dps);
        const lm = rest.match(/length (\d+)/);
        const payload = lm ? Number(lm[1]) : 0;
        let proto = PROTO.OTHER;
        let flags = 0;
        let q = null;
        let header = 20;
        if (rest.startsWith('Flags [')) {
          proto = PROTO.TCP;
          flags = parseFlags(rest.slice(7, rest.indexOf(']')));
          header = 40;
        } else if (/ICMP/.test(rest)) {
          proto = PROTO.ICMP;
          flags = /echo request/.test(rest) ? 8 : /echo reply/.test(rest) ? 0 : 3;
          header = 28;
        } else if (sps || dps || /UDP/.test(rest)) {
          proto = PROTO.UDP;
          header = 28;
          if (dp === 53) {
            const dq = rest.match(DNS_Q);
            if (dq) q = dq[1].toLowerCase().replace(/\.$/, '');
          }
        }
        builder.push(t, src, dst, sp, dp, proto, payload + header, flags, 1, q, null);
      }
    },
    onProgress,
  );
}
