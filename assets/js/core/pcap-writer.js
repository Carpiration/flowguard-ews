// Запись трассы в классический PCAP (Ethernet + IPv4). Сохраняются заголовки
// и DNS-вопросы; полезная нагрузка не пишется (как при захвате с малым snaplen),
// исходная длина кадра указывается в orig_len.

import { parseIPv4 } from './net.js';
import { PROTO } from './trace.js';

function checksum(b, off, len) {
  let sum = 0;
  for (let i = 0; i < len; i += 2) sum += (b[off + i] << 8) | (i + 1 < len ? b[off + i + 1] : 0);
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return ~sum & 0xffff;
}

function dnsQuestion(name) {
  const labels = name.split('.').filter(Boolean);
  const out = [];
  for (const l of labels) {
    const s = l.slice(0, 63);
    out.push(s.length);
    for (let i = 0; i < s.length; i++) out.push(s.charCodeAt(i) & 0x7f);
  }
  out.push(0, 0, 1, 0, 1);
  return out;
}

export function writePcap(trace) {
  const chunks = [];
  const header = new DataView(new ArrayBuffer(24));
  header.setUint32(0, 0xa1b2c3d4, true);
  header.setUint16(4, 2, true);
  header.setUint16(6, 4, true);
  header.setUint32(16, 65535, true);
  header.setUint32(20, 1, true);
  chunks.push(new Uint8Array(header.buffer));
  let seq = 1000;
  for (let i = 0; i < trace.length; i++) {
    const s4 = parseIPv4(trace.hosts.name(trace.src[i]));
    const d4 = parseIPv4(trace.hosts.name(trace.dst[i]));
    if (s4 === null || d4 === null) continue;
    const proto = trace.proto[i];
    const qname = trace.q[i] >= 0 ? trace.strings[trace.q[i]] : null;
    const dns = qname && proto === PROTO.UDP ? dnsQuestion(qname) : null;
    const l4 = proto === PROTO.TCP ? 20 : proto === PROTO.UDP ? 8 + (dns ? 12 + dns.length : 0) : proto === PROTO.ICMP ? 8 : 0;
    const incl = 14 + 20 + l4;
    const orig = Math.max(incl, Math.round(trace.len[i]));
    const buf = new Uint8Array(16 + incl);
    const dv = new DataView(buf.buffer);
    const t = trace.t[i];
    const sec = Math.floor(t);
    dv.setUint32(0, sec, true);
    dv.setUint32(4, Math.min(999999, Math.round((t - sec) * 1e6)), true);
    dv.setUint32(8, incl, true);
    dv.setUint32(12, orig, true);
    let p = 16;
    buf.set([0x02, 0, d4 >>> 24, (d4 >>> 16) & 255, (d4 >>> 8) & 255, d4 & 255], p);
    buf.set([0x02, 0, s4 >>> 24, (s4 >>> 16) & 255, (s4 >>> 8) & 255, s4 & 255], p + 6);
    dv.setUint16(p + 12, 0x0800);
    p += 14;
    const ipProto = proto === PROTO.TCP ? 6 : proto === PROTO.UDP ? 17 : proto === PROTO.ICMP ? 1 : 253;
    buf[p] = 0x45;
    dv.setUint16(p + 2, Math.min(65535, orig - 14));
    dv.setUint16(p + 4, i & 0xffff);
    dv.setUint16(p + 6, 0x4000);
    buf[p + 8] = 64;
    buf[p + 9] = ipProto;
    dv.setUint32(p + 12, s4);
    dv.setUint32(p + 16, d4);
    dv.setUint16(p + 10, checksum(buf, p, 20));
    p += 20;
    if (proto === PROTO.TCP) {
      dv.setUint16(p, trace.sp[i]);
      dv.setUint16(p + 2, trace.dp[i]);
      dv.setUint32(p + 4, seq);
      dv.setUint32(p + 8, seq ^ 0x5a5a);
      seq = (seq + 1460) >>> 0;
      buf[p + 12] = 0x50;
      buf[p + 13] = trace.flags[i] & 0x3f;
      dv.setUint16(p + 14, 65535);
    } else if (proto === PROTO.UDP) {
      dv.setUint16(p, trace.sp[i]);
      dv.setUint16(p + 2, trace.dp[i]);
      dv.setUint16(p + 4, Math.min(65535, Math.max(8, orig - 34)));
      if (dns) {
        dv.setUint16(p + 8, i & 0xffff);
        dv.setUint16(p + 10, 0x0100);
        dv.setUint16(p + 12, 1);
        buf.set(dns, p + 20);
      }
    } else if (proto === PROTO.ICMP) {
      buf[p] = trace.flags[i] & 0xff;
      dv.setUint16(p + 4, 1);
      dv.setUint16(p + 6, i & 0xffff);
      dv.setUint16(p + 2, checksum(buf, p, 8));
    }
    chunks.push(buf);
  }
  return new Blob(chunks, { type: 'application/vnd.tcpdump.pcap' });
}
