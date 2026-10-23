// Разбор кадров канального уровня до L4: Ethernet/VLAN, Linux SLL/SLL2,
// loopback и «сырые» IP-кадры; IPv4, IPv6 с заголовками расширения; TCP, UDP, ICMP
// и имя DNS-запроса.

import { formatIPv6 } from './net.js';
import { PROTO } from './trace.js';

export const SUPPORTED_LINKTYPES = new Set([0, 1, 12, 14, 101, 108, 113, 228, 229, 276]);

export function decodePacket(link, b, off, caplen, out) {
  const end = off + caplen;
  let p = off;
  let et = -1;
  switch (link) {
    case 1:
      if (caplen < 14) return false;
      et = (b[p + 12] << 8) | b[p + 13];
      p += 14;
      while ((et === 0x8100 || et === 0x88a8 || et === 0x9100) && p + 4 <= end) {
        et = (b[p + 2] << 8) | b[p + 3];
        p += 4;
      }
      break;
    case 113:
      if (caplen < 16) return false;
      et = (b[p + 14] << 8) | b[p + 15];
      p += 16;
      break;
    case 276:
      if (caplen < 20) return false;
      et = (b[p] << 8) | b[p + 1];
      p += 20;
      break;
    case 0:
    case 108: {
      if (caplen < 4) return false;
      const le = b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24);
      const be = (b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3];
      const fam = le > 0 && le < 256 ? le : be;
      if (fam === 2) et = 0x0800;
      else if (fam === 24 || fam === 28 || fam === 30) et = 0x86dd;
      p += 4;
      break;
    }
    case 12:
    case 14:
    case 101:
    case 228:
    case 229: {
      if (caplen < 1) return false;
      const v = b[p] >> 4;
      et = v === 4 ? 0x0800 : v === 6 ? 0x86dd : -1;
      break;
    }
    default:
      return false;
  }
  if (et === 0x0800) return decodeIPv4(b, p, end, out);
  if (et === 0x86dd) return decodeIPv6(b, p, end, out);
  return false;
}

function decodeIPv4(b, p, end, out) {
  if (p + 20 > end || b[p] >> 4 !== 4) return false;
  const ihl = (b[p] & 15) * 4;
  if (ihl < 20) return false;
  const proto = b[p + 9];
  const fragOffset = ((b[p + 6] & 0x1f) << 8) | b[p + 7];
  out.v6 = false;
  out.src4 = ((b[p + 12] << 24) | (b[p + 13] << 16) | (b[p + 14] << 8) | b[p + 15]) >>> 0;
  out.dst4 = ((b[p + 16] << 24) | (b[p + 17] << 16) | (b[p + 18] << 8) | b[p + 19]) >>> 0;
  return decodeL4(b, p + ihl, end, proto, fragOffset !== 0, out);
}

function decodeIPv6(b, p, end, out) {
  if (p + 40 > end || b[p] >> 4 !== 6) return false;
  let nh = b[p + 6];
  out.v6 = true;
  out.src = formatIPv6(b, p + 8);
  out.dst = formatIPv6(b, p + 24);
  let q = p + 40;
  let frag = false;
  for (let guard = 0; guard < 8 && q + 8 <= end; guard++) {
    if (nh === 0 || nh === 43 || nh === 60) {
      const next = b[q];
      q += (b[q + 1] + 1) * 8;
      nh = next;
    } else if (nh === 44) {
      const next = b[q];
      frag = (((b[q + 2] << 8) | b[q + 3]) >> 3) !== 0;
      q += 8;
      nh = next;
    } else if (nh === 51) {
      const next = b[q];
      q += (b[q + 1] + 2) * 4;
      nh = next;
    } else {
      break;
    }
  }
  return decodeL4(b, q, end, nh, frag, out);
}

function decodeL4(b, p, end, proto, isFrag, out) {
  out.sp = 0;
  out.dp = 0;
  out.flags = 0;
  out.q = null;
  if (proto === 6) {
    out.proto = PROTO.TCP;
    if (!isFrag && p + 14 <= end) {
      out.sp = (b[p] << 8) | b[p + 1];
      out.dp = (b[p + 2] << 8) | b[p + 3];
      out.flags = b[p + 13] & 0x3f;
    }
  } else if (proto === 17) {
    out.proto = PROTO.UDP;
    if (!isFrag && p + 8 <= end) {
      out.sp = (b[p] << 8) | b[p + 1];
      out.dp = (b[p + 2] << 8) | b[p + 3];
      if (out.dp === 53) out.q = parseDnsQuery(b, p + 8, end);
    }
  } else if (proto === 1 || proto === 58) {
    out.proto = PROTO.ICMP;
    if (p < end) {
      const type = b[p];
      // ICMPv6 echo request/reply приводятся к кодам ICMPv4 (8 и 0).
      out.flags = proto === 58 ? (type === 128 ? 8 : type === 129 ? 0 : type) : type;
    }
  } else {
    out.proto = PROTO.OTHER;
  }
  return true;
}

export function parseDnsQuery(b, p, end) {
  if (p + 12 > end) return null;
  if (b[p + 2] & 0x80) return null;
  const qd = (b[p + 4] << 8) | b[p + 5];
  if (qd < 1) return null;
  let i = p + 12;
  let total = 0;
  const labels = [];
  while (i < end) {
    const l = b[i];
    if (l === 0) break;
    if ((l & 0xc0) !== 0 || i + 1 + l > end) return null;
    let s = '';
    for (let k = 0; k < l; k++) s += String.fromCharCode(b[i + 1 + k]);
    labels.push(s);
    total += l + 1;
    if (total > 255) return null;
    i += 1 + l;
  }
  return labels.length ? labels.join('.').toLowerCase() : null;
}
