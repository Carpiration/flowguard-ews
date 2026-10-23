// Потоковое чтение PCAP и PCAPNG: файл читается частями, поэтому большие
// захваты не требуют загрузки целиком в память.

import { decodePacket, SUPPORTED_LINKTYPES } from './decode.js';
import { FormatError } from './errors.js';

export class BlobReader {
  constructor(blob, chunkSize = 8 << 20) {
    this.blob = blob;
    this.chunkSize = chunkSize;
    this.offset = 0;
    this.buf = new Uint8Array(0);
    this.dv = new DataView(this.buf.buffer);
    this.pos = 0;
    this.end = 0;
  }

  async more() {
    if (this.offset >= this.blob.size) return false;
    const next = new Uint8Array(await this.blob.slice(this.offset, this.offset + this.chunkSize).arrayBuffer());
    this.offset += next.length;
    const rest = this.end - this.pos;
    const merged = new Uint8Array(rest + next.length);
    merged.set(this.buf.subarray(this.pos, this.end), 0);
    merged.set(next, rest);
    this.buf = merged;
    this.dv = new DataView(merged.buffer);
    this.pos = 0;
    this.end = merged.length;
    return true;
  }

  async ensure(n) {
    while (this.end - this.pos < n) {
      if (!(await this.more())) return false;
    }
    return true;
  }

  progress() {
    if (!this.blob.size) return 1;
    return (this.offset - (this.end - this.pos)) / this.blob.size;
  }
}

function linkError(link) {
  return new FormatError(
    `Тип канального уровня ${link} не поддерживается. Поддерживаются Ethernet, Linux SLL/SLL2, loopback и raw IP.`,
  );
}

export async function parsePcap(reader, builder, onProgress) {
  if (!(await reader.ensure(24))) throw new FormatError('Файл PCAP повреждён: отсутствует глобальный заголовок.');
  const magic = reader.dv.getUint32(reader.pos, false);
  let le;
  let nano;
  if (magic === 0xa1b2c3d4) [le, nano] = [false, false];
  else if (magic === 0xd4c3b2a1) [le, nano] = [true, false];
  else if (magic === 0xa1b23c4d) [le, nano] = [false, true];
  else if (magic === 0x4d3cb2a1) [le, nano] = [true, true];
  else throw new FormatError('Неизвестная сигнатура PCAP.');
  const link = reader.dv.getUint32(reader.pos + 20, le) & 0x0fffffff;
  if (!SUPPORTED_LINKTYPES.has(link)) throw linkError(link);
  reader.pos += 24;
  const div = nano ? 1e9 : 1e6;
  const out = {};
  for (;;) {
    const b = reader.buf;
    const dv = reader.dv;
    const end = reader.end;
    let p = reader.pos;
    while (p + 16 <= end) {
      const sec = dv.getUint32(p, le);
      const frac = dv.getUint32(p + 4, le);
      const incl = dv.getUint32(p + 8, le);
      const orig = dv.getUint32(p + 12, le);
      if (incl > 0x4000000) throw new FormatError(`Повреждённая запись пакета: длина ${incl} байт.`);
      if (p + 16 + incl > end) break;
      if (decodePacket(link, b, p + 16, incl, out)) builder.pushDecoded(sec + frac / div, out, orig || incl);
      else builder.skipped++;
      p += 16 + incl;
    }
    reader.pos = p;
    onProgress?.(reader.progress());
    if (!(await reader.more())) break;
  }
  if (reader.end - reader.pos > 0) builder.notes.push('Последняя запись файла обрезана и пропущена.');
}

export async function parsePcapng(reader, builder, onProgress) {
  let le = true;
  let ifaces = [];
  let lastTs = 0;
  const out = {};
  for (;;) {
    const b = reader.buf;
    const dv = reader.dv;
    const end = reader.end;
    let p = reader.pos;
    while (p + 12 <= end) {
      const type = dv.getUint32(p, le);
      if (type === 0x0a0d0d0a) {
        const bomLe = dv.getUint32(p + 8, true);
        if (bomLe === 0x1a2b3c4d) le = true;
        else if (dv.getUint32(p + 8, false) === 0x1a2b3c4d) le = false;
        else throw new FormatError('Повреждённый заголовок секции PCAPNG.');
        ifaces = [];
      }
      const blen = dv.getUint32(p + 4, le);
      if (blen < 12 || blen % 4 !== 0 || blen > 0x8000000) {
        throw new FormatError('Повреждённый блок PCAPNG: недопустимая длина.');
      }
      if (p + blen > end) break;
      if (type === 1) {
        const link = dv.getUint16(p + 8, le);
        let res = 1e-6;
        let tsoff = 0;
        let o = p + 16;
        const oe = p + blen - 4;
        while (o + 4 <= oe) {
          const code = dv.getUint16(o, le);
          const olen = dv.getUint16(o + 2, le);
          if (code === 0) break;
          if (code === 9 && olen >= 1) {
            const v = b[o + 4];
            res = v & 0x80 ? Math.pow(2, -(v & 0x7f)) : Math.pow(10, -v);
          } else if (code === 14 && olen === 8) {
            const hi = dv.getUint32(o + 4, le);
            const lo = dv.getUint32(o + 8, le);
            tsoff = le ? lo * 4294967296 + hi : hi * 4294967296 + lo;
          }
          o += 4 + ((olen + 3) & ~3);
        }
        ifaces.push({ link, res, tsoff, ok: SUPPORTED_LINKTYPES.has(link) });
      } else if (type === 6 || type === 2) {
        const id = type === 6 ? dv.getUint32(p + 8, le) : dv.getUint16(p + 8, le);
        const hi = dv.getUint32(p + 12, le);
        const lo = dv.getUint32(p + 16, le);
        const cap = dv.getUint32(p + 20, le);
        const orig = dv.getUint32(p + 24, le);
        const ifc = ifaces[id];
        if (ifc && ifc.ok && 28 + cap <= blen) {
          const ts = (hi * 4294967296 + lo) * ifc.res + ifc.tsoff;
          lastTs = ts;
          if (decodePacket(ifc.link, b, p + 28, cap, out)) builder.pushDecoded(ts, out, orig || cap);
          else builder.skipped++;
        } else {
          builder.skipped++;
        }
      } else if (type === 3) {
        const ifc = ifaces[0];
        const orig = dv.getUint32(p + 8, le);
        const cap = Math.min(orig, blen - 16);
        if (ifc && ifc.ok && decodePacket(ifc.link, b, p + 12, cap, out)) builder.pushDecoded(lastTs, out, orig);
        else builder.skipped++;
      }
      p += blen;
    }
    reader.pos = p;
    onProgress?.(reader.progress());
    if (!(await reader.more())) break;
  }
  if (!ifaces.length && builder.length === 0) throw new FormatError('В файле PCAPNG нет описаний интерфейсов.');
  if (ifaces.length && ifaces.every((i) => !i.ok)) throw linkError(ifaces[0].link);
  if (reader.end - reader.pos > 0) builder.notes.push('Последний блок файла обрезан и пропущен.');
}
