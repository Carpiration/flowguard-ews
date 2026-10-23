// Колоночное хранилище сетевых событий. Пакеты и сетевые потоки хранятся
// в типизированных массивах, поэтому файлы на миллионы пакетов помещаются в память.

import { formatIPv4, makeInternalMatcher } from './net.js';

export const PROTO = Object.freeze({ OTHER: 0, TCP: 1, UDP: 2, ICMP: 3 });
export const PROTO_NAMES = ['Другое', 'TCP', 'UDP', 'ICMP'];
export const TCPF = Object.freeze({ FIN: 1, SYN: 2, RST: 4, PSH: 8, ACK: 16, URG: 32 });
// Служебный бит: запись потока в направлении инициатора соединения.
export const FLOW_ORIG = 0x100;

export class HostTable {
  constructor(isInternal = makeInternalMatcher()) {
    this.isInternalFn = isInternal;
    this.names = [];
    this.internal = [];
    this.index = new Map();
    this.v4 = new Map();
  }

  get size() {
    return this.names.length;
  }

  id(name) {
    let id = this.index.get(name);
    if (id === undefined) {
      id = this.names.length;
      this.names.push(name);
      this.index.set(name, id);
      this.internal.push(this.isInternalFn(name) ? 1 : 0);
    }
    return id;
  }

  idV4(n) {
    let id = this.v4.get(n);
    if (id === undefined) {
      id = this.id(formatIPv4(n));
      this.v4.set(n, id);
    }
    return id;
  }

  name(id) {
    return id < 0 ? '—' : this.names[id];
  }
}

class StringTable {
  constructor() {
    this.names = [];
    this.index = new Map();
  }

  id(s) {
    let id = this.index.get(s);
    if (id === undefined) {
      id = this.names.length;
      this.names.push(s);
      this.index.set(s, id);
    }
    return id;
  }
}

export class TraceBuilder {
  constructor({ internal } = {}) {
    this.hosts = new HostTable(makeInternalMatcher(internal));
    this.strings = new StringTable();
    this.labelTable = new StringTable();
    this.length = 0;
    this.cap = 0;
    this.flowMode = false;
    this.labelled = false;
    this.syntheticTime = false;
    this.skipped = 0;
    this.notes = [];
    this.grow(1 << 14);
  }

  grow(min) {
    const cap = Math.max(min, this.cap * 2);
    const re = (Ctor, old) => {
      const a = new Ctor(cap);
      if (old) a.set(old.subarray(0, this.length));
      return a;
    };
    this.t = re(Float64Array, this.t);
    this.src = re(Uint32Array, this.src);
    this.dst = re(Uint32Array, this.dst);
    this.sp = re(Uint16Array, this.sp);
    this.dp = re(Uint16Array, this.dp);
    this.proto = re(Uint8Array, this.proto);
    this.flags = re(Uint16Array, this.flags);
    this.len = re(Float64Array, this.len);
    this.n = re(Uint32Array, this.n);
    this.q = re(Int32Array, this.q);
    this.label = re(Int32Array, this.label);
    this.cap = cap;
  }

  pushIds(t, src, dst, sp, dp, proto, len, flags, n, q, label) {
    if (this.length === this.cap) this.grow(this.length + 1);
    const i = this.length++;
    this.t[i] = t;
    this.src[i] = src;
    this.dst[i] = dst;
    this.sp[i] = sp;
    this.dp[i] = dp;
    this.proto[i] = proto;
    this.flags[i] = flags;
    this.len[i] = len;
    this.n[i] = n;
    this.q[i] = q ? this.strings.id(q) : -1;
    this.label[i] = label ? this.labelTable.id(label) : -1;
  }

  push(t, src, dst, sp, dp, proto, len, flags = 0, n = 1, q = null, label = null) {
    this.pushIds(t, this.hosts.id(src), this.hosts.id(dst), sp, dp, proto, len, flags, n, q, label);
  }

  pushDecoded(t, d, len) {
    const src = d.v6 ? this.hosts.id(d.src) : this.hosts.idV4(d.src4);
    const dst = d.v6 ? this.hosts.id(d.dst) : this.hosts.idV4(d.dst4);
    this.pushIds(t, src, dst, d.sp, d.dp, d.proto, len, d.flags, 1, d.q, null);
  }

  finish() {
    const n = this.length;
    return {
      length: n,
      t: this.t.subarray(0, n),
      src: this.src.subarray(0, n),
      dst: this.dst.subarray(0, n),
      sp: this.sp.subarray(0, n),
      dp: this.dp.subarray(0, n),
      proto: this.proto.subarray(0, n),
      flags: this.flags.subarray(0, n),
      len: this.len.subarray(0, n),
      n: this.n.subarray(0, n),
      q: this.q.subarray(0, n),
      label: this.label.subarray(0, n),
      hosts: this.hosts,
      strings: this.strings.names,
      labels: this.labelTable.names,
      flowMode: this.flowMode,
      labelled: this.labelled,
      syntheticTime: this.syntheticTime,
      skipped: this.skipped,
      notes: this.notes,
    };
  }
}
