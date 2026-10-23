"""Генерация демонстрационных файлов для FlowGuard (только стандартная библиотека).

Запуск из корня проекта:  python scripts/make_samples.py

Реализация намеренно независима от JavaScript-кода приложения: файлы служат
перекрёстной проверкой разборщиков PCAP/PCAPNG/CSV/NDJSON/tcpdump. Внешние
адреса взяты из документационных диапазонов RFC 5737.
"""

from __future__ import annotations

import csv
import datetime as dt
import json
import pathlib
import random
import struct

OUT = pathlib.Path(__file__).resolve().parent.parent / "samples"
BASE = dt.datetime(2026, 10, 1, 7, 0, tzinfo=dt.timezone.utc).timestamp()
SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08
TCP, UDP, ICMP = 6, 17, 1

WS = [f"10.0.1.{i}" for i in range(10, 26)]
EXT = [f"203.0.113.{i}" for i in range(20, 50)] + [f"198.51.100.{i}" for i in range(20, 40)]
DNS_SERVER = "10.0.0.53"
DOMAINS = ["example.com", "example.net", "example.org", "cdn.example", "mail.example"]


class Capture:
    def __init__(self, seed: int) -> None:
        self.r = random.Random(seed)
        self.packets: list[tuple] = []

    def add(self, t, src, dst, sport, dport, proto, length, flags=0, qname=None):
        self.packets.append((t, src, dst, sport, dport, proto, length, flags, qname))

    def eph(self) -> int:
        return self.r.randint(49152, 65000)

    def tcp(self, t, c, s, dport, req=500, resp=6000, rtt=0.03):
        cp = self.eph()
        self.add(t, c, s, cp, dport, TCP, 66, SYN)
        self.add(t + rtt, s, c, dport, cp, TCP, 66, SYN | ACK)
        self.add(t + rtt * 1.5, c, s, cp, dport, TCP, 54, ACK)
        self.add(t + rtt * 1.6, c, s, cp, dport, TCP, 54 + min(req, 1400), PSH | ACK)
        x = t + rtt * 2.6
        for k in range(max(1, resp // 1448)):
            x += rtt / 6
            self.add(x, s, c, dport, cp, TCP, 1514, ACK)
            if k % 2:
                self.add(x + 0.0002, c, s, cp, dport, TCP, 54, ACK)
        self.add(x + 0.05, c, s, cp, dport, TCP, 54, FIN | ACK)
        self.add(x + 0.05 + rtt, s, c, dport, cp, TCP, 54, FIN | ACK)

    def dns(self, t, c, name):
        sp = self.eph()
        self.add(t, c, DNS_SERVER, sp, 53, UDP, 70 + len(name), 0, name)
        self.add(t + 0.004, DNS_SERVER, c, 53, sp, UDP, 180)

    def background(self, t0, t1, rate=1.0):
        t = t0
        while True:
            t += self.r.expovariate(rate)
            if t >= t1:
                break
            c = self.r.choice(WS)
            if self.r.random() < 0.6:
                self.dns(t - 0.03, c, f"www.{self.r.choice(DOMAINS)}")
            self.tcp(t, c, self.r.choice(EXT), 443, self.r.randint(200, 1200), int(self.r.lognormvariate(9.2, 0.9)), self.r.uniform(0.02, 0.07))

    def portscan(self, t0, attacker, target, count, rate):
        ports = list(range(1, 1025))
        self.r.shuffle(ports)
        for i, p in enumerate(ports[:count]):
            t = t0 + i / rate
            sp = self.eph()
            self.add(t, attacker, target, sp, p, TCP, 58, SYN)
            self.add(t + 0.0005, target, attacker, p, sp, TCP, 54, RST | ACK)

    def bruteforce(self, t0, attacker, target, count):
        for i in range(count):
            self.tcp(t0 + i * 0.75, attacker, target, 22, 900, 1500, 0.04)

    def exfil(self, t0, host, drop, seconds, rate_bytes):
        cp = self.eph()
        self.tcp(t0, host, drop, 443, 600, 3000, 0.05)
        n = int(seconds * rate_bytes / 1460)
        for i in range(n):
            t = t0 + 0.3 + i * seconds / n
            self.add(t, host, drop, cp, 443, TCP, 1514, ACK)
            if i % 2:
                self.add(t + 0.03, drop, host, 443, cp, TCP, 54, ACK)

    def tunnel(self, t0, host, seconds, rate):
        alphabet = "abcdefghijklmnopqrstuvwxyz234567"
        for i in range(int(seconds * rate)):
            label = "".join(self.r.choice(alphabet) for _ in range(self.r.randint(32, 44)))
            self.dns(t0 + i / rate, host, f"{label}.{i:x}.d.sync-tunnel.example")

    def beacon(self, t0, host, c2, period, count):
        for i in range(count):
            self.tcp(t0 + i * period + self.r.uniform(-0.25, 0.25), host, c2, 8443, 250, 200, 0.06)

    def sorted(self):
        return sorted(self.packets, key=lambda p: p[0])


def ip_bytes(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def ip_checksum(header: bytes) -> int:
    s = sum(struct.unpack("!10H", header))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def frame(p) -> tuple[bytes, int]:
    _, src, dst, sport, dport, proto, length, flags, qname = p
    if proto == TCP:
        l4 = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 64240, 0, 0)
    elif proto == UDP:
        payload = b""
        if qname:
            payload = struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0)
            for label in qname.split("."):
                payload += bytes([len(label)]) + label.encode("ascii")
            payload += b"\x00\x00\x01\x00\x01"
        l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    else:
        l4 = struct.pack("!BBHHH", flags, 0, 0, 1, 1)
    total = max(length - 14, 20 + len(l4))
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, proto, 0, ip_bytes(src), ip_bytes(dst))
    ip = ip[:10] + struct.pack("!H", ip_checksum(ip)) + ip[12:]
    eth = b"\x02\x00" + ip_bytes(dst) + b"\x02\x00" + ip_bytes(src) + b"\x08\x00"
    data = eth + ip + l4
    return data, max(length, len(data))


def write_pcap(path: pathlib.Path, packets) -> None:
    with path.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for p in packets:
            data, orig = frame(p)
            t = BASE + p[0]
            sec = int(t)
            usec = int(round((t - sec) * 1e6))
            if usec >= 1_000_000:
                sec, usec = sec + 1, 0
            f.write(struct.pack("<IIII", sec, usec, len(data), orig))
            f.write(data)


def write_pcapng(path: pathlib.Path, packets) -> None:
    def block(btype: int, body: bytes) -> bytes:
        body += b"\x00" * (-len(body) % 4)
        length = 12 + len(body)
        return struct.pack("<II", btype, length) + body + struct.pack("<I", length)

    with path.open("wb") as f:
        f.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        # if_tsresol = 9: метки времени в наносекундах.
        options = struct.pack("<HHB", 9, 1, 9) + b"\x00" * 3 + struct.pack("<HH", 0, 0)
        f.write(block(1, struct.pack("<HHI", 1, 0, 65535) + options))
        for p in packets:
            data, orig = frame(p)
            ts = int(round((BASE + p[0]) * 1e9))
            body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(data), orig) + data
            f.write(block(6, body))


def write_tcpdump(path: pathlib.Path, packets) -> None:
    names = {SYN: "S", SYN | ACK: "S.", ACK: ".", RST | ACK: "R.", FIN | ACK: "F.", PSH | ACK: "P."}
    lines = []
    for t, src, dst, sp, dp, proto, length, flags, qname in packets:
        clock = dt.datetime.fromtimestamp(BASE + t, dt.timezone.utc).strftime("%H:%M:%S.%f")
        if proto == TCP:
            lines.append(f"{clock} IP {src}.{sp} > {dst}.{dp}: Flags [{names.get(flags, '.')}], seq 1, win 64240, length {max(0, length - 54)}")
        elif proto == UDP and qname:
            lines.append(f"{clock} IP {src}.{sp} > {dst}.{dp}: 4242+ A? {qname}. ({len(qname) + 18})")
        elif proto == UDP:
            lines.append(f"{clock} IP {src}.{sp} > {dst}.{dp}: UDP, length {max(0, length - 42)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def zeek_flows(seed: int) -> list[dict]:
    r = random.Random(seed)
    rows = []

    def flow(t, oh, op, rh, rp, proto, state, ob, rb, opk, rpk, label="-"):
        rows.append({
            "ts": f"{BASE + t:.6f}", "uid": f"C{len(rows):07d}", "id.orig_h": oh, "id.orig_p": op,
            "id.resp_h": rh, "id.resp_p": rp, "proto": proto, "duration": f"{r.uniform(0.01, 3):.3f}",
            "orig_bytes": ob, "resp_bytes": rb, "conn_state": state, "orig_pkts": opk, "resp_pkts": rpk, "label": label,
        })

    t = 0.0
    while t < 1500:
        t += r.expovariate(1.5)
        c = r.choice(WS)
        flow(t, c, r.randint(49152, 65000), r.choice(EXT), 443, "tcp", "SF", r.randint(300, 2000), r.randint(2000, 90000), r.randint(4, 12), r.randint(4, 70))
        if r.random() < 0.5:
            flow(t - 0.02, c, r.randint(49152, 65000), DNS_SERVER, 53, "udp", "SF", 40, 120, 1, 1)
    for i in range(400):
        flow(400 + i * 0.3, "10.0.1.66", r.randint(40000, 60000), "10.0.0.10", i + 1, "tcp", "REJ" if i % 9 else "S0", 0, 0, 1, 1 if i % 9 else 0, "PortScan")
    for i in range(160):
        flow(900 + i * 0.6, "203.0.113.77", r.randint(40000, 60000), "10.0.0.5", 22, "tcp", "SF", 1200, 2100, 12, 10, "SSH-Patator")
    rows.sort(key=lambda x: float(x["ts"]))
    return rows


def suricata_events(seed: int) -> list[dict]:
    r = random.Random(seed)
    events = []

    def iso(t):
        return dt.datetime.fromtimestamp(BASE + t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")

    def flow(t, src, sp, dst, dp, proto, to_server, to_client, p_server, p_client):
        events.append({
            "timestamp": iso(t), "event_type": "flow", "src_ip": src, "src_port": sp, "dest_ip": dst, "dest_port": dp,
            "proto": proto, "flow": {"pkts_toserver": p_server, "pkts_toclient": p_client, "bytes_toserver": to_server, "bytes_toclient": to_client},
        })

    t = 0.0
    while t < 1200:
        t += r.expovariate(1.2)
        flow(t, r.choice(WS), r.randint(49152, 65000), r.choice(EXT), 443, "TCP", r.randint(300, 2500), r.randint(3000, 120000), r.randint(4, 12), r.randint(4, 90))
    for i in range(24):
        flow(700 + i * 5, "10.0.1.23", 51000 + i, "198.51.100.200", 443, "TCP", 2_400_000, 40_000, 1700, 600)
    events.sort(key=lambda e: e["timestamp"])
    return events


def main() -> None:
    OUT.mkdir(exist_ok=True)

    office = Capture(2026)
    office.background(0, 900, 1.1)
    office.portscan(240, "10.0.1.66", "10.0.0.10", 300, 3.0)
    office.bruteforce(480, "203.0.113.77", "10.0.0.5", 110)
    office.exfil(660, "10.0.1.23", "198.51.100.200", 90, 180_000)
    write_pcap(OUT / "office-attacks.pcap", office.sorted())

    covert = Capture(77)
    covert.background(0, 900, 1.0)
    covert.beacon(120, "10.0.1.17", "203.0.113.45", 30.0, 22)
    covert.tunnel(500, "10.0.1.31", 90, 4.0)
    write_pcapng(OUT / "covert-channels.pcapng", covert.sorted())

    quick = Capture(5)
    quick.background(0, 240, 0.8)
    quick.portscan(100, "10.0.1.66", "10.0.0.10", 120, 6.0)
    write_tcpdump(OUT / "tcpdump-scan.txt", quick.sorted())

    rows = zeek_flows(11)
    with (OUT / "zeek-conn-labeled.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    with (OUT / "suricata-eve.ndjson").open("w", encoding="utf-8") as f:
        for e in suricata_events(19):
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    for p in sorted(OUT.iterdir()):
        print(f"{p.name:28s} {p.stat().st_size / 1024:8.1f} КБ")


if __name__ == "__main__":
    main()
