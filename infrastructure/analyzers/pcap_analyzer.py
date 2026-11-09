"""Dependency-free PCAP (network capture) analyzer.

Parses the classic libpcap format (``.pcap``) with the standard library only — no scapy/tshark — so it
runs anywhere. It reads Ethernet / raw-IP → IPv4 → TCP/UDP/ICMP, aggregates talkers, ports, protocols
and DNS queries, and flags a few things a reviewer cares about: cleartext HTTP, DNS lookups, and a
simple horizontal-port-scan heuristic (one source touching many destination ports).

It only reads the capture file; it never replays traffic. pcapng (the newer format) is detected and
reported as unsupported rather than mis-parsed. Truncated/odd records are skipped defensively.
"""
from __future__ import annotations

import socket
import struct
from collections import Counter
from pathlib import Path
from typing import Any, Optional

PCAP_MAGIC_BE = 0xA1B2C3D4
PCAP_MAGIC_LE = 0xD4C3B2A1
PCAPNG_MAGIC = 0x0A0D0D0A
MAX_PACKETS = 500_000           # safety cap


class PcapError(ValueError):
    pass


def _ip(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def _dns_qname(payload: bytes) -> Optional[str]:
    """First question name from a DNS message (payload after the UDP header), or None."""
    if len(payload) < 13:
        return None
    labels, i = [], 12                      # skip the 12-byte DNS header
    try:
        for _ in range(64):
            length = payload[i]
            if length == 0:
                break
            if length & 0xC0:               # compression pointer — stop (rare in a question)
                return None
            labels.append(payload[i + 1:i + 1 + length].decode("ascii", "replace"))
            i += 1 + length
    except IndexError:
        return None
    return ".".join(labels) or None


def _parse_packet(data: bytes, linktype: int, ctx: dict) -> None:
    # link layer → IPv4 payload
    if linktype == 1:                       # Ethernet
        if len(data) < 14 or data[12:14] != b"\x08\x00":
            return
        ip = data[14:]
    elif linktype in (101, 12, 14):         # raw IP
        ip = data
    else:
        return
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    src, dst = _ip(ip[12:16]), _ip(ip[16:20])
    ctx["talkers"][f"{src} -> {dst}"] += 1
    seg = ip[ihl:]
    if proto == 6 and len(seg) >= 14:       # TCP
        ctx["proto"]["TCP"] += 1
        sport, dport = struct.unpack(">HH", seg[0:4])
        flags = seg[13]
        ctx["dports"][dport] += 1
        if flags & 0x02 and not flags & 0x10:   # SYN without ACK → connection attempt
            ctx["syn_targets"].setdefault(src, set()).add(dport)
        payload = seg[(seg[12] >> 4) * 4:]
        if dport == 80 and payload[:4] in (b"GET ", b"POST", b"HEAD", b"PUT "):
            ctx["http"].add(f"{src} -> {dst}:80")
    elif proto == 17 and len(seg) >= 8:     # UDP
        ctx["proto"]["UDP"] += 1
        sport, dport = struct.unpack(">HH", seg[0:4])
        ctx["dports"][dport] += 1
        if 53 in (sport, dport):
            name = _dns_qname(seg[8:])
            if name:
                ctx["dns"][name] += 1
    elif proto == 1:                        # ICMP
        ctx["proto"]["ICMP"] += 1
    else:
        ctx["proto"]["other"] += 1


def analyze(path: str) -> dict[str, Any]:
    """Parse a classic .pcap file and return an aggregated summary with findings."""
    blob = Path(path).expanduser().read_bytes()
    if len(blob) < 24:
        raise PcapError("file too small to be a pcap")
    magic = struct.unpack(">I", blob[:4])[0]
    if magic == PCAPNG_MAGIC:
        raise PcapError("pcapng format is not supported; convert to classic pcap (e.g. editcap/tshark)")
    if magic == PCAP_MAGIC_BE:
        endian = ">"
    elif magic == PCAP_MAGIC_LE:
        endian = "<"
    else:
        raise PcapError("not a pcap file (bad magic)")
    linktype = struct.unpack(endian + "I", blob[20:24])[0]

    ctx = {"proto": Counter(), "talkers": Counter(), "dports": Counter(), "dns": Counter(),
           "http": set(), "syn_targets": {}}
    packets = total_bytes = 0
    off = 24
    while off + 16 <= len(blob) and packets < MAX_PACKETS:
        _ts, _tu, incl, orig = struct.unpack(endian + "IIII", blob[off:off + 16])
        off += 16
        if incl == 0 or off + incl > len(blob):
            break
        _parse_packet(blob[off:off + incl], linktype, ctx)
        off += incl
        packets += 1
        total_bytes += orig

    findings = []
    for src, ports in ctx["syn_targets"].items():
        if len(ports) >= 20:
            findings.append({"severity": "medium", "title": f"Possible port scan from {src} "
                             f"({len(ports)} destination ports)", "owasp": "A00"})
    if ctx["http"]:
        findings.append({"severity": "low", "title": f"Cleartext HTTP traffic ({len(ctx['http'])} flow(s))",
                         "owasp": "A02"})

    return {
        "file": str(Path(path)), "packets": packets, "bytes": total_bytes, "linktype": linktype,
        "protocols": dict(ctx["proto"]),
        "top_talkers": ctx["talkers"].most_common(10),
        "top_ports": ctx["dports"].most_common(10),
        "dns_queries": ctx["dns"].most_common(20),
        "findings": findings,
    }


def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        prog="cybrix-pcap", description="Analyze a classic .pcap capture (local, read-only).")
    parser.add_argument("file", help="path to a .pcap file")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = parser.parse_args(argv)

    if not Path(args.file).expanduser().is_file():
        print(f"[!] no such file: {args.file}", file=sys.stderr)
        return 2
    try:
        result = analyze(args.file)
    except PcapError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"[*] {result['packets']} packets, {result['bytes']} bytes — protocols {result['protocols']}")
        if result["top_talkers"]:
            print("  top talkers:")
            for pair, n in result["top_talkers"][:5]:
                print(f"    {n:>6}  {pair}")
        if result["dns_queries"]:
            print("  DNS queries: " + ", ".join(f"{q}({n})" for q, n in result["dns_queries"][:8]))
        for f in result["findings"]:
            print(f"  [!] [{f['severity']}] {f['title']}")
        print(f"[+] {len(result['findings'])} finding(s)")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
