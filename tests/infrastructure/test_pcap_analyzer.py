"""Dependency-free PCAP analyzer: parsing, aggregation, findings, error handling, CLI."""
from __future__ import annotations

import socket
import struct

import pytest

from infrastructure.analyzers import pcap_analyzer as P


# ── tiny pcap builders (Ethernet/IPv4) ───────────────────────────────────────
def _eth_ip(proto: int, src: str, dst: str, l4: bytes) -> bytes:
    ip = bytes([0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0]) + socket.inet_aton(src) + socket.inet_aton(dst) + l4
    ip = ip[:2] + struct.pack(">H", len(ip)) + ip[4:]
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip


def _tcp(sp: int, dp: int, flags: int, payload: bytes = b"") -> bytes:
    return struct.pack(">HHIIBBHHH", sp, dp, 0, 0, 0x50, flags, 0, 0, 0) + payload


def _udp(sp: int, dp: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sp, dp, 8 + len(payload), 0) + payload


def _dns_q(name: str) -> bytes:
    q = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00\x00\x01\x00\x01"
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + q


def _write_pcap(path, packets, little=True) -> None:
    endian = "<" if little else ">"
    out = struct.pack(endian + "IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)      # linktype 1 = Ethernet
    for d in packets:
        out += struct.pack(endian + "IIII", 0, 0, len(d), len(d)) + d
    path.write_bytes(out)


def _lab_pcap(path):
    pkts = [_eth_ip(6, "10.0.0.5", "10.0.0.9", _tcp(44000, 80, 0x02, b"GET / HTTP/1.1")),
            _eth_ip(17, "10.0.0.5", "10.0.0.1", _udp(55000, 53, _dns_q("example.com")))]
    pkts += [_eth_ip(6, "10.0.0.5", "10.0.0.9", _tcp(40000 + p, p, 0x02)) for p in range(1, 26)]
    _write_pcap(path, pkts)
    return path


def test_basic_aggregation(tmp_path):
    r = P.analyze(str(_lab_pcap(tmp_path / "c.pcap")))
    assert r["packets"] == 27
    assert r["protocols"]["TCP"] == 26 and r["protocols"]["UDP"] == 1
    assert r["top_talkers"][0][0] == "10.0.0.5 -> 10.0.0.9"


def test_dns_extraction(tmp_path):
    r = P.analyze(str(_lab_pcap(tmp_path / "c.pcap")))
    assert ("example.com", 1) in r["dns_queries"]


def test_findings_portscan_and_http(tmp_path):
    r = P.analyze(str(_lab_pcap(tmp_path / "c.pcap")))
    titles = " ".join(f["title"] for f in r["findings"])
    assert "port scan" in titles and "Cleartext HTTP" in titles


def test_big_endian_pcap(tmp_path):
    f = tmp_path / "be.pcap"
    _write_pcap(f, [_eth_ip(6, "10.0.0.5", "10.0.0.9", _tcp(1, 80, 0x02))], little=False)
    assert P.analyze(str(f))["packets"] == 1


def test_pcapng_unsupported(tmp_path):
    f = tmp_path / "ng.pcapng"
    f.write_bytes(struct.pack(">I", P.PCAPNG_MAGIC) + b"\x00" * 40)
    with pytest.raises(P.PcapError):
        P.analyze(str(f))


def test_bad_magic(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"\x00" * 40)
    with pytest.raises(P.PcapError):
        P.analyze(str(f))


def test_cli(tmp_path, capsys):
    assert P.main([str(_lab_pcap(tmp_path / "c.pcap"))]) == 0
    out = capsys.readouterr().out
    assert "packets" in out and "finding(s)" in out


def test_cli_missing_file(tmp_path):
    assert P.main([str(tmp_path / "nope.pcap")]) == 2
