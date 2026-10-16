import socket
from collections import namedtuple
from unittest.mock import AsyncMock, MagicMock, patch

import psutil

from application.services.netflow_service import RESEND_AFTER, NetflowService, NetworkFlowCollector
from domain.interfaces.backend import ConnectionState
from infrastructure.remote.agent_settings import AgentSettings
from infrastructure.remote.audit_log import AgentAuditLog

from backend_fakes import RecordingBus, make_config

Addr = namedtuple("Addr", "ip port")
Conn = namedtuple("Conn", "fd family type laddr raddr status pid")


def conn(rip, rport, status=psutil.CONN_ESTABLISHED, pid=None, kind=socket.SOCK_STREAM):
    return Conn(-1, socket.AF_INET, kind, Addr("192.168.1.5", 50000), Addr(rip, rport) if rip else (), status, pid)


def test_collector_keeps_only_outbound_remote_connections():
    conns = [conn("185.215.113.50", 443), conn("127.0.0.1", 5432), conn("fe80::1", 80),
             conn(None, 0, psutil.CONN_LISTEN), conn("8.8.8.8", 53, psutil.CONN_TIME_WAIT),
             conn("1.1.1.1", 443, psutil.CONN_SYN_SENT), conn("9.9.9.9", 443, psutil.CONN_NONE, kind=socket.SOCK_DGRAM),
             conn(None, 0, psutil.CONN_NONE, kind=socket.SOCK_DGRAM)]
    with patch("psutil.net_connections", return_value=conns):
        flows = NetworkFlowCollector().collect()
    assert [(f["remote_ip"], f["proto"], f["state"]) for f in flows] == [
        ("185.215.113.50", "tcp", "ESTABLISHED"), ("1.1.1.1", "tcp", "SYN_SENT"), ("9.9.9.9", "udp", "ESTABLISHED")]
    assert set(flows[0]) == {"remote_ip", "remote_port", "local_port", "proto", "state", "process"}  # no payloads


def test_delta_only_reports_new_connections():
    c = NetworkFlowCollector()
    flow = {"remote_ip": "1.1.1.1", "remote_port": 443, "process": "chrome"}
    assert c.new_flows([flow], now=0) == [flow]
    assert c.new_flows([flow], now=60) == []
    assert c.new_flows([flow], now=RESEND_AFTER + 1) == [flow]


def make_service(tmp_path, consent):
    config = make_config(data_dir=str(tmp_path))
    settings = AgentSettings(config)
    settings.share_network_flows = consent
    bus = RecordingBus()
    realtime = MagicMock(send=AsyncMock(), state=ConnectionState.CONNECTED)
    return NetflowService(realtime, settings, config, bus, AgentAuditLog(config, bus)), realtime, bus


def test_consent_is_off_by_default(tmp_path):
    settings = AgentSettings(make_config(data_dir=str(tmp_path)))
    assert settings.share_network_flows is False


async def test_without_consent_nothing_is_scheduled(tmp_path):
    svc, realtime, bus = make_service(tmp_path, consent=False)
    bus.emit("backend.state", "connected")
    assert svc._task is None
    realtime.send.assert_not_awaited()


async def test_with_consent_sends_batch_and_surfaces_hits(tmp_path):
    svc, realtime, bus = make_service(tmp_path, consent=True)
    with patch("psutil.net_connections", return_value=[conn("185.215.113.50", 443)]):
        assert await svc.collect_once() == 1
    type_, data = realtime.send.await_args.args
    assert type_ == "netflow.batch" and data["flows"][0]["remote_ip"] == "185.215.113.50"
    bus.emit("backend.notification", {"kind": "intel_hit", "hit": {"dst_ip": "185.215.113.50", "score": 90}})
    assert bus.of("agent.intel_hit") == [{"dst_ip": "185.215.113.50", "score": 90}]
    assert any(e["event"] == "intel_hit" for e in svc._audit.recent())
