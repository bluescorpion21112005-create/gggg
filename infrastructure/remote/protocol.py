"""Desktop agent wire protocol — client mirror of cybrix_ai/desktop_agent/protocol.py.

See cybrix_ai/desktop_agent/PROTOCOL.md. Change both files together.
"""
from __future__ import annotations

PROTOCOL_VERSION = 1

# ── Client → server ──────────────────────────────────────────────────────────
AUTH = "auth"
PING = "ping"
TELEMETRY = "telemetry"
COMMAND_ACK = "command.ack"
COMMAND_PROGRESS = "command.progress"
COMMAND_RESULT = "command.result"
NETFLOW_BATCH = "netflow.batch"

# ── Server → client ──────────────────────────────────────────────────────────
AUTH_OK = "auth.ok"
PONG = "pong"
ERROR = "error"
COMMAND_DISPATCH = "command.dispatch"
SCAN_PROGRESS = "scan.progress"
SCAN_COMPLETED = "scan.completed"
NOTIFICATION = "notification"
DEVICE_REVOKED = "device.revoked"
NETFLOW_ACK = "netflow.ack"

# ── Telemetry ────────────────────────────────────────────────────────────────
TELEMETRY_KEYFRAME_INTERVAL = 60.0  # send a full sample at least this often; deltas in between

# ── Command progress stages ──────────────────────────────────────────────────
STAGE_AWAITING_APPROVAL = "awaiting_approval"
STAGE_APPROVED = "approved"
STAGE_RUNNING = "running"

# ── Close codes ──────────────────────────────────────────────────────────────
CLOSE_UNAUTHORIZED = 4401
CLOSE_REVOKED = 4403
CLOSE_UNSUPPORTED_PROTOCOL = 4426

# ── Event-bus names used inside the desktop app ─────────────────────────────
def bus_event(type_: str) -> str:
    """Server message type → event-bus event (e.g. "notification" → "backend.notification")."""
    return f"backend.{type_}"


BUS_STATE = "backend.state"
BUS_AUTH_LOST = "backend.auth_lost"
BUS_SESSION = bus_event(AUTH_OK)
BUS_AGENT_COMMAND = "agent.command"      # local command lifecycle updates for the UI
BUS_AGENT_TELEMETRY = "agent.telemetry"  # local metrics sample for the UI
BUS_AGENT_AUDIT = "agent.audit"          # appended local audit entry
BUS_AGENT_NETFLOW = "agent.netflow"      # {"sent": n, "flows": [...]} last batch shared
BUS_INTEL_HIT = "agent.intel_hit"        # server flagged one of our connections
