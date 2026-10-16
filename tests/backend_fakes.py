"""Shared fakes for server-connection tests."""
from __future__ import annotations

from dataclasses import replace

from core.config import AppConfig, BackendConfig
from core.event_bus import EventBus


class FakeVault:
    """In-memory stand-in for the keyring-backed Vault."""

    def __init__(self):
        self.data = {}

    def store_api_key(self, provider, key):
        self.data[provider] = key

    def get_api_key(self, provider, env_var=None):
        return self.data.get(provider)

    def delete_api_key(self, provider):
        self.data.pop(provider, None)


class RecordingBus(EventBus):
    """Isolated (non-singleton) event bus that also records every emit."""

    def __new__(cls):
        bus = object.__new__(cls)
        bus._subscribers = {}
        bus.events = []
        return bus

    def __init__(self):
        pass

    def emit(self, event, data=None):
        self.events.append((event, data))
        super().emit(event, data)

    def of(self, name):
        return [d for e, d in self.events if e == name]


def make_config(base_url="https://testserver", **backend) -> AppConfig:
    return AppConfig(backend=replace(BackendConfig(base_url=base_url), **backend))


class FakeApprover:
    """CommandApprover stand-in returning a preset decision and recording what it was asked."""

    def __init__(self, decision="allow_once"):
        from domain.interfaces.backend import ApprovalDecision

        self.decision = ApprovalDecision(decision)
        self.asked = []

    async def request_approval(self, command, timeout):
        self.asked.append((command, timeout))
        return self.decision
