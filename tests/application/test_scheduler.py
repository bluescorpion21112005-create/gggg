"""Recurring pentest scheduler: due logic, run_due, report writing + diff, loop, CLI."""
from __future__ import annotations

import asyncio
import json

import pytest

from application.pentest import agents as agent_mod
from application.pentest import scheduler
from application.services.pentest_service import PentestService


class _NullAI:
    async def generate(self, prompt, model="x", **kwargs):
        if False:                       # pragma: no cover - make this an async generator
            yield ""

    async def list_models(self):
        return []


@pytest.fixture
def force_simulation(monkeypatch):
    monkeypatch.setattr(agent_mod, "tool_available", lambda _n: False)


def test_due_logic():
    entry = {"target": "127.0.0.1", "every": 100}
    assert scheduler.due(entry, {}, now=1000.0)                         # never run → due
    assert not scheduler.due(entry, {"127.0.0.1": 1000.0}, now=1050.0)  # 50s < 100s
    assert scheduler.due(entry, {"127.0.0.1": 1000.0}, now=1200.0)      # 200s elapsed


def test_load_schedule(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps([{"target": "127.0.0.1", "every": 60}]))
    assert scheduler.load_schedule(str(p))[0]["target"] == "127.0.0.1"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([{"target": "x"}]))                       # missing 'every'
    with pytest.raises(ValueError):
        scheduler.load_schedule(str(bad))


def test_run_due_writes_report_and_updates_state(force_simulation, test_config, tmp_path):
    svc = PentestService(_NullAI(), test_config)
    sched = [{"target": "127.0.0.1", "every": 100}]
    state: dict = {}

    results = asyncio.run(scheduler.run_due(svc, sched, state, tmp_path, now=1000.0))
    assert len(results) == 1 and results[0]["first_run"] is True
    assert state["127.0.0.1"] == 1000.0
    assert list((tmp_path / "127.0.0.1").glob("*/report.json"))
    # not due again at the same instant → nothing runs
    assert asyncio.run(scheduler.run_due(svc, sched, state, tmp_path, now=1050.0)) == []


def test_second_run_diffs_against_first(force_simulation, test_config, tmp_path):
    svc = PentestService(_NullAI(), test_config)
    sched = [{"target": "127.0.0.1", "every": 10}]
    state: dict = {}
    asyncio.run(scheduler.run_due(svc, sched, state, tmp_path, now=1000.0))
    res = asyncio.run(scheduler.run_due(svc, sched, state, tmp_path, now=2000.0))
    # same simulated findings both runs → second run is not a first run and has 0 new
    assert res and res[0]["first_run"] is False and res[0]["new"] == 0


def test_loop_once(force_simulation, test_config, tmp_path):
    svc = PentestService(_NullAI(), test_config)
    sched = tmp_path / "s.json"
    sched.write_text(json.dumps([{"target": "127.0.0.1", "every": 100}]))

    asyncio.run(scheduler.loop(svc, str(sched), tmp_path / "out", once=True, clock=lambda: 1000.0))
    assert list((tmp_path / "out" / "127.0.0.1").glob("*/report.md"))


def test_cli_missing_schedule(tmp_path):
    assert scheduler.main([str(tmp_path / "nope.json")]) == 2
