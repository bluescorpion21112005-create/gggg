import asyncio
from unittest.mock import AsyncMock


def sent(ex):
    return [(c.args[0], c.args[1]) for c in ex.t.rt.send.await_args_list]


def result_of(ex):
    return [d for t, d in sent(ex) if t == "command.result"][-1]


async def test_full_sequence_with_approval(make_executor):
    ex = make_executor()
    await ex.execute({"command_id": "c1", "type": "ioc_analysis", "payload": {"type": "ip", "value": "1.2.3.4"}})
    ex.t.orch.dispatch.assert_awaited_once_with("ioc_analysis", {"type": "ip", "value": "1.2.3.4"})
    assert [t for t, _ in sent(ex)] == ["command.ack", "command.progress", "command.progress", "command.result"]
    stages = [d["stage"] for t, d in sent(ex) if t == "command.progress"]
    assert stages == ["awaiting_approval", "approved"]
    assert result_of(ex) == {"command_id": "c1", "success": True, "error": "", "result": {"report": "REPORT"}}
    assert len(ex.t.approver.asked) == 1
    events = [e["event"] for e in ex.t.audit.recent()]
    assert events[:3] == ["command_done", "command_approved", "command_received"]


async def test_denied_by_user_is_reported_as_rejected(make_executor):
    ex = make_executor(decision="deny")
    await ex.execute({"command_id": "c2", "type": "threat_hunting", "payload": {"query": "q"}})
    ex.t.orch.dispatch.assert_not_awaited()
    assert result_of(ex)["rejected"] is True and result_of(ex)["success"] is False


async def test_allow_always_persists_and_skips_next_prompt(make_executor):
    ex = make_executor(decision="allow_always")
    await ex.execute({"command_id": "a", "type": "threat_hunting", "payload": {"query": "q"}})
    assert "threat_hunting" in ex.t.settings.always_allowed
    await ex.execute({"command_id": "b", "type": "threat_hunting", "payload": {"query": "q"}})
    assert len(ex.t.approver.asked) == 1
    assert ex.t.orch.dispatch.await_count == 2


async def test_deny_all_policy_never_prompts(make_executor):
    ex = make_executor(policy="deny_all")
    await ex.execute({"command_id": "c", "type": "threat_hunting", "payload": {"query": "q"}})
    assert ex.t.approver.asked == []
    assert result_of(ex)["rejected"] is True


async def test_allow_listed_policy_denies_unlisted(make_executor):
    ex = make_executor(policy="allow_listed")
    ex.t.settings.allow_always("ioc_analysis")
    await ex.execute({"command_id": "x", "type": "threat_hunting", "payload": {"query": "q"}})
    assert result_of(ex)["rejected"] is True
    await ex.execute({"command_id": "y", "type": "ioc_analysis", "payload": {"type": "ip", "value": "1.1.1.1"}})
    assert result_of(ex)["success"] is True
    assert ex.t.approver.asked == []


async def test_broken_approver_fails_closed(make_executor):
    ex = make_executor()
    ex._approver.request_approval = AsyncMock(side_effect=RuntimeError("ui crashed"))
    await ex.execute({"command_id": "c", "type": "threat_hunting", "payload": {"query": "q"}})
    ex.t.orch.dispatch.assert_not_awaited()
    assert result_of(ex)["rejected"] is True


async def test_unknown_type_rejected_without_running(make_executor):
    ex = make_executor()
    await ex.execute({"command_id": "c2", "type": "shell", "payload": {"cmd": "rm -rf /"}})
    ex.t.orch.dispatch.assert_not_awaited()
    assert ex.t.approver.asked == []
    assert "unsupported" in result_of(ex)["error"]


async def test_remote_commands_can_be_disabled(make_executor):
    ex = make_executor(accept=False)
    await ex.execute({"command_id": "c3", "type": "threat_hunting", "payload": {"query": "x"}})
    ex.t.orch.dispatch.assert_not_awaited()


async def test_file_command_requires_allowed_dir(make_executor, tmp_path):
    inside = tmp_path / "logs" / "auth.log"
    inside.parent.mkdir()
    inside.write_text("x")
    (tmp_path / "secret.txt").write_text("x")

    ex = make_executor()  # no allowed dirs at all
    await ex.execute({"command_id": "a", "type": "log_analysis", "payload": {"file_path": str(inside)}})
    ex.t.orch.dispatch.assert_not_awaited()

    ex = make_executor(allowed_dirs=[inside.parent])
    await ex.execute({"command_id": "b", "type": "log_analysis",
                      "payload": {"file_path": str(inside.parent / ".." / "secret.txt")}})
    ex.t.orch.dispatch.assert_not_awaited()
    assert "outside" in result_of(ex)["error"]

    await ex.execute({"command_id": "c", "type": "log_analysis", "payload": {"file_path": str(inside)}})
    ex.t.orch.dispatch.assert_awaited_once_with("log_analysis", {"file_path": str(inside.resolve())})


async def test_report_output_dir_is_ignored(make_executor):
    ex = make_executor()
    await ex.execute({"command_id": "r", "type": "report", "payload": {"analysis_id": "x", "output_dir": "/etc"}})
    ex.t.orch.dispatch.assert_awaited_once_with("generate_report", {"analysis_id": "x"})


async def test_system_snapshot_runs_locally(make_executor):
    ex = make_executor()
    await ex.execute({"command_id": "s", "type": "system_snapshot", "payload": {"ignored": 1}})
    ex.t.orch.dispatch.assert_not_awaited()
    assert result_of(ex)["result"] == {"process_count": 3}


async def test_command_times_out_locally(make_executor):
    ex = make_executor()

    async def slow(*_a, **_k):
        await asyncio.sleep(5)

    ex.t.orch.dispatch.side_effect = slow
    await ex.execute({"command_id": "t", "type": "threat_hunting", "payload": {"query": "q"}, "timeout_seconds": 1})
    out = result_of(ex)
    assert out["success"] is False and "timed out" in out["error"]


async def test_failure_reported_via_rest_when_offline(make_executor):
    ex = make_executor(connected=False)
    ex.t.orch.dispatch.side_effect = RuntimeError("model offline")
    await ex.execute({"command_id": "c9", "type": "threat_hunting", "payload": {"query": "q"}})
    ex.t.gw.post_command_result.assert_awaited_once_with("c9", False, None, "model offline", rejected=False)


async def test_redelivery_never_runs_twice(make_executor):
    ex = make_executor()
    msg = {"command_id": "dup", "type": "threat_hunting", "payload": {"query": "q"}}
    ex._bus.emit("backend.command.dispatch", msg)
    ex._bus.emit("backend.command.dispatch", msg)  # while running
    await ex._running["dup"]
    ex._bus.emit("backend.command.dispatch", msg)  # after completion → cached result re-sent
    await asyncio.sleep(0.01)
    ex.t.orch.dispatch.assert_awaited_once()
    results = [d for t, d in sent(ex) if t == "command.result"]
    assert len(results) == 2 and results[0] == results[1]
