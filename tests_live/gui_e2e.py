"""Live GUI end-to-end: the real MVVM desktop app (offscreen) against cybrix_ai's scripts/stack.sh.

Run through pytest (tests_live/test_gui_e2e.py) or directly:
    cd gggg && QT_QPA_PLATFORM=offscreen .venv/bin/python tests_live/gui_e2e.py
Exit status 0 = every check passed.
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

GGGG = Path(__file__).resolve().parents[1]
SERVER = GGGG.parent / "cybrix_ai"
sys.path.insert(0, str(GGGG))
sys.argv = ["main.py"]

BASE = os.getenv("LIVE_BASE_URL", "http://127.0.0.1:8088")
os.environ.setdefault("CYBRIX_SERVER_URL", BASE)
os.environ.setdefault("CYBRIX_SKIP_ONBOARDING", "1")   # the wizard is covered by unit tests
os.environ.setdefault("PYTHON_KEYRING_BACKEND", "keyring.backends.null.Keyring")  # never touch the real keyring
os.environ.setdefault("CYBRIX_DATA_DIR", str(GGGG / "tests_live" / "artifacts" / f"agent-{secrets.token_hex(3)}"))

import websockets  # noqa: E402
from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from core.bootstrap import CybrixApp  # noqa: E402
from presentation.widgets.command_approval_dialog import CommandApprovalDialog  # noqa: E402

RESULTS, DASH = [], []
DECISION = {"button": "_once_btn"}


def server_env() -> dict:
    out = subprocess.run([str(SERVER / "scripts" / "stack.sh"), "env"], capture_output=True, text=True, check=True)
    env = dict(os.environ)
    for item in out.stdout.replace("export ", "").split():
        key, _, value = item.partition("=")
        env[key] = value
    return env


ENV = server_env()


def django(code: str) -> str:
    out = subprocess.run([str(SERVER / ".venv" / "bin" / "python"), "manage.py", "shell", "-c", code],
                         cwd=SERVER, env=ENV, capture_output=True, text=True, timeout=120)
    lines = [l for l in out.stdout.splitlines() if l.strip() and not l.startswith("GOOGLE") and "objects imported" not in l]
    if out.returncode:
        raise RuntimeError(out.stderr[-600:])
    return lines[-1] if lines else ""


async def dj(code: str) -> str:
    return await asyncio.get_running_loop().run_in_executor(None, django, code)


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))


async def until(pred, timeout=20.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        await asyncio.sleep(0.1)
    return False


def auto_answer():
    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, CommandApprovalDialog) and widget.isVisible():
            getattr(widget, DECISION["button"]).click()


async def dashboard(cookie):
    try:
        async with websockets.connect(BASE.replace("http", "ws", 1) + "/ws/dashboard/",
                                      additional_headers={"Cookie": cookie, "Origin": BASE}) as ws:
            async for raw in ws:
                DASH.append(json.loads(raw))
    except Exception as exc:  # noqa: BLE001
        DASH.append({"type": "dashboard_error", "data": str(exc)})


async def wait_status(cid, wanted, timeout=40):
    status = ""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        status = await dj(f"from desktop_agent.models import AgentCommand as C; print(C.objects.get(pk='{cid}').status)")
        if status in wanted:
            break
        await asyncio.sleep(0.5)
    return status


async def scenario(app):
    window = app._main_window
    vm = window._connection_vm
    toasts = []
    vm.notification.connect(toasts.append)
    username = f"gui_{secrets.token_hex(4)}"
    password = "Gui-e2e-Passw0rd!"
    await dj(f"from django.contrib.auth import get_user_model as G; G().objects.create_user('{username}', '{username}@example.test', '{password}')")
    try:
        cookie = await dj("from django.test import Client; from django.contrib.auth import get_user_model as G;"
                          f"c=Client(); c.force_login(G().objects.get(username='{username}')); print('sessionid='+c.cookies['sessionid'].value)")
        dash_task = asyncio.ensure_future(dashboard(cookie))

        vm.login(username, password)
        check("login + realtime connected via nginx", await until(lambda: vm.state == "connected"), vm.state)
        device = vm.session_info.get("device_id")
        check("token expiry in session", bool(vm.session_info.get("token_expires_at")))

        check("keyframe telemetry reaches the web dashboard",
              await until(lambda: any(m["type"] == "device.telemetry" for m in DASH), 20))
        first = next((m["data"]["changes"] for m in DASH if m["type"] == "device.telemetry"), {})
        check("keyframe carries the full sample", {"cpu_percent", "ram_percent", "disk_percent"} <= set(first), sorted(first))
        stored = await dj(f"from desktop_agent import services; from desktop_agent.models import Device as D;"
                          f"print(sorted(services.latest_telemetry(D.objects.get(pk='{device}'))))")
        check("merged telemetry state in Redis", "cpu_percent" in stored, stored)

        DECISION["button"] = "_once_btn"
        cid = await dj("from desktop_agent.models import Device as D; from desktop_agent import services;"
                       f"print(services.dispatch_command(D.objects.get(pk='{device}'), 'system_snapshot').id)")
        status = await wait_status(cid, ("done", "failed", "rejected"))
        check("approved system_snapshot → done", status == "done", status)
        states = [m["data"].get("status") for m in DASH if m["type"] == "command.updated" and m["data"].get("id") == cid]
        check("dashboard got command deltas", {"awaiting_approval", "done"} <= set(states), states)

        DECISION["button"] = "_deny_btn"
        cid2 = await dj("from desktop_agent.models import Device as D; from desktop_agent import services;"
                        f"print(services.dispatch_command(D.objects.get(pk='{device}'), 'threat_hunting', {{'query': 'x'}}).id)")
        check("denied command → rejected", await wait_status(cid2, ("done", "failed", "rejected")) == "rejected")

        local = {e["event"] for e in vm.recent_audit(100)}
        check("local audit trail", {"login", "command_approved", "command_denied"} <= local, sorted(local)[:8])

        await dj("from desktop_agent.models import Device as D; from desktop_agent import services;"
                 f"services.revoke_device(D.objects.get(pk='{device}'), reason='gui-e2e')")
        check("revoke signs the app out", await until(lambda: vm.state == "auth_failed" and not vm.is_logged_in, 15), vm.state)
        check("exactly one sign-out toast", sum(t.get("title") == "Signed out from server" for t in toasts) == 1,
              [t.get("title") for t in toasts])
        dash_task.cancel()
    finally:
        await dj(f"from django.contrib.auth import get_user_model as G; G().objects.filter(username='{username}').delete()")
        app._qt_app.quit()


def main() -> int:
    app = CybrixApp()
    timer = QTimer()
    timer.timeout.connect(auto_answer)
    timer.start(200)
    QTimer.singleShot(300, lambda: asyncio.ensure_future(scenario(app)))
    QTimer.singleShot(180_000, app._qt_app.quit)
    app.run()
    width = max((len(n) for n, _, _ in RESULTS), default=10)
    for name, ok, detail in RESULTS:
        print(f"{'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {str(detail)[:100]}")
    passed = sum(ok for _, ok, _ in RESULTS)
    print(f"{passed}/{len(RESULTS)} checks passed")
    return 0 if RESULTS and passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
