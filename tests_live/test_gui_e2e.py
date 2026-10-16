"""Runs gui_e2e.py in a subprocess (it owns the Qt/qasync loop). Needs LIVE_BASE_URL + a running stack."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent


@pytest.mark.skipif(not os.getenv("LIVE_BASE_URL"), reason="set LIVE_BASE_URL and start cybrix_ai/scripts/stack.sh")
def test_gui_end_to_end():
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    proc = subprocess.run([sys.executable, str(HERE / "gui_e2e.py")], env=env, capture_output=True, text=True,
                          timeout=240, cwd=HERE.parent)
    report = "\n".join(l for l in proc.stdout.splitlines() if l.startswith(("PASS", "FAIL")) or "checks passed" in l)
    print(report)
    assert proc.returncode == 0, report or proc.stderr[-2000:]
