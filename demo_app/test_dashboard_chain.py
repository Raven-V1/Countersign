"""
demo_app/test_dashboard_chain.py - Chain-status notice in dashboard/app.py.

The dashboard runs `countersign.py verify-chain` and shows one of three
notices: green "Chain intact", red "Chain broken" (verify-chain ran and
reported FAIL), or grey UNVERIFIED (verify-chain could not run). No evidence
is UNVERIFIED, never FAIL.

subprocess.run is stubbed in every test; no real verify-chain call is made.
The app runs through Streamlit's AppTest in an empty tmp_path.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from streamlit.testing.v1 import AppTest

_APP = Path(__file__).parent.parent / "dashboard" / "app.py"

_TRACEBACK = (
    "Traceback (most recent call last):\n"
    '  File "countersign.py", line 33, in <module>\n'
    "    import yaml\n"
    "ModuleNotFoundError: No module named 'yaml'\n"
)


def _notice(monkeypatch, tmp_path, *, result=None, exc=None) -> tuple[str, list]:
    """Run the dashboard with a stubbed subprocess.run; return (notice html, calls)."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "records").mkdir()
    calls = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        if exc is not None:
            raise exc
        return subprocess.CompletedProcess(cmd, *result)

    with patch("subprocess.run", side_effect=fake_run):
        at = AppTest.from_file(str(_APP), default_timeout=30).run()
    assert not at.exception
    bodies = [
        el.proto.body
        for el in at.get("html")
        if el.proto.body.startswith('<div class="cs-notif ')
    ]
    assert len(bodies) == 1
    return bodies[0], calls


def test_pass_shows_intact(monkeypatch, tmp_path):
    body, calls = _notice(
        monkeypatch, tmp_path, result=(0, "PASS: Chain intact across 3 record(s).\n", "")
    )
    assert "cs-notif--success" in body
    assert "Chain intact" in body
    assert calls == [[sys.executable, "countersign.py", "verify-chain"]]


def test_chain_fail_shows_broken(monkeypatch, tmp_path):
    out = "FAIL: Chain broken at record r2.json\n  Expected prev_fingerprint: a\n"
    body, _ = _notice(monkeypatch, tmp_path, result=(1, out, ""))
    assert "cs-notif--error" in body
    assert "Chain broken" in body
    assert "UNVERIFIED" not in body


@pytest.mark.parametrize(
    "kwargs, first_line",
    [
        ({"result": (1, "", _TRACEBACK)}, "ModuleNotFoundError: No module named"),
        ({"exc": OSError("No such file or directory")}, "No such file or directory"),
        ({"exc": subprocess.TimeoutExpired("verify-chain", 15)}, "timed out"),
    ],
    ids=["traceback", "oserror", "timeout"],
)
def test_cannot_run_shows_unverified(monkeypatch, tmp_path, kwargs, first_line):
    body, _ = _notice(monkeypatch, tmp_path, **kwargs)
    assert "cs-notif--unverified" in body
    assert "Chain status UNVERIFIED: verify-chain could not run" in body
    assert first_line in body
    assert "Chain broken" not in body
    assert "cs-notif--error" not in body
