"""
demo_app/test_recursion_guard.py -- Tests for the nested-gate guard.

FUNC-001 runs pytest on demo_app/.  If anything under that run starts the
gate again, the gate must refuse instead of recursing.

Covers:
  G-1. Check commands run with COUNTERSIGN_IN_CHECK=1 in their environment.
  G-2. run / ci / check exit 1 immediately when COUNTERSIGN_IN_CHECK=1.
  G-3. Non-gate subcommands (verify-chain) still run when it is set,
       since SEC-003 and SEC-004 invoke them as check commands.

main() is called in-process with the gate subcommands stubbed, so a broken
guard fails the test instead of launching real checks.
"""
from __future__ import annotations

import sys

import pytest

import countersign


def _forbid(name: str):
    def _fail(*a, **kw):
        raise AssertionError(f"{name} ran while {countersign.IN_CHECK_ENV}=1")
    return _fail


def test_run_sets_in_check_env(monkeypatch):
    monkeypatch.delenv(countersign.IN_CHECK_ENV, raising=False)
    rc, out = countersign._run(
        f"python -c \"import os; print(os.environ.get('{countersign.IN_CHECK_ENV}'))\""
    )
    assert rc == 0
    assert out == "1"


@pytest.mark.parametrize("command", ["run", "ci", "check"])
def test_gate_refuses_when_nested(monkeypatch, capsys, command):
    monkeypatch.setenv(countersign.IN_CHECK_ENV, "1")
    monkeypatch.setattr(sys, "argv", ["countersign.py", command])
    monkeypatch.setattr(countersign, "cmd_run", _forbid("cmd_run"))
    monkeypatch.setattr(countersign, "cmd_ci", _forbid("cmd_ci"))
    monkeypatch.setattr(countersign, "cmd_check", _forbid("cmd_check"))

    with pytest.raises(SystemExit) as exc:
        countersign.main()

    assert exc.value.code == 1
    assert countersign.IN_CHECK_ENV in capsys.readouterr().err


def test_verify_chain_allowed_when_nested(monkeypatch):
    monkeypatch.setenv(countersign.IN_CHECK_ENV, "1")
    monkeypatch.setattr(sys, "argv", ["countersign.py", "verify-chain"])
    monkeypatch.setattr(countersign, "cmd_verify_chain", lambda: 0)

    with pytest.raises(SystemExit) as exc:
        countersign.main()

    assert exc.value.code == 0
