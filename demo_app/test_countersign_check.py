"""
demo_app/test_countersign_check.py

Tests for the `check` subcommand of countersign.py.

Verifies:
  - check writes nothing under records/
  - check exits nonzero when a security requirement FAILS
  - check never imports or calls wx_explain.explain_failures

The autouse _no_network fixture mirrors the one in test_wx_explain.py so every
test in this file also has the watsonx SDK blocked.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

import countersign

# ---------------------------------------------------------------------------
# Credentials env vars to clear
# ---------------------------------------------------------------------------

_CRED_VARS = ("IBM_CLOUD_API_KEY", "WATSONX_URL", "WATSONX_PROJECT_ID")

# ---------------------------------------------------------------------------
# Minimal rule files
# ---------------------------------------------------------------------------

_PASSING_YAML = """\
- id: QUAL-001
  requirement: Always passes
  priority: quality
  check: "python -c \\"pass\\""
  paths:
    - "**/*.py"
  ai_access: edit
"""

_SECURITY_FAIL_YAML = """\
- id: SEC-TEST
  requirement: This check always exits 1
  priority: security
  check: "python -c \\"import sys; sys.exit(1)\\""
  paths:
    - "**/*.py"
  ai_access: read
"""

# ---------------------------------------------------------------------------
# Autouse fixture — block network for every test in this file
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Clear watsonx credentials and stub the SDK for every test."""
    for var in _CRED_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("countersign.load_dotenv", lambda **kw: None, raising=False)

    def _no_call(*a, **kw):
        raise RuntimeError("network call in test")

    monkeypatch.setattr("ibm_watsonx_ai.APIClient",                        _no_call, raising=False)
    monkeypatch.setattr("ibm_watsonx_ai.foundation_models.ModelInference", _no_call, raising=False)


# ---------------------------------------------------------------------------
# C2-a: check writes nothing under records/
# ---------------------------------------------------------------------------


def test_check_writes_no_record(tmp_path, monkeypatch):
    """cmd_check must not create or modify any file under records/."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "countersign.yaml").write_text(_PASSING_YAML, encoding="utf-8")
    (tmp_path / "records").mkdir()

    before = {f.name for f in (tmp_path / "records").iterdir()}
    countersign.cmd_check()
    after = {f.name for f in (tmp_path / "records").iterdir()}

    assert before == after, f"cmd_check wrote to records/: new files = {after - before}"


# ---------------------------------------------------------------------------
# C2-b: check exits nonzero on a security FAIL
# ---------------------------------------------------------------------------


def test_check_exits_nonzero_on_security_fail(tmp_path, monkeypatch):
    """cmd_check must return 1 when any security requirement FAILS."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "countersign.yaml").write_text(_SECURITY_FAIL_YAML, encoding="utf-8")
    (tmp_path / "records").mkdir()

    rc = countersign.cmd_check()

    assert rc == 1, f"expected exit 1 on security FAIL, got {rc}"


# ---------------------------------------------------------------------------
# C2-c: check never calls wx_explain.explain_failures
# ---------------------------------------------------------------------------


def test_check_never_calls_wx_explain(tmp_path, monkeypatch):
    """cmd_check must not call wx_explain.explain_failures under any condition.

    Two intercept points:
      - wx_explain.explain_failures: catches any future local-import inside cmd_check.
      - countersign.explain_failures: catches if it is ever imported at module scope
        into countersign (raising=False so the patch is skipped if the attribute
        does not yet exist, keeping the test forward-compatible).
    """
    monkeypatch.chdir(tmp_path)
    # Use a failing rule so the blocking path is fully exercised.
    (tmp_path / "countersign.yaml").write_text(_SECURITY_FAIL_YAML, encoding="utf-8")
    (tmp_path / "records").mkdir()

    calls: list = []

    def _spy(*a, **kw):
        calls.append(a)
        return {}, "", ""  # valid return shape so caller would not crash

    monkeypatch.setattr("countersign.explain_failures", _spy, raising=False)

    with patch("wx_explain.explain_failures", _spy):
        countersign.cmd_check()

    assert not calls, "cmd_check called wx_explain.explain_failures"
