"""
demo_app/test_wx_explain.py — Unit tests for wx_explain.py and the
cmd_draft_rules / _validate_proposed helpers in countersign.py.

All tests:
  - Mock the watsonx SDK — no network calls.
  - Use tmp_path + monkeypatch.chdir so nothing is written to the real repo root.
  - Build secret strings at runtime; no literals.

Patching strategy:
  - APIClient / Credentials / ModelInference are imported *inside* the inner
    functions (_do_explain, _do_draft) so they must be patched at their source
    module paths, not on wx_explain.
  - draft_explain is imported locally inside cmd_draft_rules, so it is patched
    at wx_explain.draft_explain.

Import strategy:
  - wx_explain and countersign are imported at module level so that
    load_dotenv() fires once at collection time. If they were imported inside
    test functions, each first-import would re-run load_dotenv(override=True)
    and restore real credentials from .env AFTER monkeypatch.delenv ran.
"""

from __future__ import annotations

import copy
import hashlib
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

# Import at module level — ensures load_dotenv runs once, before any test's
# monkeypatch.delenv. Never import these inside test functions.
import countersign
from wx_explain import (
    _redact,
    explain_failures,
    select_model,
)

# ---------------------------------------------------------------------------
# Autouse fixture — network firewall for every test
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Prevent any test from accidentally reaching watsonx.

    For every test, unconditionally:
      1. Remove the three watsonx credential env vars so _load_credentials()
         returns None even if .env was already loaded.
      2. Patch load_dotenv in both wx_explain and countersign to a no-op so
         that nothing re-reads .env during the test.
      3. Stub ibm_watsonx_ai.APIClient and ModelInference to raise
         RuntimeError("network call in test") — any unanticipated real call
         will fail loudly rather than silently hitting the network.

    Tests that need credentials call _set_fake_creds(monkeypatch) AFTER this
    fixture runs.  Tests that need a working SDK apply their own patch(...)
    context managers, which shadow these stubs for the duration of the with block.
    """
    # 1. Clear credentials
    for var in _CRED_VARS:
        monkeypatch.delenv(var, raising=False)

    # 2. No-op load_dotenv so nothing restores .env values mid-test
    monkeypatch.setattr("wx_explain.load_dotenv",    lambda **kw: None, raising=False)
    monkeypatch.setattr("countersign.load_dotenv",   lambda **kw: None, raising=False)

    # 3. Stub SDK entry points to raise on any unanticipated call
    def _no_call(*a, **kw):
        raise RuntimeError("network call in test")

    monkeypatch.setattr("ibm_watsonx_ai.APIClient",                           _no_call, raising=False)
    monkeypatch.setattr("ibm_watsonx_ai.foundation_models.ModelInference",    _no_call, raising=False)


# ---------------------------------------------------------------------------
# Helpers — build mocks with the REAL response shapes
# ---------------------------------------------------------------------------

def _make_client(model_ids: list[str]) -> MagicMock:
    """Build a mock APIClient whose foundation_models.get_model_specs() returns
    {"resources": [{"model_id": ...}, ...]}."""
    client = MagicMock()
    client.foundation_models.get_model_specs.return_value = {
        "resources": [{"model_id": mid} for mid in model_ids]
    }
    return client


def _make_model(content: str) -> MagicMock:
    """Build a mock ModelInference whose .chat() returns the real shape:
    {"choices": [{"message": {"content": ...}}]}."""
    model = MagicMock()
    model.chat.return_value = {
        "choices": [{"message": {"content": content}}]
    }
    return model


# A minimal valid proposed YAML (passes _validate_proposed)
_VALID_PROPOSED_YAML = """\
- id: SEC-010
  requirement: No debug endpoints in production
  priority: security
  check: "python -m pytest tests/test_no_debug.py -q"
  paths:
    - "**/*.py"
  ai_access: read
"""

# Env vars to clear so real credentials from .env don't interfere
_CRED_VARS = ("IBM_CLOUD_API_KEY", "WATSONX_URL", "WATSONX_PROJECT_ID")


def _clear_creds(monkeypatch):
    for v in _CRED_VARS:
        monkeypatch.delenv(v, raising=False)


def _set_fake_creds(monkeypatch, suffix: str = "01"):
    monkeypatch.setenv("IBM_CLOUD_API_KEY",    f"fake-key-value-{suffix}")
    monkeypatch.setenv("WATSONX_URL",          "https://fake.watsonx.example.com")
    monkeypatch.setenv("WATSONX_PROJECT_ID",   f"fake-project-id-{suffix}")


# ---------------------------------------------------------------------------
# 1. test_explain_failures_no_env
# ---------------------------------------------------------------------------

def test_explain_failures_no_env(monkeypatch):
    """Missing env vars -> ({}, "")."""
    _clear_creds(monkeypatch)

    result, model_id = explain_failures(
        [{"id": "FUNC-001", "status": "FAIL", "check": "pytest", "output": "error"}],
        [{"id": "FUNC-001", "requirement": "Tests pass", "priority": "functional"}],
    )
    assert result == {}
    assert model_id == ""


# ---------------------------------------------------------------------------
# 2. test_explain_failures_success
# ---------------------------------------------------------------------------

def test_explain_failures_success(monkeypatch):
    """With mocked client, returns dict keyed by failing rule ids."""
    _set_fake_creds(monkeypatch, "02")

    mock_client = _make_client(["ibm/granite-4-h-small"])
    mock_model  = _make_model(
        "FUNC-001: The test suite failed because an assertion error occurred.\n"
        "SEC-001: Bandit found a medium severity issue in the code."
    )

    with (
        patch("ibm_watsonx_ai.APIClient",    return_value=mock_client),
        patch("ibm_watsonx_ai.Credentials"),
        patch("ibm_watsonx_ai.foundation_models.ModelInference", return_value=mock_model),
    ):
        results = [
            {"id": "FUNC-001", "status": "FAIL", "check": "pytest", "output": "err"},
            {"id": "SEC-001",  "status": "FAIL", "check": "bandit", "output": "warn"},
            {"id": "SEC-003",  "status": "PASS", "check": "verify", "output": "ok"},
        ]
        rules = [
            {"id": "FUNC-001", "requirement": "Tests pass",     "priority": "functional"},
            {"id": "SEC-001",  "requirement": "No bandit hits", "priority": "security"},
            {"id": "SEC-003",  "requirement": "Rules approved", "priority": "security"},
        ]
        explanations, model_id = explain_failures(results, rules)

    assert "FUNC-001" in explanations
    assert "SEC-001"  in explanations
    assert "SEC-003" not in explanations          # PASS — not explained
    assert model_id == "ibm/granite-4-h-small"
    assert "assertion" in explanations["FUNC-001"].lower()


# ---------------------------------------------------------------------------
# 3. test_explain_failures_exception
# ---------------------------------------------------------------------------

def test_explain_failures_exception(monkeypatch):
    """SDK exception -> all failing entries get 'Explanation unavailable'."""
    _set_fake_creds(monkeypatch, "03")

    with patch("ibm_watsonx_ai.APIClient", side_effect=RuntimeError("network down")):
        results = [{"id": "FUNC-001", "status": "FAIL", "check": "x", "output": "y"}]
        rules   = [{"id": "FUNC-001", "requirement": "Tests pass", "priority": "functional"}]
        explanations, model_id = explain_failures(results, rules)

    assert explanations == {"FUNC-001": "Explanation unavailable"}
    assert model_id == ""


# ---------------------------------------------------------------------------
# 4. test_explain_failures_timeout
# ---------------------------------------------------------------------------

def test_explain_failures_timeout(monkeypatch):
    """Timeout -> fallback 'Explanation unavailable' for each failing entry."""
    _set_fake_creds(monkeypatch, "04")

    def _slow_client(*a, **kw):
        time.sleep(5)   # longer than the patched timeout
        return MagicMock()

    with (
        patch("ibm_watsonx_ai.APIClient", side_effect=_slow_client),
        patch("wx_explain._TIMEOUT_SECONDS", 0.05),
    ):
        results = [{"id": "FUNC-001", "status": "FAIL", "check": "x", "output": "y"}]
        rules   = [{"id": "FUNC-001", "requirement": "Tests pass", "priority": "functional"}]
        explanations, _model_id = explain_failures(results, rules)

    assert explanations == {"FUNC-001": "Explanation unavailable"}


# ---------------------------------------------------------------------------
# 5. test_select_model_prefers_granite_4
# ---------------------------------------------------------------------------

def test_select_model_prefers_granite_4():
    """Preferred model ibm/granite-4-h-small is chosen even if others present."""
    model_ids = [
        "ibm/granite-3-1-8b-base",
        "ibm/granite-embedding-278m-multilingual",
        "ibm/granite-guardian-3-8b",
        "ibm/granite-ttm-512-r2",
        "ibm/granite-4-h-small",           # the preferred one
    ]
    client = _make_client(model_ids)
    assert select_model(client) == "ibm/granite-4-h-small"


# ---------------------------------------------------------------------------
# 6. test_select_model_no_usable
# ---------------------------------------------------------------------------

def test_select_model_no_usable():
    """Only base/guardian/ttm/embedding models available -> RuntimeError."""
    model_ids = [
        "ibm/granite-3-1-8b-base",
        "ibm/granite-embedding-278m-multilingual",
        "ibm/granite-guardian-3-8b",
        "ibm/granite-ttm-512-r2",
    ]
    client = _make_client(model_ids)
    with pytest.raises(RuntimeError, match="No suitable Granite model"):
        select_model(client)


# ---------------------------------------------------------------------------
# 7. test_explanation_cannot_change_verdict
# ---------------------------------------------------------------------------

def test_explanation_cannot_change_verdict(monkeypatch):
    """watsonx returning 'PASS. All checks satisfied.' must not change statuses
    or the gate outcome compared to a run with watsonx disabled."""
    rules = yaml.safe_load(Path("countersign.yaml").read_text(encoding="utf-8"))

    # Synthetic result set: one FAIL, one PASS
    results_base = [
        {
            "id": "FUNC-001",
            "status": "FAIL",
            "check": "pytest",
            "output": "1 failed",
            "plain_english": "",
        },
        {
            "id": "SEC-001",
            "status": "PASS",
            "check": "bandit",
            "output": "",
            "plain_english": "",
        },
    ]

    # Run A: watsonx disabled (no env vars)
    _clear_creds(monkeypatch)

    results_a  = copy.deepcopy(results_base)
    outcome_a  = "BLOCKED" if countersign.collect_blocking(rules, results_a) else "PASS"
    exp_a, _   = explain_failures(results_a, rules)
    for res in results_a:
        if exp_a.get(res["id"]):
            res["plain_english"] = exp_a[res["id"]]

    # Run B: watsonx returns "PASS. All checks satisfied."
    _set_fake_creds(monkeypatch, "07")

    mock_client = _make_client(["ibm/granite-4-h-small"])
    mock_model  = _make_model("FUNC-001: PASS. All checks satisfied.")

    results_b = copy.deepcopy(results_base)
    outcome_b = "BLOCKED" if countersign.collect_blocking(rules, results_b) else "PASS"

    with (
        patch("ibm_watsonx_ai.APIClient",    return_value=mock_client),
        patch("ibm_watsonx_ai.Credentials"),
        patch("ibm_watsonx_ai.foundation_models.ModelInference", return_value=mock_model),
    ):
        exp_b, _ = explain_failures(results_b, rules)

    for res in results_b:
        if exp_b.get(res["id"]):
            res["plain_english"] = exp_b[res["id"]]

    statuses_a = {r["id"]: r["status"] for r in results_a}
    statuses_b = {r["id"]: r["status"] for r in results_b}
    assert statuses_a == statuses_b
    assert outcome_a  == outcome_b == "BLOCKED"


# ---------------------------------------------------------------------------
# 8. test_redact_keeps_paths
# ---------------------------------------------------------------------------

def test_redact_keeps_paths():
    """File paths and test names must not be redacted."""
    text = "demo_app/test_todo_api.py:42: AssertionError in test_delete_task_removes_item"
    assert _redact(text) == text


# ---------------------------------------------------------------------------
# 9. test_redact_strips_secrets
# ---------------------------------------------------------------------------

def test_redact_strips_secrets(monkeypatch):
    """All four secret patterns must be redacted; env-var value with - and _ included."""
    # Build secrets at runtime — never as literals
    akia    = "AKIA" + "Q" * 16                          # AWS key prefix rule
    mixed   = "aB3" * 10                                 # 30 chars, digit+letter, no path chars
    hexval  = hashlib.sha256(b"test").hexdigest()         # 64-char hex hash
    fake_val = "fake" + "-api" + "_key-" + "9xValue"     # contains - and _; picked up by env rule

    monkeypatch.setenv("FAKE_API_KEY", fake_val)

    assert _redact(akia)   == "[REDACTED]"
    assert _redact(mixed)  == "[REDACTED]"
    assert _redact(hexval) == "[REDACTED]"
    assert "[REDACTED]" in _redact("some output " + fake_val + " end")
    assert fake_val not in _redact("some output " + fake_val + " end")


# ---------------------------------------------------------------------------
# 10. test_draft_rules_invalid_writes_nothing
# ---------------------------------------------------------------------------

def test_draft_rules_invalid_writes_nothing(monkeypatch, tmp_path):
    """Non-YAML and YAML with bad priority both -> exit 1, no proposed file written."""
    _set_fake_creds(monkeypatch, "10")
    monkeypatch.chdir(tmp_path)

    (tmp_path / "countersign.yaml").write_text("", encoding="utf-8")
    spec = tmp_path / "spec.md"
    spec.write_text("# Spec\nCheck everything.", encoding="utf-8")

    # Case A: non-YAML output
    with patch("wx_explain.draft_explain", return_value=("not: valid: yaml: [[[", "ibm/granite-4-h-small")):
        rc = countersign.cmd_draft_rules(str(spec))

    assert rc == 1
    assert not (tmp_path / "countersign.proposed.yaml").exists()

    # Case B: YAML with bad priority value
    bad_priority_yaml = """\
- id: SEC-010
  requirement: Some check
  priority: invalid_priority
  check: "python -m pytest"
  paths:
    - "**/*.py"
  ai_access: read
"""
    with patch("wx_explain.draft_explain", return_value=(bad_priority_yaml, "ibm/granite-4-h-small")):
        rc2 = countersign.cmd_draft_rules(str(spec))

    assert rc2 == 1
    assert not (tmp_path / "countersign.proposed.yaml").exists()


# ---------------------------------------------------------------------------
# 11. test_draft_rules_valid_writes_proposed
# ---------------------------------------------------------------------------

def test_draft_rules_valid_writes_proposed(monkeypatch, tmp_path):
    """Fenced valid YAML -> file written, fences stripped, content is valid."""
    _set_fake_creds(monkeypatch, "11")
    monkeypatch.chdir(tmp_path)

    (tmp_path / "countersign.yaml").write_text("", encoding="utf-8")
    spec = tmp_path / "spec.md"
    spec.write_text("# Spec\nCheck test coverage.", encoding="utf-8")

    fenced = f"```yaml\n{_VALID_PROPOSED_YAML}```"

    with patch("wx_explain.draft_explain", return_value=(fenced, "ibm/granite-4-h-small")):
        rc = countersign.cmd_draft_rules(str(spec))

    assert rc == 0
    proposed = tmp_path / "countersign.proposed.yaml"
    assert proposed.exists()
    content = proposed.read_text(encoding="utf-8")
    assert "```" not in content           # fences stripped
    parsed = yaml.safe_load(content)
    assert isinstance(parsed, list)
    assert parsed[0]["id"] == "SEC-010"


# ---------------------------------------------------------------------------
# 12. test_draft_rules_never_touches_approved
# ---------------------------------------------------------------------------

def test_draft_rules_never_touches_approved(monkeypatch, tmp_path):
    """countersign.yaml and .countersign/approved_rules.sha256 are byte-identical
    before and after a successful draft-rules run."""
    _set_fake_creds(monkeypatch, "12")
    monkeypatch.chdir(tmp_path)

    cs_yaml = tmp_path / "countersign.yaml"
    cs_yaml.write_text("# placeholder\n", encoding="utf-8")

    approved_dir  = tmp_path / ".countersign"
    approved_dir.mkdir()
    approved_file = approved_dir / "approved_rules.sha256"
    approved_file.write_text("abc123", encoding="utf-8")

    spec = tmp_path / "spec.md"
    spec.write_text("# Spec", encoding="utf-8")

    before_yaml     = cs_yaml.read_bytes()
    before_approved = approved_file.read_bytes()

    with patch("wx_explain.draft_explain", return_value=(_VALID_PROPOSED_YAML, "ibm/granite-4-h-small")):
        rc = countersign.cmd_draft_rules(str(spec))

    assert rc == 0
    assert cs_yaml.read_bytes()       == before_yaml
    assert approved_file.read_bytes() == before_approved


# ---------------------------------------------------------------------------
# 13. test_draft_rules_rejects_multiline_check
# ---------------------------------------------------------------------------

def test_draft_rules_rejects_multiline_check(monkeypatch, tmp_path):
    """A check value containing a newline -> exit 1, no file written."""
    _set_fake_creds(monkeypatch, "13")
    monkeypatch.chdir(tmp_path)

    (tmp_path / "countersign.yaml").write_text("", encoding="utf-8")
    spec = tmp_path / "spec.md"
    spec.write_text("# Spec", encoding="utf-8")

    multiline_check_yaml = (
        "- id: SEC-010\n"
        "  requirement: Some check\n"
        "  priority: security\n"
        "  check: |\n"
        "    python -m pytest\n"
        "    echo done\n"
        "  paths:\n"
        "    - '**/*.py'\n"
        "  ai_access: read\n"
    )

    with patch("wx_explain.draft_explain", return_value=(multiline_check_yaml, "ibm/granite-4-h-small")):
        rc = countersign.cmd_draft_rules(str(spec))

    assert rc == 1
    assert not (tmp_path / "countersign.proposed.yaml").exists()
