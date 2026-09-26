"""
demo_app/test_z_optin.py -- Z approval is opt-in in `countersign run`.

Covers:
  ZOPT-1. ZOS_USS_DIR unset, COUNTERSIGN_REQUIRE_Z unset -> z_status
          not_configured, no Z call, commit not blocked.
  ZOPT-2. ZOS_USS_DIR set, Z unreachable -> unavailable, blocked (fail closed).
  ZOPT-3. COUNTERSIGN_REQUIRE_Z=1, ZOS_USS_DIR unset -> unavailable, blocked.
  ZOPT-4. Dashboard renders z_status not_configured as "Not configured", and
          uses `-m countersign` when launched by `countersign dashboard`.
  ZOPT-5. The Z user in ZOS_USS_DIR is printed as <zuser> by run and z-audit;
          Zowe calls still use the real path.

Checks, watsonx, and Zowe are all stubbed; runs in an empty tmp dir.
"""
from __future__ import annotations

import json
import subprocess
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

_REPO = Path(__file__).parent.parent
sys.path.insert(0, str(_REPO))
import countersign

_RULES = """\
- id: SEC-001
  requirement: stub
  priority: security
  check: "stub"
  paths: ["**/*"]
  ai_access: read
"""


@pytest.fixture
def zowe_calls(tmp_path, monkeypatch) -> list[list[str]]:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "countersign.yaml").write_text(_RULES, encoding="utf-8")
    for var in ("CI", "ZOS_USS_DIR", "COUNTERSIGN_REQUIRE_Z"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(countersign, "_run", lambda cmd, extra=None: (0, ""))
    fake_wx = types.ModuleType("wx_explain")
    fake_wx.explain_failures = lambda results, rules: ({}, "", "")
    monkeypatch.setitem(sys.modules, "wx_explain", fake_wx)

    calls: list[list[str]] = []

    def _unreachable(args, timeout=30):
        calls.append(args)
        return -1, "zowe CLI not found"

    monkeypatch.setattr(countersign, "_zowe", _unreachable)
    return calls


def _record(tmp_path: Path) -> dict:
    (rec,) = sorted((tmp_path / "records").glob("*.json"))
    return json.loads(rec.read_bytes())


def test_unset_is_not_configured(tmp_path, zowe_calls, capsys):
    assert countersign.cmd_run(skip_z=False) == 0
    assert _record(tmp_path)["z_status"] == "not_configured"
    assert zowe_calls == []
    out = capsys.readouterr().out
    assert sum("not configured" in ln for ln in out.splitlines()) == 1
    assert "commit approved" in out


def test_set_and_unreachable_blocks(tmp_path, zowe_calls, monkeypatch):
    monkeypatch.setenv("ZOS_USS_DIR", "/u/someone/countersign")
    assert countersign.cmd_run(skip_z=False) == 1
    assert _record(tmp_path)["z_status"] == "unavailable"
    assert zowe_calls  # Z was attempted


@pytest.mark.parametrize(
    ("real", "shown"),
    [
        ("//z/IBMUSER/countersign", "//z/<zuser>/countersign"),
        ("/u/someone/countersign", "/u/<zuser>/countersign"),
        ("/u/someone/countersign/approved.log", "/u/<zuser>/countersign/approved.log"),
        ("/u/someone", "/u/<zuser>"),
        ("countersign", "countersign"),
    ],
)
def test_mask_uss_dir(real, shown):
    assert countersign.mask_uss_dir(real) == shown


def test_run_and_z_audit_mask_user(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ZOS_USS_DIR", "//z/SECRETU/countersign")
    zowe_args: list[list[str]] = []

    def _fail(args, timeout=30):
        zowe_args.append(args)
        return 1, "upload to //z/SECRETU/countersign/x failed"

    monkeypatch.setattr(countersign, "_zowe", _fail)
    rec = tmp_path / "r.json"
    rec.write_text("{}", encoding="utf-8")
    assert countersign._run_z_approval(rec)[0] == "unavailable"
    assert countersign.cmd_z_audit() == 1
    out = capsys.readouterr().out
    assert "SECRETU" not in out
    assert "//z/<zuser>/countersign" in out
    assert "//z/<zuser>/countersign/approved.log" in out
    # Zowe itself still gets the real path.
    assert any("//z/SECRETU/countersign/verify_record.py" in a for a in zowe_args[0])
    assert "//z/SECRETU/countersign/approved.log" in zowe_args[1]


def test_required_but_unset_blocks(tmp_path, zowe_calls, monkeypatch):
    monkeypatch.setenv("COUNTERSIGN_REQUIRE_Z", "1")
    assert countersign.cmd_run(skip_z=False) == 1
    assert _record(tmp_path)["z_status"] == "unavailable"
    assert zowe_calls == []  # blocked before any Zowe call


# ---------------------------------------------------------------------------
# ZOPT-4: dashboard
# ---------------------------------------------------------------------------

_APP = _REPO / "dashboard" / "app.py"


def _dashboard(tmp_path, monkeypatch) -> tuple[object, list]:
    from streamlit.testing.v1 import AppTest

    monkeypatch.chdir(tmp_path)
    records = tmp_path / "records"
    records.mkdir()
    # load_records is st.cache_data'd per path string; a unique absolute path
    # keeps other dashboard tests' cached (empty) "records" out of this run.
    monkeypatch.setenv("COUNTERSIGN_RECORDS_DIR", str(records))
    rec = {
        "timestamp": "20260926T000000Z",
        "git_hash": "abc",
        "prev_record_fingerprint": "genesis",
        "outcome": "PASS",
        "z_status": "not_configured",
        "z_job_id": None,
        "z_rc": None,
        "z_verified_hash": None,
        "results": [],
    }
    (records / "20260926T000000Z_00000000.json").write_text(json.dumps(rec), encoding="utf-8")
    calls = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "PASS: Chain intact across 1 record(s).\n", "")

    with patch("subprocess.run", side_effect=fake_run):
        at = AppTest.from_file(str(_APP), default_timeout=30).run()
    assert not at.exception
    return at, calls


def test_dashboard_renders_not_configured(tmp_path, monkeypatch):
    monkeypatch.delenv("COUNTERSIGN_VERIFY_VIA_MODULE", raising=False)
    at, _ = _dashboard(tmp_path, monkeypatch)
    df = at.dataframe[0].value
    assert list(df["Z Approval"]) == ["Not configured"]


def test_dashboard_module_mode_calls_installed_cli(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNTERSIGN_VERIFY_VIA_MODULE", "1")
    _, calls = _dashboard(tmp_path, monkeypatch)
    assert calls == [[sys.executable, "-m", "countersign", "verify-chain"]]
