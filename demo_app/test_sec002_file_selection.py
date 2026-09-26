"""
demo_app/test_sec002_file_selection.py

Tests for the SEC-002 file-selection behaviour introduced in F1/F2.

Verifies:
  - get_all_scannable_files returns tracked + untracked files, not deleted ones
  - cmd_check returns 1 and SEC-002 is FAIL when a scannable file contains a fake secret
  - cmd_check returns 0 and SEC-002 is PASS when no secrets are present (control)
  - cmd_run records SEC-002 UNVERIFIED (not FAIL) when nothing is staged
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import countersign

# ---------------------------------------------------------------------------
# Credentials env vars to clear
# ---------------------------------------------------------------------------

_CRED_VARS = ("IBM_CLOUD_API_KEY", "WATSONX_URL", "WATSONX_PROJECT_ID")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _git_init(path: Path) -> None:
    """Initialise a minimal git repo with a commit so HEAD exists."""
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)
    (path / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
    subprocess.run(["git", "add", ".gitignore"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-m", "init", "--allow-empty"], cwd=path, check=True)


def _fake_key() -> str:
    """Build a fake AWS-style key that detect-secrets will flag without hardcoding."""
    return "AK" + "IA" + "A" * 16


# No baseline flag: pre_commit_hook exits 1 whenever it finds a new secret.
_SEC002_YAML = """\
- id: SEC-002
  requirement: No secrets committed
  priority: security
  check: "python -m detect_secrets.pre_commit_hook"
  paths:
    - "**/*"
  ai_access: read
"""


def _setup_sec002_repo(tmp_path: Path, monkeypatch, file_content: str) -> None:
    """Shared setup: git init, write countersign.yaml and records/, commit a target file."""
    _git_init(tmp_path)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "countersign.yaml").write_text(_SEC002_YAML, encoding="utf-8")
    (tmp_path / "records").mkdir()
    target = tmp_path / "creds.py"
    target.write_text(file_content, encoding="utf-8")
    subprocess.run(["git", "add", "creds.py", "countersign.yaml"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "add creds"], cwd=tmp_path, check=True)


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

    monkeypatch.setattr("ibm_watsonx_ai.APIClient", _no_call, raising=False)
    monkeypatch.setattr("ibm_watsonx_ai.foundation_models.ModelInference", _no_call, raising=False)


# ---------------------------------------------------------------------------
# F3-a: get_all_scannable_files filters correctly
# ---------------------------------------------------------------------------


def test_get_all_scannable_files(tmp_path, monkeypatch):
    """get_all_scannable_files returns tracked + untracked files, excludes deleted."""
    _git_init(tmp_path)
    monkeypatch.chdir(tmp_path)

    # tracked file
    tracked = tmp_path / "tracked.py"
    tracked.write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "add tracked"], cwd=tmp_path, check=True)

    # untracked (not ignored)
    untracked = tmp_path / "untracked.py"
    untracked.write_text("y = 2\n", encoding="utf-8")

    # deleted-from-disk file (staged as deleted)
    gone = tmp_path / "gone.py"
    gone.write_text("z = 3\n", encoding="utf-8")
    subprocess.run(["git", "add", "gone.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "add gone"], cwd=tmp_path, check=True)
    gone.unlink()
    subprocess.run(["git", "rm", "gone.py"], cwd=tmp_path, check=True)

    result = countersign.get_all_scannable_files()

    assert "tracked.py" in result
    assert "untracked.py" in result
    assert "gone.py" not in result, "deleted file must be excluded"


# ---------------------------------------------------------------------------
# F3-b: SEC-002 FAIL when file contains a fake secret
# ---------------------------------------------------------------------------


def test_cmd_check_fails_on_fake_secret(tmp_path, monkeypatch):
    """cmd_check exits 1 and SEC-002 is FAIL when a file contains a detectable key."""
    _setup_sec002_repo(tmp_path, monkeypatch, f'KEY = "{_fake_key()}"\n')

    rules = countersign.load_rules()
    all_files = countersign.get_all_scannable_files()
    results = countersign.run_checks(rules, staged_files=[], scannable_files=all_files)
    sec002 = next(r for r in results if r["id"] == "SEC-002")
    print(f"\n[test_cmd_check_fails_on_fake_secret] SEC-002 output: {sec002['output']!r}")

    assert sec002["status"] == "FAIL", (
        f"expected SEC-002 FAIL, got {sec002['status']!r}. Output: {sec002['output']}"
    )

    rc = countersign.cmd_check()
    assert rc == 1, f"cmd_check must return 1 when SEC-002 is FAIL, got {rc}"


# ---------------------------------------------------------------------------
# F3-b control: SEC-002 PASS when file is clean
# ---------------------------------------------------------------------------


def test_cmd_check_passes_on_clean_file(tmp_path, monkeypatch):
    """cmd_check exits 0 and SEC-002 is PASS when no secrets are present."""
    _setup_sec002_repo(tmp_path, monkeypatch, "x = 1\n")

    rules = countersign.load_rules()
    all_files = countersign.get_all_scannable_files()
    results = countersign.run_checks(rules, staged_files=[], scannable_files=all_files)
    sec002 = next(r for r in results if r["id"] == "SEC-002")
    print(f"\n[test_cmd_check_passes_on_clean_file] SEC-002 output: {sec002['output']!r}")

    assert sec002["status"] == "PASS", (
        f"expected SEC-002 PASS, got {sec002['status']!r}. Output: {sec002['output']}"
    )

    rc = countersign.cmd_check()
    assert rc == 0, f"cmd_check must return 0 on clean file, got {rc}"


# ---------------------------------------------------------------------------
# F3-c: cmd_run records SEC-002 UNVERIFIED when nothing is staged
# ---------------------------------------------------------------------------


def test_cmd_run_sec002_unverified_when_nothing_staged(tmp_path, monkeypatch):
    """With nothing staged, run_checks marks SEC-002 UNVERIFIED (not FAIL)."""
    _git_init(tmp_path)
    monkeypatch.chdir(tmp_path)

    (tmp_path / "countersign.yaml").write_text(_SEC002_YAML, encoding="utf-8")
    (tmp_path / "records").mkdir()
    (tmp_path / ".countersign").mkdir()
    import hashlib
    raw = (tmp_path / "countersign.yaml").read_text(encoding="utf-8")
    normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
    sha = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    (tmp_path / ".countersign" / "approved_rules.sha256").write_text(sha + "\n", encoding="utf-8")

    rules = countersign.load_rules()
    results = countersign.run_checks(rules, staged_files=[], scannable_files=[])

    sec002 = next(r for r in results if r["id"] == "SEC-002")
    assert sec002["status"] == "UNVERIFIED", (
        f"SEC-002 must be UNVERIFIED when nothing is staged, got {sec002['status']}"
    )
    assert "staged" in sec002["output"].lower(), (
        f"UNVERIFIED message should mention 'staged', got: {sec002['output']!r}"
    )
