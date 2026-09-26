"""
demo_app/test_init.py -- Tests for `countersign init`.

Covers:
  INIT-1. Fresh repo root: every starter file is created; hook is LF sh.
  INIT-2. Second run skips every existing file.
  INIT-3. --force overwrites.
  INIT-4. Refuses outside a repo root (subdirectory, and no repo at all).
  INIT-5. An existing non-Countersign hook is not overwritten without --force.
  INIT-6. --z also writes zos/VERIFY.jcl and zos/verify_record.py.

Each test runs in its own `git init` tmp dir. detect-secrets runs for real
(local scan, no network); approve-rules is never called.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).parent.parent
sys.path.insert(0, str(_REPO))
import countersign

_FILES = (
    "countersign.yaml",
    ".leak-baseline.json",
    ".git/hooks/pre-commit",
    ".github/workflows/countersign.yml",
    "records/.gitkeep",
)


@pytest.fixture
def repo(tmp_path, monkeypatch) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _init(capsys, *, force: bool = False, with_z: bool = False) -> tuple[int, str]:
    rc = countersign.cmd_init(force=force, with_z=with_z)
    return rc, capsys.readouterr().out


def test_init_creates_files(repo, capsys):
    rc, out = _init(capsys)
    assert rc == 0, out
    for rel in _FILES:
        assert (repo / rel).is_file(), rel
    assert out.count("created") == len(_FILES)
    assert "approve-rules" in out  # next steps printed

    rules = yaml.safe_load((repo / "countersign.yaml").read_text(encoding="utf-8"))
    by_id = {r["id"]: r for r in rules}
    assert list(by_id) == ["SEC-001", "SEC-002", "SEC-003", "SEC-004", "FUNC-001", "QUAL-001"]
    assert by_id["SEC-003"]["check"] == "python -m countersign verify-rules"
    assert by_id["SEC-004"]["check"] == "python -m countersign verify-chain"
    assert by_id["FUNC-001"]["check"] == ""
    assert "replace with your test command" in (repo / "countersign.yaml").read_text(encoding="utf-8")

    baseline = json.loads((repo / ".leak-baseline.json").read_text(encoding="utf-8"))
    assert "results" in baseline

    hook = (repo / ".git/hooks/pre-commit").read_bytes()
    assert hook.startswith(b"#!/usr/bin/env sh\n")
    assert b"\r\n" not in hook
    assert b"-m countersign run" in hook
    assert b"COUNTERSIGN_SKIP_Z" in hook

    wf = (repo / ".github/workflows/countersign.yml").read_text(encoding="utf-8")
    assert "git+https://github.com/Raven-V1/Countersign" in wf
    assert "python -m countersign ci" in wf

    assert not (repo / ".countersign").exists()  # init never approves
    assert not (repo / "zos").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="no POSIX exec bit on Windows")
def test_init_hook_executable(repo, capsys):
    _init(capsys)
    assert (repo / ".git/hooks/pre-commit").stat().st_mode & 0o111


def test_second_run_skips(repo, capsys):
    _init(capsys)
    (repo / "countersign.yaml").write_text("# mine\n", encoding="utf-8")
    rc, out = _init(capsys)
    assert rc == 0, out
    assert out.count("skipped") == len(_FILES)
    assert "created" not in out
    assert (repo / "countersign.yaml").read_text(encoding="utf-8") == "# mine\n"


def test_force_overwrites(repo, capsys):
    _init(capsys)
    (repo / "countersign.yaml").write_text("# mine\n", encoding="utf-8")
    rc, out = _init(capsys, force=True)
    assert rc == 0, out
    assert out.count("overwritten") == len(_FILES)
    assert "SEC-001" in (repo / "countersign.yaml").read_text(encoding="utf-8")


def test_refuses_in_subdirectory(repo, capsys, monkeypatch):
    sub = repo / "pkg"
    sub.mkdir()
    monkeypatch.chdir(sub)
    rc, out = _init(capsys)
    assert rc == 1
    assert "root of a git repository" in out
    assert list(sub.iterdir()) == []
    assert not (repo / "countersign.yaml").exists()


def test_refuses_outside_repo(tmp_path, capsys, monkeypatch):
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.chdir(plain)
    # Stop git from finding a repo above tmp_path.
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    rc, out = _init(capsys)
    assert rc == 1
    assert "root of a git repository" in out
    assert list(plain.iterdir()) == []


def test_foreign_hook_not_overwritten(repo, capsys):
    hook = repo / ".git/hooks/pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_bytes(b"#!/bin/sh\nexec lint-staged\n")
    rc, out = _init(capsys)
    assert rc == 1
    assert "REFUSED" in out
    assert hook.read_bytes() == b"#!/bin/sh\nexec lint-staged\n"

    rc, out = _init(capsys, force=True)
    assert rc == 0, out
    assert b"-m countersign run" in hook.read_bytes()


def test_init_with_z(repo, capsys):
    rc, out = _init(capsys, with_z=True)
    assert rc == 0, out
    for name in ("VERIFY.jcl", "verify_record.py"):
        written = (repo / "zos" / name).read_bytes()
        assert written == (_REPO / "zos" / name).read_bytes().replace(b"\r\n", b"\n")
    assert "ZOS_USS_DIR" in out
