"""
demo_app/test_dashboard_connect.py -- Dashboard "Connect a repo" / "Upload records".

Covers:
  CON-1. verify_chain_bytes matches cmd_verify_chain on the real records/ (parity),
         and reports FAIL on a tampered chain.
  CON-2. Good repo zip -> PASS notice, banner, no subprocess after connecting.
  CON-3. Tampered record -> FAIL ("Chain broken") notice.
  CON-4. Invalid owner/repo and a "../" branch are rejected without any fetch.
  CON-5. Oversize download, too many record files, and a >1 MB record are rejected.
  CON-6. HTTP 404 -> grey UNVERIFIED notice, never "Chain broken".
  CON-7. plain_english with markdown link/image syntax renders as literal text.
  CON-8. Uploads use the same verify path; Disconnect returns to the default view.

No network: fetch_zip is stubbed with an in-memory zip, or urllib's opener is
stubbed to exercise fetch_zip's own error handling. subprocess.run is stubbed.
"""
from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import urllib.error
import zipfile
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

_REPO = Path(__file__).parent.parent
sys.path.insert(0, str(_REPO))
import countersign
import countersign_connect as connect

_APP = _REPO / "dashboard" / "app.py"
_EVIL = "[click me](https://evil.example) ![img](https://evil.example/x.png) **bold**"

_RULES_YAML = b"""\
- id: SEC-001
  requirement: No secrets
  priority: security
  check: "x"
  paths: ["**/*"]
  ai_access: read
"""


def _record(prev: str, *, outcome: str = "PASS", plain: str = "", status: str = "PASS") -> bytes:
    rec = {
        "timestamp": "20260926T000000Z",
        "git_hash": "abc123",
        "prev_record_fingerprint": prev,
        "outcome": outcome,
        "z_status": "not_configured",
        "z_job_id": None,
        "z_rc": None,
        "z_verified_hash": None,
        "wx_model_id": "",
        "wx_error": "",
        "results": [
            {"id": "SEC-001", "status": status, "check": "x", "output": "out", "plain_english": plain}
        ],
    }
    return json.dumps(rec, indent=2).encode("utf-8")


def _chain(n: int = 2, **kw) -> list[tuple[str, bytes]]:
    files, prev = [], "genesis"
    for i in range(n):
        raw = _record(prev, **kw)
        files.append((f"20260926T00000{i}Z_0000000{i}.json", raw))
        prev = hashlib.sha256(raw).hexdigest()
    return files


def _zip(files: list[tuple[str, bytes]], rules: bytes | None = _RULES_YAML) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("repo-main/README.md", "hello")
        for name, raw in files:
            zf.writestr(f"repo-main/records/{name}", raw)
        if rules is not None:
            zf.writestr("repo-main/countersign.yaml", rules)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# CON-1: verify_chain_bytes
# ---------------------------------------------------------------------------


def test_verify_chain_bytes_parity_with_cmd(monkeypatch, capsys):
    monkeypatch.chdir(_REPO)
    rc = countersign.cmd_verify_chain()
    printed = capsys.readouterr().out.strip()
    files = [(f.name, f.read_bytes()) for f in (_REPO / "records").glob("*.json")]
    status, msg = countersign.verify_chain_bytes(files)
    assert (rc == 0) == (status == "PASS")
    assert printed == f"{status}: {msg}"
    assert status == "PASS"


def test_verify_chain_bytes_tampered():
    files = _chain(3)
    name, raw = files[1]
    files[1] = (name, raw.replace(b'"outcome": "PASS"', b'"outcome": "BLOCKED"'))
    status, msg = countersign.verify_chain_bytes(list(reversed(files)))  # order-independent
    assert status == "FAIL"
    assert "Chain broken at record " + files[2][0] in msg


# ---------------------------------------------------------------------------
# App harness
# ---------------------------------------------------------------------------


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Run the dashboard in an empty dir; record subprocess and fetch calls."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("COUNTERSIGN_VERIFY_VIA_MODULE", raising=False)
    monkeypatch.setenv("COUNTERSIGN_RECORDS_DIR", str(tmp_path / "records"))
    calls = {"subprocess": [], "fetch": []}

    def fake_run(cmd, *a, **kw):
        calls["subprocess"].append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "PASS: No records yet.\n", "")

    monkeypatch.setattr(subprocess, "run", fake_run)

    def use_zip(data: bytes) -> None:
        def fake_fetch(owner, repo, branch):
            calls["fetch"].append((owner, repo, branch))
            return data

        monkeypatch.setattr(connect, "fetch_zip", fake_fetch)

    at = AppTest.from_file(str(_APP), default_timeout=30).run()
    assert not at.exception
    return at, calls, use_zip


def _connect(at: AppTest, repo: str, branch: str = "main") -> AppTest:
    at.sidebar.text_input(key="cs_repo").input(repo)
    at.sidebar.text_input(key="cs_branch").input(branch)
    at.sidebar.button(key="cs_connect").click()
    at.run()
    assert not at.exception
    return at


def _notices(at: AppTest) -> list[str]:
    return [h.proto.body for h in at.get("html") if h.proto.body.startswith('<div class="cs-notif ')]


def _banner(at: AppTest) -> str:
    return next((h.proto.body for h in at.get("html") if "cs-banner" in h.proto.body), "")


# ---------------------------------------------------------------------------
# CON-2..4
# ---------------------------------------------------------------------------


def test_good_repo_pass(app):
    at, calls, use_zip = app
    use_zip(_zip(_chain(3)))
    before = len(calls["subprocess"])
    _connect(at, "https://github.com/Owner/my.repo")
    assert calls["fetch"] == [("Owner", "my.repo", "main")]
    (notice,) = _notices(at)
    assert "cs-notif--success" in notice and "Chain intact across 3 record(s)" in notice
    assert "Viewing <code>Owner/my.repo@main</code>" in _banner(at)
    assert len(calls["subprocess"]) == before  # connected view never runs a subprocess
    assert len(at.dataframe[0].value) == 3


def test_tampered_record_fail(app):
    at, _, use_zip = app
    files = _chain(3)
    name, raw = files[0]
    files[0] = (name, raw.replace(b'"git_hash": "abc123"', b'"git_hash": "abc124"'))
    use_zip(_zip(files))
    _connect(at, "owner/repo")
    (notice,) = _notices(at)
    assert "cs-notif--error" in notice and "Chain broken" in notice


@pytest.mark.parametrize(
    ("repo", "branch"),
    [
        ("owner", "main"),
        ("own er/repo", "main"),
        ("owner/repo/extra", "main"),
        ("https://evil.example/owner/repo", "main"),
        ("owner/..", "main"),
        ("owner/repo", "../main"),
        ("owner/repo", "feature/../x"),
        ("owner/repo", "main;rm"),
    ],
)
def test_invalid_input_rejected_without_fetch(app, repo, branch):
    at, calls, use_zip = app
    use_zip(_zip(_chain(1)))
    _connect(at, repo, branch)
    assert calls["fetch"] == []
    assert at.sidebar.error, "expected a validation message"
    assert _banner(at) == ""  # still the default view


# ---------------------------------------------------------------------------
# CON-5: caps
# ---------------------------------------------------------------------------


class _Resp:
    def __init__(self, data: bytes, length: str | None = None):
        self._data, self.headers = data, {"Content-Length": length} if length else {}

    def read(self, n=-1):
        return self._data if n < 0 else self._data[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _opener(monkeypatch, resp=None, exc=None) -> list[str]:
    urls: list[str] = []

    class _Opener:
        def open(self, url, timeout=None):
            urls.append(url)
            assert timeout == connect.FETCH_TIMEOUT
            if exc is not None:
                raise exc
            return resp

    monkeypatch.setattr(connect.urllib.request, "build_opener", lambda *h: _Opener())
    return urls


def test_oversize_download_rejected(monkeypatch):
    monkeypatch.setattr(connect, "MAX_DOWNLOAD", 100)
    _opener(monkeypatch, _Resp(b"x" * 10, length="101"))
    with pytest.raises(connect.LoadError, match="larger than"):
        connect.fetch_zip("o", "r", "main")
    urls = _opener(monkeypatch, _Resp(b"x" * 101))  # no Content-Length: counted while reading
    with pytest.raises(connect.LoadError, match="larger than"):
        connect.fetch_zip("o", "r", "feature/x")
    assert urls == ["https://codeload.github.com/o/r/zip/refs/heads/feature/x"]


def test_too_many_record_files_rejected(monkeypatch):
    monkeypatch.setattr(connect, "MAX_RECORD_FILES", 3)
    with pytest.raises(connect.LoadError, match="More than 3 record files"):
        connect.extract_zip(_zip(_chain(4)))
    records, rules = connect.extract_zip(_zip(_chain(3)))
    assert len(records) == 3 and rules == _RULES_YAML


def test_oversize_record_and_total_rejected(monkeypatch):
    big = [("big.json", b" " * (connect.MAX_FILE + 1))]
    with pytest.raises(connect.LoadError, match="larger than 1 MB"):
        connect.extract_zip(_zip(big))
    monkeypatch.setattr(connect, "MAX_RECORDS_TOTAL", 1000)
    with pytest.raises(connect.LoadError, match="Records total"):
        connect.extract_zip(_zip(_chain(3)))


def test_oversize_zip_shows_unverified(app, monkeypatch):
    at, _, _ = app
    monkeypatch.setattr(connect, "MAX_DOWNLOAD", 100)
    _opener(monkeypatch, _Resp(b"x" * 101))
    _connect(at, "owner/repo")
    (notice,) = _notices(at)
    assert "cs-notif--unverified" in notice and "larger than" in notice
    assert "Chain broken" not in notice


# ---------------------------------------------------------------------------
# CON-6: 404
# ---------------------------------------------------------------------------


def test_404_shows_unverified(app, monkeypatch):
    at, _, _ = app
    err = urllib.error.HTTPError("https://codeload.github.com/x", 404, "Not Found", {}, None)
    _opener(monkeypatch, exc=err)
    _connect(at, "owner/private-repo")
    (notice,) = _notices(at)
    assert "cs-notif--unverified" in notice
    assert "could not load owner/private-repo@main" in notice
    assert "private" in notice
    assert "Chain broken" not in notice


def test_no_records_shows_unverified(app):
    at, _, use_zip = app
    use_zip(_zip([]))
    _connect(at, "owner/repo")
    (notice,) = _notices(at)
    assert "cs-notif--unverified" in notice and "No records found" in notice


# ---------------------------------------------------------------------------
# CON-7: untrusted text is literal
# ---------------------------------------------------------------------------


def test_markdown_in_plain_english_is_literal(app):
    at, _, use_zip = app
    use_zip(_zip(_chain(1, outcome="BLOCKED", status="FAIL", plain=_EVIL)))
    _connect(at, "owner/repo")
    at.session_state["cs_timeline:owner/repo@main"] = {
        "selection": {"rows": [0], "columns": [], "cells": []}
    }
    at.run()
    assert not at.exception
    texts = [t.value for t in at.text]
    assert _EVIL in texts
    assert any(t.startswith("Record file: ") for t in texts)
    rendered_md = [m.value for m in at.markdown] + [i.value for i in at.info]
    assert not any("evil.example" in v for v in rendered_md)
    assert not any("evil.example" in h.proto.body for h in at.get("html"))


def test_missing_rules_hides_requirements(app):
    at, _, use_zip = app
    use_zip(_zip(_chain(2), rules=None))
    _connect(at, "owner/repo")
    at.session_state["cs_timeline:owner/repo@main"] = {
        "selection": {"rows": [0], "columns": [], "cells": []}
    }
    at.run()
    assert len(at.dataframe[0].value) == 2
    assert not any(s.value == "Requirements" for s in at.subheader)
    assert any("requirements panel is hidden" in c.value for c in at.caption)


# ---------------------------------------------------------------------------
# CON-8: uploads + disconnect
# ---------------------------------------------------------------------------


def test_uploads_same_verify_path():
    good = connect.load_uploads(_chain(2), _RULES_YAML)
    assert good["chain"][0] == "PASS" and good["error"] is None
    assert [r["id"] for r in good["rules"]] == ["SEC-001"]

    files = _chain(2)
    files[0] = (files[0][0], files[0][1] + b" ")
    assert connect.load_uploads(files, None)["chain"][0] == "FAIL"

    too_big = connect.load_uploads([("a.json", b" " * (connect.MAX_FILE + 1))], None)
    assert too_big["error"] and too_big["chain"] is None

    # Upload names are reduced to a base name.
    named = connect.load_uploads([("..\\..\\x.json", _chain(1)[0][1])], None)
    assert named["records"][0]["_filename"] == "x.json"


def test_disconnect_returns_to_default(app):
    at, _, use_zip = app
    use_zip(_zip(_chain(2)))
    _connect(at, "owner/repo")
    assert _banner(at)
    at.button(key="cs_disconnect").click()
    at.run()
    assert _banner(at) == ""
    assert "cs_source" not in at.session_state
    (notice,) = _notices(at)
    assert "No records yet" in notice  # default view's verify-chain again
