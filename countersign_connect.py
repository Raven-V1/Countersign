"""
countersign_connect.py — load another repo's Countersign records for the dashboard.

Two sources, one verify path:
  load_github(owner, repo, branch)   one codeload zip download, read in memory
  load_uploads(records, rules_yaml)  files a user uploaded to the dashboard

Everything here treats the data as untrusted: nothing is written to disk,
nothing from the repo is executed or imported, no subprocess runs. The chain
is verified with countersign.verify_chain_bytes on the raw bytes; display
fields are normalised so they can be rendered as plain text.
"""

from __future__ import annotations

import io
import json
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import yaml

from countersign import verify_chain_bytes

CODELOAD_HOST = "codeload.github.com"
FETCH_TIMEOUT = 15
MAX_DOWNLOAD = 25 * 1024 * 1024
MAX_RECORDS_TOTAL = 10 * 1024 * 1024
MAX_RECORD_FILES = 2000
MAX_FILE = 1024 * 1024

_REPO_RE = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")
_URL_RE = re.compile(r"^https://github\.com/([^/?#]+/[^/?#]+?)(?:\.git)?/?$")
_ZIP_RECORD_RE = re.compile(r"^[^/]+/records/([^/]+\.json)$")
_ZIP_RULES_RE = re.compile(r"^[^/]+/countersign\.yaml$")

_STATUSES = ("PASS", "FAIL", "UNVERIFIED")
_PRIORITIES = ("security", "functional", "quality")
_RULE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


class LoadError(Exception):
    """A repo or upload could not be loaded. The message is shown to the user."""


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def parse_repo(text: str, branch: str) -> tuple[str, str, str]:
    """Validate owner/repo (or a https://github.com/owner/repo URL) and branch.

    Returns (owner, repo, branch); raises LoadError with a clear message.
    """
    text = (text or "").strip()
    branch = (branch or "").strip()
    m = _URL_RE.match(text)
    if m:
        text = m.group(1)
    if not _REPO_RE.match(text) or text.split("/")[1] in (".", ".."):
        raise LoadError(
            "Repository must be owner/repo (letters, digits, - . _) "
            "or a https://github.com/owner/repo URL."
        )
    if not _BRANCH_RE.match(branch) or ".." in branch:
        raise LoadError("Branch may contain only letters, digits, and . _ / - (no '..').")
    owner, repo = text.split("/")
    return owner, repo, branch


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlparse(newurl)
        if parts.scheme != "https" or parts.hostname != CODELOAD_HOST:
            raise LoadError("GitHub redirected the download to another host; refused.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_zip(owner: str, repo: str, branch: str) -> bytes:
    """Download the branch zip from codeload.github.com (one request, capped)."""
    path = "/".join(urllib.parse.quote(p, safe="") for p in (owner, repo))
    url = f"https://{CODELOAD_HOST}/{path}/zip/refs/heads/{urllib.parse.quote(branch, safe='/')}"
    opener = urllib.request.build_opener(_SameHostRedirects)
    try:
        # URL is https to a fixed host; owner/repo/branch are validated above.
        with opener.open(url, timeout=FETCH_TIMEOUT) as resp:  # nosec B310
            length = resp.headers.get("Content-Length")
            if length and length.isdigit() and int(length) > MAX_DOWNLOAD:
                raise LoadError(f"Repository zip is larger than {MAX_DOWNLOAD // 2**20} MB.")
            data = resp.read(MAX_DOWNLOAD + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise LoadError(
                f"{owner}/{repo}@{branch} not found. The repo may be private, "
                "misspelled, or have no such branch. For a private repo, use Upload records."
            ) from None
        raise LoadError(f"GitHub returned HTTP {exc.code}.") from None
    except TimeoutError:
        raise LoadError(f"Download timed out after {FETCH_TIMEOUT}s.") from None
    except urllib.error.URLError as exc:
        raise LoadError(f"Could not reach GitHub ({exc.reason}).") from None
    if len(data) > MAX_DOWNLOAD:
        raise LoadError(f"Repository zip is larger than {MAX_DOWNLOAD // 2**20} MB.")
    return data


def extract_zip(data: bytes) -> tuple[list[tuple[str, bytes]], bytes | None]:
    """Read */records/*.json and */countersign.yaml from zip bytes, in memory."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise LoadError("Download is not a valid zip archive.") from None

    records: list[tuple[str, bytes]] = []
    rules: bytes | None = None
    total = 0
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            m = _ZIP_RECORD_RE.match(info.filename)
            if m:
                if len(records) >= MAX_RECORD_FILES:
                    raise LoadError(f"More than {MAX_RECORD_FILES} record files.")
                raw = _read_capped(zf, info)
                total += len(raw)
                if total > MAX_RECORDS_TOTAL:
                    raise LoadError(f"Records total more than {MAX_RECORDS_TOTAL // 2**20} MB.")
                records.append((m.group(1), raw))
            elif _ZIP_RULES_RE.match(info.filename):
                rules = _read_capped(zf, info)
    return records, rules


def _read_capped(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    if info.file_size > MAX_FILE:
        raise LoadError(f"{info.filename.split('/', 1)[-1]} is larger than 1 MB.")
    with zf.open(info) as fh:
        raw = fh.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise LoadError(f"{info.filename.split('/', 1)[-1]} is larger than 1 MB.")
    return raw


# ---------------------------------------------------------------------------
# Build a dashboard source
# ---------------------------------------------------------------------------


def _text(value: object, limit: int = 20000) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _normalise_record(name: str, data: dict) -> dict:
    """Keep only display fields, coerced to plain strings / known values."""
    results = []
    for r in data.get("results") or []:
        if not isinstance(r, dict):
            continue
        status = r.get("status")
        results.append(
            {
                "id": _text(r.get("id"), 100),
                "status": status if status in _STATUSES else "UNVERIFIED",
                "output": _text(r.get("output")),
                "plain_english": _text(r.get("plain_english")),
            }
        )
    outcome = data.get("outcome")
    z_rc = data.get("z_rc")
    return {
        "_filename": name,
        "timestamp": re.sub(r"[^0-9TZ]", "", _text(data.get("timestamp"), 40)),
        "git_hash": re.sub(r"[^0-9a-fA-F]", "", _text(data.get("git_hash"), 64)),
        "outcome": outcome if outcome in ("PASS", "BLOCKED") else "UNVERIFIED",
        "z_status": _text(data.get("z_status"), 40),
        "z_job_id": _text(data.get("z_job_id"), 40),
        "z_rc": z_rc if isinstance(z_rc, int) and not isinstance(z_rc, bool) else None,
        "results": results,
    }


def _parse_rules(raw: bytes | None) -> list[dict] | None:
    """safe_load their countersign.yaml; None when missing or unusable."""
    if raw is None:
        return None
    try:
        data = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        return None
    if not isinstance(data, list):
        return None
    rules = []
    for r in data:
        if not isinstance(r, dict):
            continue
        rid, prio = r.get("id"), r.get("priority")
        if isinstance(rid, str) and _RULE_ID_RE.match(rid) and prio in _PRIORITIES:
            rules.append({"id": rid, "priority": prio, "requirement": _text(r.get("requirement"), 500)})
    rules.sort(key=lambda r: _PRIORITIES.index(r["priority"]))
    return rules or None


def build_source(label: str, files: list[tuple[str, bytes]], rules_raw: bytes | None) -> dict:
    """Verify raw record bytes and return the dashboard's session-state source."""
    if not files:
        raise LoadError("No records found (expected records/*.json).")
    chain_status, chain_msg = verify_chain_bytes(files)
    records = []
    for name, raw in sorted(files, key=lambda f: f[0], reverse=True):
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            continue
        if isinstance(data, dict):
            records.append(_normalise_record(name, data))
    return {
        "label": label,
        "chain": (chain_status, chain_msg),
        "records": records,
        "rules": _parse_rules(rules_raw),
        "error": None,
    }


def error_source(label: str, message: str) -> dict:
    return {"label": label, "chain": None, "records": [], "rules": None, "error": message}


def load_github(owner: str, repo: str, branch: str) -> dict:
    label = f"{owner}/{repo}@{branch}"
    try:
        records, rules = extract_zip(fetch_zip(owner, repo, branch))
        return build_source(label, records, rules)
    except LoadError as exc:
        return error_source(label, str(exc))


def load_uploads(uploads: list[tuple[str, bytes]], rules_raw: bytes | None) -> dict:
    """uploads: (file name, bytes) for each uploaded .json record."""
    label = "uploaded records"
    uploads = [(name.replace("\\", "/").rsplit("/", 1)[-1][:200], raw) for name, raw in uploads]
    try:
        if len(uploads) > MAX_RECORD_FILES:
            raise LoadError(f"More than {MAX_RECORD_FILES} record files.")
        if any(len(raw) > MAX_FILE for _, raw in uploads) or (
            rules_raw is not None and len(rules_raw) > MAX_FILE
        ):
            raise LoadError("Each file must be 1 MB or smaller.")
        if sum(len(raw) for _, raw in uploads) > MAX_RECORDS_TOTAL:
            raise LoadError(f"Records total more than {MAX_RECORDS_TOTAL // 2**20} MB.")
        return build_source(label, uploads, rules_raw)
    except LoadError as exc:
        return error_source(label, str(exc))
