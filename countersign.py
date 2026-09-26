"""
countersign.py — Countersign core engine.

Subcommands:
  run             Run all checks, write evidence record, gate the commit.
  run --skip-z    Same but skip Z approval (records z_status=skipped_by_human).
  check           Run all checks, print results; no record written, no Z, no watsonx.
  approve-rules   Write SHA-256 of countersign.yaml to .countersign/approved_rules.sha256.
  verify-rules    Exit 0 if countersign.yaml matches approved hash, else exit 1.
  verify-chain    Walk records/ in timestamp order and verify SHA-256 chain; exit 0/1.
  draft-rules     (Phase 3) Read a file and ask watsonx to propose countersign.yaml entries.
  init            Write starter countersign.yaml, baseline, hook, workflow in a repo root.
  dashboard       Run the Streamlit dashboard on records/ in the current directory.

Z approval is opt-in: it runs only when ZOS_USS_DIR is set (or is required via
COUNTERSIGN_REQUIRE_Z=1); otherwise records get z_status=not_configured.

Hard rules (enforced by project):
  - Never call approve-rules from an AI agent.
  - Never modify records/.
  - Never read ~/.zowe/ directly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from importlib import resources
from importlib import util as importlib_util
from pathlib import Path

import yaml
from dotenv import find_dotenv, load_dotenv

# Look for .env from the working directory (the repo being gated), not from
# wherever this module is installed.
load_dotenv(find_dotenv(usecwd=True))

YAML_FILE = Path("countersign.yaml")
RECORDS_DIR = Path("records")
APPROVED_HASH_FILE = Path(".countersign") / "approved_rules.sha256"

# Set in every check command's environment. A gate subcommand (run/ci/check)
# started while it is set is a nested gate (e.g. FUNC-001 → pytest → a test
# that shells out to the gate) and refuses to run instead of recursing.
IN_CHECK_ENV = "COUNTERSIGN_IN_CHECK"
GATE_COMMANDS = ("run", "ci", "check")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    """Return hex SHA-256 of a file's contents."""
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode())


def _run(cmd: str, extra_args: list[str] | None = None) -> tuple[int, str]:
    """Run a check command and return (returncode, combined stdout+stderr).

    The command string is split with shlex.split (no shell=True).
    A leading 'python' token is replaced with sys.executable so the check
    always runs inside the active virtual-env, fixing bandit B602.

    Returns (-1, <message>) when the executable is not found (FileNotFoundError).
    Callers treat rc == -1 as UNVERIFIED.
    """
    tokens = shlex.split(cmd)
    if tokens and tokens[0] == "python":
        tokens[0] = sys.executable
    if extra_args:
        tokens.extend(extra_args)
    try:
        result = subprocess.run(
            tokens,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            env={**os.environ, "PYTHONUTF8": "1", IN_CHECK_ENV: "1"},
        )
    except FileNotFoundError as exc:
        return -1, f"Command not found: {exc}"
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    return result.returncode, output


def _is_not_found(rc: int, output: str, cmd: str = "") -> bool:
    """Return True only when the tool itself could not be found/loaded.

    Two cases:
      1. rc == -1  — FileNotFoundError: the executable binary is absent.
      2. rc == 1 and output contains "No module named <name>" for the exact
         module requested via '-m', OR its top-level package (the part before
         the first dot).  The second form is needed for dotted modules such as
         detect_secrets.pre_commit_hook where Python reports
         "No module named detect_secrets".
         Only these precise strings are matched to avoid misclassifying a tool
         that *runs* but exits 1 (e.g. ruff finding lint errors).
    """
    if rc == -1:
        return True
    if rc == 1:
        tokens = shlex.split(cmd) if cmd else []
        # Find the module name: token after '-m'
        try:
            m_idx = tokens.index("-m")
            module = tokens[m_idx + 1] if m_idx + 1 < len(tokens) else ""
        except ValueError:
            module = ""
        if module:
            top = module.split(".")[0]
            if f"No module named {module}" in output or (
                top != module and f"No module named {top}" in output
            ):
                return True
    return False


def _is_usage_error(rc: int, output: str) -> bool:
    """Return True when a tool printed a usage/help message (argparse rc=2).

    Indicates the check was not actually performed — record as UNVERIFIED.
    """
    return rc == 2 and output.lower().startswith("usage:")


def _truncate(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, {len(text) - limit} chars omitted]"


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------


def get_staged_files() -> list[str]:
    """All staged file paths (add/modify/delete), used for the diff hash."""
    _, out = _run("git diff --cached --name-only")
    return [f for f in out.splitlines() if f]


def _filter_existing(paths: list[str]) -> list[str]:
    """Return only paths that exist on disk as files."""
    return [p for p in paths if Path(p).is_file()]


def get_staged_scannable_files() -> list[str]:
    """Staged files that exist on disk (Added/Copied/Modified only).

    Deleted files are excluded because detect-secrets cannot scan them.
    Used as arguments to SEC-002 (detect-secrets).
    """
    _, out = _run("git diff --cached --name-only --diff-filter=ACM")
    return _filter_existing([f for f in out.splitlines() if f])


def get_all_scannable_files() -> list[str]:
    """All tracked and untracked-but-not-ignored files that exist on disk.

    Used by cmd_check so SEC-002 has files to scan even when nothing is staged.
    """
    _, out = _run("git ls-files --cached --others --exclude-standard")
    return _filter_existing([f for f in out.splitlines() if f])


def get_staged_diff() -> str:
    _, out = _run("git diff --cached")
    return out


def get_git_hash() -> str:
    rc, out = _run("git rev-parse HEAD")
    return out if rc == 0 else "unknown"


# ---------------------------------------------------------------------------
# Load rules
# ---------------------------------------------------------------------------


def load_rules() -> list[dict]:
    return yaml.safe_load(YAML_FILE.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Run checks
# ---------------------------------------------------------------------------


def run_checks(
    rules: list[dict],
    staged_files: list[str],
    scannable_files: list[str] | None = None,
    sec002_empty_msg: str = "0 files staged — skipped.",
    sec002_empty_status: str = "UNVERIFIED",
) -> list[dict]:
    results = []
    for rule in rules:
        rid = rule["id"]
        check_cmd = rule.get("check", "").strip()

        if not check_cmd:
            results.append(
                {
                    "id": rid,
                    "status": "UNVERIFIED",
                    "check": "",
                    "output": "No check command defined.",
                    "plain_english": "",
                }
            )
            continue

        # SEC-002: append only ACM-filtered staged files so detect-secrets
        # never receives paths that no longer exist on disk.
        # Zero scannable files → nothing to scan; status controlled by caller.
        extra: list[str] | None = None
        if rid == "SEC-002":
            files_to_scan = scannable_files if scannable_files is not None else []
            if not files_to_scan:
                results.append(
                    {
                        "id": rid,
                        "status": sec002_empty_status,
                        "check": check_cmd,
                        "output": sec002_empty_msg,
                        "plain_english": "",
                    }
                )
                continue
            extra = files_to_scan

        rc, output = _run(check_cmd, extra)
        if rc == 0:
            status = "PASS"
        elif _is_not_found(rc, output, check_cmd) or _is_usage_error(rc, output):
            status = "UNVERIFIED"
        else:
            status = "FAIL"
        results.append(
            {
                "id": rid,
                "status": status,
                "check": check_cmd,
                "output": _truncate(output),
                "plain_english": "",
            }
        )
    return results


# ---------------------------------------------------------------------------
# Blocking logic
# ---------------------------------------------------------------------------


def is_blocking(rule: dict, result: dict) -> bool:
    priority = rule["priority"]
    status = result["status"]
    return (priority == "security" and status in ("FAIL", "UNVERIFIED")) or (
        priority == "functional" and status == "FAIL"
    )


def collect_blocking(rules: list[dict], results: list[dict]) -> list[dict]:
    rule_map = {r["id"]: r for r in rules}
    return [res for res in results if is_blocking(rule_map[res["id"]], res)]


# ---------------------------------------------------------------------------
# Evidence record
# ---------------------------------------------------------------------------


def prev_fingerprint() -> str:
    """Return SHA-256 of the most recent record, or 'genesis'."""
    files = sorted(RECORDS_DIR.glob("*.json"))
    if not files:
        return "genesis"
    return sha256_file(files[-1])


def write_record(
    results: list[dict],
    outcome: str,
    z_status: str | None,
    z_job_id: str | None,
    z_rc: int | None,
    z_verified_hash: str | None = None,
    wx_model_id: str = "",
    wx_error: str = "",
) -> Path:
    RECORDS_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    diff_text = get_staged_diff()
    diff_hash = sha256_text(diff_text)[:8]
    filename = RECORDS_DIR / f"{ts}_{diff_hash}.json"

    record = {
        "timestamp": ts,
        "git_hash": get_git_hash(),
        "prev_record_fingerprint": prev_fingerprint(),
        "outcome": outcome,
        "z_status": z_status,
        "z_job_id": z_job_id,
        "z_rc": z_rc,
        "z_verified_hash": z_verified_hash,
        "wx_model_id": wx_model_id,
        "wx_error": wx_error,
        "results": results,
    }
    # write_bytes avoids CRLF translation on Windows; records are always LF.
    filename.write_bytes(json.dumps(record, indent=2).encode("utf-8"))
    return filename


# ---------------------------------------------------------------------------
# Z approval helpers
# ---------------------------------------------------------------------------

_ZOS_VERIFY_JCL = Path("zos") / "VERIFY.jcl"
_ZOS_VERIFY_PY = Path("zos") / "verify_record.py"


def _z_configured() -> bool:
    """True when Z approval should run: ZOS_USS_DIR is set, or Z is required.

    COUNTERSIGN_REQUIRE_Z=1 with ZOS_USS_DIR unset still counts as configured,
    so _run_z_approval reports it unavailable and the commit is blocked.
    """
    return bool(os.getenv("ZOS_USS_DIR", "").strip()) or os.getenv("COUNTERSIGN_REQUIRE_Z") == "1"


def mask_uss_dir(uss_dir: str) -> str:
    """USS path for printing: the user segment becomes <zuser>.

    //z/IBMUSER/countersign -> //z/<zuser>/countersign; /u/ibmuser/x -> /u/<zuser>/x.
    Printout only; Zowe calls still use the real path.
    """
    return re.sub(r"^(/+[^/]+/)[^/]+", r"\g<1><zuser>", uss_dir)


def _masked(text: str, uss_dir: str) -> str:
    """Replace the real USS dir in Zowe output with its masked form."""
    return text.replace(uss_dir, mask_uss_dir(uss_dir)) if uss_dir else text


def _update_record_z(
    path: Path,
    z_status: str,
    z_job_id: str | None,
    z_rc: int | None,
    z_verified_hash: str | None,
) -> None:
    """Rewrite z_status, z_job_id, z_rc, z_verified_hash in an existing record file."""
    data = json.loads(path.read_bytes().decode("utf-8"))
    data["z_status"] = z_status
    data["z_job_id"] = z_job_id
    data["z_rc"] = z_rc
    data["z_verified_hash"] = z_verified_hash
    path.write_bytes(json.dumps(data, indent=2).encode("utf-8"))


def _zowe(args: list, timeout: int = 30) -> tuple[int, str]:
    """Run the Zowe CLI with the given argument list.

    Returns (returncode, combined stdout+stderr).
    rc == -1: zowe not found.  rc == -2: timed out.

    On Windows, zowe is a .cmd file so we go through cmd /c.
    """
    if sys.platform == "win32":
        cmd = ["cmd", "/c", "zowe"] + args
    else:
        cmd = ["zowe"] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        out = ((result.stdout or "") + (result.stderr or "")).strip()
        return result.returncode, out
    except subprocess.TimeoutExpired:
        return -2, f"timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "zowe CLI not found"


def _run_z_approval(
    record_path: Path,
) -> tuple[str, str | None, int | None, str | None]:
    """Upload record + verifier to USS, submit VERIFY.jcl.

    Returns (z_status, z_job_id, z_rc, z_verified_hash).

    z_status values:
      approved        -- Z job CC 0000
      blocked_by_z    -- Z job CC != 0000
      unavailable     -- Zowe unreachable, timeout, or parse failure
    z_verified_hash is the sha256 of the uploaded record bytes (pre-Z fields),
    or None when z_status != "approved".
    """
    uss_dir = os.getenv("ZOS_USS_DIR", "").strip()
    if not uss_dir:
        print("  Z approval: ZOS_USS_DIR not set in .env — commit blocked.")
        return "unavailable", None, None, None

    # Capture the record hash before any Z fields are written back.
    expected_hash = sha256_file(record_path)

    print(f"  Z approval: uploading to {mask_uss_dir(uss_dir)} …")

    # Upload verify_record.py
    rc, out = _zowe([
        "zos-files", "upload", "file-to-uss",
        str(_ZOS_VERIFY_PY), f"{uss_dir}/verify_record.py",
        "--binary",
    ])
    if rc != 0:
        print(f"  Z upload failed (verify_record.py): {_masked(out, uss_dir)[:200]}")
        return "unavailable", None, None, None

    # Upload the evidence record
    record_name = record_path.name
    rc, out = _zowe([
        "zos-files", "upload", "file-to-uss",
        str(record_path), f"{uss_dir}/{record_name}",
        "--binary",
    ])
    if rc != 0:
        print(f"  Z upload failed ({record_name}): {_masked(out, uss_dir)[:200]}")
        return "unavailable", None, None, None

    # Generate temp JCL from template; substitute both name and hash placeholders.
    if not _ZOS_VERIFY_JCL.exists():
        print(f"  Z approval: {_ZOS_VERIFY_JCL} not found.")
        return "unavailable", None, None, None

    jcl_text = (
        _ZOS_VERIFY_JCL.read_text(encoding="utf-8")
        .replace("%%RECORD_NAME%%", record_name)
        .replace("%%EXPECTED_HASH%%", expected_hash)
    )

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".jcl", prefix="countersign_verify_")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            fh.write(jcl_text)

        print("  Z approval: submitting VERIFY job …")
        rc, out = _zowe([
            "zos-jobs", "submit", "local-file", tmp_path,
            "--wait-for-output", "--rfj",
        ])
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    if rc == -1:
        print("  Z approval: zowe CLI not found.")
        return "unavailable", None, None, None
    if rc == -2:
        print("  Z approval: timed out waiting for job.")
        return "unavailable", None, None, None

    # Parse Zowe --rfj JSON response
    z_job_id: str | None = None
    z_rc_val: int | None = None
    try:
        payload = json.loads(out)
        job_data = payload.get("data") or {}
        z_job_id = job_data.get("jobid")
        retcode_str = str(job_data.get("retcode") or "")
        if retcode_str.startswith("CC "):
            z_rc_val = int(retcode_str[3:].strip())
        else:
            z_rc_val = None
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"  Z approval: could not parse Zowe response ({exc}); raw: {_masked(out, uss_dir)[:300]}")
        return "unavailable", z_job_id, None, None

    if z_rc_val is None:
        print(f"  Z approval: unexpected retcode in response: {_masked(out, uss_dir)[:200]}")
        return "unavailable", z_job_id, None, None

    if z_rc_val == 0:
        print(f"  Z approval: approved (job {z_job_id} CC 0000).")
        return "approved", z_job_id, z_rc_val, expected_hash

    # BPXBATCH propagates Python sys.exit(N) as CC N*256 (e.g. exit 8 -> CC 2048).
    print(f"  Z approval: blocked (job {z_job_id} CC {z_rc_val:04d}).")
    return "blocked_by_z", z_job_id, z_rc_val, None


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

STATUS_ICON = {"PASS": "✓", "FAIL": "✗", "UNVERIFIED": "?"}


def print_summary(rules: list[dict], results: list[dict], record_path: Path | None = None) -> None:
    print("\n── Countersign Results ──────────────────────────────────────────")
    if record_path is not None:
        print(f"  Record: {record_path}")
    print()
    col_id = max(len(r["id"]) for r in results)
    for res in results:
        icon = STATUS_ICON.get(res["status"], "?")
        rule = next(r for r in rules if r["id"] == res["id"])
        print(
            f"  [{icon}] {res['id']:<{col_id}}  {res['status']:<10}  "
            f"({rule['priority']})  {rule['requirement'][:60]}"
        )
    print("─────────────────────────────────────────────────────────────────\n")


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def cmd_run(skip_z: bool) -> int:
    rules = load_rules()
    staged_files = get_staged_files()
    scannable_files = get_staged_scannable_files()

    print("Running Countersign checks…")

    # 1. Run checks
    results = run_checks(rules, staged_files, scannable_files)

    # 2. Compute gate outcome — watsonx must never influence this
    blocking = collect_blocking(rules, results)
    outcome = "BLOCKED" if blocking else "PASS"

    # 3. Phase 3: watsonx plain-English explanations (fail-soft)
    wx_model_id = ""
    wx_error = ""
    try:
        from wx_explain import explain_failures  # local import keeps it optional
        explanations, wx_model_id, wx_error = explain_failures(results, rules)
    except Exception:  # noqa: BLE001
        explanations = {}

    # 4. Fill plain_english into results (display-only; does not touch status)
    for res in results:
        expl = explanations.get(res["id"], "")
        if expl:
            res["plain_english"] = expl

    # 5. Determine initial Z status; write record with it.
    ci_mode = os.getenv("CI", "").lower() in ("true", "1", "yes")
    z_configured = _z_configured()
    if ci_mode:
        initial_z_status: str = "skipped_ci"
    elif skip_z:
        initial_z_status = "skipped_by_human"
    elif not z_configured:
        initial_z_status = "not_configured"
        print(
            "  Z approval: not configured (ZOS_USS_DIR unset) — skipped, "
            "recorded as z_status=not_configured."
        )
    else:
        initial_z_status = None
    run_z = not ci_mode and not skip_z and z_configured

    record_path = write_record(results, outcome, initial_z_status, None, None, None, wx_model_id, wx_error)
    print_summary(rules, results, record_path)

    if blocking:
        print(f"  ✗ Commit BLOCKED — {len(blocking)} blocking failure(s):\n")
        for b in blocking:
            rule = next(r for r in rules if r["id"] == b["id"])
            print(f"    [{b['id']}] {rule['requirement']}")
            if b["output"]:
                for line in b["output"].splitlines()[:5]:
                    print(f"        {line}")
            plain = b.get("plain_english", "").strip()
            if plain:
                print(f"        → {plain}")
            print()
        if run_z:
            # Still run Z so BLOCKED records are audited; Z will also reject them.
            z_status_final, z_job_id, z_rc, z_verified_hash = _run_z_approval(record_path)
            _update_record_z(record_path, z_status_final, z_job_id, z_rc, z_verified_hash)
        return 1

    # 6. Z approval (non-CI, non-skipped, configured or required only)
    z_blocked = False
    if run_z:
        z_status_final, z_job_id, z_rc, z_verified_hash = _run_z_approval(record_path)
        _update_record_z(record_path, z_status_final, z_job_id, z_rc, z_verified_hash)
        if z_status_final in ("blocked_by_z", "unavailable"):
            print(f"  ✗ Z approval failed (z_status={z_status_final}) — commit blocked.\n")
            z_blocked = True

    if z_blocked:
        return 1

    print("  ✓ All checks passed — commit approved.\n")
    return 0


def cmd_check() -> int:
    """Run all checks and print results.

    No record is written, no Z approval is contacted, no watsonx is called.
    Exit code follows the same gate rule as `run`:
      security FAIL/UNVERIFIED or functional FAIL -> exit 1
      quality FAIL -> warning only, exit 0
    """
    import sys as _sys
    if hasattr(_sys.stdout, "reconfigure"):
        _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(_sys.stderr, "reconfigure"):
        _sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    rules = load_rules()
    staged_files = get_staged_files()
    scannable_files = get_all_scannable_files()

    print("Checking requirements (read-only, no record written)…")

    results = run_checks(
        rules,
        staged_files,
        scannable_files,
        sec002_empty_msg="0 files found — skipped.",
    )
    blocking = collect_blocking(rules, results)

    print_summary(rules, results, record_path=None)

    if blocking:
        print(f"  ✗ Would BLOCK commit — {len(blocking)} blocking failure(s):\n")
        for b in blocking:
            rule = next(r for r in rules if r["id"] == b["id"])
            print(f"    [{b['id']}] {rule['requirement']}")
            if b["output"]:
                for line in b["output"].splitlines()[:5]:
                    print(f"        {line}")
            print()
        return 1

    print("  ✓ All checks pass.\n")
    return 0


def cmd_ci(changed_files: list[str] | None = None) -> int:
    """CI mode: same gate as run — no records, no Z, no watsonx, no .env.

    File list for SEC-002:
      1. --changed-files args (if provided via CLI)
      2. CS_CHANGED_FILES env var (newline-separated; empty string = 0 files)
      3. Neither set → scan all tracked files (e.g. new branch or first push)

    Zero changed files → SEC-002 PASS with a note (not UNVERIFIED).
    """
    rules = load_rules()

    # Resolve the file list for SEC-002.
    if changed_files is not None:
        # CLI args take precedence.
        ci_files: list[str] | None = [f for f in changed_files if Path(f).is_file()]
    elif "CS_CHANGED_FILES" in os.environ:
        raw = os.environ["CS_CHANGED_FILES"].strip()
        ci_files = [f for f in raw.splitlines() if f and Path(f).is_file()]
    else:
        # Not set at all → scan all tracked files (handles new branch / zeros base).
        ci_files = None

    if ci_files is None:
        scannable = get_all_scannable_files()
        sec002_msg = "No base SHA — scanning all tracked files."
        sec002_status = "UNVERIFIED"  # can't happen (scannable will be non-empty if files exist)
    elif not ci_files:
        scannable = []
        sec002_msg = "0 changed files — SEC-002 skipped (PASS)."
        sec002_status = "PASS"
    else:
        scannable = ci_files
        sec002_msg = "0 changed files — SEC-002 skipped (PASS)."
        sec002_status = "PASS"

    print("Running Countersign CI checks…")

    results = run_checks(
        rules,
        staged_files=[],
        scannable_files=scannable,
        sec002_empty_msg=sec002_msg,
        sec002_empty_status=sec002_status,
    )
    blocking = collect_blocking(rules, results)

    print_summary(rules, results, record_path=None)

    if blocking:
        print(f"  ✗ CI gate FAILED — {len(blocking)} blocking failure(s):\n")
        for b in blocking:
            rule = next(r for r in rules if r["id"] == b["id"])
            print(f"    [{b['id']}] {rule['requirement']}")
            if b["output"]:
                for line in b["output"].splitlines()[:5]:
                    print(f"        {line}")
            print()
        return 1

    print("  ✓ All checks passed — CI gate green.\n")
    print("  Note: IBM Z approval runs locally only (Zowe not available in CI).")
    return 0


def cmd_approve_rules() -> int:
    """Write SHA-256 of countersign.yaml to .countersign/approved_rules.sha256.
    Human-only — AI agents must never call this subcommand."""
    answer = input(
        "You are about to approve the current countersign.yaml as the trusted baseline.\n"
        "Type 'y' to confirm: "
    ).strip().lower()
    if answer != "y":
        print("Aborted.")
        return 1
    digest = sha256_file(YAML_FILE)
    APPROVED_HASH_FILE.parent.mkdir(exist_ok=True)
    APPROVED_HASH_FILE.write_text(digest, encoding="utf-8")
    print(f"Approved. SHA-256: {digest}")
    return 0


def cmd_verify_rules() -> int:
    if not APPROVED_HASH_FILE.exists():
        print("FAIL: No approved baseline found. Run 'python countersign.py approve-rules' first.")
        return 1
    approved = APPROVED_HASH_FILE.read_text(encoding="utf-8").strip()
    current = sha256_file(YAML_FILE)
    if current == approved:
        print("PASS: countersign.yaml matches approved baseline.")
        return 0
    print(
        "FAIL: countersign.yaml has been modified since last approval.\n"
        f"  Approved: {approved}\n"
        f"  Current:  {current}"
    )
    return 1


def verify_chain_bytes(files: list[tuple[str, bytes]]) -> tuple[str, str]:
    """Verify a record chain from (file name, raw bytes) pairs.

    Pure: no filesystem, no subprocess. Files are checked in name order.
    Returns ("PASS" | "FAIL", message).
    """
    files = sorted(files, key=lambda f: f[0])
    if not files:
        return "PASS", "No records yet — chain is trivially intact (genesis)."

    prev_fp = "genesis"
    for name, raw_bytes in files:
        try:
            record = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            return "FAIL", f"Record {name} is not valid UTF-8 JSON ({exc})"
        if not isinstance(record, dict):
            return "FAIL", f"Record {name} is not a JSON object"
        stored_prev = record.get("prev_record_fingerprint", "")
        if stored_prev != prev_fp:
            return "FAIL", (
                f"Chain broken at record {name}\n"
                f"  Expected prev_fingerprint: {prev_fp}\n"
                f"  Stored  prev_fingerprint:  {stored_prev}"
            )

        # For Z-approved records, verify the pre-Z hash hasn't been tampered.
        # Reconstruct the record as it was before _update_record_z wrote it back.
        zvh = record.get("z_verified_hash")
        if zvh is not None:
            pre_z = dict(record)
            pre_z["z_status"] = None
            pre_z["z_job_id"] = None
            pre_z["z_rc"] = None
            pre_z["z_verified_hash"] = None
            recon_hash = sha256_bytes(json.dumps(pre_z, indent=2).encode("utf-8"))
            if recon_hash != zvh:
                return "FAIL", (
                    f"z_verified_hash mismatch at {name}\n"
                    f"  Stored z_verified_hash: {zvh}\n"
                    f"  Reconstructed hash:     {recon_hash}"
                )

        prev_fp = sha256_bytes(raw_bytes)

    return "PASS", f"Chain intact across {len(files)} record(s)."


def cmd_verify_chain() -> int:
    files = [(f.name, f.read_bytes()) for f in RECORDS_DIR.glob("*.json")]
    status, message = verify_chain_bytes(files)
    print(f"{status}: {message}")
    return 0 if status == "PASS" else 1


# Required top-level keys every proposed rule entry must contain.
_RULE_REQUIRED_KEYS: frozenset[str] = frozenset(
    {"id", "requirement", "priority", "check", "paths", "ai_access"}
)
# Optional keys that are also allowed.
_RULE_OPTIONAL_KEYS: frozenset[str] = frozenset({"protect"})
_RULE_ALL_KEYS: frozenset[str] = _RULE_REQUIRED_KEYS | _RULE_OPTIONAL_KEYS

_VALID_PRIORITIES: frozenset[str] = frozenset({"security", "functional", "quality"})
_VALID_AI_ACCESS: frozenset[str] = frozenset({"none", "read", "edit"})
_RULE_ID_RE = re.compile(r"^[A-Z]+-\d{3}$")

# Shell operators / features that _run() cannot handle (no shell=True)
_UNSAFE_CHECK_RE = re.compile(r"[\n|&;><`]|\$\(")

_FENCE_RE = re.compile(r"^```[a-z]*\n?", re.MULTILINE)


def _strip_fences(text: str) -> str:
    """Remove leading/trailing markdown code fences from model output."""
    text = _FENCE_RE.sub("", text)
    text = text.replace("```", "")
    return text.strip()


def _validate_proposed(entries: object) -> str:
    """Return "" if entries is a valid list of rule dicts, else an error message.

    Checks required keys, value constraints, and uniqueness of ids.
    """
    if not isinstance(entries, list) or len(entries) == 0:
        return "Proposed YAML must be a non-empty list of rule entries."

    seen_ids: set[str] = set()

    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            return f"Entry {i} is not a mapping."

        label = f"Entry {i} (id={entry.get('id', '?')!r})"

        missing = _RULE_REQUIRED_KEYS - entry.keys()
        if missing:
            return f"{label} is missing required key(s): {', '.join(sorted(missing))}"

        # id: matches ^[A-Z]+-\d{3}$
        rid = entry["id"]
        if not isinstance(rid, str) or not _RULE_ID_RE.match(rid):
            return f"{label}: 'id' must match [A-Z]+-NNN (e.g. SEC-001), got {rid!r}"
        if rid in seen_ids:
            return f"Duplicate id {rid!r} in proposal."
        seen_ids.add(rid)

        # priority
        priority = entry["priority"]
        if priority not in _VALID_PRIORITIES:
            return (
                f"{label}: 'priority' must be one of "
                f"{sorted(_VALID_PRIORITIES)}, got {priority!r}"
            )

        # ai_access
        ai_access = entry["ai_access"]
        if ai_access not in _VALID_AI_ACCESS:
            return (
                f"{label}: 'ai_access' must be one of "
                f"{sorted(_VALID_AI_ACCESS)}, got {ai_access!r}"
            )

        # check: must be a string, single line, no shell operators
        check = entry["check"]
        if not isinstance(check, str):
            return f"{label}: 'check' must be a string."
        if _UNSAFE_CHECK_RE.search(check):
            return (
                f"{label}: 'check' contains a newline or shell operator "
                f"(| & ; > < ` $()). Use a single command with no shell features."
            )

        # paths: non-empty list of strings
        paths = entry["paths"]
        if not isinstance(paths, list) or len(paths) == 0:
            return f"{label}: 'paths' must be a non-empty list of strings."
        for j, p in enumerate(paths):
            if not isinstance(p, str):
                return f"{label}: 'paths[{j}]' must be a string."

    return ""


def cmd_draft_rules(from_file: str) -> int:
    """Read --from file, ask watsonx to propose countersign.yaml entries,
    validate structure, and write countersign.proposed.yaml.

    Never touches countersign.yaml or .countersign/approved_rules.sha256.
    """
    wx_url = os.getenv("WATSONX_URL")
    wx_key = os.getenv("IBM_CLOUD_API_KEY")
    wx_proj = os.getenv("WATSONX_PROJECT_ID")
    if not all([wx_url, wx_key, wx_proj]):
        print(
            "draft-rules requires IBM_CLOUD_API_KEY, WATSONX_URL, and "
            "WATSONX_PROJECT_ID to be set in the environment."
        )
        return 1

    src = Path(from_file)
    if not src.exists():
        print(f"draft-rules: file not found: {from_file}")
        return 1

    spec_text = src.read_text(encoding="utf-8")

    # Collect existing rule IDs so the model doesn't reuse them
    existing_ids: list[str] = []
    if YAML_FILE.exists():
        try:
            existing_ids = [r["id"] for r in (yaml.safe_load(YAML_FILE.read_text(encoding="utf-8")) or [])]
        except Exception:  # noqa: BLE001  # S110 — best-effort; absence of ids is safe
            existing_ids = []

    # Redact the spec before sending to watsonx
    from wx_explain import _redact, draft_explain  # local import keeps it optional

    spec_text = _redact(spec_text)

    print(f"Sending {src.name} to watsonx for rule drafting…")
    raw_yaml, model_id = draft_explain(spec_text, existing_ids=existing_ids)

    if not raw_yaml.strip():
        print(
            "draft-rules: watsonx returned an empty response. "
            "countersign.proposed.yaml was NOT written."
        )
        return 1

    # Strip markdown code fences the model may have added
    clean_yaml = _strip_fences(raw_yaml)

    # Validate structure
    try:
        entries = yaml.safe_load(clean_yaml)
    except yaml.YAMLError as exc:
        print(f"draft-rules: watsonx output is not valid YAML.\n  {exc}")
        print("countersign.proposed.yaml was NOT written.")
        return 1

    err = _validate_proposed(entries)
    if err:
        print(f"draft-rules: proposed YAML failed schema validation.\n  {err}")
        print("countersign.proposed.yaml was NOT written.")
        return 1

    proposed_path = Path("countersign.proposed.yaml")
    proposed_path.write_text(clean_yaml, encoding="utf-8")

    if model_id:
        print(f"  Model used: {model_id}")
    print(f"  Written:    {proposed_path}")
    print(
        "\n  *** WARNING: check commands were written by AI and run as shell "
        "commands.\n"
        "  *** Read each one carefully before approving.\n"
        "\n  Review countersign.proposed.yaml, then manually update\n"
        "  countersign.yaml and run: python countersign.py approve-rules"
    )
    return 0


# ---------------------------------------------------------------------------
# Z audit
# ---------------------------------------------------------------------------


def _parse_ledger(text: str) -> dict[str, set[str]]:
    """Parse approved.log text into {hash: {record_name, ...}}."""
    ledger: dict[str, set[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            h, rname = parts[0], parts[1]
            ledger.setdefault(h, set()).add(rname)
    return ledger


def _audit_records(
    ledger: dict[str, set[str]],
    records_dir: Path = RECORDS_DIR,
) -> int:
    """Audit all approved records against the ledger.

    For each record with z_status=="approved":
      - z_verified_hash must appear in the ledger with the same record name.
      - Reconstruct pre-Z bytes (null all four Z fields) and verify hash matches.

    Returns 0 if all pass, 1 on any failure.
    """
    approved = sorted(f for f in records_dir.glob("*.json") if f.is_file())
    approved = [
        f for f in approved
        if json.loads(f.read_bytes().decode("utf-8")).get("z_status") == "approved"
    ]

    if not approved:
        print("z-audit: no approved records found.")
        return 0

    failures = 0
    for f in approved:
        data = json.loads(f.read_bytes().decode("utf-8"))
        zvh = data.get("z_verified_hash")
        rname = f.name

        if zvh is None:
            # Pre-ledger record: approved before the expected-hash / log feature existed.
            print(f"  SKIP (pre-ledger) {rname}")
            continue

        if zvh not in ledger or rname not in ledger[zvh]:
            print(f"  MISSING-FROM-LEDGER  {rname}")
            failures += 1
            continue

        pre_z = dict(data)
        pre_z["z_status"] = None
        pre_z["z_job_id"] = None
        pre_z["z_rc"] = None
        pre_z["z_verified_hash"] = None
        recon_hash = sha256_bytes(json.dumps(pre_z, indent=2).encode("utf-8"))
        if recon_hash != zvh:
            print(f"  RECONSTRUCT-MISMATCH {rname}  (stored={zvh[:16]}… recon={recon_hash[:16]}…)")
            failures += 1
            continue

        print(f"  OK  {rname}")

    if failures:
        print(f"\nz-audit: {failures} failure(s).")
        return 1

    print(f"\nz-audit: all {len(approved)} approved record(s) OK.")
    return 0


def cmd_z_audit() -> int:
    """Download approved.log from USS and audit all approved records."""
    uss_dir = os.getenv("ZOS_USS_DIR", "").strip()
    if not uss_dir:
        print("z-audit: ZOS_USS_DIR not set — cannot continue.")
        return 1

    log_remote = f"{uss_dir}/approved.log"
    print(f"z-audit: downloading {mask_uss_dir(log_remote)} …")

    # mkstemp creates the file; Zowe skips downloads when the target already
    # exists.  Remove it immediately so Zowe can write it.
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".log", prefix="cs_audit_")
    os.close(tmp_fd)
    os.unlink(tmp_path)
    try:
        rc, out = _zowe([
            "zos-files", "download", "uss-file", log_remote,
            "--file", tmp_path, "--binary",
        ])
        if rc != 0:
            print(f"z-audit: could not download approved.log ({_masked(out, uss_dir)[:200]})")
            return 1

        try:
            log_text = Path(tmp_path).read_bytes().decode("utf-8", errors="replace")
        except OSError as exc:
            print(f"z-audit: could not read downloaded log: {exc}")
            return 1
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    ledger = _parse_ledger(log_text)
    return _audit_records(ledger)


# ---------------------------------------------------------------------------
# init / dashboard
# ---------------------------------------------------------------------------

_HOOK_MARKER = b"countersign"


def _resource_bytes(package: str, name: str, repo_dir: str) -> bytes:
    """Read a packaged data file; fall back to the repo layout when not installed."""
    try:
        data = (resources.files(package) / name).read_bytes()
    except ModuleNotFoundError:
        data = (Path(__file__).resolve().parent / repo_dir / name).read_bytes()
    # A Windows checkout may have converted templates to CRLF; hooks, YAML and
    # JCL are always written LF.
    return data.replace(b"\r\n", b"\n")


def _write_file(path: Path, data: bytes, force: bool) -> str:
    """Write data to path unless it exists and force is False. Return the status."""
    existed = path.exists()
    if existed and not force:
        return "skipped (exists; --force to overwrite)"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return "overwritten" if existed else "created"


_GITATTR_BEGIN = "# BEGIN countersign"
_GITATTR_END = "# END countersign"
_GITATTR_LINES = (
    "countersign.yaml     text eol=lf",
    "records/*.json       binary",
    ".countersign/*       binary",
    ".leak-baseline.json  binary",
)


def _write_gitattributes(path: Path, force: bool) -> str:
    """Create .gitattributes or maintain a marked Countersign block in it.

    Hashed files must keep exact bytes on clones with core.autocrlf=true.
    Lines outside the BEGIN/END block are never changed; --force replaces
    only the block.
    """
    if not path.exists():
        block = "\n".join((_GITATTR_BEGIN, *_GITATTR_LINES, _GITATTR_END)) + "\n"
        path.write_bytes(block.encode("utf-8"))
        return "created"

    text = path.read_bytes().decode("utf-8")
    nl = "\r\n" if "\r\n" in text else "\n"
    block = nl.join((_GITATTR_BEGIN, *_GITATTR_LINES, _GITATTR_END))
    start = text.find(_GITATTR_BEGIN)
    end = text.find(_GITATTR_END, start) if start != -1 else -1
    if start != -1 and end != -1:
        if not force:
            return "skipped (countersign block present; --force to replace)"
        text = text[:start] + block + text[end + len(_GITATTR_END):]
        status = "block replaced"
    else:
        if text and not text.endswith("\n"):
            text += nl
        text += block + nl
        status = "appended"
    path.write_bytes(text.encode("utf-8"))
    return status


def _leak_baseline() -> bytes | None:
    """Run detect-secrets scan (git-tracked files) and return the baseline JSON."""
    result = subprocess.run(
        [
            sys.executable, "-m", "detect_secrets", "scan",
            "--exclude-files", "^records", "--exclude-files", "^.countersign",
        ],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        err = (result.stderr or b"").decode("utf-8", errors="replace").strip()
        print(f"  detect-secrets scan failed (rc={result.returncode}): {err[:300]}")
        return None
    return result.stdout.replace(b"\r\n", b"\n")


def baseline_findings(data: bytes) -> list[tuple[str, int]]:
    """(file, line) for each finding in a detect-secrets baseline; never the values."""
    try:
        results = json.loads(data.decode("utf-8")).get("results") or {}
    except (UnicodeDecodeError, ValueError, AttributeError):
        return []
    return sorted(
        (str(fname), int(f.get("line_number") or 0))
        for fname, items in results.items()
        for f in items
        if isinstance(f, dict)
    )


def print_baseline_warning(findings: list[tuple[str, int]]) -> None:
    if not findings:
        return
    print(
        f"\nWARNING: {len(findings)} potential secret(s) already in this repo were recorded\n"
        "in .leak-baseline.json as known, so SEC-002 will not flag them.\n"
        "Review before approving: python -m detect_secrets audit .leak-baseline.json\n"
        "Anything real must be removed and rotated."
    )
    for fname, line in findings:
        print(f"  {fname}:{line}")


def cmd_init(force: bool, with_z: bool) -> int:
    """Write starter Countersign files into the current git repo root.

    Never runs approve-rules: approving countersign.yaml is the human's step.
    """
    rc, top = _run("git rev-parse --show-toplevel")
    if rc != 0 or not top or not os.path.samefile(top, os.getcwd()):
        print(
            "countersign init: run this from the root of a git repository "
            "(`git rev-parse --show-toplevel` must be the current directory)."
        )
        return 1

    print("Countersign init:\n")
    report: list[tuple[str, str]] = []

    def put(path: Path, data: bytes) -> None:
        report.append((path.as_posix(), _write_file(path, data, force)))

    put(YAML_FILE, _resource_bytes("countersign_templates", "countersign.yaml", "countersign_templates"))

    baseline = Path(".leak-baseline.json")
    findings: list[tuple[str, int]] = []
    if baseline.exists() and not force:
        report.append((baseline.as_posix(), "skipped (exists; --force to overwrite)"))
    else:
        data = _leak_baseline()
        if data is None:
            report.append((baseline.as_posix(), "FAILED (detect-secrets scan)"))
        else:
            put(baseline, data)
            findings = baseline_findings(data)

    _, hook_rel = _run("git rev-parse --git-path hooks/pre-commit")
    hook = Path(hook_rel)
    hook_refused = False
    if hook.exists() and not force and _HOOK_MARKER not in hook.read_bytes().lower():
        hook_refused = True
        report.append((hook.as_posix(), "REFUSED (existing non-Countersign hook; --force to replace)"))
    else:
        put(hook, _resource_bytes("countersign_templates", "pre-commit", "countersign_templates"))
        hook.chmod(hook.stat().st_mode | 0o111)

    put(
        Path(".github") / "workflows" / "countersign.yml",
        _resource_bytes("countersign_templates", "countersign.yml", "countersign_templates"),
    )
    put(RECORDS_DIR / ".gitkeep", b"")
    report.append((".gitattributes", _write_gitattributes(Path(".gitattributes"), force)))

    if with_z:
        for name in ("VERIFY.jcl", "verify_record.py"):
            put(Path("zos") / name, _resource_bytes("countersign_zos", name, "zos"))

    width = max(len(p) for p, _ in report)
    for path_str, status in report:
        print(f"  {path_str:<{width}}  {status}")
    print_baseline_warning(findings)

    if with_z:
        print(
            "\n  Z: set ZOS_USS_DIR in .env to the USS directory VERIFY.jcl reads\n"
            "     ($HOME/countersign), and set the Python path (PY=...) in\n"
            "     zos/VERIFY.jcl to your z/OS Python. Until ZOS_USS_DIR is set,\n"
            "     records get z_status=not_configured."
        )

    failed = hook_refused or any(s.startswith("FAILED") for _, s in report)
    if failed:
        print("\n  Countersign is NOT fully installed — fix the items above and rerun.")
        return 1

    print(
        "\nNext steps:\n"
        "  1. Edit countersign.yaml (set FUNC-001 to your test command), then approve it yourself:\n"
        "       python -m countersign approve-rules\n"
        "  2. Stage the Countersign files:\n"
        "       git add countersign.yaml .countersign .leak-baseline.json .github records/.gitkeep .gitattributes\n"
        "  3. Commit; the pre-commit hook gates this and every later commit:\n"
        '       git commit -m "Add Countersign"'
    )
    return 0


def cmd_dashboard(repo: str | None = None) -> int:
    """Run the packaged Streamlit dashboard against records/ in the cwd.

    repo (CLI --repo only): a local directory containing records/ to run in
    instead of the cwd. Nothing in the web UI accepts local paths.
    """
    cwd = Path.cwd()
    if repo is not None:
        cwd = Path(repo).expanduser().resolve()
        if not cwd.is_dir():
            print(f"countersign dashboard: --repo {repo}: not a directory.")
            return 1
        if not (cwd / "records").is_dir():
            print(f"countersign dashboard: --repo {cwd}: no records/ directory there.")
            return 1

    missing = [m for m in ("streamlit", "pandas") if importlib_util.find_spec(m) is None]
    if missing:
        print(
            f"countersign dashboard: {', '.join(missing)} not installed. Install the dashboard extra:\n"
            '  pip install "countersign[dashboard] @ git+https://github.com/Raven-V1/Countersign"'
        )
        return 1

    try:
        app_ref = resources.files("countersign_dashboard") / "app.py"
    except ModuleNotFoundError:
        app_ref = Path(__file__).resolve().parent / "dashboard" / "app.py"

    cmd = [sys.executable, "-m", "streamlit", "run"]
    theme = []
    if not (cwd / ".streamlit" / "config.toml").exists():
        theme = [
            "--theme.base", "dark",
            "--theme.primaryColor", "#0f62fe",
            "--theme.backgroundColor", "#161616",
            "--theme.secondaryBackgroundColor", "#262626",
            "--theme.textColor", "#f4f4f4",
        ]
    # The dashboard calls verify-chain; outside this repo there is no
    # countersign.py in the cwd, so it must go through the installed module.
    env = {**os.environ, "COUNTERSIGN_VERIFY_VIA_MODULE": "1"}
    with resources.as_file(app_ref) as app_path:
        try:
            return subprocess.call([*cmd, str(app_path), *theme], env=env, cwd=cwd)
        except KeyboardInterrupt:
            return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(
        prog="countersign",
        description="Countersign — mainframe-grade change-control gate.",
    )
    sub = parser.add_subparsers(dest="command")

    run_p = sub.add_parser("run", help="Run all checks and gate the commit.")
    run_p.add_argument(
        "--skip-z",
        action="store_true",
        help="Skip Z approval; records z_status=skipped_by_human.",
    )

    sub.add_parser("check", help="Run checks read-only: print results, no record, no Z, no watsonx.")

    ci_p = sub.add_parser("ci", help="CI mode: same gate as run — no records, no Z, no watsonx.")
    ci_p.add_argument(
        "--changed-files",
        nargs="*",
        metavar="FILE",
        help="Files changed in this push/PR (for SEC-002). Defaults to CS_CHANGED_FILES env var.",
    )
    sub.add_parser("approve-rules", help="Approve current countersign.yaml (human only).")
    sub.add_parser("verify-rules", help="Verify countersign.yaml matches approved hash.")
    sub.add_parser("verify-chain", help="Verify evidence record chain integrity.")
    sub.add_parser("z-audit", help="Audit approved records against the Z ledger.")

    draft_p = sub.add_parser("draft-rules", help="Ask watsonx to draft rules from a spec file.")
    draft_p.add_argument("--from", dest="from_file", required=True, help="Source spec file.")

    init_p = sub.add_parser("init", help="Write starter Countersign files into this git repo root.")
    init_p.add_argument("--force", action="store_true", help="Overwrite existing files.")
    init_p.add_argument("--z", dest="with_z", action="store_true", help="Also write zos/ IBM Z files.")
    dash_p = sub.add_parser("dashboard", help="Run the Streamlit dashboard on records/ in this directory.")
    dash_p.add_argument(
        "--repo", metavar="PATH", help="Local repo directory (with records/) to show instead of the cwd."
    )

    args = parser.parse_args()

    if args.command in GATE_COMMANDS and os.environ.get(IN_CHECK_ENV) == "1":
        print(
            f"countersign: refusing to run '{args.command}' inside a check command "
            f"({IN_CHECK_ENV}=1). A test or check is invoking the gate recursively.",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.command == "run":
        sys.exit(cmd_run(skip_z=args.skip_z))
    elif args.command == "check":
        sys.exit(cmd_check())
    elif args.command == "ci":
        sys.exit(cmd_ci(changed_files=args.changed_files))
    elif args.command == "approve-rules":
        sys.exit(cmd_approve_rules())
    elif args.command == "verify-rules":
        sys.exit(cmd_verify_rules())
    elif args.command == "verify-chain":
        sys.exit(cmd_verify_chain())
    elif args.command == "z-audit":
        sys.exit(cmd_z_audit())
    elif args.command == "draft-rules":
        sys.exit(cmd_draft_rules(args.from_file))
    elif args.command == "init":
        sys.exit(cmd_init(force=args.force, with_z=args.with_z))
    elif args.command == "dashboard":
        sys.exit(cmd_dashboard(repo=args.repo))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
