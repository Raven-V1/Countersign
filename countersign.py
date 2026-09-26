"""
countersign.py — Countersign core engine.

Subcommands:
  run             Run all checks, write evidence record, gate the commit.
  run --skip-z    Same but skip Z approval (records z_status=skipped_by_human).
  approve-rules   Write SHA-256 of countersign.yaml to .countersign/approved_rules.sha256.
  verify-rules    Exit 0 if countersign.yaml matches approved hash, else exit 1.
  verify-chain    Walk records/ in timestamp order and verify SHA-256 chain; exit 0/1.
  draft-rules     (Phase 3) Read a file and ask watsonx to propose countersign.yaml entries.

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
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml
from dotenv import load_dotenv

load_dotenv()

YAML_FILE = Path("countersign.yaml")
RECORDS_DIR = Path("records")
APPROVED_HASH_FILE = Path(".countersign") / "approved_rules.sha256"

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


def get_staged_scannable_files() -> list[str]:
    """Staged files that exist on disk (Added/Copied/Modified only).

    Deleted files are excluded because detect-secrets cannot scan them.
    Used as arguments to SEC-002 (detect-secrets).
    """
    _, out = _run("git diff --cached --name-only --diff-filter=ACM")
    return [f for f in out.splitlines() if f]


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
        # Zero scannable files → nothing to scan; record as UNVERIFIED.
        extra: list[str] | None = None
        if rid == "SEC-002":
            files_to_scan = scannable_files if scannable_files is not None else []
            if not files_to_scan:
                results.append(
                    {
                        "id": rid,
                        "status": "UNVERIFIED",
                        "check": check_cmd,
                        "output": "0 files staged — skipped.",
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
        "results": results,
    }
    filename.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return filename


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

STATUS_ICON = {"PASS": "✓", "FAIL": "✗", "UNVERIFIED": "?"}


def print_summary(rules: list[dict], results: list[dict], record_path: Path) -> None:
    print("\n── Countersign Results ──────────────────────────────────────────")
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
    results = run_checks(rules, staged_files, scannable_files)

    blocking = collect_blocking(rules, results)
    outcome = "BLOCKED" if blocking else "PASS"

    # Phase 3: watsonx plain-English explanations wired here
    # (no-op until wx_explain module is added)

    # Z approval (Phase 5 — stub)
    ci_mode = os.getenv("CI", "").lower() in ("true", "1", "yes")
    if ci_mode:
        z_status: str | None = "skipped_ci"
    elif skip_z:
        z_status = "skipped_by_human"
    else:
        z_status = "not_implemented"  # Phase 5 will wire real Z approval

    record_path = write_record(results, outcome, z_status, None, None)
    print_summary(rules, results, record_path)

    if blocking:
        print(f"  ✗ Commit BLOCKED — {len(blocking)} blocking failure(s):\n")
        for b in blocking:
            rule = next(r for r in rules if r["id"] == b["id"])
            print(f"    [{b['id']}] {rule['requirement']}")
            if b["output"]:
                for line in b["output"].splitlines()[:5]:
                    print(f"        {line}")
            print()
        return 1

    print("  ✓ All checks passed — commit approved.\n")
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


def cmd_verify_chain() -> int:
    files = sorted(RECORDS_DIR.glob("*.json"))
    if not files:
        print("PASS: No records yet — chain is trivially intact (genesis).")
        return 0

    prev_fp = "genesis"
    for i, f in enumerate(files):
        record = json.loads(f.read_text(encoding="utf-8"))
        stored_prev = record.get("prev_record_fingerprint", "")
        if stored_prev != prev_fp:
            print(
                f"FAIL: Chain broken at record {f.name}\n"
                f"  Expected prev_fingerprint: {prev_fp}\n"
                f"  Stored  prev_fingerprint:  {stored_prev}"
            )
            return 1
        prev_fp = sha256_file(f)

    print(f"PASS: Chain intact across {len(files)} record(s).")
    return 0


def cmd_draft_rules(from_file: str) -> int:
    """Phase 3 stub — watsonx rule drafting wired in Phase 3."""
    wx_url = os.getenv("WATSONX_URL")
    wx_key = os.getenv("IBM_CLOUD_API_KEY")
    wx_proj = os.getenv("WATSONX_PROJECT_ID")
    if not all([wx_url, wx_key, wx_proj]):
        print(
            "draft-rules requires IBM_CLOUD_API_KEY, WATSONX_URL, and WATSONX_PROJECT_ID "
            "to be set. Skipping."
        )
        return 0
    print("draft-rules watsonx integration will be wired in Phase 3.")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
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

    sub.add_parser("approve-rules", help="Approve current countersign.yaml (human only).")
    sub.add_parser("verify-rules", help="Verify countersign.yaml matches approved hash.")
    sub.add_parser("verify-chain", help="Verify evidence record chain integrity.")

    draft_p = sub.add_parser("draft-rules", help="Ask watsonx to draft rules from a spec file.")
    draft_p.add_argument("--from", dest="from_file", required=True, help="Source spec file.")

    args = parser.parse_args()

    if args.command == "run":
        sys.exit(cmd_run(skip_z=args.skip_z))
    elif args.command == "approve-rules":
        sys.exit(cmd_approve_rules())
    elif args.command == "verify-rules":
        sys.exit(cmd_verify_rules())
    elif args.command == "verify-chain":
        sys.exit(cmd_verify_chain())
    elif args.command == "draft-rules":
        sys.exit(cmd_draft_rules(args.from_file))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
