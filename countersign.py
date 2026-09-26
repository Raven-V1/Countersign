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
            env={**os.environ, "PYTHONUTF8": "1"},
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
        "wx_model_id": wx_model_id,
        "wx_error": wx_error,
        "results": results,
    }
    filename.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return filename


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

    # Z approval (Phase 5 — stub)
    ci_mode = os.getenv("CI", "").lower() in ("true", "1", "yes")
    if ci_mode:
        z_status: str | None = "skipped_ci"
    elif skip_z:
        z_status = "skipped_by_human"
    else:
        z_status = "not_implemented"  # Phase 5 will wire real Z approval

    # 5. Write record (chain hash is prev_fingerprint() inside write_record)
    record_path = write_record(results, outcome, z_status, None, None, wx_model_id, wx_error)
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
    sub.add_parser("approve-rules", help="Approve current countersign.yaml (human only).")
    sub.add_parser("verify-rules", help="Verify countersign.yaml matches approved hash.")
    sub.add_parser("verify-chain", help="Verify evidence record chain integrity.")

    draft_p = sub.add_parser("draft-rules", help="Ask watsonx to draft rules from a spec file.")
    draft_p.add_argument("--from", dest="from_file", required=True, help="Source spec file.")

    args = parser.parse_args()

    if args.command == "run":
        sys.exit(cmd_run(skip_z=args.skip_z))
    elif args.command == "check":
        sys.exit(cmd_check())
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
