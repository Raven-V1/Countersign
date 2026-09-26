"""
scripts/generate_bob_rules.py

Reads countersign.yaml, writes .bob/rules/countersign.md, and updates .bobignore.

Run from repo root:
    python scripts/generate_bob_rules.py
    python scripts/generate_bob_rules.py --check   (verify, write nothing)
"""

import argparse
import hashlib
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

REPO_ROOT        = Path(__file__).resolve().parent.parent
RULES_PATH       = REPO_ROOT / ".bob" / "rules" / "countersign.md"
YAML_PATH        = REPO_ROOT / "countersign.yaml"
BOBIGNORE_PATH   = REPO_ROOT / ".bobignore"
BOBIGNORE_MARKER = "# === Countersign project patterns ==="

# -- Static sections embedded in every generated file -------------------------

_ACCESS_TABLE = """\
## Access Level Reference

| Level | Meaning |
|-------|---------|
| `edit` | You may propose and apply fixes to files covered by this rule |
| `read` | You may read and analyse covered files, but must not write them |
| `none` | You must not read, reference, or touch covered files |"""

_HARD_RULES = """\
## Hard Rules for AI Agents

1. **Never run `python countersign.py approve-rules`** - reserved for the human owner.
2. **Never modify `records/`** - tamper-evident evidence chain; any write corrupts it.
3. **Never modify `.gitignore`, `.bobignore`, `.env.example`, or `SECURITY.MD`** except to append project-specific patterns below the marked lines.
4. **Never write a real or realistic-looking credential** into any committed file, including tests and scenario scripts.
5. **Never hardcode z/OS user IDs, hostnames, or HLQs** - read from environment variables only.
6. **Never call watsonx.ai to decide PASS or FAIL** - it may only explain results after they are determined.
7. **If Z approval is unavailable, do not bypass it** - fail closed; record `"z_status": "unavailable"`.
8. **Never read files in `~/.zowe/`** - shell out to `zowe` CLI commands only."""

_GUARDIAN_MODE = """\
## Guardian Mode Constraints

When operating in **guardian** mode you are additionally restricted to:
- Check current status by running `python countersign.py check` in the terminal and reading stdout. \
Never open files in `records/` directly.
- Propose fixes **only** for requirements whose current status is FAIL.
- Do not touch requirements with status PASS or UNVERIFIED.
- Do not modify `countersign.yaml` under any circumstances.
- Do not run `countersign.py approve-rules`."""

# -- Per-requirement supplementary notes (keyed by entry id) ------------------
# These explain HOW agents should handle each requirement beyond the access level.

_EXTRA_NOTES: dict[str, str] = {
    "SEC-001": "If FAIL: show the bandit output to the human; do not auto-fix security issues.",
    "SEC-002": (
        "Baseline file is `.leak-baseline.json` "
        "(not `.detect-secrets.json` - the old name matched a gitignore pattern)."
    ),
    "SEC-003": (
        "`approve-rules` writes a SHA-256 hash of the approved file to "
        "`.countersign/approved_rules.sha256`. "
        "`verify-rules` checks the current file matches that hash."
    ),
    "FUNC-002": (
        "You may edit - but only when this requirement is currently FAIL "
        "(guardian mode constraint)."
    ),
}

_ACCESS_LABEL: dict[str, str] = {
    "none": "**NONE**",
    "read": "**read only**",
    "edit": "**edit**",
}

_PRIORITY_ORDER   = ["security", "functional", "quality"]
_PRIORITY_HEADING = {
    "security": (
        "### Security"
        " (highest priority - every security FAIL or UNVERIFIED blocks the commit)"
    ),
    "functional": "### Functional (functional FAIL blocks the commit)",
    "quality":    "### Quality (quality FAIL is a warning only - commit is not blocked)",
}


# -- Hash helpers --------------------------------------------------------------

def _yaml_hash(raw: str) -> str:
    """SHA-256 over yaml bytes with CRLF normalized to LF."""
    normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# -- Formatting helpers --------------------------------------------------------

def _fmt_entry(e: dict) -> str:
    lines: list[str] = [f"**{e['id']} - {e['requirement']}**"]

    check = e.get("check", "")
    if check:
        lines.append(f"- Check: `{check}`")
    else:
        lines.append("- Check: *(none - always UNVERIFIED)*")

    paths = e.get("paths", [])
    if paths:
        watches = "`, `".join(paths)
        lines.append(f"- Watches: `{watches}`")

    access = e.get("ai_access", "read")
    label  = _ACCESS_LABEL.get(access, f"**{access}**")
    lines.append(f"- Your access: {label}")

    extra = _EXTRA_NOTES.get(e["id"], "")
    if extra:
        lines.append(f"- {extra}")

    return "\n".join(lines)


def _generate_rules_md(entries: list[dict], source_hash: str) -> str:
    by_priority: dict[str, list[dict]] = {p: [] for p in _PRIORITY_ORDER}
    for e in entries:
        p = e.get("priority", "quality")
        by_priority.setdefault(p, []).append(e)

    parts: list[str] = [
        "# Countersign - Bob Rules",
        "> Derived from `countersign.yaml`. Regenerate with: `python scripts/generate_bob_rules.py`",
        f"> Source hash (countersign.yaml, SHA-256): {source_hash}",
        "",
        _ACCESS_TABLE,
        "",
        "---",
        "",
        "## Requirements and Access",
        "",
    ]

    for p in _PRIORITY_ORDER:
        group = by_priority.get(p, [])
        if not group:
            continue
        parts.append(_PRIORITY_HEADING[p])
        parts.append("")
        for e in group:
            parts.append(_fmt_entry(e))
            parts.append("")

    parts += [
        "---",
        "",
        _HARD_RULES,
        "",
        "---",
        "",
        _GUARDIAN_MODE,
        "",
    ]

    return "\n".join(parts)


def _bobignore_block(entries: list[dict]) -> str:
    none_entries = [e for e in entries if e.get("ai_access") == "none"]
    if not none_entries:
        return ""

    lines: list[str] = [
        BOBIGNORE_MARKER,
        "# Auto-generated from countersign.yaml (ai_access: none).",
        "# Do not edit by hand - rerun scripts/generate_bob_rules.py.",
        "",
    ]
    for e in none_entries:
        lines.append(f"# {e['id']}: {e['requirement']}")
        lines.extend(e.get("paths", []))
        lines.append("")

    return "\n".join(lines)


def _compute_new_bobignore(current_normalized: str, block: str) -> str:
    """Return expected .bobignore content after injecting the generated block."""
    if BOBIGNORE_MARKER in current_normalized:
        idx = current_normalized.index(BOBIGNORE_MARKER)
        before = current_normalized[:idx]
        return before + block
    # Marker absent: append after one blank line.
    stripped = current_normalized.rstrip("\n")
    return stripped + "\n\n" + block


# -- I/O helpers ---------------------------------------------------------------

def _read_normalized(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")


def _write_lf(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)


# -- Entry point ---------------------------------------------------------------

def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Regenerate .bob/rules/countersign.md and update .bobignore.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify outputs are up to date without writing anything. Exit 1 if out of sync.",
    )
    args = parser.parse_args()

    if not YAML_PATH.exists():
        sys.exit(f"countersign.yaml not found at {YAML_PATH}")

    raw      = YAML_PATH.read_text(encoding="utf-8")
    entries: list[dict] = yaml.safe_load(raw) or []
    src_hash = _yaml_hash(raw)

    new_rules_md = _generate_rules_md(entries, src_hash)
    block        = _bobignore_block(entries)

    current_rules     = _read_normalized(RULES_PATH)
    current_bobignore = _read_normalized(BOBIGNORE_PATH)

    new_bobignore     = (
        _compute_new_bobignore(current_bobignore, block) if block else current_bobignore
    )

    rules_changed     = new_rules_md     != current_rules
    bobignore_changed = new_bobignore    != current_bobignore

    if args.check:
        ok = True
        rel_rules = RULES_PATH.relative_to(REPO_ROOT)
        if rules_changed:
            print(f"OUT OF SYNC: {rel_rules}")
            ok = False
        else:
            print(f"OK:          {rel_rules}")
        if bobignore_changed:
            print("OUT OF SYNC: .bobignore")
            ok = False
        else:
            print("OK:          .bobignore")
        sys.exit(0 if ok else 1)

    # Normal write mode
    _write_lf(RULES_PATH, new_rules_md)
    label = "Wrote" if rules_changed else "No change"
    print(f"{label}: {RULES_PATH.relative_to(REPO_ROOT)}")

    if block:
        _write_lf(BOBIGNORE_PATH, new_bobignore)
        label = "Wrote" if bobignore_changed else "No change"
        print(f"{label}: .bobignore")
    else:
        print("No ai_access:none entries - .bobignore not changed.")


if __name__ == "__main__":
    main()
