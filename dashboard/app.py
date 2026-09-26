"""Countersign Dashboard — reads records/ read-only, never calls watsonx."""

import copy
import html
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st
import yaml

try:
    import countersign_connect as connect
except ModuleNotFoundError:  # running from the repo: countersign_connect.py is one level up
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import countersign_connect as connect

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
RECORDS_DIR = Path(os.environ.get("COUNTERSIGN_RECORDS_DIR", "records"))
RULES_FILE = Path("countersign.yaml")

PRIORITY_ORDER = ["security", "functional", "quality"]

# Carbon Gray 100 dark theme token subset
C_TEXT    = "#f4f4f4"
C_TEXT2   = "#c6c6c6"
C_LAYER2  = "#393939"
C_BORDER  = "#393939"
C_LINK    = "#78a9ff"

# Carbon dark tag/notification fill pairs  (background / foreground)
_GREEN_BG  = "#044317"
_GREEN_FG  = "#6fdc8c"
_YELLOW_BG = "#483700"
_YELLOW_FG = "#f1c21b"
_RED_BG    = "#750e13"
_RED_FG    = "#ffb3b8"

# ---------------------------------------------------------------------------
# Carbon inline SVGs (16x16) — checkmark--filled, error--filled, help--filled
# ---------------------------------------------------------------------------
_SVG_CHECK = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" '
    'width="16" height="16" fill="currentColor" aria-hidden="true">'
    '<path d="M16 2a14 14 0 1 0 14 14A14 14 0 0 0 16 2zm-2 19.59-5-5L10.41 15 14 '
    '18.59l7.59-7.6L23 12.41z"/></svg>'
)
_SVG_ERROR = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" '
    'width="16" height="16" fill="currentColor" aria-hidden="true">'
    '<path d="M16 2a14 14 0 1 0 14 14A14 14 0 0 0 16 2zm-1.25-7.5h2.5v9.5h-2.5zm1.25 '
    '16a1.5 1.5 0 1 1 1.5-1.5 1.5 1.5 0 0 1-1.5 1.5z"/>'
    '<path d="M14.75 10.5h2.5v9.5h-2.5z"/>'
    '<circle cx="16" cy="22.5" r="1.5"/></svg>'
)
_SVG_HELP = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" '
    'width="16" height="16" fill="currentColor" aria-hidden="true">'
    '<path d="M16 2a14 14 0 1 0 14 14A14 14 0 0 0 16 2zm-1 21v-2h2v2zm1-4a4 4 0 0 1-4-4h2'
    'a2 2 0 1 0 2-2 4 4 0 0 1 0-8 4 4 0 0 1 4 4h-2a2 2 0 1 0-2 2 4 4 0 0 1 0 8z"/></svg>'
)

# ---------------------------------------------------------------------------
# Carbon CSS injection
# ---------------------------------------------------------------------------
_CSS = f"""
<style>
/* Carbon spacing + square corners */
*, *::before, *::after {{ box-sizing: border-box; }}
.stApp {{ background-color: #161616; }}
h1, h2, h3, h4 {{ font-weight: 600; letter-spacing: 0; }}

/* Square corners everywhere */
div[data-testid="stExpander"],
div[data-testid="metric-container"],
div[data-testid="stAlert"],
.stTextInput input,
.stSelectbox select,
.stDataFrame {{ border-radius: 0 !important; }}

/* Carbon tag base */
.cs-tag {{
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 0;
  font-size: 12px;
  font-weight: 500;
  font-family: "IBM Plex Sans", "Helvetica Neue", Arial, sans-serif;
  line-height: 18px;
  white-space: nowrap;
}}
.cs-tag svg {{ flex-shrink: 0; }}

/* Tag variants — Carbon dark fill pairs */
.cs-tag--pass       {{ background: {_GREEN_BG};  color: {_GREEN_FG};  }}
.cs-tag--fail       {{ background: {_RED_BG};    color: {_RED_FG};    }}
.cs-tag--blocked    {{ background: {_RED_BG};    color: {_RED_FG};    }}
.cs-tag--warning    {{ background: {_YELLOW_BG}; color: {_YELLOW_FG}; }}
.cs-tag--unverified {{ background: {_YELLOW_BG}; color: {_YELLOW_FG}; }}

/* Carbon inline notification — solid filled block, no border */
.cs-notif {{
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 16px;
  margin-bottom: 16px;
  font-family: "IBM Plex Sans", "Helvetica Neue", Arial, sans-serif;
  font-size: 14px;
  line-height: 1.5;
}}
.cs-notif--success {{
  background: {_GREEN_BG};
  color: {_GREEN_FG};
}}
.cs-notif--error {{
  background: {_RED_BG};
  color: {_RED_FG};
}}
.cs-notif--unverified {{
  background: {C_LAYER2};
  color: {C_TEXT2};
}}
.cs-notif svg {{ flex-shrink: 0; margin-top: 1px; }}
.cs-notif-body {{ display: flex; flex-direction: column; gap: 2px; }}
.cs-notif-title {{ font-weight: 600; }}
.cs-notif-msg   {{ font-size: 13px; opacity: 0.85; }}

/* Mono font for IDs, hashes, job IDs */
code, .stCode, pre,
[data-testid="stMetricValue"] {{
  font-family: "IBM Plex Mono", "Courier New", monospace !important;
}}
</style>
"""

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


@st.cache_data(ttl=30)
def load_records(records_dir: str) -> list[dict]:
    """Load and return all records sorted newest-first."""
    path = Path(records_dir)
    records = []
    for f in sorted(path.glob("*.json"), reverse=True):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            data["_filename"] = f.name
            records.append(data)
        except (json.JSONDecodeError, OSError):
            pass
    return records


@st.cache_data(ttl=60)
def load_rules(rules_file: str) -> list[dict]:
    """Load countersign.yaml and return rules in priority order."""
    path = Path(rules_file)
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        rules = yaml.safe_load(fh) or []

    def priority_key(r: dict) -> int:
        p = r.get("priority", "")
        return PRIORITY_ORDER.index(p) if p in PRIORITY_ORDER else len(PRIORITY_ORDER)

    return sorted(rules, key=priority_key)


_ERROR_LINE_RE = re.compile(r"^\w+(Error|Exception):")


def _first_error_line(output: str) -> str:
    """Return the exception line of a traceback, else the first non-empty line."""
    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
    for ln in lines:
        if _ERROR_LINE_RE.match(ln):
            return ln
    return lines[0] if lines else "no output"


def run_verify_chain() -> tuple[str, str]:
    """Run `countersign.py verify-chain`; return (status, message).

    Launched by `python -m countersign dashboard` (COUNTERSIGN_VERIFY_VIA_MODULE=1)
    the cwd is the user's repo, which has no countersign.py, so the installed
    module is used instead.

    status is PASS, FAIL, or UNVERIFIED. FAIL only when verify-chain ran and
    reported a broken chain; if it could not run there is no evidence, so the
    status is UNVERIFIED, never FAIL.
    """
    try:
        if os.environ.get("COUNTERSIGN_VERIFY_VIA_MODULE") == "1":
            cmd = [sys.executable, "-m", "countersign", "verify-chain"]
        else:
            cmd = [sys.executable, "countersign.py", "verify-chain"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "UNVERIFIED", _first_error_line(str(exc))
    output = "\n".join(s for s in (result.stdout, result.stderr) if s).strip()
    if result.returncode == 0:
        return "PASS", output
    crashed = "Traceback" in output or "ModuleNotFoundError" in output
    if not crashed and any(ln.startswith("FAIL:") for ln in output.splitlines()):
        return "FAIL", output
    return "UNVERIFIED", _first_error_line(output)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def fmt_timestamp(ts: str) -> str:
    """20260926T140922Z -> 2026-09-26 14:09:22 UTC"""
    try:
        return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]}:{ts[13:15]} UTC"
    except (IndexError, TypeError):
        return ts or "—"


_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def fmt_when(ts: str) -> str:
    """20260926T140922Z -> Sep 26, 14:09 UTC"""
    try:
        dt = datetime.strptime(ts, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return ts or "—"
    return f"{_MONTHS[dt.month - 1]} {dt.day:02d}, {dt:%H:%M} UTC"  # locale-independent


def _outcome_label(rec: dict, priority_map: dict[str, str]) -> str:
    """Return display label for the Outcome cell, adding '(warnings)' when needed.

    priority_map: {rule_id: priority} built from countersign.yaml via load_rules().
    """
    outcome = rec.get("outcome", "—")
    if outcome == "PASS":
        has_qual_fail = any(
            r.get("status") == "FAIL"
            for r in rec.get("results", [])
            if priority_map.get(r.get("id", "")) == "quality"
        )
        if has_qual_fail:
            return "PASS (warnings)"
    return outcome


def run_numbers(records: list[dict]) -> dict[str, int]:
    """{record file: run number}; oldest record in the loaded source is #1."""
    return {name: i for i, name in enumerate(sorted(r["_filename"] for r in records), start=1)}


def run_label(rec: dict, run_no: int, priority_map: dict[str, str]) -> str:
    """Run #N · Mon DD, HH:MM UTC · OUTCOME · commit abc1234 (display only)."""
    commit = (rec.get("git_hash") or "")[:7] or "—"
    return (
        f"Run #{run_no} · {fmt_when(rec.get('timestamp', ''))} · "
        f"{_outcome_label(rec, priority_map)} · commit {commit}"
    )


def rule_display(rule_id: str, rules_by_id: dict[str, dict]) -> str:
    """<ID> · <requirement> from the loaded countersign.yaml, else the bare ID."""
    requirement = (rules_by_id.get(rule_id, {}).get("requirement") or "").strip()
    return f"{rule_id} · {requirement}" if requirement else rule_id


_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|~<>$:])")


def md_escape(text: str) -> str:
    """Backslash-escape markdown so a widget label shows the text literally."""
    return _MD_SPECIAL.sub(r"\\\1", text)


# Display labels for z_status values — stored values are never changed
_Z_STATUS_LABELS: dict[str, str] = {
    "skipped_by_human": "Skipped by user",
    "not_implemented":  "Not configured",
    "not_configured":   "Not configured",
    "approved":         "Approved",
    "unavailable":      "Unavailable",
}


def z_cell(record: dict) -> str:
    """Return a plain-text Z approval string suitable for a dataframe cell."""
    z_status = record.get("z_status") or ""
    z_job    = record.get("z_job_id") or ""
    z_rc     = record.get("z_rc")
    label    = _Z_STATUS_LABELS.get(z_status, z_status or "—")
    if z_status == "approved":
        parts = [label]
        if z_job:
            parts.append(f"job {z_job}")
        if z_rc is not None:
            parts.append(f"RC={z_rc}")
        return " · ".join(parts)
    return label


def z_detail(record: dict) -> str:
    """Return a safe HTML string for Z approval in the record detail panel."""
    z_status = record.get("z_status") or ""
    z_job    = html.escape(record.get("z_job_id") or "")
    z_rc     = record.get("z_rc")
    label    = html.escape(_Z_STATUS_LABELS.get(z_status, z_status or "—"))
    if z_status == "approved" and z_job:
        rc_part = f"&nbsp;&nbsp;RC={html.escape(str(z_rc))}" if z_rc is not None else ""
        return f"{label}&nbsp;&nbsp;job&nbsp;<code>{z_job}</code>{rc_part}"
    return label


def sec004_text(record: dict) -> str:
    """Return plain text chain status for the timeline dataframe."""
    for r in record.get("results", []):
        if r.get("id") == "SEC-004":
            s = r.get("status", "")
            if s == "PASS":
                return "INTACT"
            if s == "FAIL":
                return "BROKEN"
            return s
    return "—"


def _tag(status: str) -> str:
    """Return a Carbon-style HTML tag for a rule status (safe; no record data)."""
    if status == "PASS":
        return f'<span class="cs-tag cs-tag--pass">{_SVG_CHECK} PASS</span>'
    if status == "FAIL":
        return f'<span class="cs-tag cs-tag--fail">{_SVG_ERROR} FAIL</span>'
    if status == "BLOCKED":
        return f'<span class="cs-tag cs-tag--blocked">{_SVG_ERROR} BLOCKED</span>'
    # UNVERIFIED or anything else
    return f'<span class="cs-tag cs-tag--unverified">{_SVG_HELP} UNVERIFIED</span>'


_NOTIF_VARIANTS: dict[str, tuple[str, str, str, str]] = {
    # status -> (css variant, icon, icon colour, title)
    "PASS":       ("success",    _SVG_CHECK, _GREEN_FG, "Chain intact"),
    "FAIL":       ("error",      _SVG_ERROR, _RED_FG,   "Chain broken"),
    "UNVERIFIED": ("unverified", _SVG_HELP,  C_TEXT2,
                   "Chain status UNVERIFIED: verify-chain could not run"),
}


def _notif_html(status: str, msg: str, title: str | None = None) -> str:
    """Return a Carbon inline-notification HTML block. msg and title are escaped internally."""
    variant, svg, icon_col, default_title = _NOTIF_VARIANTS.get(status, _NOTIF_VARIANTS["UNVERIFIED"])
    title     = html.escape(title) if title is not None else default_title
    safe_msg  = html.escape(msg)
    return (
        f'<div class="cs-notif cs-notif--{variant}">'
        f'<span style="color:{icon_col}">{svg}</span>'
        f'<div class="cs-notif-body">'
        f'<span class="cs-notif-title">{title}</span>'
        f'<span class="cs-notif-msg">{safe_msg}</span>'
        f'</div>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Pandas Styler — filled cell backgrounds for timeline table
# ---------------------------------------------------------------------------

# Maps cell text value -> (background, foreground) Carbon dark pair
_OUTCOME_FILLS: dict[str, tuple[str, str]] = {
    "PASS":             (_GREEN_BG,  _GREEN_FG),
    "PASS (warnings)":  (_YELLOW_BG, _YELLOW_FG),
    "BLOCKED":          (_RED_BG,    _RED_FG),
}
_CHAIN_FILLS: dict[str, tuple[str, str]] = {
    "INTACT":       (_GREEN_BG,  _GREEN_FG),
    "BROKEN":       (_RED_BG,    _RED_FG),
    "UNVERIFIED":   (_YELLOW_BG, _YELLOW_FG),
    "—":            (_YELLOW_BG, _YELLOW_FG),
}
# Z Approval column: keyed on the display string produced by z_cell()
_Z_FILL_KEYS: dict[str, tuple[str, str]] = {
    "Approved":         (_GREEN_BG,  _GREEN_FG),
    "Skipped by user":  (_YELLOW_BG, _YELLOW_FG),
    "Not configured":   (_YELLOW_BG, _YELLOW_FG),
    "Unavailable":      (_RED_BG,    _RED_FG),
}


def _cell_style(val: str, mapping: dict[str, tuple[str, str]]) -> str:
    pair = mapping.get(val)
    if pair:
        bg, fg = pair
        return f"background-color: {bg}; color: {fg}; font-weight: 600;"
    # approved with job detail starts with "Approved"
    if isinstance(val, str) and val.startswith("Approved"):
        bg, fg = _Z_FILL_KEYS["Approved"]
        return f"background-color: {bg}; color: {fg}; font-weight: 600;"
    return ""


def _style_timeline(df: pd.DataFrame) -> pd.io.formats.style.Styler:
    """Apply Carbon filled-cell styles to Outcome, Chain, and Z Approval columns."""
    styler = df.style
    if "Outcome" in df.columns:
        styler = styler.map(
            lambda v: _cell_style(v, _OUTCOME_FILLS), subset=["Outcome"]
        )
    if "Chain" in df.columns:
        styler = styler.map(
            lambda v: _cell_style(v, _CHAIN_FILLS), subset=["Chain"]
        )
    if "Z Approval" in df.columns:
        styler = styler.map(
            lambda v: _cell_style(v, _Z_FILL_KEYS), subset=["Z Approval"]
        )
    return styler


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# watsonx explanations view
# ---------------------------------------------------------------------------

_WX_CAPTION = (
    "Explanations were generated by watsonx at check time and are stored in the "
    "records. The dashboard never calls watsonx."
)


def wx_entries(
    records: list[dict], labels: dict[str, str], run_no: dict[str, int], rules_by_id: dict[str, dict]
) -> tuple[list[dict], list[dict]]:
    """Return (explanations, errors) from records, newest record first.

    An explanation is any result with plain_english text, including guard notes
    ("Explanation withheld: ..."). An error is a record whose wx_error is set.
    """
    explanations, errors = [], []
    for rec in sorted(records, key=lambda r: r.get("_filename", ""), reverse=True):
        name = rec.get("_filename", "")
        base = {
            "file": name,
            "run": run_no.get(name, 0),
            "label": labels.get(name, name),
            "model": rec.get("wx_model_id") or "",
        }
        for res in rec.get("results", []):
            text = (res.get("plain_english") or "").strip()
            if text:
                rid = res.get("id", "")
                explanations.append({
                    **base,
                    "rule": rid,
                    "display": rule_display(rid, rules_by_id),
                    "requirement": rules_by_id.get(rid, {}).get("requirement") or "",
                    "status": res.get("status", ""),
                    "text": text,
                })
        if (rec.get("wx_error") or "").strip():
            errors.append({**base, "error": rec["wx_error"].strip()})
    return explanations, errors


def _matches(query: str, fields: list[str]) -> bool:
    """Plain case-insensitive substring match; the query is never a pattern."""
    return not query or any(query in (f or "").lower() for f in fields)


def render_wx_explanations(
    records: list[dict],
    labels: dict[str, str],
    run_no: dict[str, int],
    rules_by_id: dict[str, dict],
    scope_file: str | None,
) -> None:
    """List stored explanations. Every record-derived string goes through st.text."""
    st.subheader("watsonx explanations")
    st.caption(_WX_CAPTION)
    explanations, errors = wx_entries(records, labels, run_no, rules_by_id)

    if scope_file in run_no:
        st.text(f"Showing explanations for Run #{run_no[scope_file]}")
        scope = st.radio("Scope", ["This run", "All runs"], key="cs_wx_scope_mode", horizontal=True)
        if scope == "This run":
            explanations = [e for e in explanations if e["file"] == scope_file]
            errors = [e for e in errors if e["file"] == scope_file]

    if not explanations and not errors:
        st.info("No watsonx explanations in these records.")
        return

    models = sorted({e["model"] for e in explanations if e["model"]})
    n_recs = len({e["file"] for e in explanations})
    st.text(
        f"{len(explanations)} explanation(s) across {n_recs} record(s); "
        f"model(s) used: {', '.join(models) or 'none recorded'}"
    )

    query = st.text_input("Search explanations", max_chars=200, key="cs_wx_search")
    query = query.strip().lower()[:200]
    col1, col2 = st.columns(2)
    status_f = col1.selectbox("Status", ["All", "FAIL", "UNVERIFIED"], key="cs_wx_status")
    rule_ids = sorted({e["rule"] for e in explanations})
    rule_f = col2.selectbox("Rule id", ["All", *rule_ids], key="cs_wx_rule")

    shown = [
        e for e in explanations
        if (status_f == "All" or e["status"] == status_f)
        and (rule_f == "All" or e["rule"] == rule_f)
        and _matches(query, [e["text"], e["rule"], e["requirement"], e["label"]])
    ]
    # watsonx failures are not per-rule, so they show only when unfiltered.
    shown_errors = [
        e for e in errors
        if status_f == "All" and rule_f == "All" and _matches(query, [e["label"], e["error"]])
    ]
    st.text(f"{len(shown) + len(shown_errors)} of {len(explanations) + len(errors)} shown")
    if not shown and not shown_errors:
        st.caption("No explanations match these filters.")

    for e in shown:
        with st.container(border=True):
            st.text(f"Run #{e['run']} · {e['display']} · {e['status']} · {e['model'] or 'no model recorded'}")
            st.text(e["text"])

    if shown_errors:
        st.markdown("**watsonx errors**")
        for e in shown_errors:
            with st.container(border=True):
                st.text(f"Run #{e['run']} · watsonx error · {e['model'] or 'no model recorded'}")
                st.text(f"wx_error: {e['error']}")


st.set_page_config(page_title="Countersign Dashboard", layout="wide")

# Optional: an installed copy without the asset simply shows no logo.
_LOGO = Path(__file__).resolve().parent / "assets" / "belvenar_logo.png"
if _LOGO.is_file():
    _, _logo_col, _ = st.sidebar.columns([1, 2, 1])
    _logo_col.image(str(_LOGO), width=130)
st.html(_CSS)

st.title("Countersign Dashboard")

# ---------------------------------------------------------------------------
# Sidebar: view another repo's records (session only, nothing stored)
# ---------------------------------------------------------------------------
_SOURCE_KEY = "cs_source"
_VIEW_KEY = "cs_view"
_SEL_KEY = "cs_sel"          # last timeline selection: {"src", "file", "state"}
_RESTORE_KEY = "cs_restore_sel"

with st.sidebar:
    st.header("Connect a repo")
    repo_in = st.text_input(
        "GitHub repo", placeholder="owner/repo or https://github.com/owner/repo", key="cs_repo"
    )
    branch_in = st.text_input("Branch", value="main", key="cs_branch")
    if st.button("Connect", key="cs_connect"):
        try:
            owner, repo, branch = connect.parse_repo(repo_in, branch_in)
        except connect.LoadError as exc:
            st.error(str(exc))
        else:
            with st.spinner(f"Downloading {owner}/{repo}@{branch} …"):
                st.session_state[_SOURCE_KEY] = connect.load_github(owner, repo, branch)
    st.caption(
        "Public repos only. Records are downloaded into memory for this session and never stored."
    )

    st.header("watsonx")
    if st.button("watsonx explanations", key="cs_wx"):
        st.session_state[_VIEW_KEY] = "wx"

    st.header("Upload records")
    uploads = st.file_uploader(
        "Record files (.json)", type=["json"], accept_multiple_files=True, key="cs_uploads"
    )
    rules_upload = st.file_uploader(
        "countersign.yaml (optional)", type=["yaml", "yml"], key="cs_rules_upload"
    )
    if st.button("Verify uploads", key="cs_verify_uploads", disabled=not uploads):
        st.session_state[_SOURCE_KEY] = connect.load_uploads(
            [(u.name, u.getvalue()) for u in uploads],
            rules_upload.getvalue() if rules_upload else None,
        )
    st.caption("For private repos. Uploads stay in this session only.")

# ---------------------------------------------------------------------------
# Data source: this repo (default) or a connected/uploaded one (untrusted)
# ---------------------------------------------------------------------------
source = st.session_state.get(_SOURCE_KEY)
untrusted = source is not None

if source is None:
    # --- Carbon chain-status notification ---
    chain_status, chain_msg = run_verify_chain()
    st.html(_notif_html(chain_status, chain_msg))

    records = load_records(str(RECORDS_DIR))
    rules   = load_rules(str(RULES_FILE))
else:
    st.html(
        f'<div class="cs-banner" style="padding:12px 16px;margin-bottom:8px;'
        f'background:{C_LAYER2};color:{C_TEXT}">Viewing '
        f'<code>{html.escape(source["label"])}</code></div>'
    )
    if st.button("Disconnect", key="cs_disconnect"):
        del st.session_state[_SOURCE_KEY]
        st.rerun()
    if source["error"]:
        st.html(_notif_html(
            "UNVERIFIED", source["error"], title=f"UNVERIFIED: could not load {source['label']}"
        ))
        st.stop()
    chain_status, chain_msg = source["chain"]
    st.html(_notif_html(chain_status, chain_msg))
    st.caption(
        "Z Approval shows what the records say. The Z ledger (approved.log on z/OS) "
        "can't be audited from the dashboard."
    )
    records = source["records"]
    rules   = source["rules"] or []

src_id = source["label"] if untrusted else "local"
# {rule_id: priority} — built from countersign.yaml; used for outcome label detection
_priority_map: dict[str, str] = {r["id"]: r.get("priority", "") for r in rules}
rules_by_id = {r["id"]: r for r in rules}
run_no = run_numbers(records)
labels = {r["_filename"]: run_label(r, run_no[r["_filename"]], _priority_map) for r in records}

if st.session_state.get(_VIEW_KEY) == "wx":
    if st.button("Back to timeline", key="cs_wx_back"):
        del st.session_state[_VIEW_KEY]
        st.session_state[_RESTORE_KEY] = True
        st.rerun()
    sel = st.session_state.get(_SEL_KEY) or {}
    render_wx_explanations(
        records, labels, run_no, rules_by_id, sel.get("file") if sel.get("src") == src_id else None
    )
    st.stop()

# ---------------------------------------------------------------------------
# Timeline table (newest first)
# ---------------------------------------------------------------------------
st.subheader("Run Timeline")

if not records:
    if untrusted:
        st.info("No readable records.")
    else:
        st.info("No records found. Run `python -m countersign run` to create the first record.")
    st.stop()

timeline_rows = []
for rec in records:
    timeline_rows.append(
        {
            "Run":          f"Run #{run_no[rec['_filename']]}",
            "When":         fmt_when(rec.get("timestamp", "")),
            "Outcome":      _outcome_label(rec, _priority_map),
            "Chain":        sec004_text(rec),
            "Z Approval":   z_cell(rec),
            "Commit":       (rec.get("git_hash") or "")[:7],
            "Record file":  rec["_filename"],
        }
    )
timeline_df = pd.DataFrame(timeline_rows)

# Per-source key: a row picked in one source must not index into another.
timeline_key = f"cs_timeline:{src_id}" if untrusted else "cs_timeline"
# Streamlit drops a widget's state on runs where it is not drawn (the watsonx
# view), so the selection is saved below and put back on Back to timeline.
if st.session_state.pop(_RESTORE_KEY, False):
    saved = st.session_state.get(_SEL_KEY) or {}
    if saved.get("src") == src_id and saved.get("state") is not None:
        st.session_state[timeline_key] = saved["state"]

selected_idx = st.dataframe(
    _style_timeline(timeline_df),
    width="stretch",
    hide_index=True,
    on_select="rerun",
    selection_mode="single-row",
    key=timeline_key,
).selection.rows

if not selected_idx or selected_idx[0] >= len(records):
    st.session_state[_SEL_KEY] = None
    st.info("Select a record above to inspect its rules.")
    st.stop()

selected_rec = records[selected_idx[0]]
st.session_state[_SEL_KEY] = {
    "src": src_id,
    "file": selected_rec["_filename"],
    "state": copy.deepcopy(st.session_state.get(timeline_key)),
}

# ---------------------------------------------------------------------------
# Selected record detail
# ---------------------------------------------------------------------------
outcome = selected_rec.get("outcome", "—")

# The label is built from normalised fields only (run number, date, outcome, hex commit).
st.subheader(md_escape(labels[selected_rec["_filename"]]))
if untrusted:
    # File names from a connected repo or upload are shown as plain text only.
    st.text(f"Record file: {selected_rec['_filename']}")
else:
    st.caption(f"Record file: `{html.escape(selected_rec['_filename'])}`")
st.html(
    f'<div style="margin-bottom:16px">'
    f'Outcome:&nbsp;{_tag(outcome)}&nbsp;&nbsp;'
    f'Z Approval:&nbsp;<span style="font-family:\'IBM Plex Mono\',monospace;font-size:13px;'
    f'color:{C_TEXT2}">{z_detail(selected_rec)}</span>'
    f'</div>'
)

col1, col2 = st.columns(2)
col1.metric("Timestamp", fmt_timestamp(selected_rec.get("timestamp", "")))
col2.metric("Base commit", (selected_rec.get("git_hash") or "")[:12])

# Index results by id
results_by_id = {r["id"]: r for r in selected_rec.get("results", [])}

# ---------------------------------------------------------------------------
# Rules — security first, then functional, then quality
# ---------------------------------------------------------------------------
if untrusted and not rules:
    st.caption("No usable countersign.yaml in this source, so the requirements panel is hidden.")
    st.stop()

st.subheader("Requirements")

current_priority = None
for rule in rules:
    prio = rule.get("priority", "other")
    if prio != current_priority:
        current_priority = prio
        st.markdown(f"**{prio.upper()}**")

    rid         = rule["id"]
    requirement = rule.get("requirement", "")
    result      = results_by_id.get(rid)
    status      = result["status"] if result else "UNVERIFIED"

    # Expander label is always plain text
    use_expander = status in ("FAIL", "UNVERIFIED") or outcome == "BLOCKED"
    expander_label = f"{md_escape(rule_display(rid, rules_by_id))}  ·  {status}"

    if use_expander:
        with st.expander(expander_label, expanded=(status == "FAIL")):
            # Carbon tag at top of body
            st.html(
                f'<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">'
                f'{_tag(status)}'
                f'<span style="font-family:\'IBM Plex Sans\',sans-serif;font-size:13px;'
                f'color:{C_TEXT2}">{html.escape(requirement)}</span>'
                f'</div>'
            )
            if result:
                plain = (result.get("plain_english") or "").strip()
                if plain:
                    if untrusted:
                        # Untrusted text: never markdown or HTML.
                        st.text(plain)
                    else:
                        st.info(plain)
                raw_out = (result.get("output") or "").strip()
                if raw_out:
                    st.code(raw_out, language="text")
                elif not plain:
                    st.caption("No output captured.")
            else:
                st.caption("No result recorded for this rule in this run.")
    else:
        # PASS: compact inline row
        st.html(
            f'<div style="display:flex;align-items:center;gap:12px;padding:6px 0;'
            f'border-bottom:1px solid {C_BORDER}">'
            f'{_tag(status)}'
            f'<span style="font-family:\'IBM Plex Mono\',monospace;font-size:12px;'
            f'color:{C_LINK};min-width:80px">{html.escape(rid)}</span>'
            f'<span style="font-size:13px;color:{C_TEXT2}">{html.escape(requirement)}</span>'
            f'</div>'
        )
