"""Countersign Dashboard — reads records/ read-only, never calls watsonx."""

import html
import json
import os
import subprocess
from pathlib import Path

import pandas as pd
import streamlit as st
import yaml

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


def run_verify_chain() -> tuple[bool, str]:
    """Run `python countersign.py verify-chain` and return (ok, output)."""
    try:
        result = subprocess.run(
            ["python", "countersign.py", "verify-chain"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        ok = result.returncode == 0
        return ok, (result.stdout or result.stderr or "").strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verify-chain unavailable: {exc}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def fmt_timestamp(ts: str) -> str:
    """20260926T140922Z -> 2026-09-26 14:09:22 UTC"""
    try:
        return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]}:{ts[13:15]} UTC"
    except (IndexError, TypeError):
        return ts or "—"


# Display labels for z_status values — stored values are never changed
_Z_STATUS_LABELS: dict[str, str] = {
    "skipped_by_human": "Skipped by user",
    "not_implemented":  "Not configured",
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


def _notif_html(ok: bool, msg: str) -> str:
    """Return a Carbon inline-notification HTML block. msg is escaped internally."""
    variant   = "success" if ok else "error"
    svg       = _SVG_CHECK if ok else _SVG_ERROR
    icon_col  = _GREEN_FG if ok else _RED_FG
    title     = "Chain intact" if ok else "Chain broken"
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
    if "Chain (SEC-004)" in df.columns:
        styler = styler.map(
            lambda v: _cell_style(v, _CHAIN_FILLS), subset=["Chain (SEC-004)"]
        )
    if "Z Approval" in df.columns:
        styler = styler.map(
            lambda v: _cell_style(v, _Z_FILL_KEYS), subset=["Z Approval"]
        )
    return styler


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

st.set_page_config(page_title="Countersign Dashboard", layout="wide")
st.html(_CSS)

st.title("Countersign Dashboard")

# --- Carbon chain-status notification ---
chain_ok, chain_msg = run_verify_chain()
st.html(_notif_html(chain_ok, chain_msg))

records = load_records(str(RECORDS_DIR))
rules   = load_rules(str(RULES_FILE))

# ---------------------------------------------------------------------------
# Timeline table (newest first)
# ---------------------------------------------------------------------------
st.subheader("Run Timeline")

if not records:
    st.info("No records found. Run `python countersign.py run` to create the first record.")
    st.stop()

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


# {rule_id: priority} — built from countersign.yaml; used for outcome label detection
_priority_map: dict[str, str] = {r["id"]: r.get("priority", "") for r in rules}

timeline_rows = []
for rec in records:
    timeline_rows.append(
        {
            "File":             rec["_filename"],
            "Timestamp":        fmt_timestamp(rec.get("timestamp", "")),
            "Base commit":      (rec.get("git_hash") or "")[:8],
            "Outcome":          _outcome_label(rec, _priority_map),
            "Chain (SEC-004)":  sec004_text(rec),
            "Z Approval":       z_cell(rec),
        }
    )
timeline_df = pd.DataFrame(timeline_rows)

selected_idx = st.dataframe(
    _style_timeline(timeline_df),
    width="stretch",
    hide_index=True,
    on_select="rerun",
    selection_mode="single-row",
).selection.rows

if not selected_idx:
    st.info("Select a record above to inspect its rules.")
    st.stop()

selected_rec = records[selected_idx[0]]

# ---------------------------------------------------------------------------
# Selected record detail
# ---------------------------------------------------------------------------
outcome = selected_rec.get("outcome", "—")
safe_fname = html.escape(selected_rec["_filename"])

st.markdown(f"### Record: `{safe_fname}`")
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
    expander_label = f"{rid}  {status}"

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
