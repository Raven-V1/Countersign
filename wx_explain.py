"""
wx_explain.py — watsonx.ai integration for Countersign.

Public API
----------
explain_failures(results, rules) -> (dict[str, str], model_id)
    Maps rule_id -> plain-English explanation for every FAIL / UNVERIFIED result.
    Returns ({}, "") when credentials are absent; falls back to
    "Explanation unavailable" per entry on any error.
    One watsonx call per record at most.

select_model(client) -> str
    Lists models via client.foundation_models.get_model_specs()["resources"].
    Returns the first preferred model, then the first sorted Granite fallback.
    Raises RuntimeError if none is found.

draft_explain(spec_text) -> (raw_yaml_text, model_id)
    Sends a spec/README to Granite and returns proposed countersign.yaml YAML.
    Returns ("", "") on any error.

Hard rules enforced here:
  - Credentials are never printed, logged, or written anywhere.
  - watsonx NEVER affects status / gate outcome.
  - Redact check output before sending.
  - One network round-trip per record (whole path in one _call_with_timeout).
  - 15 s total budget enforced explicitly; SDK default is not assumed.
"""

from __future__ import annotations

import os
import re
import threading
from typing import Any

from dotenv import load_dotenv

load_dotenv(override=True)

# ---------------------------------------------------------------------------
# Model selection
# ---------------------------------------------------------------------------

# Banned model IDs (project constraint)
_BANNED: frozenset[str] = frozenset(
    {
        "llama-3-405b-instruct",
        "mistral-medium-2505",
        "mistral-small-3-1-24b-instruct-2503",
    }
)

# Preferred models tried in order before the sorted fallback.
_PREFERRED_MODELS: list[str] = [
    "ibm/granite-4-h-small",
]

# Exclude these Granite sub-families from the fallback (not chat/instruct models).
_GRANITE_EXCLUDE_RE = re.compile(
    r"(?i)(?:base|embedding|guardian|ttm)"
)


def select_model(client: Any) -> str:
    """Return the best available Granite model ID.

    Strategy (deterministic):
      1. Walk _PREFERRED_MODELS in order; return the first one present in the
         API listing and not banned.
      2. Collect all models whose id contains "granite", excludes the
         base/embedding/guardian/ttm sub-families, and is not banned.
         Sort them and return the first.
      3. Raise RuntimeError if no suitable model is found.

    Uses client.foundation_models.get_model_specs()["resources"]; each
    resource dict has a "model_id" key.
    """
    resources = client.foundation_models.get_model_specs()["resources"]
    available: set[str] = set()
    for item in resources:
        mid = item.get("model_id") if isinstance(item, dict) else getattr(item, "model_id", None)
        if mid:
            available.add(mid)

    # 1. Preferred list — deterministic, ordered
    for mid in _PREFERRED_MODELS:
        if mid in available and mid not in _BANNED:
            return mid

    # 2. Sorted Granite fallback — exclude base/embedding/guardian/ttm variants
    granite_candidates = sorted(
        mid
        for mid in available
        if "granite" in mid.lower()
        and not _GRANITE_EXCLUDE_RE.search(mid)
        and mid not in _BANNED
    )
    if granite_candidates:
        return granite_candidates[0]

    raise RuntimeError("No suitable Granite model found in available model list.")


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

# Known secret prefixes (e.g. AWS access key IDs) — kept as-is.
_SECRET_PREFIX_RE = re.compile(r"AKIA[A-Z0-9]{16}", re.IGNORECASE)

# Lookahead/lookbehind alone can't enforce the "contains digit AND letter" rule,
# so we use a sub() callable instead of a simple pattern replacement.
_ENTROPY_CHAR_RE = re.compile(r"[A-Za-z0-9+/=]{20,}")
_PATH_CHAR_RE = re.compile(r"[/\\._\-]")


def _is_high_entropy_token(token: str) -> bool:
    """Return True when token should be redacted.

    Rules:
      - 20+ characters long
      - contains at least one ASCII digit
      - contains at least one ASCII letter
      - contains NONE of: / \\ . _ -
    """
    if len(token) < 20:
        return False
    if _PATH_CHAR_RE.search(token):
        return False
    has_digit = any(c.isdigit() for c in token)
    has_alpha = any(c.isalpha() for c in token)
    return has_digit and has_alpha


def _redact_token(m: re.Match) -> str:  # type: ignore[type-arg]
    return "[REDACTED]" if _is_high_entropy_token(m.group(0)) else m.group(0)


# Key-value redaction: mask the *value* when the key name suggests a secret.
# Group 1 = key name, group 2 = separator with surrounding whitespace,
# group 3 = value (non-whitespace run).
# Matches:  api_key=abc123   secret: s3cr3t   token = xyz
_KV_RE = re.compile(
    r"(?i)\b((?:api[-_]?key|secret|token|password|apikey))(\s*(?:=|:)\s*)(\S+)"
)

# Env-var scrub: names whose values should be masked verbatim.
# Read fresh on every _redact call so tests setting vars after import are covered.
_SECRET_ENV_NAME_RE = re.compile(r"(?i)(?:key|secret|token|password)")


def _env_secrets() -> list[str]:
    """Return current env-var values whose name contains KEY/SECRET/TOKEN/PASSWORD."""
    return [
        v
        for k, v in os.environ.items()
        if _SECRET_ENV_NAME_RE.search(k) and len(v) >= 8
    ]


def _redact_kv(m: re.Match) -> str:  # type: ignore[type-arg]
    """Replace only the value portion of a key=value / key: value pair."""
    return f"{m.group(1)}{m.group(2)}[REDACTED]"


def _redact(text: str) -> str:
    """Mask credentials and high-entropy strings before sending to watsonx.

    Pass order:
      1. Exact env-var values (from os.environ) whose var name contains
         KEY, SECRET, TOKEN, or PASSWORD — length >= 8.
      2. Known AWS-style AKIA key prefixes.
      3. key=value / key: value pairs where the key name suggests a secret.
      4. High-entropy standalone tokens (20+ chars, digit+letter, no path chars).
    """
    # 1. Verbatim env-var values — re-read on each call, never printed/logged
    for secret_val in _env_secrets():
        if secret_val in text:
            text = text.replace(secret_val, "[REDACTED]")
    # 2. Known AWS-style key prefixes
    text = _SECRET_PREFIX_RE.sub("[REDACTED]", text)
    # 3. Key=value / key: value pairs with secret-sounding key names
    text = _KV_RE.sub(_redact_kv, text)
    # 4. High-entropy standalone tokens
    text = _ENTROPY_CHAR_RE.sub(_redact_token, text)
    return text


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


def _load_credentials() -> tuple[str, str, str] | None:
    """Return (api_key, url, project_id) or None if any variable is missing.

    Values are never logged or printed.
    """
    api_key = os.getenv("IBM_CLOUD_API_KEY", "")
    url = os.getenv("WATSONX_URL", "")
    project_id = os.getenv("WATSONX_PROJECT_ID", "")
    if not all([api_key, url, project_id]):
        return None
    return api_key, url, project_id


# ---------------------------------------------------------------------------
# Internal: timed watsonx call
# ---------------------------------------------------------------------------

_TIMEOUT_SECONDS = 15


def _call_with_timeout(fn, *args, timeout: float = _TIMEOUT_SECONDS, **kwargs):
    """Run fn(*args, **kwargs) in a thread; raise TimeoutError if it exceeds timeout."""
    result: list[Any] = [None]
    exc: list[BaseException | None] = [None]

    def _run():
        try:
            result[0] = fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001
            exc[0] = e

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError(f"watsonx call timed out after {timeout}s")
    if exc[0] is not None:
        raise exc[0]
    return result[0]


# ---------------------------------------------------------------------------
# explain_failures
# ---------------------------------------------------------------------------

# Matches a rule ID line in any of these formats Granite may produce:
#   SEC-002: text          Rule SEC-002: text
#   **SEC-002**: text      `SEC-002`: text      <SEC-002>: text
#   SEC-002 - text         SEC-002 – text  (en-dash)
_EXPL_LINE_RE = re.compile(
    "^(?:Rule\\s+)?(?:\\*\\*|`|<)?([A-Z]+-\\d+)(?:\\*\\*|`|>)?\\s*[:–-]\\s*(.*)"
)

# Contradiction guard — model must not claim a FAIL/UNVERIFIED check passed.
_CONTRADICTION_RE = re.compile(
    r"\b(?:check|it|this|rule|verification)\s+(?:has\s+|have\s+|was\s+)?passed\b"
    r"|no action(?: is)? needed|nothing to fix",
    re.IGNORECASE,
)


def explain_failures(results: list[dict], rules: list[dict]) -> tuple[dict[str, str], str, str]:
    """Return (explanations_dict, model_id, wx_error).

    explanations_dict maps rule_id -> plain-English string for every result
    whose status is FAIL or UNVERIFIED.  Returns ({}, "", "") when credentials
    are absent.  Falls back to "Explanation unavailable" per entry on any
    error.  If a model was selected before the error, model_id is still
    returned so the record shows which model was attempted.
    wx_error is "" on success; otherwise a short diagnostic string.

    watsonx NEVER affects status or gate outcome.
    """
    creds = _load_credentials()
    if not creds:
        return {}, "", ""

    failing = [r for r in results if r.get("status") in ("FAIL", "UNVERIFIED")]
    if not failing:
        return {}, "", ""

    api_key, url, project_id = creds
    rule_map = {r["id"]: r for r in rules}
    fallback = {r["id"]: "Explanation unavailable" for r in failing}

    # Build prompt sections now (outside the timed call) — redact outputs
    sections = []
    for r in failing:
        rid = r["id"]
        rule = rule_map.get(rid, {})
        req = rule.get("requirement", rid)
        check_cmd = r.get("check", "")
        output = _redact(r.get("output", ""))
        status = r.get("status", "UNKNOWN")
        status_line = f"Status: {status}"
        if status == "UNVERIFIED":
            status_line += (
                " (UNVERIFIED means the check did not produce evidence,"
                " so it cannot count as a pass.)"
            )
        sections.append(
            f"### {rid}\n"
            f"{status_line}\n"
            f"Requirement: {req}\n"
            f"Check command: {check_cmd}\n"
            f"Check output:\n{output}"
        )

    max_tokens = min(150 * len(failing), 800)
    _fmt = (
        "Answer with one line per rule, exactly like:\n"
        "XMP-000: The login test failed because the password check returns False "
        "for valid users. Fix the comparison in auth.py and rerun the tests."
    )
    system_content = (
        "You are a helpful assistant for a software quality gate called Countersign. "
        "The user will give you a list of checks that have FAILED or are UNVERIFIED. "
        "For each rule, explain in plain English why it likely failed and what a "
        "developer should do to fix it. Keep each explanation to 2-3 sentences. "
        "The status given is final and was decided by deterministic checks. "
        "Never say a check passed or that no action is needed. "
        "Explain why it failed or why it could not be verified, and what the developer should do. "
        + _fmt
    )
    user_content = _fmt + "\n\n" + "\n\n".join(sections)

    # Track which model was selected so we can return it even on later failure
    selected_model: list[str] = [""]

    def _do_explain() -> tuple[dict[str, str], str]:
        from ibm_watsonx_ai import (  # type: ignore[import-untyped]
            APIClient,
            Credentials,
        )
        from ibm_watsonx_ai.foundation_models import (  # type: ignore[import-untyped]
            ModelInference,
        )

        credentials = Credentials(url=url, api_key=api_key)
        api_client = APIClient(credentials=credentials)
        model_id = select_model(api_client)
        selected_model[0] = model_id

        model = ModelInference(
            model_id=model_id,
            credentials=credentials,
            project_id=project_id,
        )
        response = model.chat(
            messages=[
                {"role": "system", "content": system_content},
                {"role": "user", "content": user_content},
            ],
            params={"max_tokens": max_tokens, "temperature": 0},
        )
        raw_text = response["choices"][0]["message"]["content"]

        # Parse rule ID lines — accepts: SEC-002: | Rule SEC-002: |
        # **SEC-002**: | `SEC-002`: | <SEC-002>: | SEC-002 - | SEC-002 –
        explanations: dict[str, str] = dict(fallback)
        matched_ids: set[str] = set()
        current_id: str | None = None
        current_lines: list[str] = []

        def _flush() -> None:
            if current_id and current_lines:
                explanations[current_id] = " ".join(current_lines).strip()
                matched_ids.add(current_id)

        for line in (raw_text or "").splitlines():
            m = _EXPL_LINE_RE.match(line)
            if m and m.group(1) in explanations:
                _flush()
                current_id = m.group(1)
                current_lines = [m.group(2)]
            elif current_id:
                current_lines.append(line)
        _flush()

        if not matched_ids:
            stripped = (raw_text or "").strip()
            if len(failing) == 1:
                explanations[failing[0]["id"]] = stripped or "Explanation unavailable"
                return explanations, ""
            return explanations, "ParseError: no rule ids in response"

        return explanations, ""

    try:
        explanations, wx_error = _call_with_timeout(_do_explain, timeout=_TIMEOUT_SECONDS)
        contradicted = sorted(
            rid for rid, expl in explanations.items()
            if _CONTRADICTION_RE.search(expl)
        )
        for rid in contradicted:
            explanations[rid] = "Explanation withheld: model output contradicted the verdict."
        if contradicted:
            guard = "ContradictionGuard: " + ", ".join(contradicted)
            wx_error = f"{wx_error}; {guard}" if wx_error else guard
        return explanations, selected_model[0], wx_error
    except TimeoutError:
        return fallback, selected_model[0], "TimeoutError"
    except Exception as exc:  # noqa: BLE001
        msg = _redact(str(exc))[:120]
        return fallback, selected_model[0], f"{type(exc).__name__}: {msg}"


# ---------------------------------------------------------------------------
# draft_explain  (used by cmd_draft_rules)
# ---------------------------------------------------------------------------


def draft_explain(
    spec_text: str,
    existing_ids: list[str] | None = None,
) -> tuple[str, str]:
    """Send spec_text to Granite; return (raw_yaml_text, model_id).

    Returns ("", "") when credentials are absent or on any error.
    spec_text must already be redacted by the caller.

    existing_ids: rule IDs already in countersign.yaml — the model will not
    reuse them.
    """
    creds = _load_credentials()
    if not creds:
        return "", ""

    api_key, url, project_id = creds
    safe_spec = _redact(spec_text)

    existing_note = ""
    if existing_ids:
        existing_note = (
            f"\nExisting rule IDs (do NOT reuse any of these): "
            f"{', '.join(existing_ids)}\n"
        )

    system_content = (
        "You are an expert in software quality gates.\n"
        "Read the project specification the user provides and produce YAML entries "
        "for a countersign.yaml file.\n\n"
        "Rules:\n"
        "- Use IDs in the form SEC-NNN, FUNC-NNN, or QUAL-NNN (e.g. SEC-005).\n"
        "- 'check' must be a SINGLE shell command with NO shell operators "
        "(no | & ; > < ` $() and no newlines). Use an empty string if no "
        "automated check is possible.\n"
        "- 'priority' must be exactly one of: security, functional, quality.\n"
        "- 'ai_access' must be exactly one of: none, read, edit.\n"
        "- 'paths' must be a non-empty YAML list of glob strings.\n"
        f"{existing_note}"
        "\nEach entry must follow this exact schema:\n\n"
        "- id: SEC-005\n"
        "  requirement: No hard-coded credentials in source files\n"
        "  priority: security\n"
        "  check: \"python -m detect_secrets scan .\"\n"
        "  paths:\n"
        "    - \"**/*\"\n"
        "  ai_access: read\n\n"
        "Output ONLY valid YAML — no explanations, no markdown fences."
    )

    def _do_draft() -> tuple[str, str]:
        from ibm_watsonx_ai import (  # type: ignore[import-untyped]
            APIClient,
            Credentials,
        )
        from ibm_watsonx_ai.foundation_models import (  # type: ignore[import-untyped]
            ModelInference,
        )

        credentials = Credentials(url=url, api_key=api_key)
        api_client = APIClient(credentials=credentials)
        model_id = select_model(api_client)

        model = ModelInference(
            model_id=model_id,
            credentials=credentials,
            project_id=project_id,
        )
        response = model.chat(
            messages=[
                {"role": "system", "content": system_content},
                {"role": "user", "content": safe_spec},
            ],
            params={"max_tokens": 1500, "temperature": 0},
        )
        raw = response["choices"][0]["message"]["content"]
        return raw or "", model_id

    try:
        return _call_with_timeout(_do_draft, timeout=_TIMEOUT_SECONDS)
    except Exception:  # noqa: BLE001
        return "", ""
