# Countersign — Build Plan

> Deadline: **Sunday Sep 27, 08:00 America/Denver** (= 10:00 ET). Phase 6 must finish by 06:30 Denver.
> Stack: Python 3, PowerShell, Git, Zowe CLI, Streamlit, GitHub Actions, ibm-watsonx-ai SDK (Dallas, Granite)
> Constraint: do NOT touch `.gitignore`, `.bobignore`, `.env.example`, `SECURITY.MD` except to append project patterns below the marked line in `.gitignore`.
> NOTE: `.env.example` already exists and is hidden from Bob by `.bobignore`. Do NOT create or modify it.

---

## Top-Level Overview

Countersign is a mainframe-grade change-control gate for AI-written code.
Every staged commit must collect *evidence* (deterministic check results) and an *IBM Z approval* before it is accepted.
The project is built in six phases so a working demo exists early and each integration is layered on top.

Architecture at a glance:

```
countersign.yaml  ──►  countersign.py  ──►  records/<ts>_<hash>.json
       │                     │                        │
       │             pre-commit hook              GitHub Action
       │             (+ Z approval)               (evidence only)
       │
       ├──► watsonx (Phase 3): explain FAILs, draft proposed rules
       ├──► .bob/rules/countersign.md   (Bob reads this)
       ├──► .bobignore append           (ai_access:none paths)
       └──► .bob/custom_modes.yaml      (guardian mode)

records/  ──►  dashboard/app.py  (Streamlit, deployed)
               reads plain_english from records; never calls watsonx live

demo_app/ ──►  own countersign.yaml + pytest + scripted attack scenario
```

Blocking policy:
- security FAIL or UNVERIFIED → commit BLOCKED
- functional FAIL → commit BLOCKED
- quality FAIL → warning only, commit proceeds
- A blocked attempt still writes a record with `"outcome": "BLOCKED"`

---

## Phase 1 — Core engine + demo app + pre-commit hook

### 1.1 — Project skeleton

**Intent:** Create the folder structure so all phases have somewhere to write to.

**Expected Outcomes:**
- Folders `records/`, `demo_app/`, `dashboard/`, `bob_sessions/`, `.bob/rules/`, `scripts/`, `hooks/`, `zos/` exist (`.gitkeep` stubs where needed).
- `.gitignore` has a project-specific section appended below the marked line.
- `.env.example` is NOT touched.
- `bob_sessions/` contains a `.gitkeep`; PNG screenshots named `countersign_taskNN_<description>.png` will be added by the human after each Bob session.

**Todo List:**
1. Create `.gitkeep` stubs in `records/`, `bob_sessions/`.
2. Append to `.gitignore` below `# Add project-specific patterns below`:
   - `.countersign/` (holds `approved_rules.sha256` sentinel — not a credential but internal state)
   - `.leak-baseline.json` is NOT ignored (must be committed; name avoids the banned `secret`/`credential` patterns)
   - `countersign.proposed.yaml` is NOT ignored (human-reviewed watsonx output)
   - `ruff-cache/` and `.ruff_cache/`

**Relevant Context:** `.gitignore` line 120 is the insertion point. `*.pyc` and `__pycache__/` are already covered by the template.

**Status:** [ ] pending

---

### 1.2 — `countersign.yaml` ✅ (already written)

`countersign.yaml` is complete with IDs: SEC-001 through SEC-004, FUNC-001, FUNC-002, QUAL-001.

**Status:** [x] done

---

### 1.3 — `countersign.py` CLI

**Intent:** The core engine: parse `countersign.yaml`, run each check, write a SHA-256-chained evidence record, gate the commit, and expose the subcommands needed by SEC-003 and SEC-004.

**Expected Outcomes:**
- `python countersign.py run` exits 0 only when no blocking failures exist.
- `python countersign.py run --skip-z` skips Z approval; records `"z_status": "skipped_by_human"`. Never shown as Z-approved on the dashboard.
- `python countersign.py approve-rules` writes SHA-256 of current `countersign.yaml` to `.countersign/approved_rules.sha256`; prompts for explicit y/n confirmation first. Human-only; agents must never run this.
- `python countersign.py verify-rules` exits 0 if current `countersign.yaml` SHA-256 matches `.countersign/approved_rules.sha256`, exits 1 otherwise.
- `python countersign.py verify-chain` walks all records in `records/` in timestamp order and checks each record's `prev_record_fingerprint` matches the SHA-256 of the preceding file; exits 0 if intact, 1 if broken.
- `records/<ISO-timestamp>_<8-char-sha256-of-staged-diff>.json` written on every run (including BLOCKED runs).
- Record schema: `timestamp`, `git_hash`, `prev_record_fingerprint` (SHA-256 of prior record file, or `"genesis"`), `outcome` (PASS/BLOCKED), `z_status` (null/approved/skipped_by_human/unavailable), `z_job_id`, `z_rc`, `results` array with `id`, `status` (PASS/FAIL/UNVERIFIED), `check`, `output` (truncated), `plain_english` (populated in Phase 3).
- SEC-002 check receives the list of staged file paths as arguments (countersign.py builds this list from `git diff --cached --name-only`).
- On BLOCKED: print a summary table, print watsonx plain-language explanations for every FAIL (Phase 3 adds this), then exit 1.

**Todo List:**
1. Parse `countersign.yaml` with PyYAML.
2. Get staged file list with `git diff --cached --name-only`; get full staged diff with `git diff --cached`.
3. For each entry: if no `check` → UNVERIFIED; else run the shell command (for SEC-002, append staged file list as args), capture stdout/stderr, map RC=0 → PASS, RC≠0 → FAIL.
4. Implement blocking logic: collect all FAIL/UNVERIFIED security and all FAIL functional results.
5. Build record dict, compute `prev_record_fingerprint`.
6. Write record JSON to `records/` before deciding to block (so even BLOCKED runs are recorded).
7. Print summary table to stdout.
8. Exit 0 if no blocking failures; exit 1 with `outcome: BLOCKED`.
9. Implement `approve-rules`, `verify-rules`, `verify-chain` subcommands.
10. Add `--skip-z` flag (Z integration wired in Phase 5; for now the flag is accepted and recorded).
11. Detect `CI=true` environment variable and skip Z approval automatically in CI.

**Relevant Context:** No external deps beyond stdlib + PyYAML + python-dotenv. `bandit`, `detect-secrets`, `ruff`, `pytest` are check tools run as subprocesses (not imported). Load `.env` with `python-dotenv` at startup.

**Status:** [ ] pending

---

### 1.4 — `demo_app/` — small to-do API with its own rules

**Intent:** Provide a concrete target that shows Countersign working in practice, and scripts the "AI skips a requirement" attack scenario for the demo.

**Expected Outcomes:**
- `demo_app/app.py`: stdlib HTTP to-do API (GET /todos, POST /todos, DELETE /todos/<id>).
- `demo_app/test_app.py`: pytest tests for all three routes.
- `demo_app/countersign.yaml`: its own minimal rules (SEC-001 bandit, FUNC-001 pytest, FUNC-002 DELETE route present).
- `demo_app/scenarios/attack.md`: step-by-step demo script (AI removes DELETE → commit blocked; AI adds fake key → commit blocked).

**Todo List:**
1. Write `demo_app/app.py` as a minimal stdlib `http.server` + in-memory JSON to-do store (no Flask, no extra deps).
2. Write `demo_app/test_app.py` with pytest tests for GET, POST, DELETE.
3. Write `demo_app/countersign.yaml` with three entries.
4. Write `demo_app/scenarios/attack.md` with the scripted demo steps.

**Relevant Context:** `demo_app/scenarios/` is excluded from the bandit scan in SEC-001 (the attack script contains intentional fake credential strings for demo purposes).

**Status:** [ ] pending

---

### 1.5 — `requirements.txt` and dev tooling

**Intent:** Pin all Python dependencies so installs are reproducible.

**Expected Outcomes:**
- `requirements.txt` at repo root: `pyyaml`, `python-dotenv`, `bandit`, `detect-secrets`, `ruff`, `pytest`, `streamlit`, `pandas`, `ibm-watsonx-ai`.

**Todo List:**
1. Write `requirements.txt` with the above packages (no version pins yet; add `>=` minimums if known).

**Status:** [ ] pending

---

### 1.6 — Git pre-commit hook

**Intent:** Wire `countersign.py run` as a pre-commit hook so every local commit is gated automatically.

**Expected Outcomes:**
- `hooks/pre-commit` (committed to repo): shell script that runs `python countersign.py run`.
- `scripts/install_hooks.ps1`: copies `hooks/pre-commit` to `.git/hooks/pre-commit`.

**Todo List:**
1. Write `hooks/pre-commit`.
2. Write `scripts/install_hooks.ps1`.

**Relevant Context:** `.git/hooks/` is never committed; `hooks/` at repo root is the committed source.

**Status:** [ ] pending

---

### Phase 1 Test Checkpoint

1. `python countersign.py run` prints a summary table and writes a JSON file in `records/`.
2. `python countersign.py verify-chain` exits 0 on a fresh chain.
3. Stage a change and run the hook; commit is blocked if any security/functional check fails.
4. `pytest demo_app/` shows three green tests.

---

## Phase 2 — Streamlit dashboard

### 2.1 — Dashboard app

**Intent:** Give judges a visual timeline of every requirement's status across commits.

**Expected Outcomes:**
- `dashboard/app.py`: reads all `records/*.json`, renders one row per requirement with ✓ PASS / ✗ FAIL / ? UNVERIFIED, grouped by priority (security first), with a timeline of when each requirement last changed status, the `plain_english` explanation (from record), and Z job ID + RC.
- Blocked records are displayed with a distinct icon/colour to show rejected changes.
- Dashboard never calls watsonx; it only reads what is already in the records.

**Todo List:**
1. Write `dashboard/app.py` using `streamlit`, `pandas`, stdlib only.
2. Load all `records/*.json`, flatten to DataFrame keyed by `(record_file, id)`.
3. Group by `priority`, render with colour-coded status icons.
4. Sidebar timeline: per requirement, show timestamp of last status change.
5. Show Z job ID / RC and `plain_english` columns (null until populated by later phases).
6. Show `outcome: BLOCKED` records in red with a blocked indicator.

**Relevant Context:** Records are plain JSON committed to the repo; no database needed.

**Status:** [ ] pending

---

### 2.2 — Deploy to Streamlit Community Cloud

**Intent:** Make the dashboard publicly accessible for the demo and judges.

**Expected Outcomes:**
- `dashboard/requirements.txt`: `streamlit`, `pandas`.
- `.streamlit/config.toml`: theme settings only (no credentials).
- Deploy instructions added to README (Phase 6).

**Todo List:**
1. Write `dashboard/requirements.txt`.
2. Write `.streamlit/config.toml`.

**Relevant Context:** Streamlit Community Cloud uses `dashboard/requirements.txt` automatically when the main file is `dashboard/app.py`.

**Status:** [ ] pending

---

### Phase 2 Test Checkpoint

1. `streamlit run dashboard/app.py` shows icons per requirement.
2. After a BLOCKED run, dashboard shows the rejected record in red.
3. Dashboard deployed and live at a `*.streamlit.app` URL.

---

## Phase 3 — watsonx.ai integration

### 3.1 — Plain-language FAIL explanations

**Intent:** When a commit is blocked, countersign.py calls watsonx (Granite instruct model, Dallas) to explain each FAIL in plain English. Saved in the record; printed in the terminal. Never affects PASS/FAIL outcome.

**Expected Outcomes:**
- `countersign.py run` (and the pre-commit hook) automatically calls watsonx after determining FAIL results if `IBM_CLOUD_API_KEY`, `WATSONX_URL`, and `WATSONX_PROJECT_ID` are set in the environment.
- If watsonx errors or is unreachable, `plain_english` is set to `"explanation unavailable"` and the gate result is unchanged.
- The model is selected at runtime: call the watsonx API to list available models, filter to Granite instruct models, pick the first. Never hardcode a model ID. Never use: `llama-3-405b-instruct`, `mistral-medium-2505`, `mistral-small-3-1-24b-instruct-2503`.
- `plain_english` is written into the record JSON for every FAIL result.
- The dashboard reads `plain_english` from records and shows it as a tooltip or expander — never calls watsonx live.

**Todo List:**
1. Write `countersign/wx_explain.py` module: `explain_failures(results) -> dict[id, str]`.
   - Load credentials from env via `python-dotenv`; return `{}` if any var is missing.
   - Use `ibm-watsonx-ai` SDK (not raw REST).
   - List available models, filter to Granite instruct, select first.
   - For each FAIL result, send: the requirement text, the check command, the captured output; ask for a plain-English explanation of why it failed and what to fix.
   - Catch all exceptions; return `"explanation unavailable"` per entry on error.
2. Wire `wx_explain.py` into `countersign.py run`: call after checks, before writing the record, only on FAIL entries.
3. Print explanations in the terminal when a commit is blocked.
4. Update dashboard to show `plain_english` per FAIL.

**Relevant Context:** Credentials: `IBM_CLOUD_API_KEY`, `WATSONX_URL`, `WATSONX_PROJECT_ID` in `.env`. The hackathon account closes Sep 27 10 AM ET — explanations must be generated at check time and saved in the record. Do NOT use Agent Lab, fine-tuning, AutoAI, AI governance, Evaluation Studio, or AgentOps.

**Status:** [ ] pending

---

### 3.2 — Rule drafting from spec

**Intent:** Let watsonx read a README or spec file and propose `countersign.yaml` entries for human review.

**Expected Outcomes:**
- `python countersign.py draft-rules --from <file>` reads the file, sends it to Granite, and writes proposed entries to `countersign.proposed.yaml`.
- `countersign.proposed.yaml` is never auto-applied; the human reviews it, then runs `approve-rules` after manually editing `countersign.yaml`.
- Same model selection logic as 3.1.
- Graceful skip if watsonx env vars are not set: print a message and exit 0.

**Todo List:**
1. Add `draft-rules` subcommand to `countersign.py`.
2. Prompt asks Granite to produce YAML entries following the countersign.yaml schema.
3. Write output to `countersign.proposed.yaml`.

**Status:** [ ] pending

---

### Phase 3 Test Checkpoint

1. With watsonx env vars set: `python countersign.py run` on a failing check prints a plain-English explanation and saves it in the record.
2. Without watsonx env vars: same run completes with `"explanation unavailable"` in the record — no error.
3. `python countersign.py draft-rules --from README.md` writes `countersign.proposed.yaml`.
4. Dashboard shows `plain_english` tooltip on FAIL icons.

---

## Phase 4 — Bob wiring + GitHub Action

### 4.1 — Bob rules and guardian mode

**Intent:** Make Bob aware of Countersign's own rules while building it.

**Expected Outcomes:**
- `scripts/generate_bob_rules.py`: parses `countersign.yaml`, regenerates `.bob/rules/countersign.md` and prints an append block for `.bobignore` (human reviews and applies).
- `.bob/custom_modes.yaml` defines a `guardian` mode: Bob may only read FAIL results and propose fixes for FAILED requirements; may not touch `countersign.yaml`, `records/`, or PASS/UNVERIFIED requirements.
- `.bobignore` has project-specific patterns appended for `ai_access: none` paths (SEC-003 and SEC-004 — `countersign.yaml` and `records/*.json`).

**Todo List:**
1. Write `scripts/generate_bob_rules.py`.
2. Run it; commit generated `.bob/rules/countersign.md`.
3. Write `.bob/custom_modes.yaml` with `guardian` mode.
4. Append `ai_access: none` path patterns to `.bobignore` below the template's marked line.

**Relevant Context:** `.bobignore` template section must not be touched. Append a clearly marked `# === Countersign project patterns ===` section.

**Status:** [ ] pending

---

### 4.2 — GitHub Action

**Intent:** Ensure CI runs the same checks as the pre-commit hook.

**Expected Outcomes:**
- `.github/workflows/countersign.yml`: on push and PR, installs deps, runs `python countersign.py run`, uploads `records/` as artifact.
- CI never runs Z approval (`CI=true` is set automatically by GitHub Actions; countersign.py detects it).
- CI never calls watsonx live (watsonx env vars are not set in CI secrets; `plain_english` will be `"explanation unavailable"` in CI records).

**Todo List:**
1. Write `.github/workflows/countersign.yml`.
2. Steps: checkout, setup-python 3.11, `pip install -r requirements.txt`, `python countersign.py run`, upload `records/` artifact.

**Relevant Context:** Do NOT add watsonx secrets to GitHub Actions — the hackathon account closes Sep 27 and records already contain explanations from local runs.

**Status:** [ ] pending

---

### Phase 4 Test Checkpoint

1. Push a commit → GitHub Action runs green/red.
2. Bob in guardian mode refuses to edit `countersign.yaml`.
3. `.bob/rules/countersign.md` is generated, not hand-written.

---

## Phase 5 — IBM Z approval

### 5.0 — USS Python probe job

**Intent:** Discover the USS Python 3 path on Z Xplore before writing the real JCL.

**Expected Outcomes:**
- `zos/PROBE.jcl`: BPXBATCH job that prints `command -v python3` and lists `/usr/lpp/IBM/cyp`.
- Human submits it (`zowe zos-jobs submit local-file zos/PROBE.jcl`) and pastes the SYSOUT back to update this plan with the confirmed Python path.

**Todo List:**
1. Write `zos/PROBE.jcl` with run instructions in a comment header.

**Relevant Context:** Zowe profile name TBD — confirm with `zowe config profiles`. Use `--zosmf-profile <name>` or rely on the default.

**Confirmed USS Python path:** _TBD — paste SYSOUT from PROBE.jcl here_

**Status:** [ ] pending

---

### 5.1 — Zowe upload + JCL approval job

**Intent:** After evidence is collected locally, upload the record to z/OS, submit a JCL job that verifies the fingerprint chain and that all security requirements passed, and accept the commit only on RC=0.

**Expected Outcomes:**
- Z approval runs automatically on every non-CI invocation unless `--skip-z` is passed.
- `countersign.py run --skip-z` records `"z_status": "skipped_by_human"`; never shown as Z-approved on dashboard.
- On Z approval: upload record JSON to `<ZOS_HLQ>.COUNTERSIGN.RECORDS` via Zowe CLI, submit `zos/CSGNJOB.jcl`.
- JCL calls `zos/verify_chain.py` in USS: checks (a) SHA-256 fingerprint matches previous record, (b) all security requirements are PASS.
- countersign.py polls job status, reads RC; fails closed (records `"z_status": "unavailable"`) if Zowe is unreachable or times out after 30 s.
- Z job ID and RC written back into the local record JSON.
- Dashboard shows Z job ID, RC, and Z-approved badge.

**Todo List:**
1. Write `zos/CSGNJOB.jcl`: BPXBATCH step using confirmed Python path from 5.0.
2. Write `zos/verify_chain.py`: reads uploaded JSON, re-computes SHA-256, checks chain and security requirements.
3. Add `_run_z_approval(record_path)` to `countersign.py`: upload → submit → poll → read RC → update record.
4. `ZOS_HLQ` read from `os.getenv("ZOS_HLQ")` only; Zowe profile read by `zowe` CLI, not by Python.
5. Update dashboard to show Z approval status.

**Relevant Context:** `ZOS_HLQ` in `.env` only — not in `.env.example` (do not modify that file). Never read `~/.zowe/` directly.

**Status:** [ ] pending

---

### Phase 5 Test Checkpoint

1. `python countersign.py run` uploads a record, submits the JCL job, prints the job ID, exits 0 when all security checks pass.
2. Deliberate security FAIL → Z job RC ≠ 0 → commit blocked.
3. No network → "Z approval unavailable — commit blocked."
4. Dashboard shows Z job ID, RC, and Z-approved badge.
5. `--skip-z` run: record shows `z_status: skipped_by_human`; dashboard does NOT show Z-approved.

---

## Phase 6 — README, submission, wrap-up

> Must be complete by **06:30 America/Denver Sunday Sep 27**.

### 6.1 — README overhaul

**Expected Outcomes:**
- `README.md` replaces template content with: What Countersign Is, Quick Start, Architecture (ASCII), Dashboard link, watsonx features, IBM Z walkthrough, Demo scenario, bob_sessions note.
- All commands are PowerShell-compatible.

**Todo List:**
1. Write new `README.md`.

**Status:** [ ] pending

---

### 6.2 — Submission statement

**Expected Outcomes:**
- `SUBMISSION.md`: project name, description, team, IBM Z integration notes, watsonx integration notes, link to deployed dashboard.
- `bob_sessions/` contains `.gitkeep` plus PNG screenshots named `countersign_taskNN_<description>.png` (human adds these after each session).

**Todo List:**
1. Write `SUBMISSION.md`.
2. Confirm `bob_sessions/.gitkeep` is committed.

**Status:** [ ] pending

---

### Phase 6 Test Checkpoint

1. `README.md` is fully project-specific with no template boilerplate remaining.
2. `SUBMISSION.md` is complete.
3. `bob_sessions/` has `.gitkeep` committed.
4. Repo is pushed to `https://github.com/Raven-V1/Countersign`.

---

## Open Items

| # | Item | Status |
|---|------|--------|
| 1 | Zowe profile name | TBD — run `zowe config profiles` |
| 2 | `ZOS_HLQ` value | In `.env`; never committed |
| 3 | USS Python path | TBD — discovered in Phase 5.0 probe |
| 4 | Streamlit Community Cloud account | Needed for Phase 2 deploy |
| 5 | `bandit`, `detect-secrets`, `ruff` installable | Confirm with `pip install bandit detect-secrets ruff` |

---

## File Creation Order Summary

```
Phase 1:  records/.gitkeep  bob_sessions/.gitkeep
          countersign.yaml  (done)
          countersign.py
          requirements.txt
          demo_app/app.py  demo_app/test_app.py  demo_app/countersign.yaml
          demo_app/scenarios/attack.md
          hooks/pre-commit  scripts/install_hooks.ps1

Phase 2:  dashboard/app.py  dashboard/requirements.txt
          .streamlit/config.toml

Phase 3:  countersign/wx_explain.py  (wired into countersign.py)
          countersign.proposed.yaml  (generated at runtime)

Phase 4:  scripts/generate_bob_rules.py
          .bob/rules/countersign.md  (generated)
          .bob/custom_modes.yaml
          .github/workflows/countersign.yml

Phase 5:  zos/PROBE.jcl
          zos/CSGNJOB.jcl  zos/verify_chain.py

Phase 6:  README.md (rewrite)  SUBMISSION.md
```
