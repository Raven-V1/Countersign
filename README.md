# Countersign

No evidence, no pass.

Live dashboard: https://countersign.streamlit.app/

## Problem

AI coding agents skip requirements or drop them silently, and security
requirements are the ones that go missing most often. Asking the same AI to
re-check its own work is the AI grading itself. When nothing checks locally,
the problem surfaces late, as a failed CI run after the commit is already
pushed.

## How it works

```
countersign.yaml  ->  deterministic checks  ->  gate rule  ->  hash-chained record  ->  IBM Z approval + ledger
```

1. **`countersign.yaml`** lists every requirement as a rule with an id, a
   priority (`security`, `functional`, `quality`), a shell command that checks
   it, the paths it watches, and the access level an AI agent gets to those
   paths. The file is human-owned: its SHA-256 is pinned in
   `.countersign/approved_rules.sha256` and changes only through
   `approve-rules`.
2. **Deterministic checks.** Each rule's command runs (bandit, detect-secrets,
   pytest, ruff, hash checks). Its exit code sets the status: `PASS` or
   `FAIL`. A rule with no command is `UNVERIFIED`, never `PASS`.
3. **Gate rule.** Block on any security FAIL or UNVERIFIED and any functional
   FAIL; quality FAIL warns.
4. **Hash-chained record.** Every run writes a JSON record to `records/`
   carrying the git hash, every result, and the SHA-256 of the previous
   record. `verify-chain` detects any edited, removed, or reordered record.
5. **IBM Z approval + ledger.** A PASS record is uploaded to z/OS USS and
   re-verified there by a batch job. On success the job appends the record's
   hash to a ledger file on Z. See [IBM Z Approval](#ibm-z-approval).

## Components

| Component | What it does |
|-----------|--------------|
| Pre-commit hook (`hooks/pre-commit`) | Runs `countersign.py run` on every `git commit`. A non-zero exit blocks the commit. |
| GitHub Action (`.github/workflows/countersign.yml`) | Runs the same checks and gate on push and PR to `main` via `countersign.py ci`. Read-only: `contents: read`, no records written, no Z, no watsonx. |
| watsonx.ai (`wx_explain.py`) | Explains FAILs in plain language. It never decides. The verdict is fixed before the model is called. A contradiction guard withholds any explanation that claims a FAIL or UNVERIFIED check passed. `draft-rules` writes proposals only, to `countersign.proposed.yaml`. A human reviews them, copies what they accept into `countersign.yaml`, and runs `approve-rules`. |
| Dashboard (`dashboard/app.py`) | Streamlit view of `records/`. Read-only; never calls watsonx. |
| Bob rules + guardian mode (`.bob/`) | `scripts/generate_bob_rules.py` derives `.bob/rules/countersign.md` and `.bobignore` from `countersign.yaml`; rule BOB-001 fails if they drift. Guardian mode lets Bob edit only non-test source files to fix current FAILs, and bars it from rules, records, and approval commands. |
| IBM Z (`zos/`) | `VERIFY.jcl` and `verify_record.py` re-verify each PASS record on USS and append it to the ledger. `z-audit` cross-checks local records against that ledger. |

### Rules in this repo

| ID | Priority | Check |
|----|----------|-------|
| SEC-001 | security | bandit, medium and high severity |
| SEC-002 | security | detect-secrets against `.leak-baseline.json` |
| SEC-003 | security | `countersign.yaml` matches the approved hash |
| SEC-004 | security | evidence record chain is intact |
| FUNC-001 | functional | pytest over `demo_app/` |
| FUNC-002 | functional | `countersign.py` compiles |
| DEMO-001 | functional | `do_DELETE` route exists in the demo app |
| BOB-001 | quality | Bob rules are in sync with `countersign.yaml` |
| QUAL-001 | quality | ruff |

## Quickstart

Requires Python 3 (CI runs 3.14) and Git. The Z steps also need the Zowe CLI
with a configured z/OSMF profile.

```sh
# 1. Install
pip install -r requirements.txt
cp .env.example .env          # add watsonx credentials and ZOS_USS_DIR (both optional)

# 2. Install the pre-commit hook (PowerShell)
./scripts/install_hooks.ps1
#    or on a POSIX shell:
cp hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

# 3. Run the gate: checks, record, watsonx explanations, Z approval
python countersign.py run

# 4. Read-only check: prints results, writes nothing, no Z, no watsonx
python countersign.py check

# 5. Verify the evidence record chain
python countersign.py verify-chain

# 6. Audit approved records against the Z ledger
python countersign.py z-audit

# 7. Skip Z when it is unreachable (recorded as z_status=skipped_by_human)
python countersign.py run --skip-z
COUNTERSIGN_SKIP_Z=1 git commit -m "..."
```

Other commands: `verify-rules`, `approve-rules` (human only),
`draft-rules --from <file>`, `ci`, and `init`. The dashboard runs with
`python countersign.py dashboard` (or `streamlit run dashboard/app.py`).

## Use Countersign in your own repo

```sh
pip install git+https://github.com/Raven-V1/Countersign
cd your-repo                        # must be the git repo root
python -m countersign init          # writes the files below; never approves
python -m countersign approve-rules # you do this, after reading countersign.yaml
git add countersign.yaml .countersign .leak-baseline.json .github records/.gitkeep
git commit -m "Add Countersign"     # the hook gates this and every later commit
```

`init` writes a starter `countersign.yaml` (bandit, detect-secrets, rules
approval, record chain, an empty FUNC-001 for your test command, ruff), a
`.leak-baseline.json` from `detect-secrets scan`, the pre-commit hook, a
GitHub Action that installs Countersign from this repo and runs
`python -m countersign ci`, and `records/.gitkeep`. Existing files are
skipped unless you pass `--force`; an existing pre-commit hook that is not
Countersign's is never replaced without `--force`.

- **FUNC-001** starts with an empty check, so it is UNVERIFIED until you set
  it to your test command (e.g. `python -m pytest -q`) and re-approve.
- **watsonx** is optional: `pip install "countersign[watsonx] @ git+https://github.com/Raven-V1/Countersign"`
  and set `IBM_CLOUD_API_KEY`, `WATSONX_URL`, and `WATSONX_PROJECT_ID` in
  `.env`. Without them, FAIL explanations are skipped and the gate still works.
- **IBM Z** is opt-in. Without `ZOS_USS_DIR`, runs record
  `z_status=not_configured` and are not blocked. `python -m countersign init --z`
  adds `zos/VERIFY.jcl` and `zos/verify_record.py`; set your Zowe profile,
  `ZOS_USS_DIR` (the USS directory the job reads, `$HOME/countersign`), and
  the Python path in `zos/VERIFY.jcl`. Once `ZOS_USS_DIR` is set, an
  unreachable Z blocks the commit; `COUNTERSIGN_REQUIRE_Z=1` blocks even when
  `ZOS_USS_DIR` is missing.
- **Dashboard**: `pip install "countersign[dashboard] @ git+https://github.com/Raven-V1/Countersign"`,
  then `python -m countersign dashboard` from the repo root.

Settings live in `countersign.yaml`, not in the dashboard, on purpose: a
settings UI would bypass the `approve-rules` human gate.

Rough edges: tested on Python 3.14 only (Windows locally, Ubuntu in CI); the
Z verifier identifies security rules by the `SEC-` prefix, so security rule
ids must start with it; with `core.autocrlf=true` on Windows, mark
`countersign.yaml`, `records/*.json`, `.countersign/*`, and
`.leak-baseline.json` in `.gitattributes` (see this repo's) so checkouts do
not change the hashed bytes.

## How Bob was used

Phases 0 to 3 (rules file and plan, core engine and hook, dashboard, watsonx
integration) were built in IBM Bob. The session summaries are in
[`bob_sessions/`](bob_sessions/). The Bobcoin allowance ran out during
Phase 3, and the remaining phases (Bob wiring, GitHub Action, IBM Z approval,
this README) were built with Claude Code. For that reason the generated Bob
rules and guardian mode have not been tested live in Bob. They are committed,
and their sync with `countersign.yaml` is enforced by BOB-001 in both the hook
and CI.

## Limitations

- **Shared Z user ID.** In this demo the Z verify job and the developer run
  under the same z/OS user ID, so the developer could write to the ledger
  directly. In production the job runs under a dedicated RACF ID that owns the
  ledger, and the developer ID gets read access at most.
- **`approve-rules` is a human gate by convention.** Nothing technical stops
  an agent with shell access from running it. BOB-001 was approved in-session
  by the coding agent and reviewed by the human afterwards.
- **Records lag one commit.** The hook writes its record while the commit is
  being made, so that record cannot be part of the same commit. Each hook
  commit leaves its record for the next commit to include.
- **Z approval is local-only.** CI has no connection to z/OS. CI re-runs the
  checks and the gate, but it does not re-verify on Z.

## Caught by its own gate

Two real incidents from building this project.

**A watsonx rule proposal that would have blocked every commit.** Running
`draft-rules` produced a Granite proposal whose security rule checked
`git check-ignore -v .bobignore`. `.bobignore` is a tracked file, so that
command always exits 1. As a security rule it would have failed on every run
and blocked every commit. Because `draft-rules` only writes to
`countersign.proposed.yaml`, the proposal went to a human, who rejected it.
It never reached `countersign.yaml`. The rejected proposal is kept as
[`docs/evidence/granite_proposal_rejected.yaml`](docs/evidence/granite_proposal_rejected.yaml).

**Phase 4 CI dependency drift.** The Phase 4 commit narrowed the workflow's
install step from `requirements.txt` to an inline package list that left out
`ibm-watsonx-ai`. The test fixtures patch `ibm_watsonx_ai.APIClient`, so
FUNC-001 errored at setup in CI while passing locally. The GitHub Action
blocked the push. The fix restored `pip install -r requirements.txt` so CI runs
exactly the checks that run locally.

---

## IBM Z Approval

Every PASS commit goes through a second verification step running on z/OS USS
before the commit is allowed. The gate is implemented in `zos/VERIFY.jcl`
(submitted via Zowe CLI) and `zos/verify_record.py` (runs on USS under
Python 3.9).

### What Z verifies

1. **Exact bytes vs expected hash.** `countersign.py` computes a SHA-256 of
   the evidence record *before* writing the Z-approval fields back to the
   file. That hash is passed to `verify_record.py` as `argv[2]`. If the
   file on USS does not match byte-for-byte, the job exits 8 (`VERIFY FAIL
   hash-mismatch`). This catches any modification made after upload,
   including the canonical-tamper attack where an attacker replaces a
   well-formed BLOCKED record with a well-formed PASS record.

2. **Verdict re-check.** `verify_record.py` independently checks that
   `outcome` is not `"BLOCKED"`. The outcome field is verified against the
   raw bytes that were already hash-checked, so flipping it without changing
   the hash is impossible.

3. **SEC-* re-check.** Every result whose `id` starts with `SEC-` must have
   `status == "PASS"`. The rule YAML is not available on USS; the `SEC-`
   prefix convention is sufficient.

### The ledger

On `VERIFY OK`, `verify_record.py` appends one line to
`$HOME/countersign/approved.log` on USS:

```
<sha256>  <record_name>  <UTC_timestamp>
```

The `z_verified_hash` field written back into the local record is the same
SHA-256. This creates a cross-system audit trail: each approved record
carries a hash that must appear in the Z-side ledger.

### z-audit

```
python countersign.py z-audit
```

Downloads `approved.log` from USS (path from `ZOS_USS_DIR` in `.env`) and
checks every local record whose `z_status == "approved"`:

- `OK`: `z_verified_hash` is in the ledger with the correct record name, and
  re-nulling the four Z fields and re-hashing the record reproduces the same
  hash.
- `MISSING-FROM-LEDGER`: the hash is not in the ledger.
- `RECONSTRUCT-MISMATCH`: the record was modified after Z approval.
- `SKIP (pre-ledger)`: approved before the ledger feature existed
  (`z_verified_hash` is `None`).

Exit 0 only if all ledger-eligible records are OK.

### Limitation (demo context)

See [Limitations](#limitations): in this demo the verify job and the developer share one Z user ID.
