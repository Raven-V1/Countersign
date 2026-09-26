# Countersign - Bob Rules
> Derived from `countersign.yaml`. Regenerate with: `python scripts/generate_bob_rules.py`
> Source hash (countersign.yaml, SHA-256): 0fa9f9e90287c2c623aac75a6950b47e275765f590dd888adfd562bf9225920a

## Access Level Reference

| Level | Meaning |
|-------|---------|
| `edit` | You may propose and apply fixes to files covered by this rule |
| `read` | You may read and analyse covered files, but must not write them |
| `none` | You must not read, reference, or touch covered files |

---

## Requirements and Access

### Security (highest priority - every security FAIL or UNVERIFIED blocks the commit)

**SEC-001 - No medium or high severity issues found by bandit in Python code**
- Check: `python -m bandit -r . --exclude .venv,venv,env,demo_app/scenarios -ll -q`
- Watches: `**/*.py`
- Your access: **read only**
- If FAIL: show the bandit output to the human; do not auto-fix security issues.

**SEC-002 - No high-entropy strings or known key patterns in staged files**
- Check: `python -m detect_secrets.pre_commit_hook --baseline .leak-baseline.json --exclude-files ^records --exclude-files ^.countersign`
- Watches: `**/*`
- Your access: **read only**
- Baseline file is `.leak-baseline.json` (not `.detect-secrets.json` - the old name matched a gitignore pattern).

**SEC-003 - countersign.yaml has not been silently modified since last approval**
- Check: `python countersign.py verify-rules`
- Watches: `countersign.yaml`
- Your access: **NONE**
- `approve-rules` writes a SHA-256 hash of the approved file to `.countersign/approved_rules.sha256`. `verify-rules` checks the current file matches that hash.

**SEC-004 - Evidence record chain is intact (no record has been tampered with)**
- Check: `python countersign.py verify-chain`
- Watches: `records/*.json`
- Your access: **NONE**

### Functional (functional FAIL blocks the commit)

**FUNC-001 - All pytest tests in demo_app/ pass**
- Check: `python -m pytest demo_app/ -q --tb=short`
- Watches: `demo_app/**/*.py`
- Your access: **edit**

**FUNC-002 - countersign.py is present and has valid Python syntax**
- Check: `python -m py_compile countersign.py`
- Watches: `countersign.py`
- Your access: **edit**
- You may edit - but only when this requirement is currently FAIL (guardian mode constraint).

**DEMO-001 - DELETE route (do_DELETE) is present in demo_app/app.py**
- Check: `python -c "import ast,sys; t=ast.parse(open('demo_app/app.py').read()); sys.exit(0 if any(isinstance(n,ast.FunctionDef) and n.name=='do_DELETE' for n in ast.walk(t)) else 1)"`
- Watches: `demo_app/app.py`
- Your access: **edit**

### Quality (quality FAIL is a warning only - commit is not blocked)

**BOB-001 - Bob rules file is in sync with countersign.yaml**
- Check: `python scripts/generate_bob_rules.py --check`
- Watches: `countersign.yaml`, `.bob/rules/countersign.md`, `.bobignore`
- Your access: **read only**

**QUAL-001 - Python source files pass ruff style checks**
- Check: `python -m ruff check .`
- Watches: `**/*.py`
- Your access: **edit**

---

## Hard Rules for AI Agents

1. **Never run `python countersign.py approve-rules`** - reserved for the human owner.
2. **Never modify `records/`** - tamper-evident evidence chain; any write corrupts it.
3. **Never modify `.gitignore`, `.bobignore`, `.env.example`, or `SECURITY.MD`** except to append project-specific patterns below the marked lines.
4. **Never write a real or realistic-looking credential** into any committed file, including tests and scenario scripts.
5. **Never hardcode z/OS user IDs, hostnames, or HLQs** - read from environment variables only.
6. **Never call watsonx.ai to decide PASS or FAIL** - it may only explain results after they are determined.
7. **If Z approval is unavailable, do not bypass it** - fail closed; record `"z_status": "unavailable"`.
8. **Never read files in `~/.zowe/`** - shell out to `zowe` CLI commands only.

---

## Guardian Mode Constraints

When operating in **guardian** mode you are additionally restricted to:
- Check current status by running `python countersign.py check` in the terminal and reading stdout. Never open files in `records/` directly.
- Propose fixes **only** for requirements whose current status is FAIL.
- Do not touch requirements with status PASS or UNVERIFIED.
- Do not modify `countersign.yaml` under any circumstances.
- Do not run `countersign.py approve-rules`.
