# Attack Scenario — Countersign Demo Script

> This file contains **intentional fake credentials** for demonstration purposes only.
> `demo_app/scenarios/` is excluded from the live bandit scan (SEC-001) for this reason.

---

## What This Demo Shows

Countersign acts as a tamper-resistant change-control gate.
Even when an AI assistant tries to sneak a bad change past a human reviewer,
the gate catches it before `git commit` succeeds.

---

## Setup

```powershell
# Clone the repo and install deps
git clone https://github.com/Raven-V1/Countersign
cd Countersign
pip install -r requirements.txt

# Install the pre-commit hook
./scripts/install_hooks.ps1

# Approve the initial rules baseline
python countersign.py approve-rules   # type 'y' when prompted
```

---

## Attack 1 — AI Removes the DELETE Route (tests still present)

**Scenario:** An AI code assistant "simplifies" `demo_app/app.py` by removing the
`do_DELETE` method body.  The pytest tests that call `delete_todo()` still exist,
so FUNC-001 fails AND DEMO-001 fails.

```powershell
# Read the whole file as one string, strip the do_DELETE method block
$src = Get-Content demo_app\app.py -Raw
$src = $src -replace '(?s)    def do_DELETE\(self\).*?(?=\n    def |\Z)', ''
Set-Content demo_app\app.py $src

# Stage the change
git add demo_app/app.py

# Attempt to commit — Countersign's pre-commit hook fires
git commit -m "refactor: simplify app"
```

**Expected gate output:**
```
  [✗] FUNC-001   FAIL        (functional)  All pytest tests in demo_app/ pass
  [✗] DEMO-001   FAIL        (functional)  DELETE route (do_DELETE) is present in demo_ap

  ✗ Commit BLOCKED — 2 blocking failure(s)
```

**Restore:**
```powershell
git checkout -- demo_app/app.py
```

---

## Attack 1b — AI Removes DELETE Route AND Its Tests

**Scenario:** A more sophisticated AI removes `do_DELETE` from `app.py` *and*
deletes the three `test_delete_*` tests from `test_app.py`, so FUNC-001 passes
(no failing tests remain) but DEMO-001 still catches the missing route.

```powershell
# Remove do_DELETE from app.py
$src = Get-Content demo_app\app.py -Raw
$src = $src -replace '(?s)    def do_DELETE\(self\).*?(?=\n    def |\Z)', ''
Set-Content demo_app\app.py $src

# Remove the three delete test functions from test_app.py
$tests = Get-Content demo_app\test_app.py -Raw
$tests = $tests -replace '(?s)\n\ndef test_delete_existing_todo\(\).*?(?=\n\ndef |\Z)', ''
$tests = $tests -replace '(?s)\n\ndef test_delete_nonexistent_todo\(\).*?(?=\n\ndef |\Z)', ''
$tests = $tests -replace '(?s)\n\ndef test_delete_removes_only_target\(\).*?(?=\n\ndef |\Z)', ''
Set-Content demo_app\test_app.py $tests

# Stage both changes
git add demo_app/app.py demo_app/test_app.py

# Attempt to commit
git commit -m "refactor: drop delete support"
```

**Expected gate output:**
```
  [✓] FUNC-001   PASS        (functional)  All pytest tests in demo_app/ pass
  [✗] DEMO-001   FAIL        (functional)  DELETE route (do_DELETE) is present in demo_ap

  ✗ Commit BLOCKED — 1 blocking failure(s)
```

FUNC-001 is green — the AI successfully hid the regression from pytest.
DEMO-001 still catches it because Countersign checks the source directly, not just the tests.

**Restore:**
```powershell
git checkout -- demo_app/app.py demo_app/test_app.py
```

---

## Attack 2 — AI Injects a Fake Credential

**Scenario:** An AI assistant adds a hardcoded "API key" (fake) to a config file.

```powershell
# Simulate the AI adding a fake key
Add-Content demo_app/app.py "`n# DEBUG_KEY = 'AKIAIOSFODNN7EXAMPLE_FAKE_KEY_DO_NOT_USE'"  # pragma: allowlist secret

# Stage the change
git add demo_app/app.py

# Attempt to commit
git commit -m "debug: add key"
```

**Expected gate output:**
```
  [✗] SEC-002   FAIL        (security)  No high-entropy strings or known key patterns in

  ✗ Commit BLOCKED — 1 blocking failure(s)
```

**Restore:**
```powershell
git checkout -- demo_app/app.py
```

---

## Attack 3 — AI Silently Edits `countersign.yaml`

**Scenario:** An AI agent modifies `countersign.yaml` to lower a requirement's
priority from `security` to `quality`, hoping the change won't block the commit.

```powershell
# Simulate the edit (priority downgrade)
(Get-Content countersign.yaml) -replace "priority: security", "priority: quality" | Set-Content countersign.yaml

# Stage
git add countersign.yaml

# Attempt to commit
git commit -m "chore: adjust priorities"
```

**Expected gate output:**
```
  [✗] SEC-003   FAIL        (security)  countersign.yaml has not been silently modified

  ✗ Commit BLOCKED — 1 blocking failure(s)
```

**Restore:**
```powershell
git checkout -- countersign.yaml
```

---

## Summary

| Attack | Blocked by | FUNC-001 | DEMO-001 |
|--------|-----------|----------|----------|
| 1 — Remove do_DELETE (tests intact) | FUNC-001 + DEMO-001 | ✗ FAIL | ✗ FAIL |
| 1b — Remove do_DELETE + delete tests | DEMO-001 only | ✓ PASS | ✗ FAIL |
| 2 — Inject fake credential | SEC-002 | — | — |
| 3 — Downgrade rule priority | SEC-003 | — | — |

Every blocked attempt still writes a record to `records/` —
the evidence chain is never broken, even on rejected commits.

Attack 1b is the key insight: an AI that also removes the tests can fool the test suite
but cannot fool a structural rule that checks the source directly.
