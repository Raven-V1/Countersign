# IBM Hackathon GitHub Project Template

This GitHub project template is for IBM Hackathon projects. It includes pre-configured security files to help prevent accidental credential commits and potential account suspension during the hackathon.

## 🚀 Quick Start

1. **Use this template to create your project:**
   - Click "Use this template" button above and select "Create a new repository"
   - Name your repository
   - Click "Create repository"

2. **Clone your new repository:**

   ```bash
   git clone https://github.com/HACKATHON-ORG/your-repo-name.git
   cd your-repo-name
   ```

3. **Set up environment variables:**

   ```bash
   # Copy the example file
   cp .env.example .env

   # Edit .env with your actual credentials
   # Use your preferred editor (nano, vim, code, etc.)
   nano .env
   ```

4. **Verify .gitignore is working:**

   ```bash
   # This should NOT show .env file
   git status

   # This should confirm .env is ignored
   git check-ignore -v .env
   ```

5. **Start developing!**

## 🔒 Security Features

This template includes:

- **`.gitignore`** - Prevents committing credentials and live session files
- **`.bobignore`** - Prevents AI assistants from logging credentials
- **`.env.example`** - Template for your environment variables

## 📋 Before Every Commit

Always run this checklist:

- [ ] Reviewed `git diff` for sensitive data
- [ ] No hardcoded API keys or passwords
- [ ] `.env` file is NOT in staged changes
- [ ] No files with "credential" or "secret" in name
- [ ] Used environment variables for all credentials

## 🆘 Need Help?

- Read [SECURITY.md](SECURITY.MD) for detailed guidelines
- Contact hackathon support through mentor channel
- Ask in the hackathon Slack workspace

---

**Remember:** Security is everyone's responsibility. When in doubt, ask for help!

---

## IBM Z Approval

Every PASS commit goes through a second verification step running on z/OS USS
before the commit is allowed.  The gate is implemented in `zos/VERIFY.jcl`
(submitted via Zowe CLI) and `zos/verify_record.py` (runs on USS under
Python 3.9).

### What Z verifies

1. **Exact bytes vs expected hash** — `countersign.py` computes a SHA-256 of
   the evidence record *before* writing the Z-approval fields back to the
   file.  That hash is passed to `verify_record.py` as `argv[2]`.  If the
   file on USS does not match byte-for-byte, the job exits 8 (`VERIFY FAIL
   hash-mismatch`).  This catches any modification made after upload —
   including the canonical-tamper attack where an attacker replaces a
   well-formed BLOCKED record with a well-formed PASS record.

2. **Verdict re-check** — `verify_record.py` independently checks that
   `outcome` is not `"BLOCKED"`.  The outcome field is verified against the
   raw bytes that were already hash-checked, so flipping it without changing
   the hash is impossible.

3. **SEC-* re-check** — Every result whose `id` starts with `SEC-` must have
   `status == "PASS"`.  The rule YAML is not available on USS; the `SEC-`
   prefix convention is sufficient.

### The ledger

On `VERIFY OK`, `verify_record.py` appends one line to
`$HOME/countersign/approved.log` on USS:

```
<sha256>  <record_name>  <UTC_timestamp>
```

The `z_verified_hash` field written back into the local record is the same
SHA-256.  This creates a cross-system audit trail: each approved record
carries a hash that must appear in the Z-side ledger.

### z-audit

```
python countersign.py z-audit
```

Downloads `approved.log` from USS (path from `ZOS_USS_DIR` in `.env`) and
checks every local record whose `z_status == "approved"`:

- `OK` — `z_verified_hash` is in the ledger with the correct record name, and
  re-nulling the four Z fields and re-hashing the record reproduces the same
  hash.
- `MISSING-FROM-LEDGER` — the hash is not in the ledger.
- `RECONSTRUCT-MISMATCH` — the record was modified after Z approval.
- `SKIP (pre-ledger)` — approved before the ledger feature existed
  (`z_verified_hash` is `None`).

Exit 0 only if all ledger-eligible records are OK.

### Limitation (demo context)

In this demo, the developer and the `VERIFY` job share the same z/OS user ID,
so there is nothing preventing the developer from writing to `approved.log`
directly.  In production the job would run under a dedicated RACF service ID;
only that ID would have write access to the ledger file, and the developer's
ID would have read-only access at most.  Under that model, a forged ledger
entry requires compromising the RACF service account, which is a much higher
bar than compromising a developer workstation.
