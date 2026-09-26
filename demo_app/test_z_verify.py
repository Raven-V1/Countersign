"""
demo_app/test_z_verify.py -- Parity tests for zos/verify_record.py.

Runs verify_record.py as a subprocess against these cases:
  Z-1. Real PASS record from records/          -> exit 0, "VERIFY OK <hash>"
  Z-2. Tampered copy (original hash passed)    -> exit 8, "VERIFY FAIL"
  Z-3. Synthetic BLOCKED record                -> exit 8, "VERIFY FAIL"
  Z-4. Wrong expected hash                     -> exit 8, "hash-mismatch"
  Z-5. Canonical tamper (FAIL->PASS, orig hash)-> exit 8, "hash-mismatch"
  Z-6. z_verified_hash round-trip              -> reconstruction hash matches

No Zowe calls are made; the autouse _no_network fixture blocks the SDK.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

_VR_SCRIPT = Path(__file__).parent.parent / "zos" / "verify_record.py"
_RECORDS_DIR = Path(__file__).parent.parent / "records"

_CRED_VARS = ("IBM_CLOUD_API_KEY", "WATSONX_URL", "WATSONX_PROJECT_ID")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Clear watsonx credentials and stub the SDK for every test."""
    for var in _CRED_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("countersign.load_dotenv", lambda **kw: None, raising=False)

    def _no_call(*a, **kw):
        raise RuntimeError("network call in test")

    monkeypatch.setattr("ibm_watsonx_ai.APIClient",                        _no_call, raising=False)
    monkeypatch.setattr("ibm_watsonx_ai.foundation_models.ModelInference", _no_call, raising=False)


def _run_vr(path: Path, expected_hash: str) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, str(_VR_SCRIPT), str(path), expected_hash],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    return result.returncode, (result.stdout + result.stderr).strip()


def _latest_pass_record() -> Path:
    """Return the most-recent record in records/ whose outcome is PASS."""
    candidates = sorted(
        (f for f in _RECORDS_DIR.glob("*.json") if f.is_file()),
        reverse=True,
    )
    for f in candidates:
        try:
            data = json.loads(f.read_bytes().decode("utf-8"))
        except (OSError, UnicodeDecodeError, ValueError):
            continue
        if data.get("outcome") == "PASS":
            return f
    pytest.skip("no PASS record found in records/")


# ---------------------------------------------------------------------------
# Z-1: good record -> exit 0
# ---------------------------------------------------------------------------


def test_verify_good_record():
    record = _latest_pass_record()
    raw = record.read_bytes()
    h = hashlib.sha256(raw).hexdigest()
    rc, out = _run_vr(record, h)
    assert rc == 0, f"expected exit 0 for PASS record, got {rc}\noutput: {out}"
    assert out.startswith("VERIFY OK "), f"unexpected output: {out}"


# ---------------------------------------------------------------------------
# Z-2: tampered record (original hash passed) -> exit 8, hash-mismatch
# ---------------------------------------------------------------------------


def test_verify_tampered_record(tmp_path):
    record = _latest_pass_record()
    raw = record.read_bytes()
    original_hash = hashlib.sha256(raw).hexdigest()

    # Replace the opening '{' — changes the bytes without touching any field value.
    idx = raw.index(b"{")
    tampered = raw[:idx] + b"X" + raw[idx + 1:]
    tampered_file = tmp_path / "tampered.json"
    tampered_file.write_bytes(tampered)

    rc, out = _run_vr(tampered_file, original_hash)
    assert rc == 8, f"expected exit 8 for tampered record, got {rc}\noutput: {out}"
    assert "VERIFY FAIL" in out, f"expected VERIFY FAIL in output: {out}"


# ---------------------------------------------------------------------------
# Z-3: BLOCKED record -> exit 8
# ---------------------------------------------------------------------------


def test_verify_blocked_record(tmp_path):
    blocked = {
        "timestamp": "20260101T000000Z",
        "git_hash": "0" * 40,
        "prev_record_fingerprint": "genesis",
        "outcome": "BLOCKED",
        "z_status": None,
        "z_job_id": None,
        "z_rc": None,
        "z_verified_hash": None,
        "wx_model_id": "",
        "wx_error": "",
        "results": [
            {
                "id": "SEC-001",
                "status": "FAIL",
                "check": "python -m bandit -r .",
                "output": "Issue found",
                "plain_english": "",
            }
        ],
    }
    blocked_bytes = json.dumps(blocked, indent=2).encode("utf-8")
    blocked_file = tmp_path / "blocked.json"
    blocked_file.write_bytes(blocked_bytes)
    blocked_hash = hashlib.sha256(blocked_bytes).hexdigest()

    rc, out = _run_vr(blocked_file, blocked_hash)
    assert rc == 8, f"expected exit 8 for BLOCKED record, got {rc}\noutput: {out}"
    assert "VERIFY FAIL" in out, f"expected VERIFY FAIL in output: {out}"


# ---------------------------------------------------------------------------
# Z-4: wrong expected hash -> exit 8, hash-mismatch
# ---------------------------------------------------------------------------


def test_verify_hash_mismatch(tmp_path):
    record = _latest_pass_record()
    wrong_hash = "0" * 64
    rc, out = _run_vr(record, wrong_hash)
    assert rc == 8, f"expected exit 8 for hash mismatch, got {rc}\noutput: {out}"
    assert "hash-mismatch" in out, f"expected 'hash-mismatch' in output: {out}"


# ---------------------------------------------------------------------------
# Z-5: canonical tamper (FAIL->PASS edit, original hash) -> exit 8, hash-mismatch
# This is the attack that the old verifier (no expected_hash) could not catch.
# ---------------------------------------------------------------------------


def test_verify_canonical_tamper_with_original_hash(tmp_path):
    # Build a BLOCKED record in canonical form.
    original = {
        "timestamp": "20260101T120000Z",
        "git_hash": "a" * 40,
        "prev_record_fingerprint": "genesis",
        "outcome": "BLOCKED",
        "z_status": None,
        "z_job_id": None,
        "z_rc": None,
        "z_verified_hash": None,
        "wx_model_id": "",
        "wx_error": "",
        "results": [
            {
                "id": "SEC-001",
                "status": "FAIL",
                "check": "python -m bandit -r .",
                "output": "Issue found",
                "plain_english": "",
            }
        ],
    }
    original_bytes = json.dumps(original, indent=2).encode("utf-8")
    original_hash = hashlib.sha256(original_bytes).hexdigest()

    # Attacker flips outcome and SEC-001 status, writes a canonical new record.
    tampered = dict(original)
    tampered["outcome"] = "PASS"
    tampered["results"] = [
        {
            "id": "SEC-001",
            "status": "PASS",
            "check": "python -m bandit -r .",
            "output": "",
            "plain_english": "",
        }
    ]
    tampered_bytes = json.dumps(tampered, indent=2).encode("utf-8")
    tampered_file = tmp_path / "tampered_canonical.json"
    tampered_file.write_bytes(tampered_bytes)

    # Passing the original hash against the tampered file must fail.
    rc, out = _run_vr(tampered_file, original_hash)
    assert rc == 8, f"expected exit 8 for canonical tamper, got {rc}\noutput: {out}"
    assert "hash-mismatch" in out, f"expected 'hash-mismatch' in output: {out}"


# ---------------------------------------------------------------------------
# Z-6: z_verified_hash round-trip (tests countersign._update_record_z logic)
# ---------------------------------------------------------------------------


def test_z_verified_hash_round_trip(tmp_path):
    """Pre-Z bytes -> z_verified_hash stored -> reconstruct -> hashes agree."""
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).parent.parent))
    import countersign

    pre_z = {
        "timestamp": "20260101T000000Z",
        "git_hash": "b" * 40,
        "prev_record_fingerprint": "genesis",
        "outcome": "PASS",
        "z_status": None,
        "z_job_id": None,
        "z_rc": None,
        "z_verified_hash": None,
        "wx_model_id": "",
        "wx_error": "",
        "results": [
            {
                "id": "SEC-001",
                "status": "PASS",
                "check": "test",
                "output": "",
                "plain_english": "",
            }
        ],
    }
    pre_z_bytes = json.dumps(pre_z, indent=2).encode("utf-8")
    pre_z_hash = hashlib.sha256(pre_z_bytes).hexdigest()

    record_file = tmp_path / "roundtrip.json"
    record_file.write_bytes(pre_z_bytes)

    # Simulate _update_record_z writing back Z-approval fields.
    countersign._update_record_z(
        record_file,
        z_status="approved",
        z_job_id="JOB99999",
        z_rc=0,
        z_verified_hash=pre_z_hash,
    )

    updated = json.loads(record_file.read_bytes().decode("utf-8"))
    assert updated["z_verified_hash"] == pre_z_hash

    # Reconstruct pre-Z state (mirrors cmd_verify_chain logic).
    recon = dict(updated)
    recon["z_status"] = None
    recon["z_job_id"] = None
    recon["z_rc"] = None
    recon["z_verified_hash"] = None
    recon_hash = hashlib.sha256(json.dumps(recon, indent=2).encode("utf-8")).hexdigest()

    assert recon_hash == pre_z_hash, (
        f"Round-trip failed:\n  pre_z_hash={pre_z_hash}\n  recon_hash={recon_hash}"
    )


# ---------------------------------------------------------------------------
# Z-7: z-audit OK — all approved records appear in the ledger
# ---------------------------------------------------------------------------


def _make_approved_record(tmp_dir: Path, name: str) -> tuple[Path, str]:
    """Write a minimal approved record; return (path, z_verified_hash)."""
    pre_z = {
        "timestamp": name,
        "git_hash": "c" * 40,
        "prev_record_fingerprint": "genesis",
        "outcome": "PASS",
        "z_status": None,
        "z_job_id": None,
        "z_rc": None,
        "z_verified_hash": None,
        "wx_model_id": "",
        "wx_error": "",
        "results": [],
    }
    pre_z_bytes = json.dumps(pre_z, indent=2).encode("utf-8")
    zvh = hashlib.sha256(pre_z_bytes).hexdigest()

    approved = dict(pre_z)
    approved["z_status"] = "approved"
    approved["z_job_id"] = "JOB00001"
    approved["z_rc"] = 0
    approved["z_verified_hash"] = zvh
    rec_file = tmp_dir / f"{name}.json"
    rec_file.write_bytes(json.dumps(approved, indent=2).encode("utf-8"))
    return rec_file, zvh


def test_z_audit_ok(tmp_path):
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).parent.parent))
    import countersign

    rec_dir = tmp_path / "records"
    rec_dir.mkdir()
    rec_file, zvh = _make_approved_record(rec_dir, "20260101T000000Z")
    rname = rec_file.name

    ledger = {zvh: {rname}}
    rc = countersign._audit_records(ledger, records_dir=rec_dir)
    assert rc == 0, "expected z-audit OK"


def test_z_audit_missing_from_ledger(tmp_path):
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).parent.parent))
    import countersign

    rec_dir = tmp_path / "records"
    rec_dir.mkdir()
    _make_approved_record(rec_dir, "20260101T000000Z")

    ledger: dict = {}  # empty ledger
    rc = countersign._audit_records(ledger, records_dir=rec_dir)
    assert rc == 1, "expected z-audit to fail when record missing from ledger"


def test_z_audit_reconstruct_mismatch(tmp_path):
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).parent.parent))
    import countersign

    rec_dir = tmp_path / "records"
    rec_dir.mkdir()
    rec_file, zvh = _make_approved_record(rec_dir, "20260101T000000Z")
    rname = rec_file.name

    # Tamper the record: change a field without updating z_verified_hash
    data = json.loads(rec_file.read_bytes().decode("utf-8"))
    data["wx_model_id"] = "tampered"
    rec_file.write_bytes(json.dumps(data, indent=2).encode("utf-8"))

    ledger = {zvh: {rname}}
    rc = countersign._audit_records(ledger, records_dir=rec_dir)
    assert rc == 1, "expected z-audit to fail on reconstruct mismatch"
