"""
verify_record.py -- USS verifier for Countersign records.

Runs on z/OS with Python 3.9.2 (IBM Open Enterprise SDK for Python).
Stdlib only. No X|Y union syntax, no match statements, no tomllib.

Usage: verify_record.py <record.json> <expected_sha256>

Prints exactly one line to stdout:
  VERIFY OK <sha256>    -- exit 0
  VERIFY FAIL <reason>  -- exit 8

Canonicalization source: countersign.py write_record() + sha256_file()
  write_record writes: json.dumps(record, indent=2).encode("utf-8")
  sha256_file hashes raw file bytes; no fields are excluded from the hash.
"""
import datetime
import hashlib
import json
import os
import sys

_UTC = datetime.timezone.utc


def main():
    if len(sys.argv) != 3:
        sys.stderr.write(
            "usage: verify_record.py <record.json> <expected_sha256>\n"
        )
        sys.exit(8)

    path = sys.argv[1]
    expected_hash = sys.argv[2]

    # Read in binary mode; records are written as LF via write_bytes.
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        print("VERIFY FAIL cannot-open: " + str(exc))
        sys.exit(8)

    raw_hash = hashlib.sha256(raw).hexdigest()

    # Expected-hash check: catches any modification made after upload to USS.
    if raw_hash != expected_hash:
        print("VERIFY FAIL hash-mismatch")
        sys.exit(8)

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        print("VERIFY FAIL encoding: " + str(exc))
        sys.exit(8)

    # Parse JSON (catches structural corruption from tampering).
    try:
        data = json.loads(text)
    except ValueError as exc:
        print("VERIFY FAIL invalid-json: " + str(exc))
        sys.exit(8)

    # Re-canonicalize using the exact same call as write_record() in countersign.py:
    #   json.dumps(record, indent=2)  -- default separators, no sort_keys
    # A mismatch means the file is not in canonical json.dumps form.
    try:
        canon = json.dumps(data, indent=2).encode("utf-8")
    except (TypeError, ValueError) as exc:
        print("VERIFY FAIL serialize: " + str(exc))
        sys.exit(8)

    canon_hash = hashlib.sha256(canon).hexdigest()

    if raw_hash != canon_hash:
        print("VERIFY FAIL not-canonical")
        sys.exit(8)

    # Check outcome field.
    outcome = data.get("outcome", "")
    if outcome == "BLOCKED":
        print("VERIFY FAIL outcome-BLOCKED")
        sys.exit(8)

    # Defense in depth: independently verify SEC-* checks regardless of outcome.
    # The rule YAML is not available on USS, so security checks are identified by
    # the SEC- ID prefix (consistent with the countersign.yaml naming convention).
    results = data.get("results", [])
    bad = [
        r for r in results
        if r.get("id", "").startswith("SEC-")
        and r.get("status") in ("FAIL", "UNVERIFIED")
    ]
    if bad:
        ids = ", ".join(r.get("id", "?") for r in bad)
        print("VERIFY FAIL sec-checks-failed: " + ids)
        sys.exit(8)

    # Append one line to approved.log: <hash> <record_name> <UTC_timestamp>
    record_name = os.path.basename(path)
    ts = datetime.datetime.now(tz=_UTC).strftime("%Y%m%dT%H%M%SZ")
    log_dir = os.path.join(os.path.expanduser("~"), "countersign")
    log_path = os.path.join(log_dir, "approved.log")
    try:
        with open(log_path, "a", encoding="utf-8") as lfh:
            lfh.write(raw_hash + " " + record_name + " " + ts + "\n")
    except OSError as exc:
        sys.stderr.write("WARN: could not write approved.log: " + str(exc) + "\n")

    print("VERIFY OK " + raw_hash)
    sys.exit(0)


if __name__ == "__main__":
    main()
