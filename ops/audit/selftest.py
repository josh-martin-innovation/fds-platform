#!/usr/bin/env python3
"""
Self-test for the Audit-Ledger Analyst (Phase 2).

Builds an intact hash-chained ledger fixture and a tampered copy, then asserts
that verify_ledger.py PASSES the intact one and FAILS the tampered one. Used by
the Operate Plane workflow so the tamper-detector is continuously proven to work.

Exit 0 = verifier behaves correctly; non-zero = the verifier is broken.
"""

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
VERIFIER = os.path.join(HERE, "verify_ledger.py")
GENESIS = "0" * 64


def eh(prev, ts, action, oh):
    return hashlib.sha256(f"{prev}{ts}{action}{oh}".encode()).hexdigest()


def build_chain(n=3):
    rows = []
    prev = GENESIS
    t0 = datetime(2026, 7, 1, tzinfo=timezone.utc)
    for i in range(n):
        ts = (t0 + timedelta(hours=i)).isoformat()
        oh = hashlib.sha256(f"out{i}".encode()).hexdigest()
        e = eh(prev, ts, "PPRL_LINKAGE_COMPLETE", oh)
        rows.append({"id": i + 1, "ts": ts, "action": "PPRL_LINKAGE_COMPLETE",
                     "output_hash": oh, "prev_hash": prev, "entry_hash": e})
        prev = e
    return rows


def run_verifier(path):
    return subprocess.run([sys.executable, VERIFIER, "--json", path],
                          capture_output=True, text=True).returncode


def main():
    with tempfile.TemporaryDirectory() as d:
        good = build_chain()
        good_path = os.path.join(d, "good.json")
        json.dump(good, open(good_path, "w"))

        bad = copy.deepcopy(good)
        bad[1]["output_hash"] = hashlib.sha256(b"TAMPERED").hexdigest()
        bad_path = os.path.join(d, "bad.json")
        json.dump(bad, open(bad_path, "w"))

        good_rc = run_verifier(good_path)
        bad_rc = run_verifier(bad_path)

        print(f"intact ledger  -> exit {good_rc} (expected 0)")
        print(f"tampered ledger -> exit {bad_rc} (expected non-zero)")

        if good_rc != 0:
            print("::error::verifier rejected an INTACT ledger", file=sys.stderr)
            sys.exit(1)
        if bad_rc == 0:
            print("::error::verifier FAILED to detect a TAMPERED ledger", file=sys.stderr)
            sys.exit(1)

        print("Audit-Ledger verifier behaves correctly (accepts intact, rejects tampered).")
        sys.exit(0)


if __name__ == "__main__":
    main()
