#!/usr/bin/env python3
"""
FDS Audit-Ledger Analyst (Phase 2)

Verifies the integrity of the immutable, hash-chained audit ledger produced by
the linkage worker, and flags anomalies. Read-only: never edits the ledger.

Chain rule (must match worker/federated_worker.py step E):
  entry_hash = sha256(prev_hash + ts_isoformat + action + output_hash)
  genesis prev_hash = "0" * 64

Two modes:
  * --db  DSN   : connect to the live Postgres audit ledger (production/lab)
  * --json FILE : verify an exported ledger (list of row dicts) offline / in CI

Exit code 0 = chain intact and no anomalies; non-zero = tampering or anomaly.
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime

GENESIS = "0" * 64
EXPECTED_ACTION = "PPRL_LINKAGE_COMPLETE"


def entry_hash(prev_hash: str, ts_iso: str, action: str, output_hash: str) -> str:
    return hashlib.sha256(f"{prev_hash}{ts_iso}{action}{output_hash}".encode()).hexdigest()


def verify_rows(rows: list) -> dict:
    report = {"entries": len(rows), "chain_intact": True, "problems": [], "anomalies": []}
    expected_prev = GENESIS
    seen_ts = None
    for i, r in enumerate(rows):
        rid = r.get("id", i + 1)

        if r["prev_hash"] != expected_prev:
            report["chain_intact"] = False
            report["problems"].append(
                f"entry {rid}: prev_hash {r['prev_hash'][:12]}... != expected {expected_prev[:12]}..."
            )

        recomputed = entry_hash(r["prev_hash"], r["ts"], r["action"], r["output_hash"])
        if recomputed != r["entry_hash"]:
            report["chain_intact"] = False
            report["problems"].append(
                f"entry {rid}: entry_hash mismatch (row tampered or miscomputed)"
            )

        if r["action"] != EXPECTED_ACTION:
            report["anomalies"].append(f"entry {rid}: unexpected action '{r['action']}'")
        try:
            ts = datetime.fromisoformat(r["ts"])
            if seen_ts and ts < seen_ts:
                report["anomalies"].append(f"entry {rid}: timestamp goes backwards")
            seen_ts = ts
        except Exception:
            report["anomalies"].append(f"entry {rid}: unparseable timestamp '{r['ts']}'")

        expected_prev = r["entry_hash"]

    return report


def load_json(path: str) -> list:
    with open(path) as f:
        data = json.load(f)
    for r in data:
        r["ts"] = str(r["ts"])
    return sorted(data, key=lambda r: r.get("id", 0))


def load_db(dsn: str) -> list:
    import psycopg2
    rows = []
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT id, ts, action, output_hash, prev_hash, entry_hash FROM ledger ORDER BY id;")
        for row in cur.fetchall():
            rows.append({
                "id": row[0], "ts": row[1].isoformat(), "action": row[2],
                "output_hash": row[3], "prev_hash": row[4], "entry_hash": row[5],
            })
    return rows


def main():
    ap = argparse.ArgumentParser(description="Verify FDS audit-ledger hash chain")
    ap.add_argument("--db", help="Postgres DSN of the audit ledger")
    ap.add_argument("--json", help="Path to an exported ledger JSON file")
    args = ap.parse_args()

    if not args.db and not args.json:
        ap.error("provide --db DSN or --json FILE")

    rows = load_db(args.db) if args.db else load_json(args.json)
    report = verify_rows(rows)

    print(json.dumps(report, indent=2))
    if not report["chain_intact"]:
        print("RESULT: FAIL - audit ledger chain is broken (possible tampering).", file=sys.stderr)
        sys.exit(2)
    if report["anomalies"]:
        print("RESULT: PASS with anomalies - chain intact, review flagged items.", file=sys.stderr)
        sys.exit(1)
    print("RESULT: PASS - chain intact, no anomalies.", file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
