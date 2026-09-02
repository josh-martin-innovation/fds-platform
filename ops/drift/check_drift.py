#!/usr/bin/env python3
"""
FDS Drift & SecOps Agent (Phase 2)

Detects drift between the repository's declared governance baseline and the
current state of the tree. In a real deployment this agent also diffs live cloud
state against the committed IaC; here it enforces the invariants that must hold
in the repo itself, so a scheduled run (or a PR) catches silent weakening even
outside the Policy-as-Code path.

Invariants checked:
  1. Deny-by-default is still present in the policy.
  2. All three CI gates still exist.
  3. CODEOWNERS still protects policy/ and .github/.
  4. No obvious secret material committed (basic heuristic).
  5. The worker still routes authorization through OPA before any DB access.

Exit 0 = no drift; non-zero = drift detected (CI should alert / a human reviews).
"""

import os
import re
import sys

REPO = os.environ.get("GITHUB_WORKSPACE", os.getcwd())


def read(path):
    p = os.path.join(REPO, path)
    if not os.path.exists(p):
        return None
    with open(p, errors="ignore") as f:
        return f.read()


def main():
    problems = []

    pol = read("policy/governance.rego")
    if not pol or "default allow_linkage_job := false" not in pol:
        problems.append("DRIFT: deny-by-default missing from policy/governance.rego")

    for wf in ("policy-as-code.yml", "iac-review.yml", "artifact-integrity.yml"):
        if not os.path.exists(os.path.join(REPO, ".github", "workflows", wf)):
            problems.append(f"DRIFT: CI gate missing (.github/workflows/{wf})")

    co = read(".github/CODEOWNERS")
    if not co or "/policy/" not in co or "/.github/" not in co:
        problems.append("DRIFT: CODEOWNERS no longer protects policy/ and .github/")

    worker = read("worker/federated_worker.py")
    if worker:
        opa_idx = worker.find("OPA DENIED")
        db_idx = worker.find("psycopg2.connect")
        if opa_idx == -1 or db_idx == -1 or opa_idx > db_idx:
            problems.append("DRIFT: worker no longer gates DB access behind OPA authorization")

    secret_pat = re.compile(r"(AKIA[0-9A-Z]{16}|-----BEGIN (RSA|OPENSSH|PRIVATE) KEY-----|ghp_[0-9A-Za-z]{36})")
    for root, _dirs, files in os.walk(REPO):
        if "/.git" in root:
            continue
        for fn in files:
            if fn.endswith((".py", ".yml", ".yaml", ".rego", ".tf", ".md", ".txt", ".json")):
                fp = os.path.join(root, fn)
                try:
                    with open(fp, errors="ignore") as f:
                        if secret_pat.search(f.read()):
                            problems.append(f"DRIFT: possible secret material in {os.path.relpath(fp, REPO)}")
                except Exception:
                    pass

    if problems:
        print("\n".join(problems), file=sys.stderr)
        print(f"\nDRIFT DETECTED: {len(problems)} issue(s).")
        sys.exit(1)

    print("No drift detected: all governance invariants hold.")
    sys.exit(0)


if __name__ == "__main__":
    main()
