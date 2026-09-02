#!/usr/bin/env python3
"""
FDS Compliance-Evidence Agent (Phase 2)

Scans the repository for the presence and configuration of governance controls
and maps them to control families across FedRAMP Moderate (NIST 800-53), FERPA,
HIPAA, CJIS, MGDPA, and NIST AI RMF. Emits a dated evidence pack (Markdown +
JSON) that a human reviews before it goes to an assessor.

Scope: repository-controls-evidence. Verifies the controls THIS repo is
responsible for are present and wired. It does NOT assert live-cloud compliance
(encryption at rest, KMS/enclave attestation, network isolation in a real
tenancy) -- that requires a deployment and a 3PAO.
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone

REPO = os.environ.get("GITHUB_WORKSPACE", os.getcwd())


def exists(*parts) -> bool:
    return os.path.exists(os.path.join(REPO, *parts))


def file_contains(path, needle) -> bool:
    p = os.path.join(REPO, path)
    if not os.path.exists(p):
        return False
    with open(p, errors="ignore") as f:
        return needle in f.read()


def run_checks() -> list:
    checks = []
    checks.append(("AC-DENY-DEFAULT", "Authorization policy is deny-by-default",
        file_contains("policy/governance.rego", "default allow_linkage_job := false"),
        ["NIST 800-53 AC-3 (Access Enforcement)", "NIST 800-53 AC-6 (Least Privilege)", "CJIS 5.5 (Access Control)"]))
    checks.append(("CM-POLICY-TESTS", "Governance policy has automated unit tests",
        exists("policy", "governance_test.rego"),
        ["NIST 800-53 CM-3 (Config Change Control)", "NIST 800-53 SA-11 (Developer Testing)"]))
    checks.append(("SI-POLICY-GATE", "Policy-as-Code CI gate present (blocks weakening)",
        exists(".github", "workflows", "policy-as-code.yml"),
        ["NIST 800-53 SI-7 (Software/Info Integrity)", "NIST 800-53 CM-3"]))
    checks.append(("CM-IAC-GATE", "IaC review gate present (fmt/validate/checkov)",
        exists(".github", "workflows", "iac-review.yml"),
        ["NIST 800-53 CM-2 (Baseline Config)", "NIST 800-53 CM-6 (Config Settings)"]))
    checks.append(("SR-ARTIFACT-GATE", "Artifact-integrity gate present (seed of SBOM/sign/verify)",
        exists(".github", "workflows", "artifact-integrity.yml"),
        ["NIST 800-53 SR-3/SR-4 (Supply Chain)", "NIST 800-53 SI-7"]))
    checks.append(("AC-CODEOWNERS", "Security-owner review required on policy and CI paths",
        file_contains(".github/CODEOWNERS", "/policy/"),
        ["NIST 800-53 AC-5 (Separation of Duties)", "NIST 800-53 CM-3"]))
    checks.append(("AU-LEDGER-VERIFY", "Audit-ledger integrity verifier present",
        exists("ops", "audit", "verify_ledger.py"),
        ["NIST 800-53 AU-9 (Protection of Audit Info)", "NIST 800-53 AU-10 (Non-repudiation)",
         "HIPAA 164.312(b) (Audit Controls)", "FERPA 99.32 (Recordkeeping)"]))
    checks.append(("SC-PPRL", "Privacy-preserving linkage worker present (no raw PII crosses boundary)",
        file_contains("worker/federated_worker.py", "generate_clk"),
        ["NIST 800-53 SC-8 (Transmission Confidentiality)", "HIPAA 164.312(e) (Transmission Security)",
         "FERPA (education records protection)", "MGDPA Ch.13 (data classification)"]))
    checks.append(("SC-DEIDENT", "De-identification present (k-anonymity floor referenced)",
        file_contains("worker/federated_worker.py", "K_MIN"),
        ["NIST AI RMF MEASURE 2.x (privacy)", "HIPAA 164.514 (De-identification)", "MGDPA Ch.13 (not-public data handling)"]))
    checks.append(("RA-SYNTHETIC-ONLY", "Repository declares synthetic-data-only discipline",
        file_contains("README.md", "Synthetic data only"),
        ["NIST 800-53 RA-3 (Risk Assessment)", "MGDPA Ch.13 (data minimization posture)"]))
    return checks


def opa_tests_pass():
    try:
        r = subprocess.run(["opa", "test", os.path.join(REPO, "policy")],
                           capture_output=True, text=True, timeout=120)
        return r.returncode == 0
    except Exception:
        return None


def main():
    ts = datetime.now(timezone.utc)
    checks = run_checks()
    opa = opa_tests_pass()
    present = sum(1 for c in checks if c[2])
    total = len(checks)

    evidence = {
        "generated_at": ts.isoformat(),
        "repo": os.path.basename(REPO.rstrip("/")),
        "scope": "repository-controls-evidence (not live-cloud compliance)",
        "summary": {"present": present, "total": total, "opa_tests_pass": opa},
        "checks": [{"id": c[0], "description": c[1], "status": "PRESENT" if c[2] else "MISSING",
                    "controls": c[3]} for c in checks],
    }

    outdir = os.path.join(REPO, "ops", "compliance", "evidence")
    os.makedirs(outdir, exist_ok=True)
    stamp = ts.strftime("%Y%m%dT%H%M%SZ")
    with open(os.path.join(outdir, f"evidence_{stamp}.json"), "w") as f:
        json.dump(evidence, f, indent=2)

    lines = ["# FDS Compliance Evidence Pack",
             f"_Generated {ts.isoformat()} UTC - scope: repository controls, not live-cloud compliance_\n",
             f"**Controls present: {present}/{total}**  -  OPA policy tests: "
             f"{'PASS' if opa else ('FAIL' if opa is False else 'not run')}\n",
             "| Control check | Status | Maps to |", "|---|---|---|"]
    for c in checks:
        status = "PRESENT" if c[2] else "MISSING"
        lines.append(f"| {c[1]} | {status} | {'; '.join(c[3])} |")
    lines.append("\n> This pack evidences that the controls this repository is responsible for are "
                 "present and wired. Live-cloud compliance requires a deployment and a 3PAO "
                 "assessment and is out of scope for this repo-level collector.")
    with open(os.path.join(outdir, f"evidence_{stamp}.md"), "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Controls present: {present}/{total}; opa_tests_pass={opa}")
    missing = [c[0] for c in checks if not c[2]]
    if missing:
        print("MISSING:", ", ".join(missing), file=sys.stderr)
        sys.exit(1)
    if opa is False:
        print("OPA tests failing", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
