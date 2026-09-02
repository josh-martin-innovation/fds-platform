# FDS Platform — Federated Data System

Reference implementation of a governed, multi-domain **Federated Data System (FDS)** —
the connective infrastructure for linking data across program silos (education,
workforce, health, human services, justice, housing) under governed, purpose-limited
access.

**Status:** Phase 0 prototype demonstrated end-to-end on synthetic data (private
infrastructure). This repository holds the **Phase-1 build/operate scaffolding** —
the CI/CD gates that continuously build and govern the platform.

> Synthetic data only. No real student, health, or justice data belongs in this repo
> or its test fixtures.

## What CI gates this repo (Phase 1)

| Gate | Workflow | What it enforces |
|---|---|---|
| **Policy-as-Code** | `.github/workflows/policy-as-code.yml` | `opa test` must pass on every change to `policy/**`. Governance policy cannot be silently weakened. |
| **IaC Build &amp; Review** | `.github/workflows/iac-review.yml` | `terraform fmt`/`validate`/`tflint`/`checkov` on changes to `iac/**`. |
| **Artifact Integrity** | `.github/workflows/artifact-integrity.yml` | Lints/scans the worker + container definitions (seed of the SBOM/sign/verify chain). |

`policy/**` and `.github/workflows/**` are protected by `CODEOWNERS` so security-relevant
changes require a security-owner review — this prevents policy+test co-modification.

## Layout

```
policy/          OPA governance policy + unit tests (the PDP the FDS enforces)
iac/             Infrastructure-as-Code (Terraform/Bicep) — placeholder in Phase 1
worker/          Reference linkage worker (synthetic-data PPRL + de-identification)
.github/         CI workflows, CODEOWNERS, PR template
```

## Roadmap

- **Phase 1 (this repo):** build/operate CI gates on code + config. No sensitive data.
- **Phase 2:** compliance-evidence, audit-ledger analysis, drift/SecOps agents.
- **Phase 3:** self-managed governed-analysis in the data plane (preserving zero-egress).
