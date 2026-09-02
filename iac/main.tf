# FDS Infrastructure-as-Code (placeholder)
#
# Phase 1 ships a minimal, valid Terraform root so the IaC Build and Review gate
# has something real to fmt/validate/lint/scan. The full ~11k-line multi-cloud
# IaC (13 modules, AWS + Azure) lands here module-by-module in Phase 2, each
# arriving through this same governed CI gate.

terraform {
  required_version = ">= 1.5.0"
}

# Non-sensitive marker so `terraform validate` has a resource to check.
# `null_resource` requires no provider credentials and no cloud access.
resource "null_resource" "fds_placeholder" {
  triggers = {
    note = "Phase 1 scaffolding — replace with real FDS modules in Phase 2."
  }
}
