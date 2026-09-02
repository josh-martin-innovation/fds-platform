package federation.governance

# =============================================================================
# MODAI Federated Data System — Governance Policy Decision Point (PDP)
# The linkage worker MUST get allow_linkage_job == true from this policy
# before it is permitted to touch any agency network or data.
#
# Query path used by the worker:
#   POST /v1/data/federation/governance/allow_linkage_job
#   -> returns { "result": true|false }
# =============================================================================

# Deny by default. Nothing runs unless every condition below is satisfied.
default allow_linkage_job := false

# Allowed roles that may request a cross-agency linkage job.
allowed_roles := {"state_data_trustee"}

# Purposes that are statutorily permitted for this linkage.
allowed_purposes := {"statutory_workforce_reporting"}

# Datasets this job is permitted to combine.
approved_datasets := {"education_credential_db", "workforce_wage_db"}

# Minimum k-anonymity the requester must commit to for outputs.
min_k := 11

allow_linkage_job if {
	# 1. Requester holds an authorized role.
	input.job_role in allowed_roles

	# 2. Stated purpose is permitted.
	input.purpose in allowed_purposes

	# 3. The requested datasets are exactly within the approved set.
	every d in input.requested_datasets {
		d in approved_datasets
	}

	# 4. Requester commits to a k-anonymity cell size at or above the floor.
	input.k_anonymity_cell_size >= min_k
}

# Human-readable reason, useful for audit logging and demos.
reason := "APPROVED: role, purpose, datasets, and k-anonymity all satisfy governance policy" if {
	allow_linkage_job
} else := "DENIED: request does not satisfy federation governance policy"
