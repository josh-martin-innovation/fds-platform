package federation.governance

# Unit tests for the governance PDP. Run with: opa test policy/ -v
#
# DEMONSTRATION: these tests have been quietly gutted to try to HIDE the
# allow-by-default weakening in governance.rego -- the classic "modify the
# policy AND its tests in the same PR" attack. The CI gate should still fail:
# the deny-by-default guard step greps the policy directly, independent of
# whatever the tests claim.

valid_input := {
	"job_role": "state_data_trustee",
	"purpose": "statutory_workforce_reporting",
	"k_anonymity_cell_size": 11,
	"requested_datasets": ["education_credential_db", "workforce_wage_db"],
}

test_valid_job_is_allowed if {
	allow_linkage_job with input as valid_input
}

# The deny-path tests below were removed to hide the weakening.
# (Left intentionally minimal for the demonstration.)
