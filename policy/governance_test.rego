package federation.governance

# Unit tests for the governance PDP. Run with: opa test policy/ -v

# The exact input the worker sends on the happy path.
valid_input := {
	"job_role": "state_data_trustee",
	"purpose": "statutory_workforce_reporting",
	"k_anonymity_cell_size": 11,
	"requested_datasets": ["education_credential_db", "workforce_wage_db"],
}

test_valid_job_is_allowed if {
	allow_linkage_job with input as valid_input
}

test_wrong_role_denied if {
	not allow_linkage_job with input as object.union(valid_input, {"job_role": "random_researcher"})
}

test_wrong_purpose_denied if {
	not allow_linkage_job with input as object.union(valid_input, {"purpose": "marketing"})
}

test_unapproved_dataset_denied if {
	not allow_linkage_job with input as object.union(valid_input, {"requested_datasets": ["education_credential_db", "justice_records_db"]})
}

test_k_below_floor_denied if {
	not allow_linkage_job with input as object.union(valid_input, {"k_anonymity_cell_size": 5})
}

test_missing_fields_denied if {
	not allow_linkage_job with input as {"job_role": "state_data_trustee"}
}
