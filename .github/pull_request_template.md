## What this PR changes


## Security & governance checklist
- [ ] If this touches `policy/**`, the OPA tests still pass (`opa test policy/ -v`) and the intent is **not** to weaken a control.
- [ ] Deny-by-default (`default allow_linkage_job := false`) is preserved.
- [ ] No real PII / student / health / justice data added anywhere (synthetic only).
- [ ] No secrets, salts, tokens, or credentials committed.
- [ ] If this touches `iac/**`, `terraform fmt`/`validate` pass and checkov findings were reviewed.
- [ ] A security-owner (CODEOWNERS) has reviewed changes to `policy/**` or `.github/**`.

## How this was tested

