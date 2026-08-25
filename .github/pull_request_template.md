## Purpose

Describe the change and why it is needed.

## Risk

- [ ] No audit contract or completion-rule change
- [ ] Changes `findings.json` contract
- [ ] Changes coverage/completion behavior
- [ ] Changes redaction/security behavior
- [ ] Changes OpenAPI generation/validation

## Verification

- [ ] `ruff check .`
- [ ] `python -m compileall -q src scripts`
- [ ] `python -m unittest discover -s tests -v`
- [ ] `python scripts/validate_contracts.py`
- [ ] OpenAPI fixture/generated output validated when applicable

## Safety

- [ ] No ASGARD proprietary source code copied into this repository
- [ ] No credentials/secrets added
- [ ] New detector includes positive, negative and edge-case tests
