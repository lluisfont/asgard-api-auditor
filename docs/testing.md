# Testing Strategy

## Required test layers

### Contract tests

Verify constants, required schema fields, output metadata and completion rules.

### Detector tests

Every detector must have:

- positive fixture;
- negative fixture;
- edge/dynamic fixture;
- false-positive test;
- coverage-status test.

### Redaction tests

Verify credentials and secret-like query/header values are removed without destroying structural information.

### Publication tests

Verify:

- missing output prevents publication;
- failed validation does not replace previous audit;
- successful publish replaces a complete audit set atomically as far as the local filesystem allows.

### OpenAPI tests

Generated fixtures must pass Redocly CLI 2.47.0 validation in CI.

## CI gates

Pull requests run:

1. Ruff;
2. Python compile check;
3. unittest;
4. contract validation;
5. Redocly lint for OpenAPI fixtures.
