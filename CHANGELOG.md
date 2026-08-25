# Changelog

## 0.2.0 - 2026-08-25

### Added

- Explicit audit coverage model.
- Stable audit/API/endpoint/detector identifiers.
- Expanded findings contract for requests, responses, consumed fields, security and non-OpenAPI surfaces.
- Conservative completion gate preventing false `complete` results.
- Atomic artifact publication helpers.
- Basic secret redaction utilities.
- OpenAPI 3.1.2 project standard and Redocly configuration.
- CI, CODEOWNERS, contribution guidance and dependency update configuration.
- Contract, coverage, redaction and publication tests.

### Changed

- `complete` now requires proven coverage, not merely classification of discovered findings.
- RAG knowledge template includes schema/audit/auditor metadata and stable endpoint IDs.
