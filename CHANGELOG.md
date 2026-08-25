# Changelog

## 0.3.0 - 2026-08-25

### Added

- Deterministic technical repository inventory command.
- Exact Git commit/ref verification before scanning.
- Clean-working-tree requirement with explicit diagnostic `--allow-dirty` mode.
- Stable repository identity using explicit ID, sanitized origin, or documented directory fallback.
- Language, framework, HTTP client and integration-surface detection with evidence and confidence.
- Existing OpenAPI/Swagger specification signals.
- Detector-category planning and detector hints for later endpoint discovery.
- Explicit exclusion of dependency/build/generated directories to reduce false positives.
- Fail-closed handling for symlinks, submodules, oversized candidates and manifest/read errors.
- Versioned `technical-inventory.schema.json` contract.
- CLI and inventory tests, including false-positive and provenance cases.

## 0.2.0 - 2026-08-25

### Added

- Explicit audit coverage model.
- Stable audit/API/endpoint/detector identifiers.
- Expanded findings contract for requests, responses, consumed fields, security and non-OpenAPI surfaces.
- Conservative completion gate preventing false `complete` results.
- Atomic artifact publication helpers.
- Basic redaction utilities.
- OpenAPI 3.1.2 project standard and Redocly configuration.
- CI, CODEOWNERS, contribution guidance and dependency update configuration.
- Contract, coverage, redaction and publication tests.

### Changed

- `complete` now requires proven coverage, not merely classification of discovered findings.
- RAG knowledge template includes schema/audit/auditor metadata and stable endpoint IDs.
