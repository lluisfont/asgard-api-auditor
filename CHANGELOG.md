# Changelog

## 0.4.0 - 2026-08-25

### Added

- Coverage-aware endpoint discovery command: `asgard-api-auditor discover`.
- Laravel exposed-route detector for literal HTTP routes and literal `Route::match`.
- Consumed HTTP detectors for Axios, Fetch, Guzzle, Laravel HTTP facade, Dio and Dart `http`.
- Explicit unresolved findings for dynamic URLs, dynamic Laravel routes, route resources/prefixes and unsupported HTTP clients.
- `schemas/endpoint-discovery.schema.json`.
- Endpoint discovery documentation and contract tests.

### Changed

- The auditor now distinguishes `inventory_complete` from `discovery_complete`.
- Full audit generation remains blocked until endpoint enrichment, OpenAPI generation and cross-repository correlation are implemented.

## 0.3.0 - 2026-08-25

### Added

- Deterministic technical inventory.
- Git provenance and clean-working-tree checks.
- Detection of languages, frameworks, HTTP clients, existing API specs and non-HTTP integration surfaces.
- Versioned technical inventory schema and detector planning.

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
