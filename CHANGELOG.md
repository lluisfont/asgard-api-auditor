# Changelog

## 0.4.2 - 2026-08-25

### Fixed

- Slim route discovery now only inspects verified Slim app/router receivers, avoiding false positives such as SFTP `->put(...)` calls.
- Fetch discovery resolves same-class literal properties such as `fetch(this.API_URL, { method: 'POST' })` with multiline options.
- PHP cURL discovery supports classic `curl_setopt_array($curl, array(...))` syntax.
- cURL constant/expression bases remain traceable without inventing constant values.

### Changed

- Fetch coverage no longer emits the aggregate no-calls issue once a supported call has been proven.
- Dynamic `curl_init($url)` remains fail-closed unless the URL can be proven deterministically.

## 0.4.1 - 2026-08-25

### Added

- Slim 4 route discovery for literal `$app->get/post/put/patch/delete/options(...)` routes.
- Angular `HttpClient` consumer discovery with simple `GLOBAL.url`/`this.url` assignment and concatenation resolution.
- PHP cURL consumer discovery for `curl_init`, `curl_setopt` and `curl_setopt_array`.
- SOAP integration findings that stay separate from REST endpoints and keep discovery partial until full WSDL extraction exists.
- Repeatable `--exclude-path` for `inventory` and `discover`.

### Fixed

- Angular `HttpClient` is no longer misclassified as .NET `HttpClient`.
- PHP `PDO::fetch` is no longer misclassified as JavaScript HTTP `fetch`.
- Source-code technology signatures are now scoped by file extension/language.

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
