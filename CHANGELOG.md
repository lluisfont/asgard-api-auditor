# Changelog

## 0.5.3 - 2026-08-26

### Added

- Deterministic PHP request reconstruction now supports unused `json_decode` filtering, top-level JSON arrays, scalar lists, array-of-object access, element aliases, `foreach` aliases, bounded nested array/object access and limited unique local positional propagation.
- Multipart request reconstruction now supports literal `$_POST[...]` fields and `$_FILES[...]` uploads.

### Changed

- Request applicability is calculated from demonstrated request-body usage rather than from every body `json_decode`.
- Dynamic request keys remain fail-closed, while dynamic outer indices with literal object keys can now be reconstructed.
- Audit status remains `partial` behind an explicit v0.5.3 coverage gate until SOAP and later provider/consumer completion gates are closed.

## 0.5.2 - 2026-08-26

### Added

- Deterministic Slim/PHP contract enrichment for exposed endpoints during audit artifact generation.
- Path parameters now carry source evidence and survive v0.5.1 OpenAPI canonical path mapping.
- Supported Slim/PHP patterns enrich JSON request body fields, optional `??` defaults, JSON response fields, `Content-Type: application/json`, route middleware and demonstrated JWT Authorization header evidence without assuming bearer syntax.
- Unique local Slim/PHP middleware closures can now provide route authentication evidence for routes using `->add($verifyToken)`.
- Findings coverage now includes objective contract-enrichment counters and unresolved contract-enrichment findings.

### Changed

- OpenAPI generation uses only demonstrated request/response/security enrichment and still avoids consumed HTTP and SOAP provider paths.
- Audit status remains `partial` behind an explicit v0.5.2 coverage gate instead of claiming behavioral completion.

## 0.5.1 - 2026-08-26

### Fixed

- OpenAPI generation canonicalizes source route templates that differ only by parameter names when their HTTP methods are distinct, avoiding invalid duplicate path templates without dropping operations.
- Canonicalized operations preserve the exact source path and original parameter name through `x-asgard-source-path`, `x-asgard-source-paths` and `x-asgard-source-parameter-name` traceability extensions.
- Multiple source routes with the same template shape and the same HTTP method now fail closed instead of being overwritten or silently merged.

### Changed

- Redocly keeps identical template paths as an error while treating source-preserved trailing slashes as guidance rather than rewriting observed behavior.
- Unknown server URLs and security schemes remain intentionally uninvented until contract enrichment proves them.

## 0.5.0 - 2026-08-26

### Added

- `asgard-api-auditor audit` now generates the four primary audit artifacts: `openapi.yaml`, `api-knowledge.md`, `findings.json` and `audit-report.md`.
- Generated OpenAPI contains only proven exposed HTTP paths/methods and carries ASGARD audit/source traceability extensions.
- API Knowledge retains exposed HTTP, consumed HTTP, non-HTTP integrations, evidence and unresolved discovery findings.
- Findings generation maps discovery and technical-inventory evidence into the versioned findings contract.
- Audit artifacts are validated together and atomically published using the existing fail-safe artifact pipeline.
- `audit` accepts `--repository-id`, repeatable `--exclude-path`, `--allow-dirty` and repeatable `--soap-wsdl` mappings.

### Changed

- Full audit generation is no longer blocked, but v0.5.0 audit status remains deliberately `partial` because request/response/authentication/authorization enrichment is not yet implemented.
- Consumed HTTP calls are never emitted as provider OpenAPI paths.
- SOAP remains a separate integration surface and is never converted into REST/OpenAPI paths.
- A blocking `contract-enrichment-v0.5.0` unresolved finding prevents structural artifact generation from being misrepresented as a complete behavioral contract.

## 0.4.5 - 2026-08-26

### Added

- Repeatable `--soap-wsdl SERVICE=PATH` mappings for explicitly supplying repository-local SOAP contract snapshots.
- SOAP snapshot validation requires the WSDL path to remain inside the audited repository and be tracked by Git.
- SOAP operations discovered in code are validated against the supplied WSDL; missing operations produce blocking `soap_operation_not_in_wsdl` findings.
- Explicit WSDL snapshots enrich SOAP findings with service, port, binding, input message and output message metadata.

### Changed

- SOAP contract completion can become `true` when all detected SOAP operations are backed by valid local or explicitly supplied versioned WSDL snapshots.
- Discovery never downloads WSDLs from the network; reproducibility remains mandatory.

## 0.4.4 - 2026-08-26

### Added

- SOAP operation discovery now traces PHP `SoapClient` usage separately from REST/HTTP endpoints.
- SOAP clients passed as deterministic positional arguments into same-repository class methods can be propagated to operation calls with evidence for creation, argument passing, parameter receiving and operation usage.
- Endpoint discovery now reports `soap_operations_complete`, `soap_contracts_complete`, `soap_services` and `soap_operations`.
- Local WSDL snapshots are parsed for service, port, binding and operation message metadata when available.

### Changed

- SOAP contract extraction remains fail-closed: external or unresolved WSDL expressions keep `discovery_complete=false` while preserving detected operations.
- SOAP findings are not converted into REST endpoints or OpenAPI paths.

## 0.4.3 - 2026-08-25

### Added

- PHP cURL discovery can now resolve local, same-class HTTP wrappers through deterministic `$this->method(...)` call chains.
- Wrapper resolution preserves evidence for the original call site, intermediate wrapper calls, `curl_init(...)`, and local URL construction helpers.

### Fixed

- Warehouse-style Blob Storage calls such as `callHttp(...) -> callHttpCurl(...) -> curl_init($url)` now produce the real HTTP operations instead of a generic unresolved cURL URL.
- Dynamic wrapper methods, unknown wrapper targets, and unresolved URL/method values continue to fail closed.

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
