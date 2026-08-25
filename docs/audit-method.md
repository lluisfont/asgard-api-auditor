# Audit Method

## Definition of a complete repository audit

A repository audit is `complete` only when the auditor can demonstrate coverage of the repository's detectable integration surfaces. Classification of discovered findings alone is not sufficient.

The auditor investigates at minimum:

1. **Exposed HTTP endpoints** — routes implemented by the repository.
2. **Consumed HTTP endpoints** — outbound HTTP/API calls made by the repository.
3. **Other integration surfaces** — GraphQL, WebSocket, gRPC, SOAP, SSE, webhook patterns or other protocols when detected.

## Phase 1 — Identify the audited snapshot

Record:

- `audit_id`;
- auditor version;
- repository/repository ID;
- source location;
- branch or ref;
- exact commit SHA;
- audit timestamp.

The exact commit is mandatory for publishable outputs.

## Phase 2 — Inventory repository and coverage prerequisites

Inventory relevant files and detect languages, frameworks and integration libraries before endpoint discovery.

Search at minimum for:

- route definitions;
- controllers/handlers;
- middleware;
- API/service layers;
- HTTP clients;
- SDK wrappers/generated clients;
- environment and configuration files;
- tests;
- existing OpenAPI/Swagger files;
- Postman collections when present;
- webhook handlers and emitters;
- GraphQL/gRPC/WebSocket/SOAP/SSE indicators.

Generated dependencies/vendor directories should be excluded unless evidence requires them.

The inventory must record files scanned, files excluded and exclusion rules.

## Phase 3 — Select and run detectors

For every detected framework/client/integration pattern, resolve a detector and record:

- detector ID;
- detector version;
- category;
- status;
- files inspected;
- supported/unsupported patterns;
- notes/errors.

If a relevant pattern has no supported detector, audit status cannot be `complete`.

## Phase 4 — Discover exposed HTTP endpoints

For every route found, attempt to determine:

- stable endpoint ID;
- API/logical service ID when resolvable;
- HTTP method;
- normalized path;
- handler/controller;
- path/query/header parameters;
- request content type/body/schema;
- response status codes/schema/fields;
- authentication/authorization;
- evidence paths and line ranges;
- confidence and confidence reason.

Unresolved details remain explicit; they are not silently invented or discarded.

## Phase 5 — Discover consumed HTTP endpoints

Search for outbound integrations including, where relevant:

- cURL;
- Guzzle;
- framework HTTP clients;
- Axios;
- Fetch;
- Dart `http`;
- Dio;
- generated SDKs;
- configured base URLs;
- webhook destinations;
- raw HTTP wrappers.

For every call found, capture:

- stable endpoint ID;
- method;
- base URL/path when resolvable;
- calling file/function;
- request fields;
- response fields actually read by the consumer;
- authentication mechanism when visible;
- evidence;
- probable provider only when supported by evidence.

`response_fields_used` is mandatory when it can be determined because it is central to impact analysis.

## Phase 6 — Detect non-OpenAPI integration surfaces

Record detected GraphQL, WebSocket, gRPC, SOAP, SSE or other integration surfaces.

If such a surface is detected but the auditor cannot cover it sufficiently, mark it `unsupported` or `partial`; do not ignore it and do not return `complete`.

## Phase 7 — Normalize and classify

Normalize equivalent paths/methods while preserving original evidence.

Confidence values:

- `confirmed`;
- `probable`;
- `unverified`.

Absence/coverage must be represented independently:

- `confirmed_absent`;
- `not_detected`;
- `unknown`;
- `unsupported`.

`not_detected` must never be presented as proof of absence.

## Phase 8 — Generate OpenAPI AS-IS

Generate OpenAPI **3.1.2** only from sufficiently supported exposed HTTP endpoints.

Rules:

- do not invent missing schema details;
- retain incomplete facts explicitly;
- use vendor extensions for ASGARD traceability when useful (`x-asgard-*`);
- represent actual error behavior before proposing a target standard;
- never include secrets or real credentials;
- validate the generated document with Redocly CLI 2.47.0 or an explicitly approved replacement.

If the repo has no confirmed exposed HTTP API, the audit report must state that distinction; lack of output content must not be confused with lack of coverage.

## Phase 9 — Generate RAG knowledge

Create `api-knowledge.md` containing:

- schema/audit/auditor metadata;
- repository identity and commit;
- coverage summary;
- exposed APIs/endpoints with stable IDs;
- consumed APIs/endpoints with stable IDs;
- provider/consumer relationships;
- fields consumed where detectable;
- evidence;
- non-HTTP surfaces;
- unresolved items;
- impact notes supported by evidence.

## Phase 10 — Generate findings and report

`findings.json` is the canonical machine-readable derived knowledge for that audit. `audit-report.md` is the human review layer.

The report must explicitly state coverage limitations, unsupported surfaces and detector failures.

## Phase 11 — Compare with previous audit

When previous approved artifacts exist, identify:

- new endpoints;
- removed endpoints;
- changed methods/paths;
- request/response contract changes;
- changed consumed response fields;
- changed consumers/providers;
- changed authentication;
- probable breaking changes.

Do not overwrite evidence of a breaking change without reporting it.

## Phase 12 — Validate as one audit set

Before publication verify:

- all four outputs exist;
- all outputs share the same `audit_id`, repository and commit;
- findings contract is valid;
- OpenAPI is valid when generated;
- secrets are redacted;
- coverage gate allows the proposed status.

## Phase 13 — Atomic publication

Publish only after all validations pass. Candidate files must be staged separately. A failed/partial candidate must never destroy or silently replace the previous valid audit.

## Completion gate

The auditor may return `complete` only if:

- repository inventory completed;
- relevant files were scanned under documented exclusions;
- every detected relevant framework/client has a detector with `supported` status;
- all required detector executions succeeded;
- no unsupported integration surface remains;
- every discovered HTTP route/outbound call is represented;
- unresolved facts are explicit and do not represent missing coverage;
- all primary outputs are generated and mutually consistent;
- OpenAPI passes structural validation when applicable.

Any failed detector, unsupported relevant pattern, unknown coverage or incomplete inventory downgrades the audit to `partial` or `failed`.
