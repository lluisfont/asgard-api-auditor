# Audit Method

## Definition of a complete repository audit

A repository audit is complete only when all detectable HTTP integration surfaces have been classified or explicitly recorded as unresolved.

The auditor must investigate both directions:

1. **Exposed endpoints** — routes implemented by the repository.
2. **Consumed endpoints** — outbound HTTP/API calls made by the repository.

## Phase 1 — Identify the audited snapshot

Record:

- repository name;
- local/source location;
- branch or ref;
- exact commit SHA;
- audit timestamp;
- detected languages/frameworks.

## Phase 2 — Inventory relevant files

Search at minimum for:

- route definitions;
- controllers/handlers;
- middleware;
- API/service layers;
- HTTP clients;
- SDK wrappers;
- environment and configuration files;
- tests;
- existing OpenAPI/Swagger files;
- Postman collections when present;
- webhook handlers and emitters.

Generated dependencies/vendor directories should be excluded unless evidence requires them.

## Phase 3 — Discover exposed endpoints

For every route found, attempt to determine:

- HTTP method;
- normalized path;
- handler/controller;
- request parameters/body;
- response shape;
- authentication/authorization;
- status/error responses;
- evidence paths and lines;
- confidence.

Unresolved routes remain findings; they are not silently discarded.

## Phase 4 — Discover consumed endpoints

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
- raw socket/HTTP wrappers if present.

For every call found, capture:

- method;
- URL/base URL/path where resolvable;
- calling file/function;
- request fields;
- response fields actually read by the consumer;
- authentication mechanism when visible;
- evidence;
- probable provider, only when supported by evidence.

## Phase 5 — Normalize and classify

Normalize equivalent paths and methods while preserving original evidence.

Classify each finding as:

- `confirmed`;
- `probable`;
- `unverified`.

Unknown provider/consumer relationships must remain explicit.

## Phase 6 — Generate OpenAPI AS-IS

Generate OpenAPI only from sufficiently supported exposed endpoints.

Rules:

- do not invent missing schema details;
- mark incomplete descriptions visibly;
- retain evidence in vendor extensions when useful;
- represent actual current error behavior before proposing a standard error model;
- never include secrets or real credentials.

## Phase 7 — Generate RAG knowledge

Create `api-knowledge.md` containing:

- repository identity and commit;
- summary counts;
- exposed APIs/endpoints;
- consumed APIs/endpoints;
- provider/consumer relationships;
- fields consumed where detectable;
- evidence;
- unresolved findings;
- impact notes supported by evidence.

## Phase 8 — Generate findings and report

`findings.json` is machine-readable. `audit-report.md` is for human review.

The report must explicitly state coverage limitations and unresolved items.

## Phase 9 — Compare with previous audit

When previous artifacts exist, identify:

- new endpoints;
- removed endpoints;
- changed methods/paths;
- request/response contract changes;
- changed consumers/providers;
- changed authentication;
- probable breaking changes.

Do not overwrite evidence of a breaking change without reporting it.

## Completion gate

The auditor may return `complete` only if:

- every discovered exposed route is classified;
- every discovered outbound HTTP call is classified;
- unresolved items are represented explicitly;
- all four required output files were generated;
- output identifies the exact source commit;
- OpenAPI passes structural validation when produced.
