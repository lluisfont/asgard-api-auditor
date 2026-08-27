# v0.8.0 Design: Canonical API Contracts and Cross-Repository Compatibility

## Status

Design only. This file describes the intended architecture for v0.8.0 before implementation.

## Architecture

```text
repository snapshot(s)
        |
        v
DISCOVERY
  source-proven exposed/consumed HTTP endpoints
  detector coverage and unresolved patterns
        |
        v
CONTRACT RECONSTRUCTION
  request/response/security/behavior facts
  enrichment coverage and semantic status
        |
        v
CANONICAL CATALOG
  api-catalog.json
  normalized provider/consumer API contracts
        |
        +-----------------------------+
        |                             |
        v                             v
REFERENCE/CANDIDATE COMPARISON    PROVIDER/CONSUMER CORRELATION
  api-compatibility.json/md        deterministic candidate matching
        |                             |
        +-------------+---------------+
                      v
             COMPATIBILITY ANALYSIS
               same/additive/breaking/unknown
                      |
                      v
              COMPATIBILITY GATE
                pass/fail by explicit mode
```

Each layer consumes normalized facts from the previous layer. The catalog, comparison, and gate layers must be detector-agnostic: they do not inspect framework source code directly and do not contain rules for specific repositories, products, or business domains.

## Layer Responsibilities

### DISCOVERY

Discovery remains responsible for finding exposed and consumed HTTP endpoints, integration surfaces, evidence, detector coverage, and unresolved patterns. Discovery decides whether a path, method, direction, receiver, route, or call is proven enough to emit.

v0.8.0 must not weaken discovery fail-closed behavior. A catalog cannot turn a discovery `unresolved` into a compatible contract.

### CONTRACT RECONSTRUCTION

Contract reconstruction remains responsible for request, response, headers, authentication/security, and behavior facts derived from source evidence. It may enrich only the facts it can prove.

Contract reconstruction owns:

- path parameters;
- query parameters when demonstrable;
- request fields, types, requiredness, and media type when demonstrable;
- response fields, types, status codes, and media type when demonstrable;
- headers when demonstrable;
- authentication/security when demonstrable;
- source-proven behavior and semantics.

### CANONICAL CATALOG

The catalog layer converts versioned audit findings into a stable API contract inventory. It is a normalization and packaging layer, not a scanner.

`api-catalog.json` must include exposed and consumed HTTP endpoints. Consumed endpoints remain consumer requirements; they do not become provider paths or OpenAPI operations.

Minimum endpoint fields:

- `api_id`;
- `endpoint_id`;
- `stable_identity`;
- `direction`;
- `method`;
- `normalized_path`;
- `path_parameters`;
- `query_parameters`;
- `request`;
- `response`;
- `headers`;
- `authentication`;
- `security`;
- `behavior`;
- `contract_status`;
- `semantic_status`;
- `evidence`;
- `unresolved`.

Absent information must be represented as `unknown`, `not_applicable`, empty arrays, or `null` according to schema semantics. The catalog must never fabricate values to improve compatibility.

### PROVIDER/CONSUMER CORRELATION

The existing v0.6 correlation model remains valid. v0.8.0 may consume catalog entries instead of raw findings only after preserving the current matching guarantees:

- exact HTTP method;
- normalized path shape;
- no fuzzy matching;
- no host substring matching;
- no repository-name heuristics;
- no manual mandatory mappings.

Correlation can produce candidate provider relationships. Compatibility analysis decides whether a matched provider contract satisfies the consumer contract.

### COMPATIBILITY ANALYSIS

Compatibility compares a `reference` catalog against a `candidate` catalog. The `reference` does not imply inheritance, ownership, or repository type; it is simply the contract selected as the baseline for that execution.

Endpoint classification:

- `same`: candidate proves the same externally relevant contract as reference.
- `additive`: candidate adds behavior that is demonstrably backward-compatible.
- `breaking`: candidate removes or changes behavior in a way that can break clients of the reference.
- `unknown`: evidence is insufficient to prove one of the previous states.

`same` is a compatibility claim, not a byte-for-byte equality claim. Identical unknown observations remain `unknown` when the unknown field is material to compatibility. To support snapshot drift checks without weakening `UNKNOWN > GUESS`, comparison results may carry separate booleans:

- `artifact_equal`: the compared catalog artifacts are byte-identical after canonical serialization and metadata handling defined by the comparison command.
- `observed_equal`: the endpoint observations that are present in both catalogs are equal.

Neither property implies `same` for compatibility when material request, response, status, header, type, requiredness, auth/security, or behavior facts remain unknown.

`artifact_equal` canonicalization:

- parse both catalog JSON documents;
- remove or separately compare volatile generation metadata selected by the command, such as `generated_at` and catalog execution IDs;
- sort object keys recursively;
- sort arrays only where the schema defines order-insensitive collections;
- preserve endpoint arrays in canonical `endpoint_id` order;
- compare the canonical byte representation and record the metadata handling used.

This canonicalization is for snapshot equality only. It must not affect endpoint compatibility classification.

Breaking conditions include:

- endpoint removed;
- HTTP method changed;
- incompatible path changed;
- path parameter removed, renamed incompatibly, or changed in type/format;
- required query/header parameter added;
- required request field added;
- request field removed when required by the reference;
- request type/media type changed incompatibly;
- response field removed;
- response type/media type changed incompatibly;
- authentication/security made stricter or changed incompatibly for backward API compatibility;
- incompatible required headers;
- demonstrated semantic behavior made incompatible with the reference contract.

Additive conditions include:

- new endpoint;
- optional request field added;
- optional response field added;
- optional header/query parameter added;
- additional response status or media type only when compatibility is demonstrated;
- stronger semantic detail added without contradicting the reference.

`unknown` conditions include:

- reference lacks enough evidence to define a compatibility boundary;
- candidate lacks enough evidence to prove compatibility;
- both sides are partial in a field that materially affects compatibility;
- correlation is ambiguous and the gate requires a provider match;
- schema types are unknown where compatibility depends on type;
- an additional response status such as `401`, `409`, or `500` is observed but its compatibility with existing consumers is not demonstrated.

### COMPATIBILITY GATE

The gate evaluates comparison results according to explicit execution mode.

Reference/candidate modes:

- `report`: emit all classifications and a report verdict; do not fail only because `breaking` or `unknown` exists.
- `fail_on_breaking`: fail when a required reference API is `breaking`; report `unknown` without failing.
- `fail_closed`: fail when a required reference API is `breaking` or `unknown`.

Provider/consumer modes use the same names but dependency-oriented statuses:

- `report`: emit all dependency classifications without failing solely on `breaking`, `missing`, `ambiguous`, or `unknown`.
- `fail_on_breaking`: fail on `breaking` or `missing` required dependencies; report `ambiguous` and `unknown` without failing.
- `fail_closed`: fail on `breaking`, `missing`, `ambiguous`, or `unknown` required dependencies.

Reference/candidate comparison defaults to `report` unless a gate mode is supplied. Provider/consumer compatibility defaults to `fail_closed` for required dependencies.

### Required API and Dependency Scope

Reference/candidate requirements:

- By default, every endpoint included in the `reference` catalog and inside the selected scope is a required API for compatibility evaluation.
- `breaking` on any scoped reference endpoint affects `fail_on_breaking` and `fail_closed`.
- `unknown` on any scoped reference endpoint affects `fail_closed`.
- When an explicit scope/filter is supplied, only endpoints included by that scope participate as required APIs.
- Endpoints excluded by scope/filter must be recorded in metadata/scope with the rule that excluded them.
- Required/optional API status must not be inferred from endpoint name, usage frequency, conditional code, repository identity, framework, business domain, feature naming, or implementation structure.

Provider/consumer required dependencies:

- By default, every consumed endpoint included in the `consumer` catalogs and inside the selected scope is a required dependency.
- A consumed endpoint can be removed from the dependency gate only by explicit scope/filter.
- Excluded dependencies must be recorded in metadata/scope with the rule that excluded them.
- Required/optional dependency status must not be inferred from endpoint name, usage frequency, conditional code, repository identity, framework, business domain, feature naming, or implementation structure.

## Stable Identity

Endpoint identity must be stable across line movement, formatting changes, and schema evolution.

Recommended identity inputs:

- direction;
- method;
- normalized path shape;
- contract namespace only when explicitly supplied by the caller or artifact metadata.

Catalog schema version is metadata for reproducibility and validation. It must not be an endpoint identity input, because schema evolution must not change endpoint IDs when the API contract did not change.

Identity terms:

- `stable_identity`: structured, serializable contractual identity inputs such as direction, method, normalized path shape, and optional proven namespace.
- `endpoint_id`: deterministic digest or identifier derived from `stable_identity`.
- `api_id`: optional higher-level API grouping when source evidence or explicit catalog configuration proves a stable grouping.

`api_id` is grouping metadata, not an endpoint identity input. `endpoint_id` must remain stable if the same endpoint is first cataloged with `api_id=null` and later gains a proven `api_id`, unless method, path shape, direction, or explicit namespace changed. `endpoint_id` must never be an input to `api_id` or `stable_identity`.

Identity must not include:

- source file path;
- source line;
- generated order;
- repository display name;
- framework name;
- business name;
- catalog schema version.
- `api_id`.

Source evidence remains attached separately so reviewers can trace the identity back to code.

## Contract Comparison Semantics

Comparison is field-aware and conservative.

### Reference/Candidate Direction

Reference/candidate comparison asks whether the `candidate` preserves the externally relevant contract selected as `reference`. It does not assume repository inheritance, runtime dependency, or product lineage.

Request compatibility:

- Adding an optional request field is additive.
- Adding a required request field is breaking.
- Removing a required reference request field is breaking unless the field is no longer required by the external contract and that is proven.
- Unknown requiredness yields `unknown`, not `same`.
- Type narrowing is breaking unless proven compatible.
- Type widening may be additive only when source evidence proves the candidate still accepts reference values.

Response compatibility:

- Removing a response field present in the reference is breaking when consumers may depend on it.
- Adding an optional response field is additive.
- Changing a field type is breaking unless compatibility can be proven.
- Adding a response status is not automatically additive; it is additive only when the status is demonstrably compatible with the reference contract.
- A newly observable error status may be `breaking` if evidence shows existing valid requests can now receive it incompatibly, otherwise it is `unknown`.
- Unknown candidate response structure yields `unknown` for response compatibility.

Security compatibility:

- Adding stricter auth to an unauthenticated or differently authenticated reference endpoint is breaking.
- Unknown auth on either side yields `unknown` when auth matters to the gate.
- Removing or weakening auth is not automatically a backward client compatibility break, because existing clients may still call successfully. It must be reported separately as security policy/conformance drift.
- A security policy gate may classify weakening auth as a failure, but the API compatibility classifier must not silently merge that policy result into `breaking` unless the selected gate explicitly requires it.

Behavior compatibility:

- Source-proven behavior can strengthen the report and explain impact.
- Behavior unknown cannot be used to prove `same`.
- Functional body fields remain distinct from HTTP status.
- Consumed JWT context remains distinct from produced JWT context.

Self-comparison:

- Complete material facts compared with the same facts may classify as `same`.
- Material unknown facts compared with the same unknown facts classify as `unknown` for compatibility and may set `observed_equal=true`.
- Byte-identical catalogs may set `artifact_equal=true`, but this is not a compatibility verdict.

### Provider/Consumer Direction

Provider/consumer compatibility asks whether each `provider` can satisfy what each `consumer` is proven to require. It must not automatically reuse reference/candidate comparison rules because the direction of obligation differs.

Request rules:

- The provider must accept every request shape the consumer can produce within the demonstrated consumer contract.
- If the consumer sends `{id}` and the provider accepts `{id, comment?}`, the dependency is `compatible`.
- If the consumer may send `{id, comment}` and the provider accepts only `{id}` and proves additional fields invalid, the dependency is `breaking`.
- If provider tolerance for consumer-produced fields is material and unknown, the dependency is `unknown`.
- If consumer requiredness is unknown and material to provider acceptance, the dependency is `unknown`.

Response rules:

- The provider must produce at least the response data and statuses the consumer demonstrates it needs.
- If the consumer requires `{id, status}` and the provider produces `{id, status, description}`, the dependency is `compatible` only when additional fields are demonstrated not to break the consumer or are immaterial under the consumer contract.
- If the consumer requires `{id, status}` and the provider only proves `{id}`, the dependency is `breaking`.
- If tolerance for provider response additions is material and cannot be demonstrated, the dependency is `unknown`.

Path and query parameter rules:

- Provider path shape must match the consumed path shape deterministically.
- Provider must accept every path parameter shape the consumer can produce.
- Provider-required query parameters not produced by the consumer are `breaking`.
- Consumer-produced query parameters rejected by the provider are `breaking`.
- Unknown parameter requiredness, type, format, or acceptance is `unknown` when material.

Header rules:

- Provider-required headers not produced by the consumer are `breaking`.
- Consumer-produced headers rejected by the provider are `breaking`.
- Additional optional provider headers are compatible only when no consumer obligation is created.
- Unknown header requiredness or acceptance is `unknown` when material.

Content type rules:

- Provider must accept the content types the consumer can send.
- Provider response content type must be one the consumer can parse when response parsing is demonstrated.
- Unknown content-type support is `unknown` when material.

Status code rules:

- Provider must preserve statuses the consumer demonstrates it handles or requires.
- Additional provider statuses are compatible only when the consumer is proven tolerant or the status is outside the demonstrated successful dependency path.
- A new reachable error status is `unknown` or `breaking` according to evidence; it is never automatically additive.

Auth/security rules:

- Provider auth requirements must be satisfiable by the consumer's demonstrated produced credentials, headers, or tokens.
- Stricter provider auth that the consumer cannot satisfy is `breaking`.
- Unknown auth compatibility is `unknown`.
- Provider auth weakening is reported as security drift and only fails compatibility when an explicit policy gate requires it.

Type and format rules:

- Provider request types must accept the consumer-produced values.
- Provider response types must satisfy the consumer-required values.
- Type narrowing is `breaking` when it excludes demonstrated consumer values.
- Type widening is compatible only when it still includes all demonstrated required values.
- Unknown type/format compatibility is `unknown`.

## Provider/Consumer Compatibility

Inputs:

- one or more `consumer` catalogs;
- one or more `provider` catalogs;
- optional correlation artifacts;
- explicit gate mode.

For each consumed endpoint:

1. Build the normalized method/path requirement.
2. Locate compatible provider candidates by deterministic correlation.
3. Compare the consumer requirement against the provider contract using provider/consumer directional rules.
4. Classify as `compatible`, `breaking`, `missing`, `ambiguous`, or `unknown`.
5. Attach evidence from both sides.

A provider may expose extra endpoints without failing the gate. Extra provider APIs are additive relative to consumer requirements.

## Traceability

Every catalog and comparison artifact must record:

- `schema_version`;
- `repository_id`;
- `source_ref`;
- `source_commit`;
- `auditor_version`;
- `audit_id`;
- `catalog_id` or `comparison_id`;
- `generated_at`;
- hashes of input artifacts;
- command options affecting scope.

The comparison must be reproducible from the recorded inputs and hashes.

## Validation Plan

Required deterministic validations:

- Reference catalog with three scoped endpoints and one `breaking` endpoint fails `fail_on_breaking`.
- Reference catalog with three scoped endpoints and one `unknown` endpoint passes `fail_on_breaking` while reporting `unknown`.
- Reference catalog with three scoped endpoints and one `unknown` endpoint fails `fail_closed`.
- Explicit reference scope excluding a `breaking` endpoint removes that endpoint from gate participation and records the exclusion in metadata/scope.
- Consumer catalog with three scoped consumed endpoints and one `missing` dependency fails `fail_on_breaking`.
- Explicit consumer scope excluding a dependency removes it from gate participation and records the exclusion in metadata/scope.
- Same endpoint without `api_id` and later with a proven `api_id` keeps the same `endpoint_id`.
- Complete reference catalog compared with itself yields `same` for complete material facts and no `breaking`.
- Reference catalog with material unknowns compared with itself yields `observed_equal=true` and preserves endpoint-level `unknown` compatibility for those material unknowns.
- Candidate with one new endpoint classifies that endpoint as `additive`.
- Candidate with a removed endpoint classifies the reference endpoint as `breaking`.
- Candidate with an incompatible request change classifies the endpoint as `breaking`.
- Candidate with an incompatible response change classifies the endpoint as `breaking`.
- Candidate with stricter incompatible security classifies the endpoint as `breaking`.
- Candidate with weaker security is reported as security drift and only fails a security policy gate.
- Additional response status is `additive` only when compatibility is demonstrated; otherwise it is `unknown` or `breaking` according to evidence.
- Consumer/provider validation checks all consumed dependencies against providers without hard-coded endpoint lists.

Real validation repositories are allowed only as fixtures. Product code must remain generic.

## Open Questions

- Whether `api-catalog.json` should be emitted by `audit` by default or by an explicit `catalog-api` command.
- Whether comparison should accept `findings.json` as a convenience input and internally build temporary catalogs.
- Whether consumer compatibility should be a mode of `compare-api` or a separate command.
