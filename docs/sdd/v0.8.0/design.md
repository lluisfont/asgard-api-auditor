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
                pass/fail/unknown by mode
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
- authentication/security made stricter, removed when required, or changed incompatibly;
- incompatible required headers;
- demonstrated semantic behavior made incompatible with the reference contract.

Additive conditions include:

- new endpoint;
- optional request field added;
- optional response field added;
- optional header/query parameter added;
- additional response status documented without removing compatible existing responses;
- stronger semantic detail added without contradicting the reference.

`unknown` conditions include:

- reference lacks enough evidence to define a compatibility boundary;
- candidate lacks enough evidence to prove compatibility;
- both sides are partial in a field that materially affects compatibility;
- correlation is ambiguous and the gate requires a provider match;
- schema types are unknown where compatibility depends on type.

### COMPATIBILITY GATE

The gate evaluates comparison results according to execution mode.

Recommended modes:

- `report`: emit all classifications; do not fail only because `unknown` exists.
- `fail_on_breaking`: fail when any required API is `breaking`.
- `fail_closed`: fail on `breaking`, `missing`, `ambiguous`, or `unknown` for required APIs.

Provider/consumer gates should default to fail-closed for required consumer dependencies. Reference/candidate reports may default to report mode unless explicitly used as a CI gate.

## Stable Identity

Endpoint identity must be stable across line movement and formatting changes.

Recommended identity inputs:

- catalog schema version;
- direction;
- method;
- normalized path shape;
- optional stable `api_id` only when proven;
- contract namespace only when explicitly supplied by the caller or artifact metadata.

Identity must not include:

- source file path;
- source line;
- generated order;
- repository display name;
- framework name;
- business name.

Source evidence remains attached separately so reviewers can trace the identity back to code.

## Contract Comparison Semantics

Comparison is field-aware and conservative.

Request compatibility:

- Adding an optional request field is additive.
- Adding a required request field is breaking.
- Removing a required reference request field is breaking unless the field is no longer required by the external contract and that is proven.
- Unknown requiredness yields `unknown`, not `same`.
- Type narrowing is breaking unless proven compatible.
- Type widening may be additive only when source evidence proves the provider still accepts reference values.

Response compatibility:

- Removing a response field present in the reference is breaking when consumers may depend on it.
- Adding an optional response field is additive.
- Changing a field type is breaking unless compatibility can be proven.
- Unknown candidate response structure yields `unknown` for response compatibility.

Security compatibility:

- Removing required auth where the reference required it is breaking unless the execution explicitly treats weakening auth as non-breaking for consumers.
- Adding stricter auth to an unauthenticated or differently authenticated reference endpoint is breaking.
- Unknown auth on either side yields `unknown` when auth matters to the gate.

Behavior compatibility:

- Source-proven behavior can strengthen the report and explain impact.
- Behavior unknown cannot be used to prove `same`.
- Functional body fields remain distinct from HTTP status.
- Consumed JWT context remains distinct from produced JWT context.

## Provider/Consumer Compatibility

Inputs:

- one or more `consumer` catalogs;
- one or more `provider` catalogs;
- optional correlation artifacts;
- explicit gate mode.

For each consumed endpoint:

1. Build the normalized method/path requirement.
2. Locate compatible provider candidates by deterministic correlation.
3. Compare the consumer requirement against the provider contract.
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

- Reference catalog compared with itself yields no `breaking` and no `unknown` compatibility changes.
- Candidate with one new endpoint classifies that endpoint as `additive`.
- Candidate with a removed endpoint classifies the reference endpoint as `breaking`.
- Candidate with an incompatible request change classifies the endpoint as `breaking`.
- Candidate with an incompatible response change classifies the endpoint as `breaking`.
- Candidate with incompatible security classifies the endpoint as `breaking`.
- Consumer/provider validation checks all consumed dependencies against providers without hard-coded endpoint lists.

Real validation repositories are allowed only as fixtures. Product code must remain generic.

## Open Questions

- Whether `api-catalog.json` should be emitted by `audit` by default or by an explicit `catalog-api` command.
- Whether comparison should accept `findings.json` as a convenience input and internally build temporary catalogs.
- Whether consumer compatibility should be a mode of `compare-api` or a separate command.
- How strict default CI behavior should be for `unknown` in reference/candidate comparison when no gate mode is supplied.
