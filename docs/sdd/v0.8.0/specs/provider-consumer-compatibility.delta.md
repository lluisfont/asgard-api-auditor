# Delta Spec: Provider/Consumer Compatibility Gate

## Status

Specification draft only.

## Purpose

The provider/consumer compatibility gate verifies that consumed API requirements are satisfied by compatible provider contracts. It is generic and does not assume repository relationships unless provided as explicit inputs.

Provider/consumer compatibility is directional. It must not automatically reuse reference/candidate comparison rules.

## Inputs

The gate accepts:

- one or more `consumer` API catalogs;
- one or more `provider` API catalogs;
- optional existing correlation artifacts;
- gate mode;
- scope options.

Consumers and providers are execution roles, not repository types. The same repository may act as a provider, consumer, or both in different executions.

## Matching

For each consumed endpoint:

1. Use deterministic correlation to find provider candidates.
2. Match by HTTP method and normalized path shape.
3. Preserve ambiguity when multiple providers match.
4. Preserve unmatched requirements explicitly.
5. Do not use repository names, host substrings, business terms, or manual mappings.

## Dependency Classification

Each consumed endpoint receives exactly one status:

- `compatible`: a provider candidate is deterministically matched and contract compatibility is proven.
- `breaking`: a provider candidate exists but its contract is incompatible with the consumer requirement.
- `missing`: no provider candidate exists.
- `ambiguous`: multiple provider candidates exist and no deterministic evidence selects one.
- `unknown`: a candidate exists but compatibility cannot be proven.

## Directional Compatibility Rules

### Request

The provider must accept every request shape the consumer can produce within the demonstrated consumer contract.

Examples:

- Consumer sends `{id}` and provider accepts `{id, comment?}`: `compatible`.
- Consumer may send `{id, comment}` and provider accepts only `{id}` while proving additional fields invalid: `breaking`.
- Unknown provider acceptance or unknown consumer requiredness is `unknown` when material.

### Response

The provider must produce at least the data and responses the consumer demonstrates it needs.

Examples:

- Consumer requires `{id, status}` and provider produces `{id, status, description}`: `compatible` only when additional fields are demonstrated not to break the consumer or are immaterial.
- Consumer requires `{id, status}` and provider only proves `{id}`: `breaking`.
- Consumer tolerance for additional fields is not inferred. Unknown tolerance is `unknown` when material.

### Path and Query Parameters

- Provider path shape must match the consumed path shape deterministically.
- Provider must accept every path parameter value shape the consumer can produce.
- Provider-required query parameters not produced by the consumer are `breaking`.
- Consumer-produced query parameters rejected by the provider are `breaking`.
- Unknown parameter requiredness, type, format, or acceptance is `unknown` when material.

### Headers

- Provider-required headers not produced by the consumer are `breaking`.
- Consumer-produced headers rejected by the provider are `breaking`.
- Additional optional provider headers are compatible only when they create no consumer obligation.
- Unknown header requiredness or acceptance is `unknown` when material.

### Content Types

- Provider must accept every request content type the consumer can send.
- Provider must produce a response content type the consumer can parse when response parsing is demonstrated.
- Unknown content-type support is `unknown` when material.

### Status Codes

- Provider must preserve statuses the consumer demonstrates it handles or requires.
- Additional provider statuses are compatible only when the consumer is proven tolerant or the status is outside the demonstrated successful dependency path.
- A new reachable error status is `unknown` or `breaking` according to evidence; it is never automatically additive.

### Authentication and Security

- Provider auth requirements must be satisfiable by the consumer's demonstrated credentials, headers, or tokens.
- Stricter provider auth that the consumer cannot satisfy is `breaking`.
- Unknown auth compatibility is `unknown`.
- Provider auth weakening is reported as security drift and only fails compatibility when an explicit policy gate requires it.

### Types, Formats, and Requiredness

- Provider request types must accept consumer-produced values.
- Provider response types must satisfy consumer-required values.
- Type narrowing is `breaking` when it excludes demonstrated consumer values.
- Type widening is compatible only when it still includes all demonstrated required values.
- Unknown type, format, or requiredness compatibility is `unknown`.

## Gate Modes

- `report`: publish results without failing solely on `breaking`, `missing`, `ambiguous`, or `unknown`.
- `fail_on_breaking`: fail on `breaking` or `missing` required dependencies; report `ambiguous` and `unknown`.
- `fail_closed`: fail on `breaking`, `missing`, `ambiguous`, or `unknown` required dependencies.

Required consumer dependencies default to `fail_closed` in CI.

## Required Dependency Semantics

By default, every consumed endpoint included in the `consumer` catalogs and inside the selected scope is a required dependency.

Rules:

- `breaking` or `missing` on any scoped consumed endpoint affects `fail_on_breaking` and `fail_closed`.
- `ambiguous` or `unknown` on any scoped consumed endpoint affects `fail_closed`.
- Explicit scope/filter options may exclude consumed endpoints from the dependency gate.
- Excluded dependencies must be listed in output metadata/scope with the rule that excluded them.
- Required/optional dependency status must not be inferred from endpoint name, usage frequency, conditional code, repository identity, framework, business domain, feature naming, or implementation structure.

## Output Summary

The machine-readable output must include:

- consumer catalogs;
- provider catalogs;
- input hashes;
- total consumed dependencies;
- scoped required dependencies;
- excluded consumed dependencies;
- compatible;
- breaking;
- missing;
- ambiguous;
- unknown;
- security drift count;
- gate mode;
- gate verdict;
- endpoint-level evidence.

## Fail-Closed Rules

- Missing provider candidate cannot pass a required dependency gate.
- Ambiguous provider candidate cannot be treated as compatible.
- Unknown request, response, path/query, header, content type, status, auth/security, type/format, or requiredness compatibility cannot be treated as compatible in `fail_closed` mode.
- Consumer tolerance must not be inferred.
- Provider tolerance must not be inferred.
- A provider's extra endpoints do not fail the consumer gate.
- A consumer's consumed-only endpoints are never converted into provider paths.
- Non-HTTP surfaces remain out of this HTTP compatibility gate unless a future dedicated surface gate is specified.

## Relationship to Reference/Candidate Comparison

Reference/candidate comparison answers:

> Did the candidate preserve the selected reference contract?

Provider/consumer compatibility answers:

> Are the consumer's required API dependencies satisfied by the selected providers?

Both reuse catalog facts, but they are distinct workflows and must not share assumptions about repository lineage or compatibility direction.
