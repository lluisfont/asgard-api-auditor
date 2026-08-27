# Delta Spec: Provider/Consumer Compatibility Gate

## Status

Specification draft only.

## Purpose

The provider/consumer compatibility gate verifies that consumed API requirements are satisfied by compatible provider contracts. It is generic and does not assume repository relationships unless provided as explicit inputs.

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

## Gate Modes

- `report`: publish results without failing solely on `breaking`, `missing`, `ambiguous`, or `unknown`.
- `fail_on_breaking`: fail on `breaking` or `missing`.
- `fail_closed`: fail on `breaking`, `missing`, `ambiguous`, or `unknown`.

Required consumer dependencies should use `fail_closed` in CI.

## Output Summary

The machine-readable output must include:

- consumer catalogs;
- provider catalogs;
- input hashes;
- total consumed dependencies;
- compatible;
- breaking;
- missing;
- ambiguous;
- unknown;
- gate mode;
- gate verdict;
- endpoint-level evidence.

## Fail-Closed Rules

- Missing provider candidate cannot pass a required dependency gate.
- Ambiguous provider candidate cannot be treated as compatible.
- Unknown request/response/security compatibility cannot be treated as compatible in `fail_closed` mode.
- A provider's extra endpoints do not fail the consumer gate.
- A consumer's consumed-only endpoints are never converted into provider paths.
- Non-HTTP surfaces remain out of this HTTP compatibility gate unless a future dedicated surface gate is specified.

## Relationship to Reference/Candidate Comparison

Reference/candidate comparison answers:

> Did the candidate preserve the selected reference contract?

Provider/consumer compatibility answers:

> Are the consumer's required API dependencies satisfied by the selected providers?

Both reuse catalog facts, but they are distinct workflows and must not share assumptions about repository lineage.
