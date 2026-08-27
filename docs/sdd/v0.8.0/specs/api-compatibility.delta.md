# Delta Spec: `api-compatibility.json` and `api-compatibility.md`

## Status

Specification draft only.

## Purpose

The compatibility artifacts compare a `reference` API catalog with a `candidate` API catalog and explain whether the candidate preserves the reference contract. They also expose observed equality separately from compatibility so unknown facts remain honest.

## Conceptual Command

```bash
asgard-api-auditor compare-api reference-api-catalog.json candidate-api-catalog.json \
  --output api-compatibility-output
```

## JSON Top-Level Shape

```json
{
  "schema_version": "1.0",
  "comparison_id": "comparison_...",
  "auditor_version": "0.8.0",
  "generated_at": "2026-01-01T00:00:00Z",
  "reference": {},
  "candidate": {},
  "gate": {},
  "summary": {},
  "endpoint_results": [],
  "security_drift": [],
  "unresolved": []
}
```

## Inputs

Each input record must include:

- role: `reference` or `candidate`;
- `catalog_id`;
- `repository_id`;
- `source_ref`;
- `source_commit`;
- `auditor_version`;
- `schema_version`;
- SHA-256 hash.

Input `schema_version` is reproducibility metadata only. It must not participate in endpoint identity comparison.

## Classifications

Endpoint compatibility classifications:

- `same`;
- `additive`;
- `breaking`;
- `unknown`.

Endpoint observation fields:

- `artifact_equal`: true when the relevant canonicalized artifacts are identical according to command-defined metadata handling.
- `observed_equal`: true when the compared endpoint observations present on both sides are equal.

`artifact_equal` and `observed_equal` are not compatibility classifications. They must not convert material unknown fields into `same`.

`artifact_equal` canonicalization:

- parse both catalog JSON inputs;
- apply command-defined volatile metadata handling, recorded in the output;
- sort object keys recursively;
- sort order-insensitive arrays only when allowed by schema semantics;
- preserve endpoint arrays in canonical `endpoint_id` order;
- compare the canonical byte representation.

This canonicalization is a snapshot equality check only. It must not influence endpoint compatibility classification.

Compatibility is field-level first, then endpoint-level:

- any field-level `breaking` makes the endpoint `breaking`;
- if no `breaking` exists but one or more material field comparisons are `unknown`, the endpoint is `unknown`;
- if all reference requirements are compatible and candidate adds demonstrably backward-compatible fields or endpoints, classify as `additive`;
- classify as `same` only when all material compatibility facts are demonstrated compatible and no additive or breaking field exists.

Self-comparison rules:

- Complete material facts compared with themselves may classify as `same`.
- Identical unknown request, response, status, header, type, requiredness, auth/security, or behavior facts remain `unknown` when material.
- Self-comparison may set `artifact_equal=true` or `observed_equal=true`; neither value implies contract compatibility.

## Breaking Rules

The comparison must classify as `breaking` when source-proven evidence shows:

- reference endpoint missing from candidate;
- HTTP method changed;
- path changed incompatibly;
- path parameter removed or changed incompatibly;
- required query/header parameter added;
- required request field added;
- required request field removed;
- request type changed incompatibly;
- request media type changed incompatibly;
- response field removed;
- response type changed incompatibly;
- response media type changed incompatibly;
- stricter or otherwise incompatible auth/security for backward API compatibility;
- required header changed incompatibly;
- additional reachable response status breaks previously valid reference behavior.

## Additive Rules

The comparison may classify as `additive` when source-proven evidence shows:

- candidate endpoint not present in reference;
- optional request field added and optionality is proven;
- optional response field added and compatibility is proven;
- optional query/header parameter added and no consumer obligation is created;
- additional response status or media type is demonstrably compatible;
- additional semantic evidence does not contradict reference behavior.

Additional response status is never additive by default. A new `401`, `409`, `500`, or other observable status is `unknown` unless compatibility is proven, or `breaking` when evidence proves it can affect previously valid reference calls.

## Unknown Rules

The comparison must classify as `unknown` when:

- compatibility depends on request/response/security facts that are unknown on either side;
- endpoint identity or path shape cannot be matched deterministically;
- requiredness cannot be proven;
- type compatibility cannot be proven;
- field-level evidence is partial and material to the result;
- correlation is required but ambiguous or not evaluable;
- an additional response status is observed but compatibility is not demonstrated;
- self-comparison observes identical material unknowns.

`unknown` must never be promoted to `same`.

## Security Drift

Backward API compatibility and security policy/conformance drift are separate.

Rules:

- Stricter auth/security that existing clients cannot satisfy is a compatibility `breaking` change.
- Weaker auth/security is not automatically a backward client compatibility break.
- Weaker auth/security must be reported as `security_drift` with evidence.
- A security policy gate may fail on `security_drift`, but that decision must be explicit in the gate configuration.

## Gate Semantics

Reference/candidate comparison supports:

- `report`: publish classifications and return a non-failing report verdict even when `breaking` or `unknown` exists.
- `fail_on_breaking`: fail when any required reference API is `breaking`; `unknown` is reported but does not fail.
- `fail_closed`: fail when any required reference API is `breaking` or `unknown`.

Security drift does not fail these gates unless the gate explicitly enables security policy enforcement.

## Required API Semantics

By default, every endpoint included in the `reference` catalog and inside the selected scope is a required API for compatibility evaluation.

Rules:

- `breaking` on any scoped reference endpoint affects `fail_on_breaking` and `fail_closed`.
- `unknown` on any scoped reference endpoint affects `fail_closed`.
- Explicit scope/filter options may exclude reference endpoints from the gate.
- Excluded endpoints must be listed in output metadata/scope with the rule that excluded them.
- Required/optional API status must not be inferred from endpoint name, usage frequency, conditional code, repository identity, framework, business domain, feature naming, or implementation structure.

## Summary Counts

The summary must include:

- reference endpoints;
- candidate endpoints;
- scoped reference requirements;
- excluded reference endpoints;
- same;
- additive;
- breaking;
- unknown;
- artifact equal endpoints;
- observed equal endpoints;
- removed endpoints;
- added endpoints;
- changed endpoints;
- security drift count;
- unresolved count;
- gate result.

## Markdown Report

`api-compatibility.md` must include:

- input catalogs and hashes;
- gate mode and verdict;
- summary counts;
- breaking changes with field-level reason and evidence;
- unknown compatibility items with reason and evidence;
- additive changes;
- security drift;
- artifact/observed equality notes;
- same endpoint count;
- reproducibility metadata.

The Markdown report must not introduce stronger claims than JSON.

## Publication Rules

The JSON and Markdown report are generated in staging, validated together, and published atomically. A failed validation must not publish partial comparison artifacts.
