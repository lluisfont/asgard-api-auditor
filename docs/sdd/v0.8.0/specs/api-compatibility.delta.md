# Delta Spec: `api-compatibility.json` and `api-compatibility.md`

## Status

Specification draft only.

## Purpose

The compatibility artifacts compare a `reference` API catalog with a `candidate` API catalog and explain whether the candidate preserves the reference contract.

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

## Classifications

Endpoint classifications:

- `same`;
- `additive`;
- `breaking`;
- `unknown`.

Compatibility is field-level first, then endpoint-level:

- any field-level `breaking` makes the endpoint `breaking`;
- if no `breaking` exists but one or more required field comparisons are `unknown`, the endpoint is `unknown`;
- if all reference requirements are compatible and candidate adds demonstrably optional fields or endpoints, classify as `additive`;
- otherwise classify as `same`.

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
- auth/security changed incompatibly;
- required header changed incompatibly.

## Additive Rules

The comparison may classify as `additive` when source-proven evidence shows:

- candidate endpoint not present in reference;
- optional request field added;
- optional response field added;
- optional query/header parameter added;
- additional compatible response status or media type;
- additional semantic evidence that does not contradict reference behavior.

## Unknown Rules

The comparison must classify as `unknown` when:

- compatibility depends on request/response/security facts that are unknown on either side;
- endpoint identity or path shape cannot be matched deterministically;
- requiredness cannot be proven;
- type compatibility cannot be proven;
- field-level evidence is partial and material to the result;
- correlation is required but ambiguous or not evaluable.

`unknown` must never be promoted to `same`.

## Summary Counts

The summary must include:

- reference endpoints;
- candidate endpoints;
- same;
- additive;
- breaking;
- unknown;
- removed endpoints;
- added endpoints;
- changed endpoints;
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
- same endpoint count;
- reproducibility metadata.

The Markdown report must not introduce stronger claims than JSON.

## Publication Rules

The JSON and Markdown report are generated in staging, validated together, and published atomically. A failed validation must not publish partial comparison artifacts.
