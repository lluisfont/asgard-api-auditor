# Delta Spec: `api-catalog.json`

## Status

Specification draft only.

## Purpose

`api-catalog.json` is the canonical machine-readable inventory of HTTP API contracts derived from source-proven audit facts. It is intended for cross-repository comparison, provider/consumer compatibility checks, and human documentation generation.

## Source Inputs

The catalog may be built from validated audit artifacts, primarily `findings.json`. The builder must reject invalid inputs and must not read repository source code directly.

## Top-Level Shape

```json
{
  "schema_version": "1.0",
  "catalog_id": "catalog_...",
  "audit_id": "audit_...",
  "auditor_version": "0.8.0",
  "generated_at": "2026-01-01T00:00:00Z",
  "repository": "...",
  "repository_id": "...",
  "source_ref": "...",
  "source_commit": "...",
  "source_artifacts": [],
  "scope": {},
  "summary": {},
  "endpoints": [],
  "unresolved": []
}
```

## Required Metadata

- `schema_version`: catalog schema version.
- `catalog_id`: unique catalog artifact identifier.
- `audit_id`: source audit execution identifier.
- `auditor_version`: auditor version that generated the catalog.
- `generated_at`: timestamp.
- `repository`: display repository value copied from input metadata.
- `repository_id`: normalized repository identifier copied from input metadata.
- `source_ref`: source ref copied from input metadata.
- `source_commit`: exact source commit copied from input metadata.
- `source_artifacts`: input artifacts with SHA-256 hashes.
- `scope`: command options affecting the catalog.

Metadata supports validation and reproducibility. Metadata fields must not be used as contractual endpoint identity inputs unless the field is explicitly part of the externally selected contract namespace. In particular, `schema_version` must not influence endpoint IDs.

## Endpoint Entry

Each endpoint entry must include:

- `api_id`: stable logical API identity when proven, otherwise `null`.
- `endpoint_id`: stable endpoint identity.
- `stable_identity`: structured identity inputs used to create `endpoint_id`.
- `direction`: `exposed` or `consumed`.
- `surface_type`: `http`.
- `method`: HTTP method.
- `normalized_path`: normalized HTTP path.
- `path_shape`: path with parameter names normalized for matching.
- `base_url`: only when proven for consumed APIs, otherwise `null`.
- `parameters`: path, query, header, and cookie parameters when demonstrable.
- `request`: request contract facts.
- `response`: response contract facts.
- `headers`: demonstrated headers not already modeled as parameters.
- `authentication`: demonstrated auth mechanism or `unknown`.
- `security`: structured security requirements when demonstrable.
- `behavior`: semantic facts when available.
- `contract_status`: `complete`, `partial`, `unresolved`, `not_applicable`, or `unknown`.
- `semantic_status`: `complete`, `partial`, `unresolved`, `not_applicable`, or `unknown`.
- `evidence`: source evidence.
- `unresolved`: endpoint-scoped unresolved items.

## Stable Identity Fields

Identity fields have distinct responsibilities:

- `stable_identity`: structured contractual identity inputs used for matching and ID derivation.
- `endpoint_id`: deterministic ID derived from `stable_identity`.
- `api_id`: optional stable grouping when independently proven by source evidence or explicit catalog configuration.

`stable_identity` may include:

- `direction`;
- `method`;
- `path_shape`;
- optional proven namespace;
- optional proven `api_id`.

`stable_identity` must not include:

- `endpoint_id`;
- catalog `schema_version`;
- source file path;
- source line;
- generated order;
- repository display name;
- framework name;
- business or customer name.

`api_id` must not be derived from `endpoint_id`. `endpoint_id` must not be used to derive `stable_identity`. This avoids circular identity and keeps endpoint IDs stable across catalog schema evolution.

## Parameter Facts

Parameter entries should include:

- `name`;
- `location`;
- `required`;
- `schema`;
- `source`;
- `evidence`.

`required` and `schema` may be `unknown` when evidence is insufficient.

## Request Contract

Request contract entries should include:

- `content_type`;
- `schema`;
- `fields`;
- `required_fields`;
- `optional_fields`;
- `unknown_requiredness_fields`;
- `evidence`;
- `unresolved`.

The catalog must not infer requiredness from naming, examples, comments, or consumer expectations unless the source artifact proves it.

## Response Contract

Response contract entries should include:

- `status_codes`;
- `content_type`;
- `schema`;
- `fields`;
- `functional_body_fields`;
- `evidence`;
- `unresolved`.

HTTP status codes and functional body fields remain separate.

## Summary

The summary must include:

- total endpoints;
- exposed endpoints;
- consumed endpoints;
- endpoints by method;
- endpoints by direction;
- contract status counts;
- semantic status counts;
- unresolved count.

## Fail-Closed Rules

- Invalid source artifact means no catalog publication.
- Endpoint without method/path/direction evidence is rejected or represented as unresolved according to schema rules.
- Unknown fields remain unknown.
- Unknown request, response, status, auth/security, header, type, requiredness, or behavior facts remain material unknowns for compatibility until later evidence resolves them.
- The catalog must not erase unresolved findings from the source audit.
- A complete catalog does not imply complete compatibility; compatibility is evaluated separately.
