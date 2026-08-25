# Output Contracts

## Shared metadata

All four primary outputs must carry or visibly state:

- `schema_version`;
- `audit_id`;
- `auditor_version`;
- `repository`;
- `source_ref`;
- `source_commit`;
- `audit_timestamp`.

## `findings.json`

Canonical structured result for automation and cross-repository correlation.

It contains:

- coverage;
- HTTP endpoints exposed and consumed;
- request/response contract details;
- response fields actually consumed;
- authentication;
- evidence;
- other integration surfaces;
- unresolved items;
- comparison/breaking-change data when available;
- hashes/status of sibling artifacts.

Schema: [`../schemas/findings.schema.json`](../schemas/findings.schema.json).

## `openapi.yaml`

OpenAPI 3.1.2 representation of sufficiently verified exposed HTTP APIs.

Required traceability extensions should use the `x-asgard-` prefix, for example:

```yaml
x-asgard-audit-id: audit-...
x-asgard-source-commit: abc123...
x-asgard-endpoint-id: api::GET::/path
```

OpenAPI does not represent the complete repository integration inventory; consumed APIs and unsupported/non-HTTP surfaces remain in findings/knowledge.

## `api-knowledge.md`

RAG-oriented semantic representation. It must not introduce claims absent from `findings.json` or other cited evidence.

Every endpoint section must include its stable endpoint ID and evidence summary.

## `audit-report.md`

Human-facing audit result including:

- verdict/status;
- source snapshot;
- coverage;
- detector limitations/failures;
- summary counts;
- breaking changes since previous audit;
- unresolved items;
- security-sensitive findings by reference without exposing secrets.

## Cross-output consistency

A candidate audit set is invalid if repository, commit, audit ID or auditor version differ across outputs.
