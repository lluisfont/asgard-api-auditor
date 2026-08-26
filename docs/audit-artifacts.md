# v0.5 audit artifacts

`asgard-api-auditor audit` converts proven repository discovery evidence into the four primary audit artifacts:

- `openapi.yaml`
- `api-knowledge.md`
- `findings.json`
- `audit-report.md`

## Command

```bash
asgard-api-auditor audit /path/to/repository \
  --repository-id logical-repository-id \
  --exclude-path audit \
  --exclude-path work_sample \
  --output api-audit-output
```

SOAP snapshots accepted by `discover` are also accepted by `audit`:

```bash
--soap-wsdl servicioovp=contracts/soap/ovp.wsdl
```

## Semantics

### OpenAPI

The OpenAPI document contains only HTTP endpoints proven as `exposed` by discovery.

Consumed calls are not emitted as provider paths. SOAP operations are not converted to REST paths.

v0.5.2 enriches Slim/PHP route contracts only when source reconstruction can prove the data. Request bodies, response schemas, authentication and authorization are not invented. Generated operations include ASGARD traceability extensions, canonical path mapping and conservative defaults where details remain unknown.

Supported Slim/PHP enrichment patterns in v0.5.2:

- route path parameters from literal Slim templates, with source parameter names preserved through canonical OpenAPI paths;
- JSON request bodies decoded from `$request->getBody()` into a local variable and read through literal keys;
- optional JSON request fields using `??` with literal defaults;
- JSON responses encoded from inline `array(...)` payloads or local variables assigned to deterministic arrays;
- `Content-Type: application/json` set through `withHeader(...)`;
- route middleware via `->add($verifyToken)` and JWT bearer validation using `Authorization` plus `JWT::decode(... new Key(..., 'HS256'))`.

Dynamic request keys, dynamic response payloads, unsupported body parsing, status-code inference from JSON fields, scopes/roles/issuer/audience and global security assumptions remain unresolved or unknown.

### API Knowledge

The Markdown knowledge artifact includes:

- exposed HTTP endpoints;
- consumed HTTP calls;
- non-HTTP integration operations;
- source evidence;
- discovery unresolved findings;
- explicit contract-enrichment limitations.

### Findings

`findings.json` maps discovery evidence into the versioned findings contract, includes `coverage.contract_enrichment` counters and adds a blocking `contract-enrichment-v0.5.2-coverage-gate` unresolved item until all completion gates are explicitly satisfied.

Therefore v0.5.2 audit status is `partial` even when `discovery_complete=true`.

### Audit report

The report gives the audit verdict, proven surface counts and the remaining blockers before the output can be treated as a complete behavioral API contract.

## Publication safety

Artifacts are generated in a staging directory, validated together, checked for obvious secret leakage and published atomically. A failed candidate must not replace a previously valid audit set.

## Current completion boundary

`discovery_complete=true` means supported API surfaces were discovered without known coverage gaps.

It does **not** mean the full API audit is complete.

Full audit completion additionally requires reconstruction and validation of request, response and security contracts, followed later by cross-repository provider/consumer correlation and breaking-change analysis.
