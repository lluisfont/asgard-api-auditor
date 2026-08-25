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

v0.5.0 is deliberately structural: request bodies, response schemas, authentication and authorization are not invented when source reconstruction has not yet proved them. Generated operations include ASGARD traceability extensions and a conservative default response description.

### API Knowledge

The Markdown knowledge artifact includes:

- exposed HTTP endpoints;
- consumed HTTP calls;
- non-HTTP integration operations;
- source evidence;
- discovery unresolved findings;
- explicit contract-enrichment limitations.

### Findings

`findings.json` maps discovery evidence into the versioned findings contract and adds a blocking `contract-enrichment-v0.5.0` unresolved item until request/response/security reconstruction is implemented.

Therefore v0.5.0 audit status is `partial` even when `discovery_complete=true`.

### Audit report

The report gives the audit verdict, proven surface counts and the remaining blockers before the output can be treated as a complete behavioral API contract.

## Publication safety

Artifacts are generated in a staging directory, validated together, checked for obvious secret leakage and published atomically. A failed candidate must not replace a previously valid audit set.

## Current completion boundary

`discovery_complete=true` means supported API surfaces were discovered without known coverage gaps.

It does **not** mean the full API audit is complete.

Full audit completion additionally requires reconstruction and validation of request, response and security contracts, followed later by cross-repository provider/consumer correlation and breaking-change analysis.
