# v0.8.0 Tasks: Canonical API Contracts and Compatibility

## Status

Task plan only. Do not implement until the SDD proposal and design are approved.

## 1. Schema and Contract Specs

- Add `api-catalog.schema.json` for `api-catalog.json`.
- Add `api-compatibility.schema.json` for `api-compatibility.json`.
- Add `consumer-compatibility.schema.json` if provider/consumer gate output is separate.
- Package all new schemas with the installed Python package.
- Extend contract validation so new artifacts are validated fail-closed from packaged resources.
- Add schema-level tests for required metadata, endpoint entries, compatibility entries, evidence, unresolved items, and summary counts.

## 2. Catalog Builder

- Build a catalog from existing `findings.json` data.
- Preserve exposed and consumed directions without converting consumed calls into provider operations.
- Preserve existing `endpoint_id` when compatible with the stable identity rules.
- Add canonical identity generation independent of file and line.
- Preserve all available request, response, headers, auth/security, behavior, evidence, unresolved, contract status, and semantic status.
- Record input artifact hashes and source metadata.
- Emit `api-catalog.json` atomically and validate before publication.

## 3. CLI Surface

- Add a catalog generation command, pending final naming decision.
- Add conceptual comparison command:

```bash
asgard-api-auditor compare-api reference-api-catalog.json candidate-api-catalog.json \
  --output api-compatibility-output
```

- Add provider/consumer compatibility command or mode, pending final naming decision.
- Support explicit gate mode flags: `report`, `fail_on_breaking`, and `fail_closed`.
- Ensure all commands accept generic `reference`, `candidate`, `provider`, and `consumer` terminology.

## 4. Reference/Candidate Comparison Engine

- Match reference and candidate endpoints by stable identity and normalized method/path shape.
- Classify each endpoint as `same`, `additive`, `breaking`, or `unknown`.
- Detect breaking endpoint removal, method changes, incompatible path changes, path parameter changes, required request additions, request removals, incompatible request types, response removals, incompatible response types, auth/security incompatibilities, and incompatible required headers.
- Detect additive new endpoints and optional contract additions.
- Emit `unknown` whenever evidence is insufficient to prove compatibility.
- Attach evidence and field-level reasons to every non-`same` classification.
- Keep comparison deterministic and order-stable across repeated runs.

## 5. Compatibility Reports

- Emit `api-compatibility.json`.
- Emit `api-compatibility.md`.
- Include summary counts:
  - reference endpoints;
  - candidate endpoints;
  - same;
  - additive;
  - breaking;
  - unknown.
- Include endpoint-level details, evidence, contract field diffs, and gate verdict.
- Ensure Markdown does not make stronger claims than JSON.

## 6. Provider/Consumer Compatibility

- Reuse deterministic correlation guarantees from v0.6.
- Accept one or more consumer catalogs and one or more provider catalogs.
- For each consumed endpoint, find compatible provider candidates without manual mappings.
- Classify dependencies as `compatible`, `breaking`, `missing`, `ambiguous`, or `unknown`.
- Fail closed when a required consumer dependency is missing, ambiguous, breaking, or unknown in `fail_closed` mode.
- Emit machine-readable and Markdown reports.
- Preserve candidate provider matches without overstating them as confirmed runtime dependencies.

## 7. Documentation

- Update architecture documentation after implementation.
- Update output contract documentation after schemas are finalized.
- Document generic workflows:
  - reference vs candidate;
  - release vs release;
  - main vs branch;
  - provider vs consumer;
  - multiple providers/consumers.
- Document all gate modes and failure meanings.

## 8. Required Unit Tests

- Catalog generated from exposed endpoints.
- Catalog generated from consumed endpoints.
- Catalog preserves source evidence and unresolved items.
- Stable endpoint identity is independent of file, line, and output order.
- Self comparison produces `same` for all comparable APIs and no `breaking`.
- Added endpoint is `additive`.
- Removed endpoint is `breaking`.
- Required request field added is `breaking`.
- Optional request field added is `additive`.
- Request field removed is `breaking` when required by reference.
- Request type incompatibility is `breaking`.
- Response field removed is `breaking`.
- Optional response field added is `additive`.
- Response type incompatibility is `breaking`.
- Auth/security incompatibility is `breaking`.
- Unknown requiredness or unknown type yields `unknown`.
- Unknown is never promoted to `same`.
- Gate `report` emits findings without failing.
- Gate `fail_on_breaking` fails only on breaking required APIs.
- Gate `fail_closed` fails on breaking, missing, ambiguous, or unknown required APIs.

## 9. Required Integration and E2E Tests

- Reference real fixture compared with itself:
  - baseline endpoint count equals candidate endpoint count;
  - zero `breaking`;
  - zero `unknown`.
- Reference fixture with additional API:
  - additional API is `additive`;
  - gate does not fail when additive changes are allowed.
- Reference fixture with removed endpoint:
  - removed API is `breaking`.
- Reference fixture with incompatible request:
  - request change is `breaking`.
- Reference fixture with incompatible response:
  - response change is `breaking`.
- Reference fixture with incompatible auth/security:
  - security change is `breaking`.
- Real consumer/provider validation:
  - all consumed endpoints are evaluated;
  - no hard-coded endpoint list;
  - every missing, ambiguous, incompatible, or unknown dependency is explicit.

## 10. Regression Gates

- Full unit test suite.
- Ruff.
- Compileall.
- Existing contract validation.
- New catalog and compatibility schema validation.
- Existing discovery baselines unchanged.
- Existing correlation v0.6 tests unchanged.
- Existing semantic reconstruction v0.7 tests unchanged.
- Real provider/reference validation.
- Real consumer/provider validation.
- CI success on final PR head.

## 11. Implementation Constraints

- Do not modify real validation repositories.
- Do not add repository-specific logic.
- Do not add framework-specific comparison logic to the catalog/comparison/gate layers.
- Do not infer missing contracts.
- Do not change SOAP behavior.
- Do not generate OpenAPI provider paths from consumed-only APIs.
- Do not use LLM output as authoritative compatibility evidence.
