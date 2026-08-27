# v0.8.0 Tasks: Canonical API Contracts and Compatibility

## Status

Task plan only. Do not implement until the SDD proposal and design are approved.

## 1. Schema and Contract Specs

- Add `api-catalog.schema.json` for `api-catalog.json`.
- Add `api-compatibility.schema.json` for `api-compatibility.json`.
- Add `consumer-compatibility.schema.json` if provider/consumer gate output is separate.
- Package all new schemas with the installed Python package.
- Extend contract validation so new artifacts are validated fail-closed from packaged resources.
- Add schema-level tests for required metadata, endpoint entries, stable identity, compatibility entries, evidence, unresolved items, security drift, gate mode, and summary counts.

## 2. Catalog Builder

- Build a catalog from existing `findings.json` data.
- Preserve exposed and consumed directions without converting consumed calls into provider operations.
- Preserve existing `endpoint_id` only when compatible with the v0.8 stable identity rules.
- Add canonical identity generation independent of file, line, generated order, repository display name, framework name, business name, and catalog schema version.
- Define `stable_identity`, derive `endpoint_id` from it, and keep `api_id` as an optional independently proven grouping.
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
- Define reference/candidate default as `report`.
- Define provider/consumer required-dependency default as `fail_closed`.
- Ensure all commands accept generic `reference`, `candidate`, `provider`, and `consumer` terminology.

## 4. Reference/Candidate Comparison Engine

- Match reference and candidate endpoints by stable identity and normalized method/path shape.
- Classify each endpoint as `same`, `additive`, `breaking`, or `unknown`.
- Add separate `artifact_equal` and `observed_equal` fields that do not imply compatibility.
- Preserve material unknowns as `unknown`, including self-comparison.
- Detect breaking endpoint removal, method changes, incompatible path changes, path parameter changes, required request additions, request removals, incompatible request types, response removals, incompatible response types, stricter incompatible auth/security, and incompatible required headers.
- Report weaker auth/security separately as security policy/conformance drift unless a security policy gate explicitly treats it as failure.
- Detect additive new endpoints and optional contract additions only when backward compatibility is demonstrated.
- Treat additional response statuses as `unknown` unless compatibility is demonstrated, or `breaking` when evidence proves incompatibility.
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
  - unknown;
  - artifact equal;
  - observed equal;
  - security drift.
- Include endpoint-level details, evidence, contract field diffs, security drift, and gate verdict.
- Ensure Markdown does not make stronger claims than JSON.

## 6. Provider/Consumer Compatibility

- Reuse deterministic correlation guarantees from v0.6.
- Accept one or more consumer catalogs and one or more provider catalogs.
- For each consumed endpoint, find compatible provider candidates without manual mappings.
- Classify dependencies as `compatible`, `breaking`, `missing`, `ambiguous`, or `unknown`.
- Apply directional request rules: provider must accept every demonstrated request shape the consumer can produce.
- Apply directional response rules: provider must produce at least the demonstrated response data the consumer needs.
- Apply directional path/query, header, content type, status code, auth/security, type/format, and requiredness rules.
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
- Document that exact observation equality is distinct from compatibility.
- Document that security policy/conformance drift is distinct from backward API compatibility unless a policy gate combines them.

## 8. Required Unit Tests

- Catalog generated from exposed endpoints.
- Catalog generated from consumed endpoints.
- Catalog preserves source evidence and unresolved items.
- Stable endpoint identity is independent of file, line, output order, and catalog schema version.
- `api_id`, `endpoint_id`, and `stable_identity` do not depend circularly on each other.
- Complete self-comparison produces `same` for complete material facts and no `breaking`.
- Self-comparison with material unknown response/auth facts preserves `unknown` while setting `observed_equal=true`.
- Byte-identical catalogs can set `artifact_equal=true` without converting material unknowns to `same`.
- Added endpoint is `additive`.
- Removed endpoint is `breaking`.
- Required request field added is `breaking`.
- Optional request field added is `additive` only when optionality is proven.
- Request field removed is `breaking` when required by reference.
- Request type incompatibility is `breaking`.
- Response field removed is `breaking`.
- Optional response field added is `additive` only when compatibility is proven.
- Response type incompatibility is `breaking`.
- Additional response status is `unknown` without compatibility evidence.
- Additional reachable error status is `breaking` when evidence proves it can affect previously valid calls.
- Stricter incompatible auth/security is `breaking`.
- Weaker auth/security is reported as security drift, not automatically as `breaking`.
- Unknown requiredness or unknown type yields `unknown`.
- Unknown is never promoted to `same`.
- Gate `report` emits findings without failing on `breaking` or `unknown`.
- Reference/candidate gate `fail_on_breaking` fails on `breaking` and reports `unknown`.
- Reference/candidate gate `fail_closed` fails on `breaking` or `unknown`.
- Provider/consumer gate `fail_on_breaking` fails on `breaking` or `missing` required dependencies.
- Provider/consumer gate `fail_closed` fails on `breaking`, `missing`, `ambiguous`, or `unknown` required dependencies.

## 9. Required Provider/Consumer Directional Tests

- Consumer sends `{id}` and provider accepts `{id, comment?}`: `compatible`.
- Consumer may send `{id, comment}` and provider proves only `{id}` is accepted with extra fields invalid: `breaking`.
- Provider acceptance of consumer-produced field is unknown and material: `unknown`.
- Consumer requires response `{id, status}` and provider produces `{id, status, description}` with demonstrated tolerance: `compatible`.
- Consumer requires response `{id, status}` and provider only proves `{id}`: `breaking`.
- Provider response addition has material unknown consumer tolerance: `unknown`.
- Provider-required query parameter not produced by consumer: `breaking`.
- Consumer-produced query parameter rejected by provider: `breaking`.
- Unknown path/query parameter requiredness or type: `unknown`.
- Provider-required header not produced by consumer: `breaking`.
- Consumer-produced header rejected by provider: `breaking`.
- Unknown header acceptance: `unknown`.
- Provider does not accept consumer content type: `breaking`.
- Unknown content-type compatibility: `unknown`.
- Provider does not produce a status the consumer requires or handles as success: `breaking`.
- Additional provider status without proven consumer tolerance: `unknown`.
- Provider auth cannot be satisfied by consumer-produced credentials: `breaking`.
- Unknown auth compatibility: `unknown`.
- Provider request type narrowing excludes demonstrated consumer value: `breaking`.
- Unknown type/format compatibility: `unknown`.

## 10. Required Integration and E2E Tests

- Reference real fixture compared with itself:
  - baseline endpoint count equals candidate endpoint count;
  - no artificial changes are introduced;
  - `artifact_equal` or `observed_equal` is true according to input handling;
  - material unknowns remain `unknown`;
  - zero `breaking`.
- Reference fixture with complete material facts compared with itself:
  - all comparable APIs are `same`;
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
- Reference fixture with stricter incompatible auth/security:
  - compatibility classification is `breaking`.
- Reference fixture with weaker auth/security:
  - compatibility classification is not automatically `breaking`;
  - security drift is reported.
- Real consumer/provider validation:
  - all consumed endpoints are evaluated;
  - no hard-coded endpoint list;
  - every missing, ambiguous, incompatible, or unknown dependency is explicit.

## 11. Regression Gates

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

## 12. Implementation Constraints

- Do not modify real validation repositories.
- Do not add repository-specific logic.
- Do not add framework-specific comparison logic to the catalog/comparison/gate layers.
- Do not infer missing contracts.
- Do not change SOAP behavior.
- Do not generate OpenAPI provider paths from consumed-only APIs.
- Do not use LLM output as authoritative compatibility evidence.
