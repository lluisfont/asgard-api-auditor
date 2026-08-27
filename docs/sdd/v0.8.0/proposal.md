# v0.8.0 Proposal: Canonical API Contracts and Cross-Repository Compatibility

## Status

Proposal only. This document defines the intended product behavior for v0.8.0 and does not implement it.

## Problem

The auditor can already discover HTTP APIs, enrich exposed contracts where source evidence allows it, reconstruct deterministic semantics, and correlate provider/consumer artifacts. The next missing capability is a generic contract layer that can compare API compatibility across repository snapshots without depending on repository names, business domains, framework names, or manually maintained mappings.

The operational question for v0.8.0 is:

> Is this candidate API set compatible with the reference API set, and are the required consumer dependencies still satisfied?

## Goals

- Produce a canonical `api-catalog.json` artifact from source-proven audit facts.
- Represent exposed and consumed HTTP contracts in one generic, machine-readable catalog.
- Compare a `reference` catalog with a `candidate` catalog deterministically.
- Classify endpoint-level changes as `same`, `additive`, `breaking`, or `unknown`.
- Validate one or more `consumer` catalogs against one or more `provider` catalogs.
- Preserve strict `UNKNOWN > GUESS` behavior and fail closed when compatibility cannot be demonstrated.
- Keep existing discovery, enrichment, semantic reconstruction, and v0.6 correlation behavior compatible.
- Provide human-readable compatibility documentation suitable for review and API knowledge workflows.

## Non-Goals

- No implementation in this SDD phase.
- No repository-specific rules, path mappings, endpoint mappings, or customer-specific logic.
- No LLM as source of truth.
- No inference of fields, authentication, semantics, providers, or consumers without evidence.
- No changes to SOAP handling.
- No business API versioning model.
- No deployment or automatic synchronization between forks, clones, or variants.
- No generation of provider OpenAPI paths from consumed-only endpoints.

## Generic Use Cases

1. Compare a `reference` repository snapshot with a `candidate` variant.
2. Compare an older release with a newer release.
3. Compare `main` with a branch or pull request.
4. Validate forks or white-label products against a shared API contract.
5. Validate that a `consumer` remains compatible with a `provider`.
6. Compare multiple implementations that must preserve a common API contract.

## Proposed Artifacts

v0.8.0 adds the following generic artifacts:

- `api-catalog.json`: canonical API catalog derived from proven audit facts.
- `api-compatibility.json`: machine-readable comparison result for `reference` vs `candidate`.
- `api-compatibility.md`: human-readable comparison report.
- `consumer-compatibility.json`: machine-readable provider/consumer gate result.
- `consumer-compatibility.md`: human-readable provider/consumer compatibility report.

The existing artifacts remain valid:

- `findings.json` remains the detailed audit evidence artifact.
- `correlations.json` remains the deterministic relationship artifact.
- `openapi.yaml` remains provider-facing OpenAPI for exposed HTTP endpoints only.
- `api-knowledge.md` remains source-proven semantic documentation.

## Compatibility Principles

- `same` requires demonstrated compatibility, not absence of detected differences.
- `additive` requires demonstrated backward compatibility.
- `breaking` requires demonstrated incompatibility against the selected `reference`.
- `unknown` is required when evidence is insufficient to prove `same`, `additive`, or `breaking`.
- Material `unknown` facts remain `unknown` even when a catalog is compared with itself.
- Self-comparison may prove `observed_equal=true` or `artifact_equal=true`; that does not prove contract compatibility for material unknown fields.
- Gates fail on `unknown` in `fail_closed` mode and report `unknown` without failing in `report` and `fail_on_breaking` modes.
- Backward API compatibility and security policy/conformance drift are separate results unless a gate explicitly combines them.
- Additional response statuses are never additive by default; compatibility must be demonstrated.
- Provider/consumer compatibility uses directional obligations and must not blindly reuse reference/candidate comparison rules.

## Identity Principles

- `stable_identity` is the structured contractual identity input.
- `endpoint_id` is derived from `stable_identity`.
- `api_id` is an optional independently proven grouping and must not be required to derive `endpoint_id`.
- `endpoint_id` should be derived only from intrinsic stable contract identity: `direction`, `method`, `path_shape`, and an explicit stable namespace when one is supplied.
- Catalog schema version is reproducibility metadata and must not affect endpoint identity.
- No identity input may depend on file, line, generated order, framework name, repository display name, or business/customer naming.
- If an endpoint is first cataloged without `api_id` and later gains a proven `api_id`, its `endpoint_id` must remain stable unless the intrinsic method/path contract or explicit namespace changed.

## Gate Semantics

Reference/candidate comparison must support:

- `report`: generate classifications and return a non-failing verdict for reporting, while still surfacing `breaking` and `unknown`.
- `fail_on_breaking`: fail only when a reference requirement is classified as `breaking`.
- `fail_closed`: fail when a reference requirement is `breaking` or `unknown`.

Provider/consumer compatibility must support the same modes, with `fail_closed` as the recommended default for required consumer dependencies:

- `report`: generate dependency classifications without failing solely on `breaking`, `missing`, `ambiguous`, or `unknown`.
- `fail_on_breaking`: fail on `breaking` or `missing` required dependencies.
- `fail_closed`: fail on `breaking`, `missing`, `ambiguous`, or `unknown` required dependencies.

## Requirement Semantics

Reference/candidate requirements:

- By default, every endpoint included in the `reference` catalog and inside the selected scope is a compatibility requirement.
- `breaking` on any scoped reference endpoint affects `fail_on_breaking` and `fail_closed`.
- `unknown` on any scoped reference endpoint affects `fail_closed`.
- If an explicit scope/filter is supplied, only endpoints included by that scope participate as requirements.
- Excluded endpoints must be recorded in metadata/scope with the exclusion rule that removed them from the gate.
- The auditor must not infer required or optional APIs from name, usage frequency, conditional code, repository identity, framework, business domain, feature naming, or implementation structure.

Provider/consumer required dependencies:

- By default, every consumed endpoint included in the `consumer` catalogs and inside the selected scope is a required dependency.
- A consumed dependency can be excluded only by explicit scope/filter.
- Excluded dependencies must be recorded in metadata/scope with the exclusion rule that removed them from the gate.
- The auditor must not infer that a dependency is optional from name, usage frequency, conditional code, repository identity, framework, business domain, feature naming, or implementation structure.

## Real Validation Scope

Real repositories may be used only as validation fixtures. Their names and business concepts must not appear in product schemas, comparison rules, identity rules, or compatibility algorithms.

Required real validations:

- Reference catalog compared with itself: `artifact_equal`/`observed_equal` is true, no artificial changes are introduced, and material unknowns remain `unknown`.
- Reference catalog compared with a fixture that adds an API: additive.
- Reference catalog compared with fixtures that remove an endpoint, change a request incompatibly, change a response incompatibly, or change auth incompatibly: breaking.
- Consumer catalog checked against provider catalog: all consumed dependencies must resolve to compatible provider endpoints or fail closed.

## Success Criteria

- The SDD artifacts are reviewed and accepted before implementation starts.
- The implementation plan has explicit tasks for schemas, artifact generation, comparison, reports, gates, tests, and real validation.
- The design keeps generic product terminology: `reference`, `candidate`, `provider`, `consumer`, `api catalog`, `contract`, `compatibility`, `correlation`, and `breaking change`.
- The future implementation can be validated without hard-coded routes, repositories, framework assumptions, or manually supplied endpoint mappings.
