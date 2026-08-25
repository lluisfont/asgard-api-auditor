# AGENTS.md

## Purpose

This repository builds the ASGARD API Auditor. Agents working here must preserve the distinction between evidence, inference, absence, unsupported coverage and unknowns.

## Non-negotiable rules

- Never invent an endpoint, consumer, provider, schema, authentication method or dependency.
- Every technical finding must include source evidence when technically possible.
- Unknown facts must remain explicit (`unknown`, `unverified`, `not_detected`, `unsupported`).
- `not_detected` never means `confirmed_absent`.
- Do not copy audited proprietary source code into generated knowledge artifacts.
- Never emit secrets, tokens, passwords, private keys, credentials or credential-bearing connection strings.
- Do not treat existing documentation as authoritative when it conflicts with code/runtime evidence.
- Do not mark an audit `complete` while coverage is partial, unknown, failed or unsupported.
- Do not mark an audit `complete` merely because every discovered finding is classified.
- Preserve AS-IS behavior in OpenAPI output before suggesting TO-BE improvements.
- OpenAPI output must use version `3.1.2` unless an explicit repository decision changes this standard.
- Non-HTTP integration surfaces must be recorded even when OpenAPI cannot represent them.
- A failed or partial candidate audit must never overwrite the last valid published audit.

## Required primary outputs

Each publishable audit generates:

1. `openapi.yaml`
2. `api-knowledge.md`
3. `findings.json`
4. `audit-report.md`

All four outputs must identify:

- `schema_version`
- `audit_id`
- `auditor_version`
- audited repository
- source ref
- exact source commit
- audit timestamp

## Development rules

- Python 3.11+.
- Prefer deterministic parsers and static analysis before LLM inference.
- Framework/client detectors must declare supported patterns, unsupported patterns, detector version and confidence rules.
- New detectors require positive, negative and edge-case fixtures.
- Every detector execution contributes to the coverage model.
- A detector failure must downgrade audit status; it must not be swallowed.
- Keep generated artifacts outside source directories.
- Avoid network access during unit tests.
- Changes to schemas, coverage rules or completion logic require tests.

## Audit philosophy

The goal is not to produce attractive API documentation. The goal is to reconstruct reliable integration knowledge that can safely support impact analysis before changing ASGARD APIs.
