# AGENTS.md

## Purpose

This repository builds the ASGARD API Auditor. Agents working here must preserve the distinction between evidence, inference and unknowns.

## Non-negotiable rules

- Never invent an endpoint, consumer, provider, schema, authentication method or dependency.
- Every finding must include source evidence when technically possible.
- Unknown facts must remain explicit (`unknown`, `unverified`, `not_detected`).
- Do not copy audited proprietary source code into generated knowledge artifacts.
- Never emit secrets, tokens, passwords, private keys or credentials.
- Do not treat existing documentation as authoritative when it conflicts with code evidence.
- Do not mark an audit complete while HTTP routes or outbound HTTP calls remain unclassified.
- Preserve AS-IS behavior in OpenAPI output before suggesting TO-BE improvements.

## Expected outputs

Each complete audit must generate:

1. `openapi.yaml`
2. `api-knowledge.md`
3. `findings.json`
4. `audit-report.md`

All outputs must identify the audited repository, branch/ref, source commit and audit timestamp.

## Development rules

- Python 3.11+.
- Prefer deterministic parsers and static analysis before LLM inference.
- Framework-specific detectors must declare what they support and what they do not support.
- New detectors require tests with positive and negative fixtures.
- Keep generated artifacts outside source directories.
- Avoid network access during tests.

## Audit philosophy

The goal is not to produce attractive API documentation. The goal is to reconstruct enough reliable integration knowledge to answer: **what can break if this API changes?**
