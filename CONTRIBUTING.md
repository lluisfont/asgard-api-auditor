# Contributing

## Workflow

1. Create a short-lived branch from `main`.
2. Make the smallest coherent change.
3. Add or update tests.
4. Run local quality gates.
5. Open a pull request.
6. Merge only after required checks pass.

## Required local checks

```bash
ruff check .
python -m compileall -q src scripts
python -m unittest discover -s tests -v
python scripts/validate_contracts.py
```

For changes affecting OpenAPI generation, also validate a generated fixture with:

```bash
npx -y @redocly/cli@2.47.0 lint <openapi-file>
```

## Detector changes

Every detector must document:

- supported patterns;
- unsupported patterns;
- confidence rules;
- evidence emitted;
- coverage status behavior.

Every detector requires positive, negative and edge-case fixtures.

## Contract changes

Changes to `schemas/findings.schema.json`, completion rules, IDs or output metadata are compatibility-sensitive and require explicit tests and changelog entry.
