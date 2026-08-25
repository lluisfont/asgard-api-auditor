# Technical inventory

## Purpose

The technical inventory is the first executable stage of the ASGARD API Auditor. Its job is to establish, before endpoint discovery, which technologies and integration surfaces are present in the exact Git revision being inspected.

It does **not** claim that an API audit is complete. It produces the evidence and detector plan required by later discovery stages.

## Command

```bash
asgard-api-auditor inventory /path/to/repository
```

Optional arguments:

- `--ref <ref>`: the requested ref must resolve to the checked-out `HEAD`.
- `--repository-id <id>`: stable logical repository identity when `origin` is absent or unsuitable.
- `--output <file>`: write JSON atomically instead of stdout.
- `--allow-dirty`: permit diagnostic inventory of a dirty working tree. The result is always incomplete and exits with code `3`.

## Git provenance rules

The inventory fails closed unless it can prove what source tree it is reading.

1. The supplied path must be the Git repository root.
2. The requested ref must resolve to the checked-out `HEAD` commit.
3. The working tree must be clean by default.
4. Repository identity is resolved in this order:
   - explicit `--repository-id`;
   - sanitized `origin` host/path;
   - directory name as a documented fallback.
5. Credentials embedded in an HTTPS remote are never included in `repository_id`.

A working tree contains files, not an arbitrary Git object. Therefore v0.3 refuses to attach working-tree evidence to a different commit even when that commit exists locally.

## Inventory scope v1.0

The scanner inventories:

- source languages by file extension;
- recognized framework dependencies and source signatures;
- recognized HTTP-client dependencies and source signatures;
- GraphQL, WebSocket, gRPC, SOAP, SSE and webhook signals;
- existing files named like OpenAPI or Swagger specifications;
- manifest files relevant to supported ecosystems;
- detector categories and concrete detector hints required by subsequent stages.

Dependency/build/generated directories are pruned before inspection, including `.git`, `node_modules`, `vendor`, virtual environments, build outputs and auditor output directories.

Documentation files are deliberately not searched for technology signatures. A README that mentions Axios or GraphQL is not evidence that the repository uses them.

## Confidence

- `confirmed`: direct manifest/dependency evidence or another deterministic source defined as authoritative by the inventory stage.
- `probable`: a recognized source-code/configuration signature that still requires a framework/client-specific detector to confirm behavior.
- `unverified`: reserved for signals retained without enough evidence for either level above.

The inventory never upgrades a probable code signature to confirmed merely because the same word appears repeatedly.

## `inventory_complete`

`inventory_complete=true` means the **defined inventory scope** executed without a known coverage gap. It does not mean the API audit is complete.

The inventory is marked incomplete when, among other cases:

- `--allow-dirty` is used on a dirty tree;
- a candidate file or manifest cannot be read/parsed;
- an oversize candidate text file is skipped;
- a symlink is encountered and therefore not traversed;
- Git submodules are declared, because v0.3 does not recurse into them.

These conditions are visible in the JSON output and cannot be silently ignored.

## Detector plan

The inventory produces `required_detector_categories` and `detector_hints`.

Examples:

```text
framework:laravel
exposed:laravel
consumed:axios
integration:graphql
existing_spec:openapi-or-swagger
```

Later versions use this plan to decide which endpoint and integration detectors must execute before an audit can be considered complete.

## Contract

The machine-readable result follows:

`schemas/technical-inventory.schema.json`

The contract is versioned independently through:

- `schema_version`: structure of the JSON document;
- `scope_version`: semantic definition of what the inventory claims to cover.

Changing either contract requires explicit tests and a changelog entry.
