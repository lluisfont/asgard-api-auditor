# Architecture

## Purpose

`asgard-api-auditor` is a producer of verified API knowledge. It is intentionally separate from the central knowledge repository/RAG.

## Components

```text
repository snapshot
      |
      v
[discovery]
  exposed routes
  outbound HTTP calls
      |
      v
[analysis]
  normalize
  classify
  attach evidence
  detect unknowns
      |
      +------------------+
      |                  |
      v                  v
[openapi]           [knowledge]
openapi.yaml        api-knowledge.md
      |                  |
      +--------+---------+
               |
               v
          findings.json
          audit-report.md
```

## Source of truth

The source repository and audited commit are the primary evidence. Generated artifacts are derived knowledge and must always record the source commit.

## Separation of responsibilities

### Auditor repository

Contains:
- detection logic;
- parsers;
- normalization;
- OpenAPI generation;
- knowledge generation;
- comparison between audits;
- validation.

It must not contain copies of proprietary ASGARD repositories.

### API knowledge repository

Contains generated and approved knowledge from multiple repositories. It is optimized for retrieval, dependency analysis and RAG use.

## Detector architecture

Detectors should implement narrow responsibilities and produce normalized `EndpointFinding` objects. Examples:

- Laravel/PHP route detector;
- generic PHP cURL/Guzzle consumer detector;
- JavaScript Axios/Fetch detector;
- Flutter/Dart HTTP/Dio detector;
- environment/config URL detector;
- OpenAPI/Swagger existing-spec detector.

Each detector must state:

- supported patterns;
- unsupported patterns;
- confidence rules;
- evidence emitted.

## Cross-repository correlation

Provider-consumer correlation is not assumed from names alone. It should use, in descending strength:

1. exact base URL + normalized path;
2. service/domain configuration + path;
3. explicit SDK/client reference;
4. runtime/test evidence;
5. inferred relation marked as unverified.

## Future API gate

The same engine can later compare the OpenAPI reconstructed from a PR with the previous approved contract to detect breaking changes and identify affected consumers in `asgard-api-knowledge`.
