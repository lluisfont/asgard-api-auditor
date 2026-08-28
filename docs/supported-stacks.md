# Supported stacks and coverage levels

This document describes the capabilities currently demonstrated by ASGARD API Auditor v0.8.0.

The auditor is repository-agnostic: it can be executed against any local Git repository. Coverage depth depends on the languages, frameworks, HTTP clients and integration patterns detected in that repository.

A detected but unsupported or unresolved integration surface is never silently ignored. It keeps the audit `partial` or otherwise explicitly unresolved. The auditor follows the rule `UNKNOWN > GUESS`.

## Coverage levels

- **Inventory**: the technology or integration surface can be detected during repository inventory.
- **Exposed discovery**: server-side HTTP routes can be discovered as exposed endpoints.
- **Consumed discovery**: outbound HTTP calls can be discovered as consumed endpoints.
- **Contract enrichment**: request, response or security contract facts can be reconstructed from source when supported patterns are demonstrated.
- **Semantic enrichment**: source-proven behavior facts can be reconstructed beyond the structural HTTP contract.
- **Separate integration surface**: the technology is tracked outside REST/OpenAPI rather than converted into an HTTP endpoint.

## Current support matrix

| Stack / pattern | Inventory | Exposed discovery | Consumed discovery | Contract enrichment | Semantic enrichment | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Slim PHP | Yes | Yes | — | Yes | Yes | Deepest current provider-side support. Literal routes and supported request/response/security patterns are reconstructed conservatively. |
| Laravel routes | Yes | Yes | — | Limited | Limited | Route discovery is supported for demonstrated literal route patterns. Unsupported/dynamic patterns remain unresolved. |
| Angular `HttpClient` | Yes | — | Yes | Limited to source-proven discovery facts | — | Consumer-side HTTP discovery. |
| Axios | Yes | — | Yes | Limited to source-proven discovery facts | — | Consumer-side HTTP discovery. |
| Fetch | Yes | — | Yes | Limited to source-proven discovery facts | — | Consumer-side HTTP discovery. |
| Guzzle | Yes | — | Yes | Limited to source-proven discovery facts | — | Consumer-side HTTP discovery. |
| Laravel HTTP facade | Yes | — | Yes | Limited to source-proven discovery facts | — | Consumer-side HTTP discovery. |
| PHP cURL | Yes | — | Yes | Limited to source-proven discovery facts | Partial where semantics are demonstrated | Supports direct calls and deterministic local wrappers. Dynamic resolution remains unresolved. |
| Dio | Yes | — | Yes | Limited to source-proven discovery facts | — | Consumer-side Dart/Flutter discovery with fail-closed receiver resolution. |
| Dart `http` | Yes | — | Yes | Limited to source-proven discovery facts | — | Consumer-side discovery for supported `Uri` patterns. |
| PHP `SoapClient` / SOAP | Yes | — | — | WSDL-backed where available | Partial | Tracked as a separate integration surface, never converted into REST/OpenAPI. Local versioned WSDL snapshots can be supplied explicitly. |

`—` means the capability is not currently the responsibility of that detector or is not demonstrated as a general capability.

## Important limitations

The matrix is intentionally conservative. It does **not** mean that every pattern used by a listed framework or client is supported.

Examples that can keep an audit incomplete include:

- dynamic route construction;
- ambiguous helper/wrapper propagation;
- unsupported HTTP clients;
- dynamic URLs or methods that cannot be resolved deterministically;
- non-HTTP integration surfaces without sufficient detector coverage;
- external SOAP contracts that are not available as reproducible versioned WSDL snapshots;
- request/response/security behavior that cannot be proven from source.

When such a case is detected, it is reported through coverage and `unresolved` facts rather than guessed.

## Meaning of a generic audit

ASGARD API Auditor is generic at the repository level, not omniscient at the framework level.

The correct interpretation is:

> The auditor can inspect any Git repository fail-closed. A `complete` result is only possible when the repository's relevant integration surfaces are covered by supported deterministic detectors and no material coverage gaps remain.

This distinction is part of the product contract.