---
repository: {{ repository }}
source_ref: {{ source_ref }}
source_commit: {{ source_commit }}
audit_timestamp: {{ audit_timestamp }}
audit_status: {{ audit_status }}
---

# API Knowledge — {{ repository }}

## Resumen

- Repositorio: `{{ repository }}`
- Commit: `{{ source_commit }}`
- APIs expuestas: {{ exposed_api_count }}
- Endpoints expuestos: {{ exposed_endpoint_count }}
- APIs consumidas: {{ consumed_api_count }}
- Endpoints consumidos: {{ consumed_endpoint_count }}
- Elementos sin resolver: {{ unresolved_count }}

## APIs expuestas

{{ exposed_apis }}

## APIs consumidas

{{ consumed_apis }}

## Dependencias detectadas

{{ dependencies }}

## Elementos sin resolver

{{ unresolved }}

## Cobertura y limitaciones

{{ coverage_notes }}

## Trazabilidad

Toda afirmación técnica anterior debe incluir evidencia de código, configuración, tests o ejecución. Las relaciones inferidas deben marcarse explícitamente como `probable` o `unverified`.
