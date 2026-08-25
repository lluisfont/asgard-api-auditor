---
document_type: asgard_api_knowledge
schema_version: "1.0"
audit_id: {{ audit_id }}
auditor_version: {{ auditor_version }}
repository: {{ repository }}
repository_id: {{ repository_id }}
source_ref: {{ source_ref }}
source_commit: {{ source_commit }}
audit_timestamp: {{ audit_timestamp }}
audit_status: {{ audit_status }}
---

# API Knowledge — {{ repository }}

## Resumen

- Repositorio: `{{ repository }}`
- Commit: `{{ source_commit }}`
- Estado de auditoría: `{{ audit_status }}`
- APIs expuestas: {{ exposed_api_count }}
- Endpoints expuestos: {{ exposed_endpoint_count }}
- APIs consumidas: {{ consumed_api_count }}
- Endpoints consumidos: {{ consumed_endpoint_count }}
- Otras superficies de integración: {{ integration_surface_count }}
- Elementos sin resolver: {{ unresolved_count }}

## Cobertura

{{ coverage_summary }}

## APIs expuestas

Cada endpoint debe mostrar su `endpoint_id`, contrato observado, autenticación, evidencia y nivel de confianza.

{{ exposed_apis }}

## APIs consumidas

Cada endpoint debe mostrar su `endpoint_id`, proveedor cuando esté verificado, request observado y especialmente `response_fields_used` cuando pueda determinarse.

{{ consumed_apis }}

## Otras superficies de integración

{{ integration_surfaces }}

## Dependencias detectadas

{{ dependencies }}

## Cambios desde la auditoría anterior

{{ changes }}

## Elementos sin resolver

{{ unresolved }}

## Cobertura y limitaciones

{{ coverage_notes }}

## Trazabilidad

Toda afirmación técnica anterior debe provenir de `findings.json` o incluir evidencia equivalente de código, configuración, tests o ejecución. Las relaciones inferidas deben marcarse explícitamente como `probable` o `unverified`.
