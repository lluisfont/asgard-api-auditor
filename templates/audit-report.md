---
document_type: asgard_api_audit_report
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

# API Audit Report — {{ repository }}

## Veredicto

{{ verdict }}

## Cobertura

{{ coverage }}

## APIs expuestas

{{ exposed_summary }}

## APIs consumidas

{{ consumed_summary }}

## Otras superficies de integración

{{ integration_surfaces }}

## Cambios desde la auditoría anterior

{{ changes }}

## Riesgos y breaking changes

{{ breaking_changes }}

## Elementos sin resolver

{{ unresolved }}

## Limitaciones

{{ limitations }}
