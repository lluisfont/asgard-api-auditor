# ASGARD API Auditor

Auditor técnico para reconstruir y mantener el conocimiento de integración de ASGARD a partir del código real de sus repositorios.

## Objetivo

Analizar exhaustivamente un repositorio ASGARD, identificar todos los endpoints HTTP que expone y consume, reconstruir sus contratos, detectar cambios entre auditorías y producir artefactos trazables listos para incorporar al repositorio central de conocimiento/RAG de APIs.

## Outputs obligatorios por auditoría

- `openapi.yaml`: contrato OpenAPI AS-IS de las APIs HTTP expuestas.
- `api-knowledge.md`: conocimiento semántico preparado para el RAG central.
- `findings.json`: resultado estructurado y procesable por máquinas.
- `audit-report.md`: informe humano con hallazgos, incertidumbres y anomalías.

## Principios

1. Código real como evidencia principal.
2. Cobertura exhaustiva de endpoints expuestos y consumidos.
3. No inventar: lo no demostrado se marca como `unknown` o `unverified`.
4. Trazabilidad por repositorio, commit y evidencia concreta.
5. Proveedor y consumidor tienen la misma importancia.
6. OpenAPI representa primero el contrato AS-IS.
7. El RAG central consolida dependencias para análisis de impacto.

## Estado

**v0.1 — scaffold inicial.** Define arquitectura, método, contratos de salida y una CLI mínima. Los detectores específicos por lenguaje/framework se incorporarán progresivamente y deberán declarar su cobertura.

## Arquitectura

```text
Repositorios ASGARD
        |
        v
asgard-api-auditor
        |
        +--> discovery: endpoints expuestos
        +--> discovery: endpoints consumidos
        +--> analysis: clasificación y dependencias
        +--> openapi: contrato AS-IS
        +--> knowledge: salida para RAG
        |
        v
output/
  openapi.yaml
  api-knowledge.md
  findings.json
  audit-report.md
        |
        v
asgard-api-knowledge
```

Ver [`docs/architecture.md`](docs/architecture.md) y [`docs/audit-method.md`](docs/audit-method.md).

## Requisitos

- Python 3.11+
- Git
- Acceso de solo lectura a los repositorios auditados

No deben copiarse repositorios ASGARD, credenciales, tokens ni datos sensibles dentro de este repositorio.

## Desarrollo local

```bash
python -m venv .venv
pip install -e .
asgard-api-auditor --help
python -m unittest discover -s tests -v
```

## Roadmap inmediato

1. Implementar inventario de archivos y fingerprint del commit auditado.
2. Añadir detectores de endpoints expuestos para stacks reales de ASGARD.
3. Añadir detectores de consumidores HTTP: cURL, Guzzle, Axios, Fetch, Flutter/Dart, SDKs y URLs configuradas.
4. Correlacionar productores y consumidores entre repositorios.
5. Generar `openapi.yaml` y `api-knowledge.md` de forma determinista.
6. Comparar auditorías sucesivas y detectar cambios.
7. Integrar la salida con `asgard-api-knowledge`.

## Licencia

Copyright © 2026. Todos los derechos reservados. No se concede licencia de uso, copia, modificación o redistribución salvo autorización expresa del titular.
