# ASGARD API Auditor

Auditor técnico para reconstruir y mantener el conocimiento de integración de ASGARD a partir del código real de sus repositorios.

## Objetivo

Analizar un repositorio ASGARD, identificar las APIs que expone y consume, reconstruir contratos AS-IS, detectar dependencias y producir conocimiento trazable para el RAG central de APIs.

La pregunta operativa es:

> ¿Qué puede romperse si esta API cambia?

## Outputs primarios de una auditoría

Una auditoría publicable debe producir:

- `openapi.yaml`: contrato OpenAPI **3.1.2** AS-IS.
- `api-knowledge.md`: conocimiento preparado para el RAG central.
- `findings.json`: resultado estructurado y versionado.
- `audit-report.md`: informe humano de cobertura, cambios, riesgos e incertidumbres.

Los cuatro artefactos deben corresponder al mismo repositorio, commit y `audit_id`.

## Principios

1. Código real como evidencia principal.
2. Proveedor y consumidor tienen la misma importancia.
3. Cobertura antes que confianza: no se declara `complete` por ausencia de hallazgos.
4. Lo no demostrado permanece explícitamente desconocido o no verificado.
5. Trazabilidad a commit y evidencia concreta.
6. OpenAPI representa primero el contrato AS-IS.
7. GraphQL, WebSocket, gRPC, SOAP, SSE, webhooks y otras superficies no se ignoran.
8. Una ejecución fallida nunca reemplaza una auditoría válida anterior.

## Estado

**v0.3 — inventario técnico determinista.**

La v0.3 incorpora la primera fase ejecutable: antes de buscar endpoints, inspecciona el repositorio y determina con evidencia qué lenguajes, frameworks, clientes HTTP, especificaciones existentes y superficies de integración están presentes.

La auditoría completa de endpoints sigue deliberadamente bloqueada hasta disponer de detectores con cobertura probada.

## Inventario técnico

Ejecutar sobre la raíz de un repositorio Git limpio:

```bash
asgard-api-auditor inventory /ruta/al/repositorio
```

Guardar el resultado:

```bash
asgard-api-auditor inventory /ruta/al/repositorio --output technical-inventory.json
```

Si es necesario fijar una identidad lógica estable:

```bash
asgard-api-auditor inventory /ruta/al/repositorio --repository-id github.com/organizacion/repositorio
```

El `--ref` debe resolver exactamente al `HEAD` que se está leyendo. Un árbol con cambios locales se rechaza por defecto. Para un diagnóstico explícito puede usarse `--allow-dirty`; el resultado quedará marcado como incompleto.

El resultado cumple [`schemas/technical-inventory.schema.json`](schemas/technical-inventory.schema.json). `inventory_complete` significa que el alcance de inventario soportado se ejecutó sin huecos técnicos conocidos; **no significa que la auditoría API esté completa**.

Más detalle: [`docs/technical-inventory.md`](docs/technical-inventory.md).

## Arquitectura

```text
Repositorios ASGARD
        |
        v
asgard-api-auditor
        |
        +--> inventory       archivos, lenguajes, frameworks y superficies
        +--> discovery       endpoints expuestos y consumidos
        +--> analysis        normalización, evidencia y dependencias
        +--> coverage        cobertura real y límites del auditor
        +--> openapi         contrato AS-IS OpenAPI 3.1.2
        +--> knowledge       salida preparada para RAG
        +--> comparison      diferencias entre auditorías
        +--> publication     publicación atómica
        |
        v
openapi.yaml
api-knowledge.md
findings.json
audit-report.md
        |
        v
asgard-api-knowledge / RAG
```

## Documentación

- [`docs/architecture.md`](docs/architecture.md)
- [`docs/audit-method.md`](docs/audit-method.md)
- [`docs/coverage-model.md`](docs/coverage-model.md)
- [`docs/output-contracts.md`](docs/output-contracts.md)
- [`docs/technical-inventory.md`](docs/technical-inventory.md)
- [`docs/testing.md`](docs/testing.md)

## Requisitos

- Python 3.11+
- Git
- Node.js 20.19+ o 22.12+ para validar OpenAPI con Redocly CLI 2.x
- Acceso de solo lectura a los repositorios auditados

## Desarrollo local

```bash
python -m venv .venv
pip install -e .
pip install -r requirements-dev.lock
ruff check .
python -m compileall -q src scripts
python -m unittest discover -s tests -v
python scripts/validate_contracts.py
```

Validación OpenAPI:

```bash
npx -y @redocly/cli@2.47.0 lint openapi.yaml
```

## Política de finalización

`status=complete` solo es válido cuando el inventario terminó correctamente, todos los detectores requeridos se ejecutaron con cobertura completa, no existen superficies sin soporte y los cuatro outputs son coherentes y válidos para el mismo commit.

Si aparece un framework, cliente HTTP o superficie no soportada, el resultado máximo permitido es `partial`.

## Licencia

Software propietario. Ver [`LICENSE`](LICENSE).
