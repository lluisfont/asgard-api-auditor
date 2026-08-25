# ASGARD API Auditor

Auditor técnico para reconstruir y mantener el conocimiento de integración de ASGARD a partir del código real de sus repositorios.

## Objetivo

Analizar exhaustivamente un repositorio ASGARD, identificar todos los endpoints HTTP que expone y consume, detectar otras superficies de integración, reconstruir contratos AS-IS, comparar auditorías y producir conocimiento trazable listo para incorporar al RAG central de APIs.

El objetivo operativo es responder con evidencia:

> ¿Qué puede romperse si esta API cambia?

## Outputs primarios por auditoría

Cada auditoría publicable debe producir exactamente estos cuatro artefactos primarios:

- `openapi.yaml`: contrato OpenAPI **3.1.2** AS-IS de las APIs HTTP expuestas y suficientemente verificadas.
- `api-knowledge.md`: conocimiento semántico preparado para el RAG central.
- `findings.json`: resultado estructurado, versionado y procesable por máquinas.
- `audit-report.md`: informe humano con cobertura, cambios, riesgos, incertidumbres y anomalías.

Los cuatro artefactos deben compartir el mismo `audit_id`, repositorio, commit, versión del auditor y timestamp.

## Principios no negociables

1. **Código real como evidencia principal.**
2. **Proveedor y consumidor tienen la misma importancia.**
3. **Cobertura antes que confianza.** No se puede declarar `complete` solo porque no queden hallazgos sin clasificar.
4. **No inventar.** Lo no demostrado se marca como `unknown`, `unverified`, `not_detected` o `unsupported`.
5. **Trazabilidad a commit y evidencia concreta.**
6. **OpenAPI representa primero el contrato AS-IS.**
7. **Las superficies no representables por OpenAPI no se ignoran.** GraphQL, WebSocket, gRPC, SOAP, SSE u otras se registran como superficies de integración.
8. **Una auditoría fallida nunca reemplaza una auditoría válida anterior.** La publicación debe ser atómica.
9. **No publicar secretos ni código propietario en los artefactos.**

## Estado

**v0.2 — hardening de arquitectura y contratos.**

Esta versión corrige los riesgos de diseño de la v0.1: falsos `complete`, contrato de findings insuficiente, falta de IDs estables, ausencia de modelo de cobertura, publicación no atómica y falta de gobernanza/CI.

Los detectores específicos por lenguaje/framework todavía se incorporarán progresivamente y deberán declarar explícitamente qué patrones soportan y cuáles no.

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

Documentación:

- [`docs/architecture.md`](docs/architecture.md)
- [`docs/audit-method.md`](docs/audit-method.md)
- [`docs/coverage-model.md`](docs/coverage-model.md)
- [`docs/output-contracts.md`](docs/output-contracts.md)
- [`docs/security-and-redaction.md`](docs/security-and-redaction.md)
- [`docs/testing.md`](docs/testing.md)

## Requisitos

- Python 3.11+
- Git
- Node.js 20.19+ o 22.12+ para Redocly CLI 2.x en validación OpenAPI
- Acceso de solo lectura a los repositorios auditados

No deben copiarse repositorios ASGARD, credenciales, tokens ni datos sensibles dentro de este repositorio.

## Desarrollo local

```bash
python -m venv .venv
```

Instala el paquete y herramientas de desarrollo fijadas:

```bash
pip install -e .
pip install -r requirements-dev.lock
```

Ejecuta los controles locales:

```bash
ruff check .
python -m compileall -q src scripts
python -m unittest discover -s tests -v
python scripts/validate_contracts.py
```

Validación OpenAPI de un artefacto generado:

```bash
npx -y @redocly/cli@2.47.0 lint openapi.yaml
```

## Política de finalización

`status=complete` solo es válido cuando:

- el inventario de archivos relevante terminó correctamente;
- todos los frameworks/clientes HTTP detectados están soportados por detectores ejecutados con éxito;
- no hay superficies de integración detectadas sin cobertura;
- los hallazgos descubiertos están clasificados o explícitamente documentados;
- se generaron los cuatro outputs primarios;
- `findings.json` cumple el contrato;
- `openapi.yaml` pasa validación estructural cuando existe API HTTP expuesta;
- todos los outputs corresponden al mismo `audit_id` y `source_commit`.

Si aparece un framework, cliente HTTP o superficie no soportada, el resultado máximo permitido es `partial`.

## Seguridad

El auditor puede analizar repositorios privados, pero sus artefactos nunca deben contener secretos ni fragmentos de código propietario innecesarios. Ver [`SECURITY.md`](SECURITY.md).

## Licencia

Software propietario. Ver [`LICENSE`](LICENSE).
