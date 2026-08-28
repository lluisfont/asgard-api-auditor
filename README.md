# ASGARD API Auditor

Auditor determinista de APIs para repositorios de software existentes.

Analiza el código real de un repositorio Git, identifica APIs HTTP expuestas y consumidas, reconstruye contratos AS-IS cuando existe evidencia suficiente, registra incertidumbre de forma explícita y genera artefactos trazables para análisis técnico y compatibilidad entre repositorios.

La pregunta operativa central es:

> ¿Qué APIs contiene o consume este repositorio y qué puede romperse si cambian?

ASGARD es el entorno real en el que se ha desarrollado y validado el auditor, pero la v0.8 no contiene lógica específica por repositorio. El auditor puede ejecutarse contra cualquier repositorio Git. La profundidad del resultado depende de los lenguajes, frameworks y patrones que tengan detector soportado.

**Principio:** `UNKNOWN > GUESS`. Una superficie detectada pero no soportada o un hecho que no puede demostrarse no se inventa ni se omite para obtener artificialmente un resultado `complete`.

## Estado

**v0.8.0 — Canonical API Contracts & Cross-Repository Compatibility.**

La v0.8 incorpora inventario técnico, discovery de APIs HTTP expuestas y consumidas, tratamiento separado de SOAP, reconstrucción conservadora de contratos y semántica, artefactos auditables, catálogo API canónico, correlación provider/consumer, comparación reference/candidate y gates de compatibilidad.

## Requisitos

- Python 3.11+
- Git
- Node.js 20.19+ o 22.12+ únicamente para la validación OpenAPI con Redocly CLI 2.x usada por el proyecto

## Instalación

```bash
git clone https://github.com/lluisfont/asgard-api-auditor.git
cd asgard-api-auditor
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Instalar y comprobar:

```bash
python -m pip install -e .
asgard-api-auditor --version
```

## Quick Start

### 1. Auditar un repositorio

El repositorio objetivo debe ser un repositorio Git local con un `HEAD` identificable.

```bash
asgard-api-auditor audit /ruta/al/repositorio \
  --repository-id my-repository \
  --output audit/my-repository
```

Genera y valida atómicamente:

- `openapi.yaml` — OpenAPI AS-IS de endpoints HTTP expuestos demostrados;
- `api-knowledge.md` — conocimiento técnico legible;
- `findings.json` — findings canónicos y evidencia de la auditoría;
- `audit-report.md` — informe humano de cobertura, resultados y blockers.

Puede excluir rutas fuera del producto auditado:

```bash
asgard-api-auditor audit /ruta/al/repositorio \
  --repository-id my-repository \
  --exclude-path audit \
  --exclude-path work_sample \
  --output audit/my-repository
```

### 2. Generar el catálogo API canónico

```bash
asgard-api-auditor catalog-api \
  --findings audit/my-repository/findings.json \
  --output audit/my-repository/api-catalog.json
```

`api-catalog.json` es la representación estructurada y normalizada de las APIs expuestas y consumidas del repositorio. Conserva dirección, identidad estable, contrato, seguridad, comportamiento demostrado, evidencia, cobertura y unresolved facts.

### 3. Revisar el resultado

No interprete únicamente el número de endpoints. Revise siempre el estado de auditoría, la cobertura de detectores y los elementos `unresolved`.

## Cómo interpretar los estados

### `complete`

El auditor ha demostrado cobertura suficiente para las superficies de integración detectadas dentro del alcance y no quedan gaps de cobertura que invaliden el resultado.

`complete` no significa que se hayan inventado detalles ausentes. Los hechos no demostrados permanecen desconocidos.

### `partial`

La auditoría produjo conocimiento válido, pero existe al menos una limitación relevante de cobertura o reconstrucción, por ejemplo una tecnología sin detector suficiente, SOAP sin contrato reproducible, resolución dinámica o ambigua, detector parcial o contrato material no reconstruible de forma determinista.

Un resultado `partial` es evidencia válida, pero no debe presentarse como reconstrucción completa del repositorio.

### `failed`

La auditoría no puede producir un conjunto publicable de artefactos bajo las garantías del auditor. Los contratos inválidos y errores de validación fallan cerrado.

## Cobertura y stacks soportados

El auditor es genérico respecto al repositorio, pero su profundidad depende de los detectores disponibles.

| Stack / patrón | APIs expuestas | APIs consumidas | Enrichment profundo |
| --- | --- | --- | --- |
| Slim PHP | Sí | — | Sí: contratos, seguridad y semántica en patrones soportados |
| Laravel routes | Sí | — | Limitado/conservador |
| Angular `HttpClient` | — | Sí | Discovery y facts demostrables |
| Axios | — | Sí | Discovery y facts demostrables |
| Fetch | — | Sí | Discovery y facts demostrables |
| Guzzle | — | Sí | Discovery y facts demostrables |
| Laravel HTTP facade | — | Sí | Discovery y facts demostrables |
| PHP cURL | — | Sí | Discovery determinista; wrappers locales acotados |
| Dio | — | Sí | Discovery fail-closed de receptores demostrables |
| Dart `http` | — | Sí | Discovery en patrones soportados |
| PHP `SoapClient` / SOAP | Superficie separada | Superficie separada | Contrato WSDL cuando existe snapshot local versionado |

La matriz detallada y sus límites están en [`docs/supported-stacks.md`](docs/supported-stacks.md).

**Importante:** que un framework aparezca en la tabla no significa que cualquier construcción dinámica esté soportada. Los patrones no resolubles permanecen `unresolved` y pueden impedir `complete`.

## Inventario técnico

```bash
asgard-api-auditor inventory /ruta/al/repositorio
```

Guardar inventario:

```bash
asgard-api-auditor inventory /ruta/al/repositorio --output inventory.json
```

Más detalle: [`docs/technical-inventory.md`](docs/technical-inventory.md).

## Discovery de endpoints

```bash
asgard-api-auditor discover /ruta/al/repositorio
```

Guardar resultado:

```bash
asgard-api-auditor discover /ruta/al/repositorio --output endpoint-discovery.json
```

Cuando aparece un framework, cliente o patrón no soportado, `discovery_complete=false` y el gap queda registrado en `unresolved`.

Más detalle: [`docs/endpoint-discovery.md`](docs/endpoint-discovery.md).

## SOAP

SOAP se mantiene separado de REST/OpenAPI. Cuando el WSDL no puede resolverse de forma reproducible desde el repositorio, puede aportarse un snapshot local y versionado:

```bash
asgard-api-auditor audit /ruta/al/repositorio \
  --soap-wsdl servicio=contracts/soap/service.wsdl \
  --output audit/my-repository
```

El auditor no descarga WSDLs de red durante discovery/audit.

## Correlación provider/consumer

```bash
asgard-api-auditor correlate \
  --findings repo-a/findings.json \
  --findings repo-b/findings.json \
  --output correlation-results
```

Genera `correlations.json` y `api-relations.md` con estados `matched_confirmed`, `matched_unique_candidate`, `ambiguous` y `unmatched`.

La correlación HTTP no utiliza fuzzy matching, heurísticas por nombre de repositorio ni mappings manuales.

## Compatibilidad reference/candidate

```bash
asgard-api-auditor compare-api \
  reference-api-catalog.json \
  candidate-api-catalog.json \
  --output api-compatibility-output \
  --gate-mode fail_closed
```

Clasifica como `same`, `additive`, `breaking` o `unknown`. `unknown` material bloquea `fail_closed`.

## Compatibilidad provider/consumer

```bash
asgard-api-auditor check-consumer-compatibility \
  --consumer-catalog consumer-api-catalog.json \
  --provider-catalog provider-api-catalog.json \
  --output consumer-compatibility-output
```

Por defecto, todo endpoint consumido dentro del scope seleccionado es una required dependency. Ausencia de conflicto no equivale a compatibilidad demostrada.

## Modelo conservador

- Solo se generan facts demostrables desde código y artefactos versionados.
- OpenAPI contiene únicamente endpoints HTTP expuestos.
- Las APIs consumidas permanecen como consumers; no se transforman en providers.
- SOAP nunca se convierte artificialmente en REST.
- Raw JWT en `Authorization` permanece raw JWT; no se convierte en `Bearer` salvo evidencia explícita.
- `codigo`, `estado` y `mensaje` en JSON no se interpretan como HTTP status.
- Los datos desconocidos permanecen `unknown`.
- Evidencia y commits forman parte de la trazabilidad de los outputs.

## Documentación técnica

- [`docs/audit-method.md`](docs/audit-method.md) — método completo y completion gate.
- [`docs/architecture.md`](docs/architecture.md) — arquitectura interna.
- [`docs/technical-inventory.md`](docs/technical-inventory.md) — inventario técnico.
- [`docs/endpoint-discovery.md`](docs/endpoint-discovery.md) — discovery y cobertura.
- [`docs/audit-artifacts.md`](docs/audit-artifacts.md) — artefactos generados.
- [`docs/output-contracts.md`](docs/output-contracts.md) — contratos machine-readable.
- [`docs/coverage-model.md`](docs/coverage-model.md) — modelo de cobertura.
- [`docs/security-and-redaction.md`](docs/security-and-redaction.md) — seguridad y redacción.
- [`docs/testing.md`](docs/testing.md) — testing.
- [`docs/supported-stacks.md`](docs/supported-stacks.md) — matriz de tecnologías soportadas.

## Desarrollo local

```bash
python -m venv .venv
python -m pip install -e .
python -m pip install -r requirements-dev.lock
ruff check .
python -m compileall -q src scripts
python -m unittest discover -s tests -v
python scripts/validate_contracts.py
```

## Alcance futuro

Los catálogos canónicos están diseñados para poder alimentar capacidades cross-repository posteriores. El diseño de una capa central de conocimiento, registry o dependency graph queda fuera de esta documentación hasta definir su arquitectura.

## Licencia

Software propietario. Ver [`LICENSE`](LICENSE).
