# ASGARD API Auditor

Auditor técnico para reconstruir y mantener el conocimiento de integración de ASGARD a partir del código real de sus repositorios.

## Objetivo

Analizar un repositorio ASGARD, identificar las APIs que expone y consume, reconstruir contratos AS-IS, detectar dependencias y producir conocimiento trazable para el RAG central de APIs.

La pregunta operativa es:

> ¿Qué puede romperse si esta API cambia?

## Estado

**v0.5.3 — generación trazable con reconstrucción determinista de requests PHP y fail-closed.**

La v0.3 detecta tecnologías y superficies. La v0.4.x localiza endpoints HTTP expuestos/consumidos y operaciones SOAP con cobertura fail-closed. La v0.5 empieza a convertir ese discovery en artefactos auditables y reutilizables.

## Inventario técnico

```bash
asgard-api-auditor inventory /ruta/al/repositorio
```

Excluir fixtures o artefactos locales:

```bash
asgard-api-auditor inventory /ruta/al/repositorio --exclude-path audit --exclude-path work_sample
```

## Discovery de endpoints

```bash
asgard-api-auditor discover /ruta/al/repositorio
```

Guardar resultado:

```bash
asgard-api-auditor discover /ruta/al/repositorio --output endpoint-discovery.json
```

Actualmente incluye detectores para Laravel, Slim, Angular `HttpClient`, Axios, Fetch, Guzzle, Laravel HTTP facade, PHP cURL, Dio y Dart `http`.

Slim solo se reconoce en receptores verificables de aplicación/router. PHP cURL soporta `curl_setopt`, `curl_setopt_array([...])`, `curl_setopt_array(array(...))` y wrappers locales `$this->method(...)` cuando la propagación de argumentos es inequívoca.

Las integraciones SOAP se reportan en `integrations`, no como endpoints REST. La detección separa `soap_operations_complete` de `soap_contracts_complete`: puede demostrar operaciones PHP `SoapClient` aunque el contrato WSDL no esté versionado localmente.

Cuando la expresión usada por `SoapClient` no puede resolverse desde código versionado, se puede aportar explícitamente un snapshot WSDL local y versionado:

```bash
asgard-api-auditor discover /ruta/al/repositorio \
  --soap-wsdl servicioovp=contracts/soap/ovp.wsdl
```

`--soap-wsdl` es repetible. La clave puede ser la expresión o valor del servicio detectado. El path debe permanecer dentro del repositorio y estar versionado por Git. El auditor no descarga WSDLs de red durante el discovery.

Si el snapshot es válido, las operaciones SOAP usadas por el código se contrastan contra el WSDL. Una operación consumida que no exista en el contrato genera `soap_operation_not_in_wsdl` y mantiene `discovery_complete=false`.

Si aparece un framework, cliente o patrón no soportado, `discovery_complete=false` y el problema queda explícitamente registrado en `unresolved`.

Más detalle: [`docs/endpoint-discovery.md`](docs/endpoint-discovery.md).

## Generación de auditoría v0.5

```bash
asgard-api-auditor audit /ruta/al/repositorio \
  --repository-id asgard-warehouse \
  --exclude-path audit \
  --exclude-path work_sample \
  --output api-audit-output
```

El comando genera y valida atómicamente:

- `openapi.yaml`
- `api-knowledge.md`
- `findings.json`
- `audit-report.md`

Los mismos snapshots SOAP de `discover` pueden pasarse a `audit` con `--soap-wsdl`.

### Semántica conservadora

- OpenAPI contiene únicamente endpoints HTTP **expuestos** y demostrados por código.
- Las llamadas HTTP consumidas permanecen en `findings.json` y `api-knowledge.md`; no se convierten en paths del proveedor.
- SOAP permanece como superficie de integración separada y nunca se convierte artificialmente en REST.
- Request bodies, responses, autenticación y autorización se añaden solo cuando pueden demostrarse desde código Slim/PHP.
- v0.5.3 registra cobertura objetiva de enrichment y mantiene un blocker explícito `contract-enrichment-v0.5.3-coverage-gate`; por tanto el `audit` permanece `partial` aunque `discovery_complete=true`.

Más detalle: [`docs/audit-artifacts.md`](docs/audit-artifacts.md).

## Arquitectura

```text
Repositorios ASGARD
        |
        v
inventory (v0.3)
        |
        v
discover (v0.4)
        |
        +--> endpoints expuestos
        +--> endpoints consumidos
        +--> integraciones SOAP
        +--> evidencia
        +--> cobertura por detector
        +--> unresolved / unsupported
        |
        v
audit artifacts (v0.5)
        +--> openapi.yaml
        +--> api-knowledge.md
        +--> findings.json
        +--> audit-report.md
        |
        v
fases siguientes
        +--> deeper request/response/security enrichment
        +--> provider/consumer correlation
        +--> breaking-change gate
        +--> API Knowledge / RAG central
```

## Cobertura

`discovery_complete=true` solo puede producirse cuando el inventario terminó sin huecos conocidos, existe al menos un detector aplicable, todos los detectores ejecutados están soportados y no existen patrones o superficies pendientes.

`audit status=complete` exige además que el contrato behavioral esté reconstruido y validado. En v0.5.3 el audit permanece intencionadamente `partial`: existe enrichment Slim/PHP parcial y trazable, pero los gates globales todavía no están completos.

Encontrar cero endpoints nunca se interpreta automáticamente como ausencia de APIs.

## Requisitos

- Python 3.11+
- Git
- Node.js 20.19+ o 22.12+ para validar OpenAPI con Redocly CLI 2.x

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

## Licencia

Software propietario. Ver [`LICENSE`](LICENSE).
