# ASGARD API Auditor

Auditor técnico para reconstruir y mantener el conocimiento de integración de ASGARD a partir del código real de sus repositorios.

## Objetivo

Analizar un repositorio ASGARD, identificar las APIs que expone y consume, reconstruir contratos AS-IS, detectar dependencias y producir conocimiento trazable para el RAG central de APIs.

La pregunta operativa es:

> ¿Qué puede romperse si esta API cambia?

## Estado

**v0.8.0 — catálogos API canónicos y compatibilidad cross-repository.**

La v0.3 detecta tecnologías y superficies. La v0.4.x localiza endpoints HTTP expuestos/consumidos y operaciones SOAP con cobertura fail-closed. La v0.5 convierte ese discovery en artefactos auditables y reutilizables. La v0.6 añade una primera capa de relación entre consumidores y proveedores a partir de artifacts versionados. La v0.7 añade una capa semántica determinística entre el enrichment de contratos y la generación de OpenAPI/findings. La v0.8 genera catálogos API canónicos y compara contratos entre reference/candidate o provider/consumer sin lógica específica por repositorio.

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

## Generación de auditoría v0.7

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
- Cada operación expuesta incluye `x-asgard-behavior` con hechos semánticos trazables: acceso a datos, JWT consumido/producido, condiciones, response body funcional, llamadas locales, integraciones salientes, efectos laterales y unresolved.
- `codigo`, `estado` y `mensaje` del body se registran como campos funcionales y no se transforman en HTTP status; solo `withStatus(...)` demuestra status HTTP explícito.
- v0.7.0 registra cobertura objetiva de contract enrichment y semantic enrichment, y mantiene un blocker explícito `contract-enrichment-v0.7.0-coverage-gate`; por tanto el `audit` permanece `partial` aunque `discovery_complete=true`.
- Los detectores de consumidores HTTP enmascaran comentarios antes de buscar llamadas activas, preservando líneas/evidencia y evitando falsos positivos de código comentado.

Más detalle: [`docs/audit-artifacts.md`](docs/audit-artifacts.md).

## Correlación proveedor-consumidor v0.6

```bash
asgard-api-auditor correlate \
  --findings warehouse-audit/findings.json \
  --findings mobile-audit/findings.json \
  --output correlation-results
```

El comando genera y valida atómicamente:

- `correlations.json`
- `api-relations.md`

La correlación opera sobre artifacts `findings.json`, no sobre scanners acoplados entre repositorios. La clave MVP es estrictamente `HTTP method + normalized path shape`: solo se normalizan nombres de parámetros de ruta, preservando segmentos literales, cantidad de segmentos, método y semántica de slash final.

Estados:

- `matched_confirmed`: existe identidad de proveedor explícita en el artifact del consumidor y coincide con un proveedor.
- `matched_unique_candidate`: un único proveedor comparte método y shape, pero no está probado como dependencia runtime.
- `ambiguous`: más de un proveedor comparte método y shape; no se elige ninguno.
- `unmatched`: no existe candidato por método y shape.

No hay fuzzy matching, heurísticas por host, nombres de repositorio, mappings manuales ni clasificación automática de externos. SOAP permanece fuera de la correlación HTTP.

Más detalle: [`docs/output-contracts.md`](docs/output-contracts.md).

## Catálogo API canónico v0.8

```bash
asgard-api-auditor catalog-api \
  --findings api-audit-output/findings.json \
  --output api-catalog.json
```

`api-catalog.json` conserva endpoints expuestos y consumidos como direcciones distintas. La identidad estable del endpoint se deriva solo de dirección, método, path shape y un namespace estable explícito si se proporciona; `api_id` es agrupación independiente y no cambia el `endpoint_id`.

## Compatibilidad reference/candidate v0.8

```bash
asgard-api-auditor compare-api \
  reference-api-catalog.json \
  candidate-api-catalog.json \
  --output api-compatibility-output \
  --gate-mode fail_closed
```

Por defecto, todo endpoint del reference dentro del scope seleccionado es required. `report` nunca falla el gate, `fail_on_breaking` falla por cambios breaking y `fail_closed` falla por breaking o unknown materiales. `observed_equal` describe igualdad de observaciones, no compatibilidad probada.

## Compatibilidad provider/consumer v0.8

```bash
asgard-api-auditor check-consumer-compatibility \
  --consumer-catalog consumer-api-catalog.json \
  --provider-catalog provider-api-catalog.json \
  --output consumer-compatibility-output
```

Por defecto, todo endpoint consumido dentro del scope seleccionado es una required dependency y el gate recomendado es `fail_closed`. El provider debe aceptar todos los requests que el consumer puede producir y producir al menos los datos/responses que el consumer demuestra necesitar. Unknown material permanece unknown; no se infiere tolerancia.

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
audit artifacts (v0.7)
        +--> openapi.yaml
        +--> api-knowledge.md
        +--> findings.json
        +--> audit-report.md
        |
        v
api catalog (v0.8)
        +--> stable API contract catalog
        +--> reference/candidate compatibility
        +--> provider/consumer compatibility
        +--> breaking-change gates
```

## Cobertura

`discovery_complete=true` solo puede producirse cuando el inventario terminó sin huecos conocidos, existe al menos un detector aplicable, todos los detectores ejecutados están soportados y no existen patrones o superficies pendientes.

`audit status=complete` exige además que el contrato behavioral esté reconstruido y validado. En v0.7.0 el audit permanece intencionadamente `partial`: existe enrichment Slim/PHP semántico parcial y trazable, y la correlación se genera en artifacts separados para evaluación explícita antes de futuros gates de breaking changes.

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
