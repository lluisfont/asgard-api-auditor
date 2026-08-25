# ASGARD API Auditor

Auditor técnico para reconstruir y mantener el conocimiento de integración de ASGARD a partir del código real de sus repositorios.

## Objetivo

Analizar un repositorio ASGARD, identificar las APIs que expone y consume, reconstruir contratos AS-IS, detectar dependencias y producir conocimiento trazable para el RAG central de APIs.

La pregunta operativa es:

> ¿Qué puede romperse si esta API cambia?

## Estado

**v0.4.5 — snapshots WSDL explícitos y reproducibles para completar contratos SOAP.**

La v0.3 detecta tecnologías y superficies. La v0.4.x utiliza ese inventario para localizar endpoints HTTP expuestos y consumidos con evidencia concreta y falla de forma cerrada ante patrones dinámicos o todavía no soportados.

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
fases siguientes
        +--> request/response enrichment
        +--> provider/consumer correlation
        +--> OpenAPI 3.1.2
        +--> API Knowledge / RAG
```

## Cobertura

`discovery_complete=true` solo puede producirse cuando el inventario terminó sin huecos conocidos, existe al menos un detector aplicable, todos los detectores ejecutados están soportados y no existen patrones o superficies pendientes.

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
