# Endpoint discovery v0.4.4

La fase `discover` convierte el inventario técnico de v0.3 en hallazgos HTTP concretos sin afirmar más de lo que puede demostrar.

## Objetivo

Encontrar endpoints HTTP expuestos y consumidos con evidencia de archivo/línea y declarar explícitamente cualquier patrón que impida asegurar cobertura completa.

## Comando

```bash
asgard-api-auditor discover /ruta/al/repositorio
```

Guardar resultado:

```bash
asgard-api-auditor discover /ruta/al/repositorio --output endpoint-discovery.json
```

Excluir rutas del repositorio:

```bash
asgard-api-auditor discover /ruta/al/repositorio --exclude-path audit --exclude-path work_sample
```

El resultado cumple `schemas/endpoint-discovery.schema.json`.

## Detectores incluidos

Expuestos:

- Laravel `Route::get/post/put/patch/delete/options/head` con path literal y `Route::match` con métodos/path literales.
- Slim `$app->get/post/put/patch/delete/options(...)` con path literal, limitado a receptores verificables de aplicación/router Slim.

Consumidos: Angular `HttpClient`, Axios, Fetch, Guzzle, Laravel HTTP facade, PHP cURL, Dio y Dart `http` con `Uri.parse` literal.

PHP cURL cubre `curl_init`, `curl_setopt`, `curl_setopt_array([...])`, `curl_setopt_array(array(...))` y wrappers HTTP locales dentro de la misma clase cuando la propagación de parámetros posicionales es determinista. Cuando una base es una constante o expresión no resuelta, se conserva como expresión trazable en vez de inventar su valor.

La resolución de wrappers se limita a llamadas `$this->method(...)`, métodos definidos en la misma clase/archivo, literales, variables locales trazables, concatenaciones deterministas y helpers locales con retorno demostrable. Dispatch dinámico, herencia ambigua, callbacks, reflection, métodos externos o valores incompatibles quedan como `unresolved`.

Integraciones: SOAP se emite en `integrations`, no como endpoints REST/OpenAPI. El detector PHP `SoapClient` descubre operaciones directas y operaciones alcanzadas al pasar el cliente como argumento posicional a métodos de clases locales cuando la procedencia es inequívoca.

SOAP distingue dos estados:

- `soap_operations_complete`: todas las instancias `SoapClient` detectadas tienen operaciones demostrables.
- `soap_contracts_complete`: las operaciones descubiertas están respaldadas por contratos WSDL reproducibles y versionados localmente.

Si el WSDL es externo, no existe en el repositorio o la expresión de servicio no se puede resolver de forma determinista, las operaciones se conservan con `contract_status` parcial y `discovery_complete=false`.

Los patrones dinámicos, `Route::resource`, `Route::apiResource`, `Route::any`, `Route::fallback`, grupos/prefijos no demostrados, rutas Slim dinámicas, clientes HTTP sin detector o integraciones no HTTP parciales quedan en `unresolved` y bloquean `discovery_complete`.

## Regla de cobertura

`discovery_complete=true` requiere:

1. `inventory_complete=true`.
2. al menos un detector aplicable.
3. todos los detectores en estado `supported`.
4. ningún patrón bloqueante sin resolver.
5. ninguna superficie no HTTP pendiente de detector específico.

Encontrar cero endpoints nunca demuestra por sí mismo que no existan APIs.

## Pendiente después de v0.4

- enriquecer request/response;
- identificar campos realmente usados por consumidores;
- correlacionar proveedores y consumidores entre repositorios;
- generar OpenAPI final y `api-knowledge.md`.
