# Endpoint discovery v0.4.2

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

PHP cURL cubre `curl_init`, `curl_setopt`, `curl_setopt_array([...])` y `curl_setopt_array(array(...))`. Cuando una base es una constante o expresión no resuelta, se conserva como expresión trazable en vez de inventar su valor.

Integraciones: SOAP se emite en `integrations` con WSDL/operación cuando puede demostrarse. SOAP no se convierte en REST/OpenAPI y mantiene `discovery_complete=false` mientras la extracción WSDL sea parcial.

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
