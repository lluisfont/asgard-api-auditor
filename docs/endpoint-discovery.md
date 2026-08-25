# Endpoint discovery v0.4

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

El resultado cumple `schemas/endpoint-discovery.schema.json`.

## Detectores incluidos

Expuestos: Laravel `Route::get/post/put/patch/delete/options/head` con path literal y `Route::match` con métodos/path literales.

Consumidos: Axios, Fetch, Guzzle, Laravel HTTP facade, Dio y Dart `http` con `Uri.parse` literal.

Los patrones dinámicos, `Route::resource`, `Route::apiResource`, `Route::any`, `Route::fallback`, grupos/prefijos no demostrados o clientes HTTP sin detector quedan en `unresolved` y bloquean `discovery_complete`.

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
