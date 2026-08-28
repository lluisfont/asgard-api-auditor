"""Canonical API catalog construction from source-proven findings."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .artifacts import sha256_file
from .constants import API_CATALOG_SCHEMA_VERSION, FINDINGS_SCHEMA_VERSION
from .path_normalization import normalized_path_shape, path_parameter_names
from .redaction import contains_unredacted_secret_like_value, redact_text
from .schema_validation import SchemaValidationError, validate_json_schema

SCHEMAS_PACKAGE = "asgard_api_auditor.schemas"


class CatalogError(ValueError):
    """Raised when catalog inputs or outputs cannot be proven valid."""


@dataclass(frozen=True)
class FindingsSnapshot:
    path: Path
    sha256: str
    payload: dict[str, object]
    audit_id: str
    repository: str
    repository_id: str
    source_ref: str
    source_commit: str
    auditor_version: str
    schema_version: str


def _schema(name: str) -> dict[str, object]:
    try:
        payload = json.loads(
            resources.files(SCHEMAS_PACKAGE).joinpath(name).read_text(encoding="utf-8")
        )
    except (FileNotFoundError, ModuleNotFoundError, OSError, json.JSONDecodeError) as exc:
        raise CatalogError(f"Unable to read packaged JSON schema {name}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CatalogError(f"Packaged JSON schema {name} must be an object")
    return payload


def _require_string(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise CatalogError(f"findings.json is missing required string field: {key}")
    return value


def load_findings_snapshot(path: Path) -> FindingsSnapshot:
    resolved = path.resolve()
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogError(f"Unable to read findings artifact {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CatalogError(f"{path}: findings artifact must be a JSON object")
    try:
        validate_json_schema(payload, _schema("findings.schema.json"), source=str(path))
    except SchemaValidationError as exc:
        raise CatalogError(str(exc)) from exc
    schema_version = _require_string(payload, "schema_version")
    if schema_version != FINDINGS_SCHEMA_VERSION:
        raise CatalogError(
            f"{path}: unsupported findings schema_version {schema_version!r}; "
            f"expected {FINDINGS_SCHEMA_VERSION!r}"
        )
    endpoints = payload.get("endpoints")
    if not isinstance(endpoints, list):
        raise CatalogError(f"{path}: findings artifact must contain endpoints array")
    for index, endpoint in enumerate(endpoints):
        if not isinstance(endpoint, dict):
            raise CatalogError(f"{path}: endpoints[{index}] must be an object")
        for key in ("endpoint_id", "direction", "surface_type", "method", "path", "evidence"):
            if key not in endpoint:
                raise CatalogError(f"{path}: endpoints[{index}] misses {key}")
    return FindingsSnapshot(
        path=resolved,
        sha256=sha256_file(resolved),
        payload=payload,
        audit_id=_require_string(payload, "audit_id"),
        repository=_require_string(payload, "repository"),
        repository_id=_require_string(payload, "repository_id"),
        source_ref=_require_string(payload, "source_ref"),
        source_commit=_require_string(payload, "source_commit"),
        auditor_version=_require_string(payload, "auditor_version"),
        schema_version=schema_version,
    )


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest_id(prefix: str, payload: object) -> str:
    return f"{prefix}-{hashlib.sha256(_canonical_json(payload).encode('utf-8')).hexdigest()[:20]}"


def _contract_path(path: str) -> str:
    parsed = urlsplit(path)
    if parsed.scheme in {"http", "https"} and parsed.path:
        return parsed.path
    return path


def _stable_identity(endpoint: dict[str, object], *, namespace: str | None) -> dict[str, object]:
    method = str(endpoint.get("method", "")).upper()
    path = _contract_path(str(endpoint.get("path", "")))
    identity: dict[str, object] = {
        "direction": endpoint.get("direction"),
        "method": method,
        "path_shape": normalized_path_shape(path),
    }
    if namespace:
        identity["stable_namespace"] = namespace
    return identity


def endpoint_contract_id(endpoint: dict[str, object], *, namespace: str | None = None) -> str:
    """Return the v0.8 endpoint ID from contract identity only."""

    return _digest_id("endpoint", _stable_identity(endpoint, namespace=namespace))


def _as_list(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else []


def _string_list(value: object) -> list[str]:
    return sorted({item for item in _as_list(value) if isinstance(item, str)})


def _bool_or_none(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _dict_or_none(value: object) -> dict[str, object] | None:
    return value if isinstance(value, dict) else None


def _field_names_from_schema(schema: object) -> list[str]:
    if not isinstance(schema, dict):
        return []
    properties = schema.get("properties")
    if isinstance(properties, dict):
        return sorted(key for key in properties if isinstance(key, str))
    return []


def _required_from_schema(schema: object) -> list[str]:
    if not isinstance(schema, dict):
        return []
    fields = set(_string_list(schema.get("required")))
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, field_schema in properties.items():
            if (
                isinstance(name, str)
                and isinstance(field_schema, dict)
                and field_schema.get("x-asgard-requiredness") == "required"
            ):
                fields.add(name)
    fields.update(_string_list(schema.get("x-asgard-required-fields")))
    return sorted(fields)


def _optional_from_schema(schema: object) -> list[str]:
    if not isinstance(schema, dict):
        return []
    fields = set(_string_list(schema.get("x-asgard-optional-fields")))
    fields.update(_string_list(schema.get("x-asgard-optional")))
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, field_schema in properties.items():
            if (
                isinstance(name, str)
                and isinstance(field_schema, dict)
                and field_schema.get("x-asgard-requiredness") == "optional"
            ):
                fields.add(name)
    return sorted(fields)


def _request_contract(endpoint: dict[str, object]) -> dict[str, object]:
    source = endpoint.get("request")
    request = source if isinstance(source, dict) else {}
    fields = sorted(set(_string_list(request.get("fields")) + _field_names_from_schema(request.get("body_schema"))))
    required = _required_from_schema(request.get("body_schema"))
    optional = sorted(set(_optional_from_schema(request.get("body_schema"))) & set(fields) - set(required))
    parameters = [
        _parameter_contract(item)
        for item in _as_list(request.get("parameters"))
        if isinstance(item, dict)
    ]
    return {
        "parameters": parameters,
        "content_type": request.get("content_type"),
        "body_schema": request.get("body_schema"),
        "fields": fields,
        "required_fields": required,
        "optional_fields": optional,
        "unknown_requiredness_fields": sorted(set(fields) - set(required) - set(optional)),
        "accepts_additional_parameters": _bool_or_none(request.get("accepts_additional_parameters")),
        "rejects_additional_parameters": _bool_or_none(request.get("rejects_additional_parameters")),
        "evidence": [],
        "unresolved": [],
    }


def _parameter_contract(parameter: dict[str, object]) -> dict[str, object]:
    return {
        "name": parameter.get("name"),
        "location": parameter.get("location"),
        "required": parameter.get("required") if isinstance(parameter.get("required"), bool) else None,
        "schema": parameter.get("schema") if isinstance(parameter.get("schema"), dict) else None,
        "evidence": _as_list(parameter.get("evidence")),
    }


def _response_contract(endpoint: dict[str, object]) -> dict[str, object]:
    source = endpoint.get("response")
    response = source if isinstance(source, dict) else {}
    fields = sorted(set(_string_list(response.get("fields")) + _field_names_from_schema(response.get("schema"))))
    used = _string_list(response.get("fields_used_by_consumer"))
    return {
        "status_codes": sorted(
            code for code in _as_list(response.get("status_codes")) if isinstance(code, int)
        ),
        "content_type": response.get("content_type"),
        "schema": response.get("schema"),
        "fields": fields,
        "required_fields": _required_from_schema(response.get("schema")),
        "optional_fields": sorted(set(_optional_from_schema(response.get("schema"))) & set(fields)),
        "unknown_requiredness_fields": sorted(
            set(fields)
            - set(_required_from_schema(response.get("schema")))
            - set(_optional_from_schema(response.get("schema")))
        ),
        "additional_fields_backward_compatible": _bool_or_none(response.get("additional_fields_backward_compatible")),
        "fields_used_by_consumer": used,
        "tolerates_additional_fields": _bool_or_none(response.get("tolerates_additional_fields")),
        "tolerates_additional_statuses": _bool_or_none(response.get("tolerates_additional_statuses")),
        "status_code_compatibility": _dict_or_none(response.get("status_code_compatibility")),
        "evidence": [],
        "unresolved": [],
    }


def _auth_contract(endpoint: dict[str, object]) -> dict[str, object]:
    return {
        "authentication": endpoint.get("authentication"),
        "authorization": endpoint.get("authorization"),
        "credential_format": endpoint.get("credential_format"),
        "scheme": endpoint.get("scheme"),
        "schemes": [],
        "header_semantics": endpoint.get("header_semantics"),
        "required": None if endpoint.get("authentication") is None else True,
        "evidence": [],
        "unresolved": [],
    }


def _headers(endpoint: dict[str, object]) -> list[dict[str, object]]:
    request = endpoint.get("request")
    parameters = request.get("parameters") if isinstance(request, dict) else []
    headers = []
    for parameter in _as_list(parameters):
        if isinstance(parameter, dict) and parameter.get("location") == "header":
            headers.append(_parameter_contract(parameter))
    return sorted(headers, key=lambda item: str(item.get("name", "")))


def _contract_status(endpoint: dict[str, object]) -> str:
    mapping = {
        "evaluated_complete": "complete",
        "evaluated_partial": "partial",
        "required_not_complete": "partial",
        "not_applicable": "not_applicable",
        "complete": "complete",
        "partial": "partial",
        "unresolved": "unresolved",
        "unknown": "unknown",
    }
    notes = _as_list(endpoint.get("notes"))
    for note in notes:
        if isinstance(note, str) and note.startswith("contract_enrichment_status="):
            return mapping.get(note.split("=", 1)[1], "unknown")
    return "unknown"


def _semantic_status(endpoint: dict[str, object]) -> str:
    behavior = endpoint.get("behavior")
    if isinstance(behavior, dict):
        value = behavior.get("semantic_status")
        if isinstance(value, str) and value in {"complete", "partial", "unresolved"}:
            return value
    return "unknown"


def _semantic_behavior(endpoint: dict[str, object]) -> dict[str, object]:
    behavior = endpoint.get("behavior")
    if not isinstance(behavior, dict):
        return {
            "schema_version": None,
            "semantic_status": None,
            "confidence": None,
            "summary": None,
            "source_module": None,
            "semantic_partial_materiality": None,
            "tags": [],
            "request_fields": [],
            "data_access": [],
            "auth_context": {
                "consumed_jwt_claims": [],
                "produced_jwt_claims": [],
            },
            "local_calls": [],
            "outbound_integrations": [],
            "conditions": [],
            "side_effects": [],
            "response_semantics": {},
            "unresolved": [],
            "evidence": [],
        }
    materiality = behavior.get("semantic_partial_materiality")
    return {
        "schema_version": behavior.get("schema_version"),
        "semantic_status": behavior.get("semantic_status"),
        "confidence": behavior.get("confidence"),
        "summary": behavior.get("summary"),
        "source_module": behavior.get("source_module"),
        "semantic_partial_materiality": materiality if materiality in {"internal", "external", "unknown"} else None,
        "tags": _as_list(behavior.get("tags")),
        "request_fields": _as_list(behavior.get("request_fields")),
        "data_access": _as_list(behavior.get("data_access")),
        "auth_context": behavior.get(
            "auth_context",
            {"consumed_jwt_claims": [], "produced_jwt_claims": []},
        ),
        "local_calls": _as_list(behavior.get("local_calls")),
        "outbound_integrations": _as_list(behavior.get("outbound_integrations")),
        "conditions": _as_list(behavior.get("conditions")),
        "side_effects": _as_list(behavior.get("side_effects")),
        "response_semantics": behavior.get("response_semantics") or {},
        "unresolved": _as_list(behavior.get("unresolved")),
        "evidence": _as_list(behavior.get("evidence")),
    }


def _endpoint_matches(endpoint: dict[str, object], selectors: tuple[str, ...]) -> bool:
    if not selectors:
        return False
    method = str(endpoint.get("method", "")).upper()
    path = _contract_path(str(endpoint.get("path", "")))
    path_shape = normalized_path_shape(path)
    endpoint_id = str(endpoint.get("endpoint_id", ""))
    values = {endpoint_id, path, path_shape, f"{method} {path}", f"{method} {path_shape}"}
    return any(fnmatch.fnmatchcase(value, selector) for selector in selectors for value in values)


def _scope_status(endpoint: dict[str, object], include: tuple[str, ...], exclude: tuple[str, ...]) -> str:
    if include and not _endpoint_matches(endpoint, include):
        return "excluded"
    if exclude and _endpoint_matches(endpoint, exclude):
        return "excluded"
    return "included"


def _catalog_endpoint(
    endpoint: dict[str, object],
    *,
    snapshot: FindingsSnapshot,
    namespace: str | None,
    include: tuple[str, ...],
    exclude: tuple[str, ...],
) -> dict[str, object]:
    stable_identity = _stable_identity(endpoint, namespace=namespace)
    path = _contract_path(str(endpoint.get("path", "")))
    path_shape = normalized_path_shape(path)
    request = _request_contract(endpoint)
    parameters = list(request["parameters"])
    for name in path_parameter_names(path):
        if not any(isinstance(item, dict) and item.get("name") == name and item.get("location") == "path" for item in parameters):
            parameters.append({"name": name, "location": "path", "required": True, "schema": None, "evidence": []})
    return {
        "endpoint_id": _digest_id("endpoint", stable_identity),
        "api_id": endpoint.get("api_id"),
        "source_endpoint_id": endpoint.get("endpoint_id"),
        "stable_identity": stable_identity,
        "direction": endpoint.get("direction"),
        "surface_type": endpoint.get("surface_type"),
        "method": str(endpoint.get("method", "")).upper(),
        "normalized_path": path,
        "path_shape": path_shape,
        "base_url": endpoint.get("base_url"),
        "parameters": parameters,
        "request": request,
        "response": _response_contract(endpoint),
        "headers": _headers(endpoint),
        "authentication": _auth_contract(endpoint),
        "security": {"policy": "unknown", "drift": []},
        "behavior": _semantic_behavior(endpoint),
        "contract_status": _contract_status(endpoint),
        "semantic_status": _semantic_status(endpoint),
        "confidence": endpoint.get("confidence"),
        "confidence_reason": endpoint.get("confidence_reason"),
        "evidence": _as_list(endpoint.get("evidence")),
        "unresolved": _as_list(endpoint.get("unresolved")),
        "notes": _as_list(endpoint.get("notes")),
        "scope": {"status": _scope_status(endpoint, include, exclude), "selectors": []},
        "source": {
            "repository_id": snapshot.repository_id,
            "source_commit": snapshot.source_commit,
            "findings_sha256": snapshot.sha256,
        },
    }


def build_api_catalog(
    findings_path: Path,
    *,
    namespace: str | None = None,
    include_endpoints: tuple[str, ...] = (),
    exclude_endpoints: tuple[str, ...] = (),
) -> dict[str, object]:
    snapshot = load_findings_snapshot(findings_path)
    endpoints = [
        _catalog_endpoint(
            endpoint,
            snapshot=snapshot,
            namespace=namespace,
            include=include_endpoints,
            exclude=exclude_endpoints,
        )
        for endpoint in snapshot.payload["endpoints"]
        if isinstance(endpoint, dict)
    ]
    endpoints.sort(key=lambda item: (str(item["direction"]), str(item["method"]), str(item["path_shape"]), str(item["endpoint_id"])))
    included = [item for item in endpoints if item["scope"]["status"] == "included"]
    payload = {
        "schema_version": API_CATALOG_SCHEMA_VERSION,
        "catalog_id": _digest_id(
            "catalog",
            {
                "repository_id": snapshot.repository_id,
                "source_commit": snapshot.source_commit,
                "input_sha256": snapshot.sha256,
                "namespace": namespace,
                "include_endpoints": include_endpoints,
                "exclude_endpoints": exclude_endpoints,
            },
        ),
        "auditor_version": __version__,
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "repository": snapshot.repository,
            "repository_id": snapshot.repository_id,
            "source_ref": snapshot.source_ref,
            "source_commit": snapshot.source_commit,
            "findings_audit_id": snapshot.audit_id,
            "findings_schema_version": snapshot.schema_version,
            "findings_auditor_version": snapshot.auditor_version,
            "findings_sha256": snapshot.sha256,
            "stable_namespace": namespace,
        },
        "scope": {
            "mode": "explicit" if include_endpoints or exclude_endpoints else "all",
            "include_endpoints": list(include_endpoints),
            "exclude_endpoints": list(exclude_endpoints),
            "included_endpoints": len(included),
            "excluded_endpoints": len(endpoints) - len(included),
        },
        "coverage": {
            "inventory_complete": bool(snapshot.payload.get("coverage", {}).get("inventory_complete")) if isinstance(snapshot.payload.get("coverage"), dict) else False,
            "discovery_complete": snapshot.payload.get("status") == "complete",
            "total_endpoints": len(endpoints),
            "included_endpoints": len(included),
            "excluded_endpoints": len(endpoints) - len(included),
            "exposed_endpoints": sum(1 for item in included if item["direction"] == "exposed"),
            "consumed_endpoints": sum(1 for item in included if item["direction"] == "consumed"),
            "unresolved": len(_as_list(snapshot.payload.get("unresolved"))),
        },
        "endpoints": endpoints,
        "unresolved": _as_list(snapshot.payload.get("unresolved")),
        "input_hashes": [{"path": str(snapshot.path), "sha256": snapshot.sha256}],
    }
    validate_api_catalog(payload)
    return payload


def validate_api_catalog(payload: dict[str, object], *, source: str = "api-catalog.json") -> None:
    try:
        validate_json_schema(payload, _schema("api-catalog.schema.json"), source=source)
    except SchemaValidationError as exc:
        raise CatalogError(str(exc)) from exc


def write_api_catalog(
    findings_path: Path,
    output: Path,
    *,
    namespace: str | None = None,
    include_endpoints: tuple[str, ...] = (),
    exclude_endpoints: tuple[str, ...] = (),
) -> tuple[Path, dict[str, object]]:
    payload = build_api_catalog(
        findings_path,
        namespace=namespace,
        include_endpoints=include_endpoints,
        exclude_endpoints=exclude_endpoints,
    )
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        staging = Path(tmp) / output.name
        text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        if contains_unredacted_secret_like_value(text):
            raise CatalogError("Potential unredacted secret in api-catalog.json")
        staging.write_text(redact_text(text), encoding="utf-8", newline="\n")
        loaded = json.loads(staging.read_text(encoding="utf-8"))
        validate_api_catalog(loaded, source=str(staging))
        os.replace(staging, output)
    return output, payload


def copy_packaged_schema(schema_name: str, destination: Path) -> None:
    """Copy a packaged schema for callers that need a local contract artifact."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    with (
        resources.files(SCHEMAS_PACKAGE).joinpath(schema_name).open("rb") as source,
        tempfile.NamedTemporaryFile(delete=False, dir=destination.parent) as handle,
    ):
        temp = Path(handle.name)
        shutil.copyfileobj(source, handle)
    try:
        os.replace(temp, destination)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise
