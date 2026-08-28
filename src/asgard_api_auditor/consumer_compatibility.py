"""Directional provider/consumer compatibility checks over API catalogs."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import shutil
import tempfile
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Literal

from . import __version__
from .api_compatibility import load_catalog
from .constants import CONSUMER_COMPATIBILITY_SCHEMA_VERSION
from .redaction import contains_unredacted_secret_like_value, redact_text
from .schema_validation import SchemaValidationError, validate_json_schema

SCHEMAS_PACKAGE = "asgard_api_auditor.schemas"
GateMode = Literal["report", "fail_on_breaking", "fail_closed"]


class ConsumerCompatibilityError(ValueError):
    """Raised when provider/consumer compatibility cannot be evaluated safely."""


def _schema(name: str) -> dict[str, object]:
    try:
        payload = json.loads(
            resources.files(SCHEMAS_PACKAGE).joinpath(name).read_text(encoding="utf-8")
        )
    except (FileNotFoundError, ModuleNotFoundError, OSError, json.JSONDecodeError) as exc:
        raise ConsumerCompatibilityError(f"Unable to read packaged JSON schema {name}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConsumerCompatibilityError(f"Packaged JSON schema {name} must be an object")
    return payload


def _validate(payload: dict[str, object], schema_name: str, source: str) -> None:
    try:
        validate_json_schema(payload, _schema(schema_name), source=source)
    except SchemaValidationError as exc:
        raise ConsumerCompatibilityError(str(exc)) from exc


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(prefix: str, payload: object) -> str:
    return f"{prefix}-{hashlib.sha256(_canonical_json(payload).encode('utf-8')).hexdigest()[:20]}"


def _as_dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _as_list(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else []


def _strings(value: object) -> set[str]:
    return {item for item in _as_list(value) if isinstance(item, str)}


def _endpoint_values(endpoint: dict[str, object]) -> set[str]:
    method = str(endpoint.get("method", "")).upper()
    path = str(endpoint.get("normalized_path", ""))
    path_shape = str(endpoint.get("path_shape", ""))
    return {
        str(endpoint.get("endpoint_id", "")),
        path,
        path_shape,
        f"{method} {path}",
        f"{method} {path_shape}",
    }


def _matches_scope(endpoint: dict[str, object], selectors: tuple[str, ...]) -> bool:
    return any(
        fnmatch.fnmatchcase(value, selector)
        for selector in selectors
        for value in _endpoint_values(endpoint)
    )


def _scope(
    endpoints: list[dict[str, object]],
    *,
    include: tuple[str, ...],
    exclude: tuple[str, ...],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    required: list[dict[str, object]] = []
    excluded: list[dict[str, object]] = []
    for endpoint in endpoints:
        if (include and not _matches_scope(endpoint, include)) or (
            exclude and _matches_scope(endpoint, exclude)
        ):
            excluded.append(endpoint)
        else:
            required.append(endpoint)
    return required, excluded


def _provider_index(providers: list[dict[str, object]]) -> dict[tuple[str, str], list[dict[str, object]]]:
    indexed: dict[tuple[str, str], list[dict[str, object]]] = {}
    for endpoint in providers:
        key = (str(endpoint.get("method")), str(endpoint.get("path_shape")))
        indexed.setdefault(key, []).append(endpoint)
    return indexed


def _field_type(schema: object, field: str) -> object:
    properties = _as_dict(_as_dict(schema).get("properties"))
    field_schema = _as_dict(properties.get(field))
    return field_schema.get("type") or field_schema.get("format")


def _request_checks(consumer: dict[str, object], provider: dict[str, object]) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    consumer_request = _as_dict(consumer.get("request"))
    provider_request = _as_dict(provider.get("request"))
    consumer_fields = _strings(consumer_request.get("fields"))
    provider_fields = _strings(provider_request.get("fields"))
    provider_required = _strings(provider_request.get("required_fields"))
    for field in sorted(_strings(consumer_request.get("unknown_requiredness_fields"))):
        checks.append({"status": "unknown", "code": "consumer_request_requiredness_unknown", "detail": field})
    for field in sorted(_strings(provider_request.get("unknown_requiredness_fields"))):
        checks.append({"status": "unknown", "code": "provider_request_requiredness_unknown", "detail": field})
    for field in sorted(provider_required - consumer_fields):
        checks.append({"status": "breaking", "code": "provider_requires_unsent_request_field", "detail": field})
    extra_sent = consumer_fields - provider_fields
    if extra_sent:
        if provider_request.get("accepts_additional_fields") is True:
            checks.append({"status": "compatible", "code": "provider_accepts_additional_request_fields", "detail": ",".join(sorted(extra_sent))})
        elif provider_request.get("rejects_additional_fields") is True:
            checks.append({"status": "breaking", "code": "provider_rejects_consumer_request_field", "detail": ",".join(sorted(extra_sent))})
        else:
            checks.append({"status": "unknown", "code": "provider_request_field_acceptance_unknown", "detail": ",".join(sorted(extra_sent))})
    for field in sorted(consumer_fields & provider_fields):
        consumer_type = _field_type(consumer_request.get("body_schema"), field)
        provider_type = _field_type(provider_request.get("body_schema"), field)
        if consumer_type is None or provider_type is None:
            checks.append({"status": "unknown", "code": "request_field_type_unknown", "detail": field})
        elif consumer_type != provider_type:
            checks.append({"status": "breaking", "code": "request_field_type_incompatible", "detail": field})
    return checks


def _response_checks(consumer: dict[str, object], provider: dict[str, object]) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    consumer_response = _as_dict(consumer.get("response"))
    provider_response = _as_dict(provider.get("response"))
    required_fields = _strings(consumer_response.get("fields_used_by_consumer")) or _strings(consumer_response.get("required_fields"))
    provider_fields = _strings(provider_response.get("fields"))
    if not required_fields:
        checks.append({"status": "unknown", "code": "consumer_response_requirements_unknown", "detail": "no consumed response requirements were demonstrated"})
    if not provider_fields and provider_response.get("schema") is None:
        checks.append({"status": "unknown", "code": "provider_response_schema_unknown", "detail": "provider response schema missing"})
    for field in sorted(required_fields - provider_fields):
        checks.append({"status": "breaking", "code": "provider_missing_required_response_field", "detail": field})
    extra_provider_fields = provider_fields - required_fields
    if extra_provider_fields and required_fields:
        if consumer_response.get("tolerates_additional_fields") is True:
            checks.append({"status": "compatible", "code": "consumer_tolerates_additional_response_fields", "detail": ",".join(sorted(extra_provider_fields))})
        elif consumer_response.get("tolerates_additional_fields") is False:
            checks.append({"status": "breaking", "code": "consumer_rejects_additional_response_fields", "detail": ",".join(sorted(extra_provider_fields))})
        else:
            checks.append({"status": "unknown", "code": "consumer_response_field_tolerance_unknown", "detail": ",".join(sorted(extra_provider_fields))})
    for field in sorted(required_fields & provider_fields):
        consumer_type = _field_type(consumer_response.get("schema"), field)
        provider_type = _field_type(provider_response.get("schema"), field)
        if consumer_type is None or provider_type is None:
            checks.append({"status": "unknown", "code": "response_field_type_unknown", "detail": field})
        elif consumer_type != provider_type:
            checks.append({"status": "breaking", "code": "response_field_type_incompatible", "detail": field})
    consumer_statuses = {code for code in _as_list(consumer_response.get("status_codes")) if isinstance(code, int)}
    provider_statuses = {code for code in _as_list(provider_response.get("status_codes")) if isinstance(code, int)}
    if not consumer_statuses:
        checks.append({"status": "unknown", "code": "consumer_status_codes_unknown", "detail": "consumer status expectations missing"})
    if not provider_statuses:
        checks.append({"status": "unknown", "code": "provider_status_codes_unknown", "detail": "provider status evidence missing"})
    for code in sorted(consumer_statuses - provider_statuses):
        checks.append({"status": "breaking", "code": "provider_missing_required_status_code", "detail": str(code)})
    extra_statuses = provider_statuses - consumer_statuses
    if extra_statuses:
        if consumer_response.get("tolerates_additional_statuses") is True:
            checks.append({"status": "compatible", "code": "consumer_tolerates_additional_status_codes", "detail": ",".join(str(code) for code in sorted(extra_statuses))})
        elif consumer_response.get("tolerates_additional_statuses") is False:
            checks.append({"status": "breaking", "code": "consumer_rejects_additional_status_codes", "detail": ",".join(str(code) for code in sorted(extra_statuses))})
        else:
            checks.append({"status": "unknown", "code": "consumer_status_code_tolerance_unknown", "detail": ",".join(str(code) for code in sorted(extra_statuses))})
    return checks


def _parameter_checks(consumer: dict[str, object], provider: dict[str, object]) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    consumer_params = {
        (str(item.get("location")), str(item.get("name"))): item
        for item in _as_list(consumer.get("parameters"))
        if isinstance(item, dict)
    }
    for source, parameters in (("consumer", consumer.get("parameters")), ("provider", provider.get("parameters"))):
        for item in _as_list(parameters):
            if not isinstance(item, dict):
                continue
            detail = f"{item.get('location')}:{item.get('name')}"
            if item.get("required") is None:
                checks.append({"status": "unknown", "code": f"{source}_parameter_requiredness_unknown", "detail": detail})
            if item.get("schema") is None:
                checks.append({"status": "unknown", "code": f"{source}_parameter_type_unknown", "detail": detail})
    for item in _as_list(provider.get("parameters")):
        if not isinstance(item, dict) or item.get("required") is not True:
            continue
        key = (str(item.get("location")), str(item.get("name")))
        if key not in consumer_params:
            checks.append({"status": "breaking", "code": "provider_requires_unsent_parameter", "detail": f"{key[0]}:{key[1]}"})
    return checks


def _content_type_checks(consumer: dict[str, object], provider: dict[str, object]) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    consumer_request = _as_dict(consumer.get("request"))
    provider_request = _as_dict(provider.get("request"))
    consumer_response = _as_dict(consumer.get("response"))
    provider_response = _as_dict(provider.get("response"))
    consumer_type = consumer_request.get("content_type")
    provider_type = provider_request.get("content_type")
    if consumer_type and provider_type and consumer_type != provider_type:
        checks.append({"status": "breaking", "code": "request_content_type_incompatible", "detail": f"{consumer_type} != {provider_type}"})
    elif consumer_type is None or provider_type is None:
        checks.append({"status": "unknown", "code": "request_content_type_unknown", "detail": "missing content type evidence"})
    consumer_response_type = consumer_response.get("content_type")
    provider_response_type = provider_response.get("content_type")
    if consumer_response_type and provider_response_type and consumer_response_type != provider_response_type:
        checks.append({"status": "breaking", "code": "response_content_type_incompatible", "detail": f"{consumer_response_type} != {provider_response_type}"})
    elif consumer_response_type is None or provider_response_type is None:
        checks.append({"status": "unknown", "code": "response_content_type_unknown", "detail": "missing response content type evidence"})
    return checks


def _auth_checks(consumer: dict[str, object], provider: dict[str, object], *, enforce_security_policy: bool) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    consumer_auth = _as_dict(consumer.get("authentication"))
    provider_auth = _as_dict(provider.get("authentication"))
    consumer_has_auth = consumer_auth.get("required") is True or bool(consumer_auth.get("authentication"))
    provider_requires = provider_auth.get("required")
    if provider_requires is True and not consumer_has_auth:
        checks.append({"status": "breaking", "code": "provider_requires_authentication_not_sent_by_consumer", "detail": "authentication"})
    elif provider_requires is None:
        checks.append({"status": "unknown", "code": "provider_authentication_requiredness_unknown", "detail": "authentication"})
    elif provider_requires is False and consumer_has_auth and enforce_security_policy:
        checks.append({"status": "breaking", "code": "security_policy_drift_weaker_provider_authentication", "detail": "authentication"})
    elif provider_requires is False and consumer_has_auth:
        checks.append({"status": "compatible", "code": "security_policy_drift_weaker_provider_authentication", "detail": "reported separately"})
    return checks


def _record_status(checks: list[dict[str, object]]) -> str:
    statuses = {str(item.get("status")) for item in checks}
    if "breaking" in statuses:
        return "breaking"
    if "unknown" in statuses:
        return "unknown"
    return "compatible"


def _compatibility_record(
    consumer: dict[str, object],
    providers: list[dict[str, object]],
    *,
    enforce_security_policy: bool,
) -> dict[str, object]:
    if not providers:
        return {
            "consumer_endpoint_id": consumer["endpoint_id"],
            "provider_endpoint_id": None,
            "method": consumer["method"],
            "path_shape": consumer["path_shape"],
            "status": "missing",
            "required": True,
            "checks": [{"status": "breaking", "code": "provider_missing", "detail": "no provider endpoint matched method/path_shape"}],
            "evidence": _as_list(consumer.get("evidence")),
        }
    if len(providers) > 1:
        return {
            "consumer_endpoint_id": consumer["endpoint_id"],
            "provider_endpoint_id": None,
            "method": consumer["method"],
            "path_shape": consumer["path_shape"],
            "status": "ambiguous",
            "required": True,
            "checks": [{"status": "unknown", "code": "provider_ambiguous", "detail": ",".join(str(item.get("endpoint_id")) for item in providers)}],
            "evidence": _as_list(consumer.get("evidence")),
        }
    provider = providers[0]
    checks = (
        _parameter_checks(consumer, provider)
        + _content_type_checks(consumer, provider)
        + _request_checks(consumer, provider)
        + _response_checks(consumer, provider)
        + _auth_checks(consumer, provider, enforce_security_policy=enforce_security_policy)
    )
    return {
        "consumer_endpoint_id": consumer["endpoint_id"],
        "provider_endpoint_id": provider["endpoint_id"],
        "method": consumer["method"],
        "path_shape": consumer["path_shape"],
        "status": _record_status(checks),
        "required": True,
        "checks": checks,
        "evidence": _as_list(consumer.get("evidence")) + _as_list(provider.get("evidence")),
    }


def _gate_status(records: list[dict[str, object]], mode: GateMode) -> str:
    if mode == "report":
        return "passed"
    has_breaking = any(item["status"] in {"breaking", "missing"} for item in records)
    has_unknown = any(item["status"] in {"unknown", "ambiguous"} for item in records)
    if mode == "fail_on_breaking":
        return "failed" if has_breaking else "passed"
    return "failed" if has_breaking or has_unknown else "passed"


def build_consumer_compatibility(
    consumer_catalog_paths: list[Path],
    provider_catalog_paths: list[Path],
    *,
    gate_mode: GateMode = "fail_closed",
    include_endpoints: tuple[str, ...] = (),
    exclude_endpoints: tuple[str, ...] = (),
    enforce_security_policy: bool = False,
) -> dict[str, object]:
    consumers = [load_catalog(path) for path in consumer_catalog_paths]
    providers = [load_catalog(path) for path in provider_catalog_paths]
    consumed = [
        endpoint
        for snapshot in consumers
        for endpoint in _as_list(snapshot.payload.get("endpoints"))
        if isinstance(endpoint, dict) and endpoint.get("direction") == "consumed"
    ]
    exposed = [
        endpoint
        for snapshot in providers
        for endpoint in _as_list(snapshot.payload.get("endpoints"))
        if isinstance(endpoint, dict) and endpoint.get("direction") == "exposed"
    ]
    required_consumed, excluded_consumed = _scope(
        consumed,
        include=include_endpoints,
        exclude=exclude_endpoints,
    )
    provider_index = _provider_index(exposed)
    records = [
        _compatibility_record(
            consumer,
            provider_index.get((str(consumer.get("method")), str(consumer.get("path_shape"))), []),
            enforce_security_policy=enforce_security_policy,
        )
        for consumer in required_consumed
    ]
    records.sort(key=lambda item: (str(item["method"]), str(item["path_shape"]), str(item["status"])))
    summary = {
        "compatible": sum(1 for item in records if item["status"] == "compatible"),
        "breaking": sum(1 for item in records if item["status"] == "breaking"),
        "missing": sum(1 for item in records if item["status"] == "missing"),
        "ambiguous": sum(1 for item in records if item["status"] == "ambiguous"),
        "unknown": sum(1 for item in records if item["status"] == "unknown"),
        "security_drift": sum(
            1
            for item in records
            for check in _as_list(item.get("checks"))
            if isinstance(check, dict) and str(check.get("code")).startswith("security_policy_drift")
        ),
        "required_dependencies": len(required_consumed),
        "excluded_dependencies": len(excluded_consumed),
    }
    payload = {
        "schema_version": CONSUMER_COMPATIBILITY_SCHEMA_VERSION,
        "compatibility_id": _digest(
            "consumer-compatibility",
            {
                "consumers": [item.payload["catalog_id"] for item in consumers],
                "providers": [item.payload["catalog_id"] for item in providers],
                "gate_mode": gate_mode,
                "include": include_endpoints,
                "exclude": exclude_endpoints,
            },
        ),
        "auditor_version": __version__,
        "generated_at": datetime.now(UTC).isoformat(),
        "mode": "provider_consumer",
        "inputs": {
            "consumer_catalog_ids": [item.payload["catalog_id"] for item in consumers],
            "provider_catalog_ids": [item.payload["catalog_id"] for item in providers],
        },
        "scope": {
            "include_endpoints": list(include_endpoints),
            "exclude_endpoints": list(exclude_endpoints),
            "required_rule": "all_consumed_endpoints_in_scope",
            "excluded_dependencies": [
                {"endpoint_id": item["endpoint_id"], "method": item["method"], "path_shape": item["path_shape"]}
                for item in excluded_consumed
            ],
        },
        "summary": summary,
        "gate": {"mode": gate_mode, "status": _gate_status(records, gate_mode)},
        "records": records,
    }
    _validate(payload, "consumer-compatibility.schema.json", "consumer-compatibility.json")
    return payload


def render_consumer_compatibility_markdown(payload: dict[str, object]) -> str:
    summary = _as_dict(payload.get("summary"))
    gate = _as_dict(payload.get("gate"))
    lines = [
        "# Provider Consumer Compatibility",
        "",
        f"- Gate: {gate.get('mode')} -> {gate.get('status')}",
        f"- compatible: {summary.get('compatible', 0)}",
        f"- breaking: {summary.get('breaking', 0)}",
        f"- missing: {summary.get('missing', 0)}",
        f"- ambiguous: {summary.get('ambiguous', 0)}",
        f"- unknown: {summary.get('unknown', 0)}",
        f"- security drift: {summary.get('security_drift', 0)}",
        "",
        "## Dependencies",
    ]
    for record in _as_list(payload.get("records")):
        if not isinstance(record, dict):
            continue
        lines.append(f"- {record.get('status')} {record.get('method')} {record.get('path_shape')}")
        for check in _as_list(record.get("checks")):
            if isinstance(check, dict):
                lines.append(f"  - {check.get('code')}: {check.get('detail')}")
    return "\n".join(lines) + "\n"


def validate_consumer_compatibility_set(directory: Path) -> dict[str, str]:
    json_path = directory / "consumer-compatibility.json"
    markdown_path = directory / "consumer-compatibility.md"
    missing = [path.name for path in (json_path, markdown_path) if not path.is_file()]
    if missing:
        raise ConsumerCompatibilityError(
            f"Missing consumer compatibility artifacts: {', '.join(missing)}"
        )
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ConsumerCompatibilityError("consumer-compatibility.json must be a JSON object")
    _validate(payload, "consumer-compatibility.schema.json", str(json_path))
    for path in (json_path, markdown_path):
        if contains_unredacted_secret_like_value(path.read_text(encoding="utf-8", errors="replace")):
            raise ConsumerCompatibilityError(f"Potential unredacted secret in {path.name}")
    return {
        "consumer-compatibility.json": hashlib.sha256(json_path.read_bytes()).hexdigest(),
        "consumer-compatibility.md": hashlib.sha256(markdown_path.read_bytes()).hexdigest(),
    }


def _atomic_publish(staging_dir: Path, destination: Path) -> None:
    validate_consumer_compatibility_set(staging_dir)
    destination.parent.mkdir(parents=True, exist_ok=True)
    token = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
    candidate = destination.parent / f".{destination.name}.new-{token}"
    backup = destination.parent / f".{destination.name}.previous-{token}"
    shutil.copytree(staging_dir, candidate)
    moved_previous = False
    try:
        if destination.exists():
            os.replace(destination, backup)
            moved_previous = True
        os.replace(candidate, destination)
        if moved_previous:
            shutil.rmtree(backup)
    except Exception:
        if candidate.exists():
            shutil.rmtree(candidate, ignore_errors=True)
        if moved_previous and backup.exists() and not destination.exists():
            os.replace(backup, destination)
        raise


def write_consumer_compatibility(
    consumer_catalog_paths: list[Path],
    provider_catalog_paths: list[Path],
    output: Path,
    *,
    gate_mode: GateMode = "fail_closed",
    include_endpoints: tuple[str, ...] = (),
    exclude_endpoints: tuple[str, ...] = (),
    enforce_security_policy: bool = False,
) -> tuple[Path, dict[str, object]]:
    payload = build_consumer_compatibility(
        consumer_catalog_paths,
        provider_catalog_paths,
        gate_mode=gate_mode,
        include_endpoints=include_endpoints,
        exclude_endpoints=exclude_endpoints,
        enforce_security_policy=enforce_security_policy,
    )
    destination = output.resolve()
    with tempfile.TemporaryDirectory(prefix="asgard-consumer-compatibility-") as tmp:
        staging = Path(tmp)
        json_text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        markdown = render_consumer_compatibility_markdown(payload)
        for name, text in (("consumer-compatibility.json", json_text), ("consumer-compatibility.md", markdown)):
            if contains_unredacted_secret_like_value(text):
                raise ConsumerCompatibilityError(f"Potential unredacted secret in {name}")
            (staging / name).write_text(redact_text(text), encoding="utf-8", newline="\n")
        validate_consumer_compatibility_set(staging)
        _atomic_publish(staging, destination)
    return destination, payload
