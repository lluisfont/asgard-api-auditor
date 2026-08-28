"""Reference/candidate API catalog compatibility checks."""

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
from typing import Literal

from . import __version__
from .constants import API_CATALOG_SCHEMA_VERSION, API_COMPATIBILITY_SCHEMA_VERSION
from .redaction import contains_unredacted_secret_like_value, redact_text
from .schema_validation import SchemaValidationError, validate_json_schema

SCHEMAS_PACKAGE = "asgard_api_auditor.schemas"
GateMode = Literal["report", "fail_on_breaking", "fail_closed"]
ORDER_INSENSITIVE_KEYS = {
    "endpoints",
    "evidence",
    "fields",
    "required_fields",
    "optional_fields",
    "unknown_requiredness_fields",
    "status_codes",
    "parameters",
    "headers",
    "unresolved",
    "notes",
}
VOLATILE_CATALOG_KEYS = {
    "catalog_id",
    "generated_at",
    "input_hashes",
}


class ApiCompatibilityError(ValueError):
    """Raised when API compatibility cannot be evaluated safely."""


@dataclass(frozen=True)
class CatalogSnapshot:
    path: Path
    payload: dict[str, object]


def _schema(name: str) -> dict[str, object]:
    try:
        payload = json.loads(
            resources.files(SCHEMAS_PACKAGE).joinpath(name).read_text(encoding="utf-8")
        )
    except (FileNotFoundError, ModuleNotFoundError, OSError, json.JSONDecodeError) as exc:
        raise ApiCompatibilityError(f"Unable to read packaged JSON schema {name}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ApiCompatibilityError(f"Packaged JSON schema {name} must be an object")
    return payload


def _validate(payload: dict[str, object], schema_name: str, source: str) -> None:
    try:
        validate_json_schema(payload, _schema(schema_name), source=source)
    except SchemaValidationError as exc:
        raise ApiCompatibilityError(str(exc)) from exc


def load_catalog(path: Path) -> CatalogSnapshot:
    resolved = path.resolve()
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ApiCompatibilityError(f"Unable to read API catalog {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ApiCompatibilityError(f"{path}: API catalog must be a JSON object")
    _validate(payload, "api-catalog.schema.json", str(path))
    if payload.get("schema_version") != API_CATALOG_SCHEMA_VERSION:
        raise ApiCompatibilityError(
            f"{path}: unsupported api catalog schema_version {payload.get('schema_version')!r}"
        )
    return CatalogSnapshot(resolved, payload)


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


def _canonical_artifact(payload: dict[str, object]) -> object:
    def normalize(value: object, key: str | None = None) -> object:
        if isinstance(value, dict):
            normalized: dict[str, object] = {}
            for child_key, child_value in value.items():
                if child_key in VOLATILE_CATALOG_KEYS:
                    continue
                if child_key == "metadata":
                    if not isinstance(child_value, dict):
                        continue
                    child = {
                        metadata_key: metadata_value
                        for metadata_key, metadata_value in child_value.items()
                        if metadata_key
                        not in {
                            "findings_audit_id",
                            "findings_sha256",
                            "source_ref",
                            "source_commit",
                        }
                    }
                    normalized[child_key] = normalize(child, child_key)
                    continue
                normalized[child_key] = normalize(child_value, child_key)
            return {child_key: normalized[child_key] for child_key in sorted(normalized)}
        if isinstance(value, list):
            normalized_list = [normalize(item) for item in value]
            if key == "endpoints":
                return sorted(
                    normalized_list,
                    key=lambda item: (
                        str(item.get("endpoint_id")) if isinstance(item, dict) else "",
                        _canonical_json(item),
                    ),
                )
            if key in ORDER_INSENSITIVE_KEYS:
                return sorted(normalized_list, key=_canonical_json)
            return normalized_list
        return value

    return normalize(payload)


def artifact_equal(reference: dict[str, object], candidate: dict[str, object]) -> bool:
    """Compare catalog artifacts after removing volatile metadata."""

    return _canonical_json(_canonical_artifact(reference)) == _canonical_json(
        _canonical_artifact(candidate)
    )


def _canonical_endpoint(endpoint: dict[str, object]) -> object:
    return _canonical_artifact({"endpoint": endpoint})["endpoint"]  # type: ignore[index]


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


def _scoped(
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


def _material_unknown(endpoint: dict[str, object]) -> list[str]:
    reasons: list[str] = []
    request = _as_dict(endpoint.get("request"))
    response = _as_dict(endpoint.get("response"))
    auth = _as_dict(endpoint.get("authentication"))
    if endpoint.get("contract_status") in {None, "unknown", "partial", "required_not_complete"}:
        reasons.append("contract_status")
    if endpoint.get("semantic_status") in {None, "unknown", "partial", "unresolved"}:
        reasons.append("semantic_status")
    if _strings(request.get("unknown_requiredness_fields")):
        reasons.append("request_requiredness")
    if request.get("fields") and request.get("body_schema") is None:
        reasons.append("request")
    if request.get("fields") and request.get("content_type") is None:
        reasons.append("request_content_type")
    if not response.get("status_codes") or response.get("schema") is None:
        reasons.append("response")
    if response.get("fields") and response.get("content_type") is None:
        reasons.append("response_content_type")
    if auth.get("required") is None:
        reasons.append("authentication")
    for parameter in _as_list(endpoint.get("parameters")):
        if not isinstance(parameter, dict):
            continue
        if parameter.get("required") is None:
            reasons.append(f"{parameter.get('location')}_parameter_requiredness")
        if parameter.get("schema") is None:
            reasons.append(f"{parameter.get('location')}_parameter_type")
    if endpoint.get("semantic_status") == "complete":
        behavior = _as_dict(endpoint.get("behavior"))
        if behavior.get("summary") is None and not any(
            behavior.get(key)
            for key in ("data_access", "local_calls", "outbound_integrations", "conditions", "side_effects")
        ):
            reasons.append("behavior")
    if _as_list(endpoint.get("unresolved")) or _as_list(request.get("unresolved")) or _as_list(response.get("unresolved")):
        reasons.append("unresolved")
    return sorted(set(reasons))


def _field_type(schema: object, field: str) -> object:
    properties = _as_dict(_as_dict(schema).get("properties"))
    field_schema = _as_dict(properties.get(field))
    return field_schema.get("type") or field_schema.get("format")


def _compare_request(reference: dict[str, object], candidate: dict[str, object]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    reference_request = _as_dict(reference.get("request"))
    candidate_request = _as_dict(candidate.get("request"))
    reference_fields = _strings(reference_request.get("fields"))
    candidate_fields = _strings(candidate_request.get("fields"))
    reference_required = _strings(reference_request.get("required_fields"))
    candidate_required = _strings(candidate_request.get("required_fields"))
    removed_required = sorted(reference_required - candidate_fields)
    added_required = sorted(candidate_required - reference_fields)
    for field in removed_required:
        findings.append({"classification": "breaking", "code": "required_request_field_removed", "detail": field})
    for field in added_required:
        findings.append({"classification": "breaking", "code": "required_request_field_added", "detail": field})
    for field in sorted(_strings(reference_request.get("unknown_requiredness_fields")) | _strings(candidate_request.get("unknown_requiredness_fields"))):
        findings.append({"classification": "unknown", "code": "request_field_requiredness_unknown", "detail": field})
    for field in sorted(reference_fields & candidate_fields):
        before = _field_type(reference_request.get("body_schema"), field)
        after = _field_type(candidate_request.get("body_schema"), field)
        if before is not None and after is not None and before != after:
            findings.append({"classification": "breaking", "code": "request_field_type_changed", "detail": field})
    before_type = reference_request.get("content_type")
    after_type = candidate_request.get("content_type")
    if before_type and after_type and before_type != after_type:
        findings.append({"classification": "breaking", "code": "request_content_type_incompatible", "detail": f"{before_type} != {after_type}"})
    elif (reference_fields or candidate_fields) and (before_type is None or after_type is None):
        findings.append({"classification": "unknown", "code": "request_content_type_unknown", "detail": "missing request content type evidence"})
    return findings


def _compare_response(reference: dict[str, object], candidate: dict[str, object]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    reference_response = _as_dict(reference.get("response"))
    candidate_response = _as_dict(candidate.get("response"))
    reference_fields = _strings(reference_response.get("fields"))
    candidate_fields = _strings(candidate_response.get("fields"))
    for field in sorted(reference_fields - candidate_fields):
        findings.append({"classification": "breaking", "code": "response_field_removed", "detail": field})
    for field in sorted(reference_fields & candidate_fields):
        before = _field_type(reference_response.get("schema"), field)
        after = _field_type(candidate_response.get("schema"), field)
        if before is not None and after is not None and before != after:
            findings.append({"classification": "breaking", "code": "response_field_type_changed", "detail": field})
    before_statuses = {code for code in _as_list(reference_response.get("status_codes")) if isinstance(code, int)}
    after_statuses = {code for code in _as_list(candidate_response.get("status_codes")) if isinstance(code, int)}
    for code in sorted(before_statuses - after_statuses):
        findings.append({"classification": "breaking", "code": "response_status_removed", "detail": str(code)})
    compatibility = _as_dict(candidate_response.get("status_code_compatibility"))
    for code in sorted(after_statuses - before_statuses):
        status = compatibility.get(str(code)) or compatibility.get(code)
        if status == "breaking":
            findings.append({"classification": "breaking", "code": "response_status_added_breaking", "detail": str(code)})
        elif status == "compatible":
            findings.append({"classification": "additive", "code": "response_status_added_compatible", "detail": str(code)})
        else:
            findings.append({"classification": "unknown", "code": "response_status_added_unknown", "detail": str(code)})
    if candidate_fields - reference_fields:
        findings.append({
            "classification": "additive",
            "code": "response_fields_added",
            "detail": ",".join(sorted(candidate_fields - reference_fields)),
        })
    before_type = reference_response.get("content_type")
    after_type = candidate_response.get("content_type")
    if before_type and after_type and before_type != after_type:
        findings.append({"classification": "breaking", "code": "response_content_type_incompatible", "detail": f"{before_type} != {after_type}"})
    elif (reference_response.get("schema") is not None or candidate_response.get("schema") is not None) and (before_type is None or after_type is None):
        findings.append({"classification": "unknown", "code": "response_content_type_unknown", "detail": "missing response content type evidence"})
    return findings


def _parameter_key(parameter: dict[str, object]) -> tuple[str, str]:
    return (str(parameter.get("location")), str(parameter.get("name")))


def _parameter_type(parameter: dict[str, object]) -> object:
    schema = _as_dict(parameter.get("schema"))
    return schema.get("type") or schema.get("format")


def _parameter_label(key: tuple[str, str]) -> str:
    return f"{key[0]}:{key[1]}"


def _compare_parameters(reference: dict[str, object], candidate: dict[str, object]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    reference_params = {
        _parameter_key(item): item
        for item in _as_list(reference.get("parameters"))
        if isinstance(item, dict)
    }
    candidate_params = {
        _parameter_key(item): item
        for item in _as_list(candidate.get("parameters"))
        if isinstance(item, dict)
    }
    for key, parameter in sorted(reference_params.items()):
        if key not in candidate_params:
            code = "path_parameter_removed" if key[0] == "path" else "parameter_removed"
            findings.append({"classification": "breaking", "code": code, "detail": _parameter_label(key)})
            continue
        candidate_parameter = candidate_params[key]
        before_required = parameter.get("required")
        after_required = candidate_parameter.get("required")
        if before_required is None or after_required is None:
            findings.append({"classification": "unknown", "code": "parameter_requiredness_unknown", "detail": _parameter_label(key)})
        elif before_required is False and after_required is True:
            findings.append({"classification": "breaking", "code": "parameter_requiredness_became_stricter", "detail": _parameter_label(key)})
        before_type = _parameter_type(parameter)
        after_type = _parameter_type(candidate_parameter)
        if before_type is None or after_type is None:
            findings.append({"classification": "unknown", "code": "parameter_type_unknown", "detail": _parameter_label(key)})
        elif before_type != after_type:
            code = "path_parameter_incompatible_type" if key[0] == "path" else "parameter_incompatible_type"
            findings.append({"classification": "breaking", "code": code, "detail": _parameter_label(key)})
    for key, parameter in sorted(candidate_params.items()):
        if key in reference_params:
            continue
        required = parameter.get("required")
        if required is True:
            code = "required_header_added" if key[0] == "header" else "required_parameter_added"
            findings.append({"classification": "breaking", "code": code, "detail": _parameter_label(key)})
        elif required is False:
            code = "optional_query_parameter_added" if key[0] == "query" else "optional_parameter_added"
            findings.append({"classification": "additive", "code": code, "detail": _parameter_label(key)})
        else:
            code = "header_compatibility_unknown" if key[0] == "header" else "parameter_requiredness_unknown"
            findings.append({"classification": "unknown", "code": code, "detail": _parameter_label(key)})
    return findings


def _material_behavior(endpoint: dict[str, object]) -> dict[str, object]:
    behavior = _as_dict(endpoint.get("behavior"))
    return {
        "data_access": behavior.get("data_access") or [],
        "local_calls": behavior.get("local_calls") or [],
        "outbound_integrations": behavior.get("outbound_integrations") or [],
        "side_effects": behavior.get("side_effects") or [],
        "response_semantics": behavior.get("response_semantics") or {},
    }


def _compare_behavior(reference: dict[str, object], candidate: dict[str, object]) -> list[dict[str, object]]:
    if reference.get("semantic_status") in {"unknown", "partial", "unresolved"} or candidate.get("semantic_status") in {"unknown", "partial", "unresolved"}:
        return [{"classification": "unknown", "code": "semantic_behavior_unknown", "detail": "material behavior is not fully reconstructed"}]
    if _material_behavior(reference) != _material_behavior(candidate):
        return [{"classification": "breaking", "code": "semantic_behavior_incompatible", "detail": "demonstrated behavior facts differ"}]
    return []


def _auth_strength(auth: dict[str, object]) -> int:
    required = auth.get("required")
    if required is True:
        return 2
    if required is False:
        return 0
    return 1


def _compare_auth(reference: dict[str, object], candidate: dict[str, object], *, enforce_security_policy: bool) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    before = _auth_strength(_as_dict(reference.get("authentication")))
    after = _auth_strength(_as_dict(candidate.get("authentication")))
    if after > before:
        findings.append({"classification": "breaking", "code": "authentication_stricter", "detail": "candidate requires stronger authentication"})
    elif after < before:
        classification = "breaking" if enforce_security_policy else "same"
        findings.append({"classification": classification, "code": "security_policy_drift_weaker_authentication", "detail": "candidate is less strict"})
    return findings


def _observable(endpoint: dict[str, object]) -> dict[str, object]:
    return {
        "stable_identity": endpoint.get("stable_identity"),
        "method": endpoint.get("method"),
        "path_shape": endpoint.get("path_shape"),
        "parameters": endpoint.get("parameters"),
        "request": endpoint.get("request"),
        "response": endpoint.get("response"),
        "headers": endpoint.get("headers"),
        "authentication": endpoint.get("authentication"),
        "security": endpoint.get("security"),
        "behavior": endpoint.get("behavior"),
        "contract_status": endpoint.get("contract_status"),
        "semantic_status": endpoint.get("semantic_status"),
        "unresolved": endpoint.get("unresolved"),
    }


def _classification(findings: list[dict[str, object]], unknown_reasons: list[str]) -> str:
    if any(item["classification"] == "breaking" for item in findings):
        return "breaking"
    if unknown_reasons or any(item["classification"] == "unknown" for item in findings):
        return "unknown"
    if any(item["classification"] == "additive" for item in findings):
        return "additive"
    return "same"


def _compare_endpoint(reference: dict[str, object], candidate: dict[str, object], *, enforce_security_policy: bool) -> dict[str, object]:
    findings = (
        _compare_parameters(reference, candidate)
        + _compare_request(reference, candidate)
        + _compare_response(reference, candidate)
        + _compare_auth(reference, candidate, enforce_security_policy=enforce_security_policy)
        + _compare_behavior(reference, candidate)
    )
    unknown_reasons = _material_unknown(reference) + _material_unknown(candidate)
    observed_equal = _observable(reference) == _observable(candidate)
    endpoint_artifact_equal = _canonical_endpoint(reference) == _canonical_endpoint(candidate)
    classification = _classification(findings, unknown_reasons)
    return {
        "reference_endpoint_id": reference["endpoint_id"],
        "candidate_endpoint_id": candidate["endpoint_id"],
        "method": reference["method"],
        "path_shape": reference["path_shape"],
        "classification": classification,
        "observed_equal": observed_equal,
        "artifact_equal": endpoint_artifact_equal,
        "required": True,
        "findings": findings,
        "unknown_reasons": sorted(set(unknown_reasons)),
        "evidence": _as_list(reference.get("evidence")) + _as_list(candidate.get("evidence")),
    }


def _unique_endpoint_index(
    endpoints: list[dict[str, object]], *, catalog_role: str
) -> dict[tuple[str, str, str], list[dict[str, object]]]:
    indexed: dict[tuple[str, str, str], list[dict[str, object]]] = {}
    for endpoint in endpoints:
        key = (
            str(endpoint.get("direction")),
            str(endpoint.get("method")),
            str(endpoint.get("path_shape")),
        )
        indexed.setdefault(key, []).append(endpoint)
    duplicates = {
        key: values
        for key, values in indexed.items()
        if len(values) > 1
    }
    if duplicates:
        labels = ", ".join(f"{key[0]} {key[1]} {key[2]}" for key in sorted(duplicates))
        raise ApiCompatibilityError(f"{catalog_role} catalog contains duplicate stable identity: {labels}")
    return indexed


def _gate_status(records: list[dict[str, object]], mode: GateMode) -> str:
    if mode == "report":
        return "passed"
    has_breaking = any(item["classification"] == "breaking" for item in records)
    has_unknown = any(item["classification"] == "unknown" for item in records)
    if mode == "fail_on_breaking":
        return "failed" if has_breaking else "passed"
    return "failed" if has_breaking or has_unknown else "passed"


def build_api_compatibility(
    reference_catalog_path: Path,
    candidate_catalog_path: Path,
    *,
    gate_mode: GateMode = "report",
    include_endpoints: tuple[str, ...] = (),
    exclude_endpoints: tuple[str, ...] = (),
    enforce_security_policy: bool = False,
) -> dict[str, object]:
    reference = load_catalog(reference_catalog_path)
    candidate = load_catalog(candidate_catalog_path)
    reference_endpoints = [
        item for item in _as_list(reference.payload.get("endpoints")) if isinstance(item, dict)
    ]
    candidate_endpoints = [
        item for item in _as_list(candidate.payload.get("endpoints")) if isinstance(item, dict)
    ]
    required_reference, excluded_reference = _scoped(
        reference_endpoints,
        include=include_endpoints,
        exclude=exclude_endpoints,
    )
    _unique_endpoint_index(reference_endpoints, catalog_role="Reference")
    candidates = _unique_endpoint_index(candidate_endpoints, catalog_role="Candidate")
    records: list[dict[str, object]] = []
    matched_candidate_ids: set[str] = set()
    for endpoint in required_reference:
        key = (
            str(endpoint.get("direction")),
            str(endpoint.get("method")),
            str(endpoint.get("path_shape")),
        )
        matches = candidates.get(key, [])
        if not matches:
            records.append({
                "reference_endpoint_id": endpoint["endpoint_id"],
                "candidate_endpoint_id": None,
                "method": endpoint["method"],
                "path_shape": endpoint["path_shape"],
                "classification": "breaking",
                "observed_equal": False,
                "artifact_equal": False,
                "required": True,
                "findings": [{"classification": "breaking", "code": "endpoint_removed", "detail": "required reference endpoint missing from candidate"}],
                "unknown_reasons": [],
                "evidence": _as_list(endpoint.get("evidence")),
            })
            continue
        match = matches[0]
        matched_candidate_ids.add(str(match["endpoint_id"]))
        records.append(
            _compare_endpoint(endpoint, match, enforce_security_policy=enforce_security_policy)
        )
    for endpoint in candidate_endpoints:
        if str(endpoint.get("endpoint_id")) not in matched_candidate_ids:
            records.append({
                "reference_endpoint_id": None,
                "candidate_endpoint_id": endpoint["endpoint_id"],
                "method": endpoint["method"],
                "path_shape": endpoint["path_shape"],
                "classification": "additive",
                "observed_equal": False,
                "artifact_equal": False,
                "required": False,
                "findings": [{"classification": "additive", "code": "endpoint_added", "detail": "candidate exposes an additional endpoint"}],
                "unknown_reasons": [],
                "evidence": _as_list(endpoint.get("evidence")),
            })
    records.sort(key=lambda item: (str(item["method"]), str(item["path_shape"]), str(item["classification"])))
    summary = {
        "same": sum(1 for item in records if item["classification"] == "same"),
        "additive": sum(1 for item in records if item["classification"] == "additive"),
        "breaking": sum(1 for item in records if item["classification"] == "breaking"),
        "unknown": sum(1 for item in records if item["classification"] == "unknown"),
        "required_reference_endpoints": len(required_reference),
        "excluded_reference_endpoints": len(excluded_reference),
    }
    payload = {
        "schema_version": API_COMPATIBILITY_SCHEMA_VERSION,
        "comparison_id": _digest(
            "api-compatibility",
            {
                "reference": reference.payload["catalog_id"],
                "candidate": candidate.payload["catalog_id"],
                "gate_mode": gate_mode,
                "include": include_endpoints,
                "exclude": exclude_endpoints,
            },
        ),
        "auditor_version": __version__,
        "generated_at": datetime.now(UTC).isoformat(),
        "mode": "reference_candidate",
        "artifact_equal": artifact_equal(reference.payload, candidate.payload),
        "artifact_canonicalization": {
            "volatile_metadata": sorted(VOLATILE_CATALOG_KEYS),
            "order_insensitive_arrays": sorted(ORDER_INSENSITIVE_KEYS),
            "endpoint_order": "endpoint_id",
        },
        "inputs": {
            "reference_catalog_id": reference.payload["catalog_id"],
            "candidate_catalog_id": candidate.payload["catalog_id"],
        },
        "scope": {
            "include_endpoints": list(include_endpoints),
            "exclude_endpoints": list(exclude_endpoints),
            "required_rule": "all_reference_endpoints_in_scope",
            "excluded_reference_endpoints": [
                {"endpoint_id": item["endpoint_id"], "method": item["method"], "path_shape": item["path_shape"]}
                for item in excluded_reference
            ],
        },
        "summary": summary,
        "gate": {"mode": gate_mode, "status": _gate_status(records, gate_mode)},
        "records": records,
    }
    _validate(payload, "api-compatibility.schema.json", "api-compatibility.json")
    return payload


def render_api_compatibility_markdown(payload: dict[str, object]) -> str:
    summary = _as_dict(payload.get("summary"))
    gate = _as_dict(payload.get("gate"))
    lines = [
        "# API Compatibility",
        "",
        f"- Gate: {gate.get('mode')} -> {gate.get('status')}",
        f"- same: {summary.get('same', 0)}",
        f"- additive: {summary.get('additive', 0)}",
        f"- breaking: {summary.get('breaking', 0)}",
        f"- unknown: {summary.get('unknown', 0)}",
        "",
        "## Records",
    ]
    for record in _as_list(payload.get("records")):
        if not isinstance(record, dict):
            continue
        lines.append(
            f"- {record.get('classification')} {record.get('method')} {record.get('path_shape')} "
            f"(required={str(record.get('required')).lower()})"
        )
        for finding in _as_list(record.get("findings")):
            if isinstance(finding, dict):
                lines.append(f"  - {finding.get('code')}: {finding.get('detail')}")
        for reason in _as_list(record.get("unknown_reasons")):
            lines.append(f"  - unknown: {reason}")
    return "\n".join(lines) + "\n"


def validate_api_compatibility_set(directory: Path) -> dict[str, str]:
    json_path = directory / "api-compatibility.json"
    markdown_path = directory / "api-compatibility.md"
    missing = [path.name for path in (json_path, markdown_path) if not path.is_file()]
    if missing:
        raise ApiCompatibilityError(f"Missing API compatibility artifacts: {', '.join(missing)}")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ApiCompatibilityError("api-compatibility.json must be a JSON object")
    _validate(payload, "api-compatibility.schema.json", str(json_path))
    for path in (json_path, markdown_path):
        if contains_unredacted_secret_like_value(path.read_text(encoding="utf-8", errors="replace")):
            raise ApiCompatibilityError(f"Potential unredacted secret in {path.name}")
    return {
        "api-compatibility.json": hashlib.sha256(json_path.read_bytes()).hexdigest(),
        "api-compatibility.md": hashlib.sha256(markdown_path.read_bytes()).hexdigest(),
    }


def _atomic_publish(staging_dir: Path, destination: Path) -> None:
    validate_api_compatibility_set(staging_dir)
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


def write_api_compatibility(
    reference_catalog_path: Path,
    candidate_catalog_path: Path,
    output: Path,
    *,
    gate_mode: GateMode = "report",
    include_endpoints: tuple[str, ...] = (),
    exclude_endpoints: tuple[str, ...] = (),
    enforce_security_policy: bool = False,
) -> tuple[Path, dict[str, object]]:
    payload = build_api_compatibility(
        reference_catalog_path,
        candidate_catalog_path,
        gate_mode=gate_mode,
        include_endpoints=include_endpoints,
        exclude_endpoints=exclude_endpoints,
        enforce_security_policy=enforce_security_policy,
    )
    destination = output.resolve()
    with tempfile.TemporaryDirectory(prefix="asgard-api-compatibility-") as tmp:
        staging = Path(tmp)
        json_text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        markdown = render_api_compatibility_markdown(payload)
        for name, text in (("api-compatibility.json", json_text), ("api-compatibility.md", markdown)):
            if contains_unredacted_secret_like_value(text):
                raise ApiCompatibilityError(f"Potential unredacted secret in {name}")
            (staging / name).write_text(redact_text(text), encoding="utf-8", newline="\n")
        validate_api_compatibility_set(staging)
        _atomic_publish(staging, destination)
    return destination, payload
