"""Deterministic provider-consumer correlation over generated findings artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from . import __version__
from .artifacts import sha256_file
from .constants import CORRELATIONS_SCHEMA_VERSION, FINDINGS_SCHEMA_VERSION
from .path_normalization import normalized_path_shape
from .redaction import contains_unredacted_secret_like_value, redact_text

CorrelationStatus = Literal[
    "matched_confirmed",
    "matched_unique_candidate",
    "ambiguous",
    "unmatched",
]


class CorrelationError(ValueError):
    """Raised when correlation inputs or outputs fail closed."""


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


@dataclass(frozen=True)
class EndpointSnapshot:
    snapshot: FindingsSnapshot
    endpoint: dict[str, object]


def _stable_id(prefix: str, *parts: str) -> str:
    payload = "|".join(parts).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(payload).hexdigest()[:16]}"


def _require_string(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise CorrelationError(f"findings.json is missing required string field: {key}")
    return value


def _validate_endpoint(endpoint: object, *, index: int, source: Path) -> dict[str, object]:
    if not isinstance(endpoint, dict):
        raise CorrelationError(f"{source}: endpoints[{index}] must be an object")
    for key in ("endpoint_id", "direction", "surface_type", "method", "path", "evidence"):
        if key not in endpoint:
            raise CorrelationError(f"{source}: endpoints[{index}] misses {key}")
    if endpoint["direction"] not in {"exposed", "consumed"}:
        raise CorrelationError(f"{source}: endpoints[{index}] has unsupported direction")
    if endpoint["surface_type"] != "http":
        raise CorrelationError(f"{source}: endpoints[{index}] has unsupported surface_type")
    if not isinstance(endpoint["endpoint_id"], str) or not endpoint["endpoint_id"]:
        raise CorrelationError(f"{source}: endpoints[{index}] has invalid endpoint_id")
    if not isinstance(endpoint["method"], str) or not endpoint["method"]:
        raise CorrelationError(f"{source}: endpoints[{index}] has invalid method")
    if not isinstance(endpoint["path"], str) or not endpoint["path"]:
        raise CorrelationError(f"{source}: endpoints[{index}] has invalid path")
    if not isinstance(endpoint["evidence"], list):
        raise CorrelationError(f"{source}: endpoints[{index}] has invalid evidence")
    return endpoint


def _load_findings(path: Path) -> FindingsSnapshot:
    resolved = path.resolve()
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CorrelationError(f"Unable to read findings artifact {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CorrelationError(f"{path}: findings artifact must be a JSON object")
    required = {
        "schema_version",
        "audit_id",
        "auditor_version",
        "repository",
        "repository_id",
        "source_ref",
        "source_commit",
        "audit_timestamp",
        "status",
        "coverage",
        "endpoints",
        "integration_surfaces",
        "unresolved",
        "artifacts",
    }
    missing = sorted(required - payload.keys())
    if missing:
        raise CorrelationError(f"{path}: findings artifact misses required fields: {', '.join(missing)}")
    schema_version = _require_string(payload, "schema_version")
    if schema_version != FINDINGS_SCHEMA_VERSION:
        raise CorrelationError(
            f"{path}: unsupported findings schema_version {schema_version!r}; "
            f"expected {FINDINGS_SCHEMA_VERSION!r}"
        )
    endpoints = payload.get("endpoints")
    if not isinstance(endpoints, list):
        raise CorrelationError(f"{path}: findings artifact must contain endpoints array")
    if not isinstance(payload.get("coverage"), dict):
        raise CorrelationError(f"{path}: findings artifact must contain coverage object")
    if not isinstance(payload.get("integration_surfaces"), list):
        raise CorrelationError(f"{path}: findings artifact must contain integration_surfaces array")
    if not isinstance(payload.get("unresolved"), list):
        raise CorrelationError(f"{path}: findings artifact must contain unresolved array")
    if not isinstance(payload.get("artifacts"), dict):
        raise CorrelationError(f"{path}: findings artifact must contain artifacts object")
    for index, endpoint in enumerate(endpoints):
        _validate_endpoint(endpoint, index=index, source=path)
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


def _dedupe_snapshots(paths: list[Path]) -> list[FindingsSnapshot]:
    by_hash: dict[str, FindingsSnapshot] = {}
    ordered: list[FindingsSnapshot] = []
    for path in paths:
        snapshot = _load_findings(path)
        if snapshot.sha256 in by_hash:
            continue
        by_hash[snapshot.sha256] = snapshot
        ordered.append(snapshot)

    by_repository: dict[str, FindingsSnapshot] = {}
    for snapshot in ordered:
        previous = by_repository.get(snapshot.repository_id)
        if previous is None:
            by_repository[snapshot.repository_id] = snapshot
            continue
        if previous.source_commit != snapshot.source_commit:
            raise CorrelationError(
                "Conflicting snapshots for repository_id "
                f"{snapshot.repository_id!r}: {previous.source_commit} vs {snapshot.source_commit}"
            )
        raise CorrelationError(
            "Duplicate non-identical snapshots for repository_id "
            f"{snapshot.repository_id!r} at commit {snapshot.source_commit}"
        )

    return sorted(ordered, key=lambda item: (item.repository_id, item.source_commit, item.sha256))


def _input_record(snapshot: FindingsSnapshot) -> dict[str, object]:
    return {
        "audit_id": snapshot.audit_id,
        "repository": snapshot.repository,
        "repository_id": snapshot.repository_id,
        "source_ref": snapshot.source_ref,
        "source_commit": snapshot.source_commit,
        "auditor_version": snapshot.auditor_version,
        "schema_version": snapshot.schema_version,
        "sha256": snapshot.sha256,
    }


def _endpoint_value(endpoint: dict[str, object], key: str) -> str:
    value = endpoint.get(key)
    return value if isinstance(value, str) else ""


def _correlation_path(path: str) -> str:
    parsed = urlsplit(path)
    if parsed.scheme in {"http", "https"} and parsed.path:
        return parsed.path
    if path.startswith("{") and "}/" in path:
        return path.split("}", 1)[1]
    return path


def _evidence(endpoint: dict[str, object]) -> list[dict[str, object]]:
    evidence = endpoint.get("evidence")
    if not isinstance(evidence, list):
        return []
    return [item for item in evidence if isinstance(item, dict)]


def _provider_record(provider: EndpointSnapshot) -> dict[str, object]:
    endpoint = provider.endpoint
    return {
        "provider_repository": provider.snapshot.repository,
        "provider_repository_id": provider.snapshot.repository_id,
        "provider_endpoint_id": _endpoint_value(endpoint, "endpoint_id"),
        "provider_method": _endpoint_value(endpoint, "method").upper(),
        "provider_path": _endpoint_value(endpoint, "path"),
        "provider_evidence": _evidence(endpoint),
    }


def _consumer_ref(record: dict[str, object]) -> dict[str, object]:
    return {
        "correlation_id": record["correlation_id"],
        "consumer_repository": record["consumer_repository"],
        "consumer_repository_id": record["consumer_repository_id"],
        "consumer_endpoint_id": record["consumer_endpoint_id"],
        "consumer_method": record["consumer_method"],
        "consumer_path": record["consumer_path"],
        "consumer_base_url": record.get("consumer_base_url"),
        "consumer_evidence": record["consumer_evidence"],
        "status": record["status"],
    }


def _provider_identity_matches(provider: EndpointSnapshot, identity: str) -> bool:
    endpoint_provider = _endpoint_value(provider.endpoint, "provider_repository")
    identities = {
        provider.snapshot.repository,
        provider.snapshot.repository_id,
        endpoint_provider,
    }
    return identity in identities


def _status_and_candidates(
    consumer: EndpointSnapshot,
    candidates: list[EndpointSnapshot],
) -> tuple[CorrelationStatus, list[EndpointSnapshot], str, dict[str, str]]:
    endpoint = consumer.endpoint
    provider_identity = _endpoint_value(endpoint, "provider_repository")
    if provider_identity:
        proven = [item for item in candidates if _provider_identity_matches(item, provider_identity)]
        if len(proven) == 1:
            return (
                "matched_confirmed",
                proven,
                "http_method_and_normalized_path_shape+explicit_provider_identity",
                {
                    "classification": "confirmed_dependency",
                    "semantics": (
                        "Provider identity is explicitly present in the consumer finding and "
                        "matches exactly one provider endpoint with the same method and path shape."
                    ),
                },
            )

    if len(candidates) == 1:
        return (
            "matched_unique_candidate",
            candidates,
            "http_method_and_normalized_path_shape",
            {
                "classification": "deterministic_candidate_unconfirmed",
                "semantics": (
                    "Exactly one provider endpoint has the same HTTP method and normalized path "
                    "shape. This is not a confirmed runtime dependency."
                ),
            },
        )
    if candidates:
        return (
            "ambiguous",
            candidates,
            "http_method_and_normalized_path_shape",
            {
                "classification": "ambiguous_candidate_set",
                "semantics": "Multiple provider endpoints share the same method and normalized path shape.",
            },
        )
    return (
        "unmatched",
        [],
        "http_method_and_normalized_path_shape",
        {
            "classification": "unknown",
            "semantics": "No provider endpoint shares the same method and normalized path shape.",
        },
    )


def _correlation_record(
    consumer: EndpointSnapshot,
    candidates: list[EndpointSnapshot],
) -> dict[str, object]:
    endpoint = consumer.endpoint
    method = _endpoint_value(endpoint, "method").upper()
    path = _endpoint_value(endpoint, "path")
    shape = normalized_path_shape(_correlation_path(path))
    status, retained_candidates, strategy, confidence = _status_and_candidates(consumer, candidates)
    correlation_id = _stable_id(
        "corr",
        consumer.snapshot.repository_id,
        consumer.snapshot.source_commit,
        _endpoint_value(endpoint, "endpoint_id"),
        method,
        path,
    )
    base_url = endpoint.get("base_url")
    return {
        "correlation_id": correlation_id,
        "status": status,
        "consumer_repository": consumer.snapshot.repository,
        "consumer_repository_id": consumer.snapshot.repository_id,
        "consumer_endpoint_id": _endpoint_value(endpoint, "endpoint_id"),
        "consumer_method": method,
        "consumer_path": path,
        "consumer_base_url": base_url if isinstance(base_url, str) else None,
        "consumer_evidence": _evidence(endpoint),
        "normalized_path_shape": shape,
        "candidate_count": len(retained_candidates),
        "candidate_providers": [_provider_record(item) for item in retained_candidates],
        "match_strategy": strategy,
        "confidence": confidence,
    }


def _endpoint_sort_key(item: EndpointSnapshot) -> tuple[str, str, str, str, str]:
    endpoint = item.endpoint
    return (
        item.snapshot.repository_id,
        _endpoint_value(endpoint, "method").upper(),
        normalized_path_shape(_correlation_path(_endpoint_value(endpoint, "path"))),
        _endpoint_value(endpoint, "path"),
        _endpoint_value(endpoint, "endpoint_id"),
    )


def _build_correlations(snapshots: list[FindingsSnapshot]) -> list[dict[str, object]]:
    providers: list[EndpointSnapshot] = []
    consumers: list[EndpointSnapshot] = []
    for snapshot in snapshots:
        endpoints = snapshot.payload["endpoints"]
        assert isinstance(endpoints, list)
        for endpoint in endpoints:
            assert isinstance(endpoint, dict)
            direction = endpoint["direction"]
            wrapped = EndpointSnapshot(snapshot=snapshot, endpoint=endpoint)
            if direction == "exposed":
                providers.append(wrapped)
            elif direction == "consumed":
                consumers.append(wrapped)

    provider_index: dict[tuple[str, str], list[EndpointSnapshot]] = {}
    for provider in sorted(providers, key=_endpoint_sort_key):
        endpoint = provider.endpoint
        key = (
            _endpoint_value(endpoint, "method").upper(),
            normalized_path_shape(_correlation_path(_endpoint_value(endpoint, "path"))),
        )
        provider_index.setdefault(key, []).append(provider)

    records = []
    for consumer in sorted(consumers, key=_endpoint_sort_key):
        endpoint = consumer.endpoint
        key = (
            _endpoint_value(endpoint, "method").upper(),
            normalized_path_shape(_correlation_path(_endpoint_value(endpoint, "path"))),
        )
        records.append(_correlation_record(consumer, provider_index.get(key, [])))
    return records


def _coverage(
    snapshots: list[FindingsSnapshot],
    correlations: list[dict[str, object]],
) -> dict[str, object]:
    exposed = 0
    consumed = 0
    for snapshot in snapshots:
        endpoints = snapshot.payload["endpoints"]
        assert isinstance(endpoints, list)
        for endpoint in endpoints:
            assert isinstance(endpoint, dict)
            if endpoint["direction"] == "exposed":
                exposed += 1
            elif endpoint["direction"] == "consumed":
                consumed += 1
    status_counts = {
        "matched_confirmed": 0,
        "matched_unique_candidate": 0,
        "ambiguous": 0,
        "unmatched": 0,
    }
    provider_keys: set[tuple[str, str, str]] = set()
    for record in correlations:
        status = str(record["status"])
        status_counts[status] += 1
        for candidate in record["candidate_providers"]:
            assert isinstance(candidate, dict)
            provider_keys.add(
                (
                    str(candidate["provider_repository_id"]),
                    str(candidate["provider_endpoint_id"]),
                    str(candidate["provider_method"]),
                )
            )
    return {
        "input_repositories": len(snapshots),
        "exposed_endpoints_total": exposed,
        "consumed_endpoints_total": consumed,
        "matched_confirmed": status_counts["matched_confirmed"],
        "matched_unique_candidate": status_counts["matched_unique_candidate"],
        "ambiguous": status_counts["ambiguous"],
        "unmatched": status_counts["unmatched"],
        "providers_with_at_least_one_candidate_consumer": len(provider_keys),
        "consumers_correlated": consumed - status_counts["unmatched"],
        "consumers_total": consumed,
        "status_total": sum(status_counts.values()),
    }


def _reverse_index(correlations: list[dict[str, object]]) -> list[dict[str, object]]:
    index: dict[tuple[str, str, str], dict[str, object]] = {}
    for record in correlations:
        status = record["status"]
        for candidate in record["candidate_providers"]:
            assert isinstance(candidate, dict)
            key = (
                str(candidate["provider_repository_id"]),
                str(candidate["provider_endpoint_id"]),
                str(candidate["provider_method"]),
            )
            entry = index.setdefault(
                key,
                {
                    "provider_repository": candidate["provider_repository"],
                    "provider_repository_id": candidate["provider_repository_id"],
                    "provider_endpoint_id": candidate["provider_endpoint_id"],
                    "provider_method": candidate["provider_method"],
                    "provider_path": candidate["provider_path"],
                    "provider_evidence": candidate["provider_evidence"],
                    "confirmed_consumers": [],
                    "unique_candidate_consumers": [],
                    "ambiguous_candidate_consumers": [],
                },
            )
            if status == "matched_confirmed":
                bucket = "confirmed_consumers"
            elif status == "matched_unique_candidate":
                bucket = "unique_candidate_consumers"
            else:
                bucket = "ambiguous_candidate_consumers"
            consumers = entry[bucket]
            assert isinstance(consumers, list)
            consumers.append(_consumer_ref(record))

    for entry in index.values():
        for bucket in (
            "confirmed_consumers",
            "unique_candidate_consumers",
            "ambiguous_candidate_consumers",
        ):
            consumers = entry[bucket]
            assert isinstance(consumers, list)
            consumers.sort(
                key=lambda item: (
                    item["consumer_repository_id"],
                    item["consumer_method"],
                    item["consumer_path"],
                    item["consumer_endpoint_id"],
                )
            )
    return sorted(
        index.values(),
        key=lambda item: (
            item["provider_repository_id"],
            item["provider_method"],
            item["provider_path"],
            item["provider_endpoint_id"],
        ),
    )


def _evidence_label(evidence: object) -> str:
    if not isinstance(evidence, list) or not evidence:
        return "n/a"
    labels: list[str] = []
    for item in evidence:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        if not isinstance(path, str):
            continue
        line = item.get("line")
        labels.append(f"{path}:{line}" if isinstance(line, int) else path)
    return ", ".join(labels) if labels else "n/a"


def _render_markdown(payload: dict[str, object]) -> str:
    coverage = payload["coverage"]
    assert isinstance(coverage, dict)
    lines = [
        "---",
        f'schema_version: "{payload["schema_version"]}"',
        f'correlation_id: "{payload["correlation_id"]}"',
        f'auditor_version: "{payload["auditor_version"]}"',
        "---",
        "",
        "# API Relations",
        "",
        "Generated from versioned ASGARD API Auditor findings artifacts. Unique structural matches are candidate relationships unless provider identity is independently proven.",
        "",
        "## Coverage Summary",
        "",
        f"- Input repositories: **{coverage['input_repositories']}**",
        f"- Exposed HTTP endpoints: **{coverage['exposed_endpoints_total']}**",
        f"- Consumed HTTP endpoints: **{coverage['consumed_endpoints_total']}**",
        f"- Matched confirmed: **{coverage['matched_confirmed']}**",
        f"- Matched unique candidates: **{coverage['matched_unique_candidate']}**",
        f"- Ambiguous: **{coverage['ambiguous']}**",
        f"- Unmatched: **{coverage['unmatched']}**",
        "",
        "## Input Snapshot Provenance",
        "",
    ]
    inputs = payload["inputs"]
    assert isinstance(inputs, list)
    for item in inputs:
        assert isinstance(item, dict)
        lines.append(
            f"- `{item['repository_id']}` commit `{item['source_commit']}` "
            f"findings `{item['sha256']}`"
        )

    lines.extend(["", "## Provider Relationships", ""])
    reverse = payload["provider_reverse_index"]
    assert isinstance(reverse, list)
    if not reverse:
        lines.append("No provider relationships were identified.")
    for provider in reverse:
        assert isinstance(provider, dict)
        lines.extend(
            [
                f"## {provider['provider_method']} {provider['provider_path']}",
                "",
                f"Provider: {provider['provider_repository_id']}",
                f"Provider endpoint ID: {provider['provider_endpoint_id']}",
                f"Evidence: {_evidence_label(provider['provider_evidence'])}",
                "",
                "Consumers:",
            ]
        )
        for bucket in (
            "confirmed_consumers",
            "unique_candidate_consumers",
            "ambiguous_candidate_consumers",
        ):
            consumers = provider[bucket]
            assert isinstance(consumers, list)
            for consumer in consumers:
                assert isinstance(consumer, dict)
                lines.append(
                    f"- {consumer['consumer_repository_id']} - {consumer['status']} - "
                    f"`{consumer['consumer_method']} {consumer['consumer_path']}`; "
                    f"evidence: {_evidence_label(consumer['consumer_evidence'])}"
                )
        lines.append("")

    correlations = payload["correlations"]
    assert isinstance(correlations, list)
    unmatched = [item for item in correlations if isinstance(item, dict) and item["status"] == "unmatched"]
    ambiguous = [item for item in correlations if isinstance(item, dict) and item["status"] == "ambiguous"]
    lines.extend(["## Unmatched Consumers", ""])
    if not unmatched:
        lines.append("No unmatched consumers.")
    for item in unmatched:
        lines.append(
            f"- {item['consumer_repository_id']} `{item['consumer_method']} {item['consumer_path']}`; "
            f"base: `{item.get('consumer_base_url') or 'n/a'}`; "
            f"evidence: {_evidence_label(item['consumer_evidence'])}"
        )
    lines.extend(["", "## Ambiguous Consumers", ""])
    if not ambiguous:
        lines.append("No ambiguous consumers.")
    for item in ambiguous:
        lines.append(
            f"- {item['consumer_repository_id']} `{item['consumer_method']} {item['consumer_path']}`; "
            f"candidates: {item['candidate_count']}; evidence: {_evidence_label(item['consumer_evidence'])}"
        )
    return redact_text("\n".join(lines) + "\n")


def build_correlation_payload(findings_paths: list[Path]) -> dict[str, object]:
    """Build deterministic provider-consumer correlations from findings files."""
    if len(findings_paths) < 1:
        raise CorrelationError("At least one --findings artifact is required")
    snapshots = _dedupe_snapshots(findings_paths)
    if not snapshots:
        raise CorrelationError("No unique findings artifacts were supplied")
    correlations = _build_correlations(snapshots)
    payload: dict[str, object] = {
        "schema_version": CORRELATIONS_SCHEMA_VERSION,
        "correlation_id": _stable_id("corr-run", *(snapshot.sha256 for snapshot in snapshots)),
        "auditor_version": __version__,
        "generated_at": datetime.now(UTC).isoformat(),
        "inputs": [_input_record(snapshot) for snapshot in snapshots],
        "coverage": _coverage(snapshots, correlations),
        "correlations": correlations,
        "provider_reverse_index": _reverse_index(correlations),
        "notes": [
            "Correlation uses exact HTTP method plus normalized path shape only.",
            "Unique structural matches are candidates, not confirmed dependencies.",
            "No fuzzy matching, host guessing, repository-name heuristics or manual mappings are used.",
            "SOAP and other non-HTTP integration surfaces are not correlated as REST endpoints.",
        ],
    }
    coverage = payload["coverage"]
    assert isinstance(coverage, dict)
    if coverage["status_total"] != coverage["consumed_endpoints_total"]:
        raise CorrelationError("Correlation status counts do not reconcile with consumed endpoint total")
    return payload


def validate_correlation_set(directory: Path) -> dict[str, str]:
    """Validate generated correlation artifacts before publication."""
    correlations_path = directory / "correlations.json"
    relations_path = directory / "api-relations.md"
    missing = [path.name for path in (correlations_path, relations_path) if not path.is_file()]
    if missing:
        raise CorrelationError(f"Missing correlation artifacts: {', '.join(missing)}")
    payload = json.loads(correlations_path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != CORRELATIONS_SCHEMA_VERSION:
        raise CorrelationError("correlations.json schema_version mismatch")
    coverage = payload.get("coverage")
    if not isinstance(coverage, dict):
        raise CorrelationError("correlations.json missing coverage")
    if coverage.get("status_total") != coverage.get("consumed_endpoints_total"):
        raise CorrelationError("Correlation status counts do not reconcile")
    correlations = payload.get("correlations")
    if not isinstance(correlations, list):
        raise CorrelationError("correlations.json missing correlations")
    if len(correlations) != coverage.get("consumed_endpoints_total"):
        raise CorrelationError("Every consumed endpoint must have exactly one correlation record")
    for name in ("correlations.json", "api-relations.md"):
        text = (directory / name).read_text(encoding="utf-8", errors="replace")
        if contains_unredacted_secret_like_value(text):
            raise CorrelationError(f"Potential unredacted secret in {name}")
    return {
        "correlations.json": sha256_file(correlations_path),
        "api-relations.md": sha256_file(relations_path),
    }


def _atomic_publish(staging_dir: Path, destination: Path) -> None:
    validate_correlation_set(staging_dir)
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


def correlate_findings(findings_paths: list[Path], output: Path) -> tuple[Path, dict[str, object]]:
    """Generate and atomically publish correlation artifacts."""
    payload = build_correlation_payload(findings_paths)
    destination = output.resolve()
    with tempfile.TemporaryDirectory(prefix="asgard-api-correlation-") as temporary:
        staging = Path(temporary)
        correlations_path = staging / "correlations.json"
        relations_path = staging / "api-relations.md"
        correlations_text = redact_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        correlations_path.write_text(correlations_text, encoding="utf-8")
        relations_path.write_text(_render_markdown(payload), encoding="utf-8")
        validate_correlation_set(staging)
        _atomic_publish(staging, destination)
    return destination, payload


__all__ = [
    "CorrelationError",
    "build_correlation_payload",
    "correlate_findings",
    "validate_correlation_set",
]
