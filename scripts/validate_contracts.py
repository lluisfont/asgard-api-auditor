#!/usr/bin/env python3
"""Deterministic repository contract validation with standard-library dependencies only."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from asgard_api_auditor.constants import (  # noqa: E402
    API_CATALOG_SCHEMA_VERSION,
    API_COMPATIBILITY_SCHEMA_VERSION,
    CONSUMER_COMPATIBILITY_SCHEMA_VERSION,
    CORRELATIONS_SCHEMA_VERSION,
    ENDPOINT_DISCOVERY_SCHEMA_VERSION,
    FINDINGS_SCHEMA_VERSION,
    OPENAPI_VERSION,
    PRIMARY_ARTIFACTS,
    TECHNICAL_INVENTORY_SCHEMA_VERSION,
)


class ContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def validate_findings_schema() -> None:
    path = ROOT / "schemas" / "findings.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    props = schema["properties"]
    required = set(schema["required"])
    expected = {
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
    require(expected.issubset(required), "findings schema misses required top-level fields")
    require(
        props["schema_version"].get("const") == FINDINGS_SCHEMA_VERSION,
        "schema version mismatch",
    )

    endpoint_required = set(schema["$defs"]["endpoint"]["required"])
    require("endpoint_id" in endpoint_required, "endpoint_id must be required")
    require("confidence_reason" in endpoint_required, "confidence_reason must be required")

    response_props = schema["$defs"]["response"]["properties"]
    require("fields_used_by_consumer" in response_props, "consumer response fields are missing")

    coverage_required = set(schema["$defs"]["coverage"]["required"])
    require("inventory_complete" in coverage_required, "coverage must require inventory_complete")
    require(
        "required_detector_categories" in coverage_required,
        "coverage must require required_detector_categories",
    )
    require(
        "unsupported_surfaces" in coverage_required,
        "coverage must require unsupported surfaces",
    )


def validate_inventory_schema() -> None:
    path = ROOT / "schemas" / "technical-inventory.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    require(
        schema["properties"]["schema_version"].get("const")
        == TECHNICAL_INVENTORY_SCHEMA_VERSION,
        "technical inventory schema version mismatch",
    )
    required = set(schema["required"])
    require("repository_id" in required, "technical inventory must require repository_id")
    require("source_commit" in required, "technical inventory must require source_commit")
    require("inventory_complete" in required, "technical inventory must require completeness")


def validate_discovery_schema() -> None:
    path = ROOT / "schemas" / "endpoint-discovery.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    require(
        schema["properties"]["schema_version"].get("const")
        == ENDPOINT_DISCOVERY_SCHEMA_VERSION,
        "endpoint discovery schema version mismatch",
    )
    required = set(schema["required"])
    expected = {
        "repository_id",
        "source_ref",
        "source_commit",
        "inventory_complete",
        "discovery_complete",
        "endpoints",
        "integrations",
        "detectors",
        "unresolved",
    }
    require(expected.issubset(required), "endpoint discovery schema misses coverage/provenance fields")


def validate_correlations_schema() -> None:
    path = ROOT / "schemas" / "correlations.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    props = schema["properties"]
    required = set(schema["required"])
    expected = {
        "schema_version",
        "correlation_id",
        "auditor_version",
        "generated_at",
        "inputs",
        "coverage",
        "correlations",
        "provider_reverse_index",
    }
    require(expected.issubset(required), "correlations schema misses required top-level fields")
    require(
        props["schema_version"].get("const") == CORRELATIONS_SCHEMA_VERSION,
        "correlations schema version mismatch",
    )
    correlation_required = set(schema["$defs"]["correlation"]["required"])
    for key in (
        "correlation_id",
        "status",
        "consumer_endpoint_id",
        "normalized_path_shape",
        "candidate_count",
        "candidate_providers",
        "match_strategy",
        "confidence",
    ):
        require(key in correlation_required, f"correlation records must require {key}")
    reverse_required = set(schema["$defs"]["providerReverseIndex"]["required"])
    require("confirmed_consumers" in reverse_required, "reverse index must list confirmed consumers")
    require(
        "unique_candidate_consumers" in reverse_required,
        "reverse index must list unique candidate consumers",
    )
    require(
        "ambiguous_candidate_consumers" in reverse_required,
        "reverse index must keep ambiguous consumers separate",
    )


def validate_v08_schemas() -> None:
    catalog = json.loads((ROOT / "schemas" / "api-catalog.schema.json").read_text(encoding="utf-8"))
    require(
        catalog["properties"]["schema_version"].get("const") == API_CATALOG_SCHEMA_VERSION,
        "api catalog schema version mismatch",
    )
    endpoint_required = set(catalog["$defs"]["endpoint"]["required"])
    for key in ("endpoint_id", "api_id", "stable_identity", "direction", "method", "path_shape"):
        require(key in endpoint_required, f"api catalog endpoint must require {key}")
    stable_required = set(catalog["$defs"]["stableIdentity"]["required"])
    require("api_id" not in stable_required, "stable identity must not require api_id")
    require("schema_version" not in stable_required, "stable identity must not include schema version")

    compatibility = json.loads(
        (ROOT / "schemas" / "api-compatibility.schema.json").read_text(encoding="utf-8")
    )
    require(
        compatibility["properties"]["schema_version"].get("const")
        == API_COMPATIBILITY_SCHEMA_VERSION,
        "api compatibility schema version mismatch",
    )
    require(
        {"same", "additive", "breaking", "unknown"}.issubset(
            set(compatibility["$defs"]["summary"]["properties"])
        ),
        "api compatibility summary must include required classifications",
    )

    consumer = json.loads(
        (ROOT / "schemas" / "consumer-compatibility.schema.json").read_text(encoding="utf-8")
    )
    require(
        consumer["properties"]["schema_version"].get("const")
        == CONSUMER_COMPATIBILITY_SCHEMA_VERSION,
        "consumer compatibility schema version mismatch",
    )
    require(
        "required_dependencies" in consumer["$defs"]["summary"]["required"],
        "consumer compatibility must track required dependencies",
    )


def validate_templates() -> None:
    shared_tokens = (
        "{{ audit_id }}",
        "{{ auditor_version }}",
        "{{ repository }}",
        "{{ source_ref }}",
        "{{ source_commit }}",
        "{{ audit_timestamp }}",
        "{{ audit_status }}",
    )
    for name in ("api-knowledge.md", "audit-report.md"):
        text = (ROOT / "templates" / name).read_text(encoding="utf-8")
        for token in shared_tokens:
            require(token in text, f"{name} missing shared metadata token {token}")

    openapi = (ROOT / "templates" / "openapi.yaml").read_text(encoding="utf-8")
    require(f"openapi: {OPENAPI_VERSION}" in openapi, "OpenAPI template version mismatch")
    require("x-asgard-audit-id" in openapi, "OpenAPI template missing audit ID")
    require("x-asgard-source-commit" in openapi, "OpenAPI template missing commit traceability")


def validate_primary_contract() -> None:
    require(
        PRIMARY_ARTIFACTS
        == ("openapi.yaml", "api-knowledge.md", "findings.json", "audit-report.md"),
        "primary artifact contract changed unexpectedly",
    )


def main() -> int:
    checks = [
        validate_findings_schema,
        validate_inventory_schema,
        validate_discovery_schema,
        validate_correlations_schema,
        validate_v08_schemas,
        validate_templates,
        validate_primary_contract,
    ]
    try:
        for check in checks:
            check()
    except (ContractError, KeyError, json.JSONDecodeError) as exc:
        print(f"CONTRACT VALIDATION FAILED: {exc}", file=sys.stderr)
        return 1
    print("Contract validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
