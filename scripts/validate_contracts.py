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
    FINDINGS_SCHEMA_VERSION,
    OPENAPI_VERSION,
    PRIMARY_ARTIFACTS,
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
    checks = [validate_findings_schema, validate_templates, validate_primary_contract]
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
