from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from asgard_api_auditor.catalog import endpoint_contract_id
from asgard_api_auditor.consumer_compatibility import build_consumer_compatibility


def _schema(fields: dict[str, str], required: list[str] | None = None) -> dict[str, object]:
    return {
        "type": "object",
        "properties": {name: {"type": type_name} for name, type_name in fields.items()},
        "required": required or [],
    }


def _endpoint(
    direction: str,
    method: str,
    path: str,
    *,
    request_fields: dict[str, str] | None = None,
    request_required: list[str] | None = None,
    response_fields: dict[str, str] | None = None,
    response_used: list[str] | None = None,
    auth_required: bool | None = False,
    accepts_additional_fields: bool | None = None,
    tolerates_additional_fields: bool | None = True,
) -> dict[str, object]:
    request_fields = request_fields or {}
    response_fields = response_fields or {}
    endpoint: dict[str, object] = {"direction": direction, "method": method, "path": path}
    endpoint_id = endpoint_contract_id(endpoint)
    return {
        "endpoint_id": endpoint_id,
        "api_id": None,
        "source_endpoint_id": f"source-{endpoint_id}",
        "stable_identity": {"direction": direction, "method": method, "path_shape": path},
        "direction": direction,
        "surface_type": "http",
        "method": method,
        "normalized_path": path,
        "path_shape": path,
        "base_url": None,
        "parameters": [],
        "request": {
            "parameters": [],
            "content_type": "application/json",
            "body_schema": _schema(request_fields, request_required),
            "fields": sorted(request_fields),
            "required_fields": request_required or [],
            "optional_fields": sorted(set(request_fields) - set(request_required or [])),
            "unknown_requiredness_fields": [],
            "accepts_additional_fields": accepts_additional_fields,
            "evidence": [],
            "unresolved": [],
        },
        "response": {
            "status_codes": [200],
            "content_type": "application/json",
            "schema": _schema(response_fields, sorted(response_fields)),
            "fields": sorted(response_fields),
            "required_fields": sorted(response_fields),
            "fields_used_by_consumer": response_used or [],
            "tolerates_additional_fields": tolerates_additional_fields,
            "tolerates_additional_statuses": True,
            "evidence": [],
            "unresolved": [],
        },
        "headers": [],
        "authentication": {"authentication": "jwt" if auth_required else None, "authorization": None, "schemes": [], "required": auth_required, "evidence": [], "unresolved": []},
        "security": {"policy": "unknown", "drift": []},
        "behavior": {"summary": "fixture", "data_access": [], "auth_context": {"consumed_jwt_claims": [], "produced_jwt_claims": []}, "local_calls": [], "outbound_integrations": [], "conditions": [], "side_effects": [], "response_semantics": {}},
        "contract_status": "evaluated_complete",
        "semantic_status": "complete",
        "confidence": "confirmed",
        "confidence_reason": "fixture",
        "evidence": [{"path": "api.dart", "line": 1, "kind": "http_client"}],
        "unresolved": [],
        "notes": [],
        "scope": {"status": "included", "selectors": []},
        "source": {"repository_id": "fixture", "source_commit": "a" * 40, "findings_sha256": "0" * 64},
    }


def _catalog(path: Path, endpoints: list[dict[str, object]], *, repo: str) -> None:
    exposed = sum(1 for item in endpoints if item["direction"] == "exposed")
    consumed = sum(1 for item in endpoints if item["direction"] == "consumed")
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "catalog_id": f"catalog-{repo}",
                "auditor_version": "0.8.0",
                "generated_at": "2026-08-27T00:00:00+00:00",
                "metadata": {
                    "repository": repo,
                    "repository_id": repo,
                    "source_ref": "main",
                    "source_commit": "a" * 40,
                    "findings_audit_id": f"audit-{repo}",
                    "findings_schema_version": "2.0",
                    "findings_auditor_version": "0.8.0",
                    "findings_sha256": "0" * 64,
                    "stable_namespace": None,
                },
                "scope": {"mode": "all", "include_endpoints": [], "exclude_endpoints": [], "included_endpoints": len(endpoints), "excluded_endpoints": 0},
                "coverage": {"inventory_complete": True, "discovery_complete": True, "total_endpoints": len(endpoints), "included_endpoints": len(endpoints), "excluded_endpoints": 0, "exposed_endpoints": exposed, "consumed_endpoints": consumed, "unresolved": 0},
                "endpoints": endpoints,
                "unresolved": [],
                "input_hashes": [{"path": "findings.json", "sha256": "0" * 64}],
            }
        ),
        encoding="utf-8",
    )


class ConsumerCompatibilityTests(unittest.TestCase):
    def test_provider_accepts_consumer_request_and_superset_response(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            consumer = root / "consumer.json"
            provider = root / "provider.json"
            _catalog(
                consumer,
                [_endpoint("consumed", "POST", "/items", request_fields={"id": "string"}, response_fields={"id": "string", "status": "string"}, response_used=["id", "status"], tolerates_additional_fields=True)],
                repo="consumer",
            )
            _catalog(
                provider,
                [_endpoint("exposed", "POST", "/items", request_fields={"id": "string", "comment": "string"}, request_required=["id"], response_fields={"id": "string", "status": "string", "description": "string"}, accepts_additional_fields=True)],
                repo="provider",
            )

            payload = build_consumer_compatibility([consumer], [provider])

            self.assertEqual(payload["gate"]["status"], "passed")
            self.assertEqual(payload["records"][0]["status"], "compatible")

    def test_consumer_dependency_missing_fails_on_breaking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            consumer = root / "consumer.json"
            provider = root / "provider.json"
            _catalog(
                consumer,
                [
                    _endpoint("consumed", "GET", "/a"),
                    _endpoint("consumed", "GET", "/b"),
                    _endpoint("consumed", "GET", "/c"),
                ],
                repo="consumer",
            )
            _catalog(
                provider,
                [_endpoint("exposed", "GET", "/a"), _endpoint("exposed", "GET", "/b")],
                repo="provider",
            )

            payload = build_consumer_compatibility([consumer], [provider], gate_mode="fail_on_breaking")

            self.assertEqual(payload["summary"]["missing"], 1)
            self.assertEqual(payload["gate"]["status"], "failed")

    def test_consumer_scope_excludes_dependency_from_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            consumer = root / "consumer.json"
            provider = root / "provider.json"
            _catalog(
                consumer,
                [_endpoint("consumed", "GET", "/keep"), _endpoint("consumed", "GET", "/skip")],
                repo="consumer",
            )
            _catalog(provider, [_endpoint("exposed", "GET", "/keep")], repo="provider")

            payload = build_consumer_compatibility(
                [consumer],
                [provider],
                exclude_endpoints=("GET /skip",),
                gate_mode="fail_on_breaking",
            )

            self.assertEqual(payload["gate"]["status"], "passed")
            self.assertEqual(payload["summary"]["excluded_dependencies"], 1)
            self.assertEqual(payload["scope"]["excluded_dependencies"][0]["path_shape"], "/skip")

    def test_provider_rejects_consumer_additional_request_field_is_breaking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            consumer = root / "consumer.json"
            provider = root / "provider.json"
            _catalog(
                consumer,
                [_endpoint("consumed", "POST", "/items", request_fields={"id": "string", "comment": "string"})],
                repo="consumer",
            )
            provider_endpoint = _endpoint("exposed", "POST", "/items", request_fields={"id": "string"})
            provider_endpoint["request"]["rejects_additional_fields"] = True
            _catalog(provider, [provider_endpoint], repo="provider")

            payload = build_consumer_compatibility([consumer], [provider], gate_mode="fail_on_breaking")

            self.assertEqual(payload["records"][0]["status"], "breaking")
            self.assertEqual(payload["gate"]["status"], "failed")


if __name__ == "__main__":
    unittest.main()
