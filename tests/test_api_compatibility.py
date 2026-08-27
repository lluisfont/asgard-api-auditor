from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from asgard_api_auditor.api_compatibility import build_api_compatibility
from asgard_api_auditor.catalog import endpoint_contract_id


def _schema(fields: dict[str, str], required: list[str] | None = None) -> dict[str, object]:
    return {
        "type": "object",
        "properties": {name: {"type": type_name} for name, type_name in fields.items()},
        "required": required or [],
    }


def _endpoint(
    method: str,
    path: str,
    *,
    direction: str = "exposed",
    request_fields: dict[str, str] | None = None,
    request_required: list[str] | None = None,
    response_fields: dict[str, str] | None = None,
    response_statuses: list[int] | None = None,
    auth_required: bool | None = False,
    contract_status: str = "evaluated_complete",
    semantic_status: str = "complete",
    status_code_compatibility: dict[str, str] | None = None,
) -> dict[str, object]:
    request_fields = request_fields or {}
    response_fields = response_fields or {}
    endpoint: dict[str, object] = {
        "direction": direction,
        "method": method,
        "path": path,
    }
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
            "evidence": [],
            "unresolved": [],
        },
        "response": {
            "status_codes": response_statuses or [200],
            "content_type": "application/json",
            "schema": _schema(response_fields, sorted(response_fields)),
            "fields": sorted(response_fields),
            "required_fields": sorted(response_fields),
            "fields_used_by_consumer": [],
            "tolerates_additional_fields": True,
            "tolerates_additional_statuses": True,
            "status_code_compatibility": status_code_compatibility,
            "evidence": [],
            "unresolved": [],
        },
        "headers": [],
        "authentication": {"authentication": "jwt" if auth_required else None, "authorization": None, "schemes": [], "required": auth_required, "evidence": [], "unresolved": []},
        "security": {"policy": "unknown", "drift": []},
        "behavior": {"summary": "fixture", "data_access": [], "auth_context": {"consumed_jwt_claims": [], "produced_jwt_claims": []}, "local_calls": [], "outbound_integrations": [], "conditions": [], "side_effects": [], "response_semantics": {}},
        "contract_status": contract_status,
        "semantic_status": semantic_status,
        "confidence": "confirmed",
        "confidence_reason": "fixture",
        "evidence": [{"path": "api.php", "line": 1, "kind": "route"}],
        "unresolved": [],
        "notes": [],
        "scope": {"status": "included", "selectors": []},
        "source": {"repository_id": "fixture", "source_commit": "a" * 40, "findings_sha256": "0" * 64},
    }


def _catalog(path: Path, endpoints: list[dict[str, object]], *, repo: str = "repo") -> None:
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
                "coverage": {"inventory_complete": True, "discovery_complete": True, "total_endpoints": len(endpoints), "included_endpoints": len(endpoints), "excluded_endpoints": 0, "exposed_endpoints": sum(1 for item in endpoints if item["direction"] == "exposed"), "consumed_endpoints": sum(1 for item in endpoints if item["direction"] == "consumed"), "unresolved": 0},
                "endpoints": endpoints,
                "unresolved": [],
                "input_hashes": [{"path": "findings.json", "sha256": "0" * 64}],
            }
        ),
        encoding="utf-8",
    )


class ApiCompatibilityTests(unittest.TestCase):
    def test_identical_unknown_remains_unknown_in_self_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            catalog = Path(tmp) / "catalog.json"
            endpoint = _endpoint("GET", "/x", contract_status="unknown", semantic_status="unknown")
            endpoint["request"]["body_schema"] = None
            endpoint["response"]["schema"] = None
            endpoint["authentication"]["required"] = None
            _catalog(catalog, [endpoint])

            payload = build_api_compatibility(catalog, catalog)

            self.assertEqual(payload["records"][0]["classification"], "unknown")
            self.assertTrue(payload["records"][0]["observed_equal"])
            self.assertIn("response", payload["records"][0]["unknown_reasons"])

    def test_reference_with_three_endpoints_one_breaking_fails_on_breaking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            _catalog(
                reference,
                [
                    _endpoint("GET", "/a", response_fields={"id": "string"}),
                    _endpoint("GET", "/b", response_fields={"id": "string"}),
                    _endpoint("GET", "/c", response_fields={"id": "string"}),
                ],
                repo="reference",
            )
            _catalog(
                candidate,
                [
                    _endpoint("GET", "/a", response_fields={"id": "string"}),
                    _endpoint("GET", "/b", response_fields={"id": "string"}),
                ],
                repo="candidate",
            )

            payload = build_api_compatibility(reference, candidate, gate_mode="fail_on_breaking")

            self.assertEqual(payload["summary"]["breaking"], 1)
            self.assertEqual(payload["gate"]["status"], "failed")

    def test_reference_unknown_passes_fail_on_breaking_but_fails_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            unknown = _endpoint("GET", "/b", response_fields={"id": "string"}, contract_status="unknown")
            _catalog(reference, [_endpoint("GET", "/a", response_fields={"id": "string"}), unknown, _endpoint("GET", "/c", response_fields={"id": "string"})], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/a", response_fields={"id": "string"}), unknown, _endpoint("GET", "/c", response_fields={"id": "string"})], repo="candidate")

            breaking_only = build_api_compatibility(reference, candidate, gate_mode="fail_on_breaking")
            fail_closed = build_api_compatibility(reference, candidate, gate_mode="fail_closed")

            self.assertEqual(breaking_only["summary"]["unknown"], 1)
            self.assertEqual(breaking_only["gate"]["status"], "passed")
            self.assertEqual(fail_closed["gate"]["status"], "failed")

    def test_explicit_scope_excludes_breaking_endpoint_from_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            _catalog(reference, [_endpoint("GET", "/keep", response_fields={"id": "string"}), _endpoint("DELETE", "/drop", response_fields={"id": "string"})], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/keep", response_fields={"id": "string"})], repo="candidate")

            payload = build_api_compatibility(
                reference,
                candidate,
                gate_mode="fail_on_breaking",
                exclude_endpoints=("DELETE /drop",),
            )

            self.assertEqual(payload["gate"]["status"], "passed")
            self.assertEqual(payload["summary"]["excluded_reference_endpoints"], 1)
            self.assertEqual(payload["scope"]["excluded_reference_endpoints"][0]["path_shape"], "/drop")

    def test_reference_candidate_compares_consumed_endpoints_too(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            _catalog(
                reference,
                [_endpoint("GET", "/consumer-dependency", direction="consumed")],
                repo="reference",
            )
            _catalog(candidate, [], repo="candidate")

            payload = build_api_compatibility(reference, candidate, gate_mode="fail_on_breaking")

            self.assertEqual(payload["summary"]["required_reference_endpoints"], 1)
            self.assertEqual(payload["summary"]["breaking"], 1)
            self.assertEqual(payload["gate"]["status"], "failed")


if __name__ == "__main__":
    unittest.main()
