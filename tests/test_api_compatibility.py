from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from asgard_api_auditor.api_compatibility import ApiCompatibilityError, build_api_compatibility
from asgard_api_auditor.catalog import endpoint_contract_id


def _schema(
    fields: dict[str, str | tuple[str, str | None]], required: list[str] | None = None
) -> dict[str, object]:
    properties: dict[str, dict[str, str]] = {}
    for name, value in fields.items():
        if isinstance(value, tuple):
            type_name, format_name = value
            properties[name] = {"type": type_name}
            if format_name is not None:
                properties[name]["format"] = format_name
        else:
            properties[name] = {"type": value}
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
    }


def _endpoint(
    method: str,
    path: str,
    *,
    direction: str = "exposed",
    request_fields: dict[str, str | tuple[str, str | None]] | None = None,
    request_required: list[str] | None = None,
    request_optional: list[str] | None = None,
    response_fields: dict[str, str | tuple[str, str | None]] | None = None,
    response_optional: list[str] | None = None,
    response_statuses: list[int] | None = None,
    request_content_type: str | None = "application/json",
    response_content_type: str | None = "application/json",
    parameters: list[dict[str, object]] | None = None,
    behavior: dict[str, object] | None = None,
    auth_required: bool | None = False,
    auth_mechanism: str | None = None,
    authorization: str | None = None,
    auth_schemes: list[str] | None = None,
    contract_status: str = "complete",
    semantic_status: str = "complete",
    status_code_compatibility: dict[str, str] | None = None,
    additional_fields_backward_compatible: bool | None = None,
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
        "parameters": parameters or [],
        "request": {
            "parameters": [],
            "content_type": request_content_type,
            "body_schema": _schema(request_fields, request_required),
            "fields": sorted(request_fields),
            "required_fields": request_required or [],
            "optional_fields": request_optional or [],
            "unknown_requiredness_fields": [],
            "evidence": [],
            "unresolved": [],
        },
        "response": {
            "status_codes": response_statuses or [200],
            "content_type": response_content_type,
            "schema": _schema(response_fields, sorted(response_fields)),
            "fields": sorted(response_fields),
            "required_fields": sorted(set(response_fields) - set(response_optional or [])),
            "optional_fields": response_optional or [],
            "unknown_requiredness_fields": [],
            "additional_fields_backward_compatible": additional_fields_backward_compatible,
            "fields_used_by_consumer": [],
            "tolerates_additional_fields": True,
            "tolerates_additional_statuses": True,
            "status_code_compatibility": status_code_compatibility,
            "evidence": [],
            "unresolved": [],
        },
        "headers": [],
        "authentication": {
            "authentication": auth_mechanism or ("jwt" if auth_required else None),
            "authorization": authorization,
            "credential_format": None,
            "scheme": None,
            "schemes": auth_schemes or [],
            "header_semantics": None,
            "required": auth_required,
            "evidence": [],
            "unresolved": [],
        },
        "security": {"policy": "unknown", "drift": []},
        "behavior": behavior or {"summary": "fixture", "data_access": [], "auth_context": {"consumed_jwt_claims": [], "produced_jwt_claims": []}, "local_calls": [], "outbound_integrations": [], "conditions": [], "side_effects": [], "response_semantics": {}},
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
            self.assertTrue(payload["artifact_equal"])
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

    def test_path_parameter_removed_is_breaking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            parameter = {"name": "id", "location": "path", "required": True, "schema": {"type": "string"}, "evidence": []}
            _catalog(reference, [_endpoint("GET", "/items/{}", parameters=[parameter])], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/items/{}")], repo="candidate")

            payload = build_api_compatibility(reference, candidate)

            self.assertEqual(payload["records"][0]["classification"], "breaking")
            self.assertIn("path_parameter_removed", [item["code"] for item in payload["records"][0]["findings"]])

    def test_path_parameter_incompatible_type_is_breaking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            _catalog(reference, [_endpoint("GET", "/items/{}", parameters=[{"name": "id", "location": "path", "required": True, "schema": {"type": "integer"}, "evidence": []}])], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/items/{}", parameters=[{"name": "id", "location": "path", "required": True, "schema": {"type": "string"}, "evidence": []}])], repo="candidate")

            payload = build_api_compatibility(reference, candidate)

            self.assertEqual(payload["records"][0]["classification"], "breaking")
            self.assertIn("path_parameter_incompatible_type", [item["code"] for item in payload["records"][0]["findings"]])

    def test_type_and_format_are_compared_independently_for_fields_and_parameters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            _catalog(reference, [_endpoint("POST", "/items", request_fields={"id": ("string", "uuid")}, request_required=["id"], response_fields={"email": ("string", "email")})], repo="reference")
            _catalog(candidate, [_endpoint("POST", "/items", request_fields={"id": ("string", "date-time")}, request_required=["id"], response_fields={"email": ("string", "uri")})], repo="candidate")

            payload = build_api_compatibility(reference, candidate)
            codes = [item["code"] for item in payload["records"][0]["findings"]]

            self.assertEqual(payload["records"][0]["classification"], "breaking")
            self.assertIn("request_field_format_changed", codes)
            self.assertIn("response_field_format_changed", codes)

            reference_param = {"name": "id", "location": "path", "required": True, "schema": {"type": "string", "format": "uuid"}, "evidence": []}
            candidate_param = {"name": "id", "location": "path", "required": True, "schema": {"type": "string", "format": "date-time"}, "evidence": []}
            _catalog(reference, [_endpoint("GET", "/items/{}", parameters=[reference_param])], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/items/{}", parameters=[candidate_param])], repo="candidate")
            self.assertIn("path_parameter_incompatible_format", [item["code"] for item in build_api_compatibility(reference, candidate)["records"][0]["findings"]])

    def test_format_unknown_when_material_and_same_format_is_same(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            _catalog(reference, [_endpoint("GET", "/items", response_fields={"id": ("string", "uuid")})], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/items", response_fields={"id": ("string", None)})], repo="candidate")
            unknown = build_api_compatibility(reference, candidate)
            self.assertEqual(unknown["records"][0]["classification"], "unknown")
            self.assertIn("response_field_format_unknown", [item["code"] for item in unknown["records"][0]["findings"]])

            _catalog(candidate, [_endpoint("GET", "/items", response_fields={"id": ("string", "uuid")})], repo="candidate")
            self.assertEqual(build_api_compatibility(reference, candidate)["records"][0]["classification"], "same")

    def test_required_query_parameter_added_is_breaking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            _catalog(reference, [_endpoint("GET", "/items")], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/items", parameters=[{"name": "filter", "location": "query", "required": True, "schema": {"type": "string"}, "evidence": []}])], repo="candidate")

            payload = build_api_compatibility(reference, candidate)

            self.assertEqual(payload["records"][0]["classification"], "breaking")
            self.assertIn("required_parameter_added", [item["code"] for item in payload["records"][0]["findings"]])

    def test_optional_query_parameter_added_is_additive_only_when_proven(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            _catalog(reference, [_endpoint("GET", "/items")], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/items", parameters=[{"name": "filter", "location": "query", "required": False, "schema": {"type": "string"}, "evidence": []}])], repo="candidate")

            payload = build_api_compatibility(reference, candidate)

            self.assertEqual(payload["records"][0]["classification"], "additive")
            self.assertIn("optional_query_parameter_added", [item["code"] for item in payload["records"][0]["findings"]])

    def test_required_header_added_is_breaking_and_unknown_header_stays_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            _catalog(reference, [_endpoint("GET", "/items")], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/items", parameters=[{"name": "X-Tenant", "location": "header", "required": True, "schema": {"type": "string"}, "evidence": []}])], repo="candidate")
            self.assertEqual(build_api_compatibility(reference, candidate)["records"][0]["classification"], "breaking")

            _catalog(candidate, [_endpoint("GET", "/items", parameters=[{"name": "X-Tenant", "location": "header", "required": None, "schema": {"type": "string"}, "evidence": []}])], repo="candidate")
            payload = build_api_compatibility(reference, candidate)
            self.assertEqual(payload["records"][0]["classification"], "unknown")
            self.assertIn("header_compatibility_unknown", [item["code"] for item in payload["records"][0]["findings"]])

    def test_request_and_response_media_type_incompatibility_are_breaking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            _catalog(reference, [_endpoint("POST", "/items", request_fields={"id": "string"}, response_fields={"id": "string"})], repo="reference")
            _catalog(candidate, [_endpoint("POST", "/items", request_fields={"id": "string"}, response_fields={"id": "string"}, request_content_type="application/xml")], repo="candidate")
            self.assertIn("request_content_type_incompatible", [item["code"] for item in build_api_compatibility(reference, candidate)["records"][0]["findings"]])

            _catalog(candidate, [_endpoint("POST", "/items", request_fields={"id": "string"}, response_fields={"id": "string"}, response_content_type="application/xml")], repo="candidate")
            self.assertIn("response_content_type_incompatible", [item["code"] for item in build_api_compatibility(reference, candidate)["records"][0]["findings"]])

    def test_absent_content_type_is_unknown_only_when_body_material(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            _catalog(reference, [_endpoint("GET", "/health", request_content_type=None, response_content_type=None)], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/health", request_content_type=None, response_content_type=None)], repo="candidate")

            payload = build_api_compatibility(reference, candidate)

            codes = [item["code"] for item in payload["records"][0]["findings"]]
            self.assertNotIn("request_content_type_unknown", codes)
            self.assertNotIn("response_content_type_unknown", codes)

    def test_auth_mechanism_mismatch_is_breaking_even_when_required_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            _catalog(reference, [_endpoint("GET", "/secure", auth_required=True, auth_mechanism="jwt", authorization="raw", auth_schemes=["raw-jwt"])], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/secure", auth_required=True, auth_mechanism="jwt", authorization="bearer", auth_schemes=["bearer"])], repo="candidate")

            payload = build_api_compatibility(reference, candidate)

            self.assertEqual(payload["records"][0]["classification"], "breaking")
            self.assertIn("auth_mechanism_incompatible", [item["code"] for item in payload["records"][0]["findings"]])

    def test_auth_mechanism_unknown_remains_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            _catalog(reference, [_endpoint("GET", "/secure", auth_required=True, auth_mechanism="jwt")], repo="reference")
            unknown = _endpoint("GET", "/secure", auth_required=True)
            unknown["authentication"]["authentication"] = None
            _catalog(candidate, [unknown], repo="candidate")

            payload = build_api_compatibility(reference, candidate)

            self.assertEqual(payload["records"][0]["classification"], "unknown")
            self.assertIn("auth_mechanism_compatibility_unknown", [item["code"] for item in payload["records"][0]["findings"]])

    def test_request_field_additions_require_requiredness_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            _catalog(reference, [_endpoint("POST", "/items", request_fields={"id": "string"}, request_required=["id"])], repo="reference")
            _catalog(candidate, [_endpoint("POST", "/items", request_fields={"id": "string", "comment": "string"}, request_required=["id", "comment"])], repo="candidate")
            self.assertIn("required_request_field_added", [item["code"] for item in build_api_compatibility(reference, candidate)["records"][0]["findings"]])

            _catalog(candidate, [_endpoint("POST", "/items", request_fields={"id": "string", "comment": "string"}, request_required=["id"], request_optional=["comment"])], repo="candidate")
            optional = build_api_compatibility(reference, candidate)
            self.assertEqual(optional["records"][0]["classification"], "additive")
            self.assertIn("optional_request_field_added", [item["code"] for item in optional["records"][0]["findings"]])

            unknown_endpoint = _endpoint("POST", "/items", request_fields={"id": "string", "comment": "string"}, request_required=["id"])
            unknown_endpoint["request"]["unknown_requiredness_fields"] = ["comment"]
            _catalog(candidate, [unknown_endpoint], repo="candidate")
            unknown = build_api_compatibility(reference, candidate)
            self.assertEqual(unknown["records"][0]["classification"], "unknown")

    def test_response_field_additions_require_compatibility_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            reference_endpoint = _endpoint("GET", "/items", response_fields={"id": "string"})
            reference_endpoint["response"]["tolerates_additional_fields"] = None
            _catalog(reference, [reference_endpoint], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/items", response_fields={"id": "string", "description": "string"}, response_optional=["description"])], repo="candidate")
            unknown = build_api_compatibility(reference, candidate)
            self.assertEqual(unknown["records"][0]["classification"], "unknown")

            _catalog(candidate, [_endpoint("GET", "/items", response_fields={"id": "string", "description": "string"}, response_optional=["description"], additional_fields_backward_compatible=True)], repo="candidate")
            additive = build_api_compatibility(reference, candidate)
            self.assertEqual(additive["records"][0]["classification"], "additive")
            self.assertIn("response_fields_added_compatible", [item["code"] for item in additive["records"][0]["findings"]])

    def test_material_behavior_contradiction_and_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            write_effect = {"summary": "fixture", "data_access": [], "auth_context": {"consumed_jwt_claims": [], "produced_jwt_claims": []}, "local_calls": [], "outbound_integrations": [], "conditions": [], "side_effects": [{"type": "write", "target": "a"}], "response_semantics": {}}
            other_effect = {"summary": "fixture", "data_access": [], "auth_context": {"consumed_jwt_claims": [], "produced_jwt_claims": []}, "local_calls": [], "outbound_integrations": [], "conditions": [], "side_effects": [{"type": "write", "target": "b"}], "response_semantics": {}}
            _catalog(reference, [_endpoint("POST", "/items", behavior=write_effect)], repo="reference")
            _catalog(candidate, [_endpoint("POST", "/items", behavior=other_effect)], repo="candidate")
            self.assertEqual(build_api_compatibility(reference, candidate)["records"][0]["classification"], "breaking")

            _catalog(candidate, [_endpoint("POST", "/items", behavior=other_effect, semantic_status="unknown")], repo="candidate")
            self.assertEqual(build_api_compatibility(reference, candidate)["records"][0]["classification"], "unknown")

    def test_internal_semantic_drift_is_reported_without_api_breaking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            reference_behavior = {"summary": "fixture", "data_access": [{"table": "a"}], "auth_context": {"consumed_jwt_claims": [], "produced_jwt_claims": []}, "local_calls": ["A"], "outbound_integrations": [], "conditions": [], "side_effects": [], "response_semantics": {"success": "returns id"}}
            candidate_behavior = {"summary": "fixture", "data_access": [{"table": "b"}], "auth_context": {"consumed_jwt_claims": [], "produced_jwt_claims": []}, "local_calls": ["B"], "outbound_integrations": [], "conditions": [], "side_effects": [], "response_semantics": {"success": "returns id"}}
            _catalog(reference, [_endpoint("GET", "/items", behavior=reference_behavior)], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/items", behavior=candidate_behavior)], repo="candidate")

            payload = build_api_compatibility(reference, candidate)

            self.assertEqual(payload["records"][0]["classification"], "same")
            self.assertIn("internal_semantic_drift_reported", [item["code"] for item in payload["records"][0]["findings"]])

    def test_response_semantics_incompatible_or_additional_are_external_contract_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            reference_behavior = {"summary": "fixture", "data_access": [], "auth_context": {"consumed_jwt_claims": [], "produced_jwt_claims": []}, "local_calls": [], "outbound_integrations": [], "conditions": [], "side_effects": [], "response_semantics": {"success": "returns id"}}
            incompatible_behavior = {"summary": "fixture", "data_access": [], "auth_context": {"consumed_jwt_claims": [], "produced_jwt_claims": []}, "local_calls": [], "outbound_integrations": [], "conditions": [], "side_effects": [], "response_semantics": {"success": "returns error"}}
            _catalog(reference, [_endpoint("GET", "/items", behavior=reference_behavior)], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/items", behavior=incompatible_behavior)], repo="candidate")
            self.assertEqual(build_api_compatibility(reference, candidate)["records"][0]["classification"], "breaking")

            additive_behavior = {"summary": "fixture", "data_access": [], "auth_context": {"consumed_jwt_claims": [], "produced_jwt_claims": []}, "local_calls": [], "outbound_integrations": [], "conditions": [], "side_effects": [], "response_semantics": {"success": "returns id", "cache": "may include etag"}}
            _catalog(candidate, [_endpoint("GET", "/items", behavior=additive_behavior)], repo="candidate")
            self.assertEqual(build_api_compatibility(reference, candidate)["records"][0]["classification"], "additive")

    def test_external_side_effect_additions_require_compatibility_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            base = {"summary": "fixture", "data_access": [], "auth_context": {"consumed_jwt_claims": [], "produced_jwt_claims": []}, "local_calls": [], "outbound_integrations": [], "conditions": [], "side_effects": [], "response_semantics": {}}
            unknown_effect = dict(base)
            unknown_effect["side_effects"] = [{"type": "webhook", "target": "external"}]
            _catalog(reference, [_endpoint("POST", "/items", behavior=base)], repo="reference")
            _catalog(candidate, [_endpoint("POST", "/items", behavior=unknown_effect)], repo="candidate")
            unknown = build_api_compatibility(reference, candidate)
            self.assertEqual(unknown["records"][0]["classification"], "unknown")
            self.assertIn("external_side_effect_added_unknown", [item["code"] for item in unknown["records"][0]["findings"]])

            compatible_effect = dict(base)
            compatible_effect["side_effects"] = [{"type": "webhook", "target": "external", "compatibility": "compatible"}]
            _catalog(candidate, [_endpoint("POST", "/items", behavior=compatible_effect)], repo="candidate")
            self.assertEqual(build_api_compatibility(reference, candidate)["records"][0]["classification"], "additive")

            breaking_effect = dict(base)
            breaking_effect["side_effects"] = [{"type": "webhook", "target": "external", "compatibility": "breaking"}]
            _catalog(candidate, [_endpoint("POST", "/items", behavior=breaking_effect)], repo="candidate")
            self.assertEqual(build_api_compatibility(reference, candidate)["records"][0]["classification"], "breaking")

    def test_internal_only_semantic_partial_does_not_block_api_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            behavior = {"summary": "fixture", "semantic_partial_scope": "internal", "data_access": [], "auth_context": {"consumed_jwt_claims": [], "produced_jwt_claims": []}, "local_calls": [], "outbound_integrations": [], "conditions": [], "side_effects": [], "response_semantics": {"success": "returns id"}}
            _catalog(reference, [_endpoint("GET", "/items", behavior=behavior, semantic_status="partial")], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/items", behavior=behavior, semantic_status="partial")], repo="candidate")
            self.assertEqual(build_api_compatibility(reference, candidate)["records"][0]["classification"], "same")

    def test_external_or_unknown_semantic_partial_blocks_api_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            external = {"summary": "fixture", "semantic_partial_scope": "external", "data_access": [], "auth_context": {"consumed_jwt_claims": [], "produced_jwt_claims": []}, "local_calls": [], "outbound_integrations": [], "conditions": [], "side_effects": [], "response_semantics": {}}
            unknown = {"summary": "fixture", "data_access": [], "auth_context": {"consumed_jwt_claims": [], "produced_jwt_claims": []}, "local_calls": [], "outbound_integrations": [], "conditions": [], "side_effects": [], "response_semantics": {}}
            _catalog(reference, [_endpoint("GET", "/items", behavior=external, semantic_status="partial")], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/items", behavior=external, semantic_status="partial")], repo="candidate")
            self.assertEqual(build_api_compatibility(reference, candidate)["records"][0]["classification"], "unknown")

            _catalog(reference, [_endpoint("GET", "/items", behavior=unknown, semantic_status="partial")], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/items", behavior=unknown, semantic_status="partial")], repo="candidate")
            self.assertEqual(build_api_compatibility(reference, candidate)["records"][0]["classification"], "unknown")

    def test_inputs_are_traceable_and_policy_changes_comparison_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            _catalog(reference, [_endpoint("GET", "/items")], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/items")], repo="candidate")

            loose = build_api_compatibility(reference, candidate, enforce_security_policy=False)
            strict = build_api_compatibility(reference, candidate, enforce_security_policy=True)

            self.assertNotEqual(loose["comparison_id"], strict["comparison_id"])
            self.assertEqual(loose["inputs"]["reference"]["repository_id"], "reference")
            self.assertEqual(loose["inputs"]["candidate"]["source_ref"], "main")
            self.assertEqual(len(loose["inputs"]["reference"]["sha256"]), 64)
            self.assertIn("security_drift", loose["summary"])

    def test_summary_contains_complete_output_contract_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            _catalog(reference, [_endpoint("GET", "/same"), _endpoint("GET", "/removed")], repo="reference")
            _catalog(candidate, [_endpoint("GET", "/same"), _endpoint("GET", "/added")], repo="candidate")

            summary = build_api_compatibility(reference, candidate)["summary"]

            for key in (
                "reference_endpoints",
                "candidate_endpoints",
                "scoped_reference_endpoints",
                "required_reference_endpoints",
                "excluded_reference_endpoints",
                "same",
                "additive",
                "breaking",
                "unknown",
                "artifact_equal_endpoints",
                "observed_equal_endpoints",
                "removed_endpoints",
                "added_endpoints",
                "changed_endpoints",
                "security_drift",
                "unresolved",
            ):
                self.assertIn(key, summary)

    def test_artifact_equal_ignores_key_order_and_volatile_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            endpoint = _endpoint("GET", "/items", response_fields={"id": "string"})
            _catalog(reference, [endpoint], repo="same")
            payload = json.loads(reference.read_text(encoding="utf-8"))
            payload["generated_at"] = "2026-08-28T12:00:00+00:00"
            payload["catalog_id"] = "catalog-other"
            candidate.write_text(json.dumps(payload, sort_keys=False), encoding="utf-8")

            self.assertTrue(build_api_compatibility(reference, candidate)["artifact_equal"])

            payload["endpoints"][0]["response"]["fields"] = ["different"]
            candidate.write_text(json.dumps(payload), encoding="utf-8")
            self.assertFalse(build_api_compatibility(reference, candidate)["artifact_equal"])

    def test_duplicate_reference_or_candidate_identity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            endpoint = _endpoint("GET", "/items")
            duplicate = dict(endpoint)
            duplicate["endpoint_id"] = "duplicate-id"
            _catalog(reference, [endpoint], repo="reference")
            _catalog(candidate, [endpoint, duplicate], repo="candidate")

            with self.assertRaises(ApiCompatibilityError):
                build_api_compatibility(reference, candidate)

            _catalog(reference, [endpoint, duplicate], repo="reference")
            _catalog(candidate, [endpoint], repo="candidate")
            with self.assertRaises(ApiCompatibilityError):
                build_api_compatibility(reference, candidate)


if __name__ == "__main__":
    unittest.main()
