from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from asgard_api_auditor.api_compatibility import build_api_compatibility
from asgard_api_auditor.catalog import build_api_catalog
from asgard_api_auditor.consumer_compatibility import build_consumer_compatibility


EVIDENCE = [{"path": "api.php", "line": 1, "kind": "route", "note": "fixture"}]


def _coverage() -> dict[str, object]:
    return {
        "inventory_complete": True,
        "languages": [],
        "frameworks": [],
        "http_clients": [],
        "required_detector_categories": [],
        "detectors": [],
        "files_scanned": 0,
        "files_excluded": 0,
        "exclusion_rules": [],
        "unsupported_surfaces": [],
    }


def _schema(fields: dict[str, str], required: list[str] | None = None) -> dict[str, object]:
    return {
        "type": "object",
        "properties": {name: {"type": type_name} for name, type_name in fields.items()},
        "required": required or [],
    }


def _behavior(
    *,
    semantic_status: str = "complete",
    materiality: str | None = None,
    side_effects: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "semantic_status": semantic_status,
        "confidence": "confirmed",
        "summary": "fixture behavior",
        "source_module": "api.php",
        "tags": [],
        "request_fields": [],
        "data_access": [],
        "auth_context": {"consumed_jwt_claims": [], "produced_jwt_claims": []},
        "local_calls": [],
        "outbound_integrations": [],
        "conditions": [],
        "response_semantics": {
            "http_status_codes": [200],
            "body_fields": ["id"],
            "functional_body_fields": [],
        },
        "side_effects": side_effects or [],
        "unresolved": [],
        "evidence": EVIDENCE,
    }
    if materiality is not None:
        payload["semantic_partial_materiality"] = materiality
    return payload


def _endpoint(
    direction: str,
    method: str = "GET",
    path: str = "/items",
    *,
    request: dict[str, object] | None = None,
    response: dict[str, object] | None = None,
    behavior: dict[str, object] | None = None,
    authentication: str = "jwt",
    authorization: str = "raw",
    credential_format: str = "raw_jwt",
    scheme: str | None = None,
    header_semantics: str = "raw_authorization_header",
) -> dict[str, object]:
    return {
        "endpoint_id": f"{direction}-{method}-{path}".replace("/", "-"),
        "direction": direction,
        "surface_type": "http",
        "method": method,
        "path": path,
        "authentication": authentication,
        "authorization": authorization,
        "credential_format": credential_format,
        "scheme": scheme,
        "header_semantics": header_semantics,
        "request": request
        or {
            "parameters": [],
            "content_type": None,
            "body_schema": None,
            "fields": [],
        },
        "response": response
        or {
            "status_codes": [200],
            "content_type": "application/json",
            "schema": _schema({"id": "string"}, ["id"]),
            "fields": ["id"],
        },
        "behavior": behavior or _behavior(),
        "confidence": "confirmed",
        "confidence_reason": "fixture",
        "evidence": EVIDENCE,
        "notes": ["contract_enrichment_status=evaluated_complete"],
    }


def _write_findings(path: Path, endpoints: list[dict[str, object]], *, repo: str) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "2.0",
                "audit_id": f"audit-{repo}",
                "auditor_version": "0.8.0",
                "repository": repo,
                "repository_id": repo,
                "source_ref": "main",
                "source_commit": "a" * 40,
                "audit_timestamp": "2026-08-27T00:00:00+00:00",
                "status": "complete",
                "coverage": _coverage(),
                "endpoints": endpoints,
                "integration_surfaces": [],
                "unresolved": [],
                "artifacts": {
                    "openapi.yaml": {"status": "validated"},
                    "api-knowledge.md": {"status": "validated"},
                    "audit-report.md": {"status": "validated"},
                },
            }
        ),
        encoding="utf-8",
    )


def _catalog_file(root: Path, findings_name: str, endpoints: list[dict[str, object]]) -> Path:
    findings = root / f"{findings_name}-findings.json"
    catalog = root / f"{findings_name}-catalog.json"
    _write_findings(findings, endpoints, repo=findings_name)
    catalog.write_text(json.dumps(build_api_catalog(findings)), encoding="utf-8")
    return catalog


class CatalogFactPipelineTests(unittest.TestCase):
    def test_raw_jwt_vs_bearer_auth_incompatibility_flows_from_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = _catalog_file(root, "reference", [_endpoint("exposed")])
            candidate = _catalog_file(
                root,
                "candidate",
                [
                    _endpoint(
                        "exposed",
                        authorization="bearer",
                        credential_format="bearer_token",
                        scheme="bearer",
                        header_semantics="authorization_bearer",
                    )
                ],
            )

            payload = build_api_compatibility(reference, candidate)
            codes = [item["code"] for item in payload["records"][0]["findings"]]

            self.assertEqual(payload["records"][0]["classification"], "breaking")
            self.assertIn("auth_mechanism_incompatible", codes)

    def test_semantic_partial_materiality_is_preserved_from_valid_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            internal = _catalog_file(
                root,
                "internal",
                [
                    _endpoint(
                        "exposed",
                        behavior=_behavior(
                            semantic_status="partial",
                            materiality="internal",
                        ),
                    )
                ],
            )
            internal_catalog = json.loads(internal.read_text(encoding="utf-8"))
            self.assertEqual(
                internal_catalog["endpoints"][0]["behavior"]["semantic_partial_materiality"],
                "internal",
            )
            self.assertEqual(
                build_api_compatibility(internal, internal)["records"][0]["classification"],
                "same",
            )

            external = _catalog_file(
                root,
                "external",
                [
                    _endpoint(
                        "exposed",
                        behavior=_behavior(
                            semantic_status="partial",
                            materiality="external",
                        ),
                    )
                ],
            )
            self.assertEqual(
                build_api_compatibility(external, external)["records"][0]["classification"],
                "unknown",
            )

            unproven = _catalog_file(
                root,
                "unproven",
                [_endpoint("exposed", behavior=_behavior(semantic_status="partial"))],
            )
            self.assertEqual(
                build_api_compatibility(unproven, unproven)["records"][0]["classification"],
                "unknown",
            )

    def test_response_tolerance_requires_findings_fact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = _catalog_file(root, "reference", [_endpoint("exposed")])
            candidate_response = {
                "status_codes": [200],
                "content_type": "application/json",
                "schema": _schema(
                    {"id": "string", "description": "string"},
                    ["id"],
                )
                | {"x-asgard-optional-fields": ["description"]},
                "fields": ["id", "description"],
            }
            candidate = _catalog_file(
                root,
                "candidate",
                [_endpoint("exposed", response=candidate_response)],
            )
            self.assertEqual(
                build_api_compatibility(reference, candidate)["records"][0]["classification"],
                "unknown",
            )

            candidate_response["additional_fields_backward_compatible"] = True
            compatible = _catalog_file(
                root,
                "compatible",
                [_endpoint("exposed", response=candidate_response)],
            )
            self.assertEqual(
                build_api_compatibility(reference, compatible)["records"][0]["classification"],
                "additive",
            )

    def test_side_effect_compatibility_requires_findings_fact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = _catalog_file(root, "reference", [_endpoint("exposed")])
            side_effect = {"id": "side-effect", "type": "webhook", "target": "external", "evidence": EVIDENCE}
            unknown = _catalog_file(
                root,
                "unknown",
                [_endpoint("exposed", behavior=_behavior(side_effects=[side_effect]))],
            )
            self.assertEqual(
                build_api_compatibility(reference, unknown)["records"][0]["classification"],
                "unknown",
            )

            compatible_effect = dict(side_effect)
            compatible_effect["compatibility"] = "compatible"
            compatible = _catalog_file(
                root,
                "compatible",
                [_endpoint("exposed", behavior=_behavior(side_effects=[compatible_effect]))],
            )
            self.assertEqual(
                build_api_compatibility(reference, compatible)["records"][0]["classification"],
                "additive",
            )

            incompatible_effect = dict(side_effect)
            incompatible_effect["compatibility"] = "incompatible"
            incompatible = _catalog_file(
                root,
                "incompatible",
                [_endpoint("exposed", behavior=_behavior(side_effects=[incompatible_effect]))],
            )
            self.assertEqual(
                build_api_compatibility(reference, incompatible)["records"][0]["classification"],
                "breaking",
            )

    def test_provider_request_and_response_tolerance_flow_from_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            consumer_request = {
                "parameters": [
                    {
                        "name": "trace",
                        "location": "query",
                        "required": False,
                        "schema": {"type": "string"},
                        "evidence": EVIDENCE,
                    }
                ],
                "content_type": None,
                "body_schema": None,
                "fields": [],
            }
            provider_request = {
                "parameters": [],
                "content_type": None,
                "body_schema": None,
                "fields": [],
            }
            provider_response = {
                "status_codes": [200, 202],
                "content_type": "application/json",
                "schema": _schema({"id": "string"}, ["id"]),
                "fields": ["id"],
            }
            consumer = _catalog_file(
                root,
                "consumer",
                [_endpoint("consumed", request=consumer_request)],
            )
            provider = _catalog_file(
                root,
                "provider",
                [
                    _endpoint(
                        "exposed",
                        request=provider_request,
                        response=provider_response,
                    )
                ],
            )
            self.assertEqual(
                build_consumer_compatibility([consumer], [provider])["records"][0]["status"],
                "unknown",
            )

            provider_request["accepts_additional_parameters"] = True
            consumer_response = {
                "status_codes": [200],
                "content_type": "application/json",
                "schema": _schema({"id": "string"}, ["id"]),
                "fields": ["id"],
                "fields_used_by_consumer": ["id"],
                "tolerates_additional_statuses": True,
            }
            consumer = _catalog_file(
                root,
                "consumer-compatible",
                [_endpoint("consumed", request=consumer_request, response=consumer_response)],
            )
            provider = _catalog_file(
                root,
                "provider-compatible",
                [
                    _endpoint(
                        "exposed",
                        request=provider_request,
                        response=provider_response,
                    )
                ],
            )
            self.assertEqual(
                build_consumer_compatibility([consumer], [provider])["records"][0]["status"],
                "compatible",
            )


if __name__ == "__main__":
    unittest.main()
