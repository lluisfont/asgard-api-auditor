from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from asgard_api_auditor.catalog import build_api_catalog


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


def _endpoint(direction: str, method: str, path: str, *, api_id: str | None = None) -> dict[str, object]:
    payload: dict[str, object] = {
        "endpoint_id": f"source-{direction}-{method}-{path}".replace("/", "-"),
        "direction": direction,
        "surface_type": "http",
        "method": method,
        "path": path,
        "confidence": "confirmed",
        "confidence_reason": "fixture",
        "evidence": [{"path": "api.php", "line": 3, "kind": "route"}],
        "notes": ["contract_enrichment_status=evaluated_complete"],
    }
    if api_id is not None:
        payload["api_id"] = api_id
    return payload


def _write_findings(path: Path, endpoints: list[dict[str, object]]) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "2.0",
                "audit_id": "audit-catalog-fixture",
                "auditor_version": "0.8.0",
                "repository": "fixture",
                "repository_id": "fixture",
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


class ApiCatalogTests(unittest.TestCase):
    def test_catalog_preserves_endpoint_direction_without_provider_conversion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings = Path(tmp) / "findings.json"
            _write_findings(
                findings,
                [
                    _endpoint("exposed", "GET", "/items/{id}"),
                    _endpoint("consumed", "POST", "/events"),
                ],
            )

            catalog = build_api_catalog(findings)

            self.assertEqual(catalog["coverage"]["exposed_endpoints"], 1)
            self.assertEqual(catalog["coverage"]["consumed_endpoints"], 1)
            self.assertEqual([item["direction"] for item in catalog["endpoints"]], ["consumed", "exposed"])

    def test_endpoint_id_does_not_change_when_api_id_becomes_known(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            without_api = root / "without.json"
            with_api = root / "with.json"
            _write_findings(without_api, [_endpoint("exposed", "GET", "/items/{id}")])
            _write_findings(with_api, [_endpoint("exposed", "GET", "/items/{id}", api_id="catalog-group")])

            first = build_api_catalog(without_api)
            second = build_api_catalog(with_api)

            self.assertEqual(first["endpoints"][0]["endpoint_id"], second["endpoints"][0]["endpoint_id"])
            self.assertIsNone(first["endpoints"][0]["api_id"])
            self.assertEqual(second["endpoints"][0]["api_id"], "catalog-group")

    def test_explicit_scope_is_recorded_in_catalog_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings = Path(tmp) / "findings.json"
            _write_findings(
                findings,
                [
                    _endpoint("exposed", "GET", "/included"),
                    _endpoint("exposed", "DELETE", "/excluded"),
                ],
            )

            catalog = build_api_catalog(findings, exclude_endpoints=("DELETE /excluded",))

            self.assertEqual(catalog["scope"]["mode"], "explicit")
            self.assertEqual(catalog["scope"]["excluded_endpoints"], 1)
            excluded = [item for item in catalog["endpoints"] if item["scope"]["status"] == "excluded"]
            self.assertEqual(excluded[0]["path_shape"], "/excluded")


if __name__ == "__main__":
    unittest.main()
