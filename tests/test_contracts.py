import json
import unittest
from pathlib import Path

from asgard_api_auditor.constants import (
    API_CATALOG_SCHEMA_VERSION,
    API_COMPATIBILITY_SCHEMA_VERSION,
    CONSUMER_COMPATIBILITY_SCHEMA_VERSION,
    FINDINGS_SCHEMA_VERSION,
    OPENAPI_VERSION,
)

ROOT = Path(__file__).resolve().parents[1]


class ContractTests(unittest.TestCase):
    def test_findings_schema_is_valid_json_and_versioned(self) -> None:
        schema = json.loads((ROOT / "schemas/findings.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["schema_version"]["const"], FINDINGS_SCHEMA_VERSION)

    def test_findings_schema_supports_impact_analysis_fields(self) -> None:
        schema = json.loads((ROOT / "schemas/findings.schema.json").read_text(encoding="utf-8"))
        response = schema["$defs"]["response"]["properties"]
        self.assertIn("fields_used_by_consumer", response)
        endpoint_required = schema["$defs"]["endpoint"]["required"]
        self.assertIn("endpoint_id", endpoint_required)
        evidence_kinds = schema["$defs"]["evidence"]["properties"]["kind"]["enum"]
        self.assertIn("integration", evidence_kinds)

    def test_findings_schema_has_coverage_gate_fields(self) -> None:
        schema = json.loads((ROOT / "schemas/findings.schema.json").read_text(encoding="utf-8"))
        coverage_required = schema["$defs"]["coverage"]["required"]
        self.assertIn("inventory_complete", coverage_required)
        self.assertIn("required_detector_categories", coverage_required)
        self.assertIn("unsupported_surfaces", coverage_required)
        coverage_properties = schema["$defs"]["coverage"]["properties"]
        self.assertIn("contract_enrichment", coverage_properties)
        enrichment_required = schema["$defs"]["contractEnrichmentCoverage"]["required"]
        self.assertIn("request_enriched", enrichment_required)
        self.assertIn("unresolved_contract_enrichment", enrichment_required)

    def test_openapi_template_uses_approved_version(self) -> None:
        text = (ROOT / "templates/openapi.yaml").read_text(encoding="utf-8")
        self.assertIn(f"openapi: {OPENAPI_VERSION}", text)

    def test_v08_schemas_are_valid_json_and_versioned(self) -> None:
        expectations = {
            "api-catalog.schema.json": API_CATALOG_SCHEMA_VERSION,
            "api-compatibility.schema.json": API_COMPATIBILITY_SCHEMA_VERSION,
            "consumer-compatibility.schema.json": CONSUMER_COMPATIBILITY_SCHEMA_VERSION,
        }
        for name, version in expectations.items():
            with self.subTest(schema=name):
                schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
                self.assertEqual(schema["properties"]["schema_version"]["const"], version)


if __name__ == "__main__":
    unittest.main()
