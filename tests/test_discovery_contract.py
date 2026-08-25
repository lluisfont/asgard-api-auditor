from __future__ import annotations

import json
import unittest
from pathlib import Path

from asgard_api_auditor.constants import ENDPOINT_DISCOVERY_SCHEMA_VERSION

ROOT = Path(__file__).resolve().parents[1]


class EndpointDiscoveryContractTests(unittest.TestCase):
    def test_schema_is_valid_json_and_versioned(self) -> None:
        schema = json.loads((ROOT / "schemas" / "endpoint-discovery.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["schema_version"]["const"], ENDPOINT_DISCOVERY_SCHEMA_VERSION)

    def test_schema_requires_provenance_coverage_and_unresolved(self) -> None:
        schema = json.loads((ROOT / "schemas" / "endpoint-discovery.schema.json").read_text(encoding="utf-8"))
        required = set(schema["required"])
        self.assertTrue({
            "repository_id",
            "source_ref",
            "source_commit",
            "inventory_complete",
            "discovery_complete",
            "soap_operations_complete",
            "soap_contracts_complete",
            "soap_services",
            "soap_operations",
            "endpoints",
            "integrations",
            "detectors",
            "unresolved",
        }.issubset(required))


if __name__ == "__main__":
    unittest.main()
