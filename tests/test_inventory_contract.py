import json
import unittest
from pathlib import Path

from asgard_api_auditor.constants import (
    INVENTORY_SCOPE_VERSION,
    TECHNICAL_INVENTORY_SCHEMA_VERSION,
)

ROOT = Path(__file__).resolve().parents[1]


class InventoryContractTests(unittest.TestCase):
    def test_inventory_schema_versions_are_fixed(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/technical-inventory.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            schema["properties"]["schema_version"]["const"],
            TECHNICAL_INVENTORY_SCHEMA_VERSION,
        )
        self.assertEqual(
            schema["properties"]["scope_version"]["const"],
            INVENTORY_SCOPE_VERSION,
        )

    def test_inventory_schema_requires_provenance_and_coverage(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/technical-inventory.schema.json").read_text(encoding="utf-8")
        )
        required = set(schema["required"])
        for key in (
            "repository_id",
            "source_commit",
            "working_tree_dirty",
            "inventory_complete",
            "manifest_errors",
            "skipped_symlinks",
            "submodules",
            "required_detector_categories",
        ):
            self.assertIn(key, required)


if __name__ == "__main__":
    unittest.main()
