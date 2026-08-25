import json
import tempfile
import unittest
from pathlib import Path

from asgard_api_auditor.artifacts import (
    ArtifactValidationError,
    atomic_publish,
    sha256_file,
    validate_audit_set,
)


class ArtifactTests(unittest.TestCase):
    def _write_valid_set(self, directory: Path, audit_id: str = "audit_12345678") -> None:
        directory.mkdir(parents=True, exist_ok=True)
        repository = "asgard-warehouse"
        commit = "a" * 40
        common = (
            "---\n"
            "document_type: test\n"
            'schema_version: "1.0"\n'
            f"audit_id: {audit_id}\n"
            "auditor_version: 0.2.0\n"
            f"repository: {repository}\n"
            "repository_id: asgard-warehouse\n"
            "source_ref: main\n"
            f"source_commit: {commit}\n"
            "audit_timestamp: 2026-08-25T10:00:00Z\n"
            "audit_status: complete\n"
            "---\n"
        )
        (directory / "api-knowledge.md").write_text(common + "# Knowledge\n", encoding="utf-8")
        (directory / "audit-report.md").write_text(common + "# Report\n", encoding="utf-8")
        (directory / "openapi.yaml").write_text(
            "openapi: 3.1.2\n"
            "info:\n  title: Test\n  version: 1.0.0\n"
            f'x-asgard-audit-id: "{audit_id}"\n'
            f'x-asgard-source-commit: "{commit}"\n'
            "paths: {}\ncomponents:\n  schemas: {}\n",
            encoding="utf-8",
        )
        findings = {
            "schema_version": "2.0",
            "audit_id": audit_id,
            "auditor_version": "0.2.0",
            "repository": repository,
            "repository_id": repository,
            "source_ref": "main",
            "source_commit": commit,
            "audit_timestamp": "2026-08-25T10:00:00Z",
            "status": "complete",
            "coverage": {},
            "endpoints": [],
            "integration_surfaces": [],
            "unresolved": [],
            "artifacts": {
                "openapi.yaml": {
                    "status": "validated",
                    "sha256": sha256_file(directory / "openapi.yaml"),
                    "validation": "redocly",
                },
                "api-knowledge.md": {
                    "status": "validated",
                    "sha256": sha256_file(directory / "api-knowledge.md"),
                    "validation": "shared-metadata",
                },
                "audit-report.md": {
                    "status": "validated",
                    "sha256": sha256_file(directory / "audit-report.md"),
                    "validation": "shared-metadata",
                },
            },
        }
        (directory / "findings.json").write_text(json.dumps(findings), encoding="utf-8")

    def test_valid_audit_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "staging"
            self._write_valid_set(staging)
            metadata = validate_audit_set(staging)
            self.assertEqual(metadata["repository"], "asgard-warehouse")

    def test_missing_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "staging"
            self._write_valid_set(staging)
            (staging / "openapi.yaml").unlink()
            with self.assertRaises(ArtifactValidationError):
                validate_audit_set(staging)

    def test_metadata_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "staging"
            self._write_valid_set(staging)
            report = (staging / "audit-report.md").read_text(encoding="utf-8")
            (staging / "audit-report.md").write_text(
                report.replace("audit_12345678", "audit_wrong000"), encoding="utf-8"
            )
            with self.assertRaises(ArtifactValidationError):
                validate_audit_set(staging)

    def test_failed_candidate_does_not_replace_previous(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous_source = root / "previous-source"
            destination = root / "published"
            self._write_valid_set(previous_source, "audit_previous1")
            atomic_publish(previous_source, destination)

            candidate = root / "candidate"
            self._write_valid_set(candidate, "audit_candidate1")
            (candidate / "openapi.yaml").unlink()
            with self.assertRaises(ArtifactValidationError):
                atomic_publish(candidate, destination)

            text = (destination / "findings.json").read_text(encoding="utf-8")
            self.assertIn("audit_previous1", text)


if __name__ == "__main__":
    unittest.main()
