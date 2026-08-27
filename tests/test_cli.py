from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from asgard_api_auditor.cli import main


def _init_repo(root: Path, *, with_supported_api: bool = False) -> Path:
    repo = root / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test User"], check=True)
    if with_supported_api:
        (repo / "package.json").write_text(
            json.dumps({"dependencies": {"axios": "^1.0.0"}}), encoding="utf-8"
        )
        (repo / "api.ts").write_text(
            "import axios from 'axios';\naxios.get('/health');\n", encoding="utf-8"
        )
    else:
        (repo / "app.py").write_text("import requests\n", encoding="utf-8")
        (repo / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
    return repo


def _findings_coverage() -> dict[str, object]:
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


class CliTests(unittest.TestCase):
    def test_inventory_writes_json_to_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(Path(tmp))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["inventory", str(repo)])
            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertTrue(payload["inventory_complete"])
            self.assertEqual(payload["schema_version"], "1.0")

    def test_inventory_atomic_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _init_repo(root)
            output = root / "inventory.json"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main(["inventory", str(repo), "--output", str(output)])
            self.assertEqual(code, 0)
            self.assertTrue(output.exists())
            self.assertEqual(json.loads(output.read_text())["repository"], "repo")

    def test_discover_writes_supported_endpoint_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(Path(tmp), with_supported_api=True)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["discover", str(repo)])
            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertTrue(payload["discovery_complete"])
            self.assertEqual(payload["endpoints"][0]["method"], "GET")
            self.assertEqual(payload["endpoints"][0]["path"], "/health")

    def test_discover_returns_partial_exit_code_for_unsupported_client(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(Path(tmp))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["discover", str(repo)])
            self.assertEqual(code, 3)
            self.assertFalse(json.loads(stdout.getvalue())["discovery_complete"])

    def test_discover_accepts_repeated_exclude_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(Path(tmp), with_supported_api=True)
            (repo / "audit").mkdir()
            (repo / "audit" / "bad.ts").write_text("fetch(buildUrl());\n", encoding="utf-8")
            (repo / "work_sample").mkdir()
            (repo / "work_sample" / "bad.ts").write_text("fetch(buildUrl());\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "excluded fixtures"], check=True)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main([
                    "discover",
                    str(repo),
                    "--exclude-path",
                    "audit",
                    "--exclude-path",
                    "work_sample",
                ])
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(stdout.getvalue())["discovery_complete"])

    def test_full_audit_client_only_generates_complete_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _init_repo(root, with_supported_api=True)
            output = root / "audit-output"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["audit", str(repo), "--output", str(output)])
            self.assertEqual(code, 0)
            self.assertIn("Audit status: complete", stdout.getvalue())
            self.assertTrue((output / "openapi.yaml").is_file())
            self.assertTrue((output / "api-knowledge.md").is_file())
            self.assertTrue((output / "findings.json").is_file())
            self.assertTrue((output / "audit-report.md").is_file())

    def test_full_audit_required_correlation_remains_partial_without_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _init_repo(root, with_supported_api=True)
            output = root / "audit-output"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["audit", str(repo), "--output", str(output), "--require-correlation"])
            self.assertEqual(code, 3)
            self.assertIn("Audit status: partial", stdout.getvalue())
            payload = json.loads((output / "findings.json").read_text(encoding="utf-8"))
            ids = {item["unresolved_id"] for item in payload["unresolved"]}
            self.assertIn("provider-consumer-correlation-required-not-evaluable", ids)

    def test_bare_repository_keeps_backward_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _init_repo(root)
            stdout = io.StringIO()
            with contextlib.chdir(root), contextlib.redirect_stdout(stdout):
                code = main([str(repo)])
            self.assertEqual(code, 3)
            self.assertTrue((root / "output" / "findings.json").is_file())

    def test_correlate_generates_relationship_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = root / "findings.json"
            findings.write_text(
                json.dumps(
                    {
                        "schema_version": "2.0",
                        "audit_id": "audit-repo",
                        "auditor_version": "0.6.0",
                        "repository": "repo",
                        "repository_id": "repo",
                        "source_ref": "main",
                        "source_commit": "a" * 40,
                        "audit_timestamp": "2026-08-26T00:00:00+00:00",
                        "status": "partial",
                        "coverage": _findings_coverage(),
                        "endpoints": [
                            {
                                "endpoint_id": "consumed-get-health",
                                "direction": "consumed",
                                "surface_type": "http",
                                "method": "GET",
                                "path": "/health",
                                "confidence": "confirmed",
                                "confidence_reason": "fixture",
                                "evidence": [{"path": "api.ts", "line": 1, "kind": "http_client"}],
                                "notes": [],
                            }
                        ],
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
            output = root / "relations"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["correlate", "--findings", str(findings), "--output", str(output)])
            self.assertEqual(code, 0)
            self.assertIn("Correlation artifacts written", stdout.getvalue())
            self.assertTrue((output / "correlations.json").is_file())
            self.assertTrue((output / "api-relations.md").is_file())

    def test_catalog_api_command_generates_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = root / "findings.json"
            findings.write_text(
                json.dumps(
                    {
                        "schema_version": "2.0",
                        "audit_id": "audit-repo",
                        "auditor_version": "0.8.0",
                        "repository": "repo",
                        "repository_id": "repo",
                        "source_ref": "main",
                        "source_commit": "a" * 40,
                        "audit_timestamp": "2026-08-27T00:00:00+00:00",
                        "status": "complete",
                        "coverage": _findings_coverage(),
                        "endpoints": [
                            {
                                "endpoint_id": "exposed-get-health",
                                "direction": "exposed",
                                "surface_type": "http",
                                "method": "GET",
                                "path": "/health",
                                "confidence": "confirmed",
                                "confidence_reason": "fixture",
                                "evidence": [{"path": "api.ts", "line": 1, "kind": "route"}],
                                "notes": [],
                            }
                        ],
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
            output = root / "api-catalog.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["catalog-api", "--findings", str(findings), "--output", str(output)])
            self.assertEqual(code, 0)
            self.assertIn("API catalog written", stdout.getvalue())
            self.assertTrue(output.is_file())

    def test_compare_api_command_returns_partial_when_gate_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = root / "findings.json"
            findings.write_text(
                json.dumps(
                    {
                        "schema_version": "2.0",
                        "audit_id": "audit-repo",
                        "auditor_version": "0.8.0",
                        "repository": "repo",
                        "repository_id": "repo",
                        "source_ref": "main",
                        "source_commit": "a" * 40,
                        "audit_timestamp": "2026-08-27T00:00:00+00:00",
                        "status": "complete",
                        "coverage": _findings_coverage(),
                        "endpoints": [
                            {
                                "endpoint_id": "exposed-get-health",
                                "direction": "exposed",
                                "surface_type": "http",
                                "method": "GET",
                                "path": "/health",
                                "confidence": "confirmed",
                                "confidence_reason": "fixture",
                                "evidence": [{"path": "api.ts", "line": 1, "kind": "route"}],
                                "notes": [],
                            }
                        ],
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
            reference = root / "reference.json"
            candidate = root / "candidate.json"
            self.assertEqual(main(["catalog-api", "--findings", str(findings), "--output", str(reference)]), 0)
            candidate.write_text(
                reference.read_text(encoding="utf-8").replace('"endpoints": [', '"endpoints": []\n  ,"removed": ['),
                encoding="utf-8",
            )
            candidate_payload = json.loads(reference.read_text(encoding="utf-8"))
            candidate_payload["catalog_id"] = "catalog-candidate"
            candidate_payload["endpoints"] = []
            candidate_payload["coverage"]["total_endpoints"] = 0
            candidate_payload["coverage"]["included_endpoints"] = 0
            candidate_payload["coverage"]["exposed_endpoints"] = 0
            candidate.write_text(json.dumps(candidate_payload), encoding="utf-8")
            output = root / "compatibility"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main([
                    "compare-api",
                    str(reference),
                    str(candidate),
                    "--output",
                    str(output),
                    "--gate-mode",
                    "fail_on_breaking",
                ])
            self.assertEqual(code, 3)
            self.assertIn("failed", stdout.getvalue())
            self.assertTrue((output / "api-compatibility.json").is_file())


if __name__ == "__main__":
    unittest.main()
