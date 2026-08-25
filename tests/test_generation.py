from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from asgard_api_auditor.artifacts import validate_audit_set
from asgard_api_auditor.cli import main
from asgard_api_auditor.generation import generate_audit
from asgard_api_auditor.models import AuditTarget


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)
    return proc.stdout.strip()


def _repo(root: Path) -> Path:
    repo = root / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "composer.json").write_text(
        json.dumps({"require": {"slim/slim": "^4.14"}}), encoding="utf-8"
    )
    (repo / "package.json").write_text(
        json.dumps({"dependencies": {"axios": "^1.0.0"}}), encoding="utf-8"
    )
    (repo / "routes.php").write_text(
        "<?php\n$app->get('/inventory/{id}', $handler);\n", encoding="utf-8"
    )
    (repo / "client.ts").write_text(
        "import axios from 'axios';\naxios.post('https://consumer.example/sync', {});\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "fixture")
    return repo


class GenerationTests(unittest.TestCase):
    def test_generate_audit_publishes_valid_primary_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            destination = root / "audit-output"
            published, findings = generate_audit(
                AuditTarget(repo, output=destination, repository_id="fixture")
            )
            self.assertEqual(published, destination.resolve())
            self.assertEqual(findings["status"], "partial")
            self.assertTrue((destination / "openapi.yaml").is_file())
            self.assertTrue((destination / "api-knowledge.md").is_file())
            self.assertTrue((destination / "findings.json").is_file())
            self.assertTrue((destination / "audit-report.md").is_file())
            validate_audit_set(destination)

    def test_openapi_contains_only_exposed_http(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            openapi = (destination / "openapi.yaml").read_text(encoding="utf-8")
            knowledge = (destination / "api-knowledge.md").read_text(encoding="utf-8")
            self.assertIn('/inventory/{id}', openapi)
            self.assertNotIn("consumer.example", openapi)
            self.assertIn("consumer.example", knowledge)
            self.assertIn("x-asgard-contract-enrichment: partial", openapi)

    def test_findings_keep_contract_enrichment_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            payload = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "partial")
            ids = {item["unresolved_id"] for item in payload["unresolved"]}
            self.assertIn("contract-enrichment-v0.5.0", ids)
            exposed = [item for item in payload["endpoints"] if item["direction"] == "exposed"]
            self.assertEqual(len(exposed), 1)
            self.assertNotIn("request", exposed[0])
            self.assertNotIn("response", exposed[0])

    def test_cli_audit_generates_artifacts_and_returns_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            destination = root / "audit-output"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main([
                    "audit",
                    str(repo),
                    "--repository-id",
                    "fixture",
                    "--output",
                    str(destination),
                ])
            self.assertEqual(code, 3)
            self.assertIn("Audit status: partial", stdout.getvalue())
            validate_audit_set(destination)


if __name__ == "__main__":
    unittest.main()
