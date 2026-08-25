from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from asgard_api_auditor.inventory import InventoryError, inventory_repository
from asgard_api_auditor.models import AuditTarget, TechnologyDetection


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()


def _init_repo(root: Path, files: dict[str, str]) -> Path:
    repo = root / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    for relative, content in files.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "fixture")
    return repo


def _names(items: list[TechnologyDetection]) -> set[str]:
    return {item.name for item in items}


class TechnicalInventoryTests(unittest.TestCase):
    def test_detects_laravel_vue_guzzle_and_axios(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(
                Path(tmp),
                {
                    "composer.json": json.dumps(
                        {
                            "require": {
                                "php": "^8.2",
                                "laravel/framework": "^11.0",
                                "guzzlehttp/guzzle": "^7.0",
                            }
                        }
                    ),
                    "package.json": json.dumps(
                        {"dependencies": {"vue": "^3.0.0", "axios": "^1.0.0"}}
                    ),
                    "routes/api.php": "<?php Route::get('/health', fn () => ['ok' => true]);\n",
                    "src/api.ts": (
                        "import axios from 'axios';\n"
                        "export const getX = () => axios.get('/x');\n"
                    ),
                },
            )
            result = inventory_repository(AuditTarget(repo))
            self.assertTrue(result.inventory_complete)
            self.assertEqual(result.source_commit, _git(repo, "rev-parse", "HEAD"))
            self.assertIn("laravel", _names(result.frameworks))
            self.assertIn("vue", _names(result.frameworks))
            self.assertIn("guzzle", _names(result.http_clients))
            self.assertIn("axios", _names(result.http_clients))
            self.assertIn("exposed", result.required_detector_categories)
            self.assertIn("consumed", result.required_detector_categories)
            self.assertIn("framework:laravel", result.detector_hints)

    def test_detects_flutter_dio_and_graphql_from_pubspec(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(
                Path(tmp),
                {
                    "pubspec.yaml": (
                        "name: inventory_mobile\n"
                        "dependencies:\n"
                        "  flutter:\n"
                        "    sdk: flutter\n"
                        "  dio: ^5.0.0\n"
                        "  graphql: ^5.0.0\n"
                    ),
                    "lib/api.dart": "import 'package:dio/dio.dart';\n",
                },
            )
            result = inventory_repository(AuditTarget(repo))
            self.assertIn("flutter", _names(result.frameworks))
            self.assertIn("dio", _names(result.http_clients))
            self.assertIn("graphql", _names(result.integration_surfaces))
            self.assertNotIn("exposed", result.required_detector_categories)
            self.assertIn("consumed", result.required_detector_categories)
            self.assertIn("integration", result.required_detector_categories)

    def test_documentation_mentions_do_not_create_technology_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(
                Path(tmp),
                {
                    "README.md": (
                        "This document mentions axios, Laravel and GraphQL "
                        "only as examples.\n"
                    )
                },
            )
            result = inventory_repository(AuditTarget(repo))
            self.assertEqual(result.frameworks, [])
            self.assertEqual(result.http_clients, [])
            self.assertEqual(result.integration_surfaces, [])

    def test_dependency_directories_are_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(
                Path(tmp),
                {
                    "src/index.ts": "export const answer = 42;\n",
                    "node_modules/fake/index.js": "import axios from 'axios';\n",
                },
            )
            result = inventory_repository(AuditTarget(repo))
            self.assertIn("node_modules", result.excluded_roots)
            self.assertNotIn("axios", _names(result.http_clients))

    def test_requested_ref_must_be_checked_out_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(Path(tmp), {"a.py": "x = 1\n"})
            previous = _git(repo, "rev-parse", "HEAD")
            (repo / "a.py").write_text("x = 2\n", encoding="utf-8")
            _git(repo, "add", "a.py")
            _git(repo, "commit", "-qm", "second")
            with self.assertRaises(InventoryError):
                inventory_repository(AuditTarget(repo, ref=previous))

    def test_dirty_worktree_is_rejected_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(Path(tmp), {"a.py": "x = 1\n"})
            (repo / "a.py").write_text("x = 2\n", encoding="utf-8")
            with self.assertRaisesRegex(InventoryError, "dirty"):
                inventory_repository(AuditTarget(repo))

    def test_allow_dirty_marks_inventory_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(Path(tmp), {"a.py": "x = 1\n"})
            (repo / "a.py").write_text("x = 2\n", encoding="utf-8")
            result = inventory_repository(AuditTarget(repo), allow_dirty=True)
            self.assertTrue(result.working_tree_dirty)
            self.assertFalse(result.inventory_complete)

    def test_git_submodules_make_inventory_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(
                Path(tmp),
                {
                    ".gitmodules": (
                        '[submodule "shared"]\n'
                        "\tpath = packages/shared\n"
                        "\turl = https://example.invalid/shared.git\n"
                    ),
                    "src/index.ts": "export const x = 1;\n",
                },
            )
            result = inventory_repository(AuditTarget(repo))
            self.assertEqual(result.submodules, ["packages/shared"])
            self.assertFalse(result.inventory_complete)

    def test_existing_openapi_filename_creates_probable_spec_signal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(
                Path(tmp),
                {
                    "docs/openapi.yaml": (
                        "openapi: 3.1.2\ninfo:\n  title: X\n"
                        "  version: 1.0.0\npaths: {}\n"
                    )
                },
            )
            result = inventory_repository(AuditTarget(repo))
            self.assertIn("openapi-or-swagger", _names(result.existing_specs))
            self.assertIn("existing_spec", result.required_detector_categories)

    def test_webhook_environment_signal_is_probable_not_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(
                Path(tmp),
                {"src/config.ts": "const url = process.env.PAYMENT_WEBHOOK_URL;\n"},
            )
            result = inventory_repository(AuditTarget(repo))
            webhook = next(item for item in result.integration_surfaces if item.name == "webhook")
            self.assertEqual(webhook.confidence, "probable")

    def test_repository_identity_sanitizes_origin_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(Path(tmp), {"a.py": "x = 1\n"})
            _git(
                repo,
                "remote",
                "add",
                "origin",
                "https://user:secret-token@github.com/kpo/asgard-warehouse.git",
            )
            result = inventory_repository(AuditTarget(repo))
            self.assertEqual(result.repository_id, "github.com/kpo/asgard-warehouse")
            self.assertEqual(result.repository_identity_source, "origin")
            self.assertNotIn("secret-token", str(result))

    def test_explicit_repository_id_has_priority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(Path(tmp), {"a.py": "x = 1\n"})
            result = inventory_repository(
                AuditTarget(repo, repository_id="asgard/warehouse")
            )
            self.assertEqual(result.repository_id, "asgard/warehouse")
            self.assertEqual(result.repository_identity_source, "explicit")


if __name__ == "__main__":
    unittest.main()
