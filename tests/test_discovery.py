from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from asgard_api_auditor.discovery import discover_endpoints
from asgard_api_auditor.models import AuditTarget


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)
    return proc.stdout.strip()


def _repo(root: Path, files: dict[str, str]) -> Path:
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


def _endpoint_set(result: object) -> set[tuple[str, str, str]]:
    return {(item.direction, item.method, item.path) for item in result.endpoints}


class EndpointDiscoveryTests(unittest.TestCase):
    def test_discovers_laravel_exposed_and_axios_consumed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "composer.json": json.dumps({"require": {"laravel/framework": "^11.0"}}),
                "package.json": json.dumps({"dependencies": {"axios": "^1.0.0"}}),
                "routes/api.php": "<?php\nRoute::get('/inventory/{id}', [InventoryController::class, 'show']);\n",
                "src/api.ts": "import axios from 'axios';\naxios.post('/warehouse/sync', {});\n",
            })
            result = discover_endpoints(AuditTarget(repo))
            found = _endpoint_set(result)
            self.assertIn(("exposed", "GET", "/inventory/{id}"), found)
            self.assertIn(("consumed", "POST", "/warehouse/sync"), found)
            self.assertTrue(result.discovery_complete)

    def test_dynamic_laravel_route_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "composer.json": json.dumps({"require": {"laravel/framework": "^11.0"}}),
                "routes/api.php": "<?php\nRoute::get($dynamicPath, Handler::class);\n",
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertFalse(result.discovery_complete)
            self.assertIn("laravel_dynamic_route_unresolved", {x.code for x in result.unresolved})

    def test_resource_route_is_not_silently_expanded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "composer.json": json.dumps({"require": {"laravel/framework": "^11.0"}}),
                "routes/api.php": "<?php\nRoute::apiResource('orders', OrderController::class);\n",
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertFalse(result.discovery_complete)
            self.assertIn("laravel_apiresource_unsupported", {x.code for x in result.unresolved})

    def test_fetch_get_and_post(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "package.json": json.dumps({"dependencies": {"node-fetch": "^3.0.0"}}),
                "src/api.ts": "fetch('https://warehouse.example/api/items');\nfetch('/sync', { method: 'POST' });\n",
            })
            found = _endpoint_set(discover_endpoints(AuditTarget(repo)))
            self.assertIn(("consumed", "GET", "/api/items"), found)
            self.assertIn(("consumed", "POST", "/sync"), found)

    def test_guzzle_request_and_direct_method(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "composer.json": json.dumps({"require": {"guzzlehttp/guzzle": "^7.0"}}),
                "src/Client.php": "<?php\nuse GuzzleHttp\\Client;\n$client = new Client();\n$client->get('https://warehouse.example/api/items');\n$client->request('POST', '/api/sync');\n",
            })
            found = _endpoint_set(discover_endpoints(AuditTarget(repo)))
            self.assertIn(("consumed", "GET", "/api/items"), found)
            self.assertIn(("consumed", "POST", "/api/sync"), found)

    def test_dio_literal_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "pubspec.yaml": "name: app\ndependencies:\n  dio: ^5.0.0\n",
                "lib/api.dart": "import 'package:dio/dio.dart';\nfinal dio = Dio();\nvoid load() { dio.get('/inventory/42'); }\n",
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertIn(("consumed", "GET", "/inventory/42"), _endpoint_set(result))
            self.assertTrue(result.discovery_complete)

    def test_unsupported_http_client_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "requirements.txt": "requests==2.32.0\n",
                "src/api.py": "import requests\nrequests.get('https://example.invalid/x')\n",
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertFalse(result.discovery_complete)
            self.assertIn("unsupported_http_client", {x.code for x in result.unresolved})


if __name__ == "__main__":
    unittest.main()
