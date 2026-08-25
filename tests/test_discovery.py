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

    def test_discovers_slim_literal_route(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "composer.json": json.dumps({"require": {"slim/slim": "^4.14"}}),
                "public/index.php": "<?php\n$app->get('/almacenes/{idalmacen}', $handler);\n",
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertIn(("exposed", "GET", "/almacenes/{idalmacen}"), _endpoint_set(result))
            self.assertTrue(result.discovery_complete)

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

    def test_fetch_resolves_this_property_literal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/api.ts": (
                    "export class Api {\n"
                    "  private API_URL = 'https://warehouse.example/api/login';\n"
                    "  save() { return fetch(this.API_URL, { method: 'POST' }); }\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertIn(("consumed", "POST", "/api/login"), _endpoint_set(result))
            self.assertTrue(result.discovery_complete)

    def test_dynamic_fetch_remains_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {"src/api.ts": "fetch(buildUrl());\n"})
            result = discover_endpoints(AuditTarget(repo))
            self.assertFalse(result.discovery_complete)
            self.assertIn("fetch_dynamic_or_complex_call_unresolved", {x.code for x in result.unresolved})

    def test_discovers_angular_httpclient_methods_and_base_assignment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "package.json": json.dumps(
                    {"dependencies": {"@angular/core": "^17.0.0", "@angular/common": "^17.0.0"}}
                ),
                "src/global.ts": "export var GLOBAL = { url: 'http://localhost/atlantes-api/public/' };\n",
                "src/api.service.ts": (
                    "import { HttpClient } from '@angular/common/http';\n"
                    "import { GLOBAL } from './global';\n"
                    "export class ApiService {\n"
                    "  url = GLOBAL.url;\n"
                    "  constructor(private _http: HttpClient) {}\n"
                    "  all() { return this._http.get(this.url + 'almacenes/'); }\n"
                    "  create(x: any) { return this._http.post(this.url + 'almacenes/', x); }\n"
                    "  update(idalmacen: string) { return this._http.put(this.url + 'almacenes/' + idalmacen, {}); }\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            found = _endpoint_set(result)
            self.assertIn(("consumed", "GET", "/almacenes/"), found)
            self.assertIn(("consumed", "POST", "/almacenes/"), found)
            self.assertIn(("consumed", "PUT", "/almacenes/{idalmacen}"), found)
            put = next(item for item in result.endpoints if item.method == "PUT")
            self.assertEqual(put.base_url, "http://localhost/atlantes-api/public")

    def test_discovers_php_curl_literal_and_expression_urls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/Auth.php": (
                    "<?php\n"
                    "$ch = curl_init();\n"
                    "curl_setopt($ch, CURLOPT_URL, url_intercompany_delosi.'/seguridad/autenticar');\n"
                    "curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');\n"
                    "$sync = curl_init('https://warehouse.example/api/sync');\n"
                    "curl_setopt($sync, CURLOPT_POST, true);\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            found = _endpoint_set(result)
            self.assertIn(("consumed", "POST", "/seguridad/autenticar"), found)
            self.assertIn(("consumed", "POST", "/api/sync"), found)
            auth = next(item for item in result.endpoints if item.path == "/seguridad/autenticar")
            self.assertEqual(auth.base_url, "url_intercompany_delosi")

    def test_discover_excludes_audit_and_work_sample(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "package.json": json.dumps({"dependencies": {"axios": "^1.0.0"}}),
                "src/api.ts": "import axios from 'axios';\naxios.get('/real');\n",
                "work_sample/api.ts": "import axios from 'axios';\naxios.get(buildUrl());\n",
                "audit/fixture.ts": "fetch(buildUrl());\n",
            })
            result = discover_endpoints(
                AuditTarget(repo, exclude_paths=("audit", "work_sample"))
            )
            self.assertIn(("consumed", "GET", "/real"), _endpoint_set(result))
            self.assertTrue(result.discovery_complete)

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

    def test_soap_is_separate_from_rest_and_keeps_discovery_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/Soap.php": (
                    "<?php\n"
                    "$client = new SoapClient($wsdl);\n"
                    "$client->__soapCall('GetStock', []);\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertFalse(result.discovery_complete)
            self.assertEqual(result.endpoints, [])
            self.assertEqual(result.integrations[0].type, "soap")
            self.assertEqual(result.integrations[0].operation, "GetStock")
            self.assertIn("soap_contract_extraction_partial", {x.code for x in result.unresolved})
            soap_detector = next(item for item in result.detectors if item.detector_id == "soap-integration")
            self.assertEqual(soap_detector.status, "partial")


if __name__ == "__main__":
    unittest.main()
