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
                "public/index.php": "<?php\n$app->put('/route', $handler);\n",
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertIn(("exposed", "PUT", "/route"), _endpoint_set(result))
            self.assertTrue(result.discovery_complete)

    def test_sftp_put_is_not_slim_route_or_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "composer.json": json.dumps({"require": {"slim/slim": "^4.14"}}),
                "public/index.php": "<?php\n$app->get('/health', $handler);\n",
                "src/Sftp.php": (
                    "<?php\n"
                    "if (!$sftp->put($remotePath, $origin, \\phpseclib\\Net\\SFTP::SOURCE_LOCAL_FILE)) {\n"
                    "    throw new RuntimeException('failed');\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertNotIn(("exposed", "PUT", "{remotePath}"), _endpoint_set(result))
            self.assertNotIn("slim_dynamic_route_unresolved", {x.code for x in result.unresolved})
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
                    "export class ChatbotComponent {\n"
                    "  API_URL = 'https://n8n.kpogroup.bo/webhook/asgard-chatbot';\n"
                    "  async send(formData: FormData) {\n"
                    "    const res = await fetch(this.API_URL, {\n"
                    "      method: 'POST',\n"
                    "      body: formData\n"
                    "    });\n"
                    "    return res;\n"
                    "  }\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertIn(("consumed", "POST", "/webhook/asgard-chatbot"), _endpoint_set(result))
            endpoint = next(item for item in result.endpoints if item.path == "/webhook/asgard-chatbot")
            self.assertEqual(endpoint.base_url, "https://n8n.kpogroup.bo")
            self.assertEqual(endpoint.confidence, "confirmed")
            self.assertEqual({e.note for e in endpoint.evidence}, {"fetch HTTP call", "literal fetch URL property"})
            self.assertNotIn("http_client_detected_no_calls", {x.code for x in result.unresolved})
            self.assertTrue(result.discovery_complete)

    def test_dynamic_fetch_remains_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {"src/api.ts": "fetch(buildUrl());\n"})
            result = discover_endpoints(AuditTarget(repo))
            self.assertFalse(result.discovery_complete)
            self.assertIn("fetch_dynamic_or_complex_call_unresolved", {x.code for x in result.unresolved})

    def test_fetch_property_concatenation_remains_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/api.ts": (
                    "export class Api {\n"
                    "  API_URL = 'https://warehouse.example/api';\n"
                    "  load(path: string) { return fetch(this.API_URL + path); }\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertEqual([], result.endpoints)
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

    def test_angular_commented_httpclient_calls_are_ignored_and_offsets_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "package.json": json.dumps(
                    {"dependencies": {"@angular/core": "^17.0.0", "@angular/common": "^17.0.0"}}
                ),
                "src/api.service.ts": (
                    "import { HttpClient } from '@angular/common/http';\n"
                    "export class ApiService {\n"
                    "  url = 'https://warehouse.example/api/';\n"
                    "  note = \"text // not comment\";\n"
                    "  constructor(private _http: HttpClient) {}\n"
                    "  before() { return this._http.get(this.url + 'active-before'); }\n"
                    "  /* block() { return this._http.get(this.url + 'commented-block'); } */\n"
                    "  // line() { return this._http.get(this.url + 'commented-line'); }\n"
                    "  after() { return this._http.get(this.url + 'active-after'); }\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            found = _endpoint_set(result)
            descriptions = {issue.code for issue in result.unresolved}
            after = next(item for item in result.endpoints if item.path == "/active-after")

            self.assertIn(("consumed", "GET", "/active-before"), found)
            self.assertIn(("consumed", "GET", "/active-after"), found)
            self.assertNotIn(("consumed", "GET", "/commented-block"), found)
            self.assertNotIn(("consumed", "GET", "/commented-line"), found)
            self.assertNotIn("angular_httpclient_dynamic_url_unresolved", descriptions)
            self.assertEqual(after.evidence[0].line, 9)

    def test_fetch_comment_masking_keeps_strings_and_template_urls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/api.ts": (
                    "const note = 'text // not comment';\n"
                    "/* fetch('/commented-block'); */\n"
                    "// fetch('/commented-line');\n"
                    "fetch('https://warehouse.example/api/items');\n"
                    "fetch(`https://warehouse.example/api/items/${id}`);\n"
                    "fetch('/active', { method: 'POST' });\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            found = _endpoint_set(result)
            descriptions = {issue.code for issue in result.unresolved}

            self.assertIn(("consumed", "GET", "/api/items"), found)
            self.assertIn(("consumed", "GET", "/api/items/{id}"), found)
            self.assertIn(("consumed", "POST", "/active"), found)
            self.assertNotIn(("consumed", "GET", "/commented-block"), found)
            self.assertNotIn(("consumed", "GET", "/commented-line"), found)
            self.assertNotIn("fetch_dynamic_or_complex_call_unresolved", descriptions)

    def test_vue_html_commented_fetch_call_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/App.vue": (
                    "<template></template>\n"
                    "<!-- fetch('/commented-html'); -->\n"
                    "<script>\n"
                    "fetch('/active-vue');\n"
                    "</script>\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            found = _endpoint_set(result)

            self.assertIn(("consumed", "GET", "/active-vue"), found)
            self.assertNotIn(("consumed", "GET", "/commented-html"), found)
            self.assertNotIn("fetch_dynamic_or_complex_call_unresolved", {issue.code for issue in result.unresolved})

    def test_axios_commented_calls_are_ignored_but_active_calls_remain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "package.json": json.dumps({"dependencies": {"axios": "^1.0.0"}}),
                "src/api.ts": (
                    "import axios from 'axios';\n"
                    "/* axios.get('/commented-block'); */\n"
                    "// axios.post('/commented-line');\n"
                    "axios.get('/active');\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            found = _endpoint_set(result)

            self.assertIn(("consumed", "GET", "/active"), found)
            self.assertNotIn(("consumed", "GET", "/commented-block"), found)
            self.assertNotIn(("consumed", "POST", "/commented-line"), found)
            self.assertNotIn("axios_dynamic_url_unresolved", {issue.code for issue in result.unresolved})

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

    def test_discovers_php_curl_setopt_array_classic_array_syntax(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/Delosi.php": (
                    "<?php\n"
                    "$curl = curl_init();\n"
                    "curl_setopt_array($curl, array(\n"
                    "  CURLOPT_URL => url_intercompany_delosi.'/almacen/movimientointerno',\n"
                    "  CURLOPT_CUSTOMREQUEST => 'POST',\n"
                    "  CURLOPT_POSTFIELDS => json_encode($data),\n"
                    "));\n"
                    "$lookup = curl_init();\n"
                    "curl_setopt_array($lookup, array(\n"
                    "  CURLOPT_URL => URL_ASGARD_API.'/inventario/reportes/buscar-chasis',\n"
                    "  CURLOPT_CUSTOMREQUEST => 'POST',\n"
                    "));\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            found = _endpoint_set(result)
            self.assertIn(("consumed", "POST", "/almacen/movimientointerno"), found)
            self.assertIn(("consumed", "POST", "/inventario/reportes/buscar-chasis"), found)
            movimiento = next(item for item in result.endpoints if item.path == "/almacen/movimientointerno")
            buscar = next(item for item in result.endpoints if item.path == "/inventario/reportes/buscar-chasis")
            self.assertEqual(movimiento.base_url, "url_intercompany_delosi")
            self.assertEqual(buscar.base_url, "URL_ASGARD_API")
            self.assertTrue(result.discovery_complete)

    def test_php_curl_commented_calls_are_ignored_but_active_calls_remain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/Auth.php": (
                    "<?php\n"
                    "/*\n"
                    "$old = curl_init('https://warehouse.example/commented-block');\n"
                    "curl_setopt($old, CURLOPT_POST, true);\n"
                    "*/\n"
                    "# $hash = curl_init('https://warehouse.example/commented-hash');\n"
                    "// $line = curl_init('https://warehouse.example/commented-line');\n"
                    "$sync = curl_init('https://warehouse.example/api/sync');\n"
                    "curl_setopt($sync, CURLOPT_POST, true);\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            found = _endpoint_set(result)

            self.assertIn(("consumed", "POST", "/api/sync"), found)
            self.assertNotIn(("consumed", "POST", "/commented-block"), found)
            self.assertNotIn(("consumed", "GET", "/commented-hash"), found)
            self.assertNotIn(("consumed", "GET", "/commented-line"), found)
            self.assertNotIn("php_curl_url_unresolved", {issue.code for issue in result.unresolved})

    def test_ambiguous_curl_init_variable_remains_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/BlobStorageService.php": (
                    "<?php\n"
                    "function callHttpCurl($method, $url) {\n"
                    "  $ch = curl_init($url);\n"
                    "  curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertFalse(result.discovery_complete)
            self.assertIn("php_curl_url_unresolved", {x.code for x in result.unresolved})

    def test_resolves_simple_php_curl_wrapper_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/Client.php": (
                    "<?php\n"
                    "class Client {\n"
                    "  public function run() { return $this->request('GET', 'https://example.com/items'); }\n"
                    "  private function request($method, $url) { return $this->curlRequest($method, $url); }\n"
                    "  private function curlRequest($method, $url) {\n"
                    "    $ch = curl_init($url);\n"
                    "    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);\n"
                    "  }\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertEqual([("consumed", "GET", "/items")], sorted(_endpoint_set(result)))
            endpoint = result.endpoints[0]
            self.assertEqual(endpoint.base_url, "https://example.com")
            self.assertEqual(len(result.endpoints), 1)
            self.assertNotIn("php_curl_url_unresolved", {x.code for x in result.unresolved})
            self.assertTrue(result.discovery_complete)

    def test_resolves_blob_storage_like_php_curl_wrappers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/BlobStorageService.php": (
                    "<?php\n"
                    "class BlobStorageService {\n"
                    "  private $container = '';\n"
                    "  private $baseUrl = '';\n"
                    "  public function uploadBlob($blobName, $content) {\n"
                    "    $url = $this->blobUrl($blobName);\n"
                    "    return $this->callHttp('PUT', $url, array(), $content);\n"
                    "  }\n"
                    "  public function getBlob($blobName) {\n"
                    "    $url = $this->blobUrl($blobName);\n"
                    "    return $this->callHttp('GET', $url, array(), null);\n"
                    "  }\n"
                    "  public function exists($blobName) {\n"
                    "    $url = $this->blobUrl($blobName);\n"
                    "    return $this->callHttp('HEAD', $url, array(), null);\n"
                    "  }\n"
                    "  public function deleteBlob($blobName) {\n"
                    "    $url = $this->blobUrl($blobName);\n"
                    "    return $this->callHttp('DELETE', $url, array(), null);\n"
                    "  }\n"
                    "  protected function callHttp($method, $url, array $flatHeaders, $body) {\n"
                    "    return $this->callHttpCurl($method, $url, $flatHeaders, $body);\n"
                    "  }\n"
                    "  private function callHttpCurl($method, $url, array $flatHeaders, $body) {\n"
                    "    $ch = curl_init($url);\n"
                    "    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);\n"
                    "  }\n"
                    "  private function blobUrl($blobName) {\n"
                    "    $segments = explode('/', $blobName);\n"
                    "    $encoded = array_map('rawurlencode', $segments);\n"
                    "    return $this->baseUrl . '/' . $this->container . '/' . implode('/', $encoded);\n"
                    "  }\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            found = _endpoint_set(result)
            self.assertEqual(
                {
                    ("consumed", "DELETE", "/{container}/{blobName}"),
                    ("consumed", "GET", "/{container}/{blobName}"),
                    ("consumed", "HEAD", "/{container}/{blobName}"),
                    ("consumed", "PUT", "/{container}/{blobName}"),
                },
                found,
            )
            self.assertEqual(4, len(result.endpoints))
            for endpoint in result.endpoints:
                self.assertEqual(endpoint.base_url, "$this->baseUrl")
                self.assertIn(
                    "Azure Blob Storage URL resolved from local blobUrl helper with dynamic blob identifier.",
                    endpoint.notes,
                )
                self.assertGreaterEqual(len(endpoint.evidence), 4)
            self.assertNotIn("php_curl_url_unresolved", {x.code for x in result.unresolved})
            self.assertTrue(result.discovery_complete)

    def test_dynamic_php_wrapper_method_remains_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/Client.php": (
                    "<?php\n"
                    "class Client {\n"
                    "  public function run($url) {\n"
                    "    $m = runtimeMethod();\n"
                    "    return $this->request($m, $url);\n"
                    "  }\n"
                    "  private function request($method, $url) { return $this->curlRequest($method, $url); }\n"
                    "  private function curlRequest($method, $url) {\n"
                    "    $ch = curl_init($url);\n"
                    "    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);\n"
                    "  }\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertEqual([], result.endpoints)
            self.assertIn("php_curl_url_unresolved", {x.code for x in result.unresolved})
            self.assertFalse(result.discovery_complete)

    def test_unknown_php_wrapper_target_is_not_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/Client.php": (
                    "<?php\n"
                    "class Client {\n"
                    "  public function run() { return $this->externalCurl('GET', 'https://example.com/items'); }\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertEqual([], result.endpoints)

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

    def test_guzzle_commented_calls_are_ignored_but_active_calls_remain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "composer.json": json.dumps({"require": {"guzzlehttp/guzzle": "^7.0"}}),
                "src/Client.php": (
                    "<?php\n"
                    "use GuzzleHttp\\Client;\n"
                    "$client = new Client();\n"
                    "/* $client->get('/commented-block'); */\n"
                    "// $client->request('POST', '/commented-line');\n"
                    "$client->get('/active');\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            found = _endpoint_set(result)

            self.assertIn(("consumed", "GET", "/active"), found)
            self.assertNotIn(("consumed", "GET", "/commented-block"), found)
            self.assertNotIn(("consumed", "POST", "/commented-line"), found)
            self.assertNotIn("guzzle_dynamic_url_unresolved", {issue.code for issue in result.unresolved})

    def test_laravel_http_commented_calls_are_ignored_but_active_calls_remain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "composer.json": json.dumps({"require": {"laravel/framework": "^11.0"}}),
                "src/Client.php": (
                    "<?php\n"
                    "use Illuminate\\Support\\Facades\\Http;\n"
                    "/* Http::get('/commented-block'); */\n"
                    "// Http::post('/commented-line');\n"
                    "Http::get('/active');\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            found = _endpoint_set(result)

            self.assertIn(("consumed", "GET", "/active"), found)
            self.assertNotIn(("consumed", "GET", "/commented-block"), found)
            self.assertNotIn(("consumed", "POST", "/commented-line"), found)
            self.assertNotIn("laravel_http_complex_call_unresolved", {issue.code for issue in result.unresolved})

    def test_dio_literal_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "pubspec.yaml": "name: app\ndependencies:\n  dio: ^5.0.0\n",
                "lib/api.dart": "import 'package:dio/dio.dart';\nfinal dio = Dio();\nvoid load() { dio.get('/inventory/42'); }\n",
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertIn(("consumed", "GET", "/inventory/42"), _endpoint_set(result))
            self.assertTrue(result.discovery_complete)

    def test_dio_assigned_receiver_keeps_original_variable_name_support(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "pubspec.yaml": "name: app\ndependencies:\n  dio: ^5.0.0\n",
                "lib/api.dart": (
                    "import 'package:dio/dio.dart';\n"
                    "final client = Dio();\n"
                    "void load() { client.get('/x'); }\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertIn(("consumed", "GET", "/x"), _endpoint_set(result))
            self.assertTrue(result.discovery_complete)

    def test_dio_inline_receiver_literal_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "pubspec.yaml": "name: app\ndependencies:\n  dio: ^5.0.0\n",
                "lib/api.dart": "import 'package:dio/dio.dart';\nvoid load() { Dio().get('/x'); }\n",
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertIn(("consumed", "GET", "/x"), _endpoint_set(result))
            self.assertTrue(result.discovery_complete)

    def test_dio_late_typed_field_initialized_in_constructor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "pubspec.yaml": "name: app\ndependencies:\n  dio: ^5.0.0\n",
                "lib/api.dart": (
                    "import 'package:dio/dio.dart';\n"
                    "class Api {\n"
                    "  late Dio dio;\n"
                    "  Api() { dio = Dio(); }\n"
                    "  void load() { dio.get('/x'); }\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertIn(("consumed", "GET", "/x"), _endpoint_set(result))
            self.assertTrue(result.discovery_complete)

    def test_dio_typed_dependency_field_member_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "pubspec.yaml": "name: app\ndependencies:\n  dio: ^5.0.0\n",
                "lib/api.dart": (
                    "import 'package:dio/dio.dart';\n"
                    "class Api { late Dio dio; }\n"
                    "class Remote {\n"
                    "  final Api _api;\n"
                    "  Remote(this._api);\n"
                    "  void load() { _api.dio.get('/x'); }\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertIn(("consumed", "GET", "/x"), _endpoint_set(result))
            self.assertTrue(result.discovery_complete)

    def test_dio_typed_dependency_field_member_chain_post(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "pubspec.yaml": "name: app\ndependencies:\n  dio: ^5.0.0\n",
                "lib/api.dart": (
                    "import 'package:dio/dio.dart';\n"
                    "class Api { late Dio dio; }\n"
                    "class Remote {\n"
                    "  final Api _api;\n"
                    "  Remote(this._api);\n"
                    "  void save() { _api.dio.post('/x'); }\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertIn(("consumed", "POST", "/x"), _endpoint_set(result))
            self.assertTrue(result.discovery_complete)

    def test_dio_interpolated_path_parameters_are_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "pubspec.yaml": "name: app\ndependencies:\n  dio: ^5.0.0\n",
                "lib/api.dart": (
                    "import 'package:dio/dio.dart';\n"
                    "class Api { late Dio dio; }\n"
                    "class Remote {\n"
                    "  final Api _api;\n"
                    "  Remote(this._api);\n"
                    "  void finish(String journeyId) { _api.dio.put('/journey/finish/$journeyId'); }\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertIn(("consumed", "PUT", "/journey/finish/{journeyId}"), _endpoint_set(result))
            self.assertTrue(result.discovery_complete)

    def test_dio_unproven_member_chain_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "pubspec.yaml": "name: app\ndependencies:\n  dio: ^5.0.0\n",
                "lib/api.dart": (
                    "import 'package:dio/dio.dart';\n"
                    "class Remote {\n"
                    "  final Object _api;\n"
                    "  Remote(this._api);\n"
                    "  void load() { _api.dio.get('/x'); }\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            dio = next(item for item in result.detectors if item.detector_id == "dio-consumer")
            self.assertEqual([], result.endpoints)
            self.assertFalse(result.discovery_complete)
            self.assertEqual(dio.status, "partial")
            self.assertIn("dio_receiver_unresolved", {issue.code for issue in result.unresolved})
            self.assertIn("dio_receiver_unresolved", set(dio.unsupported_patterns))

    def test_dio_resolved_and_unresolved_candidates_keep_discovery_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "pubspec.yaml": "name: app\ndependencies:\n  dio: ^5.0.0\n",
                "lib/api.dart": (
                    "import 'package:dio/dio.dart';\n"
                    "final dio = Dio();\n"
                    "class Remote {\n"
                    "  final Object _api;\n"
                    "  Remote(this._api);\n"
                    "  void load() { dio.get('/ok'); _api.dio.post('/unknown'); }\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            dio = next(item for item in result.detectors if item.detector_id == "dio-consumer")
            self.assertIn(("consumed", "GET", "/ok"), _endpoint_set(result))
            self.assertFalse(result.discovery_complete)
            self.assertEqual(dio.status, "partial")
            self.assertIn("dio_receiver_unresolved", {issue.code for issue in result.unresolved})

    def test_dio_member_chain_uses_enclosing_class_field_type_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "pubspec.yaml": "name: app\ndependencies:\n  dio: ^5.0.0\n",
                "lib/api.dart": (
                    "import 'package:dio/dio.dart';\n"
                    "class Api { late Dio dio; }\n"
                    "class OtherRemote {\n"
                    "  final Object _api;\n"
                    "  OtherRemote(this._api);\n"
                    "  void load() { _api.dio.get('/unknown'); }\n"
                    "}\n"
                    "class Remote {\n"
                    "  final Api _api;\n"
                    "  Remote(this._api);\n"
                    "  void load() { _api.dio.get('/known'); }\n"
                    "}\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            dio = next(item for item in result.detectors if item.detector_id == "dio-consumer")
            self.assertIn(("consumed", "GET", "/known"), _endpoint_set(result))
            self.assertNotIn(("consumed", "GET", "/unknown"), _endpoint_set(result))
            self.assertFalse(result.discovery_complete)
            self.assertEqual(dio.status, "partial")
            self.assertIn("dio_receiver_unresolved", {issue.code for issue in result.unresolved})

    def test_dio_commented_calls_are_ignored_but_active_calls_remain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "pubspec.yaml": "name: app\ndependencies:\n  dio: ^5.0.0\n",
                "lib/api.dart": (
                    "import 'package:dio/dio.dart';\n"
                    "final dio = Dio();\n"
                    "/* void old() { dio.get('/commented-block'); } */\n"
                    "// void line() { dio.post('/commented-line'); }\n"
                    "void load() { dio.get('/active'); }\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            found = _endpoint_set(result)

            self.assertIn(("consumed", "GET", "/active"), found)
            self.assertNotIn(("consumed", "GET", "/commented-block"), found)
            self.assertNotIn(("consumed", "POST", "/commented-line"), found)
            self.assertNotIn("dio_dynamic_url_unresolved", {issue.code for issue in result.unresolved})

    def test_dart_http_commented_calls_are_ignored_but_active_calls_remain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "pubspec.yaml": "name: app\ndependencies:\n  http: ^1.0.0\n",
                "lib/api.dart": (
                    "import 'package:http/http.dart' as http;\n"
                    "/* void old() { http.get(Uri.parse('/commented-block')); } */\n"
                    "// void line() { http.post(Uri.parse('/commented-line')); }\n"
                    "void load() { http.get(Uri.parse('/active')); }\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            found = _endpoint_set(result)

            self.assertIn(("consumed", "GET", "/active"), found)
            self.assertNotIn(("consumed", "GET", "/commented-block"), found)
            self.assertNotIn(("consumed", "POST", "/commented-line"), found)
            self.assertNotIn("dart_http_complex_uri_unresolved", {issue.code for issue in result.unresolved})

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
            self.assertEqual(result.integrations[0].direction, "consumed")
            self.assertEqual(result.integrations[0].service_expression, "$wsdl")
            self.assertEqual(result.integrations[0].contract_status, "expression_unresolved")
            self.assertEqual(result.integrations[0].operation, "GetStock")
            self.assertTrue(result.soap_operations_complete)
            self.assertFalse(result.soap_contracts_complete)
            self.assertEqual(result.soap_services, 1)
            self.assertEqual(result.soap_operations, 1)
            self.assertIn("soap_contract_extraction_partial", {x.code for x in result.unresolved})
            soap_detector = next(item for item in result.detectors if item.detector_id == "soap-integration")
            self.assertEqual(soap_detector.status, "partial")

    def test_direct_soapclient_literal_operation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/Soap.php": (
                    "<?php\n"
                    "$client = new SoapClient('https://example.com/service.wsdl');\n"
                    "$client->GetStock(array('sku' => 'A'));\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertEqual(result.endpoints, [])
            self.assertEqual(result.soap_services, 1)
            self.assertEqual(result.soap_operations, 1)
            soap = result.integrations[0]
            self.assertEqual(soap.type, "soap")
            self.assertEqual(soap.operation, "GetStock")
            self.assertEqual(soap.service_expression, "'https://example.com/service.wsdl'")
            self.assertEqual(soap.service_value, "https://example.com/service.wsdl")
            self.assertEqual(soap.contract_status, "external_not_snapshotted")
            self.assertTrue(result.soap_operations_complete)
            self.assertFalse(result.soap_contracts_complete)
            self.assertFalse(result.discovery_complete)

    def test_soapclient_passed_to_local_method_preserves_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/Caller.php": (
                    "<?php\n"
                    "class Worker {\n"
                    "  public function send($client) { $client->SubmitInvoice([]); }\n"
                    "}\n"
                    "$client = new SoapClient('https://example.com/service.wsdl');\n"
                    "$worker = new Worker();\n"
                    "$worker->send($client);\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertEqual(result.soap_operations, 1)
            soap = result.integrations[0]
            self.assertEqual(soap.operation, "SubmitInvoice")
            self.assertEqual(
                {e.note for e in soap.evidence},
                {
                    "SOAP client creation",
                    "SOAP service expression",
                    "SOAP client passed as argument",
                    "SOAP client parameter receiver",
                    "SOAP operation",
                },
            )
            self.assertTrue(result.soap_operations_complete)

    def test_non_soap_object_call_is_not_reported_as_soap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/Repository.php": (
                    "<?php\n"
                    "$repository = new Repository();\n"
                    "$repository->save($payload);\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertEqual(result.integrations, [])
            self.assertEqual(result.soap_services, 0)
            self.assertEqual(result.soap_operations, 0)

    def test_ambiguous_soapclient_flow_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/Caller.php": (
                    "<?php\n"
                    "$client = new SoapClient('https://example.com/service.wsdl');\n"
                    "$target = resolveTarget();\n"
                    "$target->send($client);\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertEqual(result.integrations, [])
            self.assertFalse(result.soap_operations_complete)
            self.assertIn("soap_operation_unresolved", {x.code for x in result.unresolved})
            self.assertFalse(result.discovery_complete)

    def test_multiple_soap_operations_are_deduplicated_per_client(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/Soap.php": (
                    "<?php\n"
                    "$client = new SoapClient('https://example.com/service.wsdl');\n"
                    "$client->CreateOrder([]);\n"
                    "$client->CreateOrder([]);\n"
                    "$client->CloseOrder([]);\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertEqual(
                ["CloseOrder", "CreateOrder"],
                sorted(item.operation for item in result.integrations),
            )
            self.assertEqual(result.soap_operations, 2)

    def test_distinct_soapclients_do_not_mix_operations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/Soap.php": (
                    "<?php\n"
                    "$sales = new SoapClient('https://example.com/sales.wsdl');\n"
                    "$stock = new SoapClient('https://example.com/stock.wsdl');\n"
                    "$sales->CreateInvoice([]);\n"
                    "$stock->ReserveItem([]);\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            found = {(item.service_value, item.operation) for item in result.integrations}
            self.assertEqual(
                {
                    ("https://example.com/sales.wsdl", "CreateInvoice"),
                    ("https://example.com/stock.wsdl", "ReserveItem"),
                },
                found,
            )
            self.assertEqual(result.soap_services, 2)
            self.assertEqual(result.soap_operations, 2)

    def test_reassigned_soapclient_variable_uses_nearest_source_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/Soap.php": (
                    "<?php\n"
                    "$client = new SoapClient('https://example.com/a.wsdl');\n"
                    "$client->FirstOperation([]);\n"
                    "$client = new SoapClient('https://example.com/b.wsdl');\n"
                    "$client->SecondOperation([]);\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            found = {(item.service_value, item.operation) for item in result.integrations}
            self.assertEqual(
                {
                    ("https://example.com/a.wsdl", "FirstOperation"),
                    ("https://example.com/b.wsdl", "SecondOperation"),
                },
                found,
            )
            first = next(item for item in result.integrations if item.operation == "FirstOperation")
            second = next(item for item in result.integrations if item.operation == "SecondOperation")
            self.assertEqual(first.evidence[0].line, 2)
            self.assertEqual(second.evidence[0].line, 4)

    def test_local_wsdl_contract_is_parsed_for_soap_operation(self) -> None:
        wsdl = """<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" name="StockService">
  <message name="GetStockRequest"/>
  <message name="GetStockResponse"/>
  <portType name="StockPortType">
    <operation name="GetStock">
      <input message="tns:GetStockRequest"/>
      <output message="tns:GetStockResponse"/>
    </operation>
  </portType>
  <binding name="StockBinding" type="tns:StockPortType">
    <operation name="GetStock"/>
  </binding>
  <service name="StockService">
    <port name="StockPort" binding="tns:StockBinding"/>
  </service>
</definitions>
"""
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/Soap.php": (
                    "<?php\n"
                    "$client = new SoapClient('service.wsdl');\n"
                    "$client->GetStock([]);\n"
                ),
                "src/service.wsdl": wsdl,
            })
            result = discover_endpoints(AuditTarget(repo))
            soap = result.integrations[0]
            self.assertEqual(soap.contract_status, "local_parsed")
            self.assertEqual(soap.service, "StockService")
            self.assertEqual(soap.port, "StockPort")
            self.assertEqual(soap.binding, "StockBinding")
            self.assertEqual(soap.input_message, "tns:GetStockRequest")
            self.assertEqual(soap.output_message, "tns:GetStockResponse")
            self.assertTrue(soap.defined_in_wsdl)
            self.assertTrue(result.soap_operations_complete)
            self.assertTrue(result.soap_contracts_complete)
            self.assertTrue(result.discovery_complete)

    def test_external_wsdl_keeps_contract_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/Soap.php": (
                    "<?php\n"
                    "$client = new SoapClient('https://example.com/service.wsdl');\n"
                    "$client->GetStock([]);\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertEqual(result.integrations[0].contract_status, "external_not_snapshotted")
            self.assertTrue(result.soap_operations_complete)
            self.assertFalse(result.soap_contracts_complete)
            self.assertIn("soap_contract_extraction_partial", {x.code for x in result.unresolved})
            self.assertFalse(result.discovery_complete)

    def test_soap_operations_do_not_increment_rest_endpoint_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "composer.json": json.dumps({"require": {"laravel/framework": "^11.0"}}),
                "routes/api.php": "<?php\nRoute::get('/inventory/{id}', [InventoryController::class, 'show']);\n",
                "src/Soap.php": (
                    "<?php\n"
                    "$client = new SoapClient('https://example.com/service.wsdl');\n"
                    "$client->GetStock([]);\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertEqual([("exposed", "GET", "/inventory/{id}")], sorted(_endpoint_set(result)))
            self.assertEqual(result.soap_operations, 1)
            self.assertEqual(len(result.integrations), 1)

    def test_dynamic_soap_operation_name_remains_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), {
                "src/Soap.php": (
                    "<?php\n"
                    "$client = new SoapClient('https://example.com/service.wsdl');\n"
                    "$client->__soapCall($operation, []);\n"
                ),
            })
            result = discover_endpoints(AuditTarget(repo))
            self.assertEqual(result.integrations, [])
            self.assertFalse(result.soap_operations_complete)
            self.assertIn("soap_operation_unresolved", {x.code for x in result.unresolved})


if __name__ == "__main__":
    unittest.main()
