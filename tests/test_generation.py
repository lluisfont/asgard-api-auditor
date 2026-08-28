from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from asgard_api_auditor.artifacts import validate_audit_set
from asgard_api_auditor.api_compatibility import build_api_compatibility
from asgard_api_auditor.catalog import build_api_catalog
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


def _client_only_repo(root: Path) -> Path:
    repo = root / "client"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "package.json").write_text(
        json.dumps({"dependencies": {"axios": "^1.0.0"}}), encoding="utf-8"
    )
    (repo / "client.ts").write_text(
        "import axios from 'axios';\naxios.get('/health');\n", encoding="utf-8"
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "client fixture")
    return repo


def _replace_routes(repo: Path, content: str) -> None:
    (repo / "routes.php").write_text(content, encoding="utf-8")
    _git(repo, "add", "routes.php")
    _git(repo, "commit", "-qm", "route variants")


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
            self.assertIn("x-asgard-contract-enrichment: required_not_complete", openapi)

    def test_equivalent_templates_with_distinct_methods_share_canonical_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->get('/pedidos/{idcliente}', $handler);\n"
                "$app->put('/pedidos/{idpedido}', $handler);\n"
                "$app->delete('/pedidos/{idpedido}', $handler);\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            openapi = (destination / "openapi.yaml").read_text(encoding="utf-8")
            self.assertIn('/pedidos/{param1}', openapi)
            self.assertNotIn('  "/pedidos/{idcliente}":', openapi)
            self.assertNotIn('  "/pedidos/{idpedido}":', openapi)
            self.assertIn('x-asgard-source-path: "/pedidos/{idcliente}"', openapi)
            self.assertIn('x-asgard-source-path: "/pedidos/{idpedido}"', openapi)
            self.assertIn('x-asgard-source-parameter-name: "idcliente"', openapi)
            self.assertIn('x-asgard-source-parameter-name: "idpedido"', openapi)
            self.assertEqual(openapi.count("operationId:"), 3)

    def test_equivalent_templates_with_same_method_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->get('/pedidos/{idcliente}', $handler);\n"
                "$app->get('/pedidos/{idpedido}', $handler);\n",
            )
            destination = root / "audit-output"
            with self.assertRaisesRegex(ValueError, "same template shape"):
                generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            self.assertFalse(destination.exists())

    def test_client_only_audit_completes_when_contract_and_correlation_are_out_of_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _client_only_repo(root)
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="client"))
            payload = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            openapi = (destination / "openapi.yaml").read_text(encoding="utf-8")

            self.assertEqual(payload["status"], "complete")
            self.assertEqual(len([item for item in payload["endpoints"] if item["direction"] == "exposed"]), 0)
            self.assertEqual(len([item for item in payload["endpoints"] if item["direction"] == "consumed"]), 1)
            self.assertEqual(payload["unresolved"], [])
            self.assertIn("contract_enrichment_scope=not_applicable", payload["coverage"]["notes"])
            self.assertIn("correlation_scope=out_of_scope", payload["coverage"]["notes"])
            self.assertIn("x-asgard-contract-enrichment: not_applicable", openapi)
            validate_audit_set(destination)

    def test_provider_incomplete_contract_enrichment_blocks_completion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(repo, "<?php\n$app->get('/health', function($request, $response, $args) { return $response; });\n")
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            payload = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "partial")
            ids = {item["unresolved_id"] for item in payload["unresolved"]}
            self.assertIn("contract-enrichment-v0.7.0-coverage-gate", ids)
            exposed = [item for item in payload["endpoints"] if item["direction"] == "exposed"]
            self.assertEqual(len(exposed), 1)
            self.assertNotIn("request", exposed[0])
            self.assertNotIn("response", exposed[0])
            self.assertIn("contract_enrichment_scope=required_not_complete", payload["coverage"]["notes"])
            self.assertIn("contract_enrichment", payload["coverage"])

    def test_provider_complete_contract_enrichment_does_not_add_contract_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->get('/health', function($request, $response, $args) {\n"
                "    $response->getBody()->write(json_encode(array('ok' => true)));\n"
                "    return $response->withHeader('Content-Type', 'application/json');\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            payload = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            ids = {item["unresolved_id"] for item in payload["unresolved"]}

            self.assertEqual(payload["status"], "partial")
            self.assertNotIn("contract-enrichment-v0.7.0-coverage-gate", ids)
            self.assertIn("contract_enrichment_scope=evaluated_complete", payload["coverage"]["notes"])
            self.assertIn("correlation_scope=out_of_scope", payload["coverage"]["notes"])

    def test_required_correlation_without_provider_artifacts_blocks_completion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _client_only_repo(root)
            destination = root / "audit-output"
            generate_audit(
                AuditTarget(repo, output=destination, repository_id="client"),
                require_correlation=True,
            )
            payload = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            ids = {item["unresolved_id"] for item in payload["unresolved"]}

            self.assertEqual(payload["status"], "partial")
            self.assertIn("provider-consumer-correlation-required-not-evaluable", ids)
            self.assertIn("correlation_scope=required_not_evaluable", payload["coverage"]["notes"])

    def test_provider_only_required_correlation_is_not_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            (repo / "client.ts").unlink()
            (repo / "package.json").unlink()
            _replace_routes(
                repo,
                "<?php\n"
                "$app->get('/health', function($request, $response, $args) {\n"
                "    $response->getBody()->write(json_encode(array('ok' => true)));\n"
                "    return $response->withHeader('Content-Type', 'application/json');\n"
                "});\n",
            )
            _git(repo, "add", "-A")
            _git(repo, "commit", "-qm", "provider only")
            destination = root / "audit-output"
            generate_audit(
                AuditTarget(repo, output=destination, repository_id="provider"),
                require_correlation=True,
            )
            payload = json.loads((destination / "findings.json").read_text(encoding="utf-8"))

            ids = {item["unresolved_id"] for item in payload["unresolved"]}
            self.assertNotIn("provider-consumer-correlation-required-not-evaluable", ids)
            self.assertIn("correlation_scope=not_applicable", payload["coverage"]["notes"])

    def test_slim_php_contract_enrichment_warehouse_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->get('/almacenes/{idalmacen}', function($request, $response, $args) {\n"
                "    $idalmacen = $args['idalmacen'];\n"
                "    $headers = apache_request_headers();\n"
                "    $token = $headers['Authorization'];\n"
                "    $decoded = JWT::decode($token, new Key(jwt_key, 'HS256'));\n"
                "    $response->getBody()->write(json_encode(array(\n"
                "        'estado' => 'Exito',\n"
                "        'codigo' => 200,\n"
                "        'mensaje' => 'Todo correcto',\n"
                "        'almacen_ubicaciones' => $almacen_ubicaciones\n"
                "    )));\n"
                "    return $response->withHeader('Content-Type', 'application/json');\n"
                "})->add($verifyToken);\n"
                "\n"
                "$app->post('/agruparpedidos', function($request, $response, $args) {\n"
                "    $params = json_decode((string) $request->getBody(),true);\n"
                "    $idcliente=$params[\"idcliente\"];\n"
                "    $pedidos=$params[\"pedidos\"] ?? [];\n"
                "    $fecha_entrega=$params[\"fecha_entrega\"];\n"
                "    $resultado=array(\n"
                "        'codigo'=> $codigo,\n"
                "        'estado'=> $status,\n"
                "        'mensaje'=> $mensaje,\n"
                "        'idpedido'=>$idpedido,\n"
                "        'numero_pedido'=>$numero.\"/\".$gestion\n"
                "    );\n"
                "    $response->getBody()->write(json_encode($resultado));\n"
                "    return $response->withHeader(\n"
                "        'Content-Type',\n"
                "        'application/json'\n"
                "    );\n"
                "})->add($verifyToken);\n"
                "\n"
                "$app->get('/publico', function($request, $response, $args) {\n"
                "    return $response;\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            openapi = (destination / "openapi.yaml").read_text(encoding="utf-8")
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            endpoints = {
                (item["method"], item["path"]): item
                for item in findings["endpoints"]
                if item["direction"] == "exposed"
            }

            get_almacen = endpoints[("GET", "/almacenes/{idalmacen}")]
            self.assertEqual(get_almacen["authentication"], "Authorization header raw JWT HS256")
            self.assertEqual(get_almacen["authorization"], "middleware:$verifyToken")
            self.assertEqual(
                get_almacen["request"]["parameters"][0]["name"],
                "idalmacen",
            )
            self.assertEqual(get_almacen["response"]["content_type"], "application/json")
            self.assertEqual(
                get_almacen["response"]["schema"]["properties"]["codigo"]["type"],
                "integer",
            )
            self.assertEqual(
                get_almacen["response"]["schema"]["properties"]["estado"]["type"],
                "string",
            )

            post = endpoints[("POST", "/agruparpedidos")]
            request_schema = post["request"]["body_schema"]
            self.assertEqual(request_schema["properties"]["pedidos"]["type"], "array")
            self.assertEqual(request_schema["properties"]["pedidos"]["default"], [])
            self.assertEqual(
                sorted(request_schema["required"]),
                ["fecha_entrega", "idcliente"],
            )
            self.assertIn("numero_pedido", post["response"]["schema"]["properties"])
            self.assertNotIn("type", post["response"]["schema"]["properties"]["numero_pedido"])

            publico = endpoints[("GET", "/publico")]
            self.assertNotIn("authentication", publico)
            self.assertNotIn("scheme: bearer", openapi)
            self.assertIn("authorizationHeader:", openapi)
            self.assertIn("type: apiKey", openapi)
            self.assertIn("name: Authorization", openapi)
            self.assertIn("x-asgard-authorization-syntax: raw-jwt", openapi)
            self.assertIn("security:", openapi)
            self.assertIn('"application/json":', openapi)
            self.assertNotIn("consumer.example", openapi)
            self.assertEqual(findings["coverage"]["contract_enrichment"]["request_enriched"], 1)
            self.assertEqual(findings["coverage"]["contract_enrichment"]["response_enriched"], 2)
            self.assertEqual(findings["status"], "partial")

    def test_authorization_header_jwt_decode_raw_header_is_not_bearer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->get('/private', function($request, $response, $args) {\n"
                "    $token = $request->getHeaderLine('Authorization');\n"
                "    $decoded = (array) JWT::decode($token, new Key(jwt_key, 'HS256'));\n"
                "    return $response;\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            openapi = (destination / "openapi.yaml").read_text(encoding="utf-8")
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            endpoint = next(
                item
                for item in findings["endpoints"]
                if item["direction"] == "exposed" and item["path"] == "/private"
            )

            self.assertEqual(endpoint["authentication"], "Authorization header raw JWT HS256")
            self.assertNotIn("scheme: bearer", openapi)
            self.assertIn("authorizationHeader:", openapi)
            self.assertIn("type: apiKey", openapi)
            self.assertIn("in: header", openapi)
            self.assertIn("name: Authorization", openapi)
            self.assertIn("x-asgard-credential-format: JWT", openapi)
            self.assertIn("x-asgard-jwt-algorithm: HS256", openapi)
            self.assertIn("x-asgard-authorization-syntax: raw-jwt", openapi)

    def test_local_jwt_middleware_is_resolved_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$verifyToken = function($request, $handler) {\n"
                "    $token = $request->getHeaderLine('Authorization');\n"
                "    $decoded = (array) JWT::decode(\n"
                "        $token,\n"
                "        new Key(jwt_key, 'HS256')\n"
                "    );\n"
                "    return $handler->handle($request);\n"
                "};\n"
                "$app->get('/private', function($request, $response, $args) {\n"
                "    return $response;\n"
                "})->add($verifyToken);\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            openapi = (destination / "openapi.yaml").read_text(encoding="utf-8")
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            endpoint = next(
                item
                for item in findings["endpoints"]
                if item["direction"] == "exposed" and item["path"] == "/private"
            )
            coverage = findings["coverage"]["contract_enrichment"]

            self.assertEqual(endpoint["authentication"], "Authorization header raw JWT HS256")
            self.assertEqual(endpoint["authorization"], "middleware:$verifyToken")
            self.assertIn("authorizationHeader:", openapi)
            self.assertNotIn("scheme: bearer", openapi)
            self.assertEqual(coverage["security_enrichment_applicable"], 1)
            self.assertEqual(coverage["security_enriched"], 1)

    def test_source_to_findings_catalog_compatibility_preserves_supported_facts_only(self) -> None:
        def write_route(repo: Path, *, side_effect: bool) -> None:
            effect = "    file_put_contents('/tmp/audit.txt', 'x');\n" if side_effect else ""
            _replace_routes(
                repo,
                "<?php\n"
                "$verifyToken = function($request, $handler) {\n"
                "    $token = $request->getHeaderLine('Authorization');\n"
                "    JWT::decode($token, new Key(jwt_key, 'HS256'));\n"
                "    return $handler->handle($request);\n"
                "};\n"
                "$app->get('/private/{id}', function($request, $response, $args) {\n"
                "    $db->query(\"SELECT * FROM t_items\");\n"
                f"{effect}"
                "    $payload = ['id' => '1'];\n"
                "    $response->getBody()->write(json_encode($payload));\n"
                "    return $response->withHeader('Content-Type', 'application/json');\n"
                "})->add($verifyToken);\n",
            )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference_root = root / "reference-root"
            candidate_root = root / "candidate-root"
            reference_root.mkdir()
            candidate_root.mkdir()
            reference_repo = _repo(reference_root)
            candidate_repo = _repo(candidate_root)
            write_route(reference_repo, side_effect=False)
            write_route(candidate_repo, side_effect=True)
            reference_output = root / "reference-audit"
            candidate_output = root / "candidate-audit"
            generate_audit(AuditTarget(reference_repo, output=reference_output, repository_id="reference"))
            generate_audit(AuditTarget(candidate_repo, output=candidate_output, repository_id="candidate"))

            reference_findings = json.loads((reference_output / "findings.json").read_text(encoding="utf-8"))
            candidate_findings = json.loads((candidate_output / "findings.json").read_text(encoding="utf-8"))
            reference_endpoint = next(
                item for item in reference_findings["endpoints"] if item["direction"] == "exposed" and item["path"] == "/private/{id}"
            )
            candidate_endpoint = next(
                item for item in candidate_findings["endpoints"] if item["direction"] == "exposed" and item["path"] == "/private/{id}"
            )

            self.assertEqual(reference_endpoint["authentication"], "Authorization header raw JWT HS256")
            self.assertEqual(reference_endpoint["credential_format"], "raw_jwt")
            self.assertEqual(reference_endpoint["header_semantics"], "raw_authorization_header")
            self.assertNotIn("scheme", reference_endpoint)
            self.assertIsNone(reference_endpoint["request"]["accepts_additional_parameters"])
            self.assertIsNone(reference_endpoint["response"]["tolerates_additional_fields"])
            self.assertIsNone(reference_endpoint["response"]["tolerates_additional_statuses"])
            self.assertNotIn("compatibility", candidate_endpoint["behavior"]["side_effects"][0])

            reference_catalog_path = root / "reference-catalog.json"
            candidate_catalog_path = root / "candidate-catalog.json"
            reference_catalog = build_api_catalog(reference_output / "findings.json")
            candidate_catalog = build_api_catalog(candidate_output / "findings.json")
            reference_catalog_path.write_text(json.dumps(reference_catalog), encoding="utf-8")
            candidate_catalog_path.write_text(json.dumps(candidate_catalog), encoding="utf-8")

            catalog_auth = next(
                item for item in reference_catalog["endpoints"] if item["direction"] == "exposed" and item["normalized_path"] == "/private/{id}"
            )["authentication"]
            self.assertEqual(catalog_auth["credential_format"], "raw_jwt")
            self.assertIsNone(catalog_auth["scheme"])
            self.assertEqual(catalog_auth["header_semantics"], "raw_authorization_header")

            compatibility = build_api_compatibility(reference_catalog_path, candidate_catalog_path)
            record = next(item for item in compatibility["records"] if item["path_shape"] == "/private/{}")
            self.assertEqual(record["classification"], "unknown")
            self.assertIn("external_side_effect_added_unknown", [item["code"] for item in record["findings"]])

    def test_unknown_middleware_creates_security_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->get('/private', function($request, $response, $args) {\n"
                "    return $response;\n"
                "})->add($unknownMiddleware);\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            openapi = (destination / "openapi.yaml").read_text(encoding="utf-8")
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            endpoint = next(
                item
                for item in findings["endpoints"]
                if item["direction"] == "exposed" and item["path"] == "/private"
            )
            descriptions = [item["description"] for item in findings["unresolved"]]
            coverage = findings["coverage"]["contract_enrichment"]

            self.assertEqual(endpoint["authorization"], "middleware:$unknownMiddleware")
            self.assertNotIn("authentication", endpoint)
            self.assertNotIn("authorizationHeader:", openapi)
            self.assertTrue(any("slim_php_security_unresolved" in item for item in descriptions))
            self.assertEqual(coverage["security_enrichment_applicable"], 1)
            self.assertEqual(coverage["security_enriched"], 0)
            self.assertEqual(coverage["unresolved_contract_enrichment"], 1)

    def test_ambiguous_middleware_definitions_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$verifyToken = function($request, $handler) {\n"
                "    $token = $request->getHeaderLine('Authorization');\n"
                "    JWT::decode($token, new Key(jwt_key, 'HS256'));\n"
                "    return $handler->handle($request);\n"
                "};\n"
                "$verifyToken = function($request, $handler) {\n"
                "    return $handler->handle($request);\n"
                "};\n"
                "$app->get('/private', function($request, $response, $args) {\n"
                "    return $response;\n"
                "})->add($verifyToken);\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            endpoint = next(
                item
                for item in findings["endpoints"]
                if item["direction"] == "exposed" and item["path"] == "/private"
            )
            descriptions = [item["description"] for item in findings["unresolved"]]

            self.assertNotIn("authentication", endpoint)
            self.assertTrue(any("multiple middleware definitions exist" in item for item in descriptions))

    def test_consumed_http_and_soap_remain_out_of_provider_openapi(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            (repo / "soap.php").write_text(
                "<?php\n$client = new SoapClient('https://soap.example/service.wsdl');\n"
                "$client->__soapCall('SubmitOrder', array());\n",
                encoding="utf-8",
            )
            _git(repo, "add", "soap.php")
            _git(repo, "commit", "-qm", "soap client")
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            openapi = (destination / "openapi.yaml").read_text(encoding="utf-8")
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))

            self.assertNotIn("consumer.example", openapi)
            self.assertNotIn("soap.example", openapi)
            self.assertNotIn("SubmitOrder", openapi)
            self.assertTrue(any(item["direction"] == "consumed" for item in findings["endpoints"]))

    def test_dynamic_contract_inputs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->post('/dynamic', function($request, $response, $args) {\n"
                "    $params = json_decode($request->getBody(), true);\n"
                "    $field = runtimeField();\n"
                "    $value = $params[$field];\n"
                "    $payload = buildPayload();\n"
                "    $response->getBody()->write(json_encode($payload));\n"
                "    return $response;\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            descriptions = [item["description"] for item in findings["unresolved"]]
            self.assertTrue(any("slim_php_request_body_dynamic" in item for item in descriptions))
            self.assertTrue(any("slim_php_response_json_dynamic" in item for item in descriptions))
            endpoint = next(
                item
                for item in findings["endpoints"]
                if item["direction"] == "exposed" and item["path"] == "/dynamic"
            )
            self.assertNotIn("request", endpoint)
            self.assertNotIn("response", endpoint)

    def test_dynamic_nested_request_index_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->post('/dynamic-nested', function($request, $response, $args) {\n"
                "    $params = json_decode($request->getBody(), true);\n"
                "    $runtimeKey = runtimeKey();\n"
                "    $value = $params[$runtimeKey][\"field\"];\n"
                "    return $response;\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            descriptions = [item["description"] for item in findings["unresolved"]]
            endpoint = next(
                item
                for item in findings["endpoints"]
                if item["direction"] == "exposed" and item["path"] == "/dynamic-nested"
            )

            self.assertTrue(any("slim_php_request_body_dynamic" in item for item in descriptions))
            self.assertNotIn("request", endpoint)

    def test_named_index_without_loop_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->post('/no-loop-index', function($request, $response, $args) {\n"
                "    $params = json_decode($request->getBody(), true);\n"
                "    $value = $params[$i][\"field\"];\n"
                "    return $response;\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            descriptions = [item["description"] for item in findings["unresolved"]]
            endpoint = next(
                item
                for item in findings["endpoints"]
                if item["direction"] == "exposed" and item["path"] == "/no-loop-index"
            )

            self.assertTrue(any("slim_php_request_body_dynamic" in item for item in descriptions))
            self.assertNotIn("request", endpoint)

    def test_demonstrated_for_loop_index_resolves_array_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->post('/loop-index', function($request, $response, $args) {\n"
                "    $params = json_decode($request->getBody(), true);\n"
                "    for ($i=0; $i<count($params); $i++) { $field = $params[$i][\"field\"]; }\n"
                "    return $response;\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            schema = next(
                item["request"]["body_schema"]
                for item in findings["endpoints"]
                if item["direction"] == "exposed" and item["path"] == "/loop-index"
            )
            descriptions = [item["description"] for item in findings["unresolved"]]

            self.assertEqual(schema["type"], "array")
            self.assertIn("field", schema["items"]["properties"])
            self.assertFalse(any("slim_php_request_body_dynamic" in item for item in descriptions))

    def test_unused_json_decode_is_not_request_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->post('/unused', function($request, $response, $args) {\n"
                "    $params = json_decode((string) $request->getBody(), true);\n"
                "    return $response;\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            endpoint = next(
                item
                for item in findings["endpoints"]
                if item["direction"] == "exposed" and item["path"] == "/unused"
            )
            descriptions = [item["description"] for item in findings["unresolved"]]

            self.assertNotIn("request", endpoint)
            self.assertEqual(
                findings["coverage"]["contract_enrichment"]["request_enrichment_applicable"],
                0,
            )
            self.assertFalse(any("slim_php_request_body" in item for item in descriptions))

    def test_decoded_var_passed_to_function_is_not_unused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "function forward($payload) { return true; }\n"
                "$app->post('/forward', function($request, $response, $args) {\n"
                "    $params = json_decode($request->getBody(), true);\n"
                "    forward($params);\n"
                "    return $response;\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            descriptions = [item["description"] for item in findings["unresolved"]]

            self.assertEqual(
                findings["coverage"]["contract_enrichment"]["request_enrichment_applicable"],
                1,
            )
            self.assertEqual(findings["coverage"]["contract_enrichment"]["request_enriched"], 0)
            self.assertTrue(any("local function forward" in item for item in descriptions))

    def test_top_level_scalar_json_array(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->post('/ids', function($request, $response, $args) {\n"
                "    $params = json_decode($request->getBody(), true);\n"
                "    for ($i = 0; $i < count($params); $i++) { $id = $params[$i]; }\n"
                "    return $response;\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            endpoint = next(
                item
                for item in findings["endpoints"]
                if item["direction"] == "exposed" and item["path"] == "/ids"
            )

            self.assertEqual(endpoint["request"]["body_schema"]["type"], "array")
            self.assertIn("items", endpoint["request"]["body_schema"])
            self.assertEqual(findings["coverage"]["contract_enrichment"]["request_enriched"], 1)

    def test_array_object_and_single_quote_access(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->post('/items', function($request, $response, $args) {\n"
                "    $params = json_decode($request->getBody(), true);\n"
                "    for ($i = 0; $i < count($params); $i++) {\n"
                "        $sku = $params[$i]['sku'];\n"
                "        $qty = (int) $params[$i][\"quantity\"];\n"
                "    }\n"
                "    return $response;\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            schema = next(
                item["request"]["body_schema"]
                for item in findings["endpoints"]
                if item["direction"] == "exposed" and item["path"] == "/items"
            )
            properties = schema["items"]["properties"]

            self.assertEqual(schema["type"], "array")
            self.assertIn("sku", properties)
            self.assertEqual(properties["quantity"]["type"], "integer")

    def test_element_alias_and_foreach_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->post('/aliases', function($request, $response, $args) {\n"
                "    $params = json_decode($request->getBody(), true);\n"
                "    $first = $params[0];\n"
                "    $firstName = $first['name'];\n"
                "    foreach ($params as $item) { $code = $item[\"code\"]; }\n"
                "    $copy = $params;\n"
                "    foreach ($copy as $entry) { $label = $entry['label']; }\n"
                "    return $response;\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            schema = next(
                item["request"]["body_schema"]
                for item in findings["endpoints"]
                if item["direction"] == "exposed" and item["path"] == "/aliases"
            )
            properties = schema["items"]["properties"]

            self.assertIn("name", properties)
            self.assertIn("code", properties)
            self.assertIn("label", properties)

    def test_nested_json_array_object_access(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->post('/nested', function($request, $response, $args) {\n"
                "    $params = json_decode($request->getBody(), true);\n"
                "    for ($i = 0; $i < count($params); $i++) {\n"
                "        for ($j = 0; $j < count($params[$i][\"detail\"]); $j++) {\n"
                "            $quantity = (int) $params[$i][\"detail\"][$j][\"quantity\"];\n"
                "        }\n"
                "    }\n"
                "    return $response;\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            schema = next(
                item["request"]["body_schema"]
                for item in findings["endpoints"]
                if item["direction"] == "exposed" and item["path"] == "/nested"
            )
            quantity = schema["items"]["properties"]["detail"]["items"]["properties"]["quantity"]

            self.assertEqual(schema["type"], "array")
            self.assertEqual(schema["items"]["properties"]["detail"]["type"], "array")
            self.assertEqual(quantity["type"], "integer")

    def test_unique_local_positional_request_propagation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "function enviarmailfactura($correosarray) {\n"
                "    foreach ($correosarray as $cc => $correoitem) {\n"
                "        $correo = $correosarray[$cc][\"correo\"];\n"
                "    }\n"
                "}\n"
                "$app->post('/migrarovp', function($request, $response, $args) {\n"
                "    $params = json_decode($request->getBody(), true);\n"
                "    enviarmailfactura($params);\n"
                "    return $response;\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            schema = next(
                item["request"]["body_schema"]
                for item in findings["endpoints"]
                if item["direction"] == "exposed" and item["path"] == "/migrarovp"
            )

            self.assertIn("correo", schema["items"]["properties"])
            self.assertEqual(findings["coverage"]["contract_enrichment"]["request_enriched"], 1)

    def test_ambiguous_local_positional_request_propagation_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "function enviar($payload) { $mail = $payload[$i]['correo']; }\n"
                "function enviar($payload) { return true; }\n"
                "$app->post('/ambiguous', function($request, $response, $args) {\n"
                "    $params = json_decode($request->getBody(), true);\n"
                "    enviar($params);\n"
                "    return $response;\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            descriptions = [item["description"] for item in findings["unresolved"]]

            self.assertEqual(findings["coverage"]["contract_enrichment"]["request_enriched"], 0)
            self.assertTrue(any("function enviar" in item and "not unique" in item for item in descriptions))

    def test_multipart_post_and_files_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->post('/salidas', function($request, $response, $args) {\n"
                "    $idcliente = $_POST['idcliente'];\n"
                "    $documento = $_FILES[\"documento\"];\n"
                "    return $response;\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            request = next(
                item["request"]
                for item in findings["endpoints"]
                if item["direction"] == "exposed" and item["path"] == "/salidas"
            )

            self.assertEqual(request["content_type"], "multipart/form-data")
            self.assertEqual(request["body_schema"]["properties"]["documento"]["format"], "binary")
            self.assertIn("idcliente", request["body_schema"]["properties"])

    def test_multipart_wins_over_unused_json_decode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->post('/upload', function($request, $response, $args) {\n"
                "    $params = json_decode($request->getBody(), true);\n"
                "    $name = $_POST['name'];\n"
                "    $file = $_FILES['file'];\n"
                "    return $response;\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            findings = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            request = next(
                item["request"]
                for item in findings["endpoints"]
                if item["direction"] == "exposed" and item["path"] == "/upload"
            )
            descriptions = [item["description"] for item in findings["unresolved"]]

            self.assertEqual(request["content_type"], "multipart/form-data")
            self.assertFalse(any("slim_php_request_body" in item for item in descriptions))

    def test_canonical_openapi_mapping_survives_contract_enrichment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            _replace_routes(
                repo,
                "<?php\n"
                "$app->get('/pedidos/{idcliente}', function($request, $response, $args) {\n"
                "    $idcliente = $args['idcliente'];\n"
                "    return $response;\n"
                "});\n"
                "$app->put('/pedidos/{idpedido}', function($request, $response, $args) {\n"
                "    $idpedido = $args['idpedido'];\n"
                "    return $response;\n"
                "});\n",
            )
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            openapi = (destination / "openapi.yaml").read_text(encoding="utf-8")
            self.assertIn('/pedidos/{param1}', openapi)
            self.assertIn('x-asgard-source-path: "/pedidos/{idcliente}"', openapi)
            self.assertIn('x-asgard-source-path: "/pedidos/{idpedido}"', openapi)
            self.assertIn('x-asgard-source-parameter-name: "idcliente"', openapi)
            self.assertIn('x-asgard-source-parameter-name: "idpedido"', openapi)
            self.assertEqual(openapi.count("operationId:"), 2)

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
