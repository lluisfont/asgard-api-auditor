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
            self.assertIn("x-asgard-contract-enrichment: partial", openapi)

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

    def test_findings_keep_contract_enrichment_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            destination = root / "audit-output"
            generate_audit(AuditTarget(repo, output=destination, repository_id="fixture"))
            payload = json.loads((destination / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "partial")
            ids = {item["unresolved_id"] for item in payload["unresolved"]}
            self.assertIn("contract-enrichment-v0.5.2-coverage-gate", ids)
            exposed = [item for item in payload["endpoints"] if item["direction"] == "exposed"]
            self.assertEqual(len(exposed), 1)
            self.assertIn("request", exposed[0])
            self.assertNotIn("response", exposed[0])
            self.assertIn("contract_enrichment", payload["coverage"])

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
            self.assertEqual(get_almacen["authentication"], "bearer JWT Authorization HS256")
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
            self.assertIn("bearerAuth", openapi)
            self.assertIn("security:", openapi)
            self.assertIn('"application/json":', openapi)
            self.assertNotIn("consumer.example", openapi)
            self.assertEqual(findings["coverage"]["contract_enrichment"]["request_enriched"], 1)
            self.assertEqual(findings["coverage"]["contract_enrichment"]["response_enriched"], 2)
            self.assertEqual(findings["status"], "partial")

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
