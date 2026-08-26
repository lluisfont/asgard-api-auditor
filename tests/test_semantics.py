from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import venv
from pathlib import Path

from asgard_api_auditor.artifacts import validate_audit_set
from asgard_api_auditor.correlation import correlate_findings, validate_correlation_set
from asgard_api_auditor.generation import generate_audit
from asgard_api_auditor.models import AuditTarget


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)
    return proc.stdout.strip()


def _repo(root: Path, routes: str) -> Path:
    repo = root / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "composer.json").write_text(json.dumps({"require": {"slim/slim": "^4.14"}}), encoding="utf-8")
    (repo / "routes.php").write_text(routes, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "fixture")
    return repo


def _audit(repo: Path, output: Path) -> dict[str, object]:
    generate_audit(AuditTarget(repo, output=output, repository_id="fixture"))
    validate_audit_set(output)
    return json.loads((output / "findings.json").read_text(encoding="utf-8"))


def _endpoint(findings: dict[str, object], method: str, path: str) -> dict[str, object]:
    endpoints = findings["endpoints"]
    assert isinstance(endpoints, list)
    return next(item for item in endpoints if item["direction"] == "exposed" and item["method"] == method and item["path"] == path)


class SemanticReconstructionTests(unittest.TestCase):
    def test_semantic_reconstruction_separates_sql_jwt_http_body_and_outbound_facts(self) -> None:
        routes = """<?php
function persistDetails($conexion, $idpedido) {
    $conexion->exec("INSERT INTO t_pedidodetalle (idpedido) VALUES ($idpedido)");
    $conexion->exec("UPDATE t_pedido SET estado = 2 WHERE idpedido = $idpedido");
}

$app->post('/login', function($request, $response, $args) use ($conexion) {
    $params = json_decode((string) $request->getBody(), true);
    $username = $params['username'];
    $contrasena = $params['contrasena'];
    $query = "SELECT * FROM t_usuario u JOIN t_empresa e ON e.idempresa = u.idempresa WHERE u.username = '".$username."'";
    $conexion->query($query);
    if ($usuario_inactivo) {
        $resultado = array('codigo' => 400, 'estado' => 'Error', 'mensaje' => 'Usuario inactivo');
    }
    $payload = array('idusuario' => $idusuario, 'idempresa' => $idempresa, 'perfil' => $perfil);
    $token = JWT::encode($payload, jwt_key, 'HS256');
    $response->getBody()->write(json_encode(array('estado' => 'Exito', 'codigo' => 200, 'mensaje' => 'OK', 'usuario' => $usuario, 'token' => $token, 'cambiocontrasena' => false)));
    return $response->withHeader('Content-Type', 'application/json');
});

$app->post('/agruparpedidos', function($request, $response, $args) use ($conexion) {
    $params = json_decode((string) $request->getBody(), true);
    $idcliente = $params['idcliente'];
    $pedidos = $params['pedidos'] ?? [];
    $fecha_entrega = $params['fecha_entrega'];
    $headers = apache_request_headers();
    $token = $headers['Authorization'];
    $decoded = (array) JWT::decode($token, new Key(jwt_key, 'HS256'));
    $idalmacen = $decoded['idalmacen'];
    $idusuario = $decoded['idusuario'];
    $conexion->query("SELECT * FROM t_cliente WHERE idcliente = ".$idcliente);
    $conexion->query("SELECT TRIM(LEADING '0' FROM t_pedidodetalle.codigo) as codigo FROM t_pedido p JOIN t_pedidodetalle d ON d.idpedido = p.idpedido");
    $conexion->exec("INSERT INTO t_pedido (idcliente, fecha_entrega) VALUES ($idcliente, '$fecha_entrega')");
    persistDetails($conexion, $idpedido);
    if (!$cliente) {
        $resultado = array('codigo' => 400, 'estado' => 'Error', 'mensaje' => 'Cliente no encontrado');
    }
    $response->getBody()->write(json_encode(array('codigo' => $codigo, 'estado' => $status, 'mensaje' => $mensaje, 'idpedido' => $idpedido, 'numero_pedido' => $numero)));
    return $response->withHeader('Content-Type', 'application/json');
});

$app->get('/clientes/{idcliente}', function($request, $response, $args) use ($conexion) {
    $conexion->query("SELECT * FROM t_cliente WHERE idcliente = ".$args['idcliente']);
    $response->getBody()->write(json_encode(array('codigo' => 200, 'estado' => 'Exito', 'mensaje' => 'OK', 'cliente' => $cliente)));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(202);
});

$app->delete('/productos_cliente/{idbaseproductos}', function($request, $response, $args) use ($conexion) {
    $conexion->exec("DELETE FROM t_baseproductos WHERE idbaseproductos = ".$args['idbaseproductos']);
    return $response;
});

$app->put('/inventario/mailvencimiento/{idalmacen}', function($request, $response, $args) use ($conexion) {
    $curl = curl_init("https://example.test/hook");
    curl_exec($curl);
    $client = new SoapClient($wsdl);
    $client->__soapCall('Notify', array());
    file_put_contents('/tmp/audit.txt', 'x');
    return $response;
});
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = _audit(_repo(root, routes), root / "out")
            openapi = (root / "out" / "openapi.yaml").read_text(encoding="utf-8")

            self.assertNotIn("Discovered from source. Request/response/authentication details are not yet reconstructed.", openapi)
            self.assertIn("x-asgard-behavior:", openapi)
            self.assertIn("semantic_enrichment", findings["coverage"])
            self.assertEqual(findings["coverage"]["semantic_enrichment"]["semantic_analysis_attempted"], 5)

            agrupar = _endpoint(findings, "POST", "/agruparpedidos")
            behavior = agrupar["behavior"]
            resources = {(item["operation"], item["resource"]) for item in behavior["data_access"]}
            self.assertIn(("SELECT", "t_cliente"), resources)
            self.assertIn(("SELECT", "t_pedido"), resources)
            self.assertIn(("SELECT", "t_pedidodetalle"), resources)
            self.assertNotIn(("SELECT", "t_pedidodetalle.codigo"), resources)
            self.assertIn(("INSERT", "t_pedido"), resources)
            self.assertIn(("INSERT", "t_pedidodetalle"), resources)
            self.assertIn(("UPDATE", "t_pedido"), resources)
            self.assertEqual({item["claim"] for item in behavior["auth_context"]["consumed_jwt_claims"]}, {"idalmacen", "idusuario"})
            self.assertEqual(behavior["response_semantics"]["http_status_codes"], [])
            self.assertIn("codigo", behavior["response_semantics"]["functional_body_fields"])

            login = _endpoint(findings, "POST", "/login")["behavior"]
            self.assertEqual({item["claim"] for item in login["auth_context"]["produced_jwt_claims"]}, {"idusuario", "idempresa", "perfil"})
            self.assertEqual(login["response_semantics"]["http_status_codes"], [])
            self.assertIn("codigo", login["response_semantics"]["functional_body_fields"])

            simple_get = _endpoint(findings, "GET", "/clientes/{idcliente}")["behavior"]
            self.assertEqual(simple_get["response_semantics"]["http_status_codes"], [202])
            self.assertIn(("SELECT", "t_cliente"), {(item["operation"], item["resource"]) for item in simple_get["data_access"]})

            delete = _endpoint(findings, "DELETE", "/productos_cliente/{idbaseproductos}")["behavior"]
            self.assertIn(("DELETE", "t_baseproductos"), {(item["operation"], item["resource"]) for item in delete["data_access"]})

            external = _endpoint(findings, "PUT", "/inventario/mailvencimiento/{idalmacen}")["behavior"]
            self.assertEqual({item["type"] for item in external["outbound_integrations"]}, {"http", "soap"})
            self.assertIn("file", {item["type"] for item in external["side_effects"]})

    def test_dynamic_sql_target_and_helper_cycle_are_partial_unresolved(self) -> None:
        routes = """<?php
function recurse($conexion) {
    recurse($conexion);
}
$app->get('/dynamic', function($request, $response, $args) use ($conexion) {
    $params = json_decode((string) $request->getBody(), true);
    $table = $params['table'];
    $sql = "SELECT * FROM ".$table;
    $conexion->query($sql);
    recurse($conexion);
    return $response;
});
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            behavior = _endpoint(_audit(_repo(root, routes), root / "out"), "GET", "/dynamic")["behavior"]
            self.assertEqual(behavior["semantic_status"], "partial")
            codes = {item["code"] for item in behavior["unresolved"]}
            self.assertIn("slim_php_semantic_sql_target_unresolved", codes)
            self.assertIn("slim_php_semantic_helper_cycle", codes)

    def test_installed_wheel_uses_packaged_schemas_from_directory_without_schemas(self) -> None:
        routes = """<?php
$app->get('/local', function($request, $response, $args) use ($conexion) {
    $conexion->query("SELECT * FROM t_local");
    return $response;
});
file_get_contents('https://consumer.example/local');
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root, routes)
            wheelhouse = root / "wheelhouse"
            subprocess.run([sys.executable, "-m", "pip", "wheel", ".", "-w", str(wheelhouse)], cwd=Path(__file__).resolve().parents[1], check=True, capture_output=True, text=True)
            env_dir = root / "venv"
            venv.EnvBuilder(with_pip=True).create(env_dir)
            python = env_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
            wheel = next(wheelhouse.glob("asgard_api_auditor-0.7.0-*.whl"))
            subprocess.run([str(python), "-m", "pip", "install", str(wheel)], check=True, capture_output=True, text=True)
            runner = root / "runner"
            runner.mkdir()
            self.assertFalse((runner / "schemas").exists())
            out = root / "out"
            proc = subprocess.run(
                [str(python), "-m", "asgard_api_auditor.cli", "audit", str(repo), "--repository-id", "fixture", "--output", str(out)],
                cwd=runner,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 3, proc.stderr + proc.stdout)
            validate_audit_set(out)
            corr = root / "corr"
            proc = subprocess.run(
                [str(python), "-m", "asgard_api_auditor.cli", "correlate", "--findings", str(out / "findings.json"), "--output", str(corr)],
                cwd=runner,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            validate_correlation_set(corr)

            direct_corr = root / "direct-corr"
            correlate_findings([out / "findings.json"], direct_corr)
            validate_correlation_set(direct_corr)
