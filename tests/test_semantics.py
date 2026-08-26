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
    $body = $request->getParsedBody();
    $username = $body['username'] ?? null;
    $contrasena = $body['contrasena'] ?? null;
    $codigo = 0;
    $status = 'Error';
    $mensaje = '';
    $query = "SELECT * FROM t_usuario u JOIN t_empresa e ON e.idempresa = u.idempresa WHERE u.username = '".$username."'";
    $conexion->query($query);
    if ($usuario_inactivo) {
        $codigo = 400;
        $status = 'Error';
        $mensaje = 'Usuario inactivo';
    }
    $payload = array('idusuario' => $idusuario, 'idempresa' => $idempresa, 'perfil' => $perfil);
    $token = JWT::encode($payload, jwt_key, 'HS256');
    $response->getBody()->write(json_encode(array('estado' => $status, 'codigo' => $codigo, 'mensaje' => $mensaje, 'usuario' => $usuario, 'token' => $token, 'cambiocontrasena' => false)));
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
    $query = "INSERT INTO t_pedido (idcliente, fecha_entrega) VALUES ($idcliente, '$fecha_entrega');";
    $query = $query."INSERT INTO t_pedidotienda (idpedido) SELECT idpedido FROM t_pedido;";
    $query .= "INSERT INTO t_pediodetalletienda (idpedido) SELECT idpedido FROM t_pedidotienda;";
    $query .= "SELECT TRIM(LEADING '0' FROM t_pedidodetalle.codigo) as codigo";
    $query .= " FROM t_pedido p JOIN t_pedidodetalle d ON d.idpedido = p.idpedido";
    $conexion->exec($query);
    persistDetails($conexion, $idpedido);
    if (!$cliente) {
        $codigo = 400;
        $status = 'Error';
        $mensaje = 'Cliente no encontrado';
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
            self.assertIn(("INSERT", "t_pedidotienda"), resources)
            self.assertIn(("INSERT", "t_pediodetalletienda"), resources)
            self.assertIn(("UPDATE", "t_pedido"), resources)
            self.assertEqual({item["claim"] for item in behavior["auth_context"]["consumed_jwt_claims"]}, {"idalmacen", "idusuario"})
            self.assertEqual(behavior["response_semantics"]["http_status_codes"], [])
            self.assertIn("codigo", behavior["response_semantics"]["functional_body_fields"])
            self.assertIn("idcliente", {item["name"] for item in behavior["request_fields"]})
            agrupar_outcomes = {
                (field["field"], field["expression"])
                for condition in behavior["conditions"]
                for field in condition["body_fields"]
            }
            self.assertIn(("codigo", "400"), agrupar_outcomes)
            self.assertIn(("estado", "'Error'"), agrupar_outcomes)
            self.assertIn(("mensaje", "'Cliente no encontrado'"), agrupar_outcomes)

            login = _endpoint(findings, "POST", "/login")["behavior"]
            self.assertEqual({item["name"] for item in login["request_fields"]}, {"username", "contrasena"})
            self.assertEqual({item["claim"] for item in login["auth_context"]["produced_jwt_claims"]}, {"idusuario", "idempresa", "perfil"})
            self.assertEqual(login["response_semantics"]["http_status_codes"], [])
            self.assertIn("codigo", login["response_semantics"]["functional_body_fields"])
            login_outcomes = {
                (field["field"], field["expression"])
                for condition in login["conditions"]
                for field in condition["body_fields"]
            }
            self.assertIn(("codigo", "400"), login_outcomes)
            self.assertIn(("estado", "'Error'"), login_outcomes)
            self.assertIn(("mensaje", "'Usuario inactivo'"), login_outcomes)

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

    def test_concatenated_join_from_fragments_are_reconstructed(self) -> None:
        routes = """<?php
$app->get('/fragments', function($request, $response, $args) use ($conexion) {
    $sql = "SELECT t_a.id, IFNULL(t_a.name, '') AS name";
    $sql .= " FROM t_a";
    $sql .= " JOIN t_b ON t_b.id = t_a.id";
    $conexion->query($sql);
    return $response;
});
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            behavior = _endpoint(_audit(_repo(root, routes), root / "out"), "GET", "/fragments")["behavior"]
            resources = {(item["operation"], item["resource"]) for item in behavior["data_access"]}
            self.assertIn(("SELECT", "t_a"), resources)
            self.assertIn(("SELECT", "t_b"), resources)
            self.assertNotIn(
                "slim_php_semantic_unpropagated_function_call",
                {item["code"] for item in behavior["unresolved"]},
            )

    def test_dynamic_table_prefix_suffix_does_not_record_prefix_as_resource(self) -> None:
        routes = """<?php
$app->get('/dynamic-table', function($request, $response, $args) use ($conexion) {
    $suffix = $args['suffix'];
    $sql = "SELECT * FROM t_" . $suffix;
    $conexion->query($sql);
    return $response;
});
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            behavior = _endpoint(_audit(_repo(root, routes), root / "out"), "GET", "/dynamic-table")["behavior"]
            self.assertNotIn(("SELECT", "t_"), {(item["operation"], item["resource"]) for item in behavior["data_access"]})
            self.assertIn(
                "slim_php_semantic_sql_target_unresolved",
                {item["code"] for item in behavior["unresolved"]},
            )
            self.assertEqual(behavior["semantic_status"], "unresolved")

    def test_dynamic_sql_identifier_boundary_fails_closed_but_dynamic_values_trace_fields(self) -> None:
        routes = """<?php
$app->post('/sql-boundary', function($request, $response, $args) use ($conexion) {
    $body = $request->getParsedBody();
    $idcliente = $body['idcliente'] ?? null;
    $username = $body['username'] ?? null;
    $suffix = $body['suffix'] ?? null;
    $conexion->query("SELECT * FROM t_cliente" . $suffix);
    $conexion->query("SELECT * FROM t_cliente WHERE idcliente=" . $idcliente);
    $conexion->query("SELECT * FROM t_usuario WHERE t_usuario.username='" . $username . "'");
    $conexion->exec("INSERT INTO t_cliente" . $suffix . " (idcliente) VALUES (1)");
    $conexion->exec("UPDATE t_cliente" . $suffix . " SET activo=1");
    $conexion->exec("DELETE FROM t_cliente" . $suffix . " WHERE idcliente=1");
    $conexion->exec("CALL sp_cliente" . $suffix . "()");
    return $response;
});
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            behavior = _endpoint(_audit(_repo(root, routes), root / "out"), "POST", "/sql-boundary")["behavior"]
            facts = {(item["operation"], item["resource"]) for item in behavior["data_access"]}
            self.assertIn(("SELECT", "t_cliente"), facts)
            self.assertIn(("SELECT", "t_usuario"), facts)
            self.assertNotIn(("INSERT", "t_cliente"), facts)
            self.assertNotIn(("UPDATE", "t_cliente"), facts)
            self.assertNotIn(("DELETE", "t_cliente"), facts)
            self.assertNotIn(("CALL", "sp_cliente"), facts)
            cliente_facts = [
                item
                for item in behavior["data_access"]
                if item["operation"] == "SELECT" and item["resource"] == "t_cliente"
            ]
            usuario_facts = [
                item
                for item in behavior["data_access"]
                if item["operation"] == "SELECT" and item["resource"] == "t_usuario"
            ]
            self.assertIn("idcliente", set().union(*(item["source_fields"] for item in cliente_facts)))
            self.assertIn("username", set().union(*(item["source_fields"] for item in usuario_facts)))
            self.assertIn(
                "slim_php_semantic_sql_target_unresolved",
                {item["code"] for item in behavior["unresolved"]},
            )
            self.assertIn(
                "slim_php_semantic_sql_dynamic_expression",
                {item["code"] for item in behavior["unresolved"]},
            )

    def test_real_shape_login_nested_conditions_and_else_outcomes_are_direct_only(self) -> None:
        routes = """<?php
$app->post('/login', function($request, $response, $args) use ($conexion) {
    $body = $request->getParsedBody();
    $username = $body['username'] ?? null;
    $contrasena = $body['contrasena'] ?? null;
    $codigo=0;
    $status='Error';
    $token='';
    $usuario='';
    $cambiocontrasena=false;
    $result = $conexion->query("SELECT idcontrasenamaestra FROM t_contrasenamaestra WHERE contrasena=md5('$contrasena')");
    if(($row = $result->fetch(PDO::FETCH_ASSOC))){
        $pass_master=true;
    }
    $result = $conexion->query("SELECT t_usuario.idusuario, t_usuario.contrasena, md5('".$contrasena."') as contrasenaint, IFNULL(t_usuario.activo,0) as activo, t_usuario.fecha_contrasena FROM t_usuario WHERE t_usuario.username='$username';");
    if(($row = $result->fetch(PDO::FETCH_ASSOC))){
        if($row["contrasena"] != $row["contrasenaint"] && !$pass_master){
            $codigo=400;
            $mensaje='Contraseña Incorrecta';
        }else{
            if((int)$row["activo"]==1 || $pass_master){
                $diasContrasena = DateTimeService::daysSinceLocalDate($row['fecha_contrasena'], $timezoneName);
                if($diasContrasena>90 && !$pass_master){
                    $cambiocontrasena=true;
                }
                $payload = array(
                    "idusuario" => $row["idusuario"],
                    'cambiocontrasena'=>$cambiocontrasena
                );
                $token = JWT::encode($payload, $key, 'HS256');
                if($token<>''){
                    $status="Exito";
                    $codigo=200;
                    $mensaje="Ingreso Existoso";
                    $usuario=$row['nombre'];
                }else{
                    $codigo=500;
                    $mensaje="Ocurrio un problema, vuelva a intentarlo mas tarde";
                }
            }else{
                $codigo=400;
                $mensaje='Usuario inactivo';
            }
        }
    }else{
        $codigo=400;
        $mensaje='Usuario Inexistente';
    }
    $resultado=array(
        'estado'=>$status,
        'codigo'=>$codigo,
        'mensaje'=>$mensaje,
        'usuario'=>$usuario,
        'token'=>$token,
        'cambiocontrasena'=>$cambiocontrasena
    );
    $response->getBody()->write(json_encode($resultado));
    return $response->withHeader('Content-Type', 'application/json');
});
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            behavior = _endpoint(_audit(_repo(root, routes), root / "out"), "POST", "/login")["behavior"]
            self.assertEqual({item["name"] for item in behavior["request_fields"]}, {"username", "contrasena"})
            self.assertIn("cambiocontrasena", behavior["response_semantics"]["body_fields"])
            by_condition = {
                condition["condition"]: {
                    (field["field"], field.get("expression"))
                    for field in condition["body_fields"]
                }
                for condition in behavior["conditions"]
            }
            self.assertIn(
                ("mensaje", "'Contraseña Incorrecta'"),
                by_condition['$row["contrasena"] != $row["contrasenaint"] && !$pass_master'],
            )
            self.assertIn(("codigo", "400"), by_condition['$row["contrasena"] != $row["contrasenaint"] && !$pass_master'])
            self.assertIn(("mensaje", "'Usuario inactivo'"), by_condition['else !((int)$row["activo"]==1 || $pass_master)'])
            self.assertIn(("mensaje", "'Usuario Inexistente'"), by_condition['else !(($row = $result->fetch(PDO::FETCH_ASSOC)))'])
            self.assertIn(("cambiocontrasena", "true"), by_condition["$diasContrasena>90 && !$pass_master"])
            self.assertIn(("codigo", "200"), by_condition["$token<>''"])
            self.assertIn(("estado", '"Exito"'), by_condition["$token<>''"])
            self.assertIn(("mensaje", '"Ingreso Existoso"'), by_condition["$token<>''"])
            self.assertIn(("codigo", "500"), by_condition["else !($token<>'')"])
            self.assertIn(("mensaje", '"Ocurrio un problema, vuelva a intentarlo mas tarde"'), by_condition["else !($token<>'')"])
            active_outcomes = by_condition.get('(int)$row["activo"]==1 || $pass_master', set())
            self.assertNotIn(("codigo", "200"), active_outcomes)
            self.assertNotIn(("mensaje", '"Ingreso Existoso"'), active_outcomes)
            self.assertNotIn(("permisos", "[]"), active_outcomes)
            self.assertIn(
                "slim_php_semantic_nested_condition_branch",
                {item["code"] for item in behavior["unresolved"]},
            )

    def test_dynamic_callback_forces_partial(self) -> None:
        routes = """<?php
$app->post('/callback', function($request, $response, $args) use ($conexion) {
    $conexion->query("SELECT * FROM t_callback");
    $callback = $args['handler'];
    call_user_func($callback, $response);
    return $response;
});
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            behavior = _endpoint(_audit(_repo(root, routes), root / "out"), "POST", "/callback")["behavior"]
            self.assertEqual(behavior["semantic_status"], "partial")
            self.assertIn(
                "slim_php_semantic_dynamic_callback",
                {item["code"] for item in behavior["unresolved"]},
            )

    def test_outbound_url_is_not_bound_by_proximity(self) -> None:
        routes = """<?php
$app->post('/outbound', function($request, $response, $args) use ($conexion) {
    $curl = curl_init();
    $nearby = "https://not-bound.example/api";
    curl_exec($curl);
    return $response;
});
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            behavior = _endpoint(_audit(_repo(root, routes), root / "out"), "POST", "/outbound")["behavior"]
            self.assertEqual({item["target"] for item in behavior["outbound_integrations"]}, {None})
            self.assertIn(
                "slim_php_semantic_outbound_target_unresolved",
                {item["code"] for item in behavior["unresolved"]},
            )

    def test_stable_semantic_ids_and_order_across_repeated_runs(self) -> None:
        routes = """<?php
$app->get('/stable', function($request, $response, $args) use ($conexion) {
    $conexion->query("SELECT * FROM t_stable JOIN t_other ON t_other.id = t_stable.id");
    return $response;
});
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root, routes)
            first = _endpoint(_audit(repo, root / "out1"), "GET", "/stable")["behavior"]
            second = _endpoint(_audit(repo, root / "out2"), "GET", "/stable")["behavior"]
            self.assertEqual(first["data_access"], second["data_access"])
            self.assertEqual([item["id"] for item in first["data_access"]], sorted(item["id"] for item in first["data_access"]))

    def test_api_knowledge_and_openapi_render_semantic_details_and_outcomes(self) -> None:
        routes = """<?php
$app->post('/render', function($request, $response, $args) use ($conexion) {
    $body = $request->getParsedBody();
    $name = $body['name'] ?? null;
    $codigo = 0;
    $status = 'Error';
    $mensaje = '';
    $conexion->exec("UPDATE t_render SET name = '".$name."'");
    if (!$name) {
        $codigo = 400;
        $status = 'Error';
        $mensaje = 'Missing name';
    }
    $response->getBody()->write(json_encode(array('codigo' => $codigo, 'estado' => $status, 'mensaje' => $mensaje)));
    return $response->withHeader('Content-Type', 'application/json');
});
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root, routes)
            _audit(repo, root / "out")
            knowledge = (root / "out" / "api-knowledge.md").read_text(encoding="utf-8")
            openapi = (root / "out" / "openapi.yaml").read_text(encoding="utf-8")
            for expected in (
                "Request fields",
                "`name` via `$name`",
                "Data written",
                "UPDATE t_render",
                "Auth context",
                "Local calls",
                "Outbound",
                "Side effects",
                "Unresolved",
                "Evidence",
            ):
                self.assertIn(expected, knowledge)
            self.assertIn("!$name -> codigo=400", openapi)
            self.assertIn("estado='Error'", openapi)
            self.assertIn("mensaje='Missing name'", openapi)

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
