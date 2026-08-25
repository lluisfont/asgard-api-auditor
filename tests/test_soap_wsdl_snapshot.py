from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from asgard_api_auditor.cli import main
from asgard_api_auditor.discovery import discover_endpoints
from asgard_api_auditor.models import AuditTarget


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)
    return proc.stdout.strip()


def _wsdl(*operations: str) -> str:
    messages = "\n".join(
        f'<message name="{name}Request"/><message name="{name}Response"/>' for name in operations
    )
    port_ops = "\n".join(
        (
            f'<operation name="{name}">'
            f'<input message="tns:{name}Request"/>'
            f'<output message="tns:{name}Response"/>'
            "</operation>"
        )
        for name in operations
    )
    binding_ops = "\n".join(f'<operation name="{name}"/>' for name in operations)
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:tns="urn:test"
             targetNamespace="urn:test">
  {messages}
  <portType name="TestPortType">{port_ops}</portType>
  <binding name="TestBinding" type="tns:TestPortType">{binding_ops}</binding>
  <service name="TestService"><port name="TestPort" binding="tns:TestBinding"/></service>
</definitions>
'''


def _repo(root: Path, operation: str = "OperationA", wsdl_operations: tuple[str, ...] = ("OperationA",)) -> Path:
    repo = root / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    source = repo / "src" / "client.php"
    source.parent.mkdir(parents=True)
    source.write_text(
        "<?php\n"
        "$client = new SoapClient(servicioovp);\n"
        f"$client->{operation}($params);\n",
        encoding="utf-8",
    )
    wsdl = repo / "contracts" / "soap" / "ovp.wsdl"
    wsdl.parent.mkdir(parents=True)
    wsdl.write_text(_wsdl(*wsdl_operations), encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "fixture")
    return repo


class SoapWsdlSnapshotTests(unittest.TestCase):
    def test_explicit_snapshot_completes_soap_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp))
            result = discover_endpoints(
                AuditTarget(repo),
                soap_wsdl={"servicioovp": Path("contracts/soap/ovp.wsdl")},
            )
            self.assertTrue(result.soap_operations_complete)
            self.assertTrue(result.soap_contracts_complete)
            self.assertTrue(result.discovery_complete)
            self.assertEqual(result.soap_services, 1)
            self.assertEqual(result.soap_operations, 1)
            integration = result.integrations[0]
            self.assertEqual(integration.operation, "OperationA")
            self.assertEqual(integration.wsdl, "contracts/soap/ovp.wsdl")
            self.assertEqual(integration.contract_status, "provided_snapshot_parsed")
            self.assertTrue(integration.defined_in_wsdl)
            self.assertEqual(integration.service, "TestService")
            self.assertEqual(integration.port, "TestPort")
            self.assertNotIn("soap_contract_extraction_partial", {item.code for item in result.unresolved})

    def test_operation_missing_from_snapshot_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp), operation="OperationB", wsdl_operations=("OperationA",))
            result = discover_endpoints(
                AuditTarget(repo),
                soap_wsdl={"servicioovp": Path("contracts/soap/ovp.wsdl")},
            )
            codes = {item.code for item in result.unresolved}
            self.assertFalse(result.soap_contracts_complete)
            self.assertFalse(result.discovery_complete)
            self.assertIn("soap_operation_not_in_wsdl", codes)
            self.assertIn("soap_contract_extraction_partial", codes)
            self.assertFalse(result.integrations[0].defined_in_wsdl)

    def test_snapshot_outside_repository_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _repo(root)
            outside = root / "outside.wsdl"
            outside.write_text(_wsdl("OperationA"), encoding="utf-8")
            result = discover_endpoints(
                AuditTarget(repo),
                soap_wsdl={"servicioovp": Path("../outside.wsdl")},
            )
            self.assertFalse(result.soap_contracts_complete)
            self.assertFalse(result.discovery_complete)
            self.assertIn(
                "soap_wsdl_snapshot_outside_repository",
                {item.code for item in result.unresolved},
            )

    def test_cli_accepts_explicit_snapshot_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main([
                    "discover",
                    str(repo),
                    "--soap-wsdl",
                    "servicioovp=contracts/soap/ovp.wsdl",
                ])
            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertTrue(payload["soap_contracts_complete"])
            self.assertTrue(payload["discovery_complete"])

    def test_cli_rejects_malformed_snapshot_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp))
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main(["discover", str(repo), "--soap-wsdl", "servicioovp"])
            self.assertEqual(code, 2)
            self.assertIn("SERVICE=PATH", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
