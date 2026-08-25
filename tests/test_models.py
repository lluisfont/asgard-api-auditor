import unittest
from pathlib import Path

from asgard_api_auditor.identity import make_endpoint_id
from asgard_api_auditor.models import AuditTarget, EndpointFinding, Evidence


class ModelTests(unittest.TestCase):
    def test_endpoint_identity_normalizes_method(self) -> None:
        finding = EndpointFinding(
            direction="consumed",
            method="get",
            path="/inventory/{id}",
            confidence_reason="HTTP client call is explicit",
            evidence=[Evidence(path="src/client.py", line=10, kind="http_client")],
        )
        self.assertEqual(finding.identity(), ("consumed", "GET", "/inventory/{id}"))

    def test_endpoint_id_is_stable(self) -> None:
        first = make_endpoint_id("consumed", "get", "/inventory/{id}", "warehouse-api")
        second = make_endpoint_id("consumed", "GET", "/inventory/{id}", "warehouse-api")
        self.assertEqual(first, second)

    def test_audit_target_defaults(self) -> None:
        target = AuditTarget(repository=Path("repo"))
        self.assertEqual(target.ref, "HEAD")
        self.assertEqual(target.output, Path("output"))


if __name__ == "__main__":
    unittest.main()
