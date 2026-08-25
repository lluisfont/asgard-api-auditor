import unittest
from pathlib import Path

from asgard_api_auditor.models import AuditTarget, EndpointFinding, Evidence


class ModelTests(unittest.TestCase):
    def test_endpoint_identity_normalizes_method(self) -> None:
        finding = EndpointFinding(
            direction="consumed",
            method="get",
            path="/inventory/{id}",
            evidence=[Evidence(path="src/client.py", line=10, kind="http_client")],
        )
        self.assertEqual(
            finding.identity(),
            ("consumed", "GET", "/inventory/{id}"),
        )

    def test_audit_target_defaults(self) -> None:
        target = AuditTarget(repository=Path("repo"))
        self.assertEqual(target.ref, "HEAD")
        self.assertEqual(target.output, Path("output"))


if __name__ == "__main__":
    unittest.main()
