from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from asgard_api_auditor.correlation import (
    CorrelationError,
    build_correlation_payload,
    correlate_findings,
    validate_correlation_set,
)


def _endpoint(
    direction: str,
    method: str,
    path: str,
    *,
    endpoint_id: str | None = None,
    provider_repository: str | None = None,
    base_url: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "endpoint_id": endpoint_id or f"{direction}:{method}:{path}",
        "direction": direction,
        "surface_type": "http",
        "method": method,
        "path": path,
        "confidence": "confirmed",
        "confidence_reason": "test fixture",
        "evidence": [
            {
                "path": "src/api.ts",
                "line": 7,
                "kind": "route" if direction == "exposed" else "http_client",
                "note": "test evidence",
            }
        ],
        "notes": [],
    }
    if provider_repository is not None:
        payload["provider_repository"] = provider_repository
    if base_url is not None:
        payload["base_url"] = base_url
    return payload


def _coverage() -> dict[str, object]:
    return {
        "inventory_complete": True,
        "languages": [],
        "frameworks": [],
        "http_clients": [],
        "required_detector_categories": [],
        "detectors": [],
        "files_scanned": 0,
        "files_excluded": 0,
        "exclusion_rules": [],
        "unsupported_surfaces": [],
    }


def _write_findings(
    root: Path,
    name: str,
    *,
    repository_id: str,
    source_commit: str,
    endpoints: list[dict[str, object]],
    schema_version: str = "2.0",
    integrations: list[dict[str, object]] | None = None,
    audit_id: str | None = None,
) -> Path:
    payload = {
        "schema_version": schema_version,
        "audit_id": audit_id or f"audit-{repository_id}-fixture",
        "auditor_version": "0.6.0",
        "repository": repository_id,
        "repository_id": repository_id,
        "source_ref": "main",
        "source_commit": source_commit,
        "audit_timestamp": "2026-08-26T00:00:00+00:00",
        "status": "partial",
        "coverage": _coverage(),
        "endpoints": endpoints,
        "integration_surfaces": integrations or [],
        "unresolved": [],
        "artifacts": {
            "openapi.yaml": {"status": "validated"},
            "api-knowledge.md": {"status": "validated"},
            "audit-report.md": {"status": "validated"},
        },
    }
    path = root / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


class CorrelationTests(unittest.TestCase):
    def _correlate(self, *paths: Path) -> dict[str, object]:
        return build_correlation_payload(list(paths))

    def test_exact_method_and_path_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = _write_findings(
                root,
                "provider.json",
                repository_id="provider",
                source_commit="a" * 40,
                endpoints=[_endpoint("exposed", "GET", "/orders/{id}", endpoint_id="provider-1")],
            )
            consumer = _write_findings(
                root,
                "consumer.json",
                repository_id="consumer",
                source_commit="b" * 40,
                endpoints=[_endpoint("consumed", "GET", "/orders/{id}", endpoint_id="consumer-1")],
            )
            record = self._correlate(provider, consumer)["correlations"][0]
            self.assertEqual(record["status"], "matched_unique_candidate")
            self.assertEqual(record["candidate_providers"][0]["provider_endpoint_id"], "provider-1")

    def test_parameter_name_differences_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = _write_findings(
                root,
                "provider.json",
                repository_id="provider",
                source_commit="a" * 40,
                endpoints=[_endpoint("exposed", "GET", "/orders/{id}")],
            )
            consumer = _write_findings(
                root,
                "consumer.json",
                repository_id="consumer",
                source_commit="b" * 40,
                endpoints=[_endpoint("consumed", "GET", "/orders/{orderId}")],
            )
            record = self._correlate(provider, consumer)["correlations"][0]
            self.assertEqual(record["normalized_path_shape"], "/orders/{}")
            self.assertEqual(record["status"], "matched_unique_candidate")

    def test_method_mismatch_does_not_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = _write_findings(root, "p.json", repository_id="p", source_commit="a" * 40, endpoints=[_endpoint("exposed", "POST", "/orders/{id}")])
            consumer = _write_findings(root, "c.json", repository_id="c", source_commit="b" * 40, endpoints=[_endpoint("consumed", "GET", "/orders/{id}")])
            self.assertEqual(self._correlate(provider, consumer)["correlations"][0]["status"], "unmatched")

    def test_literal_segment_mismatch_does_not_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = _write_findings(root, "p.json", repository_id="p", source_commit="a" * 40, endpoints=[_endpoint("exposed", "GET", "/orders/{id}")])
            consumer = _write_findings(root, "c.json", repository_id="c", source_commit="b" * 40, endpoints=[_endpoint("consumed", "GET", "/order/{id}")])
            self.assertEqual(self._correlate(provider, consumer)["correlations"][0]["status"], "unmatched")

    def test_trailing_slash_mismatch_remains_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = _write_findings(root, "p.json", repository_id="p", source_commit="a" * 40, endpoints=[_endpoint("exposed", "GET", "/orders/{id}/")])
            consumer = _write_findings(root, "c.json", repository_id="c", source_commit="b" * 40, endpoints=[_endpoint("consumed", "GET", "/orders/{id}")])
            self.assertEqual(self._correlate(provider, consumer)["correlations"][0]["status"], "unmatched")

    def test_one_provider_is_unique_candidate_not_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = _write_findings(root, "p.json", repository_id="p", source_commit="a" * 40, endpoints=[_endpoint("exposed", "GET", "/health")])
            consumer = _write_findings(root, "c.json", repository_id="c", source_commit="b" * 40, endpoints=[_endpoint("consumed", "GET", "/health")])
            record = self._correlate(provider, consumer)["correlations"][0]
            self.assertEqual(record["status"], "matched_unique_candidate")
            self.assertEqual(record["confidence"]["classification"], "deterministic_candidate_unconfirmed")

    def test_explicit_provider_identity_is_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = _write_findings(root, "p.json", repository_id="provider-api", source_commit="a" * 40, endpoints=[_endpoint("exposed", "POST", "/login")])
            consumer = _write_findings(root, "c.json", repository_id="c", source_commit="b" * 40, endpoints=[_endpoint("consumed", "POST", "/login", provider_repository="provider-api")])
            record = self._correlate(provider, consumer)["correlations"][0]
            self.assertEqual(record["status"], "matched_confirmed")
            self.assertIn("explicit_provider_identity", record["match_strategy"])

    def test_two_providers_same_shape_are_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = _write_findings(root, "p1.json", repository_id="p1", source_commit="a" * 40, endpoints=[_endpoint("exposed", "GET", "/items/{id}", endpoint_id="p1")])
            second = _write_findings(root, "p2.json", repository_id="p2", source_commit="b" * 40, endpoints=[_endpoint("exposed", "GET", "/items/{itemId}", endpoint_id="p2")])
            consumer = _write_findings(root, "c.json", repository_id="c", source_commit="c" * 40, endpoints=[_endpoint("consumed", "GET", "/items/{item}", endpoint_id="c1")])
            record = self._correlate(first, second, consumer)["correlations"][0]
            self.assertEqual(record["status"], "ambiguous")
            self.assertEqual([item["provider_endpoint_id"] for item in record["candidate_providers"]], ["p1", "p2"])

    def test_zero_providers_is_unmatched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            consumer = _write_findings(Path(tmp), "c.json", repository_id="c", source_commit="a" * 40, endpoints=[_endpoint("consumed", "GET", "/missing")])
            self.assertEqual(self._correlate(consumer)["correlations"][0]["status"], "unmatched")

    def test_same_repository_correlation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings = _write_findings(
                Path(tmp),
                "repo.json",
                repository_id="repo",
                source_commit="a" * 40,
                endpoints=[
                    _endpoint("exposed", "GET", "/local"),
                    _endpoint("consumed", "GET", "/local"),
                ],
            )
            self.assertEqual(self._correlate(findings)["correlations"][0]["status"], "matched_unique_candidate")

    def test_cross_repository_correlation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = _write_findings(root, "warehouse.json", repository_id="asgard-warehouse", source_commit="a" * 40, endpoints=[_endpoint("exposed", "POST", "/inventario/login")])
            mobile = _write_findings(root, "mobile.json", repository_id="asgard-mobile-embarques", source_commit="b" * 40, endpoints=[_endpoint("consumed", "POST", "/inventario/login")])
            record = self._correlate(provider, mobile)["correlations"][0]
            self.assertEqual(record["candidate_providers"][0]["provider_repository_id"], "asgard-warehouse")

    def test_dynamic_base_prefix_is_not_used_for_provider_guessing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = _write_findings(root, "warehouse.json", repository_id="asgard-warehouse", source_commit="a" * 40, endpoints=[_endpoint("exposed", "POST", "/inventario/login")])
            mobile = _write_findings(root, "mobile.json", repository_id="asgard-mobile-embarques", source_commit="b" * 40, endpoints=[_endpoint("consumed", "POST", "{apiUrl}/inventario/login")])
            record = self._correlate(provider, mobile)["correlations"][0]
            self.assertEqual(record["status"], "unmatched")
            self.assertEqual(record["normalized_path_shape"], "{}/inventario/login")
            self.assertEqual(record["consumer_path"], "{apiUrl}/inventario/login")

    def test_duplicate_identical_input_is_deduplicated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings = _write_findings(Path(tmp), "repo.json", repository_id="repo", source_commit="a" * 40, endpoints=[_endpoint("consumed", "GET", "/x")])
            payload = self._correlate(findings, findings)
            self.assertEqual(payload["coverage"]["input_repositories"], 1)
            self.assertEqual(payload["coverage"]["consumed_endpoints_total"], 1)

    def test_conflicting_repository_snapshots_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = _write_findings(root, "old.json", repository_id="repo", source_commit="a" * 40, endpoints=[])
            new = _write_findings(root, "new.json", repository_id="repo", source_commit="b" * 40, endpoints=[])
            with self.assertRaises(CorrelationError):
                self._correlate(old, new)

    def test_unsupported_findings_schema_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings = _write_findings(Path(tmp), "repo.json", repository_id="repo", source_commit="a" * 40, endpoints=[], schema_version="9.0")
            with self.assertRaises(CorrelationError):
                self._correlate(findings)

    def test_invalid_findings_schema_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = _write_findings(
                root,
                "repo.json",
                repository_id="repo",
                source_commit="a" * 40,
                endpoints=[_endpoint("consumed", "GET", "/health")],
            )
            payload = json.loads(findings.read_text(encoding="utf-8"))
            payload["coverage"] = {}
            findings.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

            with self.assertRaises(CorrelationError):
                self._correlate(findings)

    def test_invalid_endpoint_enum_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = _write_findings(
                root,
                "repo.json",
                repository_id="repo",
                source_commit="a" * 40,
                endpoints=[_endpoint("consumed", "GET", "/health")],
            )
            payload = json.loads(findings.read_text(encoding="utf-8"))
            payload["endpoints"][0]["method"] = "BREW"
            findings.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

            with self.assertRaises(CorrelationError):
                self._correlate(findings)

    def test_endpoint_additional_property_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = _write_findings(
                root,
                "repo.json",
                repository_id="repo",
                source_commit="a" * 40,
                endpoints=[_endpoint("consumed", "GET", "/health")],
            )
            payload = json.loads(findings.read_text(encoding="utf-8"))
            payload["endpoints"][0]["guessed_provider"] = "warehouse"
            findings.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

            with self.assertRaises(CorrelationError):
                self._correlate(findings)

    def test_deterministic_ordering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = _write_findings(root, "p.json", repository_id="p", source_commit="a" * 40, endpoints=[_endpoint("exposed", "GET", "/b"), _endpoint("exposed", "GET", "/a")])
            consumer = _write_findings(root, "c.json", repository_id="c", source_commit="b" * 40, endpoints=[_endpoint("consumed", "GET", "/b"), _endpoint("consumed", "GET", "/a")])
            payload = self._correlate(consumer, provider)
            self.assertEqual([item["consumer_path"] for item in payload["correlations"]], ["/a", "/b"])

    def test_stable_correlation_ids_across_repeated_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings = _write_findings(Path(tmp), "repo.json", repository_id="repo", source_commit="a" * 40, endpoints=[_endpoint("consumed", "GET", "/x", endpoint_id="c-x")])
            first = self._correlate(findings)["correlations"][0]["correlation_id"]
            second = self._correlate(findings)["correlations"][0]["correlation_id"]
            self.assertEqual(first, second)

    def test_reverse_provider_index_correctness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = _write_findings(root, "p.json", repository_id="p", source_commit="a" * 40, endpoints=[_endpoint("exposed", "GET", "/x", endpoint_id="p-x")])
            consumer = _write_findings(root, "c.json", repository_id="c", source_commit="b" * 40, endpoints=[_endpoint("consumed", "GET", "/x", endpoint_id="c-x")])
            index = self._correlate(provider, consumer)["provider_reverse_index"][0]
            self.assertEqual(index["provider_endpoint_id"], "p-x")
            self.assertEqual(index["unique_candidate_consumers"][0]["consumer_endpoint_id"], "c-x")
            self.assertEqual(index["confirmed_consumers"], [])

    def test_every_consumer_has_exactly_one_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings = _write_findings(
                Path(tmp),
                "repo.json",
                repository_id="repo",
                source_commit="a" * 40,
                endpoints=[
                    _endpoint("consumed", "GET", "/one"),
                    _endpoint("consumed", "POST", "/two"),
                ],
            )
            payload = self._correlate(findings)
            self.assertEqual(len(payload["correlations"]), 2)
            self.assertTrue(all(item["status"] in {"matched_confirmed", "matched_unique_candidate", "ambiguous", "unmatched"} for item in payload["correlations"]))

    def test_relationship_counts_reconcile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings = _write_findings(Path(tmp), "repo.json", repository_id="repo", source_commit="a" * 40, endpoints=[_endpoint("consumed", "GET", "/one")])
            coverage = self._correlate(findings)["coverage"]
            self.assertEqual(coverage["status_total"], coverage["consumed_endpoints_total"])
            self.assertEqual(
                coverage["matched_confirmed"] + coverage["matched_unique_candidate"] + coverage["ambiguous"] + coverage["unmatched"],
                coverage["consumed_endpoints_total"],
            )

    def test_consumed_endpoints_never_become_providers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings = _write_findings(Path(tmp), "repo.json", repository_id="repo", source_commit="a" * 40, endpoints=[_endpoint("consumed", "GET", "/only-consumed")])
            payload = self._correlate(findings)
            self.assertEqual(payload["provider_reverse_index"], [])
            self.assertEqual(payload["coverage"]["exposed_endpoints_total"], 0)

    def test_soap_is_ignored_by_http_correlation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings = _write_findings(
                Path(tmp),
                "repo.json",
                repository_id="repo",
                source_commit="a" * 40,
                endpoints=[],
                integrations=[
                    {
                        "surface_id": "soap-1",
                        "type": "soap",
                        "status": "confirmed",
                        "direction": "consumed",
                        "confidence": "confirmed",
                        "evidence": [{"path": "soap.php", "kind": "unknown"}],
                    }
                ],
            )
            payload = self._correlate(findings)
            self.assertEqual(payload["coverage"]["consumed_endpoints_total"], 0)
            self.assertEqual(payload["correlations"], [])

    def test_redaction_and_evidence_safety_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = _write_findings(
                root,
                "repo.json",
                repository_id="repo",
                source_commit="a" * 40,
                endpoints=[
                    _endpoint(
                        "consumed",
                        "GET",
                        "/secret",
                        base_url="https://example.test?access_token=topsecret",
                    )
                ],
            )
            output = root / "correlation-output"
            correlate_findings([findings], output)
            text = (output / "correlations.json").read_text(encoding="utf-8")
            self.assertIn("access_token=[REDACTED]", text)
            self.assertIn('"line": 7', text)
            self.assertNotIn("topsecret", text)

    def test_invalid_correlations_schema_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = _write_findings(root, "repo.json", repository_id="repo", source_commit="a" * 40, endpoints=[_endpoint("consumed", "GET", "/x")])
            output = root / "correlation-output"
            correlate_findings([findings], output)
            correlations_path = output / "correlations.json"
            payload = json.loads(correlations_path.read_text(encoding="utf-8"))
            payload["coverage"].pop("status_total")
            correlations_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

            with self.assertRaises(CorrelationError):
                validate_correlation_set(output)

    def test_atomic_artifact_publication_preserves_previous_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = _write_findings(root, "repo.json", repository_id="repo", source_commit="a" * 40, endpoints=[_endpoint("consumed", "GET", "/x")])
            output = root / "correlation-output"
            correlate_findings([findings], output)
            previous = (output / "correlations.json").read_text(encoding="utf-8")
            with patch(
                "asgard_api_auditor.correlation.validate_correlation_set",
                side_effect=CorrelationError("forced validation failure"),
            ), self.assertRaises(CorrelationError):
                correlate_findings([findings], output)
            self.assertEqual((output / "correlations.json").read_text(encoding="utf-8"), previous)


if __name__ == "__main__":
    unittest.main()
