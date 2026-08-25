import unittest

from asgard_api_auditor.completion import determine_audit_status
from asgard_api_auditor.models import CoverageSummary, DetectorCoverage, IntegrationSurfaceFinding


class CompletionTests(unittest.TestCase):
    def _complete_coverage(self) -> CoverageSummary:
        return CoverageSummary(
            inventory_complete=True,
            required_detector_categories=["inventory", "exposed", "consumed"],
            detectors=[
                DetectorCoverage("inventory", "1.0", "inventory", "supported", 100),
                DetectorCoverage("routes", "1.0", "exposed", "supported", 10),
                DetectorCoverage("clients", "1.0", "consumed", "supported", 20),
            ],
            files_scanned=130,
        )

    def test_complete_requires_proven_coverage(self) -> None:
        status = determine_audit_status(
            self._complete_coverage(),
            [],
            primary_outputs_valid=True,
            openapi_valid=True,
        )
        self.assertEqual(status, "complete")

    def test_incomplete_inventory_can_never_be_complete(self) -> None:
        coverage = self._complete_coverage()
        coverage.inventory_complete = False
        self.assertEqual(
            determine_audit_status(coverage, [], primary_outputs_valid=True, openapi_valid=True),
            "partial",
        )

    def test_missing_required_detector_can_never_be_complete(self) -> None:
        coverage = self._complete_coverage()
        coverage.detectors = coverage.detectors[:-1]
        self.assertEqual(
            determine_audit_status(coverage, [], primary_outputs_valid=True, openapi_valid=True),
            "partial",
        )

    def test_partial_detector_can_never_be_complete(self) -> None:
        coverage = self._complete_coverage()
        coverage.detectors[2] = DetectorCoverage("clients", "1.0", "consumed", "partial", 20)
        self.assertEqual(
            determine_audit_status(coverage, [], primary_outputs_valid=True, openapi_valid=True),
            "partial",
        )

    def test_unsupported_surface_can_never_be_complete(self) -> None:
        coverage = self._complete_coverage()
        surface = IntegrationSurfaceFinding(
            surface_id="surface_graphql",
            type="graphql",
            status="unsupported",
            direction="consumed",
            confidence="confirmed",
            evidence=(),
        )
        self.assertEqual(
            determine_audit_status(
                coverage, [surface], primary_outputs_valid=True, openapi_valid=True
            ),
            "partial",
        )

    def test_invalid_outputs_fail_closed(self) -> None:
        self.assertEqual(
            determine_audit_status(
                self._complete_coverage(), [], primary_outputs_valid=False, openapi_valid=True
            ),
            "failed",
        )


if __name__ == "__main__":
    unittest.main()
