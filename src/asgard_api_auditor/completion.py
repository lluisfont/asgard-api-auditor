"""Conservative audit completion gate."""

from __future__ import annotations

from .models import AuditStatus, CoverageSummary, IntegrationSurfaceFinding


def determine_audit_status(
    coverage: CoverageSummary,
    integration_surfaces: list[IntegrationSurfaceFinding],
    *,
    primary_outputs_valid: bool,
    openapi_valid: bool,
) -> AuditStatus:
    """Return the strongest audit status justified by demonstrated coverage.

    This function deliberately fails closed: missing inventory, detector coverage,
    unsupported surfaces or invalid outputs can never produce ``complete``.
    """
    if not primary_outputs_valid or not openapi_valid:
        return "failed"

    if not coverage.inventory_complete:
        return "partial"

    if coverage.unsupported_surfaces:
        return "partial"

    required = set(coverage.required_detector_categories)
    supported = {
        detector.category
        for detector in coverage.detectors
        if detector.status == "supported"
    }
    if not required.issubset(supported):
        return "partial"

    if any(detector.status != "supported" for detector in coverage.detectors):
        return "partial"

    if any(surface.status == "unsupported" for surface in integration_surfaces):
        return "partial"

    return "complete"
