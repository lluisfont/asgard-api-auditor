"""Coverage-aware endpoint discovery orchestration."""

from __future__ import annotations

from dataclasses import asdict

from . import __version__
from .constants import ENDPOINT_DISCOVERY_SCHEMA_VERSION
from .detectors.consumed import detect_consumed_endpoints
from .detectors.laravel import detect_laravel_routes
from .discovery_types import DiscoveryIssue, EndpointDiscovery
from .discovery_utils import iter_source_files
from .inventory import inventory_repository
from .models import AuditTarget, DetectorCoverage, EndpointFinding

_SUPPORTED_SERVER_FRAMEWORKS = {"laravel"}


def _dedupe_endpoints(endpoints: list[EndpointFinding]) -> list[EndpointFinding]:
    by_id: dict[str, EndpointFinding] = {}
    for endpoint in endpoints:
        existing = by_id.get(endpoint.endpoint_id)
        if existing is None:
            by_id[endpoint.endpoint_id] = endpoint
            continue
        for evidence in endpoint.evidence:
            if evidence not in existing.evidence:
                existing.evidence.append(evidence)
        if existing.confidence != "confirmed" and endpoint.confidence == "confirmed":
            existing.confidence = "confirmed"
            existing.confidence_reason = endpoint.confidence_reason
    return sorted(by_id.values(), key=lambda item: (item.direction, item.path, item.method))


def discover_endpoints(target: AuditTarget, *, allow_dirty: bool = False) -> EndpointDiscovery:
    inventory = inventory_repository(target, allow_dirty=allow_dirty)
    repository = target.repository.resolve()
    files = iter_source_files(repository)

    endpoints: list[EndpointFinding] = []
    issues: list[DiscoveryIssue] = []
    coverage: list[DetectorCoverage] = []

    frameworks = {item.name for item in inventory.frameworks}
    clients = {item.name for item in inventory.http_clients}

    if "laravel" in frameworks:
        found, detector_issues, detector_coverage = detect_laravel_routes(repository, files)
        endpoints.extend(found)
        issues.extend(detector_issues)
        if not found:
            issues.append(
                DiscoveryIssue(
                    code="laravel_detected_no_routes",
                    message=(
                        "Laravel was detected but no supported route declarations were proven. "
                        "Routes may be registered dynamically or outside supported patterns."
                    ),
                    detector_id="laravel-routes",
                )
            )
            detector_coverage = DetectorCoverage(
                detector_id=detector_coverage.detector_id,
                detector_version=detector_coverage.detector_version,
                category=detector_coverage.category,
                status="partial",
                files_scanned=detector_coverage.files_scanned,
                supported_patterns=detector_coverage.supported_patterns,
                unsupported_patterns=tuple(
                    sorted(
                        set(detector_coverage.unsupported_patterns)
                        | {"laravel_detected_no_routes"}
                    )
                ),
                notes=detector_coverage.notes,
            )
        coverage.append(detector_coverage)

    for framework in sorted(frameworks - _SUPPORTED_SERVER_FRAMEWORKS):
        if framework in {"vue", "react", "flutter"}:
            continue
        issue = DiscoveryIssue(
            code="unsupported_server_framework",
            message=f"Server framework '{framework}' has no v0.4 exposed-endpoint detector.",
            detector_id=f"{framework}-routes",
        )
        issues.append(issue)
        coverage.append(
            DetectorCoverage(
                detector_id=f"{framework}-routes",
                detector_version="0.0.0",
                category="exposed",
                status="unsupported",
                unsupported_patterns=(framework,),
            )
        )

    consumed, consumed_issues, consumed_coverage = detect_consumed_endpoints(
        repository, files, clients
    )
    endpoints.extend(consumed)
    issues.extend(consumed_issues)
    coverage.extend(consumed_coverage)

    if not coverage:
        issues.append(
            DiscoveryIssue(
                code="no_supported_api_detector_selected",
                message=(
                    "Inventory did not select any v0.4 API detector. Absence of findings is not "
                    "proof that the repository has no API integrations."
                ),
                detector_id="discovery-orchestrator",
            )
        )

    if inventory.integration_surfaces:
        names = ", ".join(sorted({item.name for item in inventory.integration_surfaces}))
        issues.append(
            DiscoveryIssue(
                code="non_http_integration_requires_dedicated_detector",
                message=(
                    f"Non-HTTP/OpenAPI integration surfaces detected ({names}); v0.4 endpoint "
                    "discovery does not audit those contracts yet."
                ),
                detector_id="integration-surface-gate",
            )
        )
        coverage.append(
            DetectorCoverage(
                detector_id="integration-surface-gate",
                detector_version="1.0.0",
                category="integration",
                status="partial",
                supported_patterns=(),
                unsupported_patterns=tuple(
                    sorted({item.name for item in inventory.integration_surfaces})
                ),
            )
        )

    discovery_complete = (
        inventory.inventory_complete
        and bool(coverage)
        and all(item.status == "supported" for item in coverage)
        and not any(issue.severity == "blocking" for issue in issues)
    )

    notes = [
        (
            "v0.4 discovers literal HTTP routes/calls and fails closed on dynamic or "
            "unsupported patterns."
        ),
        (
            "discovery_complete is not equivalent to final audit status; OpenAPI generation "
            "and contract enrichment follow later."
        ),
    ]
    return EndpointDiscovery(
        schema_version=ENDPOINT_DISCOVERY_SCHEMA_VERSION,
        auditor_version=__version__,
        repository=inventory.repository,
        repository_id=inventory.repository_id,
        source_ref=inventory.source_ref,
        source_commit=inventory.source_commit,
        inventory_complete=inventory.inventory_complete,
        discovery_complete=discovery_complete,
        endpoints=_dedupe_endpoints(endpoints),
        detectors=coverage,
        unresolved=issues,
        notes=notes,
    )


def discovery_to_dict(discovery: EndpointDiscovery) -> dict[str, object]:
    return asdict(discovery)


__all__ = ["DiscoveryIssue", "EndpointDiscovery", "discover_endpoints", "discovery_to_dict"]
