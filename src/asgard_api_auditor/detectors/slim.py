"""Slim route discovery with explicit dynamic-route reporting."""

from __future__ import annotations

import re
from pathlib import Path

from ..discovery_types import DiscoveryIssue
from ..discovery_utils import line_number, normalize_literal_url, read_source, relative_path
from ..models import DetectorCoverage, EndpointFinding, Evidence

DETECTOR_ID = "slim-routes"
DETECTOR_VERSION = "1.0.0"

_METHODS = "get|post|put|patch|delete|options"
_DIRECT = re.compile(
    rf"\$[A-Za-z_]\w*->(?P<method>{_METHODS})\s*\(\s*"
    r"(?P<quote>['\"])(?P<path>.*?)(?P=quote)",
    re.IGNORECASE | re.DOTALL,
)
_ANY_ROUTE_CALL = re.compile(rf"\$[A-Za-z_]\w*->(?:{_METHODS})\s*\(", re.IGNORECASE)


def _evidence(repository: Path, path: Path, text: str, offset: int, note: str) -> Evidence:
    return Evidence(
        path=relative_path(repository, path),
        line=line_number(text, offset),
        kind="route",
        note=note,
    )


def detect_slim_routes(
    repository: Path,
    files: list[Path],
) -> tuple[list[EndpointFinding], list[DiscoveryIssue], DetectorCoverage]:
    endpoints: dict[tuple[str, str, str], EndpointFinding] = {}
    issues: list[DiscoveryIssue] = []
    php_files = [path for path in files if path.suffix.lower() == ".php"]

    for path in php_files:
        text = read_source(path)
        if text is None:
            issues.append(
                DiscoveryIssue(
                    code="slim_source_unreadable",
                    message=f"Could not read Slim candidate source: {relative_path(repository, path)}",
                    detector_id=DETECTOR_ID,
                )
            )
            continue
        if "->" not in text:
            continue

        recognized: set[int] = set()
        for match in _DIRECT.finditer(text):
            recognized.add(match.start())
            base_url, route_path = normalize_literal_url(match.group("path"))
            finding = EndpointFinding(
                direction="exposed",
                method=match.group("method"),
                path=route_path,
                base_url=base_url,
                provider_repository=repository.name,
                confidence="confirmed",
                confidence_reason="Literal Slim route method and path found in source.",
                evidence=[_evidence(repository, path, text, match.start(), "literal Slim route")],
            )
            endpoints[finding.identity()] = finding

        for call in _ANY_ROUTE_CALL.finditer(text):
            if call.start() in recognized:
                continue
            issues.append(
                DiscoveryIssue(
                    code="slim_dynamic_route_unresolved",
                    message=(
                        "Slim route call was found but its path could not be resolved as a "
                        "supported literal."
                    ),
                    detector_id=DETECTOR_ID,
                    evidence=(_evidence(repository, path, text, call.start(), "unresolved Slim route"),),
                )
            )

    coverage = DetectorCoverage(
        detector_id=DETECTOR_ID,
        detector_version=DETECTOR_VERSION,
        category="exposed",
        status="partial" if issues else "supported",
        files_scanned=len(php_files),
        supported_patterns=("$app->get/post/put/patch/delete/options with literal path",),
        unsupported_patterns=tuple(sorted({issue.code for issue in issues})),
        notes=("Dynamic Slim route paths fail closed.",),
    )
    return list(endpoints.values()), issues, coverage
