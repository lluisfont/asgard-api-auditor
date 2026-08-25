"""Laravel route discovery with explicit unsupported-pattern reporting."""

from __future__ import annotations

import re
from pathlib import Path

from ..discovery_types import DiscoveryIssue
from ..discovery_utils import line_number, normalize_literal_url, read_source, relative_path
from ..models import DetectorCoverage, EndpointFinding, Evidence

DETECTOR_ID = "laravel-routes"
DETECTOR_VERSION = "1.0.0"

_DIRECT = re.compile(
    r"\bRoute::(?P<method>get|post|put|patch|delete|options|head)\s*\(\s*"
    r"(?P<quote>['\"])(?P<path>.*?)(?P=quote)",
    re.IGNORECASE,
)
_MATCH = re.compile(
    r"\bRoute::match\s*\(\s*\[(?P<methods>[^\]]+)\]\s*,\s*"
    r"(?P<quote>['\"])(?P<path>.*?)(?P=quote)",
    re.IGNORECASE | re.DOTALL,
)
_ENDPOINT_CALL = re.compile(
    r"\bRoute::(?P<kind>get|post|put|patch|delete|options|head|match|any|resource|"
    r"apiResource|fallback)\s*\(",
    re.IGNORECASE,
)
_PREFIX = re.compile(
    r"(?:\bRoute::prefix\s*\(|['\"]prefix['\"]\s*=>)",
    re.IGNORECASE,
)
_LITERAL_METHOD = re.compile(r"['\"](get|post|put|patch|delete|options|head)['\"]", re.I)


def _evidence(repository: Path, path: Path, text: str, offset: int, note: str) -> Evidence:
    return Evidence(
        path=relative_path(repository, path),
        line=line_number(text, offset),
        kind="route",
        note=note,
    )


def detect_laravel_routes(
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
                    code="laravel_source_unreadable",
                    message=f"Could not read Laravel candidate source: {relative_path(repository, path)}",
                    detector_id=DETECTOR_ID,
                )
            )
            continue

        recognized_offsets: set[int] = set()
        for match in _DIRECT.finditer(text):
            recognized_offsets.add(match.start())
            method = match.group("method").upper()
            base_url, route_path = normalize_literal_url(match.group("path"))
            finding = EndpointFinding(
                direction="exposed",
                method=method,
                path=route_path,
                base_url=base_url,
                provider_repository=repository.name,
                confidence="confirmed",
                confidence_reason="Literal Laravel Route method and path found in source.",
                evidence=[_evidence(repository, path, text, match.start(), "literal Laravel route")],
            )
            endpoints[finding.identity()] = finding

        for match in _MATCH.finditer(text):
            recognized_offsets.add(match.start())
            methods = [item.upper() for item in _LITERAL_METHOD.findall(match.group("methods"))]
            if not methods:
                issues.append(
                    DiscoveryIssue(
                        code="laravel_dynamic_match_methods",
                        message="Route::match uses methods that could not be resolved as literals.",
                        detector_id=DETECTOR_ID,
                        evidence=(_evidence(repository, path, text, match.start(), "dynamic match methods"),),
                    )
                )
                continue
            base_url, route_path = normalize_literal_url(match.group("path"))
            for method in methods:
                finding = EndpointFinding(
                    direction="exposed",
                    method=method,
                    path=route_path,
                    base_url=base_url,
                    provider_repository=repository.name,
                    confidence="confirmed",
                    confidence_reason="Literal Laravel Route::match methods and path found in source.",
                    evidence=[_evidence(repository, path, text, match.start(), "literal Laravel match route")],
                )
                endpoints[finding.identity()] = finding

        for prefix in _PREFIX.finditer(text):
            issues.append(
                DiscoveryIssue(
                    code="laravel_route_prefix_unresolved",
                    message=(
                        "Laravel route prefix/group detected. v0.4 does not yet prove the fully "
                        "resolved path of nested routes."
                    ),
                    detector_id=DETECTOR_ID,
                    evidence=(_evidence(repository, path, text, prefix.start(), "route prefix/group"),),
                )
            )

        for call in _ENDPOINT_CALL.finditer(text):
            kind = call.group("kind").lower()
            if call.start() in recognized_offsets:
                continue
            if kind in {"resource", "apiresource", "any", "fallback"}:
                code = f"laravel_{kind}_unsupported"
                message = f"Laravel Route::{call.group('kind')} requires explicit expansion before completeness."
            else:
                code = "laravel_dynamic_route_unresolved"
                message = (
                    f"Laravel Route::{call.group('kind')} was found but its method/path could not "
                    "be resolved as supported literals."
                )
            issues.append(
                DiscoveryIssue(
                    code=code,
                    message=message,
                    detector_id=DETECTOR_ID,
                    evidence=(_evidence(repository, path, text, call.start(), "unresolved Laravel route"),),
                )
            )

    status = "partial" if issues else "supported"
    coverage = DetectorCoverage(
        detector_id=DETECTOR_ID,
        detector_version=DETECTOR_VERSION,
        category="exposed",
        status=status,
        files_scanned=len(php_files),
        supported_patterns=(
            "Route::get/post/put/patch/delete/options/head with literal path",
            "Route::match with literal method list and literal path",
        ),
        unsupported_patterns=tuple(sorted({issue.code for issue in issues})),
        notes=(
            "Route prefixes/groups, resource routes, any/fallback and dynamic expressions fail closed.",
        ),
    )
    return list(endpoints.values()), issues, coverage
