"""HTTP consumer discovery for the first ASGARD client set."""

from __future__ import annotations

import re
from pathlib import Path

from ..discovery_types import DiscoveryIssue
from ..discovery_utils import line_number, normalize_literal_url, read_source, relative_path
from ..models import DetectorCoverage, EndpointFinding, Evidence

_SUPPORTED = {"axios", "fetch", "guzzle", "laravel-http", "dio", "dart-http"}
_METHODS = "get|post|put|patch|delete|head|options"


def _evidence(repository: Path, path: Path, text: str, offset: int, note: str) -> Evidence:
    return Evidence(
        path=relative_path(repository, path),
        line=line_number(text, offset),
        kind="http_client",
        note=note,
    )


def _finding(
    repository: Path,
    path: Path,
    text: str,
    offset: int,
    method: str,
    url: str,
    client: str,
    *,
    confidence: str = "confirmed",
) -> EndpointFinding:
    base_url, endpoint_path = normalize_literal_url(url)
    return EndpointFinding(
        direction="consumed",
        method=method.upper(),
        path=endpoint_path,
        base_url=base_url,
        consumer_repository=repository.name,
        confidence=confidence,  # type: ignore[arg-type]
        confidence_reason=f"Literal {client} HTTP method and URL found in source.",
        evidence=[_evidence(repository, path, text, offset, f"{client} HTTP call")],
    )


def _axios(repository: Path, files: list[Path]) -> tuple[list[EndpointFinding], list[DiscoveryIssue], int]:
    endpoints: list[EndpointFinding] = []
    issues: list[DiscoveryIssue] = []
    scanned = 0
    for path in files:
        if path.suffix.lower() not in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue"}:
            continue
        text = read_source(path)
        if text is None or "axios" not in text:
            continue
        scanned += 1
        names = {"axios"}
        names.update(re.findall(r"\b(?:const|let|var)\s+(\w+)\s*=\s*axios\.create\s*\(", text))
        name_pattern = "|".join(re.escape(name) for name in sorted(names, key=len, reverse=True))
        literal = re.compile(
            rf"\b(?P<object>{name_pattern})\.(?P<method>{_METHODS})\s*\(\s*"
            r"(?P<quote>['\"`])(?P<url>.*?)(?P=quote)",
            re.IGNORECASE | re.DOTALL,
        )
        any_call = re.compile(rf"\b(?:{name_pattern})\.(?:{_METHODS})\s*\(", re.IGNORECASE)
        recognized = set()
        for match in literal.finditer(text):
            recognized.add(match.start())
            endpoints.append(
                _finding(
                    repository, path, text, match.start(), match.group("method"),
                    match.group("url"), "axios"
                )
            )
        for call in any_call.finditer(text):
            if call.start() not in recognized:
                issues.append(
                    DiscoveryIssue(
                        code="axios_dynamic_url_unresolved",
                        message="Axios call found with a URL expression that is not a supported literal.",
                        detector_id="axios-consumer",
                        evidence=(_evidence(repository, path, text, call.start(), "dynamic axios call"),),
                    )
                )
        for pattern, code in (
            (r"\baxios\.request\s*\(", "axios_request_config_unsupported"),
            (r"\baxios\s*\(\s*\{", "axios_callable_config_unsupported"),
        ):
            for match in re.finditer(pattern, text):
                issues.append(
                    DiscoveryIssue(
                        code=code,
                        message="Axios config-object call requires structured parsing before completeness.",
                        detector_id="axios-consumer",
                        evidence=(_evidence(repository, path, text, match.start(), "axios config call"),),
                    )
                )
    return endpoints, issues, scanned


def _fetch(repository: Path, files: list[Path]) -> tuple[list[EndpointFinding], list[DiscoveryIssue], int]:
    endpoints: list[EndpointFinding] = []
    issues: list[DiscoveryIssue] = []
    scanned = 0
    literal = re.compile(
        r"\bfetch\s*\(\s*(?P<quote>['\"`])(?P<url>.*?)(?P=quote)"
        r"(?P<options>\s*,\s*\{.*?\})?\s*\)",
        re.IGNORECASE | re.DOTALL,
    )
    any_call = re.compile(r"\bfetch\s*\(")
    for path in files:
        if path.suffix.lower() not in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue"}:
            continue
        text = read_source(path)
        if text is None or "fetch" not in text:
            continue
        scanned += 1
        recognized = set()
        for match in literal.finditer(text):
            recognized.add(match.start())
            method = "GET"
            options = match.group("options") or ""
            method_match = re.search(r"\bmethod\s*:\s*['\"]([A-Za-z]+)['\"]", options)
            if method_match:
                method = method_match.group(1).upper()
            endpoints.append(
                _finding(repository, path, text, match.start(), method, match.group("url"), "fetch")
            )
        for call in any_call.finditer(text):
            if call.start() not in recognized:
                issues.append(
                    DiscoveryIssue(
                        code="fetch_dynamic_or_complex_call_unresolved",
                        message="fetch() call could not be resolved as a supported literal URL/options form.",
                        detector_id="fetch-consumer",
                        evidence=(_evidence(repository, path, text, call.start(), "unresolved fetch call"),),
                    )
                )
    return endpoints, issues, scanned


def _guzzle(repository: Path, files: list[Path]) -> tuple[list[EndpointFinding], list[DiscoveryIssue], int]:
    endpoints: list[EndpointFinding] = []
    issues: list[DiscoveryIssue] = []
    scanned = 0
    for path in files:
        if path.suffix.lower() != ".php":
            continue
        text = read_source(path)
        if text is None:
            continue
        if not re.search(r"GuzzleHttp|new\s+Client\s*\(|->request\s*\(", text):
            continue
        scanned += 1
        variables = set(
            re.findall(
                r"(?P<var>\$[A-Za-z_]\w*)\s*=\s*new\s+(?:\\?GuzzleHttp\\Client|Client)\s*\(",
                text,
            )
        )
        request_literal = re.compile(
            r"(?P<object>\$[A-Za-z_]\w*(?:->\w+)*)->request\s*\(\s*"
            r"(?P<mq>['\"])(?P<method>[A-Za-z]+)(?P=mq)\s*,\s*"
            r"(?P<uq>['\"])(?P<url>.*?)(?P=uq)",
            re.IGNORECASE | re.DOTALL,
        )
        for match in request_literal.finditer(text):
            endpoints.append(
                _finding(
                    repository, path, text, match.start(), match.group("method"), match.group("url"),
                    "guzzle", confidence="confirmed" if match.group("object").split("->")[0] in variables else "probable"
                )
            )
        for variable in variables:
            direct = re.compile(
                rf"{re.escape(variable)}->(?P<method>{_METHODS})\s*\(\s*"
                r"(?P<quote>['\"])(?P<url>.*?)(?P=quote)",
                re.IGNORECASE | re.DOTALL,
            )
            any_call = re.compile(rf"{re.escape(variable)}->(?:{_METHODS})\s*\(", re.IGNORECASE)
            recognized = set()
            for match in direct.finditer(text):
                recognized.add(match.start())
                endpoints.append(
                    _finding(
                        repository, path, text, match.start(), match.group("method"), match.group("url"), "guzzle"
                    )
                )
            for call in any_call.finditer(text):
                if call.start() not in recognized:
                    issues.append(
                        DiscoveryIssue(
                            code="guzzle_dynamic_url_unresolved",
                            message="Guzzle direct method call found with a non-literal URL.",
                            detector_id="guzzle-consumer",
                            evidence=(_evidence(repository, path, text, call.start(), "dynamic Guzzle call"),),
                        )
                    )
    return endpoints, issues, scanned


def _laravel_http(repository: Path, files: list[Path]) -> tuple[list[EndpointFinding], list[DiscoveryIssue], int]:
    endpoints: list[EndpointFinding] = []
    issues: list[DiscoveryIssue] = []
    scanned = 0
    literal = re.compile(
        rf"\bHttp::(?P<method>{_METHODS})\s*\(\s*(?P<quote>['\"])(?P<url>.*?)(?P=quote)",
        re.IGNORECASE | re.DOTALL,
    )
    any_call = re.compile(rf"\bHttp::(?:{_METHODS}|send)\s*\(", re.IGNORECASE)
    for path in files:
        if path.suffix.lower() != ".php":
            continue
        text = read_source(path)
        if text is None or "Http::" not in text:
            continue
        scanned += 1
        recognized = set()
        for match in literal.finditer(text):
            recognized.add(match.start())
            endpoints.append(
                _finding(repository, path, text, match.start(), match.group("method"), match.group("url"), "laravel-http")
            )
        for call in any_call.finditer(text):
            if call.start() not in recognized:
                issues.append(
                    DiscoveryIssue(
                        code="laravel_http_complex_call_unresolved",
                        message="Laravel Http facade call could not be resolved as a direct literal method/URL.",
                        detector_id="laravel-http-consumer",
                        evidence=(_evidence(repository, path, text, call.start(), "unresolved Laravel Http call"),),
                    )
                )
    return endpoints, issues, scanned


def _dio(repository: Path, files: list[Path]) -> tuple[list[EndpointFinding], list[DiscoveryIssue], int]:
    endpoints: list[EndpointFinding] = []
    issues: list[DiscoveryIssue] = []
    scanned = 0
    for path in files:
        if path.suffix.lower() != ".dart":
            continue
        text = read_source(path)
        if text is None or "Dio" not in text:
            continue
        scanned += 1
        names = set(re.findall(r"\b(?:final|var|late\s+final)\s+(\w+)\s*=\s*Dio\s*\(", text))
        patterns = [r"Dio\s*\(\s*\)"] + [re.escape(name) for name in names]
        object_pattern = "|".join(patterns)
        literal = re.compile(
            rf"(?P<object>{object_pattern})\.(?P<method>{_METHODS})\s*\(\s*"
            r"(?P<quote>['\"])(?P<url>.*?)(?P=quote)",
            re.IGNORECASE | re.DOTALL,
        )
        any_call = re.compile(rf"(?:{object_pattern})\.(?:{_METHODS})\s*\(", re.IGNORECASE)
        recognized = set()
        for match in literal.finditer(text):
            recognized.add(match.start())
            endpoints.append(
                _finding(repository, path, text, match.start(), match.group("method"), match.group("url"), "dio")
            )
        for call in any_call.finditer(text):
            if call.start() not in recognized:
                issues.append(
                    DiscoveryIssue(
                        code="dio_dynamic_url_unresolved",
                        message="Dio call found with a non-literal URL.",
                        detector_id="dio-consumer",
                        evidence=(_evidence(repository, path, text, call.start(), "dynamic Dio call"),),
                    )
                )
    return endpoints, issues, scanned


def _dart_http(repository: Path, files: list[Path]) -> tuple[list[EndpointFinding], list[DiscoveryIssue], int]:
    endpoints: list[EndpointFinding] = []
    issues: list[DiscoveryIssue] = []
    scanned = 0
    for path in files:
        if path.suffix.lower() != ".dart":
            continue
        text = read_source(path)
        if text is None or "package:http/" not in text:
            continue
        scanned += 1
        aliases = set(re.findall(r"import\s+['\"]package:http/http\.dart['\"]\s+as\s+(\w+)\s*;", text))
        aliases.add("http")
        alias_pattern = "|".join(re.escape(alias) for alias in sorted(aliases))
        literal = re.compile(
            rf"\b(?P<object>{alias_pattern})\.(?P<method>{_METHODS})\s*\(\s*Uri\.parse\s*\(\s*"
            r"(?P<quote>['\"])(?P<url>.*?)(?P=quote)\s*\)",
            re.IGNORECASE | re.DOTALL,
        )
        any_call = re.compile(rf"\b(?:{alias_pattern})\.(?:{_METHODS})\s*\(", re.IGNORECASE)
        recognized = set()
        for match in literal.finditer(text):
            recognized.add(match.start())
            endpoints.append(
                _finding(repository, path, text, match.start(), match.group("method"), match.group("url"), "dart-http")
            )
        for call in any_call.finditer(text):
            if call.start() not in recognized:
                issues.append(
                    DiscoveryIssue(
                        code="dart_http_complex_uri_unresolved",
                        message="Dart http call uses a URI form that v0.4 cannot resolve exactly.",
                        detector_id="dart-http-consumer",
                        evidence=(_evidence(repository, path, text, call.start(), "complex Dart http call"),),
                    )
                )
    return endpoints, issues, scanned


_HANDLERS = {
    "axios": _axios,
    "fetch": _fetch,
    "guzzle": _guzzle,
    "laravel-http": _laravel_http,
    "dio": _dio,
    "dart-http": _dart_http,
}


def detect_consumed_endpoints(
    repository: Path,
    files: list[Path],
    client_names: set[str],
) -> tuple[list[EndpointFinding], list[DiscoveryIssue], list[DetectorCoverage]]:
    endpoints: dict[tuple[str, str, str], EndpointFinding] = {}
    issues: list[DiscoveryIssue] = []
    coverages: list[DetectorCoverage] = []

    for client in sorted(client_names):
        detector_id = f"{client}-consumer"
        if client not in _SUPPORTED:
            issue = DiscoveryIssue(
                code="unsupported_http_client",
                message=f"HTTP client '{client}' is detected but has no v0.4 endpoint detector.",
                detector_id=detector_id,
            )
            issues.append(issue)
            coverages.append(
                DetectorCoverage(
                    detector_id=detector_id,
                    detector_version="0.0.0",
                    category="consumed",
                    status="unsupported",
                    unsupported_patterns=(client,),
                )
            )
            continue

        found, client_issues, scanned = _HANDLERS[client](repository, files)
        for finding in found:
            endpoints[finding.identity()] = finding
        if not found:
            client_issues.append(
                DiscoveryIssue(
                    code="http_client_detected_no_calls",
                    message=(
                        f"HTTP client '{client}' was detected by inventory but no supported direct calls "
                        "were proven. Wrapper or dynamic usage may exist."
                    ),
                    detector_id=detector_id,
                )
            )
        issues.extend(client_issues)
        coverages.append(
            DetectorCoverage(
                detector_id=detector_id,
                detector_version="1.0.0",
                category="consumed",
                status="partial" if client_issues else "supported",
                files_scanned=scanned,
                supported_patterns=(f"direct literal {client} HTTP calls",),
                unsupported_patterns=tuple(sorted({issue.code for issue in client_issues})),
            )
        )

    return list(endpoints.values()), issues, coverages
