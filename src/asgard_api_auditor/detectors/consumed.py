"""HTTP consumer discovery for the first ASGARD client set."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..discovery_types import DiscoveryIssue
from ..discovery_utils import line_number, mask_c_like_comments, normalize_literal_url, read_source, relative_path
from ..models import DetectorCoverage, EndpointFinding, Evidence

_SUPPORTED = {
    "angular-httpclient",
    "axios",
    "fetch",
    "guzzle",
    "laravel-http",
    "dio",
    "dart-http",
    "php-curl",
}
_METHODS = "get|post|put|patch|delete|head|options"


def _mask_consumer_comments(path: Path, text: str) -> str:
    suffix = path.suffix.lower()
    return mask_c_like_comments(
        text,
        hash_comments=suffix == ".php",
        html_comments=suffix == ".vue",
    )


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
    base_url: str | None = None,
    endpoint_path: str | None = None,
    extra_evidence: tuple[Evidence, ...] = (),
) -> EndpointFinding:
    if endpoint_path is None:
        base_url, endpoint_path = normalize_literal_url(url)
    return EndpointFinding(
        direction="consumed",
        method=method.upper(),
        path=endpoint_path,
        base_url=base_url,
        consumer_repository=repository.name,
        confidence=confidence,  # type: ignore[arg-type]
        confidence_reason=f"Literal {client} HTTP method and URL found in source.",
        evidence=[
            _evidence(repository, path, text, offset, f"{client} HTTP call"),
            *extra_evidence,
        ],
    )


def _method_from_options(options: str, default: str = "GET") -> str:
    method_match = re.search(r"\bmethod\s*:\s*['\"]([A-Za-z]+)['\"]", options)
    if method_match:
        return method_match.group(1).upper()
    return default


def _literal_value(expression: str) -> str | None:
    expression = expression.strip()
    match = re.fullmatch(r"(?P<quote>['\"`])(?P<value>.*?)(?P=quote)", expression, re.DOTALL)
    if not match:
        return None
    return match.group("value")


def _split_concat(expression: str) -> list[str]:
    return [part.strip() for part in expression.split("+") if part.strip()]


def _axios(repository: Path, files: list[Path]) -> tuple[list[EndpointFinding], list[DiscoveryIssue], int]:
    endpoints: list[EndpointFinding] = []
    issues: list[DiscoveryIssue] = []
    scanned = 0
    for path in files:
        if path.suffix.lower() not in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue"}:
            continue
        text = read_source(path)
        if text is None:
            continue
        masked = _mask_consumer_comments(path, text)
        if "axios" not in masked:
            continue
        scanned += 1
        names = {"axios"}
        names.update(re.findall(r"\b(?:const|let|var)\s+(\w+)\s*=\s*axios\.create\s*\(", masked))
        name_pattern = "|".join(re.escape(name) for name in sorted(names, key=len, reverse=True))
        literal = re.compile(
            rf"\b(?P<object>{name_pattern})\.(?P<method>{_METHODS})\s*\(\s*"
            r"(?P<quote>['\"`])(?P<url>.*?)(?P=quote)",
            re.IGNORECASE | re.DOTALL,
        )
        any_call = re.compile(rf"\b(?:{name_pattern})\.(?:{_METHODS})\s*\(", re.IGNORECASE)
        recognized = set()
        for match in literal.finditer(masked):
            recognized.add(match.start())
            endpoints.append(
                _finding(
                    repository, path, text, match.start(), match.group("method"),
                    match.group("url"), "axios"
                )
            )
        for call in any_call.finditer(masked):
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
            for match in re.finditer(pattern, masked):
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
    this_property = re.compile(
        r"\bfetch\s*\(\s*this\.(?P<property>[A-Za-z_]\w*)"
        r"\s*(?:(?P<options>,\s*\{.*?\})\s*)?\)",
        re.IGNORECASE | re.DOTALL,
    )
    any_call = re.compile(r"\bfetch\s*\(")
    for path in files:
        if path.suffix.lower() not in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue"}:
            continue
        text = read_source(path)
        if text is None:
            continue
        masked = _mask_consumer_comments(path, text)
        if "fetch" not in masked:
            continue
        scanned += 1
        property_literals: dict[str, tuple[str, int]] = {}
        for assignment in re.finditer(
            r"\bthis\.(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<quote>['\"`])(?P<value>.*?)(?P=quote)",
            masked,
            re.DOTALL,
        ):
            property_literals[assignment.group("name")] = (assignment.group("value"), assignment.start())
        for field in re.finditer(
            r"\b(?:(?:private|public|protected|readonly|static)\s+)*"
            r"(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<quote>['\"`])(?P<value>.*?)(?P=quote)",
            masked,
            re.DOTALL,
        ):
            property_literals.setdefault(field.group("name"), (field.group("value"), field.start()))
        recognized = set()
        for match in literal.finditer(masked):
            recognized.add(match.start())
            method = _method_from_options(match.group("options") or "")
            endpoints.append(
                _finding(repository, path, text, match.start(), method, match.group("url"), "fetch")
            )
        for match in this_property.finditer(masked):
            property_name = match.group("property")
            resolved = property_literals.get(property_name)
            if resolved is None:
                continue
            recognized.add(match.start())
            url, assignment_offset = resolved
            endpoints.append(
                _finding(
                    repository,
                    path,
                    text,
                    match.start(),
                    _method_from_options(match.group("options") or ""),
                    url,
                    "fetch",
                    extra_evidence=(
                        _evidence(repository, path, text, assignment_offset, "literal fetch URL property"),
                    ),
                )
            )
        for call in any_call.finditer(masked):
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
        masked = _mask_consumer_comments(path, text)
        if not re.search(r"GuzzleHttp|new\s+Client\s*\(|->request\s*\(", masked):
            continue
        scanned += 1
        variables = set(
            re.findall(
                r"(?P<var>\$[A-Za-z_]\w*)\s*=\s*new\s+(?:\\?GuzzleHttp\\Client|Client)\s*\(",
                masked,
            )
        )
        request_literal = re.compile(
            r"(?P<object>\$[A-Za-z_]\w*(?:->\w+)*)->request\s*\(\s*"
            r"(?P<mq>['\"])(?P<method>[A-Za-z]+)(?P=mq)\s*,\s*"
            r"(?P<uq>['\"])(?P<url>.*?)(?P=uq)",
            re.IGNORECASE | re.DOTALL,
        )
        for match in request_literal.finditer(masked):
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
            for match in direct.finditer(masked):
                recognized.add(match.start())
                endpoints.append(
                    _finding(
                        repository, path, text, match.start(), match.group("method"), match.group("url"), "guzzle"
                    )
                )
            for call in any_call.finditer(masked):
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
        if text is None:
            continue
        masked = _mask_consumer_comments(path, text)
        if "Http::" not in masked:
            continue
        scanned += 1
        recognized = set()
        for match in literal.finditer(masked):
            recognized.add(match.start())
            endpoints.append(
                _finding(repository, path, text, match.start(), match.group("method"), match.group("url"), "laravel-http")
            )
        for call in any_call.finditer(masked):
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


def _angular_global_values(text: str) -> dict[str, tuple[str, int]]:
    values: dict[str, tuple[str, int]] = {}
    for match in re.finditer(
        r"\bGLOBAL\.(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<quote>['\"`])(?P<value>.*?)(?P=quote)",
        text,
        re.DOTALL,
    ):
        values[f"GLOBAL.{match.group('name')}"] = (match.group("value"), match.start())
    for obj in re.finditer(r"\bGLOBAL\s*=\s*\{(?P<body>.*?)\}", text, re.DOTALL):
        for prop in re.finditer(
            r"\b(?P<name>[A-Za-z_]\w*)\s*:\s*(?P<quote>['\"`])(?P<value>.*?)(?P=quote)",
            obj.group("body"),
            re.DOTALL,
        ):
            values[f"GLOBAL.{prop.group('name')}"] = (
                prop.group("value"),
                obj.start() + prop.start(),
            )
    return values


def _angular_this_values(
    text: str,
    globals_by_name: dict[str, tuple[str, int]],
) -> dict[str, tuple[str, int]]:
    values: dict[str, tuple[str, int]] = {}
    for match in re.finditer(
        r"\b(?:this\.)?(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<expr>[^;\n]+)",
        text,
        re.DOTALL,
    ):
        name = f"this.{match.group('name')}"
        expression = match.group("expr").strip()
        literal = _literal_value(expression)
        if literal is not None:
            values[name] = (literal, match.start())
            continue
        resolved = globals_by_name.get(expression)
        if resolved is not None:
            values[name] = (resolved[0], match.start())
    return values


def _placeholder_for_expression(expression: str) -> str:
    name = (
        expression.strip()
        .removeprefix("$this->")
        .removeprefix("this.")
        .removeprefix("$")
    )
    name = re.sub(r"[^A-Za-z0-9_]+", "_", name).strip("_")
    return "{" + (name or "value") + "}"


def _resolve_angular_url(expression: str, values: dict[str, tuple[str, int]]) -> tuple[str | None, str | None, int | None]:
    expression = expression.strip()
    literal = _literal_value(expression)
    if literal is not None:
        base_url, endpoint_path = normalize_literal_url(literal)
        return base_url, endpoint_path, None

    parts = _split_concat(expression)
    if not parts:
        return None, None, None

    first = parts[0]
    resolved_first = values.get(first)
    if resolved_first is not None and len(parts) > 1:
        suffix = ""
        for part in parts[1:]:
            literal_part = _literal_value(part)
            suffix += literal_part if literal_part is not None else _placeholder_for_expression(part)
        assignment_offset = None if first.startswith("GLOBAL.") else resolved_first[1]
        return resolved_first[0].rstrip("/"), "/" + suffix.lstrip("/"), assignment_offset

    resolved_parts: list[str] = []
    assignment_offset: int | None = None
    for part in parts:
        literal_part = _literal_value(part)
        if literal_part is not None:
            resolved_parts.append(literal_part)
            continue
        value = values.get(part)
        if value is not None:
            resolved_parts.append(value[0])
            if not part.startswith("GLOBAL."):
                assignment_offset = value[1]
            continue
        resolved_parts.append(_placeholder_for_expression(part))
    base_url, endpoint_path = normalize_literal_url("".join(resolved_parts))
    return base_url, endpoint_path, assignment_offset


def _angular_httpclient(
    repository: Path,
    files: list[Path],
) -> tuple[list[EndpointFinding], list[DiscoveryIssue], int]:
    endpoints: list[EndpointFinding] = []
    issues: list[DiscoveryIssue] = []
    scanned = 0
    global_values: dict[str, tuple[str, int]] = {}
    for path in files:
        if path.suffix.lower() not in {".ts", ".tsx"}:
            continue
        text = read_source(path)
        if text is None:
            continue
        masked = _mask_consumer_comments(path, text)
        if "GLOBAL" in masked:
            global_values.update(_angular_global_values(masked))

    for path in files:
        if path.suffix.lower() not in {".ts", ".tsx"}:
            continue
        text = read_source(path)
        if text is None:
            continue
        masked = _mask_consumer_comments(path, text)
        if "HttpClient" not in masked:
            continue
        clients = set(
            re.findall(
                r"\b(?:private|public|protected|readonly|\s)+(?P<name>[A-Za-z_]\w*)\s*:\s*HttpClient\b",
                masked,
            )
        )
        clients.update({"http", "_http"})
        client_pattern = "|".join(re.escape(client) for client in sorted(clients, key=len, reverse=True))
        calls = re.compile(
            rf"\bthis\.(?P<object>{client_pattern})\.(?P<method>get|post|put|delete|patch)"
            r"\s*\(\s*(?P<url>[^,\n;)]+)",
            re.IGNORECASE,
        )
        any_call = re.compile(
            rf"\bthis\.(?:{client_pattern})\.(?:get|post|put|delete|patch)\s*\(",
            re.IGNORECASE,
        )
        values = _angular_this_values(masked, {**global_values, **_angular_global_values(masked)})
        scanned += 1
        recognized: set[int] = set()
        for match in calls.finditer(masked):
            base_url, endpoint_path, assignment_offset = _resolve_angular_url(match.group("url"), values)
            if endpoint_path is None:
                continue
            recognized.add(match.start())
            extra_evidence: tuple[Evidence, ...] = ()
            if assignment_offset is not None:
                extra_evidence = (
                    _evidence(repository, path, text, assignment_offset, "Angular base URL assignment"),
                )
            endpoints.append(
                _finding(
                    repository,
                    path,
                    text,
                    match.start(),
                    match.group("method"),
                    match.group("url"),
                    "angular-httpclient",
                    base_url=base_url,
                    endpoint_path=endpoint_path,
                    extra_evidence=extra_evidence,
                )
            )
        for call in any_call.finditer(masked):
            if call.start() not in recognized:
                issues.append(
                    DiscoveryIssue(
                        code="angular_httpclient_dynamic_url_unresolved",
                        message="Angular HttpClient call found with a URL expression that is not supported.",
                        detector_id="angular-httpclient-consumer",
                        evidence=(_evidence(repository, path, text, call.start(), "dynamic Angular HttpClient call"),),
                    )
                )
    return endpoints, issues, scanned


@dataclass(frozen=True)
class _DartClassFacts:
    fields: dict[str, str]


@dataclass(frozen=True)
class _DartClassRange:
    name: str
    start: int
    end: int


@dataclass(frozen=True)
class _DartFunctionRange:
    start: int
    end: int


@dataclass(frozen=True)
class _DartCallCandidate:
    receiver: str
    method: str
    url: str | None
    offset: int


def _dart_class_body(text: str, class_match: re.Match[str]) -> str:
    open_brace = text.find("{", class_match.end())
    if open_brace < 0:
        return ""
    close_brace = _matching_brace(text, open_brace)
    if close_brace is None:
        return text[open_brace + 1 :]
    return text[open_brace + 1 : close_brace]


def _dart_class_ranges(text: str) -> list[_DartClassRange]:
    ranges: list[_DartClassRange] = []
    for class_match in re.finditer(r"\bclass\s+(?P<name>[A-Z][A-Za-z0-9_]*)\b", text):
        open_brace = text.find("{", class_match.end())
        if open_brace < 0:
            continue
        close_brace = _matching_brace(text, open_brace)
        if close_brace is None:
            close_brace = len(text)
        ranges.append(_DartClassRange(class_match.group("name"), open_brace + 1, close_brace))
    return ranges


def _dart_function_ranges(text: str) -> list[_DartFunctionRange]:
    ranges: list[_DartFunctionRange] = []
    declaration = re.compile(
        r"(?:^|[;\}\n])\s*"
        r"(?:[A-Za-z_<>,\?\[\]\s]+\s+)?"
        r"(?P<name>_?[A-Za-z]\w*)\s*"
        r"\([^;{}]*\)\s*(?:async\s*)?\{",
        re.MULTILINE,
    )
    control_keywords = {"if", "for", "while", "switch", "catch", "do"}
    for match in declaration.finditer(text):
        if match.group("name") in control_keywords:
            continue
        open_brace = text.find("{", match.start())
        if open_brace < 0:
            continue
        close_brace = _matching_brace(text, open_brace)
        if close_brace is None:
            close_brace = len(text)
        ranges.append(_DartFunctionRange(open_brace + 1, close_brace))
    return ranges


def _dart_brace_depth(text: str, offset: int) -> int:
    depth = 0
    for char in text[:offset]:
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
    return depth


def _dart_class_facts(files: list[Path]) -> dict[str, _DartClassFacts]:
    facts: dict[str, _DartClassFacts] = {}
    field_pattern = re.compile(
        r"^\s*(?:late\s+)?(?:final\s+)?(?P<type>[A-Z][A-Za-z0-9_]*)\??\s+"
        r"(?P<name>_?[A-Za-z][A-Za-z0-9_]*)\s*(?:[;=,])",
        re.MULTILINE,
    )
    for path in files:
        if path.suffix.lower() != ".dart":
            continue
        text = read_source(path)
        if text is None:
            continue
        masked = _mask_consumer_comments(path, text)
        for class_range in _dart_class_ranges(masked):
            body = masked[class_range.start : class_range.end]
            if not body:
                continue
            fields = dict(facts.get(class_range.name, _DartClassFacts({})).fields)
            for field in field_pattern.finditer(body):
                if _dart_brace_depth(body, field.start()) != 0:
                    continue
                fields[field.group("name")] = field.group("type")
            facts[class_range.name] = _DartClassFacts(fields)
    return facts


def _dart_enclosing_class(ranges: list[_DartClassRange], offset: int) -> _DartClassRange | None:
    enclosing = [item for item in ranges if item.start <= offset <= item.end]
    if not enclosing:
        return None
    return min(enclosing, key=lambda item: item.end - item.start)


def _dart_enclosing_function(ranges: list[_DartFunctionRange], offset: int) -> _DartFunctionRange | None:
    enclosing = [item for item in ranges if item.start <= offset <= item.end]
    if not enclosing:
        return None
    return min(enclosing, key=lambda item: item.end - item.start)


def _dart_dio_direct_receivers_before(masked: str, offset: int, scope_start: int) -> set[str]:
    receivers: set[str] = set()
    prefix = masked[scope_start:offset]
    for match in re.finditer(
        r"\b(?:final|var|late\s+final)\s+(?P<name>_?[A-Za-z]\w*)\s*=\s*Dio\s*\(",
        prefix,
    ):
        receivers.add(match.group("name"))
    for match in re.finditer(
        r"^\s*(?:late\s+)?(?:final\s+)?Dio\??\s+(?P<name>_?[A-Za-z]\w*)\s*(?:[;=,])",
        prefix,
        re.MULTILINE,
    ):
        receivers.add(match.group("name"))
        receivers.add(f"this.{match.group('name')}")
    return receivers


def _dart_top_level_dio_receivers_before(masked: str, offset: int) -> set[str]:
    receivers: set[str] = set()
    for match in re.finditer(
        r"\b(?:final|var|late\s+final)\s+(?P<name>_?[A-Za-z]\w*)\s*=\s*Dio\s*\(",
        masked[:offset],
    ):
        if _dart_brace_depth(masked, match.start()) == 0:
            receivers.add(match.group("name"))
    for match in re.finditer(
        r"^\s*(?:late\s+)?(?:final\s+)?Dio\??\s+(?P<name>_?[A-Za-z]\w*)\s*(?:[;=,])",
        masked[:offset],
        re.MULTILINE,
    ):
        if _dart_brace_depth(masked, match.start()) == 0:
            receivers.add(match.group("name"))
    return receivers


def _dart_dio_candidate_direct_receivers(masked: str) -> set[str]:
    receivers: set[str] = {"dio", "this.dio"}
    for match in re.finditer(
        r"\b(?:final|var|late\s+final)\s+(?P<name>_?[A-Za-z]\w*)\s*=\s*Dio\s*\(",
        masked,
    ):
        receivers.add(match.group("name"))
    for match in re.finditer(
        r"^\s*(?:late\s+)?(?:final\s+)?Dio\??\s+(?P<name>_?[A-Za-z]\w*)\s*(?:[;=,])",
        masked,
        re.MULTILINE,
    ):
        receivers.add(match.group("name"))
        receivers.add(f"this.{match.group('name')}")
    return receivers


def _dart_receiver_is_proven_dio(
    receiver: str,
    masked: str,
    class_facts: dict[str, _DartClassFacts],
    class_ranges: list[_DartClassRange],
    function_ranges: list[_DartFunctionRange],
    offset: int,
) -> bool:
    if receiver == "Dio()":
        return True
    enclosing_class = _dart_enclosing_class(class_ranges, offset)
    enclosing_function = _dart_enclosing_function(function_ranges, offset)
    if enclosing_function and receiver in _dart_dio_direct_receivers_before(masked, offset, enclosing_function.start):
        return True
    if receiver in _dart_top_level_dio_receivers_before(masked, offset):
        return True

    normalized = receiver.removeprefix("this.")
    parts = normalized.split(".")
    if not parts:
        return False
    if len(parts) == 1:
        if enclosing_class is None:
            return False
        return class_facts.get(enclosing_class.name, _DartClassFacts({})).fields.get(parts[0]) == "Dio"
    if enclosing_class is None:
        return False
    current_type = class_facts.get(enclosing_class.name, _DartClassFacts({})).fields.get(parts[0])
    for member in parts[1:]:
        if current_type is None:
            return False
        current_type = class_facts.get(current_type, _DartClassFacts({})).fields.get(member)
    return current_type == "Dio"


def _dart_dio_candidates(masked: str) -> list[_DartCallCandidate]:
    candidates: list[_DartCallCandidate] = []
    direct_receivers = _dart_dio_candidate_direct_receivers(masked)
    call_pattern = re.compile(
        rf"(?P<receiver>Dio\s*\(\s*\)|(?:this\.)?_?[A-Za-z]\w*(?:\._?[A-Za-z]\w*)*)"
        rf"\.(?P<method>{_METHODS})\s*\(\s*"
        r"(?:(?P<quote>['\"])(?P<url>.*?)(?P=quote))?",
        re.IGNORECASE | re.DOTALL,
    )
    for match in call_pattern.finditer(masked):
        receiver = re.sub(r"\s+", "", match.group("receiver"))
        normalized = receiver.removeprefix("this.")
        if receiver != "Dio()" and ".dio" not in receiver and receiver not in direct_receivers and normalized not in direct_receivers:
            continue
        candidates.append(
            _DartCallCandidate(
                receiver=receiver,
                method=match.group("method"),
                url=match.group("url"),
                offset=match.start(),
            )
        )
    return candidates


def _dio(repository: Path, files: list[Path]) -> tuple[list[EndpointFinding], list[DiscoveryIssue], int]:
    endpoints: list[EndpointFinding] = []
    issues: list[DiscoveryIssue] = []
    scanned = 0
    class_facts = _dart_class_facts(files)
    for path in files:
        if path.suffix.lower() != ".dart":
            continue
        text = read_source(path)
        if text is None:
            continue
        masked = _mask_consumer_comments(path, text)
        if "Dio" not in masked and ".dio" not in masked:
            continue
        scanned += 1
        class_ranges = _dart_class_ranges(masked)
        function_ranges = _dart_function_ranges(masked)
        for candidate in _dart_dio_candidates(masked):
            if not _dart_receiver_is_proven_dio(
                candidate.receiver,
                masked,
                class_facts,
                class_ranges,
                function_ranges,
                candidate.offset,
            ):
                issues.append(
                    DiscoveryIssue(
                        code="dio_receiver_unresolved",
                        message=(
                            "Dio-like HTTP call found, but the receiver could not be proven "
                            "as a Dio instance from source types or assignments."
                        ),
                        detector_id="dio-consumer",
                        evidence=(_evidence(repository, path, text, candidate.offset, "unresolved Dio receiver"),),
                    )
                )
                continue
            if candidate.url is None:
                issues.append(
                    DiscoveryIssue(
                        code="dio_dynamic_url_unresolved",
                        message="Dio call found with a non-literal URL.",
                        detector_id="dio-consumer",
                        evidence=(_evidence(repository, path, text, candidate.offset, "dynamic Dio call"),),
                    )
                )
                continue
            endpoints.append(
                _finding(
                    repository,
                    path,
                    text,
                    candidate.offset,
                    candidate.method,
                    candidate.url,
                    "dio",
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
        if text is None:
            continue
        masked = _mask_consumer_comments(path, text)
        if "package:http/" not in masked:
            continue
        scanned += 1
        aliases = set(re.findall(r"import\s+['\"]package:http/http\.dart['\"]\s+as\s+(\w+)\s*;", masked))
        aliases.add("http")
        alias_pattern = "|".join(re.escape(alias) for alias in sorted(aliases))
        literal = re.compile(
            rf"\b(?P<object>{alias_pattern})\.(?P<method>{_METHODS})\s*\(\s*Uri\.parse\s*\(\s*"
            r"(?P<quote>['\"])(?P<url>.*?)(?P=quote)\s*\)",
            re.IGNORECASE | re.DOTALL,
        )
        any_call = re.compile(rf"\b(?:{alias_pattern})\.(?:{_METHODS})\s*\(", re.IGNORECASE)
        recognized = set()
        for match in literal.finditer(masked):
            recognized.add(match.start())
            endpoints.append(
                _finding(repository, path, text, match.start(), match.group("method"), match.group("url"), "dart-http")
            )
        for call in any_call.finditer(masked):
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


def _php_concat_parts(expression: str) -> list[str]:
    return [part.strip() for part in expression.split(".") if part.strip()]


def _php_expression_to_url_parts(expression: str) -> tuple[str | None, str | None]:
    expression = expression.strip().rstrip(",")
    literal = _literal_value(expression)
    if literal is not None:
        return normalize_literal_url(literal)

    parts = _php_concat_parts(expression)
    if len(parts) < 2:
        return None, None

    base_expression: str | None = None
    path = ""
    for part in parts:
        literal_part = _literal_value(part)
        if literal_part is not None:
            path += literal_part
        elif base_expression is None:
            base_expression = part.strip().removeprefix("$")
        else:
            path += _placeholder_for_expression(part)

    if base_expression and path:
        return base_expression, "/" + path.lstrip("/")
    return None, None


def _php_literal_method(expression: str) -> str | None:
    literal = _literal_value(expression.strip().rstrip(","))
    return literal.upper() if literal else None


@dataclass(frozen=True)
class _PhpMethod:
    name: str
    params: tuple[str, ...]
    body: str
    start: int
    body_start: int
    body_end: int


@dataclass(frozen=True)
class _PhpClass:
    body: str
    start: int
    body_start: int
    body_end: int
    methods: dict[str, _PhpMethod]


@dataclass(frozen=True)
class _PhpScope:
    method: _PhpMethod
    parent: _PhpScope | None = None
    bindings: dict[str, str] | None = None
    call_offset: int | None = None


@dataclass(frozen=True)
class _PhpResolvedUrl:
    base_url: str | None
    endpoint_path: str
    evidence: tuple[Evidence, ...] = ()
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class _PhpResolvedCall:
    method: str
    url: _PhpResolvedUrl
    curl_offset: int
    evidence_offsets: tuple[tuple[int, str], ...] = ()


def _matching_brace(text: str, open_offset: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(open_offset, len(text)):
        char = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _matching_paren(text: str, open_offset: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(open_offset, len(text)):
        char = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_php_arguments(arguments: str) -> list[str]:
    result: list[str] = []
    start = 0
    parens = brackets = arrays = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(arguments):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "(":
            parens += 1
        elif char == ")":
            parens -= 1
        elif char == "[":
            brackets += 1
        elif char == "]":
            brackets -= 1
        elif char == "{":
            arrays += 1
        elif char == "}":
            arrays -= 1
        elif char == "," and parens == 0 and brackets == 0 and arrays == 0:
            result.append(arguments[start:index].strip())
            start = index + 1
    tail = arguments[start:].strip()
    if tail:
        result.append(tail)
    return result


def _php_classes(text: str) -> list[_PhpClass]:
    classes: list[_PhpClass] = []
    for class_match in re.finditer(r"\bclass\s+[A-Za-z_]\w*[^{]*\{", text):
        body_start = class_match.end()
        body_end = _matching_brace(text, body_start - 1)
        if body_end is None:
            continue
        body = text[body_start:body_end]
        methods: dict[str, _PhpMethod] = {}
        for method_match in re.finditer(
            r"\b(?:public|protected|private)?\s*function\s+"
            r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*\{",
            body,
        ):
            method_body_start = body_start + method_match.end()
            method_body_end = _matching_brace(text, method_body_start - 1)
            if method_body_end is None or method_body_end > body_end:
                continue
            params = tuple(
                match.group(0)
                for match in re.finditer(r"\$[A-Za-z_]\w*", method_match.group("params"))
            )
            methods.setdefault(
                method_match.group("name"),
                _PhpMethod(
                    name=method_match.group("name"),
                    params=params,
                    body=text[method_body_start:method_body_end],
                    start=body_start + method_match.start(),
                    body_start=method_body_start,
                    body_end=method_body_end,
                ),
            )
        classes.append(_PhpClass(body=body, start=class_match.start(), body_start=body_start, body_end=body_end, methods=methods))
    return classes


def _php_method_assignments(method: _PhpMethod, before_offset: int) -> dict[str, str | None]:
    assignments: dict[str, str | None] = {}
    body_limit = max(0, before_offset - method.body_start)
    prefix = method.body[:body_limit]
    for match in re.finditer(r"(?P<var>\$[A-Za-z_]\w*)\s*(?P<op>=|\.=)\s*(?P<expr>.*?)\s*;", prefix, re.DOTALL):
        variable = match.group("var")
        expression = match.group("expr").strip()
        if match.group("op") == "=":
            previous = assignments.get(variable)
            assignments[variable] = expression if previous in {None, expression} else None
        elif _literal_value(expression.split(".", 1)[0].strip()) == "?":
            assignments.setdefault(variable, assignments.get(variable))
        else:
            assignments[variable] = None
    return assignments


def _php_find_this_calls(method: _PhpMethod) -> list[tuple[str, list[str], int]]:
    calls: list[tuple[str, list[str], int]] = []
    for match in re.finditer(r"\$this->(?P<name>[A-Za-z_]\w*)\s*\(", method.body):
        close_offset = _matching_paren(method.body, match.end() - 1)
        if close_offset is None:
            continue
        args = _split_php_arguments(method.body[match.end():close_offset])
        calls.append((match.group("name"), args, method.body_start + match.start()))
    return calls


def _php_resolve_method_expression(expression: str, scope: _PhpScope, depth: int = 0) -> str | None:
    if depth > 8:
        return None
    expression = expression.strip().rstrip(",")
    literal = _php_literal_method(expression)
    if literal is not None:
        return literal
    if re.fullmatch(r"\$[A-Za-z_]\w*", expression):
        assignments = _php_method_assignments(scope.method, scope.call_offset or scope.method.body_end)
        assigned = assignments.get(expression)
        if assigned:
            return _php_resolve_method_expression(assigned, scope, depth + 1)
        if scope.bindings and expression in scope.bindings and scope.parent is not None:
            return _php_resolve_method_expression(scope.bindings[expression], scope.parent, depth + 1)
    return None


def _php_local_expression(method: _PhpMethod, variable: str, before_offset: int) -> str | None:
    assignments = _php_method_assignments(method, before_offset)
    value = assignments.get(variable)
    return value if isinstance(value, str) else None


def _php_blob_placeholder(expression: str, method: _PhpMethod, before_offset: int) -> str:
    expression = expression.strip()
    if re.fullmatch(r"\$[A-Za-z_]\w*", expression):
        assigned = _php_local_expression(method, expression, before_offset)
        if assigned:
            if re.match(r"array_map\s*\(\s*['\"]rawurlencode['\"]\s*,", assigned):
                inner = _split_php_arguments(assigned[assigned.find("(") + 1 : assigned.rfind(")")])
                if len(inner) >= 2:
                    return _php_blob_placeholder(inner[1], method, before_offset)
            if re.match(r"explode\s*\(", assigned):
                inner = _split_php_arguments(assigned[assigned.find("(") + 1 : assigned.rfind(")")])
                if len(inner) >= 2:
                    return _placeholder_for_expression(inner[1])
    if re.match(r"implode\s*\(", expression):
        args = _split_php_arguments(expression[expression.find("(") + 1 : expression.rfind(")")])
        if len(args) >= 2:
            return _php_blob_placeholder(args[1], method, before_offset)
    return _placeholder_for_expression(expression)


def _php_resolve_return_url(
    target_method: _PhpMethod,
    args: list[str],
    caller_scope: _PhpScope,
    methods: dict[str, _PhpMethod],
    repository: Path,
    path: Path,
    text: str,
    depth: int,
) -> _PhpResolvedUrl | None:
    if len(args) < len(target_method.params):
        return None
    bindings = dict(zip(target_method.params, args, strict=False))
    return_match = re.search(r"\breturn\s+(?P<expr>.*?)\s*;", target_method.body, re.DOTALL)
    if return_match is None:
        return None
    scope = _PhpScope(target_method, parent=caller_scope, bindings=bindings, call_offset=target_method.body_start + return_match.start())
    return _php_resolve_url_expression(
        return_match.group("expr"),
        scope,
        methods,
        repository,
        path,
        text,
        target_method.body_start + return_match.start(),
        depth + 1,
    )


def _php_resolve_url_expression(
    expression: str,
    scope: _PhpScope,
    methods: dict[str, _PhpMethod],
    repository: Path,
    path: Path,
    text: str,
    offset: int,
    depth: int = 0,
) -> _PhpResolvedUrl | None:
    if depth > 8:
        return None
    expression = expression.strip().rstrip(",")
    literal = _literal_value(expression)
    if literal is not None:
        base_url, endpoint_path = normalize_literal_url(literal)
        return _PhpResolvedUrl(base_url=base_url, endpoint_path=endpoint_path)
    if re.fullmatch(r"\$[A-Za-z_]\w*", expression):
        assignments = _php_method_assignments(scope.method, offset)
        assigned = assignments.get(expression)
        if assigned:
            return _php_resolve_url_expression(assigned, scope, methods, repository, path, text, offset, depth + 1)
        if scope.bindings and expression in scope.bindings and scope.parent is not None:
            return _php_resolve_url_expression(
                scope.bindings[expression],
                scope.parent,
                methods,
                repository,
                path,
                text,
                scope.call_offset or offset,
                depth + 1,
            )
        return None
    this_call = re.fullmatch(r"\$this->(?P<name>[A-Za-z_]\w*)\s*\((?P<args>.*)\)", expression, re.DOTALL)
    if this_call is not None:
        target = methods.get(this_call.group("name"))
        if target is None:
            return None
        return _php_resolve_return_url(
            target,
            _split_php_arguments(this_call.group("args")),
            scope,
            methods,
            repository,
            path,
            text,
            depth + 1,
        )

    parts = _php_concat_parts(expression)
    if len(parts) >= 2:
        base_expression: str | None = None
        endpoint_path = ""
        evidence: list[Evidence] = []
        notes: list[str] = []
        for part in parts:
            literal_part = _literal_value(part)
            if literal_part is not None:
                endpoint_path += literal_part
                continue
            if base_expression is None:
                base_expression = part.strip()
                continue
            endpoint_path += _php_blob_placeholder(part, scope.method, offset)
        if base_expression and endpoint_path:
            if "$this->baseUrl" in expression and "$this->container" in expression:
                notes.append("Azure Blob Storage URL resolved from local blobUrl helper with dynamic blob identifier.")
            evidence.append(_evidence(repository, path, text, offset, "local URL construction"))
            return _PhpResolvedUrl(
                base_url=base_expression,
                endpoint_path="/" + endpoint_path.lstrip("/"),
                evidence=tuple(evidence),
                notes=tuple(notes),
            )

    base_url, endpoint_path = _php_expression_to_url_parts(expression)
    if endpoint_path is None:
        return None
    return _PhpResolvedUrl(base_url=base_url, endpoint_path=endpoint_path)


def _php_direct_curl_call(
    method: _PhpMethod,
    scope: _PhpScope,
    methods: dict[str, _PhpMethod],
    repository: Path,
    path: Path,
    text: str,
) -> _PhpResolvedCall | None:
    curl_match = re.search(r"(?P<handle>\$[A-Za-z_]\w*)\s*=\s*curl_init\s*\(\s*(?P<url>[^)]*)\)", method.body, re.DOTALL)
    if curl_match is None:
        return None
    handle = curl_match.group("handle")
    curl_offset = method.body_start + curl_match.start()
    method_expression: str | None = None
    for option in re.finditer(
        rf"curl_setopt\s*\(\s*{re.escape(handle)}\s*,\s*CURLOPT_CUSTOMREQUEST\s*,\s*(?P<value>.*?)\s*\)\s*;",
        method.body,
        re.DOTALL,
    ):
        method_expression = option.group("value")
        break
    if method_expression is None:
        return None
    resolved_method = _php_resolve_method_expression(method_expression, scope)
    if resolved_method is None:
        return None
    resolved_url = _php_resolve_url_expression(
        curl_match.group("url"),
        scope,
        methods,
        repository,
        path,
        text,
        curl_offset,
    )
    if resolved_url is None:
        return None
    return _PhpResolvedCall(
        method=resolved_method,
        url=resolved_url,
        curl_offset=curl_offset,
        evidence_offsets=((curl_offset, "curl_init URL"),),
    )


def _php_resolve_wrapper_call(
    method_name: str,
    args: list[str],
    caller_scope: _PhpScope,
    methods: dict[str, _PhpMethod],
    repository: Path,
    path: Path,
    text: str,
    call_offset: int,
    depth: int = 0,
) -> list[_PhpResolvedCall]:
    if depth > 8:
        return []
    target = methods.get(method_name)
    if target is None or len(args) < len(target.params):
        return []
    scope = _PhpScope(
        target,
        parent=caller_scope,
        bindings=dict(zip(target.params, args, strict=False)),
        call_offset=call_offset,
    )
    direct = _php_direct_curl_call(target, scope, methods, repository, path, text)
    if direct is not None:
        return [
            _PhpResolvedCall(
                method=direct.method,
                url=direct.url,
                curl_offset=direct.curl_offset,
                evidence_offsets=((call_offset, f"$this->{method_name} call"), *direct.evidence_offsets),
            )
        ]

    resolved: list[_PhpResolvedCall] = []
    for nested_name, nested_args, nested_offset in _php_find_this_calls(target):
        nested = _php_resolve_wrapper_call(
            nested_name,
            nested_args,
            scope,
            methods,
            repository,
            path,
            text,
            nested_offset,
            depth + 1,
        )
        for item in nested:
            resolved.append(
                _PhpResolvedCall(
                    method=item.method,
                    url=item.url,
                    curl_offset=item.curl_offset,
                    evidence_offsets=((call_offset, f"$this->{method_name} call"), *item.evidence_offsets),
                )
            )
    return resolved


def _php_wrapper_endpoints(
    repository: Path,
    path: Path,
    text: str,
    masked: str,
) -> tuple[list[EndpointFinding], set[int]]:
    findings: dict[tuple[str, str, str], EndpointFinding] = {}
    resolved_curl_offsets: set[int] = set()
    for php_class in _php_classes(masked):
        methods = php_class.methods
        for method in methods.values():
            caller_scope = _PhpScope(method, call_offset=method.body_start)
            for call_name, call_args, call_offset in _php_find_this_calls(method):
                if call_name not in methods:
                    continue
                resolved_calls = _php_resolve_wrapper_call(
                    call_name,
                    call_args,
                    caller_scope,
                    methods,
                    repository,
                    path,
                    text,
                    call_offset,
                )
                for resolved in resolved_calls:
                    resolved_curl_offsets.add(resolved.curl_offset)
                    evidence = [
                        _evidence(repository, path, text, call_offset, f"{method.name} wrapper call site"),
                    ]
                    evidence.extend(
                        _evidence(repository, path, text, item_offset, note)
                        for item_offset, note in resolved.evidence_offsets
                    )
                    evidence.extend(resolved.url.evidence)
                    finding = _finding(
                        repository,
                        path,
                        text,
                        call_offset,
                        resolved.method,
                        "",
                        "php-curl",
                        base_url=resolved.url.base_url,
                        endpoint_path=resolved.url.endpoint_path,
                        extra_evidence=tuple(evidence[1:]),
                    )
                    finding.notes.extend(resolved.url.notes)
                    findings.setdefault(finding.identity(), finding)
    return list(findings.values()), resolved_curl_offsets


def _php_curl(repository: Path, files: list[Path]) -> tuple[list[EndpointFinding], list[DiscoveryIssue], int]:
    endpoints: list[EndpointFinding] = []
    issues: list[DiscoveryIssue] = []
    scanned = 0
    for path in files:
        if path.suffix.lower() != ".php":
            continue
        text = read_source(path)
        if text is None:
            continue
        masked = _mask_consumer_comments(path, text)
        if "curl_" not in masked:
            continue
        scanned += 1
        handles: dict[str, dict[str, object]] = {}
        wrapper_endpoints, resolved_curl_offsets = _php_wrapper_endpoints(repository, path, text, masked)

        for match in re.finditer(
            r"(?P<handle>\$[A-Za-z_]\w*)\s*=\s*curl_init\s*\(\s*(?P<url>[^)]*)\)",
            masked,
            re.DOTALL,
        ):
            handle = match.group("handle")
            handles.setdefault(handle, {"offset": match.start()})
            url_expr = match.group("url").strip()
            if url_expr:
                handles[handle]["url"] = url_expr
                handles[handle]["url_offset"] = match.start()

        for match in re.finditer(
            r"curl_setopt\s*\(\s*(?P<handle>\$[A-Za-z_]\w*)\s*,\s*"
            r"(?P<option>CURLOPT_[A-Z_]+)\s*,\s*(?P<value>.*?)\s*\)\s*;",
            masked,
            re.DOTALL,
        ):
            handle = match.group("handle")
            option = match.group("option")
            value = match.group("value").strip()
            state = handles.setdefault(handle, {"offset": match.start()})
            if option == "CURLOPT_URL":
                state["url"] = value
                state["url_offset"] = match.start()
            elif option == "CURLOPT_CUSTOMREQUEST":
                method = _php_literal_method(value)
                if method:
                    state["method"] = method
            elif option in {"CURLOPT_POST", "CURLOPT_POSTFIELDS"}:
                state.setdefault("method", "POST")

        for match in re.finditer(
            r"curl_setopt_array\s*\(\s*(?P<handle>\$[A-Za-z_]\w*)\s*,\s*"
            r"(?:\[(?P<bracket_body>.*?)\]|array\s*\((?P<array_body>.*?)\))\s*\)\s*;",
            masked,
            re.DOTALL,
        ):
            handle = match.group("handle")
            body = match.group("bracket_body") or match.group("array_body") or ""
            state = handles.setdefault(handle, {"offset": match.start()})
            for item in re.finditer(r"(?P<option>CURLOPT_[A-Z_]+)\s*=>\s*(?P<value>[^,\n]+)", body):
                option = item.group("option")
                value = item.group("value").strip()
                if option == "CURLOPT_URL":
                    state["url"] = value
                    state["url_offset"] = match.start() + item.start()
                elif option == "CURLOPT_CUSTOMREQUEST":
                    method = _php_literal_method(value)
                    if method:
                        state["method"] = method
                elif option in {"CURLOPT_POST", "CURLOPT_POSTFIELDS"}:
                    state.setdefault("method", "POST")

        for handle, state in sorted(handles.items()):
            url_expression = state.get("url")
            offset = int(state.get("url_offset", state.get("offset", 0)))
            if not isinstance(url_expression, str):
                if offset in resolved_curl_offsets:
                    continue
                issues.append(
                    DiscoveryIssue(
                        code="php_curl_url_unresolved",
                        message=f"cURL handle {handle} was found without a supported URL expression.",
                        detector_id="php-curl-consumer",
                        evidence=(_evidence(repository, path, text, offset, "unresolved cURL URL"),),
                    )
                )
                continue
            base_url, endpoint_path = _php_expression_to_url_parts(url_expression)
            if endpoint_path is None:
                if offset in resolved_curl_offsets:
                    continue
                issues.append(
                    DiscoveryIssue(
                        code="php_curl_url_unresolved",
                        message="cURL URL expression could not be resolved conservatively.",
                        detector_id="php-curl-consumer",
                        evidence=(_evidence(repository, path, text, offset, "unresolved cURL URL"),),
                    )
                )
                continue
            endpoints.append(
                _finding(
                    repository,
                    path,
                    text,
                    offset,
                    str(state.get("method", "GET")),
                    url_expression,
                    "php-curl",
                    base_url=base_url,
                    endpoint_path=endpoint_path,
                )
            )
        endpoints.extend(wrapper_endpoints)
    return endpoints, issues, scanned


_HANDLERS = {
    "angular-httpclient": _angular_httpclient,
    "axios": _axios,
    "fetch": _fetch,
    "guzzle": _guzzle,
    "laravel-http": _laravel_http,
    "dio": _dio,
    "dart-http": _dart_http,
    "php-curl": _php_curl,
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
        if not found and scanned:
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
        supported_patterns = (f"direct literal {client} HTTP calls",)
        detector_version = "1.0.0"
        if client == "dio":
            detector_version = "1.1.0"
            supported_patterns = (
                "Dio() literal HTTP calls",
                "local variables assigned from Dio(...)",
                "typed Dio fields",
                "typed dependency member chains ending in a proven Dio field",
            )
        coverages.append(
            DetectorCoverage(
                detector_id=detector_id,
                detector_version=detector_version,
                category="consumed",
                status="partial" if client_issues else "supported",
                files_scanned=scanned,
                supported_patterns=supported_patterns,
                unsupported_patterns=tuple(sorted({issue.code for issue in client_issues})),
            )
        )

    return list(endpoints.values()), issues, coverages
