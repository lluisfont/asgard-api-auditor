"""HTTP consumer discovery for the first ASGARD client set."""

from __future__ import annotations

import re
from pathlib import Path

from ..discovery_types import DiscoveryIssue
from ..discovery_utils import line_number, normalize_literal_url, read_source, relative_path
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
    this_property = re.compile(
        r"\bfetch\s*\(\s*this\.(?P<property>[A-Za-z_]\w*)"
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
        property_literals: dict[str, tuple[str, int]] = {}
        for assignment in re.finditer(
            r"\bthis\.(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<quote>['\"`])(?P<value>.*?)(?P=quote)",
            text,
            re.DOTALL,
        ):
            property_literals[assignment.group("name")] = (assignment.group("value"), assignment.start())
        for field in re.finditer(
            r"\b(?:private|public|protected|readonly|static|\s)+"
            r"(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<quote>['\"`])(?P<value>.*?)(?P=quote)",
            text,
            re.DOTALL,
        ):
            property_literals.setdefault(field.group("name"), (field.group("value"), field.start()))
        recognized = set()
        for match in literal.finditer(text):
            recognized.add(match.start())
            method = _method_from_options(match.group("options") or "")
            endpoints.append(
                _finding(repository, path, text, match.start(), method, match.group("url"), "fetch")
            )
        for match in this_property.finditer(text):
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
    name = expression.strip().removeprefix("this.").removeprefix("$")
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
        if text is not None and "GLOBAL" in text:
            global_values.update(_angular_global_values(text))

    for path in files:
        if path.suffix.lower() not in {".ts", ".tsx"}:
            continue
        text = read_source(path)
        if text is None or "HttpClient" not in text:
            continue
        clients = set(
            re.findall(
                r"\b(?:private|public|protected|readonly|\s)+(?P<name>[A-Za-z_]\w*)\s*:\s*HttpClient\b",
                text,
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
        values = _angular_this_values(text, {**global_values, **_angular_global_values(text)})
        scanned += 1
        recognized: set[int] = set()
        for match in calls.finditer(text):
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
        for call in any_call.finditer(text):
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


def _php_curl(repository: Path, files: list[Path]) -> tuple[list[EndpointFinding], list[DiscoveryIssue], int]:
    endpoints: list[EndpointFinding] = []
    issues: list[DiscoveryIssue] = []
    scanned = 0
    for path in files:
        if path.suffix.lower() != ".php":
            continue
        text = read_source(path)
        if text is None or "curl_" not in text:
            continue
        scanned += 1
        handles: dict[str, dict[str, object]] = {}

        for match in re.finditer(
            r"(?P<handle>\$[A-Za-z_]\w*)\s*=\s*curl_init\s*\(\s*(?P<url>[^)]*)\)",
            text,
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
            text,
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
            r"curl_setopt_array\s*\(\s*(?P<handle>\$[A-Za-z_]\w*)\s*,\s*\[(?P<body>.*?)\]\s*\)",
            text,
            re.DOTALL,
        ):
            handle = match.group("handle")
            body = match.group("body")
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
