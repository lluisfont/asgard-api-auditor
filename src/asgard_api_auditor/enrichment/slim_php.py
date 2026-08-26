"""Deterministic Slim/PHP behavioral contract enrichment."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from pathlib import Path

from ..discovery_utils import line_number, normalize_literal_url, read_source, relative_path
from ..models import EndpointFinding, Evidence, ParameterFinding, RequestFinding, ResponseFinding
from .types import ContractEnrichmentCoverage, ContractEnrichmentResult, ContractUnresolved

_PATH_PARAMETER = re.compile(r"\{(?P<name>[A-Za-z_][A-Za-z0-9_-]*)(?::[^}]+)?\}")
_ROUTE_START = re.compile(
    r"(?P<receiver>\$[A-Za-z_]\w*)->(?P<method>get|post|put|patch|delete|options)\s*"
    r"\(\s*(?P<quote>['\"])(?P<path>.*?)(?P=quote)\s*,\s*function\s*"
    r"\((?P<args>[^)]*)\)\s*(?:use\s*\([^)]*\)\s*)?\{",
    re.IGNORECASE | re.DOTALL,
)
_JSON_BODY = re.compile(
    r"(?P<var>\$[A-Za-z_]\w*)\s*=\s*json_decode\s*\(\s*"
    r"(?:\(\s*string\s*\)\s*)?\$request->getBody\s*\(\s*\)\s*,\s*true\s*\)",
    re.IGNORECASE | re.DOTALL,
)
_CONTENT_TYPE_JSON = re.compile(
    r"withHeader\s*\(\s*['\"]Content-Type['\"]\s*,\s*['\"]application/json['\"]\s*\)",
    re.IGNORECASE | re.DOTALL,
)
_MIDDLEWARE_FUNCTION = re.compile(
    r"(?P<variable>\$[A-Za-z_]\w*)\s*=\s*function\s*"
    r"\([^)]*\)\s*(?:use\s*\([^)]*\)\s*)?\{",
    re.IGNORECASE | re.DOTALL,
)
_ROUTE_MIDDLEWARE = re.compile(r"->add\s*\(\s*(?P<middleware>\$[A-Za-z_]\w*)")
_JWT_DECODE = re.compile(
    r"JWT::decode\s*\(\s*(?P<credential>.*?)\s*,\s*new\s+Key\s*"
    r"\([^;]*?['\"](?P<algorithm>[A-Za-z0-9_-]+)['\"]",
    re.IGNORECASE | re.DOTALL,
)
_HEADER_LINE_ASSIGNMENT = re.compile(
    r"(?P<var>\$[A-Za-z_]\w*)\s*=\s*\$request->getHeaderLine\s*\(\s*"
    r"['\"]Authorization['\"]\s*\)",
    re.IGNORECASE,
)
_HEADERS_ASSIGNMENT = re.compile(
    r"(?P<var>\$[A-Za-z_]\w*)\s*=\s*apache_request_headers\s*\(\s*\)",
    re.IGNORECASE,
)
_AUTHORIZATION_INDEX_ASSIGNMENT = re.compile(
    r"(?P<var>\$[A-Za-z_]\w*)\s*=\s*(?P<headers>\$[A-Za-z_]\w*)"
    r"\s*\[\s*['\"]Authorization['\"]\s*\]",
    re.IGNORECASE,
)
_DIRECT_HEADER_LINE = re.compile(
    r"\$request->getHeaderLine\s*\(\s*['\"]Authorization['\"]\s*\)",
    re.IGNORECASE,
)
_DIRECT_AUTHORIZATION_INDEX = re.compile(r"\[\s*['\"]Authorization['\"]\s*\]", re.IGNORECASE)
_BEARER_SYNTAX = re.compile(
    r"preg_replace\s*\([^)]*Bearer|str_ireplace\s*\([^)]*Bearer|"
    r"str_replace\s*\([^)]*Bearer",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True)
class _RouteSource:
    method: str
    path: str
    file: Path
    text: str
    route_offset: int
    body: str
    body_start: int
    body_end: int
    suffix: str


@dataclass(frozen=True)
class _MiddlewareSource:
    variable: str
    file: Path
    text: str
    offset: int
    body: str
    body_start: int


@dataclass(frozen=True)
class _AuthenticationEvidence:
    authentication: str
    evidence: Evidence


@dataclass
class _Field:
    name: str
    required: bool
    schema: dict[str, object]
    evidence: Evidence


def _evidence(repository: Path, file: Path, text: str, offset: int, note: str) -> Evidence:
    return Evidence(
        path=relative_path(repository, file),
        line=line_number(text, offset),
        kind="controller",
        note=note,
    )


def _mask_comments(text: str) -> str:
    chars = list(text)
    index = 0
    quote: str | None = None
    escaped = False
    while index < len(chars):
        char = chars[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char == "/" and index + 1 < len(chars) and chars[index + 1] == "/":
            while index < len(chars) and chars[index] != "\n":
                chars[index] = " "
                index += 1
            continue
        if char == "#":
            while index < len(chars) and chars[index] != "\n":
                chars[index] = " "
                index += 1
            continue
        if char == "/" and index + 1 < len(chars) and chars[index + 1] == "*":
            chars[index] = " "
            chars[index + 1] = " "
            index += 2
            while index + 1 < len(chars) and not (chars[index] == "*" and chars[index + 1] == "/"):
                if chars[index] != "\n":
                    chars[index] = " "
                index += 1
            if index + 1 < len(chars):
                chars[index] = " "
                chars[index + 1] = " "
                index += 2
            continue
        index += 1
    return "".join(chars)


def _matching_delimiter(text: str, open_offset: int, open_char: str, close_char: str) -> int | None:
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
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_top_level(text: str, separator: str = ",") -> list[str]:
    parts: list[str] = []
    start = 0
    parens = brackets = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(text):
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
        elif char == separator and parens == 0 and brackets == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _literal_string(expression: str) -> str | None:
    match = re.fullmatch(r"\s*(?P<quote>['\"])(?P<value>.*?)(?P=quote)\s*", expression, re.DOTALL)
    return match.group("value") if match else None


def _path_parameters(path: str) -> list[str]:
    return [match.group("name") for match in _PATH_PARAMETER.finditer(path)]


def _schema_from_expression(expression: str) -> dict[str, object]:
    value = expression.strip()
    lower = value.lower()
    if re.fullmatch(r"[-+]?\d+", value):
        return {"type": "integer"}
    if re.fullmatch(r"[-+]?\d+\.\d+", value):
        return {"type": "number"}
    if lower in {"true", "false"}:
        return {"type": "boolean"}
    if _literal_string(value) is not None:
        return {"type": "string"}
    if value in {"[]"} or re.fullmatch(r"array\s*\(\s*\)", value, re.IGNORECASE):
        return {"type": "array"}
    return {}


def _default_from_expression(expression: str) -> object:
    value = expression.strip()
    lower = value.lower()
    if value in {"[]"} or re.fullmatch(r"array\s*\(\s*\)", value, re.IGNORECASE):
        return []
    if lower == "true":
        return True
    if lower == "false":
        return False
    if re.fullmatch(r"[-+]?\d+", value):
        return int(value)
    if re.fullmatch(r"[-+]?\d+\.\d+", value):
        return float(value)
    literal = _literal_string(value)
    if literal is not None:
        return literal
    return None


def _field_schema(expression: str, default: str | None = None) -> dict[str, object]:
    schema = _schema_from_expression(expression)
    if default is not None:
        default_value = _default_from_expression(default)
        if default_value is not None or default.strip() in {"[]"}:
            schema = {**_schema_from_expression(default), **schema}
            schema["default"] = default_value
    return schema


def _schema_with_evidence(schema: dict[str, object], evidence: Evidence) -> dict[str, object]:
    enriched = dict(schema)
    enriched["x-asgard-evidence"] = [
        {
            "path": evidence.path,
            "line": evidence.line,
            "kind": evidence.kind,
            "note": evidence.note,
        }
    ]
    return enriched


def _extract_routes(repository: Path, files: list[Path]) -> dict[tuple[str, str], _RouteSource]:
    routes: dict[tuple[str, str], _RouteSource] = {}
    for file in files:
        if file.suffix.lower() != ".php":
            continue
        text = read_source(file)
        if text is None or "function" not in text or "->" not in text:
            continue
        masked = _mask_comments(text)
        for match in _ROUTE_START.finditer(masked):
            body_start = match.end()
            body_end = _matching_delimiter(masked, body_start - 1, "{", "}")
            if body_end is None:
                continue
            call_end = _matching_delimiter(masked, match.start(), "(", ")")
            suffix_end = masked.find(";", body_end)
            suffix = masked[body_end : suffix_end if suffix_end != -1 else body_end]
            _, route_path = normalize_literal_url(match.group("path"))
            source = _RouteSource(
                method=match.group("method").upper(),
                path=route_path,
                file=file,
                text=text,
                route_offset=match.start(),
                body=masked[body_start:body_end],
                body_start=body_start,
                body_end=body_end,
                suffix=suffix if call_end is not None else suffix,
            )
            routes[(source.method, source.path)] = source
    return routes


def _extract_middleware_definitions(files: list[Path]) -> dict[str, list[_MiddlewareSource]]:
    definitions: dict[str, list[_MiddlewareSource]] = {}
    for file in files:
        if file.suffix.lower() != ".php":
            continue
        text = read_source(file)
        if text is None or "function" not in text:
            continue
        masked = _mask_comments(text)
        for match in _MIDDLEWARE_FUNCTION.finditer(masked):
            body_start = match.end()
            body_end = _matching_delimiter(masked, body_start - 1, "{", "}")
            if body_end is None:
                continue
            source = _MiddlewareSource(
                variable=match.group("variable"),
                file=file,
                text=text,
                offset=match.start(),
                body=masked[body_start:body_end],
                body_start=body_start,
            )
            definitions.setdefault(source.variable, []).append(source)
    return definitions


def _path_request(
    repository: Path,
    endpoint: EndpointFinding,
    source: _RouteSource | None,
) -> list[ParameterFinding]:
    parameters: list[ParameterFinding] = []
    for name in _path_parameters(endpoint.path):
        evidence: list[Evidence] = []
        if source is not None:
            route_evidence = Evidence(
                path=relative_path(repository, source.file),
                line=line_number(source.text, source.route_offset),
                kind="route",
                note="Slim route path parameter",
            )
            evidence.append(route_evidence)
            access = re.search(
                rf"\$args\s*\[\s*['\"]{re.escape(name)}['\"]\s*\]",
                source.body,
            )
            if access is not None:
                evidence.append(
                    _evidence(
                        repository,
                        source.file,
                        source.text,
                        source.body_start + access.start(),
                        "Slim path parameter read from $args",
                    )
                )
        else:
            evidence.extend(endpoint.evidence)
        parameters.append(
            ParameterFinding(
                name=name,
                location="path",
                required=True,
                schema={"type": "string"},
                evidence=tuple(evidence),
            )
        )
    return parameters


def _request_body(
    repository: Path,
    source: _RouteSource,
) -> tuple[RequestFinding | None, list[ContractUnresolved], bool, bool]:
    body_match = _JSON_BODY.search(source.body)
    if body_match is None:
        return None, [], False, False

    variable = body_match.group("var")
    access = rf"{re.escape(variable)}\s*\[\s*['\"](?P<field>[A-Za-z_][A-Za-z0-9_]*)['\"]\s*\]"
    dynamic = re.search(rf"{re.escape(variable)}\s*\[\s*(?!['\"])", source.body)
    unresolved: list[ContractUnresolved] = []
    if dynamic is not None:
        unresolved.append(
            ContractUnresolved(
                code="slim_php_request_body_dynamic",
                message="JSON request body is accessed with a dynamic key and cannot be fully reconstructed.",
                evidence=(
                    _evidence(
                        repository,
                        source.file,
                        source.text,
                        source.body_start + dynamic.start(),
                        "dynamic JSON request body key",
                    ),
                ),
            )
        )

    fields: dict[str, _Field] = {}
    optional = re.compile(rf"(?P<cast>\((?:int|integer|string|bool|boolean)\)\s*)?{access}\s*\?\?\s*(?P<default>[^;\n,\)]+)", re.IGNORECASE)
    optional_spans: list[tuple[int, int]] = []
    for match in optional.finditer(source.body):
        optional_spans.append(match.span())
        name = match.group("field")
        expression = f"{match.group('cast') or ''}{variable}['{name}']"
        default = match.group("default")
        evidence = _evidence(
            repository,
            source.file,
            source.text,
            source.body_start + match.start(),
            "optional JSON request property with literal default",
        )
        fields.setdefault(name, _Field(name, False, _field_schema(expression, default), evidence))

    direct = re.compile(rf"(?P<cast>\((?:int|integer|string|bool|boolean)\)\s*)?{access}", re.IGNORECASE)
    for match in direct.finditer(source.body):
        if any(start <= match.start() < end for start, end in optional_spans):
            continue
        name = match.group("field")
        cast = (match.group("cast") or "").lower()
        schema: dict[str, object] = {}
        if "int" in cast:
            schema["type"] = "integer"
        elif "bool" in cast:
            schema["type"] = "boolean"
        elif "string" in cast:
            schema["type"] = "string"
        evidence = _evidence(
            repository,
            source.file,
            source.text,
            source.body_start + match.start(),
            "required JSON request property access",
        )
        previous = fields.get(name)
        if previous is None or previous.required is False:
            fields[name] = _Field(name, True, schema, evidence)

    if not fields:
        unresolved.append(
            ContractUnresolved(
                code="slim_php_request_body_unresolved",
                message="JSON request body is decoded but no supported literal property access was found.",
                evidence=(
                    _evidence(
                        repository,
                        source.file,
                        source.text,
                        source.body_start + body_match.start(),
                        "JSON request body decode",
                    ),
                ),
            )
        )
        return None, unresolved, True, False

    properties = {
        name: _schema_with_evidence(field.schema, field.evidence)
        for name, field in sorted(fields.items())
    }
    required = sorted(name for name, field in fields.items() if field.required)
    schema: dict[str, object] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    request = RequestFinding(
        content_type="application/json",
        body_schema=schema,
        fields=sorted(fields),
    )
    return request, unresolved, True, not unresolved


def _array_payload(expression: str) -> str | None:
    stripped = expression.strip()
    if stripped.lower().startswith("array"):
        open_offset = stripped.find("(")
        if open_offset == -1:
            return None
        close = _matching_delimiter(stripped, open_offset, "(", ")")
        return stripped[open_offset + 1 : close] if close is not None else None
    if stripped.startswith("["):
        close = _matching_delimiter(stripped, 0, "[", "]")
        return stripped[1:close] if close is not None else None
    return None


def _array_assignment(body: str, variable: str, before: int) -> tuple[str | None, int | None]:
    assignment = re.compile(rf"{re.escape(variable)}\s*=\s*(?P<array>array\s*\(|\[)", re.IGNORECASE)
    found: tuple[str | None, int | None] = (None, None)
    for match in assignment.finditer(body, 0, before):
        open_char = "(" if match.group("array").lower().startswith("array") else "["
        open_offset = body.find(open_char, match.start("array"))
        close = _matching_delimiter(body, open_offset, open_char, ")" if open_char == "(" else "]")
        if close is None:
            continue
        found = (body[open_offset + 1 : close], match.start())
    return found


def _parse_array_fields(
    repository: Path,
    source: _RouteSource,
    payload: str,
    base_offset: int,
) -> dict[str, _Field]:
    fields: dict[str, _Field] = {}
    offset = 0
    for part in _split_top_level(payload):
        if "=>" not in part:
            offset += len(part) + 1
            continue
        key_raw, value = part.split("=>", 1)
        key = _literal_string(key_raw.strip())
        if key is None:
            offset += len(part) + 1
            continue
        part_offset = payload.find(part, offset)
        offset = part_offset + len(part) if part_offset != -1 else offset + len(part)
        evidence = _evidence(
            repository,
            source.file,
            source.text,
            source.body_start + base_offset + max(part_offset, 0),
            "JSON response property",
        )
        fields[key] = _Field(key, True, _schema_from_expression(value), evidence)
    return fields


def _response_json(
    repository: Path,
    source: _RouteSource,
) -> tuple[ResponseFinding | None, list[ContractUnresolved], bool, bool]:
    json_call = re.search(r"json_encode\s*\(", source.body, re.IGNORECASE)
    if json_call is None:
        return None, [], False, False

    open_offset = source.body.find("(", json_call.start())
    close = _matching_delimiter(source.body, open_offset, "(", ")")
    if close is None:
        return None, [
            ContractUnresolved(
                code="slim_php_response_json_unresolved",
                message="json_encode response call could not be parsed deterministically.",
                evidence=(
                    _evidence(
                        repository,
                        source.file,
                        source.text,
                        source.body_start + json_call.start(),
                        "JSON response encode",
                    ),
                ),
            )
        ], True, False

    argument = source.body[open_offset + 1 : close].strip()
    payload = _array_payload(argument)
    payload_offset = open_offset + 1
    if payload is None and re.fullmatch(r"\$[A-Za-z_]\w*", argument):
        payload, assignment_offset = _array_assignment(source.body, argument, json_call.start())
        payload_offset = assignment_offset or payload_offset
    if payload is None:
        return None, [
            ContractUnresolved(
                code="slim_php_response_json_dynamic",
                message="JSON response payload is dynamic and cannot be reconstructed.",
                evidence=(
                    _evidence(
                        repository,
                        source.file,
                        source.text,
                        source.body_start + json_call.start(),
                        "dynamic JSON response payload",
                    ),
                ),
            )
        ], True, False

    fields = _parse_array_fields(repository, source, payload, payload_offset)
    if not fields:
        return None, [
            ContractUnresolved(
                code="slim_php_response_json_unresolved",
                message="JSON response array has no supported literal keys.",
                evidence=(
                    _evidence(
                        repository,
                        source.file,
                        source.text,
                        source.body_start + json_call.start(),
                        "JSON response encode",
                    ),
                ),
            )
        ], True, False

    properties = {
        name: _schema_with_evidence(field.schema, field.evidence)
        for name, field in sorted(fields.items())
    }
    content_type = "application/json" if _CONTENT_TYPE_JSON.search(source.body) else None
    response = ResponseFinding(
        content_type=content_type,
        schema={"type": "object", "properties": properties},
        fields=sorted(fields),
    )
    return response, [], True, True


def _authorization_header_variables(body: str) -> set[str]:
    variables: set[str] = set()
    header_collections = {match.group("var") for match in _HEADERS_ASSIGNMENT.finditer(body)}
    for match in _HEADER_LINE_ASSIGNMENT.finditer(body):
        variables.add(match.group("var"))
    for match in _AUTHORIZATION_INDEX_ASSIGNMENT.finditer(body):
        if match.group("headers") in header_collections:
            variables.add(match.group("var"))
    return variables


def _credential_uses_authorization_header(body: str, credential: str) -> bool:
    stripped = credential.strip()
    if _DIRECT_HEADER_LINE.fullmatch(stripped):
        return True
    if _DIRECT_AUTHORIZATION_INDEX.search(stripped) is not None:
        return "apache_request_headers" in body or "$headers" in stripped
    if re.fullmatch(r"\$[A-Za-z_]\w*", stripped):
        return stripped in _authorization_header_variables(body)
    return False


def _authentication_from_body(
    repository: Path,
    file: Path,
    text: str,
    body: str,
    body_start: int,
) -> _AuthenticationEvidence | None:
    for match in _JWT_DECODE.finditer(body):
        algorithm = match.group("algorithm")
        if not _credential_uses_authorization_header(body, match.group("credential")):
            continue
        if _BEARER_SYNTAX.search(body):
            authentication = f"bearer JWT Authorization {algorithm}"
            note = "JWT Authorization bearer validation"
        else:
            authentication = f"Authorization header raw JWT {algorithm}"
            note = "JWT Authorization header raw value validation"
        return _AuthenticationEvidence(
            authentication=authentication,
            evidence=_evidence(
                repository,
                file,
                text,
                body_start + match.start(),
                note,
            ),
        )
    return None


def _middleware_unresolved(
    repository: Path,
    source: _RouteSource,
    middleware: str,
    reason: str,
    offset: int,
) -> ContractUnresolved:
    return ContractUnresolved(
        code="slim_php_security_unresolved",
        message=(
            f"{source.method} {source.path} uses middleware {middleware}, "
            f"but authentication could not be reconstructed: {reason}."
        ),
        evidence=(
            _evidence(
                repository,
                source.file,
                source.text,
                source.body_end + offset,
                f"Slim route middleware {middleware}",
            ),
        ),
    )


def _security_unresolved(
    repository: Path,
    source: _RouteSource,
    reason: str,
) -> ContractUnresolved:
    return ContractUnresolved(
        code="slim_php_security_unresolved",
        message=(
            f"{source.method} {source.path} contains security evidence, "
            f"but authentication could not be reconstructed: {reason}."
        ),
        evidence=(
            _evidence(
                repository,
                source.file,
                source.text,
                source.route_offset,
                "Slim route security evidence",
            ),
        ),
    )


def _security(
    repository: Path,
    endpoint: EndpointFinding,
    source: _RouteSource,
    middleware_definitions: dict[str, list[_MiddlewareSource]],
) -> tuple[bool, bool, list[ContractUnresolved]]:
    body = source.body
    suffix = source.suffix
    middleware_matches = list(_ROUTE_MIDDLEWARE.finditer(suffix))
    inline_auth = _authentication_from_body(repository, source.file, source.text, body, source.body_start)
    applicable = bool(middleware_matches) or inline_auth is not None or "Authorization" in body or "JWT::decode" in body
    if not applicable:
        return False, False, []

    unresolved: list[ContractUnresolved] = []
    middleware_names = [match.group("middleware") for match in middleware_matches]
    if middleware_names:
        endpoint.authorization = ", ".join(f"middleware:{name}" for name in middleware_names)
    for match in middleware_matches:
        endpoint.evidence.append(
            _evidence(
                repository,
                source.file,
                source.text,
                source.body_end + match.start(),
                f"Slim route middleware {match.group('middleware')}",
            )
        )

    authentication = inline_auth
    for match in middleware_matches:
        if authentication is not None:
            break
        middleware = match.group("middleware")
        definitions = middleware_definitions.get(middleware, [])
        if len(definitions) == 1:
            definition = definitions[0]
            authentication = _authentication_from_body(
                repository,
                definition.file,
                definition.text,
                definition.body,
                definition.body_start,
            )
            if authentication is None:
                unresolved.append(
                    _middleware_unresolved(
                        repository,
                        source,
                        middleware,
                        "middleware definition has no supported Authorization JWT evidence",
                        match.start(),
                    )
                )
        elif len(definitions) > 1:
            unresolved.append(
                _middleware_unresolved(
                    repository,
                    source,
                    middleware,
                    "multiple middleware definitions exist",
                    match.start(),
                )
            )
        else:
            unresolved.append(
                _middleware_unresolved(
                    repository,
                    source,
                    middleware,
                    "middleware definition was not found in scanned PHP files",
                    match.start(),
                )
            )

    if authentication is not None:
        endpoint.authentication = authentication.authentication
        endpoint.evidence.append(authentication.evidence)
        return True, True, unresolved

    if not unresolved:
        unresolved.append(
            _security_unresolved(
                repository,
                source,
                "Authorization/JWT evidence is incomplete or dynamic",
            )
        )
    return True, False, unresolved


def _merge_request(existing: RequestFinding | None, parameters: list[ParameterFinding]) -> RequestFinding:
    request = existing or RequestFinding()
    names = {(item.location, item.name) for item in request.parameters}
    for parameter in parameters:
        if (parameter.location, parameter.name) not in names:
            request.parameters.append(parameter)
    return request


def _dedupe_unresolved(unresolved: list[ContractUnresolved]) -> list[ContractUnresolved]:
    seen: set[tuple[object, ...]] = set()
    deduped: list[ContractUnresolved] = []
    for issue in unresolved:
        key = (
            issue.code,
            issue.message,
            tuple(
                (item.path, item.line, item.end_line, item.kind, item.note)
                for item in issue.evidence
            ),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(issue)
    return deduped


def enrich_slim_php_contracts(
    repository: Path,
    endpoints: list[EndpointFinding],
    files: list[Path],
) -> ContractEnrichmentResult:
    enriched = copy.deepcopy(endpoints)
    exposed = [item for item in enriched if item.direction == "exposed"]
    coverage = ContractEnrichmentCoverage(total_exposed_endpoints=len(exposed))
    unresolved: list[ContractUnresolved] = []
    routes = _extract_routes(repository, files)
    middleware_definitions = _extract_middleware_definitions(files)

    for endpoint in exposed:
        source = routes.get((endpoint.method, endpoint.path))
        path_parameters = _path_request(repository, endpoint, source)
        if path_parameters:
            coverage.path_parameters_applicable += 1
            endpoint.request = _merge_request(endpoint.request, path_parameters)
            coverage.path_parameters_enriched += 1

        if source is None:
            continue

        request, request_unresolved, request_applicable, request_enriched = _request_body(
            repository, source
        )
        if request_applicable:
            coverage.request_enrichment_applicable += 1
            if request is not None:
                endpoint.request = _merge_request(request, path_parameters)
            if request_enriched:
                coverage.request_enriched += 1
        unresolved.extend(request_unresolved)

        response, response_unresolved, response_applicable, response_enriched = _response_json(
            repository, source
        )
        if response_applicable:
            coverage.response_enrichment_applicable += 1
            if response is not None:
                endpoint.response = response
            if response_enriched:
                coverage.response_enriched += 1
        unresolved.extend(response_unresolved)

        security_applicable, security_enriched, security_unresolved = _security(
            repository,
            endpoint,
            source,
            middleware_definitions,
        )
        if security_applicable:
            coverage.security_enrichment_applicable += 1
            if security_enriched:
                coverage.security_enriched += 1
        unresolved.extend(security_unresolved)

        if any(note.startswith("contract_enrichment_status=") for note in endpoint.notes):
            continue
        status = "enriched" if any([endpoint.request, endpoint.response, endpoint.authentication]) else "pending"
        if request_unresolved or response_unresolved or security_unresolved:
            status = "partial"
        endpoint.notes.append(f"contract_enrichment_status={status}")

    unresolved = _dedupe_unresolved(unresolved)
    coverage.unresolved_contract_enrichment = len(unresolved)
    return ContractEnrichmentResult(enriched, coverage, unresolved)
