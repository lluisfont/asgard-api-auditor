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
_POST_FIELD = re.compile(r"\$_POST\s*\[\s*(?P<quote>['\"])(?P<field>[^'\"]+)(?P=quote)\s*\]")
_FILES_FIELD = re.compile(r"\$_FILES\s*\[\s*(?P<quote>['\"])(?P<field>[^'\"]+)(?P=quote)\s*\]")
_FUNCTION_DEFINITION = re.compile(
    r"function\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*\{",
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
class _FunctionSource:
    name: str
    parameters: tuple[str, ...]
    file: Path
    text: str
    offset: int
    body: str
    body_start: int


@dataclass(frozen=True)
class _AuthenticationEvidence:
    authentication: str
    evidence: Evidence
    credential_format: str
    scheme: str | None
    header_semantics: str


@dataclass
class _Field:
    name: str
    required: bool
    schema: dict[str, object]
    evidence: Evidence


@dataclass
class _RequestShape:
    schema: dict[str, object]
    fields: dict[str, _Field]
    unresolved: list[ContractUnresolved]
    used: bool = False
    scalar_array: bool = False


@dataclass(frozen=True)
class _ParsedChain:
    segments: tuple[str, ...]
    dynamic: bool = False


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
    cast = re.match(r"\s*\((?:int|integer|string|bool|boolean)\)", expression, re.IGNORECASE)
    schema: dict[str, object]
    if cast is None:
        schema = _schema_from_expression(expression)
    else:
        cast_value = cast.group(0).lower()
        if "int" in cast_value:
            schema = {"type": "integer"}
        elif "bool" in cast_value:
            schema = {"type": "boolean"}
        else:
            schema = {"type": "string"}
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


def _function_parameters(raw: str) -> tuple[str, ...]:
    parameters: list[str] = []
    for part in _split_top_level(raw):
        match = re.search(r"(\$[A-Za-z_]\w*)", part)
        if match is not None:
            parameters.append(match.group(1))
    return tuple(parameters)


def _extract_function_definitions(files: list[Path]) -> dict[str, list[_FunctionSource]]:
    definitions: dict[str, list[_FunctionSource]] = {}
    for file in files:
        if file.suffix.lower() != ".php":
            continue
        text = read_source(file)
        if text is None or "function" not in text:
            continue
        masked = _mask_comments(text)
        for match in _FUNCTION_DEFINITION.finditer(masked):
            body_start = match.end()
            body_end = _matching_delimiter(masked, body_start - 1, "{", "}")
            if body_end is None:
                continue
            source = _FunctionSource(
                name=match.group("name"),
                parameters=_function_parameters(match.group("params")),
                file=file,
                text=text,
                offset=match.start(),
                body=masked[body_start:body_end],
                body_start=body_start,
            )
            definitions.setdefault(source.name, []).append(source)
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


def _parse_chain(
    chain: str,
    index_context: dict[tuple[str, ...], set[str]] | None = None,
    *,
    base_path: tuple[str, ...] = (),
) -> _ParsedChain:
    raw_segments = re.findall(r"\[\s*([^\]]+?)\s*\]", chain, re.DOTALL)
    segments: list[str] = []
    dynamic = False
    for raw in raw_segments:
        value = raw.strip()
        literal = _literal_string(value)
        if literal is not None:
            segments.append(f"property:{literal}")
            continue
        if re.fullmatch(r"\d+", value) is not None:
            segments.append("index")
            continue
        current_path = base_path + tuple(segments)
        allowed_indexes = (index_context or {}).get(current_path, set())
        if value in allowed_indexes:
            segments.append("index")
            continue
        segments.append("dynamic")
        dynamic = True
    return _ParsedChain(tuple(segments), dynamic)


def _count_argument(expression: str) -> str | None:
    stripped = expression.strip()
    match = re.match(r"count\s*\(", stripped, re.IGNORECASE)
    if match is None:
        return None
    open_offset = stripped.find("(", match.start())
    close = _matching_delimiter(stripped, open_offset, "(", ")")
    if close is None or stripped[close + 1 :].strip():
        return None
    return stripped[open_offset + 1 : close]


def _for_loop_headers(body: str) -> list[str]:
    headers: list[str] = []
    for match in re.finditer(r"\bfor\s*\(", body, re.IGNORECASE):
        open_offset = body.find("(", match.start())
        close = _matching_delimiter(body, open_offset, "(", ")")
        if close is not None:
            headers.append(body[open_offset + 1 : close])
    return headers


def _expression_path(
    expression: str,
    aliases: dict[str, tuple[str, ...]],
    index_context: dict[tuple[str, ...], set[str]],
) -> tuple[str, ...] | None:
    match = re.fullmatch(
        r"\s*(?P<variable>\$[A-Za-z_]\w*)(?P<chain>(?:\s*\[[^\]]+\])*)\s*",
        expression,
        re.DOTALL,
    )
    if match is None:
        return None
    variable = match.group("variable")
    if variable not in aliases:
        return None
    prefix = aliases[variable]
    parsed = _parse_chain(match.group("chain") or "", index_context, base_path=prefix)
    if parsed.dynamic:
        return None
    return prefix + parsed.segments


def _increment_matches_variable(increment: str, variable: str) -> bool:
    escaped = re.escape(variable)
    patterns = (
        rf"\+\+\s*{escaped}",
        rf"{escaped}\s*\+\+",
        rf"{escaped}\s*\+=\s*1",
        rf"{escaped}\s*=\s*{escaped}\s*\+\s*1",
    )
    return any(re.fullmatch(pattern, increment.strip()) is not None for pattern in patterns)


def _for_loop_index_bindings(
    body: str,
    aliases: dict[str, tuple[str, ...]],
    index_context: dict[tuple[str, ...], set[str]],
) -> list[tuple[tuple[str, ...], str]]:
    bindings: list[tuple[tuple[str, ...], str]] = []
    for header in _for_loop_headers(body):
        parts = [part.strip() for part in header.split(";")]
        if len(parts) != 3:
            continue
        init, condition, increment = parts
        init_match = re.fullmatch(r"(?P<variable>\$[A-Za-z_]\w*)\s*=\s*0", init)
        if init_match is None:
            continue
        variable = init_match.group("variable")
        if not _increment_matches_variable(increment, variable):
            continue
        target_expression: str | None = None
        left_less_than = re.fullmatch(rf"{re.escape(variable)}\s*<\s*(?P<count>.+)", condition, re.DOTALL)
        if left_less_than is not None:
            target_expression = _count_argument(left_less_than.group("count"))
        else:
            right_greater_than = re.fullmatch(rf"(?P<count>.+)\s*>\s*{re.escape(variable)}", condition, re.DOTALL)
            if right_greater_than is not None:
                target_expression = _count_argument(right_greater_than.group("count"))
        if target_expression is None:
            continue
        target_path = _expression_path(target_expression, aliases, index_context)
        if target_path is not None:
            bindings.append((target_path, variable))
    return bindings


def _add_index_context(
    index_context: dict[tuple[str, ...], set[str]],
    path: tuple[str, ...],
    variable: str,
) -> bool:
    values = index_context.setdefault(path, set())
    if variable in values:
        return False
    values.add(variable)
    return True


def _request_context(
    source: _RouteSource | _FunctionSource,
    root_paths: dict[str, tuple[str, ...]],
) -> tuple[dict[str, tuple[str, ...]], dict[tuple[str, ...], set[str]], list[tuple[tuple[str, ...], int]]]:
    aliases = dict(root_paths)
    index_context: dict[tuple[str, ...], set[str]] = {}
    foreach_arrays: dict[tuple[tuple[str, ...], int], tuple[tuple[str, ...], int]] = {}
    changed = True
    while changed:
        changed = False
        for path, variable in _for_loop_index_bindings(source.body, aliases, index_context):
            changed = _add_index_context(index_context, path, variable) or changed
        for variable, prefix in list(aliases.items()):
            alias_pattern = re.compile(
                rf"(?P<alias>\$[A-Za-z_]\w*)\s*=\s*{re.escape(variable)}(?P<chain>(?:\s*\[[^\]]+\])*)\s*;",
                re.DOTALL,
            )
            for match in alias_pattern.finditer(source.body):
                alias = match.group("alias")
                parsed = _parse_chain(match.group("chain") or "", index_context, base_path=prefix)
                if parsed.dynamic:
                    continue
                resolved = prefix + parsed.segments
                if aliases.get(alias) != resolved:
                    aliases[alias] = resolved
                    changed = True
            foreach_pattern = re.compile(
                rf"foreach\s*\(\s*{re.escape(variable)}(?P<chain>(?:\s*\[[^\]]+\])*)\s+as\s+"
                r"(?:(?P<key>\$[A-Za-z_]\w*)\s*=>\s*)?(?P<alias>\$[A-Za-z_]\w*)\s*\)",
                re.IGNORECASE | re.DOTALL,
            )
            for match in foreach_pattern.finditer(source.body):
                parsed = _parse_chain(match.group("chain") or "", index_context, base_path=prefix)
                if parsed.dynamic:
                    continue
                target_path = prefix + parsed.segments
                alias = match.group("alias")
                resolved = target_path + ("index",)
                foreach_arrays[(resolved, match.start())] = (resolved, match.start())
                key = match.group("key")
                if key is not None:
                    changed = _add_index_context(index_context, target_path, key) or changed
                if aliases.get(alias) != resolved:
                    aliases[alias] = resolved
                    changed = True
    return aliases, index_context, list(foreach_arrays.values())


def _merge_dict_schema(target: dict[str, object], source: dict[str, object]) -> None:
    for key, value in source.items():
        if key == "x-asgard-evidence":
            existing = target.setdefault(key, [])
            if isinstance(existing, list) and isinstance(value, list):
                existing.extend(item for item in value if item not in existing)
            continue
        existing_mapping = target.get(key)
        if key in {"properties", "items"} and isinstance(existing_mapping, dict) and isinstance(value, dict):
            _merge_dict_schema(existing_mapping, value)
            continue
        if key == "required" and isinstance(target.get(key), list) and isinstance(value, list):
            required = target[key]
            assert isinstance(required, list)
            required.extend(item for item in value if item not in required)
            continue
        if key not in target:
            target[key] = value


def _merge_schema_path(
    root: dict[str, object],
    segments: tuple[str, ...],
    schema: dict[str, object],
    evidence: Evidence,
    *,
    required: bool,
) -> str | None:
    current = root
    for index, segment in enumerate(segments):
        if segment == "index":
            current["type"] = "array"
            items = current.setdefault("items", {})
            if not isinstance(items, dict):
                return None
            current = items
            continue
        if segment == "dynamic":
            return None
        name = segment.removeprefix("property:")
        current["type"] = "object"
        properties = current.setdefault("properties", {})
        if not isinstance(properties, dict):
            return None
        field_schema = properties.setdefault(name, {})
        if not isinstance(field_schema, dict):
            return None
        required_values = current.setdefault("required", []) if required else None
        if isinstance(required_values, list) and name not in {str(item) for item in required_values}:
            required_values.append(name)
        if index == len(segments) - 1:
            _merge_dict_schema(field_schema, _schema_with_evidence(schema, evidence))
            return name
        current = field_schema
    if segments and segments[-1] == "index":
        root["type"] = "array"
    return None


def _dynamic_request_unresolved(
    repository: Path,
    source: _RouteSource | _FunctionSource,
    offset: int,
) -> ContractUnresolved:
    return ContractUnresolved(
        code="slim_php_request_body_dynamic",
        message="JSON request body is accessed with a dynamic key and cannot be fully reconstructed.",
        evidence=(
            _evidence(
                repository,
                source.file,
                source.text,
                source.body_start + offset,
                "dynamic JSON request body key",
            ),
        ),
    )


def _request_unresolved(
    repository: Path,
    source: _RouteSource | _FunctionSource,
    offset: int,
    message: str,
    note: str,
) -> ContractUnresolved:
    return ContractUnresolved(
        code="slim_php_request_body_unresolved",
        message=message,
        evidence=(
            _evidence(
                repository,
                source.file,
                source.text,
                source.body_start + offset,
                note,
            ),
        ),
    )


def _scan_request_accesses(
    repository: Path,
    source: _RouteSource | _FunctionSource,
    root_paths: dict[str, tuple[str, ...]],
) -> _RequestShape:
    shape = _RequestShape(schema={}, fields={}, unresolved=[])
    aliases, index_context, foreach_arrays = _request_context(source, root_paths)

    for prefix, offset in foreach_arrays:
        _merge_schema_path(
            shape.schema,
            prefix,
            {},
            _evidence(repository, source.file, source.text, source.body_start + offset, "JSON request array iteration"),
            required=True,
        )
        shape.used = True
        shape.scalar_array = True

    matches: list[tuple[int, str, tuple[str, ...], bool, dict[str, object], Evidence]] = []
    for variable, prefix in aliases.items():
        access = re.compile(
            rf"(?P<cast>\((?:int|integer|string|bool|boolean)\)\s*)?"
            rf"{re.escape(variable)}(?P<chain>(?:\s*\[[^\]]+\])+)",
            re.IGNORECASE | re.DOTALL,
        )
        for match in access.finditer(source.body):
            parsed = _parse_chain(match.group("chain"), index_context, base_path=prefix)
            if parsed.dynamic:
                shape.unresolved.append(_dynamic_request_unresolved(repository, source, match.start()))
                shape.used = True
                continue
            segments = prefix + parsed.segments
            default_match = re.match(r"\s*\?\?\s*(?P<default>[^;\n,\)]+)", source.body[match.end() :])
            required = default_match is None
            expression = f"{match.group('cast') or ''}{variable}{match.group('chain')}"
            schema = _field_schema(expression, default_match.group("default") if default_match else None)
            evidence = _evidence(
                repository,
                source.file,
                source.text,
                source.body_start + match.start(),
                (
                    "optional JSON request property with literal default"
                    if default_match
                    else "JSON request property access"
                ),
            )
            matches.append((match.start(), variable, segments, required, schema, evidence))

    for _offset, _variable, segments, required, schema, evidence in sorted(matches):
        if not segments:
            continue
        if segments[-1] == "index":
            _merge_schema_path(shape.schema, segments, schema, evidence, required=required)
            shape.used = True
            shape.scalar_array = True
            continue
        field_name = _merge_schema_path(
            shape.schema,
            segments,
            schema,
            evidence,
            required=required,
        )
        if field_name is not None:
            existing = shape.fields.get(field_name)
            if existing is None or (existing.required is False and required):
                shape.fields[field_name] = _Field(field_name, required, schema, evidence)
            shape.used = True

    return shape


def _function_calls(body: str) -> list[tuple[str, list[str], int]]:
    calls: list[tuple[str, list[str], int]] = []
    pattern = re.compile(r"(?<!->)(?<!::)\b(?P<name>[A-Za-z_]\w*)\s*\(", re.IGNORECASE)
    ignored = {
        "array",
        "count",
        "json_decode",
        "json_encode",
        "foreach",
        "if",
        "while",
        "for",
        "switch",
        "function",
    }
    for match in pattern.finditer(body):
        name = match.group("name")
        if name.lower() in ignored:
            continue
        open_offset = body.find("(", match.start())
        close = _matching_delimiter(body, open_offset, "(", ")")
        if close is None:
            continue
        calls.append((name, _split_top_level(body[open_offset + 1 : close]), match.start()))
    return calls


def _argument_root_path(
    argument: str,
    aliases: dict[str, tuple[str, ...]],
    index_context: dict[tuple[str, ...], set[str]],
) -> tuple[str, tuple[str, ...]] | None:
    stripped = argument.strip()
    match = re.fullmatch(r"(?P<variable>\$[A-Za-z_]\w*)(?P<chain>(?:\s*\[[^\]]+\])*)", stripped, re.DOTALL)
    if match is None:
        return None
    variable = match.group("variable")
    if variable not in aliases:
        return None
    prefix = aliases[variable]
    parsed = _parse_chain(match.group("chain") or "", index_context, base_path=prefix)
    if parsed.dynamic:
        return None
    return variable, prefix + parsed.segments


def _multipart_body(repository: Path, source: _RouteSource) -> RequestFinding | None:
    fields: dict[str, _Field] = {}
    schema: dict[str, object] = {"type": "object", "properties": {}}
    properties = schema["properties"]
    assert isinstance(properties, dict)
    for pattern, field_schema, note in (
        (_POST_FIELD, {"type": "string"}, "multipart form field"),
        (_FILES_FIELD, {"type": "string", "format": "binary"}, "multipart file field"),
    ):
        for match in pattern.finditer(source.body):
            name = match.group("field")
            evidence = _evidence(repository, source.file, source.text, source.body_start + match.start(), note)
            properties[name] = _schema_with_evidence(field_schema, evidence)
            fields[name] = _Field(name, True, field_schema, evidence)
    if not fields:
        return None
    schema["required"] = sorted(fields)
    return RequestFinding(
        content_type="multipart/form-data",
        body_schema=schema,
        fields=sorted(fields),
    )


def _request_body(
    repository: Path,
    source: _RouteSource,
    function_definitions: dict[str, list[_FunctionSource]],
) -> tuple[RequestFinding | None, list[ContractUnresolved], bool, bool]:
    multipart = _multipart_body(repository, source)
    if multipart is not None:
        return multipart, [], True, True

    body_match = _JSON_BODY.search(source.body)
    if body_match is None:
        return None, [], False, False

    variable = body_match.group("var")
    unresolved: list[ContractUnresolved] = []
    root_paths = {variable: ()}
    shape = _scan_request_accesses(repository, source, root_paths)
    unresolved.extend(shape.unresolved)

    aliases, index_context, _foreach_arrays = _request_context(source, root_paths)

    function_used = False
    for name, arguments, offset in _function_calls(source.body):
        definitions = function_definitions.get(name)
        if definitions is None:
            continue
        for position, argument in enumerate(arguments):
            mapped = _argument_root_path(argument, aliases, index_context)
            if mapped is None:
                continue
            if any(segment.startswith("property:") for segment in mapped[1]):
                continue
            function_used = True
            if len(definitions) != 1:
                unresolved.append(
                    _request_unresolved(
                        repository,
                        source,
                        offset,
                        (
                            f"JSON request body is passed to local function {name} but "
                            "the function definition is not unique."
                        ),
                        "ambiguous local function request propagation",
                    )
                )
                continue
            definition = definitions[0]
            if position >= len(definition.parameters):
                unresolved.append(
                    _request_unresolved(
                        repository,
                        source,
                        offset,
                        (
                            f"JSON request body is passed to local function {name} but "
                            "the target parameter cannot be identified."
                        ),
                        "unsupported local function request propagation",
                    )
                )
                continue
            parameter = definition.parameters[position]
            propagated = _scan_request_accesses(
                repository,
                definition,
                {parameter: mapped[1]},
            )
            unresolved.extend(propagated.unresolved)
            if not propagated.used:
                unresolved.append(
                    _request_unresolved(
                        repository,
                        definition,
                        0,
                        (
                            f"JSON request body reaches local function {name} but no supported "
                            "literal request access was found there."
                        ),
                        "local function request propagation",
                    )
                )
                continue
            _merge_dict_schema(shape.schema, propagated.schema)
            shape.fields.update(propagated.fields)
            shape.used = True
            shape.scalar_array = shape.scalar_array or propagated.scalar_array

    if not shape.used and not function_used:
        return None, [], False, False

    if not shape.schema and unresolved:
        return None, unresolved, True, False
    if not shape.schema:
        unresolved.append(
            _request_unresolved(
                repository,
                source,
                body_match.start(),
                "JSON request body is decoded but no supported literal property access was found.",
                "JSON request body decode",
            )
        )
        return None, unresolved, True, False

    request = RequestFinding(
        content_type="application/json",
        body_schema=shape.schema,
        fields=sorted(shape.fields),
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
            credential_format = "bearer_jwt"
            scheme = "bearer"
            header_semantics = "bearer_authorization_header"
        else:
            authentication = f"Authorization header raw JWT {algorithm}"
            note = "JWT Authorization header raw value validation"
            credential_format = "raw_jwt"
            scheme = None
            header_semantics = "raw_authorization_header"
        return _AuthenticationEvidence(
            authentication=authentication,
            evidence=_evidence(
                repository,
                file,
                text,
                body_start + match.start(),
                note,
            ),
            credential_format=credential_format,
            scheme=scheme,
            header_semantics=header_semantics,
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
        endpoint.credential_format = authentication.credential_format
        endpoint.scheme = authentication.scheme
        endpoint.header_semantics = authentication.header_semantics
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
    function_definitions = _extract_function_definitions(files)

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
            repository, source, function_definitions
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
