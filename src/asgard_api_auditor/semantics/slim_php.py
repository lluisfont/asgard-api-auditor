"""Deterministic Slim/PHP semantic reconstruction."""

from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..discovery_types import IntegrationFinding
from ..discovery_utils import line_number, relative_path
from ..enrichment.slim_php import (
    _FunctionSource,
    _RouteSource,
    _evidence,
    _extract_function_definitions,
    _extract_routes,
    _function_calls,
    _matching_delimiter,
    _split_top_level,
)
from ..models import EndpointFinding, Evidence
from .types import SemanticEnrichmentCoverage, SemanticEnrichmentResult, SemanticUnresolved

_STRING = re.compile(r"(?P<quote>['\"])(?P<value>.*?)(?P=quote)", re.DOTALL)
_SQL_CALL = re.compile(r"->(?P<method>query|exec|prepare)\s*\(", re.IGNORECASE)
_SQL_ASSIGN = re.compile(r"(?P<var>\$[A-Za-z_]\w*)\s*=\s*(?P<expr>.*)\s*;\s*$", re.IGNORECASE | re.DOTALL)
_SQL_APPEND = re.compile(r"(?P<var>\$[A-Za-z_]\w*)\s*\.=\s*(?P<expr>.*)\s*;\s*$", re.IGNORECASE | re.DOTALL)
_SQL_KEYWORD = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|CALL)\b", re.IGNORECASE)
_SQL_FRAGMENT_KEYWORD = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|CALL|FROM|JOIN|VALUES|WHERE|SET)\b",
    re.IGNORECASE,
)
_REQUEST_ROOT = re.compile(r"(?P<var>\$[A-Za-z_]\w*)\s*=\s*json_decode\s*\(\s*(?:\(\s*string\s*\)\s*)?\$request->getBody\s*\(\s*\)\s*,\s*true\s*\)", re.IGNORECASE | re.DOTALL)
_PARSED_BODY_ROOT = re.compile(
    r"(?P<var>\$[A-Za-z_]\w*)\s*=\s*\$request->getParsedBody\s*\(\s*\)",
    re.IGNORECASE,
)
_REQUEST_FIELD_ASSIGN = re.compile(r"(?P<var>\$[A-Za-z_]\w*)\s*=\s*(?P<root>\$[A-Za-z_]\w*)\s*\[\s*['\"](?P<field>[^'\"]+)['\"]\s*\]", re.IGNORECASE)
_JWT_DECODE_ASSIGN = re.compile(r"(?P<var>\$[A-Za-z_]\w*)\s*=\s*(?:\(array\)\s*)?JWT::decode\s*\(", re.IGNORECASE)
_JWT_CAST_ASSIGN = re.compile(r"(?P<alias>\$[A-Za-z_]\w*)\s*=\s*\(array\)\s*(?P<source>\$[A-Za-z_]\w*)\s*;", re.IGNORECASE)
_JWT_DECODE = re.compile(r"JWT::decode\s*\((?P<args>.*?)new\s+Key\s*\([^;]*?['\"](?P<algorithm>[A-Za-z0-9_-]+)['\"]", re.IGNORECASE | re.DOTALL)
_JWT_CLAIM_OBJECT = re.compile(r"(?P<var>\$[A-Za-z_]\w*)\s*->\s*(?P<claim>[A-Za-z_][A-Za-z0-9_]*)")
_JWT_CLAIM_ARRAY = re.compile(r"(?P<var>\$[A-Za-z_]\w*)\s*\[\s*['\"](?P<claim>[^'\"]+)['\"]\s*\]")
_JWT_ENCODE = re.compile(r"JWT::encode\s*\(", re.IGNORECASE)
_ARRAY_ASSIGN = re.compile(r"(?P<var>\$[A-Za-z_]\w*)\s*=\s*(?P<kind>array\s*\(|\[)", re.IGNORECASE)
_ARRAY_KEY = re.compile(r"['\"](?P<key>[^'\"]+)['\"]\s*=>")
_WITH_STATUS = re.compile(r"withStatus\s*\(\s*(?P<status>[1-5][0-9]{2})\s*\)", re.IGNORECASE)
_IF_START = re.compile(r"\bif\s*\(", re.IGNORECASE)
_BODY_FIELD = re.compile(r"['\"](?P<field>codigo|estado|mensaje)['\"]\s*=>\s*(?P<expr>[^,\)\]\n]+)", re.IGNORECASE)
_RESPONSE_FIELD_BINDING = re.compile(
    r"['\"](?P<field>[A-Za-z_][A-Za-z0-9_]*)['\"]\s*=>\s*(?P<var>\$[A-Za-z_]\w*)",
    re.IGNORECASE,
)
_VARIABLE_ASSIGNMENT = re.compile(
    r"(?P<var>\$[A-Za-z_]\w*)\s*=\s*(?P<expr>[^;]+);",
    re.IGNORECASE | re.DOTALL,
)
_CURL = re.compile(r"\bcurl_(?:init|setopt|setopt_array|exec)\s*\(", re.IGNORECASE)
_SOAP = re.compile(r"\bnew\s+SoapClient\s*\(|->__soapCall\s*\(", re.IGNORECASE)
_HTTP_LITERAL = re.compile(r"['\"](?P<url>https?://[^'\"]+)['\"]", re.IGNORECASE)
_LITERAL_ASSIGN = re.compile(r"(?P<var>\$[A-Za-z_]\w*)\s*=\s*(?P<expr>[^;]+);", re.IGNORECASE | re.DOTALL)
_CURL_INIT = re.compile(r"\bcurl_init\s*\(", re.IGNORECASE)
_CURL_SETOPT = re.compile(r"\bcurl_setopt\s*\(", re.IGNORECASE)
_CURL_SETOPT_ARRAY = re.compile(r"\bcurl_setopt_array\s*\(", re.IGNORECASE)
_SOAP_CLIENT = re.compile(r"\bnew\s+SoapClient\s*\(", re.IGNORECASE)
_SOAP_CALL = re.compile(r"->__soapCall\s*\(", re.IGNORECASE)
_FILE = re.compile(r"\b(file_put_contents|move_uploaded_file|unlink|fopen)\s*\(", re.IGNORECASE)
_MAIL = re.compile(r"\b(mail|PHPMailer)\s*\(", re.IGNORECASE)
_SELECT = re.compile(r"\b(?:FROM|JOIN)\s+([`\"']?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?[`\"']?)", re.IGNORECASE)
_INSERT = re.compile(r"\bINSERT\s+INTO\s+([`\"']?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?[`\"']?)", re.IGNORECASE)
_UPDATE = re.compile(r"\bUPDATE\s+([`\"']?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?[`\"']?)", re.IGNORECASE)
_DELETE = re.compile(r"\bDELETE\s+FROM\s+([`\"']?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?[`\"']?)", re.IGNORECASE)
_CALL = re.compile(r"\bCALL\s+([`\"']?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?[`\"']?)", re.IGNORECASE)
_DYNAMIC_SQL_PART = "__ASGARD_DYNAMIC_SQL_PART__"
_DYNAMIC_FUNCTION_CALL = re.compile(r"(?<!->)(?<!::)(?P<var>\$[A-Za-z_]\w*)\s*\(", re.IGNORECASE)
_CALL_USER_FUNC = re.compile(r"\bcall_user_func(?:_array)?\s*\(", re.IGNORECASE)
_DYNAMIC_METHOD_CALL = re.compile(r"->\s*(?P<method>\$[A-Za-z_]\w*)\s*\(", re.IGNORECASE)
_DYNAMIC_CLASS = re.compile(r"\bnew\s+(?P<class>\$[A-Za-z_]\w*)", re.IGNORECASE)
_SWITCH = re.compile(r"\bswitch\s*\(", re.IGNORECASE)
_DYNAMIC_CALLBACK_ARG = re.compile(r"\barray_(?:map|filter|walk|reduce)\s*\([^;\n]*\$[A-Za-z_]\w*", re.IGNORECASE)
_IGNORED_UNRESOLVED_CALLS = {
    "apache_request_headers",
    "array",
    "array_key_exists",
    "array_map",
    "array_push",
    "boolval",
    "call_user_func",
    "call_user_func_array",
    "count",
    "curl_close",
    "curl_exec",
    "curl_init",
    "curl_setopt",
    "curl_setopt_array",
    "date",
    "empty",
    "explode",
    "file_put_contents",
    "floatval",
    "fopen",
    "implode",
    "in_array",
    "intval",
    "isset",
    "json_decode",
    "json_encode",
    "key",
    "mail",
    "md5",
    "move_uploaded_file",
    "preg_replace",
    "round",
    "soapclient",
    "str_replace",
    "strlen",
    "trim",
    "unlink",
}


@dataclass
class _Context:
    source: _RouteSource | _FunctionSource
    body: str
    body_start: int
    file: Path
    text: str


@dataclass
class _Builder:
    repository: Path
    endpoint: EndpointFinding
    source: _RouteSource
    data_access: list[dict[str, object]] = field(default_factory=list)
    consumed_claims: dict[str, dict[str, object]] = field(default_factory=dict)
    produced_claims: dict[str, dict[str, object]] = field(default_factory=dict)
    request_fields: dict[str, dict[str, object]] = field(default_factory=dict)
    local_calls: list[dict[str, object]] = field(default_factory=list)
    outbound: list[dict[str, object]] = field(default_factory=list)
    conditions: list[dict[str, object]] = field(default_factory=list)
    http_status_codes: set[int] = field(default_factory=set)
    side_effects: list[dict[str, object]] = field(default_factory=list)
    unresolved: list[SemanticUnresolved] = field(default_factory=list)


def _stable_id(prefix: str, *parts: object) -> str:
    return f"{prefix}-{hashlib.sha256('|'.join(str(part) for part in parts).encode()).hexdigest()[:16]}"


def _safe_evidence(evidence: Evidence) -> dict[str, object]:
    payload: dict[str, object] = {"path": evidence.path, "kind": evidence.kind}
    if evidence.line is not None:
        payload["line"] = evidence.line
    if evidence.end_line is not None:
        payload["end_line"] = evidence.end_line
    if evidence.symbol is not None:
        payload["symbol"] = evidence.symbol
    if evidence.note is not None:
        payload["note"] = evidence.note
    return payload


def _mask_strings(text: str) -> str:
    chars = list(text)
    i = 0
    while i < len(chars):
        quote = chars[i]
        if quote not in {"'", '"'}:
            i += 1
            continue
        i += 1
        while i < len(chars):
            if chars[i] == "\\":
                chars[i] = " "
                if i + 1 < len(chars):
                    chars[i + 1] = " "
                i += 2
                continue
            if chars[i] == quote:
                i += 1
                break
            if chars[i] != "\n":
                chars[i] = " "
            i += 1
    return "".join(chars)


def _ctx(source: _RouteSource | _FunctionSource) -> _Context:
    return _Context(source, source.body, source.body_start, source.file, source.text)


def _ev(repository: Path, ctx: _Context, offset: int, note: str) -> Evidence:
    return _evidence(repository, ctx.file, ctx.text, ctx.body_start + offset, note)


def _unresolved(builder: _Builder, code: str, message: str, evidence: Evidence) -> None:
    builder.unresolved.append(SemanticUnresolved(code, message, (evidence,)))


def _contains_php_variable(expr: str, variable: str) -> bool:
    return re.search(rf"(?<![A-Za-z0-9_]){re.escape(variable)}(?![A-Za-z0-9_])", expr) is not None


def _literal(expr: str, field_vars: dict[str, str]) -> tuple[str, list[str], bool]:
    parts: list[str] = []
    cursor = 0
    dynamic = False
    for match in _STRING.finditer(expr):
        if expr[cursor : match.start()].strip(" \t\r\n."):
            dynamic = True
        parts.append(match.group("value"))
        cursor = match.end()
    if expr[cursor:].strip(" \t\r\n."):
        dynamic = True
    fields = sorted({field for variable, field in field_vars.items() if _contains_php_variable(expr, variable)})
    return " ".join(parts), fields, dynamic


def _sql_literal(expr: str, field_vars: dict[str, str]) -> tuple[str, list[str], bool]:
    parts: list[str] = []
    cursor = 0
    dynamic = False
    for match in _STRING.finditer(expr):
        if expr[cursor : match.start()].strip(" \t\r\n."):
            parts.append(_DYNAMIC_SQL_PART)
            dynamic = True
        parts.append(match.group("value"))
        cursor = match.end()
    if expr[cursor:].strip(" \t\r\n."):
        parts.append(_DYNAMIC_SQL_PART)
        dynamic = True
    fields = sorted({field for variable, field in field_vars.items() if _contains_php_variable(expr, variable)})
    return "".join(parts), fields, dynamic


def _field_vars(body: str) -> dict[str, str]:
    roots = {match.group("var") for match in _REQUEST_ROOT.finditer(body)}
    roots.update(match.group("var") for match in _PARSED_BODY_ROOT.finditer(body))
    return {
        match.group("var"): match.group("field")
        for match in _REQUEST_FIELD_ASSIGN.finditer(body)
        if match.group("root") in roots
    }


def _record_request_fields(builder: _Builder, ctx: _Context) -> None:
    roots = {match.group("var") for match in _REQUEST_ROOT.finditer(ctx.body)}
    roots.update(match.group("var") for match in _PARSED_BODY_ROOT.finditer(ctx.body))
    for match in _REQUEST_FIELD_ASSIGN.finditer(ctx.body):
        if match.group("root") not in roots:
            continue
        field = match.group("field")
        builder.request_fields[field] = {
            "name": field,
            "variable": match.group("var"),
            "evidence": [_safe_evidence(_ev(builder.repository, ctx, match.start(), "request field assigned to local variable"))],
        }


def _php_statements(body: str) -> list[str]:
    statements: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(body):
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
        if char == ";":
            statements.append(body[start : index + 1])
            start = index + 1
    tail = body[start:].strip()
    if tail:
        statements.append(tail)
    return statements


def _sql_vars(body: str) -> dict[str, tuple[str, list[str], bool]]:
    values: dict[str, tuple[str, list[str], bool]] = {}
    field_vars = _field_vars(body)
    for statement in _php_statements(body):
        match = _SQL_ASSIGN.search(statement)
        if match is not None:
            if _SQL_FRAGMENT_KEYWORD.search(statement) is None:
                continue
            reassigned_append = re.match(
                rf"\s*{re.escape(match.group('var'))}\s*\.\s*(?P<tail>.+)\s*$",
                match.group("expr"),
                re.DOTALL,
            )
            if reassigned_append is not None:
                literal, fields, dynamic = _sql_literal(reassigned_append.group("tail"), field_vars)
                if literal:
                    previous_sql, previous_fields, previous_dynamic = values.get(match.group("var"), ("", [], False))
                    values[match.group("var")] = (
                        f"{previous_sql} {literal}".strip(),
                        sorted(set(previous_fields + fields)),
                        previous_dynamic or dynamic,
                    )
                continue
            literal, fields, dynamic = _sql_literal(match.group("expr"), field_vars)
            if literal:
                values[match.group("var")] = (literal, fields, dynamic)
            continue
        match = _SQL_APPEND.search(statement)
        if match is None:
            continue
        if match.group("var") not in values and _SQL_FRAGMENT_KEYWORD.search(statement) is None:
            continue
        literal, fields, dynamic = _sql_literal(match.group("expr"), field_vars)
        if literal:
            previous_sql, previous_fields, previous_dynamic = values.get(match.group("var"), ("", [], False))
            values[match.group("var")] = (
                f"{previous_sql} {literal}".strip(),
                sorted(set(previous_fields + fields)),
                previous_dynamic or dynamic,
            )
    return values


def _clean(raw: str) -> str:
    return raw.strip().strip("`\"'")


def _complete_resource(raw: str) -> bool:
    return bool(raw) and _DYNAMIC_SQL_PART not in raw and not raw.endswith(("_", "."))


def _sql_targets(statement: str) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for match in _SELECT.finditer(statement):
        prefix = statement[max(0, match.start() - 32) : match.start()].upper()
        if any(marker in prefix for marker in ("LEADING", "TRAILING", "BOTH")):
            continue
        resource = _clean(match.group(1))
        if _complete_resource(resource):
            result.append(("SELECT", resource))
    for regex, operation in ((_INSERT, "INSERT"), (_UPDATE, "UPDATE"), (_DELETE, "DELETE"), (_CALL, "CALL")):
        match = regex.search(statement)
        if match is not None:
            resource = _clean(match.group(1))
            if _complete_resource(resource):
                result.append((operation, resource))
    return result


def _record_sql(builder: _Builder, ctx: _Context) -> None:
    sql_vars = _sql_vars(ctx.body)
    field_vars = _field_vars(ctx.body)
    for call in _SQL_CALL.finditer(ctx.body):
        open_at = ctx.body.find("(", call.start())
        close_at = _matching_delimiter(ctx.body, open_at, "(", ")")
        evidence = _ev(builder.repository, ctx, call.start(), f"PDO {call.group('method')} SQL call")
        if close_at is None:
            _unresolved(builder, "slim_php_semantic_sql_call_unparsed", "SQL call arguments could not be parsed deterministically.", evidence)
            continue
        args = _split_top_level(ctx.body[open_at + 1 : close_at])
        if not args:
            continue
        expr = args[0].strip()
        if expr in sql_vars:
            sql, source_fields, dynamic = sql_vars[expr]
        else:
            sql, source_fields, dynamic = _sql_literal(expr, field_vars)
        if not sql:
            _unresolved(builder, "slim_php_semantic_dynamic_sql", "SQL expression is dynamic and no literal statement text could be reconstructed.", evidence)
            continue
        targets = [target for statement in sql.split(";") for target in _sql_targets(statement)]
        if not targets:
            _unresolved(builder, "slim_php_semantic_sql_target_unresolved", "SQL statement did not contain a supported literal table/procedure target.", evidence)
            continue
        for operation, resource in targets:
            entry = {
                "id": _stable_id("sem-sql", builder.endpoint.endpoint_id, operation, resource, evidence.path, evidence.line),
                "operation": operation,
                "resource": resource,
                "source_fields": source_fields,
                "evidence": [_safe_evidence(evidence)],
            }
            builder.data_access.append(entry)
            if operation in {"INSERT", "UPDATE", "DELETE", "CALL"}:
                builder.side_effects.append(
                    {
                        "id": _stable_id("sem-side-effect", builder.endpoint.endpoint_id, operation, resource, evidence.path, evidence.line),
                        "type": "database_write" if operation != "CALL" else "database_call",
                        "operation": operation,
                        "resource": resource,
                        "evidence": [_safe_evidence(evidence)],
                    }
                )
        if dynamic:
            _unresolved(builder, "slim_php_semantic_sql_dynamic_expression", "SQL contains dynamic expression parts; only literal table/procedure targets were recorded.", evidence)


def _array_assignment(body: str, variable: str, before: int) -> str | None:
    found: str | None = None
    for match in _ARRAY_ASSIGN.finditer(body[:before]):
        if match.group("var") != variable:
            continue
        open_char = "(" if match.group("kind").lower().startswith("array") else "["
        close_char = ")" if open_char == "(" else "]"
        open_at = body.find(open_char, match.start())
        close_at = _matching_delimiter(body, open_at, open_char, close_char)
        if close_at is not None:
            found = body[open_at + 1 : close_at]
    return found


def _array_keys(expr: str) -> list[str]:
    return sorted({match.group("key") for match in _ARRAY_KEY.finditer(expr)})


def _record_jwt(builder: _Builder, ctx: _Context) -> None:
    decode_vars = {match.group("var") for match in _JWT_DECODE_ASSIGN.finditer(ctx.body)}
    changed = True
    while changed:
        changed = False
        for match in _JWT_CAST_ASSIGN.finditer(ctx.body):
            if match.group("source") in decode_vars and match.group("alias") not in decode_vars:
                decode_vars.add(match.group("alias"))
                changed = True
    for variable in decode_vars:
        for regex in (_JWT_CLAIM_OBJECT, _JWT_CLAIM_ARRAY):
            for match in regex.finditer(ctx.body):
                if match.group("var") == variable:
                    claim = match.group("claim")
                    builder.consumed_claims[claim] = {
                        "claim": claim,
                        "evidence": [_safe_evidence(_ev(builder.repository, ctx, match.start(), "JWT consumed claim read"))],
                    }
    for match in _JWT_DECODE.finditer(ctx.body):
        evidence = _ev(builder.repository, ctx, match.start(), "JWT decode")
        if not decode_vars:
            _unresolved(builder, "slim_php_semantic_jwt_decode_result_unresolved", "JWT decode result variable could not be identified.", evidence)
    for match in _JWT_ENCODE.finditer(ctx.body):
        open_at = ctx.body.find("(", match.start())
        close_at = _matching_delimiter(ctx.body, open_at, "(", ")")
        evidence = _ev(builder.repository, ctx, match.start(), "JWT produced token")
        if close_at is None:
            _unresolved(builder, "slim_php_semantic_jwt_encode_unparsed", "JWT encode arguments could not be parsed deterministically.", evidence)
            continue
        args = _split_top_level(ctx.body[open_at + 1 : close_at])
        claims: list[str] = []
        if args:
            claims = _array_keys(args[0])
            if not claims and re.fullmatch(r"\$[A-Za-z_]\w*", args[0].strip()):
                assignment = _array_assignment(ctx.body, args[0].strip(), match.start())
                claims = _array_keys(assignment or "")
        if not claims:
            _unresolved(builder, "slim_php_semantic_jwt_claims_unresolved", "Produced JWT claims could not be reconstructed from literal array keys.", evidence)
            continue
        for claim in claims:
            builder.produced_claims[claim] = {"claim": claim, "evidence": [_safe_evidence(evidence)]}


def _skip_ws(body: str, offset: int) -> int:
    while offset < len(body) and body[offset].isspace():
        offset += 1
    return offset


def _parse_else_block(body: str, offset: int) -> tuple[str, int] | None:
    offset = _skip_ws(body, offset)
    if not body.startswith("else", offset):
        return None
    after_else = offset + len("else")
    if after_else < len(body) and (body[after_else].isalnum() or body[after_else] == "_"):
        return None
    branch_start = _skip_ws(body, after_else)
    if body.startswith("if", branch_start):
        return None
    if branch_start >= len(body) or body[branch_start] != "{":
        return None
    branch_end = _matching_delimiter(body, branch_start, "{", "}")
    if branch_end is None:
        return None
    return body[branch_start + 1 : branch_end], offset


def _condition_span_end(body: str, if_start: int) -> int | None:
    open_at = body.find("(", if_start)
    close_at = _matching_delimiter(body, open_at, "(", ")")
    if close_at is None:
        return None
    brace = body.find("{", close_at)
    if brace == -1:
        return None
    end = _matching_delimiter(body, brace, "{", "}")
    if end is None:
        return None
    parsed_else = _parse_else_block(body, end + 1)
    if parsed_else is None:
        return end + 1
    else_offset = parsed_else[1]
    else_brace = body.find("{", else_offset)
    else_end = _matching_delimiter(body, else_brace, "{", "}")
    return None if else_end is None else else_end + 1


def _mask_nested_condition_structures(block: str) -> str:
    chars = list(block)
    masked_until = 0
    for match in _IF_START.finditer(block):
        if match.start() < masked_until:
            continue
        end = _condition_span_end(block, match.start())
        if end is None:
            continue
        for index in range(match.start(), end):
            if chars[index] != "\n":
                chars[index] = " "
        masked_until = end
    return "".join(chars)


def _has_nested_condition(block: str) -> bool:
    return _IF_START.search(_mask_strings(block)) is not None


def _conditions(body: str) -> list[tuple[str, str, int]]:
    result: list[tuple[str, str, int]] = []
    for match in _IF_START.finditer(body):
        open_at = body.find("(", match.start())
        close_at = _matching_delimiter(body, open_at, "(", ")")
        if close_at is None:
            continue
        brace = body.find("{", close_at)
        end = _matching_delimiter(body, brace, "{", "}") if brace != -1 else None
        if end is not None:
            result.append((body[open_at + 1 : close_at].strip(), body[brace + 1 : end], match.start()))
            parsed_else = _parse_else_block(body, end + 1)
            if parsed_else is not None:
                else_block, else_offset = parsed_else
                result.append((f"else !({body[open_at + 1 : close_at].strip()})", else_block, else_offset))
    return result


def _response_field_bindings(body: str) -> dict[str, set[str]]:
    bindings: dict[str, set[str]] = {}
    for match in _RESPONSE_FIELD_BINDING.finditer(body):
        bindings.setdefault(match.group("var"), set()).add(match.group("field"))
    return bindings


def _record_conditions(builder: _Builder, ctx: _Context) -> None:
    response_bindings = _response_field_bindings(ctx.body)
    response_fields = set(builder.endpoint.response.fields if builder.endpoint.response else [])
    for condition, block, offset in _conditions(ctx.body):
        if _has_nested_condition(block):
            _unresolved(
                builder,
                "slim_php_semantic_nested_condition_branch",
                "Condition branch contains nested control flow; only direct assignments were attributed to this condition.",
                _ev(builder.repository, ctx, offset, "nested condition branch"),
            )
        direct_block = _mask_nested_condition_structures(block)
        fields = [
            {"field": match.group("field"), "expression": match.group("expr").strip()}
            for match in _BODY_FIELD.finditer(direct_block)
            if match.group("field") in response_fields
        ]
        for match in _VARIABLE_ASSIGNMENT.finditer(direct_block):
            variable = match.group("var")
            for response_field in response_bindings.get(variable, set()):
                if response_field not in response_fields:
                    continue
                fields.append(
                    {
                        "field": response_field,
                        "variable": variable,
                        "expression": match.group("expr").strip(),
                    }
                )
        if fields:
            evidence = _ev(builder.repository, ctx, offset, "conditional response body fields")
            builder.conditions.append(
                {
                    "id": _stable_id("sem-condition", builder.endpoint.endpoint_id, evidence.path, evidence.line, condition),
                    "condition": condition,
                    "body_fields": sorted(
                        fields,
                        key=lambda item: (str(item["field"]), str(item.get("variable", "")), str(item["expression"])),
                    ),
                    "evidence": [_safe_evidence(evidence)],
                }
            )


def _literal_vars(body: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for statement in _php_statements(body):
        match = _LITERAL_ASSIGN.search(statement)
        if match is None:
            continue
        value, _fields, dynamic = _literal(match.group("expr"), {})
        if value and not dynamic:
            values[match.group("var")] = value
    return values


def _call_args(body: str, start: int) -> list[str] | None:
    open_at = body.find("(", start)
    close_at = _matching_delimiter(body, open_at, "(", ")")
    if close_at is None:
        return None
    return _split_top_level(body[open_at + 1 : close_at])


def _bound_target(expr: str, variables: dict[str, str]) -> tuple[str | None, bool]:
    stripped = expr.strip()
    if stripped in variables:
        return variables[stripped], False
    literal, _fields, dynamic = _literal(stripped, {})
    if literal and not dynamic:
        return literal, False
    return None, dynamic or bool(stripped)


def _record_outbound_entry(
    builder: _Builder,
    evidence: Evidence,
    kind: str,
    target: str | None,
    *,
    operation: str | None = None,
    unresolved_target: bool = False,
) -> None:
    entry = {
        "id": _stable_id("sem-outbound", builder.endpoint.endpoint_id, kind, operation or "", target or "", evidence.path, evidence.line),
        "type": kind,
        "target": target,
        "evidence": [_safe_evidence(evidence)],
    }
    if operation is not None:
        entry["operation"] = operation
    builder.outbound.append(entry)
    builder.side_effects.append({**entry, "type": "outbound_integration", "integration_type": kind})
    if unresolved_target:
        _unresolved(
            builder,
            "slim_php_semantic_outbound_target_unresolved",
            f"Outbound {kind} target could not be bound deterministically.",
            evidence,
        )


def _record_outbound(builder: _Builder, ctx: _Context) -> None:
    variables = _literal_vars(ctx.body)
    curl_targets: list[str | None] = []
    for match in _CURL_INIT.finditer(ctx.body):
        args = _call_args(ctx.body, match.start())
        if not args:
            continue
        target, dynamic = _bound_target(args[0], variables)
        evidence = _ev(builder.repository, ctx, match.start(), "curl_init outbound target")
        _record_outbound_entry(builder, evidence, "http", target, unresolved_target=target is None and dynamic)
        curl_targets.append(target)
    for match in _CURL_SETOPT.finditer(ctx.body):
        args = _call_args(ctx.body, match.start())
        if args is None or len(args) < 3 or "CURLOPT_URL" not in args[1]:
            continue
        target, dynamic = _bound_target(args[2], variables)
        evidence = _ev(builder.repository, ctx, match.start(), "CURLOPT_URL outbound target")
        _record_outbound_entry(builder, evidence, "http", target, unresolved_target=target is None and dynamic)
        curl_targets.append(target)
    for match in _CURL_SETOPT_ARRAY.finditer(ctx.body):
        args = _call_args(ctx.body, match.start())
        if args is None or len(args) < 2 or "CURLOPT_URL" not in args[1]:
            continue
        option = re.search(r"CURLOPT_URL\s*=>\s*(?P<expr>[^,\]\)]+)", args[1], re.IGNORECASE | re.DOTALL)
        if option is None:
            evidence = _ev(builder.repository, ctx, match.start(), "CURLOPT_URL outbound target")
            _record_outbound_entry(builder, evidence, "http", None, unresolved_target=True)
            curl_targets.append(None)
            continue
        target, dynamic = _bound_target(option.group("expr"), variables)
        evidence = _ev(builder.repository, ctx, match.start(), "CURLOPT_URL outbound target")
        _record_outbound_entry(builder, evidence, "http", target, unresolved_target=target is None and dynamic)
        curl_targets.append(target)
    if not curl_targets:
        for match in re.finditer(r"\bcurl_exec\s*\(", ctx.body, re.IGNORECASE):
            evidence = _ev(builder.repository, ctx, match.start(), "curl_exec outbound call without bound target")
            _record_outbound_entry(builder, evidence, "http", None, unresolved_target=True)
    soap_targets: list[str | None] = []
    for match in _SOAP_CLIENT.finditer(ctx.body):
        args = _call_args(ctx.body, match.start())
        if not args:
            continue
        target, dynamic = _bound_target(args[0], variables)
        evidence = _ev(builder.repository, ctx, match.start(), "SOAP client target")
        _record_outbound_entry(builder, evidence, "soap", target, unresolved_target=target is None and dynamic)
        soap_targets.append(target)
    for match in _SOAP_CALL.finditer(ctx.body):
        args = _call_args(ctx.body, match.start())
        operation, dynamic = (None, True) if not args else _bound_target(args[0], variables)
        evidence = _ev(builder.repository, ctx, match.start(), "SOAP operation call")
        _record_outbound_entry(
            builder,
            evidence,
            "soap",
            soap_targets[-1] if soap_targets else None,
            operation=operation,
            unresolved_target=(not soap_targets and dynamic),
        )
    for regex, kind, note in ((_FILE, "file", "file side effect"), (_MAIL, "mail", "mail side effect")):
        for match in regex.finditer(ctx.body):
            evidence = _ev(builder.repository, ctx, match.start(), note)
            builder.side_effects.append(
                {"id": _stable_id("sem-side-effect", builder.endpoint.endpoint_id, kind, evidence.path, evidence.line), "type": kind, "evidence": [_safe_evidence(evidence)]}
            )


def _record_discovery_integrations(builder: _Builder, integrations: list[IntegrationFinding]) -> None:
    source_path = relative_path(builder.repository, builder.source.file)
    start = line_number(builder.source.text, builder.source.route_offset) or 0
    end = line_number(builder.source.text, builder.source.body_end) or 0
    for integration in integrations:
        if integration.direction != "consumed":
            continue
        for evidence in integration.evidence:
            if evidence.path == source_path and evidence.line is not None and start <= evidence.line <= end:
                builder.outbound.append(
                    {
                        "id": _stable_id("sem-outbound-discovery", builder.endpoint.endpoint_id, integration.type, evidence.path, evidence.line, integration.operation or ""),
                        "type": integration.type,
                        "operation": integration.operation,
                        "target": integration.service_expression or integration.wsdl,
                        "evidence": [_safe_evidence(evidence)],
                    }
                )


def _record_coverage_blockers(
    builder: _Builder,
    ctx: _Context,
    functions: dict[str, list[_FunctionSource]],
) -> None:
    masked_body = _mask_strings(ctx.body)
    for match in _DYNAMIC_FUNCTION_CALL.finditer(masked_body):
        _unresolved(
            builder,
            "slim_php_semantic_dynamic_function_call",
            "Dynamic function call cannot be propagated deterministically.",
            _ev(builder.repository, ctx, match.start(), "dynamic function call"),
        )
    for regex, code, message, note in (
        (
            _CALL_USER_FUNC,
            "slim_php_semantic_dynamic_callback",
            "Dynamic callback invocation cannot be propagated deterministically.",
            "dynamic callback invocation",
        ),
        (
            _DYNAMIC_METHOD_CALL,
            "slim_php_semantic_dynamic_method_call",
            "Dynamic method call cannot be propagated deterministically.",
            "dynamic method call",
        ),
        (
            _DYNAMIC_CLASS,
            "slim_php_semantic_dynamic_class",
            "Dynamic class construction cannot be propagated deterministically.",
            "dynamic class construction",
        ),
        (
            _SWITCH,
            "slim_php_semantic_switch_control_flow",
            "Switch control flow is material and not yet semantically reconstructed.",
            "unsupported switch control flow",
        ),
        (
            _DYNAMIC_CALLBACK_ARG,
            "slim_php_semantic_dynamic_callback",
            "Dynamic callback argument cannot be propagated deterministically.",
            "dynamic callback argument",
        ),
    ):
        for match in regex.finditer(masked_body):
            _unresolved(builder, code, message, _ev(builder.repository, ctx, match.start(), note))

    for name, _args, offset in _function_calls(masked_body):
        lowered = name.lower()
        if lowered in _IGNORED_UNRESOLVED_CALLS or name in functions:
            continue
        _unresolved(
            builder,
            "slim_php_semantic_unpropagated_function_call",
            f"Function call {name} has no unique local definition and was not propagated.",
            _ev(builder.repository, ctx, offset, "unpropagated function call"),
        )


def _analyze(builder: _Builder, ctx: _Context, functions: dict[str, list[_FunctionSource]], stack: tuple[str, ...]) -> None:
    masked_body = _mask_strings(ctx.body)
    _record_request_fields(builder, ctx)
    _record_sql(builder, ctx)
    _record_jwt(builder, ctx)
    _record_conditions(builder, ctx)
    for match in _WITH_STATUS.finditer(ctx.body):
        builder.http_status_codes.add(int(match.group("status")))
    _record_outbound(builder, ctx)
    _record_coverage_blockers(builder, ctx, functions)
    if len(stack) >= 4:
        _unresolved(builder, "slim_php_semantic_helper_depth_limit", "Local helper propagation reached the deterministic depth limit.", _ev(builder.repository, ctx, 0, "helper propagation depth limit"))
        return
    for name, _args, offset in _function_calls(masked_body):
        definitions = functions.get(name, [])
        if not definitions:
            continue
        evidence = _ev(builder.repository, ctx, offset, "local helper call")
        builder.local_calls.append({"id": _stable_id("sem-call", builder.endpoint.endpoint_id, name, evidence.path, evidence.line), "name": name, "evidence": [_safe_evidence(evidence)]})
        if name in stack:
            _unresolved(builder, "slim_php_semantic_helper_cycle", f"Local helper propagation stopped at recursive call {name}.", evidence)
        elif len(definitions) != 1:
            _unresolved(builder, "slim_php_semantic_helper_ambiguous", f"Local helper {name} has {len(definitions)} definitions; semantic propagation is ambiguous.", evidence)
        else:
            _analyze(builder, _ctx(definitions[0]), functions, stack + (name,))


def _dedupe_dicts(values: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[str] = set()
    result: list[dict[str, object]] = []
    for value in values:
        key = repr(sorted(value.items(), key=lambda item: item[0]))
        if key not in seen:
            seen.add(key)
            result.append(value)
    return sorted(result, key=lambda item: str(item.get("id", repr(item))))


def _dedupe_unresolved(values: list[SemanticUnresolved]) -> list[SemanticUnresolved]:
    seen: set[tuple[object, ...]] = set()
    result: list[SemanticUnresolved] = []
    for value in values:
        key = (value.code, value.message, tuple((item.path, item.line, item.note) for item in value.evidence))
        if key not in seen:
            seen.add(key)
            result.append(value)
    return sorted(result, key=lambda item: (item.code, item.message, tuple(e.line or 0 for e in item.evidence)))


def _summary(endpoint: EndpointFinding, reads: list[str], writes: list[str], outbound: list[dict[str, object]], status: str) -> str:
    if writes and reads:
        return f"{endpoint.method} {endpoint.path} writes {', '.join(writes[:3])} and reads {', '.join(reads[:3])}"
    if writes:
        return f"{endpoint.method} {endpoint.path} writes {', '.join(writes[:3])}"
    if reads:
        return f"{endpoint.method} {endpoint.path} reads {', '.join(reads[:3])}"
    if outbound:
        return f"{endpoint.method} {endpoint.path} performs outbound {', '.join(sorted({str(item.get('type')) for item in outbound}))} integration"
    return f"{endpoint.method} {endpoint.path} has {status} source semantics"


def _partial_materiality(unresolved: list[SemanticUnresolved]) -> str:
    if not unresolved:
        return "unknown"
    external_markers = (
        "condition",
        "outbound",
        "response",
        "side_effect",
        "status",
    )
    internal_codes = {
        "slim_php_semantic_sql_call_unparsed",
        "slim_php_semantic_dynamic_sql",
        "slim_php_semantic_sql_target_unresolved",
        "slim_php_semantic_sql_dynamic_expression",
    }
    codes = {item.code for item in unresolved}
    if any(any(marker in code for marker in external_markers) for code in codes):
        return "external"
    if codes and codes <= internal_codes:
        return "internal"
    return "unknown"


def _behavior(builder: _Builder) -> tuple[dict[str, object], list[SemanticUnresolved]]:
    data_access = _dedupe_dicts(builder.data_access)
    outbound = _dedupe_dicts(builder.outbound)
    side_effects = _dedupe_dicts(builder.side_effects)
    local_calls = _dedupe_dicts(builder.local_calls)
    conditions = _dedupe_dicts(builder.conditions)
    unresolved = _dedupe_unresolved(builder.unresolved)
    reads = sorted({str(item["resource"]) for item in data_access if item.get("operation") == "SELECT"})
    writes = sorted({str(item["resource"]) for item in data_access if item.get("operation") in {"INSERT", "UPDATE", "DELETE", "CALL"}})
    request_fields = sorted(builder.request_fields.values(), key=lambda item: str(item["name"]))
    facts = bool(
        data_access
        or outbound
        or side_effects
        or local_calls
        or conditions
        or request_fields
        or builder.consumed_claims
        or builder.produced_claims
    )
    if unresolved:
        status = "partial" if facts else "unresolved"
    elif facts:
        status = "complete"
    else:
        status = "unresolved"
        evidence = builder.endpoint.evidence[0] if builder.endpoint.evidence else Evidence(relative_path(builder.repository, builder.source.file), kind="controller")
        unresolved = [SemanticUnresolved("slim_php_semantic_no_supported_facts", "No supported semantic facts were reconstructed from this route.", (evidence,))]
    response_fields = sorted(builder.endpoint.response.fields if builder.endpoint.response else [])
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "semantic_status": status,
        "confidence": "confirmed" if facts else "unverified",
        "summary": _summary(builder.endpoint, reads, writes, outbound, status),
        "source_module": relative_path(builder.repository, builder.source.file),
        "tags": [f"module:{builder.source.file.stem}"],
        "request_fields": request_fields,
        "data_access": data_access,
        "auth_context": {
            "consumed_jwt_claims": sorted(builder.consumed_claims.values(), key=lambda item: str(item["claim"])),
            "produced_jwt_claims": sorted(builder.produced_claims.values(), key=lambda item: str(item["claim"])),
        },
        "local_calls": local_calls,
        "outbound_integrations": outbound,
        "conditions": conditions,
        "response_semantics": {
            "http_status_codes": sorted(builder.http_status_codes),
            "body_fields": response_fields,
            "functional_body_fields": [field for field in ("codigo", "estado", "mensaje") if field in response_fields],
        },
        "side_effects": side_effects,
        "unresolved": [{"code": item.code, "message": item.message, "evidence": [_safe_evidence(ev) for ev in item.evidence]} for item in unresolved],
        "evidence": [_safe_evidence(item) for item in sorted(builder.endpoint.evidence, key=lambda item: (item.path, item.line or 0, item.note or ""))],
    }
    if status == "partial":
        payload["semantic_partial_materiality"] = _partial_materiality(unresolved)
    return payload, unresolved


def semantic_unresolved_payload(issue: SemanticUnresolved) -> dict[str, object]:
    evidence_key = "|".join(f"{item.path}:{item.line}:{item.note or ''}" for item in issue.evidence)
    return {
        "unresolved_id": _stable_id("unresolved", "semantic-enrichment", issue.code, issue.message, evidence_key),
        "category": "schema",
        "description": f"{issue.code}: {issue.message}",
        "impact": "blocking" if issue.code != "slim_php_semantic_no_supported_facts" else "medium",
        "evidence": [_safe_evidence(item) for item in issue.evidence],
    }


def enrich_slim_php_semantics(
    repository: Path,
    endpoints: list[EndpointFinding],
    files: list[Path],
    integrations: list[IntegrationFinding],
) -> SemanticEnrichmentResult:
    enriched = copy.deepcopy(endpoints)
    exposed = [item for item in enriched if item.direction == "exposed"]
    coverage = SemanticEnrichmentCoverage(total_exposed_endpoints=len(exposed))
    routes = _extract_routes(repository, files)
    functions = _extract_function_definitions(files)
    unresolved: list[SemanticUnresolved] = []
    for endpoint in exposed:
        source = routes.get((endpoint.method, endpoint.path))
        if source is None:
            coverage.semantic_unresolved += 1
            issue = SemanticUnresolved("slim_php_semantic_route_source_missing", f"No Slim/PHP route source was found for {endpoint.method} {endpoint.path}.", tuple(endpoint.evidence))
            endpoint.behavior = {
                "schema_version": "1.0",
                "semantic_status": "unresolved",
                "confidence": "unverified",
                "summary": f"{endpoint.method} {endpoint.path} semantic source unresolved",
                "source_module": None,
                "semantic_partial_materiality": "unknown",
                "tags": ["module:unknown"],
                "request_fields": [],
                "data_access": [],
                "auth_context": {"consumed_jwt_claims": [], "produced_jwt_claims": []},
                "local_calls": [],
                "outbound_integrations": [],
                "conditions": [],
                "response_semantics": {"http_status_codes": [], "body_fields": [], "functional_body_fields": []},
                "side_effects": [],
                "unresolved": [{"code": issue.code, "message": issue.message, "evidence": [_safe_evidence(item) for item in issue.evidence]}],
                "evidence": [_safe_evidence(item) for item in endpoint.evidence],
            }
            unresolved.append(issue)
            continue
        coverage.semantic_analysis_attempted += 1
        builder = _Builder(repository, endpoint, source)
        _analyze(builder, _ctx(source), functions, ())
        _record_discovery_integrations(builder, integrations)
        behavior, endpoint_unresolved = _behavior(builder)
        endpoint.behavior = behavior
        unresolved.extend(endpoint_unresolved)
        status = str(behavior["semantic_status"])
        if status == "complete":
            coverage.semantic_complete += 1
        elif status == "partial":
            coverage.semantic_partial += 1
        else:
            coverage.semantic_unresolved += 1
        coverage.operations_with_non_generic_description += 1
        if behavior["data_access"]:
            coverage.operations_with_data_access_facts += 1
        auth = behavior["auth_context"]
        if isinstance(auth, dict) and (auth.get("consumed_jwt_claims") or auth.get("produced_jwt_claims")):
            coverage.operations_with_auth_context_facts += 1
        if behavior["conditions"]:
            coverage.operations_with_conditional_outcome_facts += 1
        if behavior["outbound_integrations"]:
            coverage.operations_with_outbound_integration_facts += 1
    coverage.semantic_unresolved_count = len(_dedupe_unresolved(unresolved))
    return SemanticEnrichmentResult(enriched, coverage, _dedupe_unresolved(unresolved))
