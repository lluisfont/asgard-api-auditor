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
_REQUEST_ROOT = re.compile(r"(?P<var>\$[A-Za-z_]\w*)\s*=\s*json_decode\s*\(\s*(?:\(\s*string\s*\)\s*)?\$request->getBody\s*\(\s*\)\s*,\s*true\s*\)", re.IGNORECASE | re.DOTALL)
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
_CURL = re.compile(r"\bcurl_(?:init|setopt|setopt_array|exec)\s*\(", re.IGNORECASE)
_SOAP = re.compile(r"\bnew\s+SoapClient\s*\(|->__soapCall\s*\(", re.IGNORECASE)
_HTTP_LITERAL = re.compile(r"['\"](?P<url>https?://[^'\"]+)['\"]", re.IGNORECASE)
_FILE = re.compile(r"\b(file_put_contents|move_uploaded_file|unlink|fopen)\s*\(", re.IGNORECASE)
_MAIL = re.compile(r"\b(mail|PHPMailer)\s*\(", re.IGNORECASE)
_SELECT = re.compile(r"\b(?:FROM|JOIN)\s+([`\"']?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?[`\"']?)", re.IGNORECASE)
_INSERT = re.compile(r"\bINSERT\s+INTO\s+([`\"']?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?[`\"']?)", re.IGNORECASE)
_UPDATE = re.compile(r"\bUPDATE\s+([`\"']?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?[`\"']?)", re.IGNORECASE)
_DELETE = re.compile(r"\bDELETE\s+FROM\s+([`\"']?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?[`\"']?)", re.IGNORECASE)
_CALL = re.compile(r"\bCALL\s+([`\"']?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?[`\"']?)", re.IGNORECASE)


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


def _ctx(source: _RouteSource | _FunctionSource) -> _Context:
    return _Context(source, source.body, source.body_start, source.file, source.text)


def _ev(repository: Path, ctx: _Context, offset: int, note: str) -> Evidence:
    return _evidence(repository, ctx.file, ctx.text, ctx.body_start + offset, note)


def _unresolved(builder: _Builder, code: str, message: str, evidence: Evidence) -> None:
    builder.unresolved.append(SemanticUnresolved(code, message, (evidence,)))


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
    fields = sorted({field for variable, field in field_vars.items() if re.search(rf"\b{re.escape(variable)}\b", expr)})
    return " ".join(parts), fields, dynamic


def _field_vars(body: str) -> dict[str, str]:
    roots = {match.group("var") for match in _REQUEST_ROOT.finditer(body)}
    return {
        match.group("var"): match.group("field")
        for match in _REQUEST_FIELD_ASSIGN.finditer(body)
        if match.group("root") in roots
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
            if _SQL_KEYWORD.search(statement) is None:
                continue
            reassigned_append = re.match(
                rf"\s*{re.escape(match.group('var'))}\s*\.\s*(?P<tail>.+)\s*$",
                match.group("expr"),
                re.DOTALL,
            )
            if reassigned_append is not None:
                literal, fields, dynamic = _literal(reassigned_append.group("tail"), field_vars)
                if literal:
                    previous_sql, previous_fields, previous_dynamic = values.get(match.group("var"), ("", [], False))
                    values[match.group("var")] = (
                        f"{previous_sql} {literal}".strip(),
                        sorted(set(previous_fields + fields)),
                        previous_dynamic or dynamic,
                    )
                continue
            literal, fields, dynamic = _literal(match.group("expr"), field_vars)
            if literal:
                values[match.group("var")] = (literal, fields, dynamic)
            continue
        match = _SQL_APPEND.search(statement)
        if match is None:
            continue
        if _SQL_KEYWORD.search(statement) is None:
            continue
        literal, fields, dynamic = _literal(match.group("expr"), field_vars)
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


def _sql_targets(statement: str) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for match in _SELECT.finditer(statement):
        prefix = statement[max(0, match.start() - 32) : match.start()].upper()
        if any(marker in prefix for marker in ("LEADING", "TRAILING", "BOTH")):
            continue
        result.append(("SELECT", _clean(match.group(1))))
    for regex, operation in ((_INSERT, "INSERT"), (_UPDATE, "UPDATE"), (_DELETE, "DELETE"), (_CALL, "CALL")):
        match = regex.search(statement)
        if match is not None:
            result.append((operation, _clean(match.group(1))))
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
            sql, source_fields, dynamic = _literal(expr, field_vars)
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
    return result


def _record_conditions(builder: _Builder, ctx: _Context) -> None:
    for condition, block, offset in _conditions(ctx.body):
        fields = [{"field": match.group("field"), "expression": match.group("expr").strip()} for match in _BODY_FIELD.finditer(block)]
        if fields:
            evidence = _ev(builder.repository, ctx, offset, "conditional response body fields")
            builder.conditions.append(
                {
                    "id": _stable_id("sem-condition", builder.endpoint.endpoint_id, evidence.path, evidence.line, condition),
                    "condition": condition,
                    "body_fields": sorted(fields, key=lambda item: str(item["field"])),
                    "evidence": [_safe_evidence(evidence)],
                }
            )


def _record_outbound(builder: _Builder, ctx: _Context) -> None:
    for regex, kind, note in ((_CURL, "http", "outbound HTTP client call"), (_SOAP, "soap", "SOAP client call")):
        for match in regex.finditer(ctx.body):
            evidence = _ev(builder.repository, ctx, match.start(), note)
            url_match = _HTTP_LITERAL.search(ctx.body[match.start() : match.start() + 500])
            target = url_match.group("url") if url_match is not None else None
            entry = {
                "id": _stable_id("sem-outbound", builder.endpoint.endpoint_id, kind, evidence.path, evidence.line),
                "type": kind,
                "target": target,
                "evidence": [_safe_evidence(evidence)],
            }
            builder.outbound.append(entry)
            builder.side_effects.append({**entry, "type": "outbound_integration", "integration_type": kind})
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


def _analyze(builder: _Builder, ctx: _Context, functions: dict[str, list[_FunctionSource]], stack: tuple[str, ...]) -> None:
    _record_sql(builder, ctx)
    _record_jwt(builder, ctx)
    _record_conditions(builder, ctx)
    for match in _WITH_STATUS.finditer(ctx.body):
        builder.http_status_codes.add(int(match.group("status")))
    _record_outbound(builder, ctx)
    if len(stack) >= 4:
        _unresolved(builder, "slim_php_semantic_helper_depth_limit", "Local helper propagation reached the deterministic depth limit.", _ev(builder.repository, ctx, 0, "helper propagation depth limit"))
        return
    for name, _args, offset in _function_calls(ctx.body):
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


def _behavior(builder: _Builder) -> tuple[dict[str, object], list[SemanticUnresolved]]:
    data_access = _dedupe_dicts(builder.data_access)
    outbound = _dedupe_dicts(builder.outbound)
    side_effects = _dedupe_dicts(builder.side_effects)
    local_calls = _dedupe_dicts(builder.local_calls)
    conditions = _dedupe_dicts(builder.conditions)
    unresolved = _dedupe_unresolved(builder.unresolved)
    reads = sorted({str(item["resource"]) for item in data_access if item.get("operation") == "SELECT"})
    writes = sorted({str(item["resource"]) for item in data_access if item.get("operation") in {"INSERT", "UPDATE", "DELETE", "CALL"}})
    facts = bool(data_access or outbound or side_effects or local_calls or conditions or builder.consumed_claims or builder.produced_claims)
    if unresolved:
        status = "partial" if facts else "unresolved"
    elif facts:
        status = "complete"
    else:
        status = "unresolved"
        evidence = builder.endpoint.evidence[0] if builder.endpoint.evidence else Evidence(relative_path(builder.repository, builder.source.file), kind="controller")
        unresolved = [SemanticUnresolved("slim_php_semantic_no_supported_facts", "No supported semantic facts were reconstructed from this route.", (evidence,))]
    response_fields = sorted(builder.endpoint.response.fields if builder.endpoint.response else [])
    return {
        "schema_version": "1.0",
        "semantic_status": status,
        "confidence": "confirmed" if facts else "unverified",
        "summary": _summary(builder.endpoint, reads, writes, outbound, status),
        "source_module": relative_path(builder.repository, builder.source.file),
        "tags": [f"module:{builder.source.file.stem}"],
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
    }, unresolved


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
                "tags": ["module:unknown"],
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
