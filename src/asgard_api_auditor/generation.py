"""Generate conservative v0.5 audit artifacts from proven discovery evidence."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .artifacts import atomic_publish, sha256_file, validate_audit_set
from .constants import FINDINGS_SCHEMA_VERSION, KNOWLEDGE_SCHEMA_VERSION, OPENAPI_VERSION
from .discovery import discover_endpoints
from .discovery_types import DiscoveryIssue, EndpointDiscovery, IntegrationFinding
from .inventory import inventory_repository
from .models import AuditTarget, EndpointFinding, Evidence, TechnicalInventory
from .redaction import redact_text

_PATH_PARAMETER = re.compile(r"\{(?P<name>[A-Za-z_][A-Za-z0-9_-]*)(?::[^}]+)?\}")
_ALLOWED_FINDINGS_EVIDENCE = {
    "route",
    "controller",
    "http_client",
    "configuration",
    "test",
    "documentation",
    "runtime",
    "existing_spec",
    "webhook",
    "generated_sdk",
    "unknown",
}


def _stable_id(prefix: str, *parts: str) -> str:
    payload = "|".join(parts).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(payload).hexdigest()[:16]}"


def _audit_id(target: AuditTarget, discovery: EndpointDiscovery, soap_wsdl: dict[str, Path]) -> str:
    scope = [
        discovery.repository_id,
        discovery.source_commit,
        __version__,
        *sorted(target.exclude_paths),
        *(f"{key}={value.as_posix()}" for key, value in sorted(soap_wsdl.items())),
    ]
    return _stable_id("audit", *scope)


def _safe_evidence(evidence: Evidence) -> dict[str, object]:
    kind = evidence.kind if evidence.kind in _ALLOWED_FINDINGS_EVIDENCE else "unknown"
    payload: dict[str, object] = {"path": evidence.path, "kind": kind}
    if evidence.line is not None:
        payload["line"] = evidence.line
    if evidence.end_line is not None:
        payload["end_line"] = evidence.end_line
    if evidence.symbol is not None:
        payload["symbol"] = evidence.symbol
    if evidence.note is not None:
        payload["note"] = evidence.note
    return payload


def _endpoint_payload(endpoint: EndpointFinding) -> dict[str, object]:
    payload: dict[str, object] = {
        "endpoint_id": endpoint.endpoint_id,
        "direction": endpoint.direction,
        "surface_type": "http",
        "method": endpoint.method,
        "path": endpoint.path,
        "confidence": endpoint.confidence,
        "confidence_reason": endpoint.confidence_reason,
        "evidence": [_safe_evidence(item) for item in endpoint.evidence],
        "notes": list(endpoint.notes),
    }
    optional = {
        "base_url": endpoint.base_url,
        "api_id": endpoint.api_id,
        "api_name": endpoint.api_name,
        "provider_repository": endpoint.provider_repository,
        "consumer_repository": endpoint.consumer_repository,
        "handler": endpoint.handler,
        "authentication": endpoint.authentication,
        "authorization": endpoint.authorization,
    }
    for key, value in optional.items():
        if value is not None:
            payload[key] = value
    if endpoint.request is not None:
        payload["request"] = asdict(endpoint.request)
    if endpoint.response is not None:
        payload["response"] = asdict(endpoint.response)
    return payload


def _integration_payload(item: IntegrationFinding) -> dict[str, object]:
    description_parts = [f"{item.type.upper()} integration"]
    if item.operation:
        description_parts.append(f"operation {item.operation}")
    if item.service_expression:
        description_parts.append(f"service expression {item.service_expression}")
    if item.contract_status:
        description_parts.append(f"contract status {item.contract_status}")
    notes = list(item.notes)
    if item.defined_in_wsdl is not None:
        notes.append(f"defined_in_wsdl={str(item.defined_in_wsdl).lower()}")
    if item.service:
        notes.append(f"service={item.service}")
    if item.port:
        notes.append(f"port={item.port}")
    if item.binding:
        notes.append(f"binding={item.binding}")
    surface_id = _stable_id(
        "surface",
        item.type,
        item.direction,
        item.service_expression or item.wsdl or "",
        item.operation or "",
    )
    return {
        "surface_id": surface_id,
        "type": item.type,
        "status": "confirmed" if item.confidence == "confirmed" else item.confidence,
        "direction": item.direction,
        "confidence": item.confidence,
        "description": "; ".join(description_parts),
        "evidence": [_safe_evidence(evidence) for evidence in item.evidence],
        "notes": notes,
    }


def _issue_category(issue: DiscoveryIssue) -> str:
    code = issue.code.lower()
    if "url" in code:
        return "dynamic_url"
    if "soap" in code or "schema" in code or "contract" in code:
        return "schema"
    if "consumer" in code:
        return "consumer"
    if "provider" in code:
        return "provider"
    return "coverage"


def _unresolved_payload(issue: DiscoveryIssue) -> dict[str, object]:
    return {
        "unresolved_id": _stable_id("unresolved", issue.detector_id, issue.code, issue.message),
        "category": _issue_category(issue),
        "description": f"{issue.code}: {issue.message}",
        "impact": "blocking" if issue.severity == "blocking" else "low",
        "evidence": [_safe_evidence(item) for item in issue.evidence],
    }


def _front_matter(audit_id: str, discovery: EndpointDiscovery) -> str:
    return "\n".join(
        [
            "---",
            f'audit_id: "{audit_id}"',
            f'auditor_version: "{__version__}"',
            f'repository: "{discovery.repository}"',
            f'source_ref: "{discovery.source_ref}"',
            f'source_commit: "{discovery.source_commit}"',
            "---",
            "",
        ]
    )


def _evidence_label(endpoint: EndpointFinding) -> str:
    parts: list[str] = []
    for item in endpoint.evidence:
        suffix = f":{item.line}" if item.line is not None else ""
        parts.append(f"{item.path}{suffix}")
    return ", ".join(parts)


def _render_knowledge(audit_id: str, discovery: EndpointDiscovery) -> str:
    exposed = [item for item in discovery.endpoints if item.direction == "exposed"]
    consumed = [item for item in discovery.endpoints if item.direction == "consumed"]
    lines = [
        _front_matter(audit_id, discovery).rstrip(),
        "",
        "# API Knowledge",
        "",
        f"Knowledge schema: `{KNOWLEDGE_SCHEMA_VERSION}`",
        "",
        "This document is generated from source evidence. Unknown request/response/authentication details are not inferred.",
        "",
        "## Summary",
        "",
        f"- HTTP exposed: **{len(exposed)}**",
        f"- HTTP consumed: **{len(consumed)}**",
        f"- Integration findings: **{len(discovery.integrations)}**",
        f"- Discovery complete: **{str(discovery.discovery_complete).lower()}**",
        "",
        "## Exposed HTTP",
        "",
    ]
    if not exposed:
        lines.append("No exposed HTTP endpoints were proven.")
    for item in exposed:
        lines.extend(
            [
                f"### `{item.method} {item.path}`",
                "",
                f"- Endpoint ID: `{item.endpoint_id}`",
                f"- Confidence: `{item.confidence}`",
                f"- Evidence: {_evidence_label(item) or 'n/a'}",
                "- Contract enrichment: `pending`",
                "",
            ]
        )
    lines.extend(["## Consumed HTTP", ""])
    if not consumed:
        lines.append("No consumed HTTP endpoints were proven.")
    for item in consumed:
        base = f"{item.base_url or ''}{item.path}"
        lines.extend(
            [
                f"### `{item.method} {base}`",
                "",
                f"- Endpoint ID: `{item.endpoint_id}`",
                f"- Confidence: `{item.confidence}`",
                f"- Evidence: {_evidence_label(item) or 'n/a'}",
                "",
            ]
        )
    lines.extend(["## Integration surfaces", ""])
    if not discovery.integrations:
        lines.append("No non-HTTP integration operations were proven.")
    for item in discovery.integrations:
        label = item.operation or item.type
        lines.extend(
            [
                f"### `{item.type.upper()} {label}`",
                "",
                f"- Direction: `{item.direction}`",
                f"- Service expression: `{item.service_expression or 'n/a'}`",
                f"- WSDL/contract: `{item.wsdl or 'n/a'}`",
                f"- Contract status: `{item.contract_status or 'n/a'}`",
                f"- Defined in WSDL: `{item.defined_in_wsdl}`",
                "",
            ]
        )
    lines.extend(["## Unresolved", ""])
    if not discovery.unresolved:
        lines.append("No discovery-level unresolved findings.")
    for issue in discovery.unresolved:
        lines.append(f"- **{issue.code}** — {issue.message}")
    lines.extend(
        [
            "",
            "## v0.5 limitation",
            "",
            "Request schemas, response schemas, authentication and authorization are not yet reconstructed. This artifact must not be treated as a complete behavioral API contract.",
            "",
        ]
    )
    return redact_text("\n".join(lines))


def _render_report(audit_id: str, discovery: EndpointDiscovery) -> str:
    exposed = sum(1 for item in discovery.endpoints if item.direction == "exposed")
    consumed = sum(1 for item in discovery.endpoints if item.direction == "consumed")
    lines = [
        _front_matter(audit_id, discovery).rstrip(),
        "",
        "# API Audit Report",
        "",
        "## Verdict",
        "",
        "**PARTIAL** — structural API discovery artifacts were generated and validated, but request/response/security contract enrichment is not implemented in v0.5.0.",
        "",
        "## Proven surface",
        "",
        f"- Exposed HTTP endpoints: **{exposed}**",
        f"- Consumed HTTP endpoints: **{consumed}**",
        f"- Integration findings: **{len(discovery.integrations)}**",
        f"- Discovery complete: **{str(discovery.discovery_complete).lower()}**",
        "",
        "## Blocking work before full audit completion",
        "",
        "- Reconstruct request parameters and bodies.",
        "- Reconstruct response status codes, schemas and fields.",
        "- Reconstruct authentication and authorization evidence.",
    ]
    if discovery.unresolved:
        lines.append("- Resolve discovery-level blocking findings listed below.")
        lines.extend(f"  - `{item.code}`: {item.message}" for item in discovery.unresolved)
    lines.extend(
        [
            "",
            "## OpenAPI semantics",
            "",
            "The generated OpenAPI describes only proven exposed HTTP paths/methods. Unknown payload and response schemas are intentionally not invented.",
            "",
        ]
    )
    return redact_text("\n".join(lines))


def _operation_id(endpoint: EndpointFinding) -> str:
    return f"{endpoint.method.lower()}_{hashlib.sha256(endpoint.endpoint_id.encode()).hexdigest()[:12]}"


def _render_openapi(audit_id: str, discovery: EndpointDiscovery) -> str:
    exposed = [item for item in discovery.endpoints if item.direction == "exposed"]
    by_path: dict[str, list[EndpointFinding]] = {}
    for item in exposed:
        by_path.setdefault(item.path, []).append(item)

    lines = [
        f"openapi: {OPENAPI_VERSION}",
        "info:",
        f"  title: {json.dumps(discovery.repository_id + ' discovered API')}",
        f"  version: {json.dumps(discovery.source_commit[:12])}",
        "  description: \"Structural OpenAPI generated from source evidence; request/response/security enrichment is pending.\"",
        f'x-asgard-audit-id: "{audit_id}"',
        f'x-asgard-source-commit: "{discovery.source_commit}"',
        "x-asgard-contract-enrichment: partial",
        "paths:",
    ]
    if not by_path:
        lines[-1] = "paths: {}"
        return redact_text("\n".join(lines) + "\n")

    for path in sorted(by_path):
        lines.append(f"  {json.dumps(path)}:")
        for endpoint in sorted(by_path[path], key=lambda item: item.method):
            lines.extend(
                [
                    f"    {endpoint.method.lower()}:",
                    f"      operationId: {json.dumps(_operation_id(endpoint))}",
                    f"      summary: {json.dumps(endpoint.method + ' ' + endpoint.path)}",
                    "      description: \"Discovered from source. Request/response/authentication details are not yet reconstructed.\"",
                    f"      x-asgard-endpoint-id: {json.dumps(endpoint.endpoint_id)}",
                    f"      x-asgard-confidence: {json.dumps(endpoint.confidence)}",
                ]
            )
            evidence = [
                f"{item.path}:{item.line}" if item.line is not None else item.path
                for item in endpoint.evidence
            ]
            if evidence:
                lines.append("      x-asgard-evidence:")
                lines.extend(f"        - {json.dumps(value)}" for value in evidence)
            parameters = sorted(set(_PATH_PARAMETER.findall(endpoint.path)))
            if parameters:
                lines.append("      parameters:")
                for name in parameters:
                    lines.extend(
                        [
                            f"        - name: {json.dumps(name)}",
                            "          in: path",
                            "          required: true",
                            "          schema:",
                            "            type: string",
                        ]
                    )
            lines.extend(
                [
                    "      responses:",
                    "        default:",
                    "          description: \"Response contract not yet reconstructed from source evidence.\"",
                ]
            )
    return redact_text("\n".join(lines) + "\n")


def _findings(
    audit_id: str,
    inventory: TechnicalInventory,
    discovery: EndpointDiscovery,
    artifact_hashes: dict[str, str],
) -> dict[str, object]:
    unresolved = [_unresolved_payload(item) for item in discovery.unresolved]
    unresolved.append(
        {
            "unresolved_id": "contract-enrichment-v0.5.0",
            "category": "schema",
            "description": (
                "Request/response/authentication/authorization contract enrichment is pending; "
                "v0.5.0 OpenAPI is structural and cannot represent the full behavioral contract."
            ),
            "impact": "blocking",
            "evidence": [],
        }
    )
    unsupported_surfaces = sorted(
        item.name for item in inventory.integration_surfaces if item.name != "soap"
    )
    return {
        "schema_version": FINDINGS_SCHEMA_VERSION,
        "audit_id": audit_id,
        "auditor_version": __version__,
        "repository": discovery.repository,
        "repository_id": discovery.repository_id,
        "source_ref": discovery.source_ref,
        "source_commit": discovery.source_commit,
        "audit_timestamp": datetime.now(UTC).isoformat(),
        "status": "partial",
        "coverage": {
            "inventory_complete": inventory.inventory_complete,
            "languages": sorted(item.name for item in inventory.languages),
            "frameworks": sorted(item.name for item in inventory.frameworks),
            "http_clients": sorted(item.name for item in inventory.http_clients),
            "required_detector_categories": list(inventory.required_detector_categories),
            "detectors": [asdict(item) for item in discovery.detectors],
            "files_scanned": inventory.files_scanned,
            "files_excluded": 0,
            "exclusion_rules": list(inventory.excluded_roots),
            "unsupported_surfaces": unsupported_surfaces,
            "notes": [
                "Exact excluded-file count is not tracked in technical inventory v1.0.",
                "Audit status remains partial until contract enrichment is implemented.",
            ],
        },
        "endpoints": [_endpoint_payload(item) for item in discovery.endpoints],
        "integration_surfaces": [_integration_payload(item) for item in discovery.integrations],
        "unresolved": unresolved,
        "artifacts": {
            name: {"status": "validated", "sha256": digest, "validation": "validate_audit_set"}
            for name, digest in artifact_hashes.items()
        },
        "notes": [
            "Generated from deterministic source discovery.",
            "Consumed HTTP calls are retained in findings/knowledge but are not emitted as OpenAPI paths.",
            "SOAP is retained as a non-REST integration surface.",
        ],
    }


def generate_audit(
    target: AuditTarget,
    *,
    allow_dirty: bool = False,
    soap_wsdl: dict[str, Path] | None = None,
) -> tuple[Path, dict[str, object]]:
    """Generate and atomically publish the four primary audit artifacts."""

    mappings = soap_wsdl or {}
    inventory = inventory_repository(target, allow_dirty=allow_dirty)
    discovery = discover_endpoints(target, allow_dirty=allow_dirty, soap_wsdl=mappings)
    audit_id = _audit_id(target, discovery, mappings)
    destination = target.output.resolve()

    with tempfile.TemporaryDirectory(prefix="asgard-api-audit-") as temporary:
        staging = Path(temporary)
        openapi_path = staging / "openapi.yaml"
        knowledge_path = staging / "api-knowledge.md"
        report_path = staging / "audit-report.md"
        findings_path = staging / "findings.json"

        openapi_path.write_text(_render_openapi(audit_id, discovery), encoding="utf-8")
        knowledge_path.write_text(_render_knowledge(audit_id, discovery), encoding="utf-8")
        report_path.write_text(_render_report(audit_id, discovery), encoding="utf-8")

        hashes = {
            "openapi.yaml": sha256_file(openapi_path),
            "api-knowledge.md": sha256_file(knowledge_path),
            "audit-report.md": sha256_file(report_path),
        }
        findings = _findings(audit_id, inventory, discovery, hashes)
        findings_text = redact_text(json.dumps(findings, indent=2, sort_keys=True) + "\n")
        findings_path.write_text(findings_text, encoding="utf-8")

        validate_audit_set(staging)
        atomic_publish(staging, destination)

    return destination, findings


__all__ = ["generate_audit"]
