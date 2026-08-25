"""Integration-surface discovery that is deliberately separate from REST endpoints."""

from __future__ import annotations

import re
from pathlib import Path

from ..discovery_types import DiscoveryIssue, IntegrationFinding
from ..discovery_utils import line_number, read_source, relative_path
from ..models import DetectorCoverage, Evidence

SOAP_DETECTOR_ID = "soap-integration"
SOAP_DETECTOR_VERSION = "1.0.0"


def _evidence(repository: Path, path: Path, text: str, offset: int, note: str) -> Evidence:
    return Evidence(
        path=relative_path(repository, path),
        line=line_number(text, offset),
        kind="integration",
        note=note,
    )


def _literal(expression: str) -> str | None:
    match = re.fullmatch(r"\s*(?P<quote>['\"])(?P<value>.*?)(?P=quote)\s*", expression, re.DOTALL)
    return match.group("value") if match else None


def detect_soap_integrations(
    repository: Path,
    files: list[Path],
) -> tuple[list[IntegrationFinding], list[DiscoveryIssue], DetectorCoverage]:
    integrations: list[IntegrationFinding] = []
    issues: list[DiscoveryIssue] = []
    php_files = [path for path in files if path.suffix.lower() == ".php"]

    for path in php_files:
        text = read_source(path)
        if text is None or "SoapClient" not in text:
            continue

        clients: dict[str, tuple[str, int]] = {}
        for match in re.finditer(
            r"(?P<handle>\$[A-Za-z_]\w*)\s*=\s*new\s+\\?SoapClient\s*\(\s*(?P<wsdl>[^),]+)",
            text,
            re.DOTALL,
        ):
            clients[match.group("handle")] = (match.group("wsdl").strip(), match.start())

        for handle, (wsdl_expr, client_offset) in clients.items():
            operation_found = False
            escaped = re.escape(handle)
            soap_call = re.compile(
                rf"{escaped}->__soapCall\s*\(\s*(?P<operation>[^,\)]+)",
                re.DOTALL,
            )
            direct_call = re.compile(
                rf"{escaped}->(?P<operation>[A-Za-z_]\w*)\s*\(",
                re.DOTALL,
            )
            for match in soap_call.finditer(text):
                operation_found = True
                operation = _literal(match.group("operation"))
                if operation is None:
                    issues.append(
                        DiscoveryIssue(
                            code="soap_operation_unresolved",
                            message="SOAP __soapCall operation could not be resolved as a literal.",
                            detector_id=SOAP_DETECTOR_ID,
                            evidence=(_evidence(repository, path, text, match.start(), "dynamic SOAP operation"),),
                        )
                    )
                    continue
                integrations.append(
                    IntegrationFinding(
                        type="soap",
                        direction="consumed",
                        confidence="confirmed" if _literal(wsdl_expr) else "probable",
                        confidence_reason="SOAP client operation found; WSDL expression is preserved separately.",
                        wsdl=_literal(wsdl_expr) or wsdl_expr,
                        operation=operation,
                        evidence=[
                            _evidence(repository, path, text, match.start(), "SOAP operation"),
                            _evidence(repository, path, text, client_offset, "SOAP WSDL expression"),
                        ],
                        notes=["SOAP is not represented as a REST endpoint."],
                    )
                )
            for match in direct_call.finditer(text):
                operation = match.group("operation")
                if operation == "__soapCall":
                    continue
                operation_found = True
                integrations.append(
                    IntegrationFinding(
                        type="soap",
                        direction="consumed",
                        confidence="confirmed" if _literal(wsdl_expr) else "probable",
                        confidence_reason="Direct SOAP client operation found.",
                        wsdl=_literal(wsdl_expr) or wsdl_expr,
                        operation=operation,
                        evidence=[
                            _evidence(repository, path, text, match.start(), "SOAP operation"),
                            _evidence(repository, path, text, client_offset, "SOAP WSDL expression"),
                        ],
                        notes=["SOAP is not represented as a REST endpoint."],
                    )
                )
            if not operation_found:
                issues.append(
                    DiscoveryIssue(
                        code="soap_operation_unresolved",
                        message="SoapClient was found without a supported operation call.",
                        detector_id=SOAP_DETECTOR_ID,
                        evidence=(_evidence(repository, path, text, client_offset, "SOAP client"),),
                    )
                )

    issues.append(
        DiscoveryIssue(
            code="soap_contract_extraction_partial",
            message=(
                "SOAP integrations are represented separately from REST endpoints, but full WSDL "
                "contract extraction is not complete in this version."
            ),
            detector_id=SOAP_DETECTOR_ID,
        )
    )
    coverage = DetectorCoverage(
        detector_id=SOAP_DETECTOR_ID,
        detector_version=SOAP_DETECTOR_VERSION,
        category="integration",
        status="partial",
        files_scanned=len(php_files),
        supported_patterns=("PHP SoapClient WSDL expression and operation calls",),
        unsupported_patterns=tuple(sorted({issue.code for issue in issues})),
        notes=("SOAP findings are emitted as integrations, never REST endpoints.",),
    )
    return integrations, issues, coverage
