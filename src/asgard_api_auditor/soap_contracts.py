"""Explicit, reproducible SOAP WSDL snapshot enrichment."""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from .detectors.integrations import SOAP_DETECTOR_ID, SOAP_DETECTOR_VERSION
from .discovery_types import DiscoveryIssue, IntegrationFinding
from .models import DetectorCoverage

_PARSED_STATUSES = {"local_parsed", "provided_snapshot_parsed"}


def _message_name(value: str | None) -> str | None:
    if value is None:
        return None
    return value.rsplit(":", 1)[-1]


def _parse_wsdl(path: Path) -> dict[str, dict[str, str | None]] | None:
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8"))
    except (OSError, ET.ParseError, UnicodeDecodeError):
        return None

    namespace = {"wsdl": "http://schemas.xmlsoap.org/wsdl/"}
    messages = {
        item.attrib["name"]
        for item in root.findall("wsdl:message", namespace)
        if item.attrib.get("name")
    }

    port_type_ops: dict[str, tuple[str | None, str | None]] = {}
    for operation in root.findall(".//wsdl:portType/wsdl:operation", namespace):
        name = operation.attrib.get("name")
        if not name:
            continue
        input_message = operation.find("wsdl:input", namespace)
        output_message = operation.find("wsdl:output", namespace)
        port_type_ops[name] = (
            input_message.attrib.get("message") if input_message is not None else None,
            output_message.attrib.get("message") if output_message is not None else None,
        )

    binding_by_operation: dict[str, str | None] = {}
    for binding in root.findall("wsdl:binding", namespace):
        binding_name = binding.attrib.get("name")
        for operation in binding.findall("wsdl:operation", namespace):
            name = operation.attrib.get("name")
            if name:
                binding_by_operation[name] = binding_name

    service_name: str | None = None
    port_name: str | None = None
    for service in root.findall("wsdl:service", namespace):
        service_name = service.attrib.get("name")
        port = service.find("wsdl:port", namespace)
        if port is not None:
            port_name = port.attrib.get("name")
        break

    operations: dict[str, dict[str, str | None]] = {}
    for name, (input_message, output_message) in port_type_ops.items():
        operations[name] = {
            "service": service_name,
            "port": port_name,
            "binding": binding_by_operation.get(name),
            "input_message": input_message if _message_name(input_message) in messages else input_message,
            "output_message": output_message if _message_name(output_message) in messages else output_message,
        }
    return operations


def _tracked_snapshot(repository: Path, configured: Path) -> tuple[Path | None, str, str | None]:
    repository = repository.resolve()
    candidate = configured if configured.is_absolute() else repository / configured
    candidate = candidate.resolve()
    try:
        relative = candidate.relative_to(repository)
    except ValueError:
        return None, "provided_snapshot_outside_repository", None

    relative_text = relative.as_posix()
    if not candidate.is_file():
        return None, "provided_snapshot_missing", relative_text

    tracked = subprocess.run(
        ["git", "-C", str(repository), "ls-files", "--error-unmatch", "--", relative_text],
        check=False,
        capture_output=True,
        text=True,
    )
    if tracked.returncode != 0:
        return None, "provided_snapshot_untracked", relative_text

    contract = _parse_wsdl(candidate)
    if contract is None:
        return None, "provided_snapshot_invalid", relative_text
    if not contract:
        return candidate, "provided_snapshot_empty", relative_text
    return candidate, "provided_snapshot_parsed", relative_text


def _mapping_for(
    item: IntegrationFinding,
    mappings: dict[str, Path],
) -> Path | None:
    candidates = (item.service_expression, item.service_value, item.wsdl)
    for candidate in candidates:
        if candidate and candidate in mappings:
            return mappings[candidate]
    return None


def _snapshot_issue_code(status: str) -> str:
    return {
        "provided_snapshot_outside_repository": "soap_wsdl_snapshot_outside_repository",
        "provided_snapshot_missing": "soap_wsdl_snapshot_missing",
        "provided_snapshot_untracked": "soap_wsdl_snapshot_untracked",
        "provided_snapshot_invalid": "soap_wsdl_snapshot_invalid",
        "provided_snapshot_empty": "soap_wsdl_snapshot_empty",
    }.get(status, "soap_wsdl_snapshot_unresolved")


def apply_soap_wsdl_snapshots(
    repository: Path,
    integrations: list[IntegrationFinding],
    issues: list[DiscoveryIssue],
    coverage: DetectorCoverage,
    soap_operations_complete: bool,
    mappings: dict[str, Path] | None,
) -> tuple[list[DiscoveryIssue], DetectorCoverage, bool]:
    """Apply explicit service-expression -> versioned WSDL mappings without network access."""

    if not mappings:
        soap_contracts_complete = bool(integrations) and all(
            item.contract_status in _PARSED_STATUSES and item.defined_in_wsdl is not False
            for item in integrations
            if item.type == "soap"
        )
        return issues, coverage, soap_contracts_complete

    soap_items = [item for item in integrations if item.type == "soap"]
    new_issues = [item for item in issues if item.code != "soap_contract_extraction_partial"]
    cache: dict[Path, tuple[Path | None, str, str | None, dict[str, dict[str, str | None]] | None]] = {}

    for item in soap_items:
        configured = _mapping_for(item, mappings)
        if configured is None:
            continue

        cached = cache.get(configured)
        if cached is None:
            snapshot, status, relative = _tracked_snapshot(repository, configured)
            contract = _parse_wsdl(snapshot) if snapshot is not None and status == "provided_snapshot_parsed" else None
            cached = (snapshot, status, relative, contract)
            cache[configured] = cached
        snapshot, status, relative, contract = cached

        item.contract_status = status
        if relative is not None:
            item.wsdl = relative
        item.notes.append("SOAP contract supplied explicitly as a local versioned WSDL snapshot.")

        if status != "provided_snapshot_parsed" or snapshot is None or contract is None:
            item.defined_in_wsdl = None
            evidence = tuple(item.evidence[:1])
            new_issues.append(
                DiscoveryIssue(
                    code=_snapshot_issue_code(status),
                    message=(
                        f"SOAP WSDL snapshot for '{item.service_expression or item.wsdl}' could not be "
                        f"used reproducibly ({status})."
                    ),
                    detector_id=SOAP_DETECTOR_ID,
                    evidence=evidence,
                )
            )
            continue

        operation_contract = contract.get(item.operation or "")
        item.defined_in_wsdl = operation_contract is not None
        if operation_contract is None:
            new_issues.append(
                DiscoveryIssue(
                    code="soap_operation_not_in_wsdl",
                    message=(
                        f"SOAP operation '{item.operation}' is used by code but is not defined in "
                        f"the supplied WSDL snapshot '{relative}'."
                    ),
                    detector_id=SOAP_DETECTOR_ID,
                    evidence=tuple(item.evidence),
                )
            )
            continue

        item.service = operation_contract.get("service")
        item.port = operation_contract.get("port")
        item.binding = operation_contract.get("binding")
        item.input_message = operation_contract.get("input_message")
        item.output_message = operation_contract.get("output_message")

    soap_contracts_complete = bool(soap_items) and all(
        item.contract_status in _PARSED_STATUSES and item.defined_in_wsdl is not False
        for item in soap_items
    )

    if not soap_contracts_complete:
        new_issues.append(
            DiscoveryIssue(
                code="soap_contract_extraction_partial",
                message=(
                    "SOAP operations are represented separately from REST endpoints, but one or more "
                    "SOAP contracts are not available as reproducible local WSDL snapshots."
                ),
                detector_id=SOAP_DETECTOR_ID,
            )
        )

    soap_issue_codes = {
        item.code for item in new_issues if item.detector_id == SOAP_DETECTOR_ID
    }
    updated_coverage = DetectorCoverage(
        detector_id=coverage.detector_id,
        detector_version=SOAP_DETECTOR_VERSION,
        category=coverage.category,
        status="supported" if soap_operations_complete and soap_contracts_complete else "partial",
        files_scanned=coverage.files_scanned,
        supported_patterns=tuple(
            sorted(set(coverage.supported_patterns) | {"explicit versioned WSDL snapshot mapping"})
        ),
        unsupported_patterns=tuple(sorted(soap_issue_codes)),
        notes=tuple(
            note
            for note in coverage.notes
            if not note.startswith("soap_contracts_complete=")
        )
        + (f"soap_contracts_complete={str(soap_contracts_complete).lower()}",),
    )
    return new_issues, updated_coverage, soap_contracts_complete


__all__ = ["apply_soap_wsdl_snapshots"]
