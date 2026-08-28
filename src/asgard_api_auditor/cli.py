from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .api_compatibility import ApiCompatibilityError, write_api_compatibility
from .catalog import CatalogError, write_api_catalog
from .correlation import CorrelationError, correlate_findings
from .consumer_compatibility import ConsumerCompatibilityError, write_consumer_compatibility
from .discovery import discover_endpoints, discovery_to_dict
from .generation import generate_audit
from .inventory import InventoryError, inventory_repository, inventory_to_dict
from .models import AuditTarget


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="asgard-api-auditor",
        description="Audit ASGARD repositories for exposed and consumed APIs.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    inventory = subparsers.add_parser("inventory", help="Inventory repository technologies and integration surfaces.")
    inventory.add_argument("repository", type=Path, help="Local Git repository root")
    inventory.add_argument("--ref", default="HEAD", help="Git ref; it must resolve to checked-out HEAD")
    inventory.add_argument("--repository-id", help="Stable logical repository ID")
    inventory.add_argument("--output", type=Path, help="Optional JSON output file")
    inventory.add_argument("--allow-dirty", action="store_true", help="Allow diagnostic scan of dirty tree")
    inventory.add_argument("--exclude-path", action="append", help="Repository-relative path to exclude; may be repeated")

    discover = subparsers.add_parser("discover", help="Discover exposed and consumed HTTP endpoints")
    discover.add_argument("repository", type=Path, help="Local Git repository root")
    discover.add_argument("--ref", default="HEAD", help="Git ref; it must resolve to checked-out HEAD")
    discover.add_argument("--repository-id", help="Stable logical repository ID")
    discover.add_argument("--output", type=Path, help="Optional JSON output file")
    discover.add_argument("--allow-dirty", action="store_true", help="Allow diagnostic discovery on dirty tree")
    discover.add_argument("--exclude-path", action="append", help="Repository-relative path to exclude; may be repeated")
    discover.add_argument(
        "--soap-wsdl",
        action="append",
        metavar="SERVICE=PATH",
        help=(
            "Map a SOAP service expression/value to a versioned repository-local WSDL snapshot; "
            "may be repeated"
        ),
    )

    audit = subparsers.add_parser("audit", help="Generate the audit artifact set")
    audit.add_argument("repository", type=Path, help="Local Git repository root")
    audit.add_argument("--ref", default="HEAD", help="Git ref; it must resolve to checked-out HEAD")
    audit.add_argument("--repository-id", help="Stable logical repository ID")
    audit.add_argument("--output", type=Path, default=Path("output"), help="Output directory")
    audit.add_argument("--allow-dirty", action="store_true", help="Allow diagnostic audit of dirty tree")
    audit.add_argument("--exclude-path", action="append", help="Repository-relative path to exclude; may be repeated")
    audit.add_argument(
        "--require-correlation",
        action="store_true",
        help="Fail closed unless provider/consumer correlation can be evaluated for consumed endpoints.",
    )
    audit.add_argument(
        "--soap-wsdl",
        action="append",
        metavar="SERVICE=PATH",
        help=(
            "Map a SOAP service expression/value to a versioned repository-local WSDL snapshot; "
            "may be repeated"
        ),
    )

    correlate = subparsers.add_parser(
        "correlate",
        help="Correlate consumed HTTP endpoints with provider candidates from findings artifacts.",
    )
    correlate.add_argument(
        "--findings",
        action="append",
        type=Path,
        required=True,
        help="Path to a findings.json artifact; may be repeated",
    )
    correlate.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output directory for correlations.json and api-relations.md",
    )

    catalog = subparsers.add_parser(
        "catalog-api",
        help="Build a canonical API catalog from a findings.json artifact.",
    )
    catalog.add_argument("--findings", type=Path, required=True, help="Path to findings.json")
    catalog.add_argument("--output", type=Path, required=True, help="Output api-catalog.json path")
    catalog.add_argument(
        "--stable-namespace",
        help="Explicit stable namespace for endpoint identity when required by the caller.",
    )
    catalog.add_argument("--include-endpoint", action="append", help="Endpoint selector to include")
    catalog.add_argument("--exclude-endpoint", action="append", help="Endpoint selector to exclude")

    compare = subparsers.add_parser(
        "compare-api",
        help="Compare reference and candidate API catalogs.",
    )
    compare.add_argument("reference_catalog", type=Path, help="Reference api-catalog.json")
    compare.add_argument("candidate_catalog", type=Path, help="Candidate api-catalog.json")
    compare.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output directory for api-compatibility.json and api-compatibility.md",
    )
    compare.add_argument(
        "--gate-mode",
        choices=("report", "fail_on_breaking", "fail_closed"),
        default="report",
        help="Compatibility gate semantics",
    )
    compare.add_argument("--include-endpoint", action="append", help="Endpoint selector to include")
    compare.add_argument("--exclude-endpoint", action="append", help="Endpoint selector to exclude")
    compare.add_argument(
        "--enforce-security-policy",
        action="store_true",
        help="Treat security policy drift as gate-breaking when applicable.",
    )

    provider_consumer = subparsers.add_parser(
        "check-consumer-compatibility",
        help="Check consumed API dependencies against provider catalogs.",
    )
    provider_consumer.add_argument(
        "--consumer-catalog",
        action="append",
        type=Path,
        required=True,
        help="Consumer api-catalog.json; may be repeated",
    )
    provider_consumer.add_argument(
        "--provider-catalog",
        action="append",
        type=Path,
        required=True,
        help="Provider api-catalog.json; may be repeated",
    )
    provider_consumer.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output directory for consumer-compatibility.json and consumer-compatibility.md",
    )
    provider_consumer.add_argument(
        "--gate-mode",
        choices=("report", "fail_on_breaking", "fail_closed"),
        default="fail_closed",
        help="Provider/consumer compatibility gate semantics",
    )
    provider_consumer.add_argument("--include-endpoint", action="append", help="Endpoint selector to include")
    provider_consumer.add_argument("--exclude-endpoint", action="append", help="Endpoint selector to exclude")
    provider_consumer.add_argument(
        "--enforce-security-policy",
        action="store_true",
        help="Treat security policy drift as gate-breaking when applicable.",
    )
    return parser


def _write_atomic(path: Path, content: str) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise


def _emit_json(payload: dict[str, object], output: Path | None) -> None:
    content = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if output:
        _write_atomic(output, content)
        print(f"Result written to {output}", file=sys.stderr)
    else:
        print(content, end="")


def _parse_soap_wsdl(values: list[str] | None) -> dict[str, Path]:
    mappings: dict[str, Path] = {}
    for raw in values or []:
        if "=" not in raw:
            raise ValueError("--soap-wsdl must use SERVICE=PATH syntax")
        service, path = raw.split("=", 1)
        service = service.strip()
        path = path.strip()
        if not service or not path:
            raise ValueError("--soap-wsdl requires non-empty SERVICE and PATH")
        candidate = Path(path)
        existing = mappings.get(service)
        if existing is not None and existing != candidate:
            raise ValueError(f"--soap-wsdl service '{service}' is mapped more than once")
        mappings[service] = candidate
    return mappings


def _inventory_command(args: argparse.Namespace) -> int:
    target = AuditTarget(
        repository=args.repository,
        ref=args.ref,
        repository_id=args.repository_id,
        exclude_paths=tuple(args.exclude_path or ()),
    )
    try:
        inventory = inventory_repository(target, allow_dirty=args.allow_dirty)
    except InventoryError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    _emit_json(inventory_to_dict(inventory), args.output)
    return 0 if inventory.inventory_complete else 3


def _discover_command(args: argparse.Namespace) -> int:
    target = AuditTarget(
        repository=args.repository,
        ref=args.ref,
        repository_id=args.repository_id,
        exclude_paths=tuple(args.exclude_path or ()),
    )
    try:
        soap_wsdl = _parse_soap_wsdl(args.soap_wsdl)
        discovery = discover_endpoints(
            target,
            allow_dirty=args.allow_dirty,
            soap_wsdl=soap_wsdl,
        )
    except (InventoryError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    _emit_json(discovery_to_dict(discovery), args.output)
    return 0 if discovery.discovery_complete else 3


def _audit_command(args: argparse.Namespace) -> int:
    target = AuditTarget(
        repository=args.repository,
        ref=args.ref,
        output=args.output,
        repository_id=args.repository_id,
        exclude_paths=tuple(args.exclude_path or ()),
    )
    try:
        soap_wsdl = _parse_soap_wsdl(args.soap_wsdl)
        destination, findings = generate_audit(
            target,
            allow_dirty=args.allow_dirty,
            soap_wsdl=soap_wsdl,
            require_correlation=args.require_correlation,
        )
    except (InventoryError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"ASGARD API Auditor v{__version__}")
    print(f"Audit artifacts written to {destination}")
    print(f"Audit status: {findings['status']}")
    return 0 if findings["status"] == "complete" else 3


def _correlate_command(args: argparse.Namespace) -> int:
    try:
        destination, payload = correlate_findings(args.findings, args.output)
    except CorrelationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    coverage = payload["coverage"]
    assert isinstance(coverage, dict)
    print(f"Correlation artifacts written to {destination}")
    print(
        "Correlation status: "
        f"{coverage['consumers_correlated']}/{coverage['consumers_total']} consumers have candidates"
    )
    return 0


def _catalog_command(args: argparse.Namespace) -> int:
    try:
        destination, payload = write_api_catalog(
            args.findings,
            args.output,
            namespace=args.stable_namespace,
            include_endpoints=tuple(args.include_endpoint or ()),
            exclude_endpoints=tuple(args.exclude_endpoint or ()),
        )
    except CatalogError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    coverage = payload["coverage"]
    assert isinstance(coverage, dict)
    print(f"API catalog written to {destination}")
    print(
        "Catalog endpoints: "
        f"{coverage['exposed_endpoints']} exposed / {coverage['consumed_endpoints']} consumed"
    )
    return 0


def _compare_api_command(args: argparse.Namespace) -> int:
    try:
        destination, payload = write_api_compatibility(
            args.reference_catalog,
            args.candidate_catalog,
            args.output,
            gate_mode=args.gate_mode,
            include_endpoints=tuple(args.include_endpoint or ()),
            exclude_endpoints=tuple(args.exclude_endpoint or ()),
            enforce_security_policy=args.enforce_security_policy,
        )
    except ApiCompatibilityError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    gate = payload["gate"]
    assert isinstance(gate, dict)
    print(f"API compatibility artifacts written to {destination}")
    print(f"Compatibility gate: {gate['mode']} -> {gate['status']}")
    return 0 if gate["status"] == "passed" else 3


def _consumer_compatibility_command(args: argparse.Namespace) -> int:
    try:
        destination, payload = write_consumer_compatibility(
            args.consumer_catalog,
            args.provider_catalog,
            args.output,
            gate_mode=args.gate_mode,
            include_endpoints=tuple(args.include_endpoint or ()),
            exclude_endpoints=tuple(args.exclude_endpoint or ()),
            enforce_security_policy=args.enforce_security_policy,
        )
    except ConsumerCompatibilityError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    gate = payload["gate"]
    assert isinstance(gate, dict)
    print(f"Consumer compatibility artifacts written to {destination}")
    print(f"Consumer compatibility gate: {gate['mode']} -> {gate['status']}")
    return 0 if gate["status"] == "passed" else 3


def main(argv: Sequence[str] | None = None) -> int:
    actual = list(sys.argv[1:] if argv is None else argv)
    commands = {
        "inventory",
        "discover",
        "audit",
        "correlate",
        "catalog-api",
        "compare-api",
        "check-consumer-compatibility",
    }
    if actual and actual[0] not in commands and not actual[0].startswith("-"):
        actual.insert(0, "audit")
    parser = build_parser()
    args = parser.parse_args(actual)
    if args.command == "inventory":
        return _inventory_command(args)
    if args.command == "discover":
        return _discover_command(args)
    if args.command == "audit":
        return _audit_command(args)
    if args.command == "correlate":
        return _correlate_command(args)
    if args.command == "catalog-api":
        return _catalog_command(args)
    if args.command == "compare-api":
        return _compare_api_command(args)
    if args.command == "check-consumer-compatibility":
        return _consumer_compatibility_command(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
