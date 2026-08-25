from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .discovery import discover_endpoints, discovery_to_dict
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

    discover = subparsers.add_parser("discover", help="Discover exposed and consumed HTTP endpoints")
    discover.add_argument("repository", type=Path, help="Local Git repository root")
    discover.add_argument("--ref", default="HEAD", help="Git ref; it must resolve to checked-out HEAD")
    discover.add_argument("--repository-id", help="Stable logical repository ID")
    discover.add_argument("--output", type=Path, help="Optional JSON output file")
    discover.add_argument("--allow-dirty", action="store_true", help="Allow diagnostic discovery on dirty tree")

    audit = subparsers.add_parser("audit", help="Run the full API audit (not implemented yet).")
    audit.add_argument("repository", type=Path, help="Local Git repository root")
    audit.add_argument("--ref", default="HEAD", help="Git ref or commit being audited")
    audit.add_argument("--output", type=Path, default=Path("output"), help="Output directory")
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


def _inventory_command(args: argparse.Namespace) -> int:
    target = AuditTarget(repository=args.repository, ref=args.ref, repository_id=args.repository_id)
    try:
        inventory = inventory_repository(target, allow_dirty=args.allow_dirty)
    except InventoryError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    _emit_json(inventory_to_dict(inventory), args.output)
    return 0 if inventory.inventory_complete else 3


def _discover_command(args: argparse.Namespace) -> int:
    target = AuditTarget(repository=args.repository, ref=args.ref, repository_id=args.repository_id)
    try:
        discovery = discover_endpoints(target, allow_dirty=args.allow_dirty)
    except InventoryError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    _emit_json(discovery_to_dict(discovery), args.output)
    return 0 if discovery.discovery_complete else 3


def _audit_command(args: argparse.Namespace) -> int:
    target = AuditTarget(repository=args.repository, ref=args.ref, output=args.output)
    if not target.repository.is_dir():
        print(f"ERROR: Repository path does not exist or is not a directory: {target.repository}", file=sys.stderr)
        return 2
    print(f"ASGARD API Auditor v{__version__}")
    print("Full audit output generation is intentionally not implemented in v0.4.")
    print("Run `asgard-api-auditor discover <repository>` to discover HTTP endpoints.")
    return 4


def main(argv: Sequence[str] | None = None) -> int:
    actual = list(sys.argv[1:] if argv is None else argv)
    if actual and actual[0] not in {"inventory", "discover", "audit"} and not actual[0].startswith("-"):
        actual.insert(0, "audit")
    parser = build_parser()
    args = parser.parse_args(actual)
    if args.command == "inventory":
        return _inventory_command(args)
    if args.command == "discover":
        return _discover_command(args)
    if args.command == "audit":
        return _audit_command(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
