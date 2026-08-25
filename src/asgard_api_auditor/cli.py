from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .models import AuditTarget


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="asgard-api-auditor",
        description="Audit an ASGARD repository for exposed and consumed APIs.",
    )
    parser.add_argument("repository", type=Path, nargs="?", help="Local repository path")
    parser.add_argument("--ref", default="HEAD", help="Git ref or commit being audited")
    parser.add_argument("--output", type=Path, default=Path("output"), help="Output directory")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.repository is None:
        build_parser().print_help()
        return 2

    target = AuditTarget(repository=args.repository, ref=args.ref, output=args.output)
    if not target.repository.is_dir():
        raise SystemExit(
            f"Repository path does not exist or is not a directory: {target.repository}"
        )
    if not (target.repository / ".git").exists():
        raise SystemExit(f"Target is not a Git working tree: {target.repository}")

    print(f"ASGARD API Auditor v{__version__}")
    print(f"Repository: {target.repository}")
    print(f"Ref: {target.ref}")
    print(f"Output: {target.output}")
    print("Detector execution is intentionally not implemented in v0.2.")
    print("No audit status or output is emitted until coverage-aware detectors are implemented.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
