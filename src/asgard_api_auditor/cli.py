from __future__ import annotations

import argparse
from pathlib import Path

from .models import AuditTarget


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="asgard-api-auditor",
        description="Audit an ASGARD repository for exposed and consumed HTTP APIs.",
    )
    parser.add_argument("repository", type=Path, help="Local path to the repository to audit")
    parser.add_argument("--ref", default="HEAD", help="Git ref or commit being audited")
    parser.add_argument("--output", type=Path, default=Path("output"), help="Output directory")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    target = AuditTarget(repository=args.repository, ref=args.ref, output=args.output)
    if not target.repository.exists():
        raise SystemExit(f"Repository path does not exist: {target.repository}")

    print("ASGARD API Auditor v0.1")
    print(f"Repository: {target.repository}")
    print(f"Ref: {target.ref}")
    print(f"Output: {target.output}")
    print("Detector execution is not implemented yet; this scaffold only validates the audit target.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
