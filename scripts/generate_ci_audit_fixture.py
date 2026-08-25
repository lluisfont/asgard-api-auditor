#!/usr/bin/env python3
"""Generate an OpenAPI document through the real v0.5 audit pipeline for CI linting."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from asgard_api_auditor.generation import generate_audit  # noqa: E402
from asgard_api_auditor.models import AuditTarget  # noqa: E402


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: generate_ci_audit_fixture.py OUTPUT_OPENAPI", file=sys.stderr)
        return 2

    destination = Path(sys.argv[1]).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="asgard-ci-audit-") as tmp:
        root = Path(tmp)
        repo = root / "fixture-repo"
        repo.mkdir()
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "ci@example.com")
        _git(repo, "config", "user.name", "CI Fixture")
        (repo / "composer.json").write_text(
            json.dumps({"require": {"slim/slim": "^4.14"}}), encoding="utf-8"
        )
        (repo / "routes.php").write_text(
            "<?php\n$app->get('/inventory/{id}', $handler);\n"
            "$app->post('/inventory', $handler);\n",
            encoding="utf-8",
        )
        _git(repo, "add", ".")
        _git(repo, "commit", "-qm", "fixture")

        output = root / "audit-output"
        generate_audit(AuditTarget(repo, output=output, repository_id="ci-fixture"))
        shutil.copyfile(output / "openapi.yaml", destination)

    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
