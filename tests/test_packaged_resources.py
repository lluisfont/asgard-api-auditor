from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _python_executable(virtualenv: Path) -> Path:
    if os.name == "nt":
        return virtualenv / "Scripts" / "python.exe"
    return virtualenv / "bin" / "python"


def _clean_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    return env


def _coverage() -> dict[str, object]:
    return {
        "inventory_complete": True,
        "languages": [],
        "frameworks": [],
        "http_clients": [],
        "required_detector_categories": [],
        "detectors": [],
        "files_scanned": 0,
        "files_excluded": 0,
        "exclusion_rules": [],
        "unsupported_surfaces": [],
    }


def _endpoint(direction: str, method: str, path: str) -> dict[str, object]:
    return {
        "endpoint_id": f"{direction}-{method}-{path}".replace("/", "-"),
        "direction": direction,
        "surface_type": "http",
        "method": method,
        "path": path,
        "confidence": "confirmed",
        "confidence_reason": "packaged resource fixture",
        "evidence": [
            {
                "path": "src/api.ts",
                "line": 1,
                "kind": "route" if direction == "exposed" else "http_client",
            }
        ],
    }


def _write_findings(path: Path, *, repository_id: str, commit: str, endpoints: list[dict[str, object]]) -> None:
    payload = {
        "schema_version": "2.0",
        "audit_id": f"audit-{repository_id}-packaged",
        "auditor_version": "0.6.0",
        "repository": repository_id,
        "repository_id": repository_id,
        "source_ref": "main",
        "source_commit": commit,
        "audit_timestamp": "2026-08-26T00:00:00+00:00",
        "status": "partial",
        "coverage": _coverage(),
        "endpoints": endpoints,
        "integration_surfaces": [],
        "unresolved": [],
        "artifacts": {
            "openapi.yaml": {"status": "validated"},
            "api-knowledge.md": {"status": "validated"},
            "audit-report.md": {"status": "validated"},
        },
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


class PackagedResourcesTests(unittest.TestCase):
    def test_packaged_runtime_schemas_match_repository_contracts(self) -> None:
        for name in ("findings.schema.json", "correlations.schema.json"):
            with self.subTest(schema=name):
                repository_schema = (ROOT / "schemas" / name).read_text(encoding="utf-8")
                packaged_schema = (ROOT / "src" / "asgard_api_auditor" / "schemas" / name).read_text(
                    encoding="utf-8"
                )
                self.assertEqual(packaged_schema, repository_schema)

    def test_installed_wheel_correlates_without_cwd_schemas(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wheelhouse = root / "wheelhouse"
            wheelhouse.mkdir()
            env = _clean_env()
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    "--no-deps",
                    "--no-build-isolation",
                    str(ROOT),
                    "-w",
                    str(wheelhouse),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            wheels = sorted(wheelhouse.glob("asgard_api_auditor-*.whl"))
            self.assertEqual(len(wheels), 1)

            virtualenv = root / "venv"
            venv.EnvBuilder(with_pip=True).create(virtualenv)
            python = _python_executable(virtualenv)
            subprocess.run(
                [str(python), "-m", "pip", "install", str(wheels[0])],
                cwd=root,
                env=env,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            inputs = root / "inputs"
            inputs.mkdir()
            provider = inputs / "provider-findings.json"
            consumer = inputs / "consumer-findings.json"
            _write_findings(
                provider,
                repository_id="provider",
                commit="a" * 40,
                endpoints=[_endpoint("exposed", "GET", "/health")],
            )
            _write_findings(
                consumer,
                repository_id="consumer",
                commit="b" * 40,
                endpoints=[_endpoint("consumed", "GET", "/health")],
            )

            run_dir = root / "run-without-schemas"
            run_dir.mkdir()
            self.assertFalse((run_dir / "schemas").exists())
            output = root / "correlation-output"
            subprocess.run(
                [
                    str(python),
                    "-m",
                    "asgard_api_auditor.cli",
                    "correlate",
                    "--findings",
                    str(provider),
                    "--findings",
                    str(consumer),
                    "--output",
                    str(output),
                ],
                cwd=run_dir,
                env=env,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            subprocess.run(
                [
                    str(python),
                    "-c",
                    (
                        "from pathlib import Path; "
                        "from asgard_api_auditor.correlation import validate_correlation_set; "
                        f"validate_correlation_set(Path({str(output)!r}))"
                    ),
                ],
                cwd=run_dir,
                env=env,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            correlations = json.loads((output / "correlations.json").read_text(encoding="utf-8"))
            self.assertEqual(correlations["coverage"]["consumed_endpoints_total"], 1)
            self.assertEqual(correlations["correlations"][0]["status"], "matched_unique_candidate")


if __name__ == "__main__":
    unittest.main()
