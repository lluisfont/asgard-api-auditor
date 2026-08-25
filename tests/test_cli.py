from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from asgard_api_auditor.cli import main


def _init_repo(root: Path) -> Path:
    repo = root / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test User"], check=True)
    (repo / "app.py").write_text("import requests\n", encoding="utf-8")
    (repo / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
    return repo


class CliTests(unittest.TestCase):
    def test_inventory_writes_json_to_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(Path(tmp))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["inventory", str(repo)])
            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertTrue(payload["inventory_complete"])
            self.assertEqual(payload["schema_version"], "1.0")

    def test_inventory_atomic_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _init_repo(root)
            output = root / "inventory.json"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main(["inventory", str(repo), "--output", str(output)])
            self.assertEqual(code, 0)
            self.assertTrue(output.exists())
            self.assertEqual(json.loads(output.read_text())["repository"], "repo")

    def test_full_audit_remains_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(Path(tmp))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["audit", str(repo)])
            self.assertEqual(code, 4)
            self.assertIn("not implemented", stdout.getvalue())

    def test_bare_repository_keeps_v02_backward_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(Path(tmp))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main([str(repo)])
            self.assertEqual(code, 4)


if __name__ == "__main__":
    unittest.main()
