"""Git provenance helpers for the technical inventory."""

from __future__ import annotations

import configparser
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from .models import AuditTarget


class InventoryError(RuntimeError):
    """Raised when a reliable technical inventory cannot be started."""


def run_git(repository: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "git command failed"
        raise InventoryError(message)
    return proc.stdout.strip()


def verify_git_target(target: AuditTarget) -> tuple[Path, str, bool]:
    repository = target.repository.resolve()
    if not repository.is_dir():
        raise InventoryError(f"Repository path does not exist or is not a directory: {repository}")

    top_level = Path(run_git(repository, "rev-parse", "--show-toplevel")).resolve()
    if top_level != repository:
        raise InventoryError(
            f"Target must be the Git repository root. Resolved root is: {top_level}"
        )

    requested = run_git(repository, "rev-parse", "--verify", f"{target.ref}^{{commit}}")
    head = run_git(repository, "rev-parse", "--verify", "HEAD^{commit}")
    if requested != head:
        raise InventoryError(
            "The requested ref is not the checked-out HEAD. v0.3 scans the working tree and "
            "refuses to attach evidence to a different commit. Check out the requested ref first."
        )

    dirty = bool(run_git(repository, "status", "--porcelain", "--untracked-files=normal"))
    return repository, head, dirty


def repository_identity(repository: Path, explicit: str | None) -> tuple[str, str]:
    if explicit and explicit.strip():
        return explicit.strip(), "explicit"
    try:
        remote = run_git(repository, "remote", "get-url", "origin")
    except InventoryError:
        return repository.name, "directory-name"

    if remote.startswith("git@") and ":" in remote:
        host_part, path_part = remote.split(":", 1)
        host = host_part.split("@", 1)[1]
        clean_path = path_part.removesuffix(".git").strip("/")
        if clean_path:
            return f"{host}/{clean_path}", "origin"

    parsed = urlparse(remote)
    if parsed.hostname and parsed.path:
        clean_path = parsed.path.removesuffix(".git").strip("/")
        if clean_path:
            return f"{parsed.hostname}/{clean_path}", "origin"
    return repository.name, "directory-name"


def discover_submodules(repository: Path) -> list[str]:
    gitmodules = repository / ".gitmodules"
    if not gitmodules.exists():
        return []
    parser = configparser.ConfigParser()
    try:
        parser.read(gitmodules, encoding="utf-8")
    except (configparser.Error, OSError):
        return [".gitmodules:unparsed"]
    paths = [
        parser.get(section, "path")
        for section in parser.sections()
        if parser.has_option(section, "path")
    ]
    return sorted(set(paths))
