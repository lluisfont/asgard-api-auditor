"""Shared helpers for conservative endpoint discovery."""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from .inventory_catalog import CODE_EXTENSIONS, EXCLUDED_DIRS, MAX_TEXT_FILE_BYTES


_PLACEHOLDER_PATTERNS = (
    (re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}"), r"{\1}"),
    (re.compile(r"\{\$([A-Za-z_][A-Za-z0-9_]*)\}"), r"{\1}"),
    (re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)"), r"{\1}"),
)


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def iter_source_files(repository: Path) -> list[Path]:
    files: list[Path] = []
    for root, dirs, filenames in os.walk(repository, topdown=True, followlinks=False):
        root_path = Path(root)
        dirs[:] = [
            name
            for name in sorted(dirs)
            if name not in EXCLUDED_DIRS and not (root_path / name).is_symlink()
        ]
        for filename in sorted(filenames):
            path = root_path / filename
            if path.is_symlink() or not path.is_file():
                continue
            if path.suffix.lower() not in CODE_EXTENSIONS:
                continue
            try:
                if path.stat().st_size <= MAX_TEXT_FILE_BYTES:
                    files.append(path)
            except OSError:
                continue
    return files


def read_source(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def relative_path(repository: Path, path: Path) -> str:
    return path.relative_to(repository).as_posix()


def normalize_literal_url(value: str) -> tuple[str | None, str]:
    """Return optional base URL and normalized path without query/fragment.

    Literal interpolation markers are normalized to OpenAPI-like placeholders but
    this function never evaluates expressions or concatenations.
    """
    normalized = value.strip()
    for pattern, replacement in _PLACEHOLDER_PATTERNS:
        normalized = pattern.sub(replacement, normalized)

    if normalized.startswith(("http://", "https://")):
        parsed = urlsplit(normalized)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        return base, path

    path = normalized.split("?", 1)[0].split("#", 1)[0]
    return None, path or "/"
