"""Shared helpers for conservative endpoint discovery."""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from .inventory_catalog import CODE_EXTENSIONS, EXCLUDED_DIRS, MAX_TEXT_FILE_BYTES
from .path_filters import is_excluded_path, normalize_exclude_paths


_PLACEHOLDER_PATTERNS = (
    (re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}"), r"{\1}"),
    (re.compile(r"\{\$([A-Za-z_][A-Za-z0-9_]*)\}"), r"{\1}"),
    (re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)"), r"{\1}"),
)


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def iter_source_files(repository: Path, exclude_paths: tuple[str, ...] = ()) -> list[Path]:
    exclude_paths = normalize_exclude_paths(repository, exclude_paths)
    files: list[Path] = []
    for root, dirs, filenames in os.walk(repository, topdown=True, followlinks=False):
        root_path = Path(root)
        dirs[:] = [
            name
            for name in sorted(dirs)
            if name not in EXCLUDED_DIRS and not (root_path / name).is_symlink()
            and not is_excluded_path(repository, root_path / name, exclude_paths)
        ]
        for filename in sorted(filenames):
            path = root_path / filename
            if is_excluded_path(repository, path, exclude_paths):
                continue
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


def mask_c_like_comments(
    text: str,
    *,
    hash_comments: bool = False,
    html_comments: bool = False,
) -> str:
    """Replace comments with spaces while preserving length and newlines."""
    chars = list(text)
    index = 0
    quote: str | None = None
    escaped = False
    while index < len(chars):
        char = chars[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            index += 1
            continue
        if char == "/" and index + 1 < len(chars) and chars[index + 1] == "/":
            while index < len(chars) and chars[index] != "\n":
                chars[index] = " "
                index += 1
            continue
        if hash_comments and char == "#":
            while index < len(chars) and chars[index] != "\n":
                chars[index] = " "
                index += 1
            continue
        if char == "/" and index + 1 < len(chars) and chars[index + 1] == "*":
            chars[index] = " "
            chars[index + 1] = " "
            index += 2
            while index + 1 < len(chars) and not (chars[index] == "*" and chars[index + 1] == "/"):
                if chars[index] != "\n":
                    chars[index] = " "
                index += 1
            if index + 1 < len(chars):
                chars[index] = " "
                chars[index + 1] = " "
                index += 2
            continue
        if html_comments and text.startswith("<!--", index):
            for _ in range(4):
                chars[index] = " "
                index += 1
            while index + 2 < len(chars) and not text.startswith("-->", index):
                if chars[index] != "\n":
                    chars[index] = " "
                index += 1
            if index + 2 < len(chars):
                for _ in range(3):
                    chars[index] = " "
                    index += 1
            continue
        index += 1
    return "".join(chars)


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
