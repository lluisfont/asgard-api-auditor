"""Path exclusion helpers shared by inventory and discovery."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path


def _clean_relative(value: str) -> str:
    return value.replace("\\", "/").strip().strip("/")


def normalize_exclude_paths(repository: Path, paths: Iterable[str]) -> tuple[str, ...]:
    repository = repository.resolve()
    normalized: set[str] = set()
    for raw in paths:
        if not raw:
            continue
        candidate = Path(raw)
        if candidate.is_absolute():
            try:
                normalized.add(candidate.resolve().relative_to(repository).as_posix())
                continue
            except ValueError:
                pass
        cleaned = _clean_relative(raw)
        if cleaned and cleaned != ".":
            normalized.add(cleaned)
    return tuple(sorted(normalized))


def is_excluded_path(repository: Path, path: Path, exclude_paths: Iterable[str]) -> bool:
    try:
        rel = path.relative_to(repository).as_posix()
    except ValueError:
        return False
    for rule in exclude_paths:
        cleaned = _clean_relative(rule)
        if rel == cleaned or rel.startswith(f"{cleaned}/"):
            return True
    return False
