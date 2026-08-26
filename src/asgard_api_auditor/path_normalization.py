"""Shared deterministic path-shape normalization."""

from __future__ import annotations

import re

ROUTE_PARAMETER = re.compile(r"\{(?P<name>[A-Za-z_][A-Za-z0-9_-]*)(?::[^}]+)?\}")


def normalized_path_shape(path: str) -> str:
    """Normalize only route parameter names, preserving literals and slashes."""
    return ROUTE_PARAMETER.sub("{}", path)


def path_parameter_names(path: str) -> list[str]:
    """Return route parameter names in source order."""
    return [match.group("name") for match in ROUTE_PARAMETER.finditer(path)]
