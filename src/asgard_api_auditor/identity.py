"""Stable identifiers for audit entities."""

from __future__ import annotations

import hashlib
import uuid


def make_audit_id() -> str:
    """Return a unique audit execution identifier."""
    return f"audit_{uuid.uuid4().hex}"


def make_endpoint_id(
    direction: str,
    method: str,
    path: str,
    api_id: str | None = None,
) -> str:
    """Create a stable endpoint ID from normalized contract identity."""
    canonical = "|".join(
        [
            api_id or "unknown-api",
            direction.strip().lower(),
            method.strip().upper(),
            path.strip(),
        ]
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20]
    return f"ep_{digest}"
