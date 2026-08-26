"""Conservative redaction helpers for generated knowledge artifacts."""

from __future__ import annotations

import re

_REDACTION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s\"']+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(authorization\s*[:=]\s*basic\s+)[^\s\"']+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|secret)"
            r"(\s*[:=]\s*)[^\s,&;\"']+"
        ),
        r"\1\2[REDACTED]",
    ),
    (
        re.compile(r"(?i)(://[^:/\s]+:)[^@/\s]+(@)"),
        r"\1[REDACTED]\2",
    ),
    (
        re.compile(
            r"(?i)([?&](?:api[_-]?key|token|access[_-]?token|password|secret)=)"
            r"[^&#\s\"']+"
        ),
        r"\1[REDACTED]",
    ),
)

_SECRET_LIKE = re.compile(
    r"(?i)(authorization\s*[:=]\s*(?:bearer|basic)\s+(?!\[REDACTED\])\S+|"
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|secret)"
    r"\s*[:=]\s*(?!\[REDACTED\])\S+)"
)


def redact_text(text: str) -> str:
    """Redact common credential-bearing patterns while retaining mechanism names."""
    redacted = text
    for pattern, replacement in _REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def contains_unredacted_secret_like_value(text: str) -> bool:
    """Return True when common unredacted credential patterns remain."""
    return _SECRET_LIKE.search(text) is not None
