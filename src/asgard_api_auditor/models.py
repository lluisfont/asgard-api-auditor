from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

EvidenceType = Literal[
    "route",
    "controller",
    "http_client",
    "configuration",
    "test",
    "documentation",
    "runtime",
    "unknown",
]

Confidence = Literal["confirmed", "probable", "unverified"]
Direction = Literal["exposed", "consumed"]


@dataclass(frozen=True)
class AuditTarget:
    repository: Path
    ref: str = "HEAD"
    output: Path = Path("output")


@dataclass(frozen=True)
class Evidence:
    path: str
    line: int | None = None
    kind: EvidenceType = "unknown"
    note: str | None = None


@dataclass
class EndpointFinding:
    direction: Direction
    method: str
    path: str
    api_name: str | None = None
    provider_repository: str | None = None
    consumer_repository: str | None = None
    authentication: str | None = None
    confidence: Confidence = "unverified"
    evidence: list[Evidence] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def identity(self) -> tuple[str, str, str]:
        return self.direction, self.method.upper(), self.path
