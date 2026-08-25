"""Types for endpoint discovery before full audit generation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .models import DetectorCoverage, EndpointFinding, Evidence

IssueSeverity = Literal["warning", "blocking"]


@dataclass(frozen=True)
class DiscoveryIssue:
    code: str
    message: str
    detector_id: str
    severity: IssueSeverity = "blocking"
    evidence: tuple[Evidence, ...] = ()


@dataclass
class EndpointDiscovery:
    schema_version: str
    auditor_version: str
    repository: str
    repository_id: str
    source_ref: str
    source_commit: str
    inventory_complete: bool
    discovery_complete: bool
    endpoints: list[EndpointFinding] = field(default_factory=list)
    detectors: list[DetectorCoverage] = field(default_factory=list)
    unresolved: list[DiscoveryIssue] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
