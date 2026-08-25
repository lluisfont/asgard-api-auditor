from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .identity import make_endpoint_id

EvidenceType = Literal[
    "route",
    "controller",
    "http_client",
    "configuration",
    "test",
    "documentation",
    "runtime",
    "existing_spec",
    "webhook",
    "generated_sdk",
    "unknown",
]
Confidence = Literal["confirmed", "probable", "unverified"]
Direction = Literal["exposed", "consumed"]
AuditStatus = Literal["complete", "partial", "failed"]
DetectorStatus = Literal["supported", "partial", "unsupported", "failed"]
DetectorCategory = Literal[
    "inventory",
    "exposed",
    "consumed",
    "framework",
    "configuration",
    "existing_spec",
    "integration",
]
IntegrationType = Literal["graphql", "websocket", "grpc", "soap", "sse", "webhook", "other"]
IntegrationStatus = Literal["confirmed", "probable", "unverified", "unsupported"]


@dataclass(frozen=True)
class AuditTarget:
    repository: Path
    ref: str = "HEAD"
    output: Path = Path("output")


@dataclass(frozen=True)
class Evidence:
    path: str
    line: int | None = None
    end_line: int | None = None
    symbol: str | None = None
    kind: EvidenceType = "unknown"
    note: str | None = None


@dataclass(frozen=True)
class ParameterFinding:
    name: str
    location: Literal["path", "query", "header", "cookie"]
    required: bool | None = None
    schema: dict[str, object] | None = None
    evidence: tuple[Evidence, ...] = ()


@dataclass
class RequestFinding:
    parameters: list[ParameterFinding] = field(default_factory=list)
    content_type: str | None = None
    body_schema: dict[str, object] | None = None
    fields: list[str] = field(default_factory=list)


@dataclass
class ResponseFinding:
    status_codes: list[int] = field(default_factory=list)
    content_type: str | None = None
    schema: dict[str, object] | None = None
    fields: list[str] = field(default_factory=list)
    fields_used_by_consumer: list[str] = field(default_factory=list)


@dataclass
class EndpointFinding:
    direction: Direction
    method: str
    path: str
    confidence_reason: str
    evidence: list[Evidence]
    api_id: str | None = None
    api_name: str | None = None
    base_url: str | None = None
    provider_repository: str | None = None
    consumer_repository: str | None = None
    handler: str | None = None
    authentication: str | None = None
    authorization: str | None = None
    request: RequestFinding | None = None
    response: ResponseFinding | None = None
    confidence: Confidence = "unverified"
    notes: list[str] = field(default_factory=list)
    endpoint_id: str = ""

    def __post_init__(self) -> None:
        self.method = self.method.upper()
        if not self.endpoint_id:
            self.endpoint_id = make_endpoint_id(
                self.direction,
                self.method,
                self.path,
                self.api_id,
            )

    def identity(self) -> tuple[str, str, str]:
        return self.direction, self.method, self.path


@dataclass(frozen=True)
class DetectorCoverage:
    detector_id: str
    detector_version: str
    category: DetectorCategory
    status: DetectorStatus
    files_scanned: int = 0
    supported_patterns: tuple[str, ...] = ()
    unsupported_patterns: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


@dataclass
class CoverageSummary:
    inventory_complete: bool = False
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    http_clients: list[str] = field(default_factory=list)
    required_detector_categories: list[DetectorCategory] = field(default_factory=list)
    detectors: list[DetectorCoverage] = field(default_factory=list)
    files_scanned: int = 0
    files_excluded: int = 0
    exclusion_rules: list[str] = field(default_factory=list)
    unsupported_surfaces: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class IntegrationSurfaceFinding:
    surface_id: str
    type: IntegrationType
    status: IntegrationStatus
    direction: Literal["exposed", "consumed", "bidirectional", "unknown"]
    confidence: Confidence
    evidence: tuple[Evidence, ...]
    description: str | None = None
    notes: tuple[str, ...] = ()
