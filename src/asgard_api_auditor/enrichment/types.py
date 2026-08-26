"""Types for contract enrichment coverage and fail-closed unresolved findings."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import EndpointFinding, Evidence


@dataclass(frozen=True)
class ContractUnresolved:
    code: str
    message: str
    evidence: tuple[Evidence, ...] = ()


@dataclass
class ContractEnrichmentCoverage:
    total_exposed_endpoints: int = 0
    path_parameters_applicable: int = 0
    path_parameters_enriched: int = 0
    request_enrichment_applicable: int = 0
    request_enriched: int = 0
    response_enrichment_applicable: int = 0
    response_enriched: int = 0
    security_enrichment_applicable: int = 0
    security_enriched: int = 0
    unresolved_contract_enrichment: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "total_exposed_endpoints": self.total_exposed_endpoints,
            "path_parameters_applicable": self.path_parameters_applicable,
            "path_parameters_enriched": self.path_parameters_enriched,
            "request_enrichment_applicable": self.request_enrichment_applicable,
            "request_enriched": self.request_enriched,
            "response_enrichment_applicable": self.response_enrichment_applicable,
            "response_enriched": self.response_enriched,
            "security_enrichment_applicable": self.security_enrichment_applicable,
            "security_enriched": self.security_enriched,
            "unresolved_contract_enrichment": self.unresolved_contract_enrichment,
        }


@dataclass
class ContractEnrichmentResult:
    endpoints: list[EndpointFinding]
    coverage: ContractEnrichmentCoverage
    unresolved: list[ContractUnresolved] = field(default_factory=list)
