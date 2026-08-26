"""Types for deterministic semantic API reconstruction."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import EndpointFinding, Evidence


@dataclass(frozen=True)
class SemanticUnresolved:
    code: str
    message: str
    evidence: tuple[Evidence, ...] = ()


@dataclass
class SemanticEnrichmentCoverage:
    total_exposed_endpoints: int = 0
    semantic_analysis_attempted: int = 0
    semantic_complete: int = 0
    semantic_partial: int = 0
    semantic_unresolved: int = 0
    operations_with_non_generic_description: int = 0
    operations_with_data_access_facts: int = 0
    operations_with_auth_context_facts: int = 0
    operations_with_conditional_outcome_facts: int = 0
    operations_with_outbound_integration_facts: int = 0
    semantic_unresolved_count: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "total_exposed_endpoints": self.total_exposed_endpoints,
            "semantic_analysis_attempted": self.semantic_analysis_attempted,
            "semantic_complete": self.semantic_complete,
            "semantic_partial": self.semantic_partial,
            "semantic_unresolved": self.semantic_unresolved,
            "operations_with_non_generic_description": self.operations_with_non_generic_description,
            "operations_with_data_access_facts": self.operations_with_data_access_facts,
            "operations_with_auth_context_facts": self.operations_with_auth_context_facts,
            "operations_with_conditional_outcome_facts": self.operations_with_conditional_outcome_facts,
            "operations_with_outbound_integration_facts": self.operations_with_outbound_integration_facts,
            "semantic_unresolved_count": self.semantic_unresolved_count,
        }


@dataclass
class SemanticEnrichmentResult:
    endpoints: list[EndpointFinding]
    coverage: SemanticEnrichmentCoverage
    unresolved: list[SemanticUnresolved] = field(default_factory=list)
