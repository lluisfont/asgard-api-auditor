"""Deterministic semantic enrichment entry points."""

from .slim_php import enrich_slim_php_semantics, semantic_unresolved_payload
from .types import SemanticEnrichmentCoverage, SemanticEnrichmentResult, SemanticUnresolved

__all__ = [
    "SemanticEnrichmentCoverage",
    "SemanticEnrichmentResult",
    "SemanticUnresolved",
    "enrich_slim_php_semantics",
    "semantic_unresolved_payload",
]
