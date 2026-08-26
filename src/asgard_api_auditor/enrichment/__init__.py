"""Deterministic contract enrichment for proven discovery findings."""

from .slim_php import enrich_slim_php_contracts
from .types import ContractEnrichmentCoverage, ContractEnrichmentResult, ContractUnresolved

__all__ = [
    "ContractEnrichmentCoverage",
    "ContractEnrichmentResult",
    "ContractUnresolved",
    "enrich_slim_php_contracts",
]
