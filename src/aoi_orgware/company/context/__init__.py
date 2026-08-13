"""Observation-only views of legacy context-manifest contracts.

These helpers do not compile, materialize, transmit, or admit context.
"""

from .legacy_v1 import (
    ContextEvidenceRef,
    ContextManifestInventory,
    ContextUnavailableFact,
    LegacyContextV1Error,
    LegacyContextV1Observation,
    LegacyContextV1Key,
    observe_legacy_context_v1,
)

__all__ = (
    "ContextEvidenceRef",
    "ContextManifestInventory",
    "ContextUnavailableFact",
    "LegacyContextV1Error",
    "LegacyContextV1Key",
    "LegacyContextV1Observation",
    "observe_legacy_context_v1",
)
