"""Observation-only usage derivations.

These helpers deliberately do not write the ledger, schedule work, or make
admission/enforcement decisions.
"""

from .high_water import (
    UsageCounterScopeKey,
    UsageHighWaterError,
    UsageHighWaterObservation,
    derive_usage_high_water,
)

__all__ = (
    "UsageCounterScopeKey",
    "UsageHighWaterError",
    "UsageHighWaterObservation",
    "derive_usage_high_water",
)
