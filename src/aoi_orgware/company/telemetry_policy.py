"""Pure deterministic policy shared by telemetry ingest and invariant replay.

The provider parser establishes raw facts.  This module derives AOI registry
joins, stable object IDs, and automatic coverage state without reading clocks,
files, or mutable process state.  The sole-writer path and historical reducer
must call the same functions so a caller cannot substitute a stronger join or
coverage claim than the raw facts and registry support.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .contracts import ZERO_SHA256, company_contract_sha256


class TelemetryPolicyError(ValueError):
    """Telemetry registry state is internally ambiguous."""


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(member) for key, member in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(member) for member in value]
    return value


def telemetry_id(
    binding: Mapping[str, Any],
    label: str,
    *parts: str,
) -> str:
    digest = company_contract_sha256({
        "binding": dict(binding),
        "label": label,
        "parts": list(parts),
    })
    return f"telemetry-{label}-{digest[:24]}"


def unknown_drop(reason: str) -> dict[str, Any]:
    return {
        "value": None,
        "source": "none",
        "quality": "unavailable",
        "reason": reason,
    }


def coverage_event_kinds(
    provider: str,
    source_class: str,
    surface: str,
) -> list[str]:
    if surface == "usage":
        return (
            ["provider_usage"]
            if provider == "claude"
            else ["thread_token_usage_updated"]
        )
    if provider == "claude":
        return [
            "stop_runtime_observed",
            "subagent_start_runtime_observed",
        ]
    return [
        "item_completed_runtime_observed",
        "item_started_runtime_observed",
        "model_rerouted_runtime_observed",
        "thread_started",
        "thread_status_changed",
        "thread_token_usage_updated",
        "thread_waiting_on_user_input",
        "turn_completed_runtime_observed",
        "turn_started_runtime_observed",
        "unknown_codex_event",
    ]


def automatic_coverage_state(
    outcome: str,
    prior_sequence: int | None,
    intake_sequence: int,
    *,
    prior: Mapping[str, Any] | None,
) -> tuple[str, str, dict[str, Any]]:
    if prior is not None and prior["state"] == "degraded":
        return (
            "degraded",
            "prior_degraded_requires_explicit_recovery",
            _plain(prior["dropped_event_count"]),
        )
    if outcome != "normalized":
        reason = "parser_" + outcome
        return "degraded", reason, unknown_drop(reason)
    if prior_sequence is None and intake_sequence > 1:
        return "degraded", "adapter_initial_sequence_gap", {
            "value": intake_sequence - 1,
            "source": "adapter_route",
            "quality": "observed",
            "reason": "observed",
        }
    if prior_sequence is not None and intake_sequence > prior_sequence + 1:
        return "degraded", "adapter_sequence_gap", {
            "value": intake_sequence - prior_sequence - 1,
            "source": "adapter_route",
            "quality": "observed",
            "reason": "observed",
        }
    if prior_sequence is not None and intake_sequence <= prior_sequence:
        return (
            "degraded",
            "adapter_sequence_nonmonotonic",
            unknown_drop("adapter_sequence_nonmonotonic"),
        )
    return "observed", "observed", {
        "value": 0,
        "source": "adapter_route",
        "quality": "observed",
        "reason": "observed",
    }


def exact_provider_telemetry_join(
    *,
    provider: str,
    facts: Mapping[str, Mapping[str, Any]],
    executions: Sequence[Mapping[str, Any]],
    dispatches: Sequence[Mapping[str, Any]],
    registry_cursor: int,
) -> dict[str, Any]:
    """Derive one join solely from raw-verified native IDs and AOI registry."""

    exact = {
        name: str(facts[name]["value"])
        for name in ("thread_id", "turn_id", "agent_id")
        if facts[name]["quality"] == "observed"
    }
    ranked_candidates: list[
        tuple[tuple[int, int], dict[str, Any]]
    ] = []
    if exact:
        for execution in executions:
            if execution["provider"] != provider:
                continue
            claimed = {
                name: str(execution[name])
                for name in ("thread_id", "turn_id", "agent_id")
                if execution[name] is not None
            }
            matched = {
                name
                for name, value in claimed.items()
                if exact.get(name) == value
            }
            if not matched or any(
                name in exact and exact[name] != value
                for name, value in claimed.items()
            ):
                continue
            ranked_candidates.append((
                (len(matched), -(len(claimed) - len(matched))),
                {
                    "execution_id": execution["execution_id"],
                    "carrier_id": execution["carrier_id"],
                    "dispatch_id": execution["dispatch_id"],
                    "registration_id": execution["registration_id"],
                },
            ))
    best_rank = max(
        (rank for rank, _candidate in ranked_candidates),
        default=None,
    )
    candidates = [
        candidate
        for rank, candidate in ranked_candidates
        if rank == best_rank
    ]
    candidates.sort(key=lambda item: str(item["execution_id"]))
    if not candidates:
        return {
            "state": "none",
            "binding_kind": "none",
            "registry_cursor": registry_cursor,
            "dispatch_request_id": None,
            "dispatch_revision_id": None,
            "registration_id": None,
            "execution_id": None,
            "carrier_id": None,
            "candidate_count": 0,
            "candidates_sha256": ZERO_SHA256,
            "reason": "no_exact_registered_native_identity",
        }
    if len(candidates) != 1:
        return {
            "state": "ambiguous",
            "binding_kind": "none",
            "registry_cursor": registry_cursor,
            "dispatch_request_id": None,
            "dispatch_revision_id": None,
            "registration_id": None,
            "execution_id": None,
            "carrier_id": None,
            "candidate_count": len(candidates),
            "candidates_sha256": company_contract_sha256(candidates),
            "reason": "multiple_exact_registered_native_identities",
        }
    candidate = candidates[0]
    dispatch_id = candidate["dispatch_id"]
    binding_kind = (
        "dispatch"
        if dispatch_id is not None
        else (
            "registration"
            if candidate["registration_id"] is not None
            else "carrier"
        )
    )
    dispatch_revision_id = None
    if dispatch_id is not None:
        matching = [
            dispatch
            for dispatch in dispatches
            if dispatch["dispatch_request_id"] == dispatch_id
        ]
        if len(matching) != 1:
            raise TelemetryPolicyError(
                "exact dispatch binding is no longer unique",
            )
        dispatch_revision_id = matching[0]["dispatch_revision_id"]
    return {
        "state": "exact",
        "binding_kind": binding_kind,
        "registry_cursor": registry_cursor,
        "dispatch_request_id": dispatch_id,
        "dispatch_revision_id": dispatch_revision_id,
        "registration_id": candidate["registration_id"],
        "execution_id": candidate["execution_id"],
        "carrier_id": candidate["carrier_id"],
        "candidate_count": 1,
        "candidates_sha256": company_contract_sha256(candidates),
        "reason": "exact_registered_native_identity",
    }


__all__ = [
    "TelemetryPolicyError",
    "automatic_coverage_state",
    "coverage_event_kinds",
    "exact_provider_telemetry_join",
    "telemetry_id",
    "unknown_drop",
]
