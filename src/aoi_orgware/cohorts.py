"""Pure deterministic cohort planning and projection (no transport launch).

The schema binds a v6 packet authority reference to a fixed dependency graph
and wave plan.  It intentionally does *not* dispatch a packet, reserve a real
transport, or create a transport receipt.  A caller that later implements a
transport must make and persist that claim separately.
"""
from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any

from .semantic_events import SemanticEventError, canonical_json_bytes, canonical_sha256


COHORT_SCHEMA_VERSION = 1
EXPECTED_PACKET_SCHEMA_VERSION = 6
MAX_COHORT_BYTES = 64 * 1024
MAX_COHORT_PACKETS = 1_024
MAX_COHORT_WAVES = MAX_COHORT_PACKETS
MAX_CONCURRENCY = 1_024

_SHA256 = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SLOT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_BASE_FIELDS = {
    "schema_version",
    "cohort_id",
    "packet_schema_version",
    "packet_refs",
    "dependencies",
    "waves",
    "max_concurrency",
    "transport_slots",
    "failure_policy",
    "cancel_policy",
}
_SEALED_FIELDS = _BASE_FIELDS | {"cohort_sha256"}
_PACKET_REF_FIELDS = {"packet_id", "routing_authority_sha256"}
_SLOT_FIELDS = {"packet_id", "slot_id"}
_STATE_FIELDS = {"status", "terminal_outcome"}
_STATUSES = {"planned", "armed", "start_observed", "terminal", "cancelled"}
_TERMINAL_OUTCOMES = {"accepted", "rejected", "failed", "cancelled"}
_POLICIES = {"continue", "cancel_remaining"}


class CohortError(ValueError):
    """A cohort schema, status input, or projection is invalid."""


def _fail(message: str) -> None:
    raise CohortError(message)


def _clone(value: Any) -> Any:
    try:
        return json.loads(canonical_json_bytes(value, max_bytes=MAX_COHORT_BYTES))
    except (SemanticEventError, TypeError, ValueError) as exc:
        raise CohortError(str(exc)) from exc


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(f"{label} schema is invalid")
    return dict(value)


def _id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        _fail(f"{label} is invalid")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        _fail(f"{label} is not lowercase SHA-256")
    return value


def _policy(value: Any, label: str) -> str:
    if not isinstance(value, str) or value not in _POLICIES:
        _fail(f"{label} is invalid")
    return value


def _packet_refs(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value or len(value) > MAX_COHORT_PACKETS:
        _fail("packet_refs is invalid")
    refs: list[dict[str, str]] = []
    seen: set[str] = set()
    for entry in value:
        item = _object(entry, _PACKET_REF_FIELDS, "packet_ref")
        packet_id = _id(item["packet_id"], "packet_ref.packet_id")
        if packet_id in seen:
            _fail("packet_refs contains duplicates")
        seen.add(packet_id)
        refs.append(
            {
                "packet_id": packet_id,
                "routing_authority_sha256": _sha(
                    item["routing_authority_sha256"], "packet_ref.routing_authority_sha256"
                ),
            }
        )
    return refs


def _dependencies(value: Any, packet_ids: list[str]) -> dict[str, list[str]]:
    if not isinstance(value, Mapping) or set(value) != set(packet_ids):
        _fail("dependencies schema is invalid")
    result: dict[str, list[str]] = {}
    allowed = set(packet_ids)
    for packet_id in packet_ids:
        raw = value[packet_id]
        if not isinstance(raw, list) or len(raw) > MAX_COHORT_PACKETS:
            _fail("dependencies is invalid")
        dependencies = [_id(item, "dependency") for item in raw]
        if len(set(dependencies)) != len(dependencies):
            _fail("dependencies contains duplicates")
        if packet_id in dependencies:
            _fail("dependencies contains a self dependency")
        if any(item not in allowed for item in dependencies):
            _fail("dependencies names an unknown packet")
        result[packet_id] = sorted(dependencies)
    _reject_cycles(result, packet_ids)
    return result


def _reject_cycles(dependencies: Mapping[str, list[str]], packet_ids: list[str]) -> None:
    state = {packet_id: 0 for packet_id in packet_ids}
    for packet_id in packet_ids:
        if state[packet_id] != 0:
            continue
        state[packet_id] = 1
        stack: list[tuple[str, int]] = [(packet_id, 0)]
        while stack:
            current, dependency_index = stack[-1]
            dependencies_for_current = dependencies[current]
            if dependency_index == len(dependencies_for_current):
                state[current] = 2
                stack.pop()
                continue
            dependency = dependencies_for_current[dependency_index]
            stack[-1] = (current, dependency_index + 1)
            if state[dependency] == 1:
                _fail("dependencies contains a cycle")
            if state[dependency] == 0:
                state[dependency] = 1
                stack.append((dependency, 0))


def _waves(value: Any, packet_ids: list[str], dependencies: Mapping[str, list[str]], max_concurrency: int) -> list[list[str]]:
    if not isinstance(value, list) or not value or len(value) > MAX_COHORT_WAVES:
        _fail("waves is invalid")
    positions: dict[str, int] = {}
    waves: list[list[str]] = []
    for index, raw_wave in enumerate(value):
        if not isinstance(raw_wave, list) or not raw_wave or len(raw_wave) > max_concurrency:
            _fail("wave exceeds max_concurrency or is invalid")
        wave = [_id(item, "wave packet_id") for item in raw_wave]
        if len(set(wave)) != len(wave):
            _fail("wave contains duplicate packet references")
        for packet_id in wave:
            if packet_id not in packet_ids:
                _fail("waves names an unknown packet")
            if packet_id in positions:
                _fail("packet appears in more than one wave")
            positions[packet_id] = index
        waves.append(wave)
    if set(positions) != set(packet_ids):
        _fail("waves must contain every packet exactly once")
    for packet_id, dependencies_for_packet in dependencies.items():
        if any(positions[dependency] >= positions[packet_id] for dependency in dependencies_for_packet):
            _fail("dependency must be in an earlier wave")
    return waves


def _max_concurrency(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_CONCURRENCY:
        _fail("max_concurrency is invalid")
    return value


def _transport_slots(value: Any, packet_ids: list[str], waves: list[list[str]]) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) != len(packet_ids):
        _fail("transport_slots is invalid")
    seen_packets: set[str] = set()
    slot_by_packet: dict[str, str] = {}
    for entry in value:
        item = _object(entry, _SLOT_FIELDS, "transport_slot")
        packet_id = _id(item["packet_id"], "transport_slot.packet_id")
        slot_id = item["slot_id"]
        if packet_id not in packet_ids:
            _fail("transport_slots names an unknown packet")
        if packet_id in seen_packets:
            _fail("transport_slots contains duplicate packet references")
        if not isinstance(slot_id, str) or not _SLOT.fullmatch(slot_id):
            _fail("transport_slot.slot_id is invalid")
        seen_packets.add(packet_id)
        slot_by_packet[packet_id] = slot_id
    for wave in waves:
        wave_slots = [slot_by_packet[packet_id] for packet_id in wave]
        if len(set(wave_slots)) != len(wave_slots):
            _fail("transport slot conflict within a wave")
    # The packet list is the schedule's canonical identity.  Input order of a
    # mapping-like slot list must not create a distinct sealed cohort.
    return [{"packet_id": packet_id, "slot_id": slot_by_packet[packet_id]} for packet_id in packet_ids]


def _base(value: Any) -> dict[str, Any]:
    item = _object(value, _BASE_FIELDS, "cohort")
    if item["schema_version"] != COHORT_SCHEMA_VERSION or isinstance(item["schema_version"], bool):
        _fail("cohort schema_version is invalid")
    if item["packet_schema_version"] != EXPECTED_PACKET_SCHEMA_VERSION or isinstance(item["packet_schema_version"], bool):
        _fail("packet_schema_version is incompatible")
    packet_refs = _packet_refs(item["packet_refs"])
    packet_ids = [ref["packet_id"] for ref in packet_refs]
    max_concurrency = _max_concurrency(item["max_concurrency"])
    dependencies = _dependencies(item["dependencies"], packet_ids)
    waves = _waves(item["waves"], packet_ids, dependencies, max_concurrency)
    return {
        "schema_version": COHORT_SCHEMA_VERSION,
        "cohort_id": _id(item["cohort_id"], "cohort_id"),
        "packet_schema_version": EXPECTED_PACKET_SCHEMA_VERSION,
        "packet_refs": packet_refs,
        "dependencies": dependencies,
        "waves": waves,
        "max_concurrency": max_concurrency,
        "transport_slots": _transport_slots(item["transport_slots"], packet_ids, waves),
        "failure_policy": _policy(item["failure_policy"], "failure_policy"),
        "cancel_policy": _policy(item["cancel_policy"], "cancel_policy"),
    }


def cohort_sha256(cohort: Mapping[str, Any]) -> str:
    """Return the canonical digest of the exact unsealed cohort plan."""

    try:
        return canonical_sha256(_base(cohort), max_bytes=MAX_COHORT_BYTES)
    except SemanticEventError as exc:
        raise CohortError(str(exc)) from exc


def seal_cohort(cohort: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and seal a cohort's immutable schedule and authority refs."""

    base = _base(cohort)
    try:
        base["cohort_sha256"] = canonical_sha256(base, max_bytes=MAX_COHORT_BYTES)
    except SemanticEventError as exc:
        raise CohortError(str(exc)) from exc
    return base


def validate_cohort(cohort: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a sealed cohort and return a detached canonical copy."""

    item = _object(cohort, _SEALED_FIELDS, "cohort")
    base = _base({key: item[key] for key in _BASE_FIELDS})
    expected = cohort_sha256(base)
    if item["cohort_sha256"] != expected:
        _fail("cohort_sha256 does not match cohort")
    return {**base, "cohort_sha256": expected}


def _packet_states(value: Any, packet_ids: list[str]) -> dict[str, dict[str, str | None]]:
    if not isinstance(value, Mapping):
        _fail("packet_states must be an object")
    if any(packet_id not in packet_ids for packet_id in value):
        _fail("packet_states names an unknown packet")
    states: dict[str, dict[str, str | None]] = {}
    for packet_id in packet_ids:
        raw = value.get(packet_id, {"status": "planned", "terminal_outcome": None})
        item = _object(raw, _STATE_FIELDS, "packet_state")
        status = item["status"]
        outcome = item["terminal_outcome"]
        if not isinstance(status, str) or status not in _STATUSES:
            _fail("packet_state.status is invalid; running requires start_observed")
        if status == "terminal":
            if not isinstance(outcome, str) or outcome not in _TERMINAL_OUTCOMES:
                _fail("terminal packet_state requires a terminal_outcome")
        elif outcome is not None:
            _fail("only terminal packet_state may carry terminal_outcome")
        states[packet_id] = {"status": status, "terminal_outcome": outcome}
    return states


def _is_success(state: Mapping[str, str | None]) -> bool:
    return state["status"] == "terminal" and state["terminal_outcome"] == "accepted"


def _is_terminal_or_cancelled(state: Mapping[str, str | None]) -> bool:
    return state["status"] in {"terminal", "cancelled"}


def cohort_projection_sha256(projection: Mapping[str, Any]) -> str:
    """Return a canonical digest of a cohort projection."""

    try:
        return canonical_sha256(_clone(projection), max_bytes=MAX_COHORT_BYTES)
    except SemanticEventError as exc:
        raise CohortError(str(exc)) from exc


def project_cohort(cohort: Mapping[str, Any], packet_states: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Project observed packet states without launching or cancelling transport.

    ``packet_states`` is a current-state mapping, not an arrival log.  Output
    order is fixed by the sealed packet and wave order, so equivalent terminal
    observations have the same next-wave decision regardless of delivery order.
    """

    item = validate_cohort(cohort)
    packet_ids = [ref["packet_id"] for ref in item["packet_refs"]]
    states = _packet_states({} if packet_states is None else packet_states, packet_ids)
    failure_triggered = any(
        state["status"] == "terminal" and state["terminal_outcome"] == "failed"
        for state in states.values()
    )
    cancellation_triggered = any(
        state["status"] == "cancelled"
        or (state["status"] == "terminal" and state["terminal_outcome"] == "cancelled")
        for state in states.values()
    )
    stop_remaining = (
        failure_triggered and item["failure_policy"] == "cancel_remaining"
    ) or (
        cancellation_triggered and item["cancel_policy"] == "cancel_remaining"
    )

    # Resolve the complete dependency closure before projecting waves.  A
    # direct failed dependency blocks a not-yet-started packet; that blocked
    # packet in turn blocks each not-yet-started dependent.  This fixed point
    # lets a later independent wave advance under ``continue`` while a failed
    # chain cannot stall the schedule forever.
    blocked_packet_ids: set[str] = set()
    changed = True
    while changed:
        changed = False
        for packet_id in packet_ids:
            state = states[packet_id]
            if packet_id in blocked_packet_ids or state["status"] not in {"planned", "armed"}:
                continue
            if any(
                dependency in blocked_packet_ids
                or (
                    _is_terminal_or_cancelled(states[dependency])
                    and not _is_success(states[dependency])
                )
                for dependency in item["dependencies"][packet_id]
            ):
                blocked_packet_ids.add(packet_id)
                changed = True

    wave_index_by_packet = {
        packet_id: wave_index
        for wave_index, wave in enumerate(item["waves"])
        for packet_id in wave
    }
    for packet_id in packet_ids:
        if states[packet_id]["status"] != "start_observed":
            continue
        if not all(_is_success(states[dependency]) for dependency in item["dependencies"][packet_id]):
            _fail("observed start requires successful dependencies")
        for prior_wave in item["waves"][:wave_index_by_packet[packet_id]]:
            if not all(
                _is_terminal_or_cancelled(states[prior_packet_id])
                or prior_packet_id in blocked_packet_ids
                for prior_packet_id in prior_wave
            ):
                _fail("observed start requires prior waves resolved")

    active_packet_ids = [
        packet_id for packet_id in packet_ids if states[packet_id]["status"] == "start_observed"
    ]
    if len(active_packet_ids) > item["max_concurrency"]:
        _fail("observed active starts exceed max_concurrency")
    slot_by_packet = {entry["packet_id"]: entry["slot_id"] for entry in item["transport_slots"]}
    active_slots = [slot_by_packet[packet_id] for packet_id in active_packet_ids]
    if len(set(active_slots)) != len(active_slots):
        _fail("observed active starts reuse a transport slot")

    prior_waves_resolved = True
    waves: list[dict[str, Any]] = []
    packet_rows: list[dict[str, Any]] = []
    for wave_index, wave in enumerate(item["waves"]):
        all_success = all(_is_success(states[packet_id]) for packet_id in wave)
        all_done = all(_is_terminal_or_cancelled(states[packet_id]) for packet_id in wave)
        packet_eligible = {
            packet_id: (
                not stop_remaining
                and prior_waves_resolved
                and states[packet_id]["status"] in {"planned", "armed"}
                and all(_is_success(states[dependency]) for dependency in item["dependencies"][packet_id])
            )
            for packet_id in wave
        }
        wave_eligible = any(packet_eligible.values())
        all_resolved = all(
            _is_terminal_or_cancelled(states[packet_id]) or packet_id in blocked_packet_ids
            for packet_id in wave
        )
        # An observed start is a fact, not an intent.  A later cancellation
        # request may block new work but cannot rewrite a live packet as
        # merely "blocked" until its actual terminal observation arrives.
        if any(states[packet_id]["status"] == "start_observed" for packet_id in wave):
            wave_status = "active"
        elif all_success:
            wave_status = "complete"
        elif all_done:
            wave_status = "terminal"
        elif wave_eligible:
            wave_status = "ready"
        elif all_resolved:
            wave_status = "blocked"
        elif stop_remaining:
            wave_status = "blocked"
        else:
            wave_status = "waiting"
        waves.append(
            {
                "wave_index": wave_index,
                "packet_ids": list(wave),
                "status": wave_status,
                "eligible": wave_eligible,
            }
        )
        for packet_id in wave:
            state = states[packet_id]
            packet_rows.append(
                {
                    "packet_id": packet_id,
                    "status": state["status"],
                    "terminal_outcome": state["terminal_outcome"],
                    "running": state["status"] == "start_observed",
                    "eligible": packet_eligible[packet_id],
                }
            )
        # Waves are an explicit launch schedule, not merely a display order.
        # "continue" relaxes the prior-success requirement only after the
        # earlier wave has terminally resolved or has become unlaunchable.
        prior_waves_resolved = prior_waves_resolved and all_resolved

    projection = {
        "schema_version": COHORT_SCHEMA_VERSION,
        "cohort_sha256": item["cohort_sha256"],
        "packet_schema_version": EXPECTED_PACKET_SCHEMA_VERSION,
        "transport_launch_claimed": False,
        "cancel_requested": stop_remaining,
        "packets": packet_rows,
        "waves": waves,
    }
    projection["projection_sha256"] = cohort_projection_sha256(projection)
    return projection
