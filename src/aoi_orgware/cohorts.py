"""Pure deterministic cohort planning and projection (no transport launch).

The schema binds a v6 packet authority reference to a fixed dependency graph
and wave plan.  Its execution-selection references seal both the selection
identity and the immutable v2 target contract; the integration layer still
has to prove that exact contract is active at the authorized semantic head.
It intentionally does *not* dispatch a packet, reserve a real
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
COHORT_ADVANCE_SELECTION_SCHEMA_VERSION = 1
EXPECTED_PACKET_SCHEMA_VERSION = 6
MAX_COHORT_BYTES = 64 * 1024
MAX_COHORT_PACKETS = 1_024
MAX_COHORT_WAVES = MAX_COHORT_PACKETS
MAX_CONCURRENCY = 12

_SHA256 = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_PARENT_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,511}")
_CANONICAL_AGENT_TYPES = frozenset(
    {
        "architect",
        "batch",
        "default",
        "eda_expert",
        "eda_operator",
        "explorer",
        "numeric_debugger",
        "reviewer",
        "rtl_engineer",
        "worker",
    }
)
_BASE_FIELDS = {
    "schema_version",
    "cohort_id",
    "packet_schema_version",
    "resource_envelope_sha256",
    "execution_selection_identity_sha256",
    "execution_selection_target_contract_sha256",
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
_SLOT_FIELDS = {"packet_id", "transport", "parent_session_id", "expected_agent_type"}
_SEALED_SLOT_FIELDS = _SLOT_FIELDS | {"slot_sha256"}
_ADVANCE_ROUTE_FIELDS = {
    "packet_id",
    "routing_authority_sha256",
    "outcome_slot_sha256",
}
_ADVANCE_SELECTION_FIELDS = {
    "schema_version",
    "cohort_sha256",
    "wave_index",
    "routes",
}
_SEALED_ADVANCE_SELECTION_FIELDS = _ADVANCE_SELECTION_FIELDS | {
    "selection_sha256"
}
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


def _parent_session_id(value: Any) -> str:
    if not isinstance(value, str) or not _PARENT_SESSION_ID.fullmatch(value):
        _fail("transport_slot.parent_session_id is invalid")
    return value


def _expected_agent_type(value: Any) -> str:
    if not isinstance(value, str) or (value != "*" and value not in _CANONICAL_AGENT_TYPES):
        _fail("transport_slot.expected_agent_type is invalid")
    return value


def _slot_identity(slot: Mapping[str, str]) -> dict[str, str]:
    return {
        "transport": slot["transport"],
        "parent_session_id": slot["parent_session_id"],
        "expected_agent_type": slot["expected_agent_type"],
    }


def _slots_collide(left: Mapping[str, str], right: Mapping[str, str]) -> bool:
    return left["parent_session_id"] == right["parent_session_id"] and (
        left["expected_agent_type"] == "*"
        or right["expected_agent_type"] == "*"
        or left["expected_agent_type"] == right["expected_agent_type"]
    )


def _transport_slots(value: Any, packet_ids: list[str], *, sealed: bool) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) != len(packet_ids):
        _fail("transport_slots is invalid")
    seen_packets: set[str] = set()
    slot_by_packet: dict[str, dict[str, str]] = {}
    for entry in value:
        item = _object(entry, _SEALED_SLOT_FIELDS if sealed else _SLOT_FIELDS, "transport_slot")
        packet_id = _id(item["packet_id"], "transport_slot.packet_id")
        if packet_id not in packet_ids:
            _fail("transport_slots names an unknown packet")
        if packet_id in seen_packets:
            _fail("transport_slots contains duplicate packet references")
        if item["transport"] != "codex":
            _fail("transport_slot.transport is invalid")
        slot = {
            "packet_id": packet_id,
            "transport": "codex",
            "parent_session_id": _parent_session_id(item["parent_session_id"]),
            "expected_agent_type": _expected_agent_type(item["expected_agent_type"]),
        }
        slot_sha256 = canonical_sha256(_slot_identity(slot), max_bytes=MAX_COHORT_BYTES)
        if sealed:
            if item["slot_sha256"] != slot_sha256:
                _fail("transport_slot.slot_sha256 does not match slot")
        slot["slot_sha256"] = slot_sha256
        seen_packets.add(packet_id)
        slot_by_packet[packet_id] = slot
    # The packet list is the schedule's canonical identity.  Input order of a
    # mapping-like slot list must not create a distinct sealed cohort.
    return [slot_by_packet[packet_id] for packet_id in packet_ids]


def _base(value: Any, *, sealed_slots: bool = False) -> dict[str, Any]:
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
        # These are sealed references only.  The integration layer must prove
        # the exact target contract is the one active at the authorized head,
        # bind it to every arm's applied resource event/dynamic envelope, and
        # then re-derive live caps.
        "resource_envelope_sha256": _sha(item["resource_envelope_sha256"], "resource_envelope_sha256"),
        "execution_selection_identity_sha256": _sha(
            item["execution_selection_identity_sha256"],
            "execution_selection_identity_sha256",
        ),
        "execution_selection_target_contract_sha256": _sha(
            item["execution_selection_target_contract_sha256"],
            "execution_selection_target_contract_sha256",
        ),
        "packet_refs": packet_refs,
        "dependencies": dependencies,
        "waves": waves,
        "max_concurrency": max_concurrency,
        "transport_slots": _transport_slots(item["transport_slots"], packet_ids, sealed=sealed_slots),
        "failure_policy": _policy(item["failure_policy"], "failure_policy"),
        "cancel_policy": _policy(item["cancel_policy"], "cancel_policy"),
    }


def cohort_sha256(cohort: Mapping[str, Any]) -> str:
    """Return the canonical digest of the exact unsealed cohort plan."""

    try:
        return canonical_sha256(_base(cohort), max_bytes=MAX_COHORT_BYTES)
    except SemanticEventError as exc:
        raise CohortError(str(exc)) from exc


def execution_selection_identity_sha256(execution_selection_id: str) -> str:
    """Hash the exact non-empty execution-selection identity used by an arm.

    This digest binds identity only.  It is not a digest of the mutable task
    selection record or a substitute for integration-time active-state checks.
    """

    identity = {
        "schema_version": 1,
        "execution_selection_id": _id(
            execution_selection_id, "execution_selection_id"
        ),
    }
    try:
        return canonical_sha256(identity, max_bytes=MAX_COHORT_BYTES)
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
    base = _base({key: item[key] for key in _BASE_FIELDS}, sealed_slots=True)
    try:
        expected = canonical_sha256(base, max_bytes=MAX_COHORT_BYTES)
    except SemanticEventError as exc:
        raise CohortError(str(exc)) from exc
    if item["cohort_sha256"] != expected:
        _fail("cohort_sha256 does not match cohort")
    return {**base, "cohort_sha256": expected}


def _wave_index(value: Any, cohort: Mapping[str, Any]) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value < len(cohort["waves"])
    ):
        _fail("cohort advance wave_index is invalid")
    return value


def _advance_selection_base(
    cohort: Mapping[str, Any], value: Any
) -> dict[str, Any]:
    item = _object(value, _ADVANCE_SELECTION_FIELDS, "cohort advance selection")
    if (
        item["schema_version"] != COHORT_ADVANCE_SELECTION_SCHEMA_VERSION
        or isinstance(item["schema_version"], bool)
    ):
        _fail("cohort advance selection schema_version is invalid")
    checked_cohort = validate_cohort(cohort)
    if item["cohort_sha256"] != checked_cohort["cohort_sha256"]:
        _fail("cohort advance selection names another cohort")
    wave_index = _wave_index(item["wave_index"], checked_cohort)
    routes = item["routes"]
    if (
        not isinstance(routes, list)
        or not routes
        or len(routes) > checked_cohort["max_concurrency"]
    ):
        _fail("cohort advance routes are invalid or over capacity")
    refs = {
        ref["packet_id"]: ref["routing_authority_sha256"]
        for ref in checked_cohort["packet_refs"]
    }
    wave = checked_cohort["waves"][wave_index]
    wave_position = {packet_id: index for index, packet_id in enumerate(wave)}
    checked_routes: list[dict[str, str]] = []
    seen_packets: set[str] = set()
    seen_slots: set[str] = set()
    prior_position = -1
    for raw in routes:
        route = _object(raw, _ADVANCE_ROUTE_FIELDS, "cohort advance route")
        packet_id = _id(route["packet_id"], "cohort advance route packet_id")
        if packet_id not in wave_position:
            _fail("cohort advance route names a packet outside its wave")
        position = wave_position[packet_id]
        if packet_id in seen_packets or position <= prior_position:
            _fail("cohort advance routes are duplicate or out of wave order")
        routing_authority_sha256 = _sha(
            route["routing_authority_sha256"],
            "cohort advance routing authority SHA-256",
        )
        if refs[packet_id] != routing_authority_sha256:
            _fail("cohort advance route differs from sealed packet authority")
        outcome_slot_sha256 = _sha(
            route["outcome_slot_sha256"], "cohort advance outcome slot SHA-256"
        )
        if outcome_slot_sha256 in seen_slots:
            _fail("cohort advance routes contain a duplicate outcome slot")
        checked_routes.append(
            {
                "packet_id": packet_id,
                "routing_authority_sha256": routing_authority_sha256,
                "outcome_slot_sha256": outcome_slot_sha256,
            }
        )
        seen_packets.add(packet_id)
        seen_slots.add(outcome_slot_sha256)
        prior_position = position
    return {
        "schema_version": COHORT_ADVANCE_SELECTION_SCHEMA_VERSION,
        "cohort_sha256": checked_cohort["cohort_sha256"],
        "wave_index": wave_index,
        "routes": checked_routes,
    }


def cohort_advance_selection_sha256(
    cohort: Mapping[str, Any],
    selection: Mapping[str, Any],
    packet_states: Mapping[str, Any] | None,
    *,
    available_capacity: int | None = None,
) -> str:
    """Hash one exact eligible ordered subset of a sealed cohort wave."""

    try:
        base = _advance_selection_base(cohort, selection)
        _require_eligible_selection(
            cohort,
            packet_states,
            base,
            available_capacity=available_capacity,
        )
        return canonical_sha256(base, max_bytes=MAX_COHORT_BYTES)
    except SemanticEventError as exc:
        raise CohortError(str(exc)) from exc


def seal_cohort_advance_selection(
    cohort: Mapping[str, Any],
    selection: Mapping[str, Any],
    packet_states: Mapping[str, Any] | None,
    *,
    available_capacity: int | None = None,
) -> dict[str, Any]:
    """Seal packet, authority, and routing-slot identities for one advance."""

    base = _advance_selection_base(cohort, selection)
    _require_eligible_selection(
        cohort,
        packet_states,
        base,
        available_capacity=available_capacity,
    )
    try:
        base["selection_sha256"] = canonical_sha256(
            base, max_bytes=MAX_COHORT_BYTES
        )
    except SemanticEventError as exc:
        raise CohortError(str(exc)) from exc
    return base


def validate_cohort_advance_selection(
    cohort: Mapping[str, Any],
    selection: Mapping[str, Any],
    packet_states: Mapping[str, Any] | None,
    *,
    available_capacity: int | None = None,
) -> dict[str, Any]:
    """Validate a sealed exact cohort advance selection."""

    item = _object(
        selection,
        _SEALED_ADVANCE_SELECTION_FIELDS,
        "sealed cohort advance selection",
    )
    base = _advance_selection_base(
        cohort, {key: item[key] for key in _ADVANCE_SELECTION_FIELDS}
    )
    _require_eligible_selection(
        cohort,
        packet_states,
        base,
        available_capacity=available_capacity,
    )
    try:
        expected = canonical_sha256(base, max_bytes=MAX_COHORT_BYTES)
    except SemanticEventError as exc:
        raise CohortError(str(exc)) from exc
    if item["selection_sha256"] != expected:
        _fail("cohort advance selection SHA-256 does not match selection")
    return {**base, "selection_sha256": expected}


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
    slot_by_packet = {entry["packet_id"]: entry for entry in item["transport_slots"]}
    armed_packet_ids = [
        packet_id for packet_id in packet_ids if states[packet_id]["status"] == "armed"
    ]
    for index, packet_id in enumerate(armed_packet_ids):
        if any(
            _slots_collide(slot_by_packet[packet_id], slot_by_packet[other_packet_id])
            for other_packet_id in armed_packet_ids[index + 1 :]
        ):
            _fail("simultaneously armed packets collide in a transport slot")
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
        # An already-armed slot wins over any still-planned colliding packet,
        # regardless of plan order.  Otherwise an adversarial state with a
        # later packet armed could make an earlier colliding packet appear
        # eligible and permit two simultaneous arms for one transport slot.
        for packet_id in wave:
            if states[packet_id]["status"] != "planned":
                continue
            if any(
                states[other_packet_id]["status"] == "armed"
                and _slots_collide(
                    slot_by_packet[packet_id], slot_by_packet[other_packet_id]
                )
                for other_packet_id in packet_ids
                if other_packet_id != packet_id
            ):
                packet_eligible[packet_id] = False
        # A slot is only a deterministic pre-arm ordering constraint.  Once a
        # start has been observed, a following packet may be pre-armed even if
        # the earlier execution is still live; integration owns live capacity.
        for index, packet_id in enumerate(wave):
            if not packet_eligible[packet_id]:
                continue
            if any(
                packet_eligible[prior_packet_id]
                and states[prior_packet_id]["status"] in {"planned", "armed"}
                and _slots_collide(slot_by_packet[prior_packet_id], slot_by_packet[packet_id])
                for prior_packet_id in wave[:index]
            ):
                packet_eligible[packet_id] = False
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


def eligible_cohort_wave_packet_ids(
    cohort: Mapping[str, Any],
    packet_states: Mapping[str, Any] | None,
    *,
    wave_index: int,
    available_capacity: int | None = None,
) -> list[str]:
    """Return the deterministic, not-yet-armed selection for one manual round.

    This function only chooses identities from a supplied current-state view.
    It neither creates routing authority nor claims a transport launch.
    """

    checked = validate_cohort(cohort)
    wave_index = _wave_index(wave_index, checked)
    states = _packet_states({} if packet_states is None else packet_states, [
        ref["packet_id"] for ref in checked["packet_refs"]
    ])
    inflight = sum(
        state["status"] in {"armed", "start_observed"}
        for state in states.values()
    )
    local_available = max(0, checked["max_concurrency"] - inflight)
    if available_capacity is None:
        external_available = checked["max_concurrency"]
    elif (
        not isinstance(available_capacity, int)
        or isinstance(available_capacity, bool)
        or not 0 <= available_capacity <= MAX_CONCURRENCY
    ):
        _fail("cohort advance available capacity is invalid")
    else:
        external_available = available_capacity
    budget = min(local_available, external_available)
    projection = project_cohort(checked, packet_states)
    by_packet = {row["packet_id"]: row for row in projection["packets"]}
    candidates = [
        packet_id
        for packet_id in checked["waves"][wave_index]
        if by_packet[packet_id]["status"] == "planned"
        and by_packet[packet_id]["eligible"]
    ]
    return candidates[:budget]


def _require_eligible_selection(
    cohort: Mapping[str, Any],
    packet_states: Mapping[str, Any] | None,
    selection: Mapping[str, Any],
    *,
    available_capacity: int | None,
) -> None:
    expected = eligible_cohort_wave_packet_ids(
        cohort,
        packet_states,
        wave_index=selection["wave_index"],
        available_capacity=available_capacity,
    )
    selected = [route["packet_id"] for route in selection["routes"]]
    if not expected or selected != expected:
        _fail("cohort advance routes are not the exact eligible round selection")


__all__ = [
    "COHORT_ADVANCE_SELECTION_SCHEMA_VERSION",
    "COHORT_SCHEMA_VERSION",
    "EXPECTED_PACKET_SCHEMA_VERSION",
    "MAX_COHORT_BYTES",
    "MAX_COHORT_PACKETS",
    "MAX_COHORT_WAVES",
    "MAX_CONCURRENCY",
    "CohortError",
    "cohort_advance_selection_sha256",
    "cohort_projection_sha256",
    "cohort_sha256",
    "eligible_cohort_wave_packet_ids",
    "execution_selection_identity_sha256",
    "project_cohort",
    "seal_cohort",
    "seal_cohort_advance_selection",
    "validate_cohort",
    "validate_cohort_advance_selection",
]
