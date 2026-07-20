"""Canonical AOI authority check for one Codex transport launch.

The launch intent and permit are deliberately insufficient on their own: a
self-consistent packet/routing tuple could otherwise name bytes that were
never committed by the task.  This module is called only while the AOI state
lock is held and proves the tuple against the live semantic task, the unique
armed dispatch attempt, and the authenticated routing projection.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any, NoReturn

from . import codex_transport_contracts as contracts
from . import dispatch_protocol
from . import harnesslib as h
from . import packet_integrity
from . import routing_authority
from . import routing_persistence
from . import semantic_events as semantic
from . import state_lookup
from . import transition_permits


CODEX_TRANSPORT_DISPATCH_PROVENANCE = "codex_app_server_reserved"
CODEX_TRANSPORT_ATTEMPT_STATUS = "transport_reserved"
CODEX_TRANSPORT_DISPATCH_MODEL_VERSION = 2


class CodexTransportAuthorityError(h.HarnessError):
    """The proposed launch is not owned by canonical live AOI authority."""


def _fail(message: str) -> NoReturn:
    raise CodexTransportAuthorityError(message)


def _aware(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail("current_time needs a timezone-aware datetime")
    return value


def _time(value: Any, label: str) -> datetime:
    try:
        parsed = h.parse_tz_aware_time(value)
    except (h.HarnessError, TypeError) as exc:
        raise CodexTransportAuthorityError(f"{label} is invalid: {exc}") from exc
    if parsed is None:
        _fail(f"{label} is invalid")
    return parsed


def _canonical_packet_authority(
    state: Mapping[str, Any], packet: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "task_id": state.get("task_id"),
        "packet_id": packet.get("packet_id"),
        "packet_contract_sha256": packet.get("packet_contract_sha256"),
        "task_plan_sha256": state.get("plan_sha256"),
        "delegation_depth": packet.get("delegation_depth", 1),
        "parent_packet_id": packet.get("parent_packet_id", ""),
        "agent_role": packet.get("agent_role"),
    }


def _require_attempt_matches_arm(
    state: Mapping[str, Any],
    packet: Mapping[str, Any],
    attempt: Mapping[str, Any],
    arm: Mapping[str, Any],
    *,
    current_time: datetime,
) -> None:
    if packet.get("status") != "armed":
        _fail("Codex launch packet is not in canonical armed state")
    expected_packet = _canonical_packet_authority(state, packet)
    if arm.get("packet_authority") != expected_packet:
        _fail("routing authority packet tuple differs from canonical task state")
    expected_attempt = {
        "attempt": attempt.get("attempt"),
        "arm_id": attempt.get("arm_id"),
        "armed_at": attempt.get("armed_at"),
        "expires_at": attempt.get("expires_at"),
    }
    if arm.get("attempt_identity") != expected_attempt:
        _fail("routing authority attempt tuple differs from the unique active arm")
    chief = arm.get("chief_authority")
    if not isinstance(chief, Mapping) or chief != {
        "session_id": attempt.get("chief_session_id"),
        "epoch": attempt.get("chief_epoch"),
        "authority_sha256": attempt.get("authority_sha256"),
    }:
        _fail("routing authority Chief tuple differs from the active arm")
    parent = arm.get("parent_authority")
    transport = arm.get("transport_authority")
    if (
        not isinstance(parent, Mapping)
        or parent.get("session_id") != attempt.get("parent_session_id")
        or not isinstance(transport, Mapping)
        or transport
        != {
            "transport": "codex",
            "expected_agent_type": attempt.get("expected_agent_type"),
        }
    ):
        _fail("routing authority transport tuple differs from the active arm")
    armed_at = _time(attempt.get("armed_at"), "active arm armed_at")
    expires_at = _time(attempt.get("expires_at"), "active arm expires_at")
    now = _aware(current_time)
    if now < armed_at or expires_at <= now:
        _fail("Codex launch active arm is not live at issuance time")


def _binding_for_group(group: Mapping[str, Any], arm: Mapping[str, Any]) -> dict[str, Any]:
    authority_sha256 = routing_authority.authority_sha256(arm)
    common: dict[str, Any] = {
        "kind": "standalone",
        "routing_authority_sha256": authority_sha256,
        "transport": arm["transport_authority"]["transport"],
        "parent_session_id": arm["parent_authority"]["session_id"],
        "expected_agent_type": arm["transport_authority"]["expected_agent_type"],
    }
    if group.get("composite_kind") != "cohort":
        if group.get("composite") is not True:
            _fail("standalone Codex launch lacks a permitted packet.arm binding")
        return common
    plan = group.get("cohort_plan")
    decision = group.get("decision")
    if not isinstance(plan, Mapping) or not isinstance(decision, Mapping):
        _fail("cohort routing group lacks its exact plan or decision")
    parameters = decision.get("parameters")
    if not isinstance(parameters, Mapping):
        _fail("cohort routing group decision parameters are invalid")
    packet_id = arm["packet_authority"]["packet_id"]
    slots = [
        slot
        for slot in plan.get("transport_slots", [])
        if isinstance(slot, Mapping) and slot.get("packet_id") == packet_id
    ]
    if len(slots) != 1:
        _fail("cohort routing group lacks one exact packet transport slot")
    slot = slots[0]
    return {
        **common,
        "kind": "cohort",
        "cohort_id": plan.get("cohort_id"),
        "cohort_sha256": plan.get("cohort_sha256"),
        "wave_index": parameters.get("wave_index"),
        "transport_slot_sha256": slot.get("slot_sha256"),
    }


def _sealed_launch_authority(
    state: Mapping[str, Any],
    packet: Mapping[str, Any],
    attempt: Mapping[str, Any],
    intent: Mapping[str, Any],
    routing_binding: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        return contracts.seal_launch_authority(
            {
                "contract_type": contracts.CODEX_LAUNCH_AUTHORITY_V1,
                "task_id": state["task_id"],
                "packet_id": packet["packet_id"],
                "packet_contract_sha256": packet["packet_contract_sha256"],
                "attempt_number": attempt["attempt"],
                "arm_id": attempt["arm_id"],
                "armed_at": attempt["armed_at"],
                "expires_at": attempt["expires_at"],
                "dispatch_attempt_authority_sha256": attempt[
                    "arm_authority_sha256"
                ],
                "chief_authority_sha256": attempt["authority_sha256"],
                "parent_session_id": attempt["parent_session_id"],
                "expected_agent_type": attempt["expected_agent_type"],
                "routing_binding": dict(routing_binding),
                "expected_semantic_head_sha256": intent[
                    "expected_semantic_head_sha256"
                ],
                "launch_intent_sha256": intent["intent_sha256"],
            }
        )
    except (KeyError, contracts.CodexTransportContractError) as exc:
        raise CodexTransportAuthorityError(
            f"cannot seal canonical Codex launch authority: {exc}"
        ) from exc


def _require_authority_matches_live_arm(
    authority: Mapping[str, Any],
    state: Mapping[str, Any],
    packet: Mapping[str, Any],
    attempt: Mapping[str, Any],
    intent: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        checked = contracts.validate_launch_authority(authority)
    except contracts.CodexTransportContractError as exc:
        raise CodexTransportAuthorityError(
            f"Codex launch authority contract is invalid: {exc}"
        ) from exc
    expected = _sealed_launch_authority(
        state, packet, attempt, intent, intent["routing_binding"]
    )
    if checked != expected:
        _fail("Codex launch authority differs from the exact active packet arm")
    return checked


def reserve_packet_for_codex_launch(
    state: Mapping[str, Any],
    *,
    intent: Mapping[str, Any],
    permit: Mapping[str, Any],
    reservation: Mapping[str, Any],
    launch_authority: Mapping[str, Any],
    launch_id: str,
    reservation_effective_at: str,
) -> dict[str, Any]:
    """Atomically consume one arm into truthful bridge ownership.

    The result is a detached semantic domain.  No hook observation, runtime
    agent id, thread id, or turn id is invented at this boundary.
    """

    try:
        domain = semantic.projection_domain(state)
        checked_intent = contracts.validate_launch_intent(intent)
        checked_reservation = contracts.validate_reservation(reservation)
        checked_authority = contracts.validate_launch_authority(launch_authority)
        checked_permit = transition_permits.validate_transition_permit(permit)
        identity = h.validate_id(launch_id, "Codex launch id")
        if checked_permit["action"] != "codex.launch":
            _fail("packet ownership requires a codex.launch permit")
        packet = state_lookup._packet_by_id(domain, checked_intent["packet_id"])
        attempt = dispatch_protocol.active_dispatch_attempt(packet)
        _require_authority_matches_live_arm(
            checked_authority, domain, packet, attempt, checked_intent
        )
        if checked_reservation["permit_sha256"] != checked_permit["permit_sha256"]:
            _fail("packet ownership reservation binds another permit")
        if (
            checked_reservation["launch_intent_sha256"]
            != checked_intent["intent_sha256"]
        ):
            _fail("packet ownership reservation binds another launch intent")
        if checked_permit["parameters"]["launch_id"] != identity:
            _fail("packet ownership permit binds another launch id")
        armed_at = _time(checked_authority["armed_at"], "launch authority armed_at")
        arm_expires = _time(
            checked_authority["expires_at"], "launch authority expires_at"
        )
        permit_expires = _time(
            checked_permit["expires_at"], "launch permit expires_at"
        )
        recorded = _time(
            reservation_effective_at,
            "packet ownership reservation_effective_at",
        )
        if permit_expires > arm_expires:
            _fail("Codex launch permit expires after its packet arm")
        if recorded < armed_at or recorded >= arm_expires:
            _fail(
                "packet ownership reservation_effective_at is outside the packet arm window"
            )
        ownership = contracts.seal_packet_transport_ownership(
            {
                "contract_type": contracts.CODEX_PACKET_TRANSPORT_OWNERSHIP_V1,
                "task_id": checked_intent["task_id"],
                "packet_id": checked_intent["packet_id"],
                "launch_id": identity,
                "arm_id": checked_authority["arm_id"],
                "launch_intent_sha256": checked_intent["intent_sha256"],
                "permit_sha256": checked_permit["permit_sha256"],
                "reservation_sha256": checked_reservation["reservation_sha256"],
                "launch_authority_sha256": checked_authority[
                    "launch_authority_sha256"
                ],
                "routing_authority_sha256": checked_intent["routing_binding"][
                    "routing_authority_sha256"
                ],
                "reservation_effective_at": reservation_effective_at,
                "owner_kind": "codex_app_server_stdio",
            }
        )
    except CodexTransportAuthorityError:
        raise
    except (
        KeyError,
        TypeError,
        ValueError,
        h.HarnessError,
        semantic.SemanticEventError,
        contracts.CodexTransportContractError,
        transition_permits.TransitionPermitError,
    ) as exc:
        raise CodexTransportAuthorityError(
            f"cannot reserve packet for Codex transport: {exc}"
        ) from exc

    attempt["status"] = CODEX_TRANSPORT_ATTEMPT_STATUS
    attempt["observation"] = None
    attempt["closed_at"] = reservation_effective_at
    attempt["reason"] = ""
    attempt["transport_ownership"] = dict(ownership)
    packet["status"] = "dispatched"
    packet["dispatch_provenance"] = CODEX_TRANSPORT_DISPATCH_PROVENANCE
    packet["dispatch_recorded_at"] = reservation_effective_at
    packet["transport_ownership"] = dict(ownership)
    packet["dispatch_version"] = CODEX_TRANSPORT_DISPATCH_MODEL_VERSION
    packet["updated_at"] = reservation_effective_at
    domain["dispatch_model_version"] = CODEX_TRANSPORT_DISPATCH_MODEL_VERSION
    packet.pop("agent_id", None)
    packet.pop("manual_unverified_reason", None)
    revision = domain.get("revision")
    if isinstance(revision, int) and not isinstance(revision, bool):
        domain["revision"] = revision + 1
        domain["updated_at"] = reservation_effective_at
        domain["checkpoint_required"] = True
    return domain


def require_canonical_launch_authority(
    paths: h.HarnessPaths,
    *,
    task_id: str,
    intent: Mapping[str, Any],
    event_chain: Iterable[Mapping[str, Any]],
    current_time: datetime,
    packet_integrity_services: packet_integrity.PacketIntegrityServices,
) -> dict[str, Any]:
    """Prove one sealed intent against live packet and routing authority.

    The caller must hold AOI's state lock.  The returned record is diagnostic;
    the durable proof is the intent's exact semantic head plus the immutable
    routing objects already committed under that head.
    """

    h._require_chief_lock(paths)
    checked_intent = contracts.validate_launch_intent(intent)
    if checked_intent["task_id"] != h.validate_id(task_id, "task id"):
        _fail("launch intent belongs to another task")
    records = [dict(row) for row in event_chain]
    try:
        state = h.load_task(paths, task_id)
        envelope = state.get(semantic.SEMANTIC_ENVELOPE_KEY)
        if (
            not isinstance(envelope, Mapping)
            or envelope.get("head_event_sha256")
            != checked_intent["expected_semantic_head_sha256"]
        ):
            _fail("canonical task state differs from the launch semantic head")
        packet = state_lookup._packet_by_id(state, checked_intent["packet_id"])
        errors = packet_integrity.packet_authority_integrity_errors(
            paths,
            state,
            packet,
            require_origin=True,
            services=packet_integrity_services,
        )
        if errors:
            _fail("Codex launch packet authority is invalid: " + "; ".join(errors))
        attempt = dispatch_protocol.active_dispatch_attempt(packet)
        report = routing_persistence.inspect_routing_persistence(
            paths, task_id, records
        )
    except CodexTransportAuthorityError:
        raise
    except (
        h.HarnessError,
        routing_persistence.RoutingPersistenceError,
        TypeError,
        ValueError,
    ) as exc:
        raise CodexTransportAuthorityError(
            f"cannot authenticate canonical Codex launch authority: {exc}"
        ) from exc

    binding = checked_intent["routing_binding"]
    matches: list[dict[str, Any]] = []
    for raw_group in report.get("groups", []):
        if not isinstance(raw_group, dict):
            _fail("routing report contains a malformed group")
        if raw_group.get("stage") != "authority" or raw_group.get("classification") != "committed":
            continue
        raw_arm = raw_group.get("authority")
        if not isinstance(raw_arm, Mapping):
            continue
        try:
            arm = routing_authority.validate_arm_authority(raw_arm)
            authority_sha256 = routing_authority.authority_sha256(arm)
        except routing_authority.RoutingAuthorityError as exc:
            raise CodexTransportAuthorityError(
                f"routing report contains invalid launch authority: {exc}"
            ) from exc
        if authority_sha256 == binding["routing_authority_sha256"]:
            matches.append({**raw_group, "authority": arm})
    if len(matches) != 1:
        _fail("launch routing authority is not one unique committed authority group")
    group = matches[0]
    arm = group["authority"]
    route_object = group.get("objects", {}).get("routing_authority")
    if (
        not isinstance(route_object, Mapping)
        or route_object.get("object_identity")
        != binding["routing_authority_sha256"]
    ):
        _fail("launch routing semantic object identity is invalid")
    _require_attempt_matches_arm(
        state, packet, attempt, arm, current_time=current_time
    )
    expected_binding = _binding_for_group(group, arm)
    if binding != expected_binding:
        _fail("launch routing binding differs from canonical routing authority")
    if binding["kind"] == "cohort":
        plan = group["cohort_plan"]
        wave_index = binding["wave_index"]
        if (
            not isinstance(wave_index, int)
            or isinstance(wave_index, bool)
            or not 0 <= wave_index < len(plan["waves"])
            or checked_intent["packet_id"] not in plan["waves"][wave_index]
        ):
            _fail("launch packet is not selected by the canonical cohort wave")
    return _sealed_launch_authority(
        state, packet, attempt, checked_intent, expected_binding
    )


__all__ = [
    "CODEX_TRANSPORT_ATTEMPT_STATUS",
    "CODEX_TRANSPORT_DISPATCH_PROVENANCE",
    "CodexTransportAuthorityError",
    "require_canonical_launch_authority",
    "reserve_packet_for_codex_launch",
]
