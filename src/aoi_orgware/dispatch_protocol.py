"""Sub-agent dispatch observation independent of CLI parsing.

AOI packet roles describe the technical work contract.  Codex ``agent_type``
values are transport labels observed by the SubagentStart hook.  The two are
deliberately separate: an arm is consumed only by its exact parent session and
expected transport type, while packet-role authority remains in the packet and
is validated by services injected from the CLI composition root.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

from .harnesslib import (
    HarnessError,
    HarnessPaths,
    bump_task,
    load_json,
    load_task,
    now_iso,
    parse_time,
    session_path,
    state_lock,
    write_task,
)


@dataclass(frozen=True)
class DispatchProtocolPolicy:
    """Immutable protocol constants used while observing one hook event."""

    hook_protocol_version: int
    hook_id_re: re.Pattern[str]
    executing_packet_statuses: frozenset[str]
    root_session_mapping_kind: str = "root"
    subagent_parent_mapping_kind: str = "subagent_parent"
    observation_text_limit: int = 512
    dispatch_model_version: int = 1
    dispatch_provenance: str = "codex_subagent_start_observed"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "executing_packet_statuses",
            frozenset(self.executing_packet_statuses),
        )
        if self.hook_protocol_version < 1:
            raise ValueError("hook protocol version must be positive")
        if self.observation_text_limit < 1:
            raise ValueError("observation text limit must be positive")
        if self.dispatch_model_version < 1:
            raise ValueError("dispatch model version must be positive")
        if not self.dispatch_provenance:
            raise ValueError("dispatch provenance must be a non-empty label")


class PacketById(Protocol):
    def __call__(
        self, state: dict[str, Any], packet_id: str
    ) -> dict[str, Any]: ...


class PacketAuthorityIntegrityErrors(Protocol):
    def __call__(
        self,
        paths: HarnessPaths,
        state: dict[str, Any],
        packet: dict[str, Any],
        *,
        require_origin: bool,
    ) -> list[str]: ...


class ValidateObservedArm(Protocol):
    def __call__(
        self,
        paths: HarnessPaths,
        state: dict[str, Any],
        packet: dict[str, Any],
        attempt: dict[str, Any],
        *,
        parent_session_id: str,
        transport_agent_type: str,
        current: dt.datetime,
    ) -> None: ...


class EnsureSubagentParentMapping(Protocol):
    def __call__(
        self,
        paths: HarnessPaths,
        state: dict[str, Any],
        packet: dict[str, Any],
    ) -> Any: ...


class RefreshIndexAfterCommit(Protocol):
    def __call__(self, paths: HarnessPaths) -> bool: ...


@dataclass(frozen=True)
class DispatchProtocolServices:
    """Authority and derived-state operations supplied by the composition root."""

    packet_by_id: PacketById
    packet_authority_integrity_errors: PacketAuthorityIntegrityErrors
    validate_observed_arm: ValidateObservedArm
    ensure_subagent_parent_mapping: EnsureSubagentParentMapping
    refresh_index_after_commit: RefreshIndexAfterCommit


def _canonical_record_sha256(value: dict[str, Any]) -> str:
    payload = json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def active_dispatch_attempt(packet: dict[str, Any]) -> dict[str, Any]:
    """Return the unique live arm for a packet or fail closed."""

    attempts = packet.get("dispatch_attempts", [])
    matches = [
        attempt
        for attempt in attempts
        if isinstance(attempt, dict) and attempt.get("status") == "armed"
    ]
    if len(matches) != 1:
        raise HarnessError(
            f"armed packet {packet.get('packet_id')} must have exactly one active arm"
        )
    return matches[0]


def validate_hook_identity(
    value: Any, label: str, *, policy: DispatchProtocolPolicy
) -> str:
    text = str(value or "")
    if (
        not policy.hook_id_re.fullmatch(text)
        or "\x00" in text
        or "\n" in text
        or "\r" in text
    ):
        raise HarnessError(f"{label} is missing or unsafe")
    return text


def safe_hook_observation_text(
    value: Any, *, policy: DispatchProtocolPolicy
) -> str:
    text = str(value or "")
    if len(text) > policy.observation_text_limit or any(
        character in text for character in ("\x00", "\n", "\r")
    ):
        return ""
    return text


def expire_dispatch_arms(
    state: dict[str, Any], *, current: dt.datetime
) -> list[dict[str, str]]:
    """Expire stale arms and return their transport matching coordinates."""

    expired: list[dict[str, str]] = []
    closed_at = current.isoformat(timespec="microseconds")
    for packet in state.get("packets", []):
        if packet.get("status") != "armed":
            continue
        attempt = active_dispatch_attempt(packet)
        expires_at = parse_time(str(attempt.get("expires_at", "")))
        if expires_at is None or expires_at > current:
            continue
        attempt["status"] = "expired"
        attempt["closed_at"] = closed_at
        attempt["reason"] = "Arm expired before an observed SubagentStart event."
        packet["status"] = "ready"
        packet["updated_at"] = closed_at
        expired.append(
            {
                "packet_id": str(packet.get("packet_id", "")),
                "parent_session_id": str(attempt.get("parent_session_id", "")),
                "expected_agent_type": str(attempt.get("expected_agent_type", "")),
            }
        )
    return expired


def subagent_event_id(
    payload: dict[str, Any], *, policy: DispatchProtocolPolicy
) -> str:
    identity = {
        "session_id": safe_hook_observation_text(
            payload.get("session_id", ""), policy=policy
        ),
        "turn_id": safe_hook_observation_text(
            payload.get("turn_id", ""), policy=policy
        ),
        "agent_id": safe_hook_observation_text(
            payload.get("agent_id", ""), policy=policy
        ),
        "agent_type": safe_hook_observation_text(
            payload.get("agent_type", ""), policy=policy
        ),
        "hook_protocol_version": policy.hook_protocol_version,
    }
    return "spawn-" + _canonical_record_sha256(identity)[:32]


def record_subagent_incident(
    state: dict[str, Any],
    payload: dict[str, Any],
    *,
    reason_code: str,
    candidate_packet_ids: list[str],
    observed_at: str,
    policy: DispatchProtocolPolicy,
) -> dict[str, Any]:
    """Idempotently record an unmanaged SubagentStart event."""

    incident_id = subagent_event_id(payload, policy=policy)
    existing = [
        item
        for item in state.get("subagent_incidents", [])
        if item.get("incident_id") == incident_id
    ]
    if existing:
        return existing[0]
    incident = {
        "incident_id": incident_id,
        "kind": "unmanaged_subagent_start",
        "status": "open",
        "parent_session_id": safe_hook_observation_text(
            payload.get("session_id", ""), policy=policy
        ),
        "turn_id": safe_hook_observation_text(
            payload.get("turn_id", ""), policy=policy
        ),
        "agent_id": safe_hook_observation_text(
            payload.get("agent_id", ""), policy=policy
        ),
        "agent_type": safe_hook_observation_text(
            payload.get("agent_type", ""), policy=policy
        ),
        "observed_at": observed_at,
        "reason_code": reason_code,
        "candidate_packet_ids": sorted(set(candidate_packet_ids)),
        "hook_protocol_version": policy.hook_protocol_version,
        "resolution": None,
    }
    state["dispatch_model_version"] = policy.dispatch_model_version
    state.setdefault("subagent_incidents", []).append(incident)
    return incident


def matching_armed_packets(
    state: dict[str, Any],
    *,
    parent_session_id: str,
    transport_agent_type: str,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Match arms by transport coordinates, never by the AOI packet role."""

    matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for packet in state.get("packets", []):
        if packet.get("status") != "armed":
            continue
        attempt = active_dispatch_attempt(packet)
        if (
            attempt.get("parent_session_id") == parent_session_id
            and attempt.get("expected_agent_type") == transport_agent_type
        ):
            matches.append((packet, attempt))
    return matches


def matching_expired_packet_ids(
    expired_arms: list[dict[str, str]],
    *,
    parent_session_id: str,
    transport_agent_type: str,
) -> list[str]:
    return [
        item["packet_id"]
        for item in expired_arms
        if item["parent_session_id"] == parent_session_id
        and item["expected_agent_type"] == transport_agent_type
    ]


def _load_mapped_task_unlocked(
    paths: HarnessPaths,
    parent_session_id: str,
    *,
    policy: DispatchProtocolPolicy,
    services: DispatchProtocolServices,
) -> dict[str, Any]:
    """Load and validate the session-to-task backlink under the state lock."""

    mapping = load_json(session_path(paths, parent_session_id))
    if mapping.get("session_id") != parent_session_id:
        raise HarnessError("session mapping identity mismatch")
    state = load_task(paths, str(mapping.get("task_id", "")))
    mapping_kind = mapping.get("mapping_kind", policy.root_session_mapping_kind)
    if mapping_kind == policy.root_session_mapping_kind:
        if parent_session_id not in state.get("session_ids", []):
            raise HarnessError("root session mapping lacks task backlink")
    elif mapping_kind == policy.subagent_parent_mapping_kind:
        if parent_session_id not in state.get("subagent_parent_session_ids", []):
            raise HarnessError("subagent parent mapping lacks task backlink")
        parent_packet = services.packet_by_id(
            state, str(mapping.get("packet_id", ""))
        )
        if (
            int(parent_packet.get("delegation_depth", 1)) != 1
            or parent_packet.get("agent_id") != parent_session_id
        ):
            raise HarnessError("subagent parent mapping lost packet identity")
    else:
        raise HarnessError("session mapping kind is invalid")
    return state


def _arm_validation_rejection_reason(exc: HarnessError) -> str:
    message = str(exc).lower()
    if "expired" in message:
        return "expired_arm"
    if any(
        marker in message
        for marker in ("topology", "selection", "depth-one", "depth-two", "lane")
    ):
        return "topology_rejected"
    return "authority_invalid"


def initial_rejection_reason(
    state: dict[str, Any],
    *,
    valid_event: bool,
    agent_id: str,
    candidates: list[tuple[dict[str, Any], dict[str, Any]]],
    matched_expired_packet_ids: list[str],
    policy: DispatchProtocolPolicy,
) -> str:
    """Classify failures that do not require authority/topology validation."""

    if not valid_event:
        return "invalid_event"
    if any(
        packet.get("agent_id") == agent_id
        for packet in state.get("packets", [])
        if packet.get("status") in policy.executing_packet_statuses
    ):
        return "duplicate_agent"
    if len(candidates) > 1:
        return "ambiguous_arm"
    if not candidates:
        return "expired_arm" if matched_expired_packet_ids else "no_matching_arm"
    return ""


def validate_pre_spawn_arm(
    paths: HarnessPaths,
    *,
    parent_session_id: str,
    transport_agent_type: str,
    policy: DispatchProtocolPolicy,
    services: DispatchProtocolServices,
    current: dt.datetime | None = None,
) -> dict[str, Any]:
    """Read-only exact-arm validation for transports with a pre-spawn gate."""

    if not policy.hook_id_re.fullmatch(parent_session_id):
        return {"status": "corrupt", "reason_code": "invalid_parent_session"}
    if not policy.hook_id_re.fullmatch(transport_agent_type):
        return {"status": "denied", "reason_code": "invalid_agent_type"}
    mapping_path = session_path(paths, parent_session_id)
    if not mapping_path.exists():
        return {"status": "unbound", "reason_code": "no_task_mapping"}
    current = current or dt.datetime.now().astimezone()
    with state_lock(paths, create_layout=False):
        try:
            state = _load_mapped_task_unlocked(
                paths,
                parent_session_id,
                policy=policy,
                services=services,
            )
            candidates = matching_armed_packets(
                state,
                parent_session_id=parent_session_id,
                transport_agent_type=transport_agent_type,
            )
        except HarnessError:
            return {"status": "corrupt", "reason_code": "corrupt_task_mapping"}
        packet_ids = [str(packet.get("packet_id", "")) for packet, _ in candidates]
        if len(candidates) > 1:
            return {
                "status": "denied",
                "reason_code": "ambiguous_arm",
                "task_id": state["task_id"],
                "candidate_packet_ids": packet_ids,
            }
        if not candidates:
            return {
                "status": "denied",
                "reason_code": "no_matching_arm",
                "task_id": state["task_id"],
                "candidate_packet_ids": [],
            }
        packet, attempt = candidates[0]
        expires_at = parse_time(str(attempt.get("expires_at", "")))
        if expires_at is None or expires_at <= current:
            return {
                "status": "denied",
                "reason_code": "expired_arm",
                "task_id": state["task_id"],
                "candidate_packet_ids": packet_ids,
            }
        try:
            services.validate_observed_arm(
                paths,
                state,
                packet,
                attempt,
                parent_session_id=parent_session_id,
                transport_agent_type=transport_agent_type,
                current=current,
            )
        except HarnessError as exc:
            return {
                "status": "denied",
                "reason_code": _arm_validation_rejection_reason(exc),
                "task_id": state["task_id"],
                "candidate_packet_ids": packet_ids,
            }
        return {
            "status": "authorized",
            "reason_code": "",
            "task_id": state["task_id"],
            "packet_id": packet.get("packet_id"),
            "packet_path": packet.get("path"),
        }


def observe_subagent_start(
    paths: HarnessPaths,
    payload: dict[str, Any],
    *,
    policy: DispatchProtocolPolicy,
    services: DispatchProtocolServices,
) -> dict[str, Any]:
    """Consume one exact arm or durably record an unmanaged start incident."""

    parent_session_id = str(payload.get("session_id", ""))
    if not policy.hook_id_re.fullmatch(parent_session_id):
        return {"status": "unbound", "reason_code": "invalid_parent_session"}
    mapping_path = session_path(paths, parent_session_id)
    if not mapping_path.exists():
        return {"status": "unbound", "reason_code": "no_task_mapping"}
    with state_lock(paths, create_layout=False):
        try:
            state = _load_mapped_task_unlocked(
                paths,
                parent_session_id,
                policy=policy,
                services=services,
            )
        except HarnessError:
            return {"status": "corrupt", "reason_code": "corrupt_task_mapping"}

        event_id = subagent_event_id(payload, policy=policy)
        for packet in state.get("packets", []):
            for attempt in packet.get("dispatch_attempts", []):
                observation = attempt.get("observation")
                if (
                    isinstance(observation, dict)
                    and observation.get("event_id") == event_id
                ):
                    authority_errors = services.packet_authority_integrity_errors(
                        paths,
                        state,
                        packet,
                        require_origin=False,
                    )
                    if authority_errors:
                        return {
                            "status": "corrupt",
                            "reason_code": "packet_authority_invalid",
                            "task_id": state["task_id"],
                            "packet_id": packet.get("packet_id"),
                            "event_id": event_id,
                            "idempotent": True,
                        }
                    return {
                        "status": "authorized",
                        "task_id": state["task_id"],
                        "packet_id": packet.get("packet_id"),
                        "packet_path": packet.get("path"),
                        "event_id": event_id,
                        "idempotent": True,
                    }

        existing_incident = next(
            (
                item
                for item in state.get("subagent_incidents", [])
                if item.get("incident_id") == event_id
            ),
            None,
        )
        if existing_incident is not None:
            return {
                "status": "incident",
                "task_id": state["task_id"],
                "incident_id": event_id,
                "reason_code": existing_incident.get("reason_code"),
                "idempotent": True,
            }

        observed_at = now_iso()
        current = dt.datetime.now().astimezone()
        transport_agent_type = str(payload.get("agent_type", ""))
        agent_id = str(payload.get("agent_id", ""))
        expired_arms = expire_dispatch_arms(state, current=current)
        valid_event = bool(
            policy.hook_id_re.fullmatch(transport_agent_type)
            and policy.hook_id_re.fullmatch(agent_id)
        )
        candidates = (
            matching_armed_packets(
                state,
                parent_session_id=parent_session_id,
                transport_agent_type=transport_agent_type,
            )
            if valid_event
            else []
        )
        matched_expired_ids = matching_expired_packet_ids(
            expired_arms,
            parent_session_id=parent_session_id,
            transport_agent_type=transport_agent_type,
        )
        reason_code = initial_rejection_reason(
            state,
            valid_event=valid_event,
            agent_id=agent_id,
            candidates=candidates,
            matched_expired_packet_ids=matched_expired_ids,
            policy=policy,
        )
        if not reason_code:
            packet, attempt = candidates[0]
            try:
                services.validate_observed_arm(
                    paths,
                    state,
                    packet,
                    attempt,
                    parent_session_id=parent_session_id,
                    transport_agent_type=transport_agent_type,
                    current=current,
                )
            except HarnessError as exc:
                reason_code = _arm_validation_rejection_reason(exc)

        if reason_code:
            incident = record_subagent_incident(
                state,
                payload,
                reason_code=reason_code,
                candidate_packet_ids=[
                    str(packet.get("packet_id", "")) for packet, _ in candidates
                ]
                or matched_expired_ids,
                observed_at=observed_at,
                policy=policy,
            )
            bump_task(state)
            write_task(paths, state)
            index_refreshed = services.refresh_index_after_commit(paths)
            return {
                "status": "incident",
                "task_id": state["task_id"],
                "incident_id": incident["incident_id"],
                "reason_code": reason_code,
                "idempotent": False,
                "index_refresh_deferred": not index_refreshed,
            }

        packet, attempt = candidates[0]
        observation = {
            "event_id": event_id,
            "hook_protocol_version": policy.hook_protocol_version,
            "parent_session_id": parent_session_id,
            "turn_id": safe_hook_observation_text(
                payload.get("turn_id", ""), policy=policy
            ),
            "agent_id": agent_id,
            "agent_type": transport_agent_type,
            "permission_mode": safe_hook_observation_text(
                payload.get("permission_mode", ""), policy=policy
            ),
            "observed_at": observed_at,
        }
        attempt["status"] = "consumed"
        attempt["observation"] = observation
        attempt["closed_at"] = observed_at
        packet["status"] = "dispatched"
        packet["dispatch_provenance"] = policy.dispatch_provenance
        packet["dispatch_recorded_at"] = observed_at
        packet["agent_id"] = agent_id
        packet["updated_at"] = observed_at
        state["dispatch_model_version"] = policy.dispatch_model_version
        parent_mapping_deferred = False
        if int(packet.get("delegation_depth", 1)) == 1:
            try:
                services.ensure_subagent_parent_mapping(paths, state, packet)
            except HarnessError:
                # The observed dispatch remains valid. Nested delegation stays
                # fail-closed until the Chief can repair the parent-only mapping.
                parent_mapping_deferred = True
        bump_task(state)
        write_task(paths, state)
        index_refreshed = services.refresh_index_after_commit(paths)
        return {
            "status": "authorized",
            "task_id": state["task_id"],
            "packet_id": packet["packet_id"],
            "packet_path": packet["path"],
            "event_id": event_id,
            "idempotent": False,
            "index_refresh_deferred": not index_refreshed,
            "parent_mapping_deferred": parent_mapping_deferred,
        }
