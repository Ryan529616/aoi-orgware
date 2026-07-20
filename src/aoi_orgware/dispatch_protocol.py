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
from typing import Any, Mapping, Protocol

from .agent_identity import AgentIdentityError, validate_agent_id
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


# A wildcard arm owns its parent-session slot for any observed transport type.
# It is a deliberate sentinel that never matches the transport-id regex, so every
# match and validation site accepts it through an explicit branch rather than by
# widening ``hook_id_re``.
WILDCARD_AGENT_TYPE = "*"

_DISPATCH_ATTEMPT_AUTHORITY_FIELDS = (
    "attempt",
    "arm_id",
    "chief_session_id",
    "chief_epoch",
    "parent_session_id",
    "parent_packet_id",
    "expected_agent_type",
    "plan_sha256",
    "packet_contract_sha256",
    "execution_selection_id",
    "lane_snapshot",
    "steward_snapshot",
    "armed_at",
    "expires_at",
    "authority_sha256",
)


def _expected_type_matches(expected: Any, transport_agent_type: str) -> bool:
    """An arm's expected transport matches a concrete observed transport."""

    return expected == transport_agent_type or expected == WILDCARD_AGENT_TYPE


def _helper_spawn_budget(packet: dict[str, Any]) -> int:
    """Read a packet's Chief-granted depth-two helper budget, fail closed to 0."""

    value = packet.get("helper_spawn_budget", 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


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


def _record_dispatch_model_version(
    state: dict[str, Any], policy: DispatchProtocolPolicy
) -> None:
    """Never downgrade a task that already contains transport model v2."""

    has_transport_v2 = any(
        isinstance(packet, dict) and packet.get("dispatch_version") == 2
        for packet in state.get("packets", [])
    )
    state["dispatch_model_version"] = (
        2 if has_transport_v2 else policy.dispatch_model_version
    )


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


def dispatch_attempt_authority_sha256(attempt: Mapping[str, Any]) -> str:
    """Hash the immutable pre-dispatch authority shared by every writer.

    Semantic-v2 permit consumption and the legacy CLI must produce the same
    digest.  Keeping the preimage here avoids a second, subtly different arm
    identity in the Bridge path.
    """

    return _canonical_record_sha256(
        {field: attempt.get(field) for field in _DISPATCH_ATTEMPT_AUTHORITY_FIELDS}
    )


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
    if not isinstance(value, str):
        raise HarnessError(f"{label} is missing or unsafe")
    text = value
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


def safe_exact_hook_observation_text(
    value: Any, *, policy: DispatchProtocolPolicy
) -> str:
    """Return bounded hook text only when the transport supplied a string."""

    if not isinstance(value, str):
        return ""
    return safe_hook_observation_text(value, policy=policy)


def safe_hook_identity_observation(
    value: Any, *, policy: DispatchProtocolPolicy
) -> str:
    """Return one exact transport identity, or explicit absence."""

    try:
        return validate_hook_identity(value, "observed hook identity", policy=policy)
    except HarnessError:
        return ""


def event_identity_component(value: Any, *, policy: DispatchProtocolPolicy) -> str:
    """Preserve valid legacy string keys and separate malformed JSON types."""

    if isinstance(value, str):
        safe = safe_exact_hook_observation_text(value, policy=policy)
        if value == "" or safe:
            return safe
        return "!invalid-string-" + hashlib.sha256(value.encode("utf-8")).hexdigest()
    try:
        payload = json.dumps(
            value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError):
        payload = type(value).__qualname__.encode("utf-8", errors="backslashreplace")
    # The sentinel cannot collide with a valid hook identity because ``!`` is
    # outside the public identity grammar.  The digest also keeps the preimage
    # bounded when malformed JSON values are large.
    return "!invalid-json-" + hashlib.sha256(payload).hexdigest()


def safe_agent_identity_observation(value: Any) -> str:
    """Persist a canonical identity, or an explicit absence for unsafe input."""

    try:
        return validate_agent_id(value, "observed agent identity")
    except AgentIdentityError:
        return ""


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
        "session_id": event_identity_component(
            payload.get("session_id", ""), policy=policy
        ),
        "turn_id": event_identity_component(payload.get("turn_id", ""), policy=policy),
        "agent_id": event_identity_component(
            payload.get("agent_id", ""), policy=policy
        ),
        "agent_type": event_identity_component(
            payload.get("agent_type", ""), policy=policy
        ),
        "hook_protocol_version": policy.hook_protocol_version,
    }
    return "spawn-" + _canonical_record_sha256(identity)[:32]


def live_arm_snapshot(
    state: dict[str, Any], *, parent_session_id: str
) -> list[dict[str, str]]:
    """Machine-readable armed slots for one parent session at observation time.

    A guard misfire (armed under an AOI role label while the transport reported
    a different type) is otherwise only diagnosable by prose archaeology; this
    snapshot records the exact armed slots the observed transport failed to
    match.  Callers invoke it after the expiry sweep so it reflects live arms.
    """

    arms: list[dict[str, str]] = []
    for packet in state.get("packets", []):
        if packet.get("status") != "armed":
            continue
        attempt = active_dispatch_attempt(packet)
        if attempt.get("parent_session_id") != parent_session_id:
            continue
        arms.append(
            {
                "packet_id": str(packet.get("packet_id", "")),
                "expected_agent_type": str(attempt.get("expected_agent_type", "")),
                "expires_at": str(attempt.get("expires_at", "")),
            }
        )
    arms.sort(key=lambda item: item["packet_id"])
    return arms


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
        "incident_identity_version": 1,
        "kind": "unmanaged_subagent_start",
        "status": "open",
        "parent_session_id": safe_hook_identity_observation(
            payload.get("session_id", ""), policy=policy
        ),
        "turn_id": safe_exact_hook_observation_text(
            payload.get("turn_id", ""), policy=policy
        ),
        "agent_id": safe_agent_identity_observation(payload.get("agent_id", "")),
        "agent_type": safe_hook_identity_observation(
            payload.get("agent_type", ""), policy=policy
        ),
        "model": safe_hook_observation_text(
            payload.get("model", ""), policy=policy
        ),
        "observed_at": observed_at,
        "reason_code": reason_code,
        "candidate_packet_ids": sorted(set(candidate_packet_ids)),
        "live_arms": live_arm_snapshot(
            state, parent_session_id=str(payload.get("session_id", ""))
        ),
        "hook_protocol_version": policy.hook_protocol_version,
        "resolution": None,
    }
    _record_dispatch_model_version(state, policy)
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
        if attempt.get("parent_session_id") == parent_session_id and (
            _expected_type_matches(
                attempt.get("expected_agent_type"), transport_agent_type
            )
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
        and _expected_type_matches(item["expected_agent_type"], transport_agent_type)
    ]


def _load_mapped_task_unlocked(
    paths: HarnessPaths,
    parent_session_id: str,
    *,
    policy: DispatchProtocolPolicy,
    services: DispatchProtocolServices,
) -> tuple[dict[str, Any], dict[str, Any]]:
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
    return state, mapping


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


def _resumable_packet(
    state: dict[str, Any],
    *,
    agent_id: str,
    parent_session_id: str,
    policy: DispatchProtocolPolicy,
) -> dict[str, Any] | None:
    """Locate the executing packet this SubagentStart resumes, if any.

    A resume (the Chief re-entering an already-dispatched packet thread) shares
    the dispatched packet's ``agent_id`` and its consumed attempt's parent
    session.  That is the same packet thread, not a new unmanaged agent; a
    matching ``agent_id`` under a *different* parent stays a duplicate_agent
    incident because it is genuinely suspicious.
    """

    for packet in state.get("packets", []):
        if packet.get("status") not in policy.executing_packet_statuses:
            continue
        if packet.get("agent_id") != agent_id:
            continue
        consumed_parent = None
        for attempt in packet.get("dispatch_attempts", []):
            if isinstance(attempt, dict) and attempt.get("status") == "consumed":
                consumed_parent = attempt.get("parent_session_id")
                break
        if consumed_parent is not None and consumed_parent == parent_session_id:
            return packet
    return None


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
            state, _mapping = _load_mapped_task_unlocked(
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
            "model_tier": packet.get("model_tier"),
        }


def helper_budget_slot(
    paths: HarnessPaths,
    *,
    parent_session_id: str,
    policy: DispatchProtocolPolicy,
    services: DispatchProtocolServices,
) -> dict[str, Any]:
    """Read-only: does this depth-one agent have remaining helper spawn budget?"""

    if not policy.hook_id_re.fullmatch(parent_session_id):
        return {"status": "denied", "reason_code": "invalid_parent_session"}
    mapping_path = session_path(paths, parent_session_id)
    if not mapping_path.exists():
        return {"status": "unbound", "reason_code": "no_task_mapping"}
    with state_lock(paths, create_layout=False):
        try:
            state, mapping = _load_mapped_task_unlocked(
                paths,
                parent_session_id,
                policy=policy,
                services=services,
            )
        except HarnessError:
            return {"status": "corrupt", "reason_code": "corrupt_task_mapping"}
        if (
            mapping.get("mapping_kind", policy.root_session_mapping_kind)
            != policy.subagent_parent_mapping_kind
        ):
            return {"status": "denied", "reason_code": "not_subagent_parent"}
        try:
            parent_packet = services.packet_by_id(
                state, str(mapping.get("packet_id", ""))
            )
        except HarnessError:
            return {"status": "corrupt", "reason_code": "corrupt_task_mapping"}
        budget = _helper_spawn_budget(parent_packet)
        used = len(parent_packet.get("helper_spawns", []))
        remaining = max(budget - used, 0)
        if (
            parent_packet.get("status") in policy.executing_packet_statuses
            and used < budget
        ):
            return {
                "status": "authorized",
                "task_id": state["task_id"],
                "packet_id": parent_packet.get("packet_id"),
                "helper_spawn_budget": budget,
                "remaining_helper_budget": remaining,
                "model_tier": parent_packet.get("model_tier"),
            }
        return {
            "status": "denied",
            "reason_code": "no_helper_budget",
            "task_id": state["task_id"],
            "packet_id": parent_packet.get("packet_id"),
            "helper_spawn_budget": budget,
            "remaining_helper_budget": remaining,
        }


def observe_subagent_start(
    paths: HarnessPaths,
    payload: dict[str, Any],
    *,
    policy: DispatchProtocolPolicy,
    services: DispatchProtocolServices,
) -> dict[str, Any]:
    """Consume one exact arm or durably record an unmanaged start incident."""

    try:
        parent_session_id = validate_hook_identity(
            payload.get("session_id", ""), "parent session", policy=policy
        )
    except HarnessError:
        return {"status": "unbound", "reason_code": "invalid_parent_session"}
    mapping_path = session_path(paths, parent_session_id)
    if not mapping_path.exists():
        return {"status": "unbound", "reason_code": "no_task_mapping"}
    with state_lock(paths, create_layout=False):
        try:
            state, mapping = _load_mapped_task_unlocked(
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

        for packet in state.get("packets", []):
            for resumption in packet.get("agent_resumptions", []):
                if (
                    isinstance(resumption, dict)
                    and resumption.get("event_id") == event_id
                ):
                    return {
                        "status": "authorized",
                        "resumed": True,
                        "task_id": state["task_id"],
                        "packet_id": packet.get("packet_id"),
                        "packet_path": packet.get("path"),
                        "event_id": event_id,
                        "idempotent": True,
                    }
            helper_spawns = packet.get("helper_spawns", [])
            for helper in helper_spawns:
                if isinstance(helper, dict) and helper.get("event_id") == event_id:
                    budget = _helper_spawn_budget(packet)
                    return {
                        "status": "authorized",
                        "helper": True,
                        "task_id": state["task_id"],
                        "packet_id": packet.get("packet_id"),
                        "packet_path": packet.get("path"),
                        "remaining_helper_budget": max(
                            budget - len(helper_spawns), 0
                        ),
                        "event_id": event_id,
                        "idempotent": True,
                    }

        observed_at = now_iso()
        current = dt.datetime.now().astimezone()
        try:
            transport_agent_type = validate_hook_identity(
                payload.get("agent_type", ""), "agent type", policy=policy
            )
        except HarnessError:
            transport_agent_type = ""
        try:
            agent_id = validate_agent_id(payload.get("agent_id", ""), "agent id")
        except AgentIdentityError:
            agent_id = ""
        # Transport-honest routing observation: record the model exactly as the
        # hook payload provided it, empty when the transport did not expose one.
        observed_model = safe_hook_observation_text(
            payload.get("model", ""), policy=policy
        )
        expired_arms = expire_dispatch_arms(state, current=current)
        valid_event = bool(transport_agent_type and agent_id)
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
        helper_refusal_parent_id = ""
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

        if reason_code == "duplicate_agent":
            resumed_packet = _resumable_packet(
                state,
                agent_id=agent_id,
                parent_session_id=parent_session_id,
                policy=policy,
            )
            if resumed_packet is not None:
                resumed_packet.setdefault("agent_resumptions", []).append(
                    {
                        "event_id": event_id,
                        "turn_id": safe_hook_observation_text(
                            payload.get("turn_id", ""), policy=policy
                        ),
                        "agent_type": transport_agent_type,
                        "model": observed_model,
                        "observed_at": observed_at,
                    }
                )
                _record_dispatch_model_version(state, policy)
                bump_task(state)
                write_task(paths, state)
                index_refreshed = services.refresh_index_after_commit(paths)
                return {
                    "status": "authorized",
                    "resumed": True,
                    "task_id": state["task_id"],
                    "packet_id": resumed_packet["packet_id"],
                    "packet_path": resumed_packet["path"],
                    "event_id": event_id,
                    "idempotent": False,
                    "index_refresh_deferred": not index_refreshed,
                }

        if reason_code == "no_matching_arm" and (
            mapping.get("mapping_kind", policy.root_session_mapping_kind)
            == policy.subagent_parent_mapping_kind
        ):
            try:
                parent_packet = services.packet_by_id(
                    state, str(mapping.get("packet_id", ""))
                )
            except HarnessError:
                parent_packet = None
            if parent_packet is not None:
                budget = _helper_spawn_budget(parent_packet)
                used = len(parent_packet.get("helper_spawns", []))
                if parent_packet.get("status") in policy.executing_packet_statuses:
                    # Direct-parent linkage worked; a refusal here is a budget
                    # fact, not an arm-matching fact. Distinct reason codes let
                    # the helper canary tell the taxonomy apart, and the
                    # resolved direct parent is recorded so one parent's
                    # refusal can never be attributed to another packet.
                    if budget < 1:
                        reason_code = "no_helper_budget"
                        helper_refusal_parent_id = str(
                            parent_packet.get("packet_id", "")
                        )
                    elif used >= budget:
                        reason_code = "helper_budget_exhausted"
                        helper_refusal_parent_id = str(
                            parent_packet.get("packet_id", "")
                        )
                if (
                    parent_packet.get("status") in policy.executing_packet_statuses
                    and used < budget
                ):
                    parent_packet.setdefault("helper_spawns", []).append(
                        {
                            "event_id": event_id,
                            "agent_id": agent_id,
                            "agent_type": transport_agent_type,
                            "turn_id": safe_hook_observation_text(
                                payload.get("turn_id", ""), policy=policy
                            ),
                            "model": observed_model,
                            "observed_at": observed_at,
                        }
                    )
                    _record_dispatch_model_version(state, policy)
                    bump_task(state)
                    write_task(paths, state)
                    index_refreshed = services.refresh_index_after_commit(paths)
                    return {
                        "status": "authorized",
                        "helper": True,
                        "task_id": state["task_id"],
                        "packet_id": parent_packet["packet_id"],
                        "packet_path": parent_packet["path"],
                        "remaining_helper_budget": budget - used - 1,
                        "event_id": event_id,
                        "idempotent": False,
                        "index_refresh_deferred": not index_refreshed,
                    }

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
            if helper_refusal_parent_id:
                incident.setdefault(
                    "helper_parent_packet_id", helper_refusal_parent_id
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
            "turn_id": safe_exact_hook_observation_text(
                payload.get("turn_id", ""), policy=policy
            ),
            "agent_id": agent_id,
            "agent_type": transport_agent_type,
            "permission_mode": safe_hook_observation_text(
                payload.get("permission_mode", ""), policy=policy
            ),
            "model": observed_model,
            "observed_at": observed_at,
        }
        # Tamper evidence for the routing observation: the event identity hash
        # deliberately excludes the model (replay identity must stay stable),
        # so the model is bound here instead. Editing any observation field —
        # including model — after consumption breaks this digest.
        observation["observation_sha256"] = _canonical_record_sha256(observation)
        attempt["status"] = "consumed"
        attempt["observation"] = observation
        attempt["closed_at"] = observed_at
        packet["status"] = "dispatched"
        packet["dispatch_provenance"] = policy.dispatch_provenance
        packet["dispatch_recorded_at"] = observed_at
        packet["agent_id"] = agent_id
        packet["updated_at"] = observed_at
        _record_dispatch_model_version(state, policy)
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
