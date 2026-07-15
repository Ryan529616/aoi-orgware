"""Resource authority and integrity rules independent of CLI parsing.

The CLI remains the composition root.  It snapshots the current project profile
into :class:`ResourceGovernancePolicy` and passes that immutable policy to this
module.  Keeping the policy explicit prevents extracted code from observing
stale module globals after a project-specific role map is loaded.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Set
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .harnesslib import (
    HarnessError,
    HarnessPaths,
    is_expired,
    load_json,
    parse_time,
    sha256_file,
    task_dir,
    validate_id,
)
from .resource_config import (
    AOI_MAX_DELEGATION_DEPTH,
    ARISE_MAX_THREADS_CEILING,
    parse_override_settings,
    validate_resource_receipt,
)


@dataclass(frozen=True)
class ResourceGovernancePolicy:
    """Immutable runtime policy required by resource-domain decisions."""

    role_tier_map: Mapping[str, str]
    depth_two_roles: Set[str]
    executing_packet_statuses: Set[str]
    override_target_kinds: Set[str]
    override_statuses: Set[str]
    resource_config_event_statuses: Set[str]
    envelope_schema_version: int = 1
    default_parallel_agents: int = 4

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "role_tier_map", MappingProxyType(dict(self.role_tier_map))
        )
        for field in (
            "depth_two_roles",
            "executing_packet_statuses",
            "override_target_kinds",
            "override_statuses",
            "resource_config_event_statuses",
        ):
            object.__setattr__(self, field, frozenset(getattr(self, field)))
        if self.envelope_schema_version < 1:
            raise ValueError("resource envelope schema version must be positive")
        if self.default_parallel_agents < 1:
            raise ValueError("default parallel agent count must be positive")


def _canonical_record_sha256(value: dict[str, Any]) -> str:
    payload = json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _lane_by_id(state: dict[str, Any], lane_id: str) -> dict[str, Any]:
    lane_id = validate_id(lane_id, "lane id")
    matches = [
        lane for lane in state.get("lanes", []) if lane.get("lane_id") == lane_id
    ]
    if len(matches) != 1:
        raise HarnessError(
            f"expected exactly one lane named {lane_id}, found {len(matches)}"
        )
    return matches[0]


def execution_selection_target_contract_from_record(
    state: dict[str, Any], selection: dict[str, Any]
) -> dict[str, Any]:
    envelope = selection.get("resource_envelope") or {}
    return {
        "schema_version": 1,
        "target_kind": "execution_resource",
        "target_id": selection.get("selection_id"),
        "target_task_id": state.get("task_id"),
        "task_plan_sha256": selection.get("task_plan_sha256"),
        "override_id": envelope.get("override_id", ""),
        "work_unit_id": selection.get("work_unit_id"),
        "supersedes_selection_id": selection.get("supersedes_selection_id", ""),
        "scope": selection.get("scope"),
        "mode": selection.get("mode"),
        "lane_snapshots": selection.get("lane_snapshots"),
        "steward_snapshot": selection.get("steward_snapshot"),
        "resource_envelope": envelope,
        "resource_envelope_sha256": selection.get("resource_envelope_sha256"),
        "task_characteristics": selection.get("task_characteristics"),
        "rationale": selection.get("rationale"),
        "falsification_condition": selection.get("falsification_condition"),
        "escalation_condition": selection.get("escalation_condition"),
    }


def lane_authority_snapshot(lane: dict[str, Any]) -> dict[str, Any]:
    return {
        "lane_id": lane["lane_id"],
        "revision": lane["revision"],
        "authority_commit": lane["authority_commit"],
        "contract_version": lane["contract_version"],
    }


def build_execution_resource_envelope(
    *,
    mode: str,
    lanes: list[dict[str, Any]],
    steward: dict[str, Any] | None,
    override_id: str,
    override_settings: dict[str, str | int],
    policy: ResourceGovernancePolicy,
) -> tuple[dict[str, Any], str]:
    lane_count = len(lanes)
    max_first_level = (
        1
        if mode == "single"
        else min(policy.default_parallel_agents, lane_count)
    )
    max_total_override: int | None = None
    max_depth = AOI_MAX_DELEGATION_DEPTH
    role_model_tiers: dict[str, str] = {}
    for lane in lanes + ([steward] if steward is not None else []):
        role = str(lane.get("role", ""))
        tier = policy.role_tier_map.get(role)
        if not role or tier is None:
            raise HarnessError(
                f"execution resource envelope cannot resolve lane role {role!r}"
            )
        role_model_tiers[role] = tier
    depth_two_role_model_tiers = {
        role: policy.role_tier_map[role]
        for role in sorted(policy.depth_two_roles)
        if role in policy.role_tier_map
    }
    configurable_roles = set(role_model_tiers) | set(depth_two_role_model_tiers)
    role_settings: dict[str, str | int] = {}
    for key, value in override_settings.items():
        if key == "envelope.max_active_first_level_agents":
            max_first_level = int(value)
        elif key == "envelope.max_active_total_agents":
            max_total_override = int(value)
        elif key == "envelope.max_delegation_depth":
            max_depth = int(value)
        elif key.startswith("agents."):
            role = key.split(".", 2)[1]
            if role not in configurable_roles:
                raise HarnessError(
                    f"execution resource override references unselected role {role}"
                )
            role_settings[key] = value
        else:
            raise HarnessError(f"invalid execution resource setting: {key}")
    hard_first_level = min(ARISE_MAX_THREADS_CEILING, max(1, lane_count))
    if not 1 <= max_first_level <= hard_first_level:
        raise HarnessError(
            "execution max_active_first_level_agents must be within the selected "
            f"lane count and hard ceiling (1-{hard_first_level})"
        )
    if mode == "single" and max_first_level != 1:
        raise HarnessError("single execution mode has exactly one first-level agent")
    max_total = (
        max_total_override
        if max_total_override is not None
        else min(ARISE_MAX_THREADS_CEILING, max_first_level * 2)
    )
    if not max_first_level <= max_total <= ARISE_MAX_THREADS_CEILING:
        raise HarnessError(
            "execution max_active_total_agents must be at least the first-level "
            f"limit and at most {ARISE_MAX_THREADS_CEILING}"
        )
    if not 1 <= max_depth <= AOI_MAX_DELEGATION_DEPTH:
        raise HarnessError(
            f"execution max delegation depth must be 1-{AOI_MAX_DELEGATION_DEPTH}"
        )
    envelope = {
        "schema_version": policy.envelope_schema_version,
        "max_active_first_level_agents": max_first_level,
        "max_active_total_agents": max_total,
        "max_delegation_depth": max_depth,
        "selected_lane_count": lane_count,
        "role_model_tiers": dict(sorted(role_model_tiers.items())),
        "depth_two_role_model_tiers": depth_two_role_model_tiers,
        "role_config_overrides": dict(sorted(role_settings.items())),
        "override_id": override_id,
        "decision_source": (
            "chief_approved_user_override" if override_id else "topology_policy_default"
        ),
        "depth_two_boundary": (
            "Depth two remains separately gated by one exact acknowledged capacity "
            "decision and the batch/explorer/worker leaf-role allowlist."
        ),
        "routing_evidence_boundary": (
            "Role model tier and project configuration are requested authority only; "
            "actual provider routing, token usage, and price remain unverified."
        ),
    }
    return envelope, _canonical_record_sha256(envelope)


def validate_selection_resource_envelope(
    state: dict[str, Any],
    selection: dict[str, Any],
    *,
    policy: ResourceGovernancePolicy,
) -> dict[str, Any] | None:
    envelope = selection.get("resource_envelope")
    digest = str(selection.get("resource_envelope_sha256", ""))
    if envelope is None:
        if digest:
            raise HarnessError("execution selection has a digest without an envelope")
        return None
    if not isinstance(envelope, dict):
        raise HarnessError("execution selection resource envelope is not an object")
    if envelope.get("schema_version") != policy.envelope_schema_version:
        raise HarnessError("execution selection resource envelope schema is unsupported")
    if digest != _canonical_record_sha256(envelope):
        raise HarnessError("execution selection resource envelope lost integrity")
    selection_target_contract_sha256 = str(
        selection.get("target_contract_sha256", "")
    )
    if selection_target_contract_sha256:
        actual_target_contract_sha256 = _canonical_record_sha256(
            execution_selection_target_contract_from_record(state, selection)
        )
        if selection_target_contract_sha256 != actual_target_contract_sha256:
            raise HarnessError("execution selection target contract lost integrity")
    mode = str(selection.get("mode", ""))
    lane_count = len(selection.get("lane_snapshots", []))
    max_first_level = envelope.get("max_active_first_level_agents")
    max_total = envelope.get("max_active_total_agents")
    max_depth = envelope.get("max_delegation_depth")
    if (
        not isinstance(max_first_level, int)
        or isinstance(max_first_level, bool)
        or not 1
        <= max_first_level
        <= min(ARISE_MAX_THREADS_CEILING, max(1, lane_count))
    ):
        raise HarnessError("execution resource first-level agent limit is invalid")
    if mode == "single" and max_first_level != 1:
        raise HarnessError("single execution resource envelope must limit first level to one")
    if (
        not isinstance(max_total, int)
        or isinstance(max_total, bool)
        or not max_first_level <= max_total <= ARISE_MAX_THREADS_CEILING
    ):
        raise HarnessError("execution resource total active-agent limit is invalid")
    if (
        not isinstance(max_depth, int)
        or isinstance(max_depth, bool)
        or not 1 <= max_depth <= AOI_MAX_DELEGATION_DEPTH
    ):
        raise HarnessError("execution resource delegation-depth limit is invalid")
    expected_roles: dict[str, str] = {}
    selected_lanes: list[dict[str, Any]] = []
    for snapshot in selection.get("lane_snapshots", []):
        lane = _lane_by_id(state, str(snapshot.get("lane_id", "")))
        selected_lanes.append(lane)
        expected_roles[str(lane.get("role", ""))] = policy.role_tier_map.get(
            str(lane.get("role", "")), ""
        )
    steward_snapshot = selection.get("steward_snapshot", {})
    steward: dict[str, Any] | None = None
    if isinstance(steward_snapshot, dict) and steward_snapshot.get("lane_id"):
        steward = _lane_by_id(state, str(steward_snapshot.get("lane_id", "")))
        expected_roles[str(steward.get("role", ""))] = policy.role_tier_map.get(
            str(steward.get("role", "")), ""
        )
    if envelope.get("role_model_tiers") != dict(sorted(expected_roles.items())):
        raise HarnessError("execution resource role/model-tier mapping is stale")
    expected_depth_two_roles = {
        role: policy.role_tier_map[role]
        for role in sorted(policy.depth_two_roles)
        if role in policy.role_tier_map
    }
    if envelope.get("depth_two_role_model_tiers") != expected_depth_two_roles:
        raise HarnessError("execution resource depth-two role mapping is stale")
    settings = envelope.get("role_config_overrides", {})
    if not isinstance(settings, dict):
        raise HarnessError("execution resource role configuration override is invalid")
    if settings:
        canonical = parse_override_settings(
            [f"{key}={value}" for key, value in settings.items()],
            roles=policy.role_tier_map,
            target_kind="execution_resource",
        )
        if canonical != settings:
            raise HarnessError("execution resource role overrides are not canonical")
    override_id = str(envelope.get("override_id", ""))
    approved_settings: dict[str, str | int] = {}
    if override_id:
        matches = [
            item
            for item in state.get("override_requests", [])
            if item.get("override_id") == override_id
        ]
        if len(matches) != 1 or matches[0].get("status") != "consumed":
            raise HarnessError("execution resource envelope lacks consumed override authority")
        consumption = matches[0].get("consumption") or {}
        target_contract = execution_selection_target_contract_from_record(
            state, selection
        )
        target_contract_sha256 = _canonical_record_sha256(target_contract)
        decision = matches[0].get("chief_decision") or {}
        if (
            matches[0].get("target_kind") != "execution_resource"
            or matches[0].get("target_id") != selection.get("selection_id")
            or matches[0].get("task_plan_sha256")
            != selection.get("task_plan_sha256")
            or matches[0].get("target_contract_sha256")
            != target_contract_sha256
            or decision.get("target_contract_sha256")
            != target_contract_sha256
            or selection.get("target_contract_sha256")
            != target_contract_sha256
            or consumption.get("consumer_command") != "execution-select"
            or consumption.get("selection_id") != selection.get("selection_id")
            or consumption.get("resource_envelope_sha256") != digest
            or consumption.get("target_contract_sha256")
            != target_contract_sha256
        ):
            raise HarnessError("execution resource override consumption binding is invalid")
        decision_settings = (matches[0].get("chief_decision") or {}).get(
            "approved_settings"
        )
        if not isinstance(decision_settings, dict):
            raise HarnessError("execution resource override lacks exact approved settings")
        approved_settings = dict(decision_settings)
    expected_envelope, expected_digest = build_execution_resource_envelope(
        mode=mode,
        lanes=selected_lanes,
        steward=steward,
        override_id=override_id,
        override_settings=approved_settings,
        policy=policy,
    )
    if envelope != expected_envelope or digest != expected_digest:
        raise HarnessError(
            "execution resource envelope differs from its topology/Chief authority"
        )
    return envelope


def validate_packet_resource_envelope(
    state: dict[str, Any],
    packet: dict[str, Any],
    selection: dict[str, Any] | None,
    *,
    enforce_active_limit: bool,
    policy: ResourceGovernancePolicy,
) -> None:
    packet_digest = str(packet.get("resource_envelope_sha256", ""))
    if selection is None:
        if packet_digest:
            raise HarnessError("packet has resource authority without an execution selection")
        return
    envelope = validate_selection_resource_envelope(state, selection, policy=policy)
    if envelope is None:
        if packet_digest:
            raise HarnessError("legacy execution selection does not own packet resource authority")
        return
    selection_digest = str(selection.get("resource_envelope_sha256", ""))
    if packet_digest != selection_digest:
        raise HarnessError("packet resource envelope binding is missing or stale")
    depth = int(packet.get("delegation_depth", 1))
    if depth > int(envelope["max_delegation_depth"]):
        raise HarnessError("packet exceeds the selected resource delegation-depth limit")
    role = str(packet.get("agent_role", ""))
    tier = str(packet.get("model_tier", ""))
    if depth == 1 and policy.role_tier_map.get(role) != tier:
        raise HarnessError("packet role/model tier is outside the selected resource envelope")
    if depth == 1:
        lane = _lane_by_id(state, str(packet.get("lane_id", "")))
        selected_lane_ids = {
            str(snapshot.get("lane_id", ""))
            for snapshot in selection.get("lane_snapshots", [])
        }
        steward_snapshot = selection.get("steward_snapshot", {})
        if isinstance(steward_snapshot, dict) and steward_snapshot.get("lane_id"):
            selected_lane_ids.add(str(steward_snapshot["lane_id"]))
        if lane.get("lane_id") not in selected_lane_ids:
            raise HarnessError("depth-one packet lane is outside the selected resource envelope")
        if role != lane.get("role"):
            raise HarnessError(
                "depth-one packet role differs from its selected lane authority"
            )
        if role not in envelope["role_model_tiers"]:
            raise HarnessError("depth-one packet role is absent from the selected envelope")
    if depth == 2 and role not in envelope["depth_two_role_model_tiers"]:
        raise HarnessError("packet leaf role is outside the selected resource envelope")
    if enforce_active_limit:
        selection_id = str(selection.get("selection_id", ""))
        active_total_peers = sum(
            other.get("packet_id") != packet.get("packet_id")
            and other.get("status") in policy.executing_packet_statuses
            and other.get("execution_selection_id") == selection_id
            for other in state.get("packets", [])
        )
        if active_total_peers + 1 > int(envelope["max_active_total_agents"]):
            raise HarnessError(
                "execution resource envelope has no remaining total agent slot"
            )
    if enforce_active_limit and depth == 1:
        selection_id = str(selection.get("selection_id", ""))
        active_peers = sum(
            other.get("packet_id") != packet.get("packet_id")
            and other.get("status") in policy.executing_packet_statuses
            and int(other.get("delegation_depth", 1)) == 1
            and other.get("execution_selection_id") == selection_id
            for other in state.get("packets", [])
        )
        if active_peers + 1 > int(envelope["max_active_first_level_agents"]):
            raise HarnessError(
                "execution resource envelope has no remaining first-level agent slot"
            )


def resource_envelope_integrity_errors(
    state: dict[str, Any], *, policy: ResourceGovernancePolicy
) -> list[str]:
    errors: list[str] = []
    for selection in state.get("execution_selections", []):
        try:
            envelope = validate_selection_resource_envelope(state, selection, policy=policy)
            if envelope is not None:
                active_first_level = sum(
                    packet.get("status") in policy.executing_packet_statuses
                    and int(packet.get("delegation_depth", 1)) == 1
                    and packet.get("execution_selection_id")
                    == selection.get("selection_id")
                    for packet in state.get("packets", [])
                )
                if active_first_level > int(
                    envelope["max_active_first_level_agents"]
                ):
                    raise HarnessError(
                        "active first-level packets exceed the resource envelope"
                    )
                active_total = sum(
                    packet.get("status") in policy.executing_packet_statuses
                    and packet.get("execution_selection_id")
                    == selection.get("selection_id")
                    for packet in state.get("packets", [])
                )
                if active_total > int(envelope["max_active_total_agents"]):
                    raise HarnessError(
                        "active packets exceed the total-agent resource envelope"
                    )
        except (HarnessError, TypeError, ValueError) as exc:
            errors.append(
                f"execution selection {selection.get('selection_id')} resource envelope: {exc}"
            )
    return errors


def override_by_id(state: dict[str, Any], override_id: str) -> dict[str, Any]:
    override_id = validate_id(override_id, "override id")
    matches = [
        item
        for item in state.get("override_requests", [])
        if item.get("override_id") == override_id
    ]
    if len(matches) != 1:
        raise HarnessError(
            f"expected exactly one override named {override_id}, found {len(matches)}"
        )
    return matches[0]


def approved_override_settings(
    state: dict[str, Any],
    override_id: str,
    *,
    target_kind: str,
    target_id: str,
    policy: ResourceGovernancePolicy,
) -> dict[str, str | int]:
    if not override_id:
        return {}
    item = override_by_id(state, override_id)
    if (
        item.get("target_kind") != target_kind
        or item.get("target_id") != target_id
        or item.get("target_task_id") != state.get("task_id")
    ):
        raise HarnessError("override is outside the exact requested target")
    if item.get("status") != "approved" or is_expired(item.get("expires_at")):
        raise HarnessError("override is not approved, is already consumed, or has expired")
    if (
        item.get("integrity_version") != 1
        or item.get("version") != 2
        or item.get("task_plan_sha256") != state.get("plan_sha256")
        or not re.fullmatch(
            r"[0-9a-f]{64}", str(item.get("target_contract_sha256", ""))
        )
        or item.get("root_session_id") not in state.get("session_ids", [])
        or item.get("consumption") is not None
        or item.get("revocation") is not None
    ):
        raise HarnessError("override authority metadata is stale or invalid")
    try:
        requested = parse_override_settings(
            [
                f"{key}={value}"
                for key, value in item.get("requested_settings", {}).items()
            ],
            roles=policy.role_tier_map,
            target_kind=target_kind,
        )
    except (HarnessError, AttributeError) as exc:
        raise HarnessError("override requested settings lost integrity") from exc
    if requested != item.get("requested_settings"):
        raise HarnessError("override requested settings are not canonical")
    decision = item.get("chief_decision") or {}
    settings = decision.get("approved_settings")
    if (
        decision.get("decision") != "approved"
        or not isinstance(settings, dict)
        or decision.get("target_contract_sha256")
        != item.get("target_contract_sha256")
        or decision.get("root_session_id") not in state.get("session_ids", [])
    ):
        raise HarnessError("override lacks an exact Chief-approved setting set")
    try:
        canonical = parse_override_settings(
            [f"{key}={value}" for key, value in settings.items()],
            roles=policy.role_tier_map,
            target_kind=target_kind,
        )
    except (HarnessError, AttributeError) as exc:
        raise HarnessError("override approved settings lost integrity") from exc
    if canonical != settings:
        raise HarnessError("override approved settings are not canonical")
    return canonical


def require_override_target_contract(
    state: dict[str, Any], override_id: str, target_contract_sha256: str
) -> None:
    if not override_id:
        return
    item = override_by_id(state, override_id)
    if item.get("target_contract_sha256") != target_contract_sha256:
        raise HarnessError(
            "Chief-approved override targets a different canonical contract"
        )


def override_integrity_errors(
    state: dict[str, Any], *, policy: ResourceGovernancePolicy
) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for item in state.get("override_requests", []):
        override_id = str(item.get("override_id", ""))
        try:
            validate_id(override_id, "override id")
        except HarnessError as exc:
            errors.append(str(exc))
            continue
        if override_id in seen:
            errors.append(f"duplicate override id {override_id}")
        seen.add(override_id)
        if item.get("integrity_version") != 1:
            errors.append(f"override {override_id} lacks integrity_version=1")
        target_kind = str(item.get("target_kind", ""))
        if target_kind not in policy.override_target_kinds:
            errors.append(f"override {override_id} has an invalid target kind")
        try:
            validate_id(str(item.get("target_id", "")), "override target id")
        except HarnessError as exc:
            errors.append(f"override {override_id}: {exc}")
        if item.get("status") not in policy.override_statuses:
            errors.append(f"override {override_id} has an invalid status")
        version = item.get("version")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            errors.append(f"override {override_id} has an invalid version")
        if item.get("root_session_id") not in state.get("session_ids", []):
            errors.append(f"override {override_id} lacks a task-bound user/Chief session")
        if item.get("target_task_id") != state.get("task_id"):
            errors.append(f"override {override_id} targets a different task")
        if item.get("task_plan_sha256") != state.get("plan_sha256"):
            errors.append(f"override {override_id} targets a different task plan")
        target_contract_sha256 = str(item.get("target_contract_sha256", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", target_contract_sha256):
            errors.append(f"override {override_id} target contract SHA-256 is invalid")
        if parse_time(str(item.get("expires_at", ""))) is None:
            errors.append(f"override {override_id} has an invalid expiry")
        try:
            requested = parse_override_settings(
                [f"{key}={value}" for key, value in item.get("requested_settings", {}).items()],
                roles=policy.role_tier_map,
                target_kind=target_kind,
            )
        except (HarnessError, AttributeError) as exc:
            errors.append(f"override {override_id} requested settings are invalid: {exc}")
            requested = {}
        if requested != item.get("requested_settings"):
            errors.append(f"override {override_id} requested settings are not canonical")
        decision = item.get("chief_decision")
        if item.get("status") == "awaiting_chief":
            if decision is not None:
                errors.append(f"pending override {override_id} unexpectedly has a decision")
        else:
            if not isinstance(decision, dict) or decision.get("decision") not in {
                "approved",
                "rejected",
            }:
                errors.append(f"terminal override {override_id} lacks a Chief decision")
            elif decision.get("decision") == "approved":
                if decision.get("target_contract_sha256") != target_contract_sha256:
                    errors.append(
                        f"override {override_id} Chief decision targets a different contract"
                    )
                try:
                    approved = parse_override_settings(
                        [
                            f"{key}={value}"
                            for key, value in decision.get("approved_settings", {}).items()
                        ],
                        roles=policy.role_tier_map,
                        target_kind=target_kind,
                    )
                except (HarnessError, AttributeError) as exc:
                    errors.append(
                        f"override {override_id} approved settings are invalid: {exc}"
                    )
                else:
                    if approved != decision.get("approved_settings"):
                        errors.append(
                            f"override {override_id} approved settings are not canonical"
                        )
        if item.get("status") == "consumed" and not item.get("consumption"):
            errors.append(f"consumed override {override_id} lacks consumption evidence")
        if item.get("status") == "revoked" and not item.get("revocation"):
            errors.append(f"revoked override {override_id} lacks revocation evidence")
        consumption = item.get("consumption")
        revocation = item.get("revocation")
        if item.get("status") == "consumed" and isinstance(consumption, dict):
            if consumption.get("root_session_id") not in state.get("session_ids", []):
                errors.append(
                    f"consumed override {override_id} lacks a task-bound consumer session"
                )
            consumer = consumption.get("consumer_command")
            if consumer == "execution-select":
                selections = [
                    selection
                    for selection in state.get("execution_selections", [])
                    if selection.get("selection_id") == item.get("target_id")
                    and (selection.get("resource_envelope") or {}).get("override_id")
                    == override_id
                    and selection.get("resource_envelope_sha256")
                    == consumption.get("resource_envelope_sha256")
                ]
                if item.get("target_kind") != "execution_resource" or len(selections) != 1:
                    errors.append(
                        f"consumed override {override_id} lacks its exact execution selection"
                    )
                elif consumption.get("target_contract_sha256") != item.get(
                    "target_contract_sha256"
                ):
                    errors.append(
                        f"consumed override {override_id} lost its target contract binding"
                    )
            elif consumer == "codex-config-apply":
                events = [
                    event
                    for event in state.get("resource_config_events", [])
                    if event.get("event_id") == item.get("target_id")
                    and event.get("override_id") == override_id
                    and event.get("plan_sha256") == consumption.get("plan_sha256")
                ]
                if item.get("target_kind") != "resource_config" or len(events) != 1:
                    errors.append(
                        f"consumed override {override_id} lacks its exact resource config event"
                    )
                elif consumption.get("target_contract_sha256") != item.get(
                    "target_contract_sha256"
                ):
                    errors.append(
                        f"consumed override {override_id} lost its target contract binding"
                    )
            else:
                errors.append(f"consumed override {override_id} has an unknown consumer")
        if item.get("status") != "consumed" and consumption is not None:
            errors.append(f"unconsumed override {override_id} carries consumption evidence")
        if item.get("status") == "revoked" and isinstance(revocation, dict):
            if revocation.get("root_session_id") not in state.get("session_ids", []):
                errors.append(
                    f"revoked override {override_id} lacks a task-bound revocation session"
                )
        if item.get("status") != "revoked" and revocation is not None:
            errors.append(f"non-revoked override {override_id} carries revocation evidence")
        if item.get("status") in {"approved", "consumed", "revoked"} and (
            not isinstance(decision, dict) or decision.get("decision") != "approved"
        ):
            errors.append(f"override {override_id} lacks an approved Chief decision")
        if item.get("status") == "rejected" and (
            not isinstance(decision, dict) or decision.get("decision") != "rejected"
        ):
            errors.append(f"override {override_id} lacks a rejected Chief decision")
        expected_version = {
            "awaiting_chief": 1,
            "approved": 2,
            "rejected": 2,
            "consumed": 3,
            "revoked": 3,
        }.get(str(item.get("status", "")))
        if expected_version is not None and version != expected_version:
            errors.append(
                f"override {override_id} status/version binding is invalid"
            )
        if isinstance(decision, dict) and decision.get("root_session_id") not in state.get(
            "session_ids", []
        ):
            errors.append(f"override {override_id} Chief decision lacks a task-bound session")
    return errors


def resource_config_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    policy: ResourceGovernancePolicy,
) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for event in state.get("resource_config_events", []):
        event_id = str(event.get("event_id", ""))
        try:
            validate_id(event_id, "resource config event id")
        except HarnessError as exc:
            errors.append(str(exc))
            continue
        if event_id in seen:
            errors.append(f"duplicate resource config event id {event_id}")
        seen.add(event_id)
        if event.get("integrity_version") != 1:
            errors.append(f"resource config event {event_id} lacks integrity_version=1")
        if event.get("status") not in policy.resource_config_event_statuses:
            errors.append(f"resource config event {event_id} has invalid status")
        if event.get("root_session_id") not in state.get("session_ids", []):
            errors.append(
                f"resource config event {event_id} lacks a task-bound root session"
            )
        if not re.fullmatch(r"[0-9a-f]{64}", str(event.get("plan_sha256", ""))):
            errors.append(f"resource config event {event_id} plan SHA-256 is invalid")
        if not re.fullmatch(
            r"[0-9a-f]{64}", str(event.get("task_plan_sha256", ""))
        ):
            errors.append(
                f"resource config event {event_id} task plan SHA-256 is invalid"
            )
        receipt_path = Path(str(event.get("receipt_path", "")))
        expected_receipt_path = (
            task_dir(paths, state["task_id"])
            / "results"
            / f"resource-config-{event_id}.json"
        )
        receipt_sha = str(event.get("receipt_sha256", ""))
        if (
            receipt_path != expected_receipt_path
            or not receipt_path.is_file()
            or receipt_path.is_symlink()
            or not re.fullmatch(r"[0-9a-f]{64}", receipt_sha)
            or sha256_file(receipt_path) != receipt_sha
        ):
            errors.append(f"resource config event {event_id} receipt identity is invalid")
        else:
            try:
                receipt = load_json(receipt_path)
            except HarnessError as exc:
                errors.append(
                    f"resource config event {event_id} receipt is invalid: {exc}"
                )
            else:
                try:
                    validate_resource_receipt(receipt)
                except HarnessError as exc:
                    errors.append(
                        f"resource config event {event_id} receipt is invalid: {exc}"
                    )
                else:
                    receipt_plan = receipt["plan"]
                    if (
                        receipt.get("event_id") != event_id
                        or receipt.get("task_id") != state.get("task_id")
                        or receipt.get("plan_sha256") != event.get("plan_sha256")
                        or receipt_plan.get("approved_task_plan_sha256")
                        != event.get("task_plan_sha256")
                        or receipt.get("override_id", "")
                        != event.get("override_id", "")
                        or receipt.get("root_session_id")
                        != event.get("root_session_id")
                        or receipt.get("applied_at") != event.get("applied_at")
                        or receipt.get("restart_required")
                        != event.get("restart_required")
                        or receipt_plan.get("resolved") != event.get("resolved")
                        or receipt_plan.get("dynamic_envelope")
                        != event.get("dynamic_envelope")
                        or receipt_plan.get("required_locks")
                        != event.get("required_locks")
                    ):
                        errors.append(
                            f"resource config event {event_id} receipt binding is invalid"
                        )
        if event.get("override_id"):
            matches = [
                item
                for item in state.get("override_requests", [])
                if item.get("override_id") == event.get("override_id")
            ]
            consumption = (matches[0].get("consumption") or {}) if len(matches) == 1 else {}
            if (
                len(matches) != 1
                or matches[0].get("status") != "consumed"
                or matches[0].get("target_kind") != "resource_config"
                or matches[0].get("target_id") != event_id
                or consumption.get("consumer_command") != "codex-config-apply"
                or consumption.get("event_id") != event_id
                or consumption.get("plan_sha256") != event.get("plan_sha256")
                or matches[0].get("target_contract_sha256")
                != event.get("plan_sha256")
                or consumption.get("target_contract_sha256")
                != event.get("plan_sha256")
            ):
                errors.append(
                    f"resource config event {event_id} lacks consumed override authority"
                )
        rollback = event.get("rollback")
        if event.get("status") == "rolled_back":
            if not isinstance(rollback, dict):
                errors.append(f"resource config event {event_id} lacks rollback evidence")
            elif (
                rollback.get("root_session_id") not in state.get("session_ids", [])
                or not str(rollback.get("reason", "")).strip()
                or parse_time(str(rollback.get("recorded_at", ""))) is None
            ):
                errors.append(
                    f"resource config event {event_id} rollback evidence is invalid"
                )
        elif rollback is not None:
            errors.append(
                f"applied resource config event {event_id} carries rollback evidence"
            )
    return errors



__all__ = [
    "ResourceGovernancePolicy",
    "approved_override_settings",
    "build_execution_resource_envelope",
    "execution_selection_target_contract_from_record",
    "lane_authority_snapshot",
    "override_by_id",
    "override_integrity_errors",
    "require_override_target_contract",
    "resource_config_integrity_errors",
    "resource_envelope_integrity_errors",
    "validate_packet_resource_envelope",
    "validate_selection_resource_envelope",
]
