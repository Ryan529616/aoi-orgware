"""Packet authority, contract, result, and dispatch-attempt integrity fences.

The CLI remains the composition root.  It validates every packet and
subagent-incident authority surface a transition or consumer relies on: exact
command artifacts, v4+ contract seals, input-artifact provenance, persisted
lock authority, resource envelopes, terminal results, and the schema-v5
dispatch-attempt state machine.

Six operations these fences depend on live outside this module and arrive
through the frozen :class:`PacketIntegrityServices` dataclass rather than being
imported from the monolithic CLI: the packet resource-envelope check (a CLI
wrapper over :mod:`aoi_orgware.resource_governance`), the Steward terminal
specialist bindings, the dispatch-attempt authority digest, the active
dispatch-attempt selector, the hook observation-text sanitizer, and the
subagent event-id derivation (the last three are CLI wrappers over
:mod:`aoi_orgware.dispatch_protocol`).  The dispatch/hook contract constants
are project-immutable, so they are defined module-locally rather than threaded
through a policy.  This module imports only sibling packages and never imports
:mod:`aoi_orgware.cli`.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .evidence_artifacts import (
    COMMAND_ARTIFACT_MAX_BYTES,
    _is_legacy_snapshot_version,
    _packet_schema_version,
    artifact_ref_integrity_error,
    read_regular_artifact,
)
from .execution_topology import _is_steward_synthesis_packet
from .harnesslib import (
    ACTIVE_PACKET_STATUSES,
    PACKET_STATUSES,
    HarnessError,
    HarnessPaths,
    parse_time,
    sha256_file,
    task_dir,
    validate_id,
    validate_packet_lock_identities,
)
from .state_lookup import _packet_by_id, execution_selection_by_id


TERMINAL_PACKET_STATUSES = PACKET_STATUSES - ACTIVE_PACKET_STATUSES
NATIVE_V5_PACKET_CONTRACT_MARKER = "- AOI dispatch schema origin: `native_v5`"
HOOK_PROTOCOL_VERSION = "6"
HOOK_ID_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,512}$")
DISPATCH_ARM_MAX_SECONDS = 15 * 60
HOOK_OBSERVED_DISPATCH_PROVENANCES = {
    "codex_subagent_start_observed",
    "claude_subagent_start_observed",
}
DISPATCH_PROVENANCES = {
    "none",
    *HOOK_OBSERVED_DISPATCH_PROVENANCES,
    "manual_unverified",
}


class ValidatePacketResourceEnvelope(Protocol):
    def __call__(
        self,
        state: dict[str, Any],
        packet: dict[str, Any],
        selection: dict[str, Any] | None,
        *,
        enforce_active_limit: bool,
    ) -> None: ...


class SelectionTerminalPacketBindings(Protocol):
    def __call__(
        self, state: dict[str, Any], selection_id: str
    ) -> list[dict[str, Any]]: ...


class DispatchAttemptAuthoritySha256(Protocol):
    def __call__(self, attempt: dict[str, Any]) -> str: ...


class ActiveDispatchAttempt(Protocol):
    def __call__(self, packet: dict[str, Any]) -> dict[str, Any]: ...


class SafeHookObservationText(Protocol):
    def __call__(self, value: Any) -> str: ...


class SubagentEventId(Protocol):
    def __call__(self, payload: dict[str, Any]) -> str: ...


@dataclass(frozen=True)
class PacketIntegrityServices:
    """Authority and derived-state operations supplied by the composition root."""

    validate_packet_resource_envelope: ValidatePacketResourceEnvelope
    selection_terminal_packet_bindings: SelectionTerminalPacketBindings
    dispatch_attempt_authority_sha256: DispatchAttemptAuthoritySha256
    active_dispatch_attempt: ActiveDispatchAttempt
    safe_hook_observation_text: SafeHookObservationText
    subagent_event_id: SubagentEventId


def _is_exact_int(value: Any, expected: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == expected


def packet_command_integrity_error(packet: dict[str, Any]) -> str | None:
    mode = packet.get("packet_mode", "legacy")
    if mode in {"legacy", "read_only", "bounded_mutation"}:
        return None
    if mode != "exact_command":
        return f"packet {packet.get('packet_id')} has invalid packet mode {mode!r}"
    path = Path(str(packet.get("command_path", "")))
    expected_sha = str(packet.get("command_sha256", ""))
    expected_size = packet.get("command_size_bytes")
    if not path.is_file() or path.is_symlink():
        return f"packet {packet.get('packet_id')} exact command artifact is missing/non-regular"
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        return f"packet {packet.get('packet_id')} exact command SHA-256 is invalid"
    if sha256_file(path) != expected_sha or path.stat().st_size != expected_size:
        return f"packet {packet.get('packet_id')} exact command artifact identity mismatch"
    return None


def packet_contract_integrity_error(
    paths: HarnessPaths, state: dict[str, Any], packet: dict[str, Any]
) -> str | None:
    schema_version = _packet_schema_version(packet)
    if schema_version is None:
        return f"packet {packet.get('packet_id')} schema version is invalid"
    if schema_version < 4:
        return None
    packet_id = str(packet.get("packet_id", ""))
    expected_path = task_dir(paths, state["task_id"]) / "packets" / f"{packet_id}.md"
    recorded_path = Path(str(packet.get("path", "")))
    expected_sha = str(packet.get("packet_contract_sha256", ""))
    if recorded_path != expected_path:
        return f"packet {packet_id} contract path is not canonical"
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        return f"packet {packet_id} contract SHA-256 is invalid"
    try:
        _, data = read_regular_artifact(
            recorded_path,
            "packet contract",
            max_bytes=COMMAND_ARTIFACT_MAX_BYTES,
            require_utf8=True,
        )
    except HarnessError as exc:
        return f"packet {packet_id} contract is missing or tampered: {exc}"
    if hashlib.sha256(data).hexdigest() != expected_sha:
        return f"packet {packet_id} contract SHA-256 mismatch"
    contract_lines = data.decode("utf-8").splitlines()
    resource_digest = str(packet.get("resource_envelope_sha256", ""))
    resource_digest_lines = [
        line
        for line in contract_lines
        if line.startswith("- Resource envelope SHA-256:")
    ]
    if resource_digest:
        expected_resource_digest_line = (
            f"- Resource envelope SHA-256: `{resource_digest}`"
        )
        expected_selection_line = (
            "- Execution selection: "
            f"`{packet.get('execution_selection_id', '')}`"
        )
        if (
            resource_digest_lines != [expected_resource_digest_line]
            or expected_selection_line not in contract_lines
        ):
            return f"packet {packet_id} contract lost its exact resource authority"
    elif resource_digest_lines or "## AOI resource authority" in contract_lines:
        return f"packet {packet_id} contract resource authority was removed from state"
    has_native_v5_marker = NATIVE_V5_PACKET_CONTRACT_MARKER in contract_lines
    dispatch_origin = packet.get("dispatch_schema_origin")
    if schema_version < 5 and (
        has_native_v5_marker or dispatch_origin == "native_v5"
    ):
        return f"packet {packet_id} native-v5 contract was downgraded to a legacy schema"
    if schema_version >= 5:
        if dispatch_origin == "native_v5" and not has_native_v5_marker:
            return f"packet {packet_id} native-v5 dispatch origin lost its contract marker"
        if dispatch_origin == "legacy_v4_migration" and has_native_v5_marker:
            return f"packet {packet_id} falsely claims a legacy-v4 dispatch migration"
        if dispatch_origin not in {"native_v5", "legacy_v4_migration"}:
            return f"packet {packet_id} dispatch schema origin is missing or invalid"
    return None


def packet_input_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet: dict[str, Any],
    *,
    require_origin: bool,
) -> list[str]:
    packet_id = str(packet.get("packet_id", ""))
    errors: list[str] = []
    for artifact in packet.get("input_artifact_refs", []):
        error = artifact_ref_integrity_error(
            paths, state, artifact, require_origin=require_origin
        )
        if error:
            errors.append(f"packet {packet_id} input artifact: {error}")
    return errors


def packet_lock_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet: dict[str, Any],
) -> list[str]:
    """Validate lock authority already persisted in a delegation packet."""

    try:
        validate_packet_lock_identities(paths, state, packet)
    except HarnessError as exc:
        return [str(exc)]
    return []


def packet_resource_envelope_integrity_errors(
    state: dict[str, Any], packet: dict[str, Any], *, services: PacketIntegrityServices
) -> list[str]:
    selection_id = str(packet.get("execution_selection_id", ""))
    if not selection_id:
        return (
            ["packet has a resource envelope digest without an execution selection"]
            if packet.get("resource_envelope_sha256")
            else []
        )
    try:
        selection = execution_selection_by_id(state, selection_id)
        services.validate_packet_resource_envelope(
            state,
            packet,
            selection,
            enforce_active_limit=False,
        )
    except (HarnessError, TypeError, ValueError) as exc:
        return [str(exc)]
    return []


def packet_authority_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet: dict[str, Any],
    *,
    require_origin: bool,
    _visited: set[str] | None = None,
    services: PacketIntegrityServices,
) -> list[str]:
    """Validate every packet authority surface used by a transition/consumer."""

    packet_id = str(packet.get("packet_id", ""))
    visited = set(_visited or ())
    if packet_id in visited:
        return [f"packet {packet_id} authority dependency cycle"]
    visited.add(packet_id)
    errors: list[str] = []
    errors.extend(packet_lock_integrity_errors(paths, state, packet))
    errors.extend(packet_resource_envelope_integrity_errors(state, packet, services=services))
    contract_error = packet_contract_integrity_error(paths, state, packet)
    if contract_error:
        errors.append(contract_error)
    errors.extend(
        packet_input_integrity_errors(
            paths, state, packet, require_origin=require_origin
        )
    )
    command_error = packet_command_integrity_error(packet)
    if command_error:
        errors.append(command_error)
    try:
        delegation_depth = int(packet.get("delegation_depth", 1))
    except (TypeError, ValueError):
        delegation_depth = 0
        errors.append(f"packet {packet_id} delegation depth is invalid")
    if delegation_depth == 2:
        parent_id = str(packet.get("parent_packet_id", ""))
        try:
            parent = _packet_by_id(state, parent_id)
        except HarnessError as exc:
            errors.append(f"packet {packet_id} parent authority: {exc}")
        else:
            errors.extend(
                f"packet {packet_id} parent authority: {item}"
                for item in packet_authority_integrity_errors(
                    paths,
                    state,
                    parent,
                    require_origin=False,
                    _visited=visited,
                    services=services,
                )
            )
    if _is_steward_synthesis_packet(packet):
        selection_id = str(packet.get("execution_selection_id", ""))
        for specialist in state.get("packets", []):
            if (
                specialist.get("execution_selection_id") != selection_id
                or _is_steward_synthesis_packet(specialist)
                or specialist.get("status") != "done"
            ):
                continue
            specialist_id = str(specialist.get("packet_id", ""))
            errors.extend(
                f"packet {packet_id} specialist {specialist_id} authority: {item}"
                for item in packet_authority_integrity_errors(
                    paths,
                    state,
                    specialist,
                    require_origin=False,
                    _visited=visited,
                    services=services,
                )
            )
            errors.extend(
                f"packet {packet_id} specialist {specialist_id} result: {item}"
                for item in packet_result_integrity_errors(
                    paths,
                    state,
                    specialist,
                )
            )
    return errors


def selection_done_packet_authority_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    selection_id: str,
    *,
    services: PacketIntegrityServices,
) -> list[str]:
    """Validate done specialist evidence before a Steward packet can bind it."""

    errors: list[str] = []
    for packet in state.get("packets", []):
        if (
            packet.get("execution_selection_id") != selection_id
            or _is_steward_synthesis_packet(packet)
            or packet.get("status") != "done"
        ):
            continue
        packet_id = str(packet.get("packet_id", ""))
        errors.extend(
            f"specialist packet {packet_id}: {item}"
            for item in packet_authority_integrity_errors(
                paths,
                state,
                packet,
                require_origin=False,
                services=services,
            )
        )
        errors.extend(
            f"specialist packet {packet_id}: {item}"
            for item in packet_result_integrity_errors(paths, state, packet)
        )
    return errors


def packet_integrity_warnings(state: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    for packet in state.get("packets", []):
        packet_id = str(packet.get("packet_id", ""))
        schema_version = _packet_schema_version(packet)
        if (
            schema_version is not None
            and schema_version < 4
            and packet.get("status") in {"failed", "cancelled"}
            and any(
                _is_legacy_snapshot_version(artifact.get("snapshot_version"))
                for artifact in packet.get("input_artifact_refs", [])
            )
        ):
            warnings.append(
                f"packet {packet_id} has legacy digest-only inputs; "
                "failed/cancelled live origins are not revalidated"
            )
        if (
            schema_version is not None
            and schema_version < 5
            and packet.get("status") in {"dispatched", "done", "failed", "cancelled"}
        ):
            warnings.append(
                f"packet {packet_id} dispatch timing/provenance is legacy_unverified"
            )
        legacy_recovery_fields = {
            "version",
            "method",
            "carrier_input_index",
            "carrier_sha256",
            "archive_member",
            "packet_result_sha256",
            "reason",
            "recovered_at",
        }
        for input_index, artifact in enumerate(
            packet.get("input_artifact_refs", []), start=1
        ):
            recovery = artifact.get("recovery")
            if isinstance(recovery, dict) and set(recovery) == legacy_recovery_fields:
                warnings.append(
                    f"packet {packet_id} recovered input #{input_index} has an "
                    "unsealed legacy receipt; archive identity is replay-validated"
                )
    return warnings


def packet_result_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet: dict[str, Any],
) -> list[str]:
    """Validate one terminal packet result before it is consumed as evidence."""

    packet_id = str(packet.get("packet_id", ""))
    status = packet.get("status")
    if status not in TERMINAL_PACKET_STATUSES:
        return [f"packet {packet_id} result is not terminal"]
    expected_path = task_dir(paths, state["task_id"]) / "results" / f"{packet_id}.md"
    recorded_path = Path(str(packet.get("result_path", "")))
    if recorded_path != expected_path:
        return [f"packet {packet_id} result path is not canonical"]
    if packet.get("integrity_version") != 1:
        return [f"packet {packet_id} result lacks explicit integrity attestation"]
    if not expected_path.is_file():
        return [f"packet {packet_id} result file is missing"]
    errors: list[str] = []
    expected_sha = str(packet.get("result_sha256", ""))
    actual_sha = sha256_file(expected_path)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        errors.append(f"packet {packet_id} result SHA-256 is invalid")
    elif actual_sha != expected_sha:
        errors.append(f"packet {packet_id} result SHA-256 mismatch")
    if not packet.get("summary"):
        errors.append(f"packet {packet_id} terminal summary is empty")
    if status in {"done", "failed"} and not packet.get("evidence"):
        errors.append(f"packet {packet_id} terminal evidence is empty")
    return errors


def packet_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    allow_done_lock_recovery: bool = False,
    services: PacketIntegrityServices,
) -> list[str]:
    errors: list[str] = []
    for packet in state.get("packets", []):
        packet_id = str(packet.get("packet_id", ""))
        status = packet.get("status")
        mode = packet.get("packet_mode", "legacy")
        locks = packet.get("locks", [])
        packet_purpose = packet.get("packet_purpose", "work")
        lock_authority_is_recoverable = status in {"failed", "cancelled"} or (
            status == "done"
            and (allow_done_lock_recovery or state.get("status") == "cancelled")
        )
        if not lock_authority_is_recoverable:
            errors.extend(packet_lock_integrity_errors(paths, state, packet))
        errors.extend(packet_resource_envelope_integrity_errors(state, packet, services=services))
        if packet_purpose not in {"work", "steward_synthesis"}:
            errors.append(f"packet {packet_id} has an invalid packet purpose")
        if packet_purpose == "steward_synthesis":
            if (
                int(packet.get("delegation_depth", 1)) != 1
                or mode != "read_only"
                or not packet.get("execution_selection_id")
                or not isinstance(packet.get("steward_selection_snapshot"), dict)
                or not isinstance(packet.get("steward_execution_snapshot"), dict)
                or not isinstance(packet.get("steward_input_bindings"), list)
            ):
                errors.append(
                    f"packet {packet_id} has malformed Steward synthesis authority"
                )
            if status not in {"failed", "cancelled"} and packet.get(
                "steward_input_bindings"
            ) != services.selection_terminal_packet_bindings(
                state, str(packet.get("execution_selection_id", ""))
            ):
                errors.append(
                    f"packet {packet_id} Steward synthesis specialist bindings are stale"
                )
        if mode == "read_only" and locks:
            errors.append(f"packet {packet_id} read_only mode has mutation locks")
        if mode in {"bounded_mutation", "exact_command"} and not locks:
            errors.append(f"packet {packet_id} {mode} mode lacks mutation authority")
        contract_error = packet_contract_integrity_error(paths, state, packet)
        if contract_error:
            errors.append(contract_error)
        schema_version = _packet_schema_version(packet)
        legacy_terminal = (
            schema_version is not None
            and schema_version < 4
            and status in {"failed", "cancelled"}
        )
        if legacy_terminal:
            for artifact in packet.get("input_artifact_refs", []):
                if _is_legacy_snapshot_version(artifact.get("snapshot_version")):
                    continue
                snapshot_error = artifact_ref_integrity_error(
                    paths, state, artifact, require_origin=False
                )
                if snapshot_error:
                    errors.append(
                        f"packet {packet_id} input artifact: {snapshot_error}"
                    )
        else:
            errors.extend(
                packet_input_integrity_errors(
                    paths,
                    state,
                    packet,
                    require_origin=status in {"ready", "armed"},
                )
            )
        command_error = packet_command_integrity_error(packet)
        if command_error:
            errors.append(command_error)
        if status not in PACKET_STATUSES:
            errors.append(f"packet {packet_id} has invalid status {status!r}")
            continue
        if status == "dispatched" and not packet.get("agent_id"):
            errors.append(f"packet {packet_id} is dispatched without an agent id")
        if schema_version is not None and schema_version >= 5:
            if (
                not _is_exact_int(packet.get("dispatch_version"), 1)
                or packet.get("dispatch_provenance") not in DISPATCH_PROVENANCES
                or not isinstance(packet.get("dispatch_attempts"), list)
            ):
                errors.append(f"packet {packet_id} dispatch schema is invalid")
            if packet.get("dispatched_at"):
                errors.append(
                    f"packet {packet_id} v5 must not claim an unobserved dispatched_at"
                )
            attempts = packet.get("dispatch_attempts", [])
            active_attempts = [
                attempt
                for attempt in attempts
                if isinstance(attempt, dict) and attempt.get("status") == "armed"
            ]
            if status == "armed" and len(active_attempts) != 1:
                errors.append(f"packet {packet_id} armed state lacks one active permit")
            if status != "armed" and active_attempts:
                errors.append(f"packet {packet_id} retains an active permit after arm state")
            for attempt_index, attempt in enumerate(attempts, start=1):
                if not isinstance(attempt, dict):
                    errors.append(
                        f"packet {packet_id} dispatch attempt {attempt_index} is malformed"
                    )
                    continue
                attempt_status = attempt.get("status")
                if attempt.get("arm_authority_sha256") != (
                    services.dispatch_attempt_authority_sha256(attempt)
                ):
                    errors.append(
                        f"packet {packet_id} dispatch attempt {attempt_index} lost authority integrity"
                    )
                if attempt_status not in {
                    "armed",
                    "consumed",
                    "disarmed",
                    "expired",
                }:
                    errors.append(
                        f"packet {packet_id} dispatch attempt {attempt_index} has invalid status"
                    )
                    continue
                if (
                    not _is_exact_int(attempt.get("attempt"), attempt_index)
                    or attempt.get("arm_id") != f"{packet_id}-a{attempt_index}"
                ):
                    errors.append(
                        f"packet {packet_id} dispatch attempt {attempt_index} has invalid sequence identity"
                    )
                armed_time = parse_time(str(attempt.get("armed_at", "")))
                expiry_time = parse_time(str(attempt.get("expires_at", "")))
                if (
                    armed_time is None
                    or expiry_time is None
                    or expiry_time <= armed_time
                    or expiry_time - armed_time
                    > dt.timedelta(seconds=DISPATCH_ARM_MAX_SECONDS)
                ):
                    errors.append(
                        f"packet {packet_id} dispatch attempt {attempt_index} has invalid arm timing"
                    )
                observation = attempt.get("observation")
                closed_at = str(attempt.get("closed_at", ""))
                reason = str(attempt.get("reason", ""))
                if attempt_status == "armed":
                    if (
                        expiry_time is not None
                        and expiry_time <= dt.datetime.now().astimezone()
                    ):
                        errors.append(
                            f"packet {packet_id} active dispatch attempt {attempt_index} is expired"
                        )
                    if observation is not None or closed_at or reason:
                        errors.append(
                            f"packet {packet_id} active dispatch attempt {attempt_index} carries closure data"
                        )
                elif attempt_status == "consumed":
                    required_observation_fields = {
                        "event_id",
                        "hook_protocol_version",
                        "parent_session_id",
                        "turn_id",
                        "agent_id",
                        "agent_type",
                        "permission_mode",
                        "observed_at",
                    }
                    if (
                        not isinstance(observation, dict)
                        or set(observation) != required_observation_fields
                    ):
                        errors.append(
                            f"packet {packet_id} consumed dispatch attempt {attempt_index} has an invalid observation schema"
                        )
                    else:
                        observation_time = parse_time(
                            str(observation.get("observed_at", ""))
                        )
                        observation_payload = {
                            "session_id": observation.get("parent_session_id", ""),
                            "turn_id": observation.get("turn_id", ""),
                            "agent_id": observation.get("agent_id", ""),
                            "agent_type": observation.get("agent_type", ""),
                        }
                        if (
                            not _is_exact_int(
                                observation.get("hook_protocol_version"),
                                int(HOOK_PROTOCOL_VERSION),
                            )
                            or observation_time is None
                            or closed_at != observation.get("observed_at")
                            or reason
                            or observation.get("event_id")
                            != services.subagent_event_id(observation_payload)
                            or observation.get("parent_session_id")
                            != attempt.get("parent_session_id")
                            or observation.get("agent_type")
                            != attempt.get("expected_agent_type")
                            or not HOOK_ID_RE.fullmatch(
                                str(observation.get("parent_session_id", ""))
                            )
                            or not HOOK_ID_RE.fullmatch(
                                str(observation.get("agent_id", ""))
                            )
                            or not HOOK_ID_RE.fullmatch(
                                str(observation.get("agent_type", ""))
                            )
                            or not isinstance(observation.get("turn_id"), str)
                            or services.safe_hook_observation_text(
                                observation.get("turn_id", "")
                            )
                            != observation.get("turn_id")
                            or not isinstance(observation.get("permission_mode"), str)
                            or services.safe_hook_observation_text(
                                observation.get("permission_mode", "")
                            )
                            != observation.get("permission_mode")
                        ):
                            errors.append(
                                f"packet {packet_id} consumed dispatch attempt {attempt_index} observation lost identity integrity"
                            )
                elif (
                    observation is not None
                    or parse_time(closed_at) is None
                    or not reason
                ):
                    errors.append(
                        f"packet {packet_id} closed dispatch attempt {attempt_index} lacks valid closure evidence"
                    )
            provenance = packet.get("dispatch_provenance")
            dispatch_recorded_at = str(packet.get("dispatch_recorded_at", ""))
            if status in {"ready", "armed"} and provenance != "none":
                errors.append(
                    f"packet {packet_id} has dispatch provenance before dispatch"
                )
            if provenance == "none" and dispatch_recorded_at:
                errors.append(
                    f"packet {packet_id} records dispatch timing without dispatch provenance"
                )
            if status == "dispatched" and provenance not in (
                HOOK_OBSERVED_DISPATCH_PROVENANCES | {"manual_unverified"}
            ):
                errors.append(f"packet {packet_id} dispatched state lacks provenance")
            if status in {"done", "failed"} and provenance not in (
                HOOK_OBSERVED_DISPATCH_PROVENANCES | {"manual_unverified"}
            ):
                errors.append(f"packet {packet_id} terminal work lacks dispatch provenance")
            if provenance == "manual_unverified":
                if not packet.get("manual_unverified_reason"):
                    errors.append(f"packet {packet_id} manual dispatch lacks a reason")
                if parse_time(dispatch_recorded_at) is None:
                    errors.append(
                        f"packet {packet_id} manual dispatch lacks a valid registration time"
                    )
                if any(
                    isinstance(attempt, dict) and attempt.get("observation")
                    for attempt in attempts
                ):
                    errors.append(
                        f"packet {packet_id} manual dispatch carries a hook observation"
                    )
                if not any(
                    isinstance(attempt, dict)
                    and attempt.get("status") == "disarmed"
                    for attempt in attempts
                ) and packet.get("legacy_manual_dispatch_migration") is not True:
                    errors.append(
                        f"packet {packet_id} manual dispatch lacks a prior arm or legacy migration marker"
                    )
            if provenance in HOOK_OBSERVED_DISPATCH_PROVENANCES:
                consumed = [
                    attempt
                    for attempt in attempts
                    if isinstance(attempt, dict)
                    and attempt.get("status") == "consumed"
                    and isinstance(attempt.get("observation"), dict)
                ]
                if len(consumed) != 1:
                    errors.append(
                        f"packet {packet_id} observed dispatch lacks one consumed observation"
                    )
                else:
                    observation = consumed[0]["observation"]
                    if (
                        packet.get("agent_id") != observation.get("agent_id")
                        or dispatch_recorded_at != observation.get("observed_at")
                        or packet.get("manual_unverified_reason")
                    ):
                        errors.append(
                            f"packet {packet_id} observed dispatch lost packet/observation binding"
                        )
            if provenance in (
                HOOK_OBSERVED_DISPATCH_PROVENANCES | {"manual_unverified"}
            ) and not packet.get("agent_id"):
                errors.append(
                    f"packet {packet_id} dispatch provenance lacks an agent id"
                )
        if status in TERMINAL_PACKET_STATUSES:
            errors.extend(packet_result_integrity_errors(paths, state, packet))
    return errors


def subagent_incident_integrity_errors(
    state: dict[str, Any], *, services: PacketIntegrityServices
) -> list[str]:
    errors: list[str] = []
    incidents = state.get("subagent_incidents", [])
    v5_packets = any(
        (_packet_schema_version(packet) or 0) >= 5
        for packet in state.get("packets", [])
    )
    if (incidents or v5_packets) and state.get("dispatch_model_version") != 1:
        errors.append("dispatch v1 records require dispatch_model_version=1")
    seen: set[str] = set()
    arm_slots: dict[tuple[str, str], str] = {}
    for packet in state.get("packets", []):
        if packet.get("status") != "armed":
            continue
        try:
            attempt = services.active_dispatch_attempt(packet)
        except HarnessError as exc:
            errors.append(str(exc))
            continue
        slot = (
            str(attempt.get("parent_session_id", "")),
            str(attempt.get("expected_agent_type", "")),
        )
        prior = arm_slots.get(slot)
        if prior is not None:
            errors.append(
                "multiple armed packets occupy parent-session/agent-type slot "
                f"{slot[0]}/{slot[1]}: {prior}, {packet.get('packet_id')}"
            )
        arm_slots[slot] = str(packet.get("packet_id", ""))
    for incident in incidents:
        incident_id = str(incident.get("incident_id", ""))
        if not re.fullmatch(r"spawn-[0-9a-f]{32}", incident_id):
            errors.append(f"spawn incident {incident_id!r} has an invalid id")
        if incident_id in seen:
            errors.append(f"duplicate spawn incident id {incident_id}")
        seen.add(incident_id)
        if (
            incident.get("kind") != "unmanaged_subagent_start"
            or incident.get("status") not in {"open", "accounted"}
            or not _is_exact_int(
                incident.get("hook_protocol_version"), int(HOOK_PROTOCOL_VERSION)
            )
            or not isinstance(incident.get("candidate_packet_ids"), list)
        ):
            errors.append(f"spawn incident {incident_id} has an invalid schema")
        if incident.get("status") == "open" and incident.get("resolution") is not None:
            errors.append(f"open spawn incident {incident_id} carries a resolution")
        if incident.get("status") == "accounted":
            resolution = incident.get("resolution")
            if (
                not isinstance(resolution, dict)
                or resolution.get("disposition")
                not in {"no_material_work", "work_discarded", "manual_unverified"}
            ):
                errors.append(f"accounted spawn incident {incident_id} lacks disposition")
    return errors


def _require_done_reviewer_packet(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet_id: str,
    *,
    required_artifact_shas: set[str] | None = None,
    services: PacketIntegrityServices,
) -> dict[str, Any]:
    packet_id = validate_id(packet_id, "independent review packet id")
    matches = [
        packet
        for packet in state.get("packets", [])
        if packet.get("packet_id") == packet_id
    ]
    if len(matches) != 1:
        raise HarnessError(
            f"independent review requires exactly one reviewer packet named {packet_id}"
        )
    packet = matches[0]
    if (
        packet.get("status") != "done"
        or packet.get("agent_role") != "reviewer"
        or not str(packet.get("agent_id", "")).strip()
        or (
            packet.get("actual_role")
            and packet.get("actual_role") != "reviewer"
        )
    ):
        raise HarnessError(
            "independent review packet must be a done reviewer assignment with an agent identity"
        )
    authority_errors = packet_authority_integrity_errors(
        paths, state, packet, require_origin=False, services=services
    )
    if authority_errors:
        raise HarnessError(
            "independent review packet authority is missing or tampered: "
            + "; ".join(authority_errors)
        )
    expected = task_dir(paths, state["task_id"]) / "results" / f"{packet_id}.md"
    if (
        Path(str(packet.get("result_path", ""))) != expected
        or not expected.is_file()
        or expected.is_symlink()
        or packet.get("integrity_version") != 1
        or sha256_file(expected) != packet.get("result_sha256")
    ):
        raise HarnessError("independent review packet result is missing or tampered")
    if required_artifact_shas is not None:
        packet_artifact_shas = {
            str(item.get("sha256", ""))
            for item in packet.get("input_artifact_refs", [])
        }
        if not required_artifact_shas.issubset(packet_artifact_shas):
            raise HarnessError(
                "independent reviewer packet is not bound to every candidate artifact"
            )
    return packet


__all__ = [
    "ActiveDispatchAttempt",
    "DISPATCH_ARM_MAX_SECONDS",
    "DISPATCH_PROVENANCES",
    "DispatchAttemptAuthoritySha256",
    "HOOK_ID_RE",
    "HOOK_PROTOCOL_VERSION",
    "NATIVE_V5_PACKET_CONTRACT_MARKER",
    "PacketIntegrityServices",
    "SafeHookObservationText",
    "SelectionTerminalPacketBindings",
    "SubagentEventId",
    "ValidatePacketResourceEnvelope",
    "_require_done_reviewer_packet",
    "packet_authority_integrity_errors",
    "packet_command_integrity_error",
    "packet_contract_integrity_error",
    "packet_input_integrity_errors",
    "packet_integrity_errors",
    "packet_integrity_warnings",
    "packet_lock_integrity_errors",
    "packet_resource_envelope_integrity_errors",
    "packet_result_integrity_errors",
    "selection_done_packet_authority_errors",
    "subagent_incident_integrity_errors",
]
