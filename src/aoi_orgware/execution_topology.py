"""Execution-topology and job-activation fences independent of CLI parsing.

The CLI remains the composition root.  It validates the exact execution
selection, resource envelope, and delegation topology a packet or external job
may activate under.  Resource-envelope authority itself lives in
:mod:`aoi_orgware.resource_governance`; the small ``_lane_authority_snapshot``
helper here delegates to that module so lane snapshots stay canonical.

Two families of authority are supplied by the composition root rather than read
from mutable CLI globals: packet authority integrity and packet resource
envelopes (both project-profile dependent) plus the terminal specialist
bindings a Steward synthesis packet must match.  They arrive through the frozen
:class:`ExecutionTopologyServices` dataclass so this module never observes stale
CLI state.  This module imports only sibling packages and never imports
:mod:`aoi_orgware.cli`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from . import resource_governance
from .execution_policy import _execution_policy_v2_enabled
from .harnesslib import (
    ACTIVE_JOB_STATUSES,
    ACTIVE_PACKET_STATUSES,
    HarnessError,
    HarnessPaths,
    lock_covers,
)
from .state_lookup import (
    _engaged_steward_lane,
    _packet_by_id,
    execution_selection_by_id,
    lane_by_id,
)


EXECUTING_PACKET_STATUSES = {"armed", "dispatched"}


class PacketAuthorityIntegrityErrors(Protocol):
    def __call__(
        self,
        paths: HarnessPaths,
        state: dict[str, Any],
        packet: dict[str, Any],
        *,
        require_origin: bool,
    ) -> list[str]: ...


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


@dataclass(frozen=True)
class ExecutionTopologyServices:
    """Authority and derived-state operations supplied by the composition root."""

    packet_authority_integrity_errors: PacketAuthorityIntegrityErrors
    validate_packet_resource_envelope: ValidatePacketResourceEnvelope
    selection_terminal_packet_bindings: SelectionTerminalPacketBindings


def _is_exact_int(value: Any, expected: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == expected


def _lane_authority_snapshot(lane: dict[str, Any]) -> dict[str, Any]:
    return resource_governance.lane_authority_snapshot(lane)


def _validate_active_execution_selection(
    state: dict[str, Any], lane_id: str, selection_id: str
) -> dict[str, Any] | None:
    active = [
        item
        for item in state.get("execution_selections", [])
        if item.get("status") == "active"
    ]
    if active and not selection_id:
        raise HarnessError(
            "task has active execution topology; bind --execution-selection-id"
        )
    if not selection_id:
        return None
    selection = execution_selection_by_id(state, selection_id)
    if selection.get("status") != "active":
        raise HarnessError("execution selection is not active")
    if not lane_id:
        raise HarnessError("execution-selected work requires an exact --lane-id")
    snapshots = {
        str(item.get("lane_id")): item
        for item in selection.get("lane_snapshots", [])
    }
    if lane_id not in snapshots:
        raise HarnessError("packet/job lane is outside the selected execution topology")
    _require_execution_selection_snapshots_current(state, selection)
    return selection


def _require_execution_selection_snapshots_current(
    state: dict[str, Any], selection: dict[str, Any], *, include_steward: bool = False
) -> None:
    snapshots = {
        str(item.get("lane_id")): item
        for item in selection.get("lane_snapshots", [])
    }
    steward_snapshot = selection.get("steward_snapshot", {})
    if (
        include_steward
        and isinstance(steward_snapshot, dict)
        and steward_snapshot.get("lane_id")
    ):
        snapshots[str(steward_snapshot["lane_id"])] = steward_snapshot
    for selected_lane_id, snapshot in snapshots.items():
        lane = lane_by_id(state, selected_lane_id)
        if any(
            snapshot.get(field) != lane.get(field)
            for field in ("revision", "authority_commit", "contract_version")
        ):
            raise HarnessError(
                "execution selection is stale; select topology again before dispatch"
            )


def _is_steward_synthesis_packet(packet: dict[str, Any]) -> bool:
    return packet.get("packet_purpose") == "steward_synthesis"


def _selection_synthesis_freeze_packet_ids(
    state: dict[str, Any], selection_id: str
) -> list[str]:
    return sorted(
        str(packet.get("packet_id", ""))
        for packet in state.get("packets", [])
        if packet.get("execution_selection_id") == selection_id
        and _is_steward_synthesis_packet(packet)
        and packet.get("status") not in {"failed", "cancelled"}
    )


def _validate_steward_synthesis_dispatch(
    state: dict[str, Any], packet: dict[str, Any], *, services: ExecutionTopologyServices
) -> dict[str, Any]:
    selection_id = str(packet.get("execution_selection_id", ""))
    selection = execution_selection_by_id(state, selection_id)
    if (
        selection.get("status") != "active"
        or not _is_exact_int(selection.get("execution_selection_version"), 2)
        or selection.get("mode") not in {"centralized_parallel", "hybrid"}
    ):
        raise HarnessError(
            "Steward synthesis requires an active parallel/hybrid selection v2"
        )
    selected_steward = selection.get("steward_snapshot", {})
    current_steward = _engaged_steward_lane(state)
    if (
        not isinstance(selected_steward, dict)
        or not selected_steward
        or packet.get("lane_id") != selected_steward.get("lane_id")
        or packet.get("steward_selection_snapshot") != selected_steward
        or packet.get("steward_execution_snapshot")
        != _lane_authority_snapshot(current_steward)
    ):
        raise HarnessError("Steward synthesis authority snapshot is stale or mismatched")
    bindings = services.selection_terminal_packet_bindings(state, selection_id)
    if not bindings or packet.get("steward_input_bindings") != bindings:
        raise HarnessError("Steward synthesis specialist result bindings are stale")
    selected_lane_ids = {
        str(item.get("lane_id", "")) for item in selection.get("lane_snapshots", [])
    }
    if {item["lane_id"] for item in bindings} != selected_lane_ids:
        raise HarnessError(
            "Steward synthesis requires terminal specialist evidence from every selected lane"
        )
    unfinished = [
        str(item.get("packet_id", ""))
        for item in state.get("packets", [])
        if item.get("packet_id") != packet.get("packet_id")
        and item.get("execution_selection_id") == selection_id
        and not _is_steward_synthesis_packet(item)
        and item.get("status") in ACTIVE_PACKET_STATUSES
    ]
    active_jobs = [
        str(item.get("run_id", ""))
        for item in state.get("jobs", [])
        if item.get("execution_selection_id") == selection_id
        and item.get("status") in ACTIVE_JOB_STATUSES
    ]
    if unfinished or active_jobs:
        raise HarnessError(
            "Steward synthesis requires terminal specialist work: "
            + ", ".join(unfinished + active_jobs)
        )
    return selection


def _validate_dispatch_selection(
    state: dict[str, Any], packet: dict[str, Any], *, services: ExecutionTopologyServices
) -> dict[str, Any] | None:
    """Validate the exact topology contract used by a packet activation."""

    if _is_steward_synthesis_packet(packet):
        return _validate_steward_synthesis_dispatch(state, packet, services=services)
    selection = _validate_active_execution_selection(
        state,
        str(packet.get("lane_id", "")),
        str(packet.get("execution_selection_id", "")),
    )
    if selection is None:
        return None
    if not _is_exact_int(selection.get("execution_selection_version"), 2):
        raise HarnessError(
            "packet activation requires execution selection v2; supersede the legacy selection"
        )
    mode = str(selection.get("mode", ""))
    steward_snapshot = selection.get("steward_snapshot", {})
    if mode == "single":
        if steward_snapshot not in ({}, None):
            raise HarnessError("single execution selection may not carry a Steward snapshot")
        return selection
    if mode not in {"centralized_parallel", "hybrid"}:
        raise HarnessError("execution selection has an invalid dispatch mode")
    if not isinstance(steward_snapshot, dict) or not steward_snapshot:
        raise HarnessError("parallel execution selection lacks its Steward snapshot")
    steward = _engaged_steward_lane(state)
    if steward_snapshot != _lane_authority_snapshot(steward):
        raise HarnessError(
            "execution selection Steward snapshot is stale; select topology again"
        )
    selected_lane_ids = {
        str(item.get("lane_id", "")) for item in selection.get("lane_snapshots", [])
    }
    if steward["lane_id"] in selected_lane_ids:
        raise HarnessError("parallel specialist lanes may not include the Steward lane")
    return selection


def _validate_packet_activation_topology(
    state: dict[str, Any], packet: dict[str, Any], *, services: ExecutionTopologyServices
) -> dict[str, Any] | None:
    """Fence active packet chains; ready packets remain pre-buildable."""

    selection = _validate_dispatch_selection(state, packet, services=services)
    services.validate_packet_resource_envelope(
        state,
        packet,
        selection,
        enforce_active_limit=False,
    )
    packet_id = str(packet.get("packet_id", ""))
    depth = int(packet.get("delegation_depth", 1))
    executing = [
        item
        for item in state.get("packets", [])
        if item.get("packet_id") != packet_id
        and item.get("status") in EXECUTING_PACKET_STATUSES
    ]
    standalone_jobs = [
        item
        for item in state.get("jobs", [])
        if item.get("status") in ACTIVE_JOB_STATUSES
        and not str(item.get("owner_packet_id", ""))
    ]

    def chain_names(
        packets: list[dict[str, Any]], jobs: list[dict[str, Any]]
    ) -> str:
        return ", ".join(
            [str(item.get("packet_id")) for item in packets]
            + [f"job:{item.get('run_id')}" for item in jobs]
        )

    selection_id = str(packet.get("execution_selection_id", ""))
    lane_id = str(packet.get("lane_id", ""))
    if depth == 1:
        peers = [
            item
            for item in executing
            if int(item.get("delegation_depth", 1)) == 1
        ]
        if _is_steward_synthesis_packet(packet):
            if peers or standalone_jobs:
                raise HarnessError(
                    "Steward synthesis is sequential and requires an empty task execution epoch: "
                    + chain_names(peers, standalone_jobs)
                )
            return selection
        if _execution_policy_v2_enabled(state):
            synthesis_peers = [
                item for item in peers if _is_steward_synthesis_packet(item)
            ]
            if synthesis_peers:
                raise HarnessError(
                    "Steward synthesis already occupies the sequential execution phase: "
                    + ", ".join(
                        str(item.get("packet_id")) for item in synthesis_peers
                    )
                )
            if selection is None:
                if peers or standalone_jobs:
                    raise HarnessError(
                        "implicit single execution already has an active depth-one "
                        "packet chain: "
                        + chain_names(peers, standalone_jobs)
                    )
                return None
            foreign = [
                item
                for item in peers
                if str(item.get("execution_selection_id", "")) != selection_id
            ]
            if foreign:
                raise HarnessError(
                    "task-global execution epoch is already occupied by another "
                    "selection/implicit chain: "
                    + ", ".join(str(item.get("packet_id")) for item in foreign)
                )
            foreign_jobs = [
                item
                for item in standalone_jobs
                if str(item.get("execution_selection_id", "")) != selection_id
            ]
            if foreign_jobs:
                raise HarnessError(
                    "task-global execution epoch is already occupied by another "
                    "selection/implicit job chain: "
                    + chain_names([], foreign_jobs)
                )
            mode = str(selection.get("mode", "single"))
            if mode == "single" and (peers or standalone_jobs):
                raise HarnessError(
                    "single execution mode already has an active depth-one packet chain: "
                    + chain_names(peers, standalone_jobs)
                )
            if mode in {"centralized_parallel", "hybrid"}:
                same_lane = [item for item in peers if item.get("lane_id") == lane_id]
                same_lane_jobs = [
                    item for item in standalone_jobs if item.get("lane_id") == lane_id
                ]
                if same_lane or same_lane_jobs:
                    raise HarnessError(
                        "parallel execution mode already has an active depth-one chain in lane "
                        f"{lane_id}: "
                        + chain_names(same_lane, same_lane_jobs)
                    )
            return selection
        if selection is None:
            # Legacy/unselected tasks retain their prior cooperative behavior.
            # Once a task selects topology, v2 activation rules are mandatory.
            return None
        peers = [
            item
            for item in executing
            if int(item.get("delegation_depth", 1)) == 1
            and str(item.get("execution_selection_id", "")) == selection_id
        ]
        selection_jobs = [
            item
            for item in standalone_jobs
            if str(item.get("execution_selection_id", "")) == selection_id
        ]
        mode = str(selection.get("mode", "single")) if selection else "single"
        if mode == "single" and (peers or selection_jobs):
            raise HarnessError(
                "single execution mode already has an active depth-one packet chain: "
                + chain_names(peers, selection_jobs)
            )
        if mode in {"centralized_parallel", "hybrid"}:
            same_lane = [item for item in peers if item.get("lane_id") == lane_id]
            same_lane_jobs = [
                item for item in selection_jobs if item.get("lane_id") == lane_id
            ]
            if same_lane or same_lane_jobs:
                raise HarnessError(
                    "parallel execution mode already has an active depth-one chain in lane "
                    f"{lane_id}: "
                    + chain_names(same_lane, same_lane_jobs)
                )
        return selection
    if depth != 2:
        raise HarnessError("packet delegation depth is invalid")
    parent_id = str(packet.get("parent_packet_id", ""))
    parent = _packet_by_id(state, parent_id)
    if (
        parent.get("status") != "dispatched"
        or int(parent.get("delegation_depth", 1)) != 1
        or str(parent.get("lane_id", "")) != lane_id
        or str(parent.get("execution_selection_id", "")) != selection_id
    ):
        raise HarnessError(
            "depth-two activation requires its dispatched depth-one parent in the same lane"
        )
    siblings = [
        item
        for item in executing
        if int(item.get("delegation_depth", 1)) == 2
        and item.get("parent_packet_id") == parent_id
    ]
    if siblings:
        raise HarnessError(
            "depth-two parent already has an active child: "
            + ", ".join(str(item.get("packet_id")) for item in siblings)
        )
    return selection


def _validate_owned_job_authority(
    paths: HarnessPaths | None,
    state: dict[str, Any],
    job: dict[str, Any],
    *,
    require_dispatched: bool,
    services: ExecutionTopologyServices,
) -> dict[str, Any]:
    """Recompute the physical and semantic authority for one owned job."""

    run_id = str(job.get("run_id", ""))
    owner_packet_id = str(job.get("owner_packet_id", ""))
    owner = _packet_by_id(state, owner_packet_id)
    if (
        int(owner.get("delegation_depth", 1)) != 1
        or _is_steward_synthesis_packet(owner)
        or owner.get("packet_mode") not in {"bounded_mutation", "exact_command"}
        or str(owner.get("lane_id", "")) != str(job.get("lane_id", ""))
        or str(owner.get("execution_selection_id", ""))
        != str(job.get("execution_selection_id", ""))
    ):
        raise HarnessError(
            "external job owner must be a depth-one mutation packet in the same "
            "lane and execution selection"
        )
    if require_dispatched and owner.get("status") != "dispatched":
        raise HarnessError("active external job owner packet is not dispatched")
    if job.get("owner_packet_contract_sha256") != owner.get(
        "packet_contract_sha256", ""
    ):
        raise HarnessError("external job owner packet contract binding changed")
    if paths is not None:
        authority_errors = services.packet_authority_integrity_errors(
            paths,
            state,
            owner,
            require_origin=False,
        )
        if authority_errors:
            raise HarnessError(
                "external job owner packet authority is missing or tampered: "
                + "; ".join(authority_errors)
            )
        namespace = paths.project.external_lock_namespace
        if job.get("external_lock_namespace") != namespace:
            raise HarnessError(
                f"external job {run_id} lost its external lock namespace binding"
            )
        required_output_locks = [
            f"{namespace}:tree:{job.get('work_root', '')}",
            f"{namespace}:file:{job.get('log', '')}",
        ]
        if job.get("required_output_locks") != required_output_locks:
            raise HarnessError(
                f"external job {run_id} required output locks are non-canonical or changed"
            )
        uncovered = [
            lock
            for lock in required_output_locks
            if not any(
                lock_covers(held, lock) for held in owner.get("locks", [])
            )
        ]
        if uncovered:
            raise HarnessError(
                "external job output paths exceed the owner packet locks: "
                + ", ".join(uncovered)
            )
    if (
        owner.get("packet_mode") == "exact_command"
        and owner.get("command_sha256") != job.get("command_sha256")
    ):
        raise HarnessError(
            "external job command differs from its exact-command owner packet"
        )
    return owner


def _validate_job_activation_topology(
    state: dict[str, Any],
    job: dict[str, Any],
    selection: dict[str, Any] | None,
    *,
    paths: HarnessPaths | None = None,
    exclude_run_id: str = "",
    services: ExecutionTopologyServices,
) -> dict[str, Any] | None:
    """Bind an external job to one depth-one chain or make it that chain."""

    selection_id = str(job.get("execution_selection_id", ""))
    lane_id = str(job.get("lane_id", ""))
    owner_packet_id = str(job.get("owner_packet_id", ""))
    if owner_packet_id:
        owner = _validate_owned_job_authority(
            paths, state, job, require_dispatched=True, services=services
        )
        _validate_packet_activation_topology(state, owner, services=services)
        return selection

    packet_chains = [
        packet
        for packet in state.get("packets", [])
        if packet.get("status") in EXECUTING_PACKET_STATUSES
        and int(packet.get("delegation_depth", 1)) == 1
    ]
    job_chains = [
        item
        for item in state.get("jobs", [])
        if item.get("status") in ACTIVE_JOB_STATUSES
        and not str(item.get("owner_packet_id", ""))
        and str(item.get("run_id", "")) != exclude_run_id
    ]

    def names(
        packets: list[dict[str, Any]], jobs: list[dict[str, Any]]
    ) -> str:
        return ", ".join(
            [f"packet:{item.get('packet_id')}" for item in packets]
            + [f"job:{item.get('run_id')}" for item in jobs]
        )

    if _execution_policy_v2_enabled(state):
        if selection is None:
            if packet_chains or job_chains:
                raise HarnessError(
                    "implicit single execution already has an active chain: "
                    + names(packet_chains, job_chains)
                )
            return None
        foreign_packets = [
            item
            for item in packet_chains
            if str(item.get("execution_selection_id", "")) != selection_id
        ]
        foreign_jobs = [
            item
            for item in job_chains
            if str(item.get("execution_selection_id", "")) != selection_id
        ]
        if foreign_packets or foreign_jobs:
            raise HarnessError(
                "task-global execution epoch is already occupied by another "
                "selection/implicit chain: "
                + names(foreign_packets, foreign_jobs)
            )
        mode = str(selection.get("mode", "single"))
        if mode == "single" and (packet_chains or job_chains):
            raise HarnessError(
                "single execution mode already has an active chain: "
                + names(packet_chains, job_chains)
            )
        if mode in {"centralized_parallel", "hybrid"}:
            same_lane_packets = [
                item for item in packet_chains if item.get("lane_id") == lane_id
            ]
            same_lane_jobs = [
                item for item in job_chains if item.get("lane_id") == lane_id
            ]
            if same_lane_packets or same_lane_jobs:
                raise HarnessError(
                    "parallel execution mode already has an active chain in lane "
                    f"{lane_id}: "
                    + names(same_lane_packets, same_lane_jobs)
                )
        return selection

    if selection is None:
        return None
    same_selection_packets = [
        item
        for item in packet_chains
        if str(item.get("execution_selection_id", "")) == selection_id
    ]
    same_selection_jobs = [
        item
        for item in job_chains
        if str(item.get("execution_selection_id", "")) == selection_id
    ]
    mode = str(selection.get("mode", "single"))
    if mode == "single" and (same_selection_packets or same_selection_jobs):
        raise HarnessError(
            "single execution mode already has an active chain: "
            + names(same_selection_packets, same_selection_jobs)
        )
    if mode in {"centralized_parallel", "hybrid"}:
        same_lane_packets = [
            item for item in same_selection_packets if item.get("lane_id") == lane_id
        ]
        same_lane_jobs = [
            item for item in same_selection_jobs if item.get("lane_id") == lane_id
        ]
        if same_lane_packets or same_lane_jobs:
            raise HarnessError(
                "parallel execution mode already has an active chain in lane "
                f"{lane_id}: "
                + names(same_lane_packets, same_lane_jobs)
            )
    return selection


__all__ = [
    "EXECUTING_PACKET_STATUSES",
    "ExecutionTopologyServices",
    "PacketAuthorityIntegrityErrors",
    "SelectionTerminalPacketBindings",
    "ValidatePacketResourceEnvelope",
    "_is_steward_synthesis_packet",
    "_require_execution_selection_snapshots_current",
    "_selection_synthesis_freeze_packet_ids",
    "_validate_active_execution_selection",
    "_validate_dispatch_selection",
    "_validate_job_activation_topology",
    "_validate_owned_job_authority",
    "_validate_packet_activation_topology",
    "_validate_steward_synthesis_dispatch",
]
