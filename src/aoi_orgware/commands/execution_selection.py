"""Execution-selection / execution-brief command family: syntax registration
and command bodies.

This module owns the ``execution-select-plan``, ``execution-select`` and
``execution-brief-record`` command implementations together with their
argument-validation and target-contract helpers.  It stays a leaf of the
composition root: it imports only sibling packages (``harnesslib``,
``state_lookup``, ``execution_policy``, ``resource_config``,
``context_receipts``, ``resource_governance``), never the monolithic
:mod:`aoi_orgware.cli`.  The CLI imports the command bodies back for handler
wiring and keeps the mutable-constant/factory composition root.

Composition-root concerns that cannot be imported statically are threaded in
through the frozen :class:`ExecutionSelectionCmdServices` dataclass built by
``cli._execution_selection_cmd_services()``:

* CLI-resident derived-state operations (``require_plan_ready``,
  ``require_root_session``, ``approved_override_settings``,
  ``require_override_target_contract``, ``override_by_id``,
  ``packet_authority_integrity_errors``, ``packet_result_integrity_errors``,
  ``selection_done_packet_authority_errors``) and the CLI-resident helpers that
  stay in ``cli`` as single sources of truth — ``_build_execution_resource_envelope``
  and ``_lane_authority_snapshot`` (policy-closing wrappers, the latter also
  consumed by the keep-list Steward-synthesis command),
  ``_selection_terminal_packet_bindings`` and ``_steward_packet_binding`` (both
  wired into the CLI-resident ``PacketIntegrityServices`` /
  ``ExecutionTopologyServices`` / ``PortfolioIntegrityServices`` factories, and
  identity-asserted off ``cli`` in the suite), and
  ``_execution_brief_coverage_error`` (unit-tested off ``cli`` and consumed by
  the keep-list task-integrity projection) — are direct-bound: none is
  fault-injected via ``mock.patch.object(cli, ...)``.
* ``role_tier_map`` is a zero-argument callable that resolves ``cli``'s current
  ``apply_project_config``-mutable ``ROLE_TIER_MAP`` binding at call time (the
  one name the suite fault-injects via ``mock.patch.object(cli, ...)``), so it
  is bound late.  The immutable ``TERMINAL_COORDINATION_STATUSES`` set (not
  rebound by ``apply_project_config``, not test-patched) is value-bound so
  ``cli`` stays its single source of truth.

``_validate_execution_selection_arguments`` and
``_execution_selection_target_contract_from_record`` depend on no
composition-root concern, so they are pure verbatim moves.
``_build_execution_selection_target_contract`` needs the two policy-closing
wrappers above, so it takes the ``services`` object as a keyword argument.
``emit``, ``require_text``, ``require_evidence_detail``, ``canonical_record_sha256``
and ``_is_exact_int`` are pure leaf helpers redeclared module-locally (neither
project-mutable nor test-patched), mirroring the sibling extraction precedent,
so the relocated bodies bind the module-local copies rather than reaching back
into ``cli``.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .. import resource_governance as resource_governance_impl
from ..context_receipts import context_provider_brief_bindings
from ..execution_policy import (
    _adopt_execution_policy_v2_for_new_work,
    _execution_policy_v2_enabled,
)
from ..harnesslib import (
    ACTIVE_JOB_STATUSES,
    ACTIVE_PACKET_STATUSES,
    HarnessError,
    HarnessPaths,
    bump_task,
    load_task,
    now_iso,
    state_lock,
    validate_id,
    write_index,
    write_task,
)
from ..resource_config import parse_override_settings
from ..state_lookup import (
    _engaged_steward_lane,
    _packet_by_id,
    coordination_by_id,
    execution_selection_by_id,
    lane_by_id,
    require_open_task,
)


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset(
    {
        "execution_select_plan",
        "execution_select",
        "execution_brief_record",
    }
)


class _RequirePlanReady(Protocol):
    def __call__(
        self, paths: HarnessPaths, state: dict[str, Any], action: str
    ) -> None: ...


class _RequireRootSession(Protocol):
    def __call__(
        self, paths: HarnessPaths, state: dict[str, Any], session_id: str
    ) -> str: ...


class _ApprovedOverrideSettings(Protocol):
    def __call__(
        self,
        state: dict[str, Any],
        override_id: str,
        *,
        target_kind: str,
        target_id: str,
    ) -> dict[str, str | int]: ...


class _RequireOverrideTargetContract(Protocol):
    def __call__(
        self, state: dict[str, Any], override_id: str, target_contract_sha256: str
    ) -> None: ...


class _OverrideById(Protocol):
    def __call__(
        self, state: dict[str, Any], override_id: str
    ) -> dict[str, Any]: ...


class _BuildExecutionResourceEnvelope(Protocol):
    def __call__(
        self,
        *,
        mode: str,
        lanes: list[dict[str, Any]],
        steward: dict[str, Any] | None,
        override_id: str,
        override_settings: dict[str, str | int],
    ) -> tuple[dict[str, Any], str]: ...


class _LaneAuthoritySnapshot(Protocol):
    def __call__(self, lane: dict[str, Any]) -> dict[str, Any]: ...


class _ExecutionBriefCoverageError(Protocol):
    def __call__(
        self,
        paths: HarnessPaths,
        state: dict[str, Any],
        selection: dict[str, Any],
    ) -> str | None: ...


class _StewardPacketBinding(Protocol):
    def __call__(
        self, state: dict[str, Any], selection_id: str, packet_id: str
    ) -> dict[str, Any]: ...


class _SelectionTerminalPacketBindings(Protocol):
    def __call__(
        self, state: dict[str, Any], selection_id: str
    ) -> list[dict[str, Any]]: ...


class _PacketAuthorityIntegrityErrors(Protocol):
    def __call__(
        self,
        paths: HarnessPaths,
        state: dict[str, Any],
        packet: dict[str, Any],
        *,
        require_origin: bool,
    ) -> list[str]: ...


class _PacketResultIntegrityErrors(Protocol):
    def __call__(
        self, paths: HarnessPaths, state: dict[str, Any], packet: dict[str, Any]
    ) -> list[str]: ...


class _SelectionDonePacketAuthorityErrors(Protocol):
    def __call__(
        self, paths: HarnessPaths, state: dict[str, Any], selection_id: str
    ) -> list[str]: ...


@dataclass(frozen=True)
class ExecutionSelectionCmdServices:
    """CLI-resident helpers and composition-root policy constants.

    Every callable field is direct-bound in
    ``cli._execution_selection_cmd_services()`` except ``role_tier_map``: the
    suite fault-injects ``cli.ROLE_TIER_MAP`` via ``mock.patch.object`` and
    ``apply_project_config`` rebinds it, so it is a zero-argument callable that
    resolves the current binding at call time.  ``terminal_coordination_statuses``
    is an immutable set value-bound so ``cli`` stays its single source of truth.
    """

    require_plan_ready: _RequirePlanReady
    require_root_session: _RequireRootSession
    role_tier_map: Callable[[], Mapping[str, str]]
    terminal_coordination_statuses: Collection[str]
    approved_override_settings: _ApprovedOverrideSettings
    require_override_target_contract: _RequireOverrideTargetContract
    override_by_id: _OverrideById
    build_execution_resource_envelope: _BuildExecutionResourceEnvelope
    lane_authority_snapshot: _LaneAuthoritySnapshot
    execution_brief_coverage_error: _ExecutionBriefCoverageError
    steward_packet_binding: _StewardPacketBinding
    selection_terminal_packet_bindings: _SelectionTerminalPacketBindings
    packet_authority_integrity_errors: _PacketAuthorityIntegrityErrors
    packet_result_integrity_errors: _PacketResultIntegrityErrors
    selection_done_packet_authority_errors: _SelectionDonePacketAuthorityErrors


def emit(payload: Any, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif isinstance(payload, str):
        print(payload)
    elif isinstance(payload, dict):
        for key, value in payload.items():
            print(f"{key}: {value}")
    else:
        print(payload)


def require_text(value: str, label: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise HarnessError(f"{label} may not be empty")
    return stripped


def require_evidence_detail(value: str, label: str) -> str:
    detail = require_text(value, label)
    if len(detail) < 12 or detail.lower() in {"pass", "passed", "ok", "success", "done"}:
        raise HarnessError(
            f"{label} is too generic; cite an artifact, command result, or bounded observation"
        )
    return detail


def canonical_record_sha256(value: dict[str, Any]) -> str:
    payload = json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _is_exact_int(value: Any, expected: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == expected


def _validate_execution_selection_arguments(
    args: argparse.Namespace,
) -> tuple[str, str, list[str]]:
    selection_id = validate_id(args.selection_id, "execution selection id")
    work_unit_id = validate_id(args.work_unit_id, "execution work-unit id")
    if args.supersedes_selection_id:
        validate_id(args.supersedes_selection_id, "superseded execution selection id")
    lane_ids = list(dict.fromkeys(args.lane))
    if args.mode == "single" and len(lane_ids) != 1:
        raise HarnessError("single execution mode requires exactly one lane")
    if args.mode in {"centralized_parallel", "hybrid"} and len(lane_ids) < 2:
        raise HarnessError(f"{args.mode} execution mode requires at least two lanes")
    if args.mode == "centralized_parallel" and (
        args.sequential_dependency == "high" or args.shared_context == "high"
    ):
        raise HarnessError(
            "centralized_parallel is not allowed for high sequential dependency or shared context"
        )
    if args.mode == "single" and args.steward_lane_id:
        raise HarnessError("single execution mode may not bind a Steward lane")
    if args.mode in {"centralized_parallel", "hybrid"} and not args.steward_lane_id:
        raise HarnessError(f"{args.mode} execution mode requires --steward-lane-id")
    return selection_id, work_unit_id, lane_ids


def _build_execution_selection_target_contract(
    *,
    state: dict[str, Any],
    args: argparse.Namespace,
    selection_id: str,
    work_unit_id: str,
    lanes: list[dict[str, Any]],
    steward: dict[str, Any] | None,
    override_settings: dict[str, str | int],
    services: ExecutionSelectionCmdServices,
) -> tuple[dict[str, Any], str]:
    resource_envelope, resource_envelope_sha256 = services.build_execution_resource_envelope(
        mode=args.mode,
        lanes=lanes,
        steward=steward,
        override_id=args.override_id,
        override_settings=override_settings,
    )
    contract = {
        "schema_version": 1,
        "target_kind": "execution_resource",
        "target_id": selection_id,
        "target_task_id": state["task_id"],
        "task_plan_sha256": state["plan_sha256"],
        "override_id": args.override_id,
        "work_unit_id": work_unit_id,
        "supersedes_selection_id": args.supersedes_selection_id or "",
        "scope": require_evidence_detail(args.scope, "execution selection scope"),
        "mode": args.mode,
        "lane_snapshots": [
            services.lane_authority_snapshot(lane)
            for lane in sorted(lanes, key=lambda item: item["lane_id"])
        ],
        "steward_snapshot": (
            services.lane_authority_snapshot(steward) if steward is not None else {}
        ),
        "resource_envelope": resource_envelope,
        "resource_envelope_sha256": resource_envelope_sha256,
        "task_characteristics": {
            "sequential_dependency": args.sequential_dependency,
            "tool_density": args.tool_density,
            "shared_context": args.shared_context,
        },
        "rationale": require_evidence_detail(
            args.rationale, "execution topology rationale"
        ),
        "falsification_condition": require_evidence_detail(
            args.falsification_condition,
            "execution topology falsification condition",
        ),
        "escalation_condition": require_evidence_detail(
            args.escalation_condition, "execution topology escalation condition"
        ),
    }
    return contract, canonical_record_sha256(contract)


def _execution_selection_target_contract_from_record(
    state: dict[str, Any], selection: dict[str, Any]
) -> dict[str, Any]:
    return (
        resource_governance_impl.execution_selection_target_contract_from_record(
            state, selection
        )
    )


def cmd_execution_select_plan(
    args: argparse.Namespace,
    paths: HarnessPaths,
    *,
    services: ExecutionSelectionCmdServices,
) -> int:
    selection_id, work_unit_id, lane_ids = _validate_execution_selection_arguments(
        args
    )
    proposed_settings = parse_override_settings(
        args.proposed_setting,
        roles=services.role_tier_map(),
        target_kind="execution_resource",
    )
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "plan execution resource override for")
        services.require_plan_ready(paths, state, "plan execution resource override")
        services.require_root_session(paths, state, args.session_id)
        lanes = [lane_by_id(state, lane_id) for lane_id in lane_ids]
        if any(lane.get("status") in {"done", "parked"} for lane in lanes):
            raise HarnessError("execution selection may not use done or parked lanes")
        steward: dict[str, Any] | None = None
        if args.mode in {"centralized_parallel", "hybrid"}:
            steward = _engaged_steward_lane(state)
            if steward.get("lane_id") != args.steward_lane_id:
                raise HarnessError(
                    "--steward-lane-id must name the one engaged coordination_steward lane"
                )
            if any(lane.get("lane_id") == steward.get("lane_id") for lane in lanes):
                raise HarnessError("parallel specialist lanes may not include the Steward lane")
        contract, digest = _build_execution_selection_target_contract(
            state=state,
            args=args,
            selection_id=selection_id,
            work_unit_id=work_unit_id,
            lanes=lanes,
            steward=steward,
            override_settings=proposed_settings,
            services=services,
        )
    emit({**contract, "target_contract_sha256": digest}, args.json)
    return 0


def cmd_execution_select(
    args: argparse.Namespace,
    paths: HarnessPaths,
    *,
    services: ExecutionSelectionCmdServices,
) -> int:
    selection_id, work_unit_id, lane_ids = _validate_execution_selection_arguments(
        args
    )
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "select execution topology for")
        services.require_plan_ready(paths, state, "select execution topology")
        _adopt_execution_policy_v2_for_new_work(state)
        session_id = services.require_root_session(paths, state, args.session_id)
        resource_override_settings = services.approved_override_settings(
            state,
            args.override_id,
            target_kind="execution_resource",
            target_id=selection_id,
        )
        if any(
            item.get("selection_id") == selection_id
            for item in state.get("execution_selections", [])
        ):
            raise HarnessError(f"execution selection already exists: {selection_id}")
        active_same_work_unit = [
            item
            for item in state.get("execution_selections", [])
            if item.get("status") == "active"
            and item.get("work_unit_id") == work_unit_id
        ]
        if active_same_work_unit:
            if (
                len(active_same_work_unit) != 1
                or args.supersedes_selection_id
                != active_same_work_unit[0].get("selection_id")
            ):
                raise HarnessError(
                    "active topology for this work unit requires exact --supersedes-selection-id"
                )
            prior_selection = active_same_work_unit[0]
            prior_selection_id = str(prior_selection.get("selection_id", ""))
            blocking_cross_sessions = []
            for cross_session in state.get("cross_lane_sessions", []):
                if cross_session.get("execution_selection_id") != prior_selection_id:
                    continue
                request = coordination_by_id(
                    state, str(cross_session.get("request_id", ""))
                )
                if cross_session.get("status") == "open" or (
                    cross_session.get("status") == "closed"
                    and request.get("status")
                    not in services.terminal_coordination_statuses | {"accepted"}
                ):
                    blocking_cross_sessions.append(
                        str(cross_session.get("cross_lane_session_id", ""))
                    )
            active_records = [
                f"packet:{item.get('packet_id')}"
                for item in state.get("packets", [])
                if item.get("execution_selection_id") == prior_selection_id
                and item.get("status") in ACTIVE_PACKET_STATUSES
            ] + [
                f"job:{item.get('run_id')}"
                for item in state.get("jobs", [])
                if item.get("execution_selection_id") == prior_selection_id
                and item.get("status") in ACTIVE_JOB_STATUSES
            ]
            if blocking_cross_sessions or active_records:
                detail = ", ".join(blocking_cross_sessions + active_records)
                raise HarnessError(
                    "cannot supersede execution selection with active/unconsumed work; "
                    f"cancel, complete, or arbitrate first: {detail}"
                )
            if prior_selection.get("mode") in {"centralized_parallel", "hybrid"}:
                brief_error = services.execution_brief_coverage_error(
                    paths,
                    state,
                    prior_selection,
                )
                if brief_error:
                    raise HarnessError(brief_error)
            prior_selection["status"] = "superseded"
            prior_selection["superseded_by"] = selection_id
            prior_selection["superseded_at"] = now_iso()
        elif args.supersedes_selection_id:
            raise HarnessError("superseded execution selection is not active for this work unit")
        lanes = [lane_by_id(state, lane_id) for lane_id in lane_ids]
        if any(lane.get("status") in {"done", "parked"} for lane in lanes):
            raise HarnessError("execution selection may not use done or parked lanes")
        steward: dict[str, Any] | None = None
        if args.mode in {"centralized_parallel", "hybrid"}:
            steward = _engaged_steward_lane(state)
            if steward.get("lane_id") != args.steward_lane_id:
                raise HarnessError(
                    "--steward-lane-id must name the one engaged coordination_steward lane"
                )
            if any(lane.get("lane_id") == steward.get("lane_id") for lane in lanes):
                raise HarnessError("parallel specialist lanes may not include the Steward lane")
        target_contract, target_contract_sha256 = (
            _build_execution_selection_target_contract(
                state=state,
                args=args,
                selection_id=selection_id,
                work_unit_id=work_unit_id,
                lanes=lanes,
                steward=steward,
                override_settings=resource_override_settings,
                services=services,
            )
        )
        services.require_override_target_contract(
            state, args.override_id, target_contract_sha256
        )
        resource_envelope = target_contract["resource_envelope"]
        resource_envelope_sha256 = target_contract["resource_envelope_sha256"]
        recorded = now_iso()
        selection = {
            "integrity_version": 1,
            "execution_selection_version": 2,
            "selection_id": selection_id,
            "work_unit_id": work_unit_id,
            "supersedes_selection_id": target_contract["supersedes_selection_id"],
            "task_plan_sha256": target_contract["task_plan_sha256"],
            "scope": target_contract["scope"],
            "mode": target_contract["mode"],
            "lane_snapshots": target_contract["lane_snapshots"],
            "steward_snapshot": target_contract["steward_snapshot"],
            "resource_envelope": resource_envelope,
            "resource_envelope_sha256": resource_envelope_sha256,
            "target_contract_sha256": target_contract_sha256,
            "task_characteristics": target_contract["task_characteristics"],
            "rationale": target_contract["rationale"],
            "falsification_condition": target_contract["falsification_condition"],
            "escalation_condition": target_contract["escalation_condition"],
            "root_owner": state.get("owner"),
            "root_session_id": session_id,
            "status": "active",
            "recorded_at": recorded,
        }
        if args.override_id:
            refreshed_settings = services.approved_override_settings(
                state,
                args.override_id,
                target_kind="execution_resource",
                target_id=selection_id,
            )
            if refreshed_settings != resource_override_settings:
                raise HarnessError(
                    "execution resource override changed before consumption"
                )
        state["execution_model_version"] = 1
        state.setdefault("execution_selections", []).append(selection)
        if args.override_id:
            resource_override = services.override_by_id(state, args.override_id)
            if resource_override.get("status") != "approved":
                raise HarnessError("execution resource override changed before consumption")
            resource_override["version"] = int(resource_override["version"]) + 1
            resource_override["status"] = "consumed"
            resource_override["consumption"] = {
                "consumer_command": "execution-select",
                "selection_id": selection_id,
                "resource_envelope_sha256": resource_envelope_sha256,
                "target_contract_sha256": target_contract_sha256,
                "root_session_id": session_id,
                "recorded_at": recorded,
            }
            resource_override["updated_at"] = recorded
        state.setdefault("cross_lane_sessions", [])
        state.setdefault("needs_user_escalations", [])
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(selection, args.json)
    return 0


def cmd_execution_brief_record(
    args: argparse.Namespace,
    paths: HarnessPaths,
    *,
    services: ExecutionSelectionCmdServices,
) -> int:
    brief_id = validate_id(args.brief_id, "execution brief id")
    packet_ids = sorted(set(args.packet_id))
    cross_session_ids = sorted(set(args.cross_lane_session_id))
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "record execution brief for")
        services.require_plan_ready(paths, state, "record execution brief")
        if any(
            item.get("brief_id") == brief_id
            for item in state.get("execution_briefs", [])
        ):
            raise HarnessError(f"execution brief already exists: {brief_id}")
        selection = execution_selection_by_id(state, args.execution_selection_id)
        if (
            selection.get("status") != "active"
            or not _is_exact_int(selection.get("execution_selection_version"), 2)
            or selection.get("mode") not in {"centralized_parallel", "hybrid"}
        ):
            raise HarnessError(
                "execution brief requires an active parallel/hybrid selection v2"
            )
        steward = _engaged_steward_lane(state)
        selection_steward = selection.get("steward_snapshot", {})
        if (
            steward.get("lane_id") != args.steward_lane_id
            or not isinstance(selection_steward, dict)
            or selection_steward.get("lane_id") != steward.get("lane_id")
        ):
            raise HarnessError("execution brief Steward identity is missing or mismatched")
        root_session_id = services.require_root_session(paths, state, args.session_id)
        steward_packet_binding: dict[str, Any] | None = None
        brief_version = 2
        if _execution_policy_v2_enabled(state):
            if not args.steward_packet_id:
                raise HarnessError(
                    "execution policy v2 requires --steward-packet-id for a terminal synthesis packet"
                )
            steward_packet_binding = services.steward_packet_binding(
                state, args.execution_selection_id, args.steward_packet_id
            )
            synthesis_packet = _packet_by_id(state, args.steward_packet_id)
            authority_errors = services.packet_authority_integrity_errors(
                paths, state, synthesis_packet, require_origin=False
            )
            result_errors = services.packet_result_integrity_errors(
                paths,
                state,
                synthesis_packet,
            )
            specialist_errors = services.selection_done_packet_authority_errors(
                paths,
                state,
                args.execution_selection_id,
            )
            if authority_errors or result_errors or specialist_errors:
                raise HarnessError(
                    "Steward synthesis evidence is missing or tampered: "
                    + "; ".join(
                        authority_errors + result_errors + specialist_errors
                    )
                )
            brief_version = 3
        elif args.steward_packet_id:
            steward_packet_binding = services.steward_packet_binding(
                state, args.execution_selection_id, args.steward_packet_id
            )
            brief_version = 3
        active_packets = [
            str(packet.get("packet_id", ""))
            for packet in state.get("packets", [])
            if packet.get("execution_selection_id") == args.execution_selection_id
            and packet.get("status") in ACTIVE_PACKET_STATUSES
        ]
        if active_packets:
            raise HarnessError(
                "execution brief requires terminal selected packets: "
                + ", ".join(active_packets)
            )
        active_jobs = [
            str(job.get("run_id", ""))
            for job in state.get("jobs", [])
            if job.get("execution_selection_id") == args.execution_selection_id
            and job.get("status") in ACTIVE_JOB_STATUSES
        ]
        if active_jobs:
            raise HarnessError(
                "execution brief requires terminal selected jobs: "
                + ", ".join(active_jobs)
            )
        bindings = services.selection_terminal_packet_bindings(
            state, args.execution_selection_id
        )
        expected_packet_ids = [item["packet_id"] for item in bindings]
        if not bindings or packet_ids != expected_packet_ids:
            raise HarnessError(
                "execution brief --packet-id set must equal all terminal packets for the selection"
            )
        if selection.get("mode") == "centralized_parallel":
            if cross_session_ids:
                raise HarnessError(
                    "centralized_parallel brief may not claim direct cross-lane sessions"
                )
            selected_lanes = {
                str(item.get("lane_id", ""))
                for item in selection.get("lane_snapshots", [])
            }
            result_lanes = {item["lane_id"] for item in bindings}
            if result_lanes != selected_lanes:
                raise HarnessError(
                    "centralized_parallel brief requires terminal packet evidence from every selected lane"
                )
        else:
            valid_closed = {
                str(item.get("cross_lane_session_id", ""))
                for item in state.get("cross_lane_sessions", [])
                if item.get("execution_selection_id") == args.execution_selection_id
                and item.get("status") == "closed"
            }
            if not cross_session_ids or not set(cross_session_ids) <= valid_closed:
                raise HarnessError(
                    "hybrid execution brief requires at least one exact closed cross-lane session"
                )
        context_provider_bindings = context_provider_brief_bindings(paths, state)
        brief = {
            "integrity_version": 1,
            "brief_version": brief_version,
            "brief_id": brief_id,
            "execution_selection_id": args.execution_selection_id,
            "mode": selection["mode"],
            "steward_snapshot": copy.deepcopy(selection["steward_snapshot"]),
            "recording_steward_snapshot": services.lane_authority_snapshot(steward),
            "packet_bindings": bindings,
            **(
                {"steward_packet_binding": steward_packet_binding}
                if steward_packet_binding is not None
                else {}
            ),
            "cross_lane_session_ids": cross_session_ids,
            "context_provider_bindings": context_provider_bindings,
            "summary": require_evidence_detail(
                args.summary, "execution brief summary"
            ),
            "dissent": require_text(args.dissent, "execution brief dissent"),
            "blockers": require_text(args.blocker, "execution brief blockers"),
            "recommendation": require_evidence_detail(
                args.recommendation, "execution brief recommendation"
            ),
            "root_session_id": root_session_id,
            "recorded_at": now_iso(),
        }
        brief["brief_sha256"] = canonical_record_sha256(brief)
        state.setdefault("execution_briefs", []).append(brief)
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(brief, args.json)
    return 0


def _add_execution_selection_arguments(
    parser: argparse.ArgumentParser, *, vocab: Any, override_required: bool
) -> None:
    parser.add_argument("--task", required=True)
    parser.add_argument("--selection-id", required=True)
    parser.add_argument("--work-unit-id", required=True)
    parser.add_argument("--supersedes-selection-id")
    parser.add_argument(
        "--mode", choices=sorted(vocab.execution_modes), required=True
    )
    parser.add_argument("--lane", action="append", default=[], required=True)
    parser.add_argument("--steward-lane-id")
    parser.add_argument("--scope", required=True)
    parser.add_argument(
        "--sequential-dependency",
        choices=sorted(vocab.dependency_levels),
        required=True,
    )
    parser.add_argument(
        "--tool-density", choices=sorted(vocab.tool_densities), required=True
    )
    parser.add_argument(
        "--shared-context", choices=sorted(vocab.dependency_levels), required=True
    )
    parser.add_argument("--rationale", required=True)
    parser.add_argument("--falsification-condition", required=True)
    parser.add_argument("--escalation-condition", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--override-id", required=override_required, default="")


def register_execution_selection_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
    vocab: Any,
) -> None:
    """Register the execution-selection command family on one subparser set."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "execution selection command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("execution-select-plan")
    _add_execution_selection_arguments(parser, vocab=vocab, override_required=True)
    parser.add_argument("--proposed-setting", action="append", default=[], required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["execution_select_plan"])

    parser = subparsers.add_parser("execution-select")
    _add_execution_selection_arguments(parser, vocab=vocab, override_required=False)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["execution_select"])

    parser = subparsers.add_parser("execution-brief-record")
    parser.add_argument("--task", required=True)
    parser.add_argument("--brief-id", required=True)
    parser.add_argument("--execution-selection-id", required=True)
    parser.add_argument("--steward-lane-id", required=True)
    parser.add_argument("--steward-packet-id")
    parser.add_argument("--packet-id", action="append", default=[], required=True)
    parser.add_argument("--cross-lane-session-id", action="append", default=[])
    parser.add_argument("--summary", required=True)
    parser.add_argument("--dissent", required=True)
    parser.add_argument("--blocker", required=True)
    parser.add_argument("--recommendation", required=True)
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["execution_brief_record"])


__all__ = [
    "ExecutionSelectionCmdServices",
    "cmd_execution_brief_record",
    "cmd_execution_select",
    "cmd_execution_select_plan",
    "register_execution_selection_commands",
]
