"""Lane lifecycle and lane-dependency command family: syntax registration and
command bodies.

This module owns the ``lane-*`` command implementations (set-status, create,
revise, dependency-add, dependency-update).  It stays a leaf of the composition
root: it imports only sibling packages (``harnesslib``, ``state_lookup``,
``git_plumbing``, ``portfolio_integrity``) and the standard library, never the
monolithic :mod:`aoi_orgware.cli`.  The CLI imports the command bodies back for
handler wiring and keeps the mutable-constant/factory composition root.

Three classes of composition-root concern cannot be imported statically and are
threaded in through the frozen :class:`LanesCmdServices` dataclass built by
``cli._lanes_cmd_services()``:

* CLI-resident derived-state operations (``require_plan_ready``,
  ``require_root_session``) and the ``portfolio_integrity_errors`` wrapper (which
  closes over ``cli``'s ``_portfolio_integrity_policy()`` /
  ``_portfolio_integrity_services()`` factories) are direct-bound: none is
  fault-injected via ``mock.patch.object(cli, ...)``.
* The ``apply_project_config``-mutable vocabularies ``LANE_KINDS`` and
  ``ROLE_TIER_MAP`` are late-bound through zero-argument callables so a body
  reads ``cli``'s *current* binding at call time (never a stale snapshot), which
  also preserves observability of any future ``mock.patch.object(cli, ...)``.
* The immutable composition-root policy constants ``MAX_ENGAGED_LANES``,
  ``TERMINAL_COORDINATION_STATUSES``, ``TERMINAL_IMPROVEMENT_STATUSES``,
  ``CHANGE_CLASSES`` and ``DEPENDENCY_KINDS`` (none rebound by
  ``apply_project_config``, none test-patched) are direct value-bound so ``cli``
  stays their single source of truth.

``ENGAGED_LANE_STATUSES``, ``ACTIVE_PACKET_STATUSES`` and ``ACTIVE_JOB_STATUSES``
live in the ``state_lookup`` / ``harnesslib`` siblings and are imported directly.
``emit``, ``require_text`` and ``require_evidence_detail`` are pure leaf helpers
(no project-mutable or test-patched dependency) redeclared module-locally,
mirroring the sibling extraction precedent, so the relocated bodies bind the
module-local copies rather than reaching back into ``cli``.

Handlers are injected by the CLI composition root.  Choice vocabularies arrive as
an immutable ``ParserVocabulary`` snapshot (built in ``cli.build_parser``) so no
mutable CLI global is imported or re-declared for parser construction.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from typing import AbstractSet, Any, Protocol

from ..git_plumbing import git_is_ancestor, resolve_task_commit, state_worktree
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
from ..portfolio_integrity import _hard_dependency_cycle
from ..state_lookup import (
    ENGAGED_LANE_STATUSES,
    coordination_by_id,
    lane_by_id,
    require_open_task,
)


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset(
    {
        "lane_set_status",
        "lane_create",
        "lane_revise",
        "lane_dependency_add",
        "lane_dependency_update",
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


class _PortfolioIntegrityErrors(Protocol):
    def __call__(
        self, state: dict[str, Any], paths: HarnessPaths | None = None
    ) -> list[str]: ...


@dataclass(frozen=True)
class LanesCmdServices:
    """CLI-resident helpers and composition-root policy constants.

    ``require_plan_ready``, ``require_root_session`` and
    ``portfolio_integrity_errors`` are direct-bound (none is fault-injected via
    ``mock.patch.object(cli, ...)``).  ``lane_kinds`` and ``role_tier_map`` are
    zero-argument callables that resolve ``cli``'s current
    ``apply_project_config``-mutable binding at call time.  The remaining
    constants are immutable and value-bound so ``cli`` stays their single source
    of truth.
    """

    require_plan_ready: _RequirePlanReady
    require_root_session: _RequireRootSession
    portfolio_integrity_errors: _PortfolioIntegrityErrors
    lane_kinds: Callable[[], Collection[str]]
    role_tier_map: Callable[[], Mapping[str, str]]
    max_engaged_lanes: int
    terminal_coordination_statuses: Collection[str]
    terminal_improvement_statuses: Collection[str]
    change_classes: AbstractSet[str]
    dependency_kinds: Collection[str]


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


LANE_CLOSURE_KINDS = ("completed_work", "no_work", "aborted", "superseded")


def _lane_packet_terminal_stats(packets: list[dict[str, Any]]) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    by_task_type: dict[str, int] = {}
    for packet in packets:
        status = str(packet.get("status", ""))
        task_type = str(packet.get("task_type", ""))
        by_status[status] = by_status.get(status, 0) + 1
        by_task_type[task_type] = by_task_type.get(task_type, 0) + 1
    return {
        "total": len(packets),
        "by_status": dict(sorted(by_status.items())),
        "by_task_type": dict(sorted(by_task_type.items())),
    }


def cmd_lane_set_status(
    args: argparse.Namespace, paths: HarnessPaths, *, services: LanesCmdServices
) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "set lane status for")
        session_id = services.require_root_session(paths, state, args.session_id)
        lane = lane_by_id(state, args.lane_id)
        if (
            lane.get("revision") != args.expected_revision
            or lane.get("status") != args.expected_status
        ):
            raise HarnessError("lane status CAS failed")
        if args.status == lane.get("status"):
            raise HarnessError("lane status transition must change status")
        if args.status in ENGAGED_LANE_STATUSES and lane.get("status") not in ENGAGED_LANE_STATUSES:
            engaged = sum(
                item.get("status") in ENGAGED_LANE_STATUSES
                for item in state.get("lanes", [])
            )
            if engaged >= services.max_engaged_lanes:
                raise HarnessError(f"engaged lane ceiling is {services.max_engaged_lanes}")
        if args.status not in ENGAGED_LANE_STATUSES:
            active_packets = [
                packet.get("packet_id")
                for packet in state.get("packets", [])
                if packet.get("lane_id") == lane["lane_id"]
                and packet.get("status") in ACTIVE_PACKET_STATUSES
            ]
            active_jobs = [
                job.get("run_id")
                for job in state.get("jobs", [])
                if job.get("lane_id") == lane["lane_id"]
                and job.get("status") in ACTIVE_JOB_STATUSES
            ]
            if active_packets or active_jobs:
                raise HarnessError("cannot park a lane with active packets or jobs")
            if lane.get("kind") == "coordination_steward":
                if any(
                    request.get("status") not in services.terminal_coordination_statuses
                    for request in state.get("coordination_requests", [])
                ) or any(
                    review.get("status") not in {"rejected", "consumed", "superseded"}
                    for review in state.get("capacity_reviews", [])
                ) or any(
                    request.get("status") not in services.terminal_improvement_statuses
                    for request in state.get("improvement_requests", [])
                ):
                    raise HarnessError("cannot park the steward while its control-plane inbox is active")
            if lane.get("kind") == "capacity_planning" and any(
                review.get("capacity_lane_id") == lane["lane_id"]
                and review.get("status") not in {"rejected", "consumed", "superseded"}
                for review in state.get("capacity_reviews", [])
            ):
                raise HarnessError("cannot park Capacity Planning with an active review")
        closure_kind = args.closure_kind
        terminal_stats: dict[str, Any] | None = None
        if args.status == "done":
            if not closure_kind:
                raise HarnessError("closing a lane to done requires --closure-kind")
            owned_packets = [
                packet
                for packet in state.get("packets", [])
                if packet.get("lane_id") == lane["lane_id"]
            ]
            done_packet_ids = sorted(
                str(packet.get("packet_id"))
                for packet in owned_packets
                if packet.get("status") == "done"
            )
            if closure_kind == "no_work" and done_packet_ids:
                raise HarnessError(
                    "no_work lane closure contradicts done packets: "
                    + ", ".join(done_packet_ids)
                )
            if closure_kind == "completed_work" and not done_packet_ids:
                raise HarnessError(
                    "completed_work lane closure requires at least one done owned packet"
                )
            terminal_stats = _lane_packet_terminal_stats(owned_packets)
        elif closure_kind is not None:
            raise HarnessError("--closure-kind applies only when closing a lane to done")
        recorded = now_iso()
        old_status = lane["status"]
        lane["status"] = args.status
        lane["next_action"] = require_text(args.next_action, "lane next action")
        lane["status_updated_at"] = recorded
        status_event = {
            "old_status": old_status,
            "new_status": args.status,
            "root_session_id": session_id,
            "reason": require_evidence_detail(args.reason, "lane status reason"),
            "recorded_at": recorded,
        }
        if terminal_stats is not None:
            status_event["closure_kind"] = closure_kind
            status_event["packet_terminal_stats"] = terminal_stats
        lane.setdefault("status_events", []).append(status_event)
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(lane, args.json)
    return 0


def cmd_lane_create(
    args: argparse.Namespace, paths: HarnessPaths, *, services: LanesCmdServices
) -> int:
    lane_id = validate_id(args.lane_id, "lane id")
    if args.kind not in services.lane_kinds():
        raise HarnessError(f"unknown lane kind: {args.kind}")
    if args.role not in services.role_tier_map():
        raise HarnessError(f"unknown lane role: {args.role}")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "create lane for")
        services.require_plan_ready(paths, state, "create lane")
        if state.get("profile") == "mini":
            raise HarnessError("mini task may not use lane orchestration")
        authority_commit = resolve_task_commit(
            state, args.authority_commit, "lane authority commit"
        )
        if any(lane.get("lane_id") == lane_id for lane in state.get("lanes", [])):
            raise HarnessError(f"lane already exists: {lane_id}")
        engaged = sum(
            lane.get("status") in ENGAGED_LANE_STATUSES for lane in state.get("lanes", [])
        )
        if args.status in ENGAGED_LANE_STATUSES and engaged >= services.max_engaged_lanes:
            raise HarnessError(f"engaged lane ceiling is {services.max_engaged_lanes}")
        recorded = now_iso()
        revision = {
            "revision": 1,
            "authority_commit": authority_commit,
            "contract_version": require_text(args.contract_version, "contract version"),
            "generator_version": require_text(
                args.generator_version, "generator version"
            ),
            "adapter_version": require_text(args.adapter_version, "adapter version"),
            "change_class": "genesis",
            "coordination_request_ids": [],
            "root_decision": "initial lane authority recorded by root",
            "recorded_at": recorded,
        }
        lane = {
            "integrity_version": 1,
            "lane_id": lane_id,
            "kind": args.kind,
            "status": args.status,
            "owner": require_text(args.owner, "lane owner"),
            "role": args.role,
            "revision": 1,
            "authority_commit": authority_commit,
            "contract_version": revision["contract_version"],
            "generator_version": revision["generator_version"],
            "adapter_version": revision["adapter_version"],
            "next_action": require_text(args.next_action, "lane next action"),
            "revisions": [revision],
            "created_at": recorded,
            "updated_at": recorded,
        }
        state["lane_model_version"] = 1
        state.setdefault("lanes", []).append(lane)
        state.setdefault("lane_dependencies", [])
        state.setdefault("coordination_requests", [])
        state.setdefault("integration_baselines", [])
        errors = services.portfolio_integrity_errors(state)
        if errors:
            raise HarnessError("invalid lane portfolio: " + "; ".join(errors))
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(lane, args.json)
    return 0


def cmd_lane_revise(
    args: argparse.Namespace, paths: HarnessPaths, *, services: LanesCmdServices
) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "revise lane for")
        services.require_plan_ready(paths, state, "revise lane")
        lane = lane_by_id(state, args.lane_id)
        if lane.get("revision") != args.expected_revision:
            raise HarnessError(
                f"lane revision CAS failed: expected {args.expected_revision}, "
                f"current {lane.get('revision')}"
            )
        if args.change_class not in services.change_classes - {"genesis"}:
            raise HarnessError(f"invalid lane change class: {args.change_class}")
        authority_commit = resolve_task_commit(
            state, args.authority_commit, "lane authority commit"
        )
        if not git_is_ancestor(
            state_worktree(paths, state), str(lane.get("authority_commit")), authority_commit
        ):
            raise HarnessError("new lane authority commit must descend from current lane authority")
        contract = require_text(args.contract_version, "contract version")
        generator = require_text(args.generator_version, "generator version")
        adapter = require_text(args.adapter_version, "adapter version")
        old_tuple = (
            str(lane.get("contract_version")),
            str(lane.get("generator_version")),
            str(lane.get("adapter_version")),
        )
        new_tuple = (contract, generator, adapter)
        if args.change_class in {"evidence_only", "same_contract_implementation"}:
            if new_tuple != old_tuple:
                raise HarnessError(
                    f"{args.change_class} must keep contract, generator, and adapter versions fixed"
                )
        elif args.change_class == "semantic_change":
            if contract == old_tuple[0] or generator == old_tuple[1] or adapter != old_tuple[2]:
                raise HarnessError(
                    "semantic_change must change contract and generator together while keeping adapter fixed"
                )
        elif args.change_class == "transport_layout_change":
            if contract != old_tuple[0] or generator != old_tuple[1] or adapter == old_tuple[2]:
                raise HarnessError(
                    "transport_layout_change must change only the adapter version"
                )
        coordination_ids = list(dict.fromkeys(args.coord))
        for request_id in coordination_ids:
            request = coordination_by_id(state, request_id)
            if request.get("status") != "accepted" or not request.get("root_arbitrations"):
                raise HarnessError(
                    f"coordination request {request_id} lacks accepted root arbitration"
                )
            if lane.get("lane_id") not in {
                request.get("source_lane"),
                request.get("target_lane"),
            }:
                raise HarnessError(
                    f"coordination request {request_id} does not concern lane {lane.get('lane_id')}"
                )
        if args.change_class == "semantic_change" and not coordination_ids:
            raise HarnessError("semantic_change requires an accepted --coord request")
        root_session_id = services.require_root_session(paths, state, args.session_id)
        revision_number = int(lane["revision"]) + 1
        recorded = now_iso()
        revision = {
            "revision": revision_number,
            "authority_commit": authority_commit,
            "contract_version": contract,
            "generator_version": generator,
            "adapter_version": adapter,
            "change_class": args.change_class,
            "coordination_request_ids": coordination_ids,
            "root_decision": require_text(args.decision, "root lane decision"),
            "root_session_id": root_session_id,
            "recorded_at": recorded,
        }
        lane["revision"] = revision_number
        lane["authority_commit"] = authority_commit
        lane["contract_version"] = contract
        lane["generator_version"] = generator
        lane["adapter_version"] = adapter
        lane["next_action"] = require_text(args.next_action, "lane next action")
        lane["updated_at"] = recorded
        lane.setdefault("revisions", []).append(revision)
        errors = services.portfolio_integrity_errors(state)
        if errors:
            raise HarnessError("invalid lane portfolio: " + "; ".join(errors))
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(lane, args.json)
    return 0


def cmd_lane_dependency_add(
    args: argparse.Namespace, paths: HarnessPaths, *, services: LanesCmdServices
) -> int:
    dependency_id = validate_id(args.dependency_id, "dependency id")
    if args.kind not in services.dependency_kinds:
        raise HarnessError(f"invalid dependency kind: {args.kind}")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "add lane dependency to")
        services.require_plan_ready(paths, state, "add lane dependency")
        lane_by_id(state, args.source_lane)
        lane_by_id(state, args.target_lane)
        if args.source_lane == args.target_lane:
            raise HarnessError("lane dependency may not be a self-edge")
        if any(
            item.get("dependency_id") == dependency_id
            for item in state.get("lane_dependencies", [])
        ):
            raise HarnessError(f"dependency already exists: {dependency_id}")
        dependency = {
            "integrity_version": 1,
            "dependency_id": dependency_id,
            "source_lane": args.source_lane,
            "target_lane": args.target_lane,
            "kind": args.kind,
            "status": "open",
            "reason": require_text(args.reason, "dependency reason"),
            "needed_by_gate": str(args.needed_by_gate or ""),
            "created_at": now_iso(),
        }
        proposed = [*state.get("lane_dependencies", []), dependency]
        if _hard_dependency_cycle(proposed):
            raise HarnessError("hard-gate dependency would create a cycle")
        state.setdefault("lane_dependencies", []).append(dependency)
        errors = services.portfolio_integrity_errors(state)
        if errors:
            raise HarnessError("invalid lane portfolio: " + "; ".join(errors))
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(dependency, args.json)
    return 0


def cmd_lane_dependency_update(
    args: argparse.Namespace, paths: HarnessPaths, *, services: LanesCmdServices
) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "update lane dependency for")
        session_id = services.require_root_session(paths, state, args.session_id)
        matches = [
            item
            for item in state.get("lane_dependencies", [])
            if item.get("dependency_id") == args.dependency_id
        ]
        if len(matches) != 1:
            raise HarnessError("dependency id does not name exactly one lane dependency")
        dependency = matches[0]
        if dependency.get("status") != "open":
            raise HarnessError("only an open dependency can be updated")
        dependency["status"] = args.status
        dependency["root_owner"] = state.get("owner")
        dependency["root_session_id"] = session_id
        dependency["source_revision"] = lane_by_id(
            state, str(dependency["source_lane"])
        )["revision"]
        dependency["target_revision"] = lane_by_id(
            state, str(dependency["target_lane"])
        )["revision"]
        dependency["evidence"] = require_evidence_detail(
            args.evidence, "dependency update evidence"
        )
        dependency["updated_at"] = now_iso()
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(dependency, args.json)
    return 0


def register_lane_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
    vocab: Any,
) -> None:
    """Register the lane command family on one argparse subparser set."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "lane command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("lane-set-status")
    parser.add_argument("--task", required=True)
    parser.add_argument("--lane-id", required=True)
    parser.add_argument("--expected-revision", type=int, required=True)
    parser.add_argument(
        "--expected-status", choices=sorted(vocab.lane_statuses), required=True
    )
    parser.add_argument("--status", choices=sorted(vocab.lane_statuses), required=True)
    parser.add_argument("--next-action", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--closure-kind", choices=list(LANE_CLOSURE_KINDS))
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["lane_set_status"])

    parser = subparsers.add_parser("lane-create")
    parser.add_argument("--task", required=True)
    parser.add_argument("--lane-id", required=True)
    parser.add_argument("--kind", choices=sorted(vocab.lane_kinds), required=True)
    parser.add_argument("--status", choices=sorted(vocab.lane_statuses), default="active")
    parser.add_argument("--owner", required=True)
    parser.add_argument("--role", choices=sorted(vocab.role_tier_map), required=True)
    parser.add_argument("--authority-commit", required=True)
    parser.add_argument("--contract-version", required=True)
    parser.add_argument("--generator-version", default="not_applicable")
    parser.add_argument("--adapter-version", default="not_applicable")
    parser.add_argument("--next-action", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["lane_create"])

    parser = subparsers.add_parser("lane-revise")
    parser.add_argument("--task", required=True)
    parser.add_argument("--lane-id", required=True)
    parser.add_argument("--expected-revision", type=int, required=True)
    parser.add_argument("--authority-commit", required=True)
    parser.add_argument(
        "--change-class",
        choices=sorted(vocab.change_classes - {"genesis"}),
        required=True,
    )
    parser.add_argument("--contract-version", required=True)
    parser.add_argument("--generator-version", required=True)
    parser.add_argument("--adapter-version", required=True)
    parser.add_argument("--next-action", required=True)
    parser.add_argument("--decision", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--coord", action="append", default=[])
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["lane_revise"])

    parser = subparsers.add_parser("lane-dependency-add")
    parser.add_argument("--task", required=True)
    parser.add_argument("--dependency-id", required=True)
    parser.add_argument("--source-lane", required=True)
    parser.add_argument("--target-lane", required=True)
    parser.add_argument("--kind", choices=sorted(vocab.dependency_kinds), required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--needed-by-gate")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["lane_dependency_add"])

    parser = subparsers.add_parser("lane-dependency-update")
    parser.add_argument("--task", required=True)
    parser.add_argument("--dependency-id", required=True)
    parser.add_argument(
        "--status", choices=["satisfied", "waived", "superseded"], required=True
    )
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--evidence", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["lane_dependency_update"])


__all__ = [
    "LanesCmdServices",
    "cmd_lane_create",
    "cmd_lane_dependency_add",
    "cmd_lane_dependency_update",
    "cmd_lane_revise",
    "cmd_lane_set_status",
    "register_lane_commands",
]
