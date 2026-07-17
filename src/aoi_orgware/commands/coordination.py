"""Cross-lane / needs-user / coordination-request / baseline-freeze command
family: syntax registration and command bodies.

This module owns the ``cross-lane-*``, ``needs-user-*``, ``coordination-*`` and
``baseline-freeze`` command implementations.  It stays a leaf of the composition
root: it imports only sibling packages (``harnesslib``, ``state_lookup``), never
the monolithic :mod:`aoi_orgware.cli`.  The CLI imports the command bodies back
for handler wiring and keeps the mutable-constant/factory composition root.

Composition-root concerns that cannot be imported statically are threaded in
through the frozen :class:`CoordinationCmdServices` dataclass built by
``cli._coordination_cmd_services()``:

* CLI-resident derived-state operations (``require_plan_ready``,
  ``require_root_session``), the ``portfolio_integrity_errors`` wrapper (which
  closes over ``cli``'s ``_portfolio_integrity_*`` factories), and the
  ``snapshot_evidence_artifact`` wrapper (which closes over
  ``cli.TERMINAL_ARTIFACT_MAX_BYTES`` and the ``evidence_artifacts`` policy) are
  direct-bound: none is fault-injected via ``mock.patch.object(cli, ...)``.
* The immutable composition-root policy constants ``CHANGE_CLASSES``,
  ``DEPENDENCY_KINDS``, ``TERMINAL_COORDINATION_STATUSES`` and
  ``COOPERATIVE_AUTHORITY_BOUNDARY`` (none rebound by ``apply_project_config``,
  none test-patched) are direct value-bound so ``cli`` stays their single source
  of truth.

``cross-lane-close``, ``cross-lane-cancel`` and ``coordination-directive-ack``
depend on no composition-root concern, so they keep the ``(args, paths)``
signature and are wired as bare handlers — pure verbatim moves.  ``state_lock``,
``write_task``, ``write_index`` and the domain lookups import directly from
``harnesslib`` / ``state_lookup`` (no test fault-injects them on a coordination
command), mirroring the capacity precedent.  ``emit``, ``require_text`` and
``require_evidence_detail`` are pure leaf helpers redeclared module-locally, so
the relocated bodies bind the module-local copies rather than reaching into
``cli``.

This domain is registered through TWO public functions rather than one, because
its original ``add_parser`` blocks are not contiguous in ``cli.py``: the
resource-override and lane registrar calls sit between the cross-lane/needs-user
block and the coordination-request/baseline-freeze block.  ``build_parser``
calls both functions at the exact positions their source blocks originally
occupied, preserving top-level ``aoi --help`` registration order.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import AbstractSet, Any, Protocol

from ..harnesslib import (
    RESERVING_CLAIM_STATUSES,
    HarnessError,
    HarnessPaths,
    bump_task,
    claims_owned_by_task,
    is_expired,
    load_task,
    now_iso,
    sha256_file,
    state_lock,
    validate_id,
    write_index,
    write_task,
)
from ..state_lookup import (
    _baseline_by_id,
    _engaged_steward_lane,
    coordination_by_id,
    cross_lane_session_by_id,
    execution_selection_by_id,
    lane_by_id,
    needs_user_by_id,
    require_open_task,
)


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_CROSS_LANE_HANDLER_NAMES = frozenset(
    {
        "cross_lane_open",
        "cross_lane_close",
        "cross_lane_cancel",
        "needs_user_create",
        "needs_user_resolve",
    }
)

_COORDINATION_HANDLER_NAMES = frozenset(
    {
        "coordination_create",
        "coordination_update",
        "coordination_arbitrate",
        "coordination_directive_ack",
        "coordination_resolve",
        "coordination_implementation_submit",
        "coordination_verify",
        "baseline_freeze",
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


class _SnapshotEvidenceArtifact(Protocol):
    def __call__(
        self,
        paths: HarnessPaths,
        task_id: str,
        source_value: str | Path,
        expected_sha: str,
        *,
        label: str,
        basename: str,
        max_bytes: int = ...,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class CoordinationCmdServices:
    """CLI-resident helpers and composition-root policy constants.

    ``require_plan_ready``, ``require_root_session``,
    ``portfolio_integrity_errors`` and ``snapshot_evidence_artifact`` are
    direct-bound (none is fault-injected via ``mock.patch.object(cli, ...)``).
    The remaining constants are immutable and value-bound so ``cli`` stays their
    single source of truth.
    """

    require_plan_ready: _RequirePlanReady
    require_root_session: _RequireRootSession
    portfolio_integrity_errors: _PortfolioIntegrityErrors
    snapshot_evidence_artifact: _SnapshotEvidenceArtifact
    change_classes: AbstractSet[str]
    dependency_kinds: Collection[str]
    terminal_coordination_statuses: AbstractSet[str]
    cooperative_authority_boundary: str


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


def cmd_cross_lane_open(
    args: argparse.Namespace, paths: HarnessPaths, *, services: CoordinationCmdServices
) -> int:
    cross_id = validate_id(args.cross_lane_session_id, "cross-lane session id")
    participants = list(dict.fromkeys(args.participant_lane))
    if len(participants) < 2:
        raise HarnessError("cross-lane session requires at least two participant lanes")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "open cross-lane session for")
        if any(
            item.get("cross_lane_session_id") == cross_id
            for item in state.get("cross_lane_sessions", [])
        ):
            raise HarnessError(f"cross-lane session already exists: {cross_id}")
        steward = _engaged_steward_lane(state)
        if steward.get("lane_id") != args.steward_lane_id:
            raise HarnessError("cross-lane session must be opened by the engaged steward")
        selection = execution_selection_by_id(state, args.execution_selection_id)
        if selection.get("mode") != "hybrid" or selection.get("status") != "active":
            raise HarnessError("cross-lane session requires an active hybrid execution selection")
        selected_lanes = {
            item.get("lane_id") for item in selection.get("lane_snapshots", [])
        }
        if not set(participants).issubset(selected_lanes):
            raise HarnessError("cross-lane participants exceed the hybrid execution scope")
        selection_snapshots = {
            str(item.get("lane_id")): item
            for item in selection.get("lane_snapshots", [])
        }
        for lane_id in participants:
            lane = lane_by_id(state, lane_id)
            snapshot = selection_snapshots.get(lane_id, {})
            if any(
                snapshot.get(field) != lane.get(field)
                for field in (
                    "revision",
                    "authority_commit",
                    "contract_version",
                )
            ):
                raise HarnessError(
                    "hybrid execution selection is stale; select topology again"
                )
        request = coordination_by_id(state, args.request_id)
        if request.get("status") in services.terminal_coordination_statuses:
            raise HarnessError("cross-lane session may not attach to a terminal request")
        if not {request.get("source_lane"), request.get("target_lane")}.issubset(
            set(participants)
        ):
            raise HarnessError("cross-lane session must include both affected request lanes")
        expires_at = require_text(args.expires_at, "cross-lane session expiry")
        if is_expired(expires_at):
            raise HarnessError("cross-lane session expiry must be in the future")
        lane_snapshots = []
        for lane_id in participants:
            lane = lane_by_id(state, lane_id)
            lane_snapshots.append(
                {
                    "lane_id": lane_id,
                    "revision": lane["revision"],
                    "authority_commit": lane["authority_commit"],
                    "contract_version": lane["contract_version"],
                }
            )
        recorded = now_iso()
        item = {
            "integrity_version": 1,
            "cross_lane_session_id": cross_id,
            "version": 1,
            "status": "open",
            "request_id": request["request_id"],
            "execution_selection_id": selection["selection_id"],
            "steward_lane_id": steward["lane_id"],
            "participant_snapshots": sorted(
                lane_snapshots, key=lambda entry: entry["lane_id"]
            ),
            "topic": require_evidence_detail(args.topic, "cross-lane session topic"),
            "evidence_boundary": require_evidence_detail(
                args.evidence_boundary, "cross-lane session evidence boundary"
            ),
            "prohibited_mutations": [
                "no harness state mutation outside steward close/backfill",
                "no cross-lane source or contract mutation",
                "no private decision, baseline, PASS, or release authority",
            ],
            "expires_at": expires_at,
            "opened_at": recorded,
            "closure": None,
        }
        state.setdefault("cross_lane_sessions", []).append(item)
        request["version"] = int(request["version"]) + 1
        request.setdefault("events", []).append(
            {
                "version": request["version"],
                "actor_lane": steward["lane_id"],
                "event": "controlled_cross_lane_session_opened",
                "detail": cross_id,
                "recorded_at": recorded,
            }
        )
        request["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(item, args.json)
    return 0


def cmd_cross_lane_close(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "close cross-lane session for")
        item = cross_lane_session_by_id(state, args.cross_lane_session_id)
        if item.get("version") != args.expected_version or item.get("status") != "open":
            raise HarnessError("cross-lane session CAS/status gate failed")
        if is_expired(str(item.get("expires_at", ""))):
            raise HarnessError(
                "cross-lane session expired; cancel it and open a fresh authority snapshot"
            )
        selection = execution_selection_by_id(
            state, str(item.get("execution_selection_id", ""))
        )
        if selection.get("status") != "active":
            raise HarnessError(
                "cross-lane session selection is no longer active; cancel the session"
            )
        steward = _engaged_steward_lane(state)
        if steward.get("lane_id") != args.steward_lane_id:
            raise HarnessError("cross-lane session must be closed by the engaged steward")
        for snapshot in item.get("participant_snapshots", []):
            lane = lane_by_id(state, str(snapshot.get("lane_id")))
            if (
                lane.get("revision") != snapshot.get("revision")
                or lane.get("authority_commit") != snapshot.get("authority_commit")
                or lane.get("contract_version") != snapshot.get("contract_version")
            ):
                raise HarnessError("cross-lane session participant authority changed")
        request = coordination_by_id(state, str(item.get("request_id")))
        recorded = now_iso()
        item["version"] = int(item["version"]) + 1
        item["status"] = "closed"
        item["closure"] = {
            "conclusion": require_evidence_detail(
                args.conclusion, "cross-lane conclusion"
            ),
            "dissent": require_evidence_detail(args.dissent, "cross-lane dissent"),
            "blocker": require_evidence_detail(args.blocker, "cross-lane blocker"),
            "evidence": [
                require_evidence_detail(value, "cross-lane evidence")
                for value in args.evidence
            ],
            "closed_by_steward_lane": steward["lane_id"],
            "recorded_at": recorded,
        }
        request["version"] = int(request["version"]) + 1
        request.setdefault("events", []).append(
            {
                "version": request["version"],
                "actor_lane": steward["lane_id"],
                "event": "cross_lane_results_backfilled",
                "detail": item["closure"]["conclusion"],
                "dissent": item["closure"]["dissent"],
                "blocker": item["closure"]["blocker"],
                "evidence": item["closure"]["evidence"],
                "recorded_at": recorded,
            }
        )
        request["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(item, args.json)
    return 0


def cmd_cross_lane_cancel(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "cancel cross-lane session for")
        item = cross_lane_session_by_id(state, args.cross_lane_session_id)
        if item.get("version") != args.expected_version or item.get("status") != "open":
            raise HarnessError("cross-lane session cancellation CAS/status gate failed")
        steward = _engaged_steward_lane(state)
        if steward.get("lane_id") != args.steward_lane_id:
            raise HarnessError("cross-lane session must be cancelled by the engaged steward")
        request = coordination_by_id(state, str(item.get("request_id")))
        recorded = now_iso()
        item["version"] = int(item["version"]) + 1
        item["status"] = "cancelled"
        item["cancellation"] = {
            "reason": require_evidence_detail(
                args.reason, "cross-lane cancellation reason"
            ),
            "cancelled_by_steward_lane": steward["lane_id"],
            "recorded_at": recorded,
        }
        request["version"] = int(request["version"]) + 1
        request.setdefault("events", []).append(
            {
                "version": request["version"],
                "actor_lane": steward["lane_id"],
                "event": "cross_lane_session_cancelled_without_technical_backfill",
                "detail": item["cancellation"]["reason"],
                "recorded_at": recorded,
            }
        )
        request["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(item, args.json)
    return 0


def cmd_needs_user_create(
    args: argparse.Namespace, paths: HarnessPaths, *, services: CoordinationCmdServices
) -> int:
    escalation_id = validate_id(args.escalation_id, "needs-user escalation id")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "create needs-user escalation for")
        services.require_plan_ready(paths, state, "create needs-user escalation")
        session_id = services.require_root_session(paths, state, args.session_id)
        steward = _engaged_steward_lane(state)
        source = lane_by_id(state, args.source_lane)
        if any(
            item.get("escalation_id") == escalation_id
            for item in state.get("needs_user_escalations", [])
        ):
            raise HarnessError(f"needs-user escalation already exists: {escalation_id}")
        request_id = ""
        if args.request_id:
            request = coordination_by_id(state, args.request_id)
            if source["lane_id"] not in {
                request.get("source_lane"),
                request.get("target_lane"),
            }:
                raise HarnessError("needs-user request does not concern the source lane")
            request_id = request["request_id"]
        options = [require_evidence_detail(value, "needs-user option") for value in args.option]
        if len(options) < 2:
            raise HarnessError("needs-user escalation requires at least two bounded options")
        recorded = now_iso()
        escalation = {
            "integrity_version": 1,
            "escalation_id": escalation_id,
            "status": "needs_user",
            "category": args.category,
            "source_lane_id": source["lane_id"],
            "source_lane_revision": source["revision"],
            "request_id": request_id,
            "steward_lane_id": steward["lane_id"],
            "problem": require_evidence_detail(args.problem, "needs-user problem"),
            "options": options,
            "evidence": [
                require_evidence_detail(value, "needs-user evidence")
                for value in args.evidence
            ],
            "chief_recommendation": require_evidence_detail(
                args.chief_recommendation, "Chief recommendation"
            ),
            "root_owner": state.get("owner"),
            "root_session_id": session_id,
            "user_disposition": None,
            "created_at": recorded,
            "updated_at": recorded,
        }
        state["execution_model_version"] = 1
        state.setdefault("needs_user_escalations", []).append(escalation)
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(escalation, args.json)
    return 0


def cmd_needs_user_resolve(
    args: argparse.Namespace, paths: HarnessPaths, *, services: CoordinationCmdServices
) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "resolve needs-user escalation for")
        escalation = needs_user_by_id(state, args.escalation_id)
        if escalation.get("status") != "needs_user":
            raise HarnessError("needs-user escalation is already terminal")
        session_id = services.require_root_session(paths, state, args.session_id)
        recorded = now_iso()
        escalation["status"] = "resolved"
        escalation["user_disposition"] = {
            "decision": require_evidence_detail(args.user_decision, "user decision"),
            "evidence": require_evidence_detail(
                args.user_evidence, "user decision evidence"
            ),
            "recorded_by_root_session": session_id,
            "authority_boundary": "root attestation of explicit user direction; platform identity unavailable",
            "recorded_at": recorded,
        }
        escalation["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(escalation, args.json)
    return 0


def cmd_coordination_create(
    args: argparse.Namespace, paths: HarnessPaths, *, services: CoordinationCmdServices
) -> int:
    request_id = validate_id(args.request_id, "coordination request id")
    if args.severity not in services.dependency_kinds:
        raise HarnessError(f"invalid coordination severity: {args.severity}")
    if args.change_class not in services.change_classes - {"genesis"}:
        raise HarnessError(f"invalid requested change class: {args.change_class}")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "create coordination request for")
        services.require_plan_ready(paths, state, "create coordination request")
        lane_by_id(state, args.source_lane)
        lane_by_id(state, args.target_lane)
        if args.source_lane == args.target_lane:
            raise HarnessError(
                "coordination self-request may not target its source lane"
            )
        steward = _engaged_steward_lane(state)
        if any(
            request.get("request_id") == request_id
            for request in state.get("coordination_requests", [])
        ):
            raise HarnessError(f"coordination request already exists: {request_id}")
        recorded = now_iso()
        request = {
            "integrity_version": 1,
            "request_id": request_id,
            "source_lane": args.source_lane,
            "target_lane": args.target_lane,
            "steward_lane": steward["lane_id"],
            "severity": args.severity,
            "status": "open",
            "control_phase": "submitted",
            "version": 1,
            "request": require_text(args.request, "coordination request"),
            "requested_outcome": require_text(args.outcome, "requested outcome"),
            "evidence": [
                require_evidence_detail(item, "coordination evidence")
                for item in args.evidence
            ],
            "options": [require_text(item, "coordination option") for item in args.option],
            "needed_by_gate": str(args.needed_by_gate or ""),
            "change_class": args.change_class,
            "decision_class": "formal_technical",
            "closure_category": args.closure_category,
            "events": [
                {
                    "version": 1,
                    "actor_lane": args.source_lane,
                    "event": "submitted_to_steward",
                    "detail": require_text(args.request, "coordination request"),
                    "recorded_at": recorded,
                }
            ],
            "root_arbitrations": [],
            "directives": [],
            "created_at": recorded,
            "updated_at": recorded,
        }
        state.setdefault("coordination_requests", []).append(request)
        errors = services.portfolio_integrity_errors(state)
        if errors:
            raise HarnessError("invalid lane portfolio: " + "; ".join(errors))
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(request, args.json)
    return 0


def cmd_coordination_update(
    args: argparse.Namespace, paths: HarnessPaths, *, services: CoordinationCmdServices
) -> int:
    if args.status not in {"acknowledged", "countered"}:
        raise HarnessError(
            "specialist coordination update accepts acknowledged or countered only; root arbitrates decisions"
        )
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "update coordination request for")
        request = coordination_by_id(state, args.request_id)
        _engaged_steward_lane(state)
        if request.get("status") in services.terminal_coordination_statuses | {"accepted"}:
            raise HarnessError("coordination request is already decided or terminal")
        if any(
            item.get("request_id") == request["request_id"] and item.get("status") == "open"
            for item in state.get("cross_lane_sessions", [])
        ):
            raise HarnessError("close and backfill the cross-lane session before arbitration")
        closed_sessions = [
            item
            for item in state.get("cross_lane_sessions", [])
            if item.get("request_id") == request["request_id"]
            and item.get("status") == "closed"
        ]
        if any(
            execution_selection_by_id(
                state, str(item.get("execution_selection_id", ""))
            ).get("status")
            != "active"
            for item in closed_sessions
        ):
            raise HarnessError(
                "closed cross-lane backfill is bound to a superseded topology; "
                "select and backfill a fresh topology before arbitration"
            )
        if any(
            item.get("status") == "needs_user"
            and item.get("request_id") in {"", request["request_id"]}
            for item in state.get("needs_user_escalations", [])
        ):
            raise HarnessError("needs-user escalation blocks Chief arbitration")
        if request.get("version") != args.expected_version:
            raise HarnessError(
                f"coordination request CAS failed: expected {args.expected_version}, "
                f"current {request.get('version')}"
            )
        if args.actor_lane not in {request.get("source_lane"), request.get("target_lane")}:
            raise HarnessError("only an affected specialist lane may submit a response")
        if args.status == "acknowledged" and args.actor_lane != request.get("target_lane"):
            raise HarnessError("the target lane must acknowledge the initial request")
        response = require_text(args.response, "coordination response")
        version = int(request["version"]) + 1
        request["version"] = version
        request["status"] = args.status
        request["control_phase"] = "awaiting_chief"
        request["updated_at"] = now_iso()
        request.setdefault("events", []).append(
            {
                "version": version,
                "actor_lane": args.actor_lane,
                "event": f"specialist_{args.status}_via_steward",
                "detail": response,
                "evidence": [
                    require_evidence_detail(item, "coordination response evidence")
                    for item in args.evidence
                ],
                "recorded_at": request["updated_at"],
            }
        )
        errors = services.portfolio_integrity_errors(state)
        if errors:
            raise HarnessError("invalid lane portfolio: " + "; ".join(errors))
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(request, args.json)
    return 0


def cmd_coordination_arbitrate(
    args: argparse.Namespace, paths: HarnessPaths, *, services: CoordinationCmdServices
) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "arbitrate coordination request for")
        request = coordination_by_id(state, args.request_id)
        steward = _engaged_steward_lane(state)
        session_id = services.require_root_session(paths, state, args.session_id)
        if request.get("status") in services.terminal_coordination_statuses | {"accepted"}:
            raise HarnessError("coordination request is already decided or terminal")
        if request.get("version") != args.expected_version:
            raise HarnessError(
                f"coordination arbitration CAS failed: expected {args.expected_version}, "
                f"current {request.get('version')}"
            )
        if any(
            item.get("request_id") == request["request_id"] and item.get("status") == "open"
            for item in state.get("cross_lane_sessions", [])
        ):
            raise HarnessError("close and backfill the cross-lane session before arbitration")
        if any(
            item.get("status") == "needs_user"
            and item.get("request_id") in {"", request["request_id"]}
            for item in state.get("needs_user_escalations", [])
        ):
            raise HarnessError("needs-user escalation blocks Chief arbitration")
        if args.decision == "approved" and request.get("status") not in {
            "acknowledged",
            "countered",
        }:
            raise HarnessError("approval requires a target acknowledgement or counterproposal")
        status = "accepted" if args.decision == "approved" else "rejected"
        recorded = now_iso()
        arbitration_id = f"{request['request_id']}-root-{len(request.get('root_arbitrations', [])) + 1}"
        arbitration = {
            "arbitration_id": arbitration_id,
            "decision": args.decision,
            "rationale": require_evidence_detail(args.rationale, "root arbitration rationale"),
            "selected_option": str(args.selected_option or ""),
            "root_owner": state.get("owner"),
            "root_session_id": session_id,
            "authority_boundary": services.cooperative_authority_boundary,
            "recorded_at": recorded,
        }
        request.setdefault("root_arbitrations", []).append(arbitration)
        request["version"] = int(request["version"]) + 1
        request["status"] = status
        request["control_phase"] = "decided"
        request["updated_at"] = recorded
        request.setdefault("events", []).append(
            {
                "version": request["version"],
                "actor_lane": "root",
                "event": f"chief_{args.decision}",
                "detail": arbitration["rationale"],
                "recorded_at": recorded,
            }
        )
        if args.decision == "approved":
            for index, target_lane in enumerate(
                (request["source_lane"], request["target_lane"]), start=1
            ):
                request.setdefault("directives", []).append(
                    {
                        "directive_id": f"{arbitration_id}-directive-{index}",
                        "steward_lane": steward["lane_id"],
                        "target_lane": target_lane,
                        "decision_ref": arbitration_id,
                        "status": "pending_distribution",
                        "detail": arbitration["rationale"],
                    }
                )
        errors = services.portfolio_integrity_errors(state)
        if errors:
            raise HarnessError("invalid lane portfolio: " + "; ".join(errors))
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(request, args.json)
    return 0


def cmd_baseline_freeze(
    args: argparse.Namespace, paths: HarnessPaths, *, services: CoordinationCmdServices
) -> int:
    baseline_id = validate_id(args.baseline_id, "baseline id")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "freeze baseline for")
        services.require_plan_ready(paths, state, "freeze baseline")
        session_id = services.require_root_session(paths, state, args.session_id)
        if any(
            baseline.get("baseline_id") == baseline_id
            for baseline in state.get("integration_baselines", [])
        ):
            raise HarnessError(f"baseline already exists: {baseline_id}")
        selected_ids = list(dict.fromkeys(args.lane))
        selected = (
            [lane_by_id(state, lane_id) for lane_id in selected_ids]
            if selected_ids
            else [
                lane
                for lane in state.get("lanes", [])
                if lane.get("status") not in {"standby", "parked"}
            ]
        )
        if not selected:
            raise HarnessError("baseline freeze requires at least one lane")
        selected_lane_ids = {str(lane["lane_id"]) for lane in selected}
        baseline_contract = require_text(
            args.contract_version, "baseline contract version"
        )
        mismatched_contracts = [
            f"{lane['lane_id']}={lane['contract_version']}"
            for lane in selected
            if lane.get("contract_version") != baseline_contract
        ]
        if mismatched_contracts:
            raise HarnessError(
                "baseline contract differs from selected lane authority: "
                + ", ".join(mismatched_contracts)
            )
        relevant_dependencies = [
            item
            for item in state.get("lane_dependencies", [])
            if item.get("source_lane") in selected_lane_ids
            and item.get("target_lane") in selected_lane_ids
            and item.get("needed_by_gate", "") in {"", baseline_id}
            and item.get("status") != "superseded"
        ]
        open_hard = [
            str(item.get("dependency_id"))
            for item in relevant_dependencies
            if item.get("kind") == "hard_gate" and item.get("status") == "open"
        ]
        if open_hard:
            raise HarnessError(
                "open hard-gate dependencies block this baseline: " + ", ".join(open_hard)
            )
        coord_ids = list(dict.fromkeys(args.coord))
        for request in state.get("coordination_requests", []):
            if request.get("severity") != "hard_gate":
                continue
            if not {
                str(request.get("source_lane")),
                str(request.get("target_lane")),
            }.issubset(selected_lane_ids):
                continue
            if request.get("needed_by_gate", "") not in {"", baseline_id}:
                continue
            if request.get("status") in {"open", "acknowledged", "countered"}:
                raise HarnessError(
                    f"hard coordination request {request.get('request_id')} is not decided"
                )
            if request.get("status") == "accepted" and request.get("request_id") not in coord_ids:
                raise HarnessError(
                    f"accepted hard coordination request {request.get('request_id')} must be bound with --coord"
                )
        for request_id in coord_ids:
            request = coordination_by_id(state, request_id)
            if request.get("status") not in {"accepted", "resolved"}:
                raise HarnessError(
                    f"baseline coordination request {request_id} is not accepted/resolved"
                )
            if not request.get("root_arbitrations"):
                raise HarnessError(
                    f"baseline coordination request {request_id} lacks root arbitration"
                )
        recorded = now_iso()
        coordination_snapshots = []
        for request_id in coord_ids:
            request = coordination_by_id(state, request_id)
            arbitration = request["root_arbitrations"][-1]
            arbitration_sha = hashlib.sha256(
                json.dumps(
                    arbitration, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                ).encode("utf-8")
            ).hexdigest()
            coordination_snapshots.append(
                {
                    "request_id": request_id,
                    "request_version": request["version"],
                    "request_status": request["status"],
                    "arbitration_id": arbitration["arbitration_id"],
                    "arbitration_sha256": arbitration_sha,
                }
            )
        baseline = {
            "integrity_version": 1,
            "baseline_id": baseline_id,
            "status": "frozen",
            "contract_version": baseline_contract,
            "lane_snapshots": [
                {
                    "lane_id": lane["lane_id"],
                    "revision": lane["revision"],
                    "authority_commit": lane["authority_commit"],
                    "contract_version": lane["contract_version"],
                    "generator_version": lane["generator_version"],
                    "adapter_version": lane["adapter_version"],
                }
                for lane in sorted(selected, key=lambda item: item["lane_id"])
            ],
            "coordination_snapshots": coordination_snapshots,
            "dependency_snapshots": [
                {
                    "dependency_id": dependency["dependency_id"],
                    "kind": dependency["kind"],
                    "status": dependency["status"],
                    "source_lane": dependency["source_lane"],
                    "source_revision": lane_by_id(
                        state, dependency["source_lane"]
                    )["revision"],
                    "target_lane": dependency["target_lane"],
                    "target_revision": lane_by_id(
                        state, dependency["target_lane"]
                    )["revision"],
                    "evidence": dependency.get("evidence", ""),
                }
                for dependency in sorted(
                    relevant_dependencies, key=lambda item: item["dependency_id"]
                )
            ],
            "root_owner": state.get("owner"),
            "root_session_id": session_id,
            "root_decision": require_evidence_detail(args.decision, "baseline root decision"),
            "recorded_at": recorded,
        }
        baseline["baseline_sha256"] = hashlib.sha256(
            json.dumps(
                baseline, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        state.setdefault("integration_baselines", []).append(baseline)
        for request_id in coord_ids:
            request = coordination_by_id(state, request_id)
            for directive in request.get("directives", []):
                if directive.get("status") == "pending_distribution":
                    directive["status"] = "distributed"
                    directive["baseline_id"] = baseline_id
            request["control_phase"] = "distributed"
            request["baseline_id"] = baseline_id
        errors = services.portfolio_integrity_errors(state)
        if errors:
            raise HarnessError("invalid lane portfolio: " + "; ".join(errors))
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(baseline, args.json)
    return 0


def cmd_coordination_directive_ack(
    args: argparse.Namespace, paths: HarnessPaths
) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "acknowledge coordination directive for")
        request = coordination_by_id(state, args.request_id)
        _engaged_steward_lane(state)
        if request.get("status") != "accepted" or request.get("control_phase") != "distributed":
            raise HarnessError("only a distributed accepted request can be acknowledged")
        matches = [
            directive
            for directive in request.get("directives", [])
            if directive.get("directive_id") == args.directive_id
        ]
        if len(matches) != 1:
            raise HarnessError("directive id does not name exactly one request directive")
        directive = matches[0]
        if directive.get("target_lane") != args.actor_lane:
            raise HarnessError("only the directive target lane may acknowledge it")
        if directive.get("status") != "distributed":
            raise HarnessError("directive is not awaiting acknowledgement")
        lane_by_id(state, args.actor_lane)
        recorded = now_iso()
        directive["status"] = "acknowledged"
        directive["acknowledgement"] = require_evidence_detail(
            args.evidence, "directive acknowledgement evidence"
        )
        directive["acknowledged_at"] = recorded
        request["version"] = int(request["version"]) + 1
        if all(
            item.get("status") == "acknowledged"
            for item in request.get("directives", [])
        ):
            request["control_phase"] = "acknowledged"
        request["updated_at"] = recorded
        request.setdefault("events", []).append(
            {
                "version": request["version"],
                "actor_lane": args.actor_lane,
                "event": "directive_acknowledged_via_steward",
                "detail": directive["acknowledgement"],
                "recorded_at": recorded,
            }
        )
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(request, args.json)
    return 0


def _baseline_lane_snapshot(
    baseline: dict[str, Any], lane_id: str
) -> dict[str, Any]:
    matches = [
        item for item in baseline.get("lane_snapshots", []) if item.get("lane_id") == lane_id
    ]
    if len(matches) != 1:
        raise HarnessError(f"baseline does not contain exactly one lane snapshot for {lane_id}")
    return matches[0]


def cmd_coordination_implementation_submit(
    args: argparse.Namespace, paths: HarnessPaths, *, services: CoordinationCmdServices
) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "submit coordination implementation evidence for")
        request = coordination_by_id(state, args.request_id)
        _engaged_steward_lane(state)
        if request.get("version") != args.expected_version:
            raise HarnessError("coordination implementation CAS failed")
        if request.get("status") != "accepted" or request.get("control_phase") not in {
            "acknowledged",
            "verification_failed",
        }:
            raise HarnessError(
                "implementation evidence requires acknowledged directives or a failed verification retry"
            )
        if args.actor_lane != request.get("target_lane"):
            raise HarnessError("only the target implementer lane may submit implementation evidence")
        if args.evidence_category != request.get("closure_category", "integration_test"):
            raise HarnessError("implementation evidence category differs from the closure oracle")
        claims = [
            claim
            for claim in claims_owned_by_task(paths, state["task_id"])
            if claim.get("token") == args.claim_token
            and claim.get("status") in RESERVING_CLAIM_STATUSES
        ]
        if len(claims) != 1:
            raise HarnessError("implementation evidence requires one reserving task claim")
        baseline = _baseline_by_id(state, args.baseline_id)
        target = lane_by_id(state, args.actor_lane)
        target_snapshot = _baseline_lane_snapshot(baseline, target["lane_id"])
        if (
            target_snapshot.get("revision") != target.get("revision")
            or target_snapshot.get("authority_commit") != target.get("authority_commit")
            or target_snapshot.get("contract_version") != target.get("contract_version")
        ):
            raise HarnessError("implementation baseline does not match target lane authority")
        attempt_number = len(request.get("implementation_attempts", [])) + 1
        artifact = services.snapshot_evidence_artifact(
            paths,
            args.task,
            args.evidence_artifact,
            args.evidence_sha256,
            label="implementation evidence",
            basename=f"coord-{request['request_id']}-implementation-{attempt_number}.artifact",
        )
        recorded = now_iso()
        attempt = {
            "integrity_version": 1,
            "attempt_id": f"{request['request_id']}-implementation-{attempt_number}",
            "actor_lane": target["lane_id"],
            "lane_revision": target["revision"],
            "authority_commit": target["authority_commit"],
            "contract_version": target["contract_version"],
            "directive_ids": sorted(
                directive["directive_id"]
                for directive in request.get("directives", [])
                if directive.get("target_lane") == target["lane_id"]
            ),
            "baseline_id": baseline["baseline_id"],
            "baseline_sha256": baseline["baseline_sha256"],
            "claim_token": claims[0]["token"],
            "evidence_category": args.evidence_category,
            "command": require_evidence_detail(args.command, "implementation command"),
            "boundary": require_evidence_detail(args.boundary, "implementation boundary"),
            "artifact": artifact,
            "recorded_at": recorded,
        }
        request.setdefault("implementation_attempts", []).append(attempt)
        request["version"] = int(request["version"]) + 1
        request["control_phase"] = "evidence_submitted"
        request["updated_at"] = recorded
        request.setdefault("events", []).append(
            {
                "version": request["version"],
                "actor_lane": target["lane_id"],
                "event": "implementation_evidence_submitted_via_steward",
                "detail": attempt["attempt_id"],
                "recorded_at": recorded,
            }
        )
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(attempt, args.json)
    return 0


def cmd_coordination_verify(
    args: argparse.Namespace, paths: HarnessPaths, *, services: CoordinationCmdServices
) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "verify coordination implementation for")
        request = coordination_by_id(state, args.request_id)
        _engaged_steward_lane(state)
        if (
            request.get("version") != args.expected_version
            or request.get("status") != "accepted"
            or request.get("control_phase") != "evidence_submitted"
        ):
            raise HarnessError("coordination verification CAS/status gate failed")
        verifier = lane_by_id(state, args.verifier_lane)
        if verifier["lane_id"] == request.get("target_lane"):
            raise HarnessError("target implementer lane may not independently verify itself")
        if verifier.get("kind") in {"coordination_steward", "capacity_planning"}:
            raise HarnessError("steward and Capacity Planning cannot act as technical verifier")
        if args.category != request.get("closure_category", "integration_test"):
            raise HarnessError("verification category differs from the exact closure oracle")
        implementation = request.get("implementation_attempts", [])[-1]
        baseline = _baseline_by_id(state, str(implementation.get("baseline_id")))
        verifier_snapshot = _baseline_lane_snapshot(baseline, verifier["lane_id"])
        if (
            verifier_snapshot.get("revision") != verifier.get("revision")
            or verifier_snapshot.get("authority_commit") != verifier.get("authority_commit")
            or verifier_snapshot.get("contract_version") != verifier.get("contract_version")
        ):
            raise HarnessError("verification baseline does not match verifier lane authority")
        attempt_number = len(request.get("verification_attempts", [])) + 1
        artifact = services.snapshot_evidence_artifact(
            paths,
            args.task,
            args.evidence_artifact,
            args.evidence_sha256,
            label="independent verification evidence",
            basename=f"coord-{request['request_id']}-verification-{attempt_number}.artifact",
        )
        recorded = now_iso()
        verification = {
            "integrity_version": 1,
            "verification_id": f"{request['request_id']}-verification-{attempt_number}",
            "implementation_attempt_id": implementation["attempt_id"],
            "verifier_lane": verifier["lane_id"],
            "verifier_lane_revision": verifier["revision"],
            "baseline_id": baseline["baseline_id"],
            "baseline_sha256": baseline["baseline_sha256"],
            "category": args.category,
            "status": args.status,
            "test_oracle": require_evidence_detail(args.test_oracle, "verification test oracle"),
            "command": require_evidence_detail(args.command, "verification command"),
            "boundary": require_evidence_detail(args.boundary, "verification boundary"),
            "artifact": artifact,
            "recorded_at": recorded,
        }
        request.setdefault("verification_attempts", []).append(verification)
        request["version"] = int(request["version"]) + 1
        request["control_phase"] = (
            "independently_verified" if args.status == "pass" else "verification_failed"
        )
        request["updated_at"] = recorded
        request.setdefault("events", []).append(
            {
                "version": request["version"],
                "actor_lane": verifier["lane_id"],
                "event": f"independent_verification_{args.status}_via_steward",
                "detail": verification["verification_id"],
                "recorded_at": recorded,
            }
        )
        state.setdefault("verification", []).append(
            {
                "integrity_version": 1,
                "category": args.category,
                "status": args.status,
                "evidence": f"{verification['verification_id']} artifact {artifact['sha256']}",
                "command": verification["command"],
                "boundary": verification["boundary"],
                "run_id": "",
                "lane_id": verifier["lane_id"],
                "coordination_request_id": request["request_id"],
                "baseline_id": baseline["baseline_id"],
                "baseline_sha256": baseline["baseline_sha256"],
                "implementation_attempt_id": implementation["attempt_id"],
                "artifact_refs": [artifact],
                "recorded_at": recorded,
            }
        )
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(verification, args.json)
    return 0


def cmd_coordination_resolve(
    args: argparse.Namespace, paths: HarnessPaths, *, services: CoordinationCmdServices
) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "resolve coordination request for")
        request = coordination_by_id(state, args.request_id)
        _engaged_steward_lane(state)
        session_id = services.require_root_session(paths, state, args.session_id)
        if request.get("version") != args.expected_version:
            raise HarnessError("coordination resolution CAS failed")
        if request.get("status") != "accepted" or request.get("control_phase") != "independently_verified":
            raise HarnessError("coordination resolution requires independent verification PASS")
        if not request.get("baseline_id"):
            raise HarnessError("coordination resolution requires a linked frozen baseline")
        if not request.get("directives") or any(
            directive.get("status") != "acknowledged"
            for directive in request.get("directives", [])
        ):
            raise HarnessError("all distributed directives must be acknowledged before resolution")
        if any(
            item.get("status") == "needs_user"
            and item.get("request_id") in {"", request["request_id"]}
            for item in state.get("needs_user_escalations", [])
        ):
            raise HarnessError("unresolved needs-user escalation blocks coordination resolution")
        verification = request.get("verification_attempts", [])[-1]
        implementation = request.get("implementation_attempts", [])[-1]
        if (
            verification.get("status") != "pass"
            or verification.get("implementation_attempt_id") != implementation.get("attempt_id")
            or verification.get("baseline_id") != implementation.get("baseline_id")
            or verification.get("baseline_sha256") != implementation.get("baseline_sha256")
            or verification.get("category") != request.get("closure_category", "integration_test")
        ):
            raise HarnessError("latest independent verification does not close the latest implementation")
        baseline = _baseline_by_id(state, str(implementation.get("baseline_id")))
        if baseline.get("baseline_sha256") != implementation.get("baseline_sha256"):
            raise HarnessError("implementation verification baseline identity changed")
        involved_lanes = {
            str(request.get("source_lane")),
            str(request.get("target_lane")),
            str(verification.get("verifier_lane")),
        }
        for lane_id in involved_lanes:
            lane = lane_by_id(state, lane_id)
            snapshot = _baseline_lane_snapshot(baseline, lane_id)
            if any(
                snapshot.get(field) != lane.get(field)
                for field in ("revision", "authority_commit", "contract_version")
            ):
                raise HarnessError(
                    "lane authority changed after verification; freeze and verify a fresh baseline"
                )
        for evidence_record, label in (
            (implementation.get("artifact", {}), "implementation evidence"),
            (verification.get("artifact", {}), "verification evidence"),
        ):
            artifact_path = Path(str(evidence_record.get("path", "")))
            artifact_sha = str(evidence_record.get("sha256", ""))
            if (
                not artifact_path.is_file()
                or artifact_path.is_symlink()
                or not re.fullmatch(r"[0-9a-f]{64}", artifact_sha)
                or sha256_file(artifact_path) != artifact_sha
            ):
                raise HarnessError(f"{label} is missing or tampered")
        recorded = now_iso()
        request["version"] = int(request["version"]) + 1
        request["status"] = "resolved"
        request["control_phase"] = "resolved"
        request["resolution"] = {
            "root_owner": state.get("owner"),
            "root_session_id": session_id,
            "evidence": require_evidence_detail(args.evidence, "coordination resolution evidence"),
            "implementation_attempt_id": implementation["attempt_id"],
            "verification_id": verification["verification_id"],
            "verification_baseline_id": verification["baseline_id"],
            "recorded_at": recorded,
        }
        request["updated_at"] = recorded
        request.setdefault("events", []).append(
            {
                "version": request["version"],
                "actor_lane": "root",
                "event": "chief_resolved_after_independent_verification",
                "detail": request["resolution"]["evidence"],
                "recorded_at": recorded,
            }
        )
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(request, args.json)
    return 0


def register_cross_lane_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
    vocab: Any,
) -> None:
    """Register cross-lane session and needs-user escalation commands."""

    missing = sorted(_CROSS_LANE_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _CROSS_LANE_HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "cross-lane command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("cross-lane-open")
    parser.add_argument("--task", required=True)
    parser.add_argument("--cross-lane-session-id", required=True)
    parser.add_argument("--execution-selection-id", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--steward-lane-id", required=True)
    parser.add_argument(
        "--participant-lane", action="append", default=[], required=True
    )
    parser.add_argument("--topic", required=True)
    parser.add_argument("--evidence-boundary", required=True)
    parser.add_argument("--expires-at", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["cross_lane_open"])

    parser = subparsers.add_parser("cross-lane-close")
    parser.add_argument("--task", required=True)
    parser.add_argument("--cross-lane-session-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--steward-lane-id", required=True)
    parser.add_argument("--conclusion", required=True)
    parser.add_argument("--dissent", required=True)
    parser.add_argument("--blocker", required=True)
    parser.add_argument("--evidence", action="append", default=[], required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["cross_lane_close"])

    parser = subparsers.add_parser("cross-lane-cancel")
    parser.add_argument("--task", required=True)
    parser.add_argument("--cross-lane-session-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--steward-lane-id", required=True)
    parser.add_argument("--reason", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["cross_lane_cancel"])

    parser = subparsers.add_parser("needs-user-create")
    parser.add_argument("--task", required=True)
    parser.add_argument("--escalation-id", required=True)
    parser.add_argument(
        "--category", choices=sorted(vocab.needs_user_categories), required=True
    )
    parser.add_argument("--source-lane", required=True)
    parser.add_argument("--request-id")
    parser.add_argument("--problem", required=True)
    parser.add_argument("--option", action="append", default=[], required=True)
    parser.add_argument("--evidence", action="append", default=[], required=True)
    parser.add_argument("--chief-recommendation", required=True)
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["needs_user_create"])

    parser = subparsers.add_parser("needs-user-resolve")
    parser.add_argument("--task", required=True)
    parser.add_argument("--escalation-id", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--user-decision", required=True)
    parser.add_argument("--user-evidence", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["needs_user_resolve"])


def register_coordination_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
    vocab: Any,
) -> None:
    """Register coordination-request and baseline-freeze commands."""

    missing = sorted(_COORDINATION_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _COORDINATION_HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "coordination command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("coordination-create")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--source-lane", required=True)
    parser.add_argument("--target-lane", required=True)
    parser.add_argument(
        "--severity", choices=sorted(vocab.dependency_kinds), required=True
    )
    parser.add_argument("--request", required=True)
    parser.add_argument("--outcome", required=True)
    parser.add_argument("--evidence", action="append", default=[], required=True)
    parser.add_argument("--option", action="append", default=[])
    parser.add_argument("--needed-by-gate")
    parser.add_argument(
        "--change-class",
        choices=sorted(vocab.change_classes - {"genesis"}),
        default="same_contract_implementation",
    )
    parser.add_argument(
        "--closure-category",
        choices=sorted(vocab.close_qualifying_categories),
        default="integration_test",
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["coordination_create"])

    parser = subparsers.add_parser("coordination-update")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--actor-lane", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument(
        "--status", choices=["acknowledged", "countered"], required=True
    )
    parser.add_argument("--response", required=True)
    parser.add_argument("--evidence", action="append", default=[])
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["coordination_update"])

    parser = subparsers.add_parser("coordination-arbitrate")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--decision", choices=["approved", "rejected"], required=True)
    parser.add_argument("--rationale", required=True)
    parser.add_argument("--selected-option")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["coordination_arbitrate"])

    parser = subparsers.add_parser("coordination-directive-ack")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--directive-id", required=True)
    parser.add_argument("--actor-lane", required=True)
    parser.add_argument("--evidence", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["coordination_directive_ack"])

    parser = subparsers.add_parser("coordination-resolve")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--evidence", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["coordination_resolve"])

    parser = subparsers.add_parser("coordination-implementation-submit")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--actor-lane", required=True)
    parser.add_argument("--claim-token", required=True)
    parser.add_argument("--baseline-id", required=True)
    parser.add_argument(
        "--evidence-category",
        choices=sorted(vocab.close_qualifying_categories),
        required=True,
    )
    parser.add_argument("--command", required=True)
    parser.add_argument("--boundary", required=True)
    parser.add_argument("--evidence-artifact", required=True)
    parser.add_argument("--evidence-sha256", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["coordination_implementation_submit"])

    parser = subparsers.add_parser("coordination-verify")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--verifier-lane", required=True)
    parser.add_argument(
        "--category", choices=sorted(vocab.close_qualifying_categories), required=True
    )
    parser.add_argument("--status", choices=["pass", "fail"], required=True)
    parser.add_argument("--test-oracle", required=True)
    parser.add_argument("--command", required=True)
    parser.add_argument("--boundary", required=True)
    parser.add_argument("--evidence-artifact", required=True)
    parser.add_argument("--evidence-sha256", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["coordination_verify"])

    parser = subparsers.add_parser("baseline-freeze")
    parser.add_argument("--task", required=True)
    parser.add_argument("--baseline-id", required=True)
    parser.add_argument("--contract-version", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--decision", required=True)
    parser.add_argument("--lane", action="append", default=[])
    parser.add_argument("--coord", action="append", default=[])
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["baseline_freeze"])


__all__ = [
    "CoordinationCmdServices",
    "cmd_baseline_freeze",
    "cmd_coordination_arbitrate",
    "cmd_coordination_create",
    "cmd_coordination_directive_ack",
    "cmd_coordination_implementation_submit",
    "cmd_coordination_resolve",
    "cmd_coordination_update",
    "cmd_coordination_verify",
    "cmd_cross_lane_cancel",
    "cmd_cross_lane_close",
    "cmd_cross_lane_open",
    "cmd_needs_user_create",
    "cmd_needs_user_resolve",
    "register_coordination_commands",
    "register_cross_lane_commands",
]
