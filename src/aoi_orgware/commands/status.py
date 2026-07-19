"""Read-oriented status, resume, and index command family.

This module owns both parser registration and command bodies for ``resume``,
``status``, and ``render-index``.  It remains a leaf of the CLI composition
root: project-specific policy and the two remaining CLI-resident helpers are
provided through :class:`StatusCmdServices`; the module never imports
``aoi_orgware.cli``.
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from typing import Any

from ..harnesslib import (
    ACTIVE_JOB_STATUSES,
    ACTIVE_PACKET_STATUSES,
    RESERVING_CLAIM_STATUSES,
    HarnessError,
    HarnessPaths,
    checkpoint_matches,
    chief_authority_summary,
    is_expired,
    is_semantic_v2_task,
    load_all_claims,
    load_all_tasks,
    load_json,
    load_task,
    require_complete_layout,
    session_path,
    sha256_file,
    state_lock,
    task_dir,
    task_state_path,
    task_summary,
    write_index,
)
from ..semantic_store import load_semantic_events
from ..state_lookup import ENGAGED_LANE_STATUSES


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset({"resume", "status", "render_index"})
_SEMANTIC_CURSOR_RE = re.compile(r"([1-9][0-9]*):([0-9a-f]{64})\Z")


@dataclass(frozen=True)
class StatusCmdServices:
    """CLI-owned helpers and immutable projection-policy values."""

    check_session_id: Callable[[str], str]
    plan_digest: Callable[[HarnessPaths, dict[str, Any]], str]
    terminal_coordination_statuses: Collection[str]
    terminal_improvement_statuses: Collection[str]
    max_engaged_lanes: int
    critical_view_max_bytes: int
    critical_text_limit: int


def emit(payload: Any, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
        return
    if isinstance(payload, str):
        print(payload)
        return
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


def _semantic_cursor(event: Mapping[str, Any]) -> str:
    """Return the stable cursor for one authenticated semantic event."""

    return f"{event['sequence']}:{event['event_sha256']}"


def _semantic_delta(
    task_id: str, cursor: str, events: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], str]:
    """Select the authenticated semantic tail strictly after ``cursor``."""

    match = _SEMANTIC_CURSOR_RE.fullmatch(cursor)
    if match is None:
        raise HarnessError(
            "semantic status cursor is malformed; expected <sequence>:<event-sha256>"
        )
    sequence = int(match.group(1))
    event_sha256 = match.group(2)
    for index, event in enumerate(events):
        if event["sequence"] == sequence and event["event_sha256"] == event_sha256:
            return events[index + 1 :], _semantic_cursor(events[-1])
    raise HarnessError(
        f"semantic status cursor is unknown for task {task_id}; "
        "refusing a partial delta"
    )


def _short(value: Any, length: int = 12) -> str:
    text_value = str(value or "")
    return text_value[:length] if text_value else "-"


def _claim_text(claim: Mapping[str, Any]) -> str:
    return f"{claim.get('token', '-')}@{claim.get('owner', '-')}"


def _first_line(value: Any, *, fallback: str = "none") -> str:
    text = str(value or "").strip()
    return text.splitlines()[0] if text else fallback


def _human_claims(claims: list[dict[str, Any]], task_id: str | None = None) -> str:
    relevant = [
        claim for claim in claims if task_id is None or claim.get("task_id") == task_id
    ]
    active = sorted(
        [
            claim
            for claim in relevant
            if claim.get("status") in RESERVING_CLAIM_STATUSES
            and not is_expired(claim.get("expires_at"))
        ],
        key=lambda claim: (
            str(claim.get("task_id", "")),
            str(claim.get("token", "")),
            str(claim.get("owner", "")),
        ),
    )
    stale = sorted(
        [
            claim
            for claim in relevant
            if claim.get("status") in RESERVING_CLAIM_STATUSES
            and is_expired(claim.get("expires_at"))
        ],
        key=lambda claim: (
            str(claim.get("task_id", "")),
            str(claim.get("token", "")),
            str(claim.get("owner", "")),
        ),
    )

    def concise(items: list[dict[str, Any]]) -> str:
        shown = ", ".join(_claim_text(item) for item in items[:3])
        return shown + (f", +{len(items) - 3}" if len(items) > 3 else "")

    return (
        f"claims: active={len(active)}"
        + (f" [{concise(active)}]" if active else "")
        + f"; stale={len(stale)}"
        + (f" [{concise(stale)}]" if stale else "")
    )


def _human_event_summary(paths: HarnessPaths, state: dict[str, Any]) -> tuple[str, str]:
    task_id = str(state["task_id"])
    if not is_semantic_v2_task(paths, task_id):
        return "unavailable", "unavailable"
    events = load_semantic_events(paths, task_id)
    head = _semantic_cursor(events[-1])
    recent = ", ".join(
        f"{event['sequence']}:{event['event_type']}/{event['command_id']}"
        for event in events[-3:]
    )
    return head, recent


def _human_task_status(
    paths: HarnessPaths, state: dict[str, Any], claims: list[dict[str, Any]]
) -> list[str]:
    semantic_head, recent_events = _human_event_summary(paths, state)
    running = sorted(
        [
            *(
                f"packet:{packet.get('packet_id', '-')}"
                for packet in state.get("packets", [])
                if packet.get("status") in ACTIVE_PACKET_STATUSES
            ),
            *(
                f"job:{job.get('run_id', '-')}"
                for job in state.get("jobs", [])
                if job.get("status") in ACTIVE_JOB_STATUSES
            ),
        ]
    )
    needs_user = sorted(
        str(item.get("escalation_id", "-"))
        for item in state.get("needs_user_escalations", [])
        if item.get("status") == "needs_user"
    )
    blocked = sorted(
        [
            *(
                str(lane.get("lane_id", "-"))
                for lane in state.get("lanes", [])
                if lane.get("status") == "blocked"
            ),
            *(
                str(job.get("run_id", "-"))
                for job in state.get("jobs", [])
                if job.get("status") == "blocked"
            ),
        ]
    )
    task_blocked = state.get("status") == "blocked"
    task_id = str(state["task_id"])
    try:
        checkpoint_current, checkpoint_reason = checkpoint_matches(paths, state)
    except (AttributeError, HarnessError, KeyError, OSError, TypeError, ValueError):
        checkpoint_current, checkpoint_reason = False, "checkpoint state is invalid"
    relevant_claims = [claim for claim in claims if claim.get("task_id") == task_id]
    stale_claim_count = sum(
        claim.get("status") in RESERVING_CLAIM_STATUSES
        and is_expired(claim.get("expires_at"))
        for claim in relevant_claims
    )
    verification = state.get("verification", [])
    last_evidence = verification[-1] if isinstance(verification, list) and verification else None
    if isinstance(last_evidence, Mapping):
        evidence_summary = (
            f"{last_evidence.get('category', 'unclassified')}: "
            f"{_first_line(last_evidence.get('boundary') or last_evidence.get('evidence'))}"
        )
    else:
        evidence_summary = "none"
    raw_risks = state.get("risks", [])
    risks = (
        [_first_line(item) for item in raw_risks[:3]]
        if isinstance(raw_risks, list)
        else ["invalid risk record"]
    )
    blocked_summary = (
        ", ".join(blocked[:3])
        if blocked
        else ("task" if task_blocked else "none")
    )
    lines = [
        (
            f"Task {task_id}: {state.get('status', '-')} "
            f"profile={state.get('profile', 'full')} phase={state.get('phase', '-')} "
            f"revision={state.get('revision', '-')} owner={state.get('owner', '-')}"
        ),
        f"  semantic-head: {semantic_head}",
        f"  {_human_claims(claims, task_id)}",
        (
            f"  running: {', '.join(running[:3]) if running else 'none'}; "
            f"needs-user: {', '.join(needs_user[:3]) if needs_user else 'none'}; "
            f"blocked: {blocked_summary}; checkpoint: "
            f"{'current' if checkpoint_current else checkpoint_reason}; "
            f"expired-claims: {stale_claim_count}"
        ),
        f"  evidence: {evidence_summary}",
        f"  risks: {', '.join(risks) if risks else 'none'}",
        f"  recent-events: {recent_events}",
    ]
    if state.get("next_action"):
        lines.append(f"  next: {state['next_action']}")
    return lines


def _render_human_status(
    paths: HarnessPaths,
    tasks: list[dict[str, Any]],
    claims: list[dict[str, Any]],
    *,
    terminal_task_count: int = 0,
) -> str:
    chief = chief_authority_summary(paths)
    lines = [
        "Chief: "
        f"{chief.get('status', 'unavailable')} "
        f"session={_short(chief.get('session_id'))} "
        f"epoch={chief.get('epoch', '-')} expires={chief.get('expires_at', '-')}",
        _human_claims(claims),
    ]
    if terminal_task_count:
        lines.append(
            f"terminal tasks omitted: {terminal_task_count} (use --task <id> or --json)"
        )
    for state in sorted(tasks, key=lambda item: str(item.get("task_id", ""))):
        lines.extend(_human_task_status(paths, state, claims))
    return "\n".join(lines)


def _render_human_semantic_delta(
    task_id: str, events: list[dict[str, Any]], next_cursor: str
) -> str:
    lines = [f"Task {task_id}: semantic delta={len(events)}"]
    lines.extend(
        f"  {event['sequence']}: {event['event_type']} command={event['command_id']}"
        for event in events
    )
    lines.append(f"next-cursor: {next_cursor}")
    return "\n".join(lines)


def _clip_critical(value: Any, *, services: StatusCmdServices) -> str:
    text_value = str(value or "")
    if len(text_value.encode("utf-8")) <= services.critical_text_limit:
        return text_value
    encoded = text_value.encode("utf-8")[: services.critical_text_limit - 3]
    return encoded.decode("utf-8", "ignore") + "..."


def critical_projection(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    services: StatusCmdServices,
) -> dict[str, Any]:
    state_path = task_state_path(paths, state["task_id"])
    lanes = sorted(
        [
            lane
            for lane in state.get("lanes", [])
            if lane.get("status") in ENGAGED_LANE_STATUSES
        ],
        key=lambda lane: lane["lane_id"],
    )
    standby_count = sum(
        lane.get("status") in {"standby", "parked"}
        for lane in state.get("lanes", [])
    )
    active_requests = sorted(
        [
            request
            for request in state.get("coordination_requests", [])
            if request.get("status") not in services.terminal_coordination_statuses
        ],
        key=lambda request: (
            {"hard_gate": 0, "soft_dependency": 1, "informational": 2}.get(
                request.get("severity"), 3
            ),
            request.get("needed_by_gate", ""),
            request.get("request_id", ""),
        ),
    )
    request_tail = active_requests[:8]
    active_capacity = sorted(
        [
            review
            for review in state.get("capacity_reviews", [])
            if review.get("status") not in {"rejected", "consumed", "superseded"}
        ],
        key=lambda review: str(review.get("review_id", "")),
    )
    active_improvements = sorted(
        [
            request
            for request in state.get("improvement_requests", [])
            if request.get("status") not in services.terminal_improvement_statuses
        ],
        key=lambda request: str(request.get("request_id", "")),
    )
    open_cross_sessions = sorted(
        [
            item
            for item in state.get("cross_lane_sessions", [])
            if item.get("status") == "open"
        ],
        key=lambda item: str(item.get("cross_lane_session_id", "")),
    )
    needs_user = sorted(
        [
            item
            for item in state.get("needs_user_escalations", [])
            if item.get("status") == "needs_user"
        ],
        key=lambda item: str(item.get("escalation_id", "")),
    )
    open_spawn_incidents = sorted(
        [
            item
            for item in state.get("subagent_incidents", [])
            if item.get("status") == "open"
        ],
        key=lambda item: str(item.get("incident_id", "")),
    )
    baseline = state.get("integration_baselines", [])[-1:] or []
    payload: dict[str, Any] = {
        "view_version": 1,
        "task_id": state["task_id"],
        "task_revision": state.get("revision"),
        "root_authority": {
            "owner": state.get("owner"),
            "session_ids": sorted(state.get("session_ids", [])),
            "role": "chief_architect_arbitrator_release_authority",
        },
        "authority_mode": "lane_modeled" if state.get("lanes") else "legacy_unmodeled",
        "artifact_mode": "manifest_attested"
        if any(job.get("job_schema_version") == 2 for job in state.get("jobs", []))
        else "legacy_unattested",
        "baseline": baseline[0] if baseline else None,
        "execution_topology": [
            {
                "selection_id": item.get("selection_id"),
                "mode": item.get("mode"),
                "status": item.get("status"),
                "lanes": [
                    lane.get("lane_id") for lane in item.get("lane_snapshots", [])
                ],
                "scope": _clip_critical(item.get("scope"), services=services),
            }
            for item in state.get("execution_selections", [])[-4:]
        ],
        "lanes": [
            {
                "lane_id": lane["lane_id"],
                "kind": lane["kind"],
                "status": lane["status"],
                "owner": lane["owner"],
                "revision": lane["revision"],
                "authority_commit": lane["authority_commit"],
                "contract_version": lane["contract_version"],
                "generator_version": lane["generator_version"],
                "next_action": _clip_critical(
                    lane["next_action"], services=services
                ),
                "active_packets": sorted(
                    packet.get("packet_id")
                    for packet in state.get("packets", [])
                    if packet.get("lane_id") == lane["lane_id"]
                    and packet.get("status") in ACTIVE_PACKET_STATUSES
                ),
                "active_jobs": sorted(
                    job.get("run_id")
                    for job in state.get("jobs", [])
                    if job.get("lane_id") == lane["lane_id"]
                    and job.get("status") in ACTIVE_JOB_STATUSES
                ),
            }
            for lane in lanes[: services.max_engaged_lanes]
        ],
        "coordination_inbox": [
            {
                "request_id": request["request_id"],
                "source_lane": request["source_lane"],
                "target_lane": request["target_lane"],
                "steward_lane": request.get("steward_lane"),
                "severity": request["severity"],
                "status": request["status"],
                "control_phase": request.get("control_phase"),
                "needed_by_gate": request.get("needed_by_gate", ""),
                "request": _clip_critical(
                    request.get("request"), services=services
                ),
            }
            for request in request_tail
        ],
        "capacity_inbox": [
            {
                "review_id": review.get("review_id"),
                "status": review.get("status"),
                "version": review.get("version"),
                "target_lane_id": review.get("scope", {}).get("target_lane_id"),
                "task_type": review.get("scope", {}).get("task_type"),
                "leaf_role": review.get("scope", {}).get("leaf_role"),
                "capability_tier": (review.get("recommendation") or {}).get(
                    "capability_tier"
                ),
                "record_count": review.get("dataset", {}).get("record_count"),
            }
            for review in active_capacity[:8]
        ],
        "improvement_inbox": [
            {
                "request_id": request.get("request_id"),
                "status": request.get("status"),
                "version": request.get("version"),
                "source_lane_id": request.get("source_lane_id"),
                "task_type": request.get("task_type"),
                "trigger_class": request.get("trigger_class"),
                "selected_option_id": (request.get("chief_decision") or {}).get(
                    "selected_option_id"
                ),
                "project_task_id": request.get("project", {}).get("task_id"),
                "release_blocking": bool(request.get("release_blocking")),
            }
            for request in active_improvements[:8]
        ],
        "controlled_cross_lane_sessions": [
            {
                "cross_lane_session_id": item.get("cross_lane_session_id"),
                "request_id": item.get("request_id"),
                "execution_selection_id": item.get("execution_selection_id"),
                "participants": [
                    lane.get("lane_id")
                    for lane in item.get("participant_snapshots", [])
                ],
                "expires_at": item.get("expires_at"),
            }
            for item in open_cross_sessions[:6]
        ],
        "needs_user": [
            {
                "escalation_id": item.get("escalation_id"),
                "category": item.get("category"),
                "source_lane_id": item.get("source_lane_id"),
                "request_id": item.get("request_id"),
                "problem": _clip_critical(item.get("problem"), services=services),
                "chief_recommendation": _clip_critical(
                    item.get("chief_recommendation"), services=services
                ),
            }
            for item in needs_user[:8]
        ],
        "subagent_spawn_incidents": [
            {
                "incident_id": item.get("incident_id"),
                "reason_code": item.get("reason_code"),
                "agent_id": item.get("agent_id"),
                "agent_type": item.get("agent_type"),
                "observed_at": item.get("observed_at"),
            }
            for item in open_spawn_incidents[:8]
        ],
        "execution_briefs": [
            {
                "brief_id": item.get("brief_id"),
                "execution_selection_id": item.get("execution_selection_id"),
                "packet_count": len(item.get("packet_bindings", [])),
                "recommendation": _clip_critical(
                    item.get("recommendation"), services=services
                ),
            }
            for item in state.get("execution_briefs", [])[-4:]
        ],
        "open_hard_gates": sorted(
            dependency.get("dependency_id")
            for dependency in state.get("lane_dependencies", [])
            if dependency.get("kind") == "hard_gate"
            and dependency.get("status") == "open"
        ),
        "task_level_active": {
            "packets": sorted(
                packet.get("packet_id")
                for packet in state.get("packets", [])
                if packet.get("status") in ACTIVE_PACKET_STATUSES
                and not packet.get("lane_id")
            ),
            "jobs": sorted(
                job.get("run_id")
                for job in state.get("jobs", [])
                if job.get("status") in ACTIVE_JOB_STATUSES and not job.get("lane_id")
            ),
        },
        "omitted": {
            "standby_or_parked_lanes": standby_count,
            "coordination_requests": max(0, len(active_requests) - len(request_tail)),
            "capacity_reviews": max(0, len(active_capacity) - 8),
            "improvement_requests": max(0, len(active_improvements) - 8),
            "cross_lane_sessions": max(0, len(open_cross_sessions) - 6),
            "needs_user": max(0, len(needs_user) - 8),
            "subagent_spawn_incidents": max(0, len(open_spawn_incidents) - 8),
            "execution_briefs": max(
                0, len(state.get("execution_briefs", [])) - 4
            ),
        },
        "full_state": {"path": str(state_path), "sha256": sha256_file(state_path)},
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    if len(raw) > services.critical_view_max_bytes:
        payload["coordination_inbox"] = []
        payload["omitted"]["coordination_requests"] = len(active_requests)
        payload["improvement_inbox"] = []
        payload["omitted"]["improvement_requests"] = len(active_improvements)
        payload["controlled_cross_lane_sessions"] = []
        payload["omitted"]["cross_lane_sessions"] = len(open_cross_sessions)
        payload["view_complete"] = False
    else:
        payload["view_complete"] = not any(payload["omitted"].values())
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    if len(raw) > services.critical_view_max_bytes:
        raise HarnessError("critical status projection exceeds 12 KiB")
    return payload


def resolve_resume_task(
    paths: HarnessPaths,
    task_id: str | None,
    session_id: str | None,
    *,
    services: StatusCmdServices,
) -> dict[str, Any]:
    if task_id:
        return load_task(paths, task_id)
    if session_id:
        mapping = load_json(session_path(paths, services.check_session_id(session_id)))
        return load_task(paths, str(mapping.get("task_id")))
    raise HarnessError("provide --task or --session-id")


def cmd_resume(
    args: argparse.Namespace,
    paths: HarnessPaths,
    *,
    services: StatusCmdServices,
) -> int:
    state = resolve_resume_task(paths, args.task, args.session_id, services=services)
    checkpoint_path = task_dir(paths, state["task_id"]) / "checkpoint.md"
    checkpoint_ok, checkpoint_reason = checkpoint_matches(paths, state)
    try:
        plan_current = bool(
            state.get("plan_ready")
            and state.get("plan_sha256") == services.plan_digest(paths, state)
        )
    except HarnessError:
        plan_current = False
    payload = task_summary(state)
    payload.update(
        {
            "objective": state.get("objective"),
            "completion_boundary": state.get("completion_boundary"),
            "plan_path": str(task_dir(paths, state["task_id"]) / "plan.md"),
            "checkpoint_path": str(checkpoint_path),
            "checkpoint_exists": checkpoint_path.exists(),
            "warnings": [
                warning
                for warning in (
                    f"checkpoint is stale: {checkpoint_reason}"
                    if not checkpoint_ok
                    else "",
                    "plan is not approved/current" if not plan_current else "",
                    "task is not active"
                    if state.get("status") not in {"active", "blocked"}
                    else "",
                )
                if warning
            ],
        }
    )
    emit(payload, args.json)
    return 0


def cmd_status(
    args: argparse.Namespace,
    paths: HarnessPaths,
    *,
    services: StatusCmdServices,
) -> int:
    since = getattr(args, "since", None)
    if args.critical:
        if since is not None:
            raise HarnessError("status --since cannot be combined with --critical")
        if not args.task:
            raise HarnessError("status --critical requires --task")
        emit(
            critical_projection(
                paths, load_task(paths, args.task), services=services
            ),
            args.json,
        )
        return 0
    if since is not None:
        if not args.task:
            raise HarnessError("status --since requires --task")
        state = load_task(paths, args.task)
        if not is_semantic_v2_task(paths, state["task_id"]):
            raise HarnessError("status --since is unavailable for legacy tasks")
        events = load_semantic_events(paths, state["task_id"])
        delta, next_cursor = _semantic_delta(state["task_id"], since, events)
        delta_payload = {
            "task_id": state["task_id"],
            "events": delta,
            "next_cursor": next_cursor,
        }
        if args.json:
            emit(delta_payload, True)
        else:
            emit(_render_human_semantic_delta(state["task_id"], delta, next_cursor))
        return 0
    if args.task:
        state = load_task(paths, args.task)
        if args.json:
            emit(task_summary(state), True)
        else:
            emit(_render_human_status(paths, [state], load_all_claims(paths)))
        return 0
    require_complete_layout(paths)
    tasks = load_all_tasks(paths)
    claims = load_all_claims(paths)
    structured = [claim for claim in claims if not claim.get("legacy")]
    legacy = [claim for claim in claims if claim.get("legacy")]
    payload: dict[str, Any] = {
        "root": str(paths.root),
        "chief_authority": chief_authority_summary(paths),
        "tasks": [task_summary(task) for task in tasks],
        "structured_claims": [
            {
                "token": claim.get("token"),
                "task_id": claim.get("task_id"),
                "owner": claim.get("owner"),
                "status": claim.get("status"),
                "expires_at": claim.get("expires_at"),
                "expired_still_reserved": bool(
                    claim.get("status") in RESERVING_CLAIM_STATUSES
                    and is_expired(claim.get("expires_at"))
                ),
                "locks": claim.get("locks", []),
            }
            for claim in structured
        ],
        "legacy_pending_count": len(
            [
                claim
                for claim in legacy
                if claim.get("status") in RESERVING_CLAIM_STATUSES
            ]
        ),
        "legacy_expired_unverified_count": len(
            [
                claim
                for claim in legacy
                if claim.get("legacy_classification") == "expired_unverified"
            ]
        ),
    }
    if args.legacy:
        payload["legacy_pending"] = [
            {
                "token": claim.get("token"),
                "owner": claim.get("owner"),
                "status": claim.get("status"),
                "classification": claim.get("legacy_classification"),
                "expires_at": claim.get("expires_at"),
                "locks": claim.get("locks", []),
                "raw_scope": claim.get("raw_scope"),
                "scope_parse_warnings": claim.get("scope_parse_warnings", []),
                "source_file": claim.get("source_file"),
                "source_line": claim.get("source_line"),
                "pending_file": claim.get("_path"),
            }
            for claim in legacy
        ]
    if args.json:
        emit(payload, True)
    else:
        active_tasks = [
            task for task in tasks if task.get("status") in {"active", "blocked"}
        ]
        emit(
            _render_human_status(
                paths,
                active_tasks,
                claims,
                terminal_task_count=len(tasks) - len(active_tasks),
            )
        )
    return 0


def cmd_render_index(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        write_index(paths)
    emit({"index": str(paths.index)}, args.json)
    return 0


def register_status_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register ``resume``, ``status``, and ``render-index``."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "status command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("resume")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--task")
    group.add_argument("--session-id")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["resume"])

    parser = subparsers.add_parser("status")
    parser.add_argument("--legacy", action="store_true")
    parser.add_argument("--task")
    parser.add_argument("--critical", action="store_true")
    parser.add_argument(
        "--since",
        help=(
            "semantic cursor (<sequence>:<event-sha256>) for one task's "
            "authenticated delta"
        ),
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["status"])

    parser = subparsers.add_parser("render-index")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["render_index"])


__all__ = [
    "StatusCmdServices",
    "cmd_render_index",
    "cmd_resume",
    "cmd_status",
    "critical_projection",
    "register_status_commands",
    "resolve_resume_task",
]
