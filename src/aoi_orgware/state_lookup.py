"""Pure by-id state lookups and engagement guards over task state dicts.

Every function here takes a task-state ``dict`` (and, for a few finders, a
lookup key) and either returns the unique matching record or raises
``HarnessError`` — no I/O, no CLI composition. ``require_full_commit`` needs
``FULL_COMMIT_RE``, whose canonical definition lives in
:mod:`aoi_orgware.git_plumbing`; this module imports it from there rather
than duplicating the regex. This module imports only sibling packages and
never imports :mod:`aoi_orgware.cli`.
"""

from __future__ import annotations

from typing import Any

from .git_plumbing import FULL_COMMIT_RE
from .harnesslib import HarnessError, validate_id


ENGAGED_LANE_STATUSES = {"active", "waiting", "recovering", "blocked"}


def require_text(value: str, label: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise HarnessError(f"{label} may not be empty")
    return stripped


def require_open_task(state: dict[str, Any], action: str) -> None:
    if state.get("status") not in {"active", "blocked"}:
        raise HarnessError(
            f"cannot {action} task {state.get('task_id')} in status {state.get('status')}"
        )


def require_full_commit(value: str, label: str) -> str:
    commit = require_text(value, label).lower()
    if not FULL_COMMIT_RE.fullmatch(commit):
        raise HarnessError(f"{label} must be a full 40-64 hex commit id")
    return commit


def lane_by_id(state: dict[str, Any], lane_id: str) -> dict[str, Any]:
    lane_id = validate_id(lane_id, "lane id")
    matches = [lane for lane in state.get("lanes", []) if lane.get("lane_id") == lane_id]
    if len(matches) != 1:
        raise HarnessError(f"expected exactly one lane named {lane_id}, found {len(matches)}")
    return matches[0]


def coordination_by_id(state: dict[str, Any], request_id: str) -> dict[str, Any]:
    request_id = validate_id(request_id, "coordination request id")
    matches = [
        request
        for request in state.get("coordination_requests", [])
        if request.get("request_id") == request_id
    ]
    if len(matches) != 1:
        raise HarnessError(
            f"expected exactly one coordination request named {request_id}, found {len(matches)}"
        )
    return matches[0]


def capacity_review_by_id(state: dict[str, Any], review_id: str) -> dict[str, Any]:
    review_id = validate_id(review_id, "capacity review id")
    matches = [
        review
        for review in state.get("capacity_reviews", [])
        if review.get("review_id") == review_id
    ]
    if len(matches) != 1:
        raise HarnessError(
            f"expected exactly one capacity review named {review_id}, found {len(matches)}"
        )
    return matches[0]


def execution_selection_by_id(state: dict[str, Any], selection_id: str) -> dict[str, Any]:
    selection_id = validate_id(selection_id, "execution selection id")
    matches = [
        item
        for item in state.get("execution_selections", [])
        if item.get("selection_id") == selection_id
    ]
    if len(matches) != 1:
        raise HarnessError(
            f"expected exactly one execution selection named {selection_id}, found {len(matches)}"
        )
    return matches[0]


def _packet_by_id(state: dict[str, Any], packet_id: str) -> dict[str, Any]:
    matches = [
        packet
        for packet in state.get("packets", [])
        if packet.get("packet_id") == packet_id
    ]
    if len(matches) != 1:
        raise HarnessError(
            f"expected exactly one packet named {packet_id}, found {len(matches)}"
        )
    return matches[0]


def cross_lane_session_by_id(state: dict[str, Any], session_id: str) -> dict[str, Any]:
    session_id = validate_id(session_id, "cross-lane session id")
    matches = [
        item
        for item in state.get("cross_lane_sessions", [])
        if item.get("cross_lane_session_id") == session_id
    ]
    if len(matches) != 1:
        raise HarnessError(
            f"expected exactly one cross-lane session named {session_id}, found {len(matches)}"
        )
    return matches[0]


def needs_user_by_id(state: dict[str, Any], escalation_id: str) -> dict[str, Any]:
    escalation_id = validate_id(escalation_id, "needs-user escalation id")
    matches = [
        item
        for item in state.get("needs_user_escalations", [])
        if item.get("escalation_id") == escalation_id
    ]
    if len(matches) != 1:
        raise HarnessError(
            f"expected exactly one needs-user escalation named {escalation_id}, found {len(matches)}"
        )
    return matches[0]


def improvement_request_by_id(state: dict[str, Any], request_id: str) -> dict[str, Any]:
    request_id = validate_id(request_id, "improvement request id")
    matches = [
        request
        for request in state.get("improvement_requests", [])
        if request.get("request_id") == request_id
    ]
    if len(matches) != 1:
        raise HarnessError(
            f"expected exactly one improvement request named {request_id}, found {len(matches)}"
        )
    return matches[0]


def _baseline_by_id(state: dict[str, Any], baseline_id: str) -> dict[str, Any]:
    baseline_id = validate_id(baseline_id, "baseline id")
    matches = [
        item
        for item in state.get("integration_baselines", [])
        if item.get("baseline_id") == baseline_id
    ]
    if len(matches) != 1:
        raise HarnessError(f"expected exactly one baseline named {baseline_id}, found {len(matches)}")
    return matches[0]


def _engaged_steward_lane(state: dict[str, Any]) -> dict[str, Any]:
    stewards = [
        lane
        for lane in state.get("lanes", [])
        if lane.get("kind") == "coordination_steward"
        and lane.get("status") in ENGAGED_LANE_STATUSES
    ]
    if len(stewards) != 1:
        raise HarnessError(
            "coordination requires exactly one engaged coordination_steward lane"
        )
    return stewards[0]


def _engaged_capacity_lane(state: dict[str, Any], lane_id: str) -> dict[str, Any]:
    lane = lane_by_id(state, lane_id)
    if lane.get("kind") != "capacity_planning" or lane.get("status") not in ENGAGED_LANE_STATUSES:
        raise HarnessError("capacity review requires an engaged capacity_planning lane")
    return lane


__all__ = [
    "ENGAGED_LANE_STATUSES",
    "_baseline_by_id",
    "_engaged_capacity_lane",
    "_engaged_steward_lane",
    "_packet_by_id",
    "capacity_review_by_id",
    "coordination_by_id",
    "cross_lane_session_by_id",
    "execution_selection_by_id",
    "improvement_request_by_id",
    "lane_by_id",
    "needs_user_by_id",
    "require_full_commit",
    "require_open_task",
]
