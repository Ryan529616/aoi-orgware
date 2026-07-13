#!/usr/bin/env python3
"""Plan/claim/delegate/verify/checkpoint CLI for ARISE work."""

from __future__ import annotations

import sys

# Prevent importing the local harness library from creating workspace bytecode.
sys.dont_write_bytecode = True

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from harnesslib import (
    ACCOUNTED_VERIFICATION_STATUSES,
    ACTIVE_JOB_STATUSES,
    ACTIVE_PACKET_STATUSES,
    CLAIM_STATUSES,
    DELIVERY_MODES,
    JOB_STATUSES,
    PACKET_STATUSES,
    RESERVING_CLAIM_STATUSES,
    SCHEMA_VERSION,
    TASK_PHASES,
    TASK_STATUSES,
    TERMINAL_CLAIM_STATUSES,
    VERIFICATION_STATUSES,
    HarnessError,
    HarnessPaths,
    atomic_write_bytes,
    atomic_write_json,
    atomic_write_text,
    baselines_for_locks,
    bump_task,
    checkpoint_matches,
    claim_path,
    claims_for_task,
    claims_owned_by_task,
    ensure_layout,
    find_conflicts,
    fsync_directory,
    get_paths,
    host_path_to_wsl,
    import_legacy,
    is_expired,
    lock_covers,
    legacy_pending_path,
    load_all_claims,
    load_all_tasks,
    load_claim_file,
    load_json,
    load_task,
    normalize_lock,
    now_iso,
    parse_legacy_table,
    parse_lock,
    parse_time,
    prepare_checkpoint,
    record_legacy_decision,
    render_checkpoint,
    session_path,
    sha256_file,
    state_lock,
    task_dir,
    task_state_path,
    task_summary,
    validate_id,
    write_index,
    write_task,
)


PLAN_FALLBACK = """# Plan — {{TASK_ID}}

- Title: {{TITLE}}
- Owner: {{OWNER}}
- Objective: {{OBJECTIVE}}
- Completion boundary: {{COMPLETION_BOUNDARY}}

## Work breakdown

1. Inspect current evidence.
2. Acquire claims.
3. Delegate bounded independent packets.
4. Implement and verify.
5. Checkpoint and close.
"""

PACKET_FALLBACK = """# Sub-agent packet — {{PACKET_ID}}

- Parent task: {{TASK_ID}}
- Role / model tier: {{AGENT_ROLE}} / {{MODEL_TIER}}
- Objective: {{OBJECTIVE}}
- Scope: {{SCOPE}}
- Locks owned by root: {{LOCKS}}
- Deliverable: {{DELIVERABLE}}
- Verification: {{VALIDATION}}

## Required context

{{READ_FIRST}}

Return conclusion, evidence paths, files touched, checks, risks, and next action.
Do not edit harness state or work outside this packet.
"""

ROLE_TIER_MAP = {
    "architect": "sol-max",
    "numeric_debugger": "sol-max",
    "rtl_engineer": "sol-high",
    "reviewer": "sol-high",
    "eda_expert": "sol-high",
    "worker": "terra-high",
    "explorer": "terra-medium",
    "eda_operator": "terra-medium",
    "default": "terra-medium",
    "batch": "luna-low",
}
TERMINAL_PACKET_STATUSES = PACKET_STATUSES - ACTIVE_PACKET_STATUSES
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
FULL_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")
VERIFICATION_CATEGORIES = {
    "static_check",
    "unit_test",
    "integration_test",
    "compile_acceptance",
    "runtime_test",
    "numeric_runtime",
    "eda_runtime",
    "physical_evidence",
    "hook_smoke",
    "skill_validation",
    "doctor",
    "independent_review",
    "documentation_check",
    "historical_terminal_readback",
    "citation_hygiene_review",
    "resource_governance",
    "delivery_check",
    "engineering_inference",
}
CLOSE_QUALIFYING_CATEGORIES = VERIFICATION_CATEGORIES - {
    "engineering_inference",
    "historical_terminal_readback",
}
RECEIPT_COMPONENTS = ("rtl", "tb", "sram", "runner", "golden", "overlay")
HOOK_PROTOCOL_VERSION = "5"
MINI_MAX_LOCKS = 3
MINI_FORBIDDEN_REPO_PREFIXES = (
    "rtl/",
    "tb/",
    "paper/",
    "experiments/",
    "scripts/harness/",
    "scripts/run/",
    ".codex/",
    "docs/current/contracts/",
    "docs/current/status/evidence/",
)
LANE_KINDS = {
    "architecture",
    "rtl",
    "numeric",
    "golden_numeric",
    "verification",
    "eda_pd",
    "physical",
    "performance",
    "integration",
    "coordination_steward",
    "capacity_planning",
    "other",
}
LANE_STATUSES = {
    "active",
    "waiting",
    "recovering",
    "blocked",
    "standby",
    "parked",
    "done",
}
ENGAGED_LANE_STATUSES = {"active", "waiting", "recovering", "blocked"}
DEPENDENCY_KINDS = {"hard_gate", "soft_dependency", "informational"}
DEPENDENCY_STATUSES = {"open", "satisfied", "waived", "superseded"}
COORDINATION_STATUSES = {
    "open",
    "acknowledged",
    "countered",
    "accepted",
    "rejected",
    "resolved",
    "superseded",
}
TERMINAL_COORDINATION_STATUSES = {"rejected", "resolved", "superseded"}
CHANGE_CLASSES = {
    "genesis",
    "evidence_only",
    "same_contract_implementation",
    "semantic_change",
    "transport_layout_change",
}
MAX_ENGAGED_LANES = 12
CRITICAL_VIEW_MAX_BYTES = 12 * 1024
CRITICAL_TEXT_LIMIT = 160
COMMAND_ARTIFACT_MAX_BYTES = 1024 * 1024
TERMINAL_ARTIFACT_MAX_BYTES = 64 * 1024 * 1024
CAPABILITY_CATALOG_VERSION = 1
CAPABILITY_TIER_MAP = {
    "c1_mechanical": "luna-low",
    "c2_routine": "terra-medium",
    "c3_advanced": "terra-high",
    "c4_expert": "sol-high",
    "c5_frontier": "sol-max",
}
DEPTH_TWO_ROLES = {"batch", "explorer", "worker"}
IMPROVEMENT_TRIGGER_CLASSES = {"repeated_pain", "critical_single_incident"}
IMPROVEMENT_STATUSES = {
    "submitted",
    "awaiting_chief",
    "approved",
    "rejected",
    "delegated",
    "building",
    "validating",
    "release_candidate",
    "canary",
    "adopted",
    "paused",
    "rolled_back",
    "deprecated",
}
TERMINAL_IMPROVEMENT_STATUSES = {"rejected", "adopted", "rolled_back", "deprecated"}
IMPROVEMENT_OPTION_IDS = {"maintain-current", "capacity", "skill-automation"}
SKILL_ADOPTION_ACTIONS = {"canary", "adopt", "pause", "rollback", "deprecate"}
EXECUTION_MODES = {"single", "centralized_parallel", "hybrid"}
DEPENDENCY_LEVELS = {"low", "medium", "high"}
TOOL_DENSITIES = {"low", "medium", "high"}
CROSS_LANE_SESSION_STATUSES = {"open", "closed", "cancelled"}
NEEDS_USER_CATEGORIES = {
    "goal_change",
    "accuracy_budget",
    "irreversible_action",
    "cost_budget",
    "unresolved_dissent",
    "user_preference",
}
NEEDS_USER_STATUSES = {"needs_user", "resolved", "cancelled"}


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


def read_regular_artifact(
    value: str | Path,
    label: str,
    *,
    max_bytes: int,
    require_utf8: bool = False,
) -> tuple[Path, bytes]:
    """Read one stable regular file without following a final-component symlink."""
    source = Path(value).expanduser()
    try:
        before = os.lstat(source)
    except OSError as exc:
        raise HarnessError(f"{label} is missing or unreadable: {source}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise HarnessError(f"{label} must be a regular non-symlink file")
    if before.st_nlink != 1:
        raise HarnessError(f"{label} must not be hard-linked")
    if before.st_size <= 0 or before.st_size > max_bytes:
        raise HarnessError(f"{label} must be non-empty and at most {max_bytes} bytes")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise HarnessError(f"{label} could not be opened safely: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
        ):
            raise HarnessError(f"{label} changed while it was being opened")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(descriptor)
    if not data or len(data) > max_bytes:
        raise HarnessError(f"{label} must be non-empty and at most {max_bytes} bytes")
    if require_utf8:
        if b"\x00" in data:
            raise HarnessError(f"{label} may not contain NUL bytes")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HarnessError(f"{label} is not UTF-8: {exc}") from exc
    return source.resolve(), data


def snapshot_evidence_artifact(
    paths: HarnessPaths,
    task_id: str,
    source_value: str | Path,
    expected_sha: str,
    *,
    label: str,
    basename: str,
    max_bytes: int = TERMINAL_ARTIFACT_MAX_BYTES,
) -> dict[str, Any]:
    expected = require_text(expected_sha, f"{label} SHA-256").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise HarnessError(f"{label} SHA-256 must be full 64 hex")
    source, data = read_regular_artifact(
        source_value, label, max_bytes=max_bytes
    )
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise HarnessError(f"{label} SHA-256 mismatch")
    destination = task_dir(paths, task_id) / "results" / basename
    if destination.exists():
        raise HarnessError(f"canonical {label} snapshot already exists: {destination}")
    atomic_write_bytes(destination, data)
    os.chmod(destination, 0o600)
    return {
        "source_path": str(source),
        "path": str(destination),
        "sha256": actual,
        "size_bytes": len(data),
    }


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


def _validate_skill_canary_work_unit_binding(
    state: dict[str, Any],
    release_id: str,
    canary_event_id: str,
    *,
    require_live_canary: bool,
) -> dict[str, str] | None:
    if bool(release_id) != bool(canary_event_id):
        raise HarnessError(
            "skill canary work requires both --skill-release-id and "
            "--skill-canary-event-id"
        )
    if not release_id:
        return None
    release_id = validate_id(release_id, "skill release id")
    canary_event_id = validate_id(canary_event_id, "skill canary event id")
    releases = [
        item
        for item in state.get("skill_releases", [])
        if item.get("release_id") == release_id
    ]
    events = [
        item
        for item in state.get("skill_adoption_events", [])
        if item.get("event_id") == canary_event_id
    ]
    if len(releases) != 1 or len(events) != 1:
        raise HarnessError("skill canary work references a missing or ambiguous release/event")
    release = releases[0]
    event = events[0]
    if (
        release.get("integrity_version") != 1
        or event.get("integrity_version") != 1
        or event.get("release_id") != release_id
        or event.get("request_id") != release.get("request_id")
        or event.get("action") != "canary"
        or event.get("resulting_status") != "canary"
    ):
        raise HarnessError("skill canary work is not bound to an exact canary authority")
    if require_live_canary:
        latest_canary = [
            item
            for item in state.get("skill_adoption_events", [])
            if item.get("release_id") == release_id and item.get("action") == "canary"
        ]
        requests = [
            item
            for item in state.get("improvement_requests", [])
            if item.get("request_id") == release.get("request_id")
        ]
        if (
            not latest_canary
            or latest_canary[-1].get("event_id") != canary_event_id
            or len(requests) != 1
            or requests[0].get("status") != "canary"
            or release.get("status") != "canary"
        ):
            raise HarnessError("skill canary work requires the current live canary authority")
    return {
        "skill_release_id": release_id,
        "skill_version": str(release.get("skill_version", "")),
        "skill_canary_event_id": canary_event_id,
    }


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
    for selected_lane_id, snapshot in snapshots.items():
        lane = lane_by_id(state, selected_lane_id)
        if any(
            snapshot.get(field) != lane.get(field)
            for field in ("revision", "authority_commit", "contract_version")
        ):
            raise HarnessError(
                "execution selection is stale; select topology again before dispatch"
            )
    return selection


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


def require_root_session(
    paths: HarnessPaths, state: dict[str, Any], session_id: str
) -> str:
    session_id = check_session_id(session_id)
    if session_id not in state.get("session_ids", []):
        raise HarnessError("root arbitration requires a session bound to this task")
    mapping = load_json(session_path(paths, session_id))
    if mapping.get("task_id") != state.get("task_id"):
        raise HarnessError("root arbitration session mapping does not match this task")
    return session_id


def _hard_dependency_cycle(dependencies: list[dict[str, Any]]) -> bool:
    graph: dict[str, set[str]] = {}
    for dependency in dependencies:
        if dependency.get("kind") != "hard_gate" or dependency.get("status") == "superseded":
            continue
        source = str(dependency.get("source_lane", ""))
        target = str(dependency.get("target_lane", ""))
        graph.setdefault(source, set()).add(target)
        graph.setdefault(target, set())
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        if any(visit(target) for target in graph.get(node, set())):
            return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in sorted(graph))


def portfolio_integrity_errors(
    state: dict[str, Any], paths: HarnessPaths | None = None
) -> list[str]:
    if not any(
        key in state
        for key in (
            "lane_model_version",
            "lanes",
            "lane_dependencies",
            "coordination_requests",
            "integration_baselines",
            "capacity_reviews",
            "improvement_requests",
            "skill_releases",
            "skill_adoption_events",
            "execution_selections",
            "cross_lane_sessions",
            "needs_user_escalations",
        )
    ):
        return []
    errors: list[str] = []
    if state.get("lane_model_version") != 1:
        errors.append("lane portfolio requires lane_model_version=1")
    lanes = state.get("lanes", [])
    if not isinstance(lanes, list):
        return [*errors, "lanes must be a list"]
    lane_ids: set[str] = set()
    engaged = 0
    for lane in lanes:
        if not isinstance(lane, dict):
            errors.append("lane entry is not an object")
            continue
        lane_id = str(lane.get("lane_id", ""))
        try:
            validate_id(lane_id, "lane id")
        except HarnessError as exc:
            errors.append(str(exc))
            continue
        if lane_id in lane_ids:
            errors.append(f"duplicate lane id {lane_id}")
        lane_ids.add(lane_id)
        if lane.get("integrity_version") != 1:
            errors.append(f"lane {lane_id} lacks integrity_version=1")
        if lane.get("kind") not in LANE_KINDS:
            errors.append(f"lane {lane_id} has invalid kind {lane.get('kind')!r}")
        if lane.get("status") not in LANE_STATUSES:
            errors.append(f"lane {lane_id} has invalid status {lane.get('status')!r}")
        if lane.get("status") in ENGAGED_LANE_STATUSES:
            engaged += 1
        if not isinstance(lane.get("revision"), int) or int(lane.get("revision", 0)) < 1:
            errors.append(f"lane {lane_id} has invalid revision")
        if not FULL_COMMIT_RE.fullmatch(str(lane.get("authority_commit", ""))):
            errors.append(f"lane {lane_id} has invalid authority commit")
        for field in ("owner", "role", "contract_version", "next_action"):
            if not str(lane.get(field, "")).strip():
                errors.append(f"lane {lane_id} has empty {field}")
        revisions = lane.get("revisions", [])
        if not isinstance(revisions, list) or len(revisions) != lane.get("revision"):
            errors.append(f"lane {lane_id} revision history is not contiguous")
        elif revisions and revisions[-1].get("revision") != lane.get("revision"):
            errors.append(f"lane {lane_id} current revision differs from history tail")
    if engaged > MAX_ENGAGED_LANES:
        errors.append(
            f"engaged lane count {engaged} exceeds hard ceiling {MAX_ENGAGED_LANES}"
        )

    dependencies = state.get("lane_dependencies", [])
    if not isinstance(dependencies, list):
        errors.append("lane_dependencies must be a list")
        dependencies = []
    dependency_ids: set[str] = set()
    for dependency in dependencies:
        dependency_id = str(dependency.get("dependency_id", ""))
        if dependency_id in dependency_ids:
            errors.append(f"duplicate dependency id {dependency_id}")
        dependency_ids.add(dependency_id)
        source = dependency.get("source_lane")
        target = dependency.get("target_lane")
        if source not in lane_ids or target not in lane_ids:
            errors.append(f"dependency {dependency_id} references missing lane")
        if source == target:
            errors.append(f"dependency {dependency_id} is a self-edge")
        if dependency.get("kind") not in DEPENDENCY_KINDS:
            errors.append(f"dependency {dependency_id} has invalid kind")
        if dependency.get("status") not in DEPENDENCY_STATUSES:
            errors.append(f"dependency {dependency_id} has invalid status")
    if _hard_dependency_cycle(dependencies):
        errors.append("active hard-gate dependency graph contains a cycle")

    request_ids: set[str] = set()
    for request in state.get("coordination_requests", []):
        request_id = str(request.get("request_id", ""))
        if request_id in request_ids:
            errors.append(f"duplicate coordination request id {request_id}")
        request_ids.add(request_id)
        if request.get("source_lane") not in lane_ids or request.get("target_lane") not in lane_ids:
            errors.append(f"coordination request {request_id} references missing lane")
        if request.get("source_lane") == request.get("target_lane"):
            errors.append(f"coordination request {request_id} targets its source lane")
        if request.get("status") not in COORDINATION_STATUSES:
            errors.append(f"coordination request {request_id} has invalid status")
        if request.get("severity") not in DEPENDENCY_KINDS:
            errors.append(f"coordination request {request_id} has invalid severity")
        if not isinstance(request.get("version"), int) or int(request.get("version", 0)) < 1:
            errors.append(f"coordination request {request_id} has invalid version")
        if request.get("decision_class", "formal_technical") != "formal_technical":
            errors.append(f"coordination request {request_id} has invalid decision class")
        if request.get("closure_category", "integration_test") not in CLOSE_QUALIFYING_CATEGORIES:
            errors.append(f"coordination request {request_id} has invalid closure category")
        if request.get("status") in {"accepted", "resolved"}:
            directive_lanes = {
                item.get("target_lane") for item in request.get("directives", [])
            }
            if directive_lanes != {request.get("source_lane"), request.get("target_lane")}:
                errors.append(f"coordination request {request_id} lacks all affected-lane directives")
        if request.get("status") == "resolved":
            resolution = request.get("resolution", {})
            verifications = request.get("verification_attempts", [])
            implementations = request.get("implementation_attempts", [])
            if (
                not verifications
                or not implementations
                or verifications[-1].get("status") != "pass"
                or resolution.get("verification_id") != verifications[-1].get("verification_id")
                or resolution.get("implementation_attempt_id")
                != implementations[-1].get("attempt_id")
            ):
                errors.append(f"coordination request {request_id} resolution lacks bound verification")

    baseline_ids: set[str] = set()
    for baseline in state.get("integration_baselines", []):
        baseline_id = str(baseline.get("baseline_id", ""))
        if baseline_id in baseline_ids:
            errors.append(f"duplicate baseline id {baseline_id}")
        baseline_ids.add(baseline_id)
        if baseline.get("integrity_version") != 1:
            errors.append(f"baseline {baseline_id} lacks integrity_version=1")
        expected_baseline_sha = str(baseline.get("baseline_sha256", ""))
        baseline_payload = {
            key: value for key, value in baseline.items() if key != "baseline_sha256"
        }
        actual_baseline_sha = hashlib.sha256(
            json.dumps(
                baseline_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        if (
            not re.fullmatch(r"[0-9a-f]{64}", expected_baseline_sha)
            or expected_baseline_sha != actual_baseline_sha
        ):
            errors.append(f"baseline {baseline_id} SHA-256 identity is invalid")
        snapshots = baseline.get("lane_snapshots", [])
        if not isinstance(snapshots, list) or not snapshots:
            errors.append(f"baseline {baseline_id} has no lane snapshots")
    reviews = state.get("capacity_reviews", [])
    if not isinstance(reviews, list):
        errors.append("capacity_reviews must be a list")
        reviews = []
    if reviews and state.get("capacity_planning_version") != 1:
        errors.append("capacity reviews require capacity_planning_version=1")
    review_ids: set[str] = set()
    for review in reviews:
        review_id = str(review.get("review_id", ""))
        if review_id in review_ids:
            errors.append(f"duplicate capacity review id {review_id}")
        review_ids.add(review_id)
        if review.get("integrity_version") != 1:
            errors.append(f"capacity review {review_id} lacks integrity_version=1")
        if review.get("status") not in {
            "data_ready",
            "awaiting_chief",
            "approved",
            "rejected",
            "distributed",
            "acknowledged",
            "consumed",
            "superseded",
        }:
            errors.append(f"capacity review {review_id} has invalid status")
        if not isinstance(review.get("version"), int) or int(review.get("version", 0)) < 1:
            errors.append(f"capacity review {review_id} has invalid version")
        dataset = review.get("dataset", {})
        dataset_path = Path(str(dataset.get("path", "")))
        dataset_sha = str(dataset.get("sha256", ""))
        if (
            not dataset_path.is_file()
            or dataset_path.is_symlink()
            or not re.fullmatch(r"[0-9a-f]{64}", dataset_sha)
        ):
            errors.append(f"capacity review {review_id} dataset identity is missing")
        elif sha256_file(dataset_path) != dataset_sha:
            errors.append(f"capacity review {review_id} dataset SHA-256 mismatch")
        if review.get("catalog_version") != CAPABILITY_CATALOG_VERSION:
            errors.append(f"capacity review {review_id} catalog version is unsupported")
        recommendation = review.get("recommendation")
        if recommendation is not None and (
            recommendation.get("capability_tier") not in CAPABILITY_TIER_MAP
            or CAPABILITY_TIER_MAP.get(recommendation.get("capability_tier"))
            != recommendation.get("requested_model_tier")
        ):
            errors.append(f"capacity review {review_id} recommendation is inconsistent")
        if review.get("status") in {"approved", "distributed", "acknowledged", "consumed"}:
            decision = review.get("chief_decision", {})
            if decision.get("decision") != "approved" or not decision.get("root_session_id"):
                errors.append(f"capacity review {review_id} lacks chief approval")
        if review.get("status") in {"distributed", "acknowledged", "consumed"} and not review.get(
            "distribution"
        ):
            errors.append(f"capacity review {review_id} lacks steward distribution")
        if review.get("status") in {"acknowledged", "consumed"} and not review.get(
            "acknowledgement"
        ):
            errors.append(f"capacity review {review_id} lacks target acknowledgement")
        if review.get("status") == "consumed" and not review.get("consumption"):
            errors.append(f"capacity review {review_id} lacks packet consumption")

    improvements = state.get("improvement_requests", [])
    releases = state.get("skill_releases", [])
    adoption_events = state.get("skill_adoption_events", [])
    if any((improvements, releases, adoption_events)) and state.get("improvement_model_version") != 1:
        errors.append("improvement records require improvement_model_version=1")
    if not isinstance(improvements, list):
        errors.append("improvement_requests must be a list")
        improvements = []
    if not isinstance(releases, list):
        errors.append("skill_releases must be a list")
        releases = []
    if not isinstance(adoption_events, list):
        errors.append("skill_adoption_events must be a list")
        adoption_events = []
    improvement_ids: set[str] = set()
    for request in improvements:
        request_id = str(request.get("request_id", ""))
        if request_id in improvement_ids:
            errors.append(f"duplicate improvement request id {request_id}")
        improvement_ids.add(request_id)
        if request.get("integrity_version") != 1:
            errors.append(f"improvement request {request_id} lacks integrity_version=1")
        if request.get("status") not in IMPROVEMENT_STATUSES:
            errors.append(f"improvement request {request_id} has invalid status")
        if request.get("trigger_class") not in IMPROVEMENT_TRIGGER_CLASSES:
            errors.append(f"improvement request {request_id} has invalid trigger class")
        occurrences = request.get("occurrences", [])
        if (
            not isinstance(occurrences, list)
            or not occurrences
            or request.get("occurrence_fingerprint") != _records_fingerprint(occurrences)
        ):
            errors.append(f"improvement request {request_id} occurrence identity is invalid")
        if not isinstance(request.get("version"), int) or int(request.get("version", 0)) < 1:
            errors.append(f"improvement request {request_id} has invalid version")
        if request.get("status") not in {"submitted", "awaiting_chief"} and not request.get(
            "chief_decision"
        ):
            errors.append(f"improvement request {request_id} lacks chief decision")
    release_ids: set[str] = set()
    for release in releases:
        release_id = str(release.get("release_id", ""))
        if release_id in release_ids:
            errors.append(f"duplicate skill release id {release_id}")
        release_ids.add(release_id)
        if release.get("request_id") not in improvement_ids:
            errors.append(f"skill release {release_id} references missing improvement request")
        for path_field, sha_field in (
            ("bundle_path", "bundle_sha256"),
            ("manifest_path", "manifest_sha256"),
            ("validation_path", "validation_sha256"),
        ):
            artifact_path = Path(str(release.get(path_field, "")))
            artifact_sha = str(release.get(sha_field, ""))
            if (
                not artifact_path.is_file()
                or artifact_path.is_symlink()
                or not re.fullmatch(r"[0-9a-f]{64}", artifact_sha)
                or sha256_file(artifact_path) != artifact_sha
            ):
                errors.append(f"skill release {release_id} {path_field} identity is invalid")
        errors.extend(_skill_release_semantic_integrity_errors(state, release, paths))
    event_ids: set[str] = set()
    for event in adoption_events:
        event_id = str(event.get("event_id", ""))
        if event_id in event_ids:
            errors.append(f"duplicate skill adoption event id {event_id}")
        event_ids.add(event_id)
        if event.get("release_id") not in release_ids:
            errors.append(f"skill adoption event {event_id} references missing release")
        evidence_path = Path(str(event.get("evidence_path", "")))
        evidence_sha = str(event.get("evidence_sha256", ""))
        if (
            not evidence_path.is_file()
            or evidence_path.is_symlink()
            or not re.fullmatch(r"[0-9a-f]{64}", evidence_sha)
            or sha256_file(evidence_path) != evidence_sha
        ):
            errors.append(f"skill adoption event {event_id} evidence identity is invalid")
        errors.extend(_skill_adoption_semantic_integrity_errors(state, event))

    selections = state.get("execution_selections", [])
    cross_sessions = state.get("cross_lane_sessions", [])
    escalations = state.get("needs_user_escalations", [])
    if any((selections, cross_sessions, escalations)) and state.get("execution_model_version") != 1:
        errors.append("execution governance records require execution_model_version=1")
    selection_ids: set[str] = set()
    active_work_units: set[str] = set()
    for selection in selections:
        selection_id = str(selection.get("selection_id", ""))
        if selection_id in selection_ids:
            errors.append(f"duplicate execution selection id {selection_id}")
        selection_ids.add(selection_id)
        status = selection.get("status")
        work_unit_id = str(selection.get("work_unit_id", ""))
        try:
            validate_id(work_unit_id, "execution work-unit id")
        except HarnessError as exc:
            errors.append(f"execution selection {selection_id}: {exc}")
        if status not in {"active", "superseded"}:
            errors.append(f"execution selection {selection_id} has invalid status")
        if status == "active":
            if work_unit_id in active_work_units:
                errors.append(
                    f"multiple active execution selections exist for work unit {work_unit_id}"
                )
            active_work_units.add(work_unit_id)
            if selection.get("superseded_by"):
                errors.append(
                    f"active execution selection {selection_id} unexpectedly names a successor"
                )
        if status == "superseded" and not selection.get("superseded_by"):
            errors.append(
                f"superseded execution selection {selection_id} lacks successor identity"
            )
        mode = selection.get("mode")
        snapshots = selection.get("lane_snapshots", [])
        if mode not in EXECUTION_MODES:
            errors.append(f"execution selection {selection_id} has invalid mode")
        if mode == "single" and len(snapshots) != 1:
            errors.append(f"execution selection {selection_id} single mode is not one lane")
        if mode in {"centralized_parallel", "hybrid"} and len(snapshots) < 2:
            errors.append(f"execution selection {selection_id} parallel mode lacks lanes")
        snapshot_lane_ids = [str(item.get("lane_id", "")) for item in snapshots]
        if len(snapshot_lane_ids) != len(set(snapshot_lane_ids)):
            errors.append(f"execution selection {selection_id} repeats a lane snapshot")
        for snapshot in snapshots:
            if snapshot.get("lane_id") not in lane_ids:
                errors.append(f"execution selection {selection_id} references missing lane")
        if selection.get("root_session_id") not in state.get("session_ids", []):
            errors.append(f"execution selection {selection_id} lacks task-bound Chief session")
    for selection in selections:
        successor = selection.get("superseded_by")
        if successor and successor not in selection_ids:
            errors.append(
                f"execution selection {selection.get('selection_id')} references missing successor"
            )
    active_selection_ids = {
        str(item.get("selection_id"))
        for item in selections
        if item.get("status") == "active"
    }
    selection_by_id = {
        str(item.get("selection_id")): item for item in selections
    }
    for record_kind, records, active_statuses, identity_field in (
        ("packet", state.get("packets", []), ACTIVE_PACKET_STATUSES, "packet_id"),
        ("job", state.get("jobs", []), ACTIVE_JOB_STATUSES, "run_id"),
    ):
        for record in records:
            selection_id = str(record.get("execution_selection_id", ""))
            if selection_id and selection_id not in selection_ids:
                errors.append(
                    f"{record_kind} {record.get(identity_field)} references missing execution selection"
                )
                continue
            if (
                active_selection_ids
                and record.get("status") in active_statuses
                and not selection_id
            ):
                errors.append(
                    f"active {record_kind} {record.get(identity_field)} lacks execution selection binding"
                )
                continue
            if selection_id:
                if (
                    record.get("status") in active_statuses
                    and selection_id not in active_selection_ids
                ):
                    errors.append(
                        f"active {record_kind} {record.get(identity_field)} is bound to "
                        "a non-active execution selection"
                    )
                selection_lane_ids = {
                    str(item.get("lane_id"))
                    for item in selection_by_id[selection_id].get("lane_snapshots", [])
                }
                if record.get("lane_id") not in selection_lane_ids:
                    errors.append(
                        f"{record_kind} {record.get(identity_field)} lane is outside its execution selection"
                    )
            try:
                binding = _validate_skill_canary_work_unit_binding(
                    state,
                    str(record.get("skill_release_id", "")),
                    str(record.get("skill_canary_event_id", "")),
                    require_live_canary=False,
                )
                if binding is not None and any(
                    record.get(field) != binding.get(field)
                    for field in (
                        "skill_release_id",
                        "skill_version",
                        "skill_canary_event_id",
                    )
                ):
                    errors.append(
                        f"{record_kind} {record.get(identity_field)} lost its exact skill canary binding"
                    )
            except HarnessError as exc:
                errors.append(f"{record_kind} {record.get(identity_field)}: {exc}")
            if record_kind == "job":
                errors.extend(_job_launch_authority_errors(state, record))
    cross_ids: set[str] = set()
    for item in cross_sessions:
        cross_id = str(item.get("cross_lane_session_id", ""))
        if cross_id in cross_ids:
            errors.append(f"duplicate cross-lane session id {cross_id}")
        cross_ids.add(cross_id)
        if item.get("status") not in CROSS_LANE_SESSION_STATUSES:
            errors.append(f"cross-lane session {cross_id} has invalid status")
        if item.get("execution_selection_id") not in selection_ids:
            errors.append(f"cross-lane session {cross_id} references missing selection")
        elif item.get("status") == "open" and item.get(
            "execution_selection_id"
        ) not in active_selection_ids:
            errors.append(
                f"open cross-lane session {cross_id} is bound to a non-active selection"
            )
        if item.get("request_id") not in request_ids:
            errors.append(f"cross-lane session {cross_id} references missing request")
        if item.get("status") == "closed" and not item.get("closure"):
            errors.append(f"cross-lane session {cross_id} lacks steward closure")
    escalation_ids: set[str] = set()
    for item in escalations:
        escalation_id = str(item.get("escalation_id", ""))
        if escalation_id in escalation_ids:
            errors.append(f"duplicate needs-user escalation id {escalation_id}")
        escalation_ids.add(escalation_id)
        if item.get("status") not in NEEDS_USER_STATUSES:
            errors.append(f"needs-user escalation {escalation_id} has invalid status")
        if item.get("category") not in NEEDS_USER_CATEGORIES:
            errors.append(f"needs-user escalation {escalation_id} has invalid category")
        if item.get("source_lane_id") not in lane_ids:
            errors.append(f"needs-user escalation {escalation_id} references missing lane")
        if item.get("request_id") and item.get("request_id") not in request_ids:
            errors.append(f"needs-user escalation {escalation_id} references missing request")
        if item.get("status") == "resolved" and not item.get("user_disposition"):
            errors.append(f"needs-user escalation {escalation_id} lacks user disposition")
    return errors


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


def git_metadata(worktree: Path) -> dict[str, str]:
    resolved = worktree.resolve()
    if not resolved.is_dir():
        raise HarnessError(f"worktree does not exist: {resolved}")

    def run(*arguments: str) -> str:
        try:
            result = subprocess.run(
                ["git", "-C", str(resolved), *arguments],
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HarnessError(f"Git metadata command failed: {exc}") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise HarnessError(
                f"Git metadata command failed ({' '.join(arguments)}): {detail or 'unknown error'}"
            )
        return result.stdout.strip()

    top = run("rev-parse", "--show-toplevel")
    if Path(top).resolve() != resolved:
        raise HarnessError(
            f"--worktree must be the Git worktree root, got {resolved} (root is {top})"
        )
    head_sha = run("rev-parse", "HEAD").lower()
    if not FULL_COMMIT_RE.fullmatch(head_sha):
        raise HarnessError(f"Git worktree has no valid HEAD commit: {head_sha!r}")
    branch = run("branch", "--show-current") or "detached"
    return {
        "worktree": str(resolved),
        "branch": branch,
        "head_sha": head_sha,
    }


def git_is_ancestor(worktree: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(worktree), "merge-base", "--is-ancestor", ancestor, descendant],
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if result.returncode not in {0, 1}:
        detail = (result.stderr or result.stdout).strip()
        raise HarnessError(f"Git ancestry check failed: {detail or result.returncode}")
    return result.returncode == 0


def resolve_task_commit(state: dict[str, Any], value: str, label: str) -> str:
    requested = require_full_commit(value, label)
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(Path(state.get("worktree", "")).resolve()),
                "rev-parse",
                f"{requested}^{{commit}}",
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HarnessError(f"could not resolve {label}: {exc}") from exc
    resolved = result.stdout.strip().lower()
    if result.returncode != 0 or not FULL_COMMIT_RE.fullmatch(resolved):
        raise HarnessError(f"{label} is not a commit in the task worktree")
    if resolved != requested:
        raise HarnessError(f"{label} must name the exact full commit, got {resolved}")
    return resolved


def referenced_claims(paths: HarnessPaths, state: dict[str, Any]) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for token in state.get("claims", []):
        active = claim_path(paths, str(token), active=True)
        archived = claim_path(paths, str(token), active=False)
        candidates = [path for path in (active, archived) if path.exists()]
        if len(candidates) != 1:
            raise HarnessError(
                f"task {state.get('task_id')} claim {token} has {len(candidates)} canonical records"
            )
        claims.append(load_claim_file(candidates[0]))
    return claims


def validate_mini_locks(raw_locks: Iterable[str]) -> list[str]:
    locks = list(dict.fromkeys(normalize_lock(item) for item in raw_locks))
    if not 1 <= len(locks) <= MINI_MAX_LOCKS:
        raise HarnessError(f"mini task requires 1-{MINI_MAX_LOCKS} unique exact file locks")
    for lock in locks:
        namespace, kind, raw_path = parse_lock(lock)
        if namespace not in {"repo", "host"} or kind != "file":
            raise HarnessError("mini task accepts only exact repo:file or host:file locks")
        if namespace == "repo" and any(
            raw_path == prefix.rstrip("/") or raw_path.startswith(prefix)
            for prefix in MINI_FORBIDDEN_REPO_PREFIXES
        ):
            raise HarnessError(f"mini task may not own high-risk path: {raw_path}")
        if namespace == "host" and raw_path.casefold().endswith("/.codex/hooks.json"):
            raise HarnessError("mini task may not change trusted hook definitions")
    return locks


def state_worktree(paths: HarnessPaths, state: dict[str, Any]) -> Path:
    return Path(state.get("worktree") or paths.root).resolve()


def worktree_integrity_errors(
    paths: HarnessPaths, state: dict[str, Any]
) -> tuple[list[str], dict[str, str] | None]:
    try:
        current = git_metadata(state_worktree(paths, state))
    except HarnessError as exc:
        return [str(exc)], None
    errors: list[str] = []
    if current["worktree"] != str(state.get("worktree", "")):
        errors.append(
            f"recorded worktree {state.get('worktree')!r} differs from {current['worktree']!r}"
        )
    if current["branch"] != state.get("branch"):
        errors.append(
            f"task branch changed from {state.get('branch')!r} to {current['branch']!r}"
        )
    if not FULL_COMMIT_RE.fullmatch(str(state.get("head_sha", ""))):
        errors.append("task starting HEAD is missing or invalid")
    return errors, current


def legacy_ambiguities(
    paths: HarnessPaths, *, ignore_token: str | None = None
) -> list[dict[str, Any]]:
    ambiguous: list[dict[str, Any]] = []
    for pending in sorted(paths.legacy_pending.glob("*.json")):
        claim = load_claim_file(pending)
        if claim.get("token") == ignore_token:
            continue
        if claim.get("scope_parse_warnings"):
            ambiguous.append(
                {
                    "token": claim.get("token"),
                    "owner": claim.get("owner"),
                    "raw_scope": claim.get("raw_scope"),
                    "warnings": claim.get("scope_parse_warnings"),
                    "locks": claim.get("locks", []),
                    "source_file": claim.get("source_file"),
                    "source_line": claim.get("source_line"),
                    "pending_file": str(pending),
                }
            )
    return ambiguous


def packet_integrity_errors(paths: HarnessPaths, state: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for packet in state.get("packets", []):
        packet_id = str(packet.get("packet_id", ""))
        mode = packet.get("packet_mode", "legacy")
        locks = packet.get("locks", [])
        if mode == "read_only" and locks:
            errors.append(f"packet {packet_id} read_only mode has mutation locks")
        if mode in {"bounded_mutation", "exact_command"} and not locks:
            errors.append(f"packet {packet_id} {mode} mode lacks mutation authority")
        for artifact in packet.get("input_artifact_refs", []):
            artifact_path = Path(str(artifact.get("path", "")))
            artifact_sha = str(artifact.get("sha256", ""))
            if (
                not artifact_path.is_file()
                or artifact_path.is_symlink()
                or not re.fullmatch(r"[0-9a-f]{64}", artifact_sha)
                or sha256_file(artifact_path) != artifact_sha
            ):
                errors.append(f"packet {packet_id} input artifact is missing or tampered")
        command_error = packet_command_integrity_error(packet)
        if command_error:
            errors.append(command_error)
        status = packet.get("status")
        if status not in PACKET_STATUSES:
            errors.append(f"packet {packet_id} has invalid status {status!r}")
            continue
        if status == "dispatched" and not packet.get("agent_id"):
            errors.append(f"packet {packet_id} is dispatched without an agent id")
        if status in TERMINAL_PACKET_STATUSES:
            expected_path = task_dir(paths, state["task_id"]) / "results" / f"{packet_id}.md"
            recorded_path = Path(str(packet.get("result_path", "")))
            if recorded_path != expected_path:
                errors.append(f"packet {packet_id} result path is not canonical")
                continue
            if packet.get("integrity_version") != 1:
                errors.append(f"packet {packet_id} result lacks explicit integrity attestation")
                continue
            if not expected_path.is_file():
                errors.append(f"packet {packet_id} result file is missing")
                continue
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


def _require_done_reviewer_packet(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet_id: str,
    *,
    required_artifact_shas: set[str] | None = None,
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


def validate_source_receipt(
    source: Path,
    expected_sha: str,
    *,
    tool_path: str,
    tool_version: str,
    command: str,
) -> dict[str, Any]:
    if not source.is_file():
        raise HarnessError(f"source receipt does not exist: {source}")
    actual_sha = sha256_file(source)
    if actual_sha != expected_sha:
        raise HarnessError(
            f"source receipt SHA-256 mismatch: expected {expected_sha}, actual {actual_sha}"
        )
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HarnessError(f"source receipt is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("receipt_version") != 1:
        raise HarnessError("source receipt must be an object with receipt_version=1")
    require_text(str(payload.get("source_set_id", "")), "source receipt source_set_id")
    require_text(str(payload.get("producer", "")), "source receipt producer")
    tool = payload.get("tool")
    if not isinstance(tool, dict):
        raise HarnessError("source receipt requires a tool object")
    expected_tool = {"path": tool_path, "version": tool_version, "command": command}
    if {key: tool.get(key) for key in expected_tool} != expected_tool:
        raise HarnessError("source receipt tool path/version/command differ from job arguments")
    components = payload.get("components")
    if not isinstance(components, dict):
        raise HarnessError("source receipt requires a components object")
    for component_name in RECEIPT_COMPONENTS:
        component = components.get(component_name)
        if not isinstance(component, dict):
            raise HarnessError(f"source receipt component {component_name!r} is missing")
        status = component.get("status")
        if status == "not_applicable":
            require_text(
                str(component.get("reason", "")),
                f"source receipt {component_name} not_applicable reason",
            )
            continue
        if status != "included":
            raise HarnessError(
                f"source receipt component {component_name!r} must be included or not_applicable"
            )
        files = component.get("files")
        if not isinstance(files, list) or not files:
            raise HarnessError(f"source receipt component {component_name!r} has no files")
        for entry in files:
            if not isinstance(entry, dict):
                raise HarnessError(f"source receipt {component_name} entry is not an object")
            entry_path = require_absolute_posix(
                str(entry.get("path", "")), f"source receipt {component_name} path"
            )
            entry_sha = str(entry.get("sha256", "")).lower()
            if not re.fullmatch(r"[0-9a-f]{64}", entry_sha):
                raise HarnessError(
                    f"source receipt {component_name} entry has invalid SHA-256: {entry_path}"
                )
    for required_included in ("rtl", "runner"):
        if components[required_included].get("status") != "included":
            raise HarnessError(f"source receipt component {required_included!r} must be included")
    return payload


def job_integrity_errors(paths: HarnessPaths, state: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for job in state.get("jobs", []):
        run_id = str(job.get("run_id", ""))
        status = job.get("status")
        if status not in JOB_STATUSES:
            errors.append(f"job {run_id} has invalid status {status!r}")
            continue
        if job.get("integrity_version") != 1:
            errors.append(f"job {run_id} lacks integrity_version=1")
        if job.get("job_schema_version") == 2:
            command_path = Path(str(job.get("command_path", "")))
            command_sha = str(job.get("command_sha256", ""))
            if not command_path.is_file():
                errors.append(f"job {run_id} command snapshot is missing")
            elif not re.fullmatch(r"[0-9a-f]{64}", command_sha):
                errors.append(f"job {run_id} command snapshot SHA-256 is invalid")
            elif (
                sha256_file(command_path) != command_sha
                or command_path.stat().st_size != job.get("command_size_bytes")
                or command_path.read_text(encoding="utf-8") != str(job.get("command", ""))
            ):
                errors.append(f"job {run_id} command snapshot identity mismatch")
        expected_receipt_path = (
            task_dir(paths, state["task_id"]) / "results" / f"source-receipt-{run_id}.json"
        )
        receipt_path = Path(str(job.get("source_receipt_path", "")))
        receipt_sha = str(job.get("source_sha", ""))
        if receipt_path != expected_receipt_path:
            errors.append(f"job {run_id} source receipt path is not canonical")
        elif not receipt_path.is_file():
            errors.append(f"job {run_id} source receipt snapshot is missing")
        elif not re.fullmatch(r"[0-9a-f]{64}", receipt_sha):
            errors.append(f"job {run_id} source receipt SHA-256 is invalid")
        elif sha256_file(receipt_path) != receipt_sha:
            errors.append(f"job {run_id} source receipt SHA-256 mismatch")
        else:
            try:
                validate_source_receipt(
                    receipt_path,
                    receipt_sha,
                    tool_path=str(job.get("tool_path", "")),
                    tool_version=str(job.get("tool_version", "")),
                    command=str(job.get("command", "")),
                )
            except HarnessError as exc:
                errors.append(f"job {run_id} source receipt is invalid: {exc}")
        if status == "running" and not (job.get("pid") or job.get("tmux")):
            errors.append(f"job {run_id} is running without pid or tmux identity")
        if status in {"pass", "fail", "stopped"}:
            if not job.get("evidence") or job.get("exit_code") is None:
                errors.append(f"terminal job {run_id} lacks evidence/exit code")
            if status == "pass" and job.get("exit_code") != job.get("success_exit_code", 0):
                errors.append(f"passing job {run_id} does not match its success exit code")
            if job.get("job_schema_version") == 2:
                expected_manifest = (
                    task_dir(paths, state["task_id"])
                    / "results"
                    / f"terminal-artifacts-{run_id}.json"
                )
                manifest_path = Path(str(job.get("terminal_manifest_path", "")))
                manifest_sha = str(job.get("terminal_manifest_sha256", ""))
                if manifest_path != expected_manifest or not manifest_path.is_file():
                    errors.append(f"terminal job {run_id} artifact manifest is missing/non-canonical")
                elif not re.fullmatch(r"[0-9a-f]{64}", manifest_sha):
                    errors.append(f"terminal job {run_id} artifact manifest SHA-256 is invalid")
                elif sha256_file(manifest_path) != manifest_sha:
                    errors.append(f"terminal job {run_id} artifact manifest SHA-256 mismatch")
                else:
                    try:
                        manifest = load_json(manifest_path)
                        artifact = manifest.get("artifact", {})
                        if status == "pass" and job.get(
                            "launch_authority_version"
                        ) == 1:
                            launch_events = job.get("launch_authority_events", [])
                            expected_launch_sha = (
                                launch_events[-1].get("authority_sha256", "")
                                if launch_events
                                else ""
                            )
                            if (
                                not expected_launch_sha
                                or manifest.get("launch_authority_sha256")
                                != expected_launch_sha
                            ):
                                errors.append(
                                    f"passing job {run_id} terminal manifest lost launch authority"
                                )
                        blob_path = Path(str(artifact.get("blob_path", "")))
                        if artifact.get("capture_status") == "preserved":
                            if not blob_path.is_file() or blob_path.is_symlink():
                                errors.append(
                                    f"terminal job {run_id} preserved artifact blob is missing/non-regular"
                                )
                            elif (
                                sha256_file(blob_path) != artifact.get("sha256")
                                or blob_path.stat().st_size != artifact.get("size_bytes")
                            ):
                                errors.append(
                                    f"terminal job {run_id} preserved artifact blob identity mismatch"
                                )
                    except HarnessError as exc:
                        errors.append(f"terminal job {run_id} manifest is invalid: {exc}")
                if status == "pass" and job.get("terminal_artifact_status") != "preserved":
                    errors.append(f"passing job {run_id} lacks a preserved primary terminal log")
    return errors


def verification_integrity_errors(state: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for index, item in enumerate(state.get("verification", []), start=1):
        label = f"verification #{index}"
        if item.get("integrity_version") != 1:
            errors.append(f"{label} lacks integrity_version=1")
            continue
        if item.get("category") not in VERIFICATION_CATEGORIES:
            errors.append(f"{label} has unknown category {item.get('category')!r}")
        if item.get("status") not in VERIFICATION_STATUSES:
            errors.append(f"{label} has invalid status {item.get('status')!r}")
        if not str(item.get("evidence", "")).strip():
            errors.append(f"{label} has empty evidence")
        if not str(item.get("boundary", "")).strip():
            errors.append(f"{label} has empty evidence boundary")
        if item.get("status") in {"pass", "fail"} and not str(
            item.get("command", "")
        ).strip():
            errors.append(f"{label} pass/fail record has empty command or method")
        if item.get("category") == "independent_review" and any(
            item.get(field)
            for field in (
                "review_packet_id",
                "review_result_sha256",
                "reviewer_agent_id",
            )
        ):
            try:
                validate_id(
                    str(item.get("review_packet_id", "")),
                    "independent review packet id",
                )
            except HarnessError as exc:
                errors.append(f"{label} {exc}")
            if not re.fullmatch(
                r"[0-9a-f]{64}", str(item.get("review_result_sha256", ""))
            ):
                errors.append(f"{label} lacks reviewer result SHA-256")
            if not str(item.get("reviewer_agent_id", "")).strip():
                errors.append(f"{label} lacks reviewer agent identity")
        for artifact in item.get("artifact_refs", []):
            path = Path(str(artifact.get("path", "")))
            digest = str(artifact.get("sha256", ""))
            if (
                not path.is_file()
                or path.is_symlink()
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or sha256_file(path) != digest
            ):
                errors.append(f"{label} artifact reference is missing or tampered")
    return errors


def remote_ref_tip(worktree: Path, remote: str, remote_ref: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", remote):
        raise HarnessError(f"invalid Git remote name: {remote!r}")
    if not re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]+", remote_ref) or ".." in remote_ref:
        raise HarnessError(f"--remote-ref must be a full refs/heads/... ref: {remote_ref!r}")
    try:
        result = subprocess.run(
            ["git", "-C", str(worktree), "ls-remote", "--exit-code", remote, remote_ref],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HarnessError(f"could not verify pushed remote ref: {exc}") from exc
    if result.returncode != 0:
        raise HarnessError(
            "could not verify pushed remote ref: "
            + ((result.stderr or result.stdout).strip() or "ref not found")
        )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise HarnessError(f"expected exactly one remote ref result, got {len(lines)}")
    tip = lines[0].split()[0].lower()
    if not FULL_COMMIT_RE.fullmatch(tip):
        raise HarnessError(f"remote ref returned invalid commit id: {tip!r}")
    return tip


def delivery_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    verify_remote: bool,
) -> list[str]:
    delivery = state.get("delivery", {})
    mode = delivery.get("mode")
    errors: list[str] = []
    if mode not in DELIVERY_MODES:
        return [f"invalid delivery mode {mode!r}"]
    if mode in {"pending", "blocked"}:
        return [f"delivery mode {mode} cannot satisfy an achieved close"]
    if not str(delivery.get("detail", "")).strip():
        errors.append("delivery detail is empty")
    if mode == "none" and state.get("changed_files"):
        errors.append("delivery mode none conflicts with recorded changed files")
    if mode != "pushed":
        return errors
    commit = str(delivery.get("commit", "")).lower()
    remote = str(delivery.get("remote", ""))
    remote_ref = str(delivery.get("remote_ref", ""))
    remote_sha = str(delivery.get("remote_sha", "")).lower()
    if not FULL_COMMIT_RE.fullmatch(commit):
        errors.append("pushed delivery commit is missing or invalid")
        return errors
    worktree_errors, current = worktree_integrity_errors(paths, state)
    errors.extend(worktree_errors)
    if current is None:
        return errors
    terminal = state.get("status") in {"done", "cancelled"}
    if terminal:
        try:
            commit_is_ancestor = git_is_ancestor(
                state_worktree(paths, state), commit, current["head_sha"]
            )
        except HarnessError as exc:
            errors.append(str(exc))
        else:
            if not commit_is_ancestor:
                errors.append(
                    f"pushed delivery commit {commit} is not an ancestor of the "
                    f"terminal task worktree HEAD {current['head_sha']}"
                )
    elif current["head_sha"] != commit:
        errors.append(
            f"pushed delivery commit {commit} is not the task worktree HEAD {current['head_sha']}"
        )
    if remote_sha != commit:
        errors.append("recorded pushed remote SHA differs from delivery commit")
    if not remote or not remote_ref or not delivery.get("verified_at"):
        errors.append("pushed delivery lacks remote/ref verification receipt")
        return errors
    if verify_remote:
        try:
            actual_tip = remote_ref_tip(state_worktree(paths, state), remote, remote_ref)
        except HarnessError as exc:
            errors.append(str(exc))
        else:
            expected_tip = current["head_sha"] if terminal else commit
            if actual_tip != expected_tip:
                errors.append(
                    f"remote {remote} {remote_ref} points to {actual_tip}, "
                    f"not the {'terminal task worktree HEAD' if terminal else 'delivery commit'} "
                    f"{expected_tip}"
                )
    return errors


def plan_path(paths: HarnessPaths, state: dict[str, Any]) -> Path:
    return task_dir(paths, state["task_id"]) / "plan.md"


def plan_digest(paths: HarnessPaths, state: dict[str, Any]) -> str:
    path = plan_path(paths, state)
    if not path.is_file():
        raise HarnessError(f"plan file is missing: {path}")
    return sha256_file(path)


def require_plan_ready(paths: HarnessPaths, state: dict[str, Any], action: str) -> None:
    if not state.get("plan_ready"):
        raise HarnessError(f"cannot {action}; approve the task plan first")
    expected = state.get("plan_sha256")
    actual = plan_digest(paths, state)
    if expected != actual:
        raise HarnessError(
            f"cannot {action}; plan changed after approval (expected {expected}, actual {actual})"
        )


def require_absolute_posix(value: str, label: str) -> str:
    cleaned = require_text(value, label)
    path = PurePosixPath(cleaned)
    if not path.is_absolute() or ".." in path.parts or "\\" in cleaned:
        raise HarnessError(f"{label} must be an absolute normalized POSIX path: {value!r}")
    return path.as_posix()


def commit_checkpoint(paths: HarnessPaths, state: dict[str, Any]) -> Path:
    destination, text, digest = prepare_checkpoint(paths, state)
    # Safe order: a crash after the file write leaves old state marked stale;
    # state is never allowed to claim a checkpoint that was not written.
    atomic_write_text(destination, text)
    state["checkpoint_sha256"] = digest
    write_task(paths, state)
    return destination


def template_text(paths: HarnessPaths, name: str, fallback: str) -> str:
    source = paths.templates / name
    return source.read_text(encoding="utf-8") if source.exists() else fallback


def substitute(template: str, values: dict[str, str]) -> str:
    for key, value in values.items():
        template = template.replace("{{" + key + "}}", value)
    return template


def check_session_id(session_id: str) -> str:
    if not session_id or len(session_id) > 512 or "\x00" in session_id:
        raise HarnessError("session id must be 1-512 characters and contain no NUL")
    return session_id


def bind_session_unlocked(
    paths: HarnessPaths,
    state: dict[str, Any],
    session_id: str,
    *,
    bump: bool,
    force: bool = False,
) -> None:
    check_session_id(session_id)
    destination = session_path(paths, session_id)
    if destination.exists():
        current = load_json(destination)
        if current.get("task_id") != state["task_id"] and not force:
            raise HarnessError(
                f"session is already bound to task {current.get('task_id')}; use --force only after auditing"
            )
        if current.get("task_id") != state["task_id"] and force:
            old_task_id = str(current.get("task_id", ""))
            try:
                old_state = load_task(paths, old_task_id)
            except HarnessError:
                old_state = None
            if old_state and old_state.get("status") in {"active", "blocked"}:
                old_state["session_ids"] = [
                    item for item in old_state.get("session_ids", []) if item != session_id
                ]
                bump_task(old_state)
                write_task(paths, old_state)
    mapping = {
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id,
        "task_id": state["task_id"],
        "checkpoint_path": str(task_dir(paths, state["task_id"]) / "checkpoint.md"),
        "updated_at": now_iso(),
    }
    atomic_write_json(destination, mapping)
    session_ids = state.setdefault("session_ids", [])
    if session_id not in session_ids:
        session_ids.append(session_id)
        if bump:
            bump_task(state)
    if bump:
        write_task(paths, state)


def unbind_all_sessions_unlocked(paths: HarnessPaths, state: dict[str, Any]) -> None:
    for session_id in state.get("session_ids", []):
        destination = session_path(paths, session_id)
        if not destination.exists():
            continue
        try:
            mapping = load_json(destination)
        except HarnessError:
            continue
        if mapping.get("task_id") == state["task_id"]:
            destination.unlink()


def cmd_unbind_session(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        session_id = check_session_id(args.session_id)
        destination = session_path(paths, session_id)
        mapping = load_json(destination)
        task_id = str(mapping.get("task_id", ""))
        if args.task and args.task != task_id:
            raise HarnessError(
                f"session maps to {task_id}, not the requested task {args.task}"
            )
        state = load_task(paths, task_id)
        destination.unlink()
        if state.get("status") in {"active", "blocked"}:
            state["session_ids"] = [
                item for item in state.get("session_ids", []) if item != session_id
            ]
            bump_task(state)
            write_task(paths, state)
        write_index(paths)
    emit({"session_id": session_id, "task_id": task_id, "unbound": True}, args.json)
    return 0


def cmd_init_task(args: argparse.Namespace, paths: HarnessPaths) -> int:
    task_id = validate_id(args.task_id, "task id")
    title = require_text(args.title, "title")
    objective = require_text(args.objective, "objective")
    owner = require_text(args.owner, "owner")
    completion = require_text(args.completion_boundary, "completion boundary")
    metadata = git_metadata(Path(args.worktree) if args.worktree else paths.root)
    with state_lock(paths):
        destination = task_state_path(paths, task_id)
        if destination.exists():
            raise HarnessError(f"task already exists: {task_id}")
        created = now_iso()
        state: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "task_id": task_id,
            "profile": "full",
            "title": title,
            "objective": objective,
            "owner": owner,
            "status": "active",
            "phase": "planning",
            "revision": 1,
            "checkpoint_revision": 0,
            "checkpoint_required": True,
            "checkpoint_sha256": "",
            "created_at": created,
            "updated_at": created,
            "outcome": "in_progress",
            "completion_boundary": completion,
            "next_action": args.next_action or "Complete the plan and acquire minimum claims.",
            "claims": [],
            "session_ids": [],
            "packets": [],
            "facts": [],
            "decisions": [],
            "rejected_paths": [],
            "changed_files": [],
            "verification": [],
            "jobs": [],
            "blockers": [],
            "risks": [],
            "delivery": {"mode": "pending", "detail": "", "commit": ""},
            "plan_ready": False,
            "plan_sha256": "",
            **metadata,
        }
        directory = task_dir(paths, task_id)
        (directory / "packets").mkdir(parents=True, exist_ok=True)
        (directory / "results").mkdir(parents=True, exist_ok=True)
        plan = substitute(
            template_text(paths, "plan.md", PLAN_FALLBACK),
            {
                "TASK_ID": task_id,
                "TITLE": title,
                "OWNER": owner,
                "OBJECTIVE": objective,
                "COMPLETION_BOUNDARY": completion,
            },
        )
        atomic_write_text(directory / "plan.md", plan)
        checkpoint, checkpoint_text, _ = prepare_checkpoint(paths, state)
        atomic_write_text(checkpoint, checkpoint_text)
        write_task(paths, state)
        if args.session_id:
            bind_session_unlocked(paths, state, args.session_id, bump=False)
            write_task(paths, state)
        write_index(paths)
    emit(
        {
            "task_id": task_id,
            "plan": str(directory / "plan.md"),
            "checkpoint": str(directory / "checkpoint.md"),
            "checkpoint_required": True,
            "plan_ready": False,
        },
        args.json,
    )
    return 0


def cmd_start_mini(args: argparse.Namespace, paths: HarnessPaths) -> int:
    task_id = validate_id(args.task_id, "task id")
    token = validate_id(args.token, "claim token")
    session_id = check_session_id(args.session_id)
    locks = validate_mini_locks(args.lock)
    title = require_text(args.title, "title")
    objective = require_text(args.objective, "objective")
    owner = require_text(args.owner, "owner")
    completion = require_text(args.completion_boundary, "completion boundary")
    intent = require_text(args.intent, "intent")
    validation = require_text(args.validation, "validation")
    metadata = git_metadata(Path(args.worktree) if args.worktree else paths.root)
    lock_lines = "\n".join(f"- `{lock}`" for lock in locks)
    plan = (
        f"# Mini Plan — {task_id}\n\n"
        f"- Title: {title}\n- Owner: {owner}\n- Objective: {objective}\n"
        f"- Completion boundary: {completion}\n\n"
        "## Exact write scope\n\n"
        f"{lock_lines}\n\n"
        "## Intent and verification\n\n"
        f"- Intent: {intent}\n- Validation: {validation}\n\n"
        "## Fixed exclusions\n\n"
        "- No RTL, EDA, tree locks, delegation packets, or additional claims.\n"
        "- Normal verification, delivery, checkpoint, release, and close gates remain required.\n"
    )
    timestamp = now_iso()
    with state_lock(paths):
        if task_state_path(paths, task_id).exists():
            raise HarnessError(f"task already exists: {task_id}")
        if claim_path(paths, token, active=True).exists() or claim_path(
            paths, token, active=False
        ).exists():
            raise HarnessError(f"claim token already exists: {token}")
        if session_path(paths, session_id).exists():
            raise HarnessError("mini task requires an unbound, non-corrupt session")
        ambiguous = legacy_ambiguities(paths)
        if ambiguous:
            raise HarnessError(
                "unresolved ambiguous legacy scope(s) block mini ownership:\n"
                + json.dumps(ambiguous, indent=2, ensure_ascii=False)
            )
        conflicts = find_conflicts(paths, locks)
        if conflicts:
            raise HarnessError(
                "mini claim conflict(s):\n" + json.dumps(conflicts, indent=2, ensure_ascii=False)
            )
        baselines = baselines_for_locks(paths, locks, repo_root=Path(metadata["worktree"]))
        state: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "task_id": task_id,
            "profile": "mini",
            "title": title,
            "objective": objective,
            "owner": owner,
            "status": "active",
            "phase": "implementing",
            "revision": 1,
            "checkpoint_revision": 0,
            "checkpoint_required": True,
            "checkpoint_sha256": "",
            "created_at": timestamp,
            "updated_at": timestamp,
            "outcome": "in_progress",
            "completion_boundary": completion,
            "next_action": args.next_action or "Perform the exact mini edit and verification.",
            "claims": [token],
            "session_ids": [session_id],
            "packets": [],
            "facts": ["Mini lifecycle atomically initialized, approved, bound, and claimed."],
            "decisions": [],
            "rejected_paths": [],
            "changed_files": [],
            "verification": [],
            "jobs": [],
            "blockers": [],
            "risks": [],
            "delivery": {"mode": "pending", "detail": "", "commit": ""},
            "plan_ready": True,
            "plan_sha256": hashlib.sha256(plan.encode("utf-8")).hexdigest(),
            "plan_approved_at": timestamp,
            "plan_approval_note": "Atomic constrained mini lifecycle",
            **metadata,
        }
        claim = {
            "schema_version": SCHEMA_VERSION,
            "legacy": False,
            "source": "structured",
            "token": token,
            "task_id": task_id,
            "owner": owner,
            "kind": "MINI",
            "locks": locks,
            "intent": intent,
            "validation": validation,
            "status": "active",
            "created_at": timestamp,
            "updated_at": timestamp,
            "expires_at": args.expires_at,
            "worktree": metadata["worktree"],
            "baselines": baselines,
        }
        directory = task_dir(paths, task_id)
        (directory / "packets").mkdir(parents=True, exist_ok=False)
        (directory / "results").mkdir(parents=True, exist_ok=False)
        atomic_write_text(directory / "plan.md", plan)
        checkpoint, checkpoint_text, _ = prepare_checkpoint(paths, state)
        atomic_write_text(checkpoint, checkpoint_text)
        write_task(paths, state)
        atomic_write_json(claim_path(paths, token, active=True), claim)
        atomic_write_json(
            session_path(paths, session_id),
            {
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id,
                "task_id": task_id,
                "checkpoint_path": str(checkpoint),
                "updated_at": timestamp,
            },
        )
        write_index(paths)
    emit(
        {
            "task_id": task_id,
            "profile": "mini",
            "plan_ready": True,
            "claim": token,
            "locks": locks,
            "session_id": session_id,
        },
        args.json,
    )
    return 0


def cmd_approve_plan(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "approve plan for")
        source = plan_path(paths, state)
        text = source.read_text(encoding="utf-8")
        unresolved = [
            marker
            for marker in ("Replace this line", "[TODO", "{{TASK_ID}}", "{{OBJECTIVE}}")
            if marker in text
        ]
        if unresolved:
            raise HarnessError(
                "plan still contains unresolved template markers: " + ", ".join(unresolved)
            )
        if len(text.strip()) < 400:
            raise HarnessError("plan is too short; record evidence, work breakdown, and verification")
        if not state.get("worktree"):
            state.update(git_metadata(paths.root))
        digest = sha256_file(source)
        state["plan_ready"] = True
        state["plan_sha256"] = digest
        state["plan_approved_at"] = now_iso()
        state["plan_approval_note"] = require_text(args.note, "approval note")
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit({"task_id": args.task, "plan_sha256": digest, "plan_ready": True}, args.json)
    return 0


def cmd_bind_session(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "bind session to")
        bind_session_unlocked(paths, state, args.session_id, bump=True, force=args.force)
        write_index(paths)
    emit(
        {
            "session_id": args.session_id,
            "task_id": args.task,
            "checkpoint_required": bool(state.get("checkpoint_required")),
            "revision": state.get("revision"),
        },
        args.json,
    )
    return 0


def cmd_import_legacy(args: argparse.Namespace, paths: HarnessPaths) -> int:
    source = Path(args.source).resolve() if args.source else paths.root / "notes" / "SESSION_CONTROL.md"
    with state_lock(paths):
        result = import_legacy(paths, source)
        write_index(paths)
    emit(result, args.json)
    return 0


def cmd_check_locks(args: argparse.Namespace, paths: HarnessPaths) -> int:
    locks = list(dict.fromkeys(normalize_lock(item) for item in args.lock))
    conflicts = find_conflicts(paths, locks, ignore_token=args.ignore_token)
    ambiguous = legacy_ambiguities(paths, ignore_token=args.ignore_token)
    payload = {
        "ok": not conflicts and not ambiguous,
        "requested_locks": locks,
        "conflicts": conflicts,
        "ambiguous_legacy_rows": ambiguous,
        "note": (
            "Any partially unparsed non-terminal legacy scope blocks new ownership. "
            "Audit the named token or explicitly adopt that same token with evidence."
        ),
    }
    emit(payload, args.json)
    return 0 if payload["ok"] else 1


def cmd_inspect_legacy(args: argparse.Namespace, paths: HarnessPaths) -> int:
    pending = legacy_pending_path(paths, args.token)
    claim = load_claim_file(pending)
    emit(claim, True if args.json else False)
    return 0


def cmd_claim(args: argparse.Namespace, paths: HarnessPaths) -> int:
    token = validate_id(args.token, "claim token")
    locks = list(dict.fromkeys(normalize_lock(item) for item in args.lock))
    if not locks:
        raise HarnessError("at least one --lock is required")
    with state_lock(paths):
        state = load_task(paths, args.task)
        if state["status"] not in {"active", "blocked"}:
            raise HarnessError(f"cannot add claim to task in status {state['status']}")
        if state.get("profile") == "mini":
            raise HarnessError("mini task may not acquire additional claims")
        require_plan_ready(paths, state, "acquire claim")
        active_path = claim_path(paths, token, active=True)
        archived_path = claim_path(paths, token, active=False)
        if active_path.exists() or archived_path.exists():
            raise HarnessError(f"claim token already exists: {token}")
        pending_legacy_path = legacy_pending_path(paths, token)
        legacy_claim = (
            load_claim_file(pending_legacy_path) if pending_legacy_path.exists() else None
        )
        if legacy_claim and not args.adopt_legacy:
            raise HarnessError(
                f"claim token collides with legacy token {token}; use explicit "
                "--adopt-legacy plus --adoption-evidence after auditing owner/scope/jobs"
            )
        if args.adopt_legacy:
            if not legacy_claim:
                raise HarnessError(f"no pending legacy claim exists for token {token}")
            evidence = require_text(args.adoption_evidence or "", "adoption evidence")
            if not legacy_claim.get("locks"):
                raise HarnessError(
                    "legacy scope has no machine-parseable locks; audit/release it and use a new token"
                )
            if legacy_claim.get("scope_parse_warnings") and not args.ack_legacy_ambiguity:
                raise HarnessError(
                    "legacy scope has unparsed components; inspect the row and pass "
                    "--ack-legacy-ambiguity only when adoption evidence covers them"
                )
            uncovered = [
                held
                for held in legacy_claim.get("locks", [])
                if not any(lock_covers(proposed, held) for proposed in locks)
            ]
            if uncovered:
                raise HarnessError(
                    "structured adoption must cover every parsed legacy lock; uncovered: "
                    + ", ".join(uncovered)
                )
        elif args.adoption_evidence:
            raise HarnessError("--adoption-evidence requires --adopt-legacy")
        elif args.ack_legacy_ambiguity:
            raise HarnessError("--ack-legacy-ambiguity requires --adopt-legacy")
        ambiguous = legacy_ambiguities(
            paths,
            ignore_token=(
                token if args.adopt_legacy and args.ack_legacy_ambiguity else None
            ),
        )
        if ambiguous:
            raise HarnessError(
                "unresolved ambiguous legacy scope(s) block new ownership:\n"
                + json.dumps(ambiguous, indent=2, ensure_ascii=False)
            )
        conflicts = find_conflicts(
            paths, locks, ignore_token=token if args.adopt_legacy else None
        )
        if conflicts:
            raise HarnessError(
                "claim conflict(s):\n" + json.dumps(conflicts, indent=2, ensure_ascii=False)
            )
        timestamp = now_iso()
        claim = {
            "schema_version": SCHEMA_VERSION,
            "legacy": False,
            "source": "structured",
            "token": token,
            "task_id": state["task_id"],
            "owner": require_text(args.owner, "owner"),
            "kind": require_text(args.kind, "kind"),
            "locks": locks,
            "intent": require_text(args.intent, "intent"),
            "validation": require_text(args.validation, "validation"),
            "status": "active",
            "created_at": timestamp,
            "updated_at": timestamp,
            "expires_at": args.expires_at,
            "worktree": state.get("worktree"),
            "baselines": baselines_for_locks(
                paths, locks, repo_root=state_worktree(paths, state)
            ),
        }
        atomic_write_json(active_path, claim)
        if token not in state["claims"]:
            state["claims"].append(token)
        bump_task(state)
        write_task(paths, state)
        if legacy_claim:
            record_legacy_decision(
                paths,
                token,
                "adopted_structured",
                f"task={state['task_id']}; owner={args.owner}; evidence={evidence}; "
                f"legacy_locks={legacy_claim.get('locks', [])}; new_locks={locks}",
            )
            pending_legacy_path.unlink()
        write_index(paths)
    emit(claim, args.json)
    return 0


def cmd_set_claim_status(args: argparse.Namespace, paths: HarnessPaths) -> int:
    if args.status not in RESERVING_CLAIM_STATUSES:
        raise HarnessError("set-claim-status accepts active or blocked only")
    with state_lock(paths):
        source = claim_path(paths, args.token, active=True)
        claim = load_claim_file(source)
        state = load_task(paths, claim["task_id"])
        claim["status"] = args.status
        claim["status_reason"] = require_text(args.reason, "reason")
        claim["updated_at"] = now_iso()
        atomic_write_json(source, claim)
        state = load_task(paths, claim["task_id"])
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit({"token": args.token, "status": args.status}, args.json)
    return 0


def uncovered_dependencies_after_release(
    paths: HarnessPaths,
    state: dict[str, Any],
    token: str,
) -> list[str]:
    remaining_locks = [
        lock
        for claim in claims_owned_by_task(paths, state["task_id"])
        if claim.get("token") != token
        and claim.get("status") in RESERVING_CLAIM_STATUSES
        for lock in claim.get("locks", [])
    ]
    dependencies: list[tuple[str, str]] = []
    for packet in state.get("packets", []):
        if packet.get("status") in ACTIVE_PACKET_STATUSES:
            dependencies.extend(
                (f"packet {packet.get('packet_id')}", lock)
                for lock in packet.get("locks", [])
            )
    for job in state.get("jobs", []):
        if job.get("status") in ACTIVE_JOB_STATUSES:
            work_root = job.get("work_root")
            log = job.get("log")
            if work_root:
                dependencies.append(
                    (f"job {job.get('run_id')}", f"eda:tree:{work_root}")
                )
            if log:
                dependencies.append((f"job {job.get('run_id')}", f"eda:file:{log}"))
    return [
        f"{owner} requires {lock}"
        for owner, lock in dependencies
        if not any(lock_covers(held, lock) for held in remaining_locks)
    ]


def cmd_release_claim(args: argparse.Namespace, paths: HarnessPaths) -> int:
    if args.status not in TERMINAL_CLAIM_STATUSES:
        raise HarnessError("release status must be done, released, or stale")
    with state_lock(paths):
        source = claim_path(paths, args.token, active=True)
        claim = load_claim_file(source)
        state = load_task(paths, claim["task_id"])
        uncovered = uncovered_dependencies_after_release(
            paths, state, str(claim.get("token"))
        )
        if uncovered:
            raise HarnessError(
                "cannot release claim while active work depends on its locks:\n- "
                + "\n- ".join(uncovered)
            )
        claim["status"] = args.status
        claim["close_reason"] = require_text(args.reason, "reason")
        claim["updated_at"] = now_iso()
        claim["final_baselines"] = baselines_for_locks(
            paths,
            claim.get("locks", []),
            repo_root=state_worktree(paths, state),
        )
        changed: dict[str, bool] = {}
        for lock, baseline in claim.get("baselines", {}).items():
            changed[lock] = baseline != claim["final_baselines"].get(lock)
        claim["baseline_changed"] = changed
        destination = claim_path(paths, args.token, active=False)
        # Fail-safe ordering: make the task stale before copying/unlinking the
        # reserving claim. A crash may leave duplicate records, never an early
        # lock release.
        bump_task(state)
        write_task(paths, state)
        atomic_write_json(destination, claim)
        source.unlink()
        write_index(paths)
    emit(
        {"token": args.token, "status": args.status, "baseline_changed": changed},
        args.json,
    )
    return 0


def cmd_audit_legacy(args: argparse.Namespace, paths: HarnessPaths) -> int:
    pending = legacy_pending_path(paths, args.token)
    with state_lock(paths):
        claim = load_claim_file(pending)
        detail = require_text(args.detail, "detail")
        if args.decision == "still-active":
            record_legacy_decision(paths, args.token, "still-active", detail)
            claim["legacy_classification"] = "confirmed_active"
            claim["audit_detail"] = detail
            claim["updated_at"] = now_iso()
            atomic_write_json(pending, claim)
        else:
            record_legacy_decision(paths, args.token, args.decision, detail)
            pending.unlink()
        write_index(paths)
    emit({"token": args.token, "decision": args.decision}, args.json)
    return 0


def cmd_set_phase(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "change phase for")
        state["phase"] = args.phase
        if args.task_status:
            state["status"] = args.task_status
            if args.task_status == "active":
                state["outcome"] = "in_progress"
        if args.summary:
            state.setdefault("facts", []).append(args.summary)
        if args.next_action:
            state["next_action"] = args.next_action
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(task_summary(state), args.json)
    return 0


def cmd_adopt_current_branch(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "adopt current branch for")
        require_plan_ready(paths, state, "adopt current branch")
        checkpoint_ok, checkpoint_reason = checkpoint_matches(paths, state)
        if not checkpoint_ok:
            raise HarnessError(
                "branch adoption requires a current pre-adoption checkpoint: "
                + checkpoint_reason
            )
        if state.get("delivery", {}).get("mode") == "pushed":
            raise HarnessError("cannot adopt a branch after pushed delivery is recorded")
        active_jobs = [
            str(job.get("run_id"))
            for job in state.get("jobs", [])
            if job.get("status") in ACTIVE_JOB_STATUSES
        ]
        if active_jobs:
            raise HarnessError(
                "cannot adopt branch while jobs are active: " + ", ".join(active_jobs)
            )
        worktree = state_worktree(paths, state)
        current = git_metadata(worktree)
        if current["worktree"] != str(state.get("worktree", "")):
            raise HarnessError("task worktree path changed; branch adoption cannot repair it")
        if current["branch"] == "detached":
            raise HarnessError("cannot adopt a detached HEAD")
        old_branch = str(state.get("branch", ""))
        if current["branch"] == old_branch:
            emit(
                {"task_id": args.task, "branch": old_branch, "changed": False},
                args.json,
            )
            return 0
        start_head = str(state.get("head_sha", ""))
        if not FULL_COMMIT_RE.fullmatch(start_head) or not git_is_ancestor(
            worktree, start_head, current["head_sha"]
        ):
            raise HarnessError(
                f"recorded starting HEAD {start_head!r} is not an ancestor of "
                f"current HEAD {current['head_sha']}"
            )
        required_lock = normalize_lock(f"git:merge:{current['branch']}")
        reserving = [
            claim
            for claim in claims_owned_by_task(paths, state["task_id"])
            if claim.get("status") in RESERVING_CLAIM_STATUSES
        ]
        owners = [
            str(claim.get("token"))
            for claim in reserving
            if any(lock_covers(lock, required_lock) for lock in claim.get("locks", []))
        ]
        if len(owners) != 1:
            raise HarnessError(
                f"branch adoption requires exactly one reserving owner of {required_lock}; "
                f"found {owners}"
            )
        reason = require_text(args.reason, "branch adoption reason")
        adoption = {
            "old_branch": old_branch,
            "new_branch": current["branch"],
            "starting_head": start_head,
            "current_head": current["head_sha"],
            "claim_token": owners[0],
            "reason": reason,
            "adopted_at": now_iso(),
        }
        state.setdefault("branch_adoptions", []).append(adoption)
        state["branch"] = current["branch"]
        state.setdefault("facts", []).append(
            f"Adopted current branch {current['branch']} from {old_branch}; "
            f"starting HEAD ancestry and {required_lock} ownership verified."
        )
        state.setdefault("decisions", []).append(reason)
        if args.next_action:
            state["next_action"] = require_text(args.next_action, "next action")
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit({"task_id": args.task, "changed": True, **adoption}, args.json)
    return 0


def _extend_unique(state: dict[str, Any], key: str, values: Iterable[str]) -> None:
    destination = state.setdefault(key, [])
    for value in values:
        cleaned = value.strip()
        if cleaned and cleaned not in destination:
            destination.append(cleaned)


def cmd_checkpoint(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "checkpoint")
        _extend_unique(state, "facts", args.fact)
        _extend_unique(state, "decisions", args.decision)
        _extend_unique(state, "rejected_paths", args.rejected)
        _extend_unique(state, "changed_files", args.changed_file)
        _extend_unique(state, "blockers", args.blocker)
        _extend_unique(state, "risks", args.risk)
        if args.next_action:
            state["next_action"] = args.next_action
        if state["status"] in {"active", "blocked"} and not state.get("next_action"):
            raise HarnessError("active checkpoint requires an exact next action")
        bump_task(state, checkpoint_required=False)
        state["checkpoint_revision"] = state["revision"]
        state["checkpoint_required"] = False
        checkpoint = commit_checkpoint(paths, state)
        write_index(paths)
    emit(
        {
            "task_id": state["task_id"],
            "revision": state["revision"],
            "checkpoint": str(checkpoint),
        },
        args.json,
    )
    return 0


def _engaged_capacity_lane(state: dict[str, Any], lane_id: str) -> dict[str, Any]:
    lane = lane_by_id(state, lane_id)
    if lane.get("kind") != "capacity_planning" or lane.get("status") not in ENGAGED_LANE_STATUSES:
        raise HarnessError("capacity review requires an engaged capacity_planning lane")
    return lane


def _capacity_records(
    state: dict[str, Any], target_lane_id: str, task_type: str
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for packet in state.get("packets", []):
        if (
            packet.get("lane_id") != target_lane_id
            or packet.get("task_type") != task_type
            or packet.get("status") not in TERMINAL_PACKET_STATUSES
        ):
            continue
        records.append(
            {
                "packet_id": packet.get("packet_id"),
                "status": packet.get("status"),
                "requested_role": packet.get("agent_role"),
                "requested_model_tier": packet.get("model_tier"),
                "actual_role": packet.get("actual_role")
                if packet.get("routing_verified")
                else "unavailable",
                "actual_model_tier": packet.get("actual_model_tier")
                if packet.get("routing_verified")
                else "unavailable",
                "routing_verified": bool(packet.get("routing_verified")),
                "retry_of_packet_id": packet.get("retry_of_packet_id", ""),
                "result_sha256": packet.get("result_sha256", ""),
                "orchestration_started_at": packet.get("dispatched_at", ""),
                "orchestration_completed_at": packet.get("completed_at", ""),
                "token_usage": "unavailable",
                "cost": "unavailable",
                "engineering_acceptance": "not_inferred_from_packet_status",
            }
        )
    records.sort(key=lambda item: str(item["packet_id"]))
    return records


def _records_fingerprint(records: list[dict[str, Any]]) -> str:
    return hashlib.sha256(
        json.dumps(
            records, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


def cmd_capacity_snapshot(args: argparse.Namespace, paths: HarnessPaths) -> int:
    review_id = validate_id(args.review_id, "capacity review id")
    task_type = validate_id(args.task_type, "capacity task type")
    if args.leaf_role not in DEPTH_TWO_ROLES:
        raise HarnessError("capacity review leaf role must be batch, explorer, or worker")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "snapshot capacity data for")
        require_plan_ready(paths, state, "snapshot capacity data")
        if any(review.get("review_id") == review_id for review in state.get("capacity_reviews", [])):
            raise HarnessError(f"capacity review already exists: {review_id}")
        capacity_lane = _engaged_capacity_lane(state, args.capacity_lane_id)
        steward = _engaged_steward_lane(state)
        target = lane_by_id(state, args.target_lane_id)
        if target.get("revision") != args.expected_lane_revision:
            raise HarnessError("capacity target lane revision CAS failed")
        records = _capacity_records(state, target["lane_id"], task_type)
        dataset_payload = {
            "dataset_version": 1,
            "task_id": state["task_id"],
            "review_id": review_id,
            "steward_lane_id": steward["lane_id"],
            "steward_lane_revision": steward["revision"],
            "capacity_lane_id": capacity_lane["lane_id"],
            "capacity_lane_revision": capacity_lane["revision"],
            "target_lane_id": target["lane_id"],
            "target_lane_revision": target["revision"],
            "task_type": task_type,
            "leaf_role": args.leaf_role,
            "records": records,
            "token_usage": "unavailable",
            "cost": "unavailable",
        }
        dataset_path = (
            task_dir(paths, args.task) / "results" / f"capacity-dataset-{review_id}.json"
        )
        atomic_write_json(dataset_path, dataset_payload)
        dataset_sha = sha256_file(dataset_path)
        recorded = now_iso()
        review = {
            "integrity_version": 1,
            "review_id": review_id,
            "version": 1,
            "status": "data_ready",
            "scope": {
                "target_lane_id": target["lane_id"],
                "target_lane_revision": target["revision"],
                "authority_commit": target["authority_commit"],
                "contract_version": target["contract_version"],
                "task_type": task_type,
                "leaf_role": args.leaf_role,
                "target_depth": 2,
            },
            "capacity_lane_id": capacity_lane["lane_id"],
            "capacity_lane_revision": capacity_lane["revision"],
            "steward_lane_id": steward["lane_id"],
            "steward_lane_revision": steward["revision"],
            "catalog_version": CAPABILITY_CATALOG_VERSION,
            "plan_sha256": state.get("plan_sha256"),
            "dataset": {
                "path": str(dataset_path),
                "sha256": dataset_sha,
                "record_count": len(records),
                "fingerprint": _records_fingerprint(records),
                "cutoff_at": recorded,
            },
            "recommendation": None,
            "chief_decision": None,
            "distribution": None,
            "acknowledgement": None,
            "consumption": None,
            "created_at": recorded,
            "updated_at": recorded,
        }
        state["capacity_planning_version"] = 1
        state.setdefault("capacity_reviews", []).append(review)
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(review, args.json)
    return 0


def cmd_capacity_recommend(args: argparse.Namespace, paths: HarnessPaths) -> int:
    if args.capability_tier not in CAPABILITY_TIER_MAP:
        raise HarnessError("unknown capability tier")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "record capacity recommendation for")
        review = capacity_review_by_id(state, args.review_id)
        if review.get("version") != args.expected_version or review.get("status") != "data_ready":
            raise HarnessError("capacity recommendation CAS/status gate failed")
        dataset = review.get("dataset", {})
        dataset_path = Path(str(dataset.get("path", "")))
        if not dataset_path.is_file() or sha256_file(dataset_path) != dataset.get("sha256"):
            raise HarnessError("capacity dataset is missing or tampered")
        if int(dataset.get("record_count", 0)) < 1:
            raise HarnessError("capacity recommendation requires at least one verified task-type record")
        matches = [
            packet
            for packet in state.get("packets", [])
            if packet.get("packet_id") == args.source_packet_id
        ]
        if len(matches) != 1:
            raise HarnessError("capacity source packet does not exist")
        source_packet = matches[0]
        if (
            source_packet.get("status") != "done"
            or source_packet.get("lane_id") != review.get("capacity_lane_id")
            or not source_packet.get("result_sha256")
            or source_packet.get("capacity_review_source_id") != review["review_id"]
            or not any(
                ref.get("path") == dataset.get("path")
                and ref.get("sha256") == dataset.get("sha256")
                for ref in source_packet.get("input_artifact_refs", [])
            )
        ):
            raise HarnessError(
                "capacity recommendation requires a done source packet bound to this review dataset"
            )
        source_result = Path(str(source_packet.get("result_path", "")))
        expected_source_result = (
            task_dir(paths, args.task) / "results" / f"{source_packet['packet_id']}.md"
        )
        if (
            source_result != expected_source_result
            or not source_result.is_file()
            or source_result.is_symlink()
            or sha256_file(source_result) != source_packet.get("result_sha256")
        ):
            raise HarnessError("capacity recommendation source result is missing or tampered")
        review["version"] = int(review["version"]) + 1
        review["status"] = "awaiting_chief"
        review["recommendation"] = {
            "capability_tier": args.capability_tier,
            "requested_model_tier": CAPABILITY_TIER_MAP[args.capability_tier],
            "rationale": require_evidence_detail(args.rationale, "capacity rationale"),
            "risk": require_evidence_detail(args.risk, "capacity risk"),
            "confidence_boundary": require_evidence_detail(
                args.confidence_boundary, "capacity confidence boundary"
            ),
            "source_packet_id": source_packet["packet_id"],
            "source_result_sha256": source_packet["result_sha256"],
        }
        review["updated_at"] = now_iso()
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(review, args.json)
    return 0


def cmd_capacity_arbitrate(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "arbitrate capacity recommendation for")
        if any(
            item.get("status") == "needs_user"
            for item in state.get("needs_user_escalations", [])
        ):
            raise HarnessError(
                "unresolved needs-user escalation blocks capacity arbitration"
            )
        review = capacity_review_by_id(state, args.review_id)
        if review.get("version") != args.expected_version or review.get("status") != "awaiting_chief":
            raise HarnessError("capacity arbitration CAS/status gate failed")
        session_id = require_root_session(paths, state, args.session_id)
        recorded = now_iso()
        decision_id = f"{review['review_id']}-chief-1"
        review["version"] = int(review["version"]) + 1
        review["status"] = "approved" if args.decision == "approved" else "rejected"
        review["chief_decision"] = {
            "decision_id": decision_id,
            "decision": args.decision,
            "rationale": require_evidence_detail(args.rationale, "capacity chief rationale"),
            "root_owner": state.get("owner"),
            "root_session_id": session_id,
            "recorded_at": recorded,
        }
        review["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(review, args.json)
    return 0


def cmd_capacity_distribute(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "distribute capacity decision for")
        review = capacity_review_by_id(state, args.review_id)
        if review.get("version") != args.expected_version or review.get("status") != "approved":
            raise HarnessError("capacity distribution CAS/status gate failed")
        steward = _engaged_steward_lane(state)
        if steward.get("lane_id") != args.steward_lane_id:
            raise HarnessError("capacity decision must be distributed by the engaged steward")
        review["version"] = int(review["version"]) + 1
        review["status"] = "distributed"
        review["distribution"] = {
            "steward_lane_id": steward["lane_id"],
            "decision_id": review["chief_decision"]["decision_id"],
            "recorded_at": now_iso(),
        }
        review["updated_at"] = review["distribution"]["recorded_at"]
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(review, args.json)
    return 0


def cmd_capacity_ack(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "acknowledge capacity decision for")
        review = capacity_review_by_id(state, args.review_id)
        if review.get("version") != args.expected_version or review.get("status") != "distributed":
            raise HarnessError("capacity acknowledgement CAS/status gate failed")
        scope = review["scope"]
        if args.actor_lane != scope["target_lane_id"]:
            raise HarnessError("only the target department lane may acknowledge capacity")
        target = lane_by_id(state, args.actor_lane)
        if (
            target.get("revision") != scope["target_lane_revision"]
            or target.get("authority_commit") != scope["authority_commit"]
            or target.get("contract_version") != scope["contract_version"]
        ):
            raise HarnessError("capacity recommendation is stale against target lane authority")
        review["version"] = int(review["version"]) + 1
        review["status"] = "acknowledged"
        review["acknowledgement"] = {
            "actor_lane": args.actor_lane,
            "evidence": require_evidence_detail(args.evidence, "capacity acknowledgement"),
            "recorded_at": now_iso(),
        }
        review["updated_at"] = review["acknowledgement"]["recorded_at"]
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(review, args.json)
    return 0


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


def _resolve_improvement_occurrence(state: dict[str, Any], reference: str) -> dict[str, Any]:
    kind, separator, identifier = require_text(reference, "improvement occurrence").partition(":")
    if not separator or not identifier:
        raise HarnessError("improvement occurrence must use kind:identifier")
    if kind == "packet":
        matches = [
            item for item in state.get("packets", []) if item.get("packet_id") == identifier
        ]
        if len(matches) != 1 or matches[0].get("status") not in TERMINAL_PACKET_STATUSES:
            raise HarnessError(f"improvement occurrence {reference} is not a terminal packet")
        item = matches[0]
        identity = item.get("result_sha256")
        lane_id = item.get("lane_id", "")
        status = item.get("status")
        completed_at = item.get("completed_at") or item.get("updated_at")
    elif kind == "job":
        matches = [item for item in state.get("jobs", []) if item.get("run_id") == identifier]
        if len(matches) != 1 or matches[0].get("status") in ACTIVE_JOB_STATUSES:
            raise HarnessError(f"improvement occurrence {reference} is not a terminal job")
        item = matches[0]
        identity = item.get("terminal_manifest_sha256") or item.get("source_sha")
        lane_id = item.get("lane_id", "")
        status = item.get("status")
        completed_at = item.get("updated_at")
    elif kind == "verification":
        try:
            index = int(identifier)
            item = state.get("verification", [])[index]
        except (ValueError, IndexError) as exc:
            raise HarnessError(f"improvement occurrence {reference} does not exist") from exc
        if item.get("integrity_version") != 1:
            raise HarnessError(f"improvement occurrence {reference} lacks integrity")
        identity = hashlib.sha256(
            json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
        ).hexdigest()
        lane_id = item.get("lane_id", "")
        status = item.get("status")
        completed_at = item.get("recorded_at")
    elif kind == "coordination":
        item = coordination_by_id(state, identifier)
        identity = hashlib.sha256(
            json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
        ).hexdigest()
        lane_id = item.get("source_lane", "")
        status = item.get("status")
        completed_at = item.get("updated_at")
    elif kind == "capacity":
        item = capacity_review_by_id(state, identifier)
        identity = item.get("dataset", {}).get("sha256")
        lane_id = item.get("scope", {}).get("target_lane_id", "")
        status = item.get("status")
        completed_at = item.get("updated_at")
    else:
        raise HarnessError(
            "improvement occurrence kind must be packet, job, verification, coordination, or capacity"
        )
    if not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{64}", identity):
        raise HarnessError(f"improvement occurrence {reference} lacks a durable identity")
    return {
        "reference": reference,
        "kind": kind,
        "identifier": identifier,
        "lane_id": lane_id,
        "identity_sha256": identity,
        "status": status,
        "completed_at": completed_at,
        "skill_release_id": item.get("skill_release_id", ""),
        "skill_version": item.get("skill_version", ""),
        "skill_canary_event_id": item.get("skill_canary_event_id", ""),
    }


def _resolve_adoption_work_units(
    state: dict[str, Any],
    references: Any,
    *,
    label: str,
    minimum: int,
    canary_recorded_at: str,
    require_after_canary: bool,
    expected_skill_release_id: str = "",
    expected_skill_version: str = "",
    expected_canary_event_id: str = "",
) -> list[dict[str, Any]]:
    if (
        not isinstance(references, list)
        or len(references) < minimum
        or not all(isinstance(item, str) and item.strip() for item in references)
        or len(references) != len(set(references))
    ):
        raise HarnessError(
            f"{label} requires at least {minimum} distinct durable work-unit references"
        )
    bindings = [_resolve_improvement_occurrence(state, item) for item in references]
    if len({item["identity_sha256"] for item in bindings}) != len(bindings):
        raise HarnessError(f"{label} work units must have distinct durable identities")
    success_status = {
        "packet": "done",
        "job": "pass",
        "verification": "pass",
        "coordination": "resolved",
    }
    for item in bindings:
        expected = success_status.get(item["kind"])
        if expected is None or item.get("status") != expected:
            raise HarnessError(
                f"{label} reference {item['reference']} is not a successful work unit"
            )
        completed = parse_time(str(item.get("completed_at", "")))
        canary_time = parse_time(canary_recorded_at)
        if completed is None or canary_time is None:
            raise HarnessError(f"{label} work unit lacks a comparable completion time")
        if require_after_canary and completed <= canary_time:
            raise HarnessError(
                f"{label} reference {item['reference']} does not postdate the bound canary"
            )
        if not require_after_canary and completed >= canary_time:
            raise HarnessError(
                f"{label} reference {item['reference']} is not a pre-canary baseline"
            )
        if require_after_canary and (
            item.get("kind") not in {"packet", "job"}
            or item.get("skill_release_id") != expected_skill_release_id
            or item.get("skill_version") != expected_skill_version
            or item.get("skill_canary_event_id") != expected_canary_event_id
        ):
            raise HarnessError(
                f"{label} reference {item['reference']} is not bound to the exact skill canary"
            )
    return bindings


def _parse_improvement_options(values: Iterable[str]) -> list[dict[str, str]]:
    parsed: dict[str, str] = {}
    for value in values:
        option_id, separator, description = value.partition("=")
        option_id = validate_id(option_id, "improvement option id")
        if not separator:
            raise HarnessError("improvement option must use option-id=description")
        if option_id in parsed:
            raise HarnessError(f"duplicate improvement option id {option_id}")
        parsed[option_id] = require_evidence_detail(
            description, f"improvement option {option_id}"
        )
    if set(parsed) != IMPROVEMENT_OPTION_IDS:
        raise HarnessError(
            "improvement brief must compare maintain-current, capacity, and skill-automation"
        )
    return [
        {"option_id": option_id, "description": parsed[option_id]}
        for option_id in sorted(parsed)
    ]


def cmd_improvement_create(args: argparse.Namespace, paths: HarnessPaths) -> int:
    request_id = validate_id(args.request_id, "improvement request id")
    task_type = validate_id(args.task_type, "improvement task type")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "submit improvement request for")
        require_plan_ready(paths, state, "submit improvement request")
        if any(
            request.get("request_id") == request_id
            for request in state.get("improvement_requests", [])
        ):
            raise HarnessError(f"improvement request already exists: {request_id}")
        source_lane = lane_by_id(state, args.source_lane)
        steward = _engaged_steward_lane(state)
        occurrences = [_resolve_improvement_occurrence(state, item) for item in args.occurrence]
        references = [item["reference"] for item in occurrences]
        if len(references) != len(set(references)):
            raise HarnessError("improvement occurrences must be distinct")
        if args.trigger_class == "repeated_pain":
            if len(occurrences) < 3 or len({item["kind"] for item in occurrences}) < 2:
                raise HarnessError(
                    "repeated pain requires at least three occurrences across two work-unit kinds"
                )
        elif len(occurrences) != 1:
            raise HarnessError("critical single incident requires exactly one occurrence")
        recorded = now_iso()
        request = {
            "integrity_version": 1,
            "request_id": request_id,
            "version": 1,
            "status": "submitted",
            "trigger_class": args.trigger_class,
            "release_blocking": bool(args.release_blocking),
            "source_lane_id": source_lane["lane_id"],
            "source_lane_revision": source_lane["revision"],
            "steward_lane_id": steward["lane_id"],
            "task_type": task_type,
            "pain_statement": require_evidence_detail(
                args.pain_statement, "improvement pain statement"
            ),
            "desired_outcome": require_evidence_detail(
                args.desired_outcome, "improvement desired outcome"
            ),
            "occurrences": occurrences,
            "occurrence_fingerprint": _records_fingerprint(occurrences),
            "brief": None,
            "chief_decision": None,
            "project": None,
            "release_ids": [],
            "events": [
                {
                    "event": "submitted",
                    "actor_lane": source_lane["lane_id"],
                    "recorded_at": recorded,
                }
            ],
            "created_at": recorded,
            "updated_at": recorded,
        }
        state["improvement_model_version"] = 1
        state.setdefault("improvement_requests", []).append(request)
        state.setdefault("skill_releases", [])
        state.setdefault("skill_adoption_events", [])
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(request, args.json)
    return 0


def cmd_improvement_brief(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "brief improvement request for")
        request = improvement_request_by_id(state, args.request_id)
        if request.get("version") != args.expected_version or request.get("status") != "submitted":
            raise HarnessError("improvement brief CAS/status gate failed")
        steward = _engaged_steward_lane(state)
        if steward.get("lane_id") != args.steward_lane_id:
            raise HarnessError("improvement brief must be issued by the engaged steward")
        capacity_reference = None
        if args.capacity_review_id:
            capacity = capacity_review_by_id(state, args.capacity_review_id)
            if capacity.get("scope", {}).get("target_lane_id") != request.get("source_lane_id"):
                raise HarnessError("capacity comparison targets a different department lane")
            capacity_reference = {
                "review_id": capacity["review_id"],
                "version": capacity["version"],
                "status": capacity["status"],
                "dataset_sha256": capacity.get("dataset", {}).get("sha256"),
            }
        recorded = now_iso()
        request["version"] = int(request["version"]) + 1
        request["status"] = "awaiting_chief"
        request["brief"] = {
            "steward_lane_id": steward["lane_id"],
            "options": _parse_improvement_options(args.option),
            "capacity_reference": capacity_reference,
            "recommendation": require_evidence_detail(
                args.recommendation, "improvement recommendation"
            ),
            "evidence_boundary": require_evidence_detail(
                args.evidence_boundary, "improvement evidence boundary"
            ),
            "recorded_at": recorded,
        }
        request["events"].append(
            {"event": "awaiting_chief", "actor_lane": steward["lane_id"], "recorded_at": recorded}
        )
        request["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(request, args.json)
    return 0


def cmd_improvement_arbitrate(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "arbitrate improvement request for")
        if any(
            item.get("status") == "needs_user"
            for item in state.get("needs_user_escalations", [])
        ):
            raise HarnessError(
                "unresolved needs-user escalation blocks improvement arbitration"
            )
        request = improvement_request_by_id(state, args.request_id)
        if (
            request.get("version") != args.expected_version
            or request.get("status") != "awaiting_chief"
        ):
            raise HarnessError("improvement arbitration CAS/status gate failed")
        session_id = require_root_session(paths, state, args.session_id)
        options = {
            item.get("option_id") for item in request.get("brief", {}).get("options", [])
        }
        selected = args.selected_option or ""
        if args.decision == "approved" and selected not in options:
            raise HarnessError("approved improvement requires a valid selected option")
        if args.decision == "rejected" and selected:
            raise HarnessError("rejected improvement may not select an option")
        recorded = now_iso()
        request["version"] = int(request["version"]) + 1
        request["status"] = "approved" if args.decision == "approved" else "rejected"
        request["chief_decision"] = {
            "decision_id": f"{request['request_id']}-chief-1",
            "decision": args.decision,
            "selected_option_id": selected,
            "rationale": require_evidence_detail(
                args.rationale, "improvement chief rationale"
            ),
            "root_owner": state.get("owner"),
            "root_session_id": session_id,
            "recorded_at": recorded,
        }
        request["events"].append(
            {"event": request["status"], "actor_lane": "chief", "recorded_at": recorded}
        )
        request["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(request, args.json)
    return 0


def cmd_improvement_link_project(args: argparse.Namespace, paths: HarnessPaths) -> int:
    project_task_id = validate_id(args.project_task_id, "improvement project task id")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "link improvement project for")
        request = improvement_request_by_id(state, args.request_id)
        if request.get("version") != args.expected_version or request.get("status") != "approved":
            raise HarnessError("improvement project link CAS/status gate failed")
        if (request.get("chief_decision") or {}).get("selected_option_id") != "skill-automation":
            raise HarnessError("only a chief-selected skill-automation option may create a project")
        if project_task_id == state.get("task_id"):
            raise HarnessError("improvement work must use an independent full harness task")
        _engaged_steward_lane(state)
        project = load_task(paths, project_task_id)
        if project.get("profile", "full") != "full":
            raise HarnessError("improvement project must use the full task profile")
        require_open_task(project, "serve as improvement project")
        require_plan_ready(paths, project, "link improvement project")
        if not any(
            claim.get("status") in RESERVING_CLAIM_STATUSES
            for claim in claims_owned_by_task(paths, project_task_id)
        ):
            raise HarnessError("improvement project must own at least one reserving claim")
        recorded = now_iso()
        request["version"] = int(request["version"]) + 1
        request["status"] = "delegated"
        request["project"] = {
            "task_id": project_task_id,
            "plan_sha256": project.get("plan_sha256"),
            "worktree": project.get("worktree"),
            "branch": project.get("branch"),
            "linked_at": recorded,
        }
        request["events"].append(
            {"event": "delegated", "actor_lane": "steward", "recorded_at": recorded}
        )
        request["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(request, args.json)
    return 0


def _load_json_artifact(
    value: str | Path, label: str, expected_sha: str
) -> tuple[Path, bytes, dict[str, Any]]:
    expected_sha = require_text(expected_sha, f"{label} SHA-256").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise HarnessError(f"{label} SHA-256 must be full 64 hex")
    source, data = read_regular_artifact(
        value, label, max_bytes=COMMAND_ARTIFACT_MAX_BYTES, require_utf8=True
    )
    if hashlib.sha256(data).hexdigest() != expected_sha:
        raise HarnessError(f"{label} SHA-256 mismatch")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HarnessError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise HarnessError(f"{label} must contain a JSON object")
    return source, data, payload


def _json_nonnegative_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise HarnessError(f"JSON field {key} must be a non-negative integer")
    return value


def _valid_named_checks(value: Any, minimum: int) -> bool:
    return (
        isinstance(value, list)
        and len(value) >= minimum
        and all(isinstance(item, str) and item.strip() for item in value)
        and len(value) == len(set(value))
    )


def _valid_skill_manifest_files(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    names: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            return False
        name = str(item.get("path", ""))
        pure = PurePosixPath(name)
        digest = str(item.get("sha256", ""))
        if (
            not name
            or pure.is_absolute()
            or ".." in pure.parts
            or name in names
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            return False
        names.add(name)
    return True


def _skill_bundle_member_hashes(data: bytes) -> dict[str, str]:
    members: dict[str, str] = {}
    total_size = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            entries = archive.getmembers()
            if len(entries) > 256:
                raise HarnessError("skill bundle contains more than 256 archive members")
            for entry in entries:
                pure = PurePosixPath(entry.name)
                if (
                    pure.is_absolute()
                    or not entry.name
                    or ".." in pure.parts
                    or entry.issym()
                    or entry.islnk()
                    or entry.isdev()
                ):
                    raise HarnessError(f"unsafe skill bundle member: {entry.name!r}")
                if entry.isdir():
                    continue
                if not entry.isfile() or entry.name in members:
                    raise HarnessError(f"unsupported or duplicate skill bundle member: {entry.name!r}")
                total_size += int(entry.size)
                if entry.size < 0 or total_size > 64 * 1024 * 1024:
                    raise HarnessError("skill bundle expanded content exceeds 64 MiB")
                stream = archive.extractfile(entry)
                if stream is None:
                    raise HarnessError(f"skill bundle member cannot be read: {entry.name}")
                payload = stream.read(entry.size + 1)
                if len(payload) != entry.size:
                    raise HarnessError(f"skill bundle member size mismatch: {entry.name}")
                members[entry.name] = hashlib.sha256(payload).hexdigest()
    except (tarfile.TarError, OSError) as exc:
        raise HarnessError(f"skill bundle must be a valid gzip tar archive: {exc}") from exc
    if "SKILL.md" not in members:
        raise HarnessError("skill bundle must contain SKILL.md at archive root")
    return members


def _skill_release_semantic_integrity_errors(
    state: dict[str, Any],
    release: dict[str, Any],
    paths: HarnessPaths | None,
) -> list[str]:
    release_id = str(release.get("release_id", ""))
    try:
        _, bundle_data = read_regular_artifact(
            str(release.get("bundle_path", "")),
            "skill release bundle",
            max_bytes=32 * 1024 * 1024,
        )
        _, manifest_data, manifest = _load_json_artifact(
            str(release.get("manifest_path", "")),
            "skill release manifest",
            str(release.get("manifest_sha256", "")),
        )
        _, validation_data, validation = _load_json_artifact(
            str(release.get("validation_path", "")),
            "skill validation receipt",
            str(release.get("validation_sha256", "")),
        )
        bundle_sha = hashlib.sha256(bundle_data).hexdigest()
        validation_sha = hashlib.sha256(validation_data).hexdigest()
        bundle_members = _skill_bundle_member_hashes(bundle_data)
        independent = validation.get("independent_review", {})
        release_review = release.get("independent_review", {})
        if (
            release.get("integrity_version") != 1
            or bundle_sha != release.get("bundle_sha256")
            or len(bundle_data) != release.get("bundle_size_bytes")
            or manifest.get("skill_release_manifest_version") != 1
            or manifest.get("skill_id") != release.get("skill_id")
            or manifest.get("skill_version") != release.get("skill_version")
            or manifest.get("maintenance_owner") != release.get("maintenance_owner")
            or manifest.get("rollback_plan") != release.get("rollback_plan")
            or manifest.get("bundle_sha256") != bundle_sha
            or manifest.get("validation_receipt_sha256") != validation_sha
            or not _valid_skill_manifest_files(manifest.get("files"))
            or {
                str(item["path"]): str(item["sha256"])
                for item in manifest.get("files", [])
            }
            != bundle_members
            or validation.get("validation_version") != 1
            or validation.get("skill_creator_used") is not True
            or validation.get("structural_pass") is not True
            or validation.get("agents_metadata_consistent") is not True
            or validation.get("bundled_scripts_tested") is not True
            or not _valid_named_checks(validation.get("representative_arise_fixtures"), 2)
            or not _valid_named_checks(validation.get("adversarial_fixtures"), 3)
            or not _valid_named_checks(validation.get("blind_forward_tests"), 2)
            or independent.get("status") != "pass"
            or not independent.get("evidence")
            or independent.get("review_packet_id")
            != release_review.get("review_packet_id")
        ):
            raise HarnessError("release snapshots no longer satisfy the skill contract")
        if paths is not None:
            project = load_task(paths, str(release.get("project_task_id", "")))
            required_artifact_shas = {
                bundle_sha,
                hashlib.sha256(manifest_data).hexdigest(),
                validation_sha,
            }
            review_packet = _require_done_reviewer_packet(
                paths,
                project,
                str(release_review.get("review_packet_id", "")),
                required_artifact_shas=required_artifact_shas,
            )
            if (
                release_review.get("review_result_sha256")
                != review_packet.get("result_sha256")
                or release_review.get("reviewer_agent_id")
                != review_packet.get("agent_id")
            ):
                raise HarnessError("release reviewer identity no longer matches its packet")
            candidate_records = [
                item
                for item in project.get("verification", [])
                if item.get("status") == "pass"
                and item.get("integrity_version") == 1
                and item.get("category") in {"skill_validation", "independent_review"}
                and required_artifact_shas.issubset(
                    {ref.get("sha256") for ref in item.get("artifact_refs", [])}
                )
            ]
            if (
                len(candidate_records) != 2
                or {item.get("category") for item in candidate_records}
                != {"skill_validation", "independent_review"}
            ):
                raise HarnessError("release project candidate verification set changed")
            review_record = next(
                item
                for item in candidate_records
                if item.get("category") == "independent_review"
            )
            if (
                review_record.get("review_packet_id") != review_packet.get("packet_id")
                or review_record.get("review_result_sha256")
                != review_packet.get("result_sha256")
                or review_record.get("reviewer_agent_id")
                != review_packet.get("agent_id")
            ):
                raise HarnessError("release review verification lost reviewer binding")
    except (HarnessError, KeyError, TypeError, ValueError) as exc:
        return [f"skill release {release_id} semantic integrity failed: {exc}"]
    return []


def _skill_adoption_semantic_integrity_errors(
    state: dict[str, Any], event: dict[str, Any]
) -> list[str]:
    event_id = str(event.get("event_id", ""))
    try:
        _, _, payload = _load_json_artifact(
            str(event.get("evidence_path", "")),
            "skill adoption evidence",
            str(event.get("evidence_sha256", "")),
        )
        releases = [
            item
            for item in state.get("skill_releases", [])
            if item.get("release_id") == event.get("release_id")
        ]
        if len(releases) != 1:
            raise HarnessError("adoption event release identity is ambiguous")
        release = releases[0]
        status_map = {
            "canary": "canary",
            "adopt": "adopted",
            "pause": "paused",
            "rollback": "rolled_back",
            "deprecate": "deprecated",
        }
        action = str(event.get("action", ""))
        if (
            event.get("integrity_version") != 1
            or payload.get("adoption_receipt_version") != 1
            or payload.get("request_id") != event.get("request_id")
            or payload.get("release_id") != event.get("release_id")
            or payload.get("skill_version") != release.get("skill_version")
            or payload.get("action") != action
            or status_map.get(action) != event.get("resulting_status")
        ):
            raise HarnessError("adoption event no longer matches its receipt")
        if action == "canary":
            if (
                _json_nonnegative_int(payload, "planned_skill_units") < 3
                or not str(payload.get("rollback_plan", "")).strip()
            ):
                raise HarnessError("canary receipt no longer satisfies its gate")
        elif action == "adopt":
            canary_events = [
                item
                for item in state.get("skill_adoption_events", [])
                if item.get("event_id") == event.get("canary_event_id")
                and item.get("release_id") == event.get("release_id")
                and item.get("action") == "canary"
            ]
            if (
                len(canary_events) != 1
                or payload.get("canary_event_id") != event.get("canary_event_id")
            ):
                raise HarnessError("adoption event lost its exact canary binding")
            canary = canary_events[0]
            skill_bindings = _resolve_adoption_work_units(
                state,
                payload.get("skill_work_units"),
                label="skill canary",
                minimum=3,
                canary_recorded_at=str(canary.get("recorded_at", "")),
                require_after_canary=True,
                expected_skill_release_id=str(release.get("release_id", "")),
                expected_skill_version=str(release.get("skill_version", "")),
                expected_canary_event_id=str(canary.get("event_id", "")),
            )
            baseline_bindings: list[dict[str, Any]] = []
            if payload.get("efficiency_claim") is True:
                baseline_bindings = _resolve_adoption_work_units(
                    state,
                    payload.get("baseline_work_units"),
                    label="skill baseline",
                    minimum=3,
                    canary_recorded_at=str(canary.get("recorded_at", "")),
                    require_after_canary=False,
                )
            if (
                _json_nonnegative_int(payload, "skill_units") != len(skill_bindings)
                or (
                    payload.get("efficiency_claim") is True
                    and _json_nonnegative_int(payload, "baseline_units")
                    != len(baseline_bindings)
                )
                or payload.get("success_criteria_met") is not True
                or _json_nonnegative_int(payload, "quality_regressions") != 0
                or payload.get("rollback_path_verified") is not True
                or event.get("skill_work_unit_bindings") != skill_bindings
                or event.get("baseline_work_unit_bindings") != baseline_bindings
            ):
                raise HarnessError("adoption work-unit bindings no longer satisfy the gate")
        elif action in {"pause", "rollback", "deprecate"}:
            require_evidence_detail(str(payload.get("reason", "")), "adoption action reason")
        else:
            raise HarnessError("adoption event action is unsupported")
    except (HarnessError, KeyError, TypeError, ValueError) as exc:
        return [f"skill adoption event {event_id} semantic integrity failed: {exc}"]
    return []


def _require_project_result(project_dir: Path, source: Path, label: str) -> None:
    try:
        source.relative_to(project_dir / "results")
    except ValueError as exc:
        raise HarnessError(f"{label} must come from the linked project results directory") from exc


def cmd_skill_release_record(args: argparse.Namespace, paths: HarnessPaths) -> int:
    release_id = validate_id(args.release_id, "skill release id")
    skill_id = validate_id(args.skill_id, "skill id")
    expected_bundle_sha = require_text(args.bundle_sha256, "skill bundle SHA-256").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_bundle_sha):
        raise HarnessError("skill bundle SHA-256 must be full 64 hex")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "record skill release for")
        _engaged_steward_lane(state)
        request = improvement_request_by_id(state, args.request_id)
        if request.get("version") != args.expected_version or request.get("status") != "delegated":
            raise HarnessError("skill release CAS/status gate failed")
        if any(item.get("release_id") == release_id for item in state.get("skill_releases", [])):
            raise HarnessError(f"skill release already exists: {release_id}")
        project_task_id = request.get("project", {}).get("task_id")
        project = load_task(paths, str(project_task_id))
        if project.get("plan_sha256") != request.get("project", {}).get("plan_sha256"):
            raise HarnessError("linked improvement project plan changed")
        project_dir = task_dir(paths, str(project_task_id))
        bundle_source, bundle_data = read_regular_artifact(
            args.bundle, "skill bundle", max_bytes=32 * 1024 * 1024
        )
        manifest_source, manifest_data, manifest = _load_json_artifact(
            args.manifest, "skill release manifest", args.manifest_sha256
        )
        validation_source, validation_data, validation = _load_json_artifact(
            args.validation_receipt,
            "skill validation receipt",
            args.validation_receipt_sha256,
        )
        for source, label in (
            (bundle_source, "skill bundle"),
            (manifest_source, "skill release manifest"),
            (validation_source, "skill validation receipt"),
        ):
            _require_project_result(project_dir, source, label)
        bundle_sha = hashlib.sha256(bundle_data).hexdigest()
        validation_sha = hashlib.sha256(validation_data).hexdigest()
        bundle_members = _skill_bundle_member_hashes(bundle_data)
        if bundle_sha != expected_bundle_sha:
            raise HarnessError("skill bundle SHA-256 mismatch")
        if (
            manifest.get("skill_release_manifest_version") != 1
            or manifest.get("skill_id") != skill_id
            or manifest.get("skill_version") != args.skill_version
            or manifest.get("maintenance_owner") != args.maintenance_owner
            or manifest.get("rollback_plan") != args.rollback_plan
            or manifest.get("bundle_sha256") != bundle_sha
            or manifest.get("validation_receipt_sha256") != validation_sha
            or not _valid_skill_manifest_files(manifest.get("files"))
        ):
            raise HarnessError("skill release manifest contract is incomplete or inconsistent")
        manifest_members = {
            str(item["path"]): str(item["sha256"])
            for item in manifest["files"]
        }
        if manifest_members != bundle_members:
            raise HarnessError("skill release manifest does not match archive members and SHA-256")
        independent = validation.get("independent_review", {})
        review_packet_id = str(independent.get("review_packet_id", ""))
        if (
            validation.get("validation_version") != 1
            or validation.get("skill_creator_used") is not True
            or validation.get("structural_pass") is not True
            or validation.get("agents_metadata_consistent") is not True
            or validation.get("bundled_scripts_tested") is not True
            or not _valid_named_checks(validation.get("representative_arise_fixtures"), 2)
            or not _valid_named_checks(validation.get("adversarial_fixtures"), 3)
            or not _valid_named_checks(validation.get("blind_forward_tests"), 2)
            or independent.get("status") != "pass"
            or not independent.get("evidence")
            or not review_packet_id
        ):
            raise HarnessError("skill validation receipt does not meet the release quality gate")
        required_artifact_shas = {
            bundle_sha,
            hashlib.sha256(manifest_data).hexdigest(),
            validation_sha,
        }
        review_packet = _require_done_reviewer_packet(
            paths,
            project,
            review_packet_id,
            required_artifact_shas=required_artifact_shas,
        )
        project_records = [
            item
            for item in project.get("verification", [])
            if item.get("status") == "pass"
            and item.get("integrity_version") == 1
            and item.get("category") in {"skill_validation", "independent_review"}
            and required_artifact_shas.issubset(
                {ref.get("sha256") for ref in item.get("artifact_refs", [])}
            )
        ]
        if (
            len(project_records) != 2
            or {item.get("category") for item in project_records}
            != {"skill_validation", "independent_review"}
        ):
            raise HarnessError(
                "linked project requires candidate-bound skill_validation and independent_review records"
            )
        independent_record = next(
            item
            for item in project_records
            if item.get("category") == "independent_review"
        )
        if (
            independent_record.get("review_packet_id") != review_packet["packet_id"]
            or independent_record.get("review_result_sha256")
            != review_packet.get("result_sha256")
            or independent_record.get("reviewer_agent_id")
            != review_packet.get("agent_id")
        ):
            raise HarnessError(
                "independent review verification is not bound to the reviewer result identity"
            )
        destination_root = task_dir(paths, args.task) / "results"
        bundle_snapshot = destination_root / f"skill-release-{release_id}.bundle"
        manifest_snapshot = destination_root / f"skill-release-{release_id}.manifest.json"
        validation_snapshot = destination_root / f"skill-release-{release_id}.validation.json"
        atomic_write_bytes(bundle_snapshot, bundle_data)
        atomic_write_bytes(manifest_snapshot, manifest_data)
        atomic_write_bytes(validation_snapshot, validation_data)
        for destination in (bundle_snapshot, manifest_snapshot, validation_snapshot):
            os.chmod(destination, 0o600)
        recorded = now_iso()
        release = {
            "integrity_version": 1,
            "release_id": release_id,
            "request_id": request["request_id"],
            "project_task_id": project_task_id,
            "skill_id": skill_id,
            "skill_version": require_text(args.skill_version, "skill version"),
            "maintenance_owner": require_text(
                args.maintenance_owner, "skill maintenance owner"
            ),
            "rollback_plan": require_evidence_detail(
                args.rollback_plan, "skill rollback plan"
            ),
            "status": "release_candidate",
            "bundle_path": str(bundle_snapshot),
            "bundle_sha256": bundle_sha,
            "bundle_size_bytes": len(bundle_data),
            "manifest_path": str(manifest_snapshot),
            "manifest_sha256": sha256_file(manifest_snapshot),
            "validation_path": str(validation_snapshot),
            "validation_sha256": sha256_file(validation_snapshot),
            "independent_review": {
                "review_packet_id": review_packet["packet_id"],
                "review_result_sha256": review_packet["result_sha256"],
                "reviewer_agent_id": review_packet["agent_id"],
            },
            "recorded_at": recorded,
        }
        state.setdefault("skill_releases", []).append(release)
        request["release_ids"].append(release_id)
        request["version"] = int(request["version"]) + 1
        request["status"] = "release_candidate"
        request["events"].append(
            {"event": "release_candidate", "actor_lane": "steward", "recorded_at": recorded}
        )
        request["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(release, args.json)
    return 0


def cmd_skill_adoption_record(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "record skill adoption decision for")
        request = improvement_request_by_id(state, args.request_id)
        if request.get("version") != args.expected_version:
            raise HarnessError("skill adoption CAS failed")
        releases = [
            item for item in state.get("skill_releases", []) if item.get("release_id") == args.release_id
        ]
        if len(releases) != 1 or args.release_id not in request.get("release_ids", []):
            raise HarnessError("skill release does not belong to this improvement request")
        release = releases[0]
        for path_field, sha_field in (
            ("bundle_path", "bundle_sha256"),
            ("manifest_path", "manifest_sha256"),
            ("validation_path", "validation_sha256"),
        ):
            release_path = Path(str(release.get(path_field, "")))
            if (
                not release_path.is_file()
                or release_path.is_symlink()
                or sha256_file(release_path) != release.get(sha_field)
            ):
                raise HarnessError("skill release artifact is missing or tampered")
        release_errors = _skill_release_semantic_integrity_errors(state, release, paths)
        if release_errors:
            raise HarnessError("; ".join(release_errors))
        allowed = {
            "release_candidate": {"canary"},
            "canary": {"adopt", "pause", "rollback"},
            "paused": {"canary", "rollback", "deprecate"},
            "adopted": {"pause", "rollback", "deprecate"},
        }
        if args.action not in allowed.get(str(request.get("status")), set()):
            raise HarnessError(
                f"invalid skill adoption transition {request.get('status')} -> {args.action}"
            )
        session_id = require_root_session(paths, state, args.session_id)
        _, evidence_data, evidence_payload = _load_json_artifact(
            args.evidence_artifact, "skill adoption evidence", args.evidence_sha256
        )
        if evidence_payload.get("adoption_receipt_version") != 1:
            raise HarnessError("skill adoption evidence has an unsupported schema")
        if (
            evidence_payload.get("request_id") != request["request_id"]
            or evidence_payload.get("release_id") != release["release_id"]
            or evidence_payload.get("skill_version") != release["skill_version"]
            or evidence_payload.get("action") != args.action
        ):
            raise HarnessError("skill adoption evidence is bound to a different release")
        skill_work_unit_bindings: list[dict[str, Any]] = []
        baseline_work_unit_bindings: list[dict[str, Any]] = []
        bound_canary_event_id = ""
        if args.action == "canary":
            if (
                _json_nonnegative_int(evidence_payload, "planned_skill_units") < 3
                or not str(evidence_payload.get("rollback_plan", "")).strip()
            ):
                raise HarnessError("skill canary requires at least three units and a rollback plan")
        if args.action == "adopt":
            canary_events = [
                item
                for item in state.get("skill_adoption_events", [])
                if item.get("release_id") == release["release_id"]
                and item.get("action") == "canary"
            ]
            if (
                not canary_events
                or evidence_payload.get("canary_event_id")
                != canary_events[-1].get("event_id")
            ):
                raise HarnessError("skill adoption evidence is not bound to the current canary")
            canary_event = canary_events[-1]
            bound_canary_event_id = str(canary_event["event_id"])
            skill_work_unit_bindings = _resolve_adoption_work_units(
                state,
                evidence_payload.get("skill_work_units"),
                label="skill canary",
                minimum=3,
                canary_recorded_at=str(canary_event.get("recorded_at", "")),
                require_after_canary=True,
                expected_skill_release_id=str(release.get("release_id", "")),
                expected_skill_version=str(release.get("skill_version", "")),
                expected_canary_event_id=bound_canary_event_id,
            )
            if _json_nonnegative_int(evidence_payload, "skill_units") != len(
                skill_work_unit_bindings
            ):
                raise HarnessError(
                    "skill_units must equal the number of bound skill_work_units"
                )
            if evidence_payload.get("efficiency_claim") is True:
                baseline_work_unit_bindings = _resolve_adoption_work_units(
                    state,
                    evidence_payload.get("baseline_work_units"),
                    label="skill baseline",
                    minimum=3,
                    canary_recorded_at=str(canary_event.get("recorded_at", "")),
                    require_after_canary=False,
                )
                if _json_nonnegative_int(evidence_payload, "baseline_units") != len(
                    baseline_work_unit_bindings
                ):
                    raise HarnessError(
                        "baseline_units must equal the number of bound baseline_work_units"
                    )
                if {
                    item["identity_sha256"] for item in skill_work_unit_bindings
                } & {
                    item["identity_sha256"] for item in baseline_work_unit_bindings
                }:
                    raise HarnessError(
                        "skill and baseline work units must have disjoint durable identities"
                    )
            if (
                evidence_payload.get("success_criteria_met") is not True
                or _json_nonnegative_int(evidence_payload, "quality_regressions") != 0
                or evidence_payload.get("rollback_path_verified") is not True
            ):
                raise HarnessError("skill adoption evidence does not meet the canary quality gate")
        if args.action in {"pause", "rollback", "deprecate"}:
            require_evidence_detail(
                str(evidence_payload.get("reason", "")), "skill adoption action reason"
            )
        recorded = now_iso()
        evidence_snapshot = (
            task_dir(paths, args.task)
            / "results"
            / f"skill-adoption-{args.release_id}-{len(state.get('skill_adoption_events', [])) + 1}.json"
        )
        atomic_write_bytes(evidence_snapshot, evidence_data)
        os.chmod(evidence_snapshot, 0o600)
        status_map = {
            "canary": "canary",
            "adopt": "adopted",
            "pause": "paused",
            "rollback": "rolled_back",
            "deprecate": "deprecated",
        }
        event = {
            "integrity_version": 1,
            "event_id": f"{args.release_id}-adoption-{len(state.get('skill_adoption_events', [])) + 1}",
            "request_id": request["request_id"],
            "release_id": args.release_id,
            "action": args.action,
            "resulting_status": status_map[args.action],
            "evidence_path": str(evidence_snapshot),
            "evidence_sha256": sha256_file(evidence_snapshot),
            "rationale": require_evidence_detail(args.rationale, "skill adoption rationale"),
            "root_owner": state.get("owner"),
            "root_session_id": session_id,
            "recorded_at": recorded,
        }
        if args.action == "adopt":
            event["canary_event_id"] = bound_canary_event_id
            event["skill_work_unit_bindings"] = skill_work_unit_bindings
            event["baseline_work_unit_bindings"] = baseline_work_unit_bindings
        state.setdefault("skill_adoption_events", []).append(event)
        request["version"] = int(request["version"]) + 1
        request["status"] = event["resulting_status"]
        request["events"].append(
            {"event": event["resulting_status"], "actor_lane": "chief", "recorded_at": recorded}
        )
        request["updated_at"] = recorded
        release["status"] = event["resulting_status"]
        release["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(event, args.json)
    return 0


def cmd_execution_select(args: argparse.Namespace, paths: HarnessPaths) -> int:
    selection_id = validate_id(args.selection_id, "execution selection id")
    work_unit_id = validate_id(args.work_unit_id, "execution work-unit id")
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
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "select execution topology for")
        require_plan_ready(paths, state, "select execution topology")
        session_id = require_root_session(paths, state, args.session_id)
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
                    not in TERMINAL_COORDINATION_STATUSES | {"accepted"}
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
            prior_selection["status"] = "superseded"
            prior_selection["superseded_by"] = selection_id
            prior_selection["superseded_at"] = now_iso()
        elif args.supersedes_selection_id:
            raise HarnessError("superseded execution selection is not active for this work unit")
        lanes = [lane_by_id(state, lane_id) for lane_id in lane_ids]
        if any(lane.get("status") in {"done", "parked"} for lane in lanes):
            raise HarnessError("execution selection may not use done or parked lanes")
        recorded = now_iso()
        selection = {
            "integrity_version": 1,
            "selection_id": selection_id,
            "work_unit_id": work_unit_id,
            "scope": require_evidence_detail(args.scope, "execution selection scope"),
            "mode": args.mode,
            "lane_snapshots": [
                {
                    "lane_id": lane["lane_id"],
                    "revision": lane["revision"],
                    "authority_commit": lane["authority_commit"],
                    "contract_version": lane["contract_version"],
                }
                for lane in sorted(lanes, key=lambda item: item["lane_id"])
            ],
            "task_characteristics": {
                "sequential_dependency": args.sequential_dependency,
                "tool_density": args.tool_density,
                "shared_context": args.shared_context,
            },
            "rationale": require_evidence_detail(
                args.rationale, "execution topology rationale"
            ),
            "falsification_condition": require_evidence_detail(
                args.falsification_condition, "execution topology falsification condition"
            ),
            "escalation_condition": require_evidence_detail(
                args.escalation_condition, "execution topology escalation condition"
            ),
            "root_owner": state.get("owner"),
            "root_session_id": session_id,
            "status": "active",
            "recorded_at": recorded,
        }
        state["execution_model_version"] = 1
        state.setdefault("execution_selections", []).append(selection)
        state.setdefault("cross_lane_sessions", [])
        state.setdefault("needs_user_escalations", [])
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(selection, args.json)
    return 0


def cmd_cross_lane_open(args: argparse.Namespace, paths: HarnessPaths) -> int:
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
        if request.get("status") in TERMINAL_COORDINATION_STATUSES:
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


def cmd_needs_user_create(args: argparse.Namespace, paths: HarnessPaths) -> int:
    escalation_id = validate_id(args.escalation_id, "needs-user escalation id")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "create needs-user escalation for")
        require_plan_ready(paths, state, "create needs-user escalation")
        session_id = require_root_session(paths, state, args.session_id)
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


def cmd_needs_user_resolve(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "resolve needs-user escalation for")
        escalation = needs_user_by_id(state, args.escalation_id)
        if escalation.get("status") != "needs_user":
            raise HarnessError("needs-user escalation is already terminal")
        session_id = require_root_session(paths, state, args.session_id)
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


def cmd_lane_set_status(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "set lane status for")
        session_id = require_root_session(paths, state, args.session_id)
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
            if engaged >= MAX_ENGAGED_LANES:
                raise HarnessError(f"engaged lane ceiling is {MAX_ENGAGED_LANES}")
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
                    request.get("status") not in TERMINAL_COORDINATION_STATUSES
                    for request in state.get("coordination_requests", [])
                ) or any(
                    review.get("status") not in {"rejected", "consumed", "superseded"}
                    for review in state.get("capacity_reviews", [])
                ) or any(
                    request.get("status") not in TERMINAL_IMPROVEMENT_STATUSES
                    for request in state.get("improvement_requests", [])
                ):
                    raise HarnessError("cannot park the steward while its control-plane inbox is active")
            if lane.get("kind") == "capacity_planning" and any(
                review.get("capacity_lane_id") == lane["lane_id"]
                and review.get("status") not in {"rejected", "consumed", "superseded"}
                for review in state.get("capacity_reviews", [])
            ):
                raise HarnessError("cannot park Capacity Planning with an active review")
        recorded = now_iso()
        old_status = lane["status"]
        lane["status"] = args.status
        lane["next_action"] = require_text(args.next_action, "lane next action")
        lane["status_updated_at"] = recorded
        lane.setdefault("status_events", []).append(
            {
                "old_status": old_status,
                "new_status": args.status,
                "root_session_id": session_id,
                "reason": require_evidence_detail(args.reason, "lane status reason"),
                "recorded_at": recorded,
            }
        )
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(lane, args.json)
    return 0


def cmd_lane_create(args: argparse.Namespace, paths: HarnessPaths) -> int:
    lane_id = validate_id(args.lane_id, "lane id")
    if args.kind not in LANE_KINDS:
        raise HarnessError(f"unknown lane kind: {args.kind}")
    if args.role not in ROLE_TIER_MAP:
        raise HarnessError(f"unknown lane role: {args.role}")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "create lane for")
        require_plan_ready(paths, state, "create lane")
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
        if args.status in ENGAGED_LANE_STATUSES and engaged >= MAX_ENGAGED_LANES:
            raise HarnessError(f"engaged lane ceiling is {MAX_ENGAGED_LANES}")
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
        errors = portfolio_integrity_errors(state)
        if errors:
            raise HarnessError("invalid lane portfolio: " + "; ".join(errors))
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(lane, args.json)
    return 0


def cmd_lane_revise(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "revise lane for")
        require_plan_ready(paths, state, "revise lane")
        lane = lane_by_id(state, args.lane_id)
        if lane.get("revision") != args.expected_revision:
            raise HarnessError(
                f"lane revision CAS failed: expected {args.expected_revision}, "
                f"current {lane.get('revision')}"
            )
        if args.change_class not in CHANGE_CLASSES - {"genesis"}:
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
        root_session_id = require_root_session(paths, state, args.session_id)
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
        errors = portfolio_integrity_errors(state)
        if errors:
            raise HarnessError("invalid lane portfolio: " + "; ".join(errors))
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(lane, args.json)
    return 0


def cmd_lane_dependency_add(args: argparse.Namespace, paths: HarnessPaths) -> int:
    dependency_id = validate_id(args.dependency_id, "dependency id")
    if args.kind not in DEPENDENCY_KINDS:
        raise HarnessError(f"invalid dependency kind: {args.kind}")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "add lane dependency to")
        require_plan_ready(paths, state, "add lane dependency")
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
        errors = portfolio_integrity_errors(state)
        if errors:
            raise HarnessError("invalid lane portfolio: " + "; ".join(errors))
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(dependency, args.json)
    return 0


def cmd_lane_dependency_update(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "update lane dependency for")
        session_id = require_root_session(paths, state, args.session_id)
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


def cmd_coordination_create(args: argparse.Namespace, paths: HarnessPaths) -> int:
    request_id = validate_id(args.request_id, "coordination request id")
    if args.severity not in DEPENDENCY_KINDS:
        raise HarnessError(f"invalid coordination severity: {args.severity}")
    if args.change_class not in CHANGE_CLASSES - {"genesis"}:
        raise HarnessError(f"invalid requested change class: {args.change_class}")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "create coordination request for")
        require_plan_ready(paths, state, "create coordination request")
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
        errors = portfolio_integrity_errors(state)
        if errors:
            raise HarnessError("invalid lane portfolio: " + "; ".join(errors))
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(request, args.json)
    return 0


def cmd_coordination_update(args: argparse.Namespace, paths: HarnessPaths) -> int:
    if args.status not in {"acknowledged", "countered"}:
        raise HarnessError(
            "specialist coordination update accepts acknowledged or countered only; root arbitrates decisions"
        )
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "update coordination request for")
        request = coordination_by_id(state, args.request_id)
        _engaged_steward_lane(state)
        if request.get("status") in TERMINAL_COORDINATION_STATUSES | {"accepted"}:
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
        errors = portfolio_integrity_errors(state)
        if errors:
            raise HarnessError("invalid lane portfolio: " + "; ".join(errors))
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(request, args.json)
    return 0


def cmd_coordination_arbitrate(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "arbitrate coordination request for")
        request = coordination_by_id(state, args.request_id)
        steward = _engaged_steward_lane(state)
        session_id = require_root_session(paths, state, args.session_id)
        if request.get("status") in TERMINAL_COORDINATION_STATUSES | {"accepted"}:
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
        errors = portfolio_integrity_errors(state)
        if errors:
            raise HarnessError("invalid lane portfolio: " + "; ".join(errors))
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(request, args.json)
    return 0


def cmd_baseline_freeze(args: argparse.Namespace, paths: HarnessPaths) -> int:
    baseline_id = validate_id(args.baseline_id, "baseline id")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "freeze baseline for")
        require_plan_ready(paths, state, "freeze baseline")
        session_id = require_root_session(paths, state, args.session_id)
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
        errors = portfolio_integrity_errors(state)
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
    args: argparse.Namespace, paths: HarnessPaths
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
        artifact = snapshot_evidence_artifact(
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


def cmd_coordination_verify(args: argparse.Namespace, paths: HarnessPaths) -> int:
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
        artifact = snapshot_evidence_artifact(
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


def cmd_coordination_resolve(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "resolve coordination request for")
        request = coordination_by_id(state, args.request_id)
        _engaged_steward_lane(state)
        session_id = require_root_session(paths, state, args.session_id)
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


def _clip_critical(value: Any) -> str:
    text_value = str(value or "")
    if len(text_value.encode("utf-8")) <= CRITICAL_TEXT_LIMIT:
        return text_value
    encoded = text_value.encode("utf-8")[: CRITICAL_TEXT_LIMIT - 3]
    return encoded.decode("utf-8", "ignore") + "..."


def critical_projection(paths: HarnessPaths, state: dict[str, Any]) -> dict[str, Any]:
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
        lane.get("status") in {"standby", "parked"} for lane in state.get("lanes", [])
    )
    active_requests = sorted(
        [
            request
            for request in state.get("coordination_requests", [])
            if request.get("status") not in TERMINAL_COORDINATION_STATUSES
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
            if request.get("status") not in TERMINAL_IMPROVEMENT_STATUSES
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
                "scope": _clip_critical(item.get("scope")),
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
                "next_action": _clip_critical(lane["next_action"]),
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
            for lane in lanes[:MAX_ENGAGED_LANES]
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
                "request": _clip_critical(request.get("request")),
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
                "problem": _clip_critical(item.get("problem")),
                "chief_recommendation": _clip_critical(
                    item.get("chief_recommendation")
                ),
            }
            for item in needs_user[:8]
        ],
        "open_hard_gates": sorted(
            dependency.get("dependency_id")
            for dependency in state.get("lane_dependencies", [])
            if dependency.get("kind") == "hard_gate" and dependency.get("status") == "open"
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
        },
        "full_state": {"path": str(state_path), "sha256": sha256_file(state_path)},
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    if len(raw) > CRITICAL_VIEW_MAX_BYTES:
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
    if len(raw) > CRITICAL_VIEW_MAX_BYTES:
        raise HarnessError("critical status projection exceeds 12 KiB")
    return payload


def cmd_reconcile(args: argparse.Namespace, paths: HarnessPaths) -> int:
    state_path = task_state_path(paths, args.task)
    state = load_task(paths, args.task)
    before_sha = sha256_file(state_path)
    observations: dict[str, Any] = {}
    if bool(args.observations) != bool(args.observations_sha):
        raise HarnessError("--observations and --observations-sha must be provided together")
    if args.observations:
        observation_path = Path(args.observations).resolve()
        expected_sha = str(args.observations_sha).lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
            raise HarnessError("observation SHA-256 must be full 64 hex")
        if not observation_path.is_file() or sha256_file(observation_path) != expected_sha:
            raise HarnessError("observation artifact is missing or has a SHA-256 mismatch")
        observations = load_json(observation_path)
        if observations.get("observation_version") != 1:
            raise HarnessError("observations require observation_version=1")
    packet_observations = observations.get("packets", {})
    job_observations = observations.get("jobs", {})

    def packet_classification(packet: dict[str, Any]) -> str:
        observed = packet_observations.get(packet.get("packet_id"), {}).get("state")
        return {
            "running": "live",
            "interrupted": "reattachable",
            "completed": "result_candidate",
            "absent": "orphan_candidate",
        }.get(observed, "unobserved")

    def job_classification(job: dict[str, Any]) -> str:
        observed = job_observations.get(job.get("run_id"), {}).get("state")
        return {
            "running": "live",
            "terminal": "terminal_candidate",
            "identity_mismatch": "identity_collision",
            "absent": "orphan_candidate",
            "unreachable": "unreachable",
        }.get(observed, "unobserved")

    lane_ids = [lane["lane_id"] for lane in state.get("lanes", [])]
    has_task_level_active = any(
        packet.get("status") in ACTIVE_PACKET_STATUSES and not packet.get("lane_id")
        for packet in state.get("packets", [])
    ) or any(
        job.get("status") in ACTIVE_JOB_STATUSES and not job.get("lane_id")
        for job in state.get("jobs", [])
    )
    if not lane_ids or has_task_level_active:
        lane_ids = ["_legacy_task"]
        lane_ids.extend(
            lane["lane_id"] for lane in state.get("lanes", [])
        )
    report = {
        "reconcile_version": 1,
        "task_id": state["task_id"],
        "task_revision": state["revision"],
        "state_sha256": before_sha,
        "lanes": [],
        "mutation_performed": False,
        "mutated": False,
    }
    for lane_id in sorted(lane_ids):
        packet_rows = [
            {
                "packet_id": packet["packet_id"],
                "status": packet["status"],
                "classification": packet_classification(packet),
            }
            for packet in state.get("packets", [])
            if packet.get("status") in ACTIVE_PACKET_STATUSES
            and (
                packet.get("lane_id") == lane_id
                or (lane_id == "_legacy_task" and not packet.get("lane_id"))
            )
        ]
        job_rows = [
            {
                "run_id": job["run_id"],
                "status": job["status"],
                "classification": job_classification(job),
            }
            for job in state.get("jobs", [])
            if job.get("status") in ACTIVE_JOB_STATUSES
            and (
                job.get("lane_id") == lane_id
                or (lane_id == "_legacy_task" and not job.get("lane_id"))
            )
        ]
        report["lanes"].append(
            {
                "lane_id": lane_id,
                "packets": sorted(packet_rows, key=lambda row: row["packet_id"]),
                "jobs": sorted(job_rows, key=lambda row: row["run_id"]),
            }
        )
    if sha256_file(state_path) != before_sha:
        raise HarnessError("read-only reconcile observed an unexpected task-state mutation")
    emit(report, args.json)
    return 0


def cmd_add_verification(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "add verification to")
        if args.lane_id:
            lane_by_id(state, args.lane_id)
        command = require_text(args.command or "", "verification command or method")
        boundary = require_text(args.boundary or "", "verification evidence boundary")
        if args.category not in VERIFICATION_CATEGORIES:
            raise HarnessError(f"unknown verification category: {args.category}")
        if state.get("profile") == "mini" and args.category in {
            "runtime_test",
            "numeric_runtime",
            "eda_runtime",
            "physical_evidence",
            "resource_governance",
        }:
            raise HarnessError(f"mini task may not record {args.category} evidence")
        if args.run_id:
            matches = [
                job for job in state.get("jobs", []) if job.get("run_id") == args.run_id
            ]
            if len(matches) != 1:
                raise HarnessError(
                    f"verification run id {args.run_id!r} does not name exactly one task job"
                )
            if args.status == "pass" and matches[0].get("status") != "pass":
                raise HarnessError("passing job-linked verification requires a passing job")
        if args.category in {"eda_runtime", "numeric_runtime", "physical_evidence"}:
            if not args.run_id:
                raise HarnessError(f"{args.category} verification requires --run-id")
        artifact_refs = []
        for value in args.artifact_ref:
            path_text, separator, digest = value.rpartition("=")
            if not separator:
                raise HarnessError("verification artifact ref must use absolute-path=sha256")
            path = Path(path_text).resolve()
            digest = digest.lower()
            if (
                not path.is_absolute()
                or not path.is_file()
                or path.is_symlink()
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or sha256_file(path) != digest
            ):
                raise HarnessError("verification artifact ref is missing or has a SHA-256 mismatch")
            artifact_refs.append(
                {"path": str(path), "sha256": digest, "size_bytes": path.stat().st_size}
            )
        review_packet = None
        if args.category == "independent_review":
            if not args.review_packet_id:
                raise HarnessError(
                    "independent_review verification requires --review-packet-id"
                )
            review_packet = _require_done_reviewer_packet(
                paths,
                state,
                args.review_packet_id,
                required_artifact_shas={item["sha256"] for item in artifact_refs},
            )
        elif args.review_packet_id:
            raise HarnessError(
                "--review-packet-id is accepted only for independent_review verification"
            )
        item = {
            "integrity_version": 1,
            "category": require_text(args.category, "category"),
            "status": args.status,
            "evidence": require_evidence_detail(args.evidence, "evidence"),
            "command": command,
            "boundary": boundary,
            "run_id": args.run_id or "",
            "lane_id": args.lane_id or "",
            "artifact_refs": artifact_refs,
            "recorded_at": now_iso(),
        }
        if review_packet is not None:
            item["review_packet_id"] = review_packet["packet_id"]
            item["review_result_sha256"] = review_packet["result_sha256"]
            item["reviewer_agent_id"] = review_packet["agent_id"]
        state.setdefault("verification", []).append(item)
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(item, args.json)
    return 0


def cmd_create_packet(args: argparse.Namespace, paths: HarnessPaths) -> int:
    packet_id = validate_id(args.packet_id, "packet id")
    task_type = validate_id(args.task_type, "packet task type")
    if args.packet_mode not in {"read_only", "bounded_mutation", "exact_command"}:
        raise HarnessError(f"invalid packet mode: {args.packet_mode}")
    if args.packet_mode == "exact_command":
        if not args.command_artifact or not args.command_sha256:
            raise HarnessError(
                "exact_command packet requires --command-artifact and --command-sha256"
            )
    elif args.command_artifact or args.command_sha256:
        raise HarnessError("command authority fields require packet_mode=exact_command")
    expected_tier = ROLE_TIER_MAP.get(args.agent_role)
    if expected_tier is None:
        raise HarnessError(
            "unknown agent role; choose one of: " + ", ".join(sorted(ROLE_TIER_MAP))
        )
    if args.delegation_depth == 1 and args.model_tier != expected_tier:
        raise HarnessError(
            f"role {args.agent_role} must use tier {expected_tier}, got {args.model_tier}"
        )
    if args.delegation_depth == 1 and any(
        (args.parent_packet_id, args.capability_tier, args.capacity_decision_id)
    ):
        raise HarnessError("depth-one packet may not consume depth-two capacity authority")
    if args.delegation_depth == 2:
        if args.agent_role not in DEPTH_TWO_ROLES:
            raise HarnessError("depth-two packet role must be batch, explorer, or worker")
        if not args.parent_packet_id or not args.capability_tier or not args.capacity_decision_id:
            raise HarnessError(
                "depth-two packet requires parent packet, capability tier, and capacity decision"
            )
        if CAPABILITY_TIER_MAP.get(args.capability_tier) != args.model_tier:
            raise HarnessError("packet model tier differs from requested capability tier")
    packet_locks = list(dict.fromkeys(normalize_lock(item) for item in args.lock))
    if args.packet_mode == "read_only" and packet_locks:
        raise HarnessError("read_only packet may not request mutation locks")
    if args.packet_mode in {"bounded_mutation", "exact_command"} and not packet_locks:
        raise HarnessError(f"{args.packet_mode} packet requires at least one owned lock")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "create packet for")
        if state.get("profile") == "mini":
            raise HarnessError("mini task may not create delegation packets")
        require_plan_ready(paths, state, "create packet")
        if args.lane_id:
            lane_by_id(state, args.lane_id)
        selection = _validate_active_execution_selection(
            state, args.lane_id or "", args.execution_selection_id or ""
        )
        skill_binding = _validate_skill_canary_work_unit_binding(
            state,
            args.skill_release_id or "",
            args.skill_canary_event_id or "",
            require_live_canary=True,
        )
        input_artifact_refs = []
        for value in args.input_artifact:
            path_text, separator, digest = value.rpartition("=")
            if not separator:
                raise HarnessError("packet input artifact must use absolute-path=sha256")
            path = Path(path_text).resolve()
            digest = digest.lower()
            if (
                not path.is_absolute()
                or not path.is_file()
                or path.is_symlink()
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or sha256_file(path) != digest
            ):
                raise HarnessError("packet input artifact is missing or has a SHA-256 mismatch")
            input_artifact_refs.append(
                {"path": str(path), "sha256": digest, "size_bytes": path.stat().st_size}
            )
        if args.capacity_review_source_id:
            source_review = capacity_review_by_id(state, args.capacity_review_source_id)
            dataset = source_review.get("dataset", {})
            if (
                source_review.get("status") != "data_ready"
                or args.lane_id != source_review.get("capacity_lane_id")
                or task_type != "capacity-analysis"
                or not any(
                    ref.get("path") == dataset.get("path")
                    and ref.get("sha256") == dataset.get("sha256")
                    for ref in input_artifact_refs
                )
            ):
                raise HarnessError(
                    "capacity analysis packet must bind its exact data_ready review dataset"
                )
        capacity_review: dict[str, Any] | None = None
        if args.delegation_depth == 2:
            if not args.lane_id:
                raise HarnessError("depth-two packet requires --lane-id")
            parent_matches = [
                packet
                for packet in state.get("packets", [])
                if packet.get("packet_id") == args.parent_packet_id
            ]
            if len(parent_matches) != 1:
                raise HarnessError("depth-two parent packet does not exist")
            parent = parent_matches[0]
            if (
                parent.get("status") != "dispatched"
                or int(parent.get("delegation_depth", 1)) != 1
                or parent.get("lane_id") != args.lane_id
                or parent.get("execution_selection_id", "")
                != (args.execution_selection_id or "")
            ):
                raise HarnessError(
                    "depth-two parent must be a dispatched depth-one packet in the same lane"
                )
            decision_matches = [
                review
                for review in state.get("capacity_reviews", [])
                if (review.get("chief_decision") or {}).get("decision_id")
                == args.capacity_decision_id
            ]
            if len(decision_matches) != 1:
                raise HarnessError("capacity decision id does not exist")
            capacity_review = decision_matches[0]
            scope = capacity_review.get("scope", {})
            recommendation = capacity_review.get("recommendation") or {}
            target = lane_by_id(state, args.lane_id)
            dataset = capacity_review.get("dataset", {})
            dataset_path = Path(str(dataset.get("path", "")))
            expected_dataset_path = (
                task_dir(paths, args.task)
                / "results"
                / f"capacity-dataset-{capacity_review.get('review_id')}.json"
            )
            current_records = _capacity_records(state, args.lane_id, task_type)
            if (
                capacity_review.get("status") != "acknowledged"
                or capacity_review.get("consumption") is not None
                or (capacity_review.get("chief_decision") or {}).get("decision") != "approved"
                or capacity_review.get("catalog_version") != CAPABILITY_CATALOG_VERSION
                or capacity_review.get("plan_sha256") != state.get("plan_sha256")
                or dataset_path != expected_dataset_path
                or not dataset_path.is_file()
                or dataset_path.is_symlink()
                or sha256_file(dataset_path) != dataset.get("sha256")
                or dataset.get("record_count") != len(current_records)
                or dataset.get("fingerprint") != _records_fingerprint(current_records)
                or scope.get("target_lane_id") != args.lane_id
                or scope.get("target_lane_revision") != target.get("revision")
                or scope.get("authority_commit") != target.get("authority_commit")
                or scope.get("contract_version") != target.get("contract_version")
                or scope.get("task_type") != task_type
                or scope.get("leaf_role") != args.agent_role
                or scope.get("target_depth") != 2
                or recommendation.get("capability_tier") != args.capability_tier
                or recommendation.get("requested_model_tier") != args.model_tier
            ):
                raise HarnessError("capacity decision is stale, consumed, or outside packet scope")
        if args.retry_of_packet_id:
            retry_matches = [
                packet
                for packet in state.get("packets", [])
                if packet.get("packet_id") == args.retry_of_packet_id
            ]
            if len(retry_matches) != 1:
                raise HarnessError("retry_of_packet_id must name one terminal packet")
            retry = retry_matches[0]
            if (
                retry.get("status") not in TERMINAL_PACKET_STATUSES
                or retry.get("lane_id", "") != (args.lane_id or "")
                or retry.get("task_type", "general") != task_type
                or retry.get("agent_role") != args.agent_role
            ):
                raise HarnessError("retry_of_packet_id must name one terminal packet")
        reserving = [
            claim
            for claim in claims_owned_by_task(paths, state["task_id"])
            if claim.get("status") in RESERVING_CLAIM_STATUSES
        ]
        held_locks = [lock for claim in reserving for lock in claim.get("locks", [])]
        unowned = [
            lock
            for lock in packet_locks
            if not any(lock_covers(held, lock) for held in held_locks)
        ]
        if unowned:
            raise HarnessError(
                "packet locks are not fully covered by this task's reserving claims: "
                + ", ".join(unowned)
            )
        destination = task_dir(paths, args.task) / "packets" / f"{packet_id}.md"
        if destination.exists():
            raise HarnessError(f"packet already exists: {packet_id}")
        command_record: dict[str, Any] = {}
        if args.packet_mode == "exact_command":
            expected_sha = str(args.command_sha256).lower()
            if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
                raise HarnessError("--command-sha256 must be a full 64-hex SHA-256")
            _, data = read_regular_artifact(
                args.command_artifact,
                "command artifact",
                max_bytes=COMMAND_ARTIFACT_MAX_BYTES,
                require_utf8=True,
            )
            actual_sha = hashlib.sha256(data).hexdigest()
            if actual_sha != expected_sha:
                raise HarnessError(
                    f"command artifact SHA-256 mismatch: expected {expected_sha}, actual {actual_sha}"
                )
            command_snapshot = (
                task_dir(paths, args.task) / "results" / f"packet-command-{packet_id}.txt"
            )
            atomic_write_bytes(command_snapshot, data)
            os.chmod(command_snapshot, 0o600)
            command_record = {
                "command_path": str(command_snapshot),
                "command_sha256": actual_sha,
                "command_size_bytes": len(data),
            }
        text = substitute(
            template_text(paths, "packet.md", PACKET_FALLBACK),
            {
                "PACKET_ID": packet_id,
                "TASK_ID": args.task,
                "AGENT_ROLE": require_text(args.agent_role, "agent role"),
                "MODEL_TIER": require_text(args.model_tier, "model tier"),
                "OBJECTIVE": require_text(args.objective, "objective"),
                "SCOPE": require_text(args.scope, "scope"),
                "LOCKS": ", ".join(packet_locks) or "read-only/no additional lock",
                "DELIVERABLE": require_text(args.deliverable, "deliverable"),
                "VALIDATION": require_text(args.validation, "validation"),
                "READ_FIRST": "\n".join(f"- {item}" for item in args.read_first)
                or "- Parent task plan and only the relevant source/evidence.",
            },
        )
        if command_record:
            text += (
                "\n## Exact command authority\n\n"
                f"- Path: `{command_record['command_path']}`\n"
                f"- SHA-256: `{command_record['command_sha256']}`\n"
                f"- Size: `{command_record['command_size_bytes']}` bytes\n"
            )
        atomic_write_text(destination, text)
        state.setdefault("packets", []).append(
            {
                "packet_id": packet_id,
                "path": str(destination),
                "agent_role": args.agent_role,
                "model_tier": args.model_tier,
                "lane_id": args.lane_id or "",
                "execution_selection_id": selection.get("selection_id", "")
                if selection
                else "",
                **(skill_binding or {}),
                "packet_schema_version": 3,
                "packet_mode": args.packet_mode,
                "task_type": task_type,
                "delegation_depth": args.delegation_depth,
                "parent_packet_id": args.parent_packet_id or "",
                "requested_capability_tier": args.capability_tier or "",
                "capacity_decision_id": args.capacity_decision_id or "",
                "retry_of_packet_id": args.retry_of_packet_id or "",
                "capacity_review_source_id": args.capacity_review_source_id or "",
                "input_artifact_refs": input_artifact_refs,
                **command_record,
                "locks": packet_locks,
                "created_at": now_iso(),
                "status": "ready",
            }
        )
        if capacity_review is not None:
            capacity_review["version"] = int(capacity_review["version"]) + 1
            capacity_review["status"] = "consumed"
            capacity_review["consumption"] = {
                "packet_id": packet_id,
                "decision_id": args.capacity_decision_id,
                "recorded_at": now_iso(),
            }
            capacity_review["updated_at"] = capacity_review["consumption"][
                "recorded_at"
            ]
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit({"packet_id": packet_id, "path": str(destination)}, args.json)
    return 0


def cmd_packet_update(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "update packet for")
        matches = [
            packet
            for packet in state.get("packets", [])
            if packet.get("packet_id") == args.packet_id
        ]
        if len(matches) != 1:
            raise HarnessError(
                f"expected exactly one packet named {args.packet_id}, found {len(matches)}"
            )
        packet = matches[0]
        previous_status = packet.get("status")
        if args.status == "dispatched":
            command_error = packet_command_integrity_error(packet)
            if command_error:
                raise HarnessError(command_error)
            _validate_active_execution_selection(
                state,
                str(packet.get("lane_id", "")),
                str(packet.get("execution_selection_id", "")),
            )
            _validate_skill_canary_work_unit_binding(
                state,
                str(packet.get("skill_release_id", "")),
                str(packet.get("skill_canary_event_id", "")),
                require_live_canary=True,
            )
        if previous_status in TERMINAL_PACKET_STATUSES:
            raise HarnessError(f"packet {args.packet_id} is already terminal")
        allowed_transitions = {
            "ready": {"dispatched", "cancelled"},
            "dispatched": {"dispatched", "done", "failed", "cancelled"},
        }
        if args.status not in allowed_transitions.get(str(previous_status), set()):
            raise HarnessError(
                f"invalid packet transition {previous_status!r} -> {args.status!r}"
            )
        existing_agent = str(packet.get("agent_id", ""))
        supplied_agent = str(args.agent_id or "")
        if existing_agent and supplied_agent and existing_agent != supplied_agent:
            raise HarnessError("packet agent id is immutable after dispatch")
        agent_id = existing_agent or supplied_agent
        if args.status == "dispatched" and not agent_id:
            raise HarnessError("dispatched packet requires --agent-id")
        if previous_status == "dispatched" and not agent_id:
            raise HarnessError("terminal packet transition requires the dispatched agent id")
        actual_pair = bool(args.actual_role) or bool(args.actual_model_tier)
        if actual_pair and not (args.actual_role and args.actual_model_tier):
            raise HarnessError("actual role and model tier must be recorded together")
        if actual_pair and not args.routing_evidence:
            raise HarnessError("actual routing verification requires --routing-evidence")
        if args.routing_evidence and not actual_pair:
            raise HarnessError("--routing-evidence requires actual role and model tier")
        if args.actual_role and args.actual_role != packet.get("agent_role"):
            raise HarnessError(
                f"actual role {args.actual_role} differs from requested {packet.get('agent_role')}"
            )
        if args.actual_model_tier and args.actual_model_tier != packet.get("model_tier"):
            raise HarnessError(
                "actual model tier differs from requested tier; do not claim routing verification"
            )
        if args.status in TERMINAL_PACKET_STATUSES:
            summary = require_text(args.summary or "", "terminal packet summary")
            if args.status in {"done", "failed"} and not args.evidence:
                raise HarnessError("done/failed packet requires at least one --evidence")
            terminal_evidence = [
                require_evidence_detail(item, "terminal packet evidence")
                for item in args.evidence
            ]
        elif args.summary or args.evidence:
            raise HarnessError("summary/evidence are accepted only for terminal packet status")

        packet["status"] = args.status
        packet["updated_at"] = now_iso()
        if args.status == "dispatched" and not packet.get("dispatched_at"):
            packet["dispatched_at"] = packet["updated_at"]
        if agent_id:
            packet["agent_id"] = agent_id
        if args.actual_role:
            packet["actual_role"] = args.actual_role
        if args.actual_model_tier:
            packet["actual_model_tier"] = args.actual_model_tier
        if args.routing_evidence:
            packet["routing_evidence"] = require_evidence_detail(
                args.routing_evidence, "routing evidence"
            )
        packet["routing_verified"] = bool(
            packet.get("agent_id")
            and packet.get("actual_role") == packet.get("agent_role")
            and packet.get("actual_model_tier") == packet.get("model_tier")
            and packet.get("routing_evidence")
        )
        if args.status in TERMINAL_PACKET_STATUSES:
            result = task_dir(paths, args.task) / "results" / f"{args.packet_id}.md"
            result_text = (
                f"# Sub-agent result — {args.packet_id}\n\n"
                f"- Status: `{args.status}`\n"
                f"- Requested role/tier: `{packet.get('agent_role')}` / "
                f"`{packet.get('model_tier')}`\n"
                f"- Actual role/tier: `{packet.get('actual_role') or 'unverified'}` / "
                f"`{packet.get('actual_model_tier') or 'unverified'}`\n"
                f"- Routing verified: `{str(packet['routing_verified']).lower()}`\n\n"
                f"- Routing evidence: {packet.get('routing_evidence') or 'Not exposed by platform.'}\n\n"
                "## Summary\n\n"
                f"{summary}\n\n"
                "## Evidence\n\n"
                + ("\n".join(f"- {item}" for item in terminal_evidence) or "- None recorded.")
                + "\n"
            )
            atomic_write_text(result, result_text)
            packet["summary"] = summary
            packet["evidence"] = terminal_evidence
            packet["result_path"] = str(result)
            packet["result_sha256"] = sha256_file(result)
            packet["integrity_version"] = 1
            packet["completed_at"] = now_iso()
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(packet, args.json)
    return 0


def cmd_packet_attest_result(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "attest packet result for")
        matches = [
            packet
            for packet in state.get("packets", [])
            if packet.get("packet_id") == args.packet_id
        ]
        if len(matches) != 1:
            raise HarnessError(
                f"expected exactly one packet named {args.packet_id}, found {len(matches)}"
            )
        packet = matches[0]
        if packet.get("status") not in TERMINAL_PACKET_STATUSES:
            raise HarnessError("only a terminal packet result can be attested")
        expected = task_dir(paths, args.task) / "results" / f"{args.packet_id}.md"
        if Path(str(packet.get("result_path", ""))) != expected or not expected.is_file():
            raise HarnessError("packet result path is missing or non-canonical")
        packet["result_sha256"] = sha256_file(expected)
        packet["integrity_version"] = 1
        packet["result_attestation"] = require_evidence_detail(
            args.evidence, "attestation evidence"
        )
        packet["attested_at"] = now_iso()
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(
        {
            "task_id": args.task,
            "packet_id": args.packet_id,
            "result_sha256": packet["result_sha256"],
        },
        args.json,
    )
    return 0


def _job_launch_authority_record(
    job: dict[str, Any],
    selection: dict[str, Any] | None,
    skill_binding: dict[str, str] | None,
) -> dict[str, Any]:
    lane_snapshot: dict[str, Any] = {}
    if selection is not None:
        lane_snapshot = next(
            dict(item)
            for item in selection.get("lane_snapshots", [])
            if item.get("lane_id") == job.get("lane_id")
        )
    record = {
        "integrity_version": 1,
        "execution_selection_id": selection.get("selection_id", "")
        if selection
        else "",
        "lane_id": str(job.get("lane_id", "")),
        "lane_snapshot": lane_snapshot,
        "skill_binding": dict(skill_binding or {}),
        "recorded_at": now_iso(),
    }
    record["authority_sha256"] = hashlib.sha256(
        json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()
    return record


def _job_launch_authority_errors(
    state: dict[str, Any], job: dict[str, Any]
) -> list[str]:
    if job.get("launch_authority_version") != 1:
        return []
    errors: list[str] = []
    events = job.get("launch_authority_events", [])
    if not isinstance(events, list):
        return [f"job {job.get('run_id')} launch authority events are malformed"]
    if job.get("status") == "pass" and not events:
        errors.append(f"passing job {job.get('run_id')} lacks launch authority")
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            errors.append(f"job {job.get('run_id')} launch event {index} is malformed")
            continue
        stored_sha = str(event.get("authority_sha256", ""))
        unhashed = dict(event)
        unhashed.pop("authority_sha256", None)
        actual_sha = hashlib.sha256(
            json.dumps(
                unhashed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        if event.get("integrity_version") != 1 or stored_sha != actual_sha:
            errors.append(f"job {job.get('run_id')} launch event {index} lost integrity")
            continue
        if (
            event.get("lane_id") != job.get("lane_id", "")
            or event.get("execution_selection_id")
            != job.get("execution_selection_id", "")
        ):
            errors.append(f"job {job.get('run_id')} launch event {index} changed authority")
            continue
        selection_id = str(event.get("execution_selection_id", ""))
        if selection_id:
            try:
                selection = execution_selection_by_id(state, selection_id)
                expected_snapshot = next(
                    dict(item)
                    for item in selection.get("lane_snapshots", [])
                    if item.get("lane_id") == job.get("lane_id")
                )
            except (HarnessError, StopIteration):
                errors.append(
                    f"job {job.get('run_id')} launch event {index} references missing authority"
                )
                continue
            if event.get("lane_snapshot") != expected_snapshot:
                errors.append(
                    f"job {job.get('run_id')} launch event {index} lane snapshot changed"
                )
        elif event.get("lane_snapshot"):
            errors.append(
                f"job {job.get('run_id')} launch event {index} has an unbound lane snapshot"
            )
        try:
            expected_binding = _validate_skill_canary_work_unit_binding(
                state,
                str(job.get("skill_release_id", "")),
                str(job.get("skill_canary_event_id", "")),
                require_live_canary=False,
            )
        except HarnessError as exc:
            errors.append(f"job {job.get('run_id')} launch event {index}: {exc}")
            continue
        if event.get("skill_binding") != dict(expected_binding or {}):
            errors.append(
                f"job {job.get('run_id')} launch event {index} skill binding changed"
            )
    return errors


def cmd_job_start(args: argparse.Namespace, paths: HarnessPaths) -> int:
    run_id = validate_id(args.run_id, "run id")
    work_root = require_absolute_posix(args.work_root, "work root")
    log = require_absolute_posix(args.log, "log")
    source_manifest = require_absolute_posix(args.source_manifest, "source manifest")
    tool_path = require_absolute_posix(args.tool_path, "tool path")
    source_sha = require_text(args.source_sha, "source SHA-256").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", source_sha):
        raise HarnessError("--source-sha must be the 64-hex SHA-256 of the source manifest")
    if args.status != "queued":
        raise HarnessError("job-start must record status queued before any launch")
    tool_version = require_text(args.tool_version, "tool version")
    command = require_text(args.command, "command")
    validate_source_receipt(
        Path(source_manifest),
        source_sha,
        tool_path=tool_path,
        tool_version=tool_version,
        command=command,
    )
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "start job for")
        if state.get("profile") == "mini":
            raise HarnessError("mini task may not launch or register EDA jobs")
        require_plan_ready(paths, state, "start EDA job")
        if args.lane_id:
            lane_by_id(state, args.lane_id)
        selection = _validate_active_execution_selection(
            state, args.lane_id or "", args.execution_selection_id or ""
        )
        skill_binding = _validate_skill_canary_work_unit_binding(
            state,
            args.skill_release_id or "",
            args.skill_canary_event_id or "",
            require_live_canary=True,
        )
        if any(job.get("run_id") == run_id for job in state.get("jobs", [])):
            raise HarnessError(f"run id already exists in task: {run_id}")
        held_locks = [
            lock
            for claim in claims_owned_by_task(paths, state["task_id"])
            if claim.get("status") in RESERVING_CLAIM_STATUSES
            for lock in claim.get("locks", [])
        ]
        required_output_locks = [f"eda:tree:{work_root}", f"eda:file:{log}"]
        unowned = [
            lock
            for lock in required_output_locks
            if not any(lock_covers(held, lock) for held in held_locks)
        ]
        if unowned:
            raise HarnessError(
                "EDA job output paths are not covered by this task's claims: "
                + ", ".join(unowned)
            )
        receipt_snapshot = (
            task_dir(paths, args.task) / "results" / f"source-receipt-{run_id}.json"
        )
        receipt_text = Path(source_manifest).read_text(encoding="utf-8")
        atomic_write_text(receipt_snapshot, receipt_text)
        if sha256_file(receipt_snapshot) != source_sha:
            raise HarnessError("source receipt snapshot SHA-256 changed during copy")
        command_snapshot = (
            task_dir(paths, args.task) / "results" / f"job-command-{run_id}.txt"
        )
        atomic_write_text(command_snapshot, command)
        os.chmod(command_snapshot, 0o600)
        command_sha = sha256_file(command_snapshot)
        job = {
            "integrity_version": 1,
            "job_schema_version": 2,
            "launch_authority_version": 1,
            "launch_authority_events": [],
            "run_id": run_id,
            "lane_id": args.lane_id or "",
            "execution_selection_id": selection.get("selection_id", "")
            if selection
            else "",
            **(skill_binding or {}),
            "host": require_text(args.host, "host"),
            "tool": require_text(args.tool, "tool"),
            "work_root": work_root,
            "status": args.status,
            "log": log,
            "pid": args.pid or "",
            "tmux": args.tmux or "",
            "stop_condition": require_text(args.stop_condition, "stop condition"),
            "source_sha": source_sha,
            "source_manifest": source_manifest,
            "source_receipt_path": str(receipt_snapshot),
            "tool_path": tool_path,
            "tool_version": tool_version,
            "command": command,
            "command_path": str(command_snapshot),
            "command_sha256": command_sha,
            "command_size_bytes": command_snapshot.stat().st_size,
            "success_exit_code": args.success_exit_code,
            "evidence": "queued before launch" if args.status == "queued" else "launch recorded",
            "started_at": now_iso(),
            "updated_at": now_iso(),
        }
        state.setdefault("jobs", []).append(job)
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(job, args.json)
    return 0


def cmd_job_update(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "update job for")
        matches = [job for job in state.get("jobs", []) if job.get("run_id") == args.run_id]
        if len(matches) != 1:
            raise HarnessError(f"expected exactly one job named {args.run_id}, found {len(matches)}")
        job = matches[0]
        previous_status = job.get("status")
        if previous_status in {"pass", "fail", "stopped"}:
            raise HarnessError(f"job {args.run_id} is already terminal")
        allowed_transitions = {
            "queued": {"running", "fail", "stopped", "unknown"},
            "running": {"pass", "fail", "stopped", "unknown"},
            "unknown": {"running", "pass", "fail", "stopped", "unknown"},
        }
        if args.status not in allowed_transitions.get(str(previous_status), set()):
            raise HarnessError(
                f"invalid job transition {previous_status!r} -> {args.status!r}"
            )
        launch_authority: dict[str, Any] | None = None
        if args.status == "running":
            selection = _validate_active_execution_selection(
                state,
                str(job.get("lane_id", "")),
                str(job.get("execution_selection_id", "")),
            )
            skill_binding = _validate_skill_canary_work_unit_binding(
                state,
                str(job.get("skill_release_id", "")),
                str(job.get("skill_canary_event_id", "")),
                require_live_canary=True,
            )
            launch_authority = _job_launch_authority_record(
                job, selection, skill_binding
            )
        evidence = require_evidence_detail(args.evidence, "job evidence")
        if args.status in {"pass", "fail", "stopped"} and args.exit_code is None:
            raise HarnessError("terminal job update requires --exit-code")
        if args.status in ACTIVE_JOB_STATUSES and args.exit_code is not None:
            raise HarnessError("queued/running/unknown job may not have a terminal exit code")
        pid = args.pid if args.pid is not None else job.get("pid", "")
        tmux = args.tmux if args.tmux is not None else job.get("tmux", "")
        if args.status == "running" and not (pid or tmux):
            raise HarnessError("running job requires a pid or tmux identity")
        if args.status == "pass" and args.exit_code != job.get("success_exit_code", 0):
            raise HarnessError(
                f"passing job requires exit code {job.get('success_exit_code', 0)}"
            )
        if args.status == "pass" and not job.get("launch_authority_events"):
            raise HarnessError(
                "passing job requires a prior topology/skill-validated running transition"
            )
        terminal_manifest: dict[str, Any] | None = None
        terminal_manifest_path: Path | None = None
        if args.status in {"pass", "fail", "stopped"}:
            if bool(args.terminal_log_artifact) != bool(args.terminal_log_sha256):
                raise HarnessError(
                    "--terminal-log-artifact and --terminal-log-sha256 must be provided together"
                )
            origin_path = Path(str(job.get("log", "")))
            capture_source = origin_path
            data: bytes | None = None
            if args.terminal_log_artifact:
                capture_source, data = read_regular_artifact(
                    args.terminal_log_artifact,
                    "staged terminal log artifact",
                    max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
                )
            else:
                try:
                    capture_source, data = read_regular_artifact(
                        origin_path,
                        "terminal log artifact",
                        max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
                    )
                except HarnessError:
                    data = None
            if data is not None:
                artifact_sha = hashlib.sha256(data).hexdigest()
                if args.terminal_log_sha256:
                    expected_sha = str(args.terminal_log_sha256).lower()
                    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
                        raise HarnessError("--terminal-log-sha256 must be full 64 hex")
                    if artifact_sha != expected_sha:
                        raise HarnessError(
                            "staged terminal log artifact SHA-256 does not match authority"
                        )
                blob_path = (
                    task_dir(paths, args.task)
                    / "results"
                    / f"artifact-sha256-{artifact_sha}.blob"
                )
                if blob_path.exists() and sha256_file(blob_path) != artifact_sha:
                    raise HarnessError("content-addressed terminal artifact path is corrupted")
                if not blob_path.exists():
                    atomic_write_bytes(blob_path, data)
                    os.chmod(blob_path, 0o600)
                artifact = {
                    "role": "primary_log",
                    "origin_path": str(origin_path),
                    "capture_source": str(capture_source),
                    "capture_status": "preserved",
                    "blob_path": str(blob_path),
                    "sha256": artifact_sha,
                    "size_bytes": len(data),
                }
            else:
                artifact = {
                    "role": "primary_log",
                    "origin_path": str(origin_path),
                    "capture_source": str(capture_source),
                    "capture_status": "missing_at_capture",
                    "blob_path": "",
                    "sha256": "",
                    "size_bytes": 0,
                }
            if args.status == "pass" and artifact["capture_status"] != "preserved":
                raise HarnessError(
                    "passing job requires a preserved primary log; stage remote logs with "
                    "--terminal-log-artifact and --terminal-log-sha256"
                )
            terminal_manifest = {
                "manifest_version": 1,
                "task_id": state["task_id"],
                "run_id": job["run_id"],
                "status": args.status,
                "exit_code": args.exit_code,
                "command_path": job.get("command_path"),
                "command_sha256": job.get("command_sha256"),
                "launch_authority_sha256": (
                    job.get("launch_authority_events", [{}])[-1].get(
                        "authority_sha256", ""
                    )
                    if args.status == "pass"
                    else ""
                ),
                "artifact": artifact,
                "recorded_at": now_iso(),
            }
            terminal_manifest_path = (
                task_dir(paths, args.task)
                / "results"
                / f"terminal-artifacts-{job['run_id']}.json"
            )
            atomic_write_json(terminal_manifest_path, terminal_manifest)
        job["status"] = args.status
        job["updated_at"] = now_iso()
        job["evidence"] = evidence
        job["exit_code"] = args.exit_code
        job["pid"] = pid
        job["tmux"] = tmux
        if launch_authority is not None:
            job["launch_authority_version"] = 1
            job.setdefault("launch_authority_events", []).append(launch_authority)
        if terminal_manifest is not None and terminal_manifest_path is not None:
            job["terminal_manifest_path"] = str(terminal_manifest_path)
            job["terminal_manifest_sha256"] = sha256_file(terminal_manifest_path)
            job["terminal_artifact_status"] = terminal_manifest["artifact"][
                "capture_status"
            ]
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(job, args.json)
    return 0


def cmd_set_delivery(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "set delivery for")
        detail = require_text(args.detail, "delivery detail")
        commit = args.commit or ""
        if args.mode == "pushed":
            if not COMMIT_RE.fullmatch(commit):
                raise HarnessError("pushed delivery requires a 7-64 hex --commit")
            if not args.remote or not args.remote_ref:
                raise HarnessError("pushed delivery requires --remote and --remote-ref")
            worktree_errors, current = worktree_integrity_errors(paths, state)
            if worktree_errors or current is None:
                raise HarnessError(
                    "task worktree identity is not current: " + "; ".join(worktree_errors)
                )
            try:
                result = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(state_worktree(paths, state)),
                        "rev-parse",
                        f"{commit}^{{commit}}",
                    ],
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=10,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise HarnessError(f"could not resolve pushed commit: {exc}") from exc
            if result.returncode != 0:
                raise HarnessError(f"pushed commit is not present in task worktree: {commit}")
            commit = result.stdout.strip().lower()
            if not FULL_COMMIT_RE.fullmatch(commit):
                raise HarnessError("could not resolve pushed commit to a full commit id")
            if current["head_sha"] != commit:
                raise HarnessError(
                    f"pushed commit {commit} is not the recorded worktree HEAD {current['head_sha']}"
                )
            remote_sha = remote_ref_tip(
                state_worktree(paths, state), args.remote, args.remote_ref
            )
            if remote_sha != commit:
                raise HarnessError(
                    f"remote {args.remote} {args.remote_ref} points to {remote_sha}, not {commit}"
                )
        elif commit or args.remote or args.remote_ref:
            raise HarnessError(
                "--commit/--remote/--remote-ref are valid only with --mode pushed"
            )
        state["delivery"] = {
            "mode": args.mode,
            "detail": detail,
            "commit": commit,
            "remote": args.remote or "",
            "remote_ref": args.remote_ref or "",
            "remote_sha": commit if args.mode == "pushed" else "",
            "verified_at": now_iso() if args.mode == "pushed" else "",
        }
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(state["delivery"], args.json)
    return 0


def close_gate(paths: HarnessPaths, state: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if not state.get("completion_boundary"):
        failures.append("completion boundary is empty")
    checkpoint_ok, checkpoint_reason = checkpoint_matches(paths, state)
    if not checkpoint_ok:
        failures.append(f"checkpoint is stale: {checkpoint_reason}")
    try:
        require_plan_ready(paths, state, "close task")
    except HarnessError as exc:
        failures.append(str(exc))
    referenced = set(state.get("claims", []))
    owned_claims = claims_owned_by_task(paths, state["task_id"])
    owned_tokens = {str(claim.get("token")) for claim in owned_claims}
    missing_membership = sorted(owned_tokens - referenced)
    missing_claims = sorted(referenced - owned_tokens)
    if missing_membership:
        failures.append("orphan claims owned by task: " + ", ".join(missing_membership))
    if missing_claims:
        failures.append("task references missing claims: " + ", ".join(missing_claims))
    claims = owned_claims
    nonterminal = [
        str(claim.get("token"))
        for claim in claims
        if claim.get("status") not in TERMINAL_CLAIM_STATUSES
    ]
    if nonterminal:
        failures.append("non-terminal claims: " + ", ".join(nonterminal))
    running = [
        str(job.get("run_id"))
        for job in state.get("jobs", [])
        if job.get("status") in ACTIVE_JOB_STATUSES
    ]
    if running:
        failures.append("unresolved queued/running/unknown jobs: " + ", ".join(running))
    active_packets = [
        str(packet.get("packet_id"))
        for packet in state.get("packets", [])
        if packet.get("status") in ACTIVE_PACKET_STATUSES
    ]
    if active_packets:
        failures.append("unfinished delegation packets: " + ", ".join(active_packets))
    failures.extend(packet_integrity_errors(paths, state))
    failures.extend(job_integrity_errors(paths, state))
    failures.extend(verification_integrity_errors(state))
    failures.extend(portfolio_integrity_errors(state, paths))
    unresolved_coordination = [
        str(request.get("request_id"))
        for request in state.get("coordination_requests", [])
        if request.get("status") not in TERMINAL_COORDINATION_STATUSES
    ]
    if unresolved_coordination:
        failures.append(
            "unresolved coordination requests: " + ", ".join(unresolved_coordination)
        )
    open_hard_dependencies = [
        str(dependency.get("dependency_id"))
        for dependency in state.get("lane_dependencies", [])
        if dependency.get("kind") == "hard_gate" and dependency.get("status") == "open"
    ]
    if open_hard_dependencies:
        failures.append(
            "open hard-gate dependencies: " + ", ".join(open_hard_dependencies)
        )
    blocking_improvements = [
        str(request.get("request_id"))
        for request in state.get("improvement_requests", [])
        if request.get("release_blocking")
        and request.get("status") not in TERMINAL_IMPROVEMENT_STATUSES
    ]
    if blocking_improvements:
        failures.append(
            "unresolved release-blocking improvements: " + ", ".join(blocking_improvements)
        )
    open_cross_sessions = [
        str(item.get("cross_lane_session_id"))
        for item in state.get("cross_lane_sessions", [])
        if item.get("status") == "open"
    ]
    if open_cross_sessions:
        failures.append(
            "open controlled cross-lane sessions: " + ", ".join(open_cross_sessions)
        )
    open_user_escalations = [
        str(item.get("escalation_id"))
        for item in state.get("needs_user_escalations", [])
        if item.get("status") == "needs_user"
    ]
    if open_user_escalations:
        failures.append(
            "unresolved needs-user escalations: " + ", ".join(open_user_escalations)
        )
    worktree_errors, _ = worktree_integrity_errors(paths, state)
    failures.extend(worktree_errors)
    verification = state.get("verification", [])
    if not verification:
        failures.append("no verification/evidence record")
    if verification and not any(
        item.get("integrity_version") == 1
        and item.get("status") == "pass"
        and item.get("category") in CLOSE_QUALIFYING_CATEGORIES
        for item in verification
    ):
        failures.append(
            "achieved outcome requires at least one passing, close-qualifying verification"
        )
    unaccounted = [
        str(item.get("category"))
        for item in verification
        if item.get("status") not in ACCOUNTED_VERIFICATION_STATUSES
    ]
    if unaccounted:
        failures.append("unaccounted verification: " + ", ".join(unaccounted))
    failures.extend(delivery_integrity_errors(paths, state, verify_remote=True))
    return failures


def cmd_close_task(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "close")
        failures = close_gate(paths, state)
        if failures:
            raise HarnessError("close gate failed:\n- " + "\n- ".join(failures))
        state["status"] = "done"
        state["phase"] = "closing"
        state["outcome"] = "achieved"
        state.setdefault("facts", []).append(require_text(args.summary, "summary"))
        state["next_action"] = args.next_action or "No further action; task closed."
        bump_task(state, checkpoint_required=False)
        state["checkpoint_revision"] = state["revision"]
        state["checkpoint_required"] = False
        state["closed_at"] = now_iso()
        _, current = worktree_integrity_errors(paths, state)
        if current:
            state["closed_head_sha"] = current["head_sha"]
        checkpoint = commit_checkpoint(paths, state)
        unbind_all_sessions_unlocked(paths, state)
        write_index(paths)
    emit(
        {"task_id": args.task, "status": "done", "checkpoint": str(checkpoint)},
        args.json,
    )
    return 0


def cmd_block_task(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "block")
        blocker = require_text(args.blocker, "blocker")
        next_action = require_text(args.next_action, "next action")
        _extend_unique(state, "blockers", [blocker])
        state["status"] = "blocked"
        state["outcome"] = "blocked"
        state["next_action"] = next_action
        bump_task(state, checkpoint_required=False)
        state["checkpoint_revision"] = state["revision"]
        state["checkpoint_required"] = False
        checkpoint = commit_checkpoint(paths, state)
        write_index(paths)
    emit(
        {"task_id": args.task, "status": "blocked", "checkpoint": str(checkpoint)},
        args.json,
    )
    return 0


def cmd_cancel_task(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "cancel")
        reason = require_text(args.reason, "cancellation reason")
        owned_claims = claims_owned_by_task(paths, state["task_id"])
        nonterminal = [
            str(claim.get("token"))
            for claim in owned_claims
            if claim.get("status") not in TERMINAL_CLAIM_STATUSES
        ]
        active_jobs = [
            str(job.get("run_id"))
            for job in state.get("jobs", [])
            if job.get("status") in ACTIVE_JOB_STATUSES
        ]
        active_packets = [
            str(packet.get("packet_id"))
            for packet in state.get("packets", [])
            if packet.get("status") in ACTIVE_PACKET_STATUSES
        ]
        failures = []
        if nonterminal:
            failures.append("non-terminal claims: " + ", ".join(nonterminal))
        if active_jobs:
            failures.append("unresolved jobs: " + ", ".join(active_jobs))
        if active_packets:
            failures.append("unfinished packets: " + ", ".join(active_packets))
        if state.get("delivery", {}).get("mode") == "pending":
            failures.append("delivery disposition is pending")
        failures.extend(packet_integrity_errors(paths, state))
        failures.extend(job_integrity_errors(paths, state))
        worktree_errors, _ = worktree_integrity_errors(paths, state)
        failures.extend(worktree_errors)
        if failures:
            raise HarnessError("cancel gate failed:\n- " + "\n- ".join(failures))
        _extend_unique(state, "blockers", [f"CANCELLED: {reason}"])
        state["status"] = "cancelled"
        state["phase"] = "closing"
        state["outcome"] = "cancelled"
        state["next_action"] = args.next_action or "No further action; task cancelled."
        state["cancelled_at"] = now_iso()
        bump_task(state, checkpoint_required=False)
        state["checkpoint_revision"] = state["revision"]
        state["checkpoint_required"] = False
        checkpoint = commit_checkpoint(paths, state)
        unbind_all_sessions_unlocked(paths, state)
        write_index(paths)
    emit(
        {"task_id": args.task, "status": "cancelled", "checkpoint": str(checkpoint)},
        args.json,
    )
    return 0


def resolve_resume_task(
    paths: HarnessPaths, task_id: str | None, session_id: str | None
) -> dict[str, Any]:
    if task_id:
        return load_task(paths, task_id)
    if session_id:
        mapping = load_json(session_path(paths, check_session_id(session_id)))
        return load_task(paths, str(mapping.get("task_id")))
    raise HarnessError("provide --task or --session-id")


def cmd_resume(args: argparse.Namespace, paths: HarnessPaths) -> int:
    state = resolve_resume_task(paths, args.task, args.session_id)
    checkpoint_path = task_dir(paths, state["task_id"]) / "checkpoint.md"
    checkpoint_ok, checkpoint_reason = checkpoint_matches(paths, state)
    try:
        plan_current = bool(
            state.get("plan_ready") and state.get("plan_sha256") == plan_digest(paths, state)
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
                    f"checkpoint is stale: {checkpoint_reason}" if not checkpoint_ok else "",
                    "plan is not approved/current" if not plan_current else "",
                    "task is not active" if state.get("status") not in {"active", "blocked"} else "",
                )
                if warning
            ],
        }
    )
    emit(payload, args.json)
    return 0


def cmd_status(args: argparse.Namespace, paths: HarnessPaths) -> int:
    if args.critical:
        if not args.task:
            raise HarnessError("status --critical requires --task")
        emit(critical_projection(paths, load_task(paths, args.task)), args.json)
        return 0
    if args.task:
        emit(task_summary(load_task(paths, args.task)), args.json)
        return 0
    ensure_layout(paths)
    tasks = load_all_tasks(paths)
    claims = load_all_claims(paths)
    structured = [claim for claim in claims if not claim.get("legacy")]
    legacy = [claim for claim in claims if claim.get("legacy")]
    payload: dict[str, Any] = {
        "root": str(paths.root),
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
            [claim for claim in legacy if claim.get("status") in RESERVING_CLAIM_STATUSES]
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
    emit(payload, args.json)
    return 0


def cmd_render_index(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        write_index(paths)
    emit({"index": str(paths.index)}, args.json)
    return 0


def _check_json_file(path: Path, errors: list[str]) -> None:
    try:
        load_json(path)
    except HarnessError as exc:
        errors.append(str(exc))


def _backup_sources(paths: HarnessPaths) -> list[tuple[str, Path]]:
    sources: list[tuple[str, Path]] = []

    def add_file(archive_name: str, source: Path) -> None:
        if not source.exists():
            return
        if source.is_symlink() or not source.is_file() or source.stat().st_nlink != 1:
            raise HarnessError(f"backup source must be one regular non-linked file: {source}")
        sources.append((archive_name, source))

    def add_tree(prefix: str, source_root: Path) -> None:
        if not source_root.exists():
            return
        for source in sorted(source_root.rglob("*"), key=lambda item: item.as_posix()):
            if source.name == ".state.lock" or "__pycache__" in source.parts:
                continue
            if source.suffix == ".pyc":
                continue
            if source.is_symlink():
                raise HarnessError(f"backup source tree contains symlink: {source}")
            if source.is_file():
                if source.stat().st_nlink != 1:
                    raise HarnessError(f"backup source has multiple hard links: {source}")
                relative = source.relative_to(source_root).as_posix()
                sources.append((f"{prefix}/{relative}", source))

    add_file("repo/AGENTS.md", paths.root / "AGENTS.md")
    add_tree("repo/notes/harness", paths.harness)
    for name in ("arise_harness.py", "harnesslib.py", "codex_hook.py", "test_arise_harness.py"):
        add_file(f"repo/scripts/harness/{name}", paths.root / "scripts" / "harness" / name)
    for name in ("config.toml", "hooks.json"):
        add_file(f"repo/.codex/{name}", paths.root / ".codex" / name)
    relay_root = Path(
        os.environ.get("ARISE_HARNESS_RELAY_ROOT", "/mnt/d/workspace/project")
    ).resolve()
    for name in ("config.toml", "hooks.json"):
        add_file(f"external/windows-relay/.codex/{name}", relay_root / ".codex" / name)
    skill = Path(
        os.environ.get(
            "ARISE_HARNESS_SKILL_PATH",
            "/opt/aoi/skills/aoi/SKILL.md",
        )
    )
    add_file("external/personal-skill/arise-harness/SKILL.md", skill)
    names = [name for name, _ in sources]
    if len(names) != len(set(names)):
        raise HarnessError("backup allowlist produced duplicate archive names")
    return sorted(sources, key=lambda item: item[0])


def _tarinfo(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o600
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    return info


def _build_backup_archive(paths: HarnessPaths) -> tuple[bytes, dict[str, Any]]:
    members: list[tuple[str, bytes]] = []
    manifest_members: list[dict[str, Any]] = []
    for name, source in _backup_sources(paths):
        payload = source.read_bytes()
        members.append((name, payload))
        manifest_members.append(
            {"path": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        )
    manifest = {"format_version": 1, "members": manifest_members}
    manifest_bytes = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        + b"\n"
    )
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        archive.addfile(_tarinfo("manifest.json", len(manifest_bytes)), io.BytesIO(manifest_bytes))
        for name, payload in members:
            archive.addfile(_tarinfo(name, len(payload)), io.BytesIO(payload))
    gzip_buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=gzip_buffer, mtime=0) as zipped:
        zipped.write(tar_buffer.getvalue())
    return gzip_buffer.getvalue(), manifest


def verify_backup(archive_path: Path, sidecar_path: Path) -> dict[str, Any]:
    sidecar = load_json(sidecar_path)
    archive_sha = sha256_file(archive_path)
    if sidecar.get("format_version") != 1 or sidecar.get("archive_sha256") != archive_sha:
        raise HarnessError("backup sidecar does not match archive SHA-256")
    seen: dict[str, bytes] = {}
    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if (
                not member.isfile()
                or path.is_absolute()
                or ".." in path.parts
                or member.name in seen
            ):
                raise HarnessError(f"unsafe or duplicate backup member: {member.name}")
            handle = archive.extractfile(member)
            if handle is None:
                raise HarnessError(f"backup member cannot be read: {member.name}")
            seen[member.name] = handle.read()
    manifest_bytes = seen.pop("manifest.json", None)
    if manifest_bytes is None:
        raise HarnessError("backup archive lacks manifest.json")
    if hashlib.sha256(manifest_bytes).hexdigest() != sidecar.get("manifest_sha256"):
        raise HarnessError("backup internal manifest SHA-256 mismatch")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HarnessError(f"invalid backup internal manifest: {exc}") from exc
    members = manifest.get("members")
    if manifest.get("format_version") != 1 or not isinstance(members, list):
        raise HarnessError("backup internal manifest has an unsupported schema")
    expected: dict[str, dict[str, Any]] = {}
    for item in members:
        if not isinstance(item, dict):
            raise HarnessError("backup internal manifest member is not an object")
        name = str(item.get("path", ""))
        path = PurePosixPath(name)
        if not name or path.is_absolute() or ".." in path.parts or name in expected:
            raise HarnessError(f"unsafe or duplicate backup manifest member: {name!r}")
        expected[name] = item
    if set(expected) != set(seen):
        raise HarnessError("backup member set differs from internal manifest")
    if sidecar.get("member_count") != len(expected):
        raise HarnessError("backup sidecar member count differs from internal manifest")
    for name, payload in seen.items():
        item = expected[name]
        if item.get("size") != len(payload) or item.get("sha256") != hashlib.sha256(
            payload
        ).hexdigest():
            raise HarnessError(f"backup member hash mismatch: {name}")
    return {
        "archive": str(archive_path),
        "archive_sha256": archive_sha,
        "manifest": str(sidecar_path),
        "member_count": len(seen),
        "verified": True,
    }


def cmd_backup_state(args: argparse.Namespace, paths: HarnessPaths) -> int:
    configured_raw = Path(
        os.environ.get(
            "ARISE_HARNESS_BACKUP_ROOT", "/mnt/d/workspace/project/backups/harness"
        )
    ).expanduser()
    requested_raw = Path(args.destination).expanduser() if args.destination else configured_raw
    if not configured_raw.is_absolute() or not requested_raw.is_absolute():
        raise HarnessError("backup root and destination must be absolute paths")
    if ".." in requested_raw.parts:
        raise HarnessError("backup destination may not contain '..'")
    configured_root = configured_raw.resolve()
    destination = requested_raw.resolve()
    if destination != configured_root and configured_root not in destination.parents:
        raise HarnessError(f"backup destination must stay within {configured_root}")
    if destination == paths.root or paths.root in destination.parents:
        raise HarnessError("backup destination may not be inside the implementation repo")
    current = requested_raw
    while True:
        if current.exists() and current.is_symlink():
            raise HarnessError(f"backup destination path may not contain symlinks: {current}")
        if current == configured_raw or current.parent == current:
            break
        current = current.parent
    destination.mkdir(parents=True, exist_ok=True)
    with state_lock(paths):
        archive_bytes, manifest = _build_backup_archive(paths)
    archive_sha = hashlib.sha256(archive_bytes).hexdigest()
    archive_path = destination / f"arise-harness-state-{archive_sha[:16]}.tar.gz"
    sidecar_path = archive_path.with_suffix(archive_path.suffix + ".manifest.json")
    manifest_bytes = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        + b"\n"
    )
    sidecar = {
        "format_version": 1,
        "archive": archive_path.name,
        "archive_sha256": archive_sha,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "member_count": len(manifest["members"]),
        "durability_boundary": "Windows-side same-host recovery copy; not off-host disaster recovery",
    }
    if archive_path.exists() or sidecar_path.exists():
        if not (archive_path.exists() and sidecar_path.exists()):
            raise HarnessError("backup publication is incomplete; archive/sidecar pair differs")
        result = verify_backup(archive_path, sidecar_path)
        result["existing"] = True
        emit(result, args.json)
        return 0
    atomic_write_bytes(archive_path, archive_bytes)
    atomic_write_json(sidecar_path, sidecar)
    fsync_directory(destination)
    result = verify_backup(archive_path, sidecar_path)
    result["existing"] = False
    emit(result, args.json)
    return 0


def cmd_verify_backup(args: argparse.Namespace, paths: HarnessPaths) -> int:
    sidecar = Path(args.manifest).resolve()
    payload = load_json(sidecar)
    archive_name = require_text(str(payload.get("archive", "")), "archive name")
    archive_posix = PurePosixPath(archive_name)
    if archive_posix.name != archive_name or "\\" in archive_name:
        raise HarnessError("backup sidecar archive must be a plain filename")
    archive = sidecar.parent / archive_name
    result = verify_backup(archive, sidecar)
    emit(result, args.json)
    return 0


def cmd_doctor(args: argparse.Namespace, paths: HarnessPaths) -> int:
    ensure_layout(paths)
    errors: list[str] = []
    warnings: list[str] = []
    scoped = bool(args.task)
    if scoped:
        try:
            task = load_task(paths, args.task)
            tasks = [task]
            claims = referenced_claims(paths, task)
        except HarnessError as exc:
            tasks = []
            claims = []
            errors.append(str(exc))
    else:
        try:
            tasks = load_all_tasks(paths)
        except HarnessError as exc:
            tasks = []
            errors.append(str(exc))
        try:
            claims = load_all_claims(paths)
        except HarnessError as exc:
            claims = []
            errors.append(str(exc))

    seen: dict[str, str] = {}
    structured_by_task: dict[str, set[str]] = {}
    for claim in claims:
        token = str(claim.get("token"))
        if token in seen:
            errors.append(f"duplicate claim token {token}: {seen[token]} and {claim.get('_path')}")
        seen[token] = str(claim.get("_path"))
        if claim.get("status") in RESERVING_CLAIM_STATUSES and is_expired(
            claim.get("expires_at")
        ):
            warnings.append(f"expired but still reserving: {token}")
        if claim.get("legacy") and claim.get("scope_parse_warnings"):
            warnings.append(f"legacy scope needs audit: {token}")
        if not claim.get("legacy"):
            task_id = str(claim.get("task_id", ""))
            structured_by_task.setdefault(task_id, set()).add(token)

    task_ids = {task["task_id"] for task in tasks}
    for task in tasks:
        task_id = task["task_id"]
        referenced = set(task.get("claims", []))
        owned = structured_by_task.get(task_id, set())
        for token in sorted(referenced - owned):
            errors.append(f"task {task_id} references missing/foreign claim {token}")
        for token in sorted(owned - referenced):
            errors.append(f"active/archive orphan claim {token} is absent from task {task_id}")

        if task.get("profile") == "mini":
            if len(referenced) != 1:
                errors.append(f"mini task {task_id} must reference exactly one claim")
            if task.get("packets") or task.get("jobs"):
                errors.append(f"mini task {task_id} may not contain packets or jobs")
            for claim in claims:
                if claim.get("task_id") != task_id:
                    continue
                try:
                    if validate_mini_locks(claim.get("locks", [])) != claim.get("locks", []):
                        errors.append(f"mini task {task_id} claim locks are not canonical")
                except HarnessError as exc:
                    errors.append(f"mini task {task_id}: {exc}")

        checkpoint_ok, checkpoint_reason = checkpoint_matches(paths, task)
        if not checkpoint_ok:
            message = f"checkpoint mismatch for {task_id}: {checkpoint_reason}"
            if task.get("status") in {"done", "cancelled"} or not task.get(
                "checkpoint_required", True
            ):
                errors.append(message)
            else:
                warnings.append(message)

        try:
            actual_plan_sha = plan_digest(paths, task)
            if task.get("plan_ready") and task.get("plan_sha256") != actual_plan_sha:
                errors.append(f"approved plan changed for {task_id}")
            if not task.get("plan_ready") and task.get("status") in {"active", "blocked"}:
                warnings.append(f"plan is not approved: {task_id}")
        except HarnessError as exc:
            errors.append(str(exc))

        worktree = state_worktree(paths, task)
        if task.get("status") in {"active", "blocked"}:
            task_worktree_errors, _ = worktree_integrity_errors(paths, task)
            errors.extend(f"task {task_id}: {item}" for item in task_worktree_errors)
        elif not worktree.is_dir():
            errors.append(f"task worktree is missing for {task_id}: {worktree}")

        errors.extend(
            f"task {task_id}: {item}" for item in portfolio_integrity_errors(task, paths)
        )

        if task.get("status") in {"active", "blocked"}:
            errors.extend(
                f"task {task_id}: {item}"
                for item in packet_integrity_errors(paths, task)
            )
            errors.extend(
                f"task {task_id}: {item}" for item in job_integrity_errors(paths, task)
            )
            errors.extend(
                f"task {task_id}: {item}" for item in verification_integrity_errors(task)
            )
        else:
            # Grandfather only records that explicitly predate integrity v1.
            # Once a terminal artifact has a v1 attestation, any later mismatch
            # remains a doctor error even though the task is already closed.
            for packet in task.get("packets", []):
                packet_state = {**task, "packets": [packet]}
                destination = (
                    warnings if packet.get("integrity_version") != 1 else errors
                )
                prefix = (
                    "legacy terminal task" if destination is warnings else "terminal task"
                )
                destination.extend(
                    f"{prefix} {task_id}: {item}"
                    for item in packet_integrity_errors(paths, packet_state)
                )
            for job in task.get("jobs", []):
                job_state = {**task, "jobs": [job]}
                destination = warnings if job.get("integrity_version") != 1 else errors
                prefix = (
                    "legacy terminal task" if destination is warnings else "terminal task"
                )
                destination.extend(
                    f"{prefix} {task_id}: {item}"
                    for item in job_integrity_errors(paths, job_state)
                )
            for item in task.get("verification", []):
                verification_state = {**task, "verification": [item]}
                destination = (
                    warnings if item.get("integrity_version") != 1 else errors
                )
                prefix = (
                    "legacy terminal task" if destination is warnings else "terminal task"
                )
                destination.extend(
                    f"{prefix} {task_id}: {message}"
                    for message in verification_integrity_errors(verification_state)
                )

        for packet in task.get("packets", []):
            packet_id = packet.get("packet_id")
            role = packet.get("agent_role")
            tier = packet.get("model_tier")
            if role not in ROLE_TIER_MAP or ROLE_TIER_MAP.get(role) != tier:
                errors.append(f"packet {task_id}/{packet_id} has invalid role/tier")
            if packet.get("status") not in PACKET_STATUSES:
                errors.append(f"packet {task_id}/{packet_id} has invalid status")
            if packet.get("status") in TERMINAL_PACKET_STATUSES:
                if not packet.get("routing_verified"):
                    warnings.append(
                        f"packet routing is unverified: {task_id}/{packet_id} "
                        f"requested {role}/{tier}"
                    )

        if task.get("delivery", {}).get("mode") == "pushed":
            errors.extend(
                f"task {task_id}: {item}"
                for item in delivery_integrity_errors(paths, task, verify_remote=True)
            )

    for claim in claims:
        if not claim.get("legacy") and claim.get("task_id") not in task_ids:
            errors.append(
                f"claim {claim.get('token')} references missing task {claim.get('task_id')}"
            )

    mappings: dict[str, dict[str, Any]] = {}
    if scoped:
        mapping_paths = []
        for task in tasks:
            for session_id in task.get("session_ids", []):
                candidate = session_path(paths, session_id)
                if task.get("status") in {"active", "blocked"} or candidate.exists():
                    mapping_paths.append(candidate)
    else:
        mapping_paths = list(paths.sessions.glob("*.json"))
    for mapping_path in mapping_paths:
        try:
            mapping = load_json(mapping_path)
            session_id = str(mapping.get("session_id", ""))
            if session_path(paths, session_id) != mapping_path:
                errors.append(f"session mapping filename/hash mismatch: {mapping_path}")
            if (
                scoped
                and all(task.get("status") in {"done", "cancelled"} for task in tasks)
                and mapping.get("task_id") not in task_ids
            ):
                continue
            mappings[session_id] = mapping
            if mapping.get("task_id") not in task_ids:
                errors.append(
                    f"session mapping {mapping_path.name} references missing task {mapping.get('task_id')}"
                )
            else:
                task = next(item for item in tasks if item["task_id"] == mapping.get("task_id"))
                if task.get("status") in {"done", "cancelled"}:
                    errors.append(
                        f"session {session_id} remains mapped to closed task {task['task_id']}"
                    )
                if session_id not in task.get("session_ids", []):
                    errors.append(
                        f"session {session_id} mapping lacks backlink in task {task['task_id']}"
                    )
        except HarnessError as exc:
            errors.append(str(exc))

    for task in tasks:
        if task.get("status") not in {"active", "blocked"}:
            continue
        for session_id in task.get("session_ids", []):
            if mappings.get(session_id, {}).get("task_id") != task["task_id"]:
                errors.append(
                    f"task {task['task_id']} backlink has no matching session mapping: {session_id}"
                )

    relay_root = Path(
        os.environ.get("ARISE_HARNESS_RELAY_ROOT", "/mnt/d/workspace/project")
    ).resolve()
    config_paths = [
        paths.root / ".codex" / "config.toml",
        relay_root / ".codex" / "config.toml",
    ]
    hook_paths = [
        paths.root / ".codex" / "hooks.json",
        relay_root / ".codex" / "hooks.json",
    ]
    for path in config_paths:
        if not path.exists():
            warnings.append(f"missing project config layer: {path}")
            continue
        try:
            config = tomllib.loads(path.read_text(encoding="utf-8"))
            if config.get("features", {}).get("hooks") is not True:
                errors.append(f"hooks feature is not enabled in {path}")
        except (OSError, tomllib.TOMLDecodeError) as exc:
            errors.append(f"invalid TOML {path}: {exc}")
    hook_payloads: list[dict[str, Any]] = []
    for path in hook_paths:
        if not path.exists():
            warnings.append(f"missing hook layer: {path}")
        else:
            _check_json_file(path, errors)
            try:
                hook_payloads.append(load_json(path))
            except HarnessError:
                pass
    if len(hook_payloads) == 2 and hook_paths[0].read_bytes() != hook_paths[1].read_bytes():
        errors.append("WSL and Windows relay hook definitions differ")
    expected_events = {"SessionStart", "UserPromptSubmit", "SubagentStart", "Stop"}
    for path, payload in zip(hook_paths, hook_payloads):
        hooks = payload.get("hooks", {})
        if set(hooks) != expected_events:
            errors.append(f"unexpected hook event set in {path}: {sorted(hooks)}")
            continue
        for event in expected_events:
            entries = hooks.get(event, [])
            if len(entries) != 1 or len(entries[0].get("hooks", [])) != 1:
                errors.append(f"{path} must have exactly one handler for {event}")
                continue
            handler = entries[0]["hooks"][0]
            if handler.get("type") != "command":
                errors.append(f"{path} {event} handler is not a command")
            if handler.get("timeout", 0) < 30:
                errors.append(f"{path} {event} timeout is below 30 seconds")
            for key in ("command", "commandWindows"):
                if f"--hook-version {HOOK_PROTOCOL_VERSION}" not in str(handler.get(key, "")):
                    errors.append(f"{path} {event} {key} has wrong hook version")

    dispatcher = paths.root / "scripts" / "harness" / "codex_hook.py"
    if dispatcher.exists():
        source = dispatcher.read_text(encoding="utf-8")
        if f'SUPPORTED_HOOK_VERSION = "{HOOK_PROTOCOL_VERSION}"' not in source:
            errors.append("hook dispatcher protocol version differs from hook definitions")
    else:
        errors.append(f"hook dispatcher is missing: {dispatcher}")

    legacy_source = paths.root / "notes" / "SESSION_CONTROL.md"
    if not scoped and legacy_source.exists():
        try:
            parse_legacy_table(paths, legacy_source)
        except HarnessError as exc:
            errors.append(str(exc))

    skill = Path(
        os.environ.get(
            "ARISE_HARNESS_SKILL_PATH",
            "/opt/aoi/skills/aoi/SKILL.md",
        )
    )
    if not skill.exists():
        warnings.append(f"personal skill not installed: {skill}")
    if not paths.index.exists():
        warnings.append(f"index has not been rendered: {paths.index}")

    payload = {
        "ok": not errors,
        "scope": args.task or "global",
        "errors": errors,
        "warnings": warnings,
        "task_count": len(tasks),
        "claim_count": len(claims),
    }
    emit(payload, args.json)
    return 0 if not errors else 1


def add_json_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="emit JSON")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ARISE plan/claim/delegate/verify/checkpoint harness"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init-task")
    p.add_argument("--task-id", required=True)
    p.add_argument("--title", required=True)
    p.add_argument("--objective", required=True)
    p.add_argument("--owner", required=True)
    p.add_argument("--completion-boundary", required=True)
    p.add_argument("--next-action")
    p.add_argument("--session-id")
    p.add_argument("--worktree")
    add_json_argument(p)
    p.set_defaults(handler=cmd_init_task)

    p = sub.add_parser("start-mini")
    p.add_argument("--task-id", required=True)
    p.add_argument("--title", required=True)
    p.add_argument("--objective", required=True)
    p.add_argument("--owner", required=True)
    p.add_argument("--completion-boundary", required=True)
    p.add_argument("--next-action")
    p.add_argument("--session-id", required=True)
    p.add_argument("--worktree")
    p.add_argument("--token", required=True)
    p.add_argument("--lock", action="append", required=True)
    p.add_argument("--intent", required=True)
    p.add_argument("--validation", required=True)
    p.add_argument("--expires-at", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_start_mini)

    p = sub.add_parser("approve-plan")
    p.add_argument("--task", required=True)
    p.add_argument("--note", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_approve_plan)

    p = sub.add_parser("bind-session")
    p.add_argument("--task", required=True)
    p.add_argument("--session-id", required=True)
    p.add_argument("--force", action="store_true")
    add_json_argument(p)
    p.set_defaults(handler=cmd_bind_session)

    p = sub.add_parser("unbind-session")
    p.add_argument("--session-id", required=True)
    p.add_argument("--task")
    add_json_argument(p)
    p.set_defaults(handler=cmd_unbind_session)

    p = sub.add_parser("import-legacy")
    p.add_argument("--source")
    add_json_argument(p)
    p.set_defaults(handler=cmd_import_legacy)

    p = sub.add_parser("check-locks")
    p.add_argument("--lock", action="append", required=True)
    p.add_argument("--ignore-token")
    add_json_argument(p)
    p.set_defaults(handler=cmd_check_locks)

    p = sub.add_parser("inspect-legacy")
    p.add_argument("--token", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_inspect_legacy)

    p = sub.add_parser("claim")
    p.add_argument("--task", required=True)
    p.add_argument("--token", required=True)
    p.add_argument("--owner", required=True)
    p.add_argument("--kind", required=True)
    p.add_argument("--lock", action="append", default=[], required=True)
    p.add_argument("--intent", required=True)
    p.add_argument("--validation", required=True)
    p.add_argument("--expires-at", required=True)
    p.add_argument("--adopt-legacy", action="store_true")
    p.add_argument("--adoption-evidence")
    p.add_argument("--ack-legacy-ambiguity", action="store_true")
    add_json_argument(p)
    p.set_defaults(handler=cmd_claim)

    p = sub.add_parser("set-claim-status")
    p.add_argument("--token", required=True)
    p.add_argument("--status", choices=sorted(RESERVING_CLAIM_STATUSES), required=True)
    p.add_argument("--reason", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_set_claim_status)

    p = sub.add_parser("release-claim")
    p.add_argument("--token", required=True)
    p.add_argument("--status", choices=sorted(TERMINAL_CLAIM_STATUSES), required=True)
    p.add_argument("--reason", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_release_claim)

    p = sub.add_parser("audit-legacy")
    p.add_argument("--token", required=True)
    p.add_argument("--decision", choices=["still-active", "released", "stale"], required=True)
    p.add_argument("--detail", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_audit_legacy)

    p = sub.add_parser("set-phase")
    p.add_argument("--task", required=True)
    p.add_argument("--phase", choices=sorted(TASK_PHASES), required=True)
    p.add_argument("--task-status", choices=sorted({"active", "blocked"}))
    p.add_argument("--summary")
    p.add_argument("--next-action")
    add_json_argument(p)
    p.set_defaults(handler=cmd_set_phase)

    p = sub.add_parser("adopt-current-branch")
    p.add_argument("--task", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--next-action")
    add_json_argument(p)
    p.set_defaults(handler=cmd_adopt_current_branch)

    p = sub.add_parser("checkpoint")
    p.add_argument("--task", required=True)
    p.add_argument("--fact", action="append", default=[])
    p.add_argument("--decision", action="append", default=[])
    p.add_argument("--rejected", action="append", default=[])
    p.add_argument("--changed-file", action="append", default=[])
    p.add_argument("--blocker", action="append", default=[])
    p.add_argument("--risk", action="append", default=[])
    p.add_argument("--next-action")
    add_json_argument(p)
    p.set_defaults(handler=cmd_checkpoint)

    p = sub.add_parser("capacity-snapshot")
    p.add_argument("--task", required=True)
    p.add_argument("--review-id", required=True)
    p.add_argument("--capacity-lane-id", required=True)
    p.add_argument("--target-lane-id", required=True)
    p.add_argument("--task-type", required=True)
    p.add_argument("--leaf-role", choices=sorted(DEPTH_TWO_ROLES), required=True)
    p.add_argument("--expected-lane-revision", type=int, required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_capacity_snapshot)

    p = sub.add_parser("capacity-recommend")
    p.add_argument("--task", required=True)
    p.add_argument("--review-id", required=True)
    p.add_argument("--expected-version", type=int, required=True)
    p.add_argument("--source-packet-id", required=True)
    p.add_argument("--capability-tier", choices=sorted(CAPABILITY_TIER_MAP), required=True)
    p.add_argument("--rationale", required=True)
    p.add_argument("--risk", required=True)
    p.add_argument("--confidence-boundary", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_capacity_recommend)

    p = sub.add_parser("capacity-arbitrate")
    p.add_argument("--task", required=True)
    p.add_argument("--review-id", required=True)
    p.add_argument("--expected-version", type=int, required=True)
    p.add_argument("--session-id", required=True)
    p.add_argument("--decision", choices=["approved", "rejected"], required=True)
    p.add_argument("--rationale", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_capacity_arbitrate)

    p = sub.add_parser("capacity-distribute")
    p.add_argument("--task", required=True)
    p.add_argument("--review-id", required=True)
    p.add_argument("--expected-version", type=int, required=True)
    p.add_argument("--steward-lane-id", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_capacity_distribute)

    p = sub.add_parser("capacity-ack")
    p.add_argument("--task", required=True)
    p.add_argument("--review-id", required=True)
    p.add_argument("--expected-version", type=int, required=True)
    p.add_argument("--actor-lane", required=True)
    p.add_argument("--evidence", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_capacity_ack)

    p = sub.add_parser("improvement-create")
    p.add_argument("--task", required=True)
    p.add_argument("--request-id", required=True)
    p.add_argument("--source-lane", required=True)
    p.add_argument("--task-type", required=True)
    p.add_argument(
        "--trigger-class", choices=sorted(IMPROVEMENT_TRIGGER_CLASSES), required=True
    )
    p.add_argument("--pain-statement", required=True)
    p.add_argument("--desired-outcome", required=True)
    p.add_argument("--occurrence", action="append", default=[], required=True)
    p.add_argument("--release-blocking", action="store_true")
    add_json_argument(p)
    p.set_defaults(handler=cmd_improvement_create)

    p = sub.add_parser("improvement-brief")
    p.add_argument("--task", required=True)
    p.add_argument("--request-id", required=True)
    p.add_argument("--expected-version", type=int, required=True)
    p.add_argument("--steward-lane-id", required=True)
    p.add_argument("--option", action="append", default=[], required=True)
    p.add_argument("--capacity-review-id")
    p.add_argument("--recommendation", required=True)
    p.add_argument("--evidence-boundary", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_improvement_brief)

    p = sub.add_parser("improvement-arbitrate")
    p.add_argument("--task", required=True)
    p.add_argument("--request-id", required=True)
    p.add_argument("--expected-version", type=int, required=True)
    p.add_argument("--session-id", required=True)
    p.add_argument("--decision", choices=["approved", "rejected"], required=True)
    p.add_argument("--selected-option", choices=sorted(IMPROVEMENT_OPTION_IDS))
    p.add_argument("--rationale", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_improvement_arbitrate)

    p = sub.add_parser("improvement-link-project")
    p.add_argument("--task", required=True)
    p.add_argument("--request-id", required=True)
    p.add_argument("--expected-version", type=int, required=True)
    p.add_argument("--project-task-id", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_improvement_link_project)

    p = sub.add_parser("skill-release-record")
    p.add_argument("--task", required=True)
    p.add_argument("--request-id", required=True)
    p.add_argument("--expected-version", type=int, required=True)
    p.add_argument("--release-id", required=True)
    p.add_argument("--skill-id", required=True)
    p.add_argument("--skill-version", required=True)
    p.add_argument("--maintenance-owner", required=True)
    p.add_argument("--rollback-plan", required=True)
    p.add_argument("--bundle", required=True)
    p.add_argument("--bundle-sha256", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--manifest-sha256", required=True)
    p.add_argument("--validation-receipt", required=True)
    p.add_argument("--validation-receipt-sha256", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_skill_release_record)

    p = sub.add_parser("skill-adoption-record")
    p.add_argument("--task", required=True)
    p.add_argument("--request-id", required=True)
    p.add_argument("--expected-version", type=int, required=True)
    p.add_argument("--release-id", required=True)
    p.add_argument("--action", choices=sorted(SKILL_ADOPTION_ACTIONS), required=True)
    p.add_argument("--session-id", required=True)
    p.add_argument("--evidence-artifact", required=True)
    p.add_argument("--evidence-sha256", required=True)
    p.add_argument("--rationale", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_skill_adoption_record)

    p = sub.add_parser("execution-select")
    p.add_argument("--task", required=True)
    p.add_argument("--selection-id", required=True)
    p.add_argument("--work-unit-id", required=True)
    p.add_argument("--supersedes-selection-id")
    p.add_argument("--mode", choices=sorted(EXECUTION_MODES), required=True)
    p.add_argument("--lane", action="append", default=[], required=True)
    p.add_argument("--scope", required=True)
    p.add_argument(
        "--sequential-dependency", choices=sorted(DEPENDENCY_LEVELS), required=True
    )
    p.add_argument("--tool-density", choices=sorted(TOOL_DENSITIES), required=True)
    p.add_argument("--shared-context", choices=sorted(DEPENDENCY_LEVELS), required=True)
    p.add_argument("--rationale", required=True)
    p.add_argument("--falsification-condition", required=True)
    p.add_argument("--escalation-condition", required=True)
    p.add_argument("--session-id", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_execution_select)

    p = sub.add_parser("cross-lane-open")
    p.add_argument("--task", required=True)
    p.add_argument("--cross-lane-session-id", required=True)
    p.add_argument("--execution-selection-id", required=True)
    p.add_argument("--request-id", required=True)
    p.add_argument("--steward-lane-id", required=True)
    p.add_argument("--participant-lane", action="append", default=[], required=True)
    p.add_argument("--topic", required=True)
    p.add_argument("--evidence-boundary", required=True)
    p.add_argument("--expires-at", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_cross_lane_open)

    p = sub.add_parser("cross-lane-close")
    p.add_argument("--task", required=True)
    p.add_argument("--cross-lane-session-id", required=True)
    p.add_argument("--expected-version", type=int, required=True)
    p.add_argument("--steward-lane-id", required=True)
    p.add_argument("--conclusion", required=True)
    p.add_argument("--dissent", required=True)
    p.add_argument("--blocker", required=True)
    p.add_argument("--evidence", action="append", default=[], required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_cross_lane_close)

    p = sub.add_parser("cross-lane-cancel")
    p.add_argument("--task", required=True)
    p.add_argument("--cross-lane-session-id", required=True)
    p.add_argument("--expected-version", type=int, required=True)
    p.add_argument("--steward-lane-id", required=True)
    p.add_argument("--reason", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_cross_lane_cancel)

    p = sub.add_parser("needs-user-create")
    p.add_argument("--task", required=True)
    p.add_argument("--escalation-id", required=True)
    p.add_argument("--category", choices=sorted(NEEDS_USER_CATEGORIES), required=True)
    p.add_argument("--source-lane", required=True)
    p.add_argument("--request-id")
    p.add_argument("--problem", required=True)
    p.add_argument("--option", action="append", default=[], required=True)
    p.add_argument("--evidence", action="append", default=[], required=True)
    p.add_argument("--chief-recommendation", required=True)
    p.add_argument("--session-id", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_needs_user_create)

    p = sub.add_parser("needs-user-resolve")
    p.add_argument("--task", required=True)
    p.add_argument("--escalation-id", required=True)
    p.add_argument("--session-id", required=True)
    p.add_argument("--user-decision", required=True)
    p.add_argument("--user-evidence", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_needs_user_resolve)

    p = sub.add_parser("lane-set-status")
    p.add_argument("--task", required=True)
    p.add_argument("--lane-id", required=True)
    p.add_argument("--expected-revision", type=int, required=True)
    p.add_argument("--expected-status", choices=sorted(LANE_STATUSES), required=True)
    p.add_argument("--status", choices=sorted(LANE_STATUSES), required=True)
    p.add_argument("--next-action", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--session-id", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_lane_set_status)

    p = sub.add_parser("lane-create")
    p.add_argument("--task", required=True)
    p.add_argument("--lane-id", required=True)
    p.add_argument("--kind", choices=sorted(LANE_KINDS), required=True)
    p.add_argument("--status", choices=sorted(LANE_STATUSES), default="active")
    p.add_argument("--owner", required=True)
    p.add_argument("--role", choices=sorted(ROLE_TIER_MAP), required=True)
    p.add_argument("--authority-commit", required=True)
    p.add_argument("--contract-version", required=True)
    p.add_argument("--generator-version", default="not_applicable")
    p.add_argument("--adapter-version", default="not_applicable")
    p.add_argument("--next-action", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_lane_create)

    p = sub.add_parser("lane-revise")
    p.add_argument("--task", required=True)
    p.add_argument("--lane-id", required=True)
    p.add_argument("--expected-revision", type=int, required=True)
    p.add_argument("--authority-commit", required=True)
    p.add_argument(
        "--change-class", choices=sorted(CHANGE_CLASSES - {"genesis"}), required=True
    )
    p.add_argument("--contract-version", required=True)
    p.add_argument("--generator-version", required=True)
    p.add_argument("--adapter-version", required=True)
    p.add_argument("--next-action", required=True)
    p.add_argument("--decision", required=True)
    p.add_argument("--session-id", required=True)
    p.add_argument("--coord", action="append", default=[])
    add_json_argument(p)
    p.set_defaults(handler=cmd_lane_revise)

    p = sub.add_parser("lane-dependency-add")
    p.add_argument("--task", required=True)
    p.add_argument("--dependency-id", required=True)
    p.add_argument("--source-lane", required=True)
    p.add_argument("--target-lane", required=True)
    p.add_argument("--kind", choices=sorted(DEPENDENCY_KINDS), required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--needed-by-gate")
    add_json_argument(p)
    p.set_defaults(handler=cmd_lane_dependency_add)

    p = sub.add_parser("lane-dependency-update")
    p.add_argument("--task", required=True)
    p.add_argument("--dependency-id", required=True)
    p.add_argument("--status", choices=["satisfied", "waived", "superseded"], required=True)
    p.add_argument("--session-id", required=True)
    p.add_argument("--evidence", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_lane_dependency_update)

    p = sub.add_parser("coordination-create")
    p.add_argument("--task", required=True)
    p.add_argument("--request-id", required=True)
    p.add_argument("--source-lane", required=True)
    p.add_argument("--target-lane", required=True)
    p.add_argument("--severity", choices=sorted(DEPENDENCY_KINDS), required=True)
    p.add_argument("--request", required=True)
    p.add_argument("--outcome", required=True)
    p.add_argument("--evidence", action="append", default=[], required=True)
    p.add_argument("--option", action="append", default=[])
    p.add_argument("--needed-by-gate")
    p.add_argument(
        "--change-class",
        choices=sorted(CHANGE_CLASSES - {"genesis"}),
        default="same_contract_implementation",
    )
    p.add_argument(
        "--closure-category",
        choices=sorted(CLOSE_QUALIFYING_CATEGORIES),
        default="integration_test",
    )
    add_json_argument(p)
    p.set_defaults(handler=cmd_coordination_create)

    p = sub.add_parser("coordination-update")
    p.add_argument("--task", required=True)
    p.add_argument("--request-id", required=True)
    p.add_argument("--actor-lane", required=True)
    p.add_argument("--expected-version", type=int, required=True)
    p.add_argument("--status", choices=["acknowledged", "countered"], required=True)
    p.add_argument("--response", required=True)
    p.add_argument("--evidence", action="append", default=[])
    add_json_argument(p)
    p.set_defaults(handler=cmd_coordination_update)

    p = sub.add_parser("coordination-arbitrate")
    p.add_argument("--task", required=True)
    p.add_argument("--request-id", required=True)
    p.add_argument("--session-id", required=True)
    p.add_argument("--expected-version", type=int, required=True)
    p.add_argument("--decision", choices=["approved", "rejected"], required=True)
    p.add_argument("--rationale", required=True)
    p.add_argument("--selected-option")
    add_json_argument(p)
    p.set_defaults(handler=cmd_coordination_arbitrate)

    p = sub.add_parser("coordination-directive-ack")
    p.add_argument("--task", required=True)
    p.add_argument("--request-id", required=True)
    p.add_argument("--directive-id", required=True)
    p.add_argument("--actor-lane", required=True)
    p.add_argument("--evidence", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_coordination_directive_ack)

    p = sub.add_parser("coordination-resolve")
    p.add_argument("--task", required=True)
    p.add_argument("--request-id", required=True)
    p.add_argument("--expected-version", type=int, required=True)
    p.add_argument("--session-id", required=True)
    p.add_argument("--evidence", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_coordination_resolve)

    p = sub.add_parser("coordination-implementation-submit")
    p.add_argument("--task", required=True)
    p.add_argument("--request-id", required=True)
    p.add_argument("--expected-version", type=int, required=True)
    p.add_argument("--actor-lane", required=True)
    p.add_argument("--claim-token", required=True)
    p.add_argument("--baseline-id", required=True)
    p.add_argument(
        "--evidence-category",
        choices=sorted(CLOSE_QUALIFYING_CATEGORIES),
        required=True,
    )
    p.add_argument("--command", required=True)
    p.add_argument("--boundary", required=True)
    p.add_argument("--evidence-artifact", required=True)
    p.add_argument("--evidence-sha256", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_coordination_implementation_submit)

    p = sub.add_parser("coordination-verify")
    p.add_argument("--task", required=True)
    p.add_argument("--request-id", required=True)
    p.add_argument("--expected-version", type=int, required=True)
    p.add_argument("--verifier-lane", required=True)
    p.add_argument(
        "--category", choices=sorted(CLOSE_QUALIFYING_CATEGORIES), required=True
    )
    p.add_argument("--status", choices=["pass", "fail"], required=True)
    p.add_argument("--test-oracle", required=True)
    p.add_argument("--command", required=True)
    p.add_argument("--boundary", required=True)
    p.add_argument("--evidence-artifact", required=True)
    p.add_argument("--evidence-sha256", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_coordination_verify)

    p = sub.add_parser("baseline-freeze")
    p.add_argument("--task", required=True)
    p.add_argument("--baseline-id", required=True)
    p.add_argument("--contract-version", required=True)
    p.add_argument("--session-id", required=True)
    p.add_argument("--decision", required=True)
    p.add_argument("--lane", action="append", default=[])
    p.add_argument("--coord", action="append", default=[])
    add_json_argument(p)
    p.set_defaults(handler=cmd_baseline_freeze)

    p = sub.add_parser("reconcile")
    p.add_argument("--task", required=True)
    p.add_argument("--observations")
    p.add_argument("--observations-sha")
    add_json_argument(p)
    p.set_defaults(handler=cmd_reconcile)

    p = sub.add_parser("add-verification")
    p.add_argument("--task", required=True)
    p.add_argument("--category", choices=sorted(VERIFICATION_CATEGORIES), required=True)
    p.add_argument("--status", choices=sorted(VERIFICATION_STATUSES), required=True)
    p.add_argument("--evidence", required=True)
    p.add_argument("--command", required=True)
    p.add_argument("--boundary", required=True)
    p.add_argument("--run-id")
    p.add_argument("--lane-id")
    p.add_argument("--artifact-ref", action="append", default=[])
    p.add_argument("--review-packet-id")
    add_json_argument(p)
    p.set_defaults(handler=cmd_add_verification)

    p = sub.add_parser("create-packet")
    p.add_argument("--task", required=True)
    p.add_argument("--packet-id", required=True)
    p.add_argument("--agent-role", required=True)
    p.add_argument("--model-tier", required=True)
    p.add_argument("--objective", required=True)
    p.add_argument("--scope", required=True)
    p.add_argument("--lock", action="append", default=[])
    p.add_argument("--deliverable", required=True)
    p.add_argument("--validation", required=True)
    p.add_argument("--read-first", action="append", default=[])
    p.add_argument("--lane-id")
    p.add_argument("--execution-selection-id")
    p.add_argument("--skill-release-id")
    p.add_argument("--skill-canary-event-id")
    p.add_argument("--task-type", default="general")
    p.add_argument("--delegation-depth", type=int, choices=[1, 2], default=1)
    p.add_argument("--parent-packet-id")
    p.add_argument("--capability-tier", choices=sorted(CAPABILITY_TIER_MAP))
    p.add_argument("--capacity-decision-id")
    p.add_argument("--retry-of-packet-id")
    p.add_argument("--capacity-review-source-id")
    p.add_argument("--input-artifact", action="append", default=[])
    p.add_argument(
        "--packet-mode",
        choices=["read_only", "bounded_mutation", "exact_command"],
        default="read_only",
    )
    p.add_argument("--command-artifact")
    p.add_argument("--command-sha256")
    add_json_argument(p)
    p.set_defaults(handler=cmd_create_packet)

    p = sub.add_parser("packet-update")
    p.add_argument("--task", required=True)
    p.add_argument("--packet-id", required=True)
    p.add_argument("--status", choices=sorted(PACKET_STATUSES - {"ready"}), required=True)
    p.add_argument("--agent-id")
    p.add_argument("--actual-role", choices=sorted(ROLE_TIER_MAP))
    p.add_argument("--actual-model-tier", choices=sorted(set(ROLE_TIER_MAP.values())))
    p.add_argument("--routing-evidence")
    p.add_argument("--summary")
    p.add_argument("--evidence", action="append", default=[])
    add_json_argument(p)
    p.set_defaults(handler=cmd_packet_update)

    p = sub.add_parser("packet-attest-result")
    p.add_argument("--task", required=True)
    p.add_argument("--packet-id", required=True)
    p.add_argument("--evidence", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_packet_attest_result)

    p = sub.add_parser("job-start")
    p.add_argument("--task", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--tool", required=True)
    p.add_argument("--work-root", required=True)
    p.add_argument("--status", choices=["queued"], default="queued")
    p.add_argument("--log", required=True)
    p.add_argument("--pid")
    p.add_argument("--tmux")
    p.add_argument("--stop-condition", required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--source-manifest", required=True)
    p.add_argument("--tool-path", required=True)
    p.add_argument("--tool-version", required=True)
    p.add_argument("--command", required=True)
    p.add_argument("--success-exit-code", type=int, default=0)
    p.add_argument("--lane-id")
    p.add_argument("--execution-selection-id")
    p.add_argument("--skill-release-id")
    p.add_argument("--skill-canary-event-id")
    add_json_argument(p)
    p.set_defaults(handler=cmd_job_start)

    p = sub.add_parser("job-update")
    p.add_argument("--task", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--status", choices=sorted(JOB_STATUSES), required=True)
    p.add_argument("--evidence", required=True)
    p.add_argument("--exit-code", type=int)
    p.add_argument("--pid")
    p.add_argument("--tmux")
    p.add_argument("--terminal-log-artifact")
    p.add_argument("--terminal-log-sha256")
    add_json_argument(p)
    p.set_defaults(handler=cmd_job_update)

    p = sub.add_parser("set-delivery")
    p.add_argument("--task", required=True)
    p.add_argument("--mode", choices=sorted(DELIVERY_MODES - {"pending"}), required=True)
    p.add_argument("--detail", required=True)
    p.add_argument("--commit")
    p.add_argument("--remote")
    p.add_argument("--remote-ref")
    add_json_argument(p)
    p.set_defaults(handler=cmd_set_delivery)

    p = sub.add_parser("close-task")
    p.add_argument("--task", required=True)
    p.add_argument("--summary", required=True)
    p.add_argument("--next-action")
    add_json_argument(p)
    p.set_defaults(handler=cmd_close_task)

    p = sub.add_parser("block-task")
    p.add_argument("--task", required=True)
    p.add_argument("--blocker", required=True)
    p.add_argument("--next-action", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_block_task)

    p = sub.add_parser("cancel-task")
    p.add_argument("--task", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--next-action")
    add_json_argument(p)
    p.set_defaults(handler=cmd_cancel_task)

    p = sub.add_parser("resume")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--task")
    group.add_argument("--session-id")
    add_json_argument(p)
    p.set_defaults(handler=cmd_resume)

    p = sub.add_parser("status")
    p.add_argument("--legacy", action="store_true")
    p.add_argument("--task")
    p.add_argument("--critical", action="store_true")
    add_json_argument(p)
    p.set_defaults(handler=cmd_status)

    p = sub.add_parser("render-index")
    add_json_argument(p)
    p.set_defaults(handler=cmd_render_index)

    p = sub.add_parser("backup-state")
    p.add_argument("--destination")
    add_json_argument(p)
    p.set_defaults(handler=cmd_backup_state)

    p = sub.add_parser("verify-backup")
    p.add_argument("--manifest", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_verify_backup)

    p = sub.add_parser("doctor")
    p.add_argument("--task")
    add_json_argument(p)
    p.set_defaults(handler=cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    paths = get_paths()
    try:
        return int(args.handler(args, paths))
    except HarnessError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("ERROR: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
