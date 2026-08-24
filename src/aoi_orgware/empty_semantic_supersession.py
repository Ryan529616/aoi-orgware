"""Exact empty native-semantic task supersession contract."""
from __future__ import annotations

import re
from typing import Any

from . import semantic_events, semantic_store
from .git_plumbing import (
    FULL_COMMIT_RE,
    git_is_ancestor,
    git_metadata,
    state_worktree,
)
from .harnesslib import (
    HarnessError,
    HarnessPaths,
    claims_owned_by_task,
    normalize_lock,
    parse_tz_aware_time,
)


EMPTY_NATIVE_SEMANTIC_COLLECTION_FIELDS = (
    "blockers",
    "changed_files",
    "claims",
    "context_provider_benchmarks",
    "context_provider_receipts",
    "decisions",
    "execution_briefs",
    "facts",
    "jobs",
    "override_requests",
    "packets",
    "plan_approvals",
    "rejected_paths",
    "resource_config_events",
    "resource_config_legacy_migrations",
    "resource_session_registrations",
    "risks",
    "scope_revisions",
    "session_ids",
    "subagent_incidents",
    "subagent_parent_session_ids",
    "verification",
)

EMPTY_SUPERSESSION_DELIVERY = {
    "commit": "",
    "detail": "Superseded before plan approval or material work; no delivery exists.",
    "mode": "none",
}

_TERMINAL_DELTA_FIELDS = frozenset(
    {
        "boundary_disposition",
        "branch",
        "checkpoint_required",
        "checkpoint_revision",
        "checkpoint_sha256",
        "closed_at",
        "closed_head_sha",
        "delivery",
        "facts",
        "next_action",
        "outcome",
        "phase",
        "revision",
        "status",
        "updated_at",
    }
)


def _same_json(left: Any, right: Any) -> bool:
    try:
        return semantic_events.canonical_json_bytes(
            left
        ) == semantic_events.canonical_json_bytes(right)
    except semantic_events.SemanticEventError:
        return False


def _canonical_merge_branch(value: Any) -> str | None:
    if (
        not isinstance(value, str)
        or value == "HEAD"
        or value.casefold() == "detached"
    ):
        return None
    try:
        canonical = normalize_lock(f"git:merge:{value}")
    except HarnessError:
        return None
    if (
        ".." in value
        or "//" in value
        or "@{" in value
        or value.endswith(("/", "."))
    ):
        return None
    if any(
        not component
        or component.startswith(".")
        or component.endswith(".lock")
        for component in value.split("/")
    ):
        return None
    return canonical


def _valid_terminal_times(
    before: dict[str, Any], after: dict[str, Any]
) -> bool:
    before_raw = before.get("updated_at")
    after_raw = after.get("updated_at")
    closed_raw = after.get("closed_at")
    if (
        not isinstance(before_raw, str)
        or not isinstance(after_raw, str)
        or not isinstance(closed_raw, str)
        or before_raw != before_raw.strip()
        or after_raw != after_raw.strip()
        or closed_raw != closed_raw.strip()
    ):
        return False
    before_time = parse_tz_aware_time(before_raw)
    after_time = parse_tz_aware_time(after_raw)
    closed_time = parse_tz_aware_time(closed_raw)
    return (
        before_time is not None
        and after_time is not None
        and closed_time is not None
        and before_time <= after_time <= closed_time
    )


def _has_exact_terminal_event_delta(
    paths: HarnessPaths, state: dict[str, Any]
) -> bool:
    task_id = state.get("task_id")
    if not isinstance(task_id, str) or not task_id:
        return False
    try:
        events = semantic_store.load_semantic_events(paths, task_id)
        if [event.get("event_type") for event in events] != [
            "genesis",
            "integrity_adopt",
            "task_closed",
        ]:
            return False
        before = semantic_events.projection_domain(
            semantic_events.replay_events(events[:2])
        )
        terminal = semantic_events.replay_events(events)
        after = semantic_events.projection_domain(terminal)
        if not _same_json(state, terminal):
            return False
    except (HarnessError, semantic_events.SemanticEventError, TypeError, ValueError):
        return False

    unchanged = (set(before) | set(after)) - _TERMINAL_DELTA_FIELDS
    if any(
        key not in before
        or key not in after
        or not _same_json(before[key], after[key])
        for key in unchanged
    ):
        return False
    if any(
        key not in _TERMINAL_DELTA_FIELDS
        for key in (set(before) ^ set(after))
    ):
        return False
    before_branch = _canonical_merge_branch(before.get("branch"))
    after_branch = _canonical_merge_branch(after.get("branch"))
    if (
        before.get("status") != "active"
        or before.get("phase") != "planning"
        or before.get("outcome") != "in_progress"
        or before.get("plan_ready") is not False
        or before.get("plan_sha256") != ""
        or before.get("checkpoint_required") is not True
        or type(before.get("revision")) is not int
        or type(before.get("checkpoint_revision")) is not int
        or before.get("checkpoint_revision") != 0
        or before.get("checkpoint_sha256") != ""
        or before.get("delivery") != {"commit": "", "detail": "", "mode": "pending"}
        or before.get("facts") != []
        or before_branch is None
        or after_branch is None
        or before_branch == after_branch
        or not _valid_terminal_times(before, after)
        or "boundary_disposition" in before
        or "closed_at" in before
        or "closed_head_sha" in before
        or "blockers_disposition" in after
        or after.get("revision") != before["revision"] + 1
        or after.get("updated_at") == before.get("updated_at")
        or events[-1].get("recorded_at") != after.get("closed_at")
    ):
        return False
    return all(
        before.get(field) == []
        for field in EMPTY_NATIVE_SEMANTIC_COLLECTION_FIELDS
    )


def is_empty_native_semantic_terminal_supersession(
    paths: HarnessPaths | None,
    state: dict[str, Any],
    contract: dict[str, Any],
) -> bool:
    """Recognize the sole terminal state that needs no integrity seal.

    The authenticated ledger and its exact sequence-2 to sequence-3 delta are
    part of this exception.  Projection shape alone never waives the seal.
    """

    semantic = state.get("_semantic")
    facts = state.get("facts")
    revision = state.get("revision")
    return bool(
        paths is not None
        and _has_exact_terminal_event_delta(paths, state)
        and state.get("status") == "done"
        and state.get("phase") == "closing"
        and state.get("outcome") == "superseded"
        and state.get("plan_ready") is False
        and state.get("plan_sha256") == ""
        and state.get("checkpoint_required") is False
        and isinstance(revision, int)
        and not isinstance(revision, bool)
        and type(state.get("checkpoint_revision")) is int
        and state.get("checkpoint_revision") == revision
        and re.fullmatch(r"[0-9a-f]{64}", str(state.get("checkpoint_sha256", "")))
        and isinstance(state.get("closed_at"), str)
        and bool(str(state.get("closed_at", "")).strip())
        and re.fullmatch(r"[0-9a-f]{40}", str(state.get("closed_head_sha", "")))
        and isinstance(state.get("boundary_disposition"), str)
        and bool(str(state.get("boundary_disposition", "")).strip())
        and isinstance(state.get("next_action"), str)
        and bool(str(state.get("next_action", "")).strip())
        and state.get("delivery") == EMPTY_SUPERSESSION_DELIVERY
        and isinstance(semantic, dict)
        and set(semantic)
        == {
            "schema_version",
            "sequence",
            "head_event_sha256",
            "domain_sha256",
        }
        and type(semantic.get("schema_version")) is int
        and semantic.get("schema_version") == 2
        and type(semantic.get("sequence")) is int
        and semantic.get("sequence") == 3
        and re.fullmatch(r"[0-9a-f]{64}", str(semantic.get("head_event_sha256", "")))
        and re.fullmatch(r"[0-9a-f]{64}", str(semantic.get("domain_sha256", "")))
        and set(contract)
        == {
            "schema_version",
            "mode",
            "adopted_at",
            "baseline_head",
            "migration_receipt",
            "records",
            "seal",
        }
        and type(contract.get("schema_version")) is int
        and contract.get("schema_version") == 2
        and contract.get("mode") == "required_v2"
        and contract.get("baseline_head") == state.get("head_sha")
        and contract.get("migration_receipt") is None
        and contract.get("records") == []
        and contract.get("seal") is None
        and _same_json(state.get("integrity_contract"), contract)
        and isinstance(facts, list)
        and len(facts) == 1
        and isinstance(facts[0], str)
        and bool(facts[0].strip())
        and all(
            state.get(field) == []
            for field in EMPTY_NATIVE_SEMANTIC_COLLECTION_FIELDS
            if field != "facts"
        )
    )


def prepare_empty_native_semantic_supersession(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    intended_outcome: str,
) -> bool:
    """Validate and prepare one exact empty task for semantic supersession."""

    if (
        intended_outcome != "superseded"
        or "_semantic" not in state
        or state.get("delivery", {}).get("mode") != "pending"
    ):
        return False

    failures: list[str] = []
    if state.get("status") != "active" or state.get("phase") != "planning":
        failures.append("task is not an active planning task")
    if state.get("outcome") != "in_progress":
        failures.append("task outcome is not in_progress")
    if state.get("plan_ready") is not False or state.get("plan_sha256") != "":
        failures.append("task has plan state")
    if (
        state.get("checkpoint_required") is not True
        or state.get("checkpoint_revision") != 0
        or state.get("checkpoint_sha256") != ""
    ):
        failures.append("task has checkpoint progress")
    for field in EMPTY_NATIVE_SEMANTIC_COLLECTION_FIELDS:
        value = state.get(field, [])
        if not isinstance(value, list) or value:
            failures.append(f"task has material {field}")

    delivery = state.get("delivery")
    if not isinstance(delivery, dict) or set(delivery) != {"commit", "detail", "mode"}:
        failures.append("pending delivery shape is not empty-native canonical")
    elif delivery.get("commit") or delivery.get("detail"):
        failures.append("pending delivery already carries material state")

    contract = state.get("integrity_contract")
    if not isinstance(contract, dict):
        failures.append("integrity contract is missing")
    elif (
        contract.get("schema_version") != 2
        or contract.get("mode") != "required_v2"
        or contract.get("baseline_head") != state.get("head_sha")
        or contract.get("records") != []
        or contract.get("seal") is not None
        or contract.get("migration_receipt") is not None
    ):
        failures.append("integrity contract contains work beyond initial adoption")

    try:
        events = semantic_store.load_semantic_events(paths, str(state.get("task_id", "")))
    except HarnessError as exc:
        failures.append(f"semantic ledger cannot be authenticated: {exc}")
        events = []
    if [event.get("event_type") for event in events] != ["genesis", "integrity_adopt"]:
        failures.append("semantic ledger is not exactly genesis plus integrity_adopt")
    semantic_state = state.get("_semantic")
    if not isinstance(semantic_state, dict) or semantic_state.get("sequence") != 2:
        failures.append("semantic projection sequence is not exactly 2")
    elif events and semantic_state.get("head_event_sha256") != events[-1].get(
        "event_sha256"
    ):
        failures.append("semantic projection head differs from the authenticated ledger")

    if claims_owned_by_task(paths, str(state.get("task_id", ""))):
        failures.append("task has claim history")

    current: dict[str, str] | None = None
    try:
        worktree = state_worktree(paths, state)
        current = git_metadata(worktree)
        if current["worktree"] != str(state.get("worktree", "")):
            failures.append("task worktree path changed")
        start_head = str(state.get("head_sha", ""))
        if not FULL_COMMIT_RE.fullmatch(start_head):
            failures.append("task starting HEAD is missing or invalid")
        elif not git_is_ancestor(worktree, start_head, current["head_sha"]):
            failures.append("current worktree HEAD no longer contains task starting HEAD")
        if current["branch"] == "detached":
            failures.append("current worktree is detached")
    except HarnessError as exc:
        failures.append(str(exc))

    if failures:
        raise HarnessError(
            "empty native semantic supersession gate failed:\n- "
            + "\n- ".join(failures)
        )
    assert current is not None
    state["branch"] = current["branch"]
    state["delivery"] = dict(EMPTY_SUPERSESSION_DELIVERY)
    return True


__all__ = [
    "EMPTY_NATIVE_SEMANTIC_COLLECTION_FIELDS",
    "EMPTY_SUPERSESSION_DELIVERY",
    "is_empty_native_semantic_terminal_supersession",
    "prepare_empty_native_semantic_supersession",
]
