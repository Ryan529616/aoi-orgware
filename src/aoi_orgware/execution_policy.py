"""Task-global execution-policy generation and one-way migration guards.

Pure state-dict logic: every function reads or mutates a task-state ``dict``
in place and raises ``HarnessError`` on an invalid or downgraded policy
marker. ``EXECUTION_POLICY_VERSION``/``TASK_EXECUTION_SCHEMA_VERSION`` are
owned here as the single canonical source; the CLI re-exports both rather
than redefining them. This module imports only sibling packages
(:mod:`aoi_orgware.harnesslib`) and never imports :mod:`aoi_orgware.cli`.
"""

from __future__ import annotations

from typing import Any

from .harnesslib import ACTIVE_JOB_STATUSES, ACTIVE_PACKET_STATUSES, HarnessError


EXECUTION_POLICY_VERSION = 2
TASK_EXECUTION_SCHEMA_VERSION = 2


def _is_exact_int(value: Any, expected: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == expected


def _execution_policy_v2_enabled(state: dict[str, Any]) -> bool:
    """Return the task-global policy generation, failing closed on downgrade."""

    task_schema = state.get("task_execution_schema_version")
    policy_version = state.get("execution_policy_version")
    legacy_provenance_present = "legacy_execution_policy" in state
    legacy_execution_policy = state.get("legacy_execution_policy")
    if legacy_provenance_present and not isinstance(legacy_execution_policy, bool):
        raise HarnessError("legacy_execution_policy must be exactly true or false")
    if task_schema is not None and not _is_exact_int(
        task_schema, TASK_EXECUTION_SCHEMA_VERSION
    ):
        raise HarnessError(
            f"task_execution_schema_version must be {TASK_EXECUTION_SCHEMA_VERSION}"
        )
    if _is_exact_int(task_schema, TASK_EXECUTION_SCHEMA_VERSION) and not _is_exact_int(
        policy_version, EXECUTION_POLICY_VERSION
    ):
        raise HarnessError(
            "task execution policy marker is missing or downgraded from schema v2"
        )
    v2_artifacts_exist = any(
        _is_exact_int(item.get("execution_selection_version"), 2)
        for item in state.get("execution_selections", [])
    ) or any(
        item.get("dispatch_schema_origin") == "native_v5"
        for item in state.get("packets", [])
    ) or any(
        _is_exact_int(item.get("task_execution_policy_version"), 2)
        for item in state.get("jobs", [])
    )
    if legacy_execution_policy is False and (
        not _is_exact_int(task_schema, TASK_EXECUTION_SCHEMA_VERSION)
        or not _is_exact_int(policy_version, EXECUTION_POLICY_VERSION)
    ):
        raise HarnessError(
            "native execution-policy task lost or downgraded its schema-v2 markers"
        )
    if legacy_execution_policy is True:
        if task_schema is not None or policy_version is not None or v2_artifacts_exist:
            raise HarnessError(
                "legacy execution-policy provenance conflicts with v2 execution state"
            )
        return False
    if policy_version is None and v2_artifacts_exist:
        raise HarnessError(
            "task execution policy marker is missing while v2 execution artifacts exist"
        )
    if policy_version is None:
        return False
    if not _is_exact_int(policy_version, EXECUTION_POLICY_VERSION):
        raise HarnessError(
            f"execution_policy_version must be {EXECUTION_POLICY_VERSION}"
        )
    return True


def _adopt_execution_policy_v2_for_new_work(state: dict[str, Any]) -> None:
    """Upgrade a quiescent legacy task before it creates v0.2 execution work."""

    if _execution_policy_v2_enabled(state):
        state["legacy_execution_policy"] = False
        return
    if state.get("execution_selections"):
        raise HarnessError(
            "legacy task already has execution selections; finish it under the legacy "
            "policy or start a new task before creating v0.2 execution work"
        )
    active_records = [
        f"packet:{item.get('packet_id')}"
        for item in state.get("packets", [])
        if item.get("status") in ACTIVE_PACKET_STATUSES
    ] + [
        f"job:{item.get('run_id')}"
        for item in state.get("jobs", [])
        if item.get("status") in ACTIVE_JOB_STATUSES
    ]
    if active_records:
        raise HarnessError(
            "legacy task must be quiescent before adopting execution policy v2: "
            + ", ".join(active_records)
        )
    state["task_execution_schema_version"] = TASK_EXECUTION_SCHEMA_VERSION
    state["execution_policy_version"] = EXECUTION_POLICY_VERSION
    state["legacy_execution_policy"] = False


def _adopt_legacy_execution_provenance_for_v4_migration(
    state: dict[str, Any],
) -> None:
    """Seal a clean pre-marker task as legacy before its one-way v4 upgrade."""

    provenance = state.get("legacy_execution_policy")
    if provenance is False:
        raise HarnessError(
            "schema-v4 migration is forbidden for a native execution-policy task"
        )
    if provenance is not None and provenance is not True:
        raise HarnessError("legacy_execution_policy must be exactly true or false")
    if _execution_policy_v2_enabled(state):
        raise HarnessError(
            "schema-v4 migration requires an explicitly legacy execution-policy task"
        )
    state["legacy_execution_policy"] = True


__all__ = [
    "EXECUTION_POLICY_VERSION",
    "TASK_EXECUTION_SCHEMA_VERSION",
    "_adopt_execution_policy_v2_for_new_work",
    "_adopt_legacy_execution_provenance_for_v4_migration",
    "_execution_policy_v2_enabled",
]
