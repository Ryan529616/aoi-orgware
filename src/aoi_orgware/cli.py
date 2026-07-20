#!/usr/bin/env python3
"""Plan/claim/delegate/verify/checkpoint CLI for AOI orgware."""

from __future__ import annotations

import sys

# Prevent importing the local harness library from creating workspace bytecode.
sys.dont_write_bytecode = True

import argparse
import copy
import datetime as dt
import functools
import gzip
import hashlib
import importlib.resources
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tomllib
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, cast

from . import __version__
from . import codex_install_provenance as codex_install_provenance_impl
from . import confidentiality as confidentiality_impl
from . import codex_hook_receipts as codex_hook_receipts_impl
from . import dispatch_protocol as dispatch_protocol_impl
from . import evidence_artifacts as evidence_artifacts_impl
from .agent_identity import AgentIdentityError, AGENT_ID_RE, validate_agent_id
from . import execution_topology as execution_topology_impl
from . import integrity_records as integrity_records_impl
from . import integrity_records_v2 as integrity_records_v2_impl
from . import job_integrity as job_integrity_impl
from . import packet_integrity as packet_integrity_impl
from . import portfolio_integrity as portfolio_integrity_impl
from . import resource_governance as resource_governance_impl
from . import release_runtime as release_runtime_impl
from . import semantic_store as semantic_store_impl
from . import skill_lifecycle as skill_lifecycle_impl
from . import verification_integrity as verification_integrity_impl
from .evidence_artifacts import (
    BOUND_ARTIFACT_MAX_COUNT,
    COMMAND_ARTIFACT_MAX_BYTES,
    TERMINAL_ARTIFACT_MAX_BYTES,
)
from .execution_policy import (
    EXECUTION_POLICY_VERSION,
    TASK_EXECUTION_SCHEMA_VERSION,
    _adopt_execution_policy_v2_for_new_work,
    _adopt_legacy_execution_provenance_for_v4_migration,
    _execution_policy_v2_enabled,
)
from .git_plumbing import (
    COMMIT_RE,
    FULL_COMMIT_RE,
    git_is_ancestor,
    git_metadata,
    legacy_ambiguities,
    remote_ref_tip,
    resolve_task_commit,
    state_worktree,
    task_mutation_snapshot,
    validate_task_mutation_snapshot,
    validate_task_mutation_snapshot_claim_scope,
    worktree_integrity_errors,
)
from .state_lookup import (
    ENGAGED_LANE_STATUSES,
    _baseline_by_id,
    _engaged_capacity_lane,
    _engaged_steward_lane,
    _packet_by_id,
    capacity_review_by_id,
    coordination_by_id,
    cross_lane_session_by_id,
    execution_selection_by_id,
    improvement_request_by_id,
    lane_by_id,
    needs_user_by_id,
    require_full_commit,
    require_open_task,
)
from .commands.backup import (
    _check_json_file,
    cmd_backup_state,
    cmd_verify_backup,
    register_backup_commands,
    verify_backup,
)
from .commands.capacity import (
    CapacityCmdServices,
    cmd_capacity_ack,
    cmd_capacity_arbitrate,
    cmd_capacity_distribute,
    cmd_capacity_recommend,
    cmd_capacity_snapshot,
    register_capacity_commands,
)
from .commands.canary import (
    CanaryCmdServices,
    cmd_codex_helper_canary,
    register_canary_commands,
)
from .commands.context_memory import (
    ContextMemoryCmdServices,
    cmd_codebase_memory_benchmark_record,
    cmd_codebase_memory_benchmark_validate,
    cmd_context_receipt_record,
    register_context_memory_commands,
)
from .commands.coordination import (
    CoordinationCmdServices,
    cmd_baseline_freeze,
    cmd_coordination_arbitrate,
    cmd_coordination_create,
    cmd_coordination_directive_ack,
    cmd_coordination_implementation_submit,
    cmd_coordination_resolve,
    cmd_coordination_update,
    cmd_coordination_verify,
    cmd_cross_lane_cancel,
    cmd_cross_lane_close,
    cmd_cross_lane_open,
    cmd_needs_user_create,
    cmd_needs_user_resolve,
    register_coordination_commands,
    register_cross_lane_commands,
)
from .commands.confidentiality import (
    cmd_external_export_permit_consume,
    cmd_external_export_permit_issue,
    register_confidentiality_commands,
)
from .commands.execution_selection import (
    ExecutionSelectionCmdServices,
    cmd_execution_brief_record,
    cmd_execution_select,
    cmd_execution_select_plan,
    register_execution_selection_commands,
)
from .commands.improvement import (
    ImprovementCmdServices,
    cmd_improvement_arbitrate,
    cmd_improvement_brief,
    cmd_improvement_create,
    cmd_improvement_link_project,
    cmd_skill_adoption_record,
    cmd_skill_release_record,
    register_improvement_commands,
)
from .commands.integrity_v2 import (
    cmd_integrity_adopt,
    cmd_integrity_fix,
    cmd_integrity_review,
    cmd_integrity_seal,
    cmd_integrity_show,
    cmd_integrity_snapshot,
    cmd_integrity_upgrade_v2,
    cmd_integrity_verify,
    register_integrity_commands,
)
from .commands.jobs import register_job_commands
from .commands.lanes import (
    LanesCmdServices,
    cmd_lane_create,
    cmd_lane_dependency_add,
    cmd_lane_dependency_update,
    cmd_lane_revise,
    cmd_lane_set_status,
    register_lane_commands,
)
from .commands.packets import register_packet_commands
from .commands.offboard import cmd_offboard, register_offboard_commands
from .commands.resource import (
    ResourceCmdServices,
    cmd_codex_config_apply,
    cmd_codex_config_plan,
    cmd_codex_config_rollback,
    cmd_codex_session_register,
    cmd_codex_startup_receipt_show,
    cmd_override_arbitrate,
    cmd_override_request,
    cmd_override_revoke,
    register_resource_commands,
)
from .commands.release import (
    cmd_release_abandon_pending,
    cmd_release_manifest_observe,
    cmd_release_promote,
    cmd_release_show,
    register_release_commands,
)
from .commands.status import (
    StatusCmdServices,
    _clip_critical,
    cmd_render_index,
    cmd_resume,
    cmd_status,
    critical_projection,
    register_status_commands,
    resolve_resume_task,
)
from .commands.semantic import (
    cmd_cohort_round_prepare,
    cmd_cohort_round_preview,
    cmd_cohort_show,
    cmd_permit_consume,
    cmd_permit_issue,
    cmd_semantic_head,
    cmd_semantic_migrate,
    cmd_semantic_migration_rollback,
    register_semantic_commands,
)
from .commands.temporary_recovery import (
    TemporaryRecoveryServices,
    cmd_recover_temporaries,
    register_temporary_recovery_commands,
)
from .commands.mini_completion import MiniCompletionServices, cmd_finish_mini
from .commands import claude_onboarding as claude_onboarding_impl
from .commands import codex_onboarding as codex_onboarding_impl
from .commands.task_lifecycle import (
    TaskLifecycleCmdServices,
    _chief_credential,
    cmd_adopt_current_branch,
    cmd_approve_plan,
    cmd_audit_legacy,
    cmd_bind_session,
    cmd_check_locks,
    cmd_checkpoint,
    cmd_chief_acquire,
    cmd_chief_release,
    cmd_chief_renew,
    cmd_chief_status,
    cmd_chief_takeover,
    cmd_claim,
    cmd_config_check,
    cmd_import_legacy,
    cmd_init as _cmd_init,
    cmd_init_task,
    cmd_inspect_legacy,
    cmd_pilot_init,
    cmd_pilot_summary,
    cmd_pilot_validate,
    cmd_plan_update,
    cmd_release_claim,
    cmd_retarget_task,
    cmd_retire_risk,
    cmd_set_claim_status,
    cmd_set_phase,
    cmd_start_mini,
    cmd_unbind_session,
    register_bootstrap_commands,
    register_chief_commands,
    register_pilot_commands,
    register_task_lifecycle_commands,
)
from .commands.verification import register_verification_commands
from .codebase_memory import (
    QUERY_EVIDENCE_CATEGORY as CODEBASE_MEMORY_QUERY_EVIDENCE_CATEGORY,
    RECEIPT_MAX_BYTES as CODEBASE_MEMORY_RECEIPT_MAX_BYTES,
    active_receipt_records as active_context_receipt_records,
    canonical_json_sha256 as context_record_sha256,
    evaluate_live_receipt,
    make_receipt_record,
    parse_receipt_bytes,
    receipt_chain_errors,
    receipt_record_preimage,
    steward_binding as codebase_memory_steward_binding,
    validate_receipt_record,
    validate_steward_binding_set as validate_codebase_memory_steward_binding_set,
)
from .codebase_memory_benchmark import (
    EVIDENCE_CLASS as CODEBASE_MEMORY_BENCHMARK_EVIDENCE_CLASS,
    summarize_records as summarize_codebase_memory_benchmark_records,
    validate_record as validate_codebase_memory_benchmark_record,
)
from .context_receipts import (
    benchmark_ledger_preimage,
    context_benchmark_integrity_errors,
    context_provider_brief_bindings,
    context_receipt_integrity_errors,
    context_receipt_reports,
    validate_benchmark_ledger_record,
)
from .verification_integrity import (
    SUPERSESSION_MUTATION_FIELDS,
    verification_integrity_warnings,
    verification_legacy_materialization_preimage,
    verification_legacy_seal_preimage,
    verification_source_preimage,
    verification_supersession_errors,
)
from .execution_topology import (
    _is_steward_synthesis_packet,
    _require_execution_selection_snapshots_current,
    _selection_synthesis_freeze_packet_ids,
    _validate_active_execution_selection,
)
from .skill_lifecycle import (
    _json_nonnegative_int,
    _load_json_artifact,
    _parse_improvement_options,
    _require_project_result,
    _resolve_adoption_work_units,
    _resolve_improvement_occurrence,
    _skill_adoption_semantic_integrity_errors,
    _skill_bundle_member_hashes,
    _valid_named_checks,
    _valid_skill_manifest_files,
    _validate_skill_canary_work_unit_binding,
)
from .portfolio_integrity import _hard_dependency_cycle
from .config import ProjectConfig, default_config_text, load_config_path
from .pilot import (
    PilotError,
    _pilot_output_projects,
    initialize_kit,
    load_record,
    write_summary,
)
from .resource_config import (
    AOI_MAX_DELEGATION_DEPTH,
    ARISE_MAX_THREADS_CEILING,
    RESOURCE_RECEIPT_SCHEMA_VERSION,
    ResourceApplyRollbackError,
    apply_resource_files,
    build_codex_resource_plan,
    make_resource_receipt,
    parse_override_settings,
    reapply_files_from_receipt,
    resource_plan_sha256,
    rollback_files_from_receipt,
    validate_resource_receipt,
)
from .semantic_events import SemanticEventError, canonical_json_bytes

from .harnesslib import (
    ACCOUNTED_VERIFICATION_STATUSES,
    ACTIVE_JOB_STATUSES,
    ACTIVE_PACKET_STATUSES,
    MODEL_QUALITY_ELIGIBLE_OUTCOMES,
    PACKET_TYPED_OUTCOMES_BY_STATUS,
    CHIEF_DEFAULT_TTL_SECONDS,
    CLAIM_STATUSES,
    DELIVERY_MODES,
    JOB_STATUSES,
    PACKET_STATUSES,
    RESERVING_CLAIM_STATUSES,
    SCHEMA_VERSION,
    TASK_STATUSES,
    TERMINAL_CLAIM_STATUSES,
    VERIFICATION_STATUSES,
    HarnessError,
    HarnessPaths,
    atomic_create_bytes,
    atomic_create_text,
    atomic_write_bytes,
    atomic_write_json,
    atomic_write_text,
    acquire_chief_authority,
    baselines_for_locks,
    bootstrap_chief_state_lock,
    bump_task,
    canonicalize_no_link_traversal,
    checkpoint_matches,
    chief_authority_summary,
    claim_path,
    claims_for_task,
    claims_owned_by_task,
    discover_root,
    find_conflicts,
    fsync_directory,
    get_paths,
    host_path_to_wsl,
    import_legacy,
    is_expired,
    is_semantic_v2_task,
    lock_covers,
    legacy_pending_path,
    load_all_claims,
    load_all_tasks,
    load_claim_file,
    load_chief_authority,
    load_chief_credential,
    load_json,
    load_task,
    normalize_lock,
    now_iso,
    parse_legacy_table,
    parse_lock,
    parse_time,
    parse_tz_aware_time,
    platform_capabilities,
    preflight_layout,
    prepare_checkpoint,
    release_chief_authority,
    remove_chief_credential,
    record_legacy_decision,
    render_checkpoint,
    renew_chief_authority,
    require_complete_layout,
    require_chief_authority,
    scan_atomic_temporaries,
    semantic_task_projection_status,
    session_path,
    sha256_file,
    state_lock,
    task_dir,
    task_state_path,
    task_summary,
    takeover_chief_authority,
    validate_id,
    validate_existing_regular_file,
    validate_claim_lock_identities,
    validate_lock_identity,
    validate_packet_lock_identities,
    validated_state_worktree,
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
    "architect": "frontier",
    "analysis_specialist": "frontier",
    "implementation_specialist": "expert",
    "reviewer": "expert",
    "external_systems_expert": "expert",
    "worker": "advanced",
    "explorer": "standard",
    "external_operator": "standard",
    "default": "standard",
    "batch": "economical",
}
TERMINAL_PACKET_STATUSES = PACKET_STATUSES - ACTIVE_PACKET_STATUSES
EXECUTING_PACKET_STATUSES = {"armed", "dispatched"}
_CODEX_TRANSPORT_PACKET_TERMINAL_STATUS = {
    "completed": "done",
    "failed": "failed",
    "interrupted": "cancelled",
}
_CODEX_TRANSPORT_UNRESOLVED_TERMINAL_STATES = {
    "launch_unknown",
    "runtime_unknown",
}
NATIVE_V5_PACKET_CONTRACT_MARKER = "- AOI dispatch schema origin: `native_v5`"
HELPER_SPAWN_BUDGET_CONTRACT_PREFIX = "- AOI helper spawn budget:"
VERIFICATION_CATEGORIES = {
    "static_check",
    "unit_test",
    "integration_test",
    "compile_acceptance",
    "runtime_test",
    "runtime_test",
    "external_runtime",
    "system_evidence",
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


def _require_codex_transport_packet_terminal_status(
    launch_state: str, packet_status: str
) -> None:
    """Keep runtime terminal meaning distinct from the packet lifecycle.

    Unknown launch/runtime outcomes require explicit reconciliation and cannot
    be collapsed into any terminal packet verdict.  Known outcomes have one
    exact packet-status mapping; a technical result such as rejection belongs
    in ``typed_outcome`` rather than by contradicting the runtime state.
    """

    if launch_state in _CODEX_TRANSPORT_UNRESOLVED_TERMINAL_STATES:
        raise HarnessError(
            f"Codex transport launch is {launch_state}; reconcile the exact "
            "launch before recording any terminal packet status"
        )
    expected_status = _CODEX_TRANSPORT_PACKET_TERMINAL_STATUS.get(launch_state)
    if expected_status is None:
        raise HarnessError(
            f"Codex transport launch state {launch_state!r} is not a terminal verdict"
        )
    if packet_status != expected_status:
        raise HarnessError(
            f"Codex transport launch state {launch_state!r} requires packet "
            f"status {expected_status!r}, not {packet_status!r}"
        )
CLOSE_QUALIFYING_CATEGORIES = VERIFICATION_CATEGORIES - {
    "engineering_inference",
    "historical_terminal_readback",
}
RECEIPT_COMPONENTS: tuple[str, ...] = ("source", "runner", "config", "dependencies", "other")
REQUIRED_RECEIPT_COMPONENTS: tuple[str, ...] = ("source", "runner")
HOOK_PROTOCOL_VERSION = "6"
DISPATCH_ARM_MAX_SECONDS = 15 * 60
HELPER_SPAWN_BUDGET_MAX = 8
HOOK_ID_RE = AGENT_ID_RE
ROOT_SESSION_MAPPING_KIND = "root"
SUBAGENT_PARENT_MAPPING_KIND = "subagent_parent"
HOOK_OBSERVED_DISPATCH_PROVENANCES = {
    "codex_subagent_start_observed",
    "claude_subagent_start_observed",
}
DISPATCH_PROVENANCES = {
    "none",
    *HOOK_OBSERVED_DISPATCH_PROVENANCES,
    "manual_unverified",
}
MINI_MAX_LOCKS = 3
MINI_FORBIDDEN_REPO_PREFIXES: tuple[str, ...] = (
    ".aoi/",
    "infra/",
    "security/",
    "deploy/",
    ".codex/",
)
LANE_KINDS = {
    "architecture",
    "implementation",
    "analysis",
    "reference",
    "verification",
    "external_systems",
    "physical",
    "performance",
    "integration",
    "coordination_steward",
    "capacity_planning",
    "other",
}


def apply_project_config(config: ProjectConfig) -> None:
    """Apply one immutable project profile before parser construction."""

    global ROLE_TIER_MAP
    global VERIFICATION_CATEGORIES, CLOSE_QUALIFYING_CATEGORIES
    global RECEIPT_COMPONENTS, REQUIRED_RECEIPT_COMPONENTS
    global MINI_FORBIDDEN_REPO_PREFIXES, LANE_KINDS
    ROLE_TIER_MAP = dict(config.roles)
    VERIFICATION_CATEGORIES = set(config.evidence_categories)
    CLOSE_QUALIFYING_CATEGORIES = set(config.close_qualifying_categories)
    RECEIPT_COMPONENTS = tuple(config.receipt_components)
    REQUIRED_RECEIPT_COMPONENTS = tuple(config.required_receipt_components)
    MINI_FORBIDDEN_REPO_PREFIXES = tuple(config.high_risk_paths)
    LANE_KINDS = {
        "architecture",
        "implementation",
        "analysis",
        "reference",
        "verification",
        "external_systems",
        "physical",
        "performance",
        "integration",
        "coordination_steward",
        "capacity_planning",
        "other",
        *config.departments,
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
BOUND_ARTIFACT_TOTAL_MAX_BYTES = 64 * 1024 * 1024
CAPABILITY_CATALOG_VERSION = 1
CAPABILITY_TIER_MAP = {
    "c1_mechanical": "economical",
    "c2_routine": "standard",
    "c3_advanced": "advanced",
    "c4_expert": "expert",
    "c5_frontier": "frontier",
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
OVERRIDE_TARGET_KINDS = {"execution_resource", "resource_config"}
OVERRIDE_STATUSES = {
    "awaiting_chief",
    "approved",
    "rejected",
    "consumed",
    "revoked",
}
RESOURCE_CONFIG_EVENT_STATUSES = {"applied", "rolled_back"}
RESOURCE_ENVELOPE_SCHEMA_VERSION = 1
RESOURCE_DEFAULT_PARALLEL_AGENTS = 4
COOPERATIVE_AUTHORITY_BOUNDARY = (
    "task-bound session assertion only; AOI does not authenticate the caller identity"
)
CHIEF_AUTHORITY_CONTROL_COMMANDS = {
    "chief-acquire",
    "chief-renew",
    "chief-release",
    "chief-takeover",
    "recover-temporaries",
}
CHIEF_PROJECT_READ_ONLY_COMMANDS = {
    "chief-status",
    "check-locks",
    "codebase-memory-benchmark-validate",
    "codex-config-plan",
    "codex-startup-receipt-show",
    "cohort-round-prepare",
    "cohort-round-preview",
    "cohort-show",
    "inspect-legacy",
    "integrity-show",
    "release-manifest-observe",
    "release-show",
    "reconcile",
    "resume",
    "semantic-head",
    "status",
    "verify-backup",
    "doctor",
}
# Permit consumption is an explicit no-Chief project mutation.  It is not
# read-only: the command may publish one already Chief-issued exact semantic
# transition, and its handler therefore owns the normal project state lock.
CHIEF_PROJECT_PERMIT_CONSUMER_COMMANDS = {
    "external-export-permit-consume",
    "permit-consume",
}
CHIEF_STANDALONE_READ_ONLY_COMMANDS = {
    "config-check",
    "pilot-validate",
}
CHIEF_STANDALONE_WRITER_COMMANDS = {
    "pilot-init",
    "pilot-summary",
}
CHIEF_STANDALONE_COMMANDS = (
    CHIEF_STANDALONE_READ_ONLY_COMMANDS | CHIEF_STANDALONE_WRITER_COMMANDS
)
KNOWN_MANAGED_POLICY_SHA256 = {
    # AOI v0.1.3 packaged policy; safe one-way replacement during authenticated init.
    "76f116580d535ec33ca19da1e53ec3c3d35c107b05768a55d5ee654f477a3c85",
    # AOI v0.2.1 policy before canonical long-spelling lock enforcement.
    "eb03c009470e9bd27b521de6116b6206bfc0abf9785d0b1a1fe31416054a083f",
}


class AOIArgumentParser(argparse.ArgumentParser):
    """Disable ambiguous long-option abbreviation on every parser level."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)


def command_requires_chief(command: str, *, initialized: bool) -> bool:
    """Default-fence every project command not explicitly proven exempt."""

    if command in {"init", "claude-init", "codex-init"}:
        return initialized
    return command not in (
        CHIEF_AUTHORITY_CONTROL_COMMANDS
        | CHIEF_PROJECT_READ_ONLY_COMMANDS
        | CHIEF_PROJECT_PERMIT_CONSUMER_COMMANDS
        | CHIEF_STANDALONE_READ_ONLY_COMMANDS
    )


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


def _evidence_artifacts_policy() -> evidence_artifacts_impl.EvidenceArtifactsPolicy:
    return evidence_artifacts_impl.EvidenceArtifactsPolicy(
        bound_artifact_total_max_bytes=BOUND_ARTIFACT_TOTAL_MAX_BYTES,
    )


def _is_canonical_snapshot_version(value: Any) -> bool:
    return evidence_artifacts_impl._is_canonical_snapshot_version(value)


def _is_legacy_snapshot_version(value: Any) -> bool:
    return evidence_artifacts_impl._is_legacy_snapshot_version(value)


def _packet_schema_version(packet: dict[str, Any]) -> int | None:
    return evidence_artifacts_impl._packet_schema_version(packet)


def read_regular_artifact(
    value: str | Path,
    label: str,
    *,
    max_bytes: int,
    require_utf8: bool = False,
) -> tuple[Path, bytes]:
    return evidence_artifacts_impl.read_regular_artifact(
        value, label, max_bytes=max_bytes, require_utf8=require_utf8
    )


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
    return evidence_artifacts_impl.snapshot_evidence_artifact(
        paths,
        task_id,
        source_value,
        expected_sha,
        label=label,
        basename=basename,
        max_bytes=max_bytes,
    )


def artifact_blob_path(paths: HarnessPaths, task_id: str, digest: str) -> Path:
    return evidence_artifacts_impl.artifact_blob_path(paths, task_id, digest)


def ensure_artifact_blob_parent(
    paths: HarnessPaths, task_id: str, digest: str, *, create: bool
) -> Path:
    return evidence_artifacts_impl.ensure_artifact_blob_parent(
        paths, task_id, digest, create=create
    )


def prepare_bound_artifacts(
    values: Iterable[str],
    label: str,
) -> list[dict[str, Any]]:
    return evidence_artifacts_impl.prepare_bound_artifacts(
        values, label, policy=_evidence_artifacts_policy()
    )


def preserve_bound_artifacts(
    paths: HarnessPaths,
    task_id: str,
    prepared: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    return evidence_artifacts_impl.preserve_bound_artifacts(paths, task_id, prepared)


def canonical_recovery_archive_member(member_name: str) -> str:
    return evidence_artifacts_impl.canonical_recovery_archive_member(member_name)


def read_recovery_tar_member(
    archive_data: bytes,
    member_name: str,
    *,
    budget: dict[str, int] | None = None,
) -> bytes:
    return evidence_artifacts_impl.read_recovery_tar_member(
        archive_data, member_name, budget=budget, policy=_evidence_artifacts_policy()
    )


def recovery_record_preimage(
    state: dict[str, Any],
    packet: dict[str, Any],
    target_index: int,
    target: dict[str, Any],
    carrier_index: int,
    carrier: dict[str, Any],
    recovery: dict[str, Any],
) -> dict[str, Any]:
    return evidence_artifacts_impl.recovery_record_preimage(
        state, packet, target_index, target, carrier_index, carrier, recovery
    )


def artifact_ref_integrity_error(
    paths: HarnessPaths,
    state: dict[str, Any],
    artifact: dict[str, Any],
    *,
    require_origin: bool,
) -> str | None:
    return evidence_artifacts_impl.artifact_ref_integrity_error(
        paths, state, artifact, require_origin=require_origin
    )


def _skill_lifecycle_services() -> skill_lifecycle_impl.SkillLifecycleServices:
    return skill_lifecycle_impl.SkillLifecycleServices(
        require_done_reviewer_packet=_require_done_reviewer_packet,
    )


def _skill_release_semantic_integrity_errors(
    state: dict[str, Any],
    release: dict[str, Any],
    paths: HarnessPaths | None,
) -> list[str]:
    return skill_lifecycle_impl._skill_release_semantic_integrity_errors(
        state,
        release,
        paths,
        services=_skill_lifecycle_services(),
    )


def _resource_governance_policy(
) -> resource_governance_impl.ResourceGovernancePolicy:
    return resource_governance_impl.ResourceGovernancePolicy(
        role_tier_map=ROLE_TIER_MAP,
        depth_two_roles=DEPTH_TWO_ROLES,
        executing_packet_statuses=EXECUTING_PACKET_STATUSES,
        override_target_kinds=OVERRIDE_TARGET_KINDS,
        override_statuses=OVERRIDE_STATUSES,
        resource_config_event_statuses=RESOURCE_CONFIG_EVENT_STATUSES,
        envelope_schema_version=RESOURCE_ENVELOPE_SCHEMA_VERSION,
        default_parallel_agents=RESOURCE_DEFAULT_PARALLEL_AGENTS,
    )


def _dispatch_protocol_policy(
) -> dispatch_protocol_impl.DispatchProtocolPolicy:
    return dispatch_protocol_impl.DispatchProtocolPolicy(
        hook_protocol_version=int(HOOK_PROTOCOL_VERSION),
        hook_id_re=HOOK_ID_RE,
        executing_packet_statuses=frozenset(EXECUTING_PACKET_STATUSES),
        root_session_mapping_kind=ROOT_SESSION_MAPPING_KIND,
        subagent_parent_mapping_kind=SUBAGENT_PARENT_MAPPING_KIND,
    )


def _claude_dispatch_protocol_policy(
) -> dispatch_protocol_impl.DispatchProtocolPolicy:
    """Claude Code transport shares dispatch protocol v6; only provenance differs.

    Consumption is observed at the Claude ``SubagentStart`` hook event, which
    carries the same parent-session/agent-type/agent-id coordinates as the
    Codex event. The distinct provenance label keeps the transport that
    actually observed the dispatch auditable instead of implying a Codex
    observation that never happened.
    """
    return dispatch_protocol_impl.DispatchProtocolPolicy(
        hook_protocol_version=int(HOOK_PROTOCOL_VERSION),
        hook_id_re=HOOK_ID_RE,
        executing_packet_statuses=frozenset(EXECUTING_PACKET_STATUSES),
        root_session_mapping_kind=ROOT_SESSION_MAPPING_KIND,
        subagent_parent_mapping_kind=SUBAGENT_PARENT_MAPPING_KIND,
        dispatch_provenance="claude_subagent_start_observed",
    )


def _verification_policy() -> verification_integrity_impl.VerificationPolicy:
    return verification_integrity_impl.VerificationPolicy(
        verification_categories=VERIFICATION_CATEGORIES,
        close_qualifying_categories=CLOSE_QUALIFYING_CATEGORIES,
    )


def _job_integrity_policy() -> job_integrity_impl.JobIntegrityPolicy:
    return job_integrity_impl.JobIntegrityPolicy(
        receipt_components=tuple(RECEIPT_COMPONENTS),
        required_receipt_components=tuple(REQUIRED_RECEIPT_COMPONENTS),
    )


def _job_integrity_services() -> job_integrity_impl.JobIntegrityServices:
    return job_integrity_impl.JobIntegrityServices(
        validate_skill_canary_work_unit_binding=_validate_skill_canary_work_unit_binding,
        execution_topology=_execution_topology_services(),
    )


def _packet_integrity_services() -> packet_integrity_impl.PacketIntegrityServices:
    return packet_integrity_impl.PacketIntegrityServices(
        validate_packet_resource_envelope=_validate_packet_resource_envelope,
        selection_terminal_packet_bindings=_selection_terminal_packet_bindings,
        dispatch_attempt_authority_sha256=_dispatch_attempt_authority_sha256,
        active_dispatch_attempt=_active_dispatch_attempt,
        safe_hook_observation_text=_safe_hook_observation_text,
        subagent_event_id=_subagent_event_id,
    )


def _lane_authority_snapshot(lane: dict[str, Any]) -> dict[str, Any]:
    return resource_governance_impl.lane_authority_snapshot(lane)


def _build_execution_resource_envelope(
    *,
    mode: str,
    lanes: list[dict[str, Any]],
    steward: dict[str, Any] | None,
    override_id: str,
    override_settings: dict[str, str | int],
) -> tuple[dict[str, Any], str]:
    return resource_governance_impl.build_execution_resource_envelope(
        mode=mode,
        lanes=lanes,
        steward=steward,
        override_id=override_id,
        override_settings=override_settings,
        policy=_resource_governance_policy(),
    )


def _validate_selection_resource_envelope(
    state: dict[str, Any], selection: dict[str, Any]
) -> dict[str, Any] | None:
    return resource_governance_impl.validate_selection_resource_envelope(
        state,
        selection,
        policy=_resource_governance_policy(),
    )


def _validate_packet_resource_envelope(
    state: dict[str, Any],
    packet: dict[str, Any],
    selection: dict[str, Any] | None,
    *,
    enforce_active_limit: bool,
) -> None:
    resource_governance_impl.validate_packet_resource_envelope(
        state,
        packet,
        selection,
        enforce_active_limit=enforce_active_limit,
        policy=_resource_governance_policy(),
    )


def resource_envelope_integrity_errors(state: dict[str, Any]) -> list[str]:
    return resource_governance_impl.resource_envelope_integrity_errors(
        state, policy=_resource_governance_policy()
    )


def _execution_topology_services() -> execution_topology_impl.ExecutionTopologyServices:
    return execution_topology_impl.ExecutionTopologyServices(
        packet_authority_integrity_errors=packet_authority_integrity_errors,
        validate_packet_resource_envelope=_validate_packet_resource_envelope,
        selection_terminal_packet_bindings=_selection_terminal_packet_bindings,
    )


def _validate_packet_activation_topology(
    state: dict[str, Any], packet: dict[str, Any]
) -> dict[str, Any] | None:
    return execution_topology_impl._validate_packet_activation_topology(
        state, packet, services=_execution_topology_services()
    )


def _validate_owned_job_authority(
    paths: HarnessPaths | None,
    state: dict[str, Any],
    job: dict[str, Any],
    *,
    require_dispatched: bool,
) -> dict[str, Any]:
    return execution_topology_impl._validate_owned_job_authority(
        paths,
        state,
        job,
        require_dispatched=require_dispatched,
        services=_execution_topology_services(),
    )


def _validate_job_activation_topology(
    state: dict[str, Any],
    job: dict[str, Any],
    selection: dict[str, Any] | None,
    *,
    paths: HarnessPaths | None = None,
    exclude_run_id: str = "",
) -> dict[str, Any] | None:
    return execution_topology_impl._validate_job_activation_topology(
        state,
        job,
        selection,
        paths=paths,
        exclude_run_id=exclude_run_id,
        services=_execution_topology_services(),
    )


def override_by_id(state: dict[str, Any], override_id: str) -> dict[str, Any]:
    return resource_governance_impl.override_by_id(state, override_id)


def approved_override_settings(
    state: dict[str, Any],
    override_id: str,
    *,
    target_kind: str,
    target_id: str,
) -> dict[str, str | int]:
    return resource_governance_impl.approved_override_settings(
        state,
        override_id,
        target_kind=target_kind,
        target_id=target_id,
        policy=_resource_governance_policy(),
    )


def require_override_target_contract(
    state: dict[str, Any], override_id: str, target_contract_sha256: str
) -> None:
    resource_governance_impl.require_override_target_contract(
        state, override_id, target_contract_sha256
    )


def override_integrity_errors(state: dict[str, Any]) -> list[str]:
    return resource_governance_impl.override_integrity_errors(
        state, policy=_resource_governance_policy()
    )


def resource_config_integrity_errors(
    paths: HarnessPaths, state: dict[str, Any]
) -> list[str]:
    return resource_governance_impl.resource_config_integrity_errors(
        paths, state, policy=_resource_governance_policy()
    )


def require_root_session(
    paths: HarnessPaths, state: dict[str, Any], session_id: str
) -> str:
    """Check task/session continuity, not platform-authenticated identity."""
    session_id = check_session_id(session_id)
    if session_id not in state.get("session_ids", []):
        raise HarnessError(
            "root arbitration requires a cooperatively asserted session bound to this task"
        )
    mapping = load_json(session_path(paths, session_id))
    if (
        mapping.get("task_id") != state.get("task_id")
        or mapping.get("mapping_kind", ROOT_SESSION_MAPPING_KIND)
        != ROOT_SESSION_MAPPING_KIND
    ):
        raise HarnessError("root arbitration session mapping does not match this task")
    return session_id


def _portfolio_integrity_policy() -> portfolio_integrity_impl.PortfolioIntegrityPolicy:
    return portfolio_integrity_impl.PortfolioIntegrityPolicy(
        lane_kinds=LANE_KINDS,
        lane_statuses=LANE_STATUSES,
        max_engaged_lanes=MAX_ENGAGED_LANES,
        dependency_kinds=DEPENDENCY_KINDS,
        dependency_statuses=DEPENDENCY_STATUSES,
        coordination_statuses=COORDINATION_STATUSES,
        close_qualifying_categories=CLOSE_QUALIFYING_CATEGORIES,
        capability_catalog_version=CAPABILITY_CATALOG_VERSION,
        capability_tier_map=CAPABILITY_TIER_MAP,
        improvement_statuses=IMPROVEMENT_STATUSES,
        improvement_trigger_classes=IMPROVEMENT_TRIGGER_CLASSES,
        execution_modes=EXECUTION_MODES,
        executing_packet_statuses=EXECUTING_PACKET_STATUSES,
        cross_lane_session_statuses=CROSS_LANE_SESSION_STATUSES,
        needs_user_statuses=NEEDS_USER_STATUSES,
        needs_user_categories=NEEDS_USER_CATEGORIES,
    )


def _portfolio_integrity_services() -> portfolio_integrity_impl.PortfolioIntegrityServices:
    return portfolio_integrity_impl.PortfolioIntegrityServices(
        records_fingerprint=_records_fingerprint,
        steward_packet_binding=_steward_packet_binding,
        skill_release_semantic_integrity_errors=_skill_release_semantic_integrity_errors,
        validate_packet_activation_topology=_validate_packet_activation_topology,
        validate_job_activation_topology=_validate_job_activation_topology,
        job_launch_authority_errors=_job_launch_authority_errors,
    )


def portfolio_integrity_errors(
    state: dict[str, Any], paths: HarnessPaths | None = None
) -> list[str]:
    return portfolio_integrity_impl.portfolio_integrity_errors(
        state,
        paths,
        policy=_portfolio_integrity_policy(),
        services=_portfolio_integrity_services(),
    )


def packet_command_integrity_error(packet: dict[str, Any]) -> str | None:
    return packet_integrity_impl.packet_command_integrity_error(packet)


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
            raw_path == prefix.rstrip("/")
            or raw_path.startswith(prefix.rstrip("/") + "/")
            for prefix in MINI_FORBIDDEN_REPO_PREFIXES
        ):
            raise HarnessError(f"mini task may not own high-risk path: {raw_path}")
        if namespace == "host" and raw_path.casefold().endswith("/.codex/hooks.json"):
            raise HarnessError("mini task may not change trusted hook definitions")
    return locks


def packet_contract_integrity_error(
    paths: HarnessPaths, state: dict[str, Any], packet: dict[str, Any]
) -> str | None:
    return packet_integrity_impl.packet_contract_integrity_error(paths, state, packet)


def packet_input_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet: dict[str, Any],
    *,
    require_origin: bool,
) -> list[str]:
    return packet_integrity_impl.packet_input_integrity_errors(
        paths, state, packet, require_origin=require_origin
    )


def packet_lock_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet: dict[str, Any],
) -> list[str]:
    return packet_integrity_impl.packet_lock_integrity_errors(paths, state, packet)


def packet_resource_envelope_integrity_errors(
    state: dict[str, Any], packet: dict[str, Any]
) -> list[str]:
    return packet_integrity_impl.packet_resource_envelope_integrity_errors(
        state, packet, services=_packet_integrity_services()
    )


def packet_authority_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet: dict[str, Any],
    *,
    require_origin: bool,
    _visited: set[str] | None = None,
) -> list[str]:
    return packet_integrity_impl.packet_authority_integrity_errors(
        paths,
        state,
        packet,
        require_origin=require_origin,
        _visited=_visited,
        services=_packet_integrity_services(),
    )


def selection_done_packet_authority_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    selection_id: str,
) -> list[str]:
    return packet_integrity_impl.selection_done_packet_authority_errors(
        paths, state, selection_id, services=_packet_integrity_services()
    )


def packet_integrity_warnings(state: dict[str, Any]) -> list[str]:
    return packet_integrity_impl.packet_integrity_warnings(state)


def packet_result_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet: dict[str, Any],
) -> list[str]:
    return packet_integrity_impl.packet_result_integrity_errors(paths, state, packet)


def packet_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    allow_done_lock_recovery: bool = False,
    packet_ids: set[str] | None = None,
) -> list[str]:
    return packet_integrity_impl.packet_integrity_errors(
        paths,
        state,
        allow_done_lock_recovery=allow_done_lock_recovery,
        packet_ids=packet_ids,
        services=_packet_integrity_services(),
    )


def subagent_incident_integrity_errors(state: dict[str, Any]) -> list[str]:
    return packet_integrity_impl.subagent_incident_integrity_errors(
        state, services=_packet_integrity_services()
    )


def _object_records_for_derivation(
    state: dict[str, Any], field: str
) -> list[dict[str, Any]]:
    """Return trusted object records only after the whole collection is shaped.

    Command gates call the corresponding integrity reader before using this
    helper.  Returning an empty list for malformed input prevents a second,
    raw Python exception or misleading derived gate failures while preserving
    the reader's canonical integrity diagnostic.
    """

    records = state.get(field, [])
    if not isinstance(records, list) or not all(
        isinstance(item, dict) for item in records
    ):
        return []
    return cast(list[dict[str, Any]], records)


def packet_recovery_integrity_errors(
    paths: HarnessPaths, state: dict[str, Any]
) -> list[str]:
    return evidence_artifacts_impl.packet_recovery_integrity_errors(
        paths, state, policy=_evidence_artifacts_policy()
    )


def _require_done_reviewer_packet(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet_id: str,
    *,
    required_artifact_shas: set[str] | None = None,
) -> dict[str, Any]:
    return packet_integrity_impl._require_done_reviewer_packet(
        paths,
        state,
        packet_id,
        required_artifact_shas=required_artifact_shas,
        services=_packet_integrity_services(),
    )


def validate_source_receipt(
    source: Path,
    expected_sha: str,
    *,
    tool_path: str,
    tool_version: str,
    command: str,
) -> tuple[dict[str, Any], bytes]:
    return job_integrity_impl.validate_source_receipt(
        source,
        expected_sha,
        tool_path=tool_path,
        tool_version=tool_version,
        command=command,
        policy=_job_integrity_policy(),
    )


def job_integrity_errors(paths: HarnessPaths, state: dict[str, Any]) -> list[str]:
    return job_integrity_impl.job_integrity_errors(
        paths,
        state,
        policy=_job_integrity_policy(),
        services=_job_integrity_services(),
    )


def verification_record_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    indexed_records: Iterable[tuple[int, dict[str, Any]]] | None = None,
) -> list[str]:
    return verification_integrity_impl.verification_record_integrity_errors(
        paths,
        state,
        indexed_records,
        policy=_verification_policy(),
    )


def verification_integrity_errors(
    paths: HarnessPaths, state: dict[str, Any]
) -> list[str]:
    return verification_integrity_impl.verification_integrity_errors(
        paths, state, policy=_verification_policy()
    )


def verification_migration_integrity_errors(
    paths: HarnessPaths, state: dict[str, Any]
) -> list[str]:
    return verification_integrity_impl.verification_migration_integrity_errors(
        paths, state, policy=_verification_policy()
    )


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


def require_absolute_local_path(value: str, label: str) -> Path:
    """Validate a controller-local path without imposing remote POSIX syntax."""

    cleaned = require_text(value, label)
    path = Path(cleaned).expanduser()
    if not path.is_absolute() or ".." in path.parts:
        raise HarnessError(f"{label} must be an absolute normalized local path: {value!r}")
    return path


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
        if (
            current.get("mapping_kind", ROOT_SESSION_MAPPING_KIND)
            == SUBAGENT_PARENT_MAPPING_KIND
        ):
            raise HarnessError(
                "subagent parent mapping cannot be promoted to a root session; "
                "explicitly unbind it first"
            )
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
        "mapping_kind": ROOT_SESSION_MAPPING_KIND,
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


def ensure_subagent_parent_mapping_unlocked(
    paths: HarnessPaths, state: dict[str, Any], packet: dict[str, Any]
) -> None:
    """Bind a depth-one agent only for nested SubagentStart task lookup."""

    if int(packet.get("delegation_depth", 1)) != 1:
        raise HarnessError("only a depth-one packet may own a subagent parent mapping")
    session_id = str(packet.get("agent_id", ""))
    if not HOOK_ID_RE.fullmatch(session_id):
        raise HarnessError("depth-one packet agent id is unsafe for parent mapping")
    destination = session_path(paths, session_id)
    expected_identity = {
        "mapping_kind": SUBAGENT_PARENT_MAPPING_KIND,
        "session_id": session_id,
        "task_id": state["task_id"],
        "packet_id": str(packet.get("packet_id", "")),
    }
    if destination.exists():
        current = load_json(destination)
        if any(current.get(key) != value for key, value in expected_identity.items()):
            raise HarnessError(
                "depth-one agent id already has a different session authority mapping"
            )
    else:
        atomic_write_json(
            destination,
            {
                "schema_version": SCHEMA_VERSION,
                **expected_identity,
                "checkpoint_path": str(
                    task_dir(paths, state["task_id"]) / "checkpoint.md"
                ),
                "updated_at": now_iso(),
            },
        )
    parent_ids = state.setdefault("subagent_parent_session_ids", [])
    if session_id not in parent_ids:
        parent_ids.append(session_id)


def unbind_all_sessions_unlocked(paths: HarnessPaths, state: dict[str, Any]) -> None:
    session_ids = [
        *state.get("session_ids", []),
        *state.get("subagent_parent_session_ids", []),
    ]
    for session_id in dict.fromkeys(session_ids):
        destination = session_path(paths, session_id)
        if not destination.exists():
            continue
        try:
            mapping = load_json(destination)
        except HarnessError:
            continue
        if mapping.get("task_id") == state["task_id"]:
            destination.unlink()


def _resource_text(name: str) -> str:
    resource = importlib.resources.files("aoi_orgware.resources").joinpath(name)
    return resource.read_text(encoding="utf-8")


def _onboarding_resume_instruction(command: str, *, created_config: bool) -> str:
    if created_config:
        return (
            f"{command} writes each destination atomically and is idempotent, but "
            "AOI is now initialized. Acquire a Chief lease with `aoi "
            "chief-acquire --session-id <session-id> --json`, export the returned "
            "AOI_CHIEF_* credential fields, then rerun the same command to resume"
        )
    return (
        f"{command} writes each destination atomically and is idempotent; "
        "rerun the same command with the current Chief credential to resume"
    )


def cmd_claude_init(args: argparse.Namespace, paths: HarnessPaths) -> int:
    """One command: initialize AOI and wire this repo's Claude Code sessions.

    Combines the standard ``aoi init`` contract with client-side wiring — the
    lifecycle hooks in ``.claude/settings.json`` and the user-scope AOI skill —
    so a repo can be put under AOI governance in a single step. First-time use
    on an uninitialized project needs no Chief credential (like ``aoi init``);
    re-running on an initialized project is Chief-fenced.
    """

    if not (paths.root / ".git").exists():
        raise HarnessError("aoi claude-init requires a Git repository root")
    user_skills_root = (
        Path(args.user_skills_root).expanduser()
        if args.user_skills_root
        else Path.home() / ".claude" / "skills"
    )
    claude_skill_text = _resource_text("claude/SKILL.md")
    settings_path = paths.root / ".claude" / "settings.json"
    try:
        hooks_preflight = claude_onboarding_impl.preflight_claude_onboarding(
            settings_path,
            governed_agent_types=args.governed_agent_types,
        )
        skill_preflight = claude_onboarding_impl.preflight_claude_user_skill(
            user_skills_root,
            claude_skill_text,
            replace_sha256=args.replace_user_skill_sha256,
        )
    except (OSError, claude_onboarding_impl.ClaudeOnboardingError) as exc:
        raise HarnessError(str(exc)) from exc
    # 1. Initialize AOI if needed, reusing the exact init contract. Capture its
    #    JSON emit so claude-init can print one combined summary.
    init_ns = argparse.Namespace(
        project_name=args.project_name,
        config=None,
        expected_config_sha256=None,
        replace_policy_sha256=None,
        json=True,
    )
    captured = io.StringIO()
    saved_stdout = sys.stdout
    sys.stdout = captured
    try:
        cmd_init(init_ns, paths)
    finally:
        sys.stdout = saved_stdout
    try:
        init_result = json.loads(captured.getvalue() or "{}")
    except json.JSONDecodeError:
        init_result = {}
    paths = get_paths(paths.root)
    project_name = init_result.get("project", paths.project.name)
    created_config = bool(init_result.get("created_config", False))
    # 2. Wire the Claude Code lifecycle hooks and install the AOI skill.
    try:
        # Existing projects already hold the command-wide lock. Fresh init did
        # not, so keep this reentrant acquisition across every later write and
        # refuse if a competing Chief appeared after bootstrap.
        with state_lock(paths):
            paths = _reload_locked_paths(paths)
            if created_config and load_chief_authority(
                paths, allow_missing=True
            ) is not None:
                raise HarnessError(
                    "Chief authority appeared after fresh AOI initialization; "
                    "acquire that Chief authority and rerun claude-init"
                )
            hooks_result = claude_onboarding_impl.install_claude_hooks(
                settings_path,
                governed_agent_types=args.governed_agent_types,
            )
            skill_result = claude_onboarding_impl.install_claude_user_skill(
                user_skills_root,
                claude_skill_text,
                replace_sha256=args.replace_user_skill_sha256,
            )
    except (
        HarnessError,
        OSError,
        claude_onboarding_impl.ClaudeOnboardingError,
    ) as exc:
        raise HarnessError(
            f"{exc}; "
            + _onboarding_resume_instruction(
                "claude-init",
                created_config=created_config,
            )
        ) from exc
    payload = {
        "claude_init": True,
        "project": project_name,
        "root": str(paths.root),
        "aoi_initialized": init_result.get("initialized", True),
        "created_config": init_result.get("created_config", False),
        "preflight": {
            "hooks": hooks_preflight,
            "user_skill": skill_preflight,
        },
        "resumable": True,
        "hooks": hooks_result,
        "skill": skill_result,
        "next_steps": [
            "Install aoi on your PATH (e.g. pipx install aoi-orgware) so the "
            "hook command 'aoi-claude-hook' resolves.",
            "Open a NEW Claude Code session in this repo; the SessionStart hook "
            f"will announce that AOI is active for {project_name!r}.",
            "The generic AOI skill is installed once at Claude user scope; keep "
            "project-specific instructions in the repository CLAUDE.md/AGENTS.md.",
            "For governed work, acquire a Chief lease: aoi chief-acquire "
            "--session-id <session-id> --json, then export the returned "
            "AOI_CHIEF_* variables.",
        ],
    }
    emit(payload, args.json)
    return 0

def _enable_codex_hook_policy(
    paths: HarnessPaths, *, fresh_unauthenticated_init: bool
) -> tuple[HarnessPaths, bool]:
    """Enable the explicit AOI Codex-hook policy without changing any other key."""

    # Existing projects arrive under the command-wide state lock. Fresh init
    # releases its bootstrap lock before returning, so reacquire it here and
    # recheck that no Chief/task appeared in the gap before changing the config
    # digest. The lock is exact-path reentrant for the existing-project path.
    with state_lock(paths):
        paths = _reload_locked_paths(paths)
        if fresh_unauthenticated_init and load_chief_authority(
            paths, allow_missing=True
        ) is not None:
            raise HarnessError(
                "Chief authority appeared after fresh AOI initialization; acquire "
                "that Chief authority and rerun codex-init"
            )
        if paths.project.codex_hooks_enabled:
            return paths, False
        active_tasks = [
            str(state.get("task_id", ""))
            for state in load_all_tasks(paths)
            if state.get("status") in {"active", "blocked"}
        ]
        if active_tasks:
            raise HarnessError(
                "cannot enable hooks.codex while active AOI tasks bind the current "
                f"configuration digest: {sorted(active_tasks)}"
            )
        try:
            current_text = paths.config.read_text(encoding="utf-8")
            candidate, changed = codex_onboarding_impl.enable_aoi_codex_hooks_policy(
                current_text
            )
        except (OSError, codex_onboarding_impl.CodexOnboardingError) as exc:
            raise HarnessError(str(exc)) from exc
        if not changed:
            return paths, False
        atomic_write_text(paths.config, candidate)
        updated = get_paths(paths.root)
        if updated.harness != paths.harness or updated.lock != paths.lock:
            raise HarnessError(
                "codex-init changed an AOI path or lock domain unexpectedly; "
                "restore aoi.toml"
            )
        if not updated.project.codex_hooks_enabled:
            raise HarnessError("codex-init failed to enable hooks.codex in aoi.toml")
        write_index(updated)
        return updated, True


_CODEX_PROVENANCE_HISTORY_DIRECTORY = "codex-install-provenance-history-v1"
_CODEX_PROVENANCE_HISTORY_MAX = 16


def _codex_provenance_bytes(receipt: dict[str, Any]) -> bytes:
    validated = (
        codex_install_provenance_impl.validate_codex_install_provenance_receipt(
            receipt
        )
    )
    return canonical_json_bytes(validated, max_bytes=64 * 1024)


def _codex_provenance_preflight(
    paths: HarnessPaths, candidate: dict[str, Any]
) -> dict[str, Any]:
    """Validate the current receipt/history before any onboarding mutation."""

    candidate_bytes = _codex_provenance_bytes(candidate)
    receipt_path = (
        paths.root
        / codex_install_provenance_impl.CODEX_INSTALL_PROVENANCE_RECEIPT
    )
    if not receipt_path.exists() and not receipt_path.is_symlink():
        return {
            "receipt_path": str(receipt_path),
            "changed": True,
            "previous_provenance_sha256": None,
        }
    existing = (
        codex_install_provenance_impl.load_codex_install_provenance_receipt(
            paths.root
        )
    )
    existing_bytes = _codex_provenance_bytes(existing)
    if existing_bytes == candidate_bytes:
        return {
            "receipt_path": str(receipt_path),
            "changed": False,
            "previous_provenance_sha256": existing[
                "provenance_receipt_sha256"
            ],
        }

    history = paths.harness / _CODEX_PROVENANCE_HISTORY_DIRECTORY
    if history.exists() or history.is_symlink():
        if canonicalize_no_link_traversal(
            history, "Codex install provenance history"
        ) != history:
            raise HarnessError("Codex install provenance history is not canonical")
        metadata = history.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or history.is_symlink():
            raise HarnessError(
                "Codex install provenance history must be a non-linked directory"
            )
        entries = sorted(history.iterdir(), key=lambda item: item.name)
        if any(
            not re.fullmatch(r"[0-9a-f]{64}\.json", item.name)
            for item in entries
        ):
            raise HarnessError(
                "Codex install provenance history has an unexpected entry"
            )
        old_archive = history / (
            f"{existing['provenance_receipt_sha256']}.json"
        )
        if old_archive.exists():
            if old_archive.read_bytes() != existing_bytes:
                raise HarnessError(
                    "Codex install provenance history conflicts with current receipt"
                )
        elif len(entries) >= _CODEX_PROVENANCE_HISTORY_MAX:
            raise HarnessError(
                "Codex install provenance history reached its bounded entry cap"
            )
    return {
        "receipt_path": str(receipt_path),
        "changed": True,
        "previous_provenance_sha256": existing["provenance_receipt_sha256"],
    }


def _install_codex_provenance_receipt(
    paths: HarnessPaths, candidate: dict[str, Any]
) -> dict[str, Any]:
    """Publish the current receipt, archiving a replaced trusted receipt."""

    preflight = _codex_provenance_preflight(paths, candidate)
    candidate_bytes = _codex_provenance_bytes(candidate)
    receipt_path = Path(preflight["receipt_path"])
    if not preflight["changed"]:
        return {
            **preflight,
            "provenance_receipt_sha256": candidate[
                "provenance_receipt_sha256"
            ],
            "history_path": None,
        }
    history_path: Path | None = None
    if preflight["previous_provenance_sha256"] is not None:
        existing = (
            codex_install_provenance_impl.load_codex_install_provenance_receipt(
                paths.root
            )
        )
        existing_bytes = _codex_provenance_bytes(existing)
        history = paths.harness / _CODEX_PROVENANCE_HISTORY_DIRECTORY
        if not history.exists():
            history.mkdir(mode=0o700)
            if os.name != "nt":
                history.chmod(0o700)
        if canonicalize_no_link_traversal(
            history, "Codex install provenance history"
        ) != history or not stat.S_ISDIR(history.lstat().st_mode):
            raise HarnessError(
                "Codex install provenance history is not a safe directory"
            )
        history_path = history / f"{existing['provenance_receipt_sha256']}.json"
        if history_path.exists():
            if history_path.read_bytes() != existing_bytes:
                raise HarnessError(
                    "Codex install provenance history archive is divergent"
                )
        else:
            atomic_create_bytes(history_path, existing_bytes)
        atomic_write_bytes(receipt_path, candidate_bytes)
    else:
        atomic_create_bytes(receipt_path, candidate_bytes)
    persisted = codex_install_provenance_impl.load_codex_install_provenance_receipt(
        paths.root
    )
    if persisted != candidate:
        raise HarnessError("persisted Codex install provenance receipt is divergent")
    return {
        **preflight,
        "provenance_receipt_sha256": candidate["provenance_receipt_sha256"],
        "history_path": str(history_path) if history_path is not None else None,
    }

def cmd_codex_init(args: argparse.Namespace, paths: HarnessPaths) -> int:
    """Initialize AOI, wire project hooks, and install the user AOI skill."""

    if not (paths.root / ".git").exists():
        raise HarnessError("aoi codex-init requires a Git repository root")
    promotion_bundle_file = cast(
        str | None, getattr(args, "promotion_bundle_file", None)
    )
    expected_promotion_bundle_sha256 = cast(
        str | None, getattr(args, "expected_promotion_bundle_sha256", None)
    )
    local_artifact_bundle_file = cast(
        str | None, getattr(args, "local_artifact_bundle_file", None)
    )
    expected_local_artifact_bundle_sha256 = cast(
        str | None,
        getattr(args, "expected_local_artifact_bundle_sha256", None),
    )
    public_complete = (
        promotion_bundle_file is not None
        and expected_promotion_bundle_sha256 is not None
    )
    local_complete = (
        local_artifact_bundle_file is not None
        and expected_local_artifact_bundle_sha256 is not None
    )
    if (promotion_bundle_file is None) != (expected_promotion_bundle_sha256 is None):
        raise HarnessError(
            "Codex install provenance preflight failed before mutation: "
            "--promotion-bundle-file and --expected-promotion-bundle-sha256 "
            "must be supplied together"
        )
    if (local_artifact_bundle_file is None) != (
        expected_local_artifact_bundle_sha256 is None
    ):
        raise HarnessError(
            "Codex install provenance preflight failed before mutation: "
            "--local-artifact-bundle-file and "
            "--expected-local-artifact-bundle-sha256 must be supplied together"
        )
    if public_complete == local_complete:
        raise HarnessError(
            "Codex install provenance preflight failed before mutation: supply "
            "exactly one complete proof pair: promoted release or reviewed local install"
        )
    if public_complete:
        confidentiality_impl.require_publication_action_allowed(
            paths.project.confidentiality,
            "release_publish",
        )
    try:
        if public_complete:
            if (
                promotion_bundle_file is None
                or expected_promotion_bundle_sha256 is None
            ):
                raise AssertionError("complete public proof pair was not present")
            provenance_receipt = (
                codex_install_provenance_impl.validate_codex_install_provenance(
                    promotion_bundle_file,
                    expected_promotion_bundle_sha256,
                    Path(sys.argv[0]).resolve(),
                )
            )
        else:
            if (
                local_artifact_bundle_file is None
                or expected_local_artifact_bundle_sha256 is None
            ):
                raise AssertionError("complete local proof pair was not present")
            provenance_receipt = (
                codex_install_provenance_impl.validate_codex_local_install_provenance(
                    local_artifact_bundle_file,
                    expected_local_artifact_bundle_sha256,
                    Path(sys.argv[0]).resolve(),
                )
            )
        hook_command = codex_onboarding_impl.build_codex_hook_command(
            provenance_receipt["codex_hook_entry_point"]["path"],
            paths.root,
            provenance_receipt["provenance_receipt_sha256"],
        )
        provenance_preflight = _codex_provenance_preflight(
            paths, provenance_receipt
        )
    except (
        HarnessError,
        OSError,
        codex_install_provenance_impl.CodexInstallProvenanceError,
        codex_onboarding_impl.CodexOnboardingError,
    ) as exc:
        raise HarnessError(
            f"Codex install provenance preflight failed before mutation: {exc}"
        ) from exc
    if paths.config.is_file() and not paths.project.codex_hooks_enabled:
        active_tasks = [
            str(state.get("task_id", ""))
            for state in load_all_tasks(paths)
            if state.get("status") in {"active", "blocked"}
        ]
        if active_tasks:
            raise HarnessError(
                "cannot enable hooks.codex while active AOI tasks bind the current "
                f"configuration digest: {sorted(active_tasks)}"
            )
    user_skills_root = (
        Path(args.user_skills_root).expanduser()
        if args.user_skills_root
        else Path.home() / ".agents" / "skills"
    )
    try:
        codex_skill_text = _resource_text("codex/SKILL.md")
        skill_preflight = codex_onboarding_impl.preflight_codex_user_skill(
            user_skills_root,
            codex_skill_text,
            replace_sha256=args.replace_user_skill_sha256,
        )
        preflight = codex_onboarding_impl.preflight_codex_onboarding(
            paths.root,
            command=hook_command,
            command_windows=hook_command,
        )
        if paths.config.is_file():
            _candidate, policy_change = (
                codex_onboarding_impl.enable_aoi_codex_hooks_policy(
                    paths.config.read_text(encoding="utf-8")
                )
            )
            policy_preflight = {
                "config_path": str(paths.config),
                "changed": policy_change,
            }
        else:
            policy_preflight = {
                "config_path": str(paths.config),
                "changed": True,
                "source": "default_config",
            }
        preflight["aoi_hook_policy"] = policy_preflight
        preflight["user_skill"] = skill_preflight
        preflight["install_provenance"] = provenance_preflight
    except (OSError, codex_onboarding_impl.CodexOnboardingError) as exc:
        raise HarnessError(str(exc)) from exc
    init_ns = argparse.Namespace(
        project_name=args.project_name,
        config=None,
        expected_config_sha256=None,
        replace_policy_sha256=None,
        json=True,
    )
    captured = io.StringIO()
    saved_stdout = sys.stdout
    sys.stdout = captured
    try:
        cmd_init(init_ns, paths)
    finally:
        sys.stdout = saved_stdout
    try:
        init_result = json.loads(captured.getvalue() or "{}")
    except json.JSONDecodeError:
        init_result = {}

    paths = get_paths(paths.root)
    created_config = bool(init_result.get("created_config", False))
    try:
        # The initialized-project dispatcher already holds this lock. Fresh init
        # did not, so take it here and retain it across the policy flip and all
        # client writes; a competing Chief/task cannot enter between stages.
        with state_lock(paths):
            provenance_result = _install_codex_provenance_receipt(
                paths, provenance_receipt
            )
            paths, policy_changed = _enable_codex_hook_policy(
                paths,
                fresh_unauthenticated_init=created_config,
            )
            config_result = codex_onboarding_impl.install_codex_config(
                paths.root / ".codex" / "config.toml"
            )
            hooks_result = codex_onboarding_impl.install_codex_hooks(
                paths.root / ".codex" / "hooks.json",
                command=hook_command,
                command_windows=hook_command,
            )
            skill_result = codex_onboarding_impl.install_codex_user_skill(
                user_skills_root,
                codex_skill_text,
                replace_sha256=args.replace_user_skill_sha256,
            )
    except (
        HarnessError,
        OSError,
        codex_onboarding_impl.CodexOnboardingError,
    ) as exc:
        raise HarnessError(
            f"{exc}; "
            + _onboarding_resume_instruction(
                "codex-init",
                created_config=created_config,
            )
        ) from exc

    payload = {
        "codex_init": True,
        "project": paths.project.name,
        "root": str(paths.root),
        "aoi_initialized": init_result.get("initialized", True),
        "created_config": init_result.get("created_config", False),
        "aoi_hook_policy_enabled": True,
        "aoi_hook_policy_changed": policy_changed,
        "config_sha256": paths.project.sha256,
        "install_provenance": provenance_result,
        "codex_config": config_result,
        "preflight": preflight,
        "resumable": True,
        "hooks": hooks_result,
        "skill": skill_result,
        "next_steps": [
            "Keep the promoted AOI installation and exact recorded hook launcher available.",
            "The generic AOI skill is installed once at user scope; keep "
            "project-specific instructions in the repository AGENTS.md.",
            "Start a new Codex session in this trusted repo, open /hooks, and "
            "review/trust the exact absolute AOI hook definition and provenance digest.",
            "Run aoi doctor --json after hook trust; structural PASS does not prove "
            "that Codex executed or trusted a hook.",
        ],
    }
    emit(payload, args.json)
    return 0

def _extend_unique(state: dict[str, Any], key: str, values: Iterable[str]) -> None:
    destination = state.setdefault(key, [])
    for value in values:
        cleaned = value.strip()
        if cleaned and cleaned not in destination:
            destination.append(cleaned)


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
        schema_version = _packet_schema_version(packet)
        dispatch_provenance = str(
            packet.get("dispatch_provenance")
            or ("legacy_unverified" if (schema_version or 0) < 5 else "none")
        )
        observed_starts = [
            attempt.get("observation")
            for attempt in packet.get("dispatch_attempts", [])
            if isinstance(attempt, dict)
            and attempt.get("status") == "consumed"
            and isinstance(attempt.get("observation"), dict)
        ]
        subagent_start_observed_at = (
            str(cast("dict[str, Any]", observed_starts[0]).get("observed_at", ""))
            if dispatch_provenance in HOOK_OBSERVED_DISPATCH_PROVENANCES
            and len(observed_starts) == 1
            else ""
        )
        legacy_started_at = (
            str(packet.get("dispatched_at", ""))
            if (schema_version or 0) < 5
            else ""
        )
        records.append(
            {
                "packet_id": packet.get("packet_id"),
                "status": packet.get("status"),
                "requested_role": packet.get("agent_role"),
                "requested_model_tier": packet.get("model_tier"),
                # The stored flag is never trusted here: eligibility for the
                # dataset is re-derived from the hook observation and the
                # applied binding at export time, so a forged boolean in
                # state.json cannot reach a capacity dataset.
                "actual_role": packet.get("actual_role")
                if _derived_routing_verified(state, packet)
                else "unavailable",
                "actual_model_tier": packet.get("actual_model_tier")
                if _derived_routing_verified(state, packet)
                else "unavailable",
                "routing_verified": _derived_routing_verified(state, packet),
                "hook_observed_model": _hook_observed_routing_model(packet),
                "routing_claim_provenance": str(
                    (packet.get("routing_claim") or {}).get("provenance", "")
                ),
                "retry_of_packet_id": packet.get("retry_of_packet_id", ""),
                "result_sha256": packet.get("result_sha256", ""),
                "dispatch_provenance": dispatch_provenance,
                "dispatch_recorded_at": str(
                    packet.get("dispatch_recorded_at", "") or legacy_started_at
                ),
                "subagent_start_observed_at": subagent_start_observed_at,
                "orchestration_started_at": legacy_started_at,
                "orchestration_completed_at": packet.get("completed_at", ""),
                "token_usage": "unavailable",
                "cost": "unavailable",
                "engineering_acceptance": "not_inferred_from_packet_status",
                "typed_outcome": str(packet.get("typed_outcome") or "unclassified"),
                "typed_outcome_provenance": str(
                    packet.get("typed_outcome_provenance") or "unclassified"
                ),
                # Model-quality denominators may only contain explicit
                # accepted/rejected outcomes; transport status, cancellations,
                # procedural and transport failures are excluded by design.
                "model_quality_eligible": str(
                    packet.get("typed_outcome") or "unclassified"
                )
                in MODEL_QUALITY_ELIGIBLE_OUTCOMES,
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


def _selection_terminal_packet_bindings(
    state: dict[str, Any], selection_id: str
) -> list[dict[str, Any]]:
    return sorted(
        [
            {
                "packet_id": str(packet.get("packet_id", "")),
                "lane_id": str(packet.get("lane_id", "")),
                "status": str(packet.get("status", "")),
                "result_sha256": str(packet.get("result_sha256", "")),
                "dispatch_provenance": str(
                    packet.get("dispatch_provenance") or "legacy_unverified"
                ),
            }
            for packet in state.get("packets", [])
            if packet.get("execution_selection_id") == selection_id
            and not _is_steward_synthesis_packet(packet)
            and packet.get("status") in TERMINAL_PACKET_STATUSES
        ],
        key=lambda item: item["packet_id"],
    )


def _build_steward_packet_binding(
    state: dict[str, Any], selection_id: str, packet_id: str, *, strict_agent_id: bool
) -> dict[str, Any]:
    packet = _packet_by_id(state, packet_id)
    if (
        not _is_steward_synthesis_packet(packet)
        or packet.get("execution_selection_id") != selection_id
        or packet.get("status") != "done"
        or not re.fullmatch(r"[0-9a-f]{64}", str(packet.get("result_sha256", "")))
        or packet.get("steward_input_bindings")
        != _selection_terminal_packet_bindings(state, selection_id)
    ):
        raise HarnessError(
            "execution brief requires a done Steward synthesis packet bound to current specialist results"
        )
    if strict_agent_id:
        try:
            steward_agent_id = validate_agent_id(
                packet.get("agent_id"), "Steward packet agent id"
            )
        except AgentIdentityError as exc:
            raise HarnessError(
                "legacy Steward packet has a non-canonical agent identity; "
                "create a new Steward packet before recording a new execution brief"
            ) from exc
    else:
        # Reconstruct the original v3 binding byte-for-byte for already sealed
        # briefs.  Old writers stringified this field, including legacy display
        # names; read compatibility must not elevate that value into new authority.
        steward_agent_id = str(packet.get("agent_id", ""))
    return {
        "packet_id": packet_id,
        "lane_id": str(packet.get("lane_id", "")),
        "agent_id": steward_agent_id,
        "result_sha256": str(packet.get("result_sha256", "")),
        "dispatch_provenance": str(
            packet.get("dispatch_provenance") or "legacy_unverified"
        ),
        "steward_selection_snapshot": copy.deepcopy(
            packet.get("steward_selection_snapshot", {})
        ),
        "steward_execution_snapshot": copy.deepcopy(
            packet.get("steward_execution_snapshot", {})
        ),
        "steward_input_bindings": copy.deepcopy(
            packet.get("steward_input_bindings", [])
        ),
    }


def _steward_packet_binding(
    state: dict[str, Any], selection_id: str, packet_id: str
) -> dict[str, Any]:
    """Reconstruct an existing v3 binding with original reader semantics."""

    return _build_steward_packet_binding(
        state, selection_id, packet_id, strict_agent_id=False
    )


def _new_steward_packet_binding(
    state: dict[str, Any], selection_id: str, packet_id: str
) -> dict[str, Any]:
    """Build a new v3 binding only from a canonical current identity."""

    return _build_steward_packet_binding(
        state, selection_id, packet_id, strict_agent_id=True
    )


def _execution_brief_coverage_error(
    paths: HarnessPaths,
    state: dict[str, Any],
    selection: dict[str, Any],
) -> str | None:
    # A v2 Steward brief cannot be retroactively asserted for a legacy selection.
    # Preserve those results as legacy evidence and allow an exact supersession or
    # task close instead of creating a migration deadlock.
    try:
        policy_v2 = _execution_policy_v2_enabled(state)
    except HarnessError as exc:
        return str(exc)
    if policy_v2 and not _is_exact_int(
        selection.get("execution_selection_version"), 2
    ):
        return (
            f"execution selection {selection.get('selection_id', '')} is not sealed as "
            "version 2 under task execution policy v2"
        )
    if selection.get("execution_selection_version") is None and "steward_snapshot" in selection:
        return (
            f"execution selection {selection.get('selection_id', '')} has v2-only "
            "fields without a selection version"
        )
    if not _is_exact_int(selection.get("execution_selection_version"), 2):
        return None
    selection_id = str(selection.get("selection_id", ""))
    bindings = _selection_terminal_packet_bindings(state, selection_id)
    if not bindings:
        return None
    briefs = [
        item
        for item in state.get("execution_briefs", [])
        if item.get("execution_selection_id") == selection_id
    ]
    if not briefs:
        return f"execution selection {selection_id} lacks a Steward result brief"
    brief = briefs[-1]
    if brief.get("packet_bindings") != bindings:
        return f"execution selection {selection_id} Steward result brief is stale"
    if brief.get("steward_snapshot") != selection.get("steward_snapshot"):
        return f"execution selection {selection_id} Steward result brief lost authority binding"
    if policy_v2:
        if not _is_exact_int(brief.get("brief_version"), 3):
            return (
                f"execution selection {selection_id} brief lacks a terminal "
                "Steward synthesis packet"
            )
        stored_binding = brief.get("steward_packet_binding")
        if not isinstance(stored_binding, dict):
            return f"execution selection {selection_id} Steward packet binding is malformed"
        try:
            current_binding = _steward_packet_binding(
                state, selection_id, str(stored_binding.get("packet_id", ""))
            )
        except HarnessError as exc:
            return f"execution selection {selection_id} Steward packet binding is invalid: {exc}"
        if stored_binding != current_binding:
            return f"execution selection {selection_id} Steward packet binding is stale"
        steward_packet = _packet_by_id(
            state,
            str(stored_binding.get("packet_id", "")),
        )
        authority_errors = packet_authority_integrity_errors(
            paths,
            state,
            steward_packet,
            require_origin=False,
        )
        result_errors = packet_result_integrity_errors(
            paths,
            state,
            steward_packet,
        )
        specialist_errors = selection_done_packet_authority_errors(
            paths,
            state,
            selection_id,
        )
        if authority_errors or result_errors or specialist_errors:
            return (
                f"execution selection {selection_id} Steward evidence authority is invalid: "
                + "; ".join(authority_errors + result_errors + specialist_errors)
            )
    stored_sha = str(brief.get("brief_sha256", ""))
    preimage = copy.deepcopy(brief)
    preimage.pop("brief_sha256", None)
    if stored_sha != canonical_record_sha256(preimage):
        return f"execution selection {selection_id} Steward result brief lost integrity"
    context_bindings = brief.get("context_provider_bindings", [])
    try:
        validate_codebase_memory_steward_binding_set(state, context_bindings)
    except HarnessError as exc:
        return (
            f"execution selection {selection_id} Steward context-provider "
            f"binding is stale or invalid: {exc}"
        )
    if selection.get("mode") == "hybrid":
        referenced = set(brief.get("cross_lane_session_ids", []))
        valid_closed = {
            str(item.get("cross_lane_session_id", ""))
            for item in state.get("cross_lane_sessions", [])
            if item.get("execution_selection_id") == selection_id
            and item.get("status") == "closed"
        }
        if not referenced or not referenced <= valid_closed:
            return f"hybrid selection {selection_id} brief lacks closed cross-lane evidence"
    return None


def _resource_cmd_services() -> ResourceCmdServices:
    return ResourceCmdServices(
        state_lock=lambda *a, **kw: state_lock(*a, **kw),
        write_task=lambda *a, **kw: write_task(*a, **kw),
        write_index=lambda *a, **kw: write_index(*a, **kw),
        role_tier_map=lambda: ROLE_TIER_MAP,
        require_plan_ready=require_plan_ready,
        require_root_session=require_root_session,
        approved_override_settings=approved_override_settings,
        validate_selection_resource_envelope=_validate_selection_resource_envelope,
        resource_config_integrity_errors=resource_config_integrity_errors,
    )


def _context_memory_cmd_services() -> ContextMemoryCmdServices:
    return ContextMemoryCmdServices(
        require_plan_ready=require_plan_ready,
        require_root_session=require_root_session,
    )


def _capacity_cmd_services() -> CapacityCmdServices:
    return CapacityCmdServices(
        require_plan_ready=require_plan_ready,
        require_root_session=require_root_session,
        packet_authority_integrity_errors=packet_authority_integrity_errors,
        capacity_records=_capacity_records,
        records_fingerprint=_records_fingerprint,
        capability_catalog_version=CAPABILITY_CATALOG_VERSION,
        capability_tier_map=CAPABILITY_TIER_MAP,
        depth_two_roles=DEPTH_TWO_ROLES,
    )


def _improvement_cmd_services() -> ImprovementCmdServices:
    return ImprovementCmdServices(
        require_plan_ready=require_plan_ready,
        require_root_session=require_root_session,
        read_regular_artifact=read_regular_artifact,
        records_fingerprint=_records_fingerprint,
        require_done_reviewer_packet=_require_done_reviewer_packet,
        skill_release_semantic_integrity_errors=_skill_release_semantic_integrity_errors,
    )


def _lanes_cmd_services() -> LanesCmdServices:
    return LanesCmdServices(
        require_plan_ready=require_plan_ready,
        require_root_session=require_root_session,
        portfolio_integrity_errors=portfolio_integrity_errors,
        lane_kinds=lambda: LANE_KINDS,
        role_tier_map=lambda: ROLE_TIER_MAP,
        max_engaged_lanes=MAX_ENGAGED_LANES,
        terminal_coordination_statuses=TERMINAL_COORDINATION_STATUSES,
        terminal_improvement_statuses=TERMINAL_IMPROVEMENT_STATUSES,
        change_classes=CHANGE_CLASSES,
        dependency_kinds=DEPENDENCY_KINDS,
    )


def _coordination_cmd_services() -> CoordinationCmdServices:
    return CoordinationCmdServices(
        require_plan_ready=require_plan_ready,
        require_root_session=require_root_session,
        portfolio_integrity_errors=portfolio_integrity_errors,
        snapshot_evidence_artifact=snapshot_evidence_artifact,
        change_classes=CHANGE_CLASSES,
        dependency_kinds=DEPENDENCY_KINDS,
        terminal_coordination_statuses=TERMINAL_COORDINATION_STATUSES,
        cooperative_authority_boundary=COOPERATIVE_AUTHORITY_BOUNDARY,
    )


def _execution_selection_cmd_services() -> ExecutionSelectionCmdServices:
    return ExecutionSelectionCmdServices(
        require_plan_ready=require_plan_ready,
        require_root_session=require_root_session,
        role_tier_map=lambda: ROLE_TIER_MAP,
        terminal_coordination_statuses=TERMINAL_COORDINATION_STATUSES,
        approved_override_settings=approved_override_settings,
        require_override_target_contract=require_override_target_contract,
        override_by_id=override_by_id,
        build_execution_resource_envelope=_build_execution_resource_envelope,
        lane_authority_snapshot=_lane_authority_snapshot,
        execution_brief_coverage_error=_execution_brief_coverage_error,
        steward_packet_binding=_new_steward_packet_binding,
        selection_terminal_packet_bindings=_selection_terminal_packet_bindings,
        packet_authority_integrity_errors=packet_authority_integrity_errors,
        packet_result_integrity_errors=packet_result_integrity_errors,
        selection_done_packet_authority_errors=selection_done_packet_authority_errors,
    )


def _task_lifecycle_cmd_services() -> TaskLifecycleCmdServices:
    return TaskLifecycleCmdServices(
        state_lock=lambda *a, **kw: state_lock(*a, **kw),
        reload_locked_paths=_reload_locked_paths,
        require_plan_ready=require_plan_ready,
        check_session_id=check_session_id,
        validate_mini_locks=validate_mini_locks,
        plan_path=plan_path,
        commit_checkpoint=commit_checkpoint,
        substitute=substitute,
        template_text=template_text,
        bind_session_unlocked=bind_session_unlocked,
        root_session_mapping_kind=ROOT_SESSION_MAPPING_KIND,
        subagent_parent_mapping_kind=SUBAGENT_PARENT_MAPPING_KIND,
        known_managed_policy_sha256=KNOWN_MANAGED_POLICY_SHA256,
        plan_fallback=PLAN_FALLBACK,
    )


def _status_cmd_services() -> StatusCmdServices:
    return StatusCmdServices(
        check_session_id=check_session_id,
        plan_digest=plan_digest,
        terminal_coordination_statuses=TERMINAL_COORDINATION_STATUSES,
        terminal_improvement_statuses=TERMINAL_IMPROVEMENT_STATUSES,
        max_engaged_lanes=MAX_ENGAGED_LANES,
        critical_view_max_bytes=CRITICAL_VIEW_MAX_BYTES,
        critical_text_limit=CRITICAL_TEXT_LIMIT,
    )


def _mini_completion_services(
    task_services: TaskLifecycleCmdServices,
) -> MiniCompletionServices:
    return MiniCompletionServices(
        close_gate=close_gate,
        prepare_delivery=prepare_delivery,
        set_delivery=cmd_set_delivery,
        release_claim=cmd_release_claim,
        checkpoint=functools.partial(cmd_checkpoint, services=task_services),
        close_task=cmd_close_task,
        delivery_integrity_errors=delivery_integrity_errors,
        validate_mini_locks=validate_mini_locks,
    )


def _authorize_temporary_recovery_chief(
    args: argparse.Namespace, paths: HarnessPaths
) -> None:
    """Verify current Chief authority from within the recovery-held state lock."""

    session_id, epoch, token, _credential_path = _chief_credential(args, paths)
    require_chief_authority(
        paths,
        session_id=session_id,
        epoch=epoch,
        token=token,
    )


def _temporary_recovery_services() -> TemporaryRecoveryServices:
    return TemporaryRecoveryServices(
        authorize_chief=_authorize_temporary_recovery_chief,
        reload_locked_paths=_reload_locked_paths,
    )


def cmd_init(args: argparse.Namespace, paths: HarnessPaths) -> int:
    """Re-export the relocated body with composition-root services bound."""

    return _cmd_init(args, paths, services=_task_lifecycle_cmd_services())


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
            "runtime_test",
            "external_runtime",
            "system_evidence",
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
        if args.category in {"external_runtime", "runtime_test", "system_evidence"}:
            if not args.run_id:
                raise HarnessError(f"{args.category} verification requires --run-id")
        prepared_artifact_refs = prepare_bound_artifacts(
            args.artifact_ref, "verification artifact ref"
        )
        review_packet = None
        reviewer_agent_id: str | None = None
        if args.category == "independent_review":
            if not args.review_packet_id:
                raise HarnessError(
                    "independent_review verification requires --review-packet-id"
                )
            review_packet = _require_done_reviewer_packet(
                paths,
                state,
                args.review_packet_id,
                required_artifact_shas={
                    item["sha256"] for item in prepared_artifact_refs
                },
            )
            try:
                reviewer_agent_id = validate_agent_id(
                    review_packet.get("agent_id"), "reviewer packet agent id"
                )
            except AgentIdentityError as exc:
                raise HarnessError(
                    "legacy reviewer packet has a non-canonical agent identity; "
                    "create a new reviewer packet before recording a new verification"
                ) from exc
        elif args.review_packet_id:
            raise HarnessError(
                "--review-packet-id is accepted only for independent_review verification"
            )
        category = require_text(args.category, "category")
        evidence = require_evidence_detail(args.evidence, "evidence")
        asserts_completion_boundary = bool(
            getattr(args, "asserts_completion_boundary", False)
        )
        if asserts_completion_boundary and args.status != "pass":
            raise HarnessError(
                "--asserts-completion-boundary is valid only on a passing verification"
            )
        artifact_refs = preserve_bound_artifacts(
            paths, args.task, prepared_artifact_refs
        )
        item = {
            "integrity_version": 1,
            "artifact_snapshot_version": 1,
            "category": category,
            "status": args.status,
            "evidence": evidence,
            "command": command,
            "boundary": boundary,
            "run_id": args.run_id or "",
            "lane_id": args.lane_id or "",
            "artifact_refs": artifact_refs,
            "recorded_at": now_iso(),
        }
        if asserts_completion_boundary:
            item["asserts_completion_boundary"] = True
            # Bind the assertion to the exact boundary text it covered so a
            # later retarget cannot be closed against a stale assertion.
            item["completion_boundary_sha256"] = hashlib.sha256(
                str(state.get("completion_boundary", "")).encode("utf-8")
            ).hexdigest()
        if review_packet is not None:
            assert reviewer_agent_id is not None
            item["review_packet_id"] = review_packet["packet_id"]
            item["review_result_sha256"] = review_packet["result_sha256"]
            item["reviewer_agent_id"] = reviewer_agent_id
        state.setdefault("verification", []).append(item)
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(item, args.json)
    return 0


def cmd_materialize_artifacts(args: argparse.Namespace, paths: HarnessPaths) -> int:
    """Migrate still-valid legacy live refs into canonical task-local blobs."""

    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "materialize artifacts for")
        selected_verifications = set(args.verification_index or [])
        verification_count = len(state.get("verification", []))
        if any(index < 1 or index > verification_count for index in selected_verifications):
            raise HarnessError("verification index is outside the task verification list")
        pending: list[tuple[dict[str, Any], str]] = []
        plans: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
        skipped_failed_packets: list[str] = []
        for packet in [] if selected_verifications else state.get("packets", []):
            packet_refs = packet.get("input_artifact_refs", [])
            unsupported_refs = [
                artifact
                for artifact in packet_refs
                if not (
                    _is_legacy_snapshot_version(artifact.get("snapshot_version"))
                    or _is_canonical_snapshot_version(artifact.get("snapshot_version"))
                )
            ]
            if unsupported_refs:
                raise HarnessError(
                    f"packet {packet.get('packet_id')} contains an unsupported "
                    "artifact snapshot version"
                )
            legacy_refs = [
                artifact
                for artifact in packet_refs
                if _is_legacy_snapshot_version(artifact.get("snapshot_version"))
            ]
            if not legacy_refs:
                continue
            schema_version = _packet_schema_version(packet)
            if schema_version is None:
                raise HarnessError(
                    f"packet {packet.get('packet_id')} schema version is invalid"
                )
            if schema_version >= 4:
                raise HarnessError(
                    f"schema-v4 packet {packet.get('packet_id')} contains legacy live refs"
                )
            if packet.get("status") in {"failed", "cancelled"}:
                skipped_failed_packets.append(str(packet.get("packet_id")))
                continue
            if packet.get("status") != "done":
                raise HarnessError(
                    f"packet {packet.get('packet_id')} is {packet.get('status')}; "
                    "active legacy packet authority cannot be materialized"
                )
            for artifact in legacy_refs:
                pending.append(
                    (artifact, f"packet {packet.get('packet_id')} legacy input")
                )
        for index, verification in enumerate(state.get("verification", []), start=1):
            if selected_verifications and index not in selected_verifications:
                continue
            if verification.get("superseded_at"):
                continue
            for artifact in verification.get("artifact_refs", []):
                if _is_canonical_snapshot_version(artifact.get("snapshot_version")):
                    continue
                if not _is_legacy_snapshot_version(artifact.get("snapshot_version")):
                    raise HarnessError(
                        f"verification #{index} contains an unsupported "
                        "artifact snapshot version"
                    )
                pending.append(
                    (artifact, f"verification #{index} legacy artifact")
                )

        if len(pending) > BOUND_ARTIFACT_MAX_COUNT:
            raise HarnessError(
                "materialize-artifacts would retain "
                f"{len(pending)} refs; limit is {BOUND_ARTIFACT_MAX_COUNT}"
            )
        aggregate_bytes = 0
        for artifact, label in pending:
            legacy_path = Path(str(artifact.get("path", "")))
            if not legacy_path.is_absolute():
                raise HarnessError(f"{label} path must be absolute")
            integrity_error = artifact_ref_integrity_error(
                paths, state, artifact, require_origin=False
            )
            if integrity_error:
                raise HarnessError(f"{label} is not physically valid: {integrity_error}")
            prepared = prepare_bound_artifacts(
                [f"{artifact.get('path', '')}={artifact.get('sha256', '')}"],
                label,
            )
            if prepared[0]["size_bytes"] != artifact.get("size_bytes"):
                raise HarnessError(f"{label} recorded size changed during materialization")
            aggregate_bytes += int(prepared[0]["size_bytes"])
            if aggregate_bytes > BOUND_ARTIFACT_TOTAL_MAX_BYTES:
                raise HarnessError(
                    "materialize-artifacts aggregate size exceeds "
                    f"{BOUND_ARTIFACT_TOTAL_MAX_BYTES} bytes"
                )
            plans.append((artifact, prepared))

        for target, prepared in plans:
            target.clear()
            target.update(preserve_bound_artifacts(paths, args.task, prepared)[0])

        if plans:
            for packet in state.get("packets", []):
                refs = packet.get("input_artifact_refs", [])
                if refs and all(
                    _is_canonical_snapshot_version(ref.get("snapshot_version"))
                    for ref in refs
                ):
                    packet["input_snapshot_version"] = 1
            for verification in state.get("verification", []):
                refs = verification.get("artifact_refs", [])
                if refs and all(
                    _is_canonical_snapshot_version(ref.get("snapshot_version"))
                    for ref in refs
                ):
                    verification["artifact_snapshot_version"] = 1
            bump_task(state)
            write_task(paths, state)
            write_index(paths)
    emit(
        {
            "task_id": args.task,
            "materialized_refs": len(plans),
            "skipped_legacy_failed_packets": skipped_failed_packets,
        },
        args.json,
    )
    return 0


def cmd_packet_input_recover_from_tar(
    args: argparse.Namespace, paths: HarnessPaths
) -> int:
    """Recover one drifted legacy done-packet input from a bound tar member."""

    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "recover packet input for")
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
        if packet.get("status") != "done":
            raise HarnessError("archive-member recovery is limited to legacy done packets")
        schema_version = _packet_schema_version(packet)
        if schema_version is None:
            raise HarnessError("packet schema version is invalid")
        if schema_version >= 4:
            raise HarnessError("schema-v4 packet inputs already use immutable snapshots")

        expected_result_sha = str(args.expected_result_sha256).lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_result_sha):
            raise HarnessError("expected packet result SHA-256 must be full 64 hex")
        expected_result_path = (
            task_dir(paths, args.task) / "results" / f"{args.packet_id}.md"
        )
        if (
            packet.get("integrity_version") != 1
            or packet.get("result_sha256") != expected_result_sha
            or Path(str(packet.get("result_path", ""))) != expected_result_path
            or not expected_result_path.is_file()
            or expected_result_path.is_symlink()
            or sha256_file(expected_result_path) != expected_result_sha
        ):
            raise HarnessError("done packet result does not match the approved exact SHA-256")

        refs = packet.get("input_artifact_refs", [])
        input_index = int(args.input_index) - 1
        carrier_index = int(args.carrier_input_index) - 1
        if (
            input_index < 0
            or input_index >= len(refs)
            or carrier_index < 0
            or carrier_index >= len(refs)
            or input_index == carrier_index
        ):
            raise HarnessError("input and carrier indices must name distinct packet inputs")
        target = refs[input_index]
        carrier = refs[carrier_index]
        if not _is_legacy_snapshot_version(target.get("snapshot_version")):
            raise HarnessError("packet input is already materialized")
        source_path = Path(str(target.get("path", "")))
        if not source_path.is_absolute():
            raise HarnessError("legacy packet input source path must be absolute")
        target_sha = str(target.get("sha256", "")).lower()
        expected_target_sha = str(args.expected_input_sha256).lower()
        target_size = target.get("size_bytes")
        if (
            not re.fullmatch(r"[0-9a-f]{64}", target_sha)
            or expected_target_sha != target_sha
            or not isinstance(target_size, int)
            or isinstance(target_size, bool)
            or target_size <= 0
        ):
            raise HarnessError("legacy packet input identity does not match the approved SHA-256")
        if artifact_ref_integrity_error(
            paths, state, target, require_origin=False
        ) is None:
            raise HarnessError(
                "legacy packet input is still exact; use materialize-artifacts instead"
            )

        carrier_sha = str(carrier.get("sha256", "")).lower()
        expected_carrier_sha = str(args.carrier_sha256).lower()
        if (
            not re.fullmatch(r"[0-9a-f]{64}", carrier_sha)
            or expected_carrier_sha != carrier_sha
        ):
            raise HarnessError("carrier packet input does not match the approved SHA-256")
        carrier_error = artifact_ref_integrity_error(
            paths, state, carrier, require_origin=False
        )
        if carrier_error:
            raise HarnessError(f"carrier packet input is not physically valid: {carrier_error}")
        carrier_path = Path(str(carrier.get("path", "")))
        _, carrier_data = read_regular_artifact(
            carrier_path,
            "packet-bound recovery archive",
            max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
        )
        if (
            hashlib.sha256(carrier_data).hexdigest() != carrier_sha
            or len(carrier_data) != carrier.get("size_bytes")
        ):
            raise HarnessError("carrier packet input changed while being read")
        canonical_member = canonical_recovery_archive_member(args.archive_member)
        recovered_data = read_recovery_tar_member(carrier_data, canonical_member)
        if (
            hashlib.sha256(recovered_data).hexdigest() != target_sha
            or len(recovered_data) != target_size
        ):
            raise HarnessError("recovery archive member does not match the legacy input identity")

        recovery_reason = require_evidence_detail(
            args.reason, "packet input recovery reason"
        )
        recovered_at = now_iso()
        preserved = preserve_bound_artifacts(
            paths,
            args.task,
            [
                {
                    "source_path": str(source_path),
                    "sha256": target_sha,
                    "size_bytes": target_size,
                    "data": recovered_data,
                }
            ],
        )[0]
        recovery = {
            "version": 1,
            "method": "packet-bound-tar-member",
            "carrier_input_index": carrier_index + 1,
            "carrier_sha256": carrier_sha,
            "archive_member": canonical_member,
            "packet_result_sha256": expected_result_sha,
            "reason": recovery_reason,
            "recovered_at": recovered_at,
        }
        recovery["record_sha256"] = canonical_record_sha256(
            recovery_record_preimage(
                state,
                packet,
                input_index,
                preserved,
                carrier_index,
                carrier,
                recovery,
            )
        )
        preserved["recovery"] = recovery
        target.clear()
        target.update(preserved)
        recovery_errors = packet_recovery_integrity_errors(paths, state)
        if recovery_errors:
            raise HarnessError(
                "recovered packet input failed provenance validation: "
                + "; ".join(recovery_errors)
            )
        if refs and all(
            _is_canonical_snapshot_version(ref.get("snapshot_version")) for ref in refs
        ):
            packet["input_snapshot_version"] = 1
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(
        {
            "task_id": args.task,
            "packet_id": args.packet_id,
            "input_index": input_index + 1,
            "snapshot_path": preserved["path"],
            "sha256": preserved["sha256"],
            "recovery": preserved["recovery"],
        },
        args.json,
    )
    return 0


def cmd_verification_supersession_seal(
    args: argparse.Namespace, paths: HarnessPaths
) -> int:
    """Seal a legacy supersession against its exact canonical replacement."""

    migration_field = "terminal_supersession_checkpoint_migration"
    with state_lock(paths):
        state = load_task(paths, args.task)
        terminal_migration = state.get("status") in {"done", "cancelled"}
        records = state.get("verification", [])
        source_index = int(args.verification_index) - 1
        replacement_index = int(args.replacement_index) - 1
        if (
            source_index < 0
            or source_index >= len(records)
            or replacement_index < 0
            or replacement_index >= len(records)
            or source_index == replacement_index
        ):
            raise HarnessError("verification and replacement indices must name distinct records")
        source = records[source_index]
        replacement = records[replacement_index]
        supplied_hashes = {
            "current source": str(args.expected_current_record_sha256).lower(),
            "source preimage": str(args.expected_source_record_sha256).lower(),
            "replacement before materialize": str(
                args.expected_replacement_before_materialize_sha256
            ).lower(),
            "replacement current": str(
                args.expected_replacement_current_sha256
            ).lower(),
        }
        if any(
            not re.fullmatch(r"[0-9a-f]{64}", digest)
            for digest in supplied_hashes.values()
        ):
            raise HarnessError("supersession seal SHA-256 values must be full 64 hex")

        pending = state.get(migration_field)
        checkpoint: Path | None = None
        resumed = False
        already_sealed = False
        replacement_is_sealed_supersession = bool(
            replacement.get("superseded_at")
            and _is_exact_int(replacement.get("supersession_version"), 2)
        )
        replacement_was_materialized = (
            not replacement_is_sealed_supersession
            and supplied_hashes["replacement before materialize"]
            != supplied_hashes["replacement current"]
        )
        completed_replay = (
            pending is None
            and terminal_migration
            and _is_exact_int(source.get("supersession_version"), 2)
        )
        if completed_replay:
            if (
                canonical_record_sha256(verification_legacy_seal_preimage(source))
                != supplied_hashes["current source"]
                or source.get("source_record_sha256")
                != supplied_hashes["source preimage"]
                or source.get("replacement_index") != replacement_index + 1
                or source.get("replacement_record_sha256")
                != supplied_hashes["replacement before materialize"]
                or canonical_record_sha256(replacement)
                != supplied_hashes["replacement current"]
            ):
                raise HarnessError("completed supersession seal identity does not match replay")
            materialization = source.get("replacement_materialization")
            if replacement_was_materialized:
                if (
                    not isinstance(materialization, dict)
                    or materialization.get("from_record_sha256")
                    != supplied_hashes["replacement before materialize"]
                    or materialization.get("to_record_sha256")
                    != supplied_hashes["replacement current"]
                ):
                    raise HarnessError(
                        "completed supersession materialization does not match replay"
                    )
            elif materialization is not None:
                raise HarnessError(
                    "completed direct supersession unexpectedly has materialization metadata"
                )
            checkpoint_ok, checkpoint_reason = checkpoint_matches(paths, state)
            if not checkpoint_ok:
                raise HarnessError(
                    "completed terminal supersession checkpoint is invalid: "
                    + checkpoint_reason
                )
            integrity_errors = verification_migration_integrity_errors(paths, state)
            if integrity_errors:
                raise HarnessError(
                    "completed terminal supersession migration is damaged: "
                    + "; ".join(integrity_errors)
                )
            checkpoint = task_dir(paths, args.task) / "checkpoint.md"
            write_index(paths)
            resumed = True
            already_sealed = True
        elif pending is not None:
            required_pending_fields = {
                "version",
                "method",
                "verification_index",
                "replacement_index",
                "previous_source_record_sha256",
                "source_preimage_sha256",
                "replacement_before_materialize_sha256",
                "replacement_current_sha256",
                "replacement_was_materialized",
                "pending_state_sha256",
                "target_checkpoint_sha256",
                "target_state_sha256",
            }
            expected_pending = {
                "verification_index": source_index + 1,
                "replacement_index": replacement_index + 1,
                "previous_source_record_sha256": supplied_hashes["current source"],
                "source_preimage_sha256": supplied_hashes["source preimage"],
                "replacement_before_materialize_sha256": supplied_hashes[
                    "replacement before materialize"
                ],
                "replacement_current_sha256": supplied_hashes["replacement current"],
            }
            state_revision = state.get("revision")
            if (
                not terminal_migration
                or not isinstance(pending, dict)
                or set(pending) != required_pending_fields
                or not _is_exact_int(pending.get("version"), 2)
                or pending.get("method") != "terminal-supersession-checkpoint-v2"
                or any(pending.get(key) != value for key, value in expected_pending.items())
                or not isinstance(pending.get("replacement_was_materialized"), bool)
                or pending.get("replacement_was_materialized")
                != replacement_was_materialized
                or not re.fullmatch(
                    r"[0-9a-f]{64}", str(pending.get("pending_state_sha256", ""))
                )
                or not re.fullmatch(
                    r"[0-9a-f]{64}", str(pending.get("target_state_sha256", ""))
                )
                or state.get("checkpoint_required") is not True
                or not isinstance(state_revision, int)
                or isinstance(state_revision, bool)
                or state.get("checkpoint_revision") != state_revision - 1
            ):
                raise HarnessError("terminal supersession checkpoint migration state is invalid")
            pending_preimage = copy.deepcopy(state)
            pending_preimage.pop(migration_field, None)
            if canonical_record_sha256(pending_preimage) != pending.get(
                "pending_state_sha256"
            ):
                raise HarnessError(
                    "terminal supersession pending state identity changed"
                )
            if (
                not _is_exact_int(source.get("supersession_version"), 2)
                or source.get("source_record_sha256") != supplied_hashes["source preimage"]
                or source.get("replacement_index") != replacement_index + 1
                or source.get("replacement_record_sha256")
                != supplied_hashes["replacement before materialize"]
            ):
                raise HarnessError("terminal supersession checkpoint migration identity changed")
            integrity_errors = verification_migration_integrity_errors(paths, state)
            if integrity_errors:
                raise HarnessError(
                    "terminal supersession checkpoint migration is damaged: "
                    + "; ".join(integrity_errors)
                )
            final_state = copy.deepcopy(state)
            final_state.pop(migration_field, None)
            final_state["checkpoint_required"] = False
            final_state["checkpoint_revision"] = final_state["revision"]
            checkpoint, checkpoint_text, checkpoint_sha = prepare_checkpoint(
                paths, final_state
            )
            if pending.get("target_checkpoint_sha256") != checkpoint_sha:
                raise HarnessError("terminal supersession target checkpoint SHA-256 changed")
            final_state["checkpoint_sha256"] = checkpoint_sha
            if canonical_record_sha256(final_state) != pending.get(
                "target_state_sha256"
            ):
                raise HarnessError("terminal supersession target state identity changed")
            atomic_write_text(checkpoint, checkpoint_text)
            write_task(paths, final_state)
            write_index(paths)
            state = final_state
            replacement_was_materialized = bool(
                pending["replacement_was_materialized"]
            )
            resumed = True
        else:
            if terminal_migration:
                checkpoint_ok, checkpoint_reason = checkpoint_matches(paths, state)
                if not checkpoint_ok:
                    raise HarnessError(
                        "terminal supersession migration requires a current physical checkpoint: "
                        + checkpoint_reason
                    )
                migration_errors = verification_migration_integrity_errors(paths, state)
                if migration_errors:
                    raise HarnessError(
                        "terminal supersession migration found unrelated verification damage: "
                        + "; ".join(migration_errors)
                    )
            else:
                require_open_task(state, "seal verification supersession for")
            if canonical_record_sha256(source) != supplied_hashes["current source"]:
                raise HarnessError("superseded verification changed after seal approval")
            if not source.get("superseded_at") or _is_exact_int(
                source.get("supersession_version"), 2
            ):
                raise HarnessError("verification must be an unsealed legacy supersession")
            if (
                source.get("replacement_index") != replacement_index + 1
                or source.get("replacement_record_sha256")
                != supplied_hashes["replacement before materialize"]
            ):
                raise HarnessError("legacy supersession replacement identity changed")
            if canonical_record_sha256(
                verification_source_preimage(source)
            ) != supplied_hashes["source preimage"]:
                raise HarnessError("legacy supersession source preimage SHA-256 mismatch")
            if canonical_record_sha256(replacement) != supplied_hashes[
                "replacement current"
            ]:
                raise HarnessError("materialized replacement changed after seal approval")
            if any(
                not _is_canonical_snapshot_version(artifact.get("snapshot_version"))
                for artifact in replacement.get("artifact_refs", [])
            ):
                raise HarnessError("supersession seal replacement is not fully materialized")
            if replacement_is_sealed_supersession:
                if replacement.get("source_record_sha256") != supplied_hashes[
                    "replacement before materialize"
                ]:
                    raise HarnessError(
                        "replacement supersession source identity does not match legacy edge"
                    )
            elif replacement_was_materialized:
                legacy_replacement_sha = canonical_record_sha256(
                    verification_legacy_materialization_preimage(replacement)
                )
                if legacy_replacement_sha != supplied_hashes[
                    "replacement before materialize"
                ]:
                    raise HarnessError("replacement legacy preimage SHA-256 mismatch")
            replacement_errors = verification_record_integrity_errors(
                paths, state, [(replacement_index + 1, replacement)]
            )
            if replacement_errors:
                raise HarnessError(
                    "supersession seal replacement is not physically valid: "
                    + "; ".join(replacement_errors)
                )
            source_time = parse_time(str(source.get("recorded_at", "")))
            replacement_time = parse_time(str(replacement.get("recorded_at", "")))
            if (
                source.get("category") != replacement.get("category")
                or (
                    replacement.get("status") != "pass"
                    and not (
                        replacement_is_sealed_supersession
                        and replacement.get("status") == "skipped"
                    )
                )
                or source_time is None
                or replacement_time is None
                or replacement_time <= source_time
            ):
                raise HarnessError("legacy supersession replacement relationship is invalid")
            source["supersession_version"] = 2
            source["source_record_sha256"] = supplied_hashes["source preimage"]
            if replacement_was_materialized:
                source["replacement_materialization"] = {
                    "version": 1,
                    "method": "canonical-artifact-materialization",
                    "from_record_sha256": supplied_hashes[
                        "replacement before materialize"
                    ],
                    "to_record_sha256": supplied_hashes["replacement current"],
                    "sealed_at": now_iso(),
                }
            else:
                source.pop("replacement_materialization", None)
            staged_errors = verification_migration_integrity_errors(paths, state)
            if staged_errors:
                raise HarnessError(
                    "sealed supersession failed integrity validation: "
                    + "; ".join(staged_errors)
                )
            if terminal_migration:
                bump_task(state, checkpoint_required=True)
                final_state = copy.deepcopy(state)
                final_state["checkpoint_required"] = False
                final_state["checkpoint_revision"] = final_state["revision"]
                checkpoint, checkpoint_text, checkpoint_sha = prepare_checkpoint(
                    paths, final_state
                )
                final_state["checkpoint_sha256"] = checkpoint_sha
                pending_state_sha = canonical_record_sha256(state)
                target_state_sha = canonical_record_sha256(final_state)
                state[migration_field] = {
                    "version": 2,
                    "method": "terminal-supersession-checkpoint-v2",
                    "verification_index": source_index + 1,
                    "replacement_index": replacement_index + 1,
                    "previous_source_record_sha256": supplied_hashes["current source"],
                    "source_preimage_sha256": supplied_hashes["source preimage"],
                    "replacement_before_materialize_sha256": supplied_hashes[
                        "replacement before materialize"
                    ],
                    "replacement_current_sha256": supplied_hashes[
                        "replacement current"
                    ],
                    "replacement_was_materialized": replacement_was_materialized,
                    "pending_state_sha256": pending_state_sha,
                    "target_checkpoint_sha256": checkpoint_sha,
                    "target_state_sha256": target_state_sha,
                }
                write_task(paths, state)
                atomic_write_text(checkpoint, checkpoint_text)
                write_task(paths, final_state)
                state = final_state
            else:
                bump_task(state)
                write_task(paths, state)
            write_index(paths)
    emit(
        {
            "task_id": args.task,
            "verification_index": source_index + 1,
            "replacement_index": replacement_index + 1,
            "supersession_version": 2,
            "replacement_was_materialized": replacement_was_materialized,
            "terminal_migration": terminal_migration,
            "resumed": resumed,
            "already_sealed": already_sealed,
            "checkpoint": str(checkpoint) if checkpoint is not None else None,
        },
        args.json,
    )
    return 0


def cmd_verification_supersede(args: argparse.Namespace, paths: HarnessPaths) -> int:
    """Explicitly retire one legacy verification in favor of a valid replacement."""

    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "supersede verification for")
        records = state.get("verification", [])
        source_index = int(args.verification_index) - 1
        replacement_index = int(args.replacement_index) - 1
        if (
            source_index < 0
            or source_index >= len(records)
            or replacement_index < 0
            or replacement_index >= len(records)
            or source_index == replacement_index
        ):
            raise HarnessError("verification and replacement indices must name distinct records")
        source = records[source_index]
        replacement = records[replacement_index]
        expected_source_sha = str(args.expected_record_sha256).lower()
        expected_replacement_sha = str(args.replacement_record_sha256).lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_source_sha) or not re.fullmatch(
            r"[0-9a-f]{64}", expected_replacement_sha
        ):
            raise HarnessError("verification record SHA-256 values must be full 64 hex")
        if canonical_record_sha256(source) != expected_source_sha:
            raise HarnessError("verification record changed after approval")
        if canonical_record_sha256(replacement) != expected_replacement_sha:
            raise HarnessError("replacement verification record changed after approval")
        if source.get("superseded_at"):
            raise HarnessError("verification record is already superseded")
        if source.get("status") not in ACCOUNTED_VERIFICATION_STATUSES - {"skipped"}:
            raise HarnessError("only an accounted non-skipped verification can be superseded")
        if any(
            not _is_canonical_snapshot_version(artifact.get("snapshot_version"))
            for artifact in replacement.get("artifact_refs", [])
        ):
            raise HarnessError(
                "replacement verification artifacts must be materialized before supersession"
            )
        source_time = parse_time(str(source.get("recorded_at", "")))
        replacement_time = parse_time(str(replacement.get("recorded_at", "")))
        if (
            source.get("category") != replacement.get("category")
            or replacement.get("status") != "pass"
            or source_time is None
            or replacement_time is None
            or replacement_time <= source_time
        ):
            raise HarnessError(
                "replacement must be a later passing verification in the same category"
            )
        replacement_errors = verification_record_integrity_errors(
            paths, state, [(replacement_index + 1, replacement)]
        )
        if replacement_errors:
            raise HarnessError(
                "replacement verification is not physically valid: "
                + "; ".join(replacement_errors)
            )
        supersession_reason = require_evidence_detail(
            args.reason, "verification supersession reason"
        )
        source["original_status"] = source.get("status")
        source["status"] = "skipped"
        source["superseded_at"] = now_iso()
        source["supersession_reason"] = supersession_reason
        source["supersession_version"] = 2
        source["source_record_sha256"] = expected_source_sha
        source["replacement_index"] = replacement_index + 1
        source["replacement_record_sha256"] = expected_replacement_sha
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(
        {
            "task_id": args.task,
            "verification_index": source_index + 1,
            "replacement_index": replacement_index + 1,
            "status": "skipped",
        },
        args.json,
    )
    return 0


def _upgrade_packet_dispatch_schema(packet: dict[str, Any]) -> None:
    schema_version = _packet_schema_version(packet)
    if schema_version is None:
        raise HarnessError(
            f"packet {packet.get('packet_id')} schema version is invalid"
        )
    if schema_version == 5:
        if (
            not _is_exact_int(packet.get("dispatch_version"), 1)
            or not isinstance(packet.get("dispatch_attempts"), list)
        ):
            raise HarnessError("packet dispatch schema v5 is malformed")
        return
    if schema_version != 4 or packet.get("status") != "ready":
        raise HarnessError(
            "only a ready legacy packet may be upgraded to dispatch schema v5"
        )
    packet["packet_schema_version"] = 5
    packet["dispatch_version"] = 1
    packet["dispatch_provenance"] = "none"
    packet["dispatch_attempts"] = []
    packet["dispatch_schema_origin"] = "legacy_v4_migration"


def _record_core_dispatch_model_version(state: dict[str, Any]) -> None:
    """Record core v1 without downgrading an existing transport-v2 task."""

    state["dispatch_model_version"] = (
        2
        if state.get("dispatch_model_version") == 2
        or any(
            isinstance(packet, dict) and packet.get("dispatch_version") == 2
            for packet in state.get("packets", [])
        )
        else 1
    )


def _dispatch_attempt_authority_sha256(attempt: dict[str, Any]) -> str:
    immutable_fields = (
        "attempt",
        "arm_id",
        "chief_session_id",
        "chief_epoch",
        "parent_session_id",
        "parent_packet_id",
        "expected_agent_type",
        "plan_sha256",
        "packet_contract_sha256",
        "execution_selection_id",
        "lane_snapshot",
        "steward_snapshot",
        "armed_at",
        "expires_at",
        "authority_sha256",
    )
    return canonical_record_sha256(
        {field: copy.deepcopy(attempt.get(field)) for field in immutable_fields}
    )


def _active_dispatch_attempt(packet: dict[str, Any]) -> dict[str, Any]:
    return dispatch_protocol_impl.active_dispatch_attempt(packet)


def _selection_lane_snapshot(
    selection: dict[str, Any] | None, lane_id: str
) -> dict[str, Any]:
    if selection is None:
        return {}
    matches = [
        item
        for item in selection.get("lane_snapshots", [])
        if item.get("lane_id") == lane_id
    ]
    if len(matches) != 1:
        raise HarnessError("execution selection lacks the packet lane snapshot")
    return copy.deepcopy(matches[0])


def _packet_execution_lane_snapshot(
    selection: dict[str, Any] | None, packet: dict[str, Any]
) -> dict[str, Any]:
    if _is_steward_synthesis_packet(packet):
        snapshot = packet.get("steward_execution_snapshot")
        if not isinstance(snapshot, dict) or not snapshot:
            raise HarnessError("Steward synthesis packet lacks an execution snapshot")
        return copy.deepcopy(snapshot)
    return _selection_lane_snapshot(selection, str(packet.get("lane_id", "")))


def _validate_hook_identity(value: Any, label: str) -> str:
    return dispatch_protocol_impl.validate_hook_identity(
        value, label, policy=_dispatch_protocol_policy()
    )


def _safe_hook_observation_text(value: Any) -> str:
    return dispatch_protocol_impl.safe_hook_observation_text(
        value, policy=_dispatch_protocol_policy()
    )


def _expire_dispatch_arms(
    state: dict[str, Any], *, current: dt.datetime
) -> list[dict[str, str]]:
    return dispatch_protocol_impl.expire_dispatch_arms(state, current=current)


def cmd_packet_arm(args: argparse.Namespace, paths: HarnessPaths) -> int:
    if bool(args.any_agent_type) == bool(args.expected_agent_type):
        raise HarnessError(
            "packet arm requires exactly one of --expected-agent-type or --any-agent-type"
        )
    if args.any_agent_type:
        # The wildcard sentinel is a deliberate non-identity value; it owns the
        # whole parent slot and bypasses the transport-id regex on purpose.
        expected_agent_type = dispatch_protocol_impl.WILDCARD_AGENT_TYPE
    else:
        expected_agent_type = _validate_hook_identity(
            args.expected_agent_type, "expected Codex transport agent type"
        )
    expires_at = parse_time(args.expires_at)
    current = dt.datetime.now().astimezone()
    if expires_at is None or expires_at <= current:
        raise HarnessError("packet arm expiry must be a future timezone-aware timestamp")
    if expires_at > current + dt.timedelta(seconds=DISPATCH_ARM_MAX_SECONDS):
        raise HarnessError(
            f"packet arm expiry may be at most {DISPATCH_ARM_MAX_SECONDS} seconds ahead"
        )
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "arm packet for")
        require_plan_ready(paths, state, "arm packet")
        _expire_dispatch_arms(state, current=current)
        packet = _packet_by_id(state, args.packet_id)
        if packet.get("status") != "ready":
            raise HarnessError("only a ready packet can be armed")
        if _packet_schema_version(packet) == 4:
            legacy_contract_error = packet_contract_integrity_error(paths, state, packet)
            if legacy_contract_error:
                raise HarnessError(legacy_contract_error)
            _adopt_legacy_execution_provenance_for_v4_migration(state)
        _upgrade_packet_dispatch_schema(packet)
        authority = load_chief_authority(paths)
        assert authority is not None
        chief_session_id = str(authority.get("session_id", ""))
        parent_session_id = str(args.parent_session_id or chief_session_id)
        parent_session_id = _validate_hook_identity(
            parent_session_id, "parent session id"
        )
        depth = int(packet.get("delegation_depth", 1))
        parent: dict[str, Any] | None = None
        if depth == 1:
            require_root_session(paths, state, parent_session_id)
        if depth == 2:
            parent = _packet_by_id(
                state, str(packet.get("parent_packet_id", ""))
            )
            if parent.get("agent_id") != parent_session_id:
                raise HarnessError(
                    "depth-two packet arm parent session must equal its dispatched parent agent id"
                )
        wildcard = dispatch_protocol_impl.WILDCARD_AGENT_TYPE
        collisions: list[str] = []
        for other in state.get("packets", []):
            if other.get("status") != "armed":
                continue
            attempt = _active_dispatch_attempt(other)
            if attempt.get("parent_session_id") != parent_session_id:
                continue
            other_type = attempt.get("expected_agent_type")
            # A wildcard on either side owns the whole parent slot, so it
            # collides with any armed type; two exact types collide only when
            # equal. This preserves the exactly-one-candidate invariant.
            if (
                expected_agent_type == wildcard
                or other_type == wildcard
                or other_type == expected_agent_type
            ):
                collisions.append(str(other.get("packet_id", "")))
        if collisions:
            raise HarnessError(
                "an armed packet already occupies this parent-session/agent-type slot: "
                + ", ".join(collisions)
            )
        authority_errors = packet_authority_integrity_errors(
            paths, state, packet, require_origin=True
        )
        if authority_errors:
            raise HarnessError(
                "packet authority is missing or tampered: "
                + "; ".join(authority_errors)
            )
        selection = _validate_packet_activation_topology(state, packet)
        _validate_packet_resource_envelope(
            state,
            packet,
            selection,
            enforce_active_limit=True,
        )
        _validate_skill_canary_work_unit_binding(
            state,
            str(packet.get("skill_release_id", "")),
            str(packet.get("skill_canary_event_id", "")),
            require_live_canary=True,
        )
        if parent is not None:
            ensure_subagent_parent_mapping_unlocked(paths, state, parent)
        attempt_number = len(packet["dispatch_attempts"]) + 1
        armed_at = now_iso()
        attempt = {
            "attempt": attempt_number,
            "arm_id": f"{packet['packet_id']}-a{attempt_number}",
            "status": "armed",
            "chief_session_id": chief_session_id,
            "chief_epoch": authority["epoch"],
            "parent_session_id": parent_session_id,
            "parent_packet_id": str(packet.get("parent_packet_id", "")),
            "expected_agent_type": expected_agent_type,
            "plan_sha256": state.get("plan_sha256", ""),
            "packet_contract_sha256": packet.get("packet_contract_sha256", ""),
            "execution_selection_id": packet.get("execution_selection_id", ""),
            "lane_snapshot": _packet_execution_lane_snapshot(selection, packet),
            "steward_snapshot": copy.deepcopy(
                selection.get("steward_snapshot", {}) if selection else {}
            ),
            "armed_at": armed_at,
            "expires_at": expires_at.isoformat(timespec="microseconds"),
            "authority_sha256": canonical_record_sha256(authority),
            "observation": None,
            "closed_at": "",
            "reason": "",
        }
        attempt["arm_authority_sha256"] = _dispatch_attempt_authority_sha256(
            attempt
        )
        packet["dispatch_attempts"].append(attempt)
        packet["status"] = "armed"
        packet["updated_at"] = armed_at
        _record_core_dispatch_model_version(state)
        state.setdefault("subagent_incidents", [])
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(
        {
            "task_id": args.task,
            "packet_id": args.packet_id,
            "status": "armed",
            "arm_id": attempt["arm_id"],
            "parent_session_id": parent_session_id,
            "expected_agent_type": expected_agent_type,
            "expires_at": attempt["expires_at"],
        },
        args.json,
    )
    return 0


def cmd_packet_disarm(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "disarm packet for")
        packet = _packet_by_id(state, args.packet_id)
        if packet.get("status") != "armed":
            raise HarnessError("only an armed packet can be disarmed")
        attempt = _active_dispatch_attempt(packet)
        recorded = now_iso()
        attempt["status"] = "disarmed"
        attempt["closed_at"] = recorded
        attempt["reason"] = require_evidence_detail(
            args.reason, "packet disarm reason"
        )
        packet["status"] = "ready"
        packet["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(
        {"task_id": args.task, "packet_id": args.packet_id, "status": "ready"},
        args.json,
    )
    return 0


def _subagent_event_id(payload: dict[str, Any]) -> str:
    return dispatch_protocol_impl.subagent_event_id(
        payload, policy=_dispatch_protocol_policy()
    )


def _validate_current_dispatch_arm(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet: dict[str, Any],
    attempt: dict[str, Any],
    *,
    current: dt.datetime,
) -> None:
    if packet.get("status") != "armed" or _packet_schema_version(packet) != 5:
        raise HarnessError("matching packet is not armed under schema v5")
    if attempt.get("arm_authority_sha256") != _dispatch_attempt_authority_sha256(
        attempt
    ):
        raise HarnessError("packet arm authority digest is invalid")
    expires_at = parse_time(str(attempt.get("expires_at", "")))
    if expires_at is None or expires_at <= current:
        raise HarnessError("packet arm expired before dispatch")
    authority = load_chief_authority(paths)
    if (
        authority is None
        or authority.get("status") != "active"
        or is_expired(str(authority.get("expires_at", "")))
        or attempt.get("chief_session_id") != authority.get("session_id")
        or attempt.get("chief_epoch") != authority.get("epoch")
        or attempt.get("authority_sha256") != canonical_record_sha256(authority)
    ):
        raise HarnessError("packet arm Chief authority is no longer current")
    require_plan_ready(paths, state, "consume packet arm")
    if (
        attempt.get("plan_sha256") != state.get("plan_sha256")
        or attempt.get("packet_contract_sha256")
        != packet.get("packet_contract_sha256")
        or attempt.get("execution_selection_id")
        != packet.get("execution_selection_id", "")
    ):
        raise HarnessError("packet arm authority changed after it was issued")
    authority_errors = packet_authority_integrity_errors(
        paths, state, packet, require_origin=True
    )
    if authority_errors:
        raise HarnessError("packet authority is invalid: " + "; ".join(authority_errors))
    selection = _validate_packet_activation_topology(state, packet)
    _validate_packet_resource_envelope(
        state,
        packet,
        selection,
        enforce_active_limit=True,
    )
    if attempt.get("lane_snapshot") != _packet_execution_lane_snapshot(
        selection, packet
    ) or attempt.get("steward_snapshot") != (
        selection.get("steward_snapshot", {}) if selection else {}
    ):
        raise HarnessError("packet arm topology snapshot is stale")
    _validate_skill_canary_work_unit_binding(
        state,
        str(packet.get("skill_release_id", "")),
        str(packet.get("skill_canary_event_id", "")),
        require_live_canary=True,
    )


def _validate_observed_arm(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet: dict[str, Any],
    attempt: dict[str, Any],
    *,
    parent_session_id: str,
    transport_agent_type: str,
    current: dt.datetime,
) -> None:
    if attempt.get("parent_session_id") != parent_session_id or not (
        dispatch_protocol_impl._expected_type_matches(
            attempt.get("expected_agent_type"), transport_agent_type
        )
    ):
        raise HarnessError("packet arm no longer matches the observed parent/type")
    _validate_current_dispatch_arm(
        paths, state, packet, attempt, current=current
    )


def _refresh_index_after_hook_commit(paths: HarnessPaths) -> bool:
    """Refresh the derived index without hiding an already committed hook result."""

    try:
        write_index(paths)
    except Exception:
        # The target task mutation is already durable. INDEX.md is derived and may
        # depend on unrelated task state, so its failure must not erase the packet
        # contract or stop-without-work context returned to the new sub-agent.
        return False
    return True


def _dispatch_protocol_services(
) -> dispatch_protocol_impl.DispatchProtocolServices:
    return dispatch_protocol_impl.DispatchProtocolServices(
        packet_by_id=_packet_by_id,
        packet_authority_integrity_errors=packet_authority_integrity_errors,
        validate_observed_arm=_validate_observed_arm,
        ensure_subagent_parent_mapping=ensure_subagent_parent_mapping_unlocked,
        refresh_index_after_commit=_refresh_index_after_hook_commit,
    )


def observe_subagent_start(
    paths: HarnessPaths, payload: dict[str, Any]
) -> dict[str, Any]:
    return dispatch_protocol_impl.observe_subagent_start(
        paths,
        payload,
        policy=_dispatch_protocol_policy(),
        services=_dispatch_protocol_services(),
    )


def validate_claude_pre_spawn_arm(
    paths: HarnessPaths,
    *,
    parent_session_id: str,
    transport_agent_type: str,
) -> dict[str, Any]:
    """Validate Claude's pre-spawn slot against the full live arm authority."""

    return dispatch_protocol_impl.validate_pre_spawn_arm(
        paths,
        parent_session_id=parent_session_id,
        transport_agent_type=transport_agent_type,
        policy=_claude_dispatch_protocol_policy(),
        services=_dispatch_protocol_services(),
    )


def observe_claude_subagent_start(
    paths: HarnessPaths, payload: dict[str, Any]
) -> dict[str, Any]:
    return dispatch_protocol_impl.observe_subagent_start(
        paths,
        payload,
        policy=_claude_dispatch_protocol_policy(),
        services=_dispatch_protocol_services(),
    )


def validate_claude_helper_slot(
    paths: HarnessPaths, *, parent_session_id: str
) -> dict[str, Any]:
    """Read-only helper-budget check for Claude's depth-two pre-spawn gate."""

    return dispatch_protocol_impl.helper_budget_slot(
        paths,
        parent_session_id=parent_session_id,
        policy=_claude_dispatch_protocol_policy(),
        services=_dispatch_protocol_services(),
    )


def cmd_subagent_incident_account(
    args: argparse.Namespace, paths: HarnessPaths
) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "account sub-agent incident for")
        session_id = require_root_session(paths, state, args.session_id)
        matches = [
            item
            for item in state.get("subagent_incidents", [])
            if item.get("incident_id") == args.incident_id
        ]
        if len(matches) != 1:
            raise HarnessError("incident id does not name exactly one spawn incident")
        incident = matches[0]
        if incident.get("status") != "open":
            raise HarnessError("only an open spawn incident can be accounted")
        incident["status"] = "accounted"
        resolution = {
            "disposition": args.disposition,
            "reason": require_evidence_detail(
                args.reason, "spawn incident accounting reason"
            ),
            "evidence": require_evidence_detail(
                args.evidence, "spawn incident accounting evidence"
            ),
            "root_session_id": session_id,
            "recorded_at": now_iso(),
        }
        if args.disposition_kind:
            # Machine-readable guard-outcome tag alongside the free-text
            # disposition; legacy resolutions without it stay valid.
            resolution["disposition_kind"] = args.disposition_kind
        incident["resolution"] = resolution
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(incident, args.json)
    return 0


def cmd_create_packet(args: argparse.Namespace, paths: HarnessPaths) -> int:
    packet_id = validate_id(args.packet_id, "packet id")
    task_type = validate_id(args.task_type, "packet task type")
    synthesis_selection_id = str(args.steward_synthesis_for_selection_id or "")
    if synthesis_selection_id:
        synthesis_selection_id = validate_id(
            synthesis_selection_id, "Steward synthesis selection id"
        )
        task_type = "steward-synthesis"
        if args.execution_selection_id and (
            args.execution_selection_id != synthesis_selection_id
        ):
            raise HarnessError(
                "Steward synthesis selection must match --execution-selection-id when both are given"
            )
        if args.delegation_depth != 1 or args.packet_mode != "read_only":
            raise HarnessError("Steward synthesis must be a depth-one read_only packet")
        if any(
            (
                args.skill_release_id,
                args.skill_canary_event_id,
                args.capacity_review_source_id,
                args.input_artifact,
                args.command_artifact,
                args.command_sha256,
            )
        ):
            raise HarnessError(
                "Steward synthesis consumes only its immutable specialist result bindings"
            )
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
    helper_spawn_budget = int(args.helper_spawn_budget or 0)
    if helper_spawn_budget < 0 or helper_spawn_budget > HELPER_SPAWN_BUDGET_MAX:
        raise HarnessError(
            f"--helper-spawn-budget must be between 0 and {HELPER_SPAWN_BUDGET_MAX}"
        )
    if helper_spawn_budget and args.delegation_depth != 1:
        raise HarnessError("only a depth-one packet may carry a helper spawn budget")
    if helper_spawn_budget and synthesis_selection_id:
        raise HarnessError("Steward synthesis packets may not carry a helper spawn budget")
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
        packet_worktree = state_worktree(paths, state)
        packet_locks = list(
            dict.fromkeys(
                validate_lock_identity(paths, lock, repo_root=packet_worktree)
                for lock in packet_locks
            )
        )
        _adopt_execution_policy_v2_for_new_work(state)
        packet_purpose = "work"
        steward_input_bindings: list[dict[str, Any]] = []
        steward_selection_snapshot: dict[str, Any] = {}
        steward_execution_snapshot: dict[str, Any] = {}
        selection: dict[str, Any] | None
        if synthesis_selection_id:
            packet_purpose = "steward_synthesis"
            if not args.lane_id:
                raise HarnessError("Steward synthesis requires --lane-id")
            selection = execution_selection_by_id(state, synthesis_selection_id)
            if (
                selection.get("status") != "active"
                or not _is_exact_int(
                    selection.get("execution_selection_version"), 2
                )
                or selection.get("mode")
                not in {"centralized_parallel", "hybrid"}
            ):
                raise HarnessError(
                    "Steward synthesis requires an active parallel/hybrid selection v2"
                )
            steward = _engaged_steward_lane(state)
            selected_steward = selection.get("steward_snapshot", {})
            if (
                not isinstance(selected_steward, dict)
                or selected_steward.get("lane_id") != steward.get("lane_id")
                or args.lane_id != steward.get("lane_id")
                or args.agent_role != steward.get("role")
            ):
                raise HarnessError(
                    "Steward synthesis role/lane must match the engaged selected Steward"
                )
            unfinished = [
                str(item.get("packet_id", ""))
                for item in state.get("packets", [])
                if item.get("execution_selection_id") == synthesis_selection_id
                and not _is_steward_synthesis_packet(item)
                and item.get("status") in ACTIVE_PACKET_STATUSES
            ]
            active_jobs = [
                str(item.get("run_id", ""))
                for item in state.get("jobs", [])
                if item.get("execution_selection_id") == synthesis_selection_id
                and item.get("status") in ACTIVE_JOB_STATUSES
            ]
            if unfinished or active_jobs:
                raise HarnessError(
                    "Steward synthesis requires terminal specialist work: "
                    + ", ".join(unfinished + active_jobs)
                )
            specialist_authority_errors = selection_done_packet_authority_errors(
                paths,
                state,
                synthesis_selection_id,
            )
            if specialist_authority_errors:
                raise HarnessError(
                    "Steward synthesis specialist authority is missing or tampered: "
                    + "; ".join(specialist_authority_errors)
                )
            steward_input_bindings = _selection_terminal_packet_bindings(
                state, synthesis_selection_id
            )
            selected_lane_ids = {
                str(item.get("lane_id", ""))
                for item in selection.get("lane_snapshots", [])
            }
            if not steward_input_bindings or {
                item["lane_id"] for item in steward_input_bindings
            } != selected_lane_ids:
                raise HarnessError(
                    "Steward synthesis requires terminal packet evidence from every selected lane"
                )
            prior_synthesis = [
                item
                for item in state.get("packets", [])
                if item.get("execution_selection_id") == synthesis_selection_id
                and _is_steward_synthesis_packet(item)
            ]
            blocking_synthesis = [
                str(item.get("packet_id", ""))
                for item in prior_synthesis
                if item.get("status") not in {"failed", "cancelled"}
            ]
            if blocking_synthesis:
                raise HarnessError(
                    "selection already has a live or successful Steward synthesis packet: "
                    + ", ".join(blocking_synthesis)
                )
            if prior_synthesis and args.retry_of_packet_id not in {
                str(item.get("packet_id", "")) for item in prior_synthesis
            }:
                raise HarnessError(
                    "retrying Steward synthesis requires --retry-of-packet-id"
                )
            steward_selection_snapshot = copy.deepcopy(selected_steward)
            steward_execution_snapshot = _lane_authority_snapshot(steward)
        else:
            if args.lane_id:
                lane_by_id(state, args.lane_id)
            selection = _validate_active_execution_selection(
                state, args.lane_id or "", args.execution_selection_id or ""
            )
            if selection is not None:
                frozen_by = _selection_synthesis_freeze_packet_ids(
                    state, str(selection.get("selection_id", ""))
                )
                if frozen_by:
                    raise HarnessError(
                        "specialist packet creation is frozen after Steward synthesis "
                        "begins: "
                        + ", ".join(frozen_by)
                    )
        resource_envelope_sha256 = ""
        if selection is not None and selection.get("resource_envelope") is not None:
            resource_envelope_sha256 = str(
                selection.get("resource_envelope_sha256", "")
            )
            _validate_packet_resource_envelope(
                state,
                {
                    "packet_id": packet_id,
                    "lane_id": args.lane_id or "",
                    "agent_role": args.agent_role,
                    "model_tier": args.model_tier,
                    "delegation_depth": args.delegation_depth,
                    "execution_selection_id": selection.get("selection_id", ""),
                    "resource_envelope_sha256": resource_envelope_sha256,
                },
                selection,
                enforce_active_limit=False,
            )
        skill_binding = _validate_skill_canary_work_unit_binding(
            state,
            args.skill_release_id or "",
            args.skill_canary_event_id or "",
            require_live_canary=True,
        )
        prepared_input_artifacts = prepare_bound_artifacts(
            args.input_artifact, "packet input artifact"
        )
        if args.capacity_review_source_id:
            source_review = capacity_review_by_id(state, args.capacity_review_source_id)
            dataset = source_review.get("dataset", {})
            if (
                source_review.get("status") != "data_ready"
                or args.lane_id != source_review.get("capacity_lane_id")
                or task_type != "capacity-analysis"
                or not any(
                    ref.get("source_path") == dataset.get("path")
                    and ref.get("sha256") == dataset.get("sha256")
                    for ref in prepared_input_artifacts
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
            parent_authority_errors = packet_authority_integrity_errors(
                paths,
                state,
                parent,
                require_origin=False,
            )
            if parent_authority_errors:
                raise HarnessError(
                    "depth-two parent authority is missing or tampered: "
                    + "; ".join(parent_authority_errors)
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
            if getattr(
                paths.project, "capacity_recommendation_only", True
            ) and recommendation.get("phase") != "recommendation_only":
                raise HarnessError(
                    "policy.capacity_recommendation_only is in force: a "
                    "capacity decision may only be consumed when its "
                    "recommendation records phase=recommendation_only"
                )
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
        held_locks = [
            str(lock)
            for claim in reserving
            for lock in claim.get("locks", [])
        ]
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
        input_artifact_refs = preserve_bound_artifacts(
            paths, args.task, prepared_input_artifacts
        )
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
            source_sha = hashlib.sha256(data).hexdigest()
            normalized_data = packet_integrity_impl.normalize_exact_command_bytes(data)
            actual_sha = hashlib.sha256(normalized_data).hexdigest()
            if expected_sha not in {source_sha, actual_sha}:
                raise HarnessError(
                    "command artifact SHA-256 mismatch after exact-command "
                    f"normalization: expected {expected_sha}, source {source_sha}, "
                    f"canonical {actual_sha}"
                )
            command_snapshot = (
                task_dir(paths, args.task) / "results" / f"packet-command-{packet_id}.txt"
            )
            atomic_write_bytes(command_snapshot, normalized_data)
            os.chmod(command_snapshot, 0o600)
            command_record = {
                "command_path": str(command_snapshot),
                "command_sha256": actual_sha,
                "command_size_bytes": len(normalized_data),
                "command_normalization": packet_integrity_impl.EXACT_COMMAND_NORMALIZATION_V1,
                "command_source_sha256": source_sha,
                "command_supplied_sha256": expected_sha,
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
        text += f"\n## AOI dispatch authority\n\n{NATIVE_V5_PACKET_CONTRACT_MARKER}\n"
        if helper_spawn_budget:
            text += (
                f"{HELPER_SPAWN_BUDGET_CONTRACT_PREFIX} `{helper_spawn_budget}`\n"
            )
        if resource_envelope_sha256:
            text += (
                "\n## AOI resource authority\n\n"
                f"- Execution selection: `{cast('dict[str, Any]', selection).get('selection_id', '')}`\n"
                f"- Resource envelope SHA-256: `{resource_envelope_sha256}`\n"
                "- Requested model routing remains unverified until observed.\n"
            )
        if command_record:
            text += (
                "\n## Exact command authority\n\n"
                f"- Path: `{command_record['command_path']}`\n"
                f"- SHA-256: `{command_record['command_sha256']}`\n"
                f"- Size: `{command_record['command_size_bytes']}` bytes\n"
                f"- Normalization: `{command_record['command_normalization']}`\n"
                f"- Source SHA-256: `{command_record['command_source_sha256']}`\n"
                f"- Supplied SHA-256: `{command_record['command_supplied_sha256']}`\n"
            )
        if input_artifact_refs:
            text += "\n## Immutable input snapshots\n\n"
            for artifact in input_artifact_refs:
                text += (
                    f"- Source: `{artifact['source_path']}`\n"
                    f"  Snapshot authority: `{artifact['path']}`\n"
                    f"  SHA-256: `{artifact['sha256']}`\n"
                    f"  Size: `{artifact['size_bytes']}` bytes\n"
                )
        if synthesis_selection_id:
            text += (
                "\n## Steward synthesis authority\n\n"
                f"- Execution selection: `{synthesis_selection_id}`\n"
                f"- Selected Steward snapshot: `{json.dumps(steward_selection_snapshot, sort_keys=True)}`\n"
                f"- Dispatch Steward snapshot: `{json.dumps(steward_execution_snapshot, sort_keys=True)}`\n"
                "- Immutable specialist result bindings:\n"
            )
            for binding in steward_input_bindings:
                text += (
                    f"  - `{binding['packet_id']}` / `{binding['lane_id']}` / "
                    f"`{binding['status']}` / `{binding['result_sha256']}`\n"
                )
        atomic_write_text(destination, text)
        packet_contract_sha256 = sha256_file(destination)
        _record_core_dispatch_model_version(state)
        state.setdefault("subagent_incidents", [])
        state.setdefault("packets", []).append(
            {
                "packet_id": packet_id,
                "path": str(destination),
                "packet_contract_sha256": packet_contract_sha256,
                "agent_role": args.agent_role,
                "model_tier": args.model_tier,
                "lane_id": args.lane_id or "",
                "execution_selection_id": selection.get("selection_id", "")
                if selection
                else "",
                "resource_envelope_sha256": resource_envelope_sha256,
                "packet_purpose": packet_purpose,
                **(
                    {
                        "steward_selection_snapshot": steward_selection_snapshot,
                        "steward_execution_snapshot": steward_execution_snapshot,
                        "steward_input_bindings": steward_input_bindings,
                    }
                    if synthesis_selection_id
                    else {}
                ),
                **(skill_binding or {}),
                "packet_schema_version": 5,
                "dispatch_version": 1,
                "dispatch_provenance": "none",
                "dispatch_attempts": [],
                "dispatch_schema_origin": "native_v5",
                "packet_mode": args.packet_mode,
                "task_type": task_type,
                "delegation_depth": args.delegation_depth,
                "helper_spawn_budget": helper_spawn_budget,
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
                # Consumption stays a depth-two packet LABEL under the
                # recommendation-only phase; it never selects a dispatch-time
                # profile or provider model.
                "phase": str(
                    (capacity_review.get("recommendation") or {}).get(
                        "phase", "recommendation_only"
                    )
                ),
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


def _hook_observed_routing_model(packet: dict[str, Any]) -> str:
    """Return the transport-observed model for this packet's consumed dispatch.

    Empty when the dispatch was never hook-observed or the transport did not
    expose a model field. This is the only routing-model source AOI trusts.
    """

    for attempt in packet.get("dispatch_attempts", []):
        if not isinstance(attempt, dict) or attempt.get("status") != "consumed":
            continue
        observation = attempt.get("observation")
        if isinstance(observation, dict):
            return str(observation.get("model", "") or "")
    return ""


def _applied_model_binding(state: dict[str, Any], role: str) -> str:
    """Return the newest applied, un-rolled-back resource-config model for role."""

    for event in reversed(state.get("resource_config_events", [])):
        if not isinstance(event, dict) or event.get("status") != "applied":
            continue
        if event.get("rollback"):
            continue
        agents = (event.get("resolved") or {}).get("agents") or {}
        assignment = agents.get(role)
        if isinstance(assignment, dict):
            return str(assignment.get("model", "") or "")
    return ""


def routing_verification_integrity_errors(state: dict[str, Any]) -> list[str]:
    """A stored routing_verified=true must be provable from hook + binding.

    A true flag that the derivation cannot reproduce is either a forged state
    edit or a legacy operator attestation — both are unproven routing claims
    and must surface in doctor instead of silently feeding downstream
    consumers. False/absent flags are always acceptable.
    """

    errors: list[str] = []
    for packet in state.get("packets", []):
        if not isinstance(packet, dict) or not packet.get("routing_verified"):
            continue
        if not _derived_routing_verified(state, packet):
            errors.append(
                f"packet {packet.get('packet_id')} claims routing_verified but "
                "no hook-observed model matches a current applied "
                "resource-config binding for its role"
            )
    return errors


def _derived_routing_verified(state: dict[str, Any], packet: dict[str, Any]) -> bool:
    """Routing is verified only by hook observation against an applied binding.

    CLI free text (--routing-evidence and friends) records a claim but never
    verification: the observed model must come from a consumed SubagentStart
    observation and must equal the model an applied resource-config event bound
    to this packet's role. Anything less stays routing_verified=false.
    """

    if packet.get("dispatch_provenance") not in HOOK_OBSERVED_DISPATCH_PROVENANCES:
        return False
    observed_model = _hook_observed_routing_model(packet)
    if not observed_model:
        return False
    bound_model = _applied_model_binding(state, str(packet.get("agent_role", "")))
    return bool(bound_model) and observed_model == bound_model


def cmd_packet_update(args: argparse.Namespace, paths: HarnessPaths) -> int:
    supplied_agent = ""
    if args.agent_id is not None:
        try:
            supplied_agent = validate_agent_id(args.agent_id, "packet agent id")
        except AgentIdentityError as exc:
            raise HarnessError(str(exc)) from exc
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "update packet for")
        packet = _packet_by_id(state, args.packet_id)
        previous_status = packet.get("status")
        previous_schema_version = _packet_schema_version(packet)
        if args.status == "dispatched":
            if previous_status in {"ready", "armed"}:
                if previous_schema_version == 4:
                    legacy_contract_error = packet_contract_integrity_error(
                        paths, state, packet
                    )
                    if legacy_contract_error:
                        raise HarnessError(legacy_contract_error)
                    _adopt_legacy_execution_provenance_for_v4_migration(state)
                _upgrade_packet_dispatch_schema(packet)
            if (_packet_schema_version(packet) or 0) >= 5:
                _record_core_dispatch_model_version(state)
                state.setdefault("subagent_incidents", [])
            if previous_status == "armed":
                _validate_current_dispatch_arm(
                    paths,
                    state,
                    packet,
                    _active_dispatch_attempt(packet),
                    current=dt.datetime.now().astimezone(),
                )
            authority_errors = packet_authority_integrity_errors(
                paths,
                state,
                packet,
                require_origin=previous_status == "ready",
            )
            if authority_errors:
                raise HarnessError(
                    "packet authority is missing or tampered: "
                    + "; ".join(authority_errors)
                )
            selection = _validate_packet_activation_topology(state, packet)
            _validate_packet_resource_envelope(
                state,
                packet,
                selection,
                enforce_active_limit=True,
            )
            _validate_skill_canary_work_unit_binding(
                state,
                str(packet.get("skill_release_id", "")),
                str(packet.get("skill_canary_event_id", "")),
                require_live_canary=True,
            )
            if previous_status == "ready" and previous_schema_version == 5:
                raise HarnessError(
                    "schema-v5 manual dispatch requires a prior packet-arm; "
                    "ready-to-dispatched registration is not allowed"
                )
        if previous_status in TERMINAL_PACKET_STATUSES:
            raise HarnessError(f"packet {args.packet_id} is already terminal")
        allowed_transitions = {
            "ready": {"dispatched", "cancelled"},
            "armed": {"dispatched", "cancelled"},
            "dispatched": {"dispatched", "done", "failed", "cancelled"},
        }
        if args.status not in allowed_transitions.get(str(previous_status), set()):
            raise HarnessError(
                f"invalid packet transition {previous_status!r} -> {args.status!r}"
            )
        existing_agent_value = packet.get("agent_id", "")
        existing_agent = (
            existing_agent_value if isinstance(existing_agent_value, str) else ""
        )
        existing_agent_is_canonical = bool(AGENT_ID_RE.fullmatch(existing_agent))
        transport_owned = (
            packet.get("dispatch_provenance")
            == packet_integrity_impl.CODEX_TRANSPORT_DISPATCH_PROVENANCE
        )
        if transport_owned and args.status in TERMINAL_PACKET_STATUSES:
            # A transport-owned packet remains exclusively owned until its
            # exact launch reaches a terminal runtime state.  A generic packet
            # update cannot cancel/rebind a live App Server launch behind the
            # controller's back.
            from . import codex_transport_contracts as codex_contracts
            from . import codex_transport_projection as codex_projection

            try:
                ownership = codex_contracts.validate_packet_transport_ownership(
                    packet.get("transport_ownership")
                )
                namespace = (
                    codex_projection.codex_transport_namespace_from_projection(
                        state
                    )
                )
                launch_row = namespace["launches"].get(ownership["launch_id"])
            except (
                codex_contracts.CodexTransportContractError,
                codex_projection.CodexTransportProjectionError,
                KeyError,
                TypeError,
            ) as exc:
                raise HarnessError(
                    f"Codex transport packet ownership cannot be authenticated: {exc}"
                ) from exc
            if not isinstance(launch_row, dict) or launch_row.get("state") not in {
                "completed",
                "failed",
                "interrupted",
                "launch_unknown",
                "runtime_unknown",
            }:
                raise HarnessError(
                    "Codex transport-owned packet cannot become terminal while "
                    "its launch is nonterminal; interrupt or reconcile the exact "
                    "bridge launch first"
                )
            _require_codex_transport_packet_terminal_status(
                str(launch_row["state"]), args.status
            )
        if transport_owned and supplied_agent:
            raise HarnessError(
                "Codex transport-owned packet cannot fabricate a SubagentStart agent id"
            )
        if transport_owned and args.status == "dispatched":
            raise HarnessError(
                "Codex transport-owned packet lifecycle is controlled by its exact bridge launch"
            )
        if (
            existing_agent
            and supplied_agent
            and existing_agent != supplied_agent
            and (existing_agent_is_canonical or previous_status == "dispatched")
        ):
            raise HarnessError("packet agent id is immutable after dispatch")
        reusable_existing_agent = (
            existing_agent
            if existing_agent_is_canonical or previous_status == "dispatched"
            else ""
        )
        agent_id = reusable_existing_agent or supplied_agent
        if args.status == "dispatched" and not agent_id and not transport_owned:
            raise HarnessError("dispatched packet requires --agent-id")
        if previous_status == "dispatched" and not agent_id and not transport_owned:
            raise HarnessError("terminal packet transition requires the dispatched agent id")
        actual_pair = bool(args.actual_role) or bool(args.actual_model_tier)
        if actual_pair and not (args.actual_role and args.actual_model_tier):
            raise HarnessError("actual role and model tier must be recorded together")
        if actual_pair and not args.routing_evidence:
            raise HarnessError("actual routing verification requires --routing-evidence")
        if args.routing_evidence and not actual_pair:
            raise HarnessError("--routing-evidence requires actual role and model tier")
        routing_evidence = (
            require_evidence_detail(args.routing_evidence, "routing evidence")
            if args.routing_evidence
            else ""
        )
        if args.actual_role and args.actual_role != packet.get("agent_role"):
            raise HarnessError(
                f"actual role {args.actual_role} differs from requested {packet.get('agent_role')}"
            )
        if args.actual_model_tier and args.actual_model_tier != packet.get("model_tier"):
            raise HarnessError(
                "actual model tier differs from requested tier; do not claim routing verification"
            )
        typed_outcome = getattr(args, "typed_outcome", None)
        if typed_outcome and args.status not in TERMINAL_PACKET_STATUSES:
            raise HarnessError(
                "typed outcome is only recordable on a terminal packet transition"
            )
        if typed_outcome and typed_outcome not in PACKET_TYPED_OUTCOMES_BY_STATUS.get(
            args.status, set()
        ):
            allowed = ", ".join(
                sorted(PACKET_TYPED_OUTCOMES_BY_STATUS.get(args.status, set()))
            )
            raise HarnessError(
                f"typed outcome {typed_outcome!r} is not valid for status "
                f"{args.status!r}; allowed: {allowed}"
            )
        if args.status == "done":
            authority_errors = packet_authority_integrity_errors(
                paths, state, packet, require_origin=False
            )
            if authority_errors:
                raise HarnessError(
                    "done packet authority is missing or tampered: "
                    + "; ".join(authority_errors)
                )
        if (
            args.status in TERMINAL_PACKET_STATUSES
            and int(packet.get("delegation_depth", 1)) == 1
        ):
            active_children = [
                str(item.get("packet_id", ""))
                for item in state.get("packets", [])
                if item.get("parent_packet_id") == args.packet_id
                and item.get("status") in EXECUTING_PACKET_STATUSES
            ]
            active_owned_jobs = [
                str(item.get("run_id", ""))
                for item in state.get("jobs", [])
                if item.get("owner_packet_id") == args.packet_id
                and item.get("status") in ACTIVE_JOB_STATUSES
            ]
            if active_children or active_owned_jobs:
                raise HarnessError(
                    "depth-one packet cannot become terminal while child work is active: "
                    + ", ".join(
                        active_children
                        + [f"job:{run_id}" for run_id in active_owned_jobs]
                    )
                )
        if args.status in TERMINAL_PACKET_STATUSES:
            summary = require_text(args.summary or "", "terminal packet summary")
            if args.status in {"done", "failed"} and not args.evidence:
                raise HarnessError("done/failed packet requires at least one --evidence")
            terminal_evidence = [
                require_evidence_detail(item, "terminal packet evidence")
                for item in args.evidence
            ]
            if args.status in {"done", "failed"}:
                gate_error = packet_integrity_impl.packet_evidence_self_reference_error(
                    args.packet_id,
                    terminal_evidence,
                    task_dir(paths, args.task),
                )
                if gate_error:
                    raise HarnessError(gate_error)
        elif args.summary or args.evidence:
            raise HarnessError("summary/evidence are accepted only for terminal packet status")

        packet["status"] = args.status
        packet["updated_at"] = now_iso()
        if args.status == "dispatched" and previous_status in {"ready", "armed"}:
            reason = args.manual_unverified_reason or (
                "Manual CLI registration; agent start timing was not observed by AOI."
            )
            packet["dispatch_provenance"] = "manual_unverified"
            packet["dispatch_recorded_at"] = packet["updated_at"]
            packet["manual_unverified_reason"] = require_evidence_detail(
                reason, "manual dispatch reason"
            )
            if previous_status == "ready" and previous_schema_version == 4:
                packet["legacy_manual_dispatch_migration"] = True
            if previous_status == "armed":
                attempt = _active_dispatch_attempt(packet)
                attempt["status"] = "disarmed"
                attempt["closed_at"] = packet["updated_at"]
                attempt["reason"] = packet["manual_unverified_reason"]
        elif args.status == "cancelled" and previous_status == "armed":
            attempt = _active_dispatch_attempt(packet)
            attempt["status"] = "disarmed"
            attempt["closed_at"] = packet["updated_at"]
            attempt["reason"] = "Packet was cancelled before observed dispatch."
        if (
            args.status in TERMINAL_PACKET_STATUSES
            and _packet_schema_version(packet) is not None
            and cast(int, _packet_schema_version(packet)) < 5
            and not packet.get("dispatch_provenance")
        ):
            packet["dispatch_provenance"] = "legacy_unverified"
        if supplied_agent:
            packet["agent_id"] = agent_id
        if (
            args.status == "dispatched"
            and int(packet.get("delegation_depth", 1)) == 1
        ):
            ensure_subagent_parent_mapping_unlocked(paths, state, packet)
        if args.actual_role:
            packet["actual_role"] = args.actual_role
        if args.actual_model_tier:
            packet["actual_model_tier"] = args.actual_model_tier
        if routing_evidence:
            packet["routing_evidence"] = routing_evidence
        if args.actual_role or args.actual_model_tier or args.routing_evidence:
            # Operator statements stay recorded, but only as an explicit claim:
            # they can never flip routing_verified on their own.
            packet["routing_claim"] = {
                "actual_role": str(args.actual_role or packet.get("actual_role") or ""),
                "actual_model_tier": str(
                    args.actual_model_tier or packet.get("actual_model_tier") or ""
                ),
                "evidence": str(packet.get("routing_evidence") or ""),
                "provenance": "cli_claimed",
                "recorded_at": packet["updated_at"],
            }
        packet["routing_verified"] = _derived_routing_verified(state, packet)
        if args.status in TERMINAL_PACKET_STATUSES:
            # Typed technical outcome: explicit when supplied, "cancelled" as a
            # safe default for cancellations, otherwise "unclassified" — which
            # is never model-quality eligible. Transport status alone must not
            # be readable as a model verdict.
            if typed_outcome:
                packet["typed_outcome"] = typed_outcome
                packet["typed_outcome_provenance"] = "operator_declared"
            elif args.status == "cancelled":
                packet["typed_outcome"] = "cancelled"
                packet["typed_outcome_provenance"] = "derived_from_status"
            else:
                packet["typed_outcome"] = "unclassified"
                packet["typed_outcome_provenance"] = "unclassified"
            result = task_dir(paths, args.task) / "results" / f"{args.packet_id}.md"
            result_text = (
                f"# Sub-agent result — {args.packet_id}\n\n"
                f"- Status: `{args.status}`\n"
                f"- Typed outcome: `{packet['typed_outcome']}` "
                f"(`{packet['typed_outcome_provenance']}`)\n"
                f"- Requested role/tier: `{packet.get('agent_role')}` / "
                f"`{packet.get('model_tier')}`\n"
                f"- Actual role/tier (operator claim): `{packet.get('actual_role') or 'unverified'}` / "
                f"`{packet.get('actual_model_tier') or 'unverified'}`\n"
                f"- Hook-observed model: `{_hook_observed_routing_model(packet) or 'not exposed by transport'}`\n"
                f"- Routing verified (hook-observed vs applied binding): "
                f"`{str(packet['routing_verified']).lower()}`\n\n"
                f"- Routing evidence (operator claim, never verification): "
                f"{packet.get('routing_evidence') or 'Not exposed by platform.'}\n\n"
                f"- Dispatch provenance: `{packet.get('dispatch_provenance') or 'legacy_unverified'}`\n\n"
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
            if args.status in {"done", "failed"}:
                packet["evidence_gate_version"] = 1
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
        if packet.get("status") == "done":
            authority_errors = packet_authority_integrity_errors(
                paths,
                state,
                packet,
                require_origin=False,
            )
            if authority_errors:
                raise HarnessError(
                    "done packet authority is missing or tampered: "
                    + "; ".join(authority_errors)
                )
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
    return job_integrity_impl._job_launch_authority_record(
        job, selection, skill_binding
    )


def _job_launch_authority_errors(
    state: dict[str, Any], job: dict[str, Any]
) -> list[str]:
    return job_integrity_impl._job_launch_authority_errors(
        state, job, services=_job_integrity_services()
    )


def cmd_job_start(args: argparse.Namespace, paths: HarnessPaths) -> int:
    run_id = validate_id(args.run_id, "run id")
    work_root = require_absolute_posix(args.work_root, "work root")
    log = require_absolute_posix(args.log, "log")
    source_manifest = require_absolute_local_path(args.source_manifest, "source manifest")
    tool_path = require_absolute_posix(args.tool_path, "tool path")
    source_sha = require_text(args.source_sha, "source SHA-256").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", source_sha):
        raise HarnessError("--source-sha must be the 64-hex SHA-256 of the source manifest")
    if args.status != "queued":
        raise HarnessError("job-start must record status queued before any launch")
    tool_version = require_text(args.tool_version, "tool version")
    command = require_text(args.command, "command")
    registered_at = now_iso()
    observed_start_at: str | None = None
    registration_lag_seconds: float | None = None
    retroactive_reason: str | None = None
    if args.observed_start_at:
        observed_dt = parse_tz_aware_time(args.observed_start_at)
        if observed_dt is None:
            raise HarnessError(
                "--observed-start-at must be a timezone-aware ISO-8601 timestamp"
            )
        registered_dt = parse_tz_aware_time(registered_at)
        assert registered_dt is not None  # now_iso() is always tz-aware
        registration_lag_seconds = (registered_dt - observed_dt).total_seconds()
        lag_limit = job_integrity_impl.JOB_REGISTRATION_LAG_LIMIT_SECONDS
        if registration_lag_seconds < 0:
            raise HarnessError(
                "--observed-start-at is in the future relative to job registration; "
                "an observed launch cannot post-date its own registration"
            )
        if registration_lag_seconds > lag_limit and not (
            args.retroactive_reason or ""
        ).strip():
            raise HarnessError(
                f"a job registered more than {lag_limit}s after its observed "
                "start is retroactive; supply --retroactive-reason to account "
                "for the inversion"
            )
        observed_start_at = observed_dt.isoformat()
        if args.retroactive_reason:
            retroactive_reason = require_evidence_detail(
                args.retroactive_reason, "retroactive reason"
            )
    elif args.retroactive_reason:
        raise HarnessError("--retroactive-reason requires --observed-start-at")
    _, source_receipt_data = validate_source_receipt(
        source_manifest,
        source_sha,
        tool_path=tool_path,
        tool_version=tool_version,
        command=command,
    )
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "start job for")
        if state.get("profile") == "mini":
            raise HarnessError("mini task may not launch or register external jobs")
        require_plan_ready(paths, state, "start external job")
        _adopt_execution_policy_v2_for_new_work(state)
        if args.lane_id:
            lane_by_id(state, args.lane_id)
        selection = _validate_active_execution_selection(
            state, args.lane_id or "", args.execution_selection_id or ""
        )
        if selection is not None:
            frozen_by = _selection_synthesis_freeze_packet_ids(
                state, str(selection.get("selection_id", ""))
            )
            if frozen_by:
                raise HarnessError(
                    "external job creation is frozen after Steward synthesis begins: "
                    + ", ".join(frozen_by)
                )
        active_synthesis_packets = [
            str(packet.get("packet_id", ""))
            for packet in state.get("packets", [])
            if _is_steward_synthesis_packet(packet)
            and packet.get("status") in EXECUTING_PACKET_STATUSES
        ]
        if active_synthesis_packets:
            raise HarnessError(
                "external job cannot start during the sequential Steward synthesis phase: "
                + ", ".join(active_synthesis_packets)
            )
        owner_packet = (
            _packet_by_id(state, args.owner_packet_id)
            if args.owner_packet_id
            else None
        )
        namespace = paths.project.external_lock_namespace
        required_output_locks = [
            f"{namespace}:tree:{work_root}",
            f"{namespace}:file:{log}",
        ]
        command_authority_sha = hashlib.sha256(command.encode("utf-8")).hexdigest()
        _validate_job_activation_topology(
            state,
            {
                "run_id": run_id,
                "lane_id": args.lane_id or "",
                "execution_selection_id": selection.get("selection_id", "")
                if selection
                else "",
                "owner_packet_id": args.owner_packet_id or "",
                "owner_packet_contract_sha256": (
                    owner_packet.get("packet_contract_sha256", "")
                    if owner_packet is not None
                    else ""
                ),
                "external_lock_namespace": namespace,
                "required_output_locks": required_output_locks,
                "work_root": work_root,
                "log": log,
                "command_sha256": command_authority_sha,
            },
            selection,
            paths=paths,
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
        unowned = [
            lock
            for lock in required_output_locks
            if not any(lock_covers(held, lock) for held in held_locks)
        ]
        if unowned:
            raise HarnessError(
                "external job output paths are not covered by this task's claims: "
                + ", ".join(unowned)
            )
        receipt_snapshot = (
            task_dir(paths, args.task) / "results" / f"source-receipt-{run_id}.json"
        )
        atomic_write_bytes(receipt_snapshot, source_receipt_data)
        if sha256_file(receipt_snapshot) != source_sha:
            raise HarnessError("source receipt snapshot SHA-256 changed during copy")
        command_snapshot = (
            task_dir(paths, args.task) / "results" / f"job-command-{run_id}.txt"
        )
        atomic_write_text(command_snapshot, command)
        os.chmod(command_snapshot, 0o600)
        command_sha = sha256_file(command_snapshot)
        if command_sha != command_authority_sha:
            raise HarnessError("external job command snapshot changed during copy")
        job = {
            "integrity_version": 1,
            "job_schema_version": 2,
            "task_execution_policy_version": EXECUTION_POLICY_VERSION,
            "launch_authority_version": 1,
            "launch_authority_events": [],
            "run_id": run_id,
            "lane_id": args.lane_id or "",
            "execution_selection_id": selection.get("selection_id", "")
            if selection
            else "",
            "owner_packet_id": args.owner_packet_id or "",
            "owner_packet_contract_sha256": (
                owner_packet.get("packet_contract_sha256", "")
                if owner_packet is not None
                else ""
            ),
            "external_lock_namespace": namespace,
            "required_output_locks": required_output_locks,
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
            "source_manifest": str(source_manifest),
            "source_receipt_path": str(receipt_snapshot),
            "tool_path": tool_path,
            "tool_version": tool_version,
            "command": command,
            "command_path": str(command_snapshot),
            "command_sha256": command_sha,
            "command_size_bytes": command_snapshot.stat().st_size,
            "success_exit_code": args.success_exit_code,
            "evidence": "queued before launch" if args.status == "queued" else "launch recorded",
            "registered_at": registered_at,
            "started_at": now_iso(),
            "updated_at": now_iso(),
        }
        if observed_start_at is not None:
            job["observed_start_at"] = observed_start_at
            job["registration_lag_seconds"] = registration_lag_seconds
            if retroactive_reason is not None:
                job["retroactive_reason"] = retroactive_reason
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
            _validate_job_activation_topology(
                state,
                job,
                selection,
                paths=paths,
                exclude_run_id=str(job.get("run_id", "")),
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


def prepare_delivery(
    paths: HarnessPaths,
    state: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Validate one delivery record without mutating AOI state."""

    detail = require_text(args.detail, "delivery detail")
    commit = args.commit or ""
    if args.mode == "pushed":
        confidentiality_impl.require_publication_action_allowed(
            paths.project.confidentiality,
            "git_push",
        )
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
    return {
        "mode": args.mode,
        "detail": detail,
        "commit": commit,
        "remote": args.remote or "",
        "remote_ref": args.remote_ref or "",
        "remote_sha": commit if args.mode == "pushed" else "",
        "verified_at": now_iso() if args.mode == "pushed" else "",
    }


def cmd_set_delivery(
    args: argparse.Namespace,
    paths: HarnessPaths,
    *,
    emit_result: bool = True,
) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "set delivery for")
        state["delivery"] = prepare_delivery(paths, state, args)
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    if emit_result:
        emit(state["delivery"], args.json)
    return 0


_INTEGRITY_ARTIFACT_FIELDS: tuple[tuple[str, str], ...] = (
    ("snapshots", "artifact"),
    ("review_results", "result_artifact"),
    ("fixes", "fix_artifact"),
    ("review_verifications", "verification_artifact"),
)


def _integrity_contract_required(paths: HarnessPaths, state: dict[str, Any]) -> bool:
    """Return whether this task has crossed the required-v1 integrity boundary."""

    del paths
    return "integrity_contract" in state


def _integrity_runtime_errors_v1(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    require_current_snapshot: bool,
    require_complete: bool = True,
) -> list[str]:
    """Validate persisted O8 evidence and, at a close boundary, live Git bytes.

    Historical terminal state deliberately does not recapture the worktree: a
    later task is allowed to change it.  A close attempt and an active sealed
    task, however, must still reproduce the exact sealed candidate bytes.
    """

    task_id = str(state.get("task_id", ""))
    required = _integrity_contract_required(paths, state)
    contract = state.get("integrity_contract")
    if not isinstance(contract, dict):
        return ["required integrity_contract is missing"] if required else []

    errors = integrity_records_impl.integrity_contract_errors(
        contract,
        task_id=task_id,
        worktree=state.get("worktree"),
        require_complete=require_complete,
    )
    if errors:
        return [f"integrity contract: {error}" for error in errors]

    try:
        for collection, field in _INTEGRITY_ARTIFACT_FIELDS:
            for index, record in enumerate(contract[collection], start=1):
                evidence_artifacts_impl.verify_generated_artifact_blob(
                    paths,
                    task_id,
                    record[field],
                    label=f"integrity {collection} record {index} {field}",
                    max_bytes=integrity_records_impl.MAX_INTEGRITY_ARTIFACT_BYTES,
                )

        claims = load_all_claims(paths)
        sealed = contract.get("seal") is not None
        for index, record in enumerate(contract["snapshots"], start=1):
            snapshot_bytes = evidence_artifacts_impl.verify_generated_artifact_blob(
                paths,
                task_id,
                record["artifact"],
                label=f"integrity snapshots record {index} artifact",
                max_bytes=integrity_records_impl.MAX_INTEGRITY_ARTIFACT_BYTES,
            )
            snapshot = json.loads(snapshot_bytes.decode("utf-8"))
            if snapshot_bytes != canonical_json_bytes(
                snapshot,
                max_bytes=integrity_records_impl.MAX_INTEGRITY_ARTIFACT_BYTES,
            ):
                raise HarnessError(f"integrity snapshot record {index} artifact is not canonical JSON")
            snapshot_task_id, _mutation_paths = validate_task_mutation_snapshot(snapshot)
            if snapshot_task_id != task_id or snapshot.get("task_id") != record["task_id"]:
                raise HarnessError(f"integrity snapshot record {index} task binding differs from its artifact")
            if snapshot.get("worktree") != record["worktree"] or record["worktree"] != state.get("worktree"):
                raise HarnessError(f"integrity snapshot record {index} worktree binding differs from its artifact")
            if (
                snapshot.get("baseline_head") != record["baseline_head"]
                or record["baseline_head"] != contract["baseline_head"]
            ):
                raise HarnessError(f"integrity snapshot record {index} baseline binding differs from its artifact")
            if snapshot.get("current_head") != record["current_head"]:
                raise HarnessError(f"integrity snapshot record {index} current-head binding differs from its artifact")
            if snapshot.get("snapshot_sha256") != record["snapshot_sha256"]:
                raise HarnessError(f"integrity snapshot record {index} digest differs from its artifact")
            validate_task_mutation_snapshot_claim_scope(
                snapshot,
                record["covered_claim_tokens"],
                record["claim_scope_sha256"],
                claims,
                sealed=sealed,
            )

        candidates = [
            record for record in contract["snapshots"]
            if record.get("purpose") == "candidate"
        ]
        if not candidates:
            return []
        candidate = candidates[-1]
        candidate_bytes = evidence_artifacts_impl.verify_generated_artifact_blob(
            paths,
            task_id,
            candidate["artifact"],
            label="latest integrity candidate snapshot",
            max_bytes=integrity_records_impl.MAX_INTEGRITY_ARTIFACT_BYTES,
        )
        candidate_snapshot = json.loads(candidate_bytes.decode("utf-8"))
        if candidate_bytes != canonical_json_bytes(
            candidate_snapshot,
            max_bytes=integrity_records_impl.MAX_INTEGRITY_ARTIFACT_BYTES,
        ):
            raise HarnessError("latest candidate artifact is not canonical JSON")
        validate_task_mutation_snapshot(candidate_snapshot)

        if require_current_snapshot:
            current = task_mutation_snapshot(
                task_id,
                state_worktree(paths, state),
                str(contract["baseline_head"]),
            )
            current_bytes = canonical_json_bytes(
                current,
                max_bytes=integrity_records_impl.MAX_INTEGRITY_ARTIFACT_BYTES,
            )
            if current_bytes != candidate_bytes:
                raise HarnessError(
                    "latest candidate integrity snapshot is not byte-identical to current Git task mutation snapshot"
                )
    except (
        HarnessError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        OSError,
        SemanticEventError,
    ) as exc:
        return [f"integrity runtime: {exc}"]
    return []


def _integrity_v2_record_artifact_fields(record: dict[str, Any]) -> tuple[str, ...]:
    """Return the immutable artifact references carried by one v2 record."""

    record_type = record.get("record_type")
    if not isinstance(record_type, str):
        return ()
    artifact_fields: dict[str, tuple[str, ...]] = {
        "snapshot": ("artifact",),
        "review_result": ("result_artifact",),
        "fix": ("fix_artifact",),
        "review_verification": ("verification_artifact",),
    }
    return artifact_fields.get(record_type, ())


def _integrity_runtime_errors_v2(
    paths: HarnessPaths,
    state: dict[str, Any],
    contract: dict[str, Any],
    *,
    require_current_snapshot: bool,
    require_complete: bool,
) -> list[str]:
    """Verify v2's ordered graph, CAS references, and sealed live target.

    Unlike v1, a v2 draft deliberately has no implicit ``candidate`` target:
    only a sealed contract selects a snapshot whose bytes must still match the
    worktree.  This prevents an earlier same-content candidate from becoming a
    misleading terminal anchor.
    """

    task_id = str(state.get("task_id", ""))
    try:
        source_v1_contract: dict[str, Any] | None = None
        receipt = contract.get("migration_receipt")
        if receipt is not None:
            if not isinstance(receipt, dict):
                raise HarnessError("integrity v2 migration receipt is not an object")
            source_artifact = receipt.get("source_contract_artifact")
            if not isinstance(source_artifact, dict):
                raise HarnessError("integrity v2 migration receipt has no source v1 contract artifact")
            source_bytes = evidence_artifacts_impl.verify_generated_artifact_blob(
                paths,
                task_id,
                source_artifact,
                label="integrity v2 migration source v1 contract",
                max_bytes=integrity_records_v2_impl.MAX_INTEGRITY_MIGRATION_SOURCE_BYTES,
            )
            source = json.loads(source_bytes.decode("utf-8"))
            if not isinstance(source, dict) or source_bytes != canonical_json_bytes(
                source,
                max_bytes=integrity_records_v2_impl.MAX_INTEGRITY_MIGRATION_SOURCE_BYTES,
            ):
                raise HarnessError("integrity v2 migration source v1 contract is not canonical JSON")
            source_digest = hashlib.sha256(source_bytes).hexdigest()
            if source_artifact.get("sha256") != source_digest or source_artifact.get("size_bytes") != len(source_bytes):
                raise HarnessError("integrity v2 migration source v1 CAS reference differs from canonical bytes")
            source_errors = integrity_records_impl.integrity_contract_errors(
                source,
                task_id=task_id,
                worktree=state.get("worktree"),
                require_complete=False,
            )
            if source_errors:
                raise HarnessError("integrity v2 migration source v1 contract invalid: " + "; ".join(source_errors))
            source_v1_contract = source

        errors = integrity_records_v2_impl.integrity_contract_errors(
            contract,
            task_id=task_id,
            worktree=state.get("worktree"),
            require_complete=require_complete,
            source_v1_contract=source_v1_contract,
        )
        if errors:
            return [f"integrity contract: {error}" for error in errors]

        effective_records = (
            integrity_records_v2_impl.materialize_effective_integrity_records(
                contract, source_v1_contract
            )
            if source_v1_contract is not None
            else contract.get("records")
        )
        if not isinstance(effective_records, list):
            return ["integrity contract: v2 records collection is missing"]
        claims = load_all_claims(paths)
        snapshots_by_sha: dict[str, tuple[dict[str, Any], bytes]] = {}
        sealed = contract.get("seal") is not None
        for index, raw_record in enumerate(effective_records, start=1):
            if not isinstance(raw_record, dict):
                raise HarnessError(f"integrity v2 record {index} is not an object")
            record = raw_record
            for field in _integrity_v2_record_artifact_fields(record):
                value = record.get(field)
                if not isinstance(value, dict):
                    raise HarnessError(f"integrity v2 record {index} {field} is missing")
                evidence_artifacts_impl.verify_generated_artifact_blob(
                    paths,
                    task_id,
                    value,
                    label=f"integrity v2 record {index} {field}",
                    max_bytes=integrity_records_v2_impl.MAX_INTEGRITY_ARTIFACT_BYTES,
                )
            if record.get("record_type") != "snapshot":
                continue
            snapshot_bytes = evidence_artifacts_impl.verify_generated_artifact_blob(
                paths,
                task_id,
                record["artifact"],
                label=f"integrity v2 snapshot record {index} artifact",
                max_bytes=integrity_records_v2_impl.MAX_INTEGRITY_ARTIFACT_BYTES,
            )
            snapshot = json.loads(snapshot_bytes.decode("utf-8"))
            if snapshot_bytes != canonical_json_bytes(
                snapshot,
                max_bytes=integrity_records_v2_impl.MAX_INTEGRITY_ARTIFACT_BYTES,
            ):
                raise HarnessError(f"integrity v2 snapshot record {index} artifact is not canonical JSON")
            snapshot_task_id, _mutation_paths = validate_task_mutation_snapshot(snapshot)
            if snapshot_task_id != task_id or snapshot.get("task_id") != record.get("task_id"):
                raise HarnessError(f"integrity v2 snapshot record {index} task binding differs from its artifact")
            if snapshot.get("worktree") != record.get("worktree") or record.get("worktree") != state.get("worktree"):
                raise HarnessError(f"integrity v2 snapshot record {index} worktree binding differs from its artifact")
            if snapshot.get("baseline_head") != record.get("baseline_head") or record.get("baseline_head") != contract.get("baseline_head"):
                raise HarnessError(f"integrity v2 snapshot record {index} baseline binding differs from its artifact")
            if snapshot.get("current_head") != record.get("current_head"):
                raise HarnessError(f"integrity v2 snapshot record {index} current-head binding differs from its artifact")
            if snapshot.get("snapshot_sha256") != record.get("snapshot_sha256"):
                raise HarnessError(f"integrity v2 snapshot record {index} digest differs from its artifact")
            validate_task_mutation_snapshot_claim_scope(
                snapshot,
                record["covered_claim_tokens"],
                record["claim_scope_sha256"],
                claims,
                sealed=sealed,
            )
            record_sha = record.get("record_sha256")
            if not isinstance(record_sha, str):
                raise HarnessError(f"integrity v2 snapshot record {index} has no record SHA-256")
            snapshots_by_sha[record_sha] = (record, snapshot_bytes)

        if require_current_snapshot and sealed:
            seal = contract.get("seal")
            if not isinstance(seal, dict):
                raise HarnessError("integrity v2 seal is not an object")
            target_sha = seal.get("terminal_snapshot_record_sha256")
            target = snapshots_by_sha.get(target_sha) if isinstance(target_sha, str) else None
            if target is None:
                raise HarnessError("integrity v2 seal terminal snapshot record is unavailable")
            _target_record, target_bytes = target
            current = task_mutation_snapshot(
                task_id,
                state_worktree(paths, state),
                str(contract["baseline_head"]),
            )
            current_bytes = canonical_json_bytes(
                current,
                max_bytes=integrity_records_v2_impl.MAX_INTEGRITY_ARTIFACT_BYTES,
            )
            if current_bytes != target_bytes:
                raise HarnessError(
                    "sealed integrity v2 terminal snapshot is not byte-identical to current Git task mutation snapshot"
                )
    except (
        HarnessError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        OSError,
        SemanticEventError,
        integrity_records_v2_impl.IntegrityRecordError,
    ) as exc:
        return [f"integrity runtime: {exc}"]
    return []


def _integrity_runtime_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    require_current_snapshot: bool,
    require_complete: bool = True,
) -> list[str]:
    """Dispatch an integrity contract by its exact frozen schema header."""

    required = _integrity_contract_required(paths, state)
    contract = state.get("integrity_contract")
    if not isinstance(contract, dict):
        return ["required integrity_contract is missing"] if required else []
    header = (contract.get("schema_version"), contract.get("mode"))
    if header == (
        integrity_records_impl.INTEGRITY_CONTRACT_SCHEMA_VERSION,
        integrity_records_impl.INTEGRITY_CONTRACT_MODE,
    ):
        return _integrity_runtime_errors_v1(
            paths,
            state,
            require_current_snapshot=require_current_snapshot,
            require_complete=require_complete,
        )
    if header == (
        integrity_records_v2_impl.INTEGRITY_CONTRACT_SCHEMA_VERSION,
        integrity_records_v2_impl.INTEGRITY_CONTRACT_MODE,
    ):
        return _integrity_runtime_errors_v2(
            paths,
            state,
            contract,
            require_current_snapshot=require_current_snapshot,
            require_complete=require_complete,
        )
    return ["task integrity contract header invalid"]


def close_gate(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    intended_outcome: str = "achieved",
    preparing_mini: bool = False,
) -> list[str]:
    failures: list[str] = []
    failures.extend(_integrity_runtime_errors(paths, state, require_current_snapshot=True))
    if not state.get("completion_boundary"):
        failures.append("completion boundary is empty")
    checkpoint_ok, checkpoint_reason = checkpoint_matches(paths, state)
    if not checkpoint_ok and not preparing_mini:
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
    if nonterminal and not preparing_mini:
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
    failures.extend(subagent_incident_integrity_errors(state))
    failures.extend(packet_recovery_integrity_errors(paths, state))
    failures.extend(job_integrity_errors(paths, state))
    failures.extend(verification_integrity_errors(paths, state))
    _provider_reports, provider_errors, _provider_warnings = context_receipt_reports(
        paths, state, evaluate_live=True
    )
    failures.extend(provider_errors)
    failures.extend(context_benchmark_integrity_errors(paths, state))
    failures.extend(routing_verification_integrity_errors(state))
    failures.extend(portfolio_integrity_errors(state, paths))
    failures.extend(override_integrity_errors(state))
    failures.extend(resource_config_integrity_errors(paths, state))
    failures.extend(resource_envelope_integrity_errors(state))
    failures.extend(
        f"semantic authority: {error}"
        for error in semantic_store_impl.semantic_integrity_errors(
            paths,
            str(state.get("task_id", "")),
            require_current_projection=True,
        )
    )
    for selection in state.get("execution_selections", []):
        if selection.get("mode") not in {"centralized_parallel", "hybrid"}:
            continue
        brief_error = _execution_brief_coverage_error(paths, state, selection)
        if brief_error:
            failures.append(brief_error)
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
    open_overrides = [
        str(item.get("override_id"))
        for item in state.get("override_requests", [])
        if item.get("status") in {"awaiting_chief", "approved"}
    ]
    if open_overrides:
        failures.append(
            "unresolved or unconsumed Chief overrides: " + ", ".join(open_overrides)
        )
    open_spawn_incidents = [
        str(item.get("incident_id"))
        for item in _object_records_for_derivation(state, "subagent_incidents")
        if item.get("status") == "open"
    ]
    if open_spawn_incidents:
        failures.append(
            "unaccounted sub-agent spawn incidents: "
            + ", ".join(open_spawn_incidents)
        )
    worktree_errors, _ = worktree_integrity_errors(paths, state)
    failures.extend(worktree_errors)
    raw_verification = state.get("verification", [])
    verification = _object_records_for_derivation(state, "verification")
    verification_shape_valid = isinstance(raw_verification, list) and len(
        verification
    ) == len(raw_verification)
    if intended_outcome == "achieved" and verification_shape_valid:
        if not verification:
            failures.append("no verification/evidence record")
        if not any(
            item.get("integrity_version") == 1
            and item.get("status") == "pass"
            and item.get("category") in CLOSE_QUALIFYING_CATEGORIES
            for item in verification
        ):
            failures.append(
                "achieved outcome requires at least one passing, close-qualifying verification"
            )
        current_boundary_sha256 = hashlib.sha256(
            str(state.get("completion_boundary", "")).encode("utf-8")
        ).hexdigest()
        if verification and not any(
            item.get("integrity_version") == 1
            and item.get("status") == "pass"
            and item.get("category") in CLOSE_QUALIFYING_CATEGORIES
            and item.get("asserts_completion_boundary") is True
            and item.get("completion_boundary_sha256") == current_boundary_sha256
            for item in verification
        ):
            # An achieved close must bind at least one passing verification to
            # the exact registered completion boundary. Observed on ARISE: a
            # task closed outcome=achieved while all 23 verification boundaries
            # explicitly excluded the completion boundary's own claim, and the
            # gate was satisfied by an unrelated bootstrap delivery_check. The
            # SHA binding additionally prevents an assertion recorded against a
            # superseded boundary from surviving a retarget.
            failures.append(
                "achieved outcome requires a passing, close-qualifying "
                "verification recorded with --asserts-completion-boundary "
                "against the CURRENT registered completion boundary"
            )
    unaccounted = (
        [
            str(item.get("category"))
            for item in verification
            if item.get("status") not in ACCOUNTED_VERIFICATION_STATUSES
        ]
        if verification_shape_valid
        else []
    )
    if unaccounted:
        failures.append("unaccounted verification: " + ", ".join(unaccounted))
    if not preparing_mini:
        failures.extend(delivery_integrity_errors(paths, state, verify_remote=True))
    return failures


def cmd_close_task(
    args: argparse.Namespace,
    paths: HarnessPaths,
    *,
    emit_result: bool = True,
) -> int:
    outcome = args.outcome
    if outcome != "achieved" and not (args.boundary_disposition or "").strip():
        # A non-achieved close must say where the registered boundary went.
        raise HarnessError(
            f"closing with outcome {outcome!r} requires --boundary-disposition "
            "stating why the registered completion boundary was not met and "
            "where that scope now lives"
        )
    semantic_result: semantic_store_impl.SemanticAppendResult | None = None
    index_warning = ""
    with state_lock(paths):
        state = load_task(paths, args.task)
        semantic_v2 = "_semantic" in state
        semantic_command_id = str(
            getattr(args, "semantic_command_id", "") or ""
        ).strip()
        semantic_expected_head = str(
            getattr(args, "semantic_expected_head_sha256", "") or ""
        ).strip()
        if semantic_v2:
            validate_id(semantic_command_id, "semantic command id")
            if not re.fullmatch(r"[0-9a-f]{64}", semantic_expected_head):
                raise HarnessError(
                    "semantic-v2 close requires --semantic-expected-head-sha256"
                )
        elif semantic_command_id or semantic_expected_head:
            raise HarnessError(
                "semantic close options require a semantic-v2 task"
            )
        if semantic_v2 and state.get("status") == "done":
            expected_next_action = args.next_action or "No further action; task closed."
            retry_summary = require_text(args.summary, "summary")
            published_summary = semantic_store_impl.published_semantic_close_summary(
                paths,
                str(state["task_id"]),
                command_id=semantic_command_id,
                expected_head_sha256=semantic_expected_head,
            )
            if (
                state.get("outcome") != outcome
                or retry_summary != published_summary
                or state.get("next_action") != expected_next_action
                or str(state.get("boundary_disposition", ""))
                != str((args.boundary_disposition or "").strip())
                or str(state.get("blockers_disposition", ""))
                != str((args.blockers_disposition or "").strip())
            ):
                raise HarnessError(
                    "semantic close retry differs from the published close semantics"
                )
            semantic_result = semantic_store_impl.recover_published_semantic_transition(
                paths,
                str(state["task_id"]),
                state,
                event_type="task_closed",
                command_id=semantic_command_id,
                expected_head_sha256=semantic_expected_head,
            )
            checkpoint = task_dir(paths, args.task) / "checkpoint.md"
            checkpoint_sha256 = str(state.get("checkpoint_sha256", ""))
            if not re.fullmatch(r"[0-9a-f]{64}", checkpoint_sha256):
                raise HarnessError(
                    "semantic close checkpoint digest is invalid"
                )
            checkpoint_current = False
            try:
                checkpoint_current = (
                    checkpoint.is_file()
                    and sha256_file(checkpoint) == checkpoint_sha256
                )
            except OSError:
                checkpoint_current = False
            if not checkpoint_current:
                checkpoint, checkpoint_text, rendered_sha256 = prepare_checkpoint(
                    paths, state
                )
                if rendered_sha256 != checkpoint_sha256:
                    raise HarnessError(
                        "semantic close checkpoint is missing or damaged and the "
                        "installed renderer cannot reproduce its authoritative bytes"
                    )
                atomic_write_text(checkpoint, checkpoint_text)
            unbind_all_sessions_unlocked(paths, state)
            try:
                write_index(paths)
            except HarnessError as exc:
                index_warning = str(exc)
            if emit_result:
                emit(
                    {
                        "task_id": args.task,
                        "status": "done",
                        "checkpoint": str(checkpoint),
                        "semantic_head_sha256": semantic_result.event["event_sha256"],
                        "idempotent_replay": True,
                        "index_warning": index_warning,
                    },
                    args.json,
                )
            return 0
        require_open_task(state, "close")
        if outcome == "achieved" and state.get("blockers"):
            if not (args.blockers_disposition or "").strip():
                raise HarnessError(
                    "closing achieved with recorded blockers requires "
                    "--blockers-disposition accounting for: "
                    + "; ".join(str(item) for item in state.get("blockers", []))
                )
        failures = close_gate(paths, state, intended_outcome=outcome)
        if failures:
            raise HarnessError("close gate failed:\n- " + "\n- ".join(failures))
        state["status"] = "done"
        state["phase"] = "closing"
        state["outcome"] = outcome
        if (args.boundary_disposition or "").strip():
            state["boundary_disposition"] = args.boundary_disposition.strip()
        if (args.blockers_disposition or "").strip():
            state["blockers_disposition"] = args.blockers_disposition.strip()
        state.setdefault("facts", []).append(require_text(args.summary, "summary"))
        state["next_action"] = args.next_action or "No further action; task closed."
        bump_task(state, checkpoint_required=False)
        state["checkpoint_revision"] = state["revision"]
        state["checkpoint_required"] = False
        state["closed_at"] = now_iso()
        _, current = worktree_integrity_errors(paths, state)
        if current:
            state["closed_head_sha"] = current["head_sha"]
        if semantic_v2:
            semantic_store_impl.preflight_semantic_append(
                paths,
                str(state["task_id"]),
                command_id=semantic_command_id,
                expected_head_sha256=semantic_expected_head,
            )
            checkpoint, checkpoint_text, checkpoint_sha256 = prepare_checkpoint(
                paths, state
            )
            state["checkpoint_sha256"] = checkpoint_sha256
            semantic_result = semantic_store_impl.append_semantic_transition(
                paths,
                str(state["task_id"]),
                state,
                event_type="task_closed",
                command_id=semantic_command_id,
                recorded_at=state["closed_at"],
                authority_ref=str(getattr(args, "_aoi_authority_ref", "") or ""),
                expected_head_sha256=semantic_expected_head,
            )
            # The event plus its replayed projection are authoritative; the
            # checkpoint is a derived artifact.  Its bytes/digest are bound in
            # the event state above, but publication must happen afterwards so
            # an event-first interruption leaves the prior checkpoint intact.
            atomic_write_text(checkpoint, checkpoint_text)
        else:
            checkpoint = commit_checkpoint(paths, state)
        unbind_all_sessions_unlocked(paths, state)
        try:
            write_index(paths)
        except HarnessError as exc:
            if not semantic_v2:
                raise
            index_warning = str(exc)
    if emit_result:
        payload = {
            "task_id": args.task,
            "status": "done",
            "checkpoint": str(checkpoint),
        }
        if semantic_result is not None:
            payload.update(
                {
                    "semantic_head_sha256": semantic_result.event["event_sha256"],
                    "idempotent_replay": semantic_result.idempotent_replay,
                    "index_warning": index_warning,
                }
            )
        emit(payload, args.json)
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
        open_user_escalations = [
            str(item.get("escalation_id"))
            for item in state.get("needs_user_escalations", [])
            if item.get("status") == "needs_user"
        ]
        failures = []
        if nonterminal:
            failures.append("non-terminal claims: " + ", ".join(nonterminal))
        if active_jobs:
            failures.append("unresolved jobs: " + ", ".join(active_jobs))
        if active_packets:
            failures.append("unfinished packets: " + ", ".join(active_packets))
        if open_user_escalations:
            failures.append(
                "unresolved needs-user escalations: "
                + ", ".join(open_user_escalations)
            )
        open_overrides = [
            str(item.get("override_id"))
            for item in state.get("override_requests", [])
            if item.get("status") in {"awaiting_chief", "approved"}
        ]
        if open_overrides:
            failures.append(
                "unresolved or unconsumed Chief overrides: "
                + ", ".join(open_overrides)
            )
        open_spawn_incidents = [
            str(item.get("incident_id"))
            for item in _object_records_for_derivation(
                state, "subagent_incidents"
            )
            if item.get("status") == "open"
        ]
        if open_spawn_incidents:
            failures.append(
                "unaccounted sub-agent spawn incidents: "
                + ", ".join(open_spawn_incidents)
            )
        if state.get("delivery", {}).get("mode") == "pending":
            failures.append("delivery disposition is pending")
        failures.extend(
            packet_integrity_errors(
                paths,
                state,
                allow_done_lock_recovery=True,
            )
        )
        failures.extend(subagent_incident_integrity_errors(state))
        failures.extend(packet_recovery_integrity_errors(paths, state))
        failures.extend(job_integrity_errors(paths, state))
        failures.extend(override_integrity_errors(state))
        failures.extend(resource_config_integrity_errors(paths, state))
        failures.extend(resource_envelope_integrity_errors(state))
        worktree_errors, _ = worktree_integrity_errors(paths, state)
        failures.extend(worktree_errors)
        if state.get("changed_files") and not (
            args.changed_files_disposition or ""
        ).strip():
            # Cancelling a task that recorded real mutations must account for
            # them. Observed on ARISE: a cancelled task's delivery detail said
            # "no mutation" while the same state carried three committed
            # changed files in another repository.
            failures.append(
                "recorded changed files require --changed-files-disposition: "
                + ", ".join(str(item) for item in state.get("changed_files", []))
            )
        if failures:
            raise HarnessError("cancel gate failed:\n- " + "\n- ".join(failures))
        if (args.changed_files_disposition or "").strip():
            state["changed_files_disposition"] = args.changed_files_disposition.strip()
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


def cmd_doctor(args: argparse.Namespace, paths: HarnessPaths) -> int:
    preflight_layout(paths)
    errors: list[str] = []
    warnings: list[str] = []
    try:
        require_complete_layout(paths)
    except HarnessError as exc:
        errors.append(str(exc))
    policy_path = paths.harness / "POLICY.md"
    if policy_path.is_file():
        current_policy_sha256 = hashlib.sha256(policy_path.read_bytes()).hexdigest()
        packaged_policy_sha256 = hashlib.sha256(
            _resource_text("policy.md").encode("utf-8")
        ).hexdigest()
        if current_policy_sha256 != packaged_policy_sha256:
            errors.append(
                "managed AOI policy differs from the packaged contract; run "
                "authenticated `aoi init` after reviewing the exact policy digest "
                f"{current_policy_sha256}"
            )
    try:
        authority = chief_authority_summary(paths)
    except HarnessError as exc:
        authority = {"status": "invalid"}
        errors.append(str(exc))
    else:
        if authority["status"] == "uninitialized":
            warnings.append(
                "Chief authority is uninitialized; lifecycle mutations require chief-acquire"
            )
        elif authority["status"] == "inactive":
            warnings.append("Chief authority is inactive; lifecycle mutations are fenced")
        elif authority["expired"]:
            warnings.append(
                "Chief authority is expired; lifecycle mutations require explicit takeover"
            )
    scoped = bool(args.task)
    if scoped:
        try:
            task = load_task(paths, args.task)
            tasks = [task]
        except HarnessError as exc:
            tasks = []
            claims: list[dict[str, Any]] = []
            errors.append(str(exc))
        else:
            try:
                all_claims = load_all_claims(paths)
            except HarnessError as exc:
                claims = []
                errors.append(str(exc))
            else:
                referenced_tokens = {
                    str(token) for token in task.get("claims", [])
                }
                claims = [
                    claim
                    for claim in all_claims
                    if str(claim.get("token", "")) in referenced_tokens
                    or (
                        not claim.get("legacy")
                        and str(claim.get("task_id", "")) == task["task_id"]
                    )
                ]
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
        for item in claim.get("malformed_locks", []):
            message = (
                f"claim {token} carries a malformed lock excluded from "
                f"mutual exclusion: {item.get('lock')} ({item.get('error')})"
            )
            if claim.get("status") in RESERVING_CLAIM_STATUSES:
                # The reservation never actually covered this path (fail-open
                # defect class); release and re-acquire the corrected lock.
                errors.append(message)
            else:
                warnings.append(message)
        if claim.get("legacy") and claim.get("scope_parse_warnings"):
            warnings.append(f"legacy scope needs audit: {token}")
        try:
            validate_claim_lock_identities(paths, claim)
        except HarnessError as exc:
            message = f"claim {token} lock authority: {exc}"
            if claim.get("status") in RESERVING_CLAIM_STATUSES:
                errors.append(message)
            else:
                warnings.append(message)
        if not claim.get("legacy"):
            task_id = str(claim.get("task_id", ""))
            structured_by_task.setdefault(task_id, set()).add(token)

    task_ids = {task["task_id"] for task in tasks}
    provider_reports: list[dict[str, Any]] = []
    benchmark_reports: list[dict[str, Any]] = []
    release_reports: list[dict[str, Any]] = []
    for task in tasks:
        task_id = task["task_id"]
        semantic_errors = semantic_store_impl.semantic_integrity_errors(
            paths, task_id
        )
        errors.extend(
            f"task {task_id}: semantic authority: {error}"
            for error in semantic_errors
        )
        try:
            migration_rolled_back = (
                semantic_store_impl.semantic_migration_rolled_back(paths, task_id)
            )
        except HarnessError as exc:
            migration_rolled_back = False
            errors.append(f"task {task_id}: semantic rollback archive: {exc}")
        if migration_rolled_back:
            warnings.append(
                f"task {task_id}: semantic migration is an inert preserved rollback archive"
            )
        projection_status: str | None = None
        if "_semantic" in task:
            try:
                projection_status = semantic_task_projection_status(paths, task_id)
            except HarnessError as exc:
                errors.append(f"task {task_id}: {exc}")
            else:
                if projection_status != "current":
                    warnings.append(
                        f"task {task_id}: semantic projection is {projection_status}; "
                        "the validated ledger was replayed in memory and explicit repair "
                        "is required before mutation"
                    )
        if (
            "_semantic" in task
            and not semantic_errors
            and projection_status == "current"
        ):
            try:
                release_report = release_runtime_impl.inspect_release_runtime(
                    paths, task_id
                )
            except release_runtime_impl.ReleaseRuntimeError as exc:
                errors.append(f"task {task_id}: release authority: {exc}")
            else:
                release_reports.append(release_report)
                pending_release = release_report["pending_binding_sha256s"]
                if pending_release:
                    errors.append(
                        f"task {task_id}: release authority has pending binding(s): "
                        + ", ".join(pending_release)
                    )
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

        integrity_contract = task.get("integrity_contract")
        integrity_required = _integrity_contract_required(paths, task)
        active_integrity_task = task.get("status") in {"active", "blocked"}
        if not isinstance(integrity_contract, dict):
            if integrity_required:
                errors.append(f"task {task_id}: required integrity_contract is missing")
            elif (
                active_integrity_task
                and task.get("profile") == "full"
                and not is_semantic_v2_task(paths, task_id)
            ):
                warnings.append(
                    f"task {task_id}: legacy active full task has not adopted integrity v1"
                )
        else:
            sealed = integrity_contract.get("seal") is not None
            integrity_errors = _integrity_runtime_errors(
                paths,
                task,
                require_current_snapshot=active_integrity_task and sealed,
                require_complete=sealed,
            )
            errors.extend(f"task {task_id}: {item}" for item in integrity_errors)
            if active_integrity_task and not sealed and not integrity_errors:
                warnings.append(
                    f"task {task_id}: integrity contract is active but unsealed"
                )

        worktree = state_worktree(paths, task)
        for packet in task.get("packets", []):
            if packet.get("status") not in {"failed", "cancelled"} and not (
                task.get("status") == "cancelled"
                and packet.get("status") == "done"
            ):
                continue
            lock_errors = packet_lock_integrity_errors(paths, task, packet)
            warnings.extend(f"task {task_id}: {item}" for item in lock_errors)
        if task.get("status") in {"active", "blocked"}:
            task_worktree_errors, _ = worktree_integrity_errors(paths, task)
            errors.extend(f"task {task_id}: {item}" for item in task_worktree_errors)
        elif not worktree.is_dir():
            errors.append(f"task worktree is missing for {task_id}: {worktree}")

        errors.extend(
            f"task {task_id}: {item}" for item in portfolio_integrity_errors(task, paths)
        )
        errors.extend(
            f"task {task_id}: {item}" for item in override_integrity_errors(task)
        )
        errors.extend(
            f"task {task_id}: {item}"
            for item in resource_config_integrity_errors(paths, task)
        )
        errors.extend(
            f"task {task_id}: {item}"
            for item in resource_envelope_integrity_errors(task)
        )
        errors.extend(
            f"task {task_id}: {item}"
            for item in subagent_incident_integrity_errors(task)
        )
        for incident in _object_records_for_derivation(
            task, "subagent_incidents"
        ):
            if incident.get("status") == "open":
                errors.append(
                    f"task {task_id}: open sub-agent spawn incident "
                    f"{incident.get('incident_id')} ({incident.get('reason_code')})"
                )
        warnings.extend(
            f"task {task_id}: {item}" for item in packet_integrity_warnings(task)
        )
        warnings.extend(
            f"task {task_id}: {item}" for item in verification_integrity_warnings(task)
        )

        task_provider_reports, task_provider_errors, task_provider_warnings = (
            context_receipt_reports(
                paths,
                task,
                evaluate_live=task.get("status") in {"active", "blocked"},
            )
        )
        provider_reports.extend(task_provider_reports)
        errors.extend(f"task {task_id}: {item}" for item in task_provider_errors)
        warnings.extend(f"task {task_id}: {item}" for item in task_provider_warnings)
        benchmark_errors = context_benchmark_integrity_errors(paths, task)
        errors.extend(f"task {task_id}: {item}" for item in benchmark_errors)
        if not benchmark_errors:
            benchmark_reports.extend(
                {
                    "task_id": task_id,
                    "benchmark_id": item.get("benchmark_id"),
                    "receipt_id": item.get("receipt_id"),
                    "summary_sha256": item.get("summary_sha256"),
                    "evidence_class": item.get("evidence_class"),
                    "close_qualifying": item.get("close_qualifying"),
                }
                for item in task.get("context_provider_benchmarks", [])
            )

        if task.get("status") in {"active", "blocked"}:
            errors.extend(
                f"task {task_id}: {item}"
                for item in packet_integrity_errors(paths, task)
            )
            errors.extend(
                f"task {task_id}: {item}"
                for item in packet_recovery_integrity_errors(paths, task)
            )
            errors.extend(
                f"task {task_id}: {item}" for item in job_integrity_errors(paths, task)
            )
            errors.extend(
                f"task {task_id}: {item}"
                for item in verification_integrity_errors(paths, task)
            )
        else:
            # Grandfather only records that explicitly predate integrity v1.
            # Once a terminal artifact has a v1 attestation, any later mismatch
            # remains a doctor error even though the task is already closed.
            terminal_packets = task.get("packets", [])
            terminal_packet_id_counts: dict[str, int] = {}
            for packet in terminal_packets:
                packet_id = str(packet.get("packet_id", ""))
                terminal_packet_id_counts[packet_id] = (
                    terminal_packet_id_counts.get(packet_id, 0) + 1
                )
            duplicate_terminal_packet_ids = {
                packet_id
                for packet_id, count in terminal_packet_id_counts.items()
                if count > 1
            }
            errors.extend(
                f"terminal task {task_id}: duplicate packet id {packet_id!r}"
                for packet_id in sorted(duplicate_terminal_packet_ids)
            )
            for packet in terminal_packets:
                packet_id = str(packet.get("packet_id", ""))
                if packet_id in duplicate_terminal_packet_ids:
                    continue
                destination = (
                    warnings if packet.get("integrity_version") != 1 else errors
                )
                prefix = (
                    "legacy terminal task" if destination is warnings else "terminal task"
                )
                destination.extend(
                    f"{prefix} {task_id}: {item}"
                    for item in packet_integrity_errors(
                        paths, task, packet_ids={packet_id}
                    )
                )
            errors.extend(
                f"terminal task {task_id}: {item}"
                for item in packet_recovery_integrity_errors(paths, task)
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
            terminal_verification = _object_records_for_derivation(
                task, "verification"
            )
            for verification_index, item in enumerate(
                terminal_verification, start=1
            ):
                destination = (
                    warnings if item.get("integrity_version") != 1 else errors
                )
                prefix = (
                    "legacy terminal task" if destination is warnings else "terminal task"
                )
                destination.extend(
                    f"{prefix} {task_id}: {message}"
                    for message in verification_record_integrity_errors(
                        paths, task, [(verification_index, item)]
                    )
                )
            supersession_records = [
                item
                for item in terminal_verification
                if item.get("superseded_at")
            ]
            graph_destination = (
                warnings
                if supersession_records
                and all(item.get("integrity_version") != 1 for item in supersession_records)
                else errors
            )
            graph_prefix = (
                "legacy terminal task"
                if graph_destination is warnings
                else "terminal task"
            )
            graph_destination.extend(
                f"{graph_prefix} {task_id}: {message}"
                for message in verification_supersession_errors(task)
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
            scoped_session_ids = [
                *task.get("session_ids", []),
                *task.get("subagent_parent_session_ids", []),
            ]
            for session_id in dict.fromkeys(scoped_session_ids):
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
                mapping_kind = mapping.get(
                    "mapping_kind", ROOT_SESSION_MAPPING_KIND
                )
                if mapping_kind == ROOT_SESSION_MAPPING_KIND:
                    if session_id not in task.get("session_ids", []):
                        errors.append(
                            f"root session {session_id} mapping lacks backlink in task {task['task_id']}"
                        )
                    if session_id in task.get("subagent_parent_session_ids", []):
                        errors.append(
                            f"root session {session_id} also has a subagent-parent backlink"
                        )
                elif mapping_kind == SUBAGENT_PARENT_MAPPING_KIND:
                    if session_id not in task.get(
                        "subagent_parent_session_ids", []
                    ):
                        errors.append(
                            f"subagent parent {session_id} mapping lacks backlink in task {task['task_id']}"
                        )
                    if session_id in task.get("session_ids", []):
                        errors.append(
                            f"subagent parent {session_id} is incorrectly root-authorized"
                        )
                    packet_matches = [
                        packet
                        for packet in task.get("packets", [])
                        if packet.get("packet_id") == mapping.get("packet_id")
                        and packet.get("agent_id") == session_id
                        and int(packet.get("delegation_depth", 1)) == 1
                    ]
                    if len(packet_matches) != 1:
                        errors.append(
                            f"subagent parent {session_id} mapping lacks its depth-one packet"
                        )
                else:
                    errors.append(
                        f"session {session_id} has invalid mapping kind {mapping_kind!r}"
                    )
        except HarnessError as exc:
            errors.append(str(exc))

    for task in tasks:
        if task.get("status") not in {"active", "blocked"}:
            continue
        for session_id in task.get("session_ids", []):
            mapping = mappings.get(session_id, {})
            if (
                mapping.get("task_id") != task["task_id"]
                or mapping.get("mapping_kind", ROOT_SESSION_MAPPING_KIND)
                != ROOT_SESSION_MAPPING_KIND
            ):
                errors.append(
                    f"task {task['task_id']} backlink has no matching session mapping: {session_id}"
                )
        for session_id in task.get("subagent_parent_session_ids", []):
            mapping = mappings.get(session_id, {})
            if (
                mapping.get("task_id") != task["task_id"]
                or mapping.get("mapping_kind") != SUBAGENT_PARENT_MAPPING_KIND
            ):
                errors.append(
                    f"task {task['task_id']} subagent-parent backlink has no matching mapping: {session_id}"
                )

    codex_provenance_report: dict[str, Any] | None = None
    codex_hook_receipt_report: dict[str, Any] | None = None
    codex_hook_delivery = "not_configured"
    if paths.project.codex_hooks_enabled:
        config_path = paths.root / ".codex" / "config.toml"
        hook_path = paths.root / ".codex" / "hooks.json"
        expected_hook_command: str | None = None
        try:
            codex_provenance_report = (
                codex_install_provenance_impl.load_codex_install_provenance_receipt(
                    paths.root
                )
            )
            hook_entry = codex_provenance_report["codex_hook_entry_point"]
            codex_install_provenance_impl.verify_runtime_hook_provenance(
                paths.root,
                codex_provenance_report["provenance_receipt_sha256"],
                hook_entry["path"],
            )
            expected_hook_command = (
                codex_onboarding_impl.build_codex_hook_command(
                    hook_entry["path"],
                    paths.root,
                    codex_provenance_report["provenance_receipt_sha256"],
                )
            )
        except (
            OSError,
            codex_install_provenance_impl.CodexInstallProvenanceError,
            codex_onboarding_impl.CodexOnboardingError,
        ) as exc:
            errors.append(f"Codex install provenance is invalid: {exc}")
        try:
            codex_hook_receipt_report = (
                codex_hook_receipts_impl.inspect_codex_hook_receipt_store(paths)
            )
            if codex_hook_receipt_report["entry_count"]:
                codex_hook_delivery = "adapter_receipt_observed"
            else:
                codex_hook_delivery = "no_adapter_receipt_observed"
                warnings.append(
                    "Codex hook configuration has no live adapter receipt evidence yet"
                )
            capacity_status = codex_hook_receipt_report["capacity_status"]
            if capacity_status == "full":
                errors.append(
                    "Codex hook receipt store is full; PreToolUse denies until receipts are preserved or rotated."
                )
            elif capacity_status == "near_full":
                warnings.append(
                    "Codex hook receipt store is near capacity; PreToolUse will deny once it is full."
                )
        except HarnessError as exc:
            codex_hook_delivery = "receipt_store_invalid"
            errors.append(f"Codex hook receipt store is invalid: {exc}")
        if not config_path.exists():
            errors.append(f"Codex hooks are enabled but config is missing: {config_path}")
        else:
            try:
                hook_config = tomllib.loads(
                    codex_onboarding_impl.read_verified_codex_text(
                        config_path, label="Codex hook config"
                    )
                )
                if hook_config.get("features", {}).get("hooks") is not True:
                    errors.append(f"hooks feature is not enabled in {config_path}")
            except (
                OSError,
                tomllib.TOMLDecodeError,
                codex_onboarding_impl.CodexOnboardingError,
            ) as exc:
                errors.append(f"invalid TOML {config_path}: {exc}")
        if not hook_path.exists():
            errors.append(f"Codex hooks are enabled but definition is missing: {hook_path}")
        else:
            _check_json_file(hook_path, errors)
            try:
                hook_payload = load_json(hook_path)
            except HarnessError:
                hook_payload = {}
            expected_events = set(codex_onboarding_impl.CODEX_HOOK_EVENTS)
            hooks = hook_payload.get("hooks", {})
            if not isinstance(hooks, dict):
                errors.append(f"{hook_path} hooks must be a JSON object")
            else:
                for event in expected_events:
                    entries = hooks.get(event, [])
                    if not isinstance(entries, list):
                        errors.append(f"{hook_path} {event} must be a JSON array")
                        continue
                    matching_handlers: list[dict[str, Any]] = []
                    for entry in entries:
                        if not isinstance(entry, dict):
                            continue
                        handlers = entry.get("hooks", [])
                        if not isinstance(handlers, list):
                            continue
                        for handler in handlers:
                            if not isinstance(handler, dict):
                                continue
                            commands = (
                                str(handler.get("command", "")),
                                str(handler.get("commandWindows", "")),
                            )
                            if any(
                                (
                                    codex_onboarding_impl.is_aoi_codex_hook_command(
                                        command
                                    )
                                    or codex_onboarding_impl.is_aoi_codex_hook_command(
                                        command, require_current=False
                                    )
                                )
                                for command in commands
                            ):
                                matching_handlers.append(handler)
                    if len(matching_handlers) != 1:
                        errors.append(
                            f"{hook_path} must have exactly one AOI handler for {event}"
                        )
                        continue
                    handler = matching_handlers[0]
                    if handler.get("type") != "command":
                        errors.append(f"{hook_path} {event} AOI handler is not a command")
                    timeout = handler.get("timeout", 0)
                    if not isinstance(timeout, (int, float)) or timeout < 30:
                        errors.append(
                            f"{hook_path} {event} AOI handler timeout is below 30 seconds"
                        )
                    for key in ("command", "commandWindows"):
                        command = str(handler.get(key, ""))
                        current = False
                        if expected_hook_command is not None:
                            assert codex_provenance_report is not None
                            hook_entry = codex_provenance_report[
                                "codex_hook_entry_point"
                            ]
                            current = (
                                codex_onboarding_impl.is_aoi_codex_hook_command(
                                    command,
                                    expected_launcher=hook_entry["path"],
                                    expected_project_root=paths.root,
                                    expected_provenance_sha256=codex_provenance_report[
                                        "provenance_receipt_sha256"
                                    ],
                                )
                            )
                        if not current:
                            errors.append(
                                f"{hook_path} {event} {key} must directly invoke the "
                                "exact provenance-bound AOI Codex hook command"
                            )

    if paths.project.legacy_enabled:
        legacy_source = paths.root / "LEGACY_CONTROL.md"
        if not scoped and legacy_source.exists():
            try:
                parse_legacy_table(paths, legacy_source)
            except HarnessError as exc:
                errors.append(str(exc))

    temporary_records = []
    try:
        with state_lock(
            paths,
            create_layout=False,
            allow_recoverable_nonlock_aliases=True,
        ):
            temporary_records = scan_atomic_temporaries(paths)
    except HarnessError as exc:
        errors.append(f"AOI temporary-file scan failed: {exc}")
    else:
        for record in temporary_records:
            relative = record.path.relative_to(paths.harness).as_posix()
            if record.classification == "legacy_manual":
                warnings.append(
                    f"legacy AOI temporary requires manual audit and cleanup: {relative}"
                )
            elif record.recoverable:
                errors.append(
                    "recoverable AOI temporary residue requires "
                    f"`aoi recover-temporaries`: {relative}"
                )
            else:
                errors.append(
                    "ambiguous AOI temporary residue blocks automatic recovery: "
                    f"{relative} ({record.classification})"
                )

    confidentiality_report: dict[str, Any]
    if paths.project.confidentiality.local_files:
        try:
            confidentiality_report = confidentiality_impl.inspect_confidentiality(
                root=paths.root,
                state_dir=paths.harness,
                policy=paths.project.confidentiality,
                config_sha256=paths.project.sha256,
                tasks=tasks,
            )
        except (OSError, HarnessError) as exc:
            confidentiality_report = {
                "schema_version": 1,
                "mode": paths.project.confidentiality.mode,
                "errors": [str(exc)],
                "warnings": [],
            }
            errors.append(f"confidentiality inspection failed: {exc}")
        else:
            errors.extend(
                f"confidentiality: {item}"
                for item in confidentiality_report["errors"]
            )
            warnings.extend(
                f"confidentiality: {item}"
                for item in confidentiality_report["warnings"]
            )
    else:
        confidentiality_report = {
            "schema_version": 1,
            "mode": paths.project.confidentiality.mode,
            "model_context": paths.project.confidentiality.model_context,
            "guarantee": "standard_publication_policy",
            "boundary": "local_files_enforcement_not_active",
            "errors": [],
            "warnings": [],
        }

    if not paths.config.is_file():
        errors.append(f"AOI configuration is missing: {paths.config}")
    if os.name == "nt":
        warnings.append(
            "windows_acl_unverified: AOI cannot prove that the state directory ACL "
            f"is private; restrict access manually: {paths.harness}"
        )
    elif paths.harness.exists() and stat.S_IMODE(paths.harness.stat().st_mode) & 0o077:
        errors.append(f"AOI state directory is not private (expected 0700): {paths.harness}")
    if not paths.index.exists():
        warnings.append(f"index has not been rendered: {paths.index}")

    payload = {
        "ok": not errors,
        "scope": args.task or "global",
        "chief_authority": authority,
        "errors": errors,
        "warnings": warnings,
        "task_count": len(tasks),
        "claim_count": len(claims),
        "context_providers": provider_reports,
        "context_provider_benchmarks": benchmark_reports,
        "release_promotions": release_reports,
        "codex_install_provenance": codex_provenance_report,
        "codex_hook_receipts": codex_hook_receipt_report,
        "codex_hook_delivery": codex_hook_delivery,
        "confidentiality": confidentiality_report,
        "temporary_files": [
            record.as_dict(paths) for record in temporary_records
        ],
        "platform": platform_capabilities(),
    }
    emit(payload, args.json)
    return 0 if not errors else 1


def add_json_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="emit JSON")


@dataclass(frozen=True)
class ParserVocabulary:
    """Immutable snapshot of parser-facing choice vocabularies.

    Built once inside :func:`build_parser` from the live module globals and
    injected into extracted command registrars (see ``commands/``) so they can
    declare ``choices=`` without importing this monolithic module or
    re-declaring its mutable constants.  Fields stay alphabetized; later
    extraction steps append more as their command blocks need them.
    """

    capability_tier_map: tuple[str, ...]
    change_classes: frozenset[str]
    close_qualifying_categories: frozenset[str]
    dependency_kinds: tuple[str, ...]
    dependency_levels: tuple[str, ...]
    depth_two_roles: tuple[str, ...]
    execution_modes: tuple[str, ...]
    improvement_option_ids: tuple[str, ...]
    improvement_trigger_classes: tuple[str, ...]
    lane_kinds: tuple[str, ...]
    lane_statuses: tuple[str, ...]
    needs_user_categories: tuple[str, ...]
    role_tier_map: tuple[str, ...]
    role_tier_values: frozenset[str]
    skill_adoption_actions: tuple[str, ...]
    tool_densities: tuple[str, ...]
    verification_categories: frozenset[str]


def _parser_vocabulary() -> ParserVocabulary:
    """Snapshot the live parser vocabulary globals for registrar injection."""

    return ParserVocabulary(
        capability_tier_map=tuple(CAPABILITY_TIER_MAP),
        change_classes=frozenset(CHANGE_CLASSES),
        close_qualifying_categories=frozenset(CLOSE_QUALIFYING_CATEGORIES),
        dependency_kinds=tuple(DEPENDENCY_KINDS),
        dependency_levels=tuple(DEPENDENCY_LEVELS),
        depth_two_roles=tuple(DEPTH_TWO_ROLES),
        execution_modes=tuple(EXECUTION_MODES),
        improvement_option_ids=tuple(IMPROVEMENT_OPTION_IDS),
        improvement_trigger_classes=tuple(IMPROVEMENT_TRIGGER_CLASSES),
        lane_kinds=tuple(LANE_KINDS),
        lane_statuses=tuple(LANE_STATUSES),
        needs_user_categories=tuple(NEEDS_USER_CATEGORIES),
        role_tier_map=tuple(ROLE_TIER_MAP),
        role_tier_values=frozenset(ROLE_TIER_MAP.values()),
        skill_adoption_actions=tuple(SKILL_ADOPTION_ACTIONS),
        tool_densities=tuple(TOOL_DENSITIES),
        verification_categories=frozenset(VERIFICATION_CATEGORIES),
    )


def build_parser(
    chief_defaults: dict[str, str | None] | None = None,
) -> argparse.ArgumentParser:
    if chief_defaults is None:
        chief_defaults = {
            "session_id": os.environ.get("AOI_CHIEF_SESSION_ID"),
            "epoch": os.environ.get("AOI_CHIEF_EPOCH"),
            "token": os.environ.get("AOI_CHIEF_TOKEN"),
            "credential_file": os.environ.get("AOI_CHIEF_CREDENTIAL_FILE"),
        }
    parser = AOIArgumentParser(
        description="AOI governed multi-agent organization infrastructure"
    )
    parser.add_argument("--version", action="version", version=f"AOI {__version__}")
    parser.add_argument(
        "--chief-session-id",
        default=chief_defaults.get("session_id"),
        help=(
            "Chief lease session id (or AOI_CHIEF_SESSION_ID); Chief global "
            "options are accepted before or after the command"
        ),
    )
    parser.add_argument(
        "--chief-epoch",
        default=chief_defaults.get("epoch"),
        help="Chief lease epoch (or AOI_CHIEF_EPOCH)",
    )
    parser.add_argument(
        "--chief-token",
        default=chief_defaults.get("token"),
        help=(
            "deprecated explicit Chief token fallback; prefer the private credential file"
        ),
    )
    parser.add_argument(
        "--chief-credential-file",
        default=chief_defaults.get("credential_file"),
        help=(
            "private repo-external Chief credential file (or "
            "AOI_CHIEF_CREDENTIAL_FILE); defaults to the user credential store"
        ),
    )
    sub = parser.add_subparsers(dest="_aoi_command", required=True)
    vocab = _parser_vocabulary()

    register_bootstrap_commands(
        sub,
        handlers={
            "init": cmd_init,
            "config_check": cmd_config_check,
        },
        add_json_argument=add_json_argument,
    )

    context_memory_services = _context_memory_cmd_services()
    register_context_memory_commands(
        sub,
        handlers={
            "context_receipt_record": functools.partial(
                cmd_context_receipt_record, services=context_memory_services
            ),
            "codebase_memory_benchmark_validate": cmd_codebase_memory_benchmark_validate,
            "codebase_memory_benchmark_record": functools.partial(
                cmd_codebase_memory_benchmark_record, services=context_memory_services
            ),
        },
        add_json_argument=add_json_argument,
    )

    task_lifecycle_services = _task_lifecycle_cmd_services()
    register_chief_commands(
        sub,
        handlers={
            "chief_acquire": functools.partial(
                cmd_chief_acquire, services=task_lifecycle_services
            ),
            "chief_renew": functools.partial(
                cmd_chief_renew, services=task_lifecycle_services
            ),
            "chief_release": functools.partial(
                cmd_chief_release, services=task_lifecycle_services
            ),
            "chief_takeover": functools.partial(
                cmd_chief_takeover, services=task_lifecycle_services
            ),
            "chief_status": cmd_chief_status,
        },
        add_json_argument=add_json_argument,
    )

    register_pilot_commands(
        sub,
        handlers={
            "pilot_init": cmd_pilot_init,
            "pilot_validate": cmd_pilot_validate,
            "pilot_summary": cmd_pilot_summary,
        },
        add_json_argument=add_json_argument,
    )

    mini_completion_services = _mini_completion_services(task_lifecycle_services)
    register_task_lifecycle_commands(
        sub,
        handlers={
            "init_task": functools.partial(
                cmd_init_task, services=task_lifecycle_services
            ),
            "start_mini": functools.partial(
                cmd_start_mini, services=task_lifecycle_services
            ),
            "finish_mini": functools.partial(
                cmd_finish_mini, services=mini_completion_services
            ),
            "approve_plan": functools.partial(
                cmd_approve_plan, services=task_lifecycle_services
            ),
            "plan_update": functools.partial(
                cmd_plan_update, services=task_lifecycle_services
            ),
            "bind_session": functools.partial(
                cmd_bind_session, services=task_lifecycle_services
            ),
            "unbind_session": functools.partial(
                cmd_unbind_session, services=task_lifecycle_services
            ),
            "import_legacy": cmd_import_legacy,
            "check_locks": cmd_check_locks,
            "inspect_legacy": cmd_inspect_legacy,
            "claim": functools.partial(cmd_claim, services=task_lifecycle_services),
            "set_claim_status": cmd_set_claim_status,
            "release_claim": cmd_release_claim,
            "audit_legacy": cmd_audit_legacy,
            "set_phase": cmd_set_phase,
            "adopt_current_branch": functools.partial(
                cmd_adopt_current_branch, services=task_lifecycle_services
            ),
            "checkpoint": functools.partial(
                cmd_checkpoint, services=task_lifecycle_services
            ),
            "retarget_task": cmd_retarget_task,
            "retire_risk": cmd_retire_risk,
        },
        add_json_argument=add_json_argument,
    )

    argparse_subparsers = cast(
        "argparse._SubParsersAction[argparse.ArgumentParser]", sub
    )
    register_semantic_commands(
        argparse_subparsers,
        handlers={
            "cohort_round_prepare": cmd_cohort_round_prepare,
            "cohort_round_preview": cmd_cohort_round_preview,
            "cohort_show": cmd_cohort_show,
            "permit_consume": cmd_permit_consume,
            "permit_issue": cmd_permit_issue,
            "semantic_head": cmd_semantic_head,
            "semantic_migrate": cmd_semantic_migrate,
            "semantic_migration_rollback": cmd_semantic_migration_rollback,
        },
        add_json_argument=add_json_argument,
    )

    register_confidentiality_commands(
        argparse_subparsers,
        handlers={
            "external_export_permit_consume": cmd_external_export_permit_consume,
            "external_export_permit_issue": cmd_external_export_permit_issue,
        },
        add_json_argument=add_json_argument,
    )

    register_integrity_commands(
        argparse_subparsers,
        handlers={
            "integrity_adopt": cmd_integrity_adopt,
            "integrity_snapshot": cmd_integrity_snapshot,
            "integrity_review": cmd_integrity_review,
            "integrity_fix": cmd_integrity_fix,
            "integrity_verify": cmd_integrity_verify,
            "integrity_seal": cmd_integrity_seal,
            "integrity_show": cmd_integrity_show,
            "integrity_upgrade_v2": cmd_integrity_upgrade_v2,
        },
        add_json_argument=add_json_argument,
    )

    register_release_commands(
        argparse_subparsers,
        handlers={
            "release_abandon_pending": cmd_release_abandon_pending,
            "release_manifest_observe": cmd_release_manifest_observe,
            "release_promote": cmd_release_promote,
            "release_show": cmd_release_show,
        },
        add_json_argument=add_json_argument,
    )

    capacity_services = _capacity_cmd_services()
    register_capacity_commands(
        sub,
        handlers={
            "capacity_snapshot": functools.partial(
                cmd_capacity_snapshot, services=capacity_services
            ),
            "capacity_recommend": functools.partial(
                cmd_capacity_recommend, services=capacity_services
            ),
            "capacity_arbitrate": functools.partial(
                cmd_capacity_arbitrate, services=capacity_services
            ),
            "capacity_distribute": cmd_capacity_distribute,
            "capacity_ack": cmd_capacity_ack,
        },
        add_json_argument=add_json_argument,
        vocab=vocab,
    )

    register_canary_commands(
        sub,
        handlers={
            "codex_helper_canary": functools.partial(
                cmd_codex_helper_canary,
                services=CanaryCmdServices(
                    require_plan_ready=require_plan_ready,
                    require_root_session=require_root_session,
                    packet_by_id=_packet_by_id,
                ),
            ),
        },
        add_json_argument=add_json_argument,
    )

    improvement_services = _improvement_cmd_services()
    register_improvement_commands(
        sub,
        handlers={
            "improvement_create": functools.partial(
                cmd_improvement_create, services=improvement_services
            ),
            "improvement_brief": cmd_improvement_brief,
            "improvement_arbitrate": functools.partial(
                cmd_improvement_arbitrate, services=improvement_services
            ),
            "improvement_link_project": functools.partial(
                cmd_improvement_link_project, services=improvement_services
            ),
            "skill_release_record": functools.partial(
                cmd_skill_release_record, services=improvement_services
            ),
            "skill_adoption_record": functools.partial(
                cmd_skill_adoption_record, services=improvement_services
            ),
        },
        add_json_argument=add_json_argument,
        vocab=vocab,
    )

    execution_selection_services = _execution_selection_cmd_services()
    register_execution_selection_commands(
        sub,
        handlers={
            "execution_select_plan": functools.partial(
                cmd_execution_select_plan, services=execution_selection_services
            ),
            "execution_select": functools.partial(
                cmd_execution_select, services=execution_selection_services
            ),
            "execution_brief_record": functools.partial(
                cmd_execution_brief_record, services=execution_selection_services
            ),
        },
        add_json_argument=add_json_argument,
        vocab=vocab,
    )

    coordination_services = _coordination_cmd_services()
    register_cross_lane_commands(
        sub,
        handlers={
            "cross_lane_open": functools.partial(
                cmd_cross_lane_open, services=coordination_services
            ),
            "cross_lane_close": cmd_cross_lane_close,
            "cross_lane_cancel": cmd_cross_lane_cancel,
            "needs_user_create": functools.partial(
                cmd_needs_user_create, services=coordination_services
            ),
            "needs_user_resolve": functools.partial(
                cmd_needs_user_resolve, services=coordination_services
            ),
        },
        add_json_argument=add_json_argument,
        vocab=vocab,
    )

    resource_services = _resource_cmd_services()
    register_resource_commands(
        sub,
        handlers={
            "override_request": functools.partial(
                cmd_override_request, services=resource_services
            ),
            "override_arbitrate": functools.partial(
                cmd_override_arbitrate, services=resource_services
            ),
            "override_revoke": functools.partial(
                cmd_override_revoke, services=resource_services
            ),
            "codex_config_plan": functools.partial(
                cmd_codex_config_plan, services=resource_services
            ),
            "codex_config_apply": functools.partial(
                cmd_codex_config_apply, services=resource_services
            ),
            "codex_config_rollback": functools.partial(
                cmd_codex_config_rollback, services=resource_services
            ),
            "codex_session_register": functools.partial(
                cmd_codex_session_register, services=resource_services
            ),
            "codex_startup_receipt_show": cmd_codex_startup_receipt_show,
        },
        add_json_argument=add_json_argument,
    )

    lanes_services = _lanes_cmd_services()
    register_lane_commands(
        sub,
        handlers={
            "lane_set_status": functools.partial(
                cmd_lane_set_status, services=lanes_services
            ),
            "lane_create": functools.partial(
                cmd_lane_create, services=lanes_services
            ),
            "lane_revise": functools.partial(
                cmd_lane_revise, services=lanes_services
            ),
            "lane_dependency_add": functools.partial(
                cmd_lane_dependency_add, services=lanes_services
            ),
            "lane_dependency_update": functools.partial(
                cmd_lane_dependency_update, services=lanes_services
            ),
        },
        add_json_argument=add_json_argument,
        vocab=vocab,
    )

    register_coordination_commands(
        sub,
        handlers={
            "coordination_create": functools.partial(
                cmd_coordination_create, services=coordination_services
            ),
            "coordination_update": functools.partial(
                cmd_coordination_update, services=coordination_services
            ),
            "coordination_arbitrate": functools.partial(
                cmd_coordination_arbitrate, services=coordination_services
            ),
            "coordination_directive_ack": cmd_coordination_directive_ack,
            "coordination_resolve": functools.partial(
                cmd_coordination_resolve, services=coordination_services
            ),
            "coordination_implementation_submit": functools.partial(
                cmd_coordination_implementation_submit, services=coordination_services
            ),
            "coordination_verify": functools.partial(
                cmd_coordination_verify, services=coordination_services
            ),
            "baseline_freeze": functools.partial(
                cmd_baseline_freeze, services=coordination_services
            ),
        },
        add_json_argument=add_json_argument,
        vocab=vocab,
    )

    register_verification_commands(
        sub,
        handlers={
            "reconcile": cmd_reconcile,
            "add_verification": cmd_add_verification,
            "materialize_artifacts": cmd_materialize_artifacts,
            "packet_input_recover_from_tar": cmd_packet_input_recover_from_tar,
            "verification_supersede": cmd_verification_supersede,
            "verification_supersession_seal": cmd_verification_supersession_seal,
        },
        add_json_argument=add_json_argument,
        vocab=vocab,
    )

    register_packet_commands(
        sub,
        handlers={
            "create_packet": cmd_create_packet,
            "packet_arm": cmd_packet_arm,
            "packet_disarm": cmd_packet_disarm,
            "packet_update": cmd_packet_update,
            "packet_attest_result": cmd_packet_attest_result,
            "subagent_incident_account": cmd_subagent_incident_account,
        },
        add_json_argument=add_json_argument,
        vocab=vocab,
    )

    register_job_commands(
        sub,
        handlers={
            "job_start": cmd_job_start,
            "job_update": cmd_job_update,
        },
        add_json_argument=add_json_argument,
    )

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
    p.add_argument(
        "--outcome",
        choices=("achieved", "scope_changed", "partial", "superseded"),
        required=True,
        help="honest close disposition against the registered completion boundary",
    )
    p.add_argument(
        "--boundary-disposition",
        help=(
            "required for non-achieved outcomes: why the registered boundary "
            "was not met and where that scope now lives"
        ),
    )
    p.add_argument(
        "--blockers-disposition",
        help="required when closing achieved with recorded blockers",
    )
    p.add_argument("--next-action")
    p.add_argument(
        "--semantic-command-id",
        help="stable idempotency key required when closing a semantic-v2 task",
    )
    p.add_argument(
        "--semantic-expected-head-sha256",
        help="exact semantic head required when closing a semantic-v2 task",
    )
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
    p.add_argument(
        "--changed-files-disposition",
        help="required when the task recorded changed files: what happens to them",
    )
    p.add_argument("--next-action")
    add_json_argument(p)
    p.set_defaults(handler=cmd_cancel_task)

    status_services = _status_cmd_services()
    register_status_commands(
        sub,
        handlers={
            "resume": functools.partial(cmd_resume, services=status_services),
            "status": functools.partial(cmd_status, services=status_services),
            "render_index": cmd_render_index,
        },
        add_json_argument=add_json_argument,
    )

    codex_onboarding_impl.register_codex_onboarding_commands(
        sub,
        handlers={"codex_init": cmd_codex_init},
        add_json_argument=add_json_argument,
    )

    claude_onboarding_impl.register_claude_onboarding_commands(
        sub,
        handlers={"claude_init": cmd_claude_init},
        add_json_argument=add_json_argument,
    )

    register_offboard_commands(
        sub,
        handlers={"offboard": cmd_offboard},
        add_json_argument=add_json_argument,
    )

    register_backup_commands(
        sub,
        handlers={
            "backup_state": cmd_backup_state,
            "verify_backup": cmd_verify_backup,
        },
        add_json_argument=add_json_argument,
    )

    register_temporary_recovery_commands(
        sub,
        handlers={
            "recover_temporaries": functools.partial(
                cmd_recover_temporaries,
                services=_temporary_recovery_services(),
            )
        },
        add_json_argument=add_json_argument,
    )

    p = sub.add_parser("doctor")
    p.add_argument("--task")
    add_json_argument(p)
    p.set_defaults(handler=cmd_doctor)

    return parser


_CHIEF_GLOBAL_VALUE_OPTIONS = {
    "--chief-session-id",
    "--chief-epoch",
    "--chief-token",
    "--chief-credential-file",
}


def _normalize_chief_global_options(raw_argv: list[str]) -> list[str]:
    """Accept Chief globals anywhere without exposing their values in errors."""

    global_items: list[str] = []
    remaining: list[str] = []
    index = 0
    while index < len(raw_argv):
        item = raw_argv[index]
        if item in _CHIEF_GLOBAL_VALUE_OPTIONS:
            global_items.append(item)
            if index + 1 < len(raw_argv):
                global_items.append(raw_argv[index + 1])
                index += 2
            else:
                index += 1
            continue
        if any(item.startswith(option + "=") for option in _CHIEF_GLOBAL_VALUE_OPTIONS):
            global_items.append(item)
            index += 1
            continue
        remaining.append(item)
        index += 1
    return [*global_items, *remaining]


def _command_from_normalized_argv(raw_argv: list[str]) -> str:
    """Locate the command after exact Chief globals have been normalized."""

    index = 0
    while index < len(raw_argv):
        item = raw_argv[index]
        if item in _CHIEF_GLOBAL_VALUE_OPTIONS:
            index += 2
            continue
        if any(item.startswith(option + "=") for option in _CHIEF_GLOBAL_VALUE_OPTIONS):
            index += 1
            continue
        if item == "--":
            return raw_argv[index + 1] if index + 1 < len(raw_argv) else ""
        if item.startswith("-"):
            index += 1
            continue
        return item
    return ""


def _take_chief_environment_defaults() -> dict[str, str | None]:
    mapping = {
        "session_id": "AOI_CHIEF_SESSION_ID",
        "epoch": "AOI_CHIEF_EPOCH",
        "token": "AOI_CHIEF_TOKEN",
        "credential_file": "AOI_CHIEF_CREDENTIAL_FILE",
    }
    defaults = {key: os.environ.get(name) for key, name in mapping.items()}
    for name in mapping.values():
        os.environ.pop(name, None)
    return defaults


def _reload_locked_paths(paths: HarnessPaths) -> HarnessPaths:
    if not paths.config.is_file():
        raise HarnessError(
            "aoi.toml disappeared while acquiring the project state lock"
        )
    current = get_paths(paths.root)
    if not paths.config.is_file():
        raise HarnessError(
            "aoi.toml disappeared while acquiring the project state lock"
        )
    if (
        current.project.sha256 != paths.project.sha256
        or current.harness != paths.harness
        or current.lock != paths.lock
    ):
        raise HarnessError("aoi.toml changed while acquiring the project state lock")
    return current


_SEMANTIC_V2_STAGE1_TARGET_COMMANDS = {
    "check-locks",
    "close-task",
    "cohort-round-prepare",
    "cohort-round-preview",
    "cohort-show",
    "doctor",
    "external-export-permit-consume",
    "external-export-permit-issue",
    "inspect-legacy",
    "integrity-adopt",
    "integrity-fix",
    "integrity-review",
    "integrity-seal",
    "integrity-show",
    "integrity-snapshot",
    "integrity-upgrade-v2",
    "integrity-verify",
    "permit-consume",
    "permit-issue",
    "release-manifest-observe",
    "release-abandon-pending",
    "release-promote",
    "release-show",
    "resume",
    "semantic-head",
    "semantic-migrate",
    "semantic-migration-rollback",
    "status",
    "verify-backup",
}


def _semantic_v2_stage1_target(
    args: argparse.Namespace, paths: HarnessPaths
) -> str | None:
    """Resolve direct and legacy-indirect task references without mutation."""

    command = str(args._aoi_command)
    direct = getattr(args, "task", None) or getattr(args, "task_id", None)
    if isinstance(direct, str) and direct:
        return validate_id(direct, "task id")
    if command == "unbind-session":
        session_id = str(getattr(args, "session_id", "") or "")
        mapping = load_json(session_path(paths, session_id))
        return validate_id(str(mapping.get("task_id", "")), "session task id")
    if command in {"set-claim-status", "release-claim"}:
        token = validate_id(str(getattr(args, "token", "") or ""), "claim token")
        claim = load_claim_file(claim_path(paths, token, active=True))
        return validate_id(str(claim.get("task_id", "")), "claim task id")
    return None


def _enforce_semantic_v2_stage1_boundary(
    args: argparse.Namespace, paths: HarnessPaths
) -> None:
    """Block unported v1 handlers before they can publish cross-file effects."""

    command = str(args._aoi_command)
    target = _semantic_v2_stage1_target(args, paths)
    if target is None or not is_semantic_v2_task(paths, target):
        return
    if command == "init-task" and bool(getattr(args, "semantic_v2", False)):
        return
    if command in _SEMANTIC_V2_STAGE1_TARGET_COMMANDS:
        return
    raise HarnessError(
        f"semantic-v2 task {target} requires explicit semantic transitions; command {command!r} "
        "requires an explicit semantic transition and side-effect transaction port"
    )


def _execute_project_command(
    args: argparse.Namespace, paths: HarnessPaths, *, initialized: bool
) -> int:
    command = str(args._aoi_command)
    args._aoi_initialized_at_dispatch = initialized
    if not command_requires_chief(command, initialized=initialized):
        _enforce_semantic_v2_stage1_boundary(args, paths)
        return int(args.handler(args, paths))
    with state_lock(paths, create_layout=False):
        paths = _reload_locked_paths(paths)
        session_id, epoch, token, _credential_path = _chief_credential(args, paths)
        chief_record = require_chief_authority(
            paths,
            session_id=session_id,
            epoch=epoch,
            token=token,
        )
        args._aoi_authority_ref = f"chief:{session_id}@{epoch}"
        args._aoi_chief_authority = {
            "session_id": chief_record["session_id"],
            "epoch": chief_record["epoch"],
            "authority_record_sha256": canonical_record_sha256(chief_record),
        }
        _enforce_semantic_v2_stage1_boundary(args, paths)
        return int(args.handler(args, paths))


def main(argv: list[str] | None = None) -> int:
    raw_argv = _normalize_chief_global_options(
        list(sys.argv[1:] if argv is None else argv)
    )
    chief_defaults = _take_chief_environment_defaults()
    try:
        command = _command_from_normalized_argv(raw_argv)
        if not command:
            parser = build_parser(chief_defaults)
            parser.parse_args(raw_argv)
            return 0
        if any(argument in {"-h", "--help"} for argument in raw_argv):
            paths = get_paths()
            if paths.config.is_file():
                apply_project_config(paths.project)
            parser = build_parser(chief_defaults)
            parser.parse_args(raw_argv)
            return 0
        if command in CHIEF_STANDALONE_COMMANDS:
            parser = build_parser(chief_defaults)
            args = parser.parse_args(raw_argv)
            if args._aoi_command != command:
                raise HarnessError("parsed command differs from normalized command routing")
            if command in CHIEF_STANDALONE_WRITER_COMMANDS:
                projects = _pilot_output_projects(
                    Path(args.output), kit_destinations=command == "pilot-init"
                )
                if len(projects) > 1:
                    raise HarnessError(
                        "pilot output overlaps multiple initialized AOI projects"
                    )
                if projects:
                    project_paths = projects[0]
                    apply_project_config(project_paths.project)
                    return _execute_project_command(
                        args, project_paths, initialized=True
                    )
            return int(args.handler(args, None))
        paths = get_paths()
        initialized = paths.config.is_file()
        if command not in {"init", "claude-init", "codex-init", ""} and not initialized:
            raise HarnessError(f"AOI is not initialized at {paths.root}; run 'aoi init' first")
        if initialized:
            apply_project_config(paths.project)
        parser = build_parser(chief_defaults)
        args = parser.parse_args(raw_argv)
        if args._aoi_command != command:
            raise HarnessError("parsed command differs from normalized command routing")
        return _execute_project_command(args, paths, initialized=initialized)
    except (HarnessError, PilotError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("ERROR: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
