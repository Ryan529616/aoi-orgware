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
from typing import Any, Iterable

from . import __version__
from . import dispatch_protocol as dispatch_protocol_impl
from . import evidence_artifacts as evidence_artifacts_impl
from . import execution_topology as execution_topology_impl
from . import job_integrity as job_integrity_impl
from . import packet_integrity as packet_integrity_impl
from . import portfolio_integrity as portfolio_integrity_impl
from . import resource_governance as resource_governance_impl
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
from .commands.context_memory import (
    ContextMemoryCmdServices,
    cmd_codebase_memory_benchmark_record,
    cmd_codebase_memory_benchmark_validate,
    cmd_context_receipt_record,
    register_context_memory_commands,
)
from .commands.coordination import (
    register_coordination_commands,
    register_cross_lane_commands,
)
from .commands.execution_selection import register_execution_selection_commands
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
from .commands.resource import (
    ResourceCmdServices,
    cmd_codex_config_apply,
    cmd_codex_config_plan,
    cmd_codex_config_rollback,
    cmd_override_arbitrate,
    cmd_override_request,
    cmd_override_revoke,
    register_resource_commands,
)
from .commands.status import register_status_commands
from .commands.task_lifecycle import (
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

from .harnesslib import (
    ACCOUNTED_VERIFICATION_STATUSES,
    ACTIVE_JOB_STATUSES,
    ACTIVE_PACKET_STATUSES,
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
    platform_capabilities,
    preflight_layout,
    paths_for_project,
    prepare_checkpoint,
    release_chief_authority,
    remove_chief_credential,
    record_legacy_decision,
    render_checkpoint,
    renew_chief_authority,
    require_complete_layout,
    require_chief_authority,
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
NATIVE_V5_PACKET_CONTRACT_MARKER = "- AOI dispatch schema origin: `native_v5`"
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
CLOSE_QUALIFYING_CATEGORIES = VERIFICATION_CATEGORIES - {
    "engineering_inference",
    "historical_terminal_readback",
}
RECEIPT_COMPONENTS = ("source", "runner", "config", "dependencies", "other")
REQUIRED_RECEIPT_COMPONENTS = ("source", "runner")
HOOK_PROTOCOL_VERSION = "6"
DISPATCH_ARM_MAX_SECONDS = 15 * 60
HOOK_ID_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,512}$")
ROOT_SESSION_MAPPING_KIND = "root"
SUBAGENT_PARENT_MAPPING_KIND = "subagent_parent"
DISPATCH_PROVENANCES = {
    "none",
    "codex_subagent_start_observed",
    "manual_unverified",
}
MINI_MAX_LOCKS = 3
MINI_FORBIDDEN_REPO_PREFIXES = (
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
}
CHIEF_PROJECT_READ_ONLY_COMMANDS = {
    "chief-status",
    "check-locks",
    "codebase-memory-benchmark-validate",
    "codex-config-plan",
    "inspect-legacy",
    "reconcile",
    "resume",
    "status",
    "verify-backup",
    "doctor",
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

    if command == "init":
        return initialized
    return command not in (
        CHIEF_AUTHORITY_CONTROL_COMMANDS
        | CHIEF_PROJECT_READ_ONLY_COMMANDS
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
) -> list[str]:
    return packet_integrity_impl.packet_integrity_errors(
        paths,
        state,
        allow_done_lock_recovery=allow_done_lock_recovery,
        services=_packet_integrity_services(),
    )


def subagent_incident_integrity_errors(state: dict[str, Any]) -> list[str]:
    return packet_integrity_impl.subagent_incident_integrity_errors(
        state, services=_packet_integrity_services()
    )


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
            mapping_kind = mapping.get("mapping_kind", ROOT_SESSION_MAPPING_KIND)
            backlink_field = (
                "subagent_parent_session_ids"
                if mapping_kind == SUBAGENT_PARENT_MAPPING_KIND
                else "session_ids"
            )
            state[backlink_field] = [
                item for item in state.get(backlink_field, []) if item != session_id
            ]
            bump_task(state)
            write_task(paths, state)
        write_index(paths)
    emit({"session_id": session_id, "task_id": task_id, "unbound": True}, args.json)
    return 0


def _resource_text(name: str) -> str:
    resource = importlib.resources.files("aoi_orgware.resources").joinpath(name)
    return resource.read_text(encoding="utf-8")


def _explicit_config(root: Path, value: str) -> tuple[ProjectConfig, bytes, Path]:
    source = Path(value).expanduser().absolute()
    try:
        config, raw = load_config_path(root, source)
    except ValueError as exc:
        raise HarnessError(str(exc)) from exc
    return config, raw, source


def _config_summary(config: ProjectConfig, source: Path) -> dict[str, Any]:
    warnings: list[str] = []
    if config.state_dir != ".aoi":
        warnings.append("non-default state_dir requires explicit user review")
    if config.codex_hooks_enabled:
        warnings.append("Codex hooks are enabled in policy but are not installed by init")
    if config.legacy_enabled:
        warnings.append("legacy compatibility is enabled")
    if "steward" not in config.departments:
        warnings.append("no department is literally named 'steward'; verify control-plane ownership")
    return {
        "valid": True,
        "source": str(source),
        "project": config.name,
        "profile_id": config.profile_id,
        "state_dir": config.state_dir,
        "departments": list(config.departments),
        "roles": dict(config.roles),
        "evidence_categories": list(config.evidence_categories),
        "close_qualifying_categories": list(config.close_qualifying_categories),
        "receipt_components": list(config.receipt_components),
        "required_receipt_components": list(config.required_receipt_components),
        "high_risk_paths": list(config.high_risk_paths),
        "external_lock_namespace": config.external_lock_namespace,
        "hooks_enabled": config.codex_hooks_enabled,
        "legacy_enabled": config.legacy_enabled,
        "config_sha256": config.sha256,
        "warnings": warnings,
    }


def cmd_config_check(args: argparse.Namespace, paths: HarnessPaths | None) -> int:
    root = discover_root()
    config, _raw, source = _explicit_config(root, args.file)
    emit(_config_summary(config, source), args.json)
    return 0


def _require_pristine_bootstrap_state(paths: HarnessPaths) -> None:
    preflight_layout(paths)
    if not paths.harness.exists():
        return
    try:
        populated = any(paths.harness.iterdir())
    except OSError as exc:
        raise HarnessError(
            f"cannot inspect unconfigured AOI state directory {paths.harness}: {exc}"
        ) from exc
    if populated:
        raise HarnessError(
            "aoi.toml is missing while an AOI state tree already exists; restore the "
            "approved configuration instead of using unauthenticated init"
        )


def cmd_init(args: argparse.Namespace, paths: HarnessPaths) -> int:
    if not (paths.root / ".git").exists():
        raise HarnessError("aoi init requires a Git repository root")
    ignore_path = paths.root / ".gitignore"
    validate_existing_regular_file(ignore_path, "project .gitignore")
    candidate: ProjectConfig | None = None
    candidate_raw: bytes | None = None
    expected_config_sha256 = (args.expected_config_sha256 or "").lower()
    replace_policy_sha256 = (args.replace_policy_sha256 or "").lower()
    if replace_policy_sha256 and not re.fullmatch(r"[0-9a-f]{64}", replace_policy_sha256):
        raise HarnessError("--replace-policy-sha256 must be a full SHA-256")
    if not paths.config.exists():
        _require_pristine_bootstrap_state(paths)
    if expected_config_sha256 and not args.config:
        raise HarnessError("--expected-config-sha256 requires --config")
    if args.config and not expected_config_sha256:
        raise HarnessError("--config requires --expected-config-sha256")
    if expected_config_sha256 and not re.fullmatch(
        r"[0-9a-f]{64}", expected_config_sha256
    ):
        raise HarnessError("--expected-config-sha256 must be a full SHA-256")
    if args.config:
        candidate, candidate_raw, _source = _explicit_config(paths.root, args.config)
        if candidate.sha256 != expected_config_sha256:
            raise HarnessError(
                "candidate configuration SHA-256 differs from the approved digest"
            )
    initialized_at_dispatch = bool(
        getattr(args, "_aoi_initialized_at_dispatch", paths.config.is_file())
    )
    created_config = False
    if paths.config.exists():
        if not initialized_at_dispatch:
            raise HarnessError(
                "aoi.toml appeared after unauthenticated init was dispatched; rerun "
                "the command with the active Chief credential"
            )
        if candidate is not None and candidate.sha256 != paths.project.sha256:
            raise HarnessError(
                "AOI is already initialized with a different configuration; refusing to overwrite"
            )
        if args.project_name and paths.project.name != args.project_name:
            raise HarnessError(
                f"AOI is already initialized as {paths.project.name!r}; refusing to rename"
            )
        initialized = paths
    else:
        if initialized_at_dispatch:
            raise HarnessError(
                "aoi.toml disappeared after authenticated init was dispatched; restore "
                "the approved configuration"
            )
        if candidate is not None:
            initialized = paths_for_project(paths.root, candidate)
            assert candidate_raw is not None
            _require_pristine_bootstrap_state(initialized)
            atomic_create_bytes(paths.config, candidate_raw)
        else:
            project_name = args.project_name or paths.root.name or "AOI Project"
            try:
                config_text = default_config_text(project_name)
            except ValueError as exc:
                raise HarnessError(str(exc)) from exc
            atomic_create_text(paths.config, config_text)
            initialized = get_paths(paths.root)
        created_config = True
    # Establish the selected state lock domain only after the candidate profile
    # has passed strict parsing and non-clobber checks.
    with state_lock(initialized):
        initialized = _reload_locked_paths(initialized)
        if created_config and load_chief_authority(
            initialized, allow_missing=True
        ) is not None:
            raise HarnessError(
                "Chief authority appeared during first initialization; rerun init "
                "with that Chief credential"
            )
        for name in (
            "plan.md",
            "packet.md",
            "checkpoint.md",
            "source_receipt.example.json",
        ):
            destination = initialized.templates / name
            if not destination.exists():
                atomic_write_text(destination, _resource_text(f"templates/{name}"))
        policy = initialized.harness / "POLICY.md"
        packaged_policy = _resource_text("policy.md").encode("utf-8")
        policy_updated = False
        if not policy.exists():
            atomic_write_bytes(policy, packaged_policy)
            policy_updated = True
        else:
            current_policy = policy.read_bytes()
            current_policy_sha256 = hashlib.sha256(current_policy).hexdigest()
            if current_policy != packaged_policy:
                if (
                    current_policy_sha256 not in KNOWN_MANAGED_POLICY_SHA256
                    and replace_policy_sha256 != current_policy_sha256
                ):
                    raise HarnessError(
                        "existing AOI policy differs from the packaged contract; rerun "
                        "authenticated init with --replace-policy-sha256 "
                        f"{current_policy_sha256} after reviewing the replacement"
                    )
                atomic_write_bytes(policy, packaged_policy)
                policy_updated = True
        ignore_entry = f"/{initialized.project.state_dir.rstrip('/')}/"
        current_ignore = (
            ignore_path.read_text(encoding="utf-8") if ignore_path.exists() else ""
        )
        if ignore_entry not in {line.strip() for line in current_ignore.splitlines()}:
            updated = current_ignore
            if updated and not updated.endswith("\n"):
                updated += "\n"
            updated += ignore_entry + "\n"
            atomic_write_text(ignore_path, updated)
        write_index(initialized)
    emit(
        {
            "initialized": True,
            "created_config": created_config,
            "project": initialized.project.name,
            "root": str(initialized.root),
            "state_dir": str(initialized.harness),
            "config_sha256": initialized.project.sha256,
            "hooks_enabled": initialized.project.codex_hooks_enabled,
            "policy_updated": policy_updated,
            "platform": platform_capabilities(),
        },
        args.json,
    )
    return 0


def _chief_identity(args: argparse.Namespace) -> tuple[str | None, int | None]:
    raw_epoch = args.chief_epoch
    if raw_epoch in {None, ""}:
        epoch = None
    else:
        try:
            epoch = int(raw_epoch)
        except (TypeError, ValueError) as exc:
            raise HarnessError("Chief credential epoch must be a positive integer") from exc
    return args.chief_session_id, epoch


def _chief_credential(
    args: argparse.Namespace, paths: HarnessPaths
) -> tuple[str | None, int | None, str | None, Path | None]:
    session_id, epoch = _chief_identity(args)
    token = args.chief_token
    raw_file = args.chief_credential_file
    if token and raw_file:
        raise HarnessError("use either a Chief credential file or explicit token, not both")
    if token:
        return session_id, epoch, token, None
    credential_file = Path(raw_file) if raw_file else None
    loaded_token, loaded_path = load_chief_credential(
        paths,
        session_id=session_id,
        epoch=epoch,
        credential_file=credential_file,
    )
    return session_id, epoch, loaded_token, loaded_path


def _chief_acquisition_payload(
    paths: HarnessPaths, credential_path: Path
) -> dict[str, Any]:
    return {
        "authority": chief_authority_summary(paths),
        "credential_file": str(credential_path),
        "credential_environment": [
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
        ],
        "credential_notice": (
            "The plaintext token is stored only in the private repo-external file. "
            "Do not copy that file into shared state, logs, checkpoints, or artifacts."
        ),
        "credential_protection": (
            "windows-dpapi-current-user" if os.name == "nt" else "posix-owner-mode-0600"
        ),
    }


def cmd_chief_acquire(args: argparse.Namespace, paths: HarnessPaths) -> int:
    bootstrap_chief_state_lock(paths)
    with state_lock(paths, create_layout=False):
        paths = _reload_locked_paths(paths)
        _record, credential_path = acquire_chief_authority(
            paths,
            session_id=args.session_id,
            ttl_seconds=args.ttl_seconds,
            credential_home=(
                Path(args.credential_home) if args.credential_home else None
            ),
        )
        payload = _chief_acquisition_payload(paths, credential_path)
    emit(payload, args.json)
    return 0


def cmd_chief_renew(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths, create_layout=False):
        paths = _reload_locked_paths(paths)
        session_id, epoch, token, _credential_path = _chief_credential(args, paths)
        renew_chief_authority(
            paths,
            session_id=session_id,
            epoch=epoch,
            token=token,
            ttl_seconds=args.ttl_seconds,
        )
        payload = {"authority": chief_authority_summary(paths)}
    emit(payload, args.json)
    return 0


def cmd_chief_release(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths, create_layout=False):
        paths = _reload_locked_paths(paths)
        session_id, epoch, token, credential_path = _chief_credential(args, paths)
        release_chief_authority(
            paths,
            session_id=session_id,
            epoch=epoch,
            token=token,
            reason=args.reason,
        )
        cleanup: dict[str, Any]
        try:
            removed = remove_chief_credential(credential_path)
        except (HarnessError, OSError) as exc:
            cleanup = {
                "removed": False,
                "warning": f"inactive authority committed; credential cleanup failed: {exc}",
            }
        else:
            cleanup = {"removed": removed}
        payload = {
            "authority": chief_authority_summary(paths),
            "credential_cleanup": cleanup,
        }
    emit(payload, args.json)
    return 0


def cmd_chief_takeover(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths, create_layout=False):
        paths = _reload_locked_paths(paths)
        _record, credential_path = takeover_chief_authority(
            paths,
            session_id=args.session_id,
            expected_epoch=args.expected_epoch,
            reason=args.reason,
            force_live=args.force_live,
            ttl_seconds=args.ttl_seconds,
            credential_home=(
                Path(args.credential_home) if args.credential_home else None
            ),
        )
        payload = _chief_acquisition_payload(paths, credential_path)
    emit(payload, args.json)
    return 0


def cmd_chief_status(args: argparse.Namespace, paths: HarnessPaths) -> int:
    require_complete_layout(paths)
    emit(chief_authority_summary(paths), args.json)
    return 0


def cmd_pilot_init(args: argparse.Namespace, paths: HarnessPaths | None) -> int:
    result = initialize_kit(
        Path(args.output),
        force=args.force,
        allow_unverified_windows_acl=args.allow_unverified_windows_acl,
        authorized_project_root=paths.root if paths is not None else None,
    )
    emit(result, args.json)
    return 0


def cmd_pilot_validate(args: argparse.Namespace, _paths: HarnessPaths | None) -> int:
    record = load_record(Path(args.record))
    emit(
        {
            "ok": True,
            "protocol_version": record["protocol_version"],
            "variant": record["variant"],
            "run_status": record["run_status"],
            "oracle_status": record["oracle"]["status"],
            "aggregate_consent": record["consent"]["aggregate"],
            "share_with_coordinator_consent": record["consent"][
                "share_with_coordinator"
            ],
        },
        args.json,
    )
    return 0


def cmd_pilot_summary(args: argparse.Namespace, paths: HarnessPaths | None) -> int:
    records = [load_record(Path(value)) for value in args.record]
    result = write_summary(
        records,
        Path(args.output),
        output_format=args.format,
        force=args.force,
        authorized_project_root=paths.root if paths is not None else None,
    )
    emit(result, args.json)
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
            "profile_id": paths.project.profile_id,
            "config_sha256": paths.project.sha256,
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
            "subagent_parent_session_ids": [],
            "packets": [],
            "dispatch_model_version": 1,
            "subagent_incidents": [],
            "task_execution_schema_version": TASK_EXECUTION_SCHEMA_VERSION,
            "execution_policy_version": EXECUTION_POLICY_VERSION,
            "legacy_execution_policy": False,
            "execution_briefs": [],
            "context_provider_receipts": [],
            "context_provider_benchmarks": [],
            "override_requests": [],
            "resource_config_events": [],
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
    mini_worktree = Path(metadata["worktree"])
    locks = list(
        dict.fromkeys(
            validate_lock_identity(paths, lock, repo_root=mini_worktree)
            for lock in locks
        )
    )
    locks = validate_mini_locks(locks)
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
        "- No high-risk paths, external jobs, tree locks, delegation packets, or additional claims.\n"
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
        conflicts = find_conflicts(paths, locks, repo_root=mini_worktree)
        if conflicts:
            raise HarnessError(
                "mini claim conflict(s):\n" + json.dumps(conflicts, indent=2, ensure_ascii=False)
            )
        baselines = baselines_for_locks(paths, locks, repo_root=Path(metadata["worktree"]))
        state: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "profile_id": paths.project.profile_id,
            "config_sha256": paths.project.sha256,
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
            "subagent_parent_session_ids": [],
            "packets": [],
            "dispatch_model_version": 1,
            "subagent_incidents": [],
            "task_execution_schema_version": TASK_EXECUTION_SCHEMA_VERSION,
            "execution_policy_version": EXECUTION_POLICY_VERSION,
            "legacy_execution_policy": False,
            "execution_briefs": [],
            "context_provider_receipts": [],
            "context_provider_benchmarks": [],
            "override_requests": [],
            "resource_config_events": [],
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
        claim_destination = claim_path(paths, token, active=True)
        session_destination = session_path(paths, session_id)
        if directory.exists():
            raise HarnessError(f"task directory already exists without state: {task_id}")
        try:
            (directory / "packets").mkdir(parents=True, exist_ok=False)
            (directory / "results").mkdir(parents=True, exist_ok=False)
            atomic_write_text(directory / "plan.md", plan)
            # The claim must be visible while the semantic checkpoint validates
            # task/claim backlinks. Any ordinary exception rolls every newly
            # published mini artifact back while the global state lock is held.
            atomic_write_json(claim_destination, claim)
            write_task(paths, state)
            checkpoint, checkpoint_text, _ = prepare_checkpoint(paths, state)
            atomic_write_text(checkpoint, checkpoint_text)
            atomic_write_json(
                session_destination,
                {
                    "schema_version": SCHEMA_VERSION,
                    "session_id": session_id,
                    "task_id": task_id,
                    "checkpoint_path": str(checkpoint),
                    "updated_at": timestamp,
                },
            )
            write_index(paths)
        except Exception:
            for published in (session_destination, claim_destination):
                try:
                    published.unlink(missing_ok=True)
                except OSError:
                    pass
            try:
                shutil.rmtree(directory)
            except FileNotFoundError:
                pass
            try:
                write_index(paths)
            except Exception:
                pass
            raise
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
    source = Path(args.source).resolve() if args.source else paths.root / "LEGACY_CONTROL.md"
    with state_lock(paths):
        result = import_legacy(paths, source)
        write_index(paths)
    emit(result, args.json)
    return 0


def cmd_check_locks(args: argparse.Namespace, paths: HarnessPaths) -> int:
    locks = list(
        dict.fromkeys(
            validate_lock_identity(paths, item, repo_root=paths.root)
            for item in args.lock
        )
    )
    conflicts = find_conflicts(
        paths,
        locks,
        ignore_token=args.ignore_token,
        repo_root=paths.root,
    )
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
        claim_worktree = state_worktree(paths, state)
        locks = list(
            dict.fromkeys(
                validate_lock_identity(paths, lock, repo_root=claim_worktree)
                for lock in locks
            )
        )
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
            paths,
            locks,
            ignore_token=token if args.adopt_legacy else None,
            repo_root=claim_worktree,
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
                paths, locks, repo_root=claim_worktree
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
        validate_claim_lock_identities(paths, claim)
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
    remaining_locks: list[str] = []
    for claim in claims_for_task(paths, state, validate_reserving=False):
        if (
            claim.get("token") == token
            or claim.get("status") not in RESERVING_CLAIM_STATUSES
        ):
            continue
        validate_claim_lock_identities(paths, claim)
        remaining_locks.extend(str(lock) for lock in claim.get("locks", []))
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
                    (
                        f"job {job.get('run_id')}",
                        f"{paths.project.external_lock_namespace}:tree:{work_root}",
                    )
                )
            if log:
                dependencies.append(
                    (
                        f"job {job.get('run_id')}",
                        f"{paths.project.external_lock_namespace}:file:{log}",
                    )
                )
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
        stale_lock_authority_error = ""
        try:
            claim["final_baselines"] = baselines_for_locks(
                paths,
                claim.get("locks", []),
                repo_root=state_worktree(paths, state),
            )
        except HarnessError as exc:
            if args.status != "stale":
                raise HarnessError(
                    "claim lock authority cannot be revalidated; audit active "
                    "dependencies and release explicitly with --status stale: "
                    f"{exc}"
                ) from exc
            claim["final_baselines"] = {}
            stale_lock_authority_error = str(exc)
            claim["stale_lock_authority_error"] = stale_lock_authority_error
        changed: dict[str, bool] = {}
        for lock, baseline in claim.get("baselines", {}).items():
            changed[lock] = baseline != claim["final_baselines"].get(lock)
        if stale_lock_authority_error:
            for lock in claim.get("locks", []):
                changed[str(lock)] = True
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
        required_lock = validate_lock_identity(
            paths,
            f"git:merge:{current['branch']}",
            repo_root=worktree,
        )
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
            str(observed_starts[0].get("observed_at", ""))
            if dispatch_provenance == "codex_subagent_start_observed"
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
                "actual_role": packet.get("actual_role")
                if packet.get("routing_verified")
                else "unavailable",
                "actual_model_tier": packet.get("actual_model_tier")
                if packet.get("routing_verified")
                else "unavailable",
                "routing_verified": bool(packet.get("routing_verified")),
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


def _steward_packet_binding(
    state: dict[str, Any], selection_id: str, packet_id: str
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
    return {
        "packet_id": packet_id,
        "lane_id": str(packet.get("lane_id", "")),
        "agent_id": str(packet.get("agent_id", "")),
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
) -> tuple[dict[str, Any], str]:
    resource_envelope, resource_envelope_sha256 = _build_execution_resource_envelope(
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
            _lane_authority_snapshot(lane)
            for lane in sorted(lanes, key=lambda item: item["lane_id"])
        ],
        "steward_snapshot": (
            _lane_authority_snapshot(steward) if steward is not None else {}
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


def cmd_execution_select_plan(args: argparse.Namespace, paths: HarnessPaths) -> int:
    selection_id, work_unit_id, lane_ids = _validate_execution_selection_arguments(
        args
    )
    proposed_settings = parse_override_settings(
        args.proposed_setting,
        roles=ROLE_TIER_MAP,
        target_kind="execution_resource",
    )
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "plan execution resource override for")
        require_plan_ready(paths, state, "plan execution resource override")
        require_root_session(paths, state, args.session_id)
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
        )
    emit({**contract, "target_contract_sha256": digest}, args.json)
    return 0


def cmd_execution_select(args: argparse.Namespace, paths: HarnessPaths) -> int:
    selection_id, work_unit_id, lane_ids = _validate_execution_selection_arguments(
        args
    )
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "select execution topology for")
        require_plan_ready(paths, state, "select execution topology")
        _adopt_execution_policy_v2_for_new_work(state)
        session_id = require_root_session(paths, state, args.session_id)
        resource_override_settings = approved_override_settings(
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
            if prior_selection.get("mode") in {"centralized_parallel", "hybrid"}:
                brief_error = _execution_brief_coverage_error(
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
            )
        )
        require_override_target_contract(
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
            refreshed_settings = approved_override_settings(
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
            resource_override = override_by_id(state, args.override_id)
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
    args: argparse.Namespace, paths: HarnessPaths
) -> int:
    brief_id = validate_id(args.brief_id, "execution brief id")
    packet_ids = sorted(set(args.packet_id))
    cross_session_ids = sorted(set(args.cross_lane_session_id))
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "record execution brief for")
        require_plan_ready(paths, state, "record execution brief")
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
        root_session_id = require_root_session(paths, state, args.session_id)
        steward_packet_binding: dict[str, Any] | None = None
        brief_version = 2
        if _execution_policy_v2_enabled(state):
            if not args.steward_packet_id:
                raise HarnessError(
                    "execution policy v2 requires --steward-packet-id for a terminal synthesis packet"
                )
            steward_packet_binding = _steward_packet_binding(
                state, args.execution_selection_id, args.steward_packet_id
            )
            synthesis_packet = _packet_by_id(state, args.steward_packet_id)
            authority_errors = packet_authority_integrity_errors(
                paths, state, synthesis_packet, require_origin=False
            )
            result_errors = packet_result_integrity_errors(
                paths,
                state,
                synthesis_packet,
            )
            specialist_errors = selection_done_packet_authority_errors(
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
            steward_packet_binding = _steward_packet_binding(
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
        bindings = _selection_terminal_packet_bindings(
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
            "recording_steward_snapshot": _lane_authority_snapshot(steward),
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
            "authority_boundary": COOPERATIVE_AUTHORITY_BOUNDARY,
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
                "recommendation": _clip_critical(item.get("recommendation")),
            }
            for item in state.get("execution_briefs", [])[-4:]
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
            "subagent_spawn_incidents": max(
                0, len(open_spawn_incidents) - 8
            ),
            "execution_briefs": max(
                0, len(state.get("execution_briefs", [])) - 4
            ),
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
        elif args.review_packet_id:
            raise HarnessError(
                "--review-packet-id is accepted only for independent_review verification"
            )
        artifact_refs = preserve_bound_artifacts(
            paths, args.task, prepared_artifact_refs
        )
        item = {
            "integrity_version": 1,
            "artifact_snapshot_version": 1,
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
        collisions: list[str] = []
        for other in state.get("packets", []):
            if other.get("status") != "armed":
                continue
            attempt = _active_dispatch_attempt(other)
            if (
                attempt.get("parent_session_id") == parent_session_id
                and attempt.get("expected_agent_type") == expected_agent_type
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
        state["dispatch_model_version"] = 1
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
    if (
        attempt.get("parent_session_id") != parent_session_id
        or attempt.get("expected_agent_type") != transport_agent_type
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
        incident["resolution"] = {
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
        text += f"\n## AOI dispatch authority\n\n{NATIVE_V5_PACKET_CONTRACT_MARKER}\n"
        if resource_envelope_sha256:
            text += (
                "\n## AOI resource authority\n\n"
                f"- Execution selection: `{selection.get('selection_id', '')}`\n"
                f"- Resource envelope SHA-256: `{resource_envelope_sha256}`\n"
                "- Requested model routing remains unverified until observed.\n"
            )
        if command_record:
            text += (
                "\n## Exact command authority\n\n"
                f"- Path: `{command_record['command_path']}`\n"
                f"- SHA-256: `{command_record['command_sha256']}`\n"
                f"- Size: `{command_record['command_size_bytes']}` bytes\n"
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
        state["dispatch_model_version"] = 1
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
                state["dispatch_model_version"] = 1
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
            and _packet_schema_version(packet) < 5
            and not packet.get("dispatch_provenance")
        ):
            packet["dispatch_provenance"] = "legacy_unverified"
        if agent_id:
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
    failures.extend(subagent_incident_integrity_errors(state))
    failures.extend(packet_recovery_integrity_errors(paths, state))
    failures.extend(job_integrity_errors(paths, state))
    failures.extend(verification_integrity_errors(paths, state))
    _provider_reports, provider_errors, _provider_warnings = context_receipt_reports(
        paths, state, evaluate_live=True
    )
    failures.extend(provider_errors)
    failures.extend(context_benchmark_integrity_errors(paths, state))
    failures.extend(portfolio_integrity_errors(state, paths))
    failures.extend(override_integrity_errors(state))
    failures.extend(resource_config_integrity_errors(paths, state))
    failures.extend(resource_envelope_integrity_errors(state))
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
        for item in state.get("subagent_incidents", [])
        if item.get("status") == "open"
    ]
    if open_spawn_incidents:
        failures.append(
            "unaccounted sub-agent spawn incidents: "
            + ", ".join(open_spawn_incidents)
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
            for item in state.get("subagent_incidents", [])
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
            claims = []
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
        for incident in task.get("subagent_incidents", []):
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
            for verification_index, item in enumerate(
                task.get("verification", []), start=1
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
                for item in task.get("verification", [])
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

    if paths.project.codex_hooks_enabled:
        config_path = paths.root / ".codex" / "config.toml"
        hook_path = paths.root / ".codex" / "hooks.json"
        if not config_path.exists():
            errors.append(f"Codex hooks are enabled but config is missing: {config_path}")
        else:
            try:
                hook_config = tomllib.loads(config_path.read_text(encoding="utf-8"))
                if hook_config.get("features", {}).get("hooks") is not True:
                    errors.append(f"hooks feature is not enabled in {config_path}")
            except (OSError, tomllib.TOMLDecodeError) as exc:
                errors.append(f"invalid TOML {config_path}: {exc}")
        if not hook_path.exists():
            errors.append(f"Codex hooks are enabled but definition is missing: {hook_path}")
        else:
            _check_json_file(hook_path, errors)
            try:
                hook_payload = load_json(hook_path)
            except HarnessError:
                hook_payload = {}
            expected_events = {"SessionStart", "UserPromptSubmit", "SubagentStart", "Stop"}
            hooks = hook_payload.get("hooks", {})
            if set(hooks) != expected_events:
                errors.append(f"unexpected hook event set in {hook_path}: {sorted(hooks)}")
            else:
                for event in expected_events:
                    entries = hooks.get(event, [])
                    if len(entries) != 1 or len(entries[0].get("hooks", [])) != 1:
                        errors.append(f"{hook_path} must have exactly one handler for {event}")
                        continue
                    handler = entries[0]["hooks"][0]
                    if handler.get("type") != "command":
                        errors.append(f"{hook_path} {event} handler is not a command")
                    if handler.get("timeout", 0) < 30:
                        errors.append(f"{hook_path} {event} timeout is below 30 seconds")
                    for key in ("command", "commandWindows"):
                        command = str(handler.get(key, ""))
                        if "aoi-codex-hook" not in command:
                            errors.append(f"{hook_path} {event} {key} does not invoke AOI")
                        if f"--hook-version {HOOK_PROTOCOL_VERSION}" not in command:
                            errors.append(f"{hook_path} {event} {key} has wrong hook version")

    if paths.project.legacy_enabled:
        legacy_source = paths.root / "LEGACY_CONTROL.md"
        if not scoped and legacy_source.exists():
            try:
                parse_legacy_table(paths, legacy_source)
            except HarnessError as exc:
                errors.append(str(exc))

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

    register_chief_commands(
        sub,
        handlers={
            "chief_acquire": cmd_chief_acquire,
            "chief_renew": cmd_chief_renew,
            "chief_release": cmd_chief_release,
            "chief_takeover": cmd_chief_takeover,
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

    register_task_lifecycle_commands(
        sub,
        handlers={
            "init_task": cmd_init_task,
            "start_mini": cmd_start_mini,
            "approve_plan": cmd_approve_plan,
            "bind_session": cmd_bind_session,
            "unbind_session": cmd_unbind_session,
            "import_legacy": cmd_import_legacy,
            "check_locks": cmd_check_locks,
            "inspect_legacy": cmd_inspect_legacy,
            "claim": cmd_claim,
            "set_claim_status": cmd_set_claim_status,
            "release_claim": cmd_release_claim,
            "audit_legacy": cmd_audit_legacy,
            "set_phase": cmd_set_phase,
            "adopt_current_branch": cmd_adopt_current_branch,
            "checkpoint": cmd_checkpoint,
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

    register_execution_selection_commands(
        sub,
        handlers={
            "execution_select_plan": cmd_execution_select_plan,
            "execution_select": cmd_execution_select,
            "execution_brief_record": cmd_execution_brief_record,
        },
        add_json_argument=add_json_argument,
        vocab=vocab,
    )

    register_cross_lane_commands(
        sub,
        handlers={
            "cross_lane_open": cmd_cross_lane_open,
            "cross_lane_close": cmd_cross_lane_close,
            "cross_lane_cancel": cmd_cross_lane_cancel,
            "needs_user_create": cmd_needs_user_create,
            "needs_user_resolve": cmd_needs_user_resolve,
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
            "coordination_create": cmd_coordination_create,
            "coordination_update": cmd_coordination_update,
            "coordination_arbitrate": cmd_coordination_arbitrate,
            "coordination_directive_ack": cmd_coordination_directive_ack,
            "coordination_resolve": cmd_coordination_resolve,
            "coordination_implementation_submit": cmd_coordination_implementation_submit,
            "coordination_verify": cmd_coordination_verify,
            "baseline_freeze": cmd_baseline_freeze,
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

    register_status_commands(
        sub,
        handlers={
            "resume": cmd_resume,
            "status": cmd_status,
            "render_index": cmd_render_index,
        },
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


def _execute_project_command(
    args: argparse.Namespace, paths: HarnessPaths, *, initialized: bool
) -> int:
    command = str(args._aoi_command)
    args._aoi_initialized_at_dispatch = initialized
    if not command_requires_chief(command, initialized=initialized):
        return int(args.handler(args, paths))
    with state_lock(paths, create_layout=False):
        paths = _reload_locked_paths(paths)
        session_id, epoch, token, _credential_path = _chief_credential(args, paths)
        require_chief_authority(
            paths,
            session_id=session_id,
            epoch=epoch,
            token=token,
        )
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
        if command not in {"init", ""} and not initialized:
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
