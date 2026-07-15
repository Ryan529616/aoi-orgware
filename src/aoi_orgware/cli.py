#!/usr/bin/env python3
"""Plan/claim/delegate/verify/checkpoint CLI for AOI orgware."""

from __future__ import annotations

import sys

# Prevent importing the local harness library from creating workspace bytecode.
sys.dont_write_bytecode = True

import argparse
import copy
import datetime as dt
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
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from . import __version__
from . import dispatch_protocol as dispatch_protocol_impl
from . import resource_governance as resource_governance_impl
from .commands.resource import register_resource_commands
from .codebase_memory import (
    FRESHNESS_PROFILES as CODEBASE_MEMORY_FRESHNESS_PROFILES,
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
    TASK_PHASES,
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
EXECUTION_POLICY_VERSION = 2
TASK_EXECUTION_SCHEMA_VERSION = 2
NATIVE_V5_PACKET_CONTRACT_MARKER = "- AOI dispatch schema origin: `native_v5`"
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
FULL_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")
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
BOUND_ARTIFACT_MAX_COUNT = 64
BOUND_ARTIFACT_TOTAL_MAX_BYTES = 64 * 1024 * 1024
RECOVERY_TAR_MAX_MEMBERS = 4096
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


def _is_canonical_snapshot_version(value: Any) -> bool:
    return _is_exact_int(value, 1)


def _is_legacy_snapshot_version(value: Any) -> bool:
    return value is None or _is_exact_int(value, 0)


def _packet_schema_version(packet: dict[str, Any]) -> int | None:
    value = packet.get("packet_schema_version", 0)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return None
    return value


SUPERSESSION_MUTATION_FIELDS = {
    "supersession_version",
    "source_record_sha256",
    "original_status",
    "superseded_at",
    "supersession_reason",
    "replacement_index",
    "replacement_record_sha256",
    "replacement_materialization",
}


def verification_source_preimage(record: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct the exact verification record before supersession mutation."""

    preimage = copy.deepcopy(record)
    original_status = preimage.get("original_status")
    for field in SUPERSESSION_MUTATION_FIELDS:
        preimage.pop(field, None)
    preimage["status"] = original_status
    return preimage


def verification_legacy_seal_preimage(record: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct the legacy supersession record immediately before sealing."""

    preimage = copy.deepcopy(record)
    for field in (
        "supersession_version",
        "source_record_sha256",
        "replacement_materialization",
    ):
        preimage.pop(field, None)
    return preimage


def verification_legacy_materialization_preimage(
    record: dict[str, Any],
) -> dict[str, Any]:
    """Reconstruct a legacy live-ref record from canonical snapshot refs."""

    preimage = copy.deepcopy(record)
    refs: list[dict[str, Any]] = []
    for artifact in preimage.get("artifact_refs", []):
        if not _is_canonical_snapshot_version(artifact.get("snapshot_version")):
            raise HarnessError(
                "replacement materialization preimage requires canonical snapshots"
            )
        source_path = str(artifact.get("source_path", ""))
        if not Path(source_path).is_absolute():
            raise HarnessError("canonical snapshot lacks an absolute legacy source path")
        refs.append(
            {
                "path": source_path,
                "sha256": artifact.get("sha256"),
                "size_bytes": artifact.get("size_bytes"),
            }
        )
    preimage["artifact_refs"] = refs
    preimage.pop("artifact_snapshot_version", None)
    return preimage


def read_regular_artifact(
    value: str | Path,
    label: str,
    *,
    max_bytes: int,
    require_utf8: bool = False,
) -> tuple[Path, bytes]:
    """Read one stable regular file without following a final-component symlink."""
    source = canonicalize_no_link_traversal(
        Path(value).expanduser(), f"{label} path"
    )
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
    # Windows low-level descriptors default to text mode, which silently
    # translates CRLF to LF and breaks physical SHA-256 identity. Always read
    # artifacts as exact bytes on every platform.
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
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
        finished = os.fstat(descriptor)
        if (
            finished.st_size != opened.st_size
            or getattr(finished, "st_mtime_ns", None)
            != getattr(opened, "st_mtime_ns", None)
        ):
            raise HarnessError(f"{label} changed while it was being read")
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
    if canonicalize_no_link_traversal(source, f"{label} path") != source:
        raise HarnessError(f"{label} path changed while it was being read")
    return source, data


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
        raise HarnessError(
            f"{label} SHA-256 mismatch: expected {expected}, actual {actual}"
        )
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


def artifact_blob_path(paths: HarnessPaths, task_id: str, digest: str) -> Path:
    """Return the canonical task-local path for one content-addressed artifact."""

    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise HarnessError("artifact blob SHA-256 must be full 64 hex")
    return task_dir(paths, task_id) / "results" / "artifact-blobs" / digest[:2] / digest


def ensure_artifact_blob_parent(
    paths: HarnessPaths, task_id: str, digest: str, *, create: bool
) -> Path:
    """Validate every managed blob ancestor and optionally create missing dirs."""

    destination = artifact_blob_path(paths, task_id, digest)
    boundary = paths.root
    try:
        relative_parent = destination.parent.relative_to(boundary)
    except ValueError as exc:
        raise HarnessError("artifact blob path escapes the harness root") from exc
    current = boundary
    for part in relative_parent.parts:
        parent = current
        current = current / part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            if not create:
                raise HarnessError(f"artifact blob ancestor is missing: {current}")
            try:
                os.mkdir(current, 0o700)
                fsync_directory(parent)
            except FileExistsError:
                pass
            metadata = os.lstat(current)
        is_junction = bool(getattr(current, "is_junction", lambda: False)())
        is_reparse = os.name == "nt" and bool(
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
        if (
            stat.S_ISLNK(metadata.st_mode)
            or is_junction
            or is_reparse
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise HarnessError(
                f"artifact blob ancestor must be a real directory: {current}"
            )
    return destination.parent


def prepare_bound_artifacts(
    values: Iterable[str],
    label: str,
) -> list[dict[str, Any]]:
    """Safely read and SHA-bind a bounded set of artifacts before state mutation."""

    raw_values = list(values)
    if len(raw_values) > BOUND_ARTIFACT_MAX_COUNT:
        raise HarnessError(
            f"{label} accepts at most {BOUND_ARTIFACT_MAX_COUNT} artifacts"
        )
    prepared: list[dict[str, Any]] = []
    total_bytes = 0
    for index, value in enumerate(raw_values, start=1):
        path_text, separator, digest = value.rpartition("=")
        if not separator:
            raise HarnessError(f"{label} must use absolute-path=sha256")
        digest = digest.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise HarnessError(f"{label} SHA-256 must be full 64 hex")
        source, data = read_regular_artifact(
            path_text,
            f"{label} #{index}",
            max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
        )
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise HarnessError(
                f"{label} #{index} SHA-256 mismatch: expected {digest}, actual {actual}"
            )
        total_bytes += len(data)
        if total_bytes > BOUND_ARTIFACT_TOTAL_MAX_BYTES:
            raise HarnessError(
                f"{label} aggregate size exceeds {BOUND_ARTIFACT_TOTAL_MAX_BYTES} bytes"
            )
        prepared.append(
            {
                "source_path": str(source),
                "sha256": actual,
                "size_bytes": len(data),
                "data": data,
            }
        )
    return prepared


def preserve_bound_artifacts(
    paths: HarnessPaths,
    task_id: str,
    prepared: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Create or safely reuse canonical content-addressed task artifact blobs."""

    preserved: list[dict[str, Any]] = []
    for item in prepared:
        digest = str(item["sha256"])
        data = bytes(item["data"])
        destination = artifact_blob_path(paths, task_id, digest)
        ensure_artifact_blob_parent(paths, task_id, digest, create=True)
        if destination.exists():
            _, existing = read_regular_artifact(
                destination,
                "existing task artifact blob",
                max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
            )
            if hashlib.sha256(existing).hexdigest() != digest or existing != data:
                raise HarnessError(
                    f"canonical task artifact blob is missing or tampered: {destination}"
                )
        else:
            try:
                atomic_create_bytes(destination, data)
            except HarnessError:
                if not destination.exists():
                    raise
                _, existing = read_regular_artifact(
                    destination,
                    "concurrently published task artifact blob",
                    max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
                )
                if hashlib.sha256(existing).hexdigest() != digest or existing != data:
                    raise
        preserved.append(
            {
                "snapshot_version": 1,
                "source_path": str(item["source_path"]),
                "path": str(destination),
                "sha256": digest,
                "size_bytes": len(data),
            }
        )
    return preserved


def canonical_recovery_archive_member(member_name: str) -> str:
    """Return the canonical relative POSIX member name used in recovery receipts."""

    member_name = require_text(member_name, "recovery archive member")
    member_path = PurePosixPath(member_name)
    if (
        "\\" in member_name
        or member_path.is_absolute()
        or member_path.as_posix() != member_name
        or any(part in {"", ".", ".."} for part in member_path.parts)
    ):
        raise HarnessError("recovery archive member must be a canonical relative POSIX path")
    return member_name


def read_recovery_tar_member(
    archive_data: bytes,
    member_name: str,
    *,
    budget: dict[str, int] | None = None,
) -> bytes:
    """Read one exact regular member from a bounded in-memory tar archive."""

    member_name = canonical_recovery_archive_member(member_name)
    if budget is None:
        budget = {
            "decompressed_bytes": 0,
            "member_count": 0,
            "declared_bytes": 0,
            "extracted_bytes": 0,
        }
    required_budget_fields = {
        "decompressed_bytes",
        "member_count",
        "declared_bytes",
        "extracted_bytes",
    }
    if set(budget) != required_budget_fields or any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in budget.values()
    ):
        raise HarnessError("recovery archive replay budget is invalid")
    try:
        remaining_decompressed = (
            BOUND_ARTIFACT_TOTAL_MAX_BYTES - budget["decompressed_bytes"]
        )
        if remaining_decompressed < 0:
            raise HarnessError("recovery archive aggregate decompressed budget is exceeded")
        if archive_data.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=io.BytesIO(archive_data), mode="rb") as stream:
                tar_data = stream.read(remaining_decompressed + 1)
        else:
            tar_data = archive_data[: remaining_decompressed + 1]
        if len(tar_data) > remaining_decompressed:
            raise HarnessError(
                "recovery archive aggregate decompressed budget is exceeded"
            )
        budget["decompressed_bytes"] += len(tar_data)
        with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:") as archive:
            match: tarfile.TarInfo | None = None
            for candidate in archive:
                budget["member_count"] += 1
                if budget["member_count"] > RECOVERY_TAR_MAX_MEMBERS:
                    raise HarnessError(
                        "recovery archive aggregate member budget is exceeded"
                    )
                if candidate.isfile():
                    if candidate.size < 0 or candidate.size > TERMINAL_ARTIFACT_MAX_BYTES:
                        raise HarnessError(
                            "recovery archive contains a file outside the size bound"
                        )
                    budget["declared_bytes"] += candidate.size
                    if budget["declared_bytes"] > BOUND_ARTIFACT_TOTAL_MAX_BYTES:
                        raise HarnessError(
                            "recovery archive aggregate declared-size budget is exceeded"
                        )
                if candidate.name == member_name:
                    if match is not None:
                        raise HarnessError("recovery archive member name is duplicated")
                    match = candidate
            if match is None:
                raise HarnessError("recovery archive member is missing")
            if not match.isfile() or match.issym() or match.islnk():
                raise HarnessError("recovery archive member must be a regular file")
            if match.size <= 0 or match.size > TERMINAL_ARTIFACT_MAX_BYTES:
                raise HarnessError("recovery archive member size is outside the allowed bound")
            stream = archive.extractfile(match)
            if stream is None:
                raise HarnessError("recovery archive member cannot be read")
            remaining_extracted = (
                BOUND_ARTIFACT_TOTAL_MAX_BYTES - budget["extracted_bytes"]
            )
            if remaining_extracted < match.size:
                raise HarnessError("recovery archive aggregate extraction budget is exceeded")
            data = stream.read(min(TERMINAL_ARTIFACT_MAX_BYTES, remaining_extracted) + 1)
            if len(data) != match.size:
                raise HarnessError("recovery archive member size does not match its header")
            budget["extracted_bytes"] += len(data)
            return data
    except HarnessError:
        raise
    except (tarfile.TarError, gzip.BadGzipFile, zlib.error, OSError, EOFError) as exc:
        raise HarnessError(f"recovery archive is invalid: {exc}") from exc


def recovery_record_preimage(
    state: dict[str, Any],
    packet: dict[str, Any],
    target_index: int,
    target: dict[str, Any],
    carrier_index: int,
    carrier: dict[str, Any],
    recovery: dict[str, Any],
) -> dict[str, Any]:
    """Build the sealed semantic preimage for one packet-bound recovery."""

    return {
        "task_id": state.get("task_id"),
        "packet_id": packet.get("packet_id"),
        "packet_schema_version": packet.get("packet_schema_version"),
        "target_input_index": target_index + 1,
        "target_source_path": target.get("source_path"),
        "target_sha256": target.get("sha256"),
        "target_size_bytes": target.get("size_bytes"),
        "carrier_input_index": carrier_index + 1,
        "carrier_sha256": carrier.get("sha256"),
        "carrier_size_bytes": carrier.get("size_bytes"),
        "archive_member": recovery.get("archive_member"),
        "packet_result_sha256": recovery.get("packet_result_sha256"),
        "reason": recovery.get("reason"),
        "recovered_at": recovery.get("recovered_at"),
    }


def artifact_ref_integrity_error(
    paths: HarnessPaths,
    state: dict[str, Any],
    artifact: dict[str, Any],
    *,
    require_origin: bool,
) -> str | None:
    """Validate a legacy live ref or a canonical snapshot without mutating state."""

    digest = str(artifact.get("sha256", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        return "artifact SHA-256 is invalid"
    expected_size = artifact.get("size_bytes")
    if (
        not isinstance(expected_size, int)
        or isinstance(expected_size, bool)
        or expected_size <= 0
    ):
        return "artifact size is invalid"
    snapshot_version = artifact.get("snapshot_version")
    if _is_canonical_snapshot_version(snapshot_version):
        expected_path = artifact_blob_path(paths, state["task_id"], digest)
        recorded_path = Path(str(artifact.get("path", "")))
        if recorded_path != expected_path:
            return "artifact snapshot path is not canonical"
        try:
            ensure_artifact_blob_parent(
                paths, state["task_id"], digest, create=False
            )
        except HarnessError as exc:
            return str(exc)
        try:
            _, data = read_regular_artifact(
                recorded_path,
                "artifact snapshot",
                max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
            )
        except HarnessError as exc:
            return str(exc)
        if len(data) != expected_size or hashlib.sha256(data).hexdigest() != digest:
            return "artifact snapshot identity mismatch"
        if require_origin:
            source_path = Path(str(artifact.get("source_path", "")))
            if not source_path.is_absolute():
                return "artifact source path is not absolute"
            try:
                _, source_data = read_regular_artifact(
                    source_path,
                    "artifact source",
                    max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
                )
            except HarnessError as exc:
                return str(exc)
            if (
                len(source_data) != expected_size
                or hashlib.sha256(source_data).hexdigest() != digest
            ):
                return "artifact source changed after snapshot creation"
        return None
    if not _is_legacy_snapshot_version(snapshot_version):
        return "artifact snapshot version is unsupported"
    legacy_path = Path(str(artifact.get("path", "")))
    try:
        _, data = read_regular_artifact(
            legacy_path,
            "legacy artifact reference",
            max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
        )
    except HarnessError as exc:
        return str(exc)
    if len(data) != expected_size or hashlib.sha256(data).hexdigest() != digest:
        return "legacy artifact reference identity mismatch"
    return None


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
    _require_execution_selection_snapshots_current(state, selection)
    return selection


def _require_execution_selection_snapshots_current(
    state: dict[str, Any], selection: dict[str, Any], *, include_steward: bool = False
) -> None:
    snapshots = {
        str(item.get("lane_id")): item
        for item in selection.get("lane_snapshots", [])
    }
    steward_snapshot = selection.get("steward_snapshot", {})
    if (
        include_steward
        and isinstance(steward_snapshot, dict)
        and steward_snapshot.get("lane_id")
    ):
        snapshots[str(steward_snapshot["lane_id"])] = steward_snapshot
    for selected_lane_id, snapshot in snapshots.items():
        lane = lane_by_id(state, selected_lane_id)
        if any(
            snapshot.get(field) != lane.get(field)
            for field in ("revision", "authority_commit", "contract_version")
        ):
            raise HarnessError(
                "execution selection is stale; select topology again before dispatch"
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


def _is_steward_synthesis_packet(packet: dict[str, Any]) -> bool:
    return packet.get("packet_purpose") == "steward_synthesis"


def _selection_synthesis_freeze_packet_ids(
    state: dict[str, Any], selection_id: str
) -> list[str]:
    return sorted(
        str(packet.get("packet_id", ""))
        for packet in state.get("packets", [])
        if packet.get("execution_selection_id") == selection_id
        and _is_steward_synthesis_packet(packet)
        and packet.get("status") not in {"failed", "cancelled"}
    )


def _validate_steward_synthesis_dispatch(
    state: dict[str, Any], packet: dict[str, Any]
) -> dict[str, Any]:
    selection_id = str(packet.get("execution_selection_id", ""))
    selection = execution_selection_by_id(state, selection_id)
    if (
        selection.get("status") != "active"
        or not _is_exact_int(selection.get("execution_selection_version"), 2)
        or selection.get("mode") not in {"centralized_parallel", "hybrid"}
    ):
        raise HarnessError(
            "Steward synthesis requires an active parallel/hybrid selection v2"
        )
    selected_steward = selection.get("steward_snapshot", {})
    current_steward = _engaged_steward_lane(state)
    if (
        not isinstance(selected_steward, dict)
        or not selected_steward
        or packet.get("lane_id") != selected_steward.get("lane_id")
        or packet.get("steward_selection_snapshot") != selected_steward
        or packet.get("steward_execution_snapshot")
        != _lane_authority_snapshot(current_steward)
    ):
        raise HarnessError("Steward synthesis authority snapshot is stale or mismatched")
    bindings = _selection_terminal_packet_bindings(state, selection_id)
    if not bindings or packet.get("steward_input_bindings") != bindings:
        raise HarnessError("Steward synthesis specialist result bindings are stale")
    selected_lane_ids = {
        str(item.get("lane_id", "")) for item in selection.get("lane_snapshots", [])
    }
    if {item["lane_id"] for item in bindings} != selected_lane_ids:
        raise HarnessError(
            "Steward synthesis requires terminal specialist evidence from every selected lane"
        )
    unfinished = [
        str(item.get("packet_id", ""))
        for item in state.get("packets", [])
        if item.get("packet_id") != packet.get("packet_id")
        and item.get("execution_selection_id") == selection_id
        and not _is_steward_synthesis_packet(item)
        and item.get("status") in ACTIVE_PACKET_STATUSES
    ]
    active_jobs = [
        str(item.get("run_id", ""))
        for item in state.get("jobs", [])
        if item.get("execution_selection_id") == selection_id
        and item.get("status") in ACTIVE_JOB_STATUSES
    ]
    if unfinished or active_jobs:
        raise HarnessError(
            "Steward synthesis requires terminal specialist work: "
            + ", ".join(unfinished + active_jobs)
        )
    return selection


def _validate_dispatch_selection(
    state: dict[str, Any], packet: dict[str, Any]
) -> dict[str, Any] | None:
    """Validate the exact topology contract used by a packet activation."""

    if _is_steward_synthesis_packet(packet):
        return _validate_steward_synthesis_dispatch(state, packet)
    selection = _validate_active_execution_selection(
        state,
        str(packet.get("lane_id", "")),
        str(packet.get("execution_selection_id", "")),
    )
    if selection is None:
        return None
    if not _is_exact_int(selection.get("execution_selection_version"), 2):
        raise HarnessError(
            "packet activation requires execution selection v2; supersede the legacy selection"
        )
    mode = str(selection.get("mode", ""))
    steward_snapshot = selection.get("steward_snapshot", {})
    if mode == "single":
        if steward_snapshot not in ({}, None):
            raise HarnessError("single execution selection may not carry a Steward snapshot")
        return selection
    if mode not in {"centralized_parallel", "hybrid"}:
        raise HarnessError("execution selection has an invalid dispatch mode")
    if not isinstance(steward_snapshot, dict) or not steward_snapshot:
        raise HarnessError("parallel execution selection lacks its Steward snapshot")
    steward = _engaged_steward_lane(state)
    if steward_snapshot != _lane_authority_snapshot(steward):
        raise HarnessError(
            "execution selection Steward snapshot is stale; select topology again"
        )
    selected_lane_ids = {
        str(item.get("lane_id", "")) for item in selection.get("lane_snapshots", [])
    }
    if steward["lane_id"] in selected_lane_ids:
        raise HarnessError("parallel specialist lanes may not include the Steward lane")
    return selection


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


def _validate_packet_activation_topology(
    state: dict[str, Any], packet: dict[str, Any]
) -> dict[str, Any] | None:
    """Fence active packet chains; ready packets remain pre-buildable."""

    selection = _validate_dispatch_selection(state, packet)
    _validate_packet_resource_envelope(
        state,
        packet,
        selection,
        enforce_active_limit=False,
    )
    packet_id = str(packet.get("packet_id", ""))
    depth = int(packet.get("delegation_depth", 1))
    executing = [
        item
        for item in state.get("packets", [])
        if item.get("packet_id") != packet_id
        and item.get("status") in EXECUTING_PACKET_STATUSES
    ]
    standalone_jobs = [
        item
        for item in state.get("jobs", [])
        if item.get("status") in ACTIVE_JOB_STATUSES
        and not str(item.get("owner_packet_id", ""))
    ]

    def chain_names(
        packets: list[dict[str, Any]], jobs: list[dict[str, Any]]
    ) -> str:
        return ", ".join(
            [str(item.get("packet_id")) for item in packets]
            + [f"job:{item.get('run_id')}" for item in jobs]
        )

    selection_id = str(packet.get("execution_selection_id", ""))
    lane_id = str(packet.get("lane_id", ""))
    if depth == 1:
        peers = [
            item
            for item in executing
            if int(item.get("delegation_depth", 1)) == 1
        ]
        if _is_steward_synthesis_packet(packet):
            if peers or standalone_jobs:
                raise HarnessError(
                    "Steward synthesis is sequential and requires an empty task execution epoch: "
                    + chain_names(peers, standalone_jobs)
                )
            return selection
        if _execution_policy_v2_enabled(state):
            synthesis_peers = [
                item for item in peers if _is_steward_synthesis_packet(item)
            ]
            if synthesis_peers:
                raise HarnessError(
                    "Steward synthesis already occupies the sequential execution phase: "
                    + ", ".join(
                        str(item.get("packet_id")) for item in synthesis_peers
                    )
                )
            if selection is None:
                if peers or standalone_jobs:
                    raise HarnessError(
                        "implicit single execution already has an active depth-one "
                        "packet chain: "
                        + chain_names(peers, standalone_jobs)
                    )
                return None
            foreign = [
                item
                for item in peers
                if str(item.get("execution_selection_id", "")) != selection_id
            ]
            if foreign:
                raise HarnessError(
                    "task-global execution epoch is already occupied by another "
                    "selection/implicit chain: "
                    + ", ".join(str(item.get("packet_id")) for item in foreign)
                )
            foreign_jobs = [
                item
                for item in standalone_jobs
                if str(item.get("execution_selection_id", "")) != selection_id
            ]
            if foreign_jobs:
                raise HarnessError(
                    "task-global execution epoch is already occupied by another "
                    "selection/implicit job chain: "
                    + chain_names([], foreign_jobs)
                )
            mode = str(selection.get("mode", "single"))
            if mode == "single" and (peers or standalone_jobs):
                raise HarnessError(
                    "single execution mode already has an active depth-one packet chain: "
                    + chain_names(peers, standalone_jobs)
                )
            if mode in {"centralized_parallel", "hybrid"}:
                same_lane = [item for item in peers if item.get("lane_id") == lane_id]
                same_lane_jobs = [
                    item for item in standalone_jobs if item.get("lane_id") == lane_id
                ]
                if same_lane or same_lane_jobs:
                    raise HarnessError(
                        "parallel execution mode already has an active depth-one chain in lane "
                        f"{lane_id}: "
                        + chain_names(same_lane, same_lane_jobs)
                    )
            return selection
        if selection is None:
            # Legacy/unselected tasks retain their prior cooperative behavior.
            # Once a task selects topology, v2 activation rules are mandatory.
            return None
        peers = [
            item
            for item in executing
            if int(item.get("delegation_depth", 1)) == 1
            and str(item.get("execution_selection_id", "")) == selection_id
        ]
        selection_jobs = [
            item
            for item in standalone_jobs
            if str(item.get("execution_selection_id", "")) == selection_id
        ]
        mode = str(selection.get("mode", "single")) if selection else "single"
        if mode == "single" and (peers or selection_jobs):
            raise HarnessError(
                "single execution mode already has an active depth-one packet chain: "
                + chain_names(peers, selection_jobs)
            )
        if mode in {"centralized_parallel", "hybrid"}:
            same_lane = [item for item in peers if item.get("lane_id") == lane_id]
            same_lane_jobs = [
                item for item in selection_jobs if item.get("lane_id") == lane_id
            ]
            if same_lane or same_lane_jobs:
                raise HarnessError(
                    "parallel execution mode already has an active depth-one chain in lane "
                    f"{lane_id}: "
                    + chain_names(same_lane, same_lane_jobs)
                )
        return selection
    if depth != 2:
        raise HarnessError("packet delegation depth is invalid")
    parent_id = str(packet.get("parent_packet_id", ""))
    parent = _packet_by_id(state, parent_id)
    if (
        parent.get("status") != "dispatched"
        or int(parent.get("delegation_depth", 1)) != 1
        or str(parent.get("lane_id", "")) != lane_id
        or str(parent.get("execution_selection_id", "")) != selection_id
    ):
        raise HarnessError(
            "depth-two activation requires its dispatched depth-one parent in the same lane"
        )
    siblings = [
        item
        for item in executing
        if int(item.get("delegation_depth", 1)) == 2
        and item.get("parent_packet_id") == parent_id
    ]
    if siblings:
        raise HarnessError(
            "depth-two parent already has an active child: "
            + ", ".join(str(item.get("packet_id")) for item in siblings)
        )
    return selection


def _validate_owned_job_authority(
    paths: HarnessPaths | None,
    state: dict[str, Any],
    job: dict[str, Any],
    *,
    require_dispatched: bool,
) -> dict[str, Any]:
    """Recompute the physical and semantic authority for one owned job."""

    run_id = str(job.get("run_id", ""))
    owner_packet_id = str(job.get("owner_packet_id", ""))
    owner = _packet_by_id(state, owner_packet_id)
    if (
        int(owner.get("delegation_depth", 1)) != 1
        or _is_steward_synthesis_packet(owner)
        or owner.get("packet_mode") not in {"bounded_mutation", "exact_command"}
        or str(owner.get("lane_id", "")) != str(job.get("lane_id", ""))
        or str(owner.get("execution_selection_id", ""))
        != str(job.get("execution_selection_id", ""))
    ):
        raise HarnessError(
            "external job owner must be a depth-one mutation packet in the same "
            "lane and execution selection"
        )
    if require_dispatched and owner.get("status") != "dispatched":
        raise HarnessError("active external job owner packet is not dispatched")
    if job.get("owner_packet_contract_sha256") != owner.get(
        "packet_contract_sha256", ""
    ):
        raise HarnessError("external job owner packet contract binding changed")
    if paths is not None:
        authority_errors = packet_authority_integrity_errors(
            paths,
            state,
            owner,
            require_origin=False,
        )
        if authority_errors:
            raise HarnessError(
                "external job owner packet authority is missing or tampered: "
                + "; ".join(authority_errors)
            )
        namespace = paths.project.external_lock_namespace
        if job.get("external_lock_namespace") != namespace:
            raise HarnessError(
                f"external job {run_id} lost its external lock namespace binding"
            )
        required_output_locks = [
            f"{namespace}:tree:{job.get('work_root', '')}",
            f"{namespace}:file:{job.get('log', '')}",
        ]
        if job.get("required_output_locks") != required_output_locks:
            raise HarnessError(
                f"external job {run_id} required output locks are non-canonical or changed"
            )
        uncovered = [
            lock
            for lock in required_output_locks
            if not any(
                lock_covers(held, lock) for held in owner.get("locks", [])
            )
        ]
        if uncovered:
            raise HarnessError(
                "external job output paths exceed the owner packet locks: "
                + ", ".join(uncovered)
            )
    if (
        owner.get("packet_mode") == "exact_command"
        and owner.get("command_sha256") != job.get("command_sha256")
    ):
        raise HarnessError(
            "external job command differs from its exact-command owner packet"
        )
    return owner


def _validate_job_activation_topology(
    state: dict[str, Any],
    job: dict[str, Any],
    selection: dict[str, Any] | None,
    *,
    paths: HarnessPaths | None = None,
    exclude_run_id: str = "",
) -> dict[str, Any] | None:
    """Bind an external job to one depth-one chain or make it that chain."""

    selection_id = str(job.get("execution_selection_id", ""))
    lane_id = str(job.get("lane_id", ""))
    owner_packet_id = str(job.get("owner_packet_id", ""))
    if owner_packet_id:
        owner = _validate_owned_job_authority(
            paths, state, job, require_dispatched=True
        )
        _validate_packet_activation_topology(state, owner)
        return selection

    packet_chains = [
        packet
        for packet in state.get("packets", [])
        if packet.get("status") in EXECUTING_PACKET_STATUSES
        and int(packet.get("delegation_depth", 1)) == 1
    ]
    job_chains = [
        item
        for item in state.get("jobs", [])
        if item.get("status") in ACTIVE_JOB_STATUSES
        and not str(item.get("owner_packet_id", ""))
        and str(item.get("run_id", "")) != exclude_run_id
    ]

    def names(
        packets: list[dict[str, Any]], jobs: list[dict[str, Any]]
    ) -> str:
        return ", ".join(
            [f"packet:{item.get('packet_id')}" for item in packets]
            + [f"job:{item.get('run_id')}" for item in jobs]
        )

    if _execution_policy_v2_enabled(state):
        if selection is None:
            if packet_chains or job_chains:
                raise HarnessError(
                    "implicit single execution already has an active chain: "
                    + names(packet_chains, job_chains)
                )
            return None
        foreign_packets = [
            item
            for item in packet_chains
            if str(item.get("execution_selection_id", "")) != selection_id
        ]
        foreign_jobs = [
            item
            for item in job_chains
            if str(item.get("execution_selection_id", "")) != selection_id
        ]
        if foreign_packets or foreign_jobs:
            raise HarnessError(
                "task-global execution epoch is already occupied by another "
                "selection/implicit chain: "
                + names(foreign_packets, foreign_jobs)
            )
        mode = str(selection.get("mode", "single"))
        if mode == "single" and (packet_chains or job_chains):
            raise HarnessError(
                "single execution mode already has an active chain: "
                + names(packet_chains, job_chains)
            )
        if mode in {"centralized_parallel", "hybrid"}:
            same_lane_packets = [
                item for item in packet_chains if item.get("lane_id") == lane_id
            ]
            same_lane_jobs = [
                item for item in job_chains if item.get("lane_id") == lane_id
            ]
            if same_lane_packets or same_lane_jobs:
                raise HarnessError(
                    "parallel execution mode already has an active chain in lane "
                    f"{lane_id}: "
                    + names(same_lane_packets, same_lane_jobs)
                )
        return selection

    if selection is None:
        return None
    same_selection_packets = [
        item
        for item in packet_chains
        if str(item.get("execution_selection_id", "")) == selection_id
    ]
    same_selection_jobs = [
        item
        for item in job_chains
        if str(item.get("execution_selection_id", "")) == selection_id
    ]
    mode = str(selection.get("mode", "single"))
    if mode == "single" and (same_selection_packets or same_selection_jobs):
        raise HarnessError(
            "single execution mode already has an active chain: "
            + names(same_selection_packets, same_selection_jobs)
        )
    if mode in {"centralized_parallel", "hybrid"}:
        same_lane_packets = [
            item for item in same_selection_packets if item.get("lane_id") == lane_id
        ]
        same_lane_jobs = [
            item for item in same_selection_jobs if item.get("lane_id") == lane_id
        ]
        if same_lane_packets or same_lane_jobs:
            raise HarnessError(
                "parallel execution mode already has an active chain in lane "
                f"{lane_id}: "
                + names(same_lane_packets, same_lane_jobs)
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
    try:
        policy_v2 = _execution_policy_v2_enabled(state)
    except HarnessError as exc:
        errors.append(str(exc))
        policy_v2 = False
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
        selection_version = selection.get("execution_selection_version")
        if policy_v2 and not _is_exact_int(selection_version, 2):
            errors.append(
                f"execution selection {selection_id} is not sealed as version 2 "
                "under task execution policy v2"
            )
        elif selection_version is None and "steward_snapshot" in selection:
            errors.append(
                f"execution selection {selection_id} has v2-only fields without a selection version"
            )
        if selection_version is not None and not _is_exact_int(selection_version, 2):
            errors.append(
                f"execution selection {selection_id} has an invalid selection version"
            )
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
        if _is_exact_int(selection_version, 2):
            steward_snapshot = selection.get("steward_snapshot")
            if mode == "single" and steward_snapshot != {}:
                errors.append(
                    f"execution selection {selection_id} single mode carries a Steward snapshot"
                )
            if mode in {"centralized_parallel", "hybrid"}:
                if not isinstance(steward_snapshot, dict) or not steward_snapshot:
                    errors.append(
                        f"execution selection {selection_id} parallel mode lacks a Steward snapshot"
                    )
                else:
                    steward_lane_id = steward_snapshot.get("lane_id")
                    steward_matches = [
                        lane
                        for lane in state.get("lanes", [])
                        if lane.get("lane_id") == steward_lane_id
                    ]
                    if (
                        len(steward_matches) != 1
                        or steward_matches[0].get("kind") != "coordination_steward"
                        or steward_lane_id in snapshot_lane_ids
                    ):
                        errors.append(
                            f"execution selection {selection_id} has an invalid Steward binding"
                        )
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
    brief_ids: set[str] = set()
    for brief in state.get("execution_briefs", []):
        brief_id = str(brief.get("brief_id", ""))
        if brief_id in brief_ids:
            errors.append(f"duplicate execution brief id {brief_id}")
        brief_ids.add(brief_id)
        selection_id = str(brief.get("execution_selection_id", ""))
        selection = selection_by_id.get(selection_id)
        selected_steward = (
            selection.get("steward_snapshot", {})
            if isinstance(selection, dict)
            else {}
        )
        if not isinstance(selected_steward, dict):
            selected_steward = {}
        preimage = copy.deepcopy(brief)
        stored_sha = str(preimage.pop("brief_sha256", ""))
        brief_version = brief.get("brief_version")
        if (
            not _is_exact_int(brief.get("integrity_version"), 1)
            or not any(_is_exact_int(brief_version, version) for version in (1, 2, 3))
            or not re.fullmatch(r"[0-9a-f]{64}", stored_sha)
            or stored_sha != canonical_record_sha256(preimage)
        ):
            errors.append(f"execution brief {brief_id} lost integrity")
        if (
            selection is None
            or selection.get("mode") not in {"centralized_parallel", "hybrid"}
            or brief.get("mode") != selection.get("mode")
            or brief.get("steward_snapshot") != selection.get("steward_snapshot")
        ):
            errors.append(f"execution brief {brief_id} has an invalid selection binding")
        if not isinstance(brief.get("packet_bindings"), list):
            errors.append(f"execution brief {brief_id} packet bindings are malformed")
        if any(_is_exact_int(brief_version, version) for version in (2, 3)):
            recording_steward = brief.get("recording_steward_snapshot")
            if (
                not isinstance(recording_steward, dict)
                or recording_steward.get("lane_id")
                != selected_steward.get("lane_id")
            ):
                errors.append(
                    f"execution brief {brief_id} lacks its recording Steward binding"
                )
        if _is_exact_int(brief_version, 3):
            stored_binding = brief.get("steward_packet_binding")
            try:
                current_binding = _steward_packet_binding(
                    state,
                    selection_id,
                    str(stored_binding.get("packet_id", ""))
                    if isinstance(stored_binding, dict)
                    else "",
                )
            except HarnessError as exc:
                errors.append(
                    f"execution brief {brief_id} has an invalid Steward packet binding: {exc}"
                )
            else:
                if stored_binding != current_binding:
                    errors.append(
                        f"execution brief {brief_id} Steward packet binding is stale"
                    )
        if brief.get("root_session_id") not in state.get("session_ids", []):
            errors.append(f"execution brief {brief_id} lacks task-bound Chief session")
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
                is_steward_packet = (
                    record_kind == "packet"
                    and _is_steward_synthesis_packet(record)
                )
                selected_steward_snapshot = selection_by_id[selection_id].get(
                    "steward_snapshot", {}
                )
                selected_steward_lane = (
                    str(selected_steward_snapshot.get("lane_id", ""))
                    if isinstance(selected_steward_snapshot, dict)
                    else ""
                )
                if is_steward_packet:
                    lane_valid = record.get("lane_id") == selected_steward_lane
                else:
                    lane_valid = record.get("lane_id") in selection_lane_ids
                if not lane_valid:
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
    for packet in state.get("packets", []):
        if packet.get("status") not in EXECUTING_PACKET_STATUSES:
            continue
        try:
            _validate_packet_activation_topology(state, packet)
        except (HarnessError, TypeError, ValueError) as exc:
            errors.append(
                f"packet {packet.get('packet_id')} violates execution topology: {exc}"
            )
    for job in state.get("jobs", []):
        if job.get("status") not in ACTIVE_JOB_STATUSES:
            continue
        try:
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
        except (HarnessError, TypeError, ValueError) as exc:
            errors.append(
                f"job {job.get('run_id')} violates execution topology: {exc}"
            )
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
            raw_path == prefix.rstrip("/")
            or raw_path.startswith(prefix.rstrip("/") + "/")
            for prefix in MINI_FORBIDDEN_REPO_PREFIXES
        ):
            raise HarnessError(f"mini task may not own high-risk path: {raw_path}")
        if namespace == "host" and raw_path.casefold().endswith("/.codex/hooks.json"):
            raise HarnessError("mini task may not change trusted hook definitions")
    return locks


def state_worktree(paths: HarnessPaths, state: dict[str, Any]) -> Path:
    return validated_state_worktree(paths, state)


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


def packet_contract_integrity_error(
    paths: HarnessPaths, state: dict[str, Any], packet: dict[str, Any]
) -> str | None:
    schema_version = _packet_schema_version(packet)
    if schema_version is None:
        return f"packet {packet.get('packet_id')} schema version is invalid"
    if schema_version < 4:
        return None
    packet_id = str(packet.get("packet_id", ""))
    expected_path = task_dir(paths, state["task_id"]) / "packets" / f"{packet_id}.md"
    recorded_path = Path(str(packet.get("path", "")))
    expected_sha = str(packet.get("packet_contract_sha256", ""))
    if recorded_path != expected_path:
        return f"packet {packet_id} contract path is not canonical"
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        return f"packet {packet_id} contract SHA-256 is invalid"
    try:
        _, data = read_regular_artifact(
            recorded_path,
            "packet contract",
            max_bytes=COMMAND_ARTIFACT_MAX_BYTES,
            require_utf8=True,
        )
    except HarnessError as exc:
        return f"packet {packet_id} contract is missing or tampered: {exc}"
    if hashlib.sha256(data).hexdigest() != expected_sha:
        return f"packet {packet_id} contract SHA-256 mismatch"
    contract_lines = data.decode("utf-8").splitlines()
    resource_digest = str(packet.get("resource_envelope_sha256", ""))
    resource_digest_lines = [
        line
        for line in contract_lines
        if line.startswith("- Resource envelope SHA-256:")
    ]
    if resource_digest:
        expected_resource_digest_line = (
            f"- Resource envelope SHA-256: `{resource_digest}`"
        )
        expected_selection_line = (
            "- Execution selection: "
            f"`{packet.get('execution_selection_id', '')}`"
        )
        if (
            resource_digest_lines != [expected_resource_digest_line]
            or expected_selection_line not in contract_lines
        ):
            return f"packet {packet_id} contract lost its exact resource authority"
    elif resource_digest_lines or "## AOI resource authority" in contract_lines:
        return f"packet {packet_id} contract resource authority was removed from state"
    has_native_v5_marker = NATIVE_V5_PACKET_CONTRACT_MARKER in contract_lines
    dispatch_origin = packet.get("dispatch_schema_origin")
    if schema_version < 5 and (
        has_native_v5_marker or dispatch_origin == "native_v5"
    ):
        return f"packet {packet_id} native-v5 contract was downgraded to a legacy schema"
    if schema_version >= 5:
        if dispatch_origin == "native_v5" and not has_native_v5_marker:
            return f"packet {packet_id} native-v5 dispatch origin lost its contract marker"
        if dispatch_origin == "legacy_v4_migration" and has_native_v5_marker:
            return f"packet {packet_id} falsely claims a legacy-v4 dispatch migration"
        if dispatch_origin not in {"native_v5", "legacy_v4_migration"}:
            return f"packet {packet_id} dispatch schema origin is missing or invalid"
    return None


def packet_input_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet: dict[str, Any],
    *,
    require_origin: bool,
) -> list[str]:
    packet_id = str(packet.get("packet_id", ""))
    errors: list[str] = []
    for artifact in packet.get("input_artifact_refs", []):
        error = artifact_ref_integrity_error(
            paths, state, artifact, require_origin=require_origin
        )
        if error:
            errors.append(f"packet {packet_id} input artifact: {error}")
    return errors


def packet_lock_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet: dict[str, Any],
) -> list[str]:
    """Validate lock authority already persisted in a delegation packet."""

    try:
        validate_packet_lock_identities(paths, state, packet)
    except HarnessError as exc:
        return [str(exc)]
    return []


def packet_resource_envelope_integrity_errors(
    state: dict[str, Any], packet: dict[str, Any]
) -> list[str]:
    selection_id = str(packet.get("execution_selection_id", ""))
    if not selection_id:
        return (
            ["packet has a resource envelope digest without an execution selection"]
            if packet.get("resource_envelope_sha256")
            else []
        )
    try:
        selection = execution_selection_by_id(state, selection_id)
        _validate_packet_resource_envelope(
            state,
            packet,
            selection,
            enforce_active_limit=False,
        )
    except (HarnessError, TypeError, ValueError) as exc:
        return [str(exc)]
    return []


def packet_authority_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet: dict[str, Any],
    *,
    require_origin: bool,
    _visited: set[str] | None = None,
) -> list[str]:
    """Validate every packet authority surface used by a transition/consumer."""

    packet_id = str(packet.get("packet_id", ""))
    visited = set(_visited or ())
    if packet_id in visited:
        return [f"packet {packet_id} authority dependency cycle"]
    visited.add(packet_id)
    errors: list[str] = []
    errors.extend(packet_lock_integrity_errors(paths, state, packet))
    errors.extend(packet_resource_envelope_integrity_errors(state, packet))
    contract_error = packet_contract_integrity_error(paths, state, packet)
    if contract_error:
        errors.append(contract_error)
    errors.extend(
        packet_input_integrity_errors(
            paths, state, packet, require_origin=require_origin
        )
    )
    command_error = packet_command_integrity_error(packet)
    if command_error:
        errors.append(command_error)
    try:
        delegation_depth = int(packet.get("delegation_depth", 1))
    except (TypeError, ValueError):
        delegation_depth = 0
        errors.append(f"packet {packet_id} delegation depth is invalid")
    if delegation_depth == 2:
        parent_id = str(packet.get("parent_packet_id", ""))
        try:
            parent = _packet_by_id(state, parent_id)
        except HarnessError as exc:
            errors.append(f"packet {packet_id} parent authority: {exc}")
        else:
            errors.extend(
                f"packet {packet_id} parent authority: {item}"
                for item in packet_authority_integrity_errors(
                    paths,
                    state,
                    parent,
                    require_origin=False,
                    _visited=visited,
                )
            )
    if _is_steward_synthesis_packet(packet):
        selection_id = str(packet.get("execution_selection_id", ""))
        for specialist in state.get("packets", []):
            if (
                specialist.get("execution_selection_id") != selection_id
                or _is_steward_synthesis_packet(specialist)
                or specialist.get("status") != "done"
            ):
                continue
            specialist_id = str(specialist.get("packet_id", ""))
            errors.extend(
                f"packet {packet_id} specialist {specialist_id} authority: {item}"
                for item in packet_authority_integrity_errors(
                    paths,
                    state,
                    specialist,
                    require_origin=False,
                    _visited=visited,
                )
            )
            errors.extend(
                f"packet {packet_id} specialist {specialist_id} result: {item}"
                for item in packet_result_integrity_errors(
                    paths,
                    state,
                    specialist,
                )
            )
    return errors


def selection_done_packet_authority_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    selection_id: str,
) -> list[str]:
    """Validate done specialist evidence before a Steward packet can bind it."""

    errors: list[str] = []
    for packet in state.get("packets", []):
        if (
            packet.get("execution_selection_id") != selection_id
            or _is_steward_synthesis_packet(packet)
            or packet.get("status") != "done"
        ):
            continue
        packet_id = str(packet.get("packet_id", ""))
        errors.extend(
            f"specialist packet {packet_id}: {item}"
            for item in packet_authority_integrity_errors(
                paths,
                state,
                packet,
                require_origin=False,
            )
        )
        errors.extend(
            f"specialist packet {packet_id}: {item}"
            for item in packet_result_integrity_errors(paths, state, packet)
        )
    return errors


def packet_integrity_warnings(state: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    for packet in state.get("packets", []):
        packet_id = str(packet.get("packet_id", ""))
        schema_version = _packet_schema_version(packet)
        if (
            schema_version is not None
            and schema_version < 4
            and packet.get("status") in {"failed", "cancelled"}
            and any(
                _is_legacy_snapshot_version(artifact.get("snapshot_version"))
                for artifact in packet.get("input_artifact_refs", [])
            )
        ):
            warnings.append(
                f"packet {packet_id} has legacy digest-only inputs; "
                "failed/cancelled live origins are not revalidated"
            )
        if (
            schema_version is not None
            and schema_version < 5
            and packet.get("status") in {"dispatched", "done", "failed", "cancelled"}
        ):
            warnings.append(
                f"packet {packet_id} dispatch timing/provenance is legacy_unverified"
            )
        legacy_recovery_fields = {
            "version",
            "method",
            "carrier_input_index",
            "carrier_sha256",
            "archive_member",
            "packet_result_sha256",
            "reason",
            "recovered_at",
        }
        for input_index, artifact in enumerate(
            packet.get("input_artifact_refs", []), start=1
        ):
            recovery = artifact.get("recovery")
            if isinstance(recovery, dict) and set(recovery) == legacy_recovery_fields:
                warnings.append(
                    f"packet {packet_id} recovered input #{input_index} has an "
                    "unsealed legacy receipt; archive identity is replay-validated"
                )
    return warnings


def packet_result_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    packet: dict[str, Any],
) -> list[str]:
    """Validate one terminal packet result before it is consumed as evidence."""

    packet_id = str(packet.get("packet_id", ""))
    status = packet.get("status")
    if status not in TERMINAL_PACKET_STATUSES:
        return [f"packet {packet_id} result is not terminal"]
    expected_path = task_dir(paths, state["task_id"]) / "results" / f"{packet_id}.md"
    recorded_path = Path(str(packet.get("result_path", "")))
    if recorded_path != expected_path:
        return [f"packet {packet_id} result path is not canonical"]
    if packet.get("integrity_version") != 1:
        return [f"packet {packet_id} result lacks explicit integrity attestation"]
    if not expected_path.is_file():
        return [f"packet {packet_id} result file is missing"]
    errors: list[str] = []
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


def packet_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    allow_done_lock_recovery: bool = False,
) -> list[str]:
    errors: list[str] = []
    for packet in state.get("packets", []):
        packet_id = str(packet.get("packet_id", ""))
        status = packet.get("status")
        mode = packet.get("packet_mode", "legacy")
        locks = packet.get("locks", [])
        packet_purpose = packet.get("packet_purpose", "work")
        lock_authority_is_recoverable = status in {"failed", "cancelled"} or (
            status == "done"
            and (allow_done_lock_recovery or state.get("status") == "cancelled")
        )
        if not lock_authority_is_recoverable:
            errors.extend(packet_lock_integrity_errors(paths, state, packet))
        errors.extend(packet_resource_envelope_integrity_errors(state, packet))
        if packet_purpose not in {"work", "steward_synthesis"}:
            errors.append(f"packet {packet_id} has an invalid packet purpose")
        if packet_purpose == "steward_synthesis":
            if (
                int(packet.get("delegation_depth", 1)) != 1
                or mode != "read_only"
                or not packet.get("execution_selection_id")
                or not isinstance(packet.get("steward_selection_snapshot"), dict)
                or not isinstance(packet.get("steward_execution_snapshot"), dict)
                or not isinstance(packet.get("steward_input_bindings"), list)
            ):
                errors.append(
                    f"packet {packet_id} has malformed Steward synthesis authority"
                )
            if status not in {"failed", "cancelled"} and packet.get(
                "steward_input_bindings"
            ) != _selection_terminal_packet_bindings(
                state, str(packet.get("execution_selection_id", ""))
            ):
                errors.append(
                    f"packet {packet_id} Steward synthesis specialist bindings are stale"
                )
        if mode == "read_only" and locks:
            errors.append(f"packet {packet_id} read_only mode has mutation locks")
        if mode in {"bounded_mutation", "exact_command"} and not locks:
            errors.append(f"packet {packet_id} {mode} mode lacks mutation authority")
        contract_error = packet_contract_integrity_error(paths, state, packet)
        if contract_error:
            errors.append(contract_error)
        schema_version = _packet_schema_version(packet)
        legacy_terminal = (
            schema_version is not None
            and schema_version < 4
            and status in {"failed", "cancelled"}
        )
        if legacy_terminal:
            for artifact in packet.get("input_artifact_refs", []):
                if _is_legacy_snapshot_version(artifact.get("snapshot_version")):
                    continue
                snapshot_error = artifact_ref_integrity_error(
                    paths, state, artifact, require_origin=False
                )
                if snapshot_error:
                    errors.append(
                        f"packet {packet_id} input artifact: {snapshot_error}"
                    )
        else:
            errors.extend(
                packet_input_integrity_errors(
                    paths,
                    state,
                    packet,
                    require_origin=status in {"ready", "armed"},
                )
            )
        command_error = packet_command_integrity_error(packet)
        if command_error:
            errors.append(command_error)
        if status not in PACKET_STATUSES:
            errors.append(f"packet {packet_id} has invalid status {status!r}")
            continue
        if status == "dispatched" and not packet.get("agent_id"):
            errors.append(f"packet {packet_id} is dispatched without an agent id")
        if schema_version is not None and schema_version >= 5:
            if (
                not _is_exact_int(packet.get("dispatch_version"), 1)
                or packet.get("dispatch_provenance") not in DISPATCH_PROVENANCES
                or not isinstance(packet.get("dispatch_attempts"), list)
            ):
                errors.append(f"packet {packet_id} dispatch schema is invalid")
            if packet.get("dispatched_at"):
                errors.append(
                    f"packet {packet_id} v5 must not claim an unobserved dispatched_at"
                )
            attempts = packet.get("dispatch_attempts", [])
            active_attempts = [
                attempt
                for attempt in attempts
                if isinstance(attempt, dict) and attempt.get("status") == "armed"
            ]
            if status == "armed" and len(active_attempts) != 1:
                errors.append(f"packet {packet_id} armed state lacks one active permit")
            if status != "armed" and active_attempts:
                errors.append(f"packet {packet_id} retains an active permit after arm state")
            for attempt_index, attempt in enumerate(attempts, start=1):
                if not isinstance(attempt, dict):
                    errors.append(
                        f"packet {packet_id} dispatch attempt {attempt_index} is malformed"
                    )
                    continue
                attempt_status = attempt.get("status")
                if attempt.get("arm_authority_sha256") != (
                    _dispatch_attempt_authority_sha256(attempt)
                ):
                    errors.append(
                        f"packet {packet_id} dispatch attempt {attempt_index} lost authority integrity"
                    )
                if attempt_status not in {
                    "armed",
                    "consumed",
                    "disarmed",
                    "expired",
                }:
                    errors.append(
                        f"packet {packet_id} dispatch attempt {attempt_index} has invalid status"
                    )
                    continue
                if (
                    not _is_exact_int(attempt.get("attempt"), attempt_index)
                    or attempt.get("arm_id") != f"{packet_id}-a{attempt_index}"
                ):
                    errors.append(
                        f"packet {packet_id} dispatch attempt {attempt_index} has invalid sequence identity"
                    )
                armed_time = parse_time(str(attempt.get("armed_at", "")))
                expiry_time = parse_time(str(attempt.get("expires_at", "")))
                if (
                    armed_time is None
                    or expiry_time is None
                    or expiry_time <= armed_time
                    or expiry_time - armed_time
                    > dt.timedelta(seconds=DISPATCH_ARM_MAX_SECONDS)
                ):
                    errors.append(
                        f"packet {packet_id} dispatch attempt {attempt_index} has invalid arm timing"
                    )
                observation = attempt.get("observation")
                closed_at = str(attempt.get("closed_at", ""))
                reason = str(attempt.get("reason", ""))
                if attempt_status == "armed":
                    if (
                        expiry_time is not None
                        and expiry_time <= dt.datetime.now().astimezone()
                    ):
                        errors.append(
                            f"packet {packet_id} active dispatch attempt {attempt_index} is expired"
                        )
                    if observation is not None or closed_at or reason:
                        errors.append(
                            f"packet {packet_id} active dispatch attempt {attempt_index} carries closure data"
                        )
                elif attempt_status == "consumed":
                    required_observation_fields = {
                        "event_id",
                        "hook_protocol_version",
                        "parent_session_id",
                        "turn_id",
                        "agent_id",
                        "agent_type",
                        "permission_mode",
                        "observed_at",
                    }
                    if (
                        not isinstance(observation, dict)
                        or set(observation) != required_observation_fields
                    ):
                        errors.append(
                            f"packet {packet_id} consumed dispatch attempt {attempt_index} has an invalid observation schema"
                        )
                    else:
                        observation_time = parse_time(
                            str(observation.get("observed_at", ""))
                        )
                        observation_payload = {
                            "session_id": observation.get("parent_session_id", ""),
                            "turn_id": observation.get("turn_id", ""),
                            "agent_id": observation.get("agent_id", ""),
                            "agent_type": observation.get("agent_type", ""),
                        }
                        if (
                            not _is_exact_int(
                                observation.get("hook_protocol_version"),
                                int(HOOK_PROTOCOL_VERSION),
                            )
                            or observation_time is None
                            or closed_at != observation.get("observed_at")
                            or reason
                            or observation.get("event_id")
                            != _subagent_event_id(observation_payload)
                            or observation.get("parent_session_id")
                            != attempt.get("parent_session_id")
                            or observation.get("agent_type")
                            != attempt.get("expected_agent_type")
                            or not HOOK_ID_RE.fullmatch(
                                str(observation.get("parent_session_id", ""))
                            )
                            or not HOOK_ID_RE.fullmatch(
                                str(observation.get("agent_id", ""))
                            )
                            or not HOOK_ID_RE.fullmatch(
                                str(observation.get("agent_type", ""))
                            )
                            or not isinstance(observation.get("turn_id"), str)
                            or _safe_hook_observation_text(
                                observation.get("turn_id", "")
                            )
                            != observation.get("turn_id")
                            or not isinstance(observation.get("permission_mode"), str)
                            or _safe_hook_observation_text(
                                observation.get("permission_mode", "")
                            )
                            != observation.get("permission_mode")
                        ):
                            errors.append(
                                f"packet {packet_id} consumed dispatch attempt {attempt_index} observation lost identity integrity"
                            )
                elif (
                    observation is not None
                    or parse_time(closed_at) is None
                    or not reason
                ):
                    errors.append(
                        f"packet {packet_id} closed dispatch attempt {attempt_index} lacks valid closure evidence"
                    )
            provenance = packet.get("dispatch_provenance")
            dispatch_recorded_at = str(packet.get("dispatch_recorded_at", ""))
            if status in {"ready", "armed"} and provenance != "none":
                errors.append(
                    f"packet {packet_id} has dispatch provenance before dispatch"
                )
            if provenance == "none" and dispatch_recorded_at:
                errors.append(
                    f"packet {packet_id} records dispatch timing without dispatch provenance"
                )
            if status == "dispatched" and provenance not in {
                "codex_subagent_start_observed",
                "manual_unverified",
            }:
                errors.append(f"packet {packet_id} dispatched state lacks provenance")
            if status in {"done", "failed"} and provenance not in {
                "codex_subagent_start_observed",
                "manual_unverified",
            }:
                errors.append(f"packet {packet_id} terminal work lacks dispatch provenance")
            if provenance == "manual_unverified":
                if not packet.get("manual_unverified_reason"):
                    errors.append(f"packet {packet_id} manual dispatch lacks a reason")
                if parse_time(dispatch_recorded_at) is None:
                    errors.append(
                        f"packet {packet_id} manual dispatch lacks a valid registration time"
                    )
                if any(
                    isinstance(attempt, dict) and attempt.get("observation")
                    for attempt in attempts
                ):
                    errors.append(
                        f"packet {packet_id} manual dispatch carries a hook observation"
                    )
                if not any(
                    isinstance(attempt, dict)
                    and attempt.get("status") == "disarmed"
                    for attempt in attempts
                ) and packet.get("legacy_manual_dispatch_migration") is not True:
                    errors.append(
                        f"packet {packet_id} manual dispatch lacks a prior arm or legacy migration marker"
                    )
            if provenance == "codex_subagent_start_observed":
                consumed = [
                    attempt
                    for attempt in attempts
                    if isinstance(attempt, dict)
                    and attempt.get("status") == "consumed"
                    and isinstance(attempt.get("observation"), dict)
                ]
                if len(consumed) != 1:
                    errors.append(
                        f"packet {packet_id} observed dispatch lacks one consumed observation"
                    )
                else:
                    observation = consumed[0]["observation"]
                    if (
                        packet.get("agent_id") != observation.get("agent_id")
                        or dispatch_recorded_at != observation.get("observed_at")
                        or packet.get("manual_unverified_reason")
                    ):
                        errors.append(
                            f"packet {packet_id} observed dispatch lost packet/observation binding"
                        )
            if provenance in {
                "codex_subagent_start_observed",
                "manual_unverified",
            } and not packet.get("agent_id"):
                errors.append(
                    f"packet {packet_id} dispatch provenance lacks an agent id"
                )
        if status in TERMINAL_PACKET_STATUSES:
            errors.extend(packet_result_integrity_errors(paths, state, packet))
    return errors


def subagent_incident_integrity_errors(state: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    incidents = state.get("subagent_incidents", [])
    v5_packets = any(
        (_packet_schema_version(packet) or 0) >= 5
        for packet in state.get("packets", [])
    )
    if (incidents or v5_packets) and state.get("dispatch_model_version") != 1:
        errors.append("dispatch v1 records require dispatch_model_version=1")
    seen: set[str] = set()
    arm_slots: dict[tuple[str, str], str] = {}
    for packet in state.get("packets", []):
        if packet.get("status") != "armed":
            continue
        try:
            attempt = _active_dispatch_attempt(packet)
        except HarnessError as exc:
            errors.append(str(exc))
            continue
        slot = (
            str(attempt.get("parent_session_id", "")),
            str(attempt.get("expected_agent_type", "")),
        )
        prior = arm_slots.get(slot)
        if prior is not None:
            errors.append(
                "multiple armed packets occupy parent-session/agent-type slot "
                f"{slot[0]}/{slot[1]}: {prior}, {packet.get('packet_id')}"
            )
        arm_slots[slot] = str(packet.get("packet_id", ""))
    for incident in incidents:
        incident_id = str(incident.get("incident_id", ""))
        if not re.fullmatch(r"spawn-[0-9a-f]{32}", incident_id):
            errors.append(f"spawn incident {incident_id!r} has an invalid id")
        if incident_id in seen:
            errors.append(f"duplicate spawn incident id {incident_id}")
        seen.add(incident_id)
        if (
            incident.get("kind") != "unmanaged_subagent_start"
            or incident.get("status") not in {"open", "accounted"}
            or not _is_exact_int(
                incident.get("hook_protocol_version"), int(HOOK_PROTOCOL_VERSION)
            )
            or not isinstance(incident.get("candidate_packet_ids"), list)
        ):
            errors.append(f"spawn incident {incident_id} has an invalid schema")
        if incident.get("status") == "open" and incident.get("resolution") is not None:
            errors.append(f"open spawn incident {incident_id} carries a resolution")
        if incident.get("status") == "accounted":
            resolution = incident.get("resolution")
            if (
                not isinstance(resolution, dict)
                or resolution.get("disposition")
                not in {"no_material_work", "work_discarded", "manual_unverified"}
            ):
                errors.append(f"accounted spawn incident {incident_id} lacks disposition")
    return errors


def packet_recovery_integrity_errors(
    paths: HarnessPaths, state: dict[str, Any]
) -> list[str]:
    """Validate sealed recovery provenance and the still-bound archive member."""

    errors: list[str] = []
    recovery_count = 0
    aggregate_carrier_bytes = 0
    aggregate_recovered_bytes = 0
    replay_budget = {
        "decompressed_bytes": 0,
        "member_count": 0,
        "declared_bytes": 0,
        "extracted_bytes": 0,
    }
    required_fields = {
        "version",
        "method",
        "carrier_input_index",
        "carrier_sha256",
        "archive_member",
        "packet_result_sha256",
        "reason",
        "recovered_at",
        "record_sha256",
    }
    legacy_required_fields = required_fields - {"record_sha256"}
    for packet in state.get("packets", []):
        packet_id = str(packet.get("packet_id", ""))
        refs = packet.get("input_artifact_refs", [])
        for target_index, target in enumerate(refs):
            if "recovery" not in target:
                continue
            recovery_count += 1
            label = f"packet {packet_id} recovered input #{target_index + 1}"
            if recovery_count > BOUND_ARTIFACT_MAX_COUNT:
                errors.append(
                    f"packet recovery receipts exceed {BOUND_ARTIFACT_MAX_COUNT} records"
                )
                return errors
            recovery = target.get("recovery")
            recovery_fields = set(recovery) if isinstance(recovery, dict) else set()
            sealed_receipt = recovery_fields == required_fields
            legacy_receipt = recovery_fields == legacy_required_fields
            if (
                not isinstance(recovery, dict)
                or not (sealed_receipt or legacy_receipt)
                or not _is_exact_int(recovery.get("version"), 1)
                or recovery.get("method") != "packet-bound-tar-member"
            ):
                errors.append(f"{label} receipt schema is invalid")
                continue
            packet_schema_version = packet.get("packet_schema_version")
            if (
                not isinstance(packet_schema_version, int)
                or isinstance(packet_schema_version, bool)
                or packet_schema_version < 1
                or packet_schema_version >= 4
                or packet.get("status") != "done"
                or not _is_exact_int(packet.get("integrity_version"), 1)
            ):
                errors.append(f"{label} is attached to an ineligible packet")
                continue
            if not _is_canonical_snapshot_version(target.get("snapshot_version")):
                errors.append(f"{label} target is not a canonical snapshot")
                continue
            target_error = artifact_ref_integrity_error(
                paths, state, target, require_origin=False
            )
            if target_error:
                errors.append(f"{label} target: {target_error}")
                continue
            target_source = Path(str(target.get("source_path", "")))
            if not target_source.is_absolute():
                errors.append(f"{label} source path is not absolute")
                continue
            carrier_number = recovery.get("carrier_input_index")
            if (
                not isinstance(carrier_number, int)
                or isinstance(carrier_number, bool)
                or carrier_number < 1
                or carrier_number > len(refs)
                or carrier_number == target_index + 1
            ):
                errors.append(f"{label} carrier input index is invalid")
                continue
            carrier_index = carrier_number - 1
            carrier = refs[carrier_index]
            carrier_sha = str(recovery.get("carrier_sha256", ""))
            if (
                not re.fullmatch(r"[0-9a-f]{64}", carrier_sha)
                or carrier_sha != carrier.get("sha256")
            ):
                errors.append(f"{label} carrier SHA-256 binding is invalid")
                continue
            carrier_error = artifact_ref_integrity_error(
                paths, state, carrier, require_origin=False
            )
            if carrier_error:
                errors.append(f"{label} carrier: {carrier_error}")
                continue
            packet_result_sha = str(recovery.get("packet_result_sha256", ""))
            expected_result_path = (
                task_dir(paths, state["task_id"]) / "results" / f"{packet_id}.md"
            )
            if (
                not re.fullmatch(r"[0-9a-f]{64}", packet_result_sha)
                or packet_result_sha != packet.get("result_sha256")
                or Path(str(packet.get("result_path", ""))) != expected_result_path
                or not expected_result_path.is_file()
                or expected_result_path.is_symlink()
                or sha256_file(expected_result_path) != packet_result_sha
            ):
                errors.append(f"{label} packet result binding is invalid")
                continue
            stored_member = recovery.get("archive_member")
            try:
                canonical_member = canonical_recovery_archive_member(stored_member)
            except (AttributeError, HarnessError) as exc:
                errors.append(f"{label} archive member is invalid: {exc}")
                continue
            if canonical_member != stored_member:
                errors.append(f"{label} archive member is not canonical")
                continue
            reason = recovery.get("reason")
            if not isinstance(reason, str) or reason != reason.strip():
                errors.append(f"{label} reason is not canonical text")
                continue
            try:
                require_evidence_detail(reason, f"{label} reason")
            except HarnessError as exc:
                errors.append(str(exc))
                continue
            recovered_at = recovery.get("recovered_at")
            if (
                not isinstance(recovered_at, str)
                or parse_time(recovered_at) is None
                or re.search(r"(?:Z|[+-]\d{2}:\d{2})$", recovered_at) is None
            ):
                errors.append(f"{label} recovered_at is not a timezone-aware timestamp")
                continue
            if sealed_receipt:
                record_sha = str(recovery.get("record_sha256", ""))
                expected_record_sha = canonical_record_sha256(
                    recovery_record_preimage(
                        state,
                        packet,
                        target_index,
                        target,
                        carrier_index,
                        carrier,
                        recovery,
                    )
                )
                if (
                    not re.fullmatch(r"[0-9a-f]{64}", record_sha)
                    or record_sha != expected_record_sha
                ):
                    errors.append(f"{label} receipt record SHA-256 mismatch")
                    continue
            carrier_size = carrier.get("size_bytes")
            target_size = target.get("size_bytes")
            if (
                not isinstance(carrier_size, int)
                or isinstance(carrier_size, bool)
                or not isinstance(target_size, int)
                or isinstance(target_size, bool)
            ):
                errors.append(f"{label} size metadata is invalid")
                continue
            aggregate_carrier_bytes += carrier_size
            aggregate_recovered_bytes += target_size
            if (
                aggregate_carrier_bytes > BOUND_ARTIFACT_TOTAL_MAX_BYTES
                or aggregate_recovered_bytes > BOUND_ARTIFACT_TOTAL_MAX_BYTES
            ):
                errors.append("packet recovery aggregate byte budget is exceeded")
                return errors
            try:
                _, carrier_data = read_regular_artifact(
                    Path(str(carrier.get("path", ""))),
                    "packet recovery carrier",
                    max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
                )
                recovered_data = read_recovery_tar_member(
                    carrier_data,
                    canonical_member,
                    budget=replay_budget,
                )
            except HarnessError as exc:
                errors.append(f"{label} archive replay failed: {exc}")
                continue
            if (
                hashlib.sha256(recovered_data).hexdigest() != target.get("sha256")
                or len(recovered_data) != target_size
            ):
                errors.append(f"{label} archive member no longer matches the target")
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
    authority_errors = packet_authority_integrity_errors(
        paths, state, packet, require_origin=False
    )
    if authority_errors:
        raise HarnessError(
            "independent review packet authority is missing or tampered: "
            + "; ".join(authority_errors)
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
) -> tuple[dict[str, Any], bytes]:
    _, source_data = read_regular_artifact(
        source,
        "source receipt",
        max_bytes=COMMAND_ARTIFACT_MAX_BYTES,
        require_utf8=True,
    )
    actual_sha = hashlib.sha256(source_data).hexdigest()
    if actual_sha != expected_sha:
        raise HarnessError(
            f"source receipt SHA-256 mismatch: expected {expected_sha}, actual {actual_sha}"
        )
    try:
        payload = json.loads(source_data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
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
    for required_included in REQUIRED_RECEIPT_COMPONENTS:
        if components[required_included].get("status") != "included":
            raise HarnessError(f"source receipt component {required_included!r} must be included")
    return payload, source_data


def context_receipt_integrity_errors(
    paths: HarnessPaths, state: dict[str, Any]
) -> list[str]:
    """Validate every immutable context-provider receipt and its chain."""

    errors = receipt_chain_errors(state)
    for index, record in enumerate(state.get("context_provider_receipts", []), start=1):
        try:
            validate_receipt_record(paths, state, record)
        except (HarnessError, OSError, TypeError, ValueError) as exc:
            receipt_id = (
                str(record.get("receipt_id", index))
                if isinstance(record, dict)
                else str(index)
            )
            errors.append(f"context receipt {receipt_id} is invalid: {exc}")
    return errors


def context_receipt_reports(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    evaluate_live: bool,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """Return machine-readable Steward health data plus doctor messages."""

    reports: list[dict[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []
    integrity_errors = context_receipt_integrity_errors(paths, state)
    errors.extend(integrity_errors)
    if integrity_errors:
        return reports, errors, warnings
    for record in active_context_receipt_records(state):
        payload = validate_receipt_record(paths, state, record)
        if evaluate_live:
            live = evaluate_live_receipt(
                payload,
                freshness_profile=record["freshness_profile"],
                project_root=record["project_root"],
            )
        else:
            live = {
                "provider": "codebase-memory",
                "provider_health": "historical_not_rechecked",
                "freshness": "historical_not_rechecked",
                "freshness_profile": record["freshness_profile"],
                "health_findings": [],
                "freshness_findings": [],
                "diagnostics": [],
                "query_evidence_category": CODEBASE_MEMORY_QUERY_EVIDENCE_CATEGORY,
                "close_qualifying": False,
            }
        report = {
            "task_id": state["task_id"],
            "receipt_id": record["receipt_id"],
            "receipt_integrity": "valid",
            "receipt_sha256": record["receipt_sha256"],
            "source_set_id": record["source_set_id"],
            "requirement": record["requirement"],
            "refresh_authority": record["refresh_authority"],
            **live,
            "technical_verdict_authority": "none",
        }
        reports.append(report)
        if not evaluate_live:
            continue
        unhealthy = live["provider_health"] != "healthy"
        nonfresh = live["freshness"] != "fresh"
        if not unhealthy and not nonfresh:
            continue
        details = [
            *(item["detail"] for item in live["health_findings"]),
            *(item["detail"] for item in live["freshness_findings"]),
        ]
        rendered_details = "; ".join(details[:8])
        if len(details) > 8:
            rendered_details += f"; ... {len(details) - 8} more findings"
        message = (
            f"codebase-memory receipt {record['receipt_id']} is "
            f"health={live['provider_health']}, freshness={live['freshness']}: "
            + (rendered_details if details else "no qualifying live receipt")
        )
        (errors if record["requirement"] == "required" else warnings).append(message)
    return reports, errors, warnings


def context_provider_brief_bindings(
    paths: HarnessPaths, state: dict[str, Any]
) -> list[dict[str, Any]]:
    """Evaluate active receipts for a Steward brief without technical verdicts."""

    bindings: list[dict[str, Any]] = []
    integrity_errors = context_receipt_integrity_errors(paths, state)
    if integrity_errors:
        raise HarnessError("context-provider receipt integrity failed: " + "; ".join(integrity_errors))
    for record in active_context_receipt_records(state):
        payload = validate_receipt_record(paths, state, record)
        report = evaluate_live_receipt(
            payload,
            freshness_profile=record["freshness_profile"],
            project_root=record["project_root"],
        )
        if record["requirement"] == "required" and (
            report["provider_health"] != "healthy"
            or report["freshness"] != "fresh"
        ):
            raise HarnessError(
                f"required codebase-memory receipt {record['receipt_id']} is not healthy and fresh"
            )
        bindings.append(codebase_memory_steward_binding(record, report))
    return bindings


def benchmark_ledger_preimage(record: dict[str, Any]) -> dict[str, Any]:
    preimage = copy.deepcopy(record)
    preimage.pop("record_sha256", None)
    return preimage


def validate_benchmark_ledger_record(
    paths: HarnessPaths, state: dict[str, Any], record: Any
) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise HarnessError("codebase-memory benchmark ledger entry must be an object")
    expected_fields = {
        "integrity_version",
        "record_version",
        "benchmark_id",
        "provider",
        "receipt_id",
        "receipt_sha256",
        "source_set_id",
        "input_snapshots",
        "summary_path",
        "summary_sha256",
        "summary_size_bytes",
        "evidence_class",
        "close_qualifying",
        "recorded_by_session_id",
        "recorded_at",
        "record_sha256",
    }
    if set(record) != expected_fields:
        raise HarnessError("codebase-memory benchmark ledger fields are invalid")
    if record.get("integrity_version") != 1 or record.get("record_version") != 1:
        raise HarnessError("codebase-memory benchmark ledger version is invalid")
    benchmark_id = validate_id(str(record.get("benchmark_id", "")), "benchmark id")
    if record.get("provider") != "codebase-memory":
        raise HarnessError("codebase-memory benchmark provider changed")
    if record.get("evidence_class") != CODEBASE_MEMORY_BENCHMARK_EVIDENCE_CLASS:
        raise HarnessError("codebase-memory benchmark evidence class changed")
    if record.get("close_qualifying") is not False:
        raise HarnessError("codebase-memory benchmark became close-qualifying")
    receipt_id = str(record.get("receipt_id", ""))
    matching_receipts = [
        item
        for item in state.get("context_provider_receipts", [])
        if item.get("receipt_id") == receipt_id
    ]
    if len(matching_receipts) != 1:
        raise HarnessError("codebase-memory benchmark receipt binding is missing")
    receipt = matching_receipts[0]
    if (
        record.get("receipt_sha256") != receipt.get("receipt_sha256")
        or record.get("source_set_id") != receipt.get("source_set_id")
    ):
        raise HarnessError("codebase-memory benchmark receipt/source-set binding changed")
    inputs = record.get("input_snapshots")
    if not isinstance(inputs, list) or not inputs:
        raise HarnessError("codebase-memory benchmark lacks input snapshots")
    parsed: list[dict[str, Any]] = []
    for index, snapshot in enumerate(inputs, start=1):
        if not isinstance(snapshot, dict):
            raise HarnessError("codebase-memory benchmark input snapshot is malformed")
        if set(snapshot) != {"source_path", "path", "sha256", "size_bytes"}:
            raise HarnessError("codebase-memory benchmark input snapshot fields are invalid")
        if not Path(str(snapshot.get("source_path", ""))).is_absolute():
            raise HarnessError("codebase-memory benchmark input source path is not absolute")
        expected_path = (
            task_dir(paths, state["task_id"])
            / "results"
            / f"codebase-memory-benchmark-{benchmark_id}-input-{index:03}.json"
        )
        if Path(str(snapshot.get("path", ""))) != expected_path:
            raise HarnessError("codebase-memory benchmark input path is not canonical")
        _, data = read_regular_artifact(
            expected_path,
            "codebase-memory benchmark input snapshot",
            max_bytes=COMMAND_ARTIFACT_MAX_BYTES,
            require_utf8=True,
        )
        if (
            len(data) != snapshot.get("size_bytes")
            or hashlib.sha256(data).hexdigest() != snapshot.get("sha256")
        ):
            raise HarnessError("codebase-memory benchmark input snapshot identity mismatch")
        try:
            payload = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise HarnessError(f"codebase-memory benchmark input JSON is invalid: {exc}") from exc
        payload = validate_codebase_memory_benchmark_record(payload)
        if (
            payload["controls"]["provider_receipt_sha256"]
            != record["receipt_sha256"]
            or payload["controls"]["source_set_id"] != record["source_set_id"]
        ):
            raise HarnessError("codebase-memory benchmark input lost receipt binding")
        parsed.append(payload)
    summary_path = (
        task_dir(paths, state["task_id"])
        / "results"
        / f"codebase-memory-benchmark-{benchmark_id}-summary.json"
    )
    if Path(str(record.get("summary_path", ""))) != summary_path:
        raise HarnessError("codebase-memory benchmark summary path is not canonical")
    _, summary_data = read_regular_artifact(
        summary_path,
        "codebase-memory benchmark summary",
        max_bytes=COMMAND_ARTIFACT_MAX_BYTES,
        require_utf8=True,
    )
    if (
        len(summary_data) != record.get("summary_size_bytes")
        or hashlib.sha256(summary_data).hexdigest() != record.get("summary_sha256")
    ):
        raise HarnessError("codebase-memory benchmark summary identity mismatch")
    try:
        summary = json.loads(summary_data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HarnessError(f"codebase-memory benchmark summary JSON is invalid: {exc}") from exc
    if summary.get("evidence_class") != CODEBASE_MEMORY_BENCHMARK_EVIDENCE_CLASS:
        raise HarnessError("codebase-memory benchmark summary evidence class changed")
    try:
        parse_time(str(summary.get("generated_at", "")))
        parse_time(str(record.get("recorded_at", "")))
    except (TypeError, ValueError) as exc:
        raise HarnessError(f"codebase-memory benchmark timestamp is invalid: {exc}") from exc
    require_text(
        str(record.get("recorded_by_session_id", "")),
        "codebase-memory benchmark recording session",
    )
    expected_summary = summarize_codebase_memory_benchmark_records(
        parsed, generated_at=str(summary.get("generated_at", ""))
    )
    if summary != expected_summary:
        raise HarnessError("codebase-memory benchmark summary is not reproducible")
    if record.get("record_sha256") != context_record_sha256(
        benchmark_ledger_preimage(record)
    ):
        raise HarnessError("codebase-memory benchmark ledger integrity mismatch")
    return summary


def context_benchmark_integrity_errors(
    paths: HarnessPaths, state: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for index, record in enumerate(state.get("context_provider_benchmarks", []), start=1):
        benchmark_id = (
            str(record.get("benchmark_id", index))
            if isinstance(record, dict)
            else str(index)
        )
        if benchmark_id in seen:
            errors.append(f"codebase-memory benchmark id is duplicated: {benchmark_id}")
        seen.add(benchmark_id)
        try:
            validate_benchmark_ledger_record(paths, state, record)
        except (HarnessError, OSError, TypeError, ValueError) as exc:
            errors.append(f"codebase-memory benchmark {benchmark_id} is invalid: {exc}")
    return errors


def job_integrity_errors(paths: HarnessPaths, state: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        policy_v2 = _execution_policy_v2_enabled(state)
    except HarnessError as exc:
        errors.append(str(exc))
        policy_v2 = False
    for job in state.get("jobs", []):
        run_id = str(job.get("run_id", ""))
        status = job.get("status")
        if status not in JOB_STATUSES:
            errors.append(f"job {run_id} has invalid status {status!r}")
            continue
        if job.get("integrity_version") != 1:
            errors.append(f"job {run_id} lacks integrity_version=1")
        owner_packet_id = str(job.get("owner_packet_id", ""))
        if owner_packet_id:
            try:
                _validate_owned_job_authority(
                    paths,
                    state,
                    job,
                    require_dispatched=status in ACTIVE_JOB_STATUSES,
                )
            except (HarnessError, TypeError, ValueError) as exc:
                errors.append(f"job {run_id} owner packet authority is invalid: {exc}")
        if job.get("job_schema_version") == 2:
            if policy_v2 and status in ACTIVE_JOB_STATUSES and not _is_exact_int(
                job.get("task_execution_policy_version"), EXECUTION_POLICY_VERSION
            ):
                errors.append(
                    f"job {run_id} lacks its task execution policy v2 binding"
                )
            namespace = paths.project.external_lock_namespace
            expected_output_locks = [
                f"{namespace}:tree:{job.get('work_root', '')}",
                f"{namespace}:file:{job.get('log', '')}",
            ]
            if (
                job.get("external_lock_namespace") != namespace
                or job.get("required_output_locks") != expected_output_locks
            ):
                errors.append(
                    f"job {run_id} external output-lock authority is non-canonical or changed"
                )
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


def verification_integrity_warnings(state: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    for index, item in enumerate(state.get("verification", []), start=1):
        legacy_refs = [
            artifact
            for artifact in item.get("artifact_refs", [])
            if _is_legacy_snapshot_version(artifact.get("snapshot_version"))
        ]
        if not legacy_refs:
            continue
        if item.get("superseded_at"):
            warnings.append(
                f"verification #{index} is explicitly superseded with legacy "
                "digest-only artifact metadata"
            )
        else:
            warnings.append(
                f"verification #{index} uses legacy live artifact references; "
                "materialize or supersede it before the origins evolve"
            )
    return warnings


def verification_supersession_errors(state: dict[str, Any]) -> list[str]:
    """Validate immutable supersession identities and every chain to a pass leaf."""

    records = state.get("verification", [])
    errors: list[str] = []
    for source_index, source in enumerate(records, start=1):
        label = f"verification #{source_index}"
        superseded_raw = source.get("superseded_at")
        superseded = superseded_raw is not None and superseded_raw != ""
        metadata_present = any(
            field in source for field in SUPERSESSION_MUTATION_FIELDS
        )
        if not superseded:
            if metadata_present:
                errors.append(f"{label} has supersession metadata without superseded_at")
            continue
        superseded_time = (
            parse_time(superseded_raw) if isinstance(superseded_raw, str) else None
        )
        if superseded_time is None:
            errors.append(f"{label} superseded_at is not a valid timestamp")
        reason = source.get("supersession_reason")
        if not isinstance(reason, str):
            errors.append(f"{label} supersession reason is not text")
        else:
            try:
                require_evidence_detail(reason, f"{label} supersession reason")
            except HarnessError as exc:
                errors.append(str(exc))
        if not _is_exact_int(source.get("supersession_version"), 2):
            errors.append(f"{label} supersession is not sealed as version 2")
            continue
        source_sha = str(source.get("source_record_sha256", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", source_sha):
            errors.append(f"{label} source record SHA-256 is invalid")
        elif canonical_record_sha256(verification_source_preimage(source)) != source_sha:
            errors.append(f"{label} source preimage SHA-256 mismatch")
        original_status = source.get("original_status")
        if original_status not in ACCOUNTED_VERIFICATION_STATUSES - {"skipped"}:
            errors.append(f"{label} has invalid original superseded status")
        replacement_index = source.get("replacement_index")
        if (
            not isinstance(replacement_index, int)
            or isinstance(replacement_index, bool)
            or replacement_index < 1
            or replacement_index > len(records)
            or replacement_index == source_index
        ):
            errors.append(f"{label} has invalid replacement index")
            continue
        replacement = records[replacement_index - 1]
        stored_replacement_sha = str(source.get("replacement_record_sha256", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", stored_replacement_sha):
            errors.append(f"{label} replacement record SHA-256 is invalid")
            continue
        effective_replacement_sha = stored_replacement_sha
        materialization = source.get("replacement_materialization")
        if materialization is not None:
            required_materialization_fields = {
                "version",
                "method",
                "from_record_sha256",
                "to_record_sha256",
                "sealed_at",
            }
            if (
                not isinstance(materialization, dict)
                or set(materialization) != required_materialization_fields
                or not _is_exact_int(materialization.get("version"), 1)
                or materialization.get("method")
                != "canonical-artifact-materialization"
            ):
                errors.append(f"{label} replacement materialization receipt is invalid")
                continue
            from_sha = str(materialization.get("from_record_sha256", ""))
            to_sha = str(materialization.get("to_record_sha256", ""))
            if from_sha != stored_replacement_sha or not re.fullmatch(
                r"[0-9a-f]{64}", to_sha
            ) or from_sha == to_sha:
                errors.append(f"{label} replacement materialization SHA mapping is invalid")
                continue
            sealed_raw = materialization.get("sealed_at")
            sealed_time = parse_time(sealed_raw) if isinstance(sealed_raw, str) else None
            if (
                sealed_time is None
                or superseded_time is None
                or sealed_time < superseded_time
            ):
                errors.append(f"{label} replacement materialization time is invalid")
                continue
            replacement_pre_supersede = (
                verification_source_preimage(replacement)
                if replacement.get("superseded_at")
                and _is_exact_int(replacement.get("supersession_version"), 2)
                else replacement
            )
            try:
                legacy_preimage_sha = canonical_record_sha256(
                    verification_legacy_materialization_preimage(
                        replacement_pre_supersede
                    )
                )
            except HarnessError as exc:
                errors.append(f"{label} replacement materialization: {exc}")
                continue
            if legacy_preimage_sha != from_sha:
                errors.append(f"{label} replacement legacy preimage SHA-256 mismatch")
            effective_replacement_sha = to_sha
        replacement_identity = (
            str(replacement.get("source_record_sha256", ""))
            if replacement.get("superseded_at")
            and _is_exact_int(replacement.get("supersession_version"), 2)
            else canonical_record_sha256(replacement)
        )
        if replacement_identity != effective_replacement_sha:
            errors.append(f"{label} replacement record SHA-256 mismatch")
        source_time = parse_time(str(source.get("recorded_at", "")))
        replacement_time = parse_time(str(replacement.get("recorded_at", "")))
        if (
            source.get("category") != replacement.get("category")
            or source_time is None
            or replacement_time is None
            or replacement_time <= source_time
            or superseded_time is None
            or superseded_time < replacement_time
        ):
            errors.append(f"{label} replacement category/time relationship is invalid")

        seen: set[int] = set()
        cursor = source_index
        while True:
            if cursor in seen:
                errors.append(f"{label} replacement chain contains a cycle")
                break
            seen.add(cursor)
            current = records[cursor - 1]
            if not current.get("superseded_at"):
                if current.get("status") != "pass":
                    errors.append(f"{label} replacement chain does not end in pass")
                break
            next_index = current.get("replacement_index")
            if (
                not isinstance(next_index, int)
                or isinstance(next_index, bool)
                or next_index < 1
                or next_index > len(records)
            ):
                break
            cursor = next_index
    return errors


def verification_record_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    indexed_records: Iterable[tuple[int, dict[str, Any]]] | None = None,
) -> list[str]:
    """Validate individual verification records without reindexing graph edges."""

    errors: list[str] = []
    records = (
        indexed_records
        if indexed_records is not None
        else enumerate(state.get("verification", []), start=1)
    )
    for index, item in records:
        label = f"verification #{index}"
        if not _is_exact_int(item.get("integrity_version"), 1):
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
        if item.get("superseded_at"):
            if item.get("status") != "skipped":
                errors.append(f"{label} superseded record must have status='skipped'")
            if not isinstance(item.get("supersession_reason"), str) or not item.get(
                "supersession_reason", ""
            ).strip():
                errors.append(f"{label} superseded record lacks a reason")
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
            if item.get("superseded_at") and _is_legacy_snapshot_version(
                artifact.get("snapshot_version")
            ):
                continue
            error = artifact_ref_integrity_error(
                paths, state, artifact, require_origin=False
            )
            if error:
                errors.append(f"{label} artifact reference: {error}")
    return errors


def verification_integrity_errors(
    paths: HarnessPaths, state: dict[str, Any]
) -> list[str]:
    errors = verification_record_integrity_errors(paths, state)
    errors.extend(verification_supersession_errors(state))
    return errors


def verification_migration_integrity_errors(
    paths: HarnessPaths, state: dict[str, Any]
) -> list[str]:
    """Allow only the explicit unsealed-edge error during one-by-one migration."""

    return [
        error
        for error in verification_integrity_errors(paths, state)
        if not re.fullmatch(
            r"verification #\d+ supersession is not sealed as version 2",
            error,
        )
    ]


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
                (ref.get("source_path") or ref.get("path")) == dataset.get("path")
                and ref.get("sha256") == dataset.get("sha256")
                for ref in source_packet.get("input_artifact_refs", [])
            )
        ):
            raise HarnessError(
                "capacity recommendation requires a done source packet bound to this review dataset"
            )
        authority_errors = packet_authority_integrity_errors(
            paths, state, source_packet, require_origin=False
        )
        if authority_errors:
            raise HarnessError(
                "capacity recommendation source packet authority is missing or tampered: "
                + "; ".join(authority_errors)
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
        if require_after_canary and (
            item.get("kind") not in {"packet", "job"}
            or item.get("skill_release_id") != expected_skill_release_id
            or item.get("skill_version") != expected_skill_version
            or item.get("skill_canary_event_id") != expected_canary_event_id
        ):
            raise HarnessError(
                f"{label} reference {item['reference']} is not bound to the exact skill canary"
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
    actual_sha = hashlib.sha256(data).hexdigest()
    if actual_sha != expected_sha:
        raise HarnessError(
            f"{label} SHA-256 mismatch: expected {expected_sha}, actual {actual_sha}"
        )
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
            or not _valid_named_checks(validation.get("representative_project_fixtures"), 2)
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
            or not _valid_named_checks(validation.get("representative_project_fixtures"), 2)
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


def cmd_override_request(args: argparse.Namespace, paths: HarnessPaths) -> int:
    override_id = validate_id(args.override_id, "override id")
    target_id = validate_id(args.target_id, "override target id")
    target_contract_sha256 = args.target_contract_sha256.lower()
    if not re.fullmatch(r"[0-9a-f]{64}", target_contract_sha256):
        raise HarnessError("--target-contract-sha256 must be full lowercase SHA-256")
    settings = parse_override_settings(
        args.setting,
        roles=ROLE_TIER_MAP,
        target_kind=args.target_kind,
    )
    expires_at = parse_time(args.expires_at)
    if expires_at is None or expires_at <= dt.datetime.now(dt.timezone.utc):
        raise HarnessError("override expiry must be in the future")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "request Chief override for")
        require_plan_ready(paths, state, "request Chief override")
        session_id = require_root_session(paths, state, args.session_id)
        if any(
            item.get("override_id") == override_id
            for item in state.get("override_requests", [])
        ):
            raise HarnessError(f"override already exists: {override_id}")
        recorded = now_iso()
        item = {
            "integrity_version": 1,
            "version": 1,
            "override_id": override_id,
            "status": "awaiting_chief",
            "target_kind": args.target_kind,
            "target_id": target_id,
            "target_task_id": state["task_id"],
            "task_plan_sha256": state["plan_sha256"],
            "target_contract_sha256": target_contract_sha256,
            "scope": require_evidence_detail(args.scope, "override scope"),
            "requested_settings": settings,
            "user_position": {
                "rationale": require_evidence_detail(
                    args.user_rationale, "user override rationale"
                ),
                "evidence": require_evidence_detail(
                    args.user_evidence, "user override evidence"
                ),
                "authority_boundary": (
                    "root attestation of direct user discussion; AOI does not "
                    "authenticate the human speaker"
                ),
            },
            "deliberation": {
                "chief_preliminary_assessment": require_evidence_detail(
                    args.chief_assessment, "Chief preliminary assessment"
                ),
                "alternatives": [
                    require_evidence_detail(value, "override alternative")
                    for value in args.alternative
                ],
            },
            "root_session_id": session_id,
            "root_owner": state.get("owner"),
            "chief_decision": None,
            "consumption": None,
            "revocation": None,
            "expires_at": expires_at.isoformat(timespec="microseconds"),
            "created_at": recorded,
            "updated_at": recorded,
        }
        state.setdefault("override_requests", []).append(item)
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(item, args.json)
    return 0


def cmd_override_arbitrate(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "arbitrate Chief override for")
        item = override_by_id(state, args.override_id)
        if item.get("version") != args.expected_version:
            raise HarnessError("override arbitration CAS failed")
        if item.get("status") != "awaiting_chief" or is_expired(
            item.get("expires_at")
        ):
            raise HarnessError("override is not awaiting a current Chief decision")
        session_id = require_root_session(paths, state, args.session_id)
        if args.decision == "approved":
            approved = parse_override_settings(
                args.approved_setting or [
                    f"{key}={value}"
                    for key, value in item["requested_settings"].items()
                ],
                roles=ROLE_TIER_MAP,
                target_kind=str(item.get("target_kind", "")),
            )
            if approved != item.get("requested_settings"):
                raise HarnessError(
                    "changing approved settings requires a new target contract and "
                    "override request"
                )
            item["status"] = "approved"
        else:
            if args.approved_setting:
                raise HarnessError("rejected override may not carry approved settings")
            approved = {}
            item["status"] = "rejected"
        recorded = now_iso()
        item["version"] = int(item["version"]) + 1
        item["chief_decision"] = {
            "decision": args.decision,
            "approved_settings": approved,
            "target_contract_sha256": item["target_contract_sha256"],
            "rationale": require_evidence_detail(
                args.rationale, "Chief override rationale"
            ),
            "risk_boundary": require_evidence_detail(
                args.risk_boundary, "Chief override risk boundary"
            ),
            "rollback_condition": require_evidence_detail(
                args.rollback_condition, "Chief override rollback condition"
            ),
            "compensating_controls": [
                require_evidence_detail(value, "override compensating control")
                for value in args.compensating_control
            ],
            "non_overridable_guardrails": [
                "Chief lease and task-bound session authority",
                "current approved plan and exact claim coverage",
                "dispatch-before-work and packet/result integrity",
                "evidence-strength and technical PASS boundaries",
                "ARISE 12-thread and AOI depth-two hard ceilings",
                "Codex project trust, sandbox, and provider availability",
            ],
            "root_session_id": session_id,
            "recorded_at": recorded,
        }
        item["updated_at"] = recorded
        state.setdefault("decisions", []).append(
            f"Chief {args.decision} override {item['override_id']}: "
            f"{item['chief_decision']['rationale']}"
        )
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(item, args.json)
    return 0


def cmd_override_revoke(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "revoke Chief override for")
        item = override_by_id(state, args.override_id)
        if item.get("version") != args.expected_version:
            raise HarnessError("override revocation CAS failed")
        if item.get("status") != "approved":
            raise HarnessError("only an approved, unconsumed override may be revoked")
        session_id = require_root_session(paths, state, args.session_id)
        recorded = now_iso()
        item["version"] = int(item["version"]) + 1
        item["status"] = "revoked"
        item["revocation"] = {
            "reason": require_evidence_detail(args.reason, "override revocation reason"),
            "root_session_id": session_id,
            "recorded_at": recorded,
        }
        item["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(item, args.json)
    return 0


def _codex_home(args: argparse.Namespace) -> Path:
    if args.codex_home:
        return Path(args.codex_home)
    configured = os.environ.get("CODEX_HOME")
    return Path(configured) if configured else Path.home() / ".codex"


def _task_resource_worktree(paths: HarnessPaths, state: dict[str, Any]) -> Path:
    worktree = validated_state_worktree(paths, state)
    if worktree != Path(state.get("worktree", "")).resolve():
        raise HarnessError("task resource worktree identity changed")
    return worktree


def _require_task_lock_coverage(
    paths: HarnessPaths, state: dict[str, Any], locks: Iterable[str]
) -> list[str]:
    worktree = _task_resource_worktree(paths, state)
    normalized = [
        validate_lock_identity(paths, lock, repo_root=worktree) for lock in locks
    ]
    held = [
        str(lock)
        for claim in claims_owned_by_task(paths, state["task_id"])
        if claim.get("status") in RESERVING_CLAIM_STATUSES
        for lock in claim.get("locks", [])
    ]
    missing = [
        lock for lock in normalized if not any(lock_covers(owner, lock) for owner in held)
    ]
    if missing:
        raise HarnessError(
            "Codex resource targets lack reserving claim coverage: "
            + ", ".join(missing)
        )
    return normalized


def _resource_plan(
    args: argparse.Namespace,
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    proposed_override_settings: dict[str, str | int] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    active_selections = [
        item
        for item in state.get("execution_selections", [])
        if item.get("status") == "active"
        and (
            not args.execution_selection_id
            or item.get("selection_id") == args.execution_selection_id
        )
    ]
    if args.execution_selection_id and len(active_selections) != 1:
        raise HarnessError("Codex resource plan selection is missing or inactive")
    if not args.execution_selection_id and len(active_selections) > 1:
        raise HarnessError(
            "multiple active execution selections exist; pass --execution-selection-id"
        )
    if active_selections:
        _require_execution_selection_snapshots_current(
            state, active_selections[0], include_steward=True
        )
        _validate_selection_resource_envelope(state, active_selections[0])
    if proposed_override_settings is not None:
        if not args.override_id:
            raise HarnessError("proposed resource settings require --override-id")
        override_settings = proposed_override_settings
    else:
        override_settings = approved_override_settings(
            state,
            args.override_id,
            target_kind="resource_config",
            target_id=args.event_id,
        )
    return build_codex_resource_plan(
        event_id=args.event_id,
        root=_task_resource_worktree(paths, state),
        config=paths.project,
        state=state,
        codex_home=_codex_home(args),
        managed_roles=args.role,
        platform_max_threads=args.max_threads,
        platform_max_depth=args.max_depth,
        execution_selection_id=args.execution_selection_id,
        override_id=args.override_id,
        override_settings=override_settings,
    )


def cmd_codex_config_plan(args: argparse.Namespace, paths: HarnessPaths) -> int:
    validate_id(args.event_id, "resource config event id")
    proposed_settings: dict[str, str | int] | None = None
    if args.proposed_setting:
        proposed_settings = parse_override_settings(
            args.proposed_setting,
            roles=ROLE_TIER_MAP,
            target_kind="resource_config",
        )
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "plan Codex resource configuration for")
        require_plan_ready(paths, state, "plan Codex resource configuration")
        plan, _files = _resource_plan(
            args,
            paths,
            state,
            proposed_override_settings=proposed_settings,
        )
        if args.override_id and proposed_settings is None:
            require_override_target_contract(
                state, args.override_id, plan["plan_sha256"]
            )
    emit(plan, args.json)
    return 0


def cmd_codex_config_apply(args: argparse.Namespace, paths: HarnessPaths) -> int:
    event_id = validate_id(args.event_id, "resource config event id")
    expected_plan = args.expected_plan_sha256.lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_plan):
        raise HarnessError("--expected-plan-sha256 must be full lowercase SHA-256")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "apply Codex resource configuration for")
        require_plan_ready(paths, state, "apply Codex resource configuration")
        session_id = require_root_session(paths, state, args.session_id)
        if any(
            event.get("event_id") == event_id
            for event in state.get("resource_config_events", [])
        ):
            raise HarnessError(f"resource config event already exists: {event_id}")
        plan, files = _resource_plan(args, paths, state)
        require_override_target_contract(state, args.override_id, plan["plan_sha256"])
        if plan["plan_sha256"] != expected_plan:
            raise HarnessError("Codex resource plan changed after Chief review")
        _require_task_lock_coverage(paths, state, plan["required_locks"])
        recorded = now_iso()
        receipt = make_resource_receipt(
            event_id=event_id,
            plan=plan,
            files=files,
            applied_at=recorded,
            root_session_id=session_id,
        )
        receipt_path = task_dir(paths, state["task_id"]) / "results" / (
            f"resource-config-{event_id}.json"
        )
        receipt_payload = (
            json.dumps(receipt, indent=2, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        receipt_sha = hashlib.sha256(receipt_payload).hexdigest()
        if args.override_id:
            refreshed_settings = approved_override_settings(
                state,
                args.override_id,
                target_kind="resource_config",
                target_id=event_id,
            )
            if refreshed_settings != plan["override_settings"]:
                raise HarnessError("resource override changed before file mutation")
        atomic_create_bytes(receipt_path, receipt_payload)
        applied = False
        state_published = False
        try:
            apply_resource_files(files)
            applied = True
            if args.override_id:
                refreshed_settings = approved_override_settings(
                    state,
                    args.override_id,
                    target_kind="resource_config",
                    target_id=event_id,
                )
                if refreshed_settings != plan["override_settings"]:
                    raise HarnessError("resource override changed during file apply")
            event = {
                "integrity_version": 1,
                "event_id": event_id,
                "status": "applied",
                "plan_sha256": plan["plan_sha256"],
                "task_plan_sha256": plan["approved_task_plan_sha256"],
                "override_id": args.override_id,
                "receipt_path": str(receipt_path),
                "receipt_sha256": receipt_sha,
                "resolved": plan["resolved"],
                "dynamic_envelope": plan["dynamic_envelope"],
                "execution_selection_id": plan["dynamic_envelope"].get(
                    "execution_selection_id", ""
                ),
                "required_locks": plan["required_locks"],
                "restart_required": True,
                "root_session_id": session_id,
                "applied_at": recorded,
                "rollback": None,
            }
            state.setdefault("resource_config_events", []).append(event)
            if args.override_id:
                override = override_by_id(state, args.override_id)
                if override.get("status") != "approved":
                    raise HarnessError("override authority changed before consumption")
                override["version"] = int(override["version"]) + 1
                override["status"] = "consumed"
                override["consumption"] = {
                    "consumer_command": "codex-config-apply",
                    "event_id": event_id,
                    "plan_sha256": plan["plan_sha256"],
                    "target_contract_sha256": plan["plan_sha256"],
                    "root_session_id": session_id,
                    "recorded_at": recorded,
                }
                override["updated_at"] = recorded
            _extend_unique(
                state,
                "changed_files",
                [item["relative_path"] for item in plan["files"]],
            )
            state.setdefault("facts", []).append(
                f"Applied Codex resource event {event_id}; a fresh trusted session "
                "is still required before claiming activation."
            )
            bump_task(state)
            write_task(paths, state)
            state_published = True
        except BaseException as exc:
            rollback_uncertain = isinstance(exc, ResourceApplyRollbackError)
            if applied and not state_published:
                try:
                    published_state = load_task(paths, args.task)
                except (HarnessError, OSError, ValueError):
                    published_state = {}
                published_events = [
                    item
                    for item in published_state.get("resource_config_events", [])
                    if item.get("event_id") == event_id
                    and item.get("plan_sha256") == plan["plan_sha256"]
                    and item.get("receipt_sha256") == receipt_sha
                    and item.get("status") == "applied"
                ]
                state_published = len(published_events) == 1
            if applied and not state_published:
                rollback_files_from_receipt(
                    root=_task_resource_worktree(paths, state), receipt=receipt
                )
            if not state_published and not rollback_uncertain:
                try:
                    receipt_path.unlink()
                except FileNotFoundError:
                    pass
            if rollback_uncertain:
                raise HarnessError(
                    "Codex resource apply and automatic rollback both failed; "
                    f"recovery receipt retained at {receipt_path}"
                ) from exc
            if state_published:
                raise HarnessError(
                    "Codex resource state and files were published, but the final "
                    "durability step reported an error; event retained for doctor/reconcile"
                ) from exc
            raise
        write_index(paths)
    emit(
        {
            "event_id": event_id,
            "status": "applied",
            "plan_sha256": plan["plan_sha256"],
            "receipt_path": str(receipt_path),
            "receipt_sha256": receipt_sha,
            "restart_required": True,
            "routing_verified": False,
        },
        args.json,
    )
    return 0


def cmd_codex_config_rollback(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "roll back Codex resource configuration for")
        session_id = require_root_session(paths, state, args.session_id)
        matches = [
            event
            for event in state.get("resource_config_events", [])
            if event.get("event_id") == args.event_id
        ]
        if len(matches) != 1 or matches[0].get("status") != "applied":
            raise HarnessError("resource config event is not uniquely applied")
        event = matches[0]
        receipt_path = Path(str(event.get("receipt_path", "")))
        expected_receipt_path = (
            task_dir(paths, state["task_id"])
            / "results"
            / f"resource-config-{args.event_id}.json"
        )
        if (
            receipt_path != expected_receipt_path
            or not receipt_path.is_file()
            or receipt_path.is_symlink()
            or sha256_file(receipt_path) != event.get("receipt_sha256")
        ):
            raise HarnessError("resource config rollback receipt is missing or changed")
        receipt = load_json(receipt_path)
        receipt_plan = receipt.get("plan")
        if (
            receipt.get("schema_version") != RESOURCE_RECEIPT_SCHEMA_VERSION
            or receipt.get("event_id") != event.get("event_id")
            or receipt.get("plan_sha256") != event.get("plan_sha256")
            or receipt_plan.get("approved_task_plan_sha256")
            != event.get("task_plan_sha256")
            or receipt.get("task_id") != state.get("task_id")
            or receipt.get("root_session_id") != event.get("root_session_id")
            or receipt.get("applied_at") != event.get("applied_at")
            or receipt.get("restart_required") != event.get("restart_required")
            or not isinstance(receipt_plan, dict)
            or receipt_plan.get("plan_sha256") != event.get("plan_sha256")
            or resource_plan_sha256(receipt_plan) != event.get("plan_sha256")
            or receipt_plan.get("resolved") != event.get("resolved")
            or receipt_plan.get("dynamic_envelope")
            != event.get("dynamic_envelope")
            or receipt_plan.get("required_locks") != event.get("required_locks")
        ):
            raise HarnessError("resource config receipt binding is invalid")
        _require_task_lock_coverage(paths, state, event.get("required_locks", []))
        rollback_reason = require_evidence_detail(
            args.reason, "resource config rollback reason"
        )
        prior_event = copy.deepcopy(event)
        rollback_files_from_receipt(
            root=_task_resource_worktree(paths, state), receipt=receipt
        )
        recorded = now_iso()
        event["status"] = "rolled_back"
        event["rollback"] = {
            "reason": rollback_reason,
            "root_session_id": session_id,
            "recorded_at": recorded,
        }
        bump_task(state)
        state_published = False
        try:
            write_task(paths, state)
            state_published = True
            write_index(paths)
        except BaseException as exc:
            if not state_published:
                try:
                    published_state = load_task(paths, args.task)
                except (HarnessError, OSError, ValueError) as probe_exc:
                    raise HarnessError(
                        "Codex resource files were rolled back, but task-state "
                        "publication failed and the published state cannot be read; "
                        f"receipt retained at {receipt_path}"
                    ) from probe_exc
                published_events = [
                    item
                    for item in published_state.get("resource_config_events", [])
                    if item == event
                ]
                state_published = len(published_events) == 1
                if not state_published:
                    prior_events = [
                        item
                        for item in published_state.get("resource_config_events", [])
                        if item == prior_event
                    ]
                    if len(prior_events) != 1:
                        raise HarnessError(
                            "Codex resource rollback state publication is ambiguous; "
                            f"receipt retained at {receipt_path}"
                        ) from exc
            if state_published:
                raise HarnessError(
                    "Codex resource files and rolled-back state were published, but "
                    "the final durability/index step reported an error"
                ) from exc
            try:
                reapply_files_from_receipt(
                    root=_task_resource_worktree(paths, state), receipt=receipt
                )
            except BaseException as recovery_exc:
                raise HarnessError(
                    "Codex resource files were rolled back, task-state publication "
                    "failed, and exact re-apply also failed; "
                    f"receipt retained at {receipt_path}"
                ) from recovery_exc
            raise HarnessError(
                "Codex resource rollback state publication failed; exact applied "
                "bytes were restored and the event remains applied"
            ) from exc
    emit(event, args.json)
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
        "owner_packet_id": str(job.get("owner_packet_id", "")),
        "owner_packet_contract_sha256": str(
            job.get("owner_packet_contract_sha256", "")
        ),
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
            or str(event.get("owner_packet_id", ""))
            != str(job.get("owner_packet_id", ""))
            or str(event.get("owner_packet_contract_sha256", ""))
            != str(job.get("owner_packet_contract_sha256", ""))
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

    add_file("project/aoi.toml", paths.config)
    add_tree("project/state", paths.harness)
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
            "AOI_BACKUP_ROOT",
            str(Path.home() / ".local" / "state" / "aoi" / "backups" / paths.root.name),
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
    archive_path = destination / f"aoi-state-{archive_sha[:16]}.tar.gz"
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
        "durability_boundary": "same-host recovery copy; not off-host disaster recovery",
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


def cmd_context_receipt_record(
    args: argparse.Namespace, paths: HarnessPaths
) -> int:
    receipt_id = validate_id(args.receipt_id, "context receipt id")
    expected_sha = require_text(
        args.receipt_sha256, "codebase-memory receipt SHA-256"
    ).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise HarnessError("codebase-memory receipt SHA-256 must be full 64 hex")
    supersedes = args.supersedes_receipt_id or ""
    if supersedes:
        validate_id(supersedes, "superseded context receipt id")
    if args.requirement == "required" and args.freshness_profile == "receipt-only":
        raise HarnessError(
            "a required codebase-memory receipt needs an independently defined freshness profile"
        )
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "record context receipt for")
        require_plan_ready(paths, state, "record context receipt")
        if state.get("profile") == "mini":
            raise HarnessError("mini task may not record context-provider receipts")
        root_session_id = require_root_session(paths, state, args.session_id)
        existing_errors = context_receipt_integrity_errors(paths, state)
        if existing_errors:
            raise HarnessError(
                "existing context receipt integrity failed: " + "; ".join(existing_errors)
            )
        records = state.setdefault("context_provider_receipts", [])
        if any(item.get("receipt_id") == receipt_id for item in records):
            raise HarnessError(f"context receipt already exists: {receipt_id}")
        active = active_context_receipt_records(state)
        if active:
            if len(active) != 1 or supersedes != active[0].get("receipt_id"):
                raise HarnessError(
                    "a new codebase-memory receipt must supersede the exact active receipt"
                )
        elif supersedes:
            raise HarnessError("context receipt cannot supersede a missing active receipt")
        _, source_data = read_regular_artifact(
            args.receipt,
            "codebase-memory receipt",
            max_bytes=CODEBASE_MEMORY_RECEIPT_MAX_BYTES,
            require_utf8=True,
        )
        actual_sha = hashlib.sha256(source_data).hexdigest()
        if actual_sha != expected_sha:
            raise HarnessError(
                f"codebase-memory receipt SHA-256 mismatch: expected {expected_sha}, actual {actual_sha}"
            )
        payload = parse_receipt_bytes(source_data)
        snapshot = snapshot_evidence_artifact(
            paths,
            state["task_id"],
            args.receipt,
            expected_sha,
            label="codebase-memory receipt",
            basename=f"codebase-memory-receipt-{receipt_id}.json",
            max_bytes=CODEBASE_MEMORY_RECEIPT_MAX_BYTES,
        )
        record = make_receipt_record(
            receipt_id=receipt_id,
            snapshot=snapshot,
            payload=payload,
            requirement=args.requirement,
            freshness_profile=args.freshness_profile,
            supersedes_receipt_id=supersedes,
            recorded_by_session_id=root_session_id,
            recorded_at=now_iso(),
        )
        records.append(record)
        chain_errors = receipt_chain_errors(state)
        if chain_errors:
            raise HarnessError("context receipt chain is invalid: " + "; ".join(chain_errors))
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    provider_report = evaluate_live_receipt(
        payload,
        freshness_profile=record["freshness_profile"],
        project_root=record["project_root"],
    )
    emit({"record": record, "provider_report": provider_report}, args.json)
    return 0


def cmd_codebase_memory_benchmark_validate(
    args: argparse.Namespace, _paths: HarnessPaths
) -> int:
    _, data = read_regular_artifact(
        args.record,
        "codebase-memory benchmark record",
        max_bytes=COMMAND_ARTIFACT_MAX_BYTES,
        require_utf8=True,
    )
    try:
        payload = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HarnessError(f"codebase-memory benchmark record JSON is invalid: {exc}") from exc
    record = validate_codebase_memory_benchmark_record(payload)
    emit(
        {
            "valid": True,
            "run_id": record["run_id"],
            "case_pair_id": record["case_pair_id"],
            "variant": record["variant"],
            "run_status": record["run_status"],
            "evidence_class": CODEBASE_MEMORY_BENCHMARK_EVIDENCE_CLASS,
            "close_qualifying": False,
        },
        args.json,
    )
    return 0


def cmd_codebase_memory_benchmark_record(
    args: argparse.Namespace, paths: HarnessPaths
) -> int:
    benchmark_id = validate_id(args.benchmark_id, "codebase-memory benchmark id")
    if len(args.record) != len(args.record_sha256):
        raise HarnessError("each benchmark --record requires one --record-sha256")
    if not args.record:
        raise HarnessError("codebase-memory benchmark requires at least one record")
    prepared: list[tuple[str, str, bytes, dict[str, Any]]] = []
    for source_value, expected_value in zip(args.record, args.record_sha256, strict=True):
        expected = require_text(expected_value, "benchmark record SHA-256").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise HarnessError("benchmark record SHA-256 must be full 64 hex")
        source, data = read_regular_artifact(
            source_value,
            "codebase-memory benchmark record",
            max_bytes=COMMAND_ARTIFACT_MAX_BYTES,
            require_utf8=True,
        )
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise HarnessError(
                f"benchmark record SHA-256 mismatch: expected {expected}, actual {actual}"
            )
        try:
            payload = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise HarnessError(f"benchmark record JSON is invalid: {exc}") from exc
        prepared.append(
            (
                str(source),
                expected,
                data,
                validate_codebase_memory_benchmark_record(payload),
            )
        )
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "record codebase-memory benchmark for")
        require_plan_ready(paths, state, "record codebase-memory benchmark")
        if state.get("profile") == "mini":
            raise HarnessError("mini task may not record context-provider benchmarks")
        root_session_id = require_root_session(paths, state, args.session_id)
        if any(
            item.get("benchmark_id") == benchmark_id
            for item in state.setdefault("context_provider_benchmarks", [])
        ):
            raise HarnessError(f"codebase-memory benchmark already exists: {benchmark_id}")
        integrity_errors = context_receipt_integrity_errors(paths, state)
        if integrity_errors:
            raise HarnessError("context receipt integrity failed: " + "; ".join(integrity_errors))
        active = active_context_receipt_records(state)
        if len(active) != 1 or active[0].get("receipt_id") != args.receipt_id:
            raise HarnessError("benchmark must bind the exact active codebase-memory receipt")
        receipt = active[0]
        receipt_payload = validate_receipt_record(paths, state, receipt)
        provider_report = evaluate_live_receipt(
            receipt_payload,
            freshness_profile=receipt["freshness_profile"],
            project_root=receipt["project_root"],
        )
        records = [item[3] for item in prepared]
        graph_query_observed = any(
            item["variant"] == "codebase_memory_assisted"
            and item["trace"]["graph_query_calls"] > 0
            for item in records
        )
        if graph_query_observed and (
            provider_report["provider_health"] != "healthy"
            or provider_report["freshness"] != "fresh"
        ):
            raise HarnessError(
                "benchmark graph observations require a currently healthy and fresh receipt"
            )
        for item in records:
            controls = item["controls"]
            if (
                controls["provider_receipt_sha256"] != receipt["receipt_sha256"]
                or controls["source_set_id"] != receipt["source_set_id"]
            ):
                raise HarnessError("benchmark record differs from the active receipt/source set")
            if item["freshness"]["profile"] != receipt["freshness_profile"]:
                raise HarnessError("benchmark record freshness profile differs from AOI receipt")
            if item["freshness"]["status"] != provider_report["freshness"]:
                raise HarnessError("benchmark record freshness status differs from AOI doctor")
        summary = summarize_codebase_memory_benchmark_records(
            records, generated_at=now_iso()
        )
        snapshots: list[dict[str, Any]] = []
        for index, (source, expected, _data, _payload) in enumerate(prepared, start=1):
            snapshots.append(
                snapshot_evidence_artifact(
                    paths,
                    state["task_id"],
                    source,
                    expected,
                    label="codebase-memory benchmark record",
                    basename=(
                        f"codebase-memory-benchmark-{benchmark_id}-input-{index:03}.json"
                    ),
                    max_bytes=COMMAND_ARTIFACT_MAX_BYTES,
                )
            )
        summary_path = (
            task_dir(paths, state["task_id"])
            / "results"
            / f"codebase-memory-benchmark-{benchmark_id}-summary.json"
        )
        atomic_write_json(summary_path, summary)
        ledger = {
            "integrity_version": 1,
            "record_version": 1,
            "benchmark_id": benchmark_id,
            "provider": "codebase-memory",
            "receipt_id": receipt["receipt_id"],
            "receipt_sha256": receipt["receipt_sha256"],
            "source_set_id": receipt["source_set_id"],
            "input_snapshots": snapshots,
            "summary_path": str(summary_path),
            "summary_sha256": sha256_file(summary_path),
            "summary_size_bytes": summary_path.stat().st_size,
            "evidence_class": CODEBASE_MEMORY_BENCHMARK_EVIDENCE_CLASS,
            "close_qualifying": False,
            "recorded_by_session_id": root_session_id,
            "recorded_at": now_iso(),
        }
        ledger["record_sha256"] = context_record_sha256(
            benchmark_ledger_preimage(ledger)
        )
        state["context_provider_benchmarks"].append(ledger)
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(
        {"benchmark": ledger, "summary": summary, "provider_report": provider_report},
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

    p = sub.add_parser("init", help="initialize AOI in the current Git repository")
    source = p.add_mutually_exclusive_group()
    source.add_argument("--project-name")
    source.add_argument(
        "--config",
        help="initialize from one strictly validated candidate aoi.toml",
    )
    p.add_argument(
        "--expected-config-sha256",
        help=(
            "required with --config; fail unless it still matches this "
            "approved full SHA-256"
        ),
    )
    p.add_argument(
        "--replace-policy-sha256",
        help=(
            "replace a reviewed non-packaged managed policy only if its current "
            "full SHA-256 still matches"
        ),
    )
    add_json_argument(p)
    p.set_defaults(handler=cmd_init)

    p = sub.add_parser(
        "config-check",
        help="validate and summarize a candidate aoi.toml without applying it",
    )
    p.add_argument("--file", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_config_check)

    p = sub.add_parser(
        "context-receipt-record",
        help="record an immutable optional context-provider receipt",
    )
    p.add_argument("--task", required=True)
    p.add_argument("--provider", choices=["codebase-memory"], required=True)
    p.add_argument("--receipt-id", required=True)
    p.add_argument("--receipt", required=True)
    p.add_argument("--receipt-sha256", required=True)
    p.add_argument(
        "--requirement", choices=["optional", "required"], default="optional"
    )
    p.add_argument(
        "--freshness-profile",
        choices=sorted(CODEBASE_MEMORY_FRESHNESS_PROFILES),
        default="receipt-only",
    )
    p.add_argument("--supersedes-receipt-id")
    p.add_argument("--session-id", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_context_receipt_record)

    p = sub.add_parser(
        "codebase-memory-benchmark-validate",
        help="validate one navigation-only codebase-memory A/B record",
    )
    p.add_argument("--record", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_codebase_memory_benchmark_validate)

    p = sub.add_parser(
        "codebase-memory-benchmark-record",
        help="snapshot and summarize paired navigation-only A/B records",
    )
    p.add_argument("--task", required=True)
    p.add_argument("--benchmark-id", required=True)
    p.add_argument("--receipt-id", required=True)
    p.add_argument("--record", action="append", default=[], required=True)
    p.add_argument("--record-sha256", action="append", default=[], required=True)
    p.add_argument("--session-id", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_codebase_memory_benchmark_record)

    p = sub.add_parser("chief-acquire", help="acquire the project Chief lease")
    p.add_argument("--session-id", required=True)
    p.add_argument("--ttl-seconds", type=int, default=CHIEF_DEFAULT_TTL_SECONDS)
    p.add_argument(
        "--credential-home",
        help="optional absolute repo-external credential store root",
    )
    add_json_argument(p)
    p.set_defaults(handler=cmd_chief_acquire)

    p = sub.add_parser("chief-renew", help="renew the current Chief lease")
    p.add_argument("--ttl-seconds", type=int, default=CHIEF_DEFAULT_TTL_SECONDS)
    add_json_argument(p)
    p.set_defaults(handler=cmd_chief_renew)

    p = sub.add_parser("chief-release", help="release the current Chief lease")
    p.add_argument("--reason", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_chief_release)

    p = sub.add_parser(
        "chief-takeover",
        help="replace an expired lease or explicitly force replacement of a live lease",
    )
    p.add_argument("--session-id", required=True)
    p.add_argument("--expected-epoch", type=int, required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--force-live", action="store_true")
    p.add_argument("--ttl-seconds", type=int, default=CHIEF_DEFAULT_TTL_SECONDS)
    p.add_argument(
        "--credential-home",
        help="optional absolute repo-external credential store root",
    )
    add_json_argument(p)
    p.set_defaults(handler=cmd_chief_takeover)

    p = sub.add_parser("chief-status", help="show non-secret Chief lease status")
    add_json_argument(p)
    p.set_defaults(handler=cmd_chief_status)

    p = sub.add_parser(
        "pilot-init",
        help="create a self-contained closed-alpha tester kit",
        description="create a self-contained closed-alpha tester kit",
    )
    p.add_argument("--output", required=True)
    p.add_argument("--force", action="store_true")
    p.add_argument(
        "--allow-unverified-windows-acl",
        action="store_true",
        help="acknowledge that AOI cannot verify private file ACLs on native Windows",
    )
    add_json_argument(p)
    p.set_defaults(handler=cmd_pilot_init)

    p = sub.add_parser(
        "pilot-validate",
        help="strictly validate one sanitized closed-alpha run record",
        description="strictly validate one sanitized closed-alpha run record",
    )
    p.add_argument("--record", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_pilot_validate)

    p = sub.add_parser(
        "pilot-summary",
        help="produce a deterministic, de-identified descriptive summary",
        description="produce a deterministic, de-identified descriptive summary",
    )
    p.add_argument("--record", action="append", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--format", choices=("json", "csv"), default="json")
    p.add_argument("--force", action="store_true")
    add_json_argument(p)
    p.set_defaults(handler=cmd_pilot_summary)

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

    def add_execution_selection_arguments(
        parser: argparse.ArgumentParser, *, override_required: bool
    ) -> None:
        parser.add_argument("--task", required=True)
        parser.add_argument("--selection-id", required=True)
        parser.add_argument("--work-unit-id", required=True)
        parser.add_argument("--supersedes-selection-id")
        parser.add_argument("--mode", choices=sorted(EXECUTION_MODES), required=True)
        parser.add_argument("--lane", action="append", default=[], required=True)
        parser.add_argument("--steward-lane-id")
        parser.add_argument("--scope", required=True)
        parser.add_argument(
            "--sequential-dependency",
            choices=sorted(DEPENDENCY_LEVELS),
            required=True,
        )
        parser.add_argument(
            "--tool-density", choices=sorted(TOOL_DENSITIES), required=True
        )
        parser.add_argument(
            "--shared-context", choices=sorted(DEPENDENCY_LEVELS), required=True
        )
        parser.add_argument("--rationale", required=True)
        parser.add_argument("--falsification-condition", required=True)
        parser.add_argument("--escalation-condition", required=True)
        parser.add_argument("--session-id", required=True)
        parser.add_argument(
            "--override-id", required=override_required, default=""
        )

    p = sub.add_parser("execution-select-plan")
    add_execution_selection_arguments(p, override_required=True)
    p.add_argument("--proposed-setting", action="append", default=[], required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_execution_select_plan)

    p = sub.add_parser("execution-select")
    add_execution_selection_arguments(p, override_required=False)
    add_json_argument(p)
    p.set_defaults(handler=cmd_execution_select)

    p = sub.add_parser("execution-brief-record")
    p.add_argument("--task", required=True)
    p.add_argument("--brief-id", required=True)
    p.add_argument("--execution-selection-id", required=True)
    p.add_argument("--steward-lane-id", required=True)
    p.add_argument("--steward-packet-id")
    p.add_argument("--packet-id", action="append", default=[], required=True)
    p.add_argument("--cross-lane-session-id", action="append", default=[])
    p.add_argument("--summary", required=True)
    p.add_argument("--dissent", required=True)
    p.add_argument("--blocker", required=True)
    p.add_argument("--recommendation", required=True)
    p.add_argument("--session-id", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_execution_brief_record)

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

    register_resource_commands(
        sub,
        handlers={
            "override_request": cmd_override_request,
            "override_arbitrate": cmd_override_arbitrate,
            "override_revoke": cmd_override_revoke,
            "codex_config_plan": cmd_codex_config_plan,
            "codex_config_apply": cmd_codex_config_apply,
            "codex_config_rollback": cmd_codex_config_rollback,
        },
        add_json_argument=add_json_argument,
    )

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

    p = sub.add_parser(
        "materialize-artifacts",
        help="snapshot still-valid legacy packet and verification artifacts",
    )
    p.add_argument("--task", required=True)
    p.add_argument("--verification-index", type=int, action="append", default=[])
    add_json_argument(p)
    p.set_defaults(handler=cmd_materialize_artifacts)

    p = sub.add_parser(
        "packet-input-recover-from-tar",
        help="recover one drifted legacy done-packet input from a bound tar member",
    )
    p.add_argument("--task", required=True)
    p.add_argument("--packet-id", required=True)
    p.add_argument("--input-index", type=int, required=True)
    p.add_argument("--expected-input-sha256", required=True)
    p.add_argument("--carrier-input-index", type=int, required=True)
    p.add_argument("--carrier-sha256", required=True)
    p.add_argument("--archive-member", required=True)
    p.add_argument("--expected-result-sha256", required=True)
    p.add_argument("--reason", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_packet_input_recover_from_tar)

    p = sub.add_parser(
        "verification-supersede",
        help="retire one exact legacy verification in favor of a later valid pass",
    )
    p.add_argument("--task", required=True)
    p.add_argument("--verification-index", type=int, required=True)
    p.add_argument("--expected-record-sha256", required=True)
    p.add_argument("--replacement-index", type=int, required=True)
    p.add_argument("--replacement-record-sha256", required=True)
    p.add_argument("--reason", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_verification_supersede)

    p = sub.add_parser(
        "verification-supersession-seal",
        help="seal a legacy supersession against its exact canonical replacement",
    )
    p.add_argument("--task", required=True)
    p.add_argument("--verification-index", type=int, required=True)
    p.add_argument("--expected-current-record-sha256", required=True)
    p.add_argument("--expected-source-record-sha256", required=True)
    p.add_argument("--replacement-index", type=int, required=True)
    p.add_argument(
        "--expected-replacement-before-materialize-sha256", required=True
    )
    p.add_argument("--expected-replacement-current-sha256", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_verification_supersession_seal)

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
    p.add_argument("--steward-synthesis-for-selection-id")
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

    p = sub.add_parser("packet-arm")
    p.add_argument("--task", required=True)
    p.add_argument("--packet-id", required=True)
    p.add_argument(
        "--expected-agent-type",
        required=True,
        help=(
            "Codex transport agent_type expected from SubagentStart; independent "
            "of the packet's AOI technical role"
        ),
    )
    p.add_argument("--expires-at", required=True)
    p.add_argument("--parent-session-id")
    add_json_argument(p)
    p.set_defaults(handler=cmd_packet_arm)

    p = sub.add_parser("packet-disarm")
    p.add_argument("--task", required=True)
    p.add_argument("--packet-id", required=True)
    p.add_argument("--reason", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_packet_disarm)

    p = sub.add_parser("packet-update")
    p.add_argument("--task", required=True)
    p.add_argument("--packet-id", required=True)
    p.add_argument(
        "--status",
        choices=sorted(PACKET_STATUSES - {"ready", "armed"}),
        required=True,
    )
    p.add_argument("--agent-id")
    p.add_argument("--actual-role", choices=sorted(ROLE_TIER_MAP))
    p.add_argument("--actual-model-tier", choices=sorted(set(ROLE_TIER_MAP.values())))
    p.add_argument("--routing-evidence")
    p.add_argument("--manual-unverified-reason")
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

    p = sub.add_parser("subagent-incident-account")
    p.add_argument("--task", required=True)
    p.add_argument("--incident-id", required=True)
    p.add_argument(
        "--disposition",
        choices=["no_material_work", "work_discarded", "manual_unverified"],
        required=True,
    )
    p.add_argument("--reason", required=True)
    p.add_argument("--evidence", required=True)
    p.add_argument("--session-id", required=True)
    add_json_argument(p)
    p.set_defaults(handler=cmd_subagent_incident_account)

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
    p.add_argument("--owner-packet-id")
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
