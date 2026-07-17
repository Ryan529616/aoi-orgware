"""User/Chief override and Codex resource-control command family.

This module owns the ``override-*`` and ``codex-config-*`` command
implementations together with their plan/apply/rollback recovery helpers.  It
stays a leaf of the composition root: it imports only sibling packages
(``harnesslib``, ``resource_config``, ``resource_governance``, ``state_lookup``,
``execution_topology``) and the standard library, never the monolithic
:mod:`aoi_orgware.cli`.

Two composition-root concerns cannot be imported statically and are threaded in
through the frozen :class:`ResourceCmdServices` dataclass built by
``cli._resource_cmd_services()``:

* CLI-resident authority/derived-state operations (``require_plan_ready``,
  ``require_root_session``, ``approved_override_settings`` and
  ``validate_selection_resource_envelope`` — the latter two close over the
  mutable resource-governance policy) are direct-bound.
* Fault-injected and project-mutable names (``state_lock``, ``write_task``,
  ``write_index`` are patched via ``mock.patch.object(cli, ...)`` in the suite;
  ``ROLE_TIER_MAP`` is rebound by ``apply_project_config``) are bound LATE
  through lambdas so a patch/rebind of the ``cli`` global is still observed at
  call time.

``emit``, ``require_text``, ``require_evidence_detail`` and ``_extend_unique``
are pure leaf helpers (no project-mutable or test-patched dependency) redeclared
module-locally, mirroring the sibling extraction precedent, so the relocated
bodies bind the module-local copies rather than reaching back into ``cli``.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import os
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..execution_topology import _require_execution_selection_snapshots_current
from ..harnesslib import (
    HarnessError,
    HarnessPaths,
    RESERVING_CLAIM_STATUSES,
    atomic_create_bytes,
    bump_task,
    claims_owned_by_task,
    is_expired,
    load_json,
    load_task,
    lock_covers,
    now_iso,
    parse_time,
    sha256_file,
    task_dir,
    validate_id,
    validate_lock_identity,
    validated_state_worktree,
)
from ..resource_config import (
    AOI_MAX_DELEGATION_DEPTH,
    ARISE_MAX_THREADS_CEILING,
    OVERRIDE_TARGET_KINDS,
    RESOURCE_RECEIPT_SCHEMA_VERSION,
    ResourceApplyRollbackError,
    apply_resource_files,
    build_codex_resource_plan,
    make_resource_receipt,
    parse_override_settings,
    reapply_files_from_receipt,
    resource_plan_sha256,
    rollback_files_from_receipt,
)
from ..resource_governance import override_by_id, require_override_target_contract
from ..state_lookup import require_open_task


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset(
    {
        "override_request",
        "override_arbitrate",
        "override_revoke",
        "codex_config_plan",
        "codex_config_apply",
        "codex_config_rollback",
    }
)


class _StateLock(Protocol):
    def __call__(self, paths: HarnessPaths) -> Any: ...


class _WriteTask(Protocol):
    def __call__(self, paths: HarnessPaths, state: dict[str, Any]) -> None: ...


class _WriteIndex(Protocol):
    def __call__(self, paths: HarnessPaths) -> None: ...


class _RoleTierMap(Protocol):
    def __call__(self) -> Mapping[str, str]: ...


class _RequirePlanReady(Protocol):
    def __call__(
        self, paths: HarnessPaths, state: dict[str, Any], action: str
    ) -> None: ...


class _RequireRootSession(Protocol):
    def __call__(
        self, paths: HarnessPaths, state: dict[str, Any], session_id: str
    ) -> str: ...


class _ApprovedOverrideSettings(Protocol):
    def __call__(
        self,
        state: dict[str, Any],
        override_id: str,
        *,
        target_kind: str,
        target_id: str,
    ) -> dict[str, str | int]: ...


class _ValidateSelectionResourceEnvelope(Protocol):
    def __call__(
        self, state: dict[str, Any], selection: dict[str, Any]
    ) -> dict[str, Any] | None: ...


@dataclass(frozen=True)
class ResourceCmdServices:
    """CLI-resident, project-mutable, and fault-injected operations.

    ``state_lock``/``write_task``/``write_index``/``role_tier_map`` are bound
    late in the factory so a ``mock.patch.object(cli, ...)`` or an
    ``apply_project_config`` rebind of the ``cli`` global is observed at call
    time; the remaining fields are direct-bound CLI-resident helpers.
    """

    state_lock: _StateLock
    write_task: _WriteTask
    write_index: _WriteIndex
    role_tier_map: _RoleTierMap
    require_plan_ready: _RequirePlanReady
    require_root_session: _RequireRootSession
    approved_override_settings: _ApprovedOverrideSettings
    validate_selection_resource_envelope: _ValidateSelectionResourceEnvelope


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


def _extend_unique(state: dict[str, Any], key: str, values: Iterable[str]) -> None:
    destination = state.setdefault(key, [])
    for value in values:
        cleaned = value.strip()
        if cleaned and cleaned not in destination:
            destination.append(cleaned)


def cmd_override_request(
    args: argparse.Namespace, paths: HarnessPaths, *, services: ResourceCmdServices
) -> int:
    override_id = validate_id(args.override_id, "override id")
    target_id = validate_id(args.target_id, "override target id")
    target_contract_sha256 = args.target_contract_sha256.lower()
    if not re.fullmatch(r"[0-9a-f]{64}", target_contract_sha256):
        raise HarnessError("--target-contract-sha256 must be full lowercase SHA-256")
    settings = parse_override_settings(
        args.setting,
        roles=services.role_tier_map(),
        target_kind=args.target_kind,
    )
    expires_at = parse_time(args.expires_at)
    if expires_at is None or expires_at <= dt.datetime.now(dt.timezone.utc):
        raise HarnessError("override expiry must be in the future")
    with services.state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "request Chief override for")
        services.require_plan_ready(paths, state, "request Chief override")
        session_id = services.require_root_session(paths, state, args.session_id)
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
        services.write_task(paths, state)
        services.write_index(paths)
    emit(item, args.json)
    return 0


def cmd_override_arbitrate(
    args: argparse.Namespace, paths: HarnessPaths, *, services: ResourceCmdServices
) -> int:
    with services.state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "arbitrate Chief override for")
        item = override_by_id(state, args.override_id)
        if item.get("version") != args.expected_version:
            raise HarnessError("override arbitration CAS failed")
        if item.get("status") != "awaiting_chief" or is_expired(
            item.get("expires_at")
        ):
            raise HarnessError("override is not awaiting a current Chief decision")
        session_id = services.require_root_session(paths, state, args.session_id)
        if args.decision == "approved":
            approved = parse_override_settings(
                args.approved_setting or [
                    f"{key}={value}"
                    for key, value in item["requested_settings"].items()
                ],
                roles=services.role_tier_map(),
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
        services.write_task(paths, state)
        services.write_index(paths)
    emit(item, args.json)
    return 0


def cmd_override_revoke(
    args: argparse.Namespace, paths: HarnessPaths, *, services: ResourceCmdServices
) -> int:
    with services.state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "revoke Chief override for")
        item = override_by_id(state, args.override_id)
        if item.get("version") != args.expected_version:
            raise HarnessError("override revocation CAS failed")
        if item.get("status") != "approved":
            raise HarnessError("only an approved, unconsumed override may be revoked")
        session_id = services.require_root_session(paths, state, args.session_id)
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
        services.write_task(paths, state)
        services.write_index(paths)
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
    services: ResourceCmdServices,
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
        services.validate_selection_resource_envelope(state, active_selections[0])
    if proposed_override_settings is not None:
        if not args.override_id:
            raise HarnessError("proposed resource settings require --override-id")
        override_settings = proposed_override_settings
    else:
        override_settings = services.approved_override_settings(
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
        invocation_cwd=Path.cwd(),
    )


def cmd_codex_config_plan(
    args: argparse.Namespace, paths: HarnessPaths, *, services: ResourceCmdServices
) -> int:
    validate_id(args.event_id, "resource config event id")
    proposed_settings: dict[str, str | int] | None = None
    if args.proposed_setting:
        proposed_settings = parse_override_settings(
            args.proposed_setting,
            roles=services.role_tier_map(),
            target_kind="resource_config",
        )
    with services.state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "plan Codex resource configuration for")
        services.require_plan_ready(paths, state, "plan Codex resource configuration")
        plan, _files = _resource_plan(
            args,
            paths,
            state,
            proposed_override_settings=proposed_settings,
            services=services,
        )
        if args.override_id and proposed_settings is None:
            require_override_target_contract(
                state, args.override_id, plan["plan_sha256"]
            )
    emit(plan, args.json)
    return 0


def cmd_codex_config_apply(
    args: argparse.Namespace, paths: HarnessPaths, *, services: ResourceCmdServices
) -> int:
    event_id = validate_id(args.event_id, "resource config event id")
    expected_plan = args.expected_plan_sha256.lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_plan):
        raise HarnessError("--expected-plan-sha256 must be full lowercase SHA-256")
    with services.state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "apply Codex resource configuration for")
        services.require_plan_ready(paths, state, "apply Codex resource configuration")
        session_id = services.require_root_session(paths, state, args.session_id)
        if any(
            event.get("event_id") == event_id
            for event in state.get("resource_config_events", [])
        ):
            raise HarnessError(f"resource config event already exists: {event_id}")
        plan, files = _resource_plan(args, paths, state, services=services)
        require_override_target_contract(state, args.override_id, plan["plan_sha256"])
        applicability = str(plan.get("config_applicability", "unknown"))
        if applicability == "not_applicable" and not getattr(
            args, "allow_inapplicable", False
        ):
            raise HarnessError(
                "codex-config-apply refused: the target worktree is outside the "
                "invoking session's config ancestry, so no session like this one "
                f"will ever load the written config ({plan.get('applicability_basis')}). "
                "Start the fresh Codex session inside the target root, or pass "
                "--allow-inapplicable to record an explicit acknowledgement."
            )
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
            refreshed_settings = services.approved_override_settings(
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
                refreshed_settings = services.approved_override_settings(
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
                "config_applicability": plan.get("config_applicability", "unknown"),
                "applicability_basis": plan.get("applicability_basis", ""),
                "inapplicable_acknowledged": bool(
                    getattr(args, "allow_inapplicable", False)
                ),
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
            services.write_task(paths, state)
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
        services.write_index(paths)
    emit(
        {
            "event_id": event_id,
            "status": "applied",
            "plan_sha256": plan["plan_sha256"],
            "receipt_path": str(receipt_path),
            "receipt_sha256": receipt_sha,
            "restart_required": True,
            "config_applicability": plan.get("config_applicability", "unknown"),
            "applicability_basis": plan.get("applicability_basis", ""),
            "routing_verified": False,
        },
        args.json,
    )
    return 0


def cmd_codex_config_rollback(
    args: argparse.Namespace, paths: HarnessPaths, *, services: ResourceCmdServices
) -> int:
    with services.state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "roll back Codex resource configuration for")
        session_id = services.require_root_session(paths, state, args.session_id)
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
            services.write_task(paths, state)
            state_published = True
            services.write_index(paths)
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


def register_resource_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register the resource command family on one argparse subparser set."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "resource command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("override-request")
    parser.add_argument("--task", required=True)
    parser.add_argument("--override-id", required=True)
    parser.add_argument(
        "--target-kind", choices=sorted(OVERRIDE_TARGET_KINDS), required=True
    )
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--target-contract-sha256", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--setting", action="append", default=[], required=True)
    parser.add_argument("--user-rationale", required=True)
    parser.add_argument("--user-evidence", required=True)
    parser.add_argument("--chief-assessment", required=True)
    parser.add_argument("--alternative", action="append", default=[], required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["override_request"])

    parser = subparsers.add_parser("override-arbitrate")
    parser.add_argument("--task", required=True)
    parser.add_argument("--override-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--decision", choices=["approved", "rejected"], required=True)
    parser.add_argument("--approved-setting", action="append", default=[])
    parser.add_argument("--rationale", required=True)
    parser.add_argument("--risk-boundary", required=True)
    parser.add_argument("--rollback-condition", required=True)
    parser.add_argument(
        "--compensating-control", action="append", default=[], required=True
    )
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["override_arbitrate"])

    parser = subparsers.add_parser("override-revoke")
    parser.add_argument("--task", required=True)
    parser.add_argument("--override-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["override_revoke"])

    def add_plan_arguments(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--task", required=True)
        parser.add_argument("--event-id", required=True)
        parser.add_argument("--override-id", default="")
        parser.add_argument("--execution-selection-id", default="")
        parser.add_argument("--codex-home")
        parser.add_argument("--role", action="append", default=[])
        parser.add_argument(
            "--max-threads",
            type=int,
            default=ARISE_MAX_THREADS_CEILING,
            help="static project ceiling",
        )
        parser.add_argument(
            "--max-depth",
            type=int,
            default=AOI_MAX_DELEGATION_DEPTH,
            help="static project ceiling",
        )

    parser = subparsers.add_parser("codex-config-plan")
    add_plan_arguments(parser)
    parser.add_argument("--proposed-setting", action="append", default=[])
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["codex_config_plan"])

    parser = subparsers.add_parser("codex-config-apply")
    add_plan_arguments(parser)
    parser.add_argument("--expected-plan-sha256", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument(
        "--allow-inapplicable",
        action="store_true",
        help=(
            "acknowledge that the target worktree is outside the invoking "
            "session's config ancestry and apply anyway; the acknowledgement "
            "is recorded in the event and receipt"
        ),
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["codex_config_apply"])

    parser = subparsers.add_parser("codex-config-rollback")
    parser.add_argument("--task", required=True)
    parser.add_argument("--event-id", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["codex_config_rollback"])


__all__ = [
    "ResourceCmdServices",
    "cmd_codex_config_apply",
    "cmd_codex_config_plan",
    "cmd_codex_config_rollback",
    "cmd_override_arbitrate",
    "cmd_override_request",
    "cmd_override_revoke",
    "register_resource_commands",
]
