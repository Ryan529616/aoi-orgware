"""Repo bootstrap, task/claim lifecycle, Chief-lease, and pilot-kit command
family: parser registration and command bodies.

This module owns the ``init``/``config-check`` bootstrap commands, the
task/claim state-machine commands (``init-task`` through ``checkpoint``), the
``chief-*`` Chief-lease commands, and the ``pilot-*`` closed-alpha kit commands,
together with their small helpers.  It stays a leaf of the composition root: it
imports only sibling packages (``harnesslib``, ``config``, ``pilot``,
``git_plumbing``, ``state_lookup``, ``execution_policy``) and the standard
library, never the monolithic :mod:`aoi_orgware.cli`.  The CLI imports the
command bodies back for handler wiring, re-exports ``cmd_init`` (a test calls
``cli.cmd_init`` directly) and ``_chief_credential`` (its dispatch pre-flight
reuses it), and keeps the mutable-constant/factory composition root.

The session-binding trio (``bind_session_unlocked``,
``ensure_subagent_parent_mapping_unlocked``, ``unbind_all_sessions_unlocked``)
STAYS in ``cli`` because the extraction contract and keep-list bodies share it;
``bind_session_unlocked`` is threaded back in through the services object for
``cmd_init_task``/``cmd_bind_session``.

Composition-root concerns that cannot be imported statically are threaded in
through the frozen :class:`TaskLifecycleCmdServices` dataclass built by
``cli._task_lifecycle_cmd_services()``:

* ``state_lock`` is the one infra name the suite fault-injects via
  ``mock.patch.object(cli, "state_lock", ...)`` while driving ``init`` (the
  init/config-race tests), so it is bound LATE through a lambda that resolves
  ``cli``'s current global at call time.  ``write_task``/``write_index`` and the
  ``atomic_*`` primitives are never patched on ``cli`` for this family, so the
  relocated bodies import them directly from ``harnesslib`` (byte-identical, no
  seam); the other locking bodies likewise use the direct ``harnesslib``
  ``state_lock`` — only ``cmd_init`` needs the late-bound one.
* CLI-resident derived-state/composition helpers that remain defined in ``cli``
  as their single source of truth are direct-bound (none is fault-injected nor
  rebound by ``apply_project_config``): ``reload_locked_paths``
  (``_reload_locked_paths``), ``require_plan_ready``, ``check_session_id``,
  ``validate_mini_locks``, ``plan_path``, ``commit_checkpoint``, ``substitute``,
  ``template_text`` and the keep-list ``bind_session_unlocked``.
* CLI-owned values shared with keep-list bodies (or asserted off ``cli`` in the
  suite) are value-bound so ``cli`` stays their single source of truth:
  ``root_session_mapping_kind``/``subagent_parent_mapping_kind``
  (also read by the session-binding trio), ``known_managed_policy_sha256``
  (a mutable set that project config does not rebind, asserted via
  ``cli.KNOWN_MANAGED_POLICY_SHA256``) and ``plan_fallback``.

``emit``, ``require_text``, ``_extend_unique`` and ``_resource_text`` are pure
leaf helpers (no project-mutable or test-patched dependency; ``_extend_unique``
and ``_resource_text`` also stay in ``cli`` for keep-list bodies) redeclared
module-locally, mirroring the sibling extraction precedent, so the relocated
bodies bind the module-local copies rather than reaching back into ``cli``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.resources
import json
import os
import re
import shutil
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..config import ProjectConfig, default_config_text, load_config_path
from ..execution_policy import EXECUTION_POLICY_VERSION, TASK_EXECUTION_SCHEMA_VERSION
from ..git_plumbing import (
    FULL_COMMIT_RE,
    git_is_ancestor,
    git_metadata,
    legacy_ambiguities,
    state_worktree,
)
from ..harnesslib import (
    ACTIVE_JOB_STATUSES,
    ACTIVE_PACKET_STATUSES,
    CHIEF_DEFAULT_TTL_SECONDS,
    RESERVING_CLAIM_STATUSES,
    SCHEMA_VERSION,
    TASK_PHASES,
    TERMINAL_CLAIM_STATUSES,
    HarnessError,
    HarnessPaths,
    acquire_chief_authority,
    admit_new_claim_locks,
    atomic_create_bytes,
    atomic_create_text,
    atomic_write_bytes,
    atomic_write_json,
    atomic_write_text,
    baselines_for_locks,
    bootstrap_chief_state_lock,
    bump_task,
    checkpoint_matches,
    chief_authority_summary,
    claim_path,
    claims_for_task,
    claims_owned_by_task,
    directory_has_any_entry,
    discover_root,
    find_conflicts,
    get_paths,
    import_legacy,
    legacy_pending_path,
    load_chief_authority,
    load_chief_credential,
    load_claim_file,
    load_json,
    load_task,
    lock_covers,
    normalize_lock,
    now_iso,
    paths_for_project,
    platform_capabilities,
    preflight_layout,
    prepare_checkpoint,
    record_legacy_decision,
    release_chief_authority,
    remove_chief_credential,
    renew_chief_authority,
    require_complete_layout,
    session_path,
    sha256_file,
    state_lock,
    takeover_chief_authority,
    task_dir,
    task_state_path,
    task_summary,
    validate_claim_lock_identities,
    validate_existing_regular_file,
    validate_id,
    validate_lock_identity,
    write_index,
    write_task,
)
from ..pilot import initialize_kit, load_record, write_summary
from ..state_lookup import require_open_task


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_BOOTSTRAP_HANDLER_NAMES = frozenset({"init", "config_check"})

_CHIEF_HANDLER_NAMES = frozenset(
    {
        "chief_acquire",
        "chief_renew",
        "chief_release",
        "chief_takeover",
        "chief_status",
    }
)

_PILOT_HANDLER_NAMES = frozenset({"pilot_init", "pilot_validate", "pilot_summary"})

_HANDLER_NAMES = frozenset(
    {
        "init_task",
        "start_mini",
        "finish_mini",
        "approve_plan",
        "bind_session",
        "unbind_session",
        "import_legacy",
        "check_locks",
        "inspect_legacy",
        "claim",
        "set_claim_status",
        "release_claim",
        "audit_legacy",
        "set_phase",
        "adopt_current_branch",
        "checkpoint",
        "retarget_task",
        "retire_risk",
    }
)


class _StateLock(Protocol):
    def __call__(self, paths: HarnessPaths) -> Any: ...


class _ReloadLockedPaths(Protocol):
    def __call__(self, paths: HarnessPaths) -> HarnessPaths: ...


class _RequirePlanReady(Protocol):
    def __call__(
        self, paths: HarnessPaths, state: dict[str, Any], action: str
    ) -> None: ...


class _CheckSessionId(Protocol):
    def __call__(self, session_id: str) -> str: ...


class _ValidateMiniLocks(Protocol):
    def __call__(self, raw_locks: Iterable[str]) -> list[str]: ...


class _PlanPath(Protocol):
    def __call__(self, paths: HarnessPaths, state: dict[str, Any]) -> Path: ...


class _CommitCheckpoint(Protocol):
    def __call__(self, paths: HarnessPaths, state: dict[str, Any]) -> Path: ...


class _Substitute(Protocol):
    def __call__(self, template: str, values: dict[str, str]) -> str: ...


class _TemplateText(Protocol):
    def __call__(self, paths: HarnessPaths, name: str, fallback: str) -> str: ...


class _BindSessionUnlocked(Protocol):
    def __call__(
        self,
        paths: HarnessPaths,
        state: dict[str, Any],
        session_id: str,
        *,
        bump: bool,
        force: bool = False,
    ) -> None: ...


@dataclass(frozen=True)
class TaskLifecycleCmdServices:
    """CLI-resident, fault-injected, and value-bound composition-root concerns.

    ``state_lock`` is bound late in ``cli._task_lifecycle_cmd_services()`` so a
    ``mock.patch.object(cli, "state_lock", ...)`` driving ``init`` is observed at
    call time; the remaining callables are direct-bound CLI-resident helpers
    (single source of truth in ``cli``), and the trailing fields are value-bound
    CLI-owned values.
    """

    state_lock: _StateLock
    reload_locked_paths: _ReloadLockedPaths
    require_plan_ready: _RequirePlanReady
    check_session_id: _CheckSessionId
    validate_mini_locks: _ValidateMiniLocks
    plan_path: _PlanPath
    commit_checkpoint: _CommitCheckpoint
    substitute: _Substitute
    template_text: _TemplateText
    bind_session_unlocked: _BindSessionUnlocked
    root_session_mapping_kind: str
    subagent_parent_mapping_kind: str
    known_managed_policy_sha256: Collection[str]
    plan_fallback: str


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


def _extend_unique(state: dict[str, Any], key: str, values: Iterable[str]) -> None:
    destination = state.setdefault(key, [])
    for value in values:
        cleaned = value.strip()
        if cleaned and cleaned not in destination:
            destination.append(cleaned)


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


def _require_pristine_bootstrap_state(paths: HarnessPaths) -> None:
    preflight_layout(paths)
    if not paths.harness.exists():
        return
    populated = directory_has_any_entry(
        paths.harness, "unconfigured AOI state directory"
    )
    if populated:
        raise HarnessError(
            "aoi.toml is missing while an AOI state tree already exists; restore the "
            "approved configuration instead of using unauthenticated init"
        )


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


def cmd_unbind_session(args: argparse.Namespace, paths: HarnessPaths, *, services: TaskLifecycleCmdServices) -> int:
    with state_lock(paths):
        session_id = services.check_session_id(args.session_id)
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
            mapping_kind = mapping.get("mapping_kind", services.root_session_mapping_kind)
            backlink_field = (
                "subagent_parent_session_ids"
                if mapping_kind == services.subagent_parent_mapping_kind
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


def cmd_config_check(args: argparse.Namespace, paths: HarnessPaths | None) -> int:
    root = discover_root()
    config, _raw, source = _explicit_config(root, args.file)
    emit(_config_summary(config, source), args.json)
    return 0


def cmd_init(args: argparse.Namespace, paths: HarnessPaths, *, services: TaskLifecycleCmdServices) -> int:
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
    with services.state_lock(initialized):
        initialized = services.reload_locked_paths(initialized)
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
                    current_policy_sha256 not in services.known_managed_policy_sha256
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


def cmd_chief_acquire(args: argparse.Namespace, paths: HarnessPaths, *, services: TaskLifecycleCmdServices) -> int:
    bootstrap_chief_state_lock(paths)
    with state_lock(paths, create_layout=False):
        paths = services.reload_locked_paths(paths)
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


def cmd_chief_renew(args: argparse.Namespace, paths: HarnessPaths, *, services: TaskLifecycleCmdServices) -> int:
    with state_lock(paths, create_layout=False):
        paths = services.reload_locked_paths(paths)
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


def cmd_chief_release(args: argparse.Namespace, paths: HarnessPaths, *, services: TaskLifecycleCmdServices) -> int:
    with state_lock(paths, create_layout=False):
        paths = services.reload_locked_paths(paths)
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


def cmd_chief_takeover(args: argparse.Namespace, paths: HarnessPaths, *, services: TaskLifecycleCmdServices) -> int:
    with state_lock(paths, create_layout=False):
        paths = services.reload_locked_paths(paths)
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


def cmd_init_task(args: argparse.Namespace, paths: HarnessPaths, *, services: TaskLifecycleCmdServices) -> int:
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
            "plan_approvals": [],
            "scope_revisions": [],
            **metadata,
        }
        directory = task_dir(paths, task_id)
        (directory / "packets").mkdir(parents=True, exist_ok=True)
        (directory / "results").mkdir(parents=True, exist_ok=True)
        plan = services.substitute(
            services.template_text(paths, "plan.md", services.plan_fallback),
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
            services.bind_session_unlocked(paths, state, args.session_id, bump=False)
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


def cmd_start_mini(args: argparse.Namespace, paths: HarnessPaths, *, services: TaskLifecycleCmdServices) -> int:
    task_id = validate_id(args.task_id, "task id")
    token = validate_id(args.token, "claim token")
    session_id = services.check_session_id(args.session_id)
    locks = services.validate_mini_locks(args.lock)
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
    locks = services.validate_mini_locks(locks)
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
        admit_new_claim_locks(
            paths,
            locks,
            repo_root=mini_worktree,
            allow_nonexistent=False,
            mini=True,
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
            "facts": [
                "Mini lifecycle initialized, approved, bound, and claimed with "
                "ordinary-exception rollback; process termination may require recovery."
            ],
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
            "plan_approvals": [
                {
                    "plan_sha256": hashlib.sha256(plan.encode("utf-8")).hexdigest(),
                    "approved_at": timestamp,
                    "note": "Atomic constrained mini lifecycle",
                    "revision": 1,
                }
            ],
            "scope_revisions": [],
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


def cmd_approve_plan(args: argparse.Namespace, paths: HarnessPaths, *, services: TaskLifecycleCmdServices) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "approve plan for")
        source = services.plan_path(paths, state)
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
        previous_digest = str(state.get("plan_sha256", ""))
        has_dispatched_work = bool(state.get("packets") or state.get("jobs"))
        coverage_note = ""
        if previous_digest and previous_digest != digest and has_dispatched_work:
            # Packets/jobs already ran under the earlier approved plan. Without a
            # coverage note the close gate would validate against a plan that
            # never governed that work (observed on ARISE: 39 packets and 40
            # jobs closed against a later audit plan that replaced the original).
            coverage_note = require_text(
                args.coverage_note or "",
                "plan re-approval coverage note (--coverage-note): state which "
                "packets/jobs the superseded plan governed",
            )
        approved_at = now_iso()
        state["plan_ready"] = True
        state["plan_sha256"] = digest
        state["plan_approved_at"] = approved_at
        state["plan_approval_note"] = require_text(args.note, "approval note")
        approval = {
            "plan_sha256": digest,
            "approved_at": approved_at,
            "note": state["plan_approval_note"],
            "revision": int(state.get("revision", 0)) + 1,
        }
        if coverage_note:
            approval["coverage_note"] = coverage_note
        state.setdefault("plan_approvals", []).append(approval)
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit({"task_id": args.task, "plan_sha256": digest, "plan_ready": True}, args.json)
    return 0


def cmd_bind_session(args: argparse.Namespace, paths: HarnessPaths, *, services: TaskLifecycleCmdServices) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "bind session to")
        services.bind_session_unlocked(paths, state, args.session_id, bump=True, force=args.force)
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


def cmd_claim(args: argparse.Namespace, paths: HarnessPaths, *, services: TaskLifecycleCmdServices) -> int:
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
        services.require_plan_ready(paths, state, "acquire claim")
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
        planned = admit_new_claim_locks(
            paths,
            locks,
            repo_root=claim_worktree,
            allow_nonexistent=args.allow_nonexistent,
        )
        baselines = baselines_for_locks(paths, locks, repo_root=claim_worktree)
        for planned_lock in planned:
            if planned_lock in baselines:
                baselines[planned_lock]["planned"] = True
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
            "baselines": baselines,
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


def cmd_release_claim(
    args: argparse.Namespace,
    paths: HarnessPaths,
    *,
    emit_result: bool = True,
) -> int:
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
    if emit_result:
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


def cmd_adopt_current_branch(args: argparse.Namespace, paths: HarnessPaths, *, services: TaskLifecycleCmdServices) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "adopt current branch for")
        services.require_plan_ready(paths, state, "adopt current branch")
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


def _next_risk_id(state: dict[str, Any]) -> str:
    highest = 0
    for item in state.get("risks", []):
        if isinstance(item, dict):
            match = re.fullmatch(r"r([1-9][0-9]{0,5})", str(item.get("id", "")))
            if match:
                highest = max(highest, int(match.group(1)))
    return f"r{highest + 1}"


def _append_risks(state: dict[str, Any], values: Iterable[str]) -> None:
    """Append typed open risks, skipping texts already present in any shape."""

    existing = {
        item if isinstance(item, str) else str(item.get("text", ""))
        for item in state.get("risks", [])
    }
    for value in values:
        if value in existing:
            continue
        existing.add(value)
        state.setdefault("risks", []).append(
            {
                "id": _next_risk_id(state),
                "text": value,
                "status": "open",
                "recorded_at": now_iso(),
            }
        )


def _require_changed_files_in_worktree(
    state: dict[str, Any], values: Iterable[str], *, allow_outside: bool
) -> None:
    """Reject absolute changed-file records outside the bound worktree.

    Observed on ARISE (fec-worth-hunt): a task bound to one repository recorded
    committed mutations in a different repository, leaving them unclaimed and
    unverified. Relative paths are implicitly worktree-scoped and stay allowed.
    """

    worktree = str(state.get("worktree", "") or "")
    for value in values:
        candidate = Path(value)
        if not candidate.is_absolute():
            continue
        if allow_outside:
            continue
        if not worktree:
            raise HarnessError(
                f"changed file {value!r} is absolute but the task has no bound "
                "worktree; use a repo-relative path or --allow-outside-worktree"
            )
        try:
            candidate.resolve().relative_to(Path(worktree).resolve())
        except (ValueError, OSError) as exc:
            raise HarnessError(
                f"changed file {value!r} is outside the task worktree "
                f"{worktree!r}; acknowledge cross-repository mutation with "
                "--allow-outside-worktree"
            ) from exc


def cmd_checkpoint(
    args: argparse.Namespace,
    paths: HarnessPaths,
    *,
    services: TaskLifecycleCmdServices,
    emit_result: bool = True,
) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "checkpoint")
        _require_changed_files_in_worktree(
            state,
            args.changed_file,
            allow_outside=bool(getattr(args, "allow_outside_worktree", False)),
        )
        _extend_unique(state, "facts", args.fact)
        _extend_unique(state, "decisions", args.decision)
        _extend_unique(state, "rejected_paths", args.rejected)
        _extend_unique(state, "changed_files", args.changed_file)
        _extend_unique(state, "blockers", args.blocker)
        _append_risks(state, args.risk)
        if args.next_action:
            state["next_action"] = args.next_action
        if state["status"] in {"active", "blocked"} and not state.get("next_action"):
            raise HarnessError("active checkpoint requires an exact next action")
        bump_task(state, checkpoint_required=False)
        state["checkpoint_revision"] = state["revision"]
        state["checkpoint_required"] = False
        checkpoint = services.commit_checkpoint(paths, state)
        write_index(paths)
    if emit_result:
        emit(
            {
                "task_id": state["task_id"],
                "revision": state["revision"],
                "checkpoint": str(checkpoint),
            },
            args.json,
        )
    return 0


def cmd_retarget_task(args: argparse.Namespace, paths: HarnessPaths) -> int:
    """Re-anchor an open task's registered scope with a durable revision trail.

    Observed on ARISE: title/objective/completion_boundary are written only at
    task creation, so a legitimately re-scoped task could only close against
    its stale registered scope (outcome said "achieved" beside an unmet
    boundary). Retargeting records old/new/reason and forces plan re-approval.
    """

    changes = {
        "title": args.title,
        "objective": args.objective,
        "completion_boundary": args.completion_boundary,
    }
    changes = {key: value for key, value in changes.items() if value is not None}
    if not changes:
        raise HarnessError(
            "retarget requires at least one of --title, --objective, "
            "--completion-boundary"
        )
    for key, value in changes.items():
        changes[key] = require_text(value, key.replace("_", " "))
    reason = require_text(args.reason, "retarget reason")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "retarget")
        old = {key: str(state.get(key, "")) for key in changes}
        if all(old[key] == value for key, value in changes.items()):
            raise HarnessError("retarget changes nothing; scope is already exact")
        revision_entry = {
            "at": now_iso(),
            "reason": reason,
            "old": old,
            "new": dict(changes),
            "plan_sha256_at_retarget": str(state.get("plan_sha256", "")),
        }
        for key, value in changes.items():
            state[key] = value
        # The approved plan described the old scope; force explicit re-approval.
        state["plan_ready"] = False
        state.setdefault("scope_revisions", []).append(revision_entry)
        state.setdefault("facts", []).append(
            "Task scope retargeted (" + ", ".join(sorted(changes)) + f"): {reason}"
        )
        bump_task(state)
        revision_entry["revision"] = state["revision"]
        write_task(paths, state)
        write_index(paths)
    emit(
        {
            "task_id": args.task,
            "retargeted": sorted(changes),
            "revision": revision_entry["revision"],
            "plan_ready": False,
        },
        args.json,
    )
    return 0


def cmd_retire_risk(args: argparse.Namespace, paths: HarnessPaths) -> int:
    """Retire or mark-materialized one recorded risk with a reason.

    Observed on ARISE: risks[] was append-only prose with no removal path, so
    a closed task's checkpoint still carried 39 risks including seven
    already-superseded restatements the same state's facts had resolved.
    """

    if bool(args.id) == bool(args.text_exact):
        raise HarnessError("provide exactly one of --id or --text-exact")
    reason = require_text(args.reason, "retire reason")
    status = "materialized" if args.materialized else "retired"
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "retire risk for")
        risks = state.setdefault("risks", [])
        target: dict[str, Any] | None = None
        if args.id:
            for item in risks:
                if isinstance(item, dict) and item.get("id") == args.id:
                    target = item
                    break
            if target is None:
                raise HarnessError(f"no typed risk with id {args.id!r}")
        else:
            matches = [
                (index, item)
                for index, item in enumerate(risks)
                if (item if isinstance(item, str) else str(item.get("text", "")))
                == args.text_exact
            ]
            if len(matches) != 1:
                raise HarnessError(
                    f"--text-exact must match exactly one risk; found {len(matches)}"
                )
            index, item = matches[0]
            if isinstance(item, str):
                # Upgrade the legacy string in place so the retirement is typed.
                target = {
                    "id": _next_risk_id(state),
                    "text": item,
                    "status": "open",
                    "recorded_at": "",
                }
                risks[index] = target
            else:
                target = item
        if target.get("status") != "open":
            raise HarnessError(
                f"risk {target.get('id')!r} is already {target.get('status')}"
            )
        target["status"] = status
        target["retired_at"] = now_iso()
        target["retire_reason"] = reason
        if args.superseded_by:
            target["superseded_by"] = require_text(
                args.superseded_by, "superseded-by reference"
            )
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(
        {
            "task_id": args.task,
            "risk_id": target["id"],
            "status": status,
        },
        args.json,
    )
    return 0


def _check_handlers(names: frozenset[str], handlers: Mapping[str, Handler], label: str) -> None:
    missing = sorted(names - handlers.keys())
    unexpected = sorted(handlers.keys() - names)
    if missing or unexpected:
        raise ValueError(
            f"{label} command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )


def register_bootstrap_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register ``init`` and ``config-check``."""

    _check_handlers(_BOOTSTRAP_HANDLER_NAMES, handlers, "bootstrap")

    parser = subparsers.add_parser(
        "init", help="initialize AOI in the current Git repository"
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--project-name")
    source.add_argument(
        "--config",
        help="initialize from one strictly validated candidate aoi.toml",
    )
    parser.add_argument(
        "--expected-config-sha256",
        help=(
            "required with --config; fail unless it still matches this "
            "approved full SHA-256"
        ),
    )
    parser.add_argument(
        "--replace-policy-sha256",
        help=(
            "replace a reviewed non-packaged managed policy only if its current "
            "full SHA-256 still matches"
        ),
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["init"])

    parser = subparsers.add_parser(
        "config-check",
        help="validate and summarize a candidate aoi.toml without applying it",
    )
    parser.add_argument("--file", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["config_check"])


def register_chief_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register the ``chief-*`` Chief-lease command family."""

    _check_handlers(_CHIEF_HANDLER_NAMES, handlers, "chief")

    parser = subparsers.add_parser(
        "chief-acquire", help="acquire the project Chief lease"
    )
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--ttl-seconds", type=int, default=CHIEF_DEFAULT_TTL_SECONDS)
    parser.add_argument(
        "--credential-home",
        help="optional absolute repo-external credential store root",
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["chief_acquire"])

    parser = subparsers.add_parser(
        "chief-renew", help="renew the current Chief lease"
    )
    parser.add_argument("--ttl-seconds", type=int, default=CHIEF_DEFAULT_TTL_SECONDS)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["chief_renew"])

    parser = subparsers.add_parser(
        "chief-release", help="release the current Chief lease"
    )
    parser.add_argument("--reason", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["chief_release"])

    parser = subparsers.add_parser(
        "chief-takeover",
        help="replace an expired lease or explicitly force replacement of a live lease",
    )
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--expected-epoch", type=int, required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--force-live", action="store_true")
    parser.add_argument("--ttl-seconds", type=int, default=CHIEF_DEFAULT_TTL_SECONDS)
    parser.add_argument(
        "--credential-home",
        help="optional absolute repo-external credential store root",
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["chief_takeover"])

    parser = subparsers.add_parser(
        "chief-status", help="show non-secret Chief lease status"
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["chief_status"])


def register_pilot_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register the ``pilot-*`` closed-alpha tester-kit command family."""

    _check_handlers(_PILOT_HANDLER_NAMES, handlers, "pilot")

    parser = subparsers.add_parser(
        "pilot-init",
        help="create a self-contained closed-alpha tester kit",
        description="create a self-contained closed-alpha tester kit",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--allow-unverified-windows-acl",
        action="store_true",
        help="acknowledge that AOI cannot verify private file ACLs on native Windows",
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["pilot_init"])

    parser = subparsers.add_parser(
        "pilot-validate",
        help="strictly validate one sanitized closed-alpha run record",
        description="strictly validate one sanitized closed-alpha run record",
    )
    parser.add_argument("--record", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["pilot_validate"])

    parser = subparsers.add_parser(
        "pilot-summary",
        help="produce a deterministic, de-identified descriptive summary",
        description="produce a deterministic, de-identified descriptive summary",
    )
    parser.add_argument("--record", action="append", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--format", choices=("json", "csv"), default="json")
    parser.add_argument("--force", action="store_true")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["pilot_summary"])


def register_task_lifecycle_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register task/claim lifecycle commands (init-task through checkpoint)."""

    _check_handlers(_HANDLER_NAMES, handlers, "task lifecycle")

    parser = subparsers.add_parser("init-task")
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--objective", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--completion-boundary", required=True)
    parser.add_argument("--next-action")
    parser.add_argument("--session-id")
    parser.add_argument("--worktree")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["init_task"])

    parser = subparsers.add_parser("start-mini")
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--objective", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--completion-boundary", required=True)
    parser.add_argument("--next-action")
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--worktree")
    parser.add_argument("--token", required=True)
    parser.add_argument("--lock", action="append", required=True)
    parser.add_argument("--intent", required=True)
    parser.add_argument("--validation", required=True)
    parser.add_argument("--expires-at", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["start_mini"])

    parser = subparsers.add_parser(
        "finish-mini",
        help="finish one verified mini task through delivery, release, checkpoint, and close",
    )
    parser.add_argument("--task", required=True)
    parser.add_argument(
        "--mode", choices=["local-only", "none", "pushed"], required=True
    )
    parser.add_argument("--detail", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument(
        "--commit",
        help=(
            "full 40-64 hex commit id; required with pushed so an interrupted "
            "finish request remains unambiguous"
        ),
    )
    parser.add_argument("--remote")
    parser.add_argument("--remote-ref")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["finish_mini"])

    parser = subparsers.add_parser("approve-plan")
    parser.add_argument("--task", required=True)
    parser.add_argument("--note", required=True)
    parser.add_argument(
        "--coverage-note",
        help=(
            "required when re-approving a changed plan after packets/jobs "
            "already ran: state which work the superseded plan governed"
        ),
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["approve_plan"])

    parser = subparsers.add_parser(
        "retarget-task",
        help="re-anchor an open task's title/objective/completion boundary",
    )
    parser.add_argument("--task", required=True)
    parser.add_argument("--title")
    parser.add_argument("--objective")
    parser.add_argument("--completion-boundary")
    parser.add_argument("--reason", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["retarget_task"])

    parser = subparsers.add_parser(
        "retire-risk",
        help="retire or mark-materialized one recorded task risk",
    )
    parser.add_argument("--task", required=True)
    parser.add_argument("--id")
    parser.add_argument("--text-exact")
    parser.add_argument("--reason", required=True)
    parser.add_argument("--materialized", action="store_true")
    parser.add_argument("--superseded-by")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["retire_risk"])

    parser = subparsers.add_parser("bind-session")
    parser.add_argument("--task", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--force", action="store_true")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["bind_session"])

    parser = subparsers.add_parser("unbind-session")
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--task")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["unbind_session"])

    parser = subparsers.add_parser("import-legacy")
    parser.add_argument("--source")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["import_legacy"])

    parser = subparsers.add_parser("check-locks")
    parser.add_argument("--lock", action="append", required=True)
    parser.add_argument("--ignore-token")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["check_locks"])

    parser = subparsers.add_parser("inspect-legacy")
    parser.add_argument("--token", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["inspect_legacy"])

    parser = subparsers.add_parser("claim")
    parser.add_argument("--task", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--kind", required=True)
    parser.add_argument("--lock", action="append", default=[], required=True)
    parser.add_argument("--intent", required=True)
    parser.add_argument("--validation", required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--adopt-legacy", action="store_true")
    parser.add_argument("--adoption-evidence")
    parser.add_argument("--ack-legacy-ambiguity", action="store_true")
    parser.add_argument("--allow-nonexistent", action="store_true")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["claim"])

    parser = subparsers.add_parser("set-claim-status")
    parser.add_argument("--token", required=True)
    parser.add_argument(
        "--status", choices=sorted(RESERVING_CLAIM_STATUSES), required=True
    )
    parser.add_argument("--reason", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["set_claim_status"])

    parser = subparsers.add_parser("release-claim")
    parser.add_argument("--token", required=True)
    parser.add_argument(
        "--status", choices=sorted(TERMINAL_CLAIM_STATUSES), required=True
    )
    parser.add_argument("--reason", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["release_claim"])

    parser = subparsers.add_parser("audit-legacy")
    parser.add_argument("--token", required=True)
    parser.add_argument(
        "--decision", choices=["still-active", "released", "stale"], required=True
    )
    parser.add_argument("--detail", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["audit_legacy"])

    parser = subparsers.add_parser("set-phase")
    parser.add_argument("--task", required=True)
    parser.add_argument("--phase", choices=sorted(TASK_PHASES), required=True)
    parser.add_argument("--task-status", choices=sorted({"active", "blocked"}))
    parser.add_argument("--summary")
    parser.add_argument("--next-action")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["set_phase"])

    parser = subparsers.add_parser("adopt-current-branch")
    parser.add_argument("--task", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--next-action")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["adopt_current_branch"])

    parser = subparsers.add_parser("checkpoint")
    parser.add_argument("--task", required=True)
    parser.add_argument("--fact", action="append", default=[])
    parser.add_argument("--decision", action="append", default=[])
    parser.add_argument("--rejected", action="append", default=[])
    parser.add_argument("--changed-file", action="append", default=[])
    parser.add_argument("--blocker", action="append", default=[])
    parser.add_argument("--risk", action="append", default=[])
    parser.add_argument(
        "--allow-outside-worktree",
        action="store_true",
        help="acknowledge recording a changed file outside the bound worktree",
    )
    parser.add_argument("--next-action")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["checkpoint"])


__all__ = [
    "TaskLifecycleCmdServices",
    "_explicit_config",
    "_config_summary",
    "_require_pristine_bootstrap_state",
    "_chief_identity",
    "_chief_credential",
    "_chief_acquisition_payload",
    "uncovered_dependencies_after_release",
    "cmd_unbind_session",
    "cmd_config_check",
    "cmd_init",
    "cmd_chief_acquire",
    "cmd_chief_renew",
    "cmd_chief_release",
    "cmd_chief_takeover",
    "cmd_chief_status",
    "cmd_pilot_init",
    "cmd_pilot_validate",
    "cmd_pilot_summary",
    "cmd_init_task",
    "cmd_start_mini",
    "cmd_approve_plan",
    "cmd_bind_session",
    "cmd_import_legacy",
    "cmd_check_locks",
    "cmd_inspect_legacy",
    "cmd_claim",
    "cmd_set_claim_status",
    "cmd_release_claim",
    "cmd_audit_legacy",
    "cmd_set_phase",
    "cmd_adopt_current_branch",
    "cmd_checkpoint",
    "cmd_retarget_task",
    "cmd_retire_risk",
    "register_bootstrap_commands",
    "register_chief_commands",
    "register_pilot_commands",
    "register_task_lifecycle_commands",
]
