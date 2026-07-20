#!/usr/bin/env python3
"""Finite optional AOI bridge for one local Codex App Server turn.

The bridge is intentionally separate from the core ``aoi`` entry point.  Its
``issue`` command is the only surface that accepts a Chief credential.  The
``run`` controller receives only an immutable issuance marker and its exact
one-shot permit SHA, persists every lifecycle boundary synchronously, and
never retries a runtime start after an ambiguous request.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

from . import codex_transport_contracts as contracts
from . import codex_transport_authority as launch_authority
from . import codex_transport_projection as projection
from . import codex_transport_runtime as runtime
from . import codex_transport_mutation as mutation
from . import confidentiality
from . import harnesslib as h
from . import semantic_events as semantic
from . import semantic_store as store
from .codex_app_server_stdio import (
    AppServerError,
    CodexAppServerStdio,
    scrub_aoi_secret_env,
)
from .codex_transport_controller import (
    CodexTransportController,
    CodexTransportControllerError,
    ControllerResult,
)


MAX_CONTRACT_FILE_BYTES = 256 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")


class CodexTransportCLIError(RuntimeError):
    """The finite bridge command cannot proceed safely."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CodexTransportCLIError(f"JSON object repeats key {key!r}")
        result[key] = value
    return result


def _read_file(path_value: str, label: str, *, maximum: int) -> bytes:
    path = Path(path_value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    try:
        _identity, payload = h._read_regular_file_snapshot(
            path, label, max_bytes=maximum
        )
    except h.HarnessError as exc:
        raise CodexTransportCLIError(str(exc)) from exc
    return payload


def _read_object(path_value: str, label: str) -> dict[str, Any]:
    raw = _read_file(path_value, label, maximum=MAX_CONTRACT_FILE_BYTES)
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CodexTransportCLIError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CodexTransportCLIError(f"{label} must contain one JSON object")
    return value


def _read_prompt(path_value: str) -> str:
    raw = _read_file(
        path_value, "Codex bridge prompt", maximum=contracts.MAX_PROMPT_BYTES
    )
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CodexTransportCLIError("Codex bridge prompt is not strict UTF-8") from exc


def _paths(root: str | None) -> h.HarnessPaths:
    explicit = Path(root).expanduser() if root is not None else None
    try:
        return h.get_paths(explicit)
    except h.HarnessError as exc:
        raise CodexTransportCLIError(str(exc)) from exc


def _now() -> datetime:
    return datetime.now(UTC)


def _scrub_nonissuance_process_environment() -> None:
    """Drop reusable authority before any controller/readback work.

    ``issue`` is the only bridge command allowed to receive Chief authority.
    Every other entry point scrubs the current Python process as well as the
    eventual App Server child so direct library invocation cannot retain it.
    """

    scrubbed = scrub_aoi_secret_env(os.environ)
    for name in tuple(os.environ):
        if name not in scrubbed:
            os.environ.pop(name, None)


def _confidentiality_preflight(
    paths: h.HarnessPaths, intent: Mapping[str, Any]
) -> list[str]:
    """Enforce the narrow local-files storage boundary for one launch."""

    warnings = confidentiality.require_local_storage_path_allowed(
        paths.project.confidentiality,
        paths.harness,
        label="AOI artifact/CAS root",
    )
    if intent.get("sandbox") == "workspaceWrite":
        warnings.extend(
            confidentiality.require_local_storage_path_allowed(
                paths.project.confidentiality,
                Path(str(intent["cwd"])),
                label="workspaceWrite cwd",
            )
        )
    return list(dict.fromkeys(warnings))


def _require_fresh_pre_git_endpoint(
    paths: h.HarnessPaths,
    *,
    task_id: str,
    intent: Mapping[str, Any],
    pre_git_endpoint_cas_sha256: str | None,
) -> None:
    """Reject issue-to-run source or claim drift before permit consumption."""

    if intent.get("sandbox") != "workspaceWrite":
        if pre_git_endpoint_cas_sha256 is not None:
            raise CodexTransportCLIError(
                "readOnly launch unexpectedly binds a pre Git endpoint"
            )
        return
    if pre_git_endpoint_cas_sha256 is None:
        raise CodexTransportCLIError(
            "workspaceWrite launch lacks its preserved pre Git endpoint"
        )
    claims = h.claims_owned_by_task(paths, task_id)
    if not claims:
        raise CodexTransportCLIError(
            "workspaceWrite launch no longer has AOI claim records"
        )
    preserved = mutation.load_preserved_git_endpoint(
        paths,
        task_id=task_id,
        cas_sha256=pre_git_endpoint_cas_sha256,
        claims=claims,
    )
    recaptured = mutation.capture_git_endpoint(
        task_id,
        Path(str(intent["cwd"])),
        str(preserved["snapshot"]["baseline_head"]),
        claims,
    )
    if semantic.canonical_json_bytes(preserved) != semantic.canonical_json_bytes(
        recaptured
    ):
        raise CodexTransportCLIError(
            "pre-turn Git endpoint drifted after issuance and before process start"
        )
    if mutation.endpoint_pre_git_binding(recaptured) != intent.get(
        "pre_git_binding"
    ):
        raise CodexTransportCLIError(
            "fresh pre-turn Git endpoint differs from the sealed launch intent"
        )


def _aware_time(value: str, label: str) -> str:
    parsed = h.parse_tz_aware_time(value)
    if parsed is None:
        raise CodexTransportCLIError(f"{label} must be timezone-aware ISO-8601")
    return value


def _sha(value: str, label: str) -> str:
    if not _SHA256.fullmatch(value):
        raise CodexTransportCLIError(f"{label} must be lowercase SHA-256")
    return value


def _print(value: Mapping[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(dict(value), indent=2, sort_keys=True, ensure_ascii=False))
        return
    for key, item in value.items():
        print(f"{key}: {item}")


def _launch_is_committed(
    events: Sequence[Mapping[str, Any]], launch_id: str
) -> bool:
    try:
        state = semantic.replay_events(events)
        namespace = projection.codex_transport_namespace_from_projection(state)
    except (semantic.SemanticEventError, projection.CodexTransportProjectionError) as exc:
        raise CodexTransportCLIError(
            f"Codex transport projection cannot be authenticated: {exc}"
        ) from exc
    return launch_id in namespace["launches"]


def _issue(args: argparse.Namespace) -> dict[str, Any]:
    paths = _paths(args.root)
    intent = _read_object(args.intent_file, "Codex launch intent")
    decision = _read_object(args.decision_file, "Codex launch decision")
    permit = _read_object(args.permit_file, "Codex launch permit")
    recorded_at = _aware_time(args.recorded_at, "reservation recorded_at")
    credential = Path(args.chief_credential_file).expanduser()
    now = _now()
    try:
        checked_intent = contracts.validate_launch_intent(intent)
        confidentiality_warnings = _confidentiality_preflight(
            paths, checked_intent
        )
        with h.state_lock(paths, create_layout=False):
            events = store.load_semantic_events(paths, args.task)
            pre_endpoint_cas_sha256: str | None = None
            if checked_intent["sandbox"] == "workspaceWrite":
                if args.pre_git_endpoint_file is None:
                    raise CodexTransportCLIError(
                        "workspaceWrite issuance requires --pre-git-endpoint-file"
                    )
                claims = h.claims_owned_by_task(paths, args.task)
                if not claims:
                    raise CodexTransportCLIError(
                        "workspaceWrite issuance requires AOI claim records"
                    )
                pre_endpoint = _read_object(
                    args.pre_git_endpoint_file, "pre-turn Git endpoint"
                )
                checked_pre = mutation.validate_git_endpoint(
                    pre_endpoint, claims, sealed_claim_scope=False
                )
                # A caller-supplied, self-consistent endpoint is only a
                # proposed pre-image.  Re-capture under this same Chief/state
                # lock so a source or claim change between endpoint creation
                # and permit issuance cannot be published as launch evidence.
                # The sealed intent cwd is authoritative; comparing canonical
                # bytes also rejects a supplied endpoint from another
                # worktree even if its four digest binding fields collide.
                recaptured_pre = mutation.capture_git_endpoint(
                    args.task,
                    Path(checked_intent["cwd"]),
                    str(checked_pre["snapshot"]["baseline_head"]),
                    claims,
                )
                if semantic.canonical_json_bytes(
                    checked_pre
                ) != semantic.canonical_json_bytes(recaptured_pre):
                    raise CodexTransportCLIError(
                        "pre-turn Git endpoint drifted before permit issuance"
                    )
                if (
                    mutation.endpoint_pre_git_binding(recaptured_pre)
                    != checked_intent["pre_git_binding"]
                ):
                    raise CodexTransportCLIError(
                        "pre-turn Git endpoint does not match launch intent"
                    )
                preserved = mutation.preserve_git_endpoint(
                    paths,
                    task_id=args.task,
                    endpoint=recaptured_pre,
                    claims=claims,
                )
                pre_endpoint_cas_sha256 = preserved["sha256"]
            elif args.pre_git_endpoint_file is not None:
                raise CodexTransportCLIError(
                    "readOnly issuance cannot attach a pre Git endpoint"
                )
            token, _path = h.load_chief_credential(
                paths,
                session_id=args.chief_session_id,
                epoch=args.chief_epoch,
                credential_file=credential,
            )
            # Keep the optional bridge entry point separate, but reuse the
            # canonical core composition root for packet integrity.  Importing
            # lazily avoids loading the large core CLI for non-issue commands.
            from . import cli as core_cli

            packet_services = core_cli._packet_integrity_services()
            canonical_authority = launch_authority.require_canonical_launch_authority(
                paths,
                task_id=args.task,
                intent=intent,
                event_chain=events,
                current_time=now,
                packet_integrity_services=packet_services,
            )
            transaction = runtime.prepare_codex_launch_transaction(
                task_id=args.task,
                event_chain=events,
                intent=intent,
                decision=decision,
                permit=permit,
                launch_authority_contract=canonical_authority,
                launch_id=args.launch_id,
                command_id=args.command_id,
                recorded_at=recorded_at,
                current_time=now,
            )
            issued = runtime.issue_codex_launch_transaction(
                paths,
                transaction,
                events,
                chief_session_id=args.chief_session_id,
                chief_epoch=args.chief_epoch,
                chief_token=token,
                current_time=now,
                packet_integrity_services=packet_services,
                pre_git_endpoint_cas_sha256=pre_endpoint_cas_sha256,
            )
    except (
        h.HarnessError,
        store.SemanticStoreError,
        runtime.CodexTransportRuntimeError,
        mutation.CodexTransportMutationError,
        confidentiality.ConfidentialityError,
        contracts.CodexTransportContractError,
        KeyError,
        TypeError,
    ) as exc:
        if isinstance(exc, CodexTransportCLIError):
            raise
        raise CodexTransportCLIError(str(exc)) from exc
    return {
        "task_id": args.task,
        "launch_id": args.launch_id,
        "intent_sha256": transaction["intent"]["intent_sha256"],
        "permit_sha256": issued["permit_sha256"],
        "issuance_sha256": issued["issuance_sha256"],
        "idempotent_replay": issued["idempotent_replay"],
        "pre_git_endpoint_cas_sha256": pre_endpoint_cas_sha256,
        "confidentiality_warnings": confidentiality_warnings,
        "chief_credential_retained": False,
    }


def _recover_pending_locked(
    paths: h.HarnessPaths, launch: dict[str, Any]
) -> dict[str, Any]:
    """Commit at most one pre-published event and one terminal receipt."""

    for _attempt in range(3):
        pending_event = launch["pending_journal_event"]
        pending_terminal = launch["pending_terminal_receipt"]
        if pending_event is None and pending_terminal is None:
            return launch
        events = store.load_semantic_events(paths, launch["task_id"])
        if pending_event is not None:
            runtime.record_milestone(
                paths,
                task_id=launch["task_id"],
                launch_id=launch["launch_id"],
                intent=launch["intent"],
                reservation=launch["reservation"],
                journal=launch["journal"],
                milestone=pending_event,
                event_chain=events,
            )
        else:
            runtime.publish_terminal_receipt(
                paths,
                task_id=launch["task_id"],
                launch_id=launch["launch_id"],
                intent=launch["intent"],
                reservation=launch["reservation"],
                journal=launch["journal"],
                receipt=pending_terminal,
                event_chain=events,
            )
        launch = runtime.load_codex_transport_launch(
            paths,
            launch["task_id"],
            launch["launch_id"],
            store.load_semantic_events(paths, launch["task_id"]),
        )
    raise CodexTransportCLIError(
        "Codex transport recovery exceeded its one-event/one-receipt bound"
    )


def _load_or_reserve(
    paths: h.HarnessPaths, *, task_id: str, permit_sha256: str, now: datetime
) -> dict[str, Any]:
    marker = runtime.inspect_codex_launch_issuance(
        paths, task_id=task_id, permit_sha256=permit_sha256
    )
    launch_id = marker["launch_id"]
    events = store.load_semantic_events(paths, task_id)
    if not _launch_is_committed(events, launch_id):
        from . import cli as core_cli

        transaction = runtime.reconstruct_issued_launch_transaction(
            paths,
            task_id=task_id,
            permit_sha256=permit_sha256,
            event_chain=events,
            current_time=now,
        )
        _confidentiality_preflight(paths, transaction["intent"])
        _require_fresh_pre_git_endpoint(
            paths,
            task_id=task_id,
            intent=transaction["intent"],
            pre_git_endpoint_cas_sha256=marker[
                "pre_git_endpoint_cas_sha256"
            ],
        )
        runtime.reserve_codex_launch(
            paths,
            transaction,
            events,
            current_time=now,
            packet_integrity_services=core_cli._packet_integrity_services(),
        )
        events = store.load_semantic_events(paths, task_id)
    launch = runtime.load_codex_transport_launch(
        paths, task_id, launch_id, events
    )
    return _recover_pending_locked(paths, launch)


def _exact_prompt(prompt: str, intent: Mapping[str, Any]) -> None:
    raw = prompt.encode("utf-8")
    if (
        len(raw) != intent["prompt_size_bytes"]
        or hashlib.sha256(raw).hexdigest() != intent["prompt_sha256"]
    ):
        raise CodexTransportCLIError(
            "prompt bytes do not match the immutable launch intent"
        )


def _run_controller(
    paths: h.HarnessPaths,
    launch: dict[str, Any],
    *,
    prompt: str,
    timeout_seconds: float,
    interrupt_after_start: bool,
    executable: str | None,
) -> tuple[ControllerResult | None, dict[str, Any], str]:
    journal = [dict(row) for row in launch["journal"]]
    intent = dict(launch["intent"])
    reservation = dict(launch["reservation"])

    def persist_milestone(event: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        nonlocal journal
        try:
            with h.state_lock(paths, create_layout=False):
                if event.get("event_type") == "process_start_pending":
                    _confidentiality_preflight(paths, intent)
                    _require_fresh_pre_git_endpoint(
                        paths,
                        task_id=launch["task_id"],
                        intent=intent,
                        pre_git_endpoint_cas_sha256=launch[
                            "pre_git_endpoint_cas_sha256"
                        ],
                    )
                    runtime.require_codex_process_start_authority(
                        paths,
                        launch,
                        store.load_semantic_events(paths, launch["task_id"]),
                        current_time=_now(),
                    )
                result = runtime.record_milestone(
                    paths,
                    task_id=launch["task_id"],
                    launch_id=launch["launch_id"],
                    intent=intent,
                    reservation=reservation,
                    journal=journal,
                    milestone=event,
                    event_chain=store.load_semantic_events(paths, launch["task_id"]),
                )
                journal = [dict(row) for row in result["journal"]]
                return list(journal)
        except (h.HarnessError, store.SemanticStoreError, runtime.CodexTransportRuntimeError) as exc:
            raise CodexTransportCLIError(
                f"durable Codex milestone persistence failed: {exc}"
            ) from exc

    def publish_terminal(receipt: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            with h.state_lock(paths, create_layout=False):
                result = runtime.publish_terminal_receipt(
                    paths,
                    task_id=launch["task_id"],
                    launch_id=launch["launch_id"],
                    intent=intent,
                    reservation=reservation,
                    journal=journal,
                    receipt=receipt,
                    event_chain=store.load_semantic_events(paths, launch["task_id"]),
                )
            if result["receipt_sha256"] != receipt["receipt_sha256"]:
                raise CodexTransportCLIError(
                    "terminal receipt sink returned a divergent digest"
                )
            return dict(receipt)
        except (h.HarnessError, store.SemanticStoreError, runtime.CodexTransportRuntimeError) as exc:
            raise CodexTransportCLIError(
                f"durable Codex terminal publication failed: {exc}"
            ) from exc

    controller = CodexTransportController(
        intent=intent,
        reservation=reservation,
        journal=journal,
        persist_milestone=persist_milestone,
        publish_terminal=publish_terminal,
    )
    state = controller.state
    if launch["terminal_receipt"] is not None:
        return None, dict(launch["terminal_receipt"]), "not_started"
    if state.last_event_type != "reserved":
        result = controller.reconcile_after_crash()
        return result, dict(result.terminal_receipt), "not_started"

    sealed_executable = Path(str(intent["runtime_pin"]["executable_path"]))
    if not sealed_executable.is_absolute():
        raise CodexTransportCLIError(
            "sealed Codex executable path is not absolute"
        )
    if executable is not None:
        supplied_executable = Path(executable).expanduser()
        if not supplied_executable.is_absolute() or os.path.normcase(
            str(supplied_executable.resolve(strict=False))
        ) != os.path.normcase(str(sealed_executable.resolve(strict=False))):
            raise CodexTransportCLIError(
                "--executable differs from the sealed exact executable path"
            )
    executable_path = str(sealed_executable)
    adapter = CodexAppServerStdio(
        executable_path,
        cwd=str(intent["cwd"]),
    )
    result = controller.run(
        adapter,
        prompt=prompt,
        timeout_seconds=timeout_seconds,
        interrupt_after_start=interrupt_after_start,
    )
    event_types = {row["event_type"] for row in result.journal}
    process_evidence = (
        "process_started_observed"
        if "process_started" in event_types
        else (
            "process_start_pending_only"
            if "process_start_pending" in event_types
            else "not_started"
        )
    )
    return result, dict(result.terminal_receipt), process_evidence


def _run(args: argparse.Namespace) -> dict[str, Any]:
    _scrub_nonissuance_process_environment()
    paths = _paths(args.root)
    permit_sha256 = _sha(args.permit_sha256, "permit SHA-256")
    prompt = _read_prompt(args.prompt_file)
    if args.timeout_seconds <= 0 or args.timeout_seconds > 86400:
        raise CodexTransportCLIError("timeout-seconds must be in (0, 86400]")
    try:
        with h.state_lock(paths, create_layout=False):
            marker = runtime.inspect_codex_launch_issuance(
                paths, task_id=args.task, permit_sha256=permit_sha256
            )
            launch_id = str(marker["launch_id"])
        with runtime.codex_launch_process_lock(
            paths, task_id=args.task, launch_id=launch_id
        ):
            with h.state_lock(paths, create_layout=False):
                launch = _load_or_reserve(
                    paths,
                    task_id=args.task,
                    permit_sha256=permit_sha256,
                    now=_now(),
                )
                confidentiality_warnings = _confidentiality_preflight(
                    paths, launch["intent"]
                )
            _exact_prompt(prompt, launch["intent"])
            result, receipt, process_start_evidence = _run_controller(
                paths,
                launch,
                prompt=prompt,
                timeout_seconds=args.timeout_seconds,
                interrupt_after_start=args.interrupt_after_start,
                executable=args.executable,
            )
    except (
        h.HarnessError,
        store.SemanticStoreError,
        runtime.CodexTransportRuntimeError,
        mutation.CodexTransportMutationError,
        confidentiality.ConfidentialityError,
        CodexTransportCLIError,
        contracts.CodexTransportContractError,
        projection.CodexTransportProjectionError,
        CodexTransportControllerError,
        AppServerError,
        OSError,
        ValueError,
    ) as exc:
        if isinstance(exc, CodexTransportCLIError):
            raise
        raise CodexTransportCLIError(str(exc)) from exc
    return {
        "task_id": args.task,
        "launch_id": launch["launch_id"],
        "permit_sha256": permit_sha256,
        "terminal_state": receipt["terminal_state"],
        "terminal_receipt_sha256": receipt["receipt_sha256"],
        "evidence_level": receipt["evidence_level"],
        "runtime_completed": receipt["terminal_state"] == "completed",
        "process_start_evidence": process_start_evidence,
        "app_server_start_durably_observed": (
            process_start_evidence == "process_started_observed"
        ),
        "runtime_process_boundary_reached": process_start_evidence != "not_started",
        "confidentiality_warnings": confidentiality_warnings,
        "task_completion": "not_inferred",
    }


def _inspect(args: argparse.Namespace) -> dict[str, Any]:
    _scrub_nonissuance_process_environment()
    paths = _paths(args.root)
    try:
        with h.state_lock(paths, create_layout=False):
            events = store.load_semantic_events(paths, args.task)
            report = runtime.inspect_codex_transport_runtime(paths, args.task, events)
            if args.launch_id is None:
                return report
            launch = runtime.load_codex_transport_launch(
                paths, args.task, args.launch_id, events
            )
    except (h.HarnessError, store.SemanticStoreError, runtime.CodexTransportRuntimeError) as exc:
        raise CodexTransportCLIError(str(exc)) from exc
    terminal = launch["terminal_receipt"]
    return {
        "task_id": args.task,
        "launch_id": args.launch_id,
        "semantic_head_sha256": launch["semantic_head_sha256"],
        "intent_sha256": launch["intent"]["intent_sha256"],
        "reservation_sha256": launch["reservation"]["reservation_sha256"],
        "journal_event_sha256s": [row["event_sha256"] for row in launch["journal"]],
        "pending_journal_event_sha256": None
        if launch["pending_journal_event"] is None
        else launch["pending_journal_event"]["event_sha256"],
        "terminal_receipt_sha256": None
        if terminal is None
        else terminal["receipt_sha256"],
        "pending_terminal_receipt_sha256": None
        if launch["pending_terminal_receipt"] is None
        else launch["pending_terminal_receipt"]["receipt_sha256"],
        "verified_terminal_receipt_sha256": None
        if launch["verified_terminal_receipt"] is None
        else launch["verified_terminal_receipt"]["receipt_sha256"],
        "pending_verified_terminal_receipt_sha256": None
        if launch["pending_verified_terminal_receipt"] is None
        else launch["pending_verified_terminal_receipt"]["receipt_sha256"],
        "task_completion": "not_inferred",
    }


def _verify_mutation(args: argparse.Namespace) -> dict[str, Any]:
    _scrub_nonissuance_process_environment()
    paths = _paths(args.root)
    supplied_pre_endpoint = (
        None
        if args.pre_git_endpoint_file is None
        else _read_object(args.pre_git_endpoint_file, "pre-turn Git endpoint")
    )
    try:
        with h.state_lock(paths, create_layout=False):
            claims = h.claims_owned_by_task(paths, args.task)
            if not claims:
                raise CodexTransportCLIError(
                    "verified mutation requires AOI claim records for the task"
                )
            events = store.load_semantic_events(paths, args.task)
            launch = runtime.load_codex_transport_launch(
                paths, args.task, args.launch_id, events
            )
            if launch["intent"]["sandbox"] != "workspaceWrite":
                raise CodexTransportCLIError(
                    "verified mutation requires a workspaceWrite launch"
                )
            marker = runtime.inspect_codex_launch_issuance(
                paths,
                task_id=args.task,
                permit_sha256=launch["reservation"]["permit_sha256"],
            )
            pre_cas_sha256 = marker["pre_git_endpoint_cas_sha256"]
            if pre_cas_sha256 is None:
                raise CodexTransportCLIError(
                    "workspaceWrite issuance does not bind a pre Git endpoint CAS object"
                )
            pre_endpoint = mutation.load_preserved_git_endpoint(
                paths,
                task_id=args.task,
                cas_sha256=pre_cas_sha256,
                claims=claims,
                sealed_claim_scope=args.sealed_claim_scope,
            )
            if supplied_pre_endpoint is not None and (
                semantic.canonical_json_bytes(supplied_pre_endpoint)
                != semantic.canonical_json_bytes(pre_endpoint)
            ):
                raise CodexTransportCLIError(
                    "supplied pre-turn endpoint differs from issuance-bound CAS bytes"
                )
            existing = mutation.inspect_verified_mutation_commit(
                paths,
                task_id=args.task,
                launch_id=args.launch_id,
                event_chain=events,
                claims=claims,
                sealed_claim_scope=args.sealed_claim_scope,
            )
            if existing["status"] == "committed":
                committed = {**existing, "idempotent_replay": True}
            else:
                checked_pre = pre_endpoint
                if (
                    mutation.endpoint_pre_git_binding(checked_pre)
                    != launch["intent"]["pre_git_binding"]
                ):
                    raise CodexTransportCLIError(
                        "pre-turn Git endpoint does not match immutable launch intent"
                    )
                post_endpoint = mutation.capture_git_endpoint(
                    args.task,
                    Path(str(checked_pre["snapshot"]["worktree"])),
                    str(checked_pre["snapshot"]["baseline_head"]),
                    claims,
                )
                committed = mutation.commit_verified_mutation(
                    paths,
                    task_id=args.task,
                    launch_id=args.launch_id,
                    event_chain=events,
                    pre_endpoint=checked_pre,
                    post_endpoint=post_endpoint,
                    claims=claims,
                    sealed_claim_scope=args.sealed_claim_scope,
                )
    except (
        h.HarnessError,
        store.SemanticStoreError,
        runtime.CodexTransportRuntimeError,
        mutation.CodexTransportMutationError,
        contracts.CodexTransportContractError,
        KeyError,
        TypeError,
    ) as exc:
        if isinstance(exc, CodexTransportCLIError):
            raise
        raise CodexTransportCLIError(str(exc)) from exc
    receipt = committed["verified_terminal_receipt"]
    return {
        "task_id": args.task,
        "launch_id": args.launch_id,
        "evidence_level": receipt["evidence_level"],
        "verified_terminal_receipt_sha256": receipt["receipt_sha256"],
        "mutation_object_sha256": committed["object_sha256"],
        "binding_sha256": committed["binding_sha256"],
        "idempotent_replay": committed["idempotent_replay"],
        "task_completion": "not_inferred",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aoi-codex-bridge",
        description="Finite one-packet/one-thread/one-turn Codex App Server bridge",
    )
    parser.add_argument("--root", help="explicit AOI project root")
    subparsers = parser.add_subparsers(dest="command", required=True)

    issue = subparsers.add_parser("issue", help="Chief-issue one immutable launch")
    issue.add_argument("--task", required=True)
    issue.add_argument("--launch-id", required=True)
    issue.add_argument("--intent-file", required=True)
    issue.add_argument("--decision-file", required=True)
    issue.add_argument("--permit-file", required=True)
    issue.add_argument("--pre-git-endpoint-file")
    issue.add_argument("--command-id", required=True)
    issue.add_argument("--recorded-at", required=True)
    issue.add_argument("--chief-session-id", required=True)
    issue.add_argument("--chief-epoch", required=True, type=int)
    issue.add_argument("--chief-credential-file", required=True)
    issue.add_argument("--json", action="store_true")
    issue.set_defaults(handler=_issue)

    run = subparsers.add_parser("run", help="consume and supervise one launch")
    run.add_argument("--task", required=True)
    run.add_argument("--permit-sha256", required=True)
    run.add_argument("--prompt-file", required=True)
    run.add_argument("--executable", help="must match the sealed exact executable")
    run.add_argument("--timeout-seconds", type=float, default=300.0)
    run.add_argument("--interrupt-after-start", action="store_true")
    run.add_argument("--json", action="store_true")
    run.set_defaults(handler=_run)

    inspect = subparsers.add_parser("inspect", help="read authenticated launch state")
    inspect.add_argument("--task", required=True)
    inspect.add_argument("--launch-id")
    inspect.add_argument("--json", action="store_true")
    inspect.set_defaults(handler=_inspect)

    verify = subparsers.add_parser(
        "verify-mutation",
        help="separately elevate a completed workspaceWrite turn",
    )
    verify.add_argument("--task", required=True)
    verify.add_argument("--launch-id", required=True)
    verify.add_argument("--pre-git-endpoint-file")
    verify.add_argument("--sealed-claim-scope", action="store_true")
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(handler=_verify_mutation)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = args.handler(args)
        _print(result, as_json=args.json)
        return 0
    except CodexTransportCLIError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("ERROR: interrupted; rerun inspect/reconciliation before any launch", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["CodexTransportCLIError", "main"]
