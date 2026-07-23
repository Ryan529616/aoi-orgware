"""Fail-closed orchestration for the constrained ``finish-mini`` fast path.

The command deliberately reuses the existing delivery, claim-release,
checkpoint, and close handlers.  It removes mechanical CLI round trips without
creating verification or weakening the ordinary close gate.  Composition-root
policy and the existing handlers arrive through ``MiniCompletionServices``;
this module never imports :mod:`aoi_orgware.cli`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from ..git_plumbing import FULL_COMMIT_RE, state_worktree
from ..harnesslib import (
    HarnessError,
    HarnessPaths,
    baselines_for_locks,
    bump_task,
    checkpoint_matches,
    claim_path,
    load_claim_file,
    load_json,
    load_task,
    now_iso,
    parse_lock,
    parse_time,
    session_path,
    state_lock,
    task_dir,
    write_index,
    write_task,
)


class _CloseGate(Protocol):
    def __call__(
        self,
        paths: HarnessPaths,
        state: dict[str, Any],
        *,
        preparing_mini: bool = False,
    ) -> list[str]: ...


class _PrepareDelivery(Protocol):
    def __call__(
        self,
        paths: HarnessPaths,
        state: dict[str, Any],
        args: argparse.Namespace,
    ) -> dict[str, Any]: ...


class _NestedHandler(Protocol):
    def __call__(
        self,
        args: argparse.Namespace,
        paths: HarnessPaths,
        *,
        emit_result: bool = True,
    ) -> int: ...


class _DeliveryIntegrityErrors(Protocol):
    def __call__(
        self,
        paths: HarnessPaths,
        state: dict[str, Any],
        *,
        verify_remote: bool,
    ) -> list[str]: ...


@dataclass(frozen=True)
class MiniCompletionServices:
    """Composition-root policy and existing lifecycle handlers."""

    close_gate: _CloseGate
    prepare_delivery: _PrepareDelivery
    set_delivery: _NestedHandler
    release_claim: _NestedHandler
    checkpoint: _NestedHandler
    close_task: _NestedHandler
    delivery_integrity_errors: _DeliveryIntegrityErrors
    validate_mini_locks: Callable[[Iterable[str]], list[str]]


def _emit(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    for key, value in payload.items():
        print(f"{key}: {value}")


def _required_text(value: Any, label: str) -> str:
    cleaned = str(value or "").strip()
    if not cleaned:
        raise HarnessError(f"{label} may not be empty")
    return cleaned


def _request_payload(args: argparse.Namespace) -> dict[str, str | int]:
    mode = str(args.mode)
    payload: dict[str, str | int] = {
        "version": 1,
        "mode": mode,
        "detail": _required_text(args.detail, "delivery detail"),
        "summary": _required_text(args.summary, "summary"),
        "commit": str(args.commit or "").strip().lower(),
        "remote": str(args.remote or "").strip(),
        "remote_ref": str(args.remote_ref or "").strip(),
    }
    if mode == "pushed" and not FULL_COMMIT_RE.fullmatch(str(payload["commit"])):
        raise HarnessError(
            "finish-mini pushed delivery requires a full 40-64 hex --commit "
            "so an interrupted request can be resumed unambiguously"
        )
    return payload


def _request_sha256(payload: dict[str, str | int]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _finish_record(
    payload: dict[str, str | int], request_sha256: str
) -> dict[str, Any]:
    return {
        **payload,
        "request_sha256": request_sha256,
        "started_at": now_iso(),
    }


def _validate_existing_finish(
    state: dict[str, Any], request_sha256: str
) -> dict[str, Any] | None:
    record = state.get("mini_finish")
    if record is None:
        return None
    if not isinstance(record, dict) or record.get("version") != 1:
        raise HarnessError("mini finish receipt is malformed")
    stored = str(record.get("request_sha256", ""))
    if stored != request_sha256:
        raise HarnessError(
            "finish-mini was already started with different arguments; "
            "resume with the original request"
        )
    return record


def _sole_claim(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    allow_archived: bool,
) -> tuple[dict[str, Any], bool]:
    tokens = state.get("claims", [])
    if not isinstance(tokens, list) or len(tokens) != 1:
        raise HarnessError("finish-mini requires exactly one task claim")
    token = str(tokens[0])
    active = claim_path(paths, token, active=True)
    archived = claim_path(paths, token, active=False)
    present = [candidate for candidate in (active, archived) if candidate.exists()]
    if len(present) != 1:
        raise HarnessError(
            f"mini claim {token} has {len(present)} canonical records; repair it manually"
        )
    is_archived = present[0] == archived
    claim = load_claim_file(present[0])
    if claim.get("task_id") != state.get("task_id"):
        raise HarnessError("mini claim backlink does not match the task")
    if claim.get("kind") != "MINI":
        raise HarnessError("finish-mini requires the canonical MINI claim")
    if is_archived:
        if not allow_archived or claim.get("status") != "done":
            raise HarnessError("mini claim is already terminal outside this finish request")
    elif claim.get("status") != "active":
        raise HarnessError("mini claim must be active before fast completion")
    return claim, is_archived


def _claim_baseline_changes(
    paths: HarnessPaths,
    state: dict[str, Any],
    claim: dict[str, Any],
    *,
    archived: bool,
) -> tuple[dict[str, Any], dict[str, bool], list[str]]:
    locks = list(claim.get("locks", []))
    initial = claim.get("baselines")
    if not isinstance(initial, dict) or set(initial) != set(locks):
        raise HarnessError("mini claim baseline set is incomplete")
    if archived:
        final = claim.get("final_baselines")
        if not isinstance(final, dict) or set(final) != set(locks):
            raise HarnessError("archived mini claim lacks final baselines")
        current = baselines_for_locks(
            paths, locks, repo_root=state_worktree(paths, state)
        )
        if current != final:
            drifted = sorted(
                lock for lock in locks if current.get(lock) != final.get(lock)
            )
            raise HarnessError(
                "claimed files drifted after the mini claim was released: "
                + ", ".join(drifted)
            )
    else:
        final = baselines_for_locks(
            paths, locks, repo_root=state_worktree(paths, state)
        )
    changed = {lock: initial.get(lock) != final.get(lock) for lock in locks}
    paths_changed: list[str] = []
    for lock in locks:
        namespace, kind, raw_path = parse_lock(lock)
        if namespace != "repo" or kind != "file":
            raise HarnessError("finish-mini accepts only canonical repo:file locks")
        if changed[lock]:
            paths_changed.append(raw_path)
    return final, changed, paths_changed


def _delivery_matches_request(
    delivery: Any, request: dict[str, str | int]
) -> bool:
    if not isinstance(delivery, dict):
        return False
    return (
        str(delivery.get("mode", "")) == str(request["mode"])
        and str(delivery.get("detail", "")) == str(request["detail"])
        and str(delivery.get("commit", "")).lower()
        == str(request["commit"]).lower()
        and str(delivery.get("remote", "")) == str(request["remote"])
        and str(delivery.get("remote_ref", "")) == str(request["remote_ref"])
    )


def _validate_recorded_changed_files(
    state: dict[str, Any], claimed_paths: set[str], mode: str
) -> None:
    recorded = state.get("changed_files", [])
    if not isinstance(recorded, list) or any(
        not isinstance(value, str) or not value.strip() for value in recorded
    ):
        raise HarnessError("task changed-file ledger is malformed")
    outside = sorted(set(recorded) - claimed_paths)
    if outside:
        raise HarnessError(
            "mini task records changed files outside its exact claim: "
            + ", ".join(outside)
        )
    if mode == "none" and recorded:
        raise HarnessError("delivery mode none conflicts with recorded changed files")


def _nested_args(**values: Any) -> argparse.Namespace:
    return argparse.Namespace(**values, json=False)


def _finalize_terminal_mini(
    paths: HarnessPaths,
    state: dict[str, Any],
    request: dict[str, str | int],
    *,
    services: MiniCompletionServices,
) -> None:
    """Verify and finish the cross-file tail of a completed mini transaction."""

    failures: list[str] = []
    if state.get("status") != "done":
        failures.append("mini task is not done")
    if state.get("outcome") != "achieved" or state.get("phase") != "closing":
        failures.append("mini task terminal outcome or phase is invalid")
    if parse_time(str(state.get("closed_at", ""))) is None:
        failures.append("mini task closure timestamp is missing or invalid")
    if not FULL_COMMIT_RE.fullmatch(str(state.get("closed_head_sha", ""))):
        failures.append("mini task closed HEAD is missing or invalid")
    checkpoint_ok, checkpoint_reason = checkpoint_matches(paths, state)
    if not checkpoint_ok:
        failures.append(f"checkpoint is stale: {checkpoint_reason}")

    def normalized_delivery_field(value: Any, field: str) -> str:
        text = str(value)
        return text.lower() if field == "commit" else text

    delivery = state.get("delivery", {})
    if not isinstance(delivery, dict) or any(
        normalized_delivery_field(delivery.get(field, ""), field)
        != normalized_delivery_field(request[field], field)
        for field in ("mode", "detail", "commit", "remote", "remote_ref")
    ):
        failures.append("terminal delivery differs from the finish-mini receipt")
    else:
        failures.extend(
            services.delivery_integrity_errors(
                paths, state, verify_remote=False
            )
        )

    cleanup = []
    session_ids = [
        *state.get("session_ids", []),
        *state.get("subagent_parent_session_ids", []),
    ]
    for session_id in dict.fromkeys(session_ids):
        destination = session_path(paths, session_id)
        if not destination.exists():
            continue
        mapping = load_json(destination)
        if mapping.get("task_id") != state.get("task_id"):
            # Historical terminal backlinks remain while a client session may
            # be legitimately rebound to a later task.
            continue
        cleanup.append(destination)

    if failures:
        raise HarnessError(
            "finish-mini terminal finalization failed:\n- " + "\n- ".join(failures)
        )
    for destination in cleanup:
        destination.unlink()
    remaining = [str(path) for path in cleanup if path.exists()]
    if remaining:
        raise HarnessError(
            "finish-mini could not remove terminal session mappings: "
            + ", ".join(remaining)
        )
    write_index(paths)


def cmd_finish_mini(
    args: argparse.Namespace,
    paths: HarnessPaths,
    *,
    services: MiniCompletionServices,
) -> int:
    """Complete a verified mini task through its existing lifecycle gates."""

    request = _request_payload(args)
    request_sha256 = _request_sha256(request)
    with state_lock(paths):
        state = load_task(paths, args.task)
        if state.get("profile") != "mini":
            raise HarnessError("finish-mini requires a mini task")
        existing_finish = _validate_existing_finish(state, request_sha256)

        if state.get("status") == "done":
            if existing_finish is None:
                raise HarnessError("task was closed outside finish-mini")
            claim, archived = _sole_claim(paths, state, allow_archived=True)
            if not archived:
                raise HarnessError("finished mini task still has an active claim")
            locks = services.validate_mini_locks(claim.get("locks", []))
            if locks != list(claim.get("locks", [])):
                raise HarnessError("mini claim lock order or canonical spelling drifted")
            if not _delivery_matches_request(state.get("delivery"), request):
                raise HarnessError(
                    "finished mini task delivery differs from its finish receipt"
                )
            _finalize_terminal_mini(paths, state, request, services=services)
            checkpoint = task_dir(paths, str(state["task_id"])) / "checkpoint.md"
            payload = {
                "task_id": state["task_id"],
                "status": "done",
                "idempotent": True,
                "request_sha256": request_sha256,
                "checkpoint": str(checkpoint),
            }
            _emit(payload, args.json)
            return 0
        if state.get("status") not in {"active", "blocked"}:
            raise HarnessError(
                f"cannot finish mini task in status {state.get('status')}"
            )
        if state.get("packets") or state.get("jobs"):
            raise HarnessError("finish-mini requires a mini task with no packets or jobs")

        claim, archived = _sole_claim(
            paths, state, allow_archived=existing_finish is not None
        )
        locks = services.validate_mini_locks(claim.get("locks", []))
        if locks != list(claim.get("locks", [])):
            raise HarnessError("mini claim lock order or canonical spelling drifted")
        _final_baselines, changed, changed_paths = _claim_baseline_changes(
            paths, state, claim, archived=archived
        )
        claimed_paths = {parse_lock(lock)[2] for lock in locks}
        _validate_recorded_changed_files(state, claimed_paths, str(request["mode"]))

        has_changes = any(changed.values())
        if request["mode"] == "none" and has_changes:
            raise HarnessError(
                "delivery mode none rejects changed claimed files; "
                "every claimed file must retain its baseline"
            )
        if request["mode"] in {"local-only", "pushed"} and not has_changes:
            raise HarnessError(
                f"delivery mode {request['mode']} requires a changed claimed file"
            )

        delivery_args = _nested_args(
            task=args.task,
            mode=request["mode"],
            detail=request["detail"],
            commit=request["commit"] or None,
            remote=request["remote"] or None,
            remote_ref=request["remote_ref"] or None,
            confidentiality_preflight_file=getattr(
                args, "confidentiality_preflight_file", None
            ),
        )
        services.prepare_delivery(paths, state, delivery_args)
        current_delivery = state.get("delivery", {})
        if not isinstance(current_delivery, dict):
            raise HarnessError("task delivery record is malformed")
        if current_delivery.get("mode") != "pending" and not _delivery_matches_request(
            current_delivery, request
        ):
            raise HarnessError("recorded delivery differs from the finish-mini request")
        if current_delivery.get("mode") != "pending":
            delivery_errors = services.delivery_integrity_errors(
                paths, state, verify_remote=True
            )
            if delivery_errors:
                raise HarnessError(
                    "recorded delivery is not close-ready:\n- "
                    + "\n- ".join(delivery_errors)
                )

        failures = services.close_gate(paths, state, preparing_mini=True)
        if failures:
            raise HarnessError(
                "finish-mini preflight failed:\n- " + "\n- ".join(failures)
            )

        if existing_finish is None:
            state["mini_finish"] = _finish_record(request, request_sha256)
            bump_task(state)
            write_task(paths, state)
            write_index(paths)

        if current_delivery.get("mode") == "pending":
            services.set_delivery(
                delivery_args, paths, emit_result=False
            )

        if not archived:
            services.release_claim(
                _nested_args(
                    token=claim["token"],
                    status="done",
                    reason=f"Mini task completed through finish-mini: {request['summary']}",
                ),
                paths,
                emit_result=False,
            )

        services.checkpoint(
            _nested_args(
                task=args.task,
                fact=[],
                decision=[],
                rejected=[],
                changed_file=changed_paths,
                blocker=[],
                risk=[],
                next_action="Close the verified mini task through finish-mini.",
            ),
            paths,
            emit_result=False,
        )
        services.close_task(
            _nested_args(
                task=args.task,
                summary=request["summary"],
                next_action=None,
                # finish-mini closes only a fully verified mini, so the outcome
                # is achieved by construction. A mini that recorded blockers
                # still fails closed here and needs a manual honest close.
                outcome="achieved",
                boundary_disposition=None,
                blockers_disposition=None,
            ),
            paths,
            emit_result=False,
        )

        terminal_state = load_task(paths, args.task)
        terminal_claim, terminal_archived = _sole_claim(
            paths, terminal_state, allow_archived=True
        )
        if not terminal_archived or terminal_claim.get("token") != claim.get("token"):
            raise HarnessError("finish-mini terminal claim finalization is incomplete")
        _finalize_terminal_mini(
            paths, terminal_state, request, services=services
        )

        checkpoint = task_dir(paths, str(state["task_id"])) / "checkpoint.md"
        payload = {
            "task_id": state["task_id"],
            "status": "done",
            "idempotent": False,
            "request_sha256": request_sha256,
            "claim": claim["token"],
            "changed_files": changed_paths,
            "delivery": request["mode"],
            "checkpoint": str(checkpoint),
        }
    _emit(payload, args.json)
    return 0


__all__ = ["MiniCompletionServices", "cmd_finish_mini"]
