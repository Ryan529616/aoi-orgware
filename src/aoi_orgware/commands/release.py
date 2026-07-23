"""Observe and promote exact release manifests through the AOI CLI."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

from .. import confidentiality
from .. import evidence_artifacts
from .. import git_plumbing
from .. import harnesslib as h
from .. import release_artifacts
from .. import release_ci_receipt
from .. import release_manifest
from .. import release_runtime
from .. import release_tag_receipt
from .. import publication_policy
from .. import semantic_events as semantic
from .. import semantic_store as store
from ..state_lookup import require_open_task


def _read_canonical_json(path_value: str, *, label: str, maximum: int) -> Any:
    if not isinstance(path_value, str) or not path_value:
        raise h.HarnessError(f"{label} is required")
    requested = Path(path_value)
    path = requested if requested.is_absolute() else Path.cwd() / requested
    try:
        canonical = h.canonicalize_no_link_traversal(path, label)
        if canonical != path:
            raise h.HarnessError(f"{label} path is non-canonical")
        h.validate_existing_regular_file(path, label)
        before = path.lstat()
        if (
            h._path_is_link_like(path)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise h.HarnessError(f"{label} must be one regular non-linked file")
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            chunks: list[bytes] = []
            total = 0
            while total <= maximum:
                chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            finished = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = path.lstat()
    except FileNotFoundError as exc:
        raise h.HarnessError(f"{label} is missing") from exc
    except OSError as exc:
        raise h.HarnessError(f"cannot read {label}: {exc}") from exc
    raw = b"".join(chunks)
    if len(raw) > maximum:
        raise h.HarnessError(f"{label} exceeds its byte bound")
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        identity
        != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        or identity
        != (finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns)
        or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or opened.st_nlink != 1
        or finished.st_nlink != 1
        or after.st_nlink != 1
        or len(raw) != finished.st_size
        or h.canonicalize_no_link_traversal(path, label) != path
    ):
        raise h.HarnessError(f"{label} changed while being read")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise h.HarnessError(f"{label} has duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
        canonical_bytes = semantic.canonical_json_bytes(value, max_bytes=maximum)
    except h.HarnessError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, semantic.SemanticEventError) as exc:
        raise h.HarnessError(f"{label} is invalid: {exc}") from exc
    if raw != canonical_bytes:
        raise h.HarnessError(f"{label} must contain exact canonical JSON bytes")
    return value


def _canonical_stdout(value: Any, *, maximum: int) -> None:
    raw = semantic.canonical_json_bytes(value, max_bytes=maximum)
    stream = getattr(sys.stdout, "buffer", None)
    if stream is None:
        sys.stdout.write(raw.decode("utf-8"))
        sys.stdout.flush()
    else:
        stream.write(raw)
        stream.flush()


def _emit(payload: Mapping[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    for key, value in payload.items():
        print(f"{key}: {value}")


def cmd_release_manifest_observe(
    args: argparse.Namespace, _paths: h.HarnessPaths
) -> int:
    request = _read_canonical_json(
        args.request_file,
        label="release observation request",
        maximum=release_artifacts.MAX_OBSERVATION_REQUEST_BYTES,
    )
    try:
        result = release_artifacts.observe_release_artifacts(request)
    except release_artifacts.ReleaseArtifactError as exc:
        raise h.HarnessError(str(exc)) from exc
    _canonical_stdout(
        result,
        maximum=(
            release_manifest.MAX_RELEASE_MANIFEST_BYTES
            + release_artifacts.MAX_OBSERVATION_RECEIPT_BYTES
        ),
    )
    return 0


def _chief_identity(args: argparse.Namespace) -> dict[str, Any]:
    authority = getattr(args, "_aoi_chief_authority", None)
    if not isinstance(authority, Mapping):
        raise h.HarnessError("release promotion requires validated Chief authority")
    try:
        session_id = h.validate_id(authority["session_id"], "Chief session id")
        epoch = authority["epoch"]
    except (KeyError, TypeError, h.HarnessError) as exc:
        raise h.HarnessError("release promotion Chief authority is invalid") from exc
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
        raise h.HarnessError("release promotion Chief epoch is invalid")
    return {"session_id": session_id, "epoch": epoch}


def _require_current_publication_policy(
    paths: h.HarnessPaths, root: Path
) -> None:
    snapshot_path = root / "release" / "publication-policy.json"
    if not snapshot_path.is_file():
        return
    try:
        snapshot = publication_policy.load_publication_policy_snapshot(snapshot_path)
        publication_policy.require_current_publication_policy_snapshot(
            root,
            paths.project.confidentiality,
            paths.project.sha256,
            snapshot,
        )
    except publication_policy.PublicationPolicyError as exc:
        raise h.HarnessError(str(exc)) from exc


def _reload_locked_paths(paths: h.HarnessPaths) -> h.HarnessPaths:
    """Reopen ``aoi.toml`` after the state lock and reject path/config drift."""

    if not paths.config.is_file():
        raise h.HarnessError(
            "aoi.toml disappeared while acquiring the project state lock"
        )
    current = h.get_paths(paths.root)
    if not paths.config.is_file():
        raise h.HarnessError(
            "aoi.toml disappeared while acquiring the project state lock"
        )
    if (
        current.project.sha256 != paths.project.sha256
        or current.harness != paths.harness
        or current.lock != paths.lock
    ):
        raise h.HarnessError("aoi.toml changed while acquiring the project state lock")
    return current


def _require_plan_ready(
    paths: h.HarnessPaths, state: dict[str, Any], action: str
) -> None:
    """Require the approved digest to match the actual task plan bytes."""

    if not state.get("plan_ready"):
        raise h.HarnessError(f"cannot {action}; approve the task plan first")
    plan = h.task_dir(paths, str(state["task_id"])) / "plan.md"
    if not plan.is_file():
        raise h.HarnessError(f"plan file is missing: {plan}")
    expected = state.get("plan_sha256")
    actual = h.sha256_file(plan)
    if expected != actual:
        raise h.HarnessError(
            f"cannot {action}; plan changed after approval "
            f"(expected {expected}, actual {actual})"
        )


def _load_release_context(
    paths: h.HarnessPaths,
    *,
    task_id: str,
    action: str,
) -> tuple[h.HarnessPaths, dict[str, Any], dict[str, str], Path]:
    """Load one exact release task/config/plan/worktree identity under lock."""

    paths = _reload_locked_paths(paths)
    state = h.load_task(paths, task_id)
    require_open_task(state, action)
    _require_plan_ready(paths, state, action)
    worktree_errors, current = git_plumbing.worktree_integrity_errors(paths, state)
    if worktree_errors or current is None:
        raise h.HarnessError(
            "task worktree identity is not current: " + "; ".join(worktree_errors)
        )
    worktree = git_plumbing.state_worktree(paths, state)
    _require_current_publication_policy(paths, worktree)
    return paths, state, current, worktree


def _revalidate_release_context(
    paths: h.HarnessPaths,
    *,
    task_id: str,
    action: str,
    expected_state: Mapping[str, Any],
    expected_git: Mapping[str, str],
    expected_worktree: Path,
) -> tuple[h.HarnessPaths, dict[str, Any], dict[str, str], Path]:
    """Fail closed if task, plan, config, worktree, branch, or HEAD drifted."""

    refreshed = _load_release_context(
        paths,
        task_id=task_id,
        action=action,
    )
    current_paths, current_state, current_git, current_worktree = refreshed
    if (
        current_state != expected_state
        or current_git != expected_git
        or current_worktree != expected_worktree
    ):
        raise h.HarnessError(
            "release-tag task, plan, or Git context changed during verification"
        )
    return current_paths, current_state, current_git, current_worktree


def _verification_artifact_bytes(
    paths: h.HarnessPaths,
    state: dict[str, Any],
    *,
    verification_index: int,
    artifact_sha256: str,
    label: str,
    maximum: int,
) -> tuple[dict[str, Any], str, bytes]:
    if (
        isinstance(verification_index, bool)
        or not isinstance(verification_index, int)
        or verification_index < 1
    ):
        raise h.HarnessError(f"{label} verification index must be a positive integer")
    if re.fullmatch(r"[0-9a-f]{64}", artifact_sha256) is None:
        raise h.HarnessError(f"{label} artifact SHA-256 must be full lowercase hex")
    records = state.get("verification")
    if not isinstance(records, list) or verification_index > len(records):
        raise h.HarnessError(f"{label} verification index is not present")
    record = records[verification_index - 1]
    if (
        not isinstance(record, dict)
        or record.get("category") != "delivery_check"
        or record.get("status") != "pass"
        or record.get("superseded_at")
    ):
        raise h.HarnessError(
            f"{label} must name one current passing delivery_check verification"
        )
    artifact_refs = record.get("artifact_refs")
    if not isinstance(artifact_refs, list):
        raise h.HarnessError(f"{label} verification artifact set is invalid")
    matches = [
        item
        for item in artifact_refs
        if isinstance(item, dict) and item.get("sha256") == artifact_sha256
    ]
    if len(matches) != 1:
        raise h.HarnessError(
            f"{label} verification must bind the artifact SHA-256 exactly once"
        )
    artifact = matches[0]
    # Release evidence is a publication authority, not a compatibility reader:
    # it must be the immutable blob preserved in this task's CAS.  The generic
    # artifact validator still accepts legacy live references for historical
    # task records, so reject those before invoking that compatibility path.
    if type(artifact.get("snapshot_version")) is not int or artifact.get(
        "snapshot_version"
    ) != 1:
        raise h.HarnessError(f"{label} canonical task-CAS snapshot required")
    integrity_error = evidence_artifacts.artifact_ref_integrity_error(
        paths, state, artifact, require_origin=False
    )
    if integrity_error:
        raise h.HarnessError(f"{label} verification artifact is invalid: {integrity_error}")
    try:
        _path, raw = evidence_artifacts.read_regular_artifact(
            Path(str(artifact["path"])), label, max_bytes=maximum
        )
    except h.HarnessError:
        raise
    if (
        len(raw) != artifact.get("size_bytes")
        or hashlib.sha256(raw).hexdigest() != artifact_sha256
    ):
        raise h.HarnessError(f"{label} verification artifact identity changed")
    return record, evidence_artifacts.canonical_record_sha256(record), raw


def _load_exact_ci_verification(
    paths: h.HarnessPaths,
    state: dict[str, Any],
    *,
    verification_index: int,
    artifact_sha256: str,
    expected_commit: str,
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    record, record_sha256, raw = _verification_artifact_bytes(
        paths,
        state,
        verification_index=verification_index,
        artifact_sha256=artifact_sha256,
        label="exact release-CI receipt",
        maximum=release_ci_receipt.MAX_EXACT_CI_RECEIPT_BYTES,
    )
    try:
        receipt = release_ci_receipt.parse_exact_ci_receipt_bytes(raw)
        release_ci_receipt.validate_exact_ci_receipt(
            receipt, expected_commit=expected_commit
        )
    except release_ci_receipt.ReleaseCIReceiptError as exc:
        raise h.HarnessError(str(exc)) from exc
    return record, record_sha256, receipt


def _load_recorded_preflight_recheck(
    paths: h.HarnessPaths,
    state: dict[str, Any],
    *,
    verification_index: int | None,
    artifact_sha256: str | None,
) -> tuple[int, str, bytes] | None:
    """Load the exact prior preflight only for an explicit mutation-adjacent recheck."""

    if (verification_index is None) != (artifact_sha256 is None):
        raise h.HarnessError(
            "recorded preflight verification index and artifact SHA-256 must be supplied together"
        )
    if verification_index is None:
        return None
    assert artifact_sha256 is not None
    _record, _record_sha256, raw = _verification_artifact_bytes(
        paths,
        state,
        verification_index=verification_index,
        artifact_sha256=artifact_sha256,
        label="recorded release-tag preflight receipt",
        maximum=release_tag_receipt.MAX_RELEASE_TAG_RECEIPT_BYTES,
    )
    return verification_index, artifact_sha256, raw


def _require_release_tag_no_git_url_rewrites(worktree: Path) -> None:
    """Keep the exact release-tag transport outside Git URL rewrite semantics."""

    try:
        rewrite_keys = confidentiality.git_url_rewrite_keys(worktree)
    except confidentiality.ConfidentialityError as exc:
        raise h.HarnessError(str(exc)) from exc
    if rewrite_keys:
        raise h.HarnessError(
            "release-tag exact push transport is unavailable while "
            "Git URL rewrites exist"
        )


def cmd_release_tag_push_preflight(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    """Bind task-CAS exact-CI evidence to one unused annotated tag push."""

    action = "preflight a release tag for"
    with h.state_lock(paths):
        paths, state, current, worktree = _load_release_context(
            paths,
            task_id=args.task,
            action=action,
        )
        _require_release_tag_no_git_url_rewrites(worktree)
        recorded_preflight = _load_recorded_preflight_recheck(
            paths,
            state,
            verification_index=getattr(
                args, "recorded_preflight_verification_index", None
            ),
            artifact_sha256=getattr(
                args, "recorded_preflight_artifact_sha256", None
            ),
        )
        _record, record_sha256, exact_ci = _load_exact_ci_verification(
            paths,
            state,
            verification_index=args.verification_index,
            artifact_sha256=args.artifact_sha256,
            expected_commit=current["head_sha"],
        )
        tag = str(args.tag)
        tag_ref = f"refs/tags/{tag}"
        local_tag = git_plumbing.local_annotated_tag_snapshot(worktree, tag_ref)
        if local_tag["peeled_commit_oid"] != exact_ci["commit"]:
            raise h.HarnessError(
                "release tag does not peel to the exact-CI receipt commit"
            )
        try:
            _require_release_tag_no_git_url_rewrites(worktree)
            push_transport_before, destination_before = (
                confidentiality.effective_git_push_transport(
                    worktree, args.remote
                )
            )
            supplied_destination = (
                confidentiality.canonical_publication_destination(
                    args.destination, worktree
                )
            )
            if destination_before != supplied_destination:
                raise h.HarnessError(
                    "release-tag destination differs from the effective push endpoint"
                )
            git_receipt = confidentiality.preflight_git_push(
                root=worktree,
                policy=paths.project.confidentiality,
                config_sha256=paths.project.sha256,
                remote=args.remote,
                destination=args.destination,
                updates=(
                    (
                        tag_ref,
                        local_tag["tag_object_oid"],
                        tag_ref,
                        "0" * len(local_tag["tag_object_oid"]),
                    ),
                ),
                forbid_url_rewrites=True,
                required_push_transport=push_transport_before,
            )
            if git_receipt.get("rewrite_keys") != []:
                raise h.HarnessError(
                    "release-tag exact push transport is unavailable while "
                    "Git URL rewrites exist"
                )
            paths, refreshed_state, refreshed_git, refreshed_worktree = (
                _revalidate_release_context(
                    paths,
                    task_id=args.task,
                    action=action,
                    expected_state=state,
                    expected_git=current,
                    expected_worktree=worktree,
                )
            )
            _require_release_tag_no_git_url_rewrites(refreshed_worktree)
            refreshed_tag = git_plumbing.local_annotated_tag_snapshot(
                refreshed_worktree, tag_ref
            )
            push_transport_after, destination_after = (
                confidentiality.effective_git_push_transport(
                    refreshed_worktree, args.remote
                )
            )
            _require_release_tag_no_git_url_rewrites(refreshed_worktree)
            _record_after, record_sha256_after, exact_ci_after = (
                _load_exact_ci_verification(
                    paths,
                    refreshed_state,
                    verification_index=args.verification_index,
                    artifact_sha256=args.artifact_sha256,
                    expected_commit=refreshed_git["head_sha"],
                )
            )
            recorded_preflight_after = _load_recorded_preflight_recheck(
                paths,
                refreshed_state,
                verification_index=getattr(
                    args, "recorded_preflight_verification_index", None
                ),
                artifact_sha256=getattr(
                    args, "recorded_preflight_artifact_sha256", None
                ),
            )
            if (
                refreshed_tag != local_tag
                or push_transport_after != push_transport_before
                or destination_after != destination_before
                or destination_after != git_receipt["destination"]
                or record_sha256_after != record_sha256
                or exact_ci_after != exact_ci
                or recorded_preflight_after != recorded_preflight
            ):
                raise h.HarnessError(
                    "release-tag source, destination, or exact-CI evidence "
                    "changed during preflight"
                )
            git_digest = confidentiality.validate_git_push_preflight_receipt(
                git_receipt,
                root=refreshed_worktree,
                policy=paths.project.confidentiality,
                config_sha256=paths.project.sha256,
                remote=args.remote,
                destination=destination_after,
                commit=refreshed_tag["peeled_commit_oid"],
                remote_ref=tag_ref,
            )
            if git_digest != git_receipt["receipt_sha256"]:
                raise h.HarnessError(
                    "release-tag confidentiality preflight digest drifted"
                )
            receipt = release_tag_receipt.build_release_tag_preflight(
                task_id=str(refreshed_state["task_id"]),
                task_plan_sha256=str(refreshed_state["plan_sha256"]),
                verification_index=args.verification_index,
                verification_record_sha256=record_sha256_after,
                verification_artifact_sha256=args.artifact_sha256,
                exact_ci_receipt=exact_ci_after,
                tag=tag,
                tag_object_oid=refreshed_tag["tag_object_oid"],
                remote=args.remote,
                push_transport=push_transport_after,
                destination=destination_after,
                confidentiality_preflight=git_receipt,
            )
            if recorded_preflight_after is not None:
                (
                    _recorded_index,
                    recorded_artifact_sha256,
                    recorded_raw,
                ) = recorded_preflight_after
                rebuilt_raw = release_tag_receipt.canonical_release_tag_receipt_bytes(
                    receipt
                )
                if (
                    hashlib.sha256(rebuilt_raw).hexdigest()
                    != recorded_artifact_sha256
                    or recorded_raw != rebuilt_raw
                ):
                    raise h.HarnessError(
                        "recorded release-tag preflight does not exactly match the current recheck"
                    )
            _require_release_tag_no_git_url_rewrites(refreshed_worktree)
        except (
            confidentiality.ConfidentialityError,
            release_tag_receipt.ReleaseTagReceiptError,
        ) as exc:
            raise h.HarnessError(str(exc)) from exc
    _canonical_stdout(
        receipt, maximum=release_tag_receipt.MAX_RELEASE_TAG_RECEIPT_BYTES
    )
    return 0


def cmd_release_tag_push_verify(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    """Revalidate a CAS-recorded preflight and read back the pushed remote tag."""

    action = "verify release-tag delivery for"
    with h.state_lock(paths):
        paths, state, current, worktree = _load_release_context(
            paths,
            task_id=args.task,
            action=action,
        )
        _require_release_tag_no_git_url_rewrites(worktree)
        _preflight_record, preflight_record_sha, preflight_raw = (
            _verification_artifact_bytes(
                paths,
                state,
                verification_index=args.preflight_verification_index,
                artifact_sha256=args.preflight_artifact_sha256,
                label="release-tag preflight receipt",
                maximum=release_tag_receipt.MAX_RELEASE_TAG_RECEIPT_BYTES,
            )
        )
        try:
            preflight = release_tag_receipt.parse_release_tag_receipt_bytes(
                preflight_raw
            )
        except release_tag_receipt.ReleaseTagReceiptError as exc:
            raise h.HarnessError(str(exc)) from exc
        binding = preflight.get("release_ci_verification")
        if not isinstance(binding, Mapping):
            raise h.HarnessError(
                "release-tag preflight exact-CI verification binding is invalid"
            )
        binding_index = binding.get("verification_index")
        binding_artifact_sha256 = binding.get("artifact_sha256")
        if (
            isinstance(binding_index, bool)
            or not isinstance(binding_index, int)
            or binding_index < 1
            or not isinstance(binding_artifact_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", binding_artifact_sha256) is None
        ):
            raise h.HarnessError(
                "release-tag preflight exact-CI verification binding is invalid"
            )
        _ci_record, ci_record_sha, exact_ci = _load_exact_ci_verification(
            paths,
            state,
            verification_index=binding_index,
            artifact_sha256=binding_artifact_sha256,
            expected_commit=current["head_sha"],
        )
        try:
            validated = release_tag_receipt.validate_release_tag_preflight(
                preflight,
                exact_ci_receipt=exact_ci,
                expected_task_id=str(state["task_id"]),
                expected_plan_sha256=str(state["plan_sha256"]),
            )
            if (
                binding.get("verification_record_sha256") != ci_record_sha
                or validated["tag"] != args.tag
                or validated["peeled_commit_oid"] != args.expected_commit
                or validated["remote"] != args.remote
                or validated["destination"]
                != confidentiality.canonical_publication_destination(
                    args.destination, worktree
                )
            ):
                raise h.HarnessError(
                    "release-tag preflight differs from the expected delivery identity"
                )
            if validated["confidentiality_preflight"].get("rewrite_keys") != []:
                raise h.HarnessError(
                    "release-tag exact push transport is unavailable while "
                    "Git URL rewrites exist"
                )
            git_digest = confidentiality.validate_git_push_preflight_receipt(
                validated["confidentiality_preflight"],
                root=worktree,
                policy=paths.project.confidentiality,
                config_sha256=paths.project.sha256,
                remote=validated["remote"],
                destination=validated["destination"],
                commit=validated["peeled_commit_oid"],
                remote_ref=validated["tag_ref"],
            )
            if git_digest != validated["confidentiality_preflight_sha256"]:
                raise h.HarnessError(
                    "release-tag confidentiality preflight digest drifted"
                )
            local_tag_before = git_plumbing.local_annotated_tag_snapshot(
                worktree, validated["tag_ref"]
            )
            if (
                local_tag_before["tag_object_oid"] != validated["tag_object_oid"]
                or local_tag_before["peeled_commit_oid"]
                != validated["peeled_commit_oid"]
            ):
                raise h.HarnessError(
                    "release-tag local annotated tag differs from its preflight"
                )
            _require_release_tag_no_git_url_rewrites(worktree)
            push_transport_before, destination_before = (
                confidentiality.effective_git_push_transport(
                    worktree, validated["remote"]
                )
            )
            _require_release_tag_no_git_url_rewrites(worktree)
            if push_transport_before != validated["push_transport"]:
                raise h.HarnessError(
                    "release-tag preflight push transport differs from the current push endpoint"
                )
            remote_tag = git_plumbing.remote_annotated_tag_snapshot(
                worktree,
                push_transport_before,
                validated["tag_ref"],
                before_network=lambda: _require_release_tag_no_git_url_rewrites(
                    worktree
                ),
            )
            paths, refreshed_state, refreshed_git, refreshed_worktree = (
                _revalidate_release_context(
                    paths,
                    task_id=args.task,
                    action=action,
                    expected_state=state,
                    expected_git=current,
                    expected_worktree=worktree,
                )
            )
            _require_release_tag_no_git_url_rewrites(refreshed_worktree)
            (
                _preflight_record_after,
                preflight_record_sha_after,
                preflight_raw_after,
            ) = _verification_artifact_bytes(
                paths,
                refreshed_state,
                verification_index=args.preflight_verification_index,
                artifact_sha256=args.preflight_artifact_sha256,
                label="release-tag preflight receipt",
                maximum=release_tag_receipt.MAX_RELEASE_TAG_RECEIPT_BYTES,
            )
            _ci_record_after, ci_record_sha_after, exact_ci_after = (
                _load_exact_ci_verification(
                    paths,
                    refreshed_state,
                    verification_index=binding_index,
                    artifact_sha256=binding_artifact_sha256,
                    expected_commit=refreshed_git["head_sha"],
                )
            )
            local_tag_after = git_plumbing.local_annotated_tag_snapshot(
                refreshed_worktree, validated["tag_ref"]
            )
            push_transport_after, destination_after = (
                confidentiality.effective_git_push_transport(
                    refreshed_worktree, validated["remote"]
                )
            )
            _require_release_tag_no_git_url_rewrites(refreshed_worktree)
            if (
                preflight_record_sha_after != preflight_record_sha
                or preflight_raw_after != preflight_raw
                or ci_record_sha_after != ci_record_sha
                or exact_ci_after != exact_ci
                or local_tag_after != local_tag_before
                or push_transport_before != push_transport_after
                or push_transport_after != validated["push_transport"]
                or destination_before != destination_after
                or destination_before != validated["destination"]
            ):
                raise h.HarnessError(
                    "release-tag task, source, evidence, or destination changed "
                    "during remote readback"
                )
            git_digest_after = (
                confidentiality.validate_git_push_preflight_receipt(
                    validated["confidentiality_preflight"],
                    root=refreshed_worktree,
                    policy=paths.project.confidentiality,
                    config_sha256=paths.project.sha256,
                    remote=validated["remote"],
                    destination=validated["destination"],
                    commit=validated["peeled_commit_oid"],
                    remote_ref=validated["tag_ref"],
                )
            )
            if git_digest_after != git_digest:
                raise h.HarnessError(
                    "release-tag confidentiality preflight changed during readback"
                )
            _require_release_tag_no_git_url_rewrites(refreshed_worktree)
            receipt = release_tag_receipt.build_release_tag_delivery(
                preflight=validated,
                exact_ci_receipt=exact_ci_after,
                preflight_verification_index=args.preflight_verification_index,
                preflight_verification_record_sha256=preflight_record_sha_after,
                preflight_artifact_sha256=args.preflight_artifact_sha256,
                remote_tag_object_oid=remote_tag["tag_object_oid"],
                remote_peeled_commit_oid=remote_tag["peeled_commit_oid"],
                observed_destination=destination_after,
            )
        except (
            confidentiality.ConfidentialityError,
            release_tag_receipt.ReleaseTagReceiptError,
        ) as exc:
            raise h.HarnessError(str(exc)) from exc
    _canonical_stdout(
        receipt, maximum=release_tag_receipt.MAX_RELEASE_TAG_RECEIPT_BYTES
    )
    return 0


def cmd_release_promote(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    # This command records an already observed exact release in local semantic
    # state. It does not upload artifacts or publish a release. The external
    # Git/package boundary applies the destination-aware subject gate before
    # bytes leave the project.
    snapshot_path = paths.root / "release" / "publication-policy.json"
    if snapshot_path.is_file():
        try:
            snapshot = publication_policy.load_publication_policy_snapshot(
                snapshot_path
            )
            publication_policy.require_current_publication_policy_snapshot(
                paths.root,
                paths.project.confidentiality,
                paths.project.sha256,
                snapshot,
            )
        except publication_policy.PublicationPolicyError as exc:
            raise h.HarnessError(str(exc)) from exc
    task_id = h.validate_id(args.task, "task id")
    observation_result = _read_canonical_json(
        args.observation_result_file,
        label="sealed release observation result",
        maximum=(
            release_manifest.MAX_RELEASE_MANIFEST_BYTES
            + release_artifacts.MAX_OBSERVATION_RECEIPT_BYTES
        ),
    )
    if (
        not isinstance(observation_result, Mapping)
        or set(observation_result) != {"manifest", "observation_receipt"}
    ):
        raise h.HarnessError("release observation result schema is invalid")
    manifest = observation_result["manifest"]
    observation_receipt = observation_result["observation_receipt"]
    receipt = _read_canonical_json(
        args.promotion_receipt_file,
        label="sealed promotion receipt",
        maximum=release_manifest.MAX_PROMOTION_RECEIPT_BYTES,
    )
    try:
        current_head = store.semantic_head(paths, task_id)["event_sha256"]
    except store.SemanticStoreError as exc:
        raise h.HarnessError(str(exc)) from exc
    expected_head = str(args.expected_semantic_head_sha256)
    if current_head != expected_head:
        try:
            recovered = release_runtime.recover_committed_promotion_bundle(
                paths,
                task_id,
                manifest,
                observation_receipt,
                receipt,
                command_id=args.command_id,
                recorded_at=args.recorded_at,
                expected_head_sha256=expected_head,
            )
        except release_runtime.ReleaseRuntimeError as exc:
            raise h.HarnessError(
                "release promotion expected semantic head is not current and "
                f"no exact committed bundle can be recovered: {exc}"
            ) from exc
        _canonical_stdout(
            recovered, maximum=release_runtime.MAX_PROMOTION_BUNDLE_BYTES
        )
        return 0
    try:
        transaction = release_runtime.prepare_release_promotion_transaction(
            paths,
            task_id,
            manifest,
            observation_receipt,
            receipt,
            args.command_id,
            args.recorded_at,
            authority_ref=_chief_identity(args),
        )
        if transaction["expected_head_sha256"] != expected_head:
            raise h.HarnessError(
                "release promotion transaction was prepared from another head"
            )
        result = release_runtime.commit_release_promotion_transaction(
            paths, transaction
        )
        bundle = release_runtime.create_promotion_bundle(transaction)
    except (
        release_manifest.ReleaseManifestError,
        release_artifacts.ReleaseArtifactError,
        release_runtime.ReleaseRuntimeError,
        store.SemanticStoreError,
    ) as exc:
        raise h.HarnessError(str(exc)) from exc
    if result["event"]["event_sha256"] != bundle["semantic_event"]["event_sha256"]:
        raise h.HarnessError("committed release event differs from promotion bundle")
    _canonical_stdout(bundle, maximum=release_runtime.MAX_PROMOTION_BUNDLE_BYTES)
    return 0


def cmd_release_show(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    try:
        report = release_runtime.inspect_release_runtime(
            paths, h.validate_id(args.task, "task id")
        )
    except release_runtime.ReleaseRuntimeError as exc:
        raise h.HarnessError(str(exc)) from exc
    _emit(report, args.json)
    return 0


def cmd_release_abandon_pending(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    """Terminally classify one binding-only release crash after Chief takeover."""

    try:
        receipt = release_runtime.abandon_pending_release_promotion(
            paths,
            h.validate_id(args.task, "task id"),
            binding_sha256=args.binding_sha256,
            expected_head_sha256=args.expected_semantic_head_sha256,
            command_id=args.command_id,
            recorded_at=args.recorded_at,
            reason=args.reason,
            authority_ref=_chief_identity(args),
        )
    except (
        h.HarnessError,
        release_runtime.ReleaseRuntimeError,
        store.SemanticStoreError,
    ) as exc:
        raise h.HarnessError(str(exc)) from exc
    _canonical_stdout(
        receipt, maximum=release_runtime.MAX_RELEASE_ABANDONMENT_RECEIPT_BYTES
    )
    return 0


def register_release_commands(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
    *,
    handlers: dict[str, Callable[..., int]],
    add_json_argument: Callable[[argparse.ArgumentParser], None],
) -> None:
    observe = sub.add_parser(
        "release-manifest-observe",
        help="observe exact existing release bytes and emit a sealed manifest receipt",
    )
    observe.add_argument("--request-file", required=True)
    observe.set_defaults(handler=handlers["release_manifest_observe"])

    tag_preflight = sub.add_parser(
        "release-tag-push-preflight",
        help=(
            "bind one task-CAS exact-CI receipt to an unused annotated release "
            "tag and destination-aware Git preflight"
        ),
    )
    tag_preflight.add_argument("--task", required=True)
    tag_preflight.add_argument("--verification-index", required=True, type=int)
    tag_preflight.add_argument("--artifact-sha256", required=True)
    tag_preflight.add_argument("--tag", required=True)
    tag_preflight.add_argument("--remote", required=True)
    tag_preflight.add_argument("--destination", required=True)
    tag_preflight.add_argument("--recorded-preflight-verification-index", type=int)
    tag_preflight.add_argument("--recorded-preflight-artifact-sha256")
    tag_preflight.set_defaults(handler=handlers["release_tag_push_preflight"])

    tag_verify = sub.add_parser(
        "release-tag-push-verify",
        help=(
            "revalidate a CAS-recorded release-tag preflight and exact remote "
            "annotated-tag readback"
        ),
    )
    tag_verify.add_argument("--task", required=True)
    tag_verify.add_argument("--preflight-verification-index", required=True, type=int)
    tag_verify.add_argument("--preflight-artifact-sha256", required=True)
    tag_verify.add_argument("--tag", required=True)
    tag_verify.add_argument("--expected-commit", required=True)
    tag_verify.add_argument("--remote", required=True)
    tag_verify.add_argument("--destination", required=True)
    tag_verify.set_defaults(handler=handlers["release_tag_push_verify"])

    promote = sub.add_parser(
        "release-promote",
        help="Chief-promote one exact sealed release manifest into semantic history",
    )
    promote.add_argument("--task", required=True)
    promote.add_argument("--observation-result-file", required=True)
    promote.add_argument("--promotion-receipt-file", required=True)
    promote.add_argument("--command-id", required=True)
    promote.add_argument("--recorded-at", required=True)
    promote.add_argument("--expected-semantic-head-sha256", required=True)
    promote.set_defaults(handler=handlers["release_promote"])

    abandon = sub.add_parser(
        "release-abandon-pending",
        help=(
            "Chief-takeover disposition for one binding-only release crash; "
            "never completes the retired Chief event"
        ),
    )
    abandon.add_argument("--task", required=True)
    abandon.add_argument("--binding-sha256", required=True)
    abandon.add_argument("--expected-semantic-head-sha256", required=True)
    abandon.add_argument("--command-id", required=True)
    abandon.add_argument("--recorded-at", required=True)
    abandon.add_argument("--reason", required=True)
    abandon.set_defaults(handler=handlers["release_abandon_pending"])

    show = sub.add_parser(
        "release-show", help="inspect authenticated release promotion ownership"
    )
    show.add_argument("--task", required=True)
    add_json_argument(show)
    show.set_defaults(handler=handlers["release_show"])


__all__ = [
    "cmd_release_abandon_pending",
    "cmd_release_manifest_observe",
    "cmd_release_promote",
    "cmd_release_show",
    "cmd_release_tag_push_preflight",
    "cmd_release_tag_push_verify",
    "register_release_commands",
]
