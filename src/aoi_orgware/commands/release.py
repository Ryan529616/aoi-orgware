"""Observe and promote exact release manifests through the AOI CLI."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

from .. import harnesslib as h
from .. import release_artifacts
from .. import release_manifest
from .. import release_runtime
from .. import publication_policy
from .. import semantic_events as semantic
from .. import semantic_store as store


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
    "register_release_commands",
]
