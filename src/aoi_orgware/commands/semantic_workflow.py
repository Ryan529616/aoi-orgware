"""CLI boundary for the closed Phase-1 semantic IC workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from typing import Any

from .. import harnesslib as h
from .. import semantic_events as semantic
from .. import semantic_store as store
from ..evidence_artifacts import read_regular_artifact
from ..ic_rag import ICRagError, parse_document_manifest_bytes
from ..semantic_workflow import (
    MAX_REQUEST_BYTES,
    SemanticWorkflowError,
    compile_workflow_transition,
    derive_workflow_view,
    parse_workflow_request_bytes,
)
from .ic_rag import cmd_ic_rag_query, register_ic_rag_commands


Handler = Callable[[argparse.Namespace, h.HarnessPaths], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset({"semantic_workflow_apply", "semantic_workflow_show"})
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _emit(payload: Mapping[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    for key, value in payload.items():
        print(f"{key}: {value}")


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise h.HarnessError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _read_bound_artifact(
    path: str, expected_sha256: str, label: str, *, maximum: int
) -> bytes:
    expected = _sha256(expected_sha256, f"{label} SHA-256")
    _source, data = read_regular_artifact(
        path,
        label,
        max_bytes=maximum,
        require_utf8=True,
    )
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise h.HarnessError(
            f"{label} SHA-256 mismatch: expected {expected}, actual {actual}"
        )
    return data


def _authority_ref(args: argparse.Namespace) -> str:
    value = str(getattr(args, "_aoi_authority_ref", "") or "")
    if not value:
        raise h.HarnessError("semantic workflow mutation requires validated Chief authority")
    return value


def _documents_for_request(
    args: argparse.Namespace, operation: str
) -> tuple[Any, ...] | None:
    manifest = getattr(args, "rag_manifest", None)
    digest = getattr(args, "rag_manifest_sha256", None)
    requires_rag = operation in {"plan_publish", "verification_record"}
    if requires_rag and (not manifest or not digest):
        raise h.HarnessError(
            f"semantic workflow operation {operation} requires --rag-manifest and "
            "--rag-manifest-sha256"
        )
    if not requires_rag and (manifest or digest):
        raise h.HarnessError(
            f"semantic workflow operation {operation} does not accept an IC RAG manifest"
        )
    if not requires_rag:
        return None
    data = _read_bound_artifact(
        str(manifest),
        str(digest),
        "IC RAG document manifest",
        maximum=MAX_REQUEST_BYTES,
    )
    try:
        return parse_document_manifest_bytes(data)
    except ICRagError as exc:
        raise h.HarnessError(f"IC RAG document manifest is invalid: {exc}") from exc


def _compile(
    state: dict[str, Any], request: dict[str, Any], args: argparse.Namespace
) -> Any:
    documents = _documents_for_request(args, request["operation"])
    try:
        return compile_workflow_transition(
            state,
            request,
            recorded_at=args.recorded_at,
            rag_documents=documents,
            expected_semantic_head_sha256=(
                args.expected_head_sha256
                if request["operation"] == "checkpoint_record"
                else None
            ),
        )
    except SemanticWorkflowError as exc:
        raise h.HarnessError(str(exc)) from exc


def cmd_semantic_workflow_apply(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    task_id = h.validate_id(args.task, "task id")
    command_id = h.validate_id(args.command_id, "semantic workflow command id")
    expected_head = _sha256(args.expected_head_sha256, "semantic expected head SHA-256")
    request_data = _read_bound_artifact(
        args.request,
        args.request_sha256,
        "semantic workflow request",
        maximum=MAX_REQUEST_BYTES,
    )
    try:
        request = parse_workflow_request_bytes(request_data)
    except SemanticWorkflowError as exc:
        raise h.HarnessError(str(exc)) from exc
    if request["task_id"] != task_id:
        raise h.HarnessError("semantic workflow request task differs from --task")
    if request["operation_id"] != command_id:
        raise h.HarnessError("semantic workflow operation_id differs from --command-id")
    checkpoint_head = request["payload"].get("expected_semantic_head_sha256")
    if request["operation"] == "checkpoint_record" and checkpoint_head != expected_head:
        raise h.HarnessError("checkpoint payload expected head differs from command authority")

    with h.state_lock(paths, create_layout=False):
        events = store.load_semantic_events(paths, task_id)
        state = store.load_semantic_task(paths, task_id)
        matches = [event for event in events if event.get("command_id") == command_id]
        if matches:
            if len(matches) != 1 or matches[0] is not events[-1] or len(events) < 2:
                raise h.HarnessError(
                    "semantic workflow command already exists but is not the terminal event"
                )
            try:
                before = semantic.replay_events(events[:-1])
            except semantic.SemanticEventError as exc:
                raise h.HarnessError(f"semantic workflow retry base is invalid: {exc}") from exc
            transition = _compile(before, request, args)
            try:
                result = store.recover_published_semantic_transition(
                    paths,
                    task_id,
                    transition.result_state,
                    event_type=transition.event_type,
                    command_id=command_id,
                    expected_head_sha256=expected_head,
                )
            except store.SemanticStoreError as exc:
                raise h.HarnessError(str(exc)) from exc
        else:
            try:
                store.preflight_semantic_append(
                    paths,
                    task_id,
                    command_id=command_id,
                    expected_head_sha256=expected_head,
                )
            except store.SemanticStoreError as exc:
                raise h.HarnessError(str(exc)) from exc
            transition = _compile(state, request, args)
            try:
                result = store.append_semantic_transition(
                    paths,
                    task_id,
                    transition.result_state,
                    event_type=transition.event_type,
                    command_id=command_id,
                    recorded_at=args.recorded_at,
                    authority_ref=_authority_ref(args),
                    expected_head_sha256=expected_head,
                )
            except store.SemanticStoreError as exc:
                raise h.HarnessError(str(exc)) from exc
        h.write_index(paths)
    _emit(
        {
            "task_id": task_id,
            "operation": transition.operation,
            "operation_id": transition.operation_id,
            "workflow_record_sha256": transition.workflow_record_sha256,
            "semantic_head_sha256": result.event["event_sha256"],
            "semantic_sequence": result.event["sequence"],
            "idempotent_replay": result.idempotent_replay,
            "workflow": transition.workflow_view,
        },
        bool(args.json),
    )
    return 0


def cmd_semantic_workflow_show(
    args: argparse.Namespace, paths: h.HarnessPaths
) -> int:
    task_id = h.validate_id(args.task, "task id")
    with h.state_lock(paths, create_layout=False):
        state = store.load_semantic_task(paths, task_id)
        head = store.semantic_head(paths, task_id)
        try:
            view = derive_workflow_view(state)
        except SemanticWorkflowError as exc:
            raise h.HarnessError(str(exc)) from exc
    _emit(
        {
            "task_id": task_id,
            "semantic_head_sha256": head["event_sha256"],
            "semantic_sequence": head["sequence"],
            "workflow": view,
        },
        bool(args.json),
    )
    return 0


def register_semantic_workflow_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "semantic workflow handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )
    apply = subparsers.add_parser(
        "semantic-workflow-apply",
        help="append one closed Phase-1 IC semantic workflow transition",
    )
    apply.add_argument("--task", required=True)
    apply.add_argument("--request", required=True)
    apply.add_argument("--request-sha256", required=True)
    apply.add_argument("--command-id", required=True)
    apply.add_argument("--expected-head-sha256", required=True)
    apply.add_argument("--recorded-at", required=True)
    apply.add_argument("--rag-manifest")
    apply.add_argument("--rag-manifest-sha256")
    add_json_argument(apply)
    apply.set_defaults(handler=handlers["semantic_workflow_apply"])

    show = subparsers.add_parser(
        "semantic-workflow-show",
        help="show the validated Phase-1 IC workflow projection",
    )
    show.add_argument("--task", required=True)
    add_json_argument(show)
    show.set_defaults(handler=handlers["semantic_workflow_show"])


def register_ic_phase1(
    subparsers: Any, *, add_json_argument: JsonArgumentRegistrar
) -> None:
    """Register the read-only RAG and closed semantic workflow public ABI."""

    register_ic_rag_commands(
        subparsers,
        handlers={"ic_rag_query": cmd_ic_rag_query},
        add_json_argument=add_json_argument,
    )
    register_semantic_workflow_commands(
        subparsers,
        handlers={
            "semantic_workflow_apply": cmd_semantic_workflow_apply,
            "semantic_workflow_show": cmd_semantic_workflow_show,
        },
        add_json_argument=add_json_argument,
    )


__all__ = [
    "cmd_semantic_workflow_apply",
    "cmd_semantic_workflow_show",
    "register_ic_phase1",
    "register_semantic_workflow_commands",
]
