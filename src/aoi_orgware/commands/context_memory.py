"""Codebase-memory context-receipt/benchmark command family: syntax
registration and command bodies.

This module owns the ``context-receipt-record``, ``codebase-memory-benchmark-
validate`` and ``codebase-memory-benchmark-record`` command implementations.
``context-receipt-record`` is grouped here (despite its command name not
starting with ``codebase-memory-``) because it is the receipt-provider entry
point for the same codebase-memory subsystem as the two
``codebase-memory-benchmark-*`` commands, and the three are a contiguous block
in the original CLI.

It stays a leaf of the composition root: it imports validators/statics from
sibling packages (``harnesslib``, ``state_lookup``, ``evidence_artifacts``,
``context_receipts``, ``codebase_memory``, ``codebase_memory_benchmark``) and
the standard library, never the monolithic :mod:`aoi_orgware.cli`.  The two
CLI-resident authority/derived-state operations the bodies need
(``require_plan_ready``, ``require_root_session``) are injected through a
frozen :class:`ContextMemoryCmdServices` built by the CLI composition root.
``emit`` and ``require_text`` are pure leaf helpers redeclared module-locally
(neither project-mutable nor test-patched), mirroring the sibling extraction
precedent.  The CLI imports the command bodies back for handler wiring.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from ..codebase_memory import (
    FRESHNESS_PROFILES as CODEBASE_MEMORY_FRESHNESS_PROFILES,
    RECEIPT_MAX_BYTES as CODEBASE_MEMORY_RECEIPT_MAX_BYTES,
    active_receipt_records as active_context_receipt_records,
    canonical_json_sha256 as context_record_sha256,
    evaluate_live_receipt,
    make_receipt_record,
    parse_receipt_bytes,
    receipt_chain_errors,
    validate_receipt_record,
)
from ..codebase_memory_benchmark import (
    EVIDENCE_CLASS as CODEBASE_MEMORY_BENCHMARK_EVIDENCE_CLASS,
    summarize_records as summarize_codebase_memory_benchmark_records,
    validate_record as validate_codebase_memory_benchmark_record,
)
from ..context_receipts import (
    benchmark_ledger_preimage,
    context_receipt_integrity_errors,
)
from ..evidence_artifacts import (
    COMMAND_ARTIFACT_MAX_BYTES,
    read_regular_artifact,
    snapshot_evidence_artifact,
)
from ..harnesslib import (
    HarnessError,
    HarnessPaths,
    atomic_write_json,
    bump_task,
    load_task,
    now_iso,
    sha256_file,
    state_lock,
    task_dir,
    validate_id,
    write_index,
    write_task,
)
from ..state_lookup import require_open_task


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset(
    {
        "context_receipt_record",
        "codebase_memory_benchmark_validate",
        "codebase_memory_benchmark_record",
    }
)


class _RequirePlanReady(Protocol):
    def __call__(
        self, paths: HarnessPaths, state: dict[str, Any], action: str
    ) -> None: ...


class _RequireRootSession(Protocol):
    def __call__(
        self, paths: HarnessPaths, state: dict[str, Any], session_id: str
    ) -> str: ...


@dataclass(frozen=True)
class ContextMemoryCmdServices:
    """CLI-resident derived-state operations injected into the moved bodies.

    ``require_plan_ready`` and ``require_root_session`` are CLI-resident helpers
    that read CLI-local constants/helpers; they are direct-bound in the factory
    (neither is fault-injected via ``mock.patch.object(cli, ...)``).
    """

    require_plan_ready: _RequirePlanReady
    require_root_session: _RequireRootSession


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


def cmd_context_receipt_record(
    args: argparse.Namespace, paths: HarnessPaths, *, services: ContextMemoryCmdServices
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
        services.require_plan_ready(paths, state, "record context receipt")
        if state.get("profile") == "mini":
            raise HarnessError("mini task may not record context-provider receipts")
        root_session_id = services.require_root_session(paths, state, args.session_id)
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
    args: argparse.Namespace, paths: HarnessPaths, *, services: ContextMemoryCmdServices
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
        services.require_plan_ready(paths, state, "record codebase-memory benchmark")
        if state.get("profile") == "mini":
            raise HarnessError("mini task may not record context-provider benchmarks")
        root_session_id = services.require_root_session(paths, state, args.session_id)
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
        for index, (record_source, expected, _data, _payload) in enumerate(prepared, start=1):
            snapshots.append(
                snapshot_evidence_artifact(
                    paths,
                    state["task_id"],
                    record_source,
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


def register_context_memory_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register the codebase-memory context-receipt/benchmark command family."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "context memory command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser(
        "context-receipt-record",
        help="record an immutable optional context-provider receipt",
    )
    parser.add_argument("--task", required=True)
    parser.add_argument("--provider", choices=["codebase-memory"], required=True)
    parser.add_argument("--receipt-id", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--receipt-sha256", required=True)
    parser.add_argument(
        "--requirement", choices=["optional", "required"], default="optional"
    )
    parser.add_argument(
        "--freshness-profile",
        choices=sorted(CODEBASE_MEMORY_FRESHNESS_PROFILES),
        default="receipt-only",
    )
    parser.add_argument("--supersedes-receipt-id")
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["context_receipt_record"])

    parser = subparsers.add_parser(
        "codebase-memory-benchmark-validate",
        help="validate one navigation-only codebase-memory A/B record",
    )
    parser.add_argument("--record", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["codebase_memory_benchmark_validate"])

    parser = subparsers.add_parser(
        "codebase-memory-benchmark-record",
        help="snapshot and summarize paired navigation-only A/B records",
    )
    parser.add_argument("--task", required=True)
    parser.add_argument("--benchmark-id", required=True)
    parser.add_argument("--receipt-id", required=True)
    parser.add_argument("--record", action="append", default=[], required=True)
    parser.add_argument("--record-sha256", action="append", default=[], required=True)
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["codebase_memory_benchmark_record"])


__all__ = [
    "ContextMemoryCmdServices",
    "cmd_codebase_memory_benchmark_record",
    "cmd_codebase_memory_benchmark_validate",
    "cmd_context_receipt_record",
    "register_context_memory_commands",
]
