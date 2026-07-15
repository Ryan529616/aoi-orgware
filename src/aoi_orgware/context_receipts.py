"""Context-provider receipt and benchmark-ledger integrity validators.

The CLI stays the composition root.  These validators are a thin adapter over
the :mod:`aoi_orgware.codebase_memory` and
:mod:`aoi_orgware.codebase_memory_benchmark` providers plus the shared harness
library, so every dependency is imported from a sibling package.  None of the
moved functions read a mutable CLI global, therefore no immutable policy object
is threaded through them.  This module imports only sibling packages and never
imports :mod:`aoi_orgware.cli`.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from .harnesslib import (
    HarnessError,
    HarnessPaths,
    parse_time,
    task_dir,
    validate_id,
)
from .evidence_artifacts import (
    COMMAND_ARTIFACT_MAX_BYTES,
    read_regular_artifact,
)
from .codebase_memory import (
    QUERY_EVIDENCE_CATEGORY as CODEBASE_MEMORY_QUERY_EVIDENCE_CATEGORY,
    active_receipt_records as active_context_receipt_records,
    canonical_json_sha256 as context_record_sha256,
    evaluate_live_receipt,
    receipt_chain_errors,
    steward_binding as codebase_memory_steward_binding,
    validate_receipt_record,
)
from .codebase_memory_benchmark import (
    EVIDENCE_CLASS as CODEBASE_MEMORY_BENCHMARK_EVIDENCE_CLASS,
    summarize_records as summarize_codebase_memory_benchmark_records,
    validate_record as validate_codebase_memory_benchmark_record,
)


def require_text(value: str, label: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise HarnessError(f"{label} may not be empty")
    return stripped


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


__all__ = [
    "benchmark_ledger_preimage",
    "context_benchmark_integrity_errors",
    "context_provider_brief_bindings",
    "context_receipt_integrity_errors",
    "context_receipt_reports",
    "validate_benchmark_ledger_record",
]
