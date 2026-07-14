"""Strict, navigation-only A/B records for codebase-memory evaluation.

The evaluator consumes externally produced observations.  It never launches a
provider, indexes a repository, watches files, or treats navigation outcomes as
technical correctness evidence.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import statistics
from collections import Counter
from pathlib import Path
from typing import Any

from .harnesslib import HarnessError


PROTOCOL_VERSION = "codebase-memory-navigation-ab-v1"
SUMMARY_SCHEMA = "codebase-memory-navigation-ab-summary/v1"
EVIDENCE_CLASS = "engineering_inference"
ANALYSIS_BOUNDARY = "engineering_inference_navigation_only"
VARIANTS = {"rg_open", "codebase_memory_assisted"}
RUN_STATUSES = {"completed", "timeout", "failed", "aborted"}
ORACLE_STATUSES = {"matched", "wrong_path", "not_found", "unverifiable"}
MAX_RECORD_BYTES = 256 * 1024
MAX_RECORDS = 1_000
METRIC_NAMES = (
    "time_to_first_relevant_ms",
    "time_to_final_answer_ms",
    "wrong_paths_before_first_relevant",
    "first_relevant_rank",
    "checked_graph_results",
    "stale_graph_results",
    "uncheckable_graph_results",
    "fallback_episodes",
    "fallback_tool_calls",
    "input_tokens",
    "output_tokens",
    "provider_cost_usd",
)
INTEGER_METRICS = {
    "wrong_paths_before_first_relevant",
    "first_relevant_rank",
    "checked_graph_results",
    "stale_graph_results",
    "uncheckable_graph_results",
    "fallback_episodes",
    "fallback_tool_calls",
    "input_tokens",
    "output_tokens",
}
SHARED_CONTROL_FIELDS = (
    "runtime_label",
    "model_label",
    "shared_control_profile_sha256",
    "benchmark_package_sha256",
    "corpus_sha256",
    "oracle_manifest_sha256",
    "assignment_sha256",
    "provider_receipt_sha256",
    "source_set_id",
    "time_limit_seconds",
)
TOP_LEVEL_FIELDS = {
    "schema_version",
    "protocol_version",
    "analysis_boundary",
    "evidence_class",
    "run_id",
    "case_pair_id",
    "case_id",
    "case_order",
    "variant",
    "run_status",
    "started_at",
    "ended_at",
    "controls",
    "freshness",
    "navigation_oracle",
    "trace",
    "metrics",
}
CONTROL_FIELDS = {*SHARED_CONTROL_FIELDS, "variant_tool_profile_sha256"}
FRESHNESS_FIELDS = {
    "profile",
    "status",
    "checked_at",
    "validator_version",
    "check_artifact_sha256",
    "mismatch_count",
}
ORACLE_FIELDS = {"pre_registered", "oracle_id", "status"}
TRACE_FIELDS = {
    "sha256",
    "event_count",
    "graph_query_calls",
    "rg_calls",
    "open_calls",
    "mutating_provider_calls",
}
METRIC_FIELDS = {"value", "source", "missing_reason"}


def _exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unknown = sorted(set(value) - expected)
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unknown:
            details.append("unknown " + ", ".join(unknown))
        raise HarnessError(f"{label} fields are invalid: {'; '.join(details)}")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HarnessError(f"{label} must be an object")
    return value


def _text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\x00" in value
        or "\n" in value
        or "\r" in value
        or len(value) > 512
    ):
        raise HarnessError(f"{label} must be a non-empty string")
    return value


def _identifier(value: Any, label: str) -> str:
    raw = _text(value, label)
    if len(raw) > 128 or not all(character.isalnum() or character in "._-" for character in raw):
        raise HarnessError(f"{label} must be a simple identifier")
    return raw


def _sha256(value: Any, label: str) -> str:
    raw = _text(value, label).lower()
    if len(raw) != 64 or any(character not in "0123456789abcdef" for character in raw):
        raise HarnessError(f"{label} must be a full SHA-256")
    return raw


def _integer(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise HarnessError(f"{label} must be an integer")
    if value < (1 if positive else 0):
        raise HarnessError(f"{label} must be {'positive' if positive else 'non-negative'}")
    return value


def _timestamp(value: Any, label: str) -> dt.datetime:
    raw = _text(value, label)
    try:
        parsed = dt.datetime.fromisoformat(raw[:-1] + "+00:00" if raw.endswith("Z") else raw)
    except ValueError as exc:
        raise HarnessError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise HarnessError(f"{label} must include a timezone")
    return parsed


def _metric(value: Any, label: str) -> dict[str, Any]:
    metric = _object(value, label)
    _exact_fields(metric, METRIC_FIELDS, label)
    raw_value = metric["value"]
    source = _text(metric["source"], f"{label}.source")
    missing_reason = metric["missing_reason"]
    if not isinstance(missing_reason, str) or "\x00" in missing_reason:
        raise HarnessError(f"{label}.missing_reason must be a string")
    if raw_value is None:
        if source != "unavailable" or not missing_reason.strip():
            raise HarnessError(
                f"{label} unavailable values require source=unavailable and missing_reason"
            )
    else:
        if isinstance(raw_value, bool) or not isinstance(raw_value, (int, float)):
            raise HarnessError(f"{label}.value must be numeric or null")
        if not math.isfinite(float(raw_value)) or raw_value < 0:
            raise HarnessError(f"{label}.value must be finite and non-negative")
        if source == "unavailable" or missing_reason:
            raise HarnessError(
                f"{label} measured values require a real source and empty missing_reason"
            )
    return metric


def validate_record(payload: Any) -> dict[str, Any]:
    record = _object(payload, "codebase-memory benchmark record")
    _exact_fields(record, TOP_LEVEL_FIELDS, "codebase-memory benchmark record")
    if record["schema_version"] != 1 or isinstance(record["schema_version"], bool):
        raise HarnessError("benchmark schema_version must be 1")
    if record["protocol_version"] != PROTOCOL_VERSION:
        raise HarnessError(f"benchmark protocol_version must be {PROTOCOL_VERSION!r}")
    if record["analysis_boundary"] != ANALYSIS_BOUNDARY:
        raise HarnessError("benchmark analysis boundary changed")
    if record["evidence_class"] != EVIDENCE_CLASS:
        raise HarnessError("benchmark evidence_class must be engineering_inference")
    _identifier(record["run_id"], "benchmark run_id")
    _identifier(record["case_pair_id"], "benchmark case_pair_id")
    _identifier(record["case_id"], "benchmark case_id")
    _integer(record["case_order"], "benchmark case_order", positive=True)
    if record["variant"] not in VARIANTS:
        raise HarnessError("benchmark variant is invalid")
    if record["run_status"] not in RUN_STATUSES:
        raise HarnessError("benchmark run_status is invalid")
    started = _timestamp(record["started_at"], "benchmark started_at")
    ended = _timestamp(record["ended_at"], "benchmark ended_at")
    if ended < started:
        raise HarnessError("benchmark ended_at precedes started_at")

    controls = _object(record["controls"], "benchmark controls")
    _exact_fields(controls, CONTROL_FIELDS, "benchmark controls")
    _text(controls["runtime_label"], "benchmark controls.runtime_label")
    _text(controls["model_label"], "benchmark controls.model_label")
    for field in CONTROL_FIELDS - {"runtime_label", "model_label", "time_limit_seconds"}:
        _sha256(controls[field], f"benchmark controls.{field}")
    _integer(
        controls["time_limit_seconds"],
        "benchmark controls.time_limit_seconds",
        positive=True,
    )

    freshness = _object(record["freshness"], "benchmark freshness")
    _exact_fields(freshness, FRESHNESS_FIELDS, "benchmark freshness")
    if freshness["profile"] not in {"receipt-only", "codebase-memory-git-v1"}:
        raise HarnessError("benchmark freshness profile is invalid")
    if freshness["status"] not in {"fresh", "stale", "unverifiable"}:
        raise HarnessError("benchmark freshness status is invalid")
    _timestamp(freshness["checked_at"], "benchmark freshness.checked_at")
    _text(freshness["validator_version"], "benchmark freshness.validator_version")
    _sha256(
        freshness["check_artifact_sha256"],
        "benchmark freshness.check_artifact_sha256",
    )
    mismatch_count = _integer(
        freshness["mismatch_count"], "benchmark freshness.mismatch_count"
    )
    if freshness["status"] == "fresh" and mismatch_count != 0:
        raise HarnessError("benchmark freshness status/mismatch_count disagree")
    if freshness["status"] == "stale" and mismatch_count == 0:
        raise HarnessError("benchmark freshness status/mismatch_count disagree")
    if freshness["status"] == "fresh" and freshness["profile"] != "codebase-memory-git-v1":
        raise HarnessError("receipt-only benchmark freshness may not be declared fresh")

    oracle = _object(record["navigation_oracle"], "benchmark navigation_oracle")
    _exact_fields(oracle, ORACLE_FIELDS, "benchmark navigation_oracle")
    if oracle["pre_registered"] is not True:
        raise HarnessError("benchmark navigation oracle must be pre-registered")
    _identifier(oracle["oracle_id"], "benchmark navigation_oracle.oracle_id")
    if oracle["status"] not in ORACLE_STATUSES:
        raise HarnessError("benchmark navigation oracle status is invalid")

    trace = _object(record["trace"], "benchmark trace")
    _exact_fields(trace, TRACE_FIELDS, "benchmark trace")
    _sha256(trace["sha256"], "benchmark trace.sha256")
    for field in TRACE_FIELDS - {"sha256"}:
        _integer(trace[field], f"benchmark trace.{field}")
    if trace["mutating_provider_calls"] != 0:
        raise HarnessError("benchmark arms may not call index/watch or mutate the provider")
    if record["variant"] == "rg_open" and trace["graph_query_calls"] != 0:
        raise HarnessError("rg_open baseline may not query the graph")
    if (
        record["variant"] == "codebase_memory_assisted"
        and trace["graph_query_calls"] > 0
        and freshness["status"] != "fresh"
    ):
        raise HarnessError("a non-fresh graph arm must fail open without querying the graph")
    observed_tool_calls = (
        trace["graph_query_calls"] + trace["rg_calls"] + trace["open_calls"]
    )
    if trace["event_count"] < observed_tool_calls:
        raise HarnessError("benchmark trace event_count is below its recorded tool calls")

    metrics = _object(record["metrics"], "benchmark metrics")
    _exact_fields(metrics, set(METRIC_NAMES), "benchmark metrics")
    normalized_metrics = {
        name: _metric(metrics[name], f"benchmark metrics.{name}")
        for name in METRIC_NAMES
    }
    for name in INTEGER_METRICS:
        value = normalized_metrics[name]["value"]
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
            raise HarnessError(f"benchmark metrics.{name}.value must be an integer")
    first_rank = normalized_metrics["first_relevant_rank"]["value"]
    if first_rank is not None and first_rank < 1:
        raise HarnessError("benchmark first_relevant_rank must be positive")
    fallback_episodes = normalized_metrics["fallback_episodes"]["value"]
    fallback_calls = normalized_metrics["fallback_tool_calls"]["value"]
    if fallback_episodes is not None and fallback_calls is not None:
        if fallback_calls < fallback_episodes:
            raise HarnessError("benchmark fallback calls are below fallback episodes")
        if fallback_episodes == 0 and fallback_calls != 0:
            raise HarnessError("benchmark fallback calls require a fallback episode")
        if fallback_calls > trace["rg_calls"] + trace["open_calls"]:
            raise HarnessError("benchmark fallback calls exceed fallback trace calls")
    checked = normalized_metrics["checked_graph_results"]["value"]
    stale = normalized_metrics["stale_graph_results"]["value"]
    if checked is not None and stale is not None and stale > checked:
        raise HarnessError("benchmark stale graph results exceed checked results")
    if record["variant"] == "rg_open":
        for name in (
            "checked_graph_results",
            "stale_graph_results",
            "uncheckable_graph_results",
            "fallback_episodes",
            "fallback_tool_calls",
        ):
            metric = normalized_metrics[name]
            if metric["value"] is not None or metric["missing_reason"] != "not_applicable":
                raise HarnessError(f"rg_open {name} must be unavailable/not_applicable")
    else:
        graph_metric_names = (
            "checked_graph_results",
            "stale_graph_results",
            "uncheckable_graph_results",
            "fallback_episodes",
            "fallback_tool_calls",
        )
        if any(normalized_metrics[name]["value"] is None for name in graph_metric_names):
            raise HarnessError("graph-assisted benchmark lacks trace-derived metrics")
        if trace["graph_query_calls"] == 0:
            if any(
                normalized_metrics[name]["value"] != 0
                for name in (
                    "checked_graph_results",
                    "stale_graph_results",
                    "uncheckable_graph_results",
                )
            ):
                raise HarnessError("graph result metrics require an observed graph query")
            if record["run_status"] == "completed" and (
                fallback_episodes == 0
                or fallback_calls == 0
                or trace["rg_calls"] + trace["open_calls"] == 0
            ):
                raise HarnessError(
                    "a completed graph arm without a graph query must record fail-open fallback"
                )

    first_relevant = normalized_metrics["time_to_first_relevant_ms"]["value"]
    final_answer = normalized_metrics["time_to_final_answer_ms"]["value"]
    wrong_paths = normalized_metrics["wrong_paths_before_first_relevant"]["value"]
    if (
        first_relevant is not None
        and final_answer is not None
        and final_answer < first_relevant
    ):
        raise HarnessError("benchmark final-answer latency precedes first-relevant latency")
    if first_rank is not None and wrong_paths is not None and first_rank != wrong_paths + 1:
        raise HarnessError("benchmark first-relevant rank disagrees with wrong-path count")
    if oracle["status"] == "matched" and (
        first_relevant is None
        or first_rank is None
        or wrong_paths is None
        or trace["open_calls"] == 0
    ):
        raise HarnessError(
            "a matched benchmark requires first-relevant metrics and an open call"
        )
    if record["run_status"] == "completed" and normalized_metrics[
        "time_to_final_answer_ms"
    ]["value"] is None:
        raise HarnessError("completed benchmark run lacks final-answer latency")
    if record["run_status"] == "completed" and (
        trace["graph_query_calls"] + trace["rg_calls"] == 0
    ):
        raise HarnessError("completed benchmark run lacks a navigation call")
    return record


def load_record(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise HarnessError(f"benchmark record is unreadable: {path}: {exc}") from exc
    if not data or len(data) > MAX_RECORD_BYTES or b"\x00" in data:
        raise HarnessError(
            f"benchmark record must be non-empty UTF-8 JSON under {MAX_RECORD_BYTES} bytes"
        )
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HarnessError(f"benchmark record is not valid UTF-8 JSON: {exc}") from exc
    return validate_record(payload), data


def _metric_values(records: list[dict[str, Any]], name: str) -> tuple[list[float], Counter[str]]:
    values: list[float] = []
    missing: Counter[str] = Counter()
    for record in records:
        metric = record["metrics"][name]
        if metric["value"] is None:
            missing[metric["missing_reason"]] += 1
        else:
            values.append(float(metric["value"]))
    return values, missing


def _describe(records: list[dict[str, Any]], name: str) -> dict[str, Any]:
    values, missing = _metric_values(records, name)
    return {
        "available_count": len(values),
        "missing_count": sum(missing.values()),
        "missing_reasons": dict(sorted(missing.items())),
        "sum": sum(values) if values else None,
        "mean": statistics.fmean(values) if values else None,
        "median": statistics.median(values) if values else None,
        "minimum": min(values) if values else None,
        "maximum": max(values) if values else None,
    }


def _variant_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = Counter(record["run_status"] for record in records)
    oracle = Counter(record["navigation_oracle"]["status"] for record in records)
    completed = statuses["completed"]
    completed_wrong = sum(
        record["run_status"] == "completed"
        and record["navigation_oracle"]["status"] == "wrong_path"
        for record in records
    )
    return {
        "run_count": len(records),
        "run_status_counts": dict(sorted(statuses.items())),
        "oracle_status_counts": dict(sorted(oracle.items())),
        "operational_navigation_match_rate": (
            oracle["matched"] / len(records) if records else None
        ),
        "noncompletion_rate": (
            (len(records) - completed) / len(records) if records else None
        ),
        "completed_wrong_path_rate": (
            completed_wrong / completed if completed else None
        ),
        "metrics": {name: _describe(records, name) for name in METRIC_NAMES},
    }


def summarize_records(
    records: list[dict[str, Any]],
    *,
    generated_at: str,
) -> dict[str, Any]:
    if not records or len(records) > MAX_RECORDS:
        raise HarnessError(f"benchmark summary requires 1-{MAX_RECORDS} records")
    for record in records:
        validate_record(record)
    run_ids = [record["run_id"] for record in records]
    if len(run_ids) != len(set(run_ids)):
        raise HarnessError("benchmark run ids are duplicated")
    by_pair: dict[str, dict[str, dict[str, Any]]] = {}
    for record in records:
        pair = by_pair.setdefault(record["case_pair_id"], {})
        if record["variant"] in pair:
            raise HarnessError(
                f"benchmark pair {record['case_pair_id']} duplicates {record['variant']}"
            )
        pair[record["variant"]] = record
    for pair_id, pair in by_pair.items():
        if set(pair) != VARIANTS:
            raise HarnessError(f"benchmark pair {pair_id} lacks both A/B variants")
        baseline = pair["rg_open"]
        graph = pair["codebase_memory_assisted"]
        if baseline["case_id"] != graph["case_id"] or baseline["case_order"] != graph[
            "case_order"
        ]:
            raise HarnessError(f"benchmark pair {pair_id} case identity drifted")
        for field in SHARED_CONTROL_FIELDS:
            if baseline["controls"][field] != graph["controls"][field]:
                raise HarnessError(f"benchmark pair {pair_id} control drifted: {field}")
        if baseline["navigation_oracle"]["oracle_id"] != graph[
            "navigation_oracle"
        ]["oracle_id"]:
            raise HarnessError(f"benchmark pair {pair_id} oracle drifted")

    by_variant = {
        variant: sorted(
            [record for record in records if record["variant"] == variant],
            key=lambda item: (item["case_order"], item["case_pair_id"]),
        )
        for variant in sorted(VARIANTS)
    }
    paired_metrics: dict[str, Any] = {}
    for name in METRIC_NAMES:
        deltas: list[float] = []
        missing_pairs = 0
        for pair in by_pair.values():
            baseline_value = pair["rg_open"]["metrics"][name]["value"]
            graph_value = pair["codebase_memory_assisted"]["metrics"][name]["value"]
            if baseline_value is None or graph_value is None:
                missing_pairs += 1
            else:
                deltas.append(float(graph_value) - float(baseline_value))
        paired_metrics[name] = {
            "available_pair_count": len(deltas),
            "missing_pair_count": missing_pairs,
            "graph_minus_rg_open_mean": statistics.fmean(deltas) if deltas else None,
            "graph_minus_rg_open_median": statistics.median(deltas) if deltas else None,
        }

    graph_records = by_variant["codebase_memory_assisted"]
    graph_metric_totals: dict[str, dict[str, Any]] = {}
    for name in (
        "checked_graph_results",
        "stale_graph_results",
        "uncheckable_graph_results",
    ):
        values, missing = _metric_values(graph_records, name)
        graph_metric_totals[name] = {
            "value": sum(values) if values else None,
            "available_run_count": len(values),
            "missing_run_count": sum(missing.values()),
            "missing_reasons": dict(sorted(missing.items())),
        }
    stale_rate_checked = 0.0
    rate_stale = 0.0
    stale_rate_pairs = 0
    uncheckable_rate_checked = 0.0
    rate_uncheckable = 0.0
    uncheckable_rate_pairs = 0
    for record in graph_records:
        checked = record["metrics"]["checked_graph_results"]["value"]
        stale = record["metrics"]["stale_graph_results"]["value"]
        uncheckable = record["metrics"]["uncheckable_graph_results"]["value"]
        if checked is not None and stale is not None:
            stale_rate_checked += float(checked)
            rate_stale += float(stale)
            stale_rate_pairs += 1
        if checked is not None and uncheckable is not None:
            uncheckable_rate_checked += float(checked)
            rate_uncheckable += float(uncheckable)
            uncheckable_rate_pairs += 1
    graph_query_runs = sum(
        record["trace"]["graph_query_calls"] > 0
        for record in graph_records
    )
    fresh_graph_runs = sum(
        record["freshness"]["status"] == "fresh"
        for record in graph_records
    )
    return {
        "schema": SUMMARY_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "analysis_boundary": ANALYSIS_BOUNDARY,
        "evidence_class": EVIDENCE_CLASS,
        "close_qualifying": False,
        "generated_at": generated_at,
        "record_count": len(records),
        "pair_count": len(by_pair),
        "input_record_set_sha256": hashlib.sha256(
            "\n".join(
                json.dumps(
                    record,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                for record in sorted(records, key=lambda item: item["run_id"])
            ).encode("utf-8")
        ).hexdigest(),
        "variants": {
            variant: _variant_summary(by_variant[variant])
            for variant in sorted(VARIANTS)
        },
        "paired_differences": paired_metrics,
        "graph_diagnostics": {
            "freshness_eligible_rate": (
                fresh_graph_runs / len(graph_records)
                if graph_records
                else None
            ),
            "graph_query_run_count": graph_query_runs,
            "checked_graph_result_count": graph_metric_totals[
                "checked_graph_results"
            ],
            "stale_graph_result_count": graph_metric_totals[
                "stale_graph_results"
            ],
            "uncheckable_graph_result_count": graph_metric_totals[
                "uncheckable_graph_results"
            ],
            "stale_result_rate": (
                rate_stale / stale_rate_checked
                if stale_rate_checked
                else None
            ),
            "stale_result_rate_available_run_count": stale_rate_pairs,
            "uncheckable_result_rate": (
                rate_uncheckable / (uncheckable_rate_checked + rate_uncheckable)
                if uncheckable_rate_checked + rate_uncheckable
                else None
            ),
            "uncheckable_result_rate_available_run_count": uncheckable_rate_pairs,
        },
        "interpretation_boundary": (
            "Descriptive navigation efficiency only. This summary does not establish "
            "compile, simulation, numeric, synthesis, physical, signoff, or general AOI superiority."
        ),
    }
