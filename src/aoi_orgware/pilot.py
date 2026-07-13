"""Closed-alpha pilot kit generation and privacy-bounded result summaries."""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import importlib.resources
import io
import json
import math
import os
import re
import statistics
import tempfile
from pathlib import Path
from typing import Any, Iterable

from . import __version__


PILOT_SCHEMA_VERSION = 1
PROTOCOL_VERSION = "closed-alpha-v1"
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
TASK_KINDS = {"bugfix", "feature", "refactor", "documentation", "analysis", "other"}
RUN_STATUSES = {"completed", "failed", "timeout", "abandoned"}
ORACLE_STATUSES = {"pass", "fail", "not_run"}
VARIANTS = {"single", "aoi"}
TELEMETRY_SOURCES = {
    "provider_export",
    "runtime_ui",
    "manual_transcription",
    "unavailable",
}
MISSING_REASON_CODES = {
    "runtime_not_exposed",
    "provider_not_exposed",
    "not_collected",
    "not_applicable",
    "other_unavailable",
}
METRIC_FIELDS = (
    "wall_seconds",
    "human_minutes",
    "interventions",
    "retry_count",
    "rework_count",
    "regressions",
    "baseline_mismatches",
    "contract_mismatches",
    "verification_omissions",
    "unresolved_directives",
)
INTEGER_METRICS = set(METRIC_FIELDS) - {"wall_seconds", "human_minutes"}
TELEMETRY_FIELDS = (
    "input_tokens",
    "output_tokens",
    "high_capability_tokens",
    "provider_cost_usd",
)
QUESTIONNAIRE_FIELDS = (
    "workflow_clarity",
    "completion_confidence",
    "cognitive_load",
    "would_use_again",
)
PAIR_CONTROL_FIELDS = (
    "runtime_label",
    "model_label",
    "tool_profile",
    "package_sha256",
    "control_profile_sha256",
    "time_limit_minutes",
)
PILOT_RESOURCE_PATHS = (
    "AGENTS.md",
    "PRIVACY.md",
    "PROTOCOL.md",
    "README.md",
    "RUN_BRIEF.template.md",
    "assignment.csv",
    "feedback-private.template.md",
    "run-record.template.json",
    "withdrawal-private.template.csv",
    "sample_project/README.md",
    "sample_project/TASK.md",
    "sample_project/slugify.py",
    "sample_project/test_slugify.py",
)
TOP_LEVEL_FIELDS = {
    "schema_version",
    "protocol_version",
    "run_id",
    "participant_id",
    "task_pair_id",
    "task_id",
    "task_order",
    "task_kind",
    "variant",
    "run_status",
    "started_at",
    "ended_at",
    "oracle",
    "environment",
    "metrics",
    "telemetry",
    "questionnaire",
    "consent",
}
PRIVATE_TEXT = re.compile(
    r"(?i)(?:"
    r"[A-Za-z]:[\\/]"
    r"|/(?:home|Users|mnt)/"
    r"|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|(?:ghp|github_pat|sk)-[A-Za-z0-9_-]{12,}"
    r"|(?:api[_-]?key|access[_-]?token|secret)\s*[:=]"
    r")"
)


class PilotError(ValueError):
    """Expected, user-facing pilot data or filesystem error."""


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PilotError(f"{label} must be an object")
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing:
        raise PilotError(f"{label} is missing: {', '.join(missing)}")
    if unknown:
        raise PilotError(f"{label} has unknown fields: {', '.join(unknown)}")
    return value


def _safe_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SAFE_ID.fullmatch(value):
        raise PilotError(f"{label} must be a 1-64 character opaque identifier")
    return value


def _timestamp(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str):
        raise PilotError(f"{label} must be an RFC 3339 timestamp")
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(raw)
    except ValueError as exc:
        raise PilotError(f"{label} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise PilotError(f"{label} must include a timezone")
    return parsed


def _nonnegative(value: Any, label: str, *, integer: bool) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PilotError(f"{label} must be a non-negative number")
    if integer and not isinstance(value, int):
        raise PilotError(f"{label} must be a non-negative integer")
    try:
        numeric = float(value)
    except (OverflowError, ValueError) as exc:
        raise PilotError(f"{label} must be a finite non-negative number") from exc
    if not math.isfinite(numeric):
        raise PilotError(f"{label} must be finite")
    if value < 0:
        raise PilotError(f"{label} must be non-negative")
    return value


def _scan_private_text(value: Any, label: str = "record") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _scan_private_text(item, f"{label}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_private_text(item, f"{label}[{index}]")
    elif isinstance(value, str) and PRIVATE_TEXT.search(value):
        raise PilotError(f"{label} appears to contain private identity, path, or credential text")


def validate_record(payload: Any) -> dict[str, Any]:
    """Validate and return one strict, share-safe pilot record."""

    record = _exact_keys(payload, TOP_LEVEL_FIELDS, "record")
    if record["schema_version"] != PILOT_SCHEMA_VERSION:
        raise PilotError(f"record requires schema_version = {PILOT_SCHEMA_VERSION}")
    if record["protocol_version"] != PROTOCOL_VERSION:
        raise PilotError(f"record requires protocol_version = {PROTOCOL_VERSION!r}")
    _safe_id(record["run_id"], "run_id")
    _safe_id(record["participant_id"], "participant_id")
    _safe_id(record["task_pair_id"], "task_pair_id")
    _safe_id(record["task_id"], "task_id")
    if record["task_order"] not in {1, 2}:
        raise PilotError("task_order must be 1 or 2")
    if record["task_kind"] not in TASK_KINDS:
        raise PilotError(f"task_kind must be one of: {', '.join(sorted(TASK_KINDS))}")
    if record["variant"] not in VARIANTS:
        raise PilotError("closed-alpha-v1 accepts only 'single' or 'aoi'")
    if record["run_status"] not in RUN_STATUSES:
        raise PilotError(f"run_status must be one of: {', '.join(sorted(RUN_STATUSES))}")
    started = _timestamp(record["started_at"], "started_at")
    ended = _timestamp(record["ended_at"], "ended_at")
    if ended < started:
        raise PilotError("ended_at may not precede started_at")

    oracle = _exact_keys(
        record["oracle"], {"pre_registered", "oracle_id", "status"}, "oracle"
    )
    if oracle["pre_registered"] is not True:
        raise PilotError("oracle.pre_registered must be true before the run")
    _safe_id(oracle["oracle_id"], "oracle.oracle_id")
    if oracle["status"] not in ORACLE_STATUSES:
        raise PilotError(f"oracle.status must be one of: {', '.join(sorted(ORACLE_STATUSES))}")
    if record["run_status"] in {"completed", "failed"} and oracle["status"] == "not_run":
        raise PilotError("completed or failed runs require a pass/fail external oracle")

    environment = _exact_keys(
        record["environment"],
        {
            "runtime_label",
            "model_label",
            "tool_profile",
            "package_sha256",
            "control_profile_sha256",
            "baseline_id",
            "time_limit_minutes",
        },
        "environment",
    )
    for key in ("runtime_label", "model_label", "tool_profile", "baseline_id"):
        _safe_id(environment[key], f"environment.{key}")
    if not isinstance(environment["package_sha256"], str) or not SHA256.fullmatch(
        environment["package_sha256"]
    ):
        raise PilotError("environment.package_sha256 must be a full SHA-256")
    if not isinstance(
        environment["control_profile_sha256"], str
    ) or not SHA256.fullmatch(environment["control_profile_sha256"]):
        raise PilotError("environment.control_profile_sha256 must be a full SHA-256")
    _nonnegative(
        environment["time_limit_minutes"],
        "environment.time_limit_minutes",
        integer=True,
    )
    if environment["time_limit_minutes"] == 0:
        raise PilotError("environment.time_limit_minutes must be positive")

    metrics = _exact_keys(record["metrics"], set(METRIC_FIELDS), "metrics")
    for key in METRIC_FIELDS:
        _nonnegative(metrics[key], f"metrics.{key}", integer=key in INTEGER_METRICS)

    telemetry = _exact_keys(record["telemetry"], set(TELEMETRY_FIELDS), "telemetry")
    for key in TELEMETRY_FIELDS:
        item = _exact_keys(
            telemetry[key], {"value", "source", "missing_reason"}, f"telemetry.{key}"
        )
        if item["source"] not in TELEMETRY_SOURCES:
            raise PilotError(
                f"telemetry.{key}.source must be one of: "
                + ", ".join(sorted(TELEMETRY_SOURCES))
            )
        value = item["value"]
        if value is None:
            if item["source"] != "unavailable":
                raise PilotError(f"telemetry.{key} null value requires source='unavailable'")
            if item["missing_reason"] not in MISSING_REASON_CODES:
                raise PilotError(
                    f"telemetry.{key}.missing_reason must be one of: "
                    + ", ".join(sorted(MISSING_REASON_CODES))
                )
        else:
            _nonnegative(value, f"telemetry.{key}.value", integer=key != "provider_cost_usd")
            if item["source"] == "unavailable":
                raise PilotError(f"telemetry.{key} measured value requires a measurement source")
            if item["missing_reason"] != "":
                raise PilotError(f"telemetry.{key} measured value requires empty missing_reason")

    questionnaire = _exact_keys(
        record["questionnaire"], set(QUESTIONNAIRE_FIELDS), "questionnaire"
    )
    for key in QUESTIONNAIRE_FIELDS:
        value = questionnaire[key]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 5:
            raise PilotError(f"questionnaire.{key} must be an integer from 1 to 5")

    consent = _exact_keys(
        record["consent"],
        {"aggregate", "share_with_coordinator"},
        "consent",
    )
    if not isinstance(consent["aggregate"], bool) or not isinstance(
        consent["share_with_coordinator"], bool
    ):
        raise PilotError(
            "consent.aggregate and consent.share_with_coordinator must be booleans"
        )

    if record["run_status"] == "completed" and oracle["status"] != "pass":
        raise PilotError("completed runs require oracle.status='pass'")
    if record["run_status"] == "failed" and oracle["status"] != "fail":
        raise PilotError("failed runs require oracle.status='fail'")

    _scan_private_text(record)
    return record


def load_record(path: Path) -> dict[str, Any]:
    lexical = path.expanduser().absolute()
    if path.is_symlink() or lexical != path.expanduser().resolve():
        raise PilotError(f"pilot record may not traverse symlinks: {path}")
    if not path.is_file():
        raise PilotError(f"pilot record is not a file: {path}")
    if path.stat().st_size > 64 * 1024:
        raise PilotError(f"pilot record exceeds 64 KiB: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PilotError(f"invalid pilot record {path}: {exc}") from exc
    return validate_record(payload)


def _resource_files() -> list[tuple[str, bytes]]:
    root = importlib.resources.files("aoi_orgware.resources").joinpath("pilot")
    result: list[tuple[str, bytes]] = []
    if not root.is_dir():
        raise PilotError("installed package is missing pilot resources")
    for relative in PILOT_RESOURCE_PATHS:
        item = root.joinpath(*relative.split("/"))
        if not item.is_file():
            raise PilotError(f"installed package is missing pilot resource: {relative}")
        result.append((relative, item.read_bytes()))
    return result


def _atomic_write(path: Path, payload: bytes, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name = ""
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            temp_name = handle.name
        os.replace(temp_name, path)
        path.chmod(mode)
        temp_name = ""
    finally:
        if temp_name:
            Path(temp_name).unlink(missing_ok=True)


def initialize_kit(output: Path, *, force: bool = False) -> dict[str, Any]:
    """Copy the packaged tester kit after an all-files no-clobber preflight."""

    output = output.expanduser()
    lexical = output.absolute()
    resolved = output.resolve()
    if output.is_symlink() or lexical != resolved:
        raise PilotError("pilot output may not traverse symlinks")
    if output.exists() and not output.is_dir():
        raise PilotError(f"pilot output is not a directory: {output}")
    resources = _resource_files()
    destinations = [(relative, output / Path(relative)) for relative, _ in resources]
    destinations.append(("MANIFEST.json", output / "MANIFEST.json"))
    collisions = sorted(relative for relative, path in destinations if path.exists())
    if collisions and not force:
        raise PilotError(
            "refusing to overwrite existing pilot files: " + ", ".join(collisions)
        )
    for relative, path in destinations:
        if path.is_symlink():
            raise PilotError(f"pilot destination may not be a symlink: {relative}")
        current = output
        for part in Path(relative).parts[:-1]:
            current = current / part
            if current.is_symlink():
                raise PilotError(
                    f"pilot destination parent may not be a symlink: {relative}"
                )
            if current.exists() and not current.is_dir():
                raise PilotError(
                    f"pilot destination parent is not a directory: {relative}"
                )

    output.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        output.chmod(0o700)

    file_entries: list[dict[str, str]] = []
    for relative, payload in resources:
        mode = (
            0o600
            if relative
            in {"feedback-private.template.md", "withdrawal-private.template.csv"}
            else 0o644
        )
        _atomic_write(output / relative, payload, mode=mode)
        file_entries.append(
            {"path": relative, "sha256": hashlib.sha256(payload).hexdigest()}
        )
    manifest = {
        "schema_version": 1,
        "aoi_version": __version__,
        "files": file_entries,
    }
    manifest_bytes = (
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    _atomic_write(output / "MANIFEST.json", manifest_bytes)
    return {
        "created": True,
        "output": str(output.resolve()),
        "file_count": len(file_entries) + 1,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }


def _stats(values: Iterable[int | float | None]) -> dict[str, int | float | None]:
    items = list(values)
    material = [float(item) for item in items if item is not None]
    count = len(material)
    total = len(items)
    return {
        "available": count,
        "missing": total - count,
        "mean": round(statistics.fmean(material), 6) if material else None,
        "median": round(statistics.median(material), 6) if material else None,
    }


def summarize_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    if not records:
        raise PilotError("pilot summary requires at least one record")
    for record in records:
        validate_record(record)
        if (
            record["consent"]["share_with_coordinator"] is not True
            or record["consent"]["aggregate"] is not True
        ):
            raise PilotError(
                f"record {record['run_id']} lacks coordinator-sharing or aggregate consent"
            )
    run_ids = [record["run_id"] for record in records]
    if len(run_ids) != len(set(run_ids)):
        raise PilotError("pilot summary contains duplicate run_id values")
    slots = [
        (record["participant_id"], record["task_pair_id"], record["variant"])
        for record in records
    ]
    if len(slots) != len(set(slots)):
        raise PilotError("pilot summary contains a duplicate participant/pair/variant slot")
    ordered = sorted(
        records,
        key=lambda item: (
            item["participant_id"],
            item["task_pair_id"],
            item["task_order"],
            item["run_id"],
        ),
    )
    summary: dict[str, Any] = {
        "schema_version": 1,
        "protocol_version": PROTOCOL_VERSION,
        "analysis_boundary": "descriptive_closed_alpha_only",
        "record_count": len(ordered),
        "participant_count": len({item["participant_id"] for item in ordered}),
        "variants": {},
        "paired": {"complete_pair_count": 0, "metrics": {}},
    }
    for variant in sorted(VARIANTS):
        subset = [item for item in ordered if item["variant"] == variant]
        variant_metrics: dict[str, Any] = {}
        for name in METRIC_FIELDS:
            variant_metrics[name] = _stats([item["metrics"][name] for item in subset])
        for name in TELEMETRY_FIELDS:
            variant_metrics[name] = _stats(
                [item["telemetry"][name]["value"] for item in subset]
            )
        for name in QUESTIONNAIRE_FIELDS:
            variant_metrics[name] = _stats(
                [item["questionnaire"][name] for item in subset]
            )
        summary["variants"][variant] = {
            "run_count": len(subset),
            "run_status": {
                status: sum(item["run_status"] == status for item in subset)
                for status in sorted(RUN_STATUSES)
            },
            "oracle_pass": sum(item["oracle"]["status"] == "pass" for item in subset),
            "oracle_fail": sum(item["oracle"]["status"] == "fail" for item in subset),
            "oracle_not_run": sum(
                item["oracle"]["status"] == "not_run" for item in subset
            ),
            "metrics": variant_metrics,
        }

    groups: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    for item in ordered:
        groups.setdefault((item["participant_id"], item["task_pair_id"]), {})[
            item["variant"]
        ] = item
    complete = [group for group in groups.values() if set(group) == VARIANTS]
    for group in complete:
        if group["single"]["task_id"] == group["aoi"]["task_id"]:
            raise PilotError("complete pairs must use two different task_id values")
        if {group["single"]["task_order"], group["aoi"]["task_order"]} != {1, 2}:
            raise PilotError("complete pairs must contain task_order 1 and 2")
        for field in PAIR_CONTROL_FIELDS:
            if (
                group["single"]["environment"][field]
                != group["aoi"]["environment"][field]
            ):
                raise PilotError(
                    f"complete pair control mismatch: environment.{field}"
                )
    summary["paired"]["complete_pair_count"] = len(complete)
    summary["paired"]["incomplete_pair_count"] = len(groups) - len(complete)
    for name in (*METRIC_FIELDS, *TELEMETRY_FIELDS, *QUESTIONNAIRE_FIELDS):
        deltas: list[float | None] = []
        for group in complete:
            if name in METRIC_FIELDS:
                single = group["single"]["metrics"][name]
                aoi = group["aoi"]["metrics"][name]
            elif name in TELEMETRY_FIELDS:
                single = group["single"]["telemetry"][name]["value"]
                aoi = group["aoi"]["telemetry"][name]["value"]
            else:
                single = group["single"]["questionnaire"][name]
                aoi = group["aoi"]["questionnaire"][name]
            deltas.append(None if single is None or aoi is None else float(aoi) - float(single))
        summary["paired"]["metrics"][name] = _stats(deltas)
    return summary


def summary_json(summary: dict[str, Any]) -> bytes:
    return (
        json.dumps(summary, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")


def summary_csv(summary: dict[str, Any]) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "scope",
            "variant",
            "metric",
            "value",
            "available",
            "missing",
            "mean",
            "median",
        ]
    )
    writer.writerow(
        ["metadata", "", "protocol_version", summary["protocol_version"], "", "", "", ""]
    )
    writer.writerow(
        ["metadata", "", "analysis_boundary", summary["analysis_boundary"], "", "", "", ""]
    )
    for variant in sorted(summary["variants"]):
        variant_summary = summary["variants"][variant]
        writer.writerow(
            [
                "denominator",
                variant,
                "run_count",
                variant_summary["run_count"],
                "",
                "",
                "",
                "",
            ]
        )
        for status in sorted(variant_summary["run_status"]):
            writer.writerow(
                [
                    "run_status",
                    variant,
                    status,
                    variant_summary["run_status"][status],
                    "",
                    "",
                    "",
                    "",
                ]
            )
        for status in ("pass", "fail", "not_run"):
            writer.writerow(
                [
                    "oracle_status",
                    variant,
                    status,
                    variant_summary[f"oracle_{status}"],
                    "",
                    "",
                    "",
                    "",
                ]
            )
        for metric in sorted(variant_summary["metrics"]):
            stats = variant_summary["metrics"][metric]
            writer.writerow(
                [
                    "variant",
                    variant,
                    metric,
                    "",
                    stats["available"],
                    stats["missing"],
                    "" if stats["mean"] is None else stats["mean"],
                    "" if stats["median"] is None else stats["median"],
                ]
            )
    for metric in ("complete_pair_count", "incomplete_pair_count"):
        writer.writerow(
            [
                "pairing",
                "",
                metric,
                summary["paired"][metric],
                "",
                "",
                "",
                "",
            ]
        )
    for metric in sorted(summary["paired"]["metrics"]):
        stats = summary["paired"]["metrics"][metric]
        writer.writerow(
            [
                "paired_aoi_minus_single",
                "",
                metric,
                "",
                stats["available"],
                stats["missing"],
                "" if stats["mean"] is None else stats["mean"],
                "" if stats["median"] is None else stats["median"],
            ]
        )
    return buffer.getvalue().encode("utf-8")


def write_summary(
    records: list[dict[str, Any]],
    output: Path,
    *,
    output_format: str,
    force: bool = False,
) -> dict[str, Any]:
    output = output.expanduser()
    lexical = output.absolute()
    if output.is_symlink() or lexical != output.resolve():
        raise PilotError("pilot summary output may not traverse symlinks")
    if output.exists() and output.is_dir():
        raise PilotError(f"pilot summary output is a directory: {output}")
    if output.exists() and not force:
        raise PilotError(f"refusing to overwrite pilot summary: {output}")
    summary = summarize_records(records)
    if output_format == "json":
        payload = summary_json(summary)
    elif output_format == "csv":
        payload = summary_csv(summary)
    else:
        raise PilotError("pilot summary format must be json or csv")
    _atomic_write(output, payload)
    return {
        "created": True,
        "output": str(output.resolve()),
        "format": output_format,
        "record_count": len(records),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
