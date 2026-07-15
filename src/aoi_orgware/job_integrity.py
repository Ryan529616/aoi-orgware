"""External-job source-receipt, integrity, and launch-authority fences.

The CLI remains the composition root.  It owns the project-mutable receipt
component contract (``RECEIPT_COMPONENTS`` / ``REQUIRED_RECEIPT_COMPONENTS``),
so every CLI wrapper snapshots those tuples into an immutable
:class:`JobIntegrityPolicy` and passes that policy in explicitly; this module
never observes a stale or mid-call-mutated receipt contract after the CLI
globals are reconfigured from project config.

Two operations this module needs live outside it and arrive through the frozen
:class:`JobIntegrityServices` dataclass rather than being imported from the
monolithic CLI: the owned-job authority recomputation (whose real body lives in
:mod:`aoi_orgware.execution_topology` and needs its own
:class:`~aoi_orgware.execution_topology.ExecutionTopologyServices`) and the
skill-canary work-unit binding check (still CLI-resident until the skill
lifecycle extraction).  This module imports only sibling packages and never
imports :mod:`aoi_orgware.cli`.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from .evidence_artifacts import COMMAND_ARTIFACT_MAX_BYTES, read_regular_artifact
from .execution_policy import EXECUTION_POLICY_VERSION, _execution_policy_v2_enabled
from .execution_topology import ExecutionTopologyServices, _validate_owned_job_authority
from .harnesslib import (
    ACTIVE_JOB_STATUSES,
    JOB_STATUSES,
    HarnessError,
    HarnessPaths,
    load_json,
    now_iso,
    sha256_file,
    task_dir,
)
from .state_lookup import execution_selection_by_id


@dataclass(frozen=True)
class JobIntegrityPolicy:
    """Immutable snapshot of the project source-receipt component contract."""

    receipt_components: tuple[str, ...]
    required_receipt_components: tuple[str, ...]


class ValidateSkillCanaryWorkUnitBinding(Protocol):
    def __call__(
        self,
        state: dict[str, Any],
        release_id: str,
        canary_event_id: str,
        *,
        require_live_canary: bool,
    ) -> dict[str, str] | None: ...


@dataclass(frozen=True)
class JobIntegrityServices:
    """Authority operations supplied by the composition root."""

    validate_skill_canary_work_unit_binding: ValidateSkillCanaryWorkUnitBinding
    execution_topology: ExecutionTopologyServices


def _is_exact_int(value: Any, expected: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == expected


def require_text(value: str, label: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise HarnessError(f"{label} may not be empty")
    return stripped


def require_absolute_posix(value: str, label: str) -> str:
    cleaned = require_text(value, label)
    path = PurePosixPath(cleaned)
    if not path.is_absolute() or ".." in path.parts or "\\" in cleaned:
        raise HarnessError(f"{label} must be an absolute normalized POSIX path: {value!r}")
    return path.as_posix()


def validate_source_receipt(
    source: Path,
    expected_sha: str,
    *,
    tool_path: str,
    tool_version: str,
    command: str,
    policy: JobIntegrityPolicy,
) -> tuple[dict[str, Any], bytes]:
    _, source_data = read_regular_artifact(
        source,
        "source receipt",
        max_bytes=COMMAND_ARTIFACT_MAX_BYTES,
        require_utf8=True,
    )
    actual_sha = hashlib.sha256(source_data).hexdigest()
    if actual_sha != expected_sha:
        raise HarnessError(
            f"source receipt SHA-256 mismatch: expected {expected_sha}, actual {actual_sha}"
        )
    try:
        payload = json.loads(source_data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise HarnessError(f"source receipt is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("receipt_version") != 1:
        raise HarnessError("source receipt must be an object with receipt_version=1")
    require_text(str(payload.get("source_set_id", "")), "source receipt source_set_id")
    require_text(str(payload.get("producer", "")), "source receipt producer")
    tool = payload.get("tool")
    if not isinstance(tool, dict):
        raise HarnessError("source receipt requires a tool object")
    expected_tool = {"path": tool_path, "version": tool_version, "command": command}
    if {key: tool.get(key) for key in expected_tool} != expected_tool:
        raise HarnessError("source receipt tool path/version/command differ from job arguments")
    components = payload.get("components")
    if not isinstance(components, dict):
        raise HarnessError("source receipt requires a components object")
    for component_name in policy.receipt_components:
        component = components.get(component_name)
        if not isinstance(component, dict):
            raise HarnessError(f"source receipt component {component_name!r} is missing")
        status = component.get("status")
        if status == "not_applicable":
            require_text(
                str(component.get("reason", "")),
                f"source receipt {component_name} not_applicable reason",
            )
            continue
        if status != "included":
            raise HarnessError(
                f"source receipt component {component_name!r} must be included or not_applicable"
            )
        files = component.get("files")
        if not isinstance(files, list) or not files:
            raise HarnessError(f"source receipt component {component_name!r} has no files")
        for entry in files:
            if not isinstance(entry, dict):
                raise HarnessError(f"source receipt {component_name} entry is not an object")
            entry_path = require_absolute_posix(
                str(entry.get("path", "")), f"source receipt {component_name} path"
            )
            entry_sha = str(entry.get("sha256", "")).lower()
            if not re.fullmatch(r"[0-9a-f]{64}", entry_sha):
                raise HarnessError(
                    f"source receipt {component_name} entry has invalid SHA-256: {entry_path}"
                )
    for required_included in policy.required_receipt_components:
        if components[required_included].get("status") != "included":
            raise HarnessError(f"source receipt component {required_included!r} must be included")
    return payload, source_data


def job_integrity_errors(
    paths: HarnessPaths,
    state: dict[str, Any],
    *,
    policy: JobIntegrityPolicy,
    services: JobIntegrityServices,
) -> list[str]:
    errors: list[str] = []
    try:
        policy_v2 = _execution_policy_v2_enabled(state)
    except HarnessError as exc:
        errors.append(str(exc))
        policy_v2 = False
    for job in state.get("jobs", []):
        run_id = str(job.get("run_id", ""))
        status = job.get("status")
        if status not in JOB_STATUSES:
            errors.append(f"job {run_id} has invalid status {status!r}")
            continue
        if job.get("integrity_version") != 1:
            errors.append(f"job {run_id} lacks integrity_version=1")
        owner_packet_id = str(job.get("owner_packet_id", ""))
        if owner_packet_id:
            try:
                _validate_owned_job_authority(
                    paths,
                    state,
                    job,
                    require_dispatched=status in ACTIVE_JOB_STATUSES,
                    services=services.execution_topology,
                )
            except (HarnessError, TypeError, ValueError) as exc:
                errors.append(f"job {run_id} owner packet authority is invalid: {exc}")
        if job.get("job_schema_version") == 2:
            if policy_v2 and status in ACTIVE_JOB_STATUSES and not _is_exact_int(
                job.get("task_execution_policy_version"), EXECUTION_POLICY_VERSION
            ):
                errors.append(
                    f"job {run_id} lacks its task execution policy v2 binding"
                )
            namespace = paths.project.external_lock_namespace
            expected_output_locks = [
                f"{namespace}:tree:{job.get('work_root', '')}",
                f"{namespace}:file:{job.get('log', '')}",
            ]
            if (
                job.get("external_lock_namespace") != namespace
                or job.get("required_output_locks") != expected_output_locks
            ):
                errors.append(
                    f"job {run_id} external output-lock authority is non-canonical or changed"
                )
            command_path = Path(str(job.get("command_path", "")))
            command_sha = str(job.get("command_sha256", ""))
            if not command_path.is_file():
                errors.append(f"job {run_id} command snapshot is missing")
            elif not re.fullmatch(r"[0-9a-f]{64}", command_sha):
                errors.append(f"job {run_id} command snapshot SHA-256 is invalid")
            elif (
                sha256_file(command_path) != command_sha
                or command_path.stat().st_size != job.get("command_size_bytes")
                or command_path.read_text(encoding="utf-8") != str(job.get("command", ""))
            ):
                errors.append(f"job {run_id} command snapshot identity mismatch")
        expected_receipt_path = (
            task_dir(paths, state["task_id"]) / "results" / f"source-receipt-{run_id}.json"
        )
        receipt_path = Path(str(job.get("source_receipt_path", "")))
        receipt_sha = str(job.get("source_sha", ""))
        if receipt_path != expected_receipt_path:
            errors.append(f"job {run_id} source receipt path is not canonical")
        elif not receipt_path.is_file():
            errors.append(f"job {run_id} source receipt snapshot is missing")
        elif not re.fullmatch(r"[0-9a-f]{64}", receipt_sha):
            errors.append(f"job {run_id} source receipt SHA-256 is invalid")
        elif sha256_file(receipt_path) != receipt_sha:
            errors.append(f"job {run_id} source receipt SHA-256 mismatch")
        else:
            try:
                validate_source_receipt(
                    receipt_path,
                    receipt_sha,
                    tool_path=str(job.get("tool_path", "")),
                    tool_version=str(job.get("tool_version", "")),
                    command=str(job.get("command", "")),
                    policy=policy,
                )
            except HarnessError as exc:
                errors.append(f"job {run_id} source receipt is invalid: {exc}")
        if status == "running" and not (job.get("pid") or job.get("tmux")):
            errors.append(f"job {run_id} is running without pid or tmux identity")
        if status in {"pass", "fail", "stopped"}:
            if not job.get("evidence") or job.get("exit_code") is None:
                errors.append(f"terminal job {run_id} lacks evidence/exit code")
            if status == "pass" and job.get("exit_code") != job.get("success_exit_code", 0):
                errors.append(f"passing job {run_id} does not match its success exit code")
            if job.get("job_schema_version") == 2:
                expected_manifest = (
                    task_dir(paths, state["task_id"])
                    / "results"
                    / f"terminal-artifacts-{run_id}.json"
                )
                manifest_path = Path(str(job.get("terminal_manifest_path", "")))
                manifest_sha = str(job.get("terminal_manifest_sha256", ""))
                if manifest_path != expected_manifest or not manifest_path.is_file():
                    errors.append(f"terminal job {run_id} artifact manifest is missing/non-canonical")
                elif not re.fullmatch(r"[0-9a-f]{64}", manifest_sha):
                    errors.append(f"terminal job {run_id} artifact manifest SHA-256 is invalid")
                elif sha256_file(manifest_path) != manifest_sha:
                    errors.append(f"terminal job {run_id} artifact manifest SHA-256 mismatch")
                else:
                    try:
                        manifest = load_json(manifest_path)
                        artifact = manifest.get("artifact", {})
                        if status == "pass" and job.get(
                            "launch_authority_version"
                        ) == 1:
                            launch_events = job.get("launch_authority_events", [])
                            expected_launch_sha = (
                                launch_events[-1].get("authority_sha256", "")
                                if launch_events
                                else ""
                            )
                            if (
                                not expected_launch_sha
                                or manifest.get("launch_authority_sha256")
                                != expected_launch_sha
                            ):
                                errors.append(
                                    f"passing job {run_id} terminal manifest lost launch authority"
                                )
                        blob_path = Path(str(artifact.get("blob_path", "")))
                        if artifact.get("capture_status") == "preserved":
                            if not blob_path.is_file() or blob_path.is_symlink():
                                errors.append(
                                    f"terminal job {run_id} preserved artifact blob is missing/non-regular"
                                )
                            elif (
                                sha256_file(blob_path) != artifact.get("sha256")
                                or blob_path.stat().st_size != artifact.get("size_bytes")
                            ):
                                errors.append(
                                    f"terminal job {run_id} preserved artifact blob identity mismatch"
                                )
                    except HarnessError as exc:
                        errors.append(f"terminal job {run_id} manifest is invalid: {exc}")
                if status == "pass" and job.get("terminal_artifact_status") != "preserved":
                    errors.append(f"passing job {run_id} lacks a preserved primary terminal log")
    return errors


def _job_launch_authority_record(
    job: dict[str, Any],
    selection: dict[str, Any] | None,
    skill_binding: dict[str, str] | None,
) -> dict[str, Any]:
    lane_snapshot: dict[str, Any] = {}
    if selection is not None:
        lane_snapshot = next(
            dict(item)
            for item in selection.get("lane_snapshots", [])
            if item.get("lane_id") == job.get("lane_id")
        )
    record = {
        "integrity_version": 1,
        "execution_selection_id": selection.get("selection_id", "")
        if selection
        else "",
        "lane_id": str(job.get("lane_id", "")),
        "owner_packet_id": str(job.get("owner_packet_id", "")),
        "owner_packet_contract_sha256": str(
            job.get("owner_packet_contract_sha256", "")
        ),
        "lane_snapshot": lane_snapshot,
        "skill_binding": dict(skill_binding or {}),
        "recorded_at": now_iso(),
    }
    record["authority_sha256"] = hashlib.sha256(
        json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()
    return record


def _job_launch_authority_errors(
    state: dict[str, Any],
    job: dict[str, Any],
    *,
    services: JobIntegrityServices,
) -> list[str]:
    if job.get("launch_authority_version") != 1:
        return []
    errors: list[str] = []
    events = job.get("launch_authority_events", [])
    if not isinstance(events, list):
        return [f"job {job.get('run_id')} launch authority events are malformed"]
    if job.get("status") == "pass" and not events:
        errors.append(f"passing job {job.get('run_id')} lacks launch authority")
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            errors.append(f"job {job.get('run_id')} launch event {index} is malformed")
            continue
        stored_sha = str(event.get("authority_sha256", ""))
        unhashed = dict(event)
        unhashed.pop("authority_sha256", None)
        actual_sha = hashlib.sha256(
            json.dumps(
                unhashed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        if event.get("integrity_version") != 1 or stored_sha != actual_sha:
            errors.append(f"job {job.get('run_id')} launch event {index} lost integrity")
            continue
        if (
            event.get("lane_id") != job.get("lane_id", "")
            or event.get("execution_selection_id")
            != job.get("execution_selection_id", "")
            or str(event.get("owner_packet_id", ""))
            != str(job.get("owner_packet_id", ""))
            or str(event.get("owner_packet_contract_sha256", ""))
            != str(job.get("owner_packet_contract_sha256", ""))
        ):
            errors.append(f"job {job.get('run_id')} launch event {index} changed authority")
            continue
        selection_id = str(event.get("execution_selection_id", ""))
        if selection_id:
            try:
                selection = execution_selection_by_id(state, selection_id)
                expected_snapshot = next(
                    dict(item)
                    for item in selection.get("lane_snapshots", [])
                    if item.get("lane_id") == job.get("lane_id")
                )
            except (HarnessError, StopIteration):
                errors.append(
                    f"job {job.get('run_id')} launch event {index} references missing authority"
                )
                continue
            if event.get("lane_snapshot") != expected_snapshot:
                errors.append(
                    f"job {job.get('run_id')} launch event {index} lane snapshot changed"
                )
        elif event.get("lane_snapshot"):
            errors.append(
                f"job {job.get('run_id')} launch event {index} has an unbound lane snapshot"
            )
        try:
            expected_binding = services.validate_skill_canary_work_unit_binding(
                state,
                str(job.get("skill_release_id", "")),
                str(job.get("skill_canary_event_id", "")),
                require_live_canary=False,
            )
        except HarnessError as exc:
            errors.append(f"job {job.get('run_id')} launch event {index}: {exc}")
            continue
        if event.get("skill_binding") != dict(expected_binding or {}):
            errors.append(
                f"job {job.get('run_id')} launch event {index} skill binding changed"
            )
    return errors


__all__ = [
    "JobIntegrityPolicy",
    "JobIntegrityServices",
    "ValidateSkillCanaryWorkUnitBinding",
    "_job_launch_authority_errors",
    "_job_launch_authority_record",
    "job_integrity_errors",
    "validate_source_receipt",
]
