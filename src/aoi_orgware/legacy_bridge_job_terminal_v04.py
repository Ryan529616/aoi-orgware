"""Read-only legacy-v0.4 evidence adapter for one failed external job."""
from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any, NamedTuple, NoReturn

from .company.contracts import CompanyContractError, canonical_company_json_bytes
from .company.legacy_bridge import LegacyBridgeProjectionV1
from .company.legacy_bridge_contract import legacy_bridge_scope_id
from .evidence_artifacts import COMMAND_ARTIFACT_MAX_BYTES, read_regular_artifact
from .harnesslib import HarnessError, HarnessPaths, task_dir
from .legacy_bridge_snapshot_v04 import (
    produce_legacy_bridge_snapshot_v04,
    read_legacy_bridge_task_state_v04,
)
from .packet_integrity import (
    EXACT_COMMAND_NORMALIZATION_V1,
    normalize_exact_command_bytes,
)


LEGACY_JOB_PROCESS_EXIT_V1 = "aoi.legacy-job-process-exit.v1"
PROCESS_EXIT_MAX_BYTES = 65_536
TERMINAL_ARTIFACT_MAX_BYTES = 262_144
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PROCESS_EXIT_FIELDS = frozenset({
    "schema_version", "task_id", "run_id", "command_sha256",
    "host_fingerprint_sha256", "process_fingerprint_sha256", "exit_code",
    "terminal_at", "terminal_manifest_sha256", "primary_log_sha256",
})


class LegacyBridgeJobTerminalV04Error(CompanyContractError):
    """Legacy state cannot establish one exact failed-job observation."""


class LegacyBridgeJobTerminalEvidenceV04(NamedTuple):
    snapshot_bytes: bytes
    projection: LegacyBridgeProjectionV1
    evidence: dict[str, Any]
    artifacts: tuple[tuple[str, bytes], ...]


def _fail(message: str) -> NoReturn:
    raise LegacyBridgeJobTerminalV04Error(message)


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail(f"{label} is invalid")
    return value


def _exact_int(value: Any, label: str) -> int:
    if type(value) is not int or isinstance(value, bool):
        _fail(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    try:
        return hashlib.sha256(canonical_company_json_bytes(value)).hexdigest()
    except (CompanyContractError, RecursionError, TypeError, ValueError) as exc:
        raise LegacyBridgeJobTerminalV04Error(
            f"{label} is not bounded canonical JSON",
        ) from exc


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _finite(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON number")
    return parsed


def _parse_json(
    raw: bytes,
    label: str,
    *,
    require_canonical: bool,
) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("non-finite JSON number"),
            ),
            parse_float=_finite,
        )
        canonical = canonical_company_json_bytes(value)
    except (
        UnicodeDecodeError, json.JSONDecodeError, CompanyContractError,
        RecursionError, TypeError, ValueError,
    ) as exc:
        raise LegacyBridgeJobTerminalV04Error(f"{label} is invalid") from exc
    if type(value) is not dict or (require_canonical and canonical != raw):
        _fail(f"{label} JSON spelling is invalid")
    return value


def _artifact(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    expected_sha256: str,
) -> tuple[bytes, dict[str, Any]]:
    try:
        _resolved, raw = read_regular_artifact(path, label, max_bytes=max_bytes)
    except HarnessError as exc:
        raise LegacyBridgeJobTerminalV04Error(f"{label} is unavailable") from exc
    digest = hashlib.sha256(raw).hexdigest()
    if digest != _sha(expected_sha256, f"{label} digest"):
        _fail(f"{label} digest differs")
    return raw, {"sha256": digest, "size_bytes": len(raw)}


def _entity(
    projection: LegacyBridgeProjectionV1,
    *,
    kind: str,
    source_sha256: str,
) -> Any:
    matches = [
        item for item in projection.entities
        if item.kind == kind and item.source_record_sha256 == source_sha256
    ]
    if len(matches) != 1:
        _fail(f"legacy {kind} bridge entity is missing or ambiguous")
    return matches[0]


def _fingerprints(job: dict[str, Any]) -> tuple[str, str]:
    host = _digest({
        "domain": "aoi.legacy-job.host-fingerprint.v1",
        "host": job.get("host"),
        "tool": job.get("tool"),
        "tool_path": job.get("tool_path"),
        "tool_version": job.get("tool_version"),
    }, "legacy job host fingerprint")
    process = _digest({
        "domain": "aoi.legacy-job.process-fingerprint.v1",
        "run_id": job.get("run_id"),
        "pid": job.get("pid", ""),
        "tmux": job.get("tmux", ""),
        "work_root": job.get("work_root"),
        "registered_at": job.get("registered_at"),
        "started_at": job.get("started_at"),
        "command_sha256": job.get("command_sha256"),
    }, "legacy job process fingerprint")
    return host, process


def _process_exit(
    raw: bytes,
    *,
    task_id: str,
    run_id: str,
    command_sha256: str,
    host_sha256: str,
    process_sha256: str,
    exit_code: int,
    manifest_sha256: str,
    log_sha256: str,
) -> dict[str, Any]:
    value = _parse_json(
        raw, "legacy process-exit artifact", require_canonical=True,
    )
    if set(value) != _PROCESS_EXIT_FIELDS or value != {
        "schema_version": LEGACY_JOB_PROCESS_EXIT_V1,
        "task_id": task_id,
        "run_id": run_id,
        "command_sha256": command_sha256,
        "host_fingerprint_sha256": host_sha256,
        "process_fingerprint_sha256": process_sha256,
        "exit_code": exit_code,
        "terminal_at": value.get("terminal_at"),
        "terminal_manifest_sha256": manifest_sha256,
        "primary_log_sha256": log_sha256,
    }:
        _fail("legacy process-exit artifact binding differs")
    terminal_at = value["terminal_at"]
    if type(terminal_at) is not str or len(terminal_at) > 64:
        _fail("legacy process-exit terminal time is invalid")
    return value


def produce_legacy_bridge_job_terminal_evidence_v04(
    paths: HarnessPaths,
    task_id: str,
    run_id: str,
    company_id: str,
    incarnation: int,
    generation: int,
    legacy_archive_sha256: str,
    source_version: str,
    observed_at: str,
    process_exit_artifact: Path,
    process_exit_sha256: str,
) -> LegacyBridgeJobTerminalEvidenceV04:
    """Produce one command/manifest/log/exit-bound nonzero terminal fact."""

    snapshot = produce_legacy_bridge_snapshot_v04(
        paths, task_id, company_id, incarnation, generation,
        legacy_archive_sha256, source_version, observed_at,
    )
    stable = read_legacy_bridge_task_state_v04(paths, task_id)
    if stable.state_sha256 != snapshot.projection.legacy_state_sha256:
        _fail("legacy task state changed after bridge snapshot")
    state = stable.state
    jobs = [item for item in state.get("jobs", ()) if item.get("run_id") == run_id]
    if len(jobs) != 1 or type(jobs[0]) is not dict:
        _fail("legacy terminal job is missing or ambiguous")
    job = jobs[0]
    exit_code = _exact_int(job.get("exit_code"), "legacy terminal exit code")
    if job.get("status") != "fail" or exit_code == 0:
        _fail("legacy terminal v1 requires a failed nonzero job")
    owner_id = job.get("owner_packet_id")
    packets = [
        item for item in state.get("packets", ())
        if type(item) is dict and item.get("packet_id") == owner_id
    ]
    if len(packets) != 1:
        _fail("legacy terminal owner packet is missing or ambiguous")
    packet = packets[0]
    if packet.get("packet_mode") != "exact_command":
        _fail("legacy terminal owner packet is not exact-command authority")
    root = task_dir(paths, task_id)
    command_path = root / "results" / f"job-command-{run_id}.txt"
    command_raw, command_ref = _artifact(
        command_path, "legacy job command", max_bytes=COMMAND_ARTIFACT_MAX_BYTES,
        expected_sha256=str(job.get("command_sha256", "")),
    )
    try:
        normalized_command = normalize_exact_command_bytes(command_raw)
    except HarnessError as exc:
        raise LegacyBridgeJobTerminalV04Error(
            "legacy job command is invalid",
        ) from exc
    if (
        command_raw != normalized_command
        or job.get("command_path") != str(command_path)
        or job.get("command_size_bytes") != len(command_raw)
        or job.get("command_normalization") != EXACT_COMMAND_NORMALIZATION_V1
        or packet.get("command_sha256") != command_ref["sha256"]
        or packet.get("command_size_bytes") != len(command_raw)
        or packet.get("command_normalization") != EXACT_COMMAND_NORMALIZATION_V1
    ):
        _fail("legacy job and packet command authority differs")
    packet_contract_sha = _sha(
        packet.get("packet_contract_sha256"), "owner packet contract digest",
    )
    if job.get("owner_packet_contract_sha256") != packet_contract_sha:
        _fail("legacy job owner packet contract binding differs")
    manifest_path = root / "results" / f"terminal-artifacts-{run_id}.json"
    manifest_raw, manifest_ref = _artifact(
        manifest_path, "legacy terminal manifest", max_bytes=PROCESS_EXIT_MAX_BYTES,
        expected_sha256=str(job.get("terminal_manifest_sha256", "")),
    )
    manifest = _parse_json(
        manifest_raw, "legacy terminal manifest", require_canonical=False,
    )
    artifact = manifest.get("artifact")
    if (
        manifest.get("task_id") != task_id
        or manifest.get("run_id") != run_id
        or manifest.get("status") != "fail"
        or _exact_int(manifest.get("exit_code"), "terminal manifest exit code")
        != exit_code
        or manifest.get("command_path") != str(command_path)
        or manifest.get("command_sha256") != command_ref["sha256"]
        or type(artifact) is not dict
        or artifact.get("capture_status") != "preserved"
    ):
        _fail("legacy terminal manifest binding differs")
    log_path = Path(str(artifact.get("blob_path", "")))
    log_raw, log_ref = _artifact(
        log_path, "legacy primary log", max_bytes=TERMINAL_ARTIFACT_MAX_BYTES,
        expected_sha256=str(artifact.get("sha256", "")),
    )
    if artifact.get("size_bytes") != len(log_raw):
        _fail("legacy primary log size differs")
    exit_raw, exit_ref = _artifact(
        process_exit_artifact, "legacy process-exit artifact",
        max_bytes=PROCESS_EXIT_MAX_BYTES, expected_sha256=process_exit_sha256,
    )
    host_sha, process_sha = _fingerprints(job)
    exit_doc = _process_exit(
        exit_raw, task_id=task_id, run_id=run_id,
        command_sha256=str(command_ref["sha256"]), host_sha256=host_sha,
        process_sha256=process_sha, exit_code=exit_code,
        manifest_sha256=str(manifest_ref["sha256"]),
        log_sha256=str(log_ref["sha256"]),
    )
    task_entity = _entity(
        snapshot.projection, kind="task", source_sha256=stable.state_sha256,
    )
    packet_sha = _digest(packet, "legacy owner packet record")
    packet_entity = _entity(
        snapshot.projection, kind="packet", source_sha256=packet_sha,
    )
    job_sha = _digest(job, "legacy terminal job record")
    job_entity = _entity(
        snapshot.projection, kind="job", source_sha256=job_sha,
    )
    if job_entity.parent_bridge_entity_id != packet_entity.bridge_entity_id:
        _fail("legacy terminal job bridge parent differs")
    refs = [
        {"role": "command", **command_ref, "media_type": "text/plain; charset=utf-8"},
        {
            "role": "legacy_state",
            "sha256": stable.state_sha256,
            "size_bytes": len(stable.state_bytes),
            "media_type": "application/json",
        },
        {"role": "primary_log", **log_ref, "media_type": "text/plain"},
        {"role": "process_exit", **exit_ref, "media_type": "application/json"},
        {"role": "terminal_manifest", **manifest_ref, "media_type": "application/json"},
    ]
    evidence = {
        "company_id": company_id,
        "company_incarnation": incarnation,
        "lock_domain_generation": generation,
        "bridge_scope_id": legacy_bridge_scope_id(
            snapshot.projection.key,
            legacy_archive_sha256=snapshot.projection.legacy_archive_sha256,
            task_identity_digest=snapshot.projection.task_identity_digest,
        ),
        "legacy_archive_sha256": snapshot.projection.legacy_archive_sha256,
        "legacy_state_sha256": stable.state_sha256,
        "task_identity_digest": snapshot.projection.task_identity_digest,
        "task_bridge_entity_id": task_entity.bridge_entity_id,
        "task_id": task_id,
        "task_source_record_sha256": task_entity.source_record_sha256,
        "owner_packet_bridge_entity_id": packet_entity.bridge_entity_id,
        "owner_packet_id": owner_id,
        "owner_packet_source_record_sha256": packet_sha,
        "owner_packet_contract_sha256": packet_contract_sha,
        "job_bridge_entity_id": job_entity.bridge_entity_id,
        "run_id": run_id,
        "job_source_record_sha256": job_sha,
        "canonical_command": command_raw.decode("utf-8"),
        "command_normalization": EXACT_COMMAND_NORMALIZATION_V1,
        "command_sha256": command_ref["sha256"],
        "command_size_bytes": command_ref["size_bytes"],
        "host_fingerprint_sha256": host_sha,
        "process_fingerprint_sha256": process_sha,
        "closure_kind": "process_exit_observed",
        "closure_scope": "registered_job_process",
        "exit_code": exit_code,
        "artifacts": refs,
        "terminal_at": exit_doc["terminal_at"],
        "observed_at": exit_doc["terminal_at"],
    }
    return LegacyBridgeJobTerminalEvidenceV04(
        snapshot.snapshot_bytes,
        snapshot.projection,
        evidence,
        (
            ("command", command_raw),
            ("legacy_state", stable.state_bytes),
            ("primary_log", log_raw),
            ("process_exit", exit_raw),
            ("terminal_manifest", manifest_raw),
        ),
    )


__all__ = [
    "LEGACY_JOB_PROCESS_EXIT_V1", "LegacyBridgeJobTerminalEvidenceV04",
    "LegacyBridgeJobTerminalV04Error", "PROCESS_EXIT_MAX_BYTES",
    "produce_legacy_bridge_job_terminal_evidence_v04",
]
