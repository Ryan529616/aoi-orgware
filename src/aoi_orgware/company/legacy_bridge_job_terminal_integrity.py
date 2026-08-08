"""Pre-append integrity joins for legacy job terminal receipts."""
from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
import json
import math
from typing import Any, cast

from .blobs import BlobStore, BlobStoreError
from .contracts import (
    CompanyContractError,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from .legacy_bridge_contract import (
    LEGACY_BRIDGE_OBSERVATION_V1,
    validate_legacy_bridge_observation,
)
from .legacy_bridge_job_terminal import (
    LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1,
    validate_legacy_bridge_job_terminal_receipt,
    validate_legacy_bridge_job_terminal_source,
)
from .readmodel import CompanyReadModel


_SHARED_SOURCE_FIELDS = (
    "company_id", "company_incarnation", "lock_domain_generation",
    "bridge_scope_id", "source_observation_id",
    "source_observation_payload_sha256",
    "source_observation_global_sequence", "request_evidence_sha256",
    "legacy_archive_sha256",
    "legacy_state_sha256", "task_identity_digest",
    "task_bridge_entity_id", "task_id", "task_source_record_sha256",
    "owner_packet_bridge_entity_id", "owner_packet_id",
    "owner_packet_source_record_sha256", "owner_packet_contract_sha256",
    "job_bridge_entity_id", "run_id", "job_source_record_sha256",
    "command_normalization", "command_sha256", "command_size_bytes",
    "host_fingerprint_sha256", "process_fingerprint_sha256",
    "closure_kind", "closure_scope", "exit_code", "artifacts",
    "terminal_at", "observed_at",
)
_PROCESS_EXIT_FIELDS = frozenset({
    "schema_version", "task_id", "run_id", "command_sha256",
    "host_fingerprint_sha256", "process_fingerprint_sha256", "exit_code",
    "terminal_at", "terminal_manifest_sha256", "primary_log_sha256",
})
_MANIFEST_FIELDS = frozenset({
    "manifest_version", "task_id", "run_id", "status", "exit_code",
    "command_path", "command_sha256", "launch_authority_sha256", "artifact",
    "recorded_at",
})
_MANIFEST_ARTIFACT_FIELDS = frozenset({
    "role", "origin_path", "capture_source", "capture_status", "blob_path",
    "sha256", "size_bytes",
})


class LegacyBridgeJobTerminalIntegrityError(RuntimeError):
    """A terminal receipt is not joined to exact current durable evidence."""


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain_json(member) for key, member in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_json(member) for member in value]
    return value


def _fail(message: str) -> None:
    raise LegacyBridgeJobTerminalIntegrityError(message)


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


def _json_document(raw: bytes, label: str, *, canonical: bool) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("non-finite JSON number"),
            ),
            parse_float=_finite,
        )
        encoded = canonical_company_json_bytes(value)
    except (
        UnicodeDecodeError, json.JSONDecodeError, CompanyContractError,
        RecursionError, TypeError, ValueError,
    ) as exc:
        raise LegacyBridgeJobTerminalIntegrityError(
            f"legacy terminal {label} is invalid",
        ) from exc
    if type(value) is not dict or (canonical and encoded != raw):
        _fail(f"legacy terminal {label} spelling is invalid")
    return cast(dict[str, Any], value)


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_company_json_bytes(value)).hexdigest()


def _exact_record(
    records: Any,
    identity_field: str,
    identity: str,
    label: str,
) -> dict[str, Any]:
    if type(records) is not list:
        _fail(f"legacy terminal {label} inventory is invalid")
    matches = [
        item for item in records
        if type(item) is dict and item.get(identity_field) == identity
    ]
    if len(matches) != 1:
        _fail(f"legacy terminal {label} is missing or ambiguous")
    return matches[0]


def _entity_id(source: Mapping[str, Any], kind: str, legacy_id: str) -> str:
    return _digest({
        "domain": "aoi.legacy-bridge.entity.v1",
        "company": {
            "company_id": source["company_id"],
            "company_incarnation": source["company_incarnation"],
            "lock_domain_generation": source["lock_domain_generation"],
        },
        "legacy_archive_sha256": source["legacy_archive_sha256"],
        "task_id": source["task_id"],
        "kind": kind,
        "legacy_id": legacy_id,
    })


def _artifact_payloads(
    source: Mapping[str, Any],
    blobs: BlobStore,
) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    for reference in source["artifacts"]:
        role = str(reference["role"])
        raw = blobs.read(str(reference["sha256"]))
        if (
            len(raw) != reference["size_bytes"]
            or hashlib.sha256(raw).hexdigest() != reference["sha256"]
            or role in payloads
        ):
            _fail("legacy terminal artifact CAS identity differs")
        payloads[role] = raw
    return payloads


def _verify_artifact_semantics(
    source: Mapping[str, Any],
    blobs: BlobStore,
) -> None:
    payloads = _artifact_payloads(source, blobs)
    command = payloads["command"]
    state_raw = payloads["legacy_state"]
    if (
        command != str(source["canonical_command"]).encode("utf-8")
        or hashlib.sha256(state_raw).hexdigest() != source["legacy_state_sha256"]
    ):
        _fail("legacy terminal command or state artifact differs")
    state = _json_document(state_raw, "legacy state", canonical=False)
    packet = _exact_record(
        state.get("packets"), "packet_id", str(source["owner_packet_id"]),
        "owner packet",
    )
    job = _exact_record(
        state.get("jobs"), "run_id", str(source["run_id"]), "job",
    )
    host_fingerprint = _digest({
        "domain": "aoi.legacy-job.host-fingerprint.v1",
        "host": job.get("host"), "tool": job.get("tool"),
        "tool_path": job.get("tool_path"),
        "tool_version": job.get("tool_version"),
    })
    process_fingerprint = _digest({
        "domain": "aoi.legacy-job.process-fingerprint.v1",
        "run_id": job.get("run_id"), "pid": job.get("pid", ""),
        "tmux": job.get("tmux", ""), "work_root": job.get("work_root"),
        "registered_at": job.get("registered_at"),
        "started_at": job.get("started_at"),
        "command_sha256": job.get("command_sha256"),
    })
    if any((
        state.get("task_id") != source["task_id"],
        hashlib.sha256(state_raw).hexdigest()
        != source["task_source_record_sha256"],
        _digest(packet) != source["owner_packet_source_record_sha256"],
        packet.get("packet_mode") != "exact_command",
        packet.get("packet_contract_sha256")
        != source["owner_packet_contract_sha256"],
        packet.get("command_sha256") != source["command_sha256"],
        packet.get("command_size_bytes") != source["command_size_bytes"],
        packet.get("command_normalization") != source["command_normalization"],
        _digest(job) != source["job_source_record_sha256"],
        job.get("status") != "fail",
        job.get("owner_packet_id") != source["owner_packet_id"],
        job.get("owner_packet_contract_sha256")
        != source["owner_packet_contract_sha256"],
        job.get("command_sha256") != source["command_sha256"],
        job.get("command_size_bytes") != source["command_size_bytes"],
        job.get("command_normalization") != source["command_normalization"],
        job.get("exit_code") != source["exit_code"],
        host_fingerprint != source["host_fingerprint_sha256"],
        process_fingerprint != source["process_fingerprint_sha256"],
        _entity_id(source, "task", str(source["task_id"]))
        != source["task_bridge_entity_id"],
        _entity_id(source, "packet", str(source["owner_packet_id"]))
        != source["owner_packet_bridge_entity_id"],
        _entity_id(source, "job", str(source["run_id"]))
        != source["job_bridge_entity_id"],
        _digest({
            "domain": "aoi.legacy-bridge.legacy-identity.v1",
            "kind": "task", "legacy_id": source["task_id"],
        }) != source["task_identity_digest"],
    )):
        _fail("legacy terminal durable state semantics differ")
    manifest_raw = payloads["terminal_manifest"]
    manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    if (
        job.get("terminal_manifest_sha256") != manifest_sha256
        or job.get("terminal_artifact_status") != "preserved"
    ):
        _fail("legacy terminal durable manifest binding differs")
    manifest = _json_document(manifest_raw, "manifest", canonical=False)
    artifact = manifest.get("artifact")
    if (
        frozenset(manifest) != _MANIFEST_FIELDS
        or type(artifact) is not dict
        or frozenset(artifact) != _MANIFEST_ARTIFACT_FIELDS
        or type(manifest.get("manifest_version")) is not int
        or manifest.get("manifest_version") != 1
        or manifest.get("task_id") != source["task_id"]
        or manifest.get("run_id") != source["run_id"]
        or manifest.get("status") != "fail"
        or type(manifest.get("exit_code")) is not int
        or manifest.get("exit_code") != source["exit_code"]
        or manifest.get("command_path") != job.get("command_path")
        or manifest.get("command_sha256") != source["command_sha256"]
        or manifest.get("launch_authority_sha256") != ""
        or artifact.get("role") != "primary_log"
        or artifact.get("origin_path") != job.get("log")
        or type(artifact.get("capture_source")) is not str
        or not artifact.get("capture_source")
        or artifact.get("capture_status") != "preserved"
        or type(artifact.get("blob_path")) is not str
        or not artifact.get("blob_path")
        or artifact.get("sha256")
        != hashlib.sha256(payloads["primary_log"]).hexdigest()
        or artifact.get("size_bytes") != len(payloads["primary_log"])
        or type(manifest.get("recorded_at")) is not str
        or not manifest.get("recorded_at")
    ):
        _fail("legacy terminal manifest semantics differ")
    process = _json_document(payloads["process_exit"], "process exit", canonical=True)
    if (
        frozenset(process) != _PROCESS_EXIT_FIELDS
        or process.get("schema_version") != "aoi.legacy-job-process-exit.v1"
        or process.get("task_id") != source["task_id"]
        or process.get("run_id") != source["run_id"]
        or process.get("command_sha256") != source["command_sha256"]
        or process.get("host_fingerprint_sha256")
        != source["host_fingerprint_sha256"]
        or process.get("process_fingerprint_sha256")
        != source["process_fingerprint_sha256"]
        or process.get("exit_code") != source["exit_code"]
        or process.get("terminal_at") != source["terminal_at"]
        or source["observed_at"] != source["terminal_at"]
        or process.get("terminal_manifest_sha256")
        != manifest_sha256
        or process.get("primary_log_sha256")
        != hashlib.sha256(payloads["primary_log"]).hexdigest()
    ):
        _fail("legacy terminal process-exit semantics differ")


def _verify_projection_binding(
    receipt: Mapping[str, Any],
    observation: Mapping[str, Any],
) -> None:
    projection = observation["projection"]
    if (
        projection["legacy_archive_sha256"] != receipt["legacy_archive_sha256"]
        or projection["legacy_state_sha256"] != receipt["legacy_state_sha256"]
        or projection["task_identity_digest"] != receipt["task_identity_digest"]
        or projection["task_bridge_entity_id"] != receipt["task_bridge_entity_id"]
    ):
        _fail("legacy terminal source projection binding differs")
    entities = {
        str(item["bridge_entity_id"]): item for item in projection["entities"]
    }
    task = entities.get(str(receipt["task_bridge_entity_id"]))
    packet = entities.get(str(receipt["owner_packet_bridge_entity_id"]))
    job = entities.get(str(receipt["job_bridge_entity_id"]))
    if (
        task is None
        or packet is None
        or job is None
        or task["kind"] != "task"
        or task["source_record_sha256"] != receipt["task_source_record_sha256"]
        or packet["kind"] != "packet"
        or packet["source_record_sha256"]
        != receipt["owner_packet_source_record_sha256"]
        or job["kind"] != "job"
        or job["stated_status"] != "fail"
        or job["engineering_status"] != "blocked"
        or job["source_record_sha256"] != receipt["job_source_record_sha256"]
        or job["parent_bridge_entity_id"] != packet["bridge_entity_id"]
    ):
        _fail("legacy terminal task packet job join differs")


def verify_legacy_bridge_job_terminal_sources(
    request: Mapping[str, Any],
    *,
    blobs: BlobStore,
    readmodel: CompanyReadModel,
) -> None:
    """Replay source bytes and bind each new receipt to current inventory."""

    observations = readmodel.objects(contract_type=LEGACY_BRIDGE_OBSERVATION_V1)
    existing_receipts = readmodel.objects(
        contract_type=LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1,
    )
    seen_keys: set[str] = set()
    for event in request.get("events", ()):
        if (
            not isinstance(event, Mapping)
            or not isinstance(event.get("payload"), Mapping)
            or event["payload"].get("contract_type")
            != LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1
        ):
            continue
        try:
            receipt = validate_legacy_bridge_job_terminal_receipt(event["payload"])
            terminal_key = str(receipt["terminal_key_id"])
            if terminal_key in seen_keys:
                _fail("legacy terminal key is duplicated in one transaction")
            if any(
                item.payload.get("terminal_key_id") == terminal_key
                for item in existing_receipts
            ):
                _fail("legacy terminal key already has a durable receipt")
            seen_keys.add(terminal_key)
            raw = blobs.read(str(receipt["raw_artifact"]["sha256"]))
            if (
                len(raw) != receipt["raw_artifact"]["size_bytes"]
                or hashlib.sha256(raw).hexdigest() != receipt["source_sha256"]
            ):
                _fail("legacy terminal source blob identity differs")
            source = validate_legacy_bridge_job_terminal_source(
                json.loads(raw.decode("utf-8")),
            )
            if (
                canonical_company_json_bytes(source) != raw
                or any(receipt[field] != source[field]
                       for field in _SHARED_SOURCE_FIELDS)
            ):
                _fail("legacy terminal source differs from its receipt")
            _verify_artifact_semantics(source, blobs)
            matches = [
                item for item in observations
                if item.payload.get("bridge_scope_id") == receipt["bridge_scope_id"]
            ]
            if len(matches) != 1:
                _fail("legacy terminal source observation is missing or ambiguous")
            projected = matches[0]
            observation = validate_legacy_bridge_observation(
                _plain_json(projected.payload),
            )
            if (
                projected.global_sequence
                != receipt["source_observation_global_sequence"]
                or projected.record_id != receipt["source_observation_id"]
                or observation["observation_id"]
                != receipt["source_observation_id"]
                or company_contract_sha256(observation)
                != receipt["source_observation_payload_sha256"]
                or tuple(observation[field] for field in (
                    "company_id", "company_incarnation",
                    "lock_domain_generation", "bridge_scope_id",
                )) != tuple(receipt[field] for field in (
                    "company_id", "company_incarnation",
                    "lock_domain_generation", "bridge_scope_id",
                ))
            ):
                _fail("legacy terminal source observation join differs")
            _verify_projection_binding(receipt, observation)
        except LegacyBridgeJobTerminalIntegrityError:
            raise
        except (
            BlobStoreError, OSError, UnicodeDecodeError, json.JSONDecodeError,
            CompanyContractError, KeyError, TypeError, ValueError,
        ) as exc:
            raise LegacyBridgeJobTerminalIntegrityError(
                "legacy terminal source bytes are invalid",
            ) from exc


def verify_legacy_bridge_job_terminal_state(
    request: Mapping[str, Any],
    blobs: BlobStore,
    readmodel: CompanyReadModel,
    error_factory: Callable[[str], Exception],
) -> None:
    """Translate the bounded verifier error at the state-owner boundary."""

    try:
        verify_legacy_bridge_job_terminal_sources(
            request, blobs=blobs, readmodel=readmodel,
        )
    except LegacyBridgeJobTerminalIntegrityError as exc:
        raise error_factory(str(exc)) from exc


__all__ = [
    "LegacyBridgeJobTerminalIntegrityError",
    "verify_legacy_bridge_job_terminal_state",
    "verify_legacy_bridge_job_terminal_sources",
]
