from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from aoi_orgware.company import legacy_bridge_job_terminal as terminal_contract
from aoi_orgware.company import (
    legacy_bridge_job_terminal_publisher as terminal_publisher,
)
from aoi_orgware.company.contracts import (
    BLOB_REF_V1,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.invariant_carriers import InvariantObject
from aoi_orgware.company.invariants import (
    CompanyInvariantError,
    _validate_append_once_projection_ids,
)
from aoi_orgware.company.legacy_bridge_contract import LEGACY_BRIDGE_OBSERVATION_V1
from aoi_orgware.company.legacy_bridge_job_terminal import (
    LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1,
    LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_MEDIA_TYPE,
    LegacyBridgeJobTerminalError,
    build_legacy_bridge_job_terminal_receipt,
    build_legacy_bridge_job_terminal_source,
    validate_legacy_bridge_job_terminal_receipt,
)
from aoi_orgware.company.legacy_bridge_job_terminal_publisher import (
    LegacyBridgeJobTerminalPublicationError,
    publish_legacy_bridge_job_terminal,
)
from aoi_orgware.company.ledger import CompanyLedger
from aoi_orgware.company.readmodel import (
    CompanyReadModel,
    ReadModelCorruptionError,
)
from aoi_orgware.company.supervisor import CompanySupervisor
from aoi_orgware.legacy_bridge_job_terminal_v04 import (
    LEGACY_JOB_PROCESS_EXIT_V1,
    _fingerprints,
)
from aoi_orgware.packet_integrity import normalize_exact_command_bytes
from tests.company_v05.test_legacy_bridge import H, _entry, _raw, _snapshot
from tests.company_v05.test_legacy_bridge_supervisor import (
    R2,
    _initialized,
    _payloads,
    _publish,
)


COMMAND = b"exit 3\n"
PRIMARY_LOG = b"intentional terminal failure\n"
COMMAND_SHA = hashlib.sha256(COMMAND).hexdigest()
LOG_SHA = hashlib.sha256(PRIMARY_LOG).hexdigest()
MANIFEST = {
    "manifest_version": 1,
    "task_id": "task-1",
    "run_id": "run-1",
    "status": "fail",
    "exit_code": 3,
    "command_path": "job-command-run-1.txt",
    "command_sha256": COMMAND_SHA,
    "launch_authority_sha256": "",
    "artifact": {
        "role": "primary_log",
        "origin_path": "remote-driver.log",
        "capture_source": "registered_job_log",
        "capture_status": "preserved",
        "blob_path": "captured-driver.log",
        "sha256": LOG_SHA,
        "size_bytes": len(PRIMARY_LOG),
    },
    "recorded_at": R2,
}
MANIFEST_BYTES = json.dumps(MANIFEST, indent=2).encode("utf-8") + b"\n"
PACKET = {
    "packet_id": "packet-1",
    "status": "dispatched",
    "packet_mode": "exact_command",
    "command_sha256": COMMAND_SHA,
    "command_size_bytes": len(COMMAND),
    "command_normalization": "terminal-whitespace-lf-v1",
    "packet_contract_sha256": "c" * 64,
}
JOB = {
    "run_id": "run-1",
    "status": "fail",
    "exit_code": 3,
    "owner_packet_id": "packet-1",
    "owner_packet_contract_sha256": "c" * 64,
    "command_sha256": COMMAND_SHA,
    "command_size_bytes": len(COMMAND),
    "command_normalization": "terminal-whitespace-lf-v1",
    "command_path": "job-command-run-1.txt",
    "log": "remote-driver.log",
    "terminal_manifest_sha256": hashlib.sha256(MANIFEST_BYTES).hexdigest(),
    "terminal_artifact_status": "preserved",
    "host": "eda",
    "tool": "VCS",
    "tool_path": "tool-vcs",
    "tool_version": "VCS-test",
    "work_root": "synthetic-run-root",
    "pid": "1234",
    "tmux": "aoi-run",
    "registered_at": "2026-08-08T00:00:00Z",
    "started_at": "2026-08-08T00:00:01Z",
}
LEGACY_STATE = {
    "task_id": "task-1",
    "status": "active",
    "packets": [PACKET],
    "jobs": [JOB],
    "needs_user_escalations": [],
}
LEGACY_STATE_BYTES = canonical_company_json_bytes(LEGACY_STATE)
HOST_SHA, PROCESS_SHA = _fingerprints(JOB)
PROCESS_EXIT_BYTES = canonical_company_json_bytes({
    "schema_version": LEGACY_JOB_PROCESS_EXIT_V1,
    "task_id": "task-1",
    "run_id": "run-1",
    "command_sha256": COMMAND_SHA,
    "host_fingerprint_sha256": HOST_SHA,
    "process_fingerprint_sha256": PROCESS_SHA,
    "exit_code": 3,
    "terminal_at": R2,
    "terminal_manifest_sha256": hashlib.sha256(MANIFEST_BYTES).hexdigest(),
    "primary_log_sha256": LOG_SHA,
})
ARTIFACTS = (
    ("command", COMMAND),
    ("legacy_state", LEGACY_STATE_BYTES),
    ("primary_log", PRIMARY_LOG),
    ("process_exit", PROCESS_EXIT_BYTES),
    ("terminal_manifest", MANIFEST_BYTES),
)


@pytest.mark.parametrize(
    "raw",
    (b"exit 3\n", b"exit 3\r\n\t\r\n", b"printf 'x y'  \r"),
)
def test_terminal_command_normalizer_matches_packet_abi(raw: bytes) -> None:
    assert terminal_contract._normalize_exact_command_bytes(
        raw,
    ) == normalize_exact_command_bytes(raw)


def _terminal_snapshot() -> dict[str, Any]:
    task = _entry("task", "task-1", "active")
    packet = _entry(
        "packet", "packet-1", "dispatched", parent=("task", "task-1"),
    )
    job = _entry("job", "run-1", "fail", parent=("packet", "packet-1"))
    task["source_record_sha256"] = hashlib.sha256(LEGACY_STATE_BYTES).hexdigest()
    packet["source_record_sha256"] = hashlib.sha256(
        canonical_company_json_bytes(PACKET),
    ).hexdigest()
    job["source_record_sha256"] = hashlib.sha256(
        canonical_company_json_bytes(JOB),
    ).hexdigest()
    snapshot = _snapshot(
        [task, packet, job], receipt_quality="unavailable",
    )
    snapshot["legacy_state_sha256"] = hashlib.sha256(
        LEGACY_STATE_BYTES,
    ).hexdigest()
    return snapshot


def _terminal_evidence(
    supervisor: CompanySupervisor,
) -> tuple[dict[str, Any], tuple[tuple[str, bytes], ...]]:
    _publish(supervisor, _raw(_terminal_snapshot()))
    observation = _payloads(supervisor, LEGACY_BRIDGE_OBSERVATION_V1)[0]
    by_kind = {item["kind"]: item for item in observation["projection"]["entities"]}
    refs = [
        {
            "role": role,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
            "media_type": (
                "text/plain; charset=utf-8"
                if role == "command"
                else "text/plain"
                if role == "primary_log"
                else "application/json"
            ),
        }
        for role, payload in ARTIFACTS
    ]
    return {
        "company_id": observation["company_id"],
        "company_incarnation": observation["company_incarnation"],
        "lock_domain_generation": observation["lock_domain_generation"],
        "bridge_scope_id": observation["bridge_scope_id"],
        "legacy_archive_sha256": H,
        "legacy_state_sha256": observation["projection"]["legacy_state_sha256"],
        "task_identity_digest": observation["projection"]["task_identity_digest"],
        "task_bridge_entity_id": by_kind["task"]["bridge_entity_id"],
        "task_id": "task-1",
        "task_source_record_sha256": by_kind["task"]["source_record_sha256"],
        "owner_packet_bridge_entity_id": by_kind["packet"]["bridge_entity_id"],
        "owner_packet_id": "packet-1",
        "owner_packet_source_record_sha256": by_kind["packet"][
            "source_record_sha256"
        ],
        "owner_packet_contract_sha256": PACKET["packet_contract_sha256"],
        "job_bridge_entity_id": by_kind["job"]["bridge_entity_id"],
        "run_id": "run-1",
        "job_source_record_sha256": by_kind["job"]["source_record_sha256"],
        "canonical_command": COMMAND.decode("utf-8"),
        "command_normalization": "terminal-whitespace-lf-v1",
        "command_sha256": COMMAND_SHA,
        "command_size_bytes": len(COMMAND),
        "host_fingerprint_sha256": HOST_SHA,
        "process_fingerprint_sha256": PROCESS_SHA,
        "closure_kind": "process_exit_observed",
        "closure_scope": "registered_job_process",
        "exit_code": 3,
        "artifacts": refs,
        "terminal_at": R2,
        "observed_at": R2,
    }, ARTIFACTS


def _receipts(supervisor: CompanySupervisor) -> list[dict[str, Any]]:
    return _payloads(supervisor, LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1)


def test_terminal_publication_stores_all_artifacts_and_exact_replay_is_noop(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    try:
        evidence, artifacts = _terminal_evidence(supervisor)
        before = supervisor.heads().global_head.global_sequence
        first = publish_legacy_bridge_job_terminal(supervisor, evidence, artifacts)
        assert first.effect == "committed"
        assert first.global_sequence == before + 1
        assert first.idempotent_replay is False
        receipt = _receipts(supervisor)[0]
        assert validate_legacy_bridge_job_terminal_receipt(receipt) == receipt
        assert (
            receipt["engineering_status"], receipt["runtime_status"],
            receipt["coverage_status"], receipt["effect_status"],
        ) == ("blocked", "stopped", "degraded", "failed_known")
        for role, payload in artifacts:
            reference = next(item for item in receipt["artifacts"] if item["role"] == role)
            assert supervisor._state.blobs.read(reference["sha256"]) == payload
        head = supervisor.heads().global_head
        replay = publish_legacy_bridge_job_terminal(supervisor, evidence, artifacts)
        assert replay == first._replace(idempotent_replay=True)
        assert supervisor.heads().global_head == head
        assert len(_receipts(supervisor)) == 1
    finally:
        supervisor.close()


def test_artifact_mismatch_or_cas_readback_failure_appends_no_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = _initialized(tmp_path)
    try:
        evidence, artifacts = _terminal_evidence(supervisor)
        before = supervisor.heads().global_head
        wrong = list(artifacts)
        wrong[0] = ("command", b"exit 4\n")
        with pytest.raises(
            LegacyBridgeJobTerminalPublicationError,
            match="artifact payload binding",
        ):
            publish_legacy_bridge_job_terminal(supervisor, evidence, tuple(wrong))
        assert supervisor.heads().global_head == before
        assert not _receipts(supervisor)
        real_read = supervisor._state.blobs.read

        def missing(digest: str) -> bytes:
            if digest == evidence["artifacts"][0]["sha256"]:
                raise FileNotFoundError(digest)
            return real_read(digest)

        monkeypatch.setattr(supervisor._state.blobs, "read", missing)
        with pytest.raises(LegacyBridgeJobTerminalPublicationError):
            publish_legacy_bridge_job_terminal(supervisor, evidence, artifacts)
        assert supervisor.heads().global_head == before
        assert not _receipts(supervisor)
    finally:
        supervisor.close()


def test_terminal_manifest_must_match_the_durable_job_record(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    try:
        evidence, artifacts = _terminal_evidence(supervisor)
        before = supervisor.heads().global_head
        forged_manifest = copy.deepcopy(MANIFEST)
        forged_manifest["recorded_at"] = "2026-08-08T00:00:03Z"
        forged_manifest_bytes = (
            json.dumps(forged_manifest, indent=2).encode("utf-8") + b"\n"
        )
        forged_process = json.loads(PROCESS_EXIT_BYTES)
        forged_process["terminal_manifest_sha256"] = hashlib.sha256(
            forged_manifest_bytes,
        ).hexdigest()
        forged_process_bytes = canonical_company_json_bytes(forged_process)
        replaced = {
            role: payload for role, payload in artifacts
        }
        replaced["terminal_manifest"] = forged_manifest_bytes
        replaced["process_exit"] = forged_process_bytes
        forged_evidence = copy.deepcopy(evidence)
        for reference in forged_evidence["artifacts"]:
            role = reference["role"]
            reference["sha256"] = hashlib.sha256(replaced[role]).hexdigest()
            reference["size_bytes"] = len(replaced[role])
        with pytest.raises(
            LegacyBridgeJobTerminalPublicationError,
            match="conflicts with durable truth",
        ):
            publish_legacy_bridge_job_terminal(
                supervisor,
                forged_evidence,
                tuple(sorted(replaced.items())),
            )
        assert supervisor.heads().global_head == before
        assert not _receipts(supervisor)
    finally:
        supervisor.close()


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("task_id", "claimed-other-task"),
        ("owner_packet_id", "claimed-other-packet"),
        ("run_id", "claimed-other-run"),
        ("owner_packet_contract_sha256", "f" * 64),
        ("host_fingerprint_sha256", "9" * 64),
        ("exit_code", 99),
    ],
)
def test_artifact_semantics_cannot_be_forged_by_declared_evidence(
    tmp_path: Path,
    field: str,
    replacement: Any,
) -> None:
    supervisor = _initialized(tmp_path)
    try:
        evidence, artifacts = _terminal_evidence(supervisor)
        before = supervisor.heads().global_head
        evidence[field] = replacement
        with pytest.raises(
            LegacyBridgeJobTerminalPublicationError,
            match="conflicts with durable truth",
        ):
            publish_legacy_bridge_job_terminal(supervisor, evidence, artifacts)
        assert supervisor.heads().global_head == before
        assert not _receipts(supervisor)
    finally:
        supervisor.close()


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("company_incarnation", True),
        ("exit_code", False),
        ("command_size_bytes", True),
    ],
)
def test_bool_as_int_is_typed_failure(
    tmp_path: Path,
    field: str,
    replacement: bool,
) -> None:
    supervisor = _initialized(tmp_path)
    try:
        evidence, _artifacts = _terminal_evidence(supervisor)
        evidence[field] = replacement
        with pytest.raises(LegacyBridgeJobTerminalError):
            build_legacy_bridge_job_terminal_source(
                evidence,
                source_observation_id="1" * 64,
                source_observation_payload_sha256="2" * 64,
                source_observation_global_sequence=1,
            )
    finally:
        supervisor.close()


def test_duplicate_artifact_role_and_divergent_second_receipt_fail_closed(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    try:
        evidence, artifacts = _terminal_evidence(supervisor)
        duplicated = copy.deepcopy(evidence)
        duplicated["artifacts"][1]["role"] = "command"
        with pytest.raises(LegacyBridgeJobTerminalError):
            build_legacy_bridge_job_terminal_source(
                duplicated,
                source_observation_id="1" * 64,
                source_observation_payload_sha256="2" * 64,
                source_observation_global_sequence=1,
            )
        publish_legacy_bridge_job_terminal(supervisor, evidence, artifacts)
        head = supervisor.heads().global_head
        divergent = copy.deepcopy(evidence)
        divergent["observed_at"] = "2026-08-04T02:00:01Z"
        with pytest.raises(LegacyBridgeJobTerminalPublicationError):
            publish_legacy_bridge_job_terminal(supervisor, divergent, artifacts)
        assert supervisor.heads().global_head == head
        assert len(_receipts(supervisor)) == 1
    finally:
        supervisor.close()


def test_request_evidence_digest_is_builder_owned(tmp_path: Path) -> None:
    supervisor = _initialized(tmp_path)
    try:
        evidence, _artifacts = _terminal_evidence(supervisor)
        source = build_legacy_bridge_job_terminal_source(
            evidence,
            source_observation_id="1" * 64,
            source_observation_payload_sha256="2" * 64,
            source_observation_global_sequence=1,
        )
        source["request_evidence_sha256"] = "f" * 64
        with pytest.raises(
            LegacyBridgeJobTerminalError,
            match="request evidence digest differs",
        ):
            terminal_contract.validate_legacy_bridge_job_terminal_source(source)
    finally:
        supervisor.close()


def test_reducer_append_once_registry_rejects_divergent_receipt(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    try:
        evidence, artifacts = _terminal_evidence(supervisor)
        publish_legacy_bridge_job_terminal(supervisor, evidence, artifacts)
        first = _receipts(supervisor)[0]
        divergent_evidence = copy.deepcopy(evidence)
        divergent_evidence.update({
            "terminal_at": "2026-08-04T02:00:01Z",
            "observed_at": "2026-08-04T02:00:01Z",
        })
        source = build_legacy_bridge_job_terminal_source(
            divergent_evidence,
            source_observation_id=first["source_observation_id"],
            source_observation_payload_sha256=(
                first["source_observation_payload_sha256"]
            ),
            source_observation_global_sequence=(
                first["source_observation_global_sequence"]
            ),
        )
        raw = canonical_company_json_bytes(source)
        second = build_legacy_bridge_job_terminal_receipt(
            source,
            source_sha256=hashlib.sha256(raw).hexdigest(),
            raw_artifact={
                "contract_type": BLOB_REF_V1,
                "schema_version": 1,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
                "media_type": LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_MEDIA_TYPE,
                "availability": "available",
            },
        )
        assert first["terminal_key_id"] == second["terminal_key_id"]
        assert first["receipt_id"] != second["receipt_id"]
        old = InvariantObject(
            LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1,
            first["terminal_key_id"],
            "legacy-terminal-event-first",
            1,
            company_contract_sha256(first),
            first,
        )
        new = InvariantObject(
            LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1,
            second["terminal_key_id"],
            "legacy-terminal-event-second",
            2,
            company_contract_sha256(second),
            second,
        )
        with pytest.raises(
            CompanyInvariantError,
            match="append-only provider projection",
        ):
            _validate_append_once_projection_ids(
                {(old.contract_type, old.object_key): old},
                (new,),
            )
    finally:
        supervisor.close()


def test_readmodel_replay_rejects_divergent_same_key_receipt(
    tmp_path: Path,
) -> None:
    supervisor = _initialized(tmp_path)
    closed = False
    try:
        evidence, artifacts = _terminal_evidence(supervisor)
        publish_legacy_bridge_job_terminal(supervisor, evidence, artifacts)
        first = _receipts(supervisor)[0]
        divergent_evidence = copy.deepcopy(evidence)
        divergent_evidence.update({
            "terminal_at": "2026-08-04T02:00:01Z",
            "observed_at": "2026-08-04T02:00:01Z",
        })
        source = build_legacy_bridge_job_terminal_source(
            divergent_evidence,
            source_observation_id=first["source_observation_id"],
            source_observation_payload_sha256=(
                first["source_observation_payload_sha256"]
            ),
            source_observation_global_sequence=(
                first["source_observation_global_sequence"]
            ),
        )
        raw = canonical_company_json_bytes(source)
        second = build_legacy_bridge_job_terminal_receipt(
            source,
            source_sha256=hashlib.sha256(raw).hexdigest(),
            raw_artifact={
                "contract_type": BLOB_REF_V1,
                "schema_version": 1,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
                "media_type": LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_MEDIA_TYPE,
                "availability": "available",
            },
        )
        request = terminal_publisher._request(supervisor, second)
        ledger_path = supervisor._state.resolved.incarnation.ledger
        supervisor.close()
        closed = True
        with CompanyLedger(ledger_path) as ledger:
            ledger.append(request)
            records = ledger.load_records()
        with pytest.raises(
            ReadModelCorruptionError,
            match="violates company invariants",
        ):
            CompanyReadModel.rebuild(
                tmp_path / "divergent-replay.sqlite3",
                records,
            )
    finally:
        if not closed:
            supervisor.close()


def test_terminal_receipt_survives_rebuild_and_reopen(tmp_path: Path) -> None:
    supervisor = _initialized(tmp_path)
    evidence, artifacts = _terminal_evidence(supervisor)
    first = publish_legacy_bridge_job_terminal(supervisor, evidence, artifacts)
    root = supervisor.slot_root
    supervisor._state.rebuild_projection()
    assert _receipts(supervisor)[0]["receipt_id"] == first.receipt_id
    supervisor.close()
    reopened = CompanySupervisor.open(root)
    try:
        assert reopened.heads().global_head.global_sequence == first.global_sequence
        assert _receipts(reopened)[0]["receipt_id"] == first.receipt_id
    finally:
        reopened.close()
