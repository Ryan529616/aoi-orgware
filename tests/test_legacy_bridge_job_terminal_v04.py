from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

import pytest

from aoi_orgware.company.contracts import canonical_company_json_bytes
from aoi_orgware.company.legacy_bridge import normalize_legacy_bridge_snapshot
from aoi_orgware.legacy_bridge_job_terminal_v04 import (
    LEGACY_JOB_PROCESS_EXIT_V1,
    LegacyBridgeJobTerminalV04Error,
    _fingerprints,
    produce_legacy_bridge_job_terminal_evidence_v04,
)
from aoi_orgware.legacy_bridge_snapshot_v04 import (
    LegacyBridgeSnapshotV04Result,
    LegacyBridgeTaskStateV04,
)


def _fixture(
    tmp_path: Path,
    *,
    terminal_at: str = "2026-08-08T00:00:03Z",
) -> tuple[Any, LegacyBridgeSnapshotV04Result, LegacyBridgeTaskStateV04, Path, str]:
    task_id = "task-1"
    run_id = "run-1"
    task_root = tmp_path / "tasks" / task_id
    results = task_root / "results"
    results.mkdir(parents=True, exist_ok=True)
    paths = SimpleNamespace(tasks=tmp_path / "tasks")
    command = b"exit 3\n"
    command_sha = hashlib.sha256(command).hexdigest()
    command_path = results / f"job-command-{run_id}.txt"
    command_path.write_bytes(command)
    packet = {
        "packet_id": "packet-1",
        "status": "dispatched",
        "packet_mode": "exact_command",
        "command_sha256": command_sha,
        "command_size_bytes": len(command),
        "command_normalization": "terminal-whitespace-lf-v1",
        "packet_contract_sha256": "c" * 64,
    }
    log = b"intentional terminal failure\n"
    log_path = results / "remote-driver.log"
    log_path.write_bytes(log)
    manifest_path = results / f"terminal-artifacts-{run_id}.json"
    job: dict[str, Any] = {
        "run_id": run_id,
        "status": "fail",
        "exit_code": 3,
        "owner_packet_id": "packet-1",
        "owner_packet_contract_sha256": "c" * 64,
        "command_path": str(command_path),
        "command_sha256": command_sha,
        "command_size_bytes": len(command),
        "command_normalization": "terminal-whitespace-lf-v1",
        "terminal_manifest_sha256": "0" * 64,
        "host": "eda",
        "tool": "VCS",
        "tool_path": "/tools/vcs",
        "tool_version": "VCS-test",
        "work_root": "/tmp/aoi-run",
        "pid": "1234",
        "tmux": "aoi-run",
        "registered_at": "2026-08-08T00:00:00Z",
        "started_at": "2026-08-08T00:00:01Z",
    }
    manifest = {
        "manifest_version": 1,
        "task_id": task_id,
        "run_id": run_id,
        "status": "fail",
        "exit_code": 3,
        "command_path": str(command_path),
        "command_sha256": command_sha,
        "launch_authority_sha256": "f" * 64,
        "artifact": {
            "role": "primary_log",
            "origin_path": "/tmp/aoi-run/driver.log",
            "capture_source": "registered_job_log",
            "capture_status": "preserved",
            "blob_path": str(log_path),
            "sha256": hashlib.sha256(log).hexdigest(),
            "size_bytes": len(log),
        },
        "recorded_at": terminal_at,
    }
    manifest_raw = json.dumps(manifest, indent=2).encode("utf-8") + b"\n"
    manifest_path.write_bytes(manifest_raw)
    job["terminal_manifest_sha256"] = hashlib.sha256(manifest_raw).hexdigest()
    state = {
        "task_id": task_id,
        "status": "active",
        "profile_id": "profile-1",
        "config_sha256": "a" * 64,
        "packets": [packet],
        "jobs": [job],
        "needs_user_escalations": [],
    }
    state_raw = canonical_company_json_bytes(state)
    stable = LegacyBridgeTaskStateV04(
        state,
        state_raw,
        hashlib.sha256(state_raw).hexdigest(),
    )
    entries = [
        {
            "kind": "task", "legacy_id": task_id,
            "parent_kind": None, "parent_legacy_id": None,
            "stated_status": "active",
            "source_record_sha256": stable.state_sha256, "receipt_refs": [],
        },
        {
            "kind": "packet", "legacy_id": "packet-1",
            "parent_kind": "task", "parent_legacy_id": task_id,
            "stated_status": "dispatched",
            "source_record_sha256": hashlib.sha256(
                canonical_company_json_bytes(packet),
            ).hexdigest(),
            "receipt_refs": [],
        },
        {
            "kind": "job", "legacy_id": run_id,
            "parent_kind": "packet", "parent_legacy_id": "packet-1",
            "stated_status": "fail",
            "source_record_sha256": hashlib.sha256(
                canonical_company_json_bytes(job),
            ).hexdigest(),
            "receipt_refs": [],
        },
    ]
    snapshot_document = {
        "document_type": "legacy_bridge_snapshot_v1",
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "source_kind": "aoi_legacy_v04",
        "source_version": "0.4.0a4",
        "legacy_archive_sha256": "b" * 64,
        "legacy_state_sha256": stable.state_sha256,
        "legacy_receipt_set_sha256": None,
        "legacy_receipt_quality": "unavailable",
        "observed_at": "2026-08-08T00:00:04Z",
        "task_id": task_id,
        "entries": entries,
    }
    snapshot_raw = canonical_company_json_bytes(snapshot_document)
    projection = normalize_legacy_bridge_snapshot(snapshot_raw)
    snapshot = LegacyBridgeSnapshotV04Result(
        snapshot_raw,
        hashlib.sha256(snapshot_raw).hexdigest(),
        projection,
    )
    host_sha, process_sha = _fingerprints(job)
    exit_document = {
        "schema_version": LEGACY_JOB_PROCESS_EXIT_V1,
        "task_id": task_id,
        "run_id": run_id,
        "command_sha256": command_sha,
        "host_fingerprint_sha256": host_sha,
        "process_fingerprint_sha256": process_sha,
        "exit_code": 3,
        "terminal_at": terminal_at,
        "terminal_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "primary_log_sha256": hashlib.sha256(log).hexdigest(),
    }
    exit_path = results / "process-exit.json"
    exit_raw = canonical_company_json_bytes(exit_document)
    exit_path.write_bytes(exit_raw)
    return paths, snapshot, stable, exit_path, hashlib.sha256(exit_raw).hexdigest()


def _produce(
    tmp_path: Path,
    observed_at: str = "2026-08-08T00:00:04Z",
    *,
    terminal_at: str = "2026-08-08T00:00:03Z",
):
    paths, snapshot, stable, exit_path, exit_sha = _fixture(
        tmp_path, terminal_at=terminal_at,
    )
    with (
        mock.patch(
            "aoi_orgware.legacy_bridge_job_terminal_v04."
            "produce_legacy_bridge_snapshot_v04",
            return_value=snapshot,
        ),
        mock.patch(
            "aoi_orgware.legacy_bridge_job_terminal_v04."
            "read_legacy_bridge_task_state_v04",
            return_value=stable,
        ),
    ):
        return produce_legacy_bridge_job_terminal_evidence_v04(
            paths,
            "task-1",
            "run-1",
            "company-1",
            1,
            1,
            "b" * 64,
            "0.4.0a4",
            observed_at,
            exit_path,
            exit_sha,
        )


def test_adapter_binds_noncanonical_legacy_manifest_and_canonical_exit(
    tmp_path: Path,
) -> None:
    produced = _produce(tmp_path)
    assert produced.evidence["exit_code"] == 3
    assert produced.evidence["canonical_command"] == "exit 3\n"
    assert [item["role"] for item in produced.evidence["artifacts"]] == [
        "command", "legacy_state", "primary_log", "process_exit",
        "terminal_manifest",
    ]
    assert tuple(role for role, _payload in produced.artifacts) == (
        "command", "legacy_state", "primary_log", "process_exit",
        "terminal_manifest",
    )
    assert produced.evidence["observed_at"] == "2026-08-08T00:00:03Z"
    assert produced.projection.entities[-1].orphan_reason is None


def test_adapter_identity_is_stable_across_cli_observation_time(tmp_path: Path) -> None:
    first = _produce(tmp_path, "2026-08-08T00:00:04Z")
    second = _produce(tmp_path, "2026-08-08T00:05:00Z")
    assert first.evidence == second.evidence
    assert first.artifacts == second.artifacts


def test_adapter_preserves_windows_100ns_terminal_spelling_and_artifact_hash(
    tmp_path: Path,
) -> None:
    timestamp = "2026-08-08T11:09:24.1594778Z"
    produced = _produce(tmp_path, terminal_at=timestamp)
    assert produced.evidence["terminal_at"] == timestamp
    assert produced.evidence["observed_at"] == timestamp
    process_exit = next(
        payload for role, payload in produced.artifacts
        if role == "process_exit"
    )
    assert json.loads(process_exit)["terminal_at"] == timestamp
    reference = next(
        item for item in produced.evidence["artifacts"]
        if item["role"] == "process_exit"
    )
    assert reference["sha256"] == hashlib.sha256(process_exit).hexdigest()
    assert reference["size_bytes"] == len(process_exit)


@pytest.mark.parametrize(
    "mutation",
    ("manifest", "process", "artifact", "bool_exit", "command"),
)
def test_adapter_mismatch_is_typed_and_exposes_no_partial_evidence(
    tmp_path: Path,
    mutation: str,
) -> None:
    paths, snapshot, stable, exit_path, exit_sha = _fixture(tmp_path)
    state = copy.deepcopy(stable.state)
    if mutation == "bool_exit":
        state["jobs"][0]["exit_code"] = True
    elif mutation == "command":
        (paths.tasks / "task-1" / "results" / "job-command-run-1.txt").write_bytes(
            b"exit 4\n",
        )
    elif mutation == "artifact":
        (paths.tasks / "task-1" / "results" / "remote-driver.log").write_bytes(
            b"changed\n",
        )
    elif mutation == "process":
        exit_path.write_bytes(exit_path.read_bytes() + b"\n")
    else:
        manifest_path = (
            paths.tasks / "task-1" / "results" / "terminal-artifacts-run-1.json"
        )
        manifest_path.write_bytes(manifest_path.read_bytes() + b" ")
    changed_raw = canonical_company_json_bytes(state)
    changed = LegacyBridgeTaskStateV04(
        state, changed_raw, hashlib.sha256(changed_raw).hexdigest(),
    )
    with (
        mock.patch(
            "aoi_orgware.legacy_bridge_job_terminal_v04."
            "produce_legacy_bridge_snapshot_v04",
            return_value=snapshot,
        ),
        mock.patch(
            "aoi_orgware.legacy_bridge_job_terminal_v04."
            "read_legacy_bridge_task_state_v04",
            return_value=changed,
        ),
        pytest.raises(LegacyBridgeJobTerminalV04Error),
    ):
        produce_legacy_bridge_job_terminal_evidence_v04(
            paths, "task-1", "run-1", "company-1", 1, 1, "b" * 64,
            "0.4.0a4", "2026-08-08T00:00:04Z", exit_path, exit_sha,
        )
