from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence, cast
import urllib.request

import pytest

from aoi_orgware.company.contracts import (
    BLOB_REF_V1,
    CARRIER_BINDING_V1,
    EXTERNAL_JOB_EFFECT_RECEIPT_V1,
    EXTERNAL_JOB_EFFECT_SOURCE_MEDIA_TYPE,
    EXTERNAL_JOB_EFFECT_SOURCE_V1,
    EXTERNAL_JOB_V1,
    EXECUTION_NODE_V1,
    MUTATION_INTENT_V1,
    PROVIDER_LIFECYCLE_RECEIPT_V1,
    PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE,
    PROVIDER_LIFECYCLE_SOURCE_V1,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.supervisor import (
    CompanyExternalJobError,
    CompanySupervisor,
    ExternalJobLifecycleResult,
)


T = "2026-07-27T00:00:00Z"
EXPIRY = "2026-07-28T00:00:00Z"
SCOPE = "f" * 64


def _manifest() -> dict[str, object]:
    return {
        "contract_type": "company_manifest_v1",
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "git_common_dir_sha256": "a" * 64,
        "remote_fingerprint_sha256": "b" * 64,
        "configuration_sha256": "c" * 64,
        "state_root_sha256": "d" * 64,
        "lock_domain_id": "windows" if os.name == "nt" else "posix",
        "created_at": T,
        "observation": {"state": "known", "reason": "observed"},
    }


def _carrier(number: int = 1) -> dict[str, object]:
    return {
        "carrier_id": f"carrier-{number}",
        "provider": "codex",
        "model": "gpt-5",
        "session_id": f"session-{number}",
        "thread_id": f"thread-{number}",
        "provenance": "agent_reported",
        "observation": {"state": "known", "reason": "observed"},
    }


def _supervisor(tmp_path: Path) -> CompanySupervisor:
    return CompanySupervisor.initialize(
        tmp_path / "state" / "companies" / "company-1",
        _manifest(),
        bootstrap_at=T,
        grant_expires_at=EXPIRY,
        platform="windows" if os.name == "nt" else "posix",
        known_carrier=_carrier(),
    )


def _objects(
    supervisor: CompanySupervisor,
    contract_type: str,
) -> list[dict[str, object]]:
    return [
        dict(item.payload)
        for item in supervisor.objects(contract_type=contract_type)
    ]


def _chief_execution(supervisor: CompanySupervisor) -> dict[str, object]:
    return next(
        item for item in _objects(supervisor, EXECUTION_NODE_V1)
        if item["execution_kind"] == "carrier"
        and item["engineering_status"] == "active"
    )


def _job(supervisor: CompanySupervisor, job_id: str) -> dict[str, object]:
    return next(
        item for item in _objects(supervisor, EXTERNAL_JOB_V1)
        if item["job_id"] == job_id
    )


def _queue(
    supervisor: CompanySupervisor,
    *,
    suffix: str = "one",
    transaction_id: str | None = None,
    command_bytes: bytes = b'{"tool":"vcs"}',
    recorded_at: str = "2026-07-27T00:00:10Z",
) -> ExternalJobLifecycleResult:
    owner = _chief_execution(supervisor)
    return supervisor.queue_external_job(
        str(owner["execution_id"]),
        job_id=f"job-{suffix}",
        job_execution_id=f"job-execution-{suffix}",
        mutation_intent_id=f"job-intent-{suffix}",
        command_bytes=command_bytes,
        command_media_type="application/json",
        scope_sha256=SCOPE,
        display_name=f"External job {suffix}",
        objective=f"Run durable external job {suffix}.",
        authority_grant_id=f"job-grant-{suffix}",
        grant_expires_at=EXPIRY,
        transaction_id=transaction_id or f"job-queue-transaction-{suffix}",
        command_id=f"job-queue-command-{suffix}",
        recorded_at=recorded_at,
    )


def _handle(native_handle: str = "991") -> dict[str, str]:
    return {
        "provider": "eda",
        "namespace": "jobs",
        "resolver": "pid",
        "native_handle": native_handle,
        "host_fingerprint_sha256": "9" * 64,
    }


def _chief_stop_receipt(
    supervisor: CompanySupervisor,
    *,
    execution_id: str,
    transaction_id: str,
    command_id: str,
    recorded_at: str,
) -> dict[str, object]:
    execution = next(
        item
        for item in _objects(supervisor, EXECUTION_NODE_V1)
        if item["execution_id"] == execution_id
    )
    carrier = next(
        item
        for item in _objects(supervisor, CARRIER_BINDING_V1)
        if item["carrier_id"] == execution["carrier_id"]
    )
    source: dict[str, object] = {
        "source_type": PROVIDER_LIFECYCLE_SOURCE_V1,
        "schema_version": 1,
        **_binding(),
        "source_event_id": f"provider-stop-{transaction_id}",
        "event_kind": "execution_stopped",
        "dispatch_request_id": None,
        "provider_dispatch_id": None,
        "execution_id": execution_id,
        "carrier_id": execution["carrier_id"],
        "organization_node_id": execution["organization_node_id"],
        "provider": execution["provider"],
        "model": execution["model"],
        "effort": execution["effort"],
        "session_id": carrier["session_id"],
        "thread_id": execution["thread_id"],
        "reconcile_ref": None,
        "observed_at": recorded_at,
        "provenance": "host_process_observed",
        "observation": {"state": "known", "reason": "observed"},
    }
    source_bytes = canonical_company_json_bytes(source)
    metadata = supervisor._state.blobs.put(source_bytes)
    artifact = {
        "contract_type": BLOB_REF_V1,
        "schema_version": 1,
        "sha256": metadata.sha256,
        "size_bytes": metadata.size_bytes,
        "media_type": PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE,
        "availability": "available",
    }
    unsigned: dict[str, object] = {
        "contract_type": PROVIDER_LIFECYCLE_RECEIPT_V1,
        "schema_version": 1,
        **_binding(),
        "receipt_id": f"provider-stop-receipt-{transaction_id}",
        "source_event_id": source["source_event_id"],
        "event_kind": "execution_stopped",
        "transaction_id": transaction_id,
        "command_id": command_id,
        "dispatch_request_id": None,
        "dispatch_revision_id": None,
        "dispatch_revision": None,
        "provider_dispatch_id": None,
        "execution_id": execution_id,
        "carrier_id": execution["carrier_id"],
        "organization_node_id": execution["organization_node_id"],
        "provider": execution["provider"],
        "model": execution["model"],
        "effort": execution["effort"],
        "session_id": carrier["session_id"],
        "thread_id": execution["thread_id"],
        "reconcile_ref": None,
        "observed_at": recorded_at,
        "provenance": "host_process_observed",
        "observation": {"state": "known", "reason": "observed"},
        "raw_artifact": artifact,
    }
    return {
        **unsigned,
        "receipt_sha256": company_contract_sha256(unsigned),
    }


def _binding() -> dict[str, object]:
    return {
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
    }


def _effect_material(
    supervisor: CompanySupervisor,
    job_id: str,
    state: str,
    *,
    suffix: str,
    transaction_id: str,
    transition_command_id: str,
    recorded_at: str,
    external_handle: Mapping[str, object] | None,
    source_overrides: Mapping[str, object] | None = None,
    receipt_overrides: Mapping[str, object] | None = None,
) -> tuple[bytes, dict[str, object]]:
    """Build one canonical adapter source and its byte-bound typed receipt."""

    current = _job(supervisor, job_id)
    uncertain = state in {"effect_unknown", "reconcile_required"}
    terminal = state in {"completed", "failed_known"}
    prior_uncertain = current["state"] in {
        "effect_unknown", "reconcile_required",
    }
    observation: dict[str, str]
    if uncertain:
        observation = {"state": "unknown", "reason": "observer_lost"}
    elif state == "aborted":
        # The terminal job field carries ``aborted_before_launch``; an
        # adapter observation itself remains a known observed fact.
        observation = {"state": "known", "reason": "observed"}
    else:
        observation = {"state": "known", "reason": "observed"}
    handle_sha256 = (
        None
        if external_handle is None
        else company_contract_sha256(dict(external_handle))
    )
    source: dict[str, object] = {
        "source_type": EXTERNAL_JOB_EFFECT_SOURCE_V1,
        "schema_version": 1,
        **_binding(),
        "source_event_id": f"job-effect-source-{suffix}",
        "receipt_id": f"job-effect-receipt-{suffix}",
        "job_id": job_id,
        "mutation_intent_id": current["mutation_intent_id"],
        "command_id": current["command_id"],
        "transaction_id": transaction_id,
        "transition_command_id": transition_command_id,
        "previous_job_state": current["state"],
        "observed_job_state": state,
        "external_handle_sha256": handle_sha256,
        "process_fingerprint_sha256": (
            None
            if state == "aborted"
            else (
                current["process_fingerprint_sha256"]
                if uncertain
                and current["process_fingerprint_sha256"] is not None
                else hashlib.sha256(b"external-process").hexdigest()
            )
        ),
        "reconciliation_id": (
            str(current["reconcile_ref"])
            if uncertain and current["reconcile_ref"] is not None
            else (f"reconcile-{suffix}" if uncertain else None)
        ),
        "resolves_reconciliation_id": (
            str(current["reconcile_ref"])
            if terminal and prior_uncertain
            else None
        ),
        "observed_at": recorded_at,
        "provenance": "agent_reported",
        "observation": observation,
    }
    source.update(source_overrides or {})
    source_bytes = canonical_company_json_bytes(source)
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    raw_artifact = {
        "contract_type": "blob_ref_v1",
        "schema_version": 1,
        "sha256": source_sha256,
        "size_bytes": len(source_bytes),
        "media_type": EXTERNAL_JOB_EFFECT_SOURCE_MEDIA_TYPE,
        "availability": "available",
    }
    receipt: dict[str, object] = {
        "contract_type": EXTERNAL_JOB_EFFECT_RECEIPT_V1,
        "schema_version": 1,
        **{key: source[key] for key in (
            "company_id", "company_incarnation", "lock_domain_generation",
            "source_event_id", "receipt_id", "job_id", "mutation_intent_id",
            "command_id", "transaction_id", "transition_command_id",
            "previous_job_state", "observed_job_state",
            "external_handle_sha256", "process_fingerprint_sha256",
            "reconciliation_id", "resolves_reconciliation_id", "observed_at",
            "provenance", "observation",
        )},
        "source_sha256": source_sha256,
        "raw_artifact": raw_artifact,
    }
    receipt.update(receipt_overrides or {})
    receipt["receipt_sha256"] = company_contract_sha256(receipt)
    return source_bytes, receipt


def _record(
    supervisor: CompanySupervisor,
    job_id: str,
    state: str,
    *,
    suffix: str,
    external_handle: Mapping[str, object] | None = None,
    recorded_at: str,
    transaction_id: str | None = None,
    command_id: str | None = None,
    source_overrides: Mapping[str, object] | None = None,
    receipt_overrides: Mapping[str, object] | None = None,
    source_bytes_override: bytes | None = None,
) -> ExternalJobLifecycleResult:
    transaction_id = transaction_id or f"job-{state}-transaction-{suffix}"
    command_id = command_id or f"job-{state}-command-{suffix}"
    source_bytes, receipt = _effect_material(
        supervisor,
        job_id,
        state,
        suffix=suffix,
        transaction_id=transaction_id,
        transition_command_id=command_id,
        recorded_at=recorded_at,
        external_handle=external_handle,
        source_overrides=source_overrides,
        receipt_overrides=receipt_overrides,
    )
    return supervisor.record_external_job_state(
        job_id,
        effect_source_bytes=(
            source_bytes if source_bytes_override is None else source_bytes_override
        ),
        effect_receipt=receipt,
        external_handle=external_handle,
        transaction_id=transaction_id,
        command_id=command_id,
        recorded_at=recorded_at,
    )


def test_external_job_queue_is_atomic_replayable_and_dashboard_visible(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path)
    slot = supervisor.slot_root
    dashboard_url = supervisor.start_dashboard()
    try:
        queued = _queue(supervisor)
        assert queued.job_state == "queued"
        assert not queued.idempotent_replay
        assert queued.global_sequence == 2
        owner = _chief_execution(supervisor)
        job = _objects(supervisor, EXTERNAL_JOB_V1)
        intent = _objects(supervisor, MUTATION_INTENT_V1)
        execution = next(
            item for item in _objects(supervisor, EXECUTION_NODE_V1)
            if item["execution_id"] == queued.job_execution_id
        )
        assert len(job) == len(intent) == 1
        assert job[0]["owner_execution_id"] == owner["execution_id"]
        assert job[0]["mutation_intent_id"] == intent[0]["intent_id"]
        assert execution["parent_execution_id"] == owner["execution_id"]
        assert tuple(cast(Sequence[str], execution["execution_path"])) == (
            *cast(Sequence[str], owner["execution_path"]),
            queued.job_execution_id,
        )
        assert owner["job_ids"] == (queued.job_id,)
        record = supervisor.records_after(1)[0]
        assert [member.event["event_type"] for member in record.events] == [
            "authority.granted",
            "execution.external_job.attached",
            "external_job.queued.current",
            "external_job.queued",
            "mutation_intent.admitted",
            "external_job.queued",
        ]
        with urllib.request.urlopen(dashboard_url + "api/v1/snapshot", timeout=3) as response:
            snapshot = json.loads(response.read())
        assert snapshot["cursor"] == 2
        dashboard_job = next(
            item for item in snapshot["data"]["jobs"]
            if item["job_id"] == queued.job_id
        )
        assert dashboard_job["owner_execution_id"] == owner["execution_id"]
        assert dashboard_job["state"] == "queued"
        assert dashboard_job["command_blob"]["availability"] == "available"
        assert dashboard_job["external_handle"] == {"availability": "unavailable"}

        replay = _queue(supervisor)
        assert replay.idempotent_replay
        assert replay.global_sequence == queued.global_sequence
        before = supervisor.heads().global_head.global_sequence
        with pytest.raises(CompanyExternalJobError, match="command or display bytes differ"):
            _queue(supervisor, command_bytes=b'{"tool":"different"}')
        assert supervisor.heads().global_head.global_sequence == before
    finally:
        supervisor.close()

    with CompanySupervisor.open(slot) as reopened:
        assert reopened._state.rebuild_projection().global_sequence == 2
        replay = _queue(reopened)
        assert replay.idempotent_replay
        assert replay.global_sequence == 2
        assert _objects(reopened, EXTERNAL_JOB_V1)[0]["job_id"] == "job-one"


def test_external_job_launch_is_single_cas_and_retry_is_exact(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path)
    try:
        queued = _queue(supervisor)
        first = supervisor.admit_external_job_launch(
            queued.job_id,
            transaction_id="job-launch-transaction-one",
            command_id="job-launch-command-one",
            recorded_at="2026-07-27T00:00:20Z",
        )
        assert (first.job_state, first.mutation_state) == ("queued", "in_flight")
        replay = supervisor.admit_external_job_launch(
            queued.job_id,
            transaction_id="job-launch-transaction-one",
            command_id="job-launch-command-one",
            recorded_at="2026-07-27T00:00:20Z",
        )
        assert replay.idempotent_replay
        assert replay.global_sequence == first.global_sequence
        before = supervisor.heads().global_head.global_sequence
        with pytest.raises(CompanyExternalJobError, match="not newly admissible"):
            supervisor.admit_external_job_launch(
                queued.job_id,
                transaction_id="job-launch-transaction-two",
                command_id="job-launch-command-two",
                recorded_at="2026-07-27T00:00:21Z",
            )
        assert supervisor.heads().global_head.global_sequence == before
    finally:
        supervisor.close()


def test_typed_effect_receipt_orders_events_replays_and_survives_rebuild(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path)
    slot = supervisor.slot_root
    try:
        queued = _queue(supervisor)
        supervisor.admit_external_job_launch(
            queued.job_id,
            transaction_id="job-launch-transaction-one",
            command_id="job-launch-command-one",
            recorded_at="2026-07-27T00:00:20Z",
        )
        handle = _handle()
        running_source, running_receipt = _effect_material(
            supervisor, queued.job_id, "running", suffix="running",
            transaction_id="job-running-transaction-running",
            transition_command_id="job-running-command-running",
            recorded_at="2026-07-27T00:00:30Z", external_handle=handle,
        )
        running = supervisor.record_external_job_state(
            queued.job_id, effect_source_bytes=running_source,
            effect_receipt=running_receipt, external_handle=handle,
            transaction_id="job-running-transaction-running",
            command_id="job-running-command-running",
            recorded_at="2026-07-27T00:00:30Z",
        )
        assert running.job_state == "running"
        record = supervisor.records_after(running.global_sequence - 1)[0]
        assert [member.event["event_type"] for member in record.events] == [
            "external_job.effect.running.observed",
            "external_job.running.current",
            "external_job.running",
            "mutation_intent.in_flight",
            "external_job.running",
        ]
        completed = _record(
            supervisor, queued.job_id, "completed", suffix="completed",
            external_handle=handle, recorded_at="2026-07-27T00:00:31Z",
        )
        assert completed.job_state == "completed"
        receipts = _objects(supervisor, EXTERNAL_JOB_EFFECT_RECEIPT_V1)
        assert {
            str(item["observed_job_state"]) for item in receipts
        } == {"running", "completed"}
        job = _job(supervisor, queued.job_id)
        assert len(cast(Sequence[object], job["effect_evidence"])) == 1

        replayed_launch = supervisor.admit_external_job_launch(
            queued.job_id,
            transaction_id="job-launch-transaction-one",
            command_id="job-launch-command-one",
            recorded_at="2026-07-27T00:00:20Z",
        )
        assert replayed_launch.idempotent_replay
        replayed_running = supervisor.record_external_job_state(
            queued.job_id, effect_source_bytes=running_source,
            effect_receipt=running_receipt, external_handle=handle,
            transaction_id="job-running-transaction-running",
            command_id="job-running-command-running",
            recorded_at="2026-07-27T00:00:30Z",
        )
        assert replayed_running.idempotent_replay
        assert replayed_running.global_sequence == running.global_sequence
        cursor = supervisor.heads().global_head.global_sequence
        with pytest.raises(CompanyExternalJobError):
            supervisor.record_external_job_state(
                queued.job_id,
                effect_source_bytes=running_source,
                effect_receipt=running_receipt,
                external_handle=_handle("992"),
                transaction_id="job-running-transaction-running",
                command_id="job-running-command-running",
                recorded_at="2026-07-27T00:00:30Z",
            )
        assert supervisor.heads().global_head.global_sequence == cursor
        with pytest.raises(CompanyExternalJobError):
            supervisor.record_external_job_state(
                queued.job_id,
                effect_source_bytes=running_source + b"\n",
                effect_receipt=running_receipt,
                external_handle=handle,
                transaction_id="job-running-transaction-running",
                command_id="job-running-command-running",
                recorded_at="2026-07-27T00:00:30Z",
            )
        assert supervisor.heads().global_head.global_sequence == cursor
    finally:
        supervisor.close()

    with CompanySupervisor.open(slot) as reopened:
        assert reopened._state.rebuild_projection().global_sequence == completed.global_sequence
        receipts = _objects(reopened, EXTERNAL_JOB_EFFECT_RECEIPT_V1)
        assert {
            str(item["observed_job_state"]) for item in receipts
        } == {"running", "completed"}
        replay = reopened.record_external_job_state(
            "job-one", effect_source_bytes=running_source,
            effect_receipt=running_receipt, external_handle=_handle(),
            transaction_id="job-running-transaction-running",
            command_id="job-running-command-running",
            recorded_at="2026-07-27T00:00:30Z",
        )
        assert replay.idempotent_replay


def test_uncertain_reconciliation_and_aborted_before_launch(tmp_path: Path) -> None:
    uncertain = _supervisor(tmp_path / "uncertain")
    try:
        queued = _queue(uncertain, suffix="uncertain")
        uncertain.admit_external_job_launch(
            queued.job_id,
            transaction_id="job-launch-transaction-uncertain",
            command_id="job-launch-command-uncertain",
            recorded_at="2026-07-27T00:00:20Z",
        )
        running = _record(
            uncertain, queued.job_id, "running", suffix="uncertain-running",
            external_handle=_handle(), recorded_at="2026-07-27T00:00:29Z",
        )
        running_fingerprint = _job(
            uncertain, queued.job_id,
        )["process_fingerprint_sha256"]
        unknown = _record(
            uncertain, queued.job_id, "effect_unknown", suffix="unknown",
            external_handle=_handle(), recorded_at="2026-07-27T00:00:30Z",
        )
        reconcile = _record(
            uncertain, queued.job_id, "reconcile_required", suffix="reconcile",
            external_handle=_handle(), recorded_at="2026-07-27T00:00:31Z",
        )
        completed = _record(
            uncertain, queued.job_id, "completed", suffix="resolved",
            external_handle=_handle(), recorded_at="2026-07-27T00:00:32Z",
        )
        assert (unknown.job_state, reconcile.job_state, completed.job_state) == (
            "effect_unknown", "reconcile_required", "completed",
        )
        assert running.job_state == "running"
        assert _job(uncertain, queued.job_id)["process_fingerprint_sha256"] == (
            running_fingerprint
        )
        receipts = _objects(uncertain, EXTERNAL_JOB_EFFECT_RECEIPT_V1)
        resolved_receipt = next(
            item for item in receipts
            if item["observed_job_state"] == "completed"
        )
        assert resolved_receipt["resolves_reconciliation_id"] == "reconcile-unknown"
    finally:
        uncertain.close()

    aborted = _supervisor(tmp_path / "aborted")
    try:
        queued = _queue(aborted, suffix="aborted")
        result = _record(
            aborted, queued.job_id, "aborted", suffix="aborted",
            external_handle=None, recorded_at="2026-07-27T00:00:20Z",
        )
        assert result.job_state == "aborted"
        job = _job(aborted, queued.job_id)
        assert job["effect_evidence"] == ()
        assert job["external_handle"] is None
    finally:
        aborted.close()


def test_effect_receipt_rejects_mismatch_dangling_reconcile_and_blob_smuggling(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path)
    try:
        queued = _queue(supervisor)
        supervisor.admit_external_job_launch(
            queued.job_id,
            transaction_id="job-launch-transaction-one",
            command_id="job-launch-command-one",
            recorded_at="2026-07-27T00:00:20Z",
        )
        handle = _handle()
        _record(
            supervisor, queued.job_id, "running", suffix="running",
            external_handle=handle, recorded_at="2026-07-27T00:00:30Z",
        )
        cursor = supervisor.heads().global_head.global_sequence
        bad_cases: list[dict[str, object]] = [
            {"suffix": "prior", "source_overrides": {"previous_job_state": "queued"}},
            {"suffix": "handle", "source_overrides": {
                "external_handle_sha256": company_contract_sha256(_handle("992")),
            }},
            {"suffix": "job", "source_overrides": {"job_id": "other-job"}},
            {"suffix": "intent", "source_overrides": {"mutation_intent_id": "other-intent"}},
            {"suffix": "outer", "source_overrides": {"transaction_id": "wrong-transaction"}},
            {"suffix": "source-mismatch", "receipt_overrides": {"source_event_id": "other-source"}},
        ]
        for case in bad_cases:
            with pytest.raises(CompanyExternalJobError):
                _record(
                    supervisor,
                    queued.job_id,
                    "completed",
                    suffix=cast(str, case["suffix"]),
                    external_handle=handle,
                    recorded_at="2026-07-27T00:00:31Z",
                    source_overrides=cast(
                        Mapping[str, object] | None,
                        case.get("source_overrides"),
                    ),
                    receipt_overrides=cast(
                        Mapping[str, object] | None,
                        case.get("receipt_overrides"),
                    ),
                )
            assert supervisor.heads().global_head.global_sequence == cursor

    finally:
        supervisor.close()

    dangling = _supervisor(tmp_path / "dangling")
    try:
        queued = _queue(dangling, suffix="dangling")
        dangling.admit_external_job_launch(
            queued.job_id,
            transaction_id="job-launch-transaction-dangling",
            command_id="job-launch-command-dangling",
            recorded_at="2026-07-27T00:00:20Z",
        )
        _record(
            dangling, queued.job_id, "running", suffix="dangling-running",
            external_handle=_handle(), recorded_at="2026-07-27T00:00:29Z",
        )
        unknown = _record(
            dangling, queued.job_id, "effect_unknown", suffix="unknown",
            external_handle=_handle(), recorded_at="2026-07-27T00:00:30Z",
        )
        assert unknown.job_state == "effect_unknown"
        cursor = dangling.heads().global_head.global_sequence
        with pytest.raises(CompanyExternalJobError):
            _record(
                dangling, queued.job_id, "reconcile_required", suffix="wrong-ref",
                external_handle=_handle(), recorded_at="2026-07-27T00:00:31Z",
                source_overrides={"reconciliation_id": "dangling-reconcile"},
            )
        assert dangling.heads().global_head.global_sequence == cursor
        with pytest.raises(CompanyExternalJobError):
            _record(
                dangling, queued.job_id, "completed", suffix="wrong-resolve",
                external_handle=_handle(), recorded_at="2026-07-27T00:00:31Z",
                source_overrides={"resolves_reconciliation_id": "dangling-reconcile"},
            )
        assert dangling.heads().global_head.global_sequence == cursor
    finally:
        dangling.close()

    command_blob = _supervisor(tmp_path / "command-blob")
    try:
        # This command is itself a canonical typed source, so contract parsing
        # succeeds.  The state owner must still reject command-as-effect reuse.
        source: dict[str, object] = {
            "source_type": EXTERNAL_JOB_EFFECT_SOURCE_V1,
            "schema_version": 1,
            **_binding(),
            "source_event_id": "job-effect-source-command-blob",
            "receipt_id": "job-effect-receipt-command-blob",
            "job_id": "job-command-blob",
            "mutation_intent_id": "job-intent-command-blob",
            "command_id": "job-queue-command-command-blob",
            "transaction_id": "job-running-transaction-command-blob",
            "transition_command_id": "job-running-command-command-blob",
            "previous_job_state": "queued",
            "observed_job_state": "running",
            "external_handle_sha256": company_contract_sha256(_handle()),
            "process_fingerprint_sha256": hashlib.sha256(b"external-process").hexdigest(),
            "reconciliation_id": None,
            "resolves_reconciliation_id": None,
            "observed_at": "2026-07-27T00:00:30Z",
            "provenance": "agent_reported",
            "observation": {"state": "known", "reason": "observed"},
        }
        command_bytes = canonical_company_json_bytes(source)
        queued = _queue(command_blob, suffix="command-blob", command_bytes=command_bytes)
        command_blob.admit_external_job_launch(
            queued.job_id,
            transaction_id="job-launch-transaction-command-blob",
            command_id="job-launch-command-command-blob",
            recorded_at="2026-07-27T00:00:20Z",
        )
        source_bytes, receipt = _effect_material(
            command_blob, queued.job_id, "running", suffix="command-blob",
            transaction_id="job-running-transaction-command-blob",
            transition_command_id="job-running-command-command-blob",
            recorded_at="2026-07-27T00:00:30Z", external_handle=_handle(),
        )
        assert source_bytes == command_bytes
        before = command_blob.heads().global_head.global_sequence
        with pytest.raises(CompanyExternalJobError, match="differs from its durable job"):
            command_blob.record_external_job_state(
                queued.job_id, effect_source_bytes=source_bytes,
                effect_receipt=receipt, external_handle=_handle(),
                transaction_id="job-running-transaction-command-blob",
                command_id="job-running-command-command-blob",
                recorded_at="2026-07-27T00:00:30Z",
            )
        assert command_blob.heads().global_head.global_sequence == before
    finally:
        command_blob.close()


def test_missing_effect_source_degrades_reopened_company_health(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path)
    slot = supervisor.slot_root
    try:
        queued = _queue(supervisor)
        supervisor.admit_external_job_launch(
            queued.job_id,
            transaction_id="job-launch-transaction-one",
            command_id="job-launch-command-one",
            recorded_at="2026-07-27T00:00:20Z",
        )
        _record(
            supervisor,
            queued.job_id,
            "running",
            suffix="running",
            external_handle=_handle(),
            recorded_at="2026-07-27T00:00:30Z",
        )
        receipt = _objects(
            supervisor,
            EXTERNAL_JOB_EFFECT_RECEIPT_V1,
        )[0]
        raw = cast(Mapping[str, object], receipt["raw_artifact"])
        digest = str(raw["sha256"])
        blob_path = (
            supervisor._state.blobs.root
            / digest[:2]
            / digest[2:4]
            / digest
        )
    finally:
        supervisor.close()

    blob_path.unlink()
    with CompanySupervisor.open(slot) as reopened:
        health = reopened.health()
        assert health.status == "degraded"
        assert health.blob_status == "degraded"
        assert (
            "external_job_effect_source_unavailable"
            in health.degradation_reasons
        )


def test_running_external_job_survives_chief_takeover_and_completes_once(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path)
    slot = supervisor.slot_root
    queued = _queue(supervisor, suffix="handoff")
    supervisor.admit_external_job_launch(
        queued.job_id,
        transaction_id="job-launch-transaction-handoff",
        command_id="job-launch-command-handoff",
        recorded_at="2026-07-27T00:00:20Z",
    )
    handle = _handle("handoff-991")
    _record(
        supervisor,
        queued.job_id,
        "running",
        suffix="handoff-running",
        external_handle=handle,
        recorded_at="2026-07-27T00:00:30Z",
    )
    before_job = _job(supervisor, queued.job_id)
    before_job_execution = next(
        item
        for item in _objects(supervisor, EXECUTION_NODE_V1)
        if item["execution_id"] == queued.job_execution_id
    )
    chief_execution = _chief_execution(supervisor)
    stop_transaction_id = "chief-stop-transaction-running-job-handoff"
    stop_command_id = "chief-stop-command-running-job-handoff"
    stop_receipt = _chief_stop_receipt(
        supervisor,
        execution_id=str(chief_execution["execution_id"]),
        transaction_id=stop_transaction_id,
        command_id=stop_command_id,
        recorded_at="2026-07-27T00:00:35Z",
    )
    stopped = supervisor.record_current_chief_execution_stopped(
        str(chief_execution["execution_id"]),
        stop_receipt,
        transaction_id=stop_transaction_id,
        command_id=stop_command_id,
        recorded_at="2026-07-27T00:00:35Z",
    )
    assert stopped.runtime_status == "stopped"
    assert _job(supervisor, queued.job_id) == before_job
    assert next(
        item
        for item in _objects(supervisor, EXECUTION_NODE_V1)
        if item["execution_id"] == queued.job_execution_id
    ) == before_job_execution
    before_takeover_cursor = supervisor.heads().global_head.global_sequence

    contender = _carrier(2)
    capability = supervisor.prepare_chief_takeover(
        contender,
        user_action_ref="user-action-running-job-handoff",
        objective_sha256="e" * 64,
        scope_sha256=SCOPE,
        nonce_sha256="7" * 64,
        issued_at="2026-07-27T00:00:40Z",
        expires_at="2026-07-27T01:00:00Z",
    )
    takeover = supervisor.takeover_chief(
        capability,
        contender,
        consumed_at="2026-07-27T00:00:50Z",
        grant_expires_at=EXPIRY,
    )
    assert takeover.outcome == "consumed"
    assert _job(supervisor, queued.job_id) == before_job
    after_job_execution = next(
        item
        for item in _objects(supervisor, EXECUTION_NODE_V1)
        if item["execution_id"] == queued.job_execution_id
    )
    assert after_job_execution == before_job_execution
    assert before_job["state"] == "running"
    assert (
        before_job_execution["parent_execution_id"]
        == before_job["owner_execution_id"]
    )

    takeover_events = [
        member.event
        for record in supervisor.records_after(before_takeover_cursor)
        for member in record.events
    ]
    assert all(
        event["payload"]["contract_type"]
        not in {EXTERNAL_JOB_V1, MUTATION_INTENT_V1}
        for event in takeover_events
    )
    assert all(
        not (
            event["payload"]["contract_type"] == EXECUTION_NODE_V1
            and event["payload"]["execution_id"] == queued.job_execution_id
        )
        for event in takeover_events
    )
    assert sum(
        member.event["event_type"] == "external_job.launch.admitted"
        for record in supervisor.records_after(0)
        for member in record.events
    ) == 1
    cursor = supervisor.heads().global_head.global_sequence
    supervisor.close()

    with CompanySupervisor.open(slot) as reopened:
        assert reopened._state.rebuild_projection().global_sequence == cursor
        assert _job(reopened, queued.job_id) == before_job
        assert next(
            item
            for item in _objects(reopened, EXECUTION_NODE_V1)
            if item["execution_id"] == queued.job_execution_id
        ) == before_job_execution

        transaction_id = "job-completed-transaction-handoff"
        command_id = "job-completed-command-handoff"
        source_bytes, receipt = _effect_material(
            reopened,
            queued.job_id,
            "completed",
            suffix="handoff-completed",
            transaction_id=transaction_id,
            transition_command_id=command_id,
            recorded_at="2026-07-27T00:01:00Z",
            external_handle=handle,
        )
        completed = reopened.record_external_job_state(
            queued.job_id,
            effect_source_bytes=source_bytes,
            effect_receipt=receipt,
            external_handle=handle,
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at="2026-07-27T00:01:00Z",
        )
        replay = reopened.record_external_job_state(
            queued.job_id,
            effect_source_bytes=source_bytes,
            effect_receipt=receipt,
            external_handle=handle,
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at="2026-07-27T00:01:00Z",
        )
        assert completed.job_state == "completed"
        assert not completed.idempotent_replay
        assert replay.idempotent_replay
        assert replay.global_sequence == completed.global_sequence
        completed_cursor = reopened.heads().global_head.global_sequence
        with pytest.raises(CompanyExternalJobError):
            _record(
                reopened,
                queued.job_id,
                "failed_known",
                suffix="handoff-divergent-terminal",
                external_handle=handle,
                recorded_at="2026-07-27T00:01:01Z",
            )
        assert (
            reopened.heads().global_head.global_sequence
            == completed_cursor
        )
        assert sum(
            member.event["event_type"] == "external_job.launch.admitted"
            for record in reopened.records_after(0)
            for member in record.events
        ) == 1
