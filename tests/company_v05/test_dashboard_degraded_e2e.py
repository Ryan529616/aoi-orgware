"""End-to-end coverage for degraded provider-lifecycle evidence."""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from aoi_orgware.company.blobs import BlobStore
from aoi_orgware.company.contracts import (
    BLOB_REF_V1,
    COMPANY_MANIFEST_V1,
    DEPARTMENT_IDENTITY_V1,
    DEPARTMENT_SNAPSHOT_V1,
    DISPATCH_REQUEST_V1,
    MAX_PROVIDER_LIFECYCLE_SOURCE_BYTES,
    PROVIDER_LIFECYCLE_RECEIPT_V1,
    PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE,
    PROVIDER_LIFECYCLE_SOURCE_V1,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.dashboard import (
    CompanyDashboardServer,
    CompanyDashboardSnapshotCache,
)
from aoi_orgware.company.state import CompanyStateError
from aoi_orgware.company.supervisor import CompanySupervisor
from aoi_orgware.company.views import CompanyViewService


T = "2026-07-27T00:00:00Z"
EXPIRY = "2026-07-28T00:00:00Z"
REASON = "provider_lifecycle_evidence_unavailable"


def _manifest() -> dict[str, Any]:
    return {
        "contract_type": COMPANY_MANIFEST_V1,
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


def _known_carrier() -> dict[str, Any]:
    return {
        "carrier_id": "carrier-1",
        "provider": "codex",
        "model": "gpt-5",
        "session_id": "session-1",
        "thread_id": "thread-1",
        "provenance": "agent_reported",
        "observation": {"state": "known", "reason": "observed"},
    }


def _objects(
    supervisor: CompanySupervisor,
    contract_type: str,
) -> list[dict[str, Any]]:
    return [dict(item.payload) for item in supervisor.objects(contract_type=contract_type)]


def _blob_store(slot: Path) -> BlobStore:
    roots = list((slot / "incarnations").glob("*/blobs"))
    assert len(roots) == 1
    return BlobStore(roots[0])


def _dispatch_success_receipt(
    supervisor: CompanySupervisor,
    store: BlobStore,
) -> tuple[dict[str, Any], str]:
    dispatch = _objects(supervisor, DISPATCH_REQUEST_V1)[0]
    transaction_id = "success-transaction"
    command_id = "success-command"
    carrier_id = "rtl-carrier-1"
    execution_id = "department-lead-execution-" + company_contract_sha256({
        "dispatch_request_id": dispatch["dispatch_request_id"],
        "transaction_id": transaction_id,
        "carrier_id": carrier_id,
    })
    dispatch_revision_id = "department-dispatch-revision-" + company_contract_sha256({
        "company_id": dispatch["company_id"],
        "company_incarnation": dispatch["company_incarnation"],
        "lock_domain_generation": dispatch["lock_domain_generation"],
        "dispatch_request_id": dispatch["dispatch_request_id"],
        "previous_revision": dispatch["revision"],
        "target_state": "dispatched",
        "transaction_id": transaction_id,
        "command_id": command_id,
    })
    source: dict[str, Any] = {
        "source_type": PROVIDER_LIFECYCLE_SOURCE_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "source_event_id": "provider-event-success",
        "event_kind": "dispatch_succeeded",
        "dispatch_request_id": dispatch["dispatch_request_id"],
        "provider_dispatch_id": "provider-dispatch-rtl-1",
        "execution_id": execution_id,
        "carrier_id": carrier_id,
        "organization_node_id": dispatch["target_node_id"],
        "provider": "codex",
        "model": "gpt-5",
        "effort": "high",
        "session_id": "rtl-session-1",
        "thread_id": "rtl-thread-1",
        "reconcile_ref": None,
        "observed_at": "2026-07-27T00:05:00Z",
        "provenance": "adapter_receipt_persisted",
        "observation": {"state": "known", "reason": "observed"},
    }
    raw_source = canonical_company_json_bytes(source)
    assert len(raw_source) <= MAX_PROVIDER_LIFECYCLE_SOURCE_BYTES
    artifact = store.put(raw_source)
    receipt: dict[str, Any] = {
        "contract_type": PROVIDER_LIFECYCLE_RECEIPT_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "receipt_id": "provider-receipt-success",
        "source_event_id": source["source_event_id"],
        "event_kind": source["event_kind"],
        "transaction_id": transaction_id,
        "command_id": command_id,
        "dispatch_request_id": dispatch["dispatch_request_id"],
        "dispatch_revision_id": dispatch_revision_id,
        "dispatch_revision": int(dispatch["revision"]) + 1,
        "provider_dispatch_id": source["provider_dispatch_id"],
        "execution_id": execution_id,
        "carrier_id": carrier_id,
        "organization_node_id": source["organization_node_id"],
        "provider": source["provider"],
        "model": source["model"],
        "effort": source["effort"],
        "session_id": source["session_id"],
        "thread_id": source["thread_id"],
        "reconcile_ref": None,
        "observed_at": source["observed_at"],
        "provenance": source["provenance"],
        "observation": source["observation"],
        "raw_artifact": {
            "contract_type": BLOB_REF_V1,
            "schema_version": 1,
            "sha256": artifact.sha256,
            "size_bytes": artifact.size_bytes,
            "media_type": PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE,
            "availability": "available",
        },
        "receipt_sha256": "0" * 64,
    }
    receipt["receipt_sha256"] = company_contract_sha256({
        key: value for key, value in receipt.items() if key != "receipt_sha256"
    })
    return receipt, artifact.sha256


def _get_json(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=3) as response:
        assert response.status == 200
        value = json.loads(response.read())
    assert isinstance(value, dict)
    return value


def test_missing_provider_lifecycle_artifact_degrades_dashboard_after_reopen(
    tmp_path: Path,
) -> None:
    slot = tmp_path / "state" / "companies" / "company-1"
    supervisor = CompanySupervisor.initialize(
        slot,
        _manifest(),
        bootstrap_at=T,
        grant_expires_at=EXPIRY,
        known_carrier=_known_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    )
    try:
        department_id = next(
            item["department_id"]
            for item in _objects(supervisor, DEPARTMENT_IDENTITY_V1)
            if item["name"] == "RTL"
        )
        supervisor.resume_department(
            department_id,
            transaction_id="resume-transaction",
            command_id="resume-command",
            requested_at="2026-07-27T00:01:00Z",
            recorded_at="2026-07-27T00:02:00Z",
            dispatch_request_id="rtl-dispatch",
            reservation_id="rtl-reservation",
            task_id="rtl-task",
            packet_id="rtl-packet",
            route_policy_id="rtl-route",
            requested_role="rtl_lead",
            requested_capability_tier="standard",
        )
        supervisor.admit_department_dispatch(
            "rtl-dispatch",
            transaction_id="admit-transaction",
            command_id="admit-command",
            recorded_at="2026-07-27T00:03:00Z",
        )
        supervisor.begin_department_dispatch(
            "rtl-dispatch",
            transaction_id="begin-transaction",
            command_id="begin-command",
            recorded_at="2026-07-27T00:04:00Z",
        )
        receipt, raw_digest = _dispatch_success_receipt(
            supervisor,
            _blob_store(slot),
        )
        supervisor.dispatch_department_lead(
            "rtl-dispatch",
            receipt,
            transaction_id="success-transaction",
            command_id="success-command",
            recorded_at="2026-07-27T00:05:00Z",
        )
    finally:
        supervisor.close()

    store = _blob_store(slot)
    artifact_path = store.path_for_digest(raw_digest)
    assert artifact_path.is_file()
    assert artifact_path.parent.parent.parent == store.root
    artifact_path.unlink()

    with CompanySupervisor.open(slot) as reopened:
        health = reopened.health()
        assert health.status == "degraded"
        assert health.blob_status == "degraded"
        assert REASON in health.degradation_reasons

        view = CompanyViewService(reopened._state)
        snapshot = view.section("snapshot")
        assert snapshot["completeness"] == "partial"
        assert REASON in snapshot["warnings"]
        assert snapshot["data"]["meta"]["coverage"]["state"] == "degraded"

        cache = CompanyDashboardSnapshotCache(view)
        cache.refresh()
        cached = cache.section("snapshot")
        assert cached["completeness"] == snapshot["completeness"]
        assert cached["warnings"] == snapshot["warnings"]
        with CompanyDashboardServer(cache) as server:
            served = _get_json(server.url + "api/v1/snapshot")
            assert served["completeness"] == snapshot["completeness"]
            assert served["warnings"] == snapshot["warnings"]
            with urllib.request.urlopen(server.url, timeout=3) as response:
                asset = response.read()
        assert b'id="warnings" role="alert"' in asset
        assert "觀測不完整".encode() in asset


@pytest.mark.parametrize(
    ("lost_ref", "error"),
    [
        ("document", "department snapshot document cannot be verified"),
        ("member", "department snapshot member cannot be verified"),
    ],
)
def test_snapshot_blob_loss_hard_fails_reopen(
    tmp_path: Path,
    lost_ref: str,
    error: str,
) -> None:
    slot = tmp_path / "state" / "companies" / "company-1"
    with CompanySupervisor.initialize(
        slot,
        _manifest(),
        bootstrap_at=T,
        grant_expires_at=EXPIRY,
        known_carrier=_known_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    ) as supervisor:
        snapshot = _objects(supervisor, DEPARTMENT_SNAPSHOT_V1)[0]
        document_ref = dict(snapshot["artifact_refs"][0])
        document = json.loads(
            _blob_store(slot).read(str(document_ref["sha256"])),
        )
        digest = (
            str(document_ref["sha256"])
            if lost_ref == "document"
            else str(document["charter_ref"]["sha256"])
        )

    store = _blob_store(slot)
    blob_path = store.path_for_digest(digest)
    assert blob_path.is_file()
    assert blob_path.parent.parent.parent == store.root
    blob_path.unlink()

    with pytest.raises(CompanyStateError, match=error):
        CompanySupervisor.open(slot)
