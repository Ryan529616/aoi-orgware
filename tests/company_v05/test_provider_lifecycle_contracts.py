from __future__ import annotations

import copy
from typing import Any

import pytest

from aoi_orgware.company.contracts import (
    BLOB_REF_V1,
    MAX_PROVIDER_LIFECYCLE_SOURCE_BYTES,
    PROVIDER_LIFECYCLE_RECEIPT_V1,
    PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE,
    PROVIDER_LIFECYCLE_SOURCE_V1,
    CompanyContractError,
    canonical_company_json_bytes,
    company_contract_sha256,
    validate_company_contract,
    validate_provider_lifecycle_receipt,
    validate_provider_lifecycle_source,
)


T = "2026-07-27T00:00:00Z"


def _source(
    *,
    event_kind: str = "dispatch_succeeded",
) -> dict[str, Any]:
    known_runtime = event_kind in {
        "dispatch_succeeded",
        "execution_stopped",
    }
    return {
        "source_type": PROVIDER_LIFECYCLE_SOURCE_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "source_event_id": f"source-{event_kind}",
        "event_kind": event_kind,
        "dispatch_request_id": "dispatch-1",
        "provider_dispatch_id": "provider-dispatch-1" if known_runtime else None,
        "execution_id": "execution-1" if known_runtime else None,
        "carrier_id": "carrier-1" if known_runtime else None,
        "organization_node_id": "rtl-lead",
        "provider": "codex",
        "model": "gpt-5",
        "effort": "high",
        "session_id": "session-1" if known_runtime else None,
        "thread_id": "thread-1" if known_runtime else None,
        "reconcile_ref": (
            "reconcile-1"
            if event_kind == "dispatch_effect_unknown"
            else None
        ),
        "observed_at": T,
        "provenance": "adapter_receipt_persisted",
        "observation": (
            {"state": "partial", "reason": "collector_lag"}
            if event_kind == "dispatch_effect_unknown"
            else {"state": "known", "reason": "observed"}
        ),
    }


def _receipt(
    *,
    event_kind: str = "dispatch_succeeded",
) -> dict[str, Any]:
    source = _source(event_kind=event_kind)
    source_bytes = canonical_company_json_bytes(source)
    value = {
        "contract_type": PROVIDER_LIFECYCLE_RECEIPT_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "receipt_id": f"receipt-{event_kind}",
        "source_event_id": source["source_event_id"],
        "event_kind": event_kind,
        "transaction_id": "transaction-1",
        "command_id": "command-1",
        "dispatch_request_id": "dispatch-1",
        "dispatch_revision_id": "dispatch-revision-4",
        "dispatch_revision": 4,
        "provider_dispatch_id": source["provider_dispatch_id"],
        "execution_id": source["execution_id"],
        "carrier_id": source["carrier_id"],
        "organization_node_id": source["organization_node_id"],
        "provider": source["provider"],
        "model": source["model"],
        "effort": source["effort"],
        "session_id": source["session_id"],
        "thread_id": source["thread_id"],
        "reconcile_ref": source["reconcile_ref"],
        "observed_at": T,
        "provenance": source["provenance"],
        "observation": source["observation"],
        "raw_artifact": {
            "contract_type": BLOB_REF_V1,
            "schema_version": 1,
            "sha256": company_contract_sha256(source),
            "size_bytes": len(source_bytes),
            "media_type": PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE,
            "availability": "available",
        },
        "receipt_sha256": "0" * 64,
    }
    value["receipt_sha256"] = company_contract_sha256({
        key: member
        for key, member in value.items()
        if key != "receipt_sha256"
    })
    return value


def _rehash(value: dict[str, Any]) -> None:
    value["receipt_sha256"] = company_contract_sha256({
        key: member
        for key, member in value.items()
        if key != "receipt_sha256"
    })


def test_provider_source_and_receipt_round_trip_exact_contracts() -> None:
    source = _source()
    receipt = _receipt()
    assert validate_provider_lifecycle_source(source) == source
    assert validate_provider_lifecycle_receipt(receipt) == receipt
    assert validate_company_contract(receipt) == receipt


def test_provider_root_execution_stop_requires_exact_nullable_lineage() -> None:
    source = _source(event_kind="execution_stopped")
    dispatched_receipt = _receipt(event_kind="execution_stopped")
    assert validate_provider_lifecycle_source(source) == source
    assert (
        validate_provider_lifecycle_receipt(dispatched_receipt)
        == dispatched_receipt
    )
    source["dispatch_request_id"] = None
    source["provider_dispatch_id"] = None
    assert validate_provider_lifecycle_source(source) == source

    receipt = _receipt(event_kind="execution_stopped")
    receipt["dispatch_request_id"] = None
    receipt["dispatch_revision_id"] = None
    receipt["dispatch_revision"] = None
    receipt["provider_dispatch_id"] = None
    source_bytes = canonical_company_json_bytes(source)
    receipt["raw_artifact"]["sha256"] = company_contract_sha256(source)
    receipt["raw_artifact"]["size_bytes"] = len(source_bytes)
    _rehash(receipt)
    assert validate_provider_lifecycle_receipt(receipt) == receipt

    partial_source = copy.deepcopy(source)
    partial_source["provider_dispatch_id"] = "provider-dispatch-partial"
    with pytest.raises(CompanyContractError, match="exact root or dispatch"):
        validate_provider_lifecycle_source(partial_source)

    partial_receipt = copy.deepcopy(receipt)
    partial_receipt["dispatch_request_id"] = "dispatch-partial"
    _rehash(partial_receipt)
    with pytest.raises(CompanyContractError, match="exact root or dispatch"):
        validate_provider_lifecycle_receipt(partial_receipt)


@pytest.mark.parametrize(
    "event_kind",
    ["dispatch_failed", "dispatch_effect_unknown"],
)
def test_non_runtime_provider_identity_is_rejected_consistently(
    event_kind: str,
) -> None:
    source = _source(event_kind=event_kind)
    source["provider_dispatch_id"] = "ambiguous-provider-dispatch"
    with pytest.raises(CompanyContractError, match="runtime identity"):
        validate_provider_lifecycle_source(source)

    receipt = _receipt(event_kind=event_kind)
    receipt["provider_dispatch_id"] = "ambiguous-provider-dispatch"
    _rehash(receipt)
    with pytest.raises(CompanyContractError, match="runtime identity"):
        validate_provider_lifecycle_receipt(receipt)


def test_provider_receipt_rejects_oversize_wrong_media_and_hash_drift() -> None:
    oversized = _receipt()
    oversized["raw_artifact"]["size_bytes"] = (
        MAX_PROVIDER_LIFECYCLE_SOURCE_BYTES + 1
    )
    _rehash(oversized)
    with pytest.raises(CompanyContractError, match="raw artifact"):
        validate_provider_lifecycle_receipt(oversized)

    wrong_media = _receipt()
    wrong_media["raw_artifact"]["media_type"] = "application/json"
    _rehash(wrong_media)
    with pytest.raises(CompanyContractError, match="raw artifact"):
        validate_provider_lifecycle_receipt(wrong_media)

    drifted = copy.deepcopy(_receipt())
    drifted["dispatch_revision_id"] = "different-revision"
    with pytest.raises(CompanyContractError, match="receipt_sha256 differs"):
        validate_provider_lifecycle_receipt(drifted)


def test_provider_receipt_rejects_self_asserted_aoi_verification() -> None:
    receipt = _receipt()
    receipt["provenance"] = "AOI_verified"
    _rehash(receipt)
    with pytest.raises(CompanyContractError, match="provider grade"):
        validate_provider_lifecycle_receipt(receipt)
