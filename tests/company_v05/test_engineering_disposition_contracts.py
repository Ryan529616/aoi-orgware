from __future__ import annotations

import copy
from typing import Any

import pytest

from aoi_orgware.company.contracts import (
    BLOB_REF_V1,
    ENGINEERING_DISPOSITION_RECEIPT_V1,
    ENGINEERING_DISPOSITION_SOURCE_MEDIA_TYPE,
    ENGINEERING_DISPOSITION_SOURCE_V1,
    CompanyContractError,
    canonical_company_json_bytes,
    company_contract_sha256,
    validate_engineering_disposition_receipt,
    validate_engineering_disposition_source,
)


def _source() -> dict[str, Any]:
    return {
        "source_type": ENGINEERING_DISPOSITION_SOURCE_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "source_event_id": "engineering-source-1",
        "receipt_id": "engineering-receipt-1",
        "execution_id": "execution-1",
        "expected_execution_payload_sha256": "e" * 64,
        "reporter_execution_id": "execution-1",
        "reporter_carrier_id": "carrier-1",
        "provider": "codex",
        "session_id": "session-1",
        "thread_id": "thread-1",
        "from_status": "active",
        "to_status": "idle",
        "reason_code": "handoff_ready",
        "result_packet_id": "packet-1",
        "observed_at": "2026-07-27T00:01:00Z",
        "provenance": "agent_reported",
        "observation": {"state": "known", "reason": "observed"},
    }


def _receipt() -> tuple[bytes, dict[str, Any]]:
    source = _source()
    source_bytes = canonical_company_json_bytes(source)
    unsigned = {
        "contract_type": ENGINEERING_DISPOSITION_RECEIPT_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        **{
            key: source[key]
            for key in source
            if key not in {
                "source_type",
                "schema_version",
                "company_id",
                "company_incarnation",
                "lock_domain_generation",
            }
        },
        "transaction_id": "engineering-transaction-1",
        "command_id": "engineering-command-1",
        "raw_artifact": {
            "contract_type": BLOB_REF_V1,
            "schema_version": 1,
            "sha256": company_contract_sha256(source),
            "size_bytes": len(source_bytes),
            "media_type": ENGINEERING_DISPOSITION_SOURCE_MEDIA_TYPE,
            "availability": "available",
        },
    }
    return source_bytes, {
        **unsigned,
        "receipt_sha256": company_contract_sha256(unsigned),
    }


def _rehash(receipt: dict[str, Any]) -> None:
    receipt["receipt_sha256"] = company_contract_sha256({
        key: value
        for key, value in receipt.items()
        if key != "receipt_sha256"
    })


def test_engineering_disposition_source_and_receipt_are_strict() -> None:
    source_bytes, receipt = _receipt()
    assert canonical_company_json_bytes(
        validate_engineering_disposition_source(_source()),
    ) == source_bytes
    assert validate_engineering_disposition_receipt(receipt) == receipt


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("reporter_execution_id", "execution-2"),
        ("provider", "unknown"),
        ("from_status", "idle"),
        ("to_status", "completed"),
        ("reason_code", "invented"),
        ("provenance", "AOI_verified"),
        ("observation", {"state": "unknown", "reason": "silence"}),
    ),
)
def test_engineering_disposition_receipt_rejects_false_attribution(
    field: str,
    value: object,
) -> None:
    _source_bytes, receipt = _receipt()
    receipt[field] = value
    _rehash(receipt)
    with pytest.raises(CompanyContractError):
        validate_engineering_disposition_receipt(receipt)


def test_engineering_disposition_receipt_rejects_artifact_and_hash_drift(
) -> None:
    _source_bytes, receipt = _receipt()
    wrong_media = copy.deepcopy(receipt)
    wrong_media["raw_artifact"]["media_type"] = "application/json"
    _rehash(wrong_media)
    with pytest.raises(CompanyContractError):
        validate_engineering_disposition_receipt(wrong_media)

    wrong_hash = copy.deepcopy(receipt)
    wrong_hash["receipt_sha256"] = "f" * 64
    with pytest.raises(CompanyContractError):
        validate_engineering_disposition_receipt(wrong_hash)


def test_engineering_disposition_contract_rejects_schema_drift() -> None:
    source = _source()
    source["extra"] = "not-allowed"
    with pytest.raises(CompanyContractError):
        validate_engineering_disposition_source(source)

    _source_bytes, receipt = _receipt()
    receipt.pop("thread_id")
    with pytest.raises(CompanyContractError):
        validate_engineering_disposition_receipt(receipt)
