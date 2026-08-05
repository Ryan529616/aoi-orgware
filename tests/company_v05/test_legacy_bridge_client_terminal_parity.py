from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from aoi_orgware.company import legacy_bridge_client as client
from aoi_orgware.company import legacy_bridge_client_receipt_contract as contract
from aoi_orgware.company import legacy_bridge_client_receipts as receipts
from aoi_orgware.company.contracts import company_contract_sha256
from aoi_orgware.company.legacy_bridge_control_protocol import (
    build_legacy_bridge_prestart_query,
    decode_legacy_bridge_prestart_wire_result,
)
from aoi_orgware.company.legacy_bridge_ingest_protocol import (
    decode_legacy_bridge_ingest_wire_result,
)
from aoi_orgware.company.legacy_bridge import normalize_legacy_bridge_snapshot
from aoi_orgware.company.service import CompanyServiceOperationError
from tests.company_v05.test_legacy_bridge_client import (
    Services,
    _descriptor,
    _run,
)
from tests.company_v05.test_legacy_bridge_client_receipt_contract import (
    T0,
    _ingest_command,
    _post_result,
    _prepared,
    _query_result,
    _reseal,
)


def _validated_inputs() -> tuple[bytes, dict[str, Any]]:
    source, raw_prepared = _prepared()
    return source, contract.validate_prepared(raw_prepared, source)


def _query_observation(
    source: bytes,
    prepared: dict[str, Any],
    *,
    service_instance_id: str = "resident-1",
    cursor: int = 7,
) -> client._QueryObservation:
    command = build_legacy_bridge_prestart_query(
        service_instance_id=service_instance_id,
        company_id=prepared["company_id"],
        company_incarnation=prepared["company_incarnation"],
        lock_domain_generation=prepared["lock_domain_generation"],
        manifest_sha256=prepared["manifest_sha256"],
        bridge_scope_id=prepared["bridge_scope_id"],
        source_document=source,
    )
    raw = _query_result(source, prepared)
    raw["service_instance_id"] = service_instance_id
    raw["cursor"] = cursor
    gate = cast(dict[str, Any], raw["gate"])
    for name in (
        "ledger_cursor", "readmodel_cursor", "coverage_global_sequence",
        "observation_global_sequence",
    ):
        gate[name] = cursor
    unsigned = {name: value for name, value in gate.items() if name != "gate_sha256"}
    gate["gate_sha256"] = company_contract_sha256({
        "domain": "aoi.legacy-bridge.prestart-gate.v1",
        **unsigned,
    })
    result = decode_legacy_bridge_prestart_wire_result(raw, command=command)
    return client._QueryObservation(result, result.service_instance_id, None)


def _success_terminal(source: bytes, prepared: dict[str, Any]) -> dict[str, Any]:
    result = decode_legacy_bridge_ingest_wire_result(
        _post_result(source, prepared),
        command=_ingest_command(source, prepared),
    )
    return client._terminal_receipt(
        prepared=prepared,
        source=source,
        post_kind="success",
        post_code=None,
        post_status=None,
        post_cursor=result.global_sequence,
        post_effect="committed",
        wire_result=result,
        query=_query_observation(source, prepared),
        effect="committed",
        exit_code=0,
        terminal_at=T0,
    )


def test_committed_operation_error_cannot_be_resealed_as_no_effect() -> None:
    source, prepared = _validated_inputs()
    terminal = client._terminal_receipt(
        prepared=prepared,
        source=source,
        post_kind="operation_error",
        post_code="service_binding_mismatch",
        post_status=409,
        post_cursor=None,
        post_effect="none",
        wire_result=None,
        query=client._QueryObservation(None, None, "synthetic_unavailable"),
        effect="none",
        exit_code=2,
        terminal_at=T0,
    )
    contract.validate_terminal(terminal, prepared, source)
    forged = dict(terminal)
    forged.update({
        "post_code": "committed_dashboard_refresh_failed",
        "post_status": 500,
    })

    with pytest.raises(contract.ReceiptContractError, match="post_mismatch"):
        contract.validate_terminal(
            _reseal(receipts.TERMINAL_SCHEMA, forged),
            prepared,
            source,
        )


@pytest.mark.parametrize(
    ("field", "replacement", "reason"),
    [
        ("post_cursor", 8, "post_mismatch"),
        ("gate_cursor", 8, "gate_mismatch"),
        ("gate_sha256", "0" * 64, "gate_mismatch"),
    ],
)
def test_terminal_witnesses_bind_writer_fields(
    field: str,
    replacement: object,
    reason: str,
) -> None:
    source, prepared = _validated_inputs()
    terminal = _success_terminal(source, prepared)
    contract.validate_terminal(terminal, prepared, source)
    forged = dict(terminal)
    forged[field] = replacement

    with pytest.raises(contract.ReceiptContractError, match=reason):
        contract.validate_terminal(
            _reseal(receipts.TERMINAL_SCHEMA, forged),
            prepared,
            source,
        )


def test_reconciliation_gate_fields_bind_full_query_witness() -> None:
    source, prepared = _validated_inputs()
    terminal = client._terminal_receipt(
        prepared=prepared,
        source=source,
        post_kind="transport_or_decode_error",
        post_code="effect_unknown",
        post_status=None,
        post_cursor=None,
        post_effect="effect_unknown",
        wire_result=None,
        query=client._QueryObservation(None, "resident-1", "synthetic_unavailable"),
        effect="effect_unknown",
        exit_code=3,
        terminal_at=T0,
    )
    terminal = contract.validate_terminal(terminal, prepared, source)
    query_result = _query_result(source, prepared)
    gate = cast(dict[str, Any], query_result["gate"])
    reconciliation = receipts.seal(receipts.RECONCILIATION_SCHEMA, {
        "prepared_receipt_sha256": prepared["receipt_sha256"],
        "terminal_receipt_sha256": terminal["receipt_sha256"],
        "attempt_id": prepared["attempt_id"],
        "query_result": query_result,
        "query_service_instance_id": "resident-1",
        "gate_decision": "satisfied",
        "gate_reason": "current_structural_ingest_observed",
        "gate_cursor": 7,
        "gate_sha256": gate["gate_sha256"],
        "effect": "committed",
        "exit_code": 0,
        "reconciled_at": T0,
    })
    contract.validate_reconciliation(reconciliation, prepared, terminal, source)
    forged = dict(reconciliation)
    forged["gate_cursor"] = 8

    with pytest.raises(
        contract.ReceiptContractError,
        match="reconciliation_receipt_gate_mismatch",
    ):
        contract.validate_reconciliation(
            _reseal(receipts.RECONCILIATION_SCHEMA, forged),
            prepared,
            terminal,
            source,
        )


def test_reconciliation_survives_resident_carrier_reopen(tmp_path: Path) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    services.ingest_error = CompanyServiceOperationError(
        504,
        "effect_unknown",
        effect="effect_unknown",
    )
    services.query_reason = "current_source_not_observed"

    first = _run(tmp_path, services, [])
    services.descriptors[0] = _descriptor("resident-2")
    services.ingest_error = None
    services.query_reason = "current_structural_ingest_observed"
    second = _run(tmp_path, services, [])

    assert (first.effect, first.exit_code) == ("effect_unknown", 3)
    assert (second.effect, second.exit_code) == ("committed", 0)
    assert second.reconciliation_receipt_sha256 is not None
    assert services.ingest_calls == 1
    assert services.query_calls == 2


def test_terminal_rejects_committed_query_older_than_post() -> None:
    source, prepared = _validated_inputs()
    result = decode_legacy_bridge_ingest_wire_result(
        _post_result(source, prepared),
        command=_ingest_command(source, prepared),
    )

    with pytest.raises(contract.ReceiptContractError, match="cursor_regression"):
        client._terminal_receipt(
            prepared=prepared,
            source=source,
            post_kind="success",
            post_code=None,
            post_status=None,
            post_cursor=result.global_sequence,
            post_effect="committed",
            wire_result=result,
            query=_query_observation(source, prepared, cursor=6),
            effect="committed",
            exit_code=0,
            terminal_at=T0,
        )


@pytest.mark.parametrize(
    ("cursor", "reconciled_at"),
    [
        (6, "2026-08-05T08:00:03Z"),
        (7, "2026-08-05T08:00:01Z"),
    ],
)
def test_reconciliation_rejects_cursor_or_time_regression(
    cursor: int,
    reconciled_at: str,
) -> None:
    source, prepared = _validated_inputs()
    result = decode_legacy_bridge_ingest_wire_result(
        _post_result(source, prepared),
        command=_ingest_command(source, prepared),
    )
    terminal = client._terminal_receipt(
        prepared=prepared,
        source=source,
        post_kind="success",
        post_code=None,
        post_status=None,
        post_cursor=result.global_sequence,
        post_effect="committed",
        wire_result=result,
        query=client._QueryObservation(None, "resident-1", "synthetic_unavailable"),
        effect="effect_unknown",
        exit_code=3,
        terminal_at="2026-08-05T08:00:02Z",
    )
    attempt = client._Attempt(
        source,
        normalize_legacy_bridge_snapshot(source),
        prepared,
        terminal,
        None,
    )

    with pytest.raises(contract.ReceiptContractError, match="monotonicity_mismatch"):
        client._reconciliation_receipt(
            attempt,
            _query_observation(source, prepared, cursor=cursor),
            "committed",
            0,
            reconciled_at,
        )


def test_effect_unknown_operation_error_uses_generic_code(tmp_path: Path) -> None:
    source, prepared = _validated_inputs()
    with pytest.raises(contract.ReceiptContractError, match="post_mismatch"):
        client._terminal_receipt(
            prepared=prepared,
            source=source,
            post_kind="operation_error",
            post_code="service_binding_mismatch",
            post_status=418,
            post_cursor=9,
            post_effect="effect_unknown",
            wire_result=None,
            query=client._QueryObservation(None, None, "synthetic_unavailable"),
            effect="effect_unknown",
            exit_code=3,
            terminal_at=T0,
        )

    slot = tmp_path / "company"
    slot.mkdir()
    services = Services(slot)
    services.ingest_error = CompanyServiceOperationError(
        418,
        "service_binding_mismatch",
        effect="effect_unknown",
        cursor=9,
    )
    services.query_error = RuntimeError("synthetic unavailable")
    result = _run(tmp_path, services, [])
    scope_root = slot / "cv1" / "lb" / result.bridge_scope_id[:32]
    terminal = receipts.inventory(scope_root, result.bridge_scope_id).attempts[0].terminal

    assert terminal is not None
    assert terminal["post_code"] == "effect_unknown"
    assert terminal["post_status"] == 418
    assert terminal["post_cursor"] == 9


def test_huge_json_integer_has_stable_client_error() -> None:
    raw = b'{"value":' + (b"9" * 10_000) + b"}"

    with pytest.raises(receipts.LegacyBridgeClientError, match="invalid_client_receipt_json"):
        receipts._parse_json(raw)
