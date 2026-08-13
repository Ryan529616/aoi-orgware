from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path
import sys
from typing import Any, cast

from aoi_orgware.company.contracts import (
    NEEDS_USER_REVISION_V1,
    PROVIDER_COVERAGE_REVISION_V1,
    PROVIDER_LIFECYCLE_RECEIPT_V1,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    USAGE_COUNTER_SAMPLE_V1,
    company_contract_sha256,
)
from aoi_orgware.company.views import (
    CompanyViewService,
    _provider_lifecycle_receipt_view,
)
from aoi_orgware.company.state import CompanyStateHealth


sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_views import _State, _base_objects, _projected  # type: ignore[import-not-found]
from test_telemetry_contracts import (  # type: ignore[import-not-found]
    _coverage as _contract_coverage,
    _join as _contract_join,
    _needs_user as _contract_needs_user,
    _receipt as _contract_receipt,
    _sample as _contract_sample,
)
from test_provider_lifecycle_contracts import (  # type: ignore[import-not-found]
    _receipt as _contract_lifecycle_receipt,
)


T = "2026-07-27T00:00:00Z"


def _coverage(
    *,
    provider: str,
    surface: str,
    state: str,
    reason: str,
) -> dict[str, Any]:
    value = cast(dict[str, Any], copy.deepcopy(_contract_coverage()))
    value.update({
        "coverage_scope_id": f"{provider}-{surface}",
        "coverage_surface": surface,
        "revision_id": f"{provider}-{surface}-r1",
        "provider": provider,
        "source_class": (
            "claude_hook" if provider == "claude" else "codex_app_server"
        ),
        "state": state,
        "reason": reason,
    })
    if state == "degraded":
        value.update({
            "assessment_source": "collector_health",
            "gap_started_at": "2026-07-26T23:59:59Z",
            "observation": {"state": "known", "reason": "observed"},
        })
    elif state == "unavailable":
        value.update({
            "assessment_source": "configuration",
            "observation": {"state": "unavailable", "reason": reason},
            "dropped_event_count": {
                "value": None,
                "source": "none",
                "quality": "unavailable",
                "reason": reason,
            },
        })
    value["coverage_sha256"] = company_contract_sha256({
        key: member for key, member in value.items() if key != "coverage_sha256"
    })
    return value


def _telemetry_receipt() -> dict[str, Any]:
    value = cast(dict[str, Any], copy.deepcopy(_contract_receipt()))
    value["provider_native_relation"] = {
            "kind": "thread_spawn",
            "sender_thread_id": "thread-parent-1",
            "receiver_thread_ids": ["thread-child-1"],
            "child_thread_id": "thread-child-1",
            "agent_path": None,
            "activity_kind": None,
            "native_depth": 2,
            "reason": "provider_relation_observed",
    }
    value["dispatch_join"] = _contract_join(state="exact")
    value["receipt_sha256"] = company_contract_sha256({
        key: member for key, member in value.items() if key != "receipt_sha256"
    })
    return value


def _counter_sample() -> dict[str, Any]:
    return cast(dict[str, Any], copy.deepcopy(_contract_sample()))


def _lifecycle_receipt(index: int) -> dict[str, Any]:
    value = cast(dict[str, Any], copy.deepcopy(_contract_lifecycle_receipt()))
    value.update({
        "receipt_id": f"lifecycle-receipt-{index:03d}",
        "source_event_id": f"lifecycle-event-{index:03d}",
        "dispatch_request_id": f"dispatch-{index:03d}",
        "dispatch_revision_id": f"dispatch-revision-{index:03d}",
        "dispatch_revision": index + 1,
        "execution_id": f"execution-{index:03d}",
        "carrier_id": f"carrier-{index:03d}",
        "provider_dispatch_id": f"provider-dispatch-{index:03d}",
    })
    value["raw_artifact"]["sha256"] = f"{index + 1:064x}"
    value["receipt_sha256"] = company_contract_sha256({
        key: member
        for key, member in value.items()
        if key != "receipt_sha256"
    })
    return value


def _needs_user_revision() -> dict[str, Any]:
    return cast(
        dict[str, Any],
        copy.deepcopy(_contract_needs_user(state="answered")),
    )


def _service_with_telemetry() -> CompanyViewService:
    objects = (
        *_base_objects(),
        _projected(
            PROVIDER_COVERAGE_REVISION_V1,
            "coverage-codex-lifecycle",
            _coverage(
                provider="codex",
                surface="lifecycle",
                state="observed",
                reason="observed",
            ),
        ),
        _projected(
            PROVIDER_COVERAGE_REVISION_V1,
            "coverage-claude-collector",
            _coverage(
                provider="claude",
                surface="collector",
                state="degraded",
                reason="collector_gap_open",
            ),
        ),
        _projected(
            PROVIDER_COVERAGE_REVISION_V1,
            "coverage-codex-usage",
            _coverage(
                provider="codex",
                surface="usage",
                state="unavailable",
                reason="usage_counter_not_exposed",
            ),
        ),
        _projected(
            PROVIDER_TELEMETRY_RECEIPT_V1,
            "receipt-1",
            _telemetry_receipt(),
        ),
        _projected(
            USAGE_COUNTER_SAMPLE_V1,
            "sample-1",
            _counter_sample(),
        ),
        _projected(
            NEEDS_USER_REVISION_V1,
            "needs-user-1",
            _needs_user_revision(),
        ),
    )
    return CompanyViewService(
        _State(projected=objects),
        clock=lambda: T,
    )


def test_telemetry_projection_is_conservative_and_sanitized() -> None:
    service = _service_with_telemetry()

    meta = service.section("meta")["data"]
    evidence = service.section("evidence")["data"]
    usage = service.section("usage")["data"]
    alerts = service.section("alerts")["data"]

    assert meta["coverage"]["state"] == "degraded"
    assert meta["coverage"]["reason"] == "collector_gap_open"
    assert {row["surface"] for row in meta["coverage"]["revisions"]} == {
        "collector",
        "lifecycle",
        "usage",
    }
    assert usage["coverage"]["state"] == "unavailable"
    assert usage["counting_semantics"] == "non_additive_cumulative"
    assert set(usage) == {"counting_semantics", "counter_samples", "coverage"}
    assert evidence["provider_telemetry_receipts"][0]["provider_native_relation"] == {
        "kind": "thread_spawn",
        "activity_kind": None,
        "native_depth": 2,
        "reason": "provider_relation_observed",
        "interpretation": "provider_native_only_not_aoi_lineage",
    }
    assert evidence["provider_telemetry_receipts"][0]["dispatch_join"]["state"] == "exact"
    assert alerts["needs_user"] == [{
        "source": "needs_user_revision_v1",
        "item_id": "needs-user-1",
        "state": "answered",
        "revision_id": "needs-user-1-r2",
        "revision": 2,
        "origin_execution_id": "execution-1",
        "opened_chief_term": 1,
        "question_summary": None,
        "question_summary_quality": "unavailable",
        "question_summary_reason": "summary_source_unavailable_or_invalid",
        "question_sha256": "c" * 64,
        "answer_sha256": "d" * 64,
        "created_at": T,
        "updated_at": "2026-07-27T00:00:01Z",
        "answered_at": "2026-07-27T00:00:01Z",
        "answered_by_chief_term": 2,
        "observation": {"state": "known", "reason": "observed"},
    }]

    serialized = json.dumps(service.section("snapshot"), sort_keys=True)
    for private in (
        "session-1",
        "thread-1",
        "turn-1",
        "event-occurrence-1",
        "thread-parent-1",
        "thread-child-1",
        "control-answer-1",
        "question_blob",
        "answer_blob",
        "counter_scope_id",
    ):
        assert private not in serialized
    for forbidden in ('"cost"', '"burn"', '"delta"', '"company_total"'):
        assert forbidden not in serialized


def test_absent_telemetry_coverage_remains_unknown_not_zero() -> None:
    service = CompanyViewService(_State(), clock=lambda: T)

    assert service.section("meta")["data"]["coverage"] == {
        "state": "unknown",
        "reason": "provider_adapters_not_yet_connected",
    }
    assert service.section("usage")["data"]["coverage"] == {
        "state": "unknown",
        "reason": "usage_adapter_not_yet_connected",
    }


def test_provider_lifecycle_projection_is_bounded_and_never_exports_transport_content() -> None:
    objects = [*_base_objects()]
    objects.extend(
        _projected(
            PROVIDER_LIFECYCLE_RECEIPT_V1,
            f"lifecycle-receipt-{index:03d}",
            _lifecycle_receipt(index),
            global_sequence=index + 5,
        )
        for index in range(257)
    )

    evidence = CompanyViewService(
        _State(projected=tuple(objects)),
        clock=lambda: T,
    ).section("evidence")["data"]

    receipts = evidence["provider_lifecycle_receipts"]
    assert len(receipts) == 256
    assert evidence["provider_lifecycle_receipt_summary"] == {
        "visible": 257,
        "returned": 256,
        "truncated": True,
    }
    assert receipts[0] == {
        "receipt_id": "lifecycle-receipt-256",
        "receipt_sha256": _lifecycle_receipt(256)["receipt_sha256"],
        "source_event_id": "lifecycle-event-256",
        "event_kind": "dispatch_succeeded",
        "provider": "codex",
        "dispatch_request_id": "dispatch-256",
        "dispatch_revision_id": "dispatch-revision-256",
        "dispatch_revision": 257,
        "execution_id": "execution-256",
        "carrier_id": "carrier-256",
        "provider_dispatch_id": "provider-dispatch-256",
        "reconcile_ref": None,
        "observed_at": T,
        "provenance": "adapter_receipt_persisted",
        "observation": {"state": "known", "reason": "observed"},
        "raw_artifact": {
            "availability": "available",
            "sha256": f"{257:064x}",
        },
        "ledger_cursor": 261,
    }
    assert receipts[-1]["receipt_id"] == "lifecycle-receipt-001"
    assert all(
        receipt["receipt_id"] != "lifecycle-receipt-000"
        for receipt in receipts
    )
    malicious = _lifecycle_receipt(999)
    malicious["observation"] = {
        "state": "known",
        "reason": "observed",
        "session_id": "nested-session-secret",
        "raw_content": "nested-raw-content-secret",
    }
    malicious["raw_artifact"]["raw_content"] = "artifact-content-secret"
    malicious["raw_bytes"] = "raw-bytes-secret"
    projected_malicious = _provider_lifecycle_receipt_view(malicious)
    serialized = json.dumps({
        "evidence": evidence,
        "malicious": projected_malicious,
    }, sort_keys=True)
    for secret in (
        "session-secret",
        "thread-secret",
        "raw-bytes-secret",
        "nested-session-secret",
        "nested-raw-content-secret",
        "artifact-content-secret",
    ):
        assert secret not in serialized


def test_blob_health_is_an_independent_coverage_warning() -> None:
    class _BlobDegradedState(_State):  # type: ignore[misc]
        def health(self) -> CompanyStateHealth:
            return cast(CompanyStateHealth, replace(
                super().health(),
                blob_status="degraded",
                degradation_reasons=("blob_store_verify_failed",),
            ))

    state = _BlobDegradedState(projected=(
        *_base_objects(),
        _projected(
            PROVIDER_COVERAGE_REVISION_V1,
            "coverage-codex-lifecycle",
            _coverage(
                provider="codex",
                surface="lifecycle",
                state="observed",
                reason="observed",
            ),
        ),
    ))
    coverage = CompanyViewService(state, clock=lambda: T).section("meta")["data"]["coverage"]

    assert coverage["state"] == "degraded"
    assert coverage["reason"] == "blob_store_verify_failed"
    assert coverage["provider_assessment"] == {
        "state": "observed",
        "reason": "observed",
        "source": "receipt",
        "quality": "known",
    }
    assert coverage["blob_health_warning"] == {
        "state": "degraded",
        "reason": "blob_store_verify_failed",
    }


def test_unbound_provider_receipt_is_visible_and_critical() -> None:
    receipt = _telemetry_receipt()
    receipt["dispatch_join"] = _contract_join()
    receipt["receipt_sha256"] = company_contract_sha256({
        key: member
        for key, member in receipt.items()
        if key != "receipt_sha256"
    })
    service = CompanyViewService(
        _State(projected=(
            *_base_objects(),
            _projected(
                PROVIDER_TELEMETRY_RECEIPT_V1,
                "receipt-unbound",
                receipt,
            ),
        )),
        clock=lambda: T,
    )

    snapshot = service.section("snapshot")["data"]
    assert snapshot["execution"]["orphans"] == [{
        "execution_id": "unattributed-receipt-1",
        "receipt_id": "receipt-1",
        "display_name": "Unattributed provider telemetry",
        "role": "unattributed",
        "execution_kind": "provider_telemetry",
        "engineering_status": "unknown",
        "runtime_status": "unknown",
        "orphan_reason": "provider_telemetry_unattributed",
        "projection_source": "provider_telemetry_receipt",
        "created_at": T,
        "provider": "codex",
        "objective": "thread_started",
        "observation": {"state": "known", "reason": "observed"},
    }]
    derived = [
        alert
        for alert in snapshot["alerts"]["alerts"]
        if alert["category"] == "provider_telemetry_unattributed"
    ]
    assert len(derived) == 1
    assert derived[0]["severity"] == "critical"
    assert derived[0]["state"] == "open"


def test_dashboard_has_read_only_telemetry_panels() -> None:
    html = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "aoi_orgware"
        / "resources"
        / "dashboard"
        / "index.html"
    ).read_text(encoding="utf-8")

    assert 'id="telemetry-receipts"' in html
    assert 'id="usage-samples"' in html
    assert "provider_native_relation?.kind" in html
    assert "NON-ADDITIVE CUMULATIVE — no total / no cost" in html
    assert "method: \"POST\"" not in html
    assert "receipt.session_id" not in html
    assert "sample.thread_id" not in html
