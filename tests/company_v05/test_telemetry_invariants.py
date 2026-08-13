"""Logical identity tests for raw provider telemetry invariant reduction."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
from typing import Any, Callable

import pytest

from aoi_orgware.company.contracts import (
    NEEDS_USER_REVISION_V1,
    PROVIDER_COVERAGE_REVISION_V1,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    USAGE_COUNTER_SAMPLE_V1,
)
from aoi_orgware.company.invariants import (
    CompanyInvariantError,
    InvariantTransition,
    reduce_company_invariants,
)
from aoi_orgware.company.supervisor import CompanySupervisor


_TESTS_ROOT = Path(__file__).resolve().parents[1]
_THIS_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS_ROOT))
sys.path.insert(0, str(_THIS_DIRECTORY))
from test_company_readmodel import request  # type: ignore[import-not-found]
from test_telemetry_supervisor import (  # type: ignore[import-not-found]
    _carrier,
    _manifest,
    _usage,
)
from test_telemetry_contracts import (  # type: ignore[import-not-found]
    _needs_user,
    _rehash,
    _sample,
)


PayloadFactory = Callable[[], dict[str, Any]]


def _transition(
    payload: dict[str, Any],
    *,
    transaction_id: str,
    command_id: str,
    event_id: str,
    stream: str,
) -> InvariantTransition:
    return InvariantTransition(
        request(
            payload,
            tx=transaction_id,
            command=command_id,
            event_id=event_id,
            stream=stream,
        ),
        "committed",
    )


@pytest.mark.parametrize(
    ("factory", "contract_type", "stream", "identity"),
    [
        (_needs_user, NEEDS_USER_REVISION_V1, "alert", "needs-user-1"),
    ],
    ids=("needs-user",),
)
def test_raw_telemetry_transition_uses_contract_logical_identity(
    factory: PayloadFactory,
    contract_type: str,
    stream: str,
    identity: str,
) -> None:
    """Transition-produced current state never uses its ledger event ID as key."""

    projection = reduce_company_invariants(
        [],
        [],
        _transition(
            factory(),
            transaction_id="tx-1",
            command_id="cmd-1",
            event_id="ledger-event-1",
            stream=stream,
        ),
    )
    records = [
        item for item in projection.objects if item.contract_type == contract_type
    ]
    assert len(records) == 1
    assert records[0].object_key == identity
    assert records[0].event_id == "ledger-event-1"


def test_orphan_usage_sample_is_rejected_by_reducer_and_replay() -> None:
    with pytest.raises(
        CompanyInvariantError,
        match="requires a same-transaction provider telemetry receipt",
    ):
        reduce_company_invariants(
            [],
            [],
            _transition(
                _sample(),
                transaction_id="tx-orphan-usage",
                command_id="cmd-orphan-usage",
                event_id="event-orphan-usage",
                stream="usage",
            ),
        )


def test_authoritative_provider_telemetry_uses_contract_logical_identity(
    tmp_path: Path,
) -> None:
    """Atomic provider telemetry keys each member by its contract identity."""

    supervisor = CompanySupervisor.initialize(
        tmp_path / "authoritative",
        _manifest(),
        bootstrap_at="2026-07-27T00:00:00Z",
        grant_expires_at="2026-07-28T00:00:00Z",
        known_carrier=_carrier(),
        platform="windows" if sys.platform == "win32" else "posix",
    )
    try:
        raw = json.dumps(
            {
                "method": "thread/tokenUsage/updated",
                "params": {
                    "threadId": "foreign-thread",
                    "turnId": "foreign-turn",
                    "tokenUsage": _usage(),
                },
            },
            separators=(",", ":"),
        ).encode()
        supervisor.ingest_codex_telemetry(
            raw,
            adapter_instance_id="adapter-identity",
            adapter_event_id="event-identity",
            intake_sequence=1,
            transaction_id="tx-identity",
            command_id="cmd-identity",
            received_at="2026-07-27T00:00:01Z",
        )
        record = supervisor.records_after(1, limit=1)[0]
        projection = reduce_company_invariants(
            [],
            [],
            InvariantTransition(record.request, "committed"),
        )
        identity_fields = {
            PROVIDER_TELEMETRY_RECEIPT_V1: "receipt_id",
            PROVIDER_COVERAGE_REVISION_V1: "coverage_scope_id",
            USAGE_COUNTER_SAMPLE_V1: "sample_id",
        }
        for event in record.events:
            payload = event.event["payload"]
            contract_type = str(payload["contract_type"])
            if contract_type not in identity_fields:
                continue
            logical_id = str(payload[identity_fields[contract_type]])
            matches = [
                item
                for item in projection.objects
                if (
                    item.contract_type == contract_type
                    and item.object_key == logical_id
                )
            ]
            assert len(matches) == 1
            assert matches[0].event_id == event.event["event_id"]
    finally:
        supervisor.close()


def test_coverage_and_needs_user_replay_replace_current_by_logical_identity(
    tmp_path: Path,
) -> None:
    """A committed successor replaces current state while preserving event ancestry."""

    supervisor = CompanySupervisor.initialize(
        tmp_path / "coverage",
        _manifest(),
        bootstrap_at="2026-07-27T00:00:00Z",
        grant_expires_at="2026-07-28T00:00:00Z",
        known_carrier=_carrier(),
        platform="windows" if sys.platform == "win32" else "posix",
    )
    try:
        first_result = supervisor.record_provider_coverage(
            provider="codex",
            source_class="codex_app_server",
            adapter_instance_id="adapter-coverage",
            coverage_surface="lifecycle",
            declared_event_kinds=["thread_started"],
            state="unknown",
            reason="adapter_health_unknown",
            assessment_source="adapter_health",
            dropped_event_count={
                "value": None,
                "source": "none",
                "quality": "unavailable",
                "reason": "adapter_health_unknown",
            },
            assessed_at="2026-07-27T00:00:01Z",
            transaction_id="tx-coverage-1",
            command_id="cmd-coverage-1",
        )
        second_result = supervisor.record_provider_coverage(
            provider="codex",
            source_class="codex_app_server",
            adapter_instance_id="adapter-coverage",
            coverage_surface="lifecycle",
            declared_event_kinds=["thread_started"],
            state="unknown",
            reason="adapter_health_still_unknown",
            assessment_source="adapter_health",
            dropped_event_count={
                "value": None,
                "source": "none",
                "quality": "unavailable",
                "reason": "adapter_health_still_unknown",
            },
            assessed_at="2026-07-27T00:00:02Z",
            transaction_id="tx-coverage-2",
            command_id="cmd-coverage-2",
        )
        records = supervisor.records_after(1, limit=2)
        first = reduce_company_invariants(
            [],
            [],
            InvariantTransition(records[0].request, "committed"),
        )
        second = reduce_company_invariants(
            first.objects,
            [],
            InvariantTransition(records[1].request, "committed"),
        )
    finally:
        supervisor.close()
    coverage = [
        item for item in second.objects
        if item.contract_type == PROVIDER_COVERAGE_REVISION_V1
    ]
    assert len(coverage) == 1
    assert (coverage[0].object_key, coverage[0].event_id) == (
        second_result.coverage_scope_id,
        records[1].events[0].event["event_id"],
    )
    assert coverage[0].payload["revision_id"] == second_result.revision_id
    assert coverage[0].payload["revision"] == 2
    assert first_result.revision == 1

    needs_one = _needs_user()
    needs_two = _needs_user(state="answered")
    needs_two["previous_revision_sha256"] = needs_one["revision_sha256"]
    _rehash(needs_two, "revision_sha256")
    pending = reduce_company_invariants(
        [],
        [],
        _transition(
            needs_one,
            transaction_id="tx-3",
            command_id="cmd-3",
            event_id="needs-event-1",
            stream="alert",
        ),
    )
    answered = reduce_company_invariants(
        pending.objects,
        [],
        _transition(
            needs_two,
            transaction_id="tx-4",
            command_id="cmd-4",
            event_id="needs-event-2",
            stream="alert",
        ),
    )
    needs = [
        item for item in answered.objects
        if item.contract_type == NEEDS_USER_REVISION_V1
    ]
    assert len(needs) == 1
    assert (needs[0].object_key, needs[0].event_id, needs[0].payload["state"]) == (
        "needs-user-1", "needs-event-2", "answered",
    )
