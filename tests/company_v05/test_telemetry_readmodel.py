"""Read-model coverage for raw v0.5 provider telemetry contracts.

These tests deliberately exercise projection identity only.  Lifecycle
adjacency and adapter idempotency remain Supervisor responsibilities.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any, Callable, cast

import pytest

from aoi_orgware.company.contracts import (
    EXECUTION_NODE_V1,
    NEEDS_USER_REVISION_V1,
    PROVIDER_COVERAGE_REVISION_V1,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    USAGE_COUNTER_SAMPLE_V1,
)
from aoi_orgware.company.ledger import CompanyLedger
from aoi_orgware.company.readmodel import (
    CompanyReadModel,
    ReadModelCorruptionError,
)
from aoi_orgware.company.supervisor import CompanySupervisor


_TESTS_ROOT = Path(__file__).resolve().parents[1]
_THIS_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS_ROOT))
sys.path.insert(0, str(_THIS_DIRECTORY))
from test_company_readmodel import append_payload  # type: ignore[import-not-found]
from test_telemetry_supervisor import (  # type: ignore[import-not-found]
    _carrier,
    _manifest,
    _usage,
)
from test_telemetry_contracts import (  # type: ignore[import-not-found]
    _coverage,
    _needs_user,
    _receipt,
    _rehash,
    _sample,
)


PayloadFactory = Callable[[], dict[str, Any]]


@pytest.mark.parametrize(
    ("factory", "required_stream", "wrong_stream"),
    [
        (_receipt, "evidence", "usage"),
        (_coverage, "evidence", "alert"),
        (_sample, "usage", "evidence"),
        (_needs_user, "alert", "evidence"),
    ],
    ids=(
        "telemetry-receipt",
        "coverage-revision",
        "usage-counter-sample",
        "needs-user-revision",
    ),
)
def test_telemetry_projection_specs_enforce_exact_streams(
    tmp_path: Path,
    factory: PayloadFactory,
    required_stream: str,
    wrong_stream: str,
) -> None:
    """Each raw type is admitted only on its one declared logical stream."""

    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    record = append_payload(
        ledger,
        factory(),
        tx="transaction-1",
        command="command-1",
        event_id="event-1",
        stream=wrong_stream,
    )
    model = CompanyReadModel(tmp_path / "readmodel.sqlite3")
    try:
        with pytest.raises(
            ReadModelCorruptionError,
            match=rf"belongs to {required_stream}, not {wrong_stream}",
        ):
            model.apply(record)
        assert model.head().global_sequence == 0
    finally:
        model.close()
        ledger.close()


def _coverage_revision_two(first: dict[str, Any]) -> dict[str, Any]:
    second = copy.deepcopy(first)
    second.update({
        "revision_id": "coverage-rev-2",
        "revision": 2,
        "previous_revision_sha256": first["coverage_sha256"],
    })
    _rehash(second, "coverage_sha256")
    return second


def _needs_user_revision_two(first: dict[str, Any]) -> dict[str, Any]:
    second = cast(dict[str, Any], _needs_user(state="answered"))
    second["previous_revision_sha256"] = first["revision_sha256"]
    _rehash(second, "revision_sha256")
    return second


def test_telemetry_revisions_keep_immutable_history_and_latest_current_object(
    tmp_path: Path,
) -> None:
    """Revisioned coverage and needs-user records replace current, not history."""

    supervisor = CompanySupervisor.initialize(
        tmp_path / "source",
        _manifest(),
        bootstrap_at="2026-07-27T00:00:00Z",
        grant_expires_at="2026-07-28T00:00:00Z",
        known_carrier=_carrier(),
        platform="windows" if sys.platform == "win32" else "posix",
    )
    try:
        coverage_one = supervisor.record_provider_coverage(
            provider="codex",
            source_class="codex_app_server",
            adapter_instance_id="adapter-history",
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
        coverage_two = supervisor.record_provider_coverage(
            provider="codex",
            source_class="codex_app_server",
            adapter_instance_id="adapter-history",
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
        root_execution = next(
            item
            for item in supervisor.objects(contract_type=EXECUTION_NODE_V1)
            if item.payload["parent_execution_id"] is None
        )
        needs_one = supervisor.open_needs_user(
            "continue?",
            item_id="needs-user-history",
            origin_execution_id=str(root_execution.payload["execution_id"]),
            expected_chief_term=1,
            expected_carrier_id="carrier-1",
            transaction_id="tx-needs-1",
            command_id="cmd-needs-1",
            created_at="2026-07-27T00:00:03Z",
        )
        needs_two = supervisor.expire_needs_user(
            "needs-user-history",
            expected_chief_term=1,
            expected_carrier_id="carrier-1",
            transaction_id="tx-needs-2",
            command_id="cmd-needs-2",
            expired_at="2026-07-27T00:00:04Z",
        )
        records = supervisor.records_after(0, limit=32)
    finally:
        supervisor.close()
    model = CompanyReadModel(tmp_path / "readmodel.sqlite3")
    try:
        assert model.apply_many(records) == len(records)
        coverage = model.object(
            PROVIDER_COVERAGE_REVISION_V1,
            coverage_two.coverage_scope_id,
        )
        needs_user = model.object(
            NEEDS_USER_REVISION_V1,
            needs_two.item_id,
        )
        assert coverage is not None
        assert needs_user is not None
        assert coverage.record_id == coverage_two.revision_id
        assert coverage.payload["revision"] == 2
        assert needs_user.record_id == needs_two.revision_id
        assert needs_user.payload["state"] == "expired"
        with sqlite3.connect(model.path) as connection:
            coverage_history = connection.execute(
                "SELECT record_id FROM projected_events "
                "WHERE contract_type=? ORDER BY global_sequence",
                (PROVIDER_COVERAGE_REVISION_V1,),
            ).fetchall()
            needs_history = connection.execute(
                "SELECT record_id FROM projected_events "
                "WHERE contract_type=? ORDER BY global_sequence",
                (NEEDS_USER_REVISION_V1,),
            ).fetchall()
        assert coverage_history == [
            (coverage_one.revision_id,),
            (coverage_two.revision_id,),
        ]
        assert needs_history == [
            (needs_one.revision_id,),
            (needs_two.revision_id,),
        ]
    finally:
        model.close()


def test_telemetry_projection_rebuild_matches_current_cursor_and_objects(
    tmp_path: Path,
) -> None:
    """All raw telemetry projections survive deterministic ledger replay."""

    supervisor = CompanySupervisor.initialize(
        tmp_path / "source",
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
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "tokenUsage": _usage(),
                },
            },
            separators=(",", ":"),
        ).encode()
        supervisor.ingest_codex_telemetry(
            raw,
            adapter_instance_id="adapter-rebuild",
            adapter_event_id="event-rebuild-1",
            intake_sequence=1,
            transaction_id="tx-telemetry-1",
            command_id="cmd-telemetry-1",
            received_at="2026-07-27T00:00:01Z",
        )
        status = json.dumps(
            {
                "method": "thread/status/changed",
                "params": {
                    "threadId": "thread-1",
                    "status": {"type": "idle"},
                },
            },
            separators=(",", ":"),
        ).encode()
        supervisor.ingest_codex_telemetry(
            status,
            adapter_instance_id="adapter-rebuild",
            adapter_event_id="event-rebuild-2",
            intake_sequence=2,
            transaction_id="tx-telemetry-2",
            command_id="cmd-telemetry-2",
            received_at="2026-07-27T00:00:02Z",
        )
        root_execution = next(
            item
            for item in supervisor.objects(contract_type=EXECUTION_NODE_V1)
            if item.payload["parent_execution_id"] is None
        )
        supervisor.open_needs_user(
            "inspect telemetry?",
            item_id="needs-user-rebuild",
            origin_execution_id=str(root_execution.payload["execution_id"]),
            expected_chief_term=1,
            expected_carrier_id="carrier-1",
            transaction_id="tx-needs-rebuild",
            command_id="cmd-needs-rebuild",
            created_at="2026-07-27T00:00:03Z",
        )
        records = supervisor.records_after(0, limit=32)
    finally:
        supervisor.close()
    model = CompanyReadModel(tmp_path / "readmodel.sqlite3")
    rebuilt_path = tmp_path / "rebuilt.sqlite3"
    rebuilt: CompanyReadModel | None = None
    try:
        assert model.apply_many(records) == len(records)
        rebuilt_head = CompanyReadModel.rebuild(rebuilt_path, records)
        rebuilt = CompanyReadModel(rebuilt_path)
        assert rebuilt_head == model.head()
        assert rebuilt.head() == model.head()
        assert rebuilt.objects() == model.objects()
        projected_types = {
            item.contract_type for item in rebuilt.objects()
        }
        assert {
            PROVIDER_TELEMETRY_RECEIPT_V1,
            PROVIDER_COVERAGE_REVISION_V1,
            USAGE_COUNTER_SAMPLE_V1,
            NEEDS_USER_REVISION_V1,
        }.issubset(projected_types)
    finally:
        if rebuilt is not None:
            rebuilt.close()
        model.close()
