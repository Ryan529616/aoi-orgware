"""AOI-SYNTHETIC-FIXTURE-V1 tests for pure acceptance history parity."""
from __future__ import annotations

from pathlib import Path
import sys
from typing import Any, Mapping

import pytest

from aoi_orgware.company.contracts import (
    DISPATCH_REQUEST_V1,
    EXECUTION_NODE_V1,
    company_contract_sha256,
)
from aoi_orgware.company.invariants import InvariantObject
from aoi_orgware.company.latency.acceptance_history import (
    AcceptanceHistoryError,
    select_current_execution,
    timestamp_precedes,
    validate_dispatch_history,
    validate_execution_history,
    validate_execution_predecessor_pair,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_work_dispatch_result as work_result  # type: ignore[import-not-found]


def _item(
    contract_type: str,
    object_key: str,
    event_id: str,
    sequence: int,
    payload: dict[str, Any],
) -> InvariantObject:
    return InvariantObject(
        contract_type,
        object_key,
        event_id,
        sequence,
        company_contract_sha256(payload),
        payload,
    )


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(member) for key, member in value.items()}
    if isinstance(value, (tuple, list)):
        return [_thaw(member) for member in value]
    return value


def _history(
    supervisor: Any,
    contract_type: str,
    object_key: str,
) -> tuple[InvariantObject, ...]:
    identity_field = {
        DISPATCH_REQUEST_V1: "dispatch_request_id",
        EXECUTION_NODE_V1: "execution_id",
    }[contract_type]
    result: list[InvariantObject] = []
    for record in supervisor.records_after(0, limit=128):
        for event in record.events:
            payload = event.event.get("payload")
            if (
                isinstance(payload, Mapping)
                and payload.get("contract_type") == contract_type
                and payload.get(identity_field) == object_key
            ):
                result.append(
                    _item(
                        contract_type,
                        object_key,
                        str(event.event["event_id"]),
                        record.global_sequence,
                        _thaw(payload),
                    )
                )
    return tuple(result)


def test_dispatch_history_matches_real_supervisor_lifecycle(tmp_path: Path) -> None:
    """A real queued-to-dispatched Supervisor sequence is accepted verbatim."""
    supervisor, _, _, _, _, _ = work_result._registered_stopped_execution(tmp_path)
    try:
        history = _history(supervisor, DISPATCH_REQUEST_V1, "registered-dispatch")
        checked = validate_dispatch_history(history, "registered-dispatch")
        assert [entry.payload["state"] for entry in checked] == [
            "queued",
            "admitted",
            "in_flight",
            "dispatched",
        ]
        assert validate_dispatch_history(tuple(reversed(history)), "registered-dispatch") == checked
    finally:
        supervisor.close()


def test_dispatch_history_rejects_transition_identity_and_predecessor_drift(tmp_path: Path) -> None:
    supervisor, _, _, _, _, _ = work_result._registered_stopped_execution(tmp_path)
    try:
        history = _history(supervisor, DISPATCH_REQUEST_V1, "registered-dispatch")

        def changed(index: int, **updates: Any) -> InvariantObject:
            raw = _thaw(history[index].payload)
            raw.update(updates)
            return _item(
                DISPATCH_REQUEST_V1,
                "registered-dispatch",
                history[index].event_id,
                history[index].global_sequence,
                raw,
            )

        invalid_histories = (
            (history[0], changed(1, state="queued", attempt=0)),
            (history[0], changed(1, state="in_flight", attempt=1)),
            (history[0], changed(1, revision=3)),
            (history[0], changed(1, dispatch_revision_id=history[0].payload["dispatch_revision_id"])),
            (history[0], changed(1, command_id=history[0].payload["command_id"])),
            (history[0], changed(1, previous_event_id="other-predecessor")),
            (history[0], changed(1, previous_payload_sha256="0" * 64)),
            (history[0], history[0]),
        )
        for invalid in invalid_histories:
            with pytest.raises(AcceptanceHistoryError):
                validate_dispatch_history(invalid, "registered-dispatch")
    finally:
        supervisor.close()


def test_execution_history_selects_current_and_rejects_parity_drift(tmp_path: Path) -> None:
    supervisor, _, _, execution_id, _, _ = work_result._registered_stopped_execution(tmp_path)
    try:
        history = _history(supervisor, EXECUTION_NODE_V1, execution_id)
        checked = validate_execution_history(history, execution_id)
        assert checked[-1].item == history[-1]
        values = [(item, _thaw(item.payload)) for item in reversed(history)]
        assert select_current_execution(values, execution_id).item == history[-1]
        assert validate_execution_predecessor_pair(history[-2], history[-1])[1].item == history[-1]

        duplicate_cursor = _item(
            EXECUTION_NODE_V1,
            execution_id,
            "synthetic-duplicate-cursor",
            history[-1].global_sequence,
            _thaw(history[-1].payload),
        )
        changed_identity = _thaw(history[-1].payload)
        changed_identity["role"] = "synthetic-other-role"
        changed_identity_item = _item(
            EXECUTION_NODE_V1,
            execution_id,
            "synthetic-identity-drift",
            history[-1].global_sequence + 1,
            changed_identity,
        )
        reused_event_item = _item(
            EXECUTION_NODE_V1,
            execution_id,
            history[-1].event_id,
            history[-1].global_sequence + 1,
            changed_identity,
        )
        for invalid in (
            (*history, duplicate_cursor),
            (*history[:-1], changed_identity_item),
            (*history, reused_event_item),
        ):
            with pytest.raises(AcceptanceHistoryError):
                validate_execution_history(tuple(invalid), execution_id)
        assert validate_execution_history(
            (history[-1], history[-2]), execution_id,
        ) == checked
    finally:
        supervisor.close()


def test_timestamp_comparison_is_timezone_aware_and_fail_closed() -> None:
    assert timestamp_precedes("2026-07-27T00:00:00Z", "2026-07-27T08:00:01+08:00")
    assert not timestamp_precedes("2026-07-27T08:00:01+08:00", "2026-07-27T00:00:00Z")
    with pytest.raises(AcceptanceHistoryError, match="timezone"):
        timestamp_precedes("2026-07-27T00:00:00", "2026-07-27T00:00:01Z")
