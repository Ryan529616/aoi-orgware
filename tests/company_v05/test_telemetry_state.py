from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, cast

import pytest

from aoi_orgware.company.contracts import (
    NEEDS_USER_QUESTION_MEDIA_TYPE,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.state import CompanyStateInvariantError
from aoi_orgware.company.supervisor import CompanySupervisor
from aoi_orgware.company.transactions import (
    CompanyEventDraft,
    build_company_transaction_request,
)

from test_state import (  # type: ignore[import-not-found]
    T,
    authority,
    bootstrap,
    initialized,
)
from test_telemetry_contracts import _needs_user  # type: ignore[import-not-found]
from test_telemetry_supervisor import (  # type: ignore[import-not-found]
    _carrier,
    _manifest,
)


def _rehash(value: dict[str, object], field: str) -> None:
    value[field] = company_contract_sha256(
        {key: member for key, member in value.items() if key != field},
    )


def _request(
    owner: Any,
    payload: dict[str, object],
    *,
    tx: str,
    cmd: str,
) -> dict[str, object]:
    return build_company_transaction_request(
        owner.heads(), authority(), transaction_id=tx, command_id=cmd,
        events=(CompanyEventDraft(
            event_id=f"event-{tx}", event_type="telemetry.recorded",
            recorded_at=T, payload=payload,
        ),),
    )


def test_telemetry_raw_receipt_replays_and_rejects_divergence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = CompanySupervisor.initialize(
        tmp_path / "state",
        _manifest(),
        bootstrap_at=T,
        grant_expires_at="2026-07-28T00:00:00Z",
        known_carrier=_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    )
    try:
        raw = json.dumps(
            {
                "method": "thread/started",
                "params": {"thread": {"id": "thread-1"}},
            },
            separators=(",", ":"),
        ).encode()
        first = supervisor.ingest_codex_telemetry(
            raw,
            adapter_instance_id="adapter-1",
            adapter_event_id="event-1",
            intake_sequence=1,
            transaction_id="tx-telemetry",
            command_id="cmd-telemetry",
            received_at="2026-07-27T00:00:01Z",
        )
        replay = supervisor.ingest_codex_telemetry(
            raw,
            adapter_instance_id="adapter-1",
            adapter_event_id="event-1",
            intake_sequence=1,
            transaction_id="tx-telemetry",
            command_id="cmd-telemetry",
            received_at="2026-07-27T00:00:01Z",
        )
        assert replay.receipt_id == first.receipt_id
        assert replay.idempotent_replay
        assert not any(
            reason.startswith("provider_telemetry_raw_")
            for reason in supervisor.health().degradation_reasons
        )

        bad_raw = json.dumps(
            {
                "method": "thread/status/changed",
                "params": {
                    "threadId": "thread-2",
                    "status": {"type": "idle"},
                },
            },
            separators=(",", ":"),
        ).encode()
        captured: dict[str, Any] = {}

        def capture(request: dict[str, Any], **_kwargs: Any) -> Any:
            captured["request"] = request
            raise RuntimeError("captured telemetry request")

        with monkeypatch.context() as context:
            context.setattr(supervisor, "commit", capture)
            with pytest.raises(
                RuntimeError,
                match="captured telemetry request",
            ):
                supervisor.ingest_codex_telemetry(
                    bad_raw,
                    adapter_instance_id="adapter-2",
                    adapter_event_id="event-2",
                    intake_sequence=1,
                    transaction_id="tx-bad",
                    command_id="cmd-bad",
                    received_at="2026-07-27T00:00:02Z",
                )
        captured_request = cast(dict[str, Any], captured["request"])
        drafts: list[CompanyEventDraft] = []
        for wrapper in captured_request["events"]:
            payload = copy.deepcopy(wrapper["payload"])
            if payload["contract_type"] == PROVIDER_TELEMETRY_RECEIPT_V1:
                payload["facts"]["actual_model"]["reason"] = (
                    "forged_missing_reason"
                )
                _rehash(payload, "receipt_sha256")
            drafts.append(CompanyEventDraft(
                str(wrapper["event_id"]),
                str(wrapper["event_type"]),
                str(wrapper["recorded_at"]),
                payload,
                str(wrapper["provenance"]),
            ))
        bad_request = build_company_transaction_request(
            supervisor.heads(),
            supervisor._supervisor_authority(),
            transaction_id="tx-bad",
            command_id="cmd-bad",
            events=drafts,
        )
        cursor = supervisor.heads().global_head.global_sequence
        with pytest.raises(CompanyStateInvariantError, match="differs"):
            supervisor.commit(
                bad_request,
                recorded_at="2026-07-27T00:00:02Z",
            )
        assert supervisor.heads().global_head.global_sequence == cursor
    finally:
        supervisor.close()


def test_needs_user_question_blob_is_preappend_bound_and_health_visible(tmp_path: object) -> None:
    owner = initialized(tmp_path)
    try:
        bootstrap(owner)
        raw = canonical_company_json_bytes(
            {"schema_version": 1, "content_type": "question", "text": "continue?"},
        )
        reference = owner.blobs.put(raw)
        revision = _needs_user()
        revision["question_blob"].update({"sha256": reference.sha256, "size_bytes": reference.size_bytes, "media_type": NEEDS_USER_QUESTION_MEDIA_TYPE})
        revision["question_sha256"] = reference.sha256
        _rehash(revision, "revision_sha256")
        owner.commit(_request(owner, revision, tx="tx-question", cmd="cmd-question"))
        owner.blobs.path_for_digest(reference.sha256).unlink()
        assert "needs_user_question_unavailable" in owner.health().degradation_reasons
    finally:
        owner.close()
