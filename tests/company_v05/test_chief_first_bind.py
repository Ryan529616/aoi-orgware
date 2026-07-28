from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from aoi_orgware.company.contracts import (
    CARRIER_BINDING_V1,
    CHIEF_TERM_V1,
    COMPANY_MANIFEST_V1,
    EXECUTION_NODE_V1,
    CompanyContractError,
    validate_carrier_binding,
)
from aoi_orgware.company.state import CompanyStateInvariantError
from aoi_orgware.company.supervisor import (
    ChiefTakeoverResult,
    CompanyChiefTakeoverError,
    CompanySupervisor,
)
from aoi_orgware.company.transactions import (
    CompanyEventDraft,
    build_company_transaction_request,
)


T = "2026-07-27T00:00:00Z"
EXPIRY = "2026-07-29T00:00:00Z"


def _manifest() -> dict[str, Any]:
    return {
        "contract_type": COMPANY_MANIFEST_V1,
        "schema_version": 1,
        "company_id": "first-bind-company",
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


def _carrier(number: int) -> dict[str, Any]:
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
        tmp_path / "s",
        _manifest(),
        bootstrap_at=T,
        grant_expires_at=EXPIRY,
        known_carrier=None,
        platform="windows" if os.name == "nt" else "posix",
    )


def _objects(
    supervisor: CompanySupervisor,
    contract_type: str,
) -> list[dict[str, Any]]:
    return [dict(item.payload) for item in supervisor.objects(contract_type=contract_type)]


def _prepare(
    supervisor: CompanySupervisor,
    carrier: dict[str, Any],
    *,
    nonce: str,
    issued_at: str = "2026-07-27T00:01:00Z",
) -> dict[str, Any]:
    return supervisor.prepare_chief_takeover(
        carrier,
        user_action_ref=f"first-bind-{nonce[0]}",
        objective_sha256="e" * 64,
        scope_sha256="f" * 64,
        nonce_sha256=nonce,
        issued_at=issued_at,
        expires_at="2026-07-27T01:00:00Z",
    )


def _consume(
    supervisor: CompanySupervisor,
    capability: dict[str, Any],
    carrier: dict[str, Any],
    *,
    consumed_at: str = "2026-07-27T00:02:00Z",
    grant_expires_at: str = EXPIRY,
) -> ChiefTakeoverResult:
    return supervisor.takeover_chief(
        capability,
        carrier,
        consumed_at=consumed_at,
        grant_expires_at=grant_expires_at,
    )


def test_unknown_genesis_first_bind_fences_only_the_deterministic_carrier(
    tmp_path: Path,
) -> None:
    with _supervisor(tmp_path) as supervisor:
        contender = _carrier(2)
        result = _consume(supervisor, _prepare(supervisor, contender, nonce="2" * 64), contender)

        assert result.outcome == "consumed"
        assert (result.term, result.epoch, result.global_sequence) == (2, 2, 2)
        term = _objects(supervisor, CHIEF_TERM_V1)
        assert [(item["term"], item["epoch"], item["carrier_id"]) for item in term] == [
            (2, 2, contender["carrier_id"]),
        ]
        carriers = {item["carrier_id"]: item for item in _objects(supervisor, CARRIER_BINDING_V1)}
        genesis = next(item for item in carriers.values() if item["provider"] == "unknown")
        assert genesis["state"] == "fenced"
        assert genesis["model"] is None and genesis["session_id"] is None
        assert genesis["session_availability"] == "unknown"
        assert genesis["bound_at"] == genesis["last_observed_at"] == T
        assert genesis["observation"] == {
            "state": "unknown",
            "reason": "provider_session_unavailable",
        }
        chief_executions = [
            item for item in _objects(supervisor, EXECUTION_NODE_V1)
            if item["role"] == "chief"
        ]
        assert [item["carrier_id"] for item in chief_executions] == [contender["carrier_id"]]
        record = next(
            item for item in supervisor.records_after(0)
            if item.request["transaction_id"] == result.transaction_id
        )
        assert all(event.event["event_type"] != "execution.authority_fenced" for event in record.events)


def test_fenced_unknown_contract_and_generic_transaction_reject_arbitrary_identity(
    tmp_path: Path,
) -> None:
    with _supervisor(tmp_path) as supervisor:
        genesis = _objects(supervisor, CARRIER_BINDING_V1)[0]
        validate_carrier_binding({**genesis, "state": "fenced"})
        arbitrary = {
            **genesis,
            "carrier_id": "arbitrary-fenced-unknown-carrier",
            "state": "fenced",
        }
        with pytest.raises(
            CompanyContractError,
            match="terminal CarrierBinding",
        ):
            validate_carrier_binding(arbitrary)
        with pytest.raises(
            (CompanyContractError, CompanyStateInvariantError),
        ):
            request = build_company_transaction_request(
                supervisor.heads(),
                supervisor._supervisor_authority(),
                transaction_id="arbitrary-fenced-unknown-transaction",
                command_id="arbitrary-fenced-unknown-command",
                events=[
                    CompanyEventDraft(
                        event_id="arbitrary-fenced-unknown-event",
                        event_type="carrier.fenced",
                        recorded_at="2026-07-27T00:01:00Z",
                        payload=arbitrary,
                        provenance="AOI_verified",
                    ),
                ],
            )
            supervisor.commit(
                request,
                recorded_at="2026-07-27T00:01:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == 1


def test_unknown_first_bind_retry_is_exact_before_and_after_reopen(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path)
    slot = supervisor.slot_root
    contender = _carrier(2)
    capability = _prepare(supervisor, contender, nonce="2" * 64)
    winner = _consume(supervisor, capability, contender)
    replay = _consume(supervisor, capability, contender)
    assert replay.idempotent_replay
    assert replay.global_sequence == winner.global_sequence == 2
    with pytest.raises(CompanyChiefTakeoverError, match="retry differs"):
        _consume(supervisor, capability, contender, consumed_at="2026-07-27T00:02:01Z")
    with pytest.raises(CompanyChiefTakeoverError, match="grant differs"):
        _consume(supervisor, capability, contender, grant_expires_at="2026-07-30T00:00:00Z")
    supervisor.close()

    with CompanySupervisor.open(slot) as reopened:
        restarted = _consume(reopened, capability, contender)
        assert restarted.idempotent_replay
        assert restarted.global_sequence == winner.global_sequence
        assert reopened.heads().global_head.global_sequence == 2


def test_unknown_first_bind_same_head_contenders_have_one_active_chief(
    tmp_path: Path,
) -> None:
    with _supervisor(tmp_path) as supervisor:
        winner_carrier = _carrier(2)
        loser_carrier = _carrier(3)
        winner_capability = _prepare(supervisor, winner_carrier, nonce="2" * 64)
        loser_capability = _prepare(supervisor, loser_carrier, nonce="3" * 64)
        assert winner_capability["expected_head_sha256"] == loser_capability["expected_head_sha256"]

        winner = _consume(supervisor, winner_capability, winner_carrier)
        loser = _consume(
            supervisor,
            loser_capability,
            loser_carrier,
            consumed_at="2026-07-27T00:03:00Z",
        )
        assert (winner.outcome, loser.outcome) == ("consumed", "fenced")
        assert supervisor.heads().global_head.global_sequence == 3
        carriers = {item["carrier_id"]: item for item in _objects(supervisor, CARRIER_BINDING_V1)}
        assert carriers[loser_carrier["carrier_id"]]["state"] == "fenced"
        active_chiefs = [
            item for item in _objects(supervisor, EXECUTION_NODE_V1)
            if item["role"] == "chief" and item["engineering_status"] == "active"
        ]
        assert [item["carrier_id"] for item in active_chiefs] == [winner_carrier["carrier_id"]]


def test_stale_unknown_first_bind_capability_fences_then_fresh_capability_binds(
    tmp_path: Path,
) -> None:
    with _supervisor(tmp_path) as supervisor:
        stale_carrier = _carrier(2)
        stale_capability = _prepare(supervisor, stale_carrier, nonce="2" * 64)
        supervisor.record_provider_coverage(
            provider="codex",
            source_class="codex_app_server",
            adapter_instance_id="first-bind-adapter",
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
            assessed_at="2026-07-27T00:01:30Z",
            transaction_id="first-bind-unrelated",
            command_id="first-bind-unrelated",
        )
        stale = _consume(supervisor, stale_capability, stale_carrier)
        assert stale.outcome == "fenced"
        carriers = {item["carrier_id"]: item for item in _objects(supervisor, CARRIER_BINDING_V1)}
        assert carriers[stale_carrier["carrier_id"]]["state"] == "fenced"

        fresh_carrier = _carrier(3)
        fresh_capability = _prepare(
            supervisor,
            fresh_carrier,
            nonce="3" * 64,
            issued_at="2026-07-27T00:03:00Z",
        )
        fresh = _consume(
            supervisor,
            fresh_capability,
            fresh_carrier,
            consumed_at="2026-07-27T00:04:00Z",
        )
        assert (fresh.outcome, fresh.term, fresh.epoch) == ("consumed", 2, 2)
