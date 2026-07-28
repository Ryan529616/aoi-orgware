"""Exact historical Command Center projections stay outside company state."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, cast
import urllib.error
import urllib.request

import pytest

from aoi_orgware.company.contracts import COMPANY_MANIFEST_V1
from aoi_orgware.company.supervisor import CompanySupervisor
from aoi_orgware.company.views import CompanyViewService


T = "2026-07-27T00:00:00Z"
EXPIRY = "2026-07-28T00:00:00Z"


def _manifest() -> dict[str, object]:
    return {
        "contract_type": COMPANY_MANIFEST_V1,
        "schema_version": 1,
        "company_id": "company-history-1",
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


def _carrier(number: int) -> dict[str, object]:
    return {
        "carrier_id": f"carrier-history-{number}",
        "provider": "codex" if number == 1 else "claude",
        "model": "gpt-5",
        "session_id": f"session-history-{number}",
        "thread_id": f"thread-history-{number}",
        "provenance": "agent_reported",
        "observation": {"state": "known", "reason": "observed"},
    }


def _request(url: str) -> tuple[int, dict[str, Any]]:
    try:
        response = urllib.request.urlopen(url, timeout=3)
    except urllib.error.HTTPError as exc:
        return exc.code, cast(dict[str, Any], json.loads(exc.read()))
    with response:
        return response.status, cast(dict[str, Any], json.loads(response.read()))


def _state_digest_tree(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        # The live process lock is intentionally held by the Supervisor and
        # cannot be read on Windows.  It is not ledger/read-model state.
        if path.is_file() and path.name != "company.lock"
    }


def _historical_company(
    supervisor: CompanySupervisor,
    cursor: int,
) -> dict[str, Any]:
    url = supervisor.dashboard_url
    assert url is not None
    status, payload = _request(url + f"api/v1/snapshot?cursor={cursor}")
    assert status == 200, payload
    return payload


def _queue_job(supervisor: CompanySupervisor) -> None:
    owner = next(
        item.payload
        for item in supervisor.objects(contract_type="execution_node_v1")
        if item.payload["execution_kind"] == "carrier"
        and item.payload["engineering_status"] == "active"
    )
    supervisor.queue_external_job(
        str(owner["execution_id"]),
        job_id="job-history-1",
        job_execution_id="job-execution-history-1",
        mutation_intent_id="mutation-history-1",
        command_bytes=b'{"tool":"vcs"}',
        command_media_type="application/json",
        scope_sha256="f" * 64,
        display_name="History VCS job",
        objective="Keep the external job visible at historical cursors.",
        authority_grant_id="job-grant-history-1",
        grant_expires_at=EXPIRY,
        transaction_id="job-transaction-history-1",
        command_id="job-command-history-1",
        recorded_at="2026-07-27T00:00:10Z",
    )


def test_dashboard_historical_snapshot_replays_handoff_and_job_without_mutation(
    tmp_path: Path,
) -> None:
    slot = tmp_path / "company-history"
    supervisor = CompanySupervisor.initialize(
        slot,
        _manifest(),
        bootstrap_at=T,
        grant_expires_at=EXPIRY,
        platform="windows" if os.name == "nt" else "posix",
        known_carrier=_carrier(1),
    )
    try:
        supervisor.start_dashboard()
        before_handoff = supervisor.heads().global_head.global_sequence
        capability = supervisor.prepare_chief_takeover(
            _carrier(2),
            user_action_ref="user-action/history-handoff",
            objective_sha256="e" * 64,
            scope_sha256="f" * 64,
            nonce_sha256="1" * 64,
            issued_at="2026-07-27T00:00:01Z",
            expires_at="2026-07-27T01:00:00Z",
        )
        supervisor.takeover_chief(
            capability,
            _carrier(2),
            consumed_at="2026-07-27T00:00:02Z",
            grant_expires_at=EXPIRY,
        )
        after_handoff = supervisor.heads().global_head.global_sequence
        _queue_job(supervisor)
        after_job = supervisor.heads().global_head.global_sequence

        current_before = CompanyViewService(supervisor._state).section("snapshot")
        state_before = _state_digest_tree(slot)
        before = _historical_company(supervisor, before_handoff)
        handoff = _historical_company(supervisor, after_handoff)
        job = _historical_company(supervisor, after_job)
        state_after = _state_digest_tree(slot)
        current_after = CompanyViewService(supervisor._state).section("snapshot")

        assert before["cursor"] == before_handoff
        assert handoff["cursor"] == after_handoff
        assert job["cursor"] == after_job
        assert before["data"]["company"]["chief"]["carrier"]["carrier_id"] == _carrier(1)["carrier_id"]
        assert handoff["data"]["company"]["chief"]["carrier"]["carrier_id"] == _carrier(2)["carrier_id"]
        assert before["data"]["jobs"] == []
        assert handoff["data"]["jobs"] == []
        assert [item["job_id"] for item in job["data"]["jobs"]] == [
            "job-history-1",
        ]
        assert before["data"]["meta"]["ledger"]["cursor"] == before_handoff
        assert handoff["data"]["meta"]["ledger"]["cursor"] == after_handoff
        assert job["data"]["meta"]["ledger"]["cursor"] == after_job
        assert {
            key: value
            for key, value in current_before.items()
            if key != "generated_at"
        } == {
            key: value
            for key, value in current_after.items()
            if key != "generated_at"
        }
        assert state_before == state_after
    finally:
        supervisor.close()

    reopened = CompanySupervisor.open(slot)
    try:
        reopened.start_dashboard()
        replayed = _historical_company(reopened, after_handoff)
        assert replayed["cursor"] == after_handoff
        assert replayed["data"]["company"]["chief"]["carrier"]["carrier_id"] == _carrier(2)["carrier_id"]
        assert replayed["data"]["jobs"] == []
    finally:
        reopened.close()


@pytest.mark.parametrize("query", ("abc", "-1", "1&cursor=2"))
def test_dashboard_historical_snapshot_rejects_malformed_cursor(
    tmp_path: Path,
    query: str,
) -> None:
    supervisor = CompanySupervisor.initialize(
        tmp_path / "company-history-invalid",
        _manifest(),
        bootstrap_at=T,
        grant_expires_at=EXPIRY,
        platform="windows" if os.name == "nt" else "posix",
        known_carrier=_carrier(1),
    )
    try:
        url = supervisor.start_dashboard()
        status, payload = _request(url + f"api/v1/snapshot?cursor={query}")
        assert status == 400
        assert payload["error"] == "invalid_cursor"

        head = supervisor.heads().global_head.global_sequence
        status, payload = _request(url + f"api/v1/snapshot?cursor={head + 1}")
        assert status == 409
        assert payload["error"] == "historical_projection_unavailable"

        status, payload = _request(url + "api/v1/snapshot?cursor=0")
        assert status == 409
        assert payload["error"] == "historical_projection_unavailable"
    finally:
        supervisor.close()
