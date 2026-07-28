from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from typing import Any

import pytest

from aoi_orgware.company.dashboard import (
    CompanyDashboardBusyError,
    CompanyDashboardError,
    CompanyDashboardResetRequiredError,
    CompanyDashboardServer,
    CompanyDashboardSnapshotCache,
)


class _ReplayInput:
    def __init__(self, cursor: int) -> None:
        self.records = tuple(range(cursor))


class _View:
    def __init__(self, *, cursor: int = 3) -> None:
        self.cursor = cursor

    @staticmethod
    def _section_data(name: str) -> Any:
        if name == "execution":
            return {
                "nodes": [
                    {
                        "execution_id": "execution-chief",
                        "engineering_status": "active",
                        "runtime_status": "running",
                    },
                ],
                "events": [],
            }
        if name == "company":
            return {
                "manifest": {"display_name": "Local company"},
                "capacity": {
                    "occupied": 0,
                    "occupied_semantics": "exact",
                    "limit": 16,
                    "available": 16,
                },
                "chief": {
                    "term": {
                        "chief_id": "chief-1",
                        "term": 2,
                        "epoch": 2,
                        "state": "active",
                    },
                    "carrier": {
                        "carrier_id": "carrier-current",
                        "provider": "provider",
                    },
                    "authority_grants": [
                        {"effective_state": "active"},
                    ],
                    "takeover_attempts": [
                        {"outcome": "consumed"},
                    ],
                    "fenced_carriers": [],
                },
            }
        if name == "export":
            return {
                "state": "unavailable",
                "sanitized": False,
                "reason": "sanitized_export_not_implemented",
                "snapshot": None,
            }
        return {"section": name}

    def section(self, name: str) -> dict[str, Any]:
        if name == "snapshot":
            sections = (
                "meta",
                "company",
                "departments",
                "execution",
                "jobs",
                "evidence",
                "usage",
                "work",
                "optimizer",
                "alerts",
                "export",
            )
            data: Any = {
                section: self._section_data(section)
                for section in sections
            }
        else:
            data = self._section_data(name)
        return {
            "schema_version": 1,
            "company_id": "company-1",
            "cursor": self.cursor,
            "generated_at": "2026-07-27T00:00:00Z",
            "completeness": "complete",
            "warnings": [],
            "data": data,
        }

    def events_after(
        self,
        cursor: int,
        *,
        limit: int = 256,
    ) -> tuple[dict[str, Any], ...]:
        assert limit <= 256
        if cursor >= self.cursor:
            return ()
        return tuple(
            {
                "cursor": value,
                "transaction_id": f"transaction-{value}",
                "events": [],
            }
            for value in range(cursor + 1, self.cursor + 1)
        )[:limit]

    def historical_replay_input(self) -> object:
        return _ReplayInput(self.cursor)

    def snapshot_from_replay(
        self,
        replay: object,
        cursor: int,
    ) -> dict[str, Any]:
        del replay, cursor
        raise ValueError("historical projection is unavailable")

    def snapshot_at(self, cursor: int) -> dict[str, Any]:
        return self.snapshot_from_replay(
            self.historical_replay_input(),
            cursor,
        )


def _cache(
    view: _View | None = None,
    *,
    max_cached_events: int = 4096,
) -> CompanyDashboardSnapshotCache:
    result = CompanyDashboardSnapshotCache(
        view or _View(),
        max_cached_events=max_cached_events,
    )
    result.refresh()
    return result


class _GapView(_View):
    def events_after(
        self,
        cursor: int,
        *,
        limit: int = 256,
    ) -> tuple[dict[str, Any], ...]:
        del cursor, limit
        return (
            {
                "cursor": 2,
                "transaction_id": "transaction-2",
                "events": [],
            },
        )


class _AvailableExportView(_View):
    def section(self, name: str) -> dict[str, Any]:
        result = super().section(name)
        summary = {
            "state": "available",
            "sanitized": True,
            "reason": None,
            "export_id": "export-1",
            "export_sha256": "a" * 64,
            "generated_at": "2026-07-27T00:00:00Z",
            "verified_at": "2026-07-27T00:00:00Z",
            "cursor": self.cursor,
            "head_sha256": "b" * 64,
            "checkpoint_manifest_sha256": "c" * 64,
            "current": True,
            "checkpoint": {
                "state": "verified",
                "reason": None,
                "checkpoint_id": "checkpoint-1",
                "cursor": self.cursor,
                "head_sha256": "b" * 64,
                "manifest_sha256": "c" * 64,
                "generated_at": "2026-07-27T00:00:00Z",
                "verified_at": "2026-07-27T00:00:00Z",
                "current": True,
            },
            "redaction": {
                "class": "operational",
                "security_boundary": False,
                "warning": "operational_redaction_not_security_boundary",
            },
            "snapshot": None,
        }
        if name == "snapshot":
            result["data"]["export"] = summary
        elif name == "export":
            result["data"] = {
                **summary,
                "snapshot": {
                    "schema_version": 1,
                    "ledger": {"cursor": self.cursor},
                    "snapshot": {"execution": {"nodes": []}},
                },
            }
        return result


class _OwnerBoundSnapshotView(_View):
    def __init__(self) -> None:
        super().__init__()
        self.owner_thread_id = threading.get_ident()
        self.call_thread_ids: list[int] = []

    def _assert_owner(self) -> None:
        thread_id = threading.get_ident()
        self.call_thread_ids.append(thread_id)
        assert thread_id == self.owner_thread_id

    def section(self, name: str) -> dict[str, Any]:
        self._assert_owner()
        return super().section(name)

    def events_after(
        self,
        cursor: int,
        *,
        limit: int = 256,
    ) -> tuple[dict[str, Any], ...]:
        self._assert_owner()
        return super().events_after(cursor, limit=limit)


class _HistoricalView(_View):
    def __init__(self, *, cursor: int = 3) -> None:
        super().__init__(cursor=cursor)
        self.replay_freezes = 0
        self.active_replays = 0
        self.peak_active_replays = 0
        self.replay_started = threading.Event()
        self.allow_replay = threading.Event()
        self.block_replay = False
        self.failure: BaseException | None = None

    def historical_replay_input(self) -> object:
        self.replay_freezes += 1
        return _ReplayInput(self.cursor)

    def snapshot_from_replay(
        self,
        replay: object,
        cursor: int,
    ) -> dict[str, Any]:
        del replay
        if self.failure is not None:
            raise self.failure
        self.active_replays += 1
        self.peak_active_replays = max(
            self.peak_active_replays,
            self.active_replays,
        )
        self.replay_started.set()
        try:
            if self.block_replay:
                assert self.allow_replay.wait(timeout=5.0)
            result = super().section("snapshot")
            result["cursor"] = cursor
            return result
        finally:
            self.active_replays -= 1


def _request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(
        url,
        method=method,
        headers=headers or {},
    )
    try:
        response = urllib.request.urlopen(request, timeout=3)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read()
    with response:
        return response.status, dict(response.headers.items()), response.read()


def test_loopback_dashboard_serves_asset_and_versioned_sections() -> None:
    with CompanyDashboardServer(_cache()) as server:
        status, headers, payload = _request(server.url)
        assert status == 200
        assert b"AOI" in payload
        assert b"COMMAND CENTER" in payload
        assert b'id="export-status"' in payload
        assert b"setInterval(() => { void refresh(); }, 5000)" in payload
        assert b"snapshot unavailable" in payload
        assert b"lastSeenEventCursor" in payload
        assert b"lastAcceptedTransactionData" in payload
        assert b"same cursor carried non-identical transaction bytes" in payload
        assert b"/api/v1/history?cursor=${replayCursor}" in payload
        assert b"/api/v1/events?cursor=${replayCursor}" in payload
        assert b"/api/v1/events?cursor=${snapshot.cursor}" not in payload
        assert b"history_gap" in payload
        assert b"event.lastEventId" in payload
        assert headers["Cache-Control"] == "no-store"
        assert "default-src 'self'" in headers["Content-Security-Policy"]

        status, _, payload = _request(server.url + "api/v1/execution")
        assert status == 200
        value = json.loads(payload)
        assert value["company_id"] == "company-1"
        assert value["data"]["nodes"][0]["engineering_status"] == "active"
        assert value["data"]["nodes"][0]["runtime_status"] == "running"

        status, _, payload = _request(
            server.url + "api/v1/execution/execution-chief",
        )
        assert status == 200
        assert json.loads(payload)["data"]["execution_id"] == (
            "execution-chief"
        )

        status, _, payload = _request(server.url + "api/v1/optimizer")
        assert status == 200
        assert json.loads(payload)["data"]["section"] == "optimizer"

        status, _, payload = _request(server.url + "api/v1/export")
        assert status == 200
        assert json.loads(payload)["data"]["sanitized"] is False


def test_dashboard_asset_has_bounded_truthful_dispatch_queue_surface() -> None:
    with CompanyDashboardServer(_cache()) as server:
        status, _, payload = _request(server.url)
    assert status == 200
    assert b'id="dispatch-queue"' in payload
    assert b'id="environment-banner"' in payload
    assert b'id="work-definitions"' in payload
    assert b"Environment: ${environmentKind}" in payload
    assert b"provider-live ${" in payload
    assert b"provider worker ${providerWorker.state" in payload
    assert b"Registered-work gate" in payload
    assert b"durable contract admission" in payload
    assert b"contract gate eligible" in payload
    assert b"contract gate blocked" in payload
    assert b"eligibility unknown" in payload
    assert b"provider worker remains unavailable" in payload
    assert b"work.collection_summary" in payload
    assert b"workCollectionSummary[name]?.truncated" in payload
    assert b'id="provider-lifecycle-receipts"' in payload
    assert b'id="execution-orphans"' in payload
    assert b'Orphan / Unattributed' in payload
    assert b'orphan-heading' in payload
    assert b'execution.orphans' in payload
    assert b'projection_source' in payload
    assert b'source: ${node.projection_source' in payload
    assert b"active capacity" in payload
    assert b"lead fanout" in payload
    assert b"capacityLine" in payload
    assert "known ≥".encode() in payload
    assert b"dispatchQueue" in payload
    assert b"barrierReservations" in payload
    assert b"width: clamp(150px, 15vw, 240px)" in payload
    assert b"overflow-wrap: anywhere" in payload
    assert b"FROZEN \xe2\x80\x94 reconcile required" in payload
    assert b"freeze / reconcile before retry" in payload
    assert b"slice(0, 256)" in payload
    assert b"\xe5\x8f\xaa\xe9\xa1\xaf\xe7\xa4\xba\xe5\x89\x8d 256 \xe7\xad\x86 dispatch summary" in payload
    assert b"queue-card" in payload
    assert b'const chiefCardClass = selectedChief?.state === "active"' in payload
    assert b'<div class="card ${chiefCardClass}">' in payload
    assert b'${activeChief ? "active" : "unknown"}' not in payload
    assert b"logical ${selectedChief.chief_id" in payload
    assert b"current carrier ${chiefCarrier.carrier_id}" in payload
    assert b"pill(\"takeover\", item.outcome" in payload
    assert b"pill(\"carrier\", node.carrier_state" in payload
    assert b"dep.lifecycle_reason" in payload
    assert b"dep.lead?.organization_status" in payload
    assert b"dep.current_execution.engineering_status" in payload
    assert b"dep.current_execution.runtime_status" in payload
    assert b"dep.current_execution.descendant_count" in payload
    assert b"executionAnchor(dep.current_execution.execution_id)" in payload
    assert b"current-department-execution" in payload
    assert b"department: ${item.department_id" in payload
    assert b"dep.snapshot.snapshot_id" in payload
    assert b"dep.snapshot.cursor" in payload
    assert b"dep.carrier.session_availability" in payload
    assert b"dep.wake_dispatch.revision" in payload
    assert b"queued, no runtime execution" in payload
    assert b"job.owner_execution_id" in payload
    assert b"job.mutation_intent_id" in payload
    assert b"job.external_handle?.availability" in payload
    assert b'id="job-receipts"' in payload
    assert b"external_job_effect_receipts" in payload
    assert b"receipt.previous_job_state" in payload
    assert b"receipt.observed_job_state" in payload
    assert b"receipt.raw_artifact?.sha256" in payload
    assert b"receipt.resolves_reconciliation_id" in payload
    assert b"provider_lifecycle_receipts" in payload
    assert b"provider_lifecycle_receipt_summary" in payload
    assert b"receipt.provider_dispatch_id" in payload
    assert b"receipt.ledger_cursor" in payload
    assert b"lifecycleReceipts.map(receipt" in payload
    assert b"lifecycleReceipts.slice().reverse()" not in payload
    assert "\u53ea\u986f\u793a\u6700\u65b0 256 \u7b46 provider lifecycle receipt summary".encode() in payload
    assert b"receipt.raw_artifact?.availability" in payload
    assert b'id="checkpoint"' in payload
    assert b'id="checkpoint-export"' in payload
    assert b"Plain checkpoint" in payload
    assert b"Sanitized export" in payload
    assert b"checkpoint.manifest_sha256" in payload
    assert b"delivery.export_sha256" in payload
    assert b"job.tool" not in payload
    assert b"job.command_sha256" not in payload
    assert b"item.title" not in payload
    assert b"item.question ||" not in payload
    assert b"item.summary" not in payload
    assert b"item.summary || item.reason" not in payload
    assert b"item.question_sha256" in payload
    assert b"item.detail_sha256" in payload
    assert b"Question content unavailable in this read-only projection." in payload
    assert b"Alert detail content unavailable in this read-only projection." in payload
    assert b"item.payload" not in payload
    assert b"item.evidence" not in payload
    assert b"item.session_id" not in payload
    assert b"receipt.session_id" not in payload
    assert b"receipt.thread_id" not in payload
    assert b"item.resume_id" not in payload
    assert b"method: \"POST\"" not in payload


def test_dashboard_has_no_mutation_surface_and_rejects_unknown_host() -> None:
    with CompanyDashboardServer(_cache()) as server:
        status, headers, payload = _request(
            server.url + "api/v1/company",
            method="POST",
        )
        assert status == 405
        assert headers["Allow"] == "GET"
        assert json.loads(payload)["error"] == "read_only"

        host, port = server.address
        del host
        status, _, payload = _request(
            server.url + "api/v1/meta",
            headers={"Host": f"attacker.example:{port}"},
        )
        assert status == 400
        assert json.loads(payload)["error"] == "invalid_host_or_origin"

        for request_host, origin_host in (
            ("127.0.0.1", "localhost"),
            ("localhost", "127.0.0.1"),
        ):
            status, _, payload = _request(
                server.url + "api/v1/meta",
                headers={
                    "Host": f"{request_host}:{port}",
                    "Origin": f"http://{origin_host}:{port}",
                },
            )
            assert status == 400
            assert json.loads(payload)["error"] == (
                "invalid_host_or_origin"
            )


def test_dashboard_serves_read_only_work_route() -> None:
    with CompanyDashboardServer(_cache()) as server:
        status, headers, payload = _request(server.url + "api/v1/work")
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert json.loads(payload)["data"] == {"section": "work"}


def test_current_snapshot_is_explicit_about_missing_history() -> None:
    with CompanyDashboardServer(_cache()) as server:
        status, _, payload = _request(
            server.url + "api/v1/snapshot?cursor=2",
        )
        assert status == 409
        assert json.loads(payload)["error"] == (
            "historical_projection_unavailable"
        )

        status, _, payload = _request(
            server.url + "api/v1/history?cursor=2",
        )
        assert status == 200
        value = json.loads(payload)
        assert value["data"]["transactions"][0]["cursor"] == 3


def test_historical_replay_is_bounded_cached_and_internal_faults_are_500() -> None:
    source = _HistoricalView()
    cache = _cache(source)
    assert source.replay_freezes == 1
    assert cache.refresh() == 3
    assert source.replay_freezes == 1

    first = cache.snapshot_at(2)
    assert first["cursor"] == 2
    assert cache.snapshot_at(2) == first
    assert source.peak_active_replays == 1

    failing = _HistoricalView()
    failing.failure = OSError("simulated disk full")
    with CompanyDashboardServer(_cache(failing)) as server:
        status, _, payload = _request(
            server.url + "api/v1/snapshot?cursor=2",
        )
    assert status == 500
    assert json.loads(payload)["error"] == "historical_projection_failed"


def test_historical_replay_allows_only_one_active_projection() -> None:
    source = _HistoricalView()
    source.block_replay = True
    cache = _cache(source)
    results: list[int] = []
    failures: list[BaseException] = []

    def replay(cursor: int) -> None:
        try:
            results.append(int(cache.snapshot_at(cursor)["cursor"]))
        except BaseException as exc:
            failures.append(exc)

    first = threading.Thread(target=replay, args=(1,))
    first.start()
    assert source.replay_started.wait(timeout=3.0)
    contenders = [
        threading.Thread(target=replay, args=(2,))
        for _ in range(6)
    ]
    for contender in contenders:
        contender.start()
    for contender in contenders:
        contender.join(timeout=3.0)
        assert not contender.is_alive()
    source.allow_replay.set()
    first.join(timeout=3.0)
    assert not first.is_alive()
    assert results == [1]
    assert len(failures) == 6
    assert all(
        isinstance(failure, CompanyDashboardBusyError)
        for failure in failures
    )
    assert source.peak_active_replays == 1


def test_snapshot_cache_keeps_state_reads_on_owner_thread() -> None:
    source = _OwnerBoundSnapshotView()
    cache = CompanyDashboardSnapshotCache(source)
    assert cache.refresh() == 3
    owner_calls = len(source.call_thread_ids)

    with CompanyDashboardServer(cache) as server:
        status, _, payload = _request(server.url + "api/v1/execution")
        assert status == 200
        value = json.loads(payload)
        assert value["data"]["nodes"][0]["execution_id"] == (
            "execution-chief"
        )
        assert len(source.call_thread_ids) == owner_calls


def test_export_bundle_is_cached_separately_from_lightweight_snapshot() -> None:
    cache = _cache(_AvailableExportView(cursor=7))
    summary = cache.section("snapshot")["data"]["export"]
    exported = cache.section("export")["data"]
    assert summary["snapshot"] is None
    assert exported["snapshot"]["ledger"]["cursor"] == 7
    with CompanyDashboardServer(cache) as server:
        status, _headers, payload = _request(server.url + "api/v1/export")
        assert status == 200
        decoded = json.loads(payload)
        assert decoded["data"]["snapshot"]["ledger"]["cursor"] == 7


def test_dashboard_rejects_direct_state_backed_view() -> None:
    with pytest.raises(CompanyDashboardError, match="snapshot cache"):
        CompanyDashboardServer(_View())  # type: ignore[arg-type]


def test_snapshot_cache_catches_up_in_batches_without_silent_gap() -> None:
    cache = _cache(_View(cursor=300), max_cached_events=256)
    events = cache.events_after(256)
    assert len(events) == 44
    assert events[0]["cursor"] == 257
    assert events[-1]["cursor"] == 300

    with pytest.raises(CompanyDashboardError, match="cursor gap"):
        CompanyDashboardSnapshotCache(_GapView()).refresh()


def test_expired_history_and_sse_cursor_require_reset() -> None:
    cache = _cache(_View(cursor=512), max_cached_events=256)
    with pytest.raises(CompanyDashboardResetRequiredError):
        cache.events_after(255)
    assert cache.events_after(256)[0]["cursor"] == 257

    with CompanyDashboardServer(cache) as server:
        status, _, payload = _request(
            server.url + "api/v1/history?cursor=255",
        )
        assert status == 409
        assert json.loads(payload)["error"] == "reset_required"

        status, _, payload = _request(
            server.url + "api/v1/events",
            headers={"Last-Event-ID": "255"},
        )
        assert status == 409
        assert json.loads(payload)["error"] == "reset_required"

        status, _, payload = _request(
            server.url + "api/v1/events?cursor=255",
        )
        assert status == 409
        assert json.loads(payload)["error"] == "reset_required"


def test_history_returns_contiguous_transactions_after_cursor() -> None:
    with CompanyDashboardServer(_cache(_View(cursor=13))) as server:
        status, _, payload = _request(
            server.url + "api/v1/history?cursor=10",
        )
        assert status == 200
        value = json.loads(payload)
        assert value["data"]["after_cursor"] == 10
        assert [
            transaction["cursor"]
            for transaction in value["data"]["transactions"]
        ] == [11, 12, 13]


@pytest.mark.parametrize("host", ["0.0.0.0", "::1", "localhost"])
def test_dashboard_refuses_noncanonical_bind_address(host: str) -> None:
    with pytest.raises(CompanyDashboardError, match="127.0.0.1"):
        CompanyDashboardServer(_cache(), host=host)
