from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import urlopen

import pytest

from aoi_orgware.company.dashboard import (
    CompanyDashboardServer,
    CompanyDashboardSnapshotCache,
)


HTML = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "aoi_orgware"
    / "resources"
    / "dashboard"
    / "index.html"
)


def _html() -> str:
    return HTML.read_text(encoding="utf-8")


class _DrawerDetailView:
    """Small loopback projection containing normal and orphan executions."""

    cursor = 1

    def __init__(self, *, nodes: list[dict[str, Any]], orphans: list[dict[str, Any]]) -> None:
        self._execution = {"nodes": nodes, "orphans": orphans, "events": []}
        self._export = {
            "state": "unavailable", "sanitized": False,
            "reason": "not_implemented", "snapshot": None,
        }

    def section(self, name: str) -> dict[str, Any]:
        if name == "snapshot":
            data: dict[str, Any] = {
                "execution": self._execution,
                "export": self._export,
            }
        elif name == "export":
            data = self._export
        elif name == "execution":
            data = self._execution
        elif name == "meta":
            data = {"status": "ok"}
        else:
            data = {"section": name}
        return {
            "schema_version": 1, "company_id": "drawer-company",
            "cursor": self.cursor, "generated_at": "2026-07-28T00:00:00Z",
            "completeness": "complete", "warnings": [], "data": data,
        }

    def events_after(self, cursor: int, *, limit: int = 256) -> tuple[dict[str, Any], ...]:
        assert limit <= 256
        return () if cursor >= self.cursor else ({"cursor": 1, "events": []},)

    def snapshot_at(self, cursor: int) -> dict[str, Any]:
        if cursor != self.cursor:
            raise ValueError("test projection has no historical cursor")
        return self.section("snapshot")

    def historical_replay_input(self) -> object:
        return None

    def snapshot_from_replay(self, replay: object, cursor: int) -> dict[str, Any]:
        del replay
        if cursor != self.cursor:
            raise ValueError("test projection has no historical cursor")
        return self.section("snapshot")


def _drawer_server(*, nodes: list[dict[str, Any]], orphans: list[dict[str, Any]]) -> CompanyDashboardServer:
    cache = CompanyDashboardSnapshotCache(_DrawerDetailView(nodes=nodes, orphans=orphans))
    assert cache.refresh() == 1
    return CompanyDashboardServer(cache)


def _get_json(url: str) -> tuple[int, dict[str, Any]]:
    try:
        with urlopen(url, timeout=3) as response:
            return response.status, json.loads(response.read())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _drawer_records(data: dict[str, Any], execution_id: str) -> dict[str, list[dict[str, Any]]]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the Dashboard JavaScript unit probe")
    script = """
const fs = require("fs");
const [path, payload, executionId] = process.argv.slice(1);
const html = fs.readFileSync(path, "utf8");
const start = html.indexOf("const DRAWER_RECORD_LIMIT");
const end = html.indexOf("    function truncateRaw", start);
if (start < 0 || end < 0) throw new Error("drawer helper bounds not found");
const drawerRecords = new Function(`${html.slice(start, end)}; return drawerRecords;`)();
process.stdout.write(JSON.stringify(drawerRecords(JSON.parse(payload), executionId)));
"""
    completed = subprocess.run(
        [node, "-e", script, str(HTML), json.dumps(data), execution_id],
        check=True, capture_output=True, text=True,
    )
    value = json.loads(completed.stdout)
    assert isinstance(value, dict)
    return value


def _close_focus_after_same_cursor_rerender() -> dict[str, Any]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the Dashboard JavaScript unit probe")
    script = """
const fs = require("fs");
const html = fs.readFileSync(process.argv[1], "utf8");
const start = html.indexOf("    function currentExecutionCard");
const end = html.indexOf("    function drawerTabId", start);
if (start < 0 || end < 0) throw new Error("drawer focus helper bounds not found");
class HTMLElement {}
const stale = new HTMLElement();
stale.dataset = {executionCard: "execution-1"};
const current = new HTMLElement();
current.dataset = {executionCard: "execution-1"};
let currentFocused = 0;
let staleFocused = 0;
current.focus = () => { currentFocused += 1; };
stale.focus = () => { staleFocused += 1; };
const document = {
  querySelectorAll: selector => selector === "[data-execution-card]" ? [current] : [],
  contains: value => value !== stale
};
const run = new Function("document", "HTMLElement", "stale", `
  let drawer = {trigger: stale, triggerExecutionId: "execution-1"};
  let drawerGeneration = 0;
  function renderDrawer() {}
${html.slice(start, end)}
  closeDrawer();
  return {drawerClosed: drawer === null, drawerGeneration};
`);
const result = run(document, HTMLElement, stale);
process.stdout.write(JSON.stringify({...result, currentFocused, staleFocused}));
"""
    completed = subprocess.run(
        [node, "-e", script, str(HTML)],
        check=True, capture_output=True, text=True,
    )
    value = json.loads(completed.stdout)
    assert isinstance(value, dict)
    return value


def test_execution_drawer_is_read_only_and_has_all_required_tabs() -> None:
    html = _html()

    assert 'id="execution-drawer"' in html
    assert 'role="dialog"' in html
    assert 'aria-modal="true"' in html
    assert 'data-execution-close="backdrop"' in html
    assert 'id="execution-drawer-close"' in html
    assert 'const DRAWER_TABS = ["Overview", "Activity", "Usage", "Artifacts", "Evidence", "Raw"]' in html
    assert "Read-only projection; no mutation controls are available." in html
    assert 'method: "POST"' not in html


def test_live_execution_detail_resolves_orphan_encoded_slash_and_rejects_collision() -> None:
    normal = {"execution_id": "normal", "engineering_status": "active"}
    orphan = {"execution_id": "orphan/slash", "engineering_status": "unknown"}
    with _drawer_server(nodes=[normal], orphans=[orphan]) as server:
        status, payload = _get_json(server.url + "api/v1/execution/normal")
        assert status == 200
        assert payload["data"] == normal

        status, payload = _get_json(
            server.url + "api/v1/execution/" + quote("orphan/slash", safe=""),
        )
        assert status == 200
        assert payload["data"] == orphan

        status, payload = _get_json(server.url + "api/v1/execution/orphan/slash")
        assert status == 404
        assert payload["error"] == "not_found"

    duplicate = {"execution_id": "collision", "engineering_status": "unknown"}
    with _drawer_server(nodes=[duplicate], orphans=[duplicate]) as server:
        status, payload = _get_json(server.url + "api/v1/execution/collision")
        assert status == 409
        assert payload["error"] == "execution_identity_ambiguous"


def test_execution_cards_handle_pointer_keyboard_and_copy_suppression() -> None:
    html = _html()

    assert "data-execution-card=" in html
    assert "role=\"button\" tabindex=\"0\"" in html
    assert 'event.key === "Enter" || event.key === " "' in html
    assert 'if (event.target.closest("[data-copy]")) return;' in html
    assert "event.stopPropagation();" in html
    assert "installExecutionCardInteractions();" in html


def test_drawer_closes_on_escape_backdrop_and_restores_focus() -> None:
    html = _html()

    assert 'event.key === "Escape" && drawer' in html
    assert 'event.target.dataset.executionClose === "backdrop"' in html
    assert "document.contains(restoreFocus)" in html
    assert "restoreFocus.focus()" in html
    assert "function currentExecutionCard(executionId)" in html
    assert "triggerExecutionId: executionId" in html


def test_drawer_close_restores_current_execution_card_after_same_cursor_rerender() -> None:
    outcome = _close_focus_after_same_cursor_rerender()

    assert outcome == {
        "drawerClosed": True,
        "drawerGeneration": 1,
        "currentFocused": 1,
        "staleFocused": 0,
    }


def test_drawer_usage_and_evidence_artifact_joins_are_explicit_and_bounded() -> None:
    records = _drawer_records({
        "usage": {"counter_samples": [
            *[{"sample_id": f"sample-{index}", "telemetry_receipt_id": "receipt-exec"}
              for index in range(33)],
            {"sample_id": "foreign-sample", "telemetry_receipt_id": "receipt-other"},
        ]},
        "evidence": {
            "provider_telemetry_receipts": [
                {"receipt_id": "receipt-exec", "dispatch_join": {"execution_id": "execution-1"}},
                {"receipt_id": "receipt-other", "dispatch_join": {"execution_id": "execution-other"}},
            ],
            "records": [
                {"evidence_id": "evidence-1", "execution_id": "execution-1", "artifact": {"sha256": "blob-1"}},
                {"evidence_id": "evidence-other", "execution_id": "execution-other", "artifact": {"sha256": "blob-other"}},
            ],
            "edges": [
                {"edge_id": "edge-execution", "source_kind": "execution", "source_id": "execution-1", "target_kind": "evidence", "target_id": "evidence-1"},
                {"edge_id": "edge-evidence", "source_kind": "evidence", "source_id": "evidence-1", "target_kind": "blob", "target_id": "blob-1"},
                {"edge_id": "edge-blob", "source_kind": "blob", "source_id": "blob-1", "target_kind": "snapshot", "target_id": "snapshot-1"},
                {"edge_id": "edge-foreign", "source_kind": "evidence", "source_id": "evidence-other", "target_kind": "blob", "target_id": "blob-other"},
            ],
        },
        "execution": {"events": []}, "jobs": [], "alerts": {"alerts": []},
    }, "execution-1")

    assert len(records["usage"]) == 32
    assert {sample["sample_id"] for sample in records["usage"]} == {
        f"sample-{index}" for index in range(32)
    }
    for section in ("artifacts", "evidence"):
        identifiers = json.dumps(records[section])
        assert "evidence-1" in identifiers
        assert "edge-execution" in identifiers
        assert "edge-evidence" in identifiers
        assert "edge-blob" in identifiers
        assert "evidence-other" not in identifiers
        assert "edge-foreign" not in identifiers


def test_drawer_evidence_closure_uses_only_explicit_node_event_record_and_edge_ids() -> None:
    records = _drawer_records({
        "usage": {"counter_samples": []},
        "evidence": {
            "records": [
                {"evidence_id": "node-only", "execution_id": None, "artifact": {"sha256": "blob-node"}},
                {"evidence_id": "event-only", "execution_id": None, "artifact": {"sha256": "blob-event"}},
                {"evidence_id": "edge-only", "execution_id": None, "artifact": {"sha256": "blob-edge"}},
                {"evidence_id": "direct-record", "execution_id": "execution-1", "artifact": {"sha256": "blob-direct"}},
                {"evidence_id": "foreign-evidence", "execution_id": "execution-other", "artifact": {"sha256": "blob-foreign"}},
                {"evidence_id": "time-only", "execution_id": None, "recorded_at": "2026-07-28T00:00:00Z", "artifact": {"sha256": "blob-time"}},
            ],
            "edges": [
                {"edge_id": "edge-direct", "source_kind": "execution", "source_id": "execution-1", "target_kind": "evidence", "target_id": "edge-only"},
                {"edge_id": "edge-node", "source_kind": "evidence", "source_id": "node-only", "target_kind": "blob", "target_id": "blob-node"},
                {"edge_id": "edge-event", "source_kind": "evidence", "source_id": "event-only", "target_kind": "blob", "target_id": "blob-event"},
                {"edge_id": "edge-blob", "source_kind": "blob", "source_id": "blob-edge", "target_kind": "snapshot", "target_id": "snapshot-edge"},
                {"edge_id": "edge-foreign", "source_kind": "execution", "source_id": "execution-other", "target_kind": "evidence", "target_id": "foreign-evidence"},
                {"edge_id": "edge-time-only", "source_kind": "evidence", "source_id": "time-only", "target_kind": "blob", "target_id": "blob-time"},
            ],
        },
        "execution": {
            "nodes": [{"execution_id": "execution-1", "evidence_ids": ["node-only"]}],
            "orphans": [{"execution_id": "execution-other", "evidence_ids": ["foreign-evidence"]}],
            "events": [
                {"execution_id": "execution-1", "evidence_ids": ["event-only"]},
                {"execution_id": "execution-other", "evidence_ids": ["foreign-evidence"]},
            ],
        },
        "jobs": [], "alerts": {"alerts": []},
    }, "execution-1")

    expected = {"node-only", "event-only", "edge-only", "direct-record"}
    for section in ("artifacts", "evidence"):
        identifiers = json.dumps(records[section])
        assert all(identifier in identifiers for identifier in expected)
        assert "edge-direct" in identifiers
        assert "edge-node" in identifiers
        assert "edge-event" in identifiers
        assert "edge-blob" in identifiers
        assert "foreign-evidence" not in identifiers
        assert "edge-foreign" not in identifiers
        assert "time-only" not in identifiers
        assert "edge-time-only" not in identifiers


def test_drawer_evidence_closure_remains_bounded() -> None:
    evidence_ids = [f"node-bound-{index}" for index in range(33)]
    records = _drawer_records({
        "evidence": {
            "records": [
                {"evidence_id": evidence_id, "execution_id": None, "artifact": {"sha256": f"blob-{index}"}}
                for index, evidence_id in enumerate(evidence_ids)
            ],
            "edges": [],
        },
        "execution": {
            "nodes": [{"execution_id": "execution-1", "evidence_ids": evidence_ids}],
            "orphans": [], "events": [],
        },
        "usage": {"counter_samples": []}, "jobs": [], "alerts": {"alerts": []},
    }, "execution-1")

    assert len(records["artifacts"]) == 32
    assert len(records["evidence"]) == 32
    bounded_identifiers = json.dumps(records)
    assert "node-bound-31" in bounded_identifiers
    assert "node-bound-32" not in bounded_identifiers


def test_live_detail_fetch_is_encoded_identity_checked_and_stale_guarded() -> None:
    html = _html()

    assert 'fetch(`/api/v1/execution/${encodeURIComponent(executionId)}`' in html
    assert "drawer?.requestGeneration !== requestGeneration" in html
    assert "snapshot !== source" in html
    assert "isHistoricalView()" in html
    assert "envelope?.company_id !== companyId" in html
    assert "envelope?.cursor !== cursor" in html
    assert "!isRecord(envelope?.data)" in html
    assert "envelope.data.execution_id !== executionId" in html
    assert "execution detail identity mismatch or stale response" in html
    assert "drawer?.mode === \"live\" && drawer.cursor !== incoming.cursor" in html


def test_historical_drawer_uses_selected_snapshot_without_current_detail_fetch() -> None:
    html = _html()

    historical_branch = html.split('if (drawer.mode === "historical") {', 1)[1].split('try {', 1)[0]
    assert "historicalExecution(source, executionId)" in historical_branch
    assert "snapshot !== source" in historical_branch
    assert "historicalCursor !== cursor" in historical_branch
    assert "/api/v1/execution/" not in historical_branch


def test_drawer_escapes_and_bounds_associated_and_raw_records() -> None:
    html = _html()

    assert "const DRAWER_RECORD_LIMIT = 32;" in html
    assert "const DRAWER_RAW_LIMIT = 16384;" in html
    assert ".slice(0, DRAWER_RECORD_LIMIT)" in html
    assert "activity: collect(data?.execution?.events)" in html
    assert "record.producer_execution_id" in html
    assert "record.dispatch_join?.execution_id" in html
    assert "const jobs = collect(data?.jobs);" in html
    assert "jobIds.has(item?.job_id)" in html
    assert "artifactEvidence" in html
    assert "safe(truncateRaw(record))" in html
    assert "safe(truncateRaw({" in html
    assert "… truncated at ${DRAWER_RAW_LIMIT} characters" in html
    assert "telemetryReceiptIds" in html
    assert "telemetry_receipt_id" in html
    assert "executionEvidence" in html
    assert "uniqueNodeEvidenceIds" in html
    assert "matchingEventEvidenceIds" in html
    assert "directEdgeEvidenceIds" in html
    assert "directRecordEvidenceIds" in html
    assert "visibleEvidenceIds" in html
    assert "relatedEdges" in html
    assert "edgeReferences" in html
    assert "setDrawerBackgroundInert(true)" in html
    assert "function trapDrawerFocus(event)" in html
    assert 'aria-controls="execution-drawer-content"' in html
    assert "handleDrawerTabKey" in html
