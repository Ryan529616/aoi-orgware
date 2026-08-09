from __future__ import annotations

from http import HTTPStatus
import json
from pathlib import Path
import re
import urllib.error
import urllib.request

import pytest

from aoi_orgware.company import dashboard_company_os
from aoi_orgware.company.dashboard import (
    CompanyDashboardServer,
    CompanyDashboardSnapshotCache,
)


class _View:
    cursor = 3

    class _Replay:
        records = tuple(range(3))

    def section(self, name: str) -> dict[str, object]:
        export = {
            "state": "unavailable",
            "sanitized": False,
            "reason": "test_export_unavailable",
            "snapshot": None,
        }
        if name == "snapshot":
            data: object = {
                "company": {"chief": {"term": None}},
                "departments": [],
                "execution": {"nodes": [], "orphans": []},
                "alerts": {"alerts": [], "needs_user": []},
                "export": export,
            }
        elif name == "export":
            data = export
        elif name == "meta":
            data = {"cursor": self.cursor}
        else:
            data = {"section": name}
        return {
            "schema_version": 1,
            "company_id": "company-live",
            "cursor": self.cursor,
            "generated_at": "2026-08-09T00:00:00Z",
            "completeness": "complete",
            "warnings": [],
            "data": data,
        }

    def events_after(
        self,
        cursor: int,
        *,
        limit: int = 256,
    ) -> tuple[dict[str, object], ...]:
        del limit
        if cursor >= self.cursor:
            return ()
        return tuple(
            {
                "cursor": value,
                "transaction_id": f"transaction-{value}",
                "events": [],
            }
            for value in range(cursor + 1, self.cursor + 1)
        )

    def snapshot_at(self, cursor: int) -> dict[str, object]:
        value = self.section("snapshot")
        value["cursor"] = cursor
        return value

    def historical_replay_input(self) -> object:
        return self._Replay()

    def snapshot_from_replay(
        self,
        replay: object,
        cursor: int,
    ) -> dict[str, object]:
        del replay
        return self.snapshot_at(cursor)


def _cache() -> CompanyDashboardSnapshotCache:
    cache = CompanyDashboardSnapshotCache(_View())
    cache.refresh()
    return cache


def _request(
    url: str,
    *,
    method: str = "GET",
) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(request, timeout=3.0) as response:  # noqa: S310 - exact loopback server
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read()


def test_company_os_manifest_and_generated_assets_are_package_bound() -> None:
    root = (
        Path(__file__).parents[2]
        / "src"
        / "aoi_orgware"
        / "resources"
        / "dashboard_company_os"
    )
    manifest_bytes = (root / "asset-manifest.json").read_bytes()
    assert dashboard_company_os.company_os_manifest_sha256() == (
        "204b26730a466e85c1f9f467eda9786db3c0d2e3ad45aaf2fe34bb0b4fbf9c15"
    )
    value = json.loads(manifest_bytes)
    assert value["schema_version"] == 1
    assert value["frozen_v8_receipt_sha256"] == (
        "3beba7750581c45e6e22213a04ea45771e0b43a0e2679cb6c200392d5b5063f0"
    )
    assert len(value["files"]) == 47
    assert not any(entry["path"].endswith(".map") for entry in value["files"])
    for entry in value["files"]:
        asset = dashboard_company_os.company_os_asset(entry["path"])
        assert len(asset.payload) == entry["size_bytes"]
        assert asset.content_type == entry["content_type"]


def test_company_os_route_serves_manifested_assets_and_keeps_console() -> None:
    with CompanyDashboardServer(_cache()) as server:
        status, headers, index = _request(server.url + "company-os/")
        assert status == HTTPStatus.OK
        assert headers["Content-Type"] == "text/html; charset=utf-8"
        assert b"AOI Company OS \xe2\x80\x94 Live" in index
        script = re.search(rb'src="/company-os/([^"]+\.js)"', index)
        stylesheet = re.search(rb'href="/company-os/([^"]+\.css)"', index)
        assert script is not None and stylesheet is not None
        for match, content_type in (
            (script, "text/javascript; charset=utf-8"),
            (stylesheet, "text/css; charset=utf-8"),
        ):
            asset_status, asset_headers, payload = _request(
                server.url + "company-os/" + match.group(1).decode("ascii"),
            )
            assert asset_status == HTTPStatus.OK
            assert asset_headers["Content-Type"] == content_type
            assert payload

        console_status, _, console = _request(server.url)
        assert console_status == HTTPStatus.OK
        assert b"AOI Company OS \xe2\x80\x94 Live" not in console


@pytest.mark.parametrize(
    "path",
    (
        "company-os/asset-manifest.json",
        "company-os/../dashboard/index.html",
        "company-os/%2e%2e/dashboard/index.html",
        "company-os/assets/not-manifested.js",
    ),
)
def test_company_os_rejects_unmanifested_and_unsafe_paths(path: str) -> None:
    with CompanyDashboardServer(_cache()) as server:
        status, _, payload = _request(server.url + path)
    assert status == HTTPStatus.NOT_FOUND
    assert json.loads(payload)["error"] == "not_found"


def test_company_os_browser_mutation_remains_unavailable() -> None:
    with CompanyDashboardServer(_cache()) as server:
        for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            status, headers, payload = _request(
                server.url + "company-os/",
                method=method,
            )
            assert status == HTTPStatus.METHOD_NOT_ALLOWED
            assert headers["Allow"] == "GET"
            assert json.loads(payload)["error"] == "read_only"


def test_company_os_manifest_digest_mismatch_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dashboard_company_os, "_MANIFEST_SHA256", "f" * 64)
    with CompanyDashboardServer(_cache()) as server:
        status, _, payload = _request(server.url + "company-os/")
    assert status == HTTPStatus.INTERNAL_SERVER_ERROR
    assert json.loads(payload)["error"] == "company_os_asset_integrity_failed"
