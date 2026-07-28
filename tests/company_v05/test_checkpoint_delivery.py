from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from aoi_orgware.company.dashboard import CompanyDashboardSnapshotCache
from aoi_orgware.company.state import (
    CompanyDeliveryPartialError,
    CompanyStateOwner,
)
from aoi_orgware.company.supervisor import CompanySupervisor
from tests.company_v05.test_checkpoint import T, initialized, request


class _FailingDashboardCache:
    def refresh(self) -> int:
        raise RuntimeError("test Dashboard refresh failure")


def test_creation_replay_and_immutable_export_bundle(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    try:
        first = owner.create_checkpoint_export_delivery(
            "delivery-cp",
            "delivery-export",
            T,
        )
        replay = owner.create_checkpoint_export_delivery(
            "delivery-cp",
            "delivery-export",
            T,
        )
        assert first.checkpoint.state == "verified"
        assert first.checkpoint.current is True
        assert first.sanitized_export.state == "available"
        assert first.sanitized_export.current is True
        assert first.sanitized_export.canonical_bundle_json == (
            owner.resolved.incarnation.exports / "delivery-export.json"
        ).read_bytes()
        assert replay == first
    finally:
        owner.close()


def test_restart_discovers_verified_delivery_read_only(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    root = tmp_path / "company"
    try:
        owner.create_checkpoint_export_delivery("restart-cp", "restart-export", T)
    finally:
        owner.close()
    reopened = CompanyStateOwner.open(root)
    try:
        delivery = reopened.delivery_snapshot()
        assert delivery.checkpoint.checkpoint_id == "restart-cp"
        assert delivery.checkpoint.current is True
        assert delivery.sanitized_export.export_id == "restart-export"
        assert delivery.sanitized_export.current is True
    finally:
        reopened.close()


def test_delivery_becomes_stale_when_the_ledger_advances(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    try:
        owner.create_checkpoint_export_delivery("stale-cp", "stale-export", T)
        owner.commit(request(owner, {}, 2), recorded_at=T)
        delivery = owner.delivery_snapshot()
        assert delivery.checkpoint.current is False
        assert delivery.checkpoint.reason == "ledger_cursor_or_head_drift"
        assert delivery.sanitized_export.current is False
        assert delivery.sanitized_export.reason == "checkpoint_digest_drift"
    finally:
        owner.close()


def test_corrupt_export_is_reported_without_blocking_startup(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    root = tmp_path / "company"
    try:
        owner.create_checkpoint_export_delivery("corrupt-cp", "corrupt-export", T)
    finally:
        owner.close()
    path = root / "incarnations"
    export = next(path.glob("*/exports/corrupt-export.json"))
    export.write_bytes(export.read_bytes() + b" ")
    reopened = CompanyStateOwner.open(root)
    try:
        delivery = reopened.delivery_snapshot()
        assert delivery.checkpoint.current is True
        assert delivery.sanitized_export.state == "unavailable"
        assert "sanitized_export_corrupt" in delivery.warnings
    finally:
        reopened.close()


def test_combined_creation_retains_checkpoint_partial_truth(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    try:
        with pytest.raises(CompanyDeliveryPartialError) as caught:
            owner.create_checkpoint_export_delivery(
                "partial-cp",
                "not/a-valid-export-id",
                T,
            )
        delivery = caught.value.snapshot
        assert delivery.checkpoint.checkpoint_id == "partial-cp"
        assert delivery.checkpoint.current is True
        assert delivery.sanitized_export.state == "unavailable"
        assert delivery.sanitized_export.reason == "sanitized_export_creation_failed"
        assert "sanitized_export_creation_failed" in delivery.warnings
    finally:
        owner.close()


def test_supervisor_exposes_combined_delivery_snapshot(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    supervisor = CompanySupervisor(owner)
    try:
        delivery = supervisor.create_checkpoint_export("supervisor-cp", "supervisor-export", T)
        assert supervisor.delivery() == delivery
    finally:
        supervisor.close()


def test_supervisor_keeps_partial_delivery_error_primary_on_refresh_failure(
    tmp_path: Path,
) -> None:
    supervisor = CompanySupervisor(initialized(tmp_path))
    supervisor._dashboard_cache = cast(
        CompanyDashboardSnapshotCache,
        _FailingDashboardCache(),
    )
    try:
        with pytest.raises(CompanyDeliveryPartialError) as caught:
            supervisor.create_checkpoint_export("noted-cp", "bad/export", T)
        assert any(
            "Dashboard refresh also failed" in note
            for note in getattr(caught.value, "__notes__", ())
        )
    finally:
        supervisor.close()
