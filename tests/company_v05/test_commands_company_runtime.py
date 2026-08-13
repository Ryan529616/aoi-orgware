from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from aoi_orgware.commands.company_runtime import (
    BoundCompanyTarget,
    CompanyRuntimeCommandError,
    dashboard_open,
    dashboard_url,
    register_company_runtime_commands,
    supervisor_ensure,
    supervisor_status,
    supervisor_stop,
)


@dataclass
class _Target:
    slot_root: Path
    company_id: str = "company-1"
    manifest_sha256: str = "a" * 64
    service_state: str = "unavailable"
    dashboard_url: str | None = None
    warnings: tuple[str, ...] | list[str] = ("discovery receipt is current",)


class _Services:
    def __init__(
        self,
        statuses: list[dict[str, Any]],
        *,
        discovery_states: list[str] | None = None,
    ) -> None:
        self.target = _Target(Path("C:/state/company-1"))
        self.statuses = iter(statuses)
        self.discovery_states = (
            None if discovery_states is None else iter(discovery_states)
        )
        self.ensure_calls: list[tuple[Path, str | None]] = []
        self.status_calls: list[Path] = []
        self.stop_calls: list[Path] = []
        self.resolved: list[tuple[Path, str | None]] = []

    def resolve_bound_company(
        self,
        cwd: Path,
        company_id: str | None,
    ) -> BoundCompanyTarget:
        self.resolved.append((cwd, company_id))
        if self.discovery_states is not None:
            self.target.service_state = next(self.discovery_states)
        return self.target

    def ensure_service(
        self,
        slot_root: Path,
        *,
        expected_manifest_sha256: str | None = None,
    ) -> dict[str, Any]:
        self.ensure_calls.append((slot_root, expected_manifest_sha256))
        return next(self.statuses)

    def service_status(self, slot_root: Path, **_kwargs: object) -> dict[str, Any]:
        self.status_calls.append(slot_root)
        return next(self.statuses)

    def stop_service(self, slot_root: Path, **_kwargs: object) -> dict[str, Any]:
        self.stop_calls.append(slot_root)
        return next(self.statuses)


def _running(instance_id: str = "instance-1") -> dict[str, Any]:
    return {
        "state": "running",
        "descriptor": {
            "service_instance_id": instance_id,
            "dashboard_url": "http://127.0.0.1:45817/",
            "control_url": "http://127.0.0.1:45999",
            "bearer_token": "secret",
            "telemetry_capabilities": {
                "codex_app_server": "secret-capability-path",
            },
            "slot_path": "C:/state/company-1",
            "company": {
                "company_id": "company-1",
                "manifest_sha256": "a" * 64,
            },
        },
        "status": {
            "service_instance_id": instance_id,
            "state": "running",
            "cursor": 12,
            "pid": 999,
        },
    }


def _stopping(instance_id: str = "instance-1") -> dict[str, Any]:
    value = _running(instance_id)
    value["state"] = "stopping"
    value["status"]["state"] = "stopping"
    return value


def test_ensure_resolves_cwd_and_fences_manifest_and_sanitizes() -> None:
    services = _Services([_running()])
    result = supervisor_ensure(
        company_id="company-1",
        services=services,
        cwd=Path("."),
    )
    assert services.ensure_calls == [(services.target.slot_root, "a" * 64)]
    assert result["service"]["state"] == "running"
    serialized = repr(result)
    assert "secret" not in serialized
    assert "secret-capability-path" not in serialized
    assert "control_url" not in serialized
    assert "slot_path" not in serialized


def test_status_is_read_only_and_reports_unavailable_without_sensitive_fields() -> None:
    services = _Services([{"state": "unavailable", "reason": "descriptor_absent"}])
    result = supervisor_status(services=services, cwd=Path("."))
    assert services.ensure_calls == []
    assert result["service"] == {"state": "unavailable", "reason": "descriptor_absent"}


@pytest.mark.parametrize(
    "operation",
    (supervisor_ensure, supervisor_status, dashboard_url),
)
def test_running_service_must_match_discovered_company_binding(
    operation: Callable[..., dict[str, Any]],
) -> None:
    running = _running()
    running["descriptor"]["company"] = {
        "company_id": "other-company",
        "manifest_sha256": "b" * 64,
    }
    with pytest.raises(CompanyRuntimeCommandError, match="differs from the repo-bound"):
        operation(services=_Services([running]), cwd=Path("."))


def test_ensure_never_drops_the_required_manifest_fence() -> None:
    class _UnfencedServices(_Services):
        def ensure_service(self, slot_root: Path) -> dict[str, Any]:  # type: ignore[override]
            del slot_root
            return _running()

    with pytest.raises(CompanyRuntimeCommandError, match="could not ensure"):
        supervisor_ensure(
            services=_UnfencedServices([]),  # type: ignore[arg-type]
            cwd=Path("."),
        )


@pytest.mark.parametrize(
    "status",
    (
        {"state": "unavailable", "reason": "child_exited"},
        _stopping(),
    ),
)
def test_ensure_requires_a_verified_running_result(status: dict[str, Any]) -> None:
    with pytest.raises(
        CompanyRuntimeCommandError,
        match="did not produce a running service",
    ):
        supervisor_ensure(services=_Services([status]), cwd=Path("."))


def test_dashboard_url_requires_running_and_never_ensures() -> None:
    services = _Services([{"state": "unavailable", "reason": "descriptor_absent"}])
    with pytest.raises(CompanyRuntimeCommandError, match="supervisor is not running"):
        dashboard_url(services=services, cwd=Path("."))
    assert services.ensure_calls == []


def test_dashboard_open_uses_only_verified_canonical_loopback_url() -> None:
    services = _Services([_running()])
    opened: list[str] = []

    def opener(url: str) -> bool:
        opened.append(url)
        return True

    result = dashboard_open(
        services=services,
        cwd=Path("."),
        opener=opener,
    )
    assert result["opened"] is True
    assert opened == ["http://127.0.0.1:45817/"]


@pytest.mark.parametrize(
    "url",
    (
        "https://127.0.0.1:45817/",
        "http://localhost:45817/",
        "http://127.0.0.1:45817/not-root",
        "http://user@127.0.0.1:45817/",
        "http://127.0.0.1:45817/?outside=1",
        "http://127.0.0.1:notaport/",
        "HTTP://127.0.0.1:45817/",
        "http://127.0.0.1:045817/",
    ),
)
def test_dashboard_rejects_noncanonical_url(url: str) -> None:
    running = _running()
    running["descriptor"]["dashboard_url"] = url
    with pytest.raises(CompanyRuntimeCommandError, match="noncanonical loopback"):
        dashboard_url(services=_Services([running]), cwd=Path("."))


def test_stop_waits_for_unavailable_and_never_has_pid_operation() -> None:
    services = _Services(
        [
            _running(),
            {"state": "stopping", "service_instance_id": "instance-1"},
            _stopping(),
            {"state": "unavailable", "reason": "descriptor_absent"},
        ],
        discovery_states=["running", "stopped"],
    )
    clock = iter((0.0, 0.0, 0.0, 0.01, 0.01, 0.02))
    result = supervisor_stop(
        services=services,
        cwd=Path("."),
        timeout_seconds=1.0,
        monotonic=lambda: next(clock),
        sleep=lambda _seconds: None,
    )
    assert result["stop_requested"] is True
    assert result["verified_stopped"] is True
    assert services.stop_calls == [services.target.slot_root]
    assert len(services.status_calls) == 3


def test_stop_times_out_without_force_kill() -> None:
    services = _Services(
        [
            _running(),
            {"state": "stopping", "service_instance_id": "instance-1"},
            _stopping(),
        ],
        discovery_states=["running"],
    )
    clock = iter((0.0, 1.0, 1.0))
    with pytest.raises(CompanyRuntimeCommandError, match="not force-killed"):
        supervisor_stop(
            services=services,
            cwd=Path("."),
            timeout_seconds=1.0,
            monotonic=lambda: next(clock),
            sleep=lambda _seconds: None,
        )


def test_stop_does_not_treat_transient_unavailable_as_stopped() -> None:
    services = _Services(
        [
            _running(),
            {"state": "stopping", "service_instance_id": "instance-1"},
            {
                "state": "unavailable",
                "reason": "resident control endpoint is unavailable",
            },
        ],
        discovery_states=["running"],
    )
    clock = iter((0.0, 1.0, 1.0))
    with pytest.raises(CompanyRuntimeCommandError, match="could not be verified"):
        supervisor_stop(
            services=services,
            cwd=Path("."),
            timeout_seconds=1.0,
            monotonic=lambda: next(clock),
            sleep=lambda _seconds: None,
        )


def test_stop_reports_same_company_successor_without_stopping_it() -> None:
    services = _Services(
        [
            _running("old-instance"),
            {"state": "stopping", "service_instance_id": "old-instance"},
            _running("successor-instance"),
        ],
        discovery_states=["running"],
    )
    clock = iter((0.0, 0.0))
    result = supervisor_stop(
        services=services,
        cwd=Path("."),
        timeout_seconds=1.0,
        monotonic=lambda: next(clock),
        sleep=lambda _seconds: None,
    )
    assert result["old_instance_stopped"] is True
    assert result["successor_detected"] is True
    assert result["service"]["state"] == "running"


def test_stop_is_idempotent_for_discovery_verified_stopped_company() -> None:
    services = _Services([], discovery_states=["stopped"])
    result = supervisor_stop(services=services, cwd=Path("."))
    assert result["stop_requested"] is False
    assert result["already_stopped"] is True
    assert services.status_calls == []
    assert services.stop_calls == []


def test_registrar_builds_nested_families_and_checks_handlers() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    handlers: dict[str, Callable[[argparse.Namespace, Any], int]] = {
        name: (lambda _args, _paths: 0)
        for name in (
            "supervisor_ensure",
            "supervisor_status",
            "supervisor_stop",
            "dashboard_url",
            "dashboard_open",
        )
    }
    def add_json_argument(item: argparse.ArgumentParser) -> None:
        item.add_argument("--json", action="store_true")

    register_company_runtime_commands(
        subparsers,
        handlers=handlers,
        add_json_argument=add_json_argument,
    )
    args = parser.parse_args(["supervisor", "ensure", "--company-id", "company-1", "--json"])
    assert args.command == "supervisor"
    assert args.supervisor_action == "ensure"
    assert args.company_id == "company-1"
    assert args.json is True
    args = parser.parse_args(["dashboard", "url"])
    assert args.dashboard_action == "url"
    with pytest.raises(ValueError, match="handler map mismatch"):
        register_company_runtime_commands(
            argparse.ArgumentParser().add_subparsers(),
            handlers={},
            add_json_argument=lambda _item: None,
        )
