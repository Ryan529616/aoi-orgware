"""Repo-bound resident company supervisor command family.

This is deliberately a leaf command module.  The composition root supplies
``argparse`` handlers, while the command bodies receive a small injectable
service bundle.  In particular, neither ``dashboard url`` nor ``dashboard
open`` starts a service: a user is never sent to an unverified or stale URL.
"""

from __future__ import annotations

import argparse
import json
import math
import time
import webbrowser
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast
from urllib.parse import urlsplit


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset(
    {
        "supervisor_ensure",
        "supervisor_status",
        "supervisor_stop",
        "dashboard_url",
        "dashboard_open",
    }
)
_PUBLIC_DESCRIPTOR_KEYS = frozenset(
    {
        "schema_version",
        "service_instance_id",
        "company",
        "dashboard_url",
    }
)
_PUBLIC_STATUS_KEYS = frozenset({"schema_version", "service_instance_id", "state", "cursor"})
_PUBLIC_DESCRIPTOR_COMPANY_KEYS = frozenset(
    {
        "company_id",
        "company_incarnation",
        "lock_domain_generation",
        "manifest_sha256",
        "pointer_sha256",
    }
)


class CompanyRuntimeCommandError(RuntimeError):
    """A repo-bound resident-service command could not complete safely."""


class BoundCompanyTarget(Protocol):
    """The deliberately small discovery result required by this command family."""

    slot_root: Path
    company_id: str
    manifest_sha256: str
    service_state: str
    dashboard_url: str | None
    warnings: tuple[str, ...] | list[str]


class CompanyRuntimeServices(Protocol):
    """Injectable adapter boundary for discovery and resident service operations."""

    def resolve_bound_company(
        self,
        cwd: Path,
        company_id: str | None,
    ) -> BoundCompanyTarget: ...

    def ensure_service(
        self,
        slot_root: Path,
        *,
        expected_manifest_sha256: str | None = None,
    ) -> Mapping[str, Any]: ...

    def service_status(self, slot_root: Path) -> Mapping[str, Any]: ...

    def stop_service(
        self,
        slot_root: Path,
        *,
        timeout_seconds: float = 5.0,
        expected_manifest_sha256: str | None = None,
    ) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class _DefaultServices:
    """Lazy imports keep this command module importable before composition wiring."""

    def resolve_bound_company(self, cwd: Path, company_id: str | None) -> BoundCompanyTarget:
        from aoi_orgware.company.discovery import resolve_bound_company

        return cast(BoundCompanyTarget, resolve_bound_company(cwd, company_id))

    def ensure_service(
        self,
        slot_root: Path,
        *,
        expected_manifest_sha256: str | None = None,
    ) -> Mapping[str, Any]:
        from aoi_orgware.company.service import ensure_service

        return ensure_service(
            slot_root,
            expected_manifest_sha256=expected_manifest_sha256,
        )

    def service_status(self, slot_root: Path) -> Mapping[str, Any]:
        from aoi_orgware.company.service import service_status

        return service_status(slot_root)

    def stop_service(
        self,
        slot_root: Path,
        *,
        timeout_seconds: float = 5.0,
        expected_manifest_sha256: str | None = None,
    ) -> Mapping[str, Any]:
        from aoi_orgware.company.service import stop_service

        return stop_service(
            slot_root,
            timeout_seconds=timeout_seconds,
            expected_manifest_sha256=expected_manifest_sha256,
        )


def default_services() -> CompanyRuntimeServices:
    return _DefaultServices()


def _bounded_timeout(value: float, *, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise CompanyRuntimeCommandError(f"{label} must be a finite positive number")
    numeric = float(value)
    if not math.isfinite(numeric) or not 0.0 < numeric <= 300.0:
        raise CompanyRuntimeCommandError(f"{label} must be in the range (0, 300] seconds")
    return numeric


def _resolve_target(
    *,
    company_id: str | None,
    services: CompanyRuntimeServices,
    cwd: Path | None,
) -> BoundCompanyTarget:
    try:
        target = services.resolve_bound_company((cwd or Path.cwd()).resolve(), company_id)
    except CompanyRuntimeCommandError:
        raise
    except Exception as exc:
        requested = f" {company_id!r}" if company_id else ""
        raise CompanyRuntimeCommandError(
            f"cannot resolve the repo-bound AOI company{requested}: {exc}",
        ) from exc
    if not target.company_id or not target.manifest_sha256 or not isinstance(target.slot_root, Path):
        raise CompanyRuntimeCommandError("discovery returned an incomplete bound-company target")
    return target


def _public_company(target: BoundCompanyTarget) -> dict[str, Any]:
    return {
        "company_id": target.company_id,
        "manifest_sha256": target.manifest_sha256,
        "discovery_service_state": target.service_state,
        "warnings": list(target.warnings),
    }


def _public_service_status(status: Mapping[str, Any]) -> dict[str, Any]:
    state = status.get("state")
    if not isinstance(state, str) or not state:
        raise CompanyRuntimeCommandError("resident service returned no valid lifecycle state")
    value: dict[str, Any] = {"state": state}
    reason = status.get("reason")
    if isinstance(reason, str) and reason:
        value["reason"] = reason
    descriptor = status.get("descriptor")
    if isinstance(descriptor, Mapping):
        public_descriptor: dict[str, Any] = {
            key: descriptor[key]
            for key in _PUBLIC_DESCRIPTOR_KEYS
            if key in descriptor and key != "company"
        }
        company = descriptor.get("company")
        if isinstance(company, Mapping):
            public_descriptor["company"] = {
                key: company[key]
                for key in _PUBLIC_DESCRIPTOR_COMPANY_KEYS
                if key in company
            }
        value["descriptor"] = public_descriptor
    control = status.get("status")
    if isinstance(control, Mapping):
        value["control"] = {
            key: control[key]
            for key in _PUBLIC_STATUS_KEYS
            if key in control
        }
    return value


def _verify_service_binding(
    target: BoundCompanyTarget,
    status: Mapping[str, Any],
) -> None:
    state = status.get("state")
    if state == "unavailable":
        return
    if state not in {"running", "stopping"}:
        raise CompanyRuntimeCommandError(
            "resident service returned an invalid lifecycle state",
        )
    descriptor = status.get("descriptor")
    company = descriptor.get("company") if isinstance(descriptor, Mapping) else None
    if (
        not isinstance(company, Mapping)
        or company.get("company_id") != target.company_id
        or company.get("manifest_sha256") != target.manifest_sha256
    ):
        raise CompanyRuntimeCommandError(
            "resident service differs from the repo-bound company target",
        )
    _service_instance_id(status)


def _service_instance_id(status: Mapping[str, Any]) -> str:
    descriptor = status.get("descriptor")
    control = status.get("status")
    descriptor_id = (
        descriptor.get("service_instance_id")
        if isinstance(descriptor, Mapping)
        else None
    )
    control_id = (
        control.get("service_instance_id")
        if isinstance(control, Mapping)
        else None
    )
    if (
        not isinstance(descriptor_id, str)
        or not descriptor_id
        or control_id != descriptor_id
    ):
        raise CompanyRuntimeCommandError(
            "resident service instance binding is invalid",
        )
    return descriptor_id


def _result(target: BoundCompanyTarget, status: Mapping[str, Any]) -> dict[str, Any]:
    _verify_service_binding(target, status)
    return {"company": _public_company(target), "service": _public_service_status(status)}


def _verified_dashboard_url(status: Mapping[str, Any]) -> str:
    if status.get("state") != "running":
        raise CompanyRuntimeCommandError(
            "company supervisor is not running; run `aoi supervisor ensure` first",
        )
    descriptor = status.get("descriptor")
    if not isinstance(descriptor, Mapping):
        raise CompanyRuntimeCommandError("running supervisor has no verified public descriptor")
    value = descriptor.get("dashboard_url")
    if not isinstance(value, str):
        raise CompanyRuntimeCommandError("running supervisor has no verified Dashboard URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise CompanyRuntimeCommandError(
            "resident service returned a noncanonical loopback Dashboard URL",
        ) from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/"
        or parsed.query
        or parsed.fragment
        or value != f"http://127.0.0.1:{port}/"
    ):
        raise CompanyRuntimeCommandError("resident service returned a noncanonical loopback Dashboard URL")
    return value


def supervisor_ensure(
    *,
    company_id: str | None = None,
    services: CompanyRuntimeServices | None = None,
    cwd: Path | None = None,
) -> dict[str, Any]:
    active_services = services or default_services()
    target = _resolve_target(company_id=company_id, services=active_services, cwd=cwd)
    try:
        status = active_services.ensure_service(
            target.slot_root,
            expected_manifest_sha256=target.manifest_sha256,
        )
    except Exception as exc:
        raise CompanyRuntimeCommandError(f"could not ensure company supervisor: {exc}") from exc
    if status.get("state") != "running":
        raise CompanyRuntimeCommandError(
            "company supervisor ensure did not produce a running service",
        )
    return _result(target, status)


def supervisor_status(
    *,
    company_id: str | None = None,
    services: CompanyRuntimeServices | None = None,
    cwd: Path | None = None,
) -> dict[str, Any]:
    active_services = services or default_services()
    target = _resolve_target(company_id=company_id, services=active_services, cwd=cwd)
    try:
        status = active_services.service_status(target.slot_root)
    except Exception as exc:
        raise CompanyRuntimeCommandError(f"could not read company supervisor status: {exc}") from exc
    return _result(target, status)


def supervisor_stop(
    *,
    company_id: str | None = None,
    services: CompanyRuntimeServices | None = None,
    cwd: Path | None = None,
    timeout_seconds: float = 5.0,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Request graceful stop and wait only for the old instance to disappear."""

    timeout = _bounded_timeout(timeout_seconds, label="supervisor stop timeout")
    active_services = services or default_services()
    command_cwd = (cwd or Path.cwd()).resolve()
    target = _resolve_target(
        company_id=company_id,
        services=active_services,
        cwd=command_cwd,
    )
    if target.service_state == "stopped":
        return {
            "company": _public_company(target),
            "stop_requested": False,
            "already_stopped": True,
            "old_instance_stopped": True,
            "service": {
                "state": "unavailable",
                "reason": "verified_stopped_registry",
            },
        }
    try:
        before = active_services.service_status(target.slot_root)
    except Exception as exc:
        raise CompanyRuntimeCommandError(
            f"could not verify company supervisor before stop: {exc}",
        ) from exc
    _verify_service_binding(target, before)
    old_instance_id = _service_instance_id(before)
    try:
        requested = active_services.stop_service(
            target.slot_root,
            timeout_seconds=timeout,
            expected_manifest_sha256=target.manifest_sha256,
        )
    except Exception as exc:
        raise CompanyRuntimeCommandError(f"could not request graceful supervisor stop: {exc}") from exc
    if (
        requested.get("state") != "stopping"
        or requested.get("service_instance_id") != old_instance_id
    ):
        raise CompanyRuntimeCommandError("resident service did not acknowledge graceful stopping")
    deadline = monotonic() + timeout
    last_status: Mapping[str, Any] = requested
    while True:
        try:
            last_status = active_services.service_status(target.slot_root)
        except Exception as exc:
            raise CompanyRuntimeCommandError(f"could not confirm supervisor stop: {exc}") from exc
        state = last_status.get("state")
        if state in {"running", "stopping"}:
            _verify_service_binding(target, last_status)
            if _service_instance_id(last_status) != old_instance_id:
                return {
                    "company": _public_company(target),
                    "stop_requested": True,
                    "old_instance_stopped": True,
                    "successor_detected": True,
                    "service": _public_service_status(last_status),
                }
        elif (
            state == "unavailable"
            and last_status.get("reason") == "descriptor_absent"
        ):
            confirmed = _resolve_target(
                company_id=target.company_id,
                services=active_services,
                cwd=command_cwd,
            )
            if (
                confirmed.company_id != target.company_id
                or confirmed.manifest_sha256 != target.manifest_sha256
            ):
                raise CompanyRuntimeCommandError(
                    "company binding changed while confirming supervisor stop",
                )
            if confirmed.service_state == "stopped":
                return {
                    "company": _public_company(confirmed),
                    "stop_requested": True,
                    "old_instance_stopped": True,
                    "verified_stopped": True,
                    "service": {
                        "state": "unavailable",
                        "reason": "verified_stopped_registry",
                    },
                }
        if monotonic() >= deadline:
            state = last_status.get("state", "unknown")
            reason = last_status.get("reason", "unavailable")
            raise CompanyRuntimeCommandError(
                "resident supervisor stop could not be verified after "
                f"{timeout:g} seconds (state={state!r}, reason={reason!r}); "
                "it was not force-killed",
            )
        sleep(min(0.05, max(0.0, deadline - monotonic())))


def dashboard_url(
    *,
    company_id: str | None = None,
    services: CompanyRuntimeServices | None = None,
    cwd: Path | None = None,
) -> dict[str, Any]:
    active_services = services or default_services()
    target = _resolve_target(company_id=company_id, services=active_services, cwd=cwd)
    try:
        status = active_services.service_status(target.slot_root)
    except Exception as exc:
        raise CompanyRuntimeCommandError(f"could not read company supervisor status: {exc}") from exc
    _verify_service_binding(target, status)
    return {"company": _public_company(target), "dashboard_url": _verified_dashboard_url(status)}


def dashboard_open(
    *,
    company_id: str | None = None,
    services: CompanyRuntimeServices | None = None,
    cwd: Path | None = None,
    opener: Callable[[str], bool] = webbrowser.open,
) -> dict[str, Any]:
    result = dashboard_url(company_id=company_id, services=services, cwd=cwd)
    url = cast(str, result["dashboard_url"])
    try:
        opened = opener(url)
    except Exception as exc:
        raise CompanyRuntimeCommandError(f"could not open verified Dashboard URL: {exc}") from exc
    if not opened:
        raise CompanyRuntimeCommandError("browser declined the verified Dashboard URL")
    return {**result, "opened": True}


def emit(payload: Any, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif isinstance(payload, Mapping):
        for key, value in payload.items():
            print(f"{key}: {value}")
    else:
        print(payload)


def _run(args: argparse.Namespace, operation: Callable[..., dict[str, Any]]) -> int:
    result = operation(company_id=getattr(args, "company_id", None))
    emit(result, bool(getattr(args, "json", False)))
    return 0


def cmd_supervisor_ensure(args: argparse.Namespace, _paths: Any = None) -> int:
    return _run(args, supervisor_ensure)


def cmd_supervisor_status(args: argparse.Namespace, _paths: Any = None) -> int:
    return _run(args, supervisor_status)


def cmd_supervisor_stop(args: argparse.Namespace, _paths: Any = None) -> int:
    return _run(args, supervisor_stop)


def cmd_dashboard_url(args: argparse.Namespace, _paths: Any = None) -> int:
    return _run(args, dashboard_url)


def cmd_dashboard_open(args: argparse.Namespace, _paths: Any = None) -> int:
    return _run(args, dashboard_open)


def _target_options(parser: argparse.ArgumentParser, add_json_argument: JsonArgumentRegistrar) -> None:
    parser.add_argument("--company-id")
    add_json_argument(parser)


def register_company_runtime_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register ``supervisor`` and ``dashboard`` nested command families."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "company runtime command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}",
        )

    supervisor = subparsers.add_parser("supervisor")
    supervisor_actions = supervisor.add_subparsers(dest="supervisor_action", required=True)
    for name, handler_name in (
        ("ensure", "supervisor_ensure"),
        ("status", "supervisor_status"),
        ("stop", "supervisor_stop"),
    ):
        parser = supervisor_actions.add_parser(name)
        _target_options(parser, add_json_argument)
        parser.set_defaults(handler=handlers[handler_name])

    dashboard = subparsers.add_parser("dashboard")
    dashboard_actions = dashboard.add_subparsers(dest="dashboard_action", required=True)
    for name, handler_name in (("url", "dashboard_url"), ("open", "dashboard_open")):
        parser = dashboard_actions.add_parser(name)
        _target_options(parser, add_json_argument)
        parser.set_defaults(handler=handlers[handler_name])


__all__ = [
    "BoundCompanyTarget",
    "CompanyRuntimeCommandError",
    "CompanyRuntimeServices",
    "cmd_dashboard_open",
    "cmd_dashboard_url",
    "cmd_supervisor_ensure",
    "cmd_supervisor_status",
    "cmd_supervisor_stop",
    "dashboard_open",
    "dashboard_url",
    "default_services",
    "register_company_runtime_commands",
    "supervisor_ensure",
    "supervisor_status",
    "supervisor_stop",
]
