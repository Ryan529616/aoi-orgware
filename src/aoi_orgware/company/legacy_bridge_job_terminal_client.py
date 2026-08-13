"""Single-attempt client for authenticated legacy job terminal reconcile."""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, NamedTuple, NoReturn

from .discovery import resolve_bound_company
from .legacy_bridge_job_terminal_protocol import (
    LEGACY_BRIDGE_JOB_TERMINAL_RESULT_SCHEMA,
    build_legacy_bridge_job_terminal_command,
    decode_legacy_bridge_job_terminal_result,
)
from .legacy_bridge_service_control import LEGACY_BRIDGE_JOB_TERMINAL_ROUTE
from .service import (
    CompanyServiceOperationError,
    _control_operation_request,
    _resident_admin_descriptor,
)


class LegacyBridgeJobTerminalClientError(RuntimeError):
    """The single terminal reconcile attempt did not return exact success."""

    def __init__(
        self,
        code: str,
        *,
        effect: str | None = None,
        cursor: int | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.effect = effect
        self.cursor = cursor


class LegacyBridgeJobTerminalClientResult(NamedTuple):
    transaction_id: str
    command_id: str
    bridge_scope_id: str
    terminal_key_id: str
    receipt_id: str
    effect: str
    global_sequence: int
    idempotent_replay: bool

    def public_dict(self) -> dict[str, Any]:
        return dict(self._asdict())


def _fail(code: str) -> NoReturn:
    raise LegacyBridgeJobTerminalClientError(code)


def run_legacy_bridge_job_terminal_reconcile(
    repo_root: Path,
    *,
    terminal_evidence: Mapping[str, Any],
    terminal_artifacts: Mapping[str, bytes],
    company_id: str | None = None,
    timeout_seconds: float = 30.0,
) -> LegacyBridgeJobTerminalClientResult:
    """Send one mutation request; never retry an uncertain transport effect."""

    target = resolve_bound_company(repo_root, company_id)
    descriptor = _resident_admin_descriptor(target.slot_root, runtime_root=None)
    company = descriptor.get("company")
    if (
        not isinstance(company, Mapping)
        or company.get("company_id") != target.company_id
        or company.get("company_incarnation")
        != target.manifest.get("company_incarnation")
        or company.get("lock_domain_generation")
        != target.manifest.get("lock_domain_generation")
        or company.get("manifest_sha256") != target.manifest_sha256
    ):
        _fail("resident_descriptor_binding_mismatch")
    command = build_legacy_bridge_job_terminal_command(
        service_instance_id=str(descriptor["service_instance_id"]),
        company_id=target.company_id,
        company_incarnation=int(company["company_incarnation"]),
        lock_domain_generation=int(company["lock_domain_generation"]),
        manifest_sha256=target.manifest_sha256,
        terminal_evidence=terminal_evidence,
        terminal_artifacts=terminal_artifacts,
    )
    try:
        wire = _control_operation_request(
            descriptor,
            path=LEGACY_BRIDGE_JOB_TERMINAL_ROUTE,
            token=str(descriptor["bearer_token"]),
            payload=command.as_dict(),
            timeout_seconds=timeout_seconds,
            expected_schema=LEGACY_BRIDGE_JOB_TERMINAL_RESULT_SCHEMA,
            mutation=True,
        )
        result = decode_legacy_bridge_job_terminal_result(wire, command=command)
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except CompanyServiceOperationError as exc:
        raise LegacyBridgeJobTerminalClientError(
            exc.code, effect=exc.effect, cursor=exc.cursor,
        ) from exc
    except LegacyBridgeJobTerminalClientError:
        raise
    except Exception as exc:
        raise LegacyBridgeJobTerminalClientError(
            "terminal_response_invalid",
            effect="effect_unknown",
        ) from exc
    return LegacyBridgeJobTerminalClientResult(
        result.transaction_id,
        result.command_id,
        result.bridge_scope_id,
        result.terminal_key_id,
        result.receipt_id,
        result.effect,
        result.global_sequence,
        result.idempotent_replay,
    )


__all__ = [
    "LegacyBridgeJobTerminalClientError",
    "LegacyBridgeJobTerminalClientResult",
    "run_legacy_bridge_job_terminal_reconcile",
]
