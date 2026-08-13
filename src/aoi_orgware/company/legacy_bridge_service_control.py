"""Route and resident-response helpers for legacy-bridge control.

This module owns bridge-specific HTTP classification and response derivation.
It deliberately has no HTTP listener, queue, retry loop, or import of
``service``: only the resident service owns those capabilities.
"""
from __future__ import annotations

from http import HTTPStatus
from typing import Any, NamedTuple, NoReturn

from .contracts import CompanyContractError
from .legacy_bridge_control_protocol import (
    MAX_LEGACY_BRIDGE_PRESTART_CONTROL_BYTES,
    LegacyBridgeControlProtocolError,
    LegacyBridgePrestartQueryCommand,
    derive_legacy_bridge_prestart_response,
    parse_legacy_bridge_prestart_query,
)
from .legacy_bridge_ingest_protocol import (
    MAX_LEGACY_BRIDGE_INGEST_CONTROL_BYTES,
    LegacyBridgeIngestCommand,
    LegacyBridgeIngestProtocolError,
    build_legacy_bridge_ingest_wire_result,
    parse_legacy_bridge_ingest,
)
from .legacy_bridge_job_terminal_protocol import (
    LEGACY_BRIDGE_JOB_TERMINAL_RESULT_SCHEMA,
    MAX_LEGACY_BRIDGE_JOB_TERMINAL_CONTROL_BYTES,
    LegacyBridgeJobTerminalCommand,
    LegacyBridgeJobTerminalProtocolError,
    parse_legacy_bridge_job_terminal_reconcile,
)
from .legacy_bridge_job_terminal_publisher import (
    LegacyBridgeJobTerminalPublicationError,
    publish_legacy_bridge_job_terminal,
)
from .legacy_bridge_publisher import (
    LegacyBridgePublicationError,
    publish_legacy_bridge_snapshot,
)
from .ledger import LedgerAppendResult, LedgerTransactionRecord
from .state import CompanyProjectionDegradedError, CompanyStateError
from .supervisor import (
    CompanySupervisor,
    CompanySupervisorDashboardRefreshError,
)


LEGACY_BRIDGE_PRESTART_QUERY_ROUTE = "/control/v1/legacy-bridge/prestart/query"
LEGACY_BRIDGE_INGEST_ROUTE = "/control/v1/legacy-bridge/ingest"
LEGACY_BRIDGE_JOB_TERMINAL_ROUTE = (
    "/control/v1/legacy-bridge/job-terminal/reconcile"
)
LEGACY_BRIDGE_CONTROL_ROUTES = frozenset(
    {
        LEGACY_BRIDGE_PRESTART_QUERY_ROUTE,
        LEGACY_BRIDGE_INGEST_ROUTE,
        LEGACY_BRIDGE_JOB_TERMINAL_ROUTE,
    },
)
LegacyBridgeResidentCommand = (
    LegacyBridgePrestartQueryCommand | LegacyBridgeIngestCommand
    | LegacyBridgeJobTerminalCommand
)


class LegacyBridgeServiceControlError(CompanyContractError):
    """A legacy bridge route has invalid bounded control input."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class LegacyBridgeServiceExecutionError(Exception):
    """One classified resident execution outcome, not a protocol error."""

    def __init__(
        self,
        status: HTTPStatus,
        code: str,
        effect: str | None = None,
        cursor: int | None = None,
    ) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.effect = effect
        self.cursor = cursor


class LegacyBridgeControlOperation(NamedTuple):
    """One parsed route result, retaining explicit mutation semantics."""

    command: LegacyBridgeResidentCommand
    mutation: bool
    operation: str


def _fail(code: str) -> NoReturn:
    raise LegacyBridgeServiceControlError(code)


def _committed_cursor(value: Any) -> int | None:
    """Return a durable cursor only from the exact append-result shape."""

    if type(value) is not LedgerAppendResult:
        return None
    record = value.record
    if type(record) is not LedgerTransactionRecord:
        return None
    cursor = record.global_sequence
    if type(cursor) is not int or cursor < 1:
        return None
    return cursor


def _committed_ingest_failure(
    value: Any,
    *,
    code: str,
) -> LegacyBridgeServiceExecutionError:
    """Classify a post-commit failure without inventing a recovery cursor."""

    cursor = _committed_cursor(value)
    if cursor is None:
        return LegacyBridgeServiceExecutionError(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "effect_unknown",
            "effect_unknown",
        )
    return LegacyBridgeServiceExecutionError(
        HTTPStatus.INTERNAL_SERVER_ERROR,
        code,
        "committed",
        cursor,
    )


def legacy_bridge_control_body_limit(route: str) -> int:
    """Return the bounded parser input limit for exactly one known route."""

    if route == LEGACY_BRIDGE_PRESTART_QUERY_ROUTE:
        return MAX_LEGACY_BRIDGE_PRESTART_CONTROL_BYTES
    if route == LEGACY_BRIDGE_INGEST_ROUTE:
        return MAX_LEGACY_BRIDGE_INGEST_CONTROL_BYTES
    if route == LEGACY_BRIDGE_JOB_TERMINAL_ROUTE:
        return MAX_LEGACY_BRIDGE_JOB_TERMINAL_CONTROL_BYTES
    _fail("unsupported_legacy_bridge_route")


def parse_legacy_bridge_control_request(
    route: str,
    value: Any,
) -> LegacyBridgeControlOperation:
    """Classify and parse one bounded HTTP body without service authority."""

    try:
        if route == LEGACY_BRIDGE_PRESTART_QUERY_ROUTE:
            return LegacyBridgeControlOperation(
                parse_legacy_bridge_prestart_query(value),
                False,
                "legacy_bridge_prestart",
            )
        if route == LEGACY_BRIDGE_INGEST_ROUTE:
            return LegacyBridgeControlOperation(
                parse_legacy_bridge_ingest(value),
                True,
                "legacy_bridge_ingest",
            )
        if route == LEGACY_BRIDGE_JOB_TERMINAL_ROUTE:
            return LegacyBridgeControlOperation(
                parse_legacy_bridge_job_terminal_reconcile(value),
                True,
                "legacy_bridge_job_terminal",
            )
    except (
        LegacyBridgeControlProtocolError,
        LegacyBridgeIngestProtocolError,
        LegacyBridgeJobTerminalProtocolError,
    ) as exc:
        raise LegacyBridgeServiceControlError(exc.code) from exc
    _fail("unsupported_legacy_bridge_route")


def legacy_bridge_control_is_mutation(
    command: LegacyBridgeResidentCommand,
) -> bool:
    """Keep timeout/effect handling tied to the exact command type."""

    return legacy_bridge_control_spec(command)[0]


def legacy_bridge_control_spec(
    command: LegacyBridgeResidentCommand,
) -> tuple[bool, str]:
    """Return the authoritative mutation and queue-operation pair."""

    if type(command) is LegacyBridgePrestartQueryCommand:
        return False, "legacy_bridge_prestart"
    if type(command) is LegacyBridgeIngestCommand:
        return True, "legacy_bridge_ingest"
    if type(command) is LegacyBridgeJobTerminalCommand:
        return True, "legacy_bridge_job_terminal"
    _fail("unsupported_legacy_bridge_command")


def is_legacy_bridge_control_command(value: Any) -> bool:
    """Identify the two exact command classes accepted by this helper."""

    return type(value) in {
        LegacyBridgePrestartQueryCommand,
        LegacyBridgeIngestCommand,
        LegacyBridgeJobTerminalCommand,
    }


def legacy_bridge_control_operation(
    command: LegacyBridgeResidentCommand,
) -> str:
    """Return the stable service operation label for one exact command."""

    return legacy_bridge_control_spec(command)[1]


def derive_legacy_bridge_resident_response(
    supervisor: CompanySupervisor,
    command: LegacyBridgeResidentCommand,
) -> dict[str, Any]:
    """Derive one queue-owner response; no listener or retry is involved."""

    if type(supervisor) is not CompanySupervisor:
        _fail("invalid_company_supervisor")
    if type(command) is LegacyBridgePrestartQueryCommand:
        try:
            return derive_legacy_bridge_prestart_response(
                supervisor._state,
                command,
            ).as_dict()
        except CompanyStateError as exc:
            raise LegacyBridgeServiceExecutionError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "legacy_bridge_prestart_unavailable",
            ) from exc
        except Exception as exc:
            raise LegacyBridgeServiceExecutionError(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "legacy_bridge_prestart_failed",
            ) from exc
    if type(command) is LegacyBridgeIngestCommand:
        try:
            result = publish_legacy_bridge_snapshot(
                supervisor,
                command.source_document,
                task_identity_digest=command.task_identity_digest,
                legacy_archive_sha256=command.legacy_archive_sha256,
                received_at=command.received_at,
            )
            return build_legacy_bridge_ingest_wire_result(command, result).as_dict()
        except LegacyBridgePublicationError as exc:
            raise LegacyBridgeServiceExecutionError(
                HTTPStatus.CONFLICT,
                "legacy_bridge_ingest_rejected",
            ) from exc
        except CompanyProjectionDegradedError as exc:
            raise _committed_ingest_failure(
                exc.result,
                code="committed_projection_degraded",
            ) from exc
        except CompanySupervisorDashboardRefreshError as exc:
            raise _committed_ingest_failure(
                exc.result,
                code="committed_dashboard_refresh_failed",
            ) from exc
        except CompanyStateError as exc:
            raise LegacyBridgeServiceExecutionError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "legacy_bridge_ingest_unavailable",
            ) from exc
        except Exception as exc:
            raise LegacyBridgeServiceExecutionError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "effect_unknown",
                "effect_unknown",
            ) from exc
    if type(command) is LegacyBridgeJobTerminalCommand:
        try:
            terminal_result = publish_legacy_bridge_job_terminal(
                supervisor,
                command.terminal_evidence,
                command.terminal_artifacts,
            )
            if (
                terminal_result.effect != "committed"
                or terminal_result.global_sequence is None
            ):
                raise LegacyBridgeServiceExecutionError(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "effect_unknown",
                    "effect_unknown",
                )
            return {
                "schema_version": LEGACY_BRIDGE_JOB_TERMINAL_RESULT_SCHEMA,
                "service_instance_id": command.service_instance_id,
                "company_id": command.company_id,
                "company_incarnation": command.company_incarnation,
                "lock_domain_generation": command.lock_domain_generation,
                "manifest_sha256": command.manifest_sha256,
                **terminal_result._asdict(),
            }
        except LegacyBridgeServiceExecutionError:
            raise
        except LegacyBridgeJobTerminalPublicationError as exc:
            raise LegacyBridgeServiceExecutionError(
                HTTPStatus.CONFLICT,
                "legacy_bridge_job_terminal_rejected",
            ) from exc
        except CompanyProjectionDegradedError as exc:
            raise _committed_ingest_failure(
                exc.result,
                code="committed_projection_degraded",
            ) from exc
        except CompanySupervisorDashboardRefreshError as exc:
            raise _committed_ingest_failure(
                exc.result,
                code="committed_dashboard_refresh_failed",
            ) from exc
        except CompanyStateError as exc:
            raise LegacyBridgeServiceExecutionError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "legacy_bridge_job_terminal_unavailable",
            ) from exc
        except Exception as exc:
            raise LegacyBridgeServiceExecutionError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "effect_unknown",
                "effect_unknown",
            ) from exc
    _fail("unsupported_legacy_bridge_command")


__all__ = [
    "LEGACY_BRIDGE_CONTROL_ROUTES",
    "LEGACY_BRIDGE_INGEST_ROUTE",
    "LEGACY_BRIDGE_JOB_TERMINAL_ROUTE",
    "LEGACY_BRIDGE_PRESTART_QUERY_ROUTE",
    "LegacyBridgeControlOperation",
    "LegacyBridgeResidentCommand",
    "LegacyBridgeServiceControlError",
    "LegacyBridgeServiceExecutionError",
    "derive_legacy_bridge_resident_response",
    "is_legacy_bridge_control_command",
    "legacy_bridge_control_body_limit",
    "legacy_bridge_control_is_mutation",
    "legacy_bridge_control_operation",
    "legacy_bridge_control_spec",
    "parse_legacy_bridge_control_request",
]
