"""Resident, single-writer service wrapper for the AOI company Supervisor.

This module deliberately keeps runtime discovery outside the company slot.  A
descriptor is not ledger evidence and carries no company mutation authority;
it lets local clients discover the read-only Dashboard plus the authenticated
administrative and provider-specific telemetry endpoints of the process that
currently owns the company lock.  Every ledger mutation is still serialized
onto that resident owner thread.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import queue
import re
import secrets
import subprocess
import sys
import threading
import time
from typing import Any, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)
import uuid

from .checkpoint import verify_plain_checkpoint
from .contracts import (
    MAX_PROVIDER_TELEMETRY_RAW_BYTES,
    validate_takeover_capability,
)
from .control_protocol import (
    CHIEF_TAKEOVER_CONSUME_SCHEMA,
    CHIEF_TAKEOVER_CONSUME_RESULT_SCHEMA,
    CHIEF_TAKEOVER_PREPARE_SCHEMA,
    CHIEF_TAKEOVER_PREPARE_RESULT_SCHEMA,
    ChiefControlProtocolError,
    ChiefTakeoverConsumeCommand,
    ChiefTakeoverPrepareCommand,
    parse_chief_takeover_consume,
    parse_chief_takeover_prepare,
)
from .department_control_protocol import (
    DEPARTMENT_DISPATCH_RESULT_SCHEMA,
    DEPARTMENT_DISPATCH_SCHEMA,
    DepartmentControlProtocolError,
    DepartmentDispatchCommand,
    parse_department_dispatch,
)
from .work_definition_control_protocol import (
    WORK_DEFINITION_ENFORCEMENT_ACTIVATE_SCHEMA,
    WORK_DEFINITION_ENFORCEMENT_RESULT_SCHEMA,
    WORK_DEFINITION_REGISTER_RESULT_SCHEMA,
    WORK_DEFINITION_REGISTER_SCHEMA,
    WorkDefinitionControlProtocolError,
    WorkDefinitionEnforcementActivateCommand,
    WorkDefinitionRegisterCommand,
    parse_work_definition_enforcement_activate,
    parse_work_definition_register,
)
from .ledger import (
    LedgerAppendResult,
    LedgerCommitEffectUnknownError,
    LedgerConflictError,
    LedgerError,
)
from .legacy_bridge_control_protocol import (
    LEGACY_BRIDGE_PRESTART_RESULT_SCHEMA,
    MAX_LEGACY_BRIDGE_PRESTART_CONTROL_BYTES,
    LegacyBridgeControlProtocolError,
    LegacyBridgePrestartQueryCommand,
    derive_legacy_bridge_prestart_response,
    parse_legacy_bridge_prestart_query,
)
from .process_lock import CompanyProcessLockBusyError
from .resident_time import ResidentLogicalEventClock
from .sanitized_export import verify_sanitized_export
from .state import (
    CompanyDeliveryPartialError,
    CompanyDeliverySnapshot,
    CompanyProjectionDegradedError,
    CompanyStateError,
    CompanyStateInvariantError,
)
from .supervisor import (
    ChiefTakeoverResult,
    CompanyChiefTakeoverError,
    CompanyDepartmentDispatchCapacityBlocked,
    CompanyDepartmentLifecycleError,
    CompanySupervisor,
    CompanySupervisorDashboardRefreshError,
    CompanySupervisorError,
    CompanyTelemetryIngestError,
    CompanyWorkDefinitionError,
)


SERVICE_DESCRIPTOR_SCHEMA = "aoi.company.runtime-descriptor.v3"
TELEMETRY_CAPABILITY_SCHEMA = "aoi.company.telemetry-capability.v1"
_CONTROL_SCHEMA = "aoi.company.supervisor-control.v1"
TELEMETRY_INGEST_SCHEMA = "aoi.company.telemetry-ingest.v1"
TELEMETRY_INGEST_RESULT_SCHEMA = "aoi.company.telemetry-ingest-result.v1"
_MAX_DESCRIPTOR_BYTES = 16 * 1024
_MAX_CONTROL_BODY_BYTES = (
    ((MAX_PROVIDER_TELEMETRY_RAW_BYTES + 2) // 3) * 4
    + 16 * 1024
)
_MAX_CONTROL_LENGTH_DIGITS = len(str(_MAX_CONTROL_BODY_BYTES))
_MAX_CONTROL_QUEUE = 64
_CONTROL_QUEUE_RESERVE = 4
_CONTROL_OPERATION_TIMEOUT_SECONDS = 30.0
_MAX_CONTROL_JSON_DEPTH = 16
_CHIEF_TAKEOVER_PREPARE_ROUTE = "/control/v1/chief-takeover/prepare"
_CHIEF_TAKEOVER_CONSUME_ROUTE = "/control/v1/chief-takeover/consume"
_DEPARTMENT_DISPATCH_ROUTE = "/control/v1/departments/dispatch"
_WORK_DEFINITION_REGISTER_ROUTE = "/control/v1/work-definitions/register"
_WORK_DEFINITION_ENFORCEMENT_ROUTE = (
    "/control/v1/work-definitions/enforcement/activate"
)
_LEGACY_BRIDGE_PRESTART_QUERY_ROUTE = (
    "/control/v1/legacy-bridge/prestart/query"
)
_MAX_WORK_DEFINITION_CONTROL_BODY_BYTES = 1024 * 1024
_CHIEF_CAPABILITY_TTL = timedelta(minutes=15)
_CHIEF_GRANT_TTL = timedelta(days=30)
_CHIEF_CONSUMED_AT_MAX_AGE = timedelta(minutes=5)
_CHIEF_FUTURE_CLOCK_SKEW = timedelta(minutes=1)
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
_TELEMETRY_ROUTES = {
    "codex_app_server": "/control/v1/telemetry/codex",
    "claude_hook": "/control/v1/telemetry/claude-hook",
    "otel": "/control/v1/telemetry/otel",
}
_TELEMETRY_ROUTE_SOURCES = {
    path: source_class
    for source_class, path in _TELEMETRY_ROUTES.items()
}
_DASHBOARD_ENVIRONMENT_KINDS = frozenset(
    {"synthetic_canary", "live_company_unverified", "unverified"},
)
_KNOWN_NO_EFFECT_CONTROL_ERRORS = {
    "chief_capability_expired": HTTPStatus.CONFLICT,
    "chief_consumed_at_stale": HTTPStatus.CONFLICT,
    "chief_grant_expiry_invalid": HTTPStatus.CONFLICT,
    "control_busy": HTTPStatus.SERVICE_UNAVAILABLE,
    "forbidden": HTTPStatus.FORBIDDEN,
    "ingest_busy": HTTPStatus.SERVICE_UNAVAILABLE,
    "invalid_adapter_event_id": HTTPStatus.BAD_REQUEST,
    "invalid_adapter_instance_id": HTTPStatus.BAD_REQUEST,
    "invalid_command_id": HTTPStatus.BAD_REQUEST,
    "invalid_company_id": HTTPStatus.BAD_REQUEST,
    "invalid_content_length": HTTPStatus.BAD_REQUEST,
    "invalid_json": HTTPStatus.BAD_REQUEST,
    "invalid_raw_base64": HTTPStatus.BAD_REQUEST,
    "invalid_received_at": HTTPStatus.BAD_REQUEST,
    "invalid_request_fields": HTTPStatus.BAD_REQUEST,
    "invalid_request_schema": HTTPStatus.BAD_REQUEST,
    "invalid_schema_version": HTTPStatus.BAD_REQUEST,
    "invalid_service_instance_id": HTTPStatus.BAD_REQUEST,
    "invalid_telemetry_source": HTTPStatus.UNPROCESSABLE_ENTITY,
    "invalid_transaction_id": HTTPStatus.BAD_REQUEST,
    "invalid_company_binding": HTTPStatus.BAD_REQUEST,
    "invalid_context_manifest": HTTPStatus.BAD_REQUEST,
    "invalid_prompt_base64": HTTPStatus.BAD_REQUEST,
    "invalid_prompt_utf8": HTTPStatus.BAD_REQUEST,
    "invalid_task_revision": HTTPStatus.BAD_REQUEST,
    "invalid_work_definition_bundle": HTTPStatus.BAD_REQUEST,
    "invalid_work_packet": HTTPStatus.BAD_REQUEST,
    "payload_too_large": HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
    "prompt_ref_mismatch": HTTPStatus.BAD_REQUEST,
    "raw_sha256_mismatch": HTTPStatus.BAD_REQUEST,
    "service_binding_mismatch": HTTPStatus.CONFLICT,
    "service_stopping": HTTPStatus.SERVICE_UNAVAILABLE,
    "truncated_request": HTTPStatus.BAD_REQUEST,
    "unsupported_media_type": HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
    "department_dispatch_rejected": HTTPStatus.CONFLICT,
    "department_dispatch_conflict": HTTPStatus.CONFLICT,
    "work_definition_rejected": HTTPStatus.CONFLICT,
    **{
        f"invalid_{name}": HTTPStatus.BAD_REQUEST
        for name in (
            "chief_id", "carrier_id", "term", "epoch", "chief_execution_id",
            "department_id", "enqueue_transaction_id", "enqueue_command_id",
            "admission_transaction_id", "admission_command_id",
            "dispatch_request_id", "reservation_id", "task_id", "packet_id",
            "route_policy_id", "requested_role", "requested_capability_tier",
            "company_incarnation", "lock_domain_generation", "manifest_sha256",
        )
    },
}
_KNOWN_COMMITTED_CONTROL_ERRORS = {
    "committed_pre_takeover_evidence_unavailable":
        HTTPStatus.INTERNAL_SERVER_ERROR,
    "committed_dashboard_refresh_failed":
        HTTPStatus.INTERNAL_SERVER_ERROR,
    "committed_projection_degraded":
        HTTPStatus.INTERNAL_SERVER_ERROR,
}
_WINDOWS_PRIVATE_DIRECTORY_LOCK = threading.Lock()
_WINDOWS_PRIVATE_DIRECTORIES: dict[Path, tuple[int, int]] = {}
_WINDOWS_ACL_SCRIPT = r"""
$ErrorActionPreference='Stop'
$acl=Get-Acl -LiteralPath $env:AOI_RUNTIME_ACL_PATH
$current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$owner=([System.Security.Principal.NTAccount]$acl.Owner).Translate(
  [System.Security.Principal.SecurityIdentifier]
).Value
$rules=@($acl.Access | ForEach-Object {
  [ordered]@{
    type=$_.AccessControlType.ToString()
    sid=$_.IdentityReference.Translate(
      [System.Security.Principal.SecurityIdentifier]
    ).Value
    rights=[int64]$_.FileSystemRights
  }
})
[ordered]@{
  current_user_sid=$current
  owner_sid=$owner
  rules=$rules
} | ConvertTo-Json -Compress -Depth 4
"""


class CompanyServiceError(RuntimeError):
    """The resident company service cannot be safely discovered or started."""


class CompanyServiceUnavailableError(CompanyServiceError):
    """No verified resident service is available for this company slot."""


class CompanyServiceOperationError(CompanyServiceError):
    """A resident control operation was rejected with a stable error code."""

    def __init__(
        self,
        status: int,
        code: str,
        *,
        effect: str | None = None,
        cursor: int | None = None,
    ) -> None:
        super().__init__(f"resident control operation failed: {code}")
        self.status = status
        self.code = code
        self.effect = effect
        self.cursor = cursor


class _ControlRequestError(RuntimeError):
    def __init__(
        self,
        status: HTTPStatus,
        code: str,
        *,
        effect: str | None = None,
        cursor: int | None = None,
    ) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.effect = effect
        self.cursor = cursor


class _DuplicateJsonKeyError(ValueError):
    """The control envelope contained two members with the same name."""


@dataclass(frozen=True)
class _TelemetryIngestCommand:
    service_instance_id: str
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    manifest_sha256: str
    provider: str
    source_class: str
    adapter_instance_id: str
    adapter_event_id: str
    intake_sequence: int
    transaction_id: str
    command_id: str
    received_at: str
    raw: bytes
    raw_sha256: str


_ControlCommand = (
    _TelemetryIngestCommand
    | ChiefTakeoverPrepareCommand
    | ChiefTakeoverConsumeCommand
    | DepartmentDispatchCommand
    | WorkDefinitionRegisterCommand
    | WorkDefinitionEnforcementActivateCommand
    | LegacyBridgePrestartQueryCommand
)


@dataclass
class _PendingControlOperation:
    command: _ControlCommand
    done: threading.Event = field(default_factory=threading.Event)
    response: dict[str, Any] | None = None
    error_status: HTTPStatus | None = None
    error_code: str | None = None
    error_effect: str | None = None
    error_cursor: int | None = None

_PendingTelemetryIngest = _PendingControlOperation
_PendingChiefPrepare = _PendingControlOperation

class _PrioritizedControlQueue:
    def __init__(self, *, maxsize: int) -> None:
        self._queue: queue.PriorityQueue[
            tuple[int, int, _PendingControlOperation | None]
        ] = queue.PriorityQueue(maxsize=maxsize)
        self._sequence = 0
        self._sequence_lock = threading.Lock()

    def put_nowait(self, item: _PendingControlOperation | None) -> None:
        if item is None:
            priority = -1
        elif isinstance(item.command, _TelemetryIngestCommand):
            priority = 1
        else:
            priority = 0
        with self._sequence_lock:
            sequence = self._sequence
            self._sequence += 1
        self._queue.put_nowait((priority, sequence, item))

    def get(self, *, timeout: float) -> _PendingControlOperation | None:
        return self._queue.get(timeout=timeout)[2]

    def get_nowait(self) -> _PendingControlOperation | None:
        return self._queue.get_nowait()[2]

    def qsize(self) -> int:
        return self._queue.qsize()

    def empty(self) -> bool:
        return self._queue.empty()


def _bounded_seconds(
    value: float,
    *,
    label: str,
    maximum: float,
) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or value <= 0
        or value > maximum
    ):
        raise CompanyServiceError(
            f"{label} must be finite and between 0 and {maximum:g} seconds",
        )
    return float(value)


def _canonical_control_id(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise _ControlRequestError(
            HTTPStatus.BAD_REQUEST,
            f"invalid_{label}",
        )
    return value


def _control_timestamp(value: Any) -> str:
    if (
        not isinstance(value, str)
        or _TIMESTAMP_RE.fullmatch(value) is None
    ):
        raise _ControlRequestError(
            HTTPStatus.BAD_REQUEST,
            "invalid_received_at",
        )
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value,
        )
    except ValueError as exc:
        raise _ControlRequestError(
            HTTPStatus.BAD_REQUEST,
            "invalid_received_at",
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _ControlRequestError(
            HTTPStatus.BAD_REQUEST,
            "invalid_received_at",
        )
    return value


def _parsed_control_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(
        value[:-1] + "+00:00" if value.endswith("Z") else value,
    )
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp is not timezone-aware")
    return parsed.astimezone(timezone.utc)


def _trusted_utc_now() -> datetime:
    """Return the resident owner's wall clock for freshness decisions."""

    return datetime.now(timezone.utc)


def _utc_timestamp(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc)
    timespec = "microseconds" if normalized.microsecond else "seconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def _takeover_artifact_ids(capability_id: str) -> tuple[str, str]:
    digest = hashlib.sha256(capability_id.encode("utf-8")).hexdigest()
    # Keep the checkpoint directory short enough for non-long-path Windows
    # installations.  The separate checkpoint/export namespaces make the same
    # 96-bit suffix unambiguous, and divergent collisions fail closed.
    identifier = f"cto-{digest[:24]}"
    return (
        identifier,
        identifier,
    )


def _strict_json_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            raise _DuplicateJsonKeyError(key)
        value[key] = member
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def _json_depth_within_bound(value: Any, *, maximum: int) -> bool:
    pending: list[tuple[Any, int]] = [(value, 1)]
    while pending:
        member, depth = pending.pop()
        if depth > maximum:
            return False
        if isinstance(member, Mapping):
            pending.extend(
                (child, depth + 1)
                for child in member.values()
            )
        elif isinstance(member, list):
            pending.extend(
                (child, depth + 1)
                for child in member
            )
    return True


def _strict_control_json_bytes(raw: bytes) -> Any:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKeyError,
        RecursionError,
        ValueError,
    ) as exc:
        raise CompanyServiceError(
            "control endpoint returned invalid JSON",
        ) from exc
    if not _json_depth_within_bound(
        value,
        maximum=_MAX_CONTROL_JSON_DEPTH,
    ):
        raise CompanyServiceError(
            "control endpoint returned invalid JSON",
        )
    return value


def _telemetry_ingest_command(
    value: Any,
) -> _TelemetryIngestCommand:
    fields = {
        "schema_version",
        "service_instance_id",
        "company_id",
        "company_incarnation",
        "lock_domain_generation",
        "manifest_sha256",
        "provider",
        "source_class",
        "adapter_instance_id",
        "adapter_event_id",
        "intake_sequence",
        "transaction_id",
        "command_id",
        "received_at",
        "raw_base64",
        "raw_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise _ControlRequestError(
            HTTPStatus.BAD_REQUEST,
            "invalid_request_schema",
        )
    item = dict(value)
    if item["schema_version"] != TELEMETRY_INGEST_SCHEMA:
        raise _ControlRequestError(
            HTTPStatus.BAD_REQUEST,
            "invalid_request_schema",
        )
    provider = item["provider"]
    source_class = item["source_class"]
    if (
        (provider == "codex" and source_class != "codex_app_server")
        or (
            provider == "claude"
            and source_class not in {"claude_hook", "otel"}
        )
        or provider not in {"codex", "claude"}
    ):
        raise _ControlRequestError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "invalid_telemetry_source",
        )
    incarnation = item["company_incarnation"]
    generation = item["lock_domain_generation"]
    intake_sequence = item["intake_sequence"]
    if (
        not isinstance(incarnation, int)
        or isinstance(incarnation, bool)
        or incarnation < 1
        or not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation < 1
        or not isinstance(intake_sequence, int)
        or isinstance(intake_sequence, bool)
        or not 1 <= intake_sequence <= 999_999_999_999
    ):
        raise _ControlRequestError(
            HTTPStatus.BAD_REQUEST,
            "invalid_request_schema",
        )
    manifest_sha256 = item["manifest_sha256"]
    raw_sha256 = item["raw_sha256"]
    raw_base64 = item["raw_base64"]
    if (
        not isinstance(manifest_sha256, str)
        or _SHA256_RE.fullmatch(manifest_sha256) is None
        or not isinstance(raw_sha256, str)
        or _SHA256_RE.fullmatch(raw_sha256) is None
        or not isinstance(raw_base64, str)
        or len(raw_base64.encode("utf-8")) > (
            ((MAX_PROVIDER_TELEMETRY_RAW_BYTES + 2) // 3) * 4
        )
    ):
        raise _ControlRequestError(
            HTTPStatus.BAD_REQUEST,
            "invalid_request_schema",
        )
    try:
        raw = base64.b64decode(
            raw_base64.encode("ascii"),
            validate=True,
        )
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise _ControlRequestError(
            HTTPStatus.BAD_REQUEST,
            "invalid_raw_base64",
        ) from exc
    if len(raw) > MAX_PROVIDER_TELEMETRY_RAW_BYTES:
        raise _ControlRequestError(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "payload_too_large",
        )
    if hashlib.sha256(raw).hexdigest() != raw_sha256:
        raise _ControlRequestError(
            HTTPStatus.BAD_REQUEST,
            "raw_sha256_mismatch",
        )
    return _TelemetryIngestCommand(
        service_instance_id=_canonical_control_id(
            item["service_instance_id"],
            label="service_instance_id",
        ),
        company_id=_canonical_control_id(
            item["company_id"],
            label="company_id",
        ),
        company_incarnation=incarnation,
        lock_domain_generation=generation,
        manifest_sha256=manifest_sha256,
        provider=str(provider),
        source_class=str(source_class),
        adapter_instance_id=_canonical_control_id(
            item["adapter_instance_id"],
            label="adapter_instance_id",
        ),
        adapter_event_id=_canonical_control_id(
            item["adapter_event_id"],
            label="adapter_event_id",
        ),
        intake_sequence=intake_sequence,
        transaction_id=_canonical_control_id(
            item["transaction_id"],
            label="transaction_id",
        ),
        command_id=_canonical_control_id(
            item["command_id"],
            label="command_id",
        ),
        received_at=_control_timestamp(item["received_at"]),
        raw=raw,
        raw_sha256=raw_sha256,
    )


def _absolute_slot(slot_root: str | os.PathLike[str]) -> Path:
    path = Path(slot_root)
    if not path.is_absolute() or ".." in path.parts:
        raise CompanyServiceError("company slot must be an absolute traversal-free path")
    return path.resolve(strict=False)


def _dashboard_environment_kind(value: str) -> str:
    if value not in _DASHBOARD_ENVIRONMENT_KINDS:
        raise CompanyServiceError("Dashboard environment kind is invalid")
    return value


def _slot_sha256(slot_root: Path) -> str:
    return hashlib.sha256(str(slot_root).encode("utf-8")).hexdigest()


def _runtime_companies_root(
    runtime_root: str | os.PathLike[str] | None,
) -> Path:
    if runtime_root is not None:
        root = Path(runtime_root)
        if not root.is_absolute() or ".." in root.parts:
            raise CompanyServiceError("runtime root must be an absolute traversal-free path")
        return root.resolve(strict=False)
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            raise CompanyServiceError("LOCALAPPDATA is required for Windows runtime state")
        return Path(local) / "AOI" / "runtime" / "companies"
    base = os.environ.get("XDG_RUNTIME_DIR")
    if base:
        return Path(base) / "aoi" / "companies"
    # A private cache fallback is preferable to putting runtime keys in the
    # durable company slot.  Directory permissions are verified below.
    return Path.home() / ".cache" / "aoi" / "runtime" / "companies"


def runtime_descriptor_path(
    slot_root: str | os.PathLike[str],
    *,
    runtime_root: str | os.PathLike[str] | None = None,
) -> Path:
    """Return the non-authoritative discovery descriptor path for one slot."""

    slot = _absolute_slot(slot_root)
    return _runtime_companies_root(runtime_root) / f"slot-{_slot_sha256(slot)}.json"


def _mkdir_private(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        resolved = path.resolve(strict=True)
        identity = _windows_directory_identity(resolved)
        with _WINDOWS_PRIVATE_DIRECTORY_LOCK:
            if (
                identity[1] != 0
                and _WINDOWS_PRIVATE_DIRECTORIES.get(resolved)
                == identity
            ):
                return
            _verify_windows_private_directory(resolved)
            verified_identity = _windows_directory_identity(resolved)
            if verified_identity != identity:
                raise CompanyServiceError(
                    "Windows runtime directory changed during ACL probe",
                )
            if verified_identity[1] != 0:
                _WINDOWS_PRIVATE_DIRECTORIES[resolved] = (
                    verified_identity
                )
            else:
                _WINDOWS_PRIVATE_DIRECTORIES.pop(resolved, None)
    else:
        os.chmod(path, 0o700)
        mode = path.stat().st_mode & 0o077
        if mode:
            raise CompanyServiceError("runtime directory is accessible by another user")


def _windows_directory_identity(path: Path) -> tuple[int, int]:
    try:
        value = path.stat()
    except OSError as exc:
        raise CompanyServiceError(
            "cannot identify Windows runtime directory",
        ) from exc
    return int(value.st_dev), int(value.st_ino)


def _verify_windows_private_directory(path: Path) -> None:
    environment = dict(os.environ)
    environment["AOI_RUNTIME_ACL_PATH"] = str(path)
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    program_files = os.environ.get(
        "ProgramFiles",
        r"C:\Program Files",
    )
    environment["PSModulePath"] = os.pathsep.join(
        (
            str(Path(program_files) / "WindowsPowerShell" / "Modules"),
            str(
                Path(system_root)
                / "system32"
                / "WindowsPowerShell"
                / "v1.0"
                / "Modules"
            ),
        ),
    )
    options: dict[str, Any] = {}
    if os.name == "nt":
        options["creationflags"] = getattr(
            subprocess,
            "CREATE_NO_WINDOW",
            0,
        )
    try:
        completed = subprocess.run(  # noqa: S603 - fixed OS ACL probe
            [
                str(
                    Path(system_root)
                    / "System32"
                    / "WindowsPowerShell"
                    / "v1.0"
                    / "powershell.exe"
                ),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _WINDOWS_ACL_SCRIPT,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30.0,
            check=False,
            env=environment,
            **options,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CompanyServiceError(
            "cannot verify private Windows runtime ACL",
        ) from exc
    if completed.returncode != 0 or len(completed.stdout) > 64 * 1024:
        raise CompanyServiceError(
            "cannot verify private Windows runtime ACL",
        )
    try:
        value = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompanyServiceError(
            "Windows runtime ACL probe returned invalid data",
        ) from exc
    if not isinstance(value, dict) or set(value) != {
        "current_user_sid",
        "owner_sid",
        "rules",
    }:
        raise CompanyServiceError(
            "Windows runtime ACL probe returned invalid data",
        )
    current_sid = value["current_user_sid"]
    owner_sid = value["owner_sid"]
    rules = value["rules"]
    allowed = {
        current_sid,
        "S-1-3-4",  # OWNER RIGHTS; owner is checked separately.
        "S-1-5-18",  # LocalSystem.
        "S-1-5-32-544",  # Builtin Administrators.
    }
    if (
        not isinstance(current_sid, str)
        or not current_sid.startswith("S-1-")
        or owner_sid not in {
            current_sid,
            "S-1-5-18",
            "S-1-5-32-544",
        }
        or not isinstance(rules, list)
        or any(
            not isinstance(rule, dict)
            or set(rule) != {"type", "sid", "rights"}
            or not isinstance(rule["type"], str)
            or not isinstance(rule["sid"], str)
            or not isinstance(rule["rights"], int)
            or isinstance(rule["rights"], bool)
            for rule in rules
        )
    ):
        raise CompanyServiceError(
            "Windows runtime ACL probe returned invalid data",
        )
    overbroad = [
        str(rule["sid"])
        for rule in rules
        if rule["type"] == "Allow"
        and rule["rights"] != 0
        and rule["sid"] not in allowed
    ]
    if overbroad:
        raise CompanyServiceError(
            "Windows runtime directory grants access outside the "
            "current user, OWNER RIGHTS, SYSTEM, or Administrators",
        )


def _atomic_json_write(path: Path, value: Mapping[str, Any]) -> None:
    _mkdir_private(path.parent)
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > _MAX_DESCRIPTOR_BYTES:
        raise CompanyServiceError("runtime descriptor exceeds its bounded size")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        if os.name != "nt":
            os.chmod(path, 0o600)
            directory = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _read_descriptor(path: Path) -> dict[str, Any] | None:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CompanyServiceError("cannot read company runtime descriptor") from exc
    if not raw or len(raw) > _MAX_DESCRIPTOR_BYTES:
        raise CompanyServiceError("company runtime descriptor has invalid size")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompanyServiceError("company runtime descriptor is invalid JSON") from exc
    if not isinstance(value, dict):
        raise CompanyServiceError("company runtime descriptor is not an object")
    required = {
        "schema_version", "slot_sha256", "slot_path", "company", "pid",
        "service_instance_id", "dashboard_url", "control_url", "bearer_token",
        "telemetry_capabilities",
    }
    if set(value) != required or value["schema_version"] != SERVICE_DESCRIPTOR_SCHEMA:
        raise CompanyServiceError("company runtime descriptor has an invalid schema")
    if not isinstance(value["slot_path"], str) or not isinstance(value["slot_sha256"], str):
        raise CompanyServiceError("company runtime descriptor binding is invalid")
    company = value["company"]
    company_fields = {
        "company_id",
        "company_incarnation",
        "lock_domain_generation",
        "manifest_sha256",
        "pointer_sha256",
    }
    if (
        not isinstance(company, dict)
        or set(company) != company_fields
        or not isinstance(company["company_id"], str)
        or not company["company_id"]
        or not isinstance(company["company_incarnation"], int)
        or isinstance(company["company_incarnation"], bool)
        or company["company_incarnation"] < 1
        or not isinstance(company["lock_domain_generation"], int)
        or isinstance(company["lock_domain_generation"], bool)
        or company["lock_domain_generation"] < 1
        or not isinstance(company["manifest_sha256"], str)
        or _SHA256_RE.fullmatch(company["manifest_sha256"]) is None
        or not isinstance(company["pointer_sha256"], str)
        or _SHA256_RE.fullmatch(company["pointer_sha256"]) is None
        or not isinstance(value["pid"], int)
        or isinstance(value["pid"], bool)
        or value["pid"] < 1
    ):
        raise CompanyServiceError("company runtime descriptor identity is invalid")
    for key in (
        "service_instance_id",
        "dashboard_url",
        "control_url",
        "bearer_token",
    ):
        if not isinstance(value[key], str) or not value[key]:
            raise CompanyServiceError("company runtime descriptor endpoint is invalid")
    try:
        if str(uuid.UUID(value["service_instance_id"])) != value["service_instance_id"]:
            raise ValueError
    except ValueError as exc:
        raise CompanyServiceError(
            "company runtime descriptor instance ID is invalid",
        ) from exc
    if _SHA256_RE.fullmatch(value["bearer_token"]) is None:
        raise CompanyServiceError("company runtime descriptor bearer token is invalid")
    telemetry_capabilities = value["telemetry_capabilities"]
    if (
        not isinstance(telemetry_capabilities, dict)
        or set(telemetry_capabilities) != set(_TELEMETRY_ROUTES)
        or any(
            not isinstance(member, str)
            or not Path(member).is_absolute()
            or ".." in Path(member).parts
            or Path(member).resolve(strict=False).parent
            != path.parent.resolve(strict=False)
            for member in telemetry_capabilities.values()
        )
        or len(set(telemetry_capabilities.values()))
        != len(telemetry_capabilities)
    ):
        raise CompanyServiceError(
            "company runtime descriptor telemetry capabilities are invalid",
        )
    _validated_loopback_url(
        value["dashboard_url"],
        label="Dashboard",
        expected_path="/",
    )
    _validated_loopback_url(
        value["control_url"],
        label="control",
        expected_path="",
    )
    return value


def _read_telemetry_capability(
    capability_path: str | os.PathLike[str],
    *,
    slot: Path,
    runtime_root: str | os.PathLike[str] | None,
    source_class: str,
) -> dict[str, Any]:
    path = Path(capability_path)
    expected_parent = runtime_descriptor_path(
        slot,
        runtime_root=runtime_root,
    ).parent.resolve(strict=False)
    if (
        not path.is_absolute()
        or ".." in path.parts
        or path.resolve(strict=False).parent != expected_parent
    ):
        raise CompanyServiceError(
            "telemetry capability path is outside the company runtime directory",
        )
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise CompanyServiceUnavailableError(
            "telemetry capability is absent",
        ) from exc
    except OSError as exc:
        raise CompanyServiceError(
            "cannot read telemetry capability",
        ) from exc
    if not raw or len(raw) > _MAX_DESCRIPTOR_BYTES:
        raise CompanyServiceError("telemetry capability has invalid size")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKeyError,
        ValueError,
    ) as exc:
        raise CompanyServiceError(
            "telemetry capability is invalid JSON",
        ) from exc
    fields = {
        "schema_version",
        "capability_id",
        "slot_sha256",
        "slot_path",
        "company",
        "service_instance_id",
        "control_url",
        "source_class",
        "bearer_token",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value["schema_version"] != TELEMETRY_CAPABILITY_SCHEMA
        or value["slot_sha256"] != _slot_sha256(slot)
        or value["slot_path"] != str(slot)
        or value["source_class"] != source_class
        or source_class not in _TELEMETRY_ROUTES
    ):
        raise CompanyServiceError(
            "telemetry capability has an invalid binding",
        )
    company = value["company"]
    company_fields = {
        "company_id",
        "company_incarnation",
        "lock_domain_generation",
        "manifest_sha256",
        "pointer_sha256",
    }
    if (
        not isinstance(company, dict)
        or set(company) != company_fields
        or not isinstance(company["company_id"], str)
        or not company["company_id"]
        or not isinstance(company["company_incarnation"], int)
        or isinstance(company["company_incarnation"], bool)
        or company["company_incarnation"] < 1
        or not isinstance(company["lock_domain_generation"], int)
        or isinstance(company["lock_domain_generation"], bool)
        or company["lock_domain_generation"] < 1
        or not isinstance(company["manifest_sha256"], str)
        or _SHA256_RE.fullmatch(company["manifest_sha256"]) is None
        or not isinstance(company["pointer_sha256"], str)
        or _SHA256_RE.fullmatch(company["pointer_sha256"]) is None
        or not isinstance(value["service_instance_id"], str)
        or not isinstance(value["capability_id"], str)
        or not isinstance(value["control_url"], str)
        or not isinstance(value["bearer_token"], str)
        or _SHA256_RE.fullmatch(value["bearer_token"]) is None
    ):
        raise CompanyServiceError(
            "telemetry capability identity is invalid",
        )
    for key in ("service_instance_id", "capability_id"):
        try:
            if str(uuid.UUID(value[key])) != value[key]:
                raise ValueError
        except ValueError as exc:
            raise CompanyServiceError(
                f"telemetry capability {key} is invalid",
            ) from exc
    _validated_loopback_url(
        value["control_url"],
        label="control",
        expected_path="",
    )
    return value


def _validated_loopback_url(
    value: str,
    *,
    label: str,
    expected_path: str,
) -> str:
    """Accept one canonical literal-loopback HTTP origin without redirects."""

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise CompanyServiceError(
            f"company runtime {label} URL is invalid",
        ) from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or port is None
        or not 1 <= port <= 65535
        or parsed.path != expected_path
        or parsed.query
        or parsed.fragment
    ):
        raise CompanyServiceError(
            f"company runtime {label} URL is not canonical loopback HTTP",
        )
    canonical = f"http://127.0.0.1:{port}{expected_path}"
    if value != canonical:
        raise CompanyServiceError(
            f"company runtime {label} URL is not canonical",
        )
    return value


class _NoRedirectHandler(HTTPRedirectHandler):
    """Never let a verified loopback request escape through a redirect."""

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Request | None:
        del req, fp, code, msg, headers, newurl
        return None


def _open_local(request: Request, *, timeout_seconds: float) -> Any:
    return build_opener(_NoRedirectHandler()).open(
        request,
        timeout=timeout_seconds,
    )


def _public_descriptor(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return discovery facts without any authenticated control capability."""

    return {
        key: member
        for key, member in value.items()
        if key not in {"bearer_token", "telemetry_capabilities"}
    }


def _bound_descriptor(
    slot: Path,
    value: Mapping[str, Any],
) -> dict[str, Any]:
    if value.get("slot_path") != str(slot) or value.get("slot_sha256") != _slot_sha256(slot):
        raise CompanyServiceError("runtime descriptor does not bind this company slot")
    return dict(value)


def _control_request(
    descriptor: Mapping[str, Any],
    *,
    method: str,
    path: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    control_url = _validated_loopback_url(
        str(descriptor["control_url"]),
        label="control",
        expected_path="",
    )
    request = Request(
        control_url + path,
        method=method,
        headers={"Authorization": f"Bearer {descriptor['bearer_token']}"},
    )
    try:
        with _open_local(request, timeout_seconds=timeout_seconds) as response:
            raw = response.read(_MAX_DESCRIPTOR_BYTES + 1)
            if response.status != HTTPStatus.OK:
                raise CompanyServiceUnavailableError("resident control endpoint rejected request")
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise CompanyServiceUnavailableError("resident control endpoint is unavailable") from exc
    if len(raw) > _MAX_DESCRIPTOR_BYTES:
        raise CompanyServiceUnavailableError(
            "resident control endpoint response exceeds its bound",
        )
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompanyServiceUnavailableError("resident control endpoint returned invalid JSON") from exc
    if not isinstance(value, dict) or value.get("schema_version") != _CONTROL_SCHEMA:
        raise CompanyServiceUnavailableError("resident control endpoint has an invalid schema")
    return value


def _control_operation_request(
    descriptor: Mapping[str, Any],
    *,
    path: str,
    token: str,
    payload: Mapping[str, Any],
    timeout_seconds: float,
    expected_schema: str = TELEMETRY_INGEST_RESULT_SCHEMA,
    mutation: bool = True,
) -> dict[str, Any]:
    control_url = _validated_loopback_url(
        str(descriptor["control_url"]),
        label="control",
        expected_path="",
    )
    raw_request = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(raw_request) > _MAX_CONTROL_BODY_BYTES:
        raise CompanyServiceError(
            "resident control request exceeds its wire bound",
        )
    request = Request(
        control_url + path,
        data=raw_request,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with _open_local(request, timeout_seconds=timeout_seconds) as response:
            raw = response.read(_MAX_DESCRIPTOR_BYTES + 1)
            if response.status != HTTPStatus.OK:
                raise CompanyServiceUnavailableError(
                    "resident control endpoint rejected request",
                )
    except HTTPError as exc:
        raw_error = exc.read(_MAX_DESCRIPTOR_BYTES + 1)
        code = "effect_unknown" if mutation else "unavailable"
        effect: str | None = "effect_unknown" if mutation else None
        cursor: int | None = None
        if len(raw_error) <= _MAX_DESCRIPTOR_BYTES:
            try:
                error_value = _strict_control_json_bytes(raw_error)
            except CompanyServiceError:
                error_value = None
            if (
                isinstance(error_value, Mapping)
                and isinstance(error_value.get("error"), str)
            ):
                code = str(error_value["error"])
                candidate_effect = error_value.get("effect")
                candidate_cursor = error_value.get("cursor")
                valid_cursor = (
                    type(candidate_cursor) is int
                    and candidate_cursor >= 1
                )
                if not mutation and set(error_value) == {"error"}:
                    effect = None
                elif (
                    set(error_value)
                    in ({"error"}, {"error", "cursor"})
                    and _KNOWN_NO_EFFECT_CONTROL_ERRORS.get(code)
                    == exc.code
                    and candidate_effect is None
                    and (
                        candidate_cursor is None
                        or valid_cursor
                    )
                ):
                    effect = None
                    if valid_cursor:
                        cursor = candidate_cursor
                elif mutation and (
                    set(error_value) == {
                        "error",
                        "effect",
                        "cursor",
                    }
                    and _KNOWN_COMMITTED_CONTROL_ERRORS.get(code)
                    == exc.code
                    and candidate_effect == "committed"
                    and valid_cursor
                ):
                    effect = "committed"
                    cursor = candidate_cursor
                elif mutation and (
                    set(error_value)
                    in (
                        {"error", "effect"},
                        {"error", "effect", "cursor"},
                    )
                    and candidate_effect == "effect_unknown"
                    and (
                        candidate_cursor is None
                        or valid_cursor
                    )
                ):
                    effect = "effect_unknown"
                    if valid_cursor:
                        cursor = candidate_cursor
        raise CompanyServiceOperationError(
            int(exc.code),
            code,
            effect=effect,
            cursor=cursor,
        ) from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise CompanyServiceOperationError(
            int(HTTPStatus.GATEWAY_TIMEOUT),
            "effect_unknown" if mutation else "unavailable",
            effect="effect_unknown" if mutation else None,
        ) from exc
    if len(raw) > _MAX_DESCRIPTOR_BYTES:
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY),
            "effect_unknown" if mutation else "unavailable",
            effect="effect_unknown" if mutation else None,
        )
    try:
        value = _strict_control_json_bytes(raw)
    except CompanyServiceError as exc:
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY),
            "effect_unknown" if mutation else "unavailable",
            effect="effect_unknown" if mutation else None,
        ) from exc
    if (
        not isinstance(value, dict)
        or value.get("schema_version")
        != expected_schema
    ):
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY),
            "effect_unknown" if mutation else "unavailable",
            effect="effect_unknown" if mutation else None,
        )
    return value


def _validated_telemetry_ingest_result(
    value: Any,
    *,
    service_instance_id: str,
    company_id: str,
    provider: str,
    transaction_id: str,
    command_id: str,
) -> dict[str, Any]:
    top_fields = {
        "schema_version",
        "service_instance_id",
        "company_id",
        "cursor",
        "result",
    }
    result_fields = {
        "receipt_id",
        "provider",
        "parse_outcome",
        "normalized_kind",
        "dispatch_join_state",
        "lifecycle_coverage_revision_id",
        "usage_coverage_revision_id",
        "usage_sample_id",
        "transaction_id",
        "command_id",
        "global_sequence",
        "idempotent_replay",
    }
    if type(value) is not dict or set(value) != top_fields:
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY),
            "effect_unknown",
            effect="effect_unknown",
        )
    cursor = value["cursor"]
    result = value["result"]
    if (
        value["schema_version"] != TELEMETRY_INGEST_RESULT_SCHEMA
        or value["service_instance_id"] != service_instance_id
        or value["company_id"] != company_id
        or type(cursor) is not int
        or cursor < 1
        or type(result) is not dict
        or set(result) != result_fields
    ):
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY),
            "effect_unknown",
            effect="effect_unknown",
        )

    required_ids = (
        result["receipt_id"],
        result["lifecycle_coverage_revision_id"],
        result["transaction_id"],
        result["command_id"],
    )
    usage_coverage_id = result["usage_coverage_revision_id"]
    usage_sample_id = result["usage_sample_id"]
    if (
        any(
            type(member) is not str
            or _ID_RE.fullmatch(member) is None
            for member in required_ids
        )
        or type(result["normalized_kind"]) is not str
        or _ID_RE.fullmatch(result["normalized_kind"]) is None
        or type(usage_coverage_id) is not str
        or (
            usage_coverage_id != ""
            and _ID_RE.fullmatch(usage_coverage_id) is None
        )
        or (
            usage_sample_id is not None
            and (
                type(usage_sample_id) is not str
                or _ID_RE.fullmatch(usage_sample_id) is None
            )
        )
        or result["provider"] != provider
        or type(result["parse_outcome"]) is not str
        or result["parse_outcome"] not in {
            "normalized",
            "unsupported_valid",
            "malformed",
        }
        or type(result["dispatch_join_state"]) is not str
        or result["dispatch_join_state"] not in {
            "exact",
            "ambiguous",
            "none",
        }
        or result["transaction_id"] != transaction_id
        or result["command_id"] != command_id
        or type(result["global_sequence"]) is not int
        or result["global_sequence"] != cursor
        or type(result["idempotent_replay"]) is not bool
    ):
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY),
            "effect_unknown",
            effect="effect_unknown",
        )
    return value


def _validated_chief_response_binding(
    value: Any,
    *,
    schema_version: str,
    service_instance_id: str,
    company: Mapping[str, Any],
    additional_fields: set[str],
    mutation: bool,
) -> tuple[dict[str, Any], int]:
    fields = {
        "schema_version",
        "service_instance_id",
        "company_id",
        "company_incarnation",
        "lock_domain_generation",
        "manifest_sha256",
        "cursor",
        *additional_fields,
    }
    code = "effect_unknown" if mutation else "unavailable"
    effect = "effect_unknown" if mutation else None
    if type(value) is not dict or set(value) != fields:
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY),
            code,
            effect=effect,
        )
    cursor = value["cursor"]
    if (
        value["schema_version"] != schema_version
        or value["service_instance_id"] != service_instance_id
        or value["company_id"] != company["company_id"]
        or value["company_incarnation"] != company["company_incarnation"]
        or value["lock_domain_generation"]
        != company["lock_domain_generation"]
        or value["manifest_sha256"] != company["manifest_sha256"]
        or type(cursor) is not int
        or cursor < 1
    ):
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY),
            code,
            effect=effect,
        )
    return value, cursor


def _validated_chief_prepare_result(
    value: Any,
    *,
    service_instance_id: str,
    company: Mapping[str, Any],
    command: ChiefTakeoverPrepareCommand,
) -> dict[str, Any]:
    response, _cursor = _validated_chief_response_binding(
        value,
        schema_version=CHIEF_TAKEOVER_PREPARE_RESULT_SCHEMA,
        service_instance_id=service_instance_id,
        company=company,
        additional_fields={"capability"},
        mutation=False,
    )
    capability_value = response["capability"]
    try:
        capability = validate_takeover_capability(capability_value)
    except ValueError as exc:
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY),
            "unavailable",
        ) from exc
    issued_at = _parsed_control_time(str(capability["issued_at"]))
    expires_at = _parsed_control_time(str(capability["expires_at"]))
    if (
        capability != capability_value
        or capability["company_id"] != command.company_id
        or capability["company_incarnation"]
        != command.company_incarnation
        or capability["lock_domain_generation"]
        != command.lock_domain_generation
        or capability["contender_carrier_id"]
        != command.known_carrier.carrier_id
        or capability["objective_sha256"] != command.objective_sha256
        or capability["scope_sha256"] != command.scope_sha256
        or capability["nonce_sha256"] != command.nonce_sha256
        or capability["user_action_ref"] != command.user_action_ref
        or expires_at - issued_at != _CHIEF_CAPABILITY_TTL
    ):
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY),
            "unavailable",
        )
    return response


def _valid_control_id(value: Any) -> bool:
    return type(value) is str and _ID_RE.fullmatch(value) is not None


def _valid_sha256(value: Any) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _validated_chief_consume_result(
    value: Any,
    *,
    service_instance_id: str,
    company: Mapping[str, Any],
    command: ChiefTakeoverConsumeCommand,
) -> dict[str, Any]:
    response, cursor = _validated_chief_response_binding(
        value,
        schema_version=CHIEF_TAKEOVER_CONSUME_RESULT_SCHEMA,
        service_instance_id=service_instance_id,
        company=company,
        additional_fields={"result", "pre_takeover_evidence"},
        mutation=True,
    )
    result = response["result"]
    result_fields = {
        "outcome",
        "receipt_state",
        "capability_id",
        "consumption_id",
        "transaction_id",
        "command_id",
        "chief_id",
        "carrier_id",
        "term",
        "epoch",
        "global_sequence",
        "idempotent_replay",
    }
    evidence = response["pre_takeover_evidence"]
    evidence_fields = {
        "state",
        "checkpoint_id",
        "checkpoint_manifest_sha256",
        "export_id",
        "export_sha256",
        "cursor",
        "head_sha256",
        "generated_at",
    }
    try:
        capability = validate_takeover_capability(command.capability)
    except ValueError as exc:
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY),
            "effect_unknown",
            effect="effect_unknown",
        ) from exc
    if (
        type(result) is not dict
        or set(result) != result_fields
        or type(evidence) is not dict
        or set(evidence) != evidence_fields
        or result["outcome"] not in {"consumed", "fenced"}
        or result["receipt_state"] != "committed"
        or not all(
            _valid_control_id(result[key])
            for key in (
                "capability_id",
                "consumption_id",
                "transaction_id",
                "command_id",
                "chief_id",
                "carrier_id",
            )
        )
        or result["capability_id"] != capability["capability_id"]
        or result["consumption_id"] != capability["consumption_id"]
        or result["transaction_id"]
        != capability["consumption_transaction_id"]
        or result["command_id"] != capability["consumption_command_id"]
        or result["chief_id"] != capability["resulting_chief_id"]
        or result["carrier_id"] != capability["contender_carrier_id"]
        or type(result["global_sequence"]) is not int
        or result["global_sequence"] != cursor
        or type(result["idempotent_replay"]) is not bool
    ):
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY),
            "effect_unknown",
            effect="effect_unknown",
        )
    if result["outcome"] == "consumed":
        checkpoint_id, export_id = _takeover_artifact_ids(
            str(capability["capability_id"]),
        )
        if (
            type(result["term"]) is not int
            or result["term"] != capability["resulting_term"]
            or type(result["epoch"]) is not int
            or result["epoch"] != capability["resulting_epoch"]
            or evidence["state"] != "pre_takeover_verified"
            or evidence["checkpoint_id"] != checkpoint_id
            or evidence["export_id"] != export_id
            or not _valid_sha256(evidence["checkpoint_manifest_sha256"])
            or not _valid_sha256(evidence["export_sha256"])
            or type(evidence["cursor"]) is not int
            or evidence["cursor"] != cursor - 1
            or evidence["head_sha256"]
            != capability["expected_head_sha256"]
            or evidence["generated_at"] != command.consumed_at
        ):
            raise CompanyServiceOperationError(
                int(HTTPStatus.BAD_GATEWAY),
                "effect_unknown",
                effect="effect_unknown",
            )
    elif (
        result["term"] is not None
        or result["epoch"] is not None
        or evidence["state"] != "not_required_fenced_head_drift"
        or any(
            evidence[key] is not None
            for key in evidence_fields - {"state"}
        )
    ):
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY),
            "effect_unknown",
            effect="effect_unknown",
        )
    return response


def _resident_admin_descriptor(
    slot: Path,
    *,
    runtime_root: str | os.PathLike[str] | None,
) -> dict[str, Any]:
    descriptor = _read_descriptor(
        runtime_descriptor_path(slot, runtime_root=runtime_root),
    )
    if descriptor is None:
        raise CompanyServiceUnavailableError(
            "company service descriptor is absent",
        )
    return _bound_descriptor(slot, descriptor)


def prepare_service_chief_takeover(
    slot_root: str | os.PathLike[str],
    known_carrier: Mapping[str, Any],
    *,
    user_action_ref: str,
    objective_sha256: str,
    scope_sha256: str,
    nonce_sha256: str,
    runtime_root: str | os.PathLike[str] | None = None,
    timeout_seconds: float = _CONTROL_OPERATION_TIMEOUT_SECONDS + 10.0,
) -> dict[str, Any]:
    """Ask the resident owner for one head-bound fresh-user takeover grant."""

    timeout_seconds = _bounded_seconds(
        timeout_seconds,
        label="Chief takeover prepare timeout",
        maximum=300.0,
    )
    slot = _absolute_slot(slot_root)
    descriptor = _resident_admin_descriptor(
        slot,
        runtime_root=runtime_root,
    )
    company = descriptor["company"]
    request_value = {
        "schema_version": CHIEF_TAKEOVER_PREPARE_SCHEMA,
        "service_instance_id": descriptor["service_instance_id"],
        "company_id": company["company_id"],
        "company_incarnation": company["company_incarnation"],
        "lock_domain_generation": company["lock_domain_generation"],
        "manifest_sha256": company["manifest_sha256"],
        "known_carrier": dict(known_carrier),
        "user_action_ref": user_action_ref,
        "objective_sha256": objective_sha256,
        "scope_sha256": scope_sha256,
        "nonce_sha256": nonce_sha256,
    }
    try:
        command = parse_chief_takeover_prepare(request_value)
    except ChiefControlProtocolError as exc:
        raise CompanyServiceError(
            f"Chief takeover prepare request is invalid: {exc.code}",
        ) from exc
    payload = {
        **request_value,
        "known_carrier": command.known_carrier.as_dict(),
    }
    response = _control_operation_request(
        descriptor,
        path=_CHIEF_TAKEOVER_PREPARE_ROUTE,
        token=str(descriptor["bearer_token"]),
        payload=payload,
        timeout_seconds=timeout_seconds,
        expected_schema=CHIEF_TAKEOVER_PREPARE_RESULT_SCHEMA,
        mutation=False,
    )
    return _validated_chief_prepare_result(
        response,
        service_instance_id=str(descriptor["service_instance_id"]),
        company=company,
        command=command,
    )


def consume_service_chief_takeover(
    slot_root: str | os.PathLike[str],
    capability: Mapping[str, Any],
    known_carrier: Mapping[str, Any],
    *,
    consumed_at: str,
    grant_expires_at: str,
    runtime_root: str | os.PathLike[str] | None = None,
    timeout_seconds: float = _CONTROL_OPERATION_TIMEOUT_SECONDS + 10.0,
) -> dict[str, Any]:
    """Consume one prepared capability through the resident sole writer."""

    timeout_seconds = _bounded_seconds(
        timeout_seconds,
        label="Chief takeover consume timeout",
        maximum=300.0,
    )
    slot = _absolute_slot(slot_root)
    descriptor = _resident_admin_descriptor(
        slot,
        runtime_root=runtime_root,
    )
    company = descriptor["company"]
    request_value = {
        "schema_version": CHIEF_TAKEOVER_CONSUME_SCHEMA,
        "service_instance_id": descriptor["service_instance_id"],
        "company_id": company["company_id"],
        "company_incarnation": company["company_incarnation"],
        "lock_domain_generation": company["lock_domain_generation"],
        "manifest_sha256": company["manifest_sha256"],
        "capability": dict(capability),
        "known_carrier": dict(known_carrier),
        "consumed_at": consumed_at,
        "grant_expires_at": grant_expires_at,
    }
    try:
        command = parse_chief_takeover_consume(request_value)
    except ChiefControlProtocolError as exc:
        raise CompanyServiceError(
            f"Chief takeover consume request is invalid: {exc.code}",
        ) from exc
    payload = {
        **request_value,
        "capability": command.capability,
        "known_carrier": command.known_carrier.as_dict(),
    }
    response = _control_operation_request(
        descriptor,
        path=_CHIEF_TAKEOVER_CONSUME_ROUTE,
        token=str(descriptor["bearer_token"]),
        payload=payload,
        timeout_seconds=timeout_seconds,
        expected_schema=CHIEF_TAKEOVER_CONSUME_RESULT_SCHEMA,
        mutation=True,
    )
    return _validated_chief_consume_result(
        response,
        service_instance_id=str(descriptor["service_instance_id"]),
        company=company,
        command=command,
    )


def _validated_department_dispatch_result(
    value: Any,
    *,
    service_instance_id: str,
    company: Mapping[str, Any],
    command: DepartmentDispatchCommand,
) -> dict[str, Any]:
    top_fields = {
        "schema_version", "service_instance_id", "company_id",
        "company_incarnation", "lock_domain_generation", "manifest_sha256",
        "cursor", "enqueue_result", "admission_result", "queued_reason",
    }
    enqueue_fields = {
        "operation", "department_id", "lifecycle_state", "snapshot_id",
        "snapshot_revision", "dispatch_request_id", "dispatch_state",
        "transaction_id", "command_id", "global_sequence", "idempotent_replay",
    }
    admission_fields = {
        "dispatch_request_id", "dispatch_state", "revision", "transaction_id",
        "command_id", "receipt_state", "global_sequence", "execution_id",
        "carrier_id", "idempotent_replay",
    }
    if (
        type(value) is not dict
        or set(value) != top_fields
        or value.get("schema_version") != DEPARTMENT_DISPATCH_RESULT_SCHEMA
        or value.get("service_instance_id") != service_instance_id
        or value.get("company_id") != company["company_id"]
        or value.get("company_incarnation") != company["company_incarnation"]
        or value.get("lock_domain_generation") != company["lock_domain_generation"]
        or value.get("manifest_sha256") != company["manifest_sha256"]
        or type(value.get("cursor")) is not int
        or value["cursor"] < 1
        or type(value.get("enqueue_result")) is not dict
        or set(value["enqueue_result"]) != enqueue_fields
    ):
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY), "effect_unknown", effect="effect_unknown",
        )
    enqueue = value["enqueue_result"]
    if (
        enqueue["operation"] != "enqueue"
        or enqueue["department_id"] != command.department_id
        or enqueue["dispatch_request_id"] != command.dispatch_request_id
        or enqueue["dispatch_state"] != "queued"
        or enqueue["transaction_id"] != command.enqueue_transaction_id
        or enqueue["command_id"] != command.enqueue_command_id
        or type(enqueue["snapshot_id"]) is not str
        or _ID_RE.fullmatch(enqueue["snapshot_id"]) is None
        or type(enqueue["lifecycle_state"]) is not str
        or enqueue["lifecycle_state"] not in {"active", "waking"}
        or type(enqueue["snapshot_revision"]) is not int
        or enqueue["snapshot_revision"] < 1
        or type(enqueue["global_sequence"]) is not int
        or enqueue["global_sequence"] < 1
        or type(enqueue["idempotent_replay"]) is not bool
    ):
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY), "effect_unknown", effect="effect_unknown",
        )
    admission = value["admission_result"]
    queued_reason = value["queued_reason"]
    if admission is None:
        if (
            queued_reason not in {"capacity", "fanout", "unattributed"}
            or value["cursor"] != enqueue["global_sequence"]
        ):
            raise CompanyServiceOperationError(
                int(HTTPStatus.BAD_GATEWAY), "effect_unknown", effect="effect_unknown",
            )
        return value
    if (
        type(admission) is not dict
        or set(admission) != admission_fields
        or queued_reason is not None
        or admission["dispatch_request_id"] != command.dispatch_request_id
        or admission["dispatch_state"] != "admitted"
        or admission["transaction_id"] != command.admission_transaction_id
        or admission["command_id"] != command.admission_command_id
        or admission["receipt_state"] != "committed"
        or admission["execution_id"] is not None
        or admission["carrier_id"] is not None
        or type(admission["revision"]) is not int
        or admission["revision"] < 2
        or type(admission["global_sequence"]) is not int
        or admission["global_sequence"] < enqueue["global_sequence"]
        or value["cursor"] != admission["global_sequence"]
        or type(admission["idempotent_replay"]) is not bool
    ):
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY), "effect_unknown", effect="effect_unknown",
        )
    return value


def dispatch_service_department(
    slot_root: str | os.PathLike[str],
    *,
    chief_id: str,
    carrier_id: str,
    term: int,
    epoch: int,
    chief_execution_id: str,
    department_id: str,
    enqueue_transaction_id: str,
    enqueue_command_id: str,
    admission_transaction_id: str,
    admission_command_id: str,
    dispatch_request_id: str,
    reservation_id: str,
    task_id: str,
    packet_id: str,
    route_policy_id: str,
    requested_role: str,
    requested_capability_tier: str,
    runtime_root: str | os.PathLike[str] | None = None,
    timeout_seconds: float = _CONTROL_OPERATION_TIMEOUT_SECONDS + 10.0,
) -> dict[str, Any]:
    """Ask the resident sole writer to queue then admit one department lead."""

    timeout_seconds = _bounded_seconds(
        timeout_seconds,
        label="department dispatch timeout",
        maximum=300.0,
    )
    slot = _absolute_slot(slot_root)
    descriptor = _resident_admin_descriptor(slot, runtime_root=runtime_root)
    company = descriptor["company"]
    request_value = {
        "schema_version": DEPARTMENT_DISPATCH_SCHEMA,
        "service_instance_id": descriptor["service_instance_id"],
        "company_id": company["company_id"],
        "company_incarnation": company["company_incarnation"],
        "lock_domain_generation": company["lock_domain_generation"],
        "manifest_sha256": company["manifest_sha256"],
        "chief_id": chief_id,
        "carrier_id": carrier_id,
        "term": term,
        "epoch": epoch,
        "chief_execution_id": chief_execution_id,
        "department_id": department_id,
        "enqueue_transaction_id": enqueue_transaction_id,
        "enqueue_command_id": enqueue_command_id,
        "admission_transaction_id": admission_transaction_id,
        "admission_command_id": admission_command_id,
        "dispatch_request_id": dispatch_request_id,
        "reservation_id": reservation_id,
        "task_id": task_id,
        "packet_id": packet_id,
        "route_policy_id": route_policy_id,
        "requested_role": requested_role,
        "requested_capability_tier": requested_capability_tier,
    }
    try:
        command = parse_department_dispatch(request_value)
    except DepartmentControlProtocolError as exc:
        raise CompanyServiceError(
            f"department dispatch request is invalid: {exc.code}",
        ) from exc
    response = _control_operation_request(
        descriptor,
        path=_DEPARTMENT_DISPATCH_ROUTE,
        token=str(descriptor["bearer_token"]),
        payload=command.as_dict(),
        timeout_seconds=timeout_seconds,
        expected_schema=DEPARTMENT_DISPATCH_RESULT_SCHEMA,
        mutation=True,
    )
    return _validated_department_dispatch_result(
        response,
        service_instance_id=str(descriptor["service_instance_id"]),
        company=company,
        command=command,
    )


def _validated_work_definition_register_result(
    value: Any,
    *,
    service_instance_id: str,
    company: Mapping[str, Any],
    command: WorkDefinitionRegisterCommand,
) -> dict[str, Any]:
    response, cursor = _validated_chief_response_binding(
        value,
        schema_version=WORK_DEFINITION_REGISTER_RESULT_SCHEMA,
        service_instance_id=service_instance_id,
        company=company,
        additional_fields={"result"},
        mutation=True,
    )
    result = response["result"]
    result_fields = {
        "task_id",
        "task_revision_id",
        "packet_id",
        "transaction_id",
        "command_id",
        "global_sequence",
        "idempotent_replay",
    }
    if (
        type(result) is not dict
        or set(result) != result_fields
        or result["task_id"] != command.task_revision["task_id"]
        or result["task_revision_id"]
        != command.task_revision["task_revision_id"]
        or result["packet_id"] != command.work_packet["packet_id"]
        or result["transaction_id"] != command.transaction_id
        or result["command_id"] != command.command_id
        or type(result["global_sequence"]) is not int
        or result["global_sequence"] != cursor
        or type(result["idempotent_replay"]) is not bool
    ):
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY),
            "effect_unknown",
            effect="effect_unknown",
        )
    return response


def _validated_work_definition_enforcement_result(
    value: Any,
    *,
    service_instance_id: str,
    company: Mapping[str, Any],
    command: WorkDefinitionEnforcementActivateCommand,
) -> dict[str, Any]:
    response, cursor = _validated_chief_response_binding(
        value,
        schema_version=WORK_DEFINITION_ENFORCEMENT_RESULT_SCHEMA,
        service_instance_id=service_instance_id,
        company=company,
        additional_fields={"result"},
        mutation=True,
    )
    result = response["result"]
    result_fields = {
        "gate_id",
        "mode",
        "transaction_id",
        "command_id",
        "global_sequence",
        "idempotent_replay",
    }
    if (
        type(result) is not dict
        or set(result) != result_fields
        or result["gate_id"] != "work-definition-enforcement"
        or result["mode"] != "registered_launch_required"
        or result["transaction_id"] != command.transaction_id
        or result["command_id"] != command.command_id
        or type(result["global_sequence"]) is not int
        or result["global_sequence"] != cursor
        or type(result["idempotent_replay"]) is not bool
    ):
        raise CompanyServiceOperationError(
            int(HTTPStatus.BAD_GATEWAY),
            "effect_unknown",
            effect="effect_unknown",
        )
    return response


def register_service_work_definition(
    slot_root: str | os.PathLike[str],
    task_revision: Mapping[str, Any],
    work_packet: Mapping[str, Any],
    context_manifest: Mapping[str, Any],
    prompt_bytes: bytes,
    *,
    chief_id: str,
    carrier_id: str,
    term: int,
    epoch: int,
    chief_execution_id: str,
    transaction_id: str,
    command_id: str,
    runtime_root: str | os.PathLike[str] | None = None,
    timeout_seconds: float = _CONTROL_OPERATION_TIMEOUT_SECONDS + 10.0,
) -> dict[str, Any]:
    """Register one immutable work bundle through the resident sole writer."""

    timeout_seconds = _bounded_seconds(
        timeout_seconds,
        label="work definition registration timeout",
        maximum=300.0,
    )
    if type(prompt_bytes) is not bytes:
        raise CompanyServiceError("work definition prompt must be bytes")
    slot = _absolute_slot(slot_root)
    descriptor = _resident_admin_descriptor(slot, runtime_root=runtime_root)
    company = descriptor["company"]
    request_value = {
        "schema_version": WORK_DEFINITION_REGISTER_SCHEMA,
        "service_instance_id": descriptor["service_instance_id"],
        "company_id": company["company_id"],
        "company_incarnation": company["company_incarnation"],
        "lock_domain_generation": company["lock_domain_generation"],
        "manifest_sha256": company["manifest_sha256"],
        "chief_id": chief_id,
        "carrier_id": carrier_id,
        "term": term,
        "epoch": epoch,
        "chief_execution_id": chief_execution_id,
        "transaction_id": transaction_id,
        "command_id": command_id,
        "task_revision": dict(task_revision),
        "work_packet": dict(work_packet),
        "context_manifest": dict(context_manifest),
        "prompt_base64": base64.b64encode(prompt_bytes).decode("ascii"),
    }
    try:
        command = parse_work_definition_register(request_value)
    except WorkDefinitionControlProtocolError as exc:
        raise CompanyServiceError(
            f"work definition registration request is invalid: {exc.code}",
        ) from exc
    response = _control_operation_request(
        descriptor,
        path=_WORK_DEFINITION_REGISTER_ROUTE,
        token=str(descriptor["bearer_token"]),
        payload=command.as_dict(),
        timeout_seconds=timeout_seconds,
        expected_schema=WORK_DEFINITION_REGISTER_RESULT_SCHEMA,
        mutation=True,
    )
    return _validated_work_definition_register_result(
        response,
        service_instance_id=str(descriptor["service_instance_id"]),
        company=company,
        command=command,
    )


def activate_service_work_definition_enforcement(
    slot_root: str | os.PathLike[str],
    *,
    chief_id: str,
    carrier_id: str,
    term: int,
    epoch: int,
    chief_execution_id: str,
    transaction_id: str,
    command_id: str,
    runtime_root: str | os.PathLike[str] | None = None,
    timeout_seconds: float = _CONTROL_OPERATION_TIMEOUT_SECONDS + 10.0,
) -> dict[str, Any]:
    """Activate the one-way registered-work launch gate through the resident."""

    timeout_seconds = _bounded_seconds(
        timeout_seconds,
        label="work definition enforcement timeout",
        maximum=300.0,
    )
    slot = _absolute_slot(slot_root)
    descriptor = _resident_admin_descriptor(slot, runtime_root=runtime_root)
    company = descriptor["company"]
    request_value = {
        "schema_version": WORK_DEFINITION_ENFORCEMENT_ACTIVATE_SCHEMA,
        "service_instance_id": descriptor["service_instance_id"],
        "company_id": company["company_id"],
        "company_incarnation": company["company_incarnation"],
        "lock_domain_generation": company["lock_domain_generation"],
        "manifest_sha256": company["manifest_sha256"],
        "chief_id": chief_id,
        "carrier_id": carrier_id,
        "term": term,
        "epoch": epoch,
        "chief_execution_id": chief_execution_id,
        "transaction_id": transaction_id,
        "command_id": command_id,
    }
    try:
        command = parse_work_definition_enforcement_activate(request_value)
    except WorkDefinitionControlProtocolError as exc:
        raise CompanyServiceError(
            f"work definition enforcement request is invalid: {exc.code}",
        ) from exc
    response = _control_operation_request(
        descriptor,
        path=_WORK_DEFINITION_ENFORCEMENT_ROUTE,
        token=str(descriptor["bearer_token"]),
        payload=command.as_dict(),
        timeout_seconds=timeout_seconds,
        expected_schema=WORK_DEFINITION_ENFORCEMENT_RESULT_SCHEMA,
        mutation=True,
    )
    return _validated_work_definition_enforcement_result(
        response,
        service_instance_id=str(descriptor["service_instance_id"]),
        company=company,
        command=command,
    )


def ingest_service_telemetry(
    slot_root: str | os.PathLike[str],
    raw: bytes,
    *,
    capability_path: str | os.PathLike[str],
    provider: str,
    source_class: str,
    adapter_instance_id: str,
    adapter_event_id: str,
    intake_sequence: int,
    transaction_id: str,
    command_id: str,
    received_at: str,
    runtime_root: str | os.PathLike[str] | None = None,
    timeout_seconds: float = (
        _CONTROL_OPERATION_TIMEOUT_SECONDS + 10.0
    ),
) -> dict[str, Any]:
    """Submit one provider occurrence to the resident sole-writer owner."""

    timeout_seconds = _bounded_seconds(
        timeout_seconds,
        label="telemetry ingest timeout",
        maximum=300.0,
    )
    if type(raw) is not bytes:
        raise CompanyServiceError("telemetry raw payload must be bytes")
    slot = _absolute_slot(slot_root)
    capability = _read_telemetry_capability(
        capability_path,
        slot=slot,
        runtime_root=runtime_root,
        source_class=source_class,
    )
    company = capability["company"]
    payload = {
        "schema_version": TELEMETRY_INGEST_SCHEMA,
        "service_instance_id": capability["service_instance_id"],
        "company_id": company["company_id"],
        "company_incarnation": company["company_incarnation"],
        "lock_domain_generation": company["lock_domain_generation"],
        "manifest_sha256": company["manifest_sha256"],
        "provider": provider,
        "source_class": source_class,
        "adapter_instance_id": adapter_instance_id,
        "adapter_event_id": adapter_event_id,
        "intake_sequence": intake_sequence,
        "transaction_id": transaction_id,
        "command_id": command_id,
        "received_at": received_at,
        "raw_base64": base64.b64encode(raw).decode("ascii"),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
    }
    try:
        _telemetry_ingest_command(payload)
    except _ControlRequestError as exc:
        raise CompanyServiceError(
            f"telemetry ingest request is invalid: {exc.code}",
        ) from exc
    result = _control_operation_request(
        capability,
        path=_TELEMETRY_ROUTES[source_class],
        token=str(capability["bearer_token"]),
        payload=payload,
        timeout_seconds=timeout_seconds,
    )
    return _validated_telemetry_ingest_result(
        result,
        service_instance_id=str(capability["service_instance_id"]),
        company_id=str(company["company_id"]),
        provider=provider,
        transaction_id=transaction_id,
        command_id=command_id,
    )


def service_status(
    slot_root: str | os.PathLike[str],
    *,
    runtime_root: str | os.PathLike[str] | None = None,
    timeout_seconds: float = 1.0,
) -> dict[str, Any]:
    """Return verified local service status, or an explicit unavailable state."""

    timeout_seconds = _bounded_seconds(
        timeout_seconds,
        label="service status timeout",
        maximum=300.0,
    )
    slot = _absolute_slot(slot_root)
    try:
        descriptor = _read_descriptor(runtime_descriptor_path(slot, runtime_root=runtime_root))
        if descriptor is None:
            return {"state": "unavailable", "reason": "descriptor_absent"}
        descriptor = _bound_descriptor(slot, descriptor)
        status = _control_request(descriptor, method="GET", path="/status", timeout_seconds=timeout_seconds)
        if status.get("service_instance_id") != descriptor["service_instance_id"]:
            raise CompanyServiceUnavailableError("resident service instance differs from descriptor")
        state = status.get("state")
        if state not in {"running", "stopping"}:
            raise CompanyServiceUnavailableError(
                "resident service returned an invalid lifecycle state",
            )
        return {
            "state": state,
            "descriptor": _public_descriptor(descriptor),
            "status": status,
        }
    except (CompanyServiceError, CompanyServiceUnavailableError) as exc:
        return {"state": "unavailable", "reason": str(exc)}


def stop_service(
    slot_root: str | os.PathLike[str],
    *,
    runtime_root: str | os.PathLike[str] | None = None,
    timeout_seconds: float = 5.0,
    expected_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Request an authenticated graceful stop; this function never kills a PID."""

    timeout_seconds = _bounded_seconds(
        timeout_seconds,
        label="service stop timeout",
        maximum=300.0,
    )
    if (
        expected_manifest_sha256 is not None
        and (
            not isinstance(expected_manifest_sha256, str)
            or _SHA256_RE.fullmatch(expected_manifest_sha256) is None
        )
    ):
        raise CompanyServiceError(
            "expected company manifest must be lowercase SHA-256",
        )
    slot = _absolute_slot(slot_root)
    descriptor = _read_descriptor(runtime_descriptor_path(slot, runtime_root=runtime_root))
    if descriptor is None:
        raise CompanyServiceUnavailableError("company service descriptor is absent")
    descriptor = _bound_descriptor(slot, descriptor)
    if (
        expected_manifest_sha256 is not None
        and descriptor["company"]["manifest_sha256"]
        != expected_manifest_sha256
    ):
        raise CompanyServiceUnavailableError(
            "resident service manifest differs from discovery",
        )
    response = _control_request(
        descriptor, method="POST", path="/stop", timeout_seconds=timeout_seconds,
    )
    if response.get("service_instance_id") != descriptor["service_instance_id"]:
        raise CompanyServiceUnavailableError("resident service instance differs from descriptor")
    return response


class _ControlHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, handler: type[BaseHTTPRequestHandler], service: _ResidentService) -> None:
        self.service = service
        super().__init__(("127.0.0.1", 0), handler)


class _ControlHandler(BaseHTTPRequestHandler):
    server: _ControlHTTPServer
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(
            _CONTROL_OPERATION_TIMEOUT_SECONDS + 5.0,
        )

    def log_message(self, _format: str, *args: object) -> None:
        del args

    def _reply(self, status: HTTPStatus, value: Mapping[str, Any]) -> None:
        payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header(
                "Content-Type",
                "application/json; charset=utf-8",
            )
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError, OSError):
            # A mutating caller may time out after enqueue.  The owner-thread
            # result remains authoritative even when the HTTP peer is gone.
            pass
        finally:
            self.close_connection = True

    def _request_origin_valid(self) -> bool:
        hosts = self.headers.get_all("Host", [])
        if (
            len(hosts) != 1
            or hosts[0] not in {
                f"127.0.0.1:{self.server.server_port}",
                f"localhost:{self.server.server_port}",
            }
        ):
            return False
        if self.headers.get("Origin") is not None:
            return False
        return True

    def _authenticated(self, token: str) -> bool:
        authorizations = self.headers.get_all("Authorization", [])
        if not self._request_origin_valid() or len(authorizations) != 1:
            return False
        return secrets.compare_digest(
            authorizations[0],
            f"Bearer {token}",
        )

    def _json_body(
        self,
        *,
        maximum_bytes: int = _MAX_CONTROL_BODY_BYTES,
    ) -> Any:
        if (
            self.headers.get("Transfer-Encoding") is not None
            or self.headers.get("Content-Encoding") is not None
            or self.headers.get("Expect") is not None
        ):
            raise _ControlRequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_content_length",
            )
        content_types = self.headers.get_all("Content-Type", [])
        if len(content_types) != 1:
            raise _ControlRequestError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
            )
        content_type = content_types[0]
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            raise _ControlRequestError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
            )
        length_values = self.headers.get_all("Content-Length", [])
        if len(length_values) != 1:
            raise _ControlRequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_content_length",
            )
        length_value = length_values[0]
        if (
            not length_value.isascii()
            or not length_value.isdigit()
            or len(length_value) > _MAX_CONTROL_LENGTH_DIGITS
        ):
            raise _ControlRequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_content_length",
            )
        length = int(length_value)
        if length < 1 or str(length) != length_value:
            raise _ControlRequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_content_length",
            )
        if length > maximum_bytes:
            raise _ControlRequestError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "payload_too_large",
            )
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise _ControlRequestError(
                HTTPStatus.BAD_REQUEST,
                "truncated_request",
            )
        try:
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_strict_json_object,
                parse_constant=_reject_json_constant,
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            _DuplicateJsonKeyError,
            RecursionError,
            ValueError,
        ) as exc:
            raise _ControlRequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_json",
            ) from exc
        if not _json_depth_within_bound(
            value,
            maximum=_MAX_CONTROL_JSON_DEPTH,
        ):
            raise _ControlRequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_json",
            )
        return value

    def do_GET(self) -> None:  # noqa: N802
        if (
            self.path != "/status"
            or not self._authenticated(self.server.service.bearer_token)
        ):
            self._reply(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return
        self._reply(HTTPStatus.OK, self.server.service.status_payload())

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/stop":
            if not self._authenticated(self.server.service.bearer_token):
                self._reply(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) > 1 or (lengths and lengths[0] != "0"):
                self._reply(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "invalid_request"},
                )
                return
            self.server.service.request_stop()
            self._reply(
                HTTPStatus.OK,
                self.server.service.status_payload(stopping=True),
            )
            return
        if self.path in {
            _CHIEF_TAKEOVER_PREPARE_ROUTE,
            _CHIEF_TAKEOVER_CONSUME_ROUTE,
            _DEPARTMENT_DISPATCH_ROUTE,
            _WORK_DEFINITION_REGISTER_ROUTE,
            _WORK_DEFINITION_ENFORCEMENT_ROUTE,
            _LEGACY_BRIDGE_PRESTART_QUERY_ROUTE,
        }:
            if not self._authenticated(self.server.service.bearer_token):
                self._reply(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            try:
                value = self._json_body(
                    maximum_bytes=(
                        _MAX_WORK_DEFINITION_CONTROL_BODY_BYTES
                        if self.path in {
                            _WORK_DEFINITION_REGISTER_ROUTE,
                            _WORK_DEFINITION_ENFORCEMENT_ROUTE,
                        }
                        else MAX_LEGACY_BRIDGE_PRESTART_CONTROL_BYTES
                        if self.path == _LEGACY_BRIDGE_PRESTART_QUERY_ROUTE
                        else _MAX_CONTROL_BODY_BYTES
                    ),
                )
                try:
                    if self.path == _CHIEF_TAKEOVER_PREPARE_ROUTE:
                        response = self.server.service.submit_chief_prepare(
                            parse_chief_takeover_prepare(value),
                        )
                    elif self.path == _CHIEF_TAKEOVER_CONSUME_ROUTE:
                        response = self.server.service.submit_chief_consume(
                            parse_chief_takeover_consume(value),
                        )
                    elif self.path == _DEPARTMENT_DISPATCH_ROUTE:
                        response = self.server.service.submit_department_dispatch(
                            parse_department_dispatch(value),
                        )
                    elif self.path == _WORK_DEFINITION_REGISTER_ROUTE:
                        response = (
                            self.server.service
                            .submit_work_definition_register(
                                parse_work_definition_register(value),
                            )
                        )
                    elif self.path == _LEGACY_BRIDGE_PRESTART_QUERY_ROUTE:
                        response = self.server.service.submit_legacy_bridge_prestart(
                            parse_legacy_bridge_prestart_query(value),
                        )
                    else:
                        response = (
                            self.server.service
                            .submit_work_definition_enforcement(
                                parse_work_definition_enforcement_activate(
                                    value,
                                ),
                            )
                        )
                except (
                    ChiefControlProtocolError,
                    DepartmentControlProtocolError,
                    WorkDefinitionControlProtocolError,
                    LegacyBridgeControlProtocolError,
                ) as exc:
                    raise _ControlRequestError(
                        HTTPStatus.BAD_REQUEST,
                        exc.code,
                    ) from exc
            except _ControlRequestError as exc:
                chief_error: dict[str, Any] = {"error": exc.code}
                if exc.effect is not None:
                    chief_error["effect"] = exc.effect
                if exc.cursor is not None:
                    chief_error["cursor"] = exc.cursor
                self._reply(exc.status, chief_error)
                return
            self._reply(HTTPStatus.OK, response)
            return
        source_class = _TELEMETRY_ROUTE_SOURCES.get(self.path)
        if source_class is None:
            self._reply(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return
        token = self.server.service.telemetry_tokens[source_class]
        if not self._authenticated(token):
            self._reply(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return
        try:
            command = _telemetry_ingest_command(self._json_body())
            if command.source_class != source_class:
                raise _ControlRequestError(
                    HTTPStatus.FORBIDDEN,
                    "forbidden",
                )
            response = self.server.service.submit_telemetry(command)
        except _ControlRequestError as exc:
            error: dict[str, Any] = {"error": exc.code}
            if exc.effect is not None:
                error["effect"] = exc.effect
            if exc.cursor is not None:
                error["cursor"] = exc.cursor
            self._reply(exc.status, error)
            return
        self._reply(HTTPStatus.OK, response)

    def _reject(self) -> None:
        self._reply(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method_not_allowed"})

    do_PUT = _reject
    do_PATCH = _reject
    do_DELETE = _reject
    do_OPTIONS = _reject


@dataclass
class _ResidentService:
    slot: Path
    runtime_root: Path | None
    refresh_seconds: float
    lock_timeout_seconds: float = 5.0
    expected_manifest_sha256: str | None = None
    dashboard_environment_kind: str = "unverified"

    def __post_init__(self) -> None:
        self.dashboard_environment_kind = _dashboard_environment_kind(
            self.dashboard_environment_kind,
        )
        self.service_instance_id = str(uuid.uuid4())
        self.bearer_token = secrets.token_hex(32)
        self.telemetry_tokens = {
            source_class: secrets.token_hex(32)
            for source_class in _TELEMETRY_ROUTES
        }
        self._stop = threading.Event()
        self._admission_lock = threading.Lock()
        self._status_lock = threading.Lock()
        self._cursor: int | None = None
        self._control: _ControlHTTPServer | None = None
        self._control_thread: threading.Thread | None = None
        self._supervisor: CompanySupervisor | None = None
        self._company_binding: dict[str, Any] | None = None
        self._logical_clock = ResidentLogicalEventClock()
        self._operations = _PrioritizedControlQueue(
            maxsize=_MAX_CONTROL_QUEUE,
        )
        self._descriptor_path = runtime_descriptor_path(self.slot, runtime_root=self.runtime_root)
        self._telemetry_capability_paths = {
            source_class: self._descriptor_path.parent
            / (
                f"telemetry-{self.service_instance_id}-"
                f"{source_class.replace('_', '-')}.json"
            )
            for source_class in _TELEMETRY_ROUTES
        }
        self._telemetry_capability_ids = {
            source_class: str(uuid.uuid4())
            for source_class in _TELEMETRY_ROUTES
        }

    def status_payload(self, *, stopping: bool = False) -> dict[str, Any]:
        with self._status_lock:
            cursor = self._cursor
        return {
            "schema_version": _CONTROL_SCHEMA,
            "service_instance_id": self.service_instance_id,
            "state": "stopping" if stopping or self._stop.is_set() else "running",
            "pid": os.getpid(),
            "cursor": cursor,
        }

    def request_stop(self) -> None:
        with self._admission_lock:
            self._stop.set()
            try:
                self._operations.put_nowait(None)
            except queue.Full:
                pass

    def _assert_command_binding(
        self,
        command: (
            _ControlCommand
        ),
    ) -> None:
        company = self._company_binding
        if (
            command.service_instance_id != self.service_instance_id
            or company is None
            or command.company_id != company["company_id"]
            or command.company_incarnation
            != company["company_incarnation"]
            or command.lock_domain_generation
            != company["lock_domain_generation"]
            or command.manifest_sha256 != company["manifest_sha256"]
        ):
            raise _ControlRequestError(
                HTTPStatus.CONFLICT,
                "service_binding_mismatch",
            )

    def _admit_operation(
        self,
        pending: _PendingControlOperation,
        *,
        telemetry: bool,
    ) -> None:
        with self._admission_lock:
            if self._stop.is_set():
                raise _ControlRequestError(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "service_stopping",
                )
            if (
                telemetry
                and self._operations.qsize()
                >= _MAX_CONTROL_QUEUE - _CONTROL_QUEUE_RESERVE
            ):
                raise _ControlRequestError(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "ingest_busy",
                )
            try:
                self._operations.put_nowait(pending)
            except queue.Full as exc:
                raise _ControlRequestError(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "ingest_busy" if telemetry else "control_busy",
                ) from exc

    @staticmethod
    def _await_operation(
        pending: _PendingControlOperation,
        *,
        mutation: bool,
        timeout_code: str,
        failure_code: str,
    ) -> dict[str, Any]:
        if not pending.done.wait(_CONTROL_OPERATION_TIMEOUT_SECONDS):
            raise _ControlRequestError(
                HTTPStatus.GATEWAY_TIMEOUT,
                "effect_unknown" if mutation else timeout_code,
                effect="effect_unknown" if mutation else None,
            )
        if pending.error_status is not None:
            raise _ControlRequestError(
                pending.error_status,
                pending.error_code or failure_code,
                effect=pending.error_effect,
                cursor=pending.error_cursor,
            )
        if pending.response is None:
            raise _ControlRequestError(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "effect_unknown" if mutation else failure_code,
                effect="effect_unknown" if mutation else None,
            )
        return pending.response

    def _submit_operation(
        self,
        command: _ControlCommand,
        *,
        telemetry: bool = False,
        mutation: bool = True,
        operation: str,
    ) -> dict[str, Any]:
        self._assert_command_binding(command)
        pending = _PendingControlOperation(command)
        self._admit_operation(pending, telemetry=telemetry)
        return self._await_operation(
            pending,
            mutation=mutation,
            timeout_code=f"{operation}_timeout",
            failure_code=f"{operation}_failed",
        )

    def submit_telemetry(
        self,
        command: _TelemetryIngestCommand,
    ) -> dict[str, Any]:
        """Hand one bounded request to the resident owner thread."""

        return self._submit_operation(command, telemetry=True, operation="ingest")

    def submit_chief_prepare(
        self,
        command: ChiefTakeoverPrepareCommand,
    ) -> dict[str, Any]:
        """Serialize one fresh-user prepare on the resident owner thread."""

        return self._submit_operation(command, mutation=False, operation="chief_prepare")

    def submit_chief_consume(
        self,
        command: ChiefTakeoverConsumeCommand,
    ) -> dict[str, Any]:
        """Serialize one takeover attempt on the resident owner thread."""

        return self._submit_operation(command, operation="chief_consume")

    def submit_department_dispatch(
        self,
        command: DepartmentDispatchCommand,
    ) -> dict[str, Any]:
        """Serialize a Chief-fenced department queue/admission request."""

        return self._submit_operation(command, operation="department_dispatch")

    def submit_work_definition_register(
        self,
        command: WorkDefinitionRegisterCommand,
    ) -> dict[str, Any]:
        """Serialize Chief-fenced immutable work registration."""

        return self._submit_operation(command, operation="work_definition_register")

    def submit_work_definition_enforcement(
        self,
        command: WorkDefinitionEnforcementActivateCommand,
    ) -> dict[str, Any]:
        """Serialize the one-way registered-work enforcement cutover."""

        return self._submit_operation(command, operation="work_definition_enforcement")

    def submit_legacy_bridge_prestart(
        self,
        command: LegacyBridgePrestartQueryCommand,
    ) -> dict[str, Any]:
        return self._submit_operation(
            command,
            mutation=False,
            operation="legacy_bridge_prestart",
        )

    def _execute_legacy_bridge_prestart(
        self,
        pending: _PendingControlOperation,
    ) -> None:
        supervisor = self._supervisor
        command = cast(LegacyBridgePrestartQueryCommand, pending.command)
        if supervisor is None or self._stop.is_set():
            pending.error_status = HTTPStatus.SERVICE_UNAVAILABLE
            pending.error_code = "service_stopping"
            pending.done.set()
            return
        try:
            pending.response = derive_legacy_bridge_prestart_response(
                supervisor._state, command,
            ).as_dict()
        except CompanyStateError:
            pending.error_status = HTTPStatus.SERVICE_UNAVAILABLE
            pending.error_code = "legacy_bridge_prestart_unavailable"
        except Exception:
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "legacy_bridge_prestart_failed"
        finally:
            pending.done.set()

    def _execute_telemetry(
        self,
        pending: _PendingControlOperation,
    ) -> None:
        supervisor = self._supervisor
        command = cast(_TelemetryIngestCommand, pending.command)
        if supervisor is None or self._stop.is_set():
            pending.error_status = HTTPStatus.SERVICE_UNAVAILABLE
            pending.error_code = "service_stopping"
            pending.done.set()
            return
        try:
            if command.provider == "codex":
                result = supervisor.ingest_codex_telemetry(
                    command.raw,
                    adapter_instance_id=command.adapter_instance_id,
                    adapter_event_id=command.adapter_event_id,
                    intake_sequence=command.intake_sequence,
                    transaction_id=command.transaction_id,
                    command_id=command.command_id,
                    received_at=command.received_at,
                )
            else:
                result = supervisor.ingest_claude_telemetry(
                    command.raw,
                    source_class=command.source_class,
                    adapter_instance_id=command.adapter_instance_id,
                    adapter_event_id=command.adapter_event_id,
                    intake_sequence=command.intake_sequence,
                    transaction_id=command.transaction_id,
                    command_id=command.command_id,
                    received_at=command.received_at,
                )
            pending.response = {
                "schema_version": TELEMETRY_INGEST_RESULT_SCHEMA,
                "service_instance_id": self.service_instance_id,
                "company_id": command.company_id,
                "cursor": result.global_sequence,
                "result": asdict(result),
            }
            with self._status_lock:
                self._cursor = result.global_sequence
        except CompanySupervisorDashboardRefreshError as exc:
            if isinstance(exc.result, LedgerAppendResult):
                cursor = exc.result.record.global_sequence
                pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
                pending.error_code = (
                    "committed_dashboard_refresh_failed"
                )
                pending.error_effect = "committed"
                pending.error_cursor = cursor
                with self._status_lock:
                    self._cursor = cursor
            else:
                pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
                pending.error_code = "ingest_failed"
        except LedgerCommitEffectUnknownError:
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "effect_unknown"
            pending.error_effect = "effect_unknown"
        except CompanyProjectionDegradedError as exc:
            cursor = exc.result.record.global_sequence
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "committed_projection_degraded"
            pending.error_effect = "committed"
            pending.error_cursor = cursor
            with self._status_lock:
                self._cursor = cursor
        except (
            CompanyTelemetryIngestError,
            CompanyStateInvariantError,
            LedgerConflictError,
        ):
            pending.error_status = HTTPStatus.CONFLICT
            pending.error_code = "telemetry_conflict"
        except (
            CompanySupervisorError,
            CompanyStateError,
            LedgerError,
        ):
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "ingest_failed"
        except Exception:
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "ingest_failed"
        finally:
            pending.done.set()

    @staticmethod
    def _chief_response_binding(
        command: ChiefTakeoverPrepareCommand | ChiefTakeoverConsumeCommand,
        *,
        schema_version: str,
        service_instance_id: str,
        cursor: int,
    ) -> dict[str, Any]:
        return {
            "schema_version": schema_version,
            "service_instance_id": service_instance_id,
            "company_id": command.company_id,
            "company_incarnation": command.company_incarnation,
            "lock_domain_generation": command.lock_domain_generation,
            "manifest_sha256": command.manifest_sha256,
            "cursor": cursor,
        }

    @staticmethod
    def _department_dispatch_response_binding(
        command: DepartmentDispatchCommand,
        *,
        service_instance_id: str,
        cursor: int,
    ) -> dict[str, Any]:
        return {
            "schema_version": DEPARTMENT_DISPATCH_RESULT_SCHEMA,
            "service_instance_id": service_instance_id,
            "company_id": command.company_id,
            "company_incarnation": command.company_incarnation,
            "lock_domain_generation": command.lock_domain_generation,
            "manifest_sha256": command.manifest_sha256,
            "cursor": cursor,
        }

    @staticmethod
    def _work_definition_response_binding(
        command: (
            WorkDefinitionRegisterCommand
            | WorkDefinitionEnforcementActivateCommand
        ),
        *,
        schema_version: str,
        service_instance_id: str,
        cursor: int,
    ) -> dict[str, Any]:
        return {
            "schema_version": schema_version,
            "service_instance_id": service_instance_id,
            "company_id": command.company_id,
            "company_incarnation": command.company_incarnation,
            "lock_domain_generation": command.lock_domain_generation,
            "manifest_sha256": command.manifest_sha256,
            "cursor": cursor,
        }

    def _execute_work_definition_register(
        self,
        pending: _PendingControlOperation,
    ) -> None:
        supervisor = self._supervisor
        command = cast(WorkDefinitionRegisterCommand, pending.command)
        result = None
        if supervisor is None or self._stop.is_set():
            pending.error_status = HTTPStatus.SERVICE_UNAVAILABLE
            pending.error_code = "service_stopping"
            pending.done.set()
            return
        try:
            recorded_at = self._logical_clock.recorded_at(
                supervisor,
                command.transaction_id,
                _utc_timestamp(_trusted_utc_now()),
            )
            result = supervisor.register_work_definition(
                command.task_revision,
                command.work_packet,
                command.context_manifest,
                command.prompt_bytes,
                chief_id=command.chief_id,
                carrier_id=command.carrier_id,
                term=command.term,
                epoch=command.epoch,
                chief_execution_id=command.chief_execution_id,
                transaction_id=command.transaction_id,
                command_id=command.command_id,
                recorded_at=recorded_at,
            )
            try:
                supervisor.refresh_dashboard()
            except CompanySupervisorError:
                pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
                pending.error_code = "committed_dashboard_refresh_failed"
                pending.error_effect = "committed"
                pending.error_cursor = result.global_sequence
                with self._status_lock:
                    self._cursor = result.global_sequence
                return
            pending.response = {
                **self._work_definition_response_binding(
                    command,
                    schema_version=WORK_DEFINITION_REGISTER_RESULT_SCHEMA,
                    service_instance_id=self.service_instance_id,
                    cursor=result.global_sequence,
                ),
                "result": asdict(result),
            }
            with self._status_lock:
                self._cursor = result.global_sequence
        except CompanySupervisorDashboardRefreshError as exc:
            if isinstance(exc.result, LedgerAppendResult):
                cursor = exc.result.record.global_sequence
                pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
                pending.error_code = "committed_dashboard_refresh_failed"
                pending.error_effect = "committed"
                pending.error_cursor = cursor
                with self._status_lock:
                    self._cursor = cursor
            else:
                pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
                pending.error_code = "effect_unknown"
                pending.error_effect = "effect_unknown"
        except LedgerCommitEffectUnknownError:
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "effect_unknown"
            pending.error_effect = "effect_unknown"
        except CompanyProjectionDegradedError as exc:
            cursor = exc.result.record.global_sequence
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "committed_projection_degraded"
            pending.error_effect = "committed"
            pending.error_cursor = cursor
            with self._status_lock:
                self._cursor = cursor
        except (
            CompanyWorkDefinitionError,
            CompanyDepartmentLifecycleError,
            CompanyStateInvariantError,
            LedgerConflictError,
        ):
            pending.error_status = HTTPStatus.CONFLICT
            pending.error_code = "work_definition_rejected"
        except (
            CompanySupervisorError,
            CompanyStateError,
            LedgerError,
        ):
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "work_definition_register_failed"
            pending.error_effect = "effect_unknown"
        except Exception:
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "work_definition_register_failed"
            pending.error_effect = "effect_unknown"
        finally:
            pending.done.set()

    def _execute_work_definition_enforcement(
        self,
        pending: _PendingControlOperation,
    ) -> None:
        supervisor = self._supervisor
        command = cast(WorkDefinitionEnforcementActivateCommand, pending.command)
        result = None
        if supervisor is None or self._stop.is_set():
            pending.error_status = HTTPStatus.SERVICE_UNAVAILABLE
            pending.error_code = "service_stopping"
            pending.done.set()
            return
        try:
            activated_at = self._logical_clock.recorded_at(
                supervisor,
                command.transaction_id,
                _utc_timestamp(_trusted_utc_now()),
            )
            result = supervisor.activate_work_definition_enforcement(
                chief_id=command.chief_id,
                carrier_id=command.carrier_id,
                term=command.term,
                epoch=command.epoch,
                chief_execution_id=command.chief_execution_id,
                transaction_id=command.transaction_id,
                command_id=command.command_id,
                activated_at=activated_at,
            )
            try:
                supervisor.refresh_dashboard()
            except CompanySupervisorError:
                pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
                pending.error_code = "committed_dashboard_refresh_failed"
                pending.error_effect = "committed"
                pending.error_cursor = result.global_sequence
                with self._status_lock:
                    self._cursor = result.global_sequence
                return
            pending.response = {
                **self._work_definition_response_binding(
                    command,
                    schema_version=WORK_DEFINITION_ENFORCEMENT_RESULT_SCHEMA,
                    service_instance_id=self.service_instance_id,
                    cursor=result.global_sequence,
                ),
                "result": asdict(result),
            }
            with self._status_lock:
                self._cursor = result.global_sequence
        except CompanySupervisorDashboardRefreshError as exc:
            if isinstance(exc.result, LedgerAppendResult):
                cursor = exc.result.record.global_sequence
                pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
                pending.error_code = "committed_dashboard_refresh_failed"
                pending.error_effect = "committed"
                pending.error_cursor = cursor
                with self._status_lock:
                    self._cursor = cursor
            else:
                pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
                pending.error_code = "effect_unknown"
                pending.error_effect = "effect_unknown"
        except LedgerCommitEffectUnknownError:
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "effect_unknown"
            pending.error_effect = "effect_unknown"
        except CompanyProjectionDegradedError as exc:
            cursor = exc.result.record.global_sequence
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "committed_projection_degraded"
            pending.error_effect = "committed"
            pending.error_cursor = cursor
            with self._status_lock:
                self._cursor = cursor
        except (
            CompanyWorkDefinitionError,
            CompanyDepartmentLifecycleError,
            CompanyStateInvariantError,
            LedgerConflictError,
        ):
            pending.error_status = HTTPStatus.CONFLICT
            pending.error_code = "work_definition_rejected"
        except (
            CompanySupervisorError,
            CompanyStateError,
            LedgerError,
        ):
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "work_definition_enforcement_failed"
            pending.error_effect = "effect_unknown"
        except Exception:
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "work_definition_enforcement_failed"
            pending.error_effect = "effect_unknown"
        finally:
            pending.done.set()

    def _execute_department_dispatch(
        self,
        pending: _PendingControlOperation,
    ) -> None:
        """Queue and, when capacity permits, admit without provider launch."""

        supervisor = self._supervisor
        command = cast(DepartmentDispatchCommand, pending.command)
        enqueue_result = None
        if supervisor is None or self._stop.is_set():
            pending.error_status = HTTPStatus.SERVICE_UNAVAILABLE
            pending.error_code = "service_stopping"
            pending.done.set()
            return
        try:
            recorded_at = self._logical_clock.recorded_at(
                supervisor,
                command.enqueue_transaction_id,
                _utc_timestamp(_trusted_utc_now()),
            )
            enqueue_result = supervisor.enqueue_department_dispatch_fenced(
                command.department_id,
                chief_id=command.chief_id,
                carrier_id=command.carrier_id,
                term=command.term,
                epoch=command.epoch,
                chief_execution_id=command.chief_execution_id,
                transaction_id=command.enqueue_transaction_id,
                command_id=command.enqueue_command_id,
                dispatch_request_id=command.dispatch_request_id,
                reservation_id=command.reservation_id,
                task_id=command.task_id,
                packet_id=command.packet_id,
                route_policy_id=command.route_policy_id,
                requested_role=command.requested_role,
                requested_capability_tier=command.requested_capability_tier,
                requested_at=recorded_at,
                recorded_at=recorded_at,
            )
            admission_result = None
            queued_reason = None
            try:
                admission_at = self._logical_clock.recorded_at(
                    supervisor,
                    command.admission_transaction_id,
                    _utc_timestamp(_trusted_utc_now()),
                )
                admission_result = supervisor.admit_department_dispatch_resident(
                    command.dispatch_request_id,
                    transaction_id=command.admission_transaction_id,
                    command_id=command.admission_command_id,
                    recorded_at=admission_at,
                )
            except CompanyDepartmentDispatchCapacityBlocked as exc:
                queued_reason = exc.reason
            except CompanyDepartmentLifecycleError:
                durable_admission = supervisor.record_by_transaction_id(
                    command.admission_transaction_id,
                )
                if (
                    durable_admission is None
                    or str(durable_admission.receipt["state"]) != "committed"
                    or not durable_admission.events
                ):
                    raise
                pending.error_status = HTTPStatus.CONFLICT
                pending.error_code = "department_dispatch_conflict"
                pending.error_cursor = durable_admission.global_sequence
                with self._status_lock:
                    self._cursor = durable_admission.global_sequence
                return
            cursor = (
                enqueue_result.global_sequence
                if admission_result is None
                else admission_result.global_sequence
            )
            try:
                supervisor.refresh_dashboard()
            except CompanySupervisorError:
                pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
                pending.error_code = "committed_dashboard_refresh_failed"
                pending.error_effect = "committed"
                pending.error_cursor = cursor
                with self._status_lock:
                    self._cursor = cursor
                return
            pending.response = {
                **self._department_dispatch_response_binding(
                    command,
                    service_instance_id=self.service_instance_id,
                    cursor=cursor,
                ),
                "enqueue_result": asdict(enqueue_result),
                "admission_result": (
                    None if admission_result is None else asdict(admission_result)
                ),
                "queued_reason": queued_reason,
            }
            with self._status_lock:
                self._cursor = cursor
        except CompanyDepartmentLifecycleError:
            if enqueue_result is None:
                pending.error_status = HTTPStatus.CONFLICT
                pending.error_code = "department_dispatch_rejected"
            else:
                pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
                pending.error_code = "effect_unknown"
                pending.error_effect = "effect_unknown"
                pending.error_cursor = enqueue_result.global_sequence
        except LedgerCommitEffectUnknownError:
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "effect_unknown"
            pending.error_effect = "effect_unknown"
            if enqueue_result is not None:
                pending.error_cursor = enqueue_result.global_sequence
        except (CompanyStateInvariantError, LedgerConflictError):
            pending.error_status = HTTPStatus.CONFLICT
            pending.error_code = "department_dispatch_conflict"
            if enqueue_result is not None:
                pending.error_effect = "effect_unknown"
                pending.error_cursor = enqueue_result.global_sequence
        except (CompanySupervisorError, CompanyStateError, LedgerError):
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "department_dispatch_failed"
            if enqueue_result is not None:
                pending.error_effect = "effect_unknown"
                pending.error_cursor = enqueue_result.global_sequence
        except Exception:
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "department_dispatch_failed"
            if enqueue_result is not None:
                pending.error_effect = "effect_unknown"
                pending.error_cursor = enqueue_result.global_sequence
        finally:
            pending.done.set()

    def _execute_chief_prepare(
        self,
        pending: _PendingControlOperation,
    ) -> None:
        supervisor = self._supervisor
        command = cast(ChiefTakeoverPrepareCommand, pending.command)
        if supervisor is None or self._stop.is_set():
            pending.error_status = HTTPStatus.SERVICE_UNAVAILABLE
            pending.error_code = "service_stopping"
            pending.done.set()
            return
        try:
            issued = _trusted_utc_now()
            issued_at = _utc_timestamp(issued)
            expires_at = _utc_timestamp(issued + _CHIEF_CAPABILITY_TTL)
            capability = supervisor.prepare_chief_takeover(
                command.known_carrier.as_dict(),
                user_action_ref=command.user_action_ref,
                objective_sha256=command.objective_sha256,
                scope_sha256=command.scope_sha256,
                nonce_sha256=command.nonce_sha256,
                issued_at=issued_at,
                expires_at=expires_at,
            )
            heads = supervisor.heads()
            if (
                capability["expected_head_sha256"]
                != heads.global_head.transaction_sha256
            ):
                raise CompanyChiefTakeoverError(
                    "prepared capability head changed on the owner thread",
                )
            pending.response = {
                **self._chief_response_binding(
                    command,
                    schema_version=CHIEF_TAKEOVER_PREPARE_RESULT_SCHEMA,
                    service_instance_id=self.service_instance_id,
                    cursor=heads.global_head.global_sequence,
                ),
                "capability": capability,
            }
        except CompanyChiefTakeoverError:
            pending.error_status = HTTPStatus.CONFLICT
            pending.error_code = "chief_prepare_rejected"
        except (
            CompanySupervisorError,
            CompanyStateError,
            LedgerError,
        ):
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "chief_prepare_failed"
        except Exception:
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "chief_prepare_failed"
        finally:
            pending.done.set()

    @staticmethod
    def _validate_new_takeover_timing(
        command: ChiefTakeoverConsumeCommand,
        capability: Mapping[str, Any],
        *,
        now: datetime,
    ) -> None:
        issued = _parsed_control_time(str(capability["issued_at"]))
        expires = _parsed_control_time(str(capability["expires_at"]))
        consumed = _parsed_control_time(command.consumed_at)
        if (
            _utc_timestamp(consumed) != command.consumed_at
            or now < issued
            or now >= expires
        ):
            raise _ControlRequestError(
                HTTPStatus.CONFLICT,
                "chief_capability_expired",
            )
        if (
            consumed < issued
            or consumed >= expires
            or consumed < now - _CHIEF_CONSUMED_AT_MAX_AGE
            or consumed > now + _CHIEF_FUTURE_CLOCK_SKEW
        ):
            raise _ControlRequestError(
                HTTPStatus.CONFLICT,
                "chief_consumed_at_stale",
            )
        expected_grant_expiry = _utc_timestamp(
            consumed + _CHIEF_GRANT_TTL,
        )
        if command.grant_expires_at != expected_grant_expiry:
            raise _ControlRequestError(
                HTTPStatus.CONFLICT,
                "chief_grant_expiry_invalid",
            )

    @staticmethod
    def _no_checkpoint_evidence() -> dict[str, Any]:
        return {
            "state": "not_required_fenced_head_drift",
            "checkpoint_id": None,
            "checkpoint_manifest_sha256": None,
            "export_id": None,
            "export_sha256": None,
            "cursor": None,
            "head_sha256": None,
            "generated_at": None,
        }

    @staticmethod
    def _verified_takeover_evidence(
        supervisor: CompanySupervisor,
        capability: Mapping[str, Any],
        *,
        generated_at: str,
        expected_cursor: int,
        expected_head_sha256: str,
        create: bool,
    ) -> dict[str, Any]:
        checkpoint_id, export_id = _takeover_artifact_ids(
            str(capability["capability_id"]),
        )
        delivery: CompanyDeliverySnapshot | None = None
        if create:
            try:
                delivery = supervisor.create_checkpoint_export(
                    checkpoint_id,
                    export_id,
                    generated_at,
                )
            except CompanySupervisorDashboardRefreshError as exc:
                if not isinstance(exc.result, CompanyDeliverySnapshot):
                    raise
                delivery = exc.result
            checkpoint = delivery.checkpoint
            exported = delivery.sanitized_export
            if (
                checkpoint.state != "verified"
                or not checkpoint.current
                or checkpoint.checkpoint_id != checkpoint_id
                or checkpoint.cursor != expected_cursor
                or checkpoint.head_sha256 != expected_head_sha256
                or checkpoint.generated_at != generated_at
                or exported.state != "available"
                or not exported.current
                or exported.export_id != export_id
                or exported.source_checkpoint_id != checkpoint_id
                or exported.cursor != expected_cursor
                or exported.head_sha256 != expected_head_sha256
                or exported.generated_at != generated_at
            ):
                raise CompanyStateError(
                    "pre-takeover checkpoint/export delivery differs",
                )
        root = supervisor.manifest_path.parent
        checkpoint_path = root / "checkpoints" / checkpoint_id
        export_path = root / "exports" / f"{export_id}.json"
        verified_checkpoint = verify_plain_checkpoint(checkpoint_path)
        verified_export = verify_sanitized_export(
            export_path,
            checkpoint_path=checkpoint_path,
        )
        checkpoint_manifest = verified_checkpoint.manifest
        checkpoint_ledger = checkpoint_manifest["ledger"]
        checkpoint_company = checkpoint_manifest["company"]
        export_bundle = verified_export.bundle
        if (
            checkpoint_manifest["generated_at"] != generated_at
            or checkpoint_ledger["global_sequence"] != expected_cursor
            or checkpoint_ledger["transaction_sha256"]
            != expected_head_sha256
            or checkpoint_company["company_id"]
            != capability["company_id"]
            or checkpoint_company["company_incarnation"]
            != capability["company_incarnation"]
            or checkpoint_company["lock_domain_generation"]
            != capability["lock_domain_generation"]
            or export_bundle["generated_at"] != generated_at
            or export_bundle["ledger"]
            != {
                "cursor": expected_cursor,
                "head_sha256": expected_head_sha256,
            }
        ):
            raise CompanyStateError(
                "verified pre-takeover artifact binding differs",
            )
        return {
            "state": "pre_takeover_verified",
            "checkpoint_id": checkpoint_id,
            "checkpoint_manifest_sha256": verified_checkpoint.sha256,
            "export_id": export_id,
            "export_sha256": verified_export.sha256,
            "cursor": expected_cursor,
            "head_sha256": expected_head_sha256,
            "generated_at": generated_at,
        }

    def _chief_consume_response(
        self,
        command: ChiefTakeoverConsumeCommand,
        result: ChiefTakeoverResult,
        evidence: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            **self._chief_response_binding(
                command,
                schema_version=CHIEF_TAKEOVER_CONSUME_RESULT_SCHEMA,
                service_instance_id=self.service_instance_id,
                cursor=result.global_sequence,
            ),
            "result": asdict(result),
            "pre_takeover_evidence": dict(evidence),
        }

    def _execute_chief_consume(
        self,
        pending: _PendingControlOperation,
    ) -> None:
        supervisor = self._supervisor
        command = cast(ChiefTakeoverConsumeCommand, pending.command)
        if supervisor is None or self._stop.is_set():
            pending.error_status = HTTPStatus.SERVICE_UNAVAILABLE
            pending.error_code = "service_stopping"
            pending.done.set()
            return
        committed_result: ChiefTakeoverResult | None = None
        try:
            capability = validate_takeover_capability(command.capability)
            durable = supervisor.record_by_transaction_id(
                str(capability["consumption_transaction_id"]),
            )
            if durable is not None:
                committed_result = supervisor.takeover_chief(
                    capability,
                    command.known_carrier.as_dict(),
                    consumed_at=command.consumed_at,
                    grant_expires_at=command.grant_expires_at,
                )
                if committed_result.outcome == "consumed":
                    evidence = self._verified_takeover_evidence(
                        supervisor,
                        capability,
                        generated_at=command.consumed_at,
                        expected_cursor=committed_result.global_sequence - 1,
                        expected_head_sha256=str(
                            capability["expected_head_sha256"],
                        ),
                        create=False,
                    )
                else:
                    evidence = self._no_checkpoint_evidence()
                pending.response = self._chief_consume_response(
                    command,
                    committed_result,
                    evidence,
                )
                with self._status_lock:
                    self._cursor = committed_result.global_sequence
                return

            self._validate_new_takeover_timing(
                command,
                capability,
                now=_trusted_utc_now(),
            )
            before = supervisor.heads().global_head
            head_matches = (
                before.transaction_sha256
                == capability["expected_head_sha256"]
            )
            if head_matches:
                evidence = self._verified_takeover_evidence(
                    supervisor,
                    capability,
                    generated_at=command.consumed_at,
                    expected_cursor=before.global_sequence,
                    expected_head_sha256=before.transaction_sha256,
                    create=True,
                )
                after_checkpoint = supervisor.heads().global_head
                if (
                    after_checkpoint.global_sequence
                    != before.global_sequence
                    or after_checkpoint.transaction_sha256
                    != before.transaction_sha256
                ):
                    raise CompanyStateError(
                        "ledger head changed during pre-takeover delivery",
                    )
            else:
                evidence = self._no_checkpoint_evidence()

            committed_result = supervisor.takeover_chief(
                capability,
                command.known_carrier.as_dict(),
                consumed_at=command.consumed_at,
                grant_expires_at=command.grant_expires_at,
            )
            if (
                head_matches
                and committed_result.outcome != "consumed"
            ) or (
                not head_matches
                and committed_result.outcome != "fenced"
            ):
                raise CompanyStateError(
                    "takeover outcome differs from owner-side head decision",
                )
            pending.response = self._chief_consume_response(
                command,
                committed_result,
                evidence,
            )
            with self._status_lock:
                self._cursor = committed_result.global_sequence
        except _ControlRequestError as exc:
            pending.error_status = exc.status
            pending.error_code = exc.code
            pending.error_effect = exc.effect
            pending.error_cursor = exc.cursor
        except CompanyDeliveryPartialError:
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "takeover_checkpoint_failed"
            pending.error_effect = "effect_unknown"
        except CompanySupervisorDashboardRefreshError as exc:
            if isinstance(exc.result, LedgerAppendResult):
                cursor = exc.result.record.global_sequence
                pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
                pending.error_code = "committed_dashboard_refresh_failed"
                pending.error_effect = "committed"
                pending.error_cursor = cursor
                with self._status_lock:
                    self._cursor = cursor
            else:
                pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
                pending.error_code = "takeover_checkpoint_failed"
                pending.error_effect = "effect_unknown"
        except LedgerCommitEffectUnknownError:
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "effect_unknown"
            pending.error_effect = "effect_unknown"
        except CompanyProjectionDegradedError as exc:
            cursor = exc.result.record.global_sequence
            pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
            pending.error_code = "committed_projection_degraded"
            pending.error_effect = "committed"
            pending.error_cursor = cursor
            with self._status_lock:
                self._cursor = cursor
        except CompanyChiefTakeoverError:
            pending.error_status = HTTPStatus.CONFLICT
            pending.error_code = "chief_takeover_conflict"
            pending.error_effect = "effect_unknown"
        except (
            CompanySupervisorError,
            CompanyStateError,
            LedgerError,
            ValueError,
        ):
            if committed_result is not None:
                pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
                pending.error_code = (
                    "committed_pre_takeover_evidence_unavailable"
                )
                pending.error_effect = "committed"
                pending.error_cursor = committed_result.global_sequence
            else:
                pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
                pending.error_code = "chief_consume_failed"
                pending.error_effect = "effect_unknown"
        except Exception:
            if committed_result is not None:
                pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
                pending.error_code = (
                    "committed_pre_takeover_evidence_unavailable"
                )
                pending.error_effect = "committed"
                pending.error_cursor = committed_result.global_sequence
            else:
                pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
                pending.error_code = "chief_consume_failed"
                pending.error_effect = "effect_unknown"
        finally:
            pending.done.set()

    def _fail_pending_operations(self) -> None:
        while True:
            try:
                pending = self._operations.get_nowait()
            except queue.Empty:
                return
            if pending is None:
                continue
            pending.error_status = HTTPStatus.SERVICE_UNAVAILABLE
            pending.error_code = "service_stopping"
            pending.done.set()

    def _stop_and_fail_pending_operations(self) -> None:
        with self._admission_lock:
            self._stop.set()
            self._fail_pending_operations()

    def _descriptor(self, supervisor: CompanySupervisor, dashboard_url: str) -> dict[str, Any]:
        resolved = supervisor._state.resolved  # owner thread; runtime binding only
        company = {
            "company_id": str(resolved.pointer.company_id),
            "company_incarnation": int(resolved.pointer.company_incarnation),
            "lock_domain_generation": int(resolved.pointer.lock_domain_generation),
            "manifest_sha256": str(resolved.pointer.manifest_sha256),
            "pointer_sha256": str(resolved.pointer.pointer_sha256),
        }
        self._company_binding = dict(company)
        control = self._control
        if control is None:
            raise CompanyServiceError("control server is not started")
        return {
            "schema_version": SERVICE_DESCRIPTOR_SCHEMA,
            "slot_sha256": _slot_sha256(self.slot),
            "slot_path": str(self.slot),
            "company": company,
            "pid": os.getpid(),
            "service_instance_id": self.service_instance_id,
            "dashboard_url": dashboard_url,
            "control_url": f"http://127.0.0.1:{control.server_port}",
            "bearer_token": self.bearer_token,
            "telemetry_capabilities": {
                source_class: str(path)
                for source_class, path
                in self._telemetry_capability_paths.items()
            },
        }

    def _publish_telemetry_capabilities(
        self,
        descriptor: Mapping[str, Any],
    ) -> None:
        company = descriptor["company"]
        for source_class, path in self._telemetry_capability_paths.items():
            _atomic_json_write(
                path,
                {
                    "schema_version": TELEMETRY_CAPABILITY_SCHEMA,
                    "capability_id": self._telemetry_capability_ids[
                        source_class
                    ],
                    "slot_sha256": descriptor["slot_sha256"],
                    "slot_path": descriptor["slot_path"],
                    "company": dict(company),
                    "service_instance_id": self.service_instance_id,
                    "control_url": descriptor["control_url"],
                    "source_class": source_class,
                    "bearer_token": self.telemetry_tokens[source_class],
                },
            )

    def _start_control(self) -> None:
        server = _ControlHTTPServer(_ControlHandler, self)
        thread = threading.Thread(target=server.serve_forever, name="aoi-company-control", daemon=True)
        self._control = server
        self._control_thread = thread
        thread.start()

    def _close_control(self) -> None:
        server = self._control
        thread = self._control_thread
        self._control = None
        self._control_thread = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=5.0)

    def _cleanup_descriptor(self) -> None:
        try:
            value = _read_descriptor(self._descriptor_path)
            if value is not None and value.get("service_instance_id") == self.service_instance_id:
                self._descriptor_path.unlink()
        except (CompanyServiceError, OSError):
            # Cleanup is best effort.  A new process cannot publish while this
            # instance owns the descriptor, and an instance comparison prevents
            # an old process from erasing a successor after releasing the lock.
            pass
        for source_class, path in self._telemetry_capability_paths.items():
            try:
                value = _read_telemetry_capability(
                    path,
                    slot=self.slot,
                    runtime_root=self.runtime_root,
                    source_class=source_class,
                )
                if (
                    value.get("service_instance_id")
                    == self.service_instance_id
                ):
                    path.unlink()
            except (
                CompanyServiceError,
                OSError,
            ):
                pass

    def run(self) -> int:
        supervisor: CompanySupervisor | None = None
        try:
            supervisor = CompanySupervisor.open(
                self.slot,
                lock_timeout_seconds=self.lock_timeout_seconds,
            )
            if (
                self.expected_manifest_sha256 is not None
                and supervisor._state.resolved.pointer.manifest_sha256
                != self.expected_manifest_sha256
            ):
                raise CompanyServiceUnavailableError(
                    "company manifest changed after discovery",
                )
            self._supervisor = supervisor
            dashboard_url = supervisor.start_dashboard(
                environment_kind=self.dashboard_environment_kind,
            )
            self._start_control()
            descriptor = self._descriptor(supervisor, dashboard_url)
            # Do not publish discovery until both loopback servers answer.
            dashboard = Request(
                _validated_loopback_url(
                    dashboard_url,
                    label="Dashboard",
                    expected_path="/",
                )
                + "api/v1/meta",
                method="GET",
            )
            with _open_local(dashboard, timeout_seconds=2.0) as response:
                if response.status != HTTPStatus.OK:
                    raise CompanyServiceError("Dashboard self-probe failed")
                raw_meta = response.read(_MAX_DESCRIPTOR_BYTES + 1)
            if len(raw_meta) > _MAX_DESCRIPTOR_BYTES:
                raise CompanyServiceError("Dashboard self-probe response exceeds its bound")
            try:
                meta = json.loads(raw_meta)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise CompanyServiceError(
                    "Dashboard self-probe returned invalid JSON",
                ) from exc
            if (
                not isinstance(meta, dict)
                or meta.get("company_id") != descriptor["company"]["company_id"]
            ):
                raise CompanyServiceError(
                    "Dashboard self-probe returned another company",
                )
            control_probe = _control_request(descriptor, method="GET", path="/status", timeout_seconds=2.0)
            if control_probe.get("service_instance_id") != self.service_instance_id:
                raise CompanyServiceError("control self-probe returned another service")
            self._publish_telemetry_capabilities(descriptor)
            _atomic_json_write(self._descriptor_path, descriptor)
            next_refresh = time.monotonic()
            while not self._stop.is_set():
                timeout = max(
                    0.0,
                    min(0.25, next_refresh - time.monotonic()),
                )
                try:
                    pending = self._operations.get(timeout=timeout)
                except queue.Empty:
                    pending = None
                if pending is not None:
                    if isinstance(pending.command, _TelemetryIngestCommand):
                        self._execute_telemetry(pending)
                    elif isinstance(pending.command, ChiefTakeoverPrepareCommand):
                        self._execute_chief_prepare(pending)
                    elif isinstance(pending.command, ChiefTakeoverConsumeCommand):
                        self._execute_chief_consume(pending)
                    elif isinstance(pending.command, DepartmentDispatchCommand):
                        self._execute_department_dispatch(pending)
                    elif isinstance(pending.command, WorkDefinitionRegisterCommand):
                        self._execute_work_definition_register(pending)
                    elif isinstance(
                        pending.command,
                        WorkDefinitionEnforcementActivateCommand,
                    ):
                        self._execute_work_definition_enforcement(pending)
                    elif isinstance(
                        pending.command,
                        LegacyBridgePrestartQueryCommand,
                    ):
                        self._execute_legacy_bridge_prestart(pending)
                    else:
                        pending.error_status = HTTPStatus.INTERNAL_SERVER_ERROR
                        pending.error_code = "unsupported_control_command"
                        pending.done.set()
                now = time.monotonic()
                if now >= next_refresh:
                    cursor = supervisor.refresh_dashboard()
                    with self._status_lock:
                        self._cursor = cursor
                    next_refresh = now + self.refresh_seconds
            return 0
        except CompanyProcessLockBusyError as exc:
            raise CompanyServiceUnavailableError("a live unknown writer owns the company slot") from exc
        finally:
            # Keep the authenticated status endpoint alive in ``stopping``
            # state until the Supervisor has closed SQLite and released the
            # company lock.  Only then remove this instance's descriptor.
            self._stop_and_fail_pending_operations()
            try:
                if supervisor is not None:
                    supervisor.close()
            finally:
                try:
                    self._cleanup_descriptor()
                finally:
                    self._close_control()
                    self._supervisor = None
                    self._company_binding = None


def run_service_foreground(
    slot_root: str | os.PathLike[str],
    *,
    runtime_root: str | os.PathLike[str] | None = None,
    refresh_seconds: float = 0.25,
    lock_timeout_seconds: float = 5.0,
    expected_manifest_sha256: str | None = None,
    dashboard_environment_kind: str = "unverified",
) -> int:
    """Run the service in this process (useful for installed CLI and tests)."""

    refresh_seconds = _bounded_seconds(
        refresh_seconds,
        label="Dashboard refresh interval",
        maximum=60.0,
    )
    lock_timeout_seconds = _bounded_seconds(
        lock_timeout_seconds,
        label="company lock timeout",
        maximum=300.0,
    )
    if (
        expected_manifest_sha256 is not None
        and (
            not isinstance(expected_manifest_sha256, str)
            or _SHA256_RE.fullmatch(expected_manifest_sha256) is None
        )
    ):
        raise CompanyServiceError(
            "expected company manifest must be lowercase SHA-256",
        )
    return _ResidentService(
        slot=_absolute_slot(slot_root),
        runtime_root=None if runtime_root is None else Path(runtime_root),
        refresh_seconds=refresh_seconds,
        lock_timeout_seconds=lock_timeout_seconds,
        expected_manifest_sha256=expected_manifest_sha256,
        dashboard_environment_kind=_dashboard_environment_kind(
            dashboard_environment_kind,
        ),
    ).run()


def ensure_service(
    slot_root: str | os.PathLike[str],
    *,
    runtime_root: str | os.PathLike[str] | None = None,
    timeout_seconds: float = 10.0,
    expected_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Ensure one resident service exists without ever killing a PID.

    The child command is intentionally isolated and exact.  Source-checkout
    callers should use :func:`run_service_foreground`; packaging tests must use
    an installed distribution because ``-I`` ignores ``PYTHONPATH``.
    """

    timeout_seconds = _bounded_seconds(
        timeout_seconds,
        label="service readiness timeout",
        maximum=300.0,
    )
    if (
        expected_manifest_sha256 is not None
        and (
            not isinstance(expected_manifest_sha256, str)
            or _SHA256_RE.fullmatch(expected_manifest_sha256) is None
        )
    ):
        raise CompanyServiceError(
            "expected company manifest must be lowercase SHA-256",
        )

    def verify_expected(status: Mapping[str, Any]) -> None:
        if expected_manifest_sha256 is None:
            return
        descriptor = status.get("descriptor")
        company = (
            descriptor.get("company")
            if isinstance(descriptor, Mapping)
            else None
        )
        if (
            not isinstance(company, Mapping)
            or company.get("manifest_sha256")
            != expected_manifest_sha256
        ):
            raise CompanyServiceUnavailableError(
                "resident service manifest differs from discovery",
            )

    slot = _absolute_slot(slot_root)
    deadline = time.monotonic() + timeout_seconds
    existing = service_status(
        slot,
        runtime_root=runtime_root,
        timeout_seconds=min(1.0, timeout_seconds),
    )
    if existing["state"] in {"running", "stopping"}:
        verify_expected(existing)
    while existing["state"] == "stopping" and time.monotonic() < deadline:
        time.sleep(0.05)
        existing = service_status(
            slot,
            runtime_root=runtime_root,
            timeout_seconds=min(0.5, max(0.05, deadline - time.monotonic())),
        )
        if existing["state"] in {"running", "stopping"}:
            verify_expected(existing)
    if existing["state"] == "running":
        return existing
    if time.monotonic() >= deadline:
        raise CompanyServiceUnavailableError(
            "resident service did not finish stopping before the deadline",
        )
    command = [sys.executable, "-I", "-B", "-m", "aoi_orgware.company.service", "--slot-root", str(slot)]
    if runtime_root is not None:
        command.extend(["--runtime-root", str(Path(runtime_root))])
    if expected_manifest_sha256 is not None:
        command.extend(
            [
                "--expected-manifest-sha256",
                expected_manifest_sha256,
            ],
        )
    options: dict[str, Any] = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "close_fds": True}
    if os.name == "nt":
        options["creationflags"] = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    else:
        options["start_new_session"] = True
    child = subprocess.Popen(command, **options)  # noqa: S603 -- fixed interpreter/module and validated paths
    child_exited_at: float | None = None
    while time.monotonic() < deadline:
        status = service_status(slot, runtime_root=runtime_root, timeout_seconds=0.5)
        if status["state"] == "running":
            verify_expected(status)
            return status
        if child.poll() is not None:
            if child_exited_at is None:
                child_exited_at = time.monotonic()
            elif time.monotonic() - child_exited_at >= 0.5:
                raise CompanyServiceUnavailableError(
                    "resident service child exited before readiness",
                )
        time.sleep(0.05)
    raise CompanyServiceUnavailableError("resident service did not become ready")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aoi-company-service")
    parser.add_argument("--slot-root", required=True)
    parser.add_argument("--runtime-root")
    parser.add_argument("--refresh-seconds", type=float, default=0.25)
    parser.add_argument("--lock-timeout-seconds", type=float, default=5.0)
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument(
        "--dashboard-environment-kind",
        choices=sorted(_DASHBOARD_ENVIRONMENT_KINDS),
        default="unverified",
    )
    args = parser.parse_args(argv)
    try:
        return run_service_foreground(
            args.slot_root,
            runtime_root=args.runtime_root,
            refresh_seconds=args.refresh_seconds,
            lock_timeout_seconds=args.lock_timeout_seconds,
            expected_manifest_sha256=args.expected_manifest_sha256,
            dashboard_environment_kind=args.dashboard_environment_kind,
        )
    except CompanyServiceError as exc:
        print(f"aoi company service: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover - exercised through installed module invocation
    raise SystemExit(main())


__all__ = [
    "activate_service_work_definition_enforcement",
    "CompanyServiceError",
    "CompanyServiceOperationError",
    "CompanyServiceUnavailableError",
    "SERVICE_DESCRIPTOR_SCHEMA",
    "TELEMETRY_CAPABILITY_SCHEMA",
    "TELEMETRY_INGEST_RESULT_SCHEMA",
    "TELEMETRY_INGEST_SCHEMA",
    "consume_service_chief_takeover",
    "dispatch_service_department",
    "ensure_service",
    "ingest_service_telemetry",
    "main",
    "prepare_service_chief_takeover",
    "register_service_work_definition",
    "run_service_foreground",
    "runtime_descriptor_path",
    "service_status",
    "stop_service",
]
