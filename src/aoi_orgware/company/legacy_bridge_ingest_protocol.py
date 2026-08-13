"""Bounded resident command protocol for legacy-bridge snapshot ingestion.

The command is deliberately limited to publishing a digest-bound legacy
snapshot through the already-running company Supervisor.  It grants neither
repository-write, dispatch, job-launch, provider, nor browser authority.
Consumers must use the separate pre-start query after a successful response
when they need an exact-current ledger/read-model gate.
"""
from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any, NamedTuple, NoReturn, cast

from .contracts import (
    MAX_EVENT_PAYLOAD_BYTES,
    CompanyContractError,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from .legacy_bridge import (
    LegacyBridgeCompanyKey,
    LegacyBridgeError,
    normalize_legacy_bridge_snapshot,
)
from .legacy_bridge_contract import (
    build_legacy_bridge_observation,
    legacy_bridge_scope_id,
)
from .legacy_bridge_health import (
    MAX_SOURCE_DOCUMENT_BYTES,
    legacy_bridge_attempt_id,
)
from .legacy_bridge_publisher import LegacyBridgeIngestResult


LEGACY_BRIDGE_INGEST_SCHEMA = "aoi.company.legacy-bridge-ingest.v1"
LEGACY_BRIDGE_INGEST_RESULT_SCHEMA = (
    "aoi.company.legacy-bridge-ingest-result.v1"
)
MAX_LEGACY_BRIDGE_INGEST_CONTROL_BYTES = (
    ((MAX_SOURCE_DOCUMENT_BYTES + 2) // 3) * 4 + 4096
)

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "service_instance_id",
        "company_id",
        "company_incarnation",
        "lock_domain_generation",
        "manifest_sha256",
        "source_document_base64",
        "source_document_sha256",
        "source_document_size_bytes",
        "task_identity_digest",
        "legacy_archive_sha256",
        "received_at",
    }
)
_RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "service_instance_id",
        "company_id",
        "company_incarnation",
        "lock_domain_generation",
        "manifest_sha256",
        "transaction_id",
        "command_id",
        "bridge_scope_id",
        "assessment_id",
        "observation_id",
        "ingest_state",
        "coverage_state",
        "effect",
        "global_sequence",
        "idempotent_replay",
    }
)
_INGEST_STATES = frozenset({"observed", "degraded", "unknown"})
_COVERAGE_STATES = frozenset({"degraded", "unknown"})
_EFFECTS = frozenset({"none", "effect_unknown"})


class LegacyBridgeIngestProtocolError(CompanyContractError):
    """An untrusted legacy-bridge ingest envelope is not v1-valid."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class LegacyBridgeIngestCommand(NamedTuple):
    """Exact bounded bytes and immutable bindings for one resident ingest."""

    service_instance_id: str
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    manifest_sha256: str
    source_document: bytes
    source_document_sha256: str
    task_identity_digest: str
    legacy_archive_sha256: str
    received_at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": LEGACY_BRIDGE_INGEST_SCHEMA,
            "service_instance_id": self.service_instance_id,
            "company_id": self.company_id,
            "company_incarnation": self.company_incarnation,
            "lock_domain_generation": self.lock_domain_generation,
            "manifest_sha256": self.manifest_sha256,
            "source_document_base64": base64.b64encode(
                self.source_document,
            ).decode("ascii"),
            "source_document_sha256": self.source_document_sha256,
            "source_document_size_bytes": len(self.source_document),
            "task_identity_digest": self.task_identity_digest,
            "legacy_archive_sha256": self.legacy_archive_sha256,
            "received_at": self.received_at,
        }


class LegacyBridgeIngestWireResultV1(NamedTuple):
    """Decoded resident wire outcome; it is not an authority grant."""

    service_instance_id: str
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    manifest_sha256: str
    transaction_id: str
    command_id: str
    bridge_scope_id: str
    assessment_id: str
    observation_id: str | None
    ingest_state: str
    coverage_state: str
    effect: str
    global_sequence: int | None
    idempotent_replay: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": LEGACY_BRIDGE_INGEST_RESULT_SCHEMA,
            "service_instance_id": self.service_instance_id,
            "company_id": self.company_id,
            "company_incarnation": self.company_incarnation,
            "lock_domain_generation": self.lock_domain_generation,
            "manifest_sha256": self.manifest_sha256,
            "transaction_id": self.transaction_id,
            "command_id": self.command_id,
            "bridge_scope_id": self.bridge_scope_id,
            "assessment_id": self.assessment_id,
            "observation_id": self.observation_id,
            "ingest_state": self.ingest_state,
            "coverage_state": self.coverage_state,
            "effect": self.effect,
            "global_sequence": self.global_sequence,
            "idempotent_replay": self.idempotent_replay,
        }


def _fail(code: str) -> NoReturn:
    raise LegacyBridgeIngestProtocolError(code)


def _object(value: Any, *, code: str) -> Mapping[str, Any]:
    if type(value) is not dict:
        _fail(code)
    return cast(dict[str, Any], value)


def _identifier(value: Any, *, name: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        _fail(f"invalid_{name}")
    return value


def _positive_int(value: Any, *, name: str) -> int:
    if type(value) is not int or isinstance(value, bool) or value < 1:
        _fail(f"invalid_{name}")
    return value


def _nonnegative_int(value: Any, *, name: str) -> int:
    if type(value) is not int or isinstance(value, bool) or value < 0:
        _fail(f"invalid_{name}")
    return value


def _sha256(value: Any, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        _fail(f"invalid_{name}")
    return value


def _timestamp(value: Any, *, name: str) -> str:
    if type(value) is not str or len(value) > 64:
        _fail(f"invalid_{name}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, OverflowError, ValueError) as exc:
        raise LegacyBridgeIngestProtocolError(f"invalid_{name}") from exc
    if parsed.tzinfo is None:
        _fail(f"invalid_{name}")
    return value


def _source_bytes(value: Any) -> bytes:
    if (
        type(value) is not str
        or len(value) > MAX_LEGACY_BRIDGE_INGEST_CONTROL_BYTES
    ):
        _fail("invalid_source_document_base64")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise LegacyBridgeIngestProtocolError(
            "invalid_source_document_base64",
        ) from exc
    if len(raw) > MAX_SOURCE_DOCUMENT_BYTES:
        _fail("invalid_source_document_size_bytes")
    return raw


def parse_legacy_bridge_ingest(
    value: Any,
) -> LegacyBridgeIngestCommand:
    """Parse one exact source document without trusting supplied hashes."""

    request = _object(value, code="invalid_request_schema")
    if (
        set(request) != _REQUEST_FIELDS
        or request.get("schema_version") != LEGACY_BRIDGE_INGEST_SCHEMA
    ):
        _fail("invalid_request_schema")
    raw = _source_bytes(request["source_document_base64"])
    source_sha256 = _sha256(
        request["source_document_sha256"],
        name="source_document_sha256",
    )
    if (
        _nonnegative_int(
            request["source_document_size_bytes"],
            name="source_document_size_bytes",
        )
        != len(raw)
        or source_sha256 != hashlib.sha256(raw).hexdigest()
    ):
        _fail("source_document_mismatch")
    return LegacyBridgeIngestCommand(
        service_instance_id=_identifier(
            request["service_instance_id"],
            name="service_instance_id",
        ),
        company_id=_identifier(request["company_id"], name="company_id"),
        company_incarnation=_positive_int(
            request["company_incarnation"],
            name="company_incarnation",
        ),
        lock_domain_generation=_positive_int(
            request["lock_domain_generation"],
            name="lock_domain_generation",
        ),
        manifest_sha256=_sha256(
            request["manifest_sha256"],
            name="manifest_sha256",
        ),
        source_document=raw,
        source_document_sha256=source_sha256,
        task_identity_digest=_sha256(
            request["task_identity_digest"],
            name="task_identity_digest",
        ),
        legacy_archive_sha256=_sha256(
            request["legacy_archive_sha256"],
            name="legacy_archive_sha256",
        ),
        received_at=_timestamp(request["received_at"], name="received_at"),
    )


def build_legacy_bridge_ingest_command(
    *,
    service_instance_id: str,
    company_id: str,
    company_incarnation: int,
    lock_domain_generation: int,
    manifest_sha256: str,
    source_document: bytes,
    task_identity_digest: str,
    legacy_archive_sha256: str,
    received_at: str,
) -> LegacyBridgeIngestCommand:
    """Build a parser-equivalent command from exact caller-owned bytes."""

    if type(source_document) is not bytes:
        _fail("invalid_source_document_size_bytes")
    command = LegacyBridgeIngestCommand(
        service_instance_id=_identifier(
            service_instance_id,
            name="service_instance_id",
        ),
        company_id=_identifier(company_id, name="company_id"),
        company_incarnation=_positive_int(
            company_incarnation,
            name="company_incarnation",
        ),
        lock_domain_generation=_positive_int(
            lock_domain_generation,
            name="lock_domain_generation",
        ),
        manifest_sha256=_sha256(manifest_sha256, name="manifest_sha256"),
        source_document=source_document,
        source_document_sha256=hashlib.sha256(source_document).hexdigest(),
        task_identity_digest=_sha256(
            task_identity_digest,
            name="task_identity_digest",
        ),
        legacy_archive_sha256=_sha256(
            legacy_archive_sha256,
            name="legacy_archive_sha256",
        ),
        received_at=_timestamp(received_at, name="received_at"),
    )
    return parse_legacy_bridge_ingest(command.as_dict())


def _exact_command(value: Any) -> LegacyBridgeIngestCommand:
    if type(value) is not LegacyBridgeIngestCommand:
        _fail("invalid_ingest_command")
    return value


def _exact_result_binding(value: Any, expected: Any) -> bool:
    """Compare a response binding without Python's bool/int coercion."""

    return type(value) is type(expected) and value == expected


def _valid_result_enums(
    ingest_state: Any,
    coverage_state: Any,
    effect: Any,
) -> bool:
    """Check enum members only after their exact runtime type is known."""

    return (
        type(ingest_state) is str
        and ingest_state in _INGEST_STATES
        and type(coverage_state) is str
        and coverage_state in _COVERAGE_STATES
        and type(effect) is str
        and effect in _EFFECTS
    )


def build_legacy_bridge_ingest_wire_result(
    command: LegacyBridgeIngestCommand,
    result: LegacyBridgeIngestResult,
) -> LegacyBridgeIngestWireResultV1:
    """Bind one publisher outcome to its exact resident command."""

    command = _exact_command(command)
    if type(result) is not LegacyBridgeIngestResult:
        _fail("invalid_ingest_result")
    scope = legacy_bridge_scope_id(
        LegacyBridgeCompanyKey(
            command.company_id,
            command.company_incarnation,
            command.lock_domain_generation,
        ),
        legacy_archive_sha256=command.legacy_archive_sha256,
        task_identity_digest=command.task_identity_digest,
    )
    attempt = legacy_bridge_attempt_id(
        scope,
        source_document_sha256=command.source_document_sha256,
        source_document_size_bytes=len(command.source_document),
    )
    expected_observation = _expected_observation_id(command)
    if not _valid_result_enums(
        result.ingest_state,
        result.coverage_state,
        result.effect,
    ) or type(result.idempotent_replay) is not bool:
        _fail("invalid_ingest_result")
    if (
        result.transaction_id != f"legacy-bridge-transaction-{attempt}"
        or result.command_id != f"legacy-bridge-command-{attempt}"
        or result.bridge_scope_id != scope
        or result.assessment_id
        != company_contract_sha256(
            {"domain": "aoi.legacy-bridge.coverage.v1", "attempt_id": attempt},
        )
    ):
        _fail("result_identity_mismatch")
    if result.effect == "effect_unknown":
        if (
            result.ingest_state != "unknown"
            or result.coverage_state != "unknown"
            or result.global_sequence is not None
            or result.idempotent_replay
            or result.observation_id is not None
        ):
            _fail("effect_unknown_result_mismatch")
    elif result.coverage_state != "degraded":
        _fail("committed_result_coverage_mismatch")
    elif expected_observation is None:
        if result.ingest_state != "degraded" or result.observation_id is not None:
            _fail("degraded_result_observation_mismatch")
    elif (
        result.ingest_state != "observed"
        or result.observation_id != expected_observation
    ):
        _fail("observed_result_observation_mismatch")
    if result.effect == "none" and (
        result.global_sequence is None
        or type(result.global_sequence) is not int
        or result.global_sequence < 1
    ):
        _fail("committed_result_cursor_missing")
    return LegacyBridgeIngestWireResultV1(
        service_instance_id=command.service_instance_id,
        company_id=command.company_id,
        company_incarnation=command.company_incarnation,
        lock_domain_generation=command.lock_domain_generation,
        manifest_sha256=command.manifest_sha256,
        transaction_id=_identifier(result.transaction_id, name="transaction_id"),
        command_id=_identifier(result.command_id, name="command_id"),
        bridge_scope_id=_sha256(result.bridge_scope_id, name="bridge_scope_id"),
        assessment_id=_identifier(result.assessment_id, name="assessment_id"),
        observation_id=(
            None
            if result.observation_id is None
            else _identifier(result.observation_id, name="observation_id")
        ),
        ingest_state=result.ingest_state,
        coverage_state=result.coverage_state,
        effect=result.effect,
        global_sequence=result.global_sequence,
        idempotent_replay=result.idempotent_replay,
    )


def _expected_observation_id(command: LegacyBridgeIngestCommand) -> str | None:
    """Derive the publisher's observed/degraded split from exact command bytes."""

    key = LegacyBridgeCompanyKey(
        command.company_id,
        command.company_incarnation,
        command.lock_domain_generation,
    )
    try:
        projection = normalize_legacy_bridge_snapshot(command.source_document)
    except LegacyBridgeError:
        return None
    if (
        projection.key != key
        or projection.legacy_archive_sha256 != command.legacy_archive_sha256
        or projection.task_identity_digest != command.task_identity_digest
    ):
        return None
    observation = build_legacy_bridge_observation(
        projection,
        ingested_at=command.received_at,
    )
    try:
        canonical_company_json_bytes(
            observation,
            max_bytes=MAX_EVENT_PAYLOAD_BYTES,
        )
    except CompanyContractError:
        return None
    return cast(str, observation["observation_id"])


def decode_legacy_bridge_ingest_wire_result(
    value: Any,
    *,
    command: LegacyBridgeIngestCommand,
) -> LegacyBridgeIngestWireResultV1:
    """Decode structural wire data without granting further authority."""

    command = _exact_command(command)
    payload = _object(value, code="invalid_result_schema")
    if (
        set(payload) != _RESULT_FIELDS
        or payload.get("schema_version") != LEGACY_BRIDGE_INGEST_RESULT_SCHEMA
    ):
        _fail("invalid_result_schema")
    for name in (
        "service_instance_id",
        "company_id",
        "company_incarnation",
        "lock_domain_generation",
        "manifest_sha256",
    ):
        if not _exact_result_binding(payload[name], getattr(command, name)):
            _fail("result_binding_mismatch")
    result = LegacyBridgeIngestWireResultV1(
        service_instance_id=command.service_instance_id,
        company_id=command.company_id,
        company_incarnation=command.company_incarnation,
        lock_domain_generation=command.lock_domain_generation,
        manifest_sha256=command.manifest_sha256,
        transaction_id=_identifier(payload["transaction_id"], name="transaction_id"),
        command_id=_identifier(payload["command_id"], name="command_id"),
        bridge_scope_id=_sha256(payload["bridge_scope_id"], name="bridge_scope_id"),
        assessment_id=_identifier(payload["assessment_id"], name="assessment_id"),
        observation_id=(
            None
            if payload["observation_id"] is None
            else _identifier(payload["observation_id"], name="observation_id")
        ),
        ingest_state=cast(str, payload["ingest_state"]),
        coverage_state=cast(str, payload["coverage_state"]),
        effect=cast(str, payload["effect"]),
        global_sequence=payload["global_sequence"],
        idempotent_replay=payload["idempotent_replay"],
    )
    if not _valid_result_enums(
        result.ingest_state,
        result.coverage_state,
        result.effect,
    ) or type(result.idempotent_replay) is not bool:
        _fail("invalid_result_schema")
    if result.global_sequence is not None:
        _positive_int(result.global_sequence, name="global_sequence")
    return build_legacy_bridge_ingest_wire_result(
        command,
        LegacyBridgeIngestResult(
            result.transaction_id,
            result.command_id,
            result.bridge_scope_id,
            result.assessment_id,
            result.observation_id,
            result.ingest_state,
            result.coverage_state,
            result.effect,
            result.global_sequence,
            result.idempotent_replay,
        ),
    )


__all__ = [
    "LEGACY_BRIDGE_INGEST_RESULT_SCHEMA",
    "LEGACY_BRIDGE_INGEST_SCHEMA",
    "MAX_LEGACY_BRIDGE_INGEST_CONTROL_BYTES",
    "LegacyBridgeIngestCommand",
    "LegacyBridgeIngestProtocolError",
    "LegacyBridgeIngestWireResultV1",
    "build_legacy_bridge_ingest_command",
    "build_legacy_bridge_ingest_wire_result",
    "decode_legacy_bridge_ingest_wire_result",
    "parse_legacy_bridge_ingest",
]
