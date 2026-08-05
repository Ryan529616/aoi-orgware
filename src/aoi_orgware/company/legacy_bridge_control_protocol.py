"""Strict read-only resident protocol for a legacy-bridge pre-start query.

The result is structural evidence only.  It deliberately carries no mutation,
dispatch, or job-launch authority, and a satisfied structural gate does not
claim provider-runtime coverage.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
import hashlib
import re
from typing import Any, cast, NamedTuple
from weakref import WeakKeyDictionary

from .contracts import CompanyContractError, company_contract_sha256
from .legacy_bridge_gate import (
    LegacyBridgeGateError,
    LegacyBridgePrestartGateV1,
    derive_legacy_bridge_prestart_gate,
)
from .legacy_bridge_health import MAX_SOURCE_DOCUMENT_BYTES
from .state import CompanyStateOwner


LEGACY_BRIDGE_PRESTART_QUERY_SCHEMA = (
    "aoi.company.legacy-bridge-prestart-query.v1"
)
LEGACY_BRIDGE_PRESTART_RESULT_SCHEMA = (
    "aoi.company.legacy-bridge-prestart-result.v1"
)
MAX_LEGACY_BRIDGE_PRESTART_CONTROL_BYTES = (
    ((MAX_SOURCE_DOCUMENT_BYTES + 2) // 3) * 4 + 4096
)

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_DECISIONS = frozenset({"satisfied", "blocked", "unknown"})
_REASONS = frozenset({
    "current_structural_ingest_observed",
    "current_ingest_degraded",
    "current_source_not_observed",
    "current_health_missing",
    "company_state_degraded",
})
_GATE_FIELDS = frozenset(LegacyBridgePrestartGateV1._fields)
_QUERY_FIELDS = frozenset({
    "schema_version", "service_instance_id", "company_id",
    "company_incarnation", "lock_domain_generation", "manifest_sha256",
    "bridge_scope_id", "source_document_base64", "source_document_sha256",
    "source_document_size_bytes",
})
_RESULT_FIELDS = frozenset({
    "schema_version", "service_instance_id", "company_id",
    "company_incarnation", "lock_domain_generation", "manifest_sha256",
    "bridge_scope_id", "cursor", "gate",
})


class LegacyBridgeControlProtocolError(CompanyContractError):
    """An untrusted legacy-bridge query envelope is not v1-valid."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class LegacyBridgePrestartQueryCommand(NamedTuple):
    """Bound source bytes for one resident-only structural query."""

    service_instance_id: str
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    manifest_sha256: str
    bridge_scope_id: str
    source_document: bytes
    source_document_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": LEGACY_BRIDGE_PRESTART_QUERY_SCHEMA,
            "service_instance_id": self.service_instance_id,
            "company_id": self.company_id,
            "company_incarnation": self.company_incarnation,
            "lock_domain_generation": self.lock_domain_generation,
            "manifest_sha256": self.manifest_sha256,
            "bridge_scope_id": self.bridge_scope_id,
            "source_document_base64": base64.b64encode(
                self.source_document,
            ).decode("ascii"),
            "source_document_sha256": self.source_document_sha256,
            "source_document_size_bytes": len(self.source_document),
        }


class LegacyBridgePrestartWireResultV1(NamedTuple):
    """Decoded wire data; its gate decision is not semantically verified."""

    service_instance_id: str
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    manifest_sha256: str
    bridge_scope_id: str
    cursor: int
    gate: LegacyBridgePrestartGateV1

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": LEGACY_BRIDGE_PRESTART_RESULT_SCHEMA,
            "service_instance_id": self.service_instance_id,
            "company_id": self.company_id,
            "company_incarnation": self.company_incarnation,
            "lock_domain_generation": self.lock_domain_generation,
            "manifest_sha256": self.manifest_sha256,
            "bridge_scope_id": self.bridge_scope_id,
            "cursor": self.cursor,
            "gate": self.gate.to_dict(),
        }


_VERIFIED_RESULT_TOKEN = object()


class _LegacyBridgePrestartVerifiedResultV1:
    """Immutable proof wrapper constructible only by this module's verifier."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls,
        result: LegacyBridgePrestartWireResultV1,
        *,
        _token: object | None = None,
    ) -> _LegacyBridgePrestartVerifiedResultV1:
        if cls is not _LegacyBridgePrestartVerifiedResultV1:
            _fail("verified_result_subclass_forbidden")
        if (
            _token is not _VERIFIED_RESULT_TOKEN
            or type(result) is not LegacyBridgePrestartWireResultV1
        ):
            _fail("verified_result_requires_state_rederivation")
        instance = object.__new__(cls)
        _VERIFIED_RESULTS[instance] = result
        return instance

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("verified result cannot be subclassed")

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("verified result is immutable")

    @property
    def result(self) -> LegacyBridgePrestartWireResultV1:
        return _registered_verified_result(self)

    @property
    def verification(self) -> str:
        _registered_verified_result(self)
        return "resident_state_rederived"


_VERIFIED_RESULTS: WeakKeyDictionary[
    _LegacyBridgePrestartVerifiedResultV1,
    LegacyBridgePrestartWireResultV1,
] = WeakKeyDictionary()


def _fail(code: str) -> None:
    raise LegacyBridgeControlProtocolError(code)


def _registered_verified_result(
    value: _LegacyBridgePrestartVerifiedResultV1,
) -> LegacyBridgePrestartWireResultV1:
    try:
        return _VERIFIED_RESULTS[value]
    except (KeyError, TypeError) as exc:
        raise LegacyBridgeControlProtocolError(
            "unregistered_verified_result",
        ) from exc


def _object(value: Any, *, code: str) -> Mapping[str, Any]:
    if type(value) is not dict:
        _fail(code)
    return cast(dict[str, Any], value)


def _identifier(value: Any, *, name: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        _fail(f"invalid_{name}")
    return cast(str, value)


def _positive_int(value: Any, *, name: str) -> int:
    if type(value) is not int or isinstance(value, bool) or value < 1:
        _fail(f"invalid_{name}")
    return cast(int, value)


def _sha256(value: Any, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        _fail(f"invalid_{name}")
    return cast(str, value)


def _source_bytes(value: Any) -> bytes:
    if type(value) is not str or len(value) > MAX_LEGACY_BRIDGE_PRESTART_CONTROL_BYTES:
        _fail("invalid_source_document_base64")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise LegacyBridgeControlProtocolError(
            "invalid_source_document_base64",
        ) from exc
    if len(raw) > MAX_SOURCE_DOCUMENT_BYTES:
        _fail("invalid_source_document_size_bytes")
    return raw


def parse_legacy_bridge_prestart_query(
    value: Any,
) -> LegacyBridgePrestartQueryCommand:
    """Parse bounded exact bytes; no caller-supplied source digest is trusted."""

    request = _object(value, code="invalid_request_schema")
    if (
        set(request) != _QUERY_FIELDS
        or request.get("schema_version") != LEGACY_BRIDGE_PRESTART_QUERY_SCHEMA
    ):
        _fail("invalid_request_schema")
    raw = _source_bytes(request["source_document_base64"])
    declared_size = _positive_int_or_zero(
        request["source_document_size_bytes"],
        name="source_document_size_bytes",
    )
    declared_digest = _sha256(
        request["source_document_sha256"],
        name="source_document_sha256",
    )
    if declared_size != len(raw) or declared_digest != hashlib.sha256(raw).hexdigest():
        _fail("source_document_mismatch")
    return LegacyBridgePrestartQueryCommand(
        service_instance_id=_identifier(
            request["service_instance_id"], name="service_instance_id",
        ),
        company_id=_identifier(request["company_id"], name="company_id"),
        company_incarnation=_positive_int(
            request["company_incarnation"], name="company_incarnation",
        ),
        lock_domain_generation=_positive_int(
            request["lock_domain_generation"], name="lock_domain_generation",
        ),
        manifest_sha256=_sha256(
            request["manifest_sha256"], name="manifest_sha256",
        ),
        bridge_scope_id=_sha256(
            request["bridge_scope_id"], name="bridge_scope_id",
        ),
        source_document=raw,
        source_document_sha256=declared_digest,
    )


def _positive_int_or_zero(value: Any, *, name: str) -> int:
    if type(value) is not int or isinstance(value, bool) or value < 0:
        _fail(f"invalid_{name}")
    return cast(int, value)


def build_legacy_bridge_prestart_query(
    *,
    service_instance_id: str,
    company_id: str,
    company_incarnation: int,
    lock_domain_generation: int,
    manifest_sha256: str,
    bridge_scope_id: str,
    source_document: bytes,
) -> LegacyBridgePrestartQueryCommand:
    """Build a parser-equivalent command from exact caller-owned bytes."""

    if type(source_document) is not bytes or len(source_document) > MAX_SOURCE_DOCUMENT_BYTES:
        _fail("invalid_source_document_size_bytes")
    command = LegacyBridgePrestartQueryCommand(
        service_instance_id=_identifier(service_instance_id, name="service_instance_id"),
        company_id=_identifier(company_id, name="company_id"),
        company_incarnation=_positive_int(company_incarnation, name="company_incarnation"),
        lock_domain_generation=_positive_int(
            lock_domain_generation, name="lock_domain_generation",
        ),
        manifest_sha256=_sha256(manifest_sha256, name="manifest_sha256"),
        bridge_scope_id=_sha256(bridge_scope_id, name="bridge_scope_id"),
        source_document=source_document,
        source_document_sha256=hashlib.sha256(source_document).hexdigest(),
    )
    return parse_legacy_bridge_prestart_query(command.as_dict())


def _optional_identifier(value: Any, *, name: str) -> str | None:
    if value is None:
        return None
    return _identifier(value, name=name)


def _optional_sha256(value: Any, *, name: str) -> str | None:
    if value is None:
        return None
    return _sha256(value, name=name)


def _optional_cursor(value: Any, *, name: str) -> int | None:
    if value is None:
        return None
    return _positive_int(value, name=name)


def _exact_command(value: Any) -> LegacyBridgePrestartQueryCommand:
    if type(value) is not LegacyBridgePrestartQueryCommand:
        _fail("invalid_query_command")
    return cast(LegacyBridgePrestartQueryCommand, value)


def _all_or_none(fields: Mapping[str, Any], names: tuple[str, ...]) -> bool:
    present = tuple(fields[name] is not None for name in names)
    return all(present) or not any(present)


def _validate_gate_semantics(fields: Mapping[str, Any]) -> None:
    outcomes = {
        "company_state_degraded": (
            "unknown", "unknown", "unknown", "unknown", "unknown",
        ),
        "current_health_missing": (
            "unknown", "unknown", "unknown", "missing", "unknown",
        ),
        "current_source_not_observed": (
            "blocked", None, "degraded", "stale", "unknown",
        ),
        "current_ingest_degraded": (
            "blocked", "degraded", "degraded", "exact", "durable_readback",
        ),
        "current_structural_ingest_observed": (
            "satisfied", "observed", "degraded", "exact", "durable_readback",
        ),
    }
    expected = outcomes.get(fields["reason"])
    actual = (
        fields["decision"],
        fields["ingest_state"],
        fields["provider_coverage_state"],
        fields["source_currentness"],
        fields["publication_effect"],
    )
    if expected is None or any(
        wanted is not None and observed != wanted
        for observed, wanted in zip(actual, expected, strict=True)
    ):
        _fail("gate_outcome_mismatch")
    coverage_names = (
        "transaction_id", "command_id", "transaction_sha256",
        "coverage_record_id", "coverage_event_id",
        "coverage_global_sequence", "coverage_payload_sha256",
        "assessment_id",
    )
    observation_names = (
        "observation_record_id", "observation_event_id",
        "observation_global_sequence", "observation_payload_sha256",
        "observation_id",
    )
    if not _all_or_none(fields, coverage_names):
        _fail("gate_coverage_evidence_mismatch")
    if not _all_or_none(fields, observation_names):
        _fail("gate_observation_evidence_mismatch")
    coverage_present = fields["coverage_record_id"] is not None
    observation_present = fields["observation_record_id"] is not None
    if observation_present and not coverage_present:
        _fail("gate_observation_evidence_mismatch")
    if fields["reason"] == "current_health_missing" and coverage_present:
        _fail("gate_coverage_evidence_mismatch")
    if (
        fields["reason"] == "current_structural_ingest_observed"
        and not observation_present
    ):
        _fail("gate_observation_evidence_mismatch")
    if fields["reason"] != "company_state_degraded" and (
        fields["ledger_cursor"] != fields["readmodel_cursor"]
        or fields["ledger_head_sha256"] != fields["readmodel_head_sha256"]
    ):
        _fail("gate_head_mismatch")
    if observation_present and (
        fields["coverage_global_sequence"]
        != fields["observation_global_sequence"]
    ):
        _fail("gate_evidence_sequence_mismatch")


def _parse_gate(value: Any, command: LegacyBridgePrestartQueryCommand) -> LegacyBridgePrestartGateV1:
    command = _exact_command(command)
    gate_value = _object(value, code="invalid_gate")
    if set(gate_value) != _GATE_FIELDS:
        _fail("invalid_gate")
    fields = dict(gate_value)
    if (
        type(fields["schema_version"]) is not int
        or fields["schema_version"] != 1
        or type(fields["decision"]) is not str
        or type(fields["reason"]) is not str
        or fields["company_id"] != command.company_id
        or fields["company_incarnation"] != command.company_incarnation
        or fields["lock_domain_generation"] != command.lock_domain_generation
        or fields["bridge_scope_id"] != command.bridge_scope_id
        or fields["source_document_sha256"] != command.source_document_sha256
        or fields["source_document_size_bytes"] != len(command.source_document)
        or fields["decision"] not in _DECISIONS
        or fields["reason"] not in _REASONS
        or fields["authority"] != "none"
        or fields["repo_write_capability"] != "absent"
        or fields["dispatch_capability"] != "absent"
        or fields["job_launch_capability"] != "absent"
    ):
        _fail("gate_binding_mismatch")
    _positive_int(fields["company_incarnation"], name="company_incarnation")
    _positive_int(
        fields["lock_domain_generation"],
        name="lock_domain_generation",
    )
    for name in (
        "ledger_cursor", "readmodel_cursor", "source_document_size_bytes",
    ):
        _positive_int_or_zero(fields[name], name=name)
    for name in (
        "ledger_head_sha256", "readmodel_head_sha256", "pointer_sha256",
        "source_document_sha256", "gate_sha256",
    ):
        _sha256(fields[name], name=name)
    for name in (
        "transaction_sha256", "coverage_payload_sha256",
        "observation_payload_sha256",
    ):
        _optional_sha256(fields[name], name=name)
    for name in (
        "transaction_id", "command_id", "coverage_record_id",
        "coverage_event_id", "observation_record_id", "observation_event_id",
        "assessment_id", "observation_id",
    ):
        _optional_identifier(fields[name], name=name)
    for name in ("coverage_global_sequence", "observation_global_sequence"):
        _optional_cursor(fields[name], name=name)
    if (
        type(fields["ingest_state"]) is not str
        or type(fields["provider_coverage_state"]) is not str
        or type(fields["source_currentness"]) is not str
        or type(fields["publication_effect"]) is not str
    ):
        _fail("invalid_gate")
    _validate_gate_semantics(fields)
    unsigned = {name: fields[name] for name in _GATE_FIELDS - {"gate_sha256"}}
    expected_digest = company_contract_sha256({
        "domain": "aoi.legacy-bridge.prestart-gate.v1", **unsigned,
    })
    if fields["gate_sha256"] != expected_digest:
        _fail("gate_digest_mismatch")
    return LegacyBridgePrestartGateV1(**fields)


def _build_legacy_bridge_prestart_wire_result(
    command: LegacyBridgePrestartQueryCommand,
    gate: LegacyBridgePrestartGateV1,
) -> LegacyBridgePrestartWireResultV1:
    """Bind one server-derived gate to exactly one request and cursor."""

    command = _exact_command(command)
    if type(gate) is not LegacyBridgePrestartGateV1:
        _fail("invalid_gate")
    parsed_gate = _parse_gate(gate.to_dict(), command)
    result = LegacyBridgePrestartWireResultV1(
        service_instance_id=command.service_instance_id,
        company_id=command.company_id,
        company_incarnation=command.company_incarnation,
        lock_domain_generation=command.lock_domain_generation,
        manifest_sha256=command.manifest_sha256,
        bridge_scope_id=command.bridge_scope_id,
        cursor=parsed_gate.ledger_cursor,
        gate=parsed_gate,
    )
    return decode_legacy_bridge_prestart_wire_result(
        result.as_dict(), command=command,
    )


def derive_legacy_bridge_prestart_response(
    state: CompanyStateOwner,
    command: LegacyBridgePrestartQueryCommand,
) -> LegacyBridgePrestartWireResultV1:
    """Derive one read-only response on the resident owner's exact state."""

    command = _exact_command(command)
    try:
        gate = derive_legacy_bridge_prestart_gate(
            state,
            command.bridge_scope_id,
            command.source_document,
        )
    except LegacyBridgeGateError:
        raise
    return _build_legacy_bridge_prestart_wire_result(command, gate)


def decode_legacy_bridge_prestart_wire_result(
    value: Any,
    *,
    command: LegacyBridgePrestartQueryCommand,
) -> LegacyBridgePrestartWireResultV1:
    """Decode structural wire data without granting semantic authority."""

    command = _exact_command(command)
    result = _object(value, code="invalid_result_schema")
    if (
        set(result) != _RESULT_FIELDS
        or result.get("schema_version") != LEGACY_BRIDGE_PRESTART_RESULT_SCHEMA
    ):
        _fail("invalid_result_schema")
    for name in ("company_incarnation", "lock_domain_generation"):
        _positive_int(result[name], name=name)
    for name in (
        "service_instance_id", "company_id", "company_incarnation",
        "lock_domain_generation", "manifest_sha256", "bridge_scope_id",
    ):
        if result[name] != getattr(command, name):
            _fail("result_binding_mismatch")
    cursor = _positive_int(result["cursor"], name="cursor")
    gate = _parse_gate(result["gate"], command)
    if cursor != gate.ledger_cursor:
        _fail("result_cursor_mismatch")
    return LegacyBridgePrestartWireResultV1(
        service_instance_id=command.service_instance_id,
        company_id=command.company_id,
        company_incarnation=command.company_incarnation,
        lock_domain_generation=command.lock_domain_generation,
        manifest_sha256=command.manifest_sha256,
        bridge_scope_id=command.bridge_scope_id,
        cursor=cursor,
        gate=gate,
    )


def verify_legacy_bridge_prestart_result(
    state: CompanyStateOwner,
    value: Any,
    *,
    command: LegacyBridgePrestartQueryCommand,
) -> _LegacyBridgePrestartVerifiedResultV1:
    """Re-derive exact current state; a wire digest alone is never proof."""

    if type(state) is not CompanyStateOwner:
        _fail("invalid_company_state_owner")
    decoded = decode_legacy_bridge_prestart_wire_result(value, command=command)
    expected = derive_legacy_bridge_prestart_response(state, command)
    if decoded != expected:
        _fail("result_state_mismatch")
    return _LegacyBridgePrestartVerifiedResultV1(
        decoded,
        _token=_VERIFIED_RESULT_TOKEN,
    )


def require_verified_legacy_bridge_prestart_result(
    value: Any,
) -> LegacyBridgePrestartWireResultV1:
    """Return a wire result only for an exact registered verifier product."""

    if type(value) is not _LegacyBridgePrestartVerifiedResultV1:
        _fail("unregistered_verified_result")
    return _registered_verified_result(value)


__all__ = [
    "LEGACY_BRIDGE_PRESTART_QUERY_SCHEMA",
    "LEGACY_BRIDGE_PRESTART_RESULT_SCHEMA",
    "MAX_LEGACY_BRIDGE_PRESTART_CONTROL_BYTES",
    "LegacyBridgeControlProtocolError",
    "LegacyBridgePrestartQueryCommand",
    "LegacyBridgePrestartWireResultV1",
    "build_legacy_bridge_prestart_query",
    "decode_legacy_bridge_prestart_wire_result",
    "derive_legacy_bridge_prestart_response",
    "parse_legacy_bridge_prestart_query",
    "require_verified_legacy_bridge_prestart_result",
    "verify_legacy_bridge_prestart_result",
]
