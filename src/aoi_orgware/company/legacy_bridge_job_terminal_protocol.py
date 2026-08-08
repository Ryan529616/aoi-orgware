"""Authenticated resident protocol for one legacy job terminal reconcile."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Any, Mapping, NamedTuple, NoReturn

from .contracts import CompanyContractError, canonical_company_json_bytes
from .legacy_bridge_job_terminal import (
    build_legacy_bridge_job_terminal_source,
    legacy_bridge_job_terminal_key_id,
    legacy_bridge_job_terminal_receipt_id,
)


LEGACY_BRIDGE_JOB_TERMINAL_RECONCILE_SCHEMA = (
    "aoi.company.legacy-bridge-job-terminal-reconcile.v1"
)
LEGACY_BRIDGE_JOB_TERMINAL_RESULT_SCHEMA = (
    "aoi.company.legacy-bridge-job-terminal-result.v1"
)
MAX_LEGACY_BRIDGE_JOB_TERMINAL_EVIDENCE_BYTES = 524_288
MAX_LEGACY_BRIDGE_JOB_TERMINAL_ARTIFACT_BYTES = 589_824
MAX_LEGACY_BRIDGE_JOB_TERMINAL_CONTROL_BYTES = (
    ((MAX_LEGACY_BRIDGE_JOB_TERMINAL_EVIDENCE_BYTES + 2) // 3) * 4
    + ((MAX_LEGACY_BRIDGE_JOB_TERMINAL_ARTIFACT_BYTES + 2) // 3) * 4
    + 16_384
)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_REQUEST_FIELDS = frozenset({
    "schema_version", "service_instance_id", "company_id",
    "company_incarnation", "lock_domain_generation", "manifest_sha256",
    "terminal_evidence_base64", "terminal_evidence_sha256",
    "terminal_evidence_size_bytes", "artifact_payloads",
})
_ARTIFACT_PAYLOAD_FIELDS = frozenset({"role", "data_base64"})
_RESULT_FIELDS = frozenset({
    "schema_version", "service_instance_id", "company_id",
    "company_incarnation", "lock_domain_generation", "manifest_sha256",
    "transaction_id", "command_id", "bridge_scope_id", "terminal_key_id",
    "receipt_id", "effect", "global_sequence", "idempotent_replay",
})


class LegacyBridgeJobTerminalProtocolError(CompanyContractError):
    """The terminal control envelope is malformed or ambiguously bound."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class LegacyBridgeJobTerminalCommand(NamedTuple):
    service_instance_id: str
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    manifest_sha256: str
    terminal_evidence: dict[str, Any]
    terminal_evidence_sha256: str
    terminal_artifacts: tuple[tuple[str, bytes], ...]

    def as_dict(self) -> dict[str, Any]:
        raw = canonical_company_json_bytes(self.terminal_evidence)
        return {
            "schema_version": LEGACY_BRIDGE_JOB_TERMINAL_RECONCILE_SCHEMA,
            "service_instance_id": self.service_instance_id,
            "company_id": self.company_id,
            "company_incarnation": self.company_incarnation,
            "lock_domain_generation": self.lock_domain_generation,
            "manifest_sha256": self.manifest_sha256,
            "terminal_evidence_base64": base64.b64encode(raw).decode("ascii"),
            "terminal_evidence_sha256": self.terminal_evidence_sha256,
            "terminal_evidence_size_bytes": len(raw),
            "artifact_payloads": [
                {
                    "role": role,
                    "data_base64": base64.b64encode(payload).decode("ascii"),
                }
                for role, payload in self.terminal_artifacts
            ],
        }


class LegacyBridgeJobTerminalWireResultV1(NamedTuple):
    service_instance_id: str
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    manifest_sha256: str
    transaction_id: str
    command_id: str
    bridge_scope_id: str
    terminal_key_id: str
    receipt_id: str
    effect: str
    global_sequence: int
    idempotent_replay: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": LEGACY_BRIDGE_JOB_TERMINAL_RESULT_SCHEMA,
            **self._asdict(),
        }


def _fail(code: str) -> NoReturn:
    raise LegacyBridgeJobTerminalProtocolError(code)


def _identifier(value: Any, name: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        _fail(f"invalid_{name}")
    return value


def _sha(value: Any, name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail(f"invalid_{name}")
    return value


def _positive(value: Any, name: str) -> int:
    if type(value) is not int or isinstance(value, bool) or value < 1:
        _fail(f"invalid_{name}")
    return value


def _nonnegative(value: Any, name: str) -> int:
    if type(value) is not int or isinstance(value, bool) or value < 0:
        _fail(f"invalid_{name}")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _evidence(value: Any) -> tuple[bytes, dict[str, Any]]:
    if type(value) is not str or len(value) > MAX_LEGACY_BRIDGE_JOB_TERMINAL_CONTROL_BYTES:
        _fail("invalid_terminal_evidence_base64")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
        decoded = json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=_unique_object,
        )
        canonical = canonical_company_json_bytes(decoded)
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except (
        UnicodeEncodeError, UnicodeDecodeError, binascii.Error,
        json.JSONDecodeError, CompanyContractError, RecursionError, ValueError,
    ) as exc:
        raise LegacyBridgeJobTerminalProtocolError(
            "invalid_terminal_evidence",
        ) from exc
    if (
        type(decoded) is not dict
        or not raw
        or len(raw) > MAX_LEGACY_BRIDGE_JOB_TERMINAL_EVIDENCE_BYTES
        or canonical != raw
    ):
        _fail("invalid_terminal_evidence")
    try:
        source = build_legacy_bridge_job_terminal_source(
            decoded,
            source_observation_id="0" * 64,
            source_observation_payload_sha256="0" * 64,
            source_observation_global_sequence=1,
        )
    except CompanyContractError as exc:
        raise LegacyBridgeJobTerminalProtocolError(
            "invalid_terminal_evidence",
        ) from exc
    evidence = {
        key: source[key]
        for key in decoded
    }
    return raw, evidence


def _artifact_payloads(
    value: Any,
    *,
    evidence: Mapping[str, Any],
) -> tuple[tuple[str, bytes], ...]:
    refs = evidence.get("artifacts")
    if (
        type(value) is not list
        or type(refs) is not list
        or len(value) != len(refs)
    ):
        _fail("invalid_artifact_payloads")
    decoded: list[tuple[str, bytes]] = []
    total = 0
    for member in value:
        if type(member) is not dict or frozenset(member) != _ARTIFACT_PAYLOAD_FIELDS:
            _fail("invalid_artifact_payload")
        role = _identifier(member["role"], "artifact_role")
        encoded = member["data_base64"]
        if type(encoded) is not str or len(encoded) > (
            ((MAX_LEGACY_BRIDGE_JOB_TERMINAL_ARTIFACT_BYTES + 2) // 3) * 4
        ):
            _fail("invalid_artifact_payload")
        try:
            payload = base64.b64decode(encoded.encode("ascii"), validate=True)
        except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
            raise LegacyBridgeJobTerminalProtocolError(
                "invalid_artifact_payload",
            ) from exc
        if not payload or base64.b64encode(payload).decode("ascii") != encoded:
            _fail("invalid_artifact_payload")
        total += len(payload)
        if total > MAX_LEGACY_BRIDGE_JOB_TERMINAL_ARTIFACT_BYTES:
            _fail("artifact_payloads_too_large")
        decoded.append((role, payload))
    if decoded != sorted(decoded, key=lambda item: item[0].encode("utf-8")):
        _fail("artifact_payloads_not_canonical")
    if len({role for role, _payload in decoded}) != len(decoded):
        _fail("duplicate_artifact_payload_role")
    for (role, payload), reference in zip(decoded, refs, strict=True):
        if (
            type(reference) is not dict
            or reference.get("role") != role
            or reference.get("sha256") != hashlib.sha256(payload).hexdigest()
            or reference.get("size_bytes") != len(payload)
        ):
            _fail("artifact_payload_binding_mismatch")
    return tuple(decoded)


def parse_legacy_bridge_job_terminal_reconcile(
    value: Any,
) -> LegacyBridgeJobTerminalCommand:
    """Parse exact canonical evidence without trusting declared identities."""

    if (
        type(value) is not dict
        or frozenset(value) != _REQUEST_FIELDS
        or value.get("schema_version")
        != LEGACY_BRIDGE_JOB_TERMINAL_RECONCILE_SCHEMA
    ):
        _fail("invalid_request_schema")
    raw, evidence = _evidence(value["terminal_evidence_base64"])
    digest = _sha(value["terminal_evidence_sha256"], "terminal_evidence_sha256")
    if (
        _nonnegative(
            value["terminal_evidence_size_bytes"],
            "terminal_evidence_size_bytes",
        ) != len(raw)
        or digest != hashlib.sha256(raw).hexdigest()
    ):
        _fail("terminal_evidence_mismatch")
    artifacts = _artifact_payloads(value["artifact_payloads"], evidence=evidence)
    command = LegacyBridgeJobTerminalCommand(
        _identifier(value["service_instance_id"], "service_instance_id"),
        _identifier(value["company_id"], "company_id"),
        _positive(value["company_incarnation"], "company_incarnation"),
        _nonnegative(value["lock_domain_generation"], "lock_domain_generation"),
        _sha(value["manifest_sha256"], "manifest_sha256"),
        evidence,
        digest,
        artifacts,
    )
    if (
        evidence["company_id"] != command.company_id
        or evidence["company_incarnation"] != command.company_incarnation
        or evidence["lock_domain_generation"] != command.lock_domain_generation
    ):
        _fail("terminal_evidence_company_mismatch")
    return command


def build_legacy_bridge_job_terminal_command(
    *,
    service_instance_id: str,
    company_id: str,
    company_incarnation: int,
    lock_domain_generation: int,
    manifest_sha256: str,
    terminal_evidence: Mapping[str, Any],
    terminal_artifacts: Mapping[str, bytes],
) -> LegacyBridgeJobTerminalCommand:
    if not isinstance(terminal_evidence, Mapping) or not isinstance(
        terminal_artifacts, Mapping,
    ):
        _fail("invalid_terminal_command_input")
    artifact_items = tuple(terminal_artifacts.items())
    if any(
        type(role) is not str or type(payload) is not bytes
        for role, payload in artifact_items
    ):
        _fail("invalid_terminal_command_input")
    try:
        raw = canonical_company_json_bytes(dict(terminal_evidence))
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except (CompanyContractError, RecursionError, TypeError, ValueError) as exc:
        raise LegacyBridgeJobTerminalProtocolError(
            "invalid_terminal_command_input",
        ) from exc
    candidate = {
        "schema_version": LEGACY_BRIDGE_JOB_TERMINAL_RECONCILE_SCHEMA,
        "service_instance_id": service_instance_id,
        "company_id": company_id,
        "company_incarnation": company_incarnation,
        "lock_domain_generation": lock_domain_generation,
        "manifest_sha256": manifest_sha256,
        "terminal_evidence_base64": base64.b64encode(raw).decode("ascii"),
        "terminal_evidence_sha256": hashlib.sha256(raw).hexdigest(),
        "terminal_evidence_size_bytes": len(raw),
        "artifact_payloads": [
            {
                "role": role,
                "data_base64": base64.b64encode(payload).decode("ascii"),
            }
            for role, payload in sorted(
                artifact_items, key=lambda item: item[0].encode("utf-8"),
            )
        ],
    }
    return parse_legacy_bridge_job_terminal_reconcile(candidate)


def decode_legacy_bridge_job_terminal_result(
    value: Any,
    *,
    command: LegacyBridgeJobTerminalCommand,
) -> LegacyBridgeJobTerminalWireResultV1:
    """Decode one authenticated response and bind its deterministic identity.

    The ledger cursor remains a resident observation and requires ledger or
    Dashboard readback before it is used as independent evidence.
    """

    if (
        type(value) is not dict
        or frozenset(value) != _RESULT_FIELDS
        or value.get("schema_version") != LEGACY_BRIDGE_JOB_TERMINAL_RESULT_SCHEMA
    ):
        _fail("invalid_result_schema")
    result = LegacyBridgeJobTerminalWireResultV1(
        _identifier(value["service_instance_id"], "service_instance_id"),
        _identifier(value["company_id"], "company_id"),
        _positive(value["company_incarnation"], "company_incarnation"),
        _nonnegative(value["lock_domain_generation"], "lock_domain_generation"),
        _sha(value["manifest_sha256"], "manifest_sha256"),
        _identifier(value["transaction_id"], "transaction_id"),
        _identifier(value["command_id"], "command_id"),
        _sha(value["bridge_scope_id"], "bridge_scope_id"),
        _sha(value["terminal_key_id"], "terminal_key_id"),
        _sha(value["receipt_id"], "receipt_id"),
        str(value["effect"]),
        _positive(value["global_sequence"], "global_sequence"),
        value["idempotent_replay"],
    )
    try:
        expected_source = build_legacy_bridge_job_terminal_source(
            command.terminal_evidence,
            source_observation_id="0" * 64,
            source_observation_payload_sha256="0" * 64,
            source_observation_global_sequence=1,
        )
        expected_terminal_key = legacy_bridge_job_terminal_key_id(
            expected_source,
        )
        expected_receipt_id = legacy_bridge_job_terminal_receipt_id(
            expected_terminal_key,
            expected_source["request_evidence_sha256"],
        )
    except CompanyContractError as exc:
        raise LegacyBridgeJobTerminalProtocolError(
            "terminal_result_binding_mismatch",
        ) from exc
    expected_transaction_id = f"legacy-terminal-transaction-{expected_receipt_id}"
    expected_command_id = f"legacy-terminal-command-{expected_receipt_id}"
    if (
        type(result.idempotent_replay) is not bool
        or result.effect != "committed"
        or result.service_instance_id != command.service_instance_id
        or result.company_id != command.company_id
        or result.company_incarnation != command.company_incarnation
        or result.lock_domain_generation != command.lock_domain_generation
        or result.manifest_sha256 != command.manifest_sha256
        or command.terminal_evidence_sha256
        != expected_source["request_evidence_sha256"]
        or result.bridge_scope_id != command.terminal_evidence["bridge_scope_id"]
        or result.terminal_key_id != expected_terminal_key
        or result.receipt_id != expected_receipt_id
        or result.transaction_id != expected_transaction_id
        or result.command_id != expected_command_id
    ):
        _fail("terminal_result_binding_mismatch")
    return result


__all__ = [
    "LEGACY_BRIDGE_JOB_TERMINAL_RECONCILE_SCHEMA",
    "LEGACY_BRIDGE_JOB_TERMINAL_RESULT_SCHEMA",
    "MAX_LEGACY_BRIDGE_JOB_TERMINAL_ARTIFACT_BYTES",
    "MAX_LEGACY_BRIDGE_JOB_TERMINAL_CONTROL_BYTES",
    "LegacyBridgeJobTerminalCommand", "LegacyBridgeJobTerminalProtocolError",
    "LegacyBridgeJobTerminalWireResultV1",
    "build_legacy_bridge_job_terminal_command",
    "decode_legacy_bridge_job_terminal_result",
    "parse_legacy_bridge_job_terminal_reconcile",
]
