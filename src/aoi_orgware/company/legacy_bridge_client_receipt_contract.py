"""Deterministic semantic validation for legacy bridge client receipts.

The seals provide self-consistency and accidental-tamper evidence inside AOI's
cooperative same-user boundary.  They are not authentication against a process
that can rewrite a complete receipt and recompute every digest.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Mapping, NoReturn, cast

from .contracts import canonical_company_json_bytes, company_contract_sha256
from .legacy_bridge import normalize_legacy_bridge_snapshot
from .legacy_bridge_contract import legacy_bridge_scope_id
from .legacy_bridge_control_protocol import (
    LegacyBridgePrestartWireResultV1,
    build_legacy_bridge_prestart_query,
    decode_legacy_bridge_prestart_wire_result,
)
from .legacy_bridge_health import legacy_bridge_attempt_id
from .legacy_bridge_ingest_protocol import (
    LegacyBridgeIngestWireResultV1,
    build_legacy_bridge_ingest_command,
    decode_legacy_bridge_ingest_wire_result,
)
from .service import (
    _KNOWN_COMMITTED_CONTROL_ERRORS,
    _KNOWN_NO_EFFECT_CONTROL_ERRORS,
)


PREPARED_SCHEMA = "aoi.company.legacy-bridge-client-prepared.v1"
TERMINAL_SCHEMA = "aoi.company.legacy-bridge-client-terminal.v1"
RECONCILIATION_SCHEMA = "aoi.company.legacy-bridge-client-reconciliation.v1"
MAX_RECEIPT_BYTES = 256 * 1024

_HEX = frozenset("0123456789abcdef")
_FINAL_EFFECTS = frozenset({"none", "committed", "effect_unknown"})
_COMMITTED_REASONS = frozenset({
    "current_structural_ingest_observed",
    "current_ingest_degraded",
})
_PREPARED_FIELDS = frozenset({
    "company_id", "company_incarnation", "lock_domain_generation",
    "manifest_sha256", "service_instance_id", "task_id", "source_version",
    "legacy_archive_sha256", "legacy_state_sha256", "task_identity_digest",
    "bridge_scope_id", "attempt_id", "transaction_id", "command_id",
    "source_document_sha256", "source_document_size_bytes", "request_sha256",
    "received_at",
})
_TERMINAL_FIELDS = frozenset({
    "prepared_receipt_sha256", "attempt_id", "post_kind", "post_code",
    "post_status", "post_cursor", "post_effect", "post_result",
    "wire_result_sha256", "query_state", "query_result",
    "query_service_instance_id", "gate_decision", "gate_reason",
    "gate_cursor", "gate_sha256", "effect", "exit_code", "terminal_at",
})
_RECONCILIATION_FIELDS = frozenset({
    "prepared_receipt_sha256", "terminal_receipt_sha256", "attempt_id",
    "query_result", "query_service_instance_id", "gate_decision",
    "gate_reason", "gate_cursor", "gate_sha256", "effect", "exit_code",
    "reconciled_at",
})


class ReceiptContractError(RuntimeError):
    """One stable, secret-free receipt semantic failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str) -> NoReturn:
    raise ReceiptContractError(code)


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or len(value) != 64 or any(char not in _HEX for char in value):
        _fail(f"invalid_{label}")
    return value


def _identifier(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 256
        or not value[0].isalnum()
        or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:@/-" for char in value)
    ):
        _fail(f"invalid_{label}")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or isinstance(value, bool) or value < minimum:
        _fail(f"invalid_{label}")
    return value


def _parsed_timestamp(value: Any, label: str) -> datetime:
    if type(value) is not str or len(value) > 64:
        _fail(f"invalid_{label}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (OverflowError, ValueError) as exc:
        raise ReceiptContractError(f"invalid_{label}") from exc
    if parsed.tzinfo is None:
        _fail(f"invalid_{label}")
    return parsed


def _timestamp(value: Any, label: str) -> str:
    _parsed_timestamp(value, label)
    return cast(str, value)


def _verify_seal(value: Any, schema: str, fields: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields | {"schema_version", "receipt_sha256"}:
        _fail("invalid_client_receipt_schema")
    item = cast(dict[str, Any], value)
    if item["schema_version"] != schema:
        _fail("invalid_client_receipt_schema")
    supplied = _sha(item["receipt_sha256"], "client_receipt_sha256")
    base = {name: item[name] for name in item if name != "receipt_sha256"}
    try:
        expected = company_contract_sha256({
            "domain": f"{schema}.receipt",
            "receipt": base,
        })
        canonical_company_json_bytes(item, max_bytes=MAX_RECEIPT_BYTES)
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:
        raise ReceiptContractError("invalid_client_receipt_contract") from exc
    if supplied != expected:
        _fail("client_receipt_digest_mismatch")
    return dict(item)


def _source_task_id(source: bytes) -> str:
    try:
        value = json.loads(source.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ReceiptContractError("invalid_client_receipt_source") from exc
    if type(value) is not dict:
        _fail("invalid_client_receipt_source")
    return _identifier(value.get("task_id"), "task_id")


def validate_prepared(value: Any, source: bytes) -> dict[str, Any]:
    item = _verify_seal(value, PREPARED_SCHEMA, _PREPARED_FIELDS)
    try:
        projection = normalize_legacy_bridge_snapshot(source)
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:
        raise ReceiptContractError("invalid_client_receipt_source") from exc
    task_id = _source_task_id(source)
    scope = legacy_bridge_scope_id(
        projection.key,
        legacy_archive_sha256=projection.legacy_archive_sha256,
        task_identity_digest=projection.task_identity_digest,
    )
    source_sha256 = hashlib.sha256(source).hexdigest()
    attempt = legacy_bridge_attempt_id(
        scope,
        source_document_sha256=source_sha256,
        source_document_size_bytes=len(source),
    )
    for name in ("company_id", "service_instance_id", "manifest_sha256"):
        if name == "manifest_sha256":
            _sha(item[name], name)
        else:
            _identifier(item[name], name)
    try:
        command = build_legacy_bridge_ingest_command(
            service_instance_id=item["service_instance_id"],
            company_id=item["company_id"],
            company_incarnation=item["company_incarnation"],
            lock_domain_generation=item["lock_domain_generation"],
            manifest_sha256=item["manifest_sha256"],
            source_document=source,
            task_identity_digest=item["task_identity_digest"],
            legacy_archive_sha256=item["legacy_archive_sha256"],
            received_at=item["received_at"],
        )
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:
        raise ReceiptContractError("prepared_semantic_binding_mismatch") from exc
    expected = {
        "company_id": projection.key.company_id,
        "company_incarnation": projection.key.company_incarnation,
        "lock_domain_generation": projection.key.lock_domain_generation,
        "task_id": task_id,
        "source_version": projection.source_version,
        "legacy_archive_sha256": projection.legacy_archive_sha256,
        "legacy_state_sha256": projection.legacy_state_sha256,
        "task_identity_digest": projection.task_identity_digest,
        "bridge_scope_id": scope,
        "attempt_id": attempt,
        "transaction_id": f"legacy-bridge-transaction-{attempt}",
        "command_id": f"legacy-bridge-command-{attempt}",
        "source_document_sha256": source_sha256,
        "source_document_size_bytes": len(source),
        "request_sha256": hashlib.sha256(
            canonical_company_json_bytes(command.as_dict()),
        ).hexdigest(),
        "received_at": projection.observed_at,
    }
    if any(item[name] != expected_value for name, expected_value in expected.items()):
        _fail("prepared_semantic_binding_mismatch")
    return item


def _source_bound_commands(
    prepared: Mapping[str, Any],
    source: bytes,
    *,
    query_service_instance_id: str | None = None,
) -> tuple[Any, Any]:
    if (
        type(source) is not bytes
        or len(source) != prepared["source_document_size_bytes"]
        or hashlib.sha256(source).hexdigest() != prepared["source_document_sha256"]
    ):
        _fail("terminal_receipt_source_mismatch")
    try:
        ingest = build_legacy_bridge_ingest_command(
            service_instance_id=prepared["service_instance_id"],
            company_id=prepared["company_id"],
            company_incarnation=prepared["company_incarnation"],
            lock_domain_generation=prepared["lock_domain_generation"],
            manifest_sha256=prepared["manifest_sha256"],
            source_document=source,
            task_identity_digest=prepared["task_identity_digest"],
            legacy_archive_sha256=prepared["legacy_archive_sha256"],
            received_at=prepared["received_at"],
        )
        query = build_legacy_bridge_prestart_query(
            service_instance_id=(
                prepared["service_instance_id"]
                if query_service_instance_id is None
                else query_service_instance_id
            ),
            company_id=prepared["company_id"],
            company_incarnation=prepared["company_incarnation"],
            lock_domain_generation=prepared["lock_domain_generation"],
            manifest_sha256=prepared["manifest_sha256"],
            bridge_scope_id=prepared["bridge_scope_id"],
            source_document=source,
        )
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:
        raise ReceiptContractError("terminal_receipt_source_mismatch") from exc
    return ingest, query


def _post_witness(
    item: Mapping[str, Any],
    ingest_command: Any,
) -> tuple[str, LegacyBridgeIngestWireResultV1 | None]:
    kind = item["post_kind"]
    post_effect = item["post_effect"]
    if post_effect not in _FINAL_EFFECTS:
        _fail("terminal_receipt_post_mismatch")
    result_value = item["post_result"]
    if kind == "success":
        try:
            result = decode_legacy_bridge_ingest_wire_result(
                result_value,
                command=ingest_command,
            )
        except (MemoryError, SystemExit, KeyboardInterrupt):
            raise
        except Exception as exc:
            raise ReceiptContractError("terminal_receipt_post_mismatch") from exc
        canonical_result = result.as_dict()
        result_sha256 = hashlib.sha256(
            canonical_company_json_bytes(canonical_result),
        ).hexdigest()
        expected_effect = "committed" if result.effect == "none" else "effect_unknown"
        if (
            result_value != canonical_result
            or item["post_code"] is not None
            or item["post_status"] is not None
            or item["post_cursor"] != result.global_sequence
            or item["wire_result_sha256"] != result_sha256
            or post_effect != expected_effect
        ):
            _fail("terminal_receipt_post_mismatch")
        return expected_effect, result
    if result_value is not None or item["wire_result_sha256"] is not None:
        _fail("terminal_receipt_post_mismatch")
    if kind == "operation_error":
        code = _identifier(item["post_code"], "post_code")
        status = _integer(item["post_status"], "post_status", minimum=100)
        if status > 599:
            _fail("terminal_receipt_post_mismatch")
        cursor = item["post_cursor"]
        if cursor is not None:
            _integer(cursor, "post_cursor", minimum=1)
        if post_effect == "none":
            expected_status = _KNOWN_NO_EFFECT_CONTROL_ERRORS.get(code)
            if expected_status is None or status != int(expected_status):
                _fail("terminal_receipt_post_mismatch")
        elif post_effect == "committed":
            expected_status = _KNOWN_COMMITTED_CONTROL_ERRORS.get(code)
            if (
                expected_status is None
                or status != int(expected_status)
                or cursor is None
            ):
                _fail("terminal_receipt_post_mismatch")
        elif code != "effect_unknown":
            _fail("terminal_receipt_post_mismatch")
        return post_effect, None
    if kind == "transport_or_decode_error":
        if (
            item["post_code"] != "effect_unknown"
            or item["post_status"] is not None
            or item["post_cursor"] is not None
            or post_effect != "effect_unknown"
        ):
            _fail("terminal_receipt_post_mismatch")
        return post_effect, None
    if kind == "not_sent_existing_preparation":
        if (
            item["post_code"] is not None
            or item["post_status"] is not None
            or item["post_cursor"] is not None
            or post_effect != "effect_unknown"
        ):
            _fail("terminal_receipt_post_mismatch")
        return post_effect, None
    _fail("terminal_receipt_post_mismatch")


def _query_witness(
    value: Any,
    query_command: Any,
) -> LegacyBridgePrestartWireResultV1:
    try:
        result = decode_legacy_bridge_prestart_wire_result(
            value,
            command=query_command,
        )
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:
        raise ReceiptContractError("terminal_receipt_gate_mismatch") from exc
    if value != result.as_dict():
        _fail("terminal_receipt_gate_mismatch")
    return result


def validate_terminal(
    value: Any,
    prepared: Mapping[str, Any],
    source: bytes,
) -> dict[str, Any]:
    item = _verify_seal(value, TERMINAL_SCHEMA, _TERMINAL_FIELDS)
    if (
        item["prepared_receipt_sha256"] != prepared["receipt_sha256"]
        or item["attempt_id"] != prepared["attempt_id"]
        or item["post_kind"] not in {
            "success", "operation_error", "transport_or_decode_error",
            "not_sent_existing_preparation",
        }
        or item["query_state"] not in {"resident_durable_readback", "unavailable"}
        or item["effect"] not in _FINAL_EFFECTS
        or item["exit_code"] not in {0, 2, 3, 4}
        or (item["effect"] == "committed" and item["exit_code"] not in {0, 4})
        or (item["effect"] == "none" and item["exit_code"] != 2)
        or (item["effect"] == "effect_unknown" and item["exit_code"] != 3)
    ):
        _fail("terminal_receipt_binding_mismatch")
    _sha(item["prepared_receipt_sha256"], "prepared_receipt_sha256")
    _sha(item["attempt_id"], "attempt_id")
    for name in ("query_service_instance_id", "gate_reason"):
        if item[name] is not None:
            _identifier(item[name], name)
    for name in ("post_status", "post_cursor", "gate_cursor"):
        if item[name] is not None:
            _integer(item[name], name, minimum=1)
    for name in ("wire_result_sha256", "gate_sha256"):
        if item[name] is not None:
            _sha(item[name], name)
    if item["gate_decision"] is not None and item["gate_decision"] not in {
        "satisfied", "blocked", "unknown",
    }:
        _fail("terminal_receipt_gate_mismatch")
    gate_members = (
        item["gate_decision"], item["gate_reason"], item["gate_cursor"],
        item["gate_sha256"],
    )
    if (item["query_state"] == "resident_durable_readback") != all(
        member is not None for member in gate_members
    ) or (
        item["query_state"] == "resident_durable_readback"
        and item["query_service_instance_id"] is None
    ):
        _fail("terminal_receipt_gate_mismatch")
    ingest_command, query_command = _source_bound_commands(
        prepared,
        source,
        query_service_instance_id=(
            cast(str, item["query_service_instance_id"])
            if item["query_state"] == "resident_durable_readback"
            else None
        ),
    )
    post_effect, _post_result = _post_witness(item, ingest_command)
    query_result = None
    if item["query_state"] == "resident_durable_readback":
        query_result = _query_witness(item["query_result"], query_command)
        gate = query_result.gate
        if (
            item["query_service_instance_id"] != query_result.service_instance_id
            or item["gate_decision"] != gate.decision
            or item["gate_reason"] != gate.reason
            or item["gate_cursor"] != gate.ledger_cursor
            or item["gate_sha256"] != gate.gate_sha256
        ):
            _fail("terminal_receipt_gate_mismatch")
    elif item["query_result"] is not None:
        _fail("terminal_receipt_gate_mismatch")
    committed_readback = (
        query_result is not None
        and query_result.gate.reason in _COMMITTED_REASONS
    )
    if (
        committed_readback
        and item["post_cursor"] is not None
        and cast(int, item["gate_cursor"]) < cast(int, item["post_cursor"])
    ):
        _fail("terminal_receipt_cursor_regression")
    expected_decision = (
        "satisfied"
        if item["gate_reason"] == "current_structural_ingest_observed"
        else "blocked" if item["gate_reason"] == "current_ingest_degraded" else None
    )
    expected_effect = (
        "committed"
        if committed_readback
        else "effect_unknown" if post_effect == "committed" else post_effect
    )
    expected_exit = (
        0
        if expected_effect == "committed" and item["gate_decision"] == "satisfied"
        else 4 if expected_effect == "committed"
        else 2 if expected_effect == "none"
        else 3
    )
    if (
        item["effect"] != expected_effect
        or (expected_decision is not None and item["gate_decision"] != expected_decision)
        or item["exit_code"] != expected_exit
    ):
        _fail("terminal_receipt_effect_mismatch")
    if _parsed_timestamp(item["terminal_at"], "terminal_at") < _parsed_timestamp(
        prepared["received_at"],
        "received_at",
    ):
        _fail("terminal_receipt_monotonicity_mismatch")
    return item


def validate_reconciliation(
    value: Any,
    prepared: Mapping[str, Any],
    terminal: Mapping[str, Any],
    source: bytes,
) -> dict[str, Any]:
    item = _verify_seal(value, RECONCILIATION_SCHEMA, _RECONCILIATION_FIELDS)
    terminal = validate_terminal(terminal, prepared, source)
    if (
        item["prepared_receipt_sha256"] != prepared["receipt_sha256"]
        or item["terminal_receipt_sha256"] != terminal["receipt_sha256"]
        or item["attempt_id"] != prepared["attempt_id"]
        or terminal["effect"] != "effect_unknown"
        or terminal["exit_code"] != 3
        or item["effect"] != "committed"
        or item["exit_code"] not in {0, 4}
        or item["gate_reason"] not in _COMMITTED_REASONS
        or (
            item["gate_reason"] == "current_structural_ingest_observed"
            and (item["gate_decision"] != "satisfied" or item["exit_code"] != 0)
        )
        or (
            item["gate_reason"] == "current_ingest_degraded"
            and (item["gate_decision"] != "blocked" or item["exit_code"] != 4)
        )
    ):
        _fail("reconciliation_receipt_binding_mismatch")
    for name in (
        "prepared_receipt_sha256", "terminal_receipt_sha256", "attempt_id",
        "gate_sha256",
    ):
        _sha(item[name], name)
    _identifier(item["query_service_instance_id"], "query_service_instance_id")
    if item["gate_decision"] not in {"satisfied", "blocked"}:
        _fail("reconciliation_receipt_gate_mismatch")
    _identifier(item["gate_reason"], "gate_reason")
    _integer(item["gate_cursor"], "gate_cursor", minimum=1)
    _ingest_command, query_command = _source_bound_commands(
        prepared,
        source,
        query_service_instance_id=cast(str, item["query_service_instance_id"]),
    )
    query_result = _query_witness(item["query_result"], query_command)
    gate = query_result.gate
    if (
        item["query_service_instance_id"] != query_result.service_instance_id
        or item["gate_decision"] != gate.decision
        or item["gate_reason"] != gate.reason
        or item["gate_cursor"] != gate.ledger_cursor
        or item["gate_sha256"] != gate.gate_sha256
    ):
        _fail("reconciliation_receipt_gate_mismatch")
    cursor_floor = max(
        (
            cast(int, cursor)
            for cursor in (terminal["post_cursor"], terminal["gate_cursor"])
            if cursor is not None
        ),
        default=0,
    )
    terminal_at = _parsed_timestamp(terminal["terminal_at"], "terminal_at")
    reconciled_at = _parsed_timestamp(item["reconciled_at"], "reconciled_at")
    if item["gate_cursor"] < cursor_floor or reconciled_at < terminal_at:
        _fail("reconciliation_receipt_monotonicity_mismatch")
    return item


__all__ = [
    "MAX_RECEIPT_BYTES",
    "PREPARED_SCHEMA",
    "RECONCILIATION_SCHEMA",
    "TERMINAL_SCHEMA",
    "ReceiptContractError",
    "validate_prepared",
    "validate_reconciliation",
    "validate_terminal",
]
