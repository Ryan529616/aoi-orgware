"""Versioned terminal-truth contract for the synthetic IC Pack harness."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, cast


TERMINAL_RECEIPT_SCHEMA_VERSION = 2
_FIELDS = frozenset(
    {
        "schema_version",
        "launch_id",
        "request_sha256",
        "terminal_effect",
        "worker_exit_code",
        "worker_receipt_validation",
        "worker_receipt_validation_reason",
        "stdout_sha256",
        "stderr_sha256",
        "worker_receipt",
        "receipt_sha256",
    }
)
_SHA_CHARS = frozenset("0123456789abcdef")
_TERMINAL_EFFECTS = frozenset({"completed", "failed_known"})
_WORKER_RECEIPT_VALIDATIONS = frozenset(
    {"accepted", "rejected", "not_attempted"}
)
_WORKER_RECEIPT_VALIDATION_REASONS = frozenset(
    {"accepted", "invalid_worker_receipt", "worker_exit_nonzero"}
)


class ICPackTerminalError(ValueError):
    """Typed structural or semantic terminal-receipt failure."""


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ICPackTerminalError("terminal receipt is not canonical JSON") from exc


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in _SHA_CHARS for char in value)
    ):
        raise ICPackTerminalError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _choice(value: Any, label: str, allowed: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ICPackTerminalError(f"{label} is invalid")
    return value


def _receipt_digest(value: Mapping[str, Any]) -> str:
    return _sha256_bytes(
        _canonical_json_bytes(
            {key: item for key, item in value.items() if key != "receipt_sha256"}
        )
    )


def _validate_truth(value: Mapping[str, Any]) -> str:
    validation = value["worker_receipt_validation"]
    reason = value["worker_receipt_validation_reason"]
    exit_code = value["worker_exit_code"]
    effect = value["terminal_effect"]
    worker_receipt = value["worker_receipt"]
    if validation == "accepted":
        valid = (
            effect == "completed"
            and exit_code == 0
            and reason == "accepted"
            and isinstance(worker_receipt, dict)
        )
    elif validation == "rejected":
        valid = (
            effect == "failed_known"
            and exit_code == 0
            and reason == "invalid_worker_receipt"
            and worker_receipt is None
        )
    else:
        valid = (
            effect == "failed_known"
            and exit_code != 0
            and reason == "worker_exit_nonzero"
            and worker_receipt is None
        )
    if not valid:
        raise ICPackTerminalError("terminal receipt validation and worker exit are inconsistent")
    return cast(str, validation)


def build_terminal_receipt(
    *,
    launch_id: str,
    request_sha256: str,
    worker_exit_code: int,
    stdout: bytes,
    stderr: bytes,
    validation: str,
    validation_reason: str,
    worker_receipt: dict[str, Any] | None,
) -> dict[str, Any]:
    value = {
        "schema_version": TERMINAL_RECEIPT_SCHEMA_VERSION,
        "launch_id": launch_id,
        "request_sha256": request_sha256,
        "terminal_effect": "completed" if validation == "accepted" else "failed_known",
        "worker_exit_code": worker_exit_code,
        "worker_receipt_validation": validation,
        "worker_receipt_validation_reason": validation_reason,
        "stdout_sha256": _sha256_bytes(stdout),
        "stderr_sha256": _sha256_bytes(stderr),
        "worker_receipt": worker_receipt,
    }
    _validate_terminal_receipt(
        value, launch_id=launch_id, request_sha256=request_sha256, sealed=False
    )
    return {**value, "receipt_sha256": _sha256_bytes(_canonical_json_bytes(value))}


def _validate_terminal_receipt(
    value: Mapping[str, Any], *, launch_id: str, request_sha256: str, sealed: bool
) -> str:
    expected_fields = _FIELDS if sealed else _FIELDS - {"receipt_sha256"}
    if frozenset(value) != expected_fields:
        raise ICPackTerminalError("terminal receipt fields are invalid")
    _choice(value["terminal_effect"], "terminal effect", _TERMINAL_EFFECTS)
    _choice(
        value["worker_receipt_validation"],
        "worker receipt validation",
        _WORKER_RECEIPT_VALIDATIONS,
    )
    _choice(
        value["worker_receipt_validation_reason"],
        "worker receipt validation reason",
        _WORKER_RECEIPT_VALIDATION_REASONS,
    )
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != TERMINAL_RECEIPT_SCHEMA_VERSION
        or value["launch_id"] != launch_id
        or value["request_sha256"] != request_sha256
        or isinstance(value["worker_exit_code"], bool)
        or not isinstance(value["worker_exit_code"], int)
        or _sha256(value["stdout_sha256"], "terminal stdout digest")
        != value["stdout_sha256"]
        or _sha256(value["stderr_sha256"], "terminal stderr digest")
        != value["stderr_sha256"]
    ):
        raise ICPackTerminalError("terminal receipt identity or digest is invalid")
    if sealed and (
        _sha256(value["receipt_sha256"], "terminal receipt digest")
        != _receipt_digest(value)
    ):
        raise ICPackTerminalError("terminal receipt identity or digest is invalid")
    return _validate_truth(value)


def validate_terminal_receipt(
    value: Any, *, launch_id: str, request_sha256: str
) -> str:
    if not isinstance(value, dict):
        raise ICPackTerminalError("terminal receipt must be an object")
    return _validate_terminal_receipt(
        value, launch_id=launch_id, request_sha256=request_sha256, sealed=True
    )


__all__ = [
    "ICPackTerminalError",
    "TERMINAL_RECEIPT_SCHEMA_VERSION",
    "build_terminal_receipt",
    "validate_terminal_receipt",
]
