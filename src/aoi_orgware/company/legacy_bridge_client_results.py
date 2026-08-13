"""Truthful immutable public results for the observational legacy client."""

from __future__ import annotations

from typing import Any, Mapping, NamedTuple, cast

from .legacy_bridge_client_receipts import ReceiptAttempt


RESULT_SCHEMA = "aoi.company.legacy-bridge-ingest-client-result.v1"


class LegacyBridgeIngestClientResult(NamedTuple):
    company_id: str
    bridge_scope_id: str
    attempt_id: str
    source_document_sha256: str
    source_matches_current_legacy_state: bool
    effect: str
    gate_decision: str | None
    gate_reason: str | None
    cursor: int | None
    exit_code: int
    prepared_receipt_sha256: str | None
    terminal_receipt_sha256: str | None
    reconciliation_receipt_sha256: str | None
    capacity_receipt_sha256: str | None

    def public_dict(self) -> dict[str, Any]:
        return {
            "schema_version": RESULT_SCHEMA,
            **self._asdict(),
            "authority": "none",
            "repo_write_capability": "absent",
            "dispatch_capability": "absent",
            "job_launch_capability": "absent",
        }


def _receipt_matches_result(
    receipt: Mapping[str, Any] | None,
    *,
    effect: str,
    exit_code: int,
    gate_decision: str | None,
    gate_reason: str | None,
    cursor: int | None,
) -> bool:
    """Return whether one immutable receipt proves this exact public outcome."""

    return receipt is not None and (
        receipt.get("effect"),
        receipt.get("exit_code"),
        receipt.get("gate_decision"),
        receipt.get("gate_reason"),
        receipt.get("gate_cursor"),
    ) == (effect, exit_code, gate_decision, gate_reason, cursor)


def attempt_result(
    attempt: ReceiptAttempt,
    *,
    current_state_sha256: str,
    effect: str,
    exit_code: int,
    gate_decision: str | None,
    gate_reason: str | None,
    cursor: int | None,
    terminal: Mapping[str, Any] | None,
    reconciliation: Mapping[str, Any] | None,
) -> LegacyBridgeIngestClientResult:
    matches = attempt.projection.legacy_state_sha256 == current_state_sha256
    if not matches and exit_code == 0:
        exit_code = 4
    terminal_matches = _receipt_matches_result(
        terminal,
        effect=effect,
        exit_code=exit_code,
        gate_decision=gate_decision,
        gate_reason=gate_reason,
        cursor=cursor,
    )
    reconciliation_matches = _receipt_matches_result(
        reconciliation,
        effect=effect,
        exit_code=exit_code,
        gate_decision=gate_decision,
        gate_reason=gate_reason,
        cursor=cursor,
    )
    return LegacyBridgeIngestClientResult(
        company_id=cast(str, attempt.prepared["company_id"]),
        bridge_scope_id=cast(str, attempt.prepared["bridge_scope_id"]),
        attempt_id=cast(str, attempt.prepared["attempt_id"]),
        source_document_sha256=cast(str, attempt.prepared["source_document_sha256"]),
        source_matches_current_legacy_state=matches,
        effect=effect,
        gate_decision=gate_decision,
        gate_reason=gate_reason,
        cursor=cursor,
        exit_code=exit_code,
        prepared_receipt_sha256=cast(str, attempt.prepared["receipt_sha256"]),
        terminal_receipt_sha256=(
            cast(str, terminal["receipt_sha256"])
            if terminal_matches and terminal is not None
            else None
        ),
        reconciliation_receipt_sha256=(
            cast(str, reconciliation["receipt_sha256"])
            if reconciliation_matches and reconciliation is not None
            else None
        ),
        capacity_receipt_sha256=None,
    )


def terminal_none_result(
    attempt: ReceiptAttempt,
    *,
    current_state_sha256: str,
) -> LegacyBridgeIngestClientResult:
    terminal = cast(dict[str, Any], attempt.terminal)
    return attempt_result(
        attempt,
        current_state_sha256=current_state_sha256,
        effect="none",
        exit_code=2,
        gate_decision=cast(str | None, terminal["gate_decision"]),
        gate_reason=cast(str | None, terminal["gate_reason"]),
        cursor=cast(int | None, terminal["gate_cursor"]),
        terminal=terminal,
        reconciliation=None,
    )


def capacity_result(
    company_id: str,
    *,
    bridge_scope_id: str,
    attempt_id: str,
    source_document_sha256: str,
    capacity_receipt: Mapping[str, Any] | None,
    reason: str,
) -> LegacyBridgeIngestClientResult:
    return LegacyBridgeIngestClientResult(
        company_id=company_id,
        bridge_scope_id=bridge_scope_id,
        attempt_id=attempt_id,
        source_document_sha256=source_document_sha256,
        source_matches_current_legacy_state=True,
        effect="none",
        gate_decision="blocked",
        gate_reason=reason,
        cursor=None,
        exit_code=4,
        prepared_receipt_sha256=None,
        terminal_receipt_sha256=None,
        reconciliation_receipt_sha256=None,
        capacity_receipt_sha256=(
            None
            if capacity_receipt is None
            else cast(str, capacity_receipt["receipt_sha256"])
        ),
    )


__all__ = [
    "RESULT_SCHEMA",
    "LegacyBridgeIngestClientResult",
    "attempt_result",
    "capacity_result",
    "terminal_none_result",
]
