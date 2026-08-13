from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from aoi_orgware.company import legacy_bridge_client_capacity as capacity
from aoi_orgware.company import legacy_bridge_client_receipts as receipts
from aoi_orgware.company.contracts import canonical_company_json_bytes


T0 = "2026-08-05T08:00:00Z"


def _attempt(index: int, *, state: str = "marker_only") -> capacity.CapacityAttemptV1:
    attempt_id = hashlib.sha256(f"AOI-SYNTHETIC-ATTEMPT-{index}".encode()).hexdigest()
    marker = hashlib.sha256(attempt_id.encode("ascii")).hexdigest()
    source = hashlib.sha256(f"source-{index}".encode()).hexdigest()
    prepared = hashlib.sha256(f"prepared-{index}".encode()).hexdigest()
    terminal = hashlib.sha256(f"terminal-{index}".encode()).hexdigest()
    reconciliation = hashlib.sha256(f"reconciled-{index}".encode()).hexdigest()
    members: dict[str, tuple[str | None, str | None, str | None, str | None]] = {
        "marker_only": (None, None, None, None),
        "source_only": (source, None, None, None),
        "prepared_effect_unknown": (source, prepared, None, None),
        "terminal_none": (source, prepared, terminal, None),
        "terminal_committed": (source, prepared, terminal, None),
        "terminal_effect_unknown": (source, prepared, terminal, None),
        "reconciled_committed": (source, prepared, terminal, reconciliation),
    }
    source_sha, prepared_sha, terminal_sha, reconciliation_sha = members[state]
    return capacity.CapacityAttemptV1(
        attempt_id=attempt_id,
        attempt_marker_sha256=marker,
        source_sha256=source_sha,
        prepared_receipt_sha256=prepared_sha,
        terminal_receipt_sha256=terminal_sha,
        reconciliation_receipt_sha256=reconciliation_sha,
        effective_state=state,
    )


def _saturated() -> tuple[capacity.CapacityAttemptV1, ...]:
    return tuple(_attempt(index) for index in range(capacity.ATTEMPT_LIMIT))


def _tree_identity(root: Path) -> tuple[tuple[str, str], ...]:
    return tuple(
        (path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest())
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix())
        if path.is_file()
    )


def test_capacity_receipt_is_permutation_stable_and_binds_full_inventory() -> None:
    attempts = _saturated()
    scope = "a" * 64

    forward = capacity.build_capacity_receipt(scope, attempts, sealed_at=T0)
    reverse = capacity.build_capacity_receipt(scope, tuple(reversed(attempts)), sealed_at=T0)

    assert forward == reverse
    assert len(forward["attempts"]) == capacity.ATTEMPT_LIMIT
    assert forward["attempts"][0]["attempt_id"] == min(
        item.attempt_id for item in attempts
    )
    assert len(canonical_company_json_bytes(forward)) < capacity.MAX_CAPACITY_RECEIPT_BYTES
    assert capacity.validate_capacity_receipt(
        forward,
        expected_scope_id=scope,
        current_attempts=attempts,
    ) == forward


def test_capacity_receipt_allows_only_monotonic_attempt_completion() -> None:
    sealed = list(_saturated())
    scope = "b" * 64
    receipt = capacity.build_capacity_receipt(scope, tuple(sealed), sealed_at=T0)
    advanced = list(sealed)
    advanced[0] = _attempt(0, state="reconciled_committed")

    capacity.validate_capacity_receipt(
        receipt,
        expected_scope_id=scope,
        current_attempts=tuple(advanced),
    )

    divergent = list(advanced)
    value = divergent[1]
    divergent[1] = value._replace(attempt_marker_sha256="f" * 64)
    with pytest.raises(capacity.CapacityContractError, match="digest_drift"):
        capacity.validate_capacity_receipt(
            receipt,
            expected_scope_id=scope,
            current_attempts=tuple(divergent),
        )


def test_capacity_receipt_tamper_and_identity_drift_fail_closed() -> None:
    attempts = _saturated()
    scope = "c" * 64
    receipt = capacity.build_capacity_receipt(scope, attempts, sealed_at=T0)
    tampered = json.loads(json.dumps(receipt))
    tampered["sealed_at"] = "2026-08-05T08:00:01Z"

    with pytest.raises(capacity.CapacityContractError, match="digest_mismatch"):
        capacity.validate_capacity_receipt(
            tampered,
            expected_scope_id=scope,
            current_attempts=attempts,
        )

    changed = list(attempts)
    changed[-1] = _attempt(capacity.ATTEMPT_LIMIT + 1)
    with pytest.raises(capacity.CapacityContractError, match="identity_drift"):
        capacity.validate_capacity_receipt(
            receipt,
            expected_scope_id=scope,
            current_attempts=tuple(changed),
        )


def test_store_seals_once_replays_and_keeps_predecessor_immutable(
    tmp_path: Path,
) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    scope = "d" * 64
    scope_root = receipts.ensure_scope_root(slot, scope)
    for item in _saturated():
        receipts.attempt_root(scope_root, item.attempt_id, create=True)
    observed = receipts.inventory(scope_root, scope)

    first = receipts.require_attempt_capacity(
        scope_root,
        observed,
        "e" * 64,
        sealed_at=T0,
    )
    replay_inventory = receipts.inventory(scope_root, scope)
    second = receipts.require_attempt_capacity(
        scope_root,
        replay_inventory,
        "e" * 64,
        sealed_at="2026-08-05T09:00:00Z",
    )

    assert first == second == replay_inventory.capacity_receipt
    assert first is not None
    assert first["decision"] == "successor_rollover_required"
    assert first["attempt_count"] == capacity.ATTEMPT_LIMIT
    predecessor = _tree_identity(scope_root)
    successor_root = receipts.ensure_scope_root(slot, "f" * 64)
    assert successor_root != scope_root
    assert _tree_identity(scope_root) == predecessor


def test_store_recovers_unpublished_capacity_temporary(
    tmp_path: Path,
) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    scope = "1" * 64
    scope_root = receipts.ensure_scope_root(slot, scope)
    attempts = _saturated()
    for item in attempts:
        receipts.attempt_root(scope_root, item.attempt_id, create=True)
    receipt = capacity.build_capacity_receipt(scope, attempts, sealed_at=T0)
    temporary = scope_root / f".aoi-cv1-capacity.json-{'2' * 32}.tmp"
    temporary.write_bytes(canonical_company_json_bytes(receipt))

    unpublished = receipts.inventory(scope_root, scope)

    assert unpublished.capacity_receipt is None
    assert not temporary.exists()
    published = receipts.require_attempt_capacity(
        scope_root,
        unpublished,
        "3" * 64,
        sealed_at=T0,
    )
    assert published is not None
    assert receipts.inventory(scope_root, scope).capacity_receipt == published


def test_store_rejects_capacity_digest_drift(tmp_path: Path) -> None:
    slot = tmp_path / "company"
    slot.mkdir()
    scope = "4" * 64
    scope_root = receipts.ensure_scope_root(slot, scope)
    for item in _saturated():
        receipts.attempt_root(scope_root, item.attempt_id, create=True)
    observed = receipts.inventory(scope_root, scope)
    receipt = receipts.require_attempt_capacity(
        scope_root,
        observed,
        "5" * 64,
        sealed_at=T0,
    )
    assert receipt is not None
    path = scope_root / "capacity.json"
    tampered = dict(receipt)
    tampered["sealed_at"] = "2026-08-05T09:00:00Z"
    path.write_bytes(canonical_company_json_bytes(tampered))

    with pytest.raises(receipts.LegacyBridgeClientError, match="digest_mismatch"):
        receipts.inventory(scope_root, scope)


def test_new_posix_directory_entries_sync_their_parents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[Path] = []
    monkeypatch.setattr(
        receipts,
        "_sync_created_directory_parent",
        lambda path: observed.append(path.parent),
    )

    receipts.safe_directory(tmp_path / "scope" / "attempt", create=True)

    assert observed == [tmp_path, tmp_path / "scope"]
