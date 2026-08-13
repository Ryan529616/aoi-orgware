from __future__ import annotations

import copy
import hashlib
from typing import Any

import pytest

from aoi_orgware.company.contracts import (
    MAX_CONTRACT_BYTES,
    canonical_company_json_bytes,
)
from aoi_orgware.company.legacy_bridge import (
    LegacyBridgeError,
    normalize_legacy_bridge_snapshot,
)


H = "a" * 64
T = "2026-08-04T00:00:00Z"


def _entry(
    kind: str,
    legacy_id: str,
    status: str,
    *,
    parent: tuple[str, str] | None = None,
    receipts: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "legacy_id": legacy_id,
        "parent_kind": None if parent is None else parent[0],
        "parent_legacy_id": None if parent is None else parent[1],
        "stated_status": status,
        "source_record_sha256": hashlib.sha256(
            f"{kind}:{legacy_id}:{status}".encode(),
        ).hexdigest(),
        "receipt_refs": [] if receipts is None else receipts,
    }


def _receipt(kind: str, identifier: str) -> dict[str, str]:
    return {
        "receipt_kind": kind,
        "receipt_id": identifier,
        "receipt_sha256": hashlib.sha256(identifier.encode()).hexdigest(),
    }


def _receipt_digest(entries: list[dict[str, Any]]) -> str:
    inventory = sorted(
        [
            {
                "entry_kind": entry["kind"],
                "entry_legacy_id": entry["legacy_id"],
                **ref,
            }
            for entry in entries
            for ref in sorted(
                entry["receipt_refs"],
                key=lambda item: (
                    item["receipt_kind"],
                    item["receipt_id"],
                    item["receipt_sha256"],
                ),
            )
        ],
        key=lambda item: (
            item["entry_kind"],
            item["entry_legacy_id"].encode("utf-8"),
            item["receipt_kind"],
            item["receipt_id"].encode("utf-8"),
            item["receipt_sha256"],
        ),
    )
    return hashlib.sha256(canonical_company_json_bytes(inventory)).hexdigest()


def _snapshot(
    entries: list[dict[str, Any]] | None = None,
    *,
    receipt_quality: str = "exact",
) -> dict[str, Any]:
    selected = entries or [
        _entry("task", "task-1", "active"),
        _entry("packet", "packet-1", "dispatched", parent=("task", "task-1")),
        _entry("agent", "agent-1", "unknown", parent=("packet", "packet-1")),
        _entry("job", "job-1", "running", parent=("agent", "agent-1")),
        _entry(
            "needs_user",
            "question-1",
            "needs_user",
            parent=("job", "job-1"),
            receipts=[_receipt("needs_user", "receipt-question-1")],
        ),
    ]
    return {
        "document_type": "legacy_bridge_snapshot_v1",
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "source_kind": "aoi_legacy_v04",
        "source_version": "0.4.0a4",
        "legacy_archive_sha256": H,
        "legacy_state_sha256": "b" * 64,
        "legacy_receipt_set_sha256": (
            _receipt_digest(selected) if receipt_quality == "exact" else None
        ),
        "legacy_receipt_quality": receipt_quality,
        "observed_at": T,
        "task_id": "task-1",
        "entries": selected,
    }


def _raw(value: dict[str, Any]) -> bytes:
    return canonical_company_json_bytes(value)


def _entities(result: Any) -> dict[tuple[str, str], Any]:
    return {
        (entity.kind, entity.legacy_identity_digest): entity
        for entity in result.entities
    }


def _identity_digest(kind: str, legacy_id: str) -> str:
    payload = {
        "domain": "aoi.legacy-bridge.legacy-identity.v1",
        "kind": kind,
        "legacy_id": legacy_id,
    }
    return hashlib.sha256(canonical_company_json_bytes(payload)).hexdigest()


def _entity(result: Any, kind: str, legacy_id: str) -> Any:
    return _entities(result)[(kind, _identity_digest(kind, legacy_id))]


def test_explicit_lineage_and_truth_axes_are_preserved_without_authority() -> None:
    result = normalize_legacy_bridge_snapshot(_raw(_snapshot()))
    assert _entity(result, "packet", "packet-1").parent_bridge_entity_id == _entity(
        result,
        "task",
        "task-1",
    ).bridge_entity_id
    assert _entity(result, "agent", "agent-1").parent_bridge_entity_id == _entity(
        result,
        "packet",
        "packet-1",
    ).bridge_entity_id
    assert _entity(result, "job", "job-1").parent_bridge_entity_id == _entity(
        result,
        "agent",
        "agent-1",
    ).bridge_entity_id
    assert _entity(result, "needs_user", "question-1").needs_user is True
    assert all(entity.runtime_status == "unknown" for entity in result.entities)
    assert all(entity.coverage_status == "degraded" for entity in result.entities)
    assert (result.authority, result.repo_write_capability) == ("none", "absent")
    assert (result.dispatch_capability, result.job_launch_capability) == (
        "absent",
        "absent",
    )


@pytest.mark.parametrize(
    ("kind", "status", "engineering"),
    [
        ("task", "done", "completed"),
        ("task", "cancelled", "cancelled"),
        ("packet", "done", "completed"),
        ("packet", "failed", "blocked"),
        ("packet", "cancelled", "cancelled"),
        ("job", "stopped", "unknown"),
    ],
)
def test_terminal_engineering_never_invents_runtime_stop(
    kind: str,
    status: str,
    engineering: str,
) -> None:
    entries = [_entry("task", "task-1", "active")]
    if kind == "task":
        entries[0]["stated_status"] = status
    else:
        entries.append(_entry(kind, f"{kind}-1", status, parent=("task", "task-1")))
    legacy_id = f"{kind}-1" if kind != "task" else "task-1"
    entity = _entity(
        normalize_legacy_bridge_snapshot(_raw(_snapshot(entries))),
        kind,
        legacy_id,
    )
    assert entity.engineering_status == engineering
    assert entity.runtime_status == "unknown"


def test_unknown_job_is_effect_unknown_but_no_other_effect_is_inferred() -> None:
    entries = [
        _entry("task", "task-1", "active"),
        _entry("job", "job-unknown", "unknown", parent=("task", "task-1")),
        _entry("job", "job-running", "running", parent=("task", "task-1")),
    ]
    result = normalize_legacy_bridge_snapshot(_raw(_snapshot(entries)))
    assert _entity(result, "job", "job-unknown").effect_status == "effect_unknown"
    assert _entity(result, "job", "job-running").effect_status == "unknown"


def test_entry_permutation_is_semantically_stable_and_ids_survive_new_state() -> None:
    entries = [
        _entry(
            "task",
            "task-1",
            "active",
            receipts=[_receipt("packet_result", "r-task")],
        ),
        _entry(
            "packet",
            "packet-1",
            "dispatched",
            parent=("task", "task-1"),
            receipts=[_receipt("packet_result", "r-packet")],
        ),
    ]
    snapshot = _snapshot(entries)
    first = normalize_legacy_bridge_snapshot(_raw(snapshot))
    permuted = copy.deepcopy(snapshot)
    permuted["entries"].reverse()
    second = normalize_legacy_bridge_snapshot(_raw(permuted))
    assert first.entities == second.entities
    assert first.projection_digest == second.projection_digest
    changed = copy.deepcopy(snapshot)
    changed["legacy_state_sha256"] = "c" * 64
    third = normalize_legacy_bridge_snapshot(_raw(changed))
    assert [item.bridge_entity_id for item in first.entities] == [
        item.bridge_entity_id for item in third.entities
    ]
    assert first.projection_digest != third.projection_digest


@pytest.mark.parametrize(
    ("parent", "reason"),
    [
        (("task", "missing"), "explicit_parent_absent"),
        (("job", "job-1"), "explicit_parent_kind_not_allowed"),
        (None, "explicit_parent_unavailable"),
    ],
)
def test_missing_or_disallowed_parent_is_orphan_without_guessing(
    parent: tuple[str, str] | None,
    reason: str,
) -> None:
    entries = [
        _entry("task", "task-1", "active"),
        _entry("packet", "packet-1", "ready", parent=parent),
    ]
    packet = _entity(
        normalize_legacy_bridge_snapshot(_raw(_snapshot(entries))),
        "packet",
        "packet-1",
    )
    assert packet.parent_bridge_entity_id is None
    assert packet.orphan_reason == reason


def test_parent_cycle_and_descendant_are_orphans() -> None:
    entries = [
        _entry("task", "task-1", "active"),
        _entry("agent", "agent-a", "unknown", parent=("agent", "agent-b")),
        _entry("agent", "agent-b", "unknown", parent=("agent", "agent-a")),
        _entry("job", "job-1", "queued", parent=("agent", "agent-a")),
    ]
    result = normalize_legacy_bridge_snapshot(_raw(_snapshot(entries)))
    assert _entity(result, "agent", "agent-a").orphan_reason == "explicit_parent_cycle"
    assert _entity(result, "agent", "agent-b").orphan_reason == "explicit_parent_cycle"
    assert (
        _entity(result, "job", "job-1").orphan_reason
        == "explicit_parent_ancestor_invalid"
    )


def test_error_text_cannot_mint_needs_user_and_only_explicit_item_does() -> None:
    task = _entry("task", "task-1", "blocked")
    task["error"] = "please ask the user"
    with pytest.raises(LegacyBridgeError):
        normalize_legacy_bridge_snapshot(_raw(_snapshot([task])))
    answered = [
        _entry("task", "task-1", "active"),
        _entry("needs_user", "question-1", "answered", parent=("task", "task-1")),
    ]
    item = _entity(
        normalize_legacy_bridge_snapshot(_raw(_snapshot(answered))),
        "needs_user",
        "question-1",
    )
    assert item.needs_user is False


def test_receipt_inventory_is_exact_or_explicitly_unavailable() -> None:
    exact = _snapshot()
    exact["legacy_receipt_set_sha256"] = "f" * 64
    with pytest.raises(LegacyBridgeError, match="receipt set digest differs"):
        normalize_legacy_bridge_snapshot(_raw(exact))
    unavailable_entries = [
        _entry("task", "task-1", "active"),
        _entry("packet", "packet-1", "ready", parent=("task", "task-1")),
    ]
    unavailable = normalize_legacy_bridge_snapshot(
        _raw(_snapshot(unavailable_entries, receipt_quality="unavailable")),
    )
    assert unavailable.legacy_receipt_set_sha256 is None
    assert unavailable.legacy_receipt_quality == "unavailable"
    smuggled = _snapshot(receipt_quality="unavailable")
    with pytest.raises(LegacyBridgeError, match="cannot contain receipt refs"):
        normalize_legacy_bridge_snapshot(_raw(smuggled))


def test_divergent_receipt_identity_fails_and_exact_shared_ref_is_allowed() -> None:
    shared = _receipt("packet_result", "receipt-shared")
    entries = [
        _entry("task", "task-1", "active", receipts=[shared]),
        _entry(
            "packet",
            "packet-1",
            "ready",
            parent=("task", "task-1"),
            receipts=[copy.deepcopy(shared)],
        ),
    ]
    normalize_legacy_bridge_snapshot(_raw(_snapshot(entries)))
    entries[1]["receipt_refs"][0]["receipt_sha256"] = "f" * 64
    snapshot = _snapshot(entries)
    snapshot["legacy_receipt_set_sha256"] = _receipt_digest(entries)
    with pytest.raises(LegacyBridgeError, match="divergent evidence"):
        normalize_legacy_bridge_snapshot(_raw(snapshot))


def test_duplicate_identity_and_ambiguous_task_root_fail_closed() -> None:
    duplicate = [
        _entry("task", "task-1", "active"),
        _entry("packet", "packet-1", "ready", parent=("task", "task-1")),
        _entry("packet", "packet-1", "done", parent=("task", "task-1")),
    ]
    with pytest.raises(LegacyBridgeError, match="identity is ambiguous"):
        normalize_legacy_bridge_snapshot(_raw(_snapshot(duplicate)))
    wrong_root = _snapshot([_entry("task", "other-task", "active")])
    with pytest.raises(LegacyBridgeError, match="matching task root"):
        normalize_legacy_bridge_snapshot(_raw(wrong_root))


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{\n}",
        b'{"document_type":"legacy_bridge_snapshot_v1","document_type":"x"}',
        b"\xff",
        b"[" * 5_000 + b"]" * 5_000,
    ],
)
def test_noncanonical_duplicate_unicode_and_deep_json_fail_typed(raw: bytes) -> None:
    with pytest.raises(LegacyBridgeError):
        normalize_legacy_bridge_snapshot(raw)


def test_oversize_wrong_type_and_unknown_fields_fail_closed() -> None:
    for raw in (bytearray(b"{}"), b"x" * (MAX_CONTRACT_BYTES + 1)):
        with pytest.raises(LegacyBridgeError):
            normalize_legacy_bridge_snapshot(raw)  # type: ignore[arg-type]
    value = _snapshot()
    value["local_path"] = "C:/private/repo"
    with pytest.raises(LegacyBridgeError):
        normalize_legacy_bridge_snapshot(_raw(value))


@pytest.mark.parametrize("schema_version", [True, 1.0, "1"])
def test_schema_version_requires_exact_nonbool_integer(schema_version: Any) -> None:
    value = _snapshot()
    value["schema_version"] = schema_version
    with pytest.raises(LegacyBridgeError, match="discriminator"):
        normalize_legacy_bridge_snapshot(_raw(value))


@pytest.mark.parametrize(
    "path_like_id",
    [
        "C:/private/repo",
        "home/private/repo",
        "file:/private",
        "user@example",
        "127.0.0.1",
        "server.example.com",
    ],
)
def test_raw_identifiers_are_digest_redacted_from_projection(path_like_id: str) -> None:
    value = _snapshot()
    value["task_id"] = path_like_id
    value["entries"][0]["legacy_id"] = path_like_id
    value["entries"][0]["receipt_refs"] = [
        _receipt("packet_result", path_like_id),
    ]
    value["legacy_receipt_set_sha256"] = _receipt_digest(value["entries"])
    result = normalize_legacy_bridge_snapshot(_raw(value))
    assert path_like_id not in repr(result)
    assert "legacy_id" not in result.entities[0]._fields
    assert "task_id" not in result._fields
    assert "receipt_id" not in result.entities[0].receipt_refs[0]._fields


@pytest.mark.parametrize(
    "source_version",
    [
        "1.0.",
        "1.0+",
        "1.0-",
        "1.0..x",
        "1.0+++",
        "01.0.0",
        "0.4.0",
        "0.4.0rc1",
        "0.4.999",
        "0.5.0",
        "1.0.0",
        "999.999.999",
    ],
)
def test_malformed_source_version_is_rejected(source_version: str) -> None:
    value = _snapshot()
    value["source_version"] = source_version
    with pytest.raises(LegacyBridgeError, match="source version"):
        normalize_legacy_bridge_snapshot(_raw(value))


@pytest.mark.parametrize(
    "source_version",
    ["0.4.0a3", "0.4.0a4", "0.4.0a4+frozen.n1.checkpoint2"],
)
def test_supported_aoi_source_versions_are_accepted(source_version: str) -> None:
    value = _snapshot()
    value["source_version"] = source_version
    result = normalize_legacy_bridge_snapshot(_raw(value))
    assert result.source_version == source_version


def test_source_version_has_exact_field_level_byte_bound() -> None:
    prefix = "0.4.0a4+"
    at_limit = prefix + ("a" * (128 - len(prefix)))
    value = _snapshot()
    value["source_version"] = at_limit
    assert normalize_legacy_bridge_snapshot(_raw(value)).source_version == at_limit
    value["source_version"] = at_limit + "a"
    with pytest.raises(LegacyBridgeError, match="source version"):
        normalize_legacy_bridge_snapshot(_raw(value))


def test_derived_receipt_inventory_size_failure_is_typed() -> None:
    entries = [_entry("task", "task-1", "active")]
    for entry_index in range(1, 96):
        receipts = [
            _receipt("packet_result", f"receipt-{entry_index}-{receipt_index}")
            for receipt_index in range(16)
        ]
        entries.append(
            _entry(
                "packet",
                f"packet-{entry_index}",
                "ready",
                parent=("task", "task-1"),
                receipts=receipts,
            )
        )
    value = _snapshot([_entry("task", "task-1", "active")])
    value["entries"] = entries
    value["legacy_receipt_set_sha256"] = H
    raw = _raw(value)
    assert len(raw) < MAX_CONTRACT_BYTES
    with pytest.raises(LegacyBridgeError, match="receipt set digest input"):
        normalize_legacy_bridge_snapshot(raw)


def test_projection_is_immutable_and_omits_sensitive_payload_fields() -> None:
    result = normalize_legacy_bridge_snapshot(_raw(_snapshot()))
    with pytest.raises(AttributeError):
        result.entities[0].legacy_identity_digest = "changed"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        result.entities[0].receipt_refs += (  # type: ignore[operator,misc]
            _receipt("job_result", "other"),
        )
    assert not hasattr(result, "__dict__")
    assert not hasattr(result.entities[0], "__dict__")
    assert not hasattr(result.entities[-1].receipt_refs[0], "__dict__")
    forbidden = {"path", "cwd", "raw", "log", "command", "prompt", "secret"}
    assert forbidden.isdisjoint(result._fields)
    assert forbidden.isdisjoint(result.entities[0]._fields)


def test_archive_digest_separates_company_identity_domains() -> None:
    first = normalize_legacy_bridge_snapshot(_raw(_snapshot()))
    changed = _snapshot()
    changed["legacy_archive_sha256"] = "d" * 64
    second = normalize_legacy_bridge_snapshot(_raw(changed))
    assert first.task_bridge_entity_id != second.task_bridge_entity_id
    other = _snapshot()
    other["company_id"] = "company-2"
    third = normalize_legacy_bridge_snapshot(_raw(other))
    assert first.task_bridge_entity_id != third.task_bridge_entity_id


def test_task_scope_separates_reused_legacy_child_ids() -> None:
    first = normalize_legacy_bridge_snapshot(_raw(_snapshot()))
    entries = [
        _entry("task", "task-2", "active"),
        _entry("packet", "packet-1", "ready", parent=("task", "task-2")),
    ]
    second_snapshot = _snapshot(entries)
    second_snapshot["task_id"] = "task-2"
    second = normalize_legacy_bridge_snapshot(_raw(second_snapshot))
    assert _entity(first, "packet", "packet-1").bridge_entity_id != _entity(
        second,
        "packet",
        "packet-1",
    ).bridge_entity_id
