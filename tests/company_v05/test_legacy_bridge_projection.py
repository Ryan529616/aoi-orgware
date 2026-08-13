"""Durable projection coverage for non-authoritative legacy observations."""
from __future__ import annotations

import copy
from pathlib import Path
import sqlite3
import sys
from typing import Any

import pytest

from aoi_orgware.company.contracts import (
    CompanyContractError,
    canonical_company_json_bytes,
    company_contract_sha256,
    validate_company_contract,
)
from aoi_orgware.company.ledger import CompanyLedger
from aoi_orgware.company.legacy_bridge import normalize_legacy_bridge_snapshot
from aoi_orgware.company.legacy_bridge_contract import (
    LEGACY_BRIDGE_OBSERVATION_V1,
    LegacyBridgeContractError,
    build_legacy_bridge_observation,
    validate_legacy_bridge_observation,
)
from aoi_orgware.company.projection_registry import (
    APPEND_ONCE_AUTHORITY_TYPES,
    APPEND_ONCE_PROVIDER_PROJECTION_TYPES,
    APPEND_ONCE_WORK_DEFINITION_TYPES,
    APPEND_ONCE_WRITE_ADMISSION_TYPES,
    LOGICAL_ID_FIELDS,
    PROJECTABLE_STREAM,
    PROJECTION_SPECS,
)
from aoi_orgware.company.readmodel import (
    CompanyReadModel,
    ReadModelCorruptionError,
)
from aoi_orgware.company.transactions import (
    CompanyEventDraft,
    build_company_transaction_request,
)
from aoi_orgware.frozen_json import thaw_json_payload


_TESTS_ROOT = Path(__file__).resolve().parents[1]
_THIS_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS_ROOT))
sys.path.insert(0, str(_THIS_DIRECTORY))
from test_company_readmodel import append_payload  # type: ignore[import-not-found]
from test_legacy_bridge import (  # type: ignore[import-not-found]
    _raw,
    _receipt,
    _receipt_digest,
    _snapshot,
)
from test_transactions import (  # type: ignore[import-not-found]
    authority,
    empty_heads,
)


T1 = "2026-08-04T00:01:00Z"
T2 = "2026-08-04T00:02:00Z"


def _observation(
    *,
    ingested_at: str = T1,
    legacy_state_sha256: str = "b" * 64,
    observed_at: str = "2026-08-04T00:00:00Z",
) -> dict[str, Any]:
    snapshot = _snapshot()
    snapshot["legacy_state_sha256"] = legacy_state_sha256
    snapshot["observed_at"] = observed_at
    projection = normalize_legacy_bridge_snapshot(_raw(snapshot))
    return build_legacy_bridge_observation(
        projection,
        ingested_at=ingested_at,
    )


def _rehash_observation(value: dict[str, Any]) -> None:
    unsigned = {
        key: member
        for key, member in value.items()
        if key != "observation_sha256"
    }
    value["observation_sha256"] = company_contract_sha256(unsigned)


def _reseal_observation(value: dict[str, Any]) -> None:
    projection = value["projection"]
    projection["projection_digest"] = company_contract_sha256({
        "domain": "aoi.legacy-bridge.projection.v1",
        "key": {
            "company_id": value["company_id"],
            "company_incarnation": value["company_incarnation"],
            "lock_domain_generation": value["lock_domain_generation"],
        },
        "source_kind": projection["source_kind"],
        "source_version": projection["source_version"],
        "legacy_archive_sha256": projection["legacy_archive_sha256"],
        "legacy_state_sha256": projection["legacy_state_sha256"],
        "legacy_receipt_set_sha256": projection["legacy_receipt_set_sha256"],
        "legacy_receipt_quality": projection["legacy_receipt_quality"],
        "observed_at": projection["observed_at"],
        "task_identity_digest": projection["task_identity_digest"],
        "task_bridge_entity_id": projection["task_bridge_entity_id"],
        "entities": projection["entities"],
        "snapshot_sha256": projection["snapshot_sha256"],
        "truth_boundary": {
            "projection_provenance": projection["projection_provenance"],
            "projection_completeness": projection["projection_completeness"],
            "authority": projection["authority"],
            "repo_write_capability": projection["repo_write_capability"],
            "dispatch_capability": projection["dispatch_capability"],
            "job_launch_capability": projection["job_launch_capability"],
        },
    })
    value["observation_id"] = company_contract_sha256({
        "domain": "aoi.legacy-bridge.observation-id.v1",
        "bridge_scope_id": value["bridge_scope_id"],
        "projection_digest": projection["projection_digest"],
        "ingested_at": value["ingested_at"],
    })
    _rehash_observation(value)


def _observation_with_two_receipts() -> dict[str, Any]:
    snapshot = _snapshot()
    snapshot["entries"][-1]["receipt_refs"] = [
        _receipt("needs_user", "receipt-z"),
        _receipt("needs_user", "receipt-a"),
    ]
    snapshot["legacy_receipt_set_sha256"] = _receipt_digest(snapshot["entries"])
    return build_legacy_bridge_observation(
        normalize_legacy_bridge_snapshot(_raw(snapshot)),
        ingested_at=T1,
    )


def test_contract_registry_and_transaction_builder_select_evidence_stream() -> None:
    observation = _observation()
    assert validate_company_contract(observation) == observation
    assert PROJECTABLE_STREAM[LEGACY_BRIDGE_OBSERVATION_V1] == "evidence"
    assert PROJECTION_SPECS[LEGACY_BRIDGE_OBSERVATION_V1].stream == "evidence"
    assert LOGICAL_ID_FIELDS[LEGACY_BRIDGE_OBSERVATION_V1] == "bridge_scope_id"
    assert all(
        LEGACY_BRIDGE_OBSERVATION_V1 not in contracts
        for contracts in (
            APPEND_ONCE_AUTHORITY_TYPES,
            APPEND_ONCE_PROVIDER_PROJECTION_TYPES,
            APPEND_ONCE_WORK_DEFINITION_TYPES,
            APPEND_ONCE_WRITE_ADMISSION_TYPES,
        )
    )

    request = build_company_transaction_request(
        empty_heads(),
        authority(),
        transaction_id="transaction-bridge-1",
        command_id="command-bridge-1",
        events=[CompanyEventDraft(
            event_id="event-bridge-1",
            event_type="legacy_bridge.observed",
            recorded_at=T1,
            payload=observation,
        )],
    )
    assert [event["stream"] for event in request["events"]] == ["evidence"]


def test_observation_is_deterministic_and_redacts_raw_legacy_identities() -> None:
    first = _observation()
    second = _observation()
    assert first == second
    encoded = canonical_company_json_bytes(first)
    for raw_identifier in (
        b"task-1",
        b"packet-1",
        b"agent-1",
        b"job-1",
        b"question-1",
        b"receipt-question-1",
    ):
        assert raw_identifier not in encoded
    projection = first["projection"]
    assert projection["authority"] == "none"
    assert projection["repo_write_capability"] == "absent"
    assert projection["dispatch_capability"] == "absent"
    assert projection["job_launch_capability"] == "absent"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda item: item["projection"]["entities"][0].update(
                {"runtime_status": "stopped"},
            ),
            "runtime or coverage truth",
        ),
        (
            lambda item: item["projection"].update(
                {"projection_digest": "0" * 64},
            ),
            "projection digest differs",
        ),
        (
            lambda item: item.update({"bridge_scope_id": "0" * 64}),
            "scope id differs",
        ),
        (
            lambda item: item.update({"observation_id": "0" * 64}),
            "observation id differs",
        ),
    ],
    ids=("runtime-overstatement", "projection-digest", "scope", "identity"),
)
def test_semantic_mutation_fails_before_outer_digest(
    mutate: Any,
    message: str,
) -> None:
    value = copy.deepcopy(_observation())
    mutate(value)
    _rehash_observation(value)
    with pytest.raises(LegacyBridgeContractError, match=message):
        validate_legacy_bridge_observation(value)


def test_outer_digest_and_malformed_quality_fail_with_typed_errors() -> None:
    bad_digest = copy.deepcopy(_observation())
    bad_digest["observation_sha256"] = "0" * 64
    with pytest.raises(LegacyBridgeContractError, match="digest differs"):
        validate_legacy_bridge_observation(bad_digest)

    bad_quality = copy.deepcopy(_observation())
    bad_quality["projection"]["legacy_receipt_quality"] = []
    with pytest.raises(LegacyBridgeContractError, match="receipt quality"):
        validate_legacy_bridge_observation(bad_quality)

    bad_version = copy.deepcopy(_observation())
    bad_version["projection"]["source_version"] = "0.4.0a4+\ud800"
    with pytest.raises(LegacyBridgeContractError, match="source version"):
        validate_legacy_bridge_observation(bad_version)


def test_orphan_ancestor_cannot_retain_a_joined_descendant() -> None:
    value = copy.deepcopy(_observation())
    entities = {item["kind"]: item for item in value["projection"]["entities"]}
    packet = entities["packet"]
    agent = entities["agent"]
    assert agent["parent_bridge_entity_id"] == packet["bridge_entity_id"]
    packet["parent_bridge_entity_id"] = None
    packet["orphan_reason"] = "explicit_parent_absent"
    _reseal_observation(value)
    with pytest.raises(LegacyBridgeContractError, match="orphan ancestor"):
        validate_legacy_bridge_observation(value)


def test_entity_and_receipt_order_are_one_canonical_durable_spelling() -> None:
    entity_permutation = copy.deepcopy(_observation())
    entity_permutation["projection"]["entities"].reverse()
    _reseal_observation(entity_permutation)
    with pytest.raises(LegacyBridgeContractError, match="order is not canonical"):
        validate_legacy_bridge_observation(entity_permutation)

    receipt_permutation = copy.deepcopy(_observation_with_two_receipts())
    needs_user = next(
        item
        for item in receipt_permutation["projection"]["entities"]
        if item["kind"] == "needs_user"
    )
    refs = needs_user["receipt_refs"]
    assert len(refs) == 2
    refs.reverse()
    _reseal_observation(receipt_permutation)
    with pytest.raises(LegacyBridgeContractError, match="order is not canonical"):
        validate_legacy_bridge_observation(receipt_permutation)


def test_builder_canonicalizes_projected_receipts_without_raw_identity() -> None:
    observation = _observation_with_two_receipts()
    needs_user = next(
        item
        for item in observation["projection"]["entities"]
        if item["kind"] == "needs_user"
    )
    keys = [
        (
            ref["receipt_kind"],
            ref["receipt_identity_digest"],
            ref["receipt_sha256"],
        )
        for ref in needs_user["receipt_refs"]
    ]
    assert keys == sorted(keys)
    assert validate_company_contract(observation) == observation


@pytest.mark.parametrize(
    "malformed",
    [
        lambda projection: projection._replace(key=object()),
        lambda projection: projection._replace(entities=(object(),)),
        lambda projection: projection._replace(
            entities=(
                projection.entities[0]._replace(receipt_refs=(object(),)),
                *projection.entities[1:],
            ),
        ),
    ],
    ids=("key", "entity", "receipt"),
)
def test_builder_rejects_malformed_nested_runtime_types(malformed: Any) -> None:
    projection = normalize_legacy_bridge_snapshot(_raw(_snapshot()))
    with pytest.raises(LegacyBridgeContractError, match="runtime type"):
        build_legacy_bridge_observation(
            malformed(projection),
            ingested_at=T1,
        )


def test_wrong_stream_is_zero_apply_fail_closed(tmp_path: Path) -> None:
    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    model = CompanyReadModel(tmp_path / "readmodel.sqlite3")
    try:
        record = append_payload(
            ledger,
            _observation(),
            tx="transaction-wrong-stream",
            command="command-wrong-stream",
            event_id="event-wrong-stream",
            stream="usage",
        )
        with pytest.raises(
            ReadModelCorruptionError,
            match="belongs to evidence, not usage",
        ):
            model.apply(record)
        assert model.head().global_sequence == 0
        assert model.objects() == ()
    finally:
        model.close()
        ledger.close()


def test_current_history_and_rebuild_preserve_two_observations(
    tmp_path: Path,
) -> None:
    first = _observation()
    second = _observation(
        ingested_at=T2,
        legacy_state_sha256="c" * 64,
        observed_at="2026-08-04T00:01:30Z",
    )
    assert first["bridge_scope_id"] == second["bridge_scope_id"]
    assert first["observation_id"] != second["observation_id"]

    ledger = CompanyLedger(tmp_path / "ledger.sqlite3")
    model = CompanyReadModel(tmp_path / "readmodel.sqlite3")
    rebuilt: CompanyReadModel | None = None
    try:
        records = [
            append_payload(
                ledger,
                first,
                tx="transaction-bridge-1",
                command="command-bridge-1",
                event_id="event-bridge-1",
                stream="evidence",
            ),
            append_payload(
                ledger,
                second,
                tx="transaction-bridge-2",
                command="command-bridge-2",
                event_id="event-bridge-2",
                stream="evidence",
            ),
        ]
        assert model.apply_many(records) == 2
        current = model.object(
            LEGACY_BRIDGE_OBSERVATION_V1,
            second["bridge_scope_id"],
        )
        assert current is not None
        assert current.record_id == second["observation_id"]
        assert thaw_json_payload(current.payload) == second

        with sqlite3.connect(model.path) as connection:
            history = connection.execute(
                "SELECT record_id FROM projected_events "
                "WHERE contract_type=? ORDER BY global_sequence",
                (LEGACY_BRIDGE_OBSERVATION_V1,),
            ).fetchall()
        assert history == [
            (first["observation_id"],),
            (second["observation_id"],),
        ]

        rebuilt_path = tmp_path / "rebuilt.sqlite3"
        rebuilt_head = CompanyReadModel.rebuild(rebuilt_path, records)
        rebuilt = CompanyReadModel(rebuilt_path)
        assert rebuilt_head == model.head()
        assert rebuilt.head() == model.head()
        assert rebuilt.objects() == model.objects()
    finally:
        if rebuilt is not None:
            rebuilt.close()
        model.close()
        ledger.close()


def test_public_validator_never_leaks_builtin_type_errors() -> None:
    for malformed in (None, [], object(), {"contract_type": True}):
        with pytest.raises(CompanyContractError):
            validate_company_contract(malformed)
