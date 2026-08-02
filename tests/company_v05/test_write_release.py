"""W3 release observations only accept an authoritative state owner."""

from __future__ import annotations

from collections import namedtuple
from collections.abc import Mapping
import copy
from pathlib import Path
import pickle
import sys
from typing import Any

import pytest

from aoi_orgware.company.write_release import (
    WriteReleaseError,
    WriteReleaseObservation,
    WriteReleaseRef,
    derive_write_release,
)
from aoi_orgware.company.state import CompanyStateOwner
from aoi_orgware.company.write_admission import WORK_WRITE_INTENT_V1

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_department_lifecycle as lifecycle  # type: ignore[import-not-found]
import test_write_admission_projection as support  # type: ignore[import-not-found]


def _queued_snapshot(tmp_path: Path):  # type: ignore[no-untyped-def]
    supervisor = lifecycle._initialize(tmp_path)
    packet, queued = support._registered_queued_dispatch(supervisor)
    domain = support._domain()
    intent = support._intent(domain, queued, packet)
    for payload, label, recorded_at in (
        (domain, "release-domain", support.T2),
        (intent, "release-intent", support.T3),
    ):
        supervisor.commit(
            support._request(
                supervisor,
                [payload],
                transaction_id=f"{label}-transaction-1",
                command_id=f"{label}-command-1",
                recorded_at=recorded_at,
            ),
            recorded_at=recorded_at,
        )
    return supervisor, str(intent["intent_id"])


def test_queued_dispatch_is_not_acquired_from_real_reducer_snapshot(
    tmp_path: Path,
) -> None:
    supervisor, intent_id = _queued_snapshot(tmp_path)
    try:
        result = derive_write_release(supervisor._state, intent_id)
        assert result.disposition == "not_acquired"
        assert result.reason_codes == ("dispatch_not_acquired",)
        assert result.cursor == supervisor.heads().global_head.global_sequence
        assert result.head_sha256 == supervisor.heads().global_head.transaction_sha256
        # The receipt is tied to the immutable intent event and owner event;
        # it is not a name/time-window heuristic.
        assert any(entry.startswith(f"{WORK_WRITE_INTENT_V1}:") for entry in result.evidence_ids)
        assert any(entry.startswith("dispatch_request_v1:") for entry in result.evidence_ids)
        assert result.runtime_ownership_only
    finally:
        supervisor.close()


def test_invalid_or_non_authoritative_snapshot_is_typed_and_fail_closed(
    tmp_path: Path,
) -> None:
    supervisor, intent_id = _queued_snapshot(tmp_path)
    try:
        with pytest.raises(WriteReleaseError, match="exact CompanyStateOwner"):
            derive_write_release(object(), intent_id)  # type: ignore[arg-type]
        # A caller-owned snapshot cannot forge a head/object subset into the
        # public API: derive always rebuilds from owner-frozen ledger facts.
        snapshot = supervisor._state.query_snapshot()
        with pytest.raises(WriteReleaseError, match="exact CompanyStateOwner"):
            derive_write_release(snapshot, intent_id)  # type: ignore[arg-type]
        with pytest.raises(WriteReleaseError, match="exact CompanyStateOwner"):
            derive_write_release(
                supervisor._state.historical_replay_input(),  # type: ignore[arg-type]
                intent_id,
            )

        class ForgedOwner(type(supervisor._state)):
            def historical_replay_input(self):  # type: ignore[no-untyped-def]
                raise AssertionError("must not be invoked")

        forged = object.__new__(ForgedOwner)
        with pytest.raises(WriteReleaseError, match="exact CompanyStateOwner"):
            derive_write_release(forged, intent_id)  # type: ignore[arg-type]
        with pytest.raises(WriteReleaseError, match="cursor is unavailable"):
            derive_write_release(supervisor._state, intent_id, cursor=0)
        with pytest.raises(WriteReleaseError, match="cursor is unavailable"):
            derive_write_release(supervisor._state, intent_id, cursor=True)  # type: ignore[arg-type]
        with pytest.raises(WriteReleaseError, match="cursor is unavailable"):
            derive_write_release(
                supervisor._state,
                intent_id,
                cursor=supervisor.heads().global_head.global_sequence + 1,
            )
    finally:
        supervisor.close()


def test_exact_owner_replay_cannot_be_shadowed_to_a_stale_prefix(
    tmp_path: Path,
) -> None:
    supervisor, intent_id = _queued_snapshot(tmp_path)
    try:
        stale_replay = supervisor._state.historical_replay_input()
        stale_cursor = len(stale_replay.records)
        supervisor.admit_department_dispatch(
            "dispatch-1",
            transaction_id="release-shadow-admit-transaction-1",
            command_id="release-shadow-admit-command-1",
            recorded_at=support.T6,
        )
        current_cursor = supervisor.heads().global_head.global_sequence
        # This public exact-owner instance still has the real state, but an
        # attacker can plant a stale public-instance method.  W3 must invoke
        # the class-bound implementation instead of this shadow.
        supervisor._state.historical_replay_input = lambda: stale_replay  # type: ignore[method-assign]
        result = derive_write_release(supervisor._state, intent_id)
        assert result.disposition == "held"
        assert result.reason_codes == ("dispatch_may_still_launch",)
        assert result.cursor == current_cursor
        assert result.cursor > stale_cursor
    finally:
        supervisor.close()


def test_uninitialized_exact_owner_with_attacker_replay_is_typed() -> None:
    uninitialized = object.__new__(CompanyStateOwner)
    uninitialized.historical_replay_input = lambda: None  # type: ignore[method-assign]
    with pytest.raises(WriteReleaseError, match="verified replay is unavailable"):
        derive_write_release(uninitialized, "intent-1")


def test_malformed_exact_owner_shadow_is_typed_not_raw_attribute_error() -> None:
    malformed = object.__new__(CompanyStateOwner)
    malformed.historical_replay_input = lambda: object()  # type: ignore[method-assign]
    with pytest.raises(WriteReleaseError, match="verified replay is unavailable"):
        derive_write_release(malformed, "intent-1")


def test_owner_instance_shadows_cannot_select_a_stale_release_view(
    tmp_path: Path,
) -> None:
    supervisor, intent_id = _queued_snapshot(tmp_path)
    try:
        stale_replay = CompanyStateOwner.historical_replay_input(
            supervisor._state,
        )
        stale_cursor = len(stale_replay.records)
        supervisor.admit_department_dispatch(
            "dispatch-1",
            transaction_id="release-ledger-shadow-admit-transaction-1",
            command_id="release-ledger-shadow-admit-command-1",
            recorded_at=support.T6,
        )
        # W3 explicitly protects these ordinary owner instance shadows.  It
        # does not claim to defend class monkeypatches or private-state swaps.
        supervisor._state.historical_replay_input = (  # type: ignore[method-assign]
            lambda: stale_replay
        )
        supervisor._state.heads = lambda: None  # type: ignore[method-assign]
        result = derive_write_release(supervisor._state, intent_id)
        assert result.disposition == "held"
        assert result.reason_codes == ("dispatch_may_still_launch",)
        assert result.cursor > stale_cursor
    finally:
        supervisor.close()


def test_derived_view_is_non_mutating_and_snapshot_deterministic(tmp_path: Path) -> None:
    supervisor, intent_id = _queued_snapshot(tmp_path)
    try:
        before = supervisor.heads().global_head.global_sequence
        first = derive_write_release(supervisor._state, intent_id)
        second = derive_write_release(supervisor._state, intent_id)
        assert first == second
        assert supervisor.heads().global_head.global_sequence == before
        # An explicit cursor uses the same verified historical-replay path.
        replay = derive_write_release(supervisor._state, intent_id, cursor=first.cursor)
        assert (replay.cursor, replay.head_sha256, replay.evidence_digest, replay.disposition) == (
            first.cursor, first.head_sha256, first.evidence_digest, first.disposition,
        )
        assert "release_proven" not in {first.disposition, second.disposition, replay.disposition}
    finally:
        supervisor.close()


def test_derived_view_equality_preserves_exact_json_scalar_types(
    tmp_path: Path,
) -> None:
    supervisor, intent_id = _queued_snapshot(tmp_path)
    try:
        result = derive_write_release(supervisor._state, intent_id)
        assert result.refs
        assert type(result.refs[0]) is WriteReleaseRef
        assert not isinstance(result.refs[0], Mapping)
        assert type(result.refs[0]["schema_version"]) is int
        equal_ref = dict(result.refs[0])
        assert result.refs[0] == equal_ref
        assert equal_ref == result.refs[0]
        assert not result.refs[0] != equal_ref
        assert not equal_ref != result.refs[0]
        equal_refs = (equal_ref, *result.refs[1:])
        assert result.refs == equal_refs
        assert equal_refs == result.refs
        assert not result.refs != equal_refs
        assert not equal_refs != result.refs
        equal_result = result._replace()
        assert result == equal_result
        assert equal_result == result
        assert not result != equal_result
        assert not equal_result != result
        with pytest.raises(TypeError, match="observation is invalid"):
            result._replace(refs=equal_refs)

        forged_ref = dict(result.refs[0])
        forged_ref["schema_version"] = True
        forged_refs = (forged_ref, *result.refs[1:])
        assert result.refs[0] != forged_ref
        assert forged_ref != result.refs[0]
        assert result.refs != forged_refs
        assert forged_refs != result.refs
        with pytest.raises(TypeError, match="observation is invalid"):
            result._replace(refs=forged_refs)

        for changes in (
            {"cursor": True},
            {"cursor": float(result.cursor)},
            {"cursor": -1},
            {"runtime_ownership_only": 1},
            {"reason_codes": list(result.reason_codes)},
            {"disposition": "bogus"},
            {"evidence_digest": "A" * 64},
            {"head_sha256": "0" * 63},
        ):
            with pytest.raises(TypeError, match="observation is invalid"):
                result._replace(**changes)

        ObservationPeer = namedtuple(
            "ObservationPeer",
            (
                "intent_id owner_kind owner_id disposition reason_codes "
                "evidence_ids evidence_digest cursor head_sha256 refs "
                "runtime_ownership_only"
            ),
        )
        peer = ObservationPeer(
            result.intent_id, result.owner_kind, result.owner_id,
            result.disposition, result.reason_codes, result.evidence_ids,
            result.evidence_digest, result.cursor, result.head_sha256,
            result.refs, result.runtime_ownership_only,
        )
        assert result != peer
        assert peer != result
        with pytest.raises(TypeError, match="final"):
            class ObservationSubclass(WriteReleaseObservation):
                pass

        class DuplicateItems(Mapping[str, Any]):
            def __getitem__(self, key: str) -> Any:
                return equal_ref[key]

            def __iter__(self):  # type: ignore[no-untyped-def]
                return iter(equal_ref)

            def __len__(self) -> int:
                return len(equal_ref)

            def items(self):  # type: ignore[no-untyped-def]
                return (
                    ("schema_version", 1),
                    ("schema_version", True),
                )

        class MalformedItems(DuplicateItems):
            def items(self):  # type: ignore[no-untyped-def]
                return (("schema_version", 1), ("malformed",))

        for invalid in (DuplicateItems(), MalformedItems()):
            assert not result.refs[0] == invalid
            assert not invalid == result.refs[0]
            assert result.refs[0] != invalid
            assert invalid != result.refs[0]

        with pytest.raises(TypeError, match="canonical JSON"):
            WriteReleaseRef(((1, "coerced-key"),))  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="canonical JSON"):
            WriteReleaseRef((("duplicate", 1), ("duplicate", True)))
        with pytest.raises(TypeError, match="canonical JSON"):
            WriteReleaseRef((("nested", {"values": [1, 2]}),))
        reconstructed = WriteReleaseRef(result.refs[0].items())
        assert reconstructed == result.refs[0]
        assert reconstructed != reconstructed.items()
        assert reconstructed.items() != reconstructed
        restored = pickle.loads(pickle.dumps(result))
        assert type(restored) is WriteReleaseObservation
        assert type(restored.refs[0]) is WriteReleaseRef
        assert restored == result
        assert copy.copy(result) == result
        assert copy.deepcopy(result) == result
        assert copy.copy(reconstructed) == reconstructed
        assert copy.deepcopy(reconstructed) == reconstructed
        with pytest.raises(AttributeError, match="immutable"):
            setattr(
                result,
                "_WriteReleaseObservation__cursor",
                result.cursor + 1,
            )
        with pytest.raises(AttributeError, match="immutable"):
            delattr(result, "_WriteReleaseObservation__cursor")
        with pytest.raises(AttributeError, match="immutable"):
            setattr(
                reconstructed,
                "_WriteReleaseRef__items",
                (("malicious", {"mutable": []}),),
            )
        with pytest.raises(AttributeError, match="immutable"):
            delattr(reconstructed, "_WriteReleaseRef__items")
        RefPeer = namedtuple(
            "RefPeer", tuple(f"field_{index}" for index in range(len(reconstructed))),
        )
        ref_peer = RefPeer(*reconstructed.items())
        assert reconstructed != ref_peer
        assert ref_peer != reconstructed
        with pytest.raises(TypeError, match="final"):
            class RefSubclass(WriteReleaseRef):
                pass
        with pytest.raises(TypeError):
            hash(result)
        with pytest.raises(TypeError):
            hash(reconstructed)
    finally:
        supervisor.close()
