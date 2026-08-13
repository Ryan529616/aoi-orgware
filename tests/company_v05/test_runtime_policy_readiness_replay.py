"""Real-ledger adversarial replay coverage for runtime-policy readiness."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
import sys
from typing import Any, cast

import pytest

from aoi_orgware.company.contract_registry import contract_validator_for
from aoi_orgware.company.contracts import MAX_LIST_ITEMS, canonical_company_json_bytes
from aoi_orgware.company.projection_registry import PROJECTABLE_STREAM
from aoi_orgware.company.readmodel import ProjectedObject
from aoi_orgware.company import runtime_policy_readiness_state as readiness_state
from aoi_orgware.company.runtime_policy_readiness import (
    RUNTIME_POLICY_READINESS_OBSERVATION_V1,
    RuntimePolicyChiefCoverageV1,
    RuntimePolicyDepthObservationV1,
    RuntimePolicyHoldV1,
    RuntimePolicyReadinessError,
    RuntimePolicySourceWitnessV1,
    RuntimePolicySubordinateSlotV1,
    derive_runtime_policy_readiness,
    validate_runtime_policy_readiness_observation,
)
from aoi_orgware.company.state import CompanyQuerySnapshot, CompanyStateOwner
from aoi_orgware.company.supervisor import CompanySupervisor

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_department_lifecycle as lifecycle  # type: ignore[import-not-found]


def _owner(tmp_path: Path) -> CompanySupervisor:
    return cast(CompanySupervisor, lifecycle._initialize(tmp_path))


def _patch_projection(
    monkeypatch: pytest.MonkeyPatch,
    transform: Callable[[CompanyQuerySnapshot], CompanyQuerySnapshot],
) -> None:
    """Safely alter only one detached replay projection for adversarial input."""

    original = CompanyStateOwner.project_historical_replay

    def projected(replay: object, cursor: object) -> CompanyQuerySnapshot:
        snapshot = original(replay, cursor)  # type: ignore[arg-type]
        return transform(snapshot)

    monkeypatch.setattr(
        CompanyStateOwner,
        "project_historical_replay",
        staticmethod(projected),
    )


def _nested_list(depth: int) -> object:
    value: object = "nested-execution"
    for _ in range(depth):
        value = [value]
    return value


def _nested_tuple(depth: int) -> object:
    value: object = "nested-execution"
    for _ in range(depth):
        value = (value,)
    return value


def _with_nested_execution_ids(
    observation: object,
    execution_ids: object,
) -> object:
    typed = cast(Any, observation)
    assert len(typed.current_chief) == 1
    chief = typed.current_chief[0]._replace(
        execution_ids=cast(Any, execution_ids),
    )
    return typed._replace(current_chief=(chief,))


def test_readiness_uses_only_exact_owner_and_rejects_partial_callers(
    tmp_path: Path,
) -> None:
    supervisor = _owner(tmp_path)
    try:
        state = supervisor._state
        for invalid in (
            object(),
            state.query_snapshot(),
            state.historical_replay_input(),
        ):
            with pytest.raises(RuntimePolicyReadinessError, match="exact CompanyStateOwner"):
                derive_runtime_policy_readiness(invalid)  # type: ignore[arg-type]

        class ForgedOwner(CompanyStateOwner):
            def historical_replay_input(self):  # type: ignore[no-untyped-def]
                raise AssertionError("subclass method must not run")

        with pytest.raises(RuntimePolicyReadinessError, match="exact CompanyStateOwner"):
            derive_runtime_policy_readiness(object.__new__(ForgedOwner))

        partial = object.__new__(CompanyStateOwner)
        with pytest.raises(RuntimePolicyReadinessError, match="verified replay is unavailable"):
            derive_runtime_policy_readiness(partial)
    finally:
        supervisor.close()


def test_ordinary_owner_method_shadows_cannot_select_a_stale_head(
    tmp_path: Path,
) -> None:
    supervisor = _owner(tmp_path)
    try:
        state = supervisor._state
        stale = CompanyStateOwner.historical_replay_input(state)
        stale_cursor = len(stale.records)
        lifecycle._resume(supervisor, label="readiness-shadow")
        current = supervisor.heads().global_head.global_sequence
        state.historical_replay_input = lambda: stale  # type: ignore[method-assign]
        state.heads = lambda: None  # type: ignore[assignment,return-value]
        observation = derive_runtime_policy_readiness(state)
        assert observation.cursor == current > stale_cursor
        assert observation.head_sha256 == CompanyStateOwner.heads(state).global_head.transaction_sha256
    finally:
        supervisor.close()


def test_readiness_is_non_mutating_deterministic_and_reopen_byte_identical(
    tmp_path: Path,
) -> None:
    supervisor = _owner(tmp_path)
    slot_root = supervisor.slot_root
    try:
        before = supervisor.heads()
        first = derive_runtime_policy_readiness(supervisor._state)
        second = derive_runtime_policy_readiness(supervisor._state)
        assert first == second
        assert canonical_company_json_bytes(first.to_dict()) == canonical_company_json_bytes(second.to_dict())
        assert supervisor.heads() == before
        assert supervisor._state.rebuild_projection().global_sequence == before.global_head.global_sequence
    finally:
        supervisor.close()

    with CompanySupervisor.open(slot_root) as reopened:
        replay = derive_runtime_policy_readiness(reopened._state)
        assert canonical_company_json_bytes(replay.to_dict()) == canonical_company_json_bytes(first.to_dict())
        assert replay == first


def test_validator_rederives_current_head_and_rejects_nested_digest_tampering(
    tmp_path: Path,
) -> None:
    supervisor = _owner(tmp_path)
    try:
        state = supervisor._state
        observation = derive_runtime_policy_readiness(state)
        assert validate_runtime_policy_readiness_observation(state, observation) == observation
        nested = observation.source_witnesses[0]._replace(payload_sha256="f" * 64)
        for forged in (
            observation._replace(observation_sha256="f" * 64),
            observation._replace(source_witness_sha256="f" * 64),
            observation._replace(source_witnesses=(nested, *observation.source_witnesses[1:])),
        ):
            with pytest.raises(RuntimePolicyReadinessError, match="differs from exact derivation"):
                validate_runtime_policy_readiness_observation(state, forged)

        lifecycle._resume(supervisor, label="readiness-validator-head")
        with pytest.raises(RuntimePolicyReadinessError, match="differs from exact derivation"):
            validate_runtime_policy_readiness_observation(state, observation)
    finally:
        supervisor.close()


def test_multiple_event_ids_at_one_transaction_sequence_are_accepted(
    tmp_path: Path,
) -> None:
    supervisor = _owner(tmp_path)
    try:
        state = supervisor._state
        replay = CompanyStateOwner.historical_replay_input(state)
        snapshot = CompanyStateOwner.project_historical_replay(replay, len(replay.records))
        ids_by_sequence: dict[int, set[str]] = defaultdict(set)
        for item in snapshot.objects:
            ids_by_sequence[item.global_sequence].add(item.event_id)
        assert any(len(event_ids) > 1 for event_ids in ids_by_sequence.values())
        assert derive_runtime_policy_readiness(state).cursor == len(replay.records)
    finally:
        supervisor.close()


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("malformed", "projected object type is invalid"),
        ("duplicate_identity", "projected identity is duplicated"),
        ("duplicate_event", "projected identity is duplicated"),
    ),
)
def test_malformed_detached_projection_is_typed_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    message: str,
) -> None:
    supervisor = _owner(tmp_path)
    try:
        def transform(snapshot: CompanyQuerySnapshot) -> CompanyQuerySnapshot:
            objects = snapshot.objects
            first, second = objects[:2]
            if case == "malformed":
                return replace(
                    snapshot,
                    objects=(object(),),  # type: ignore[arg-type]
                )
            if case == "duplicate_identity":
                return replace(snapshot, objects=(first, first, *objects[2:]))
            assert type(second) is ProjectedObject
            return replace(
                snapshot,
                objects=(first, replace(second, event_id=first.event_id), *objects[2:]),
            )

        _patch_projection(monkeypatch, transform)
        with pytest.raises(RuntimePolicyReadinessError, match=message):
            derive_runtime_policy_readiness(supervisor._state)
    finally:
        supervisor.close()


def test_oversize_typed_observation_is_rejected_before_current_rederivation(
    tmp_path: Path,
) -> None:
    supervisor = _owner(tmp_path)
    try:
        observation = derive_runtime_policy_readiness(supervisor._state)
        oversized = observation._replace(
            source_witnesses=observation.source_witnesses * (MAX_LIST_ITEMS + 1),
        )
        with pytest.raises(RuntimePolicyReadinessError, match="collection type is invalid"):
            validate_runtime_policy_readiness_observation(supervisor._state, oversized)
    finally:
        supervisor.close()


def test_public_validator_bounds_nested_collections_before_current_rederivation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = _owner(tmp_path)
    try:
        observation = derive_runtime_policy_readiness(supervisor._state)
        chief = observation.current_chief[0]
        candidates = (
            observation._replace(blockers=("blocker",) * (MAX_LIST_ITEMS + 1)),
            _with_nested_execution_ids(
                observation,
                ("nested-execution",) * (MAX_LIST_ITEMS + 1),
            ),
            observation._replace(
                current_chief=(
                    chief._replace(
                        reason_codes=("reason",) * (MAX_LIST_ITEMS + 1),
                    ),
                ),
            ),
        )
        rederivations = 0
        original_replay = CompanyStateOwner.historical_replay_input

        def count_rederivation(state: CompanyStateOwner) -> object:
            nonlocal rederivations
            rederivations += 1
            return original_replay(state)

        monkeypatch.setattr(
            CompanyStateOwner,
            "historical_replay_input",
            count_rederivation,
        )
        for forged in candidates:
            with pytest.raises(RuntimePolicyReadinessError):
                validate_runtime_policy_readiness_observation(supervisor._state, forged)
        assert rederivations == 0
    finally:
        supervisor.close()


@pytest.mark.parametrize(
    "execution_ids",
    (
        (object(),),
        _nested_list(80),
        ("x" * 100_000,),
        _nested_tuple(1_100),
    ),
)
def test_public_validator_rejects_frozen_nested_namedtuple_mutations(
    tmp_path: Path,
    execution_ids: object,
) -> None:
    supervisor = _owner(tmp_path)
    try:
        observation = derive_runtime_policy_readiness(supervisor._state)
        forged = _with_nested_execution_ids(observation, execution_ids)
        with pytest.raises(RuntimePolicyReadinessError):
            validate_runtime_policy_readiness_observation(supervisor._state, forged)
    finally:
        supervisor.close()


def test_public_validator_rejects_shortened_exact_nested_namedtuples(
    tmp_path: Path,
) -> None:
    supervisor = _owner(tmp_path)
    try:
        observation = derive_runtime_policy_readiness(supervisor._state)

        def shortened(named_type: Any) -> Any:
            return tuple.__new__(
                named_type,
                (None,) * (len(named_type._fields) - 1),
            )

        candidates = (
            observation._replace(
                current_chief=(shortened(RuntimePolicyChiefCoverageV1),),
            ),
            observation._replace(
                subordinate_slots=(shortened(RuntimePolicySubordinateSlotV1),),
            ),
            observation._replace(holds=(shortened(RuntimePolicyHoldV1),)),
            observation._replace(
                over_depth=(shortened(RuntimePolicyDepthObservationV1),),
            ),
            observation._replace(
                source_witnesses=(shortened(RuntimePolicySourceWitnessV1),),
            ),
        )
        for forged in candidates:
            with pytest.raises(
                RuntimePolicyReadinessError,
                match="nested value shape is invalid",
            ):
                validate_runtime_policy_readiness_observation(
                    supervisor._state,
                    forged,
                )
    finally:
        supervisor.close()


def test_public_validator_requires_exact_nested_mutable_and_scalar_types(
    tmp_path: Path,
) -> None:
    class MutableExecutionIds(list[str]):
        pass

    class ExecutionIdSubclass(str):
        pass

    supervisor = _owner(tmp_path)
    try:
        observation = derive_runtime_policy_readiness(supervisor._state)
        assert observation.source_witnesses
        bool_sequence = observation.source_witnesses[0]._replace(
            global_sequence=cast(Any, True),
        )
        for forged in (
            _with_nested_execution_ids(
                observation,
                MutableExecutionIds(["nested-execution"]),
            ),
            _with_nested_execution_ids(
                observation,
                (ExecutionIdSubclass("nested-execution"),),
            ),
            observation._replace(
                source_witnesses=(
                    bool_sequence,
                    *observation.source_witnesses[1:],
                ),
            ),
        ):
            with pytest.raises(RuntimePolicyReadinessError):
                validate_runtime_policy_readiness_observation(supervisor._state, forged)
    finally:
        supervisor.close()


@pytest.mark.parametrize("boundary", ("replay", "heads", "reducer"))
def test_ordinary_dependency_failures_are_typed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    supervisor = _owner(tmp_path)
    try:
        def fail(*_args: object, **_kwargs: object) -> object:
            raise RuntimeError("ordinary-probe")

        if boundary == "replay":
            monkeypatch.setattr(CompanyStateOwner, "historical_replay_input", fail)
        elif boundary == "heads":
            monkeypatch.setattr(readiness_state, "immutable_ledger_heads", fail)
        else:
            monkeypatch.setattr(readiness_state, "reduce_company_invariants", fail)
        with pytest.raises(
            RuntimePolicyReadinessError,
            match="verified replay is unavailable",
        ):
            derive_runtime_policy_readiness(supervisor._state)
    finally:
        supervisor.close()


@pytest.mark.parametrize("raised", (MemoryError, SystemExit, KeyboardInterrupt))
def test_resource_and_process_control_boundaries_are_not_wrapped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    raised: type[BaseException],
) -> None:
    supervisor = _owner(tmp_path)
    try:
        observation = derive_runtime_policy_readiness(supervisor._state)

        def fail_replay(_state: CompanyStateOwner) -> object:
            raise raised()

        monkeypatch.setattr(CompanyStateOwner, "historical_replay_input", fail_replay)
        with pytest.raises(raised):
            derive_runtime_policy_readiness(supervisor._state)
        with pytest.raises(raised):
            validate_runtime_policy_readiness_observation(supervisor._state, observation)
    finally:
        supervisor.close()


def test_public_observation_is_registry_free_and_never_appends_ledger_state(
    tmp_path: Path,
) -> None:
    supervisor = _owner(tmp_path)
    try:
        state = supervisor._state
        before_heads = supervisor.heads()
        before_records = state.records_after(0)
        observation = derive_runtime_policy_readiness(state)
        assert validate_runtime_policy_readiness_observation(state, observation) == observation
        assert supervisor.heads() == before_heads
        assert state.records_after(0) == before_records
        assert contract_validator_for(RUNTIME_POLICY_READINESS_OBSERVATION_V1, None, None) is None
        assert RUNTIME_POLICY_READINESS_OBSERVATION_V1 not in PROJECTABLE_STREAM
    finally:
        supervisor.close()
