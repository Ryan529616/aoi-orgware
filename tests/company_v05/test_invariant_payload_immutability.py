"""Regression tests for deeply immutable invariant payload carriers."""
from __future__ import annotations

import copy
from collections.abc import Iterator, Mapping, Sequence
import gc
from types import MappingProxyType
from typing import Any, cast

import pytest

from aoi_orgware.company.contracts import (
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.invariants import (
    CompanyInvariantError,
    InvariantObject,
    InvariantTransition,
    UncertainDispatch,
    reduce_company_invariants,
)
from aoi_orgware.company.invariant_carriers import (
    CompanyInvariantError as CarrierCompanyInvariantError,
    InvariantObject as CarrierInvariantObject,
    InvariantTransition as CarrierInvariantTransition,
    UncertainDispatch as CarrierUncertainDispatch,
)
from aoi_orgware.company.ledger import _immutable as ledger_immutable
from aoi_orgware.frozen_json import (
    FrozenJsonError,
    FrozenJsonMapping,
    FrozenJsonSequence,
    freeze_json_payload,
    thaw_json_payload,
)
from aoi_orgware.semantic_events import SemanticEventError, canonical_json_bytes

PLAIN = {"nested": {"value": 1}, "items": [{"value": 2}]}


class _ForgedFrozenMapping(FrozenJsonMapping):
    __slots__ = ()


class _ExplodingMapping(Mapping[str, Any]):
    def __getitem__(self, key: str) -> Any:
        raise RuntimeError(key)

    def __iter__(self) -> Iterator[str]:
        raise RuntimeError("iteration")

    def __len__(self) -> int:
        raise RuntimeError("length")


class _ExplodingSequence(Sequence[Any]):
    def __getitem__(self, index: int | slice) -> Any:
        raise AssertionError(index)

    def __len__(self) -> int:
        return 1


class _FatalSequence(Sequence[Any]):
    failure: BaseException

    def __init__(self, failure: BaseException) -> None:
        self.failure = failure

    def __getitem__(self, index: int | slice) -> Any:
        raise self.failure

    def __len__(self) -> int:
        return 1


class _TruncatedSequence(Sequence[Any]):
    def __getitem__(self, index: int | slice) -> Any:
        raise IndexError(index)

    def __len__(self) -> int:
        return 1


class _TruncatedMapping(Mapping[str, Any]):
    def __getitem__(self, key: str) -> Any:
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(())

    def __len__(self) -> int:
        return 1


class _InconsistentSequence(Sequence[Any]):
    def __init__(
        self,
        *,
        length: int,
        indexed: tuple[Any, ...],
        iterated: tuple[Any, ...],
        extra: Any = cast(Any, ...),
    ) -> None:
        self.length = length
        self.indexed = indexed
        self.iterated = iterated
        self.extra = extra

    def __getitem__(self, index: int | slice) -> Any:
        if isinstance(index, slice):
            return self.indexed[index]
        if index < len(self.indexed):
            return self.indexed[index]
        if index == self.length and self.extra is not ...:
            return self.extra
        raise IndexError(index)

    def __iter__(self) -> Iterator[Any]:
        return iter(self.iterated)

    def __len__(self) -> int:
        return self.length


class _InconsistentMapping(Mapping[str, Any]):
    def __getitem__(self, key: str) -> Any:
        if key == "iter-key":
            return "indexed-value"
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(("iter-key",))

    def __len__(self) -> int:
        return 1

    def items(self) -> Any:
        return (("items-key", "items-value"),)


class _SignedZeroMapping(Mapping[str, Any]):
    def __getitem__(self, key: str) -> Any:
        if key == "value":
            return -0.0
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(("value",))

    def __len__(self) -> int:
        return 1

    def items(self) -> Any:
        return (("value", 0.0),)


class _MutableStr(str):
    mutable: list[str]


class _MutableInt(int):
    mutable: list[str]


class _MutableFloat(float):
    mutable: list[str]


def _payloads() -> tuple[Mapping[str, Any], ...]:
    return (
        InvariantObject(
            "SyntheticContractV1", "object-1", "event-1", 1, "a" * 64, PLAIN,
        ).payload,
        UncertainDispatch(
            "reservation-1", "dispatch-1", "event-2", 2, "transaction-1",
            "command-1", "effect_unknown", "dispatched", "b" * 64, PLAIN,
        ).payload,
        InvariantTransition(PLAIN, "committed").request,
    )


def test_invariants_reexports_the_bounded_carrier_types() -> None:
    assert CompanyInvariantError is CarrierCompanyInvariantError
    assert InvariantObject is CarrierInvariantObject
    assert InvariantTransition is CarrierInvariantTransition
    assert UncertainDispatch is CarrierUncertainDispatch


def _mapping(value: object) -> Mapping[str, Any]:
    assert isinstance(value, Mapping)
    return value


def _sequence(value: object) -> Sequence[Any]:
    assert isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray),
    )
    return value


def _depths(payload: Mapping[str, Any]) -> tuple[
    Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], Sequence[Any],
]:
    nested = _mapping(payload["nested"])
    sequence = _sequence(payload["items"])
    member = _mapping(sequence[0])
    return payload, nested, member, sequence


@pytest.mark.parametrize("payload", _payloads())
def test_mapping_instance_and_base_class_mutators_are_rejected(
    payload: Mapping[str, Any],
) -> None:
    mutable = cast(dict[str, Any], payload)
    with pytest.raises(TypeError, match="immutable invariant payload"):
        mutable.__ior__({"injected": True})
    with pytest.raises(TypeError):
        dict.__ior__(mutable, {"injected": True})
    with pytest.raises(TypeError):
        dict.__setitem__(mutable, "injected", True)
    with pytest.raises(TypeError):
        dict.update(mutable, {"injected": True})
    assert payload == PLAIN


@pytest.mark.parametrize("payload", _payloads())
def test_nested_mapping_and_sequence_mutations_touch_only_detached_copies(
    payload: Mapping[str, Any],
) -> None:
    _, nested, member, sequence = _depths(payload)
    dict.__ior__(cast(dict[str, Any], nested), {"injected": True})
    dict.__setitem__(cast(dict[str, Any], member), "injected", True)
    mutable_sequence = cast(list[Any], sequence)
    list.append(mutable_sequence, {"injected": True})
    list.__setitem__(mutable_sequence, 0, {"injected": True})
    assert payload == PLAIN


def test_root_frozen_sequence_rejects_list_base_descriptors() -> None:
    sequence = cast(list[Any], freeze_json_payload([{"value": 1}]))
    with pytest.raises(TypeError, match="immutable invariant payload"):
        sequence.append({"injected": True})
    with pytest.raises(TypeError):
        list.append(sequence, {"injected": True})
    with pytest.raises(TypeError):
        list.__setitem__(sequence, 0, {"injected": True})
    with pytest.raises(TypeError):
        list.__iadd__(sequence, [{"injected": True}])


@pytest.mark.parametrize("payload", _payloads())
def test_existing_mapping_mutators_remain_rejected(
    payload: Mapping[str, Any],
) -> None:
    target = cast(dict[str, Any], payload)
    with pytest.raises(TypeError, match="immutable invariant payload"):
        target.__setitem__("value", 3)
    with pytest.raises(TypeError, match="immutable invariant payload"):
        target.__delitem__("nested")
    with pytest.raises(TypeError, match="immutable invariant payload"):
        target.clear()
    with pytest.raises(TypeError, match="immutable invariant payload"):
        target.pop("nested")
    with pytest.raises(TypeError, match="immutable invariant payload"):
        target.popitem()
    with pytest.raises(TypeError, match="immutable invariant payload"):
        target.setdefault("value", 3)
    with pytest.raises(TypeError, match="immutable invariant payload"):
        target.update({"value": 3})


@pytest.mark.parametrize("payload", _payloads())
def test_aliases_deepcopy_and_canonical_witness_remain_detached(
    payload: Mapping[str, Any],
) -> None:
    assert not isinstance(payload, dict)
    assert type(payload["items"]) is list
    plain = thaw_json_payload(payload)
    cloned = copy.deepcopy(payload)
    assert type(plain) is dict and type(cloned) is dict
    assert type(plain["items"]) is list and type(cloned["items"]) is list
    assert canonical_company_json_bytes(plain) == canonical_company_json_bytes(PLAIN)
    assert company_contract_sha256(plain) == company_contract_sha256(PLAIN)
    nested = cloned["nested"]
    items = cloned["items"]
    assert type(nested) is dict and type(items) is list
    nested["value"] = 9
    items.append({"value": 3})
    assert payload == PLAIN


def test_constructor_detaches_mutable_source_aliases() -> None:
    source = copy.deepcopy(PLAIN)
    payload = InvariantObject(
        "SyntheticContractV1", "object-1", "event-1", 1, "a" * 64, source,
    ).payload
    nested = source["nested"]
    items = source["items"]
    assert type(nested) is dict and type(items) is list
    nested["value"] = 9
    items.append({"value": 3})
    assert payload == PLAIN


def test_public_wrapper_constructors_validate_and_detach_their_inputs() -> None:
    source = copy.deepcopy(PLAIN)
    mapping = FrozenJsonMapping(source)
    sequence_source: list[Any] = [{"value": 1}]
    sequence = FrozenJsonSequence(sequence_source)
    nested = source["nested"]
    items = source["items"]
    assert type(nested) is dict and type(items) is list
    nested["value"] = 9
    items.append({"value": 3})
    sequence_source[0]["value"] = 9
    assert mapping == PLAIN
    assert sequence == [{"value": 1}]
    with pytest.raises(FrozenJsonError, match="unsupported JSON value"):
        FrozenJsonMapping({"value": bytearray(b"mutable")})
    with pytest.raises(FrozenJsonError, match="unsupported JSON value"):
        FrozenJsonSequence([bytearray(b"mutable")])


def test_arbitrary_mapping_does_not_leak_caller_exceptions() -> None:
    value = _ExplodingMapping()
    with pytest.raises(FrozenJsonError, match=r"cannot be (?:sized|read)"):
        freeze_json_payload(value)
    with pytest.raises(CompanyInvariantError, match="not bounded JSON"):
        InvariantObject(
            "SyntheticContractV1", "object-1", "event-1", 1, "a" * 64, value,
        )


def test_arbitrary_sequence_exceptions_are_typed_but_fatal_errors_propagate() -> None:
    with pytest.raises(FrozenJsonError, match="cannot be read"):
        freeze_json_payload(_ExplodingSequence())
    with pytest.raises(FrozenJsonError, match="cannot be read"):
        freeze_json_payload(_TruncatedSequence())
    with pytest.raises(FrozenJsonError, match="length is inconsistent"):
        freeze_json_payload(_TruncatedMapping())
    for failure in (MemoryError("memory"), SystemExit(2), KeyboardInterrupt()):
        with pytest.raises(type(failure)):
            freeze_json_payload(_FatalSequence(failure))


@pytest.mark.parametrize(
    "value",
    (
        _InconsistentSequence(length=0, indexed=("hidden",), iterated=()),
        _InconsistentSequence(length=0, indexed=(), iterated=("hidden",)),
        _InconsistentSequence(
            length=1,
            indexed=("indexed",),
            iterated=("iterated",),
        ),
        _InconsistentSequence(
            length=1,
            indexed=("indexed",),
            iterated=("indexed",),
            extra="hidden",
        ),
    ),
)
def test_sequence_views_must_agree_with_declared_length(
    value: Sequence[Any],
) -> None:
    with pytest.raises(FrozenJsonError, match="inconsistent"):
        freeze_json_payload(value)


def test_mapping_iteration_indexing_and_items_views_must_agree() -> None:
    with pytest.raises(FrozenJsonError, match="views are inconsistent"):
        freeze_json_payload(_InconsistentMapping())


def test_signed_zero_views_must_match_canonical_json_spelling() -> None:
    sequence = _InconsistentSequence(
        length=1,
        indexed=(-0.0,),
        iterated=(0.0,),
    )
    with pytest.raises(FrozenJsonError, match="views are inconsistent"):
        freeze_json_payload(sequence)
    with pytest.raises(FrozenJsonError, match="views are inconsistent"):
        freeze_json_payload(_SignedZeroMapping())


@pytest.mark.parametrize(
    "value",
    (
        object.__new__(FrozenJsonMapping),
        object.__new__(FrozenJsonSequence),
    ),
)
def test_uninitialized_exact_wrappers_fail_with_typed_error(value: object) -> None:
    with pytest.raises(FrozenJsonError, match="not initialized"):
        freeze_json_payload(value)
    with pytest.raises(FrozenJsonError, match="not initialized"):
        thaw_json_payload(value)
    with pytest.raises(SemanticEventError, match="invalid nominal"):
        canonical_json_bytes(value)


@pytest.mark.parametrize(
    ("source", "expected_type"),
    (
        (_MutableStr("stable"), str),
        (_MutableInt(7), int),
        (_MutableFloat(1.5), float),
    ),
)
def test_scalar_subclasses_are_detached_to_exact_json_scalars(
    source: Any,
    expected_type: type[Any],
) -> None:
    source.mutable = []
    payload = InvariantObject(
        "SyntheticContractV1", "object-1", "event-1", 1, "a" * 64,
        {"leaf": source},
    ).payload
    frozen_leaf = payload["leaf"]
    source.mutable.append("changed")
    assert type(frozen_leaf) is expected_type
    assert frozen_leaf is not source
    assert not hasattr(frozen_leaf, "mutable")


def test_carrier_scalar_fields_are_detached_to_exact_builtins() -> None:
    text = _MutableStr("stable")
    integer = _MutableInt(7)
    text.mutable = []
    integer.mutable = []
    invariant = InvariantObject(text, text, text, integer, text, PLAIN)
    shadow = UncertainDispatch(
        text, text, text, integer, text, text, text, text, text, PLAIN,
    )
    transition = InvariantTransition(PLAIN, text)
    scalar_values = (
        invariant.contract_type, invariant.object_key, invariant.event_id,
        invariant.global_sequence, invariant.payload_sha256,
        shadow.reservation_id, shadow.dispatch_request_id,
        shadow.source_event_id, shadow.source_global_sequence,
        shadow.source_transaction_id, shadow.source_command_id,
        shadow.receipt_state, shadow.requested_state, shadow.payload_sha256,
        transition.receipt_state,
    )
    text.mutable.append("changed")
    integer.mutable.append("changed")
    assert all(type(value) in (str, int) for value in scalar_values)
    assert all(value is not text and value is not integer for value in scalar_values)


def test_carrier_preserves_json_scalar_type_for_domain_validator() -> None:
    invariant = InvariantObject(
        "SyntheticContractV1", "object-1", "event-1", True, "a" * 64, PLAIN,
    )
    assert type(invariant.global_sequence) is bool


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("contract_type", True),
        ("object_key", True),
        ("event_id", True),
        ("payload_sha256", True),
        ("global_sequence", True),
        ("global_sequence", 1.5),
        ("global_sequence", "1"),
        ("global_sequence", None),
        ("global_sequence", []),
    ),
)
def test_reducer_rejects_invalid_invariant_carrier_scalars(
    field: str,
    invalid: object,
) -> None:
    values: dict[str, object] = {
        "contract_type": "SyntheticContractV1",
        "object_key": "object-1",
        "event_id": "event-1",
        "global_sequence": 1,
        "payload_sha256": "a" * 64,
    }
    values[field] = invalid
    item = InvariantObject(
        cast(Any, values["contract_type"]),
        cast(Any, values["object_key"]),
        cast(Any, values["event_id"]),
        cast(Any, values["global_sequence"]),
        cast(Any, values["payload_sha256"]),
        PLAIN,
    )
    with pytest.raises(
        CompanyInvariantError,
        match="current objects must be InvariantObject values",
    ):
        reduce_company_invariants([item], [])


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("reservation_id", True),
        ("dispatch_request_id", True),
        ("source_event_id", True),
        ("source_global_sequence", True),
        ("source_global_sequence", 1.5),
        ("source_transaction_id", True),
        ("source_command_id", True),
        ("receipt_state", []),
        ("requested_state", True),
        ("payload_sha256", True),
    ),
)
def test_reducer_rejects_invalid_uncertain_dispatch_scalars(
    field: str,
    invalid: object,
) -> None:
    values: dict[str, object] = {
        "reservation_id": "reservation-1",
        "dispatch_request_id": "dispatch-1",
        "source_event_id": "event-2",
        "source_global_sequence": 2,
        "source_transaction_id": "transaction-1",
        "source_command_id": "command-1",
        "receipt_state": "effect_unknown",
        "requested_state": "dispatched",
        "payload_sha256": "b" * 64,
    }
    values[field] = invalid
    shadow = UncertainDispatch(
        cast(Any, values["reservation_id"]),
        cast(Any, values["dispatch_request_id"]),
        cast(Any, values["source_event_id"]),
        cast(Any, values["source_global_sequence"]),
        cast(Any, values["source_transaction_id"]),
        cast(Any, values["source_command_id"]),
        cast(Any, values["receipt_state"]),
        cast(Any, values["requested_state"]),
        cast(Any, values["payload_sha256"]),
        PLAIN,
    )
    with pytest.raises(CompanyInvariantError, match="uncertain dispatch is invalid"):
        reduce_company_invariants([], [shadow])


@pytest.mark.parametrize("invalid", (True, 1, 1.5, None, [], {}))
def test_reducer_rejects_invalid_transition_receipt_scalars(
    invalid: object,
) -> None:
    transition = InvariantTransition(PLAIN, cast(Any, invalid))
    with pytest.raises(
        CompanyInvariantError,
        match="invariant transition receipt state is invalid",
    ):
        reduce_company_invariants([], [], transition)


def test_reducer_rejects_uninitialized_exact_carriers_with_typed_errors() -> None:
    malformed_object = object.__new__(InvariantObject)
    malformed_shadow = object.__new__(UncertainDispatch)
    malformed_transition = object.__new__(InvariantTransition)
    with pytest.raises(CompanyInvariantError):
        reduce_company_invariants([malformed_object], [])
    with pytest.raises(CompanyInvariantError):
        reduce_company_invariants([], [malformed_shadow])
    with pytest.raises(CompanyInvariantError):
        reduce_company_invariants([], [], malformed_transition)


def test_reducer_rejects_malformed_frozen_payload_with_typed_error() -> None:
    item = InvariantObject(
        "SyntheticContractV1", "object-1", "event-1", 1, "a" * 64, PLAIN,
    )
    object.__setattr__(item, "payload", object.__new__(FrozenJsonMapping))
    with pytest.raises(CompanyInvariantError, match="payload is invalid"):
        reduce_company_invariants([item], [])


@pytest.mark.parametrize(
    "carrier",
    (
        InvariantObject(
            "SyntheticContractV1", "object-1", "event-1", 1, "a" * 64, PLAIN,
        ),
        UncertainDispatch(
            "reservation-1", "dispatch-1", "event-2", 2, "transaction-1",
            "command-1", "effect_unknown", "dispatched", "b" * 64, PLAIN,
        ),
        InvariantTransition(PLAIN, "committed"),
    ),
)
def test_whole_carrier_deepcopy_preserves_the_immutable_carrier(
    carrier: object,
) -> None:
    assert copy.deepcopy(carrier) is carrier
    assert not hasattr(carrier, "__dict__")
    with pytest.raises(TypeError):
        vars(carrier)


@pytest.mark.parametrize(
    "carrier_type",
    (InvariantObject, UncertainDispatch, InvariantTransition),
)
def test_immutable_carriers_reject_runtime_subclassing(
    carrier_type: type[object],
) -> None:
    with pytest.raises(TypeError, match="final"):
        type(
            f"Bypass{carrier_type.__name__}",
            (carrier_type,),
            {"__post_init__": lambda self: None},
        )


def test_mapping_has_no_direct_mutable_backing_referent() -> None:
    value = FrozenJsonMapping(PLAIN)
    assert not any(type(item) is dict for item in gc.get_referents(value))


@pytest.mark.parametrize(
    "invalid",
    (
        {"value": bytearray(b"mutable")},
        {"value": float("nan")},
        {1: "non-string key"},
    ),
)
def test_constructor_rejects_non_json_or_mutable_leaves(invalid: object) -> None:
    with pytest.raises(CompanyInvariantError, match="not bounded JSON"):
        InvariantObject(
            "SyntheticContractV1", "object-1", "event-1", 1, "a" * 64,
            cast(Any, invalid),
        )


def test_freezer_rejects_cycles_shared_aliases_and_excess_depth() -> None:
    cyclic: dict[str, Any] = {}
    cyclic["self"] = cyclic
    with pytest.raises(FrozenJsonError, match="repeated or cyclic"):
        freeze_json_payload(cyclic)
    shared: dict[str, Any] = {"value": 1}
    with pytest.raises(FrozenJsonError, match="repeated or cyclic"):
        freeze_json_payload({"left": shared, "right": shared})
    frozen_shared = FrozenJsonMapping(shared)
    with pytest.raises(FrozenJsonError, match="repeated or cyclic"):
        freeze_json_payload({"left": frozen_shared, "right": frozen_shared})
    deep: Any = None
    for _ in range(66):
        deep = [deep]
    with pytest.raises(FrozenJsonError, match="depth bound"):
        freeze_json_payload(deep)
    frozen_deep: Any = None
    with pytest.raises(FrozenJsonError, match="depth bound"):
        for _ in range(66):
            frozen_deep = FrozenJsonSequence([frozen_deep])


def test_repeated_empty_container_singletons_do_not_form_aliases() -> None:
    empty_tuple: tuple[()] = ()
    assert freeze_json_payload(
        MappingProxyType({"left": empty_tuple, "right": empty_tuple}),
    ) == {"left": [], "right": []}
    empty_list: list[Any] = []
    assert freeze_json_payload(
        {"left": empty_list, "right": empty_list},
    ) == {"left": [], "right": []}


def test_ledger_immutable_request_with_repeated_empty_arrays_freezes() -> None:
    request = ledger_immutable({
        "events": [{
            "payload": {
                "effect_evidence": [],
                "resolves_event_ids": [],
            },
        }],
    })
    transition = InvariantTransition(request, "committed")
    events = _sequence(transition.request["events"])
    payload = _mapping(_mapping(events[0])["payload"])
    assert payload["effect_evidence"] == []
    assert payload["resolves_event_ids"] == []


def test_freezer_enforces_collection_and_global_node_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(FrozenJsonError, match="collection exceeds"):
        freeze_json_payload([None] * 100_001)
    monkeypatch.setattr("aoi_orgware.frozen_json._MAX_JSON_NODES", 3)
    with pytest.raises(FrozenJsonError, match="global node bound"):
        freeze_json_payload([None, None, None])


def test_canonical_byte_bound_still_applies_after_freezing() -> None:
    payload = freeze_json_payload({"value": "0123456789"})
    with pytest.raises(SemanticEventError, match="byte bound"):
        canonical_json_bytes(payload, max_bytes=8)


def test_canonical_encoder_accepts_only_nominal_frozen_wrappers() -> None:
    payload = _payloads()[0]
    assert canonical_json_bytes(payload) == canonical_json_bytes(PLAIN)
    with pytest.raises(SemanticEventError, match="unsupported JSON value"):
        canonical_json_bytes(("ordinary", "tuple"))
    with pytest.raises(SemanticEventError, match="unsupported JSON value"):
        canonical_json_bytes(MappingProxyType({"ordinary": "mapping"}))
    with pytest.raises(SemanticEventError, match="unsupported JSON value"):
        canonical_json_bytes(_ForgedFrozenMapping({"forged": "subclass"}))
