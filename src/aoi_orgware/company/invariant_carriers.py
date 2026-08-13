"""Bounded immutable value carriers for the company invariant reducer."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast, final, NoReturn, Self

from ..frozen_json import (
    FrozenJsonError,
    FrozenJsonMapping,
    freeze_json_payload,
)


class CompanyInvariantError(ValueError):
    """A cross-record company invariant is not satisfied."""


def _frozen_field(value: Any, label: str) -> Any:
    try:
        return freeze_json_payload(value)
    except FrozenJsonError as exc:
        raise CompanyInvariantError(
            f"{label} is not bounded JSON: {exc}",
        ) from exc


def _freeze_fields(
    value: Any,
    text: tuple[str, ...],
    integer: str | None = None,
) -> None:
    for name in text:
        object.__setattr__(
            value,
            name,
            _frozen_field(getattr(value, name), name),
        )
    if integer is not None:
        object.__setattr__(
            value,
            integer,
            _frozen_field(getattr(value, integer), integer),
        )


def _frozen_mapping(value: Any, label: str) -> Mapping[str, Any]:
    frozen = _frozen_field(value, label)
    if type(frozen) is not FrozenJsonMapping:
        raise CompanyInvariantError(f"{label} must be a JSON object")
    return cast(Mapping[str, Any], frozen)


class _ImmutableCarrier:
    __slots__ = ()

    def __deepcopy__(self, _: dict[int, Any]) -> Self:
        return self


@final
@dataclass(frozen=True, slots=True)
class InvariantObject(_ImmutableCarrier):
    contract_type: str
    object_key: str
    event_id: str
    global_sequence: int
    payload_sha256: str
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        _freeze_fields(
            self,
            ("contract_type", "object_key", "event_id", "payload_sha256"),
            "global_sequence",
        )
        object.__setattr__(
            self,
            "payload",
            _frozen_mapping(self.payload, "invariant object payload"),
        )

    def __init_subclass__(cls, **_: Any) -> NoReturn:
        raise TypeError("InvariantObject is final")


@final
@dataclass(frozen=True, slots=True)
class UncertainDispatch(_ImmutableCarrier):
    reservation_id: str
    dispatch_request_id: str
    source_event_id: str
    source_global_sequence: int
    source_transaction_id: str
    source_command_id: str
    receipt_state: str
    requested_state: str
    payload_sha256: str
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        _freeze_fields(
            self,
            (
                "reservation_id",
                "dispatch_request_id",
                "source_event_id",
                "source_transaction_id",
                "source_command_id",
                "receipt_state",
                "requested_state",
                "payload_sha256",
            ),
            "source_global_sequence",
        )
        object.__setattr__(
            self,
            "payload",
            _frozen_mapping(self.payload, "uncertain dispatch payload"),
        )

    def __init_subclass__(cls, **_: Any) -> NoReturn:
        raise TypeError("UncertainDispatch is final")


@final
@dataclass(frozen=True, slots=True)
class InvariantTransition(_ImmutableCarrier):
    request: Mapping[str, Any]
    receipt_state: str

    def __post_init__(self) -> None:
        _freeze_fields(self, ("receipt_state",))
        object.__setattr__(
            self,
            "request",
            _frozen_mapping(self.request, "invariant transition request"),
        )

    def __init_subclass__(cls, **_: Any) -> NoReturn:
        raise TypeError("InvariantTransition is final")


__all__ = [
    "CompanyInvariantError",
    "InvariantObject",
    "InvariantTransition",
    "UncertainDispatch",
]
