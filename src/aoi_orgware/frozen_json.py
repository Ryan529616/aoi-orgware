"""Nominal immutable containers for validated AOI JSON trees.

The boundary covers ordinary aliases and mutable built-in descriptors, not
hostile same-process class monkeypatching, ``object.__setattr__``, or ``ctypes``.
"""
from __future__ import annotations

from bisect import bisect_left
from collections.abc import Iterator, Mapping, Sequence
import copy
import math
from typing import Any, NoReturn, overload

_IMMUTABLE = "immutable invariant payload"
_SCALAR_SEQUENCE_TYPES = (str, bytes, bytearray)
_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 1_000_000
_MAX_COLLECTION_ENTRIES = 100_000
class FrozenJsonError(ValueError):
    """An input cannot be represented as a bounded immutable JSON tree."""


class FrozenJsonMapping(Mapping[str, Any]):
    """A mapping that cannot reach mutable ``dict`` base descriptors."""
    __slots__ = ("__items", "__keys", "__positions")
    __items: tuple[tuple[str, Any], ...]
    __keys: tuple[str, ...]
    __positions: tuple[int, ...]

    def __init__(self, value: Mapping[str, Any]) -> None:
        frozen = freeze_json_payload(value)
        if type(frozen) is not FrozenJsonMapping:
            raise FrozenJsonError("frozen mapping input must be a JSON object")
        _store_mapping(self, frozen.frozen_items())

    def __getitem__(self, key: str) -> Any:
        try:
            keys = self.__keys
            positions = self.__positions
        except AttributeError as exc:
            raise FrozenJsonError(
                "frozen JSON mapping is not initialized",
            ) from exc
        items = self.frozen_items()
        offset = bisect_left(keys, key)
        if offset >= len(keys) or keys[offset] != key:
            raise KeyError(key)
        value = items[positions[offset]][1]
        if type(value) in (FrozenJsonMapping, FrozenJsonSequence):
            return _thaw(value, {})
        return value

    def __iter__(self) -> Iterator[str]:
        return (key for key, _ in self.frozen_items())

    def __len__(self) -> int:
        return len(self.frozen_items())

    def frozen_items(self) -> tuple[tuple[str, Any], ...]:
        """Return immutable backing pairs for trusted bounded traversal."""
        try:
            return self.__items
        except AttributeError as exc:
            raise FrozenJsonError(
                "frozen JSON mapping is not initialized",
            ) from exc

    def __repr__(self) -> str:
        return repr(dict(self.items()))

    def __setattr__(self, _: str, __: Any) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def __delattr__(self, _: str) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def __setitem__(self, _: str, __: Any) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def __delitem__(self, _: str) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def __ior__(self, _: object) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def clear(self) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def pop(self, *_: Any, **__: Any) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def popitem(self) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def setdefault(self, *_: Any, **__: Any) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def update(self, *_: Any, **__: Any) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def __deepcopy__(self, memo: dict[int, Any]) -> dict[str, Any]:
        result = _thaw(self, memo)
        assert isinstance(result, dict)
        return result

    def __copy__(self) -> FrozenJsonMapping:
        return self


class FrozenJsonSequence(Sequence[Any]):
    """A sequence that cannot reach mutable ``list`` base descriptors."""
    __slots__ = ("__values",)
    __values: tuple[Any, ...]

    def __init__(self, value: Sequence[Any]) -> None:
        frozen = freeze_json_payload(value)
        if type(frozen) is not FrozenJsonSequence:
            raise FrozenJsonError("frozen sequence input must be a JSON array")
        object.__setattr__(
            self,
            "_FrozenJsonSequence__values",
            frozen.frozen_values(),
        )

    @overload
    def __getitem__(self, index: int) -> Any: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[Any, ...]: ...

    def __getitem__(self, index: int | slice) -> Any:
        return self.frozen_values()[index]

    def __iter__(self) -> Iterator[Any]:
        return iter(self.frozen_values())

    def __len__(self) -> int:
        return len(self.frozen_values())

    def frozen_values(self) -> tuple[Any, ...]:
        """Return immutable backing values for trusted bounded traversal."""
        try:
            return self.__values
        except AttributeError as exc:
            raise FrozenJsonError(
                "frozen JSON sequence is not initialized",
            ) from exc

    def __repr__(self) -> str:
        return repr(list(self))

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, Sequence)
            and not isinstance(other, _SCALAR_SEQUENCE_TYPES)
            and tuple(self) == tuple(other)
        )

    def __setattr__(self, _: str, __: Any) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def __delattr__(self, _: str) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def __setitem__(self, _: int | slice, __: Any) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def __delitem__(self, _: int | slice) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def __iadd__(self, _: object) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def __imul__(self, _: object) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def append(self, _: Any) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def clear(self) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def extend(self, _: object) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def insert(self, _: int, __: Any) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def pop(self, _: int = -1) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def remove(self, _: Any) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def reverse(self) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def sort(self, *_: Any, **__: Any) -> NoReturn:
        raise TypeError(_IMMUTABLE)

    def __deepcopy__(self, memo: dict[int, Any]) -> list[Any]:
        result = _thaw(self, memo)
        assert isinstance(result, list)
        return result

    def __copy__(self) -> FrozenJsonSequence:
        return self


def _store_mapping(
    value: FrozenJsonMapping,
    items: tuple[tuple[str, Any], ...],
) -> None:
    order = tuple(sorted(range(len(items)), key=lambda index: items[index][0]))
    object.__setattr__(
        value,
        "_FrozenJsonMapping__items",
        items,
    )
    object.__setattr__(
        value,
        "_FrozenJsonMapping__keys",
        tuple(items[index][0] for index in order),
    )
    object.__setattr__(
        value,
        "_FrozenJsonMapping__positions",
        order,
    )


def _new_mapping(items: tuple[tuple[str, Any], ...]) -> FrozenJsonMapping:
    value = object.__new__(FrozenJsonMapping)
    _store_mapping(value, items)
    return value


def _new_sequence(values: tuple[Any, ...]) -> FrozenJsonSequence:
    value = object.__new__(FrozenJsonSequence)
    object.__setattr__(value, "_FrozenJsonSequence__values", values)
    return value


def _bounded_members(value: Any, path: str) -> tuple[Any, ...]:
    result: list[Any] = []
    try:
        for member in value:
            if len(result) >= _MAX_COLLECTION_ENTRIES:
                raise FrozenJsonError(
                    f"JSON collection exceeds entry bound at {path}",
                )
            result.append(member)
    except FrozenJsonError:
        raise
    except MemoryError:
        raise
    except Exception as exc:
        raise FrozenJsonError(
            f"JSON collection cannot be read at {path}: {type(exc).__name__}",
        ) from exc
    return tuple(result)


def _bounded_length(value: Any, path: str, label: str) -> int:
    try:
        length = len(value)
    except MemoryError:
        raise
    except Exception as exc:
        raise FrozenJsonError(
            f"JSON {label} cannot be sized at {path}: {type(exc).__name__}",
        ) from exc
    if length > _MAX_COLLECTION_ENTRIES:
        raise FrozenJsonError(f"JSON collection exceeds entry bound at {path}")
    return length


def _bounded_sequence_members(
    value: Sequence[Any],
    path: str,
) -> tuple[Any, ...]:
    length = _bounded_length(value, path, "sequence")
    indexed: list[Any] = []
    for index in range(length):
        try:
            indexed.append(value[index])
        except MemoryError:
            raise
        except Exception as exc:
            raise FrozenJsonError(
                f"JSON sequence item cannot be read at {path}[{index}]: "
                f"{type(exc).__name__}",
            ) from exc
    try:
        value[length]
    except IndexError:
        pass
    except MemoryError:
        raise
    except Exception as exc:
        raise FrozenJsonError(
            f"JSON sequence boundary cannot be read at {path}: "
            f"{type(exc).__name__}",
        ) from exc
    else:
        raise FrozenJsonError(f"JSON sequence length is inconsistent at {path}")
    iterated = _bounded_members(value, path)
    if len(iterated) != length or any(
        not _observations_match(left, right)
        for left, right in zip(indexed, iterated, strict=True)
    ):
        raise FrozenJsonError(f"JSON sequence views are inconsistent at {path}")
    return tuple(indexed)


def _normalized_scalar_observation(value: Any) -> tuple[str, Any] | None:
    if value is None:
        return ("null", None)
    if type(value) is bool:
        return ("bool", value)
    if isinstance(value, str):
        return ("string", (
            value
            if type(value) is str
            else str.__getitem__(value, slice(None))
        ))
    if isinstance(value, int) and not isinstance(value, bool):
        return ("integer", value if type(value) is int else int.__int__(value))
    if isinstance(value, float):
        normalized = (
            value
            if type(value) is float
            else float.__float__(value)
        )
        return ("number", float.hex(normalized))
    return None


def _observations_match(left: Any, right: Any) -> bool:
    if left is right:
        return True
    normalized_left = _normalized_scalar_observation(left)
    normalized_right = _normalized_scalar_observation(right)
    return (
        normalized_left is not None
        and normalized_right is not None
        and normalized_left == normalized_right
    )


def _bounded_mapping_members(
    value: Mapping[str, Any],
    path: str,
) -> tuple[tuple[str, Any], ...]:
    expected_length = _bounded_length(value, path, "mapping")
    raw_keys = _bounded_members(value, path)
    if len(raw_keys) != expected_length:
        raise FrozenJsonError(f"JSON mapping length is inconsistent at {path}")
    canonical: list[tuple[str, Any]] = []
    indexed_by_key: dict[str, Any] = {}
    for raw_key in raw_keys:
        if not isinstance(raw_key, str):
            raise FrozenJsonError(f"non-string JSON object key at {path}")
        key = (
            raw_key
            if type(raw_key) is str
            else str.__getitem__(raw_key, slice(None))
        )
        if key in indexed_by_key:
            raise FrozenJsonError(f"duplicate JSON object key at {path}")
        try:
            member = value[raw_key]
        except MemoryError:
            raise
        except Exception as exc:
            raise FrozenJsonError(
                f"JSON mapping value cannot be read at {path}.{key}: "
                f"{type(exc).__name__}",
            ) from exc
        indexed_by_key[key] = member
        canonical.append((key, member))
    try:
        items_view = value.items()
    except MemoryError:
        raise
    except Exception as exc:
        raise FrozenJsonError(
            f"JSON mapping items cannot be read at {path}: "
            f"{type(exc).__name__}",
        ) from exc
    item_members = _bounded_members(items_view, path)
    if len(item_members) != expected_length:
        raise FrozenJsonError(f"JSON mapping length is inconsistent at {path}")
    item_keys: set[str] = set()
    for pair in item_members:
        try:
            raw_key, member = pair
        except MemoryError:
            raise
        except Exception as exc:
            raise FrozenJsonError(
                f"JSON mapping item is invalid at {path}",
            ) from exc
        if not isinstance(raw_key, str):
            raise FrozenJsonError(f"non-string JSON object key at {path}")
        key = (
            raw_key
            if type(raw_key) is str
            else str.__getitem__(raw_key, slice(None))
        )
        if key in item_keys:
            raise FrozenJsonError(f"duplicate JSON object key at {path}")
        item_keys.add(key)
        if key not in indexed_by_key or not _observations_match(
            indexed_by_key[key],
            member,
        ):
            raise FrozenJsonError(f"JSON mapping views are inconsistent at {path}")
    if item_keys != set(indexed_by_key):
        raise FrozenJsonError(f"JSON mapping views are inconsistent at {path}")
    return tuple(canonical)


def _exact_frozen_mapping_members(
    value: FrozenJsonMapping,
    path: str,
) -> tuple[Any, ...]:
    try:
        members = value.frozen_items()
    except FrozenJsonError:
        raise
    except MemoryError:
        raise
    except Exception as exc:
        raise FrozenJsonError(
            f"frozen JSON mapping cannot be read at {path}: "
            f"{type(exc).__name__}",
        ) from exc
    return _bounded_members(members, path)


def _exact_frozen_sequence_members(
    value: FrozenJsonSequence,
    path: str,
) -> tuple[Any, ...]:
    try:
        members = value.frozen_values()
    except FrozenJsonError:
        raise
    except MemoryError:
        raise
    except Exception as exc:
        raise FrozenJsonError(
            f"frozen JSON sequence cannot be read at {path}: "
            f"{type(exc).__name__}",
        ) from exc
    return _bounded_members(members, path)


def _freeze(
    value: Any,
    *,
    path: str,
    depth: int,
    containers: set[int],
    budget: list[int],
) -> Any:
    if depth > _MAX_JSON_DEPTH:
        raise FrozenJsonError(f"JSON value exceeds depth bound at {path}")
    budget[0] += 1
    if budget[0] > _MAX_JSON_NODES:
        raise FrozenJsonError(f"JSON value exceeds global node bound at {path}")
    if value is None or type(value) is bool:
        return value
    if isinstance(value, str):
        return (
            value
            if type(value) is str
            else str.__getitem__(value, slice(None))
        )
    if isinstance(value, int) and not isinstance(value, bool):
        return value if type(value) is int else int.__int__(value)
    if isinstance(value, float):
        normalized_float = (
            value
            if type(value) is float
            else float.__float__(value)
        )
        if not math.isfinite(normalized_float):
            raise FrozenJsonError(f"non-finite JSON number at {path}")
        return normalized_float
    is_mapping = isinstance(value, Mapping)
    is_sequence = (
        isinstance(value, Sequence)
        and not isinstance(value, _SCALAR_SEQUENCE_TYPES)
    )
    if not is_mapping and not is_sequence:
        raise FrozenJsonError(
            f"unsupported JSON value at {path}: {type(value).__name__}",
        )
    if is_mapping:
        pairs: list[tuple[str, Any]] = []
        keys: set[str] = set()
        if type(value) is FrozenJsonMapping:
            members = _exact_frozen_mapping_members(value, path)
        else:
            members = _bounded_mapping_members(value, path)
        if not members:
            return _new_mapping(())
        identity = id(value)
        if identity in containers:
            raise FrozenJsonError(f"repeated or cyclic JSON container at {path}")
        containers.add(identity)
        for pair in members:
            try:
                key, member = pair
            except MemoryError:
                raise
            except Exception as exc:
                raise FrozenJsonError(
                    f"JSON mapping item is invalid at {path}",
                ) from exc
            if not isinstance(key, str):
                raise FrozenJsonError(f"non-string JSON object key at {path}")
            if type(key) is not str:
                key = str.__getitem__(key, slice(None))
            if key in keys:
                raise FrozenJsonError(f"duplicate JSON object key at {path}")
            keys.add(key)
            pairs.append((
                key,
                _freeze(
                    member,
                    path=f"{path}.{key}",
                    depth=depth + 1,
                    containers=containers,
                    budget=budget,
                ),
            ))
        return _new_mapping(tuple(pairs))
    raw_members = (
        _exact_frozen_sequence_members(value, path)
        if type(value) is FrozenJsonSequence
        else _bounded_sequence_members(value, path)
    )
    if not raw_members:
        return _new_sequence(())
    identity = id(value)
    if identity in containers:
        raise FrozenJsonError(f"repeated or cyclic JSON container at {path}")
    containers.add(identity)
    return _new_sequence(tuple(
        _freeze(
            member,
            path=f"{path}[{index}]",
            depth=depth + 1,
            containers=containers,
            budget=budget,
        )
        for index, member in enumerate(raw_members)
    ))


def freeze_json_payload(value: Any) -> Any:
    """Detach and freeze one bounded JSON tree without retaining aliases."""
    return _freeze(value, path="$", depth=0, containers=set(), budget=[0])


def _thaw(value: Any, memo: dict[int, Any]) -> Any:
    existing = memo.get(id(value))
    if existing is not None:
        return existing
    if type(value) is FrozenJsonMapping:
        frozen_result: dict[str, Any] = {}
        memo[id(value)] = frozen_result
        frozen_result.update(
            (key, _thaw(member, memo))
            for key, member in value.frozen_items()
        )
        return frozen_result
    if type(value) is FrozenJsonSequence:
        frozen_sequence: list[Any] = []
        memo[id(value)] = frozen_sequence
        frozen_sequence.extend(
            _thaw(member, memo) for member in value.frozen_values()
        )
        return frozen_sequence
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        memo[id(value)] = result
        result.update((str(key), _thaw(member, memo)) for key, member in value.items())
        return result
    if isinstance(value, Sequence) and not isinstance(value, _SCALAR_SEQUENCE_TYPES):
        sequence: list[Any] = []
        memo[id(value)] = sequence
        sequence.extend(_thaw(member, memo) for member in value)
        return sequence
    return copy.deepcopy(value, memo)


def thaw_json_payload(value: Any) -> Any:
    """Return a detached tree containing only ordinary JSON containers."""
    return _thaw(value, {})


def thaw_frozen_json(value: Any) -> Any:
    """Normalize only AOI frozen wrappers nested inside ordinary JSON."""
    if type(value) is FrozenJsonMapping:
        return {
            key: thaw_frozen_json(member)
            for key, member in value.frozen_items()
        }
    if type(value) is FrozenJsonSequence:
        return [thaw_frozen_json(member) for member in value.frozen_values()]
    if isinstance(value, dict):
        return {key: thaw_frozen_json(member) for key, member in value.items()}
    if isinstance(value, list):
        return [thaw_frozen_json(member) for member in value]
    return value
