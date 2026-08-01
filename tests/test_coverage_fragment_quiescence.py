"""AOI-SYNTHETIC-FIXTURE-V1 coverage-fragment quiescence receipts."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from scripts.coverage_fragment_quiescence import (
    MAX_FRAGMENT_FILES,
    MAX_FRAGMENT_SET_BYTES,
    CoveragePathMappingError,
    FragmentIdentity,
    _read_stable_fragment_set,
    _snapshot_fragments,
    _snapshot_digest,
)


def _identity(
    inode: int = 1,
    *,
    size: int = 64,
    mtime_ns: int = 1,
    file_type: int = stat.S_IFREG,
) -> FragmentIdentity:
    return FragmentIdentity(file_type, inode, size, mtime_ns)


def _sequence(*states: dict[Path, FragmentIdentity]):
    remaining = iter(states)
    current = states[-1]

    def snapshot(_directory: Path) -> dict[Path, FragmentIdentity]:
        nonlocal current
        try:
            current = next(remaining)
        except StopIteration:
            pass
        return dict(current)

    return snapshot


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, duration: float) -> None:
        self.sleeps.append(duration)
        self.now += duration


def _read(
    snapshot,
    reader=lambda _fragment: ("/trusted.py",),
    *,
    attempts: int = 8,
):
    clock = _Clock()
    result = _read_stable_fragment_set(
        Path("fragments"),
        reader,
        snapshot=snapshot,
        attempts=attempts,
        stability_interval=0.25,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
    )
    return result, clock


def test_zero_byte_publication_can_finish_on_last_bounded_attempt() -> None:
    fragment = Path(".coverage.runner.pid123.secret")
    zero = {fragment: _identity(size=0)}
    valid = {fragment: _identity(size=4096, mtime_ns=2)}
    reads: list[Path] = []

    (fragments, measured, identities), clock = _read(
        _sequence(zero, zero, zero, zero, zero, valid, valid, valid),
        lambda path: reads.append(path) or ("/trusted.py",),
        attempts=4,
    )

    assert fragments == (fragment,)
    assert measured == {fragment: ("/trusted.py",)}
    assert identities == valid
    assert reads == [fragment]
    assert clock.sleeps == [0.25] * 4


def test_persistent_zero_exhausts_without_consuming_or_disclosing_name() -> None:
    fragment = Path(".coverage.runner.pid123.secret")
    zero = {fragment: _identity(size=0)}
    reads: list[Path] = []

    with pytest.raises(CoveragePathMappingError) as caught:
        _read(
            _sequence(zero),
            lambda path: reads.append(path) or (),
            attempts=3,
        )

    message = str(caught.value)
    assert "reason=incomplete_zero_byte" in message
    assert "member_count=1" in message
    assert "identity_semantics=cooperative_lstat_metadata_v1" in message
    assert "metadata_snapshot_sha256=" in message
    assert "runner" not in message
    assert "pid123" not in message
    assert "secret" not in message
    assert reads == []


def test_truncated_fragment_can_be_replaced_before_bounded_exhaustion() -> None:
    fragment = Path(".coverage.raw")
    truncated = {fragment: _identity(size=12)}
    valid = {fragment: _identity(inode=2, size=4096, mtime_ns=2)}
    calls = 0

    def reader(_fragment: Path) -> tuple[str, ...]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ValueError("secret raw sqlite failure")
        return ("/trusted.py",)

    (fragments, measured, identities), clock = _read(
        _sequence(truncated, truncated, valid, valid, valid),
        reader,
        attempts=3,
    )

    assert fragments == (fragment,)
    assert measured[fragment] == ("/trusted.py",)
    assert identities == valid
    assert calls == 2
    assert clock.sleeps == [0.25, 0.25]


def test_persistent_reader_failure_is_bounded_and_redacted() -> None:
    fragment = Path(".coverage.secret-host.pid999")
    stable = {fragment: _identity()}

    with pytest.raises(CoveragePathMappingError) as caught:
        _read(
            _sequence(stable),
            lambda _path: (_ for _ in ()).throw(
                ValueError("secret-host pid999 /private/path")
            ),
            attempts=3,
        )

    message = str(caught.value)
    assert "reason=coverage_data_incomplete_or_invalid" in message
    assert "secret-host" not in message
    assert "pid999" not in message
    assert "/private/path" not in message


@pytest.mark.parametrize("suffix", ("-journal", "-wal", "-shm"))
def test_sqlite_sidecar_must_disappear_before_the_full_set_is_read(
    suffix: str,
) -> None:
    fragment = Path(".coverage.raw")
    sidecar = Path(f".coverage.raw{suffix}")
    writing = {fragment: _identity(), sidecar: _identity(inode=2)}
    valid = {fragment: _identity()}
    reads: list[Path] = []

    (fragments, _, _), _ = _read(
        _sequence(writing, writing, valid, valid, valid),
        lambda path: reads.append(path) or ("/trusted.py",),
        attempts=3,
    )

    assert fragments == (fragment,)
    assert reads == [fragment]


def test_persistent_sqlite_sidecar_fails_without_partial_read() -> None:
    fragment = Path(".coverage.raw")
    sidecar = Path(".coverage.raw-wal")
    writing = {fragment: _identity(), sidecar: _identity(inode=2)}
    reads: list[Path] = []

    with pytest.raises(CoveragePathMappingError, match="sqlite_writer_sidecar"):
        _read(
            _sequence(writing),
            lambda path: reads.append(path) or (),
            attempts=3,
        )
    assert reads == []


@pytest.mark.parametrize(
    "identity",
    (
        _identity(size=0),
        _identity(file_type=stat.S_IFDIR),
        _identity(file_type=stat.S_IFLNK),
    ),
)
def test_reserved_destination_conflict_is_immediate(
    identity: FragmentIdentity,
) -> None:
    clock = _Clock()
    base = {Path(".coverage"): identity}

    with pytest.raises(CoveragePathMappingError, match="reserved_destination_conflict"):
        _read_stable_fragment_set(
            Path("fragments"),
            lambda _fragment: (),
            snapshot=_sequence(base),
            attempts=8,
            stability_interval=0.25,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )
    assert clock.sleeps == []


def test_valid_plus_incomplete_never_reads_a_valid_subset() -> None:
    valid = Path(".coverage.valid")
    empty = Path(".coverage.empty")
    mixed = {valid: _identity(), empty: _identity(inode=2, size=0)}
    reads: list[Path] = []

    with pytest.raises(CoveragePathMappingError, match="incomplete_zero_byte"):
        _read(
            _sequence(mixed),
            lambda path: reads.append(path) or (),
            attempts=2,
        )
    assert reads == []


def test_empty_set_can_publish_a_complete_fragment_within_budget() -> None:
    empty: dict[Path, FragmentIdentity] = {}
    fragment = Path(".coverage.late")
    valid = {fragment: _identity()}

    (fragments, _, _), _ = _read(
        _sequence(empty, empty, valid, valid, valid),
        attempts=3,
    )
    assert fragments == (fragment,)


def test_fragment_count_bound_is_fail_closed() -> None:
    over = {
        Path(f".coverage.{index:05d}"): _identity(index + 1)
        for index in range(MAX_FRAGMENT_FILES + 1)
    }
    with pytest.raises(CoveragePathMappingError, match="fragment_count_oversize"):
        _read(_sequence(over), attempts=1)


def test_real_snapshot_enumeration_stops_at_the_fragment_count_bound(
    monkeypatch,
) -> None:
    class _Directory:
        def iterdir(self):
            return (
                Path(f".coverage.{index:05d}")
                for index in range(MAX_FRAGMENT_FILES + 2)
            )

    identities = 0

    def identity(_path: Path) -> FragmentIdentity:
        nonlocal identities
        identities += 1
        return _identity(identities)

    monkeypatch.setattr(
        "scripts.coverage_fragment_quiescence._fragment_identity", identity
    )
    with pytest.raises(CoveragePathMappingError, match="fragment_count_oversize"):
        _snapshot_fragments(_Directory())  # type: ignore[arg-type]
    assert identities == 0


def test_fragment_set_aggregate_byte_bound_is_fail_closed() -> None:
    per_fragment = 64 * 1024 * 1024
    at_limit_count = MAX_FRAGMENT_SET_BYTES // per_fragment
    at_limit = {
        Path(f".coverage.{index:05d}"): _identity(index + 1, size=per_fragment)
        for index in range(at_limit_count)
    }
    (fragments, _, _), _ = _read(_sequence(at_limit), attempts=1)
    assert len(fragments) == at_limit_count

    count = at_limit_count + 1
    over = {
        Path(f".coverage.{index:05d}"): _identity(index + 1, size=per_fragment)
        for index in range(count)
    }
    with pytest.raises(CoveragePathMappingError, match="fragment_set_oversize"):
        _read(_sequence(over), attempts=1)


@pytest.mark.skipif(os.name != "posix", reason="POSIX surrogateescape boundary")
def test_posix_raw_byte_basename_has_a_typed_canonical_snapshot(tmp_path: Path) -> None:
    raw_path = os.path.join(os.fsencode(tmp_path), b".coverage.\xff")
    descriptor = os.open(raw_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, b"coverage")
    finally:
        os.close(descriptor)

    snapshot = _snapshot_fragments(tmp_path)
    assert len(snapshot) == 1
    assert len(_snapshot_digest(snapshot)) == 64


def test_fragment_basename_byte_bound_fails_typed_and_redacted() -> None:
    secret = "secret-host-pid123"
    fragment = Path(".coverage." + secret + "x" * 1100)
    with pytest.raises(CoveragePathMappingError) as caught:
        _snapshot_digest({fragment: _identity()})
    assert "byte bound" in str(caught.value)
    assert secret not in str(caught.value)


@pytest.mark.parametrize("attempts", (True, False, 0, 9))
def test_attempt_bound_rejects_bool_and_out_of_range(attempts: object) -> None:
    with pytest.raises(CoveragePathMappingError, match="attempt bound is invalid"):
        _read_stable_fragment_set(
            Path("fragments"),
            lambda _fragment: (),
            snapshot=_sequence({Path(".coverage.raw"): _identity()}),
            attempts=attempts,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("interval", (True, False))
def test_stability_interval_rejects_bool(interval: object) -> None:
    with pytest.raises(CoveragePathMappingError, match="interval is invalid"):
        _read_stable_fragment_set(
            Path("fragments"),
            lambda _fragment: (),
            snapshot=_sequence({Path(".coverage.raw"): _identity()}),
            stability_interval=interval,  # type: ignore[arg-type]
        )


def test_snapshot_digest_is_order_independent_and_identity_bound() -> None:
    left = Path(".coverage.left")
    right = Path(".coverage.right")
    first = {left: _identity(1), right: _identity(2)}
    reversed_order = {right: _identity(2), left: _identity(1)}
    changed = {left: _identity(1), right: _identity(2, mtime_ns=2)}

    assert _snapshot_digest(first) == _snapshot_digest(reversed_order)
    assert _snapshot_digest(first) != _snapshot_digest(changed)
