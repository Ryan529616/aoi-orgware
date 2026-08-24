"""AOI-SYNTHETIC-FIXTURE-V1 coverage-fragment quiescence receipts."""

from __future__ import annotations

import os
import sqlite3
import stat
import sys
from pathlib import Path

import pytest

from scripts.coverage_fragment_quiescence import (
    MAX_FRAGMENT_FILES,
    MAX_FRAGMENT_SET_BYTES,
    CoverageFragmentReadError,
    CoveragePathMappingError,
    FragmentIdentity,
    _FragmentSetChanged,
    _read_stable_fragment_set,
    _snapshot_fragments,
    _snapshot_digest,
)
from scripts import verify_coverage_path_mapping as coverage_verifier


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
    assert clock.sleeps == [0.25, 0.25, 0.25]


def test_reader_failure_retries_when_the_full_set_changes_during_error_bracket() -> None:
    fragment = Path(".coverage.raw")
    first = {fragment: _identity(inode=1, mtime_ns=1)}
    replaced = {fragment: _identity(inode=2, mtime_ns=2)}
    calls = 0

    def reader(_fragment: Path) -> tuple[str, ...]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise CoverageFragmentReadError("coverage_data_read")
        return ("/trusted.py",)

    (fragments, measured, identities), clock = _read(
        _sequence(first, first, replaced, replaced, replaced, replaced, replaced),
        reader,
        attempts=2,
    )

    assert fragments == (fragment,)
    assert measured == {fragment: ("/trusted.py",)}
    assert identities == replaced
    assert calls == 2
    assert clock.sleeps == [0.25, 0.25, 0.25]


@pytest.mark.parametrize("failure_call,reader_fails_once", ((1, False), (2, False), (3, False), (3, True)))
def test_snapshot_disappearance_retries(failure_call: int, reader_fails_once: bool) -> None:
    fragment = Path(".coverage.raw")
    stable = {fragment: _identity()}
    snapshot_calls = 0
    reader_calls = 0
    clock = _Clock()

    def snapshot(_directory: Path) -> dict[Path, FragmentIdentity]:
        nonlocal snapshot_calls
        snapshot_calls += 1
        if snapshot_calls == failure_call:
            raise _FragmentSetChanged("observed disappearance")
        return stable

    def reader(_fragment: Path) -> tuple[str, ...]:
        nonlocal reader_calls
        reader_calls += 1
        if reader_fails_once and reader_calls == 1:
            raise CoverageFragmentReadError("coverage_data_read")
        return ("/trusted.py",)

    fragments, measured, identities = _read_stable_fragment_set(
        Path("fragments"),
        reader,
        snapshot=snapshot,
        attempts=2,
        stability_interval=0.25,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
    )

    assert fragments == (fragment,)
    assert measured == {fragment: ("/trusted.py",)}
    assert identities == stable
    assert reader_calls == (2 if failure_call == 3 else 1)


def test_later_writer_change_cannot_reuse_an_earlier_reader_failure_diagnostic() -> None:
    fragment = Path(".coverage.raw")
    stable = {fragment: _identity(inode=1, mtime_ns=1)}
    changed = {fragment: _identity(inode=2, mtime_ns=2)}

    with pytest.raises(CoveragePathMappingError) as caught:
        _read(
            _sequence(stable, stable, stable, stable, stable, changed),
            lambda _fragment: (_ for _ in ()).throw(
                CoverageFragmentReadError("coverage_data_read")
            ),
            attempts=2,
        )

    assert "did not stabilize" in str(caught.value)
    assert "stably unreadable" not in str(caught.value)


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
    assert "stage=reader_unclassified" in message
    assert "fragment_basename_sha256=" in message
    assert "fragment_identity_sha256=" in message
    assert "secret-host" not in message
    assert "pid999" not in message
    assert "/private/path" not in message


@pytest.mark.parametrize("corruption", ("mutated", "missing"))
def test_corrupted_reader_stage_is_closed(corruption: str) -> None:
    fragment = Path(".coverage.raw")
    stable = {fragment: _identity()}
    error = CoverageFragmentReadError("coverage_data_read")
    if corruption == "mutated":
        error._stage = "secret-stage"  # type: ignore[attr-defined]
    else:
        del error._stage  # type: ignore[attr-defined]

    with pytest.raises(CoveragePathMappingError) as caught:
        _read(
            _sequence(stable),
            lambda _fragment: (_ for _ in ()).throw(error),
            attempts=1,
        )

    assert "stage=reader_unclassified" in str(caught.value)
    assert "secret-stage" not in str(caught.value)


@pytest.mark.parametrize(
    ("stage", "coverage_data_type"),
    (
        (
            "coverage_data_read",
            type(
                "ReadFailure",
                (),
                {
                    "__init__": lambda self, **_kwargs: None,
                    "read": lambda self: (_ for _ in ()).throw(
                        RuntimeError("secret read failure")
                    ),
                    "close": lambda self: None,
                },
            ),
        ),
        (
            "measured_files",
            type(
                "MeasuredFailure",
                (),
                {
                    "__init__": lambda self, **_kwargs: None,
                    "read": lambda self: None,
                    "measured_files": lambda self: (_ for _ in ()).throw(
                        RuntimeError("secret measured failure")
                    ),
                    "close": lambda self: None,
                },
            ),
        ),
    ),
)
def test_workflow_reader_emits_only_closed_read_stages(
    monkeypatch,
    stage: str,
    coverage_data_type: type[object],
) -> None:
    monkeypatch.setattr(
        coverage_verifier,
        "_validate_coverage_fragment_schema",
        lambda _fragment: None,
    )
    with pytest.raises(CoverageFragmentReadError) as caught:
        coverage_verifier._read_fragment_measured_files(
            Path(".coverage.secret"),
            coverage_data_type,
        )
    assert caught.value.stage == stage
    assert "secret" not in str(caught.value)


def test_workflow_reader_classifies_schema_preflight_without_exception_text(
    monkeypatch,
) -> None:
    def invalid_schema(_fragment: Path) -> None:
        raise CoveragePathMappingError("secret raw schema diagnostic")

    monkeypatch.setattr(
        coverage_verifier,
        "_validate_coverage_fragment_schema",
        invalid_schema,
    )
    with pytest.raises(CoverageFragmentReadError) as caught:
        coverage_verifier._read_fragment_measured_files(
            Path(".coverage.secret"),
            object,
        )
    assert caught.value.stage == "schema_preflight"
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize("stage", ("coverage_data_read", "measured_files"))
def test_workflow_reader_does_not_convert_memory_exhaustion(stage: str, monkeypatch) -> None:
    class MemoryFailure:
        def __init__(self, **_kwargs) -> None:
            pass

        def read(self) -> None:
            if stage == "coverage_data_read":
                raise MemoryError

        def measured_files(self) -> tuple[str, ...]:
            raise MemoryError

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        coverage_verifier,
        "_validate_coverage_fragment_schema",
        lambda _fragment: None,
    )
    with pytest.raises(MemoryError):
        coverage_verifier._read_fragment_measured_files(
            Path(".coverage.memory"),
            MemoryFailure,
        )


def test_workflow_reader_closes_success_and_failure_objects(monkeypatch) -> None:
    class TrackingData:
        instances: list["TrackingData"] = []

        def __init__(self, **_kwargs) -> None:
            self.fail = len(type(self).instances) == 1
            self.closes = 0
            type(self).instances.append(self)

        def read(self) -> None:
            if self.fail:
                raise RuntimeError("secret read failure")

        def measured_files(self) -> tuple[str, ...]:
            return ("/trusted.py",)

        def close(self) -> None:
            self.closes += 1

    monkeypatch.setattr(
        coverage_verifier,
        "_validate_coverage_fragment_schema",
        lambda _fragment: None,
    )
    assert coverage_verifier._read_fragment_measured_files(
        Path(".coverage.success"), TrackingData
    ) == ("/trusted.py",)
    with pytest.raises(CoverageFragmentReadError) as caught:
        coverage_verifier._read_fragment_measured_files(
            Path(".coverage.failure"), TrackingData
        )
    assert caught.value.stage == "coverage_data_read"
    assert [item.closes for item in TrackingData.instances] == [1, 1]


def test_workflow_reader_classifies_close_failure(monkeypatch) -> None:
    class CloseFailure:
        def __init__(self, **_kwargs) -> None:
            pass

        def read(self) -> None:
            pass

        def measured_files(self) -> tuple[str, ...]:
            return ("/trusted.py",)

        def close(self) -> None:
            raise RuntimeError("secret close failure")

    monkeypatch.setattr(
        coverage_verifier,
        "_validate_coverage_fragment_schema",
        lambda _fragment: None,
    )
    with pytest.raises(CoverageFragmentReadError) as caught:
        coverage_verifier._read_fragment_measured_files(
            Path(".coverage.close"), CloseFailure
        )
    assert caught.value.stage == "coverage_data_close"
    assert "secret" not in str(caught.value)


def test_stably_corrupt_sqlite_fragment_remains_fail_closed(tmp_path: Path) -> None:
    fragment = tmp_path / ".coverage.corrupt"
    original = b"not-a-sqlite-database"
    fragment.write_bytes(original)
    stable = _snapshot_fragments(tmp_path)
    clock = _Clock()

    with pytest.raises(CoveragePathMappingError) as caught:
        _read_stable_fragment_set(
            tmp_path,
            lambda path: coverage_verifier._read_fragment_measured_files(path, object),
            snapshot=_sequence(stable),
            attempts=1,
            stability_interval=0.25,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )

    assert "stage=schema_preflight" in str(caught.value)
    assert "corrupt" not in str(caught.value)
    assert fragment.read_bytes() == original


def test_schema_valid_but_incompatible_coverage_data_has_read_stage(
    tmp_path: Path,
) -> None:
    coverage = pytest.importorskip("coverage")
    fragment = tmp_path / ".coverage.incompatible"
    with sqlite3.connect(fragment) as database:
        database.execute("CREATE TABLE coverage_schema (version integer)")
        database.execute("INSERT INTO coverage_schema (version) VALUES (999999)")

    with pytest.raises(CoverageFragmentReadError) as caught:
        coverage_verifier._read_fragment_measured_files(
            fragment,
            coverage.CoverageData,
        )

    assert caught.value.stage == "coverage_data_read"


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
    assert MAX_FRAGMENT_FILES == 8192
    assert MAX_FRAGMENT_FILES & (MAX_FRAGMENT_FILES - 1) == 0
    reads: list[Path] = []
    over = {
        Path(f".coverage.{index:05d}"): _identity(index + 1)
        for index in range(MAX_FRAGMENT_FILES + 1)
    }
    with pytest.raises(CoveragePathMappingError, match="fragment_count_oversize"):
        _read(_sequence(over), lambda path: reads.append(path) or (), attempts=1)
    assert reads == []


def test_at_limit_fragment_set_is_feasible_and_fully_read() -> None:
    fragments = {
        Path(f".coverage.{index:04d}"): _identity(index + 1)
        for index in range(MAX_FRAGMENT_FILES)
    }
    reads: list[Path] = []

    (sealed, measured, identities), _ = _read(
        _sequence(fragments),
        lambda fragment: reads.append(fragment) or ("/trusted.py",),
        attempts=1,
    )

    assert len(sealed) == MAX_FRAGMENT_FILES
    assert len(measured) == MAX_FRAGMENT_FILES
    assert identities == fragments
    assert reads == list(sealed)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux coverage.py scale receipt")
def test_real_coverage_data_large_representative_set_is_fully_read(
    tmp_path: Path,
) -> None:
    coverage = pytest.importorskip("coverage")
    seed = tmp_path / ".coverage.0000"
    data = coverage.CoverageData(basename=str(seed))
    data.add_lines({str(tmp_path / "measured.py"): {1}})
    data.write()
    data.close()
    for index in range(1, 3908):
        os.link(seed, tmp_path / f".coverage.{index:04d}")
    clock = _Clock()

    fragments, measured, identities = _read_stable_fragment_set(
        tmp_path,
        lambda fragment: coverage_verifier._read_fragment_measured_files(
            fragment,
            coverage.CoverageData,
        ),
        attempts=1,
        stability_interval=0.01,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
    )

    assert len(fragments) == 3908
    assert len(measured) == 3908
    assert len(identities) == 3908
    assert set(measured.values()) == {(str(tmp_path / "measured.py"),)}


def test_stable_reader_retries_cache_successful_prefix() -> None:
    first = Path(".coverage.a")
    failing = Path(".coverage.z")
    stable = {failing: _identity(2), first: _identity(1)}
    reads: list[Path] = []

    def reader(fragment: Path) -> tuple[str, ...]:
        reads.append(fragment)
        if fragment == failing:
            raise CoverageFragmentReadError("coverage_data_read")
        return ("/trusted.py",)

    with pytest.raises(CoveragePathMappingError, match="stably unreadable"):
        _read(_sequence(stable), reader, attempts=3)

    assert reads == [first, failing, failing, failing]


def test_first_reader_failure_is_selected_by_canonical_basename_order() -> None:
    first = Path(".coverage.a")
    second = Path(".coverage.z")
    ordered = {first: _identity(1), second: _identity(2)}
    reversed_order = {second: _identity(2), first: _identity(1)}

    def failure_receipt(snapshot: dict[Path, FragmentIdentity]) -> str:
        with pytest.raises(CoveragePathMappingError) as caught:
            _read(
                _sequence(snapshot),
                lambda _fragment: (_ for _ in ()).throw(
                    CoverageFragmentReadError("coverage_data_read")
                ),
                attempts=1,
            )
        return str(caught.value)

    assert failure_receipt(ordered) == failure_receipt(reversed_order)

    def success_order(snapshot: dict[Path, FragmentIdentity]) -> tuple[Path, ...]:
        (fragments, _, _), _ = _read(
            _sequence(snapshot),
            lambda _fragment: ("/trusted.py",),
            attempts=1,
        )
        return fragments

    assert success_order(ordered) == success_order(reversed_order) == (first, second)


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


@pytest.mark.parametrize(
    "snapshot",
    (
        [],
        {Path(".coverage.raw"): object()},
        {".coverage.raw": _identity()},
        {Path(".coverage.raw"): FragmentIdentity(stat.S_IFREG, 1, object(), 1)},
        {Path(".coverage.raw"): FragmentIdentity(stat.S_IFREG, 1, True, 1)},
        {Path(".coverage.raw"): FragmentIdentity(stat.S_IFREG, -1, 64, 1)},
        {Path(".coverage.raw"): FragmentIdentity(stat.S_IFREG, 1, 64, 1 << 128)},
    ),
)
def test_malformed_snapshot_fails_typed_before_field_access(snapshot: object) -> None:
    with pytest.raises(CoveragePathMappingError, match="snapshot is invalid"):
        _read_stable_fragment_set(
            Path("fragments"),
            lambda _fragment: (),
            snapshot=lambda _directory: snapshot,  # type: ignore[return-value]
            attempts=1,
        )


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
