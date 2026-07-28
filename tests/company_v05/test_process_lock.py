from __future__ import annotations

import multiprocessing
import os
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from aoi_orgware.company.process_lock import (
    CompanyProcessLock,
    CompanyProcessLockBusyError,
    CompanyProcessLockError,
    CompanyProcessLockOwnershipError,
)


def _hold_in_child(path: str, ready: Any, release: Any) -> None:
    with CompanyProcessLock(path, timeout_seconds=3):
        ready.set()
        release.wait(10)


def _crash_after_lock(path: str, ready: Any) -> None:
    with CompanyProcessLock(path, timeout_seconds=3):
        ready.set()
        os._exit(0)


def _fork_reenter(path: str, write_fd: int) -> None:
    try:
        CompanyProcessLock(path, timeout_seconds=0).acquire()
    except CompanyProcessLockOwnershipError:
        os.write(write_fd, b"fenced")
    finally:
        os.close(write_fd)
    os._exit(0)


def _parent_exits_after_child_closes(
    path: str,
    parent_ready_fd: int,
    child_release_fd: int,
) -> None:
    lock = CompanyProcessLock(path)
    lock.acquire()
    child_ready_fd, child_closed_fd = os.pipe()
    child = os.fork()  # type: ignore[attr-defined]
    if child == 0:
        os.close(child_ready_fd)
        lock.close()
        os.write(child_closed_fd, b"closed")
        os.read(child_release_fd, 1)
        os._exit(0)
    os.close(child_closed_fd)
    if os.read(child_ready_fd, 6) != b"closed":
        os._exit(91)
    os.write(parent_ready_fd, f"{child}\n".encode("ascii"))
    os._exit(0)


def test_requires_absolute_existing_stable_parent(tmp_path: Path) -> None:
    with pytest.raises(CompanyProcessLockError, match="absolute"):
        CompanyProcessLock("company.lock")
    with pytest.raises(CompanyProcessLockError, match="parent must already exist"):
        CompanyProcessLock(tmp_path / "missing" / "company.lock")
    with pytest.raises(CompanyProcessLockError, match="absolute"):
        CompanyProcessLock("~/company.lock")


def test_creates_private_one_byte_sentinel_and_close_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "company.lock"
    lock = CompanyProcessLock(path)
    assert not lock.held
    lock.acquire()
    assert lock.held
    assert lock._entry is not None and not os.get_inheritable(lock._entry.descriptor)
    lock.assert_owned()
    if os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0
    lock.close()
    lock.close()
    assert not lock.held and path.read_bytes() == b"\0"
    with CompanyProcessLock(path) as reopened:
        assert reopened.held


def test_existing_only_open_never_recreates_missing_lock(
    tmp_path: Path,
) -> None:
    path = tmp_path / "company.lock"
    with pytest.raises(
        CompanyProcessLockError,
        match="cannot open existing company lock",
    ):
        CompanyProcessLock(
            path,
            create_if_missing=False,
        ).acquire()
    assert not path.exists()

    with CompanyProcessLock(path):
        pass
    with CompanyProcessLock(
        path,
        create_if_missing=False,
    ) as reopened:
        assert reopened.held


def test_same_thread_exact_path_reentrancy_balances_close(tmp_path: Path) -> None:
    path = tmp_path / "company.lock"
    outer = CompanyProcessLock(path)
    inner = CompanyProcessLock(path)
    outer.acquire()
    inner.acquire()
    inner.close()
    assert outer.held
    outer.close()
    with CompanyProcessLock(path, timeout_seconds=0):
        pass


def test_other_thread_times_out_while_owner_holds_lock(tmp_path: Path) -> None:
    path = tmp_path / "company.lock"
    result: list[type[BaseException] | None] = []

    def contend() -> None:
        try:
            CompanyProcessLock(path, timeout_seconds=0.15, poll_interval_seconds=0.01).acquire()
        except BaseException as exc:
            result.append(type(exc))

    with CompanyProcessLock(path):
        thread = threading.Thread(target=contend)
        thread.start()
        thread.join(3)
    assert not thread.is_alive()
    assert result == [CompanyProcessLockBusyError]


def test_cross_process_exclusion_then_release(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    path = str(tmp_path / "company.lock")
    ready = context.Event()
    release = context.Event()
    process = context.Process(target=_hold_in_child, args=(path, ready, release))
    process.start()
    try:
        assert ready.wait(10)
        with pytest.raises(CompanyProcessLockBusyError):
            CompanyProcessLock(path, timeout_seconds=0.15, poll_interval_seconds=0.01).acquire()
        release.set()
        process.join(10)
        assert process.exitcode == 0
        with CompanyProcessLock(path, timeout_seconds=1):
            pass
    finally:
        release.set()
        process.join(2)
        if process.is_alive():
            process.kill()


def test_crashed_process_releases_platform_lock(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    path = str(tmp_path / "company.lock")
    ready = context.Event()
    process = context.Process(target=_crash_after_lock, args=(path, ready))
    process.start()
    try:
        assert ready.wait(10)
        process.join(10)
        assert process.exitcode == 0
        with CompanyProcessLock(path, timeout_seconds=2):
            pass
    finally:
        process.join(2)
        if process.is_alive():
            process.kill()


def test_rejects_bad_sentinel_hardlink_and_symlink(tmp_path: Path) -> None:
    empty = tmp_path / "empty.lock"
    empty.write_bytes(b"")
    with pytest.raises(CompanyProcessLockError, match="sentinel"):
        CompanyProcessLock(empty).acquire()
    assert empty.read_bytes() == b""

    bad = tmp_path / "bad.lock"
    bad.write_bytes(b"bad")
    with pytest.raises(CompanyProcessLockError, match="sentinel"):
        CompanyProcessLock(bad).acquire()

    linked = tmp_path / "linked.lock"
    linked.write_bytes(b"\0")
    alias = tmp_path / "linked.alias"
    os.link(linked, alias)
    with pytest.raises(CompanyProcessLockError, match="non-linked"):
        CompanyProcessLock(linked).acquire()

    target = tmp_path / "target.lock"
    target.write_bytes(b"\0")
    link = tmp_path / "symbolic.lock"
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symbolic links unavailable: {exc}")
    with pytest.raises(CompanyProcessLockError, match="symlink|junction"):
        CompanyProcessLock(link).acquire()


def test_detects_path_inode_replacement_while_held(tmp_path: Path) -> None:
    path = tmp_path / "company.lock"
    replacement = tmp_path / "replacement.lock"
    lock = CompanyProcessLock(path)
    lock.acquire()
    replacement.write_bytes(b"\0")
    if os.name != "nt":
        replacement.chmod(0o600)
    try:
        os.replace(replacement, path)
    except PermissionError as exc:
        lock.close()
        if os.name == "nt":
            pytest.skip(f"Windows denies replacing an actively held lock: {exc}")
        raise
    with pytest.raises(CompanyProcessLockError, match="changed while held"):
        lock.assert_held()
    with pytest.raises(CompanyProcessLockError, match="changed while held"):
        lock.assert_owned()
    with pytest.raises(CompanyProcessLockError, match="changed while held"):
        lock.close()
    assert not lock.held


@pytest.mark.skipif(os.name == "nt", reason="fork is POSIX-only")
def test_forked_child_cannot_reenter_parent_lock(tmp_path: Path) -> None:
    path = tmp_path / "company.lock"
    read_fd, write_fd = os.pipe()
    with CompanyProcessLock(path):
        child = os.fork()  # type: ignore[attr-defined]
        if child == 0:
            os.close(read_fd)
            _fork_reenter(str(path), write_fd)
        os.close(write_fd)
        try:
            assert os.read(read_fd, 32) == b"fenced"
            _, status = os.waitpid(child, 0)
            assert os.waitstatus_to_exitcode(status) == 0
        finally:
            os.close(read_fd)


@pytest.mark.skipif(os.name == "nt", reason="fork is POSIX-only")
def test_fork_child_close_releases_inherited_descriptor_after_parent_exit(
    tmp_path: Path,
) -> None:
    path = tmp_path / "company.lock"
    test_ready_fd, parent_ready_fd = os.pipe()
    child_release_fd, test_release_fd = os.pipe()
    parent = os.fork()  # type: ignore[attr-defined]
    if parent == 0:
        os.close(test_ready_fd)
        os.close(test_release_fd)
        _parent_exits_after_child_closes(
            str(path), parent_ready_fd, child_release_fd,
        )
    os.close(parent_ready_fd)
    os.close(child_release_fd)
    child_pid = 0
    try:
        child_pid = int(os.read(test_ready_fd, 32).decode("ascii").strip())
        _, status = os.waitpid(parent, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        with CompanyProcessLock(path, timeout_seconds=1):
            pass
    finally:
        os.write(test_release_fd, b"x")
        os.close(test_ready_fd)
        os.close(test_release_fd)
        if child_pid:
            for _ in range(20):
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)


def test_invalid_timeout_and_poll_values(tmp_path: Path) -> None:
    path = tmp_path / "company.lock"
    with pytest.raises(CompanyProcessLockError, match="timeout"):
        CompanyProcessLock(path, timeout_seconds=-1)
    with pytest.raises(CompanyProcessLockError, match="poll interval"):
        CompanyProcessLock(path, poll_interval_seconds=0)
    with pytest.raises(CompanyProcessLockError, match="boolean"):
        CompanyProcessLock(path, create_if_missing=1)  # type: ignore[arg-type]
