"""AOI-SYNTHETIC-FIXTURE-V1 process lifecycle adversarial tests."""

from __future__ import annotations

from collections.abc import Callable, Sequence
import ctypes
import os
from pathlib import Path
import subprocess
import sys
from threading import Thread, current_thread, enumerate as enumerate_threads
import time
from typing import Any

import pytest

from aoi_orgware.company import file_governance_io as governance_io
from aoi_orgware.company.file_governance import FileGovernanceError
from aoi_orgware.company.file_governance_io import _run_git
from aoi_orgware.company.file_governance_process import (
    quiesce_git_process,
    spawn_git_process,
)


_SLEEPING_PROCESS_TREE = (
    "import pathlib,subprocess,sys,time;"
    "child=subprocess.Popen([sys.executable,'-B','-c',"
    "'import time;time.sleep(30)']);"
    "target=pathlib.Path(sys.argv[1]);temp=target.with_suffix('.tmp');"
    "temp.write_text(str(child.pid),encoding='ascii');temp.replace(target);"
    "print('ready',flush=True);time.sleep(30)"
)
_MARKER_WORKLOAD = (
    "from pathlib import Path;import sys;"
    "Path(sys.argv[1]).write_text('ran',encoding='ascii')"
)
_OVERFLOW_WORKLOAD = (
    "import sys,time;"
    "sys.stdout.buffer.write(b'x'*4096);sys.stdout.buffer.flush();time.sleep(30)"
)


def _reader_thread_ids() -> set[int]:
    return {
        id(thread)
        for thread in enumerate_threads()
        if thread.name == "aoi-file-governance-git-reader"
    }


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _recording_sleep_process(
    monkeypatch: pytest.MonkeyPatch,
    child_pid_file: Path,
    *,
    interruption: KeyboardInterrupt | None = None,
) -> list[subprocess.Popen[bytes]]:
    spawned: list[subprocess.Popen[bytes]] = []
    real_popen = subprocess.Popen

    def replacement(
        command: object,
        **kwargs: Any,
    ) -> subprocess.Popen[bytes]:
        del command
        process = real_popen(
            [sys.executable, "-B", "-c", _SLEEPING_PROCESS_TREE, child_pid_file],
            **kwargs,
        )
        if interruption is not None:
            real_wait = process.wait
            wait_calls = 0

            def wait_once(timeout: float | None = None) -> int:
                nonlocal wait_calls
                wait_calls += 1
                if wait_calls == 1:
                    deadline = time.monotonic() + 3
                    while (
                        not child_pid_file.exists()
                        and time.monotonic() < deadline
                    ):
                        time.sleep(0.01)
                    raise interruption
                return real_wait(timeout=timeout)

            monkeypatch.setattr(process, "wait", wait_once)
        spawned.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", replacement)
    return spawned


class _FunctionProxy:
    def __init__(
        self,
        target: Any,
        override: Callable[..., Any],
    ) -> None:
        self._target = target
        self._override = override

    @property
    def argtypes(self) -> object:
        return self._target.argtypes

    @argtypes.setter
    def argtypes(self, value: object) -> None:
        self._target.argtypes = value

    @property
    def restype(self) -> object:
        return self._target.restype

    @restype.setter
    def restype(self, value: object) -> None:
        self._target.restype = value

    def __call__(self, *args: object) -> Any:
        return self._override(*args)


class _KernelProxy:
    def __init__(
        self,
        target: Any,
        name: str,
        override: Callable[..., Any],
    ) -> None:
        self._target = target
        self._name = name
        self._override = _FunctionProxy(getattr(target, name), override)

    def __getattr__(self, name: str) -> Any:
        if name == self._name:
            return self._override
        return getattr(self._target, name)


def _patch_kernel(
    monkeypatch: pytest.MonkeyPatch,
    function_name: str,
    override: Callable[..., Any],
) -> None:
    win_dll = getattr(ctypes, "WinDLL")
    real_kernel = win_dll("kernel32", use_last_error=True)
    proxy = _KernelProxy(real_kernel, function_name, override)

    def replacement(
        name: str,
        *,
        use_last_error: bool = False,
    ) -> _KernelProxy:
        del name, use_last_error
        return proxy

    monkeypatch.setattr(ctypes, "WinDLL", replacement)


def test_git_reader_timeout_quiesces_process_tree_and_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_pid_file = tmp_path / "child.pid"
    readers_before = _reader_thread_ids()
    spawned = _recording_sleep_process(monkeypatch, child_pid_file)
    started = time.monotonic()
    with pytest.raises(FileGovernanceError, match="timed out"):
        _run_git(
            tmp_path,
            ("rev-parse", "--verify", "1" * 40 + "^{commit}"),
            timeout=1,
            output_limit=1024,
        )
    child_pid = int(child_pid_file.read_text(encoding="ascii"))
    assert time.monotonic() - started < 4
    assert len(spawned) == 1 and spawned[0].poll() is not None
    assert not _pid_alive(child_pid)
    assert _reader_thread_ids() == readers_before


def test_git_reader_baseexception_quiesces_process_tree_and_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_pid_file = tmp_path / "child.pid"
    interruption = KeyboardInterrupt("synthetic cancellation")
    readers_before = _reader_thread_ids()
    spawned = _recording_sleep_process(
        monkeypatch,
        child_pid_file,
        interruption=interruption,
    )
    started = time.monotonic()
    with pytest.raises(KeyboardInterrupt) as caught:
        _run_git(
            tmp_path,
            ("rev-parse", "--verify", "1" * 40 + "^{commit}"),
            timeout=10,
            output_limit=1024,
        )
    child_pid = int(child_pid_file.read_text(encoding="ascii"))
    assert caught.value is interruption
    assert time.monotonic() - started < 4
    assert len(spawned) == 1 and spawned[0].poll() is not None
    assert not _pid_alive(child_pid)
    assert _reader_thread_ids() == readers_before


def test_git_reader_rejects_alias_before_process_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_popen(*args: object, **kwargs: object) -> object:
        raise AssertionError("unsupported Git argv reached Popen")

    monkeypatch.setattr(subprocess, "Popen", forbidden_popen)
    with pytest.raises(FileGovernanceError, match="unsupported"):
        _run_git(tmp_path, ("spawn-child",), timeout=1, output_limit=1024)


def test_reader_reports_overflow_and_main_owns_process_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spawned = []
    terminate_threads: list[str] = []
    readers_before = _reader_thread_ids()
    real_spawn = spawn_git_process

    def spawn_overflow(command: Sequence[str]) -> Any:
        del command
        tree = real_spawn([sys.executable, "-B", "-c", _OVERFLOW_WORKLOAD])
        real_terminate = tree.terminate

        def record_terminate() -> None:
            terminate_threads.append(current_thread().name)
            real_terminate()

        tree.terminate = record_terminate
        spawned.append(tree)
        return tree

    monkeypatch.setattr(governance_io, "spawn_git_process", spawn_overflow)
    with pytest.raises(FileGovernanceError, match="failed"):
        _run_git(
            tmp_path,
            ("rev-parse", "--verify", "1" * 40 + "^{commit}"),
            timeout=10,
            output_limit=64,
        )
    assert terminate_threads == [current_thread().name]
    assert len(spawned) == 1 and spawned[0].process.poll() is not None
    assert _reader_thread_ids() == readers_before


@pytest.mark.skipif(os.name != "nt", reason="Windows Job contract")
@pytest.mark.parametrize(
    "failure_name",
    ("OpenProcess", "AssignProcessToJobObject"),
)
def test_windows_launch_setup_failure_never_releases_workload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_name: str,
) -> None:
    marker = tmp_path / "workload-ran"
    spawned: list[subprocess.Popen[bytes]] = []
    real_popen = subprocess.Popen

    def record_popen(
        command: Sequence[str],
        **kwargs: Any,
    ) -> subprocess.Popen[bytes]:
        process = real_popen(command, **kwargs)
        spawned.append(process)
        return process

    def fail(*args: object) -> int:
        del args
        ctypes.set_last_error(5)
        return 0

    monkeypatch.setattr(subprocess, "Popen", record_popen)
    _patch_kernel(monkeypatch, failure_name, fail)
    started = time.monotonic()
    with pytest.raises(OSError):
        spawn_git_process(
            [sys.executable, "-B", "-c", _MARKER_WORKLOAD, str(marker)]
        )
    assert time.monotonic() - started < 4
    assert len(spawned) == 1 and spawned[0].poll() is not None
    assert spawned[0].stdin is not None and spawned[0].stdin.closed
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows Job contract")
def test_windows_launch_barrier_binds_before_workload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "workload-ran"
    observed_before_bind: list[bool] = []
    win_dll = getattr(ctypes, "WinDLL")
    real_kernel = win_dll("kernel32", use_last_error=True)
    real_assign = real_kernel.AssignProcessToJobObject

    def observe_and_assign(*args: object) -> Any:
        observed_before_bind.append(marker.exists())
        return real_assign(*args)

    _patch_kernel(
        monkeypatch,
        "AssignProcessToJobObject",
        observe_and_assign,
    )
    tree = spawn_git_process(
        [sys.executable, "-B", "-c", _MARKER_WORKLOAD, str(marker)]
    )
    assert tree.process.wait(timeout=5) == 0
    assert quiesce_git_process(tree, None) is None
    if tree.process.stdout is not None:
        tree.process.stdout.close()
    assert observed_before_bind == [False]
    assert marker.read_text(encoding="ascii") == "ran"


@pytest.mark.skipif(os.name != "nt", reason="Windows Job contract")
def test_windows_terminate_failure_closes_job_before_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_pid_file = tmp_path / "child.pid"
    readers_before = _reader_thread_ids()

    def fail_terminate(*args: object) -> int:
        del args
        ctypes.set_last_error(5)
        return 0

    _patch_kernel(monkeypatch, "TerminateJobObject", fail_terminate)
    tree = spawn_git_process(
        [sys.executable, "-B", "-c", _SLEEPING_PROCESS_TREE, str(child_pid_file)]
    )
    assert tree.process.stdout is not None

    def drain() -> None:
        assert tree.process.stdout is not None
        try:
            tree.process.stdout.read()
        finally:
            tree.process.stdout.close()

    reader = Thread(
        target=drain,
        name="aoi-file-governance-git-reader",
        daemon=True,
    )
    reader.start()
    deadline = time.monotonic() + 3
    while not child_pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    child_pid = int(child_pid_file.read_text(encoding="ascii"))
    started = time.monotonic()
    assert quiesce_git_process(tree, reader) is None
    assert time.monotonic() - started < 4
    assert tree.process.poll() is not None and not reader.is_alive()
    assert not _pid_alive(child_pid)
    assert _reader_thread_ids() == readers_before


@pytest.mark.skipif(os.name != "nt", reason="Windows Job contract")
def test_run_git_terminate_failure_preserves_timeout_after_quiescence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_pid_file = tmp_path / "child.pid"
    readers_before = _reader_thread_ids()
    spawned = []
    real_spawn = spawn_git_process

    def fail_terminate(*args: object) -> int:
        del args
        ctypes.set_last_error(5)
        return 0

    def spawn_sleeping(command: Sequence[str]) -> Any:
        del command
        tree = real_spawn([
            sys.executable, "-B", "-c", _SLEEPING_PROCESS_TREE, str(child_pid_file),
        ])
        spawned.append(tree)
        return tree

    _patch_kernel(monkeypatch, "TerminateJobObject", fail_terminate)
    monkeypatch.setattr(governance_io, "spawn_git_process", spawn_sleeping)
    with pytest.raises(FileGovernanceError, match="timed out"):
        _run_git(
            tmp_path,
            ("rev-parse", "--verify", "1" * 40 + "^{commit}"),
            timeout=1,
            output_limit=1024,
        )
    child_pid = int(child_pid_file.read_text(encoding="ascii"))
    assert len(spawned) == 1 and spawned[0].process.poll() is not None
    assert not _pid_alive(child_pid)
    assert _reader_thread_ids() == readers_before


def test_run_git_surfaces_unproved_cleanup_with_primary_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_pid_file = tmp_path / "child.pid"
    spawned = _recording_sleep_process(monkeypatch, child_pid_file)
    real_quiesce = quiesce_git_process

    def report_cleanup_failure(tree: Any, reader: Thread | None) -> OSError:
        assert real_quiesce(tree, reader) is None
        return OSError(5, "synthetic cleanup receipt failure")

    monkeypatch.setattr(
        governance_io,
        "quiesce_git_process",
        report_cleanup_failure,
    )
    with pytest.raises(
        governance_io.GitProcessTreeCleanupError,
        match="cleanup failed",
    ) as caught:
        _run_git(
            tmp_path,
            ("rev-parse", "--verify", "1" * 40 + "^{commit}"),
            timeout=1,
            output_limit=1024,
        )
    assert isinstance(caught.value.primary_error, subprocess.TimeoutExpired)
    assert isinstance(caught.value.cleanup_error, OSError)
    child_pid = int(child_pid_file.read_text(encoding="ascii"))
    assert len(spawned) == 1 and spawned[0].poll() is not None
    assert not _pid_alive(child_pid)
