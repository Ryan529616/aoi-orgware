"""Bounded cross-platform process-tree lifecycle for Git observations."""

from __future__ import annotations

from collections.abc import Sequence
import os
import signal
import subprocess
import sys
from threading import Thread
import time
from typing import Callable, cast


PROCESS_TREE_CLEANUP_SECONDS = 5.0
_WINDOWS_JOB_SHIM = (
    "import subprocess,sys;"
    "token=sys.stdin.buffer.read(1);"
    "sys.stdin.close();"
    "raise SystemExit(125 if token!=b'G' else "
    "subprocess.call(sys.argv[1:],stdin=subprocess.DEVNULL))"
)


class GitProcessTree:
    def __init__(
        self,
        process: subprocess.Popen[bytes],
        *,
        terminate: Callable[[], None],
        active: Callable[[], bool],
        close: Callable[[], None],
        close_terminates_tree: bool,
    ) -> None:
        self.process = process
        self.terminate = terminate
        self.active = active
        self.close = close
        self.close_terminates_tree = close_terminates_tree


def _spawn_posix(command: Sequence[str]) -> GitProcessTree:
    kill_group = cast(Callable[[int, int], None], getattr(os, "killpg"))
    kill_signal = cast(int, getattr(signal, "SIGKILL"))
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    process_group = process.pid

    def terminate() -> None:
        try:
            kill_group(process_group, kill_signal)
        except ProcessLookupError:
            pass

    def active() -> bool:
        try:
            kill_group(process_group, 0)
        except ProcessLookupError:
            return False
        return True

    return GitProcessTree(
        process,
        terminate=terminate,
        active=active,
        close=lambda: None,
        close_terminates_tree=False,
    )


def _spawn_windows(command: Sequence[str]) -> GitProcessTree:
    import ctypes
    from ctypes import wintypes

    job_kill_on_close = 0x00002000
    job_extended_limits = 9
    job_basic_accounting = 1
    process_set_quota_terminate = 0x00000101

    class BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimits),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class BasicAccounting(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTime", ctypes.c_longlong),
            ("PerJobUserTime", ctypes.c_longlong),
            ("ThisPeriodTotalUserTime", ctypes.c_longlong),
            ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
            ("TotalPageFaultCount", wintypes.DWORD),
            ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD),
            ("TotalTerminatedProcesses", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = (
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    )
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = (
        wintypes.HANDLE, wintypes.HANDLE,
    )
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.QueryInformationJobObject.argtypes = (
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
        wintypes.DWORD, ctypes.c_void_p,
    )
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = (
        wintypes.DWORD, wintypes.BOOL, wintypes.DWORD,
    )
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
    process: subprocess.Popen[bytes] | None = None
    assigned = False
    job_open = True

    def close_handle(handle: int) -> None:
        if handle and not kernel32.CloseHandle(handle):
            raise OSError(ctypes.get_last_error(), "CloseHandle failed")

    def close_job() -> None:
        nonlocal job_open
        if job_open:
            close_handle(job)
            job_open = False

    def terminate_job() -> None:
        if not kernel32.TerminateJobObject(job, 1):
            raise OSError(ctypes.get_last_error(), "TerminateJobObject failed")

    try:
        limits = ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = job_kill_on_close
        if not kernel32.SetInformationJobObject(
            job,
            job_extended_limits,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            raise OSError(
                ctypes.get_last_error(),
                "SetInformationJobObject failed",
            )
        process = subprocess.Popen(
            [
                sys.executable, "-I", "-S", "-B", "-c",
                _WINDOWS_JOB_SHIM, *command,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        process_handle = kernel32.OpenProcess(
            process_set_quota_terminate,
            False,
            process.pid,
        )
        if not process_handle:
            raise OSError(ctypes.get_last_error(), "OpenProcess failed")
        try:
            if not kernel32.AssignProcessToJobObject(job, process_handle):
                raise OSError(
                    ctypes.get_last_error(),
                    "AssignProcessToJobObject failed",
                )
            assigned = True
        finally:
            close_handle(process_handle)
        if process.stdin is None:
            raise OSError(0, "Git launch barrier pipe is unavailable")
        process.stdin.write(b"G")
        process.stdin.flush()
        process.stdin.close()
    except BaseException as primary:
        cleanup_errors: list[BaseException] = []
        if process is not None:
            try:
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()
            except BaseException as exc:
                cleanup_errors.append(exc)
            if assigned:
                try:
                    terminate_job()
                except BaseException as exc:
                    cleanup_errors.append(exc)
            try:
                process.kill()
            except BaseException as exc:
                cleanup_errors.append(exc)
        try:
            close_job()
        except BaseException as exc:
            cleanup_errors.append(exc)
        if process is not None:
            try:
                process.wait(timeout=PROCESS_TREE_CLEANUP_SECONDS)
            except BaseException as exc:
                cleanup_errors.append(exc)
            if process.stdout is not None:
                try:
                    process.stdout.close()
                except BaseException as exc:
                    cleanup_errors.append(exc)
        for cleanup_error in cleanup_errors:
            primary.add_note(
                f"Git launch-barrier cleanup failed: "
                f"{type(cleanup_error).__name__}"
            )
        raise primary

    def active() -> bool:
        accounting = BasicAccounting()
        if not kernel32.QueryInformationJobObject(
            job,
            job_basic_accounting,
            ctypes.byref(accounting),
            ctypes.sizeof(accounting),
            None,
        ):
            raise OSError(
                ctypes.get_last_error(),
                "QueryInformationJobObject failed",
            )
        return bool(accounting.ActiveProcesses)

    return GitProcessTree(
        process,
        terminate=terminate_job,
        active=active,
        close=close_job,
        close_terminates_tree=True,
    )


def spawn_git_process(command: Sequence[str]) -> GitProcessTree:
    if os.name == "nt":
        return _spawn_windows(command)
    return _spawn_posix(command)


def quiesce_git_process(
    tree: GitProcessTree,
    reader: Thread | None,
) -> BaseException | None:
    deadline = time.monotonic() + PROCESS_TREE_CLEANUP_SECONDS
    first_error: BaseException | None = None
    close_error: BaseException | None = None
    closed = False
    try:
        tree.terminate()
    except BaseException:
        pass
    try:
        tree.close()
        closed = True
    except BaseException as exc:
        close_error = exc
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            first_error = TimeoutError("Git process did not stop")
            break
        try:
            tree.process.wait(timeout=remaining)
            break
        except subprocess.TimeoutExpired as exc:
            first_error = exc
            break
        except BaseException as exc:
            if first_error is None:
                first_error = exc
            time.sleep(min(0.01, max(0.0, remaining)))
    if reader is not None:
        reader_alive = True
        while time.monotonic() < deadline:
            try:
                reader_alive = reader.is_alive()
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
                break
            if not reader_alive:
                break
            try:
                reader.join(timeout=max(0.0, deadline - time.monotonic()))
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
        try:
            reader_alive = reader.is_alive()
        except BaseException as exc:
            if first_error is None:
                first_error = exc
            reader_alive = True
        if reader_alive and first_error is None:
            first_error = TimeoutError("Git reader did not stop")
    if not (closed and tree.close_terminates_tree):
        while time.monotonic() < deadline:
            try:
                if not tree.active():
                    break
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
                break
            time.sleep(0.01)
        else:
            if first_error is None:
                first_error = TimeoutError("Git process tree did not stop")
    if not closed:
        try:
            tree.close()
            closed = True
            close_error = None
        except BaseException as exc:
            close_error = exc
    return first_error if first_error is not None else close_error


__all__ = [
    "GitProcessTree",
    "PROCESS_TREE_CLEANUP_SECONDS",
    "quiesce_git_process",
    "spawn_git_process",
]
