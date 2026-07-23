"""Codex onboarding helpers for ``aoi codex-init``.

The module owns only client-side, repository-local wiring: Codex lifecycle
hooks, the hook feature flag, and the AOI repository skill.  It preserves
unrelated user configuration and never edits global ``CODEX_HOME`` state or
marks a hook trusted on the user's behalf.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import platform
import re
import secrets
import shlex
import stat
import tomllib
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, cast


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset({"codex_init"})

HOOK_COMMAND_HEAD = "aoi-codex-hook"
HOOK_TIMEOUT_SECONDS = 30
SESSION_START_MATCHER = "startup|resume|clear|compact"
CODEX_HOOK_EVENTS = (
    "SessionStart",
    "UserPromptSubmit",
    "SubagentStart",
    "SubagentStop",
    "PreToolUse",
    "PostToolUse",
    "Stop",
)
_STATUS_MESSAGES = {
    "SessionStart": "Loading AOI state",
    "UserPromptSubmit": "Checking AOI task binding",
    "SubagentStart": "Loading AOI packet contract",
    "SubagentStop": "Checking AOI subagent completion",
    "PreToolUse": "Checking AOI claim gate",
    "PostToolUse": "Recording AOI tool receipt",
    "Stop": "Checking AOI checkpoint state",
}
_SHA256_HEX = frozenset("0123456789abcdef")
_MAX_ONBOARDING_TEXT_BYTES = 1024 * 1024
_UNSET = object()
# Tests may replace this narrowly-scoped hook to force a parent-path switch
# during the pre-publication critical section.
_atomic_publish_test_hook: Callable[[Path], None] | None = None


class CodexOnboardingError(Exception):
    """Raised when repository-local Codex configuration is unsafe to merge."""


def _windows_api(ctypes_module: Any, name: str) -> Any:
    """Return a Windows-only ``ctypes`` API without importing platform stubs.

    The callers are reached only from the Windows publication path.  Looking up
    these APIs dynamically keeps POSIX static analysis honest while retaining
    the existing fail-closed behaviour if the required Windows primitive is
    unavailable at runtime.
    """

    value = getattr(ctypes_module, name, None)
    if value is None:
        raise OSError(f"required Windows ctypes API is unavailable: {name}")
    return value


def _windows_dll(ctypes_module: Any, name: str) -> Any:
    return _windows_api(ctypes_module, "WinDLL")(name, use_last_error=True)


def _windows_last_error(ctypes_module: Any) -> int:
    return int(_windows_api(ctypes_module, "get_last_error")())


def _windows_error_message(ctypes_module: Any, error: int) -> str:
    windows_error = _windows_api(ctypes_module, "WinError")(error)
    message = getattr(windows_error, "strerror", None)
    return message if isinstance(message, str) else str(windows_error)


def _absolute_path(path: Path | str | os.PathLike[str], label: str) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise CodexOnboardingError(f"{label} must be an absolute path")
    # ``resolve`` would follow exactly the aliases this boundary must reject.
    return Path(os.path.abspath(os.fspath(candidate)))


def _is_reparse_point(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return os.path.samestat(left, right)


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CodexOnboardingError(f"cannot inspect {path}: {exc}") from exc


def _require_safe_directory(path: Path, metadata: os.stat_result) -> None:
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        raise CodexOnboardingError(f"unsafe linked directory in Codex path: {path}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise CodexOnboardingError(f"Codex path parent is not a directory: {path}")


def _require_safe_regular_file(path: Path, metadata: os.stat_result) -> None:
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        raise CodexOnboardingError(f"unsafe linked Codex file: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise CodexOnboardingError(f"Codex target is not a regular file: {path}")


def _directory_components(path: Path) -> tuple[Path, tuple[str, ...]]:
    anchor = Path(path.anchor)
    if not path.anchor:
        raise CodexOnboardingError(f"Codex path has no filesystem anchor: {path}")
    try:
        return anchor, path.relative_to(anchor).parts
    except ValueError as exc:
        raise CodexOnboardingError(f"cannot inspect Codex path: {path}") from exc


def _audit_directory_chain(path: Path, *, create_missing: bool) -> os.stat_result | None:
    """Reject every existing linked parent; optionally create safe gaps.

    The audit intentionally starts at the filesystem anchor instead of resolving
    the requested path.  This keeps a repo ``.codex`` or user skill root from
    escaping through any existing symlink, junction, or other reparse point.
    """

    path = _absolute_path(path, "Codex path")
    current, components = _directory_components(path)
    root_metadata = _lstat(current)
    if root_metadata is None:
        raise CodexOnboardingError(f"Codex filesystem anchor is missing: {current}")
    _require_safe_directory(current, root_metadata)
    latest = root_metadata
    created_any = False
    for component in components:
        current /= component
        metadata = _lstat(current)
        if metadata is None:
            if not create_missing:
                return None
            try:
                current.mkdir()
                created_any = True
            except FileExistsError:
                pass
            except OSError as exc:
                raise CodexOnboardingError(
                    f"cannot create Codex directory {current}: {exc}"
                ) from exc
            metadata = _lstat(current)
            if metadata is None:
                raise CodexOnboardingError(
                    f"Codex directory disappeared after creation: {current}"
                )
        _require_safe_directory(current, metadata)
        latest = metadata
    if created_any:
        # Creation is not itself proof that no concurrent replacement turned a
        # parent into a link.  Walk the complete established chain once more.
        revalidated = _audit_directory_chain(path, create_missing=False)
        if revalidated is None:
            raise CodexOnboardingError(
                f"Codex directory disappeared after creation: {path}"
            )
        return revalidated
    return latest


def _safe_leaf_snapshot(path: Path) -> os.stat_result | None:
    metadata = _lstat(path)
    if metadata is not None:
        _require_safe_regular_file(path, metadata)
    return metadata


def _same_leaf_snapshot(
    expected: os.stat_result | None | object,
    current: os.stat_result | None,
) -> bool:
    return expected is _UNSET or (
        (expected is None) == (current is None)
        and (
            expected is None
            or current is None
            or _same_identity(cast(os.stat_result, expected), current)
        )
    )


def _run_atomic_publish_test_hook(path: Path) -> None:
    if _atomic_publish_test_hook is not None:
        _atomic_publish_test_hook(path)


def _posix_atomic_publish_supported() -> bool:
    return (
        os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.rename in os.supports_dir_fd
    )


def _windows_atomic_publish_supported() -> bool:
    """Check native handle-relative primitives before any target mutation."""

    try:
        import ctypes
        import msvcrt  # noqa: F401

        kernel32 = _windows_dll(ctypes, "kernel32")
        ntdll = _windows_dll(ctypes, "ntdll")
    except (AttributeError, ImportError, OSError):
        return False
    return all(
        hasattr(kernel32, name)
        for name in ("CreateFileW", "DuplicateHandle", "FlushFileBuffers", "WriteFile")
    ) and all(
        hasattr(ntdll, name)
        for name in ("NtCreateFile", "NtSetInformationFile", "RtlNtStatusToDosError")
    )


def _posix_open_verified_directory(path: Path, expected: os.stat_result) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CodexOnboardingError(f"cannot open Codex target parent {path}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        _require_safe_directory(path, opened)
        if not _same_identity(expected, opened):
            raise CodexOnboardingError(f"Codex target parent changed before publish: {path}")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _posix_leaf_snapshot(directory_fd: int, name: str, label: Path) -> os.stat_result | None:
    try:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CodexOnboardingError(f"cannot inspect {label}: {exc}") from exc
    _require_safe_regular_file(label, metadata)
    return metadata


def _posix_create_temporary(directory_fd: int, target_name: str) -> tuple[int, str]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    for _ in range(128):
        name = f".{target_name}.aoi-{secrets.token_hex(16)}.tmp"
        try:
            return os.open(name, flags, 0o600, dir_fd=directory_fd), name
        except FileExistsError:
            continue
        except OSError as exc:
            raise CodexOnboardingError(f"cannot create Codex temporary for {target_name}: {exc}") from exc
    raise CodexOnboardingError(f"cannot allocate unique Codex temporary for {target_name}")


def _atomic_write_text_posix(
    path: Path,
    text: str,
    *,
    parent_metadata: os.stat_result,
    expected_leaf: os.stat_result | None | object,
) -> None:
    """Use openat/renameat so publication cannot chase a replaced parent."""

    directory_fd = _posix_open_verified_directory(path.parent, parent_metadata)
    temporary_fd: int | None = None
    temporary_name: str | None = None
    published = False
    try:
        initial_leaf = _posix_leaf_snapshot(directory_fd, path.name, path)
        if not _same_leaf_snapshot(expected_leaf, initial_leaf):
            raise CodexOnboardingError(f"{path} changed after Codex preflight")
        temporary_fd, temporary_name = _posix_create_temporary(directory_fd, path.name)
        try:
            encoded = text.encode("utf-8")
            with os.fdopen(temporary_fd, "wb", closefd=False) as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            temporary_metadata = os.fstat(temporary_fd)
            _require_safe_regular_file(Path(temporary_name), temporary_metadata)
            current_leaf = _posix_leaf_snapshot(directory_fd, path.name, path)
            if not _same_leaf_snapshot(expected_leaf, current_leaf):
                raise CodexOnboardingError(f"{path} changed before Codex publish")
            current_temporary = _posix_leaf_snapshot(
                directory_fd, temporary_name, Path(temporary_name)
            )
            if current_temporary is None or not _same_identity(
                temporary_metadata, current_temporary
            ):
                raise CodexOnboardingError(
                    f"Codex temporary changed before publish: {temporary_name}"
                )
            _run_atomic_publish_test_hook(path)
            # POSIX renameat atomically replaces the destination when present.
            os.rename(
                temporary_name,
                path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            published = True
            os.fsync(directory_fd)
        finally:
            os.close(temporary_fd)
            temporary_fd = None
    finally:
        if temporary_name is not None and not published:
            try:
                temporary = _posix_leaf_snapshot(
                    directory_fd, temporary_name, Path(temporary_name)
                )
                if temporary is not None:
                    os.unlink(temporary_name, dir_fd=directory_fd)
            except (CodexOnboardingError, OSError):
                pass
        os.close(directory_fd)


def _windows_nt_create_relative(
    directory_handle: int,
    name: str,
    *,
    desired_access: int,
    disposition: int,
    options: int,
) -> int:
    """Open a relative leaf through an already verified Windows directory handle."""

    import ctypes
    from ctypes import wintypes

    class unicode_string(ctypes.Structure):
        _fields_ = (
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", wintypes.LPWSTR),
        )

    class object_attributes(ctypes.Structure):
        _fields_ = (
            ("Length", wintypes.ULONG),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(unicode_string)),
            ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", ctypes.c_void_p),
            ("SecurityQualityOfService", ctypes.c_void_p),
        )

    class io_status_block_union(ctypes.Union):
        _fields_ = (("Status", ctypes.c_long), ("Pointer", ctypes.c_void_p))

    class io_status_block(ctypes.Structure):
        _anonymous_ = ("u",)
        _fields_ = (("u", io_status_block_union), ("Information", ctypes.c_size_t))

    name_buffer = ctypes.create_unicode_buffer(name)
    encoded_name = name.encode("utf-16-le")
    unicode = unicode_string(
        len(encoded_name), len(encoded_name), ctypes.cast(name_buffer, wintypes.LPWSTR)
    )
    attributes = object_attributes(
        ctypes.sizeof(object_attributes),
        wintypes.HANDLE(directory_handle),
        ctypes.pointer(unicode),
        0,
        None,
        None,
    )
    status_block = io_status_block()
    handle = wintypes.HANDLE()
    ntdll = _windows_dll(ctypes, "ntdll")
    create = ntdll.NtCreateFile
    create.argtypes = (
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.ULONG,
        ctypes.POINTER(object_attributes),
        ctypes.POINTER(io_status_block),
        ctypes.c_void_p,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.c_void_p,
        wintypes.ULONG,
    )
    create.restype = ctypes.c_long
    status = create(
        ctypes.byref(handle),
        desired_access,
        ctypes.byref(attributes),
        ctypes.byref(status_block),
        None,
        0x80,  # FILE_ATTRIBUTE_NORMAL
        0x00000007,  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        disposition,
        options,
        None,
        0,
    )
    if status < 0:
        rtl_status_to_dos = ntdll.RtlNtStatusToDosError
        rtl_status_to_dos.argtypes = (ctypes.c_long,)
        rtl_status_to_dos.restype = wintypes.ULONG
        error = rtl_status_to_dos(status)
        raise OSError(error, _windows_error_message(ctypes, error))
    return _windows_handle_value(handle)


def _windows_handle_value(handle: Any) -> int:
    value = getattr(handle, "value", handle)
    if value is None:
        raise OSError("Windows returned a null file handle")
    return int(value)


def _windows_close_handle(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    close = _windows_dll(ctypes, "kernel32").CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    if not close(wintypes.HANDLE(handle)):
        error = _windows_last_error(ctypes)
        raise OSError(error, _windows_error_message(ctypes, error))


def _windows_handle_snapshot(handle: int) -> os.stat_result:
    """Return a Python stat snapshot without surrendering the supplied handle."""

    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = _windows_dll(ctypes, "kernel32")
    duplicate = wintypes.HANDLE()
    duplicate_handle = kernel32.DuplicateHandle
    duplicate_handle.argtypes = (
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    )
    duplicate_handle.restype = wintypes.BOOL
    current_process = kernel32.GetCurrentProcess()
    if not duplicate_handle(
        current_process,
        wintypes.HANDLE(handle),
        current_process,
        ctypes.byref(duplicate),
        0,
        False,
        0x00000002,  # DUPLICATE_SAME_ACCESS
    ):
        error = _windows_last_error(ctypes)
        raise OSError(error, _windows_error_message(ctypes, error))
    try:
        descriptor = cast(Any, msvcrt).open_osfhandle(
            _windows_handle_value(duplicate), os.O_RDONLY | getattr(os, "O_BINARY", 0)
        )
    except OSError:
        _windows_close_handle(_windows_handle_value(duplicate))
        raise
    try:
        return os.fstat(descriptor)
    finally:
        os.close(descriptor)


def _windows_open_verified_directory(path: Path, expected: os.stat_result) -> int:
    import ctypes
    from ctypes import wintypes

    kernel32 = _windows_dll(ctypes, "kernel32")
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        0x00000001 | 0x00000002 | 0x00000020 | 0x00000080 | 0x00100000,
        # LIST_DIRECTORY | ADD_FILE | TRAVERSE | READ_ATTRIBUTES | SYNCHRONIZE
        0x00000007,
        None,
        3,  # OPEN_EXISTING
        0x02000000 | 0x00200000,  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        None,
    )
    if _windows_handle_value(handle) == ctypes.c_void_p(-1).value:
        error = _windows_last_error(ctypes)
        raise CodexOnboardingError(
            f"cannot open Codex target parent {path}: {_windows_error_message(ctypes, error)}"
        )
    try:
        opened = _windows_handle_snapshot(_windows_handle_value(handle))
        _require_safe_directory(path, opened)
        if not _same_identity(expected, opened):
            raise CodexOnboardingError(f"Codex target parent changed before publish: {path}")
        return _windows_handle_value(handle)
    except Exception:
        _windows_close_handle(_windows_handle_value(handle))
        raise


def _windows_relative_leaf_snapshot(
    directory_handle: int, name: str, label: Path
) -> os.stat_result | None:
    try:
        handle = _windows_nt_create_relative(
            directory_handle,
            name,
            desired_access=0x00000080 | 0x00100000,  # READ_ATTRIBUTES | SYNCHRONIZE
            disposition=1,  # FILE_OPEN
            options=0x00000040 | 0x00000020 | 0x00200000,
        )
    except OSError as exc:
        if exc.errno in {2, 3}:
            return None
        raise CodexOnboardingError(f"cannot inspect {label}: {exc}") from exc
    try:
        metadata = _windows_handle_snapshot(handle)
        _require_safe_regular_file(label, metadata)
        return metadata
    finally:
        _windows_close_handle(handle)


def _windows_write_and_flush(handle: int, raw: bytes) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = _windows_dll(ctypes, "kernel32")
    write = kernel32.WriteFile
    write.argtypes = (
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    )
    write.restype = wintypes.BOOL
    buffer = ctypes.create_string_buffer(raw)
    written = wintypes.DWORD()
    if not write(
        wintypes.HANDLE(handle), buffer, len(raw), ctypes.byref(written), None
    ) or written.value != len(raw):
        error = _windows_last_error(ctypes)
        raise CodexOnboardingError(
            f"cannot write Codex temporary: {_windows_error_message(ctypes, error)}"
        )
    flush = kernel32.FlushFileBuffers
    flush.argtypes = (wintypes.HANDLE,)
    flush.restype = wintypes.BOOL
    if not flush(wintypes.HANDLE(handle)):
        error = _windows_last_error(ctypes)
        raise CodexOnboardingError(
            f"cannot fsync Codex temporary: {_windows_error_message(ctypes, error)}"
        )


def _windows_rename_relative(
    source_handle: int, directory_handle: int, target_name: str
) -> None:
    import ctypes
    from ctypes import wintypes

    class file_rename_info(ctypes.Structure):
        _fields_ = (
            ("ReplaceIfExists", wintypes.BOOL),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.DWORD),
            ("FileName", wintypes.WCHAR * 1),
        )

    encoded_name = target_name.encode("utf-16-le")
    # Win32 documents this as ``sizeof(FILE_RENAME_INFO) + FileNameLength``;
    # retain the ABI tail padding rather than truncating at FileName.offset.
    size = ctypes.sizeof(file_rename_info) + len(encoded_name)
    buffer = ctypes.create_string_buffer(size)
    info = ctypes.cast(buffer, ctypes.POINTER(file_rename_info)).contents
    info.ReplaceIfExists = True
    info.RootDirectory = wintypes.HANDLE(directory_handle)
    info.FileNameLength = len(encoded_name)
    ctypes.memmove(
        ctypes.addressof(buffer) + file_rename_info.FileName.offset,
        encoded_name,
        len(encoded_name),
    )
    class io_status_block_union(ctypes.Union):
        _fields_ = (("Status", ctypes.c_long), ("Pointer", ctypes.c_void_p))

    class io_status_block(ctypes.Structure):
        _anonymous_ = ("u",)
        _fields_ = (("u", io_status_block_union), ("Information", ctypes.c_size_t))

    status_block = io_status_block()
    ntdll = _windows_dll(ctypes, "ntdll")
    set_information = ntdll.NtSetInformationFile
    set_information.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(io_status_block),
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    set_information.restype = ctypes.c_long
    status = set_information(
        wintypes.HANDLE(source_handle),
        ctypes.byref(status_block),
        buffer,
        size,
        10,  # FileRenameInformation
    )
    if status < 0:
        status_to_dos = ntdll.RtlNtStatusToDosError
        status_to_dos.argtypes = (ctypes.c_long,)
        status_to_dos.restype = wintypes.ULONG
        error = status_to_dos(status)
        raise CodexOnboardingError(
            f"cannot publish Codex target: {_windows_error_message(ctypes, error)}"
        )


def _windows_delete_open_file(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    delete = wintypes.BOOL(True)
    set_information = _windows_dll(ctypes, "kernel32").SetFileInformationByHandle
    set_information.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    set_information.restype = wintypes.BOOL
    if not set_information(
        wintypes.HANDLE(handle), 4, ctypes.byref(delete), ctypes.sizeof(delete)
    ):
        error = _windows_last_error(ctypes)
        raise OSError(error, _windows_error_message(ctypes, error))


def _atomic_write_text_windows(
    path: Path,
    text: str,
    *,
    parent_metadata: os.stat_result,
    expected_leaf: os.stat_result | None | object,
) -> None:
    """Publish with a directory-rooted NT create and handle-relative rename."""

    directory_handle = _windows_open_verified_directory(path.parent, parent_metadata)
    temporary_handle: int | None = None
    published = False
    try:
        initial_leaf = _windows_relative_leaf_snapshot(directory_handle, path.name, path)
        if not _same_leaf_snapshot(expected_leaf, initial_leaf):
            raise CodexOnboardingError(f"{path} changed after Codex preflight")
        # Windows prevents moving a directory with an open child file even when
        # that child shares delete access.  Exercise the adversarial switch
        # while only the stable directory handle is held; all later mutations
        # remain relative to that verified handle.
        _run_atomic_publish_test_hook(path)
        for _ in range(128):
            try:
                temporary_handle = _windows_nt_create_relative(
                    directory_handle,
                    f".{path.name}.aoi-{secrets.token_hex(16)}.tmp",
                    desired_access=0x40000000 | 0x00010000 | 0x00000080 | 0x00100000,
                    disposition=2,  # FILE_CREATE
                    options=0x00000040 | 0x00000020,
                )
                break
            except OSError as exc:
                if exc.errno != 80:  # ERROR_FILE_EXISTS
                    raise CodexOnboardingError(
                        f"cannot create Codex temporary for {path.name}: {exc}"
                    ) from exc
        if temporary_handle is None:
            raise CodexOnboardingError(f"cannot allocate unique Codex temporary for {path.name}")
        _windows_write_and_flush(temporary_handle, text.encode("utf-8"))
        temporary_metadata = _windows_handle_snapshot(temporary_handle)
        _require_safe_regular_file(path, temporary_metadata)
        current_leaf = _windows_relative_leaf_snapshot(directory_handle, path.name, path)
        if not _same_leaf_snapshot(expected_leaf, current_leaf):
            raise CodexOnboardingError(f"{path} changed before Codex publish")
        _windows_rename_relative(temporary_handle, directory_handle, path.name)
        published = True
    finally:
        if temporary_handle is not None:
            if not published:
                try:
                    _windows_delete_open_file(temporary_handle)
                except OSError:
                    pass
            try:
                _windows_close_handle(temporary_handle)
            except OSError:
                pass
        try:
            _windows_close_handle(directory_handle)
        except OSError:
            pass


def _read_safe_text(path: Path, *, label: str) -> tuple[str, os.stat_result | None]:
    """Read a bounded regular file without accepting replacement-time drift."""

    path = _absolute_path(path, label)
    if _audit_directory_chain(path.parent, create_missing=False) is None:
        return "", None
    before = _safe_leaf_snapshot(path)
    if before is None:
        return "", None
    if before.st_size > _MAX_ONBOARDING_TEXT_BYTES:
        raise CodexOnboardingError(f"{path} exceeds the Codex onboarding size bound")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CodexOnboardingError(f"cannot open {path}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        _require_safe_regular_file(path, opened)
        if not _same_identity(before, opened):
            raise CodexOnboardingError(f"{path} changed while being opened")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(_MAX_ONBOARDING_TEXT_BYTES + 1)
        if len(raw) > _MAX_ONBOARDING_TEXT_BYTES:
            raise CodexOnboardingError(f"{path} exceeds the Codex onboarding size bound")
    finally:
        os.close(descriptor)
    after = _safe_leaf_snapshot(path)
    if after is None or not _same_identity(before, after):
        raise CodexOnboardingError(f"{path} changed while being read")
    try:
        # Match ``Path.read_text``'s universal-newline behavior so the
        # replacement SHA remains stable across an existing CRLF user skill.
        return raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n"), before
    except UnicodeDecodeError as exc:
        raise CodexOnboardingError(f"cannot decode {path} as UTF-8: {exc}") from exc


def read_verified_codex_text(path: Path, *, label: str) -> str:
    """Read one Codex-owned text leaf through the onboarding identity checks."""

    text, _snapshot = _read_safe_text(path, label=label)
    return text


def _atomic_write_text(
    path: Path,
    text: str,
    *,
    expected_leaf: os.stat_result | None | object = _UNSET,
) -> None:
    """Publish through the verified parent identity, never its later pathname."""

    path = _absolute_path(path, "Codex target")
    if os.name != "nt" and not _posix_atomic_publish_supported():
        raise CodexOnboardingError(
            "this platform cannot publish Codex files through a verified directory handle"
        )
    if os.name == "nt" and not _windows_atomic_publish_supported():
        raise CodexOnboardingError(
            "Windows cannot provide safe handle-relative Codex publication"
        )
    parent_metadata = _audit_directory_chain(path.parent, create_missing=True)
    assert parent_metadata is not None
    if os.name == "nt":
        try:
            _atomic_write_text_windows(
                path,
                text,
                parent_metadata=parent_metadata,
                expected_leaf=expected_leaf,
            )
        except (AttributeError, ImportError, OSError) as exc:
            # Never fall back to a pathname replace: without the native
            # handle-relative primitives, publication must leave no target write.
            raise CodexOnboardingError(
                "Windows cannot provide safe handle-relative Codex publication"
            ) from exc
        return
    _atomic_write_text_posix(
        path,
        text,
        parent_metadata=parent_metadata,
        expected_leaf=expected_leaf,
    )


def _hook_handler(command: str, command_windows: str, event: str) -> dict[str, Any]:
    return {
        "type": "command",
        "command": command,
        "commandWindows": command_windows,
        "timeout": HOOK_TIMEOUT_SECONDS,
        "statusMessage": _STATUS_MESSAGES[event],
    }


def _aoi_hook_entry(
    event: str, *, command: str, command_windows: str
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "hooks": [_hook_handler(command, command_windows, event)]
    }
    if event == "SessionStart":
        entry["matcher"] = SESSION_START_MATCHER
    return entry


def _is_absolute_path(value: str) -> bool:
    return PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute()


def _validate_absolute_path(value: str | os.PathLike[str], label: str) -> str:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or not _is_absolute_path(raw):
        raise CodexOnboardingError(f"{label} must be an absolute path")
    if any(character in raw for character in {'"', "'", "\r", "\n", "\x00"}):
        raise CodexOnboardingError(f"{label} contains an unsafe path character")
    return raw


def _validate_digest(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or set(value) - _SHA256_HEX
    ):
        raise CodexOnboardingError(f"{label} must be a lowercase SHA-256")
    return value


def build_codex_hook_command(
    launcher: str | os.PathLike[str],
    project_root: str | os.PathLike[str],
    provenance_sha256: str,
) -> str:
    """Build the sole supported current AOI Codex hook command.

    The caller supplies paths already verified against the promoted wheel and
    project receipt.  This helper makes the persisted hook representation
    unambiguous; it deliberately never emits a PATH-resolved command.
    """

    launcher_text = _validate_absolute_path(launcher, "Codex hook launcher")
    root_text = _validate_absolute_path(project_root, "Codex project root")
    if not _executable_names(launcher_text) & {
        HOOK_COMMAND_HEAD,
        f"{HOOK_COMMAND_HEAD}.exe",
    }:
        raise CodexOnboardingError(
            "Codex hook launcher must name the aoi-codex-hook entry point"
        )
    digest = _validate_digest(provenance_sha256, "Codex provenance SHA-256")
    return (
        f'"{launcher_text}" --hook-version 6 --project-root "{root_text}" '
        f'--provenance-sha256 "{digest}"'
    )


def _validate_posix_absolute_path(
    value: str | os.PathLike[str], label: str
) -> str:
    raw = os.fspath(value)
    if (
        not isinstance(raw, str)
        or not raw
        or not PurePosixPath(raw).is_absolute()
        or any(
            character in raw
            for character in {
                '"',
                "'",
                "\\",
                "\r",
                "\n",
                "\x00",
                "$",
                "`",
                "%",
                "!",
                "^",
            }
        )
    ):
        raise CodexOnboardingError(f"{label} must be a safe absolute POSIX path")
    return raw


def _validate_windows_absolute_path(
    value: str | os.PathLike[str], label: str
) -> str:
    raw = os.fspath(value)
    if (
        not isinstance(raw, str)
        or not raw
        or not PureWindowsPath(raw).is_absolute()
        or any(
            character in raw
            for character in {'"', "'", "\r", "\n", "\x00", "$", "`", "%", "!", "^"}
        )
    ):
        raise CodexOnboardingError(f"{label} must be a safe absolute Windows path")
    return raw


def _validate_wsl_identity(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,127}", value)
        or value.startswith("-")
    ):
        raise CodexOnboardingError(f"{label} is not a safe WSL identity")
    return value


def build_codex_windows_wsl_hook_command(
    launcher: str | os.PathLike[str],
    project_root: str | os.PathLike[str],
    provenance_sha256: str,
    *,
    distribution: str,
    user: str,
) -> str:
    """Build the sole trusted Windows-to-WSL hook wrapper.

    The wrapper has no shell, PATH-resolved inner command, or caller-supplied
    prefix.  ``--cd`` and ``--project-root`` are rendered from the same exact
    validated value so current-command recognition can compare the complete
    wrapper byte-for-byte.
    """

    launcher_text = _validate_posix_absolute_path(
        launcher, "WSL Codex hook launcher"
    )
    root_text = _validate_posix_absolute_path(
        project_root, "WSL Codex project root"
    )
    if not _executable_names(launcher_text) & {
        HOOK_COMMAND_HEAD,
        f"{HOOK_COMMAND_HEAD}.exe",
    }:
        raise CodexOnboardingError(
            "WSL Codex hook launcher must name the aoi-codex-hook entry point"
        )
    distro_text = _validate_wsl_identity(distribution, "WSL distribution")
    user_text = _validate_wsl_identity(user, "WSL user")
    digest = _validate_digest(provenance_sha256, "Codex provenance SHA-256")
    return (
        f'wsl.exe --distribution "{distro_text}" --user "{user_text}" '
        f'--cd "{root_text}" --exec "{launcher_text}" '
        f'--hook-version 6 --project-root "{root_text}" '
        f'--provenance-sha256 "{digest}"'
    )


def build_codex_hook_commands(
    launcher: str | os.PathLike[str],
    project_root: str | os.PathLike[str],
    provenance_sha256: str,
    *,
    environment: Mapping[str, str] | None = None,
    kernel_release: str | None = None,
    host_os_name: str | None = None,
    wsl_user: str | None = None,
) -> tuple[str, str]:
    """Build the exact native and Windows hook command pair.

    Production callers omit the keyword-only probes.  They exist so tests can
    falsify every host-detection branch without accepting an operator-provided
    command string.  Partial or contradictory WSL signals fail before any
    onboarding publication.
    """

    env = os.environ if environment is None else environment
    release = platform.release() if kernel_release is None else kernel_release
    os_name = os.name if host_os_name is None else host_os_name
    distro = env.get("WSL_DISTRO_NAME")
    interop = env.get("WSL_INTEROP")
    signals = (
        distro is not None,
        interop is not None,
        "microsoft" in release.lower(),
    )
    if any(signals):
        if os_name == "nt" or not all(signals):
            raise CodexOnboardingError(
                "WSL hook routing signals are partial or contradict the host"
            )
        assert distro is not None and interop is not None
        _validate_posix_absolute_path(interop, "WSL interop endpoint")
        launcher_text = _validate_posix_absolute_path(
            launcher, "WSL Codex hook launcher"
        )
        root_text = _validate_posix_absolute_path(
            project_root, "WSL Codex project root"
        )
        if wsl_user is None:
            try:
                pwd_module = importlib.import_module("pwd")
                getpwuid = getattr(pwd_module, "getpwuid")
                geteuid = getattr(os, "geteuid")
                wsl_user = str(getattr(getpwuid(geteuid()), "pw_name"))
            except (AttributeError, ImportError, KeyError, OSError, TypeError) as exc:
                raise CodexOnboardingError(
                    "cannot determine the exact WSL user for Windows hook routing"
                ) from exc
        direct = build_codex_hook_command(
            launcher_text, root_text, provenance_sha256
        )
        windows = build_codex_windows_wsl_hook_command(
            launcher_text,
            root_text,
            provenance_sha256,
            distribution=distro,
            user=wsl_user,
        )
        return direct, windows

    if os_name == "nt":
        raw_root = os.fspath(project_root)
        lowered_root = raw_root.replace("/", "\\").lower()
        if lowered_root.startswith("\\\\wsl$\\") or lowered_root.startswith(
            "\\\\wsl.localhost\\"
        ):
            raise CodexOnboardingError(
                "Windows onboarding cannot govern a WSL UNC project; "
                "rerun from the canonical WSL session"
            )
        launcher_text = _validate_windows_absolute_path(
            launcher, "Codex hook launcher"
        )
        root_text = _validate_windows_absolute_path(
            project_root, "Codex project root"
        )
    else:
        launcher_text = _validate_posix_absolute_path(
            launcher, "Codex hook launcher"
        )
        root_text = _validate_posix_absolute_path(
            project_root, "Codex project root"
        )
    direct = build_codex_hook_command(
        launcher_text, root_text, provenance_sha256
    )
    return direct, direct


def _strip_wrapping_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _executable_names(value: str) -> set[str]:
    return {
        PurePosixPath(value).name.lower(),
        PureWindowsPath(value).name.lower(),
    }


def _contains_shell_control(command: str) -> bool:
    quote = ""
    for character in command:
        if character in {"'", '"'}:
            if not quote:
                quote = character
            elif quote == character:
                quote = ""
            continue
        if character in "$`%!^":
            return True
        if not quote and character in "\r\n;&|<>()":
            return True
    return False


def _wsl_hook_index(argv: list[str]) -> int | None:
    """Return the hook argv index for a conservative documented WSL launcher."""

    index = 1
    options_with_value = {"-d", "--distribution", "-u", "--user", "--cd"}
    options_with_equals = ("--distribution=", "--user=", "--cd=")
    while index < len(argv):
        token = argv[index]
        if token in {"--exec", "-e", "--"}:
            index += 1
            break
        if token in options_with_value:
            if index + 1 >= len(argv):
                return None
            value = argv[index + 1]
            if not value or value.startswith("-"):
                return None
            index += 2
            continue
        if token.startswith(options_with_equals):
            value = _strip_wrapping_quotes(token.split("=", 1)[1])
            if not value or value.startswith("-"):
                return None
            index += 1
            continue
        break
    return index if index < len(argv) else None


def _direct_aoi_hook_argv(value: Any) -> list[str] | None:
    """Parse a direct hook or the narrow ``wsl [--exec]`` process wrapper."""

    command = str(value or "").strip()
    if not command or _contains_shell_control(command):
        return None
    for posix in (False, True):
        try:
            raw = shlex.split(command, posix=posix)
        except ValueError:
            continue
        argv = [_strip_wrapping_quotes(item) for item in raw]
        if not argv:
            continue
        names = _executable_names(argv[0])
        if names & {HOOK_COMMAND_HEAD, f"{HOOK_COMMAND_HEAD}.exe"}:
            return argv
        if names & {"wsl", "wsl.exe"}:
            hook_index = _wsl_hook_index(argv)
            if hook_index is not None and _executable_names(argv[hook_index]) & {
                HOOK_COMMAND_HEAD,
                f"{HOOK_COMMAND_HEAD}.exe",
            }:
                return argv[hook_index:]
    return None


def _current_wsl_hook_identity(value: Any) -> dict[str, str] | None:
    """Parse only the one canonical current Windows-to-WSL wrapper."""

    command = str(value or "").strip()
    if not command or _contains_shell_control(command):
        return None
    try:
        argv = [
            _strip_wrapping_quotes(item)
            for item in shlex.split(command, posix=True)
        ]
    except ValueError:
        return None
    if (
        len(argv) != 15
        or _executable_names(argv[0]) != {"wsl.exe"}
        or argv[1] != "--distribution"
        or argv[3] != "--user"
        or argv[5] != "--cd"
        or argv[7] != "--exec"
        or argv[9] != "--hook-version"
        or argv[10] != "6"
        or argv[11] != "--project-root"
        or argv[13] != "--provenance-sha256"
    ):
        return None
    distribution, user, cwd, launcher, root, digest = (
        argv[2],
        argv[4],
        argv[6],
        argv[8],
        argv[12],
        argv[14],
    )
    if cwd != root:
        return None
    try:
        canonical = build_codex_windows_wsl_hook_command(
            launcher,
            root,
            digest,
            distribution=distribution,
            user=user,
        )
    except CodexOnboardingError:
        return None
    if command != canonical:
        return None
    return {
        "distribution": distribution,
        "user": user,
        "launcher": launcher,
        "project_root": root,
        "provenance_sha256": digest,
    }


def _current_direct_hook_identity(value: Any) -> dict[str, str] | None:
    """Return the identity of one exact direct current hook command."""

    command = str(value or "").strip()
    argv = _direct_aoi_hook_argv(value)
    if (
        argv is None
        or len(argv) != 7
        or not _is_absolute_path(argv[0])
        or argv[1] != "--hook-version"
        or argv[2] != "6"
        or argv[3] != "--project-root"
        or not _is_absolute_path(argv[4])
        or argv[5] != "--provenance-sha256"
        or not isinstance(argv[6], str)
        or len(argv[6]) != 64
        or bool(set(argv[6]) - _SHA256_HEX)
    ):
        return None
    try:
        canonical = build_codex_hook_command(argv[0], argv[4], argv[6])
    except CodexOnboardingError:
        return None
    if command != canonical:
        return None
    return {
        "launcher": argv[0],
        "project_root": argv[4],
        "provenance_sha256": argv[6],
    }


def references_aoi_codex_hook(value: Any) -> bool:
    """Conservatively identify a command that carries an AOI hook executable."""

    command = str(value or "").strip()
    return _references_aoi_codex_hook(command, depth=0)


def _references_aoi_codex_hook(command: str, *, depth: int) -> bool:
    """Inspect direct tokens and one bounded known-shell command operand."""

    if not command:
        return False
    normalized_reference = command.lower().replace("^", "")
    has_hook_signature = (
        HOOK_COMMAND_HEAD in normalized_reference
        and any(
            flag in normalized_reference
            for flag in (
                "--hook-version",
                "--project-root",
                "--provenance-sha256",
            )
        )
    )
    if len(command.encode("utf-8")) > 32 * 1024:
        return HOOK_COMMAND_HEAD in normalized_reference
    # ``cmd.exe`` removes caret escapes before process creation.  Treat a
    # caret-normalized AOI signature as owned even when tokenization leaves
    # the caret embedded in the executable name.  This is deliberately a
    # narrow fail-closed guard, not a general shell-equivalence engine.
    if "^" in command and has_hook_signature:
        return True
    parse_failed = False
    for posix in (False, True):
        try:
            raw = shlex.split(command, posix=posix)
        except ValueError:
            parse_failed = True
            continue
        argv = [_strip_wrapping_quotes(token) for token in raw]
        for token in argv:
            if _executable_names(token) & {
                HOOK_COMMAND_HEAD,
                f"{HOOK_COMMAND_HEAD}.exe",
            }:
                return True
        if depth >= 1 or not argv:
            continue
        shell_names = _executable_names(argv[0])
        operand_indexes: list[int] = []
        if shell_names & {
            "bash",
            "bash.exe",
            "dash",
            "dash.exe",
            "sh",
            "sh.exe",
            "zsh",
            "zsh.exe",
        }:
            operand_indexes = [
                index + 1
                for index, token in enumerate(argv[:-1])
                if token.startswith("-") and "c" in token[1:]
            ]
        elif shell_names & {"cmd", "cmd.exe"}:
            operand_indexes = [
                index + 1
                for index, token in enumerate(argv[:-1])
                if token.lower() in {"/c", "/k"}
            ]
        elif shell_names & {
            "powershell",
            "powershell.exe",
            "pwsh",
            "pwsh.exe",
        }:
            operand_indexes = [
                index + 1
                for index, token in enumerate(argv[:-1])
                if token.lower() in {"-c", "-command", "-commandwithargs"}
            ]
        for index in operand_indexes:
            nested = " ".join(argv[index:]).strip()
            if _references_aoi_codex_hook(nested, depth=depth + 1):
                return True
    # If either tokenizer rejects quoting, do not preserve a raw command that
    # still carries a recognizable AOI executable plus an AOI hook flag as a
    # foreign handler.  Well-formed foreign commands that merely mention the
    # executable name (for example a Python ``print``) remain foreign.
    if parse_failed and has_hook_signature:
        return True
    return False


def is_aoi_codex_hook_command(
    value: Any,
    *,
    require_current: bool = True,
    expected_launcher: str | os.PathLike[str] | None = None,
    expected_project_root: str | os.PathLike[str] | None = None,
    expected_provenance_sha256: str | None = None,
) -> bool:
    """Recognize a current bound command or a legacy AOI-owned command.

    ``require_current=False`` is deliberately for ownership migration only:
    it recognizes the historical three-argument AOI commands so onboarding and
    offboarding can replace/remove them.  It does not make a legacy command a
    current trusted hook.  When any expected current identity is given, all
    three are required and the rendered command must match byte-for-byte.
    """

    expected_values = (
        expected_launcher,
        expected_project_root,
        expected_provenance_sha256,
    )
    if any(item is not None for item in expected_values) and not all(
        item is not None for item in expected_values
    ):
        raise CodexOnboardingError(
            "expected launcher, project root, and provenance SHA-256 must be supplied together"
        )
    if require_current:
        wsl_identity = _current_wsl_hook_identity(value)
        if wsl_identity is not None:
            if all(item is not None for item in expected_values):
                assert expected_launcher is not None
                assert expected_project_root is not None
                assert expected_provenance_sha256 is not None
                return (
                    wsl_identity["launcher"] == os.fspath(expected_launcher)
                    and wsl_identity["project_root"]
                    == os.fspath(expected_project_root)
                    and wsl_identity["provenance_sha256"]
                    == expected_provenance_sha256
                )
            return True
    argv = _direct_aoi_hook_argv(value)
    if argv is None:
        return False
    legacy = (
        len(argv) == 3
        and argv[1] == "--hook-version"
        and re.fullmatch(r"\d+", argv[2]) is not None
    )
    if not require_current:
        return legacy
    current = (
        len(argv) == 7
        and _is_absolute_path(argv[0])
        and argv[1] == "--hook-version"
        and argv[2] == "6"
        and argv[3] == "--project-root"
        and _is_absolute_path(argv[4])
        and argv[5] == "--provenance-sha256"
        and isinstance(argv[6], str)
        and len(argv[6]) == 64
        and not (set(argv[6]) - _SHA256_HEX)
    )
    if not current:
        return False
    if value != build_codex_hook_command(argv[0], argv[4], argv[6]):
        return False
    if all(item is not None for item in expected_values):
        assert expected_launcher is not None
        assert expected_project_root is not None
        assert expected_provenance_sha256 is not None
        return value == build_codex_hook_command(
            expected_launcher,
            expected_project_root,
            expected_provenance_sha256,
        )
    return True


def is_current_codex_hook_command_pair(
    command: Any,
    command_windows: Any,
    *,
    expected_launcher: str | os.PathLike[str],
    expected_project_root: str | os.PathLike[str],
    expected_provenance_sha256: str,
    environment: Mapping[str, str] | None = None,
    kernel_release: str | None = None,
    host_os_name: str | None = None,
    wsl_user: str | None = None,
) -> bool:
    """Require the complete exact platform pair for one current handler."""

    expected_native, expected_windows = build_codex_hook_commands(
        expected_launcher,
        expected_project_root,
        expected_provenance_sha256,
        environment=environment,
        kernel_release=kernel_release,
        host_os_name=host_os_name,
        wsl_user=wsl_user,
    )
    return is_exact_codex_hook_command_pair(
        command,
        command_windows,
        expected_command=expected_native,
        expected_command_windows=expected_windows,
    )


def is_exact_codex_hook_command_pair(
    command: Any,
    command_windows: Any,
    *,
    expected_command: str,
    expected_command_windows: str,
) -> bool:
    """Match one complete current handler against its exact rendered pair."""

    native = str(command or "")
    windows = str(command_windows or "")
    if native != expected_command or windows != expected_command_windows:
        return False
    try:
        _validate_codex_hook_command_pair(
            native,
            windows,
            label="expected Codex hook",
        )
    except CodexOnboardingError:
        return False
    return True


def _validate_codex_hook_command_pair(
    command: str,
    command_windows: str,
    *,
    label: str,
) -> None:
    """Require direct/direct equality or one identity-matched WSL wrapper."""

    native = _current_direct_hook_identity(command)
    if native is None:
        raise CodexOnboardingError(
            f"{label} command must be one exact direct current AOI hook"
        )
    if command_windows == command:
        return
    windows = _current_wsl_hook_identity(command_windows)
    if windows is None or any(
        windows[field] != native[field]
        for field in ("launcher", "project_root", "provenance_sha256")
    ):
        raise CodexOnboardingError(
            f"{label} command pair must bind one exact launcher, project root, "
            "and provenance SHA-256"
        )


def _validate_hook_command(value: str, label: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise CodexOnboardingError(f"{label} must be an exact quoted command string")
    command = value
    if not is_aoi_codex_hook_command(command):
        raise CodexOnboardingError(
            f"{label} must be an exact absolute aoi-codex-hook command bound to "
            "hook version 6, project root, and provenance SHA-256"
        )
    return command


def _handler_is_aoi_owned(
    handler: Any,
    *,
    accepted_command_pairs: tuple[tuple[str, str], ...],
) -> bool:
    if not isinstance(handler, dict):
        return False
    if any(
        is_exact_codex_hook_command_pair(
            handler.get("command"),
            handler.get("commandWindows"),
            expected_command=expected_command,
            expected_command_windows=expected_command_windows,
        )
        for expected_command, expected_command_windows in accepted_command_pairs
    ):
        return True
    commands = [
        handler.get(key)
        for key in ("command", "commandWindows")
        if str(handler.get(key, "")).strip()
    ]
    current = [is_aoi_codex_hook_command(command) for command in commands]
    if any(current):
        raise CodexOnboardingError(
            "Codex hook handler has a partial or route-drifted current AOI "
            "command pair; restore the exact pair before wiring AOI"
        )
    legacy = [
        is_aoi_codex_hook_command(command, require_current=False)
        for command in commands
    ]
    if any(legacy) and not all(legacy):
        raise CodexOnboardingError(
            "Codex hook handler mixes an AOI-owned command with a foreign "
            "platform command; split or remove it before wiring AOI"
        )
    if bool(legacy) and all(legacy):
        return True
    if any(references_aoi_codex_hook(command) for command in commands):
        raise CodexOnboardingError(
            "Codex hook handler has a malformed or route-drifted AOI command "
            "pair; restore or remove it before wiring AOI"
        )
    return False


def _entry_carries_aoi_hook(
    entry: Any,
    *,
    accepted_command_pairs: tuple[tuple[str, str], ...],
) -> bool:
    if not isinstance(entry, dict):
        return False
    handlers = entry.get("hooks", [])
    if not isinstance(handlers, list):
        return False
    return any(
        _handler_is_aoi_owned(
            handler,
            accepted_command_pairs=accepted_command_pairs,
        )
        for handler in handlers
    )


def _validate_event_entries(event: str, entries: list[Any]) -> None:
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise CodexOnboardingError(
                f".codex/hooks.json event {event!r} entry {index} "
                "must be a JSON object"
            )
        handlers = entry.get("hooks")
        if not isinstance(handlers, list):
            raise CodexOnboardingError(
                f".codex/hooks.json event {event!r} entry {index} "
                "'hooks' must be a JSON array"
            )
        if not all(isinstance(handler, dict) for handler in handlers):
            raise CodexOnboardingError(
                f".codex/hooks.json event {event!r} entry {index} "
                "hook handlers must be JSON objects"
            )
        if any(
            key in handler and not isinstance(handler[key], str)
            for handler in handlers
            for key in ("command", "commandWindows")
        ):
            raise CodexOnboardingError(
                f".codex/hooks.json event {event!r} entry {index} "
                "hook command values must be strings"
            )


def _merge_codex_hook_settings_detailed(
    settings: Mapping[str, Any],
    *,
    command: str,
    command_windows: str,
    previous_command: str | None = None,
    previous_command_windows: str | None = None,
) -> tuple[dict[str, Any], list[str], list[str]]:
    """Return merged settings plus added and upgraded AOI event lists."""

    command = _validate_hook_command(command, "Codex hook command")
    command_windows = _validate_hook_command(command_windows, "Codex Windows hook command")
    _validate_codex_hook_command_pair(
        command,
        command_windows,
        label="Codex hook",
    )
    if (previous_command is None) != (previous_command_windows is None):
        raise CodexOnboardingError(
            "previous Codex hook command pair must be supplied together"
        )
    accepted_command_pairs: tuple[tuple[str, str], ...] = (
        (command, command_windows),
    )
    if previous_command is not None and previous_command_windows is not None:
        previous_command = _validate_hook_command(
            previous_command, "previous Codex hook command"
        )
        previous_command_windows = _validate_hook_command(
            previous_command_windows, "previous Codex Windows hook command"
        )
        _validate_codex_hook_command_pair(
            previous_command,
            previous_command_windows,
            label="previous Codex hook",
        )
        accepted_command_pairs += ((previous_command, previous_command_windows),)
    merged: dict[str, Any] = dict(settings)
    raw_hooks = merged.get("hooks")
    if raw_hooks is not None and not isinstance(raw_hooks, dict):
        raise CodexOnboardingError(".codex/hooks.json 'hooks' must be a JSON object")
    hooks: dict[str, Any] = dict(raw_hooks) if isinstance(raw_hooks, dict) else {}
    added: list[str] = []
    updated: list[str] = []
    for event in CODEX_HOOK_EVENTS:
        existing = hooks.get(event)
        if existing is not None and not isinstance(existing, list):
            raise CodexOnboardingError(
                f".codex/hooks.json event {event!r} must be a JSON array"
            )
        entries = list(existing) if isinstance(existing, list) else []
        _validate_event_entries(event, entries)
        desired = _aoi_hook_entry(
            event,
            command=command,
            command_windows=command_windows,
        )
        aoi_entries = [
            entry
            for entry in entries
            if _entry_carries_aoi_hook(
                entry,
                accepted_command_pairs=accepted_command_pairs,
            )
        ]
        if aoi_entries == [desired]:
            hooks[event] = entries
            continue
        if not aoi_entries:
            entries.append(desired)
            hooks[event] = entries
            added.append(event)
            continue

        # Rebuild only the AOI-owned handler. If an entry also carries an
        # unrelated handler, retain that handler and its matcher/settings.
        preserved: list[Any] = []
        for entry in entries:
            if not _entry_carries_aoi_hook(
                entry,
                accepted_command_pairs=accepted_command_pairs,
            ):
                preserved.append(entry)
                continue
            handlers = entry.get("hooks", [])
            unrelated = [
                handler
                for handler in handlers
                if not _handler_is_aoi_owned(
                    handler,
                    accepted_command_pairs=accepted_command_pairs,
                )
            ]
            if unrelated:
                retained_entry = dict(entry)
                retained_entry["hooks"] = unrelated
                preserved.append(retained_entry)
        preserved.append(desired)
        hooks[event] = preserved
        updated.append(event)
    merged["hooks"] = hooks
    return merged, added, updated


def merge_codex_hook_settings(
    settings: Mapping[str, Any],
    *,
    command: str,
    command_windows: str,
) -> tuple[dict[str, Any], list[str]]:
    """Return ``(new_settings, events_added)`` while upgrading AOI handlers."""

    merged, added, _updated = _merge_codex_hook_settings_detailed(
        settings,
        command=command,
        command_windows=command_windows,
    )
    return merged, added


def install_codex_hooks(
    hooks_path: Path,
    *,
    command: str,
    command_windows: str,
    previous_command: str | None = None,
    previous_command_windows: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    hooks_text, hooks_snapshot = _read_safe_text(hooks_path, label="Codex hooks path")
    if hooks_snapshot is not None:
        try:
            loaded = json.loads(hooks_text)
        except json.JSONDecodeError as exc:
            raise CodexOnboardingError(
                f"{hooks_path} is not valid JSON; fix it before wiring AOI: {exc}"
            ) from exc
        if not isinstance(loaded, dict):
            raise CodexOnboardingError(
                f"{hooks_path} must contain a JSON object at the top level"
            )
        payload = loaded
    merged, added, updated = _merge_codex_hook_settings_detailed(
        payload,
        command=command,
        command_windows=command_windows,
        previous_command=previous_command,
        previous_command_windows=previous_command_windows,
    )
    changed = merged != payload or hooks_snapshot is None
    if changed:
        _atomic_write_text(
            hooks_path,
            json.dumps(merged, indent=2, ensure_ascii=False) + "\n",
            expected_leaf=hooks_snapshot,
        )
    return {
        "hooks_path": str(hooks_path),
        "events_added": added,
        "events_updated": updated,
        "events_already_present": [
            event
            for event in CODEX_HOOK_EVENTS
            if event not in added and event not in updated
        ],
        "hook_command": command,
        "hook_command_windows": command_windows,
        "trust_required": True,
        "changed": changed,
    }


def preflight_codex_onboarding(
    root: Path,
    *,
    command: str,
    command_windows: str,
    previous_command: str | None = None,
    previous_command_windows: str | None = None,
) -> dict[str, Any]:
    """Validate all existing Codex client files without mutating the repo."""

    root = _absolute_path(root, "Codex project root")
    if _audit_directory_chain(root, create_missing=False) is None:
        raise CodexOnboardingError(f"Codex project root is missing: {root}")
    config_path = root / ".codex" / "config.toml"
    config_text, _config_snapshot = _read_safe_text(
        config_path, label="Codex config path"
    )
    merged_config, config_changed = merge_codex_config_toml(config_text)
    # The merge helper already parses the candidate; keep the value live here
    # so a future refactor cannot silently turn this into a syntax-only probe.
    if tomllib.loads(merged_config).get("features", {}).get("hooks") is not True:
        raise CodexOnboardingError("Codex hook feature preflight did not converge")

    hooks_path = root / ".codex" / "hooks.json"
    payload: dict[str, Any] = {}
    hooks_text, hooks_snapshot = _read_safe_text(hooks_path, label="Codex hooks path")
    if hooks_snapshot is not None:
        try:
            loaded = json.loads(hooks_text)
        except json.JSONDecodeError as exc:
            raise CodexOnboardingError(
                f"{hooks_path} is not valid JSON; fix it before wiring AOI: {exc}"
            ) from exc
        if not isinstance(loaded, dict):
            raise CodexOnboardingError(
                f"{hooks_path} must contain a JSON object at the top level"
            )
        payload = loaded
    _merged_hooks, events_added, events_updated = _merge_codex_hook_settings_detailed(
        payload,
        command=command,
        command_windows=command_windows,
        previous_command=previous_command,
        previous_command_windows=previous_command_windows,
    )
    return {
        "config_path": str(config_path),
        "config_changed": config_changed,
        "hooks_path": str(hooks_path),
        "events_to_add": events_added,
        "events_to_update": events_updated,
    }


_TABLE_HEADER = re.compile(r"^\s*\[([^\]]+)\]\s*(?:#.*)?$")
_HOOKS_ASSIGNMENT = re.compile(r"^(\s*)hooks\s*=\s*(true|false)(\s*(?:#.*)?)$", re.I)


def merge_codex_config_toml(text: str) -> tuple[str, bool]:
    """Enable stable Codex lifecycle hooks while preserving other TOML bytes."""

    try:
        parsed = tomllib.loads(text) if text.strip() else {}
    except tomllib.TOMLDecodeError as exc:
        raise CodexOnboardingError(f".codex/config.toml is not valid TOML: {exc}") from exc
    features = parsed.get("features", {})
    if not isinstance(features, dict):
        raise CodexOnboardingError(".codex/config.toml 'features' must be a TOML table")
    if features.get("hooks") is True:
        return text, False
    if "hooks" in features and not isinstance(features.get("hooks"), bool):
        raise CodexOnboardingError(".codex/config.toml features.hooks must be a boolean")

    lines = text.splitlines(keepends=True)
    feature_header: int | None = None
    feature_end = len(lines)
    for index, line in enumerate(lines):
        match = _TABLE_HEADER.match(line.rstrip("\r\n"))
        if not match:
            continue
        table = match.group(1).strip()
        if table == "features":
            feature_header = index
            continue
        if feature_header is not None and index > feature_header:
            feature_end = index
            break

    if feature_header is not None:
        for index in range(feature_header + 1, feature_end):
            raw = lines[index].rstrip("\r\n")
            match = _HOOKS_ASSIGNMENT.match(raw)
            if not match:
                continue
            newline = "\r\n" if lines[index].endswith("\r\n") else "\n"
            if not lines[index].endswith(("\n", "\r")):
                newline = ""
            lines[index] = f"{match.group(1)}hooks = true{match.group(3)}{newline}"
            break
        else:
            newline = "\r\n" if any(line.endswith("\r\n") for line in lines) else "\n"
            lines.insert(feature_header + 1, f"hooks = true{newline}")
        candidate = "".join(lines)
    else:
        # An inline ``features = {...}`` table cannot be safely extended without
        # reserializing the user's file and comments.
        if re.search(r"(?m)^\s*features\s*=", text):
            raise CodexOnboardingError(
                "inline 'features = {...}' cannot be merged safely; convert it to "
                "a [features] table and rerun"
            )
        separator = "" if not text or text.endswith(("\n", "\r")) else "\n"
        blank = "" if not text.strip() else "\n"
        candidate = f"{text}{separator}{blank}[features]\nhooks = true\n"

    try:
        verified = tomllib.loads(candidate)
    except tomllib.TOMLDecodeError as exc:
        raise CodexOnboardingError(
            f"generated .codex/config.toml would be invalid: {exc}"
        ) from exc
    if verified.get("features", {}).get("hooks") is not True:
        raise CodexOnboardingError("failed to enable Codex lifecycle hooks")
    return candidate, True


def install_codex_config(config_path: Path) -> dict[str, Any]:
    text, config_snapshot = _read_safe_text(config_path, label="Codex config path")
    merged, changed = merge_codex_config_toml(text)
    if changed or config_snapshot is None:
        _atomic_write_text(config_path, merged, expected_leaf=config_snapshot)
    return {
        "config_path": str(config_path),
        "hooks_feature_enabled": True,
        "changed": changed,
    }


def enable_aoi_codex_hooks_policy(text: str) -> tuple[str, bool]:
    """Flip only ``[hooks.codex].enabled`` in an already valid AOI profile."""

    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise CodexOnboardingError(f"aoi.toml is not valid TOML: {exc}") from exc
    hooks = parsed.get("hooks", {})
    codex = hooks.get("codex", {}) if isinstance(hooks, dict) else {}
    if isinstance(codex, dict) and codex.get("enabled") is True:
        return text, False
    if not isinstance(codex, dict) or codex.get("enabled") is not False:
        raise CodexOnboardingError(
            "aoi.toml must contain boolean [hooks.codex].enabled"
        )

    lines = text.splitlines(keepends=True)
    in_section = False
    for index, line in enumerate(lines):
        header = _TABLE_HEADER.match(line.rstrip("\r\n"))
        if header:
            in_section = header.group(1).strip() == "hooks.codex"
            continue
        if not in_section:
            continue
        match = re.match(
            r"^(\s*)enabled\s*=\s*false(\s*(?:#.*)?)$",
            line.rstrip("\r\n"),
            flags=re.I,
        )
        if not match:
            continue
        newline = "\r\n" if line.endswith("\r\n") else "\n"
        if not line.endswith(("\n", "\r")):
            newline = ""
        lines[index] = f"{match.group(1)}enabled = true{match.group(2)}{newline}"
        candidate = "".join(lines)
        verified = tomllib.loads(candidate)
        if verified.get("hooks", {}).get("codex", {}).get("enabled") is not True:
            break
        return candidate, True
    raise CodexOnboardingError(
        "could not safely locate [hooks.codex].enabled = false in aoi.toml"
    )


def _preflight_codex_user_skill(
    skills_root: Path,
    skill_text: str,
    *,
    replace_sha256: str | None = None,
) -> tuple[dict[str, Any], os.stat_result | None]:
    """Validate a user-scope AOI skill install without changing it."""

    skills_root = _absolute_path(skills_root, "Codex user skills root")
    skill_path = skills_root / "aoi" / "SKILL.md"
    read_text, skill_snapshot = _read_safe_text(
        skill_path, label="Codex user skill path"
    )
    existing_text: str | None = read_text
    if skill_snapshot is None:
        existing_text = None
    existing_sha256 = (
        hashlib.sha256(existing_text.encode("utf-8")).hexdigest()
        if existing_text is not None
        else None
    )
    normalized_replace = (replace_sha256 or "").strip().lower() or None
    if normalized_replace is not None and not re.fullmatch(
        r"[0-9a-f]{64}", normalized_replace
    ):
        raise CodexOnboardingError(
            "--replace-user-skill-sha256 must be exactly 64 hexadecimal characters"
        )
    changed = existing_text != skill_text
    if (
        existing_text is not None
        and changed
        and normalized_replace != existing_sha256
    ):
        raise CodexOnboardingError(
            f"{skill_path} differs from the packaged AOI skill; review it and rerun "
            f"with --replace-user-skill-sha256 {existing_sha256} to replace those "
            "exact bytes"
        )
    return {
        "scope": "user",
        "skills_root": str(skills_root),
        "skill_path": str(skill_path),
        "existing_sha256": existing_sha256,
        "packaged_sha256": hashlib.sha256(skill_text.encode("utf-8")).hexdigest(),
        "changed": changed,
    }, skill_snapshot


def preflight_codex_user_skill(
    skills_root: Path,
    skill_text: str,
    *,
    replace_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate a user-scope AOI skill install without changing it."""

    result, _snapshot = _preflight_codex_user_skill(
        skills_root,
        skill_text,
        replace_sha256=replace_sha256,
    )
    return result


def install_codex_user_skill(
    skills_root: Path,
    skill_text: str,
    *,
    replace_sha256: str | None = None,
) -> dict[str, Any]:
    result, skill_snapshot = _preflight_codex_user_skill(
        skills_root,
        skill_text,
        replace_sha256=replace_sha256,
    )
    if result["changed"]:
        skill_path = Path(result["skill_path"])
        _atomic_write_text(
            skill_path,
            skill_text,
            expected_leaf=skill_snapshot,
        )
    result["updated"] = bool(result["changed"] and result["existing_sha256"] is not None)
    result["created"] = bool(result["changed"] and result["existing_sha256"] is None)
    return result


def register_codex_onboarding_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "codex onboarding command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )
    parser = subparsers.add_parser("codex-init")
    parser.add_argument("--project-name")
    parser.add_argument(
        "--promotion-bundle-file",
        help="exact promoted release-promotion bundle used to verify this AOI install",
    )
    parser.add_argument(
        "--expected-promotion-bundle-sha256",
        help=(
            "lowercase canonical bundle digest recorded in the promotion "
            "bundle, not the raw JSON file SHA-256"
        ),
    )
    parser.add_argument(
        "--local-artifact-bundle-file",
        help=(
            "exact reviewed local-install bundle for this AOI install; this is "
            "not a release or promotion"
        ),
    )
    parser.add_argument(
        "--expected-local-artifact-bundle-sha256",
        help=(
            "lowercase canonical bundle digest recorded in the reviewed local "
            "bundle, not the raw JSON file SHA-256"
        ),
    )
    parser.add_argument(
        "--user-skills-root",
        help=(
            "Codex user-scope skills directory; defaults to $HOME/.agents/skills "
            "on the host running AOI"
        ),
    )
    parser.add_argument(
        "--replace-user-skill-sha256",
        help="reviewed SHA-256 required to replace a differing user AOI skill",
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["codex_init"])


__all__ = [
    "CODEX_HOOK_EVENTS",
    "CodexOnboardingError",
    "HOOK_TIMEOUT_SECONDS",
    "SESSION_START_MATCHER",
    "build_codex_hook_command",
    "build_codex_hook_commands",
    "build_codex_windows_wsl_hook_command",
    "enable_aoi_codex_hooks_policy",
    "install_codex_config",
    "install_codex_hooks",
    "install_codex_user_skill",
    "is_aoi_codex_hook_command",
    "is_exact_codex_hook_command_pair",
    "is_current_codex_hook_command_pair",
    "merge_codex_config_toml",
    "merge_codex_hook_settings",
    "preflight_codex_onboarding",
    "preflight_codex_user_skill",
    "references_aoi_codex_hook",
    "read_verified_codex_text",
    "register_codex_onboarding_commands",
]
