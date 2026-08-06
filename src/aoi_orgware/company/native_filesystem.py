"""Native filesystem syscall spelling for canonical company paths."""
from __future__ import annotations

import ntpath
import os
from pathlib import Path
import stat


class NativeFilesystemIdentityError(RuntimeError):
    """A pathname no longer names the exact filesystem object expected."""


def _windows_extended_path(raw: str) -> str:
    """Return one idempotent absolute Win32 extended-path spelling."""

    if raw.startswith("\\\\?\\"):
        return raw
    absolute = ntpath.abspath(raw)
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute[2:]
    return "\\\\?\\" + absolute


def native_filesystem_path(path: Path) -> str | Path:
    """Use extended spelling only at a Windows filesystem syscall boundary."""

    if os.name != "nt":
        return path
    return _windows_extended_path(os.fspath(path))


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink


def unlink_identity_checked(path: Path, expected: os.stat_result) -> None:
    """Delete the expected file; Windows binds deletion to an opened handle.

    POSIX callers remain inside AOI's cooperative directory-lock boundary:
    POSIX does not expose a portable conditional-unlink-by-inode primitive.
    Windows uses ``SetFileInformationByHandle`` so a pathname replacement
    cannot redirect deletion after the identity check.
    """

    if os.name != "nt":
        observed = os.lstat(native_filesystem_path(path))
        if _file_identity(observed) != _file_identity(expected):
            raise NativeFilesystemIdentityError("filesystem object changed")
        os.unlink(native_filesystem_path(path))
        return

    import ctypes
    import importlib
    from ctypes import wintypes

    msvcrt = importlib.import_module("msvcrt")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    set_information = kernel32.SetFileInformationByHandle
    set_information.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    set_information.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    handle = create_file(
        os.fspath(native_filesystem_path(path)),
        0x00010000 | 0x00000080,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x00200000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    handle_value = int(handle)
    if handle_value == invalid_handle:
        error = ctypes.get_last_error()
        raise OSError(error, "CreateFileW identity-bound delete failed", str(path))

    descriptor: int | None = None
    try:
        descriptor = int(msvcrt.open_osfhandle(
            handle_value,
            os.O_RDONLY | getattr(os, "O_BINARY", 0),
        ))
        handle = None
        opened = os.fstat(descriptor)
        if (
            _file_identity(opened) != _file_identity(expected)
            or not stat.S_ISREG(opened.st_mode)
        ):
            raise NativeFilesystemIdentityError("filesystem object changed")
        delete_file = wintypes.BOOL(True)
        if not set_information(
            msvcrt.get_osfhandle(descriptor),
            4,
            ctypes.byref(delete_file),
            ctypes.sizeof(delete_file),
        ):
            error = ctypes.get_last_error()
            raise OSError(
                error,
                "SetFileInformationByHandle delete failed",
                str(path),
            )
    finally:
        if descriptor is not None:
            os.close(descriptor)
        elif handle is not None:
            close_handle(handle)


def fsync_directory(path: Path) -> None:
    """Persist one directory entry update where the platform supports it."""

    if os.name == "nt":
        return
    descriptor = os.open(
        native_filesystem_path(path),
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
