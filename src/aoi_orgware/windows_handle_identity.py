"""Stable Win32 handle identities for security-sensitive path ingress.

The standard library exposes a file descriptor but not its Windows final path.
These helpers bind a descriptor to the object namespace that was actually
opened, rather than trusting a later spelling-based path observation.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class WindowsHandleIdentity:
    final_path: str
    volume_serial: int
    file_index: int
    link_count: int
    change_time: int


@dataclass(frozen=True)
class DirectoryEntry:
    name: str
    file_index: int
    attributes: int


def _normal_path(value: str | Path) -> str:
    result = os.path.normpath(str(value))
    if result.startswith("\\\\?\\UNC\\"):
        result = "\\\\" + result[8:]
    elif result.startswith("\\\\?\\"):
        result = result[4:]
    return os.path.normcase(result)


def _kernel32() -> Any:
    if os.name != "nt":
        raise OSError("Windows handle identity is unavailable on this platform")
    import ctypes

    return ctypes.WinDLL("kernel32", use_last_error=True)


def _identity_from_handle(handle_value: int) -> WindowsHandleIdentity:
    import ctypes
    from ctypes import wintypes

    class _FILETIME(ctypes.Structure):
        _fields_ = [
            ("dwLowDateTime", wintypes.DWORD),
            ("dwHighDateTime", wintypes.DWORD),
        ]

    class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", _FILETIME),
            ("ftLastAccessTime", _FILETIME),
            ("ftLastWriteTime", _FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    class _FILE_BASIC_INFO(ctypes.Structure):
        _fields_ = [
            ("CreationTime", ctypes.c_longlong),
            ("LastAccessTime", ctypes.c_longlong),
            ("LastWriteTime", ctypes.c_longlong),
            ("ChangeTime", ctypes.c_longlong),
            ("FileAttributes", wintypes.DWORD),
        ]

    kernel32 = _kernel32()
    handle = wintypes.HANDLE(handle_value)
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION),
    ]
    get_information.restype = wintypes.BOOL
    information = _BY_HANDLE_FILE_INFORMATION()
    if not get_information(handle, ctypes.byref(information)):
        raise ctypes.WinError(ctypes.get_last_error())

    get_information_ex = kernel32.GetFileInformationByHandleEx
    get_information_ex.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    get_information_ex.restype = wintypes.BOOL
    basic = _FILE_BASIC_INFO()
    if not get_information_ex(handle, 0, ctypes.byref(basic), ctypes.sizeof(basic)):
        raise ctypes.WinError(ctypes.get_last_error())

    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    get_final_path.restype = wintypes.DWORD
    buffer_size = 512
    while True:
        buffer = ctypes.create_unicode_buffer(buffer_size)
        length = get_final_path(handle, buffer, buffer_size, 0)
        if length == 0:
            raise ctypes.WinError(ctypes.get_last_error())
        if length < buffer_size:
            break
        buffer_size = length + 1
    return WindowsHandleIdentity(
        final_path=_normal_path(buffer.value),
        volume_serial=int(information.dwVolumeSerialNumber),
        file_index=(int(information.nFileIndexHigh) << 32)
        | int(information.nFileIndexLow),
        link_count=int(information.nNumberOfLinks),
        change_time=int(basic.ChangeTime),
    )


def opened_file_identity(fd: int) -> WindowsHandleIdentity | None:
    """Return final path and volume/file identity for this already-opened fd."""

    if os.name != "nt":
        return None
    import msvcrt

    return _identity_from_handle(msvcrt.get_osfhandle(fd))


def handle_matches_path(identity: WindowsHandleIdentity | None, path: Path) -> bool:
    return identity is None or identity.final_path == _normal_path(path)


def same_handle_identity(
    left: WindowsHandleIdentity | None, right: WindowsHandleIdentity | None
) -> bool:
    return left == right


def handle_is_child_of(
    child: WindowsHandleIdentity | None,
    root: WindowsHandleIdentity | None,
    name: str,
) -> bool:
    if child is None or root is None:
        return True
    return (
        child.volume_serial == root.volume_serial
        and child.final_path == _normal_path(os.path.join(root.final_path, name))
    )


class DirectoryHandle:
    """A live Win32 directory handle and its immutable opened identity."""

    def __init__(
        self,
        handle: int | None,
        identity: WindowsHandleIdentity | None,
        fallback_path: Path | None = None,
    ):
        self._handle = handle
        self.identity = identity
        self._fallback_path = fallback_path

    def entries(self) -> list[DirectoryEntry]:
        """Enumerate exactly through the held directory handle on Windows."""

        if self._handle is None:
            if self._fallback_path is None:
                raise OSError("directory handle is closed")
            return [
                DirectoryEntry(entry.name, 0, 0)
                for entry in self._fallback_path.iterdir()
            ]
        import ctypes
        from ctypes import wintypes

        class _FILE_ID_BOTH_DIR_INFO(ctypes.Structure):
            _fields_ = [
                ("NextEntryOffset", wintypes.DWORD),
                ("FileIndex", wintypes.DWORD),
                ("CreationTime", ctypes.c_longlong),
                ("LastAccessTime", ctypes.c_longlong),
                ("LastWriteTime", ctypes.c_longlong),
                ("ChangeTime", ctypes.c_longlong),
                ("EndOfFile", ctypes.c_longlong),
                ("AllocationSize", ctypes.c_longlong),
                ("FileAttributes", wintypes.DWORD),
                ("FileNameLength", wintypes.DWORD),
                ("EaSize", wintypes.DWORD),
                ("ShortNameLength", ctypes.c_byte),
                ("ShortName", ctypes.c_wchar * 12),
                ("FileId", ctypes.c_longlong),
                ("FileName", ctypes.c_wchar * 1),
            ]

        kernel32 = _kernel32()
        query = kernel32.GetFileInformationByHandleEx
        query.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        query.restype = wintypes.BOOL
        buffer_size = 64 * 1024
        result: list[DirectoryEntry] = []
        restart = True
        while True:
            buffer = ctypes.create_string_buffer(buffer_size)
            if not query(
                wintypes.HANDLE(self._handle),
                11 if restart else 10,
                buffer,
                buffer_size,
            ):
                error = ctypes.get_last_error()
                if error == 18:  # ERROR_NO_MORE_FILES
                    break
                raise ctypes.WinError(error)
            restart = False
            offset = 0
            while offset < buffer_size:
                row = ctypes.cast(
                    ctypes.byref(buffer, offset),
                    ctypes.POINTER(_FILE_ID_BOTH_DIR_INFO),
                ).contents
                if row.FileNameLength > (
                    buffer_size - offset - _FILE_ID_BOTH_DIR_INFO.FileName.offset
                ):
                    raise OSError("directory handle returned an invalid file name length")
                raw_name = ctypes.string_at(
                    ctypes.addressof(buffer)
                    + offset
                    + _FILE_ID_BOTH_DIR_INFO.FileName.offset,
                    row.FileNameLength,
                )
                name = raw_name.decode("utf-16-le")
                if name not in {".", ".."}:
                    result.append(
                        DirectoryEntry(
                            name=name,
                            file_index=int(row.FileId),
                            attributes=int(row.FileAttributes),
                        )
                    )
                if row.NextEntryOffset == 0:
                    break
                if row.NextEntryOffset % 8 or row.NextEntryOffset > buffer_size - offset:
                    raise OSError("directory handle returned an invalid entry offset")
                offset += row.NextEntryOffset
        return result

    def require_unchanged(self) -> None:
        if self._handle is None or self.identity is None:
            return
        if _identity_from_handle(self._handle) != self.identity:
            raise OSError("directory changed while being inspected")

    def close(self) -> None:
        if self._handle is None:
            return
        import ctypes

        _close_handle(self._handle)
        self._handle = None

    def __enter__(self) -> "DirectoryHandle":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def _close_handle(handle_value: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = _kernel32()
    close = kernel32.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    if not close(wintypes.HANDLE(handle_value)):
        raise ctypes.WinError(ctypes.get_last_error())


def open_directory_identity(path: Path) -> DirectoryHandle:
    """Open one directory handle without replacing it by a later path lookup."""

    if os.name != "nt":
        return DirectoryHandle(None, None, path)
    import ctypes
    from ctypes import wintypes

    kernel32 = _kernel32()
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
    handle = create_file(
        str(path),
        0x00000001 | 0x00000080,  # FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES
        0x00000001 | 0x00000002 | 0x00000004,  # share read/write/delete
        None,
        3,  # OPEN_EXISTING
        0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return DirectoryHandle(int(handle), _identity_from_handle(int(handle)))
    except BaseException:
        _close_handle(int(handle))
        raise
