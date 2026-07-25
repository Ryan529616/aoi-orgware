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

    return ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]


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
        raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]

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
        raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]

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
            raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
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

    return _identity_from_handle(msvcrt.get_osfhandle(fd))  # type: ignore[attr-defined]


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
        self._change_buffer: Any | None = None
        self._change_overlapped: Any | None = None
        self._change_event: int | None = None
        self._change_watch_enabled = False

    def begin_change_watch(self) -> None:
        """Arm one asynchronous native change notification on this handle.

        A directory's metadata can return to its original value after a brief
        create/delete.  The outstanding request records that such a change
        happened without requiring another spelling-based directory lookup.
        """

        if self._handle is None:
            return
        if self._change_event is not None or self._change_overlapped is not None:
            raise OSError("directory change watcher is already armed")
        import ctypes
        from ctypes import wintypes

        class _OVERLAPPED(ctypes.Structure):
            _fields_ = [
                ("Internal", ctypes.c_size_t),
                ("InternalHigh", ctypes.c_size_t),
                ("Offset", wintypes.DWORD),
                ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE),
            ]

        kernel32 = _kernel32()
        create_event = kernel32.CreateEventW
        create_event.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        create_event.restype = wintypes.HANDLE
        event = create_event(None, True, False, None)
        if not event:
            raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
        overlapped = _OVERLAPPED()
        overlapped.hEvent = wintypes.HANDLE(event)
        buffer = ctypes.create_string_buffer(64 * 1024)
        read_changes = kernel32.ReadDirectoryChangesW
        read_changes.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
            wintypes.LPVOID,
            ctypes.POINTER(_OVERLAPPED),
            wintypes.LPVOID,
        ]
        read_changes.restype = wintypes.BOOL
        self._change_buffer = buffer
        self._change_overlapped = overlapped
        self._change_event = int(event)
        try:
            if not read_changes(
                wintypes.HANDLE(self._handle),
                buffer,
                len(buffer),
                False,
                0x00000001 | 0x00000002,  # FILE_NOTIFY_CHANGE_{FILE,DIR}_NAME
                None,
                ctypes.byref(overlapped),
                None,
            ):
                error = ctypes.get_last_error()  # type: ignore[attr-defined]
                if error != 997:  # ERROR_IO_PENDING
                    raise ctypes.WinError(error)  # type: ignore[attr-defined]
            self._change_watch_enabled = True
        except BaseException:
            self._release_change_watch()
            raise

    def _release_change_watch(self) -> None:
        """Release only a completed watch request; safe to call repeatedly."""

        event = self._change_event
        if event is not None:
            _close_handle(event)
        self._change_event = None
        self._change_overlapped = None
        self._change_buffer = None
        self._change_watch_enabled = False

    def _finalize_change_watch(self) -> bool:
        """Drain the exact watch request and return its pre-boundary result.

        A successful exact ``CancelIoEx`` becomes a finite shutdown boundary
        only when this exact request drains with ``ERROR_OPERATION_ABORTED``.
        A normal completion means a notification won its race with that
        cancellation request.  A retired request cannot observe a later
        mutation; this method deliberately makes no no-mutation-through-
        Python-return claim.
        """

        if self._change_event is None and self._change_overlapped is None:
            return False
        if (
            self._handle is None
            or self._change_event is None
            or self._change_overlapped is None
        ):
            raise OSError("directory change watcher is unavailable")
        import ctypes
        from ctypes import wintypes

        kernel32 = _kernel32()
        cancel = kernel32.CancelIoEx
        cancel.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        cancel.restype = wintypes.BOOL
        cancellation_error: OSError | None = None
        if not cancel(wintypes.HANDLE(self._handle), ctypes.byref(self._change_overlapped)):
            error = ctypes.get_last_error()  # type: ignore[attr-defined]
            if error != 1168:  # ERROR_NOT_FOUND: completion raced with cancellation.
                # Even an unexpected cancellation failure leaves the request's
                # lifetime unresolved.  Drain this exact OVERLAPPED before
                # releasing any resource, then re-raise this original error.
                cancellation_error = ctypes.WinError(error)  # type: ignore[attr-defined]

        get_result = kernel32.GetOverlappedResult
        get_result.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.BOOL,
        ]
        get_result.restype = wintypes.BOOL
        transferred = wintypes.DWORD()
        completed = get_result(
            wintypes.HANDLE(self._handle),
            ctypes.byref(self._change_overlapped),
            ctypes.byref(transferred),
            True,
        )
        completion_error: OSError | None = None
        watch_changed = bool(completed)
        if not completed:
            error = ctypes.get_last_error()  # type: ignore[attr-defined]
            if error == 995:  # ERROR_OPERATION_ABORTED: exact cancellation won.
                watch_changed = False
            else:
                completion_error = ctypes.WinError(error)  # type: ignore[attr-defined]
        # A normal return from GetOverlappedResult(..., TRUE) proves this exact
        # operation has completed, including a completed error result.
        try:
            self._release_change_watch()
        except BaseException as release_error:
            if cancellation_error is not None:
                cancellation_error.add_note(
                    "The cancellation error was drained, but watcher resource "
                    "release also failed."
                )
                raise cancellation_error from release_error
            raise
        if cancellation_error is not None:
            raise cancellation_error
        if completion_error is not None:
            raise completion_error
        return watch_changed

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
                error = ctypes.get_last_error()  # type: ignore[attr-defined]
                if error == 18:  # ERROR_NO_MORE_FILES
                    break
                raise ctypes.WinError(error)  # type: ignore[attr-defined]
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
        identity_changed = _identity_from_handle(self._handle) != self.identity
        # The watch result covers a notification that completed before its
        # cancellation boundary; it does not observe mutations after teardown.
        watch_changed = self._finalize_change_watch()
        if identity_changed or watch_changed:
            raise OSError("directory changed while being inspected")

    def close(self) -> None:
        if self._handle is None:
            return
        try:
            watch_changed = self._finalize_change_watch()
        except BaseException as watcher_error:
            # _finalize_change_watch releases its event/buffer/OVERLAPPED only
            # after a proven drain.  If it did, close the directory handle too
            # before preserving its original cancellation/completion error.
            if self._change_event is None:
                handle = self._handle
                try:
                    _close_handle(handle)
                except BaseException as handle_error:
                    # The watcher error remains the primary error; retaining
                    # the live handle permits a later explicit close attempt.
                    watcher_error.add_note(
                        "Directory-handle release also failed: " + str(handle_error)
                    )
                else:
                    self._handle = None
            raise
        handle = self._handle
        _close_handle(handle)
        self._handle = None
        if watch_changed:
            raise OSError("directory changed while being inspected")

    def __enter__(self) -> "DirectoryHandle":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        try:
            self.close()
        except BaseException as cleanup_error:
            if isinstance(_value, BaseException):
                _value.add_note(
                    "Directory cleanup also detected or failed on a change: "
                    f"{cleanup_error}"
                )
                return
            raise


def _close_handle(handle_value: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = _kernel32()
    close = kernel32.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    if not close(wintypes.HANDLE(handle_value)):
        raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]


def open_directory_identity(path: Path, *, watch_changes: bool = False) -> DirectoryHandle:
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
    flags = 0x02000000  # FILE_FLAG_BACKUP_SEMANTICS
    if watch_changes:
        flags |= 0x40000000  # FILE_FLAG_OVERLAPPED
    handle = create_file(
        str(path),
        0x00000001 | 0x00000080,  # FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES
        0x00000001 | 0x00000002 | 0x00000004,  # share read/write/delete
        None,
        3,  # OPEN_EXISTING
        flags,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
    directory: DirectoryHandle | None = None
    try:
        directory = DirectoryHandle(int(handle), None)
        if watch_changes:
            directory.begin_change_watch()
        directory.identity = _identity_from_handle(int(handle))
        return directory
    except BaseException:
        if directory is None:
            _close_handle(int(handle))
        else:
            try:
                directory.close()
            except BaseException:
                # The original open/arm/identity failure already fails closed.
                pass
        raise
