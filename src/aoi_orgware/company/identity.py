"""Pure, read-only inputs for binding an AOI v0.5 company to a repository.

This module deliberately does not create a company, update a registry, or
choose a legacy state tree.  Its outputs are inputs to those later operations:
callers must obtain an explicit user rebind/reconciliation decision before
mutating anything.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
import re
import stat
import subprocess
import sys
import threading
import time
from typing import Iterable, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit


_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
_REMOTE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
_LOCK_DOMAIN_RE = re.compile(r"[a-z][a-z0-9_-]{1,63}\Z")
_CONFIG_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_SCP_REMOTE_RE = re.compile(
    r"(?P<user>[^@/:\s]+@)?(?P<host>\[[^\]\s]+\]|[^/:\s]+):(?P<path>.+)\Z"
)
_WINDOWS_DRIVE_PATH_RE = re.compile(r"[A-Za-z]:[\\/].*\Z")
_MAX_WORKTREES = 4096
_MAX_GIT_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_GIT_ERROR_BYTES = 1024 * 1024
_MAX_GIT_PATH_BYTES = 32768
_MAX_REMOTE_COUNT = 4096
_MAX_REMOTE_URLS_PER_DIRECTION = 256
_MAX_REMOTE_AGGREGATE_BYTES = 8 * 1024 * 1024
_MAX_NATIVE_DECIMAL_DIGITS = 32
_MAX_LEGACY_SOURCES = 65536
_MAX_LEGACY_AGGREGATE_BYTES = 512 * 1024 * 1024
_MAX_LEGACY_OBJECT_ID_BYTES = 512
_MAX_LEGACY_KIND_BYTES = 128
_MAX_LEGACY_CONFLICT_KEY_BYTES = 4096
_MAX_LEGACY_PAYLOAD_BYTES = 64 * 1024 * 1024
_WINDOWS_ILLEGAL_COMPONENT_CHARS = frozenset('<>:"/\\|?*')
_WINDOWS_RESERVED_BASENAMES = frozenset(
    {"con", "prn", "aux", "nul", "clock$"}
    | {f"com{number}" for number in range(1, 10)}
    | {f"lpt{number}" for number in range(1, 10)}
)


class CompanyIdentityError(ValueError):
    """Raised when a read-only identity observation is malformed or ambiguous."""


@dataclass(frozen=True)
class GitWorktree:
    """One row from ``git worktree list --porcelain``."""

    path: str
    head_sha: str | None
    branch: str | None
    detached: bool
    bare: bool
    locked_reason: str | None
    prunable_reason: str | None
    platform: str
    lock_domain: str


@dataclass(frozen=True)
class CompanyBindingInput:
    """Canonical, mutation-free manifest binding input."""

    common_dir: str
    common_dir_sha256: str
    remote_fingerprint_sha256: str
    platform: str
    lock_domain: str
    config_sha256: str

    @property
    def sha256(self) -> str:
        return _sha256_json(
            {
                "schema": "aoi.company.binding-input.v2",
                "common_dir": self.common_dir,
                "common_dir_sha256": self.common_dir_sha256,
                "remote_fingerprint_sha256": self.remote_fingerprint_sha256,
                "platform": self.platform,
                "lock_domain": self.lock_domain,
                "config_sha256": self.config_sha256,
            }
        )


@dataclass(frozen=True)
class LegacyStateCandidate:
    """An observed v0.4 state-root candidate bound to one worktree."""

    worktree: str
    worktree_sha256: str
    state_root: str
    exists: bool
    platform: str
    lock_domain: str


@dataclass(frozen=True)
class LegacyStateSource:
    """Byte-preserving source descriptor supplied by a future legacy reader."""

    object_id: str
    kind: str
    worktree: str
    source_path: str
    payload: bytes
    live: bool = False
    conflict_key: str | None = None
    platform: str = "posix"
    lock_domain: str = "posix"

    @property
    def payload_sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


@dataclass(frozen=True)
class LegacySourceGroup:
    object_id: str
    kind: str
    payload_sha256: str
    sources: tuple[LegacyStateSource, ...]


@dataclass(frozen=True)
class LegacyConflict:
    object_id: str
    kind: str
    reason: str
    sources: tuple[LegacyStateSource, ...]


@dataclass(frozen=True)
class LegacyDeduplication:
    """All groups and all blockers; it intentionally names no preferred source."""

    groups: tuple[LegacySourceGroup, ...]
    conflicts: tuple[LegacyConflict, ...]


@dataclass(frozen=True)
class RebindComparison:
    requires_rebind: bool
    changed_fields: tuple[str, ...]


@dataclass(frozen=True)
class _BoundedCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def _sha256_json(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(raw).hexdigest()


def _native_platform() -> str:
    return "windows" if os.name == "nt" else "posix"


def _require_platform(platform: str | None) -> str:
    value = _native_platform() if platform is None else platform
    if value not in {"windows", "posix"}:
        raise CompanyIdentityError("platform must be exactly 'windows' or 'posix'")
    return value


def _require_lock_domain(lock_domain: str) -> str:
    if not isinstance(lock_domain, str) or _LOCK_DOMAIN_RE.fullmatch(lock_domain) is None:
        raise CompanyIdentityError("lock domain is invalid")
    return lock_domain


def _require_legacy_text(value: object, *, label: str, maximum: int) -> str:
    """Keep untrusted migration descriptors bounded before any ordering/hash use."""

    try:
        encoded = value.encode("utf-8") if isinstance(value, str) else None
    except UnicodeEncodeError as exc:
        raise CompanyIdentityError(f"legacy {label} is invalid") from exc
    if (
        not isinstance(value, str)
        or not value
        or encoded is None
        or len(encoded) > maximum
        or any(ord(char) < 32 for char in value)
    ):
        raise CompanyIdentityError(f"legacy {label} is invalid")
    return value


def _validate_windows_component(component: str, *, label: str) -> str:
    """Validate one Win32 component before canonicalizing its aliases."""

    if not isinstance(component, str):
        raise CompanyIdentityError(f"Windows {label} is invalid")
    trimmed = component.rstrip(" .")
    if (
        not trimmed
        or trimmed in {".", ".."}
        or any(char in _WINDOWS_ILLEGAL_COMPONENT_CHARS for char in trimmed)
        or any(ord(char) < 32 for char in trimmed)
    ):
        raise CompanyIdentityError(f"Windows {label} is invalid")
    basename = trimmed.split(".", 1)[0].rstrip(" ").casefold()
    if basename in _WINDOWS_RESERVED_BASENAMES:
        raise CompanyIdentityError(f"Windows {label} names a reserved device")
    return trimmed.casefold()


def _is_windows_reparse_point(metadata: os.stat_result) -> bool:
    """Fail closed when native Windows cannot classify a reparse point."""

    if os.name != "nt":
        return False
    attributes = getattr(metadata, "st_file_attributes", None)
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", None)
    if not isinstance(attributes, int) or not isinstance(marker, int) or marker == 0:
        raise CompanyIdentityError("Windows reparse-point inspection is unavailable")
    return bool(attributes & marker)


def _assert_native_existing_path_safe(path: Path, *, label: str) -> None:
    """Reject every existing link or reparse component below the native anchor."""

    if not path.is_absolute():
        raise CompanyIdentityError(f"{label} must be absolute")
    # ``lstat`` (rather than ``resolve``/``stat``) keeps a junction or symlink
    # visible.  Missing descendants are allowed for an inventory root, but all
    # extant ancestors, ``.aoi`` roots, and source leaves are inspected.
    for candidate in reversed((path, *path.parents)):
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise CompanyIdentityError(f"cannot inspect {label}: {exc}") from exc
        # Do not call ``Path.is_symlink`` here: current Python releases may
        # perform a second lstat, which both widens the race window and makes
        # this audit needlessly dependent on an implementation detail.
        if stat.S_ISLNK(metadata.st_mode) or _is_windows_reparse_point(metadata):
            raise CompanyIdentityError(f"{label} may not traverse a symlink or Windows reparse point")


def _windows_path_key(value: str, *, absolute: bool) -> str:
    """Pure Windows identity: case-insensitive, with Win32 trailing-dot/space aliases."""

    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise CompanyIdentityError("Windows path is invalid")
    raw = value.replace("\\", "/")
    if raw.startswith(("//?/", "//./")):
        raise CompanyIdentityError("Windows device paths are unsupported")
    path = PureWindowsPath(raw)
    if absolute and not path.is_absolute():
        raise CompanyIdentityError("Windows path must be absolute")
    if not absolute and path.is_absolute():
        raise CompanyIdentityError("Windows path must be relative")
    if not absolute and (":" in raw or raw.startswith("/")):
        raise CompanyIdentityError("Windows path is invalid")
    parts = list(path.parts)
    if absolute:
        if path.drive.startswith("\\\\"):
            # A UNC drive is the complete server/share anchor, not a drive letter.
            anchor_parts = path.drive.replace("\\", "/").strip("/").split("/")
            if len(anchor_parts) != 2:
                raise CompanyIdentityError("Windows UNC path is invalid")
            normalized_anchor: list[str] = []
            for component in anchor_parts:
                try:
                    normalized_anchor.append(_validate_windows_component(component, label="UNC component"))
                except CompanyIdentityError as exc:
                    raise CompanyIdentityError("Windows UNC path is invalid") from exc
            prefix = "//" + "/".join(normalized_anchor)
            parts = parts[1:]
        elif path.drive:
            # ``PureWindowsPath`` accepts non-letter drive prefixes such as
            # ``1:/...`` and ``?:/...``.  Those are not Win32 volume anchors
            # and must never become a stable company identity.
            if re.fullmatch(r"[A-Za-z]:", path.drive) is None:
                raise CompanyIdentityError("Windows drive anchor is invalid")
            prefix = path.drive[0].upper() + ":"
            parts = parts[1:]
        else:
            # PureWindowsPath renders a UNC anchor as \\server\share\.
            anchor = path.anchor.replace("\\", "/").strip("/")
            if not anchor:
                raise CompanyIdentityError("Windows path is invalid")
            anchor_parts = [component for component in anchor.split("/") if component]
            if len(anchor_parts) != 2:
                raise CompanyIdentityError("Windows UNC path is invalid")
            prefix = "//" + "/".join(_validate_windows_component(component, label="UNC component") for component in anchor_parts)
            parts = parts[1:]
    else:
        prefix = ""
    normalized: list[str] = []
    for component in parts:
        if component in {".", ".."}:
            raise CompanyIdentityError("Windows path may not contain dot components")
        normalized.append(_validate_windows_component(component, label="path component"))
    if absolute:
        return prefix + "/" + "/".join(normalized) if prefix.endswith(":") else prefix + ("/" + "/".join(normalized) if normalized else "")
    return "/".join(normalized) or "."


def _posix_path_key(value: str, *, absolute: bool) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise CompanyIdentityError("POSIX path is invalid")
    if "\\" in value:
        raise CompanyIdentityError("POSIX path is invalid")
    path = PurePosixPath(value)
    if absolute != path.is_absolute():
        raise CompanyIdentityError("POSIX path has the wrong absolute form")
    if any(part in {".", ".."} for part in path.parts):
        raise CompanyIdentityError("POSIX path may not contain dot components")
    normalized = path.as_posix().rstrip("/")
    return normalized or ("/" if absolute else ".")


def _path_key(value: str, *, platform: str, absolute: bool) -> str:
    return _windows_path_key(value, absolute=absolute) if platform == "windows" else _posix_path_key(value, absolute=absolute)


def _require_worktree(worktree: str | os.PathLike[str] | Path, *, platform: str | None = None) -> Path:
    """Resolve only a live, native worktree; never reinterpret a foreign path."""

    expected = _require_platform(platform)
    if expected != _native_platform():
        raise CompanyIdentityError("live Git inventory requires the native platform")
    if worktree is None:
        raise CompanyIdentityError("an explicit Git worktree is required")
    path = Path(worktree).expanduser()
    try:
        _path_key(str(path), platform=expected, absolute=True)
    except CompanyIdentityError as exc:
        raise CompanyIdentityError("Git worktree must be an absolute native path") from exc
    if not path.is_absolute() or path.is_symlink():
        raise CompanyIdentityError("Git worktree must be an absolute path")
    _assert_native_existing_path_safe(path, label="Git worktree")
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise CompanyIdentityError(f"cannot resolve Git worktree {path}: {exc}") from exc


def _is_absolute_path(value: str) -> bool:
    """Recognize explicit local paths without allowing CWD-dependent input."""

    return bool(
        isinstance(value, str)
        and value
        and not any(ord(char) < 32 for char in value)
        and (PureWindowsPath(value).is_absolute() or PurePosixPath(value).is_absolute())
    )


def _canonical_worktree_path(value: str, *, platform: str, live_native: bool) -> str:
    """Return a platform identity without applying the host filesystem to foreign paths."""

    try:
        key = _path_key(value, platform=platform, absolute=True)
    except CompanyIdentityError as exc:
        if str(exc) == "Windows device paths are unsupported":
            raise
        raise CompanyIdentityError("Git worktree path must be absolute")
    if not live_native:
        return key
    if platform != _native_platform():
        raise CompanyIdentityError("Git worktree path is foreign to the live host")
    path = Path(value)
    _assert_native_existing_path_safe(path, label="Git worktree")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CompanyIdentityError(f"cannot canonicalize Git worktree path {value}: {exc}") from exc
    return _path_key(str(resolved), platform=platform, absolute=True)


def _normalize_local_remote_path(value: str) -> str:
    """Give local Git remote paths a stable file-URL spelling without I/O."""

    if _WINDOWS_DRIVE_PATH_RE.fullmatch(value):
        return _windows_path_to_file_url(_windows_path_key(value, absolute=True))
    if PureWindowsPath(value).is_absolute() and value.startswith(("\\\\", "//")):
        return _windows_path_to_file_url(_windows_path_key(value, absolute=True))
    if PurePosixPath(value).is_absolute():
        path = str(PurePosixPath(value)).rstrip("/")
        if not path or path == ".":
            raise CompanyIdentityError("Git remote URL path is empty")
        return f"file://{path}"
    raise CompanyIdentityError("Git remote URL must be an absolute transport URL")


def _windows_path_to_file_url(key: str) -> str:
    """Render a validated Windows path identity as one canonical file URL."""

    # A ``.git`` final component is semantic: a bare remote and a sibling
    # non-bare directory can legitimately coexist.  Only a separator spelling
    # is harmless here.
    path = key.rstrip("/")
    if not path or path in {".", "/"} or path.endswith(":"):
        raise CompanyIdentityError("Git remote URL path is empty")
    if path.startswith("//"):
        # ``key`` already carries the server/share anchor as separate,
        # case-folded components.  Preserve that anchor in URL authority.
        return f"file:{path}"
    return f"file:///{path}"


def _normalize_windows_file_url(hostname: str, path: str) -> str:
    """Interpret a non-local file URL as a Windows UNC identity.

    Git's ``file://host/share/path`` notation is the portable spelling of a
    UNC path.  It must therefore use the same Win32 aliases as a native UNC
    path, even when this pure normalization runs on POSIX.
    """

    if not hostname or not path:
        raise CompanyIdentityError("Git remote URL path is empty")
    return _windows_path_to_file_url(_windows_path_key(f"//{hostname}{path}", absolute=True))


def _normalize_url_path(path: str) -> str:
    # Do not collapse ``project`` and ``project.git``.  Git treats these as
    # distinct transport targets; a company binding must do the same.
    normalized = path.rstrip("/")
    if not normalized or normalized == "/":
        raise CompanyIdentityError("Git remote URL path is empty")
    return normalized


def _read_bounded_pipe(
    pipe: object,
    *,
    maximum: int,
    output: list[bytes],
    overflow: threading.Event,
    failed: threading.Event,
    errors: list[BaseException],
    error_lock: threading.Lock,
) -> None:
    chunks: list[bytes] = []
    total = 0
    stream = pipe
    failure: BaseException | None = None
    try:
        while True:
            chunk = stream.read(min(65536, maximum - total + 1))  # type: ignore[attr-defined]
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                overflow.set()
                break
            chunks.append(chunk)
    except BaseException as exc:
        failure = exc
    finally:
        try:
            stream.close()  # type: ignore[attr-defined]
        except BaseException as exc:
            if failure is None:
                failure = exc
    if failure is not None:
        with error_lock:
            errors.append(failure)
        failed.set()
        return
    output.append(b"".join(chunks))


def _run_bounded_command(
    command: Sequence[str],
    *,
    label: str,
    timeout_seconds: float = 10,
    maximum_output_bytes: int | None = None,
) -> _BoundedCommandResult:
    """Capture child output without permitting an unbounded in-memory pipe."""

    stdout_maximum = (
        _MAX_GIT_OUTPUT_BYTES
        if maximum_output_bytes is None
        else maximum_output_bytes
    )
    if (
        not isinstance(stdout_maximum, int)
        or isinstance(stdout_maximum, bool)
        or stdout_maximum < 0
        or stdout_maximum > _MAX_GIT_OUTPUT_BYTES
    ):
        raise CompanyIdentityError(f"cannot {label}: output bound is invalid")
    try:
        process = subprocess.Popen(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise CompanyIdentityError(f"cannot {label}: {exc}") from exc
    if process.stdout is None or process.stderr is None:  # pragma: no cover
        process.kill()
        process.wait()
        raise CompanyIdentityError(f"cannot {label}: subprocess pipes unavailable")

    overflow = threading.Event()
    reader_failed = threading.Event()
    stdout_parts: list[bytes] = []
    stderr_parts: list[bytes] = []
    reader_errors: list[BaseException] = []
    reader_error_lock = threading.Lock()
    readers = (
        threading.Thread(
            target=_read_bounded_pipe,
            kwargs={
                "pipe": process.stdout,
                "maximum": stdout_maximum,
                "output": stdout_parts,
                "overflow": overflow,
                "failed": reader_failed,
                "errors": reader_errors,
                "error_lock": reader_error_lock,
            },
        ),
        threading.Thread(
            target=_read_bounded_pipe,
            kwargs={
                "pipe": process.stderr,
                "maximum": _MAX_GIT_ERROR_BYTES,
                "output": stderr_parts,
                "overflow": overflow,
                "failed": reader_failed,
                "errors": reader_errors,
                "error_lock": reader_error_lock,
            },
        ),
    )
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    try:
        while process.poll() is None:
            if overflow.is_set() or reader_failed.is_set():
                process.kill()
                break
            if time.monotonic() >= deadline:
                timed_out = True
                process.kill()
                break
            time.sleep(0.005)
        process.wait()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        for reader in readers:
            reader.join(timeout=1)
    if any(reader.is_alive() for reader in readers):
        raise CompanyIdentityError(f"cannot {label}: output reader did not terminate")
    if reader_errors:
        failure = reader_errors[0]
        raise CompanyIdentityError(
            f"cannot {label}: output reader failed: "
            f"{type(failure).__name__}: {failure}",
        ) from failure
    if timed_out:
        raise CompanyIdentityError(f"cannot {label}: command timed out")
    if overflow.is_set():
        raise CompanyIdentityError(f"cannot {label}: command output exceeds bound")
    return _BoundedCommandResult(
        int(process.returncode),
        stdout_parts[0] if stdout_parts else b"",
        stderr_parts[0] if stderr_parts else b"",
    )


def _run_git(
    worktree: Path,
    arguments: Sequence[str],
    *,
    maximum_output_bytes: int | None = None,
) -> bytes:
    try:
        result = _run_bounded_command(
            ["git", "-C", str(worktree), *arguments],
            label=f"inspect Git worktree {worktree}",
            maximum_output_bytes=maximum_output_bytes,
        )
    except CompanyIdentityError:
        raise
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise CompanyIdentityError(detail or f"Git inspection failed: {' '.join(arguments)}")
    return result.stdout


def _windows_file_id_info(path: Path) -> tuple[int, bytes]:
    """Read native FileIdInfo for one vetted directory without following its leaf."""

    if os.name != "nt":
        raise CompanyIdentityError("Windows FileIdInfo is unavailable on this host")
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError as exc:  # pragma: no cover - native Windows always has ctypes
        raise CompanyIdentityError("Windows FileIdInfo support is unavailable") from exc

    class _FileId128(ctypes.Structure):
        _fields_ = [("identifier", ctypes.c_ubyte * 16)]

    class _FileIdInfo(ctypes.Structure):
        _fields_ = [("volume_serial_number", ctypes.c_ulonglong), ("file_id", _FileId128)]

    create_file = ctypes.windll.kernel32.CreateFileW  # type: ignore[attr-defined]
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
    get_information = ctypes.windll.kernel32.GetFileInformationByHandleEx  # type: ignore[attr-defined]
    get_information.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
    get_information.restype = wintypes.BOOL
    close_handle = ctypes.windll.kernel32.CloseHandle  # type: ignore[attr-defined]
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    file_read_attributes = 0x00000080
    file_share_read_write_delete = 0x00000007
    open_existing = 3
    file_flag_backup_semantics = 0x02000000
    file_flag_open_reparse_point = 0x00200000
    file_id_info_class = 18
    invalid_handle_value = ctypes.c_void_p(-1).value
    handle = create_file(
        str(path),
        file_read_attributes,
        file_share_read_write_delete,
        None,
        open_existing,
        file_flag_backup_semantics | file_flag_open_reparse_point,
        None,
    )
    if handle == invalid_handle_value:
        error = ctypes.get_last_error()  # type: ignore[attr-defined]
        raise CompanyIdentityError(f"cannot open Git common-dir for FileIdInfo: WinError {error}")
    try:
        info = _FileIdInfo()
        if not get_information(handle, file_id_info_class, ctypes.byref(info), ctypes.sizeof(info)):
            error = ctypes.get_last_error()  # type: ignore[attr-defined]
            raise CompanyIdentityError(f"cannot read Git common-dir FileIdInfo: WinError {error}")
        return int(info.volume_serial_number), bytes(info.file_id.identifier)
    finally:
        if not close_handle(handle):
            # The identity observation is complete, and a close failure must
            # not turn a valid binding into a path-only fallback.
            pass


def _windows_directory_instance_identity(path: Path) -> dict[str, str]:
    volume_serial_number, file_id = _windows_file_id_info(path)
    if (
        not isinstance(volume_serial_number, int)
        or isinstance(volume_serial_number, bool)
        or not 0 <= volume_serial_number < 2**64
        or not isinstance(file_id, bytes)
        or len(file_id) != 16
    ):
        raise CompanyIdentityError("Windows Git common-dir FileIdInfo is malformed")
    return {
        "schema": "aoi.company.directory-instance.windows-file-id.v1",
        "method": "win32-file-id-info",
        "volume_serial_number": f"{volume_serial_number:016x}",
        "file_id": file_id.hex(),
    }


def _linux_directory_generation(fd: int) -> int | None:
    """Return ext-family inode generation, or ``None`` when the ioctl is absent."""

    if not sys.platform.startswith("linux"):
        return None
    try:
        import array
        import fcntl
    except ImportError:  # pragma: no cover - CPython POSIX builds provide both
        return None
    value = array.array("i", [0])
    try:
        fcntl.ioctl(fd, 0x80087601, value, True)  # FS_IOC_GETVERSION
    except OSError:
        return None
    return int(value[0]) & 0xFFFFFFFF


def _linux_statx_birthtime_ns(fd: int) -> int | None:
    """Return immutable ``statx`` btime for an open directory, if available."""

    if not sys.platform.startswith("linux"):
        return None
    try:
        import ctypes
        import platform as platform_module
    except ImportError:  # pragma: no cover - native CPython supplies ctypes
        return None
    syscall_numbers = {"x86_64": 332, "amd64": 332, "aarch64": 291, "arm64": 291}
    syscall_number = syscall_numbers.get(platform_module.machine().lower())
    if syscall_number is None:
        return None

    class _StatxTimestamp(ctypes.Structure):
        _fields_ = [("tv_sec", ctypes.c_longlong), ("tv_nsec", ctypes.c_uint), ("reserved", ctypes.c_int)]

    class _Statx(ctypes.Structure):
        _fields_ = [
            ("stx_mask", ctypes.c_uint),
            ("stx_blksize", ctypes.c_uint),
            ("stx_attributes", ctypes.c_ulonglong),
            ("stx_nlink", ctypes.c_uint),
            ("stx_uid", ctypes.c_uint),
            ("stx_gid", ctypes.c_uint),
            ("stx_mode", ctypes.c_ushort),
            ("spare0", ctypes.c_ushort),
            ("stx_ino", ctypes.c_ulonglong),
            ("stx_size", ctypes.c_ulonglong),
            ("stx_blocks", ctypes.c_ulonglong),
            ("stx_attributes_mask", ctypes.c_ulonglong),
            ("stx_atime", _StatxTimestamp),
            ("stx_btime", _StatxTimestamp),
            ("stx_ctime", _StatxTimestamp),
            ("stx_mtime", _StatxTimestamp),
            ("stx_rdev_major", ctypes.c_uint),
            ("stx_rdev_minor", ctypes.c_uint),
            ("stx_dev_major", ctypes.c_uint),
            ("stx_dev_minor", ctypes.c_uint),
            ("spare3", ctypes.c_ulonglong * 14),
        ]

    buffer = _Statx()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    # AT_EMPTY_PATH binds the birthtime to the no-follow descriptor rather than
    # re-resolving a mutable pathname.  STATX_BTIME is the only requested bit.
    result = libc.syscall(syscall_number, fd, ctypes.c_char_p(b""), 0x1000, 0x0800, ctypes.byref(buffer))
    if result != 0 or not (buffer.stx_mask & 0x0800):
        return None
    seconds = int(buffer.stx_btime.tv_sec)
    nanoseconds = int(buffer.stx_btime.tv_nsec)
    if not 0 <= nanoseconds < 1_000_000_000:
        return None
    return seconds * 1_000_000_000 + nanoseconds


def _posix_directory_instance_identity(path: Path) -> dict[str, str]:
    try:
        flags = os.O_RDONLY
        flags |= getattr(os, "O_DIRECTORY", 0)
        no_follow = getattr(os, "O_NOFOLLOW", None)
        if not isinstance(no_follow, int) or no_follow == 0:
            raise CompanyIdentityError("native Git common-dir no-follow open is unavailable")
        flags |= no_follow
        flags |= getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
    except OSError as exc:
        raise CompanyIdentityError(f"cannot open Git common-dir identity: {exc}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISDIR(metadata.st_mode):
            raise CompanyIdentityError("Git common-dir is not a non-linked directory")
        device = getattr(metadata, "st_dev", None)
        inode = getattr(metadata, "st_ino", None)
        if (
            not isinstance(device, int)
            or isinstance(device, bool)
            or not isinstance(inode, int)
            or isinstance(inode, bool)
            or device < 0
            or inode <= 0
        ):
            raise CompanyIdentityError("native Git common-dir instance identity is unavailable")
        major_function = getattr(os, "major", None)
        minor_function = getattr(os, "minor", None)
        if not callable(major_function) or not callable(minor_function):
            raise CompanyIdentityError("POSIX device-number decoding is unavailable")
        major, minor = major_function(device), minor_function(device)
        generation = _linux_directory_generation(fd)
        if generation is not None:
            return {
                "schema": "aoi.company.directory-instance.posix-dev-inode-generation.v1",
                "method": "linux-fs-ioc-getversion",
                "device_major": str(major),
                "device_minor": str(minor),
                "inode": str(inode),
                "generation": str(generation),
            }
        birthtime_ns = _linux_statx_birthtime_ns(fd)
        birthtime_method = "linux-statx-btime"
        if birthtime_ns is None:
            observed_birthtime = getattr(metadata, "st_birthtime_ns", None)
            if isinstance(observed_birthtime, int) and not isinstance(observed_birthtime, bool) and observed_birthtime >= 0:
                birthtime_ns = observed_birthtime
                birthtime_method = "native-st-birthtime-ns"
        if birthtime_ns is None:
            raise CompanyIdentityError("native Git common-dir generation or immutable birthtime is unavailable")
        return {
            "schema": "aoi.company.directory-instance.posix-dev-inode-birthtime.v1",
            "method": birthtime_method,
            "device_major": str(major),
            "device_minor": str(minor),
            "inode": str(inode),
            "birthtime_ns": str(birthtime_ns),
        }
    finally:
        os.close(fd)


def _directory_instance_identity(path: Path, *, platform: str) -> dict[str, str]:
    """Return a strict v5 native directory identity without mutable timestamps."""

    if platform == "windows":
        return _windows_directory_instance_identity(path)
    if platform != "posix":
        raise CompanyIdentityError("native Git common-dir platform identity is unavailable")
    return _posix_directory_instance_identity(path)


def git_common_dir_identity(worktree: str | os.PathLike[str] | Path) -> dict[str, object]:
    """Return a canonical identity for one explicit worktree's Git common-dir."""

    platform = _native_platform()
    root = _require_worktree(worktree, platform=platform)
    try:
        raw = _run_git(root, ("rev-parse", "--path-format=absolute", "--git-common-dir"))
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise CompanyIdentityError("Git common-dir is not UTF-8") from exc
    if (
        not text
        or len(text.encode("utf-8")) > _MAX_GIT_PATH_BYTES
        or "\x00" in text
        or "\n" in text
        or "\r" in text
    ):
        raise CompanyIdentityError("Git common-dir is malformed")
    common_dir = Path(text)
    try:
        _path_key(text, platform=platform, absolute=True)
    except CompanyIdentityError as exc:
        raise CompanyIdentityError("Git common-dir must be absolute native path") from exc
    # Check the raw path before resolution.  Resolving first would erase a
    # symlink/junction hop from the evidence that binds this company.
    _assert_native_existing_path_safe(common_dir, label="Git common-dir")
    try:
        canonical = common_dir.resolve(strict=True)
    except OSError as exc:
        raise CompanyIdentityError(f"cannot resolve Git common-dir {common_dir}: {exc}") from exc
    if not canonical.is_dir():
        raise CompanyIdentityError("Git common-dir is not a directory")
    instance = _directory_instance_identity(canonical, platform=platform)
    value = _path_key(str(canonical), platform=platform, absolute=True)
    identity: dict[str, object] = {
        "schema": "aoi.company.git-common-dir.v5",
        "common_dir": value,
        "directory_instance": instance,
        "platform": platform,
    }
    return {
        **identity,
        "common_dir": value,
        "common_dir_sha256": _sha256_json(identity),
    }


def normalize_remote_url(value: str) -> str:
    """Normalize harmless spelling differences without resolving or contacting a remote."""

    if not isinstance(value, str) or not value or len(value) > 2048:
        raise CompanyIdentityError("Git remote URL is invalid")
    if any(ord(char) < 32 for char in value):
        raise CompanyIdentityError("Git remote URL is invalid")
    # A native Windows local path may intentionally contain a trailing Win32
    # alias (dot/space).  Keep its exact bytes for the Windows identity helper;
    # URL spellings themselves still reject whitespace and ambiguous trimming.
    if "://" not in value and _is_absolute_path(value):
        return _normalize_local_remote_path(value)
    candidate = value.strip()
    if candidate != value or not candidate or any(char.isspace() for char in candidate):
        raise CompanyIdentityError("Git remote URL is invalid")
    scp = _SCP_REMOTE_RE.fullmatch(candidate)
    if scp and "://" not in candidate:
        user = scp.group("user") or ""
        raw_host = scp.group("host")
        bracketed = raw_host.startswith("[") and raw_host.endswith("]")
        host = raw_host[1:-1] if bracketed else raw_host
        rendered_host = f"[{host.lower()}]" if bracketed else host.lower()
        return f"ssh://{user}{rendered_host}/{_normalize_url_path(scp.group('path'))}"
    parsed = urlsplit(candidate)
    if not parsed.scheme or parsed.fragment or parsed.query:
        raise CompanyIdentityError("Git remote URL must be an absolute transport URL")
    if parsed.scheme.lower() == "file":
        if parsed.username is not None or parsed.password is not None:
            raise CompanyIdentityError("Git remote URL may not embed credentials")
        try:
            port_value = parsed.port
        except ValueError as exc:
            raise CompanyIdentityError("Git remote URL port is invalid") from exc
        if port_value is not None:
            raise CompanyIdentityError("file Git remote URL may not contain a port")
        hostname = parsed.hostname
        if hostname is not None and hostname.lower() not in {"localhost"}:
            return _normalize_windows_file_url(hostname, parsed.path)
        file_path = parsed.path
        if re.fullmatch(r"/[A-Za-z]:/.*", file_path):
            file_path = file_path[1:]
        return _normalize_local_remote_path(file_path)
    if not parsed.netloc:
        raise CompanyIdentityError("Git remote URL must be an absolute transport URL")
    hostname = parsed.hostname
    if hostname is None:
        raise CompanyIdentityError("Git remote URL host is invalid")
    userinfo = ""
    if parsed.password is not None:
        raise CompanyIdentityError("Git remote URL may not embed a password")
    if parsed.username is not None:
        userinfo = parsed.username
        userinfo += "@"
    try:
        port_value = parsed.port
    except ValueError as exc:
        raise CompanyIdentityError("Git remote URL port is invalid") from exc
    port = f":{port_value}" if port_value is not None else ""
    rendered_host = f"[{hostname.lower()}]" if ":" in hostname else hostname.lower()
    return urlunsplit(
        (
            parsed.scheme.lower(),
            f"{userinfo}{rendered_host}{port}",
            _normalize_url_path(parsed.path),
            "",
            "",
        )
    )


def _bounded_remote_urls(value: object, *, label: str) -> tuple[str, ...]:
    if isinstance(value, str):
        values: Sequence[object] = (value,)
    elif (
        isinstance(value, Sequence)
        and not isinstance(value, (bytes, bytearray, memoryview))
    ):
        values = value
    else:
        raise CompanyIdentityError(f"{label} URLs are invalid")
    if not values or len(values) > _MAX_REMOTE_URLS_PER_DIRECTION:
        raise CompanyIdentityError(f"{label} URL count exceeds bound")
    if not all(isinstance(url, str) for url in values):
        raise CompanyIdentityError(f"{label} URLs are invalid")
    return tuple(url for url in values if isinstance(url, str))


def _consume_remote_utf8_bytes(total: int, value: str) -> int:
    """Apply the aggregate bound before allocating a normalized copy."""

    remaining = _MAX_REMOTE_AGGREGATE_BYTES - total
    if remaining < 0 or len(value) > remaining:
        raise CompanyIdentityError("Git remote aggregate bytes exceed bound")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise CompanyIdentityError("Git remote value is not valid UTF-8") from exc
    if size > remaining:
        raise CompanyIdentityError("Git remote aggregate bytes exceed bound")
    return total + size


def _remote_rows(remotes: Mapping[str, object]) -> list[dict[str, object]]:
    """Canonicalize fetch and effective push targets without losing pushurl provenance."""

    if not isinstance(remotes, Mapping):
        raise CompanyIdentityError("Git remotes must be a mapping")
    if len(remotes) > _MAX_REMOTE_COUNT:
        raise CompanyIdentityError("Git remote count exceeds bound")
    rows: list[dict[str, object]] = []
    raw_aggregate_bytes = 0
    canonical_aggregate_bytes = 0
    for name, observation in remotes.items():
        if not isinstance(name, str) or _REMOTE_NAME_RE.fullmatch(name) is None:
            raise CompanyIdentityError("Git remote name is invalid")
        raw_aggregate_bytes = _consume_remote_utf8_bytes(
            raw_aggregate_bytes,
            name,
        )
        if isinstance(observation, Mapping):
            if set(observation) != {"fetch", "push", "pushurl_configured"}:
                raise CompanyIdentityError(f"Git remote {name!r} observation is invalid")
            fetch, push, configured = observation["fetch"], observation["push"], observation["pushurl_configured"]
            if not isinstance(configured, bool):
                raise CompanyIdentityError(f"Git remote {name!r} pushurl provenance is invalid")
        else:
            # Compatibility input is explicit about the semantic fallback, not a v1 manifest.
            fetch, push, configured = observation, observation, False
        bounded_fetch = _bounded_remote_urls(
            fetch, label=f"Git remote {name!r} fetch",
        )
        bounded_push = _bounded_remote_urls(
            push, label=f"Git remote {name!r} push",
        )
        for url in bounded_fetch:
            raw_aggregate_bytes = _consume_remote_utf8_bytes(
                raw_aggregate_bytes,
                url,
            )
        for url in bounded_push:
            raw_aggregate_bytes = _consume_remote_utf8_bytes(
                raw_aggregate_bytes,
                url,
            )
        normalized_fetch = sorted({normalize_remote_url(url) for url in bounded_fetch})
        normalized_push = sorted({normalize_remote_url(url) for url in bounded_push})
        if not normalized_fetch or not normalized_push:
            raise CompanyIdentityError(f"Git remote {name!r} has no effective fetch/push URLs")
        if not configured and normalized_push != normalized_fetch:
            raise CompanyIdentityError(f"Git remote {name!r} has an invalid unset-push fallback")
        canonical_aggregate_bytes = _consume_remote_utf8_bytes(
            canonical_aggregate_bytes,
            name,
        )
        for url in normalized_fetch:
            canonical_aggregate_bytes = _consume_remote_utf8_bytes(
                canonical_aggregate_bytes,
                url,
            )
        for url in normalized_push:
            canonical_aggregate_bytes = _consume_remote_utf8_bytes(
                canonical_aggregate_bytes,
                url,
            )
        rows.append(
            {
                "name": name,
                "fetch_urls": normalized_fetch,
                "push_urls": normalized_push,
                "pushurl_configured": configured,
            }
        )
    return sorted(rows, key=lambda row: str(row["name"]))


def normalized_remote_fingerprint(remotes: Mapping[str, object]) -> dict[str, object]:
    """Return a deterministic v3 fingerprint for fetch, push, and pushurl fallback state."""

    canonical = {"schema": "aoi.company.remote-fingerprint.v3", "remotes": _remote_rows(remotes)}
    return {**canonical, "sha256": _sha256_json(canonical)}


def observed_remote_fingerprint(worktree: str | os.PathLike[str] | Path) -> dict[str, object]:
    """Read remote URLs from one explicit worktree without network access."""

    root = _require_worktree(worktree)
    try:
        names_output = _run_git(
            root,
            ("remote",),
            maximum_output_bytes=_MAX_REMOTE_AGGREGATE_BYTES,
        )
        observed_bytes = len(names_output)
        names = names_output.decode("utf-8", "strict").splitlines()
        if len(names) > _MAX_REMOTE_COUNT:
            raise CompanyIdentityError("Git remote count exceeds bound")
        remotes: dict[str, object] = {}
        for name in names:
            if _REMOTE_NAME_RE.fullmatch(name) is None:
                raise CompanyIdentityError("Git remote name is invalid")
            remaining = _MAX_REMOTE_AGGREGATE_BYTES - observed_bytes
            fetch_output = _run_git(
                root,
                ("remote", "get-url", "--all", name),
                maximum_output_bytes=remaining,
            )
            observed_bytes += len(fetch_output)
            fetch = fetch_output.decode("utf-8", "strict").splitlines()
            remaining = _MAX_REMOTE_AGGREGATE_BYTES - observed_bytes
            push_output = _run_git(
                root,
                ("remote", "get-url", "--push", "--all", name),
                maximum_output_bytes=remaining,
            )
            observed_bytes += len(push_output)
            push = push_output.decode("utf-8", "strict").splitlines()
            remaining = _MAX_REMOTE_AGGREGATE_BYTES - observed_bytes
            configured = _run_bounded_command(
                [
                    "git", "-C", str(root), "config", "--get-all",
                    f"remote.{name}.pushurl",
                ],
                label=f"inspect pushurl for remote {name!r}",
                maximum_output_bytes=remaining,
            )
            observed_bytes += len(configured.stdout)
            if configured.returncode not in {0, 1}:
                detail = configured.stderr.decode("utf-8", "replace").strip()
                raise CompanyIdentityError(detail or f"cannot inspect pushurl for remote {name!r}")
            if configured.returncode == 0:
                configured_push = configured.stdout.decode("utf-8", "strict").splitlines()
                if not configured_push:
                    raise CompanyIdentityError(f"Git remote {name!r} has an empty pushurl")
                # Git's effective push result must agree with the configured transport.
                if sorted({normalize_remote_url(url) for url in configured_push}) != sorted({normalize_remote_url(url) for url in push}):
                    raise CompanyIdentityError(f"Git remote {name!r} pushurl observation is ambiguous")
            remotes[name] = {"fetch": fetch, "push": push, "pushurl_configured": configured.returncode == 0}
    except UnicodeDecodeError as exc:
        raise CompanyIdentityError("Git remote observation is not UTF-8") from exc
    return normalized_remote_fingerprint(remotes)


def _canonical_decimal(value: object, *, positive: bool = False, signed: bool = False) -> bool:
    if (
        not isinstance(value, str)
        or len(value) > _MAX_NATIVE_DECIMAL_DIGITS
        or value == "-0"
    ):
        return False
    pattern = r"-?(?:0|[1-9][0-9]*)" if signed else r"(?:0|[1-9][0-9]*)"
    if re.fullmatch(pattern, value) is None:
        return False
    return not positive or value != "0"


def _valid_directory_instance(instance: object, *, platform: str) -> bool:
    if not isinstance(instance, Mapping):
        return False
    if platform == "windows":
        return (
            set(instance) == {"schema", "method", "volume_serial_number", "file_id"}
            and instance.get("schema") == "aoi.company.directory-instance.windows-file-id.v1"
            and instance.get("method") == "win32-file-id-info"
            and isinstance(instance.get("volume_serial_number"), str)
            and re.fullmatch(r"[0-9a-f]{16}", instance["volume_serial_number"]) is not None
            and isinstance(instance.get("file_id"), str)
            and re.fullmatch(r"[0-9a-f]{32}", instance["file_id"]) is not None
        )
    generation_shape = {
        "schema",
        "method",
        "device_major",
        "device_minor",
        "inode",
        "generation",
    }
    birthtime_shape = generation_shape - {"generation"} | {"birthtime_ns"}
    if set(instance) == generation_shape:
        return (
            instance.get("schema") == "aoi.company.directory-instance.posix-dev-inode-generation.v1"
            and instance.get("method") == "linux-fs-ioc-getversion"
            and _canonical_decimal(instance.get("device_major"))
            and _canonical_decimal(instance.get("device_minor"))
            and _canonical_decimal(instance.get("inode"), positive=True)
            and _canonical_decimal(instance.get("generation"))
        )
    return (
        set(instance) == birthtime_shape
        and instance.get("schema") == "aoi.company.directory-instance.posix-dev-inode-birthtime.v1"
        and instance.get("method") in {"linux-statx-btime", "native-st-birthtime-ns"}
        and _canonical_decimal(instance.get("device_major"))
        and _canonical_decimal(instance.get("device_minor"))
        and _canonical_decimal(instance.get("inode"), positive=True)
        and _canonical_decimal(instance.get("birthtime_ns"), signed=True)
    )


def company_binding_input(
    common_dir: Mapping[str, object],
    remote_fingerprint: Mapping[str, object],
    *,
    platform: str,
    lock_domain: str,
    config_sha256: str,
) -> CompanyBindingInput:
    """Compose the manifest binding inputs; this does not allocate a company ID."""

    if not isinstance(common_dir, Mapping) or not isinstance(remote_fingerprint, Mapping):
        raise CompanyIdentityError("company binding inputs must be mappings")
    path = common_dir.get("common_dir")
    common_digest = common_dir.get("common_dir_sha256")
    common_platform = common_dir.get("platform")
    remote_digest = remote_fingerprint.get("sha256")
    platform = _require_platform(platform)
    instance = common_dir.get("directory_instance")
    if common_dir.get("schema") != "aoi.company.git-common-dir.v5" or common_platform != platform:
        raise CompanyIdentityError("Git common-dir platform identity is invalid")
    try:
        canonical_path = _path_key(path, platform=platform, absolute=True) if isinstance(path, str) else None
    except CompanyIdentityError:
        canonical_path = None
    if not isinstance(path, str) or canonical_path != path:
        raise CompanyIdentityError("Git common-dir identity is invalid")
    if not isinstance(common_digest, str) or _CONFIG_DIGEST_RE.fullmatch(common_digest) is None:
        raise CompanyIdentityError("Git common-dir digest is invalid")
    if (
        not isinstance(instance, Mapping)
        or not _valid_directory_instance(instance, platform=platform)
    ):
        raise CompanyIdentityError("Git common-dir native instance identity is invalid")
    canonical_common = {
        "schema": "aoi.company.git-common-dir.v5",
        "common_dir": path,
        "directory_instance": dict(instance),
        "platform": platform,
    }
    if common_digest != _sha256_json(canonical_common):
        raise CompanyIdentityError("Git common-dir digest does not bind its native instance")
    if not isinstance(remote_digest, str) or _CONFIG_DIGEST_RE.fullmatch(remote_digest) is None:
        raise CompanyIdentityError("remote fingerprint digest is invalid")
    remote_schema = remote_fingerprint.get("schema")
    remote_rows = remote_fingerprint.get("remotes")
    if remote_schema != "aoi.company.remote-fingerprint.v3" or not isinstance(remote_rows, list):
        raise CompanyIdentityError("remote fingerprint is invalid")
    if len(remote_rows) > _MAX_REMOTE_COUNT:
        raise CompanyIdentityError("Git remote count exceeds bound")
    remotes: dict[str, object] = {}
    aggregate_bytes = 0
    for row in remote_rows:
        if not isinstance(row, Mapping) or set(row) != {"name", "fetch_urls", "push_urls", "pushurl_configured"}:
            raise CompanyIdentityError("remote fingerprint rows are invalid")
        name = row.get("name")
        fetch = row.get("fetch_urls")
        push = row.get("push_urls")
        configured = row.get("pushurl_configured")
        if not isinstance(name, str) or not isinstance(fetch, list) or not isinstance(push, list) or not isinstance(configured, bool) or name in remotes:
            raise CompanyIdentityError("remote fingerprint rows are invalid")
        if (
            not fetch
            or len(fetch) > _MAX_REMOTE_URLS_PER_DIRECTION
            or not push
            or len(push) > _MAX_REMOTE_URLS_PER_DIRECTION
        ):
            raise CompanyIdentityError("remote fingerprint rows are invalid")
        aggregate_bytes = _consume_remote_utf8_bytes(aggregate_bytes, name)
        for urls in (fetch, push):
            for url in urls:
                if not isinstance(url, str):
                    raise CompanyIdentityError("remote fingerprint rows are invalid")
                aggregate_bytes = _consume_remote_utf8_bytes(
                    aggregate_bytes,
                    url,
                )
        remotes[name] = {"fetch": fetch, "push": push, "pushurl_configured": configured}
    canonical_remote = normalized_remote_fingerprint(remotes)
    if remote_rows != canonical_remote["remotes"] or remote_digest != canonical_remote["sha256"]:
        raise CompanyIdentityError("remote fingerprint must use canonical rows and digest")
    lock_domain = _require_lock_domain(lock_domain)
    if not isinstance(config_sha256, str) or _CONFIG_DIGEST_RE.fullmatch(config_sha256) is None:
        raise CompanyIdentityError("configuration digest is invalid")
    return CompanyBindingInput(path, common_digest, remote_digest, platform, lock_domain, config_sha256)


def company_state_root(
    company_id: str,
    *,
    platform: str,
    environ: Mapping[str, str],
) -> PurePath:
    """Select the repo-external root for an explicitly named platform domain."""

    if not isinstance(company_id, str) or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,127}", company_id) is None:
        raise CompanyIdentityError("company ID is invalid")
    platform = _require_platform(platform)
    if platform == "windows":
        # The public ID grammar excludes dots and spaces, so this catches every
        # remaining Win32 reserved-device spelling without reinterpreting IDs.
        _validate_windows_component(company_id, label="company ID")
    if not isinstance(environ, Mapping):
        raise CompanyIdentityError("state-root environment is invalid")
    if platform == "windows":
        base = environ.get("LOCALAPPDATA")
        if not isinstance(base, str) or not base:
            raise CompanyIdentityError("LOCALAPPDATA is required for the Windows state root")
        try:
            base_key = _windows_path_key(base, absolute=True)
        except CompanyIdentityError as exc:
            raise CompanyIdentityError("LOCALAPPDATA must be an absolute local Windows path") from exc
        if base_key.startswith("//"):
            raise CompanyIdentityError("LOCALAPPDATA may not be a UNC or network path")
        root: PurePath = PureWindowsPath(base_key) / "AOI" / "companies"
    else:
        xdg_base = environ.get("XDG_STATE_HOME")
        home_base = environ.get("HOME")
        base = xdg_base if xdg_base else home_base
        if not isinstance(base, str) or not base:
            raise CompanyIdentityError("XDG_STATE_HOME or HOME is required for the POSIX state root")
        try:
            base_key = _posix_path_key(base, absolute=True)
        except CompanyIdentityError as exc:
            raise CompanyIdentityError("company state root base must be absolute and traversal-free") from exc
        if base.startswith("//"):
            raise CompanyIdentityError("company state root base may not use a double-slash anchor")
        root = PurePosixPath(base_key) / ("aoi" if xdg_base else ".local/state/aoi") / "companies"
    return root / company_id


def parse_git_worktree_porcelain(
    raw: bytes | str, *, platform: str | None = None, lock_domain: str | None = None, live_native: bool = False
) -> tuple[GitWorktree, ...]:
    """Strictly parse read-only ``git worktree list --porcelain`` output."""

    platform = _require_platform(platform)
    lock_domain = _require_lock_domain(lock_domain or platform)
    if live_native and platform != _native_platform():
        raise CompanyIdentityError("live Git inventory requires the native platform")
    if isinstance(raw, bytes):
        if len(raw) > _MAX_GIT_OUTPUT_BYTES:
            raise CompanyIdentityError("Git worktree porcelain exceeds byte bound")
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise CompanyIdentityError("Git worktree porcelain is not UTF-8") from exc
    elif isinstance(raw, str):
        try:
            if len(raw.encode("utf-8")) > _MAX_GIT_OUTPUT_BYTES:
                raise CompanyIdentityError("Git worktree porcelain exceeds byte bound")
        except UnicodeEncodeError as exc:
            raise CompanyIdentityError("Git worktree porcelain is not UTF-8") from exc
        text = raw
    else:
        raise CompanyIdentityError("Git worktree porcelain must be bytes or text")
    groups = [group for group in text.replace("\r\n", "\n").split("\n\n") if group]
    if not groups or len(groups) > _MAX_WORKTREES:
        raise CompanyIdentityError("Git worktree porcelain has an invalid record count")
    result: list[GitWorktree] = []
    seen_paths: set[str] = set()
    for group in groups:
        fields: dict[str, str | bool] = {}
        for line in group.splitlines():
            key, separator, value = line.partition(" ")
            if not separator:
                value = ""
            if key not in {"worktree", "HEAD", "branch", "detached", "bare", "locked", "prunable"} or key in fields:
                raise CompanyIdentityError("Git worktree porcelain is malformed or ambiguous")
            if key in {"detached", "bare"} and value:
                raise CompanyIdentityError("Git worktree porcelain flag has a value")
            fields[key] = True if key in {"detached", "bare"} else value
        path = fields.get("worktree")
        if (
            not isinstance(path, str)
            or not path
            or len(path.encode("utf-8")) > _MAX_GIT_PATH_BYTES
            or any(ord(char) < 32 for char in path)
        ):
            raise CompanyIdentityError("Git worktree path is invalid")
        head = fields.get("HEAD")
        prunable = fields.get("prunable")
        bare = fields.get("bare") is True
        if head is not None and (not isinstance(head, str) or _HEX_RE.fullmatch(head) is None):
            raise CompanyIdentityError("Git worktree HEAD is invalid")
        if bare:
            if any(key in fields for key in {"HEAD", "branch", "detached", "locked", "prunable"}):
                raise CompanyIdentityError("bare Git worktree has incompatible topology markers")
        elif head is None:
            raise CompanyIdentityError("Git worktree porcelain lacks HEAD")
        branch = fields.get("branch")
        detached = fields.get("detached") is True
        if branch is not None:
            if not isinstance(branch, str) or not branch.startswith("refs/heads/"):
                raise CompanyIdentityError("Git worktree branch is invalid")
            try:
                _validate_git_refname(branch.removeprefix("refs/heads/"))
            except CompanyIdentityError as exc:
                raise CompanyIdentityError("Git worktree branch is invalid") from exc
        if branch is not None and detached:
            raise CompanyIdentityError("Git worktree cannot be both branch and detached")
        if not bare and branch is None and not detached:
            raise CompanyIdentityError("Git worktree must be branch-attached or detached")
        if "locked" in fields and "prunable" in fields:
            raise CompanyIdentityError("Git worktree cannot be both locked and prunable")
        if isinstance(prunable, str) and not prunable:
            raise CompanyIdentityError("Git worktree prunable marker lacks a reason")
        canonical_path = _canonical_worktree_path(path, platform=platform, live_native=live_native)
        if canonical_path in seen_paths:
            raise CompanyIdentityError("Git worktree porcelain contains duplicate paths")
        seen_paths.add(canonical_path)
        locked_value = fields.get("locked")
        locked_reason = locked_value if isinstance(locked_value, str) else None
        result.append(
            GitWorktree(
                canonical_path,
                head if isinstance(head, str) else None,
                branch if isinstance(branch, str) else None,
                detached,
                bare,
                locked_reason,
                prunable if isinstance(prunable, str) else None,
                platform,
                lock_domain,
            )
        )
    return tuple(sorted(result, key=lambda entry: entry.path))


def git_worktree_inventory(worktree: str | os.PathLike[str] | Path) -> tuple[GitWorktree, ...]:
    """Inventory every linked worktree for the common repository, read-only."""

    platform = _native_platform()
    return parse_git_worktree_porcelain(
        _run_git(_require_worktree(worktree, platform=platform), ("worktree", "list", "--porcelain")),
        platform=platform,
        lock_domain=platform,
        live_native=True,
    )


def legacy_aoi_state_candidates(
    worktrees: Iterable[GitWorktree | str | os.PathLike[str] | Path], *, state_dir: str = ".aoi", platform: str | None = None, lock_domain: str | None = None
) -> tuple[LegacyStateCandidate, ...]:
    """Inventory every legacy state location without selecting or reading one."""

    if not isinstance(state_dir, str) or state_dir != ".aoi":
        raise CompanyIdentityError("legacy state directory must be the exact '.aoi' name")
    platform = _require_platform(platform)
    lock_domain = _require_lock_domain(lock_domain or platform)
    candidates: list[LegacyStateCandidate] = []
    seen: set[str] = set()
    for index, value in enumerate(worktrees):
        if index >= _MAX_WORKTREES:
            raise CompanyIdentityError("legacy worktree inventory exceeds bound")
        if isinstance(value, GitWorktree) and (value.platform != platform or value.lock_domain != lock_domain):
            raise CompanyIdentityError("legacy worktree belongs to another platform or lock domain")
        raw_path = value.path if isinstance(value, GitWorktree) else value
        root = _require_worktree(raw_path, platform=platform)
        canonical = _path_key(str(root), platform=platform, absolute=True)
        if canonical in seen:
            raise CompanyIdentityError("legacy worktree inventory contains duplicate paths")
        seen.add(canonical)
        state_root = root / state_dir
        _assert_native_existing_path_safe(root, label="legacy worktree")
        _assert_native_existing_path_safe(state_root, label="legacy state root")
        if state_root.is_symlink():
            raise CompanyIdentityError("legacy state root may not be a symlink")
        state_key = _path_key(str(state_root), platform=platform, absolute=True)
        candidates.append(LegacyStateCandidate(canonical, hashlib.sha256(canonical.encode("utf-8")).hexdigest(), state_key, state_root.is_dir(), platform, lock_domain))
    if not candidates:
        raise CompanyIdentityError("legacy worktree inventory is empty")
    return tuple(sorted(candidates, key=lambda candidate: candidate.worktree))


def deduplicate_legacy_sources(sources: Iterable[LegacyStateSource]) -> LegacyDeduplication:
    """Group byte-identical legacy records and surface every divergence/conflict."""

    buckets: dict[tuple[str, str], list[LegacyStateSource]] = {}
    seen_roots: set[tuple[str, str, str]] = set()
    seen_source_paths: set[tuple[str, str, str]] = set()
    aggregate_bytes = 0
    for index, source in enumerate(sources):
        if index >= _MAX_LEGACY_SOURCES:
            raise CompanyIdentityError("legacy source count exceeds bound")
        if not isinstance(source, LegacyStateSource):
            raise CompanyIdentityError("legacy source is invalid")
        object_id = _require_legacy_text(source.object_id, label="object ID", maximum=_MAX_LEGACY_OBJECT_ID_BYTES)
        kind = _require_legacy_text(source.kind, label="kind", maximum=_MAX_LEGACY_KIND_BYTES)
        worktree_text = _require_legacy_text(
            source.worktree, label="worktree", maximum=_MAX_GIT_PATH_BYTES,
        )
        source_path_text = _require_legacy_text(
            source.source_path, label="source path", maximum=_MAX_GIT_PATH_BYTES,
        )
        if not isinstance(source.payload, bytes) or len(source.payload) > _MAX_LEGACY_PAYLOAD_BYTES:
            raise CompanyIdentityError("legacy payload must be immutable bounded bytes")
        if not isinstance(source.live, bool):
            raise CompanyIdentityError("legacy live flag is invalid")
        if source.conflict_key is not None:
            conflict_key = _require_legacy_text(
                source.conflict_key,
                label="conflict key",
                maximum=_MAX_LEGACY_CONFLICT_KEY_BYTES,
            )
        else:
            conflict_key = ""
        aggregate_bytes += sum(
            len(member.encode("utf-8"))
            for member in (
                object_id, kind, worktree_text, source_path_text, conflict_key,
            )
        ) + len(source.payload)
        if aggregate_bytes > _MAX_LEGACY_AGGREGATE_BYTES:
            raise CompanyIdentityError("legacy source aggregate bytes exceed bound")
        platform = _require_platform(source.platform)
        lock_domain = _require_lock_domain(source.lock_domain)
        worktree_key = _path_key(source.worktree, platform=platform, absolute=True)
        source_key = _path_key(source.source_path, platform=platform, absolute=True)
        if platform == _native_platform() and (Path(source.worktree).is_symlink() or Path(source.source_path).is_symlink()):
            raise CompanyIdentityError("legacy state source may not be a symlink")
        if platform == _native_platform():
            _assert_native_existing_path_safe(Path(source.worktree), label="legacy worktree")
            _assert_native_existing_path_safe(Path(source.source_path), label="legacy state source")
        root_identity = (platform, lock_domain, worktree_key)
        path_identity = (platform, lock_domain, source_key)
        if source.worktree != worktree_key:
            raise CompanyIdentityError("legacy worktree uses a non-canonical alias")
        if source.source_path != source_key:
            raise CompanyIdentityError("legacy state source uses a non-canonical alias")
        state_root_key = f"{worktree_key.rstrip('/')}/.aoi"
        if not _strict_scope_descendant(source_key, state_root_key):
            raise CompanyIdentityError("legacy state source must be below its worktree .aoi root")
        if root_identity in seen_roots and path_identity in seen_source_paths:
            raise CompanyIdentityError("legacy state inventory contains duplicate canonical roots")
        seen_roots.add(root_identity)
        seen_source_paths.add(path_identity)
        buckets.setdefault((object_id, kind), []).append(source)
    groups: list[LegacySourceGroup] = []
    conflicts: list[LegacyConflict] = []
    for (object_id, kind), members in sorted(buckets.items()):
        ordered = tuple(sorted(members, key=lambda item: (item.worktree, item.source_path)))
        digests = {member.payload_sha256 for member in ordered}
        if len(digests) != 1:
            conflicts.append(LegacyConflict(object_id, kind, "divergent_bytes", ordered))
            continue
        groups.append(LegacySourceGroup(object_id, kind, next(iter(digests)), ordered))
        if len(ordered) > 1 and any(member.live for member in ordered) and kind in {"claim", "chief_authority"}:
            conflicts.append(LegacyConflict(object_id, kind, "conflicting_live_records", ordered))
    live_authorities = tuple(
        sorted(
            (item for members in buckets.values() for item in members if item.live and item.kind == "chief_authority"),
            key=lambda item: (item.worktree, item.source_path),
        )
    )
    if len(live_authorities) > 1:
        conflicts.append(LegacyConflict("<live>", "chief_authority", "conflicting_live_authorities", live_authorities))
    live_claims: list[tuple[LegacyStateSource, str]] = []
    for members in buckets.values():
        for item in members:
            if not item.live or item.kind != "claim":
                continue
            try:
                scope = _canonical_claim_scope(item.conflict_key, platform=item.platform, lock_domain=item.lock_domain)
            except CompanyIdentityError:
                conflicts.append(LegacyConflict(item.object_id, "claim", "missing_or_invalid_live_claim_scope", (item,)))
            else:
                live_claims.append((item, scope))
    for index, (left, left_scope) in enumerate(live_claims):
        for right, right_scope in live_claims[index + 1 :]:
            if _claim_scopes_overlap(left_scope, right_scope):
                conflicts.append(
                    LegacyConflict(
                        min(left_scope.split("|", 2)[2], right_scope.split("|", 2)[2]),
                        "claim",
                        "overlapping_live_claim_scopes",
                        tuple(sorted((left, right), key=lambda item: (item.worktree, item.source_path))),
                    )
                )
    return LegacyDeduplication(tuple(groups), tuple(conflicts))


def _validate_git_refname(value: str) -> str:
    """Small deterministic subset of git-check-ref-format, with no shell dependency."""

    if not isinstance(value, str) or not value or len(value) > 1024:
        raise CompanyIdentityError("Git ref is invalid")
    if any(ord(char) <= 32 or ord(char) == 127 for char in value):
        raise CompanyIdentityError("Git ref is invalid")
    if value == "@" or value.startswith("/") or value.endswith("/") or value.endswith(".") or ".." in value or "@{" in value:
        raise CompanyIdentityError("Git ref is invalid")
    if any(char in value for char in "\\~^:?*["):
        raise CompanyIdentityError("Git ref is invalid")
    parts = value.split("/")
    if any(not part or part in {".", ".."} or part.startswith(".") or part.endswith(".lock") for part in parts):
        raise CompanyIdentityError("Git ref is invalid")
    return value


def _canonical_claim_scope(value: str | None, *, platform: str, lock_domain: str) -> str:
    """Validate the v0.4 lock URI subset needed for migration conflict checks."""

    if not isinstance(value, str) or value != value.strip() or not value or any(ord(char) < 32 for char in value):
        raise CompanyIdentityError("claim scope is invalid")
    platform = _require_platform(platform)
    lock_domain = _require_lock_domain(lock_domain)
    parts = value.split(":", 2)
    if len(parts) == 2 and parts[0] == "contract" and _REMOTE_NAME_RE.fullmatch(parts[1]):
        return f"{platform}|{lock_domain}|{value}"
    if len(parts) == 3 and parts[0] == "git" and parts[1] == "merge":
        return f"{platform}|{lock_domain}|git:merge:{_validate_git_refname(parts[2])}"
    if len(parts) != 3 or parts[0] not in {"repo", "host", "external"} or parts[1] not in {"file", "tree"}:
        raise CompanyIdentityError("claim scope is invalid")
    namespace, kind, raw_path = parts
    if namespace == "host":
        canonical_path = _path_key(raw_path, platform=platform, absolute=True)
        return f"{platform}|{lock_domain}|host:{kind}:{canonical_path}"
    if namespace == "repo":
        normalized = _path_key(raw_path, platform=platform, absolute=False)
    else:
        normalized = _path_key(raw_path, platform=platform, absolute=True)
    return f"{platform}|{lock_domain}|{namespace}:{kind}:{normalized}"


def _claim_scopes_overlap(left: str, right: str) -> bool:
    left_platform, left_domain, left_scope = left.split("|", 2)
    right_platform, right_domain, right_scope = right.split("|", 2)
    left_parts = left_scope.split(":", 2)
    right_parts = right_scope.split(":", 2)
    if left_parts[0] == right_parts[0] == "repo":
        _, left_kind, left_path = left_parts
        _, right_kind, right_path = right_parts
        if left_platform != right_platform:
            # A Windows/WSL migration cannot safely infer case sensitivity for
            # repository-relative paths.  Apply Win32 alias semantics to both
            # logical spellings: a POSIX-only trailing dot/space may name the
            # same Windows file after migration.  Invalid Windows spellings
            # are an ambiguity, not evidence that two live claims are disjoint.
            left_path = _windows_path_key(left_path, absolute=False)
            right_path = _windows_path_key(right_path, absolute=False)
        if left_kind == right_kind == "file":
            return left_path == right_path
        return _scope_descendant(left_path, right_path) or _scope_descendant(right_path, left_path)
    if left_parts[0] == right_parts[0] and left_parts[0] in {"contract", "git"}:
        # These scopes name one logical company resource and therefore retain
        # their exact exclusion during a cross-domain migration.
        return left_scope == right_scope
    if (left_platform, left_domain) != (right_platform, right_domain):
        return False
    if left_parts[0] != right_parts[0]:
        return False
    _, left_kind, left_path = left_parts
    _, right_kind, right_path = right_parts
    if left_kind == right_kind == "file":
        return left_path == right_path
    return _scope_descendant(left_path, right_path) or _scope_descendant(right_path, left_path)


def _scope_descendant(child: str, parent: str) -> bool:
    return parent in {".", "/"} or child == parent or child.startswith(parent.rstrip("/") + "/")


def _strict_scope_descendant(child: str, parent: str) -> bool:
    return child.startswith(parent.rstrip("/") + "/")


def compare_rebind(previous: CompanyBindingInput, observed: CompanyBindingInput) -> RebindComparison:
    """Describe an explicit-rebind requirement without performing it."""

    if not isinstance(previous, CompanyBindingInput) or not isinstance(observed, CompanyBindingInput):
        raise CompanyIdentityError("rebind comparison requires two company binding inputs")
    fields = ("common_dir", "common_dir_sha256", "remote_fingerprint_sha256", "platform", "lock_domain", "config_sha256")
    changed = tuple(field for field in fields if getattr(previous, field) != getattr(observed, field))
    return RebindComparison(bool(changed), changed)


__all__ = [
    "CompanyBindingInput",
    "CompanyIdentityError",
    "GitWorktree",
    "LegacyConflict",
    "LegacyDeduplication",
    "LegacySourceGroup",
    "LegacyStateCandidate",
    "LegacyStateSource",
    "RebindComparison",
    "company_binding_input",
    "company_state_root",
    "compare_rebind",
    "deduplicate_legacy_sources",
    "git_common_dir_identity",
    "git_worktree_inventory",
    "legacy_aoi_state_candidates",
    "normalize_remote_url",
    "normalized_remote_fingerprint",
    "observed_remote_fingerprint",
    "parse_git_worktree_porcelain",
]
