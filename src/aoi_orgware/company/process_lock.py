"""Cooperative lifetime lock for one AOI company state slot.

The lock is deliberately not a security boundary.  It serializes compliant
same-user Supervisor processes that use the same stable company-state path;
the CompanySupervisor must hold it for its full lifetime.  Restore/rebuild
code must acquire this lock, close its SQLite handles, and only then replace
company-state paths.
"""

from __future__ import annotations

import errno
import os
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final


class CompanyProcessLockError(RuntimeError):
    """The company process-lock contract was violated."""


class CompanyProcessLockBusyError(CompanyProcessLockError):
    """A different compliant process still owns the company lock."""


class CompanyProcessLockOwnershipError(CompanyProcessLockError):
    """A lock object was used outside the process/thread that acquired it."""


_SENTINEL: Final[bytes] = b"\0"
_CONTENDED_ERRNOS: Final[frozenset[int]] = frozenset(
    {errno.EACCES, errno.EAGAIN, errno.EDEADLK}
)


@dataclass
class _HeldLock:
    descriptor: int
    identity: tuple[int, int]
    owner_pid: int
    owner_thread: int
    depth: int
    inherited_descriptor_closed: bool = False


_LOCAL = threading.local()


def _held_locks() -> dict[str, _HeldLock]:
    held = getattr(_LOCAL, "held", None)
    if held is None:
        held = {}
        _LOCAL.held = held
    return held


def _key(path: Path) -> str:
    return os.path.normcase(os.fspath(path))


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return int(metadata.st_dev), int(metadata.st_ino)


def _link_like(path: Path) -> bool:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        return True
    if os.name == "nt":
        return bool(
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
    return False


def _absolute_stable_path(value: str | os.PathLike[str]) -> Path:
    try:
        path = Path(value)
    except TypeError as exc:
        raise CompanyProcessLockError("company lock path is invalid") from exc
    if not path.is_absolute():
        raise CompanyProcessLockError("company lock path must be absolute")
    if ".." in path.parts:
        raise CompanyProcessLockError("company lock path may not contain parent traversal")

    # Validate existing components without resolving through a potentially
    # linked parent.  The slot parent is intentionally required to exist: state
    # initialization owns directory creation and must not race the Supervisor.
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if current != path:
                raise CompanyProcessLockError(
                    "company lock parent must already exist and be stable"
                )
            break
        except OSError as exc:
            raise CompanyProcessLockError(
                f"cannot inspect company lock path component {current}: {exc}"
            ) from exc
        if _link_like(current):
            raise CompanyProcessLockError(
                f"company lock path may not traverse a symlink or junction: {current}"
            )
        if current != path and not stat.S_ISDIR(metadata.st_mode):
            raise CompanyProcessLockError(
                f"company lock parent is not a regular directory: {current}"
            )
    return path


def _validate_metadata(
    metadata: os.stat_result,
    path: Path,
    *,
    require_private_mode: bool,
) -> None:
    if not stat.S_ISREG(metadata.st_mode) or int(metadata.st_nlink) != 1:
        raise CompanyProcessLockError(
            f"company lock must be one regular non-linked file: {path}"
        )
    if require_private_mode and os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise CompanyProcessLockError(
            f"company lock permissions are not private (expected 0600): {path}"
        )
    if int(metadata.st_size) != len(_SENTINEL):
        raise CompanyProcessLockError(
            "company lock payload is invalid; expected one NUL sentinel byte"
        )


def _read_sentinel(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.read(descriptor, 2) != _SENTINEL:
        raise CompanyProcessLockError(
            "company lock payload is invalid; expected one NUL sentinel byte"
        )


def _acquire_platform_lock(descriptor: int) -> None:
    if os.name != "nt":
        import fcntl

        fcntl.flock(  # type: ignore[attr-defined]
            descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB  # type: ignore[attr-defined]
        )
        return
    import msvcrt

    os.lseek(descriptor, 0, os.SEEK_SET)
    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)


def _release_platform_lock(descriptor: int) -> None:
    if os.name != "nt":
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)  # type: ignore[attr-defined]
        return
    import msvcrt

    os.lseek(descriptor, 0, os.SEEK_SET)
    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)


class CompanyProcessLock:
    """Hold a stable company slot exclusively for one Supervisor lifetime.

    Exact-path reentrancy is allowed only on the acquiring thread and must be
    balanced by matching :meth:`close` calls.  A forked child never reuses or
    unlocks its parent's inherited open-file description.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.05,
        create_if_missing: bool = True,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds < 0
        ):
            raise CompanyProcessLockError("company lock timeout must be non-negative")
        if (
            isinstance(poll_interval_seconds, bool)
            or not isinstance(poll_interval_seconds, (int, float))
            or poll_interval_seconds <= 0
        ):
            raise CompanyProcessLockError("company lock poll interval must be positive")
        if not isinstance(create_if_missing, bool):
            raise CompanyProcessLockError(
                "company lock create_if_missing must be a boolean",
            )
        self.path = _absolute_stable_path(path)
        self.timeout_seconds = float(timeout_seconds)
        self.poll_interval_seconds = float(poll_interval_seconds)
        self.create_if_missing = create_if_missing
        self._entry: _HeldLock | None = None
        self._acquire_depth = 0

    @property
    def held(self) -> bool:
        return self._entry is not None and self._acquire_depth > 0

    def __enter__(self) -> "CompanyProcessLock":
        return self.acquire()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def acquire(self) -> "CompanyProcessLock":
        """Acquire the lock, waiting only for the configured bounded timeout."""

        if self._entry is not None:
            self._assert_owner(self._entry)
            self.assert_held()
            self._entry.depth += 1
            self._acquire_depth += 1
            return self

        key = _key(self.path)
        held = _held_locks()
        existing = held.get(key)
        if existing is not None:
            self._assert_owner(existing)
            self._validate_held_entry(existing)
            existing.depth += 1
            self._entry = existing
            self._acquire_depth = 1
            return self

        descriptor = self._open_slot()
        acquired = False
        try:
            deadline = time.monotonic() + self.timeout_seconds
            while True:
                try:
                    _acquire_platform_lock(descriptor)
                    acquired = True
                    break
                except OSError as exc:
                    if exc.errno not in _CONTENDED_ERRNOS:
                        raise CompanyProcessLockError(
                            f"could not acquire company lock: {exc}"
                        ) from exc
                    if time.monotonic() >= deadline:
                        raise CompanyProcessLockBusyError(
                            f"timed out waiting for company lock: {self.path}"
                        ) from exc
                    time.sleep(min(self.poll_interval_seconds, max(0.0, deadline - time.monotonic())))
            metadata = os.fstat(descriptor)
            self._validate_open_slot(descriptor, metadata)
            entry = _HeldLock(
                descriptor=descriptor,
                identity=_identity(metadata),
                owner_pid=os.getpid(),
                owner_thread=threading.get_ident(),
                depth=1,
            )
            held[key] = entry
            self._entry = entry
            self._acquire_depth = 1
            return self
        except BaseException:
            if acquired:
                try:
                    _release_platform_lock(descriptor)
                except OSError:
                    pass
            os.close(descriptor)
            raise

    def assert_held(self) -> None:
        """Fail closed if the owner, stable path, inode, or sentinel changed."""

        if self._entry is None or self._acquire_depth <= 0:
            raise CompanyProcessLockOwnershipError("company lock is not held")
        self._assert_owner(self._entry)
        self._validate_held_entry(self._entry)

    def assert_owned(self) -> None:
        """Public Supervisor witness that this process still owns the lock."""

        self.assert_held()

    def close(self) -> None:
        """Release one balanced acquisition; already-closed instances are inert."""

        entry = self._entry
        if entry is None or self._acquire_depth == 0:
            return
        if entry.owner_pid != os.getpid():
            # Never unlock in a forked child: closing its descriptor is safe and
            # cannot release the parent's lock.  The child object is unusable.
            self._entry = None
            self._acquire_depth = 0
            _held_locks().pop(_key(self.path), None)
            if not entry.inherited_descriptor_closed:
                entry.inherited_descriptor_closed = True
                try:
                    os.close(entry.descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise CompanyProcessLockError(
                            f"cannot close inherited company lock descriptor: {exc}"
                        ) from exc
            return
        self._assert_owner(entry)
        self._acquire_depth -= 1
        entry.depth -= 1
        if self._acquire_depth:
            return
        self._entry = None
        if entry.depth:
            return
        validation_error: BaseException | None = None
        try:
            self._validate_held_entry(entry)
        except BaseException as exc:
            validation_error = exc
        finally:
            _held_locks().pop(_key(self.path), None)
            release_error: BaseException | None = None
            try:
                _release_platform_lock(entry.descriptor)
            except BaseException as exc:
                release_error = exc
            try:
                os.close(entry.descriptor)
            except BaseException as exc:
                if release_error is None:
                    release_error = exc
            if validation_error is not None:
                raise validation_error
            if release_error is not None:
                raise release_error

    def _open_slot(self) -> int:
        # Recheck immediately before open: a parent/slot replacement is a
        # contract failure, not a signal to create a second company state tree.
        self.path = _absolute_stable_path(self.path)
        parent = self.path.parent
        parent_metadata = parent.lstat()
        if not stat.S_ISDIR(parent_metadata.st_mode) or _link_like(parent):
            raise CompanyProcessLockError("company lock parent is not a stable directory")
        flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        newly_created = False
        if self.create_if_missing:
            try:
                descriptor = os.open(
                    self.path,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                newly_created = True
            except FileExistsError:
                try:
                    descriptor = os.open(self.path, flags)
                except OSError as exc:
                    raise CompanyProcessLockError(
                        f"cannot open company lock: {exc}",
                    ) from exc
            except OSError as exc:
                raise CompanyProcessLockError(
                    f"cannot create company lock: {exc}",
                ) from exc
        else:
            try:
                descriptor = os.open(self.path, flags)
            except OSError as exc:
                raise CompanyProcessLockError(
                    f"cannot open existing company lock: {exc}",
                ) from exc
        try:
            os.set_inheritable(descriptor, False)
            metadata = os.fstat(descriptor)
            if newly_created:
                if os.write(descriptor, _SENTINEL) != len(_SENTINEL):
                    raise CompanyProcessLockError("could not initialize company lock sentinel")
                os.fsync(descriptor)
            if os.name != "nt":
                os.chmod(self.path, 0o600)
            self._validate_open_slot(
                descriptor,
                os.fstat(descriptor),
                read_sentinel=os.name != "nt",
            )
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _validate_open_slot(
        self,
        descriptor: int,
        opened: os.stat_result,
        *,
        read_sentinel: bool = True,
    ) -> None:
        try:
            current = self.path.lstat()
        except OSError as exc:
            raise CompanyProcessLockError(
                f"cannot inspect company lock slot: {self.path}: {exc}"
            ) from exc
        if _link_like(self.path):
            raise CompanyProcessLockError("company lock may not be a symlink or junction")
        _validate_metadata(current, self.path, require_private_mode=True)
        _validate_metadata(opened, self.path, require_private_mode=True)
        if _identity(current) != _identity(opened):
            raise CompanyProcessLockError("company lock path changed while being opened")
        # Windows msvcrt byte-range locking can deny a competing reader before
        # it has obtained the byte-range lock.  Validate the immutable sentinel
        # there only after this process owns the range; POSIX validates at both
        # open and post-acquire boundaries.
        if read_sentinel:
            _read_sentinel(descriptor)

    def _assert_owner(self, entry: _HeldLock) -> None:
        if entry.owner_pid != os.getpid():
            raise CompanyProcessLockOwnershipError(
                "company lock context was inherited across a process boundary"
            )
        if entry.owner_thread != threading.get_ident():
            raise CompanyProcessLockOwnershipError(
                "company lock is owned by a different thread"
            )

    def _validate_held_entry(self, entry: _HeldLock) -> None:
        try:
            current = self.path.lstat()
            opened = os.fstat(entry.descriptor)
        except OSError as exc:
            raise CompanyProcessLockError(
                f"cannot inspect held company lock: {self.path}: {exc}"
            ) from exc
        if _link_like(self.path):
            raise CompanyProcessLockError("company lock path changed while held")
        _validate_metadata(current, self.path, require_private_mode=True)
        if _identity(current) != entry.identity or _identity(opened) != entry.identity:
            raise CompanyProcessLockError("company lock path changed while held")
        _validate_metadata(opened, self.path, require_private_mode=True)
        _read_sentinel(entry.descriptor)


__all__ = [
    "CompanyProcessLock",
    "CompanyProcessLockBusyError",
    "CompanyProcessLockError",
    "CompanyProcessLockOwnershipError",
]
