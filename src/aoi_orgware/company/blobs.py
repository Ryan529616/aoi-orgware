"""Immutable, content-addressed blob storage for one explicit company root.

The store deliberately has no process-global state or default location.  A
Supervisor must supply the company-owned blob root explicitly.  Blob members
are addressed by a canonical, lowercase SHA-256 digest and are published by
creating a complete private temporary followed by an atomic no-replace hard
link.  The implementation is cooperative integrity, not a hostile same-user
filesystem sandbox.
"""

from __future__ import annotations

from dataclasses import dataclass
import contextlib
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Final

from .native_filesystem import native_filesystem_path as _native_filesystem_path


_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_DEFAULT_MAX_BYTES: Final[int] = 64 * 1024 * 1024
_COPY_CHUNK_BYTES: Final[int] = 1024 * 1024
_EXISTING_MEMBER_RETRIES: Final[int] = 128
_EXISTING_MEMBER_RETRY_SECONDS: Final[float] = 0.001
_MAX_RECOVERY_SCAN_ENTRIES: Final[int] = 4096
_TEMPORARY_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^\.aoi-blob-v1\.[0-9a-f]{32}\.tmp$"
)
_WINDOWS_NAMESPACE_ROOT_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:[\\/]{2}[?.][\\/]|[\\/]\?\?[\\/])"
)
_WINDOWS_DRIVE_COMPONENT_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z]:$")
_WINDOWS_RESERVED_DEVICE_BASENAMES: Final[frozenset[str]] = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CLOCK$",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
    }
)


class BlobStoreError(RuntimeError):
    """Base error for a company blob operation."""


class BlobPathError(BlobStoreError):
    """The supplied root, digest, or member path is unsafe or malformed."""


class BlobSizeError(BlobStoreError):
    """A payload or stored member exceeds the configured store bound."""


class BlobIntegrityError(BlobStoreError):
    """An existing member is not the bytes its digest names."""


@dataclass(frozen=True)
class BlobMetadata:
    """Verified immutable metadata for a single blob member."""

    sha256: str
    size_bytes: int
    path: Path


def _validate_digest(digest: str) -> str:
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        raise BlobPathError("blob digest must be a canonical lowercase SHA-256")
    return digest


def _as_bytes(payload: bytes | bytearray | memoryview) -> bytes:
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, bytearray):
        return bytes(payload)
    if isinstance(payload, memoryview):
        return payload.tobytes()
    raise TypeError("blob payload must be bytes-like")


def _lstat_regular(path: Path, label: str) -> os.stat_result:
    try:
        metadata = os.lstat(_native_filesystem_path(path))
    except FileNotFoundError:
        raise
    if _is_windows_reparse_point(metadata):
        raise BlobPathError(f"{label} must not be a Windows reparse point or link")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BlobPathError(f"{label} must be a regular non-link file")
    return metadata


def _lstat_directory(path: Path, label: str) -> os.stat_result:
    try:
        metadata = os.lstat(_native_filesystem_path(path))
    except FileNotFoundError:
        raise
    if _is_windows_reparse_point(metadata):
        raise BlobPathError(f"{label} must not be a Windows reparse point or link")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise BlobPathError(f"{label} must be a directory, not a link")
    return metadata


def _is_windows_reparse_point(metadata: os.stat_result) -> bool:
    """Return whether an lstat result names a native Windows reparse point."""
    if os.name != "nt":
        return False
    attributes = getattr(metadata, "st_file_attributes", None)
    reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", None)
    if (
        not isinstance(attributes, int)
        or not isinstance(reparse_point, int)
        or reparse_point == 0
    ):
        raise BlobPathError("Windows reparse-point inspection is unavailable")
    return (
        bool(attributes & reparse_point)
    )


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _reject_windows_namespace_root_alias(root: str | os.PathLike[str]) -> None:
    """Reject Win32 device and extended roots before constructing a ``Path``."""
    if os.name != "nt":
        return
    supplied = os.fspath(root)
    if isinstance(supplied, str) and _WINDOWS_NAMESPACE_ROOT_RE.match(supplied):
        raise BlobPathError("blob root must not use a Windows device or extended namespace")


def _reject_windows_colon_root_component(root: str | os.PathLike[str]) -> None:
    """Reject Windows alternate-data-stream spellings before constructing a ``Path``.

    A normal leading ``C:``-style drive anchor is the sole path component which
    may contain a colon.  In particular, a later ``D:`` component is malformed
    rather than another anchor, and colons in UNC server/share descendants are
    not ordinary UNC names.  This must remain lexical: native Windows can
    otherwise resolve an alternate data stream before the root audit runs.
    """
    if os.name != "nt":
        return
    supplied = os.fspath(root)
    if not isinstance(supplied, str):
        return

    components = [component for component in re.split(r"[\\/]+", supplied) if component]
    if components and _WINDOWS_DRIVE_COMPONENT_RE.fullmatch(components[0]):
        components = components[1:]
    if any(":" in component for component in components):
        raise BlobPathError(
            "blob root must not contain a colon outside its Windows drive anchor"
        )


def _reject_windows_reserved_device_root_component(root: str | os.PathLike[str]) -> None:
    """Reject reserved Win32 device components before constructing a ``Path``.

    Win32 resolves names such as ``CON`` and ``NUL.txt`` as devices even when
    they appear below an otherwise ordinary root.  Trailing dots/spaces and
    extensions do not make those names safe aliases.  A UNC server/share pair
    is an anchor rather than a local path component, so only descendants of a
    complete UNC anchor are subject to the device-name check.
    """
    if os.name != "nt":
        return
    supplied = os.fspath(root)
    if not isinstance(supplied, str):
        return

    components = [component for component in re.split(r"[\\/]+", supplied) if component]
    if supplied.startswith(("\\\\", "//")):
        # The first two components are the UNC server/share anchor.  They are
        # not Win32 local path components and must retain ordinary UNC support.
        components = components[2:]
    elif components and _WINDOWS_DRIVE_COMPONENT_RE.fullmatch(components[0]):
        components = components[1:]

    for component in components:
        trimmed = component.rstrip(". ")
        basename = trimmed.split(".", 1)[0].rstrip(" ").upper()
        if basename in _WINDOWS_RESERVED_DEVICE_BASENAMES:
            raise BlobPathError(
                "blob root must not contain a reserved Windows device component"
            )


def _reject_noncanonical_win32_root_alias(path: Path) -> None:
    """Reject Win32 components which the native filesystem aliases on lookup."""
    if os.name != "nt":
        return

    # ``Path.parts`` keeps a UNC server/share pair in its anchor.  Inspect it
    # separately so a trailing-dot/space alias cannot hide in that component.
    anchor_components = tuple(
        component
        for component in re.split(r"[/\\]+", path.anchor.rstrip("/\\"))
        if component
    )
    components = (*anchor_components, *path.parts[1:])
    if any(component.rstrip(". ") != component for component in components):
        raise BlobPathError(
            "blob root must not contain a non-canonical Win32 trailing-dot/space component"
        )


class BlobStore:
    """Bounded immutable blob storage rooted at one caller-supplied directory.

    On POSIX, successful publication fsyncs the member, each newly-created
    directory, and every directory whose entry changed.  A filesystem which
    rejects directory fsync therefore fails the operation; it does not receive
    that durability claim.  Native Windows exposes file fsync through the
    standard library but not a portable directory fsync; ``durability_boundary``
    makes that limitation explicit.

    This is cooperative integrity only.  In particular, hostile same-user
    directory swaps between checks are outside its guarantee.
    """

    def __init__(self, root: str | os.PathLike[str], *, max_bytes: int = _DEFAULT_MAX_BYTES) -> None:
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
            raise ValueError("max_bytes must be a non-negative integer")
        _reject_windows_namespace_root_alias(root)
        _reject_windows_colon_root_component(root)
        _reject_windows_reserved_device_root_component(root)
        supplied_root = Path(root)
        if not supplied_root.is_absolute():
            raise BlobPathError("blob root must be an explicit absolute path")
        if ".." in supplied_root.parts:
            raise BlobPathError("blob root must not contain parent traversal")
        _reject_noncanonical_win32_root_alias(supplied_root)
        self._root = supplied_root
        self._max_bytes = max_bytes
        self._initialize_root()

    @property
    def root(self) -> Path:
        return self._root

    @property
    def max_bytes(self) -> int:
        return self._max_bytes

    @property
    def durability_boundary(self) -> str:
        """State exactly which directory-sync guarantee this platform offers."""
        if os.name == "nt":
            return "file_fsync_only; Python stdlib has no portable Windows directory fsync"
        return "file_and_changed_directory_fsync"

    def path_for_digest(self, digest: str) -> Path:
        digest = _validate_digest(digest)
        return self._root / digest[:2] / digest[2:4] / digest

    def put(self, payload: bytes | bytearray | memoryview) -> BlobMetadata:
        """Publish payload once, or verify and return its pre-existing member."""
        if isinstance(payload, memoryview):
            payload_size = payload.nbytes
        elif isinstance(payload, (bytes, bytearray)):
            payload_size = len(payload)
        else:
            raise TypeError("blob payload must be bytes-like")
        if payload_size > self._max_bytes:
            raise BlobSizeError(
                f"blob size {payload_size} exceeds configured maximum {self._max_bytes}"
            )
        data = _as_bytes(payload)
        digest = hashlib.sha256(data).hexdigest()
        destination = self.path_for_digest(digest)
        self._ensure_fanout(digest)

        try:
            return self._match_existing_after_settling(destination, digest, data)
        except FileNotFoundError:
            pass

        temporary: Path | None = None
        temporary_stat: os.stat_result | None = None
        published = False
        try:
            temporary, temporary_stat = self._write_private_temporary(destination.parent, data)
            try:
                # ``link`` is no-replace on both POSIX and supported NTFS Python
                # builds.  There is intentionally no rename/replace fallback.
                os.link(
                    _native_filesystem_path(temporary),
                    _native_filesystem_path(destination),
                )
            except FileExistsError:
                return self._match_existing_after_settling(destination, digest, data)
            published = True
            self._fsync_directory(destination.parent)
            self._cleanup_private_temporary(temporary, temporary_stat, linked_destination=True)
            temporary = None
            temporary_stat = None
            return self._metadata_from_verified(destination, digest)
        finally:
            if temporary is not None and temporary_stat is not None:
                self._cleanup_private_temporary(
                    temporary,
                    temporary_stat,
                    linked_destination=published,
                )

    def read(self, digest: str) -> bytes:
        """Read a member only after checking its path, size, and SHA-256."""
        digest = _validate_digest(digest)
        self._assert_member_fanout(digest)
        destination = self.path_for_digest(digest)
        self._recover_interrupted_publication(destination, digest)
        return self._read_verified(destination, digest)

    def metadata(self, digest: str) -> BlobMetadata:
        """Return metadata after independently verifying the stored bytes."""
        digest = _validate_digest(digest)
        self._assert_member_fanout(digest)
        destination = self.path_for_digest(digest)
        self._recover_interrupted_publication(destination, digest)
        return self._metadata_from_verified(destination, digest)

    def _ensure_fanout(self, digest: str) -> None:
        self._assert_root_ancestors()
        self._ensure_directory(self._root / digest[:2], "blob fanout directory")
        self._ensure_directory(self._root / digest[:2] / digest[2:4], "blob fanout directory")

    def _assert_member_fanout(self, digest: str) -> None:
        """Audit the rooted, non-link directory path used for one member."""
        self._assert_root_ancestors()
        first_fanout = self._root / digest[:2]
        _lstat_directory(first_fanout, "blob fanout directory")
        _lstat_directory(first_fanout / digest[2:4], "blob fanout directory")

    def _initialize_root(self) -> None:
        """Audit the complete existing path before creating under its boundary."""
        boundary, missing = self._audited_existing_boundary(self._root)
        current = boundary
        for component in missing:
            current = current / component
            self._ensure_directory(current, "blob root")
        self._assert_root_ancestors()

    @staticmethod
    def _audited_existing_boundary(path: Path) -> tuple[Path, tuple[str, ...]]:
        """Return a checked existing parent and only the descendants to create."""
        pending: list[str] = []
        current = path
        while True:
            try:
                _lstat_directory(current, "blob root ancestor")
                break
            except FileNotFoundError:
                parent = current.parent
                if parent == current:
                    raise BlobPathError("blob root has no trusted existing parent")
                pending.append(current.name)
                current = parent

        # Every already-existing component is checked before any mkdir.  This
        # catches a linked/malicious parent without creating through it.
        parts = current.parts
        anchor = Path(parts[0])
        _lstat_directory(anchor, "blob root anchor")
        checked = anchor
        for component in parts[1:]:
            checked = checked / component
            _lstat_directory(checked, "blob root ancestor")
        return current, tuple(reversed(pending))

    def _assert_root_ancestors(self) -> None:
        """Reject a root reached through a link, including an intermediate one."""
        parts = self._root.parts
        if not parts:
            raise BlobPathError("blob root has no filesystem anchor")
        current = Path(parts[0])
        _lstat_directory(current, "blob root anchor")
        for component in parts[1:]:
            current = current / component
            _lstat_directory(current, "blob root ancestor")

    def _ensure_directory(self, path: Path, label: str) -> None:
        parent = path.parent
        parent_before = _lstat_directory(parent, f"{label} parent")
        created = False
        try:
            os.mkdir(_native_filesystem_path(path), mode=0o700)
            created = True
        except FileExistsError:
            pass
        _lstat_directory(path, label)
        if created:
            if os.name != "nt":
                os.chmod(path, 0o700)
            parent_after = _lstat_directory(parent, f"{label} parent")
            if not _same_identity(parent_before, parent_after):
                raise BlobPathError(f"{label} parent changed while creating directory")
            self._fsync_directory(path)
            self._fsync_directory(parent)
        return None

    def _write_private_temporary(self, parent: Path, data: bytes) -> tuple[Path, os.stat_result]:
        self._ensure_directory(parent, "blob fanout directory")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor: int | None = None
        temporary: Path | None = None
        temporary_stat: os.stat_result | None = None
        try:
            for _ in range(128):
                candidate = parent / f".aoi-blob-v1.{secrets.token_hex(16)}.tmp"
                try:
                    descriptor = os.open(
                        _native_filesystem_path(candidate), flags, 0o600,
                    )
                except FileExistsError:
                    continue
                temporary = candidate
                temporary_stat = os.fstat(descriptor)
                break
            if descriptor is None or temporary is None or temporary_stat is None:
                raise BlobStoreError("could not allocate private blob temporary")
            if os.name != "nt":
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = None
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            path_stat = _lstat_regular(temporary, "blob temporary")
            if not _same_identity(path_stat, temporary_stat) or path_stat.st_nlink != 1:
                raise BlobPathError("blob temporary must have exactly one hard link")
            self._fsync_directory(parent)
            return temporary, temporary_stat
        except BaseException:
            if descriptor is not None:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            if temporary is not None and temporary_stat is not None:
                self._cleanup_private_temporary(temporary, temporary_stat, linked_destination=False)
            raise

    def _cleanup_private_temporary(
        self,
        temporary: Path,
        expected: os.stat_result,
        *,
        linked_destination: bool,
    ) -> None:
        """Remove only the exact temporary inode we created, then sync its parent."""
        try:
            current = _lstat_regular(temporary, "blob temporary")
        except FileNotFoundError:
            return
        expected_links = 2 if linked_destination else 1
        if not _same_identity(current, expected) or current.st_nlink != expected_links:
            raise BlobPathError("blob temporary changed or was aliased before cleanup")
        os.unlink(_native_filesystem_path(temporary))
        self._fsync_directory(temporary.parent)

    def _match_existing(self, destination: Path, digest: str, data: bytes) -> BlobMetadata:
        # ``put`` already ensures the fanout, but re-audit immediately before
        # reading an existing member so an idempotent path cannot follow a
        # fanout symlink introduced after that setup.
        self._assert_member_fanout(digest)
        existing = self._read_verified(destination, digest)
        if existing != data:
            raise BlobIntegrityError("existing blob digest collides with different bytes")
        return BlobMetadata(digest, len(existing), destination)

    def _match_existing_after_settling(self, destination: Path, digest: str, data: bytes) -> BlobMetadata:
        """Allow a cooperative publisher to remove its temporary hard link.

        At no point is a member with more than one link accepted.  The bounded
        retry merely lets a concurrent same-byte publisher finish its private
        temporary cleanup; a persistent external hard link remains an error.
        """
        last_error: BlobPathError | None = None
        for attempt in range(_EXISTING_MEMBER_RETRIES):
            try:
                return self._match_existing(destination, digest, data)
            except BlobPathError as exc:
                if "hard link" not in str(exc):
                    raise
                last_error = exc
                if attempt + 1 < _EXISTING_MEMBER_RETRIES:
                    time.sleep(_EXISTING_MEMBER_RETRY_SECONDS)
        assert last_error is not None
        self._recover_interrupted_publication(
            destination, digest, expected_data=data,
        )
        return self._match_existing(destination, digest, data)

    def _recover_interrupted_publication(
        self,
        destination: Path,
        digest: str,
        *,
        expected_data: bytes | None = None,
    ) -> None:
        """Remove only a uniquely identifiable AOI crash-left temp hardlink.

        A normal external alias remains a hard error.  Recovery is possible
        only when the member has exactly two links and the second link is one
        regular, canonical AOI temporary in the same audited fanout directory.
        The bytes and digest are verified before unlinking that temporary.
        """

        self._assert_member_fanout(digest)
        try:
            destination_stat = _lstat_regular(destination, "blob member")
        except FileNotFoundError:
            return
        if destination_stat.st_nlink == 1:
            return
        if destination_stat.st_nlink != 2:
            raise BlobPathError("blob member must have exactly one hard link")

        matches: list[tuple[Path, os.stat_result]] = []
        with os.scandir(_native_filesystem_path(destination.parent)) as entries:
            for index, entry in enumerate(entries):
                if index >= _MAX_RECOVERY_SCAN_ENTRIES:
                    raise BlobPathError(
                        "blob recovery fanout scan exceeds configured bound"
                    )
                if _TEMPORARY_NAME_RE.fullmatch(entry.name) is None:
                    continue
                temporary = destination.parent / entry.name
                try:
                    temporary_stat = _lstat_regular(
                        temporary, "blob recovery temporary",
                    )
                except FileNotFoundError:
                    continue
                if _same_identity(destination_stat, temporary_stat):
                    matches.append((temporary, temporary_stat))

        if len(matches) != 1:
            current = _lstat_regular(destination, "blob member")
            if current.st_nlink == 1:
                return
            raise BlobPathError(
                "blob member hard link is not a unique recoverable AOI temporary"
            )
        temporary, temporary_stat = matches[0]
        if temporary_stat.st_nlink != 2:
            raise BlobPathError(
                "blob recovery temporary does not have the expected link count"
            )
        current_destination = _lstat_regular(destination, "blob member")
        current_temporary = _lstat_regular(
            temporary, "blob recovery temporary",
        )
        if (
            not _same_identity(destination_stat, current_destination)
            or not _same_identity(destination_stat, current_temporary)
            or current_destination.st_nlink != 2
            or current_temporary.st_nlink != 2
        ):
            raise BlobPathError("blob recovery pair changed during verification")
        recovered = self._read_verified(destination, digest, expected_links=2)
        if expected_data is not None and recovered != expected_data:
            raise BlobIntegrityError(
                "existing blob digest collides with different bytes"
            )
        try:
            os.unlink(_native_filesystem_path(temporary))
        except FileNotFoundError:
            # A cooperative original publisher may have won the same cleanup.
            if _lstat_regular(destination, "blob member").st_nlink != 1:
                raise BlobPathError("blob recovery temporary disappeared ambiguously")
        self._fsync_directory(destination.parent)
        verified = self._read_verified(destination, digest)
        if expected_data is not None and verified != expected_data:
            raise BlobIntegrityError(
                "existing blob digest collides with different bytes"
            )

    def _metadata_from_verified(self, path: Path, digest: str) -> BlobMetadata:
        payload = self._read_verified(path, digest)
        return BlobMetadata(digest, len(payload), path)

    def _read_verified(
        self, path: Path, digest: str, *, expected_links: int = 1,
    ) -> bytes:
        before = _lstat_regular(path, "blob member")
        if before.st_nlink != expected_links:
            raise BlobPathError(
                f"blob member must have exactly {expected_links} hard link"
                + ("" if expected_links == 1 else "s")
            )
        if before.st_size > self._max_bytes:
            raise BlobSizeError(f"stored blob size {before.st_size} exceeds configured maximum {self._max_bytes}")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(_native_filesystem_path(path), flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or not _same_identity(before, opened):
                raise BlobPathError("blob member changed while opening")
            if opened.st_nlink != expected_links:
                raise BlobPathError(
                    f"blob member must have exactly {expected_links} hard link"
                    + ("" if expected_links == 1 else "s")
                )
            if opened.st_size > self._max_bytes:
                raise BlobSizeError(f"stored blob size {opened.st_size} exceeds configured maximum {self._max_bytes}")
            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining:
                chunk = os.read(descriptor, min(_COPY_CHUNK_BYTES, remaining))
                if not chunk:
                    raise BlobIntegrityError("blob member truncated while reading")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise BlobIntegrityError("blob member grew while reading")
            payload = b"".join(chunks)
            after_open = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = _lstat_regular(path, "blob member")
        if not _same_identity(before, after_open) or not _same_identity(before, after_path):
            raise BlobPathError("blob member changed while reading")
        if (
            after_open.st_nlink != expected_links
            or after_path.st_nlink != expected_links
        ):
            raise BlobPathError(
                f"blob member must have exactly {expected_links} hard link"
                + ("" if expected_links == 1 else "s")
            )
        if len(payload) != before.st_size:
            raise BlobIntegrityError("blob member size changed while reading")
        observed_digest = hashlib.sha256(payload).hexdigest()
        if observed_digest != digest:
            raise BlobIntegrityError("blob member SHA-256 does not match its pathname")
        return payload

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name == "nt":
            # Native Windows has no portable directory descriptor/fsync API in
            # Python's stdlib.  File bytes were already flushed before linking.
            return
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
