"""Bounded, fail-closed inventory of bytes proposed for publication.

This is deliberately a small stdlib-only boundary.  It observes regular files
without following links, expands the two archive formats used by Python
distribution artifacts, and returns canonical rows suitable for a later policy
gate.  It does not publish, copy, or otherwise modify any input.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import tarfile
from typing import Any, NoReturn
import zipfile


_REPARSE_POINT = 0x0400
_IDENTITY_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_nlink")


class PublicationSubjectError(ValueError):
    """The proposed publication inputs cannot be safely inventoried."""


@dataclass(frozen=True, slots=True)
class PublicationSubjectLimits:
    """Resource bounds for one inventory operation."""

    max_inputs: int = 128
    max_containers: int = 10_000
    max_subjects: int = 20_000
    max_filesystem_entries: int = 40_000
    max_total_bytes: int = 512 * 1024 * 1024
    max_archive_members: int = 10_000
    chunk_bytes: int = 1024 * 1024


def _fail(message: str) -> NoReturn:
    raise PublicationSubjectError(message)


def _check_limits(limits: PublicationSubjectLimits) -> PublicationSubjectLimits:
    if not isinstance(limits, PublicationSubjectLimits):
        _fail("publication subject limits are invalid")
    for field in (
        "max_inputs",
        "max_containers",
        "max_subjects",
        "max_filesystem_entries",
        "max_total_bytes",
        "max_archive_members",
        "chunk_bytes",
    ):
        value = getattr(limits, field)
        if type(value) is not int or value < 1:
            _fail(f"publication subject limit {field} is invalid")
    return limits


def _path_value(value: Path | str, label: str) -> Path:
    if not isinstance(value, (Path, str)):
        _fail(f"{label} must be a path")
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        _fail(f"{label} is invalid")
    candidate = Path(raw)
    if any(part == ".." for part in candidate.parts):
        _fail(f"{label} contains parent traversal")
    return Path(os.path.abspath(raw))


def _is_link_like(path: Path, metadata: os.stat_result | None = None) -> bool:
    try:
        value = metadata if metadata is not None else path.lstat()
    except OSError as exc:
        _fail(f"cannot inspect {path}: {exc}")
    return stat.S_ISLNK(value.st_mode) or bool(
        getattr(value, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _validate_chain(path: Path, label: str) -> None:
    """Reject a link/reparse point in any existing lexical path component."""

    anchor = Path(path.anchor)
    if not anchor:
        _fail(f"{label} is not absolute")
    current = anchor
    try:
        if _is_link_like(current):
            _fail(f"{label} traverses a symlink, junction, or reparse point")
    except FileNotFoundError:
        pass
    for component in path.parts[1:]:
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        except OSError as exc:
            _fail(f"cannot inspect {label}: {exc}")
        if _is_link_like(current, metadata):
            _fail(f"{label} traverses a symlink, junction, or reparse point")


def _regular_file(path: Path, label: str) -> os.stat_result:
    _validate_chain(path, label)
    try:
        metadata = path.lstat()
    except OSError as exc:
        _fail(f"cannot inspect {label}: {exc}")
    if _is_link_like(path, metadata) or not stat.S_ISREG(metadata.st_mode):
        _fail(f"{label} must be a regular non-link file")
    if metadata.st_nlink != 1:
        _fail(f"{label} must not be hard linked")
    return metadata


def _directory(path: Path, label: str) -> os.stat_result:
    _validate_chain(path, label)
    try:
        metadata = path.lstat()
    except OSError as exc:
        _fail(f"cannot inspect {label}: {exc}")
    if _is_link_like(path, metadata) or not stat.S_ISDIR(metadata.st_mode):
        _fail(f"{label} must be a directory without links or reparse points")
    return metadata


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return all(getattr(left, field) == getattr(right, field) for field in _IDENTITY_FIELDS)


def _snapshot_regular_file(
    path: Path, label: str, chunk_bytes: int, maximum_bytes: int
) -> tuple[str, int, bytes]:
    before = _regular_file(path, label)
    if before.st_size > maximum_bytes:
        _fail(f"{label} bytes exceed their bound")
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not _same_identity(before, opened):
                _fail(f"{label} changed while being opened")
            digest = hashlib.sha256()
            data = bytearray()
            while True:
                chunk = handle.read(chunk_bytes)
                if not chunk:
                    break
                digest.update(chunk)
                data.extend(chunk)
            finished = os.fstat(handle.fileno())
        after = _regular_file(path, label)
    except PublicationSubjectError:
        raise
    except OSError as exc:
        _fail(f"cannot read {label}: {exc}")
    if not _same_identity(before, opened) or not _same_identity(before, finished):
        _fail(f"{label} changed while being read")
    if not _same_identity(before, after) or len(data) != before.st_size:
        _fail(f"{label} changed while being hashed")
    return digest.hexdigest(), len(data), bytes(data)


def _under(root: Path, path: Path) -> bool:
    try:
        return os.path.commonpath((os.path.normcase(str(root)), os.path.normcase(str(path)))) == os.path.normcase(str(root))
    except ValueError:
        return False


def _safe_label(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        _fail(f"{label} is invalid")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
        _fail(f"{label} contains traversal")
    if any(len(part) > 255 or any(ord(char) < 32 for char in part) for part in pure.parts):
        _fail(f"{label} is invalid")
    return pure.as_posix()


def _disk_label(root: Path, path: Path) -> str:
    if _under(root, path):
        return _safe_label(path.relative_to(root).as_posix(), "project-relative path")
    # Do not emit the external absolute path into a publication receipt.  The
    # path token is stable on the local platform while the byte digest remains
    # the exact source-content identity.
    token = hashlib.sha256(os.path.normcase(str(path)).encode("utf-8")).hexdigest()
    return f"external/{token}/{_safe_label(path.name, 'external basename')}"


def _archive_kind(label: str) -> str | None:
    lowered = label.casefold()
    if lowered.endswith((".whl", ".zip")):
        return "zip"
    if lowered.endswith((".tar.gz", ".tgz")):
        return "tar"
    return None


def _read_member(
    handle: Any, *, maximum_bytes: int, chunk_bytes: int
) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = handle.read(chunk_bytes)
        if not chunk:
            return digest.hexdigest(), size
        size += len(chunk)
        if size > maximum_bytes:
            _fail("publication archive member bytes exceed their bound")
        digest.update(chunk)


def _central_directory_member_count(
    raw: bytes,
    *,
    offset: int,
    size: int,
    declared_count: int,
    maximum_members: int,
) -> int:
    """Boundedly scan central-directory headers before ``ZipFile`` allocates."""

    if offset < 0 or size < 0 or offset + size > len(raw):
        _fail("cannot read ZIP publication input: invalid central directory")
    position = offset
    end = offset + size
    observed = 0
    while position < end:
        if observed >= maximum_members:
            _fail("publication archive member count exceeds its bound")
        if position + 46 > end or raw[position : position + 4] != b"PK\x01\x02":
            _fail("cannot read ZIP publication input: malformed central directory")
        try:
            name_size, extra_size, comment_size = struct.unpack_from(
                "<3H", raw, position + 28
            )
            disk_start = struct.unpack_from("<H", raw, position + 34)[0]
        except struct.error as exc:
            _fail(f"cannot read ZIP publication input: {exc}")
        if disk_start not in (0, 0xFFFF):
            _fail("cannot read ZIP publication input: multi-disk archives are unsupported")
        position += 46 + name_size + extra_size + comment_size
        if position > end:
            _fail("cannot read ZIP publication input: malformed central directory")
        observed += 1
    if position != end or observed != declared_count:
        _fail("cannot read ZIP publication input: inconsistent member count")
    return observed


def _zip_member_count(raw: bytes, *, maximum_members: int) -> int:
    """Read and validate the ZIP entry count before constructing ``ZipFile``.

    ``ZipFile`` builds its central-directory list at construction time.  Its
    public ``infolist`` therefore cannot be used as a resource-limit check:
    by then an attacker-controlled number of entries may already have been
    materialized.  The end records contain the authoritative count, including
    the ZIP64 form, so reject an excessive or malformed archive first.
    """

    # EOCD has a 22-byte fixed portion and a comment limited to 65535 bytes.
    signature = b"PK\x05\x06"
    minimum = 22
    start = max(0, len(raw) - (minimum + 0xFFFF))
    offset = raw.rfind(signature, start)
    if offset < 0 or offset + minimum > len(raw):
        _fail("cannot read ZIP publication input: missing end record")
    try:
        (
            _signature,
            disk_number,
            central_directory_disk,
            entries_this_disk,
            entries_total,
            central_directory_size,
            central_directory_offset,
            comment_size,
        ) = struct.unpack_from("<4s4H2LH", raw, offset)
    except struct.error as exc:
        _fail(f"cannot read ZIP publication input: {exc}")
    if offset + minimum + comment_size != len(raw):
        _fail("cannot read ZIP publication input: malformed end record")
    if disk_number or central_directory_disk or entries_this_disk != entries_total:
        _fail("cannot read ZIP publication input: multi-disk archives are unsupported")
    if entries_total != 0xFFFF:
        return _central_directory_member_count(
            raw,
            offset=int(central_directory_offset),
            size=int(central_directory_size),
            declared_count=int(entries_total),
            maximum_members=maximum_members,
        )

    # ZIP64 locator immediately precedes EOCD.  Reject malformed and
    # multi-disk forms rather than falling back to an unbounded parser.
    locator_size = 20
    locator_offset = offset - locator_size
    if locator_offset < 0:
        _fail("cannot read ZIP publication input: missing ZIP64 locator")
    try:
        (
            locator_signature,
            zip64_disk,
            zip64_offset,
            total_disks,
        ) = struct.unpack_from("<4sLQL", raw, locator_offset)
    except struct.error as exc:
        _fail(f"cannot read ZIP publication input: {exc}")
    if locator_signature != b"PK\x06\x07" or zip64_disk or total_disks != 1:
        _fail("cannot read ZIP publication input: malformed ZIP64 locator")
    fixed_size = 56
    if zip64_offset < 0 or zip64_offset + fixed_size > len(raw):
        _fail("cannot read ZIP publication input: malformed ZIP64 end record")
    try:
        (
            zip64_signature,
            zip64_size,
            _made_by,
            _required,
            zip64_disk_number,
            zip64_central_directory_disk,
            zip64_entries_this_disk,
            zip64_entries_total,
            zip64_central_directory_size,
            zip64_central_directory_offset,
        ) = struct.unpack_from("<4sQ2H2L4Q", raw, zip64_offset)
    except struct.error as exc:
        _fail(f"cannot read ZIP publication input: {exc}")
    if (
        zip64_signature != b"PK\x06\x06"
        or zip64_size < 44
        or zip64_offset + 12 + zip64_size > len(raw)
        or zip64_disk_number
        or zip64_central_directory_disk
        or zip64_entries_this_disk != zip64_entries_total
    ):
        _fail("cannot read ZIP publication input: malformed ZIP64 end record")
    return _central_directory_member_count(
        raw,
        offset=int(zip64_central_directory_offset),
        size=int(zip64_central_directory_size),
        declared_count=int(zip64_entries_total),
        maximum_members=maximum_members,
    )


def _zip_members(
    raw: bytes, *, maximum_bytes: int, maximum_members: int, chunk_bytes: int
) -> tuple[list[tuple[str, str, int]], int]:
    member_count = _zip_member_count(raw, maximum_members=maximum_members)
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except (OSError, zipfile.BadZipFile) as exc:
        _fail(f"cannot read ZIP publication input: {exc}")
    rows: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    used_bytes = 0
    try:
        # ``member_count`` was checked before ``ZipFile`` could build this
        # bounded central-directory list.  Do not call ``infolist`` here: it
        # offers no earlier enforcement boundary.
        if len(archive.filelist) != member_count:
            _fail("cannot read ZIP publication input: inconsistent member count")
        for info in archive.filelist:
            name = info.filename
            # Validate directory entries too: an unsafe directory name can be
            # used to disguise an unsafe regular descendant.
            directory = info.is_dir() or name.endswith("/")
            candidate = name[:-1] if directory else name
            safe = _safe_label(candidate, "archive member path")
            folded = safe.casefold()
            if folded in seen:
                _fail("archive has duplicate or case-colliding members")
            seen.add(folded)
            mode = (info.external_attr >> 16) & 0xFFFF
            kind = stat.S_IFMT(mode)
            if kind and (stat.S_ISLNK(mode) or kind not in (stat.S_IFREG, stat.S_IFDIR)):
                _fail("archive has an unsupported link or special member")
            if info.flag_bits & 0x1:
                _fail("archive has encrypted members")
            if directory:
                if kind and kind != stat.S_IFDIR:
                    _fail("archive directory member type is invalid")
                continue
            if kind and kind != stat.S_IFREG:
                _fail("archive regular member type is invalid")
            try:
                with archive.open(info, "r") as handle:
                    digest, size = _read_member(
                        handle,
                        maximum_bytes=maximum_bytes - used_bytes,
                        chunk_bytes=chunk_bytes,
                    )
                    rows.append((safe, digest, size))
                    used_bytes += size
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                _fail(f"cannot read ZIP archive member: {exc}")
    finally:
        archive.close()
    return rows, member_count


def _tar_members(
    raw: bytes, *, maximum_bytes: int, maximum_members: int, chunk_bytes: int
) -> tuple[list[tuple[str, str, int]], int]:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
    except (OSError, tarfile.TarError) as exc:
        _fail(f"cannot read tar publication input: {exc}")
    rows: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    member_count = 0
    used_bytes = 0
    try:
        # TarFile iteration is lazy.  Count before retaining/processing each
        # header, so no attacker-controlled full ``getmembers`` list exists.
        for member in archive:
            member_count += 1
            if member_count > maximum_members:
                _fail("publication archive member count exceeds its bound")
            directory = member.isdir()
            candidate = member.name[:-1] if directory and member.name.endswith("/") else member.name
            safe = _safe_label(candidate, "archive member path")
            folded = safe.casefold()
            if folded in seen:
                _fail("archive has duplicate or case-colliding members")
            seen.add(folded)
            if not (directory or member.isreg()):
                _fail("archive has an unsupported link or special member")
            if directory:
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                _fail("archive regular member cannot be read")
            with extracted:
                digest, size = _read_member(
                    extracted,
                    maximum_bytes=maximum_bytes - used_bytes,
                    chunk_bytes=chunk_bytes,
                )
                rows.append((safe, digest, size))
                used_bytes += size
    finally:
        archive.close()
    return _strip_sdist_prefix(rows), member_count


def _strip_sdist_prefix(
    rows: list[tuple[str, str, int]]
) -> list[tuple[str, str, int]]:
    """Strip a single common source-distribution top-level directory."""

    if not rows:
        return rows
    split = [PurePosixPath(name).parts for name, _digest, _size in rows]
    heads = {parts[0] for parts in split if len(parts) > 1}
    if len(heads) != 1 or any(len(parts) < 2 for parts in split):
        return rows
    return [
        (PurePosixPath(*parts[1:]).as_posix(), digest, size)
        for parts, (_name, digest, size) in zip(split, rows, strict=True)
    ]


def _archive_members(
    kind: str,
    raw: bytes,
    *,
    maximum_bytes: int,
    maximum_members: int,
    chunk_bytes: int,
) -> tuple[list[tuple[str, str, int]], int]:
    if kind == "zip":
        return _zip_members(
            raw,
            maximum_bytes=maximum_bytes,
            maximum_members=maximum_members,
            chunk_bytes=chunk_bytes,
        )
    if kind == "tar":
        return _tar_members(
            raw,
            maximum_bytes=maximum_bytes,
            maximum_members=maximum_members,
            chunk_bytes=chunk_bytes,
        )
    _fail("publication archive type is unsupported")


def _walk_directory(
    root: Path, *, max_entries: int, max_files: int
) -> tuple[list[Path], int]:
    _directory(root, "publication input directory")
    files: list[Path] = []
    pending = [root]
    entry_count = 0
    while pending:
        current = pending.pop()
        _directory(current, "publication input directory")
        try:
            with os.scandir(current) as scanner:
                entries = []
                for entry in scanner:
                    entry_count += 1
                    if entry_count > max_entries:
                        _fail("publication directory entry count exceeds its bound")
                    entries.append(entry)
            entries.sort(key=lambda entry: (entry.name.casefold(), entry.name))
        except OSError as exc:
            _fail(f"cannot scan publication input directory: {exc}")
        folded: set[str] = set()
        for entry in entries:
            if entry.name.casefold() in folded:
                _fail("publication directory has case-colliding entries")
            folded.add(entry.name.casefold())
            candidate = Path(entry.path)
            try:
                metadata = candidate.lstat()
            except OSError as exc:
                _fail(f"cannot inspect publication directory entry: {exc}")
            if _is_link_like(candidate, metadata):
                _fail("publication input contains a symlink, junction, or reparse point")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(candidate)
            elif stat.S_ISREG(metadata.st_mode):
                if len(files) >= max_files:
                    _fail("publication container count exceeds its bound")
                files.append(candidate)
            else:
                _fail("publication input contains an unsupported filesystem entry")
    return (
        sorted(files, key=lambda path: (str(path).casefold(), str(path))),
        entry_count,
    )


def _manifest_sha256(containers: list[dict[str, Any]], subjects: list[dict[str, str]]) -> str:
    raw = json.dumps(
        {"containers": containers, "subjects": subjects},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def inventory_publication_subjects(
    project_root: Path | str,
    inputs: Iterable[Path | str],
    *,
    limits: PublicationSubjectLimits | None = None,
) -> dict[str, Any]:
    """Return a deterministic, content-exact inventory for publication policy.

    Every disk regular file is both a container and a subject.  ZIP/WHEEL and
    gzip-tar members add source-relative subjects; their outer archive remains
    a subject too.  The byte budget charges all observed disk and member bytes.
    """

    checked_limits = _check_limits(limits or PublicationSubjectLimits())
    root = _path_value(project_root, "project root")
    _directory(root, "project root")
    if isinstance(inputs, (str, bytes)) or not isinstance(inputs, Iterable):
        _fail("publication inputs must be an iterable of paths")
    supplied: list[Path | str] = []
    for value in inputs:
        if len(supplied) >= checked_limits.max_inputs:
            _fail(
                f"publication inputs must contain 1-{checked_limits.max_inputs} paths"
            )
        supplied.append(value)
    if not supplied:
        _fail(f"publication inputs must contain 1-{checked_limits.max_inputs} paths")

    disk_files: list[Path] = []
    filesystem_entries = 0
    input_paths: set[str] = set()
    for index, value in enumerate(supplied):
        path = _path_value(value, f"publication input {index}")
        key = os.path.normcase(str(path))
        if key in input_paths:
            _fail("publication inputs contain a duplicate or case-colliding path")
        input_paths.add(key)
        _validate_chain(path, f"publication input {index}")
        try:
            metadata = path.lstat()
        except OSError as exc:
            _fail(f"cannot inspect publication input {index}: {exc}")
        if _is_link_like(path, metadata):
            _fail("publication input is a symlink, junction, or reparse point")
        if stat.S_ISREG(metadata.st_mode):
            if len(disk_files) >= checked_limits.max_containers:
                _fail("publication container count exceeds its bound")
            disk_files.append(path)
        elif stat.S_ISDIR(metadata.st_mode):
            files, used_entries = _walk_directory(
                path,
                max_entries=checked_limits.max_filesystem_entries
                - filesystem_entries,
                max_files=checked_limits.max_containers - len(disk_files),
            )
            filesystem_entries += used_entries
            disk_files.extend(files)
        else:
            _fail("publication input is not a regular file or directory")

    containers: list[dict[str, Any]] = []
    subjects: list[dict[str, str]] = []
    container_paths: set[str] = set()
    subject_identities: set[tuple[str, str]] = set()
    archive_members = 0
    total_bytes = 0

    def add_subject(path: str, digest: str, byte_count: int) -> None:
        nonlocal total_bytes
        safe = _safe_label(path, "publication subject path")
        folded = safe.casefold()
        identity = (folded, digest)
        if identity in subject_identities:
            return
        if len(subjects) >= checked_limits.max_subjects:
            _fail("publication subject count exceeds its bound")
        if total_bytes + byte_count > checked_limits.max_total_bytes:
            _fail("publication subject bytes exceed their bound")
        subject_identities.add(identity)
        subjects.append({"path": safe, "sha256": digest})
        total_bytes += byte_count

    for path in sorted(disk_files, key=lambda item: (str(item).casefold(), str(item))):
        label = _disk_label(root, path)
        folded = label.casefold()
        if folded in container_paths:
            _fail("publication containers contain a duplicate or case-colliding path")
        if len(containers) >= checked_limits.max_containers:
            _fail("publication container count exceeds its bound")
        current_metadata = _regular_file(path, "publication input file")
        if total_bytes + (2 * current_metadata.st_size) > checked_limits.max_total_bytes:
            _fail("publication container bytes exceed their bound")
        digest, size, raw = _snapshot_regular_file(
            path,
            "publication input file",
            checked_limits.chunk_bytes,
            checked_limits.max_total_bytes - total_bytes,
        )
        # Count the physical input once as a container, then once as a regular
        # subject.  Archive members are charged in addition so a compressed
        # bomb cannot hide behind a small outer file.
        if total_bytes + size > checked_limits.max_total_bytes:
            _fail("publication container bytes exceed their bound")
        container_paths.add(folded)
        containers.append({"path": label, "sha256": digest, "size_bytes": size})
        total_bytes += size
        add_subject(label, digest, size)
        kind = _archive_kind(label)
        if kind is None:
            continue
        member_rows, member_count = _archive_members(
            kind,
            raw,
            maximum_bytes=checked_limits.max_total_bytes - total_bytes,
            maximum_members=checked_limits.max_archive_members - archive_members,
            chunk_bytes=checked_limits.chunk_bytes,
        )
        archive_members += member_count
        for member_path, member_digest, member_size in member_rows:
            add_subject(member_path, member_digest, member_size)

    containers.sort(key=lambda row: (str(row["path"]).casefold(), str(row["path"])))
    subjects.sort(
        key=lambda row: (row["path"].casefold(), row["path"], row["sha256"])
    )
    return {
        "containers": containers,
        "subjects": subjects,
        "manifest_sha256": _manifest_sha256(containers, subjects),
    }


# Short alias for policy modules that prefer a verb without the domain noun.
build_publication_subject_inventory = inventory_publication_subjects


__all__ = [
    "PublicationSubjectError",
    "PublicationSubjectLimits",
    "build_publication_subject_inventory",
    "inventory_publication_subjects",
]
