"""Create/remove AOI's uniquely owned CI coverage bootstrap.

This is a cooperative quiescent same-user boundary.  It fail-closes on an
observably changed path, but does not prove historical file-object identity or
defeat hostile concurrent path substitution.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import json
import os
import stat
import sys
from typing import Any, Callable


PTH_NAME = "aoi_coverage_bootstrap.pth"
MODULE_NAMES = (
    "aoi_coverage_bootstrap.py",
    "aoi_coverage_fork_runtime.py",
    "aoi_coverage_fragment_attribution.py",
)
SCHEMA_VERSION = 3
MAX_PATH_LENGTH = 4096
MAX_RECEIPT_BYTES = 32768
MAX_MODULE_BYTES = 1048576
MAX_DEPENDENCY_ROOTS = 8
MAX_JSON_DEPTH = 12


class CoverageBootstrapInstallError(RuntimeError):
    """Raised when the narrowly owned bootstrap cannot be proved safe."""


class CoverageBootstrapEffectUnknownError(CoverageBootstrapInstallError):
    """A create-exclusive residue could not be reconciled safely."""

    def __init__(self, paths: tuple[str, ...]) -> None:
        self.paths = paths
        super().__init__("effect_unknown; reconcile required: " + ", ".join(paths))


def _typed(label: str, error: OSError) -> CoverageBootstrapInstallError:
    return CoverageBootstrapInstallError(f"{label}: {error.strerror or error}")


def _require_string(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise CoverageBootstrapInstallError(f"{label} must be a non-empty string")
    if len(value) > MAX_PATH_LENGTH or any(char in value for char in ("\x00", "\r", "\n")):
        raise CoverageBootstrapInstallError(f"{label} is malformed")
    return value


def _parts_are_safe(path: str, label: str) -> None:
    drive, tail = os.path.splitdrive(path)
    anchor = drive + os.path.sep if drive else os.path.sep
    current = anchor
    if os.path.altsep:
        tail = tail.replace(os.path.altsep, os.path.sep)
    for part in (item for item in tail.split(os.path.sep) if item):
        if part in (".", "..") or part != part.strip():
            raise CoverageBootstrapInstallError(f"{label} has an unsafe component")
        current = os.path.join(current, part)
        try:
            metadata = os.lstat(current)
        except OSError as error:
            raise _typed(f"{label} component is unavailable", error) from error
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        attributes = getattr(metadata, "st_file_attributes", 0)
        if stat.S_ISLNK(metadata.st_mode) or (reparse and attributes & reparse):
            raise CoverageBootstrapInstallError(f"{label} has a link or reparse ancestor")


def _canonical_directory(value: object, label: str) -> str:
    raw = _require_string(value, label)
    if not os.path.isabs(raw) or raw != raw.strip():
        raise CoverageBootstrapInstallError(f"{label} must be an absolute whitespace-safe path")
    _parts_are_safe(raw, label)
    try:
        resolved = os.path.realpath(raw)
        _parts_are_safe(resolved, label)
        metadata = os.lstat(resolved)
    except CoverageBootstrapInstallError:
        raise
    except OSError as error:
        raise _typed(f"{label} is unavailable", error) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise CoverageBootstrapInstallError(f"{label} must be an existing non-link directory")
    return resolved


def _canonical_file_path(value: object, label: str) -> str:
    raw = _require_string(value, label)
    if not os.path.isabs(raw) or raw != raw.strip():
        raise CoverageBootstrapInstallError(f"{label} must be an absolute whitespace-safe path")
    parent, name = os.path.dirname(raw), os.path.basename(raw)
    if not name or name in (".", "..") or name != name.strip():
        raise CoverageBootstrapInstallError(f"{label} is malformed")
    return os.path.join(_canonical_directory(parent, f"{label} parent"), name)


def _validated_roots(
    site_root: object, startup_root: object, dependency_roots: object
) -> tuple[str, str, tuple[str, ...]]:
    site = _canonical_directory(site_root, "site root")
    startup = _canonical_directory(startup_root, "startup root")
    if type(dependency_roots) not in (tuple, list):
        raise CoverageBootstrapInstallError("dependency roots must be a tuple or list")
    if len(dependency_roots) > MAX_DEPENDENCY_ROOTS:
        raise CoverageBootstrapInstallError("too many dependency roots")
    dependencies = tuple(_canonical_directory(item, "dependency root") for item in dependency_roots)
    identities = tuple(os.path.normcase(item) for item in (*dependencies, startup))
    if len(set(identities)) != len(identities):
        raise CoverageBootstrapInstallError("bootstrap roots must not be duplicated")
    return site, startup, dependencies


def _content(startup: str, dependencies: tuple[str, ...]) -> bytes:
    return ("\n".join((*dependencies, startup, "import aoi_coverage_bootstrap")) + "\n").encode("utf-8")


def bootstrap_content(startup_root: object, dependency_roots: object = ()) -> bytes:
    startup = _canonical_directory(startup_root, "startup root")
    # A synthetic site root only lets this public formatter reuse exact root checks.
    _site, startup, dependencies = _validated_roots(os.path.dirname(startup), startup, dependency_roots)
    return _content(startup, dependencies)


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _identity_time_ns(metadata: os.stat_result) -> int:
    # Python 3.12+ exposes Windows creation time as st_birthtime_ns.  On
    # Python 3.14, descriptor st_ctime_ns instead aliases mtime while path
    # st_ctime_ns remains the deprecated creation-time view, so it cannot be
    # compared across lstat/fstat.  POSIX ctime is the intended inode-change
    # discriminator; older Windows Pythons still expose creation time there.
    birthtime_ns = getattr(metadata, "st_birthtime_ns", None)
    if os.name == "nt" and type(birthtime_ns) is int:
        return birthtime_ns
    return int(metadata.st_ctime_ns)


def _identity_from_stat(metadata: os.stat_result) -> dict[str, int | None]:
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or (reparse and attributes & reparse)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise CoverageBootstrapInstallError("file must be a non-link, non-reparse regular nlink=1 file")
    return {
        "device": int(metadata.st_dev), "inode": int(metadata.st_ino), "nlink": int(metadata.st_nlink),
        "size": int(metadata.st_size), "identity_time_ns": _identity_time_ns(metadata),
        "mode": stat.S_IMODE(metadata.st_mode) if os.name == "posix" else None,
        "uid": int(metadata.st_uid) if os.name == "posix" else None,
    }


def _identity(path: str) -> dict[str, int | None]:
    try:
        return _identity_from_stat(os.lstat(path))
    except CoverageBootstrapInstallError:
        raise
    except OSError as error:
        raise _typed("file identity is unavailable", error) from error


def _same_created_file(
    current: dict[str, int | None], expected: dict[str, int | None]
) -> bool:
    """Compare fields stable across our own chmod, partial write, and fsync."""

    return all(current[key] == expected[key] for key in ("device", "inode", "nlink", "uid"))


def _read_exact(path: str, limit: int) -> bytes:
    try:
        path_identity = _identity(path)
    except CoverageBootstrapInstallError as error:
        if isinstance(error.__cause__, OSError):
            raise _typed("file open failed", error.__cause__) from error.__cause__
        raise
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise _typed("file open failed", error) from error
    failure: BaseException | None = None
    try:
        metadata = os.fstat(descriptor)
        opened_identity = _identity_from_stat(metadata)
        if opened_identity != path_identity:
            raise CoverageBootstrapInstallError("file changed while it was opened")
        if metadata.st_size > limit:
            raise CoverageBootstrapInstallError("file exceeds its bound")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(4096, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            raise CoverageBootstrapInstallError("file exceeds its bound")
        if _identity(path) != opened_identity:
            raise CoverageBootstrapInstallError("file changed during read")
        return data
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError as error:
            if failure is None:
                raise _typed("file close failed", error) from error


def _create_write(
    path: str, payload: bytes, created: Callable[[dict[str, int | None] | None], None]
) -> dict[str, int | None]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise _typed("exclusive create failed", error) from error
    failure: BaseException | None = None
    try:
        created(None)
        identity = _identity_from_stat(os.fstat(descriptor))
        created(identity)
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(descriptor)
        identity = _identity_from_stat(os.fstat(descriptor))
        created(identity)
    except OSError as error:
        failure = _typed("exclusive write failed", error)
        raise failure from error
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError as error:
            if failure is None:
                raise _typed("exclusive close failed", error) from error
    if _identity(path) != identity or _read_exact(path, len(payload)) != payload:
        raise CoverageBootstrapInstallError("exclusive target changed before binding")
    return identity


def _delete_if_exact(path: str, expected: dict[str, int | None], content: bytes) -> None:
    # Check twice so an unlink/recreate that happens during the first content
    # read is still rejected even when the filesystem immediately reuses the
    # same inode metadata.  This remains cooperative only; Python has no
    # portable unlink-by-open-file primitive for a hostile concurrent writer.
    for _attempt in range(2):
        if _identity(path) != expected or _read_exact(path, len(content)) != content:
            raise CoverageBootstrapInstallError("bootstrap target changed; refusing removal")
    if _identity(path) != expected:
        raise CoverageBootstrapInstallError("bootstrap target changed; refusing removal")
    try:
        os.unlink(path)
    except OSError as error:
        raise _typed("bootstrap unlink failed", error) from error


def _delete_created_if_exact(path: str, expected: dict[str, int | None]) -> None:
    """Undo one create-exclusive path without requiring its partial content."""

    if not _same_created_file(_identity(path), expected):
        raise CoverageBootstrapInstallError("created path changed; refusing rollback")
    try:
        os.unlink(path)
    except OSError as error:
        raise _typed("created-path rollback unlink failed", error) from error


def _rollback(
    path: str | None, created: bool, identity: dict[str, int | None] | None
) -> tuple[str, ...]:
    if path is None or not created:
        return ()
    if identity is None:
        return (path,)
    try:
        _delete_created_if_exact(path, identity)
    except BaseException:
        return (path,)
    return ()


def _effect_unknown(error: BaseException, paths: tuple[str, ...]) -> None:
    diagnostic = CoverageBootstrapEffectUnknownError(paths)
    if isinstance(error, (MemoryError, SystemExit, KeyboardInterrupt)):
        try:
            error.add_note(str(diagnostic))
        except AttributeError:
            pass
        raise error
    raise diagnostic from error


def _require_receipt_bound(payload: bytes) -> None:
    if len(payload) > MAX_RECEIPT_BYTES:
        raise CoverageBootstrapInstallError("canonical receipt exceeds its bound")


def _module_witness(startup: str, name: str) -> dict[str, Any]:
    path = os.path.join(startup, name)
    data = _read_exact(path, MAX_MODULE_BYTES)
    identity = _identity(path)
    return {"identity": identity, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def _module_witnesses(startup: str) -> dict[str, dict[str, Any]]:
    return {name: _module_witness(startup, name) for name in MODULE_NAMES}


def _valid_witness(value: object) -> bool:
    if type(value) is not dict or set(value) != {"identity", "sha256", "size"}:
        return False
    identity = value["identity"]
    return (
        type(value["sha256"]) is str and len(value["sha256"]) == 64
        and type(value["size"]) is int and value["size"] >= 0
        and type(identity) is dict and set(identity) == {"device", "inode", "nlink", "size", "identity_time_ns", "mode", "uid"}
        and all(type(identity[key]) is int for key in ("device", "inode", "nlink", "size", "identity_time_ns"))
        and identity["size"] >= 0 and identity["identity_time_ns"] >= 0
        and all(identity[key] is None or type(identity[key]) is int for key in ("mode", "uid"))
    )


def _assert_no_import_collisions(roots: tuple[str, ...]) -> None:
    suffixes = (".py", ".pyc", *importlib.machinery.EXTENSION_SUFFIXES)
    for root in roots:
        for module in (name[:-3] for name in MODULE_NAMES):
            for candidate in (module, *(module + suffix for suffix in suffixes)):
                path = os.path.join(root, candidate)
                try:
                    os.lstat(path)
                except FileNotFoundError:
                    continue
                except OSError as error:
                    raise _typed("import-collision check failed", error) from error
                raise CoverageBootstrapInstallError(f"import collision at {path}")


def install(*, site_root: object, startup_root: object, receipt_path: object, dependency_roots: object = ()) -> dict[str, Any]:
    """Create bootstrap plus an exclusive, canonical witness receipt."""

    target: str | None = None
    target_identity: dict[str, int | None] | None = None
    target_created = False
    receipt: str | None = None
    receipt_identity: dict[str, int | None] | None = None
    receipt_created = False
    try:
        site, startup, dependencies = _validated_roots(site_root, startup_root, dependency_roots)
        receipt = _canonical_file_path(receipt_path, "receipt path")
        target = os.path.join(site, PTH_NAME)
        if os.path.lexists(target) or os.path.lexists(receipt):
            raise CoverageBootstrapInstallError("bootstrap target or receipt already exists")
        witnesses = _module_witnesses(startup)
        _assert_no_import_collisions((site, *dependencies))
        content = _content(startup, dependencies)
        def mark_target(value: dict[str, int | None] | None) -> None:
            nonlocal target_created, target_identity
            target_created = True
            if value is not None:
                target_identity = value

        target_identity = _create_write(target, content, mark_target)
        record: dict[str, Any] = {
            "content_sha256": hashlib.sha256(content).hexdigest(), "dependency_roots": list(dependencies),
            "module_witnesses": witnesses, "schema_version": SCHEMA_VERSION, "site_root": site,
            "startup_root": startup, "target_identity": target_identity, "target_path": target,
        }
        receipt_bytes = _canonical_json(record)
        _require_receipt_bound(receipt_bytes)

        def mark_receipt(value: dict[str, int | None] | None) -> None:
            nonlocal receipt_created, receipt_identity
            receipt_created = True
            if value is not None:
                receipt_identity = value

        receipt_identity = _create_write(receipt, receipt_bytes, mark_receipt)
        return record
    except BaseException as error:
        remaining = _rollback(receipt, receipt_created, receipt_identity)
        remaining += _rollback(target, target_created, target_identity)
        if remaining:
            _effect_unknown(error, remaining)
        if isinstance(error, CoverageBootstrapInstallError):
            raise
        if isinstance(error, OSError):
            raise _typed("coverage bootstrap installation failed", error) from error
        raise


def _no_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CoverageBootstrapInstallError("receipt has duplicate keys")
        result[key] = value
    return result


def _exceeds_json_depth(value: object, limit: int) -> bool:
    pending: list[tuple[object, int]] = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if type(current) is dict:
            child_depth = depth + 1
            if child_depth > limit:
                return True
            pending.extend((item, child_depth) for item in current.values())
        elif type(current) is list:
            child_depth = depth + 1
            if child_depth > limit:
                return True
            pending.extend((item, child_depth) for item in current)
    return False


def _load_receipt(receipt_path: object) -> dict[str, Any]:
    receipt = _canonical_file_path(receipt_path, "receipt path")
    try:
        payload = _read_exact(receipt, MAX_RECEIPT_BYTES)
        parsed = json.loads(payload.decode("utf-8"), object_pairs_hook=_no_duplicate_pairs)
    except CoverageBootstrapInstallError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise CoverageBootstrapInstallError("receipt is unreadable") from error
    if type(parsed) is not dict or _exceeds_json_depth(parsed, MAX_JSON_DEPTH) or _canonical_json(parsed) != payload:
        raise CoverageBootstrapInstallError("receipt schema is invalid or non-canonical")
    return parsed


def _remove_record(record: dict[str, Any]) -> None:
    keys = {"content_sha256", "dependency_roots", "module_witnesses", "schema_version", "site_root", "startup_root", "target_identity", "target_path"}
    if set(record) != keys or type(record["schema_version"]) is not int or record["schema_version"] != SCHEMA_VERSION:
        raise CoverageBootstrapInstallError("receipt schema is invalid")
    site, startup, dependencies = _validated_roots(record["site_root"], record["startup_root"], record["dependency_roots"])
    target = record["target_path"]
    if type(target) is not str or target != os.path.join(site, PTH_NAME):
        raise CoverageBootstrapInstallError("receipt target is invalid")
    expected = record["target_identity"]
    if type(expected) is not dict or set(expected) != {"device", "inode", "nlink", "size", "identity_time_ns", "mode", "uid"}:
        raise CoverageBootstrapInstallError("receipt target identity is invalid")
    if (
        any(type(expected[key]) is not int for key in ("device", "inode", "nlink", "size", "identity_time_ns"))
        or expected["size"] < 0
        or expected["identity_time_ns"] < 0
        or any(expected[key] is not None and type(expected[key]) is not int for key in ("mode", "uid"))
    ):
        raise CoverageBootstrapInstallError("receipt target identity is invalid")
    witnesses = record["module_witnesses"]
    if type(witnesses) is not dict or set(witnesses) != set(MODULE_NAMES) or not all(_valid_witness(item) for item in witnesses.values()) or witnesses != _module_witnesses(startup):
        raise CoverageBootstrapInstallError("startup module witnesses changed")
    content = _content(startup, dependencies)
    if type(record["content_sha256"]) is not str or record["content_sha256"] != hashlib.sha256(content).hexdigest():
        raise CoverageBootstrapInstallError("receipt content hash is invalid")
    _delete_if_exact(target, expected, content)


def remove(*, receipt_path: object) -> None:
    """Remove a cooperative current target matching the receipt and bytes.

    A byte-identical replacement that aliases every observable metadata field
    is indistinguishable here; hostile same-user substitution is out of scope.
    """

    try:
        _remove_record(_load_receipt(receipt_path))
    except CoverageBootstrapInstallError:
        raise
    except OSError as error:
        raise _typed("coverage bootstrap removal failed", error) from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    install_parser = commands.add_parser("install")
    install_parser.add_argument("--site-root", required=True)
    install_parser.add_argument("--startup-root", required=True)
    install_parser.add_argument("--receipt", required=True)
    install_parser.add_argument("--dependency-root", action="append", default=[])
    commands.add_parser("remove").add_argument("--receipt", required=True)
    return parser


def _publish_cli_error(error: CoverageBootstrapInstallError) -> None:
    try:
        print(f"coverage bootstrap: {error}", file=sys.stderr)
    except (MemoryError, SystemExit, KeyboardInterrupt) as diagnostic_error:
        try:
            diagnostic_error.add_note(f"stderr publication failed while reporting: {error}")
        except AttributeError:
            pass
        raise
    except Exception as stderr_error:
        try:
            error.add_note(f"stderr publication failed: {stderr_error}")
        except AttributeError:
            pass
        raise error from stderr_error


def main(argv: list[str] | None = None) -> int:
    if argv is not None and type(argv) is not list:
        raise TypeError("argv must be a list or None")
    arguments = _parser().parse_args(argv)
    record: dict[str, Any] | None = None
    try:
        if arguments.command == "install":
            record = install(site_root=arguments.site_root, startup_root=arguments.startup_root, receipt_path=arguments.receipt, dependency_roots=arguments.dependency_root)
            payload = _canonical_json(record)
            if sys.stdout.buffer.write(payload) != len(payload):
                raise OSError("short stdout write")
        else:
            remove(receipt_path=arguments.receipt)
    except BaseException as error:
        if record is not None:
            expected = record["target_identity"]
            target = record["target_path"]
            if type(expected) is dict and type(target) is str:
                remaining = _rollback(target, True, expected)
                if remaining:
                    if isinstance(error, (MemoryError, SystemExit, KeyboardInterrupt)):
                        _effect_unknown(error, remaining)
                    error = CoverageBootstrapEffectUnknownError(remaining)
        if isinstance(error, (MemoryError, SystemExit, KeyboardInterrupt)):
            raise
        if isinstance(error, OSError):
            error = _typed("CLI failure", error)
        if isinstance(error, CoverageBootstrapInstallError):
            _publish_cli_error(error)
            return 2
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
