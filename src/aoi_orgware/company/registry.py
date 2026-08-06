"""Cooperative company registry."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Protocol
import uuid

from .contracts import (
    ZERO_SHA256,
    CompanyContractError,
    canonical_company_json_bytes,
    company_contract_sha256,
    validate_company_manifest,
)
from .native_filesystem import fsync_directory as _fsync, native_filesystem_path as _native


_COMPANY_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,127}")
_INCARNATION_ID_RE = re.compile(r"i[0-9]{8}-[0-9a-f]{12}")
_PLATFORMS = frozenset({"windows", "posix"})
_POINTER_FIELDS = {
    "schema_version",
    "company_id",
    "incarnation_id",
    "company_incarnation",
    "lock_domain_generation",
    "manifest_sha256",
    "updated_at",
    "previous_pointer_sha256",
    "pointer_sha256",
}
_PLATFORM_FIELDS = {
    "schema_version",
    "company_id",
    "platform",
    "lock_domain_id",
    "created_at",
    "marker_sha256",
}


class CompanyRegistryError(RuntimeError):
    """A stable company slot or incarnation pointer is unsafe or inconsistent."""


class CompanyPointerConflictError(CompanyRegistryError):
    """The active pointer compare-and-swap precondition did not match."""


class CompanyRebindRequiredError(CompanyRegistryError):
    """A related company exists but its repository binding is not exact."""


class CompanyLockWitness(Protocol):
    """Small authority surface required from ``CompanyProcessLock``."""

    def assert_owned(self) -> None:
        """Raise unless the current process still owns the lifetime lock."""


@dataclass(frozen=True)
class CompanyIncarnationPaths:
    root: Path
    manifest: Path
    ledger: Path
    readmodel: Path
    blobs: Path
    checkpoints: Path
    exports: Path
    spool: Path


@dataclass(frozen=True)
class CompanySlotPaths:
    root: Path
    lock: Path
    platform: Path
    current: Path
    incarnations: Path

    @classmethod
    def from_root(cls, root: str | os.PathLike[str]) -> CompanySlotPaths:
        supplied = Path(root)
        if not supplied.is_absolute() or ".." in supplied.parts:
            raise CompanyRegistryError(
                "company slot must be an explicit traversal-free absolute path",
            )
        return cls(
            root=supplied,
            lock=supplied / "company.lock",
            platform=supplied / "platform.json",
            current=supplied / "current.json",
            incarnations=supplied / "incarnations",
        )

    def incarnation(self, incarnation_id: str) -> CompanyIncarnationPaths:
        _require_incarnation_id(incarnation_id)
        root = self.incarnations / incarnation_id
        return CompanyIncarnationPaths(
            root=root,
            manifest=root / "manifest.json",
            ledger=root / "ledger.sqlite3",
            readmodel=root / "readmodel.sqlite3",
            blobs=root / "blobs",
            checkpoints=root / "checkpoints",
            exports=root / "exports",
            spool=root / "spool",
        )


@dataclass(frozen=True)
class CompanyCurrentPointer:
    company_id: str
    incarnation_id: str
    company_incarnation: int
    lock_domain_generation: int
    manifest_sha256: str
    updated_at: str
    previous_pointer_sha256: str
    pointer_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "company_id": self.company_id,
            "incarnation_id": self.incarnation_id,
            "company_incarnation": self.company_incarnation,
            "lock_domain_generation": self.lock_domain_generation,
            "manifest_sha256": self.manifest_sha256,
            "updated_at": self.updated_at,
            "previous_pointer_sha256": self.previous_pointer_sha256,
            "pointer_sha256": self.pointer_sha256,
        }


@dataclass(frozen=True)
class ResolvedCompanyState:
    slot: CompanySlotPaths
    pointer: CompanyCurrentPointer
    incarnation: CompanyIncarnationPaths
    manifest: Mapping[str, Any]


def _assert_incarnation_layout(
    incarnation: CompanyIncarnationPaths,
    *,
    label: str,
) -> None:
    """Verify every required directory without traversing a link.

    Ledger/readmodel files may be absent for a freshly prepared incarnation;
    the stable root and content/checkpoint/export/spool directories may not.
    This check must run before publishing ``current.json`` so readback cannot
    be the first place an invalid successor is discovered.
    """

    _assert_directory(incarnation.root, f"{label} root")
    for path, member in (
        (incarnation.blobs, "blobs"),
        (incarnation.checkpoints, "checkpoints"),
        (incarnation.exports, "exports"),
        (incarnation.spool, "spool"),
    ):
        _assert_directory(path, f"{label} {member} directory")


def _require_lock(lock: CompanyLockWitness) -> None:
    try:
        lock.assert_owned()
    except CompanyRegistryError:
        raise
    except Exception as exc:
        raise CompanyRegistryError(
            "company lifetime lock witness is not owned",
        ) from exc


def _require_company_id(value: object) -> str:
    if not isinstance(value, str) or _COMPANY_ID_RE.fullmatch(value) is None:
        raise CompanyRegistryError("company ID is invalid")
    return value


def _require_incarnation_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or _INCARNATION_ID_RE.fullmatch(value) is None
    ):
        raise CompanyRegistryError("incarnation ID is invalid")
    return value


def _require_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[0-9a-f]{64}", value) is None
    ):
        raise CompanyRegistryError(f"{label} is invalid")
    return value


def _require_positive_integer(value: object, label: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > 999_999_999
    ):
        raise CompanyRegistryError(f"{label} is invalid")
    return value


def _require_timestamp(value: object) -> str:
    if not isinstance(value, str):
        raise CompanyRegistryError("pointer timestamp is invalid")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise CompanyRegistryError("pointer timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise CompanyRegistryError("pointer timestamp lacks a timezone")
    return value


def _is_windows_reparse_point(metadata: os.stat_result) -> bool:
    if os.name != "nt":
        return False
    attributes = getattr(metadata, "st_file_attributes", None)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", None)
    if not isinstance(attributes, int) or not isinstance(reparse, int):
        raise CompanyRegistryError(
            "Windows reparse-point inspection is unavailable",
        )
    return bool(attributes & reparse)


def _assert_directory(path: Path, label: str) -> os.stat_result:
    try:
        metadata = os.lstat(_native(path))
    except OSError as exc:
        raise CompanyRegistryError(f"{label} is unavailable: {path}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_windows_reparse_point(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise CompanyRegistryError(f"{label} must be a non-link directory")
    return metadata


def _assert_regular(path: Path, label: str) -> os.stat_result:
    try:
        metadata = os.lstat(_native(path))
    except OSError as exc:
        raise CompanyRegistryError(f"{label} is unavailable: {path}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_windows_reparse_point(metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or int(metadata.st_nlink) != 1
    ):
        raise CompanyRegistryError(
            f"{label} must be one regular non-linked file",
        )
    return metadata


def _ensure_private_directory(path: Path, label: str) -> None:
    try:
        os.mkdir(_native(path), mode=0o700)
    except FileExistsError:
        _assert_directory(path, label)
    except OSError as exc:
        raise CompanyRegistryError(f"cannot create {label}: {path}") from exc
    try:
        if os.name != "nt":
            os.chmod(_native(path), 0o700)
    except OSError as exc:
        raise CompanyRegistryError(f"cannot protect {label}: {path}") from exc
    _assert_directory(path, label)


def _atomic_replace(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            _native(temporary),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            _native(temporary),
            _native(path),
        )
        if os.name != "nt":
            os.chmod(_native(path), 0o600)
        _assert_regular(path, "published company registry member")
        _fsync(path.parent)
    except OSError as exc:
        raise CompanyRegistryError(
            f"cannot publish company registry member: {path}",
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(_native(temporary))
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _create_immutable(path: Path, payload: bytes, label: str) -> None:
    try:
        descriptor = os.open(
            _native(path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        _assert_regular(path, label)
        with open(_native(path), "rb") as source:
            existing = source.read(len(payload) + 1)
        if existing != payload:
            raise CompanyRegistryError(f"{label} already has divergent bytes")
        return
    except OSError as exc:
        raise CompanyRegistryError(f"cannot create {label}: {path}") from exc
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(_native(path), 0o600)
        _assert_regular(path, label)
        _fsync(path.parent)
    except BaseException:
        try:
            os.unlink(_native(path))
        except FileNotFoundError:
            pass
        except OSError:
            pass
        raise


def _read_json(path: Path, label: str, *, maximum: int = 256 * 1024) -> Any:
    metadata = _assert_regular(path, label)
    if int(metadata.st_size) > maximum:
        raise CompanyRegistryError(f"{label} exceeds its byte bound")
    try:
        with open(_native(path), "rb") as source:
            raw = source.read(maximum + 1)
        value = json.loads(raw.decode("utf-8", "strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CompanyRegistryError(f"{label} is not canonical JSON") from exc
    if canonical_company_json_bytes(value) != raw:
        raise CompanyRegistryError(f"{label} is not canonical JSON")
    return value


def _pointer_from_value(value: Any) -> CompanyCurrentPointer:
    if not isinstance(value, dict) or set(value) != _POINTER_FIELDS:
        raise CompanyRegistryError("current pointer schema is invalid")
    if value["schema_version"] != 1:
        raise CompanyRegistryError("current pointer schema version is invalid")
    unsigned = {
        key: value[key]
        for key in _POINTER_FIELDS
        if key != "pointer_sha256"
    }
    pointer_sha256 = _require_sha256(
        value["pointer_sha256"],
        "pointer digest",
    )
    if company_contract_sha256(unsigned) != pointer_sha256:
        raise CompanyRegistryError("current pointer digest differs")
    company_incarnation = _require_positive_integer(
        value["company_incarnation"],
        "company incarnation",
    )
    incarnation_id = _require_incarnation_id(value["incarnation_id"])
    manifest_sha256 = _require_sha256(
        value["manifest_sha256"],
        "manifest digest",
    )
    previous_pointer_sha256 = _require_sha256(
        value["previous_pointer_sha256"],
        "previous pointer digest",
    )
    if incarnation_id != (
        f"i{company_incarnation:08d}-{manifest_sha256[:12]}"
    ):
        raise CompanyRegistryError(
            "incarnation ID does not bind its manifest digest",
        )
    if (company_incarnation == 1) != (
        previous_pointer_sha256 == ZERO_SHA256
    ):
        raise CompanyRegistryError(
            "current pointer predecessor and incarnation differ",
        )
    return CompanyCurrentPointer(
        company_id=_require_company_id(value["company_id"]),
        incarnation_id=incarnation_id,
        company_incarnation=company_incarnation,
        lock_domain_generation=_require_positive_integer(
            value["lock_domain_generation"],
            "lock-domain generation",
        ),
        manifest_sha256=manifest_sha256,
        updated_at=_require_timestamp(value["updated_at"]),
        previous_pointer_sha256=previous_pointer_sha256,
        pointer_sha256=pointer_sha256,
    )


def _new_pointer(
    manifest: Mapping[str, Any],
    manifest_sha256: str,
    previous_pointer_sha256: str,
    *,
    updated_at: str | None = None,
) -> CompanyCurrentPointer:
    company_incarnation = int(manifest["company_incarnation"])
    incarnation_id = (
        f"i{company_incarnation:08d}-{manifest_sha256[:12]}"
    )
    unsigned: dict[str, Any] = {
        "schema_version": 1,
        "company_id": str(manifest["company_id"]),
        "incarnation_id": incarnation_id,
        "company_incarnation": company_incarnation,
        "lock_domain_generation": int(
            manifest["lock_domain_generation"],
        ),
        "manifest_sha256": manifest_sha256,
        "updated_at": updated_at
        or datetime.now(UTC).replace(microsecond=0).isoformat().replace(
            "+00:00",
            "Z",
        ),
        "previous_pointer_sha256": previous_pointer_sha256,
    }
    return CompanyCurrentPointer(
        company_id=str(unsigned["company_id"]),
        incarnation_id=str(unsigned["incarnation_id"]),
        company_incarnation=int(unsigned["company_incarnation"]),
        lock_domain_generation=int(unsigned["lock_domain_generation"]),
        manifest_sha256=str(unsigned["manifest_sha256"]),
        updated_at=str(unsigned["updated_at"]),
        previous_pointer_sha256=str(
            unsigned["previous_pointer_sha256"],
        ),
        pointer_sha256=company_contract_sha256(unsigned),
    )


class CompanyRegistry:
    """Manage one stable company slot under an already-held lifetime lock."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.paths = CompanySlotPaths.from_root(root)

    def _assert_layout(self) -> None:
        _assert_directory(self.paths.root, "company slot")
        _assert_directory(self.paths.incarnations, "incarnations directory")

    def _ensure_layout(self) -> None:
        _assert_directory(self.paths.root, "company slot")
        _ensure_private_directory(
            self.paths.incarnations,
            "incarnations directory",
        )

    def _platform_marker(
        self,
        company_id: str,
        platform: str,
        lock_domain_id: str,
    ) -> dict[str, Any]:
        unsigned: dict[str, Any] = {
            "schema_version": 1,
            "company_id": company_id,
            "platform": platform,
            "lock_domain_id": lock_domain_id,
            "created_at": datetime.now(UTC)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        return {
            **unsigned,
            "marker_sha256": company_contract_sha256(unsigned),
        }

    def _read_platform(self) -> dict[str, Any]:
        value = _read_json(self.paths.platform, "platform marker")
        if not isinstance(value, dict) or set(value) != _PLATFORM_FIELDS:
            raise CompanyRegistryError("platform marker schema is invalid")
        if (
            value["schema_version"] != 1
            or value["platform"] not in _PLATFORMS
        ):
            raise CompanyRegistryError("platform marker values are invalid")
        _require_company_id(value["company_id"])
        if not isinstance(value["lock_domain_id"], str):
            raise CompanyRegistryError("platform lock-domain ID is invalid")
        _require_timestamp(value["created_at"])
        marker = _require_sha256(value["marker_sha256"], "platform marker")
        unsigned = {
            key: value[key]
            for key in _PLATFORM_FIELDS
            if key != "marker_sha256"
        }
        if company_contract_sha256(unsigned) != marker:
            raise CompanyRegistryError("platform marker digest differs")
        return value

    def _prepare_incarnation(
        self,
        lock: CompanyLockWitness,
        manifest: Mapping[str, Any],
    ) -> tuple[CompanyCurrentPointer, CompanyIncarnationPaths, dict[str, Any]]:
        _require_lock(lock)
        self._ensure_layout()
        try:
            normalized = validate_company_manifest(manifest)
        except CompanyContractError as exc:
            raise CompanyRegistryError("company manifest is invalid") from exc
        manifest_bytes = canonical_company_json_bytes(normalized)
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        pointer = _new_pointer(normalized, manifest_sha256, ZERO_SHA256)
        incarnation = self.paths.incarnation(pointer.incarnation_id)
        _ensure_private_directory(
            incarnation.root,
            "company incarnation directory",
        )
        for directory, label in (
            (incarnation.blobs, "company blob directory"),
            (incarnation.checkpoints, "company checkpoint directory"),
            (incarnation.exports, "company export directory"),
            (incarnation.spool, "company spool directory"),
        ):
            _ensure_private_directory(directory, label)
        _create_immutable(
            incarnation.manifest,
            manifest_bytes,
            "company incarnation manifest",
        )
        return pointer, incarnation, normalized

    def initialize(
        self,
        lock: CompanyLockWitness,
        manifest: Mapping[str, Any],
        *,
        platform: str,
    ) -> ResolvedCompanyState:
        """Create or exactly replay one genesis company pointer."""

        _require_lock(lock)
        if platform not in _PLATFORMS:
            raise CompanyRegistryError("company platform is invalid")
        if self.paths.current.exists():
            try:
                requested = validate_company_manifest(manifest)
            except CompanyContractError as exc:
                raise CompanyRegistryError("company manifest is invalid") from exc
            resolved = self.resolve_current(lock)
            marker = self._read_platform()
            if (
                canonical_company_json_bytes(resolved.manifest)
                != canonical_company_json_bytes(requested)
                or marker["platform"] != platform
            ):
                raise CompanyPointerConflictError(
                    "company already has a different active incarnation",
                )
            return resolved
        pointer, incarnation, normalized = self._prepare_incarnation(
            lock,
            manifest,
        )
        company_id = str(normalized["company_id"])
        marker = self._platform_marker(
            company_id,
            platform,
            str(normalized["lock_domain_id"]),
        )
        if self.paths.platform.exists():
            existing_marker = self._read_platform()
            if (
                existing_marker["company_id"] != company_id
                or existing_marker["platform"] != platform
                or existing_marker["lock_domain_id"]
                != normalized["lock_domain_id"]
            ):
                raise CompanyRegistryError(
                    "existing platform marker differs from genesis",
                )
        else:
            _create_immutable(
                self.paths.platform,
                canonical_company_json_bytes(marker),
                "platform marker",
            )

        _atomic_replace(
            self.paths.current,
            canonical_company_json_bytes(pointer.as_dict()),
        )
        return self.resolve_current(lock)

    def resolve_current(
        self,
        lock: CompanyLockWitness,
    ) -> ResolvedCompanyState:
        """Resolve and verify the exact active pointer and manifest."""

        _require_lock(lock)
        self._assert_layout()
        platform = self._read_platform()
        pointer = _pointer_from_value(
            _read_json(self.paths.current, "current pointer"),
        )
        if pointer.company_id != platform["company_id"]:
            raise CompanyRegistryError(
                "current pointer and platform marker company differ",
            )
        incarnation = self.paths.incarnation(pointer.incarnation_id)
        _assert_incarnation_layout(
            incarnation,
            label="active company incarnation",
        )
        manifest_value = _read_json(
            incarnation.manifest,
            "active company manifest",
        )
        try:
            manifest = validate_company_manifest(manifest_value)
        except CompanyContractError as exc:
            raise CompanyRegistryError(
                "active company manifest is invalid",
            ) from exc
        manifest_bytes = canonical_company_json_bytes(manifest)
        if (
            hashlib.sha256(manifest_bytes).hexdigest()
            != pointer.manifest_sha256
            or manifest["company_id"] != pointer.company_id
            or int(manifest["company_incarnation"])
            != pointer.company_incarnation
            or int(manifest["lock_domain_generation"])
            != pointer.lock_domain_generation
            or manifest["lock_domain_id"] != platform["lock_domain_id"]
        ):
            raise CompanyRegistryError(
                "current pointer, manifest, and platform binding differ",
            )
        return ResolvedCompanyState(
            slot=self.paths,
            pointer=pointer,
            incarnation=incarnation,
            manifest=manifest,
        )

    def prepare_next(
        self,
        lock: CompanyLockWitness,
        manifest: Mapping[str, Any],
    ) -> ResolvedCompanyState:
        """Prepare but do not activate one exact successor incarnation."""

        current = self.resolve_current(lock)
        try:
            candidate = validate_company_manifest(manifest)
        except CompanyContractError as exc:
            raise CompanyRegistryError("company manifest is invalid") from exc
        if (
            candidate["company_id"] != current.pointer.company_id
            or int(candidate["company_incarnation"])
            != current.pointer.company_incarnation + 1
            or int(candidate["lock_domain_generation"])
            <= current.pointer.lock_domain_generation
        ):
            raise CompanyRegistryError(
                "successor incarnation or lock generation is not monotonic",
            )
        pointer, incarnation, normalized = self._prepare_incarnation(
            lock,
            candidate,
        )
        pointer = _new_pointer(
            normalized,
            pointer.manifest_sha256,
            current.pointer.pointer_sha256,
        )
        return ResolvedCompanyState(
            slot=self.paths,
            pointer=pointer,
            incarnation=incarnation,
            manifest=normalized,
        )

    def compare_and_swap_current(
        self,
        lock: CompanyLockWitness,
        *,
        expected_pointer_sha256: str,
        successor: ResolvedCompanyState,
    ) -> ResolvedCompanyState:
        """Atomically activate one already-prepared verified successor."""

        current = self.resolve_current(lock)
        expected = _require_sha256(
            expected_pointer_sha256,
            "expected current pointer digest",
        )
        if current.pointer.pointer_sha256 != expected:
            raise CompanyPointerConflictError(
                "current pointer compare-and-swap failed",
            )
        if successor.slot != self.paths:
            raise CompanyRegistryError(
                "successor belongs to another company slot",
            )
        if _pointer_from_value(
            successor.pointer.as_dict(),
        ) != successor.pointer:
            raise CompanyRegistryError(
                "successor pointer self-verification failed",
            )
        canonical_incarnation = self.paths.incarnation(
            successor.pointer.incarnation_id,
        )
        if successor.incarnation != canonical_incarnation:
            raise CompanyRegistryError(
                "successor incarnation is not the canonical company-slot path",
            )
        _assert_incarnation_layout(
            canonical_incarnation,
            label="prepared successor incarnation",
        )
        manifest = _read_json(
            canonical_incarnation.manifest,
            "successor company manifest",
        )
        try:
            normalized_manifest = validate_company_manifest(manifest)
            supplied_manifest = validate_company_manifest(successor.manifest)
        except CompanyContractError as exc:
            raise CompanyRegistryError(
                "prepared successor manifest is invalid",
            ) from exc
        manifest_bytes = canonical_company_json_bytes(normalized_manifest)
        platform = self._read_platform()
        if (
            hashlib.sha256(manifest_bytes).hexdigest()
            != successor.pointer.manifest_sha256
            or canonical_company_json_bytes(supplied_manifest)
            != manifest_bytes
            or successor.pointer.previous_pointer_sha256 != expected
            or successor.pointer.company_id != current.pointer.company_id
            or successor.pointer.company_incarnation
            != current.pointer.company_incarnation + 1
            or successor.pointer.lock_domain_generation
            <= current.pointer.lock_domain_generation
            or normalized_manifest["company_id"]
            != successor.pointer.company_id
            or int(normalized_manifest["company_incarnation"])
            != successor.pointer.company_incarnation
            or int(normalized_manifest["lock_domain_generation"])
            != successor.pointer.lock_domain_generation
            or normalized_manifest["lock_domain_id"]
            != platform["lock_domain_id"]
        ):
            raise CompanyRegistryError(
                "prepared successor no longer matches its pointer",
            )
        _atomic_replace(
            self.paths.current,
            canonical_company_json_bytes(successor.pointer.as_dict()),
        )
        resolved = self.resolve_current(lock)
        if resolved.pointer != successor.pointer:
            raise CompanyRegistryError(
                "published current pointer readback differs",
            )
        return resolved
