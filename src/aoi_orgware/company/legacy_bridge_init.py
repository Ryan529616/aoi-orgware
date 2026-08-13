"""Fail-closed genesis for the deliberately read-only legacy company bridge.

This module owns the small ``aoi company init --mode legacy-bridge`` seam.  It
does not import legacy task state, start a service, dispatch work, or grant a
bridge any repository/job mutation authority.  Its only durable write is the
one ``CompanySupervisor.initialize`` genesis transaction.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import os
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
import stat
from typing import Any

from .contracts import (
    AUTHORITY_GRANT_V1,
    CARRIER_BINDING_V1,
    COMPANY_MANIFEST_V1,
    DEPARTMENT_IDENTITY_V1,
    DEPARTMENT_SNAPSHOT_V1,
    DISPATCH_REQUEST_V1,
    EXECUTION_NODE_V1,
    EXTERNAL_JOB_V1,
    MUTATION_INTENT_V1,
    canonical_company_json_bytes,
    company_contract_sha256,
    validate_company_manifest,
)
from .discovery import (
    BoundCompanyTarget,
    CompanyDiscoveryError,
    CompanyDiscoveryNotFoundError,
    resolve_bound_company,
)
from .identity import (
    CompanyBindingInput,
    CompanyIdentityError,
    _assert_native_existing_path_safe,
    company_binding_input,
    company_state_root,
    git_common_dir_identity,
    git_worktree_inventory,
    observed_remote_fingerprint,
)
from .legacy_bridge_publisher import validate_legacy_bridge_publication_envelope
from .service import service_status
from .supervisor import CompanySupervisor, CompanySupervisorError


_MODE = "legacy-bridge"
_SCHEMA = "aoi.company.legacy-bridge-init.v1"
_STATE_ROOT_SCHEMA = "aoi.company.legacy-bridge-state-root.v1"
_GRANT_TTL = timedelta(days=30)
_DEPARTMENTS = ("rtl", "dv", "pd")
_MAX_CONFIG_BYTES = 256 * 1024


class LegacyBridgeCompanyInitError(RuntimeError):
    """The bridge cannot create or prove one exact genesis company."""


@dataclass(frozen=True)
class LegacyBridgeCompanyInitResult:
    """Strict, secret-free public result for a created or exact reopened slot."""

    action: str
    company_id: str
    manifest_sha256: str
    state_root: str
    platform: str
    lock_domain: str
    chief_carrier_state: str
    departments: tuple[str, ...]
    authority_boundary: str

    def public_dict(self) -> dict[str, object]:
        return {
            "mode": _MODE,
            "action": self.action,
            "company_id": self.company_id,
            "manifest_sha256": self.manifest_sha256,
            "state_root": self.state_root,
            "platform": self.platform,
            "lock_domain": self.lock_domain,
            "chief_carrier": {"state": self.chief_carrier_state},
            "departments": [
                {"name": department, "lead_state": "parked"}
                for department in self.departments
            ],
            "authority_boundary": self.authority_boundary,
        }


def native_platform() -> str:
    """Return the only platform domain that an operational init may use."""

    return "windows" if os.name == "nt" else "posix"


def utc_second(now: datetime | None = None) -> str:
    """Canonical whole-second UTC bootstrap timestamp."""

    value = datetime.now(UTC) if now is None else now
    if value.tzinfo is None:
        raise LegacyBridgeCompanyInitError("bootstrap time must be timezone-aware")
    value = value.astimezone(UTC).replace(microsecond=0)
    return value.isoformat().replace("+00:00", "Z")


def grant_expiry(bootstrap_at: str) -> str:
    """Return the fixed genesis grant expiry; the CLI deliberately has no TTL."""

    try:
        instant = datetime.strptime(bootstrap_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=UTC,
        )
    except (TypeError, ValueError) as exc:
        raise LegacyBridgeCompanyInitError("bootstrap time must be canonical UTC seconds") from exc
    return (instant + _GRANT_TTL).isoformat().replace("+00:00", "Z")


def configuration_sha256(repo_root: Path) -> str:
    """Hash one identity-stable local configuration without crossing company bounds."""

    source = repo_root / "aoi.toml"
    try:
        before = source.lstat()
    except OSError as exc:
        raise LegacyBridgeCompanyInitError("legacy bridge configuration is unavailable") from exc
    if source.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise LegacyBridgeCompanyInitError("legacy bridge configuration is not a safe regular file")
    if not 0 < before.st_size <= _MAX_CONFIG_BYTES:
        raise LegacyBridgeCompanyInitError("legacy bridge configuration has an invalid size")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise LegacyBridgeCompanyInitError("legacy bridge configuration cannot be opened") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
        ):
            raise LegacyBridgeCompanyInitError("legacy bridge configuration changed while opening")
        raw = os.read(descriptor, _MAX_CONFIG_BYTES + 1)
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(raw) != finished.st_size
        or finished.st_dev != opened.st_dev
        or finished.st_ino != opened.st_ino
        or finished.st_size != opened.st_size
        or getattr(finished, "st_mtime_ns", None) != getattr(opened, "st_mtime_ns", None)
    ):
        raise LegacyBridgeCompanyInitError("legacy bridge configuration changed while reading")
    return hashlib.sha256(raw).hexdigest()


def legacy_bridge_company_id(common_dir_sha256: str) -> str:
    """Derive an allocation-free company ID from the exact Git common-dir digest."""

    if not isinstance(common_dir_sha256, str) or len(common_dir_sha256) != 64:
        raise LegacyBridgeCompanyInitError("Git common-dir digest is invalid")
    digest = company_contract_sha256(
        {"schema": _SCHEMA, "git_common_dir_sha256": common_dir_sha256},
    )
    return f"legacy-bridge-{digest}"


def state_root_identity_sha256(*, platform: str, state_root: PurePath | str) -> str:
    """Bind the selected external state root to exactly one native lock domain."""

    if platform not in {"windows", "posix"}:
        raise LegacyBridgeCompanyInitError("legacy bridge platform is invalid")
    return company_contract_sha256(
        {"schema": _STATE_ROOT_SCHEMA, "platform": platform, "state_root": str(state_root)},
    )


def _path_parts(value: PurePath | str, *, platform: str) -> tuple[str, ...]:
    try:
        path: PurePath
        if platform == "windows":
            path = PureWindowsPath(value)
            if not path.is_absolute() or str(path).startswith("\\\\"):
                raise ValueError
            return tuple(part.casefold() for part in path.parts)
        path = PurePosixPath(value)
        if not path.is_absolute() or str(path).startswith("//"):
            raise ValueError
        return path.parts
    except (TypeError, ValueError) as exc:
        raise LegacyBridgeCompanyInitError("state-root path is not a native local absolute path") from exc


def _overlap(first: tuple[str, ...], second: tuple[str, ...]) -> bool:
    return first[: len(second)] == second or second[: len(first)] == first


def validate_legacy_bridge_state_root(
    state_root: PurePath | str,
    *,
    platform: str,
    protected_paths: Sequence[PurePath | str],
) -> None:
    """Reject a state root that intersects the Git common-dir or any worktree."""

    root = _path_parts(state_root, platform=platform)
    if not protected_paths:
        raise LegacyBridgeCompanyInitError("Git worktree inventory is empty")
    for protected in protected_paths:
        if _overlap(root, _path_parts(protected, platform=platform)):
            raise LegacyBridgeCompanyInitError("company state root overlaps the Git repository domain")


def _assert_native_state_root_safe(state_root: Path, *, platform: str) -> None:
    """Reject existing native ancestors that could alias a bridge state root."""

    if platform != native_platform():
        return
    try:
        _assert_native_existing_path_safe(state_root, label="legacy bridge state root")
    except CompanyIdentityError as exc:
        raise LegacyBridgeCompanyInitError("legacy bridge state root cannot be safely inspected") from exc


def _manifest_from_binding(
    binding: CompanyBindingInput,
    *,
    state_root: PurePath | str,
    created_at: str,
) -> dict[str, object]:
    company_id = legacy_bridge_company_id(binding.common_dir_sha256)
    manifest = {
        "contract_type": COMPANY_MANIFEST_V1,
        "schema_version": 1,
        "company_id": company_id,
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "git_common_dir_sha256": binding.common_dir_sha256,
        "remote_fingerprint_sha256": binding.remote_fingerprint_sha256,
        "configuration_sha256": binding.config_sha256,
        "state_root_sha256": state_root_identity_sha256(
            platform=binding.platform,
            state_root=state_root,
        ),
        "lock_domain_id": binding.lock_domain,
        "created_at": created_at,
        "observation": {"state": "known", "reason": "observed"},
    }
    try:
        return validate_company_manifest(manifest)
    except ValueError as exc:
        raise LegacyBridgeCompanyInitError("legacy bridge manifest is invalid") from exc


def _expected_slot(
    repo_root: Path,
    *,
    environ: Mapping[str, str],
    bootstrap_at: str,
) -> tuple[dict[str, object], Path, str]:
    platform = native_platform()
    try:
        common = git_common_dir_identity(repo_root)
        remote = observed_remote_fingerprint(repo_root)
        binding = company_binding_input(
            common,
            remote,
            platform=platform,
            lock_domain=platform,
            config_sha256=configuration_sha256(repo_root),
        )
        company_id = legacy_bridge_company_id(binding.common_dir_sha256)
        pure_root = company_state_root(company_id, platform=platform, environ=environ)
        worktrees = git_worktree_inventory(repo_root)
        validate_legacy_bridge_state_root(
            pure_root,
            platform=platform,
            protected_paths=(binding.common_dir, *(item.path for item in worktrees)),
        )
    except (CompanyIdentityError, LegacyBridgeCompanyInitError, ValueError) as exc:
        raise LegacyBridgeCompanyInitError("legacy bridge repository binding is invalid") from exc
    _assert_native_state_root_safe(Path(str(pure_root)), platform=platform)
    manifest = _manifest_from_binding(
        binding,
        state_root=pure_root,
        created_at=bootstrap_at,
    )
    return manifest, Path(str(pure_root)), platform


def _same_slot(first: Path, second: Path, *, platform: str) -> bool:
    return _path_parts(first, platform=platform) == _path_parts(second, platform=platform)


def _assert_manifest_matches(
    target: BoundCompanyTarget,
    expected: Mapping[str, object],
    *,
    slot_root: Path,
    platform: str,
) -> dict[str, object]:
    try:
        actual = validate_company_manifest(target.manifest)
    except ValueError as exc:
        raise LegacyBridgeCompanyInitError("discovery returned an invalid company manifest") from exc
    fields = (
        "company_id",
        "company_incarnation",
        "lock_domain_generation",
        "git_common_dir_sha256",
        "remote_fingerprint_sha256",
        "configuration_sha256",
        "state_root_sha256",
        "lock_domain_id",
        "observation",
    )
    if (
        any(actual.get(field) != expected.get(field) for field in fields)
        or target.company_id != expected["company_id"]
        or not _same_slot(target.slot_root, slot_root, platform=platform)
        or target.manifest_sha256 != company_contract_sha256(actual)
        or actual["lock_domain_id"] != platform
        or actual["company_incarnation"] != 1
        or actual["lock_domain_generation"] != 1
    ):
        raise LegacyBridgeCompanyInitError("existing company differs from the legacy bridge binding")
    return actual


def _assert_genesis_shape(
    supervisor: CompanySupervisor,
    manifest: Mapping[str, object],
) -> None:
    """Add bridge-specific public assertions around Supervisor's genesis validator."""

    supervisor._validate_genesis()
    records = supervisor._state.records_after(0, limit=1)
    if len(records) != 1 or records[0].global_sequence != 1:
        raise LegacyBridgeCompanyInitError("legacy bridge must have exactly one genesis transaction")
    payloads = tuple(dict(event.event["payload"]) for event in records[0].events)

    def of_type(contract_type: str) -> tuple[dict[str, object], ...]:
        return tuple(item for item in payloads if item.get("contract_type") == contract_type)

    genesis_manifest = of_type(COMPANY_MANIFEST_V1)
    if len(genesis_manifest) != 1 or genesis_manifest[0] != dict(manifest):
        raise LegacyBridgeCompanyInitError("legacy bridge manifest is not the durable genesis manifest")
    grants = of_type(AUTHORITY_GRANT_V1)
    observed_grants: set[tuple[object, tuple[object, ...]]] = set()
    for grant in grants:
        permissions = grant.get("permissions")
        if not isinstance(permissions, (list, tuple)):
            raise LegacyBridgeCompanyInitError("legacy bridge genesis grant permissions are invalid")
        observed_grants.add((grant.get("actor_kind"), tuple(permissions)))
    if observed_grants != {("supervisor", ("company.mutate",)), ("chief", ("company.mutate",))}:
        raise LegacyBridgeCompanyInitError("legacy bridge genesis grants differ from the narrow authority boundary")
    expected_expiry = grant_expiry(str(manifest["created_at"]))
    if any(grant.get("expires_at") != expected_expiry for grant in grants):
        raise LegacyBridgeCompanyInitError("legacy bridge genesis grant expiry is not the fixed 30-day boundary")
    carriers = of_type(CARRIER_BINDING_V1)
    if len(carriers) != 1 or carriers[0].get("state") != "unknown" or carriers[0].get("provider") != "unknown":
        raise LegacyBridgeCompanyInitError("legacy bridge Chief carrier must remain unknown")
    identities = of_type(DEPARTMENT_IDENTITY_V1)
    snapshots = of_type(DEPARTMENT_SNAPSHOT_V1)
    departments = {
        str(item.get("name", "")).lower(): item.get("department_id")
        for item in identities
    }
    if (
        set(departments) != set(_DEPARTMENTS)
        or any(item.get("status") != "parked" for item in identities)
        or {item.get("department_id") for item in snapshots} != set(departments.values())
    ):
        raise LegacyBridgeCompanyInitError("legacy bridge departments are incomplete")
    for forbidden in (EXECUTION_NODE_V1, DISPATCH_REQUEST_V1, EXTERNAL_JOB_V1, MUTATION_INTENT_V1):
        if of_type(forbidden):
            raise LegacyBridgeCompanyInitError("legacy bridge genesis created execution or mutation facts")


def _assert_current_state_is_representable(
    supervisor: CompanySupervisor,
    manifest: Mapping[str, object],
) -> None:
    """Permit only validated read-only bridge publications after genesis.

    The init result has no schema for a later Chief, carrier, department, or
    execution transition.  Returning its genesis defaults after one of those
    facts would therefore be false.  Read only the complete durable suffix and
    fail closed unless every later transaction is an exact publisher-shaped
    observation/coverage publication bound to this company.
    """

    expected_key = tuple(
        manifest[field]
        for field in ("company_id", "company_incarnation", "lock_domain_generation")
    )
    cursor = 1
    try:
        head = supervisor.heads().global_head.global_sequence
        while cursor < head:
            records = supervisor._state.records_after(cursor, limit=4096)
            if not records or records[0].global_sequence != cursor + 1:
                raise LegacyBridgeCompanyInitError("current legacy bridge ledger suffix is incomplete")
            for record in records:
                if record.global_sequence != cursor + 1 or record.global_sequence > head:
                    raise LegacyBridgeCompanyInitError("current legacy bridge ledger sequence is invalid")
                envelope = validate_legacy_bridge_publication_envelope(supervisor, record)
                coverage = envelope.coverage
                observed_key = tuple(
                    coverage[field]
                    for field in ("company_id", "company_incarnation", "lock_domain_generation")
                )
                if observed_key != expected_key:
                    raise LegacyBridgeCompanyInitError("legacy bridge publication binding differs")
                cursor = record.global_sequence
        if cursor != head:
            raise LegacyBridgeCompanyInitError("current legacy bridge ledger head is not representable")
    except (MemoryError, SystemExit, KeyboardInterrupt, LegacyBridgeCompanyInitError):
        raise
    except Exception as exc:
        raise LegacyBridgeCompanyInitError("current legacy bridge state cannot be verified") from exc


def _existing_result(
    target: BoundCompanyTarget,
    expected: Mapping[str, object],
    *,
    slot_root: Path,
    platform: str,
) -> LegacyBridgeCompanyInitResult:
    manifest = _assert_manifest_matches(target, expected, slot_root=slot_root, platform=platform)
    if target.service_state == "running":
        status = service_status(slot_root)
        descriptor = status.get("descriptor") if isinstance(status, Mapping) else None
        company = descriptor.get("company") if isinstance(descriptor, Mapping) else None
        if (
            status.get("state") != "running"
            or not isinstance(company, Mapping)
            or company.get("company_id") != manifest["company_id"]
            or company.get("manifest_sha256") != target.manifest_sha256
        ):
            raise LegacyBridgeCompanyInitError("resident Supervisor identity cannot be verified")
        raise LegacyBridgeCompanyInitError(
            "running legacy bridge cannot be reopened without a verified stopped ledger",
        )
    elif target.service_state == "stopped":
        try:
            supervisor = CompanySupervisor.open(slot_root)
            try:
                _assert_genesis_shape(supervisor, manifest)
                _assert_current_state_is_representable(supervisor, manifest)
            finally:
                supervisor.close()
        except CompanySupervisorError as exc:
            raise LegacyBridgeCompanyInitError("existing company genesis cannot be verified") from exc
    else:
        raise LegacyBridgeCompanyInitError("existing company service state is unsupported")
    return LegacyBridgeCompanyInitResult(
        action="existing_exact",
        company_id=str(manifest["company_id"]),
        manifest_sha256=target.manifest_sha256,
        state_root=str(slot_root),
        platform=platform,
        lock_domain=platform,
        chief_carrier_state="unknown",
        departments=_DEPARTMENTS,
        authority_boundary="genesis grants are limited to supervisor/chief company.mutate; bridge init dispatched no work",
    )


def initialize_legacy_bridge_company(
    repo_root: Path,
    *,
    environ: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> LegacyBridgeCompanyInitResult:
    """Create or exactly reopen one repo-external read-only bridge company."""

    if not isinstance(repo_root, Path):
        raise LegacyBridgeCompanyInitError("legacy bridge init requires a repository Path")
    root = repo_root.resolve()
    environment = os.environ if environ is None else environ
    bootstrap_at = utc_second(now)
    manifest, slot_root, platform = _expected_slot(root, environ=environment, bootstrap_at=bootstrap_at)
    try:
        target = resolve_bound_company(root, environ=environment)
    except CompanyDiscoveryNotFoundError:
        target = None
    except CompanyDiscoveryError as exc:
        raise LegacyBridgeCompanyInitError("existing company discovery is not safe to reconcile") from exc
    if target is not None:
        return _existing_result(target, manifest, slot_root=slot_root, platform=platform)
    expires_at = grant_expiry(bootstrap_at)
    try:
        _assert_native_state_root_safe(slot_root, platform=platform)
        supervisor = CompanySupervisor.initialize(
            slot_root,
            manifest,
            bootstrap_at=bootstrap_at,
            grant_expires_at=expires_at,
            platform=platform,
            known_carrier=None,
        )
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception:
        try:
            winner = resolve_bound_company(root, environ=environment)
            return _existing_result(winner, manifest, slot_root=slot_root, platform=platform)
        except (MemoryError, SystemExit, KeyboardInterrupt):
            raise
        except Exception as reconcile_error:
            raise LegacyBridgeCompanyInitError(
                "legacy bridge initialization failed without an exact concurrent winner",
            ) from reconcile_error
    try:
        _assert_genesis_shape(supervisor, manifest)
    finally:
        supervisor.close()
    return LegacyBridgeCompanyInitResult(
        action="created",
        company_id=str(manifest["company_id"]),
        manifest_sha256=company_contract_sha256(manifest),
        state_root=str(slot_root),
        platform=platform,
        lock_domain=platform,
        chief_carrier_state="unknown",
        departments=_DEPARTMENTS,
        authority_boundary="genesis grants are limited to supervisor/chief company.mutate; bridge init dispatched no work",
    )
