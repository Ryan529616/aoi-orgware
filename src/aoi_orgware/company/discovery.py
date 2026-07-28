"""Fail-closed repository-to-company discovery for public local clients.

Discovery intentionally returns a *bound target*, rather than a mutable state
owner.  The caller must still pass the returned manifest digest to a resident
Supervisor before doing anything that could write company state.  This keeps a
clone, a moved worktree, and a stale runtime descriptor from silently becoming
another company.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .contracts import canonical_company_json_bytes, validate_company_manifest
from .identity import (
    CompanyIdentityError,
    company_state_root,
    git_common_dir_identity,
    observed_remote_fingerprint,
)
from .process_lock import (
    CompanyProcessLock,
    CompanyProcessLockBusyError,
    CompanyProcessLockError,
)
from .registry import CompanyRegistry, CompanyRegistryError
from .service import service_status


_COMPANY_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,127}\Z")
_MAX_CANDIDATES = 4096
_MAX_RESPONSE_BYTES = 256 * 1024


class CompanyDiscoveryError(RuntimeError):
    """A public client cannot safely select one company slot."""


class CompanyDiscoveryNotFoundError(CompanyDiscoveryError):
    """No company slot is exactly bound to the requested repository."""


class CompanyDiscoveryAmbiguousError(CompanyDiscoveryError):
    """More than one company slot is exactly bound to the repository."""


class CompanyDiscoveryBindingMismatchError(CompanyDiscoveryError):
    """A related company exists but its repository binding is not exact."""


class CompanyDiscoveryUnknownWriterError(CompanyDiscoveryError):
    """A busy slot has no independently verified resident reader."""


class CompanyDiscoveryUnsafePathError(CompanyDiscoveryError):
    """The state inventory contains a link, replacement, or invalid entry."""


class CompanyDiscoveryOverboundError(CompanyDiscoveryError):
    """The state inventory exceeded its explicit bounded scan limit."""


@dataclass(frozen=True)
class BoundCompanyTarget:
    """One verified, repo-bound company target suitable for a public CLI.

    ``configuration_digest_observation`` deliberately says what discovery did
    *not* establish.  The manifest digest is authoritative, but this read-only
    repository observation has no configuration source to compare with it.
    """

    slot_root: Path
    company_id: str
    manifest_sha256: str
    manifest: dict[str, Any]
    service_state: str
    dashboard_url: str | None
    warnings: tuple[str, ...]
    configuration_digest_observation: str = "manifest_only_not_live_observed"


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Request | None:
        del req, fp, code, msg, headers, newurl
        return None


def _native_platform() -> str:
    return "windows" if os.name == "nt" else "posix"


def _link_like(metadata: os.stat_result) -> bool:
    """Treat Windows junctions like symlinks instead of resolving through them."""

    if stat.S_ISLNK(metadata.st_mode):
        return True
    if os.name != "nt":
        return False
    attributes = getattr(metadata, "st_file_attributes", None)
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", None)
    if not isinstance(attributes, int) or not isinstance(marker, int) or marker == 0:
        raise CompanyDiscoveryUnsafePathError("Windows reparse-point inspection is unavailable")
    return bool(attributes & marker)


def _same_directory_identity(
    first: os.stat_result,
    second: os.stat_result,
) -> bool:
    return (
        first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
        and stat.S_ISDIR(second.st_mode)
    )


def _same_normalized_path(first: Path, second: Path) -> bool:
    return os.path.normcase(os.path.abspath(os.fspath(first))) == os.path.normcase(
        os.path.abspath(os.fspath(second)),
    )


def _safe_existing_directory(path: Path, *, label: str) -> Path:
    """Reject links before resolving them, so a scan cannot cross a boundary."""

    if not path.is_absolute() or ".." in path.parts:
        raise CompanyDiscoveryUnsafePathError(f"{label} is not an absolute stable path")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise CompanyDiscoveryUnsafePathError(f"cannot inspect {label}") from exc
    if _link_like(metadata):
        raise CompanyDiscoveryUnsafePathError(f"{label} may not be a symlink")
    if not stat.S_ISDIR(metadata.st_mode):
        raise CompanyDiscoveryUnsafePathError(f"{label} is not a directory")
    observed = [(path, metadata)]
    # ``resolve`` follows no link after every existing component has been
    # checked.  Check parents as well because the environment is untrusted.
    for parent in path.parents:
        try:
            parent_metadata = parent.lstat()
        except OSError as exc:
            raise CompanyDiscoveryUnsafePathError(
                f"cannot inspect {label} parent",
            ) from exc
        if _link_like(parent_metadata):
            raise CompanyDiscoveryUnsafePathError(
                f"{label} may not traverse a symlink",
            )
        if not stat.S_ISDIR(parent_metadata.st_mode):
            raise CompanyDiscoveryUnsafePathError(
                f"{label} parent is not a directory",
            )
        observed.append((parent, parent_metadata))
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CompanyDiscoveryUnsafePathError(f"cannot resolve {label}") from exc
    if not _same_normalized_path(path, resolved):
        raise CompanyDiscoveryUnsafePathError(
            f"{label} resolved outside its canonical path",
        )
    # Narrow the check/resolve race for cooperative components by requiring
    # every original component to retain the same directory identity.  This
    # remains a userspace check, not a hostile same-UID isolation claim.
    for component, before in observed:
        try:
            after = component.lstat()
        except OSError as exc:
            raise CompanyDiscoveryUnsafePathError(
                f"{label} changed while it was inspected",
            ) from exc
        if _link_like(after) or not _same_directory_identity(before, after):
            raise CompanyDiscoveryUnsafePathError(
                f"{label} changed while it was inspected",
            )
    return resolved


def _validated_loopback_dashboard_url(value: object) -> str:
    if not isinstance(value, str):
        raise CompanyDiscoveryUnknownWriterError("resident Dashboard URL is unavailable")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise CompanyDiscoveryUnknownWriterError("resident Dashboard URL is invalid") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or port is None
        or not 1 <= port <= 65535
        or parsed.path != "/"
        or parsed.query
        or parsed.fragment
        or value != f"http://127.0.0.1:{port}/"
    ):
        raise CompanyDiscoveryUnknownWriterError(
            "resident Dashboard URL is not canonical literal loopback",
        )
    return value


def _resident_manifest(status: Mapping[str, Any], *, slot: Path) -> tuple[dict[str, Any], str, str]:
    """Join a busy lock only through descriptor + Dashboard agreement."""

    service_state = status.get("state")
    if service_state not in {"running", "stopping"}:
        raise CompanyDiscoveryUnknownWriterError("busy company slot has no verified resident service")
    descriptor = status.get("descriptor")
    if not isinstance(descriptor, Mapping):
        raise CompanyDiscoveryUnknownWriterError("resident service descriptor is unavailable")
    company = descriptor.get("company")
    if not isinstance(company, Mapping):
        raise CompanyDiscoveryUnknownWriterError("resident service identity is unavailable")
    descriptor_digest = company.get("manifest_sha256")
    if not isinstance(descriptor_digest, str):
        raise CompanyDiscoveryUnknownWriterError("resident service manifest digest is unavailable")
    dashboard_url = _validated_loopback_dashboard_url(descriptor.get("dashboard_url"))
    request = Request(dashboard_url + "api/v1/company", method="GET")
    try:
        with build_opener(_NoRedirectHandler()).open(request, timeout=1.0) as response:
            if int(response.status) != 200:
                raise CompanyDiscoveryUnknownWriterError("resident Dashboard rejected company read")
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
    except CompanyDiscoveryError:
        raise
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise CompanyDiscoveryUnknownWriterError("resident Dashboard company read is unavailable") from exc
    if not raw or len(raw) > _MAX_RESPONSE_BYTES:
        raise CompanyDiscoveryUnknownWriterError("resident Dashboard company response exceeds bound")
    try:
        envelope = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompanyDiscoveryUnknownWriterError("resident Dashboard company response is invalid") from exc
    required = {
        "schema_version", "company_id", "cursor", "generated_at", "completeness", "warnings", "data",
    }
    if not isinstance(envelope, dict) or set(envelope) != required or not isinstance(envelope["data"], Mapping):
        raise CompanyDiscoveryUnknownWriterError("resident Dashboard company envelope is invalid")
    manifest_value = envelope["data"].get("manifest")
    try:
        manifest = validate_company_manifest(manifest_value)
    except Exception as exc:
        raise CompanyDiscoveryUnknownWriterError("resident Dashboard company manifest is invalid") from exc
    manifest_sha256 = hashlib.sha256(canonical_company_json_bytes(manifest)).hexdigest()
    if (
        manifest_sha256 != descriptor_digest
        or company.get("company_id") != manifest["company_id"]
        or envelope["company_id"] != manifest["company_id"]
    ):
        raise CompanyDiscoveryUnknownWriterError("resident Dashboard and descriptor company binding differ")
    return manifest, manifest_sha256, dashboard_url


def _stopped_manifest(slot: Path) -> tuple[dict[str, Any], str]:
    lock = CompanyProcessLock(
        slot / "company.lock",
        timeout_seconds=0.0,
        create_if_missing=False,
    )
    try:
        lock.acquire()
        resolved = CompanyRegistry(slot).resolve_current(lock)
        manifest = validate_company_manifest(resolved.manifest)
        manifest_sha256 = hashlib.sha256(canonical_company_json_bytes(manifest)).hexdigest()
        if manifest_sha256 != resolved.pointer.manifest_sha256:
            raise CompanyDiscoveryBindingMismatchError("company registry manifest digest differs")
        return manifest, manifest_sha256
    except CompanyProcessLockBusyError:
        raise
    except (CompanyProcessLockError, CompanyRegistryError, OSError, ValueError) as exc:
        raise CompanyDiscoveryBindingMismatchError("company slot cannot be read as a verified registry") from exc
    finally:
        lock.close()


def _candidate_manifest(slot: Path) -> tuple[dict[str, Any], str, str, str | None]:
    """Resolve one candidate without granting any write authority."""

    try:
        manifest, digest = _stopped_manifest(slot)
        return manifest, digest, "stopped", None
    except CompanyProcessLockBusyError:
        status = service_status(slot, timeout_seconds=1.0)
        manifest, digest, dashboard_url = _resident_manifest(status, slot=slot)
        return manifest, digest, str(status["state"]), dashboard_url


def _candidate_slots(root: Path, *, company_id: str | None, maximum: int) -> tuple[Path, ...]:
    try:
        entries = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise CompanyDiscoveryUnsafePathError("cannot inventory company state root") from exc
    if len(entries) > maximum:
        raise CompanyDiscoveryOverboundError("company state inventory exceeds candidate bound")
    result: list[Path] = []
    for entry in entries:
        try:
            metadata = entry.lstat()
        except OSError as exc:
            raise CompanyDiscoveryUnsafePathError("cannot inspect company state entry") from exc
        if _link_like(metadata):
            raise CompanyDiscoveryUnsafePathError("company state inventory contains a symlink")
        if not stat.S_ISDIR(metadata.st_mode):
            continue
        if _COMPANY_ID_RE.fullmatch(entry.name) is None:
            raise CompanyDiscoveryUnsafePathError("company state inventory has an invalid slot name")
        if company_id is None or entry.name == company_id:
            resolved = _safe_existing_directory(entry, label="company slot")
            if not _same_normalized_path(resolved.parent, root):
                raise CompanyDiscoveryUnsafePathError(
                    "company slot resolved outside the state inventory",
                )
            result.append(resolved)
    return tuple(result)


def resolve_bound_company(
    repo_root: str | os.PathLike[str],
    company_id: str | None = None,
    environ: Mapping[str, str] | None = None,
    max_candidates: int = 256,
) -> BoundCompanyTarget:
    """Find exactly one current company whose immutable binding matches ``repo_root``.

    ``configuration_sha256`` remains manifest-only because this function has no
    authoritative configuration source to hash.  Callers receive that explicit
    limitation instead of a made-up equality result.
    """

    if company_id is not None and (
        not isinstance(company_id, str) or _COMPANY_ID_RE.fullmatch(company_id) is None
    ):
        raise CompanyDiscoveryError("company ID filter is invalid")
    if (
        not isinstance(max_candidates, int)
        or isinstance(max_candidates, bool)
        or not 1 <= max_candidates <= _MAX_CANDIDATES
    ):
        raise CompanyDiscoveryOverboundError("company candidate bound is invalid")
    effective_environ: Mapping[str, str] = os.environ if environ is None else environ
    if not isinstance(effective_environ, Mapping):
        raise CompanyDiscoveryError("discovery environment is invalid")
    try:
        common = git_common_dir_identity(repo_root)
        remote = observed_remote_fingerprint(repo_root)
        inventory = Path(
            str(
                company_state_root(
                    "aoi-discovery",
                    platform=_native_platform(),
                    environ=effective_environ,
                ).parent,
            ),
        )
    except CompanyIdentityError as exc:
        raise CompanyDiscoveryError("repository identity cannot be observed") from exc
    try:
        inventory = _safe_existing_directory(inventory, label="company state root")
    except FileNotFoundError:
        raise CompanyDiscoveryNotFoundError("company state root does not exist") from None

    exact: list[BoundCompanyTarget] = []
    related_mismatches: list[str] = []
    for slot in _candidate_slots(inventory, company_id=company_id, maximum=max_candidates):
        manifest, digest, service_state, dashboard_url = _candidate_manifest(slot)
        if slot.name != manifest["company_id"]:
            raise CompanyDiscoveryBindingMismatchError(
                "company slot name and manifest company ID differ",
            )
        if company_id is not None and manifest["company_id"] != company_id:
            raise CompanyDiscoveryBindingMismatchError("company slot name and manifest company ID differ")
        same_common = manifest["git_common_dir_sha256"] == common["common_dir_sha256"]
        same_remote = manifest["remote_fingerprint_sha256"] == remote["sha256"]
        if same_common and same_remote:
            exact.append(
                BoundCompanyTarget(
                    slot_root=slot,
                    company_id=str(manifest["company_id"]),
                    manifest_sha256=digest,
                    manifest=manifest,
                    service_state=service_state,
                    dashboard_url=dashboard_url,
                    warnings=("configuration_digest_manifest_only_not_live_observed",),
                ),
            )
        elif company_id is not None or same_common or same_remote:
            related_mismatches.append(str(slot))

    if len(exact) > 1:
        raise CompanyDiscoveryAmbiguousError("multiple exactly bound company slots were discovered")
    if exact:
        return exact[0]
    if related_mismatches:
        raise CompanyDiscoveryBindingMismatchError("related company binding differs; explicit rebind is required")
    raise CompanyDiscoveryNotFoundError("no company is bound to this repository")


__all__ = [
    "BoundCompanyTarget",
    "CompanyDiscoveryAmbiguousError",
    "CompanyDiscoveryBindingMismatchError",
    "CompanyDiscoveryError",
    "CompanyDiscoveryNotFoundError",
    "CompanyDiscoveryOverboundError",
    "CompanyDiscoveryUnknownWriterError",
    "CompanyDiscoveryUnsafePathError",
    "resolve_bound_company",
]
