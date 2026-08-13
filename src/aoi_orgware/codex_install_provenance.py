"""Read-only provenance checks for a promoted AOI wheel installation.

This is deliberately an observer: it does not create receipts on disk, repair
launchers, or import a project configuration.  A caller that wants to persist
the returned receipt owns that mutation separately.
"""
from __future__ import annotations

from collections.abc import Mapping
import base64
import csv
import hashlib
import importlib
from importlib import metadata
import io
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat
import sys
from typing import Any, NoReturn
from urllib.parse import unquote, urlsplit
import zipfile

from . import release_runtime
from .harnesslib import HarnessError, canonicalize_no_link_traversal
from .semantic_events import SemanticEventError, canonical_json_bytes, canonical_sha256


CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION = 3
CODEX_INSTALL_PROVENANCE_RECEIPT = ".aoi/codex-install-provenance-v1.json"
CODEX_CLIENT_CONTRACT_VERSION = 1
CODEX_CLIENT_ROLE = "client_adapter_only"
CODEX_CLIENT_SKILL_RESOURCE = "resources/codex/SKILL.md"
CODEX_HOOK_RUNTIME_CONTRACT_VERSION = 1
CODEX_HOOK_RUNTIME_KIND = "python_isolated_module"
CODEX_HOOK_RUNTIME_MODULE = "aoi_orgware.codex_hook"
CODEX_HOOK_RUNTIME_ARGV_PREFIX = ("-I", "-B", "-m", CODEX_HOOK_RUNTIME_MODULE)
# This deliberately says what it is: post-import cooperative drift detection,
# not a sandbox or a defence against the local account that owns the venv.
CODEX_HOOK_RUNTIME_TRUST_CLASS = "cooperative_host_python_tcb_post_import_drift_detection"
_MAX_FILE_BYTES = 4 * 1024 * 1024
# Python runtimes are routinely larger than the receipt/package-file bound
# (for example the WSL CPython executable is about 8 MiB).  Keep this narrow:
# only the already venv-bound interpreter identity may use it.
_MAX_RUNTIME_PYTHON_BYTES = 128 * 1024 * 1024
_MAX_PACKAGE_RUNTIME_FILES = 1024
_MAX_PACKAGE_RUNTIME_MANIFEST_BYTES = 64 * 1024
_MAX_LOCAL_WHEEL_MEMBERS = 2048
_MAX_LOCAL_WHEEL_BYTES = 256 * 1024 * 1024
_LOCAL_WHEEL_COMPRESSION = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})
_SHA256_HEX = frozenset("0123456789abcdef")
_RECEIPT_FIELDS = {
    "schema_version", "promotion_bundle_sha256", "distribution_name",
    "package_version", "installed_metadata_sha256", "metadata_path",
    "package_root", "console_entry_point", "codex_hook_entry_point",
    "codex_hook_generated_script", "package_runtime_manifest",
    "hook_protocol_version", "provenance_receipt_sha256",
}
_RECEIPT_FIELDS_WITH_INSTALL_MAPPING = _RECEIPT_FIELDS | {
    "promotion_wheel_artifact", "installed_distribution_identity",
    "installed_mapping_strength", "installed_mapping_evidence",
}
_LOCAL_RECEIPT_FIELDS = {
    "schema_version", "install_proof", "distribution_name", "package_version",
    "installed_metadata_sha256", "metadata_path", "package_root",
    "console_entry_point", "codex_hook_entry_point", "codex_bridge_entry_point",
    "codex_hook_generated_script", "codex_bridge_generated_script",
    "package_runtime_manifest",
    "hook_protocol_version", "install_wheel_artifact",
    "installed_distribution_identity", "installed_mapping_strength",
    "installed_mapping_evidence", "installed_record",
    "provenance_receipt_sha256",
}
_ENTRY_RECEIPT_FIELDS = {"name", "target", "path", "record_sha256"}
_SCRIPT_RECEIPT_FIELDS = {"path", "record_sha256"}
_PACKAGE_MANIFEST_RECEIPT_FIELDS = {"count", "sha256"}
_WHEEL_ARTIFACT_FIELDS = {"name", "sha256"}
_DISTRIBUTION_IDENTITY_FIELDS = {"name", "version", "metadata_sha256"}
_MAPPING_EVIDENCE_FIELDS = {"installer", "direct_url"}
_MAPPING_FILE_FIELDS = {"path", "record_sha256"}
_DIRECT_URL_EVIDENCE_FIELDS = {"path", "record_sha256", "archive_sha256"}
_LOCAL_INSTALL_PROOF_FIELDS = {
    "kind", "proof_scope", "bundle_path", "bundle_sha256",
    "artifact_store_root", "source_commit_oid", "source_tree_oid",
    "source_manifest_sha256", "rehearsal_report_sha256", "inventory_sha256",
}
_LOCAL_WHEEL_ARTIFACT_FIELDS = {"path", "name", "size_bytes", "sha256"}
_LOCAL_DIRECT_URL_EVIDENCE_FIELDS = {
    "path", "record_sha256", "archive_sha256", "archive_path",
}
_INSTALLED_RECORD_FIELDS = {"path", "sha256"}
_CLIENT_SKILL_BINDING_FIELDS = {
    "provider", "client_contract_version", "role", "package_version",
    "package_resource", "installed_skill",
}
_CLIENT_SKILL_PACKAGE_RESOURCE_FIELDS = {
    "relative_path", "path", "record_sha256",
}
_CLIENT_SKILL_INSTALLED_FIELDS = {"path", "expected_sha256"}
_HOOK_RUNTIME_BINDING_FIELDS = {
    "contract_version", "kind", "python_invocation", "python_resolved_path",
    "python_resolved_sha256", "venv_prefix", "python_cache_tag", "module",
    "module_path", "module_record_sha256", "argv_prefix", "trust_class",
}
_V3_BINDING_FIELDS = {
    "install_provenance_schema_version",
    "install_provenance_receipt_sha256",
    "codex_client_skill",
    "codex_hook_runtime",
}
_INSTALLED_MAPPING_STRENGTHS = frozenset({
    "direct_url_archive_sha256", "record_package_and_installer",
    "record_package_only",
})
_AOI_CONSOLE_TARGET = "aoi_orgware.cli:main"
_AOI_HOOK_TARGET = "aoi_orgware.codex_hook:main"
_AOI_BRIDGE_TARGET = "aoi_orgware.codex_transport_cli:main"
_PROMOTED_INSTALL_PROVENANCE_SCHEMA_VERSION = 1
_LOCAL_INSTALL_PROVENANCE_SCHEMA_VERSION = 2


class CodexInstallProvenanceError(ValueError):
    """The running AOI installation cannot prove the promoted provenance."""


def _fail(message: str, exc: Exception | None = None) -> NoReturn:
    if exc is None:
        raise CodexInstallProvenanceError(message)
    raise CodexInstallProvenanceError(f"{message}: {exc}") from exc


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or set(value) - _SHA256_HEX:
        _fail(f"{label} must be a lowercase SHA-256")
    return value


def _absolute_receipt_path(value: object, label: str) -> str:
    """Accept absolute POSIX or drive-qualified Windows receipt paths only."""
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        _fail(f"{label} is not an absolute path")
    is_windows = len(value) >= 3 and value[0].isalpha() and value[1] == ":" and value[2] in {"/", "\\"}
    if not value.startswith("/") and not is_windows:
        _fail(f"{label} is not an absolute path")
    return value


def _receipt_join(root: str, relative: str) -> str:
    """Join one recorded absolute path without depending on the host OS."""

    is_windows = (
        len(root) >= 3
        and root[0].isalpha()
        and root[1] == ":"
        and root[2] in {"/", "\\"}
    )
    if is_windows:
        return str(PureWindowsPath(root).joinpath(*relative.split("/")))
    return str(PurePosixPath(root).joinpath(*relative.split("/")))


def _git_oid(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) not in {40, 64} or set(value) - _SHA256_HEX:
        _fail(f"{label} is not a lowercase Git object ID")
    return value


def _canonical_existing(path: str | os.PathLike[str], label: str, *, directory: bool = False) -> Path:
    raw = Path(path)
    if not raw.is_absolute():
        _fail(f"{label} must be an absolute path")
    try:
        checked = canonicalize_no_link_traversal(raw, label)
        info = checked.lstat()
    except (HarnessError, OSError) as exc:
        _fail(f"cannot inspect {label}", exc)
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            _fail(f"{label} is not a directory")
    elif not stat.S_ISREG(info.st_mode):
        _fail(f"{label} is not a regular file")
    if checked != raw:
        _fail(f"{label} is not canonical")
    return checked


def _require_executable(path: Path, label: str) -> None:
    """Require a launcher to be executable by the current POSIX identity."""

    if os.name == "nt":
        return
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        _fail(f"cannot inspect {label} permissions", exc)
    any_execute_bit = mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) != 0
    try:
        if os.access in os.supports_effective_ids:
            effective_access = os.access(path, os.X_OK, effective_ids=True)
        else:
            effective_access = os.access(path, os.X_OK)
    except OSError as exc:
        _fail(f"cannot inspect {label} effective execute access", exc)
    if not any_execute_bit or not effective_access:
        _fail(f"{label} is not executable")


def _stable_read(path: Path, label: str, *, max_bytes: int = _MAX_FILE_BYTES) -> bytes:
    try:
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or path.is_symlink():
            _fail(f"{label} is not a regular non-link file")
        if before.st_size > max_bytes:
            _fail(f"{label} exceeds byte bound")
        raw = path.read_bytes()
        after = path.stat()
    except OSError as exc:
        _fail(f"cannot read {label}", exc)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
    ) or len(raw) != before.st_size:
        _fail(f"{label} changed while being read")
    return raw


def _under(path: Path, root: Path, label: str) -> None:
    try:
        path.relative_to(root)
    except ValueError:
        _fail(f"{label} lies outside the active Python prefix")


def _normal_name(name: str) -> str:
    return "".join("-" if char in "_.-" else char.lower() for char in name).replace("--", "-")


def _load_bundle(path: str | os.PathLike[str], expected: str) -> dict[str, Any]:
    bundle_path = _canonical_existing(path, "promotion bundle")
    raw = _stable_read(bundle_path, "promotion bundle")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail("promotion bundle is not UTF-8 JSON", exc)
    try:
        return release_runtime.validate_promotion_bundle(parsed, _digest(expected, "expected promotion bundle SHA-256"))
    except (release_runtime.ReleaseRuntimeError, TypeError, ValueError) as exc:
        _fail("promotion bundle is invalid", exc)


def _record(dist_info: Path, site_root: Path) -> dict[Path, tuple[str, int]]:
    record_path = _canonical_existing(dist_info / "RECORD", "wheel RECORD")
    rows: dict[Path, tuple[str, int]] = {}
    try:
        entries = csv.reader(_stable_read(record_path, "wheel RECORD").decode("utf-8").splitlines())
        for row in entries:
            if len(row) != 3 or not row[0] or row[0] in {".", ".."}:
                _fail("wheel RECORD row is invalid")
            rel = PurePosixPath(row[0])
            if rel.is_absolute() or "" in rel.parts:
                _fail("wheel RECORD path is invalid")
            # pip records generated scripts relative to site-packages, normally
            # with leading ``..`` components (for example ``../../../Scripts``
            # on Windows).  Permit only that prefix form; an embedded parent
            # component could hide a linked traversal.
            parent_count = 0
            for part in rel.parts:
                if part == "..":
                    parent_count += 1
                else:
                    break
            if any(part in {".", ".."} for part in rel.parts[parent_count:]):
                _fail("wheel RECORD path is invalid")
            candidate = site_root
            for _ in range(parent_count):
                candidate = candidate.parent
            candidate = candidate.joinpath(*rel.parts[parent_count:])
            try:
                candidate = canonicalize_no_link_traversal(candidate, "wheel RECORD entry")
            except HarnessError as exc:
                _fail("wheel RECORD path is invalid", exc)
            if candidate in rows:
                _fail("wheel RECORD has duplicate canonical paths")
            digest, size = row[1], row[2]
            if candidate == record_path:
                if digest or size:
                    _fail("wheel RECORD self-row must omit digest and size")
                continue
            # pip may append imported bytecode caches to RECORD after install.
            # Admit only a real, canonical PEP 3147/488 cache file; a broader
            # ``__pycache__`` exemption would hide arbitrary package payloads.
            if not digest and not size and _is_cache_path(candidate.relative_to(site_root)):
                _canonical_existing(candidate, "wheel RECORD bytecode cache")
                continue
            if not digest.startswith("sha256=") or not size.isdecimal():
                _fail("wheel RECORD row lacks a verifiable SHA-256 and size")
            rows[candidate] = (digest[7:], int(size))
    except UnicodeDecodeError as exc:
        _fail("wheel RECORD is not UTF-8", exc)
    return rows


def _verify_recorded(path: Path, record: Mapping[Path, tuple[str, int]], label: str) -> str:
    entry = record.get(path)
    if entry is None:
        _fail(f"{label} is absent from wheel RECORD")
    expected_b64, expected_size = entry
    raw = _stable_read(path, label)
    actual_b64 = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    if len(raw) != expected_size or actual_b64 != expected_b64:
        _fail(f"{label} bytes differ from wheel RECORD")
    return _sha256(raw)


def _is_cache_path(relative: Path) -> bool:
    parts = relative.parts
    if (
        len(parts) < 2
        or parts[-2] != "__pycache__"
        or "__pycache__" in parts[:-2]
    ):
        return False
    cache_tag = sys.implementation.cache_tag
    if not isinstance(cache_tag, str) or not cache_tag:
        return False
    leaf = parts[-1]
    normal_suffix = f".{cache_tag}.pyc"
    if leaf.endswith(normal_suffix):
        return len(leaf) > len(normal_suffix)
    if not leaf.endswith(".pyc"):
        return False
    source_name, marker, optimization = leaf[:-4].rpartition(
        f".{cache_tag}.opt-"
    )
    return bool(marker and source_name and optimization.isalnum())


def _runtime_package_manifest(
    package_root: Path,
    record: Mapping[Path, tuple[str, int]],
) -> dict[str, Any]:
    """Verify every non-cache package byte and return its bounded manifest."""

    expected = {
        path
        for path in record
        if path.is_relative_to(package_root)
        and not _is_cache_path(path.relative_to(package_root))
    }
    actual: set[Path] = set()
    files: list[dict[str, str]] = []

    def visit(directory: Path) -> None:
        try:
            children = sorted(directory.iterdir(), key=lambda child: child.name)
        except OSError as exc:
            _fail("cannot enumerate runtime package", exc)
        for child in children:
            relative = child.relative_to(package_root)
            try:
                info = child.lstat()
            except OSError as exc:
                _fail("cannot inspect runtime package entry", exc)
            if stat.S_ISLNK(info.st_mode):
                _fail("runtime package contains a link")
            if stat.S_ISDIR(info.st_mode):
                visit(child)
                continue
            if not stat.S_ISREG(info.st_mode):
                _fail("runtime package contains a non-regular entry")
            if _is_cache_path(relative):
                continue
            if len(actual) >= _MAX_PACKAGE_RUNTIME_FILES:
                _fail("runtime package exceeds file count bound")
            actual.add(child)
            files.append(
                {
                    "path": relative.as_posix(),
                    "sha256": _verify_recorded(
                        child, record, "runtime package file"
                    ),
                }
            )

    visit(package_root)
    if actual != expected:
        _fail("runtime package files differ from wheel RECORD")
    if not files:
        _fail("runtime package has no recorded files")
    files.sort(key=lambda item: item["path"])
    try:
        digest = canonical_sha256(
            {"files": files}, max_bytes=_MAX_PACKAGE_RUNTIME_MANIFEST_BYTES
        )
    except SemanticEventError as exc:
        _fail("runtime package manifest exceeds byte bound", exc)
    return {"count": len(files), "sha256": digest}


def _entry_point(dist: metadata.Distribution, name: str, target: str, label: str) -> None:
    matches = [entry for entry in dist.entry_points if entry.group == "console_scripts" and entry.name == name]
    if len(matches) != 1 or matches[0].value != target:
        _fail(f"installed {label} entry point does not match promoted interface")


def _promotion_wheel_artifact(manifest: Mapping[str, Any]) -> dict[str, str]:
    """Return the one exact promoted wheel named by this bundle.

    A package/RECORD comparison cannot distinguish two different wheel files
    without an archive hash retained by the installer, so ambiguity is not
    silently resolved here.
    """

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        _fail("promotion manifest artifacts are unavailable")
    wheels = [
        artifact for artifact in artifacts
        if isinstance(artifact, Mapping)
        and isinstance(artifact.get("name"), str)
        and artifact["name"].lower().endswith(".whl")
    ]
    if len(wheels) != 1:
        _fail("promotion manifest must name exactly one wheel artifact")
    wheel = wheels[0]
    name = wheel.get("name")
    if not isinstance(name, str) or not name:
        _fail("promotion wheel artifact name is invalid")
    return {"name": name, "sha256": _digest(wheel.get("sha256"), "promotion wheel artifact SHA-256")}


def _optional_recorded_file(
    path: Path, record: Mapping[Path, tuple[str, int]], label: str
) -> tuple[Path, str] | None:
    if not path.exists():
        return None
    checked = _canonical_existing(path, label)
    return checked, _verify_recorded(checked, record, label)


def _installed_mapping_evidence(
    dist_info: Path,
    record: Mapping[Path, tuple[str, int]],
    promotion_wheel: Mapping[str, str],
) -> tuple[str, dict[str, Any]]:
    """Describe the strongest honest wheel-to-install mapping available.

    RECORD binds installed package bytes, not the original wheel archive.  A
    RECORD-authenticated PEP 610 archive hash can additionally bind that archive
    to the promoted wheel digest; otherwise the receipt deliberately reports a
    weaker package/installer mapping instead of claiming bitwise wheel origin.
    """

    direct_url_evidence: dict[str, str | None] | None = None
    direct_url = _optional_recorded_file(
        dist_info / "direct_url.json", record, "direct_url metadata"
    )
    if direct_url is not None:
        direct_url_path, direct_url_digest = direct_url
        try:
            value = json.loads(_stable_read(direct_url_path, "direct_url metadata").decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            _fail("direct_url metadata is invalid", exc)
        if not isinstance(value, Mapping):
            _fail("direct_url metadata is invalid")
        if isinstance(value.get("dir_info"), Mapping) and value["dir_info"].get("editable") is True:
            _fail("editable direct_url installation is not admissible")
        archive_sha: str | None = None
        archive_info = value.get("archive_info")
        if isinstance(archive_info, Mapping):
            archive_hash = archive_info.get("hash")
            if isinstance(archive_hash, str) and archive_hash.startswith("sha256="):
                archive_sha = _digest(archive_hash[7:], "direct_url archive SHA-256")
                if archive_sha != promotion_wheel["sha256"]:
                    _fail("direct_url archive SHA-256 differs from promoted wheel")
        direct_url_evidence = {
            "path": str(direct_url_path),
            "record_sha256": direct_url_digest,
            "archive_sha256": archive_sha,
        }

    installer_evidence: dict[str, str] | None = None
    installer = _optional_recorded_file(dist_info / "INSTALLER", record, "installed INSTALLER")
    if installer is not None:
        installer_path, installer_digest = installer
        try:
            installer_name = _stable_read(installer_path, "installed INSTALLER").decode("utf-8", "strict").strip()
        except UnicodeDecodeError as exc:
            _fail("installed INSTALLER is not UTF-8", exc)
        if not installer_name:
            _fail("installed INSTALLER is empty")
        installer_evidence = {"path": str(installer_path), "record_sha256": installer_digest}

    if direct_url_evidence is not None and direct_url_evidence["archive_sha256"] is not None:
        strength = "direct_url_archive_sha256"
    elif installer_evidence is not None:
        strength = "record_package_and_installer"
    else:
        strength = "record_package_only"
    return strength, {"installer": installer_evidence, "direct_url": direct_url_evidence}


def _reject_pth_shadows(site_root: Path, package_root: Path) -> None:
    # Do not allowlist standard-looking executable files such as
    # ``distutils-precedence.pth``.  Its import executes before this verifier
    # and reaches bytes outside the AOI wheel RECORD/promotion proof.  A
    # provenance-qualified AOI tool venv must contain no executable .pth.
    for pth in sorted(site_root.glob("*.pth")):
        checked = _canonical_existing(pth, "site .pth file")
        for line in _stable_read(checked, "site .pth file").decode("utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("import ") or line.startswith("import\t"):
                _fail("executable .pth shadow is not admissible")
            candidate = Path(line)
            if not candidate.is_absolute():
                candidate = site_root / candidate
            try:
                candidate = canonicalize_no_link_traversal(candidate, "site .pth target")
            except HarnessError as exc:
                _fail("site .pth target is invalid", exc)
            if candidate == package_root or (candidate / "aoi_orgware").exists():
                _fail(".pth source/package shadow is not admissible")


def _require_dedicated_venv(
    prefix: Path, site_root: Path,
) -> None:
    """Require the active runtime to be an isolated venv with one site root."""

    config = _canonical_existing(
        prefix / "pyvenv.cfg", "active virtual environment configuration"
    )
    try:
        lines = _stable_read(
            config, "active virtual environment configuration"
        ).decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as exc:
        _fail("active virtual environment configuration is not UTF-8", exc)
    system_site: str | None = None
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            _fail("active virtual environment configuration is invalid")
        key, value = line.split("=", 1)
        if key.strip().lower() == "include-system-site-packages":
            if system_site is not None:
                _fail("active virtual environment configuration is invalid")
            system_site = value.strip().lower()
    if system_site != "false":
        _fail("active virtual environment must disable system site packages")
    try:
        exec_prefix = _canonical_existing(
            sys.exec_prefix, "active Python executable prefix", directory=True
        )
    except AttributeError as exc:
        _fail("active Python executable prefix is unavailable", exc)
    if exec_prefix != prefix:
        _fail("active Python executable prefix differs from virtual environment")
    for entry in sys.path:
        if not isinstance(entry, str) or not entry:
            continue
        candidate = Path(entry)
        if candidate.name.lower() not in {"site-packages", "dist-packages"}:
            continue
        checked = _canonical_existing(
            candidate, "active site-package root", directory=True
        )
        if checked != site_root:
            _fail("active external site-package root is not admissible")


def _runtime_python_binding(
    prefix: Path,
    invocation: str | os.PathLike[str] | None = None,
) -> dict[str, object]:
    """Return the cooperating host-Python identity used by a v3 hook.

    POSIX ``venv`` commonly leaves ``bin/python`` as one final symlink to the
    base interpreter.  The invocation must still be an absolute leaf of this
    exact venv; only that final leaf may be a link, and its resolved regular
    executable is recorded and hashed.  This runs *after* module import, so it
    detects cooperative drift only; it is not pre-import or same-user isolation.
    """

    raw_value = sys.executable if invocation is None else os.fspath(invocation)
    if not isinstance(raw_value, str) or not raw_value:
        _fail("runtime Python invocation is unavailable")
    raw = Path(raw_value)
    if not raw.is_absolute():
        _fail("runtime Python invocation must be an absolute path")
    try:
        parent = canonicalize_no_link_traversal(
            raw.parent, "runtime Python invocation parent"
        )
    except HarnessError as exc:
        _fail("cannot inspect runtime Python invocation parent", exc)
    if parent != raw.parent:
        _fail("runtime Python invocation parent is not canonical")
    allowed_parent = prefix / ("Scripts" if os.name == "nt" else "bin")
    if parent != allowed_parent:
        _fail("runtime Python invocation lies outside the active virtual environment")
    try:
        info = raw.lstat()
    except OSError as exc:
        _fail("cannot inspect runtime Python invocation", exc)
    if stat.S_ISLNK(info.st_mode):
        if os.name == "nt":
            _fail("runtime Python invocation must not be a link")
        try:
            resolved = raw.resolve(strict=True)
        except OSError as exc:
            _fail("cannot resolve runtime Python invocation", exc)
        if not resolved.is_absolute() or resolved == raw:
            _fail("runtime Python invocation resolved target is invalid")
        try:
            resolved = canonicalize_no_link_traversal(
                resolved, "runtime Python resolved executable"
            )
        except HarnessError as exc:
            _fail("cannot inspect runtime Python resolved executable", exc)
    else:
        resolved = _canonical_existing(raw, "runtime Python invocation")
    try:
        resolved_info = resolved.lstat()
    except OSError as exc:
        _fail("cannot inspect runtime Python resolved executable", exc)
    if not stat.S_ISREG(resolved_info.st_mode) or resolved.is_symlink():
        _fail("runtime Python resolved executable is not a regular non-link file")
    _require_executable(resolved, "runtime Python resolved executable")
    cache_tag = getattr(getattr(sys, "implementation", None), "cache_tag", None)
    if not isinstance(cache_tag, str) or not cache_tag:
        _fail("runtime Python cache tag is unavailable")
    return {
        "python_invocation": str(raw),
        "python_resolved_path": str(resolved),
        "python_resolved_sha256": _sha256(
            _stable_read(
                resolved,
                "runtime Python resolved executable",
                max_bytes=_MAX_RUNTIME_PYTHON_BYTES,
            )
        ),
        "venv_prefix": str(prefix),
        "python_cache_tag": cache_tag,
    }


def _codex_hook_runtime_binding(
    prefix: Path, package_root: Path, record: Mapping[Path, tuple[str, int]],
    *, invocation: str | os.PathLike[str] | None = None,
) -> dict[str, object]:
    """Bind the v3 hook to its Python module, not its pip launcher."""

    module_path = _canonical_existing(
        package_root / "codex_hook.py", "runtime Codex hook module"
    )
    if module_path != package_root / "codex_hook.py":
        _fail("runtime Codex hook module is package-shadowed")
    identity = _runtime_python_binding(prefix, invocation)
    return {
        "contract_version": CODEX_HOOK_RUNTIME_CONTRACT_VERSION,
        "kind": CODEX_HOOK_RUNTIME_KIND,
        **identity,
        "module": CODEX_HOOK_RUNTIME_MODULE,
        "module_path": str(module_path),
        "module_record_sha256": _verify_recorded(
            module_path, record, "runtime Codex hook module"
        ),
        "argv_prefix": list(CODEX_HOOK_RUNTIME_ARGV_PREFIX),
        "trust_class": CODEX_HOOK_RUNTIME_TRUST_CLASS,
    }


def _verify_v3_hook_runtime_binding(
    binding: object,
    prefix: Path,
    package_root: Path,
    record: Mapping[Path, tuple[str, int]],
    *,
    runtime_python: str | os.PathLike[str] | None,
    runtime_module_path: str | os.PathLike[str] | None,
    runtime_argv_prefix: tuple[str, ...] | list[str] | None,
) -> None:
    """Recheck explicit post-import runtime facts for a v3 receipt."""

    if not isinstance(binding, Mapping):
        _fail("Codex hook runtime binding schema is invalid")
    if runtime_python is None or runtime_module_path is None or runtime_argv_prefix is None:
        _fail("schema-v3 hook provenance requires explicit Python and module identity")
    python_value = os.fspath(runtime_python)
    if not isinstance(python_value, str) or python_value != sys.executable:
        _fail("runtime Python invocation differs from current interpreter")
    if list(runtime_argv_prefix) != list(CODEX_HOOK_RUNTIME_ARGV_PREFIX):
        _fail("runtime Codex hook argv prefix is invalid")
    supplied_module = _canonical_existing(
        runtime_module_path, "explicit runtime Codex hook module"
    )
    expected_module = package_root / "codex_hook.py"
    if supplied_module != expected_module:
        _fail("explicit runtime Codex hook module differs from installed package")
    module = importlib.import_module(CODEX_HOOK_RUNTIME_MODULE)
    module_file = getattr(module, "__file__", None)
    if module_file is None or _canonical_existing(
        module_file, "imported runtime Codex hook module"
    ) != expected_module:
        _fail("imported runtime Codex hook module differs from installed package")
    current = _codex_hook_runtime_binding(
        prefix, package_root, record, invocation=runtime_python
    )
    if dict(binding) != current:
        _fail("current Codex hook Python/module runtime differs from provenance receipt")


def _generated_script(
    path: Path, target: str, record: Mapping[Path, tuple[str, int]], label: str
) -> str:
    digest = _verify_recorded(path, record, f"{label} generated script")
    try:
        text = _stable_read(path, f"{label} generated script").decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        _fail(f"{label} generated script is not UTF-8", exc)
    module, function = target.split(":", 1)
    if module not in text or function not in text:
        _fail(f"{label} generated script does not bind the promoted target")
    return digest


def _invoked_launcher(
    invoked: str | os.PathLike[str], expected: Path, label: str
) -> Path:
    """Canonicalize an invoked launcher, admitting only distlib's Windows alias."""

    if os.name == "nt":
        raw_value = os.fspath(invoked)
        raw = Path(raw_value)
        alias = expected.with_suffix("")
        # Deliberately do not use normpath here: it would turn a missing path
        # such as ``Scripts\\missing\\..\\aoi`` into the approved alias.
        # Case and separator spelling are harmless Windows differences, but
        # every canonical path component must already be exact.
        raw_spelling = os.path.normcase(raw_value).replace("/", "\\")
        alias_spelling = os.path.normcase(os.fspath(alias)).replace("/", "\\")
        if raw.is_absolute() and raw_spelling == alias_spelling:
            # distlib's Windows launcher can rewrite sys.argv[0] from the
            # RECORD-bound ``aoi.exe`` to this otherwise non-existent alias.
            # Return the already canonical expected path; no arbitrary missing
            # invocation is admitted by this exception.
            return expected
    return _canonical_existing(invoked, label)


def _launcher(
    prefix: Path,
    name: str,
    target: str,
    invoked: str | os.PathLike[str] | None,
    record: Mapping[Path, tuple[str, int]],
    label: str,
) -> tuple[Path, str, Path | None, str | None]:
    scripts = prefix / ("Scripts" if os.name == "nt" else "bin")
    if not scripts.is_dir():
        _fail(f"{label} scripts directory is missing")
    expected = scripts / (f"{name}.exe" if os.name == "nt" else name)
    checked = _canonical_existing(expected, label)
    _require_executable(checked, label)
    if invoked is not None and _invoked_launcher(invoked, checked, f"invoked {label}") != checked:
        _fail(f"invoked {label} is not the promoted launcher")
    digest = _verify_recorded(checked, record, label)
    if os.name == "nt":
        # Modern pip launchers may legitimately contain only the executable.
        # If a generated companion exists, it must remain RECORD-bound and
        # target-bound; its absence is represented explicitly in the receipt.
        companion = _optional_recorded_file(
            scripts / f"{name}-script.py", record, f"{label} generated script"
        )
        if companion is not None:
            companion_path, companion_digest = companion
            _generated_script(companion_path, target, record, label)
            return checked, digest, companion_path, companion_digest
        return checked, digest, None, None
    else:
        text = _stable_read(checked, label).decode("utf-8", "strict")
        module, function = target.split(":", 1)
        if module not in text or function not in text:
            _fail(f"{label} launcher does not bind the promoted target")
    return checked, digest, None, None


def validate_codex_install_provenance(
    promotion_bundle_file: str | os.PathLike[str], expected_bundle_sha256: str, invoked_console: str | os.PathLike[str]
) -> dict[str, Any]:
    """Return a sealed receipt only when this running install proves the bundle.

    The check deliberately fails closed for non-wheel, editable, linked, mixed
    prefix, unrecorded, or launcher-shadowed installations.
    """
    bundle = _load_bundle(promotion_bundle_file, expected_bundle_sha256)
    manifest = bundle["manifest"]
    interfaces = manifest["interfaces"]
    console, hook = interfaces["console_entry_point"], interfaces["codex_hook_entry_point"]
    if console["target"] != _AOI_CONSOLE_TARGET or hook["target"] != _AOI_HOOK_TARGET:
        _fail("promoted AOI targets are not the exact supported entry points")
    try:
        dist = metadata.distribution(manifest["distribution_name"])
        dist_info = _canonical_existing(Path(dist._path), "distribution metadata directory", directory=True)  # type: ignore[attr-defined]
    except (metadata.PackageNotFoundError, AttributeError, TypeError) as exc:
        _fail("promoted distribution metadata is unavailable", exc)
    if _normal_name(dist.metadata["Name"]) != _normal_name(manifest["distribution_name"]) or dist.version != manifest["package_version"]:
        _fail("installed distribution identity/version differs from promotion bundle")
    prefix = _canonical_existing(sys.prefix, "active Python prefix", directory=True)
    site_root = _canonical_existing(dist_info.parent, "distribution site root", directory=True)
    _require_dedicated_venv(prefix, site_root)
    _under(dist_info, prefix, "distribution metadata")
    _under(site_root, prefix, "distribution site root")
    record = _record(dist_info, site_root)
    metadata_path = _canonical_existing(dist_info / "METADATA", "installed METADATA")
    metadata_sha = _verify_recorded(metadata_path, record, "installed METADATA")
    if metadata_sha != interfaces["installed_metadata_sha256"]:
        _fail("installed METADATA digest differs from promoted interface")
    _entry_point(dist, console["name"], console["target"], "console")
    _entry_point(dist, hook["name"], hook["target"], "Codex hook")
    package = importlib.import_module("aoi_orgware")
    version_module = importlib.import_module("aoi_orgware._version")
    cli_module = importlib.import_module("aoi_orgware.cli")
    hook_module = importlib.import_module("aoi_orgware.codex_hook")
    package_file = package.__file__
    if package_file is None:
        _fail("runtime package has no file")
    package_root = _canonical_existing(Path(package_file).parent, "runtime package root", directory=True)
    if package_root.parent != site_root:
        _fail("runtime package is source-checkout or cross-site shadowed")
    _under(package_root, prefix, "runtime package")
    _verify_recorded(package_root / "__init__.py", record, "runtime package initializer")
    for module, relative, label in ((version_module, "_version.py", "runtime version module"), (cli_module, "cli.py", "runtime CLI module"), (hook_module, "codex_hook.py", "runtime hook module")):
        module_file = module.__file__
        if module_file is None:
            _fail(f"{label} has no file")
        if _canonical_existing(module_file, label) != package_root / relative:
            _fail(f"{label} is package-shadowed")
        _verify_recorded(package_root / relative, record, label)
    if package.__version__ != manifest["package_version"] or version_module.__version__ != manifest["package_version"]:
        _fail("runtime __version__ differs from promoted package version")
    promotion_wheel = _promotion_wheel_artifact(manifest)
    mapping_strength, mapping_evidence = _installed_mapping_evidence(
        dist_info, record, promotion_wheel
    )
    _reject_pth_shadows(site_root, package_root)
    package_manifest = _runtime_package_manifest(package_root, record)
    console_path, console_sha, _console_script, _console_script_sha = _launcher(
        prefix, console["name"], console["target"], invoked_console, record, "console launcher"
    )
    hook_path, hook_sha, hook_script, hook_script_sha = _launcher(
        prefix, hook["name"], hook["target"], None, record, "Codex hook launcher"
    )
    _under(console_path, prefix, "console launcher")
    _under(hook_path, prefix, "Codex hook launcher")
    base = {
        "schema_version": _PROMOTED_INSTALL_PROVENANCE_SCHEMA_VERSION,
        "promotion_bundle_sha256": bundle["bundle_sha256"],
        "distribution_name": manifest["distribution_name"],
        "package_version": manifest["package_version"],
        "installed_metadata_sha256": metadata_sha,
        "metadata_path": str(metadata_path),
        "package_root": str(package_root),
        "console_entry_point": {"name": console["name"], "target": console["target"], "path": str(console_path), "record_sha256": console_sha},
        "codex_hook_entry_point": {"name": hook["name"], "target": hook["target"], "path": str(hook_path), "record_sha256": hook_sha},
        "codex_hook_generated_script": {
            "path": str(hook_script) if hook_script is not None else None,
            "record_sha256": hook_script_sha,
        },
        "package_runtime_manifest": package_manifest,
        "hook_protocol_version": interfaces["hook_protocol_version"],
        "promotion_wheel_artifact": promotion_wheel,
        "installed_distribution_identity": {
            "name": dist.metadata["Name"],
            "version": dist.version,
            "metadata_sha256": metadata_sha,
        },
        "installed_mapping_strength": mapping_strength,
        "installed_mapping_evidence": mapping_evidence,
    }
    try:
        digest = canonical_sha256(base, max_bytes=64 * 1024)
    except SemanticEventError as exc:
        _fail("provenance receipt cannot be sealed", exc)
    return {**base, "provenance_receipt_sha256": digest}


def _local_install_contract(
    bundle_file: str | os.PathLike[str], expected_bundle_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], Path]:
    """Load the independently sealed local-install proof without release semantics.

    The proof module owns source/store observation.  This layer deliberately
    accepts only its small, normalized contract, so an installed wheel does not
    need to import a checkout or reproduce publication validation.
    """
    bundle_path = _canonical_existing(bundle_file, "local installation bundle")
    expected = _digest(expected_bundle_sha256, "expected local installation bundle SHA-256")
    try:
        from . import local_install_proof
        loader = getattr(local_install_proof, "load_local_install_bundle", None)
        contract_builder = getattr(local_install_proof, "local_install_contract", None)
        if not callable(loader) or not callable(contract_builder):
            _fail("local installation bundle verifier is unavailable")
        loaded = loader(bundle_path, expected, verify_store=True)
        contract = contract_builder(loaded, bundle_path=bundle_path)
    except (ImportError, AttributeError, TypeError, ValueError, OSError) as exc:
        _fail("local installation bundle is invalid", exc)
    if not isinstance(loaded, Mapping) or not isinstance(contract, Mapping):
        _fail("local installation bundle contract is invalid")
    normalized = dict(contract)
    required = {
        "distribution_name", "package_version", "wheel", "interfaces",
        "artifact_store_root", "source_commit_oid", "source_tree_oid",
        "source_manifest_sha256", "rehearsal_report_sha256", "inventory_sha256",
        "bundle_sha256",
    }
    if set(normalized) != required:
        _fail("local installation bundle contract has unexpected fields")
    if normalized["bundle_sha256"] != expected:
        _fail("local installation bundle contract digest differs from expected value")
    for field in ("distribution_name", "package_version", "source_commit_oid", "source_tree_oid"):
        if not isinstance(normalized[field], str) or not normalized[field]:
            _fail("local installation bundle contract identity is invalid")
    for field in ("source_manifest_sha256", "rehearsal_report_sha256", "inventory_sha256", "bundle_sha256"):
        _digest(normalized[field], f"local installation bundle {field}")
    store_root = _canonical_existing(
        normalized["artifact_store_root"], "local artifact store root", directory=True
    )
    wheel = normalized["wheel"]
    interfaces = normalized["interfaces"]
    if not isinstance(wheel, Mapping) or set(wheel) != _LOCAL_WHEEL_ARTIFACT_FIELDS:
        _fail("local installation bundle wheel contract is invalid")
    if not isinstance(wheel.get("name"), str) or not wheel["name"]:
        _fail("local installation bundle wheel name is invalid")
    if not isinstance(wheel.get("size_bytes"), int) or isinstance(wheel["size_bytes"], bool) or wheel["size_bytes"] < 1:
        _fail("local installation bundle wheel size is invalid")
    _digest(wheel.get("sha256"), "local installation bundle wheel SHA-256")
    wheel_value = wheel.get("path")
    if not isinstance(wheel_value, str) or not wheel_value:
        _fail("local installation bundle wheel path is invalid")
    wheel_path = _canonical_existing(wheel_value, "local installation wheel")
    try:
        wheel_path.relative_to(store_root)
    except ValueError:
        _fail("local installation wheel lies outside artifact store")
    wheel_raw = _stable_read(wheel_path, "local installation wheel", max_bytes=256 * 1024 * 1024)
    if wheel_path.name != wheel["name"] or len(wheel_raw) != wheel["size_bytes"] or _sha256(wheel_raw) != wheel["sha256"]:
        _fail("local installation wheel bytes differ from proof")
    if not isinstance(interfaces, Mapping) or set(interfaces) != {
        "installed_metadata_sha256",
        "console_entry_point",
        "codex_hook_entry_point",
        "codex_bridge_entry_point",
        "hook_protocol_version",
    }:
        _fail("local installation bundle interface contract is invalid")
    _digest(interfaces.get("installed_metadata_sha256"), "local installation METADATA SHA-256")
    for field, target in (
        ("console_entry_point", _AOI_CONSOLE_TARGET),
        ("codex_hook_entry_point", _AOI_HOOK_TARGET),
        ("codex_bridge_entry_point", _AOI_BRIDGE_TARGET),
    ):
        entry = interfaces[field]
        if not isinstance(entry, Mapping) or set(entry) != {"name", "target"} or not isinstance(entry.get("name"), str) or entry.get("target") != target:
            _fail("local installation bundle entry-point contract is invalid")
    if interfaces["hook_protocol_version"] != 6:
        _fail("local installation bundle hook protocol is invalid")
    return dict(loaded), normalized, bundle_path


def _file_url_path(value: object) -> Path:
    if not isinstance(value, str) or not value:
        _fail("direct_url URL is invalid")
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "file" or parsed.netloc or parsed.query or parsed.fragment:
        _fail("direct_url URL is not a local file URL")
    raw_path = unquote(parsed.path)
    # file:///C:/... has an extra leading slash only when interpreted on Windows.
    if os.name == "nt" and len(raw_path) >= 3 and raw_path[0] == "/" and raw_path[2] == ":":
        raw_path = raw_path[1:]
    if not raw_path:
        _fail("direct_url URL is not a local file URL")
    return _canonical_existing(Path(raw_path), "direct_url wheel archive")


def _local_installed_mapping_evidence(
    dist_info: Path, record: Mapping[Path, tuple[str, int]], wheel: Mapping[str, Any],
) -> dict[str, Any]:
    direct = _optional_recorded_file(
        dist_info / "direct_url.json", record, "local direct_url metadata"
    )
    if direct is None:
        _fail("local wheel installation lacks direct_url metadata")
    direct_path, direct_digest = direct
    try:
        value = json.loads(_stable_read(direct_path, "local direct_url metadata").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail("local direct_url metadata is invalid", exc)
    if not isinstance(value, Mapping) or set(value) - {"url", "archive_info"}:
        _fail("local direct_url metadata is invalid")
    if "url" not in value or "archive_info" not in value or not isinstance(value["archive_info"], Mapping):
        _fail("local direct_url metadata lacks archive identity")
    archive = value["archive_info"]
    if set(archive) not in ({"hash"}, {"hash", "hashes"}) or not isinstance(archive.get("hash"), str) or not archive["hash"].startswith("sha256="):
        _fail("local direct_url archive SHA-256 is invalid")
    archive_sha = _digest(archive["hash"][7:], "local direct_url archive SHA-256")
    if "hashes" in archive:
        hashes = archive["hashes"]
        if not isinstance(hashes, Mapping) or set(hashes) != {"sha256"} or hashes["sha256"] != archive_sha:
            _fail("local direct_url archive hashes are invalid")
    if archive_sha != wheel["sha256"]:
        _fail("local direct_url archive SHA-256 differs from proof wheel")
    archive_path = _file_url_path(value["url"])
    wheel_path = _canonical_existing(wheel["path"], "proved local installation wheel")
    if archive_path != wheel_path:
        _fail("local direct_url archive path differs from proof wheel")
    return {
        "direct_url": {
            "path": str(direct_path), "record_sha256": direct_digest,
            "archive_sha256": archive_sha, "archive_path": str(archive_path),
        }
    }


def _wheel_member_path(name: str, label: str) -> PurePosixPath:
    """Return one non-relocatable wheel member path or fail closed."""

    if (
        not name
        or "\\" in name
        or ":" in name
        or any(ord(char) < 32 for char in name)
    ):
        _fail(f"{label} path is invalid")
    raw = name[:-1] if name.endswith("/") else name
    parts = raw.split("/")
    if not raw or any(part in {"", ".", ".."} for part in parts):
        _fail(f"{label} path is invalid")
    path = PurePosixPath(raw)
    if path.is_absolute():
        _fail(f"{label} path is invalid")
    return path


def _wheel_record_digest(value: str, size: str, label: str) -> tuple[str, int]:
    if not value.startswith("sha256=") or not size.isdecimal():
        _fail(f"{label} lacks a verifiable SHA-256 and size")
    digest = value[7:]
    if not digest or str(int(size)) != size:
        _fail(f"{label} is not canonical")
    try:
        decoded = base64.urlsafe_b64decode(digest + "=" * (-len(digest) % 4))
    except (ValueError, UnicodeEncodeError) as exc:
        _fail(f"{label} SHA-256 is invalid", exc)
    if (
        len(decoded) != hashlib.sha256().digest_size
        or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != digest
    ):
        _fail(f"{label} SHA-256 is invalid")
    return digest, int(size)


def _verify_local_wheel_install_members(
    wheel_contract: Mapping[str, Any],
    dist_info: Path,
    site_root: Path,
    package_root: Path,
    installed_record: Mapping[Path, tuple[str, int]],
) -> None:
    """Bind local installed payloads to one proved wheel's ZIP members.

    The installed RECORD remains useful for pip's generated launchers and
    direct_url metadata, but it is mutable alongside an installed package.  For
    a local proof, compare its package and dist-info wheel members directly to
    the reviewed archive and validate the archive's own RECORD first.
    """

    if set(wheel_contract) != _LOCAL_WHEEL_ARTIFACT_FIELDS:
        _fail("proved local installation wheel contract is invalid")
    wheel_value = wheel_contract.get("path")
    if not isinstance(wheel_value, str) or not wheel_value:
        _fail("proved local installation wheel path is invalid")
    wheel = _canonical_existing(wheel_value, "proved local installation wheel")
    wheel_raw = _stable_read(
        wheel, "proved local installation wheel", max_bytes=_MAX_LOCAL_WHEEL_BYTES
    )
    if (
        wheel.name != wheel_contract.get("name")
        or len(wheel_raw) != wheel_contract.get("size_bytes")
        or _sha256(wheel_raw) != wheel_contract.get("sha256")
    ):
        _fail("proved local installation wheel bytes differ from proof")
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_raw)) as archive:
            members: dict[PurePosixPath, tuple[zipfile.ZipInfo, bytes]] = {}
            total_size = 0
            for info in archive.infolist():
                path = _wheel_member_path(info.filename, "local wheel member")
                if path in members or len(members) >= _MAX_LOCAL_WHEEL_MEMBERS:
                    _fail("local wheel has duplicate or ambiguous members")
                if (
                    info.flag_bits & 0x1
                    or info.compress_type not in _LOCAL_WHEEL_COMPRESSION
                    or info.file_size < 0
                    or info.file_size > _MAX_FILE_BYTES
                ):
                    _fail("local wheel member is encrypted or unsupported")
                mode = info.external_attr >> 16
                mode_type = stat.S_IFMT(mode)
                if (
                    mode_type == stat.S_IFLNK
                    or mode_type not in {0, stat.S_IFREG, stat.S_IFDIR}
                    or (info.is_dir() and mode_type == stat.S_IFREG)
                    or (not info.is_dir() and mode_type == stat.S_IFDIR)
                ):
                    _fail("local wheel member is a link or non-regular entry")
                if info.is_dir():
                    if info.file_size != 0:
                        _fail("local wheel directory member is invalid")
                    members[path] = (info, b"")
                    continue
                total_size += info.file_size
                if total_size > _MAX_LOCAL_WHEEL_BYTES:
                    _fail("local wheel exceeds uncompressed byte bound")
                members[path] = (info, archive.read(info))
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError) as exc:
        _fail("proved local installation wheel is not a safe ZIP archive", exc)

    if any(
        path.parts[0] not in {"aoi_orgware", dist_info.name}
        for path in members
    ):
        _fail("local wheel uses unsupported installation relocation")
    files = {path: raw for path, (info, raw) in members.items() if not info.is_dir()}
    records = [
        path for path in files
        if len(path.parts) == 2 and path.parts[0] == dist_info.name and path.name == "RECORD"
    ]
    if len(records) != 1:
        _fail("local wheel must contain exactly one matching embedded RECORD")
    record_member = records[0]
    wheel_record: dict[PurePosixPath, tuple[str, int]] = {}
    recorded_paths: set[PurePosixPath] = set()
    try:
        rows = csv.reader(files[record_member].decode("utf-8").splitlines())
        for row in rows:
            if len(row) != 3:
                _fail("local wheel embedded RECORD row is invalid")
            path = _wheel_member_path(row[0], "local wheel embedded RECORD")
            if path in recorded_paths or path not in files:
                _fail("local wheel embedded RECORD is ambiguous")
            recorded_paths.add(path)
            if path == record_member:
                if row[1] or row[2]:
                    _fail("local wheel embedded RECORD self-row is invalid")
                continue
            digest, size = _wheel_record_digest(
                row[1], row[2], "local wheel embedded RECORD row"
            )
            actual = base64.urlsafe_b64encode(
                hashlib.sha256(files[path]).digest()
            ).decode("ascii").rstrip("=")
            if len(files[path]) != size or actual != digest:
                _fail("local wheel member bytes differ from embedded RECORD")
            wheel_record[path] = (digest, size)
    except UnicodeDecodeError as exc:
        _fail("local wheel embedded RECORD is not UTF-8", exc)
    if set(wheel_record) | {record_member} != set(files):
        _fail("local wheel embedded RECORD does not cover its members")

    package_members: set[PurePosixPath] = set()
    for path, raw in files.items():
        if path == record_member:
            continue
        if path.parts[0] == "aoi_orgware":
            relative = PurePosixPath(*path.parts[1:])
            if _is_cache_path(Path(*relative.parts)):
                _fail("local wheel contains bytecode cache")
            package_members.add(relative)
        elif path.parts[0] != dist_info.name:
            _fail("local wheel uses unsupported installation relocation")
        installed = _canonical_existing(
            site_root.joinpath(*path.parts), "installed local wheel member"
        )
        record_entry = installed_record.get(installed)
        if record_entry != wheel_record[path]:
            _fail("installed wheel member RECORD differs from proved wheel")
        if _stable_read(installed, "installed local wheel member") != raw:
            _fail("installed wheel member bytes differ from proved wheel")
    if PurePosixPath(CODEX_CLIENT_SKILL_RESOURCE) not in package_members:
        _fail("local wheel lacks packaged Codex client skill")

    installed_package_members: set[PurePosixPath] = set()
    def visit(directory: Path) -> None:
        try:
            children = sorted(directory.iterdir(), key=lambda child: child.name)
        except OSError as exc:
            _fail("cannot enumerate installed local wheel package", exc)
        for child in children:
            relative = child.relative_to(package_root)
            try:
                info = child.lstat()
            except OSError as exc:
                _fail("cannot inspect installed local wheel package", exc)
            if stat.S_ISLNK(info.st_mode):
                _fail("installed local wheel package contains a link")
            if stat.S_ISDIR(info.st_mode):
                visit(child)
            elif stat.S_ISREG(info.st_mode):
                if not _is_cache_path(relative):
                    installed_package_members.add(PurePosixPath(relative.as_posix()))
            else:
                _fail("installed local wheel package contains a non-regular entry")

    visit(package_root)
    if installed_package_members != package_members:
        _fail("installed local wheel package members differ from proved wheel")


def validate_codex_local_install_provenance(
    local_bundle_file: str | os.PathLike[str], expected_bundle_sha256: str,
    invoked_console: str | os.PathLike[str],
) -> dict[str, Any]:
    """Return a schema-v2 receipt for one exact reviewed local wheel install."""
    _bundle, contract, bundle_path = _local_install_contract(
        local_bundle_file, expected_bundle_sha256
    )
    interfaces = contract["interfaces"]
    try:
        dist = metadata.distribution(contract["distribution_name"])
        dist_info = _canonical_existing(Path(dist._path), "distribution metadata directory", directory=True)  # type: ignore[attr-defined]
    except (metadata.PackageNotFoundError, AttributeError, TypeError) as exc:
        _fail("local installed distribution metadata is unavailable", exc)
    if _normal_name(dist.metadata["Name"]) != _normal_name(contract["distribution_name"]) or dist.version != contract["package_version"]:
        _fail("installed distribution identity/version differs from local proof")
    prefix = _canonical_existing(sys.prefix, "active Python prefix", directory=True)
    site_root = _canonical_existing(dist_info.parent, "distribution site root", directory=True)
    _require_dedicated_venv(prefix, site_root)
    _under(dist_info, prefix, "distribution metadata")
    _under(site_root, prefix, "distribution site root")
    record_path = _canonical_existing(dist_info / "RECORD", "wheel RECORD")
    installed_record_sha = _sha256(_stable_read(record_path, "wheel RECORD"))
    record = _record(dist_info, site_root)
    metadata_path = _canonical_existing(dist_info / "METADATA", "installed METADATA")
    metadata_sha = _verify_recorded(metadata_path, record, "installed METADATA")
    if metadata_sha != interfaces["installed_metadata_sha256"]:
        _fail("installed METADATA digest differs from local proof interface")
    console = interfaces["console_entry_point"]
    hook = interfaces["codex_hook_entry_point"]
    bridge = interfaces["codex_bridge_entry_point"]
    _entry_point(dist, console["name"], console["target"], "console")
    _entry_point(dist, hook["name"], hook["target"], "Codex hook")
    _entry_point(dist, bridge["name"], bridge["target"], "Codex bridge")
    package = importlib.import_module("aoi_orgware")
    version_module = importlib.import_module("aoi_orgware._version")
    cli_module = importlib.import_module("aoi_orgware.cli")
    hook_module = importlib.import_module("aoi_orgware.codex_hook")
    bridge_module = importlib.import_module("aoi_orgware.codex_transport_cli")
    if package.__file__ is None:
        _fail("runtime package has no file")
    package_root = _canonical_existing(Path(package.__file__).parent, "runtime package root", directory=True)
    if package_root.parent != site_root:
        _fail("runtime package is source-checkout or cross-site shadowed")
    _under(package_root, prefix, "runtime package")
    _verify_recorded(package_root / "__init__.py", record, "runtime package initializer")
    for module, relative, label in (
        (version_module, "_version.py", "runtime version module"),
        (cli_module, "cli.py", "runtime CLI module"),
        (hook_module, "codex_hook.py", "runtime hook module"),
        (bridge_module, "codex_transport_cli.py", "runtime Codex bridge module"),
    ):
        module_file = module.__file__
        if module_file is None or _canonical_existing(module_file, label) != package_root / relative:
            _fail(f"{label} is package-shadowed")
        _verify_recorded(package_root / relative, record, label)
    if package.__version__ != contract["package_version"] or version_module.__version__ != contract["package_version"]:
        _fail("runtime __version__ differs from local proof package version")
    evidence = _local_installed_mapping_evidence(dist_info, record, contract["wheel"])
    _reject_pth_shadows(site_root, package_root)
    package_manifest = _runtime_package_manifest(package_root, record)
    _verify_local_wheel_install_members(
        contract["wheel"], dist_info, site_root, package_root, record
    )
    console_path, console_sha, _console_script, _console_script_sha = _launcher(prefix, console["name"], console["target"], invoked_console, record, "console launcher")
    hook_path, hook_sha, hook_script, hook_script_sha = _launcher(prefix, hook["name"], hook["target"], None, record, "Codex hook launcher")
    bridge_path, bridge_sha, bridge_script, bridge_script_sha = _launcher(
        prefix,
        bridge["name"],
        bridge["target"],
        None,
        record,
        "Codex bridge launcher",
    )
    _under(console_path, prefix, "console launcher")
    _under(hook_path, prefix, "Codex hook launcher")
    _under(bridge_path, prefix, "Codex bridge launcher")
    base = {
        "schema_version": _LOCAL_INSTALL_PROVENANCE_SCHEMA_VERSION,
        "install_proof": {
            "kind": "reviewed_local_install_bundle", "proof_scope": "exact_local_wheel_install_only",
            "bundle_path": str(bundle_path), "bundle_sha256": contract["bundle_sha256"],
            "artifact_store_root": contract["artifact_store_root"],
            "source_commit_oid": contract["source_commit_oid"], "source_tree_oid": contract["source_tree_oid"],
            "source_manifest_sha256": contract["source_manifest_sha256"],
            "rehearsal_report_sha256": contract["rehearsal_report_sha256"], "inventory_sha256": contract["inventory_sha256"],
        },
        "distribution_name": contract["distribution_name"], "package_version": contract["package_version"],
        "installed_metadata_sha256": metadata_sha, "metadata_path": str(metadata_path),
        "package_root": str(package_root),
        "console_entry_point": {"name": console["name"], "target": console["target"], "path": str(console_path), "record_sha256": console_sha},
        "codex_hook_entry_point": {"name": hook["name"], "target": hook["target"], "path": str(hook_path), "record_sha256": hook_sha},
        "codex_hook_generated_script": {"path": str(hook_script) if hook_script is not None else None, "record_sha256": hook_script_sha},
        "codex_bridge_entry_point": {"name": bridge["name"], "target": bridge["target"], "path": str(bridge_path), "record_sha256": bridge_sha},
        "codex_bridge_generated_script": {"path": str(bridge_script) if bridge_script is not None else None, "record_sha256": bridge_script_sha},
        "package_runtime_manifest": package_manifest, "hook_protocol_version": 6,
        "install_wheel_artifact": dict(contract["wheel"]),
        "installed_distribution_identity": {"name": dist.metadata["Name"], "version": dist.version, "metadata_sha256": metadata_sha},
        "installed_mapping_strength": "direct_url_archive_sha256",
        "installed_mapping_evidence": evidence,
        "installed_record": {"path": str(record_path), "sha256": installed_record_sha},
    }
    try:
        return {**base, "provenance_receipt_sha256": canonical_sha256(base, max_bytes=64 * 1024)}
    except SemanticEventError as exc:
        _fail("local install provenance receipt cannot be sealed", exc)


def _validate_local_install_provenance_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    item = dict(receipt)
    if (
        set(item) != _LOCAL_RECEIPT_FIELDS
        or item.get("schema_version") != _LOCAL_INSTALL_PROVENANCE_SCHEMA_VERSION
    ):
        _fail("local Codex install provenance receipt schema is invalid")
    proof = item["install_proof"]
    if not isinstance(proof, Mapping) or set(proof) != _LOCAL_INSTALL_PROOF_FIELDS:
        _fail("local Codex install provenance receipt proof is invalid")
    if proof.get("kind") != "reviewed_local_install_bundle" or proof.get("proof_scope") != "exact_local_wheel_install_only":
        _fail("local Codex install provenance receipt proof scope is invalid")
    for field in ("bundle_path", "artifact_store_root"):
        _absolute_receipt_path(proof.get(field), f"local install proof {field}")
    for field in ("source_commit_oid", "source_tree_oid"):
        _git_oid(proof.get(field), f"local install proof {field}")
    for field in ("bundle_sha256", "source_manifest_sha256", "rehearsal_report_sha256", "inventory_sha256"):
        _digest(proof.get(field), f"local install proof {field}")
    for field in ("distribution_name", "package_version", "metadata_path", "package_root"):
        if not isinstance(item.get(field), str) or not item[field]:
            _fail("local Codex install provenance receipt identity is invalid")
    for field in ("metadata_path", "package_root"):
        _absolute_receipt_path(item[field], f"local install receipt {field}")
    _digest(item["installed_metadata_sha256"], "installed METADATA SHA-256")
    if item["hook_protocol_version"] != 6:
        _fail("local Codex install provenance receipt hook protocol is invalid")
    for field, target in (
        ("console_entry_point", _AOI_CONSOLE_TARGET),
        ("codex_hook_entry_point", _AOI_HOOK_TARGET),
        ("codex_bridge_entry_point", _AOI_BRIDGE_TARGET),
    ):
        entry = item[field]
        if not isinstance(entry, Mapping) or set(entry) != _ENTRY_RECEIPT_FIELDS:
            _fail("local Codex install provenance receipt entry point is invalid")
        if not all(isinstance(entry.get(key), str) and entry[key] for key in ("name", "target", "path")) or entry["target"] != target:
            _fail("local Codex install provenance receipt entry point is invalid")
        _absolute_receipt_path(entry["path"], f"local install receipt {field} path")
        _digest(entry["record_sha256"], "entry point RECORD SHA-256")
    for field in ("codex_hook_generated_script", "codex_bridge_generated_script"):
        script = item[field]
        if not isinstance(script, Mapping) or set(script) != _SCRIPT_RECEIPT_FIELDS or (script.get("path") is None) != (script.get("record_sha256") is None):
            _fail("local Codex install provenance receipt generated script is invalid")
        if script["path"] is not None:
            if not isinstance(script["path"], str) or not script["path"]:
                _fail("local Codex install provenance receipt generated script is invalid")
            _absolute_receipt_path(script["path"], f"local install receipt {field} path")
            _digest(script["record_sha256"], "generated script RECORD SHA-256")
    package_manifest = item["package_runtime_manifest"]
    if not isinstance(package_manifest, Mapping) or set(package_manifest) != _PACKAGE_MANIFEST_RECEIPT_FIELDS or not isinstance(package_manifest.get("count"), int) or isinstance(package_manifest["count"], bool) or not 0 < package_manifest["count"] <= _MAX_PACKAGE_RUNTIME_FILES:
        _fail("local Codex install provenance receipt package manifest is invalid")
    _digest(package_manifest.get("sha256"), "package manifest SHA-256")
    wheel = item["install_wheel_artifact"]
    if not isinstance(wheel, Mapping) or set(wheel) != _LOCAL_WHEEL_ARTIFACT_FIELDS or not isinstance(wheel.get("name"), str) or not wheel["name"] or not isinstance(wheel.get("size_bytes"), int) or isinstance(wheel["size_bytes"], bool) or wheel["size_bytes"] < 1:
        _fail("local Codex install provenance receipt wheel artifact is invalid")
    _absolute_receipt_path(wheel.get("path"), "local install wheel path")
    _digest(wheel["sha256"], "local install wheel SHA-256")
    identity = item["installed_distribution_identity"]
    if not isinstance(identity, Mapping) or set(identity) != _DISTRIBUTION_IDENTITY_FIELDS or identity.get("name") != item["distribution_name"] or identity.get("version") != item["package_version"]:
        _fail("local Codex install provenance receipt distribution identity is invalid")
    if _digest(identity.get("metadata_sha256"), "installed distribution metadata SHA-256") != item["installed_metadata_sha256"]:
        _fail("local Codex install provenance receipt distribution metadata differs from receipt")
    if item["installed_mapping_strength"] != "direct_url_archive_sha256":
        _fail("local Codex install provenance receipt mapping strength is invalid")
    evidence = item["installed_mapping_evidence"]
    if not isinstance(evidence, Mapping) or set(evidence) != {"direct_url"} or not isinstance(evidence["direct_url"], Mapping) or set(evidence["direct_url"]) != _LOCAL_DIRECT_URL_EVIDENCE_FIELDS:
        _fail("local Codex install provenance receipt mapping evidence is invalid")
    direct = evidence["direct_url"]
    if not all(isinstance(direct.get(field), str) and direct[field] for field in _LOCAL_DIRECT_URL_EVIDENCE_FIELDS):
        _fail("local Codex install provenance receipt mapping evidence is invalid")
    for field in ("path", "archive_path"):
        _absolute_receipt_path(direct[field], f"local direct_url {field}")
    for field in ("record_sha256", "archive_sha256"):
        _digest(direct[field], f"local direct_url {field}")
    if direct["archive_sha256"] != wheel["sha256"] or direct["archive_path"] != wheel["path"]:
        _fail("local Codex install provenance receipt mapping does not bind proof wheel")
    installed_record = item["installed_record"]
    if not isinstance(installed_record, Mapping) or set(installed_record) != _INSTALLED_RECORD_FIELDS:
        _fail("local Codex install provenance receipt installed RECORD is invalid")
    _absolute_receipt_path(installed_record.get("path"), "installed RECORD path")
    _digest(installed_record.get("sha256"), "installed RECORD SHA-256")
    receipt_digest = _digest(item["provenance_receipt_sha256"], "provenance receipt SHA-256")
    base = dict(item); base.pop("provenance_receipt_sha256")
    try:
        if canonical_sha256(base, max_bytes=64 * 1024) != receipt_digest:
            _fail("local Codex install provenance receipt digest is invalid")
    except SemanticEventError as exc:
        _fail("local Codex install provenance receipt is not canonical", exc)
    return item


def _install_schema_version(receipt: Mapping[str, Any]) -> int:
    """Return the underlying install-proof schema for a compatible receipt."""

    schema_version = receipt.get("schema_version")
    if schema_version == CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION:
        install_schema = receipt.get("install_provenance_schema_version")
        if (
            type(install_schema) is int
            and install_schema == _LOCAL_INSTALL_PROVENANCE_SCHEMA_VERSION
        ):
            return int(install_schema)
        _fail(
            "current schema-v3 Codex client binding requires "
            "local-v2 exact-wheel proof"
        )
    if schema_version in {
        _PROMOTED_INSTALL_PROVENANCE_SCHEMA_VERSION,
        _LOCAL_INSTALL_PROVENANCE_SCHEMA_VERSION,
    }:
        return int(schema_version)
    _fail("Codex install provenance receipt schema is invalid")


def _v3_install_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Recover and strictly validate the immutable local-v2 install proof."""

    item = dict(receipt)
    install_schema = _install_schema_version(item)
    if item.get("schema_version") != CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION:
        _fail("Codex client binding receipt schema is invalid")
    if install_schema != _LOCAL_INSTALL_PROVENANCE_SCHEMA_VERSION:
        _fail(
            "current schema-v3 Codex client binding requires "
            "local-v2 exact-wheel proof"
        )
    expected_fields = _LOCAL_RECEIPT_FIELDS | _V3_BINDING_FIELDS
    if set(item) != expected_fields:
        _fail("Codex client binding receipt fields are invalid")
    install_digest = _digest(
        item.get("install_provenance_receipt_sha256"),
        "install provenance receipt SHA-256",
    )
    legacy = {
        key: value
        for key, value in item.items()
        if key not in _V3_BINDING_FIELDS
    }
    legacy["schema_version"] = install_schema
    legacy["provenance_receipt_sha256"] = install_digest
    return validate_codex_install_provenance_receipt(legacy)


def _validate_codex_client_skill_binding(
    binding: object,
    install_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(binding, Mapping) or set(binding) != _CLIENT_SKILL_BINDING_FIELDS:
        _fail("Codex client skill binding schema is invalid")
    item = dict(binding)
    if (
        item.get("provider") != "codex"
        or type(item.get("client_contract_version")) is not int
        or item.get("client_contract_version") != CODEX_CLIENT_CONTRACT_VERSION
        or item.get("role") != CODEX_CLIENT_ROLE
        or item.get("package_version") != install_receipt.get("package_version")
    ):
        _fail("Codex client skill binding identity is invalid")
    package_resource = item["package_resource"]
    if (
        not isinstance(package_resource, Mapping)
        or set(package_resource) != _CLIENT_SKILL_PACKAGE_RESOURCE_FIELDS
        or package_resource.get("relative_path") != CODEX_CLIENT_SKILL_RESOURCE
    ):
        _fail("Codex client skill package resource binding is invalid")
    _absolute_receipt_path(
        package_resource.get("path"),
        "Codex client skill package resource path",
    )
    if package_resource["path"] != _receipt_join(
        str(install_receipt["package_root"]),
        CODEX_CLIENT_SKILL_RESOURCE,
    ):
        _fail("Codex client skill package resource path differs from package root")
    package_sha = _digest(
        package_resource.get("record_sha256"),
        "Codex client skill package resource SHA-256",
    )
    installed = item["installed_skill"]
    if (
        not isinstance(installed, Mapping)
        or set(installed) != _CLIENT_SKILL_INSTALLED_FIELDS
    ):
        _fail("Codex installed client skill binding is invalid")
    _absolute_receipt_path(
        installed.get("path"),
        "Codex installed client skill path",
    )
    if (
        _digest(
            installed.get("expected_sha256"),
            "Codex installed client skill expected SHA-256",
        )
        != package_sha
    ):
        _fail("Codex installed client skill digest differs from package resource")
    return item


def _validate_codex_hook_runtime_binding(
    binding: object,
    install_receipt: Mapping[str, Any],
) -> dict[str, object]:
    if not isinstance(binding, Mapping) or set(binding) != _HOOK_RUNTIME_BINDING_FIELDS:
        _fail("Codex hook runtime binding schema is invalid")
    item = dict(binding)
    if (
        item.get("contract_version") != CODEX_HOOK_RUNTIME_CONTRACT_VERSION
        or item.get("kind") != CODEX_HOOK_RUNTIME_KIND
        or item.get("module") != CODEX_HOOK_RUNTIME_MODULE
        or item.get("trust_class") != CODEX_HOOK_RUNTIME_TRUST_CLASS
        or item.get("argv_prefix") != list(CODEX_HOOK_RUNTIME_ARGV_PREFIX)
    ):
        _fail("Codex hook runtime binding identity is invalid")
    for field in (
        "python_invocation", "python_resolved_path", "venv_prefix",
        "module_path",
    ):
        _absolute_receipt_path(item.get(field), f"Codex hook runtime {field}")
    for field in ("python_resolved_sha256", "module_record_sha256"):
        _digest(item.get(field), f"Codex hook runtime {field}")
    if not isinstance(item.get("python_cache_tag"), str) or not item["python_cache_tag"]:
        _fail("Codex hook runtime cache tag is invalid")
    expected_module = _receipt_join(str(install_receipt["package_root"]), "codex_hook.py")
    if item["module_path"] != expected_module:
        _fail("Codex hook runtime module path differs from package root")
    return item


def _validate_v3_codex_install_provenance_receipt(
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    item = dict(receipt)
    install_receipt = _v3_install_receipt(item)
    _validate_codex_client_skill_binding(
        item.get("codex_client_skill"), install_receipt
    )
    _validate_codex_hook_runtime_binding(
        item.get("codex_hook_runtime"), install_receipt
    )
    receipt_digest = _digest(
        item.get("provenance_receipt_sha256"),
        "provenance receipt SHA-256",
    )
    base = dict(item)
    base.pop("provenance_receipt_sha256")
    try:
        if canonical_sha256(base, max_bytes=64 * 1024) != receipt_digest:
            _fail("Codex client binding provenance receipt digest is invalid")
    except SemanticEventError as exc:
        _fail("Codex client binding provenance receipt is not canonical", exc)
    return item


def validate_codex_install_provenance_receipt(
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one sealed receipt without trusting its recorded live paths."""

    if (
        isinstance(receipt, Mapping)
        and receipt.get("schema_version")
        == CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION
    ):
        return _validate_v3_codex_install_provenance_receipt(receipt)
    if (
        isinstance(receipt, Mapping)
        and receipt.get("schema_version")
        == _LOCAL_INSTALL_PROVENANCE_SCHEMA_VERSION
    ):
        return _validate_local_install_provenance_receipt(receipt)
    item = dict(receipt) if isinstance(receipt, Mapping) else {}
    if (
        not isinstance(item, dict)
        or (
            set(item) != _RECEIPT_FIELDS
            and set(item) != _RECEIPT_FIELDS_WITH_INSTALL_MAPPING
        )
        or item.get("schema_version")
        != _PROMOTED_INSTALL_PROVENANCE_SCHEMA_VERSION
    ):
        _fail("Codex install provenance receipt schema is invalid")
    for field in ("distribution_name", "package_version", "metadata_path", "package_root"):
        if not isinstance(item.get(field), str) or not item[field]:
            _fail("Codex install provenance receipt identity is invalid")
    _digest(item["promotion_bundle_sha256"], "promotion bundle SHA-256")
    _digest(item["installed_metadata_sha256"], "installed METADATA SHA-256")
    if not isinstance(item["hook_protocol_version"], int) or isinstance(item["hook_protocol_version"], bool) or item["hook_protocol_version"] < 1:
        _fail("Codex install provenance receipt hook protocol is invalid")
    for field in ("console_entry_point", "codex_hook_entry_point"):
        entry = item[field]
        if not isinstance(entry, Mapping) or set(entry) != _ENTRY_RECEIPT_FIELDS:
            _fail("Codex install provenance receipt entry point is invalid")
        if not all(isinstance(entry.get(key), str) and entry[key] for key in ("name", "target", "path")):
            _fail("Codex install provenance receipt entry point is invalid")
        _digest(entry["record_sha256"], "entry point RECORD SHA-256")
    script = item["codex_hook_generated_script"]
    if not isinstance(script, Mapping) or set(script) != _SCRIPT_RECEIPT_FIELDS:
        _fail("Codex install provenance receipt generated script is invalid")
    if not (
        (script.get("path") is None or isinstance(script.get("path"), str))
        and (script.get("record_sha256") is None or isinstance(script.get("record_sha256"), str))
    ):
        _fail("Codex install provenance receipt generated script is invalid")
    if (script["path"] is None) != (script["record_sha256"] is None):
        _fail("Codex install provenance receipt generated script is invalid")
    if script["path"] is not None:
        _digest(script["record_sha256"], "generated script RECORD SHA-256")
    package_manifest = item["package_runtime_manifest"]
    if (
        not isinstance(package_manifest, Mapping)
        or set(package_manifest) != _PACKAGE_MANIFEST_RECEIPT_FIELDS
        or not isinstance(package_manifest.get("count"), int)
        or isinstance(package_manifest["count"], bool)
        or not 0 < package_manifest["count"] <= _MAX_PACKAGE_RUNTIME_FILES
    ):
        _fail("Codex install provenance receipt package manifest is invalid")
    _digest(package_manifest.get("sha256"), "package manifest SHA-256")
    has_mapping = set(item) == _RECEIPT_FIELDS_WITH_INSTALL_MAPPING
    if has_mapping:
        wheel = item["promotion_wheel_artifact"]
        if not isinstance(wheel, Mapping) or set(wheel) != _WHEEL_ARTIFACT_FIELDS or not isinstance(wheel.get("name"), str) or not wheel["name"]:
            _fail("Codex install provenance receipt promotion wheel is invalid")
        _digest(wheel["sha256"], "promotion wheel artifact SHA-256")
        identity = item["installed_distribution_identity"]
        if not isinstance(identity, Mapping) or set(identity) != _DISTRIBUTION_IDENTITY_FIELDS or not all(isinstance(identity.get(key), str) and identity[key] for key in ("name", "version")):
            _fail("Codex install provenance receipt installed distribution identity is invalid")
        if identity["name"] != item["distribution_name"] or identity["version"] != item["package_version"]:
            _fail("Codex install provenance receipt distribution identity differs from receipt")
        if _digest(identity["metadata_sha256"], "installed distribution metadata SHA-256") != item["installed_metadata_sha256"]:
            _fail("Codex install provenance receipt distribution metadata identity differs from receipt")
        if item["installed_mapping_strength"] not in _INSTALLED_MAPPING_STRENGTHS:
            _fail("Codex install provenance receipt installed mapping strength is invalid")
        evidence = item["installed_mapping_evidence"]
        if not isinstance(evidence, Mapping) or set(evidence) != _MAPPING_EVIDENCE_FIELDS:
            _fail("Codex install provenance receipt installed mapping evidence is invalid")
        for name in ("installer", "direct_url"):
            entry = evidence[name]
            fields = _MAPPING_FILE_FIELDS if name == "installer" else _DIRECT_URL_EVIDENCE_FIELDS
            if entry is not None and (not isinstance(entry, Mapping) or set(entry) != fields):
                _fail("Codex install provenance receipt installed mapping evidence is invalid")
            if entry is not None:
                if not all(isinstance(entry.get(key), str) and entry[key] for key in ("path", "record_sha256")):
                    _fail("Codex install provenance receipt installed mapping evidence is invalid")
                _digest(entry["record_sha256"], "installed mapping RECORD SHA-256")
                if name == "direct_url":
                    if entry["archive_sha256"] is not None:
                        _digest(entry["archive_sha256"], "direct_url archive SHA-256")
        direct = evidence["direct_url"]
        installer = evidence["installer"]
        if item["installed_mapping_strength"] == "direct_url_archive_sha256":
            if not isinstance(direct, Mapping) or direct["archive_sha256"] != wheel["sha256"]:
                _fail("Codex install provenance receipt direct_url mapping is invalid")
        elif item["installed_mapping_strength"] == "record_package_and_installer" and installer is None:
            _fail("Codex install provenance receipt installer mapping is invalid")
    receipt_digest = _digest(item["provenance_receipt_sha256"], "provenance receipt SHA-256")
    base = dict(item); base.pop("provenance_receipt_sha256")
    try:
        if canonical_sha256(base, max_bytes=64 * 1024) != receipt_digest:
            _fail("Codex install provenance receipt digest is invalid")
    except SemanticEventError as exc:
        _fail("Codex install provenance receipt is not canonical", exc)
    return item


def _recorded_codex_client_skill(
    receipt: Mapping[str, Any],
) -> tuple[Path, str, bytes]:
    """Read the exact wheel-RECORD-bound Codex skill from the installed package."""

    validated = validate_codex_install_provenance_receipt(receipt)
    install_receipt = (
        _v3_install_receipt(validated)
        if validated["schema_version"] == CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION
        else validated
    )
    package_root = _canonical_existing(
        install_receipt["package_root"],
        "recorded runtime package root",
        directory=True,
    )
    metadata_path = _canonical_existing(
        install_receipt["metadata_path"],
        "recorded installed METADATA",
    )
    dist_info = _canonical_existing(
        metadata_path.parent,
        "recorded distribution metadata directory",
        directory=True,
    )
    if metadata_path != dist_info / "METADATA":
        _fail("recorded installed METADATA path is invalid")
    site_root = _canonical_existing(
        dist_info.parent,
        "recorded distribution site root",
        directory=True,
    )
    if package_root.parent != site_root:
        _fail("recorded runtime package root is cross-site")
    record = _record(dist_info, site_root)
    if (
        _runtime_package_manifest(package_root, record)
        != install_receipt["package_runtime_manifest"]
    ):
        _fail("current runtime package manifest differs from install provenance")
    if _install_schema_version(install_receipt) == _LOCAL_INSTALL_PROVENANCE_SCHEMA_VERSION:
        proof = install_receipt["install_proof"]
        _bundle, contract, _bundle_path = _local_install_contract(
            proof["bundle_path"], proof["bundle_sha256"]
        )
        if install_receipt["install_wheel_artifact"] != contract["wheel"]:
            _fail("local proof wheel differs from install provenance")
        _verify_local_wheel_install_members(
            contract["wheel"], dist_info, site_root, package_root, record
        )
    resource_path = _canonical_existing(
        package_root.joinpath(*CODEX_CLIENT_SKILL_RESOURCE.split("/")),
        "packaged Codex client skill",
    )
    if resource_path.parent.parent != package_root / "resources":
        _fail("packaged Codex client skill path is invalid")
    resource_sha = _verify_recorded(
        resource_path, record, "packaged Codex client skill"
    )
    raw = _stable_read(resource_path, "packaged Codex client skill")
    if _sha256(raw) != resource_sha:
        _fail("packaged Codex client skill changed while being read")
    if validated["schema_version"] == CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION:
        binding = validated["codex_client_skill"]["package_resource"]
        if (
            binding["path"] != str(resource_path)
            or binding["record_sha256"] != resource_sha
        ):
            _fail("current packaged Codex client skill differs from binding")
    return resource_path, resource_sha, raw


def read_recorded_codex_client_skill(receipt: Mapping[str, Any]) -> str:
    """Return UTF-8 skill text only from the receipt's exact installed wheel."""

    _path, _sha, raw = _recorded_codex_client_skill(receipt)
    try:
        return raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        _fail("packaged Codex client skill is not UTF-8", exc)


def bind_codex_client_skill(
    receipt: Mapping[str, Any],
    installed_skill_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Seal schema v3 around one local-v2 install proof and preflighted target.

    The user-scope skill remains a presentation/client adapter.  This binding
    detects package/installed-byte drift; it does not grant runtime mutation
    authority and is intentionally not consulted by hook authorization.
    """

    validated = validate_codex_install_provenance_receipt(receipt)
    if _install_schema_version(validated) != _LOCAL_INSTALL_PROVENANCE_SCHEMA_VERSION:
        _fail(
            "current schema-v3 Codex hook binding requires local-v2 exact-wheel proof"
        )
    installed_path_text = _absolute_receipt_path(
        str(installed_skill_path),
        "Codex installed client skill path",
    )
    installed_path = Path(installed_path_text)
    try:
        canonical_installed_path = canonicalize_no_link_traversal(
            installed_path, "Codex installed client skill target"
        )
    except HarnessError as exc:
        _fail("cannot inspect Codex installed client skill target", exc)
    if canonical_installed_path != installed_path:
        _fail("Codex installed client skill target is not canonical")
    resource_path, resource_sha, _raw = _recorded_codex_client_skill(validated)
    # Do this only after the package/RECORD (and, for v2, exact wheel) checks
    # above.  The hook's v3 authority is the isolated Python/module identity;
    # pip's generated launcher is retained below as compatibility evidence.
    install_receipt = (
        _v3_install_receipt(validated)
        if validated["schema_version"] == CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION
        else validated
    )
    prefix = _canonical_existing(
        sys.prefix, "active Python prefix", directory=True
    )
    metadata_path = _canonical_existing(
        install_receipt["metadata_path"], "recorded installed METADATA"
    )
    dist_info = _canonical_existing(
        metadata_path.parent, "recorded distribution metadata directory",
        directory=True,
    )
    site_root = _canonical_existing(
        dist_info.parent, "recorded distribution site root", directory=True
    )
    package_root = _canonical_existing(
        install_receipt["package_root"], "recorded runtime package root",
        directory=True,
    )
    _require_dedicated_venv(prefix, site_root)
    _under(package_root, prefix, "recorded runtime package")
    if package_root.parent != site_root:
        _fail("recorded runtime package root is cross-site")
    runtime_binding = _codex_hook_runtime_binding(
        prefix, package_root, _record(dist_info, site_root)
    )
    if validated["schema_version"] == CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION:
        installed = validated["codex_client_skill"]["installed_skill"]
        if installed["path"] != installed_path_text:
            _fail("Codex installed client skill path differs from existing binding")
        if validated["codex_hook_runtime"] != runtime_binding:
            _fail("current Codex hook Python/module runtime differs from existing binding")
        return validated

    install_schema = _install_schema_version(validated)
    install_digest = validated["provenance_receipt_sha256"]
    base = dict(validated)
    base["schema_version"] = CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION
    base["install_provenance_schema_version"] = install_schema
    base["install_provenance_receipt_sha256"] = install_digest
    base["codex_client_skill"] = {
        "provider": "codex",
        "client_contract_version": CODEX_CLIENT_CONTRACT_VERSION,
        "role": CODEX_CLIENT_ROLE,
        "package_version": validated["package_version"],
        "package_resource": {
            "relative_path": CODEX_CLIENT_SKILL_RESOURCE,
            "path": str(resource_path),
            "record_sha256": resource_sha,
        },
        "installed_skill": {
            "path": installed_path_text,
            "expected_sha256": resource_sha,
        },
    }
    base["codex_hook_runtime"] = runtime_binding
    base.pop("provenance_receipt_sha256")
    try:
        sealed = {
            **base,
            "provenance_receipt_sha256": canonical_sha256(
                base, max_bytes=64 * 1024
            ),
        }
    except SemanticEventError as exc:
        _fail("Codex client binding provenance receipt cannot be sealed", exc)
    return validate_codex_install_provenance_receipt(sealed)


def inspect_codex_client_skill(
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Classify the recorded user-scope client bytes without following links."""

    validated = validate_codex_install_provenance_receipt(receipt)
    if validated["schema_version"] != CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION:
        return {
            "status": "legacy_unbound",
            "provider": "codex",
            "client_contract_version": None,
            "role": None,
            "package_version": validated["package_version"],
            "package_resource_path": None,
            "installed_path": None,
            "expected_sha256": None,
            "actual_sha256": None,
            "reason": "receipt_schema_v1_or_v2_has_no_client_binding",
        }
    binding = validated["codex_client_skill"]
    package_resource = binding["package_resource"]
    installed = binding["installed_skill"]
    report: dict[str, Any] = {
        "status": "uninspectable",
        "provider": binding["provider"],
        "client_contract_version": binding["client_contract_version"],
        "role": binding["role"],
        "package_version": binding["package_version"],
        "package_resource_path": package_resource["path"],
        "installed_path": installed["path"],
        "expected_sha256": installed["expected_sha256"],
        "actual_sha256": None,
        "reason": None,
    }
    try:
        _recorded_codex_client_skill(validated)
    except CodexInstallProvenanceError as exc:
        report["reason"] = (
            "packaged_skill_provenance_uninspectable:"
            f"{type(exc).__name__}"
        )
        return report
    path = Path(installed["path"])
    try:
        canonical_parent = canonicalize_no_link_traversal(
            path.parent, "Codex installed client skill parent"
        )
    except HarnessError as exc:
        report["reason"] = f"installed_skill_path_uninspectable:{type(exc).__name__}"
        return report
    if canonical_parent != path.parent:
        report["reason"] = "installed_skill_path_is_not_canonical"
        return report
    try:
        info = path.lstat()
    except FileNotFoundError:
        report["status"] = "missing"
        report["reason"] = "installed_skill_path_missing"
        return report
    except OSError as exc:
        report["reason"] = f"installed_skill_lstat_failed:{type(exc).__name__}"
        return report
    if stat.S_ISLNK(info.st_mode) or path.is_symlink():
        report["reason"] = "installed_skill_is_link"
        return report
    if not stat.S_ISREG(info.st_mode):
        report["reason"] = "installed_skill_is_not_regular_file"
        return report
    try:
        canonical = canonicalize_no_link_traversal(
            path, "Codex installed client skill"
        )
        if canonical != path:
            report["reason"] = "installed_skill_path_is_not_canonical"
            return report
        raw = _stable_read(path, "Codex installed client skill")
    except (HarnessError, CodexInstallProvenanceError, OSError) as exc:
        report["reason"] = f"installed_skill_read_failed:{type(exc).__name__}"
        return report
    actual = _sha256(raw)
    report["actual_sha256"] = actual
    if actual == installed["expected_sha256"]:
        report["status"] = "exact"
        report["reason"] = None
    else:
        report["status"] = "drifted"
        report["reason"] = "installed_skill_sha256_mismatch"
    return report


def load_codex_install_provenance_receipt(
    project_root: str | os.PathLike[str],
) -> dict[str, Any]:
    """Read one exact canonical project receipt without checking launcher liveness."""

    root = _canonical_existing(project_root, "project root", directory=True)
    receipt_path = _canonical_existing(
        root / CODEX_INSTALL_PROVENANCE_RECEIPT,
        "Codex install provenance receipt",
    )
    raw = _stable_read(receipt_path, "Codex install provenance receipt")
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail("Codex install provenance receipt is not UTF-8 JSON", exc)
    item = validate_codex_install_provenance_receipt(decoded)
    try:
        if canonical_json_bytes(item, max_bytes=64 * 1024) != raw:
            _fail("Codex install provenance receipt is not exact canonical JSON")
    except SemanticEventError as exc:
        _fail("Codex install provenance receipt is not canonical", exc)
    return item


def verify_runtime_hook_provenance(
    project_root: str | os.PathLike[str],
    expected_provenance_sha256: str,
    invoked_hook: str | os.PathLike[str] | None = None,
    *,
    runtime_python: str | os.PathLike[str] | None = None,
    runtime_module_path: str | os.PathLike[str] | None = None,
    runtime_argv_prefix: tuple[str, ...] | list[str] | None = None,
) -> dict[str, Any]:
    """Recheck the exact persisted receipt against the installed wheel bytes.

    This is cooperative byte-drift detection after Python has started; it is not
    a pre-import or same-user process-isolation security boundary.  v1/v2
    retain their legacy pip-launcher identity.  v3 requires the explicit
    isolated-Python/module identity and treats the launcher as convenience
    evidence only, never as hook authority.
    """

    item = load_codex_install_provenance_receipt(project_root)
    install_schema = _install_schema_version(item)
    is_current_v3 = item["schema_version"] == CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION
    receipt_digest = item["provenance_receipt_sha256"]
    if receipt_digest != _digest(expected_provenance_sha256, "expected provenance receipt SHA-256"):
        _fail("provenance receipt differs from trusted expected SHA-256")
    hook: Mapping[str, Any] | None = None
    named: Path | None = None
    if not is_current_v3:
        hook = item["codex_hook_entry_point"]
        if not isinstance(hook, Mapping) or set(hook) != _ENTRY_RECEIPT_FIELDS or hook.get("target") != _AOI_HOOK_TARGET:
            _fail("Codex hook receipt entry is invalid")
        named = _canonical_existing(hook["path"], "recorded Codex hook launcher")
        _require_executable(named, "recorded Codex hook launcher")
        if invoked_hook is None or _canonical_existing(invoked_hook, "invoked Codex hook") != named:
            _fail("invoked Codex hook is not the recorded launcher")
    metadata_path = _canonical_existing(item["metadata_path"], "recorded installed METADATA")
    dist_info = _canonical_existing(metadata_path.parent, "recorded distribution metadata directory", directory=True)
    if metadata_path != dist_info / "METADATA":
        _fail("recorded installed METADATA path is invalid")
    site_root = _canonical_existing(dist_info.parent, "recorded distribution site root", directory=True)
    package_root = _canonical_existing(item["package_root"], "recorded runtime package root", directory=True)
    prefix = _canonical_existing(sys.prefix, "active Python prefix", directory=True)
    _require_dedicated_venv(prefix, site_root)
    _under(dist_info, prefix, "recorded distribution metadata")
    _under(site_root, prefix, "recorded distribution site root")
    if package_root.parent != site_root:
        _fail("recorded runtime package root is cross-site")
    record_path = _canonical_existing(dist_info / "RECORD", "recorded wheel RECORD")
    record = _record(dist_info, site_root)
    if _verify_recorded(metadata_path, record, "recorded installed METADATA") != item["installed_metadata_sha256"]:
        _fail("current installed METADATA bytes differ from provenance receipt")
    if _runtime_package_manifest(package_root, record) != item["package_runtime_manifest"]:
        _fail("current runtime package manifest differs from provenance receipt")
    if is_current_v3:
        _verify_v3_hook_runtime_binding(
            item["codex_hook_runtime"], prefix, package_root, record,
            runtime_python=runtime_python,
            runtime_module_path=runtime_module_path,
            runtime_argv_prefix=runtime_argv_prefix,
        )
        package_resource = item["codex_client_skill"]["package_resource"]
        expected_resource_path = package_root.joinpath(
            *CODEX_CLIENT_SKILL_RESOURCE.split("/")
        )
        recorded_resource_path = _canonical_existing(
            package_resource["path"], "recorded packaged Codex client skill"
        )
        if (
            recorded_resource_path != expected_resource_path
            or package_resource["relative_path"] != CODEX_CLIENT_SKILL_RESOURCE
        ):
            _fail("recorded packaged Codex client skill path is invalid")
        if _verify_recorded(
            recorded_resource_path,
            record,
            "recorded packaged Codex client skill",
        ) != _digest(
            package_resource["record_sha256"],
            "recorded packaged Codex client skill SHA-256",
        ):
            _fail("current packaged Codex client skill differs from provenance receipt")
    if not is_current_v3:
        assert named is not None and hook is not None
        if _verify_recorded(named, record, "recorded Codex hook launcher") != _digest(hook["record_sha256"], "recorded hook SHA-256"):
            _fail("current Codex hook launcher differs from provenance receipt")
    bridge: Mapping[str, Any] | None = None
    bridge_named: Path | None = None
    if not is_current_v3 and install_schema == _LOCAL_INSTALL_PROVENANCE_SCHEMA_VERSION:
        bridge = item["codex_bridge_entry_point"]
        bridge_named = _canonical_existing(
            bridge["path"], "recorded Codex bridge launcher"
        )
        _require_executable(bridge_named, "recorded Codex bridge launcher")
        if _verify_recorded(
            bridge_named, record, "recorded Codex bridge launcher"
        ) != _digest(bridge["record_sha256"], "recorded bridge SHA-256"):
            _fail("current Codex bridge launcher differs from provenance receipt")
    script = item["codex_hook_generated_script"]
    if not is_current_v3 and script["path"] is not None:
        assert named is not None and hook is not None
        script_path = _canonical_existing(script["path"], "recorded Codex hook generated script")
        if script_path.parent != named.parent or script_path.name != f"{hook['name']}-script.py":
            _fail("recorded Codex hook generated script path is invalid")
        if _generated_script(script_path, hook["target"], record, "Codex hook launcher") != _digest(script["record_sha256"], "recorded generated script SHA-256"):
            _fail("current Codex hook generated script differs from provenance receipt")
    if install_schema == _LOCAL_INSTALL_PROVENANCE_SCHEMA_VERSION:
        if not is_current_v3:
            if bridge is None or bridge_named is None:
                _fail("local Codex bridge receipt entry is unavailable")
            bridge_script = item["codex_bridge_generated_script"]
            if bridge_script["path"] is not None:
                bridge_script_path = _canonical_existing(
                    bridge_script["path"], "recorded Codex bridge generated script"
                )
                if (
                    bridge_script_path.parent != bridge_named.parent
                    or bridge_script_path.name != f"{bridge['name']}-script.py"
                ):
                    _fail("recorded Codex bridge generated script path is invalid")
                if _generated_script(
                    bridge_script_path,
                    bridge["target"],
                    record,
                    "Codex bridge launcher",
                ) != _digest(
                    bridge_script["record_sha256"],
                    "recorded bridge generated script SHA-256",
                ):
                    _fail(
                        "current Codex bridge generated script differs from provenance receipt"
                    )
        proof = item["install_proof"]
        _bundle, contract, bundle_path = _local_install_contract(
            proof["bundle_path"], proof["bundle_sha256"]
        )
        expected_proof = {
            "kind": "reviewed_local_install_bundle",
            "proof_scope": "exact_local_wheel_install_only",
            "bundle_path": str(bundle_path),
            "bundle_sha256": contract["bundle_sha256"],
            "artifact_store_root": contract["artifact_store_root"],
            "source_commit_oid": contract["source_commit_oid"],
            "source_tree_oid": contract["source_tree_oid"],
            "source_manifest_sha256": contract["source_manifest_sha256"],
            "rehearsal_report_sha256": contract["rehearsal_report_sha256"],
            "inventory_sha256": contract["inventory_sha256"],
        }
        if dict(proof) != expected_proof:
            _fail("local installation proof differs from provenance receipt")
        if item["install_wheel_artifact"] != contract["wheel"]:
            _fail("local proof wheel differs from provenance receipt")
        if not is_current_v3:
            if item["installed_record"]["path"] != str(record_path):
                _fail("recorded wheel RECORD path differs from provenance receipt")
            if _sha256(_stable_read(record_path, "recorded wheel RECORD")) != item["installed_record"]["sha256"]:
                _fail("current wheel RECORD differs from provenance receipt")
        evidence = _local_installed_mapping_evidence(dist_info, record, contract["wheel"])
        if evidence != item["installed_mapping_evidence"]:
            _fail("current local installed wheel mapping differs from provenance receipt")
        _verify_local_wheel_install_members(
            contract["wheel"], dist_info, site_root, package_root, record
        )
    install_receipt = (
        _v3_install_receipt(item)
        if item["schema_version"] == CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION
        else item
    )
    if set(install_receipt) == _RECEIPT_FIELDS_WITH_INSTALL_MAPPING:
        promotion_wheel = item["promotion_wheel_artifact"]
        mapping_strength, mapping_evidence = _installed_mapping_evidence(
            dist_info, record, promotion_wheel
        )
        if (
            mapping_strength != item["installed_mapping_strength"]
            or mapping_evidence != item["installed_mapping_evidence"]
        ):
            _fail("current installed wheel mapping differs from provenance receipt")
    # Every accepted receipt, including mapping-less schema-v1 receipts, must
    # reject executable .pth files before trusting the installed runtime.
    _reject_pth_shadows(site_root, package_root)
    return item


__all__ = [
    "CODEX_CLIENT_CONTRACT_VERSION", "CODEX_CLIENT_ROLE",
    "CODEX_CLIENT_SKILL_RESOURCE",
    "CODEX_HOOK_RUNTIME_ARGV_PREFIX", "CODEX_HOOK_RUNTIME_CONTRACT_VERSION",
    "CODEX_HOOK_RUNTIME_KIND", "CODEX_HOOK_RUNTIME_MODULE",
    "CODEX_HOOK_RUNTIME_TRUST_CLASS",
    "CODEX_INSTALL_PROVENANCE_RECEIPT", "CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION",
    "CodexInstallProvenanceError", "bind_codex_client_skill",
    "inspect_codex_client_skill", "load_codex_install_provenance_receipt",
    "read_recorded_codex_client_skill",
    "validate_codex_install_provenance", "validate_codex_local_install_provenance",
    "validate_codex_install_provenance_receipt",
    "verify_runtime_hook_provenance",
]
