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
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from typing import Any, NoReturn
from urllib.parse import unquote, urlsplit

from . import release_runtime
from .harnesslib import HarnessError, canonicalize_no_link_traversal
from .semantic_events import SemanticEventError, canonical_json_bytes, canonical_sha256


CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION = 1
CODEX_INSTALL_PROVENANCE_RECEIPT = ".aoi/codex-install-provenance-v1.json"
_MAX_FILE_BYTES = 4 * 1024 * 1024
_MAX_PACKAGE_RUNTIME_FILES = 1024
_MAX_PACKAGE_RUNTIME_MANIFEST_BYTES = 64 * 1024
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
    "console_entry_point", "codex_hook_entry_point",
    "codex_hook_generated_script", "package_runtime_manifest",
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
_INSTALLED_MAPPING_STRENGTHS = frozenset({
    "direct_url_archive_sha256", "record_package_and_installer",
    "record_package_only",
})
_AOI_CONSOLE_TARGET = "aoi_orgware.cli:main"
_AOI_HOOK_TARGET = "aoi_orgware.codex_hook:main"


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
    if invoked is not None and _canonical_existing(invoked, f"invoked {label}") != checked:
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
        "schema_version": CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION,
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
        "installed_metadata_sha256", "console_entry_point", "codex_hook_entry_point", "hook_protocol_version",
    }:
        _fail("local installation bundle interface contract is invalid")
    _digest(interfaces.get("installed_metadata_sha256"), "local installation METADATA SHA-256")
    for field, target in (("console_entry_point", _AOI_CONSOLE_TARGET), ("codex_hook_entry_point", _AOI_HOOK_TARGET)):
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
    _under(dist_info, prefix, "distribution metadata")
    _under(site_root, prefix, "distribution site root")
    record_path = _canonical_existing(dist_info / "RECORD", "wheel RECORD")
    installed_record_sha = _sha256(_stable_read(record_path, "wheel RECORD"))
    record = _record(dist_info, site_root)
    metadata_path = _canonical_existing(dist_info / "METADATA", "installed METADATA")
    metadata_sha = _verify_recorded(metadata_path, record, "installed METADATA")
    if metadata_sha != interfaces["installed_metadata_sha256"]:
        _fail("installed METADATA digest differs from local proof interface")
    console, hook = interfaces["console_entry_point"], interfaces["codex_hook_entry_point"]
    _entry_point(dist, console["name"], console["target"], "console")
    _entry_point(dist, hook["name"], hook["target"], "Codex hook")
    package = importlib.import_module("aoi_orgware")
    version_module = importlib.import_module("aoi_orgware._version")
    cli_module = importlib.import_module("aoi_orgware.cli")
    hook_module = importlib.import_module("aoi_orgware.codex_hook")
    if package.__file__ is None:
        _fail("runtime package has no file")
    package_root = _canonical_existing(Path(package.__file__).parent, "runtime package root", directory=True)
    if package_root.parent != site_root:
        _fail("runtime package is source-checkout or cross-site shadowed")
    _under(package_root, prefix, "runtime package")
    _verify_recorded(package_root / "__init__.py", record, "runtime package initializer")
    for module, relative, label in ((version_module, "_version.py", "runtime version module"), (cli_module, "cli.py", "runtime CLI module"), (hook_module, "codex_hook.py", "runtime hook module")):
        module_file = module.__file__
        if module_file is None or _canonical_existing(module_file, label) != package_root / relative:
            _fail(f"{label} is package-shadowed")
        _verify_recorded(package_root / relative, record, label)
    if package.__version__ != contract["package_version"] or version_module.__version__ != contract["package_version"]:
        _fail("runtime __version__ differs from local proof package version")
    evidence = _local_installed_mapping_evidence(dist_info, record, contract["wheel"])
    _reject_pth_shadows(site_root, package_root)
    package_manifest = _runtime_package_manifest(package_root, record)
    console_path, console_sha, _console_script, _console_script_sha = _launcher(prefix, console["name"], console["target"], invoked_console, record, "console launcher")
    hook_path, hook_sha, hook_script, hook_script_sha = _launcher(prefix, hook["name"], hook["target"], None, record, "Codex hook launcher")
    _under(console_path, prefix, "console launcher")
    _under(hook_path, prefix, "Codex hook launcher")
    base = {
        "schema_version": 2,
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
    if set(item) != _LOCAL_RECEIPT_FIELDS or item.get("schema_version") != 2:
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
    for field, target in (("console_entry_point", _AOI_CONSOLE_TARGET), ("codex_hook_entry_point", _AOI_HOOK_TARGET)):
        entry = item[field]
        if not isinstance(entry, Mapping) or set(entry) != _ENTRY_RECEIPT_FIELDS:
            _fail("local Codex install provenance receipt entry point is invalid")
        if not all(isinstance(entry.get(key), str) and entry[key] for key in ("name", "target", "path")) or entry["target"] != target:
            _fail("local Codex install provenance receipt entry point is invalid")
        _absolute_receipt_path(entry["path"], f"local install receipt {field} path")
        _digest(entry["record_sha256"], "entry point RECORD SHA-256")
    script = item["codex_hook_generated_script"]
    if not isinstance(script, Mapping) or set(script) != _SCRIPT_RECEIPT_FIELDS or (script.get("path") is None) != (script.get("record_sha256") is None):
        _fail("local Codex install provenance receipt generated script is invalid")
    if script["path"] is not None:
        if not isinstance(script["path"], str) or not script["path"]:
            _fail("local Codex install provenance receipt generated script is invalid")
        _absolute_receipt_path(script["path"], "local install receipt generated script path")
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


def validate_codex_install_provenance_receipt(
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one sealed receipt without trusting its recorded live paths."""

    if isinstance(receipt, Mapping) and receipt.get("schema_version") == 2:
        return _validate_local_install_provenance_receipt(receipt)
    item = dict(receipt) if isinstance(receipt, Mapping) else {}
    if (
        not isinstance(item, dict)
        or (
            set(item) != _RECEIPT_FIELDS
            and set(item) != _RECEIPT_FIELDS_WITH_INSTALL_MAPPING
        )
        or item.get("schema_version") != CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION
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


def verify_runtime_hook_provenance(project_root: str | os.PathLike[str], expected_provenance_sha256: str, invoked_hook: str | os.PathLike[str]) -> dict[str, Any]:
    """Recheck the exact persisted receipt against the installed wheel bytes.

    This is cooperative byte-drift detection after Python has started; it is not
    a pre-import or process-isolation security boundary.
    """

    item = load_codex_install_provenance_receipt(project_root)
    receipt_digest = item["provenance_receipt_sha256"]
    if receipt_digest != _digest(expected_provenance_sha256, "expected provenance receipt SHA-256"):
        _fail("provenance receipt differs from trusted expected SHA-256")
    hook = item["codex_hook_entry_point"]
    if not isinstance(hook, Mapping) or set(hook) != _ENTRY_RECEIPT_FIELDS or hook.get("target") != _AOI_HOOK_TARGET:
        _fail("Codex hook receipt entry is invalid")
    named = _canonical_existing(hook["path"], "recorded Codex hook launcher")
    _require_executable(named, "recorded Codex hook launcher")
    if _canonical_existing(invoked_hook, "invoked Codex hook") != named:
        _fail("invoked Codex hook is not the recorded launcher")
    metadata_path = _canonical_existing(item["metadata_path"], "recorded installed METADATA")
    dist_info = _canonical_existing(metadata_path.parent, "recorded distribution metadata directory", directory=True)
    if metadata_path != dist_info / "METADATA":
        _fail("recorded installed METADATA path is invalid")
    site_root = _canonical_existing(dist_info.parent, "recorded distribution site root", directory=True)
    package_root = _canonical_existing(item["package_root"], "recorded runtime package root", directory=True)
    if package_root.parent != site_root:
        _fail("recorded runtime package root is cross-site")
    record_path = _canonical_existing(dist_info / "RECORD", "recorded wheel RECORD")
    record = _record(dist_info, site_root)
    if _verify_recorded(metadata_path, record, "recorded installed METADATA") != item["installed_metadata_sha256"]:
        _fail("current installed METADATA bytes differ from provenance receipt")
    if _runtime_package_manifest(package_root, record) != item["package_runtime_manifest"]:
        _fail("current runtime package manifest differs from provenance receipt")
    if _verify_recorded(named, record, "recorded Codex hook launcher") != _digest(hook["record_sha256"], "recorded hook SHA-256"):
        _fail("current Codex hook launcher differs from provenance receipt")
    script = item["codex_hook_generated_script"]
    if script["path"] is not None:
        script_path = _canonical_existing(script["path"], "recorded Codex hook generated script")
        if script_path.parent != named.parent or script_path.name != f"{hook['name']}-script.py":
            _fail("recorded Codex hook generated script path is invalid")
        if _generated_script(script_path, hook["target"], record, "Codex hook launcher") != _digest(script["record_sha256"], "recorded generated script SHA-256"):
            _fail("current Codex hook generated script differs from provenance receipt")
    if item["schema_version"] == 2:
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
        if item["installed_record"]["path"] != str(record_path):
            _fail("recorded wheel RECORD path differs from provenance receipt")
        if _sha256(_stable_read(record_path, "recorded wheel RECORD")) != item["installed_record"]["sha256"]:
            _fail("current wheel RECORD differs from provenance receipt")
        evidence = _local_installed_mapping_evidence(dist_info, record, contract["wheel"])
        if evidence != item["installed_mapping_evidence"]:
            _fail("current local installed wheel mapping differs from provenance receipt")
        _reject_pth_shadows(site_root, package_root)
    if set(item) == _RECEIPT_FIELDS_WITH_INSTALL_MAPPING:
        promotion_wheel = item["promotion_wheel_artifact"]
        mapping_strength, mapping_evidence = _installed_mapping_evidence(
            dist_info, record, promotion_wheel
        )
        if (
            mapping_strength != item["installed_mapping_strength"]
            or mapping_evidence != item["installed_mapping_evidence"]
        ):
            _fail("current installed wheel mapping differs from provenance receipt")
        _reject_pth_shadows(site_root, package_root)
    return item


__all__ = [
    "CODEX_INSTALL_PROVENANCE_RECEIPT", "CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION",
    "CodexInstallProvenanceError", "load_codex_install_provenance_receipt",
    "validate_codex_install_provenance", "validate_codex_local_install_provenance",
    "validate_codex_install_provenance_receipt",
    "verify_runtime_hook_provenance",
]
