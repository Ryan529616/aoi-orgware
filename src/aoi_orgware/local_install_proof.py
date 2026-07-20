"""Bounded proof for an exact reviewed local wheel installation.

This is intentionally a local-artifact contract.  It performs no source-control
mutation and no package-registry action.  A sealed bundle proves only the exact
wheel stored at its bound absolute artifact-store path, not a publication.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import zipfile
from datetime import datetime
from io import BytesIO
from typing import Any, Mapping, NoReturn, Sequence


MAX_JSON_BYTES = 512 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_SOURCE_FILES = 100_000
MAX_ARTIFACTS = 2
MAX_LIMITATIONS = 32
MAX_TEXT = 2048
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_OID = {"sha1": re.compile(r"[0-9a-f]{40}\Z"), "sha256": re.compile(r"[0-9a-f]{64}\Z")}
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\Z")
_VERSION = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']\s*$', re.MULTILINE)
_HOOK = re.compile(r'^HOOK_PROTOCOL_VERSION\s*=\s*["\'](\d+)["\']\s*$', re.MULTILINE)
_SAFE_REL = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/@+-]{0,511}\Z")
_SAFE_REVIEWER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}\Z")


class LocalInstallProofError(ValueError):
    """A local-install proof input is malformed, unstable, or unbound."""


def _fail(message: str) -> NoReturn:
    raise LocalInstallProofError(message)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical(value: Any, *, limit: int = MAX_JSON_BYTES) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LocalInstallProofError(f"invalid JSON value: {exc}") from exc
    if len(raw) > limit:
        _fail("canonical JSON exceeds byte bound")
    return raw


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(dict(value))).hexdigest()


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(f"{label} has unexpected or missing fields")
    return dict(value)


def _text(value: Any, label: str, *, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(char) < 32 or ord(char) == 127 for char in value):
        _fail(f"{label} is invalid")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        _fail(f"{label} is not lowercase SHA-256")
    return value


def _timestamp(value: Any, label: str) -> str:
    value = _text(value, label, limit=27)
    if _UTC.fullmatch(value) is None:
        _fail(f"{label} is not canonical UTC time")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise LocalInstallProofError(f"{label} is not a real UTC time") from exc
    return value


def _safe_relative(value: Any, label: str) -> str:
    value = _text(value, label, limit=512)
    if value in {".", ".."} or "\\" in value or _SAFE_REL.fullmatch(value) is None:
        _fail(f"{label} is not a safe relative path")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or ".." in parsed.parts or str(parsed) != value:
        _fail(f"{label} is not a safe relative path")
    return value


def _is_link(stat_result: os.stat_result) -> bool:
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(stat_result.st_mode) or bool(getattr(stat_result, "st_file_attributes", 0) & reparse)


def _secure_directory(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    try:
        before = absolute.lstat(); resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise LocalInstallProofError(f"cannot inspect {label}: {exc}") from exc
    if _is_link(before) or not stat.S_ISDIR(before.st_mode) or os.path.normcase(str(absolute)) != os.path.normcase(str(resolved)):
        _fail(f"{label} must be a canonical non-linked directory")
    return absolute


def _stable_read(path: Path, *, label: str, limit: int = MAX_FILE_BYTES, allow_empty: bool = False) -> bytes:
    path = Path(os.path.abspath(path))
    try:
        before = path.lstat(); resolved = path.resolve(strict=True)
    except OSError as exc:
        raise LocalInstallProofError(f"cannot stat {label}: {exc}") from exc
    if _is_link(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or os.path.normcase(str(path)) != os.path.normcase(str(resolved)):
        _fail(f"{label} must be a non-linked regular file")
    if before.st_size > limit or (before.st_size < 1 and not allow_empty):
        _fail(f"{label} has invalid size")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            opened = os.fstat(handle.fileno())
            identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink)
            if identity != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_nlink):
                _fail(f"{label} changed while opening")
            raw = handle.read(limit + 1)
        after = path.lstat()
    except OSError as exc:
        raise LocalInstallProofError(f"cannot read {label}: {exc}") from exc
    if len(raw) > limit or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink):
        _fail(f"{label} changed while reading")
    return raw


def _under(root: Path, relative: str, label: str) -> Path:
    candidate = Path(os.path.abspath(root.joinpath(*PurePosixPath(relative).parts)))
    try:
        resolved = candidate.resolve(strict=True); resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise LocalInstallProofError(f"{label} escapes its root") from exc
    if os.path.normcase(str(candidate)) != os.path.normcase(str(resolved)):
        _fail(f"{label} traverses a link or alias")
    return candidate


def _read_json(path: Path, label: str, *, canonical: bool) -> tuple[bytes, dict[str, Any]]:
    raw = _stable_read(path, label=label, limit=MAX_JSON_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, LocalInstallProofError) as exc:
        raise LocalInstallProofError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        _fail(f"{label} JSON root must be an object")
    if canonical and raw != _canonical(value):
        _fail(f"{label} is not canonical JSON")
    return raw, value


def _git_raw(source_root: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(["git", "-C", str(source_root), *args], capture_output=True, check=False, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise LocalInstallProofError(f"cannot inspect Git source: {exc}") from exc
    if result.returncode != 0:
        _fail(f"Git inspection failed: {' '.join(args)}")
    return result.stdout


def _git(source_root: Path, *args: str) -> str:
    try:
        return _git_raw(source_root, *args).decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise LocalInstallProofError("Git inspection returned non-UTF-8 text") from exc


def _git_snapshot(source_root: Path) -> dict[str, Any]:
    source_root = _secure_directory(source_root, "source root")
    if _git(source_root, "status", "--porcelain=v1", "--untracked-files=all"):
        _fail("source Git worktree is not clean")
    object_format = _git(source_root, "rev-parse", "--show-object-format")
    if object_format not in _OID:
        _fail("source Git object format is unsupported")
    head = _git(source_root, "rev-parse", "HEAD").lower(); tree = _git(source_root, "rev-parse", "HEAD^{tree}").lower()
    if _OID[object_format].fullmatch(head) is None or _OID[object_format].fullmatch(tree) is None:
        _fail("source Git HEAD or tree is invalid")
    epoch = _git(source_root, "show", "-s", "--format=%ct", "HEAD")
    if not epoch.isascii() or not epoch.isdecimal() or int(epoch) < 0:
        _fail("source Git source_date_epoch is invalid")
    remote = _git(source_root, "remote", "get-url", "origin")
    if not remote or len(remote) > MAX_TEXT or any(ord(char) < 32 for char in remote):
        _fail("source Git origin remote is invalid")
    version_path = _under(source_root, "src/aoi_orgware/_version.py", "version source")
    try:
        version_text = _stable_read(version_path, label="version source", limit=64 * 1024).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LocalInstallProofError("version source is not UTF-8") from exc
    match = _VERSION.search(version_text)
    if match is None:
        _fail("source package version is unavailable")
    return {"git_object_format": object_format, "head": head, "tree": tree, "source_date_epoch": int(epoch), "remote": {"name": "origin", "url": remote}, "package_version": _text(match.group(1), "source package version", limit=128)}


def _assert_snapshot(source_root: Path, snapshot: Mapping[str, Any]) -> None:
    current = _git_snapshot(source_root)
    if any(current[key] != snapshot[key] for key in ("git_object_format", "head", "tree", "source_date_epoch", "remote", "package_version")):
        _fail("source Git identity changed during observation")


def _tracked_paths(source_root: Path) -> list[str]:
    raw = _git_raw(source_root, "ls-files", "-z")
    chunks = raw.split(b"\0")
    if chunks[-1] != b"" or len(chunks) - 1 > MAX_SOURCE_FILES:
        _fail("source Git tracked path set is invalid")
    result: list[str] = []
    for chunk in chunks[:-1]:
        try:
            path = chunk.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LocalInstallProofError("source Git path is not UTF-8") from exc
        result.append(_safe_relative(path, "source Git tracked path"))
    if result != sorted(result) or len(set(result)) != len(result):
        _fail("source Git tracked paths are not canonical")
    return result


def _git_blob(source_root: Path, relative: str) -> bytes:
    # The manifest grammar excludes ':' and option-like paths, so this revision
    # expression cannot be confused with a different object selector.
    return _git_raw(source_root, "cat-file", "blob", f"HEAD:{relative}")


def create_source_manifest(source_root: Path) -> dict[str, Any]:
    """Create a canonical manifest which proves all clean HEAD source bytes."""

    source_root = _secure_directory(source_root, "source root")
    snapshot = _git_snapshot(source_root); paths = _tracked_paths(source_root)
    files: list[dict[str, Any]] = []
    for relative in paths:
        live = _stable_read(_under(source_root, relative, "source file"), label=f"source file {relative}", allow_empty=True)
        committed = _git_blob(source_root, relative)
        if live != committed:
            _fail(f"source file differs from clean HEAD: {relative}")
        if len(live) > MAX_FILE_BYTES:
            _fail("source file exceeds byte bound")
        files.append({"path": relative, "size_bytes": len(live), "sha256": hashlib.sha256(live).hexdigest()})
    result = {"source_file_count": len(files), "files": files}
    _validate_source_manifest(result, source_root)
    _assert_snapshot(source_root, snapshot)
    return result


def create_rehearsal_report(*, source_root: Path, store_root: Path, inventory_path: str, producer_test_summary: str, source_manifest_path: str = "evidence/source-file-manifest.json", tool_lock_path: str = "requirements/release-tools.lock") -> dict[str, Any]:
    """Derive an honest cooperative review context from bound local bytes.

    ``producer_test_summary`` is caller-supplied context (for example,
    ``"42 passed, 3 skipped"``), not an execution receipt.  This function
    directly rechecks the clean source manifest and inventory artifact bytes;
    it deliberately makes no source-to-wheel, toolchain, or test-execution
    claim.
    """

    source_root = _secure_directory(source_root, "source root"); store_root = _secure_directory(store_root, "external store")
    _require_external_store(source_root, store_root)
    before = _git_snapshot(source_root)
    manifest_rel = _safe_relative(source_manifest_path, "source manifest evidence path")
    manifest_raw, manifest_value = _read_json(_under(store_root, manifest_rel, "source manifest evidence"), "source manifest evidence", canonical=True)
    manifest = _validate_source_manifest(manifest_value, source_root)
    lock_rel = _safe_relative(tool_lock_path, "tool lock path")
    lock_raw = _stable_read(_under(source_root, lock_rel, "tool lock"), label="tool lock", limit=256 * 1024)
    inventory_rel = _safe_relative(inventory_path, "inventory evidence path")
    _inventory_raw, inventory_value = _read_json(_under(store_root, inventory_rel, "inventory evidence"), "inventory evidence", canonical=True)
    inventory = _inventory(inventory_value, version=before["package_version"])
    _observe_artifacts(store_root, inventory)
    report = {
        "context": {"root": str(source_root), "source": "clean HEAD tracked files", "copied_files": [entry["path"] for entry in manifest["files"]], "source_head": before["head"], "source_date_epoch": before["source_date_epoch"], "version": before["package_version"]},
        "source_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "source_file_count": manifest["source_file_count"],
        "lock_sha256": hashlib.sha256(lock_raw).hexdigest(),
        "inventory": inventory["inventory_sha256"],
        "artifacts": inventory["artifacts"],
        "observations": {
            "source_manifest_current_bytes": "verified",
            "artifact_inventory_bytes": "verified",
            "producer_test_summary": producer_test_summary,
        },
        "limitations": [
            "producer_test_summary_is_caller_supplied_context",
            "source_identity_does_not_attest_source_to_wheel_derivation",
            "builder_toolchain_and_test_execution_are_not_attested",
        ],
    }
    _rehearsal(report, {**before, "source_manifest": {"path": manifest_rel, "raw_sha256": hashlib.sha256(manifest_raw).hexdigest(), "source_file_count": manifest["source_file_count"]}, "tool_lock": {"path": lock_rel, "raw_sha256": hashlib.sha256(lock_raw).hexdigest()}}, {"raw_sha256": hashlib.sha256(manifest_raw).hexdigest(), "source_file_count": manifest["source_file_count"]}, hashlib.sha256(lock_raw).hexdigest(), inventory)
    _assert_snapshot(source_root, before)
    return report


def _manifest_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    item = _object(value, {"source_file_count", "files"}, "source file manifest")
    count = item["source_file_count"]
    files = item["files"]
    if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= MAX_SOURCE_FILES or not isinstance(files, list) or len(files) != count:
        _fail("source file manifest count is invalid")
    normalized: list[dict[str, Any]] = []
    for entry in files:
        record = _object(entry, {"path", "size_bytes", "sha256"}, "source file manifest entry")
        path = _safe_relative(record["path"], "source file manifest path")
        size = record["size_bytes"]
        if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= MAX_FILE_BYTES:
            _fail("source file manifest size is invalid")
        normalized.append({"path": path, "size_bytes": size, "sha256": _sha(record["sha256"], "source file manifest sha256")})
    if [entry["path"] for entry in normalized] != sorted(entry["path"] for entry in normalized) or len({entry["path"] for entry in normalized}) != len(normalized):
        _fail("source file manifest paths are not canonical")
    return {"source_file_count": count, "files": normalized}


def _validate_source_manifest(value: Mapping[str, Any], source_root: Path) -> dict[str, Any]:
    item = _manifest_evidence(value)
    count = item["source_file_count"]; normalized = item["files"]
    paths = _tracked_paths(source_root)
    if count != len(paths):
        _fail("source file manifest count does not match clean HEAD")
    if [entry["path"] for entry in normalized] != paths:
        _fail("source file manifest path set does not exactly match clean HEAD")
    for entry in normalized:
        live = _stable_read(_under(source_root, entry["path"], "source file"), label=f"source file {entry['path']}", allow_empty=True)
        committed = _git_blob(source_root, entry["path"])
        if live != committed or len(live) != entry["size_bytes"] or hashlib.sha256(live).hexdigest() != entry["sha256"]:
            _fail(f"source file manifest bytes do not match clean HEAD: {entry['path']}")
    return item


def _artifact_name(value: Any, version: str) -> tuple[str, str]:
    name = _safe_relative(value, "artifact name")
    if "/" in name:
        _fail("artifact name must be a basename")
    normalized = name.replace("_", "-")
    if normalized.startswith(f"aoi-orgware-{version}-") and name.endswith(".whl"):
        return name, "wheel"
    if normalized == f"aoi-orgware-{version}.tar.gz":
        return name, "sdist"
    _fail("artifact name does not bind the source package version")


def _inventory(value: Mapping[str, Any], *, version: str) -> dict[str, Any]:
    item = _object(value, {"schema_version", "distribution_name", "package_version", "artifacts", "inventory_sha256"}, "inventory")
    if item["schema_version"] != 1 or item["distribution_name"] != "aoi-orgware" or item["package_version"] != version:
        _fail("inventory package identity does not bind source")
    artifacts = item["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != MAX_ARTIFACTS:
        _fail("inventory must contain exactly one wheel and one sdist")
    normalized: list[dict[str, Any]] = []; kinds: set[str] = set()
    for artifact in artifacts:
        entry = _object(artifact, {"name", "size_bytes", "sha256"}, "inventory artifact")
        name, kind = _artifact_name(entry["name"], version); size = entry["size_bytes"]
        if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= MAX_FILE_BYTES:
            _fail("inventory artifact size is invalid")
        normalized.append({"name": name, "size_bytes": size, "sha256": _sha(entry["sha256"], "inventory artifact sha256")}); kinds.add(kind)
    if kinds != {"wheel", "sdist"} or normalized != sorted(normalized, key=lambda entry: entry["name"]):
        _fail("inventory artifacts are not canonical")
    base = {key: item[key] for key in item if key != "inventory_sha256"}
    if _digest(base) != _sha(item["inventory_sha256"], "inventory sha256"):
        _fail("inventory SHA-256 does not match")
    return {**base, "inventory_sha256": item["inventory_sha256"]}


def _store_root(value: Any) -> Path:
    if not isinstance(value, str) or not os.path.isabs(value):
        _fail("artifact_store_root must be an absolute path")
    root = _secure_directory(Path(value), "artifact_store_root")
    if os.path.normcase(str(root)) != os.path.normcase(value):
        _fail("artifact_store_root is not canonical")
    return root


def _require_external_store(source_root: Path, store_root: Path) -> None:
    try:
        source_root.relative_to(store_root)
    except ValueError:
        pass
    else:
        _fail("external store must not contain source root")
    try:
        store_root.relative_to(source_root)
    except ValueError:
        pass
    else:
        _fail("external store must be outside source root")


def _observe_artifacts(store_root: Path, inventory: Mapping[str, Any]) -> tuple[list[dict[str, Any]], Path, bytes]:
    dist_root = _secure_directory(store_root / "dist", "external distribution directory")
    expected = {str(entry["name"]) for entry in inventory["artifacts"]}
    try:
        actual = {entry.name for entry in dist_root.iterdir()}
    except OSError as exc:
        raise LocalInstallProofError(f"cannot enumerate external distribution directory: {exc}") from exc
    if actual != expected:
        _fail("external distribution directory does not exactly match inventory")
    observed: list[dict[str, Any]] = []; wheel: Path | None = None; wheel_raw: bytes | None = None
    for artifact in inventory["artifacts"]:
        path = _under(store_root, f"dist/{artifact['name']}", "distribution artifact")
        raw = _stable_read(path, label=f"distribution artifact {artifact['name']}")
        if len(raw) != artifact["size_bytes"] or hashlib.sha256(raw).hexdigest() != artifact["sha256"]:
            _fail("distribution artifact bytes do not match inventory")
        observed.append({"path": f"dist/{artifact['name']}", **artifact})
        if artifact["name"].endswith(".whl"):
            wheel = path; wheel_raw = raw
    if wheel is None or wheel_raw is None:
        _fail("inventory lacks wheel")
    return observed, wheel, wheel_raw


def _wheel_interface(wheel_raw: bytes, *, version: str) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(BytesIO(wheel_raw)) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) > 10000 or len(set(names)) != len(names):
                _fail("wheel member count or names are invalid")
            if any(info.file_size < 0 or info.file_size > MAX_FILE_BYTES for info in infos):
                _fail("wheel member exceeds uncompressed byte bound")
            if sum(info.file_size for info in infos) > MAX_FILE_BYTES:
                _fail("wheel exceeds total uncompressed byte bound")
            members = {
                "metadata": [name for name in names if name.endswith(".dist-info/METADATA")],
                "entry_points": [name for name in names if name.endswith(".dist-info/entry_points.txt")],
                "record": [name for name in names if name.endswith(".dist-info/RECORD")],
                "cli": [name for name in names if name == "aoi_orgware/cli.py"],
            }
            if any(len(items) != 1 for items in members.values()):
                _fail("wheel lacks unique METADATA, entry_points, RECORD, or CLI module")
            selected_infos = [archive.getinfo(items[0]) for items in members.values()]
            if any(info.file_size > 4 * 1024 * 1024 for info in selected_infos):
                _fail("wheel interface member exceeds byte bound")
            if sum(info.file_size for info in selected_infos) > 16 * 1024 * 1024:
                _fail("wheel interfaces exceed total byte bound")
            raw = {name: archive.read(items[0]) for name, items in members.items()}
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise LocalInstallProofError(f"cannot inspect wheel: {exc}") from exc
    if any(len(value) > 4 * 1024 * 1024 for value in raw.values()):
        _fail("wheel interface member exceeds declared byte bound")
    try:
        metadata_text = raw["metadata"].decode("utf-8"); entries_text = raw["entry_points"].decode("utf-8"); cli_text = raw["cli"].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LocalInstallProofError("wheel interface is not UTF-8") from exc
    metadata: dict[str, str] = {}
    for line in metadata_text.splitlines():
        if ": " not in line:
            continue
        key, member_value = line.split(": ", 1)
        if key in {"Name", "Version"} and key in metadata:
            _fail("wheel METADATA repeats package identity field")
        metadata[key] = member_value
    if metadata.get("Name") != "aoi-orgware" or metadata.get("Version") != version:
        _fail("wheel METADATA does not bind package identity")
    required = {"aoi = aoi_orgware.cli:main", "aoi-codex-hook = aoi_orgware.codex_hook:main", "aoi-codex-bridge = aoi_orgware.codex_transport_cli:main", "aoi-claude-hook = aoi_orgware.claude_hook:main"}
    in_console = False; found: list[str] = []
    for line in entries_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_console = stripped == "[console_scripts]"; continue
        if in_console and stripped and not stripped.startswith(("#", ";")):
            found.append(stripped)
    if len(found) != len(set(found)) or set(found) != required:
        _fail("wheel console entry points are not exact")
    hook = _HOOK.search(cli_text)
    if hook is None or hook.group(1) != "6":
        _fail("wheel HOOK_PROTOCOL_VERSION is not 6")
    return {"metadata_sha256": hashlib.sha256(raw["metadata"]).hexdigest(), "entry_points_sha256": hashlib.sha256(raw["entry_points"]).hexdigest(), "record_sha256": hashlib.sha256(raw["record"]).hexdigest(), "cli_sha256": hashlib.sha256(raw["cli"]).hexdigest(), "hook_protocol_version": 6, "entry_points": sorted(required)}


def _report_inventory(value: Any, inventory: Mapping[str, Any]) -> None:
    if isinstance(value, str):
        if _sha(value, "rehearsal inventory") != inventory["inventory_sha256"]:
            _fail("rehearsal inventory does not cross-bind")
        return
    if isinstance(value, Mapping):
        if _inventory(value, version=str(inventory["package_version"])) != inventory:
            _fail("rehearsal inventory does not exactly cross-bind")
        return
    _fail("rehearsal inventory is invalid")


def _rehearsal(value: Mapping[str, Any], source: Mapping[str, Any], manifest: Mapping[str, Any], lock_sha256: str, inventory: Mapping[str, Any]) -> dict[str, Any]:
    fields = {"context", "source_manifest_sha256", "source_file_count", "lock_sha256", "inventory", "artifacts", "observations", "limitations"}
    item = _object(value, fields, "release rehearsal report")
    context = _object(item["context"], {"root", "source", "copied_files", "source_head", "source_date_epoch", "version"}, "release rehearsal context")
    _text(context["root"], "release rehearsal context root"); _text(context["source"], "release rehearsal context source")
    copied = context["copied_files"]
    if not isinstance(copied, list) or len(copied) != manifest["source_file_count"]:
        _fail("release rehearsal copied_files is invalid")
    copied_paths = [_safe_relative(path, "release rehearsal copied file") for path in copied]
    if copied_paths != sorted(copied_paths) or len(set(copied_paths)) != len(copied_paths):
        _fail("release rehearsal copied_files are not canonical")
    _text(context["source_head"], "release rehearsal source_head", limit=128)
    if type(context["source_date_epoch"]) is not int or context["source_head"] != source["head"] or context["source_date_epoch"] != source["source_date_epoch"] or context["version"] != source["package_version"]:
        _fail("release rehearsal context does not cross-bind source")
    if item["source_manifest_sha256"] != manifest["raw_sha256"] or item["source_file_count"] != manifest["source_file_count"] or item["lock_sha256"] != lock_sha256:
        _fail("release rehearsal does not cross-bind source manifest or tool lock")
    _report_inventory(item["inventory"], inventory)
    if item["artifacts"] != inventory["artifacts"]:
        _fail("release rehearsal artifacts do not cross-bind inventory")
    observations = _object(
        item["observations"],
        {"source_manifest_current_bytes", "artifact_inventory_bytes", "producer_test_summary"},
        "local rehearsal observations",
    )
    if observations["source_manifest_current_bytes"] != "verified" or observations["artifact_inventory_bytes"] != "verified":
        _fail("local rehearsal byte observations are invalid")
    producer = _text(observations["producer_test_summary"], "local rehearsal producer_test_summary", limit=128)
    match = re.fullmatch(r"([1-9][0-9]*) passed, ([0-9]+) skipped", producer)
    if match is None:
        _fail("local rehearsal producer_test_summary is not a passing pytest summary")
    expected_limitations = [
        "producer_test_summary_is_caller_supplied_context",
        "source_identity_does_not_attest_source_to_wheel_derivation",
        "builder_toolchain_and_test_execution_are_not_attested",
    ]
    if item["limitations"] != expected_limitations:
        _fail("local rehearsal evidence limitations are invalid")
    return item


def _source_descriptor(snapshot: Mapping[str, Any], *, store_manifest_path: str, manifest_raw: bytes, manifest: Mapping[str, Any], lock_path: str, lock_raw: bytes) -> dict[str, Any]:
    return {**snapshot, "source_manifest": {"path": store_manifest_path, "raw_sha256": hashlib.sha256(manifest_raw).hexdigest(), "source_file_count": manifest["source_file_count"]}, "tool_lock": {"path": lock_path, "raw_sha256": hashlib.sha256(lock_raw).hexdigest()}}


def _validate_subject(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {"schema_version", "kind", "proof_scope", "artifact_store_root", "source", "inventory", "rehearsal", "wheel_interface", "subject_sha256"}
    item = _object(value, fields, "local installation subject")
    if item["schema_version"] != 2 or item["kind"] != "local_install_subject" or item["proof_scope"] != "exact_local_wheel_install_only":
        _fail("local installation subject kind or proof scope is invalid")
    if not isinstance(item["artifact_store_root"], str) or not os.path.isabs(item["artifact_store_root"]):
        _fail("subject artifact_store_root is invalid")
    source = _object(item["source"], {"git_object_format", "head", "tree", "source_date_epoch", "remote", "package_version", "source_manifest", "tool_lock"}, "subject source")
    object_format = source["git_object_format"]
    if object_format not in _OID or not isinstance(source["head"], str) or not isinstance(source["tree"], str) or _OID[object_format].fullmatch(source["head"]) is None or _OID[object_format].fullmatch(source["tree"]) is None:
        _fail("subject source Git identity is invalid")
    if not isinstance(source["source_date_epoch"], int) or isinstance(source["source_date_epoch"], bool) or source["source_date_epoch"] < 0:
        _fail("subject source_date_epoch is invalid")
    version = _text(source["package_version"], "subject source package version", limit=128)
    remote = _object(source["remote"], {"name", "url"}, "subject source remote")
    if remote["name"] != "origin": _fail("subject source remote must be origin")
    _text(remote["url"], "subject source remote URL")
    manifest = _object(source["source_manifest"], {"path", "raw_sha256", "source_file_count"}, "subject source manifest")
    _safe_relative(manifest["path"], "subject source manifest path"); _sha(manifest["raw_sha256"], "subject source manifest raw sha256")
    if not isinstance(manifest["source_file_count"], int) or isinstance(manifest["source_file_count"], bool) or not 0 <= manifest["source_file_count"] <= MAX_SOURCE_FILES: _fail("subject source manifest count is invalid")
    lock = _object(source["tool_lock"], {"path", "raw_sha256"}, "subject tool lock")
    _safe_relative(lock["path"], "subject tool lock path"); _sha(lock["raw_sha256"], "subject tool lock raw sha256")
    subject_inventory = _object(item["inventory"], {"path", "raw_sha256", "inventory_sha256", "artifacts"}, "subject inventory")
    _safe_relative(subject_inventory["path"], "subject inventory path"); _sha(subject_inventory["raw_sha256"], "subject inventory raw sha256"); _sha(subject_inventory["inventory_sha256"], "subject inventory sha256")
    artifacts = subject_inventory["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != MAX_ARTIFACTS: _fail("subject inventory artifacts are invalid")
    bare: list[dict[str, Any]] = []
    for artifact in artifacts:
        entry = _object(artifact, {"path", "name", "size_bytes", "sha256"}, "subject artifact")
        name, _kind = _artifact_name(entry["name"], version)
        if entry["path"] != f"dist/{name}": _fail("subject artifact path is invalid")
        size = entry["size_bytes"]
        if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= MAX_FILE_BYTES: _fail("subject artifact size is invalid")
        bare.append({"name": name, "size_bytes": size, "sha256": _sha(entry["sha256"], "subject artifact sha256")})
    inventory = _inventory({"schema_version": 1, "distribution_name": "aoi-orgware", "package_version": version, "artifacts": bare, "inventory_sha256": subject_inventory["inventory_sha256"]}, version=version)
    rehearsal = _object(item["rehearsal"], {"path", "raw_sha256", "report"}, "subject rehearsal")
    _safe_relative(rehearsal["path"], "subject rehearsal path"); _sha(rehearsal["raw_sha256"], "subject rehearsal raw sha256")
    _rehearsal(rehearsal["report"], source, manifest, lock["raw_sha256"], inventory)
    interface = _object(item["wheel_interface"], {"metadata_sha256", "entry_points_sha256", "record_sha256", "cli_sha256", "hook_protocol_version", "entry_points"}, "subject wheel interface")
    for key in ("metadata_sha256", "entry_points_sha256", "record_sha256", "cli_sha256"): _sha(interface[key], f"subject wheel {key}")
    expected_entries = sorted(["aoi = aoi_orgware.cli:main", "aoi-codex-hook = aoi_orgware.codex_hook:main", "aoi-codex-bridge = aoi_orgware.codex_transport_cli:main", "aoi-claude-hook = aoi_orgware.claude_hook:main"])
    if interface["hook_protocol_version"] != 6 or interface["entry_points"] != expected_entries: _fail("subject wheel interface is invalid")
    _sha(item["subject_sha256"], "subject sha256")
    if _digest({key: item[key] for key in item if key != "subject_sha256"}) != item["subject_sha256"]: _fail("subject digest does not match")
    return item


def _observe_store_subject(subject: Mapping[str, Any]) -> None:
    root = _store_root(subject["artifact_store_root"]); source = subject["source"]
    manifest_path = _under(root, source["source_manifest"]["path"], "source manifest evidence")
    manifest_raw, manifest_value = _read_json(manifest_path, "source manifest evidence", canonical=True)
    manifest = _manifest_evidence(manifest_value)
    if hashlib.sha256(manifest_raw).hexdigest() != source["source_manifest"]["raw_sha256"] or manifest["source_file_count"] != source["source_manifest"]["source_file_count"]:
        _fail("source manifest evidence bytes do not match subject")
    inventory_path = _under(root, subject["inventory"]["path"], "inventory evidence")
    inventory_raw, inventory_value = _read_json(inventory_path, "inventory evidence", canonical=True)
    if hashlib.sha256(inventory_raw).hexdigest() != subject["inventory"]["raw_sha256"]:
        _fail("inventory evidence bytes do not match subject")
    inventory = _inventory(inventory_value, version=source["package_version"])
    if inventory["inventory_sha256"] != subject["inventory"]["inventory_sha256"] or subject["inventory"]["artifacts"] != [{"path": f"dist/{entry['name']}", **entry} for entry in inventory["artifacts"]]:
        _fail("inventory evidence does not match subject")
    artifacts, _wheel, wheel_raw = _observe_artifacts(root, inventory)
    if artifacts != subject["inventory"]["artifacts"]: _fail("distribution artifacts do not match subject")
    report_path = _under(root, subject["rehearsal"]["path"], "rehearsal evidence")
    report_raw, report = _read_json(report_path, "rehearsal evidence", canonical=False)
    if hashlib.sha256(report_raw).hexdigest() != subject["rehearsal"]["raw_sha256"] or report != subject["rehearsal"]["report"]:
        _fail("rehearsal evidence bytes do not match subject")
    _rehearsal(report, source, source["source_manifest"], source["tool_lock"]["raw_sha256"], inventory)
    if report["context"]["copied_files"] != [entry["path"] for entry in manifest["files"]]:
        _fail("rehearsal copied_files do not cross-bind source manifest")
    if _wheel_interface(wheel_raw, version=source["package_version"]) != subject["wheel_interface"]:
        _fail("wheel interface does not match subject")


def create_subject(*, source_root: Path, store_root: Path, inventory_path: str, rehearsal_path: str, source_manifest_path: str = "evidence/source-file-manifest.json", tool_lock_path: str = "requirements/release-tools.lock") -> dict[str, Any]:
    """Observe a clean source and immutable external store into one subject."""

    source_root = _secure_directory(source_root, "source root"); store_root = _secure_directory(store_root, "external store")
    _require_external_store(source_root, store_root)
    before = _git_snapshot(source_root)
    source_manifest_rel = _safe_relative(source_manifest_path, "source manifest evidence path")
    manifest_raw, manifest = _read_json(_under(store_root, source_manifest_rel, "source manifest evidence"), "source manifest evidence", canonical=True)
    manifest = _validate_source_manifest(manifest, source_root)
    lock_rel = _safe_relative(tool_lock_path, "tool lock path"); lock_raw = _stable_read(_under(source_root, lock_rel, "tool lock"), label="tool lock", limit=256 * 1024)
    source = _source_descriptor(before, store_manifest_path=source_manifest_rel, manifest_raw=manifest_raw, manifest=manifest, lock_path=lock_rel, lock_raw=lock_raw)
    inventory_rel = _safe_relative(inventory_path, "inventory evidence path"); inventory_raw, inventory_value = _read_json(_under(store_root, inventory_rel, "inventory evidence"), "inventory evidence", canonical=True)
    inventory = _inventory(inventory_value, version=source["package_version"]); artifacts, _wheel, wheel_raw = _observe_artifacts(store_root, inventory)
    report_rel = _safe_relative(rehearsal_path, "rehearsal evidence path"); report_raw, report = _read_json(_under(store_root, report_rel, "rehearsal evidence"), "rehearsal evidence", canonical=False)
    report = _rehearsal(report, source, source["source_manifest"], source["tool_lock"]["raw_sha256"], inventory)
    if report["context"]["copied_files"] != [entry["path"] for entry in manifest["files"]]:
        _fail("release rehearsal copied_files do not cross-bind source manifest")
    _assert_snapshot(source_root, before)
    base = {"schema_version": 2, "kind": "local_install_subject", "proof_scope": "exact_local_wheel_install_only", "artifact_store_root": str(store_root), "source": source, "inventory": {"path": inventory_rel, "raw_sha256": hashlib.sha256(inventory_raw).hexdigest(), "inventory_sha256": inventory["inventory_sha256"], "artifacts": artifacts}, "rehearsal": {"path": report_rel, "raw_sha256": hashlib.sha256(report_raw).hexdigest(), "report": report}, "wheel_interface": _wheel_interface(wheel_raw, version=source["package_version"])}
    return {**base, "subject_sha256": _digest(base)}


def create_review_assertion(*, subject: Mapping[str, Any], reviewer: str, reviewed_at: str, outcome: str, clean: bool, limitations: Sequence[str]) -> dict[str, Any]:
    subject = _validate_subject(subject)
    if outcome not in {"PASS", "FAIL"} or type(clean) is not bool: _fail("review outcome or clean flag is invalid")
    if not isinstance(limitations, Sequence) or isinstance(limitations, (str, bytes)) or not 1 <= len(limitations) <= MAX_LIMITATIONS: _fail("review limitations are invalid")
    normalized = [_text(item, "review limitation", limit=512) for item in limitations]
    if len(set(normalized)) != len(normalized) or _SAFE_REVIEWER.fullmatch(reviewer) is None: _fail("reviewer or limitations are invalid")
    base = {"schema_version": 1, "kind": "cooperative_local_install_review", "subject_sha256": subject["subject_sha256"], "reviewer": reviewer, "reviewed_at": _timestamp(reviewed_at, "reviewed_at"), "outcome": outcome, "clean": clean, "limitations": normalized}
    return {**base, "review_sha256": _digest(base)}


def _validate_review(value: Mapping[str, Any], subject: Mapping[str, Any]) -> dict[str, Any]:
    fields = {"schema_version", "kind", "subject_sha256", "reviewer", "reviewed_at", "outcome", "clean", "limitations", "review_sha256"}
    item = _object(value, fields, "local installation review")
    if item["schema_version"] != 1 or item["kind"] != "cooperative_local_install_review" or item["subject_sha256"] != subject["subject_sha256"] or item["outcome"] not in {"PASS", "FAIL"} or type(item["clean"]) is not bool: _fail("local installation review does not bind subject or outcome")
    if _SAFE_REVIEWER.fullmatch(_text(item["reviewer"], "reviewer", limit=128)) is None: _fail("reviewer is invalid")
    _timestamp(item["reviewed_at"], "reviewed_at")
    if not isinstance(item["limitations"], list) or not 1 <= len(item["limitations"]) <= MAX_LIMITATIONS: _fail("review limitations are invalid")
    if len(set(_text(entry, "review limitation", limit=512) for entry in item["limitations"])) != len(item["limitations"]): _fail("review limitations contain duplicates")
    _sha(item["review_sha256"], "review sha256")
    if _digest({key: item[key] for key in item if key != "review_sha256"}) != item["review_sha256"]: _fail("review digest does not match")
    return item


def _validate_bundle(value: Mapping[str, Any], expected_sha256: str | None = None) -> dict[str, Any]:
    fields = {"schema_version", "kind", "proof_scope", "sealed_at", "subject", "review_assertion", "bundle_sha256"}
    item = _object(value, fields, "local installation bundle")
    if item["schema_version"] != 2 or item["kind"] != "reviewed_local_install_bundle" or item["proof_scope"] != "exact_local_wheel_install_only": _fail("local installation bundle kind or proof scope is invalid")
    _timestamp(item["sealed_at"], "sealed_at"); _sha(item["bundle_sha256"], "bundle sha256")
    if _digest({key: item[key] for key in item if key != "bundle_sha256"}) != item["bundle_sha256"]: _fail("bundle digest does not match")
    if expected_sha256 is not None and _sha(expected_sha256, "expected bundle sha256") != item["bundle_sha256"]: _fail("bundle sha256 differs from expected value")
    subject = _validate_subject(item["subject"]); review = _validate_review(item["review_assertion"], subject)
    if review["outcome"] != "PASS" or review["clean"] is not True: _fail("bundle review is not a clean PASS")
    return item


def seal_bundle(*, source_root: Path, store_root: Path, subject: Mapping[str, Any], review_assertion: Mapping[str, Any], sealed_at: str) -> dict[str, Any]:
    subject = _validate_subject(subject); review = _validate_review(review_assertion, subject)
    if review["outcome"] != "PASS" or review["clean"] is not True: _fail("only a clean PASS review may be sealed")
    observed = create_subject(source_root=source_root, store_root=store_root, inventory_path=subject["inventory"]["path"], rehearsal_path=subject["rehearsal"]["path"], source_manifest_path=subject["source"]["source_manifest"]["path"], tool_lock_path=subject["source"]["tool_lock"]["path"])
    if observed != subject: _fail("source or external store changed since subject observation")
    base = {"schema_version": 2, "kind": "reviewed_local_install_bundle", "proof_scope": "exact_local_wheel_install_only", "sealed_at": _timestamp(sealed_at, "sealed_at"), "subject": subject, "review_assertion": review}
    return {**base, "bundle_sha256": _digest(base)}


def load_local_install_bundle(bundle_file: Path, expected_sha256: str, verify_store: bool = True) -> dict[str, Any]:
    """Load a canonical bundle and, by default, verify its bound store only."""

    _raw, bundle = _read_json(Path(bundle_file), "local installation bundle file", canonical=True)
    item = _validate_bundle(bundle, expected_sha256)
    if verify_store: _observe_store_subject(item["subject"])
    return item


def verify_bundle(*, source_root: Path, store_root: Path, bundle: Mapping[str, Any], expected_sha256: str) -> dict[str, Any]:
    """Strong verification which also rechecks the live source checkout."""

    item = _validate_bundle(bundle, expected_sha256); subject = item["subject"]
    bound_root = _store_root(subject["artifact_store_root"]); supplied_root = _secure_directory(store_root, "external store")
    if os.path.normcase(str(bound_root)) != os.path.normcase(str(supplied_root)): _fail("supplied store_root differs from bound artifact_store_root")
    _observe_store_subject(subject)
    observed = create_subject(source_root=source_root, store_root=supplied_root, inventory_path=subject["inventory"]["path"], rehearsal_path=subject["rehearsal"]["path"], source_manifest_path=subject["source"]["source_manifest"]["path"], tool_lock_path=subject["source"]["tool_lock"]["path"])
    if observed != subject: _fail("live source or external store no longer matches bundle subject")
    return {"ok": True, "kind": item["kind"], "proof_scope": item["proof_scope"], "bundle_sha256": item["bundle_sha256"], "subject_sha256": subject["subject_sha256"]}


def local_install_contract(bundle: Mapping[str, Any], *, bundle_path: Path | None = None) -> dict[str, Any]:
    """Return the normalized local provenance fields for an installed runtime."""

    item = _validate_bundle(bundle); subject = item["subject"]
    if bundle_path is not None:
        _raw, stored = _read_json(Path(bundle_path), "local installation bundle file", canonical=True)
        if stored != item: _fail("bundle_path does not contain these canonical bundle bytes")
    root = subject["artifact_store_root"]; source = subject["source"]
    wheel = next(entry for entry in subject["inventory"]["artifacts"] if str(entry["name"]).endswith(".whl"))
    return {
        "bundle_sha256": item["bundle_sha256"],
        "artifact_store_root": root,
        "source_commit_oid": source["head"],
        "source_tree_oid": source["tree"],
        "source_manifest_sha256": source["source_manifest"]["raw_sha256"],
        "rehearsal_report_sha256": subject["rehearsal"]["raw_sha256"],
        "inventory_sha256": subject["inventory"]["inventory_sha256"],
        "distribution_name": "aoi-orgware",
        "package_version": source["package_version"],
        "wheel": {
            "path": str(Path(root) / wheel["path"]),
            "name": wheel["name"],
            "size_bytes": wheel["size_bytes"],
            "sha256": wheel["sha256"],
        },
        "interfaces": {
            "installed_metadata_sha256": subject["wheel_interface"]["metadata_sha256"],
            "console_entry_point": {
                "name": "aoi",
                "target": "aoi_orgware.cli:main",
            },
            "codex_hook_entry_point": {
                "name": "aoi-codex-hook",
                "target": "aoi_orgware.codex_hook:main",
            },
            "codex_bridge_entry_point": {
                "name": "aoi-codex-bridge",
                "target": "aoi_orgware.codex_transport_cli:main",
            },
            "hook_protocol_version": 6,
        },
    }


build_subject = create_subject
review_subject = create_review_assertion
verify_local_install_bundle = verify_bundle
