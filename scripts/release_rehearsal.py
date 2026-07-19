"""Offline, create-only assembly of the evidence needed for an AOI release.

This tool intentionally has no registry, VCS mutation, or publication command.
Every input is named explicitly, canonical JSON is required for receipts and
requests, and the generated manifest remains subject to the later observer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any, Mapping, Sequence

_ROOT = Path(__file__).resolve().parents[1]
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from aoi_orgware.release_manifest import (  # noqa: E402
    ReleaseManifestError,
    seal_release_manifest,
    validate_release_manifest,
)
from aoi_orgware.semantic_events import (  # noqa: E402
    SemanticEventError,
    canonical_json_bytes,
    canonical_sha256,
)
from release_inventory import InventoryError, verify as verify_inventory  # noqa: E402


MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_REQUEST_BYTES = 512 * 1024
MAX_RECEIPT_BYTES = 256 * 1024
_SHA = __import__("re").compile(r"[0-9a-f]{64}")
_PLATFORMS = {"linux", "windows"}


class RehearsalError(ValueError):
    """The offline release evidence is malformed or does not bind exactly."""


def _fail(message: str) -> None:
    raise RehearsalError(message)


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(f"{label} schema is invalid")
    return dict(value)


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        _fail(f"{label} is not lowercase SHA-256")
    return value


def _text(value: Any, label: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        _fail(f"{label} is invalid")
    return value


def _identifier(value: Any, label: str) -> str:
    text = _text(value, label, 128)
    if not all(c.isascii() and (c.isalnum() or c in "._:-") for c in text):
        _fail(f"{label} is invalid")
    return text


def _release_toolchain(value: Any) -> dict[str, Any]:
    """Validate the complete, installed release-tool wheel binding.

    The wheel hashes are the hashes accepted by ``pip --require-hashes``.  The
    receipt is therefore both a record of the installed distribution versions
    and the immutable artifact set that was allowed to produce the release.
    """

    expected = _canonical_release_toolchain()
    item = _object(value, {"lock_sha256", "distributions"}, "release_toolchain")
    lock_sha256 = _sha(item["lock_sha256"], "release_toolchain.lock_sha256")
    distributions = item["distributions"]
    if not isinstance(distributions, list):
        _fail("release_toolchain.distributions is invalid")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for entry in distributions:
        record = _object(entry, {"name", "version", "artifact_sha256"}, "release_toolchain distribution")
        raw_name = _identifier(record["name"], "release_toolchain distribution.name")
        name = re.sub(r"[-_.]+", "-", raw_name.lower())
        if raw_name != name:
            _fail("release_toolchain distribution.name is not canonical")
        version = _text(record["version"], "release_toolchain distribution.version", 128)
        artifact_sha256 = _sha(record["artifact_sha256"], "release_toolchain distribution.artifact_sha256")
        if name in seen:
            _fail("release_toolchain contains duplicate distributions")
        seen.add(name)
        normalized.append({"name": name, "version": version, "artifact_sha256": artifact_sha256})
    if normalized != sorted(normalized, key=lambda entry: entry["name"]):
        _fail("release_toolchain distributions are not canonical")
    observed = {"lock_sha256": lock_sha256, "distributions": normalized}
    if observed != expected:
        _fail("release_toolchain does not match canonical requirements/release-tools.lock")
    return expected


def _read_regular(path: Path, *, limit: int = MAX_FILE_BYTES) -> bytes:
    """Read one non-link, non-hardlink regular file and detect replacement."""

    path = Path(os.path.abspath(path))
    try:
        resolved = path.resolve(strict=True)
        before = path.lstat()
    except OSError as exc:
        raise RehearsalError(f"cannot stat input file {path}: {exc}") from exc
    if os.path.normcase(str(path)) != os.path.normcase(str(resolved)):
        _fail(f"input path must not traverse a link or alias: {path}")
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    is_reparse = bool(getattr(before, "st_file_attributes", 0) & reparse_flag)
    if stat.S_ISLNK(before.st_mode) or is_reparse or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        _fail(f"input must be a non-linked regular file: {path}")
    if before.st_size > limit:
        _fail(f"input exceeds byte bound: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            opened = os.fstat(handle.fileno())
            if (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_nlink,
            ) != (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_nlink,
            ):
                _fail(f"input changed while opening: {path}")
            data = handle.read(limit + 1)
        after = path.lstat()
    except OSError as exc:
        raise RehearsalError(f"cannot read input file {path}: {exc}") from exc
    if len(data) > limit:
        _fail(f"input exceeds byte bound: {path}")
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink
    ):
        _fail(f"input changed while being read: {path}")
    return data


_LOCK_REQUIREMENT = re.compile(r"([a-z0-9]+(?:-[a-z0-9]+)*)==([^\\\s]+)\s+\\\Z")
_LOCK_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})\Z")


def _canonical_release_toolchain() -> dict[str, Any]:
    """Derive the only release-tool receipt accepted for this source tree."""

    lock_path = _ROOT / "requirements" / "release-tools.lock"
    raw = _read_regular(lock_path, limit=64 * 1024)
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise RehearsalError("release-tools lock is not ASCII") from exc
    records: list[dict[str, str]] = []
    index = 0
    while index < len(lines):
        line = lines[index].strip()
        if not line or line.startswith("#") or line == "--only-binary=:all:":
            index += 1
            continue
        requirement = _LOCK_REQUIREMENT.fullmatch(line)
        if requirement is None or index + 1 >= len(lines):
            _fail("canonical release-tools.lock is malformed")
        hash_line = _LOCK_HASH.fullmatch(lines[index + 1].strip())
        if hash_line is None:
            _fail("canonical release-tools.lock is malformed")
        name, version = requirement.groups()
        records.append({
            "name": name,
            "version": version,
            "artifact_sha256": hash_line.group(1),
        })
        index += 2
    if len(records) != 11 or records != sorted(records, key=lambda item: item["name"]):
        _fail("canonical release-tools.lock does not contain the exact 11 release tools")
    if len({record["name"] for record in records}) != len(records):
        _fail("canonical release-tools.lock has duplicate release tools")
    return {
        "lock_sha256": hashlib.sha256(raw).hexdigest(),
        "distributions": records,
    }


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RehearsalError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_canonical_json(path: Path, *, limit: int = MAX_RECEIPT_BYTES) -> dict[str, Any]:
    raw = _read_regular(path, limit=limit)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_json_pairs)
        canonical = canonical_json_bytes(value, max_bytes=limit)
    except (UnicodeDecodeError, json.JSONDecodeError, SemanticEventError, TypeError, ValueError) as exc:
        raise RehearsalError(f"invalid canonical JSON {path}: {exc}") from exc
    if raw != canonical:
        _fail(f"JSON is not exact canonical UTF-8: {path}")
    if not isinstance(value, dict):
        _fail(f"JSON root must be an object: {path}")
    return value


def _seal(base: dict[str, Any], digest_field: str = "receipt_sha256") -> dict[str, Any]:
    result = dict(base)
    result[digest_field] = canonical_sha256(base, max_bytes=MAX_RECEIPT_BYTES)
    return result


def _validate_sealed(receipt: Mapping[str, Any], *, kind: str, fields: set[str]) -> dict[str, Any]:
    item = _object(receipt, fields | {"receipt_sha256"}, f"{kind} receipt")
    if item.get("schema_version") != 1 or item.get("kind") != kind:
        _fail(f"{kind} receipt kind or schema version is invalid")
    digest = _sha(item["receipt_sha256"], f"{kind}.receipt_sha256")
    base = {key: item[key] for key in fields}
    if canonical_sha256(base, max_bytes=MAX_RECEIPT_BYTES) != digest:
        _fail(f"{kind} receipt digest does not match")
    return item


def _write_create_only(path: Path, value: Mapping[str, Any]) -> None:
    encoded = canonical_json_bytes(dict(value), max_bytes=MAX_REQUEST_BYTES)
    path = Path(os.path.abspath(path))
    parent = path.parent
    if not parent.exists():
        existing = parent
        while not existing.exists():
            if existing.parent == existing:
                _fail("output path has no existing parent")
            existing = existing.parent
        _secure_directory(existing, label="output ancestor")
        parent.mkdir(parents=True, exist_ok=True)
    _secure_directory(parent, label="output parent")
    if path.exists() or path.is_symlink():
        _fail(f"create-only output already exists: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise RehearsalError(f"create-only output already exists: {path}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        # A partially produced receipt is unsafe evidence; best-effort cleanup
        # only targets the file we just created with O_EXCL.
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _safe_relative(path: Any, label: str) -> str:
    value = _text(path, label, 1024)
    if "\\" in value:
        _fail(f"{label} is not a safe relative path")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or ".." in parsed.parts or str(parsed) != value or not parsed.parts:
        _fail(f"{label} is not a safe relative path")
    return value


def _under(root: Path, relative: str) -> Path:
    candidate = Path(os.path.abspath(root.joinpath(*PurePosixPath(relative).parts)))
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise RehearsalError("evidence path escapes artifact root") from exc
    if os.path.normcase(str(candidate)) != os.path.normcase(str(resolved)):
        _fail("evidence path must not traverse a link or alias")
    return candidate


def _secure_directory(path: Path, *, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    try:
        before = absolute.lstat()
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise RehearsalError(f"cannot inspect {label}: {path}: {exc}") from exc
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    is_reparse = bool(getattr(before, "st_file_attributes", 0) & reparse_flag)
    if stat.S_ISLNK(before.st_mode) or is_reparse or not stat.S_ISDIR(before.st_mode):
        _fail(f"{label} must be a real directory")
    if os.path.normcase(str(absolute)) != os.path.normcase(str(resolved)):
        _fail(f"{label} must not traverse a link or alias")
    return absolute


def _inventory(value: Mapping[str, Any], label: str) -> dict[str, Any]:
    item = _object(value, {"schema_version", "distribution_name", "package_version", "artifacts", "inventory_sha256"}, label)
    if item["schema_version"] != 1:
        _fail(f"{label} schema_version is invalid")
    _text(item["distribution_name"], f"{label}.distribution_name", 128)
    _text(item["package_version"], f"{label}.package_version", 128)
    if not isinstance(item["artifacts"], list) or not item["artifacts"]:
        _fail(f"{label}.artifacts is invalid")
    base = {key: item[key] for key in item if key != "inventory_sha256"}
    if canonical_sha256(base, max_bytes=MAX_RECEIPT_BYTES) != _sha(item["inventory_sha256"], f"{label}.inventory_sha256"):
        _fail(f"{label} inventory_sha256 does not match")
    # Manifest validation provides the stricter cross-platform artifact rules.
    return item


def _read_inventory(path: Path, label: str) -> dict[str, Any]:
    return _inventory(_read_canonical_json(path), label)


def _verify_inventory_root(root: Path, inventory: Mapping[str, Any], label: str) -> None:
    """Delegate exact filename-set/hash checks to the shared inventory contract."""

    try:
        verify_inventory(dict(inventory), root)
    except (InventoryError, OSError) as exc:
        raise RehearsalError(f"{label} inventory root is invalid: {exc}") from exc


def _manifest_artifacts(inventory: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Inventory names are dist-dir basenames; manifest paths are observer-root paths."""

    return [
        {"name": f"dist/{artifact['name']}", "size_bytes": artifact["size_bytes"], "sha256": artifact["sha256"]}
        for artifact in inventory["artifacts"]
    ]


def create_builder_environment_receipt(*, platform: str, python_version: str, workflow_name: str, run_id: str, run_attempt: int, runner_os: str, runner_arch: str, runner_image: str, build_frontend: str, build_frontend_version: str, source_date_epoch: int) -> dict[str, Any]:
    """Create the exact descriptor whose canonical digest enters the manifest.

    This deliberately is not a generic receipt: the later observer parses these
    exact fields and cross-binds them to the workflow identity.
    """
    if platform not in _PLATFORMS:
        _fail("builder environment platform is invalid")
    if not isinstance(run_attempt, int) or isinstance(run_attempt, bool) or run_attempt < 1:
        _fail("run_attempt is invalid")
    if not isinstance(source_date_epoch, int) or isinstance(source_date_epoch, bool) or source_date_epoch < 1:
        _fail("source_date_epoch is invalid")
    base = {"schema_version": 1, "platform": platform, "python_version": _text(python_version, "python_version", 64), "workflow_name": _identifier(workflow_name, "workflow_name"), "run_id": _identifier(run_id, "run_id"), "run_attempt": run_attempt, "runner_os": _text(runner_os, "runner_os", 128), "runner_arch": _text(runner_arch, "runner_arch", 128), "runner_image": _text(runner_image, "runner_image", 256), "build_frontend": _text(build_frontend, "build_frontend", 128), "build_frontend_version": _text(build_frontend_version, "build_frontend_version", 128), "source_date_epoch": source_date_epoch}
    canonical_json_bytes(base, max_bytes=MAX_RECEIPT_BYTES)
    return base


def create_producer_receipt(*, producer_id: str, platform: str, inventory_sha256: str, result: Mapping[str, Any]) -> dict[str, Any]:
    if platform not in _PLATFORMS:
        _fail("producer platform is invalid")
    normalized_result = dict(result)
    if platform == "linux":
        if "release_toolchain" not in normalized_result:
            _fail("Linux producer result lacks release_toolchain")
        normalized_result["release_toolchain"] = _release_toolchain(normalized_result["release_toolchain"])
    base = {"schema_version": 1, "kind": "producer", "producer_id": _identifier(producer_id, "producer_id"), "platform": platform, "inventory_sha256": _sha(inventory_sha256, "inventory_sha256"), "result": normalized_result}
    base["result_sha256"] = canonical_sha256(base["result"], max_bytes=MAX_RECEIPT_BYTES)
    return _seal(base)


def producer_binding(receipt: Mapping[str, Any]) -> dict[str, str | int]:
    """Return the immutable producer evidence that enters the manifest chain.

    A manifest previously retained only the digest of the producer's free-form
    result.  Bind that digest to the sealed producer receipt, Linux platform,
    and exact inventory so an observation (and its later promotion) has one
    durable, replayable producer identity.
    """

    item = _validate_sealed(
        receipt,
        kind="producer",
        fields={
            "schema_version",
            "kind",
            "producer_id",
            "platform",
            "inventory_sha256",
            "result",
            "result_sha256",
        },
    )
    if item["platform"] != "linux":
        _fail("producer binding platform must be linux")
    if not isinstance(item["result"], Mapping) or "release_toolchain" not in item["result"]:
        _fail("producer binding lacks release_toolchain")
    _release_toolchain(item["result"]["release_toolchain"])
    if canonical_sha256(item["result"], max_bytes=MAX_RECEIPT_BYTES) != item["result_sha256"]:
        _fail("producer binding result digest does not match")
    return {
        "schema_version": 1,
        "kind": "producer_binding",
        "producer_id": item["producer_id"],
        "producer_receipt_sha256": item["receipt_sha256"],
        "platform": item["platform"],
        "inventory_sha256": item["inventory_sha256"],
        "result_sha256": item["result_sha256"],
    }


def create_gate_contract(*, gate_id: str, contract: Mapping[str, Any]) -> dict[str, Any]:
    base = {"schema_version": 1, "kind": "check_contract", "gate_id": _identifier(gate_id, "gate_id"), "contract": dict(contract)}
    base["check_contract_sha256"] = canonical_sha256(base, max_bytes=MAX_RECEIPT_BYTES)
    return _seal(base)


def create_platform_gate_receipt(*, platform: str, gate_id: str, check_contract_sha256: str, inventory_sha256: str, details: Mapping[str, Any]) -> dict[str, Any]:
    if platform not in _PLATFORMS:
        _fail("platform gate platform is invalid")
    base = {"schema_version": 1, "kind": "platform_gate", "platform": platform, "gate_id": _identifier(gate_id, "gate_id"), "check_contract_sha256": _sha(check_contract_sha256, "check_contract_sha256"), "inventory_sha256": _sha(inventory_sha256, "inventory_sha256"), "status": "pass", "details": dict(details)}
    return _seal(base)


def create_installed_metadata_receipt(*, distribution_name: str, package_version: str, installed_metadata_sha256: str, console_entry_point_name: str, console_entry_point_target: str, codex_hook_entry_point_name: str, codex_hook_entry_point_target: str, hook_protocol_version: int) -> dict[str, Any]:
    if not isinstance(hook_protocol_version, int) or isinstance(hook_protocol_version, bool) or hook_protocol_version < 1:
        _fail("hook_protocol_version is invalid")
    base = {"schema_version": 1, "kind": "installed_metadata", "distribution_name": _text(distribution_name, "distribution_name", 128), "package_version": _text(package_version, "package_version", 128), "installed_metadata_sha256": _sha(installed_metadata_sha256, "installed_metadata_sha256"), "console_entry_point": {"name": _identifier(console_entry_point_name, "console_entry_point_name"), "target": _text(console_entry_point_target, "console_entry_point_target", 256)}, "codex_hook_entry_point": {"name": _identifier(codex_hook_entry_point_name, "codex_hook_entry_point_name"), "target": _text(codex_hook_entry_point_target, "codex_hook_entry_point_target", 256)}, "hook_protocol_version": hook_protocol_version}
    return _seal(base)


def create_placeholder_receipt(*, kind: str, location: str, input_bytes: bytes) -> dict[str, Any]:
    if kind not in {"sbom", "attestation"}:
        _fail("placeholder kind is invalid")
    base = {"schema_version": 1, "kind": kind, "location": _safe_relative(location, f"{kind}.location"), "sha256": hashlib.sha256(input_bytes).hexdigest(), "placeholder": True}
    return _seal(base)


def _validate_evidence_files(value: Any, artifact_root: Path) -> dict[str, Any]:
    """Validate the observer request evidence and hash every named file now."""
    fields = {"producer_results", "builder_environment", "matrix", "installed_metadata", "reviewed_exception_receipt"}
    item = _object(value, fields, "evidence_files")
    def descriptor(entry: Any, label: str) -> dict[str, str]:
        part = _object(entry, {"path", "sha256"}, label)
        relative = _safe_relative(part["path"], f"{label}.path")
        observed = hashlib.sha256(_read_regular(_under(artifact_root, relative))).hexdigest()
        if observed != _sha(part["sha256"], f"{label}.sha256"):
            _fail(f"{label} bytes do not match supplied SHA-256")
        return {"path": relative, "sha256": observed}
    producers = item["producer_results"]
    if not isinstance(producers, Mapping):
        _fail("evidence_files.producer_results is invalid")
    result_producers = {str(k): descriptor(v, f"producer evidence {k}") for k, v in producers.items()}
    matrix = item["matrix"]
    if not isinstance(matrix, Mapping):
        _fail("evidence_files.matrix is invalid")
    result_matrix: dict[str, Any] = {}
    for key, pair in matrix.items():
        if not isinstance(key, str) or "/" not in key:
            _fail("matrix evidence key is invalid")
        rec = _object(pair, {"check_contract", "receipt"}, f"matrix evidence {key}")
        result_matrix[key] = {"check_contract": descriptor(rec["check_contract"], f"matrix contract {key}"), "receipt": descriptor(rec["receipt"], f"matrix receipt {key}")}
    reviewed = item["reviewed_exception_receipt"]
    if reviewed is not None:
        reviewed = descriptor(reviewed, "reviewed_exception_receipt")
    return {"producer_results": result_producers, "builder_environment": descriptor(item["builder_environment"], "builder_environment"), "matrix": result_matrix, "installed_metadata": descriptor(item["installed_metadata"], "installed_metadata"), "reviewed_exception_receipt": reviewed}


def assemble(request: Mapping[str, Any]) -> dict[str, Any]:
    """Validate explicit offline evidence and create sealed manifest/request files."""
    fields = {"schema_version", "manifest", "inventory_paths", "inventory_roots", "builder_environment_receipt_path", "producer_receipt_paths", "gate_contract_paths", "platform_gate_receipt_paths", "installed_metadata_receipt_path", "sbom_receipt_path", "attestation_receipt_path", "worktree", "artifact_root", "rebuild_root", "evidence_files", "dependency_files", "outputs"}
    item = _object(request, fields, "rehearsal request")
    if item["schema_version"] != 1:
        _fail("rehearsal request schema_version is invalid")
    inventory_paths = _object(item["inventory_paths"], {"linux", "windows", "rebuild"}, "inventory_paths")
    inventories = {name: _read_inventory(Path(str(path)), f"{name} inventory") for name, path in inventory_paths.items()}
    linux, windows, rebuild = inventories["linux"], inventories["windows"], inventories["rebuild"]
    if linux != windows:
        _fail("Linux and Windows inventories do not exactly match")
    if rebuild != linux:
        _fail("reproducible rebuild inventory does not exactly match build inventory")
    inventory_roots = _object(item["inventory_roots"], {"linux", "windows", "rebuild"}, "inventory_roots")
    manifest_seed = _object(item["manifest"], {"distribution_name", "tag", "git_object_format", "commit_oid", "tree_oid", "package_version", "workflow", "schema_versions", "dependencies"}, "manifest seed")
    workflow = _object(manifest_seed["workflow"], {"workflow_name", "run_id", "run_attempt"}, "manifest workflow")
    if (linux["distribution_name"], linux["package_version"]) != (manifest_seed["distribution_name"], manifest_seed["package_version"]):
        _fail("inventory distribution/version does not match manifest seed")
    builder = _object(_read_canonical_json(Path(str(item["builder_environment_receipt_path"]))), {"schema_version", "platform", "python_version", "workflow_name", "run_id", "run_attempt", "runner_os", "runner_arch", "runner_image", "build_frontend", "build_frontend_version", "source_date_epoch"}, "builder environment descriptor")
    if builder["schema_version"] != 1 or create_builder_environment_receipt(**{key: value for key, value in builder.items() if key != "schema_version"}) != builder:
        _fail("builder environment descriptor is invalid")
    if builder["platform"] != "linux":
        _fail("release builder environment must be Linux")
    producer_paths = item["producer_receipt_paths"]
    if not isinstance(producer_paths, Mapping) or not producer_paths:
        _fail("producer_receipt_paths is invalid")
    producers: list[dict[str, str]] = []
    producer_bindings: dict[str, dict[str, str | int]] = {}
    for producer_id, path in producer_paths.items():
        receipt = _validate_sealed(_read_canonical_json(Path(str(path))), kind="producer", fields={"schema_version", "kind", "producer_id", "platform", "inventory_sha256", "result", "result_sha256"})
        if (
            receipt["producer_id"] != producer_id
            or receipt["platform"] != "linux"
            or receipt["inventory_sha256"] != linux["inventory_sha256"]
        ):
            _fail("producer receipt does not bind the Linux build inventory")
        binding = producer_binding(receipt)
        if binding["inventory_sha256"] != linux["inventory_sha256"]:
            _fail("producer binding does not bind the Linux build inventory")
        producer_bindings[receipt["producer_id"]] = binding
        producers.append({
            "producer_id": receipt["producer_id"],
            "result_sha256": canonical_sha256(binding, max_bytes=MAX_RECEIPT_BYTES),
        })
    contract_paths = item["gate_contract_paths"]
    gate_paths = item["platform_gate_receipt_paths"]
    if not isinstance(contract_paths, Mapping) or not isinstance(gate_paths, Mapping) or set(gate_paths) != _PLATFORMS:
        _fail("gate contract or platform receipt paths are invalid")
    matrix: list[dict[str, str]] = []
    for gate_id, path in contract_paths.items():
        contract = _validate_sealed(_read_canonical_json(Path(str(path))), kind="check_contract", fields={"schema_version", "kind", "gate_id", "contract", "check_contract_sha256"})
        if gate_id != contract["gate_id"] or canonical_sha256({key: contract[key] for key in ("schema_version", "kind", "gate_id", "contract")}, max_bytes=MAX_RECEIPT_BYTES) != contract["check_contract_sha256"]:
            _fail("gate contract digest does not match")
        for platform in sorted(_PLATFORMS):
            paths = gate_paths[platform]
            if not isinstance(paths, Mapping) or gate_id not in paths:
                _fail("missing platform gate receipt")
            receipt = _validate_sealed(_read_canonical_json(Path(str(paths[gate_id]))), kind="platform_gate", fields={"schema_version", "kind", "platform", "gate_id", "check_contract_sha256", "inventory_sha256", "status", "details"})
            if receipt["platform"] != platform or receipt["gate_id"] != gate_id or receipt["status"] != "pass" or receipt["check_contract_sha256"] != contract["check_contract_sha256"] or receipt["inventory_sha256"] != linux["inventory_sha256"]:
                _fail("platform gate receipt is not bound to the shared contract and inventory")
            matrix.append({"platform": platform, "gate_id": gate_id, "check_contract_sha256": contract["check_contract_sha256"], "receipt_sha256": receipt["receipt_sha256"], "status": "pass"})
    if any(set(gate_paths[p]) != set(contract_paths) for p in _PLATFORMS):
        _fail("platform gate receipts contain missing or extra gates")
    installed = _validate_sealed(_read_canonical_json(Path(str(item["installed_metadata_receipt_path"]))), kind="installed_metadata", fields={"schema_version", "kind", "distribution_name", "package_version", "installed_metadata_sha256", "console_entry_point", "codex_hook_entry_point", "hook_protocol_version"})
    if (installed["distribution_name"], installed["package_version"]) != (linux["distribution_name"], linux["package_version"]):
        _fail("installed metadata is not bound to the inventory distribution/version")
    placeholders = {}
    for kind, key in (("sbom", "sbom_receipt_path"), ("attestation", "attestation_receipt_path")):
        receipt = _validate_sealed(_read_canonical_json(Path(str(item[key]))), kind=kind, fields={"schema_version", "kind", "location", "sha256", "placeholder"})
        if receipt["placeholder"] is not True:
            _fail(f"{kind} receipt must be an explicit placeholder")
        placeholders[kind] = {"location": _safe_relative(receipt["location"], f"{kind}.location"), "sha256": _sha(receipt["sha256"], f"{kind}.sha256")}
    artifact_root = _secure_directory(Path(str(item["artifact_root"])), label="artifact_root")
    rebuild_root = _secure_directory(Path(str(item["rebuild_root"])), label="rebuild_root")
    roots = {
        name: _secure_directory(Path(str(path)), label=f"{name} inventory root")
        for name, path in inventory_roots.items()
    }
    if roots["linux"] != artifact_root / "dist" or roots["rebuild"] != rebuild_root / "dist":
        _fail("Linux and rebuild inventory roots must be the observer dist directories")
    for name, inventory in inventories.items():
        _verify_inventory_root(roots[name], inventory, name)
    evidence_files = _validate_evidence_files(item["evidence_files"], artifact_root)
    builder_digest = canonical_sha256(builder, max_bytes=MAX_RECEIPT_BYTES)
    if evidence_files["builder_environment"]["sha256"] != builder_digest:
        _fail("builder environment evidence is not the descriptor used by the manifest")
    expected_producers = {
        producer["producer_id"]: producer["result_sha256"] for producer in producers
    }
    supplied_producers = {
        name: descriptor["sha256"]
        for name, descriptor in evidence_files["producer_results"].items()
    }
    if supplied_producers != expected_producers:
        _fail("producer evidence is not the exact result used by the manifest")
    for producer_id, binding in producer_bindings.items():
        descriptor = evidence_files["producer_results"][producer_id]
        observed_binding = _read_canonical_json(
            _under(artifact_root, descriptor["path"])
        )
        if observed_binding != binding:
            _fail("producer evidence does not bind the sealed Linux producer receipt and inventory")
    expected_matrix = {
        f"{entry['platform']}/{entry['gate_id']}": {
            "check_contract_sha256": entry["check_contract_sha256"],
            "receipt_sha256": entry["receipt_sha256"],
        }
        for entry in matrix
    }
    supplied_matrix = {
        name: {
            "check_contract_sha256": descriptor["check_contract"]["sha256"],
            "receipt_sha256": descriptor["receipt"]["sha256"],
        }
        for name, descriptor in evidence_files["matrix"].items()
    }
    if supplied_matrix != expected_matrix:
        _fail("matrix evidence is not the exact contract and result used by the manifest")
    if evidence_files["installed_metadata"]["sha256"] != installed["installed_metadata_sha256"]:
        _fail("installed metadata evidence does not match the manifest interface")
    for kind, descriptor in placeholders.items():
        observed = hashlib.sha256(
            _read_regular(_under(artifact_root, descriptor["location"]))
        ).hexdigest()
        if observed != descriptor["sha256"]:
            _fail(f"{kind} bytes do not match the placeholder receipt")
    artifacts = _manifest_artifacts(linux)
    if (builder["workflow_name"], builder["run_id"], builder["run_attempt"]) != (workflow["workflow_name"], workflow["run_id"], workflow["run_attempt"]):
        _fail("builder environment does not bind the manifest workflow")
    manifest = seal_release_manifest({"schema_version": 1, **manifest_seed, "build_environment": {"platform": builder["platform"], "python_version": builder["python_version"], "builder_environment_receipt_sha256": builder_digest}, "artifacts": artifacts, "producer_results": producers, "interfaces": {key: installed[key] for key in ("console_entry_point", "codex_hook_entry_point", "hook_protocol_version", "installed_metadata_sha256")}, "verification": {"matrix": matrix, "tested_artifacts": _manifest_artifacts(linux), "rebuild": {"status": "reproducible", "artifacts": _manifest_artifacts(rebuild)}}, "sbom": placeholders["sbom"], "attestation": placeholders["attestation"]})
    validate_release_manifest(manifest)
    outputs = _object(item["outputs"], {"release_manifest", "observation_request"}, "outputs")
    output_manifest = Path(str(outputs["release_manifest"])); output_observation = Path(str(outputs["observation_request"]))
    if output_manifest.resolve(strict=False) == output_observation.resolve(strict=False):
        _fail("outputs must be distinct")
    observation = {"schema_version": 1, "manifest": manifest, "worktree": str(Path(str(item["worktree"])).resolve()), "artifact_root": str(artifact_root), "rebuild_root": str(rebuild_root), "evidence_files": evidence_files, "dependency_files": item["dependency_files"]}
    # The observer remains the authority for clean worktree, Git, dependency,
    # and descriptor verification.  This rehearsal binds and hashes all named
    # evidence before either create-only output is written.
    canonical_json_bytes(observation, max_bytes=MAX_REQUEST_BYTES)
    _write_create_only(output_manifest, manifest)
    _write_create_only(output_observation, observation)
    return {"manifest": manifest, "observation_request": observation}


def _load_mapping_argument(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_json_pairs)
    except (json.JSONDecodeError, RehearsalError) as exc:
        raise RehearsalError(f"invalid JSON argument: {exc}") from exc
    if not isinstance(value, dict):
        _fail("JSON argument must be an object")
    return value


def _emit(value: Mapping[str, Any], output: Path) -> None:
    _write_create_only(output, value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    def common(name: str) -> argparse.ArgumentParser:
        sub = commands.add_parser(name); sub.add_argument("--output", required=True, type=Path); return sub
    sub = common("builder-environment"); sub.add_argument("--platform", required=True, choices=sorted(_PLATFORMS)); sub.add_argument("--python-version", required=True); sub.add_argument("--workflow-name", required=True); sub.add_argument("--run-id", required=True); sub.add_argument("--run-attempt", required=True, type=int); sub.add_argument("--runner-os", required=True); sub.add_argument("--runner-arch", required=True); sub.add_argument("--runner-image", required=True); sub.add_argument("--build-frontend", required=True); sub.add_argument("--build-frontend-version", required=True); sub.add_argument("--source-date-epoch", required=True, type=int)
    sub = common("producer"); sub.add_argument("--producer-id", required=True); sub.add_argument("--platform", required=True, choices=sorted(_PLATFORMS)); sub.add_argument("--inventory-sha256", required=True); sub.add_argument("--result-json", required=True)
    sub = common("gate-contract"); sub.add_argument("--gate-id", required=True); sub.add_argument("--contract-json", required=True)
    sub = common("platform-gate"); sub.add_argument("--platform", required=True, choices=sorted(_PLATFORMS)); sub.add_argument("--gate-id", required=True); sub.add_argument("--check-contract-sha256", required=True); sub.add_argument("--inventory-sha256", required=True); sub.add_argument("--details-json", required=True)
    sub = common("installed-metadata"); sub.add_argument("--distribution-name", required=True); sub.add_argument("--package-version", required=True); sub.add_argument("--installed-metadata-sha256", required=True); sub.add_argument("--console-entry-point-name", required=True); sub.add_argument("--console-entry-point-target", required=True); sub.add_argument("--codex-hook-entry-point-name", required=True); sub.add_argument("--codex-hook-entry-point-target", required=True); sub.add_argument("--hook-protocol-version", required=True, type=int)
    sub = common("placeholder"); sub.add_argument("--kind", required=True, choices=("sbom", "attestation")); sub.add_argument("--location", required=True); sub.add_argument("--input-file", required=True, type=Path)
    sub = commands.add_parser("assemble"); sub.add_argument("--request-file", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "builder-environment": value = create_builder_environment_receipt(platform=args.platform, python_version=args.python_version, workflow_name=args.workflow_name, run_id=args.run_id, run_attempt=args.run_attempt, runner_os=args.runner_os, runner_arch=args.runner_arch, runner_image=args.runner_image, build_frontend=args.build_frontend, build_frontend_version=args.build_frontend_version, source_date_epoch=args.source_date_epoch); _emit(value, args.output)
        elif args.command == "producer": value = create_producer_receipt(producer_id=args.producer_id, platform=args.platform, inventory_sha256=args.inventory_sha256, result=_load_mapping_argument(args.result_json)); _emit(value, args.output)
        elif args.command == "gate-contract": value = create_gate_contract(gate_id=args.gate_id, contract=_load_mapping_argument(args.contract_json)); _emit(value, args.output)
        elif args.command == "platform-gate": value = create_platform_gate_receipt(platform=args.platform, gate_id=args.gate_id, check_contract_sha256=args.check_contract_sha256, inventory_sha256=args.inventory_sha256, details=_load_mapping_argument(args.details_json)); _emit(value, args.output)
        elif args.command == "installed-metadata": value = create_installed_metadata_receipt(distribution_name=args.distribution_name, package_version=args.package_version, installed_metadata_sha256=args.installed_metadata_sha256, console_entry_point_name=args.console_entry_point_name, console_entry_point_target=args.console_entry_point_target, codex_hook_entry_point_name=args.codex_hook_entry_point_name, codex_hook_entry_point_target=args.codex_hook_entry_point_target, hook_protocol_version=args.hook_protocol_version); _emit(value, args.output)
        elif args.command == "placeholder": value = create_placeholder_receipt(kind=args.kind, location=args.location, input_bytes=_read_regular(args.input_file)); _emit(value, args.output)
        else: assemble(_read_canonical_json(args.request_file, limit=MAX_REQUEST_BYTES))
    except (OSError, RehearsalError, ReleaseManifestError, SemanticEventError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
