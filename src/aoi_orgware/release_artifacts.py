"""Observe and seal the bytes named by a release manifest.

This module deliberately has no publisher, cache, or filesystem-writing API.
It turns a supplied release-manifest value and an explicitly enumerated set of
supporting files into a bounded observation receipt.  Every file is opened by
descriptor and read twice; a pathname or descriptor identity change fails
closed instead of silently observing a mixed release.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from typing import Any, NoReturn

from .harnesslib import HarnessError, canonicalize_no_link_traversal
from .release_manifest import (
    MAX_ARTIFACT_AGGREGATE_BYTES,
    MAX_ARTIFACT_BYTES,
    ReleaseManifestError,
    seal_release_manifest,
    validate_promotion_receipt,
    validate_release_manifest,
)
from .semantic_events import (
    SemanticEventError,
    canonical_json_bytes,
    canonical_sha256,
)


RELEASE_ARTIFACT_OBSERVATION_SCHEMA_VERSION = 1
MAX_OBSERVATION_REQUEST_BYTES = 512 * 1024
MAX_OBSERVATION_RECEIPT_BYTES = 128 * 1024
# Artifact observation must accept every artifact size admitted by the pure
# manifest schema.  The larger aggregate budget accounts for the mandatory
# descriptor double-read of both producer and independent-rebuild bytes while
# retaining a bounded allowance for receipts, SBOM, attestation and dependency
# manifests.
MAX_OBSERVED_FILE_BYTES = MAX_ARTIFACT_BYTES
MAX_SUPPORTING_OBSERVED_READ_BYTES = 128 * 1024 * 1024
MAX_OBSERVED_TOTAL_BYTES = (
    4 * MAX_ARTIFACT_AGGREGATE_BYTES + MAX_SUPPORTING_OBSERVED_READ_BYTES
)
MAX_EVIDENCE_FILES = 1024

_REQUEST_FIELDS = {
    "schema_version", "manifest", "worktree", "artifact_root", "rebuild_root",
    "evidence_files", "dependency_files",
}
_EVIDENCE_FIELDS = {
    "producer_results", "builder_environment", "matrix", "installed_metadata",
    "reviewed_exception_receipt",
}
_MATRIX_EVIDENCE_FIELDS = {"check_contract", "receipt"}
_DEPENDENCY_FILE_FIELDS = {"release_manifest_path", "promotion_receipt_path"}
_FILE_FIELDS = {"path", "sha256"}
_BUILDER_ENVIRONMENT_RECEIPT_FIELDS = {
    "schema_version", "platform", "python_version", "workflow_name", "run_id",
    "run_attempt", "runner_os", "runner_arch", "runner_image",
    "build_frontend", "build_frontend_version", "source_date_epoch",
}
_OBSERVATION_GIT_FIELDS = {
    "git_object_format", "commit_oid", "tree_oid", "tag", "package_version",
}
_OBSERVATION_EVIDENCE_FIELDS = {
    "producer_results", "builder_environment_receipt_sha256", "matrix",
    "installed_metadata_sha256",
    "reviewed_exception_receipt_sha256",
}
_OBSERVATION_BASE_FIELDS = {
    "schema_version", "manifest_sha256", "git", "artifacts", "sbom_sha256",
    "attestation_sha256", "evidence_files", "dependencies", "rebuild_status",
}
_OBSERVATION_SEALED_FIELDS = _OBSERVATION_BASE_FIELDS | {
    "observation_receipt_sha256"
}
_OID_RE = re.compile(r"[0-9a-f]+\Z")
_VERSION_RE = re.compile(r'__version__\s*=\s*[\'"]([^\'"]+)[\'"]\s*\Z', re.MULTILINE)
_WINDOWS_UNSAFE_PATH_CHARS = frozenset('<>:"|?*')
_WINDOWS_RESERVED_DEVICE = re.compile(
    r"(?:con|prn|aux|nul|conin\$|conout\$|clock\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?\Z",
    re.IGNORECASE,
)


class ReleaseArtifactError(ValueError):
    """The supplied release bytes cannot be observed as one exact release."""


def _fail(message: str) -> NoReturn:
    raise ReleaseArtifactError(message)


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(f"{label} has an invalid schema")
    return dict(value)


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        _fail(f"{label} must be a lowercase SHA-256")
    return value


def _relative_path(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1024
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        _fail(f"{label} is not a safe relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        _fail(f"{label} is not a safe relative path")
    for part in path.parts:
        try:
            windows_units = len(part.encode("utf-16-le")) // 2
        except UnicodeEncodeError:
            _fail(f"{label} is not a safe relative path")
        if (
            part.endswith((" ", "."))
            or any(character in _WINDOWS_UNSAFE_PATH_CHARS for character in part)
            or _WINDOWS_RESERVED_DEVICE.fullmatch(part)
            or windows_units > 255
        ):
            _fail(f"{label} is not a safe relative path")
    return path.as_posix()


def _root(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or len(value) > 4096:
        _fail(f"{label} is invalid")
    lexical = Path(value).expanduser()
    if not lexical.is_absolute():
        _fail(f"{label} must be an absolute path")
    try:
        canonical = canonicalize_no_link_traversal(lexical, label)
        metadata = canonical.lstat()
    except (HarnessError, OSError) as exc:
        _fail(str(exc))
    if not stat.S_ISDIR(metadata.st_mode):
        _fail(f"{label} must be an existing regular directory")
    return canonical


def _file_spec(value: Any, label: str) -> dict[str, str]:
    item = _object(value, _FILE_FIELDS, label)
    return {"path": _relative_path(item["path"], f"{label}.path"), "sha256": _sha256(item["sha256"], f"{label}.sha256")}


def _snapshot_file(root: Path, relative: str, label: str, *, capture: bool = False) -> tuple[int, str, bytes | None]:
    """Return a double-read descriptor snapshot without following aliases."""
    try:
        candidate = canonicalize_no_link_traversal(root / Path(*PurePosixPath(relative).parts), label)
    except HarnessError as exc:
        _fail(str(exc))
    try:
        candidate.relative_to(root)
        before = candidate.lstat()
    except (ValueError, FileNotFoundError, OSError) as exc:
        _fail(f"missing or escaped {label}: {exc}")
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_OBSERVED_FILE_BYTES:
        _fail(f"{label} must be a bounded private regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        _fail(f"cannot open {label}: {exc}")
    try:
        def consume(*, retain: bool) -> tuple[int, str, bytes | None]:
            hasher = hashlib.sha256()
            size = 0
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = os.read(descriptor, min(64 * 1024, MAX_OBSERVED_FILE_BYTES + 1 - size))
                except OSError as exc:
                    _fail(f"cannot read {label}: {exc}")
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_OBSERVED_FILE_BYTES:
                    _fail(f"{label} exceeds byte bound")
                hasher.update(chunk)
                if retain:
                    chunks.append(chunk)
            return size, hasher.hexdigest(), b"".join(chunks) if retain else None

        opened = os.fstat(descriptor)
        first = consume(retain=capture)
        finished = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = consume(retain=False)
        confirmed = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after = candidate.lstat()
    except OSError as exc:
        _fail(f"{label} changed while being read: {exc}")
    # NTFS exposes a different ctime precision through pathname lstat and an
    # open descriptor.  Device/inode, size and mtime remain the portable
    # replacement detector here; the repeated descriptor read catches bytes
    # changed without metadata drift.
    identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_nlink")
    identities = (before, opened, finished, confirmed, after)
    if (
        first[:2] != second[:2]
        or first[0] != before.st_size
        or any(not stat.S_ISREG(item.st_mode) or item.st_nlink != 1 for item in identities)
        or any(getattr(item, field, None) != getattr(before, field, None) for item in identities for field in identity_fields)
    ):
        _fail(f"{label} changed while being read")
    return first


def _checked_file(root: Path, spec: Mapping[str, str], label: str, budget: list[int], *, capture: bool = False) -> tuple[int, str, bytes | None]:
    size, digest, payload = _snapshot_file(root, spec["path"], label, capture=capture)
    budget[0] += size * 2
    if budget[0] > MAX_OBSERVED_TOTAL_BYTES:
        _fail("observed files exceed total byte bound")
    if digest != spec["sha256"]:
        _fail(f"{label} raw digest does not match required digest")
    return size, digest, payload


def _manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("manifest must be an object")
    try:
        return validate_release_manifest(value) if "manifest_sha256" in value else seal_release_manifest(value)
    except ReleaseManifestError as exc:
        _fail(str(exc))


def _clone_json(value: Any, *, maximum: int) -> Any:
    try:
        return json.loads(
            canonical_json_bytes(value, max_bytes=maximum).decode("utf-8")
        )
    except (
        SemanticEventError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        _fail(f"release observation receipt is not bounded canonical JSON: {exc}")


def _observation_receipt_base(
    value: Any, manifest: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate the pure receipt contract against one exact sealed manifest."""

    sealed_manifest = _manifest(manifest)
    item = _object(
        _clone_json(value, maximum=MAX_OBSERVATION_RECEIPT_BYTES),
        _OBSERVATION_BASE_FIELDS,
        "release observation receipt",
    )
    version = item["schema_version"]
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != RELEASE_ARTIFACT_OBSERVATION_SCHEMA_VERSION
    ):
        _fail("release observation receipt schema_version is invalid")
    if item["manifest_sha256"] != sealed_manifest["manifest_sha256"]:
        _fail("release observation receipt names another manifest")

    git = _object(item["git"], _OBSERVATION_GIT_FIELDS, "release observation git")
    expected_git = {
        "git_object_format": sealed_manifest["git_object_format"],
        "commit_oid": sealed_manifest["commit_oid"],
        "tree_oid": sealed_manifest["tree_oid"],
        "tag": sealed_manifest["tag"],
        "package_version": sealed_manifest["package_version"],
    }
    if git != expected_git:
        _fail("release observation Git identity does not match manifest")
    if item["artifacts"] != sealed_manifest["artifacts"]:
        _fail("release observation artifacts do not exactly match manifest")
    if item["sbom_sha256"] != sealed_manifest["sbom"]["sha256"]:
        _fail("release observation SBOM does not match manifest")
    if item["attestation_sha256"] != sealed_manifest["attestation"]["sha256"]:
        _fail("release observation attestation does not match manifest")

    evidence = _object(
        item["evidence_files"],
        _OBSERVATION_EVIDENCE_FIELDS,
        "release observation evidence",
    )
    expected_evidence = {
        "producer_results": {
            row["producer_id"]: row["result_sha256"]
            for row in sealed_manifest["producer_results"]
        },
        "builder_environment_receipt_sha256": sealed_manifest[
            "build_environment"
        ]["builder_environment_receipt_sha256"],
        "matrix": {
            f"{row['platform']}/{row['gate_id']}": {
                "check_contract_sha256": row["check_contract_sha256"],
                "receipt_sha256": row["receipt_sha256"],
            }
            for row in sealed_manifest["verification"]["matrix"]
        },
        "installed_metadata_sha256": sealed_manifest["interfaces"][
            "installed_metadata_sha256"
        ],
        "reviewed_exception_receipt_sha256": (
            sealed_manifest["verification"]["rebuild"].get(
                "review_receipt_sha256"
            )
        ),
    }
    if evidence != expected_evidence:
        _fail("release observation evidence does not exactly match manifest")
    if item["dependencies"] != sealed_manifest["dependencies"]:
        _fail("release observation dependencies do not exactly match manifest")
    if (
        item["rebuild_status"]
        != sealed_manifest["verification"]["rebuild"]["status"]
    ):
        _fail("release observation rebuild status does not match manifest")
    return {
        "schema_version": RELEASE_ARTIFACT_OBSERVATION_SCHEMA_VERSION,
        "manifest_sha256": sealed_manifest["manifest_sha256"],
        "git": expected_git,
        "artifacts": sealed_manifest["artifacts"],
        "sbom_sha256": sealed_manifest["sbom"]["sha256"],
        "attestation_sha256": sealed_manifest["attestation"]["sha256"],
        "evidence_files": expected_evidence,
        "dependencies": sealed_manifest["dependencies"],
        "rebuild_status": sealed_manifest["verification"]["rebuild"]["status"],
    }


def _seal_release_observation_receipt(
    receipt: Mapping[str, Any], manifest: Mapping[str, Any]
) -> dict[str, Any]:
    """Seal an already performed observation against one manifest."""

    base = _observation_receipt_base(receipt, manifest)
    try:
        digest = canonical_sha256(
            base, max_bytes=MAX_OBSERVATION_RECEIPT_BYTES
        )
    except SemanticEventError as exc:
        _fail(str(exc))
    return {**base, "observation_receipt_sha256": digest}


def validate_release_observation_receipt(
    receipt: Mapping[str, Any], manifest: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate a sealed observation receipt and its manifest binding."""

    item = _object(
        _clone_json(receipt, maximum=MAX_OBSERVATION_RECEIPT_BYTES),
        _OBSERVATION_SEALED_FIELDS,
        "sealed release observation receipt",
    )
    base = _observation_receipt_base(
        {key: item[key] for key in _OBSERVATION_BASE_FIELDS}, manifest
    )
    try:
        digest = canonical_sha256(
            base, max_bytes=MAX_OBSERVATION_RECEIPT_BYTES
        )
    except SemanticEventError as exc:
        _fail(str(exc))
    if item["observation_receipt_sha256"] != digest:
        _fail("observation_receipt_sha256 does not match observation receipt")
    return {**base, "observation_receipt_sha256": digest}


def _exact_keys(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        _fail(f"{label} does not exactly match release manifest")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"dependency JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def _canonical_json_file(raw: bytes, label: str) -> Any:
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs
        )
        canonical = canonical_json_bytes(value, max_bytes=MAX_OBSERVED_FILE_BYTES)
    except (UnicodeDecodeError, json.JSONDecodeError, SemanticEventError) as exc:
        _fail(f"{label} is not strict bounded JSON: {exc}")
    if raw != canonical:
        _fail(f"{label} is not exact canonical JSON bytes")
    return value


def _builder_environment_receipt(
    raw: bytes, manifest: Mapping[str, Any]
) -> dict[str, Any]:
    value = _canonical_json_file(raw, "builder environment receipt")
    item = _object(
        value,
        _BUILDER_ENVIRONMENT_RECEIPT_FIELDS,
        "builder environment receipt",
    )
    if item["schema_version"] != 1 or isinstance(item["schema_version"], bool):
        _fail("builder environment receipt schema_version is invalid")
    if (
        item["platform"] != manifest["build_environment"]["platform"]
        or item["python_version"]
        != manifest["build_environment"]["python_version"]
        or item["workflow_name"] != manifest["workflow"]["workflow_name"]
        or item["run_id"] != manifest["workflow"]["run_id"]
        or item["run_attempt"] != manifest["workflow"]["run_attempt"]
    ):
        _fail("builder environment receipt does not match release manifest")
    for key in (
        "platform",
        "python_version",
        "workflow_name",
        "run_id",
        "runner_os",
        "runner_arch",
        "runner_image",
        "build_frontend",
        "build_frontend_version",
    ):
        if (
            not isinstance(item[key], str)
            or not item[key]
            or len(item[key]) > 256
            or any(ord(character) < 32 or ord(character) == 127 for character in item[key])
        ):
            _fail(f"builder environment receipt {key} is invalid")
    for key in ("run_attempt", "source_date_epoch"):
        if (
            not isinstance(item[key], int)
            or isinstance(item[key], bool)
            or item[key] < 1
        ):
            _fail(f"builder environment receipt {key} is invalid")
    return item


def _evidence(manifest: Mapping[str, Any], value: Any, root: Path, budget: list[int], paths: set[str]) -> dict[str, Any]:
    evidence = _object(value, _EVIDENCE_FIELDS, "evidence_files")
    producers = {item["producer_id"]: item["result_sha256"] for item in manifest["producer_results"]}
    supplied_producers = _exact_keys(evidence["producer_results"], set(producers), "producer evidence")
    producer_result: dict[str, str] = {}
    for name in sorted(producers):
        spec = _file_spec(supplied_producers[name], f"producer evidence {name}")
        if spec["sha256"] != producers[name]:
            _fail("producer evidence digest does not match release manifest")
        _record_path(paths, spec["path"])
        _checked_file(root, spec, f"producer evidence {name}", budget)
        producer_result[name] = spec["sha256"]
    builder = _file_spec(
        evidence["builder_environment"], "builder environment receipt"
    )
    if (
        builder["sha256"]
        != manifest["build_environment"][
            "builder_environment_receipt_sha256"
        ]
    ):
        _fail("builder environment evidence digest does not match release manifest")
    _record_path(paths, builder["path"])
    _builder_size, _builder_digest, builder_bytes = _checked_file(
        root,
        builder,
        "builder environment receipt",
        budget,
        capture=True,
    )
    assert builder_bytes is not None
    _builder_environment_receipt(builder_bytes, manifest)
    matrix = {f"{item['platform']}/{item['gate_id']}": item for item in manifest["verification"]["matrix"]}
    supplied_matrix = _exact_keys(evidence["matrix"], set(matrix), "matrix evidence")
    matrix_result: dict[str, dict[str, str]] = {}
    for name in sorted(matrix):
        entry = _object(supplied_matrix[name], _MATRIX_EVIDENCE_FIELDS, f"matrix evidence {name}")
        contract = _file_spec(entry["check_contract"], f"matrix contract {name}")
        receipt = _file_spec(entry["receipt"], f"matrix receipt {name}")
        if contract["sha256"] != matrix[name]["check_contract_sha256"] or receipt["sha256"] != matrix[name]["receipt_sha256"]:
            _fail("matrix evidence digest does not match release manifest")
        _record_path(paths, contract["path"]); _record_path(paths, receipt["path"])
        _checked_file(root, contract, f"matrix contract {name}", budget)
        _checked_file(root, receipt, f"matrix receipt {name}", budget)
        matrix_result[name] = {"check_contract_sha256": contract["sha256"], "receipt_sha256": receipt["sha256"]}
    installed = _file_spec(evidence["installed_metadata"], "installed metadata")
    if installed["sha256"] != manifest["interfaces"]["installed_metadata_sha256"]:
        _fail("installed metadata digest does not match release manifest")
    _record_path(paths, installed["path"]); _checked_file(root, installed, "installed metadata", budget)
    rebuild = manifest["verification"]["rebuild"]
    exception = evidence["reviewed_exception_receipt"]
    if rebuild["status"] == "reviewed_exception":
        reviewed = _file_spec(exception, "reviewed exception receipt")
        if reviewed["sha256"] != rebuild["review_receipt_sha256"]:
            _fail("reviewed exception receipt does not match release manifest")
        _record_path(paths, reviewed["path"]); _checked_file(root, reviewed, "reviewed exception receipt", budget)
        reviewed_result: str | None = reviewed["sha256"]
    elif exception is not None:
        _fail("reproducible rebuild must not provide a reviewed exception receipt")
    else:
        reviewed_result = None
    return {
        "producer_results": producer_result,
        "builder_environment_receipt_sha256": builder["sha256"],
        "matrix": matrix_result,
        "installed_metadata_sha256": installed["sha256"],
        "reviewed_exception_receipt_sha256": reviewed_result,
    }


def _record_path(paths: set[str], path: str) -> None:
    identity = path.casefold()
    if identity in paths:
        _fail("observation request reuses a file path")
    if len(paths) >= MAX_EVIDENCE_FILES:
        _fail("observation request exceeds file count bound")
    paths.add(identity)


def _dependencies(manifest: Mapping[str, Any], value: Any, root: Path, budget: list[int], paths: set[str]) -> list[dict[str, str]]:
    expected = {item["name"]: item for item in manifest["dependencies"]}
    supplied = _exact_keys(value, set(expected), "dependency files")
    result: list[dict[str, str]] = []
    for name in sorted(expected):
        pair = _object(supplied[name], _DEPENDENCY_FILE_FIELDS, f"dependency files {name}")
        dependency_manifest_path = _relative_path(pair["release_manifest_path"], f"dependency manifest {name}")
        promotion_path = _relative_path(pair["promotion_receipt_path"], f"dependency promotion {name}")
        declared = expected[name]
        _record_path(paths, dependency_manifest_path); _record_path(paths, promotion_path)
        manifest_size, _, manifest_bytes = _snapshot_file(root, dependency_manifest_path, f"dependency manifest {name}", capture=True)
        promotion_size, _, promotion_bytes = _snapshot_file(root, promotion_path, f"dependency promotion {name}", capture=True)
        budget[0] += (manifest_size + promotion_size) * 2
        if budget[0] > MAX_OBSERVED_TOTAL_BYTES:
            _fail("observed files exceed total byte bound")
        assert manifest_bytes is not None and promotion_bytes is not None
        try:
            loaded_manifest = validate_release_manifest(
                _canonical_json_file(manifest_bytes, f"dependency manifest {name}")
            )
            loaded_promotion = validate_promotion_receipt(
                _canonical_json_file(promotion_bytes, f"dependency promotion {name}"),
                loaded_manifest,
            )
        except (ReleaseManifestError, TypeError) as exc:
            _fail(f"dependency {name} is not a valid manifest/promotion pair: {exc}")
        if (
            loaded_manifest["distribution_name"] != name
            or loaded_manifest["manifest_sha256"] != declared["release_manifest_sha256"]
            or loaded_promotion["promotion_receipt_sha256"] != declared["promotion_receipt_sha256"]
        ):
            _fail(f"dependency {name} sealed pair does not match its raw files")
        result.append({"name": name, "release_manifest_sha256": declared["release_manifest_sha256"], "promotion_receipt_sha256": declared["promotion_receipt_sha256"]})
    return result


def _git(worktree: Path, manifest: Mapping[str, Any], budget: list[int]) -> dict[str, str]:
    def run(*args: str, lower: bool = True) -> str:
        try:
            completed = subprocess.run(["git", "-C", str(worktree), *args], text=True, capture_output=True, check=False, timeout=10)
        except (OSError, subprocess.TimeoutExpired) as exc:
            _fail(f"Git observation failed: {exc}")
        if completed.returncode:
            _fail(f"Git observation failed for {' '.join(args)}: {(completed.stderr or completed.stdout).strip() or 'unknown error'}")
        value = completed.stdout.strip()
        return value.lower() if lower else value
    def run_bytes(*args: str) -> bytes:
        try:
            completed = subprocess.run(
                ["git", "-C", str(worktree), *args],
                capture_output=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            _fail(f"Git observation failed: {exc}")
        if completed.returncode:
            detail = (completed.stderr or completed.stdout).decode(
                "utf-8", errors="replace"
            ).strip()
            _fail(
                f"Git observation failed for {' '.join(args)}: "
                f"{detail or 'unknown error'}"
            )
        if len(completed.stdout) > MAX_OBSERVED_FILE_BYTES:
            _fail("Git observed source exceeds byte bound")
        return completed.stdout
    try:
        reported_root = canonicalize_no_link_traversal(
            Path(run("rev-parse", "--show-toplevel", lower=False)), "Git worktree"
        )
    except HarnessError as exc:
        _fail(str(exc))
    if reported_root != worktree:
        _fail("worktree must be the Git worktree root")
    if run("status", "--porcelain=v2", "-z", "--untracked-files=all", lower=False):
        _fail("Git worktree must be clean for release observation")
    object_format = run("rev-parse", "--show-object-format")
    if object_format != manifest["git_object_format"]:
        _fail("Git object format does not match release manifest")
    expected_length = 40 if object_format == "sha1" else 64
    head = run("rev-parse", "HEAD")
    tree = run("rev-parse", "HEAD^{tree}")
    tag = run("rev-parse", "--verify", f"refs/tags/{manifest['tag']}^{{commit}}")
    if any(len(value) != expected_length or not _OID_RE.fullmatch(value) for value in (head, tree, tag)):
        _fail("Git returned an invalid object id")
    if head != manifest["commit_oid"] or tree != manifest["tree_oid"] or tag != head:
        _fail("Git HEAD, tree, or tag does not match release manifest")
    # Read source through the already observed immutable commit OID.  A later
    # ref movement must not silently switch the version source underneath the
    # receipt.
    version_bytes = run_bytes("show", f"{head}:src/aoi_orgware/_version.py")
    budget[0] += len(version_bytes) * 2
    if budget[0] > MAX_OBSERVED_TOTAL_BYTES:
        _fail("observed files exceed total byte bound")
    try:
        source = version_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        _fail(f"source version is not UTF-8: {exc}")
    matches = _VERSION_RE.findall(source)
    if len(matches) != 1 or matches[0] != manifest["package_version"]:
        _fail("source _version.py does not match release manifest package version")
    object_format_after = run("rev-parse", "--show-object-format")
    head_after = run("rev-parse", "HEAD")
    tree_after = run("rev-parse", "HEAD^{tree}")
    tag_after = run(
        "rev-parse", "--verify", f"refs/tags/{manifest['tag']}^{{commit}}"
    )
    if (
        object_format_after != object_format
        or head_after != head
        or tree_after != tree
        or tag_after != tag
    ):
        _fail("Git refs changed during release observation")
    if run("status", "--porcelain=v2", "-z", "--untracked-files=all", lower=False):
        _fail("Git worktree changed during release observation")
    return {"git_object_format": object_format, "commit_oid": head, "tree_oid": tree, "tag": manifest["tag"], "package_version": matches[0]}


def observe_release_artifacts(request: Mapping[str, Any]) -> dict[str, Any]:
    """Validate existing release bytes and return sealed manifest plus receipt.

    ``artifact_root`` is an existing directory containing every manifest,
    evidence, and dependency path.  All file specifications are relative to
    it.  ``rebuild_root`` is required only for a reproducible rebuild and must
    be a distinct existing directory containing the rebuilt artifact paths.
    """
    try:
        canonical_sha256(request, max_bytes=MAX_OBSERVATION_REQUEST_BYTES)
    except SemanticEventError as exc:
        _fail(str(exc))
    item = _object(request, _REQUEST_FIELDS, "release artifact observation request")
    if item["schema_version"] != RELEASE_ARTIFACT_OBSERVATION_SCHEMA_VERSION or isinstance(item["schema_version"], bool):
        _fail("release artifact observation request schema_version is invalid")
    manifest = _manifest(item["manifest"])
    artifact_root = _root(item["artifact_root"], "artifact_root")
    worktree = _root(item["worktree"], "worktree")
    rebuild_value = item["rebuild_root"]
    rebuild_root: Path | None = None
    if rebuild_value is not None:
        rebuild_root = _root(rebuild_value, "rebuild_root")
        if rebuild_root == artifact_root:
            _fail("rebuild_root must differ from artifact_root")
    budget = [0]
    paths: set[str] = set()
    observed_artifacts: list[dict[str, Any]] = []
    for artifact in manifest["artifacts"]:
        _record_path(paths, artifact["name"])
        size, digest, _ = _snapshot_file(artifact_root, artifact["name"], f"artifact {artifact['name']}")
        budget[0] += size * 2
        if budget[0] > MAX_OBSERVED_TOTAL_BYTES or size != artifact["size_bytes"] or digest != artifact["sha256"]:
            _fail("artifact bytes do not exactly match release manifest")
        observed_artifacts.append({"name": artifact["name"], "size_bytes": size, "sha256": digest})
    for label in ("sbom", "attestation"):
        location = manifest[label]
        _record_path(paths, location["location"])
        size, digest, _ = _snapshot_file(artifact_root, location["location"], label)
        budget[0] += size * 2
        if budget[0] > MAX_OBSERVED_TOTAL_BYTES:
            _fail("observed files exceed total byte bound")
        if digest != location["sha256"]:
            _fail(f"{label} bytes do not exactly match release manifest")
    rebuild = manifest["verification"]["rebuild"]
    if rebuild["status"] == "reproducible":
        if rebuild_root is None:
            _fail("reproducible rebuild requires rebuild_root")
        for artifact in manifest["artifacts"]:
            size, digest, _ = _snapshot_file(rebuild_root, artifact["name"], f"rebuild artifact {artifact['name']}")
            budget[0] += size * 2
            if budget[0] > MAX_OBSERVED_TOTAL_BYTES or size != artifact["size_bytes"] or digest != artifact["sha256"]:
                _fail("rebuild artifact bytes do not exactly match release manifest")
    elif rebuild_root is not None:
        _fail("reviewed exception rebuild must not provide rebuild_root")
    evidence = _evidence(manifest, item["evidence_files"], artifact_root, budget, paths)
    dependencies = _dependencies(manifest, item["dependency_files"], artifact_root, budget, paths)
    git = _git(worktree, manifest, budget)
    receipt_base = {
        "schema_version": RELEASE_ARTIFACT_OBSERVATION_SCHEMA_VERSION,
        "manifest_sha256": manifest["manifest_sha256"],
        "git": git,
        "artifacts": observed_artifacts,
        "sbom_sha256": manifest["sbom"]["sha256"],
        "attestation_sha256": manifest["attestation"]["sha256"],
        "evidence_files": evidence,
        "dependencies": dependencies,
        "rebuild_status": rebuild["status"],
    }
    receipt = _seal_release_observation_receipt(receipt_base, manifest)
    return {"manifest": manifest, "observation_receipt": receipt}


__all__ = [
    "MAX_EVIDENCE_FILES", "MAX_OBSERVED_FILE_BYTES", "MAX_OBSERVED_TOTAL_BYTES",
    "MAX_OBSERVATION_RECEIPT_BYTES", "MAX_OBSERVATION_REQUEST_BYTES",
    "RELEASE_ARTIFACT_OBSERVATION_SCHEMA_VERSION", "ReleaseArtifactError",
    "MAX_SUPPORTING_OBSERVED_READ_BYTES", "observe_release_artifacts",
    "validate_release_observation_receipt",
]
