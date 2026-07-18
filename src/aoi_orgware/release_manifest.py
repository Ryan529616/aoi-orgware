"""Pure, sealed release manifests and promotion receipts (no publication I/O).

A manifest describes the exact tested bytes that may be published.  A promotion
receipt is deliberately a separate record: it binds one sealed manifest to
registry readback and an installed consumer, and models rollback as a new,
compensating promotion reference.  Neither function writes history or contacts
an artifact registry.
"""
from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import PurePosixPath
import re
from typing import Any

from .semantic_events import SemanticEventError, canonical_json_bytes, canonical_sha256


RELEASE_MANIFEST_SCHEMA_VERSION = 1
PROMOTION_RECEIPT_SCHEMA_VERSION = 1
MAX_RELEASE_MANIFEST_BYTES = 256 * 1024
MAX_PROMOTION_RECEIPT_BYTES = 128 * 1024
MAX_ARTIFACTS = 256
MAX_NAMED_RECORDS = 256

_SHA256 = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+!_-]{0,127}")
_GIT_REF_FORBIDDEN_CHARS = frozenset(" ~^:?*[\\")
_WINDOWS_UNSAFE_PATH_CHARS = frozenset('<>:"|?*')
_WINDOWS_RESERVED_DEVICE = re.compile(
    r"(?:con|prn|aux|nul|conin\$|conout\$|clock\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?\Z",
    re.IGNORECASE,
)

_ARTIFACT_FIELDS = {"name", "size_bytes", "sha256"}
_PRODUCER_FIELDS = {"producer_id", "result_sha256"}
_BUILD_ENVIRONMENT_FIELDS = {"platform", "python_version", "builder_image_sha256"}
_WORKFLOW_FIELDS = {"workflow_name", "run_id", "run_attempt"}
_INTERFACE_FIELDS = {
    "console_executable",
    "hook_protocol_version",
    "installed_metadata_sha256",
}
_DEPENDENCY_FIELDS = {"name", "release_manifest_sha256", "promotion_receipt_sha256"}
_MATRIX_FIELDS = {
    "platform",
    "gate_id",
    "check_contract_sha256",
    "receipt_sha256",
    "status",
}
_VERIFICATION_FIELDS = {"matrix", "tested_artifacts", "rebuild"}
_REPRODUCIBLE_REBUILD_FIELDS = {"status", "artifacts"}
_EXCEPTION_REBUILD_FIELDS = {"status", "review_receipt_sha256", "explanation"}
_LOCATION_FIELDS = {"location", "sha256"}
_MANIFEST_BASE_FIELDS = {
    "schema_version",
    "tag",
    "commit_sha256",
    "tree_sha256",
    "package_version",
    "build_environment",
    "workflow",
    "artifacts",
    "producer_results",
    "interfaces",
    "schema_versions",
    "dependencies",
    "verification",
    "sbom",
    "attestation",
}
_MANIFEST_SEALED_FIELDS = _MANIFEST_BASE_FIELDS | {"manifest_sha256"}

_REGISTRY_READBACK_FIELDS = {"artifacts"}
_INSTALLED_FIELDS = {
    "package_version",
    "installed_metadata_sha256",
    "console_executable",
    "hook_protocol_version",
}
_PROMOTED_DEPENDENCY_FIELDS = {"name", "promotion_receipt_sha256"}
_ROLLBACK_FIELDS = {
    "prior_promotion_receipt_sha256",
    "compensating_manifest_sha256",
    "reason",
}
_PROMOTION_BASE_FIELDS = {
    "schema_version",
    "promotion_id",
    "manifest_sha256",
    "registry_readback",
    "installed",
    "dependency_promotions",
    "rollback_provenance",
}
_PROMOTION_SEALED_FIELDS = _PROMOTION_BASE_FIELDS | {"promotion_receipt_sha256"}


class ReleaseManifestError(ValueError):
    """A release manifest, promotion receipt, or their binding is invalid."""


def _fail(message: str) -> None:
    raise ReleaseManifestError(message)


def _clone(value: Any, *, limit: int) -> Any:
    try:
        return json.loads(canonical_json_bytes(value, max_bytes=limit))
    except (SemanticEventError, TypeError, ValueError) as exc:
        raise ReleaseManifestError(str(exc)) from exc


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(f"{label} schema is invalid")
    return dict(value)


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        _fail(f"{label} is not lowercase SHA-256")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        _fail(f"{label} is invalid")
    return value


def _text(value: Any, label: str, *, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        _fail(f"{label} is invalid")
    return value


def _tag(value: Any) -> str:
    tag = _text(value, "tag", limit=128)
    components = tag.split("/")
    if (
        tag == "@"
        or tag.startswith(("refs/", "-", "/", "."))
        or tag.endswith(("/", "."))
        or "" in components
        or any(component.startswith(".") or component.endswith(".lock") for component in components)
        or ".." in tag
        or "@{" in tag
        or any(character in _GIT_REF_FORBIDDEN_CHARS for character in tag)
    ):
        _fail("tag is invalid")
    return tag


def _version(value: Any) -> str:
    if not isinstance(value, str) or not _VERSION.fullmatch(value) or ".." in value:
        _fail("package_version is invalid")
    return value


def _nonnegative_size(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail(f"{label} is invalid")
    return value


def _path_identifier(value: Any, label: str, *, limit: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > limit
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        _fail(f"{label} is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts or str(path) != value or value.endswith("/"):
        _fail(f"{label} is invalid")
    for component in path.parts:
        # These names are legal-looking POSIX paths but are non-portable or
        # redirect to a device/alternate data stream on Windows.  The manifest
        # names bytes that must be identically addressable by both matrix legs.
        try:
            windows_component_units = len(component.encode("utf-16-le")) // 2
        except UnicodeEncodeError:
            _fail(f"{label} is invalid")
        if (
            component.endswith((" ", "."))
            or any(character in _WINDOWS_UNSAFE_PATH_CHARS for character in component)
            or _WINDOWS_RESERVED_DEVICE.fullmatch(component)
            or windows_component_units > 255
        ):
            _fail(f"{label} is invalid")
    return value


def _windows_path_identity(path: str) -> str:
    """Return the Windows case-insensitive identity of an already-safe path."""

    # Components ending in a dot/space are rejected before this point, so a
    # casefolded POSIX spelling is a stable cross-platform collision key.
    return "/".join(component.casefold() for component in PurePosixPath(path).parts)


def _artifact_name(value: Any) -> str:
    return _path_identifier(value, "artifact.name")


def _artifacts(value: Any, label: str = "artifacts") -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > MAX_ARTIFACTS:
        _fail(f"{label} is invalid")
    names: set[str] = set()
    result: list[dict[str, Any]] = []
    for entry in value:
        item = _object(entry, _ARTIFACT_FIELDS, "artifact")
        name = _artifact_name(item["name"])
        identity = _windows_path_identity(name)
        if identity in names:
            _fail(f"{label} contains duplicate artifact names")
        names.add(identity)
        result.append({
            "name": name,
            "size_bytes": _nonnegative_size(item["size_bytes"], "artifact.size_bytes"),
            "sha256": _sha256(item["sha256"], "artifact.sha256"),
        })
    return sorted(result, key=lambda entry: _windows_path_identity(entry["name"]))


def _producer_results(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value or len(value) > MAX_NAMED_RECORDS:
        _fail("producer_results is invalid")
    ids: set[str] = set()
    result: list[dict[str, str]] = []
    for entry in value:
        item = _object(entry, _PRODUCER_FIELDS, "producer_result")
        producer_id = _identifier(item["producer_id"], "producer_result.producer_id")
        if producer_id in ids:
            _fail("producer_results contains duplicate producer_id")
        ids.add(producer_id)
        result.append({"producer_id": producer_id, "result_sha256": _sha256(item["result_sha256"], "producer_result.result_sha256")})
    return sorted(result, key=lambda entry: entry["producer_id"])


def _build_environment(value: Any) -> dict[str, str]:
    item = _object(value, _BUILD_ENVIRONMENT_FIELDS, "build_environment")
    return {
        "platform": _text(item["platform"], "build_environment.platform", limit=128),
        "python_version": _text(item["python_version"], "build_environment.python_version", limit=64),
        "builder_image_sha256": _sha256(item["builder_image_sha256"], "build_environment.builder_image_sha256"),
    }


def _workflow(value: Any) -> dict[str, Any]:
    item = _object(value, _WORKFLOW_FIELDS, "workflow")
    return {
        "workflow_name": _identifier(item["workflow_name"], "workflow.workflow_name"),
        "run_id": _identifier(item["run_id"], "workflow.run_id"),
        "run_attempt": _nonnegative_size(item["run_attempt"], "workflow.run_attempt"),
    }


def _interfaces(value: Any) -> dict[str, Any]:
    item = _object(value, _INTERFACE_FIELDS, "interfaces")
    version = item["hook_protocol_version"]
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        _fail("interfaces.hook_protocol_version is invalid")
    return {
        "console_executable": _identifier(item["console_executable"], "interfaces.console_executable"),
        "hook_protocol_version": version,
        "installed_metadata_sha256": _sha256(
            item["installed_metadata_sha256"], "interfaces.installed_metadata_sha256"
        ),
    }


def _schema_versions(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping) or not value or len(value) > MAX_NAMED_RECORDS:
        _fail("schema_versions is invalid")
    result: dict[str, int] = {}
    for name, version in value.items():
        name = _identifier(name, "schema_versions key")
        if not isinstance(version, int) or isinstance(version, bool) or not 1 <= version <= 1_000_000:
            _fail("schema_versions value is invalid")
        result[name] = version
    return {name: result[name] for name in sorted(result)}


def _dependencies(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > MAX_NAMED_RECORDS:
        _fail("dependencies is invalid")
    names: set[str] = set()
    result: list[dict[str, str]] = []
    for entry in value:
        item = _object(entry, _DEPENDENCY_FIELDS, "dependency")
        name = _identifier(item["name"], "dependency.name")
        if name in names:
            _fail("dependencies contains duplicate names")
        names.add(name)
        result.append({
            "name": name,
            "release_manifest_sha256": _sha256(item["release_manifest_sha256"], "dependency.release_manifest_sha256"),
            "promotion_receipt_sha256": _sha256(item["promotion_receipt_sha256"], "dependency.promotion_receipt_sha256"),
        })
    return sorted(result, key=lambda entry: entry["name"])


def _verification(value: Any, artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    item = _object(value, _VERIFICATION_FIELDS, "verification")
    matrix = item["matrix"]
    if not isinstance(matrix, list) or not matrix or len(matrix) > MAX_NAMED_RECORDS:
        _fail("verification.matrix is invalid")
    seen: set[tuple[str, str]] = set()
    gates_by_platform: dict[str, dict[str, str]] = {"linux": {}, "windows": {}}
    canonical_matrix: list[dict[str, str]] = []
    for entry in matrix:
        record = _object(entry, _MATRIX_FIELDS, "verification.matrix entry")
        platform = record["platform"]
        if platform not in {"linux", "windows"}:
            _fail("verification.matrix platform is invalid")
        gate_id = _identifier(record["gate_id"], "verification.matrix.gate_id")
        if record["status"] != "pass":
            _fail("verification.matrix gate must pass")
        key = (platform, gate_id)
        if key in seen:
            _fail("verification.matrix contains duplicate gates")
        seen.add(key)
        gates_by_platform[platform][gate_id] = _sha256(
            record["check_contract_sha256"],
            "verification.matrix.check_contract_sha256",
        )
        canonical_matrix.append(
            {
                "platform": platform,
                "gate_id": gate_id,
                "check_contract_sha256": gates_by_platform[platform][gate_id],
                "receipt_sha256": _sha256(
                    record["receipt_sha256"], "verification.matrix.receipt_sha256"
                ),
                "status": "pass",
            }
        )
    if not gates_by_platform["linux"] or not gates_by_platform["windows"]:
        _fail("verification.matrix requires linux and windows passing gates")
    if set(gates_by_platform["linux"]) != set(gates_by_platform["windows"]):
        _fail("verification.matrix requires the same named gates on linux and windows")
    if gates_by_platform["linux"] != gates_by_platform["windows"]:
        _fail("verification.matrix requires the same gate contracts on linux and windows")
    tested = _artifacts(item["tested_artifacts"], "verification.tested_artifacts")
    if tested != artifacts:
        _fail("verification.tested_artifacts does not exactly match artifacts")
    rebuild = item["rebuild"]
    if not isinstance(rebuild, Mapping):
        _fail("verification.rebuild is invalid")
    if rebuild.get("status") == "reproducible":
        record = _object(rebuild, _REPRODUCIBLE_REBUILD_FIELDS, "verification.rebuild")
        rebuilt = _artifacts(record["artifacts"], "verification.rebuild.artifacts")
        if rebuilt != artifacts:
            _fail("verification.rebuild artifacts do not exactly match artifacts")
        canonical_rebuild: dict[str, Any] = {"status": "reproducible", "artifacts": rebuilt}
    elif rebuild.get("status") == "reviewed_exception":
        record = _object(rebuild, _EXCEPTION_REBUILD_FIELDS, "verification.rebuild")
        canonical_rebuild = {"status": "reviewed_exception", "review_receipt_sha256": _sha256(record["review_receipt_sha256"], "verification.rebuild.review_receipt_sha256"), "explanation": _text(record["explanation"], "verification.rebuild.explanation", limit=2048)}
    else:
        _fail("verification.rebuild status is invalid")
    return {
        "matrix": sorted(canonical_matrix, key=lambda entry: (entry["platform"], entry["gate_id"])),
        "tested_artifacts": tested,
        "rebuild": canonical_rebuild,
    }


def _location(value: Any, label: str) -> dict[str, str]:
    item = _object(value, _LOCATION_FIELDS, label)
    return {
        "location": _path_identifier(item["location"], f"{label}.location", limit=1024),
        "sha256": _sha256(item["sha256"], f"{label}.sha256"),
    }


def _validate_global_location_uniqueness(
    artifacts: list[dict[str, Any]], sbom: Mapping[str, str], attestation: Mapping[str, str]
) -> None:
    paths = [entry["name"] for entry in artifacts] + [sbom["location"], attestation["location"]]
    identities = [tuple(_windows_path_identity(path).split("/")) for path in paths]
    for index, identity in enumerate(identities):
        for other in identities[:index]:
            shared = min(len(identity), len(other))
            if identity[:shared] == other[:shared]:
                _fail(
                    "artifacts, sbom, and attestation must have globally unique "
                    "non-overlapping paths"
                )


def _manifest_base(value: Any) -> dict[str, Any]:
    item = _object(value, _MANIFEST_BASE_FIELDS, "release manifest")
    if item["schema_version"] != RELEASE_MANIFEST_SCHEMA_VERSION or isinstance(item["schema_version"], bool):
        _fail("release manifest schema_version is invalid")
    artifacts = _artifacts(item["artifacts"])
    sbom = _location(item["sbom"], "sbom")
    attestation = _location(item["attestation"], "attestation")
    _validate_global_location_uniqueness(artifacts, sbom, attestation)
    return {
        "schema_version": RELEASE_MANIFEST_SCHEMA_VERSION,
        "tag": _tag(item["tag"]),
        "commit_sha256": _sha256(item["commit_sha256"], "commit_sha256"),
        "tree_sha256": _sha256(item["tree_sha256"], "tree_sha256"),
        "package_version": _version(item["package_version"]),
        "build_environment": _build_environment(item["build_environment"]),
        "workflow": _workflow(item["workflow"]),
        "artifacts": artifacts,
        "producer_results": _producer_results(item["producer_results"]),
        "interfaces": _interfaces(item["interfaces"]),
        "schema_versions": _schema_versions(item["schema_versions"]),
        "dependencies": _dependencies(item["dependencies"]),
        "verification": _verification(item["verification"], artifacts),
        "sbom": sbom,
        "attestation": attestation,
    }


def release_manifest_sha256(manifest: Mapping[str, Any]) -> str:
    """Return the canonical digest of one exact unsealed release manifest."""

    try:
        return canonical_sha256(_manifest_base(manifest), max_bytes=MAX_RELEASE_MANIFEST_BYTES)
    except SemanticEventError as exc:
        raise ReleaseManifestError(str(exc)) from exc


def seal_release_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and seal a manifest generated from already-tested artifact bytes."""

    base = _manifest_base(_clone(manifest, limit=MAX_RELEASE_MANIFEST_BYTES))
    try:
        base["manifest_sha256"] = canonical_sha256(base, max_bytes=MAX_RELEASE_MANIFEST_BYTES)
    except SemanticEventError as exc:
        raise ReleaseManifestError(str(exc)) from exc
    return base


def validate_release_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a sealed manifest and return a detached canonical copy."""

    item = _object(_clone(manifest, limit=MAX_RELEASE_MANIFEST_BYTES), _MANIFEST_SEALED_FIELDS, "release manifest")
    base = _manifest_base({key: item[key] for key in _MANIFEST_BASE_FIELDS})
    expected = release_manifest_sha256(base)
    if item["manifest_sha256"] != expected:
        _fail("manifest_sha256 does not match release manifest")
    return {**base, "manifest_sha256": expected}


def _registry_readback(value: Any) -> dict[str, Any]:
    item = _object(value, _REGISTRY_READBACK_FIELDS, "registry_readback")
    return {"artifacts": _artifacts(item["artifacts"], "registry_readback.artifacts")}


def _installed(value: Any) -> dict[str, Any]:
    item = _object(value, _INSTALLED_FIELDS, "installed")
    hook_version = item["hook_protocol_version"]
    if not isinstance(hook_version, int) or isinstance(hook_version, bool) or hook_version < 1:
        _fail("installed.hook_protocol_version is invalid")
    return {
        "package_version": _version(item["package_version"]),
        "installed_metadata_sha256": _sha256(item["installed_metadata_sha256"], "installed.installed_metadata_sha256"),
        "console_executable": _identifier(item["console_executable"], "installed.console_executable"),
        "hook_protocol_version": hook_version,
    }


def _dependency_promotions(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > MAX_NAMED_RECORDS:
        _fail("dependency_promotions is invalid")
    names: set[str] = set()
    result: list[dict[str, str]] = []
    for entry in value:
        item = _object(entry, _PROMOTED_DEPENDENCY_FIELDS, "dependency_promotion")
        name = _identifier(item["name"], "dependency_promotion.name")
        if name in names:
            _fail("dependency_promotions contains duplicate names")
        names.add(name)
        result.append({"name": name, "promotion_receipt_sha256": _sha256(item["promotion_receipt_sha256"], "dependency_promotion.promotion_receipt_sha256")})
    return sorted(result, key=lambda entry: entry["name"])


def _rollback_provenance(value: Any, manifest_sha256: str) -> dict[str, str] | None:
    if value is None:
        return None
    item = _object(value, _ROLLBACK_FIELDS, "rollback_provenance")
    compensating = _sha256(item["compensating_manifest_sha256"], "rollback_provenance.compensating_manifest_sha256")
    if compensating != manifest_sha256:
        _fail("rollback_provenance must name this compensating manifest")
    return {
        "prior_promotion_receipt_sha256": _sha256(item["prior_promotion_receipt_sha256"], "rollback_provenance.prior_promotion_receipt_sha256"),
        "compensating_manifest_sha256": compensating,
        "reason": _text(item["reason"], "rollback_provenance.reason", limit=2048),
    }


def _promotion_base(value: Any) -> dict[str, Any]:
    item = _object(value, _PROMOTION_BASE_FIELDS, "promotion receipt")
    if item["schema_version"] != PROMOTION_RECEIPT_SCHEMA_VERSION or isinstance(item["schema_version"], bool):
        _fail("promotion receipt schema_version is invalid")
    manifest_sha = _sha256(item["manifest_sha256"], "manifest_sha256")
    return {
        "schema_version": PROMOTION_RECEIPT_SCHEMA_VERSION,
        "promotion_id": _identifier(item["promotion_id"], "promotion_id"),
        "manifest_sha256": manifest_sha,
        "registry_readback": _registry_readback(item["registry_readback"]),
        "installed": _installed(item["installed"]),
        "dependency_promotions": _dependency_promotions(item["dependency_promotions"]),
        "rollback_provenance": _rollback_provenance(item["rollback_provenance"], manifest_sha),
    }


def _validate_promotion_binding(receipt: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    if receipt["manifest_sha256"] != manifest["manifest_sha256"]:
        _fail("promotion manifest_sha256 does not match manifest")
    if receipt["registry_readback"]["artifacts"] != manifest["artifacts"]:
        _fail("registry readback artifacts do not exactly match manifest")
    installed = receipt["installed"]
    interfaces = manifest["interfaces"]
    if (
        installed["package_version"] != manifest["package_version"]
        or installed["installed_metadata_sha256"] != interfaces["installed_metadata_sha256"]
        or installed["console_executable"] != interfaces["console_executable"]
        or installed["hook_protocol_version"] != interfaces["hook_protocol_version"]
    ):
        _fail("installed consumer does not exactly match manifest interface")
    expected_dependencies = [
        {"name": item["name"], "promotion_receipt_sha256": item["promotion_receipt_sha256"]}
        for item in manifest["dependencies"]
    ]
    if receipt["dependency_promotions"] != expected_dependencies:
        _fail("dependency promotions do not exactly match promoted manifest dependencies")


def promotion_receipt_sha256(receipt: Mapping[str, Any]) -> str:
    """Return the canonical digest of an unsealed promotion receipt."""

    try:
        return canonical_sha256(_promotion_base(receipt), max_bytes=MAX_PROMOTION_RECEIPT_BYTES)
    except SemanticEventError as exc:
        raise ReleaseManifestError(str(exc)) from exc


def seal_promotion_receipt(receipt: Mapping[str, Any], manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Seal one promotion after binding its readback to the exact sealed manifest."""

    base = _promotion_base(_clone(receipt, limit=MAX_PROMOTION_RECEIPT_BYTES))
    sealed_manifest = validate_release_manifest(manifest)
    _validate_promotion_binding(base, sealed_manifest)
    try:
        base["promotion_receipt_sha256"] = canonical_sha256(base, max_bytes=MAX_PROMOTION_RECEIPT_BYTES)
    except SemanticEventError as exc:
        raise ReleaseManifestError(str(exc)) from exc
    return base


def validate_promotion_receipt(
    receipt: Mapping[str, Any], manifest: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate a sealed receipt and its mandatory binding to one sealed manifest."""

    item = _object(_clone(receipt, limit=MAX_PROMOTION_RECEIPT_BYTES), _PROMOTION_SEALED_FIELDS, "promotion receipt")
    base = _promotion_base({key: item[key] for key in _PROMOTION_BASE_FIELDS})
    expected = promotion_receipt_sha256(base)
    if item["promotion_receipt_sha256"] != expected:
        _fail("promotion_receipt_sha256 does not match promotion receipt")
    result = {**base, "promotion_receipt_sha256": expected}
    _validate_promotion_binding(result, validate_release_manifest(manifest))
    return result


__all__ = [
    "MAX_ARTIFACTS",
    "MAX_PROMOTION_RECEIPT_BYTES",
    "MAX_RELEASE_MANIFEST_BYTES",
    "PROMOTION_RECEIPT_SCHEMA_VERSION",
    "RELEASE_MANIFEST_SCHEMA_VERSION",
    "ReleaseManifestError",
    "promotion_receipt_sha256",
    "release_manifest_sha256",
    "seal_promotion_receipt",
    "seal_release_manifest",
    "validate_promotion_receipt",
    "validate_release_manifest",
]
