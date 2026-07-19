#!/usr/bin/env python3
"""Fail-closed, post-publication PyPI readback for one sealed AOI release.

This is deliberately outside the AOI lifecycle: it only observes PyPI and
creates a candidate promotion receipt.  A Chief-fenced caller decides whether
that candidate becomes a semantic promotion.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

# Direct execution from a source checkout must use that checkout's contracts,
# even when AOI is not installed in the invoking interpreter.
REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPO_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from aoi_orgware.release_artifacts import (
    ReleaseArtifactError,
    validate_release_observation_receipt,
)
from aoi_orgware.release_manifest import (
    MAX_ARTIFACT_BYTES,
    MAX_ARTIFACT_AGGREGATE_BYTES,
    ReleaseManifestError,
    seal_promotion_receipt,
    validate_release_manifest,
)
from aoi_orgware.semantic_events import SemanticEventError, canonical_json_bytes


MAX_INPUT_BYTES = 512 * 1024
MAX_PROVENANCE_BYTES = 4 * 1024 * 1024
NETWORK_TIMEOUT_SECONDS = 30
PYPI_API_HOST = "pypi.org"
PYPI_FILE_HOST = "files.pythonhosted.org"
_PYPI_JSON_PREFIX = "https://pypi.org/pypi/"
ATTESTATION_EVIDENCE_STRENGTH = "presence_only"


class ReleaseReadbackError(RuntimeError):
    """A release could not be proven present and installable from PyPI."""


Fetcher = Callable[[str, int], bytes]
Runner = Callable[[Sequence[str | os.PathLike[str]], Path, Mapping[str, str]], subprocess.CompletedProcess[str]]


def _fail(message: str) -> None:
    raise ReleaseReadbackError(message)


def _duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail(f"JSON contains duplicate key {key!r}")
        value[key] = item
    return value


def _is_reparse_point(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_nlink,
        getattr(info, "st_file_attributes", 0),
    )


def _canonical_json(raw: bytes, label: str, *, maximum: int = MAX_INPUT_BYTES) -> Any:
    if not isinstance(raw, bytes) or len(raw) > maximum:
        _fail(f"{label} exceeds its byte bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicate_pairs)
        canonical = canonical_json_bytes(value, max_bytes=maximum)
    except (UnicodeDecodeError, json.JSONDecodeError, SemanticEventError) as exc:
        _fail(f"{label} is not bounded canonical JSON: {exc}")
    if raw != canonical:
        _fail(f"{label} is not exact canonical JSON bytes")
    return value


def _remote_json(raw: bytes, label: str, *, maximum: int = MAX_INPUT_BYTES) -> Any:
    """Parse bounded remote JSON strictly; PyPI does not promise canonical bytes."""

    if not isinstance(raw, bytes) or len(raw) > maximum:
        _fail(f"{label} exceeds its byte bound")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"{label} is not strict UTF-8 JSON: {exc}")


def read_canonical_json_file(path: Path, label: str, *, maximum: int = MAX_INPUT_BYTES) -> Any:
    """Read one stable, regular, non-link canonical JSON input file."""

    path = Path(os.path.abspath(path))
    try:
        resolved = path.resolve(strict=True)
        before = path.lstat()
        if os.path.normcase(str(path)) != os.path.normcase(str(resolved)):
            _fail(f"{label} path must not traverse a link or alias")
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or _is_reparse_point(before)
        ):
            _fail(f"{label} must be a regular non-link file")
        if before.st_nlink != 1 or before.st_size > maximum:
            _fail(f"{label} exceeds its byte bound")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            opened = os.fstat(handle.fileno())
            identity = _identity(before)
            if _is_reparse_point(opened) or _identity(opened) != identity:
                _fail(f"{label} changed while opening")
            raw = handle.read(maximum + 1)
        after = path.lstat()
    except OSError as exc:
        _fail(f"cannot read {label}: {exc}")
    if _identity(after) != identity:
        _fail(f"{label} changed while being read")
    return _canonical_json(raw, label, maximum=maximum)


def https_fetch(url: str, maximum: int) -> bytes:
    """Fetch only the two PyPI HTTPS origins, with an explicit byte ceiling."""

    parsed = urllib.parse.urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        _fail("readback fetch URL has an invalid port")
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.hostname not in {PYPI_API_HOST, PYPI_FILE_HOST}
    ):
        _fail("readback fetch URL is not an allowed PyPI HTTPS origin")
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1:
        _fail("readback fetch byte bound is invalid")
    try:
        accept = (
            "application/vnd.pypi.integrity.v1+json"
            if parsed.hostname == PYPI_API_HOST and parsed.path.startswith("/integrity/")
            else "application/json"
        )
        request = urllib.request.Request(url, headers={"Accept": accept})
        with urllib.request.urlopen(request, timeout=NETWORK_TIMEOUT_SECONDS) as response:
            raw = response.read(maximum + 1)
    except OSError as exc:
        _fail(f"PyPI fetch failed: {exc}")
    if len(raw) > maximum:
        _fail("PyPI response exceeds byte bound")
    return raw


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{label} must be an object")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a non-empty string")
    return value


def _artifact_filename(name: str) -> str:
    path = PurePosixPath(name)
    if path.name != name.split("/")[-1] or path.name in {"", ".", ".."}:
        _fail("release manifest artifact name is not a portable file path")
    return path.name


def _expected_artifacts(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    items = manifest["artifacts"]
    if not isinstance(items, list) or len(items) != 2:
        _fail("PyPI readback requires exactly one wheel and one sdist in the manifest")
    result: dict[str, Mapping[str, Any]] = {}
    kinds: set[str] = set()
    for item in items:
        artifact = _mapping(item, "manifest artifact")
        filename = _artifact_filename(_string(artifact.get("name"), "manifest artifact name"))
        if filename in result:
            _fail("release manifest has duplicate PyPI artifact filenames")
        if filename.endswith(".whl"):
            kinds.add("wheel")
        elif filename.endswith(".tar.gz"):
            kinds.add("sdist")
        else:
            _fail("PyPI readback manifest artifact is neither wheel nor sdist")
        result[filename] = artifact
    if kinds != {"wheel", "sdist"}:
        _fail("PyPI readback requires exactly one wheel and one sdist")
    return result


def validate_pypi_document(manifest: Mapping[str, Any], document: Any) -> dict[str, Mapping[str, Any]]:
    """Pure validation of PyPI JSON metadata against the sealed manifest."""

    item = _mapping(document, "PyPI JSON")
    info = _mapping(item.get("info"), "PyPI JSON info")
    if _string(info.get("name"), "PyPI project name") != manifest["distribution_name"]:
        _fail("PyPI project does not exactly match release manifest")
    if _string(info.get("version"), "PyPI project version") != manifest["package_version"]:
        _fail("PyPI project version does not exactly match release manifest")
    urls = item.get("urls")
    if not isinstance(urls, list):
        _fail("PyPI JSON urls must be a list")
    expected = _expected_artifacts(manifest)
    found: dict[str, Mapping[str, Any]] = {}
    for raw in urls:
        file_info = _mapping(raw, "PyPI release file")
        filename = _string(file_info.get("filename"), "PyPI release filename")
        if filename in found:
            _fail("PyPI release contains duplicate filenames")
        found[filename] = file_info
    if set(found) != set(expected):
        _fail("PyPI release files do not exactly match the release manifest")
    for filename, artifact in expected.items():
        file_info = found[filename]
        size = file_info.get("size")
        digests = _mapping(file_info.get("digests"), f"PyPI digest for {filename}")
        digest = _string(digests.get("sha256"), f"PyPI SHA-256 for {filename}")
        if size != artifact["size_bytes"] or digest != artifact["sha256"]:
            _fail(f"PyPI size or SHA-256 does not match manifest for {filename}")
        expected_type = "bdist_wheel" if filename.endswith(".whl") else "sdist"
        if file_info.get("packagetype") != expected_type:
            _fail(f"PyPI package type does not match filename for {filename}")
        url = _string(file_info.get("url"), f"PyPI download URL for {filename}")
        parsed = urllib.parse.urlsplit(url)
        try:
            port = parsed.port
        except ValueError:
            _fail(f"PyPI download URL has an invalid port for {filename}")
        if parsed.scheme != "https" or parsed.hostname != PYPI_FILE_HOST or port not in (None, 443):
            _fail(f"PyPI download URL is not files.pythonhosted.org HTTPS for {filename}")
    return {name: found[name] for name in sorted(found)}


def validate_integrity_provenance_presence(
    document: Any,
    *,
    filename: str,
    sha256: str,
    trusted_publisher_repository: str,
    trusted_publisher_workflow: str,
) -> dict[str, str | bool]:
    """Collect *presence-only* Integrity API evidence for exact downloaded bytes.

    PyPI's official Integrity API serves provenance objects and directs consumers
    to extract and verify individual attestations as appropriate.  This script
    performs bounded structural validation only: it binds a publish predicate,
    trusted-publisher identity, filename, and SHA-256 to the downloaded artifact.
    It deliberately performs no DSSE, certificate, Rekor, or Sigstore verification.
    """

    provenance = _mapping(document, "PyPI integrity provenance")
    if provenance.get("version") != 1:
        _fail("PyPI integrity provenance version is invalid")
    bundles = provenance.get("attestation_bundles")
    if not isinstance(bundles, list) or not bundles:
        _fail(f"PyPI integrity provenance is missing attestations for {filename}")
    matched = False
    for raw_bundle in bundles:
        bundle = _mapping(raw_bundle, "PyPI attestation bundle")
        publisher = _mapping(bundle.get("publisher"), "PyPI attestation publisher")
        if (
            publisher.get("kind") != "GitHub"
            or publisher.get("repository") != trusted_publisher_repository
            or publisher.get("workflow") != trusted_publisher_workflow
            or publisher.get("environment") != "pypi"
        ):
            continue
        attestations = bundle.get("attestations")
        if not isinstance(attestations, list) or not attestations:
            continue
        for raw_attestation in attestations:
            attestation = _mapping(raw_attestation, "PyPI attestation")
            envelope = _mapping(attestation.get("envelope"), "PyPI attestation envelope")
            signature = envelope.get("signature")
            encoded_statement = envelope.get("statement")
            verification_material = attestation.get("verification_material")
            if (
                attestation.get("version") != 1
                or not isinstance(signature, str)
                or not signature
                or not isinstance(encoded_statement, str)
                or not encoded_statement
                or not isinstance(verification_material, Mapping)
                or not verification_material
            ):
                continue
            try:
                statement_raw = base64.b64decode(encoded_statement, validate=True)
                statement = _remote_json(
                    statement_raw,
                    "PyPI attestation statement",
                    maximum=MAX_INPUT_BYTES,
                )
            except (ValueError, binascii.Error):
                continue
            statement = _mapping(statement, "PyPI attestation statement")
            if statement.get("_type") != "https://in-toto.io/Statement/v1":
                continue
            if statement.get("predicateType") != "https://docs.pypi.org/attestations/publish/v1":
                continue
            # The publish attestation has no payload beyond its typed subject.
            # Accept the documented null form and an explicitly empty object,
            # but do not treat an arbitrary predicate as equivalent.
            if statement.get("predicate") not in (None, {}):
                continue
            subjects = statement.get("subject")
            if not isinstance(subjects, list) or len(subjects) != 1:
                continue
            subject = _mapping(subjects[0], "PyPI attestation subject")
            digest = _mapping(subject.get("digest"), "PyPI attestation subject digest")
            if subject.get("name") == filename and digest.get("sha256") == sha256:
                matched = True
                break
        if matched:
            break
    if not matched:
        _fail(
            f"PyPI integrity provenance does not bind {filename} to the trusted publisher"
        )
    return {
        "artifact_filename": filename,
        "artifact_sha256": sha256,
        "provenance_sha256": hashlib.sha256(
            canonical_json_bytes(provenance, max_bytes=MAX_PROVENANCE_BYTES)
        ).hexdigest(),
        "evidence_strength": ATTESTATION_EVIDENCE_STRENGTH,
        "cryptographically_verified": False,
    }


def download_exact_artifacts(
    manifest: Mapping[str, Any], files: Mapping[str, Mapping[str, Any]], fetch: Fetcher
) -> dict[str, bytes]:
    """Download and hash the exact PyPI bytes after pure metadata validation."""

    expected = _expected_artifacts(manifest)
    total = 0
    result: dict[str, bytes] = {}
    for filename in sorted(expected):
        artifact = expected[filename]
        size = artifact["size_bytes"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 1 or size > MAX_ARTIFACT_BYTES:
            _fail(f"manifest artifact size is invalid for {filename}")
        total += size
        if total > MAX_ARTIFACT_AGGREGATE_BYTES:
            _fail("manifest artifacts exceed aggregate byte bound")
        raw = fetch(_string(files[filename].get("url"), f"PyPI download URL for {filename}"), size)
        if not isinstance(raw, bytes) or len(raw) != size:
            _fail(f"downloaded PyPI bytes have wrong size for {filename}")
        if hashlib.sha256(raw).hexdigest() != artifact["sha256"]:
            _fail(f"downloaded PyPI bytes have wrong SHA-256 for {filename}")
        result[filename] = raw
    return result


def _write_download(path: Path, raw: bytes, *, expected_sha256: str) -> Path:
    """Create one regular download file, then rehash its exact on-disk bytes."""

    path = path.resolve(strict=False)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        _fail(f"cannot stage downloaded artifact {path.name}: {exc}")
    try:
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or _is_reparse_point(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != len(raw)
        ):
            _fail(f"staged downloaded artifact is not a stable regular file: {path.name}")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            opened = os.fstat(handle.fileno())
            if _is_reparse_point(opened) or _identity(opened) != _identity(before):
                _fail(f"staged downloaded artifact changed while opening: {path.name}")
            digest = hashlib.sha256(handle.read()).hexdigest()
        after = path.lstat()
    except OSError as exc:
        _fail(f"cannot verify staged downloaded artifact {path.name}: {exc}")
    if _identity(after) != _identity(before) or digest != expected_sha256:
        _fail(f"staged downloaded artifact does not match its exact SHA-256: {path.name}")
    return path.resolve(strict=True)


def _isolated_env() -> dict[str, str]:
    env = os.environ.copy()
    for variable in tuple(env):
        if variable.startswith(("PIP_", "PYTHON")) or variable == "VIRTUAL_ENV":
            env.pop(variable, None)
    env.update({
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
    })
    return env


def _venv_executable(environment: Path, name: str) -> Path:
    return environment / ("Scripts" if os.name == "nt" else "bin") / (f"{name}.exe" if os.name == "nt" else name)


_PROBE = r'''
import hashlib, importlib.metadata, json, sys
from pathlib import Path
import aoi_orgware.cli as cli
name = sys.argv[1]
dist = importlib.metadata.distribution(name)
metadata = next((f for f in (dist.files or ()) if str(f).endswith('.dist-info/METADATA')), None)
if metadata is None: raise SystemExit('distribution METADATA is missing')
metadata_path = Path(dist.locate_file(metadata)).resolve()
package_path = Path(__import__('aoi_orgware').__file__).resolve()
entry_points = {ep.name: ep.value for ep in dist.entry_points if ep.group == 'console_scripts'}
root = Path(sys.prefix).resolve()
if not metadata_path.is_relative_to(root) or not package_path.is_relative_to(root):
    raise SystemExit('package or metadata loaded outside isolated environment')
print(json.dumps({'version': importlib.metadata.version(name), 'metadata_path': str(metadata_path), 'hook_protocol_version': int(cli.HOOK_PROTOCOL_VERSION), 'entry_points': entry_points}, sort_keys=True, separators=(',', ':')))
'''


def _run(command: Sequence[str | os.PathLike[str]], cwd: Path, env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run([os.fspath(part) for part in command], cwd=cwd, env=dict(env), text=True, capture_output=True, check=False, timeout=180)
    except (OSError, subprocess.SubprocessError) as exc:
        _fail(f"isolated installation command failed: {exc}")
    if result.returncode:
        _fail(f"isolated installation command failed ({result.returncode}): {result.stderr or result.stdout}")
    return result


def verify_isolated_install(
    manifest: Mapping[str, Any], downloads: Mapping[str, bytes], *, runner: Runner = _run, temporary_directory: Path | None = None
) -> dict[str, Any]:
    """Install the downloaded exact wheel in a disposable venv and probe it."""

    expected = _expected_artifacts(manifest)
    wheel = next(name for name in expected if name.endswith(".whl"))
    context = tempfile.TemporaryDirectory(prefix="aoi-pypi-readback-", dir=temporary_directory)
    try:
        root = Path(context.name).resolve()
        artifacts = root / "artifacts"; artifacts.mkdir()
        for filename, raw in downloads.items():
            artifact = expected.get(filename)
            if artifact is None:
                _fail(f"download set contains unexpected artifact: {filename}")
            _write_download(artifacts / filename, raw, expected_sha256=artifact["sha256"])
        if set(downloads) != set(expected):
            _fail("download set does not exactly match release manifest")
        environment = root / "environment"
        env = _isolated_env()
        runner([sys.executable, "-m", "venv", environment], root, env)
        python = _venv_executable(environment, "python")
        wheel_path = (artifacts / wheel).resolve(strict=True)
        if not wheel_path.is_absolute() or not wheel_path.is_relative_to(artifacts.resolve()):
            _fail("exact wheel path is outside isolated artifact directory")
        runner([
            python,
            "-m",
            "pip",
            "install",
            "--isolated",
            "--no-deps",
            "--only-binary=:all:",
            "--no-index",
            "--no-cache-dir",
            wheel_path,
        ], root, env)
        probe = runner([python, "-I", "-c", _PROBE, manifest["distribution_name"]], root, env)
        try:
            observed = json.loads(probe.stdout, object_pairs_hook=_duplicate_pairs)
        except (json.JSONDecodeError, TypeError) as exc:
            _fail(f"isolated install probe returned invalid JSON: {exc}")
        observed = _mapping(observed, "isolated install probe")
        if observed.get("version") != manifest["package_version"]:
            _fail("isolated installed version does not match manifest")
        if observed.get("hook_protocol_version") != manifest["interfaces"]["hook_protocol_version"]:
            _fail("isolated hook protocol does not match manifest")
        entry_points = _mapping(observed.get("entry_points"), "isolated console entry points")
        expected_entry_points = {
            manifest["interfaces"]["console_entry_point"]["name"]: manifest["interfaces"]["console_entry_point"]["target"],
            manifest["interfaces"]["codex_hook_entry_point"]["name"]: manifest["interfaces"]["codex_hook_entry_point"]["target"],
        }
        if any(entry_points.get(name) != target for name, target in expected_entry_points.items()):
            _fail("isolated console entry points do not match manifest")
        metadata_path = Path(_string(observed.get("metadata_path"), "isolated metadata path")).resolve()
        try:
            if not metadata_path.is_relative_to(environment.resolve()):
                _fail("isolated metadata path is outside virtual environment")
            metadata = metadata_path.read_bytes()
        except OSError as exc:
            _fail(f"cannot read isolated installed metadata: {exc}")
        digest = hashlib.sha256(metadata).hexdigest()
        if digest != manifest["interfaces"]["installed_metadata_sha256"]:
            _fail("isolated installed metadata SHA-256 does not match manifest")
        console_name = manifest["interfaces"]["console_entry_point"]["name"]
        hook_name = manifest["interfaces"]["codex_hook_entry_point"]["name"]
        console = _venv_executable(environment, console_name)
        hook = _venv_executable(environment, hook_name)
        try:
            for executable in (console, hook):
                if not executable.is_file() or not executable.resolve().is_relative_to(environment.resolve()):
                    _fail("isolated console executable is absent or outside virtual environment")
        except OSError as exc:
            _fail(f"cannot inspect isolated console executable: {exc}")
        console_version = runner([console, "--version"], root, env).stdout.strip()
        if console_version != f"AOI {manifest['package_version']}":
            _fail("isolated console executable does not report the manifest version")
        runner([hook, "--help"], root, env)
        return {"installed_metadata_sha256": digest, "console_entry_point": manifest["interfaces"]["console_entry_point"], "codex_hook_entry_point": manifest["interfaces"]["codex_hook_entry_point"], "hook_protocol_version": observed["hook_protocol_version"]}
    finally:
        context.cleanup()


def readback_pypi_release(
    manifest: Mapping[str, Any], observation_receipt: Mapping[str, Any], *, promotion_id: str, observed_at: str, trusted_publisher_repository: str, trusted_publisher_workflow: str, fetch: Fetcher = https_fetch, runner: Runner = _run, temporary_directory: Path | None = None
) -> dict[str, Any]:
    """Run readback and return a promotion candidate plus bounded attestation evidence.

    ``attestation_evidence`` is intentionally outside the strict promotion receipt
    schema.  It is structural, presence-only evidence and must not be represented
    as a cryptographically verified attestation in semantic release state.
    """

    try:
        sealed = validate_release_manifest(manifest)
        observation = validate_release_observation_receipt(observation_receipt, sealed)
    except (ReleaseManifestError, ReleaseArtifactError) as exc:
        _fail(str(exc))
    endpoint = _PYPI_JSON_PREFIX + urllib.parse.quote(sealed["distribution_name"], safe="-") + "/" + urllib.parse.quote(sealed["package_version"], safe=".+") + "/json"
    document = _remote_json(fetch(endpoint, MAX_INPUT_BYTES), "PyPI JSON", maximum=MAX_INPUT_BYTES)
    files = validate_pypi_document(sealed, document)
    expected = _expected_artifacts(sealed)
    downloads = download_exact_artifacts(sealed, files, fetch)
    attestation_evidence: list[dict[str, str | bool]] = []
    for filename in sorted(expected):
        provenance_endpoint = (
            "https://pypi.org/integrity/"
            + urllib.parse.quote(sealed["distribution_name"], safe="-")
            + "/"
            + urllib.parse.quote(sealed["package_version"], safe=".+")
            + "/"
            + urllib.parse.quote(filename, safe="._-")
            + "/provenance"
        )
        provenance = _remote_json(
            fetch(provenance_endpoint, MAX_PROVENANCE_BYTES),
            f"PyPI integrity provenance for {filename}",
            maximum=MAX_PROVENANCE_BYTES,
        )
        attestation_evidence.append(validate_integrity_provenance_presence(
            provenance,
            filename=filename,
            sha256=hashlib.sha256(downloads[filename]).hexdigest(),
            trusted_publisher_repository=trusted_publisher_repository,
            trusted_publisher_workflow=trusted_publisher_workflow,
        ))
    installed = verify_isolated_install(sealed, downloads, runner=runner, temporary_directory=temporary_directory)
    try:
        promotion_receipt = seal_promotion_receipt({
            "schema_version": 1,
            "promotion_id": promotion_id,
            "manifest_sha256": sealed["manifest_sha256"],
            "artifact_observation_receipt_sha256": observation["observation_receipt_sha256"],
            "registry_readback": {"registry": "https://pypi.org", "project": sealed["distribution_name"], "package_version": sealed["package_version"], "observed_at": observed_at, "artifacts": sealed["artifacts"]},
            "installed": {"distribution_name": sealed["distribution_name"], "package_version": sealed["package_version"], "observed_at": observed_at, **installed},
            "dependency_promotions": [{"name": item["name"], "promotion_receipt_sha256": item["promotion_receipt_sha256"]} for item in sealed["dependencies"]],
            "rollback_provenance": None,
        }, sealed)
    except ReleaseManifestError as exc:
        _fail(str(exc))
    return {
        "schema_version": 1,
        "promotion_receipt": promotion_receipt,
        "attestation_evidence": {
            "evidence_strength": ATTESTATION_EVIDENCE_STRENGTH,
            "cryptographically_verified": False,
            "artifacts": attestation_evidence,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--observation-result-file",
        type=Path,
        required=True,
        help="exact canonical output from aoi release-manifest-observe",
    )
    parser.add_argument("--promotion-id", required=True)
    parser.add_argument("--observed-at", required=True, help="canonical UTC timestamp with six fractional digits")
    parser.add_argument("--trusted-publisher-repository", required=True)
    parser.add_argument("--trusted-publisher-workflow", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        observation_result = read_canonical_json_file(
            args.observation_result_file, "sealed release observation result"
        )
        if not isinstance(observation_result, Mapping) or set(observation_result) != {
            "manifest",
            "observation_receipt",
        }:
            _fail("observation result must contain exactly manifest and observation_receipt")
        manifest = observation_result["manifest"]
        observation = observation_result["observation_receipt"]
        result = readback_pypi_release(
            manifest,
            observation,
            promotion_id=args.promotion_id,
            observed_at=args.observed_at,
            trusted_publisher_repository=args.trusted_publisher_repository,
            trusted_publisher_workflow=args.trusted_publisher_workflow,
        )
        sys.stdout.buffer.write(canonical_json_bytes(result, max_bytes=MAX_INPUT_BYTES))
    except (ReleaseReadbackError, OSError, SemanticEventError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
