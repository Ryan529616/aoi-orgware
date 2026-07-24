"""Run one bounded Codex transport canary in a disposable local repository.

This driver never issues authority.  It consumes an already issued one-shot
transport permit, refuses non-disposable or remotely connected repositories,
and separates read-only runtime evidence from writable Git-mutation evidence.
The default is preflight-only; ``--execute`` is required to start App Server.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import threading
import tomllib
from typing import Any, Mapping, Sequence
from urllib.parse import unquote, urlsplit
import zipfile


SCHEMA_VERSION = "aoi.codex-transport-canary.v4"
ROOT_MARKER = ".aoi-codex-transport-canary.json"
ROOT_MARKER_SCHEMA = "aoi.codex-transport-canary-root.v1"
_MODES = {
    "read_only": "readOnly",
    "workspace_write": "workspaceWrite",
}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_FILES = 4096
_MAX_ENTRIES = 8192
_MAX_FILE_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_EXECUTABLE_BYTES = 1024 * 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024
_MAX_PACKAGE_RECEIPT_BYTES = 1024 * 1024
_MAX_WHEEL_BYTES = 256 * 1024 * 1024
_MAX_WHEEL_ENTRIES = 4096
_MAX_WHEEL_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
_MAX_WHEEL_COMPRESSION_RATIO = 128
_MAX_RECORD_BYTES = 2 * 1024 * 1024
_MAX_RECORD_ROWS = 4096
_MAX_INSTALLED_FILES = 4096
_MAX_INSTALLED_BYTES = 64 * 1024 * 1024
_LOCAL_FILES_MAX_BYTES = 1_048_576
_ROOT_MARKER_MAX_BYTES = 4096
_CONSOLE_SCRIPT_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,127})")
_EXPECTED_CONSOLE_SCRIPTS = {
    "aoi": "aoi_orgware.cli:main",
    "aoi-claude-hook": "aoi_orgware.claude_hook:main",
    "aoi-codex-bridge": "aoi_orgware.codex_transport_cli:main",
    "aoi-codex-hook": "aoi_orgware.codex_hook:main",
}
_BRIDGE_MODULE_BOOTSTRAP = (
    "import sys;"
    "site_packages=sys.argv[1];"
    "sys.path.append(site_packages);"
    "from aoi_orgware.codex_transport_cli import main;"
    "raise SystemExit(main(sys.argv[2:]))"
)
_PYVENV_CONFIG_KEYS = frozenset(
    {
        "home",
        "include-system-site-packages",
        "version",
        "executable",
        "command",
        "prompt",
    }
)
_LOCAL_FILES_HOME_NAMES = frozenset(
    {"auth.json", "config.toml", "managed_config.toml"}
)
_LOCAL_FILES_CONFIG = {
    "web_search": "disabled",
    "features": {
        "apps": False,
        "remote_plugin": False,
        "multi_agent": False,
    },
    "apps": {"_default": {"enabled": False}},
}
_LOCAL_FILES_MANAGED_CONFIG = {
    "allow_remote_control": False,
    "allowed_web_search_modes": [],
    "features": {
        "apps": False,
        "remote_plugin": False,
        "multi_agent": False,
    },
}
_LOCAL_FILES_THREAD_CONFIG = {
    "web_search": "disabled",
    "features": {
        "apps": False,
        "remote_plugin": False,
        "multi_agent": False,
    },
    "apps": {"_default": {"enabled": False}},
}
_AOI_SECRET_ENV_PREFIXES = ("AOI_CHIEF_", "AOI_ROOT_", "AOI_CREDENTIAL_")
_AOI_SECRET_ENV_NAMES = frozenset(
    {"AOI_CHIEF_SESSION_ID", "AOI_CHIEF_EPOCH", "AOI_CHIEF_CREDENTIAL_FILE"}
)
_PYTHON_RUNTIME_ENV_NAMES = frozenset(
    {"VIRTUAL_ENV", "VIRTUAL_ENV_PROMPT", "__PYVENV_LAUNCHER__"}
)
_PUBLISH_CREDENTIAL_NAMES = frozenset(
    {
        "GH_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_PAT",
        "GITHUB_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_RUNTIME_TOKEN",
        "ACTIONS_RUNTIME_URL",
        "ACTIONS_RESULTS_URL",
        "ACTIONS_CACHE_URL",
        "CI_JOB_TOKEN",
        "GITLAB_PRIVATE_TOKEN",
        "GITLAB_TOKEN",
        "AZURE_DEVOPS_EXT_PAT",
        "SYSTEM_ACCESSTOKEN",
        "AZURE_ARTIFACTS_ENV_ACCESS_TOKEN",
        "VSS_NUGET_EXTERNAL_FEED_ENDPOINTS",
        "NPM_TOKEN",
        "NODE_AUTH_TOKEN",
        "NUGET_AUTH_TOKEN",
        "CARGO_REGISTRY_TOKEN",
        "RUBYGEMS_API_KEY",
        "GEM_HOST_API_KEY",
        "PYPI_TOKEN",
        "TWINE_PASSWORD",
        "HF_TOKEN",
        "HUGGING_FACE_HUB_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AZURE_STORAGE_CONNECTION_STRING",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "DOCKER_AUTH_CONFIG",
        "DOCKER_PASSWORD",
        "REGISTRY_AUTH_FILE",
    }
)
_PUBLISH_CREDENTIAL_PREFIXES = ("TWINE_", "PYPI_", "ARTIFACTORY_", "JFROG_")
_SSH_CONTROL_ENV_NAMES = frozenset(
    {
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
    }
)
_LOCAL_GIT_CONFIG_KEYS = frozenset(
    {
        "core.repositoryformatversion",
        "core.filemode",
        "core.bare",
        "core.logallrefupdates",
        "core.symlinks",
        "core.ignorecase",
        "core.autocrlf",
        "user.name",
        "user.email",
    }
)
_GIT_EXECUTABLE_BINDING_SCHEMA = "aoi.git-executable-binding.v1"
_GIT_EXECUTABLE_PROVENANCE_SCOPE = "bridge_verify_mutation_git_observation"
_GIT_MUTATION_PATHS_SCHEMA = "aoi.codex-transport.git-mutation-paths.v1"
_PACKAGE_RECEIPT_SCHEMA = "aoi.release-package-local-gate.v1"
_BRIDGE_INSTALL_BINDING_FIELDS = {
    "package_receipt_file",
    "package_receipt_sha256",
    "expected_source_commit_oid",
    "expected_source_tree_oid",
    "expected_wheel_sha256",
    "wheel_file",
    "site_packages_root",
    "distribution_info_root",
}
_PACKAGE_RECEIPT_FIELDS = {
    "schema",
    "head",
    "tree",
    "version",
    "source_date_epoch",
    "release_tools_lock_sha256",
    "bootstrap_python",
    "build_python",
    "source_clean",
    "verify_dist_exit_code",
    "artifacts",
    "recorded_at",
}
_PACKAGE_ARTIFACT_FIELDS = {"name", "size_bytes", "sha256"}
_STARTUP_INJECTION_STEMS = frozenset({"sitecustomize", "usercustomize", "site"})


class CanaryError(ValueError):
    """The canary is unsafe, malformed, or did not produce the required evidence."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _strict_json_loads(raw: bytes, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CanaryError(f"{label} contains duplicate object keys")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise CanaryError(f"{label} contains non-finite JSON number {value}")

    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanaryError(f"{label} must be strict UTF-8 JSON") from exc


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CanaryError(f"{label} schema is invalid")
    return dict(value)


def _text(value: Any, label: str, *, limit: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > limit
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise CanaryError(f"{label} is invalid")
    return value


def _identifier(value: Any, label: str) -> str:
    result = _text(value, label, limit=128)
    if not all(
        char.isascii() and (char.isalnum() or char in "._:-")
        for char in result
    ):
        raise CanaryError(f"{label} is invalid")
    return result


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise CanaryError(f"{label} is not lowercase SHA-256")
    return value


def _absolute_file(value: Any, label: str) -> Path:
    raw = (
        str(value)
        if isinstance(value, os.PathLike)
        else _text(value, label, limit=4096)
    )
    path = Path(raw)
    if (
        not path.is_absolute()
        or not path.is_file()
        or path.is_symlink()
        or _is_reparse(path, label=label)
    ):
        raise CanaryError(f"{label} must be an existing absolute regular file")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CanaryError(f"could not resolve {label}") from exc
    if not _same_physical_path(path, resolved):
        raise CanaryError(f"{label} resolves through a link or reparse boundary")
    return resolved


def _absolute_directory(value: Any, label: str) -> Path:
    raw = (
        str(value)
        if isinstance(value, os.PathLike)
        else _text(value, label, limit=4096)
    )
    path = Path(raw)
    if (
        not path.is_absolute()
        or not path.is_dir()
        or path.is_symlink()
        or _is_reparse(path, label=label)
    ):
        raise CanaryError(f"{label} must be an existing absolute directory")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CanaryError(f"could not resolve {label}") from exc
    if not _same_physical_path(path, resolved):
        raise CanaryError(f"{label} resolves through a link or reparse boundary")
    return resolved


def _is_reparse(path: Path, *, label: str) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError as exc:
        raise CanaryError(f"could not inspect {label}") from exc
    return bool(attributes & 0x400)


def _same_physical_path(path: Path, resolved: Path) -> bool:
    return os.path.normcase(os.path.abspath(path)) == os.path.normcase(str(resolved))


def _path_stat_fingerprint(value: os.stat_result) -> tuple[int, ...]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(value.st_nlink),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
        int(getattr(value, "st_file_attributes", 0)),
    )


def _handle_stat_fingerprint(value: os.stat_result) -> tuple[int, ...]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(value.st_nlink),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
        int(getattr(value, "st_file_attributes", 0)),
    )


def _path_handle_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        stat.S_IFMT(value.st_mode),
        int(value.st_nlink),
        int(value.st_size),
        int(value.st_mtime_ns),
    )


def _stable_regular_file_sha256(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    min_bytes: int = 1,
) -> tuple[int, str]:
    """Stream one regular file while proving its path and open handle stayed stable."""

    try:
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or bool(getattr(before, "st_file_attributes", 0) & 0x400)
        ):
            raise CanaryError(f"{label} must be a regular non-linked file")
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CanaryError(f"could not resolve {label}") from exc
    if not _same_physical_path(path, resolved):
        raise CanaryError(f"{label} resolves through a link or reparse boundary")
    try:
        size = int(before.st_size)
        if size < min_bytes or size > max_bytes:
            raise CanaryError(f"{label} size is outside the bounded limit")
        digest = hashlib.sha256()
        total = 0
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", buffering=0) as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or _path_handle_identity(before) != _path_handle_identity(opened)
            ):
                raise CanaryError(f"{label} changed before hashing")
            while True:
                chunk = handle.read(_HASH_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise CanaryError(f"{label} exceeds the bounded limit")
                digest.update(chunk)
            handle_after = os.fstat(handle.fileno())
        after = path.lstat()
        resolved_after = path.resolve(strict=True)
    except CanaryError:
        raise
    except OSError as exc:
        raise CanaryError(f"could not hash {label}") from exc
    if (
        total != size
        or _path_stat_fingerprint(before) != _path_stat_fingerprint(after)
        or _handle_stat_fingerprint(opened)
        != _handle_stat_fingerprint(handle_after)
        or _path_handle_identity(after) != _path_handle_identity(handle_after)
        or not _same_physical_path(path, resolved_after)
    ):
        raise CanaryError(f"{label} changed while hashing")
    return size, digest.hexdigest()


def _executable_size(value: Any, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > _MAX_EXECUTABLE_BYTES
    ):
        raise CanaryError(f"{label}_size_bytes is invalid")
    return value


def _verify_executable_binding(
    path: Path,
    label: str,
    *,
    expected_size: int,
    expected_sha256: str,
) -> None:
    try:
        actual_size, actual_sha256 = _stable_regular_file_sha256(
            path,
            label,
            max_bytes=_MAX_EXECUTABLE_BYTES,
        )
    except CanaryError as exc:
        raise CanaryError(f"{label} bytes drifted") from exc
    if actual_size != expected_size or actual_sha256 != expected_sha256:
        raise CanaryError(f"{label} bytes drifted")


def _git_oid(value: Any, label: str) -> str:
    if not isinstance(value, str) or _GIT_OID.fullmatch(value) is None:
        raise CanaryError(f"{label} is not a full Git object ID")
    return value


def _record_candidate(
    site_root: Path,
    prefix: Path,
    relative: str,
) -> Path:
    if "\\" in relative:
        raise CanaryError("installed RECORD path is not canonical POSIX")
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or not parsed.parts:
        raise CanaryError("installed RECORD path is invalid")
    parent_count = 0
    for part in parsed.parts:
        if part != "..":
            break
        parent_count += 1
    if any(part in {"", ".", ".."} for part in parsed.parts[parent_count:]):
        raise CanaryError("installed RECORD path is invalid")
    candidate = site_root
    for _ in range(parent_count):
        candidate = candidate.parent
    candidate = candidate.joinpath(*parsed.parts[parent_count:])
    path = _absolute_file(candidate, "installed RECORD member")
    if not _under(path, prefix):
        raise CanaryError("installed RECORD member escapes the isolated venv")
    return path


def _record_digest(value: str, *, label: str) -> str:
    if not value.startswith("sha256="):
        raise CanaryError(f"{label} lacks a SHA-256 digest")
    encoded = value[7:]
    if not encoded or "=" in encoded:
        raise CanaryError(f"{label} has a non-canonical SHA-256 digest")
    try:
        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, UnicodeEncodeError) as exc:
        raise CanaryError(f"{label} has an invalid SHA-256 digest") from exc
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode(
        "ascii"
    ) != encoded:
        raise CanaryError(f"{label} has a non-canonical SHA-256 digest")
    return decoded.hex()


def _wheel_member_name(value: str) -> str:
    if not value or "\\" in value or "\x00" in value:
        raise CanaryError("wheel member name is not canonical POSIX")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise CanaryError("wheel member path is invalid")
    return path.as_posix()


def _wheel_record_rows(raw: bytes, *, record_name: str) -> dict[str, tuple[str | None, int | None]]:
    try:
        rows = list(csv.reader(raw.decode("utf-8", errors="strict").splitlines()))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise CanaryError("wheel RECORD is not strict CSV") from exc
    if not rows or len(rows) > _MAX_RECORD_ROWS:
        raise CanaryError("wheel RECORD row count is outside the bound")
    result: dict[str, tuple[str | None, int | None]] = {}
    for row in rows:
        if len(row) != 3:
            raise CanaryError("wheel RECORD row is invalid")
        name = _wheel_member_name(row[0])
        if name in result:
            raise CanaryError("wheel RECORD repeats a canonical path")
        digest, size = row[1], row[2]
        if name == record_name:
            if digest or size:
                raise CanaryError("wheel RECORD self-row must be unhashed")
            result[name] = (None, None)
            continue
        if not digest or not size.isdecimal():
            raise CanaryError("wheel RECORD row lacks verifiable SHA-256 and size")
        result[name] = (_record_digest(digest, label="wheel RECORD row"), int(size))
    return result


def _wheel_payload(
    wheel_path: Path,
    *,
    expected_dist_info: str,
    expected_sha256: str,
) -> tuple[dict[str, bytes], int]:
    """Read one bounded, closed wheel and validate its own RECORD oracle."""

    raw = _bounded_regular_bytes(
        wheel_path,
        "release wheel",
        max_bytes=_MAX_WHEEL_BYTES,
    )
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise CanaryError("release wheel bytes drifted")
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except (OSError, zipfile.BadZipFile) as exc:
        raise CanaryError("release wheel is not one valid ZIP archive") from exc
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > _MAX_WHEEL_ENTRIES:
            raise CanaryError("release wheel entry count is outside the bound")
        files: dict[str, bytes] = {}
        folded: set[str] = set()
        total_size = 0
        for info in infos:
            original = getattr(info, "orig_filename", info.filename)
            if original != info.filename:
                raise CanaryError("wheel member contains a NUL byte")
            name = _wheel_member_name(info.filename)
            name_folded = name.casefold()
            if name in files or name_folded in folded:
                raise CanaryError("wheel contains duplicate or case-colliding members")
            folded.add(name_folded)
            mode = info.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if (
                info.is_dir()
                or info.flag_bits & 0x1
                or (kind and kind != stat.S_IFREG)
            ):
                raise CanaryError("wheel contains an encrypted, special, or directory member")
            if info.file_size < 0 or info.file_size > _MAX_WHEEL_UNCOMPRESSED_BYTES:
                raise CanaryError("wheel member exceeds the byte bound")
            if info.file_size and (
                not info.compress_size
                or info.file_size > info.compress_size * _MAX_WHEEL_COMPRESSION_RATIO
            ):
                raise CanaryError("wheel member exceeds the compression-ratio bound")
            total_size += info.file_size
            if total_size > _MAX_WHEEL_UNCOMPRESSED_BYTES:
                raise CanaryError("wheel payload exceeds the byte bound")
            try:
                payload = archive.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                raise CanaryError("could not read wheel member") from exc
            if len(payload) != info.file_size:
                raise CanaryError("wheel member size drifted while reading")
            files[name] = payload

    package_prefix = "aoi_orgware/"
    dist_prefix = f"{expected_dist_info}/"
    record_name = f"{expected_dist_info}/RECORD"
    if record_name not in files or not any(
        name.startswith(package_prefix) for name in files
    ):
        raise CanaryError("wheel lacks the expected AOI package or dist-info RECORD")
    if any(
        not (name.startswith(package_prefix) or name.startswith(dist_prefix))
        for name in files
    ):
        raise CanaryError("wheel contains a member outside the expected distribution")
    if any(
        name.rsplit("/", 1)[-1].endswith(".pyc")
        or "__pycache__" in PurePosixPath(name).parts
        for name in files
    ):
        raise CanaryError("wheel contains bytecode cache payload")
    rows = _wheel_record_rows(files[record_name], record_name=record_name)
    if set(rows) != set(files):
        raise CanaryError("wheel RECORD does not close every wheel member")
    for name, payload in files.items():
        expected = rows[name]
        if name == record_name:
            continue
        if expected != (hashlib.sha256(payload).hexdigest(), len(payload)):
            raise CanaryError("wheel RECORD member bytes drifted")
    wheel_metadata_name = f"{expected_dist_info}/WHEEL"
    try:
        wheel_metadata = files[wheel_metadata_name].decode(
            "utf-8",
            errors="strict",
        )
    except KeyError as exc:
        raise CanaryError("wheel lacks its WHEEL metadata") from exc
    except UnicodeDecodeError as exc:
        raise CanaryError("wheel WHEEL metadata is not UTF-8") from exc
    root_is_purelib = [
        line.partition(":")[2].strip().casefold()
        for line in wheel_metadata.splitlines()
        if line.partition(":")[0].strip().casefold() == "root-is-purelib"
    ]
    if root_is_purelib != ["true"]:
        raise CanaryError("wheel must be one Root-Is-Purelib distribution")
    return files, len(raw)


def _wheel_console_scripts(raw: bytes) -> dict[str, str]:
    """Parse the exact, closed console-script surface shipped by AOI."""

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CanaryError("wheel entry_points.txt is not UTF-8") from exc
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or lines[0].casefold() != "[console_scripts]":
        raise CanaryError("wheel console-script metadata is invalid")
    scripts: dict[str, str] = {}
    folded_names: set[str] = set()
    for line in lines[1:]:
        if line.startswith(("#", ";", "[")) or line.count("=") != 1:
            raise CanaryError("wheel console-script metadata is invalid")
        name, target = (part.strip() for part in line.split("=", 1))
        folded = name.casefold()
        if (
            _CONSOLE_SCRIPT_NAME.fullmatch(name) is None
            or folded in folded_names
            or not target
            or len(target) > 512
            or any(ord(character) < 32 or ord(character) == 127 for character in target)
        ):
            raise CanaryError("wheel console-script metadata is invalid")
        folded_names.add(folded)
        scripts[name] = target
    if scripts != _EXPECTED_CONSOLE_SCRIPTS:
        raise CanaryError("wheel console-script surface or target drifted")
    return scripts


def _trusted_bridge_python_binding() -> dict[str, Any]:
    """Bind the already-trusted interpreter running this canary."""

    value = getattr(sys, "_base_executable", None) or sys.executable
    if not isinstance(value, str) or not value:
        raise CanaryError("canary base Python executable is unavailable")
    raw_path = Path(value)
    if not raw_path.is_absolute():
        raise CanaryError("canary base Python executable is not absolute")
    try:
        resolved = raw_path.resolve(strict=True)
    except OSError as exc:
        raise CanaryError("could not resolve canary base Python executable") from exc
    executable = _absolute_file(resolved, "canary base Python executable")
    size, digest = _stable_regular_file_sha256(
        executable,
        "canary base Python executable",
        max_bytes=_MAX_EXECUTABLE_BYTES,
    )
    return {
        "path": _contract_path(executable),
        "size_bytes": size,
        "sha256": digest,
        "execution_mode": "isolated_no_site_fixed_module",
    }


def _pyvenv_configuration(
    raw: bytes,
    *,
    prefix: Path,
    trusted_python: Path,
) -> dict[str, str]:
    """Parse one unambiguous pyvenv.cfg and bind it to the trusted base runtime."""

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CanaryError("bridge pyvenv.cfg is not UTF-8") from exc
    result: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        key, separator, value = line.partition("=")
        normalized_key = key.strip().casefold()
        normalized_value = value.strip()
        if (
            not separator
            or not normalized_key
            or normalized_key not in _PYVENV_CONFIG_KEYS
            or normalized_key in result
            or not normalized_value
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in normalized_value
            )
        ):
            raise CanaryError("bridge pyvenv.cfg is ambiguous or invalid")
        result[normalized_key] = normalized_value
    required = {
        "home",
        "include-system-site-packages",
        "version",
        "executable",
        "command",
    }
    if not required.issubset(result):
        raise CanaryError("bridge pyvenv.cfg lacks required keys")
    if result["include-system-site-packages"].casefold() != "false":
        raise CanaryError("bridge venv must disable system site packages")
    expected_version = ".".join(str(value) for value in sys.version_info[:3])
    if result["version"] != expected_version:
        raise CanaryError("bridge pyvenv.cfg Python version drifted")
    home = _absolute_directory(result["home"], "bridge pyvenv.cfg home")
    try:
        executable_path = Path(result["executable"]).resolve(strict=True)
    except OSError as exc:
        raise CanaryError("could not resolve bridge pyvenv.cfg executable") from exc
    executable = _absolute_file(executable_path, "bridge pyvenv.cfg executable")
    if not _same_path(home, trusted_python.parent) or not _same_path(
        executable,
        trusted_python,
    ):
        raise CanaryError("bridge pyvenv.cfg base Python authority drifted")
    command = result["command"]
    if (
        " -m venv " not in command
        or not command.endswith(f" {prefix}")
    ):
        raise CanaryError("bridge pyvenv.cfg creation command drifted")
    return result


def _file_url_path(value: Any) -> Path:
    raw = _text(value, "direct_url.url", limit=8192)
    try:
        parsed = urlsplit(raw)
        decoded = unquote(parsed.path, errors="strict")
    except (UnicodeDecodeError, ValueError) as exc:
        raise CanaryError("direct_url URL is invalid") from exc
    if (
        parsed.scheme.lower() != "file"
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or not decoded
    ):
        raise CanaryError("direct_url URL is not one local file URL")
    if (
        os.name == "nt"
        and len(decoded) >= 3
        and decoded[0] == "/"
        and decoded[2] == ":"
    ):
        decoded = decoded[1:]
    return _absolute_file(decoded, "direct_url wheel archive")


def _installed_namespace_closure(
    roots: Sequence[Path],
    *,
    prefix: Path,
    expected_files: set[Path],
) -> dict[str, Any]:
    actual_files: set[Path] = set()
    actual_directories: set[Path] = set()
    manifest: list[dict[str, Any]] = []
    total_bytes = 0

    def visit(directory: Path) -> None:
        nonlocal total_bytes
        checked = _absolute_directory(directory, "installed namespace directory")
        if not _under(checked, prefix):
            raise CanaryError("installed namespace directory escapes the venv")
        actual_directories.add(checked)
        try:
            entries = sorted(
                os.scandir(checked),
                key=lambda entry: (entry.name.casefold(), entry.name),
            )
        except OSError as exc:
            raise CanaryError("could not enumerate installed namespace") from exc
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(prefix)
            if (
                entry.name.endswith(".pyc")
                or "__pycache__" in relative.parts
            ):
                raise CanaryError("installed AOI namespace contains bytecode cache")
            try:
                # Native Windows DirEntry.stat() may report st_nlink=0 even
                # when Path.lstat() reports the required single-link identity.
                metadata = path.lstat()
            except OSError as exc:
                raise CanaryError(
                    "could not inspect installed namespace member"
                ) from exc
            if path.is_symlink() or bool(
                getattr(metadata, "st_file_attributes", 0) & 0x400
            ):
                raise CanaryError(
                    "installed namespace contains a link or reparse point"
                )
            if stat.S_ISDIR(metadata.st_mode):
                visit(path)
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise CanaryError(
                    "installed namespace contains a non-regular or linked member"
                )
            actual_files.add(path.resolve())
            if len(actual_files) > _MAX_INSTALLED_FILES:
                raise CanaryError("installed namespace exceeds the file-count bound")
            size, digest = _stable_regular_file_sha256(
                path,
                "installed namespace file",
                max_bytes=_MAX_INSTALLED_BYTES,
                min_bytes=0,
            )
            total_bytes += size
            if total_bytes > _MAX_INSTALLED_BYTES:
                raise CanaryError("installed namespace exceeds the byte bound")
            manifest.append(
                {
                    "path": _contract_path(path),
                    "size_bytes": size,
                    "sha256": digest,
                }
            )

    for root in roots:
        visit(root)
    if actual_files != expected_files:
        unexpected = sorted(
            _contract_path(path) for path in actual_files - expected_files
        )
        missing = sorted(
            _contract_path(path) for path in expected_files - actual_files
        )
        raise CanaryError(
            "installed AOI namespace differs from exact RECORD closure: "
            f"unexpected={unexpected[:8]} missing={missing[:8]}"
        )
    manifest.sort(key=lambda row: row["path"])
    directory_names = sorted(_contract_path(path) for path in actual_directories)
    return {
        "file_count": len(manifest),
        "directory_count": len(directory_names),
        "total_size_bytes": total_bytes,
        "closure_sha256": _digest(
            {"directories": directory_names, "files": manifest}
        ),
    }


def _bridge_install_binding(
    value: Any,
    *,
    bridge_executable: Path,
) -> dict[str, Any]:
    item = _object(
        value,
        _BRIDGE_INSTALL_BINDING_FIELDS,
        "bridge_install_binding",
    )
    receipt_path = _absolute_file(
        item["package_receipt_file"],
        "bridge_install_binding.package_receipt_file",
    )
    expected_receipt_sha = _sha256(
        item["package_receipt_sha256"],
        "bridge_install_binding.package_receipt_sha256",
    )
    receipt_raw = _bounded_regular_bytes(
        receipt_path,
        "release package receipt",
        max_bytes=_MAX_PACKAGE_RECEIPT_BYTES,
    )
    if hashlib.sha256(receipt_raw).hexdigest() != expected_receipt_sha:
        raise CanaryError("release package receipt bytes drifted")
    receipt = _object(
        _strict_json_loads(receipt_raw, "release package receipt"),
        _PACKAGE_RECEIPT_FIELDS,
        "release package receipt",
    )
    if (
        receipt["schema"] != _PACKAGE_RECEIPT_SCHEMA
        or receipt["source_clean"] is not True
        or receipt["verify_dist_exit_code"] != 0
    ):
        raise CanaryError("release package receipt is not one passing clean gate")
    commit_oid = _git_oid(
        item["expected_source_commit_oid"],
        "bridge_install_binding.expected_source_commit_oid",
    )
    tree_oid = _git_oid(
        item["expected_source_tree_oid"],
        "bridge_install_binding.expected_source_tree_oid",
    )
    if receipt["head"] != commit_oid or receipt["tree"] != tree_oid:
        raise CanaryError("release package receipt source binding drifted")
    version = _text(receipt["version"], "release package version", limit=128)
    expected_dist_name = f"aoi_orgware-{version}.dist-info"
    wheel_sha = _sha256(
        item["expected_wheel_sha256"],
        "bridge_install_binding.expected_wheel_sha256",
    )
    wheel_path = _absolute_file(
        item["wheel_file"],
        "bridge_install_binding.wheel_file",
    )
    wheel_files, wheel_size = _wheel_payload(
        wheel_path,
        expected_dist_info=expected_dist_name,
        expected_sha256=wheel_sha,
    )
    entry_points_name = f"{expected_dist_name}/entry_points.txt"
    try:
        console_scripts = _wheel_console_scripts(wheel_files[entry_points_name])
    except KeyError as exc:
        raise CanaryError("wheel lacks its console-script metadata") from exc
    artifacts = receipt["artifacts"]
    if not isinstance(artifacts, list) or not artifacts or len(artifacts) > 8:
        raise CanaryError("release package receipt artifacts are invalid")
    artifact_rows: list[dict[str, Any]] = []
    for row in artifacts:
        checked = _object(
            row,
            _PACKAGE_ARTIFACT_FIELDS,
            "release package artifact",
        )
        if (
            not isinstance(checked["size_bytes"], int)
            or isinstance(checked["size_bytes"], bool)
            or checked["size_bytes"] < 1
        ):
            raise CanaryError("release package artifact size is invalid")
        _sha256(checked["sha256"], "release package artifact SHA-256")
        _text(checked["name"], "release package artifact name", limit=512)
        artifact_rows.append(checked)
    wheel_rows = [
        row
        for row in artifact_rows
        if row["name"] == wheel_path.name
        and row["size_bytes"] == wheel_size
        and row["sha256"] == wheel_sha
    ]
    if len(wheel_rows) != 1:
        raise CanaryError("release package receipt does not bind the exact wheel")

    site_root = _absolute_directory(
        item["site_packages_root"],
        "bridge_install_binding.site_packages_root",
    )
    dist_info = _absolute_directory(
        item["distribution_info_root"],
        "bridge_install_binding.distribution_info_root",
    )
    if dist_info.parent != site_root:
        raise CanaryError("distribution info root is outside exact site-packages")
    prefix = bridge_executable.parent.parent
    prefix = _absolute_directory(prefix, "bridge virtual environment")
    if not _under(site_root, prefix) or not _under(bridge_executable, prefix):
        raise CanaryError("bridge installation is not contained by one venv")
    expected_scripts_directory = "scripts" if os.name == "nt" else "bin"
    if bridge_executable.parent.name.casefold() != expected_scripts_directory:
        raise CanaryError("bridge executable is outside the venv scripts directory")
    launcher_suffix = ".exe" if os.name == "nt" else ""
    launcher_paths = {
        name: _absolute_file(
            bridge_executable.parent / f"{name}{launcher_suffix}",
            f"installed {name} launcher",
        )
        for name in console_scripts
    }
    if not _same_path(launcher_paths["aoi-codex-bridge"], bridge_executable):
        raise CanaryError("bridge executable differs from its wheel entry point")
    trusted_python_binding = _trusted_bridge_python_binding()
    trusted_python = _absolute_file(
        trusted_python_binding["path"],
        "trusted Bridge Python executable",
    )
    config = _bounded_regular_bytes(
        _absolute_file(prefix / "pyvenv.cfg", "bridge pyvenv.cfg"),
        "bridge pyvenv.cfg",
        max_bytes=64 * 1024,
    )
    pyvenv_configuration = _pyvenv_configuration(
        config,
        prefix=prefix,
        trusted_python=trusted_python,
    )

    if dist_info.name != expected_dist_name:
        raise CanaryError("distribution info directory identity drifted")
    package_root = _absolute_directory(
        site_root / "aoi_orgware",
        "installed AOI package root",
    )
    try:
        top_level = sorted(
            site_root.iterdir(),
            key=lambda path: (path.name.casefold(), path.name),
        )
    except OSError as exc:
        raise CanaryError("could not enumerate site-packages") from exc
    for entry in top_level:
        folded = entry.name.casefold()
        if entry.suffix.casefold() == ".pth":
            raise CanaryError("bridge venv may not contain a .pth authority path")
        startup_stem = folded.partition(".")[0]
        if startup_stem in _STARTUP_INJECTION_STEMS:
            raise CanaryError("bridge venv contains a Python startup injection")
        if folded == "aoi_orgware" and entry.name != "aoi_orgware":
            raise CanaryError("installed AOI package casing drifted")
        if folded.startswith("aoi_orgware."):
            raise CanaryError("site-packages contains an AOI import shadow")
        if (
            folded.startswith("aoi_orgware-")
            and folded.endswith(".dist-info")
            and entry.name != dist_info.name
        ):
            raise CanaryError("site-packages contains another AOI distribution")

    record_path = _absolute_file(dist_info / "RECORD", "installed RECORD")
    wheel_record_name = f"{expected_dist_name}/RECORD"
    forbidden_wheel_generated = {
        f"{expected_dist_name}/INSTALLER",
        f"{expected_dist_name}/REQUESTED",
        f"{expected_dist_name}/direct_url.json",
    }
    if forbidden_wheel_generated & set(wheel_files):
        raise CanaryError("wheel contains an installer-generated metadata surface")
    wheel_installed_paths: dict[Path, bytes] = {}
    for name, payload in wheel_files.items():
        if name == wheel_record_name:
            continue
        target = _absolute_file(
            site_root.joinpath(*PurePosixPath(name).parts),
            "installed wheel payload",
        )
        wheel_installed_paths[target] = payload
    direct_path = _absolute_file(
        dist_info / "direct_url.json",
        "installed direct_url.json",
    )
    installer_path = _absolute_file(dist_info / "INSTALLER", "installed INSTALLER")
    requested_path = _absolute_file(dist_info / "REQUESTED", "installed REQUESTED")
    expected_record_paths = set(wheel_installed_paths) | {
        record_path,
        direct_path,
        installer_path,
        requested_path,
        *launcher_paths.values(),
    }
    installer_surface_count = 4 + len(launcher_paths)
    if len(expected_record_paths) != (
        len(wheel_installed_paths) + installer_surface_count
    ):
        raise CanaryError("installed wheel and installer surfaces overlap")
    record_raw = _bounded_regular_bytes(
        record_path,
        "installed RECORD",
        max_bytes=_MAX_RECORD_BYTES,
    )
    try:
        rows = list(
            csv.reader(record_raw.decode("utf-8", errors="strict").splitlines())
        )
    except (UnicodeDecodeError, csv.Error) as exc:
        raise CanaryError("installed RECORD is not strict CSV") from exc
    if not rows or len(rows) > _MAX_RECORD_ROWS:
        raise CanaryError("installed RECORD row count is outside the bound")
    record_entries: dict[Path, tuple[str | None, int | None]] = {}
    total_recorded_bytes = 0
    for row in rows:
        if len(row) != 3 or not row[0]:
            raise CanaryError("installed RECORD row is invalid")
        candidate = _record_candidate(site_root, prefix, row[0])
        if candidate in record_entries:
            raise CanaryError("installed RECORD repeats a canonical path")
        digest_field, size_field = row[1], row[2]
        if candidate == record_path:
            if digest_field or size_field:
                raise CanaryError("installed RECORD self-row must be unhashed")
            record_entries[candidate] = (None, None)
            continue
        if not digest_field or not size_field.isdecimal():
            raise CanaryError(
                "installed RECORD row lacks verifiable SHA-256 and size"
            )
        expected_size = int(size_field)
        size, digest = _stable_regular_file_sha256(
            candidate,
            "installed RECORD member",
            max_bytes=_MAX_INSTALLED_BYTES,
            min_bytes=0,
        )
        if size != expected_size or digest != _record_digest(
            digest_field,
            label="installed RECORD row",
        ):
            raise CanaryError("installed RECORD member bytes drifted")
        total_recorded_bytes += size
        if total_recorded_bytes > _MAX_INSTALLED_BYTES:
            raise CanaryError("installed RECORD payload exceeds the byte bound")
        record_entries[candidate] = (digest, size)

    if set(record_entries) != expected_record_paths:
        raise CanaryError("installed RECORD differs from the wheel and installer closure")
    for installed_path, expected_payload in wheel_installed_paths.items():
        observed_payload = _bounded_regular_bytes(
            installed_path,
            "installed wheel payload",
            max_bytes=_MAX_WHEEL_UNCOMPRESSED_BYTES,
            min_bytes=0,
        )
        if observed_payload != expected_payload:
            raise CanaryError("installed payload differs from exact wheel bytes")
    if _bounded_regular_bytes(
        installer_path,
        "installed INSTALLER",
        max_bytes=1024,
    ) not in {b"pip\n", b"pip\r\n"}:
        raise CanaryError("installed INSTALLER is not the expected pip surface")
    if (
        _bounded_regular_bytes(
            requested_path,
            "installed REQUESTED",
            max_bytes=1024,
            min_bytes=0,
        )
        != b""
    ):
        raise CanaryError("installed REQUESTED is not the expected empty surface")

    expected_namespace_files = {
        path
        for path in record_entries
        if _under(path, package_root) or _under(path, dist_info)
    }
    namespace = _installed_namespace_closure(
        (package_root, dist_info),
        prefix=prefix,
        expected_files=expected_namespace_files,
    )
    launcher_manifest: list[dict[str, Any]] = []
    for name, entry_target in sorted(console_scripts.items()):
        launcher_path = launcher_paths[name]
        launcher_entry = record_entries.get(launcher_path)
        if launcher_entry is None or launcher_entry[0] is None:
            raise CanaryError("console launcher is absent from installed RECORD")
        launcher_manifest.append(
            {
                "name": name,
                "target": entry_target,
                "path": _contract_path(launcher_path),
                "sha256": launcher_entry[0],
                "size_bytes": launcher_entry[1],
            }
        )
    bridge_entry = record_entries.get(bridge_executable)
    if bridge_entry is None or bridge_entry[0] is None:
        raise CanaryError("bridge executable is absent from installed RECORD")
    bridge_size, bridge_sha = _stable_regular_file_sha256(
        bridge_executable,
        "installed bridge executable",
        max_bytes=_MAX_EXECUTABLE_BYTES,
    )
    if bridge_entry != (bridge_sha, bridge_size):
        raise CanaryError("installed RECORD does not bind the bridge executable")

    direct_path = _absolute_file(
        dist_info / "direct_url.json",
        "installed direct_url.json",
    )
    direct_entry = record_entries.get(direct_path)
    if direct_entry is None or direct_entry[0] is None:
        raise CanaryError("direct_url.json is absent from installed RECORD")
    direct_raw = _bounded_regular_bytes(
        direct_path,
        "installed direct_url.json",
        max_bytes=64 * 1024,
    )
    direct = _object(
        _strict_json_loads(direct_raw, "installed direct_url.json"),
        {"url", "archive_info"},
        "installed direct_url.json",
    )
    archive = _object(
        direct["archive_info"],
        {"hash", "hashes"},
        "installed direct_url archive_info",
    )
    if archive["hash"] != f"sha256={wheel_sha}" or archive["hashes"] != {
        "sha256": wheel_sha
    }:
        raise CanaryError("installed direct_url does not bind the exact wheel")
    if not _same_path(_file_url_path(direct["url"]), wheel_path):
        raise CanaryError("installed direct_url points at another wheel")

    metadata_raw = _bounded_regular_bytes(
        _absolute_file(dist_info / "METADATA", "installed METADATA"),
        "installed METADATA",
        max_bytes=1024 * 1024,
    )
    try:
        metadata_text = metadata_raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CanaryError("installed METADATA is not UTF-8") from exc
    metadata_lines = metadata_text.splitlines()
    names = [line[6:] for line in metadata_lines if line.startswith("Name: ")]
    versions = [
        line[9:] for line in metadata_lines if line.startswith("Version: ")
    ]
    if names != ["aoi-orgware"] or versions != [version]:
        raise CanaryError("installed distribution metadata identity drifted")
    installed_entry_points = _bounded_regular_bytes(
        _absolute_file(
            dist_info / "entry_points.txt",
            "installed entry_points.txt",
        ),
        "installed entry_points.txt",
        max_bytes=64 * 1024,
    )
    if _wheel_console_scripts(installed_entry_points) != console_scripts:
        raise CanaryError("installed console-script metadata drifted")

    closure = {
        "source_commit_oid": commit_oid,
        "source_tree_oid": tree_oid,
        "wheel_sha256": wheel_sha,
        "package_receipt_sha256": expected_receipt_sha,
        "pyvenv_config_sha256": hashlib.sha256(config).hexdigest(),
        "pyvenv_configuration": pyvenv_configuration,
        "bridge_runtime_python": trusted_python_binding,
        "record_sha256": hashlib.sha256(record_raw).hexdigest(),
        "record_rows": len(rows),
        "namespace": namespace,
        "console_scripts": launcher_manifest,
        "bridge_executable_sha256": bridge_sha,
    }
    closure["closure_sha256"] = _digest(closure)
    return {
        "package_receipt_file": _contract_path(receipt_path),
        "package_receipt_sha256": expected_receipt_sha,
        "expected_source_commit_oid": commit_oid,
        "expected_source_tree_oid": tree_oid,
        "expected_wheel_sha256": wheel_sha,
        "wheel_file": _contract_path(wheel_path),
        "site_packages_root": _contract_path(site_root),
        "distribution_info_root": _contract_path(dist_info),
        "closure": closure,
    }


def _bounded_regular_bytes(
    path: Path,
    label: str,
    *,
    max_bytes: int = _LOCAL_FILES_MAX_BYTES,
    min_bytes: int = 1,
) -> bytes:
    try:
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or bool(getattr(before, "st_file_attributes", 0) & 0x400)
        ):
            raise CanaryError(f"{label} must be a regular non-linked file")
        size = int(before.st_size)
        if min_bytes < 0 or min_bytes > max_bytes:
            raise CanaryError(f"{label} has invalid byte bounds")
        if size < min_bytes or size > max_bytes:
            raise CanaryError(f"{label} bytes are outside the bounded limit")
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CanaryError(f"could not resolve {label}") from exc
    if not _same_physical_path(path, resolved):
        raise CanaryError(f"{label} resolves through a link or reparse boundary")
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        chunks: list[bytes] = []
        total = 0
        with os.fdopen(descriptor, "rb", buffering=0) as handle:
            opened = os.fstat(handle.fileno())
            if _path_handle_identity(before) != _path_handle_identity(opened):
                raise CanaryError(f"{label} changed before reading")
            while True:
                chunk = handle.read(_HASH_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise CanaryError(f"{label} exceeds the bounded limit")
                chunks.append(chunk)
            handle_after = os.fstat(handle.fileno())
        after = path.lstat()
        resolved_after = path.resolve(strict=True)
    except OSError as exc:
        raise CanaryError(f"could not read {label}") from exc
    if (
        total != size
        or _path_stat_fingerprint(before) != _path_stat_fingerprint(after)
        or _handle_stat_fingerprint(opened)
        != _handle_stat_fingerprint(handle_after)
        or _path_handle_identity(after) != _path_handle_identity(handle_after)
        or not _same_physical_path(path, resolved_after)
    ):
        raise CanaryError(f"{label} bytes are invalid or changed while bound")
    return b"".join(chunks)


def _local_files_codex_home(value: Any) -> dict[str, Any]:
    """Bind the closed policy without hashing or persisting auth content."""

    raw = _text(value, "codex_home", limit=4096)
    home = Path(raw)
    if (
        not home.is_absolute()
        or home.is_symlink()
        or not home.is_dir()
        or _is_reparse(home, label="codex_home")
    ):
        raise CanaryError("codex_home must be an absolute non-link non-reparse directory")
    try:
        resolved_home = home.resolve(strict=True)
    except OSError as exc:
        raise CanaryError("could not resolve codex_home") from exc
    if not _same_physical_path(home, resolved_home):
        raise CanaryError("codex_home resolves through a link or reparse boundary")
    try:
        children = sorted(home.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise CanaryError("could not enumerate codex_home") from exc
    if (
        len(children) != len(_LOCAL_FILES_HOME_NAMES)
        or {child.name for child in children} != _LOCAL_FILES_HOME_NAMES
    ):
        raise CanaryError(
            "codex_home inventory must contain only auth.json, config.toml, "
            "and managed_config.toml"
        )

    inventory: list[dict[str, Any]] = []
    policy_files: dict[str, tuple[Path, bytes, str]] = {}
    for child in children:
        data = _bounded_regular_bytes(child, f"codex_home/{child.name}")
        row: dict[str, Any] = {
            "name": child.name,
            "path": _contract_path(child),
            "size_bytes": len(data),
            "type": "file",
        }
        if child.name != "auth.json":
            digest = hashlib.sha256(data).hexdigest()
            row["sha256"] = digest
            policy_files[child.name] = (child, data, digest)
        inventory.append(row)
    try:
        config = tomllib.loads(
            policy_files["config.toml"][1].decode("utf-8", errors="strict")
        )
        managed = tomllib.loads(
            policy_files["managed_config.toml"][1].decode("utf-8", errors="strict")
        )
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise CanaryError("codex_home policy files must be strict UTF-8 TOML") from exc
    if config != _LOCAL_FILES_CONFIG:
        raise CanaryError("codex_home config.toml policy differs from exact local_files profile")
    if managed != _LOCAL_FILES_MANAGED_CONFIG:
        raise CanaryError("codex_home managed_config.toml policy differs from exact local_files profile")
    inventory_bytes = json.dumps(
        inventory, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    thread_config_bytes = json.dumps(
        _LOCAL_FILES_THREAD_CONFIG,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return {
        "mode": "local_files",
        "codex_home": _contract_path(resolved_home),
        "initial_inventory": inventory,
        "initial_inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
        "config_path": _contract_path(policy_files["config.toml"][0]),
        "config_sha256": policy_files["config.toml"][2],
        "managed_config_path": _contract_path(
            policy_files["managed_config.toml"][0]
        ),
        "managed_config_sha256": policy_files["managed_config.toml"][2],
        "thread_config_sha256": hashlib.sha256(thread_config_bytes).hexdigest(),
    }


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left.resolve())) == os.path.normcase(
        str(right.resolve())
    )


def _contract_path(path: Path) -> str:
    """Return the canonical absolute spelling used by transport contracts."""

    result = path.resolve(strict=True).as_posix()
    if "\\" in result:
        raise CanaryError("could not canonicalize path for transport contract")
    return result


def _under(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _runtime_pin(value: Any) -> dict[str, Any]:
    result = _object(
        value,
        {
            "codex_cli_version",
            "codex_app_server_version",
            "app_server_executable_sha256",
            "schema_manifest_sha256",
            "combined_v2_schema_sha256",
            "executable_path",
            "executable_size_bytes",
        },
        "runtime_pin",
    )
    executable = _absolute_file(
        result["executable_path"], "runtime_pin.executable_path"
    )
    size = _executable_size(
        result["executable_size_bytes"], "runtime_pin.executable"
    )
    executable_sha256 = _sha256(
        result["app_server_executable_sha256"],
        "runtime_pin.app_server_executable_sha256",
    )
    normalized = {
        "codex_cli_version": _text(
            result["codex_cli_version"],
            "runtime_pin.codex_cli_version",
            limit=128,
        ),
        "codex_app_server_version": _text(
            result["codex_app_server_version"],
            "runtime_pin.codex_app_server_version",
            limit=128,
        ),
        "app_server_executable_sha256": executable_sha256,
        "schema_manifest_sha256": _sha256(
            result["schema_manifest_sha256"],
            "runtime_pin.schema_manifest_sha256",
        ),
        "combined_v2_schema_sha256": _sha256(
            result["combined_v2_schema_sha256"],
            "runtime_pin.combined_v2_schema_sha256",
        ),
        "executable_path": _contract_path(executable),
        "executable_size_bytes": size,
    }
    _verify_executable_binding(
        executable,
        "runtime_pin executable",
        expected_size=size,
        expected_sha256=executable_sha256,
    )
    return normalized


def load_spec(path: Path) -> dict[str, Any]:
    if (
        not path.is_absolute()
        or not path.is_file()
        or path.is_symlink()
        or _is_reparse(path, label="spec")
    ):
        raise CanaryError("spec must be an existing absolute regular file")
    raw = _bounded_regular_bytes(path, "spec", max_bytes=_MAX_JSON_BYTES)
    parsed = _strict_json_loads(raw, "spec")
    value = _object(
        parsed,
        {
            "schema_version",
            "mode",
            "aoi_root",
            "task_id",
            "launch_id",
            "permit_sha256",
            "prompt_file",
            "codex_executable",
            "bridge_executable",
            "bridge_executable_sha256",
            "bridge_executable_size_bytes",
            "bridge_install_binding",
            "git_executable",
            "git_executable_sha256",
            "git_executable_size_bytes",
            "scratch_root",
            "codex_home",
            "runtime_pin",
            "timeout_seconds",
            "post_git_endpoint_file",
        },
        "spec",
    )
    if value["schema_version"] != SCHEMA_VERSION:
        raise CanaryError("spec schema_version is unsupported")
    mode = _text(value["mode"], "mode", limit=32)
    if mode not in _MODES:
        raise CanaryError("mode is unsupported")
    scratch_root = _absolute_directory(value["scratch_root"], "scratch_root")
    aoi_root = _absolute_directory(value["aoi_root"], "aoi_root")
    if not _same_path(scratch_root, aoi_root):
        raise CanaryError("aoi_root must equal the disposable scratch_root")
    if any(part.casefold() == "arise" for part in scratch_root.parts):
        raise CanaryError("ARISE may not be used as a transport canary root")
    prompt_file = _absolute_file(value["prompt_file"], "prompt_file")
    if not _under(prompt_file, scratch_root):
        raise CanaryError("prompt_file must remain inside scratch_root")
    runtime_pin = _runtime_pin(value["runtime_pin"])
    codex_executable = _absolute_file(
        value["codex_executable"], "codex_executable"
    )
    if not _same_path(
        codex_executable, Path(runtime_pin["executable_path"])
    ):
        raise CanaryError("codex_executable differs from runtime_pin")
    bridge_executable = _absolute_file(
        value["bridge_executable"], "bridge_executable"
    )
    bridge_size = _executable_size(
        value["bridge_executable_size_bytes"], "bridge_executable"
    )
    bridge_sha256 = _sha256(
        value["bridge_executable_sha256"], "bridge_executable_sha256"
    )
    _verify_executable_binding(
        bridge_executable,
        "bridge_executable",
        expected_size=bridge_size,
        expected_sha256=bridge_sha256,
    )
    bridge_install = _bridge_install_binding(
        value["bridge_install_binding"],
        bridge_executable=bridge_executable,
    )
    git_executable = _absolute_file(value["git_executable"], "git_executable")
    git_size = _executable_size(
        value["git_executable_size_bytes"], "git_executable"
    )
    git_sha256 = _sha256(
        value["git_executable_sha256"], "git_executable_sha256"
    )
    _verify_executable_binding(
        git_executable,
        "git_executable",
        expected_size=git_size,
        expected_sha256=git_sha256,
    )
    codex_home_policy = _local_files_codex_home(value["codex_home"])
    timeout_seconds = value["timeout_seconds"]
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds < 1
        or timeout_seconds > 900
    ):
        raise CanaryError("timeout_seconds is outside 1..900")
    post_endpoint = value["post_git_endpoint_file"]
    post_endpoint_path: Path | None = None
    if post_endpoint is not None:
        post_endpoint_path = _absolute_file(
            post_endpoint, "post_git_endpoint_file"
        )
        if not _under(post_endpoint_path, scratch_root):
            raise CanaryError(
                "post_git_endpoint_file must remain inside scratch_root"
            )
    if mode == "read_only" and post_endpoint_path is not None:
        raise CanaryError("read_only canary cannot carry a post Git endpoint")
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": mode,
        "aoi_root": aoi_root,
        "task_id": _identifier(value["task_id"], "task_id"),
        "launch_id": _identifier(value["launch_id"], "launch_id"),
        "permit_sha256": _sha256(value["permit_sha256"], "permit_sha256"),
        "prompt_file": prompt_file,
        "codex_executable": codex_executable,
        "bridge_executable": bridge_executable,
        "bridge_executable_sha256": bridge_sha256,
        "bridge_executable_size_bytes": bridge_size,
        "bridge_install_binding": bridge_install,
        "git_executable": git_executable,
        "git_executable_sha256": git_sha256,
        "git_executable_size_bytes": git_size,
        "scratch_root": scratch_root,
        "codex_home_policy": codex_home_policy,
        "runtime_pin": runtime_pin,
        "timeout_seconds": float(timeout_seconds),
        "post_git_endpoint_file": post_endpoint_path,
    }


def _run_process(
    argv: Sequence[str],
    *,
    timeout_seconds: float,
    allow_codes: set[int] | None = None,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    allowed = {0} if allow_codes is None else allow_codes
    command = list(argv)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=None if environment is None else dict(environment),
            bufsize=0,
        )
    except OSError as exc:
        raise CanaryError(f"command execution failed: {argv[0]}") from exc

    assert process.stdout is not None
    assert process.stderr is not None
    outputs = [bytearray(), bytearray()]
    overflow = threading.Event()
    reader_errors: list[BaseException] = []

    def drain(stream: Any, output: bytearray) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                remaining = _MAX_JSON_BYTES - len(output)
                if len(chunk) > remaining:
                    if remaining > 0:
                        output.extend(chunk[:remaining])
                    overflow.set()
                    try:
                        process.kill()
                    except OSError:
                        pass
                    return
                output.extend(chunk)
        except (OSError, ValueError) as exc:
            reader_errors.append(exc)
            try:
                process.kill()
            except OSError:
                pass

    readers = [
        threading.Thread(
            target=drain,
            args=(process.stdout, outputs[0]),
            daemon=True,
        ),
        threading.Thread(
            target=drain,
            args=(process.stderr, outputs[1]),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()

    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            process.kill()
        except OSError:
            pass
        process.wait()
    for reader in readers:
        reader.join(timeout=5.0)
    readers_alive = any(reader.is_alive() for reader in readers)
    if readers_alive:
        try:
            process.kill()
        except OSError:
            pass
        process.stdout.close()
        process.stderr.close()
        for reader in readers:
            reader.join(timeout=1.0)
    else:
        process.stdout.close()
        process.stderr.close()

    if timed_out or reader_errors or readers_alive:
        raise CanaryError(f"command execution failed: {argv[0]}")
    if overflow.is_set():
        raise CanaryError("command output exceeds the bounded canary limit")
    completed = subprocess.CompletedProcess(
        args=command,
        returncode=process.returncode,
        stdout=bytes(outputs[0]),
        stderr=bytes(outputs[1]),
    )
    if completed.returncode not in allowed:
        stderr = completed.stderr.decode("utf-8", errors="replace")[:1024]
        raise CanaryError(
            f"command failed with status {completed.returncode}: {stderr}"
        )
    return completed


def _is_publish_credential_name(name: str) -> bool:
    upper = name.upper()
    return upper in _PUBLISH_CREDENTIAL_NAMES or upper.startswith(
        _PUBLISH_CREDENTIAL_PREFIXES
    )


def _is_git_routing_environment_name(name: str) -> bool:
    upper = name.upper()
    return upper.startswith("GIT_") or upper in _SSH_CONTROL_ENV_NAMES


def _set_closed_git_environment(environment: dict[str, str]) -> None:
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_ATTR_NOSYSTEM"] = "1"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GCM_INTERACTIVE"] = "Never"


def _native_windows_directory() -> Path:
    if os.name != "nt":
        raise CanaryError("native Windows directory is unavailable")
    import ctypes

    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise CanaryError("Win32 loader is unavailable")
    kernel32 = loader("kernel32", use_last_error=True)
    get_windows_directory = kernel32.GetWindowsDirectoryW
    get_windows_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    get_windows_directory.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32_768)
    length = int(get_windows_directory(buffer, len(buffer)))
    if length <= 0 or length >= len(buffer):
        raise CanaryError("GetWindowsDirectoryW failed")
    return _absolute_directory(Path(buffer.value), "native Windows directory")


def _validated_temp_directory() -> Path:
    path = Path(tempfile.gettempdir())
    if not path.is_absolute():
        path = path.absolute()
    return _absolute_directory(path, "temporary directory")


def _constructed_bridge_path(spec: Mapping[str, Any]) -> str:
    directories = [
        _absolute_directory(
            Path(str(spec["codex_executable"])).parent,
            "Codex executable directory",
        ),
        _absolute_directory(
            Path(str(spec["git_executable"])).parent,
            "Git executable directory",
        ),
    ]
    if os.name == "nt":
        system_root = _native_windows_directory()
        directories.extend(
            (
                _absolute_directory(
                    system_root / "System32",
                    "native Windows System32 directory",
                ),
                system_root,
            )
        )
    else:
        directories.extend((Path("/usr/local/bin"), Path("/usr/bin"), Path("/bin")))
    unique: list[str] = []
    seen: set[str] = set()
    for directory in directories:
        value = str(directory)
        folded = os.path.normcase(os.path.normpath(value))
        if folded not in seen:
            seen.add(folded)
            unique.append(value)
    return os.pathsep.join(unique)


def _bridge_environment(spec: Mapping[str, Any]) -> dict[str, str]:
    """Return the bounded child environment for bridge-owned subprocesses."""

    codex_home = str(spec["codex_home_policy"]["codex_home"])
    temporary_directory = str(_validated_temp_directory())
    environment: dict[str, str] = {
        "CODEX_HOME": codex_home,
        "HOME": codex_home,
        "USERPROFILE": codex_home,
        "PATH": _constructed_bridge_path(spec),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "PYTHONUTF8": "1",
        "LANG": "C",
        "LC_ALL": "C",
        "TEMP": temporary_directory,
        "TMP": temporary_directory,
    }
    if os.name == "nt":
        home_path = Path(codex_home)
        system_root = _native_windows_directory()
        command_processor = _absolute_file(
            system_root / "System32" / "cmd.exe",
            "native Windows command processor",
        )
        home_suffix = str(home_path)[len(home_path.drive) :] or "\\"
        environment.update(
            {
                "HOMEDRIVE": home_path.drive or "C:",
                "HOMEPATH": home_suffix,
                "SYSTEMROOT": str(system_root),
                "WINDIR": str(system_root),
                "COMSPEC": str(command_processor),
                "PATHEXT": ".COM;.EXE;.BAT;.CMD",
            }
        )
    _set_closed_git_environment(environment)
    return environment


def _revalidate_bridge_binding(spec: Mapping[str, Any]) -> None:
    _revalidate_scratch_boundaries(spec)
    runtime = spec["runtime_pin"]
    codex = _absolute_file(spec["codex_executable"], "codex_executable")
    _verify_executable_binding(
        codex,
        "runtime_pin executable",
        expected_size=int(runtime["executable_size_bytes"]),
        expected_sha256=str(runtime["app_server_executable_sha256"]),
    )
    bridge = _absolute_file(spec["bridge_executable"], "bridge_executable")
    _verify_executable_binding(
        bridge,
        "bridge_executable",
        expected_size=int(spec["bridge_executable_size_bytes"]),
        expected_sha256=str(spec["bridge_executable_sha256"]),
    )
    refreshed_install = _bridge_install_binding(
        {
            field: spec["bridge_install_binding"][field]
            for field in _BRIDGE_INSTALL_BINDING_FIELDS
        },
        bridge_executable=bridge,
    )
    if refreshed_install != spec["bridge_install_binding"]:
        raise CanaryError("bridge installed-distribution binding drifted")
    refreshed_home = _local_files_codex_home(
        spec["codex_home_policy"]["codex_home"]
    )
    if refreshed_home != spec["codex_home_policy"]:
        raise CanaryError("codex_home policy binding drifted")


def _git_environment(spec: Mapping[str, Any]) -> dict[str, str]:
    environment = _bridge_environment(spec)
    environment.pop("CODEX_HOME", None)
    return environment


def _revalidate_git_binding(spec: Mapping[str, Any]) -> None:
    executable = _absolute_file(spec["git_executable"], "git_executable")
    _verify_executable_binding(
        executable,
        "git_executable",
        expected_size=int(spec["git_executable_size_bytes"]),
        expected_sha256=str(spec["git_executable_sha256"]),
    )


def _git_process(
    spec: Mapping[str, Any],
    args: Sequence[str],
    *,
    allow_codes: set[int] | None = None,
) -> bytes:
    _revalidate_scratch_boundaries(spec)
    _revalidate_git_binding(spec)
    completed = _run_process(
        [
            str(spec["git_executable"]),
            "-C",
            str(spec["scratch_root"]),
            "--git-dir",
            str(Path(spec["scratch_root"]) / ".git"),
            "--work-tree",
            str(spec["scratch_root"]),
            *args,
        ],
        timeout_seconds=min(float(spec["timeout_seconds"]), 30.0),
        allow_codes=allow_codes,
        environment=_git_environment(spec),
    )
    return completed.stdout


def _optional_lstat(path: Path, label: str) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CanaryError(f"could not inspect {label}") from exc


def _reject_git_authority_path(path: Path, label: str) -> None:
    if _optional_lstat(path, label) is not None:
        raise CanaryError(f"scratch Git repository contains forbidden {label}")


def _git_metadata_binding(spec: Mapping[str, Any]) -> dict[str, Any]:
    """Bind all local Git metadata while rejecting alternate authority."""

    root = Path(spec["scratch_root"])
    git_dir = root / ".git"
    _require_local_directory(git_dir, "scratch .git")
    for relative, label in (
        ("commondir", "commondir"),
        ("gitdir", "linked-worktree gitdir marker"),
        ("config.worktree", "worktree config"),
        ("worktrees", "linked-worktree metadata"),
        ("shallow", "shallow repository state"),
        ("shallow.lock", "shallow repository lock"),
        ("info/grafts", "grafts"),
        ("objects/info/alternates", "object alternates"),
        ("objects/info/http-alternates", "HTTP object alternates"),
        ("objects/info/alternates.lock", "object alternates lock"),
        ("refs/replace", "replace refs"),
    ):
        _reject_git_authority_path(git_dir / Path(relative), label)

    rows: list[dict[str, Any]] = []
    total_bytes = 0
    total_entries = 0
    pending = [git_dir]
    while pending:
        directory = pending.pop()
        _require_local_directory(
            directory,
            f"scratch Git metadata directory {directory.relative_to(git_dir).as_posix()}",
        )
        try:
            directory_before = directory.lstat()
            with os.scandir(directory) as entries:
                children = sorted(
                    (Path(entry.path) for entry in entries),
                    key=lambda item: item.name,
                )
            directory_after = directory.lstat()
        except OSError as exc:
            raise CanaryError("could not enumerate scratch Git metadata") from exc
        if _path_stat_fingerprint(directory_before) != _path_stat_fingerprint(
            directory_after
        ):
            raise CanaryError("scratch Git metadata changed while enumerated")
        total_entries += len(children)
        if total_entries > _MAX_ENTRIES:
            raise CanaryError("scratch Git metadata exceeds bounded limits")
        for path in children:
            relative_path = path.relative_to(git_dir)
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise CanaryError("could not inspect scratch Git metadata") from exc
            if (
                stat.S_ISLNK(metadata.st_mode)
                or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
            ):
                raise CanaryError("scratch Git metadata cannot contain links or reparses")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise CanaryError("scratch Git metadata cannot contain special files")
            size, sha256 = _stable_regular_file_sha256(
                path,
                f"scratch Git metadata/{relative_path.as_posix()}",
                max_bytes=_MAX_FILE_BYTES,
                min_bytes=0,
            )
            total_bytes += size
            if total_bytes > _MAX_TOTAL_BYTES or len(rows) >= _MAX_FILES:
                raise CanaryError("scratch Git metadata exceeds bounded limits")
            rows.append(
                {
                    "path": relative_path.as_posix(),
                    "size_bytes": size,
                    "sha256": sha256,
                }
            )

    packed_refs = git_dir / "packed-refs"
    if _optional_lstat(packed_refs, "scratch packed-refs") is not None:
        packed = _bounded_regular_bytes(
            packed_refs,
            "scratch packed-refs",
            max_bytes=_LOCAL_FILES_MAX_BYTES,
        )
        if any(
            line and not line.startswith((b"#", b"^")) and b" refs/replace/" in line
            for line in packed.splitlines()
        ):
            raise CanaryError("scratch Git repository contains packed replace refs")
    ordered = sorted(rows, key=lambda row: str(row["path"]))
    return {
        "files_sha256": _digest(ordered),
        "file_count": len(ordered),
        "total_bytes": total_bytes,
    }


def _git_raw(
    spec: Mapping[str, Any],
    args: Sequence[str],
    *,
    allow_codes: set[int] | None = None,
) -> bytes:
    before = _git_metadata_binding(spec)
    output = _git_process(spec, args, allow_codes=allow_codes)
    after = _git_metadata_binding(spec)
    if after != before:
        raise CanaryError("scratch Git metadata changed across Git command")
    return output


def _local_git_config_binding(spec: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(spec["scratch_root"])
    config_path = root / ".git" / "config"
    before = _bounded_regular_bytes(
        config_path,
        "scratch .git/config",
        max_bytes=_LOCAL_FILES_MAX_BYTES,
    )
    output = _git_raw(
        spec,
        [
            "config",
            "--file",
            str(config_path),
            "--no-includes",
            "--null",
            "--show-origin",
            "--list",
        ],
    )
    after = _bounded_regular_bytes(
        config_path,
        "scratch .git/config",
        max_bytes=_LOCAL_FILES_MAX_BYTES,
    )
    if before != after:
        raise CanaryError("scratch .git/config changed while inspected")
    parts = output.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    if not parts or len(parts) % 2:
        raise CanaryError("scratch .git/config inventory is malformed")
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    try:
        for index in range(0, len(parts), 2):
            origin = parts[index].decode("utf-8", errors="strict")
            key_value = parts[index + 1].decode("utf-8", errors="strict")
            key, separator, value = key_value.partition("\n")
            normalized_key = key.casefold()
            if normalized_key.startswith("remote."):
                raise CanaryError(
                    "scratch .git/config contains a Git remote"
                )
            if (
                not separator
                or not origin.startswith("file:")
                or not _same_path(Path(origin[5:]), config_path)
                or normalized_key in seen
                or normalized_key not in _LOCAL_GIT_CONFIG_KEYS
            ):
                raise CanaryError(
                    "scratch .git/config contains unapproved local authority"
                )
            seen.add(normalized_key)
            rows.append({"key": normalized_key, "value": value})
    except UnicodeDecodeError as exc:
        raise CanaryError("scratch .git/config is not strict UTF-8") from exc
    values = {row["key"]: row["value"].casefold() for row in rows}
    if (
        values.get("core.repositoryformatversion") != "0"
        or values.get("core.bare") != "false"
        or values.get("core.autocrlf") != "false"
    ):
        raise CanaryError(
            "scratch .git/config lacks the exact non-bare/autocrlf contract"
        )
    return {
        "path": _contract_path(config_path),
        "sha256": hashlib.sha256(before).hexdigest(),
        "keys": sorted(seen),
    }


def _git_repository_path_binding(spec: Mapping[str, Any]) -> dict[str, str]:
    root = Path(spec["scratch_root"])
    git_dir = root / ".git"
    output = _git_raw(
        spec,
        [
            "rev-parse",
            "--absolute-git-dir",
            "--git-common-dir",
            "--git-path",
            "objects",
            "--git-path",
            "refs",
            "--show-toplevel",
        ],
    )
    try:
        rows = output.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise CanaryError("scratch Git path inventory is not strict UTF-8") from exc
    if len(rows) != 5 or any(not row for row in rows):
        raise CanaryError("scratch Git path inventory is malformed")
    expected = [
        git_dir,
        git_dir,
        git_dir / "objects",
        git_dir / "refs",
        root,
    ]
    labels = ["git_dir", "git_common_dir", "objects", "refs", "work_tree"]
    for row, target, label in zip(rows, expected, labels, strict=True):
        candidate = Path(row)
        if not candidate.is_absolute():
            candidate = root / candidate
        if not _same_path(candidate, target):
            raise CanaryError(
                f"scratch Git {label} escapes the exact disposable repository"
            )
    _require_local_directory(git_dir / "objects", "scratch Git objects")
    _require_local_directory(git_dir / "refs", "scratch Git refs")
    return {
        label: _contract_path(target)
        for label, target in zip(labels, expected, strict=True)
    }


def _git_authority_binding(spec: Mapping[str, Any]) -> dict[str, Any]:
    before = _git_metadata_binding(spec)
    local_config = _local_git_config_binding(spec)
    paths = _git_repository_path_binding(spec)
    after = _git_metadata_binding(spec)
    if after != before:
        raise CanaryError("scratch Git repository authority changed while inspected")
    return {
        "metadata": before,
        "local_config": local_config,
        "paths": paths,
    }


def _git(
    spec: Mapping[str, Any],
    args: Sequence[str],
    *,
    allow_codes: set[int] | None = None,
) -> bytes:
    before = _git_authority_binding(spec)
    output = _git_raw(spec, args, allow_codes=allow_codes)
    after = _git_authority_binding(spec)
    if after != before:
        raise CanaryError("scratch Git repository authority changed across Git command")
    return output


def _require_local_directory(path: Path, label: str) -> None:
    try:
        value = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CanaryError(f"could not inspect {label}") from exc
    if (
        stat.S_ISLNK(value.st_mode)
        or not stat.S_ISDIR(value.st_mode)
        or bool(getattr(value, "st_file_attributes", 0) & 0x400)
        or not _same_physical_path(path, resolved)
    ):
        raise CanaryError(f"{label} must be a local non-reparse directory")


def _revalidate_scratch_boundaries(spec: Mapping[str, Any]) -> None:
    root = Path(spec["scratch_root"])
    _require_local_directory(root, "scratch_root")
    _require_local_directory(root / ".git", "scratch .git")
    _require_local_directory(root / ".aoi", "scratch .aoi")


def _validate_scratch(spec: Mapping[str, Any]) -> None:
    root = Path(spec["scratch_root"])
    marker = _absolute_file(root / ROOT_MARKER, "scratch marker")
    marker_bytes = _bounded_regular_bytes(
        marker,
        "scratch marker",
        max_bytes=_ROOT_MARKER_MAX_BYTES,
    )
    try:
        marker_value = _strict_json_loads(marker_bytes, "scratch marker")
    except CanaryError as exc:
        raise CanaryError("scratch marker must be strict UTF-8 JSON") from exc
    expected_marker = {
        "schema_version": ROOT_MARKER_SCHEMA,
        "purpose": "disposable Codex transport canary",
        "mode": spec["mode"],
    }
    if marker_value != expected_marker:
        raise CanaryError("scratch marker does not exactly authorize this mode")
    _revalidate_scratch_boundaries(spec)
    authority = _git_authority_binding(spec)
    top = _git(spec, ["rev-parse", "--show-toplevel"]).decode(
        "utf-8", errors="strict"
    ).strip()
    if not _same_path(Path(top), root):
        raise CanaryError("scratch_root is not the exact Git top level")
    if _git(spec, ["remote"]).strip():
        raise CanaryError("transport canary repository must have no Git remotes")
    autocrlf = _git(
        spec,
        ["config", "--local", "--get", "core.autocrlf"],
        allow_codes={0, 1},
    ).strip().lower()
    if autocrlf != b"false":
        raise CanaryError(
            "transport canary repository must pin local core.autocrlf=false"
        )
    rewrites = _git(
        spec,
        [
            "config",
            "--show-origin",
            "--get-regexp",
            r"^url\..*\.(insteadOf|pushInsteadOf)$",
        ],
        allow_codes={0, 1},
    )
    if rewrites.strip():
        raise CanaryError("transport canary repository inherits URL rewrites")
    status = _git(
        spec, ["status", "--porcelain=v2", "--untracked-files=all"]
    )
    if status.strip():
        raise CanaryError("transport canary repository must begin Git-clean")
    if _git_authority_binding(spec) != authority:
        raise CanaryError("scratch Git repository authority changed during validation")


def _workspace_files(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    total_bytes = 0
    total_entries = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        _require_local_directory(
            directory,
            f"transport canary workload directory {directory}",
        )
        try:
            directory_before = directory.lstat()
            with os.scandir(directory) as entries:
                children = sorted(
                    (Path(entry.path) for entry in entries),
                    key=lambda item: item.name,
                )
            directory_after = directory.lstat()
        except OSError as exc:
            raise CanaryError("could not enumerate transport canary workload") from exc
        if _path_stat_fingerprint(directory_before) != _path_stat_fingerprint(
            directory_after
        ):
            raise CanaryError(
                "transport canary workload directory changed while enumerated"
            )
        total_entries += len(children)
        if total_entries > _MAX_ENTRIES:
            raise CanaryError("transport canary workload exceeds bounded limits")
        for path in children:
            relative = path.relative_to(root)
            if relative.parts and relative.parts[0] in {".git", ".aoi"}:
                _require_local_directory(
                    path,
                    f"scratch {relative.parts[0]}",
                )
                continue
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise CanaryError("could not inspect transport canary workload") from exc
            if (
                stat.S_ISLNK(metadata.st_mode)
                or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
            ):
                raise CanaryError(
                    "transport canary workload cannot contain links or reparses"
                )
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise CanaryError(
                    "transport canary workload cannot contain special files"
                )
            size, sha256 = _stable_regular_file_sha256(
                path,
                f"transport canary workload/{relative.as_posix()}",
                max_bytes=_MAX_FILE_BYTES,
                min_bytes=0,
            )
            total_bytes += size
            if total_bytes > _MAX_TOTAL_BYTES or len(rows) >= _MAX_FILES:
                raise CanaryError(
                    "transport canary workload exceeds bounded limits"
                )
            rows.append(
                {
                    "path": relative.as_posix(),
                    "mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
                    "size_bytes": size,
                    "sha256": sha256,
                }
            )
    return sorted(rows, key=lambda row: str(row["path"]))


def _git_snapshot(spec: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(spec["scratch_root"])
    authority = _git_authority_binding(spec)
    head = _git(spec, ["rev-parse", "HEAD"]).decode(
        "ascii", errors="strict"
    ).strip()
    index = _git(spec, ["ls-files", "--stage", "-z"])
    status = _git(
        spec, ["status", "--porcelain=v2", "--untracked-files=all", "-z"]
    )
    files = _workspace_files(root)
    if _git_authority_binding(spec) != authority:
        raise CanaryError("scratch Git repository authority changed during Git snapshot")
    if _GIT_OID.fullmatch(head) is None:
        raise CanaryError("transport canary requires one committed Git HEAD")
    return {
        "head_sha256": hashlib.sha256(head.encode("ascii")).hexdigest(),
        "index_sha256": hashlib.sha256(index).hexdigest(),
        "status_sha256": hashlib.sha256(status).hexdigest(),
        "workload_files_sha256": _digest(files),
        "workload_files": files,
        "local_config_sha256": str(authority["local_config"]["sha256"]),
        "repository_authority_sha256": _digest(authority),
    }


def _workload_delta_paths(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> list[str]:
    before_rows = before.get("workload_files")
    after_rows = after.get("workload_files")
    if not isinstance(before_rows, list) or not isinstance(after_rows, list):
        raise CanaryError("workload snapshot manifest is missing")
    before_by_path = {
        str(row["path"]): row
        for row in before_rows
        if isinstance(row, Mapping) and isinstance(row.get("path"), str)
    }
    after_by_path = {
        str(row["path"]): row
        for row in after_rows
        if isinstance(row, Mapping) and isinstance(row.get("path"), str)
    }
    if len(before_by_path) != len(before_rows) or len(after_by_path) != len(
        after_rows
    ):
        raise CanaryError("workload snapshot manifest is malformed")
    return sorted(
        path
        for path in set(before_by_path) | set(after_by_path)
        if before_by_path.get(path) != after_by_path.get(path)
    )


def _committed_mutation_paths(mutation: Mapping[str, Any]) -> set[str]:
    encoded = mutation.get("post_mutation_paths_b64")
    digest = mutation.get("post_mutation_paths_sha256")
    if (
        not isinstance(encoded, list)
        or len(encoded) != len(set(encoded))
        or any(not isinstance(value, str) for value in encoded)
        or digest
        != _digest(
            {
                "schema": _GIT_MUTATION_PATHS_SCHEMA,
                "paths_b64": encoded,
            }
        )
    ):
        raise CanaryError(
            "verified mutation does not bind canonical post mutation paths"
        )
    paths: set[str] = set()
    raw_paths: list[bytes] = []
    for value in encoded:
        try:
            raw = base64.b64decode(value.encode("ascii"), validate=True)
            path = raw.decode("utf-8", errors="strict")
        except (UnicodeEncodeError, UnicodeDecodeError, ValueError) as exc:
            raise CanaryError(
                "verified mutation path is not canonical UTF-8 base64"
            ) from exc
        if (
            base64.b64encode(raw).decode("ascii") != value
            or not path
            or "\\" in path
            or path.startswith("/")
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            raise CanaryError("verified mutation path is not canonical")
        raw_paths.append(raw)
        paths.add(path)
    if raw_paths != sorted(raw_paths):
        raise CanaryError("verified mutation paths are not canonically ordered")
    return paths


def _bridge_json(
    spec: Mapping[str, Any],
    args: Sequence[str],
) -> dict[str, Any]:
    _revalidate_bridge_binding(spec)
    install_binding = spec["bridge_install_binding"]
    runtime_python = install_binding["closure"]["bridge_runtime_python"]
    completed = _run_process(
        [
            str(runtime_python["path"]),
            "-I",
            "-S",
            "-B",
            "-X",
            "utf8",
            "-c",
            _BRIDGE_MODULE_BOOTSTRAP,
            str(install_binding["site_packages_root"]),
            "--root",
            str(spec["aoi_root"]),
            *args,
            "--json",
        ],
        timeout_seconds=float(spec["timeout_seconds"]) + 30.0,
        environment=_bridge_environment(spec),
    )
    _revalidate_bridge_binding(spec)
    try:
        value = _strict_json_loads(completed.stdout, "bridge result")
    except CanaryError as exc:
        raise CanaryError("bridge did not return one strict UTF-8 JSON value") from exc
    if not isinstance(value, Mapping):
        raise CanaryError("bridge JSON result is not an object")
    return dict(value)


def _inspect(spec: Mapping[str, Any]) -> dict[str, Any]:
    return _bridge_json(
        spec,
        [
            "inspect",
            "--task",
            str(spec["task_id"]),
            "--launch-id",
            str(spec["launch_id"]),
        ],
    )


def _preflight(spec: Mapping[str, Any]) -> dict[str, Any]:
    return _bridge_json(
        spec,
        [
            "preflight",
            "--task",
            str(spec["task_id"]),
            "--permit-sha256",
            str(spec["permit_sha256"]),
            "--prompt-file",
            str(spec["prompt_file"]),
        ],
    )


def _validate_intent_policy(
    spec: Mapping[str, Any],
    observed: Mapping[str, Any],
    *,
    label: str,
) -> Mapping[str, Any]:
    if (
        observed.get("task_id") != spec["task_id"]
        or observed.get("launch_id") != spec["launch_id"]
    ):
        raise CanaryError(f"{label} does not identify the exact launch")
    intent = observed.get("intent")
    if not isinstance(intent, Mapping):
        raise CanaryError(f"{label} has no authenticated intent")
    expected_runtime = dict(spec["runtime_pin"])
    if (
        intent.get("cwd") != _contract_path(Path(spec["scratch_root"]))
        or intent.get("sandbox") != _MODES[str(spec["mode"])]
        or intent.get("approval") != "never"
        or intent.get("network_access") is not False
        or intent.get("runtime_pin") != expected_runtime
    ):
        raise CanaryError(f"{label} intent differs from the canary policy")
    return intent


def _validate_issued_preflight(
    spec: Mapping[str, Any],
    preflight: Mapping[str, Any],
) -> None:
    expected_fields = {
        "task_id",
        "launch_id",
        "packet_id",
        "packet_status",
        "permit_sha256",
        "intent",
        "issuance",
        "semantic_head_sha256",
        "status",
        "evidence_level",
        "permit_consumed",
        "runtime_evidence",
        "confidentiality_warnings",
        "task_completion",
    }
    if set(preflight) != expected_fields:
        raise CanaryError("issued preflight fields differ from the v4 contract")
    intent = _validate_intent_policy(
        spec,
        preflight,
        label="issued preflight",
    )
    issuance = preflight.get("issuance")
    if (
        preflight.get("packet_id") != intent.get("packet_id")
        or preflight.get("packet_status") != "armed"
        or preflight.get("permit_sha256") != spec["permit_sha256"]
        or preflight.get("status") != "issued_unconsumed"
        or preflight.get("evidence_level") != "transport_issued"
        or preflight.get("permit_consumed") is not False
        or preflight.get("runtime_evidence") != "none"
        or preflight.get("task_completion") != "not_inferred"
        or not isinstance(preflight.get("confidentiality_warnings"), list)
        or not isinstance(issuance, Mapping)
        or issuance.get("task_id") != spec["task_id"]
        or issuance.get("launch_id") != spec["launch_id"]
        or issuance.get("permit_sha256") != spec["permit_sha256"]
        or issuance.get("intent_sha256") != intent.get("intent_sha256")
    ):
        raise CanaryError(
            "issued preflight is not the exact authenticated unconsumed launch"
        )
    _sha256(
        preflight.get("semantic_head_sha256"),
        "issued preflight semantic head",
    )
    _sha256(issuance.get("issuance_sha256"), "issued preflight issuance")


def _validate_policy(
    spec: Mapping[str, Any],
    inspected: Mapping[str, Any],
) -> None:
    if (
        inspected.get("contract_version") != "v2"
    ):
        raise CanaryError("inspect result does not identify the exact V2 launch")
    _validate_intent_policy(spec, inspected, label="inspect result")
    reservation = inspected.get("reservation")
    if not isinstance(reservation, Mapping) or (
        reservation.get("classification") != "committed"
        or reservation.get("evidence_level") != "transport_reserved"
    ):
        raise CanaryError("inspect reservation is not transport_reserved")
    issuance = inspected.get("issuance")
    if (
        reservation.get("permit_sha256") != spec["permit_sha256"]
        or not isinstance(issuance, Mapping)
        or issuance.get("classification") != "committed"
        or issuance.get("permit_sha256") != spec["permit_sha256"]
    ):
        raise CanaryError("inspect result is not bound to the exact permit")
    if inspected.get("task_completion") != "not_inferred":
        raise CanaryError("transport inspect inferred task completion")
    lifecycle = inspected.get("lifecycle")
    if not isinstance(lifecycle, list) or not lifecycle:
        raise CanaryError("transport inspect lifecycle is missing")
    terminal = inspected.get("terminal_receipts")
    if (
        not isinstance(terminal, list)
        or len(terminal) != 1
        or terminal[0].get("classification") != "committed"
        or terminal[0].get("terminal_state") != "completed"
        or terminal[0].get("evidence_level") != "codex_runtime_observed"
        or inspected.get("evidence_level") != "codex_runtime_observed"
    ):
        raise CanaryError("live canary lacks one committed completed receipt")


def _validate_run_result(
    spec: Mapping[str, Any],
    run_result: Mapping[str, Any],
) -> None:
    if (
        run_result.get("task_id") != spec["task_id"]
        or run_result.get("launch_id") != spec["launch_id"]
        or run_result.get("permit_sha256") != spec["permit_sha256"]
        or run_result.get("terminal_state") != "completed"
        or run_result.get("evidence_level") != "codex_runtime_observed"
        or run_result.get("runtime_completed") is not True
        or run_result.get("process_start_evidence")
        != "process_started_observed"
        or run_result.get("app_server_start_durably_observed") is not True
        or run_result.get("runtime_process_boundary_reached") is not True
        or run_result.get("task_completion") != "not_inferred"
    ):
        raise CanaryError("bridge run result is not one completed live launch")
    _sha256(
        run_result.get("terminal_receipt_sha256"),
        "bridge run terminal receipt",
    )


def run_canary(spec: Mapping[str, Any], *, execute: bool) -> dict[str, Any]:
    _validate_scratch(spec)
    before = _git_snapshot(spec)
    issued = _preflight(spec)
    _validate_issued_preflight(spec, issued)
    basis = {
        "schema_version": SCHEMA_VERSION,
        "mode": spec["mode"],
        "task_id": spec["task_id"],
        "launch_id": spec["launch_id"],
        "permit_sha256": spec["permit_sha256"],
        "runtime_pin": spec["runtime_pin"],
        "codex_home_policy": spec["codex_home_policy"],
        "bridge_executable": {
            "path": _contract_path(Path(spec["bridge_executable"])),
            "size_bytes": spec["bridge_executable_size_bytes"],
            "sha256": spec["bridge_executable_sha256"],
        },
        "bridge_install_binding": spec["bridge_install_binding"],
        "git_executable": {
            "path": _contract_path(Path(spec["git_executable"])),
            "size_bytes": spec["git_executable_size_bytes"],
            "sha256": spec["git_executable_sha256"],
        },
        "scratch_root": _contract_path(Path(spec["scratch_root"])),
        "pre_git_snapshot": before,
        "issued_preflight_sha256": _digest(issued),
    }
    if not execute:
        return {
            **basis,
            "status": "preflight_ready",
            "live_app_server_started": False,
            "task_completion": "not_inferred",
        }
    run_result = _bridge_json(
        spec,
        [
            "run",
            "--task",
            str(spec["task_id"]),
            "--permit-sha256",
            str(spec["permit_sha256"]),
            "--prompt-file",
            str(spec["prompt_file"]),
            "--executable",
            str(spec["codex_executable"]),
            "--timeout-seconds",
            str(spec["timeout_seconds"]),
        ],
    )
    _validate_run_result(spec, run_result)
    completed = _inspect(spec)
    _validate_policy(spec, completed)
    after = _git_snapshot(spec)
    if spec["mode"] == "read_only":
        if after != before:
            raise CanaryError("read_only canary changed workload Git bytes")
        mutation: dict[str, Any] | None = None
        evidence_level = "codex_runtime_observed"
    else:
        direct_delta_paths = _workload_delta_paths(before, after)
        if not direct_delta_paths:
            raise CanaryError("workspace_write canary made no workload mutation")
        if (
            after["local_config_sha256"] != before["local_config_sha256"]
            or after["repository_authority_sha256"]
            != before["repository_authority_sha256"]
        ):
            raise CanaryError(
                "workspace_write canary changed Git repository authority"
            )
        verify_args = [
            "verify-mutation",
            "--task",
            str(spec["task_id"]),
            "--launch-id",
            str(spec["launch_id"]),
            "--sealed-claim-scope",
            "--git-executable",
            str(spec["git_executable"]),
            "--git-executable-size-bytes",
            str(spec["git_executable_size_bytes"]),
            "--git-executable-sha256",
            str(spec["git_executable_sha256"]),
        ]
        endpoint = spec["post_git_endpoint_file"]
        if endpoint is not None:
            verify_args.extend(["--post-git-endpoint-file", str(endpoint)])
        mutation = _bridge_json(spec, verify_args)
        expected_git_provenance = {
            "schema": _GIT_EXECUTABLE_BINDING_SCHEMA,
            "path": _contract_path(Path(spec["git_executable"])),
            "size_bytes": spec["git_executable_size_bytes"],
            "sha256": spec["git_executable_sha256"],
            "provenance_scope": _GIT_EXECUTABLE_PROVENANCE_SCOPE,
        }
        if (
            mutation.get("evidence_level") != "verified_mutation"
            or mutation.get("task_completion") != "not_inferred"
            or mutation.get("git_executable") != expected_git_provenance
        ):
            raise CanaryError("writable canary was not elevated to verified_mutation")
        committed_paths = _committed_mutation_paths(mutation)
        missing_paths = sorted(set(direct_delta_paths) - committed_paths)
        if missing_paths:
            raise CanaryError(
                "verified mutation omits direct workload delta paths: "
                + ", ".join(missing_paths)
            )
        evidence_level = "verified_mutation"
    return {
        **basis,
        "status": "completed",
        "live_app_server_started": True,
        "run_result_sha256": _digest(run_result),
        "completed_inspect_sha256": _digest(completed),
        "post_git_snapshot": after,
        "mutation_receipt": mutation,
        "evidence_level": evidence_level,
        "task_completion": "not_inferred",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preflight or run one disposable Codex transport canary"
    )
    parser.add_argument("--spec", required=True)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="consume the permit and start App Server; absent means preflight-only",
    )
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        spec = load_spec(Path(args.spec))
        result = run_canary(spec, execute=args.execute)
    except (CanaryError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(
            f"{result['status']}: {result['mode']} "
            f"launch {result['launch_id']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
