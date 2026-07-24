"""Run one bounded Codex transport canary in a disposable local repository.

This driver never issues authority.  It consumes an already issued one-shot
transport permit, refuses non-disposable or remotely connected repositories,
and separates read-only runtime evidence from writable Git-mutation evidence.
The default is preflight-only; ``--execute`` is required to start App Server.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import tomllib
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "aoi.codex-transport-canary.v3"
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
_LOCAL_FILES_MAX_BYTES = 1_048_576
_ROOT_MARKER_MAX_BYTES = 4096
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
    return path.resolve()


def _absolute_directory(value: Any, label: str) -> Path:
    raw = _text(value, label, limit=4096)
    path = Path(raw)
    if (
        not path.is_absolute()
        or not path.is_dir()
        or path.is_symlink()
        or _is_reparse(path, label=label)
    ):
        raise CanaryError(f"{label} must be an existing absolute directory")
    return path.resolve()


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


def _bounded_regular_bytes(
    path: Path,
    label: str,
    *,
    max_bytes: int = _LOCAL_FILES_MAX_BYTES,
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
        if size < 1 or size > max_bytes:
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


def _bridge_environment(spec: Mapping[str, Any]) -> dict[str, str]:
    """Return the bounded child environment for bridge-owned subprocesses."""

    environment: dict[str, str] = {}
    for name, value in os.environ.items():
        upper = name.upper()
        if (
            upper == "CODEX_HOME"
            or upper in _AOI_SECRET_ENV_NAMES
            or upper.startswith(_AOI_SECRET_ENV_PREFIXES)
            or upper == "AOI_BACKUP_ROOT"
            or upper.startswith("PYTHON")
            or upper in _PYTHON_RUNTIME_ENV_NAMES
            or _is_publish_credential_name(name)
            or _is_git_routing_environment_name(name)
        ):
            continue
        environment[name] = value
    environment["CODEX_HOME"] = str(spec["codex_home_policy"]["codex_home"])
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTHONSAFEPATH"] = "1"
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
    completed = _run_process(
        [
            str(spec["bridge_executable"]),
            "--root",
            str(spec["aoi_root"]),
            *args,
            "--json",
        ],
        timeout_seconds=float(spec["timeout_seconds"]) + 30.0,
        environment=_bridge_environment(spec),
    )
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


def _validate_policy(
    spec: Mapping[str, Any],
    inspected: Mapping[str, Any],
    *,
    fresh: bool,
) -> None:
    if (
        inspected.get("task_id") != spec["task_id"]
        or inspected.get("launch_id") != spec["launch_id"]
        or inspected.get("contract_version") != "v2"
    ):
        raise CanaryError("inspect result does not identify the exact V2 launch")
    intent = inspected.get("intent")
    if not isinstance(intent, Mapping):
        raise CanaryError("inspect result has no authenticated intent")
    expected_runtime = dict(spec["runtime_pin"])
    if (
        intent.get("cwd") != _contract_path(Path(spec["scratch_root"]))
        or intent.get("sandbox") != _MODES[str(spec["mode"])]
        or intent.get("approval") != "never"
        or intent.get("network_access") is not False
        or intent.get("runtime_pin") != expected_runtime
    ):
        raise CanaryError("inspect intent differs from the canary policy")
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
    if fresh:
        if (
            len(lifecycle) != 1
            or lifecycle[0].get("event_type") != "reserved"
            or inspected.get("terminal_receipts") != []
            or inspected.get("evidence_level") != "transport_reserved"
        ):
            raise CanaryError("canary launch is not one fresh reservation")
        return
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


def run_canary(spec: Mapping[str, Any], *, execute: bool) -> dict[str, Any]:
    _validate_scratch(spec)
    before = _git_snapshot(spec)
    reserved = _inspect(spec)
    _validate_policy(spec, reserved, fresh=True)
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
        "git_executable": {
            "path": _contract_path(Path(spec["git_executable"])),
            "size_bytes": spec["git_executable_size_bytes"],
            "sha256": spec["git_executable_sha256"],
        },
        "scratch_root": _contract_path(Path(spec["scratch_root"])),
        "pre_git_snapshot": before,
        "reserved_inspect_sha256": _digest(reserved),
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
    completed = _inspect(spec)
    _validate_policy(spec, completed, fresh=False)
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
