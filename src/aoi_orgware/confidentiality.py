"""Local-files confidentiality inspection and governed publication gates.

The ``local_files`` profile is intentionally narrower than DLP or an air gap.
It allows model context, but AOI-managed file/Git/artifact publication fails
closed.  This module never reads credential values into its report.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
import os
from pathlib import Path
import re
from typing import Any
from urllib.parse import unquote_to_bytes, urlsplit, urlunsplit

from .config import ConfidentialityConfig
from . import external_exports
from .git_plumbing import _run_git_bytes_bounded
from .harnesslib import HarnessError


CONFIDENTIALITY_REPORT_SCHEMA_VERSION = 1
MAX_CONFIG_ENTRIES = 8_192
MAX_REMOTE_COUNT = 256
MAX_WORKFLOW_FILES = 512
MAX_ATTRIBUTE_FILES = 256
MAX_ATTRIBUTE_FILE_BYTES = 256 * 1024

_DRIVE_UNKNOWN = 0
_DRIVE_NO_ROOT_DIR = 1
_DRIVE_REMOVABLE = 2
_DRIVE_FIXED = 3
_DRIVE_REMOTE = 4
_DRIVE_CDROM = 5
_DRIVE_RAMDISK = 6
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_CONFIRMED_LOCAL_DRIVE_TYPES = frozenset(
    {_DRIVE_REMOVABLE, _DRIVE_FIXED, _DRIVE_CDROM, _DRIVE_RAMDISK}
)

_PUBLICATION_ACTIONS = frozenset(
    {
        "git_push",
        "remote_ci",
        "release_publish",
        "package_publish",
        "artifact_upload",
        "attachment_publish",
        "connector_publish",
    }
)
_STRONG_PUBLISH_CREDENTIAL_NAMES = frozenset(
    {
        "GH_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_PAT",
        "GITHUB_TOKEN",
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
_STRONG_PUBLISH_CREDENTIAL_PREFIXES = (
    "TWINE_",
    "PYPI_",
    "ARTIFACTORY_",
    "JFROG_",
)
_SYNC_PATH_NAMES = frozenset(
    {
        "onedrive",
        "dropbox",
        "google drive",
        "googledrive",
        "icloud drive",
        "box",
    }
)
_WORKFLOW_FILES = (
    ".gitlab-ci.yml",
    "azure-pipelines.yml",
    "Jenkinsfile",
    ".circleci/config.yml",
)


class ConfidentialityError(HarnessError):
    """A governed operation contradicts the active confidentiality profile."""


def is_publish_credential_environment_name(name: str) -> bool:
    """Return whether an environment variable conveys reusable publish authority.

    Only a finite set of known variable names and prefixes is inspected; this
    is not secret discovery and cannot prove that an unlisted credential is
    absent.  The helper deliberately excludes model-service authentication
    such as OpenAI API credentials because the ``local_files`` profile allows
    model context and is not an offline profile.
    """

    if not isinstance(name, str):
        return False
    upper = name.upper()
    return upper in _STRONG_PUBLISH_CREDENTIAL_NAMES or upper.startswith(
        _STRONG_PUBLISH_CREDENTIAL_PREFIXES
    )


def require_publication_action_allowed(
    policy: ConfidentialityConfig,
    action: str,
) -> None:
    """Reject AOI-managed publication under ``local_files``.

    Exact external export is deliberately not in this generic action set.  It
    must go through the separate one-shot permit path instead of this helper.
    """

    if action not in _PUBLICATION_ACTIONS:
        raise ConfidentialityError(f"unknown publication action: {action!r}")
    if policy.local_files:
        raise ConfidentialityError(
            f"confidentiality profile local_files denies {action}; "
            "local Git/evidence remain allowed and external export requires "
            "an exact Chief-issued one-shot permit"
        )


def _decode_lines(raw: bytes, label: str) -> list[str]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ConfidentialityError(f"{label} is not strict UTF-8") from exc
    lines = [line for line in text.splitlines() if line]
    if len(lines) > MAX_CONFIG_ENTRIES:
        raise ConfidentialityError(f"{label} exceeds its entry bound")
    return lines


def _git_lines(root: Path, arguments: Iterable[str], label: str) -> list[str]:
    return _decode_lines(
        _run_git_bytes_bounded(root, arguments, label=label),
        label,
    )


def _git_config(root: Path) -> list[tuple[str, str]]:
    raw = _run_git_bytes_bounded(
        root,
        ("config", "--null", "--list"),
        label="confidentiality Git config inspection",
    )
    try:
        records = raw.decode("utf-8", errors="strict").split("\x00")
    except UnicodeDecodeError as exc:
        raise ConfidentialityError("Git config is not strict UTF-8") from exc
    result: list[tuple[str, str]] = []
    for record in records:
        if not record:
            continue
        if "\n" not in record:
            raise ConfidentialityError("Git config output is malformed")
        key, value = record.split("\n", 1)
        if not key or "\x00" in value:
            raise ConfidentialityError("Git config entry is malformed")
        result.append((key.casefold(), value))
        if len(result) > MAX_CONFIG_ENTRIES:
            raise ConfidentialityError("Git config exceeds its entry bound")
    return result


def _win32_drive_type(volume_root: str) -> int:
    """Return ``GetDriveTypeW`` for one canonical ``X:\\`` root."""

    import ctypes

    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise OSError("Win32 loader is unavailable")
    kernel32 = loader("kernel32", use_last_error=True)
    get_drive_type = kernel32.GetDriveTypeW
    get_drive_type.argtypes = [ctypes.c_wchar_p]
    get_drive_type.restype = ctypes.c_uint
    return int(get_drive_type(volume_root))


def _win32_dos_device(drive_name: str) -> str:
    """Return the bounded ``QueryDosDeviceW`` target for ``X:``."""

    import ctypes

    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise OSError("Win32 loader is unavailable")
    kernel32 = loader("kernel32", use_last_error=True)
    query = kernel32.QueryDosDeviceW
    query.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
    query.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32_768)
    length = int(query(drive_name, buffer, len(buffer)))
    if length <= 0:
        raise OSError("QueryDosDeviceW failed")
    return buffer.value


def _windows_path_kind(value: str) -> str:
    """Classify one lexical or resolved Win32 path by its visible drive."""

    if value.startswith(("\\\\", "//")):
        return "network_path"
    if value.startswith("\\\\?\\"):
        value = value[4:]
        if value.casefold().startswith("unc\\"):
            return "network_path"
    match = re.match(r"^([A-Za-z]):(?:[\\/]|$)", value)
    if match is None:
        return "unverified_local_path"
    drive_name = f"{match.group(1).upper()}:"
    volume_root = drive_name + "\\"
    try:
        drive_type = _win32_drive_type(volume_root)
    except (AttributeError, OSError, TypeError, ValueError):
        return "unverified_local_path"
    if drive_type == _DRIVE_REMOTE:
        return "network_path"
    if drive_type in {_DRIVE_UNKNOWN, _DRIVE_NO_ROOT_DIR}:
        return "unverified_local_path"
    if drive_type not in _CONFIRMED_LOCAL_DRIVE_TYPES:
        return "unverified_local_path"
    try:
        device_target = _win32_dos_device(drive_name).casefold()
    except (AttributeError, OSError, TypeError, ValueError):
        return "unverified_local_path"
    if "\\device\\mup" in device_target or "redirector" in device_target:
        return "network_path"
    if device_target.startswith("\\??\\unc\\"):
        return "network_path"
    if device_target.startswith("\\??\\"):
        return "unverified_local_path"
    return "local_path"


def _windows_volume_kind(path: Path) -> str | None:
    """Classify both caller-visible and resolved Windows volume identities.

    ``None`` means that Windows drive classification does not apply on this
    platform.  The lexical drive is checked first so ``Path.resolve()`` cannot
    erase a mapped/SUBST alias before ``GetDriveTypeW``/``QueryDosDeviceW`` see
    it.  The resolved target is then checked independently.  Either side being
    network or unverified prevents promotion to confirmed local storage.
    """

    if os.name != "nt":
        return None
    try:
        lexical = path.expanduser()
        if not lexical.is_absolute():
            lexical = Path.cwd() / lexical
    except (OSError, RuntimeError):
        return "unverified_local_path"
    lexical_kind = _windows_path_kind(str(lexical))
    if lexical_kind != "local_path":
        return lexical_kind
    try:
        resolved = path.expanduser().resolve(strict=False)
    except (OSError, RuntimeError):
        return "unverified_local_path"
    resolved_kind = _windows_path_kind(str(resolved))
    if resolved_kind != "local_path":
        return resolved_kind
    return "local_path"


def _decode_file_uri_path(value: str) -> str | None:
    """Decode one file-URI path exactly enough to classify its real drive."""

    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        return None
    try:
        decoded = unquote_to_bytes(value).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    if "\x00" in decoded:
        return None
    return decoded


def _path_has_windows_reparse_attribute(path: Path) -> bool:
    """Read the generic Win32 reparse bit, including non-link reparse tags."""

    metadata = path.lstat()
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _filesystem_destination_kind(value: str, root: Path) -> str:
    path = Path(value)
    if not path.is_absolute() and not re.match(r"^[A-Za-z]:[\\/]", value):
        path = root / path
    windows_kind = _windows_volume_kind(path)
    if windows_kind is not None:
        return windows_kind
    return "local_path" if not str(path).startswith(("\\\\", "//")) else "network_path"


def _destination_kind(value: str, root: Path) -> str:
    candidate = value.strip()
    if not candidate:
        return "invalid"
    if candidate.startswith(("\\\\", "//")):
        return "network_path"
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return "invalid"
    if parsed.scheme:
        if len(parsed.scheme) == 1 and re.match(r"^[A-Za-z]:[\\/]", candidate):
            return _filesystem_destination_kind(candidate, root)
        if parsed.scheme.casefold() == "file":
            try:
                hostname = parsed.hostname or ""
                port = parsed.port
                username = parsed.username
                password = parsed.password
            except ValueError:
                return "invalid"
            if port is not None or username is not None or password is not None:
                return "invalid"
            if hostname.casefold() not in {"", "localhost"}:
                return "network_path"
            decoded_path = _decode_file_uri_path(parsed.path)
            if decoded_path is None:
                return "invalid"
            file_path = decoded_path
            if re.match(r"^/[A-Za-z]:/", file_path):
                file_path = file_path[1:]
            return _filesystem_destination_kind(file_path, root)
        try:
            _ = parsed.hostname
            _ = parsed.port
        except ValueError:
            return "invalid"
        return "external_url"
    if re.match(r"^(?:[^/@:]+@)?[^/:]+:.+", candidate):
        return "external_url"
    return _filesystem_destination_kind(candidate, root)


def _redacted_destination(value: str, root: Path) -> str:
    kind = _destination_kind(value, root)
    candidate = value.strip()
    if kind == "local_path":
        return "<local-path>"
    if kind == "network_path":
        return "<network-path>"
    if kind == "unverified_local_path":
        return "<unverified-local-path>"
    if kind == "invalid":
        return "<invalid>"
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return "<invalid>"
    if parsed.scheme:
        try:
            hostname = parsed.hostname or ""
            port_value = parsed.port
        except ValueError:
            return "<invalid>"
        port = f":{port_value}" if port_value is not None else ""
        return urlunsplit((parsed.scheme.casefold(), hostname + port, "", "", ""))
    if ":" in candidate:
        host = candidate.split(":", 1)[0].rsplit("@", 1)[-1]
        return f"ssh://{host}"
    return "<invalid>"


def _path_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _sync_roots(environment: Mapping[str, str]) -> list[Path]:
    names = {
        "ONEDRIVE",
        "ONEDRIVECOMMERCIAL",
        "ONEDRIVECONSUMER",
        "DROPBOX",
        "GOOGLEDRIVE",
        "GOOGLE_DRIVE",
    }
    result: list[Path] = []
    for name, value in environment.items():
        if name.upper() not in names or not value:
            continue
        try:
            resolved = Path(value).expanduser().resolve(strict=False)
        except OSError:
            continue
        if resolved not in result:
            result.append(resolved)
    return result


def _sync_findings(path: Path, environment: Mapping[str, str]) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    lexical = path.expanduser()
    if not lexical.is_absolute():
        lexical = Path.cwd() / lexical
    resolved = path.resolve(strict=False)
    volume_kind = _windows_volume_kind(path)
    if str(resolved).startswith(("\\\\", "//")) or volume_kind == "network_path":
        errors.append(f"confirmed network storage path is denied: {resolved}")
    elif volume_kind == "unverified_local_path":
        errors.append(
            "storage path locality is unverified because its Windows volume "
            f"metadata is unavailable or aliased: {resolved}"
        )
    folded_parts = {part.casefold() for part in resolved.parts}
    matched_names = sorted(folded_parts & _SYNC_PATH_NAMES)
    if matched_names:
        errors.append(
            "storage path is inside a commonly synchronized folder: "
            + ", ".join(matched_names)
        )
    for sync_root in _sync_roots(environment):
        if _path_within(resolved, sync_root):
            errors.append(f"storage path is inside configured sync root: {sync_root}")
    inspected: set[Path] = set()
    for starting_path in (lexical, resolved):
        current = starting_path
        while current not in inspected:
            inspected.add(current)
            try:
                is_junction = getattr(current, "is_junction", None)
                if (
                    current.is_symlink()
                    or (is_junction is not None and is_junction())
                    or _path_has_windows_reparse_attribute(current)
                ):
                    errors.append(
                        "storage path locality is unverified because it traverses "
                        f"a link/reparse point: {current}"
                    )
                    break
            except FileNotFoundError:
                if current.parent == current:
                    break
                current = current.parent
                continue
            except OSError:
                errors.append(f"storage path locality is unverified at: {current}")
                break
            if current.parent == current:
                break
            current = current.parent
    return errors, warnings


def require_local_storage_path_allowed(
    policy: ConfidentialityConfig,
    path: Path,
    *,
    label: str,
    environment: Mapping[str, str] | None = None,
) -> list[str]:
    """Fail closed for a confirmed publication-prone local storage path.

    This is a narrow launch-time enforcement slice, not a DLP or air-gap
    claim.  Confirmed network/sync roots are denied under ``local_files``;
    locality uncertainty is labelled separately from confirmed danger, but is
    still denied because a launch/storage gate must require confirmed-local
    evidence.
    """

    if not policy.local_files:
        return []
    env = dict(os.environ if environment is None else environment)
    errors, warnings = _sync_findings(path, env)
    if errors:
        raise ConfidentialityError(
            f"confidentiality profile local_files denies {label}: "
            + "; ".join(errors)
        )
    return [f"{label}: {item}" for item in warnings]


def _workflow_files(root: Path) -> list[str]:
    result: list[str] = []
    workflow_root = root / ".github" / "workflows"
    if workflow_root.is_dir() and not workflow_root.is_symlink():
        for candidate in sorted(workflow_root.iterdir(), key=lambda item: item.name):
            if candidate.is_file() and not candidate.is_symlink() and candidate.suffix.casefold() in {".yml", ".yaml"}:
                result.append(candidate.relative_to(root).as_posix())
                if len(result) >= MAX_WORKFLOW_FILES:
                    break
    for relative in _WORKFLOW_FILES:
        candidate = root / relative
        if candidate.is_file() and not candidate.is_symlink():
            result.append(relative)
    return sorted(set(result))[:MAX_WORKFLOW_FILES]


def _lfs_tracked(root: Path) -> tuple[bool, list[str]]:
    paths = _run_git_bytes_bounded(
        root,
        ("ls-files", "-z", "*.gitattributes", "**/.gitattributes"),
        label="confidentiality Git attributes inspection",
    )
    try:
        names = [item for item in paths.decode("utf-8", errors="strict").split("\x00") if item]
    except UnicodeDecodeError as exc:
        raise ConfidentialityError("Git attributes paths are not strict UTF-8") from exc
    if len(names) > MAX_ATTRIBUTE_FILES:
        raise ConfidentialityError("Git attributes file count exceeds its bound")
    matches: list[str] = []
    for name in names:
        candidate = (root / name).resolve(strict=True)
        if not _path_within(candidate, root.resolve(strict=True)):
            raise ConfidentialityError("Git attributes path escapes the worktree")
        if candidate.is_symlink() or not candidate.is_file():
            raise ConfidentialityError("Git attributes path is not one regular local file")
        raw = candidate.read_bytes()
        if len(raw) > MAX_ATTRIBUTE_FILE_BYTES:
            raise ConfidentialityError("Git attributes file exceeds its byte bound")
        if b"filter=lfs" in raw.replace(b" ", b""):
            matches.append(name.replace("\\", "/"))
    return bool(matches), matches


def inspect_confidentiality(
    *,
    root: Path,
    state_dir: Path,
    policy: ConfidentialityConfig,
    config_sha256: str,
    tasks: Iterable[Mapping[str, Any]],
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return a bounded, redacted confidentiality doctor report."""

    root = root.resolve(strict=True)
    state_dir = state_dir.resolve(strict=False)
    env = dict(os.environ if environment is None else environment)
    task_rows = [dict(task) for task in tasks]
    errors: list[str] = []
    warnings: list[str] = []

    config_entries = _git_config(root)
    remotes = _git_lines(root, ("remote",), "confidentiality Git remote inspection")
    if len(remotes) > MAX_REMOTE_COUNT or len(remotes) != len(set(remotes)):
        raise ConfidentialityError("Git remote collection is invalid or over bound")
    remote_rows: list[dict[str, Any]] = []
    external_push_remotes: list[str] = []
    unverified_push_remotes: list[str] = []
    for remote in remotes:
        if not remote or any(character in remote for character in "\x00\r\n"):
            raise ConfidentialityError("Git remote name is invalid")
        fetch_urls = _git_lines(
            root,
            ("remote", "get-url", "--all", remote),
            f"Git remote {remote} fetch URL inspection",
        )
        push_urls = _git_lines(
            root,
            ("remote", "get-url", "--push", "--all", remote),
            f"Git remote {remote} push URL inspection",
        )
        push_kinds = [_destination_kind(item, root) for item in push_urls]
        if any(kind == "unverified_local_path" for kind in push_kinds):
            unverified_push_remotes.append(remote)
        if any(kind not in {"local_path", "unverified_local_path"} for kind in push_kinds):
            external_push_remotes.append(remote)
        remote_rows.append(
            {
                "name": remote,
                "fetch": [
                    {"kind": _destination_kind(item, root), "destination": _redacted_destination(item, root)}
                    for item in fetch_urls
                ],
                "push": [
                    {"kind": kind, "destination": _redacted_destination(item, root)}
                    for item, kind in zip(push_urls, push_kinds, strict=True)
                ],
            }
        )

    rewrites: list[dict[str, str]] = []
    lfs_endpoints: list[dict[str, str]] = []
    credential_helpers: list[str] = []
    for key, value in config_entries:
        if key.startswith("url.") and key.endswith((".pushinsteadof", ".insteadof")):
            suffix = ".pushinsteadof" if key.endswith(".pushinsteadof") else ".insteadof"
            target = key[4 : -len(suffix)]
            kind = _destination_kind(target, root)
            rewrites.append(
                {
                    "kind": suffix[1:],
                    "target_kind": kind,
                    "target": _redacted_destination(target, root),
                    "match": _redacted_destination(value, root),
                }
            )
            if policy.local_files and kind == "unverified_local_path":
                errors.append(
                    f"Git {suffix[1:]} rewrite target could not be confirmed local"
                )
            elif policy.local_files and kind != "local_path":
                errors.append(f"Git {suffix[1:]} rewrites pushes toward an external destination")
        if key in {"lfs.url", "lfs.pushurl"} or (
            key.startswith("remote.") and key.endswith((".lfsurl", ".lfspushurl"))
        ):
            kind = _destination_kind(value, root)
            lfs_endpoints.append(
                {"key": key, "kind": kind, "destination": _redacted_destination(value, root)}
            )
            if policy.local_files and kind == "unverified_local_path":
                errors.append(f"Git LFS endpoint {key} could not be confirmed local")
            elif policy.local_files and kind != "local_path":
                errors.append(f"Git LFS endpoint {key} is external")
        if key == "credential.helper":
            credential_helpers.append(value.strip() or "<empty>")

    try:
        lfs_tracked, lfs_attribute_files = _lfs_tracked(root)
    except (OSError, HarnessError) as exc:
        raise ConfidentialityError(f"could not inspect Git LFS attributes: {exc}") from exc
    if policy.local_files and external_push_remotes:
        errors.append(
            "effective Git push URL is external for remote(s): "
            + ", ".join(sorted(external_push_remotes))
        )
    if policy.local_files and unverified_push_remotes:
        errors.append(
            "effective Git push URL could not be confirmed local for remote(s): "
            + ", ".join(sorted(unverified_push_remotes))
        )
    if policy.local_files and lfs_tracked and external_push_remotes:
        errors.append("Git LFS-tracked content inherits an external push destination")

    storage_errors, storage_warnings = _sync_findings(state_dir, env)
    if policy.local_files:
        errors.extend(storage_errors)
        warnings.extend(storage_warnings)
    workflows = _workflow_files(root)
    if policy.local_files and workflows:
        warnings.append(
            "remote CI/release workflow files are present but non-qualifying and must not be triggered"
        )

    environment_credentials = sorted(
        name
        for name in env
        if is_publish_credential_environment_name(name)
    )
    if policy.local_files and environment_credentials:
        errors.append(
            "upload/publish credential variables are present: "
            + ", ".join(environment_credentials)
        )
    if policy.local_files and credential_helpers:
        warnings.append(
            "Git credential helper configuration exists; credential availability is unverified"
        )

    push_receipts: list[dict[str, str]] = []
    for task in task_rows:
        delivery = task.get("delivery", {})
        if not isinstance(delivery, dict) or delivery.get("mode") != "pushed":
            continue
        row = {
            "task_id": str(task.get("task_id", "")),
            "commit": str(delivery.get("commit", "")),
            "config_relation": (
                "current" if task.get("config_sha256") == config_sha256 else "historical"
            ),
        }
        push_receipts.append(row)
        if policy.local_files and row["config_relation"] == "current":
            errors.append(f"current local_files task has a pushed delivery receipt: {row['task_id']}")
        elif policy.local_files:
            warnings.append(f"historical pushed delivery receipt exists: {row['task_id']}")

    export_report = external_exports.inspect_external_export_records(
        state_dir,
        [str(task.get("task_id", "")) for task in task_rows],
        current_time=datetime.now(timezone.utc),
    )
    errors.extend(
        f"external export receipt integrity: {item}"
        for item in export_report["errors"]
    )
    warnings.extend(
        f"external export receipt: {item}"
        for item in export_report["warnings"]
    )
    export_receipts: list[dict[str, Any]] = []
    for row in export_report["records"]:
        relation = "current" if row["config_sha256"] == config_sha256 else "historical"
        export_receipts.append(
            {
                **{key: value for key, value in row.items() if key != "destination"},
                "destination": _redacted_destination(row["destination"], root),
                "config_relation": relation,
            }
        )
        if policy.local_files and row["status"] == "issued_unconsumed":
            warnings.append(
                "unconsumed external export permit exists for task "
                f"{row['task_id']} export {row['export_id']}"
            )
        if policy.local_files and relation == "historical":
            warnings.append(
                "historical-config external export receipt exists for task "
                f"{row['task_id']} export {row['export_id']}"
            )

    return {
        "schema_version": CONFIDENTIALITY_REPORT_SCHEMA_VERSION,
        "mode": policy.mode,
        "model_context": policy.model_context,
        "guarantee": (
            "model_context_allowed_file_publication_denied"
            if policy.local_files
            else "standard_publication_policy"
        ),
        "boundary": "aoi_governed_workflows_not_system_dlp_or_air_gap",
        "git": {
            "remotes": remote_rows,
            "rewrites": rewrites,
            "lfs": {
                "tracked": lfs_tracked,
                "attribute_files": lfs_attribute_files,
                "endpoints": lfs_endpoints,
            },
        },
        "storage": {
            "root": str(state_dir),
            "local_cas_required": policy.local_cas,
            "sync_status": "unsafe" if storage_errors else (
                "uncertain" if storage_warnings else "local_not_detected_as_synced"
            ),
        },
        "remote_workflows": workflows,
        "credentials": {
            "environment_variable_names": environment_credentials,
            "git_credential_helpers": sorted(set(credential_helpers)),
            "values_exposed": False,
        },
        "receipts": {
            "push": push_receipts,
            "external_export": export_receipts,
        },
        "errors": list(dict.fromkeys(errors)),
        "warnings": list(dict.fromkeys(warnings)),
    }


__all__ = [
    "CONFIDENTIALITY_REPORT_SCHEMA_VERSION",
    "ConfidentialityError",
    "inspect_confidentiality",
    "is_publish_credential_environment_name",
    "require_local_storage_path_allowed",
    "require_publication_action_allowed",
]
