"""Selective local-files inspection and governed publication gates.

The ``local_files`` profile is intentionally narrower than DLP or an air gap.
It allows model context and normal repository publication, while exact
user-designated files/trees are restricted to their configured destination.
This module never reads credential values into its report.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any
from urllib.parse import unquote_to_bytes, urlsplit, urlunsplit

from .config import (
    MAX_PROTECTED_PATH_RULES,
    ConfidentialityConfig,
    ProtectedPathRule,
    fold_protected_path_identity,
)
from . import external_exports
from . import publication_subjects
from .git_plumbing import _run_git_bytes_bounded
from .harnesslib import HarnessError


CONFIDENTIALITY_REPORT_SCHEMA_VERSION = 2
MAX_CONFIG_ENTRIES = 8_192
MAX_REMOTE_COUNT = 256
MAX_WORKFLOW_FILES = 512
MAX_ATTRIBUTE_FILES = 256
MAX_ATTRIBUTE_FILE_BYTES = 256 * 1024
MAX_PUBLICATION_SUBJECTS = 10_000
MAX_PROTECTED_CONTENT_FILES = 10_000
MAX_PROTECTED_CONTENT_BYTES = 1024 * 1024 * 1024
MAX_GIT_PUSH_UPDATES = 128
MAX_GIT_PUSH_COMMITS = 4_096
MAX_GIT_TREE_ENTRIES = 250_000
MAX_GIT_EXPOSURES = 4_096
MAX_PROTECTED_BLOB_BYTES = 256 * 1024 * 1024
MAX_GIT_PREFLIGHT_RECEIPT_BYTES = 8 * 1024 * 1024

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
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_OID_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
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
    *,
    root: Path | None = None,
    remote: str | None = None,
    destination: str | None = None,
    subjects: Iterable[Mapping[str, str]] | None = None,
) -> None:
    """Require an exact subject/destination manifest when protection applies.

    Exact external export is deliberately not in this generic action set.  It
    must go through the separate one-shot permit path instead of this helper.
    """

    if action not in _PUBLICATION_ACTIONS:
        raise ConfidentialityError(f"unknown publication action: {action!r}")
    if not policy.selective_protection:
        return
    if root is None or destination is None or subjects is None:
        raise ConfidentialityError(
            f"confidentiality profile local_files requires an exact root, "
            f"destination, and subject manifest for {action} because protected "
            "paths are configured"
        )
    _evaluate_publication_subjects(
        root=root,
        policy=policy,
        action=action,
        remote=remote,
        destination=destination,
        subjects=subjects,
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


def canonical_publication_destination(value: str, root: Path) -> str:
    """Return a credential-free exact destination identity or fail closed."""

    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 2_048
        or any(ord(character) < 32 for character in value)
    ):
        raise ConfidentialityError("publication destination is malformed")
    kind = _destination_kind(value, root)
    if kind == "local_path":
        candidate_value = value
        try:
            parsed_local = urlsplit(value)
        except ValueError as exc:
            raise ConfidentialityError(
                "publication destination local path is malformed"
            ) from exc
        if parsed_local.scheme.casefold() == "file":
            decoded = _decode_file_uri_path(parsed_local.path)
            if decoded is None:
                raise ConfidentialityError(
                    "publication destination file path is malformed"
                )
            candidate_value = decoded
            if re.match(r"^/[A-Za-z]:/", candidate_value):
                candidate_value = candidate_value[1:]
        candidate = Path(candidate_value)
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            return "file:" + candidate.resolve(strict=False).as_posix()
        except (OSError, RuntimeError) as exc:
            raise ConfidentialityError(
                "publication destination local path could not be resolved"
            ) from exc
    if kind != "external_url":
        raise ConfidentialityError(
            "publication destination must be one confirmed local path or external URL"
        )
    if "://" not in value:
        match = re.fullmatch(
            r"(?:(?P<user>[^/@:]+)@)?(?P<host>[^/:]+):(?P<path>.+)", value
        )
        if match is None:
            raise ConfidentialityError("publication SSH destination is malformed")
        path = match.group("path").rstrip("/")
        if path.endswith(".git"):
            path = path[:-4]
        if not path or any(part in {"", ".", ".."} for part in path.split("/")):
            raise ConfidentialityError("publication SSH destination path is malformed")
        user = match.group("user")
        authority = (
            f"{user}@{match.group('host').casefold()}"
            if user
            else match.group("host").casefold()
        )
        return f"ssh://{authority}/{path}"
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
        username = parsed.username
        password = parsed.password
    except ValueError as exc:
        raise ConfidentialityError("publication URL is malformed") from exc
    scheme = parsed.scheme.casefold()
    if scheme not in {"https", "ssh", "git"} or not hostname:
        raise ConfidentialityError(
            "publication URL scheme must be https, ssh, or git"
        )
    if password is not None or (scheme == "https" and username is not None):
        raise ConfidentialityError("publication URL may not contain credentials")
    if parsed.query or parsed.fragment:
        raise ConfidentialityError(
            "publication URL may not contain a query or fragment"
        )
    path = parsed.path.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if (
        not path.startswith("/")
        or path == "/"
        or any(part in {".", ".."} for part in path.split("/") if part)
    ):
        raise ConfidentialityError("publication URL path is malformed")
    userinfo = f"{username}@" if username is not None else ""
    authority = userinfo + hostname.casefold()
    if port is not None:
        authority += f":{port}"
    return urlunsplit((scheme, authority, path, "", ""))


def _canonical_subject_path(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8", errors="strict")) > 16 * 1024
        or "\x00" in value
        or "\\" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise ConfidentialityError(f"{label} is not a canonical Git path")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(
        part in {"", ".", ".."} or part.casefold() == ".git"
        for part in path.parts
    ):
        raise ConfidentialityError(f"{label} is not a canonical Git path")
    return value


def _rule_covers_path(rule: ProtectedPathRule, path: str) -> bool:
    rule_path = fold_protected_path_identity(rule.path)
    candidate = fold_protected_path_identity(path)
    return candidate == rule_path or (
        rule.kind == "tree" and candidate.startswith(rule_path + "/")
    )


def _path_is_link_or_reparse(path: Path) -> bool:
    try:
        is_junction = getattr(path, "is_junction", None)
        return bool(
            path.is_symlink()
            or (is_junction is not None and is_junction())
            or _path_has_windows_reparse_attribute(path)
        )
    except OSError as exc:
        raise ConfidentialityError(
            f"protected path link identity could not be inspected: {path}"
        ) from exc


def _require_no_link_traversal(root: Path, path: Path, *, label: str) -> None:
    root = root.resolve(strict=True)
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ConfidentialityError(f"{label} escapes the project root") from exc
    current = root
    if _path_is_link_or_reparse(current):
        raise ConfidentialityError(f"{label} project root is linked/reparsed")
    for component in relative.parts:
        current = current / component
        if _path_is_link_or_reparse(current):
            raise ConfidentialityError(f"{label} traverses a link/reparse point")


def _protected_tree_files(root: Path, tree: Path) -> list[Path]:
    _require_no_link_traversal(root, tree, label="protected tree")
    if not tree.is_dir():
        raise ConfidentialityError(
            f"protected tree is missing or not a directory: {tree.relative_to(root)}"
        )
    result: list[Path] = []
    pending = [tree]
    observed_entries = 0
    while pending:
        directory = pending.pop()
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            raise ConfidentialityError(
                f"protected tree could not be enumerated: {directory}"
            ) from exc
        folded_children: dict[str, str] = {}
        for child in children:
            observed_entries += 1
            if observed_entries > MAX_PROTECTED_CONTENT_FILES:
                raise ConfidentialityError(
                    "protected content exceeds the configured entry-count bound"
                )
            folded_name = fold_protected_path_identity(child.name)
            previous_name = folded_children.setdefault(folded_name, child.name)
            if previous_name != child.name:
                raise ConfidentialityError(
                    "protected tree has an ambiguous case-fold identity: "
                    f"{child.relative_to(root)}"
                )
            if _path_is_link_or_reparse(child):
                raise ConfidentialityError(
                    f"protected tree contains a link/reparse point: {child}"
                )
            if child.is_dir():
                pending.append(child)
            elif child.is_file():
                result.append(child)
            else:
                raise ConfidentialityError(
                    f"protected tree contains an unsupported entry: {child}"
                )
    return sorted(result, key=lambda item: item.as_posix())


def _resolve_protected_path_casefold(root: Path, configured_path: str) -> Path:
    """Resolve one policy path with the same case-folded identity used by gates.

    Git exposure matching is deliberately case-insensitive on every platform.
    The current-byte lookup must therefore find a differently-cased filesystem
    spelling on case-sensitive hosts too.  Multiple spellings of one folded
    component are ambiguous and fail closed instead of selecting one.
    """

    root = root.resolve(strict=True)
    current = root
    observed_entries = 0
    for component in PurePosixPath(configured_path).parts:
        if _path_is_link_or_reparse(current):
            raise ConfidentialityError(
                "protected path case-fold lookup traverses a link/reparse point"
            )
        if not current.is_dir():
            raise ConfidentialityError(
                f"protected path is missing before publication: {configured_path}; "
                "restore it or explicitly revise the protected-path policy"
            )
        matches: list[str] = []
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    observed_entries += 1
                    if observed_entries > MAX_PROTECTED_CONTENT_FILES:
                        raise ConfidentialityError(
                            "protected path case-fold lookup exceeds the configured "
                            "entry-count bound"
                        )
                    if fold_protected_path_identity(
                        entry.name
                    ) == fold_protected_path_identity(component):
                        matches.append(entry.name)
                        if len(matches) > 1:
                            raise ConfidentialityError(
                                "protected path has an ambiguous case-fold identity: "
                                f"{configured_path}"
                            )
        except OSError as exc:
            raise ConfidentialityError(
                f"protected path could not be enumerated: {configured_path}"
            ) from exc
        if not matches:
            raise ConfidentialityError(
                f"protected path is missing before publication: {configured_path}; "
                "restore it or explicitly revise the protected-path policy"
            )
        current = current / matches[0]
    return current


def _require_unambiguous_casefold_git_paths(
    paths: Iterable[str],
    *,
    rule: ProtectedPathRule,
    label: str,
) -> list[str]:
    """Validate actual Git path spellings returned for one protected rule."""

    validated: list[str] = []
    spellings: dict[tuple[str, ...], tuple[str, ...]] = {}
    for raw_path in paths:
        path = _canonical_subject_path(raw_path, label)
        if not _rule_covers_path(rule, path):
            raise ConfidentialityError(
                f"{label} returned a path outside the protected rule"
            )
        parts = PurePosixPath(path).parts
        for length in range(1, len(parts) + 1):
            exact_prefix = parts[:length]
            folded_prefix = tuple(
                fold_protected_path_identity(part) for part in exact_prefix
            )
            previous = spellings.setdefault(folded_prefix, exact_prefix)
            if previous != exact_prefix:
                raise ConfidentialityError(
                    f"{label} has an ambiguous case-fold identity for "
                    f"protected path {rule.path!r}"
                )
        validated.append(path)
    return validated


def _stable_regular_file_hashes(
    path: Path, *, git_blob: bool
) -> tuple[dict[str, str], int]:
    """Hash one opened regular-file identity and reject pathname replacement."""

    if _path_is_link_or_reparse(path):
        raise ConfidentialityError(f"protected path may not be linked: {path}")
    try:
        before = path.lstat()
    except OSError as exc:
        raise ConfidentialityError(f"protected file is unavailable: {path}") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ConfidentialityError(f"protected file is not regular: {path}")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    hashers: dict[str, Any] = {"sha256": hashlib.sha256()}
    if git_blob:
        hashers["sha1"] = hashlib.sha1(usedforsecurity=False)
    observed = 0
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise ConfidentialityError(
                    f"protected file identity changed while opening: {path}"
                )
            if git_blob:
                header = f"blob {opened.st_size}\0".encode("ascii")
                for hasher in hashers.values():
                    hasher.update(header)
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                observed += len(chunk)
                for hasher in hashers.values():
                    hasher.update(chunk)
            after_open = os.fstat(stream.fileno())
    except ConfidentialityError:
        raise
    except OSError as exc:
        raise ConfidentialityError(f"protected file could not be read: {path}") from exc
    try:
        after_path = path.lstat()
    except OSError as exc:
        raise ConfidentialityError(f"protected file changed while hashing: {path}") from exc
    if (
        _path_is_link_or_reparse(path)
        or not stat.S_ISREG(after_path.st_mode)
        or observed != opened.st_size
        or opened.st_nlink != 1
        or after_open.st_nlink != 1
        or after_path.st_nlink != 1
        or (opened.st_dev, opened.st_ino)
        != (after_open.st_dev, after_open.st_ino)
        or (opened.st_dev, opened.st_ino)
        != (after_path.st_dev, after_path.st_ino)
        or opened.st_size != after_open.st_size
        or opened.st_size != after_path.st_size
        or opened.st_mtime_ns != after_open.st_mtime_ns
        or opened.st_mtime_ns != after_path.st_mtime_ns
    ):
        raise ConfidentialityError(f"protected file changed while hashing: {path}")
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}, observed


def _sha256_regular_file(path: Path) -> tuple[str, int]:
    hashes, observed = _stable_regular_file_hashes(path, git_blob=False)
    return hashes["sha256"], observed


def _git_blob_oids_regular_file(path: Path) -> tuple[frozenset[str], int]:
    """Return exact SHA-1/SHA-256 Git blob identities for one stable file."""

    hashes, observed = _stable_regular_file_hashes(path, git_blob=True)
    return frozenset({hashes["sha1"], hashes["sha256"]}), observed


def _protected_content_identities(
    root: Path, policy: ConfidentialityConfig
) -> dict[str, list[ProtectedPathRule]]:
    root = root.resolve(strict=True)
    identities: dict[str, list[ProtectedPathRule]] = {}
    file_count = 0
    total_bytes = 0
    for rule in policy.protected:
        candidate = _resolve_protected_path_casefold(root, rule.path)
        if not _path_within(candidate.resolve(strict=False), root):
            raise ConfidentialityError("protected path escapes the project root")
        if rule.kind == "file":
            _require_no_link_traversal(root, candidate, label="protected file")
            paths = [candidate]
        else:
            paths = _protected_tree_files(root, candidate)
        for path in paths:
            file_count += 1
            if file_count > MAX_PROTECTED_CONTENT_FILES:
                raise ConfidentialityError(
                    "protected content exceeds the configured file-count bound"
                )
            digest, size = _sha256_regular_file(path)
            total_bytes += size
            if total_bytes > MAX_PROTECTED_CONTENT_BYTES:
                raise ConfidentialityError(
                    "protected content exceeds the configured byte bound"
                )
            identities.setdefault(digest, []).append(rule)
    return identities


def _protected_current_git_blob_identities(
    root: Path, policy: ConfidentialityConfig
) -> dict[str, set[ProtectedPathRule]]:
    """Bind current protected bytes even when their configured path is untracked."""

    root = root.resolve(strict=True)
    identities: dict[str, set[ProtectedPathRule]] = {}
    file_count = 0
    total_bytes = 0
    for rule in policy.protected:
        candidate = _resolve_protected_path_casefold(root, rule.path)
        if not _path_within(candidate.resolve(strict=False), root):
            raise ConfidentialityError("protected path escapes the project root")
        if rule.kind == "file":
            _require_no_link_traversal(root, candidate, label="protected file")
            paths = [candidate]
        else:
            paths = _protected_tree_files(root, candidate)
        for path in paths:
            file_count += 1
            if file_count > MAX_PROTECTED_CONTENT_FILES:
                raise ConfidentialityError(
                    "protected content exceeds the configured file-count bound"
                )
            blob_oids, size = _git_blob_oids_regular_file(path)
            total_bytes += size
            if total_bytes > MAX_PROTECTED_CONTENT_BYTES:
                raise ConfidentialityError(
                    "protected content exceeds the configured byte bound"
                )
            for oid in blob_oids:
                identities.setdefault(oid, set()).add(rule)
    return identities


def _rule_destination_allowed(
    *,
    rule: ProtectedPathRule,
    root: Path,
    action: str,
    remote: str | None,
    destination: str,
) -> bool:
    kind = _destination_kind(destination, root)
    if rule.policy == "local_only":
        return kind == "local_path"
    # ``home_remote_only`` is a Git-history policy.  It is authorized only by
    # the exact outgoing-commit preflight, where AOI can bind the source/ref,
    # destination, protected Git objects, and current-policy receipt.  A
    # caller-supplied remote alias must never turn it into generic artifact or
    # package publication authority.
    if action != "git_push":
        return False
    if remote != rule.home_remote or rule.home_destination is None:
        return False
    return canonical_publication_destination(
        destination, root
    ) == canonical_publication_destination(rule.home_destination, root)


def _evaluate_publication_subjects(
    *,
    root: Path,
    policy: ConfidentialityConfig,
    action: str,
    remote: str | None,
    destination: str,
    subjects: Iterable[Mapping[str, str]],
) -> list[dict[str, str]]:
    root = root.resolve(strict=True)
    canonical_publication_destination(destination, root)
    rows = list(subjects)
    if not rows or len(rows) > MAX_PUBLICATION_SUBJECTS:
        raise ConfidentialityError(
            f"{action} subject manifest must contain 1-{MAX_PUBLICATION_SUBJECTS} rows"
        )
    protected_identities = _protected_content_identities(root, policy)
    matched: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, subject in enumerate(rows):
        if not isinstance(subject, Mapping) or set(subject) != {"path", "sha256"}:
            raise ConfidentialityError(
                f"{action} subject {index} must contain exact path and sha256 keys"
            )
        path = _canonical_subject_path(subject["path"], f"{action} subject path")
        digest = subject["sha256"]
        if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
            raise ConfidentialityError(f"{action} subject SHA-256 is invalid")
        identity = (path, digest)
        if identity in seen:
            raise ConfidentialityError(f"{action} subject manifest has a duplicate row")
        seen.add(identity)
        rules = {
            rule
            for rule in policy.protected
            if _rule_covers_path(rule, path)
        }
        rules.update(protected_identities.get(digest, ()))
        for rule in sorted(rules, key=lambda item: item.path):
            if not _rule_destination_allowed(
                rule=rule,
                root=root,
                action=action,
                remote=remote,
                destination=destination,
            ):
                raise ConfidentialityError(
                    f"{action} would publish protected {rule.kind} {rule.path!r} "
                    "to a destination outside its configured policy"
                )
            matched.append(
                {
                    "subject_path": path,
                    "subject_sha256": digest,
                    "rule_path": rule.path,
                    "rule_policy": rule.policy,
                }
            )
    return matched


def preflight_publication_paths(
    *,
    root: Path,
    policy: ConfidentialityConfig,
    config_sha256: str,
    action: str,
    destination: str,
    subject_paths: Iterable[Path | str],
    remote: str | None = None,
) -> dict[str, Any]:
    """Inventory exact files/archive members and apply selective publication policy."""

    root = root.resolve(strict=True)
    if action not in _PUBLICATION_ACTIONS or action == "git_push":
        raise ConfidentialityError("publication preflight action is invalid")
    if remote is not None and (
        not isinstance(remote, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", remote)
    ):
        raise ConfidentialityError("publication preflight remote is invalid")
    try:
        inventory = publication_subjects.inventory_publication_subjects(
            root, subject_paths
        )
    except publication_subjects.PublicationSubjectError as exc:
        raise ConfidentialityError(str(exc)) from exc
    canonical_destination = canonical_publication_destination(destination, root)
    exposures = _evaluate_publication_subjects(
        root=root,
        policy=policy,
        action=action,
        remote=remote,
        destination=canonical_destination,
        subjects=inventory["subjects"],
    )
    binding = confidentiality_policy_binding(policy, config_sha256)
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "action": action,
        "mode": policy.mode,
        "config_sha256": config_sha256,
        "boundary": "aoi_cooperative_exact_path_content_not_system_dlp",
        "remote": remote or "",
        "destination": canonical_destination,
        "containers": inventory["containers"],
        "subject_count": len(inventory["subjects"]),
        "subject_manifest_sha256": inventory["manifest_sha256"],
        "protected_policy_sha256": binding["protected_policy_sha256"],
        "protected_rule_count": binding["protected_rule_count"],
        "protected_exposures": exposures,
        "decision": "allowed",
    }
    receipt["receipt_sha256"] = hashlib.sha256(
        json.dumps(
            receipt,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return receipt


def _git_confidentiality_bytes(
    root: Path,
    arguments: Iterable[str],
    *,
    label: str,
    stdout_limit: int | None = None,
) -> bytes:
    try:
        return _run_git_bytes_bounded(
            root,
            arguments,
            label=label,
            stdout_limit=stdout_limit,
        )
    except HarnessError as exc:
        raise ConfidentialityError(str(exc)) from exc


def _git_preflight_lines(
    root: Path, arguments: Iterable[str], *, label: str
) -> list[str]:
    return _decode_lines(
        _git_confidentiality_bytes(root, arguments, label=label), label
    )


def effective_git_push_destination(root: Path, remote: str) -> str:
    """Resolve one remote's exact effective push destination."""

    root = root.resolve(strict=True)
    if (
        not isinstance(remote, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", remote)
    ):
        raise ConfidentialityError("Git push remote name is invalid")
    effective_urls = _git_preflight_lines(
        root,
        ("remote", "get-url", "--push", "--all", remote),
        label="Git push effective destination inspection",
    )
    if len(effective_urls) != 1:
        raise ConfidentialityError(
            "Git push remote must resolve to one exact push destination"
        )
    return canonical_publication_destination(effective_urls[0], root)


def _require_git_oid(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ConfidentialityError(f"{label} is invalid")
    lowered = value.casefold()
    if _GIT_OID_RE.fullmatch(lowered) is None:
        raise ConfidentialityError(f"{label} is invalid")
    return lowered


def _require_git_ref(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("refs/")
        or len(value) > 1_024
        or value.endswith(("/", "."))
        or any(character.isspace() or ord(character) < 32 for character in value)
        or any(token in value for token in ("..", "@{", "\\", "~", "^", ":", "?", "*", "["))
    ):
        raise ConfidentialityError(f"{label} is invalid")
    return value


def _parse_git_push_updates(
    updates: Iterable[Iterable[str]],
) -> list[dict[str, str]]:
    rows = list(updates)
    if not rows or len(rows) > MAX_GIT_PUSH_UPDATES:
        raise ConfidentialityError(
            f"Git push preflight requires 1-{MAX_GIT_PUSH_UPDATES} updates"
        )
    result: list[dict[str, str]] = []
    remote_refs: set[str] = set()
    for index, raw in enumerate(rows):
        values = list(raw)
        if len(values) != 4:
            raise ConfidentialityError(
                f"Git push update {index} must contain four exact fields"
            )
        local_ref = _require_git_ref(values[0], f"Git push update {index} local ref")
        local_sha = _require_git_oid(
            values[1], f"Git push update {index} local object"
        )
        remote_ref = _require_git_ref(
            values[2], f"Git push update {index} remote ref"
        )
        remote_sha = _require_git_oid(
            values[3], f"Git push update {index} remote object"
        )
        if len(local_sha) != len(remote_sha):
            raise ConfidentialityError("Git push update object formats differ")
        if remote_ref in remote_refs:
            raise ConfidentialityError("Git push preflight has a duplicate remote ref")
        remote_refs.add(remote_ref)
        result.append(
            {
                "local_ref": local_ref,
                "local_sha": local_sha,
                "remote_ref": remote_ref,
                "remote_sha": remote_sha,
            }
        )
    return result


def _pre_push_remote_ref_oid(
    root: Path,
    *,
    remote: str,
    remote_ref: str,
    oid_length: int,
) -> str:
    """Observe one exact remote ref before push without accepting caller scope."""

    raw = _git_confidentiality_bytes(
        root,
        ("ls-remote", "--refs", remote, remote_ref),
        label="Git push remote pre-state inspection",
        stdout_limit=4 * 1024,
    )
    lines = _decode_lines(raw, "Git push remote pre-state inspection")
    if not lines:
        return "0" * oid_length
    if len(lines) != 1:
        raise ConfidentialityError(
            "Git push remote pre-state inspection returned an ambiguous ref"
        )
    try:
        raw_oid, observed_ref = lines[0].split("\t", 1)
    except ValueError as exc:
        raise ConfidentialityError(
            "Git push remote pre-state inspection is malformed"
        ) from exc
    observed_oid = _require_git_oid(
        raw_oid, "Git push remote pre-state object"
    )
    if observed_ref != remote_ref or len(observed_oid) != oid_length:
        raise ConfidentialityError(
            "Git push remote pre-state inspection correlation failed"
        )
    return observed_oid


def _revision_commits(
    root: Path,
    arguments: Iterable[str],
    *,
    label: str,
) -> list[str]:
    lines = _git_preflight_lines(root, arguments, label=label)
    if len(lines) > MAX_GIT_PUSH_COMMITS:
        raise ConfidentialityError(
            "Git push commit set exceeds the configured bound"
        )
    result: list[str] = []
    for item in lines:
        oid = _require_git_oid(item, f"{label} commit")
        if oid in result:
            raise ConfidentialityError(f"{label} contains a duplicate commit")
        result.append(oid)
    return result


def _git_tree_entries(
    root: Path,
    commit: str,
) -> list[dict[str, str]]:
    arguments = ["ls-tree", "-r", "-z", "--full-tree", commit]
    # Unlike rev-list and ls-files, ls-tree rejects the icase pathspec magic.
    # Read its bounded full tree and apply AOI's case-folded rule correlation to
    # the strict actual paths below instead of silently falling back to exact case.
    raw = _git_confidentiality_bytes(
        root,
        arguments,
        label="Git push tree inspection",
        stdout_limit=64 * 1024 * 1024,
    )
    if raw and not raw.endswith(b"\x00"):
        raise ConfidentialityError("Git push tree output is not NUL terminated")
    records = raw[:-1].split(b"\x00") if raw else []
    if len(records) > MAX_GIT_TREE_ENTRIES:
        raise ConfidentialityError("Git push tree exceeds the configured entry bound")
    entries: list[dict[str, str]] = []
    for record in records:
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, object_type, raw_oid = header.split(b" ", 2)
            decoded_path = raw_path.decode("utf-8", errors="strict")
            decoded_mode = mode.decode("ascii", errors="strict")
            decoded_type = object_type.decode("ascii", errors="strict")
            decoded_oid = raw_oid.decode("ascii", errors="strict")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ConfidentialityError("Git push tree record is malformed") from exc
        if re.fullmatch(r"[0-7]{6}", decoded_mode) is None:
            raise ConfidentialityError("Git push tree mode is malformed")
        if decoded_type not in {"blob", "commit"}:
            raise ConfidentialityError("Git push tree object type is unsupported")
        oid = _require_git_oid(decoded_oid, "Git push tree object")
        entries.append(
            {
                "mode": decoded_mode,
                "type": decoded_type,
                "oid": oid,
                "path": _canonical_subject_path(
                    decoded_path, "Git push tree path"
                ),
            }
        )
    return entries


def _git_tree_entries_for_rule(
    entries: Iterable[dict[str, str]],
    *,
    rule: ProtectedPathRule,
    label: str,
) -> list[dict[str, str]]:
    filtered = [
        entry for entry in entries if _rule_covers_path(rule, entry["path"])
    ]
    _require_unambiguous_casefold_git_paths(
        (entry["path"] for entry in filtered),
        rule=rule,
        label=label,
    )
    return filtered


def _git_blob_sha256(root: Path, oid: str) -> tuple[str, int]:
    size_lines = _git_preflight_lines(
        root, ("cat-file", "-s", oid), label="protected Git blob size"
    )
    if len(size_lines) != 1 or re.fullmatch(r"[0-9]+", size_lines[0]) is None:
        raise ConfidentialityError("protected Git blob size is malformed")
    size = int(size_lines[0])
    if size > MAX_PROTECTED_BLOB_BYTES:
        raise ConfidentialityError(
            "protected Git blob exceeds the configured byte bound"
        )
    raw = _git_confidentiality_bytes(
        root,
        ("cat-file", "blob", oid),
        label="protected Git blob read",
        stdout_limit=size,
    )
    if len(raw) != size:
        raise ConfidentialityError("protected Git blob size changed while reading")
    return hashlib.sha256(raw).hexdigest(), size


def _git_path_uses_lfs(root: Path, commit: str, path: str) -> bool:
    raw = _git_confidentiality_bytes(
        root,
        ("check-attr", f"--source={commit}", "-z", "filter", "--", path),
        label="protected Git LFS attribute inspection",
    )
    fields = raw.split(b"\x00")
    if len(fields) != 4 or fields[-1] != b"":
        raise ConfidentialityError("protected Git LFS attribute output is malformed")
    try:
        observed_path, attribute, value = (
            item.decode("utf-8", errors="strict") for item in fields[:3]
        )
    except UnicodeDecodeError as exc:
        raise ConfidentialityError(
            "protected Git LFS attribute output is not strict UTF-8"
        ) from exc
    if observed_path != path or attribute != "filter":
        raise ConfidentialityError("protected Git LFS attribute correlation failed")
    return value == "lfs"


def _policy_receipt_payload(policy: ConfidentialityConfig) -> list[dict[str, Any]]:
    return [
        {
            "path": rule.path,
            "kind": rule.kind,
            "policy": rule.policy,
            "home_remote": rule.home_remote,
            "home_destination": rule.home_destination,
        }
        for rule in policy.protected
    ]


def confidentiality_policy_binding(
    policy: ConfidentialityConfig, config_sha256: str
) -> dict[str, Any]:
    """Return the immutable policy identity captured by a publication record."""

    if not isinstance(config_sha256, str) or _SHA256_RE.fullmatch(config_sha256) is None:
        raise ConfidentialityError("confidentiality policy config SHA-256 is invalid")
    policy_sha256 = hashlib.sha256(
        json.dumps(
            _policy_receipt_payload(policy),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()
    base: dict[str, Any] = {
        "schema_version": 1,
        "mode": policy.mode,
        "config_sha256": config_sha256,
        "protected_rule_count": len(policy.protected),
        "protected_policy_sha256": policy_sha256,
    }
    return {
        **base,
        "binding_sha256": hashlib.sha256(
            json.dumps(
                base,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
        ).hexdigest(),
    }


def validate_confidentiality_policy_binding(
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one persisted delivery-time confidentiality policy identity."""

    expected_keys = {
        "schema_version",
        "mode",
        "config_sha256",
        "protected_rule_count",
        "protected_policy_sha256",
        "binding_sha256",
    }
    if not isinstance(binding, Mapping) or set(binding) != expected_keys:
        raise ConfidentialityError("confidentiality policy binding schema is invalid")
    mode = binding.get("mode")
    rule_count = binding.get("protected_rule_count")
    if (
        type(binding.get("schema_version")) is not int
        or binding.get("schema_version") != 1
        or not isinstance(mode, str)
        or mode not in {"standard", "local_files"}
        or not isinstance(binding.get("config_sha256"), str)
        or _SHA256_RE.fullmatch(str(binding.get("config_sha256"))) is None
        or type(rule_count) is not int
        or rule_count < 0
        or rule_count > MAX_PROTECTED_PATH_RULES
        or not isinstance(binding.get("protected_policy_sha256"), str)
        or _SHA256_RE.fullmatch(str(binding.get("protected_policy_sha256"))) is None
        or not isinstance(binding.get("binding_sha256"), str)
        or _SHA256_RE.fullmatch(str(binding.get("binding_sha256"))) is None
        or (mode == "standard" and rule_count != 0)
    ):
        raise ConfidentialityError("confidentiality policy binding identity is invalid")
    base = {key: binding[key] for key in expected_keys - {"binding_sha256"}}
    expected = hashlib.sha256(
        json.dumps(
            base,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()
    if binding["binding_sha256"] != expected:
        raise ConfidentialityError("confidentiality policy binding digest is invalid")
    return dict(binding)


def preflight_git_push(
    *,
    root: Path,
    policy: ConfidentialityConfig,
    config_sha256: str,
    remote: str,
    destination: str,
    updates: Iterable[Iterable[str]],
    _verify_remote_state: bool = True,
) -> dict[str, Any]:
    """Evaluate the exact outgoing commit set before an AOI-managed push.

    The caller must execute the real push separately and immediately.  This
    cooperative preflight does not claim to intercept an ungoverned shell.
    """

    root = root.resolve(strict=True)
    if not isinstance(config_sha256, str) or _SHA256_RE.fullmatch(config_sha256) is None:
        raise ConfidentialityError("Git push preflight config SHA-256 is invalid")
    canonical_destination = canonical_publication_destination(destination, root)
    if effective_git_push_destination(root, remote) != canonical_destination:
        raise ConfidentialityError(
            "Git push supplied destination differs from the effective remote destination"
        )
    parsed_updates = _parse_git_push_updates(updates)
    for row in parsed_updates:
        for field in ("local_ref", "remote_ref"):
            _git_confidentiality_bytes(
                root,
                ("check-ref-format", row[field]),
                label="Git push ref validation",
            )
    outgoing: set[str] = set()
    required_outgoing: list[tuple[str, str, str, set[str]]] = []
    live_local_shas: list[str] = []
    for row in parsed_updates:
        local_sha = row["local_sha"]
        remote_sha = row["remote_sha"]
        zero = "0" * len(local_sha)
        local_is_tag = row["local_ref"].startswith("refs/tags/")
        remote_is_tag = row["remote_ref"].startswith("refs/tags/")
        if local_is_tag != remote_is_tag:
            raise ConfidentialityError(
                "Git push tag update must bind matching local and remote tag refs"
            )
        if local_sha == zero:
            if remote_is_tag:
                raise ConfidentialityError("Git push tag deletion is denied")
            continue
        if remote_is_tag and remote_sha != zero:
            raise ConfidentialityError("Git push tag updates after creation are denied")
        local_ref_lines = _git_preflight_lines(
            root,
            ("rev-parse", "--verify", row["local_ref"]),
            label="Git push local ref inspection",
        )
        if (
            len(local_ref_lines) != 1
            or _require_git_oid(
                local_ref_lines[0], "Git push local ref object"
            )
            != local_sha
        ):
            raise ConfidentialityError(
                f"Git push local ref {row['local_ref']} differs from its supplied object"
            )
        live_local_shas.append(local_sha)
        local_commit_lines = _git_preflight_lines(
            root,
            ("rev-parse", "--verify", f"{local_sha}^{{commit}}"),
            label="Git push local commit inspection",
        )
        if len(local_commit_lines) != 1:
            raise ConfidentialityError("Git push local ref does not peel to one commit")
        local_commit = _require_git_oid(
            local_commit_lines[0], "Git push local commit"
        )
        arguments = ["rev-list", local_commit]
        if remote_sha != zero:
            remote_commit_lines = _git_preflight_lines(
                root,
                ("rev-parse", "--verify", f"{remote_sha}^{{commit}}"),
                label="Git push remote commit inspection",
            )
            if len(remote_commit_lines) != 1:
                raise ConfidentialityError(
                    "Git push remote ref does not peel to one commit"
                )
            remote_commit = _require_git_oid(
                remote_commit_lines[0], "Git push remote commit"
            )
            arguments.extend(("--not", remote_commit))
        row_outgoing = set(
            _revision_commits(
                root, arguments, label="Git push outgoing commit inspection"
            )
        )
        required_outgoing.append(
            (row["remote_ref"], local_sha, local_commit, row_outgoing)
        )
        outgoing.update(row_outgoing)
        if len(outgoing) > MAX_GIT_PUSH_COMMITS:
            raise ConfidentialityError(
                "Git push combined commit set exceeds the configured bound"
            )

    rewrites = [
        key
        for key, _value in _git_config(root)
        if key.startswith("url.")
        and key.endswith((".pushinsteadof", ".insteadof"))
    ]
    tree_cache: dict[str, list[dict[str, str]]] = {}
    aggregate_tree_entries = 0

    def load_tree(commit: str) -> list[dict[str, str]]:
        nonlocal aggregate_tree_entries
        if commit not in tree_cache:
            entries = _git_tree_entries(root, commit)
            aggregate_tree_entries += len(entries)
            if aggregate_tree_entries > MAX_GIT_TREE_ENTRIES:
                raise ConfidentialityError(
                    "Git push aggregate tree inspection exceeds the configured bound"
                )
            tree_cache[commit] = entries
        return tree_cache[commit]

    sensitive_rules_by_oid = _protected_current_git_blob_identities(root, policy)
    history_tree_scans = 0
    for rule in policy.protected:
        history_commits: set[str] = set()
        for local_sha in live_local_shas:
            history_commits.update(
                _revision_commits(
                    root,
                    (
                        "rev-list",
                        f"--max-count={MAX_GIT_PUSH_COMMITS + 1}",
                        local_sha,
                        "--",
                        f":(icase,literal){rule.path}",
                    ),
                    label="protected Git history inspection",
                )
            )
        for commit in sorted(history_commits):
            history_tree_scans += 1
            if history_tree_scans > MAX_GIT_PUSH_COMMITS * 2:
                raise ConfidentialityError(
                    "protected Git history exceeds the configured scan bound"
                )
            for entry in _git_tree_entries_for_rule(
                load_tree(commit),
                rule=rule,
                label="protected Git tree inspection",
            ):
                if entry["type"] == "blob" and _rule_covers_path(
                    rule, entry["path"]
                ):
                    sensitive_rules_by_oid.setdefault(entry["oid"], set()).add(rule)

    exposures: list[dict[str, Any]] = []
    seen_exposures: set[tuple[str, str, str, str]] = set()
    blob_digests: dict[str, tuple[str, int]] = {}
    for commit in sorted(outgoing) if policy.protected else ():
        entries = load_tree(commit)
        for rule in policy.protected:
            _git_tree_entries_for_rule(
                entries,
                rule=rule,
                label="outgoing protected Git tree inspection",
            )
        for entry in entries:
            rules = {
                rule
                for rule in policy.protected
                if _rule_covers_path(rule, entry["path"])
            }
            rules.update(sensitive_rules_by_oid.get(entry["oid"], ()))
            for rule in sorted(rules, key=lambda item: item.path):
                identity = (commit, entry["path"], entry["oid"], rule.path)
                if identity in seen_exposures:
                    continue
                seen_exposures.add(identity)
                if len(exposures) >= MAX_GIT_EXPOSURES:
                    raise ConfidentialityError(
                        "Git push protected exposure set exceeds the configured bound"
                    )
                if entry["type"] != "blob" or entry["mode"] == "120000":
                    raise ConfidentialityError(
                        f"protected Git path {entry['path']!r} is a link or submodule"
                    )
                if _git_path_uses_lfs(root, commit, entry["path"]):
                    raise ConfidentialityError(
                        f"protected Git path {entry['path']!r} uses an ambiguous LFS upload route"
                    )
                if entry["oid"] not in blob_digests:
                    blob_digests[entry["oid"]] = _git_blob_sha256(root, entry["oid"])
                content_sha256, size_bytes = blob_digests[entry["oid"]]
                exposures.append(
                    {
                        "commit": commit,
                        "path": entry["path"],
                        "git_oid": entry["oid"],
                        "content_sha256": content_sha256,
                        "size_bytes": size_bytes,
                        "rule_path": rule.path,
                        "rule_kind": rule.kind,
                        "rule_policy": rule.policy,
                    }
                )

    if exposures and rewrites:
        raise ConfidentialityError(
            "Git push of protected content is denied while insteadOf/pushInsteadOf rewrites exist"
        )
    rules_by_path = {rule.path: rule for rule in policy.protected}
    for exposure in exposures:
        rule = rules_by_path[exposure["rule_path"]]
        if not _rule_destination_allowed(
            rule=rule,
            root=root,
            action="git_push",
            remote=remote,
            destination=destination,
        ):
            raise ConfidentialityError(
                f"Git push would send protected {rule.kind} {rule.path!r} "
                "to a repository outside its configured policy"
            )

    if _verify_remote_state:
        for row in parsed_updates:
            observed_remote_sha = _pre_push_remote_ref_oid(
                root,
                remote=remote,
                remote_ref=row["remote_ref"],
                oid_length=len(row["remote_sha"]),
            )
            if observed_remote_sha != row["remote_sha"]:
                raise ConfidentialityError(
                    f"Git push supplied remote object for {row['remote_ref']} "
                    "differs from the exact pre-push remote state"
                )
    for remote_ref, local_sha, local_commit, row_outgoing in required_outgoing:
        if local_commit not in row_outgoing:
            raise ConfidentialityError(
                f"Git push update for {remote_ref} does not prove its delivered "
                f"commit was outgoing (bound local object {local_sha})"
            )

    policy_rows = _policy_receipt_payload(policy)
    policy_sha256 = hashlib.sha256(
        json.dumps(
            policy_rows,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "action": "git_push_preflight",
        "mode": policy.mode,
        "config_sha256": config_sha256,
        "boundary": "aoi_cooperative_preflight_not_system_dlp",
        "remote": remote,
        "destination": canonical_destination,
        "updates": parsed_updates,
        "outgoing_commits": sorted(outgoing),
        "protected_policy_sha256": policy_sha256,
        "protected_rule_count": len(policy.protected),
        "protected_exposures": exposures,
        "rewrite_keys": sorted(rewrites),
        "decision": "allowed",
    }
    receipt["receipt_sha256"] = hashlib.sha256(
        json.dumps(
            receipt,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    return receipt


def parse_git_push_preflight_receipt_bytes(raw: bytes) -> dict[str, Any]:
    """Parse bounded receipt bytes without duplicate keys or non-finite numbers."""

    if (
        not isinstance(raw, bytes)
        or not raw
        or len(raw) > MAX_GIT_PREFLIGHT_RECEIPT_BYTES
    ):
        raise ConfidentialityError("Git push preflight receipt exceeds its byte bound")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ConfidentialityError(
                    f"Git push preflight receipt has duplicate key {key!r}"
                )
            result[key] = value
        return result

    def no_nonfinite(value: str) -> Any:
        raise ConfidentialityError(
            f"Git push preflight receipt contains non-finite number {value!r}"
        )

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=no_duplicates,
            parse_constant=no_nonfinite,
        )
    except ConfidentialityError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfidentialityError("Git push preflight receipt is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ConfidentialityError("Git push preflight receipt must be a JSON object")
    return value


def canonical_git_push_preflight_receipt_bytes(
    receipt: Mapping[str, Any],
) -> bytes:
    """Encode one validated receipt as bounded canonical evidence bytes."""

    try:
        raw = json.dumps(
            dict(receipt),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ConfidentialityError(
            "Git push preflight receipt cannot be encoded canonically"
        ) from exc
    if not raw or len(raw) > MAX_GIT_PREFLIGHT_RECEIPT_BYTES:
        raise ConfidentialityError("Git push preflight receipt exceeds its byte bound")
    return raw


def load_git_push_preflight_receipt(path: Path) -> dict[str, Any]:
    """Read one bounded single-link JSON receipt without accepting duplicate keys."""

    path = path.expanduser().absolute()
    try:
        resolved = path.resolve(strict=True)
        if resolved != path:
            raise ConfidentialityError(
                "Git push preflight receipt path traverses a link/reparse point"
            )
        before = path.lstat()
        if _path_is_link_or_reparse(path) or not path.is_file() or before.st_nlink != 1:
            raise ConfidentialityError(
                "Git push preflight receipt must be one regular non-linked file"
            )
        if before.st_size <= 0 or before.st_size > MAX_GIT_PREFLIGHT_RECEIPT_BYTES:
            raise ConfidentialityError(
                "Git push preflight receipt exceeds its byte bound"
            )
        raw = path.read_bytes()
        after = path.lstat()
    except ConfidentialityError:
        raise
    except OSError as exc:
        raise ConfidentialityError(
            f"Git push preflight receipt could not be read: {exc}"
        ) from exc
    if (
        len(raw) != before.st_size
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ino != after.st_ino
        or after.st_nlink != 1
    ):
        raise ConfidentialityError(
            "Git push preflight receipt changed while being read"
        )
    return parse_git_push_preflight_receipt_bytes(raw)


def validate_git_push_preflight_receipt_binding(
    receipt: Mapping[str, Any],
    *,
    root: Path,
    binding: Mapping[str, Any],
    remote: str,
    destination: str,
    commit: str,
    remote_ref: str,
) -> str:
    """Validate durable receipt bytes against a persisted policy binding."""

    validated_binding = validate_confidentiality_policy_binding(binding)

    expected_keys = {
        "schema_version",
        "action",
        "mode",
        "config_sha256",
        "boundary",
        "remote",
        "destination",
        "updates",
        "outgoing_commits",
        "protected_policy_sha256",
        "protected_rule_count",
        "protected_exposures",
        "rewrite_keys",
        "decision",
        "receipt_sha256",
    }
    if set(receipt) != expected_keys:
        raise ConfidentialityError("Git push preflight receipt schema is invalid")
    if (
        type(receipt.get("schema_version")) is not int
        or receipt.get("schema_version") != 1
        or receipt.get("action") != "git_push_preflight"
        or receipt.get("boundary") != "aoi_cooperative_preflight_not_system_dlp"
        or receipt.get("decision") != "allowed"
        or receipt.get("mode") != validated_binding["mode"]
        or receipt.get("config_sha256") != validated_binding["config_sha256"]
        or receipt.get("remote") != remote
        or receipt.get("destination")
        != canonical_publication_destination(destination, root.resolve(strict=True))
    ):
        raise ConfidentialityError("Git push preflight receipt identity is invalid")
    updates_value = receipt.get("updates")
    if not isinstance(updates_value, list):
        raise ConfidentialityError("Git push preflight receipt updates are invalid")
    updates: list[tuple[str, str, str, str]] = []
    for row in updates_value:
        if not isinstance(row, Mapping) or set(row) != {
            "local_ref",
            "local_sha",
            "remote_ref",
            "remote_sha",
        }:
            raise ConfidentialityError("Git push preflight receipt update is invalid")
        values = (
            row["local_ref"],
            row["local_sha"],
            row["remote_ref"],
            row["remote_sha"],
        )
        if not all(isinstance(item, str) for item in values):
            raise ConfidentialityError("Git push preflight receipt update is invalid")
        typed_values = (
            str(values[0]),
            str(values[1]),
            str(values[2]),
            str(values[3]),
        )
        updates.append(typed_values)
    parsed_updates = _parse_git_push_updates(updates)
    if parsed_updates != updates_value:
        raise ConfidentialityError("Git push preflight receipt updates are noncanonical")
    delivered_remote_ref = _require_git_ref(
        remote_ref, "Git push preflight delivered remote ref"
    )
    delivered_updates = [
        row for row in parsed_updates if row["remote_ref"] == delivered_remote_ref
    ]
    if len(delivered_updates) != 1:
        raise ConfidentialityError(
            "Git push preflight receipt does not bind the delivered commit/ref"
        )
    delivered_commit = _require_git_oid(
        commit, "Git push preflight delivered commit"
    )
    local_sha = delivered_updates[0]["local_sha"]
    local_commit_lines = _git_preflight_lines(
        root,
        ("rev-parse", "--verify", f"{local_sha}^{{commit}}"),
        label="Git push preflight receipt local commit inspection",
    )
    if len(local_commit_lines) != 1:
        raise ConfidentialityError(
            "Git push preflight receipt local object does not peel to one commit"
        )
    local_commit = _require_git_oid(
        local_commit_lines[0], "Git push preflight receipt local commit"
    )
    if local_commit != delivered_commit:
        raise ConfidentialityError(
            "Git push preflight receipt local object does not bind the delivered commit"
        )
    outgoing = receipt.get("outgoing_commits")
    if (
        not isinstance(outgoing, list)
        or len(outgoing) > MAX_GIT_PUSH_COMMITS
        or any(not isinstance(item, str) for item in outgoing)
        or sorted(set(outgoing)) != outgoing
    ):
        raise ConfidentialityError(
            "Git push preflight receipt outgoing commits are invalid"
        )
    for item in outgoing:
        _require_git_oid(item, "Git push preflight outgoing commit")
    if delivered_commit not in outgoing:
        raise ConfidentialityError(
            "Git push preflight receipt does not prove the delivered commit was outgoing"
        )
    if not isinstance(receipt.get("protected_exposures"), list) or not isinstance(
        receipt.get("rewrite_keys"), list
    ):
        raise ConfidentialityError("Git push preflight receipt evidence is invalid")
    if (
        type(receipt.get("protected_rule_count")) is not int
        or receipt.get("protected_rule_count")
        != validated_binding["protected_rule_count"]
        or receipt.get("protected_policy_sha256")
        != validated_binding["protected_policy_sha256"]
    ):
        raise ConfidentialityError(
            "Git push preflight receipt protected policy binding is invalid"
        )
    claimed = receipt.get("receipt_sha256")
    if not isinstance(claimed, str) or _SHA256_RE.fullmatch(claimed) is None:
        raise ConfidentialityError("Git push preflight receipt digest is invalid")
    base = dict(receipt)
    del base["receipt_sha256"]
    expected = hashlib.sha256(
        json.dumps(
            base,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()
    if claimed != expected:
        raise ConfidentialityError("Git push preflight receipt digest is invalid")
    canonical_git_push_preflight_receipt_bytes(receipt)
    return claimed


def validate_git_push_preflight_receipt_contract(
    receipt: Mapping[str, Any],
    *,
    root: Path,
    policy: ConfidentialityConfig,
    config_sha256: str,
    remote: str,
    destination: str,
    commit: str,
    remote_ref: str,
) -> str:
    """Validate durable receipt bytes against the current exact policy."""

    return validate_git_push_preflight_receipt_binding(
        receipt,
        root=root,
        binding=confidentiality_policy_binding(policy, config_sha256),
        remote=remote,
        destination=destination,
        commit=commit,
        remote_ref=remote_ref,
    )


def validate_git_push_preflight_receipt(
    receipt: Mapping[str, Any],
    *,
    root: Path,
    policy: ConfidentialityConfig,
    config_sha256: str,
    remote: str,
    destination: str,
    commit: str,
    remote_ref: str,
) -> str:
    """Recompute and bind one fresh preflight receipt before delivery recording."""

    validated_digest = validate_git_push_preflight_receipt_contract(
        receipt,
        root=root,
        policy=policy,
        config_sha256=config_sha256,
        remote=remote,
        destination=destination,
        commit=commit,
        remote_ref=remote_ref,
    )
    updates = [
        (
            str(row["local_ref"]),
            str(row["local_sha"]),
            str(row["remote_ref"]),
            str(row["remote_sha"]),
        )
        for row in receipt["updates"]
    ]
    recomputed = preflight_git_push(
        root=root,
        policy=policy,
        config_sha256=config_sha256,
        remote=remote,
        destination=destination,
        updates=updates,
        _verify_remote_state=False,
    )
    if dict(receipt) != recomputed:
        raise ConfidentialityError(
            "Git push preflight receipt differs from current exact recomputation"
        )
    if recomputed["receipt_sha256"] != validated_digest:
        raise ConfidentialityError("Git push preflight receipt digest drifted")
    return validated_digest


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

    if not policy.selective_protection:
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


def _protected_rule_report(
    *,
    root: Path,
    policy: ConfidentialityConfig,
    remotes: Iterable[str],
    errors: list[str],
    warnings: list[str],
) -> list[dict[str, Any]]:
    if not policy.protected:
        return []
    identity_rows: dict[str, list[str]] = {rule.path: [] for rule in policy.protected}
    try:
        identities = _protected_content_identities(root, policy)
    except ConfidentialityError as exc:
        errors.append(f"protected content inspection failed: {exc}")
    else:
        for digest, rules in identities.items():
            for rule in rules:
                identity_rows[rule.path].append(digest)
    remote_names = set(remotes)
    rows: list[dict[str, Any]] = []
    for rule in policy.protected:
        candidate: Path | None
        try:
            candidate = _resolve_protected_path_casefold(root, rule.path)
        except ConfidentialityError as exc:
            candidate = None
            errors.append(
                f"protected {rule.kind} inspection failed for {rule.path}: {exc}"
            )
        exists = candidate is not None
        linked = False
        if candidate is not None:
            try:
                linked = _path_is_link_or_reparse(candidate)
            except ConfidentialityError as exc:
                errors.append(str(exc))
                linked = True
        if linked:
            errors.append(f"protected {rule.kind} is linked/reparsed: {rule.path}")
        elif candidate is not None and rule.kind == "file" and not candidate.is_file():
            errors.append(f"protected file is not a regular file: {rule.path}")
        elif candidate is not None and rule.kind == "tree" and not candidate.is_dir():
            errors.append(f"protected tree is not a directory: {rule.path}")
        tracked_raw = _git_confidentiality_bytes(
            root,
            ("ls-files", "-z", "--", f":(icase,literal){rule.path}"),
            label="protected Git tracking inspection",
        )
        if tracked_raw and not tracked_raw.endswith(b"\x00"):
            raise ConfidentialityError(
                "protected Git tracking output is not NUL terminated"
            )
        raw_tracked = [item for item in tracked_raw.split(b"\x00") if item]
        if len(raw_tracked) > MAX_PROTECTED_CONTENT_FILES:
            raise ConfidentialityError(
                "protected Git tracking output exceeds the configured bound"
            )
        try:
            decoded_tracked = [
                item.decode("utf-8", errors="strict") for item in raw_tracked
            ]
        except UnicodeDecodeError as exc:
            raise ConfidentialityError(
                "protected Git tracking paths are not strict UTF-8"
            ) from exc
        tracked = _require_unambiguous_casefold_git_paths(
            decoded_tracked,
            rule=rule,
            label="protected Git tracking inspection",
        )
        if exists and not tracked:
            warnings.append(
                f"protected {rule.kind} is not currently Git-tracked: {rule.path}"
            )
        destination_status = "not_applicable"
        home_destination = None
        if rule.policy == "home_remote_only":
            home_destination = _redacted_destination(
                rule.home_destination or "", root
            )
            if rule.home_remote not in remote_names:
                errors.append(
                    f"protected path home remote is missing: {rule.home_remote}"
                )
                destination_status = "missing_remote"
            else:
                push_urls = _git_preflight_lines(
                    root,
                    ("remote", "get-url", "--push", "--all", rule.home_remote or ""),
                    label="protected home remote inspection",
                )
                if len(push_urls) != 1:
                    errors.append(
                        f"protected path home remote {rule.home_remote} does not have one exact push destination"
                    )
                    destination_status = "ambiguous"
                else:
                    try:
                        observed = canonical_publication_destination(push_urls[0], root)
                        expected = canonical_publication_destination(
                            rule.home_destination or "", root
                        )
                    except ConfidentialityError as exc:
                        errors.append(
                            f"protected path home destination is invalid: {exc}"
                        )
                        destination_status = "invalid"
                    else:
                        destination_status = (
                            "exact" if observed == expected else "drifted"
                        )
                        if observed != expected:
                            errors.append(
                                f"protected path home destination drifted for remote {rule.home_remote}"
                            )
        content_digests = sorted(identity_rows[rule.path])
        content_set_sha256 = hashlib.sha256(
            json.dumps(
                content_digests,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
        rows.append(
            {
                "path": rule.path,
                "kind": rule.kind,
                "policy": rule.policy,
                "home_remote": rule.home_remote,
                "home_destination": home_destination,
                "home_destination_status": destination_status,
                "exists": exists,
                "linked": linked,
                "tracked_path_count": len(tracked),
                "content_count": len(content_digests),
                "content_set_sha256": content_set_sha256,
            }
        )
    return rows


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
            if policy.selective_protection:
                warnings.append(
                    f"Git {suffix[1:]} rewrite exists; protected-content preflight will fail closed if it matches an outgoing push"
                )
        if key in {"lfs.url", "lfs.pushurl"} or (
            key.startswith("remote.") and key.endswith((".lfsurl", ".lfspushurl"))
        ):
            kind = _destination_kind(value, root)
            lfs_endpoints.append(
                {"key": key, "kind": kind, "destination": _redacted_destination(value, root)}
            )
            if policy.selective_protection:
                warnings.append(
                    f"Git LFS endpoint {key} exists; protected LFS paths are denied by the v0.4 preflight"
                )
        if key == "credential.helper":
            credential_helpers.append(value.strip() or "<empty>")

    try:
        lfs_tracked, lfs_attribute_files = _lfs_tracked(root)
    except (OSError, HarnessError) as exc:
        raise ConfidentialityError(f"could not inspect Git LFS attributes: {exc}") from exc
    if policy.selective_protection and external_push_remotes:
        warnings.append(
            "external Git push destinations exist and require exact protected-content preflight for remote(s): "
            + ", ".join(sorted(external_push_remotes))
        )
    if policy.selective_protection and unverified_push_remotes:
        warnings.append(
            "Git push destination locality is unverified for remote(s): "
            + ", ".join(sorted(unverified_push_remotes))
        )
    if policy.selective_protection and lfs_tracked:
        warnings.append(
            "Git LFS attributes are present; any matching protected path will fail preflight closed"
        )

    storage_errors, storage_warnings = _sync_findings(state_dir, env)
    if policy.selective_protection:
        errors.extend(storage_errors)
        warnings.extend(storage_warnings)
    workflows = _workflow_files(root)
    if policy.selective_protection and workflows:
        warnings.append(
            "remote CI/release workflow files are present; only exact protected subjects are publication-restricted"
        )

    environment_credentials = sorted(
        name
        for name in env
        if is_publish_credential_environment_name(name)
    )
    if policy.local_files and environment_credentials:
        warnings.append(
            "upload/publish credential variables are present: "
            + ", ".join(environment_credentials)
        )
    if policy.local_files and credential_helpers:
        warnings.append(
            "Git credential helper configuration exists; credential availability is unverified"
        )

    push_receipts: list[dict[str, Any]] = []
    for task in task_rows:
        delivery = task.get("delivery", {})
        if not isinstance(delivery, dict) or delivery.get("mode") != "pushed":
            continue
        artifact = delivery.get("confidentiality_preflight_artifact")
        binding_value = delivery.get("confidentiality_policy_binding")
        binding: dict[str, Any] | None = None
        if binding_value is not None:
            try:
                if not isinstance(binding_value, Mapping):
                    raise ConfidentialityError(
                        "confidentiality policy binding schema is invalid"
                    )
                binding = validate_confidentiality_policy_binding(binding_value)
            except ConfidentialityError as exc:
                errors.append(
                    f"pushed delivery confidentiality policy binding is invalid: "
                    f"{task.get('task_id', '')}: {exc}"
                )
        receipt_required = (
            binding["protected_rule_count"] > 0
            if binding is not None
            else policy.selective_protection
        )
        row = {
            "task_id": str(task.get("task_id", "")),
            "commit": str(delivery.get("commit", "")),
            "confidentiality_preflight_sha256": str(
                delivery.get("confidentiality_preflight_sha256", "")
            ),
            "receipt_artifact_sha256": (
                str(artifact.get("sha256", ""))
                if isinstance(artifact, Mapping)
                else ""
            ),
            "config_relation": (
                "current" if task.get("config_sha256") == config_sha256 else "historical"
            ),
            "delivery_policy_relation": (
                "current"
                if binding is not None
                and binding["config_sha256"] == config_sha256
                else "historical_or_unrecorded"
            ),
            "delivery_protected_rule_count": (
                binding["protected_rule_count"] if binding is not None else None
            ),
        }
        push_receipts.append(row)
        preflight_digest = str(row["confidentiality_preflight_sha256"])
        artifact_digest = str(row["receipt_artifact_sha256"])
        if receipt_required and _SHA256_RE.fullmatch(preflight_digest) is None:
            errors.append(
                f"protected-content pushed delivery lacks a bound preflight receipt: {row['task_id']}"
            )
        if receipt_required and _SHA256_RE.fullmatch(artifact_digest) is None:
            errors.append(
                f"protected-content pushed delivery lacks persisted receipt bytes: {row['task_id']}"
            )

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

    protected_rules = _protected_rule_report(
        root=root,
        policy=policy,
        remotes=remotes,
        errors=errors,
        warnings=warnings,
    )

    return {
        "schema_version": CONFIDENTIALITY_REPORT_SCHEMA_VERSION,
        "mode": policy.mode,
        "model_context": policy.model_context,
        "guarantee": (
            "model_context_allowed_selective_destination_enforcement"
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
        "protected": {
            "rule_count": len(protected_rules),
            "rules": protected_rules,
            "empty_rules_allow_normal_publication": True,
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
    "MAX_GIT_PREFLIGHT_RECEIPT_BYTES",
    "ConfidentialityError",
    "canonical_git_push_preflight_receipt_bytes",
    "canonical_publication_destination",
    "confidentiality_policy_binding",
    "effective_git_push_destination",
    "inspect_confidentiality",
    "is_publish_credential_environment_name",
    "load_git_push_preflight_receipt",
    "parse_git_push_preflight_receipt_bytes",
    "preflight_git_push",
    "preflight_publication_paths",
    "require_local_storage_path_allowed",
    "require_publication_action_allowed",
    "validate_git_push_preflight_receipt",
    "validate_git_push_preflight_receipt_binding",
    "validate_git_push_preflight_receipt_contract",
    "validate_confidentiality_policy_binding",
]
