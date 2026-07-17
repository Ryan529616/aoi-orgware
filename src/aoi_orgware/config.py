"""Strict, dependency-free project configuration for AOI."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any


CONFIG_FILE = "aoi.toml"
CONFIG_SCHEMA_VERSION = 1
MAX_CONFIG_BYTES = 256 * 1024
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
WINDOWS_FORBIDDEN = frozenset('<>:"|?*')
WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)

DEFAULT_ROLES = {
    "architect": "frontier",
    "analysis_specialist": "frontier",
    "implementation_specialist": "expert",
    "reviewer": "expert",
    "external_systems_expert": "expert",
    "worker": "advanced",
    "explorer": "standard",
    "external_operator": "standard",
    "default": "standard",
    "batch": "economical",
}

DEFAULT_EVIDENCE_CATEGORIES = (
    "static_check",
    "unit_test",
    "integration_test",
    "compile_acceptance",
    "runtime_test",
    "external_runtime",
    "system_evidence",
    "hook_smoke",
    "skill_validation",
    "doctor",
    "independent_review",
    "documentation_check",
    "historical_terminal_readback",
    "citation_hygiene_review",
    "resource_governance",
    "delivery_check",
    "engineering_inference",
)

DEFAULT_CLOSE_CATEGORIES = tuple(
    item
    for item in DEFAULT_EVIDENCE_CATEGORIES
    if item not in {"engineering_inference", "historical_terminal_readback"}
)

DEFAULT_RECEIPT_COMPONENTS = ("source", "runner", "config", "dependencies", "other")
DEFAULT_REQUIRED_RECEIPT_COMPONENTS = ("source", "runner")
DEFAULT_DEPARTMENTS = ("implementation", "verification", "operations", "steward")
DEFAULT_HIGH_RISK_PATHS = (".aoi/", "infra/", "security/", "deploy/")
CAPABILITY_TIERS = frozenset(
    {"frontier", "expert", "advanced", "standard", "economical"}
)
NON_CLOSE_QUALIFYING_EVIDENCE = frozenset(
    {"engineering_inference", "historical_terminal_readback"}
)


@dataclass(frozen=True)
class ProjectConfig:
    root: Path
    name: str
    profile_id: str
    state_dir: str
    departments: tuple[str, ...]
    roles: dict[str, str]
    evidence_categories: tuple[str, ...]
    close_qualifying_categories: tuple[str, ...]
    receipt_components: tuple[str, ...]
    required_receipt_components: tuple[str, ...]
    high_risk_paths: tuple[str, ...]
    external_lock_namespace: str
    capacity_recommendation_only: bool
    codex_hooks_enabled: bool
    codex_role_profiles: dict[str, str]
    legacy_enabled: bool
    sha256: str


def default_config_text(project_name: str) -> str:
    if not _valid_project_name(project_name):
        raise ValueError("project name must be 1-128 printable characters")
    quoted_name = json.dumps(project_name, ensure_ascii=False)
    return f'''schema_version = 1
profile_id = "generic-v1"
state_dir = ".aoi"

[project]
name = {quoted_name}

[organization]
departments = ["implementation", "verification", "operations", "steward"]

[roles]
architect = "frontier"
analysis_specialist = "frontier"
implementation_specialist = "expert"
reviewer = "expert"
external_systems_expert = "expert"
worker = "advanced"
explorer = "standard"
external_operator = "standard"
default = "standard"
batch = "economical"

[evidence]
categories = ["static_check", "unit_test", "integration_test", "compile_acceptance", "runtime_test", "external_runtime", "system_evidence", "hook_smoke", "skill_validation", "doctor", "independent_review", "documentation_check", "historical_terminal_readback", "citation_hygiene_review", "resource_governance", "delivery_check", "engineering_inference"]
close_qualifying = ["static_check", "unit_test", "integration_test", "compile_acceptance", "runtime_test", "external_runtime", "system_evidence", "hook_smoke", "skill_validation", "doctor", "independent_review", "documentation_check", "citation_hygiene_review", "resource_governance", "delivery_check"]

[receipts]
components = ["source", "runner", "config", "dependencies", "other"]
required = ["source", "runner"]

[policy]
high_risk_paths = [".aoi/", "infra/", "security/", "deploy/"]
external_lock_namespace = "external"

[hooks.codex]
enabled = false

[legacy]
enabled = false
'''


def _strings(value: Any, label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise ValueError(f"{label} must be a non-empty array of strings")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or "\x00" in item:
            raise ValueError(f"{label} contains an invalid value")
        if item in result:
            raise ValueError(f"{label} contains duplicate {item!r}")
        result.append(item)
    return tuple(result)


def _valid_project_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and value == value.strip()
        and value.isprintable()
    )


def _safe_project_relative_path(value: Any, label: str) -> str:
    """Validate one canonical path on both POSIX and Windows runtimes."""

    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ValueError(f"{label} must be a safe project-relative POSIX path")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or not posix.parts
        or str(posix) != value
    ):
        raise ValueError(f"{label} must be a safe project-relative POSIX path")
    for part in posix.parts:
        folded = part.casefold()
        stem = folded.split(".", 1)[0]
        if (
            folded in {".", "..", ".git"}
            or stem in WINDOWS_RESERVED
            or part.endswith((" ", "."))
            or any(character in WINDOWS_FORBIDDEN for character in part)
            or any(ord(character) < 32 for character in part)
        ):
            raise ValueError(f"{label} must be a safe project-relative POSIX path")
    return value


def _safe_project_relative_prefix(value: Any, label: str) -> str:
    """Validate one exact path or directory prefix used by policy."""

    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a safe project-relative POSIX path")
    directory_prefix = value.endswith("/")
    core = value[:-1] if directory_prefix else value
    canonical = _safe_project_relative_path(core, label)
    return canonical + ("/" if directory_prefix else "")


def _prefix_covers_path(prefix: str, path: str) -> bool:
    canonical = prefix.rstrip("/")
    return path == canonical or path.startswith(canonical + "/")


def _reject_unknown(table: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ValueError(f"unknown {label} key(s): {', '.join(unknown)}")


def _boolean(table: dict[str, Any], key: str, label: str) -> bool:
    value = table.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be true or false")
    return value


def _table(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key, {})
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be a table")
    return value


def _parse_config(root: Path, raw: bytes, source: Path) -> ProjectConfig:
    try:
        payload = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"invalid {source}: {exc}") from exc
    allowed = {
        "schema_version", "profile_id", "state_dir", "project", "organization",
        "roles", "evidence", "receipts", "policy", "hooks", "codex", "legacy",
    }
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ValueError(f"unknown AOI config key(s): {', '.join(unknown)}")
    schema_version = payload.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != CONFIG_SCHEMA_VERSION
    ):
        raise ValueError("AOI config requires schema_version = 1")
    project = _table(payload, "project")
    _reject_unknown(project, {"name"}, "project")
    name = project.get("name")
    if not _valid_project_name(name):
        raise ValueError("project.name is invalid")
    profile_id = payload.get("profile_id")
    if not isinstance(profile_id, str) or not SAFE_ID.fullmatch(profile_id):
        raise ValueError("profile_id must be a simple identifier")
    state_dir = _safe_project_relative_path(payload.get("state_dir"), "state_dir")
    organization = _table(payload, "organization")
    _reject_unknown(organization, {"departments"}, "organization")
    departments = _strings(
        organization.get("departments"),
        "organization.departments",
    )
    roles_payload = _table(payload, "roles")
    if not roles_payload:
        raise ValueError("roles must not be empty")
    roles: dict[str, str] = {}
    for role, tier in roles_payload.items():
        if not isinstance(role, str) or not SAFE_ID.fullmatch(role):
            raise ValueError("role names must be simple identifiers")
        if not isinstance(tier, str) or tier not in CAPABILITY_TIERS:
            allowed_tiers = ", ".join(sorted(CAPABILITY_TIERS))
            raise ValueError(
                f"roles.{role} must use a model-agnostic capability tier: "
                f"{allowed_tiers}"
            )
        roles[role] = tier
    evidence = _table(payload, "evidence")
    _reject_unknown(evidence, {"categories", "close_qualifying"}, "evidence")
    categories = _strings(evidence.get("categories"), "evidence.categories")
    close_categories = _strings(
        evidence.get("close_qualifying"), "evidence.close_qualifying"
    )
    if not set(close_categories).issubset(categories):
        raise ValueError("evidence.close_qualifying must be a subset of categories")
    weak_close = sorted(set(close_categories) & NON_CLOSE_QUALIFYING_EVIDENCE)
    if weak_close:
        raise ValueError(
            "evidence.close_qualifying may not include non-qualifying evidence: "
            + ", ".join(weak_close)
        )
    receipts = _table(payload, "receipts")
    _reject_unknown(receipts, {"components", "required"}, "receipts")
    components = _strings(receipts.get("components"), "receipts.components")
    required = _strings(receipts.get("required"), "receipts.required")
    if not set(required).issubset(components):
        raise ValueError("receipts.required must be a subset of components")
    policy = _table(payload, "policy")
    _reject_unknown(
        policy,
        {
            "high_risk_paths",
            "external_lock_namespace",
            "capacity_recommendation_only",
        },
        "policy",
    )
    raw_high_risk = _strings(
        policy.get("high_risk_paths", []), "policy.high_risk_paths", allow_empty=True
    )
    high_risk = tuple(
        _safe_project_relative_prefix(
            item, f"policy.high_risk_paths[{index}]"
        )
        for index, item in enumerate(raw_high_risk)
    )
    canonical_high_risk = [item.rstrip("/") for item in high_risk]
    if len(canonical_high_risk) != len(set(canonical_high_risk)):
        raise ValueError("policy.high_risk_paths contains duplicate canonical paths")
    if not any(_prefix_covers_path(prefix, state_dir) for prefix in high_risk):
        raise ValueError("policy.high_risk_paths must cover state_dir")
    namespace = policy.get("external_lock_namespace", "external")
    if not isinstance(namespace, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{1,31}", namespace):
        raise ValueError("policy.external_lock_namespace is invalid")
    # Absent means the restrictive phase: capacity output is advice only.
    recommendation_only = policy.get("capacity_recommendation_only", True)
    if not isinstance(recommendation_only, bool):
        raise ValueError("policy.capacity_recommendation_only must be true or false")
    hooks_table = _table(payload, "hooks")
    _reject_unknown(hooks_table, {"codex"}, "hooks")
    hooks = _table(hooks_table, "codex")
    _reject_unknown(hooks, {"enabled"}, "hooks.codex")
    codex_table = _table(payload, "codex")
    _reject_unknown(codex_table, {"profiles"}, "codex")
    profiles_table = _table(codex_table, "profiles")
    codex_role_profiles: dict[str, str] = {}
    for role, profile in profiles_table.items():
        if role not in roles:
            raise ValueError(
                f"codex.profiles.{role} does not name a declared [roles] role"
            )
        if not isinstance(profile, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", profile
        ):
            raise ValueError(
                f"codex.profiles.{role} must be a valid Codex profile name"
            )
        codex_role_profiles[role] = profile
    legacy = _table(payload, "legacy")
    _reject_unknown(legacy, {"enabled"}, "legacy")
    return ProjectConfig(
        root=root,
        name=name,
        profile_id=profile_id,
        state_dir=state_dir,
        departments=departments,
        roles=roles,
        evidence_categories=categories,
        close_qualifying_categories=close_categories,
        receipt_components=components,
        required_receipt_components=required,
        high_risk_paths=high_risk,
        external_lock_namespace=namespace,
        capacity_recommendation_only=recommendation_only,
        codex_hooks_enabled=_boolean(hooks, "enabled", "hooks.codex.enabled"),
        codex_role_profiles=codex_role_profiles,
        legacy_enabled=_boolean(legacy, "enabled", "legacy.enabled"),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _path_is_link_like(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if is_junction and is_junction():
        return True
    if os.name == "nt":
        try:
            attributes = getattr(path.lstat(), "st_file_attributes", 0)
        except (FileNotFoundError, OSError):
            return False
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return False


def load_config_path(root: Path, source: Path) -> tuple[ProjectConfig, bytes]:
    """Load one explicit candidate without mutating the target project."""

    root = root.resolve()
    source = source.expanduser().absolute()
    try:
        before = source.lstat()
    except OSError as exc:
        raise ValueError(f"cannot inspect AOI configuration {source}: {exc}") from exc
    if _path_is_link_like(source):
        raise ValueError(
            f"AOI configuration may not be a symlink or junction: {source}"
        )
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"AOI configuration is not a regular file: {source}")
    if before.st_nlink != 1:
        raise ValueError(f"AOI configuration may not be hard-linked: {source}")
    if before.st_size <= 0 or before.st_size > MAX_CONFIG_BYTES:
        raise ValueError(
            f"AOI configuration must be 1-{MAX_CONFIG_BYTES} bytes: {source}"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise ValueError(f"cannot open AOI configuration safely {source}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
        ):
            raise ValueError(f"AOI configuration changed while opening: {source}")
        chunks: list[bytes] = []
        remaining = MAX_CONFIG_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        finished = os.fstat(descriptor)
        if (
            finished.st_dev != opened.st_dev
            or finished.st_ino != opened.st_ino
            or finished.st_size != opened.st_size
            or getattr(finished, "st_mtime_ns", None)
            != getattr(opened, "st_mtime_ns", None)
            or len(raw) != finished.st_size
        ):
            raise ValueError(f"AOI configuration changed while reading: {source}")
    finally:
        os.close(descriptor)
    if not 0 < len(raw) <= MAX_CONFIG_BYTES:
        raise ValueError(
            f"AOI configuration must be 1-{MAX_CONFIG_BYTES} bytes: {source}"
        )
    return parse_config_bytes(root, raw, source), raw


def parse_config_bytes(root: Path, raw: bytes, source: Path) -> ProjectConfig:
    """Strictly parse one already identity-pinned AOI configuration snapshot.

    Filesystem callers should use :func:`load_config_path`, which pins the
    source identity and enforces the ordinary single-link file contract before
    delegating the validated bytes here.
    """

    root = root.resolve()
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_CONFIG_BYTES:
        raise ValueError(
            f"AOI configuration must be 1-{MAX_CONFIG_BYTES} bytes: {source}"
        )
    return _parse_config(root, raw, source)


def load_config(root: Path, *, allow_missing: bool = False) -> ProjectConfig:
    root = root.resolve()
    source = root / CONFIG_FILE
    if _path_is_link_like(source):
        raise ValueError(f"AOI configuration may not be a symlink or junction: {source}")
    if not source.exists():
        if not allow_missing:
            raise ValueError(f"AOI is not initialized at {root}; run 'aoi init' first")
        raw = default_config_text(root.name or "AOI Project").encode("utf-8")
        return _parse_config(root, raw, source)
    if not source.is_file():
        raise ValueError(f"AOI configuration is not a regular file: {source}")
    config, _raw = load_config_path(root, source)
    return config
