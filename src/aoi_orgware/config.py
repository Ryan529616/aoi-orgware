"""Strict, dependency-free project configuration for AOI."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


CONFIG_FILE = "aoi.toml"
CONFIG_SCHEMA_VERSION = 1
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

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
    codex_hooks_enabled: bool
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


def load_config(root: Path, *, allow_missing: bool = False) -> ProjectConfig:
    root = root.resolve()
    source = root / CONFIG_FILE
    if source.is_symlink():
        raise ValueError(f"AOI configuration may not be a symlink: {source}")
    if not source.is_file():
        if not allow_missing:
            raise ValueError(f"AOI is not initialized at {root}; run 'aoi init' first")
        raw = default_config_text(root.name or "AOI Project").encode("utf-8")
    else:
        raw = source.read_bytes()
    try:
        payload = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"invalid {source}: {exc}") from exc
    allowed = {
        "schema_version", "profile_id", "state_dir", "project", "organization",
        "roles", "evidence", "receipts", "policy", "hooks", "legacy",
    }
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ValueError(f"unknown AOI config key(s): {', '.join(unknown)}")
    if payload.get("schema_version") != CONFIG_SCHEMA_VERSION:
        raise ValueError("AOI config requires schema_version = 1")
    project = _table(payload, "project")
    _reject_unknown(project, {"name"}, "project")
    name = project.get("name")
    if not _valid_project_name(name):
        raise ValueError("project.name is invalid")
    profile_id = payload.get("profile_id")
    if not isinstance(profile_id, str) or not SAFE_ID.fullmatch(profile_id):
        raise ValueError("profile_id must be a simple identifier")
    state_dir = payload.get("state_dir")
    if not isinstance(state_dir, str) or not state_dir:
        raise ValueError("state_dir is required")
    state_path = PurePosixPath(state_dir)
    if (
        state_path.is_absolute()
        or not state_path.parts
        or ".." in state_path.parts
        or "\\" in state_dir
        or state_path.parts[0] == ".git"
    ):
        raise ValueError("state_dir must be a safe project-relative POSIX path")
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
        if not isinstance(role, str) or not isinstance(tier, str) or not role or not tier:
            raise ValueError("roles must map non-empty names to non-empty tiers")
        roles[role] = tier
    evidence = _table(payload, "evidence")
    _reject_unknown(evidence, {"categories", "close_qualifying"}, "evidence")
    categories = _strings(evidence.get("categories"), "evidence.categories")
    close_categories = _strings(
        evidence.get("close_qualifying"), "evidence.close_qualifying"
    )
    if not set(close_categories).issubset(categories):
        raise ValueError("evidence.close_qualifying must be a subset of categories")
    receipts = _table(payload, "receipts")
    _reject_unknown(receipts, {"components", "required"}, "receipts")
    components = _strings(receipts.get("components"), "receipts.components")
    required = _strings(receipts.get("required"), "receipts.required")
    if not set(required).issubset(components):
        raise ValueError("receipts.required must be a subset of components")
    policy = _table(payload, "policy")
    _reject_unknown(
        policy, {"high_risk_paths", "external_lock_namespace"}, "policy"
    )
    high_risk = _strings(
        policy.get("high_risk_paths", []), "policy.high_risk_paths", allow_empty=True
    )
    namespace = policy.get("external_lock_namespace", "external")
    if not isinstance(namespace, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{1,31}", namespace):
        raise ValueError("policy.external_lock_namespace is invalid")
    hooks_table = _table(payload, "hooks")
    _reject_unknown(hooks_table, {"codex"}, "hooks")
    hooks = _table(hooks_table, "codex")
    _reject_unknown(hooks, {"enabled"}, "hooks.codex")
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
        codex_hooks_enabled=_boolean(hooks, "enabled", "hooks.codex.enabled"),
        legacy_enabled=_boolean(legacy, "enabled", "legacy.enabled"),
        sha256=hashlib.sha256(raw).hexdigest(),
    )
