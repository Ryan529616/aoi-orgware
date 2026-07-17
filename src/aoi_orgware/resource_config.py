"""Governed Codex project resource configuration for AOI tasks.

The controller is deliberately narrow: it manages the project-scoped Codex
agent concurrency/depth keys and model/reasoning defaults for declared AOI
roles.  It never edits user-level configuration and never treats a requested
model as proof that the provider routed that model.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import tomllib
from pathlib import Path
from typing import Any, Iterable

from .config import ProjectConfig
from .harnesslib import (
    HarnessError,
    atomic_write_bytes,
    canonicalize_no_link_traversal,
    fsync_directory,
    validate_id,
)


RESOURCE_PLAN_SCHEMA_VERSION = 1
RESOURCE_RECEIPT_SCHEMA_VERSION = 2
RESOURCE_FILE_MAX_BYTES = 512 * 1024
RESOURCE_FILE_MAX_COUNT = 64
RESOURCE_TOTAL_MAX_BYTES = 4 * 1024 * 1024
ARISE_MAX_THREADS_CEILING = 12
AOI_MAX_DELEGATION_DEPTH = 2
CODEX_REASONING_EFFORTS = {
    "none",
    "minimal",
    "low",
    "medium",
    "high",
    "xhigh",
    "max",
    "ultra",
}
ENGAGED_LANE_STATUSES = {"active", "waiting", "recovering", "blocked"}
ACTIVE_PACKET_STATUSES = {"ready", "armed", "dispatched"}
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
AGENT_OVERRIDE_KEY_RE = re.compile(
    r"^agents\.(?:(max_threads|max_depth)|"
    r"([A-Za-z0-9][A-Za-z0-9._-]{0,127})\."
    r"(model|model_reasoning_effort))$"
)
ENVELOPE_OVERRIDE_KEYS = {
    "envelope.max_active_first_level_agents",
    "envelope.max_active_total_agents",
    "envelope.max_delegation_depth",
}
OVERRIDE_TARGET_KINDS = {"resource_config", "execution_resource"}


class ResourceApplyRollbackError(HarnessError):
    """Apply failed and the exact automatic rollback could not be completed."""


class ResourceRollbackReapplyError(HarnessError):
    """Rollback failed and the exact applied bytes could not be restored."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


# Ambient provenance recorded on a plan but excluded from its digest: the
# Chief-review anchor must be a pure function of the reviewed resource content,
# not of the working directory the CLI happened to run from. The
# not_applicable apply gate enforces ancestry independently of the digest.
_PLAN_UNSIGNED_CONTEXT_KEYS = frozenset(
    {
        "plan_sha256",
        "invocation_cwd",
        "config_applicability",
        "applicability_basis",
    }
)


def _plan_sha256(payload: dict[str, Any]) -> str:
    unsigned = {
        key: value
        for key, value in payload.items()
        if key not in _PLAN_UNSIGNED_CONTEXT_KEYS
    }
    return _sha256(_canonical_json(unsigned))


def resource_plan_sha256(payload: dict[str, Any]) -> str:
    """Return the canonical digest for one serializable resource plan view."""

    return _plan_sha256(payload)


def _safe_read(path: Path, label: str, *, allow_missing: bool = False) -> bytes | None:
    canonical = canonicalize_no_link_traversal(path, label)
    try:
        before = canonical.lstat()
    except FileNotFoundError:
        if allow_missing:
            return None
        raise HarnessError(f"missing {label}: {canonical}")
    except OSError as exc:
        raise HarnessError(f"cannot inspect {label} {canonical}: {exc}") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise HarnessError(f"{label} must be a private regular file: {canonical}")
    if before.st_size > RESOURCE_FILE_MAX_BYTES:
        raise HarnessError(f"{label} exceeds {RESOURCE_FILE_MAX_BYTES} bytes: {canonical}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(canonical, flags)
    except OSError as exc:
        raise HarnessError(f"cannot open {label} {canonical}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        remaining = RESOURCE_FILE_MAX_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if (
        len(payload) > RESOURCE_FILE_MAX_BYTES
        or opened.st_nlink != 1
        or not stat.S_ISREG(opened.st_mode)
        or any(
            getattr(before, field, None) != getattr(opened, field, None)
            or getattr(opened, field, None) != getattr(finished, field, None)
            for field in identity
        )
        or len(payload) != finished.st_size
        or canonicalize_no_link_traversal(path, label) != canonical
    ):
        raise HarnessError(f"{label} changed while being read: {canonical}")
    return payload


def _decode_toml(raw: bytes, label: str) -> tuple[str, dict[str, Any]]:
    try:
        text = raw.decode("utf-8")
        parsed = tomllib.loads(text)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise HarnessError(f"invalid {label}: {exc}") from exc
    return text, parsed


def _newline(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def _patch_agents_table(raw: bytes, *, max_threads: int, max_depth: int) -> bytes:
    if raw:
        text, parsed = _decode_toml(raw, "project .codex/config.toml")
    else:
        text, parsed = "", {}
    agents = parsed.get("agents", {})
    if not isinstance(agents, dict):
        raise HarnessError("project Codex config [agents] value must be a table")
    lines = text.splitlines()
    header_indices = [
        index
        for index, line in enumerate(lines)
        if re.fullmatch(r"\s*\[agents\]\s*(?:#.*)?", line)
    ]
    if len(header_indices) > 1:
        raise HarnessError("project Codex config contains duplicate [agents] tables")
    if agents and not header_indices:
        raise HarnessError(
            "project Codex config uses dotted/inline agents keys; convert them to "
            "an explicit [agents] table before AOI management"
        )
    values = {"max_threads": max_threads, "max_depth": max_depth}
    if not header_indices:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend(
            [
                "[agents]",
                f"max_threads = {max_threads}",
                f"max_depth = {max_depth}",
            ]
        )
    else:
        start = header_indices[0] + 1
        end = len(lines)
        for index in range(start, len(lines)):
            if re.fullmatch(r"\s*\[\[?.+\]\]?\s*(?:#.*)?", lines[index]):
                end = index
                break
        seen: set[str] = set()
        for index in range(start, end):
            match = re.match(r"^(\s*)(max_threads|max_depth)\s*=.*$", lines[index])
            if not match:
                continue
            key = match.group(2)
            if key in seen:
                raise HarnessError(f"duplicate agents.{key} assignment")
            seen.add(key)
            lines[index] = f"{match.group(1)}{key} = {values[key]}"
        missing = [key for key in ("max_threads", "max_depth") if key not in seen]
        lines[end:end] = [f"{key} = {values[key]}" for key in missing]
    newline = _newline(text)
    rendered = newline.join(lines).rstrip("\r\n") + newline
    try:
        checked = tomllib.loads(rendered)
    except tomllib.TOMLDecodeError as exc:
        raise HarnessError(f"AOI rendered invalid project Codex config: {exc}") from exc
    if checked.get("agents", {}).get("max_threads") != max_threads or checked.get(
        "agents", {}
    ).get("max_depth") != max_depth:
        raise HarnessError("AOI rendered project Codex config with wrong resource values")
    return rendered.encode("utf-8")


def _patch_agent_file(
    raw: bytes, *, role: str, model: str, reasoning_effort: str,
    profile: str | None = None,
) -> bytes:
    expected_name = profile if profile is not None else role
    text, parsed = _decode_toml(raw, f"Codex agent {role}")
    for key in ("name", "description", "developer_instructions"):
        if not isinstance(parsed.get(key), str) or not parsed[key].strip():
            raise HarnessError(f"Codex agent {role} lacks required top-level {key}")
    if parsed["name"] != expected_name:
        raise HarnessError(
            f"Codex agent file name mismatch: expected {expected_name!r}, "
            f"got {parsed['name']!r}"
        )
    lines = text.splitlines()
    first_table = next(
        (
            index
            for index, line in enumerate(lines)
            if re.fullmatch(r"\s*\[\[?.+\]\]?\s*(?:#.*)?", line)
        ),
        len(lines),
    )
    replacements = {
        "model": json.dumps(model),
        "model_reasoning_effort": json.dumps(reasoning_effort),
    }
    seen: set[str] = set()
    for index in range(first_table):
        match = re.match(r"^(\s*)(model|model_reasoning_effort)\s*=.*$", lines[index])
        if not match:
            continue
        key = match.group(2)
        if key in seen:
            raise HarnessError(f"Codex agent {role} has duplicate top-level {key}")
        seen.add(key)
        lines[index] = f"{match.group(1)}{key} = {replacements[key]}"
    insertion = [
        f"{key} = {replacements[key]}"
        for key in ("model", "model_reasoning_effort")
        if key not in seen
    ]
    lines[first_table:first_table] = insertion
    newline = _newline(text)
    rendered = newline.join(lines).rstrip("\r\n") + newline
    try:
        checked = tomllib.loads(rendered)
    except tomllib.TOMLDecodeError as exc:
        raise HarnessError(f"AOI rendered invalid Codex agent {role}: {exc}") from exc
    if checked.get("model") != model or checked.get(
        "model_reasoning_effort"
    ) != reasoning_effort:
        raise HarnessError(f"AOI rendered wrong model settings for Codex agent {role}")
    return rendered.encode("utf-8")


def parse_override_settings(
    values: Iterable[str],
    *,
    roles: Iterable[str] | None = None,
    target_kind: str | None = None,
) -> dict[str, str | int]:
    if target_kind is not None and target_kind not in OVERRIDE_TARGET_KINDS:
        raise HarnessError(f"unsupported resource override target kind: {target_kind}")
    allowed_roles = set(roles) if roles is not None else None
    parsed: dict[str, str | int] = {}
    for raw in values:
        if not isinstance(raw, str) or "=" not in raw:
            raise HarnessError("override setting must use key=value")
        key, value = (part.strip() for part in raw.split("=", 1))
        match = AGENT_OVERRIDE_KEY_RE.fullmatch(key)
        is_envelope_key = key in ENVELOPE_OVERRIDE_KEYS
        if not match and not is_envelope_key:
            raise HarnessError(f"unsupported resource override setting: {key}")
        if target_kind == "resource_config" and is_envelope_key:
            raise HarnessError(f"{key} is not valid for a resource_config override")
        if (
            target_kind == "execution_resource"
            and match
            and match.group(1) in {"max_threads", "max_depth"}
        ):
            raise HarnessError(
                f"{key} is a static resource_config setting, not an execution envelope setting"
            )
        scalar, role, field = match.groups() if match else (key, None, None)
        if role and allowed_roles is not None and role not in allowed_roles:
            raise HarnessError(f"resource override references unknown role: {role}")
        if key in parsed:
            raise HarnessError(f"duplicate resource override setting: {key}")
        if scalar:
            try:
                number = int(value, 10)
            except ValueError as exc:
                raise HarnessError(f"{key} must be an integer") from exc
            if str(number) != value and value != f"+{number}":
                raise HarnessError(f"{key} must use a canonical integer")
            parsed[key] = number
        elif field == "model":
            if not MODEL_RE.fullmatch(value):
                raise HarnessError(f"{key} contains an invalid model identifier")
            parsed[key] = value
        else:
            if value not in CODEX_REASONING_EFFORTS:
                raise HarnessError(f"{key} contains an unsupported reasoning effort")
            parsed[key] = value
    if not parsed:
        raise HarnessError("override request requires at least one setting")
    return dict(sorted(parsed.items()))


def _active_demand(state: dict[str, Any]) -> tuple[int, int, int]:
    engaged = sum(
        lane.get("status") in ENGAGED_LANE_STATUSES
        for lane in state.get("lanes", [])
    )
    active_packets = [
        packet
        for packet in state.get("packets", [])
        if packet.get("status") in ACTIVE_PACKET_STATUSES
    ]
    depth = max(
        (int(packet.get("delegation_depth", 1)) for packet in active_packets),
        default=1,
    )
    return engaged, len(active_packets), depth


def _active_roles(state: dict[str, Any]) -> set[str]:
    roles = {
        str(lane.get("role"))
        for lane in state.get("lanes", [])
        if lane.get("status") in ENGAGED_LANE_STATUSES and lane.get("role")
    }
    roles.update(
        str(packet.get("agent_role"))
        for packet in state.get("packets", [])
        if packet.get("status") in ACTIVE_PACKET_STATUSES and packet.get("agent_role")
    )
    return roles


def _dynamic_envelope(
    state: dict[str, Any],
    demanded_depth: int,
    execution_selection_id: str = "",
) -> dict[str, Any]:
    active_selections = [
        item
        for item in state.get("execution_selections", [])
        if item.get("status") == "active"
        and (
            not execution_selection_id
            or item.get("selection_id") == execution_selection_id
        )
    ]
    if execution_selection_id and len(active_selections) != 1:
        raise HarnessError(
            "Codex resource plan requires one exact active execution selection"
        )
    if not execution_selection_id and len(active_selections) > 1:
        raise HarnessError(
            "multiple active execution selections exist; pass --execution-selection-id"
        )
    if active_selections:
        selection = active_selections[-1]
        governed = selection.get("resource_envelope")
        if governed is not None:
            if not isinstance(governed, dict):
                raise HarnessError("execution selection resource envelope is invalid")
            return {
                **governed,
                "execution_selection_id": str(selection.get("selection_id", "")),
                "resource_envelope_sha256": str(
                    selection.get("resource_envelope_sha256", "")
                ),
            }
        lane_count = len(selection.get("lane_snapshots", []))
        mode = str(selection.get("mode", "single"))
        max_first_level = 1 if mode == "single" else min(4, max(2, lane_count))
        selection_id = str(selection.get("selection_id", ""))
    else:
        mode = "implicit_single"
        max_first_level = 1
        selection_id = ""
    max_depth = 2 if demanded_depth >= 2 else 1
    return {
        "execution_selection_id": selection_id,
        "mode": mode,
        "max_active_first_level_agents": max_first_level,
        "max_active_total_agents": min(
            ARISE_MAX_THREADS_CEILING,
            max_first_level * (2 if max_depth == 2 else 1),
        ),
        "max_delegation_depth": max_depth,
        "depth_two_roles": ["batch", "explorer", "worker"],
    }


def config_applicability_verdict(
    *, target_root: Path, invocation_cwd: Path | None
) -> tuple[str, str]:
    """Classify whether a Codex session like the invoking one can load the
    configuration AOI is about to write under ``target_root``.

    Codex discovers project configuration from its session working directory
    upward, so the written ``.codex`` tree is loadable only when the session
    CWD is at or below ``target_root``. The invocation CWD is a cooperative
    assertion (the caller is presumed to run AOI from inside the live session
    workspace); when it is unavailable the verdict is ``unknown`` rather than a
    silent restart_required=true.
    """

    if invocation_cwd is None:
        return (
            "unknown",
            "no invocation working directory was available; AOI cannot relate "
            "the target root to any live session config ancestry",
        )
    try:
        cwd = invocation_cwd.resolve()
        target = target_root.resolve()
    except OSError as exc:
        return (
            "unknown",
            f"invocation working directory could not be resolved: {exc}",
        )
    if cwd == target or target in cwd.parents:
        return (
            "applicable",
            f"invocation cwd {cwd} is at or below target root {target}; a "
            "fresh trusted session started here loads the written config",
        )
    return (
        "not_applicable",
        f"invocation cwd {cwd} is outside target root {target}; a session "
        "like the invoking one never loads the written config — start the "
        "fresh session inside the target root instead",
    )


def build_codex_resource_plan(
    *,
    event_id: str,
    root: Path,
    config: ProjectConfig,
    state: dict[str, Any],
    codex_home: Path,
    managed_roles: Iterable[str] | None = None,
    platform_max_threads: int = ARISE_MAX_THREADS_CEILING,
    platform_max_depth: int = AOI_MAX_DELEGATION_DEPTH,
    execution_selection_id: str = "",
    override_id: str = "",
    override_settings: dict[str, str | int] | None = None,
    invocation_cwd: Path | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    event_id = validate_id(event_id, "resource config event id")
    approved_task_plan_sha256 = str(state.get("plan_sha256", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", approved_task_plan_sha256):
        raise HarnessError("resource plan requires the exact approved task plan SHA-256")
    if (
        not isinstance(platform_max_threads, int)
        or isinstance(platform_max_threads, bool)
        or not 1 <= platform_max_threads <= ARISE_MAX_THREADS_CEILING
    ):
        raise HarnessError(
            f"platform max_threads must be 1-{ARISE_MAX_THREADS_CEILING}"
        )
    if (
        not isinstance(platform_max_depth, int)
        or isinstance(platform_max_depth, bool)
        or not 1 <= platform_max_depth <= AOI_MAX_DELEGATION_DEPTH
    ):
        raise HarnessError(
            f"platform max_depth must be 1-{AOI_MAX_DELEGATION_DEPTH}"
        )
    root = canonicalize_no_link_traversal(root, "Codex project root")
    if not root.is_dir():
        raise HarnessError(f"Codex project root is not a directory: {root}")
    codex_home = canonicalize_no_link_traversal(codex_home, "Codex home")
    if not codex_home.is_dir():
        raise HarnessError(f"Codex home is not a directory: {codex_home}")
    engaged, active_packets, demanded_depth = _active_demand(state)
    max_threads = platform_max_threads
    max_depth = platform_max_depth
    dynamic_envelope = _dynamic_envelope(
        state, demanded_depth, execution_selection_id
    )
    envelope_roles = dynamic_envelope.get("role_model_tiers", {})
    if envelope_roles and not isinstance(envelope_roles, dict):
        raise HarnessError("execution resource envelope role mapping is invalid")
    depth_two_roles = dynamic_envelope.get("depth_two_role_model_tiers", {})
    if depth_two_roles and not isinstance(depth_two_roles, dict):
        raise HarnessError("execution resource depth-two role mapping is invalid")
    selected_roles = set(managed_roles or envelope_roles or _active_roles(state))
    if not managed_roles:
        selected_roles.update(_active_roles(state))
    selection_settings = dict(dynamic_envelope.get("role_config_overrides", {}))
    if selection_settings:
        canonical_selection_settings = parse_override_settings(
            [f"{key}={value}" for key, value in selection_settings.items()],
            roles=config.roles,
            target_kind="execution_resource",
        )
        if canonical_selection_settings != selection_settings:
            raise HarnessError("execution selection resource settings are not canonical")
    supplied_override_settings = dict(override_settings or {})
    if supplied_override_settings:
        canonical_override_settings = parse_override_settings(
            [f"{key}={value}" for key, value in supplied_override_settings.items()],
            roles=config.roles,
            target_kind="resource_config",
        )
        if canonical_override_settings != supplied_override_settings:
            raise HarnessError("resource override settings are not canonical")
    for key in selection_settings:
        match = AGENT_OVERRIDE_KEY_RE.fullmatch(key)
        if match and match.group(2):
            selected_roles.add(match.group(2))
    selected_roles.update(
        role
        for role in depth_two_roles
        if any(
            packet.get("agent_role") == role
            and packet.get("status") in ACTIVE_PACKET_STATUSES
            for packet in state.get("packets", [])
        )
    )
    for key in supplied_override_settings:
        match = AGENT_OVERRIDE_KEY_RE.fullmatch(key)
        if match and match.group(2):
            selected_roles.add(match.group(2))
    if not selected_roles:
        raise HarnessError(
            "resource plan has no active/explicit Codex roles; pass at least one --role"
        )
    resolved_agents: dict[str, dict[str, str]] = {}
    role_sources: dict[str, bytes] = {}
    role_project_before: dict[str, bytes | None] = {}
    role_profiles = getattr(config, "codex_role_profiles", {}) or {}
    for role in sorted(selected_roles):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", role):
            raise HarnessError(f"invalid managed Codex role: {role}")
        # Four-way separation: the AOI governance role names WHO owns the
        # work; the Codex profile names WHICH agent file supplies runtime
        # defaults. They coincide only when no mapping is configured.
        profile = str(role_profiles.get(role, role))
        profile_label = (
            f"Codex profile {profile} (role {role})" if profile != role else f"Codex agent {role}"
        )
        project_source_path = root / ".codex" / "agents" / f"{profile}.toml"
        source = _safe_read(
            project_source_path,
            f"project {profile_label}",
            allow_missing=True,
        )
        source_kind = "project"
        if source is None:
            source_path = codex_home / "agents" / f"{profile}.toml"
            source = _safe_read(source_path, f"user {profile_label}")
            source_kind = "user_template"
        assert source is not None
        role_sources[role] = source
        role_project_before[role] = source if source_kind == "project" else None
        _source_text, source_profile = _decode_toml(source, f"user {profile_label}")
        declared_name = source_profile.get("name")
        if declared_name is not None and declared_name != profile:
            raise HarnessError(
                f"Codex profile name mismatch for role {role}: file resolves as "
                f"{profile!r} but declares name {declared_name!r}"
            )
        model = source_profile.get("model")
        reasoning = source_profile.get("model_reasoning_effort")
        if not isinstance(model, str) or not MODEL_RE.fullmatch(model):
            raise HarnessError(f"user {profile_label} lacks a valid model")
        if reasoning not in CODEX_REASONING_EFFORTS:
            raise HarnessError(
                f"user {profile_label} lacks a supported model_reasoning_effort"
            )
        resolved_agents[role] = {
            "capability_tier": config.roles.get(role, "project_external_role"),
            "profile": profile,
            "model": model,
            "model_reasoning_effort": reasoning,
            "profile_source_kind": source_kind,
            "profile_source_sha256": _sha256(source),
        }
    settings = {**selection_settings, **supplied_override_settings}
    for key, value in settings.items():
        if key == "agents.max_threads":
            if not isinstance(value, int) or not 1 <= value <= ARISE_MAX_THREADS_CEILING:
                raise HarnessError(
                    f"Chief override may not exceed the ARISE {ARISE_MAX_THREADS_CEILING}-thread ceiling"
                )
            max_threads = value
        elif key == "agents.max_depth":
            if not isinstance(value, int) or not 1 <= value <= AOI_MAX_DELEGATION_DEPTH:
                raise HarnessError(
                    f"Chief override may not exceed AOI delegation depth {AOI_MAX_DELEGATION_DEPTH}"
                )
            max_depth = value
        else:
            match = AGENT_OVERRIDE_KEY_RE.fullmatch(key)
            if not match or not match.group(2):
                raise HarnessError(f"invalid approved resource override setting: {key}")
            role = match.group(2)
            field = match.group(3)
            if role not in resolved_agents:
                raise HarnessError(f"approved resource override names unknown role {role}")
            resolved_agents[role][field] = str(value)
    envelope_total = int(
        dynamic_envelope.get(
            "max_active_total_agents",
            dynamic_envelope.get("max_active_first_level_agents", 1),
        )
    )
    envelope_depth = int(dynamic_envelope.get("max_delegation_depth", 1))
    if max_threads < envelope_total:
        raise HarnessError(
            "project max_threads is below the selected AOI total-agent envelope; "
            "reduce/supersede the envelope or raise the static ceiling"
        )
    if max_depth < envelope_depth:
        raise HarnessError(
            "project max_depth is below the selected AOI delegation envelope; "
            "reduce/supersede the envelope or raise the static ceiling"
        )

    files: list[dict[str, Any]] = []
    project_config_path = root / ".codex" / "config.toml"
    project_config_before = _safe_read(
        project_config_path, "project Codex config", allow_missing=True
    )
    project_config_after = _patch_agents_table(
        project_config_before or b"",
        max_threads=max_threads,
        max_depth=max_depth,
    )
    files.append(
        {
            "relative_path": ".codex/config.toml",
            "path": project_config_path,
            "before": project_config_before,
            "after": project_config_after,
            "source_kind": "project" if project_config_before is not None else "generated",
            "source_sha256": _sha256(project_config_before or b""),
        }
    )
    for role, assignment in resolved_agents.items():
        profile = assignment.get("profile", role)
        relative = f".codex/agents/{profile}.toml"
        destination = root / Path(relative)
        before = role_project_before[role]
        if before is not None:
            source = before
            source_kind = "project"
        else:
            source = role_sources[role]
            source_kind = "user_template"
        after = _patch_agent_file(
            source,
            role=role,
            profile=profile,
            model=assignment["model"],
            reasoning_effort=assignment["model_reasoning_effort"],
        )
        files.append(
            {
                "relative_path": relative,
                "path": destination,
                "before": before,
                "after": after,
                "source_kind": source_kind,
                "source_sha256": _sha256(source),
            }
        )
    if len(files) > RESOURCE_FILE_MAX_COUNT:
        raise HarnessError(
            f"Codex resource plan exceeds the {RESOURCE_FILE_MAX_COUNT}-file limit"
        )
    total = sum(len(item["after"]) + len(item["before"] or b"") for item in files)
    if total > RESOURCE_TOTAL_MAX_BYTES:
        raise HarnessError("Codex resource plan exceeds the aggregate byte limit")
    _applicability_verdict, _applicability_basis = config_applicability_verdict(
        target_root=root, invocation_cwd=invocation_cwd
    )
    view: dict[str, Any] = {
        "schema_version": RESOURCE_PLAN_SCHEMA_VERSION,
        "event_id": event_id,
        "task_id": state.get("task_id"),
        "approved_task_plan_sha256": approved_task_plan_sha256,
        "project_root": str(root),
        "aoi_config_sha256": config.sha256,
        "demand": {
            "engaged_lanes": engaged,
            "active_packets": active_packets,
            "requested_depth": demanded_depth,
        },
        "resolved": {
            "max_threads": max_threads,
            "max_depth": max_depth,
            "agents": resolved_agents,
        },
        "dynamic_envelope": dynamic_envelope,
        "policy_ceiling": {
            "max_threads": ARISE_MAX_THREADS_CEILING,
            "max_depth": AOI_MAX_DELEGATION_DEPTH,
        },
        "override_id": override_id,
        "selection_role_settings": selection_settings,
        "override_settings": supplied_override_settings,
        "required_locks": [
            f"repo:file:{item['relative_path']}" for item in files
        ],
        "files": [
            {
                "relative_path": item["relative_path"],
                "before_exists": item["before"] is not None,
                "before_sha256": _sha256(item["before"] or b""),
                "after_sha256": _sha256(item["after"]),
                "source_kind": item["source_kind"],
                "source_sha256": item["source_sha256"],
            }
            for item in files
        ],
        "restart_required": True,
        "config_applicability": _applicability_verdict,
        "applicability_basis": _applicability_basis,
        "invocation_cwd": str(invocation_cwd) if invocation_cwd else "",
        "codex_home": str(codex_home),
        "routing_evidence_boundary": (
            "Writes requested Codex configuration only; actual provider model routing, "
            "token usage, and price remain unavailable until independently observed."
        ),
        "non_overridable_guardrails": [
            "Chief lease and task-bound session authority",
            "approved plan and explicit claim coverage",
            "packet dispatch-before-work and immutable result identity",
            "evidence category and technical PASS boundaries",
            "configured concurrency/depth ceilings",
        ],
    }
    view["plan_sha256"] = _plan_sha256(view)
    return view, files


def assert_resource_plan_current(files: list[dict[str, Any]]) -> None:
    for item in files:
        current = _safe_read(
            Path(item["path"]),
            f"resource target {item['relative_path']}",
            allow_missing=True,
        )
        if current != item["before"]:
            raise HarnessError(
                f"resource target changed after planning: {item['relative_path']}"
            )


def _assert_resource_state(
    files: list[dict[str, Any]], *, state_key: str, action: str
) -> None:
    """Preflight every target before a multi-file transition mutates any file."""

    for item in files:
        current = _safe_read(
            Path(item["path"]),
            f"{action} target {item['relative_path']}",
            allow_missing=True,
        )
        if current != item[state_key]:
            raise HarnessError(f"{action} target drifted: {item['relative_path']}")


def _write_resource_state(item: dict[str, Any], *, state_key: str) -> None:
    path = Path(item["path"])
    payload = item[state_key]
    if payload is None:
        canonical = canonicalize_no_link_traversal(path, "resource file removal")
        canonical.unlink()
        fsync_directory(canonical.parent)
    else:
        atomic_write_bytes(path, payload)


def _recover_resource_transition(
    transitioned: list[dict[str, Any]], *, source_key: str, target_key: str, action: str
) -> None:
    """Return an incomplete transition to its exact source state."""

    _assert_resource_state(
        transitioned,
        state_key=target_key,
        action=f"{action} recovery preflight",
    )
    for item in reversed(transitioned):
        try:
            _write_resource_state(item, state_key=source_key)
        except BaseException:
            current = _safe_read(
                Path(item["path"]),
                f"{action} recovery target {item['relative_path']}",
                allow_missing=True,
            )
            if current == item[source_key]:
                continue
            raise


def _transition_resource_files(
    files: list[dict[str, Any]],
    *,
    source_key: str,
    target_key: str,
    action: str,
    recovery_error: type[HarnessError],
) -> None:
    """Apply one recoverable exact-byte multi-file state transition."""

    _assert_resource_state(files, state_key=source_key, action=action)
    transitioned: list[dict[str, Any]] = []
    try:
        for item in files:
            try:
                _write_resource_state(item, state_key=target_key)
            except BaseException as write_exc:
                try:
                    current = _safe_read(
                        Path(item["path"]),
                        f"failed {action} target {item['relative_path']}",
                        allow_missing=True,
                    )
                except BaseException as inspect_exc:
                    try:
                        _recover_resource_transition(
                            transitioned,
                            source_key=source_key,
                            target_key=target_key,
                            action=action,
                        )
                    except BaseException as recovery_exc:
                        raise recovery_error(
                            f"{action} target could not be classified and recovery "
                            f"also failed: {recovery_exc}"
                        ) from recovery_exc
                    raise recovery_error(
                        f"{action} target outcome could not be classified; inspect "
                        f"{item['relative_path']}"
                    ) from inspect_exc
                if current == item[target_key] and current != item[source_key]:
                    transitioned.append(item)
                elif current != item[source_key]:
                    try:
                        _recover_resource_transition(
                            transitioned,
                            source_key=source_key,
                            target_key=target_key,
                            action=action,
                        )
                    except BaseException as recovery_exc:
                        raise recovery_error(
                            f"{action} left an uncertain target and recovery also failed; "
                            f"inspect {item['relative_path']}: {recovery_exc}"
                        ) from recovery_exc
                    raise recovery_error(
                        f"{action} left a target in neither reviewed state; inspect "
                        f"{item['relative_path']}"
                    ) from write_exc
                raise
            else:
                transitioned.append(item)
    except recovery_error:
        raise
    except BaseException:
        try:
            _recover_resource_transition(
                transitioned,
                source_key=source_key,
                target_key=target_key,
                action=action,
            )
        except BaseException as recovery_exc:
            raise recovery_error(
                f"{action} failed and exact recovery also failed; inspect targets "
                f"before retry: {recovery_exc}"
            ) from recovery_exc
        raise


def apply_resource_files(files: list[dict[str, Any]]) -> None:
    _transition_resource_files(
        files,
        source_key="before",
        target_key="after",
        action="resource apply",
        recovery_error=ResourceApplyRollbackError,
    )


def make_resource_receipt(
    *,
    event_id: str,
    plan: dict[str, Any],
    files: list[dict[str, Any]],
    applied_at: str,
    root_session_id: str,
) -> dict[str, Any]:
    return {
        "schema_version": RESOURCE_RECEIPT_SCHEMA_VERSION,
        "event_id": event_id,
        "task_id": plan["task_id"],
        "plan_sha256": plan["plan_sha256"],
        "plan": plan,
        "override_id": plan.get("override_id", ""),
        "root_session_id": root_session_id,
        "applied_at": applied_at,
        "restart_required": True,
        "files": [
            {
                "relative_path": item["relative_path"],
                "before_exists": item["before"] is not None,
                "before_sha256": _sha256(item["before"] or b""),
                "before_base64": base64.b64encode(item["before"] or b"").decode(
                    "ascii"
                ),
                "after_sha256": _sha256(item["after"]),
                "after_base64": base64.b64encode(item["after"]).decode("ascii"),
                "source_kind": item["source_kind"],
                "source_sha256": item["source_sha256"],
            }
            for item in files
        ],
        "authority_boundary": (
            "Chief-fenced project configuration write; actual Codex reload and provider "
            "routing require a new session and remain externally observable facts."
        ),
    }


def receipt_sha256(receipt: dict[str, Any]) -> str:
    return _sha256(_canonical_json(receipt))


def validate_resource_receipt(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate a receipt and return its decoded, still path-relative files."""

    if receipt.get("schema_version") != RESOURCE_RECEIPT_SCHEMA_VERSION:
        raise HarnessError("unsupported resource receipt schema")
    plan = receipt.get("plan")
    if (
        not isinstance(plan, dict)
        or plan.get("schema_version") != RESOURCE_PLAN_SCHEMA_VERSION
        or receipt.get("event_id") != plan.get("event_id")
        or receipt.get("plan_sha256") != plan.get("plan_sha256")
        or resource_plan_sha256(plan) != plan.get("plan_sha256")
        or receipt.get("task_id") != plan.get("task_id")
        or receipt.get("override_id", "") != plan.get("override_id", "")
    ):
        raise HarnessError("resource receipt plan binding is invalid")
    raw_files = receipt.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        raise HarnessError("resource receipt contains no files")
    if len(raw_files) > RESOURCE_FILE_MAX_COUNT:
        raise HarnessError("resource receipt contains too many files")
    files: list[dict[str, Any]] = []
    seen: set[str] = set()
    total = 0
    for record in raw_files:
        if not isinstance(record, dict):
            raise HarnessError("resource receipt file record is invalid")
        relative = record.get("relative_path")
        if not isinstance(relative, str) or not (
            relative == ".codex/config.toml"
            or re.fullmatch(
                r"\.codex/agents/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.toml",
                relative,
            )
        ):
            raise HarnessError("resource receipt contains an invalid project path")
        if relative in seen:
            raise HarnessError("resource receipt repeats a project path")
        seen.add(relative)
        if not isinstance(record.get("before_exists"), bool):
            raise HarnessError("resource receipt before_exists must be boolean")
        if record.get("source_kind") not in {
            "generated",
            "project",
            "user_template",
        } or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("source_sha256", ""))):
            raise HarnessError("resource receipt source identity is invalid")
        try:
            before = base64.b64decode(record.get("before_base64", ""), validate=True)
            after = base64.b64decode(record.get("after_base64", ""), validate=True)
        except (ValueError, TypeError) as exc:
            raise HarnessError("resource receipt contains invalid backup bytes") from exc
        if _sha256(before) != record.get("before_sha256") or _sha256(
            after
        ) != record.get("after_sha256"):
            raise HarnessError("resource receipt backup SHA-256 mismatch")
        if not record["before_exists"] and before:
            raise HarnessError("missing resource receipt target has non-empty prior bytes")
        if len(before) > RESOURCE_FILE_MAX_BYTES or len(after) > RESOURCE_FILE_MAX_BYTES:
            raise HarnessError("resource receipt file exceeds the byte limit")
        total += len(before) + len(after)
        files.append(
            {
                "relative_path": relative,
                "before": before if record.get("before_exists") else None,
                "after": after,
                "source_kind": record.get("source_kind"),
                "source_sha256": record.get("source_sha256"),
            }
        )
    if total > RESOURCE_TOTAL_MAX_BYTES:
        raise HarnessError("resource receipt exceeds the aggregate byte limit")
    receipt_view = [
        {
            "relative_path": record["relative_path"],
            "before_exists": record["before_exists"],
            "before_sha256": record["before_sha256"],
            "after_sha256": record["after_sha256"],
            "source_kind": record.get("source_kind"),
            "source_sha256": record.get("source_sha256"),
        }
        for record in raw_files
    ]
    if receipt_view != plan.get("files"):
        raise HarnessError("resource receipt file view differs from its reviewed plan")
    expected_locks = [f"repo:file:{item['relative_path']}" for item in files]
    if plan.get("required_locks") != expected_locks:
        raise HarnessError("resource receipt lock view differs from its reviewed plan")
    return files


def _resource_files_from_receipt(
    *, root: Path, receipt: dict[str, Any]
) -> list[dict[str, Any]]:
    root = canonicalize_no_link_traversal(root, "Codex project root")
    files = validate_resource_receipt(receipt)
    for item in files:
        item["path"] = root / Path(item["relative_path"])
    return files


def rollback_files_from_receipt(*, root: Path, receipt: dict[str, Any]) -> None:
    files = _resource_files_from_receipt(root=root, receipt=receipt)
    _transition_resource_files(
        list(reversed(files)),
        source_key="after",
        target_key="before",
        action="resource rollback",
        recovery_error=ResourceRollbackReapplyError,
    )


def reapply_files_from_receipt(*, root: Path, receipt: dict[str, Any]) -> None:
    """Restore exact applied bytes after a failed rollback state publication."""

    files = _resource_files_from_receipt(root=root, receipt=receipt)
    apply_resource_files(files)
