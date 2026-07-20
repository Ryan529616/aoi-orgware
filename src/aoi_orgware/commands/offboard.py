"""Fail-closed, AOI-owned-only client offboarding.

This module deliberately does not dismantle an AOI project.  It removes only
the repository-local client wiring that the onboarding helpers can recognize,
leaving ``.aoi`` task/evidence state as an inert archive and never touching a
user-scope skill.  The composition root may register ``offboard`` later; this
leaf module has no dependency on :mod:`aoi_orgware.cli`.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
import tempfile
import tomllib
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .. import harnesslib as h
from ..harnesslib import HarnessError
from ..codex_install_provenance import (
    CodexInstallProvenanceError,
    load_codex_install_provenance_receipt,
)
from . import codex_onboarding as codex
from . import claude_onboarding as claude


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset({"offboard"})
_SCHEMA_VERSION = 1
_MANIFEST_NAMES = ("aoi-managed-manifest.json", "aoi-manifest.json")
_CLAUDE_ENV_KEY = "AOI_CLAUDE_GOVERNED_AGENT_TYPES"
_TABLE_HEADER = re.compile(r"^\s*\[([^\]]+)\]\s*(?:#.*)?$")
_TOML_ASSIGNMENT = re.compile(
    r"^(?P<indent>\s*)(?P<key>[A-Za-z0-9_-]+|\"[^\"]+\"|'[^']+')\s*=.*$"
)


class OffboardError(Exception):
    """The target cannot be offboarded without risking foreign configuration."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_root(root: Path) -> Path:
    candidate = Path(root).expanduser()
    if not candidate.is_absolute():
        raise OffboardError("offboard root must be absolute")
    _secure_path(candidate, "offboard root", require_exists=True)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise OffboardError(f"cannot resolve offboard root {candidate}: {exc}") from exc
    if not resolved.is_dir():
        raise OffboardError("offboard root must be a real directory, not a link")
    return resolved


def _is_link_like(path: Path) -> bool:
    if path.is_symlink():
        return True
    if os.name == "nt":
        try:
            attributes = getattr(path.lstat(), "st_file_attributes", 0)
        except OSError:
            return False
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return False


def _secure_path(path: Path, label: str, *, require_exists: bool = False) -> None:
    """Reject a link/reparse point in every existing component of ``path``."""

    lexical = path.expanduser()
    if not lexical.is_absolute():
        raise OffboardError(f"{label} must be absolute")
    current = Path(lexical.anchor)
    for part in lexical.parts[1:]:
        if part == "..":
            raise OffboardError(f"{label} may not contain parent traversal")
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise OffboardError(f"cannot inspect {label} component {current}: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode) or _is_link_like(current):
            raise OffboardError(f"{label} may not traverse symlinks, junctions, or reparse points")
    if require_exists and not path.exists():
        raise OffboardError(f"{label} is missing")


def _safe_file(path: Path, label: str) -> bytes | None:
    """Read one private regular configuration file without following its leaf."""

    _secure_path(path, label)
    try:
        status = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise OffboardError(f"cannot inspect {label}: {exc}") from exc
    if _is_link_like(path) or not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
        raise OffboardError(f"{label} must be one private regular non-linked file")
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            raw = stream.read()
            finished = os.fstat(stream.fileno())
    except OSError as exc:
        raise OffboardError(f"cannot read {label}: {exc}") from exc
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if (
        any(getattr(status, field) != getattr(opened, field) or getattr(opened, field) != getattr(finished, field) for field in fields)
        or opened.st_nlink != 1
        or len(raw) != finished.st_size
    ):
        raise OffboardError(f"{label} changed while being read")
    _secure_path(path, label, require_exists=True)
    return raw


def _decode(raw: bytes, label: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OffboardError(f"{label} must be UTF-8: {exc}") from exc


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(_decode(raw, label))
    except json.JSONDecodeError as exc:
        raise OffboardError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise OffboardError(f"{label} must contain a JSON object")
    return value


def _codex_handler_ownership(handler: dict[str, Any], root: Path) -> str:
    """Return current, legacy, or foreign without guessing current ownership."""

    commands: list[tuple[str, str]] = []
    for key in ("command", "commandWindows"):
        value = handler.get(key)
        if isinstance(value, str) and value.strip():
            commands.append((key, value))
    if not commands:
        return "foreign"
    receipt: dict[str, Any] | None = None
    hook: dict[str, Any] | None = None
    try:
        receipt = load_codex_install_provenance_receipt(root)
        hook = receipt["codex_hook_entry_point"]
        current_pair = codex.is_current_codex_hook_command_pair(
            handler.get("command"),
            handler.get("commandWindows"),
            expected_launcher=hook["path"],
            expected_project_root=root,
            expected_provenance_sha256=receipt["provenance_receipt_sha256"],
        )
    except (CodexInstallProvenanceError, KeyError, TypeError):
        current_pair = False
    if current_pair:
        return "current"
    if hook is not None and receipt is not None:
        individually_current = [
            codex.is_aoi_codex_hook_command(
                command,
                expected_launcher=hook["path"],
                expected_project_root=root,
                expected_provenance_sha256=receipt["provenance_receipt_sha256"],
            )
            for _key, command in commands
        ]
    else:
        individually_current = [False] * len(commands)
    if any(individually_current):
        raise OffboardError(
            "Codex hook handler has a partial or route-drifted current AOI command pair"
        )
    structurally_current = [
        codex.is_aoi_codex_hook_command(command)
        for _key, command in commands
    ]
    if any(structurally_current):
        raise OffboardError(
            "Codex hook handler has a partial or route-drifted current AOI command pair"
        )
    legacy = [
        codex.is_aoi_codex_hook_command(command, require_current=False)
        for _key, command in commands
    ]
    if any(legacy):
        if not all(legacy):
            raise OffboardError("Codex hook handler mixes legacy AOI and foreign platform commands")
        return "legacy"
    if any(codex.references_aoi_codex_hook(command) for _key, command in commands):
        raise OffboardError(
            "Codex hook handler has a malformed or route-drifted AOI command pair"
        )
    return "foreign"


def _hook_settings(
    payload: dict[str, Any], *, root: Path
) -> tuple[dict[str, Any], list[str], bool, list[str], list[str]]:
    """Remove recognized AOI handlers while retaining every foreign handler."""

    raw_hooks = payload.get("hooks")
    if raw_hooks is None:
        return dict(payload), [], False, [], []
    if not isinstance(raw_hooks, dict):
        raise OffboardError(".codex/configuration 'hooks' must be an object")
    hooks = dict(raw_hooks)
    removed: list[str] = []
    preserved: list[str] = []
    foreign_handler_present = False
    legacy: list[str] = []
    for event in sorted(hooks):
        if not isinstance(event, str) or not isinstance(hooks[event], list):
            raise OffboardError(f".codex/configuration event {event!r} must be an array")
        entries = hooks[event]
        retained_entries: list[Any] = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                raise OffboardError(
                    f".codex/configuration event {event!r} entry {index} is malformed"
                )
            handlers = entry["hooks"]
            if not all(isinstance(handler, dict) for handler in handlers):
                raise OffboardError(
                    f".codex/configuration event {event!r} entry {index} has a non-object handler"
                )
            owned_flags: list[bool] = []
            for handler in handlers:
                for command_key in ("command", "commandWindows"):
                    command = handler.get(command_key)
                    if command is not None and not isinstance(command, str):
                        raise OffboardError(
                            f".codex/configuration event {event!r} has a non-string {command_key}"
                        )
                try:
                    ownership = _codex_handler_ownership(handler, root)
                except codex.CodexOnboardingError as exc:
                    raise OffboardError(str(exc)) from exc
                if ownership == "legacy":
                    legacy.append(f"codex.hooks.{event}")
                owned_flags.append(ownership in {"current", "legacy"})
            kept = [handler for handler, owned in zip(handlers, owned_flags) if not owned]
            if any(owned_flags):
                removed.append(f"codex.hooks.{event}")
            if any(owned_flags) and kept:
                foreign_handler_present = True
                preserved.append(f"codex.hooks.{event}:foreign")
                replacement = dict(entry)
                replacement["hooks"] = kept
                retained_entries.append(replacement)
            elif not any(owned_flags):
                # An empty or opaque-but-valid hook block is not ours to erase.
                # It also means AOI cannot prove that hooks=true served only AOI.
                foreign_handler_present = True
                preserved.append(f"codex.hooks.{event}:foreign")
                retained_entries.append(entry)
        if retained_entries:
            hooks[event] = retained_entries
        else:
            hooks.pop(event, None)
    merged = dict(payload)
    if hooks:
        merged["hooks"] = hooks
    else:
        merged.pop("hooks", None)
    return (
        merged,
        sorted(set(removed)),
        foreign_handler_present,
        sorted(set(preserved)),
        sorted(set(legacy)),
    )


def _claude_owned_hook_entry(event: str, entry: Any) -> bool:
    """Recognize only the exact entry shape emitted by ``claude-init``.

    A foreign Claude configuration may happen to invoke an AOI-named command.
    Offboarding has no authority to remove it unless both its event-local shape
    and the current adapter command/version are exactly the onboarding output.
    """

    if event not in claude.CLAUDE_HOOK_EVENTS or not isinstance(entry, dict):
        return False
    expected: dict[str, Any] = {
        "hooks": [{"type": "command", "command": claude.HOOK_COMMAND}],
    }
    if event == "PreToolUse":
        expected = {"matcher": claude.PRETOOLUSE_MATCHER, **expected}
    return entry == expected


def _toml_env_keys(parsed: dict[str, Any], label: str) -> set[str]:
    env = parsed.get("env")
    if env is None:
        return set()
    if not isinstance(env, dict):
        raise OffboardError(f"{label} [env] must be a TOML table")
    if any(not isinstance(key, str) for key in env):
        raise OffboardError(f"{label} [env] contains a non-string key")
    # Codex onboarding has no managed env contract.  AOI-looking names can be
    # application or user settings and are therefore always retained.
    return set()


def _patch_codex_toml(
    text: str, *, remove_env: set[str], disable_hooks: bool
) -> str:
    """Make only line-local, parse-verified changes to explicit TOML tables."""

    lines = text.splitlines(keepends=True)
    current_table = ""
    removed_env: set[str] = set()
    hooks_changed = False
    for index, line in enumerate(lines):
        body = line.rstrip("\r\n")
        header = _TABLE_HEADER.match(body)
        if header:
            current_table = header.group(1).strip()
            continue
        match = _TOML_ASSIGNMENT.match(body)
        if not match:
            continue
        key = match.group("key").strip("\"'")
        if current_table == "env" and key in remove_env:
            lines[index] = ""
            removed_env.add(key)
            continue
        if current_table == "features" and key == "hooks" and disable_hooks:
            newline = "\r\n" if line.endswith("\r\n") else "\n"
            if not line.endswith(("\n", "\r")):
                newline = ""
            lines[index] = f"{match.group('indent')}hooks = false{newline}"
            hooks_changed = True
    if removed_env != remove_env:
        raise OffboardError(
            "AOI [env] keys use a noncanonical TOML form; refusing to rewrite config"
        )
    if disable_hooks and not hooks_changed:
        raise OffboardError(
            "[features].hooks requires an explicit canonical assignment before offboarding"
        )
    candidate = "".join(lines)
    try:
        checked = tomllib.loads(candidate) if candidate.strip() else {}
    except tomllib.TOMLDecodeError as exc:
        raise OffboardError(f"generated .codex/config.toml is invalid: {exc}") from exc
    if _toml_env_keys(checked, ".codex/config.toml"):
        raise OffboardError("generated .codex/config.toml retained AOI [env] keys")
    if disable_hooks and checked.get("features", {}).get("hooks") is not False:
        raise OffboardError("generated .codex/config.toml did not disable hooks")
    return candidate


def _manifest_is_aoi_owned(payload: dict[str, Any]) -> bool:
    markers = {
        str(payload.get(key, "")).strip().lower()
        for key in ("managed_by", "owner", "tool")
    }
    return bool(markers & {"aoi", "aoi-orgware", "aoi_orgware"})


def _quiescence_blockers_locked(paths: h.HarnessPaths) -> list[str]:
    """Prove the already-locked AOI state is inert, failing closed on ambiguity."""

    blockers: list[str] = []
    for state in h.load_all_tasks(paths):
        task_id = str(state.get("task_id", "unknown"))
        status = state.get("status")
        if status not in h.TASK_STATUSES or status in {"active", "blocked"}:
            blockers.append(f"task:{task_id}:{status if status is not None else 'unknown'}")
        packets = state.get("packets", [])
        if not isinstance(packets, list):
            blockers.append(f"packet:{task_id}:unknown:unknown")
        else:
            for packet in packets:
                if not isinstance(packet, dict):
                    blockers.append(f"packet:{task_id}:unknown:unknown")
                    continue
                packet_status = packet.get("status")
                if packet_status not in h.PACKET_STATUSES or packet_status in h.ACTIVE_PACKET_STATUSES:
                    blockers.append(
                        f"packet:{task_id}:{packet.get('packet_id', 'unknown')}:{packet_status if packet_status is not None else 'unknown'}"
                    )
        jobs = state.get("jobs", [])
        if not isinstance(jobs, list):
            blockers.append(f"job:{task_id}:unknown:unknown")
        else:
            for job in jobs:
                if not isinstance(job, dict):
                    blockers.append(f"job:{task_id}:unknown:unknown")
                    continue
                job_status = job.get("status")
                if job_status not in h.JOB_STATUSES or job_status in h.ACTIVE_JOB_STATUSES:
                    blockers.append(
                        f"job:{task_id}:{job.get('run_id', 'unknown')}:{job_status if job_status is not None else 'unknown'}"
                    )
        session_ids = state.get("session_ids", [])
        parent_session_ids = state.get("subagent_parent_session_ids", [])
        if not isinstance(session_ids, list) or not isinstance(parent_session_ids, list):
            blockers.append(f"bound-session:{task_id}:unknown")
        else:
            for session_id in (*session_ids, *parent_session_ids):
                blockers.append(f"bound-session:{task_id}:{session_id}")
    for claim in h.reserving_claims(paths):
        blockers.append(f"reserving-claim:{claim.get('token', 'unknown')}")
    if paths.sessions.exists():
        _secure_path(paths.sessions, "AOI session directory", require_exists=True)
        with os.scandir(paths.sessions) as entries:
            for entry in entries:
                # A mapping not referenced by state is still a live/ambiguous binding.
                blockers.append(f"bound-session-file:{Path(entry.path).name}")
    for temporary in h.scan_atomic_temporaries(paths):
        blockers.append(f"temporary-or-recovery-residue:{temporary.path.name}")
    return sorted(set(blockers))


def _quiescence_blockers(root: Path, *, locked_paths: h.HarnessPaths | None = None) -> list[str]:
    """Read the AOI state under one lock and prove it is inert before apply."""

    harness = root / ".aoi"
    config = root / "aoi.toml"
    if not harness.exists() and not config.exists():
        return []
    if not harness.exists() or not config.exists():
        return ["AOI state/config layout is incomplete; explicit recovery is required"]
    try:
        paths = locked_paths or h.get_paths(root)
        if paths.root != root:
            raise OffboardError("AOI state lock root does not match offboard root")
        if locked_paths is not None:
            blockers = _quiescence_blockers_locked(paths)
        else:
            with h.state_lock(paths, create_layout=False):
                blockers = _quiescence_blockers_locked(paths)
    except (HarnessError, OSError, TypeError, ValueError) as exc:
        return [f"cannot prove AOI state quiescent: {exc}"]
    return sorted(set(blockers))


def _add_change(
    changes: list[dict[str, Any]], path: Path, root: Path, raw: bytes, after: str | None
) -> None:
    changes.append(
        {
            "path": path.relative_to(root).as_posix(),
            "before_sha256": _sha256(raw),
            "after_text": after,
        }
    )


def plan_offboard(
    root: Path,
    *,
    archive_dir: Path | None = None,
    _locked_paths: h.HarnessPaths | None = None,
) -> dict[str, Any]:
    """Return a serializable, no-write offboarding plan.

    ``archive_dir`` is deliberately outside the repository by default, so AOI
    state remains untouched even while backups and receipts are produced.
    """

    root = _canonical_root(root)
    archive_raw = (
        Path(archive_dir).expanduser()
        if archive_dir is not None
        else root.parent / f".{root.name}.aoi-offboard-archive"
    )
    if not archive_raw.is_absolute():
        raise OffboardError("offboard archive directory must be absolute")
    _secure_path(archive_raw, "offboard archive directory")
    archive = archive_raw.resolve()
    if archive == root or root in archive.parents:
        raise OffboardError("offboard archive directory must stay outside the repository")

    changes: list[dict[str, Any]] = []
    removed: list[str] = []
    preserved: list[str] = []
    skipped: list[str] = []
    codex_aoi_removed = False
    codex_foreign_hooks = False

    codex_hooks = root / ".codex" / "hooks.json"
    raw = _safe_file(codex_hooks, ".codex/hooks.json")
    if raw is None:
        skipped.append("codex.hooks:missing")
    else:
        payload = _json_object(raw, ".codex/hooks.json")
        merged, entries_removed, codex_foreign_hooks, hook_preserved, legacy = _hook_settings(payload, root=root)
        codex_aoi_removed = bool(entries_removed)
        removed.extend(entries_removed)
        preserved.extend(hook_preserved)
        preserved.extend(f"{item}:legacy-owned" for item in legacy)
        if merged != payload:
            _add_change(changes, codex_hooks, root, raw, json.dumps(merged, indent=2, ensure_ascii=False) + "\n")
        else:
            skipped.append("codex.hooks:no-aoi-owned-entry")

    codex_config = root / ".codex" / "config.toml"
    raw = _safe_file(codex_config, ".codex/config.toml")
    if raw is None:
        skipped.append("codex.config:missing")
    else:
        text = _decode(raw, ".codex/config.toml")
        try:
            parsed = tomllib.loads(text) if text.strip() else {}
        except tomllib.TOMLDecodeError as exc:
            raise OffboardError(f".codex/config.toml is invalid: {exc}") from exc
        features = parsed.get("features", {})
        if not isinstance(features, dict):
            raise OffboardError(".codex/config.toml [features] must be a TOML table")
        hooks_value = features.get("hooks")
        if hooks_value is not None and not isinstance(hooks_value, bool):
            raise OffboardError(".codex/config.toml features.hooks must be a boolean")
        env_keys = _toml_env_keys(parsed, ".codex/config.toml")
        preserved.extend(
            f"codex.config.env.{key}:foreign"
            for key in sorted(set(parsed.get("env", {})) - env_keys)
        )
        disable_hooks = bool(hooks_value is True and codex_aoi_removed and not codex_foreign_hooks)
        if hooks_value is True and not disable_hooks:
            preserved.append("codex.config.features.hooks")
        if env_keys or disable_hooks:
            candidate = _patch_codex_toml(text, remove_env=env_keys, disable_hooks=disable_hooks)
            _add_change(changes, codex_config, root, raw, candidate)
            removed.extend(f"codex.config.env.{key}" for key in sorted(env_keys))
            if disable_hooks:
                removed.append("codex.config.features.hooks")
        else:
            skipped.append("codex.config:no-aoi-owned-setting")

    claude_settings = root / ".claude" / "settings.json"
    raw = _safe_file(claude_settings, ".claude/settings.json")
    if raw is None:
        skipped.append("claude.settings:missing")
    else:
        payload = _json_object(raw, ".claude/settings.json")
        # Claude offboarding is intentionally narrower than Codex: onboarding
        # owns only its exact emitted hook entries and this one env key.
        merged = dict(payload)
        raw_hooks = payload.get("hooks")
        if raw_hooks is not None and not isinstance(raw_hooks, dict):
            raise OffboardError(".claude/settings.json 'hooks' must be an object")
        hooks = dict(raw_hooks) if isinstance(raw_hooks, dict) else {}
        claude_removed: list[str] = []
        for event, entries in list(hooks.items()):
            if not isinstance(event, str) or not isinstance(entries, list):
                raise OffboardError(f".claude/settings.json event {event!r} must be an array")
            retained = []
            for index, entry in enumerate(entries):
                if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                    raise OffboardError(
                        f".claude/settings.json event {event!r} entry {index} is malformed"
                    )
                if not all(isinstance(handler, dict) for handler in entry["hooks"]):
                    raise OffboardError(
                        f".claude/settings.json event {event!r} entry {index} has a non-object handler"
                    )
                if _claude_owned_hook_entry(event, entry):
                    claude_removed.append(f"claude.hooks.{event}")
                else:
                    retained.append(entry)
            if retained:
                hooks[event] = retained
            else:
                hooks.pop(event)
        if hooks:
            merged["hooks"] = hooks
        else:
            merged.pop("hooks", None)
        raw_env = payload.get("env")
        if raw_env is not None and not isinstance(raw_env, dict):
            raise OffboardError(".claude/settings.json 'env' must be an object")
        env = dict(raw_env) if isinstance(raw_env, dict) else {}
        env_removed = [key for key in env if key == _CLAUDE_ENV_KEY]
        if any(not isinstance(key, str) for key in env):
            raise OffboardError(".claude/settings.json env contains a non-string key")
        for key in env_removed:
            env.pop(key)
        if raw_env is not None:
            if env:
                merged["env"] = env
            else:
                merged.pop("env", None)
        removed.extend(claude_removed)
        removed.extend(f"claude.settings.env.{key}" for key in env_removed)
        if "hooks" in payload:
            if hooks:
                preserved.append("claude.hooks:foreign")
        preserved.extend(
            f"claude.settings.env.{key}:foreign"
            for key in sorted(set(env) - set(env_removed))
        )
        if merged != payload:
            _add_change(changes, claude_settings, root, raw, json.dumps(merged, indent=2, ensure_ascii=False) + "\n")
        else:
            skipped.append("claude.settings:no-aoi-owned-setting")

    for name in _MANIFEST_NAMES:
        manifest = root / ".codex" / name
        raw = _safe_file(manifest, f".codex/{name}")
        if raw is None:
            continue
        payload = _json_object(raw, f".codex/{name}")
        if _manifest_is_aoi_owned(payload):
            _add_change(changes, manifest, root, raw, None)
            removed.append(f"codex.manifest.{name}")
        else:
            preserved.append(f"codex.manifest.{name}:unrecognized-owner")

    if (root / ".aoi").exists():
        preserved.append("aoi.state:inert-archive")
    preserved.append("user-scope.aoi-skill:not-touched")
    changes.sort(key=lambda item: str(item["path"]))
    plan = {
        "schema_version": _SCHEMA_VERSION,
        "operation": "aoi-owned-only-offboard",
        "root": str(root),
        "archive_dir": str(archive),
        "changes": changes,
        "removed": sorted(set(removed)),
        "preserved": sorted(set(preserved)),
        "skipped": sorted(set(skipped)),
        "quiescence_blockers": _quiescence_blockers(root, locked_paths=_locked_paths),
    }
    plan["plan_id"] = _plan_id(root, archive, changes)
    return plan


def _atomic_write(path: Path, payload: bytes) -> None:
    _secure_path(path.parent, f"offboard write parent {path.parent}")
    path.parent.mkdir(parents=True, exist_ok=True)
    _secure_path(path.parent, f"offboard write parent {path.parent}", require_exists=True)
    if path.exists():
        _safe_file(path, f"offboard write target {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.aoi-", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _plan_id(root: Path, archive: Path, changes: list[dict[str, Any]]) -> str:
    """Bind an archive namespace to one root and the complete reviewed diff."""

    canonical = json.dumps(
        {"root": str(root), "archive_dir": str(archive), "changes": changes},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return _sha256(canonical.encode("utf-8"))[:16]


def _receipt_for(
    plan: Mapping[str, Any], root: Path, archive: Path, changes: list[dict[str, Any]]
) -> dict[str, Any]:
    plan_id = _plan_id(root, archive, changes)
    return {
        "schema_version": _SCHEMA_VERSION,
        "operation": "aoi-owned-only-offboard",
        "plan_id": plan_id,
        "root": str(root),
        "archive_dir": str(archive),
        "removed": list(plan["removed"]),
        "preserved": list(plan["preserved"]),
        "skipped": list(plan["skipped"]),
        "backups": [
            {
                "path": change["path"],
                "sha256": change["before_sha256"],
                "after_sha256": (
                    _sha256(change["after_text"].encode("utf-8"))
                    if change["after_text"] is not None
                    else None
                ),
                "backup": f"backups/{index:03d}-{Path(str(change['path'])).name}.bak",
            }
            for index, change in enumerate(changes)
        ],
    }


def _receipt_bytes(receipt: Mapping[str, Any]) -> bytes:
    return json.dumps(receipt, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"


def _exact_receipt_readback(
    receipt_path: Path,
    receipt: dict[str, Any],
    root: Path,
) -> bool:
    """Accept only an exact prior receipt whose backups and after-image survive."""

    raw = _safe_file(receipt_path, f"offboard receipt {receipt_path}")
    if raw is None:
        return False
    if raw != _receipt_bytes(receipt):
        raise OffboardError("offboard receipt already exists with different reviewed identity")
    stored = _json_object(raw, f"offboard receipt {receipt_path}")
    if stored != receipt:
        raise OffboardError("offboard receipt is not exact canonical readback")
    for backup in receipt["backups"]:
        backup_path = receipt_path.parent / str(backup["backup"])
        backup_raw = _safe_file(backup_path, f"offboard backup {backup_path}")
        if backup_raw is None or _sha256(backup_raw) != backup["sha256"]:
            raise OffboardError(f"offboard receipt backup is missing or changed: {backup_path}")
        target = root / str(backup["path"])
        after_sha256 = backup["after_sha256"]
        target_raw = _safe_file(target, f"offboard after-image {target}")
        if after_sha256 is None:
            if target_raw is not None:
                raise OffboardError(f"offboard receipt after-image drifted: {target}")
        elif target_raw is None or _sha256(target_raw) != after_sha256:
            raise OffboardError(f"offboard receipt after-image drifted: {target}")
    return True


def _apply_offboard_locked(
    plan: Mapping[str, Any], root: Path, *, locked_paths: h.HarnessPaths | None
) -> dict[str, Any]:
    """Apply under the caller's full AOI lock interval, if AOI state exists."""

    if plan.get("schema_version") != _SCHEMA_VERSION or plan.get("operation") != "aoi-owned-only-offboard":
        raise OffboardError("unsupported offboard plan schema")
    planned_root = _canonical_root(Path(str(plan.get("root", ""))))
    if planned_root != root:
        raise OffboardError("offboard plan root does not match locked root")
    blockers = _quiescence_blockers(root, locked_paths=locked_paths)
    if blockers:
        raise OffboardError("AOI state is not quiescent: " + "; ".join(blockers))
    archive_raw = Path(str(plan.get("archive_dir", ""))).expanduser()
    _secure_path(archive_raw, "offboard archive directory")
    archive = archive_raw.resolve()
    if not archive.is_absolute() or archive == root or root in archive.parents:
        raise OffboardError("offboard archive directory is unsafe")
    changes = plan.get("changes")
    if not isinstance(changes, list):
        raise OffboardError("offboard plan changes must be a list")
    if not all(isinstance(item, dict) for item in changes):
        raise OffboardError("offboard plan contains an invalid change")
    for change in changes:
        if not isinstance(change.get("path"), str):
            raise OffboardError("offboard plan contains an invalid change")
        relative = Path(change["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise OffboardError("offboard plan contains an unsafe relative path")
        if not isinstance(change.get("before_sha256"), str) or not re.fullmatch(
            r"[0-9a-f]{64}", change["before_sha256"]
        ):
            raise OffboardError("offboard plan contains an invalid preimage digest")
        if change.get("after_text") is not None and not isinstance(change.get("after_text"), str):
            raise OffboardError("offboard plan after_text must be string or null")
    plan_id = _plan_id(root, archive, changes)
    stated_plan_id = plan.get("plan_id")
    if stated_plan_id is not None and stated_plan_id != plan_id:
        raise OffboardError("offboard plan id does not match its canonical root, archive, and changes")
    for key in ("removed", "preserved", "skipped"):
        if not isinstance(plan.get(key), list) or not all(isinstance(item, str) for item in plan[key]):
            raise OffboardError(f"offboard plan {key} must be a list of strings")
    receipt = _receipt_for(plan, root, archive, changes)
    archive_root = archive / plan_id
    receipt_path = archive_root / "receipt.json"
    if _exact_receipt_readback(receipt_path, receipt, root):
        return {**receipt, "dry_run": False, "receipt_path": str(receipt_path)}
    originals: list[tuple[dict[str, Any], Path, bytes]] = []
    for change in changes:
        if not isinstance(change, dict) or not isinstance(change.get("path"), str):
            raise OffboardError("offboard plan contains an invalid change")
        relative = Path(change["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise OffboardError("offboard plan contains an unsafe relative path")
        target = root / relative
        raw = _safe_file(target, f"offboard target {relative.as_posix()}")
        if raw is None or _sha256(raw) != change.get("before_sha256"):
            raise OffboardError(f"offboard target drifted since plan: {relative.as_posix()}")
        after = change.get("after_text")
        if after is not None and not isinstance(after, str):
            raise OffboardError("offboard plan after_text must be string or null")
        originals.append((change, target, raw))
    backups = archive_root / "backups"
    try:
        for index, (change, _target, raw) in enumerate(originals):
            backup = backups / f"{index:03d}-{Path(str(change['path'])).name}.bak"
            if backup.exists():
                if _safe_file(backup, f"offboard backup {backup}") != raw:
                    raise OffboardError(f"offboard backup differs from reviewed preimage: {backup}")
            else:
                _atomic_write(backup, raw)
    except OSError as exc:
        raise OffboardError(f"cannot create offboard backup: {exc}") from exc
    applied: list[tuple[Path, bytes]] = []
    try:
        for change, target, raw in originals:
            after = change["after_text"]
            if after is None:
                _safe_file(target, f"offboard delete target {target}")
                target.unlink()
            else:
                _atomic_write(target, after.encode("utf-8"))
            applied.append((target, raw))
    except (OSError, OffboardError, HarnessError) as exc:
        rollback_errors: list[str] = []
        for target, raw in reversed(applied):
            try:
                _atomic_write(target, raw)
            except (OSError, OffboardError) as rollback_exc:
                rollback_errors.append(f"{target}: {rollback_exc}")
        detail = "; ".join(rollback_errors)
        suffix = f"; rollback also failed: {detail}" if detail else "; restored applied targets"
        raise OffboardError(f"offboard apply failed: {exc}{suffix}") from exc
    try:
        h.atomic_create_bytes(receipt_path, _receipt_bytes(receipt))
    except (OSError, OffboardError, HarnessError) as exc:
        receipt_rollback_errors: list[str] = []
        for target, raw in reversed(applied):
            try:
                _atomic_write(target, raw)
            except (OSError, OffboardError) as rollback_exc:
                receipt_rollback_errors.append(f"{target}: {rollback_exc}")
        detail = "; ".join(receipt_rollback_errors)
        suffix = f"; rollback also failed: {detail}" if detail else "; restored client mutations"
        raise OffboardError(f"offboard receipt write failed: {exc}{suffix}") from exc
    return {**receipt, "dry_run": False, "receipt_path": str(receipt_path)}


def apply_offboard(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Direct API: hold one state lock from quiescence through receipt/rollback."""

    if plan.get("schema_version") != _SCHEMA_VERSION or plan.get("operation") != "aoi-owned-only-offboard":
        raise OffboardError("unsupported offboard plan schema")
    root = _canonical_root(Path(str(plan.get("root", ""))))
    if not (root / ".aoi").is_dir() or not (root / "aoi.toml").is_file():
        raise OffboardError(
            "direct offboard apply requires an initialized AOI state lock; use dry-run only until AOI is initialized"
        )
    paths = h.get_paths(root)
    try:
        with h.state_lock(paths, create_layout=False):
            return _apply_offboard_locked(plan, root, locked_paths=paths)
    except HarnessError as exc:
        raise OffboardError(str(exc)) from exc


def offboard(
    root: Path,
    *,
    archive_dir: Path | None = None,
    dry_run: bool = True,
    _locked_paths: h.HarnessPaths | None = None,
) -> dict[str, Any]:
    """Plan by default; pass ``dry_run=False`` to perform the reviewed plan."""

    plan = plan_offboard(root, archive_dir=archive_dir, _locked_paths=_locked_paths)
    if dry_run:
        return {
            "dry_run": True,
            "receipt": {
                key: plan[key]
                for key in ("schema_version", "operation", "root", "removed", "preserved", "skipped", "quiescence_blockers")
            },
            "changes": [item["path"] for item in plan["changes"]],
        }
    if _locked_paths is None:
        return apply_offboard(plan)
    canonical_root = _canonical_root(root)
    return _apply_offboard_locked(plan, canonical_root, locked_paths=_locked_paths)


def emit(payload: Any, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(payload)


def cmd_offboard(args: argparse.Namespace, paths: Any) -> int:
    try:
        result = offboard(
            Path(paths.root),
            archive_dir=Path(args.archive_dir) if args.archive_dir else None,
            dry_run=not bool(args.apply),
            _locked_paths=(
                paths if bool(getattr(args, "_aoi_initialized_at_dispatch", False)) else None
            ),
        )
    except (OSError, OffboardError) as exc:
        raise HarnessError(str(exc)) from exc
    emit(result, args.json)
    return 0


def register_offboard_commands(
    subparsers: Any, *, handlers: Mapping[str, Handler], add_json_argument: JsonArgumentRegistrar
) -> None:
    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(f"offboard command handler map mismatch: missing={missing}, unexpected={unexpected}")
    parser = subparsers.add_parser("offboard")
    parser.add_argument("--apply", action="store_true", help="apply after backup; default is dry-run")
    parser.add_argument("--archive-dir", help="absolute backup/receipt directory outside the repository")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["offboard"])


__all__ = [
    "OffboardError",
    "apply_offboard",
    "cmd_offboard",
    "offboard",
    "plan_offboard",
    "register_offboard_commands",
]
