"""Claude Code onboarding: wire the AOI lifecycle hooks and skill into a repo.

This module owns the *client-side* wiring for `aoi claude-init` — writing the
project's ``.claude/settings.json`` hook entries and installing the generic AOI
skill once at Claude user scope — as pure, injectable helpers.  It deliberately
does not import the monolithic CLI or touch AOI ``.aoi/`` state; the composition
root injects the `claude_init` handler that combines AOI initialization with the
wiring done here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset({"claude_init"})

# The console-script entry point installed by the package (see pyproject
# ``[project.scripts]``).  Hook version 1 is the Claude adapter contract.
HOOK_COMMAND = "aoi-claude-hook --hook-version 1"
HOOK_COMMAND_HEAD = "aoi-claude-hook"

# Lifecycle events the AOI Claude adapter handles.  ``PreToolUse`` is the
# pre-spawn gate and is scoped to the sub-agent dispatch tool.
CLAUDE_HOOK_EVENTS = (
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "SubagentStart",
    "Stop",
)
PRETOOLUSE_MATCHER = "Agent"
GOVERNED_AGENT_TYPES_ENV = "AOI_CLAUDE_GOVERNED_AGENT_TYPES"


class ClaudeOnboardingError(Exception):
    """Raised when the target ``.claude`` configuration cannot be wired safely."""


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.aoi-", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _aoi_hook_entry(event: str) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "hooks": [{"type": "command", "command": HOOK_COMMAND}],
    }
    if event == "PreToolUse":
        return {"matcher": PRETOOLUSE_MATCHER, **entry}
    return entry


def _strip_wrapping_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _contains_shell_control(command: str) -> bool:
    quote = ""
    for character in command:
        if character in {"'", '"'}:
            if not quote:
                quote = character
            elif quote == character:
                quote = ""
            continue
        if character in "$`%!^":
            return True
        if not quote and character in "\r\n;&|<>()":
            return True
    return False


def _direct_aoi_hook_argv(value: Any) -> list[str] | None:
    command = str(value or "").strip()
    if not command or _contains_shell_control(command):
        return None
    for posix in (False, True):
        try:
            raw = shlex.split(command, posix=posix)
        except ValueError:
            continue
        argv = [_strip_wrapping_quotes(item) for item in raw]
        if not argv:
            continue
        names = {
            PurePosixPath(argv[0]).name.lower(),
            PureWindowsPath(argv[0]).name.lower(),
        }
        if names & {HOOK_COMMAND_HEAD, f"{HOOK_COMMAND_HEAD}.exe"}:
            return argv
    return None


def _command_invokes_aoi(value: Any, *, require_current: bool = False) -> bool:
    argv = _direct_aoi_hook_argv(value)
    if argv is None:
        return False
    versioned = (
        len(argv) == 3
        and argv[1] == "--hook-version"
        and re.fullmatch(r"\d+", argv[2]) is not None
    )
    if not versioned:
        return False
    return not require_current or argv[2] == "1"


def _entry_carries_aoi_hook(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    handlers = entry.get("hooks", [])
    if not isinstance(handlers, list):
        return False
    return any(
        isinstance(handler, dict) and _command_invokes_aoi(handler.get("command"))
        for handler in handlers
    )


def _validate_event_entries(event: str, entries: list[Any]) -> None:
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ClaudeOnboardingError(
                f".claude/settings.json event {event!r} entry {index} "
                "must be a JSON object"
            )
        handlers = entry.get("hooks")
        if not isinstance(handlers, list):
            raise ClaudeOnboardingError(
                f".claude/settings.json event {event!r} entry {index} "
                "'hooks' must be a JSON array"
            )
        if not all(isinstance(handler, dict) for handler in handlers):
            raise ClaudeOnboardingError(
                f".claude/settings.json event {event!r} entry {index} "
                "hook handlers must be JSON objects"
            )
        if any(
            "command" in handler and not isinstance(handler["command"], str)
            for handler in handlers
        ):
            raise ClaudeOnboardingError(
                f".claude/settings.json event {event!r} entry {index} "
                "hook command values must be strings"
            )


def _merge_claude_hook_settings_detailed(
    settings: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str], list[str]]:
    """Preserve foreign hooks while adding or upgrading only AOI-owned entries."""

    merged: dict[str, Any] = dict(settings)
    raw_hooks = merged.get("hooks")
    if raw_hooks is not None and not isinstance(raw_hooks, dict):
        raise ClaudeOnboardingError(".claude/settings.json 'hooks' must be a JSON object")
    hooks: dict[str, Any] = dict(raw_hooks) if isinstance(raw_hooks, dict) else {}
    added: list[str] = []
    updated: list[str] = []
    for event in CLAUDE_HOOK_EVENTS:
        existing = hooks.get(event)
        if existing is not None and not isinstance(existing, list):
            raise ClaudeOnboardingError(
                f".claude/settings.json event {event!r} must be a JSON array"
            )
        entries = list(existing) if isinstance(existing, list) else []
        _validate_event_entries(event, entries)
        desired = _aoi_hook_entry(event)
        aoi_entries = [entry for entry in entries if _entry_carries_aoi_hook(entry)]
        if aoi_entries == [desired]:
            hooks[event] = entries
            continue
        if not aoi_entries:
            entries.append(desired)
            hooks[event] = entries
            added.append(event)
            continue

        preserved: list[Any] = []
        for entry in entries:
            if not _entry_carries_aoi_hook(entry):
                preserved.append(entry)
                continue
            handlers = entry.get("hooks", [])
            unrelated = [
                handler
                for handler in handlers
                if not (
                    isinstance(handler, dict)
                    and _command_invokes_aoi(handler.get("command"))
                )
            ]
            if unrelated:
                retained = dict(entry)
                retained["hooks"] = unrelated
                preserved.append(retained)
        preserved.append(desired)
        hooks[event] = preserved
        updated.append(event)
    merged["hooks"] = hooks
    return merged, added, updated


def merge_claude_hook_settings(settings: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Return a non-destructive merge while upgrading AOI-owned handlers."""

    merged, added, _updated = _merge_claude_hook_settings_detailed(settings)
    return merged, added


def _load_claude_settings(settings_path: Path) -> dict[str, Any]:
    if not settings_path.exists():
        return {}
    try:
        loaded = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise ClaudeOnboardingError(f"cannot read {settings_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ClaudeOnboardingError(
            f"{settings_path} is not valid JSON; fix or remove it before wiring AOI: {exc}"
        ) from exc
    if not isinstance(loaded, dict):
        raise ClaudeOnboardingError(
            f"{settings_path} must contain a JSON object at the top level"
        )
    return loaded


def _merge_governed_agent_types(
    merged: dict[str, Any], governed_agent_types: str | None
) -> None:
    if governed_agent_types is None:
        return
    raw_env = merged.get("env")
    if raw_env is not None and not isinstance(raw_env, dict):
        raise ClaudeOnboardingError(".claude/settings.json 'env' must be a JSON object")
    env = dict(raw_env) if isinstance(raw_env, dict) else {}
    value = governed_agent_types.strip()
    if value:
        env[GOVERNED_AGENT_TYPES_ENV] = value
    else:
        env.pop(GOVERNED_AGENT_TYPES_ENV, None)
    merged["env"] = env


def preflight_claude_onboarding(
    settings_path: Path, *, governed_agent_types: str | None = None
) -> dict[str, Any]:
    """Validate the settings merge without mutating the repository."""

    settings = _load_claude_settings(settings_path)
    merged, added, updated = _merge_claude_hook_settings_detailed(settings)
    _merge_governed_agent_types(merged, governed_agent_types)
    return {
        "settings_path": str(settings_path),
        "events_to_add": added,
        "events_to_update": updated,
        "changed": merged != settings or not settings_path.exists(),
    }


def install_claude_hooks(
    settings_path: Path,
    *,
    governed_agent_types: str | None = None,
) -> dict[str, Any]:
    """Atomically merge AOI hooks into ``settings_path`` if bytes must change."""

    settings = _load_claude_settings(settings_path)
    merged, added, updated = _merge_claude_hook_settings_detailed(settings)
    _merge_governed_agent_types(merged, governed_agent_types)
    changed = merged != settings or not settings_path.exists()
    if changed:
        _atomic_write_text(
            settings_path,
            json.dumps(merged, indent=2, ensure_ascii=False) + "\n",
        )
    already_present = [
        event
        for event in CLAUDE_HOOK_EVENTS
        if event not in added and event not in updated
    ]
    return {
        "settings_path": str(settings_path),
        "events_added": added,
        "events_updated": updated,
        "events_already_present": already_present,
        "hook_command": HOOK_COMMAND,
        "changed": changed,
    }


def preflight_claude_user_skill(
    skills_root: Path,
    skill_text: str,
    *,
    replace_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate a Claude user-scope AOI skill install without changing it."""

    skills_root = skills_root.expanduser()
    if not skills_root.is_absolute():
        raise ClaudeOnboardingError(
            "Claude user skills root must be absolute; use $HOME/.claude/skills "
            "or pass the Claude host's explicit user-skill directory"
        )
    skill_path = skills_root / "aoi" / "SKILL.md"
    existing_text: str | None = None
    if skill_path.exists():
        try:
            existing_text = skill_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ClaudeOnboardingError(f"cannot read {skill_path}: {exc}") from exc
    existing_sha256 = (
        hashlib.sha256(existing_text.encode("utf-8")).hexdigest()
        if existing_text is not None
        else None
    )
    normalized_replace = (replace_sha256 or "").strip().lower() or None
    if normalized_replace is not None and not re.fullmatch(
        r"[0-9a-f]{64}", normalized_replace
    ):
        raise ClaudeOnboardingError(
            "--replace-user-skill-sha256 must be exactly 64 hexadecimal characters"
        )
    changed = existing_text != skill_text
    if existing_text is not None and changed and normalized_replace != existing_sha256:
        raise ClaudeOnboardingError(
            f"{skill_path} differs from the packaged AOI skill; review it and rerun "
            f"with --replace-user-skill-sha256 {existing_sha256} to replace those "
            "exact bytes"
        )
    return {
        "scope": "user",
        "skills_root": str(skills_root),
        "skill_path": str(skill_path),
        "existing_sha256": existing_sha256,
        "packaged_sha256": hashlib.sha256(skill_text.encode("utf-8")).hexdigest(),
        "changed": changed,
    }


def install_claude_user_skill(
    skills_root: Path,
    skill_text: str,
    *,
    replace_sha256: str | None = None,
) -> dict[str, Any]:
    result = preflight_claude_user_skill(
        skills_root,
        skill_text,
        replace_sha256=replace_sha256,
    )
    if result["changed"]:
        _atomic_write_text(Path(result["skill_path"]), skill_text)
    result["updated"] = bool(result["changed"] and result["existing_sha256"] is not None)
    result["created"] = bool(result["changed"] and result["existing_sha256"] is None)
    return result


def register_claude_onboarding_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    """Register ``claude-init``."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "claude onboarding command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("claude-init")
    parser.add_argument("--project-name")
    parser.add_argument(
        "--governed-agent-types",
        help=(
            "comma-separated Claude sub-agent types the pre-spawn gate governs; "
            f"written to {GOVERNED_AGENT_TYPES_ENV} in .claude/settings.json"
        ),
    )
    parser.add_argument(
        "--user-skills-root",
        help=(
            "Claude user-scope skills directory; defaults to $HOME/.claude/skills "
            "on the host running AOI"
        ),
    )
    parser.add_argument(
        "--replace-user-skill-sha256",
        help="reviewed SHA-256 required to replace a differing user AOI skill",
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["claude_init"])


__all__ = [
    "ClaudeOnboardingError",
    "CLAUDE_HOOK_EVENTS",
    "HOOK_COMMAND",
    "PRETOOLUSE_MATCHER",
    "GOVERNED_AGENT_TYPES_ENV",
    "merge_claude_hook_settings",
    "install_claude_hooks",
    "install_claude_user_skill",
    "preflight_claude_onboarding",
    "register_claude_onboarding_commands",
    "preflight_claude_user_skill",
]
