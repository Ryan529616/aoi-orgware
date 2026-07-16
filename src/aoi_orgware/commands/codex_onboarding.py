"""Codex onboarding helpers for ``aoi codex-init``.

The module owns only client-side, repository-local wiring: Codex lifecycle
hooks, the hook feature flag, and the AOI repository skill.  It preserves
unrelated user configuration and never edits global ``CODEX_HOME`` state or
marks a hook trusted on the user's behalf.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import tempfile
import tomllib
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset({"codex_init"})

HOOK_COMMAND = "aoi-codex-hook --hook-version 6"
HOOK_COMMAND_HEAD = "aoi-codex-hook"
HOOK_TIMEOUT_SECONDS = 30
SESSION_START_MATCHER = "startup|resume|clear|compact"
CODEX_HOOK_EVENTS = (
    "SessionStart",
    "UserPromptSubmit",
    "SubagentStart",
    "Stop",
)
_STATUS_MESSAGES = {
    "SessionStart": "Loading AOI state",
    "UserPromptSubmit": "Checking AOI task binding",
    "SubagentStart": "Loading AOI packet contract",
    "Stop": "Checking AOI checkpoint state",
}


class CodexOnboardingError(Exception):
    """Raised when repository-local Codex configuration is unsafe to merge."""


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


def _hook_handler(command: str, command_windows: str, event: str) -> dict[str, Any]:
    return {
        "type": "command",
        "command": command,
        "commandWindows": command_windows,
        "timeout": HOOK_TIMEOUT_SECONDS,
        "statusMessage": _STATUS_MESSAGES[event],
    }


def _aoi_hook_entry(
    event: str, *, command: str, command_windows: str
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "hooks": [_hook_handler(command, command_windows, event)]
    }
    if event == "SessionStart":
        entry["matcher"] = SESSION_START_MATCHER
    return entry


def _strip_wrapping_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _executable_names(value: str) -> set[str]:
    return {
        PurePosixPath(value).name.lower(),
        PureWindowsPath(value).name.lower(),
    }


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


def _wsl_hook_index(argv: list[str]) -> int | None:
    """Return the hook argv index for a conservative documented WSL launcher."""

    index = 1
    options_with_value = {"-d", "--distribution", "-u", "--user", "--cd"}
    options_with_equals = ("--distribution=", "--user=", "--cd=")
    while index < len(argv):
        token = argv[index]
        if token in {"--exec", "-e", "--"}:
            index += 1
            break
        if token in options_with_value:
            if index + 1 >= len(argv):
                return None
            value = argv[index + 1]
            if not value or value.startswith("-"):
                return None
            index += 2
            continue
        if token.startswith(options_with_equals):
            value = _strip_wrapping_quotes(token.split("=", 1)[1])
            if not value or value.startswith("-"):
                return None
            index += 1
            continue
        break
    return index if index < len(argv) else None


def _direct_aoi_hook_argv(value: Any) -> list[str] | None:
    """Parse a direct hook or the narrow ``wsl [--exec]`` process wrapper."""

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
        names = _executable_names(argv[0])
        if names & {HOOK_COMMAND_HEAD, f"{HOOK_COMMAND_HEAD}.exe"}:
            return argv
        if names & {"wsl", "wsl.exe"}:
            hook_index = _wsl_hook_index(argv)
            if hook_index is not None and _executable_names(argv[hook_index]) & {
                HOOK_COMMAND_HEAD,
                f"{HOOK_COMMAND_HEAD}.exe",
            }:
                return argv[hook_index:]
    return None


def is_aoi_codex_hook_command(value: Any, *, require_current: bool = True) -> bool:
    """Recognize direct AOI-owned commands, optionally at any hook version."""

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
    if not require_current:
        return True
    return argv[2] == "6"


def _command_invokes_aoi(value: Any) -> bool:
    return is_aoi_codex_hook_command(value, require_current=False)


def _validate_hook_command(value: str, label: str) -> str:
    command = value.strip()
    if not is_aoi_codex_hook_command(command):
        raise CodexOnboardingError(
            f"{label} must directly invoke aoi-codex-hook --hook-version 6 "
            "(an absolute path or narrow 'wsl [--exec]' launcher is allowed)"
        )
    return command


def _handler_is_aoi_owned(handler: Any) -> bool:
    if not isinstance(handler, dict):
        return False
    commands = [
        handler.get(key)
        for key in ("command", "commandWindows")
        if str(handler.get(key, "")).strip()
    ]
    ownership = [_command_invokes_aoi(command) for command in commands]
    if any(ownership) and not all(ownership):
        raise CodexOnboardingError(
            "Codex hook handler mixes an AOI-owned command with a foreign "
            "platform command; split or remove it before wiring AOI"
        )
    return bool(ownership) and all(ownership)


def _entry_carries_aoi_hook(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    handlers = entry.get("hooks", [])
    if not isinstance(handlers, list):
        return False
    return any(_handler_is_aoi_owned(handler) for handler in handlers)


def _validate_event_entries(event: str, entries: list[Any]) -> None:
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise CodexOnboardingError(
                f".codex/hooks.json event {event!r} entry {index} "
                "must be a JSON object"
            )
        handlers = entry.get("hooks")
        if not isinstance(handlers, list):
            raise CodexOnboardingError(
                f".codex/hooks.json event {event!r} entry {index} "
                "'hooks' must be a JSON array"
            )
        if not all(isinstance(handler, dict) for handler in handlers):
            raise CodexOnboardingError(
                f".codex/hooks.json event {event!r} entry {index} "
                "hook handlers must be JSON objects"
            )
        if any(
            key in handler and not isinstance(handler[key], str)
            for handler in handlers
            for key in ("command", "commandWindows")
        ):
            raise CodexOnboardingError(
                f".codex/hooks.json event {event!r} entry {index} "
                "hook command values must be strings"
            )


def _merge_codex_hook_settings_detailed(
    settings: Mapping[str, Any],
    *,
    command: str = HOOK_COMMAND,
    command_windows: str | None = None,
) -> tuple[dict[str, Any], list[str], list[str]]:
    """Return merged settings plus added and upgraded AOI event lists."""

    command = _validate_hook_command(command, "Codex hook command")
    command_windows = _validate_hook_command(
        command_windows or command, "Codex Windows hook command"
    )
    merged: dict[str, Any] = dict(settings)
    raw_hooks = merged.get("hooks")
    if raw_hooks is not None and not isinstance(raw_hooks, dict):
        raise CodexOnboardingError(".codex/hooks.json 'hooks' must be a JSON object")
    hooks: dict[str, Any] = dict(raw_hooks) if isinstance(raw_hooks, dict) else {}
    added: list[str] = []
    updated: list[str] = []
    for event in CODEX_HOOK_EVENTS:
        existing = hooks.get(event)
        if existing is not None and not isinstance(existing, list):
            raise CodexOnboardingError(
                f".codex/hooks.json event {event!r} must be a JSON array"
            )
        entries = list(existing) if isinstance(existing, list) else []
        _validate_event_entries(event, entries)
        desired = _aoi_hook_entry(
            event,
            command=command,
            command_windows=command_windows,
        )
        aoi_entries = [entry for entry in entries if _entry_carries_aoi_hook(entry)]
        if aoi_entries == [desired]:
            hooks[event] = entries
            continue
        if not aoi_entries:
            entries.append(desired)
            hooks[event] = entries
            added.append(event)
            continue

        # Rebuild only the AOI-owned handler. If an entry also carries an
        # unrelated handler, retain that handler and its matcher/settings.
        preserved: list[Any] = []
        for entry in entries:
            if not _entry_carries_aoi_hook(entry):
                preserved.append(entry)
                continue
            handlers = entry.get("hooks", [])
            unrelated = [
                handler
                for handler in handlers
                if not _handler_is_aoi_owned(handler)
            ]
            if unrelated:
                retained_entry = dict(entry)
                retained_entry["hooks"] = unrelated
                preserved.append(retained_entry)
        preserved.append(desired)
        hooks[event] = preserved
        updated.append(event)
    merged["hooks"] = hooks
    return merged, added, updated


def merge_codex_hook_settings(
    settings: Mapping[str, Any],
    *,
    command: str = HOOK_COMMAND,
    command_windows: str | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Return ``(new_settings, events_added)`` while upgrading AOI handlers."""

    merged, added, _updated = _merge_codex_hook_settings_detailed(
        settings,
        command=command,
        command_windows=command_windows,
    )
    return merged, added


def install_codex_hooks(
    hooks_path: Path,
    *,
    command: str = HOOK_COMMAND,
    command_windows: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if hooks_path.exists():
        try:
            loaded = json.loads(hooks_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise CodexOnboardingError(
                f"{hooks_path} is not valid JSON; fix it before wiring AOI: {exc}"
            ) from exc
        if not isinstance(loaded, dict):
            raise CodexOnboardingError(
                f"{hooks_path} must contain a JSON object at the top level"
            )
        payload = loaded
    merged, added, updated = _merge_codex_hook_settings_detailed(
        payload, command=command, command_windows=command_windows
    )
    changed = merged != payload or not hooks_path.exists()
    if changed:
        _atomic_write_text(
            hooks_path,
            json.dumps(merged, indent=2, ensure_ascii=False) + "\n",
        )
    return {
        "hooks_path": str(hooks_path),
        "events_added": added,
        "events_updated": updated,
        "events_already_present": [
            event
            for event in CODEX_HOOK_EVENTS
            if event not in added and event not in updated
        ],
        "hook_command": command,
        "hook_command_windows": command_windows or command,
        "trust_required": True,
        "changed": changed,
    }


def preflight_codex_onboarding(
    root: Path,
    *,
    command: str = HOOK_COMMAND,
    command_windows: str | None = None,
) -> dict[str, Any]:
    """Validate all existing Codex client files without mutating the repo."""

    config_path = root / ".codex" / "config.toml"
    try:
        config_text = (
            config_path.read_text(encoding="utf-8") if config_path.exists() else ""
        )
    except (OSError, UnicodeError) as exc:
        raise CodexOnboardingError(f"cannot read {config_path}: {exc}") from exc
    merged_config, config_changed = merge_codex_config_toml(config_text)
    # The merge helper already parses the candidate; keep the value live here
    # so a future refactor cannot silently turn this into a syntax-only probe.
    if tomllib.loads(merged_config).get("features", {}).get("hooks") is not True:
        raise CodexOnboardingError("Codex hook feature preflight did not converge")

    hooks_path = root / ".codex" / "hooks.json"
    payload: dict[str, Any] = {}
    if hooks_path.exists():
        try:
            loaded = json.loads(hooks_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError) as exc:
            raise CodexOnboardingError(f"cannot read {hooks_path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise CodexOnboardingError(
                f"{hooks_path} is not valid JSON; fix it before wiring AOI: {exc}"
            ) from exc
        if not isinstance(loaded, dict):
            raise CodexOnboardingError(
                f"{hooks_path} must contain a JSON object at the top level"
            )
        payload = loaded
    _merged_hooks, events_added, events_updated = _merge_codex_hook_settings_detailed(
        payload, command=command, command_windows=command_windows
    )
    return {
        "config_path": str(config_path),
        "config_changed": config_changed,
        "hooks_path": str(hooks_path),
        "events_to_add": events_added,
        "events_to_update": events_updated,
    }


_TABLE_HEADER = re.compile(r"^\s*\[([^\]]+)\]\s*(?:#.*)?$")
_HOOKS_ASSIGNMENT = re.compile(r"^(\s*)hooks\s*=\s*(true|false)(\s*(?:#.*)?)$", re.I)


def merge_codex_config_toml(text: str) -> tuple[str, bool]:
    """Enable stable Codex lifecycle hooks while preserving other TOML bytes."""

    try:
        parsed = tomllib.loads(text) if text.strip() else {}
    except tomllib.TOMLDecodeError as exc:
        raise CodexOnboardingError(f".codex/config.toml is not valid TOML: {exc}") from exc
    features = parsed.get("features", {})
    if not isinstance(features, dict):
        raise CodexOnboardingError(".codex/config.toml 'features' must be a TOML table")
    if features.get("hooks") is True:
        return text, False
    if "hooks" in features and not isinstance(features.get("hooks"), bool):
        raise CodexOnboardingError(".codex/config.toml features.hooks must be a boolean")

    lines = text.splitlines(keepends=True)
    feature_header: int | None = None
    feature_end = len(lines)
    for index, line in enumerate(lines):
        match = _TABLE_HEADER.match(line.rstrip("\r\n"))
        if not match:
            continue
        table = match.group(1).strip()
        if table == "features":
            feature_header = index
            continue
        if feature_header is not None and index > feature_header:
            feature_end = index
            break

    if feature_header is not None:
        for index in range(feature_header + 1, feature_end):
            raw = lines[index].rstrip("\r\n")
            match = _HOOKS_ASSIGNMENT.match(raw)
            if not match:
                continue
            newline = "\r\n" if lines[index].endswith("\r\n") else "\n"
            if not lines[index].endswith(("\n", "\r")):
                newline = ""
            lines[index] = f"{match.group(1)}hooks = true{match.group(3)}{newline}"
            break
        else:
            newline = "\r\n" if any(line.endswith("\r\n") for line in lines) else "\n"
            lines.insert(feature_header + 1, f"hooks = true{newline}")
        candidate = "".join(lines)
    else:
        # An inline ``features = {...}`` table cannot be safely extended without
        # reserializing the user's file and comments.
        if re.search(r"(?m)^\s*features\s*=", text):
            raise CodexOnboardingError(
                "inline 'features = {...}' cannot be merged safely; convert it to "
                "a [features] table and rerun"
            )
        separator = "" if not text or text.endswith(("\n", "\r")) else "\n"
        blank = "" if not text.strip() else "\n"
        candidate = f"{text}{separator}{blank}[features]\nhooks = true\n"

    try:
        verified = tomllib.loads(candidate)
    except tomllib.TOMLDecodeError as exc:
        raise CodexOnboardingError(
            f"generated .codex/config.toml would be invalid: {exc}"
        ) from exc
    if verified.get("features", {}).get("hooks") is not True:
        raise CodexOnboardingError("failed to enable Codex lifecycle hooks")
    return candidate, True


def install_codex_config(config_path: Path) -> dict[str, Any]:
    text = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    merged, changed = merge_codex_config_toml(text)
    if changed or not config_path.exists():
        _atomic_write_text(config_path, merged)
    return {
        "config_path": str(config_path),
        "hooks_feature_enabled": True,
        "changed": changed,
    }


def enable_aoi_codex_hooks_policy(text: str) -> tuple[str, bool]:
    """Flip only ``[hooks.codex].enabled`` in an already valid AOI profile."""

    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise CodexOnboardingError(f"aoi.toml is not valid TOML: {exc}") from exc
    hooks = parsed.get("hooks", {})
    codex = hooks.get("codex", {}) if isinstance(hooks, dict) else {}
    if isinstance(codex, dict) and codex.get("enabled") is True:
        return text, False
    if not isinstance(codex, dict) or codex.get("enabled") is not False:
        raise CodexOnboardingError(
            "aoi.toml must contain boolean [hooks.codex].enabled"
        )

    lines = text.splitlines(keepends=True)
    in_section = False
    for index, line in enumerate(lines):
        header = _TABLE_HEADER.match(line.rstrip("\r\n"))
        if header:
            in_section = header.group(1).strip() == "hooks.codex"
            continue
        if not in_section:
            continue
        match = re.match(
            r"^(\s*)enabled\s*=\s*false(\s*(?:#.*)?)$",
            line.rstrip("\r\n"),
            flags=re.I,
        )
        if not match:
            continue
        newline = "\r\n" if line.endswith("\r\n") else "\n"
        if not line.endswith(("\n", "\r")):
            newline = ""
        lines[index] = f"{match.group(1)}enabled = true{match.group(2)}{newline}"
        candidate = "".join(lines)
        verified = tomllib.loads(candidate)
        if verified.get("hooks", {}).get("codex", {}).get("enabled") is not True:
            break
        return candidate, True
    raise CodexOnboardingError(
        "could not safely locate [hooks.codex].enabled = false in aoi.toml"
    )


def preflight_codex_user_skill(
    skills_root: Path,
    skill_text: str,
    *,
    replace_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate a user-scope AOI skill install without changing it."""

    skills_root = skills_root.expanduser()
    if not skills_root.is_absolute():
        raise CodexOnboardingError(
            "Codex user skills root must be absolute; use $HOME/.agents/skills "
            "or pass the Codex host's explicit user-skill directory"
        )
    skill_path = skills_root / "aoi" / "SKILL.md"
    existing_text: str | None = None
    if skill_path.exists():
        try:
            existing_text = skill_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise CodexOnboardingError(f"cannot read {skill_path}: {exc}") from exc
    existing_sha256 = (
        hashlib.sha256(existing_text.encode("utf-8")).hexdigest()
        if existing_text is not None
        else None
    )
    normalized_replace = (replace_sha256 or "").strip().lower() or None
    if normalized_replace is not None and not re.fullmatch(
        r"[0-9a-f]{64}", normalized_replace
    ):
        raise CodexOnboardingError(
            "--replace-user-skill-sha256 must be exactly 64 hexadecimal characters"
        )
    changed = existing_text != skill_text
    if (
        existing_text is not None
        and changed
        and normalized_replace != existing_sha256
    ):
        raise CodexOnboardingError(
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


def install_codex_user_skill(
    skills_root: Path,
    skill_text: str,
    *,
    replace_sha256: str | None = None,
) -> dict[str, Any]:
    result = preflight_codex_user_skill(
        skills_root,
        skill_text,
        replace_sha256=replace_sha256,
    )
    if result["changed"]:
        _atomic_write_text(Path(result["skill_path"]), skill_text)
    result["updated"] = bool(result["changed"] and result["existing_sha256"] is not None)
    result["created"] = bool(result["changed"] and result["existing_sha256"] is None)
    return result


def register_codex_onboarding_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
) -> None:
    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "codex onboarding command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )
    parser = subparsers.add_parser("codex-init")
    parser.add_argument("--project-name")
    parser.add_argument(
        "--hook-command",
        default=HOOK_COMMAND,
        help="POSIX hook command; defaults to the installed aoi-codex-hook entry point",
    )
    parser.add_argument(
        "--hook-command-windows",
        help=(
            "optional Windows AOI hook command override; direct absolute paths "
            "and a narrow 'wsl [--exec] aoi-codex-hook ...' launcher are allowed"
        ),
    )
    parser.add_argument(
        "--user-skills-root",
        help=(
            "Codex user-scope skills directory; defaults to $HOME/.agents/skills "
            "on the host running AOI"
        ),
    )
    parser.add_argument(
        "--replace-user-skill-sha256",
        help="reviewed SHA-256 required to replace a differing user AOI skill",
    )
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["codex_init"])


__all__ = [
    "CODEX_HOOK_EVENTS",
    "CodexOnboardingError",
    "HOOK_COMMAND",
    "HOOK_TIMEOUT_SECONDS",
    "SESSION_START_MATCHER",
    "enable_aoi_codex_hooks_policy",
    "install_codex_config",
    "install_codex_hooks",
    "install_codex_user_skill",
    "is_aoi_codex_hook_command",
    "merge_codex_config_toml",
    "merge_codex_hook_settings",
    "preflight_codex_onboarding",
    "preflight_codex_user_skill",
    "register_codex_onboarding_commands",
]
