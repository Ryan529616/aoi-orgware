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
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
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


def _entry_carries_aoi_hook(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    for hook in entry.get("hooks", []):
        if not isinstance(hook, dict):
            continue
        command = str(hook.get("command", "")).strip()
        if command == HOOK_COMMAND or command.split(" ", 1)[:1] == [HOOK_COMMAND_HEAD]:
            return True
    return False


def merge_claude_hook_settings(settings: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Return ``(new_settings, events_added)``.

    Idempotent and non-destructive: existing hooks and unrelated settings are
    preserved, and an event already carrying an ``aoi-claude-hook`` entry is
    left untouched.
    """

    merged: dict[str, Any] = dict(settings)
    raw_hooks = merged.get("hooks")
    hooks: dict[str, Any] = dict(raw_hooks) if isinstance(raw_hooks, dict) else {}
    added: list[str] = []
    for event in CLAUDE_HOOK_EVENTS:
        existing = hooks.get(event)
        entries = list(existing) if isinstance(existing, list) else []
        if any(_entry_carries_aoi_hook(entry) for entry in entries):
            hooks[event] = entries
            continue
        entries.append(_aoi_hook_entry(event))
        hooks[event] = entries
        added.append(event)
    merged["hooks"] = hooks
    return merged, added


def install_claude_hooks(
    settings_path: Path,
    *,
    governed_agent_types: str | None = None,
) -> dict[str, Any]:
    """Merge the AOI hooks into ``settings_path`` (creating it if needed)."""

    settings: dict[str, Any] = {}
    if settings_path.exists():
        try:
            loaded = json.loads(settings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ClaudeOnboardingError(
                f"{settings_path} is not valid JSON; fix or remove it before wiring AOI: {exc}"
            ) from exc
        if not isinstance(loaded, dict):
            raise ClaudeOnboardingError(
                f"{settings_path} must contain a JSON object at the top level"
            )
        settings = loaded

    merged, added = merge_claude_hook_settings(settings)
    if governed_agent_types:
        raw_env = merged.get("env")
        env = dict(raw_env) if isinstance(raw_env, dict) else {}
        env[GOVERNED_AGENT_TYPES_ENV] = governed_agent_types
        merged["env"] = env

    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(
        json.dumps(merged, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    already_present = [event for event in CLAUDE_HOOK_EVENTS if event not in added]
    return {
        "settings_path": str(settings_path),
        "events_added": added,
        "events_already_present": already_present,
        "hook_command": HOOK_COMMAND,
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
    result["updated"] = result["existing_sha256"] is not None
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
    "register_claude_onboarding_commands",
    "preflight_claude_user_skill",
]
