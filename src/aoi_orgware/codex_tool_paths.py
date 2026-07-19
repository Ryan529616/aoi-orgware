"""Strict, cooperative target parsing for the Codex PreToolUse claim gate.

This module deliberately recognizes only a small, stable subset of tools.  A
result marked ``ambiguous`` or ``unsupported`` is *not* evidence that a tool
operation stays inside AOI claims; callers must report it as uncovered.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
import re
import shlex
from typing import Any, Literal, Mapping

from .harnesslib import (
    RESERVING_CLAIM_STATUSES,
    HarnessPaths,
    claims_for_task,
    is_semantic_v2_task,
    lock_covers,
    normalize_lock,
    validate_persisted_lock_identity,
    validate_task_claim_references,
    validated_state_worktree,
)


ParseStatus = Literal["supported", "ambiguous", "unsupported"]
GateDecision = Literal["allow", "deny"]

UNSUPPORTED_TOOL = "uncovered_unknown_tool"
AMBIGUOUS_APPLY_PATCH = "uncovered_ambiguous_apply_patch"
AMBIGUOUS_SHELL = "uncovered_ambiguous_shell"
AMBIGUOUS_MCP = "uncovered_ambiguous_mcp"
UNSAFE_TARGET = "uncovered_unsafe_target"
MAPPING_MISSING = "uncovered_mapping_missing"
MAPPING_V2 = "uncovered_mapping_v2"
MAPPING_CORRUPT = "uncovered_mapping_corrupt"
CLAIMS_UNHEALTHY = "uncovered_claims_unhealthy"
TARGET_MISSING = "target_missing"
COVERED = "covered"

_PATCH_HEADER = re.compile(r"^\*\*\* (Add|Update|Delete) File: (.+)$")
_PATCH_MOVE = re.compile(r"^\*\*\* Move to: (.+)$")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_SHELL_UNSAFE = re.compile(r"[|&;<>`$*?\[\]{}()\r\n]")


@dataclass(frozen=True)
class ToolTargetResult:
    """Canonical parser output suitable for a receipt payload."""

    status: ParseStatus
    targets: tuple[str, ...] = ()
    reason: str = UNSUPPORTED_TOOL

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "targets": list(self.targets),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ClaimGateResult:
    """One honest cooperative-gate decision suitable for hook serialization."""

    decision: GateDecision
    covered: bool
    targets: tuple[str, ...]
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision,
            "covered": self.covered,
            "targets": list(self.targets),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class McpToolSchema:
    """An explicit top-level path-field schema for one registered MCP tool.

    ``path_fields`` maps an exact input field name to ``file`` or ``tree``.
    Nested values are intentionally unsupported: recursively discovering a key
    named ``path`` would make the registry meaningless.
    """

    path_fields: Mapping[str, Literal["file", "tree"]]


def _result(status: ParseStatus, reason: str, targets: list[str] | None = None) -> ToolTargetResult:
    return ToolTargetResult(status, tuple(sorted(set(targets or []))), reason)


def _repo_target(raw: object, *, kind: Literal["file", "tree"]) -> tuple[str | None, str | None]:
    """Return a canonical repo lock or a stable unsafe/ambiguous reason."""

    if not isinstance(raw, str) or not raw or raw != raw.strip() or "\x00" in raw:
        return None, UNSAFE_TARGET
    # Pathlib on a non-Windows host does not regard C:\\x as absolute.  Also
    # reject backslashes outright rather than silently interpreting platform
    # specific spelling as a different repo lock.
    if "\\" in raw or PurePosixPath(raw).is_absolute() or PureWindowsPath(raw).is_absolute() or _WINDOWS_DRIVE.match(raw):
        return None, UNSAFE_TARGET
    candidate = PurePosixPath(raw)
    if any(part in {"", ".", ".."} for part in candidate.parts):
        return None, UNSAFE_TARGET
    relative = candidate.as_posix()
    if relative == ".aoi" or relative.startswith(".aoi/"):
        return None, UNSAFE_TARGET
    try:
        return normalize_lock(f"repo:{kind}:{relative}"), None
    except Exception:
        return None, UNSAFE_TARGET


def parse_apply_patch_targets(patch: object) -> ToolTargetResult:
    """Parse standard Apply-Patch file headers, including a paired rename."""

    if not isinstance(patch, str) or not patch:
        return _result("ambiguous", AMBIGUOUS_APPLY_PATCH)
    lines = patch.splitlines()
    if len(lines) < 3 or lines[0] != "*** Begin Patch" or lines[-1] != "*** End Patch":
        return _result("ambiguous", AMBIGUOUS_APPLY_PATCH)
    targets: list[str] = []
    pending_update = False
    seen_header = False
    for line in lines[1:-1]:
        match = _PATCH_HEADER.fullmatch(line)
        if match:
            action, raw_path = match.groups()
            target, reason = _repo_target(raw_path, kind="file")
            if reason:
                return _result("ambiguous", reason)
            assert target is not None
            targets.append(target)
            pending_update = action == "Update"
            seen_header = True
            continue
        moved = _PATCH_MOVE.fullmatch(line)
        if moved:
            if not pending_update:
                return _result("ambiguous", AMBIGUOUS_APPLY_PATCH)
            target, reason = _repo_target(moved.group(1), kind="file")
            if reason:
                return _result("ambiguous", reason)
            assert target is not None
            targets.append(target)
            pending_update = False
            continue
        # Header-looking unknown directives are not patch body and cannot be
        # safely ignored.  Ordinary hunk/content lines may contain any text.
        if line.startswith("*** "):
            return _result("ambiguous", AMBIGUOUS_APPLY_PATCH)
    if not seen_header:
        return _result("ambiguous", AMBIGUOUS_APPLY_PATCH)
    return _result("supported", COVERED, targets)


def parse_shell_targets(command: object) -> ToolTargetResult:
    """Parse only one literal POSIX-style file operation with no shell syntax."""

    if not isinstance(command, str) or not command or command != command.strip():
        return _result("ambiguous", AMBIGUOUS_SHELL)
    if "'" in command or '"' in command or _SHELL_UNSAFE.search(command):
        return _result("ambiguous", AMBIGUOUS_SHELL)
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        return _result("ambiguous", AMBIGUOUS_SHELL)
    if not words or any(not word for word in words):
        return _result("ambiguous", AMBIGUOUS_SHELL)
    command_name = words[0]
    # These exact spellings are a deliberately small grammar.  Flags, command
    # aliases, PowerShell cmdlets/abbreviations, scripts, and interpreters are
    # all uncovered rather than guessed.
    expected: dict[str, tuple[int, tuple[Literal["file", "tree"], ...]]] = {
        "mkdir": (2, ("tree",)),
        "touch": (2, ("file",)),
        "remove": (2, ("file",)),
        "copy": (3, ("file", "file")),
        "move": (3, ("file", "file")),
    }
    grammar = expected.get(command_name)
    if grammar is None or len(words) != grammar[0] or any(word.startswith("-") for word in words[1:]):
        return _result("ambiguous", AMBIGUOUS_SHELL)
    targets: list[str] = []
    for raw_path, kind in zip(words[1:], grammar[1], strict=True):
        target, reason = _repo_target(raw_path, kind=kind)
        if reason:
            return _result("ambiguous", reason)
        assert target is not None
        targets.append(target)
    return _result("supported", COVERED, targets)


def parse_mcp_targets(
    tool_name: object,
    tool_input: object,
    registry: Mapping[str, McpToolSchema] | None,
) -> ToolTargetResult:
    """Parse only an exactly registered MCP tool and its declared fields."""

    if not isinstance(tool_name, str) or registry is None or tool_name not in registry:
        return _result("unsupported", UNSUPPORTED_TOOL)
    schema = registry[tool_name]
    if not isinstance(schema, McpToolSchema) or not isinstance(tool_input, dict):
        return _result("ambiguous", AMBIGUOUS_MCP)
    # Path-field registries are not complete mutation schemas.  An undeclared
    # input can carry a second path, rename, or delete instruction, so pure
    # registry parsing must treat it as ambiguous instead of calling it covered.
    if set(tool_input) != set(schema.path_fields):
        return _result("ambiguous", AMBIGUOUS_MCP)
    targets: list[str] = []
    for field, kind in schema.path_fields.items():
        if type(field) is not str or kind not in {"file", "tree"} or field not in tool_input:
            return _result("ambiguous", AMBIGUOUS_MCP)
        target, reason = _repo_target(tool_input[field], kind=kind)
        if reason:
            return _result("ambiguous", reason)
        assert target is not None
        targets.append(target)
    if not targets:
        return _result("ambiguous", AMBIGUOUS_MCP)
    return _result("supported", COVERED, targets)


def parse_codex_tool_targets(
    tool_name: object,
    tool_input: object,
    *,
    mcp_registry: Mapping[str, McpToolSchema] | None = None,
) -> ToolTargetResult:
    """Return canonical locks for one supported Codex mutation tool."""

    # Codex hook protocol v6 serializes both apply-patch and shell payloads
    # under the exact ``command`` field.  ``Bash`` is the canonical hook-facing
    # shell name; ``shell_command`` remains accepted only for older local
    # adapters so their evidence is not silently reclassified as MCP.
    if tool_name == "apply_patch":
        return parse_apply_patch_targets(
            tool_input.get("command") if isinstance(tool_input, dict) else None
        )
    if tool_name in {"Bash", "shell_command"}:
        return parse_shell_targets(tool_input.get("command") if isinstance(tool_input, dict) else None)
    return parse_mcp_targets(tool_name, tool_input, mcp_registry)


def claim_gate_decision(
    paths: HarnessPaths,
    state: Mapping[str, Any],
    parsed: ToolTargetResult,
    *,
    mapping_status: str,
    mapping_task_id: str | None,
) -> ClaimGateResult:
    """Apply strict task/claim health checks to a parsed target set.

    Only a legacy, exact valid task mapping and healthy, reserving claims can
    yield ``covered=True``.  All weaker states allow execution but are marked
    uncovered; an otherwise healthy task with a missing target is denied.
    """

    targets = parsed.targets
    if parsed.status != "supported":
        return ClaimGateResult("allow", False, targets, parsed.reason)
    task_id = state.get("task_id")
    if mapping_status == "v2" or (isinstance(task_id, str) and is_semantic_v2_task(paths, task_id)):
        return ClaimGateResult("allow", False, targets, MAPPING_V2)
    if mapping_status != "valid" or not isinstance(task_id, str) or mapping_task_id is None:
        reason = MAPPING_MISSING if mapping_status in {"", "unbound", "missing"} else MAPPING_CORRUPT
        return ClaimGateResult("allow", False, targets, reason)
    if mapping_task_id != task_id:
        return ClaimGateResult("allow", False, targets, MAPPING_CORRUPT)
    try:
        validate_task_claim_references(paths, dict(state))
        repo_root = validated_state_worktree(paths, dict(state))
        held: list[str] = []
        # Validate below with the exact task worktree rather than the harness
        # root default, which may differ for a bound task.
        for claim in claims_for_task(paths, dict(state), validate_reserving=False):
            if claim.get("status") not in RESERVING_CLAIM_STATUSES:
                continue
            held.extend(
                validate_persisted_lock_identity(paths, str(lock), repo_root=repo_root)
                for lock in claim.get("locks", [])
            )
    except Exception:
        return ClaimGateResult("allow", False, targets, CLAIMS_UNHEALTHY)
    if all(any(lock_covers(owner, target) for owner in held) for target in targets):
        return ClaimGateResult("allow", True, targets, COVERED)
    return ClaimGateResult("deny", False, targets, TARGET_MISSING)


__all__ = [
    "AMBIGUOUS_APPLY_PATCH",
    "AMBIGUOUS_MCP",
    "AMBIGUOUS_SHELL",
    "CLAIMS_UNHEALTHY",
    "COVERED",
    "ClaimGateResult",
    "MAPPING_CORRUPT",
    "MAPPING_MISSING",
    "MAPPING_V2",
    "McpToolSchema",
    "TARGET_MISSING",
    "ToolTargetResult",
    "UNSAFE_TARGET",
    "UNSUPPORTED_TOOL",
    "claim_gate_decision",
    "parse_apply_patch_targets",
    "parse_codex_tool_targets",
    "parse_mcp_targets",
    "parse_shell_targets",
]
