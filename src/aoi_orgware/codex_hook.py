#!/usr/bin/env python3
"""Tiny, fail-open, opt-in Codex hook adapter for AOI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any

from .agent_identity import validate_agent_id
from .harnesslib import get_paths, is_semantic_v2_task


SUPPORTED_HOOK_VERSION = "6"
SAFE_DISPLAY_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
SAFE_TASK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
HOOK_INPUT_MAX_BYTES = 64 * 1024
ROOT_SESSION_MAPPING_KIND = "root"
SUBAGENT_PARENT_MAPPING_KIND = "subagent_parent"
STARTUP_RECEIPT_WARNING = (
    "Fresh-session registration is unavailable until a valid startup. "
)
PRETOOL_FAIL_CLOSED_DENY_MESSAGE = "AOI receipt store unavailable; PreToolUse is denied."
# Kept as a compatibility alias for callers that previously named only the
# receipt-store failure.  Every internal PreToolUse fault now shares this exact
# non-diagnostic denial.
RECEIPT_STORE_DENY_MESSAGE = PRETOOL_FAIL_CLOSED_DENY_MESSAGE


def root_path() -> Path:
    return get_paths().root


def read_input() -> dict[str, Any]:
    payload = sys.stdin.buffer.read(HOOK_INPUT_MAX_BYTES + 1)
    if len(payload) > HOOK_INPUT_MAX_BYTES:
        raise ValueError("hook payload exceeds the supported size")
    raw = payload.decode("utf-8-sig")
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("hook payload has a duplicate JSON field")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise ValueError(f"hook payload has non-finite JSON number: {value}")

    value = json.loads(
        raw or "{}",
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
    return value if isinstance(value, dict) else {}


def write_output(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, ensure_ascii=False) + "\n")


def allow() -> None:
    write_output({"continue": True})


def exact_payload_string(payload: dict[str, Any], key: str) -> str:
    """Return an exact JSON string without coercing another type into authority."""

    value = payload.get(key)
    return value if type(value) is str else ""


def _json_sha256(value: Any) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(raw) > HOOK_INPUT_MAX_BYTES:
        raise ValueError("hook observation exceeds the supported size")
    return hashlib.sha256(raw).hexdigest()


def _observation(value: Any) -> dict[str, str | None]:
    if value is None:
        return {"status": "missing", "value": None}
    if type(value) is not str:
        return {"status": "invalid_type", "value": None}
    if not value or len(value) > 4096 or "\x00" in value:
        return {"status": "unsafe", "value": None}
    return {"status": "observed", "value": value}


def _tool_event_identity(payload: dict[str, Any]) -> dict[str, str]:
    session_id = exact_payload_string(payload, "session_id")
    turn_id = exact_payload_string(payload, "turn_id")
    tool_use_id = exact_payload_string(payload, "tool_use_id")
    if not all((session_id, turn_id, tool_use_id)):
        raise ValueError("tool hook identity is incomplete")
    return {
        "session_id": session_id,
        "turn_id": turn_id,
        "tool_use_id": tool_use_id,
    }


def _stop_event_identity(
    payload: dict[str, Any], *, strict_agent_id: bool = True
) -> dict[str, str]:
    session_id = exact_payload_string(payload, "session_id")
    turn_id = exact_payload_string(payload, "turn_id")
    agent_id = exact_payload_string(payload, "agent_id")
    if not all((session_id, turn_id, agent_id)):
        raise ValueError("subagent stop identity is incomplete")
    if strict_agent_id:
        agent_id = validate_agent_id(agent_id, "subagent stop agent_id")
    return {
        "session_id": session_id,
        "turn_id": turn_id,
        "agent_id": agent_id,
        # SubagentStop has no separate event id.  One child turn emits its stop
        # lifecycle event under the observed turn id.
        "event_id": turn_id,
    }


def _semantic_v2_mapping(
    root: Path, session_id: str
) -> tuple[str, tuple[dict[str, Any], Path] | None]:
    """Recognize only an exact v2 session mapping without reading state.json."""

    if not session_id or len(session_id) > 512 or "\x00" in session_id:
        return "corrupt", None
    paths = get_paths(root)
    key = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    mapping_path = paths.sessions / f"{key}.json"
    try:
        mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
        if not isinstance(mapping, dict) or mapping.get("session_id") != session_id:
            return "corrupt", None
        task_id = mapping.get("task_id")
        if type(task_id) is not str or not SAFE_TASK_ID.fullmatch(task_id):
            return "corrupt", None
        task_dir = paths.tasks / task_id
        if not is_semantic_v2_task(paths, task_id):
            return "corrupt", None
        if mapping.get("mapping_kind", ROOT_SESSION_MAPPING_KIND) not in {
            ROOT_SESSION_MAPPING_KIND,
            SUBAGENT_PARENT_MAPPING_KIND,
        }:
            return "corrupt", None
        return "v2", ({"task_id": task_id}, task_dir)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return "corrupt", None


def tool_session_state(
    root: Path, session_id: str
) -> tuple[str, tuple[dict[str, Any], Path] | None]:
    status, mapped = session_state(root, session_id)
    if status != "corrupt":
        return status, mapped
    return _semantic_v2_mapping(root, session_id)


def _mapping_observation(
    status: str, mapped: tuple[dict[str, Any], Path] | None
) -> dict[str, Any]:
    if status in {"valid", "subagent_parent", "v2"} and mapped:
        task_id = mapped[0].get("task_id")
        if type(task_id) is str and task_id:
            return {
                "status": "mapped",
                "task_id": {"status": "observed", "value": task_id},
            }
    if status == "unbound":
        return {
            "status": "missing",
            "task_id": {"status": "missing", "value": None},
        }
    return {
        "status": "mismatch",
        "task_id": {"status": "unsafe", "value": None},
    }


def _claim_snapshot_observation(
    paths: Any,
    status: str,
    mapped: tuple[dict[str, Any], Path] | None,
) -> dict[str, str | None]:
    if status != "valid" or mapped is None:
        return {"status": "missing", "value": None}
    try:
        from .harnesslib import claims_for_task

        claims = claims_for_task(paths, mapped[0], validate_reserving=False)
        return {"status": "observed", "value": _json_sha256(claims)}
    except Exception:
        return {"status": "unsafe", "value": None}


def _is_direct_aoi_path(value: str) -> bool:
    normalized = value.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized == ".aoi" or normalized.startswith(".aoi/")


def _direct_aoi_targets(tool_name: str, tool_input: Any) -> tuple[str, ...]:
    """Return exact direct AOI-state mutation targets for a mandatory deny."""

    if not isinstance(tool_input, dict):
        return ()
    command = tool_input.get("command")
    if type(command) is not str or not command:
        return ()
    raw_targets: list[str] = []
    if tool_name == "apply_patch":
        for line in command.splitlines():
            match = re.fullmatch(r"\*\*\* (?:Add|Update|Delete) File: (.+)", line)
            moved = re.fullmatch(r"\*\*\* Move to: (.+)", line)
            raw = match.group(1) if match else moved.group(1) if moved else ""
            if raw and _is_direct_aoi_path(raw):
                raw_targets.append(raw.replace("\\", "/"))
    elif tool_name in {"Bash", "shell_command"}:
        if any(character in command for character in "\r\n;&|<>`$*?[]{}()"):
            return ()
        try:
            words = shlex.split(command, posix=True)
        except ValueError:
            return ()
        mutators = {
            "mkdir",
            "touch",
            "rm",
            "remove",
            "cp",
            "copy",
            "mv",
            "move",
            "new-item",
            "remove-item",
            "copy-item",
            "move-item",
            "set-content",
            "add-content",
            "out-file",
        }
        if words and words[0].lower() in mutators:
            raw_targets.extend(
                word.replace("\\", "/")
                for word in words[1:]
                if not word.startswith("-") and _is_direct_aoi_path(word)
            )
    return tuple(sorted({f"repo:file:{target}" for target in raw_targets}))


def _pretool_receipt(
    root: Path, payload: dict[str, Any]
) -> tuple[dict[str, Any], str]:
    from .codex_adapter_contracts import (
        CODEX_PRETOOL_CLAIM_DECISION_V1,
        seal_codex_pretool_claim_decision_receipt,
    )
    from .codex_tool_paths import claim_gate_decision, parse_codex_tool_targets

    identity = _tool_event_identity(payload)
    tool_name = exact_payload_string(payload, "tool_name")
    if not tool_name:
        raise ValueError("PreToolUse tool_name is incomplete")
    tool_input = payload.get("tool_input")
    input_sha256 = _json_sha256(tool_input)
    paths = get_paths(root)
    mapping_status, mapped = tool_session_state(root, identity["session_id"])
    direct_aoi = _direct_aoi_targets(tool_name, tool_input)
    parsed = parse_codex_tool_targets(tool_name, tool_input)
    if direct_aoi:
        decision = "deny"
        coverage = "unclaimed"
        targets = list(direct_aoi)
        reason = "direct_aoi_state_mutation_denied"
    else:
        state = mapped[0] if mapped else {}
        gate = claim_gate_decision(
            paths,
            state,
            parsed,
            mapping_status=mapping_status,
            mapping_task_id=(
                state.get("task_id") if type(state.get("task_id")) is str else None
            ),
        )
        decision = gate.decision
        coverage = (
            "covered"
            if gate.covered
            else "unclaimed"
            if gate.decision == "deny"
            else "uncovered"
        )
        targets = list(gate.targets)
        reason = gate.reason
    receipt = seal_codex_pretool_claim_decision_receipt(
        {
            "receipt_type": CODEX_PRETOOL_CLAIM_DECISION_V1,
            "event_identity": identity,
            "tool_name": tool_name,
            "input_sha256": input_sha256,
            "parser": {"id": "aoi-codex-tool-targets", "version": "1"},
            "targets": sorted(targets),
            "session_mapping": _mapping_observation(mapping_status, mapped),
            "claim_snapshot_sha256": _claim_snapshot_observation(
                paths, mapping_status, mapped
            ),
            "claim_coverage": coverage,
            "decision": decision,
            "provider_verification": "unavailable",
            "profile_verification": "unavailable",
            "sandbox_verification": "unavailable",
        }
    )
    return receipt, reason


def _deny_pretool_fail_closed() -> None:
    """Emit the sole non-diagnostic response for an internal PreToolUse fault."""

    write_output(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": PRETOOL_FAIL_CLOSED_DENY_MESSAGE,
            }
        }
    )


def pre_tool_use(root: Path, payload: dict[str, Any]) -> None:
    from .codex_hook_receipts import store_codex_hook_receipt

    try:
        # Identity extraction, receipt sealing/schema validation, target parsing,
        # claim resolution, and durable storage are one cooperative permission
        # boundary.  No internal failure may be reclassified as an allow.
        receipt, reason = _pretool_receipt(root, payload)
        store_codex_hook_receipt(get_paths(root), receipt)
    except Exception:
        _deny_pretool_fail_closed()
        return
    if receipt["decision"] == "deny":
        write_output(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        "AOI cooperative claim gate denied this exact target "
                        f"({reason})."
                    ),
                }
            }
        )
        return
    allow()


def post_tool_use(root: Path, payload: dict[str, Any]) -> None:
    from .codex_adapter_contracts import (
        CODEX_POSTTOOL_MUTATION_OBSERVATION_V1,
        CODEX_PRETOOL_CLAIM_DECISION_V1,
        seal_codex_posttool_mutation_observation_receipt,
    )
    from .codex_hook_receipts import (
        load_codex_hook_receipt_by_identity,
        store_codex_hook_receipt,
    )

    identity = _tool_event_identity(payload)
    paths = get_paths(root)
    pre = load_codex_hook_receipt_by_identity(
        paths,
        receipt_type=CODEX_PRETOOL_CLAIM_DECISION_V1,
        event_identity=identity,
    )
    input_sha256 = _json_sha256(payload.get("tool_input"))
    if pre["input_sha256"] != input_sha256:
        raise ValueError("PostToolUse input differs from its PreToolUse receipt")
    receipt = seal_codex_posttool_mutation_observation_receipt(
        {
            "receipt_type": CODEX_POSTTOOL_MUTATION_OBSERVATION_V1,
            "event_identity": identity,
            "pre_receipt_sha256": pre["receipt_sha256"],
            "input_sha256": input_sha256,
            "response_sha256": _json_sha256(payload.get("tool_response")),
            "targets": pre["targets"],
            # Codex emits PostToolUse only after the tool produced a successful
            # output.  This observes completion, not a verified filesystem diff.
            "tool_completion_observed": True,
            "mutation_effect_verified": {"status": "unavailable"},
        }
    )
    store_codex_hook_receipt(paths, receipt)
    allow()


def subagent_stop(root: Path, payload: dict[str, Any]) -> None:
    if payload.get("stop_hook_active") is True:
        allow()
        return
    from .codex_adapter_contracts import (
        CODEX_SUBAGENT_STOP_V1,
        seal_codex_subagent_stop_receipt,
    )
    from .codex_hook_receipts import (
        CodexHookReceiptError,
        load_codex_hook_receipt_by_identity,
        store_codex_hook_receipt,
    )
    from .harnesslib import now_iso

    lookup_identity = _stop_event_identity(payload, strict_agent_id=False)
    transcript = payload.get("agent_transcript_path")
    if transcript is None:
        transcript = payload.get("transcript_path")
    message = payload.get("last_assistant_message")
    last_message: dict[str, dict[str, str | None]]
    if type(message) is str:
        raw_message = message.encode("utf-8")
        last_message = {
            "sha256": {
                "status": "observed",
                "value": hashlib.sha256(raw_message).hexdigest(),
            },
            "size_bytes": {"status": "observed", "value": str(len(raw_message))},
            "presence": {"status": "observed", "value": "present"},
        }
    elif message is None:
        last_message = {
            "sha256": {"status": "missing", "value": None},
            "size_bytes": {"status": "missing", "value": None},
            "presence": {"status": "observed", "value": "absent"},
        }
    else:
        last_message = {
            "sha256": {"status": "invalid_type", "value": None},
            "size_bytes": {"status": "invalid_type", "value": None},
            "presence": {"status": "invalid_type", "value": None},
        }
    paths = get_paths(root)
    observations = {
        "transcript_path_observation": _observation(transcript),
        "last_assistant_message": last_message,
        "model_observation": _observation(payload.get("model")),
        "permission_mode_observation": _observation(payload.get("permission_mode")),
        # v0.3 start observations are not sealed O6 adapter receipts.  Do not
        # relabel their digest as a start receipt merely to claim a stronger
        # correlation than the available platform evidence.
        "start_correlation": {
            "status": "missing",
            "start_receipt_sha256": {"status": "missing", "value": None},
        },
        "no_material_work_verified": False,
    }
    try:
        existing = load_codex_hook_receipt_by_identity(
            paths,
            receipt_type=CODEX_SUBAGENT_STOP_V1,
            event_identity=lookup_identity,
        )
    except CodexHookReceiptError as exc:
        if "missing" not in str(exc):
            raise
    else:
        if all(existing.get(key) == value for key, value in observations.items()):
            allow()
            return
        raise CodexHookReceiptError(
            "SubagentStop replay has divergent observations for one event identity"
        )
    # Existing v1 receipt lookup deliberately uses the original identity
    # grammar.  Only a genuinely new receipt adopts the current shared agent
    # identity contract.
    identity = _stop_event_identity(payload)
    receipt = seal_codex_subagent_stop_receipt(
        {
            "receipt_type": CODEX_SUBAGENT_STOP_V1,
            "event_identity": identity,
            "observed_at": now_iso(),
            **observations,
        }
    )
    store_codex_hook_receipt(paths, receipt)
    allow()


def session_state(
    root: Path, session_id: str
) -> tuple[str, tuple[dict[str, Any], Path] | None]:
    if not session_id:
        return "unbound", None
    if len(session_id) > 512 or "\x00" in session_id:
        return "corrupt", None
    paths = get_paths(root)
    key = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    mapping_path = paths.sessions / f"{key}.json"
    if not mapping_path.exists():
        return "unbound", None
    try:
        mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
        if not isinstance(mapping, dict) or mapping.get("session_id") != session_id:
            return "corrupt", None
        task_id = str(mapping.get("task_id", ""))
        if not SAFE_TASK_ID.fullmatch(task_id):
            return "corrupt", None
        task_dir = paths.tasks / task_id
        # Semantic-v2 task initialization cannot bind a session. The legacy hook
        # reader must not treat state.json as authority or bypass ledger replay.
        if is_semantic_v2_task(paths, task_id):
            return "corrupt", None
        state_path = task_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if not isinstance(state, dict) or state.get("task_id") != task_id:
            return "corrupt", None
        mapping_kind = mapping.get("mapping_kind", ROOT_SESSION_MAPPING_KIND)
        if mapping_kind == ROOT_SESSION_MAPPING_KIND:
            session_ids = state.get("session_ids")
            if not isinstance(session_ids, list) or session_id not in session_ids:
                return "corrupt", None
            return "valid", (state, task_dir)
        if mapping_kind == SUBAGENT_PARENT_MAPPING_KIND:
            parent_ids = state.get("subagent_parent_session_ids")
            packets = state.get("packets")
            if (
                not isinstance(parent_ids, list)
                or session_id not in parent_ids
                or not isinstance(packets, list)
            ):
                return "corrupt", None
            matches = [
                packet
                for packet in packets
                if isinstance(packet, dict)
                and packet.get("packet_id") == mapping.get("packet_id")
                and packet.get("agent_id") == session_id
                and packet.get("delegation_depth", 1) == 1
            ]
            if len(matches) != 1:
                return "corrupt", None
            return "subagent_parent", (state, task_dir)
        return "corrupt", None
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return "corrupt", None


def session_start(root: Path, payload: dict[str, Any]) -> None:
    raw_session_id = payload.get("session_id")
    session_id = exact_payload_string(payload, "session_id")
    raw_source = payload.get("source")
    source = exact_payload_string(payload, "source")
    mapping_status, mapped = session_state(root, session_id)
    paths = get_paths(root)
    base = (
        f"AOI is active for {paths.project.name!r} at {paths.root}. Read "
        f"{paths.harness / 'POLICY.md'} and the short {paths.index}. Root alone "
        "writes AOI state; use bounded sub-agent packets. This hook is a "
        "procedural guardrail, not a security boundary. "
    )
    if mapping_status == "subagent_parent" and mapped:
        state, _ = mapped
        packet = next(
            item
            for item in state.get("packets", [])
            if isinstance(item, dict) and item.get("agent_id") == session_id
        )
        context = (
            base
            + f"This is the bounded depth-one agent for task {state.get('task_id')}, "
            + f"packet {packet.get('packet_id')} at {packet.get('path')}. This mapping "
            + "permits nested SubagentStart lookup only; it is not Chief/root authority. "
            + "Stay inside the packet, do not mutate AOI state, and do not reuse this "
            + "session for unrelated work. "
        )
    elif mapping_status == "valid" and mapped:
        state, task_dir = mapped
        checkpoint = task_dir / "checkpoint.md"
        status = state.get("status")
        phase = state.get("phase")
        revision = state.get("revision")
        checkpoint_revision = state.get("checkpoint_revision")
        if status not in {"active", "blocked", "done", "cancelled"}:
            status = "unknown"
        if phase not in {
            "planning",
            "gathering",
            "diagnosing",
            "implementing",
            "waiting_external",
            "verifying",
            "reviewing",
            "closing",
        }:
            phase = "unknown"
        if not isinstance(revision, int):
            revision = "unknown"
        if not isinstance(checkpoint_revision, int):
            checkpoint_revision = "unknown"
        context = (
            base
            + f"This session is bound to task {state.get('task_id')} "
            + f"({status}/{phase}, state revision "
            + f"{revision}, checkpoint revision "
            + f"{checkpoint_revision}). Read {checkpoint} and run "
            + f"aoi resume --task "
            + f"{state.get('task_id')} before continuing. "
        )
        if source in {"resume", "compact"}:
            context += (
                "This is a resume/compaction boundary: reconstruct from the "
                "task checkpoint and current files, not from conversational memory. "
            )
    elif mapping_status == "corrupt":
        context = (
            base
            + "This session has a corrupt or inconsistent harness mapping. Do not "
            + "perform material work until root runs harness doctor and explicitly "
            + "repairs or rebinds the session. The hook is a procedural guardrail, "
            + "not a filesystem sandbox. "
        )
    else:
        display_id = session_id if SAFE_DISPLAY_ID.fullmatch(session_id) else ""
        context = (
            base
            + "No unambiguous task mapping exists for this session. Before any "
            + "material edit or external action, resume or initialize exactly one task "
            + "and bind this session. "
        )
        if display_id:
            context += (
                "After selecting the task, run "
                + "aoi bind-session --task "
                + f"<task-id> --session-id {display_id}. "
            )
    # The Codex SessionStart command input has no trustworthy event timestamp.
    # Create the timestamp locally, then let the receipt store snapshot managed
    # project resource bytes under the AOI state lock.  This remains independent
    # of task/session mapping state and never claims that Codex loaded a model,
    # provider route, or runtime profile.
    if type(raw_source) is str and raw_source == "startup":
        try:
            raw_cwd = payload.get("cwd")
            if type(raw_session_id) is not str or type(raw_cwd) is not str:
                raise ValueError("startup receipt input is incomplete")
            # Keep the receipt store optional and startup-only.  A failure here
            # must not change the established fail-open SessionStart context.
            from .harnesslib import now_iso
            from .session_receipts import persist_startup_receipt

            persist_startup_receipt(
                paths,
                {
                    "schema_version": 2,
                    "hook_protocol_version": 6,
                    "session_id": raw_session_id,
                    "source": raw_source,
                    "observed_at": now_iso(),
                    "cwd": raw_cwd,
                    "project_root": str(paths.root),
                    "aoi_config_sha256": paths.project.sha256,
                },
            )
        except Exception:
            # Do not reveal filesystem/configuration details through a hook
            # response.  The fixed warning is intentionally bounded and lets
            # the normal SessionStart context remain useful.
            context += STARTUP_RECEIPT_WARNING
    write_output(
        {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": context,
            }
        }
    )


def subagent_start(root: Path, payload: dict[str, Any]) -> None:
    agent_type = str(payload.get("agent_type", "subagent"))
    if not SAFE_DISPLAY_ID.fullmatch(agent_type):
        agent_type = "subagent"
    paths = get_paths(root)
    # Import lazily so ordinary hook startup remains tiny and bytecode-free.
    from .cli import observe_subagent_start

    outcome = observe_subagent_start(paths, payload)
    status = outcome.get("status")
    if status == "authorized" and outcome.get("resumed"):
        context = (
            f"AOI observed a resumed dispatch of an existing packet thread for "
            f"{paths.project.name!r}: task={outcome.get('task_id')}, "
            f"packet={outcome.get('packet_id')}, contract={outcome.get('packet_path')}. "
            f"This is the same packet agent resuming (Codex transport "
            f"agent_type={agent_type}), not a fresh dispatch: stay inside the original "
            f"packet contract scope and do not edit {paths.harness}."
        )
    elif status == "authorized" and outcome.get("helper"):
        remaining = outcome.get("remaining_helper_budget")
        context = (
            f"AOI authorized a budgeted depth-two helper under parent packet "
            f"{outcome.get('packet_id')} for {paths.project.name!r} "
            f"(remaining helper budget={remaining}). This is bounded read-only support: "
            "your output is the parent agent's working material, NOT independent packet "
            f"evidence. Do not mutate AOI state under {paths.harness}, do not spawn "
            "further sub-agents, and report a bounded conclusion to the parent agent."
        )
    elif status == "authorized":
        context = (
            f"AOI observed a valid pre-armed dispatch for {paths.project.name!r}: "
            f"task={outcome.get('task_id')}, packet={outcome.get('packet_id')}, "
            f"contract={outcome.get('packet_path')}. Codex transport "
            f"agent_type={agent_type}; the AOI technical role is defined by the packet "
            "contract. Read that exact packet before work and stay inside its scope. "
            "The root owns AOI state, "
            f"claims, plan, checkpoint, and final completion; do not edit {paths.harness}. "
            "Return a bounded conclusion with exact evidence/artifact paths, files inspected "
            "or changed, verification, unresolved risks, and one next action; never paste raw logs."
        )
    elif status == "incident":
        context = (
            "AOI observed this sub-agent start without one valid, unique pre-armed packet. "
            f"Incident={outcome.get('incident_id')}; reason={outcome.get('reason_code')}. "
            "The start already occurred and this hook cannot terminate it. Stop without "
            "material work, do not inspect or edit project files, and report the incident id "
            "to the parent so the Chief can account it explicitly."
        )
    elif status == "corrupt":
        context = (
            "AOI could not validate the parent task mapping or packet authority for this "
            f"start; reason={outcome.get('reason_code')}. Stop without material work and "
            "report the corrupt authority to the parent. This hook observes starts but "
            "cannot terminate an already-created sub-agent."
        )
    else:
        context = (
            "AOI found no task mapping for the parent session, so it could not consume a "
            "packet arm or persist a task incident. Stop without material work and ask the "
            "parent to bind a task and arm an exact packet before retrying."
        )
    if outcome.get("index_refresh_deferred") is True:
        context += (
            " AOI committed the target task event but deferred the derived INDEX refresh; "
            "report this to the parent so the Chief can run doctor/status."
        )
    if outcome.get("parent_mapping_deferred") is True:
        context += (
            " AOI could not publish this depth-one agent's parent-only mapping; do not "
            "spawn a child and report the condition to the Chief."
        )
    write_output(
        {
            "hookSpecificOutput": {
                "hookEventName": "SubagentStart",
                "additionalContext": context,
            }
        }
    )


def user_prompt_submit(root: Path, payload: dict[str, Any]) -> None:
    session_id = exact_payload_string(payload, "session_id")
    mapping_status, mapped = session_state(root, session_id)
    base = (
        "AOI per-turn check: substantial implementation/document/evidence "
        "work requires one approved plan, explicit claims, bounded packets, and a "
        "semantic checkpoint. Trivial read-only answers do not require a task. "
    )
    if mapping_status == "subagent_parent" and mapped:
        state, _ = mapped
        packet = next(
            item
            for item in state.get("packets", [])
            if isinstance(item, dict) and item.get("agent_id") == session_id
        )
        context = (
            base
            + f"Continue only bounded packet {packet.get('packet_id')} for task "
            + f"{state.get('task_id')}. This parent-only mapping is not Chief/root "
            + "authority; do not mutate AOI lifecycle state."
        )
    elif mapping_status == "unbound":
        context = (
            base
            + "This session is not bound to a valid harness task. Before any material "
            "mutation or external launch, initialize/resume and bind exactly one task. "
            "Read-only work requires no task; do not add lifecycle boilerplate unless "
            "it is relevant to the user's request."
        )
    elif mapping_status == "corrupt":
        context = (
            base
            + "This session has a corrupt or inconsistent harness mapping. Do not "
            + "perform material work until root runs harness doctor and explicitly "
            + "repairs or rebinds the session."
        )
    else:
        assert mapped is not None
        state, task_dir = mapped
        status = state.get("status")
        if status in {"done", "cancelled"}:
            context = (
                base
                + f"The mapped task {state.get('task_id')} is {status}. Do not reuse its "
                "closed lifecycle for new material work; initialize/resume another task "
                "and rebind this session."
            )
        else:
            context = (
                base
                + f"Continue task {state.get('task_id')} and reconstruct from "
                + f"{task_dir / 'checkpoint.md'} plus current files."
            )
    write_output(
        {
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": context,
            }
        }
    )


def stop(root: Path, payload: dict[str, Any]) -> None:
    if payload.get("stop_hook_active") is True:
        allow()
        return
    session_id = exact_payload_string(payload, "session_id")
    mapping_status, mapped = session_state(root, session_id)
    if mapping_status == "subagent_parent":
        allow()
        return
    if mapping_status == "unbound":
        allow()
        return
    if mapping_status == "corrupt" or mapped is None:
        write_output(
            {
                "decision": "block",
                "reason": (
                    "AOI session mapping is corrupt or inconsistent. Run `aoi doctor` "
                    "and explicitly repair or rebind the session before stopping."
                ),
            }
        )
        return
    state, _ = mapped
    try:
        revision = int(state["revision"])
        checkpoint_revision = int(state["checkpoint_revision"])
        required = state["checkpoint_required"]
        status = state["status"]
    except (KeyError, TypeError, ValueError):
        write_output(
            {
                "decision": "block",
                "reason": "AOI task state is malformed; run harness doctor before stopping.",
            }
        )
        return
    if not isinstance(required, bool):
        write_output(
            {
                "decision": "block",
                "reason": "AOI task state is malformed; run harness doctor before stopping.",
            }
        )
        return
    if status in {"done", "cancelled"}:
        write_output(
            {
                "decision": "block",
                "reason": (
                    f"This session is still mapped to closed AOI task {state.get('task_id')}. "
                    "For read-only follow-up, state that explicitly; for new material work, "
                    "initialize/resume a task and rebind before stopping."
                ),
            }
        )
        return
    if status not in {"active", "blocked"}:
        write_output(
            {
                "decision": "block",
                "reason": "AOI task status is invalid; run harness doctor before stopping.",
            }
        )
        return
    checkpoint = get_paths(root).tasks / state["task_id"] / "checkpoint.md"
    expected_hash = state.get("checkpoint_sha256")
    try:
        actual_hash = hashlib.sha256(checkpoint.read_bytes()).hexdigest()
    except OSError:
        actual_hash = "missing"
    if (
        required
        or checkpoint_revision != revision
        or not isinstance(expected_hash, str)
        or actual_hash != expected_hash
    ):
        task_id = state["task_id"]
        write_output(
            {
                "decision": "block",
                "reason": (
                    f"AOI task {task_id} has stale semantic state "
                    f"(state rev {revision}, checkpoint rev {checkpoint_revision}, "
                    f"required={str(required).lower()}, file_hash_match="
                    f"{str(actual_hash == expected_hash).lower()}). Before stopping, run "
                    f"aoi checkpoint --task "
                    f"{task_id} --next-action \"<one exact next action>\" and summarize "
                    "material facts, changed files, evidence boundary, and risks."
                ),
            }
        )
        return
    allow()


def dispatch(payload: dict[str, Any], *, project_root: Path | None = None) -> None:
    root = project_root if project_root is not None else root_path()
    event = str(payload.get("hook_event_name", ""))
    if event == "SessionStart":
        session_start(root, payload)
    elif event == "UserPromptSubmit":
        user_prompt_submit(root, payload)
    elif event == "SubagentStart":
        subagent_start(root, payload)
    elif event == "SubagentStop":
        subagent_stop(root, payload)
    elif event == "PreToolUse":
        pre_tool_use(root, payload)
    elif event == "PostToolUse":
        post_tool_use(root, payload)
    elif event == "Stop":
        stop(root, payload)
    else:
        allow()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Optional fail-open Codex lifecycle adapter for AOI"
    )
    parser.add_argument("--hook-version", required=True)
    parser.add_argument("--project-root")
    parser.add_argument("--provenance-sha256")
    args = parser.parse_args()
    if (
        args.hook_version != SUPPORTED_HOOK_VERSION
        or not args.project_root
        or not args.provenance_sha256
    ):
        # Legacy/unbound hook definitions must not become an argparse failure
        # that strands Codex.  They also must not process the event as trusted.
        allow()
        return 0
    try:
        from .codex_install_provenance import verify_runtime_hook_provenance

        project_root = Path(args.project_root)
        verify_runtime_hook_provenance(
            project_root,
            args.provenance_sha256,
            Path(sys.argv[0]),
        )
        # Provenance is checked before reading stdin so a stale or shadowed
        # launcher cannot process a payload under a trusted project identity.
        payload = read_input()
    except Exception:
        # Hooks must never strand a task because the local harness is missing or
        # malformed. Doctor/status expose the defect on the next normal turn.
        allow()
        return 0
    if exact_payload_string(payload, "hook_event_name") == "PreToolUse":
        try:
            dispatch(payload, project_root=project_root)
        except Exception:
            # This is a second fence for failures before PreToolUse reaches its
            # own boundary; other lifecycle receipts keep their honest
            # fail-open adapter semantics below.
            _deny_pretool_fail_closed()
        return 0
    try:
        dispatch(payload, project_root=project_root)
    except Exception:
        # Hooks must never strand a task because the local harness is missing or
        # malformed. Doctor/status expose the defect on the next normal turn.
        allow()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
