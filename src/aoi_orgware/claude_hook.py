#!/usr/bin/env python3
"""Tiny, fail-open, opt-in Claude Code hook adapter for AOI.

Transport mapping (dispatch protocol v6, Claude adapter v1):

- ``PreToolUse`` on the ``Agent`` tool is a *pre-spawn gate*. For governed
  agent types it denies a spawn that has no exact live arm, before the
  sub-agent exists. Codex has no pre-spawn control; this gate is therefore
  strictly stronger, but it is still a cooperative guardrail, not a sandbox.
- ``SubagentStart`` consumes the arm exactly like the Codex adapter and is
  the only mutation point. The payload carries the same coordinates
  (parent ``session_id``, ``agent_id``, ``agent_type``); Claude's
  ``prompt_id`` fills the protocol's turn slot. Provenance is recorded as
  ``claude_subagent_start_observed``, never as a Codex observation.
- Ambient agent types (research/analysis helpers, ``workflow-subagent``)
  outside ``AOI_CLAUDE_GOVERNED_AGENT_TYPES`` pass through without arms or
  incidents unless the Chief explicitly armed that exact slot. Their output
  is Chief-side engineering inference and never packet evidence.
- ``SessionStart``/``UserPromptSubmit``/``Stop`` share the Codex adapter's
  runtime-neutral handlers verbatim.

Workflow-orchestrated spawns bypass ``PreToolUse`` (observed empirically);
the ``SubagentStart`` path still sees them, which is why arm consumption and
incident recording live there and not in the gate.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from .codex_hook import (
    SAFE_DISPLAY_ID,
    allow,
    read_input,
    root_path,
    session_start,
    session_state,
    stop,
    user_prompt_submit,
    write_output,
)
from .harnesslib import get_paths


SUPPORTED_HOOK_VERSION = "1"
GOVERNED_AGENT_TYPES_ENV = "AOI_CLAUDE_GOVERNED_AGENT_TYPES"
DEFAULT_GOVERNED_AGENT_TYPES = ("general-purpose",)
AGENT_TOOL_NAME = "Agent"
# A wildcard arm matches any observed transport agent_type for its parent slot.
WILDCARD_AGENT_TYPE = "*"
# Tools whose target file is explicit enough to check against claims. Bash is
# deliberately excluded: its command cannot be reliably resolved to a target,
# and a false deny there would break the session.
CLAIM_WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
CLAIM_WRITE_GATE_ENV = "AOI_CLAUDE_CLAIM_WRITE_GATE"
TIER_MODELS_ENV = "AOI_CLAUDE_TIER_MODELS"
# Requested-model families each packet tier may name in a governed dispatch.
# A family alias matches only a delimiter-bounded component of a fully qualified
# model id; configured full ids match exactly. The session's
# own top-price model is deliberately in no tier: the Chief session is the only
# place for it, and a packet that needs it is an escalation, not a dispatch.
DEFAULT_TIER_MODEL_FAMILIES: dict[str, tuple[str, ...]] = {
    "frontier": ("opus",),
    "expert": ("opus", "sonnet"),
    "advanced": ("sonnet",),
    "standard": ("sonnet", "haiku"),
    "economical": ("haiku",),
}
MODEL_FAMILY_ALIASES = frozenset({"opus", "sonnet", "haiku"})


def governed_agent_types() -> frozenset[str]:
    raw = os.environ.get(GOVERNED_AGENT_TYPES_ENV, "")
    if not raw.strip():
        return frozenset(DEFAULT_GOVERNED_AGENT_TYPES)
    return frozenset(
        item.strip() for item in raw.split(",") if item.strip()
    )


def tier_model_families() -> dict[str, tuple[str, ...]]:
    """Tier -> allowed requested models, with a strict JSON override.

    A present but malformed override is a policy error. Silently falling back
    would turn a deployment typo into an authorization bypass.
    """

    raw = os.environ.get(TIER_MODELS_ENV, "")
    if not raw.strip():
        return dict(DEFAULT_TIER_MODEL_FAMILIES)
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise ValueError(f"{TIER_MODELS_ENV} is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{TIER_MODELS_ENV} must be a JSON object")
    families: dict[str, tuple[str, ...]] = {}
    for tier, models in parsed.items():
        key = str(tier).strip().lower()
        if not key:
            raise ValueError(f"{TIER_MODELS_ENV} contains an empty tier key")
        if key in families:
            raise ValueError(
                f"{TIER_MODELS_ENV} contains duplicate tier {key!r} after normalization"
            )
        if not isinstance(models, list):
            raise ValueError(f"{TIER_MODELS_ENV} tier {key!r} must be a JSON list")
        if not models or any(
            not isinstance(model, str) or not model.strip() for model in models
        ):
            raise ValueError(
                f"{TIER_MODELS_ENV} tier {key!r} must contain non-empty strings"
            )
        families[key] = tuple(model.strip().lower() for model in models)
    if not families:
        raise ValueError(f"{TIER_MODELS_ENV} must define at least one tier")
    return families


def _model_matches_approved_value(model: str, approved: str) -> bool:
    normalized = model.strip().lower()
    candidate = approved.strip().lower()
    if candidate in MODEL_FAMILY_ALIASES:
        return bool(
            re.search(
                rf"(?:^|[-_.]){re.escape(candidate)}(?:$|[-_.])",
                normalized,
            )
        )
    return normalized == candidate


def model_tier_violation(
    model_tier: Any, tool_input: dict[str, Any]
) -> str | None:
    """Deny reason when the dispatch request's model breaks the tier policy.

    This checks the *dispatch request* the runtime received, not the routing
    the runtime later performs. A packet without a tier passes through because
    there is no tier authority to enforce. A configured policy defect or a
    tier without a table row fails closed on this cooperative spawn path.
    """

    tier = str(model_tier or "").strip().lower()
    if not tier:
        return None
    try:
        policy = tier_model_families()
    except ValueError as exc:
        return f"AOI model-tier policy is invalid: {exc}."
    families = policy.get(tier)
    if not families:
        return (
            f"AOI model-tier gate: packet tier {tier!r} has no configured policy row."
        )
    model = str(tool_input.get("model", "") or "").strip()
    if not model:
        return (
            f"AOI model-tier gate: packet tier {tier!r} requires an explicit "
            f"model from families {', '.join(families)}; omitting `model` "
            "inherits the Chief session's model, which this packet's tier "
            "does not authorize."
        )
    if not any(
        _model_matches_approved_value(model, family) for family in families
    ):
        return (
            f"AOI model-tier gate: requested model {model!r} is outside packet "
            f"tier {tier!r} (allowed families: {', '.join(families)}). "
            "Re-dispatch with a matching model, or re-scope the packet tier "
            "through the normal packet path."
        )
    return None


def model_tier_note(model_tier: Any, tool_input: dict[str, Any]) -> str:
    """Allow-reason suffix naming the checked model, empty when unchecked."""

    tier = str(model_tier or "").strip().lower()
    if not tier:
        return ""
    try:
        configured = tier_model_families().get(tier)
    except ValueError:
        configured = None
    if not configured:
        return ""
    model = str(tool_input.get("model", "") or "").strip()
    if not model:
        return ""
    return (
        f" Requested model {model!r} is within tier {tier!r} at "
        "dispatch-request level."
    )


def claim_write_gate_mode() -> str:
    """`off` (default), `warn`, or `deny` for the Write/Edit claim gate."""

    raw = os.environ.get(CLAIM_WRITE_GATE_ENV, "").strip().lower()
    return raw if raw in {"warn", "deny"} else "off"


def _write_target(tool_input: dict[str, Any]) -> str:
    for key in ("file_path", "notebook_path"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _repo_relative(root: Path, target: str) -> str | None:
    """Repo-root-relative POSIX path, or None when the target is outside root."""

    try:
        candidate = Path(target)
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved = candidate.resolve()
        relative = resolved.relative_to(root.resolve())
    except (ValueError, OSError):
        return None
    return relative.as_posix()


def _repo_paths_casefold(root: Path) -> bool:
    """Mirror the lock ledger's filesystem comparison domain."""

    if os.name == "nt":
        return True
    # WSL repos on a configured Windows drive mount share the Windows lock
    # identity; native POSIX repos remain case-sensitive.
    from .harnesslib import _path_uses_windows_host_mount

    return _path_uses_windows_host_mount(root)


def _repo_path_key(root: Path, value: str) -> str:
    normalized = value.strip().strip("/")
    return normalized.casefold() if _repo_paths_casefold(root) else normalized


def _claimed_repo_scopes(
    root: Path, session_id: str
) -> tuple[str, set[str], set[str]] | None:
    """(task_id, exact-file locks, tree-prefix locks) for the bound session's
    reserving claims, or None when the session is not bound to usable state."""

    mapping_status, mapped = session_state(root, session_id)
    if mapping_status not in {"valid", "subagent_parent"} or mapped is None:
        return None
    # Lazy import keeps ordinary hook startup (session start, prompt) small.
    from .harnesslib import RESERVING_CLAIM_STATUSES, claims_for_task

    state = mapped[0]
    paths = get_paths(root)
    exact: set[str] = set()
    trees: set[str] = set()
    for claim in claims_for_task(paths, state, validate_reserving=False):
        if claim.get("status") not in RESERVING_CLAIM_STATUSES:
            continue
        for lock in claim.get("locks", []):
            text = str(lock)
            if text.startswith("repo:file:"):
                exact.add(_repo_path_key(root, text[len("repo:file:") :]))
            elif text.startswith("repo:tree:"):
                trees.add(_repo_path_key(root, text[len("repo:tree:") :]))
    return str(state.get("task_id", "")), exact, trees


def claim_write_gate(root: Path, payload: dict[str, Any]) -> None:
    """Enforce file claims on the cooperative Write/Edit tool path.

    Opt-in via ``AOI_CLAUDE_CLAIM_WRITE_GATE``; default off is an exact
    pass-through. This upgrades the claim ledger to a pre-write gate on the
    tools a cooperating agent actually uses; it is still cooperative, not an
    OS sandbox, and it never touches Bash.
    """

    mode = claim_write_gate_mode()
    if mode == "off":
        allow()
        return
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        allow()
        return
    target = _write_target(tool_input)
    if not target:
        allow()
        return
    session_id = str(payload.get("session_id", ""))
    scopes = _claimed_repo_scopes(root, session_id)
    if scopes is None:
        # Unbound / ambient session: the write gate governs bound sessions only.
        allow()
        return
    relative = _repo_relative(root, target)
    if relative is None:
        # Outside the repo (temp, external output) — not claim-governed.
        allow()
        return
    if relative == ".aoi" or relative.startswith(".aoi/"):
        # AOI state is Chief-managed through the CLI, not through file claims.
        allow()
        return
    task_id, exact, trees = scopes
    key = _repo_path_key(root, relative)
    covered = key in exact or any(
        tree and (key == tree or key.startswith(tree + "/")) for tree in trees
    )
    if covered:
        allow()
        return
    body = (
        f"{relative!r} is not covered by any live claim on AOI task "
        f"{task_id!r}. Claim the exact scope before writing "
        f"(`aoi claim --task {task_id} ... --lock repo:file:{relative}`), or "
        "write inside a claimed file or tree."
    )
    if mode == "deny":
        pretooluse_decision(
            "deny", f"AOI claim-write gate: {body}"
        )
    else:
        pretooluse_decision(
            "allow",
            f"AOI claim-write warning: {body} (advisory: "
            f"{CLAIM_WRITE_GATE_ENV}=warn)",
        )


def pretooluse_decision(decision: str, reason: str) -> None:
    write_output(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        }
    )


def _live_arm_slots(
    state: dict[str, Any], *, parent_session_id: str, agent_type: str
) -> tuple[list[str], list[str]]:
    """Read-only scan: (live packet ids, expired-by-clock packet ids) for one slot."""

    current = dt.datetime.now().astimezone()
    live: list[str] = []
    expired: list[str] = []
    for packet in state.get("packets", []):
        if packet.get("status") != "armed":
            continue
        for attempt in packet.get("dispatch_attempts", []):
            if not isinstance(attempt, dict) or attempt.get("status") != "armed":
                continue
            expected = attempt.get("expected_agent_type")
            if attempt.get("parent_session_id") != parent_session_id or (
                expected != agent_type and expected != WILDCARD_AGENT_TYPE
            ):
                continue
            packet_id = str(packet.get("packet_id", ""))
            try:
                expires_at = dt.datetime.fromisoformat(
                    str(attempt.get("expires_at", ""))
                )
            except ValueError:
                expired.append(packet_id)
                continue
            if expires_at.tzinfo is None or expires_at <= current:
                expired.append(packet_id)
            else:
                live.append(packet_id)
    return live, expired


def _armed_slot_exists(
    root: Path, parent_session_id: str, agent_type: str
) -> bool:
    mapping_status, mapped = session_state(root, parent_session_id)
    if mapping_status not in {"valid", "subagent_parent"} or mapped is None:
        return False
    live, expired = _live_arm_slots(
        mapped[0], parent_session_id=parent_session_id, agent_type=agent_type
    )
    return bool(live or expired)


def pre_tool_use(root: Path, payload: dict[str, Any]) -> None:
    tool_name = str(payload.get("tool_name", ""))
    if tool_name in CLAIM_WRITE_TOOLS:
        claim_write_gate(root, payload)
        return
    if tool_name != AGENT_TOOL_NAME:
        allow()
        return
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    subagent_type = str(tool_input.get("subagent_type", ""))
    session_id = str(payload.get("session_id", ""))
    mapping_status, _ = session_state(root, session_id)
    # The AOI-issued depth-one parent mapping is the authoritative nested case.
    # A bound root payload carrying agent_id is also treated conservatively as
    # nested; unbound/ambient payloads may carry that field and remain unbound.
    nested_request = mapping_status == "subagent_parent" or (
        mapping_status == "valid" and bool(str(payload.get("agent_id", "")))
    )
    explicit_slot = _armed_slot_exists(root, session_id, subagent_type)
    description = str(tool_input.get("description", "")).strip()
    task_suffix = f" for: {description}" if description else ""
    if (
        subagent_type not in governed_agent_types()
        and not explicit_slot
        and not nested_request
        and mapping_status != "corrupt"
    ):
        # Ungoverned agent type: not gated, but still announce the dispatch so the
        # spawn (what agent, what task) is visible rather than silent.
        pretooluse_decision(
            "allow",
            f"AOI: dispatching ungoverned sub-agent {subagent_type!r}{task_suffix}. "
            "Ambient Chief-side tooling; its output is engineering inference, not "
            "packet evidence.",
        )
        return
    # Import lazily so ordinary hook startup stays small.  This validator is
    # read-only but checks the same Chief, plan/contract, topology, lane, and
    # resource authority that SubagentStart checks before consuming the arm.
    from .cli import validate_claude_pre_spawn_arm

    outcome = validate_claude_pre_spawn_arm(
        get_paths(root),
        parent_session_id=session_id,
        transport_agent_type=subagent_type,
    )
    status = outcome.get("status")
    reason_code = str(outcome.get("reason_code", ""))
    if status == "corrupt":
        pretooluse_decision(
            "deny",
            "AOI session mapping or armed packet state is corrupt or inconsistent; "
            "run `aoi doctor` and repair or rebind before dispatching a governed "
            "sub-agent.",
        )
        return
    if nested_request:
        # A depth-two spawn. Read-only helpers are allowed against a parent
        # packet's Chief-granted helper budget; anything needing write authority
        # still goes through the manual depth-two dispatch path.
        from .cli import validate_claude_helper_slot

        helper = validate_claude_helper_slot(
            get_paths(root), parent_session_id=session_id
        )
        if helper.get("status") == "authorized":
            parent_packet_id = str(helper.get("packet_id", ""))
            violation = model_tier_violation(helper.get("model_tier"), tool_input)
            if violation:
                pretooluse_decision(
                    "deny",
                    f"{violation} Depth-two helpers are capped at the parent "
                    f"packet's tier (parent packet {parent_packet_id}"
                    f"{task_suffix}).",
                )
                return
            remaining = helper.get("remaining_helper_budget")
            budget = helper.get("helper_spawn_budget")
            pretooluse_decision(
                "allow",
                f"AOI helper-budget dispatch: parent packet {parent_packet_id} has "
                f"{remaining} of {budget} depth-two helper spawns remaining"
                f"{task_suffix}. This is bounded read-only support under the parent "
                "packet; its output is the parent agent's working material, not "
                "independent packet evidence, and it must not mutate AOI state.",
            )
            return
        pretooluse_decision(
            "deny",
            "A depth-one agent tried to spawn a nested governed sub-agent with no "
            "remaining helper budget. Grant read-only helpers with "
            "`aoi create-packet --helper-spawn-budget N`, or arm and register a "
            "depth-two packet through the manual dispatch path for write authority.",
        )
        return
    if status == "unbound":
        pretooluse_decision(
            "allow",
            f"AOI: dispatching {subagent_type!r}{task_suffix}. This session is not "
            "bound to an AOI task, so the dispatch is not packet-gated; bind a task "
            "to govern sub-agent dispatch.",
        )
        return
    if status == "authorized":
        packet_id = str(outcome.get("packet_id", ""))
        violation = model_tier_violation(outcome.get("model_tier"), tool_input)
        if violation:
            pretooluse_decision(
                "deny", f"{violation} (packet {packet_id}{task_suffix})"
            )
            return
        pretooluse_decision(
            "allow",
            f"AOI pre-armed dispatch: packet {packet_id} has current full authority "
            "and is armed for this "
            f"parent-session/agent-type slot ({subagent_type}){task_suffix}."
            f"{model_tier_note(outcome.get('model_tier'), tool_input)} The "
            "following SubagentStart observation consumes the arm.",
        )
        return
    if reason_code == "ambiguous_arm":
        pretooluse_decision(
            "deny",
            "AOI found more than one live arm for this parent-session/agent-type "
            "slot; the state is inconsistent. Run `aoi doctor` before dispatching.",
        )
        return
    if reason_code == "expired_arm":
        packet_ids = ", ".join(outcome.get("candidate_packet_ids", []))
        pretooluse_decision(
            "deny",
            f"The AOI packet arm for this slot expired ({packet_ids}). "
            "Re-arm the packet with `aoi packet-arm` and spawn again.",
        )
        return
    if reason_code in {"authority_invalid", "topology_rejected"}:
        label = "topology" if reason_code == "topology_rejected" else "authority"
        pretooluse_decision(
            "deny",
            f"The AOI packet arm for this slot failed current {label} validation. "
            "Review the packet, plan, Chief lease, lane/selection snapshots, and "
            "run `aoi doctor` before re-arming.",
        )
        return
    pretooluse_decision(
        "deny",
        f"No AOI packet is armed for governed agent type {subagent_type!r} in "
        "this bound session. Create and arm a bounded packet first "
        "(`aoi create-packet` + `aoi packet-arm`), or use an ungoverned agent "
        "type for Chief-side ambient analysis.",
    )


def subagent_start(root: Path, payload: dict[str, Any]) -> None:
    raw_agent_type = str(payload.get("agent_type", ""))
    display_agent_type = (
        raw_agent_type if SAFE_DISPLAY_ID.fullmatch(raw_agent_type) else "subagent"
    )
    session_id = str(payload.get("session_id", ""))
    paths = get_paths(root)
    mapping_status, _ = session_state(root, session_id)
    if (
        raw_agent_type not in governed_agent_types()
        and mapping_status not in {"subagent_parent", "corrupt"}
        and not _armed_slot_exists(root, session_id, raw_agent_type)
    ):
        write_output(
            {
                "hookSpecificOutput": {
                    "hookEventName": "SubagentStart",
                    "additionalContext": (
                        f"AOI: ambient sub-agent start ({display_agent_type}) in "
                        f"{paths.project.name!r}. This agent is ungoverned "
                        "Chief-side tooling: its output is engineering inference "
                        "for the Chief and never packet evidence. Do not mutate "
                        f"AOI state under {paths.harness} and do not present "
                        "conclusions as verified task results."
                    ),
                }
            }
        )
        return
    protocol_payload = {
        "hook_event_name": "SubagentStart",
        "session_id": session_id,
        # Claude has no per-turn id in this event; prompt_id is the turn analog.
        "turn_id": str(payload.get("prompt_id", "")),
        "agent_id": str(payload.get("agent_id", "")),
        "agent_type": raw_agent_type,
        "permission_mode": str(payload.get("permission_mode", "")),
    }
    # Import lazily so ordinary hook startup remains tiny and bytecode-free.
    from .cli import observe_claude_subagent_start

    outcome = observe_claude_subagent_start(paths, protocol_payload)
    status = outcome.get("status")
    if status == "authorized" and outcome.get("resumed"):
        context = (
            f"AOI observed a resumed dispatch of an existing packet thread for "
            f"{paths.project.name!r}: task={outcome.get('task_id')}, "
            f"packet={outcome.get('packet_id')}, "
            f"contract={outcome.get('packet_path')}. This is the same packet agent "
            f"resuming (Claude transport agent_type={display_agent_type}), not a fresh "
            "dispatch: stay inside the original packet contract scope, do not start "
            f"unrelated work, and do not edit {paths.harness}."
        )
    elif status == "authorized" and outcome.get("helper"):
        remaining = outcome.get("remaining_helper_budget")
        context = (
            f"AOI authorized a budgeted depth-two helper under parent packet "
            f"{outcome.get('packet_id')} for {paths.project.name!r} "
            f"(remaining helper budget={remaining}). This is bounded read-only support: "
            "your output is the parent agent's working material, NOT independent packet "
            f"evidence. Do not mutate AOI state under {paths.harness}, do not spawn "
            "further sub-agents, and report a bounded conclusion with exact paths to the "
            "parent agent."
        )
    elif status == "authorized":
        context = (
            f"AOI observed a valid pre-armed dispatch for {paths.project.name!r}: "
            f"task={outcome.get('task_id')}, packet={outcome.get('packet_id')}, "
            f"contract={outcome.get('packet_path')}. Claude transport "
            f"agent_type={display_agent_type}; the AOI technical role is defined by the "
            "packet contract. Read that exact packet before work and stay inside its "
            "scope. The root owns AOI state, claims, plan, checkpoint, and final "
            f"completion; do not edit {paths.harness}. Return a bounded conclusion "
            "with exact evidence/artifact paths, files inspected or changed, "
            "verification, unresolved risks, and one next action; never paste raw logs."
        )
    elif status == "incident":
        context = (
            "AOI observed this sub-agent start without one valid, unique pre-armed "
            f"packet. Incident={outcome.get('incident_id')}; "
            f"reason={outcome.get('reason_code')}. The start already occurred and "
            "this hook cannot terminate it. Stop without material work, do not "
            "inspect or edit project files, and report the incident id to the "
            "parent so the Chief can account it explicitly."
        )
    elif status == "corrupt":
        context = (
            "AOI could not validate the parent task mapping or packet authority for "
            f"this start; reason={outcome.get('reason_code')}. Stop without material "
            "work and report the corrupt authority to the parent. This hook observes "
            "starts but cannot terminate an already-created sub-agent."
        )
    else:
        context = (
            "AOI found no task mapping for the parent session, so it could not "
            "consume a packet arm or persist a task incident. Stop without material "
            "work and ask the parent to bind a task and arm an exact packet before "
            "retrying."
        )
    if outcome.get("index_refresh_deferred") is True:
        context += (
            " AOI committed the target task event but deferred the derived INDEX "
            "refresh; report this to the parent so the Chief can run doctor/status."
        )
    if outcome.get("parent_mapping_deferred") is True:
        context += (
            " AOI could not publish this depth-one agent's parent-only mapping; do "
            "not spawn a child and report the condition to the Chief."
        )
    write_output(
        {
            "hookSpecificOutput": {
                "hookEventName": "SubagentStart",
                "additionalContext": context,
            }
        }
    )


def dispatch(payload: dict[str, Any]) -> None:
    root = root_path()
    event = str(payload.get("hook_event_name", ""))
    if event == "SessionStart":
        session_start(root, payload)
    elif event == "UserPromptSubmit":
        user_prompt_submit(root, payload)
    elif event == "PreToolUse":
        pre_tool_use(root, payload)
    elif event == "SubagentStart":
        subagent_start(root, payload)
    elif event == "Stop":
        stop(root, payload)
    else:
        allow()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Optional fail-open Claude Code lifecycle adapter for AOI"
    )
    parser.add_argument("--hook-version", required=True)
    args = parser.parse_args()
    if args.hook_version != SUPPORTED_HOOK_VERSION:
        allow()
        return 0
    try:
        dispatch(read_input())
    except Exception:
        # Hooks must never strand a task because the local harness is missing or
        # malformed. Doctor/status expose the defect on the next normal turn.
        allow()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
