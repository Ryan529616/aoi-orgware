"""Codex helper-budget transport canary (``codex-helper-canary``).

WS4 of the observability line: whether a Codex transport can deliver
budgeted depth-two helpers is an EMPIRICAL property of the hook payloads it
sends, not something AOI may claim from code inspection. This command
classifies what a live canary window actually recorded for one depth-one
parent packet and persists the verdict as a typed ``transport_probes`` entry:

- ``supported`` — at least one helper spawn was authorized against the
  DIRECT parent packet (the transport reported the depth-one agent's own
  session id) and consumed exactly the recorded budget slots.
- ``supported_budget_enforced`` — direct-parent linkage worked and the
  refusal taxonomy fired correctly (``no_helper_budget`` /
  ``helper_budget_exhausted``) instead of authorizing over budget.
- ``unsupported_root_parent_only`` — spawns in the window arrived keyed to a
  ROOT session id and fell through to unmanaged-start incidents while the
  armed parent stayed unconsumed: the transport does not expose the direct
  parent, so a helper budget > 0 does NOT deliver nested helpers here.
- ``unknown`` — nothing observable happened in the window.

The module stays a leaf of the composition root: it imports the shared
harness library, never :mod:`aoi_orgware.cli`; composition-root lookups are
threaded in through :class:`CanaryCmdServices`.
"""

from __future__ import annotations

import argparse
import datetime as dt
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from ..harnesslib import (
    HarnessError,
    HarnessPaths,
    bump_task,
    load_task,
    now_iso,
    state_lock,
    validate_id,
    write_index,
    write_task,
)
from ..state_lookup import require_open_task

HELPER_TRANSPORT_VERDICTS = {
    "supported",
    "supported_budget_enforced",
    "unsupported_root_parent_only",
    "unknown",
}
HELPER_REFUSAL_REASON_CODES = {"no_helper_budget", "helper_budget_exhausted"}
TRANSPORT_PROBE_SCHEMA_VERSION = 1


class _RequirePlanReady(Protocol):
    def __call__(
        self, paths: HarnessPaths, state: dict[str, Any], action: str
    ) -> None: ...


class _RequireRootSession(Protocol):
    def __call__(
        self, paths: HarnessPaths, state: dict[str, Any], session_id: str
    ) -> str: ...


class _PacketById(Protocol):
    def __call__(self, state: dict[str, Any], packet_id: str) -> dict[str, Any]: ...


@dataclass(frozen=True)
class CanaryCmdServices:
    require_plan_ready: _RequirePlanReady
    require_root_session: _RequireRootSession
    packet_by_id: _PacketById


def emit(payload: Any, as_json: bool = False) -> None:
    import json

    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            print(f"{key}: {value}")
    else:
        print(payload)


def _parse_window_start(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise HarnessError(
            f"canary window start must be an ISO-8601 timestamp: {value!r}"
        ) from exc
    if parsed.tzinfo is None:
        raise HarnessError("canary window start must be timezone-aware")
    return parsed


def _observed_in_window(record: Mapping[str, Any], window_start: dt.datetime) -> bool:
    observed = str(record.get("observed_at", ""))
    try:
        parsed = dt.datetime.fromisoformat(observed)
    except ValueError:
        return False
    if parsed.tzinfo is None:
        return False
    return parsed >= window_start


def cmd_codex_helper_canary(
    args: argparse.Namespace, paths: HarnessPaths, *, services: CanaryCmdServices
) -> int:
    probe_id = validate_id(args.probe_id, "transport probe id")
    window_start = _parse_window_start(args.window_start)
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "record helper transport canary for")
        services.require_plan_ready(paths, state, "record helper transport canary")
        session_id = services.require_root_session(paths, state, args.session_id)
        if any(
            probe.get("probe_id") == probe_id
            for probe in state.get("transport_probes", [])
        ):
            raise HarnessError(f"transport probe already exists: {probe_id}")
        parent = services.packet_by_id(state, args.parent_packet_id)
        if int(parent.get("delegation_depth", 1)) != 1:
            raise HarnessError(
                "helper transport canary requires a depth-one parent packet"
            )
        budget = parent.get("helper_spawn_budget", 0)
        budget = budget if isinstance(budget, int) and budget >= 0 else 0
        helper_spawns = [
            spawn
            for spawn in parent.get("helper_spawns", [])
            if isinstance(spawn, dict) and _observed_in_window(spawn, window_start)
        ]
        root_sessions = {str(item) for item in state.get("session_ids", [])}
        incidents = [
            incident
            for incident in state.get("subagent_incidents", [])
            if isinstance(incident, dict)
            and _observed_in_window(incident, window_start)
        ]
        budget_refusals = [
            incident
            for incident in incidents
            if incident.get("reason_code") in HELPER_REFUSAL_REASON_CODES
            and str(incident.get("helper_parent_packet_id", ""))
            == str(parent.get("packet_id", ""))
        ]
        root_keyed = [
            incident
            for incident in incidents
            if incident.get("reason_code") == "no_matching_arm"
            and str(incident.get("parent_session_id", "")) in root_sessions
        ]
        if helper_spawns:
            verdict = "supported"
            basis = (
                f"{len(helper_spawns)} helper spawn(s) were authorized against "
                f"the direct parent packet {parent.get('packet_id')} within the "
                f"canary window (budget={budget})"
            )
        elif budget_refusals:
            verdict = "supported_budget_enforced"
            basis = (
                "direct-parent linkage resolved and the budget gate refused "
                "with explicit reason codes "
                f"({sorted({i.get('reason_code') for i in budget_refusals})}); "
                "the transport supports helper association but the budget "
                "correctly blocked authorization"
            )
        elif root_keyed:
            verdict = "unsupported_root_parent_only"
            basis = (
                f"{len(root_keyed)} spawn(s) in the window arrived keyed to a "
                "ROOT session id and became unmanaged-start incidents while "
                "the parent packet consumed no helper slot: this transport "
                "does not expose the direct parent session id, so a helper "
                "budget > 0 does NOT deliver nested helpers on it"
            )
        else:
            verdict = "unknown"
            basis = (
                "no helper spawn, budget refusal, or root-keyed incident was "
                "observed in the canary window; the probe proves nothing"
            )
        probe = {
            "schema_version": TRANSPORT_PROBE_SCHEMA_VERSION,
            "probe_id": probe_id,
            "kind": "codex_helper_budget",
            "parent_packet_id": parent.get("packet_id"),
            "window_start": window_start.isoformat(),
            "verdict": verdict,
            "basis": basis,
            "helper_spawn_budget": budget,
            "helper_slots_consumed": len(parent.get("helper_spawns", [])),
            "evidence": {
                "helper_event_ids": [
                    str(spawn.get("event_id", "")) for spawn in helper_spawns
                ],
                "helper_observed_models": [
                    str(spawn.get("model", "")) for spawn in helper_spawns
                ],
                "budget_refusal_incident_ids": [
                    str(incident.get("incident_id", ""))
                    for incident in budget_refusals
                ],
                "root_keyed_incident_ids": [
                    str(incident.get("incident_id", "")) for incident in root_keyed
                ],
            },
            "root_session_id": session_id,
            "recorded_at": now_iso(),
        }
        state.setdefault("transport_probes", []).append(probe)
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(probe, args.json)
    return 0


def register_canary_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Callable[..., int]],
    add_json_argument: Callable[[argparse.ArgumentParser], None],
) -> None:
    parser = subparsers.add_parser("codex-helper-canary")
    parser.add_argument("--task", required=True)
    parser.add_argument("--probe-id", required=True)
    parser.add_argument("--parent-packet-id", required=True)
    parser.add_argument(
        "--window-start",
        required=True,
        help="timezone-aware ISO-8601 start of the observed canary window",
    )
    parser.add_argument("--session-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["codex_helper_canary"])


__all__ = [
    "CanaryCmdServices",
    "HELPER_TRANSPORT_VERDICTS",
    "cmd_codex_helper_canary",
    "register_canary_commands",
]
