"""Read-only event-authoritative cohort status derivation.

This module never launches, cancels, or otherwise controls a transport.  It
derives one deterministic status view from a sealed cohort plan and the
authenticated routing object ledger.  The derived view is a report, not a
second mutable cohort state authority.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
import json
from typing import Any

from . import cohorts
from . import harnesslib as h
from . import routing_authority as authority
from . import routing_persistence as routing
from . import semantic_events as semantic


COHORT_STATUS_SCHEMA_VERSION = 1
MAX_COHORT_STATUS_BYTES = 2 * 1024 * 1024


class CohortRuntimeError(h.HarnessError):
    """Authenticated routing facts cannot form one honest cohort view."""


def _fail(message: str, exc: BaseException | None = None) -> CohortRuntimeError:
    return CohortRuntimeError(message if exc is None else f"{message}: {exc}")


def _clone(value: Any) -> Any:
    try:
        return json.loads(
            semantic.canonical_json_bytes(
                value, max_bytes=MAX_COHORT_STATUS_BYTES
            ).decode("utf-8")
        )
    except (semantic.SemanticEventError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _fail("cohort runtime value is not bounded canonical JSON", exc) from exc


def _terminal_outcome(terminal: Mapping[str, Any]) -> str:
    terminal_status = terminal.get("terminal_status")
    typed_outcome = terminal.get("typed_outcome")
    if typed_outcome == "accepted":
        return "accepted"
    if typed_outcome == "rejected" or terminal_status == "done":
        return "rejected"
    if terminal_status == "cancelled" or typed_outcome == "cancelled":
        return "cancelled"
    if terminal_status == "failed":
        return "failed"
    raise CohortRuntimeError("routing terminal has no cohort outcome mapping")


def _route_truth(
    plan: Mapping[str, Any], routing_report: Mapping[str, Any]
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    groups = routing_report.get("groups")
    if not isinstance(groups, list) or len(groups) > routing.MAX_ROUTING_ENTRIES * 3:
        raise CohortRuntimeError("routing report groups are invalid or over bound")
    refs = {
        ref["routing_authority_sha256"]: ref["packet_id"]
        for ref in plan["packet_refs"]
    }
    plan_packet_ids = set(refs.values())
    by_packet: dict[str, dict[str, Any]] = {}
    by_slot: dict[str, dict[str, dict[str, Any]]] = {}
    foreign_plan_packet_slots: dict[str, dict[str, str]] = {}
    for raw in groups:
        if not isinstance(raw, Mapping):
            raise CohortRuntimeError("routing report group is invalid")
        arm = raw.get("authority")
        if not isinstance(arm, Mapping):
            raise CohortRuntimeError("routing report group lacks authority")
        try:
            checked_arm = authority.validate_arm_authority(arm)
            digest = authority.authority_sha256(checked_arm)
        except authority.RoutingAuthorityError as exc:
            raise _fail("routing report authority is invalid", exc) from exc
        packet_id = checked_arm["packet_authority"]["packet_id"]
        stage = raw.get("stage")
        classification = raw.get("classification")
        slot = raw.get("slot")
        if (
            stage not in {"authority", "outcome", "terminal"}
            or classification not in {"pending", "committed"}
            or not isinstance(slot, str)
            or slot != routing.routing_outcome_slot_sha256(checked_arm)
        ):
            raise CohortRuntimeError("routing report group identity is invalid")
        if digest not in refs:
            if packet_id in plan_packet_ids:
                foreign_stages = foreign_plan_packet_slots.setdefault(slot, {})
                if stage in foreign_stages:
                    raise CohortRuntimeError(
                        "alternate cohort-packet authority repeats a routing stage"
                    )
                foreign_stages[stage] = classification
            continue
        if refs[digest] != packet_id:
            raise CohortRuntimeError(
                "cohort packet reference differs from routing authority packet"
            )
        stages = by_slot.setdefault(slot, {})
        if stage in stages:
            raise CohortRuntimeError("cohort routing stage has multiple owners")
        stages[stage] = dict(raw)
        prior = by_packet.setdefault(
            packet_id,
            {
                "routing_authority_sha256": digest,
                "outcome_slot_sha256": slot,
                "arm": checked_arm,
            },
        )
        if (
            prior["routing_authority_sha256"] != digest
            or prior["outcome_slot_sha256"] != slot
        ):
            raise CohortRuntimeError(
                "cohort packet has inconsistent routing authority groups"
            )
    for stages in foreign_plan_packet_slots.values():
        if stages.get("terminal") != "committed":
            raise CohortRuntimeError(
                "cohort packet has another active routing authority"
            )
    return by_packet, by_slot


def derive_cohort_status(
    paths: h.HarnessPaths,
    task_id: str,
    event_chain: Iterable[Mapping[str, Any]],
    cohort_plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive one cohort view from the authenticated routing ledger.

    ``manual_unverified`` outcomes remain armed.  Only a validated
    ``codex_subagent_start_observed`` outcome can make ``running`` true.
    """

    task_id = h.validate_id(task_id, "task id")
    try:
        plan = cohorts.validate_cohort(cohort_plan)
    except cohorts.CohortError as exc:
        raise _fail("cohort plan is invalid", exc) from exc
    routing_report = routing.inspect_routing_persistence(paths, task_id, event_chain)
    by_packet, by_slot = _route_truth(plan, routing_report)
    states: dict[str, dict[str, str | None]] = {}
    evidence_rows: list[dict[str, Any]] = []
    for ref in plan["packet_refs"]:
        packet_id = ref["packet_id"]
        truth = by_packet.get(packet_id)
        status = "planned"
        terminal_outcome: str | None = None
        recovery_pending = False
        outcome_sha256: str | None = None
        observation_sha256: str | None = None
        terminal_object_sha256: str | None = None
        terminal_status: str | None = None
        typed_outcome: str | None = None
        outcome_slot_sha256: str | None = None
        if truth is not None:
            outcome_slot_sha256 = truth["outcome_slot_sha256"]
            stages = by_slot[outcome_slot_sha256]
            authority_group = stages.get("authority")
            if authority_group is None:
                raise CohortRuntimeError(
                    "cohort routing outcome or terminal has no authority owner"
                )
            status = "armed"
            recovery_pending = any(
                group["classification"] == "pending" for group in stages.values()
            )
            outcome_group = stages.get("outcome")
            if outcome_group is not None and outcome_group["classification"] == "committed":
                outcome = outcome_group.get("outcome")
                if not isinstance(outcome, Mapping):
                    raise CohortRuntimeError("committed routing outcome is missing")
                try:
                    checked_outcome = authority.validate_dispatch_outcome(
                        truth["arm"], outcome
                    )
                except authority.RoutingAuthorityError as exc:
                    raise _fail("cohort routing outcome is invalid", exc) from exc
                outcome_sha256 = checked_outcome["routing_outcome_sha256"]
                if checked_outcome["dispatch_provenance"] == (
                    "codex_subagent_start_observed"
                ):
                    observation = checked_outcome["observation"]
                    if not isinstance(observation, Mapping):
                        raise CohortRuntimeError(
                            "observed routing outcome lacks an observation"
                        )
                    observation_sha256 = observation["observation_sha256"]
                    status = "start_observed"
            terminal_group = stages.get("terminal")
            if terminal_group is not None and terminal_group["classification"] == "committed":
                terminal = terminal_group.get("terminal")
                terminal_objects = terminal_group.get("objects")
                if not isinstance(terminal, Mapping) or not isinstance(
                    terminal_objects, Mapping
                ):
                    raise CohortRuntimeError("committed routing terminal is missing")
                terminal_object = terminal_objects.get("routing_terminal")
                if not isinstance(terminal_object, Mapping):
                    raise CohortRuntimeError(
                        "committed routing terminal object is missing"
                    )
                terminal_object_sha256 = terminal_object.get("object_sha256")
                if not isinstance(terminal_object_sha256, str):
                    raise CohortRuntimeError(
                        "committed routing terminal object digest is invalid"
                    )
                terminal_status = terminal.get("terminal_status")
                typed_outcome = terminal.get("typed_outcome")
                terminal_outcome = _terminal_outcome(terminal)
                status = "terminal"
        states[packet_id] = {
            "status": status,
            "terminal_outcome": terminal_outcome,
        }
        evidence_rows.append(
            {
                "packet_id": packet_id,
                "routing_authority_sha256": None
                if truth is None
                else truth["routing_authority_sha256"],
                "outcome_slot_sha256": outcome_slot_sha256,
                "routing_outcome_sha256": outcome_sha256,
                "start_observation_sha256": observation_sha256,
                "routing_terminal_object_sha256": terminal_object_sha256,
                "terminal_status": terminal_status,
                "typed_outcome": typed_outcome,
                "recovery_pending": recovery_pending,
            }
        )
    try:
        projection = cohorts.project_cohort(plan, states)
        if projection["cancel_requested"]:
            for row in evidence_rows:
                packet_id = row["packet_id"]
                if (
                    states[packet_id]["status"] == "planned"
                    and row["routing_authority_sha256"] is None
                ):
                    states[packet_id] = {
                        "status": "cancelled",
                        "terminal_outcome": None,
                    }
            projection = cohorts.project_cohort(plan, states)
    except cohorts.CohortError as exc:
        raise _fail("routing truth violates cohort state invariants", exc) from exc
    transport_start_observed = any(
        row["start_observation_sha256"] is not None for row in evidence_rows
    )
    base = {
        "schema_version": COHORT_STATUS_SCHEMA_VERSION,
        "task_id": task_id,
        "cohort_id": plan["cohort_id"],
        "cohort_sha256": plan["cohort_sha256"],
        "transport_launch_claimed": False,
        "transport_start_observed": transport_start_observed,
        "launch_actor": "unavailable",
        "launcher_receipt_sha256": None,
        "packet_states": states,
        "packet_evidence": evidence_rows,
        "projection": projection,
    }
    try:
        base["status_sha256"] = semantic.canonical_sha256(
            base, max_bytes=MAX_COHORT_STATUS_BYTES
        )
    except semantic.SemanticEventError as exc:
        raise _fail("cohort status exceeds its byte bound", exc) from exc
    return _clone(base)


__all__ = [
    "COHORT_STATUS_SCHEMA_VERSION",
    "MAX_COHORT_STATUS_BYTES",
    "CohortRuntimeError",
    "derive_cohort_status",
]
