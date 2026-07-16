"""Capacity review command family: syntax registration and command bodies.

This module owns the ``capacity-*`` command implementations for the
depth-two capacity-planning workflow (snapshot, recommend, arbitrate,
distribute, acknowledge).  It stays a leaf of the composition root: it imports
only sibling packages (``harnesslib``, ``state_lookup``) and the standard
library, never the monolithic :mod:`aoi_orgware.cli`.  The CLI imports the
command bodies back for handler wiring and keeps the mutable-constant/factory
composition root.

Three composition-root concerns cannot be imported statically and are threaded
in through the frozen :class:`CapacityCmdServices` dataclass built by
``cli._capacity_cmd_services()``:

* CLI-resident derived-state operations (``require_plan_ready``,
  ``require_root_session``, ``packet_authority_integrity_errors``) and the
  ``_capacity_records`` / ``_records_fingerprint`` helpers — the latter two stay
  in ``cli`` because they are also consumed by the CLI-resident packet/portfolio
  wiring (``_records_fingerprint`` is a ``PortfolioIntegrityServices`` callback,
  ``_capacity_records`` is called by ``cmd_create_packet`` and directly off
  ``cli`` in the suite) so ``cli`` remains their single source of truth.  All
  are direct-bound (none is fault-injected via ``mock.patch.object(cli, ...)``).
* The composition-root policy constants ``CAPABILITY_CATALOG_VERSION``,
  ``CAPABILITY_TIER_MAP`` and ``DEPTH_TWO_ROLES`` (none rebound by
  ``apply_project_config``, none test-patched) are direct value-bound so ``cli``
  stays their single source of truth.

``capacity-distribute`` and ``capacity-ack`` depend on no composition-root
concern, so they keep the ``(args, paths)`` signature and are wired as bare
handlers — pure verbatim moves.  ``emit``, ``require_text`` and
``require_evidence_detail`` are pure leaf helpers (no project-mutable or
test-patched dependency) redeclared module-locally, mirroring the sibling
extraction precedent, so the relocated bodies bind the module-local copies
rather than reaching back into ``cli``.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..harnesslib import (
    HarnessError,
    HarnessPaths,
    atomic_write_json,
    bump_task,
    load_task,
    now_iso,
    sha256_file,
    state_lock,
    task_dir,
    validate_id,
    write_index,
    write_task,
)
from ..state_lookup import (
    _engaged_capacity_lane,
    _engaged_steward_lane,
    capacity_review_by_id,
    lane_by_id,
    require_open_task,
)


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset(
    {
        "capacity_snapshot",
        "capacity_recommend",
        "capacity_arbitrate",
        "capacity_distribute",
        "capacity_ack",
    }
)


class _RequirePlanReady(Protocol):
    def __call__(
        self, paths: HarnessPaths, state: dict[str, Any], action: str
    ) -> None: ...


class _RequireRootSession(Protocol):
    def __call__(
        self, paths: HarnessPaths, state: dict[str, Any], session_id: str
    ) -> str: ...


class _PacketAuthorityIntegrityErrors(Protocol):
    def __call__(
        self,
        paths: HarnessPaths,
        state: dict[str, Any],
        packet: dict[str, Any],
        *,
        require_origin: bool,
    ) -> list[str]: ...


class _CapacityRecords(Protocol):
    def __call__(
        self, state: dict[str, Any], target_lane_id: str, task_type: str
    ) -> list[dict[str, Any]]: ...


class _RecordsFingerprint(Protocol):
    def __call__(self, records: list[dict[str, Any]]) -> str: ...


@dataclass(frozen=True)
class CapacityCmdServices:
    """CLI-resident helpers and composition-root policy constants.

    Every field is direct-bound in ``cli._capacity_cmd_services()``: no name is
    fault-injected via ``mock.patch.object(cli, ...)`` nor rebound by
    ``apply_project_config``, so late binding is unnecessary.  ``capacity_records``
    and ``records_fingerprint`` remain defined in ``cli`` (shared with the
    packet/portfolio wiring) and are injected here to preserve one source of
    truth.
    """

    require_plan_ready: _RequirePlanReady
    require_root_session: _RequireRootSession
    packet_authority_integrity_errors: _PacketAuthorityIntegrityErrors
    capacity_records: _CapacityRecords
    records_fingerprint: _RecordsFingerprint
    capability_catalog_version: int
    capability_tier_map: Mapping[str, str]
    depth_two_roles: Collection[str]


def emit(payload: Any, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif isinstance(payload, str):
        print(payload)
    elif isinstance(payload, dict):
        for key, value in payload.items():
            print(f"{key}: {value}")
    else:
        print(payload)


def require_text(value: str, label: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise HarnessError(f"{label} may not be empty")
    return stripped


def require_evidence_detail(value: str, label: str) -> str:
    detail = require_text(value, label)
    if len(detail) < 12 or detail.lower() in {"pass", "passed", "ok", "success", "done"}:
        raise HarnessError(
            f"{label} is too generic; cite an artifact, command result, or bounded observation"
        )
    return detail


def cmd_capacity_snapshot(
    args: argparse.Namespace, paths: HarnessPaths, *, services: CapacityCmdServices
) -> int:
    review_id = validate_id(args.review_id, "capacity review id")
    task_type = validate_id(args.task_type, "capacity task type")
    if args.leaf_role not in services.depth_two_roles:
        raise HarnessError("capacity review leaf role must be batch, explorer, or worker")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "snapshot capacity data for")
        services.require_plan_ready(paths, state, "snapshot capacity data")
        if any(review.get("review_id") == review_id for review in state.get("capacity_reviews", [])):
            raise HarnessError(f"capacity review already exists: {review_id}")
        capacity_lane = _engaged_capacity_lane(state, args.capacity_lane_id)
        steward = _engaged_steward_lane(state)
        target = lane_by_id(state, args.target_lane_id)
        if target.get("revision") != args.expected_lane_revision:
            raise HarnessError("capacity target lane revision CAS failed")
        records = services.capacity_records(state, target["lane_id"], task_type)
        dataset_payload = {
            "dataset_version": 1,
            "task_id": state["task_id"],
            "review_id": review_id,
            "steward_lane_id": steward["lane_id"],
            "steward_lane_revision": steward["revision"],
            "capacity_lane_id": capacity_lane["lane_id"],
            "capacity_lane_revision": capacity_lane["revision"],
            "target_lane_id": target["lane_id"],
            "target_lane_revision": target["revision"],
            "task_type": task_type,
            "leaf_role": args.leaf_role,
            "records": records,
            "token_usage": "unavailable",
            "cost": "unavailable",
        }
        dataset_path = (
            task_dir(paths, args.task) / "results" / f"capacity-dataset-{review_id}.json"
        )
        atomic_write_json(dataset_path, dataset_payload)
        dataset_sha = sha256_file(dataset_path)
        recorded = now_iso()
        review = {
            "integrity_version": 1,
            "review_id": review_id,
            "version": 1,
            "status": "data_ready",
            "scope": {
                "target_lane_id": target["lane_id"],
                "target_lane_revision": target["revision"],
                "authority_commit": target["authority_commit"],
                "contract_version": target["contract_version"],
                "task_type": task_type,
                "leaf_role": args.leaf_role,
                "target_depth": 2,
            },
            "capacity_lane_id": capacity_lane["lane_id"],
            "capacity_lane_revision": capacity_lane["revision"],
            "steward_lane_id": steward["lane_id"],
            "steward_lane_revision": steward["revision"],
            "catalog_version": services.capability_catalog_version,
            "plan_sha256": state.get("plan_sha256"),
            "dataset": {
                "path": str(dataset_path),
                "sha256": dataset_sha,
                "record_count": len(records),
                "fingerprint": services.records_fingerprint(records),
                "cutoff_at": recorded,
            },
            "recommendation": None,
            "chief_decision": None,
            "distribution": None,
            "acknowledgement": None,
            "consumption": None,
            "created_at": recorded,
            "updated_at": recorded,
        }
        state["capacity_planning_version"] = 1
        state.setdefault("capacity_reviews", []).append(review)
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(review, args.json)
    return 0


def cmd_capacity_recommend(
    args: argparse.Namespace, paths: HarnessPaths, *, services: CapacityCmdServices
) -> int:
    if args.capability_tier not in services.capability_tier_map:
        raise HarnessError("unknown capability tier")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "record capacity recommendation for")
        review = capacity_review_by_id(state, args.review_id)
        if review.get("version") != args.expected_version or review.get("status") != "data_ready":
            raise HarnessError("capacity recommendation CAS/status gate failed")
        dataset = review.get("dataset", {})
        dataset_path = Path(str(dataset.get("path", "")))
        if not dataset_path.is_file() or sha256_file(dataset_path) != dataset.get("sha256"):
            raise HarnessError("capacity dataset is missing or tampered")
        if int(dataset.get("record_count", 0)) < 1:
            raise HarnessError("capacity recommendation requires at least one verified task-type record")
        matches = [
            packet
            for packet in state.get("packets", [])
            if packet.get("packet_id") == args.source_packet_id
        ]
        if len(matches) != 1:
            raise HarnessError("capacity source packet does not exist")
        source_packet = matches[0]
        if (
            source_packet.get("status") != "done"
            or source_packet.get("lane_id") != review.get("capacity_lane_id")
            or not source_packet.get("result_sha256")
            or source_packet.get("capacity_review_source_id") != review["review_id"]
            or not any(
                (ref.get("source_path") or ref.get("path")) == dataset.get("path")
                and ref.get("sha256") == dataset.get("sha256")
                for ref in source_packet.get("input_artifact_refs", [])
            )
        ):
            raise HarnessError(
                "capacity recommendation requires a done source packet bound to this review dataset"
            )
        authority_errors = services.packet_authority_integrity_errors(
            paths, state, source_packet, require_origin=False
        )
        if authority_errors:
            raise HarnessError(
                "capacity recommendation source packet authority is missing or tampered: "
                + "; ".join(authority_errors)
            )
        source_result = Path(str(source_packet.get("result_path", "")))
        expected_source_result = (
            task_dir(paths, args.task) / "results" / f"{source_packet['packet_id']}.md"
        )
        if (
            source_result != expected_source_result
            or not source_result.is_file()
            or source_result.is_symlink()
            or sha256_file(source_result) != source_packet.get("result_sha256")
        ):
            raise HarnessError("capacity recommendation source result is missing or tampered")
        review["version"] = int(review["version"]) + 1
        review["status"] = "awaiting_chief"
        review["recommendation"] = {
            "capability_tier": args.capability_tier,
            "requested_model_tier": services.capability_tier_map[args.capability_tier],
            "rationale": require_evidence_detail(args.rationale, "capacity rationale"),
            "risk": require_evidence_detail(args.risk, "capacity risk"),
            "confidence_boundary": require_evidence_detail(
                args.confidence_boundary, "capacity confidence boundary"
            ),
            "source_packet_id": source_packet["packet_id"],
            "source_result_sha256": source_packet["result_sha256"],
        }
        review["updated_at"] = now_iso()
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(review, args.json)
    return 0


def cmd_capacity_arbitrate(
    args: argparse.Namespace, paths: HarnessPaths, *, services: CapacityCmdServices
) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "arbitrate capacity recommendation for")
        if any(
            item.get("status") == "needs_user"
            for item in state.get("needs_user_escalations", [])
        ):
            raise HarnessError(
                "unresolved needs-user escalation blocks capacity arbitration"
            )
        review = capacity_review_by_id(state, args.review_id)
        if review.get("version") != args.expected_version or review.get("status") != "awaiting_chief":
            raise HarnessError("capacity arbitration CAS/status gate failed")
        session_id = services.require_root_session(paths, state, args.session_id)
        recorded = now_iso()
        decision_id = f"{review['review_id']}-chief-1"
        review["version"] = int(review["version"]) + 1
        review["status"] = "approved" if args.decision == "approved" else "rejected"
        review["chief_decision"] = {
            "decision_id": decision_id,
            "decision": args.decision,
            "rationale": require_evidence_detail(args.rationale, "capacity chief rationale"),
            "root_owner": state.get("owner"),
            "root_session_id": session_id,
            "recorded_at": recorded,
        }
        review["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(review, args.json)
    return 0


def cmd_capacity_distribute(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "distribute capacity decision for")
        review = capacity_review_by_id(state, args.review_id)
        if review.get("version") != args.expected_version or review.get("status") != "approved":
            raise HarnessError("capacity distribution CAS/status gate failed")
        steward = _engaged_steward_lane(state)
        if steward.get("lane_id") != args.steward_lane_id:
            raise HarnessError("capacity decision must be distributed by the engaged steward")
        review["version"] = int(review["version"]) + 1
        review["status"] = "distributed"
        review["distribution"] = {
            "steward_lane_id": steward["lane_id"],
            "decision_id": review["chief_decision"]["decision_id"],
            "recorded_at": now_iso(),
        }
        review["updated_at"] = review["distribution"]["recorded_at"]
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(review, args.json)
    return 0


def cmd_capacity_ack(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "acknowledge capacity decision for")
        review = capacity_review_by_id(state, args.review_id)
        if review.get("version") != args.expected_version or review.get("status") != "distributed":
            raise HarnessError("capacity acknowledgement CAS/status gate failed")
        scope = review["scope"]
        if args.actor_lane != scope["target_lane_id"]:
            raise HarnessError("only the target department lane may acknowledge capacity")
        target = lane_by_id(state, args.actor_lane)
        if (
            target.get("revision") != scope["target_lane_revision"]
            or target.get("authority_commit") != scope["authority_commit"]
            or target.get("contract_version") != scope["contract_version"]
        ):
            raise HarnessError("capacity recommendation is stale against target lane authority")
        review["version"] = int(review["version"]) + 1
        review["status"] = "acknowledged"
        review["acknowledgement"] = {
            "actor_lane": args.actor_lane,
            "evidence": require_evidence_detail(args.evidence, "capacity acknowledgement"),
            "recorded_at": now_iso(),
        }
        review["updated_at"] = review["acknowledgement"]["recorded_at"]
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(review, args.json)
    return 0


def register_capacity_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
    vocab: Any,
) -> None:
    """Register the capacity command family on one argparse subparser set."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "capacity command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("capacity-snapshot")
    parser.add_argument("--task", required=True)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--capacity-lane-id", required=True)
    parser.add_argument("--target-lane-id", required=True)
    parser.add_argument("--task-type", required=True)
    parser.add_argument(
        "--leaf-role", choices=sorted(vocab.depth_two_roles), required=True
    )
    parser.add_argument("--expected-lane-revision", type=int, required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["capacity_snapshot"])

    parser = subparsers.add_parser("capacity-recommend")
    parser.add_argument("--task", required=True)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--source-packet-id", required=True)
    parser.add_argument(
        "--capability-tier", choices=sorted(vocab.capability_tier_map), required=True
    )
    parser.add_argument("--rationale", required=True)
    parser.add_argument("--risk", required=True)
    parser.add_argument("--confidence-boundary", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["capacity_recommend"])

    parser = subparsers.add_parser("capacity-arbitrate")
    parser.add_argument("--task", required=True)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--decision", choices=["approved", "rejected"], required=True)
    parser.add_argument("--rationale", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["capacity_arbitrate"])

    parser = subparsers.add_parser("capacity-distribute")
    parser.add_argument("--task", required=True)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--steward-lane-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["capacity_distribute"])

    parser = subparsers.add_parser("capacity-ack")
    parser.add_argument("--task", required=True)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--actor-lane", required=True)
    parser.add_argument("--evidence", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["capacity_ack"])


__all__ = [
    "CapacityCmdServices",
    "cmd_capacity_ack",
    "cmd_capacity_arbitrate",
    "cmd_capacity_distribute",
    "cmd_capacity_recommend",
    "cmd_capacity_snapshot",
    "register_capacity_commands",
]
