"""Improvement-request and skill-lifecycle command family.

This module owns the ``improvement-*`` and ``skill-*`` command implementations
for the continuous-improvement workflow (submit, brief, arbitrate, link-project,
skill-release-record, skill-adoption-record) together with the parser
registration.  It stays a leaf of the composition root: it imports only sibling
packages (``harnesslib``, ``state_lookup``, ``skill_lifecycle``) and the standard
library, never the monolithic :mod:`aoi_orgware.cli`.  The CLI imports the
command bodies back for handler wiring and keeps the mutable-constant/factory
composition root.

Five composition-root helpers cannot be imported statically and are threaded in
through the frozen :class:`ImprovementCmdServices` dataclass built by
``cli._improvement_cmd_services()``:

* CLI-resident derived-state operations ``require_plan_ready`` and
  ``require_root_session`` and the artifact reader ``read_regular_artifact``.
* The CLI-resident ``_records_fingerprint`` (also a ``PortfolioIntegrityServices``
  callback / shared with the capacity + packet wiring), ``_require_done_reviewer_packet``
  (shared with the packet-integrity wiring and other command families), and the
  ``_skill_release_semantic_integrity_errors`` wrapper (which itself closes over
  ``skill_lifecycle`` + ``_require_done_reviewer_packet`` in ``cli``).  All remain
  defined in ``cli`` so it stays their single source of truth; the services simply
  inject the same objects.

Every service field is direct-bound: none is fault-injected via
``mock.patch.object(cli, ...)`` (the suite's write_task/write_index/state_lock
patches drive only init/chief-acquire/observe_subagent_start/codex-config-rollback)
nor rebound by ``apply_project_config``, so late binding is unnecessary.
``cmd_improvement_brief`` depends on no composition-root concern, so it keeps the
``(args, paths)`` signature and is wired as a bare handler (pure verbatim move).
``emit``, ``require_text`` and ``require_evidence_detail`` are pure leaf helpers
(no project-mutable or test-patched dependency) redeclared module-locally,
mirroring the sibling extraction precedent.
"""


from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..agent_identity import AgentIdentityError, validate_agent_id
from ..harnesslib import (
    HarnessError,
    HarnessPaths,
    RESERVING_CLAIM_STATUSES,
    atomic_write_bytes,
    bump_task,
    claims_owned_by_task,
    load_task,
    now_iso,
    sha256_file,
    state_lock,
    task_dir,
    validate_id,
    write_index,
    write_task,
)
from ..skill_lifecycle import (
    _json_nonnegative_int,
    _load_json_artifact,
    _parse_improvement_options,
    _require_project_result,
    _resolve_adoption_work_units,
    _resolve_improvement_occurrence,
    _skill_bundle_member_hashes,
    _valid_named_checks,
    _valid_skill_manifest_files,
)
from ..state_lookup import (
    _engaged_steward_lane,
    capacity_review_by_id,
    improvement_request_by_id,
    lane_by_id,
    require_open_task,
)


Handler = Callable[[argparse.Namespace, Any], int]
JsonArgumentRegistrar = Callable[[argparse.ArgumentParser], None]

_HANDLER_NAMES = frozenset(
    {
        "improvement_create",
        "improvement_brief",
        "improvement_arbitrate",
        "improvement_link_project",
        "skill_release_record",
        "skill_adoption_record",
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


class _ReadRegularArtifact(Protocol):
    def __call__(
        self,
        value: str | Path,
        label: str,
        *,
        max_bytes: int,
        require_utf8: bool = False,
    ) -> tuple[Path, bytes]: ...


class _RecordsFingerprint(Protocol):
    def __call__(self, records: list[dict[str, Any]]) -> str: ...


class _RequireDoneReviewerPacket(Protocol):
    def __call__(
        self,
        paths: HarnessPaths,
        state: dict[str, Any],
        packet_id: str,
        *,
        required_artifact_shas: set[str] | None = None,
    ) -> dict[str, Any]: ...


class _SkillReleaseSemanticIntegrityErrors(Protocol):
    def __call__(
        self,
        state: dict[str, Any],
        release: dict[str, Any],
        paths: HarnessPaths | None,
    ) -> list[str]: ...


@dataclass(frozen=True)
class ImprovementCmdServices:
    """CLI-resident helpers threaded into the relocated improvement bodies.

    Every field is direct-bound in ``cli._improvement_cmd_services()``: no name is
    fault-injected via ``mock.patch.object(cli, ...)`` nor rebound by
    ``apply_project_config``, so late binding is unnecessary.  The helpers remain
    defined in ``cli`` (shared with the capacity/packet/portfolio wiring and other
    command families) and are injected here to preserve one source of truth.
    """

    require_plan_ready: _RequirePlanReady
    require_root_session: _RequireRootSession
    read_regular_artifact: _ReadRegularArtifact
    records_fingerprint: _RecordsFingerprint
    require_done_reviewer_packet: _RequireDoneReviewerPacket
    skill_release_semantic_integrity_errors: _SkillReleaseSemanticIntegrityErrors


def _new_release_reviewer_agent_id(value: Any) -> str:
    """Require canonical identity for a newly persisted skill-release record."""

    try:
        return validate_agent_id(value, "skill release reviewer agent id")
    except AgentIdentityError as exc:
        raise HarnessError(
            "legacy reviewer packet has a non-canonical agent identity; "
            "create a new reviewer packet before recording a new skill release"
        ) from exc


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


def cmd_improvement_create(
    args: argparse.Namespace, paths: HarnessPaths, *, services: ImprovementCmdServices
) -> int:
    request_id = validate_id(args.request_id, "improvement request id")
    task_type = validate_id(args.task_type, "improvement task type")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "submit improvement request for")
        services.require_plan_ready(paths, state, "submit improvement request")
        if any(
            request.get("request_id") == request_id
            for request in state.get("improvement_requests", [])
        ):
            raise HarnessError(f"improvement request already exists: {request_id}")
        source_lane = lane_by_id(state, args.source_lane)
        steward = _engaged_steward_lane(state)
        occurrences = [_resolve_improvement_occurrence(state, item) for item in args.occurrence]
        references = [item["reference"] for item in occurrences]
        if len(references) != len(set(references)):
            raise HarnessError("improvement occurrences must be distinct")
        if args.trigger_class == "repeated_pain":
            if len(occurrences) < 3 or len({item["kind"] for item in occurrences}) < 2:
                raise HarnessError(
                    "repeated pain requires at least three occurrences across two work-unit kinds"
                )
        elif len(occurrences) != 1:
            raise HarnessError("critical single incident requires exactly one occurrence")
        recorded = now_iso()
        request = {
            "integrity_version": 1,
            "request_id": request_id,
            "version": 1,
            "status": "submitted",
            "trigger_class": args.trigger_class,
            "release_blocking": bool(args.release_blocking),
            "source_lane_id": source_lane["lane_id"],
            "source_lane_revision": source_lane["revision"],
            "steward_lane_id": steward["lane_id"],
            "task_type": task_type,
            "pain_statement": require_evidence_detail(
                args.pain_statement, "improvement pain statement"
            ),
            "desired_outcome": require_evidence_detail(
                args.desired_outcome, "improvement desired outcome"
            ),
            "occurrences": occurrences,
            "occurrence_fingerprint": services.records_fingerprint(occurrences),
            "brief": None,
            "chief_decision": None,
            "project": None,
            "release_ids": [],
            "events": [
                {
                    "event": "submitted",
                    "actor_lane": source_lane["lane_id"],
                    "recorded_at": recorded,
                }
            ],
            "created_at": recorded,
            "updated_at": recorded,
        }
        state["improvement_model_version"] = 1
        state.setdefault("improvement_requests", []).append(request)
        state.setdefault("skill_releases", [])
        state.setdefault("skill_adoption_events", [])
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(request, args.json)
    return 0


def cmd_improvement_brief(args: argparse.Namespace, paths: HarnessPaths) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "brief improvement request for")
        request = improvement_request_by_id(state, args.request_id)
        if request.get("version") != args.expected_version or request.get("status") != "submitted":
            raise HarnessError("improvement brief CAS/status gate failed")
        steward = _engaged_steward_lane(state)
        if steward.get("lane_id") != args.steward_lane_id:
            raise HarnessError("improvement brief must be issued by the engaged steward")
        capacity_reference = None
        if args.capacity_review_id:
            capacity = capacity_review_by_id(state, args.capacity_review_id)
            if capacity.get("scope", {}).get("target_lane_id") != request.get("source_lane_id"):
                raise HarnessError("capacity comparison targets a different department lane")
            capacity_reference = {
                "review_id": capacity["review_id"],
                "version": capacity["version"],
                "status": capacity["status"],
                "dataset_sha256": capacity.get("dataset", {}).get("sha256"),
            }
        recorded = now_iso()
        request["version"] = int(request["version"]) + 1
        request["status"] = "awaiting_chief"
        request["brief"] = {
            "steward_lane_id": steward["lane_id"],
            "options": _parse_improvement_options(args.option),
            "capacity_reference": capacity_reference,
            "recommendation": require_evidence_detail(
                args.recommendation, "improvement recommendation"
            ),
            "evidence_boundary": require_evidence_detail(
                args.evidence_boundary, "improvement evidence boundary"
            ),
            "recorded_at": recorded,
        }
        request["events"].append(
            {"event": "awaiting_chief", "actor_lane": steward["lane_id"], "recorded_at": recorded}
        )
        request["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(request, args.json)
    return 0


def cmd_improvement_arbitrate(
    args: argparse.Namespace, paths: HarnessPaths, *, services: ImprovementCmdServices
) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "arbitrate improvement request for")
        if any(
            item.get("status") == "needs_user"
            for item in state.get("needs_user_escalations", [])
        ):
            raise HarnessError(
                "unresolved needs-user escalation blocks improvement arbitration"
            )
        request = improvement_request_by_id(state, args.request_id)
        if (
            request.get("version") != args.expected_version
            or request.get("status") != "awaiting_chief"
        ):
            raise HarnessError("improvement arbitration CAS/status gate failed")
        session_id = services.require_root_session(paths, state, args.session_id)
        options = {
            item.get("option_id") for item in request.get("brief", {}).get("options", [])
        }
        selected = args.selected_option or ""
        if args.decision == "approved" and selected not in options:
            raise HarnessError("approved improvement requires a valid selected option")
        if args.decision == "rejected" and selected:
            raise HarnessError("rejected improvement may not select an option")
        recorded = now_iso()
        request["version"] = int(request["version"]) + 1
        request["status"] = "approved" if args.decision == "approved" else "rejected"
        request["chief_decision"] = {
            "decision_id": f"{request['request_id']}-chief-1",
            "decision": args.decision,
            "selected_option_id": selected,
            "rationale": require_evidence_detail(
                args.rationale, "improvement chief rationale"
            ),
            "root_owner": state.get("owner"),
            "root_session_id": session_id,
            "recorded_at": recorded,
        }
        request["events"].append(
            {"event": request["status"], "actor_lane": "chief", "recorded_at": recorded}
        )
        request["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(request, args.json)
    return 0


def cmd_improvement_link_project(
    args: argparse.Namespace, paths: HarnessPaths, *, services: ImprovementCmdServices
) -> int:
    project_task_id = validate_id(args.project_task_id, "improvement project task id")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "link improvement project for")
        request = improvement_request_by_id(state, args.request_id)
        if request.get("version") != args.expected_version or request.get("status") != "approved":
            raise HarnessError("improvement project link CAS/status gate failed")
        if (request.get("chief_decision") or {}).get("selected_option_id") != "skill-automation":
            raise HarnessError("only a chief-selected skill-automation option may create a project")
        if project_task_id == state.get("task_id"):
            raise HarnessError("improvement work must use an independent full harness task")
        _engaged_steward_lane(state)
        project = load_task(paths, project_task_id)
        if project.get("profile", "full") != "full":
            raise HarnessError("improvement project must use the full task profile")
        require_open_task(project, "serve as improvement project")
        services.require_plan_ready(paths, project, "link improvement project")
        if not any(
            claim.get("status") in RESERVING_CLAIM_STATUSES
            for claim in claims_owned_by_task(paths, project_task_id)
        ):
            raise HarnessError("improvement project must own at least one reserving claim")
        recorded = now_iso()
        request["version"] = int(request["version"]) + 1
        request["status"] = "delegated"
        request["project"] = {
            "task_id": project_task_id,
            "plan_sha256": project.get("plan_sha256"),
            "worktree": project.get("worktree"),
            "branch": project.get("branch"),
            "linked_at": recorded,
        }
        request["events"].append(
            {"event": "delegated", "actor_lane": "steward", "recorded_at": recorded}
        )
        request["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(request, args.json)
    return 0


def cmd_skill_release_record(
    args: argparse.Namespace, paths: HarnessPaths, *, services: ImprovementCmdServices
) -> int:
    release_id = validate_id(args.release_id, "skill release id")
    skill_id = validate_id(args.skill_id, "skill id")
    expected_bundle_sha = require_text(args.bundle_sha256, "skill bundle SHA-256").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_bundle_sha):
        raise HarnessError("skill bundle SHA-256 must be full 64 hex")
    skill_version = require_text(args.skill_version, "skill version")
    maintenance_owner = require_text(
        args.maintenance_owner, "skill maintenance owner"
    )
    rollback_plan = require_evidence_detail(args.rollback_plan, "skill rollback plan")
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "record skill release for")
        _engaged_steward_lane(state)
        request = improvement_request_by_id(state, args.request_id)
        if request.get("version") != args.expected_version or request.get("status") != "delegated":
            raise HarnessError("skill release CAS/status gate failed")
        if any(item.get("release_id") == release_id for item in state.get("skill_releases", [])):
            raise HarnessError(f"skill release already exists: {release_id}")
        project_task_id = request.get("project", {}).get("task_id")
        project = load_task(paths, str(project_task_id))
        if project.get("plan_sha256") != request.get("project", {}).get("plan_sha256"):
            raise HarnessError("linked improvement project plan changed")
        project_dir = task_dir(paths, str(project_task_id))
        bundle_source, bundle_data = services.read_regular_artifact(
            args.bundle, "skill bundle", max_bytes=32 * 1024 * 1024
        )
        manifest_source, manifest_data, manifest = _load_json_artifact(
            args.manifest, "skill release manifest", args.manifest_sha256
        )
        validation_source, validation_data, validation = _load_json_artifact(
            args.validation_receipt,
            "skill validation receipt",
            args.validation_receipt_sha256,
        )
        for source, label in (
            (bundle_source, "skill bundle"),
            (manifest_source, "skill release manifest"),
            (validation_source, "skill validation receipt"),
        ):
            _require_project_result(project_dir, source, label)
        bundle_sha = hashlib.sha256(bundle_data).hexdigest()
        validation_sha = hashlib.sha256(validation_data).hexdigest()
        bundle_members = _skill_bundle_member_hashes(bundle_data)
        if bundle_sha != expected_bundle_sha:
            raise HarnessError("skill bundle SHA-256 mismatch")
        if (
            manifest.get("skill_release_manifest_version") != 1
            or manifest.get("skill_id") != skill_id
            or manifest.get("skill_version") != skill_version
            or manifest.get("maintenance_owner") != maintenance_owner
            or manifest.get("rollback_plan") != rollback_plan
            or manifest.get("bundle_sha256") != bundle_sha
            or manifest.get("validation_receipt_sha256") != validation_sha
            or not _valid_skill_manifest_files(manifest.get("files"))
        ):
            raise HarnessError("skill release manifest contract is incomplete or inconsistent")
        manifest_members = {
            str(item["path"]): str(item["sha256"])
            for item in manifest["files"]
        }
        if manifest_members != bundle_members:
            raise HarnessError("skill release manifest does not match archive members and SHA-256")
        independent = validation.get("independent_review", {})
        review_packet_id = str(independent.get("review_packet_id", ""))
        if (
            validation.get("validation_version") != 1
            or validation.get("skill_creator_used") is not True
            or validation.get("structural_pass") is not True
            or validation.get("agents_metadata_consistent") is not True
            or validation.get("bundled_scripts_tested") is not True
            or not _valid_named_checks(validation.get("representative_project_fixtures"), 2)
            or not _valid_named_checks(validation.get("adversarial_fixtures"), 3)
            or not _valid_named_checks(validation.get("blind_forward_tests"), 2)
            or independent.get("status") != "pass"
            or not independent.get("evidence")
            or not review_packet_id
        ):
            raise HarnessError("skill validation receipt does not meet the release quality gate")
        required_artifact_shas = {
            bundle_sha,
            hashlib.sha256(manifest_data).hexdigest(),
            validation_sha,
        }
        review_packet = services.require_done_reviewer_packet(
            paths,
            project,
            review_packet_id,
            required_artifact_shas=required_artifact_shas,
        )
        reviewer_agent_id = _new_release_reviewer_agent_id(
            review_packet.get("agent_id")
        )
        project_records = [
            item
            for item in project.get("verification", [])
            if item.get("status") == "pass"
            and item.get("integrity_version") == 1
            and item.get("category") in {"skill_validation", "independent_review"}
            and required_artifact_shas.issubset(
                {ref.get("sha256") for ref in item.get("artifact_refs", [])}
            )
        ]
        if (
            len(project_records) != 2
            or {item.get("category") for item in project_records}
            != {"skill_validation", "independent_review"}
        ):
            raise HarnessError(
                "linked project requires candidate-bound skill_validation and independent_review records"
            )
        independent_record = next(
            item
            for item in project_records
            if item.get("category") == "independent_review"
        )
        if (
            independent_record.get("review_packet_id") != review_packet["packet_id"]
            or independent_record.get("review_result_sha256")
            != review_packet.get("result_sha256")
            or independent_record.get("reviewer_agent_id")
            != reviewer_agent_id
        ):
            raise HarnessError(
                "independent review verification is not bound to the reviewer result identity"
            )
        destination_root = task_dir(paths, args.task) / "results"
        bundle_snapshot = destination_root / f"skill-release-{release_id}.bundle"
        manifest_snapshot = destination_root / f"skill-release-{release_id}.manifest.json"
        validation_snapshot = destination_root / f"skill-release-{release_id}.validation.json"
        atomic_write_bytes(bundle_snapshot, bundle_data)
        atomic_write_bytes(manifest_snapshot, manifest_data)
        atomic_write_bytes(validation_snapshot, validation_data)
        for destination in (bundle_snapshot, manifest_snapshot, validation_snapshot):
            os.chmod(destination, 0o600)
        recorded = now_iso()
        release = {
            "integrity_version": 1,
            "release_id": release_id,
            "request_id": request["request_id"],
            "project_task_id": project_task_id,
            "skill_id": skill_id,
            "skill_version": skill_version,
            "maintenance_owner": maintenance_owner,
            "rollback_plan": rollback_plan,
            "status": "release_candidate",
            "bundle_path": str(bundle_snapshot),
            "bundle_sha256": bundle_sha,
            "bundle_size_bytes": len(bundle_data),
            "manifest_path": str(manifest_snapshot),
            "manifest_sha256": sha256_file(manifest_snapshot),
            "validation_path": str(validation_snapshot),
            "validation_sha256": sha256_file(validation_snapshot),
            "independent_review": {
                "review_packet_id": review_packet["packet_id"],
                "review_result_sha256": review_packet["result_sha256"],
                "reviewer_agent_id": reviewer_agent_id,
            },
            "recorded_at": recorded,
        }
        state.setdefault("skill_releases", []).append(release)
        request["release_ids"].append(release_id)
        request["version"] = int(request["version"]) + 1
        request["status"] = "release_candidate"
        request["events"].append(
            {"event": "release_candidate", "actor_lane": "steward", "recorded_at": recorded}
        )
        request["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(release, args.json)
    return 0


def cmd_skill_adoption_record(
    args: argparse.Namespace, paths: HarnessPaths, *, services: ImprovementCmdServices
) -> int:
    with state_lock(paths):
        state = load_task(paths, args.task)
        require_open_task(state, "record skill adoption decision for")
        request = improvement_request_by_id(state, args.request_id)
        if request.get("version") != args.expected_version:
            raise HarnessError("skill adoption CAS failed")
        releases = [
            item for item in state.get("skill_releases", []) if item.get("release_id") == args.release_id
        ]
        if len(releases) != 1 or args.release_id not in request.get("release_ids", []):
            raise HarnessError("skill release does not belong to this improvement request")
        release = releases[0]
        for path_field, sha_field in (
            ("bundle_path", "bundle_sha256"),
            ("manifest_path", "manifest_sha256"),
            ("validation_path", "validation_sha256"),
        ):
            release_path = Path(str(release.get(path_field, "")))
            if (
                not release_path.is_file()
                or release_path.is_symlink()
                or sha256_file(release_path) != release.get(sha_field)
            ):
                raise HarnessError("skill release artifact is missing or tampered")
        release_errors = services.skill_release_semantic_integrity_errors(state, release, paths)
        if release_errors:
            raise HarnessError("; ".join(release_errors))
        allowed = {
            "release_candidate": {"canary"},
            "canary": {"adopt", "pause", "rollback"},
            "paused": {"canary", "rollback", "deprecate"},
            "adopted": {"pause", "rollback", "deprecate"},
        }
        if args.action not in allowed.get(str(request.get("status")), set()):
            raise HarnessError(
                f"invalid skill adoption transition {request.get('status')} -> {args.action}"
            )
        session_id = services.require_root_session(paths, state, args.session_id)
        _, evidence_data, evidence_payload = _load_json_artifact(
            args.evidence_artifact, "skill adoption evidence", args.evidence_sha256
        )
        if evidence_payload.get("adoption_receipt_version") != 1:
            raise HarnessError("skill adoption evidence has an unsupported schema")
        if (
            evidence_payload.get("request_id") != request["request_id"]
            or evidence_payload.get("release_id") != release["release_id"]
            or evidence_payload.get("skill_version") != release["skill_version"]
            or evidence_payload.get("action") != args.action
        ):
            raise HarnessError("skill adoption evidence is bound to a different release")
        skill_work_unit_bindings: list[dict[str, Any]] = []
        baseline_work_unit_bindings: list[dict[str, Any]] = []
        bound_canary_event_id = ""
        if args.action == "canary":
            if (
                _json_nonnegative_int(evidence_payload, "planned_skill_units") < 3
                or not str(evidence_payload.get("rollback_plan", "")).strip()
            ):
                raise HarnessError("skill canary requires at least three units and a rollback plan")
        if args.action == "adopt":
            canary_events = [
                item
                for item in state.get("skill_adoption_events", [])
                if item.get("release_id") == release["release_id"]
                and item.get("action") == "canary"
            ]
            if (
                not canary_events
                or evidence_payload.get("canary_event_id")
                != canary_events[-1].get("event_id")
            ):
                raise HarnessError("skill adoption evidence is not bound to the current canary")
            canary_event = canary_events[-1]
            bound_canary_event_id = str(canary_event["event_id"])
            skill_work_unit_bindings = _resolve_adoption_work_units(
                state,
                evidence_payload.get("skill_work_units"),
                label="skill canary",
                minimum=3,
                canary_recorded_at=str(canary_event.get("recorded_at", "")),
                require_after_canary=True,
                expected_skill_release_id=str(release.get("release_id", "")),
                expected_skill_version=str(release.get("skill_version", "")),
                expected_canary_event_id=bound_canary_event_id,
            )
            if _json_nonnegative_int(evidence_payload, "skill_units") != len(
                skill_work_unit_bindings
            ):
                raise HarnessError(
                    "skill_units must equal the number of bound skill_work_units"
                )
            if evidence_payload.get("efficiency_claim") is True:
                baseline_work_unit_bindings = _resolve_adoption_work_units(
                    state,
                    evidence_payload.get("baseline_work_units"),
                    label="skill baseline",
                    minimum=3,
                    canary_recorded_at=str(canary_event.get("recorded_at", "")),
                    require_after_canary=False,
                )
                if _json_nonnegative_int(evidence_payload, "baseline_units") != len(
                    baseline_work_unit_bindings
                ):
                    raise HarnessError(
                        "baseline_units must equal the number of bound baseline_work_units"
                    )
                if {
                    item["identity_sha256"] for item in skill_work_unit_bindings
                } & {
                    item["identity_sha256"] for item in baseline_work_unit_bindings
                }:
                    raise HarnessError(
                        "skill and baseline work units must have disjoint durable identities"
                    )
            if (
                evidence_payload.get("success_criteria_met") is not True
                or _json_nonnegative_int(evidence_payload, "quality_regressions") != 0
                or evidence_payload.get("rollback_path_verified") is not True
            ):
                raise HarnessError("skill adoption evidence does not meet the canary quality gate")
        if args.action in {"pause", "rollback", "deprecate"}:
            require_evidence_detail(
                str(evidence_payload.get("reason", "")), "skill adoption action reason"
            )
        recorded = now_iso()
        evidence_snapshot = (
            task_dir(paths, args.task)
            / "results"
            / f"skill-adoption-{args.release_id}-{len(state.get('skill_adoption_events', [])) + 1}.json"
        )
        atomic_write_bytes(evidence_snapshot, evidence_data)
        os.chmod(evidence_snapshot, 0o600)
        status_map = {
            "canary": "canary",
            "adopt": "adopted",
            "pause": "paused",
            "rollback": "rolled_back",
            "deprecate": "deprecated",
        }
        event = {
            "integrity_version": 1,
            "event_id": f"{args.release_id}-adoption-{len(state.get('skill_adoption_events', [])) + 1}",
            "request_id": request["request_id"],
            "release_id": args.release_id,
            "action": args.action,
            "resulting_status": status_map[args.action],
            "evidence_path": str(evidence_snapshot),
            "evidence_sha256": sha256_file(evidence_snapshot),
            "rationale": require_evidence_detail(args.rationale, "skill adoption rationale"),
            "root_owner": state.get("owner"),
            "root_session_id": session_id,
            "recorded_at": recorded,
        }
        if args.action == "adopt":
            event["canary_event_id"] = bound_canary_event_id
            event["skill_work_unit_bindings"] = skill_work_unit_bindings
            event["baseline_work_unit_bindings"] = baseline_work_unit_bindings
        state.setdefault("skill_adoption_events", []).append(event)
        request["version"] = int(request["version"]) + 1
        request["status"] = event["resulting_status"]
        request["events"].append(
            {"event": event["resulting_status"], "actor_lane": "chief", "recorded_at": recorded}
        )
        request["updated_at"] = recorded
        release["status"] = event["resulting_status"]
        release["updated_at"] = recorded
        bump_task(state)
        write_task(paths, state)
        write_index(paths)
    emit(event, args.json)
    return 0


def register_improvement_commands(
    subparsers: Any,
    *,
    handlers: Mapping[str, Handler],
    add_json_argument: JsonArgumentRegistrar,
    vocab: Any,
) -> None:
    """Register the improvement and skill command family on one subparser set."""

    missing = sorted(_HANDLER_NAMES - handlers.keys())
    unexpected = sorted(handlers.keys() - _HANDLER_NAMES)
    if missing or unexpected:
        raise ValueError(
            "improvement command handler map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    parser = subparsers.add_parser("improvement-create")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--source-lane", required=True)
    parser.add_argument("--task-type", required=True)
    parser.add_argument(
        "--trigger-class",
        choices=sorted(vocab.improvement_trigger_classes),
        required=True,
    )
    parser.add_argument("--pain-statement", required=True)
    parser.add_argument("--desired-outcome", required=True)
    parser.add_argument("--occurrence", action="append", default=[], required=True)
    parser.add_argument("--release-blocking", action="store_true")
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["improvement_create"])

    parser = subparsers.add_parser("improvement-brief")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--steward-lane-id", required=True)
    parser.add_argument("--option", action="append", default=[], required=True)
    parser.add_argument("--capacity-review-id")
    parser.add_argument("--recommendation", required=True)
    parser.add_argument("--evidence-boundary", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["improvement_brief"])

    parser = subparsers.add_parser("improvement-arbitrate")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--decision", choices=["approved", "rejected"], required=True)
    parser.add_argument(
        "--selected-option", choices=sorted(vocab.improvement_option_ids)
    )
    parser.add_argument("--rationale", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["improvement_arbitrate"])

    parser = subparsers.add_parser("improvement-link-project")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--project-task-id", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["improvement_link_project"])

    parser = subparsers.add_parser("skill-release-record")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--skill-id", required=True)
    parser.add_argument("--skill-version", required=True)
    parser.add_argument("--maintenance-owner", required=True)
    parser.add_argument("--rollback-plan", required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--validation-receipt", required=True)
    parser.add_argument("--validation-receipt-sha256", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["skill_release_record"])

    parser = subparsers.add_parser("skill-adoption-record")
    parser.add_argument("--task", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--expected-version", type=int, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument(
        "--action", choices=sorted(vocab.skill_adoption_actions), required=True
    )
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--evidence-artifact", required=True)
    parser.add_argument("--evidence-sha256", required=True)
    parser.add_argument("--rationale", required=True)
    add_json_argument(parser)
    parser.set_defaults(handler=handlers["skill_adoption_record"])


__all__ = [
    "ImprovementCmdServices",
    "cmd_improvement_arbitrate",
    "cmd_improvement_brief",
    "cmd_improvement_create",
    "cmd_improvement_link_project",
    "cmd_skill_adoption_record",
    "cmd_skill_release_record",
    "register_improvement_commands",
]
