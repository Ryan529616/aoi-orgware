"""Portfolio-wide lane, dependency, and execution-governance integrity checks.

The CLI remains the composition root.  ``portfolio_integrity_errors`` is the
highest fan-in validator in the harness: it fences lanes, lane dependencies,
coordination requests, integration baselines, capacity reviews, improvement and
skill-release records, execution selections and briefs, and the packet/job
execution topology in a single pass.  Two families of composition-root state are
supplied explicitly so this module never observes stale CLI globals:

* Project vocabulary and ceilings (lane/dependency/coordination/improvement/
  execution status sets, the capability catalog, and the engaged-lane ceiling)
  arrive through the frozen :class:`PortfolioIntegrityPolicy`, snapshotted fresh
  each call by ``cli._portfolio_integrity_policy()``.
* CLI-resident authority and derived-state operations (occurrence fingerprints,
  Steward packet bindings, skill-release semantics, packet/job activation
  topology, and job-launch authority) arrive through the frozen
  :class:`PortfolioIntegrityServices`.

Every other dependency (identifier validation, file hashing, execution-policy
version, Steward-synthesis and active-selection predicates, skill-adoption and
skill-canary checks) is imported from a sibling package.  This module imports
only sibling packages and never imports :mod:`aoi_orgware.cli`.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping, Set
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from .execution_policy import _execution_policy_v2_enabled
from .execution_topology import (
    _is_steward_synthesis_packet,
    _validate_active_execution_selection,
)
from .git_plumbing import FULL_COMMIT_RE
from .harnesslib import (
    ACTIVE_JOB_STATUSES,
    ACTIVE_PACKET_STATUSES,
    HarnessError,
    HarnessPaths,
    sha256_file,
    validate_id,
)
from .skill_lifecycle import (
    _skill_adoption_semantic_integrity_errors,
    _validate_skill_canary_work_unit_binding,
)
from .state_lookup import ENGAGED_LANE_STATUSES


@dataclass(frozen=True)
class PortfolioIntegrityPolicy:
    """Immutable project vocabulary and ceilings required by portfolio checks."""

    lane_kinds: Set[str]
    lane_statuses: Set[str]
    max_engaged_lanes: int
    dependency_kinds: Set[str]
    dependency_statuses: Set[str]
    coordination_statuses: Set[str]
    close_qualifying_categories: Set[str]
    capability_catalog_version: int
    capability_tier_map: Mapping[str, str]
    improvement_statuses: Set[str]
    improvement_trigger_classes: Set[str]
    execution_modes: Set[str]
    executing_packet_statuses: Set[str]
    cross_lane_session_statuses: Set[str]
    needs_user_statuses: Set[str]
    needs_user_categories: Set[str]

    def __post_init__(self) -> None:
        for field in (
            "lane_kinds",
            "lane_statuses",
            "dependency_kinds",
            "dependency_statuses",
            "coordination_statuses",
            "close_qualifying_categories",
            "improvement_statuses",
            "improvement_trigger_classes",
            "execution_modes",
            "executing_packet_statuses",
            "cross_lane_session_statuses",
            "needs_user_statuses",
            "needs_user_categories",
        ):
            object.__setattr__(self, field, frozenset(getattr(self, field)))


class RecordsFingerprint(Protocol):
    def __call__(self, records: list[dict[str, Any]]) -> str: ...


class StewardPacketBinding(Protocol):
    def __call__(
        self, state: dict[str, Any], selection_id: str, packet_id: str
    ) -> dict[str, Any]: ...


class SkillReleaseSemanticIntegrityErrors(Protocol):
    def __call__(
        self,
        state: dict[str, Any],
        release: dict[str, Any],
        paths: HarnessPaths | None,
    ) -> list[str]: ...


class ValidatePacketActivationTopology(Protocol):
    def __call__(
        self, state: dict[str, Any], packet: dict[str, Any]
    ) -> dict[str, Any] | None: ...


class ValidateJobActivationTopology(Protocol):
    def __call__(
        self,
        state: dict[str, Any],
        job: dict[str, Any],
        selection: dict[str, Any] | None,
        *,
        paths: HarnessPaths | None = ...,
        exclude_run_id: str = ...,
    ) -> dict[str, Any] | None: ...


class JobLaunchAuthorityErrors(Protocol):
    def __call__(
        self, state: dict[str, Any], job: dict[str, Any]
    ) -> list[str]: ...


@dataclass(frozen=True)
class PortfolioIntegrityServices:
    """CLI-resident authority and derived-state operations for portfolio checks."""

    records_fingerprint: RecordsFingerprint
    steward_packet_binding: StewardPacketBinding
    skill_release_semantic_integrity_errors: SkillReleaseSemanticIntegrityErrors
    validate_packet_activation_topology: ValidatePacketActivationTopology
    validate_job_activation_topology: ValidateJobActivationTopology
    job_launch_authority_errors: JobLaunchAuthorityErrors


def _is_exact_int(value: Any, expected: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == expected


def canonical_record_sha256(value: dict[str, Any]) -> str:
    payload = json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _hard_dependency_cycle(dependencies: list[dict[str, Any]]) -> bool:
    graph: dict[str, set[str]] = {}
    for dependency in dependencies:
        if dependency.get("kind") != "hard_gate" or dependency.get("status") == "superseded":
            continue
        source = str(dependency.get("source_lane", ""))
        target = str(dependency.get("target_lane", ""))
        graph.setdefault(source, set()).add(target)
        graph.setdefault(target, set())
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        if any(visit(target) for target in graph.get(node, set())):
            return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in sorted(graph))


def portfolio_integrity_errors(
    state: dict[str, Any],
    paths: HarnessPaths | None = None,
    *,
    policy: PortfolioIntegrityPolicy,
    services: PortfolioIntegrityServices,
) -> list[str]:
    if not any(
        key in state
        for key in (
            "lane_model_version",
            "lanes",
            "lane_dependencies",
            "coordination_requests",
            "integration_baselines",
            "capacity_reviews",
            "improvement_requests",
            "skill_releases",
            "skill_adoption_events",
            "execution_selections",
            "cross_lane_sessions",
            "needs_user_escalations",
        )
    ):
        return []
    errors: list[str] = []
    if state.get("lane_model_version") != 1:
        errors.append("lane portfolio requires lane_model_version=1")
    lanes = state.get("lanes", [])
    if not isinstance(lanes, list):
        return [*errors, "lanes must be a list"]
    lane_ids: set[str] = set()
    engaged = 0
    for lane in lanes:
        if not isinstance(lane, dict):
            errors.append("lane entry is not an object")
            continue
        lane_id = str(lane.get("lane_id", ""))
        try:
            validate_id(lane_id, "lane id")
        except HarnessError as exc:
            errors.append(str(exc))
            continue
        if lane_id in lane_ids:
            errors.append(f"duplicate lane id {lane_id}")
        lane_ids.add(lane_id)
        if lane.get("integrity_version") != 1:
            errors.append(f"lane {lane_id} lacks integrity_version=1")
        if lane.get("kind") not in policy.lane_kinds:
            errors.append(f"lane {lane_id} has invalid kind {lane.get('kind')!r}")
        if lane.get("status") not in policy.lane_statuses:
            errors.append(f"lane {lane_id} has invalid status {lane.get('status')!r}")
        if lane.get("status") in ENGAGED_LANE_STATUSES:
            engaged += 1
        if not isinstance(lane.get("revision"), int) or int(lane.get("revision", 0)) < 1:
            errors.append(f"lane {lane_id} has invalid revision")
        if not FULL_COMMIT_RE.fullmatch(str(lane.get("authority_commit", ""))):
            errors.append(f"lane {lane_id} has invalid authority commit")
        for field in ("owner", "role", "contract_version", "next_action"):
            if not str(lane.get(field, "")).strip():
                errors.append(f"lane {lane_id} has empty {field}")
        revisions = lane.get("revisions", [])
        if not isinstance(revisions, list) or len(revisions) != lane.get("revision"):
            errors.append(f"lane {lane_id} revision history is not contiguous")
        elif revisions and revisions[-1].get("revision") != lane.get("revision"):
            errors.append(f"lane {lane_id} current revision differs from history tail")
    if engaged > policy.max_engaged_lanes:
        errors.append(
            f"engaged lane count {engaged} exceeds hard ceiling {policy.max_engaged_lanes}"
        )

    dependencies = state.get("lane_dependencies", [])
    if not isinstance(dependencies, list):
        errors.append("lane_dependencies must be a list")
        dependencies = []
    dependency_ids: set[str] = set()
    for dependency in dependencies:
        dependency_id = str(dependency.get("dependency_id", ""))
        if dependency_id in dependency_ids:
            errors.append(f"duplicate dependency id {dependency_id}")
        dependency_ids.add(dependency_id)
        source = dependency.get("source_lane")
        target = dependency.get("target_lane")
        if source not in lane_ids or target not in lane_ids:
            errors.append(f"dependency {dependency_id} references missing lane")
        if source == target:
            errors.append(f"dependency {dependency_id} is a self-edge")
        if dependency.get("kind") not in policy.dependency_kinds:
            errors.append(f"dependency {dependency_id} has invalid kind")
        if dependency.get("status") not in policy.dependency_statuses:
            errors.append(f"dependency {dependency_id} has invalid status")
    if _hard_dependency_cycle(dependencies):
        errors.append("active hard-gate dependency graph contains a cycle")

    request_ids: set[str] = set()
    for request in state.get("coordination_requests", []):
        request_id = str(request.get("request_id", ""))
        if request_id in request_ids:
            errors.append(f"duplicate coordination request id {request_id}")
        request_ids.add(request_id)
        if request.get("source_lane") not in lane_ids or request.get("target_lane") not in lane_ids:
            errors.append(f"coordination request {request_id} references missing lane")
        if request.get("source_lane") == request.get("target_lane"):
            errors.append(f"coordination request {request_id} targets its source lane")
        if request.get("status") not in policy.coordination_statuses:
            errors.append(f"coordination request {request_id} has invalid status")
        if request.get("severity") not in policy.dependency_kinds:
            errors.append(f"coordination request {request_id} has invalid severity")
        if not isinstance(request.get("version"), int) or int(request.get("version", 0)) < 1:
            errors.append(f"coordination request {request_id} has invalid version")
        if request.get("decision_class", "formal_technical") != "formal_technical":
            errors.append(f"coordination request {request_id} has invalid decision class")
        if request.get("closure_category", "integration_test") not in policy.close_qualifying_categories:
            errors.append(f"coordination request {request_id} has invalid closure category")
        if request.get("status") in {"accepted", "resolved"}:
            directive_lanes = {
                item.get("target_lane") for item in request.get("directives", [])
            }
            if directive_lanes != {request.get("source_lane"), request.get("target_lane")}:
                errors.append(f"coordination request {request_id} lacks all affected-lane directives")
        if request.get("status") == "resolved":
            resolution = request.get("resolution", {})
            verifications = request.get("verification_attempts", [])
            implementations = request.get("implementation_attempts", [])
            if (
                not verifications
                or not implementations
                or verifications[-1].get("status") != "pass"
                or resolution.get("verification_id") != verifications[-1].get("verification_id")
                or resolution.get("implementation_attempt_id")
                != implementations[-1].get("attempt_id")
            ):
                errors.append(f"coordination request {request_id} resolution lacks bound verification")

    baseline_ids: set[str] = set()
    for baseline in state.get("integration_baselines", []):
        baseline_id = str(baseline.get("baseline_id", ""))
        if baseline_id in baseline_ids:
            errors.append(f"duplicate baseline id {baseline_id}")
        baseline_ids.add(baseline_id)
        if baseline.get("integrity_version") != 1:
            errors.append(f"baseline {baseline_id} lacks integrity_version=1")
        expected_baseline_sha = str(baseline.get("baseline_sha256", ""))
        baseline_payload = {
            key: value for key, value in baseline.items() if key != "baseline_sha256"
        }
        actual_baseline_sha = hashlib.sha256(
            json.dumps(
                baseline_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        if (
            not re.fullmatch(r"[0-9a-f]{64}", expected_baseline_sha)
            or expected_baseline_sha != actual_baseline_sha
        ):
            errors.append(f"baseline {baseline_id} SHA-256 identity is invalid")
        snapshots = baseline.get("lane_snapshots", [])
        if not isinstance(snapshots, list) or not snapshots:
            errors.append(f"baseline {baseline_id} has no lane snapshots")
    reviews = state.get("capacity_reviews", [])
    if not isinstance(reviews, list):
        errors.append("capacity_reviews must be a list")
        reviews = []
    if reviews and state.get("capacity_planning_version") != 1:
        errors.append("capacity reviews require capacity_planning_version=1")
    review_ids: set[str] = set()
    for review in reviews:
        review_id = str(review.get("review_id", ""))
        if review_id in review_ids:
            errors.append(f"duplicate capacity review id {review_id}")
        review_ids.add(review_id)
        if review.get("integrity_version") != 1:
            errors.append(f"capacity review {review_id} lacks integrity_version=1")
        if review.get("status") not in {
            "data_ready",
            "awaiting_chief",
            "approved",
            "rejected",
            "distributed",
            "acknowledged",
            "consumed",
            "superseded",
        }:
            errors.append(f"capacity review {review_id} has invalid status")
        if not isinstance(review.get("version"), int) or int(review.get("version", 0)) < 1:
            errors.append(f"capacity review {review_id} has invalid version")
        dataset = review.get("dataset", {})
        dataset_path = Path(str(dataset.get("path", "")))
        dataset_sha = str(dataset.get("sha256", ""))
        if (
            not dataset_path.is_file()
            or dataset_path.is_symlink()
            or not re.fullmatch(r"[0-9a-f]{64}", dataset_sha)
        ):
            errors.append(f"capacity review {review_id} dataset identity is missing")
        elif sha256_file(dataset_path) != dataset_sha:
            errors.append(f"capacity review {review_id} dataset SHA-256 mismatch")
        else:
            # The on-disk dataset is sha-anchored, so its fields cannot be
            # edited silently; use it to stop the in-state review from being
            # stripped back to a pre-typed-outcome shape (sample-gate evasion
            # by deleting keys rather than falsifying them).
            try:
                dataset_file = json.loads(dataset_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                dataset_file = None
                errors.append(
                    f"capacity review {review_id} dataset file is unreadable"
                )
            if isinstance(dataset_file, dict) and "eligible_record_count" in dataset_file:
                if dataset.get("eligible_record_count") != dataset_file.get(
                    "eligible_record_count"
                ):
                    errors.append(
                        f"capacity review {review_id} eligible record count "
                        "diverges from its sha-anchored dataset file"
                    )
                recommendation_view = review.get("recommendation")
                if recommendation_view is not None and (
                    "phase" not in recommendation_view
                    or "sample_boundary" not in recommendation_view
                ):
                    errors.append(
                        f"capacity review {review_id} recommendation lacks the "
                        "phase/sample-boundary contract its dataset version requires"
                    )
        if review.get("catalog_version") != policy.capability_catalog_version:
            errors.append(f"capacity review {review_id} catalog version is unsupported")
        recommendation = review.get("recommendation")
        if recommendation is not None and (
            recommendation.get("capability_tier") not in policy.capability_tier_map
            or policy.capability_tier_map.get(recommendation.get("capability_tier"))
            != recommendation.get("requested_model_tier")
        ):
            errors.append(f"capacity review {review_id} recommendation is inconsistent")
        if recommendation is not None and "sample_boundary" in recommendation:
            sample_boundary = recommendation.get("sample_boundary")
            if (
                not isinstance(sample_boundary, dict)
                or not isinstance(sample_boundary.get("min_eligible_records"), int)
                or isinstance(sample_boundary.get("min_eligible_records"), bool)
                or cast(int, sample_boundary.get("min_eligible_records")) < 1
                or not isinstance(
                    sample_boundary.get("eligible_record_count"), int
                )
                or isinstance(sample_boundary.get("eligible_record_count"), bool)
                or cast(int, sample_boundary.get("eligible_record_count"))
                < cast(int, sample_boundary.get("min_eligible_records"))
                or recommendation.get("phase") != "recommendation_only"
            ):
                errors.append(
                    f"capacity review {review_id} sample boundary is malformed "
                    "or below its declared minimum"
                )
        if review.get("status") in {"approved", "distributed", "acknowledged", "consumed"}:
            decision = review.get("chief_decision", {})
            if decision.get("decision") != "approved" or not decision.get("root_session_id"):
                errors.append(f"capacity review {review_id} lacks chief approval")
        if review.get("status") in {"distributed", "acknowledged", "consumed"} and not review.get(
            "distribution"
        ):
            errors.append(f"capacity review {review_id} lacks steward distribution")
        if review.get("status") in {"acknowledged", "consumed"} and not review.get(
            "acknowledgement"
        ):
            errors.append(f"capacity review {review_id} lacks target acknowledgement")
        if review.get("status") == "consumed" and not review.get("consumption"):
            errors.append(f"capacity review {review_id} lacks packet consumption")

    improvements = state.get("improvement_requests", [])
    releases = state.get("skill_releases", [])
    adoption_events = state.get("skill_adoption_events", [])
    if any((improvements, releases, adoption_events)) and state.get("improvement_model_version") != 1:
        errors.append("improvement records require improvement_model_version=1")
    if not isinstance(improvements, list):
        errors.append("improvement_requests must be a list")
        improvements = []
    if not isinstance(releases, list):
        errors.append("skill_releases must be a list")
        releases = []
    if not isinstance(adoption_events, list):
        errors.append("skill_adoption_events must be a list")
        adoption_events = []
    improvement_ids: set[str] = set()
    for request in improvements:
        request_id = str(request.get("request_id", ""))
        if request_id in improvement_ids:
            errors.append(f"duplicate improvement request id {request_id}")
        improvement_ids.add(request_id)
        if request.get("integrity_version") != 1:
            errors.append(f"improvement request {request_id} lacks integrity_version=1")
        if request.get("status") not in policy.improvement_statuses:
            errors.append(f"improvement request {request_id} has invalid status")
        if request.get("trigger_class") not in policy.improvement_trigger_classes:
            errors.append(f"improvement request {request_id} has invalid trigger class")
        occurrences = request.get("occurrences", [])
        if (
            not isinstance(occurrences, list)
            or not occurrences
            or request.get("occurrence_fingerprint") != services.records_fingerprint(occurrences)
        ):
            errors.append(f"improvement request {request_id} occurrence identity is invalid")
        if not isinstance(request.get("version"), int) or int(request.get("version", 0)) < 1:
            errors.append(f"improvement request {request_id} has invalid version")
        if request.get("status") not in {"submitted", "awaiting_chief"} and not request.get(
            "chief_decision"
        ):
            errors.append(f"improvement request {request_id} lacks chief decision")
    release_ids: set[str] = set()
    for release in releases:
        release_id = str(release.get("release_id", ""))
        if release_id in release_ids:
            errors.append(f"duplicate skill release id {release_id}")
        release_ids.add(release_id)
        if release.get("request_id") not in improvement_ids:
            errors.append(f"skill release {release_id} references missing improvement request")
        for path_field, sha_field in (
            ("bundle_path", "bundle_sha256"),
            ("manifest_path", "manifest_sha256"),
            ("validation_path", "validation_sha256"),
        ):
            artifact_path = Path(str(release.get(path_field, "")))
            artifact_sha = str(release.get(sha_field, ""))
            if (
                not artifact_path.is_file()
                or artifact_path.is_symlink()
                or not re.fullmatch(r"[0-9a-f]{64}", artifact_sha)
                or sha256_file(artifact_path) != artifact_sha
            ):
                errors.append(f"skill release {release_id} {path_field} identity is invalid")
        errors.extend(services.skill_release_semantic_integrity_errors(state, release, paths))
    event_ids: set[str] = set()
    for event in adoption_events:
        event_id = str(event.get("event_id", ""))
        if event_id in event_ids:
            errors.append(f"duplicate skill adoption event id {event_id}")
        event_ids.add(event_id)
        if event.get("release_id") not in release_ids:
            errors.append(f"skill adoption event {event_id} references missing release")
        evidence_path = Path(str(event.get("evidence_path", "")))
        evidence_sha = str(event.get("evidence_sha256", ""))
        if (
            not evidence_path.is_file()
            or evidence_path.is_symlink()
            or not re.fullmatch(r"[0-9a-f]{64}", evidence_sha)
            or sha256_file(evidence_path) != evidence_sha
        ):
            errors.append(f"skill adoption event {event_id} evidence identity is invalid")
        errors.extend(_skill_adoption_semantic_integrity_errors(state, event))

    selections = state.get("execution_selections", [])
    cross_sessions = state.get("cross_lane_sessions", [])
    escalations = state.get("needs_user_escalations", [])
    if any((selections, cross_sessions, escalations)) and state.get("execution_model_version") != 1:
        errors.append("execution governance records require execution_model_version=1")
    try:
        policy_v2 = _execution_policy_v2_enabled(state)
    except HarnessError as exc:
        errors.append(str(exc))
        policy_v2 = False
    selection_ids: set[str] = set()
    active_work_units: set[str] = set()
    for selection in selections:
        selection_id = str(selection.get("selection_id", ""))
        if selection_id in selection_ids:
            errors.append(f"duplicate execution selection id {selection_id}")
        selection_ids.add(selection_id)
        status = selection.get("status")
        work_unit_id = str(selection.get("work_unit_id", ""))
        try:
            validate_id(work_unit_id, "execution work-unit id")
        except HarnessError as exc:
            errors.append(f"execution selection {selection_id}: {exc}")
        if status not in {"active", "superseded"}:
            errors.append(f"execution selection {selection_id} has invalid status")
        if status == "active":
            if work_unit_id in active_work_units:
                errors.append(
                    f"multiple active execution selections exist for work unit {work_unit_id}"
                )
            active_work_units.add(work_unit_id)
            if selection.get("superseded_by"):
                errors.append(
                    f"active execution selection {selection_id} unexpectedly names a successor"
                )
        if status == "superseded" and not selection.get("superseded_by"):
            errors.append(
                f"superseded execution selection {selection_id} lacks successor identity"
            )
        mode = selection.get("mode")
        snapshots = selection.get("lane_snapshots", [])
        selection_version = selection.get("execution_selection_version")
        if policy_v2 and not _is_exact_int(selection_version, 2):
            errors.append(
                f"execution selection {selection_id} is not sealed as version 2 "
                "under task execution policy v2"
            )
        elif selection_version is None and "steward_snapshot" in selection:
            errors.append(
                f"execution selection {selection_id} has v2-only fields without a selection version"
            )
        if selection_version is not None and not _is_exact_int(selection_version, 2):
            errors.append(
                f"execution selection {selection_id} has an invalid selection version"
            )
        if mode not in policy.execution_modes:
            errors.append(f"execution selection {selection_id} has invalid mode")
        if mode == "single" and len(snapshots) != 1:
            errors.append(f"execution selection {selection_id} single mode is not one lane")
        if mode in {"centralized_parallel", "hybrid"} and len(snapshots) < 2:
            errors.append(f"execution selection {selection_id} parallel mode lacks lanes")
        snapshot_lane_ids = [str(item.get("lane_id", "")) for item in snapshots]
        if len(snapshot_lane_ids) != len(set(snapshot_lane_ids)):
            errors.append(f"execution selection {selection_id} repeats a lane snapshot")
        for snapshot in snapshots:
            if snapshot.get("lane_id") not in lane_ids:
                errors.append(f"execution selection {selection_id} references missing lane")
        if _is_exact_int(selection_version, 2):
            steward_snapshot = selection.get("steward_snapshot")
            if mode == "single" and steward_snapshot != {}:
                errors.append(
                    f"execution selection {selection_id} single mode carries a Steward snapshot"
                )
            if mode in {"centralized_parallel", "hybrid"}:
                if not isinstance(steward_snapshot, dict) or not steward_snapshot:
                    errors.append(
                        f"execution selection {selection_id} parallel mode lacks a Steward snapshot"
                    )
                else:
                    steward_lane_id = steward_snapshot.get("lane_id")
                    steward_matches = [
                        lane
                        for lane in state.get("lanes", [])
                        if lane.get("lane_id") == steward_lane_id
                    ]
                    if (
                        len(steward_matches) != 1
                        or steward_matches[0].get("kind") != "coordination_steward"
                        or steward_lane_id in snapshot_lane_ids
                    ):
                        errors.append(
                            f"execution selection {selection_id} has an invalid Steward binding"
                        )
        if selection.get("root_session_id") not in state.get("session_ids", []):
            errors.append(f"execution selection {selection_id} lacks task-bound Chief session")
    for selection in selections:
        successor = selection.get("superseded_by")
        if successor and successor not in selection_ids:
            errors.append(
                f"execution selection {selection.get('selection_id')} references missing successor"
            )
    active_selection_ids = {
        str(item.get("selection_id"))
        for item in selections
        if item.get("status") == "active"
    }
    selection_by_id = {
        str(item.get("selection_id")): item for item in selections
    }
    brief_ids: set[str] = set()
    for brief in state.get("execution_briefs", []):
        brief_id = str(brief.get("brief_id", ""))
        if brief_id in brief_ids:
            errors.append(f"duplicate execution brief id {brief_id}")
        brief_ids.add(brief_id)
        selection_id = str(brief.get("execution_selection_id", ""))
        selection = selection_by_id.get(selection_id)
        selected_steward = (
            selection.get("steward_snapshot", {})
            if isinstance(selection, dict)
            else {}
        )
        if not isinstance(selected_steward, dict):
            selected_steward = {}
        preimage = copy.deepcopy(brief)
        stored_sha = str(preimage.pop("brief_sha256", ""))
        brief_version = brief.get("brief_version")
        if (
            not _is_exact_int(brief.get("integrity_version"), 1)
            or not any(_is_exact_int(brief_version, version) for version in (1, 2, 3))
            or not re.fullmatch(r"[0-9a-f]{64}", stored_sha)
            or stored_sha != canonical_record_sha256(preimage)
        ):
            errors.append(f"execution brief {brief_id} lost integrity")
        if (
            selection is None
            or selection.get("mode") not in {"centralized_parallel", "hybrid"}
            or brief.get("mode") != selection.get("mode")
            or brief.get("steward_snapshot") != selection.get("steward_snapshot")
        ):
            errors.append(f"execution brief {brief_id} has an invalid selection binding")
        if not isinstance(brief.get("packet_bindings"), list):
            errors.append(f"execution brief {brief_id} packet bindings are malformed")
        if any(_is_exact_int(brief_version, version) for version in (2, 3)):
            recording_steward = brief.get("recording_steward_snapshot")
            if (
                not isinstance(recording_steward, dict)
                or recording_steward.get("lane_id")
                != selected_steward.get("lane_id")
            ):
                errors.append(
                    f"execution brief {brief_id} lacks its recording Steward binding"
                )
        if _is_exact_int(brief_version, 3):
            stored_binding = brief.get("steward_packet_binding")
            try:
                current_binding = services.steward_packet_binding(
                    state,
                    selection_id,
                    str(stored_binding.get("packet_id", ""))
                    if isinstance(stored_binding, dict)
                    else "",
                )
            except HarnessError as exc:
                errors.append(
                    f"execution brief {brief_id} has an invalid Steward packet binding: {exc}"
                )
            else:
                if stored_binding != current_binding:
                    errors.append(
                        f"execution brief {brief_id} Steward packet binding is stale"
                    )
        if brief.get("root_session_id") not in state.get("session_ids", []):
            errors.append(f"execution brief {brief_id} lacks task-bound Chief session")
    for record_kind, records, active_statuses, identity_field in (
        ("packet", state.get("packets", []), ACTIVE_PACKET_STATUSES, "packet_id"),
        ("job", state.get("jobs", []), ACTIVE_JOB_STATUSES, "run_id"),
    ):
        for record in records:
            selection_id = str(record.get("execution_selection_id", ""))
            if selection_id and selection_id not in selection_ids:
                errors.append(
                    f"{record_kind} {record.get(identity_field)} references missing execution selection"
                )
                continue
            if (
                active_selection_ids
                and record.get("status") in active_statuses
                and not selection_id
            ):
                errors.append(
                    f"active {record_kind} {record.get(identity_field)} lacks execution selection binding"
                )
                continue
            if selection_id:
                if (
                    record.get("status") in active_statuses
                    and selection_id not in active_selection_ids
                ):
                    errors.append(
                        f"active {record_kind} {record.get(identity_field)} is bound to "
                        "a non-active execution selection"
                    )
                selection_lane_ids = {
                    str(item.get("lane_id"))
                    for item in selection_by_id[selection_id].get("lane_snapshots", [])
                }
                is_steward_packet = (
                    record_kind == "packet"
                    and _is_steward_synthesis_packet(record)
                )
                selected_steward_snapshot = selection_by_id[selection_id].get(
                    "steward_snapshot", {}
                )
                selected_steward_lane = (
                    str(selected_steward_snapshot.get("lane_id", ""))
                    if isinstance(selected_steward_snapshot, dict)
                    else ""
                )
                if is_steward_packet:
                    lane_valid = record.get("lane_id") == selected_steward_lane
                else:
                    lane_valid = record.get("lane_id") in selection_lane_ids
                if not lane_valid:
                    errors.append(
                        f"{record_kind} {record.get(identity_field)} lane is outside its execution selection"
                    )
            try:
                binding = _validate_skill_canary_work_unit_binding(
                    state,
                    str(record.get("skill_release_id", "")),
                    str(record.get("skill_canary_event_id", "")),
                    require_live_canary=False,
                )
                if binding is not None and any(
                    record.get(field) != binding.get(field)
                    for field in (
                        "skill_release_id",
                        "skill_version",
                        "skill_canary_event_id",
                    )
                ):
                    errors.append(
                        f"{record_kind} {record.get(identity_field)} lost its exact skill canary binding"
                    )
            except HarnessError as exc:
                errors.append(f"{record_kind} {record.get(identity_field)}: {exc}")
            if record_kind == "job":
                errors.extend(services.job_launch_authority_errors(state, record))
    for packet in state.get("packets", []):
        if packet.get("status") not in policy.executing_packet_statuses:
            continue
        try:
            services.validate_packet_activation_topology(state, packet)
        except (HarnessError, TypeError, ValueError) as exc:
            errors.append(
                f"packet {packet.get('packet_id')} violates execution topology: {exc}"
            )
    for job in state.get("jobs", []):
        if job.get("status") not in ACTIVE_JOB_STATUSES:
            continue
        try:
            selection = _validate_active_execution_selection(
                state,
                str(job.get("lane_id", "")),
                str(job.get("execution_selection_id", "")),
            )
            services.validate_job_activation_topology(
                state,
                job,
                selection,
                paths=paths,
                exclude_run_id=str(job.get("run_id", "")),
            )
        except (HarnessError, TypeError, ValueError) as exc:
            errors.append(
                f"job {job.get('run_id')} violates execution topology: {exc}"
            )
    cross_ids: set[str] = set()
    for item in cross_sessions:
        cross_id = str(item.get("cross_lane_session_id", ""))
        if cross_id in cross_ids:
            errors.append(f"duplicate cross-lane session id {cross_id}")
        cross_ids.add(cross_id)
        if item.get("status") not in policy.cross_lane_session_statuses:
            errors.append(f"cross-lane session {cross_id} has invalid status")
        if item.get("execution_selection_id") not in selection_ids:
            errors.append(f"cross-lane session {cross_id} references missing selection")
        elif item.get("status") == "open" and item.get(
            "execution_selection_id"
        ) not in active_selection_ids:
            errors.append(
                f"open cross-lane session {cross_id} is bound to a non-active selection"
            )
        if item.get("request_id") not in request_ids:
            errors.append(f"cross-lane session {cross_id} references missing request")
        if item.get("status") == "closed" and not item.get("closure"):
            errors.append(f"cross-lane session {cross_id} lacks steward closure")
    escalation_ids: set[str] = set()
    for item in escalations:
        escalation_id = str(item.get("escalation_id", ""))
        if escalation_id in escalation_ids:
            errors.append(f"duplicate needs-user escalation id {escalation_id}")
        escalation_ids.add(escalation_id)
        if item.get("status") not in policy.needs_user_statuses:
            errors.append(f"needs-user escalation {escalation_id} has invalid status")
        if item.get("category") not in policy.needs_user_categories:
            errors.append(f"needs-user escalation {escalation_id} has invalid category")
        if item.get("source_lane_id") not in lane_ids:
            errors.append(f"needs-user escalation {escalation_id} references missing lane")
        if item.get("request_id") and item.get("request_id") not in request_ids:
            errors.append(f"needs-user escalation {escalation_id} references missing request")
        if item.get("status") == "resolved" and not item.get("user_disposition"):
            errors.append(f"needs-user escalation {escalation_id} lacks user disposition")
    return errors


__all__ = [
    "JobLaunchAuthorityErrors",
    "PortfolioIntegrityPolicy",
    "PortfolioIntegrityServices",
    "RecordsFingerprint",
    "SkillReleaseSemanticIntegrityErrors",
    "StewardPacketBinding",
    "ValidateJobActivationTopology",
    "ValidatePacketActivationTopology",
    "_hard_dependency_cycle",
    "portfolio_integrity_errors",
]
