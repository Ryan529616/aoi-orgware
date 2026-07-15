"""Skill release/adoption lifecycle and improvement-occurrence integrity.

This module owns the semantic integrity checks for skill releases and skill
adoption events, the canary work-unit binding validator, and the durable
improvement-occurrence resolvers used when building improvement briefs.  The CLI
stays the composition root: ``_require_done_reviewer_packet`` still lives there
(it wraps :mod:`aoi_orgware.packet_integrity` with CLI-resident services), so the
one entry point that needs it, :func:`_skill_release_semantic_integrity_errors`,
receives it through an immutable :class:`SkillLifecycleServices` built fresh per
call by the CLI wrapper.  ``TERMINAL_PACKET_STATUSES`` and
``IMPROVEMENT_OPTION_IDS`` are recomputed/redeclared module-locally (neither is
project-mutable nor test-patched), mirroring the sibling extraction precedent.
This module imports only sibling packages and never imports
:mod:`aoi_orgware.cli`.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Protocol

from .evidence_artifacts import COMMAND_ARTIFACT_MAX_BYTES, read_regular_artifact
from .harnesslib import (
    ACTIVE_JOB_STATUSES,
    ACTIVE_PACKET_STATUSES,
    PACKET_STATUSES,
    HarnessError,
    HarnessPaths,
    load_task,
    parse_time,
    validate_id,
)
from .state_lookup import capacity_review_by_id, coordination_by_id


TERMINAL_PACKET_STATUSES = PACKET_STATUSES - ACTIVE_PACKET_STATUSES
IMPROVEMENT_OPTION_IDS = {"maintain-current", "capacity", "skill-automation"}


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


class RequireDoneReviewerPacket(Protocol):
    def __call__(
        self,
        paths: HarnessPaths,
        state: dict[str, Any],
        packet_id: str,
        *,
        required_artifact_shas: set[str] | None = None,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class SkillLifecycleServices:
    """CLI-resident authority lookups supplied by the composition root."""

    require_done_reviewer_packet: RequireDoneReviewerPacket


def _validate_skill_canary_work_unit_binding(
    state: dict[str, Any],
    release_id: str,
    canary_event_id: str,
    *,
    require_live_canary: bool,
) -> dict[str, str] | None:
    if bool(release_id) != bool(canary_event_id):
        raise HarnessError(
            "skill canary work requires both --skill-release-id and "
            "--skill-canary-event-id"
        )
    if not release_id:
        return None
    release_id = validate_id(release_id, "skill release id")
    canary_event_id = validate_id(canary_event_id, "skill canary event id")
    releases = [
        item
        for item in state.get("skill_releases", [])
        if item.get("release_id") == release_id
    ]
    events = [
        item
        for item in state.get("skill_adoption_events", [])
        if item.get("event_id") == canary_event_id
    ]
    if len(releases) != 1 or len(events) != 1:
        raise HarnessError("skill canary work references a missing or ambiguous release/event")
    release = releases[0]
    event = events[0]
    if (
        release.get("integrity_version") != 1
        or event.get("integrity_version") != 1
        or event.get("release_id") != release_id
        or event.get("request_id") != release.get("request_id")
        or event.get("action") != "canary"
        or event.get("resulting_status") != "canary"
    ):
        raise HarnessError("skill canary work is not bound to an exact canary authority")
    if require_live_canary:
        latest_canary = [
            item
            for item in state.get("skill_adoption_events", [])
            if item.get("release_id") == release_id and item.get("action") == "canary"
        ]
        requests = [
            item
            for item in state.get("improvement_requests", [])
            if item.get("request_id") == release.get("request_id")
        ]
        if (
            not latest_canary
            or latest_canary[-1].get("event_id") != canary_event_id
            or len(requests) != 1
            or requests[0].get("status") != "canary"
            or release.get("status") != "canary"
        ):
            raise HarnessError("skill canary work requires the current live canary authority")
    return {
        "skill_release_id": release_id,
        "skill_version": str(release.get("skill_version", "")),
        "skill_canary_event_id": canary_event_id,
    }


def _resolve_improvement_occurrence(state: dict[str, Any], reference: str) -> dict[str, Any]:
    kind, separator, identifier = require_text(reference, "improvement occurrence").partition(":")
    if not separator or not identifier:
        raise HarnessError("improvement occurrence must use kind:identifier")
    if kind == "packet":
        matches = [
            item for item in state.get("packets", []) if item.get("packet_id") == identifier
        ]
        if len(matches) != 1 or matches[0].get("status") not in TERMINAL_PACKET_STATUSES:
            raise HarnessError(f"improvement occurrence {reference} is not a terminal packet")
        item = matches[0]
        identity = item.get("result_sha256")
        lane_id = item.get("lane_id", "")
        status = item.get("status")
        completed_at = item.get("completed_at") or item.get("updated_at")
    elif kind == "job":
        matches = [item for item in state.get("jobs", []) if item.get("run_id") == identifier]
        if len(matches) != 1 or matches[0].get("status") in ACTIVE_JOB_STATUSES:
            raise HarnessError(f"improvement occurrence {reference} is not a terminal job")
        item = matches[0]
        identity = item.get("terminal_manifest_sha256") or item.get("source_sha")
        lane_id = item.get("lane_id", "")
        status = item.get("status")
        completed_at = item.get("updated_at")
    elif kind == "verification":
        try:
            index = int(identifier)
            item = state.get("verification", [])[index]
        except (ValueError, IndexError) as exc:
            raise HarnessError(f"improvement occurrence {reference} does not exist") from exc
        if item.get("integrity_version") != 1:
            raise HarnessError(f"improvement occurrence {reference} lacks integrity")
        identity = hashlib.sha256(
            json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
        ).hexdigest()
        lane_id = item.get("lane_id", "")
        status = item.get("status")
        completed_at = item.get("recorded_at")
    elif kind == "coordination":
        item = coordination_by_id(state, identifier)
        identity = hashlib.sha256(
            json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
        ).hexdigest()
        lane_id = item.get("source_lane", "")
        status = item.get("status")
        completed_at = item.get("updated_at")
    elif kind == "capacity":
        item = capacity_review_by_id(state, identifier)
        identity = item.get("dataset", {}).get("sha256")
        lane_id = item.get("scope", {}).get("target_lane_id", "")
        status = item.get("status")
        completed_at = item.get("updated_at")
    else:
        raise HarnessError(
            "improvement occurrence kind must be packet, job, verification, coordination, or capacity"
        )
    if not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{64}", identity):
        raise HarnessError(f"improvement occurrence {reference} lacks a durable identity")
    return {
        "reference": reference,
        "kind": kind,
        "identifier": identifier,
        "lane_id": lane_id,
        "identity_sha256": identity,
        "status": status,
        "completed_at": completed_at,
        "skill_release_id": item.get("skill_release_id", ""),
        "skill_version": item.get("skill_version", ""),
        "skill_canary_event_id": item.get("skill_canary_event_id", ""),
    }


def _resolve_adoption_work_units(
    state: dict[str, Any],
    references: Any,
    *,
    label: str,
    minimum: int,
    canary_recorded_at: str,
    require_after_canary: bool,
    expected_skill_release_id: str = "",
    expected_skill_version: str = "",
    expected_canary_event_id: str = "",
) -> list[dict[str, Any]]:
    if (
        not isinstance(references, list)
        or len(references) < minimum
        or not all(isinstance(item, str) and item.strip() for item in references)
        or len(references) != len(set(references))
    ):
        raise HarnessError(
            f"{label} requires at least {minimum} distinct durable work-unit references"
        )
    bindings = [_resolve_improvement_occurrence(state, item) for item in references]
    if len({item["identity_sha256"] for item in bindings}) != len(bindings):
        raise HarnessError(f"{label} work units must have distinct durable identities")
    success_status = {
        "packet": "done",
        "job": "pass",
        "verification": "pass",
        "coordination": "resolved",
    }
    for item in bindings:
        expected = success_status.get(item["kind"])
        if expected is None or item.get("status") != expected:
            raise HarnessError(
                f"{label} reference {item['reference']} is not a successful work unit"
            )
        if require_after_canary and (
            item.get("kind") not in {"packet", "job"}
            or item.get("skill_release_id") != expected_skill_release_id
            or item.get("skill_version") != expected_skill_version
            or item.get("skill_canary_event_id") != expected_canary_event_id
        ):
            raise HarnessError(
                f"{label} reference {item['reference']} is not bound to the exact skill canary"
            )
        completed = parse_time(str(item.get("completed_at", "")))
        canary_time = parse_time(canary_recorded_at)
        if completed is None or canary_time is None:
            raise HarnessError(f"{label} work unit lacks a comparable completion time")
        if require_after_canary and completed <= canary_time:
            raise HarnessError(
                f"{label} reference {item['reference']} does not postdate the bound canary"
            )
        if not require_after_canary and completed >= canary_time:
            raise HarnessError(
                f"{label} reference {item['reference']} is not a pre-canary baseline"
            )
    return bindings


def _parse_improvement_options(values: Iterable[str]) -> list[dict[str, str]]:
    parsed: dict[str, str] = {}
    for value in values:
        option_id, separator, description = value.partition("=")
        option_id = validate_id(option_id, "improvement option id")
        if not separator:
            raise HarnessError("improvement option must use option-id=description")
        if option_id in parsed:
            raise HarnessError(f"duplicate improvement option id {option_id}")
        parsed[option_id] = require_evidence_detail(
            description, f"improvement option {option_id}"
        )
    if set(parsed) != IMPROVEMENT_OPTION_IDS:
        raise HarnessError(
            "improvement brief must compare maintain-current, capacity, and skill-automation"
        )
    return [
        {"option_id": option_id, "description": parsed[option_id]}
        for option_id in sorted(parsed)
    ]


def _load_json_artifact(
    value: str | Path, label: str, expected_sha: str
) -> tuple[Path, bytes, dict[str, Any]]:
    expected_sha = require_text(expected_sha, f"{label} SHA-256").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise HarnessError(f"{label} SHA-256 must be full 64 hex")
    source, data = read_regular_artifact(
        value, label, max_bytes=COMMAND_ARTIFACT_MAX_BYTES, require_utf8=True
    )
    actual_sha = hashlib.sha256(data).hexdigest()
    if actual_sha != expected_sha:
        raise HarnessError(
            f"{label} SHA-256 mismatch: expected {expected_sha}, actual {actual_sha}"
        )
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HarnessError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise HarnessError(f"{label} must contain a JSON object")
    return source, data, payload


def _json_nonnegative_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise HarnessError(f"JSON field {key} must be a non-negative integer")
    return value


def _valid_named_checks(value: Any, minimum: int) -> bool:
    return (
        isinstance(value, list)
        and len(value) >= minimum
        and all(isinstance(item, str) and item.strip() for item in value)
        and len(value) == len(set(value))
    )


def _valid_skill_manifest_files(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    names: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            return False
        name = str(item.get("path", ""))
        pure = PurePosixPath(name)
        digest = str(item.get("sha256", ""))
        if (
            not name
            or pure.is_absolute()
            or ".." in pure.parts
            or name in names
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            return False
        names.add(name)
    return True


def _skill_bundle_member_hashes(data: bytes) -> dict[str, str]:
    members: dict[str, str] = {}
    total_size = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            entries = archive.getmembers()
            if len(entries) > 256:
                raise HarnessError("skill bundle contains more than 256 archive members")
            for entry in entries:
                pure = PurePosixPath(entry.name)
                if (
                    pure.is_absolute()
                    or not entry.name
                    or ".." in pure.parts
                    or entry.issym()
                    or entry.islnk()
                    or entry.isdev()
                ):
                    raise HarnessError(f"unsafe skill bundle member: {entry.name!r}")
                if entry.isdir():
                    continue
                if not entry.isfile() or entry.name in members:
                    raise HarnessError(f"unsupported or duplicate skill bundle member: {entry.name!r}")
                total_size += int(entry.size)
                if entry.size < 0 or total_size > 64 * 1024 * 1024:
                    raise HarnessError("skill bundle expanded content exceeds 64 MiB")
                stream = archive.extractfile(entry)
                if stream is None:
                    raise HarnessError(f"skill bundle member cannot be read: {entry.name}")
                payload = stream.read(entry.size + 1)
                if len(payload) != entry.size:
                    raise HarnessError(f"skill bundle member size mismatch: {entry.name}")
                members[entry.name] = hashlib.sha256(payload).hexdigest()
    except (tarfile.TarError, OSError) as exc:
        raise HarnessError(f"skill bundle must be a valid gzip tar archive: {exc}") from exc
    if "SKILL.md" not in members:
        raise HarnessError("skill bundle must contain SKILL.md at archive root")
    return members


def _skill_release_semantic_integrity_errors(
    state: dict[str, Any],
    release: dict[str, Any],
    paths: HarnessPaths | None,
    *,
    services: SkillLifecycleServices,
) -> list[str]:
    release_id = str(release.get("release_id", ""))
    try:
        _, bundle_data = read_regular_artifact(
            str(release.get("bundle_path", "")),
            "skill release bundle",
            max_bytes=32 * 1024 * 1024,
        )
        _, manifest_data, manifest = _load_json_artifact(
            str(release.get("manifest_path", "")),
            "skill release manifest",
            str(release.get("manifest_sha256", "")),
        )
        _, validation_data, validation = _load_json_artifact(
            str(release.get("validation_path", "")),
            "skill validation receipt",
            str(release.get("validation_sha256", "")),
        )
        bundle_sha = hashlib.sha256(bundle_data).hexdigest()
        validation_sha = hashlib.sha256(validation_data).hexdigest()
        bundle_members = _skill_bundle_member_hashes(bundle_data)
        independent = validation.get("independent_review", {})
        release_review = release.get("independent_review", {})
        if (
            release.get("integrity_version") != 1
            or bundle_sha != release.get("bundle_sha256")
            or len(bundle_data) != release.get("bundle_size_bytes")
            or manifest.get("skill_release_manifest_version") != 1
            or manifest.get("skill_id") != release.get("skill_id")
            or manifest.get("skill_version") != release.get("skill_version")
            or manifest.get("maintenance_owner") != release.get("maintenance_owner")
            or manifest.get("rollback_plan") != release.get("rollback_plan")
            or manifest.get("bundle_sha256") != bundle_sha
            or manifest.get("validation_receipt_sha256") != validation_sha
            or not _valid_skill_manifest_files(manifest.get("files"))
            or {
                str(item["path"]): str(item["sha256"])
                for item in manifest.get("files", [])
            }
            != bundle_members
            or validation.get("validation_version") != 1
            or validation.get("skill_creator_used") is not True
            or validation.get("structural_pass") is not True
            or validation.get("agents_metadata_consistent") is not True
            or validation.get("bundled_scripts_tested") is not True
            or not _valid_named_checks(validation.get("representative_project_fixtures"), 2)
            or not _valid_named_checks(validation.get("adversarial_fixtures"), 3)
            or not _valid_named_checks(validation.get("blind_forward_tests"), 2)
            or independent.get("status") != "pass"
            or not independent.get("evidence")
            or independent.get("review_packet_id")
            != release_review.get("review_packet_id")
        ):
            raise HarnessError("release snapshots no longer satisfy the skill contract")
        if paths is not None:
            project = load_task(paths, str(release.get("project_task_id", "")))
            required_artifact_shas = {
                bundle_sha,
                hashlib.sha256(manifest_data).hexdigest(),
                validation_sha,
            }
            review_packet = services.require_done_reviewer_packet(
                paths,
                project,
                str(release_review.get("review_packet_id", "")),
                required_artifact_shas=required_artifact_shas,
            )
            if (
                release_review.get("review_result_sha256")
                != review_packet.get("result_sha256")
                or release_review.get("reviewer_agent_id")
                != review_packet.get("agent_id")
            ):
                raise HarnessError("release reviewer identity no longer matches its packet")
            candidate_records = [
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
                len(candidate_records) != 2
                or {item.get("category") for item in candidate_records}
                != {"skill_validation", "independent_review"}
            ):
                raise HarnessError("release project candidate verification set changed")
            review_record = next(
                item
                for item in candidate_records
                if item.get("category") == "independent_review"
            )
            if (
                review_record.get("review_packet_id") != review_packet.get("packet_id")
                or review_record.get("review_result_sha256")
                != review_packet.get("result_sha256")
                or review_record.get("reviewer_agent_id")
                != review_packet.get("agent_id")
            ):
                raise HarnessError("release review verification lost reviewer binding")
    except (HarnessError, KeyError, TypeError, ValueError) as exc:
        return [f"skill release {release_id} semantic integrity failed: {exc}"]
    return []


def _skill_adoption_semantic_integrity_errors(
    state: dict[str, Any], event: dict[str, Any]
) -> list[str]:
    event_id = str(event.get("event_id", ""))
    try:
        _, _, payload = _load_json_artifact(
            str(event.get("evidence_path", "")),
            "skill adoption evidence",
            str(event.get("evidence_sha256", "")),
        )
        releases = [
            item
            for item in state.get("skill_releases", [])
            if item.get("release_id") == event.get("release_id")
        ]
        if len(releases) != 1:
            raise HarnessError("adoption event release identity is ambiguous")
        release = releases[0]
        status_map = {
            "canary": "canary",
            "adopt": "adopted",
            "pause": "paused",
            "rollback": "rolled_back",
            "deprecate": "deprecated",
        }
        action = str(event.get("action", ""))
        if (
            event.get("integrity_version") != 1
            or payload.get("adoption_receipt_version") != 1
            or payload.get("request_id") != event.get("request_id")
            or payload.get("release_id") != event.get("release_id")
            or payload.get("skill_version") != release.get("skill_version")
            or payload.get("action") != action
            or status_map.get(action) != event.get("resulting_status")
        ):
            raise HarnessError("adoption event no longer matches its receipt")
        if action == "canary":
            if (
                _json_nonnegative_int(payload, "planned_skill_units") < 3
                or not str(payload.get("rollback_plan", "")).strip()
            ):
                raise HarnessError("canary receipt no longer satisfies its gate")
        elif action == "adopt":
            canary_events = [
                item
                for item in state.get("skill_adoption_events", [])
                if item.get("event_id") == event.get("canary_event_id")
                and item.get("release_id") == event.get("release_id")
                and item.get("action") == "canary"
            ]
            if (
                len(canary_events) != 1
                or payload.get("canary_event_id") != event.get("canary_event_id")
            ):
                raise HarnessError("adoption event lost its exact canary binding")
            canary = canary_events[0]
            skill_bindings = _resolve_adoption_work_units(
                state,
                payload.get("skill_work_units"),
                label="skill canary",
                minimum=3,
                canary_recorded_at=str(canary.get("recorded_at", "")),
                require_after_canary=True,
                expected_skill_release_id=str(release.get("release_id", "")),
                expected_skill_version=str(release.get("skill_version", "")),
                expected_canary_event_id=str(canary.get("event_id", "")),
            )
            baseline_bindings: list[dict[str, Any]] = []
            if payload.get("efficiency_claim") is True:
                baseline_bindings = _resolve_adoption_work_units(
                    state,
                    payload.get("baseline_work_units"),
                    label="skill baseline",
                    minimum=3,
                    canary_recorded_at=str(canary.get("recorded_at", "")),
                    require_after_canary=False,
                )
            if (
                _json_nonnegative_int(payload, "skill_units") != len(skill_bindings)
                or (
                    payload.get("efficiency_claim") is True
                    and _json_nonnegative_int(payload, "baseline_units")
                    != len(baseline_bindings)
                )
                or payload.get("success_criteria_met") is not True
                or _json_nonnegative_int(payload, "quality_regressions") != 0
                or payload.get("rollback_path_verified") is not True
                or event.get("skill_work_unit_bindings") != skill_bindings
                or event.get("baseline_work_unit_bindings") != baseline_bindings
            ):
                raise HarnessError("adoption work-unit bindings no longer satisfy the gate")
        elif action in {"pause", "rollback", "deprecate"}:
            require_evidence_detail(str(payload.get("reason", "")), "adoption action reason")
        else:
            raise HarnessError("adoption event action is unsupported")
    except (HarnessError, KeyError, TypeError, ValueError) as exc:
        return [f"skill adoption event {event_id} semantic integrity failed: {exc}"]
    return []


def _require_project_result(project_dir: Path, source: Path, label: str) -> None:
    try:
        source.relative_to(project_dir / "results")
    except ValueError as exc:
        raise HarnessError(f"{label} must come from the linked project results directory") from exc


__all__ = [
    "RequireDoneReviewerPacket",
    "SkillLifecycleServices",
    "_json_nonnegative_int",
    "_load_json_artifact",
    "_parse_improvement_options",
    "_require_project_result",
    "_resolve_adoption_work_units",
    "_resolve_improvement_occurrence",
    "_skill_adoption_semantic_integrity_errors",
    "_skill_bundle_member_hashes",
    "_skill_release_semantic_integrity_errors",
    "_valid_named_checks",
    "_valid_skill_manifest_files",
    "_validate_skill_canary_work_unit_binding",
]
