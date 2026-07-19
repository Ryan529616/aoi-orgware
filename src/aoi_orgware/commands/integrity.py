"""Task integrity-contract command composition.

The record schema lives in :mod:`integrity_records`; this module deliberately
only captures evidence, binds it to the task, and publishes the resulting
projection through the appropriate legacy or semantic-v2 writer.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from pathlib import Path
import re
from typing import Any

from .. import evidence_artifacts as artifacts
from .. import git_plumbing as git
from .. import harnesslib as h
from .. import integrity_records as records
from .. import semantic_events as semantic
from .. import semantic_store as store


Handler = Callable[[argparse.Namespace, h.HarnessPaths], int]
_ARTIFACT_POLICY = artifacts.EvidenceArtifactsPolicy(
    bound_artifact_total_max_bytes=records.MAX_INTEGRITY_ARTIFACT_BYTES
)
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def _emit(value: Mapping[str, Any], as_json: bool) -> None:
    if as_json:
        import json

        print(json.dumps(value, indent=2, ensure_ascii=False))
    else:
        for key, item in value.items():
            print(f"{key}: {item}")


def _validated_id(value: object, label: str) -> str:
    """Narrow untrusted command/state values before identifier validation."""

    if not isinstance(value, str):
        raise h.HarnessError(
            f"invalid {label}: {value!r}; use 1-128 ASCII letters, digits, dot, dash, or underscore"
        )
    return h.validate_id(value, label)


def _validated_agent_id(value: object, label: str) -> str:
    """Validate an agent identity using the dispatch/hook identity grammar."""

    try:
        return records.validate_agent_id(value, label)
    except records.IntegrityRecordError as exc:
        raise h.HarnessError(str(exc)) from exc


def _semantic_context(args: argparse.Namespace) -> tuple[str, str, str, str]:
    command_id = _validated_id(getattr(args, "command_id", None), "integrity command id")
    recorded_at = getattr(args, "recorded_at", None)
    if not isinstance(recorded_at, str) or not recorded_at:
        raise h.HarnessError("semantic integrity mutation requires --recorded-at")
    # The record builder is the shared strict ISO-8601 validator.
    try:
        records.build_integrity_contract(baseline_head="0" * 40, adopted_at=recorded_at)
    except records.IntegrityRecordError as exc:
        raise h.HarnessError(str(exc)) from exc
    expected = getattr(args, "expected_head_sha256", None)
    if not isinstance(expected, str) or len(expected) != 64:
        raise h.HarnessError("semantic integrity mutation requires --expected-head-sha256")
    authority = getattr(args, "_aoi_authority_ref", None)
    if not isinstance(authority, str) or not authority:
        raise h.HarnessError("semantic integrity mutation requires validated Chief authority")
    return command_id, recorded_at, expected, authority


def _task_worktree(state: Mapping[str, Any], paths: h.HarnessPaths) -> Path:
    raw = state.get("worktree") or str(paths.root)
    return Path(str(raw))


def _contract(state: Mapping[str, Any]) -> dict[str, Any]:
    value = state.get("integrity_contract")
    if not isinstance(value, dict):
        raise h.HarnessError("task has not adopted the required integrity contract")
    return value


def _validate_draft(state: Mapping[str, Any]) -> None:
    """Reject cross-record tampering without prematurely demanding a seal."""

    try:
        records.validate_integrity_contract(
            _contract(state), task_id=state.get("task_id"),
            worktree=state.get("worktree"), require_complete=False,
        )
    except records.IntegrityRecordError as exc:
        raise h.HarnessError(str(exc)) from exc


def _producer_ids(paths: h.HarnessPaths, state: Mapping[str, Any]) -> list[str]:
    values = {_validated_agent_id(state.get("owner"), "task owner agent id")}
    for claim in h.claims_owned_by_task(paths, str(state["task_id"])):
        if claim.get("status") in h.RESERVING_CLAIM_STATUSES:
            values.add(
                _validated_agent_id(claim.get("owner"), "live claim owner agent id")
            )
    packets = state.get("packets", [])
    if not isinstance(packets, list):
        raise h.HarnessError("task packets are malformed")
    for packet in packets:
        if not isinstance(packet, Mapping):
            raise h.HarnessError("task packet is malformed")
        if packet.get("status") == "done" and packet.get("packet_mode", "read_only") != "read_only":
            values.add(
                _validated_agent_id(
                    packet.get("agent_id"), "done mutation packet agent id"
                )
            )
    return sorted(values)


def _bound_artifact(paths: h.HarnessPaths, task_id: str, value: str, label: str) -> dict[str, Any]:
    if not isinstance(value, str):
        raise h.HarnessError(f"{label} must use absolute-path=sha256")
    source_text, separator, digest = value.rpartition("=")
    if not separator or not source_text or not digest:
        raise h.HarnessError(f"{label} must use absolute-path=sha256")
    # Split at the final '=' so a legitimate filename containing '=' remains
    # part of the exact source path.  A drive-qualified Windows path is also
    # unambiguous here because its ':' is never a separator.
    if not Path(source_text).is_absolute():
        raise h.HarnessError(f"{label} path must be absolute")
    prepared = artifacts.prepare_bound_artifacts([value], label, policy=_ARTIFACT_POLICY)
    preserved = artifacts.preserve_bound_artifacts(paths, task_id, prepared)[0]
    try:
        relative = Path(str(preserved["path"])).relative_to(h.task_dir(paths, task_id))
    except ValueError as exc:
        raise h.HarnessError(f"canonical {label} CAS path escapes its task") from exc
    path = relative.as_posix()
    if not path or path == ".":
        raise h.HarnessError(f"canonical {label} CAS path is empty")
    return {"path": path, "sha256": preserved["sha256"], "size_bytes": preserved["size_bytes"]}


def _retry_artifact_sha(value: Any, label: str) -> str:
    """Read only the caller's immutable artifact identity for an exact retry.

    A semantic retry must not re-publish a CAS blob merely to learn whether the
    terminal event was the same command.  The record binds the digest, not the
    caller's source pathname, so only its already-declared SHA-256 is relevant
    to retry equivalence.  Keep the input grammar aligned with ``_bound_artifact``.
    """

    if not isinstance(value, str):
        raise h.HarnessError(f"{label} must use absolute-path=sha256")
    source_text, separator, digest = value.rpartition("=")
    if not separator or not source_text or not _SHA256_RE.fullmatch(digest):
        raise h.HarnessError(f"{label} must use absolute-path=sha256")
    if not Path(source_text).is_absolute():
        raise h.HarnessError(f"{label} path must be absolute")
    return digest


def _preflight_artifact(value: Any, label: str) -> dict[str, Any]:
    """Build a non-persisted stand-in for record validation before CAS I/O."""

    return records.build_artifact_ref(
        path="preflight/artifact",
        sha256=_retry_artifact_sha(value, label),
        size_bytes=0,
    )


def _last_record(contract: Mapping[str, Any], collection: str, label: str) -> dict[str, Any]:
    value = contract.get(collection)
    if not isinstance(value, list) or not value or not isinstance(value[-1], dict):
        raise h.HarnessError(f"integrity retry has no terminal {label} record")
    return value[-1]


def _retry_contract(state: Mapping[str, Any]) -> dict[str, Any]:
    _validate_draft(state)
    return _contract(state)


def _retry_adopt_intent(args: argparse.Namespace, paths: h.HarnessPaths, state: Mapping[str, Any]) -> None:
    contract = _retry_contract(state)
    # An omitted baseline is an instruction to observe Git HEAD on the first
    # execution, not on every replay.  Once published, the contract records the
    # effective baseline and is the only stable value an exact response-loss
    # retry can compare against after the worktree advances.
    baseline = args.baseline_head or contract.get("baseline_head")
    if contract.get("baseline_head") != baseline or contract.get("adopted_at") != args.recorded_at:
        raise h.HarnessError("semantic integrity retry differs from the published adopt semantics")


def _retry_snapshot_intent(args: argparse.Namespace, state: Mapping[str, Any]) -> None:
    record = _last_record(_retry_contract(state), "snapshots", "snapshot")
    if record.get("purpose") != args.purpose:
        raise h.HarnessError("semantic integrity retry differs from the published snapshot semantics")


def _retry_review_intent(args: argparse.Namespace, state: Mapping[str, Any]) -> None:
    contract = _retry_contract(state)
    record = _last_record(contract, "review_results", "review result")
    finding_ids = sorted(args.finding_id)
    if finding_ids != sorted(set(finding_ids)):
        raise h.HarnessError("integrity review finding ids must be sorted and unique")
    if (
        record.get("snapshot_sha256") != args.snapshot_sha256
        or record.get("reviewer_agent_id") != args.reviewer_agent_id
        or record.get("outcome") != args.outcome
        or record.get("finding_ids") != finding_ids
        or record.get("result_artifact", {}).get("sha256")
        != _retry_artifact_sha(args.result_artifact, "integrity review result artifact")
    ):
        raise h.HarnessError("semantic integrity retry differs from the published review semantics")


def _retry_fix_intent(args: argparse.Namespace, state: Mapping[str, Any]) -> None:
    record = _last_record(_retry_contract(state), "fixes", "fix")
    if (
        record.get("finding_id") != args.finding_id
        or record.get("post_fix_snapshot_sha256") != args.post_fix_snapshot_sha256
        or record.get("fix_artifact", {}).get("sha256")
        != _retry_artifact_sha(args.fix_artifact, "integrity fix artifact")
    ):
        raise h.HarnessError("semantic integrity retry differs from the published fix semantics")


def _retry_verify_intent(args: argparse.Namespace, state: Mapping[str, Any]) -> None:
    record = _last_record(_retry_contract(state), "review_verifications", "review verification")
    if (
        record.get("finding_id") != args.finding_id
        or record.get("fix_record_sha256") != args.fix_record_sha256
        or record.get("snapshot_sha256") != args.snapshot_sha256
        or record.get("reviewer_agent_id") != args.reviewer_agent_id
        or record.get("outcome") != args.outcome
        or record.get("verification_artifact", {}).get("sha256")
        != _retry_artifact_sha(args.verification_artifact, "integrity verification artifact")
    ):
        raise h.HarnessError("semantic integrity retry differs from the published verification semantics")


def _retry_seal_intent(args: argparse.Namespace, state: Mapping[str, Any]) -> None:
    contract = _retry_contract(state)
    seal = contract.get("seal")
    if not isinstance(seal, dict):
        raise h.HarnessError("integrity retry has no terminal seal record")
    candidates = [item for item in contract["snapshots"] if item.get("purpose") == "candidate"]
    if not candidates:
        raise h.HarnessError("integrity retry has no terminal candidate snapshot")
    candidate = candidates[-1]
    reviews = [item for item in contract["review_results"] if item.get("snapshot_sha256") == candidate["snapshot_sha256"]]
    if len(reviews) != 1:
        raise h.HarnessError("integrity retry has ambiguous terminal candidate review")
    try:
        expected = records.build_integrity_seal(
            latest_candidate_snapshot_sha256=candidate["snapshot_sha256"],
            latest_review_result_record_sha256=reviews[0]["record_sha256"],
            claim_scope_sha256=candidate["claim_scope_sha256"],
            sealed_at=args.recorded_at,
        )
    except records.IntegrityRecordError as exc:
        raise h.HarnessError(str(exc)) from exc
    if seal != expected:
        raise h.HarnessError("semantic integrity retry differs from the published seal semantics")


def _snapshot(
    paths: h.HarnessPaths, state: Mapping[str, Any], purpose: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    contract = _contract(state)
    task_id = str(state["task_id"])
    snapshot = git.task_mutation_snapshot(
        task_id, _task_worktree(state, paths), str(contract["baseline_head"])
    )
    coverage = git.task_mutation_snapshot_claim_coverage(
        snapshot, h.claims_owned_by_task(paths, task_id)
    )
    if not coverage["covered"]:
        raise h.HarnessError("integrity snapshot has uncovered task-local mutations")
    # Validate every identity before publishing immutable CAS bytes.  A bad
    # producer must not leave an unreferenced snapshot artifact behind.
    producer_agent_ids = _producer_ids(paths, state)
    raw = semantic.canonical_json_bytes(snapshot, max_bytes=records.MAX_INTEGRITY_ARTIFACT_BYTES)
    artifact = artifacts.preserve_generated_artifact_blob(
        paths, task_id, raw, label="integrity mutation snapshot",
        max_bytes=records.MAX_INTEGRITY_ARTIFACT_BYTES,
    )
    try:
        record = records.build_snapshot_record(
            task_id=task_id,
            worktree=snapshot["worktree"],
            baseline_head=snapshot["baseline_head"],
            current_head=snapshot["current_head"],
            artifact=artifact,
            snapshot_sha256=snapshot["snapshot_sha256"],
            claim_scope_sha256=coverage["claim_scope_sha256"],
            covered_claim_tokens=coverage["covered_claim_tokens"],
            purpose=purpose,
            producer_agent_ids=producer_agent_ids,
        )
    except records.IntegrityRecordError as exc:
        raise h.HarnessError(str(exc)) from exc
    return record, snapshot


def _persist(
    args: argparse.Namespace,
    paths: h.HarnessPaths,
    task_id: str,
    event_type: str,
    mutate: Callable[[dict[str, Any]], tuple[dict[str, Any], Mapping[str, Any]]],
    retry_intent: Callable[[dict[str, Any]], None] | None = None,
) -> Mapping[str, Any]:
    """Persist a projection while preserving semantic event-first authority."""

    semantic_v2 = h.is_semantic_v2_task(paths, task_id)
    if semantic_v2:
        command_id, recorded_at, expected, authority = _semantic_context(args)
        state = h.load_task(paths, task_id)
        if store.semantic_head(paths, task_id)["event_sha256"] != expected:
            if retry_intent is None:
                raise h.HarnessError("semantic integrity retry intent validator is missing")
            # This comparison is deliberately made before recovery and is
            # strictly projection-only: no fresh Git mutation snapshot, CAS
            # publication, or normal mutation path may run for a retry.
            retry_intent(state)
            try:
                replay = store.recover_published_semantic_transition(
                    paths, task_id, state, event_type=event_type,
                    command_id=command_id, expected_head_sha256=expected,
                )
            except store.SemanticStoreError as exc:
                raise h.HarnessError(str(exc)) from exc
            return {"task_id": task_id, "event_sha256": replay.event["event_sha256"], "idempotent_replay": True}
        try:
            # Reject stale or reused command identities before mutate() can
            # publish an integrity snapshot or bound evidence blob into CAS.
            # append_semantic_transition() remains the commit-time CAS check.
            store.preflight_semantic_append(
                paths,
                task_id,
                command_id=command_id,
                expected_head_sha256=expected,
            )
        except store.SemanticStoreError as exc:
            raise h.HarnessError(str(exc)) from exc
        state, result = mutate(state)
        try:
            outcome = store.append_semantic_transition(
                paths, task_id, state, event_type=event_type, command_id=command_id,
                recorded_at=recorded_at, authority_ref=authority,
                expected_head_sha256=expected,
            )
        except store.SemanticStoreError as exc:
            raise h.HarnessError(str(exc)) from exc
        return {**dict(result), "task_id": task_id, "event_sha256": outcome.event["event_sha256"], "idempotent_replay": outcome.idempotent_replay}
    state = h.load_task(paths, task_id)
    state, result = mutate(state)
    h.bump_task(state)
    h.write_task(paths, state)
    h.write_index(paths)
    return {**dict(result), "task_id": task_id, "idempotent_replay": False}


def cmd_integrity_adopt(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    task_id = h.validate_id(args.task, "task id")
    with h.state_lock(paths, create_layout=False):
        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], Mapping[str, Any]]:
            # Adoption is one-way.  Reject an ineligible producer identity
            # before publishing the contract so the task is not stranded in a
            # required mode that can never create its first snapshot.
            _producer_ids(paths, state)
            metadata = git.git_metadata(_task_worktree(state, paths))
            baseline = args.baseline_head or metadata["head_sha"]
            try:
                adopted_at = args.recorded_at if h.is_semantic_v2_task(paths, task_id) else h.now_iso()
                state = records.adopt_integrity_contract(state, baseline_head=baseline, adopted_at=adopted_at)
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            return state, {"baseline_head": baseline}
        result = _persist(
            args, paths, task_id, "integrity_adopt", mutate,
            lambda state: _retry_adopt_intent(args, paths, state),
        )
    _emit(result, args.json)
    return 0


def cmd_integrity_snapshot(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    task_id = h.validate_id(args.task, "task id")
    with h.state_lock(paths, create_layout=False):
        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], Mapping[str, Any]]:
            record, _snapshot_value = _snapshot(paths, state, args.purpose)
            try:
                state["integrity_contract"] = records.append_snapshot(_contract(state), record)
                _validate_draft(state)
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            return state, {"snapshot_sha256": record["snapshot_sha256"], "record_sha256": record["record_sha256"]}
        result = _persist(
            args, paths, task_id, "integrity_snapshot", mutate,
            lambda state: _retry_snapshot_intent(args, state),
        )
    _emit(result, args.json)
    return 0


def _find(records_list: Any, field: str, value: str, label: str) -> dict[str, Any]:
    matches = [item for item in records_list if isinstance(item, dict) and item.get(field) == value]
    if len(matches) != 1:
        raise h.HarnessError(f"integrity {label} does not exist exactly once")
    return matches[0]


def cmd_integrity_review(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    task_id = h.validate_id(args.task, "task id")
    with h.state_lock(paths, create_layout=False):
        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], Mapping[str, Any]]:
            contract = _contract(state)
            snapshot = _find(contract["snapshots"], "snapshot_sha256", args.snapshot_sha256, "candidate snapshot")
            if snapshot.get("purpose") != "candidate":
                raise h.HarnessError("integrity review requires a candidate snapshot")
            try:
                records.build_review_result_record(
                    snapshot_sha256=args.snapshot_sha256,
                    reviewer_agent_id=args.reviewer_agent_id,
                    producer_agent_ids=snapshot["producer_agent_ids"],
                    result_artifact=_preflight_artifact(
                        args.result_artifact, "integrity review result artifact"
                    ),
                    outcome=args.outcome,
                    finding_ids=sorted(args.finding_id),
                )
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            artifact = _bound_artifact(paths, task_id, args.result_artifact, "integrity review result artifact")
            try:
                review = records.build_review_result_record(
                    snapshot_sha256=args.snapshot_sha256, reviewer_agent_id=args.reviewer_agent_id,
                    producer_agent_ids=snapshot["producer_agent_ids"], result_artifact=artifact,
                    outcome=args.outcome, finding_ids=sorted(args.finding_id),
                )
                updated = records.append_review_result(contract, review)
                for finding_id in sorted(args.finding_id):
                    updated = records.append_finding(updated, records.build_finding_record(
                        finding_id=finding_id, review_result_record_sha256=review["record_sha256"],
                        snapshot_sha256=args.snapshot_sha256, reviewer_agent_id=args.reviewer_agent_id,
                        finding_artifact_sha256=artifact["sha256"],
                    ))
                state["integrity_contract"] = updated
                _validate_draft(state)
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            return state, {"review_record_sha256": review["record_sha256"], "finding_ids": sorted(args.finding_id)}
        result = _persist(
            args, paths, task_id, "integrity_review", mutate,
            lambda state: _retry_review_intent(args, state),
        )
    _emit(result, args.json)
    return 0


def cmd_integrity_fix(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    task_id = h.validate_id(args.task, "task id")
    with h.state_lock(paths, create_layout=False):
        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], Mapping[str, Any]]:
            contract = _contract(state)
            finding = _find(contract["findings"], "finding_id", args.finding_id, "finding")
            post = _find(contract["snapshots"], "snapshot_sha256", args.post_fix_snapshot_sha256, "post-fix snapshot")
            if post.get("purpose") != "post_fix":
                raise h.HarnessError("integrity fix requires an exact post-fix snapshot")
            producer_agent_ids = _producer_ids(paths, state)
            try:
                records.build_fix_record(
                    finding_id=args.finding_id,
                    finding_record_sha256=finding["record_sha256"],
                    post_fix_snapshot_sha256=args.post_fix_snapshot_sha256,
                    fix_artifact=_preflight_artifact(
                        args.fix_artifact, "integrity fix artifact"
                    ),
                    producer_agent_ids=producer_agent_ids,
                )
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            artifact = _bound_artifact(paths, task_id, args.fix_artifact, "integrity fix artifact")
            try:
                fix = records.build_fix_record(
                    finding_id=args.finding_id, finding_record_sha256=finding["record_sha256"],
                    post_fix_snapshot_sha256=args.post_fix_snapshot_sha256, fix_artifact=artifact,
                    producer_agent_ids=producer_agent_ids,
                )
                state["integrity_contract"] = records.append_fix(contract, fix)
                _validate_draft(state)
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            return state, {"fix_record_sha256": fix["record_sha256"]}
        result = _persist(
            args, paths, task_id, "integrity_fix", mutate,
            lambda state: _retry_fix_intent(args, state),
        )
    _emit(result, args.json)
    return 0


def cmd_integrity_verify(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    task_id = h.validate_id(args.task, "task id")
    with h.state_lock(paths, create_layout=False):
        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], Mapping[str, Any]]:
            contract = _contract(state)
            _find(contract["findings"], "finding_id", args.finding_id, "finding")
            fix = _find(contract["fixes"], "record_sha256", args.fix_record_sha256, "fix record")
            if fix.get("finding_id") != args.finding_id or fix.get("post_fix_snapshot_sha256") != args.snapshot_sha256:
                raise h.HarnessError("integrity verification lost exact finding/fix/post-fix binding")
            try:
                records.build_review_verification_record(
                    finding_id=args.finding_id,
                    fix_record_sha256=args.fix_record_sha256,
                    snapshot_sha256=args.snapshot_sha256,
                    reviewer_agent_id=args.reviewer_agent_id,
                    verification_artifact=_preflight_artifact(
                        args.verification_artifact,
                        "integrity verification artifact",
                    ),
                    outcome=args.outcome,
                )
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            artifact = _bound_artifact(paths, task_id, args.verification_artifact, "integrity verification artifact")
            try:
                verification = records.build_review_verification_record(
                    finding_id=args.finding_id, fix_record_sha256=args.fix_record_sha256,
                    snapshot_sha256=args.snapshot_sha256, reviewer_agent_id=args.reviewer_agent_id,
                    verification_artifact=artifact, outcome=args.outcome,
                )
                state["integrity_contract"] = records.append_review_verification(contract, verification)
                _validate_draft(state)
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            return state, {"verification_record_sha256": verification["record_sha256"]}
        result = _persist(
            args, paths, task_id, "integrity_verify", mutate,
            lambda state: _retry_verify_intent(args, state),
        )
    _emit(result, args.json)
    return 0


def cmd_integrity_seal(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    task_id = h.validate_id(args.task, "task id")
    with h.state_lock(paths, create_layout=False):
        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], Mapping[str, Any]]:
            contract = _contract(state)
            candidates = [item for item in contract["snapshots"] if item.get("purpose") == "candidate"]
            if not candidates:
                raise h.HarnessError("integrity seal requires a candidate snapshot")
            candidate = candidates[-1]
            close, _snapshot_value = _snapshot(paths, state, "close")
            candidate_bytes = artifacts.verify_generated_artifact_blob(paths, task_id, candidate["artifact"], label="candidate integrity snapshot", max_bytes=records.MAX_INTEGRITY_ARTIFACT_BYTES)
            close_bytes = artifacts.verify_generated_artifact_blob(paths, task_id, close["artifact"], label="close integrity snapshot", max_bytes=records.MAX_INTEGRITY_ARTIFACT_BYTES)
            if candidate_bytes != close_bytes:
                raise h.HarnessError("integrity seal requires the latest candidate to be byte-identical")
            if candidate["claim_scope_sha256"] != close["claim_scope_sha256"]:
                raise h.HarnessError("integrity seal requires identical live claim scope")
            try:
                # ``close`` is a fresh observation used as a seal gate, not a
                # second persisted snapshot: byte identity intentionally gives
                # it the same snapshot_sha256 as the candidate, and duplicate
                # snapshot identities are invalid contract history.
                updated = contract
                reviews = [item for item in updated["review_results"] if item.get("snapshot_sha256") == candidate["snapshot_sha256"]]
                if len(reviews) != 1:
                    raise h.HarnessError("integrity seal requires one mandatory latest candidate review")
                sealed_at = args.recorded_at if h.is_semantic_v2_task(paths, task_id) else h.now_iso()
                seal = records.build_integrity_seal(
                    latest_candidate_snapshot_sha256=candidate["snapshot_sha256"],
                    latest_review_result_record_sha256=reviews[0]["record_sha256"],
                    claim_scope_sha256=candidate["claim_scope_sha256"], sealed_at=sealed_at,
                )
                state["integrity_contract"] = records.seal_integrity_contract(updated, seal)
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            return state, {"seal_record_sha256": seal["record_sha256"], "close_snapshot_sha256": close["snapshot_sha256"]}
        result = _persist(
            args, paths, task_id, "integrity_seal", mutate,
            lambda state: _retry_seal_intent(args, state),
        )
    _emit(result, args.json)
    return 0


def cmd_integrity_show(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    state = h.load_task(paths, h.validate_id(args.task, "task id"))
    contract = _contract(state)
    _emit({"task_id": state["task_id"], "integrity_contract": contract}, args.json)
    return 0


def _mutation_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--command-id")
    parser.add_argument("--recorded-at")
    parser.add_argument("--expected-head-sha256")


def register_integrity_commands(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
    *, handlers: Mapping[str, Handler], add_json_argument: Callable[[argparse.ArgumentParser], None],
) -> None:
    required = {"integrity_adopt", "integrity_snapshot", "integrity_review", "integrity_fix", "integrity_verify", "integrity_seal", "integrity_show"}
    if set(handlers) != required:
        raise ValueError("integrity command handler map mismatch")
    adopt = sub.add_parser("integrity-adopt")
    adopt.add_argument("--task", required=True); adopt.add_argument("--baseline-head")
    _mutation_arguments(adopt); add_json_argument(adopt); adopt.set_defaults(handler=handlers["integrity_adopt"])
    snapshot = sub.add_parser("integrity-snapshot")
    snapshot.add_argument("--task", required=True); snapshot.add_argument("--purpose", choices=("candidate", "post_fix"), required=True)
    _mutation_arguments(snapshot); add_json_argument(snapshot); snapshot.set_defaults(handler=handlers["integrity_snapshot"])
    review = sub.add_parser("integrity-review")
    review.add_argument("--task", required=True); review.add_argument("--snapshot-sha256", required=True); review.add_argument("--reviewer-agent-id", required=True); review.add_argument("--result-artifact", required=True); review.add_argument("--outcome", choices=("clean", "findings"), required=True); review.add_argument("--finding-id", action="append", default=[])
    _mutation_arguments(review); add_json_argument(review); review.set_defaults(handler=handlers["integrity_review"])
    fix = sub.add_parser("integrity-fix")
    fix.add_argument("--task", required=True); fix.add_argument("--finding-id", required=True); fix.add_argument("--post-fix-snapshot-sha256", required=True); fix.add_argument("--fix-artifact", required=True)
    _mutation_arguments(fix); add_json_argument(fix); fix.set_defaults(handler=handlers["integrity_fix"])
    verify = sub.add_parser("integrity-verify")
    verify.add_argument("--task", required=True); verify.add_argument("--finding-id", required=True); verify.add_argument("--fix-record-sha256", required=True); verify.add_argument("--snapshot-sha256", required=True); verify.add_argument("--reviewer-agent-id", required=True); verify.add_argument("--verification-artifact", required=True); verify.add_argument("--outcome", choices=("pass", "fail"), required=True)
    _mutation_arguments(verify); add_json_argument(verify); verify.set_defaults(handler=handlers["integrity_verify"])
    seal = sub.add_parser("integrity-seal")
    seal.add_argument("--task", required=True); _mutation_arguments(seal); add_json_argument(seal); seal.set_defaults(handler=handlers["integrity_seal"])
    show = sub.add_parser("integrity-show")
    show.add_argument("--task", required=True); add_json_argument(show); show.set_defaults(handler=handlers["integrity_show"])


__all__ = [name for name in globals() if name.startswith("cmd_integrity_")] + ["register_integrity_commands"]
