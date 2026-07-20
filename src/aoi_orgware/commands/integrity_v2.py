"""Version-two task-integrity commands.

This is intentionally a separate command registrar while the v1 surface is
still supported.  The v2 record module owns the persisted graph; this module
only obtains evidence, selects the permitted terminal record, and persists the
projection through the existing semantic-event writer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .. import evidence_artifacts as artifacts
from .. import git_plumbing as git
from .. import harnesslib as h
from .. import integrity_records_v2 as records
from .. import semantic_events as semantic
from .. import semantic_store as store
from . import integrity as v1


Handler = Callable[[argparse.Namespace, h.HarnessPaths], int]
_ARTIFACT_POLICY = artifacts.EvidenceArtifactsPolicy(
    bound_artifact_total_max_bytes=records.MAX_INTEGRITY_ARTIFACT_BYTES
)


def _emit(value: Mapping[str, Any], as_json: bool) -> None:
    v1._emit(value, as_json)


def _contract(state: Mapping[str, Any]) -> dict[str, Any]:
    value = state.get("integrity_contract")
    if not isinstance(value, dict):
        raise h.HarnessError("task has not adopted the required v2 integrity contract")
    return value


def _is_v2(contract: Mapping[str, Any]) -> bool:
    return contract.get("mode") == records.INTEGRITY_CONTRACT_MODE


def _require_v2(state: Mapping[str, Any]) -> dict[str, Any]:
    contract = _contract(state)
    if not _is_v2(contract):
        raise h.HarnessError(
            "integrity command requires required_v2; run integrity-upgrade-v2 first"
        )
    return contract


def _source_v1_contract(
    paths: h.HarnessPaths, state: Mapping[str, Any], contract: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Load the immutable v1 CAS source required by a compact v2 contract."""

    if not records.integrity_contract_source_required(contract):
        return None
    receipt = contract.get("migration_receipt")
    if not isinstance(receipt, Mapping):
        raise h.HarnessError("compact v2 integrity contract has no migration receipt")
    artifact = receipt.get("source_contract_artifact")
    if not isinstance(artifact, dict):
        raise h.HarnessError("compact v2 integrity contract has no source v1 CAS artifact")
    task_id = str(state.get("task_id", ""))
    try:
        raw = artifacts.verify_generated_artifact_blob(
            paths, task_id, artifact, label="compact v2 integrity source v1 contract",
            max_bytes=records.MAX_INTEGRITY_MIGRATION_SOURCE_BYTES,
        )
        source = json.loads(raw.decode("utf-8"))
        if not isinstance(source, dict):
            raise h.HarnessError("compact v2 integrity source v1 CAS is not an object")
        if raw != semantic.canonical_json_bytes(
            source, max_bytes=records.MAX_INTEGRITY_MIGRATION_SOURCE_BYTES
        ):
            raise h.HarnessError("compact v2 integrity source v1 CAS is not canonical JSON")
    except (UnicodeDecodeError, json.JSONDecodeError, h.HarnessError) as exc:
        if isinstance(exc, h.HarnessError):
            raise
        raise h.HarnessError(f"compact v2 integrity source v1 CAS is invalid: {exc}") from exc
    return source


def _validate(
    state: Mapping[str, Any], *, paths: h.HarnessPaths | None = None,
    complete: bool = False,
) -> None:
    try:
        contract = _require_v2(state)
        source = _source_v1_contract(paths, state, contract) if paths is not None else None
        records.validate_integrity_contract(
            contract, task_id=state.get("task_id"), worktree=state.get("worktree"),
            require_complete=complete, source_v1_contract=source,
        )
    except records.IntegrityRecordError as exc:
        raise h.HarnessError(str(exc)) from exc


def _append(
    contract: Mapping[str, Any], kind: str, record: Mapping[str, Any], *,
    source_v1_contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        return getattr(records, "append_" + kind)(
            contract, record, source_v1_contract=source_v1_contract
        )
    except records.IntegrityRecordError as exc:
        raise h.HarnessError(str(exc)) from exc


def _append_many(
    contract: Mapping[str, Any], pending: list[Mapping[str, Any]], *,
    source_v1_contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        return records.append_integrity_records(
            contract, pending, source_v1_contract=source_v1_contract
        )
    except records.IntegrityRecordError as exc:
        raise h.HarnessError(str(exc)) from exc


def _record_list(
    contract: Mapping[str, Any], kind: str, *,
    source_v1_contract: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return v2's unified history, accepting a named index only if supplied."""

    raw: Any
    if records.integrity_contract_source_required(contract):
        if source_v1_contract is None:
            raise h.HarnessError("compact v2 integrity source contract is required")
        raw = records.materialize_effective_integrity_records(
            contract, source_v1_contract
        )
    else:
        raw = contract.get("records")
    if isinstance(raw, list):
        return [dict(item) for item in raw if isinstance(item, Mapping) and item.get("record_type") == kind]
    # This fallback keeps the command usable with the compact v2 projection
    # used by early record-module implementations.
    names = {
        "snapshot": "snapshots", "review_result": "review_results", "finding": "findings",
        "fix": "fixes", "review_verification": "review_verifications",
    }
    value = contract.get(names.get(kind, kind + "s"), [])
    return [dict(item) for item in value if isinstance(item, Mapping)] if isinstance(value, list) else []


def _latest(
    contract: Mapping[str, Any], kind: str, label: str, *,
    source_v1_contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    values = _record_list(contract, kind, source_v1_contract=source_v1_contract)
    if not values:
        raise h.HarnessError(f"integrity v2 has no {label} record")
    return values[-1]


def _find(
    contract: Mapping[str, Any], kind: str, field: str, value: str, label: str, *,
    source_v1_contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    matches = [item for item in _record_list(
        contract, kind, source_v1_contract=source_v1_contract
    ) if item.get(field) == value]
    if len(matches) != 1:
        raise h.HarnessError(f"integrity {label} does not exist exactly once")
    return matches[0]


def _record_sha(record: Mapping[str, Any]) -> str:
    value = record.get("record_sha256")
    if not isinstance(value, str):
        raise h.HarnessError("integrity v2 record has no record_sha256")
    return value


def _producer_ids(paths: h.HarnessPaths, state: Mapping[str, Any]) -> list[str]:
    return v1._producer_ids(paths, state)


def _bound_artifact(paths: h.HarnessPaths, task_id: str, value: str, label: str) -> dict[str, Any]:
    return v1._bound_artifact(paths, task_id, value, label)


def _preflight_artifact(value: Any, label: str) -> dict[str, Any]:
    # The v2 record module deliberately retains the artifact-ref boundary.
    return records.build_artifact_ref(
        path="preflight/artifact", sha256=v1._retry_artifact_sha(value, label), size_bytes=0,
    )


def _snapshot(
    paths: h.HarnessPaths, state: Mapping[str, Any], purpose: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    contract = _require_v2(state)
    source = _source_v1_contract(paths, state, contract)
    task_id = str(state["task_id"])
    snapshot = git.task_mutation_snapshot(
        task_id, v1._task_worktree(state, paths), str(contract["baseline_head"])
    )
    coverage = git.task_mutation_snapshot_claim_coverage(
        snapshot, h.claims_owned_by_task(paths, task_id)
    )
    if not coverage["covered"]:
        raise h.HarnessError("integrity snapshot has uncovered task-local mutations")
    producer_agent_ids = _producer_ids(paths, state)
    raw = semantic.canonical_json_bytes(
        snapshot, max_bytes=records.MAX_INTEGRITY_ARTIFACT_BYTES
    )
    artifact = artifacts.preserve_generated_artifact_blob(
        paths, task_id, raw, label="integrity mutation snapshot",
        max_bytes=records.MAX_INTEGRITY_ARTIFACT_BYTES,
    )
    try:
        record = records.build_snapshot_record(
            integrity_seq=records.next_integrity_sequence(contract),
            attempt_id=records.next_snapshot_attempt_id(
                contract, source_v1_contract=source
            ),
            task_id=task_id, worktree=snapshot["worktree"],
            baseline_head=snapshot["baseline_head"], current_head=snapshot["current_head"],
            artifact=artifact, snapshot_sha256=snapshot["snapshot_sha256"],
            claim_scope_sha256=coverage["claim_scope_sha256"],
            covered_claim_tokens=coverage["covered_claim_tokens"], purpose=purpose,
            producer_agent_ids=producer_agent_ids,
        )
    except records.IntegrityRecordError as exc:
        raise h.HarnessError(str(exc)) from exc
    return record, snapshot


def _persist(
    args: argparse.Namespace, paths: h.HarnessPaths, task_id: str, event_type: str,
    mutate: Callable[[dict[str, Any]], tuple[dict[str, Any], Mapping[str, Any]]],
    retry_intent: Callable[[dict[str, Any]], None] | None = None,
) -> Mapping[str, Any]:
    """Persist v2 mutations and make response-loss timestamps exact.

    Record timestamps are deliberately absent from the v2 integrity graph so
    migration remains a pure translation of its source records.  A semantic
    transition already binds ``recorded_at`` immutably, however; inspect that
    terminal event before allowing the existing retry recovery path.
    """

    semantic_v2 = h.is_semantic_v2_task(paths, task_id)
    if semantic_v2:
        command_id, recorded_at, expected, authority = v1._semantic_context(args)
        state = h.load_task(paths, task_id)
        if store.semantic_head(paths, task_id)["event_sha256"] != expected:
            if retry_intent is None:
                raise h.HarnessError("semantic integrity retry intent validator is missing")
            try:
                events = store.load_semantic_events(paths, task_id)
            except store.SemanticStoreError as exc:
                raise h.HarnessError(str(exc)) from exc
            matches = [event for event in events if event.get("command_id") == command_id]
            # Only an exact candidate retry reaches this timestamp check.  All
            # other identity/terminal/projection conditions remain owned by
            # recover_published_semantic_transition below.
            if (
                len(matches) == 1
                and matches[0] is events[-1]
                and matches[0].get("event_type") == event_type
                and matches[0].get("prev_event_sha256") == expected
                and matches[0].get("recorded_at") != recorded_at
            ):
                raise h.HarnessError(
                    "semantic integrity retry differs from the published recorded_at"
                )
            retry_intent(state)
            try:
                replay = store.recover_published_semantic_transition(
                    paths, task_id, state, event_type=event_type,
                    command_id=command_id, expected_head_sha256=expected,
                )
            except store.SemanticStoreError as exc:
                raise h.HarnessError(str(exc)) from exc
            return {
                "task_id": task_id,
                "event_sha256": replay.event["event_sha256"],
                "idempotent_replay": True,
            }
        try:
            store.preflight_semantic_append(
                paths, task_id, command_id=command_id, expected_head_sha256=expected,
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
        return {
            **dict(result), "task_id": task_id,
            "event_sha256": outcome.event["event_sha256"],
            "idempotent_replay": outcome.idempotent_replay,
        }
    state = h.load_task(paths, task_id)
    state, result = mutate(state)
    h.bump_task(state)
    h.write_task(paths, state)
    h.write_index(paths)
    return {**dict(result), "task_id": task_id, "idempotent_replay": False}


def _retry_terminal(
    args: argparse.Namespace, state: Mapping[str, Any], kind: str, fields: tuple[str, ...], *,
    paths: h.HarnessPaths | None = None,
) -> None:
    _validate(state, paths=paths)
    contract = _require_v2(state)
    source = _source_v1_contract(paths, state, contract) if paths is not None else None
    record = _latest(
        contract, kind, kind.replace("_", " "), source_v1_contract=source
    )
    for field in fields:
        if record.get(field) != getattr(args, field, None):
            raise h.HarnessError("semantic integrity retry differs from the published v2 semantics")


def _retry_snapshot(
    args: argparse.Namespace, state: Mapping[str, Any], *, paths: h.HarnessPaths | None = None,
) -> None:
    _retry_terminal(args, state, "snapshot", ("purpose",), paths=paths)


def _retry_adopt(args: argparse.Namespace, state: Mapping[str, Any]) -> None:
    contract = _require_v2(state)
    baseline = args.baseline_head or contract.get("baseline_head")
    if contract.get("baseline_head") != baseline or contract.get("adopted_at") != args.recorded_at:
        raise h.HarnessError("semantic integrity retry differs from the published v2 adopt semantics")


def _retry_review(
    args: argparse.Namespace, state: Mapping[str, Any], *, paths: h.HarnessPaths | None = None,
) -> None:
    _retry_terminal(args, state, "review_result", (
        "snapshot_record_sha256", "reviewer_agent_id", "outcome",
    ), paths=paths)
    contract = _require_v2(state)
    source = _source_v1_contract(paths, state, contract) if paths is not None else None
    record = _latest(
        contract, "review_result", "review result", source_v1_contract=source
    )
    if (record.get("finding_ids") != sorted(args.finding_id)
            or record.get("result_artifact", {}).get("sha256") !=
            v1._retry_artifact_sha(args.result_artifact, "integrity review result artifact")):
        raise h.HarnessError("semantic integrity retry differs from the published v2 semantics")


def _retry_fix(
    args: argparse.Namespace, state: Mapping[str, Any], *, paths: h.HarnessPaths | None = None,
) -> None:
    _retry_terminal(args, state, "fix", (
        "finding_id", "post_fix_snapshot_record_sha256",
    ), paths=paths)
    contract = _require_v2(state)
    source = _source_v1_contract(paths, state, contract) if paths is not None else None
    record = _latest(contract, "fix", "fix", source_v1_contract=source)
    if record.get("fix_artifact", {}).get("sha256") != v1._retry_artifact_sha(args.fix_artifact, "integrity fix artifact"):
        raise h.HarnessError("semantic integrity retry differs from the published v2 semantics")


def _retry_verify(
    args: argparse.Namespace, state: Mapping[str, Any], *, paths: h.HarnessPaths | None = None,
) -> None:
    contract = _require_v2(state)
    source = _source_v1_contract(paths, state, contract) if paths is not None else None
    record = _latest(
        contract, "review_verification", "review verification", source_v1_contract=source
    )
    if (
        record.get("finding_id") != args.finding_id
        or record.get("fix_record_sha256") != args.fix_record_sha256
        or record.get("verification_snapshot_record_sha256") != args.verification_snapshot_record_sha256
        or record.get("reviewer_agent_id") != args.reviewer_agent_id
        or record.get("outcome") != args.outcome
    ):
        raise h.HarnessError("semantic integrity retry differs from the published v2 semantics")
    if record.get("verification_artifact", {}).get("sha256") != v1._retry_artifact_sha(args.verification_artifact, "integrity verification artifact"):
        raise h.HarnessError("semantic integrity retry differs from the published v2 semantics")


def _retry_seal(
    args: argparse.Namespace, state: Mapping[str, Any], *, paths: h.HarnessPaths | None = None,
) -> None:
    _validate(state, paths=paths, complete=True)
    contract = _require_v2(state)
    source = _source_v1_contract(paths, state, contract) if paths is not None else None
    seal = contract.get("seal")
    if not isinstance(seal, Mapping):
        raise h.HarnessError("semantic integrity retry has no terminal v2 seal")
    target = _latest(contract, "snapshot", "snapshot", source_v1_contract=source)
    reviews = [
        record for record in _record_list(
            contract, "review_result", source_v1_contract=source
        )
        if record.get("snapshot_record_sha256") == _record_sha(target)
    ]
    if seal.get("terminal_snapshot_record_sha256") != _record_sha(target):
        raise h.HarnessError("semantic integrity retry differs from the published v2 seal target")
    if len(reviews) != 1 or reviews[0].get("outcome") != "clean":
        raise h.HarnessError("semantic integrity retry differs from the published v2 seal target")
    try:
        expected = records.build_integrity_seal(
            integrity_seq=seal.get("integrity_seq"),
            terminal_snapshot_record_sha256=_record_sha(target),
            terminal_review_result_record_sha256=_record_sha(reviews[0]),
            claim_scope_sha256=target.get("claim_scope_sha256"),
            sealed_at=args.recorded_at,
        )
    except records.IntegrityRecordError as exc:
        raise h.HarnessError(str(exc)) from exc
    if dict(seal) != expected:
        raise h.HarnessError("semantic integrity retry differs from the published v2 seal semantics")


def cmd_integrity_adopt(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    task_id = h.validate_id(args.task, "task id")
    with h.state_lock(paths, create_layout=False):
        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], Mapping[str, Any]]:
            if "integrity_contract" in state:
                raise h.HarnessError("task already has an integrity contract; run integrity-upgrade-v2 for v1")
            _producer_ids(paths, state)
            baseline = args.baseline_head or git.git_metadata(v1._task_worktree(state, paths))["head_sha"]
            adopted_at = args.recorded_at if h.is_semantic_v2_task(paths, task_id) else h.now_iso()
            try:
                state["integrity_contract"] = records.build_integrity_contract(
                    baseline_head=baseline, adopted_at=adopted_at
                )
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            return state, {"baseline_head": baseline, "integrity_mode": "required_v2"}
        result = _persist(args, paths, task_id, "integrity_adopt", mutate, lambda s: _retry_adopt(args, s))
    _emit(result, args.json)
    return 0


def cmd_integrity_snapshot(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    task_id = h.validate_id(args.task, "task id")
    with h.state_lock(paths, create_layout=False):
        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], Mapping[str, Any]]:
            record, _ = _snapshot(paths, state, args.purpose)
            contract = _require_v2(state)
            source = _source_v1_contract(paths, state, contract)
            state["integrity_contract"] = _append(
                contract, "snapshot", record, source_v1_contract=source
            )
            _validate(state, paths=paths)
            return state, {
                "snapshot_sha256": record["snapshot_sha256"],
                "snapshot_record_sha256": _record_sha(record),
                "attempt_id": record["attempt_id"],
            }
        result = _persist(args, paths, task_id, "integrity_snapshot", mutate, lambda s: _retry_snapshot(args, s, paths=paths))
    _emit(result, args.json)
    return 0


def cmd_integrity_review(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    task_id = h.validate_id(args.task, "task id")
    with h.state_lock(paths, create_layout=False):
        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], Mapping[str, Any]]:
            contract = _require_v2(state)
            source = _source_v1_contract(paths, state, contract)
            snapshot = _find(contract, "snapshot", "record_sha256", args.snapshot_record_sha256, "snapshot", source_v1_contract=source)
            if snapshot != _latest(contract, "snapshot", "snapshot", source_v1_contract=source):
                raise h.HarnessError("integrity review requires the latest snapshot record")
            if _record_list(contract, "review_result", source_v1_contract=source):
                previous = _latest(contract, "review_result", "review result", source_v1_contract=source)
                if previous.get("snapshot_record_sha256") == args.snapshot_record_sha256:
                    raise h.HarnessError("integrity review permits at most one review for its snapshot")
            finding_ids = sorted(args.finding_id)
            if finding_ids != sorted(set(finding_ids)):
                raise h.HarnessError("integrity review finding ids must be sorted and unique")
            try:
                review = records.build_review_result_record(
                    integrity_seq=records.next_integrity_sequence(contract),
                    snapshot_record_sha256=args.snapshot_record_sha256,
                    reviewer_agent_id=args.reviewer_agent_id,
                    producer_agent_ids=snapshot["producer_agent_ids"],
                    result_artifact=_preflight_artifact(args.result_artifact, "integrity review result artifact"),
                    outcome=args.outcome, finding_ids=finding_ids,
                    basis_review_verification_record_sha256s=(
                        records.review_basis_review_verification_record_sha256s(
                            {**contract, "records": records.materialize_effective_integrity_records(contract, source)}
                            if source is not None else contract
                        )
                    ),
                )
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            artifact = _bound_artifact(paths, task_id, args.result_artifact, "integrity review result artifact")
            try:
                review = records.build_review_result_record(
                    integrity_seq=records.next_integrity_sequence(contract),
                    snapshot_record_sha256=args.snapshot_record_sha256,
                    reviewer_agent_id=args.reviewer_agent_id, producer_agent_ids=snapshot["producer_agent_ids"],
                    result_artifact=artifact, outcome=args.outcome, finding_ids=finding_ids,
                    basis_review_verification_record_sha256s=(
                        records.review_basis_review_verification_record_sha256s(
                            {**contract, "records": records.materialize_effective_integrity_records(contract, source)}
                            if source is not None else contract
                        )
                    ),
                )
                pending: list[Mapping[str, Any]] = [review]
                for finding_id in finding_ids:
                    finding = records.build_finding_record(
                        integrity_seq=records.next_integrity_sequence(contract) + len(pending), finding_id=finding_id,
                        review_result_record_sha256=_record_sha(review),
                        snapshot_record_sha256=args.snapshot_record_sha256,
                        reviewer_agent_id=args.reviewer_agent_id, finding_artifact_sha256=artifact["sha256"],
                    )
                    pending.append(finding)
                updated = _append_many(contract, pending, source_v1_contract=source)
                state["integrity_contract"] = updated
                _validate(state, paths=paths)
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            return state, {"review_record_sha256": _record_sha(review), "finding_ids": finding_ids}
        result = _persist(args, paths, task_id, "integrity_review", mutate, lambda s: _retry_review(args, s, paths=paths))
    _emit(result, args.json)
    return 0


def cmd_integrity_fix(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    task_id = h.validate_id(args.task, "task id")
    with h.state_lock(paths, create_layout=False):
        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], Mapping[str, Any]]:
            contract = _require_v2(state)
            source = _source_v1_contract(paths, state, contract)
            finding = _find(contract, "finding", "finding_id", args.finding_id, "finding", source_v1_contract=source)
            post = _find(contract, "snapshot", "record_sha256", args.post_fix_snapshot_record_sha256, "post-fix snapshot", source_v1_contract=source)
            if post != _latest(contract, "snapshot", "snapshot", source_v1_contract=source) or post.get("purpose") != "post_fix":
                raise h.HarnessError("integrity fix requires the latest post_fix snapshot record")
            producers = _producer_ids(paths, state)
            try:
                records.build_fix_record(
                    integrity_seq=records.next_integrity_sequence(contract), finding_id=args.finding_id,
                    finding_record_sha256=_record_sha(finding),
                    post_fix_snapshot_record_sha256=args.post_fix_snapshot_record_sha256,
                    fix_artifact=_preflight_artifact(args.fix_artifact, "integrity fix artifact"), producer_agent_ids=producers,
                )
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            artifact = _bound_artifact(paths, task_id, args.fix_artifact, "integrity fix artifact")
            try:
                fix = records.build_fix_record(
                    integrity_seq=records.next_integrity_sequence(contract), finding_id=args.finding_id,
                    finding_record_sha256=_record_sha(finding), post_fix_snapshot_record_sha256=args.post_fix_snapshot_record_sha256,
                    fix_artifact=artifact, producer_agent_ids=producers,
                )
                state["integrity_contract"] = _append(contract, "fix", fix, source_v1_contract=source)
                _validate(state, paths=paths)
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            return state, {"fix_record_sha256": _record_sha(fix)}
        result = _persist(args, paths, task_id, "integrity_fix", mutate, lambda s: _retry_fix(args, s, paths=paths))
    _emit(result, args.json)
    return 0


def cmd_integrity_verify(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    task_id = h.validate_id(args.task, "task id")
    with h.state_lock(paths, create_layout=False):
        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], Mapping[str, Any]]:
            contract = _require_v2(state)
            source = _source_v1_contract(paths, state, contract)
            snapshot = _find(contract, "snapshot", "record_sha256", args.verification_snapshot_record_sha256, "verification snapshot", source_v1_contract=source)
            if snapshot != _latest(contract, "snapshot", "snapshot", source_v1_contract=source):
                raise h.HarnessError("integrity verification requires the latest snapshot record")
            _find(contract, "finding", "finding_id", args.finding_id, "finding", source_v1_contract=source)
            fix = _find(contract, "fix", "record_sha256", args.fix_record_sha256, "fix record", source_v1_contract=source)
            if fix.get("finding_id") != args.finding_id:
                raise h.HarnessError("integrity verification lost exact finding/fix binding")
            try:
                records.build_review_verification_record(
                    integrity_seq=records.next_integrity_sequence(contract), finding_id=args.finding_id,
                    fix_record_sha256=args.fix_record_sha256,
                    verification_snapshot_record_sha256=args.verification_snapshot_record_sha256,
                    reviewer_agent_id=args.reviewer_agent_id,
                    verification_artifact=_preflight_artifact(args.verification_artifact, "integrity verification artifact"), outcome=args.outcome,
                )
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            artifact = _bound_artifact(paths, task_id, args.verification_artifact, "integrity verification artifact")
            try:
                verification = records.build_review_verification_record(
                    integrity_seq=records.next_integrity_sequence(contract), finding_id=args.finding_id,
                    fix_record_sha256=args.fix_record_sha256,
                    verification_snapshot_record_sha256=args.verification_snapshot_record_sha256,
                    reviewer_agent_id=args.reviewer_agent_id, verification_artifact=artifact, outcome=args.outcome,
                )
                state["integrity_contract"] = _append(contract, "review_verification", verification, source_v1_contract=source)
                _validate(state, paths=paths)
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            return state, {"verification_record_sha256": _record_sha(verification)}
        result = _persist(args, paths, task_id, "integrity_verify", mutate, lambda s: _retry_verify(args, s, paths=paths))
    _emit(result, args.json)
    return 0


def cmd_integrity_seal(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    task_id = h.validate_id(args.task, "task id")
    with h.state_lock(paths, create_layout=False):
        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], Mapping[str, Any]]:
            contract = _require_v2(state)
            source = _source_v1_contract(paths, state, contract)
            target = _latest(contract, "snapshot", "snapshot", source_v1_contract=source)
            close, _ = _snapshot(paths, state, "close")
            target_bytes = artifacts.verify_generated_artifact_blob(paths, task_id, target["artifact"], label="latest integrity snapshot", max_bytes=records.MAX_INTEGRITY_ARTIFACT_BYTES)
            close_bytes = artifacts.verify_generated_artifact_blob(paths, task_id, close["artifact"], label="close integrity snapshot", max_bytes=records.MAX_INTEGRITY_ARTIFACT_BYTES)
            if target_bytes != close_bytes or target.get("claim_scope_sha256") != close.get("claim_scope_sha256"):
                raise h.HarnessError("integrity seal requires byte-identical fresh close observation and claim scope")
            reviews = [r for r in _record_list(
                contract, "review_result", source_v1_contract=source
            ) if r.get("snapshot_record_sha256") == _record_sha(target)]
            if len(reviews) != 1 or reviews[0].get("outcome") != "clean":
                raise h.HarnessError("integrity seal requires exactly one clean review of the latest snapshot")
            try:
                seal = records.build_integrity_seal(
                    integrity_seq=records.next_integrity_sequence(contract),
                    terminal_snapshot_record_sha256=_record_sha(target),
                    terminal_review_result_record_sha256=_record_sha(reviews[0]),
                    claim_scope_sha256=target["claim_scope_sha256"],
                    sealed_at=args.recorded_at if h.is_semantic_v2_task(paths, task_id) else h.now_iso(),
                )
                updated = dict(contract)
                updated["seal"] = seal
                records.validate_integrity_contract(
                    updated, task_id=state.get("task_id"), worktree=state.get("worktree"),
                    require_complete=True, source_v1_contract=source,
                )
                state["integrity_contract"] = updated
                _validate(state, paths=paths, complete=True)
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            return state, {"seal_record_sha256": _record_sha(seal), "close_snapshot_sha256": close["snapshot_sha256"]}
        result = _persist(args, paths, task_id, "integrity_seal", mutate, lambda s: _retry_seal(args, s, paths=paths))
    _emit(result, args.json)
    return 0


def _canonical_sha256(value: Mapping[str, Any]) -> tuple[bytes, str]:
    raw = semantic.canonical_json_bytes(
        value, max_bytes=records.MAX_INTEGRITY_MIGRATION_SOURCE_BYTES
    )
    return raw, hashlib.sha256(raw).hexdigest()


def _retry_upgrade(args: argparse.Namespace, paths: h.HarnessPaths, state: Mapping[str, Any]) -> None:
    contract = _require_v2(state)
    receipt = contract.get("migration_receipt")
    if not isinstance(receipt, Mapping):
        raise h.HarnessError("semantic integrity retry has no migration receipt")
    if (receipt.get("source_schema_version") != 1
            or receipt.get("source_mode") != "required_v1"
            or receipt.get("source_contract_sha256") != args.expected_v1_contract_sha256
            or receipt.get("source_contract_artifact", {}).get("sha256")
            != args.expected_v1_contract_sha256
            or receipt.get("migrated_at") != args.recorded_at):
        raise h.HarnessError("semantic integrity retry differs from the published v2 upgrade semantics")
    source_head = args.expected_head_sha256 if h.is_semantic_v2_task(paths, str(state.get("task_id", ""))) else None
    if receipt.get("source_semantic_head_sha256") != source_head:
        raise h.HarnessError("semantic integrity retry differs from the published v2 upgrade provenance")


def cmd_integrity_upgrade_v2(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    task_id = h.validate_id(args.task, "task id")
    with h.state_lock(paths, create_layout=False):
        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], Mapping[str, Any]]:
            source = _contract(state)
            if _is_v2(source):
                raise h.HarnessError("task is already required_v2")
            try:
                # Migration must start from a strict, unsealed v1 graph.
                import importlib
                v1_records = importlib.import_module("aoi_orgware.integrity_records")
                v1_records.validate_integrity_contract(source, task_id=state.get("task_id"), worktree=state.get("worktree"), require_complete=False)
            except Exception as exc:
                raise h.HarnessError(f"integrity-upgrade-v2 requires a valid unsealed v1 contract: {exc}") from exc
            if source.get("seal") is not None:
                raise h.HarnessError("integrity-upgrade-v2 refuses a sealed v1 contract")
            raw, source_digest = _canonical_sha256(source)
            if source_digest != args.expected_v1_contract_sha256:
                raise h.HarnessError("expected v1 contract SHA-256 does not match canonical source bytes")
            migrated_at = args.recorded_at if h.is_semantic_v2_task(paths, task_id) else h.now_iso()
            source_head = args.expected_head_sha256 if h.is_semantic_v2_task(paths, task_id) else None
            preflight_source_artifact = records.build_artifact_ref(
                path="preflight/v1-integrity-contract.json", sha256=source_digest,
                size_bytes=len(raw),
            )
            # Validate the conversion before publication.  The following
            # second conversion swaps only the immutable CAS path/ref in the
            # receipt after preservation succeeds.
            try:
                preflight_migrated = records.migrate_v1_integrity_contract(
                    source, source_contract_artifact=preflight_source_artifact,
                    source_task_id=state.get("task_id"),
                    source_worktree=state.get("worktree"),
                    source_semantic_head_sha256=source_head, migrated_at=migrated_at,
                )
                records.validate_integrity_contract(
                    preflight_migrated, task_id=state.get("task_id"),
                    worktree=state.get("worktree"), require_complete=False,
                    source_v1_contract=source,
                )
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            artifact = artifacts.preserve_generated_artifact_blob(
                paths, task_id, raw, label="canonical v1 integrity contract",
                max_bytes=records.MAX_INTEGRITY_MIGRATION_SOURCE_BYTES,
            )
            try:
                migrated = records.migrate_v1_integrity_contract(
                    source, source_contract_artifact=artifact,
                    source_task_id=state.get("task_id"),
                    source_worktree=state.get("worktree"),
                    source_semantic_head_sha256=source_head, migrated_at=migrated_at,
                )
                records.validate_integrity_contract(
                    migrated, task_id=state.get("task_id"),
                    worktree=state.get("worktree"), require_complete=False,
                    source_v1_contract=source,
                )
            except records.IntegrityRecordError as exc:
                raise h.HarnessError(str(exc)) from exc
            # The receipt must bind immutable source bytes, never a mutable live v1 anchor.
            receipt = migrated.get("migration_receipt")
            if not isinstance(receipt, dict) or receipt.get("source_contract_artifact", {}).get("sha256") != artifact["sha256"]:
                raise h.HarnessError("v2 migration converter did not bind canonical v1 CAS source")
            state["integrity_contract"] = migrated
            return state, {"source_v1_contract_sha256": source_digest, "migration_artifact_sha256": artifact["sha256"], "integrity_mode": "required_v2"}
        result = _persist(args, paths, task_id, "integrity_upgrade_v2", mutate, lambda s: _retry_upgrade(args, paths, s))
    _emit(result, args.json)
    return 0


def cmd_integrity_show(args: argparse.Namespace, paths: h.HarnessPaths) -> int:
    state = h.load_task(paths, h.validate_id(args.task, "task id"))
    _emit({"task_id": state["task_id"], "integrity_contract": _contract(state)}, args.json)
    return 0


def _mutation_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--command-id")
    parser.add_argument("--recorded-at")
    parser.add_argument("--expected-head-sha256")


def register_integrity_commands(
    sub: argparse._SubParsersAction[argparse.ArgumentParser], *, handlers: Mapping[str, Handler],
    add_json_argument: Callable[[argparse.ArgumentParser], None],
) -> None:
    required = {"integrity_adopt", "integrity_snapshot", "integrity_review", "integrity_fix", "integrity_verify", "integrity_seal", "integrity_show", "integrity_upgrade_v2"}
    if set(handlers) != required:
        raise ValueError("integrity v2 command handler map mismatch")
    def add(name: str, key: str) -> argparse.ArgumentParser:
        parser = sub.add_parser(name); parser.add_argument("--task", required=True); return parser
    adopt = add("integrity-adopt", "integrity_adopt"); adopt.add_argument("--baseline-head"); _mutation_arguments(adopt); add_json_argument(adopt); adopt.set_defaults(handler=handlers["integrity_adopt"])
    snapshot = add("integrity-snapshot", "integrity_snapshot"); snapshot.add_argument("--purpose", choices=("candidate", "post_fix"), required=True); _mutation_arguments(snapshot); add_json_argument(snapshot); snapshot.set_defaults(handler=handlers["integrity_snapshot"])
    review = add("integrity-review", "integrity_review"); review.add_argument("--snapshot-record-sha256", required=True); review.add_argument("--reviewer-agent-id", required=True); review.add_argument("--result-artifact", required=True); review.add_argument("--outcome", choices=("clean", "findings"), required=True); review.add_argument("--finding-id", action="append", default=[]); _mutation_arguments(review); add_json_argument(review); review.set_defaults(handler=handlers["integrity_review"])
    fix = add("integrity-fix", "integrity_fix"); fix.add_argument("--finding-id", required=True); fix.add_argument("--post-fix-snapshot-record-sha256", required=True); fix.add_argument("--fix-artifact", required=True); _mutation_arguments(fix); add_json_argument(fix); fix.set_defaults(handler=handlers["integrity_fix"])
    verify = add("integrity-verify", "integrity_verify"); verify.add_argument("--finding-id", required=True); verify.add_argument("--fix-record-sha256", required=True); verify.add_argument("--verification-snapshot-record-sha256", required=True); verify.add_argument("--reviewer-agent-id", required=True); verify.add_argument("--verification-artifact", required=True); verify.add_argument("--outcome", choices=("pass", "fail"), required=True); _mutation_arguments(verify); add_json_argument(verify); verify.set_defaults(handler=handlers["integrity_verify"])
    seal = add("integrity-seal", "integrity_seal"); _mutation_arguments(seal); add_json_argument(seal); seal.set_defaults(handler=handlers["integrity_seal"])
    upgrade = add("integrity-upgrade-v2", "integrity_upgrade_v2"); upgrade.add_argument("--expected-v1-contract-sha256", required=True); _mutation_arguments(upgrade); add_json_argument(upgrade); upgrade.set_defaults(handler=handlers["integrity_upgrade_v2"])
    show = add("integrity-show", "integrity_show"); add_json_argument(show); show.set_defaults(handler=handlers["integrity_show"])


__all__ = [name for name in globals() if name.startswith("cmd_integrity_")] + ["register_integrity_commands"]
