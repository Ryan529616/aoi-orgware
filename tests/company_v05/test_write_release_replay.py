"""Real-ledger replay coverage for the observation-only W3 release view."""

from __future__ import annotations

import hashlib
import gc
from pathlib import Path
import sys
from typing import Any, Mapping

import pytest

from aoi_orgware.company.contracts import (
    EXECUTION_NODE_V1,
    authority_from_grant,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.supervisor import CompanySupervisor
from aoi_orgware.company.write_admission import (
    WORK_WRITE_INTENT_V1,
    seal_work_write_intent,
)
from aoi_orgware.company.write_admission_invariants import (
    external_job_reservation_id,
    external_job_write_owner_anchor,
)
from aoi_orgware.company.write_release import derive_write_release
from aoi_orgware.semantic_events import canonical_json_bytes, canonical_sha256

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_department_lifecycle as lifecycle  # type: ignore[import-not-found]
import test_external_jobs as jobs  # type: ignore[import-not-found]
import test_work_definition_registration as registration  # type: ignore[import-not-found]
import test_write_admission_gate_regressions as gate  # type: ignore[import-not-found]
import test_write_admission_projection as support  # type: ignore[import-not-found]


def _tree_ref() -> dict[str, str | int]:
    return {
        "schema_version": 1,
        "kind": "tree",
        "namespace": "repo",
        "canonical_identity": "docs",
        "filesystem_semantics": "posix-v1",
    }


def _stage_external_job(
    supervisor: CompanySupervisor,
) -> tuple[str, str, tuple[Mapping[str, Any], ...]]:
    """Stage a real, un-enforced W2 chain then queue one external job."""
    task, packet, context, prompt = registration._work_bundle(supervisor)
    task["authority_ceiling"] = {
        **task["authority_ceiling"],
        "write_refs": [
            {"kind": "tree", "path": "docs"},
            {"kind": "tree", "path": "src"},
        ],
    }
    registration._rehash(task, "task_sha256")
    context["source_entries"] = [
        {"path": "docs", "entry_type": "directory", "sha256": "d" * 64, "size_bytes": 0},
        *context["source_entries"],
    ]
    context["source_manifest_sha256"] = hashlib.sha256(
        canonical_company_json_bytes(context["source_entries"]),
    ).hexdigest()
    packet["authority_scope"] = {
        **packet["authority_scope"],
        "write_refs": [
            {"kind": "tree", "path": "docs"},
            {"kind": "file", "path": "src/a.py"},
        ],
    }
    packet["task_sha256"] = task["task_sha256"]
    packet["source_manifest_sha256"] = context["source_manifest_sha256"]
    context_bytes = canonical_company_json_bytes(context)
    packet["context_manifest_ref"] = {
        **packet["context_manifest_ref"],
        "sha256": hashlib.sha256(context_bytes).hexdigest(),
        "size_bytes": len(context_bytes),
    }
    registration._rehash(packet, "packet_sha256")
    registration._register(supervisor, task, packet, context, prompt)
    owner = next(
        item.payload for item in supervisor.objects(contract_type=EXECUTION_NODE_V1)
        if item.payload["execution_kind"] == "carrier" and item.payload["role"] == "chief"
    )
    scope_sha256 = company_contract_sha256(packet["authority_scope"])
    job_grant = gate._chief_job_grant(
        supervisor, scope_sha256=scope_sha256, issued_at="2026-07-27T00:03:00Z",
    )
    supervisor.commit(
        support._request(
            supervisor, [job_grant], transaction_id="release-job-grant-tx-1",
            command_id="release-job-grant-command-1", recorded_at="2026-07-27T00:03:00Z",
        ),
        recorded_at="2026-07-27T00:03:00Z",
    )
    command = b'{"tool":"vcs"}'
    job_id = "release-job-1"
    mutation_intent_id = "release-job-intent-1"
    command_blob = gate._available_blob(supervisor, command, media_type="application/json")
    job_identity = {
        "job_id": job_id,
        "owner_execution_id": owner["execution_id"],
        "mutation_intent_id": mutation_intent_id,
        "command_id": "release-job-command-1",
        "command_blob": support._plain(command_blob),
        "scope_sha256": scope_sha256,
        "actor_authority": authority_from_grant(job_grant),
    }
    domain = support._domain()
    # A single W2 intent carries every conflict class.  W3 must return this
    # whole immutable vector or none of it; it has no partial-release state.
    refs = sorted([
        support._file_ref(),
        _tree_ref(),
        support._opaque_ref("output_namespace", "release-output-1", "outputs"),
        support._opaque_ref("serialization_key", "release-serial-1", "serial"),
    ], key=canonical_json_bytes)
    intent = seal_work_write_intent({
        "contract_type": WORK_WRITE_INTENT_V1,
        "schema_version": 1,
        **support.BINDING,
        "intent_id": "release-write-intent-1",
        "domain_binding_id": domain["binding_id"],
        "domain_binding_sha256": domain["binding_sha256"],
        "owner_kind": "external_job",
        "owner_id": job_id,
        "owner_generation_id": mutation_intent_id,
        "owner_anchor_sha256": external_job_write_owner_anchor(job_identity),
        "reservation_id": external_job_reservation_id(job_id, mutation_intent_id),
        "task_id": packet["task_id"],
        "packet_id": packet["packet_id"],
        "packet_sha256": packet["packet_sha256"],
        "authority_scope_sha256": scope_sha256,
        "refs": refs,
        "refs_sha256": canonical_sha256(refs),
        "created_at": support.T3,
        "provenance": "AOI_verified",
        "observation": support.OBSERVED,
    })
    capability = support._capability(domain, intent, support._supervisor_grant(supervisor))
    for payload, label, recorded_at in (
        (domain, "release-domain", support.T2),
        (intent, "release-intent", support.T3),
        (capability, "release-capability", support.T4),
    ):
        supervisor.commit(
            support._request(
                supervisor, [payload], transaction_id=f"{label}-tx-1",
                command_id=f"{label}-command-1", recorded_at=recorded_at,
            ),
            recorded_at=recorded_at,
        )
    supervisor.queue_external_job(
        str(owner["execution_id"]), job_id=job_id, job_execution_id="release-job-execution-1",
        mutation_intent_id=mutation_intent_id, command_bytes=command,
        command_media_type="application/json", scope_sha256=scope_sha256,
        display_name="W3 known-not-started job", objective="Exercise observation-only release.",
        authority_grant_id=str(job_grant["grant_id"]), grant_expires_at=str(job_grant["expires_at"]),
        transaction_id="release-job-queue-tx-1", command_id="release-job-command-1",
        recorded_at=support.T6,
    )
    return str(intent["intent_id"]), job_id, tuple(refs)


def test_external_job_hold_abort_rebuild_and_reopen_are_observational(
    tmp_path: Path,
) -> None:
    supervisor = lifecycle._initialize(tmp_path)
    slot_root = supervisor.slot_root
    try:
        intent_id, job_id, expected_refs = _stage_external_job(supervisor)
        held = derive_write_release(supervisor._state, intent_id)
        assert held.disposition == "held"
        assert held.reason_codes == ("external_job_may_still_write",)

        jobs._record(
            supervisor, job_id, "aborted", suffix="release", recorded_at="2026-07-27T00:09:00Z",
        )
        unresolved = derive_write_release(supervisor._state, intent_id)
        # A reducer-valid aborted graph is still only negative observation;
        # this alpha has no typed durable writer-quiescence closure receipt.
        assert unresolved.disposition == "coverage_unknown"
        assert unresolved.reason_codes == ("release_proof_contract_unavailable",)
        assert unresolved.refs == expected_refs
        assert {ref["kind"] for ref in unresolved.refs} == {
            "file", "tree", "output_namespace", "serialization_key",
        }
        assert "kind" in unresolved.refs[0]
        assert dict(unresolved.refs[0]) == expected_refs[0]
        immutable_refs = unresolved.refs
        immutable_digest = unresolved.evidence_digest
        immutable_head = unresolved.head_sha256
        assert not hasattr(unresolved, "__dict__")
        with pytest.raises(AttributeError):
            unresolved.refs = ()  # type: ignore[misc]
        with pytest.raises((AttributeError, TypeError)):
            object.__setattr__(unresolved, "refs", ())
        with pytest.raises(TypeError):
            unresolved.refs[0]["canonical_identity"] = "forged"  # type: ignore[index]
        with pytest.raises(TypeError):
            dict.__setitem__(unresolved.refs[0], "canonical_identity", "forged")
        nested = next(
            (member for member in unresolved.refs[0].values() if isinstance(member, Mapping)),
            None,
        )
        if nested is not None:
            with pytest.raises(TypeError):
                nested["forged"] = "forged"  # type: ignore[index]
        assert unresolved.refs == immutable_refs
        assert unresolved.evidence_digest == immutable_digest
        assert unresolved.head_sha256 == immutable_head
        # _FrozenMapping exposes only tuple/scalar storage.  Ignore the class
        # metadata referent itself; it is not instance-owned receipt storage.
        pending = [unresolved.refs]
        seen: set[int] = set()
        mutable_backing: list[object] = []
        while pending:
            current = pending.pop()
            if id(current) in seen:
                continue
            seen.add(id(current))
            for child in gc.get_referents(current):
                if isinstance(child, type):
                    continue
                if isinstance(child, (dict, list)):
                    mutable_backing.append(child)
                pending.append(child)
        assert mutable_backing == []
        before = supervisor.heads().global_head.global_sequence
        assert unresolved.cursor == before
        assert supervisor._state.rebuild_projection().global_sequence == before
    finally:
        supervisor.close()

    with CompanySupervisor.open(slot_root) as reopened:
        assert reopened._state.rebuild_projection().global_sequence == before
        replay = derive_write_release(reopened._state, intent_id)
        assert replay.disposition == "coverage_unknown"
        assert replay.cursor == unresolved.cursor
        assert replay.head_sha256 == unresolved.head_sha256
        assert replay.evidence_digest == unresolved.evidence_digest
        assert replay.refs == unresolved.refs
        # This slice has no positive-release matrix: every tested state is
        # either not acquired, held, or explicitly coverage unknown.
        assert "release_proven" not in {held.disposition, unresolved.disposition, replay.disposition}
