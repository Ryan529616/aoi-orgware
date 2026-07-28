from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import sys
from typing import Any, Mapping

import pytest

from aoi_orgware.company.contracts import (
    BLOB_REF_V1,
    CHIEF_TERM_V1,
    DEPARTMENT_IDENTITY_V1,
    DEPARTMENT_SNAPSHOT_V1,
    EXECUTION_NODE_V1,
    ORGANIZATION_NODE_V1,
    TASK_REVISION_V1,
    WORK_CONTEXT_MANIFEST_MEDIA_TYPE,
    WORK_PACKET_PROMPT_MEDIA_TYPE,
    WORK_PACKET_V1,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.supervisor import (
    CompanySupervisor,
    CompanySupervisorError,
    CompanyWorkDefinitionError,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_company_contracts import (  # type: ignore[import-not-found]
    task_revision,
    work_context_manifest,
    work_packet,
)


T0 = "2026-07-27T00:00:00Z"
TASK_TIME = "2026-07-27T00:00:01Z"
PACKET_TIME = "2026-07-27T00:00:02Z"
EXPIRY = "2026-07-28T00:00:00Z"


def _manifest() -> dict[str, Any]:
    return {
        "contract_type": "company_manifest_v1",
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "git_common_dir_sha256": "a" * 64,
        "remote_fingerprint_sha256": "b" * 64,
        "configuration_sha256": "c" * 64,
        "state_root_sha256": "d" * 64,
        "lock_domain_id": "windows" if os.name == "nt" else "posix",
        "created_at": T0,
        "observation": {"state": "known", "reason": "observed"},
    }


def _carrier() -> dict[str, Any]:
    return {
        "carrier_id": "carrier-1",
        "provider": "codex",
        "model": "gpt-5",
        "session_id": "session-1",
        "thread_id": "thread-1",
        "provenance": "agent_reported",
        "observation": {"state": "known", "reason": "observed"},
    }


def _initialize(tmp_path: Path) -> CompanySupervisor:
    return CompanySupervisor.initialize(
        tmp_path / "state" / "companies" / "company-1",
        _manifest(),
        bootstrap_at=T0,
        grant_expires_at=EXPIRY,
        platform="windows" if os.name == "nt" else "posix",
        known_carrier=_carrier(),
    )


def _objects(
    supervisor: CompanySupervisor,
    contract_type: str,
) -> list[dict[str, Any]]:
    return [
        _plain(item.payload)
        for item in supervisor.objects(contract_type=contract_type)
    ]


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _plain(member)
            for key, member in value.items()
        }
    if isinstance(value, tuple):
        return [_plain(member) for member in value]
    return value


def _blob_ref(
    payload: bytes,
    media_type: str,
    supervisor: CompanySupervisor,
) -> dict[str, Any]:
    metadata = supervisor._state.blobs.put(payload)
    return {
        "contract_type": BLOB_REF_V1,
        "schema_version": 1,
        "sha256": metadata.sha256,
        "size_bytes": metadata.size_bytes,
        "media_type": media_type,
        "availability": "available",
    }


def _rehash(value: dict[str, Any], field: str) -> None:
    value[field] = company_contract_sha256({
        key: member
        for key, member in value.items()
        if key != field
    })


def _chief_fence(supervisor: CompanySupervisor) -> dict[str, Any]:
    term = _objects(supervisor, CHIEF_TERM_V1)[0]
    execution = next(
        item
        for item in _objects(supervisor, EXECUTION_NODE_V1)
        if item["role"] == "chief"
        and item["carrier_id"] == term["carrier_id"]
    )
    return {
        "chief_id": term["chief_id"],
        "carrier_id": term["carrier_id"],
        "term": term["term"],
        "epoch": term["epoch"],
        "chief_execution_id": execution["execution_id"],
    }


def _work_bundle(
    supervisor: CompanySupervisor,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bytes]:
    binding = {
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
    }
    rtl = next(
        item
        for item in _objects(supervisor, DEPARTMENT_IDENTITY_V1)
        if item["name"] == "RTL"
    )
    snapshot = next(
        item
        for item in _objects(supervisor, DEPARTMENT_SNAPSHOT_V1)
        if item["department_id"] == rtl["department_id"]
    )
    chief_node = next(
        item
        for item in _objects(supervisor, ORGANIZATION_NODE_V1)
        if item["role"] == "chief"
    )
    chief_execution = next(
        item
        for item in _objects(supervisor, EXECUTION_NODE_V1)
        if item["role"] == "chief"
    )

    context = copy.deepcopy(work_context_manifest())
    context.update(binding)
    context["department_snapshot_ref"] = _plain(
        snapshot["artifact_refs"][0],
    )
    context["upstream_result_refs"] = []
    for entries_field, digest_field in (
        ("source_entries", "source_manifest_sha256"),
        ("config_entries", "config_manifest_sha256"),
        ("dependency_entries", "dependency_manifest_sha256"),
    ):
        context[digest_field] = hashlib.sha256(
            canonical_company_json_bytes(context[entries_field]),
        ).hexdigest()

    completion = _blob_ref(
        b"Return a reviewed terminal engineering disposition.",
        "text/plain",
        supervisor,
    )
    task = copy.deepcopy(task_revision())
    task.update(binding)
    task["completion_boundary_ref"] = completion
    task["created_at"] = TASK_TIME
    _rehash(task, "task_sha256")

    prompt = b"Inspect the bounded source cut and return evidence only."
    packet = copy.deepcopy(
        work_packet(
            prompt_digest=hashlib.sha256(prompt).hexdigest(),
            context=context,
            task=task,
        ),
    )
    packet.update(binding)
    packet["manager_node_id"] = chief_node["node_id"]
    packet["parent_execution_id"] = chief_execution["execution_id"]
    packet["target_node_id"] = rtl["lead_node_id"]
    packet["department_id"] = rtl["department_id"]
    packet["null_relationship_justifications"] = {
        "manager_node_id": None,
        "parent_execution_id": None,
        "target_node_id": None,
        "department_id": None,
    }
    packet["prompt_ref"] = {
        "contract_type": BLOB_REF_V1,
        "schema_version": 1,
        "sha256": hashlib.sha256(prompt).hexdigest(),
        "size_bytes": len(prompt),
        "media_type": WORK_PACKET_PROMPT_MEDIA_TYPE,
        "availability": "available",
    }
    context_bytes = canonical_company_json_bytes(context)
    packet["context_manifest_ref"] = {
        "contract_type": BLOB_REF_V1,
        "schema_version": 1,
        "sha256": hashlib.sha256(context_bytes).hexdigest(),
        "size_bytes": len(context_bytes),
        "media_type": WORK_CONTEXT_MANIFEST_MEDIA_TYPE,
        "availability": "available",
    }
    packet["created_at"] = PACKET_TIME
    packet["expires_at"] = "2026-07-27T01:00:00Z"
    _rehash(packet, "packet_sha256")
    return task, packet, context, prompt


def _register(
    supervisor: CompanySupervisor,
    task: Mapping[str, Any],
    packet: Mapping[str, Any],
    context: Mapping[str, Any],
    prompt: bytes,
    *,
    transaction_id: str = "work-register-transaction-1",
    command_id: str = "work-register-command-1",
) -> Any:
    return supervisor.register_work_definition(
        task,
        packet,
        context,
        prompt,
        **_chief_fence(supervisor),
        transaction_id=transaction_id,
        command_id=command_id,
        recorded_at=PACKET_TIME,
    )


def test_root_work_definition_registers_replays_and_reopens(
    tmp_path: Path,
) -> None:
    supervisor = _initialize(tmp_path)
    slot_root = supervisor.slot_root
    task, packet, context, prompt = _work_bundle(supervisor)

    first = _register(supervisor, task, packet, context, prompt)
    second = _register(supervisor, task, packet, context, prompt)

    assert not first.idempotent_replay
    assert second.idempotent_replay
    assert second.global_sequence == first.global_sequence
    assert [item["task_revision_id"] for item in _objects(
        supervisor,
        TASK_REVISION_V1,
    )] == [task["task_revision_id"]]
    assert [item["packet_id"] for item in _objects(
        supervisor,
        WORK_PACKET_V1,
    )] == [packet["packet_id"]]
    supervisor.close()

    with CompanySupervisor.open(slot_root) as reopened:
        assert _objects(reopened, TASK_REVISION_V1)[0] == task
        assert _objects(reopened, WORK_PACKET_V1)[0] == packet


def test_durable_work_definition_replay_requires_current_chief_execution(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        task, packet, context, prompt = _work_bundle(supervisor)
        fence = _chief_fence(supervisor)
        first = supervisor.register_work_definition(
            task,
            packet,
            context,
            prompt,
            **fence,
            transaction_id="work-register-transaction-1",
            command_id="work-register-command-1",
            recorded_at=PACKET_TIME,
        )
        with pytest.raises(CompanySupervisorError, match="Chief fence is stale"):
            supervisor.register_work_definition(
                task,
                packet,
                context,
                prompt,
                **{**fence, "chief_execution_id": "changed-chief-execution"},
                transaction_id="work-register-transaction-1",
                command_id="work-register-command-1",
                recorded_at=PACKET_TIME,
            )
        assert supervisor.heads().global_head.global_sequence == first.global_sequence


def test_durable_work_definition_enforcement_replay_requires_current_chief_execution(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        fence = _chief_fence(supervisor)
        first = supervisor.activate_work_definition_enforcement(
            **fence,
            transaction_id="work-enforcement-transaction-1",
            command_id="work-enforcement-command-1",
            activated_at=PACKET_TIME,
        )
        replay = supervisor.activate_work_definition_enforcement(
            **fence,
            transaction_id="work-enforcement-transaction-1",
            command_id="work-enforcement-command-1",
            activated_at=PACKET_TIME,
        )
        assert replay.idempotent_replay
        with pytest.raises(CompanySupervisorError, match="Chief fence is stale"):
            supervisor.activate_work_definition_enforcement(
                **{**fence, "chief_execution_id": "stale-chief-execution"},
                transaction_id="work-enforcement-transaction-1",
                command_id="work-enforcement-command-1",
                activated_at=PACKET_TIME,
            )
        assert supervisor.heads().global_head.global_sequence == first.global_sequence


def test_registration_rejects_cas_mismatch_and_packet_collision(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        task, packet, context, prompt = _work_bundle(supervisor)
        with pytest.raises(
            CompanyWorkDefinitionError,
            match="prompt or context CAS",
        ):
            _register(
                supervisor,
                task,
                packet,
                context,
                prompt + b" divergent",
            )
        _register(supervisor, task, packet, context, prompt)
        with pytest.raises(
            CompanyWorkDefinitionError,
            match="already durable",
        ):
            _register(
                supervisor,
                task,
                packet,
                context,
                prompt,
                transaction_id="work-register-transaction-2",
                command_id="work-register-command-2",
            )


def test_fenced_chief_cannot_create_orphaned_work_definition_blobs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _initialize(tmp_path) as supervisor:
        task, packet, context, prompt = _work_bundle(supervisor)
        stale_fence = _chief_fence(supervisor)
        stale_fence["epoch"] = int(stale_fence["epoch"]) + 1

        def fail_put(_: bytes) -> Any:
            raise AssertionError("fenced Chief must not write CAS blobs")

        monkeypatch.setattr(supervisor._state.blobs, "put", fail_put)
        with pytest.raises(CompanySupervisorError, match="Chief fence is stale"):
            supervisor.register_work_definition(
                task,
                packet,
                context,
                prompt,
                **stale_fence,
                transaction_id="fenced-work-register-transaction",
                command_id="fenced-work-register-command",
                recorded_at=PACKET_TIME,
            )


def test_fenced_original_chief_cannot_replay_durable_work_after_takeover(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _initialize(tmp_path) as supervisor:
        task, packet, context, prompt = _work_bundle(supervisor)
        original_fence = _chief_fence(supervisor)
        _register(supervisor, task, packet, context, prompt)
        contender = {
            "carrier_id": "carrier-2",
            "provider": "codex",
            "model": "gpt-5",
            "session_id": "session-2",
            "thread_id": "thread-2",
            "provenance": "agent_reported",
            "observation": {"state": "known", "reason": "observed"},
        }
        capability = supervisor.prepare_chief_takeover(
            contender,
            user_action_ref="replay-work-definition-after-takeover",
            objective_sha256="e" * 64,
            scope_sha256="f" * 64,
            nonce_sha256="2" * 64,
            issued_at="2026-07-27T00:10:00Z",
            expires_at="2026-07-27T00:20:00Z",
        )
        supervisor.takeover_chief(
            capability,
            contender,
            consumed_at="2026-07-27T00:11:00Z",
            grant_expires_at=EXPIRY,
        )

        def fail_put(_: bytes) -> Any:
            raise AssertionError("durable replay must not recreate CAS blobs")

        monkeypatch.setattr(supervisor._state.blobs, "put", fail_put)
        cursor_after_takeover = supervisor.heads().global_head.global_sequence
        with pytest.raises(CompanySupervisorError, match="Chief fence is stale"):
            supervisor.register_work_definition(
                task,
                packet,
                context,
                prompt,
                **original_fence,
                transaction_id="work-register-transaction-1",
                command_id="work-register-command-1",
                recorded_at=PACKET_TIME,
            )
        assert supervisor.heads().global_head.global_sequence == cursor_after_takeover


def test_durable_replay_requires_exact_prompt_and_context_without_blob_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _initialize(tmp_path) as supervisor:
        task, packet, context, prompt = _work_bundle(supervisor)
        original_fence = _chief_fence(supervisor)
        _register(supervisor, task, packet, context, prompt)

        def fail_put(_: bytes) -> Any:
            raise AssertionError("durable replay must not write CAS blobs")

        monkeypatch.setattr(supervisor._state.blobs, "put", fail_put)
        with pytest.raises(
            CompanyWorkDefinitionError,
            match="durable work definition CAS bytes differ",
        ):
            supervisor.register_work_definition(
                task,
                packet,
                context,
                prompt + b" divergent replay",
                **original_fence,
                transaction_id="work-register-transaction-1",
                command_id="work-register-command-1",
                recorded_at=PACKET_TIME,
            )

        divergent_context = copy.deepcopy(context)
        divergent_context["repository_id"] = "repo-divergent"
        with pytest.raises(
            CompanyWorkDefinitionError,
            match="durable work definition CAS bytes differ",
        ):
            supervisor.register_work_definition(
                task,
                packet,
                divergent_context,
                prompt,
                **original_fence,
                transaction_id="work-register-transaction-1",
                command_id="work-register-command-1",
                recorded_at=PACKET_TIME,
            )


def test_preflight_resolves_request_local_parent_before_durable_parent(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        task, parent, context, prompt = _work_bundle(supervisor)
        child = copy.deepcopy(parent)
        child.update({
            "packet_id": "packet-child-1",
            "parent_packet_id": parent["packet_id"],
            "parent_packet_sha256": parent["packet_sha256"],
            "delegation_depth": 2,
            "authority_scope": {
                **child["authority_scope"],
                "write_refs": [],
            },
        })
        _rehash(child, "packet_sha256")

        supervisor._state.blobs.put(prompt)
        supervisor._state.blobs.put(canonical_company_json_bytes(context))
        # The child intentionally precedes its parent.  The batch preflight
        # must construct the request-local packet map before resolving links.
        supervisor._state._verify_work_definition_request_unlocked({
            "events": [
                {"payload": child},
                {"payload": parent},
                {"payload": task},
            ],
        })


def test_cas_orphan_before_ledger_commit_is_safe_to_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _initialize(tmp_path) as supervisor:
        task, packet, context, prompt = _work_bundle(supervisor)
        original_commit = supervisor.commit

        def fail_before_ledger(*_args: object, **_kwargs: object) -> Any:
            raise RuntimeError("injected before ledger commit")

        monkeypatch.setattr(supervisor, "commit", fail_before_ledger)
        with pytest.raises(RuntimeError, match="injected"):
            _register(supervisor, task, packet, context, prompt)
        assert supervisor.record_by_transaction_id(
            "work-register-transaction-1",
        ) is None
        assert supervisor._state.blobs.read(
            packet["prompt_ref"]["sha256"],
        ) == prompt

        monkeypatch.setattr(supervisor, "commit", original_commit)
        result = _register(supervisor, task, packet, context, prompt)
        assert not result.idempotent_replay
