from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import codex_adapter_contracts as contracts
from aoi_orgware.semantic_events import canonical_sha256


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def observed(value: str) -> dict[str, str | None]:
    return {"status": "observed", "value": value}


def missing(status: str = "missing") -> dict[str, str | None]:
    return {"status": status, "value": None}


def stop_receipt(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "receipt_type": contracts.CODEX_SUBAGENT_STOP_V1,
        "event_identity": {"session_id": "session-1", "turn_id": "turn-1", "agent_id": "agent-1", "event_id": "stop-1"},
        "observed_at": "2026-07-19T01:02:03Z",
        "transcript_path_observation": observed("C:/transcripts/one.jsonl"),
        "last_assistant_message": {"sha256": observed(SHA_A), "size_bytes": observed("123"), "presence": observed("present")},
        "model_observation": observed("gpt-5.6"),
        "permission_mode_observation": observed("workspace-write"),
        "start_correlation": {"status": "matched", "start_receipt_sha256": observed(SHA_B)},
        "no_material_work_verified": False,
    }
    value.update(changes)
    return value


def pre_receipt(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "receipt_type": contracts.CODEX_PRETOOL_CLAIM_DECISION_V1,
        "event_identity": {"session_id": "session-1", "turn_id": "turn-1", "tool_use_id": "use-1"},
        "tool_name": "apply_patch",
        "input_sha256": SHA_A,
        "parser": {"id": "apply-patch-v1", "version": "1"},
        "targets": ["src/a.py", "tests/test_a.py"],
        "session_mapping": {"status": "mapped", "task_id": observed("task-1")},
        "claim_snapshot_sha256": observed(SHA_B),
        "claim_coverage": "covered",
        "decision": "allow",
        "provider_verification": "unavailable",
        "profile_verification": "unavailable",
        "sandbox_verification": "unavailable",
    }
    value.update(changes)
    return value


def post_receipt(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "receipt_type": contracts.CODEX_POSTTOOL_MUTATION_OBSERVATION_V1,
        "event_identity": {"session_id": "session-1", "turn_id": "turn-1", "tool_use_id": "use-1"},
        "pre_receipt_sha256": SHA_A,
        "input_sha256": SHA_B,
        "response_sha256": SHA_C,
        "targets": ["src/a.py"],
        "tool_completion_observed": True,
        "mutation_effect_verified": {"status": "verified", "before_sha256": SHA_A, "after_sha256": SHA_D},
    }
    value.update(changes)
    return value


@pytest.mark.parametrize(
    ("base", "seal", "validate", "digest"),
    (
        (stop_receipt, contracts.seal_codex_subagent_stop_receipt, contracts.validate_codex_subagent_stop_receipt, contracts.codex_subagent_stop_receipt_sha256),
        (pre_receipt, contracts.seal_codex_pretool_claim_decision_receipt, contracts.validate_codex_pretool_claim_decision_receipt, contracts.codex_pretool_claim_decision_receipt_sha256),
        (post_receipt, contracts.seal_codex_posttool_mutation_observation_receipt, contracts.validate_codex_posttool_mutation_observation_receipt, contracts.codex_posttool_mutation_observation_receipt_sha256),
    ),
)
def test_each_receipt_type_seals_canonically_and_validates(base, seal, validate, digest) -> None:
    sealed = seal(base())
    assert sealed["receipt_sha256"] == digest(base())
    assert validate(sealed) == sealed
    assert contracts.validate_codex_adapter_receipt(sealed) == sealed


def test_stop_is_identity_bound_and_never_uses_no_material_work_as_completion() -> None:
    sealed = contracts.seal_codex_subagent_stop_receipt(stop_receipt())
    assert set(sealed) == {
        "receipt_type", "event_identity", "observed_at", "transcript_path_observation",
        "last_assistant_message", "model_observation", "permission_mode_observation",
        "start_correlation", "no_material_work_verified", "receipt_sha256",
    }
    for field, value in (("no_material_work_verified", True), ("packet_id", "packet-1")):
        malformed = copy.deepcopy(sealed)
        malformed[field] = value
        with pytest.raises(contracts.CodexAdapterContractError):
            contracts.validate_codex_subagent_stop_receipt(malformed)


def test_stop_agent_identity_uses_shared_canonical_grammar_and_boundary() -> None:
    for agent_id in (
        "/root/reviewer",
        "operator@example.invalid",
        "/" + "a" * 511,
    ):
        value = stop_receipt()
        value["event_identity"]["agent_id"] = agent_id  # type: ignore[index]
        sealed = contracts.seal_codex_subagent_stop_receipt(value)
        assert sealed["event_identity"]["agent_id"] == agent_id

    for agent_id in (
        "agent identity",
        "agent+identity",
        "agent\nidentity",
        "代理者",
        "/" + "a" * 512,
    ):
        value = stop_receipt()
        value["event_identity"]["agent_id"] = agent_id  # type: ignore[index]
        with pytest.raises(contracts.CodexAdapterContractError, match="1-512 ASCII"):
            contracts.seal_codex_subagent_stop_receipt(value)


def test_stop_v1_reader_preserves_legacy_identity_compatibility() -> None:
    legacy = stop_receipt()
    legacy["event_identity"]["agent_id"] = "legacy reviewer"  # type: ignore[index]
    sealed = {
        **legacy,
        "receipt_sha256": canonical_sha256(
            legacy, max_bytes=contracts.MAX_RECEIPT_BYTES
        ),
    }
    assert contracts.validate_codex_subagent_stop_receipt(sealed) == sealed
    with pytest.raises(contracts.CodexAdapterContractError, match="1-512 ASCII"):
        contracts.seal_codex_subagent_stop_receipt(legacy)


def test_observation_contract_never_coerces_integers_to_text() -> None:
    malformed = stop_receipt(last_assistant_message={"sha256": observed(SHA_A), "size_bytes": {"status": "observed", "value": 123}, "presence": observed("present")})
    with pytest.raises(contracts.CodexAdapterContractError, match="size_bytes.value"):
        contracts.seal_codex_subagent_stop_receipt(malformed)
    malformed = stop_receipt(transcript_path_observation={"status": "missing", "value": "not-null"})
    with pytest.raises(contracts.CodexAdapterContractError, match="must be null"):
        contracts.seal_codex_subagent_stop_receipt(malformed)


def test_stop_start_correlation_and_observed_message_fields_are_honest() -> None:
    with pytest.raises(contracts.CodexAdapterContractError, match="matched"):
        contracts.seal_codex_subagent_stop_receipt(stop_receipt(start_correlation={"status": "matched", "start_receipt_sha256": missing()}))
    with pytest.raises(contracts.CodexAdapterContractError, match="canonical decimal"):
        contracts.seal_codex_subagent_stop_receipt(stop_receipt(last_assistant_message={"sha256": observed(SHA_A), "size_bytes": observed("0123"), "presence": observed("present")}))


def test_pretool_is_bounded_canonical_and_has_no_provider_profile_or_sandbox_claim() -> None:
    with pytest.raises(contracts.CodexAdapterContractError, match="sorted and unique"):
        contracts.seal_codex_pretool_claim_decision_receipt(pre_receipt(targets=["tests/test_a.py", "src/a.py", "src/a.py"]))
    with pytest.raises(contracts.CodexAdapterContractError, match="provider_verification"):
        contracts.seal_codex_pretool_claim_decision_receipt(pre_receipt(provider_verification="verified"))
    with pytest.raises(contracts.CodexAdapterContractError, match="mapped"):
        contracts.seal_codex_pretool_claim_decision_receipt(pre_receipt(session_mapping={"status": "mapped", "task_id": missing()}))
    with pytest.raises(contracts.CodexAdapterContractError, match="targets"):
        contracts.seal_codex_pretool_claim_decision_receipt(pre_receipt(targets=[f"f-{index}" for index in range(65)]))


@pytest.mark.parametrize("seal,base", (
    (contracts.seal_codex_pretool_claim_decision_receipt, pre_receipt),
    (contracts.seal_codex_posttool_mutation_observation_receipt, post_receipt),
))
def test_tool_receipts_reject_optional_agent_or_event_identity_drift(seal, base) -> None:
    for field in ("agent_id", "event_id"):
        malformed = base()
        malformed["event_identity"][field] = f"optional-{field}"
        with pytest.raises(contracts.CodexAdapterContractError, match="schema is invalid"):
            seal(malformed)


def test_posttool_requires_pre_binding_and_explicit_effect_evidence() -> None:
    with pytest.raises(contracts.CodexAdapterContractError, match="before/after evidence"):
        contracts.seal_codex_posttool_mutation_observation_receipt(post_receipt(mutation_effect_verified={"status": "verified"}))
    with pytest.raises(contracts.CodexAdapterContractError, match="must differ"):
        contracts.seal_codex_posttool_mutation_observation_receipt(post_receipt(mutation_effect_verified={"status": "verified", "before_sha256": SHA_A, "after_sha256": SHA_A}))
    unavailable = contracts.seal_codex_posttool_mutation_observation_receipt(post_receipt(mutation_effect_verified={"status": "unavailable"}))
    assert unavailable["mutation_effect_verified"] == {"status": "unavailable"}


def test_tampering_and_oversized_receipts_fail_closed() -> None:
    sealed = contracts.seal_codex_pretool_claim_decision_receipt(pre_receipt())
    sealed["decision"] = "deny"
    with pytest.raises(contracts.CodexAdapterContractError, match="does not match"):
        contracts.validate_codex_pretool_claim_decision_receipt(sealed)
    with pytest.raises(contracts.CodexAdapterContractError, match="byte bound"):
        contracts.seal_codex_pretool_claim_decision_receipt(
            pre_receipt(targets=[f"{index:02d}" + "x" * 1022 for index in range(64)])
        )
