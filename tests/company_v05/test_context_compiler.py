"""AOI-SYNTHETIC-FIXTURE-V1: reader-only compiler boundaries."""
from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import pytest

from aoi_orgware.company.context.compiler import (
    ContextArtifact, ContextCompilerError, NeedsContext, RootContextEnvelope,
    TokenizerObservation, compile_child_work_context, compile_root_work_context,
    selected_upstream_result, verify_child_work_context, verify_root_work_context,
)
from aoi_orgware.company.context.v2_contract import work_context_manifest_v2_sha256
from aoi_orgware.company.contracts import (
    DEPARTMENT_SNAPSHOT_MEDIA_TYPE, MAX_CONTRACT_BYTES,
    canonical_company_json_bytes,
)
from aoi_orgware.company.scheduling.qos import work_qos_intent_v1_preimage_sha256


def _entry(entry_id: str, section: str, path: str, content: bytes, *, requirement: str = "mandatory", state: str = "selected", layer: str = "L1", blob: bool = False) -> dict[str, Any]:
    digest = hashlib.sha256(content).hexdigest()
    atom = {"carrier_section": section, "carrier_path": path, "entry_type": "blob_ref" if blob else "file", "contract_type": "blob_ref_v1" if blob else None, "schema_version": 1 if blob else None, "content_sha256": digest, "size_bytes": len(content), "media_type": DEPARTMENT_SNAPSHOT_MEDIA_TYPE if section == "department_snapshot_ref" else ("application/json" if blob else None), "availability": "available" if blob else None}
    carrier_digest = hashlib.sha256(__import__("aoi_orgware.company.contracts", fromlist=["canonical_company_json_bytes"]).canonical_company_json_bytes({"derivation_domain": "aoi.context.v2.v1-carrier-atom.v1", "atom": atom})).hexdigest()
    categories = {"department_snapshot_ref": "department_snapshot", "source_entries": "source", "config_entries": "policy", "dependency_entries": "baseline", "upstream_result_refs": "upstream_result"}
    return {"entry_id": entry_id, "category": categories[section], "context_layer": layer, "requirement": requirement, "state": state, "reason_code": {("mandatory", "selected"): "selected_mandatory", ("recommended", "selected"): "selected_recommended", ("recommended", "omitted"): "omitted_recommended", ("on_demand", "selected"): "selected_on_demand", ("on_demand", "omitted"): "omitted_on_demand"}[(requirement, state)], **atom, "carrier_digest": carrier_digest}


def _fixture() -> tuple[RootContextEnvelope, dict[str, Any], list[ContextArtifact]]:
    snap, source, optional, upstream = b"snap", b"source", b"optional", b"result"
    entries = [_entry("snapshot", "department_snapshot_ref", "department_snapshot_ref", snap, blob=True), _entry("source", "source_entries", "src/a.py", source, layer="L0"), _entry("optional", "config_entries", "cfg/a", optional, requirement="recommended"), _entry("upstream", "upstream_result_refs", "upstream_result_refs/0", upstream, requirement="on_demand", state="omitted", blob=True)]
    envelope = RootContextEnvelope("company-1", 1, 2, "repo-1", "a" * 64, ".")
    v1 = _v1_bytes(envelope, entries)
    declaration = {"document_type": "work_context_manifest_v2", "schema_version": 2, "manifest_id": "context-1", "context_layer": "L1", "entries": entries, "effective_entry_ids": ["optional", "snapshot", "source"], "v1_carrier": {"sha256": hashlib.sha256(v1).hexdigest(), "size_bytes": len(v1)}, "lineage": {"parent_manifest_sha256": None, "delegation_depth": 1}, "claims": {"selection": "declared_only", "freshness": "unavailable", "completeness": "unavailable", "actual_sent_bytes": "unavailable", "window_fit": "unavailable", "token_estimate": "unavailable", "ledger_authority": "unavailable", "sealed_amendment": "unavailable"}, "token_estimate": {"quality": "unknown", "tokens": None, "window_limit_tokens": None, "window_fit": "unknown"}}
    return envelope, declaration, [ContextArtifact("snapshot", snap), ContextArtifact("source", source), ContextArtifact("optional", optional)]


def _v1_bytes(envelope: RootContextEnvelope, entries: list[dict[str, Any]]) -> bytes:
    from aoi_orgware.company.context.compiler import _v1_from_root
    from aoi_orgware.company.context.v2_contract import validate_work_context_manifest_v2_structure
    raw = {"document_type": "work_context_manifest_v2", "schema_version": 2, "manifest_id": "context-1", "context_layer": "L1", "entries": entries, "effective_entry_ids": [x["entry_id"] for x in entries if x["state"] == "selected"], "v1_carrier": {"sha256": "0" * 64, "size_bytes": 0}, "lineage": {"parent_manifest_sha256": None, "delegation_depth": 1}, "claims": {"selection": "declared_only", "freshness": "unavailable", "completeness": "unavailable", "actual_sent_bytes": "unavailable", "window_fit": "unavailable", "token_estimate": "unavailable", "ledger_authority": "unavailable", "sealed_amendment": "unavailable"}, "token_estimate": {"quality": "unknown", "tokens": None, "window_limit_tokens": None, "window_fit": "unknown"}}
    # Structure accepts a provisional carrier; compiler construction uses atoms only.
    v2 = validate_work_context_manifest_v2_structure(raw)
    return _v1_from_root(envelope, v2)


def _qos(declaration: dict[str, Any], envelope: RootContextEnvelope, entries: list[ContextArtifact], budget: int = 10000) -> dict[str, Any]:
    v1 = _v1_bytes(envelope, declaration["entries"])
    digest = work_context_manifest_v2_sha256(declaration, v1)
    budgets = {name: {"budget": budget, "reserve": 0} for name in ("context", "input", "cache", "output", "reasoning", "tool")}
    value: dict[str, Any] = {"document_type": "work_qos_intent_v1", "schema_version": 1, "intent_scope": {"company_id": "company-1", "company_incarnation": 1, "lock_domain_generation": 2, "task_id": "task-1", "packet_id": "packet-1"}, "usage_scope": {"company_id": "company-1", "company_incarnation": 1, "lock_domain_generation": 2, "provider": "codex", "counter_scope_id": "thread-1"}, "intent_revision": 1, "intent_digest": "0" * 64, "context_binding": {"context_v2_semantic_sha256": digest, "v1_carrier_sha256": hashlib.sha256(v1).hexdigest(), "v1_carrier_size_bytes": len(v1)}, "configured_capacity": {"configured_capacity_id": "operator-reference-1", "configured_capacity_tokens": budget}, "budgets": budgets, "latency_class": "standard", "deadline_at": "2026-07-29T01:00:00Z", "freshness": {"state": "fresh", "clock": "2026-07-29T00:00:00Z", "expires_at": "2026-07-30T00:00:00Z"}, "verification_requirement": "required", "provider_class": "generic_api", "model_class": "generic_standard", "effort_class": "medium", "resources": []}
    value["intent_digest"] = work_qos_intent_v1_preimage_sha256(value)
    return value


def _token(payload: bytes) -> TokenizerObservation:
    return TokenizerObservation("test", "test", "exact", len(payload) // 100)


def test_root_success_snapshot_and_no_provider_claims() -> None:
    envelope, declaration, artifacts = _fixture(); qos = _qos(declaration, envelope, artifacts)
    result, witness = compile_root_work_context(envelope, declaration, qos, artifacts, [], _token)
    assert result.provider_sent is None and result.provider_state == "unavailable" and result.evidence_state == "caller_supplied_unverified"
    assert result.selected_content_size_bytes == len(b"snapsourceoptional")
    assert result.compiled_payload_size_bytes > result.selected_content_size_bytes
    assert result.provider_sent_size_bytes is None and result.service_instance_id is None
    assert type(result.compile_input_sha256) is str and len(result.compile_input_sha256) == 64
    assert witness.input_sha256 == result.compile_input_sha256
    assert [field for field in result._fields if field.endswith("size_bytes")] == [
        "selected_content_size_bytes", "compiled_payload_size_bytes", "provider_sent_size_bytes",
    ]
    assert result.emitted_entry_ids == ("optional", "snapshot", "source")
    verify_root_work_context(result, witness, envelope, declaration, qos, artifacts, [], _token)
    with pytest.raises(AttributeError): result.payload_sha256 = "x"  # type: ignore[misc]


def test_root_rejects_parented_declaration_before_tokenization() -> None:
    envelope, declaration, artifacts = _fixture()
    qos = _qos(declaration, envelope, artifacts)
    result, witness = compile_root_work_context(
        envelope, declaration, qos, artifacts, [], _token,
    )
    parented = copy.deepcopy(declaration)
    parented["lineage"] = {
        "parent_manifest_sha256": "a" * 64,
        "delegation_depth": 2,
    }
    parented_qos = _qos(parented, envelope, artifacts)
    observed: list[bytes] = []

    def tokenizer(payload: bytes) -> TokenizerObservation:
        observed.append(payload)
        return _token(payload)

    with pytest.raises(ContextCompilerError, match="V2 declaration is invalid"):
        compile_root_work_context(
            envelope, parented, parented_qos, artifacts, [], tokenizer,
        )
    with pytest.raises(ContextCompilerError, match="V2 declaration is invalid"):
        verify_root_work_context(
            result, witness, envelope, parented, parented_qos, artifacts, [],
            tokenizer,
        )
    assert observed == []


@pytest.mark.parametrize("mutate", [lambda a: a[:1], lambda a: a + [a[0]], lambda a: [ContextArtifact(a[0].entry_id, b"x")] + a[1:], lambda a: a + [ContextArtifact("upstream", b"result")]])
def test_artifact_boundaries(mutate: Any) -> None:
    envelope, declaration, artifacts = _fixture()
    with pytest.raises(ContextCompilerError): compile_root_work_context(envelope, declaration, _qos(declaration, envelope, artifacts), mutate(artifacts), [], _token)


def test_determinism_budget_l0_and_token_failures() -> None:
    envelope, declaration, artifacts = _fixture(); qos = _qos(declaration, envelope, artifacts)
    first = compile_root_work_context(envelope, declaration, qos, artifacts, [], _token)[0]
    second = compile_root_work_context(envelope, declaration, qos, list(reversed(artifacts)), [], _token)[0]
    assert first == second
    with pytest.raises(NeedsContext): compile_root_work_context(envelope, declaration, _qos(declaration, envelope, artifacts, 1), artifacts, [], _token)
    with pytest.raises(ContextCompilerError): compile_root_work_context(envelope, declaration, qos, artifacts, [], lambda _: TokenizerObservation("x", "y", "unknown", 1))
    with pytest.raises(SystemExit): compile_root_work_context(envelope, declaration, qos, artifacts, [], lambda _: (_ for _ in ()).throw(SystemExit()))


def test_on_demand_omission_seal_and_verify_mutation() -> None:
    envelope, declaration, artifacts = _fixture(); qos = _qos(declaration, envelope, artifacts)
    result, witness = compile_root_work_context(envelope, declaration, qos, artifacts, [], _token)
    assert {item.omission_code for item in result.entry_outcomes} >= {"declared_omission"}
    with pytest.raises(NeedsContext, match="sealed_amendment_unavailable"): selected_upstream_result()
    selected = copy.deepcopy(declaration); selected["entries"][3]["state"] = "selected"; selected["entries"][3]["reason_code"] = "selected_on_demand"; selected["effective_entry_ids"].append("upstream")
    with pytest.raises(NeedsContext, match="sealed_amendment_unavailable"):
        compile_root_work_context(envelope, selected, _qos(selected, envelope, artifacts), artifacts, ["upstream"], _token)
    changed = copy.deepcopy(declaration); changed["manifest_id"] = "context-2"
    with pytest.raises(ContextCompilerError): verify_root_work_context(result, witness, envelope, changed, qos, artifacts, [], _token)


def test_child_requires_durable_parent_compile_proof() -> None:
    envelope, parent, artifacts = _fixture(); v1 = _v1_bytes(envelope, parent["entries"])
    child = copy.deepcopy(parent); child["lineage"] = {"parent_manifest_sha256": work_context_manifest_v2_sha256(parent, v1), "delegation_depth": 2}; child["entries"][2]["state"] = "omitted"; child["entries"][2]["reason_code"] = "omitted_recommended"; child["effective_entry_ids"] = ["snapshot", "source"]
    parent_qos = _qos(parent, envelope, artifacts)
    parent_result, parent_witness = compile_root_work_context(envelope, parent, parent_qos, artifacts, [], _token)
    child_qos = _qos(child, envelope, artifacts)
    calls = 0

    def spy(payload: bytes) -> TokenizerObservation:
        nonlocal calls
        calls += 1
        return _token(payload)

    with pytest.raises(
        NeedsContext, match="verified_parent_compile_proof_unavailable",
    ):
        compile_child_work_context(
            parent_result, parent_witness, parent, v1, child, child_qos,
            artifacts[:2], [], spy,
        )
    with pytest.raises(
        NeedsContext, match="verified_parent_compile_proof_unavailable",
    ):
        verify_child_work_context(
            parent_result, parent_witness, parent_result, parent_witness,
            parent, v1, child, child_qos, artifacts[:2], [], spy,
        )
    with pytest.raises(ContextCompilerError, match="compilation witness"):
        verify_child_work_context(
            parent_result, parent_witness._replace(mode="child"),
            parent_result, parent_witness, parent, v1, child, child_qos,
            artifacts[:2], [], spy,
        )
    assert calls == 0
    with pytest.raises(ContextCompilerError): compile_child_work_context(parent_result, parent_witness, parent, v1 + b" ", child, child_qos, artifacts[:2], [], _token)


def test_recomputed_parent_witness_cannot_mint_child_materialization() -> None:
    envelope, parent, artifacts = _fixture()
    parent_qos = _qos(parent, envelope, artifacts)
    parent_result, parent_witness = compile_root_work_context(
        envelope, parent, parent_qos, artifacts[:2], [], _token,
    )
    forged_outcomes = tuple(
        outcome._replace(final_state="selected", omission_code=None)
        if outcome.entry_id == "optional" else outcome
        for outcome in parent_result.entry_outcomes
    )
    forged_result = parent_result._replace(
        emitted_entry_ids=("optional", "snapshot", "source"),
        entry_outcomes=forged_outcomes,
        compatibility="selected_set_equals_full_v1_carrier_inventory",
    )
    forged_witness = parent_witness._replace(
        result_sha256=hashlib.sha256(
            canonical_company_json_bytes(forged_result.to_dict())
        ).hexdigest(),
    )
    v1 = _v1_bytes(envelope, parent["entries"])
    child = copy.deepcopy(parent)
    child["lineage"] = {
        "parent_manifest_sha256": work_context_manifest_v2_sha256(parent, v1),
        "delegation_depth": 2,
    }
    child_qos = _qos(child, envelope, artifacts)
    calls = 0

    def spy(payload: bytes) -> TokenizerObservation:
        nonlocal calls
        calls += 1
        return _token(payload)

    with pytest.raises(
        NeedsContext, match="verified_parent_compile_proof_unavailable",
    ):
        compile_child_work_context(
            forged_result, forged_witness, parent, v1, child, child_qos,
            artifacts, [], spy,
        )
    assert calls == 0


def test_child_requires_exact_parent_input_identity_before_callbacks() -> None:
    envelope, parent, artifacts = _fixture(); parent_qos = _qos(parent, envelope, artifacts)
    parent_result, parent_witness = compile_root_work_context(envelope, parent, parent_qos, artifacts, [], _token)
    v1 = _v1_bytes(envelope, parent["entries"])
    child = copy.deepcopy(parent)
    child["lineage"] = {"parent_manifest_sha256": work_context_manifest_v2_sha256(parent, v1), "delegation_depth": 2}
    child_qos = _qos(child, envelope, artifacts)
    calls = 0
    def spy(_: bytes) -> TokenizerObservation:
        nonlocal calls
        calls += 1
        return _token(_)
    for witness in (parent_witness._replace(input_sha256="a" * 64), parent_witness._replace(input_sha256=1)):
        with pytest.raises(ContextCompilerError, match="parent compilation witness"):
            compile_child_work_context(parent_result, witness, parent, v1, child, child_qos, artifacts, [], spy)
    with pytest.raises(ContextCompilerError, match="parent compilation witness"):
        compile_child_work_context(parent_result._replace(compile_input_sha256="A" * 64), parent_witness, parent, v1, child, child_qos, artifacts, [], spy)
    assert calls == 0


@pytest.mark.parametrize(("field", "value"), [
    ("provider_sent_size_bytes", 1),
    ("provider_sent", True),
    ("provider_state", "available"),
    ("evidence_state", "AOI_verified"),
    ("service_instance_id", "service-1"),
])
def test_parent_result_unavailable_fields_are_witnessed(
    field: str, value: object,
) -> None:
    envelope, parent, artifacts = _fixture()
    parent_qos = _qos(parent, envelope, artifacts)
    parent_result, parent_witness = compile_root_work_context(
        envelope, parent, parent_qos, artifacts, [], _token,
    )
    v1 = _v1_bytes(envelope, parent["entries"])
    child = copy.deepcopy(parent)
    child["lineage"] = {
        "parent_manifest_sha256": work_context_manifest_v2_sha256(parent, v1),
        "delegation_depth": 2,
    }
    child_qos = _qos(child, envelope, artifacts)
    forged = parent_result._replace(**{field: value})
    wire = parent_result.to_dict()
    wire[field] = value
    forged_witness = parent_witness._replace(
        result_sha256=hashlib.sha256(
            canonical_company_json_bytes(wire)
        ).hexdigest(),
    )
    with pytest.raises(ContextCompilerError):
        forged.to_dict()
    for witness in (parent_witness, forged_witness):
        with pytest.raises(ContextCompilerError):
            compile_child_work_context(
                forged, witness, parent, v1, child, child_qos, artifacts, [],
                _token,
            )


@pytest.mark.parametrize("changes", [
    {"token_observations": (object(),)},
    {"entry_outcomes": (object(),)},
])
def test_hostile_parent_result_nesting_fails_with_typed_error(
    changes: dict[str, object],
) -> None:
    envelope, parent, artifacts = _fixture()
    parent_qos = _qos(parent, envelope, artifacts)
    parent_result, parent_witness = compile_root_work_context(
        envelope, parent, parent_qos, artifacts, [], _token,
    )
    v1 = _v1_bytes(envelope, parent["entries"])
    child = copy.deepcopy(parent)
    child["lineage"] = {
        "parent_manifest_sha256": work_context_manifest_v2_sha256(parent, v1),
        "delegation_depth": 2,
    }
    child_qos = _qos(child, envelope, artifacts)
    forged = parent_result._replace(**changes)
    with pytest.raises(ContextCompilerError):
        forged.to_dict()
    with pytest.raises(ContextCompilerError):
        compile_child_work_context(
            forged, parent_witness, parent, v1, child, child_qos, artifacts,
            [], _token,
        )
    with pytest.raises(ContextCompilerError):
        verify_root_work_context(
            forged, parent_witness, envelope, parent, parent_qos, artifacts,
            [], _token,
        )


def test_child_candidate_subset_rejects_before_payload_or_tokenizer() -> None:
    envelope, parent, artifacts = _fixture(); parent_qos = _qos(parent, envelope, artifacts)
    parent_result, parent_witness = compile_root_work_context(envelope, parent, parent_qos, artifacts[:2], [], _token)
    v1 = _v1_bytes(envelope, parent["entries"])
    child = copy.deepcopy(parent)
    child["lineage"] = {"parent_manifest_sha256": work_context_manifest_v2_sha256(parent, v1), "delegation_depth": 2}
    child_qos = _qos(child, envelope, artifacts)
    calls = 0
    def spy(_: bytes) -> TokenizerObservation:
        nonlocal calls
        calls += 1
        return _token(_)
    with pytest.raises(ContextCompilerError, match="child candidate entries are not a parent subset"):
        compile_child_work_context(parent_result, parent_witness, parent, v1, child, child_qos, artifacts, [], spy)
    assert calls == 0


@pytest.mark.parametrize(("field", "value"), [
    ("company_id", "company-2"), ("company_incarnation", 2), ("lock_domain_generation", 3),
])
def test_qos_company_binding_drift_is_closed(field: str, value: str | int) -> None:
    envelope, declaration, artifacts = _fixture(); changed = _qos(declaration, envelope, artifacts)
    for scope in ("intent_scope", "usage_scope"):
        changed[scope][field] = value
    changed["intent_digest"] = work_qos_intent_v1_preimage_sha256(changed)
    with pytest.raises(ContextCompilerError, match="intent scope"):
        compile_root_work_context(envelope, declaration, changed, artifacts, [], _token)


@pytest.mark.parametrize(("entry_index", "requirement", "expected"), [
    (1, "mandatory", "mandatory_context_payload_overflow"),
    (2, "recommended", None),
])
def test_canonical_base64_payload_overflow_is_closed(entry_index: int, requirement: str,
                                                      expected: str | None) -> None:
    envelope, declaration, artifacts = _fixture(); huge = b"x" * (MAX_CONTRACT_BYTES * 3 // 4)
    original = declaration["entries"][entry_index]
    declaration["entries"][entry_index] = _entry(
        original["entry_id"], original["carrier_section"], original["carrier_path"], huge,
        requirement=requirement, state="selected", layer=original["context_layer"],
        blob=original["entry_type"] == "blob_ref",
    )
    replacement = ContextArtifact(original["entry_id"], huge)
    changed_artifacts = [replacement if item.entry_id == replacement.entry_id else item for item in artifacts]
    v1 = _v1_bytes(envelope, declaration["entries"])
    declaration["v1_carrier"] = {"sha256": hashlib.sha256(v1).hexdigest(), "size_bytes": len(v1)}
    if expected is not None:
        with pytest.raises(NeedsContext, match=expected):
            compile_root_work_context(envelope, declaration, _qos(declaration, envelope, changed_artifacts), changed_artifacts, [], _token)
        return
    result, _ = compile_root_work_context(envelope, declaration, _qos(declaration, envelope, changed_artifacts), changed_artifacts, [], _token)
    assert next(item for item in result.entry_outcomes if item.entry_id == replacement.entry_id).omission_code == "payload_too_large"


def test_v1_casefold_ordering_is_canonical() -> None:
    envelope, declaration, _ = _fixture()
    entries = [declaration["entries"][0], _entry("upper", "source_entries", "Z.py", b"z"),
               _entry("lower", "source_entries", "a.py", b"a")]
    carrier = json.loads(_v1_bytes(envelope, entries).decode("utf-8"))
    assert [item["path"] for item in carrier["source_entries"]] == ["a.py", "Z.py"]


def test_qos_company_binding_l0_and_tokenizer_boundaries() -> None:
    envelope, declaration, artifacts = _fixture(); qos = _qos(declaration, envelope, artifacts, 10_000)
    changed = copy.deepcopy(qos); changed["intent_scope"]["company_id"] = "other"; changed["usage_scope"]["company_id"] = "other"; changed["intent_digest"] = work_qos_intent_v1_preimage_sha256(changed)
    with pytest.raises(ContextCompilerError, match="intent scope"):
        compile_root_work_context(envelope, declaration, changed, artifacts, [], _token)
    # The L0 tokenization is the L0-only canonical payload, not the full payload.
    def l0_only(payload: bytes) -> TokenizerObservation:
        return TokenizerObservation("test", "test", "exact", 15 if b'"optional"' not in payload else 10)
    assert compile_root_work_context(envelope, declaration, _qos(declaration, envelope, artifacts, 100), artifacts, [], l0_only)[0]
    def too_many(payload: bytes) -> TokenizerObservation:
        return TokenizerObservation("test", "test", "exact", 16 if b'"optional"' not in payload else 10)
    with pytest.raises(NeedsContext, match="l0_exact_gate_unmet"):
        compile_root_work_context(envelope, declaration, _qos(declaration, envelope, artifacts, 100), artifacts, [], too_many)
    for bad in (TokenizerObservation("x", "y", [], 1), TokenizerObservation("x", "y", "exact", True), TokenizerObservation("x", "y", "exact", 1_000_000_001)):
        with pytest.raises(ContextCompilerError):
            compile_root_work_context(envelope, declaration, qos, artifacts, [], lambda _, item=bad: item)


def test_tokenizer_memo_metadata_and_interrupt_boundaries() -> None:
    envelope, declaration, artifacts = _fixture(); qos = _qos(declaration, envelope, artifacts)
    seen: list[bytes] = []
    def token(payload: bytes) -> TokenizerObservation:
        seen.append(payload); return TokenizerObservation("x", "m", "exact", 1)
    result, _ = compile_root_work_context(envelope, declaration, qos, artifacts, [], token)
    assert len(seen) == len(set(seen)) == len(result.token_observations)
    calls = 0
    def drift(_: bytes) -> TokenizerObservation:
        nonlocal calls
        calls += 1; return TokenizerObservation("x", "m", "exact" if calls == 1 else "provider_estimate", 1)
    with pytest.raises(ContextCompilerError, match="metadata drift"):
        compile_root_work_context(envelope, declaration, qos, artifacts, [], drift)
    for signal in (MemoryError, SystemExit, KeyboardInterrupt):
        with pytest.raises(signal):
            compile_root_work_context(envelope, declaration, qos, artifacts, [], lambda _, kind=signal: (_ for _ in ()).throw(kind()))
    with pytest.raises(ContextCompilerError):
        compile_root_work_context(envelope, declaration, qos, artifacts, [], lambda _: (_ for _ in ()).throw(TypeError()))


def test_selected_optional_missing_is_closed_and_child_uses_parent_actual_set() -> None:
    envelope, parent, artifacts = _fixture(); qos = _qos(parent, envelope, artifacts)
    result, witness = compile_root_work_context(envelope, parent, qos, artifacts[:2], [], _token)
    assert next(item for item in result.entry_outcomes if item.entry_id == "optional").omission_code == "selected_artifact_missing"
    with pytest.raises(NeedsContext, match="mandatory_selected_artifact_missing"):
        compile_root_work_context(envelope, parent, qos, artifacts[1:], [], _token)
    v1 = _v1_bytes(envelope, parent["entries"])
    child = copy.deepcopy(parent)
    child["lineage"] = {"parent_manifest_sha256": work_context_manifest_v2_sha256(parent, v1), "delegation_depth": 2}
    child_qos = _qos(child, envelope, artifacts)
    # A child declaration may retain the parent's selected optional entry, but
    # it cannot re-emit one the actual parent outcome omitted.
    with pytest.raises(ContextCompilerError, match="parent subset"):
        compile_child_work_context(result, witness, parent, v1, child, child_qos, artifacts, [], _token)
