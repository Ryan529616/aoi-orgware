from __future__ import annotations

import copy
import hashlib
from typing import Any

import pytest

from aoi_orgware.company.context import (
    LegacyContextV1Error,
    LegacyContextV1Key,
    observe_legacy_context_v1,
)
from aoi_orgware.company.contracts import (
    BLOB_REF_V1,
    DEPARTMENT_SNAPSHOT_MEDIA_TYPE,
    MAX_CONTRACT_BYTES,
    WORK_CONTEXT_MANIFEST_MEDIA_TYPE,
    WORK_PACKET_PROMPT_MEDIA_TYPE,
    WORK_PACKET_V1,
    canonical_company_json_bytes,
    canonical_work_context_manifest_bytes,
    company_contract_sha256,
    validate_work_packet,
)
from aoi_orgware.company.invariants import InvariantObject, InvariantProjection


H = "a" * 64
T = "2026-07-29T00:00:00Z"
KEY = LegacyContextV1Key("company-1", 1, 1, "packet-1")


def _blob(media_type: str, digest: str = H, size: int = 1) -> dict[str, object]:
    return {"contract_type": BLOB_REF_V1, "schema_version": 1, "sha256": digest,
            "size_bytes": size, "media_type": media_type, "availability": "available"}


def _binding() -> dict[str, object]:
    return {"company_id": KEY.company_id, "company_incarnation": KEY.company_incarnation,
            "lock_domain_generation": KEY.lock_domain_generation}


def _scope() -> dict[str, object]:
    return {"read_refs": [{"kind": "tree", "path": "src"}], "write_refs": [],
            "run_refs": [{"kind": "tree", "path": "src"}],
            "export_refs": [], "provider_allowlist": ["codex"]}


def _manifest(*, empty: bool = False, upstream: int = 1) -> dict[str, object]:
    entries = [] if empty else [{"path": "src/a.py", "entry_type": "file", "sha256": "b" * 64, "size_bytes": 3}]
    value: dict[str, object] = {
        "document_type": "work_context_manifest_v1", "schema_version": 1, **_binding(),
        "repository_id": "repo-1", "repository_sha256": H, "cwd": ".",
        "department_snapshot_ref": _blob(DEPARTMENT_SNAPSHOT_MEDIA_TYPE, "c" * 64),
        "source_entries": entries,
        "config_entries": [], "dependency_entries": [],
        "upstream_result_refs": [_blob("application/json", f"{index + 1:064x}") for index in range(upstream)],
    }
    for name, digest in (("source_entries", "source_manifest_sha256"), ("config_entries", "config_manifest_sha256"), ("dependency_entries", "dependency_manifest_sha256")):
        value[digest] = hashlib.sha256(canonical_company_json_bytes(value[name])).hexdigest()
    return value


def _packet(manifest: dict[str, object]) -> dict[str, object]:
    raw = canonical_work_context_manifest_bytes(manifest)
    value: dict[str, object] = {
        "contract_type": WORK_PACKET_V1, "schema_version": 1, **_binding(), "packet_id": KEY.packet_id,
        "parent_packet_id": None, "parent_packet_sha256": None, "task_id": "task-1",
        "task_revision_id": "task-revision-1", "task_sha256": H, "manager_node_id": None,
        "parent_execution_id": None, "target_node_id": "worker-1", "department_id": "rtl",
        "null_relationship_justifications": {"manager_node_id": "root", "parent_execution_id": "pre-admission",
            "target_node_id": None, "department_id": None}, "delegation_depth": 1,
        "display_name": "context test", "objective": "observe only", "prompt_ref": _blob(WORK_PACKET_PROMPT_MEDIA_TYPE),
        "context_manifest_ref": _blob(WORK_CONTEXT_MANIFEST_MEDIA_TYPE, hashlib.sha256(raw).hexdigest(), len(raw)),
        "source_manifest_sha256": manifest["source_manifest_sha256"],
        "config_manifest_sha256": manifest["config_manifest_sha256"],
        "dependency_manifest_sha256": manifest["dependency_manifest_sha256"],
        "authority_scope": _scope(), "redaction_policy": {"dashboard": "metadata_only", "secrets": "excluded", "chain_of_thought": "forbidden"},
        "created_at": T, "expires_at": "2026-07-30T00:00:00Z",
    }
    value["packet_sha256"] = company_contract_sha256(value)
    return value


def _object(packet: dict[str, object], sequence: int = 7) -> InvariantObject:
    valid = validate_work_packet(packet)
    return InvariantObject(WORK_PACKET_V1, valid["packet_id"], "event-packet", sequence,
                           company_contract_sha256(valid), valid)


def _projection(*items: InvariantObject) -> InvariantProjection:
    return InvariantProjection(tuple(items), (), (), 16, (), True, (), ())


def _bundle(*, empty: bool = False, upstream: int = 1) -> tuple[InvariantProjection, bytes, InvariantObject]:
    manifest = _manifest(empty=empty, upstream=upstream)
    raw = canonical_work_context_manifest_bytes(manifest)
    item = _object(_packet(manifest))
    return _projection(item), raw, item


def test_canonical_manifest_is_degraded_inventory_only() -> None:
    projection, raw, _ = _bundle()
    result = observe_legacy_context_v1(projection, KEY, raw)
    assert result.observation_state == "degraded"
    assert result.inventory.source_entry_count == 1 and result.inventory.upstream_result_count == 1
    assert {item.fact for item in result.unavailable_facts} == {
        "selection_class_and_reason", "freshness_and_expiry", "omissions", "completeness",
        "token_estimate_tokenizer_model", "actual_sent_bytes", "window_fit", "ledger_authority",
    }
    assert all(item.availability == "unavailable" for item in result.unavailable_facts)
    assert (result.projection_provenance, result.projection_completeness, result.cas_residency,
            result.work_definition_admission) == ("unverified", "unverified", "unverified", "not_evaluated")
    assert {"paths", "raw", "selected", "completed", "authority", "sent_bytes"}.isdisjoint(result._fields)


def test_empty_and_add_only_upstream_shaped_manifest_remain_unavailable() -> None:
    empty_projection, empty_raw, _ = _bundle(empty=True, upstream=0)
    child_projection, child_raw, _ = _bundle(upstream=2)
    empty = observe_legacy_context_v1(empty_projection, KEY, empty_raw)
    declared = observe_legacy_context_v1(child_projection, KEY, child_raw)
    assert empty.inventory.source_entry_count == empty.inventory.upstream_result_count == 0
    assert declared.inventory.upstream_result_count == 2
    assert empty.unavailable_facts == declared.unavailable_facts
    assert {"parent", "child", "slice", "materialized", "full_context"}.isdisjoint(declared._fields)


@pytest.mark.parametrize("raw", [b"", b"{\n}", b'{"document_type":"work_context_manifest_v1","document_type":"x"}', b"\xff"])
def test_invalid_manifest_bytes_fail_closed(raw: bytes) -> None:
    projection, _, _ = _bundle()
    with pytest.raises(LegacyContextV1Error):
        observe_legacy_context_v1(projection, KEY, raw)


def test_manifest_wrong_type_and_oversize_fail_before_observation() -> None:
    projection, _, _ = _bundle()
    for raw in (bytearray(b"{}"), b"x" * (MAX_CONTRACT_BYTES + 1)):
        with pytest.raises(LegacyContextV1Error):
            observe_legacy_context_v1(projection, KEY, raw)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "raw",
    [b"[" * 5_000 + b"]" * 5_000, b"[" * 20_000 + b"]" * 20_000],
    ids=("validator_depth", "decoder_stack_depth"),
)
def test_deep_json_fails_as_typed_context_error(raw: bytes) -> None:
    projection, _, _ = _bundle()
    with pytest.raises(LegacyContextV1Error):
        observe_legacy_context_v1(projection, KEY, raw)


def test_manifest_binding_and_packet_identity_fail_closed() -> None:
    projection, raw, item = _bundle()
    bad = dict(item.payload)
    bad["context_manifest_ref"] = dict(bad["context_manifest_ref"], size_bytes=len(raw) + 1)
    bad["packet_sha256"] = company_contract_sha256({key: value for key, value in bad.items() if key != "packet_sha256"})
    with pytest.raises(LegacyContextV1Error):
        observe_legacy_context_v1(_projection(_object(bad)), KEY, raw)
    duplicate = InvariantObject(item.contract_type, item.object_key, "event-duplicate", 8, item.payload_sha256, item.payload)
    with pytest.raises(LegacyContextV1Error):
        observe_legacy_context_v1(_projection(item, duplicate), KEY, raw)
    wrong_digest = dict(item.payload)
    wrong_digest["source_manifest_sha256"] = "f" * 64
    wrong_digest["packet_sha256"] = company_contract_sha256(
        {key: value for key, value in wrong_digest.items() if key != "packet_sha256"},
    )
    with pytest.raises(LegacyContextV1Error):
        observe_legacy_context_v1(_projection(_object(wrong_digest)), KEY, raw)


def test_permutation_unrelated_and_input_mutation_cannot_change_result() -> None:
    projection, raw, item = _bundle()
    unrelated = InvariantObject("other_v1", "other", "event-other", 1, H, {"anything": "ignored"})
    one = observe_legacy_context_v1(_projection(item, unrelated), KEY, raw)
    two = observe_legacy_context_v1(_projection(unrelated, item), KEY, raw)
    assert one == two and one.observation_digest == two.observation_digest
    source = _packet(_manifest())
    mutable = _object(source)
    result = observe_legacy_context_v1(_projection(mutable), KEY, raw)
    source["packet_id"] = "mutated"
    assert result.inventory.manifest_sha256 == hashlib.sha256(raw).hexdigest()


def test_immutable_result_and_bad_metadata_fail_closed() -> None:
    projection, raw, item = _bundle()
    result = observe_legacy_context_v1(projection, KEY, raw)
    with pytest.raises(AttributeError):
        result.inventory.manifest_sha256 = H  # type: ignore[misc]
    bad = InvariantObject(item.contract_type, item.object_key, item.event_id, True, item.payload_sha256, item.payload)
    with pytest.raises(LegacyContextV1Error):
        observe_legacy_context_v1(_projection(bad), KEY, raw)


def test_v2_fields_and_manifest_company_mismatch_are_rejected() -> None:
    manifest = _manifest()
    manifest["selection_reason"] = "pretend-v2"
    with pytest.raises(LegacyContextV1Error):
        observe_legacy_context_v1(_projection(_object(_packet(_manifest()))), KEY,
                                  canonical_company_json_bytes(manifest))
    other = _manifest()
    other["company_id"] = "company-2"
    raw = canonical_company_json_bytes(other)
    with pytest.raises(LegacyContextV1Error):
        observe_legacy_context_v1(_projection(_object(_packet(_manifest()))), KEY, raw)
