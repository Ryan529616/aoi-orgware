from __future__ import annotations

import copy
import hashlib
from typing import Any, Callable, cast

import pytest

from aoi_orgware.company.context.v2_contract import (
    CarrierAtomV2,
    WorkContextManifestV2,
    WorkContextManifestV2Error,
    canonical_work_context_manifest_v2_bytes,
    canonical_work_context_manifest_v2_structural_bytes,
    parse_work_context_manifest_v2_structural_bytes,
    validate_child_work_context_manifest_v2,
    validate_child_work_context_manifest_v2_declaration,
    validate_root_work_context_manifest_v2,
    validate_work_context_manifest_v2,
    validate_work_context_manifest_v2_structure,
    work_context_manifest_v2_revision_identity,
    work_context_manifest_v2_sha256,
)
from aoi_orgware.company.contracts import (
    BLOB_REF_V1,
    DEPARTMENT_SNAPSHOT_MEDIA_TYPE,
    canonical_company_json_bytes,
    canonical_work_context_manifest_bytes,
)


H = "a" * 64


class _HostileHash:
    def __hash__(self) -> int:
        raise RuntimeError("hostile hash")


class _HostileEquality:
    def __eq__(self, other: object) -> bool:
        raise RuntimeError("hostile equality")

    def __ne__(self, other: object) -> bool:
        raise RuntimeError("hostile inequality")


def _blob(media: str, digest: str = H, size: int = 3) -> dict[str, object]:
    return {"contract_type": BLOB_REF_V1, "schema_version": 1, "sha256": digest,
            "size_bytes": size, "media_type": media, "availability": "available"}


def _v1(*, tilde: bool = False) -> dict[str, object]:
    path = "~/literal.py" if tilde else "src/a.py"
    sections: dict[str, object] = {
        "source_entries": [{"path": path, "entry_type": "file", "sha256": "b" * 64, "size_bytes": 1}],
        "config_entries": [{"path": "cfg/a.toml", "entry_type": "file", "sha256": "c" * 64, "size_bytes": 2}],
        "dependency_entries": [],
    }
    result: dict[str, object] = {
        "document_type": "work_context_manifest_v1", "schema_version": 1,
        "company_id": "company-1", "company_incarnation": 1, "lock_domain_generation": 1,
        "repository_id": "repo-1", "repository_sha256": H, "cwd": ".",
        "department_snapshot_ref": _blob(DEPARTMENT_SNAPSHOT_MEDIA_TYPE), **sections,
        "upstream_result_refs": [_blob("application/json", "d" * 64, 4)],
    }
    for section, digest in (("source_entries", "source_manifest_sha256"), ("config_entries", "config_manifest_sha256"), ("dependency_entries", "dependency_manifest_sha256")):
        result[digest] = hashlib.sha256(canonical_company_json_bytes(result[section])).hexdigest()
    return result


def _raw_v1(**kwargs: Any) -> bytes:
    return canonical_work_context_manifest_bytes(_v1(**kwargs))


def _atom(section: str, path: str, entry_type: str, digest: str, size: int, media: str | None = None, availability: str | None = None) -> dict[str, Any]:
    contract_type = BLOB_REF_V1 if section in {"department_snapshot_ref", "upstream_result_refs"} else None
    schema_version = 1 if section in {"department_snapshot_ref", "upstream_result_refs"} else None
    atom = CarrierAtomV2(
        section, path, entry_type, contract_type, schema_version, digest, size, media,
        availability,
    )
    bound = {"derivation_domain": "aoi.context.v2.v1-carrier-atom.v1", "atom": atom.to_dict()}
    return {**atom.to_dict(), "carrier_digest": hashlib.sha256(canonical_company_json_bytes(bound)).hexdigest()}


def _entry(entry_id: str, section: str, path: str, entry_type: str, digest: str, size: int, *, requirement: str = "mandatory", state: str = "selected", media: str | None = None, availability: str | None = None) -> dict[str, Any]:
    category = {"source_entries": "source", "config_entries": "policy", "dependency_entries": "baseline", "department_snapshot_ref": "department_snapshot", "upstream_result_refs": "upstream_result"}[section]
    reasons = {("mandatory", "selected"): "selected_mandatory", ("recommended", "selected"): "selected_recommended", ("recommended", "omitted"): "omitted_recommended", ("on_demand", "selected"): "selected_on_demand", ("on_demand", "omitted"): "omitted_on_demand", ("forbidden", "forbidden"): "forbidden_by_policy"}
    return {"entry_id": entry_id, "category": category, "context_layer": "L1", "requirement": requirement, "state": state, "reason_code": reasons[(requirement, state)], **_atom(section, path, entry_type, digest, size, media, availability)}


def _forbidden(entry_id: str = "never") -> dict[str, Any]:
    return {"entry_id": entry_id, "category": "compiler", "context_layer": "L1", "requirement": "forbidden", "state": "forbidden", "reason_code": "forbidden_by_policy", "carrier_section": None, "carrier_path": None, "entry_type": None, "contract_type": None, "schema_version": None, "content_sha256": None, "size_bytes": None, "media_type": None, "availability": None, "carrier_digest": None}


def _v2(raw: bytes, *, entries: list[dict[str, Any]] | None = None, parent: str | None = None, depth: int = 1, manifest_id: str = "context-1") -> dict[str, Any]:
    entries = entries or [_entry("snapshot", "department_snapshot_ref", "department_snapshot_ref", "blob_ref", H, 3, media=DEPARTMENT_SNAPSHOT_MEDIA_TYPE, availability="available"), _entry("source", "source_entries", "src/a.py", "file", "b" * 64, 1), _entry("config", "config_entries", "cfg/a.toml", "file", "c" * 64, 2, requirement="recommended", state="omitted"), _entry("upstream", "upstream_result_refs", "upstream_result_refs/0", "blob_ref", "d" * 64, 4, requirement="on_demand", state="omitted", media="application/json", availability="available"), _forbidden()]
    return {"document_type": "work_context_manifest_v2", "schema_version": 2, "manifest_id": manifest_id, "context_layer": "L1", "entries": entries, "effective_entry_ids": sorted(entry["entry_id"] for entry in entries if entry["state"] == "selected"), "v1_carrier": {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}, "lineage": {"parent_manifest_sha256": parent, "delegation_depth": depth}, "claims": {"selection": "declared_only", "freshness": "unavailable", "completeness": "unavailable", "actual_sent_bytes": "unavailable", "window_fit": "unavailable", "token_estimate": "unavailable", "ledger_authority": "unavailable", "sealed_amendment": "unavailable"}, "token_estimate": {"quality": "unknown", "tokens": None, "window_limit_tokens": None, "window_fit": "unknown"}}


def _rebind(value: dict[str, Any]) -> dict[str, Any]:
    value["effective_entry_ids"] = sorted(entry["entry_id"] for entry in value["entries"] if entry["state"] == "selected")
    return value


def _rebind_carrier(entry: dict[str, Any]) -> None:
    atom = CarrierAtomV2(
        entry["carrier_section"], entry["carrier_path"], entry["entry_type"],
        entry["contract_type"], entry["schema_version"], entry["content_sha256"],
        entry["size_bytes"], entry["media_type"], entry["availability"],
    )
    entry["carrier_digest"] = hashlib.sha256(canonical_company_json_bytes({
        "derivation_domain": "aoi.context.v2.v1-carrier-atom.v1", "atom": atom.to_dict(),
    })).hexdigest()


def test_byte_aware_bijection_and_explicit_unavailable_boundary() -> None:
    raw = _raw_v1()
    result = validate_work_context_manifest_v2(_v2(raw), raw)
    assert result.effective_entry_ids == ("snapshot", "source")
    assert result.token_estimate.tokens is None
    assert dict(result.claims)["actual_sent_bytes"] == "unavailable"
    assert {"effective_prompt", "provider_transport", "ledger_seal", "authority"}.isdisjoint(result.to_dict())


def test_bijection_rejects_hidden_unrelated_and_type_or_media_mutation() -> None:
    raw = _raw_v1()
    mutations: list[Callable[[dict[str, Any]], None]] = [
        lambda value: value["entries"].pop(0),
        lambda value: value["entries"][0].update(content_sha256="f" * 64),
        lambda value: value["entries"][0].update(entry_type="directory"),
        lambda value: value["entries"][3].update(media_type="text/plain"),
        lambda value: value["entries"][3].update(contract_type="blob_ref_v0"),
        lambda value: value["entries"][3].update(schema_version=2),
        lambda value: value["entries"][3].update(availability="unknown"),
        lambda value: value["entries"][1].update(contract_type=BLOB_REF_V1),
    ]
    for mutate in mutations:
        bad = copy.deepcopy(_v2(raw)); mutate(bad); _rebind(bad)
        with pytest.raises(WorkContextManifestV2Error):
            validate_work_context_manifest_v2(bad, raw)
    bad = _v2(raw)
    bad["entries"].append(_entry("unrelated", "source_entries", "x.py", "file", "f" * 64, 1))
    _rebind(bad)
    with pytest.raises(WorkContextManifestV2Error):
        validate_work_context_manifest_v2(bad, raw)


def test_snapshot_carrier_is_one_exact_mandatory_l1_blob_binding() -> None:
    raw = _raw_v1()
    snapshot_fields = (
        ("category", "source"), ("carrier_path", "other"), ("entry_type", "file"),
        ("contract_type", "blob_ref_v0"), ("schema_version", 2),
        ("media_type", "application/json"), ("availability", "unknown"),
        ("content_sha256", "e" * 64), ("size_bytes", 4),
    )
    for field, replacement in snapshot_fields:
        bad = _v2(raw)
        bad["entries"][0][field] = replacement
        _rebind_carrier(bad["entries"][0])
        with pytest.raises(WorkContextManifestV2Error):
            validate_work_context_manifest_v2(bad, raw)
    for field, replacement in (
        ("context_layer", "L0"), ("requirement", "recommended"),
        ("state", "omitted"), ("reason_code", "omitted_recommended"),
    ):
        bad = _v2(raw)
        bad["entries"][0][field] = replacement
        _rebind(bad)
        with pytest.raises(WorkContextManifestV2Error):
            validate_work_context_manifest_v2_structure(bad)
    missing = _v2(raw); missing["entries"].pop(0); _rebind(missing)
    duplicate = _v2(raw); duplicate["entries"].append(copy.deepcopy(duplicate["entries"][0])); duplicate["entries"][-1]["entry_id"] = "snapshot-duplicate"; _rebind(duplicate)
    forbidden = _v2(raw); forbidden["entries"][0] = _forbidden("snapshot-forbidden"); forbidden["entries"][0]["category"] = "department_snapshot"; _rebind(forbidden)
    for bad in (missing, duplicate, forbidden):
        with pytest.raises(WorkContextManifestV2Error):
            validate_work_context_manifest_v2(bad, raw)


def test_snapshot_v1_mutation_rejects_stale_v2_and_child_carrier_changes() -> None:
    raw = _raw_v1()
    parent = _v2(raw)
    changed = _v1()
    changed["department_snapshot_ref"] = _blob(DEPARTMENT_SNAPSHOT_MEDIA_TYPE, "e" * 64, 5)
    changed_raw = canonical_work_context_manifest_bytes(changed)
    with pytest.raises(WorkContextManifestV2Error):
        validate_work_context_manifest_v2(parent, changed_raw)
    child = _v2(raw, parent=work_context_manifest_v2_sha256(parent, raw), depth=2, manifest_id="context-2")
    missing = copy.deepcopy(child)
    missing["entries"].pop(0)
    _rebind(missing)
    with pytest.raises(WorkContextManifestV2Error):
        validate_child_work_context_manifest_v2(missing, parent, raw, raw)
    mutated = copy.deepcopy(child)
    mutated["entries"][0]["content_sha256"] = "e" * 64
    _rebind_carrier(mutated["entries"][0])
    _rebind(mutated)
    with pytest.raises(WorkContextManifestV2Error):
        validate_child_work_context_manifest_v2(mutated, parent, raw, raw)


def test_semantic_api_requires_v1_bytes_and_structural_api_is_explicit() -> None:
    raw = _raw_v1()
    unrelated = _v2(raw, entries=[
        _entry("source", "source_entries", "x.py", "file", "f" * 64, 1),
        _entry("config", "config_entries", "cfg/a.toml", "file", "c" * 64, 2,
               requirement="recommended", state="omitted"),
        _entry("upstream", "upstream_result_refs", "upstream_result_refs/0", "blob_ref",
               "d" * 64, 4, requirement="on_demand", state="omitted",
               media="application/json", availability="available"),
    ])
    structural = validate_work_context_manifest_v2_structure(unrelated)
    assert structural.manifest_id == "context-1"
    assert parse_work_context_manifest_v2_structural_bytes(
        canonical_work_context_manifest_v2_structural_bytes(unrelated)
    ) == structural
    with pytest.raises(WorkContextManifestV2Error):
        validate_work_context_manifest_v2(unrelated, raw)
    with pytest.raises(WorkContextManifestV2Error):
        canonical_work_context_manifest_v2_bytes(unrelated, raw)
    with pytest.raises(WorkContextManifestV2Error):
        work_context_manifest_v2_sha256(unrelated, raw)
    with pytest.raises(TypeError):
        validate_work_context_manifest_v2(unrelated)  # type: ignore[call-arg]


def test_lineage_uses_subordinate_root_one_and_maximum_three() -> None:
    raw = _raw_v1()
    assert validate_work_context_manifest_v2(_v2(raw), raw).lineage.delegation_depth == 1
    for depth in range(2, 4):
        assert validate_work_context_manifest_v2(_v2(raw, parent=H, depth=depth), raw).lineage.delegation_depth == depth
    for value in (_v2(raw, depth=0), _v2(raw, parent=H, depth=1), _v2(raw, parent=H, depth=4)):
        with pytest.raises(WorkContextManifestV2Error):
            validate_work_context_manifest_v2(value, raw)
    parent = _v2(raw, parent=H, depth=3)
    fourth = _v2(raw, parent=work_context_manifest_v2_sha256(parent, raw), depth=4, manifest_id="context-2")
    with pytest.raises(WorkContextManifestV2Error):
        validate_child_work_context_manifest_v2_declaration(fourth, parent, raw, raw)


def test_forbidden_cannot_smuggle_or_select_and_optional_stays_carrier_bound() -> None:
    raw = _raw_v1()
    bad = _v2(raw); bad["entries"][-1]["carrier_section"] = "source_entries"
    with pytest.raises(WorkContextManifestV2Error):
        validate_work_context_manifest_v2(bad, raw)
    bad = _v2(raw); bad["entries"][-1]["state"] = "selected"
    with pytest.raises(WorkContextManifestV2Error):
        validate_work_context_manifest_v2(bad, raw)
    result = validate_work_context_manifest_v2(_v2(raw), raw)
    optional = next(entry for entry in result.entries if entry.entry_id == "config")
    assert optional.carrier is not None and optional.state == "omitted"


def test_literal_tilde_is_v1_literal_and_canonical_bytes_are_exact() -> None:
    raw = _raw_v1(tilde=True)
    value = _v2(raw, entries=[_entry("snapshot", "department_snapshot_ref", "department_snapshot_ref", "blob_ref", H, 3, media=DEPARTMENT_SNAPSHOT_MEDIA_TYPE, availability="available"), _entry("source", "source_entries", "~/literal.py", "file", "b" * 64, 1), _entry("config", "config_entries", "cfg/a.toml", "file", "c" * 64, 2, requirement="recommended", state="omitted"), _entry("upstream", "upstream_result_refs", "upstream_result_refs/0", "blob_ref", "d" * 64, 4, requirement="on_demand", state="omitted", media="application/json", availability="available")])
    assert next(entry for entry in validate_work_context_manifest_v2(value, raw).entries if entry.entry_id == "source").carrier is not None
    for actual in (b'{"x":1,"x":2}', raw.replace(b"~/literal.py", b"~\\/literal.py")):
        with pytest.raises(WorkContextManifestV2Error):
            validate_work_context_manifest_v2(value, actual)


def test_deep_immutability_canonical_parser_and_hostile_boundaries() -> None:
    raw = _raw_v1(); value = _v2(raw)
    result = validate_work_context_manifest_v2(value, raw)
    with pytest.raises(AttributeError):
        result.entries[0].entry_id = "other"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        object.__setattr__(result.entries[0], "entry_id", "other")
    value["entries"][0]["entry_id"] = "changed"
    assert result.entries[0].entry_id == "config"
    canonical = canonical_work_context_manifest_v2_structural_bytes(_v2(raw))
    assert parse_work_context_manifest_v2_structural_bytes(canonical).manifest_id == "context-1"
    for hostile in (b"[" * 40 + b"]" * 40, b"\xff", b'{"x":1,"x":2}'):
        with pytest.raises(WorkContextManifestV2Error):
            parse_work_context_manifest_v2_structural_bytes(hostile)


def test_exact_value_object_nested_types_fail_with_typed_error() -> None:
    raw = _raw_v1()
    valid = validate_work_context_manifest_v2(_v2(raw), raw)
    hostile_entry = valid._replace(entries=cast(Any, (object(),)))
    with pytest.raises(WorkContextManifestV2Error):
        validate_work_context_manifest_v2_structure(hostile_entry)
    first = valid.entries[0]._replace(carrier=cast(Any, object()))
    hostile_carrier = valid._replace(entries=(first, *valid.entries[1:]))
    with pytest.raises(WorkContextManifestV2Error):
        validate_work_context_manifest_v2_structure(hostile_carrier)
    assert type(valid) is WorkContextManifestV2


def test_hostile_hash_and_equality_never_escape_public_validator() -> None:
    raw = _raw_v1()
    valid = validate_work_context_manifest_v2(_v2(raw), raw)
    hostile_claims = valid._replace(
        claims=cast(Any, ((_HostileHash(), "declared_only"),)),
    )
    with pytest.raises(WorkContextManifestV2Error):
        validate_work_context_manifest_v2_structure(hostile_claims)

    bad_claim = _v2(raw)
    bad_claim["claims"]["selection"] = _HostileEquality()
    with pytest.raises(WorkContextManifestV2Error):
        validate_work_context_manifest_v2_structure(bad_claim)

    bad_estimate = _v2(raw)
    bad_estimate["token_estimate"]["quality"] = _HostileEquality()
    with pytest.raises(WorkContextManifestV2Error):
        validate_work_context_manifest_v2_structure(bad_estimate)

    for field in ("contract_type", "schema_version", "media_type", "availability"):
        bad_blob = _v2(raw)
        bad_blob["entries"][0][field] = _HostileEquality()
        with pytest.raises(WorkContextManifestV2Error):
            validate_work_context_manifest_v2_structure(bad_blob)


def test_structural_acceptance_implies_bounded_canonical_bytes() -> None:
    raw = _raw_v1()
    long_entries = [
        _forbidden(f"f{index:03d}-" + "x" * 251)
        for index in range(512)
    ]
    oversized = _v2(raw, entries=long_entries)
    with pytest.raises(WorkContextManifestV2Error):
        validate_work_context_manifest_v2_structure(oversized)
    normal = validate_work_context_manifest_v2_structure(_v2(raw))
    assert len(canonical_work_context_manifest_v2_structural_bytes(normal)) < 256 * 1024


def test_root_specific_api_rejects_parented_declaration() -> None:
    raw = _raw_v1()
    root = _v2(raw)
    assert validate_root_work_context_manifest_v2(root, raw).lineage.delegation_depth == 1
    child = _v2(raw, parent=work_context_manifest_v2_sha256(root, raw), depth=2)
    assert validate_work_context_manifest_v2(child, raw).lineage.delegation_depth == 2
    with pytest.raises(WorkContextManifestV2Error, match="root context declaration"):
        validate_root_work_context_manifest_v2(child, raw)


def test_child_declaration_only_allows_optional_selected_to_omitted() -> None:
    raw = _raw_v1()
    parent_entries = [_entry("snapshot", "department_snapshot_ref", "department_snapshot_ref", "blob_ref", H, 3, media=DEPARTMENT_SNAPSHOT_MEDIA_TYPE, availability="available"), _entry("source", "source_entries", "src/a.py", "file", "b" * 64, 1), _entry("config", "config_entries", "cfg/a.toml", "file", "c" * 64, 2, requirement="recommended"), _entry("upstream", "upstream_result_refs", "upstream_result_refs/0", "blob_ref", "d" * 64, 4, requirement="on_demand", state="omitted", media="application/json", availability="available"), _forbidden()]
    parent = _v2(raw, entries=parent_entries)
    child_entries = copy.deepcopy(parent_entries); child_entries[2]["state"] = "omitted"; child_entries[2]["reason_code"] = "omitted_recommended"
    child = _v2(raw, entries=child_entries, parent=work_context_manifest_v2_sha256(parent, raw), depth=2, manifest_id="context-2")
    result = validate_child_work_context_manifest_v2_declaration(child, parent, raw, raw)
    assert result.effective_entry_ids == ("snapshot", "source")
    assert dict(result.claims)["selection"] == "declared_only"
    assert validate_child_work_context_manifest_v2(child, parent, raw, raw) == result
    mutations: list[Callable[[dict[str, Any]], None]] = [
        lambda value: value["entries"].pop(0),
        lambda value: value["entries"][3].update(state="selected", reason_code="selected_on_demand"),
        lambda value: value["entries"][0].update(context_layer="L0"),
        lambda value: value.update(context_layer="L2"),
    ]
    for mutate in mutations:
        bad = copy.deepcopy(child); mutate(bad); _rebind(bad)
        with pytest.raises(WorkContextManifestV2Error):
            validate_child_work_context_manifest_v2_declaration(bad, parent, raw, raw)
    with pytest.raises(WorkContextManifestV2Error):
        validate_child_work_context_manifest_v2_declaration(child, parent, raw + b" ", raw)


def test_declaration_subset_does_not_claim_parent_materialization() -> None:
    raw = _raw_v1()
    parent_entries = [
        _entry("snapshot", "department_snapshot_ref", "department_snapshot_ref",
               "blob_ref", H, 3, media=DEPARTMENT_SNAPSHOT_MEDIA_TYPE,
               availability="available"),
        _entry("source", "source_entries", "src/a.py", "file", "b" * 64, 1),
        _entry("config", "config_entries", "cfg/a.toml", "file", "c" * 64, 2,
               requirement="recommended"),
        _entry("upstream", "upstream_result_refs", "upstream_result_refs/0",
               "blob_ref", "d" * 64, 4, requirement="on_demand",
               state="omitted", media="application/json", availability="available"),
        _forbidden(),
    ]
    parent = _v2(raw, entries=parent_entries)
    child = _v2(
        raw, entries=copy.deepcopy(parent_entries),
        parent=work_context_manifest_v2_sha256(parent, raw), depth=2,
    )
    declaration = validate_child_work_context_manifest_v2_declaration(
        child, parent, raw, raw,
    )
    assert "config" in declaration.effective_entry_ids
    assert dict(declaration.claims)["selection"] == "declared_only"
    assert {
        "parent_compile_result", "materialized_entry_ids", "provider_transport",
    }.isdisjoint(declaration.to_dict())


def test_manifest_label_may_repeat_but_revision_identity_binds_content() -> None:
    raw = _raw_v1()
    parent = _v2(raw)
    parent_digest = work_context_manifest_v2_sha256(parent, raw)
    child = _v2(raw, parent=parent_digest, depth=2)
    result = validate_child_work_context_manifest_v2_declaration(child, parent, raw, raw)
    parent_identity = work_context_manifest_v2_revision_identity(parent, raw)
    child_identity = work_context_manifest_v2_revision_identity(child, raw)
    assert result.manifest_id == parent_identity.manifest_id == child_identity.manifest_id
    assert parent_identity.content_sha256 != child_identity.content_sha256
    assert parent_identity.to_dict() == {
        "manifest_id": "context-1", "content_sha256": parent_digest,
    }
    assert dict(result.claims)["ledger_authority"] == "unavailable"


def test_context_layer_is_highest_declared_entry_layer() -> None:
    raw = _raw_v1()
    valid = _v2(raw)
    valid["entries"][1]["context_layer"] = "L0"
    assert validate_work_context_manifest_v2(valid, raw).context_layer == "L1"
    higher = copy.deepcopy(valid)
    higher["entries"][-1]["context_layer"] = "L2"
    higher["context_layer"] = "L2"
    assert validate_work_context_manifest_v2_structure(higher).context_layer == "L2"
    too_low = copy.deepcopy(valid)
    too_low["context_layer"] = "L0"
    with pytest.raises(WorkContextManifestV2Error, match="highest declared entry layer"):
        validate_work_context_manifest_v2_structure(too_low)
    too_high = copy.deepcopy(valid)
    too_high["context_layer"] = "L2"
    with pytest.raises(WorkContextManifestV2Error, match="highest declared entry layer"):
        validate_work_context_manifest_v2_structure(too_high)


def test_snapshot_remains_bound_when_other_carrier_sections_are_empty() -> None:
    manifest = _v1(); manifest["source_entries"] = []; manifest["config_entries"] = []; manifest["upstream_result_refs"] = []
    for section, digest in (("source_entries", "source_manifest_sha256"), ("config_entries", "config_manifest_sha256")):
        manifest[digest] = hashlib.sha256(canonical_company_json_bytes(manifest[section])).hexdigest()
    raw = canonical_work_context_manifest_bytes(manifest)
    value = _v2(raw, entries=[_entry("snapshot", "department_snapshot_ref", "department_snapshot_ref", "blob_ref", H, 3, media=DEPARTMENT_SNAPSHOT_MEDIA_TYPE, availability="available"), _forbidden()])
    assert validate_work_context_manifest_v2(value, raw).effective_entry_ids == ("snapshot",)
    value["token_estimate"]["tokens"] = 0
    with pytest.raises(WorkContextManifestV2Error):
        validate_work_context_manifest_v2(value, raw)
