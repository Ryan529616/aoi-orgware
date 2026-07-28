from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from itertools import permutations
from typing import Any, cast
import unicodedata

import pytest

from aoi_orgware.company import write_admission as subject
from aoi_orgware.company.write_admission import (
    MAX_COVERAGE_GAPS,
    MAX_HELD_WRITE_INTENTS,
    MAX_HELD_WRITE_REFS,
    WORK_WRITE_INTENT_V1,
    WRITE_DOMAIN_BINDING_V1,
    WriteAdmissionError,
    WriteCoverageGapV1,
    evaluate_write_overlap,
    seal_work_write_intent,
    seal_write_domain_binding,
    validate_active_write_ref,
    validate_intent_domain_binding,
    validate_work_write_intent,
    validate_write_domain_binding,
)
from aoi_orgware.semantic_events import canonical_json_bytes, canonical_sha256


H = "a" * 64
T = "2026-07-28T20:00:00Z"


def ref(
    kind: str,
    identity: str,
    *,
    namespace: str = "repo-root",
    semantics: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": kind,
        "namespace": namespace,
        "canonical_identity": identity,
        "filesystem_semantics": (
            semantics
            if semantics is not None
            else "opaque-v1"
            if kind in {"output_namespace", "serialization_key"}
            else "posix-v1"
        ),
    }


def canonical_refs(*members: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted((deepcopy(member) for member in members), key=canonical_json_bytes)


def domain(
    *,
    binding_id: str = "write-domain-1",
    family: str = "posix-v1",
    root_namespace: str = "repo-root",
    company_incarnation: int = 1,
    lock_domain_generation: int = 1,
    opaque: tuple[tuple[str, str], ...] = (
        ("output_namespace", "outputs"),
        ("serialization_key", "serial"),
    ),
) -> dict[str, Any]:
    opaque_namespaces = [
        {"kind": kind, "namespace": namespace}
        for kind, namespace in sorted(opaque)
    ]
    return seal_write_domain_binding(
        {
            "contract_type": WRITE_DOMAIN_BINDING_V1,
            "schema_version": 1,
            "company_id": "company-1",
            "company_incarnation": company_incarnation,
            "lock_domain_generation": lock_domain_generation,
            "binding_id": binding_id,
            "root_namespace": root_namespace,
            "filesystem_family": family,
            "opaque_namespaces": opaque_namespaces,
            "created_at": T,
            "provenance": "AOI_verified",
            "observation": {"state": "known", "reason": "observed"},
        }
    )


def intent(
    intent_id: str,
    *members: dict[str, Any],
    write_domain: dict[str, Any] | None = None,
    owner_kind: str = "dispatch_request",
    owner_id: str | None = None,
    owner_generation_id: str | None = None,
    reservation_id: str | None = None,
) -> dict[str, Any]:
    selected_domain = domain() if write_domain is None else write_domain
    selected_members = members or (ref("file", f"scratch/{intent_id}.tmp"),)
    refs = canonical_refs(*selected_members)
    return seal_work_write_intent(
        {
            "contract_type": WORK_WRITE_INTENT_V1,
            "schema_version": 1,
            "company_id": selected_domain["company_id"],
            "company_incarnation": selected_domain["company_incarnation"],
            "lock_domain_generation": selected_domain["lock_domain_generation"],
            "intent_id": intent_id,
            "domain_binding_id": selected_domain["binding_id"],
            "domain_binding_sha256": selected_domain["binding_sha256"],
            "owner_kind": owner_kind,
            "owner_id": owner_id or f"owner-{intent_id}",
            "owner_generation_id": owner_generation_id or f"generation-{intent_id}",
            "owner_anchor_sha256": H,
            "reservation_id": reservation_id or f"reservation-{intent_id}",
            "task_id": "task-1",
            "packet_id": "packet-1",
            "packet_sha256": "b" * 64,
            "authority_scope_sha256": "c" * 64,
            "refs": refs,
            "refs_sha256": canonical_sha256(refs),
            "created_at": T,
            "provenance": "AOI_verified",
            "observation": {"state": "known", "reason": "observed"},
        }
    )


def reseal_intent(value: dict[str, Any], **changes: Any) -> dict[str, Any]:
    unsigned = {
        key: deepcopy(member)
        for key, member in value.items()
        if key != "intent_sha256"
    }
    unsigned.update(changes)
    if "refs" in changes and "refs_sha256" not in changes:
        unsigned["refs_sha256"] = canonical_sha256(unsigned["refs"])
    return seal_work_write_intent(unsigned)


def test_domain_and_nonempty_intent_round_trip_are_strict() -> None:
    write_domain = domain()
    candidate = intent("intent-1", write_domain=write_domain)
    assert validate_write_domain_binding(write_domain) == write_domain
    assert validate_work_write_intent(candidate) == candidate
    assert validate_intent_domain_binding(candidate, write_domain) == (
        candidate,
        write_domain,
    )
    assert len(candidate["refs"]) == 1
    overlap = evaluate_write_overlap(candidate, [], domain=write_domain)
    assert overlap.overlap_status == "overlap_clear"
    assert overlap.authority_status == "not_evaluated"


def test_empty_intent_is_rejected_and_cannot_authorize_write_launch() -> None:
    with pytest.raises(WriteAdmissionError, match="empty"):
        reseal_intent(intent("intent-1"), refs=[])


@pytest.mark.parametrize(
    ("target", "field", "value"),
    [
        ("domain", "contract_type", "Other"),
        ("domain", "schema_version", True),
        ("domain", "company_incarnation", "1"),
        ("domain", "company_incarnation", True),
        ("domain", "filesystem_family", "unknown"),
        ("domain", "provenance", "agent_reported"),
        ("domain", "observation", {"state": "unknown", "reason": "missing"}),
        ("intent", "contract_type", "Other"),
        ("intent", "schema_version", True),
        ("intent", "company_incarnation", "1"),
        ("intent", "company_incarnation", True),
        ("intent", "owner_kind", "worker"),
        ("intent", "task_id", None),
        ("intent", "packet_id", None),
        ("intent", "packet_sha256", None),
        ("intent", "authority_scope_sha256", None),
        ("intent", "owner_anchor_sha256", None),
        ("intent", "provenance", "agent_reported"),
        ("intent", "observation", {"state": "unknown", "reason": "missing"}),
    ],
)
def test_contract_fields_fail_closed(target: str, field: str, value: Any) -> None:
    original = domain() if target == "domain" else intent("intent-1")
    broken = deepcopy(original)
    broken[field] = value
    with pytest.raises(WriteAdmissionError):
        (
            validate_write_domain_binding(broken)
            if target == "domain"
            else validate_work_write_intent(broken)
        )


def test_unknown_fields_and_self_digest_tamper_are_rejected() -> None:
    for original, validator, digest_field in (
        (domain(), validate_write_domain_binding, "binding_sha256"),
        (intent("intent-1"), validate_work_write_intent, "intent_sha256"),
    ):
        extra = deepcopy(original)
        extra["unexpected"] = "value"
        with pytest.raises(WriteAdmissionError):
            validator(extra)
        tampered = deepcopy(original)
        tampered[digest_field] = "f" * 64
        with pytest.raises(WriteAdmissionError):
            validator(tampered)


def test_active_write_ref_schema_is_strict() -> None:
    for field, value in (
        ("schema_version", True),
        ("kind", []),
        ("namespace", []),
        ("canonical_identity", []),
        ("filesystem_semantics", []),
    ):
        broken = ref("file", "rtl/a.sv")
        broken[field] = value
        with pytest.raises(WriteAdmissionError):
            validate_active_write_ref(broken)


def test_domain_opaque_namespaces_are_sorted_unique_and_bounded() -> None:
    original = domain()
    for opaque in (
        list(reversed(original["opaque_namespaces"])),
        [original["opaque_namespaces"][0], original["opaque_namespaces"][0]],
        [{"kind": "file", "namespace": "outputs"}],
    ):
        unsigned = {key: value for key, value in original.items() if key != "binding_sha256"}
        unsigned["opaque_namespaces"] = opaque
        with pytest.raises(WriteAdmissionError):
            seal_write_domain_binding(unsigned)
    too_many = tuple(("output_namespace", f"output-{index}") for index in range(65))
    with pytest.raises(WriteAdmissionError):
        domain(opaque=too_many)


@pytest.mark.parametrize(
    "path",
    [
        "C:/rtl/a.sv",
        "//server/share/a.sv",
        "/mnt/c/rtl/a.sv",
        "../rtl/a.sv",
        "rtl/../a.sv",
        "rtl\\a.sv",
        "rtl//a.sv",
        "rtl/a.sv/",
        "rtl/con",
        "rtl/a?.sv",
        unicodedata.normalize("NFD", "rtl/é.sv"),
        "a" * 1025,
    ],
)
def test_filesystem_ref_rejects_noncanonical_or_platform_spelling(path: str) -> None:
    with pytest.raises(WriteAdmissionError):
        validate_active_write_ref(ref("file", path))


def test_intent_cross_binding_rejects_caller_namespace_and_semantics_override() -> None:
    posix = domain()
    wrong_namespace = intent(
        "intent-namespace",
        ref("file", "rtl/a.sv", namespace="another-root"),
        write_domain=posix,
    )
    wrong_semantics = intent(
        "intent-semantics",
        ref("file", "rtl/a.sv", semantics="windows-win32-v1"),
        write_domain=posix,
    )
    for candidate in (wrong_namespace, wrong_semantics):
        with pytest.raises(WriteAdmissionError):
            validate_intent_domain_binding(candidate, posix)
        with pytest.raises(WriteAdmissionError):
            evaluate_write_overlap(candidate, [], domain=posix)


def test_windows_domain_accepts_only_registered_windows_and_wsl_views() -> None:
    windows = domain(family="windows-backed-v1")
    win_intent = intent(
        "intent-win",
        ref("file", "rtl/a.sv", semantics="windows-win32-v1"),
        write_domain=windows,
    )
    wsl_intent = intent(
        "intent-wsl",
        ref("file", "rtl/b.sv", semantics="wsl-windows-drive-mount-v1"),
        write_domain=windows,
    )
    validate_intent_domain_binding(win_intent, windows)
    validate_intent_domain_binding(wsl_intent, windows)
    posix_spelling = intent(
        "intent-posix",
        ref("file", "rtl/c.sv", semantics="posix-v1"),
        write_domain=windows,
    )
    with pytest.raises(WriteAdmissionError):
        validate_intent_domain_binding(posix_spelling, windows)


def test_opaque_refs_require_exact_registered_kind_and_namespace() -> None:
    write_domain = domain()
    valid = intent(
        "intent-opaque",
        ref("output_namespace", "run-1", namespace="outputs"),
        ref("serialization_key", "license-1", namespace="serial"),
        write_domain=write_domain,
    )
    validate_intent_domain_binding(valid, write_domain)
    for candidate_ref in (
        ref("output_namespace", "run-1", namespace="serial"),
        ref("serialization_key", "license-1", namespace="outputs"),
        ref("output_namespace", "run-1", namespace="unknown"),
    ):
        invalid = intent("intent-bad-opaque", candidate_ref, write_domain=write_domain)
        with pytest.raises(WriteAdmissionError):
            validate_intent_domain_binding(invalid, write_domain)


def test_refs_must_be_canonical_and_self_nonoverlapping() -> None:
    write_domain = domain()
    left = ref("file", "rtl/a.sv")
    right = ref("file", "rtl/b.sv")
    unordered = [right, left]
    unsigned = {
        key: deepcopy(value)
        for key, value in intent("intent-base", write_domain=write_domain).items()
        if key != "intent_sha256"
    }
    unsigned["refs"] = unordered
    unsigned["refs_sha256"] = canonical_sha256(unordered)
    with pytest.raises(WriteAdmissionError):
        seal_work_write_intent(unsigned)
    redundant_sets = (
        canonical_refs(left, left),
        canonical_refs(ref("tree", "rtl"), left),
        canonical_refs(ref("tree", "rtl"), ref("tree", "rtl/sub")),
        canonical_refs(ref("file", "rtl"), ref("file", "rtl/a.sv")),
        canonical_refs(
            ref("output_namespace", "run-1", namespace="outputs"),
            ref("output_namespace", "run-1", namespace="outputs"),
        ),
    )
    for refs in redundant_sets:
        with pytest.raises(WriteAdmissionError):
            reseal_intent(intent("intent-base"), refs=refs)


def test_windows_case_alias_and_mixed_family_within_intent_are_rejected() -> None:
    aliases = canonical_refs(
        ref("file", "RTL/A.sv", semantics="windows-win32-v1"),
        ref("file", "rtl/a.sv", semantics="wsl-windows-drive-mount-v1"),
    )
    with pytest.raises(WriteAdmissionError):
        reseal_intent(intent("intent-alias"), refs=aliases)
    mixed = canonical_refs(
        ref("file", "rtl/a.sv", semantics="posix-v1"),
        ref("file", "dv/b.sv", semantics="windows-win32-v1"),
    )
    with pytest.raises(WriteAdmissionError):
        reseal_intent(intent("intent-mixed"), refs=mixed)


@pytest.mark.parametrize(
    ("candidate_ref", "held_ref", "expected_reason"),
    [
        (ref("file", "rtl/a.sv"), ref("file", "rtl/a.sv"), "file_exact"),
        (
            ref("file", "rtl/sub/a.sv"),
            ref("tree", "rtl"),
            "candidate_file_within_held_tree",
        ),
        (
            ref("tree", "rtl"),
            ref("file", "rtl/sub/a.sv"),
            "candidate_tree_contains_held_file",
        ),
        (
            ref("tree", "rtl/sub"),
            ref("tree", "rtl"),
            "tree_ancestor_overlap",
        ),
        (
            ref("file", "rtl"),
            ref("file", "rtl/a.sv"),
            "file_ancestor_topology",
        ),
        (
            ref("output_namespace", "run-1", namespace="outputs"),
            ref("output_namespace", "run-1", namespace="outputs"),
            "output_namespace_exact",
        ),
        (
            ref("serialization_key", "license-1", namespace="serial"),
            ref("serialization_key", "license-1", namespace="serial"),
            "serialization_key_exact",
        ),
    ],
)
def test_overlap_relation_matrix(
    candidate_ref: dict[str, Any],
    held_ref: dict[str, Any],
    expected_reason: str,
) -> None:
    write_domain = domain()
    result = evaluate_write_overlap(
        intent("candidate", candidate_ref, write_domain=write_domain),
        [intent("held", held_ref, write_domain=write_domain)],
        domain=write_domain,
    )
    assert result.overlap_status == "conflict"
    assert [conflict.reason for conflict in result.conflicts] == [expected_reason]
    assert result.conflicts[0].candidate_ref_sha256 == canonical_sha256(candidate_ref)
    assert result.conflicts[0].held_ref_sha256 == canonical_sha256(held_ref)


@pytest.mark.parametrize(
    ("candidate_ref", "held_ref"),
    [
        (ref("tree", "rtl/a"), ref("file", "rtl/ab/x.sv")),
        (ref("file", "RTL/a.sv"), ref("file", "rtl/a.sv")),
        (
            ref("output_namespace", "Run-1", namespace="outputs"),
            ref("output_namespace", "run-1", namespace="outputs"),
        ),
        (
            ref("output_namespace", "run-1", namespace="outputs"),
            ref("serialization_key", "run-1", namespace="serial"),
        ),
        (
            ref("output_namespace", "run-1", namespace="outputs"),
            ref("output_namespace", "run-1", namespace="other"),
        ),
    ],
)
def test_nonoverlap_matrix(
    candidate_ref: dict[str, Any],
    held_ref: dict[str, Any],
) -> None:
    write_domain = domain(
        opaque=(
            ("output_namespace", "other"),
            ("output_namespace", "outputs"),
            ("serialization_key", "serial"),
        )
    )
    result = evaluate_write_overlap(
        intent("candidate", candidate_ref, write_domain=write_domain),
        [intent("held", held_ref, write_domain=write_domain)],
        domain=write_domain,
    )
    assert result.overlap_status == "overlap_clear"
    assert result.conflicts == ()


def test_windows_and_wsl_views_casefold_to_one_conflict_domain() -> None:
    write_domain = domain(family="windows-backed-v1")
    candidate = intent(
        "candidate",
        ref("file", "RTL/É.sv", semantics="windows-win32-v1"),
        write_domain=write_domain,
    )
    held = intent(
        "held",
        ref("file", "rtl/é.sv", semantics="wsl-windows-drive-mount-v1"),
        write_domain=write_domain,
    )
    result = evaluate_write_overlap(candidate, [held], domain=write_domain)
    assert result.overlap_status == "conflict"
    assert result.conflicts[0].reason == "file_exact"


def test_same_lineage_has_no_automatic_overlap_exemption() -> None:
    write_domain = domain()
    candidate = intent(
        "candidate",
        ref("file", "rtl/a.sv"),
        write_domain=write_domain,
        owner_id="same-owner",
        reservation_id="same-reservation",
    )
    held = intent(
        "held",
        ref("file", "rtl/a.sv"),
        write_domain=write_domain,
        owner_id="same-owner",
        reservation_id="same-reservation",
    )
    assert (
        evaluate_write_overlap(candidate, [held], domain=write_domain).overlap_status
        == "conflict"
    )


def test_exact_replay_is_idempotent_but_divergent_identity_is_corruption() -> None:
    write_domain = domain()
    candidate = intent(
        "candidate", ref("file", "rtl/a.sv"), write_domain=write_domain
    )
    replay = evaluate_write_overlap(
        candidate, [deepcopy(candidate)], domain=write_domain
    )
    assert replay.overlap_status == "overlap_clear"
    assert replay.idempotent_replay is True
    divergent = reseal_intent(
        candidate, refs=canonical_refs(ref("file", "rtl/b.sv"))
    )
    with pytest.raises(WriteAdmissionError, match="divergent"):
        evaluate_write_overlap(candidate, [divergent], domain=write_domain)


def test_same_id_wrong_domain_is_divergence_not_coverage_unknown() -> None:
    current_domain = domain()
    stale_domain = domain(
        binding_id="write-domain-stale",
        company_incarnation=2,
        lock_domain_generation=2,
    )
    candidate = intent(
        "same-id", ref("file", "rtl/a.sv"), write_domain=current_domain
    )
    stale = intent(
        "same-id", ref("file", "rtl/a.sv"), write_domain=stale_domain
    )
    with pytest.raises(WriteAdmissionError, match="divergent"):
        evaluate_write_overlap(candidate, [stale], domain=current_domain)


def test_held_order_and_pair_direction_are_deterministic() -> None:
    write_domain = domain()
    candidate = intent(
        "candidate", ref("tree", "rtl"), write_domain=write_domain
    )
    held = [
        intent("held-b", ref("file", "rtl/b.sv"), write_domain=write_domain),
        intent("held-a", ref("file", "rtl/a.sv"), write_domain=write_domain),
    ]
    results = [
        evaluate_write_overlap(candidate, list(order), domain=write_domain)
        for order in permutations(held)
    ]
    assert results[0] == results[1]
    assert [item.held_intent_id for item in results[0].conflicts] == [
        "held-a",
        "held-b",
    ]
    reverse = evaluate_write_overlap(
        intent("reverse", ref("file", "rtl/a.sv"), write_domain=write_domain),
        [intent("held-tree", ref("tree", "rtl"), write_domain=write_domain)],
        domain=write_domain,
    )
    assert reverse.overlap_status == "conflict"


def test_adding_held_claims_cannot_change_conflict_to_accept() -> None:
    write_domain = domain()
    candidate = intent(
        "candidate", ref("file", "rtl/a.sv"), write_domain=write_domain
    )
    conflicting = intent(
        "held-conflict", ref("tree", "rtl"), write_domain=write_domain
    )
    disjoint = intent(
        "held-disjoint", ref("file", "dv/a.sv"), write_domain=write_domain
    )
    first = evaluate_write_overlap(
        candidate, [conflicting], domain=write_domain
    )
    second = evaluate_write_overlap(
        candidate, [conflicting, disjoint], domain=write_domain
    )
    assert first.overlap_status == second.overlap_status == "conflict"
    assert set(first.conflicts).issubset(second.conflicts)


def test_coverage_unknown_has_priority_and_is_order_independent() -> None:
    write_domain = domain()
    candidate = intent("candidate", write_domain=write_domain)
    gaps = (
        WriteCoverageGapV1(
            "external_job", "job-b", "active_owner_state_unknown"
        ),
        WriteCoverageGapV1(
            "dispatch_request",
            "dispatch-a",
            "legacy_active_owner_missing_intent",
        ),
    )
    left = evaluate_write_overlap(
        candidate, [], domain=write_domain, coverage_gaps=gaps
    )
    right = evaluate_write_overlap(
        candidate, [], domain=write_domain, coverage_gaps=tuple(reversed(gaps))
    )
    assert left == right
    assert left.overlap_status == "coverage_unknown"
    with pytest.raises(WriteAdmissionError, match="duplicated"):
        evaluate_write_overlap(
            candidate,
            [],
            domain=write_domain,
            coverage_gaps=(gaps[0], gaps[0]),
        )


def test_unreconciled_company_generation_is_coverage_unknown() -> None:
    current_domain = domain()
    old_domain = domain(
        binding_id="write-domain-old",
        company_incarnation=2,
        lock_domain_generation=2,
    )
    candidate = intent("candidate", write_domain=current_domain)
    held = intent("held-old", write_domain=old_domain)
    result = evaluate_write_overlap(
        candidate, [held], domain=current_domain
    )
    assert result.overlap_status == "coverage_unknown"
    assert result.coverage_gaps == (
        WriteCoverageGapV1(
            "dispatch_request", "owner-held-old", "active_owner_domain_unreconciled"
        ),
    )


def test_registered_domain_and_scope_digest_never_become_authority() -> None:
    candidate = intent(
        "candidate",
        ref("file", "rtl/a.sv"),
        ref("output_namespace", "run-1", namespace="outputs"),
        ref("serialization_key", "license-1", namespace="serial"),
    )
    validate_intent_domain_binding(candidate, domain())
    result = evaluate_write_overlap(candidate, [], domain=domain())
    assert result.overlap_status == "overlap_clear"
    assert result.authority_status == "not_evaluated"
    forged_scope = reseal_intent(candidate, authority_scope_sha256="d" * 64)
    forged_result = evaluate_write_overlap(forged_scope, [], domain=domain())
    assert forged_result.authority_status == "not_evaluated"
    assert not hasattr(subject, "write_intent_is_authorized")
    assert "write_intent_is_authorized" not in subject.__all__


def test_bounded_held_intents_refs_and_coverage_gaps() -> None:
    write_domain = domain()
    candidate = intent("candidate", write_domain=write_domain)
    too_many_intents = [
        intent(f"held-{index}", write_domain=write_domain)
        for index in range(MAX_HELD_WRITE_INTENTS + 1)
    ]
    with pytest.raises(WriteAdmissionError, match="intent set"):
        evaluate_write_overlap(candidate, too_many_intents, domain=write_domain)
    too_many_gaps = [
        WriteCoverageGapV1(
            "external_job", f"job-{index}", "active_owner_state_unknown"
        )
        for index in range(MAX_COVERAGE_GAPS + 1)
    ]
    with pytest.raises(WriteAdmissionError, match="gap set"):
        evaluate_write_overlap(
            candidate, [], domain=write_domain, coverage_gaps=too_many_gaps
        )
    intent_count = MAX_HELD_WRITE_REFS // 64 + 1
    many_refs = [
        intent(
            f"many-{owner}",
            *(
                ref("file", f"generated/{owner}/{member}.txt")
                for member in range(64)
            ),
            write_domain=write_domain,
        )
        for owner in range(intent_count)
    ]
    with pytest.raises(WriteAdmissionError, match="ref set"):
        evaluate_write_overlap(candidate, many_refs, domain=write_domain)


def test_overlap_collections_reject_none_with_typed_error() -> None:
    candidate = intent("candidate")
    with pytest.raises(WriteAdmissionError, match="intent set"):
        evaluate_write_overlap(candidate, cast(Any, None), domain=domain())
    with pytest.raises(WriteAdmissionError, match="gap set"):
        evaluate_write_overlap(
            candidate, [], domain=domain(), coverage_gaps=cast(Any, None)
        )


def test_coverage_gap_dataclass_rejects_invalid_values() -> None:
    valid = WriteCoverageGapV1(
        "external_job", "job-1", "active_owner_state_unknown"
    )
    assert replace(valid, owner_id="job-2").owner_id == "job-2"
    with pytest.raises(WriteAdmissionError):
        WriteCoverageGapV1(
            cast(Any, "worker"), "job-1", "active_owner_state_unknown"
        )
    with pytest.raises(WriteAdmissionError):
        WriteCoverageGapV1(
            "external_job", "job-1", cast(Any, "missing")
        )
