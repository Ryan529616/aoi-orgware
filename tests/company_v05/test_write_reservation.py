"""W2 capability/enforcement contracts never constitute admission on their own."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from aoi_orgware.company.write_reservation import (
    MAX_COMPANY_INCARNATION,
    MAX_LOCK_DOMAIN_GENERATION,
    WORK_WRITE_CAPABILITY_V1,
    WRITE_ADMISSION_ENFORCEMENT_V1,
    WriteReservationError,
    seal_work_write_capability,
    seal_write_admission_enforcement,
    validate_work_write_capability,
    validate_write_admission_enforcement,
)
from aoi_orgware.semantic_events import canonical_json_bytes, canonical_sha256


H = "a" * 64
T0 = "2026-07-29T00:00:00Z"
T1 = "2026-07-29T01:00:00Z"
BINDING = {
    "company_id": "company-1",
    "company_incarnation": 1,
    "lock_domain_generation": 1,
}
OBSERVED = {"state": "known", "reason": "observed"}


def opaque_ref(kind: str, identity: str, namespace: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": kind,
        "namespace": namespace,
        "canonical_identity": identity,
        "filesystem_semantics": "opaque-v1",
    }


def capability() -> dict[str, Any]:
    refs = sorted([
        opaque_ref("output_namespace", "run-output", "outputs"),
        opaque_ref("serialization_key", "index-update", "serial"),
    ], key=canonical_json_bytes)
    return seal_work_write_capability({
        "contract_type": WORK_WRITE_CAPABILITY_V1,
        "schema_version": 1,
        **BINDING,
        "capability_id": "write-capability-1",
        "domain_binding_id": "write-domain-1",
        "domain_binding_sha256": H,
        "task_id": "task-1",
        "packet_id": "packet-1",
        "packet_sha256": H,
        "authority_scope_sha256": H,
        "intent_id": "write-intent-1",
        "intent_sha256": H,
        "issuer_grant_id": "authority-grant-1",
        "issuer_grant_sha256": H,
        "issuer_action": "write_capability.issue",
        "owner_kind": "dispatch_request",
        "owner_id": "dispatch-1",
        "owner_generation_id": "dispatch-generation-1",
        "owner_anchor_sha256": H,
        "owner_reservation_id": "owner-reservation-1",
        "opaque_refs": refs,
        "opaque_refs_sha256": canonical_sha256(refs),
        "issued_at": T0,
        "expires_at": T1,
        "provenance": "AOI_verified",
        "observation": OBSERVED,
    })


def enforcement() -> dict[str, Any]:
    return seal_write_admission_enforcement({
        "contract_type": WRITE_ADMISSION_ENFORCEMENT_V1,
        "schema_version": 1,
        **BINDING,
        "gate_id": "write-admission-v1",
        "mode": "enforced",
        "domain_binding_id": "write-domain-1",
        "domain_binding_sha256": H,
        "previous_transaction_sha256": H,
        "activated_at": T0,
        "provenance": "AOI_verified",
        "observation": OBSERVED,
    })


def unsigned(value: dict[str, Any], digest: str) -> dict[str, Any]:
    return {key: member for key, member in value.items() if key != digest}


def test_registered_domain_and_self_validation_are_not_admission() -> None:
    sealed = capability()
    assert validate_work_write_capability(sealed) == sealed
    assert sealed["opaque_refs_sha256"] == canonical_sha256(sealed["opaque_refs"])
    # A registered domain and self-digest are evidence only, never admission.
    assert sealed["domain_binding_id"] == "write-domain-1"
    assert "admitted" not in sealed
    assert "issued_transaction" not in sealed
    assert "never proves admission authority" in (
        validate_work_write_capability.__doc__ or ""
    )

    for digest in ("capability_sha256",):
        extra = deepcopy(sealed)
        extra["extra"] = True
        with pytest.raises(WriteReservationError):
            validate_work_write_capability(extra)
        missing = deepcopy(sealed)
        missing.pop(digest)
        with pytest.raises(WriteReservationError):
            validate_work_write_capability(missing)
        tampered = deepcopy(sealed)
        tampered[digest] = "9" * 64
        with pytest.raises(WriteReservationError):
            validate_work_write_capability(tampered)


def test_capability_requires_exact_authority_intent_owner_and_issuer_bindings() -> None:
    sealed = capability()
    for field, invalid in (
        ("intent_id", ""),
        ("intent_sha256", "B" * 64),
        ("issuer_grant_id", ""),
        ("issuer_grant_sha256", "B" * 64),
        ("issuer_action", "company.mutate"),
        ("owner_kind", "worker"),
        ("owner_reservation_id", ""),
    ):
        altered = deepcopy(sealed)
        altered[field] = invalid
        with pytest.raises(WriteReservationError):
            seal_work_write_capability(unsigned(altered, "capability_sha256"))
    tampered = deepcopy(sealed)
    tampered["packet_sha256"] = "9" * 64
    with pytest.raises(WriteReservationError):
        validate_work_write_capability(tampered)


def test_capability_only_allows_sorted_unique_opaque_refs() -> None:
    sealed = capability()
    file_only = deepcopy(sealed)
    file_only["opaque_refs"] = []
    file_only["opaque_refs_sha256"] = canonical_sha256([])
    assert seal_work_write_capability(
        unsigned(file_only, "capability_sha256"),
    )["opaque_refs"] == []
    for kind in ("file", "tree"):
        invalid = deepcopy(sealed)
        invalid["opaque_refs"][0] = {
            "schema_version": 1, "kind": kind, "namespace": "repo-root",
            "canonical_identity": "src/a.py", "filesystem_semantics": "posix-v1",
        }
        with pytest.raises(WriteReservationError):
            seal_work_write_capability(unsigned(invalid, "capability_sha256"))
    for mutation in (
        lambda value: value["opaque_refs"].reverse(),
        lambda value: value.update({"opaque_refs": [value["opaque_refs"][0]] * 2}),
    ):
        invalid = deepcopy(sealed)
        mutation(invalid)
        with pytest.raises(WriteReservationError):
            seal_work_write_capability(unsigned(invalid, "capability_sha256"))
    bad_time = deepcopy(sealed)
    bad_time["expires_at"] = T0
    with pytest.raises(WriteReservationError):
        seal_work_write_capability(unsigned(bad_time, "capability_sha256"))
    too_long = deepcopy(sealed)
    too_long["expires_at"] = "2026-07-30T01:00:01Z"
    with pytest.raises(WriteReservationError, match="at most 24 hours"):
        seal_work_write_capability(unsigned(too_long, "capability_sha256"))
    tuple_refs = deepcopy(sealed)
    tuple_refs["opaque_refs"] = tuple(tuple_refs["opaque_refs"])
    with pytest.raises(WriteReservationError):
        validate_work_write_capability(tuple_refs)
    for alias in ("2026-07-29T00:00:00.0Z", "2026-07-29T00:00:00.000000Z"):
        timestamp_alias = deepcopy(sealed)
        timestamp_alias["issued_at"] = alias
        with pytest.raises(WriteReservationError):
            seal_work_write_capability(
                unsigned(timestamp_alias, "capability_sha256"),
            )
    for malformed_refs in ("not-a-list", b"not-a-list"):
        malformed = deepcopy(sealed)
        malformed["opaque_refs"] = malformed_refs
        with pytest.raises(WriteReservationError):
            seal_work_write_capability(
                unsigned(malformed, "capability_sha256"),
            )
    too_many = deepcopy(sealed)
    too_many["opaque_refs"] = sorted(
        [
            opaque_ref("serialization_key", f"key-{index:02d}", "serial")
            for index in range(65)
        ],
        key=canonical_json_bytes,
    )
    too_many["opaque_refs_sha256"] = canonical_sha256(too_many["opaque_refs"])
    with pytest.raises(WriteReservationError):
        seal_work_write_capability(unsigned(too_many, "capability_sha256"))
    wrong_semantics = deepcopy(sealed)
    wrong_semantics["opaque_refs"][0]["filesystem_semantics"] = "posix-v1"
    wrong_semantics["opaque_refs_sha256"] = canonical_sha256(
        wrong_semantics["opaque_refs"],
    )
    with pytest.raises(WriteReservationError):
        seal_work_write_capability(
            unsigned(wrong_semantics, "capability_sha256"),
        )


def test_company_binding_is_integer_and_not_legacy_string_or_bool() -> None:
    for factory, digest, seal in (
        (capability, "capability_sha256", seal_work_write_capability),
        (enforcement, "enforcement_sha256", seal_write_admission_enforcement),
    ):
        for invalid in ("1", True, 0):
            value = factory()
            value["company_incarnation"] = invalid
            with pytest.raises(WriteReservationError):
                seal(unsigned(value, digest))
        value = factory()
        value["lock_domain_generation"] = True
        with pytest.raises(WriteReservationError):
            seal(unsigned(value, digest))
        for field, invalid in (
            ("company_incarnation", MAX_COMPANY_INCARNATION + 1),
            ("lock_domain_generation", MAX_LOCK_DOMAIN_GENERATION + 1),
        ):
            value = factory()
            value[field] = invalid
            with pytest.raises(WriteReservationError):
                seal(unsigned(value, digest))


def test_enforcement_roundtrip_fixed_gate_observation_and_digest() -> None:
    sealed = enforcement()
    assert validate_write_admission_enforcement(sealed) == sealed
    for field, invalid in (
        ("gate_id", "other"),
        ("mode", "monitor"),
        ("provenance", "external"),
    ):
        altered = deepcopy(sealed)
        altered[field] = invalid
        with pytest.raises(WriteReservationError):
            seal_write_admission_enforcement(unsigned(altered, "enforcement_sha256"))
    observation = deepcopy(sealed)
    observation["observation"] = {"state": "unknown", "reason": "pending"}
    with pytest.raises(WriteReservationError):
        seal_write_admission_enforcement(unsigned(observation, "enforcement_sha256"))
    tampered = deepcopy(sealed)
    tampered["previous_transaction_sha256"] = "9" * 64
    with pytest.raises(WriteReservationError):
        validate_write_admission_enforcement(tampered)
    for mutation in ("extra", "missing"):
        malformed = deepcopy(sealed)
        if mutation == "extra":
            malformed["extra"] = True
        else:
            malformed.pop("mode")
        with pytest.raises(WriteReservationError):
            validate_write_admission_enforcement(malformed)
    for alias in ("2026-07-29T00:00:00.0Z", "2026-07-29T00:00:00.000000Z"):
        timestamp_alias = deepcopy(sealed)
        timestamp_alias["activated_at"] = alias
        with pytest.raises(WriteReservationError):
            seal_write_admission_enforcement(
                unsigned(timestamp_alias, "enforcement_sha256"),
            )
