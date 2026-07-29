"""Unverified inventory observation for one canonical WorkContextManifestV1.

The input is a caller-supplied invariant projection and raw manifest bytes.
This module proves neither ledger membership nor a complete repository, prompt,
materialized context, provider transmission, admission, authority, residency,
or window fit.  It only reports the contract's declared inventory metadata.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, NamedTuple, NoReturn

from aoi_orgware.company.contracts import (
    MAX_CONTRACT_BYTES,
    WORK_PACKET_V1,
    CompanyContractError,
    canonical_company_json_bytes,
    canonical_work_context_manifest_bytes,
    company_contract_sha256,
    validate_work_context_manifest,
    validate_work_packet,
)
from aoi_orgware.company.invariants import InvariantObject, InvariantProjection


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_UNAVAILABLE = (
    (
        "selection_class_and_reason",
        "work_context_manifest_v1_cannot_represent_mandatory_recommended_on_demand_forbidden_or_l0_l3_selection",
    ),
    ("freshness_and_expiry", "work_context_manifest_v1_cannot_represent_freshness_or_expiry"),
    ("omissions", "work_context_manifest_v1_cannot_represent_omitted_context"),
    ("completeness", "work_context_manifest_v1_cannot_represent_context_completeness"),
    ("token_estimate_tokenizer_model", "work_context_manifest_v1_cannot_represent_token_estimate_tokenizer_or_model"),
    ("actual_sent_bytes", "work_context_manifest_v1_cannot_represent_provider_sent_bytes"),
    ("window_fit", "work_context_manifest_v1_cannot_represent_provider_window_fit"),
    ("ledger_authority", "caller_supplied_projection_has_no_ledger_or_authority_proof"),
)


class LegacyContextV1Error(ValueError):
    """The supplied data cannot support a safe legacy manifest observation."""


class LegacyContextV1Key(NamedTuple):
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    packet_id: str


class ContextUnavailableFact(NamedTuple):
    fact: str
    availability: str
    reason: str


class ContextManifestInventory(NamedTuple):
    manifest_sha256: str
    manifest_size_bytes: int
    source_entry_count: int
    config_entry_count: int
    dependency_entry_count: int
    upstream_result_count: int
    source_manifest_sha256: str
    config_manifest_sha256: str
    dependency_manifest_sha256: str


class ContextEvidenceRef(NamedTuple):
    contract_type: str
    object_key: str
    event_id: str
    global_sequence: int
    payload_sha256: str


class LegacyContextV1Observation(NamedTuple):
    key: LegacyContextV1Key
    observation_state: str
    inventory: ContextManifestInventory
    packet_evidence: ContextEvidenceRef
    unavailable_facts: tuple[ContextUnavailableFact, ...]
    observation_digest: str
    input_ordering: str
    projection_provenance: str
    projection_completeness: str
    cas_residency: str
    work_definition_admission: str


def _fail(message: str) -> NoReturn:
    raise LegacyContextV1Error(message)


def _identity(item: InvariantObject) -> ContextEvidenceRef:
    if (
        type(item) is not InvariantObject
        or type(item.contract_type) is not str
        or type(item.object_key) is not str
        or type(item.event_id) is not str
        or type(item.global_sequence) is not int
        or isinstance(item.global_sequence, bool)
        or type(item.payload_sha256) is not str
        or not _ID.fullmatch(item.contract_type)
        or not _ID.fullmatch(item.object_key)
        or not _ID.fullmatch(item.event_id)
        or item.global_sequence < 0
        or not _SHA256.fullmatch(item.payload_sha256)
    ):
        _fail("legacy context invariant object metadata is invalid")
    return ContextEvidenceRef(
        item.contract_type, item.object_key, item.event_id,
        item.global_sequence, item.payload_sha256,
    )


def _validate_key(key: LegacyContextV1Key) -> None:
    if (
        type(key) is not LegacyContextV1Key
        or type(key.company_id) is not str
        or type(key.packet_id) is not str
        or type(key.company_incarnation) is not int
        or isinstance(key.company_incarnation, bool)
        or type(key.lock_domain_generation) is not int
        or isinstance(key.lock_domain_generation, bool)
        or not _ID.fullmatch(key.company_id)
        or not _ID.fullmatch(key.packet_id)
        or not 1 <= key.company_incarnation <= 999_999_999
        or not 0 <= key.lock_domain_generation <= 999_999_999
    ):
        _fail("legacy context observation requires an exact packet key")


def _packet(projection: InvariantProjection, key: LegacyContextV1Key) -> tuple[InvariantObject, dict[str, Any]]:
    if type(projection) is not InvariantProjection or type(projection.objects) is not tuple:
        _fail("legacy context observation requires exact caller-supplied projection objects")
    selected: list[tuple[InvariantObject, dict[str, Any]]] = []
    for item in projection.objects:
        _identity(item)
        if item.contract_type != WORK_PACKET_V1:
            continue
        try:
            packet = validate_work_packet(item.payload)
        except CompanyContractError as exc:
            _fail(f"legacy context work packet is invalid: {exc}")
        if item.object_key != packet["packet_id"] or item.payload_sha256 != company_contract_sha256(packet):
            _fail("legacy context work packet object identity differs")
        if packet["packet_id"] != key.packet_id:
            continue
        if (
            packet["company_id"] != key.company_id
            or packet["company_incarnation"] != key.company_incarnation
            or packet["lock_domain_generation"] != key.lock_domain_generation
        ):
            _fail("legacy context work packet company binding differs")
        selected.append((item, packet))
    if len(selected) != 1:
        _fail("legacy context observation requires exactly one matching work packet")
    return selected[0]


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, member in pairs:
        if name in value:
            raise ValueError("duplicate JSON key")
        value[name] = member
    return value


def _manifest(raw: bytes, key: LegacyContextV1Key, packet: dict[str, Any]) -> ContextManifestInventory:
    if type(raw) is not bytes or not raw or len(raw) > MAX_CONTRACT_BYTES:
        _fail("legacy context manifest bytes are invalid")
    try:
        decoded = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_object)
        manifest = validate_work_context_manifest(decoded)
        canonical = canonical_work_context_manifest_bytes(manifest)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError, CompanyContractError) as exc:
        _fail(f"legacy context manifest bytes are not canonical: {exc}")
    if type(decoded) is not dict or canonical != raw:
        _fail("legacy context manifest bytes are not canonical")
    if (
        manifest["company_id"] != key.company_id
        or manifest["company_incarnation"] != key.company_incarnation
        or manifest["lock_domain_generation"] != key.lock_domain_generation
    ):
        _fail("legacy context manifest company binding differs")
    reference = packet["context_manifest_ref"]
    digest = hashlib.sha256(raw).hexdigest()
    if (
        reference["sha256"] != digest
        or reference["size_bytes"] != len(raw)
        or reference["availability"] != "available"
        or reference["media_type"] != "application/vnd.aoi.work-context-manifest+json;version=1"
        or packet["source_manifest_sha256"] != manifest["source_manifest_sha256"]
        or packet["config_manifest_sha256"] != manifest["config_manifest_sha256"]
        or packet["dependency_manifest_sha256"] != manifest["dependency_manifest_sha256"]
    ):
        _fail("legacy context manifest packet binding differs")
    return ContextManifestInventory(
        digest, len(raw), len(manifest["source_entries"]), len(manifest["config_entries"]),
        len(manifest["dependency_entries"]), len(manifest["upstream_result_refs"]),
        manifest["source_manifest_sha256"], manifest["config_manifest_sha256"],
        manifest["dependency_manifest_sha256"],
    )


def _digest(observation: LegacyContextV1Observation) -> str:
    payload = {
        "derivation_domain": "aoi.context.legacy-v1.manifest-inventory-observation.v1",
        "derivation_version": 1,
        "key": observation.key._asdict(),
        "inventory": observation.inventory._asdict(),
        "packet_evidence": observation.packet_evidence._asdict(),
        "unavailable_facts": [item._asdict() for item in observation.unavailable_facts],
        "labels": {
            "observation_state": observation.observation_state,
            "input_ordering": observation.input_ordering,
            "projection_provenance": observation.projection_provenance,
            "projection_completeness": observation.projection_completeness,
            "cas_residency": observation.cas_residency,
            "work_definition_admission": observation.work_definition_admission,
        },
    }
    try:
        return hashlib.sha256(canonical_company_json_bytes(payload)).hexdigest()
    except CompanyContractError as exc:
        _fail(f"legacy context observation digest is invalid: {exc}")


def observe_legacy_context_v1(
    projection: InvariantProjection,
    key: LegacyContextV1Key,
    manifest_bytes: bytes,
) -> LegacyContextV1Observation:
    """Return only declared V1 inventory metadata and fixed unavailable facts."""
    _validate_key(key)
    item, packet = _packet(projection, key)
    inventory = _manifest(manifest_bytes, key, packet)
    unavailable = tuple(ContextUnavailableFact(name, "unavailable", reason) for name, reason in _UNAVAILABLE)
    provisional = LegacyContextV1Observation(
        key, "degraded", inventory, _identity(item), unavailable, "",
        "projection_global_sequence_metadata_only", "unverified", "unverified",
        "unverified", "not_evaluated",
    )
    return provisional._replace(observation_digest=_digest(provisional))
