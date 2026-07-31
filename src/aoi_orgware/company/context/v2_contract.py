"""Reader-only bridge from canonical WorkContextManifestV1 inventory to V2.

V1 remains caller-supplied inventory.  This module proves a byte-for-byte
carrier basis, never provider transport, prompt materialization, authority,
ledger membership, a token fit, or a sealed amendment. ``manifest_id`` is a
stable caller-supplied lineage label, not immutable byte identity; exact
revision identity also includes the canonical content digest. Context lineage
uses subordinate levels D1-D3; the Chief is D0.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, NamedTuple, NoReturn

from aoi_orgware.company.contracts import (
    BLOB_REF_V1,
    DEPARTMENT_SNAPSHOT_MEDIA_TYPE,
    MAX_CONTRACT_BYTES,
    CompanyContractError,
    canonical_company_json_bytes,
    canonical_work_context_manifest_bytes,
    validate_work_context_manifest,
)


WORK_CONTEXT_MANIFEST_V2 = "work_context_manifest_v2"
MAX_ENTRIES = 512
MAX_JSON_DEPTH = 32
MAX_DELEGATION_DEPTH = 3
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_REGULAR_SECTIONS = ("source_entries", "config_entries", "dependency_entries")
_BLOB_SECTIONS = ("department_snapshot_ref", "upstream_result_refs")
_SECTIONS = _REGULAR_SECTIONS + _BLOB_SECTIONS
_SECTION_CATEGORY = {
    "source_entries": "source", "config_entries": "policy",
    "dependency_entries": "baseline", "department_snapshot_ref": "department_snapshot",
    "upstream_result_refs": "upstream_result",
}
_LAYERS = ("L0", "L1", "L2", "L3")
_LAYER_RANK = {layer: rank for rank, layer in enumerate(_LAYERS)}
_REASONS = {
    ("mandatory", "selected"): "selected_mandatory",
    ("recommended", "selected"): "selected_recommended",
    ("recommended", "omitted"): "omitted_recommended",
    ("on_demand", "selected"): "selected_on_demand",
    ("on_demand", "omitted"): "omitted_on_demand",
    ("forbidden", "forbidden"): "forbidden_by_policy",
}
_CLAIMS = {
    "selection": "declared_only", "freshness": "unavailable",
    "completeness": "unavailable", "actual_sent_bytes": "unavailable",
    "window_fit": "unavailable", "token_estimate": "unavailable",
    "ledger_authority": "unavailable", "sealed_amendment": "unavailable",
}


class WorkContextManifestV2Error(ValueError):
    """The V2 carrier declaration is malformed or cannot bind its V1 bytes."""


class CarrierAtomV2(NamedTuple):
    carrier_section: str
    carrier_path: str
    entry_type: str
    contract_type: str | None
    schema_version: int | None
    content_sha256: str
    size_bytes: int
    media_type: str | None
    availability: str | None

    def to_dict(self) -> dict[str, Any]:
        return self._asdict()


class ContextEntryV2(NamedTuple):
    entry_id: str
    category: str
    context_layer: str
    requirement: str
    state: str
    reason_code: str
    carrier: CarrierAtomV2 | None
    carrier_digest: str | None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "entry_id": self.entry_id, "category": self.category,
            "context_layer": self.context_layer, "requirement": self.requirement,
            "state": self.state, "reason_code": self.reason_code,
            "carrier_section": None, "carrier_path": None, "entry_type": None,
            "contract_type": None, "schema_version": None, "content_sha256": None,
            "size_bytes": None, "media_type": None, "availability": None,
            "carrier_digest": self.carrier_digest,
        }
        if self.carrier is not None:
            result.update(self.carrier.to_dict())
        return result


class TokenEstimateV2(NamedTuple):
    quality: str
    tokens: None
    window_limit_tokens: None
    window_fit: str

    def to_dict(self) -> dict[str, Any]:
        return self._asdict()


class V1CarrierV2(NamedTuple):
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return self._asdict()


class LineageV2(NamedTuple):
    parent_manifest_sha256: str | None
    delegation_depth: int

    def to_dict(self) -> dict[str, Any]:
        return self._asdict()


class WorkContextManifestV2(NamedTuple):
    manifest_id: str
    context_layer: str
    entries: tuple[ContextEntryV2, ...]
    effective_entry_ids: tuple[str, ...]
    v1_carrier: V1CarrierV2
    lineage: LineageV2
    claims: tuple[tuple[str, str], ...]
    token_estimate: TokenEstimateV2

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_type": WORK_CONTEXT_MANIFEST_V2, "schema_version": 2,
            "manifest_id": self.manifest_id, "context_layer": self.context_layer,
            "entries": [entry.to_dict() for entry in self.entries],
            "effective_entry_ids": list(self.effective_entry_ids),
            "v1_carrier": self.v1_carrier.to_dict(), "lineage": self.lineage.to_dict(),
            "claims": dict(self.claims), "token_estimate": self.token_estimate.to_dict(),
        }


class WorkContextManifestRevisionIdentityV2(NamedTuple):
    manifest_id: str
    content_sha256: str

    def to_dict(self) -> dict[str, str]:
        return self._asdict()


def _fail(message: str) -> NoReturn:
    raise WorkContextManifestV2Error(message)


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(fields):
        _fail(f"{label} schema is invalid")
    if any(type(key) is not str for key in value) or set(value) != fields:
        _fail(f"{label} schema is invalid")
    return value.copy()


def _text(value: Any, label: str) -> str:
    if type(value) is not str:
        _fail(f"{label} is invalid")
    return value


def _id(value: Any, label: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        _fail(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or not _SHA256.fullmatch(value):
        _fail(f"{label} is not lowercase SHA-256")
    return value


def _integer(value: Any, label: str, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        _fail(f"{label} is invalid")
    return value


def _choice(value: Any, choices: tuple[str, ...], label: str) -> str:
    result = _text(value, label)
    if result not in choices:
        _fail(f"{label} is invalid")
    return result


def _atom_digest(atom: CarrierAtomV2) -> str:
    payload = {"derivation_domain": "aoi.context.v2.v1-carrier-atom.v1", "atom": atom.to_dict()}
    try:
        return hashlib.sha256(canonical_company_json_bytes(payload)).hexdigest()
    except (CompanyContractError, TypeError, ValueError, RecursionError) as exc:
        raise WorkContextManifestV2Error("carrier atom digest is invalid") from exc


def _v1_atoms(manifest: dict[str, Any]) -> tuple[CarrierAtomV2, ...]:
    result: list[CarrierAtomV2] = []
    snapshot = manifest["department_snapshot_ref"]
    result.append(CarrierAtomV2(
        "department_snapshot_ref", "department_snapshot_ref", "blob_ref",
        snapshot["contract_type"], snapshot["schema_version"], snapshot["sha256"],
        snapshot["size_bytes"], snapshot["media_type"], snapshot["availability"],
    ))
    for section in _REGULAR_SECTIONS:
        for entry in manifest[section]:
            result.append(CarrierAtomV2(
                section, entry["path"], entry["entry_type"], None, None,
                entry["sha256"], entry["size_bytes"], None, None,
            ))
    for index, blob in enumerate(manifest["upstream_result_refs"]):
        result.append(CarrierAtomV2(
            "upstream_result_refs", f"upstream_result_refs/{index}", "blob_ref",
            blob["contract_type"], blob["schema_version"], blob["sha256"],
            blob["size_bytes"], blob["media_type"], blob["availability"],
        ))
    return tuple(result)


def _entry(raw: Any, index: int) -> ContextEntryV2:
    fields = {
        "entry_id", "category", "context_layer", "requirement", "state", "reason_code",
        "carrier_section", "carrier_path", "entry_type", "contract_type", "schema_version",
        "content_sha256", "size_bytes", "media_type", "availability", "carrier_digest",
    }
    item = _object(raw, fields, f"entries[{index}]")
    requirement = _choice(item["requirement"], ("mandatory", "recommended", "on_demand", "forbidden"), f"entries[{index}].requirement")
    state = _choice(item["state"], ("selected", "omitted", "forbidden"), f"entries[{index}].state")
    expected_reason = _REASONS.get((requirement, state))
    if expected_reason is None or _text(item["reason_code"], f"entries[{index}].reason_code") != expected_reason:
        _fail(f"entries[{index}].reason_code is invalid")
    category = _choice(
        item["category"], tuple(sorted({*_SECTION_CATEGORY.values(), "compiler"})),
        f"entries[{index}].category",
    )
    layer = _choice(item["context_layer"], _LAYERS, f"entries[{index}].context_layer")
    entry_id = _id(item["entry_id"], f"entries[{index}].entry_id")
    carrier_fields = ("carrier_section", "carrier_path", "entry_type", "contract_type", "schema_version", "content_sha256", "size_bytes", "media_type", "availability", "carrier_digest")
    if requirement == "forbidden":
        if any(item[name] is not None for name in carrier_fields):
            _fail("forbidden entries cannot carry V1 transport bindings")
        return ContextEntryV2(entry_id, category, layer, requirement, state, expected_reason, None, None)
    section = _choice(item["carrier_section"], _SECTIONS, f"entries[{index}].carrier_section")
    path = _text(item["carrier_path"], f"entries[{index}].carrier_path")
    entry_type = _text(item["entry_type"], f"entries[{index}].entry_type")
    contract_type = item["contract_type"]
    schema_version = item["schema_version"]
    digest = _digest(item["content_sha256"], f"entries[{index}].content_sha256")
    size = _integer(item["size_bytes"], f"entries[{index}].size_bytes", MAX_CONTRACT_BYTES * 1024)
    media = item["media_type"]
    availability = item["availability"]
    if section in _BLOB_SECTIONS:
        expected_media = (
            DEPARTMENT_SNAPSHOT_MEDIA_TYPE
            if section == "department_snapshot_ref" else None
        )
        if (
            type(contract_type) is not str
            or type(schema_version) is not int
            or type(media) is not str
            or type(availability) is not str
        ):
            _fail(f"entries[{index}] blob carrier is invalid")
        if (
            entry_type != "blob_ref" or contract_type != BLOB_REF_V1 or schema_version != 1
            or availability != "available"
            or (expected_media is not None and media != expected_media)
        ):
            _fail(f"entries[{index}] blob carrier is invalid")
        if section == "department_snapshot_ref" and (
            path != "department_snapshot_ref" or category != "department_snapshot"
            or layer != "L1" or requirement != "mandatory" or state != "selected"
        ):
            _fail(f"entries[{index}] department snapshot carrier is invalid")
    elif (
        contract_type is not None or schema_version is not None or media is not None
        or availability is not None
    ):
        _fail(f"entries[{index}] regular carrier has blob-only fields")
    atom = CarrierAtomV2(
        section, path, entry_type, contract_type, schema_version, digest, size, media,
        availability,
    )
    carrier_digest = _digest(item["carrier_digest"], f"entries[{index}].carrier_digest")
    if carrier_digest != _atom_digest(atom):
        _fail(f"entries[{index}].carrier_digest differs")
    return ContextEntryV2(entry_id, category, layer, requirement, state, expected_reason, atom, carrier_digest)


def _manifest_instance_to_dict(value: WorkContextManifestV2) -> dict[str, Any]:
    """Convert only an exact, recursively typed immutable value object."""
    if (
        type(value.entries) is not tuple
        or any(type(entry) is not ContextEntryV2 for entry in value.entries)
        or any(
            entry.carrier is not None and type(entry.carrier) is not CarrierAtomV2
            for entry in value.entries
        )
        or type(value.effective_entry_ids) is not tuple
        or type(value.v1_carrier) is not V1CarrierV2
        or type(value.lineage) is not LineageV2
        or type(value.claims) is not tuple
        or any(
            type(pair) is not tuple
            or len(pair) != 2
            or type(pair[0]) is not str
            or type(pair[1]) is not str
            for pair in value.claims
        )
        or type(value.token_estimate) is not TokenEstimateV2
    ):
        _fail("WorkContextManifestV2 value object is invalid")
    return value.to_dict()


def _validate(value: Any) -> WorkContextManifestV2:
    if type(value) is WorkContextManifestV2:
        value = _manifest_instance_to_dict(value)
    fields = {"document_type", "schema_version", "manifest_id", "context_layer", "entries", "effective_entry_ids", "v1_carrier", "lineage", "claims", "token_estimate"}
    item = _object(value, fields, "WorkContextManifestV2")
    if _text(item["document_type"], "document_type") != WORK_CONTEXT_MANIFEST_V2 or _integer(item["schema_version"], "schema_version", 2) != 2:
        _fail("WorkContextManifestV2 header is invalid")
    if type(item["entries"]) is not list or len(item["entries"]) > MAX_ENTRIES:
        _fail("entries are invalid")
    entries = tuple(sorted((_entry(raw, index) for index, raw in enumerate(item["entries"])), key=lambda entry: entry.entry_id))
    if not entries:
        _fail("entries are invalid")
    if len({entry.entry_id for entry in entries}) != len(entries):
        _fail("entries contain duplicate entry ids")
    if type(item["effective_entry_ids"]) is not list or len(item["effective_entry_ids"]) > MAX_ENTRIES:
        _fail("effective_entry_ids are invalid")
    effective = tuple(sorted(_id(member, "effective_entry_ids member") for member in item["effective_entry_ids"]))
    if len(set(effective)) != len(effective) or effective != tuple(entry.entry_id for entry in entries if entry.state == "selected"):
        _fail("effective_entry_ids differ from selected entries")
    carrier = _object(item["v1_carrier"], {"sha256", "size_bytes"}, "v1_carrier")
    lineage = _object(item["lineage"], {"parent_manifest_sha256", "delegation_depth"}, "lineage")
    parent = lineage["parent_manifest_sha256"]
    if parent is not None:
        parent = _digest(parent, "lineage.parent_manifest_sha256")
    depth = _integer(lineage["delegation_depth"], "lineage.delegation_depth", MAX_DELEGATION_DEPTH)
    if depth < 1 or (depth == 1) != (parent is None):
        _fail("lineage parent and delegation depth differ")
    claims = _object(item["claims"], set(_CLAIMS), "claims")
    if (
        any(type(claims[name]) is not str for name in _CLAIMS)
        or claims != _CLAIMS
    ):
        _fail("claims must retain the fixed unavailable boundary")
    estimate = _object(item["token_estimate"], {"quality", "tokens", "window_limit_tokens", "window_fit"}, "token_estimate")
    if (
        type(estimate["quality"]) is not str
        or estimate["tokens"] is not None
        or estimate["window_limit_tokens"] is not None
        or type(estimate["window_fit"]) is not str
        or estimate != {
            "quality": "unknown", "tokens": None,
            "window_limit_tokens": None, "window_fit": "unknown",
        }
    ):
        _fail("token estimate is unavailable, not zero or fit")
    context_layer = _choice(item["context_layer"], _LAYERS, "context_layer")
    highest_entry_layer = max(entries, key=lambda entry: _LAYER_RANK[entry.context_layer]).context_layer
    if context_layer != highest_entry_layer:
        _fail("context_layer must equal the highest declared entry layer")
    return WorkContextManifestV2(
        _id(item["manifest_id"], "manifest_id"), context_layer, entries,
        effective, V1CarrierV2(_digest(carrier["sha256"], "v1_carrier.sha256"), _integer(carrier["size_bytes"], "v1_carrier.size_bytes", MAX_CONTRACT_BYTES)),
        LineageV2(parent, depth), tuple(sorted(_CLAIMS.items())), TokenEstimateV2("unknown", None, None, "unknown"),
    )


def validate_work_context_manifest_v2_structure(value: Any) -> WorkContextManifestV2:
    """Decode V2 structure only; this makes no V1 carrier or semantic claim."""
    try:
        result = _validate(value)
        canonical_company_json_bytes(result.to_dict(), max_bytes=MAX_CONTRACT_BYTES)
        return result
    except WorkContextManifestV2Error:
        raise
    except (
        AttributeError, CompanyContractError, TypeError, ValueError,
        RecursionError, OverflowError,
    ) as exc:
        raise WorkContextManifestV2Error("WorkContextManifestV2 is invalid") from exc


def canonical_work_context_manifest_v2_structural_bytes(value: Any) -> bytes:
    """Return canonical structural bytes only; this is not a semantic basis."""
    try:
        return canonical_company_json_bytes(
            validate_work_context_manifest_v2_structure(value).to_dict(),
            max_bytes=MAX_CONTRACT_BYTES,
        )
    except (CompanyContractError, TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise WorkContextManifestV2Error("V2 structural bytes are invalid") from exc


def canonical_work_context_manifest_v2_bytes(value: Any, v1_manifest_bytes: bytes) -> bytes:
    """Return canonical V2 bytes only after exact V1 carrier proof."""
    try:
        return canonical_company_json_bytes(
            validate_work_context_manifest_v2(value, v1_manifest_bytes).to_dict(),
            max_bytes=MAX_CONTRACT_BYTES,
        )
    except (CompanyContractError, TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise WorkContextManifestV2Error("V2 canonical bytes are invalid") from exc


def work_context_manifest_v2_sha256(value: Any, v1_manifest_bytes: bytes) -> str:
    """Return a V2 digest only after exact V1 carrier proof."""
    return hashlib.sha256(
        canonical_work_context_manifest_v2_bytes(value, v1_manifest_bytes)
    ).hexdigest()


def work_context_manifest_v2_revision_identity(
    value: Any, v1_manifest_bytes: bytes,
) -> WorkContextManifestRevisionIdentityV2:
    """Return the only safe immutable identity for one manifest revision."""
    manifest = validate_work_context_manifest_v2(value, v1_manifest_bytes)
    return WorkContextManifestRevisionIdentityV2(
        manifest.manifest_id,
        work_context_manifest_v2_sha256(manifest, v1_manifest_bytes),
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, member in pairs:
        if key in result:
            _fail("duplicate JSON key")
        result[key] = member
    return result


def _json_depth(raw: bytes) -> None:
    depth = 0
    quote = False
    escape = False
    for byte in raw:
        if quote:
            if escape:
                escape = False
            elif byte == 92:
                escape = True
            elif byte == 34:
                quote = False
        elif byte == 34:
            quote = True
        elif byte in (91, 123):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                _fail("JSON nesting is too deep")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                _fail("JSON nesting is invalid")
    if quote or depth != 0:
        _fail("JSON nesting is invalid")


def _canonical_v1(raw: bytes) -> tuple[bytes, dict[str, Any]]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_CONTRACT_BYTES:
        _fail("V1 carrier bytes are invalid")
    _json_depth(raw)
    try:
        decoded = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs, parse_constant=lambda _: _fail("non-finite JSON"))
        manifest = validate_work_context_manifest(decoded)
        canonical = canonical_work_context_manifest_bytes(manifest)
    except WorkContextManifestV2Error:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, CompanyContractError, TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise WorkContextManifestV2Error("V1 carrier bytes are invalid") from exc
    if type(decoded) is not dict or canonical != raw:
        _fail("V1 carrier bytes are not canonical")
    return canonical, manifest


def validate_work_context_manifest_v2(value: Any, v1_manifest_bytes: bytes) -> WorkContextManifestV2:
    """Prove an exact V1 inventory-to-V2 non-forbidden carrier bijection."""
    v2 = validate_work_context_manifest_v2_structure(value)
    raw, manifest = _canonical_v1(v1_manifest_bytes)
    if v2.v1_carrier != V1CarrierV2(hashlib.sha256(raw).hexdigest(), len(raw)):
        _fail("V1 carrier digest or size differs from actual bytes")
    atoms = _v1_atoms(manifest)
    bound = tuple(entry for entry in v2.entries if entry.requirement != "forbidden")
    if len(bound) != len(atoms):
        _fail("V1 carrier and non-forbidden V2 entries are not a bijection")
    atom_by_digest = {_atom_digest(atom): atom for atom in atoms}
    if len(atom_by_digest) != len(atoms):
        _fail("V1 carrier contains ambiguous atoms")
    seen: set[str] = set()
    for entry in bound:
        if entry.carrier is None or entry.carrier_digest is None:
            _fail("non-forbidden entry lacks carrier binding")
        if entry.category != _SECTION_CATEGORY[entry.carrier.carrier_section]:
            _fail("entry category differs from carrier section")
        expected = atom_by_digest.get(entry.carrier_digest)
        if expected != entry.carrier or entry.carrier_digest in seen:
            _fail("V2 entry is unrelated to or duplicates a V1 carrier atom")
        seen.add(entry.carrier_digest)
    if seen != set(atom_by_digest):
        _fail("V1 carrier has hidden or unbound atoms")
    return v2


def validate_root_work_context_manifest_v2(
    value: Any, v1_manifest_bytes: bytes,
) -> WorkContextManifestV2:
    """Validate the D1/no-parent declaration required by a root compiler."""
    manifest = validate_work_context_manifest_v2(value, v1_manifest_bytes)
    if (
        manifest.lineage.delegation_depth != 1
        or manifest.lineage.parent_manifest_sha256 is not None
    ):
        _fail("root context declaration must be D1 with no parent")
    return manifest


def parse_work_context_manifest_v2_structural_bytes(raw: bytes) -> WorkContextManifestV2:
    """Parse exact structural V2 bytes; it intentionally makes no semantic claim."""
    if type(raw) is not bytes or not raw or len(raw) > MAX_CONTRACT_BYTES:
        _fail("V2 manifest bytes are invalid")
    _json_depth(raw)
    try:
        decoded = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs, parse_constant=lambda _: _fail("non-finite JSON"))
    except WorkContextManifestV2Error:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise WorkContextManifestV2Error("V2 manifest bytes are invalid") from exc
    result = validate_work_context_manifest_v2_structure(decoded)
    if canonical_work_context_manifest_v2_structural_bytes(result) != raw:
        _fail("V2 manifest bytes are not canonical")
    return result


def validate_child_work_context_manifest_v2_declaration(
    child: Any, parent: Any, child_v1_manifest_bytes: bytes, parent_v1_manifest_bytes: bytes,
) -> WorkContextManifestV2:
    """Validate one declaration-only child edge.

    This proves neither the parent's compiled/materialized entry set nor ledger
    currentness. ``manifest_id`` may remain stable across the lineage; callers
    must use ``work_context_manifest_v2_revision_identity`` when they need an
    immutable revision key. Compiler/admission code must separately bind an
    immutable parent compile-result witness before treating a child as an actual
    materialized subset.
    """
    child_view = validate_work_context_manifest_v2(child, child_v1_manifest_bytes)
    parent_view = validate_work_context_manifest_v2(parent, parent_v1_manifest_bytes)
    if child_v1_manifest_bytes != parent_v1_manifest_bytes or child_view.v1_carrier != parent_view.v1_carrier:
        _fail("child must retain exact parent V1 carrier bytes")
    if child_view.context_layer != parent_view.context_layer:
        _fail("child cannot change context layer")
    if child_view.lineage.parent_manifest_sha256 != work_context_manifest_v2_sha256(
        parent_view, parent_v1_manifest_bytes,
    ):
        _fail("child parent digest differs")
    if child_view.lineage.delegation_depth != parent_view.lineage.delegation_depth + 1:
        _fail("child delegation depth differs")
    parent_by_id = {entry.entry_id: entry for entry in parent_view.entries}
    if set(parent_by_id) != {entry.entry_id for entry in child_view.entries}:
        _fail("child cannot add or delete parent entries")
    for child_entry in child_view.entries:
        parent_entry = parent_by_id[child_entry.entry_id]
        if child_entry == parent_entry:
            continue
        if not (
            parent_entry.requirement in {"recommended", "on_demand"}
            and parent_entry.state == "selected" and child_entry.state == "omitted"
            and child_entry._replace(state="selected", reason_code=parent_entry.reason_code) == parent_entry
        ):
            _fail("child entry differs from exact parent carrier basis")
    return child_view


def validate_child_work_context_manifest_v2(
    child: Any, parent: Any, child_v1_manifest_bytes: bytes, parent_v1_manifest_bytes: bytes,
) -> WorkContextManifestV2:
    """Compatibility name for declaration-only child validation.

    This wrapper intentionally provides no compiled/materialized-subset claim.
    New callers should use ``validate_child_work_context_manifest_v2_declaration``
    so the evidence boundary remains visible at the call site.
    """
    return validate_child_work_context_manifest_v2_declaration(
        child, parent, child_v1_manifest_bytes, parent_v1_manifest_bytes,
    )
