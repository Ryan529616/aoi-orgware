"""Deterministic, reader-only root V2 context payload compiler.

The compiler binds caller-supplied declarations and tokenizer observations.  It
does not materialize provider requests, authority, seals, or currentness.
Positive child compilation remains unavailable until a durable reducer-verified
parent compilation proof exists.
"""
from __future__ import annotations

import base64
import hashlib
import json
import unicodedata
from typing import Any, Callable, NamedTuple, NoReturn

from aoi_orgware.company.context.v2_contract import (
    ContextEntryV2, WorkContextManifestV2, WorkContextManifestV2Error,
    validate_child_work_context_manifest_v2, validate_work_context_manifest_v2,
    validate_root_work_context_manifest_v2,
    validate_work_context_manifest_v2_structure, work_context_manifest_v2_sha256,
)
from aoi_orgware.company.contracts import (
    MAX_CONTRACT_BYTES, CompanyContractError, canonical_company_json_bytes,
    canonical_work_context_manifest_bytes, validate_work_context_manifest,
)
from aoi_orgware.company.scheduling.qos import (
    WorkQoSIntentV1Error, validate_work_qos_intent_v1,
)


class ContextCompilerError(ValueError):
    """A caller-supplied compiler input or tokenizer observation is invalid."""


class NeedsContext(ContextCompilerError):
    """The declared mandatory/selected context cannot satisfy its boundary."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class RootContextEnvelope(NamedTuple):
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    repository_id: str
    repository_sha256: str
    cwd: str


class ContextArtifact(NamedTuple):
    entry_id: str
    content: bytes


class TokenizerObservation(NamedTuple):
    tokenizer_id: str
    model_id: str
    quality: str
    tokens: int | None


class TokenObservation(NamedTuple):
    payload_sha256: str
    payload_size_bytes: int
    observation: TokenizerObservation


class EntryOutcome(NamedTuple):
    entry_id: str
    declared_state: str
    final_state: str
    omission_code: str | None


class ContextCompileResult(NamedTuple):
    payload_sha256: str
    compile_input_sha256: str
    selected_content_size_bytes: int
    compiled_payload_size_bytes: int
    provider_sent_size_bytes: None
    context_v2_semantic_sha256: str
    v1_carrier_sha256: str
    emitted_entry_ids: tuple[str, ...]
    token_observations: tuple[TokenObservation, ...]
    entry_outcomes: tuple[EntryOutcome, ...]
    compatibility: str
    provider_sent: None
    provider_state: str
    evidence_state: str
    service_instance_id: None

    def to_dict(self) -> dict[str, Any]:
        return _compile_result_dict(self)


class ContextCompileWitness(NamedTuple):
    mode: str
    input_sha256: str
    result_sha256: str


Tokenizer = Callable[[bytes], TokenizerObservation]


def _fail(message: str) -> NoReturn:
    raise ContextCompilerError(message)


def _canonical(value: Any, label: str) -> bytes:
    try:
        return canonical_company_json_bytes(value, max_bytes=MAX_CONTRACT_BYTES)
    except (CompanyContractError, TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise ContextCompilerError(f"{label} is invalid") from exc


def _sha256(value: Any) -> bool:
    return (type(value) is str and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


def _bounded_integer(value: Any, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _compile_result_dict(value: Any) -> dict[str, Any]:
    if type(value) is not ContextCompileResult:
        _fail("compile result is invalid")
    if (
        not _sha256(value.payload_sha256)
        or not _sha256(value.compile_input_sha256)
        or not _sha256(value.context_v2_semantic_sha256)
        or not _sha256(value.v1_carrier_sha256)
        or not _bounded_integer(
            value.selected_content_size_bytes, MAX_CONTRACT_BYTES,
        )
        or not _bounded_integer(
            value.compiled_payload_size_bytes, MAX_CONTRACT_BYTES,
        )
        or value.compiled_payload_size_bytes == 0
        or value.provider_sent_size_bytes is not None
        or value.provider_sent is not None
        or type(value.provider_state) is not str
        or value.provider_state != "unavailable"
        or type(value.evidence_state) is not str
        or value.evidence_state != "caller_supplied_unverified"
        or value.service_instance_id is not None
        or type(value.compatibility) is not str
        or value.compatibility not in {
            "selected_set_equals_full_v1_carrier_inventory",
            "selected_set_not_representable_as_reduced_v1_carrier",
        }
    ):
        _fail("compile result fields are invalid")
    emitted = value.emitted_entry_ids
    if (
        type(emitted) is not tuple
        or len(emitted) > 512
        or any(type(item) is not str or not item for item in emitted)
        or len(set(emitted)) != len(emitted)
        or emitted != tuple(sorted(emitted))
    ):
        _fail("compile result emitted entries are invalid")
    observations = value.token_observations
    if (
        type(observations) is not tuple
        or not 1 <= len(observations) <= 514
    ):
        _fail("compile result token observations are invalid")
    observation_values: list[dict[str, Any]] = []
    observation_identity: tuple[str, str, str] | None = None
    seen_payloads: set[tuple[str, int]] = set()
    for observation_item in observations:
        if type(observation_item) is not TokenObservation:
            _fail("compile result token observation is invalid")
        if (
            not _sha256(observation_item.payload_sha256)
            or not _bounded_integer(
                observation_item.payload_size_bytes, MAX_CONTRACT_BYTES,
            )
            or observation_item.payload_size_bytes == 0
            or type(observation_item.observation) is not TokenizerObservation
        ):
            _fail("compile result token observation is invalid")
        observation = observation_item.observation
        if (
            type(observation.tokenizer_id) is not str
            or not observation.tokenizer_id
            or type(observation.model_id) is not str
            or not observation.model_id
            or type(observation.quality) is not str
            or observation.quality
            not in {"exact", "provider_estimate", "unknown"}
            or (
                observation.quality == "unknown"
                and observation.tokens is not None
            )
            or (
                observation.quality != "unknown"
                and not _bounded_integer(observation.tokens, 1_000_000_000)
            )
        ):
            _fail("compile result tokenizer observation is invalid")
        identity = (
            observation.tokenizer_id,
            observation.model_id,
            observation.quality,
        )
        if observation_identity is not None and identity != observation_identity:
            _fail("compile result tokenizer metadata differs")
        observation_identity = identity
        payload_identity = (
            observation_item.payload_sha256,
            observation_item.payload_size_bytes,
        )
        if payload_identity in seen_payloads:
            _fail("compile result token observations are duplicated")
        seen_payloads.add(payload_identity)
        observation_values.append({
            "payload_sha256": observation_item.payload_sha256,
            "payload_size_bytes": observation_item.payload_size_bytes,
            "observation": {
                "tokenizer_id": observation.tokenizer_id,
                "model_id": observation.model_id,
                "quality": observation.quality,
                "tokens": observation.tokens,
            },
        })
    outcomes = value.entry_outcomes
    if type(outcomes) is not tuple or not 1 <= len(outcomes) <= 512:
        _fail("compile result entry outcomes are invalid")
    outcome_values: list[dict[str, Any]] = []
    outcome_ids: list[str] = []
    selected_ids: list[str] = []
    for outcome_item in outcomes:
        if type(outcome_item) is not EntryOutcome:
            _fail("compile result entry outcome is invalid")
        if (
            type(outcome_item.entry_id) is not str
            or not outcome_item.entry_id
            or type(outcome_item.declared_state) is not str
            or outcome_item.declared_state
            not in {"selected", "omitted", "forbidden"}
            or type(outcome_item.final_state) is not str
            or outcome_item.final_state
            not in {"selected", "omitted", "forbidden"}
            or (
                outcome_item.omission_code is not None
                and type(outcome_item.omission_code) is not str
            )
        ):
            _fail("compile result entry outcome is invalid")
        if outcome_item.final_state == "selected":
            valid_relation = (
                outcome_item.declared_state == "selected"
                and outcome_item.omission_code is None
            )
            selected_ids.append(outcome_item.entry_id)
        elif outcome_item.final_state == "forbidden":
            valid_relation = (
                outcome_item.declared_state == "forbidden"
                and outcome_item.omission_code == "forbidden"
            )
        elif outcome_item.declared_state == "omitted":
            valid_relation = (
                outcome_item.omission_code == "declared_omission"
            )
        else:
            valid_relation = (
                outcome_item.declared_state == "selected"
                and outcome_item.omission_code
                in {
                    "not_requested",
                    "selected_artifact_missing",
                    "payload_too_large",
                    "budget",
                }
            )
        if not valid_relation:
            _fail("compile result entry outcome relation is invalid")
        outcome_ids.append(outcome_item.entry_id)
        outcome_values.append({
            "entry_id": outcome_item.entry_id,
            "declared_state": outcome_item.declared_state,
            "final_state": outcome_item.final_state,
            "omission_code": outcome_item.omission_code,
        })
    if (
        len(set(outcome_ids)) != len(outcome_ids)
        or outcome_ids != sorted(outcome_ids)
        or tuple(selected_ids) != emitted
    ):
        _fail("compile result entry outcome identities differ")
    return {
        "payload_sha256": value.payload_sha256,
        "compile_input_sha256": value.compile_input_sha256,
        "selected_content_size_bytes": value.selected_content_size_bytes,
        "compiled_payload_size_bytes": value.compiled_payload_size_bytes,
        "provider_sent_size_bytes": value.provider_sent_size_bytes,
        "context_v2_semantic_sha256": value.context_v2_semantic_sha256,
        "v1_carrier_sha256": value.v1_carrier_sha256,
        "emitted_entry_ids": list(emitted),
        "token_observations": observation_values,
        "entry_outcomes": outcome_values,
        "compatibility": value.compatibility,
        "provider_sent": value.provider_sent,
        "provider_state": value.provider_state,
        "evidence_state": value.evidence_state,
        "service_instance_id": value.service_instance_id,
    }


def _result_sha256(result: Any) -> str:
    return hashlib.sha256(
        _canonical(_compile_result_dict(result), "compile result")
    ).hexdigest()


def _validated_witness(value: Any) -> ContextCompileWitness:
    if (
        type(value) is not ContextCompileWitness
        or type(value.mode) is not str
        or value.mode != "root"
        or not _sha256(value.input_sha256)
        or not _sha256(value.result_sha256)
    ):
        _fail("compilation witness is invalid")
    return value


def _entry_key(value: dict[str, Any]) -> tuple[str, str, str, str, int]:
    return (unicodedata.normalize("NFC", value["path"]).casefold(), value["path"],
            value["entry_type"], value["sha256"], value["size_bytes"])


def _v1_from_root(envelope: Any, v2: WorkContextManifestV2) -> bytes:
    if type(envelope) is not RootContextEnvelope:
        _fail("root envelope is invalid")
    sections: dict[str, list[dict[str, Any]]] = {
        name: [] for name in ("source_entries", "config_entries", "dependency_entries")
    }
    snapshot: dict[str, Any] | None = None
    upstream: list[dict[str, Any]] = []
    for entry in v2.entries:
        if entry.requirement == "forbidden":
            continue
        atom = entry.carrier
        if atom is None:
            _fail("V2 carrier is invalid")
        if atom.carrier_section in sections:
            sections[atom.carrier_section].append({"path": atom.carrier_path,
                "entry_type": atom.entry_type, "sha256": atom.content_sha256,
                "size_bytes": atom.size_bytes})
        elif atom.carrier_section == "department_snapshot_ref":
            snapshot = {"contract_type": atom.contract_type, "schema_version": atom.schema_version,
                "sha256": atom.content_sha256, "size_bytes": atom.size_bytes,
                "media_type": atom.media_type, "availability": atom.availability}
        else:
            upstream.append({"contract_type": atom.contract_type, "schema_version": atom.schema_version,
                "sha256": atom.content_sha256, "size_bytes": atom.size_bytes,
                "media_type": atom.media_type, "availability": atom.availability})
    if snapshot is None:
        _fail("V2 lacks a department snapshot")
    for values in sections.values():
        values.sort(key=_entry_key)
    upstream.sort(key=lambda value: (value["sha256"], value["size_bytes"], value["media_type"]))
    manifest = {
        "document_type": "work_context_manifest_v1", "schema_version": 1,
        "company_id": envelope.company_id, "company_incarnation": envelope.company_incarnation,
        "lock_domain_generation": envelope.lock_domain_generation,
        "repository_id": envelope.repository_id, "repository_sha256": envelope.repository_sha256,
        "cwd": envelope.cwd, "department_snapshot_ref": snapshot, **sections,
        "source_manifest_sha256": hashlib.sha256(_canonical(sections["source_entries"], "source inventory")).hexdigest(),
        "config_manifest_sha256": hashlib.sha256(_canonical(sections["config_entries"], "config inventory")).hexdigest(),
        "dependency_manifest_sha256": hashlib.sha256(_canonical(sections["dependency_entries"], "dependency inventory")).hexdigest(),
        "upstream_result_refs": upstream,
    }
    try:
        return canonical_work_context_manifest_bytes(manifest)
    except (CompanyContractError, TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise ContextCompilerError("root V1 inventory is invalid") from exc


def _observe(tokenizer: Tokenizer, payload: bytes) -> TokenObservation:
    try:
        value = tokenizer(payload)
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:
        raise ContextCompilerError("tokenizer failed") from exc
    if (type(value) is not TokenizerObservation or type(value.tokenizer_id) is not str
            or not value.tokenizer_id or type(value.model_id) is not str or not value.model_id):
        _fail("tokenizer observation is invalid")
    if type(value.quality) is not str or value.quality not in {"exact", "provider_estimate", "unknown"}:
        _fail("tokenizer observation quality is invalid")
    if value.quality == "unknown":
        if value.tokens is not None:
            _fail("unknown tokenizer observation requires null tokens")
    elif type(value.tokens) is not int or not 0 <= value.tokens <= 1_000_000_000:
        _fail("tokenizer observation tokens are invalid")
    return TokenObservation(hashlib.sha256(payload).hexdigest(), len(payload), value)


def _payload(v2_digest: str, v1_digest: str, selected: list[ContextEntryV2], artifacts: dict[str, bytes]) -> bytes:
    return _canonical({"derivation_domain": "aoi.context.v2.selected-content-payload.v1",
        "context_v2_semantic_sha256": v2_digest, "v1_carrier_sha256": v1_digest,
        "entries": [{"entry_id": entry.entry_id,
            "content_base64": base64.b64encode(artifacts[entry.entry_id]).decode("ascii")}
            for entry in selected]}, "compiled payload")


def _requested(value: Any, entries: tuple[ContextEntryV2, ...]) -> tuple[str, ...]:
    if type(value) not in (tuple, list) or any(type(item) is not str for item in value):
        _fail("requested on-demand ids are invalid")
    result = tuple(sorted(value))
    if len(set(result)) != len(result):
        _fail("requested on-demand ids are not unique")
    valid = {entry.entry_id for entry in entries if entry.requirement == "on_demand"}
    if not set(result) <= valid:
        _fail("requested on-demand id is invalid")
    return result


def _candidate(entry: ContextEntryV2, requested: tuple[str, ...]) -> bool:
    return (entry.requirement != "forbidden" and entry.state == "selected"
            and (entry.requirement != "on_demand" or entry.entry_id in requested))


def _artifact_map(entries: tuple[ContextEntryV2, ...], requested: tuple[str, ...], artifacts: Any) -> dict[str, bytes]:
    if type(artifacts) not in (tuple, list):
        _fail("artifacts are invalid")
    candidates = {entry.entry_id: entry for entry in entries if _candidate(entry, requested)}
    result: dict[str, bytes] = {}
    for artifact in artifacts:
        if type(artifact) is not ContextArtifact:
            _fail("artifact is invalid")
        entry_id, content = artifact
        if type(entry_id) is not str or type(content) is not bytes or entry_id in result or entry_id not in candidates:
            _fail("artifact is invalid")
        atom = candidates[entry_id].carrier
        if atom is None or len(content) != atom.size_bytes or hashlib.sha256(content).hexdigest() != atom.content_sha256:
            _fail("artifact digest or size differs")
        result[entry_id] = content
    return result


def _validate_bindings(v2: WorkContextManifestV2, v1_bytes: bytes, qos_value: Any, envelope: RootContextEnvelope | None) -> tuple[Any, str, str]:
    try:
        qos = validate_work_qos_intent_v1(qos_value)
        v1 = validate_work_context_manifest(json.loads(v1_bytes.decode("utf-8", "strict")))
    except (WorkQoSIntentV1Error, CompanyContractError, TypeError, ValueError, UnicodeError, RecursionError, OverflowError) as exc:
        raise ContextCompilerError("context declaration or QoS is invalid") from exc
    v1_digest = hashlib.sha256(v1_bytes).hexdigest()
    try:
        v2_digest = work_context_manifest_v2_sha256(v2, v1_bytes)
    except (WorkContextManifestV2Error, CompanyContractError, TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise ContextCompilerError("context declaration is invalid") from exc
    if (qos.context_binding.context_v2_semantic_sha256 != v2_digest
            or qos.context_binding.v1_carrier_sha256 != v1_digest
            or qos.context_binding.v1_carrier_size_bytes != len(v1_bytes)):
        _fail("QoS context binding differs")
    actual = (v1["company_id"], v1["company_incarnation"], v1["lock_domain_generation"])
    if qos.intent_scope[:3] != actual:
        _fail("QoS intent scope differs from V1 carrier")
    if envelope is not None and actual != envelope[:3]:
        _fail("root envelope differs from V1 carrier")
    return qos, v2_digest, v1_digest


def _compile(v2_value: Any, v1_bytes: bytes, qos_value: Any, artifacts_value: Any,
             requested_value: Any, tokenizer: Tokenizer, *, mode: str,
             envelope: RootContextEnvelope | None = None,
             root: bool = False) -> tuple[ContextCompileResult, ContextCompileWitness]:
    try:
        v2 = (
            validate_root_work_context_manifest_v2(v2_value, v1_bytes)
            if root
            else validate_work_context_manifest_v2(v2_value, v1_bytes)
        )
    except WorkContextManifestV2Error as exc:
        raise ContextCompilerError("V2 declaration is invalid") from exc
    requested = _requested(requested_value, v2.entries)
    qos, v2_digest, v1_digest = _validate_bindings(v2, v1_bytes, qos_value, envelope)
    artifacts = _artifact_map(v2.entries, requested, artifacts_value)
    input_payload = {"mode": mode, "v2": v2.to_dict(), "v1_sha256": v1_digest,
        "v1_size": len(v1_bytes), "qos": qos.to_dict(),
        "artifacts": [[key, hashlib.sha256(value).hexdigest(), len(value)]
                      for key, value in sorted(artifacts.items())],
        "requested": list(requested)}
    input_sha256 = hashlib.sha256(_canonical(input_payload, "compile input")).hexdigest()
    budgets = dict(qos.budgets)
    available_input = budgets["input"].budget - budgets["input"].reserve
    available_context = budgets["context"].budget - budgets["context"].reserve
    if available_input < 0 or available_context < 0:
        _fail("available budget is invalid")
    cap = min(available_input, available_context)
    selected: list[ContextEntryV2] = []
    outcomes: list[EntryOutcome] = []
    observations: list[TokenObservation] = []
    memo: dict[bytes, TokenObservation] = {}
    metadata: tuple[str, str, str] | None = None

    def observe(payload: bytes) -> TokenObservation:
        nonlocal metadata
        cached = memo.get(payload)
        if cached is not None:
            return cached
        value = _observe(tokenizer, payload)
        identity = (value.observation.tokenizer_id, value.observation.model_id, value.observation.quality)
        if metadata is not None and identity != metadata:
            _fail("tokenizer observation metadata drift")
        metadata = identity
        memo[payload] = value
        observations.append(value)
        return value

    for entry in v2.entries:
        optional = entry.requirement in {"recommended", "on_demand"}
        if entry.requirement == "forbidden":
            outcomes.append(EntryOutcome(entry.entry_id, entry.state, "forbidden", "forbidden"))
            continue
        if entry.state == "omitted":
            outcomes.append(EntryOutcome(entry.entry_id, entry.state, "omitted", "declared_omission"))
            continue
        if entry.requirement == "on_demand" and entry.entry_id not in requested:
            outcomes.append(EntryOutcome(entry.entry_id, entry.state, "omitted", "not_requested"))
            continue
        if entry.category == "upstream_result":
            raise NeedsContext("sealed_amendment_unavailable")
        if entry.entry_id not in artifacts:
            if optional:
                outcomes.append(EntryOutcome(entry.entry_id, entry.state, "omitted", "selected_artifact_missing"))
                continue
            raise NeedsContext("mandatory_selected_artifact_missing")
        try:
            trial = _payload(v2_digest, v1_digest, selected + [entry], artifacts)
        except ContextCompilerError as exc:
            if optional:
                outcomes.append(EntryOutcome(entry.entry_id, entry.state, "omitted", "payload_too_large"))
                continue
            raise NeedsContext("mandatory_context_payload_overflow") from exc
        observation = observe(trial)
        if observation.observation.tokens is None or observation.observation.tokens > cap:
            if optional:
                outcomes.append(EntryOutcome(entry.entry_id, entry.state, "omitted", "budget"))
                continue
            raise NeedsContext("mandatory_context_over_budget")
        selected.append(entry)
        outcomes.append(EntryOutcome(entry.entry_id, entry.state, "selected", None))
    try:
        final_payload = _payload(v2_digest, v1_digest, selected, artifacts)
    except ContextCompilerError as exc:
        raise NeedsContext("selected_context_payload_overflow") from exc
    final_observation = observe(final_payload)
    if final_observation.observation.tokens is None or final_observation.observation.tokens > cap:
        raise NeedsContext("selected_context_over_budget")
    l0 = [entry for entry in selected if entry.context_layer == "L0"]
    if l0:
        try:
            l0_observation = observe(_payload(v2_digest, v1_digest, l0, artifacts))
        except ContextCompilerError as exc:
            raise NeedsContext("l0_payload_overflow") from exc
        if l0_observation.observation.quality != "exact" or l0_observation.observation.tokens is None or l0_observation.observation.tokens * 100 > available_input * 15:
            raise NeedsContext("l0_exact_gate_unmet")
    emitted = tuple(entry.entry_id for entry in selected)
    result = ContextCompileResult(
        hashlib.sha256(final_payload).hexdigest(), input_sha256,
        sum(len(artifacts[entry.entry_id]) for entry in selected), len(final_payload), None,
        v2_digest, v1_digest, emitted, tuple(observations), tuple(outcomes),
        "selected_set_equals_full_v1_carrier_inventory" if set(emitted) == {entry.entry_id for entry in v2.entries if entry.requirement != "forbidden"} else "selected_set_not_representable_as_reduced_v1_carrier",
        None, "unavailable", "caller_supplied_unverified", None,
    )
    witness = ContextCompileWitness(mode, input_sha256, _result_sha256(result))
    return result, witness


def compile_root_work_context(envelope: RootContextEnvelope, declaration: Any, qos: Any,
                              artifacts: Any, requested_on_demand_ids: Any,
                              tokenizer: Tokenizer) -> tuple[ContextCompileResult, ContextCompileWitness]:
    """Compile root context after rebuilding the complete canonical V1 carrier."""
    try:
        v2 = validate_work_context_manifest_v2_structure(declaration)
    except WorkContextManifestV2Error as exc:
        raise ContextCompilerError("V2 declaration is invalid") from exc
    return _compile(v2, _v1_from_root(envelope, v2), qos, artifacts, requested_on_demand_ids,
                    tokenizer, mode="root", envelope=envelope, root=True)


def verify_root_work_context(result: ContextCompileResult, witness: ContextCompileWitness,
                             envelope: RootContextEnvelope, declaration: Any, qos: Any,
                             artifacts: Any, requested_on_demand_ids: Any, tokenizer: Tokenizer) -> None:
    _compile_result_dict(result)
    _validated_witness(witness)
    actual, actual_witness = compile_root_work_context(envelope, declaration, qos, artifacts,
                                                        requested_on_demand_ids, tokenizer)
    if actual != result or actual_witness != witness:
        _fail("root compilation witness differs")


def _parent_proof(parent_result: Any, parent_witness: Any, parent_declaration: Any,
                  parent_v1_manifest_bytes: bytes) -> tuple[WorkContextManifestV2, str, str]:
    if type(parent_result) is not ContextCompileResult:
        _fail("parent compilation proof is invalid")
    try:
        witness = _validated_witness(parent_witness)
        _compile_result_dict(parent_result)
        result_digest = _result_sha256(parent_result)
    except ContextCompilerError as exc:
        raise ContextCompilerError("parent compilation witness is invalid") from exc
    if (witness.input_sha256 != parent_result.compile_input_sha256
            or witness.result_sha256 != result_digest):
        _fail("parent compilation witness differs")
    try:
        parent = validate_work_context_manifest_v2(parent_declaration, parent_v1_manifest_bytes)
        v2_digest = work_context_manifest_v2_sha256(parent, parent_v1_manifest_bytes)
    except (WorkContextManifestV2Error, CompanyContractError, TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise ContextCompilerError("parent V2 lineage is invalid") from exc
    v1_digest = hashlib.sha256(parent_v1_manifest_bytes).hexdigest()
    if parent_result.context_v2_semantic_sha256 != v2_digest or parent_result.v1_carrier_sha256 != v1_digest:
        _fail("parent compilation identities differ")
    expected_mode = "root" if parent.lineage.parent_manifest_sha256 is None else "child"
    if witness.mode != expected_mode:
        _fail("parent compilation mode differs from V2 lineage")
    return parent, v2_digest, v1_digest


def compile_child_work_context(parent_result: ContextCompileResult, parent_witness: ContextCompileWitness,
                               parent_declaration: Any, parent_v1_manifest_bytes: bytes,
                               child_declaration: Any, qos: Any, artifacts: Any,
                               requested_on_demand_ids: Any, tokenizer: Tokenizer) -> tuple[ContextCompileResult, ContextCompileWitness]:
    """Fail closed until a durable verified parent compile proof is available."""
    parent, _, _ = _parent_proof(parent_result, parent_witness, parent_declaration, parent_v1_manifest_bytes)
    try:
        child = validate_child_work_context_manifest_v2(child_declaration, parent,
                                                         parent_v1_manifest_bytes, parent_v1_manifest_bytes)
    except WorkContextManifestV2Error as exc:
        raise ContextCompilerError("child V2 lineage is invalid") from exc
    requested = _requested(requested_on_demand_ids, child.entries)
    candidate_emitted = {entry.entry_id for entry in child.entries if _candidate(entry, requested)}
    if not candidate_emitted <= set(parent_result.emitted_entry_ids):
        _fail("child candidate entries are not a parent subset")
    raise NeedsContext("verified_parent_compile_proof_unavailable")


def verify_child_work_context(result: ContextCompileResult, witness: ContextCompileWitness,
                              parent_result: ContextCompileResult, parent_witness: ContextCompileWitness,
                              parent_declaration: Any, parent_v1_manifest_bytes: bytes,
                              child_declaration: Any, qos: Any, artifacts: Any,
                              requested_on_demand_ids: Any, tokenizer: Tokenizer) -> None:
    _compile_result_dict(result)
    _validated_witness(witness)
    actual, actual_witness = compile_child_work_context(parent_result, parent_witness,
        parent_declaration, parent_v1_manifest_bytes, child_declaration, qos, artifacts,
        requested_on_demand_ids, tokenizer)
    if actual != result or actual_witness != witness:
        _fail("child compilation witness differs")


def selected_upstream_result(*_: Any) -> None:
    """A compiler cannot select a sealed upstream amendment."""
    raise NeedsContext("sealed_amendment_unavailable")
