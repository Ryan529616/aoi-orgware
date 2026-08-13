"""Supervisor-owned durable publication for bounded legacy bridge snapshots.

The public function requires an exact :class:`CompanySupervisor` and invokes
its class-bound writer methods.  This protects the ordinary in-process API
boundary; it is not hostile same-process isolation.  The bridge remains
read-only with respect to the legacy repository, dispatch, and external jobs.
Raw legacy bytes are not copied into company blobs: the durable fact binds the
actual source-document hash/size, the normalized redacted projection, and the
separately preserved legacy-archive digest.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
from typing import Any, Mapping, NamedTuple, NoReturn

from ..frozen_json import thaw_frozen_json, thaw_json_payload
from .contracts import (
    COMPANY_MANIFEST_V1,
    MAX_EVENT_PAYLOAD_BYTES,
    CompanyContractError,
    canonical_company_json_bytes,
    validate_actor_authority,
    validate_company_manifest,
    validate_company_transaction_receipt,
    validate_company_transaction_request,
)
from .ledger import (
    LedgerCommitEffectUnknownError,
    LedgerConflictError,
    LedgerTransactionRecord,
)
from .legacy_bridge import (
    LegacyBridgeCompanyKey,
    LegacyBridgeError,
    LegacyBridgeProjectionV1,
    normalize_legacy_bridge_snapshot,
)
from .legacy_bridge_contract import (
    LEGACY_BRIDGE_OBSERVATION_V1,
    build_legacy_bridge_observation,
    legacy_bridge_scope_id,
    validate_legacy_bridge_observation,
)
from .legacy_bridge_health import (
    LEGACY_BRIDGE_COVERAGE_V1,
    MAX_SOURCE_DOCUMENT_BYTES,
    build_legacy_bridge_coverage,
    legacy_bridge_attempt_id,
    validate_legacy_bridge_coverage,
)
from .supervisor import CompanySupervisor
from .transactions import CompanyEventDraft, build_company_transaction_request


class LegacyBridgePublicationError(RuntimeError):
    """A bridge snapshot cannot be durably published without ambiguity."""


class LegacyBridgeIngestResult(NamedTuple):
    transaction_id: str
    command_id: str
    bridge_scope_id: str
    assessment_id: str
    observation_id: str | None
    ingest_state: str
    coverage_state: str
    effect: str
    global_sequence: int | None
    idempotent_replay: bool


class LegacyBridgePublicationEnvelope(NamedTuple):
    """One replay-safe, Supervisor-authenticated legacy publication."""

    attempt_id: str
    transaction_id: str
    command_id: str
    observation: dict[str, Any] | None
    coverage: dict[str, Any]


class _ReplayInputs(NamedTuple):
    projection: LegacyBridgeProjectionV1 | None
    attempt_id: str
    bridge_scope_id: str
    transaction_id: str
    command_id: str
    source_document_sha256: str
    source_document_size_bytes: int
    legacy_archive_sha256: str
    task_identity_digest: str
    ingest_state: str
    reason: str


def _fail(message: str) -> NoReturn:
    raise LegacyBridgePublicationError(message)


def _plain(value: Mapping[str, Any]) -> dict[str, Any]:
    plain = thaw_frozen_json(thaw_json_payload(value))
    if type(plain) is not dict:
        _fail("legacy bridge projected payload is not an object")
    return plain


def _company_key(supervisor: CompanySupervisor) -> LegacyBridgeCompanyKey:
    manifests = CompanySupervisor.objects(
        supervisor,
        contract_type=COMPANY_MANIFEST_V1,
    )
    if len(manifests) != 1:
        _fail("company manifest projection is missing or ambiguous")
    try:
        manifest = validate_company_manifest(_plain(manifests[0].payload))
    except (TypeError, ValueError) as exc:
        raise LegacyBridgePublicationError(
            "company manifest projection is invalid",
        ) from exc
    return LegacyBridgeCompanyKey(
        str(manifest["company_id"]),
        int(manifest["company_incarnation"]),
        int(manifest["lock_domain_generation"]),
    )


def _wire_id(kind: str, attempt_id: str) -> str:
    return f"legacy-bridge-{kind}-{attempt_id}"


def _timestamp_order(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, OverflowError, ValueError) as exc:
        raise LegacyBridgePublicationError(
            "legacy bridge received_at is invalid",
        ) from exc
    if parsed.tzinfo is None:
        _fail("legacy bridge received_at lacks a timezone")
    return parsed


def _normalize_outcome(
    raw: bytes,
    key: LegacyBridgeCompanyKey,
    *,
    legacy_archive_sha256: str,
    task_identity_digest: str,
) -> tuple[LegacyBridgeProjectionV1 | None, str, str]:
    try:
        projection = normalize_legacy_bridge_snapshot(raw)
    except LegacyBridgeError:
        return None, "degraded", "snapshot_invalid"
    if (
        projection.key != key
        or projection.legacy_archive_sha256 != legacy_archive_sha256
        or projection.task_identity_digest != task_identity_digest
    ):
        return None, "degraded", "binding_mismatch"
    return projection, "observed", "provider_runtime_unavailable"


def _require_monotonic_assessment(
    supervisor: CompanySupervisor,
    bridge_scope_id: str,
    received_at: str,
) -> None:
    matches = [
        validate_legacy_bridge_coverage(_plain(item.payload))
        for item in CompanySupervisor.objects(
            supervisor,
            contract_type=LEGACY_BRIDGE_COVERAGE_V1,
        )
        if item.payload.get("bridge_scope_id") == bridge_scope_id
    ]
    if len(matches) > 1:
        _fail("legacy bridge current coverage is ambiguous")
    if matches and _timestamp_order(received_at) <= _timestamp_order(
        str(matches[0]["assessed_at"]),
    ):
        _fail("legacy bridge assessment time does not advance")


def validate_legacy_bridge_publication_envelope(
    supervisor: CompanySupervisor,
    record: LedgerTransactionRecord,
) -> LegacyBridgePublicationEnvelope:
    """Validate one exact, committed bridge publication without side effects.

    This is deliberately stronger than payload-schema validation: it binds the
    durable request, event envelopes, and Supervisor authority together before
    callers use an observation to represent a reopened company.
    """

    if type(supervisor) is not CompanySupervisor or type(record) is not LedgerTransactionRecord:
        _fail("legacy bridge durable publication envelope is invalid")
    try:
        request = validate_company_transaction_request(_plain(record.request))
        receipt = validate_company_transaction_receipt(_plain(record.receipt))
        authority = validate_actor_authority(
            _plain(request["actor_authority"]),
        )
        expected_authority = _plain(CompanySupervisor._supervisor_authority(supervisor))
        if authority != expected_authority or authority.get("actor_kind") != "supervisor":
            _fail("legacy bridge durable publication envelope is invalid")
        request_events = request["events"]
        if len(record.events) != len(request_events) or len(record.events) not in {1, 2}:
            _fail("legacy bridge durable publication envelope is invalid")
        events = [_plain(wrapped.event) for wrapped in record.events]
        if any(event != expected for event, expected in zip(events, request_events, strict=True)):
            _fail("legacy bridge durable publication envelope is invalid")
        payloads = [_plain(event["payload"]) for event in events]
        types = tuple(payload.get("contract_type") for payload in payloads)
        if types == (LEGACY_BRIDGE_OBSERVATION_V1, LEGACY_BRIDGE_COVERAGE_V1):
            observation = validate_legacy_bridge_observation(payloads[0])
            coverage = validate_legacy_bridge_coverage(payloads[1])
        elif types == (LEGACY_BRIDGE_COVERAGE_V1,):
            observation = None
            coverage = validate_legacy_bridge_coverage(payloads[0])
        else:
            _fail("legacy bridge durable publication envelope is invalid")
        expected_attempt = legacy_bridge_attempt_id(
            str(coverage["bridge_scope_id"]),
            source_document_sha256=str(coverage["source_document_sha256"]),
            source_document_size_bytes=int(coverage["source_document_size_bytes"]),
        )
        transaction_id = _wire_id("transaction", expected_attempt)
        command_id = _wire_id("command", expected_attempt)
        expected_labels = (
            ("legacy.bridge.observation", "legacy.bridge.coverage")
            if observation is not None
            else ("legacy.bridge.coverage",)
        )
        expected_times = (
            (str(observation["ingested_at"]), str(coverage["assessed_at"]))
            if observation is not None
            else (str(coverage["assessed_at"]),)
        )
        if (
            request["transaction_id"] != transaction_id
            or request["command_id"] != command_id
            or receipt["transaction_id"] != transaction_id
            or receipt["command_id"] != command_id
            or receipt["request_sha256"] != request["request_sha256"]
            or receipt["state"] != "committed"
            or receipt["recorded_at"] != str(coverage["assessed_at"])
            or receipt["global_sequence"] != record.global_sequence
            or receipt["evidence"] != []
            or tuple(
                receipt[field]
                for field in (
                    "company_id",
                    "company_incarnation",
                    "lock_domain_generation",
                )
            )
            != tuple(
                coverage[field]
                for field in (
                    "company_id",
                    "company_incarnation",
                    "lock_domain_generation",
                )
            )
            or any(
                event["transaction_id"] != transaction_id
                or event["command_id"] != command_id
                or event["event_id"] != _wire_id(f"event-{index}", expected_attempt)
                or event["event_type"] != label
                or event["recorded_at"] != recorded_at
                or event["provenance"] != "adapter_receipt_persisted"
                or validate_actor_authority(_plain(event["actor_authority"])) != authority
                for index, (event, label, recorded_at) in enumerate(
                    zip(events, expected_labels, expected_times, strict=True),
                    start=1,
                )
            )
            or (observation is None and coverage["observation_id"] is not None)
            or (
                observation is not None
                and (
                    coverage["observation_id"] != observation["observation_id"]
                    or observation["ingested_at"] != coverage["assessed_at"]
                    or tuple(coverage[field] for field in ("company_id", "company_incarnation", "lock_domain_generation"))
                    != tuple(observation[field] for field in ("company_id", "company_incarnation", "lock_domain_generation"))
                )
            )
        ):
            _fail("legacy bridge durable publication envelope is invalid")
        return LegacyBridgePublicationEnvelope(
            expected_attempt,
            transaction_id,
            command_id,
            observation,
            coverage,
        )
    except (MemoryError, SystemExit, KeyboardInterrupt, LegacyBridgePublicationError):
        raise
    except Exception as exc:
        raise LegacyBridgePublicationError(
            "legacy bridge durable publication envelope is invalid",
        ) from exc


def _replay_result(
    supervisor: CompanySupervisor,
    record: LedgerTransactionRecord,
    inputs: _ReplayInputs,
) -> LegacyBridgeIngestResult:
    envelope = validate_legacy_bridge_publication_envelope(supervisor, record)
    if (
        envelope.transaction_id != inputs.transaction_id
        or envelope.command_id != inputs.command_id
        or envelope.attempt_id != inputs.attempt_id
        or (inputs.projection is None) != (envelope.observation is None)
    ):
        _fail("legacy bridge durable transaction identity differs")
    observation = envelope.observation
    health = envelope.coverage
    if inputs.projection is not None and observation is not None:
        expected_observation = build_legacy_bridge_observation(
            inputs.projection,
            ingested_at=str(observation["ingested_at"]),
        )
        if observation != expected_observation:
            _fail("legacy bridge durable observation differs from source")
    expected_health = build_legacy_bridge_coverage(
        inputs.projection.key if inputs.projection is not None else LegacyBridgeCompanyKey(
            str(health["company_id"]),
            int(health["company_incarnation"]),
            int(health["lock_domain_generation"]),
        ),
        legacy_archive_sha256=inputs.legacy_archive_sha256,
        task_identity_digest=inputs.task_identity_digest,
        source_document_sha256=inputs.source_document_sha256,
        source_document_size_bytes=inputs.source_document_size_bytes,
        ingest_state=inputs.ingest_state,
        reason=inputs.reason,
        assessed_at=str(health["assessed_at"]),
        observation_id=health["observation_id"],
    )
    if health != expected_health or health["bridge_scope_id"] != inputs.bridge_scope_id:
        _fail("legacy bridge durable coverage differs from source")
    if (
        observation is not None
        and health["observation_id"] != observation["observation_id"]
    ):
        _fail("legacy bridge durable coverage observation join differs")
    try:
        replayed = CompanySupervisor.commit(
            supervisor,
            _plain(record.request),
            recorded_at=str(health["assessed_at"]),
        )
    except LedgerCommitEffectUnknownError:
        return LegacyBridgeIngestResult(
            inputs.transaction_id,
            inputs.command_id,
            inputs.bridge_scope_id,
            str(health["assessment_id"]),
            None,
            "unknown",
            "unknown",
            "effect_unknown",
            None,
            False,
        )
    if not replayed.idempotent_replay or replayed.record != record:
        _fail("legacy bridge durable replay acknowledgement differs")
    return LegacyBridgeIngestResult(
        inputs.transaction_id,
        inputs.command_id,
        inputs.bridge_scope_id,
        str(health["assessment_id"]),
        None if observation is None else str(observation["observation_id"]),
        inputs.ingest_state,
        "degraded",
        "none",
        record.global_sequence,
        True,
    )


def publish_legacy_bridge_snapshot(
    supervisor: CompanySupervisor,
    raw: bytes,
    *,
    task_identity_digest: str,
    legacy_archive_sha256: str,
    received_at: str,
) -> LegacyBridgeIngestResult:
    """Normalize and durably publish one legacy snapshot through one Supervisor.

    ``effect_unknown`` is returned without an internal retry.  A caller may
    reconcile only by reopening/recovering the company and presenting the same
    bytes, which reproduce the same transaction identity.
    """

    if type(supervisor) is not CompanySupervisor:
        _fail("legacy bridge publisher requires an exact CompanySupervisor")
    if type(raw) is not bytes or len(raw) > MAX_SOURCE_DOCUMENT_BYTES:
        _fail("legacy bridge source document exceeds its bounded API")
    if (
        type(task_identity_digest) is not str
        or len(task_identity_digest) != 64
        or any(character not in "0123456789abcdef" for character in task_identity_digest)
        or type(legacy_archive_sha256) is not str
        or len(legacy_archive_sha256) != 64
        or any(character not in "0123456789abcdef" for character in legacy_archive_sha256)
    ):
        _fail("legacy bridge expected digests are invalid")
    _timestamp_order(received_at)
    key = _company_key(supervisor)
    bridge_scope_id = legacy_bridge_scope_id(
        key,
        legacy_archive_sha256=legacy_archive_sha256,
        task_identity_digest=task_identity_digest,
    )
    source_sha = hashlib.sha256(raw).hexdigest()
    attempt = legacy_bridge_attempt_id(
        bridge_scope_id,
        source_document_sha256=source_sha,
        source_document_size_bytes=len(raw),
    )
    transaction_id = _wire_id("transaction", attempt)
    command_id = _wire_id("command", attempt)
    projection, ingest_state, reason = _normalize_outcome(
        raw,
        key,
        legacy_archive_sha256=legacy_archive_sha256,
        task_identity_digest=task_identity_digest,
    )
    observation = (
        None
        if projection is None
        else build_legacy_bridge_observation(projection, ingested_at=received_at)
    )
    if observation is not None:
        try:
            canonical_company_json_bytes(
                observation,
                max_bytes=MAX_EVENT_PAYLOAD_BYTES,
            )
        except CompanyContractError:
            projection = None
            observation = None
            ingest_state = "degraded"
            reason = "projection_unpublishable"
    durable = CompanySupervisor.record_by_transaction_id(
        supervisor,
        transaction_id,
    )
    replay_inputs = _ReplayInputs(
        projection,
        attempt,
        bridge_scope_id,
        transaction_id,
        command_id,
        source_sha,
        len(raw),
        legacy_archive_sha256,
        task_identity_digest,
        ingest_state,
        reason,
    )
    if durable is not None:
        return _replay_result(supervisor, durable, replay_inputs)
    _require_monotonic_assessment(supervisor, bridge_scope_id, received_at)
    health = build_legacy_bridge_coverage(
        key,
        legacy_archive_sha256=legacy_archive_sha256,
        task_identity_digest=task_identity_digest,
        source_document_sha256=source_sha,
        source_document_size_bytes=len(raw),
        ingest_state=ingest_state,
        reason=reason,
        assessed_at=received_at,
        observation_id=(
            None if observation is None else str(observation["observation_id"])
        ),
    )
    payloads = [*([] if observation is None else [observation]), health]
    labels = [
        *([] if observation is None else ["legacy.bridge.observation"]),
        "legacy.bridge.coverage",
    ]
    events = [
        CompanyEventDraft(
            event_id=_wire_id(f"event-{index}", attempt),
            event_type=label,
            recorded_at=received_at,
            payload=payload,
            provenance="adapter_receipt_persisted",
        )
        for index, (label, payload) in enumerate(
            zip(labels, payloads, strict=True),
            start=1,
        )
    ]
    request = build_company_transaction_request(
        CompanySupervisor.heads(supervisor),
        CompanySupervisor._supervisor_authority(supervisor),
        transaction_id=transaction_id,
        command_id=command_id,
        events=events,
    )
    try:
        committed = CompanySupervisor.commit(
            supervisor,
            request,
            recorded_at=received_at,
        )
    except LedgerCommitEffectUnknownError:
        return LegacyBridgeIngestResult(
            transaction_id,
            command_id,
            bridge_scope_id,
            str(health["assessment_id"]),
            None,
            "unknown",
            "unknown",
            "effect_unknown",
            None,
            False,
        )
    except LedgerConflictError:
        raced = CompanySupervisor.record_by_transaction_id(
            supervisor,
            transaction_id,
        )
        if raced is None:
            raise
        return _replay_result(supervisor, raced, replay_inputs)
    return LegacyBridgeIngestResult(
        transaction_id,
        command_id,
        bridge_scope_id,
        str(health["assessment_id"]),
        None if observation is None else str(observation["observation_id"]),
        ingest_state,
        "degraded",
        "none",
        committed.record.global_sequence,
        bool(committed.idempotent_replay),
    )


__all__ = [
    "LegacyBridgeIngestResult",
    "LegacyBridgePublicationEnvelope",
    "LegacyBridgePublicationError",
    "publish_legacy_bridge_snapshot",
    "validate_legacy_bridge_publication_envelope",
]
