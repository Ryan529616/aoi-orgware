"""Truthful read-only company views."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
import json
from typing import Any

from .contracts import (
    ALERT_V1,
    ARTIFACT_EDGE_V1,
    AUTHORITY_GRANT_V1,
    CARRIER_BINDING_V1,
    CHIEF_TERM_V1,
    COMPANY_MANIFEST_V1,
    CONTROL_INTENT_V1,
    DEPARTMENT_IDENTITY_V1,
    DEPARTMENT_LIFECYCLE_RESULT_V1,
    DEPARTMENT_SNAPSHOT_V1,
    DISPATCH_REQUEST_V1,
    EVIDENCE_RECORD_V1,
    EXECUTION_EVENT_V1,
    EXECUTION_NODE_V1,
    EXTERNAL_JOB_EFFECT_RECEIPT_V1,
    EXTERNAL_JOB_V1,
    NEEDS_USER_V1,
    NEEDS_USER_REVISION_V1,
    ORGANIZATION_NODE_V1,
    PROVIDER_COVERAGE_REVISION_V1,
    PROVIDER_LIFECYCLE_RECEIPT_V1,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    TASK_REVISION_V1,
    TAKEOVER_CAPABILITY_V1,
    TAKEOVER_CONSUMPTION_RECEIPT_V1,
    USAGE_COUNTER_SAMPLE_V1,
    WORK_DEFINITION_ENFORCEMENT_V1,
    WORK_DISPATCH_BINDING_V1,
    WORK_PACKET_V1,
    WORK_RESULT_RECEIPT_V1,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from .invariants import (
    MAX_ACTIVE_CARRIERS,
    MAX_MANAGER_ACTIVE_FANOUT,
    CompanyInvariantError,
    InvariantObject,
    QueueItem,
    UncertainDispatch,
    reduce_company_invariants,
)
from .ledger import LedgerTransactionRecord
from . import legacy_bridge_contract as bc, legacy_bridge_health as bh, legacy_bridge_job_terminal as bj
from .legacy_bridge_views import LegacyBridgeViewError, merge_legacy_bridge_coverage, project_legacy_bridge_dashboard
from .readmodel import ProjectedObject
from .state import (
    CompanyDeliverySnapshot,
    CompanyHistoricalReplayInput,
    CompanyQuerySnapshot,
    CompanyStateOwner,
)


COMPANY_VIEW_SCHEMA_VERSION = 1
_SECTIONS = frozenset(
    {
        "meta",
        "company",
        "departments",
        "execution",
        "jobs",
        "evidence",
        "usage",
        "work",
        "optimizer",
        "alerts",
        "snapshot",
        "export",
    },
)


class CompanyViewError(RuntimeError):
    """A read-only company view cannot be produced truthfully."""


def _delivery_view(
    delivery: CompanyDeliverySnapshot,
    *,
    include_bundle: bool,
) -> dict[str, Any]:
    checkpoint = delivery.checkpoint
    exported = delivery.sanitized_export
    bundle: Any = None
    if include_bundle and exported.canonical_bundle_json is not None:
        try:
            bundle = json.loads(
                exported.canonical_bundle_json.decode("utf-8", "strict"),
            )
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise CompanyViewError(
                "verified sanitized export bytes cannot be decoded",
            ) from exc
        if not isinstance(bundle, dict):
            raise CompanyViewError(
                "verified sanitized export is not an object",
            )
    return {
        "state": exported.state,
        "sanitized": exported.state in {"available", "stale"},
        "reason": exported.reason,
        "export_id": exported.export_id,
        "export_sha256": exported.export_sha256,
        "generated_at": exported.generated_at,
        "verified_at": exported.verified_at,
        "cursor": exported.cursor,
        "head_sha256": exported.head_sha256,
        "checkpoint_manifest_sha256": (
            exported.source_checkpoint_manifest_sha256
        ),
        "current": exported.current,
        "checkpoint": {
            "state": checkpoint.state,
            "reason": checkpoint.reason,
            "checkpoint_id": checkpoint.checkpoint_id,
            "cursor": checkpoint.cursor,
            "head_sha256": checkpoint.head_sha256,
            "manifest_sha256": checkpoint.manifest_sha256,
            "generated_at": checkpoint.generated_at,
            "verified_at": checkpoint.verified_at,
            "current": checkpoint.current,
        },
        "redaction": {
            "class": "operational",
            "security_boundary": False,
            "warning": "operational_redaction_not_security_boundary",
        },
        "snapshot": bundle,
    }


def _utc_now() -> str:
    return (
        datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


# Strip durable provider secrets at the view boundary.
_REDACTED_VIEW_KEYS = frozenset({
    "session_id",
    "thread_id",
    "turn_id",
    "user_action_ref",
    "nonce_sha256",
    "raw_prompt",
    "raw_bytes",
    "raw_content",
    "raw_payload",
    "prompt",
    "chain_of_thought",
})


def _is_redacted_view_key(key: str) -> bool:
    """Recognize secret-bearing transport fields."""

    normalized = key.lower()
    return (
        normalized in _REDACTED_VIEW_KEYS
        or normalized.endswith("_session_id")
        or normalized.endswith("_thread_id")
        or "native_handle" in normalized
        or normalized.endswith("_token")
        or "credential" in normalized
        or "secret" in normalized
    )


def _takeover_capability_view(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Render issuance identity without executable capability."""

    return {
        "contract_type": TAKEOVER_CAPABILITY_V1,
        "capability_id": payload.get("capability_id"),
        "contender_carrier_id": payload.get("contender_carrier_id"),
        "expected_chief_id": payload.get("expected_chief_id"),
        "expected_term": payload.get("expected_term"),
        "expected_epoch": payload.get("expected_epoch"),
        "resulting_term": payload.get("resulting_term"),
        "resulting_epoch": payload.get("resulting_epoch"),
        "issued_at": payload.get("issued_at"),
        "expires_at": payload.get("expires_at"),
        "state": "issued",
    }


def _takeover_receipt_view(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Render consumed/fenced history without embedding capability material."""

    capability = payload.get("capability")
    capability_map = capability if isinstance(capability, Mapping) else {}
    resulting = payload.get("resulting_chief_term")
    resulting_map = resulting if isinstance(resulting, Mapping) else {}
    return {
        "contract_type": TAKEOVER_CONSUMPTION_RECEIPT_V1,
        "consumption_id": payload.get("consumption_id"),
        "capability_id": capability_map.get(
            "capability_id", payload.get("capability_id"),
        ),
        "contender_carrier_id": capability_map.get(
            "contender_carrier_id", payload.get("contender_carrier_id"),
        ),
        "outcome": payload.get("outcome"),
        "consumed_at": payload.get("consumed_at"),
        "resulting_chief_term": (
            None
            if not resulting_map
            else {
                "chief_id": resulting_map.get("chief_id"),
                "carrier_id": resulting_map.get("carrier_id"),
                "term": resulting_map.get("term"),
                "epoch": resulting_map.get("epoch"),
            }
        ),
    }


def _external_job_view(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Expose durable job-handle provenance without its native resolver key."""

    handle = payload.get("external_handle")
    handle_map = handle if isinstance(handle, Mapping) else None
    return {
        **{
            str(key): _redact_view(item)
            for key, item in payload.items()
            if key != "external_handle"
        },
        "external_handle": (
            {"availability": "unavailable"}
            if handle_map is None
            else {
                "availability": "available",
                "provider": handle_map.get("provider"),
                "namespace": handle_map.get("namespace"),
                "resolver": handle_map.get("resolver"),
                "host_fingerprint_sha256": handle_map.get(
                    "host_fingerprint_sha256",
                ),
            }
        ),
    }


def _redact_view(value: Any) -> Any:
    """Recursively remove resume/intent secrets from every API surface."""

    if isinstance(value, Mapping):
        contract_type = value.get("contract_type")
        if contract_type == TAKEOVER_CAPABILITY_V1:
            return _takeover_capability_view(value)
        if contract_type == TAKEOVER_CONSUMPTION_RECEIPT_V1:
            return _takeover_receipt_view(value)
        if contract_type == EXTERNAL_JOB_V1:
            return _external_job_view(value)
        return {
            str(key): _redact_view(item)
            for key, item in value.items()
            if not _is_redacted_view_key(str(key))
        }
    if isinstance(value, (list, tuple)):
        return [_redact_view(item) for item in value]
    return value


def _carrier_view(carrier: Mapping[str, Any]) -> dict[str, Any]:
    """Expose carrier availability and identity, never its provider session."""

    return {
        "carrier_id": carrier.get("carrier_id"),
        "actor_id": carrier.get("actor_id"),
        "provider": carrier.get("provider"),
        "model": carrier.get("model"),
        "session_availability": carrier.get("session_availability"),
        "state": carrier.get("state"),
        "bound_at": carrier.get("bound_at"),
        "last_observed_at": carrier.get("last_observed_at"),
        "observation": _redact_view(carrier.get("observation")),
    }


def _department_snapshot_view(
    snapshot: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Expose snapshot availability, never its blob contents."""

    if snapshot is None:
        return {
            "availability": "unavailable",
            "snapshot_id": None,
            "revision": None,
            "cursor": None,
        }
    return {
        "availability": "available",
        "snapshot_id": snapshot.get("snapshot_id"),
        "revision": snapshot.get("revision"),
        "cursor": snapshot.get("company_cursor"),
    }


def _department_execution_view(
    execution: Mapping[str, Any] | None,
    *,
    descendant_count: int | None,
) -> dict[str, Any] | None:
    """Keep engineering and runtime truth visible without transport links."""

    if execution is None:
        return None
    return {
        "execution_id": execution.get("execution_id"),
        "engineering_status": execution.get("engineering_status"),
        "runtime_status": execution.get("runtime_status"),
        "carrier_state": execution.get("carrier_state", "unknown"),
        "updated_at": execution.get("updated_at"),
        "descendant_count": descendant_count,
    }


def _department_carrier_view(
    carrier: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Project carrier identity and availability, never a raw session handle."""

    if carrier is None:
        return None
    return {
        "carrier_id": carrier.get("carrier_id"),
        "state": carrier.get("state"),
        "provider": carrier.get("provider"),
        "model": carrier.get("model"),
        "session_availability": carrier.get("session_availability"),
    }


def _department_dispatch_view(
    dispatch: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Show the durable dispatch state without implying a runtime exists."""

    if dispatch is None:
        return None
    return {
        "dispatch_request_id": dispatch.get("dispatch_request_id"),
        "revision": dispatch.get("revision"),
        "state": dispatch.get("state"),
        "updated_at": dispatch.get("updated_at"),
    }


def _current_department_execution(
    executions: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Return a live execution only; a queued dispatch is never one."""

    current = [
        execution
        for execution in executions
        if execution.get("engineering_status") not in {"completed", "cancelled"}
        and execution.get("runtime_status") != "stopped"
    ]
    return max(
        current,
        key=lambda execution: (
            str(execution.get("updated_at", "")),
            str(execution.get("execution_id", "")),
        ),
        default=None,
    )


def _chief_authority_view(
    grant: Mapping[str, Any],
    current_term: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Keep issuance immutable while deriving current effective authority."""

    exact_current = current_term is not None and all(
        grant.get(key) == current_term.get(term_key)
        for key, term_key in (
            ("actor_id", "chief_id"),
            ("carrier_id", "carrier_id"),
            ("term", "term"),
            ("chief_epoch", "epoch"),
        )
    )
    issued_state = grant.get("authority_state")
    return {
        "grant_id": grant.get("grant_id"),
        "actor_id": grant.get("actor_id"),
        "carrier_id": grant.get("carrier_id"),
        "term": grant.get("term"),
        "epoch": grant.get("chief_epoch"),
        "issued_state": issued_state,
        "effective_state": (
            "active" if issued_state == "active" and exact_current else "fenced"
        ),
        "permissions": _redact_view(grant.get("permissions", [])),
        "issued_at": grant.get("issued_at"),
        "expires_at": grant.get("expires_at"),
        "provenance": grant.get("provenance"),
    }


def _carrier_state(
    node: Mapping[str, Any],
    *,
    carriers_by_id: Mapping[str, Mapping[str, Any]],
) -> str:
    """Derive execution-local carrier state without Chief-global aliasing."""

    carrier_id = node.get("carrier_id")
    if not isinstance(carrier_id, str):
        return "not_applicable"
    carrier = carriers_by_id.get(carrier_id)
    if carrier is None:
        return "unknown"
    state = carrier.get("state")
    if state == "fenced":
        return "fenced"
    if state == "active":
        return "active"
    if isinstance(state, str):
        return state
    return "unknown"


def _payloads(
    objects: tuple[ProjectedObject, ...],
    contract_type: str,
) -> list[dict[str, Any]]:
    return [
        _plain(item.payload)
        for item in objects
        if item.contract_type == contract_type
    ]


def _first_or_none(values: list[dict[str, Any]]) -> dict[str, Any] | None:
    return values[0] if values else None


_COVERAGE_SEVERITY = {
    "observed": 1,
    "unknown": 2,
    "unavailable": 3,
    "degraded": 4,
}


def _raw_artifact_metadata(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Expose blob identity only; raw provider payload bytes stay in storage."""

    raw = payload.get("raw_artifact")
    artifact = raw if isinstance(raw, Mapping) else {}
    return {
        "availability": artifact.get("availability", "unavailable"),
        "sha256": artifact.get("sha256"),
        "size_bytes": artifact.get("size_bytes"),
        "media_type": artifact.get("media_type"),
    }


def _coverage_revision_view(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Render one provider/surface assessment without adapter-local identity."""

    observation = payload.get("observation")
    observed = observation if isinstance(observation, Mapping) else {}
    dropped = payload.get("dropped_event_count")
    dropped_fact = dropped if isinstance(dropped, Mapping) else {}
    return {
        "provider": payload.get("provider"),
        "surface": payload.get("coverage_surface"),
        "state": payload.get("state", "unknown"),
        "reason": payload.get("reason", "coverage_reason_unavailable"),
        "source": payload.get("assessment_source", "none"),
        "quality": observed.get("state", "unknown"),
        "assessed_at": payload.get("assessed_at"),
        "revision": payload.get("revision"),
        "dropped_event_count": {
            "value": dropped_fact.get("value"),
            "source": dropped_fact.get("source", "none"),
            "quality": dropped_fact.get("quality", "unknown"),
            "reason": dropped_fact.get("reason", "not_reported"),
        },
    }


def _latest_coverage_revisions(
    revisions: list[dict[str, Any]],
    *,
    surface: str | None = None,
) -> list[dict[str, Any]]:
    """Keep the newest revision per provider/surface, never inventing coverage."""

    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for revision in revisions:
        coverage_surface = revision.get("coverage_surface")
        provider = revision.get("provider")
        if not isinstance(coverage_surface, str) or not isinstance(provider, str):
            continue
        if surface is not None and coverage_surface != surface:
            continue
        key = (provider, coverage_surface)
        previous = latest.get(key)
        current_key = (
            int(revision.get("revision", -1)),
            str(revision.get("assessed_at", "")),
            str(revision.get("revision_id", "")),
        )
        previous_key = (
            int(previous.get("revision", -1)),
            str(previous.get("assessed_at", "")),
            str(previous.get("revision_id", "")),
        ) if previous is not None else None
        if previous_key is None or current_key > previous_key:
            latest[key] = revision
    return [
        latest[key]
        for key in sorted(latest)
    ]


def _coverage_summary(
    revisions: list[dict[str, Any]],
    *,
    absent_reason: str,
) -> dict[str, Any]:
    """Summarize registered coverage conservatively by its worst current state."""

    if not revisions:
        # Keep the v0.4-compatible compact unknown response when no adapter has
        # written an assessment.  Unknown is not a zero-drop or healthy claim.
        return {"state": "unknown", "reason": absent_reason}
    views = [_coverage_revision_view(revision) for revision in revisions]
    worst = max(
        views,
        key=lambda item: (
            _COVERAGE_SEVERITY.get(str(item["state"]), 2),
            str(item["assessed_at"]),
            str(item["provider"]),
            str(item["surface"]),
        ),
    )
    return {
        "state": worst["state"],
        "reason": worst["reason"],
        "source": worst["source"],
        "quality": worst["quality"],
        "revisions": views,
    }


def _provider_telemetry_receipt_view(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Render intake provenance without raw facts or provider transport IDs."""

    join = payload.get("dispatch_join")
    binding = join if isinstance(join, Mapping) else {}
    relation = payload.get("provider_native_relation")
    native = relation if isinstance(relation, Mapping) else {}
    observation = payload.get("observation")
    return {
        "receipt_id": payload.get("receipt_id"),
        "provider": payload.get("provider"),
        "source_class": payload.get("source_class"),
        "parser": {
            "id": payload.get("parser_id"),
            "version": payload.get("parser_version"),
        },
        "parse_outcome": payload.get("parse_outcome"),
        "normalized_kind": payload.get("normalized_kind"),
        "dispatch_join": {
            "state": binding.get("state", "none"),
            "binding_kind": binding.get("binding_kind", "none"),
            "execution_id": binding.get("execution_id"),
            "carrier_id": binding.get("carrier_id"),
            "candidate_count": binding.get("candidate_count", 0),
            "candidates_sha256": binding.get("candidates_sha256"),
            "reason": binding.get("reason", "join_not_available"),
        },
        "received_at": payload.get("received_at"),
        "raw_artifact": _raw_artifact_metadata(payload),
        "provenance": payload.get("provenance"),
        "observation": _plain(observation) if isinstance(observation, Mapping) else {},
        "provider_native_relation": {
            "kind": native.get("kind", "none"),
            "activity_kind": native.get("activity_kind"),
            "native_depth": native.get("native_depth"),
            "reason": native.get("reason", "provider_relation_unavailable"),
            "interpretation": "provider_native_only_not_aoi_lineage",
        },
    }


def _provider_lifecycle_receipt_view(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Project lifecycle evidence by identity only, never transport content."""

    observation = payload.get("observation")
    raw_artifact = _raw_artifact_metadata(payload)
    return {
        "receipt_id": payload.get("receipt_id"),
        "receipt_sha256": payload.get("receipt_sha256"),
        "source_event_id": payload.get("source_event_id"),
        "event_kind": payload.get("event_kind"),
        "provider": payload.get("provider"),
        "dispatch_request_id": payload.get("dispatch_request_id"),
        "dispatch_revision_id": payload.get("dispatch_revision_id"),
        "dispatch_revision": payload.get("dispatch_revision"),
        "execution_id": payload.get("execution_id"),
        "carrier_id": payload.get("carrier_id"),
        "provider_dispatch_id": payload.get("provider_dispatch_id"),
        "reconcile_ref": payload.get("reconcile_ref"),
        "observed_at": payload.get("observed_at"),
        "provenance": payload.get("provenance"),
        "observation": (
            _redact_view(_plain(observation))
            if isinstance(observation, Mapping)
            else {}
        ),
        "raw_artifact": {
            "availability": raw_artifact["availability"],
            "sha256": raw_artifact["sha256"],
        },
    }


def _provider_lifecycle_receipts_view(
    receipts: list[ProjectedObject],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Expose the newest bounded ledger window with exact list metadata."""

    visible = len(receipts)
    newest_first = sorted(
        receipts,
        key=lambda item: (
            item.global_sequence,
            str(item.payload.get("observed_at", "")),
            item.event_id,
            item.object_key,
        ),
        reverse=True,
    )
    returned = newest_first[:256]
    return (
        [
            {
                **_provider_lifecycle_receipt_view(item.payload),
                "ledger_cursor": item.global_sequence,
            }
            for item in returned
        ],
        {
            "visible": visible,
            "returned": len(returned),
            "truncated": visible > len(returned),
        },
    )


def _usage_counter_sample_view(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Expose raw cumulative vectors only; no delta, company total, or price."""

    facts = payload.get("provenance_facts")
    observation = payload.get("observation")
    return {
        "sample_id": payload.get("sample_id"),
        "telemetry_receipt_id": payload.get("telemetry_receipt_id"),
        "telemetry_receipt_sha256": payload.get("telemetry_receipt_sha256"),
        "provider": payload.get("provider"),
        "counting_semantics": "non_additive_cumulative",
        "total_token_vector": _plain(payload.get("total_token_vector", {})),
        "last_token_vector": _plain(payload.get("last_token_vector", {})),
        "model_context_window": _plain(payload.get("model_context_window", {})),
        "provenance_facts": _plain(facts) if isinstance(facts, Mapping) else {},
        "received_at": payload.get("received_at"),
        "raw_artifact": _raw_artifact_metadata(payload),
        "provenance": payload.get("provenance"),
        "observation": _plain(observation) if isinstance(observation, Mapping) else {},
    }


def _bounded_question_summary(text: str, *, maximum_bytes: int = 512) -> str:
    """Produce one deterministic, single-line local-display summary."""

    normalized = " ".join(text.split())
    if not normalized:
        raise CompanyViewError("needs-user question has no displayable text")
    encoded = normalized.encode("utf-8", "strict")
    if len(encoded) <= maximum_bytes:
        return normalized
    suffix = "…"
    remaining = maximum_bytes - len(suffix.encode("utf-8"))
    result: list[str] = []
    used = 0
    for character in normalized:
        size = len(character.encode("utf-8"))
        if used + size > remaining:
            break
        result.append(character)
        used += size
    if not result:
        raise CompanyViewError("needs-user question cannot be summarized")
    return "".join(result).rstrip() + suffix


def _needs_user_revision_view(
    payload: Mapping[str, Any],
    *,
    question_summary: str | None,
    summary_quality: str,
    summary_reason: str,
) -> dict[str, Any]:
    """Return immutable status/digests plus one bounded local display summary."""

    observation = payload.get("observation")
    return {
        "source": "needs_user_revision_v1",
        "item_id": payload.get("item_id"),
        "state": payload.get("state", "unknown"),
        "revision_id": payload.get("revision_id"),
        "revision": payload.get("revision"),
        "origin_execution_id": payload.get("origin_execution_id"),
        "opened_chief_term": payload.get("opened_chief_term"),
        "question_summary": question_summary,
        "question_summary_quality": summary_quality,
        "question_summary_reason": summary_reason,
        "question_sha256": payload.get("question_sha256"),
        "answer_sha256": payload.get("answer_sha256"),
        "created_at": payload.get("created_at"),
        "updated_at": payload.get("updated_at"),
        "answered_at": payload.get("answered_at"),
        "answered_by_chief_term": payload.get("answered_by_chief_term"),
        "observation": _plain(observation) if isinstance(observation, Mapping) else {},
    }


def _legacy_needs_user_view(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize the prior compact NeedsUser contract for the same UI list."""

    observation = payload.get("observation")
    return {
        "source": "needs_user_v1_legacy",
        "item_id": payload.get("item_id"),
        "state": payload.get("state", "unknown"),
        "revision_id": None,
        "revision": None,
        "origin_execution_id": payload.get("execution_id"),
        "opened_chief_term": payload.get("chief_term"),
        "question_summary": None,
        "question_summary_quality": "unavailable",
        "question_summary_reason": "legacy_contract_has_no_question_blob",
        "question_sha256": payload.get("question_sha256"),
        "answer_sha256": None,
        "created_at": payload.get("created_at"),
        "updated_at": payload.get("answered_at", payload.get("created_at")),
        "answered_at": payload.get("answered_at"),
        "answered_by_chief_term": None,
        "observation": _plain(observation) if isinstance(observation, Mapping) else {},
    }


def _invariant_objects(
    objects: tuple[ProjectedObject, ...],
    *,
    excluded_execution_ids: frozenset[str] = frozenset(),
) -> tuple[InvariantObject, ...]:
    """Adapt read-model objects to the one authoritative dispatch reducer."""

    result: list[InvariantObject] = []
    for item in objects:
        if (
            item.contract_type == EXECUTION_NODE_V1
            and item.payload.get("execution_id") in excluded_execution_ids
        ):
            continue
        payload = _plain(item.payload)
        if not isinstance(payload, Mapping):  # pragma: no cover - projected rows promise mappings
            raise CompanyViewError("projected object payload is not a mapping")
        result.append(
            InvariantObject(
                contract_type=item.contract_type,
                object_key=item.object_key,
                event_id=item.event_id,
                global_sequence=item.global_sequence,
                payload_sha256=company_contract_sha256(payload),
                payload=payload,
            ),
        )
    return tuple(result)


def _capacity_reason(
    *,
    health_status: str,
    completeness: str,
    manager_capacity_complete: bool,
    unattributed_active: tuple[str, ...],
) -> str | None:
    """Say exactly why an admission capacity cannot be safely derived."""

    if health_status != "ready":
        return "company_state_degraded"
    if completeness != "complete":
        return "projection_incomplete"
    if not manager_capacity_complete:
        if unattributed_active:
            return "active_capacity_unattributed"
        return "manager_capacity_incomplete"
    return None


def _queue_item_view(
    item: QueueItem,
    *,
    launch_eligible: bool | None,
    launch_eligibility_reason: str,
) -> dict[str, Any]:
    """Render a bounded queue row without exposing transport or evidence bytes."""

    if isinstance(item, UncertainDispatch):
        payload = item.payload
        source = "uncertain_receipt"
        receipt_state = item.receipt_state
        source_cursor = item.source_global_sequence
        source_event_id = item.source_event_id
        reconcile_required = True
    else:
        payload = item.payload
        source = "committed"
        receipt_state = "committed"
        source_cursor = item.global_sequence
        source_event_id = item.event_id
        reconcile_required = payload["reconcile_ref"] is not None
    evidence = payload["effect_evidence"]
    return {
        "source": source,
        "dispatch_request_id": str(payload["dispatch_request_id"]),
        "dispatch_revision_id": str(payload["dispatch_revision_id"]),
        "reservation_id": str(payload["reservation_id"]),
        "manager_node_id": str(payload["manager_node_id"]),
        "target_node_id": str(payload["target_node_id"]),
        "department_id": payload["department_id"],
        "requested_role": str(payload["requested_role"]),
        "requested_capability_tier": str(
            payload["requested_capability_tier"],
        ),
        "delegation_depth": int(payload["delegation_depth"]),
        "state": str(payload["state"]),
        "attempt": int(payload["attempt"]),
        "receipt_state": receipt_state,
        "source_cursor": source_cursor,
        "source_event_id": source_event_id,
        "created_at": str(payload["created_at"]),
        "updated_at": str(payload["updated_at"]),
        "evidence_count": len(evidence),
        "reconcile_required": reconcile_required,
        # Registered-work admission never proves provider launch.
        "launch_eligible": launch_eligible,
        "launch_eligibility_reason": launch_eligibility_reason,
    }


def _queue_view(
    queue_items: tuple[QueueItem, ...],
    *,
    completeness: str,
    reason: str | None,
    eligibility: Mapping[str, tuple[bool | None, str]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return a bounded, deterministically ordered dispatch queue projection."""

    visible = len(queue_items)
    by_state: dict[str, int] = {}
    effect_unknown = 0
    for item in queue_items:
        state = str(item.payload["state"])
        by_state[state] = by_state.get(state, 0) + 1
        if state == "effect_unknown":
            effect_unknown += 1
    returned_items = queue_items[:256]
    return (
        [
            _queue_item_view(
                item,
                launch_eligible=eligibility.get(
                    str(item.payload["dispatch_request_id"]),
                    (None, "dispatch_registration_unavailable"),
                )[0],
                launch_eligibility_reason=eligibility.get(
                    str(item.payload["dispatch_request_id"]),
                    (None, "dispatch_registration_unavailable"),
                )[1],
            )
            for item in returned_items
        ],
        {
            "visible": visible,
            "returned": len(returned_items),
            "truncated": visible > len(returned_items),
            "effect_unknown": effect_unknown,
            "by_state": dict(sorted(by_state.items())),
            "completeness": completeness,
            "reason": reason,
        },
    )


_ENVIRONMENT_KINDS = frozenset({
    "synthetic_canary", "live_company_unverified", "unverified",
})
_WORK_VIEW_LIMIT = 256


def _work_view(
    *,
    tasks: list[dict[str, Any]],
    packets: list[dict[str, Any]],
    bindings: list[dict[str, Any]],
    gates: list[dict[str, Any]],
    results: list[dict[str, Any]],
    queue_items: tuple[QueueItem, ...],
    completeness: str,
    historical: bool,
    now: str,
    environment_kind: str,
    environment_source: str,
) -> tuple[dict[str, Any], dict[str, tuple[bool | None, str]]]:
    """Project work metadata and a conservative per-dispatch gate predicate.

    Prompt/context/result bytes remain in the content-addressed store.  This
    view deliberately returns only immutable IDs, digests, bounded labels and
    blob availability metadata.
    """

    tasks_by_revision = {
        str(item["task_revision_id"]): item for item in tasks
    }
    packets_by_id = {str(item["packet_id"]): item for item in packets}
    bindings_by_dispatch: dict[str, list[dict[str, Any]]] = {}
    for binding in bindings:
        bindings_by_dispatch.setdefault(
            str(binding["dispatch_request_id"]), [],
        ).append(binding)
    active_gate = len(gates) == 1 and gates[0].get("mode") == (
        "registered_launch_required"
    )
    eligibility: dict[str, tuple[bool | None, str]] = {}
    for item in queue_items:
        dispatch = item.payload
        dispatch_id = str(dispatch["dispatch_request_id"])
        if historical:
            eligibility[dispatch_id] = (None, "historical_time_basis_unavailable")
            continue
        if completeness != "complete":
            eligibility[dispatch_id] = (None, "projection_incomplete")
            continue
        if isinstance(item, UncertainDispatch):
            eligibility[dispatch_id] = (None, "dispatch_receipt_uncertain")
            continue
        if dispatch.get("state") == "effect_unknown":
            eligibility[dispatch_id] = (None, "dispatch_effect_unknown")
            continue
        if dispatch.get("state") != "admitted":
            eligibility[dispatch_id] = (False, "dispatch_not_admitted")
            continue
        candidates = bindings_by_dispatch.get(dispatch_id, [])
        if len(candidates) != 1:
            eligibility[dispatch_id] = (False, "registered_binding_missing_or_ambiguous")
            continue
        binding = candidates[0]
        task = tasks_by_revision.get(str(binding.get("task_revision_id")))
        packet = packets_by_id.get(str(binding.get("packet_id")))
        if task is None or packet is None:
            eligibility[dispatch_id] = (False, "registered_task_or_packet_missing")
            continue
        exact = (
            binding.get("dispatch_revision_id") == dispatch.get("dispatch_revision_id")
            and binding.get("task_id") == task.get("task_id")
            and binding.get("task_sha256") == task.get("task_sha256")
            and binding.get("task_id") == packet.get("task_id")
            and binding.get("task_revision_id") == packet.get("task_revision_id")
            and binding.get("task_sha256") == packet.get("task_sha256")
            and binding.get("packet_sha256") == packet.get("packet_sha256")
        )
        if not exact:
            eligibility[dispatch_id] = (False, "registered_binding_mismatch")
            continue
        if not active_gate:
            eligibility[dispatch_id] = (False, "registered_launch_gate_inactive")
            continue
        # Canonical UTC strings preserve chronological ordering.
        if str(binding.get("expires_at", "")) <= now:
            eligibility[dispatch_id] = (False, "registered_binding_expired")
            continue
        eligibility[dispatch_id] = (True, "registered_work_definition_admitted")

    def task_metadata(item: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: item.get(key)
            for key in (
                "task_id", "task_revision_id", "revision", "display_name",
                "objective", "created_at", "task_sha256",
            )
        }

    def packet_metadata(item: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: item.get(key)
            for key in (
                "packet_id", "parent_packet_id", "task_id",
                "task_revision_id", "task_sha256", "manager_node_id",
                "parent_execution_id", "target_node_id", "department_id",
                "delegation_depth", "display_name", "objective", "created_at",
                "expires_at", "packet_sha256",
            )
        }

    def binding_metadata(item: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: item.get(key)
            for key in (
                "binding_id", "dispatch_request_id", "dispatch_revision_id",
                "task_id", "task_revision_id", "task_sha256", "packet_id",
                "packet_sha256", "department_id", "target_node_id",
                "manager_node_id", "parent_execution_id", "delegation_depth",
                "provider_allowlist", "created_at", "expires_at", "binding_sha256",
            )
        }

    def bounded_metadata(
        values: list[dict[str, Any]],
        *,
        identity_key: str,
        timestamp_key: str,
        projector: Callable[[Mapping[str, Any]], dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        ordered = sorted(
            values,
            key=lambda item: (
                str(item.get(timestamp_key, "")),
                str(item.get(identity_key, "")),
            ),
        )
        visible = len(ordered)
        returned = ordered[-_WORK_VIEW_LIMIT:]
        return (
            [projector(item) for item in returned],
            {
                "visible": visible,
                "returned": len(returned),
                "truncated": visible > len(returned),
                "limit": _WORK_VIEW_LIMIT,
            },
        )

    task_rows, task_summary = bounded_metadata(
        tasks,
        identity_key="task_revision_id",
        timestamp_key="created_at",
        projector=task_metadata,
    )
    packet_rows, packet_summary = bounded_metadata(
        packets,
        identity_key="packet_id",
        timestamp_key="created_at",
        projector=packet_metadata,
    )
    binding_rows, binding_summary = bounded_metadata(
        bindings,
        identity_key="binding_id",
        timestamp_key="created_at",
        projector=binding_metadata,
    )
    result_rows, result_summary = bounded_metadata(
        results,
        identity_key="result_receipt_id",
        timestamp_key="recorded_at",
        projector=lambda item: {
            key: item.get(key)
            for key in (
                "result_receipt_id", "task_id", "task_revision_id",
                "task_sha256", "packet_id", "packet_sha256",
                "producer_execution_id",
                "engineering_disposition_receipt_id", "recorded_at",
                "receipt_sha256",
            )
        },
    )

    return ({
        "scope": "a4_read_only_work_truth_backend",
        "environment": {
            "environment_kind": environment_kind,
            "source": environment_source,
            "provider_live_verified": False,
            "reason": "provider_live_verification_not_implemented",
        },
        "provider_worker": {
            "state": "unavailable",
            "reason": "provider_worker_not_implemented",
        },
        "gate": {
            "active": active_gate if not historical else None,
            "reason": (
                "historical_time_basis_unavailable" if historical
                else ("registered_launch_gate_active" if active_gate
                      else "registered_launch_gate_inactive_or_ambiguous")
            ),
            "records": [
                {key: gate.get(key) for key in (
                    "gate_id", "mode", "activated_at", "enforcement_sha256",
                )}
                for gate in gates
            ],
        },
        "tasks": task_rows,
        "packets": packet_rows,
        "bindings": binding_rows,
        "results": result_rows,
        "collection_summary": {
            "tasks": task_summary,
            "packets": packet_summary,
            "bindings": binding_summary,
            "results": result_summary,
        },
        "launch_eligibility_semantics": (
            "registered_work_gate_only; provider_worker_unavailable"
        ),
    }, eligibility)


def _event_view(record: LedgerTransactionRecord) -> dict[str, Any]:
    return {
        "cursor": record.global_sequence,
        "transaction_id": str(record.request["transaction_id"]),
        "command_id": str(record.request["command_id"]),
        "state": str(record.receipt["state"]),
        "recorded_at": str(record.receipt["recorded_at"]),
        "events": [
            {
                "event_id": str(member.event["event_id"]),
                "event_type": str(member.event["event_type"]),
                "stream": str(member.event["stream"]),
                "stream_sequence": member.stream_sequence,
                "recorded_at": str(member.event["recorded_at"]),
                "provenance": str(member.event["provenance"]),
                "contract_type": str(member.event["payload"]["contract_type"]),
                "payload": _redact_view(_plain(member.event["payload"])),
            }
            for member in record.events
        ],
    }


def _execution_graph(
    nodes: list[dict[str, Any]],
) -> tuple[list[str], dict[str, list[str]], list[dict[str, str]]]:
    counts: dict[str, int] = {}
    for node in nodes:
        execution_id = node.get("execution_id")
        if isinstance(execution_id, str):
            counts[execution_id] = counts.get(execution_id, 0) + 1
    by_id = {
        str(node["execution_id"]): node
        for node in nodes
        if isinstance(node.get("execution_id"), str)
        and counts[str(node["execution_id"])] == 1
    }
    validity: dict[str, str | None] = {}

    def validate(execution_id: str, visiting: set[str]) -> str | None:
        known = validity.get(execution_id)
        if execution_id in validity:
            return known
        if execution_id in visiting:
            validity[execution_id] = "execution_cycle"
            return "execution_cycle"
        node = by_id[execution_id]
        depth = node.get("execution_depth")
        path = node.get("execution_path")
        parent_id = node.get("parent_execution_id")
        if (
            not isinstance(depth, int)
            or isinstance(depth, bool)
            or depth < 0
            or not isinstance(path, list)
            or not all(isinstance(member, str) for member in path)
            or len(path) != depth + 1
            or not path
            or path[-1] != execution_id
        ):
            validity[execution_id] = "execution_path_invalid"
            return "execution_path_invalid"
        if parent_id is None:
            reason = (
                None
                if depth == 0 and path == [execution_id]
                else "root_ancestry_invalid"
            )
            validity[execution_id] = reason
            return reason
        if not isinstance(parent_id, str) or parent_id not in by_id:
            validity[execution_id] = "parent_missing"
            return "parent_missing"
        parent_reason = validate(parent_id, {*visiting, execution_id})
        if parent_reason is not None:
            validity[execution_id] = "ancestor_invalid"
            return "ancestor_invalid"
        parent = by_id[parent_id]
        parent_path = parent.get("execution_path")
        parent_depth = parent.get("execution_depth")
        if (
            not isinstance(parent_path, list)
            or not isinstance(parent_depth, int)
            or isinstance(parent_depth, bool)
            or depth != parent_depth + 1
            or path != [*parent_path, execution_id]
        ):
            validity[execution_id] = "parent_path_mismatch"
            return "parent_path_mismatch"
        validity[execution_id] = None
        return None

    for execution_id in by_id:
        validate(execution_id, set())

    invalid: list[dict[str, str]] = []
    for node in nodes:
        raw_id = node.get("execution_id")
        if not isinstance(raw_id, str):
            invalid.append({
                "execution_id": "unknown",
                "reason": "execution_id_invalid",
            })
        elif counts.get(raw_id, 0) != 1:
            invalid.append({
                "execution_id": raw_id,
                "reason": "execution_id_duplicate",
            })
        elif validity[raw_id] is not None:
            invalid.append({
                "execution_id": raw_id,
                "reason": str(validity[raw_id]),
            })

    valid_ids = {
        execution_id
        for execution_id, reason in validity.items()
        if reason is None
    }

    def order_key(execution_id: str) -> tuple[str, str]:
        node = by_id[execution_id]
        return str(node.get("created_at", "")), execution_id

    roots = sorted(
        (
            execution_id
            for execution_id in valid_ids
            if by_id[execution_id].get("parent_execution_id") is None
        ),
        key=order_key,
    )
    children: dict[str, list[str]] = {
        execution_id: []
        for execution_id in valid_ids
    }
    for execution_id in valid_ids:
        parent_id = by_id[execution_id].get("parent_execution_id")
        if isinstance(parent_id, str) and parent_id in children:
            children[parent_id].append(execution_id)
    for child_ids in children.values():
        child_ids.sort(key=order_key)
    invalid.sort(key=lambda item: (item["execution_id"], item["reason"]))
    return roots, children, invalid


def _execution_descendant_counts(
    children: Mapping[str, list[str]],
) -> dict[str, int]:
    """Count descendants only in the validated execution tree."""

    counts: dict[str, int] = {}

    def count(execution_id: str) -> int:
        child_ids = children.get(execution_id)
        if child_ids is None:
            return 0
        total = 0
        for child_id in child_ids:
            total += 1 + count(child_id)
        counts[execution_id] = total
        return total

    for execution_id in children:
        count(execution_id)
    return counts


def _execution_orphans(
    nodes: list[dict[str, Any]],
    invalid_nodes: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """Keep unbound or graph-invalid execution visible without reparenting it."""

    invalid_reasons = {
        item["execution_id"]: item["reason"]
        for item in invalid_nodes
    }
    orphans: list[dict[str, Any]] = []
    for node in nodes:
        execution_id = node.get("execution_id")
        if not isinstance(execution_id, str):
            continue
        reason = invalid_reasons.get(execution_id)
        if reason is None and type(node.get("bridge_scope_id")) is str:
            reason = node.get("orphan_reason")
        elif reason is None and node.get("organization_node_id") is None:
            reason = "organization_node_missing"
        if reason is not None:
            orphans.append({
                **node,
                "orphan_reason": reason,
                "projection_source": node.get("projection_source", "derived_read_only"),
            })
    orphans.sort(
        key=lambda node: (
            str(node.get("created_at", "")),
            str(node.get("execution_id", "")),
            str(node.get("orphan_reason", "")),
        ),
    )
    return orphans


def _telemetry_orphans(
    receipts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Project unbound provider observations without inventing executions."""

    result: list[dict[str, Any]] = []
    for receipt in receipts:
        join = receipt.get("dispatch_join")
        binding = join if isinstance(join, Mapping) else {}
        state = binding.get("state")
        if state == "exact":
            continue
        receipt_id = receipt.get("receipt_id")
        if not isinstance(receipt_id, str):
            continue
        reason = (
            "provider_telemetry_attribution_ambiguous"
            if state == "ambiguous"
            else "provider_telemetry_unattributed"
        )
        result.append({
            "execution_id": f"unattributed-{receipt_id}",
            "receipt_id": receipt_id,
            "display_name": "Unattributed provider telemetry",
            "role": "unattributed",
            "execution_kind": "provider_telemetry",
            "engineering_status": "unknown",
            "runtime_status": "unknown",
            "orphan_reason": reason,
            "projection_source": "provider_telemetry_receipt",
            "created_at": receipt.get("received_at"),
            "provider": receipt.get("provider"),
            "objective": receipt.get("normalized_kind"),
            "observation": _plain(receipt.get("observation", {})),
        })
    result.sort(
        key=lambda item: (
            str(item.get("created_at", "")),
            str(item.get("receipt_id", "")),
        ),
    )
    return result


def _derived_execution_orphan_alerts(
    orphans: list[dict[str, Any]],
    ledger_alerts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Append deterministic, non-persistent alerts for visible orphan nodes."""

    alert_ids = {
        alert_id
        for alert in ledger_alerts
        if isinstance((alert_id := alert.get("alert_id")), str)
    }
    derived: list[dict[str, Any]] = []
    for orphan in orphans:
        execution_id = orphan.get("execution_id")
        reason = orphan.get("orphan_reason")
        if not isinstance(execution_id, str) or not isinstance(reason, str):
            continue
        category = (
            "provider_telemetry_unattributed"
            if orphan.get("projection_source")
            == "provider_telemetry_receipt"
            else "execution_orphan"
        )
        identity = {
            "category": category,
            "execution_id": execution_id,
            "reason": reason,
        }
        base_alert_id = (
            "derived-read-only-execution-orphan-"
            + company_contract_sha256(identity)
        )
        alert_id = base_alert_id
        collision = 0
        while alert_id in alert_ids:
            collision += 1
            alert_id = (
                base_alert_id
                + "-"
                + company_contract_sha256({
                    "identity": identity,
                    "collision": collision,
                })[:16]
            )
        alert_ids.add(alert_id)
        created_at = orphan.get("created_at")
        derived.append({
            "alert_id": alert_id,
            "execution_id": execution_id,
            "severity": "critical",
            "state": "open",
            "category": category,
            "created_at": created_at if isinstance(created_at, str) else None,
            "resolved_at": None,
            "detail_sha256": company_contract_sha256(identity),
            "observation": {"state": "known", "reason": "observed"},
            "orphan_reason": reason,
            "projection_source": "derived_read_only",
        })
    return derived


class CompanyViewService:
    """Serve current and incremental read-only company projections."""

    def __init__(
        self,
        state: CompanyStateOwner,
        *,
        clock: Callable[[], str] = _utc_now,
        environment_kind: str = "unverified",
    ) -> None:
        if environment_kind not in _ENVIRONMENT_KINDS:
            raise CompanyViewError("Dashboard environment kind is invalid")
        self._state = state
        self._clock = clock
        self._environment_kind = environment_kind
        self._environment_source = (
            "default_unverified"
            if environment_kind == "unverified"
            else "explicit_configuration"
        )

    def _needs_user_question_summary(
        self,
        revision: Mapping[str, Any],
    ) -> tuple[str | None, str, str]:
        reference = revision.get("question_blob")
        if not isinstance(reference, Mapping):
            return None, "unavailable", "summary_source_reference_unavailable"
        digest = reference.get("sha256")
        if not isinstance(digest, str):
            return None, "unavailable", "summary_source_reference_unavailable"
        try:
            raw = self._state.blobs.read(digest)
            document = json.loads(raw.decode("utf-8", "strict"))
            if (
                not isinstance(document, Mapping)
                or canonical_company_json_bytes(document) != raw
                or document.get("schema_version") != 1
                or document.get("content_type") != "question"
                or not isinstance(document.get("text"), str)
                or not document["text"]
            ):
                raise CompanyViewError(
                    "needs-user question blob is not canonical",
                )
            return (
                _bounded_question_summary(str(document["text"])),
                "derived",
                "bounded_local_question_content",
            )
        except (
            CompanyViewError,
            FileNotFoundError,
            AttributeError,
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ):
            return None, "unavailable", "summary_source_unavailable_or_invalid"

    def _snapshot_data(
        self,
        *,
        include_export_bundle: bool = False,
        query: CompanyQuerySnapshot | None = None,
    ) -> tuple[str, int, str, list[str], dict[str, Any]]:
        live_question_summaries = query is None
        if query is None:
            query = self._state.query_snapshot()
        health = query.health
        objects = query.objects
        uncertain_dispatches = query.uncertain_dispatches
        manifests = _payloads(objects, COMPANY_MANIFEST_V1)
        manifest = _first_or_none(manifests)
        company_id = (
            str(manifest["company_id"])
            if manifest is not None
            else str(self._state.resolved.manifest["company_id"])
        )
        completeness = "complete" if health.status == "ready" else "partial"
        warnings: list[str] = []
        if health.status != "ready":
            warnings.append("company_state_degraded")
        warnings.extend(
            reason
            for reason in health.degradation_reasons
            if reason not in warnings
        )
        warnings.extend(
            reason
            for reason in query.delivery.warnings
            if reason not in warnings
        )
        if manifest is None:
            completeness = "partial"
            warnings.append("company_manifest_not_projected")
        historical_context: dict[str, Any] | None = None
        if health.projection_status == "historical_prefix_replay":
            warnings.append(
                "historical_projection_uses_refresh_observer_health",
            )
            historical_context = {
                "ledger_projection": "exact_committed_prefix",
                "organization_execution_job_semantics": (
                    "requested_cursor"
                ),
                "observer_health_semantics": (
                    "captured_when_replay_input_was_frozen"
                ),
                "raw_content_semantics": "not_replayed",
            }

        organization = _payloads(objects, ORGANIZATION_NODE_V1)
        department_identities = _payloads(objects, DEPARTMENT_IDENTITY_V1)
        department_snapshots = _payloads(objects, DEPARTMENT_SNAPSHOT_V1)
        dispatches = _payloads(objects, DISPATCH_REQUEST_V1)
        snapshot_by_department = {
            str(item["department_id"]): item
            for item in department_snapshots
        }
        departments = [
            {
                **identity,
                "snapshot": snapshot_by_department.get(
                    str(identity["department_id"]),
                ),
            }
            for identity in department_identities
        ]
        try:
            legacy_bridge = project_legacy_bridge_dashboard(
                _payloads(objects, bc.LEGACY_BRIDGE_OBSERVATION_V1),
                _payloads(objects, bh.LEGACY_BRIDGE_COVERAGE_V1),
                _payloads(objects, bj.LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1),
            )
        except LegacyBridgeViewError as exc:
            raise CompanyViewError("legacy bridge Dashboard projection is invalid") from exc
        if legacy_bridge.coverage_degraded:
            completeness = "partial"
        warnings.extend(x for x in legacy_bridge.warnings if x not in warnings)
        execution_nodes = [*_payloads(objects, EXECUTION_NODE_V1), *legacy_bridge.nodes]
        execution_events = _payloads(objects, EXECUTION_EVENT_V1)
        telemetry_receipts = _payloads(
            objects,
            PROVIDER_TELEMETRY_RECEIPT_V1,
        )
        execution_roots, execution_children, invalid_executions = (
            _execution_graph(execution_nodes)
        )
        execution_descendant_counts = _execution_descendant_counts(
            execution_children,
        )
        execution_orphans = [
            *_execution_orphans(
                execution_nodes,
                invalid_executions,
            ),
            *_telemetry_orphans(telemetry_receipts),
        ]
        if execution_orphans:
            completeness = "partial"
            warnings.append("execution_orphan_detected")
        if invalid_executions:
            completeness = "partial"
            warnings.append("execution_graph_invalid")
        try:
            invariants = reduce_company_invariants(
                _invariant_objects(
                    objects,
                    excluded_execution_ids=frozenset(
                        str(node["execution_id"])
                        for node in execution_orphans
                    ),
                ),
                uncertain_dispatches,
            )
        except CompanyInvariantError as exc:
            raise CompanyViewError(
                "company dispatch projection violates invariants",
            ) from exc
        capacity_reason = _capacity_reason(
            health_status=health.status,
            completeness=completeness,
            manager_capacity_complete=invariants.manager_capacity_complete,
            unattributed_active=invariants.unattributed_active,
        )
        company_available = (
            None
            if capacity_reason is not None
            else MAX_ACTIVE_CARRIERS - invariants.company_capacity
        )
        manager_capacity = dict(invariants.manager_capacity)
        organization_ids = {
            str(item["node_id"])
            for item in organization
            if isinstance(item.get("node_id"), str)
        }
        for department in departments:
            lead_node_id = department.get("lead_node_id")
            lead_key = lead_node_id if isinstance(lead_node_id, str) else None
            manager_reason = capacity_reason
            if lead_key is None or lead_key not in organization_ids:
                manager_reason = "department_lead_unavailable"
            if manager_reason is not None:
                occupied: int | None = None
            else:
                # A clear reason requires a projected department lead.
                assert lead_key is not None
                occupied = manager_capacity.get(lead_key, 0)
            department["manager_capacity"] = {
                "manager_node_id": lead_key,
                "occupied": occupied,
                "limit": MAX_MANAGER_ACTIVE_FANOUT,
                "available": (
                    None
                    if occupied is None
                    else MAX_MANAGER_ACTIVE_FANOUT - occupied
                ),
                "reason": manager_reason,
            }
        tasks = _payloads(objects, TASK_REVISION_V1)
        work_packets = _payloads(objects, WORK_PACKET_V1)
        work_bindings = _payloads(objects, WORK_DISPATCH_BINDING_V1)
        work_gates = _payloads(objects, WORK_DEFINITION_ENFORCEMENT_V1)
        work_results = _payloads(objects, WORK_RESULT_RECEIPT_V1)
        work, work_eligibility = _work_view(
            tasks=tasks,
            packets=work_packets,
            bindings=work_bindings,
            gates=work_gates,
            results=work_results,
            queue_items=invariants.queue_items,
            completeness=completeness,
            historical=health.projection_status == "historical_prefix_replay",
            now=self._clock(),
            environment_kind=self._environment_kind,
            environment_source=self._environment_source,
        )
        dispatch_queue, queue_summary = _queue_view(
            invariants.queue_items,
            completeness=(
                "complete" if capacity_reason is None else "partial"
            ),
            reason=capacity_reason,
            eligibility=work_eligibility,
        )
        jobs = [*_payloads(objects, EXTERNAL_JOB_V1), *legacy_bridge.jobs]
        evidence_records = _payloads(objects, EVIDENCE_RECORD_V1)
        provider_receipts = [
            item
            for item in objects
            if item.contract_type == PROVIDER_LIFECYCLE_RECEIPT_V1
        ]
        provider_lifecycle_receipts, provider_lifecycle_receipt_summary = (
            _provider_lifecycle_receipts_view(provider_receipts)
        )
        external_job_effect_receipts = _payloads(
            objects,
            EXTERNAL_JOB_EFFECT_RECEIPT_V1,
        )
        artifact_edges = _payloads(objects, ARTIFACT_EDGE_V1)
        coverage_revisions = _payloads(
            objects,
            PROVIDER_COVERAGE_REVISION_V1,
        )
        usage_counter_samples = _payloads(objects, USAGE_COUNTER_SAMPLE_V1)
        alerts = _payloads(objects, ALERT_V1)
        alerts = [
            *alerts,
            *_derived_execution_orphan_alerts(execution_orphans, alerts),
            *legacy_bridge.alerts,
        ]
        needs_user_revisions = _payloads(objects, NEEDS_USER_REVISION_V1)
        latest_needs_user_revisions: dict[str, dict[str, Any]] = {}
        for revision in needs_user_revisions:
            item_id = revision.get("item_id")
            if not isinstance(item_id, str):
                continue
            previous = latest_needs_user_revisions.get(item_id)
            current_key = (
                int(revision.get("revision", -1)),
                str(revision.get("updated_at", "")),
                str(revision.get("revision_id", "")),
            )
            previous_key = (
                int(previous.get("revision", -1)),
                str(previous.get("updated_at", "")),
                str(previous.get("revision_id", "")),
            ) if previous is not None else None
            if previous_key is None or current_key > previous_key:
                latest_needs_user_revisions[item_id] = revision
        needs_user: list[dict[str, Any]] = []
        for item_id in sorted(latest_needs_user_revisions):
            revision = latest_needs_user_revisions[item_id]
            if live_question_summaries:
                summary, quality, reason = (
                    self._needs_user_question_summary(revision)
                )
            else:
                summary, quality, reason = (
                    None,
                    "unavailable",
                    "historical_raw_content_not_replayed",
                )
            needs_user.append(
                _needs_user_revision_view(
                    revision,
                    question_summary=summary,
                    summary_quality=quality,
                    summary_reason=reason,
                ),
            )
        needs_user.extend(
            _legacy_needs_user_view(item)
            for item in _payloads(objects, NEEDS_USER_V1)
            if item.get("item_id") not in latest_needs_user_revisions
        )
        all_coverage = _latest_coverage_revisions(coverage_revisions)
        overall_coverage = _coverage_summary(
            all_coverage,
            absent_reason="provider_adapters_not_yet_connected",
        )
        overall_coverage = merge_legacy_bridge_coverage(overall_coverage, legacy_bridge.summary)
        if health.blob_status != "ready":
            # A blob failure must remain visible in the Command Center.
            warning = {
                "state": "degraded",
                "reason": (
                    health.degradation_reasons[0]
                    if health.degradation_reasons
                    else "blob_store_not_ready"
                ),
            }
            overall_coverage["blob_health_warning"] = warning
            if overall_coverage.get("state") != "degraded":
                overall_coverage["provider_assessment"] = {
                    key: overall_coverage.get(key)
                    for key in ("state", "reason", "source", "quality")
                    if key in overall_coverage
                }
                overall_coverage.update({
                    "state": "degraded",
                    "reason": warning["reason"],
                    "source": "blob_health",
                    "quality": "known",
                })
        usage_coverage = _coverage_summary(
            _latest_coverage_revisions(coverage_revisions, surface="usage"),
            absent_reason="usage_adapter_not_yet_connected",
        )
        chief_terms = _payloads(objects, CHIEF_TERM_V1)
        carriers = _payloads(objects, CARRIER_BINDING_V1)
        authority_grants = _payloads(objects, AUTHORITY_GRANT_V1)
        takeover_receipts = _payloads(
            objects,
            TAKEOVER_CONSUMPTION_RECEIPT_V1,
        )
        active_terms = [
            term for term in chief_terms if term.get("state") == "active"
        ]
        current_term = max(
            active_terms,
            key=lambda term: (
                int(term.get("term", 0)),
                int(term.get("epoch", 0)),
            ),
            default=None,
        )
        carriers_by_id = {
            carrier_id: carrier
            for carrier in carriers
            if isinstance((carrier_id := carrier.get("carrier_id")), str)
        }
        current_carrier_id = (
            current_term.get("carrier_id")
            if current_term is not None
            else None
        )
        current_carrier = (
            carriers_by_id.get(current_carrier_id)
            if isinstance(current_carrier_id, str)
            else None
        )
        for node in execution_nodes:
            node["carrier_state"] = _carrier_state(
                node,
                carriers_by_id=carriers_by_id,
            )
        organization_by_id = {
            node_id: node
            for node in organization
            if isinstance((node_id := node.get("node_id")), str)
        }
        lifecycle_results: dict[str, Mapping[str, Any]] = {}
        for intent in _payloads(objects, CONTROL_INTENT_V1):
            result = intent.get("result_payload")
            if (
                not isinstance(result, Mapping)
                or result.get("result_type") != DEPARTMENT_LIFECYCLE_RESULT_V1
                or not isinstance(result.get("department_id"), str)
            ):
                continue
            department_id = str(result["department_id"])
            lifecycle_previous = lifecycle_results.get(department_id)
            if lifecycle_previous is None or (
                int(result.get("committed_cursor", -1)),
                str(result.get("command_id", "")),
            ) > (
                int(lifecycle_previous.get("committed_cursor", -1)),
                str(lifecycle_previous.get("command_id", "")),
            ):
                lifecycle_results[department_id] = result
        for department in departments:
            department_id = str(department["department_id"])
            lead_node_id = department.get("lead_node_id")
            lead = (
                organization_by_id.get(lead_node_id)
                if isinstance(lead_node_id, str)
                else None
            )
            lead_status = lead.get("status") if lead is not None else "unknown"
            department_executions = [
                node
                for node in execution_nodes
                if node.get("department_id") == department_id
                and (
                    lead_node_id is None
                    or node.get("organization_node_id") == lead_node_id
                )
            ]
            current_execution = _current_department_execution(
                department_executions,
            )
            latest_execution = max(
                department_executions,
                key=lambda execution: (
                    str(execution.get("updated_at", "")),
                    str(execution.get("execution_id", "")),
                ),
                default=None,
            )
            wake_dispatches = [
                dispatch
                for dispatch in dispatches
                if dispatch.get("department_id") == department_id
                and dispatch.get("target_node_id") == lead_node_id
            ]
            wake_dispatch = max(
                wake_dispatches,
                key=lambda dispatch: (
                    int(dispatch.get("revision", -1)),
                    str(dispatch.get("updated_at", "")),
                    str(dispatch.get("dispatch_revision_id", "")),
                ),
                default=None,
            )
            lifecycle_result = lifecycle_results.get(department_id)
            result_matches_wake = (
                lifecycle_result is not None
                and lifecycle_result.get("lifecycle_state") == "waking"
                and lifecycle_result.get("dispatch_request_id")
                == (None if wake_dispatch is None else wake_dispatch.get("dispatch_request_id"))
                and wake_dispatch is not None
                and wake_dispatch.get("state") in {"queued", "admitted", "in_flight"}
            )
            department_status = department.get("status")
            if department_status == "parked":
                lifecycle_state, lifecycle_reason = "parked", "department_parked"
            elif department_status != "active":
                lifecycle_state, lifecycle_reason = "unknown", "department_status_unknown"
            elif lead is None:
                lifecycle_state, lifecycle_reason = "unknown", "department_lead_unavailable"
            elif lead_status == "parked":
                lifecycle_state, lifecycle_reason = "unknown", "lead_parked_while_department_active"
            elif lead_status == "idle":
                lifecycle_state, lifecycle_reason = "idle", "lead_idle"
            elif current_execution is not None:
                lifecycle_state, lifecycle_reason = "active", "lead_execution_present"
            elif result_matches_wake:
                lifecycle_state, lifecycle_reason = "waking", "wake_dispatch_pending"
            elif wake_dispatch is not None and wake_dispatch.get("state") in {
                "failed_known",
                "failed",
            }:
                lifecycle_state, lifecycle_reason = "failed", "wake_dispatch_failed"
            elif wake_dispatch is not None and wake_dispatch.get("state") in {
                "effect_unknown",
                "reconcile_required",
            }:
                lifecycle_state, lifecycle_reason = (
                    "unknown",
                    "wake_dispatch_reconcile_required",
                )
            elif lead_status == "active":
                lifecycle_state, lifecycle_reason = "active", "department_and_lead_active"
            else:
                lifecycle_state, lifecycle_reason = "unknown", "lead_status_unknown"
            carrier_id = (
                current_execution.get("carrier_id")
                if current_execution is not None
                else (
                    latest_execution.get("carrier_id")
                    if latest_execution is not None and lifecycle_state != "failed"
                    else None
                )
            )
            carrier = (
                carriers_by_id.get(carrier_id)
                if isinstance(carrier_id, str)
                else None
            )
            department.update(
                {
                    "lifecycle_state": lifecycle_state,
                    "lifecycle_reason": lifecycle_reason,
                    "lead": {
                        "node_id": lead_node_id,
                        "organization_status": lead_status,
                    },
                    "current_execution": _department_execution_view(
                        current_execution,
                        descendant_count=(
                            None
                            if current_execution is None
                            else execution_descendant_counts.get(
                                str(current_execution["execution_id"]),
                            )
                        ),
                    ),
                    "snapshot": _department_snapshot_view(
                        snapshot_by_department.get(department_id),
                    ),
                    "carrier": _department_carrier_view(carrier),
                    "wake_dispatch": _department_dispatch_view(wake_dispatch),
                },
            )
        chief_grants = [
            _chief_authority_view(grant, current_term)
            for grant in authority_grants
            if grant.get("actor_kind") == "chief"
        ]
        chief_grants.sort(
            key=lambda grant: (
                str(grant.get("issued_at", "")),
                str(grant.get("grant_id", "")),
            ),
            reverse=True,
        )
        takeover_attempts = [
            _takeover_receipt_view(receipt)
            for receipt in takeover_receipts
            if receipt.get("outcome") in {"consumed", "fenced"}
        ]
        takeover_attempts.sort(
            key=lambda attempt: (
                str(attempt.get("consumed_at", "")),
                str(attempt.get("consumption_id", "")),
            ),
            reverse=True,
        )
        fenced_carriers = [
            _carrier_view(carrier)
            for carrier in carriers
            if carrier.get("state") == "fenced"
        ]

        data = {
            "meta": {
                "supervisor": {
                    "status": health.status,
                    "ledger_status": health.ledger_status,
                    "projection_status": health.projection_status,
                    "blob_status": health.blob_status,
                },
                "ledger": {
                    "cursor": health.ledger_heads.global_head.global_sequence,
                    "head_sha256": (
                        health.ledger_heads.global_head.transaction_sha256
                    ),
                    "stream_heads": {
                        stream: {
                            "cursor": cursor,
                            "event_sha256": digest,
                        }
                        for stream, (cursor, digest)
                        in health.ledger_heads.stream_heads.items()
                    },
                },
                "readmodel": {
                    "cursor": health.readmodel_head.global_sequence,
                    "head_sha256": health.readmodel_head.transaction_sha256,
                },
                "coverage": overall_coverage,
                "security": {
                    "surface": "loopback_get_sse_only",
                    "authentication": "unavailable",
                    "reason": "operational_alpha_authentication_deferred",
                },
                "historical_context": historical_context,
                "environment": work["environment"],
            },
            "company": {
                "manifest": manifest,
                "chief_terms": chief_terms,
                "carriers": carriers,
                "chief": {
                    "term": current_term,
                    "carrier": (
                        None
                        if current_carrier is None
                        else _carrier_view(current_carrier)
                    ),
                    "authority_grants": chief_grants,
                    "takeover_attempts": takeover_attempts,
                    "fenced_carriers": fenced_carriers,
                },
                "organization": organization,
                "capacity": {
                    "occupied": invariants.company_capacity,
                    "occupied_semantics": (
                        "exact"
                        if capacity_reason is None
                        else "lower_bound"
                    ),
                    "limit": MAX_ACTIVE_CARRIERS,
                    "available": company_available,
                    "reason": capacity_reason,
                    "unattributed_active": list(
                        invariants.unattributed_active,
                    ),
                },
            },
            "departments": departments,
            "execution": {
                "nodes": execution_nodes,
                "events": execution_events,
                "roots": execution_roots,
                "children": execution_children,
                "invalid_nodes": invalid_executions,
                "orphans": execution_orphans,
                "dispatch_queue": dispatch_queue,
                "queue_summary": queue_summary,
            },
            "jobs": jobs,
            "evidence": {
                "records": evidence_records,
                "provider_lifecycle_receipts": provider_lifecycle_receipts,
                "provider_lifecycle_receipt_summary": (
                    provider_lifecycle_receipt_summary
                ),
                "provider_telemetry_receipts": [
                    _provider_telemetry_receipt_view(receipt)
                    for receipt in telemetry_receipts
                ],
                "external_job_effect_receipts":
                    external_job_effect_receipts,
                "edges": artifact_edges,
                "legacy_bridge": legacy_bridge.summary,
            },
            "usage": {
                # Never aggregate cumulative samples or export legacy deltas.
                "counting_semantics": "non_additive_cumulative",
                "counter_samples": [
                    _usage_counter_sample_view(sample)
                    for sample in usage_counter_samples
                ],
                "coverage": usage_coverage,
            },
            "work": work,
            "optimizer": {
                "state": "unavailable",
                "reason": "optimizer_deferred_from_operational_alpha",
                "proposals": [],
            },
            "alerts": {
                "alerts": alerts,
                "needs_user": needs_user,
            },
        }
        data["export"] = _delivery_view(
            query.delivery,
            include_bundle=include_export_bundle,
        )
        data["snapshot"] = {
            key: value
            for key, value in data.items()
            if key != "snapshot"
        }
        return (
            company_id,
            health.ledger_heads.global_head.global_sequence,
            completeness,
            warnings,
            _redact_view(data),
        )

    def section(self, name: str) -> dict[str, Any]:
        """Return one API response envelope from one bounded current snapshot."""

        if name not in _SECTIONS:
            raise CompanyViewError(f"unknown company view section: {name}")
        company_id, cursor, completeness, warnings, data = (
            self._snapshot_data(
                include_export_bundle=name == "export",
            )
        )
        return {
            "schema_version": COMPANY_VIEW_SCHEMA_VERSION,
            "company_id": company_id,
            "cursor": cursor,
            "generated_at": self._clock(),
            "completeness": completeness,
            "warnings": warnings,
            "data": data[name],
        }

    def snapshot_at(self, cursor: int) -> dict[str, Any]:
        """Return one composite historical snapshot at an exact cursor."""

        return self.snapshot_from_replay(
            self._state.historical_replay_input(),
            cursor,
        )

    def historical_replay_input(self) -> CompanyHistoricalReplayInput:
        """Return owner-thread-frozen facts for a detached Dashboard replay."""

        return self._state.historical_replay_input()

    def snapshot_from_replay(
        self,
        replay: object,
        cursor: int,
    ) -> dict[str, Any]:
        """Render history from frozen facts without opening active state."""

        if not isinstance(replay, CompanyHistoricalReplayInput):
            raise CompanyViewError(
                "historical replay input has an invalid type",
            )
        query = CompanyStateOwner.project_historical_replay(replay, cursor)
        company_id, historical_cursor, completeness, warnings, data = (
            self._snapshot_data(query=query)
        )
        if historical_cursor != cursor:
            raise CompanyViewError(
                "historical snapshot cursor differs from requested cursor",
            )
        return {
            "schema_version": COMPANY_VIEW_SCHEMA_VERSION,
            "company_id": company_id,
            "cursor": historical_cursor,
            "generated_at": self._clock(),
            "completeness": completeness,
            "warnings": warnings,
            "data": data["snapshot"],
        }

    def events_after(
        self,
        cursor: int,
        *,
        limit: int = 256,
    ) -> tuple[dict[str, Any], ...]:
        """Return bounded ledger transactions after one exact global cursor."""

        if (
            not isinstance(cursor, int)
            or isinstance(cursor, bool)
            or cursor < 0
        ):
            raise CompanyViewError("event cursor must be a non-negative integer")
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or limit < 1
            or limit > 1024
        ):
            raise CompanyViewError("event limit must be between 1 and 1024")
        return tuple(
            _event_view(record)
            for record in self._state.records_after(cursor, limit=limit)
        )


__all__ = [
    "COMPANY_VIEW_SCHEMA_VERSION",
    "CompanyViewError",
    "CompanyViewService",
]
