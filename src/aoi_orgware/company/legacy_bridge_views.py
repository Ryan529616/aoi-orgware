"""Truth-preserving Dashboard projections for legacy bridge observations.

The durable legacy observation remains the source of truth.  This module only
derives read-only rows for existing Dashboard surfaces; it never creates native
execution, job, dispatch, or mutation authority.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple

from .contracts import company_contract_sha256
from .legacy_bridge_contract import validate_legacy_bridge_observation
from .legacy_bridge_health import validate_legacy_bridge_coverage
from .legacy_bridge_job_terminal import validate_legacy_bridge_job_terminal_receipt


class LegacyBridgeViewError(RuntimeError):
    """A legacy observation cannot be projected without weakening truth."""


class LegacyBridgeDashboardProjection(NamedTuple):
    nodes: tuple[dict[str, Any], ...]
    jobs: tuple[dict[str, Any], ...]
    orphans: tuple[dict[str, Any], ...]
    alerts: tuple[dict[str, Any], ...]
    summary: dict[str, Any]
    warnings: tuple[str, ...]
    coverage_degraded: bool


def _view_id(scope_id: str, bridge_entity_id: str) -> str:
    digest = company_contract_sha256({
        "domain": "aoi.legacy-bridge.dashboard-entity.v1",
        "bridge_scope_id": scope_id,
        "bridge_entity_id": bridge_entity_id,
    })
    return f"legacy-bridge-{digest}"


def _alert_id(scope_id: str, category: str, entity_id: str | None) -> str:
    digest = company_contract_sha256({
        "domain": "aoi.legacy-bridge.dashboard-alert.v1",
        "bridge_scope_id": scope_id,
        "category": category,
        "bridge_entity_id": entity_id,
    })
    return f"legacy-bridge-alert-{digest}"


def _alert(
    *,
    scope_id: str,
    category: str,
    created_at: str,
    severity: str,
    reason: str,
    node: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    bridge_entity_id = (
        str(node["bridge_entity_id"]) if node is not None else None
    )
    identity = {
        "domain": "aoi.legacy-bridge.dashboard-alert-detail.v1",
        "bridge_scope_id": scope_id,
        "category": category,
        "bridge_entity_id": bridge_entity_id,
        "reason": reason,
    }
    return {
        "alert_id": _alert_id(scope_id, category, bridge_entity_id),
        "execution_id": None if node is None else node["execution_id"],
        "severity": severity,
        "state": "open",
        "category": category,
        "created_at": created_at,
        "resolved_at": None,
        "detail_sha256": company_contract_sha256(identity),
        "observation": {
            "state": "known",
            "reason": "derived_from_validated_legacy_observation",
        },
        "orphan_reason": reason if category == "legacy_bridge_orphan" else None,
        "projection_source": "legacy_bridge_observation",
    }


def _validated_by_scope(
    values: Sequence[Mapping[str, Any]],
    *,
    coverage: bool,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    validator = (
        validate_legacy_bridge_coverage
        if coverage
        else validate_legacy_bridge_observation
    )
    for value in values:
        try:
            item = validator(value)
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise LegacyBridgeViewError(
                "legacy bridge projected object is invalid",
            ) from exc
        scope_id = str(item["bridge_scope_id"])
        if scope_id in result:
            raise LegacyBridgeViewError(
                "legacy bridge projection contains an ambiguous scope",
            )
        result[scope_id] = item
    return result


def _lineages(
    scope_id: str,
    entities: Sequence[Mapping[str, Any]],
) -> dict[str, tuple[str, ...]]:
    by_id = {str(item["bridge_entity_id"]): item for item in entities}
    cached: dict[str, tuple[str, ...]] = {}
    for entity_id in by_id:
        trail: list[str] = []
        current_id: str | None = entity_id
        while current_id is not None and current_id not in cached:
            trail.append(current_id)
            parent = by_id[current_id]["parent_bridge_entity_id"]
            current_id = None if parent is None else str(parent)
        lineage = () if current_id is None else cached[current_id]
        for item_id in reversed(trail):
            lineage = (*lineage, _view_id(scope_id, item_id))
            cached[item_id] = lineage
    return cached


def _node(
    observation: Mapping[str, Any],
    entity: Mapping[str, Any],
    path: tuple[str, ...],
) -> dict[str, Any]:
    scope_id = str(observation["bridge_scope_id"])
    bridge_entity_id = str(entity["bridge_entity_id"])
    parent = entity["parent_bridge_entity_id"]
    kind = str(entity["kind"])
    return {
        "execution_id": _view_id(scope_id, bridge_entity_id),
        "execution_kind": f"legacy_{kind}",
        "display_name": f"Legacy {kind} {bridge_entity_id[:12]}",
        "role": f"legacy_{kind}",
        "objective": None,
        "phase": None,
        "parent_execution_id": (
            None if parent is None else _view_id(scope_id, str(parent))
        ),
        "execution_depth": len(path) - 1,
        "execution_path": list(path),
        "engineering_status": entity["engineering_status"],
        "runtime_status": entity["runtime_status"],
        "coverage_status": entity["coverage_status"],
        "effect_status": entity["effect_status"],
        "carrier_state": "unknown",
        "carrier_id": None,
        "provider": "unknown",
        "model": None,
        "department_id": None,
        "target_node_id": None,
        "created_at": None,
        "updated_at": observation["ingested_at"],
        "needs_user": entity["needs_user"],
        "orphan_reason": entity["orphan_reason"],
        "stated_status": entity["stated_status"],
        "bridge_scope_id": scope_id,
        "bridge_entity_id": bridge_entity_id,
        "legacy_identity_digest": entity["legacy_identity_digest"],
        "source_record_sha256": entity["source_record_sha256"],
        "receipt_refs": list(entity["receipt_refs"]),
        "observation_id": observation["observation_id"],
        "observation": {
            "state": "unknown",
            "reason": "legacy_provider_runtime_unavailable",
        },
        "projection_source": "legacy_bridge_observation",
        "projection_provenance": observation["projection"][
            "projection_provenance"
        ],
        "authority": "none",
    }


def _job(node: Mapping[str, Any]) -> dict[str, Any]:
    terminal = node.get("terminal_receipt_id") is not None
    return {
        "job_id": node["execution_id"],
        "owner_execution_id": node["parent_execution_id"],
        "state": node["stated_status"],
        "engineering_status": node["engineering_status"],
        "runtime_status": node["runtime_status"],
        "coverage_status": node["coverage_status"],
        "effect_status": node["effect_status"],
        "mutation_intent_id": None,
        "command_id": None,
        "scope_sha256": None,
        "external_handle": {"availability": "unavailable"},
        "process_observation": ({
            "state": "known",
            "reason": "registered_job_process_nonzero_exit_reconciled",
        } if terminal else {
            "state": "unknown",
            "reason": "legacy_provider_runtime_unavailable",
        }),
        "effect_evidence": (
            [node["terminal_raw_artifact"]] if terminal else []
        ),
        "observation": ({
            "state": "known",
            "reason": "legacy_registered_process_nonzero_exit_reconciled",
        } if terminal else {
            "state": "unknown",
            "reason": "legacy_state_inventory_only_provider_runtime_unavailable",
        }),
        "bridge_scope_id": node["bridge_scope_id"],
        "bridge_entity_id": node["bridge_entity_id"],
        "source_record_sha256": node["source_record_sha256"],
        "projection_source": node["projection_source"],
        "authority": "none",
    }


def _terminal_overlay(
    node: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        **dict(node),
        "engineering_status": "blocked",
        "runtime_status": "stopped",
        "coverage_status": "degraded",
        "effect_status": "failed_known",
        "updated_at": receipt["observed_at"],
        "observation": dict(receipt["observation"]),
        "projection_source": "legacy_bridge_terminal_receipt",
        "terminal_receipt_id": receipt["receipt_id"],
        "terminal_receipt_sha256": receipt["receipt_sha256"],
        "terminal_source_observation_id": receipt["source_observation_id"],
        "terminal_raw_artifact": dict(receipt["raw_artifact"]),
    }


def _terminal_conflicts(
    observation: Mapping[str, Any],
    entity: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> bool:
    projection = observation["projection"]
    entities = {
        item["bridge_entity_id"]: item for item in projection["entities"]
    }
    task = entities.get(receipt["task_bridge_entity_id"])
    packet = entities.get(receipt["owner_packet_bridge_entity_id"])
    return any((
        receipt["company_id"] != observation["company_id"],
        receipt["company_incarnation"] != observation["company_incarnation"],
        receipt["lock_domain_generation"] != observation["lock_domain_generation"],
        receipt["bridge_scope_id"] != observation["bridge_scope_id"],
        receipt["legacy_archive_sha256"] != projection["legacy_archive_sha256"],
        receipt["task_identity_digest"] != projection["task_identity_digest"],
        receipt["task_bridge_entity_id"]
        != projection["task_bridge_entity_id"],
        task is None,
        task is not None and (
            task["kind"] != "task"
            or task["source_record_sha256"]
            != receipt["task_source_record_sha256"]
        ),
        receipt["job_bridge_entity_id"] != entity["bridge_entity_id"],
        receipt["job_source_record_sha256"] != entity["source_record_sha256"],
        receipt["owner_packet_bridge_entity_id"]
        != entity["parent_bridge_entity_id"],
        packet is None,
        packet is not None and (
            packet["kind"] != "packet"
            or packet["source_record_sha256"]
            != receipt["owner_packet_source_record_sha256"]
        ),
    ))


def project_legacy_bridge_dashboard(
    observations: Sequence[Mapping[str, Any]],
    coverages: Sequence[Mapping[str, Any]],
    terminal_receipts: Sequence[Mapping[str, Any]] = (),
) -> LegacyBridgeDashboardProjection:
    """Derive bounded Dashboard rows from validated read-model objects."""

    observed_by_scope = _validated_by_scope(observations, coverage=False)
    coverage_by_scope = _validated_by_scope(coverages, coverage=True)
    terminal_by_job: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in terminal_receipts:
        try:
            receipt = validate_legacy_bridge_job_terminal_receipt(raw)
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise LegacyBridgeViewError(
                "legacy terminal projected object is invalid",
            ) from exc
        key = (str(receipt["bridge_scope_id"]), str(receipt["job_bridge_entity_id"]))
        if key in terminal_by_job:
            raise LegacyBridgeViewError(
                "legacy terminal projection is ambiguous",
            )
        terminal_by_job[key] = receipt
    nodes: list[dict[str, Any]] = []
    jobs: list[dict[str, Any]] = []
    orphans: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    observation_rows: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()

    for scope_id in sorted(observed_by_scope):
        observation = observed_by_scope[scope_id]
        projection = observation["projection"]
        entities = projection["entities"]
        lineages = _lineages(scope_id, entities)
        observation_rows.append({
            "bridge_scope_id": scope_id,
            "observation_id": observation["observation_id"],
            "observation_sha256": observation["observation_sha256"],
            "projection_digest": projection["projection_digest"],
            "ingested_at": observation["ingested_at"],
            "observed_at": projection["observed_at"],
            "entity_count": len(entities),
        })
        for entity in entities:
            node = _node(
                observation,
                entity,
                lineages[str(entity["bridge_entity_id"])],
            )
            terminal_key = (scope_id, str(entity["bridge_entity_id"]))
            joined_receipt = (
                terminal_by_job.pop(terminal_key)
                if terminal_key in terminal_by_job else None
            )
            conflict = False
            if joined_receipt is not None:
                conflict = _terminal_conflicts(
                    observation, entity, joined_receipt,
                )
                if not conflict:
                    node = _terminal_overlay(node, joined_receipt)
            nodes.append(node)
            kind = str(entity["kind"])
            counts[kind] += 1
            if kind == "job":
                jobs.append(_job(node))
                if conflict and joined_receipt is not None:
                    alerts.append(_alert(
                        scope_id=scope_id,
                        category="legacy_bridge_terminal_conflict",
                        created_at=str(joined_receipt["observed_at"]),
                        severity="critical",
                        reason="terminal_receipt_current_source_conflict",
                        node=node,
                    ))
            if entity["orphan_reason"] is not None:
                orphans.append(dict(node))
            if entity["needs_user"] is True:
                alerts.append(_alert(
                    scope_id=scope_id,
                    category="needs_user",
                    created_at=str(observation["ingested_at"]),
                    severity="critical",
                    reason="legacy_needs_user_observed",
                    node=node,
                ))
            if entity["effect_status"] == "effect_unknown":
                alerts.append(_alert(
                    scope_id=scope_id,
                    category="effect_unknown",
                    created_at=str(observation["ingested_at"]),
                    severity="critical",
                    reason="legacy_job_effect_unknown",
                    node=node,
                ))

    coverage_rows = [
        {
            key: coverage[key]
            for key in (
                "bridge_scope_id", "assessment_id", "ingest_state",
                "coverage_state", "reason", "assessed_at", "observation_id",
                "coverage_completeness", "coverage_sha256",
            )
        }
        for _, coverage in sorted(coverage_by_scope.items())
    ]
    for (scope_id, _job_id), receipt in sorted(terminal_by_job.items()):
        alerts.append(_alert(
            scope_id=scope_id,
            category="legacy_bridge_terminal_conflict",
            created_at=str(receipt["observed_at"]),
            severity="critical",
            reason="terminal_receipt_current_entity_missing",
        ))
    for row in coverage_rows:
        alerts.append(_alert(
            scope_id=str(row["bridge_scope_id"]),
            category="legacy_bridge_coverage_degraded",
            created_at=str(row["assessed_at"]),
            severity="warning",
            reason=str(row["reason"]),
        ))

    warnings: list[str] = []
    if coverage_rows:
        warnings.append("legacy_bridge_coverage_degraded")
    if orphans:
        warnings.append("legacy_bridge_orphan_detected")
    if any(node["needs_user"] is True for node in nodes):
        warnings.append("legacy_bridge_needs_user_observed")
    if any(node["effect_status"] == "effect_unknown" for node in nodes):
        warnings.append("legacy_bridge_effect_unknown")
    if terminal_receipts:
        warnings.append("legacy_bridge_terminal_receipt_observed")
    if any(alert["category"] == "legacy_bridge_terminal_conflict" for alert in alerts):
        warnings.append("legacy_bridge_terminal_conflict")
    if terminal_by_job:
        warnings.append("legacy_bridge_terminal_without_current_entity")
    summary = {
        "state": "observed" if observation_rows else "unavailable",
        "reason": (
            "legacy_state_inventory_only_provider_runtime_unavailable"
            if observation_rows
            else "legacy_bridge_observation_unavailable"
        ),
        "projection_source": "legacy_bridge_observation",
        "projection_semantics": "read_only_derived_from_validated_observation",
        "authority": "none",
        "repo_write_capability": "absent",
        "dispatch_capability": "absent",
        "job_launch_capability": "absent",
        "runtime_truth": "unknown",
        "coverage_state": "degraded" if coverage_rows else "unavailable",
        "observations": observation_rows,
        "coverage": coverage_rows,
        "entity_counts": dict(sorted(counts.items())),
        "entity_count": sum(counts.values()),
        **({
            "terminal_receipt_count": len(terminal_receipts),
            "terminal_unjoined_count": len(terminal_by_job),
        } if terminal_receipts else {}),
    }
    return LegacyBridgeDashboardProjection(
        tuple(sorted(nodes, key=lambda item: str(item["execution_id"]))),
        tuple(sorted(jobs, key=lambda item: str(item["job_id"]))),
        tuple(sorted(orphans, key=lambda item: str(item["execution_id"]))),
        tuple(sorted(alerts, key=lambda item: str(item["alert_id"]))),
        summary,
        tuple(warnings),
        bool(coverage_rows),
    )


def merge_legacy_bridge_coverage(
    provider_coverage: Mapping[str, Any],
    legacy_summary: Mapping[str, Any],
) -> dict[str, Any]:
    """Add legacy coverage without erasing a stronger existing degradation."""

    merged = dict(provider_coverage)
    coverage = legacy_summary.get("coverage")
    if not isinstance(coverage, list) or not coverage:
        return merged
    merged["legacy_bridge"] = coverage
    if legacy_summary.get("coverage_state") == "degraded" and (
        merged.get("state") != "degraded"
    ):
        merged["provider_assessment"] = dict(provider_coverage)
        merged.update({
            "state": "degraded",
            "reason": "legacy_state_inventory_only_provider_runtime_unavailable",
            "source": "legacy_bridge_observation",
            "quality": "known",
        })
    return merged


__all__ = [
    "LegacyBridgeDashboardProjection",
    "LegacyBridgeViewError",
    "merge_legacy_bridge_coverage",
    "project_legacy_bridge_dashboard",
]
