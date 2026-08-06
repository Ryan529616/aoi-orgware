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
        "process_observation": {
            "state": "unknown",
            "reason": "legacy_provider_runtime_unavailable",
        },
        "effect_evidence": [],
        "observation": {
            "state": "unknown",
            "reason": "legacy_state_inventory_only_provider_runtime_unavailable",
        },
        "bridge_scope_id": node["bridge_scope_id"],
        "bridge_entity_id": node["bridge_entity_id"],
        "source_record_sha256": node["source_record_sha256"],
        "projection_source": "legacy_bridge_observation",
        "authority": "none",
    }


def project_legacy_bridge_dashboard(
    observations: Sequence[Mapping[str, Any]],
    coverages: Sequence[Mapping[str, Any]],
) -> LegacyBridgeDashboardProjection:
    """Derive bounded Dashboard rows from validated read-model objects."""

    observed_by_scope = _validated_by_scope(observations, coverage=False)
    coverage_by_scope = _validated_by_scope(coverages, coverage=True)
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
            nodes.append(node)
            kind = str(entity["kind"])
            counts[kind] += 1
            if kind == "job":
                jobs.append(_job(node))
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
