"""Crash-safe client for one observational legacy-v0.4 bridge ingest.

The client never starts a Supervisor and never mutates the legacy task.  It
serializes one bridge scope, publishes immutable client receipts outside the
repository, sends at most one mutation request for a prepared attempt, and
uses only the resident read-only prestart query to reconcile uncertainty.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NamedTuple, Protocol, cast

from .contracts import canonical_company_json_bytes, company_contract_sha256
from .discovery import BoundCompanyTarget, resolve_bound_company
from .legacy_bridge import LegacyBridgeProjectionV1, normalize_legacy_bridge_snapshot
from .legacy_bridge_client_receipt_contract import (
    PREPARED_SCHEMA,
    RECONCILIATION_SCHEMA,
    TERMINAL_SCHEMA,
    validate_reconciliation as _validate_reconciliation_receipt,
    validate_terminal as _validate_terminal_receipt,
)
from .legacy_bridge_client_receipts import (
    LegacyBridgeCapacityPublicationError,
    LegacyBridgeClientError,
    ReceiptAttempt as _Attempt,
    attempt_root as _attempt_root,
    ensure_scope_root as _ensure_scope_root,
    fail as _fail,
    identifier as _identifier,
    integer as _integer,
    inventory as _inventory,
    publish_exact as _publish_exact,
    require_attempt_capacity as _require_attempt_capacity,
    seal as _seal,
    sha as _sha,
    timestamp as _timestamp,
)
from .legacy_bridge_client_results import (
    LegacyBridgeIngestClientResult,
    attempt_result as _attempt_result,
    capacity_result as _capacity_result,
    terminal_none_result as _terminal_none_result,
)
from .legacy_bridge_contract import legacy_bridge_scope_id
from .legacy_bridge_control_protocol import (
    LEGACY_BRIDGE_PRESTART_RESULT_SCHEMA,
    LegacyBridgePrestartQueryCommand,
    LegacyBridgePrestartWireResultV1,
    build_legacy_bridge_prestart_query,
    decode_legacy_bridge_prestart_wire_result,
)
from .legacy_bridge_health import MAX_SOURCE_DOCUMENT_BYTES, legacy_bridge_attempt_id
from .legacy_bridge_ingest_protocol import (
    LEGACY_BRIDGE_INGEST_RESULT_SCHEMA,
    LegacyBridgeIngestCommand,
    LegacyBridgeIngestWireResultV1,
    build_legacy_bridge_ingest_command,
    decode_legacy_bridge_ingest_wire_result,
)
from .legacy_bridge_service_control import (
    LEGACY_BRIDGE_INGEST_ROUTE,
    LEGACY_BRIDGE_PRESTART_QUERY_ROUTE,
)
from .process_lock import CompanyProcessLock
from .service import (
    CompanyServiceOperationError,
    _control_operation_request,
    _resident_admin_descriptor,
)


class LegacyBridgeSourceLoader(Protocol):
    def __call__(
        self,
        company_id: str,
        company_incarnation: int,
        lock_domain_generation: int,
        observed_at: str,
    ) -> bytes: ...


class LegacyBridgeClientServices(Protocol):
    def resolve(self, repo_root: Path, company_id: str | None) -> BoundCompanyTarget: ...

    def descriptor(self, slot: Path) -> Mapping[str, Any]: ...

    def ingest(
        self,
        descriptor: Mapping[str, Any],
        command: LegacyBridgeIngestCommand,
        timeout_seconds: float,
    ) -> Mapping[str, Any]: ...

    def query(
        self,
        descriptor: Mapping[str, Any],
        command: LegacyBridgePrestartQueryCommand,
        timeout_seconds: float,
    ) -> Mapping[str, Any]: ...

    def now(self) -> str: ...


class _DefaultServices:
    def resolve(self, repo_root: Path, company_id: str | None) -> BoundCompanyTarget:
        return resolve_bound_company(repo_root, company_id)

    def descriptor(self, slot: Path) -> Mapping[str, Any]:
        return _resident_admin_descriptor(slot, runtime_root=None)

    def ingest(
        self,
        descriptor: Mapping[str, Any],
        command: LegacyBridgeIngestCommand,
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        return _control_operation_request(
            descriptor,
            path=LEGACY_BRIDGE_INGEST_ROUTE,
            token=str(descriptor["bearer_token"]),
            payload=command.as_dict(),
            timeout_seconds=timeout_seconds,
            expected_schema=LEGACY_BRIDGE_INGEST_RESULT_SCHEMA,
            mutation=True,
        )

    def query(
        self,
        descriptor: Mapping[str, Any],
        command: LegacyBridgePrestartQueryCommand,
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        return _control_operation_request(
            descriptor,
            path=LEGACY_BRIDGE_PRESTART_QUERY_ROUTE,
            token=str(descriptor["bearer_token"]),
            payload=command.as_dict(),
            timeout_seconds=timeout_seconds,
            expected_schema=LEGACY_BRIDGE_PRESTART_RESULT_SCHEMA,
            mutation=False,
        )

    def now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
            "+00:00", "Z",
        )


class _QueryObservation(NamedTuple):
    result: LegacyBridgePrestartWireResultV1 | None
    service_instance_id: str | None
    error_code: str | None


def _descriptor_binding(
    target: BoundCompanyTarget,
    descriptor: Mapping[str, Any],
) -> tuple[str, str]:
    try:
        company = descriptor["company"]
        service_id = descriptor["service_instance_id"]
        token = descriptor["bearer_token"]
        control_url = descriptor["control_url"]
    except (KeyError, TypeError) as exc:
        raise LegacyBridgeClientError("invalid_resident_descriptor") from exc
    manifest = target.manifest
    if (
        not isinstance(company, Mapping)
        or type(service_id) is not str
        or type(token) is not str
        or type(control_url) is not str
        or company.get("company_id") != target.company_id
        or company.get("company_incarnation") != manifest.get("company_incarnation")
        or company.get("lock_domain_generation") != manifest.get("lock_domain_generation")
        or company.get("manifest_sha256") != target.manifest_sha256
    ):
        _fail("resident_descriptor_binding_mismatch")
    _identifier(service_id, "service_instance_id")
    if len(token) != 64:
        _fail("invalid_resident_descriptor")
    _sha(token, "resident_descriptor")
    public_digest = company_contract_sha256({
        "domain": "aoi.legacy-bridge.client-resident.v1",
        "service_instance_id": service_id,
        "company": dict(company),
        "control_url": control_url,
    })
    return service_id, public_digest


def _validate_source(
    raw: bytes,
    *,
    target: BoundCompanyTarget,
    task_id: str,
    legacy_archive_sha256: str,
    source_version: str,
    observed_at: str,
) -> LegacyBridgeProjectionV1:
    if type(raw) is not bytes:
        _fail("invalid_legacy_source_bytes")
    try:
        projection = normalize_legacy_bridge_snapshot(raw)
        document = json.loads(raw.decode("utf-8", "strict"))
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:
        raise LegacyBridgeClientError("invalid_legacy_source_document") from exc
    manifest = target.manifest
    if (
        type(document) is not dict
        or document.get("task_id") != task_id
        or projection.key.company_id != target.company_id
        or projection.key.company_incarnation != manifest.get("company_incarnation")
        or projection.key.lock_domain_generation != manifest.get("lock_domain_generation")
        or projection.legacy_archive_sha256 != legacy_archive_sha256
        or projection.source_version != source_version
        or projection.observed_at != observed_at
    ):
        _fail("legacy_source_binding_mismatch")
    return projection


def _prepared(
    command: LegacyBridgeIngestCommand,
    projection: LegacyBridgeProjectionV1,
    task_id: str,
    source_version: str,
    bridge_scope_id: str,
    attempt_id: str,
) -> dict[str, Any]:
    request_sha = hashlib.sha256(canonical_company_json_bytes(command.as_dict())).hexdigest()
    return _seal(PREPARED_SCHEMA, {
        "company_id": command.company_id,
        "company_incarnation": command.company_incarnation,
        "lock_domain_generation": command.lock_domain_generation,
        "manifest_sha256": command.manifest_sha256,
        "service_instance_id": command.service_instance_id,
        "task_id": task_id,
        "source_version": source_version,
        "legacy_archive_sha256": command.legacy_archive_sha256,
        "legacy_state_sha256": projection.legacy_state_sha256,
        "task_identity_digest": command.task_identity_digest,
        "bridge_scope_id": bridge_scope_id,
        "attempt_id": attempt_id,
        "transaction_id": f"legacy-bridge-transaction-{attempt_id}",
        "command_id": f"legacy-bridge-command-{attempt_id}",
        "source_document_sha256": command.source_document_sha256,
        "source_document_size_bytes": len(command.source_document),
        "request_sha256": request_sha,
        "received_at": command.received_at,
    })


def _current_effect(attempt: _Attempt) -> str:
    if attempt.reconciliation is not None:
        return "committed"
    if attempt.terminal is None:
        return "effect_unknown"
    return cast(str, attempt.terminal["effect"])


def _same_semantic_source(
    attempt: _Attempt,
    current: LegacyBridgeProjectionV1,
) -> bool:
    prior = attempt.projection
    return (
        prior.key == current.key
        and prior.source_kind == current.source_kind
        and prior.source_version == current.source_version
        and prior.legacy_archive_sha256 == current.legacy_archive_sha256
        and prior.legacy_state_sha256 == current.legacy_state_sha256
        and prior.legacy_receipt_set_sha256 == current.legacy_receipt_set_sha256
        and prior.legacy_receipt_quality == current.legacy_receipt_quality
        and prior.task_identity_digest == current.task_identity_digest
        and prior.task_bridge_entity_id == current.task_bridge_entity_id
        and prior.entities == current.entities
    )


def _descriptor_for_query(
    services: LegacyBridgeClientServices,
    target: BoundCompanyTarget,
) -> tuple[Mapping[str, Any], str] | None:
    try:
        descriptor = services.descriptor(target.slot_root)
        service_id, _digest = _descriptor_binding(target, descriptor)
        return descriptor, service_id
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception:
        return None


def _query(
    services: LegacyBridgeClientServices,
    target: BoundCompanyTarget,
    source: bytes,
    bridge_scope_id: str,
    timeout_seconds: float,
) -> _QueryObservation:
    resolved = _descriptor_for_query(services, target)
    if resolved is None:
        return _QueryObservation(None, None, "resident_query_descriptor_unavailable")
    descriptor, service_id = resolved
    manifest = target.manifest
    command = build_legacy_bridge_prestart_query(
        service_instance_id=service_id,
        company_id=target.company_id,
        company_incarnation=cast(int, manifest["company_incarnation"]),
        lock_domain_generation=cast(int, manifest["lock_domain_generation"]),
        manifest_sha256=target.manifest_sha256,
        bridge_scope_id=bridge_scope_id,
        source_document=source,
    )
    try:
        wire = services.query(descriptor, command, timeout_seconds)
        result = decode_legacy_bridge_prestart_wire_result(wire, command=command)
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception:
        return _QueryObservation(None, service_id, "resident_query_unavailable")
    return _QueryObservation(result, service_id, None)


def _classify(
    post_effect: str,
    query: _QueryObservation,
    *,
    committed_lower_bound: bool = False,
) -> tuple[str, int, str | None, str | None, int | None, str | None]:
    gate = None if query.result is None else query.result.gate
    decision = None if gate is None else gate.decision
    reason = None if gate is None else gate.reason
    cursor = None if gate is None else gate.ledger_cursor
    gate_sha = None if gate is None else gate.gate_sha256
    readback_committed = reason in {
        "current_structural_ingest_observed", "current_ingest_degraded",
    }
    if readback_committed:
        effect = "committed"
    elif post_effect == "committed" and not committed_lower_bound:
        effect = "effect_unknown"
    else:
        effect = post_effect
    if effect == "committed":
        exit_code = 0 if decision == "satisfied" else 4
    elif effect == "none":
        exit_code = 2
    else:
        exit_code = 3
    return effect, exit_code, decision, reason, cursor, gate_sha


def _terminal_receipt(
    *,
    prepared: Mapping[str, Any],
    source: bytes,
    post_kind: str,
    post_code: str | None,
    post_status: int | None,
    post_cursor: int | None,
    post_effect: str,
    wire_result: LegacyBridgeIngestWireResultV1 | None,
    query: _QueryObservation,
    effect: str,
    exit_code: int,
    terminal_at: str,
) -> dict[str, Any]:
    gate = None if query.result is None else query.result.gate
    receipt = _seal(TERMINAL_SCHEMA, {
        "prepared_receipt_sha256": prepared["receipt_sha256"],
        "attempt_id": prepared["attempt_id"],
        "post_kind": post_kind,
        "post_code": post_code,
        "post_status": post_status,
        "post_cursor": post_cursor,
        "post_effect": post_effect,
        "post_result": None if wire_result is None else wire_result.as_dict(),
        "wire_result_sha256": (
            None if wire_result is None else hashlib.sha256(
                canonical_company_json_bytes(wire_result.as_dict()),
            ).hexdigest()
        ),
        "query_state": "unavailable" if query.result is None else "resident_durable_readback",
        "query_result": None if query.result is None else query.result.as_dict(),
        "query_service_instance_id": query.service_instance_id,
        "gate_decision": None if gate is None else gate.decision,
        "gate_reason": None if gate is None else gate.reason,
        "gate_cursor": None if gate is None else gate.ledger_cursor,
        "gate_sha256": None if gate is None else gate.gate_sha256,
        "effect": effect,
        "exit_code": exit_code,
        "terminal_at": terminal_at,
    })
    return _validate_terminal_receipt(receipt, prepared, source)


def _reconciliation_receipt(
    attempt: _Attempt,
    query: _QueryObservation,
    effect: str,
    exit_code: int,
    reconciled_at: str,
) -> dict[str, Any]:
    if query.result is None:
        _fail("reconciliation_requires_readback")
    gate = query.result.gate
    receipt = _seal(RECONCILIATION_SCHEMA, {
        "prepared_receipt_sha256": attempt.prepared["receipt_sha256"],
        "terminal_receipt_sha256": cast(dict[str, Any], attempt.terminal)["receipt_sha256"],
        "attempt_id": attempt.prepared["attempt_id"],
        "query_result": query.result.as_dict(),
        "query_service_instance_id": query.service_instance_id,
        "gate_decision": gate.decision,
        "gate_reason": gate.reason,
        "gate_cursor": gate.ledger_cursor,
        "gate_sha256": gate.gate_sha256,
        "effect": effect,
        "exit_code": exit_code,
        "reconciled_at": reconciled_at,
    })
    return _validate_reconciliation_receipt(
        receipt,
        attempt.prepared,
        cast(dict[str, Any], attempt.terminal),
        attempt.source,
    )


def _result(
    attempt: _Attempt,
    *,
    query: _QueryObservation,
    current_state_sha256: str,
    effect: str,
    exit_code: int,
    terminal: Mapping[str, Any] | None,
    reconciliation: Mapping[str, Any] | None,
) -> LegacyBridgeIngestClientResult:
    gate = None if query.result is None else query.result.gate
    return _attempt_result(
        attempt,
        current_state_sha256=current_state_sha256,
        effect=effect,
        exit_code=exit_code,
        gate_decision=None if gate is None else gate.decision,
        gate_reason=None if gate is None else gate.reason,
        cursor=None if gate is None else gate.ledger_cursor,
        terminal=terminal,
        reconciliation=reconciliation,
    )


def run_legacy_bridge_ingest_v04(
    repo_root: Path,
    *,
    task_id: str,
    legacy_archive_sha256: str,
    source_version: str,
    source_loader: LegacyBridgeSourceLoader,
    company_id: str | None = None,
    timeout_seconds: float = 30.0,
    services: LegacyBridgeClientServices | None = None,
) -> LegacyBridgeIngestClientResult:
    """Ingest or reconcile one exact source; never send twice for a preparation."""

    services = _DefaultServices() if services is None else services
    task_id = _identifier(task_id, "task_id")
    archive = _sha(legacy_archive_sha256, "legacy_archive_sha256")
    _identifier(source_version, "source_version")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or not 0.0 < float(timeout_seconds) <= 300.0
    ):
        _fail("invalid_timeout_seconds")
    try:
        target = services.resolve(repo_root.resolve(), company_id)
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:
        raise LegacyBridgeClientError("bound_company_resolution_failed") from exc
    if target.service_state != "running":
        _fail("resident_supervisor_not_running")
    manifest = target.manifest
    incarnation = _integer(manifest.get("company_incarnation"), "company_incarnation", minimum=1)
    generation = _integer(
        manifest.get("lock_domain_generation"), "lock_domain_generation", minimum=1,
    )
    descriptor_a = services.descriptor(target.slot_root)
    service_id, descriptor_digest = _descriptor_binding(target, descriptor_a)
    observed_at = _timestamp(services.now(), "observed_at")
    source = source_loader(target.company_id, incarnation, generation, observed_at)
    projection = _validate_source(
        source,
        target=target,
        task_id=task_id,
        legacy_archive_sha256=archive,
        source_version=source_version,
        observed_at=observed_at,
    )
    descriptor_b = services.descriptor(target.slot_root)
    service_id_b, descriptor_digest_b = _descriptor_binding(target, descriptor_b)
    if (
        service_id_b != service_id
        or descriptor_digest_b != descriptor_digest
        or dict(descriptor_b) != dict(descriptor_a)
    ):
        _fail("resident_descriptor_changed_before_send")
    command = build_legacy_bridge_ingest_command(
        service_instance_id=service_id,
        company_id=target.company_id,
        company_incarnation=incarnation,
        lock_domain_generation=generation,
        manifest_sha256=target.manifest_sha256,
        source_document=source,
        task_identity_digest=projection.task_identity_digest,
        legacy_archive_sha256=archive,
        received_at=observed_at,
    )
    scope = legacy_bridge_scope_id(
        projection.key,
        legacy_archive_sha256=archive,
        task_identity_digest=projection.task_identity_digest,
    )
    attempt_id = legacy_bridge_attempt_id(
        scope,
        source_document_sha256=command.source_document_sha256,
        source_document_size_bytes=len(source),
    )
    scope_root = _ensure_scope_root(target.slot_root, scope)
    with CompanyProcessLock(scope_root / "client.lock", timeout_seconds=5.0):
        receipt_inventory = _inventory(scope_root, scope)
        attempts = receipt_inventory.attempts
        exact_none = tuple(
            item for item in attempts
            if item.prepared["attempt_id"] == attempt_id
            and _current_effect(item) == "none"
        )
        if len(exact_none) > 1:
            _fail("ambiguous_exact_terminal_none")
        if exact_none:
            return _terminal_none_result(
                exact_none[0],
                current_state_sha256=projection.legacy_state_sha256,
            )
        outstanding = tuple(item for item in attempts if _current_effect(item) == "effect_unknown")
        if len(outstanding) > 1:
            _fail("ambiguous_effect_unknown_attempts")
        matching = tuple(
            item for item in attempts
            if _same_semantic_source(item, projection)
            and _current_effect(item) == "committed"
        )
        if len(matching) > 1:
            _fail("ambiguous_committed_current_source")
        prior = outstanding[0] if outstanding else (matching[0] if matching else None)
        if prior is not None:
            if prior.prepared["manifest_sha256"] != target.manifest_sha256:
                _fail("prior_manifest_binding_mismatch")
            query = _query(
                services, target, prior.source,
                cast(str, prior.prepared["bridge_scope_id"]), float(timeout_seconds),
            )
            prior_effect = _current_effect(prior)
            effect, exit_code, _decision, _reason, _cursor, _gate_sha = _classify(
                prior_effect,
                query,
                committed_lower_bound=prior_effect == "committed",
            )
            prior_root = _attempt_root(
                scope_root,
                cast(str, prior.prepared["attempt_id"]),
                create=False,
            )
            terminal = prior.terminal
            if terminal is None:
                try:
                    terminal = _terminal_receipt(
                        prepared=prior.prepared,
                        source=prior.source,
                        post_kind="not_sent_existing_preparation",
                        post_code=None,
                        post_status=None,
                        post_cursor=None,
                        post_effect="effect_unknown",
                        wire_result=None,
                        query=query,
                        effect=effect,
                        exit_code=exit_code,
                        terminal_at=_timestamp(services.now(), "terminal_at"),
                    )
                    _publish_exact(
                        prior_root / "terminal.json",
                        canonical_company_json_bytes(terminal),
                    )
                except (MemoryError, SystemExit, KeyboardInterrupt):
                    raise
                except Exception:
                    return _result(
                        prior,
                        query=query,
                        current_state_sha256=projection.legacy_state_sha256,
                        effect="effect_unknown",
                        exit_code=3,
                        terminal=None,
                        reconciliation=None,
                    )
            reconciliation = prior.reconciliation
            if (
                _current_effect(prior) == "effect_unknown"
                and effect == "committed"
                and prior.terminal is not None
                and reconciliation is None
            ):
                reconciliation = _reconciliation_receipt(
                    prior, query, effect, exit_code, _timestamp(services.now(), "reconciled_at"),
                )
                try:
                    _publish_exact(
                        prior_root / "reconciled.json",
                        canonical_company_json_bytes(reconciliation),
                    )
                except (MemoryError, SystemExit, KeyboardInterrupt):
                    raise
                except Exception:
                    return _result(
                        prior, query=query,
                        current_state_sha256=projection.legacy_state_sha256,
                        effect="effect_unknown", exit_code=3,
                        terminal=prior.terminal, reconciliation=None,
                    )
            return _result(
                prior,
                query=query,
                current_state_sha256=projection.legacy_state_sha256,
                effect=effect,
                exit_code=exit_code,
                terminal=terminal,
                reconciliation=reconciliation,
            )

        try:
            capacity_receipt = _require_attempt_capacity(
                scope_root,
                receipt_inventory,
                attempt_id,
                sealed_at=observed_at,
            )
        except (MemoryError, SystemExit, KeyboardInterrupt):
            raise
        except LegacyBridgeCapacityPublicationError:
            return _capacity_result(
                target.company_id,
                bridge_scope_id=scope,
                attempt_id=attempt_id,
                source_document_sha256=command.source_document_sha256,
                capacity_receipt=None,
                reason="capacity_receipt_publication_failed",
            )
        if capacity_receipt is not None:
            return _capacity_result(
                target.company_id,
                bridge_scope_id=scope,
                attempt_id=attempt_id,
                source_document_sha256=command.source_document_sha256,
                capacity_receipt=capacity_receipt,
                reason="successor_rollover_required",
            )
        prepared = _prepared(command, projection, task_id, source_version, scope, attempt_id)
        attempt_root = _attempt_root(scope_root, attempt_id, create=True)
        _publish_exact(
            attempt_root / "source.json", source,
            max_bytes=MAX_SOURCE_DOCUMENT_BYTES,
        )
        owns_post = _publish_exact(
            attempt_root / "prepared.json", canonical_company_json_bytes(prepared),
        )
        current = _Attempt(source, projection, prepared, None, None)
        if not owns_post:
            query = _query(services, target, source, scope, float(timeout_seconds))
            effect, exit_code, _decision, _reason, _cursor, _gate_sha = _classify(
                "effect_unknown", query,
            )
            try:
                terminal = _terminal_receipt(
                    prepared=prepared, post_kind="not_sent_existing_preparation",
                    source=source,
                    post_code=None, post_status=None, post_cursor=None,
                    post_effect="effect_unknown", wire_result=None,
                    query=query, effect=effect, exit_code=exit_code,
                    terminal_at=_timestamp(services.now(), "terminal_at"),
                )
                _publish_exact(
                    attempt_root / "terminal.json", canonical_company_json_bytes(terminal),
                )
            except (MemoryError, SystemExit, KeyboardInterrupt):
                raise
            except Exception:
                return _result(
                    current, query=query,
                    current_state_sha256=projection.legacy_state_sha256,
                    effect="effect_unknown", exit_code=3, terminal=None,
                    reconciliation=None,
                )
            return _result(
                current, query=query, current_state_sha256=projection.legacy_state_sha256,
                effect=effect, exit_code=exit_code, terminal=terminal, reconciliation=None,
            )

        wire_result: LegacyBridgeIngestWireResultV1 | None = None
        post_kind = "success"
        post_code: str | None = None
        post_status: int | None = None
        post_cursor: int | None = None
        post_effect = "effect_unknown"
        try:
            wire = services.ingest(descriptor_b, command, float(timeout_seconds))
            wire_result = decode_legacy_bridge_ingest_wire_result(wire, command=command)
            post_effect = "committed" if wire_result.effect == "none" else "effect_unknown"
            post_cursor = wire_result.global_sequence
        except CompanyServiceOperationError as exc:
            post_kind = "operation_error"
            post_code = "effect_unknown" if exc.effect == "effect_unknown" else exc.code
            post_status = exc.status
            post_cursor = exc.cursor
            post_effect = (
                "committed" if exc.effect == "committed"
                else "none" if exc.effect is None
                else "effect_unknown"
            )
        except (MemoryError, SystemExit, KeyboardInterrupt):
            raise
        except Exception:
            post_kind = "transport_or_decode_error"
            post_code = "effect_unknown"
        query = _query(services, target, source, scope, float(timeout_seconds))
        effect, exit_code, _decision, _reason, _cursor, _gate_sha = _classify(
            post_effect, query,
        )
        try:
            terminal = _terminal_receipt(
                prepared=prepared, post_kind=post_kind, post_code=post_code,
                source=source,
                post_status=post_status, post_cursor=post_cursor,
                post_effect=post_effect, wire_result=wire_result, query=query,
                effect=effect, exit_code=exit_code,
                terminal_at=_timestamp(services.now(), "terminal_at"),
            )
            _publish_exact(
                attempt_root / "terminal.json", canonical_company_json_bytes(terminal),
            )
        except (MemoryError, SystemExit, KeyboardInterrupt):
            raise
        except Exception:
            return _result(
                current, query=query,
                current_state_sha256=projection.legacy_state_sha256,
                effect="effect_unknown", exit_code=3, terminal=None,
                reconciliation=None,
            )
        return _result(
            current, query=query, current_state_sha256=projection.legacy_state_sha256,
            effect=effect, exit_code=exit_code, terminal=terminal, reconciliation=None,
        )


__all__ = [
    "LegacyBridgeClientError",
    "LegacyBridgeClientServices",
    "LegacyBridgeIngestClientResult",
    "LegacyBridgeSourceLoader",
    "run_legacy_bridge_ingest_v04",
]
