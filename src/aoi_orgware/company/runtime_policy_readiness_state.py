"""Exact-current-head projection boundary for runtime-policy observations.

This internal helper owns ledger replay, snapshot health, payload detachment,
and full invariant reduction.  It has no registration, mutation, admission, or
runtime-policy activation authority.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NamedTuple, Never

from .contracts import CompanyContractError, company_contract_sha256
from .invariants import CompanyInvariantError, InvariantObject, reduce_company_invariants
from .ledger import LedgerError
from .readmodel import ProjectedObject, ReadModelError
from .state import CompanyQuerySnapshot, CompanyStateError, CompanyStateOwner
from .state_reader import CompanyStateReaderError, immutable_ledger_heads


class RuntimePolicyReadinessStateError(CompanyContractError):
    """The exact current company projection cannot be verified."""


class VerifiedRuntimePolicyContextV1(NamedTuple):
    snapshot: CompanyQuerySnapshot
    objects: tuple[InvariantObject, ...]
    projected: dict[tuple[str, str], ProjectedObject]
    company: tuple[str, int, int]
    cursor: int
    head_sha256: str


def _fail(message: str) -> Never:
    raise RuntimePolicyReadinessStateError(message)


def plain_projected_payload(value: Any) -> Any:
    """Detach one reducer payload without trusting a mutable mapping wrapper."""

    if isinstance(value, Mapping):
        try:
            items = tuple(value.items())
        except MemoryError:
            raise
        except Exception as exc:
            raise RuntimePolicyReadinessStateError(
                "projected payload cannot be traversed"
            ) from exc
        result: dict[str, Any] = {}
        for pair in items:
            if type(pair) is not tuple or len(pair) != 2 or type(pair[0]) is not str:
                _fail("projected payload mapping is malformed")
            key = pair[0]
            if key in result:
                _fail("projected payload has a duplicate key")
            result[key] = plain_projected_payload(pair[1])
        return result
    if type(value) in {tuple, list}:
        return [plain_projected_payload(member) for member in value]
    return value


def verified_runtime_policy_context(
    state: CompanyStateOwner,
) -> VerifiedRuntimePolicyContextV1:
    """Replay and reduce the exact current owner-held ledger head."""

    if type(state) is not CompanyStateOwner:
        _fail("runtime-policy readiness requires exact CompanyStateOwner")
    try:
        replay = CompanyStateOwner.historical_replay_input(state)
        current_heads = immutable_ledger_heads(CompanyStateOwner.heads(state))
        if replay.heads != current_heads or not replay.records:
            _fail("runtime-policy readiness replay is not the current ledger head")
        identity = replay.heads.identity
        if identity is None:
            _fail("runtime-policy readiness company identity is unavailable")
        cursor, head_sha256 = replay.heads.global_head
        if cursor < 1 or cursor != len(replay.records):
            _fail("runtime-policy readiness ledger cursor is unavailable")
        snapshot = CompanyStateOwner.project_historical_replay(replay, cursor)
        health = snapshot.health
        if (
            health.status != "ready"
            or health.ledger_status != "ready"
            or health.projection_status not in {"ready", "historical_prefix_replay"}
            or health.blob_status != "ready"
            or health.ledger_heads.identity != identity
            or health.ledger_heads.global_head.global_sequence != cursor
            or health.ledger_heads.global_head.transaction_sha256 != head_sha256
            or health.readmodel_head.global_sequence != cursor
            or health.readmodel_head.transaction_sha256 != head_sha256
        ):
            _fail("runtime-policy readiness snapshot health is unavailable")

        values: list[InvariantObject] = []
        projected: dict[tuple[str, str], ProjectedObject] = {}
        seen_events: set[str] = set()
        for item in snapshot.objects:
            if type(item) is not ProjectedObject:
                _fail("runtime-policy readiness projected object type is invalid")
            if (
                type(item.contract_type) is not str
                or type(item.object_key) is not str
                or type(item.record_id) is not str
                or type(item.event_id) is not str
                or type(item.global_sequence) is not int
                or not item.contract_type
                or not item.object_key
                or not item.record_id
                or not item.event_id
                or item.global_sequence < 1
                or item.global_sequence > cursor
                or not isinstance(item.payload, Mapping)
            ):
                _fail("runtime-policy readiness projected object is malformed")
            key = (item.contract_type, item.object_key)
            if key in projected or item.event_id in seen_events:
                _fail("runtime-policy readiness projected identity is duplicated")
            payload = plain_projected_payload(item.payload)
            payload_sha256 = company_contract_sha256(payload)
            projected[key] = item
            seen_events.add(item.event_id)
            values.append(InvariantObject(
                item.contract_type,
                item.object_key,
                item.event_id,
                item.global_sequence,
                payload_sha256,
                payload,
            ))
        projection = reduce_company_invariants(values, snapshot.uncertain_dispatches)
        return VerifiedRuntimePolicyContextV1(
            snapshot=snapshot,
            objects=projection.objects,
            projected=projected,
            company=identity,
            cursor=cursor,
            head_sha256=head_sha256,
        )
    except RuntimePolicyReadinessStateError:
        raise
    except MemoryError:
        raise
    except Exception as exc:
        raise RuntimePolicyReadinessStateError(
            "runtime-policy readiness verified replay is unavailable"
        ) from exc


__all__ = [
    "RuntimePolicyReadinessStateError",
    "VerifiedRuntimePolicyContextV1",
    "plain_projected_payload",
    "verified_runtime_policy_context",
]
