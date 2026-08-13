"""Closed, bounded request contracts for resident Chief takeover control.

This module deliberately validates transport-shaped requests only.  It does
not decide whether a carrier may take over, nor does it interpret a capability;
that authority remains solely with :mod:`aoi_orgware.company.supervisor`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import math
import re
from collections.abc import Mapping
from typing import NoReturn, cast


CHIEF_TAKEOVER_PREPARE_SCHEMA = "aoi.company.chief-takeover-prepare.v1"
CHIEF_TAKEOVER_CONSUME_SCHEMA = "aoi.company.chief-takeover-consume.v1"
CHIEF_TAKEOVER_PREPARE_RESULT_SCHEMA = (
    "aoi.company.chief-takeover-prepare-result.v1"
)
CHIEF_TAKEOVER_CONSUME_RESULT_SCHEMA = (
    "aoi.company.chief-takeover-consume-result.v1"
)

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
_MAX_TEXT_BYTES = 8192
_MAX_USER_ACTION_REF_BYTES = 256
_MAX_JSON_DEPTH = 16
_MAX_CAPABILITY_BYTES = 16 * 1024
_MAX_JSON_MEMBERS = 128
_MAX_JSON_STRING_BYTES = 8192


class ChiefControlProtocolError(ValueError):
    """A Chief control request is malformed before it reaches authority code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ChiefTakeoverKnownCarrier:
    """The exact carrier identity declared by a Chief client."""

    carrier_id: str
    provider: str
    model: str
    session_id: str
    thread_id: str
    provenance: str
    observation: dict[str, str]

    def as_dict(self) -> dict[str, object]:
        return {
            "carrier_id": self.carrier_id,
            "provider": self.provider,
            "model": self.model,
            "session_id": self.session_id,
            "thread_id": self.thread_id,
            "provenance": self.provenance,
            "observation": dict(self.observation),
        }


@dataclass(frozen=True, slots=True)
class ChiefTakeoverPrepareCommand:
    """A bounded prepare request; it is not a takeover grant."""

    service_instance_id: str
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    manifest_sha256: str
    known_carrier: ChiefTakeoverKnownCarrier
    user_action_ref: str
    objective_sha256: str
    scope_sha256: str
    nonce_sha256: str


@dataclass(frozen=True, slots=True)
class ChiefTakeoverConsumeCommand:
    """A bounded consume request; capability authority is checked elsewhere."""

    service_instance_id: str
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    manifest_sha256: str
    capability: dict[str, object]
    known_carrier: ChiefTakeoverKnownCarrier
    consumed_at: str
    grant_expires_at: str


def _fail(code: str) -> NoReturn:
    raise ChiefControlProtocolError(code)


def _exact_object(value: object, fields: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, Mapping):
        _fail("invalid_request_fields")
    item = cast(Mapping[str, object], value)
    if set(item) != fields:
        _fail("invalid_request_fields")
    return dict(item)


def _text(value: object, code: str, *, maximum: int = _MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        _fail(code)
    try:
        if len(value.encode("utf-8")) > maximum:
            _fail(code)
    except UnicodeEncodeError:
        _fail(code)
    return value


def _identifier(value: object, code: str) -> str:
    text = _text(value, code, maximum=256)
    if _ID_RE.fullmatch(text) is None:
        _fail(code)
    return text


def _sha256(value: object, code: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        _fail(code)
    return value


def _positive_int(value: object, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _fail(code)
    return value


def _timestamp(value: object, code: str) -> str:
    text = _text(value, code, maximum=64)
    if _TIMESTAMP_RE.fullmatch(text) is None:
        _fail(code)
    try:
        parsed = datetime.fromisoformat(
            text[:-1] + "+00:00" if text.endswith("Z") else text,
        )
    except ValueError:
        _fail(code)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail(code)
    return text


def _known_carrier(value: object) -> ChiefTakeoverKnownCarrier:
    if not isinstance(value, Mapping):
        _fail("invalid_known_carrier")
    item = cast(Mapping[str, object], value)
    fields = frozenset({
        "carrier_id", "provider", "model", "session_id", "thread_id",
        "provenance", "observation",
    })
    actual = set(item)
    if actual != fields:
        _fail("invalid_known_carrier")
    provider = item["provider"]
    if provider not in {"codex", "claude"}:
        _fail("invalid_provider")
    provenance = item["provenance"]
    if provenance != "agent_reported":
        _fail("invalid_provenance")
    observation = item["observation"]
    if (
        not isinstance(observation, Mapping)
        or set(observation) != {"state", "reason"}
        or observation["state"] != "known"
        or observation["reason"] != "observed"
    ):
        _fail("invalid_observation")
    return ChiefTakeoverKnownCarrier(
        carrier_id=_identifier(item["carrier_id"], "invalid_carrier_id"),
        provider=provider,
        model=_identifier(item["model"], "invalid_model"),
        session_id=_identifier(item["session_id"], "invalid_session_id"),
        thread_id=_identifier(item["thread_id"], "invalid_thread_id"),
        provenance=provenance,
        observation={"state": "known", "reason": "observed"},
    )


def _binding(value: Mapping[str, object]) -> tuple[str, str, int, int, str]:
    return (
        _identifier(value["service_instance_id"], "invalid_service_instance_id"),
        _identifier(value["company_id"], "invalid_company_id"),
        _positive_int(value["company_incarnation"], "invalid_company_incarnation"),
        _positive_int(
            value["lock_domain_generation"],
            "invalid_lock_domain_generation",
        ),
        _sha256(value["manifest_sha256"], "invalid_manifest_sha256"),
    )


def _json_value(value: object, *, depth: int) -> object:
    if depth > _MAX_JSON_DEPTH:
        _fail("invalid_capability")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            _fail("invalid_capability")
        return value
    if isinstance(value, str):
        try:
            if len(value.encode("utf-8")) > _MAX_JSON_STRING_BYTES:
                _fail("invalid_capability")
        except UnicodeEncodeError:
            _fail("invalid_capability")
        return value
    if isinstance(value, Mapping):
        item = cast(Mapping[object, object], value)
        if len(item) > _MAX_JSON_MEMBERS:
            _fail("invalid_capability")
        normalized: dict[str, object] = {}
        for key, member in item.items():
            if not isinstance(key, str):
                _fail("invalid_capability")
            try:
                if len(key.encode("utf-8")) > 256:
                    _fail("invalid_capability")
            except UnicodeEncodeError:
                _fail("invalid_capability")
            normalized[key] = _json_value(member, depth=depth + 1)
        return normalized
    if isinstance(value, list):
        if len(value) > _MAX_JSON_MEMBERS:
            _fail("invalid_capability")
        return [_json_value(member, depth=depth + 1) for member in value]
    _fail("invalid_capability")


def _capability(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        _fail("invalid_capability")
    normalized = _json_value(value, depth=1)
    if not isinstance(normalized, dict):
        _fail("invalid_capability")
    try:
        encoded = json.dumps(
            normalized, ensure_ascii=False, allow_nan=False,
            separators=(",", ":"), sort_keys=True,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError):
        _fail("invalid_capability")
    if len(encoded) > _MAX_CAPABILITY_BYTES:
        _fail("invalid_capability")
    return cast(dict[str, object], normalized)


def parse_chief_takeover_prepare(value: object) -> ChiefTakeoverPrepareCommand:
    """Parse the sealed prepare request without granting any authority."""

    item = _exact_object(value, frozenset({
        "schema_version", "service_instance_id", "company_id",
        "company_incarnation", "lock_domain_generation", "manifest_sha256",
        "known_carrier", "user_action_ref", "objective_sha256",
        "scope_sha256", "nonce_sha256",
    }))
    if item["schema_version"] != CHIEF_TAKEOVER_PREPARE_SCHEMA:
        _fail("invalid_schema_version")
    service_instance_id, company_id, incarnation, generation, manifest_sha256 = _binding(item)
    return ChiefTakeoverPrepareCommand(
        service_instance_id=service_instance_id,
        company_id=company_id,
        company_incarnation=incarnation,
        lock_domain_generation=generation,
        manifest_sha256=manifest_sha256,
        known_carrier=_known_carrier(item["known_carrier"]),
        user_action_ref=_identifier(
            _text(
                item["user_action_ref"], "invalid_user_action_ref",
                maximum=_MAX_USER_ACTION_REF_BYTES,
            ),
            "invalid_user_action_ref",
        ),
        objective_sha256=_sha256(item["objective_sha256"], "invalid_objective_sha256"),
        scope_sha256=_sha256(item["scope_sha256"], "invalid_scope_sha256"),
        nonce_sha256=_sha256(item["nonce_sha256"], "invalid_nonce_sha256"),
    )


def parse_chief_takeover_consume(value: object) -> ChiefTakeoverConsumeCommand:
    """Parse the sealed consume request without interpreting its capability."""

    item = _exact_object(value, frozenset({
        "schema_version", "service_instance_id", "company_id",
        "company_incarnation", "lock_domain_generation", "manifest_sha256",
        "capability", "known_carrier", "consumed_at", "grant_expires_at",
    }))
    if item["schema_version"] != CHIEF_TAKEOVER_CONSUME_SCHEMA:
        _fail("invalid_schema_version")
    service_instance_id, company_id, incarnation, generation, manifest_sha256 = _binding(item)
    return ChiefTakeoverConsumeCommand(
        service_instance_id=service_instance_id,
        company_id=company_id,
        company_incarnation=incarnation,
        lock_domain_generation=generation,
        manifest_sha256=manifest_sha256,
        capability=_capability(item["capability"]),
        known_carrier=_known_carrier(item["known_carrier"]),
        consumed_at=_timestamp(item["consumed_at"], "invalid_consumed_at"),
        grant_expires_at=_timestamp(
            item["grant_expires_at"], "invalid_grant_expires_at",
        ),
    )
