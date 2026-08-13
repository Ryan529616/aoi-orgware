from __future__ import annotations

from copy import deepcopy

import pytest

from aoi_orgware.company.control_protocol import (
    CHIEF_TAKEOVER_CONSUME_SCHEMA,
    CHIEF_TAKEOVER_PREPARE_SCHEMA,
    ChiefControlProtocolError,
    parse_chief_takeover_consume,
    parse_chief_takeover_prepare,
)


H = "a" * 64


def _carrier() -> dict[str, object]:
    return {
        "carrier_id": "chief-codex-1", "provider": "codex", "model": "gpt-5.6",
        "session_id": "session-1", "thread_id": "thread-1",
        "provenance": "agent_reported",
        "observation": {"state": "known", "reason": "observed"},
    }


def _prepare() -> dict[str, object]:
    return {
        "schema_version": CHIEF_TAKEOVER_PREPARE_SCHEMA,
        "service_instance_id": "resident-1", "company_id": "company-1",
        "company_incarnation": 1, "lock_domain_generation": 2,
        "manifest_sha256": H, "known_carrier": _carrier(),
        "user_action_ref": "user-turn-1", "objective_sha256": "b" * 64,
        "scope_sha256": "c" * 64, "nonce_sha256": "d" * 64,
    }


def _consume() -> dict[str, object]:
    return {
        "schema_version": CHIEF_TAKEOVER_CONSUME_SCHEMA,
        "service_instance_id": "resident-1", "company_id": "company-1",
        "company_incarnation": 1, "lock_domain_generation": 2,
        "manifest_sha256": H, "known_carrier": _carrier(),
        # The protocol intentionally does not interpret capability fields.
        "capability": {"opaque": {"issued_at": "not-authoritative-here"}},
        "consumed_at": "2026-07-27T12:00:00Z",
        "grant_expires_at": "2026-07-27T12:05:00+00:00",
    }


def _error(code: str, func: object, value: object) -> None:
    with pytest.raises(ChiefControlProtocolError) as caught:
        func(value)  # type: ignore[operator]
    assert caught.value.code == code


def test_prepare_normalizes_exact_known_carrier() -> None:
    value = _prepare()

    command = parse_chief_takeover_prepare(value)

    assert command.company_incarnation == 1
    assert command.known_carrier.as_dict() == _carrier()
    assert command.user_action_ref == "user-turn-1"


@pytest.mark.parametrize("mutation", ["extra", "missing", "bool"])
def test_prepare_rejects_exact_fields_and_boolean_integers(mutation: str) -> None:
    value = _prepare()
    if mutation == "extra":
        value["generic_rpc"] = "forbidden"
        expected = "invalid_request_fields"
    elif mutation == "missing":
        del value["nonce_sha256"]
        expected = "invalid_request_fields"
    else:
        value["company_incarnation"] = True
        expected = "invalid_company_incarnation"

    _error(expected, parse_chief_takeover_prepare, value)


@pytest.mark.parametrize(("field", "bad", "code"), [
    ("provider", "other", "invalid_provider"),
    ("provenance", "AOI_verified", "invalid_provenance"),
    ("observation", {"state": "unknown", "reason": "observed"}, "invalid_observation"),
    ("carrier_id", "x" * 257, "invalid_carrier_id"),
])
def test_prepare_rejects_invalid_carrier_members(
    field: str, bad: object, code: str,
) -> None:
    value = _prepare()
    carrier = _carrier()
    carrier[field] = bad
    value["known_carrier"] = carrier

    _error(code, parse_chief_takeover_prepare, value)


def test_prepare_rejects_extra_or_nested_carrier_shape() -> None:
    value = _prepare()
    carrier = _carrier()
    carrier["parent"] = {"too": "deep"}
    value["known_carrier"] = carrier
    _error("invalid_known_carrier", parse_chief_takeover_prepare, value)


def test_consume_requires_exact_fields_timestamps_and_preserves_opaque_capability() -> None:
    value = _consume()
    command = parse_chief_takeover_consume(value)

    assert command.consumed_at == "2026-07-27T12:00:00Z"
    assert command.grant_expires_at == "2026-07-27T12:05:00+00:00"
    assert command.capability == value["capability"]
    assert command.known_carrier.observation == {
        "state": "known",
        "reason": "observed",
    }

    extra = deepcopy(value)
    extra["user_action_ref"] = "not-a-consume-field"
    _error("invalid_request_fields", parse_chief_takeover_consume, extra)
    bad_time = deepcopy(value)
    bad_time["consumed_at"] = "not-a-timestamp"
    _error("invalid_consumed_at", parse_chief_takeover_consume, bad_time)


def test_consume_rejects_huge_or_deep_opaque_capability() -> None:
    huge = _consume()
    huge["capability"] = {"opaque": "x" * 9000}
    _error("invalid_capability", parse_chief_takeover_consume, huge)

    deep: dict[str, object] = {"leaf": "value"}
    for _ in range(17):
        deep = {"nested": deep}
    nested = _consume()
    nested["capability"] = deep
    _error("invalid_capability", parse_chief_takeover_consume, nested)
