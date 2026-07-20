"""Pure semantic projection for the optional Codex transport bridge.

The namespace is deliberately only an indexed after-image of the immutable
transport contracts.  It starts no process and retains no prompt, runtime
output, credential, or reusable authority.  A row moves by exactly one sealed
journal event, or (after a terminal journal state) by one receipt-publication
step.  In particular, a terminal App Server observation never means that the
AOI task completed or that a Git mutation was verified.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
import re
from typing import Any, NoReturn

from . import codex_transport_contracts as contracts
from . import semantic_events as semantic


CODEX_TRANSPORT_PROJECTION_VERSION = 1
CODEX_TRANSPORT_NAMESPACE_KEY = "codex_transport_v1"
MAX_CODEX_TRANSPORT_LAUNCHES = 128
MAX_CODEX_TRANSPORT_NAMESPACE_BYTES = 2 * 1024 * 1024

_SHA256 = re.compile(r"[0-9a-f]{64}")
_LAUNCH_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_ROW_FIELDS = {
    "schema_version",
    "launch_id",
    "intent_sha256",
    "reservation_sha256",
    "state",
    "thread_id",
    "turn_id",
    "journal_sequence",
    "journal_head_sha256",
    "terminal_receipt_sha256",
}
_SEALED_ROW_FIELDS = _ROW_FIELDS | {"launch_row_sha256"}
_NAMESPACE_FIELDS = {"schema_version", "launches"}
_TERMINAL_STATES = frozenset(
    {"completed", "failed", "interrupted", "launch_unknown", "runtime_unknown"}
)
_KNOWN_STATES = _TERMINAL_STATES | frozenset(
    {"reserved", "thread_started", "turn_started"}
)


class CodexTransportProjectionError(ValueError):
    """The compact transport after-image is malformed or non-monotonic."""


def _fail(message: str) -> NoReturn:
    raise CodexTransportProjectionError(message)


def _clone(value: Any, *, maximum: int) -> Any:
    try:
        return json.loads(semantic.canonical_json_bytes(value, max_bytes=maximum))
    except (semantic.SemanticEventError, TypeError, ValueError) as exc:
        raise CodexTransportProjectionError(
            "transport projection value is not bounded canonical JSON"
        ) from exc


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        _fail(f"{label} is not lowercase SHA-256")
    return value


def _launch_id(value: Any) -> str:
    if not isinstance(value, str) or not _LAUNCH_ID.fullmatch(value):
        _fail("transport launch_id is invalid")
    return value


def _text_or_none(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > contracts.MAX_TEXT
        or "\x00" in value
    ):
        _fail(f"{label} is invalid")
    return value


def _correlation_for_state(
    state: str, thread_id: str | None, turn_id: str | None
) -> tuple[str | None, str | None]:
    if turn_id is not None and thread_id is None:
        _fail("transport turn_id requires thread_id")
    if state == "reserved":
        if thread_id is not None or turn_id is not None:
            _fail("reserved cannot name runtime objects")
    elif state == "launch_unknown":
        # A lost thread/start response has no runtime identity.  A lost
        # turn/start response preserves the already-durable thread identity
        # while the new turn identity remains unknown.
        if turn_id is not None:
            _fail("launch_unknown cannot name an unpersisted turn")
    elif state == "thread_started":
        if thread_id is None or turn_id is not None:
            _fail("thread_started requires exact thread only")
    elif state in {"turn_started", "completed", "interrupted"}:
        if thread_id is None or turn_id is None:
            _fail(f"{state} requires exact thread and turn")
    # A failure can be truthful before process/thread/turn creation.  Retain
    # only the correlation actually acquired, never fabricate a runtime id.
    elif state == "runtime_unknown":
        if thread_id is None or turn_id is None:
            _fail("runtime_unknown requires the exact known thread and turn")
    return thread_id, turn_id


def _row_base(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _ROW_FIELDS:
        _fail("transport launch row schema is invalid")
    item = _clone(dict(value), maximum=MAX_CODEX_TRANSPORT_NAMESPACE_BYTES)
    if item["schema_version"] != CODEX_TRANSPORT_PROJECTION_VERSION:
        _fail("transport launch row version is invalid")
    state = item["state"]
    if not isinstance(state, str) or state not in _KNOWN_STATES:
        _fail("transport launch row state is invalid")
    sequence = item["journal_sequence"]
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or not 1 <= sequence <= contracts.MAX_JOURNAL_EVENTS
    ):
        _fail("transport launch row journal sequence is invalid")
    thread_id, turn_id = _correlation_for_state(
        state,
        _text_or_none(item["thread_id"], "transport thread_id"),
        _text_or_none(item["turn_id"], "transport turn_id"),
    )
    receipt = item["terminal_receipt_sha256"]
    if receipt is not None:
        receipt = _sha(receipt, "transport terminal receipt SHA-256")
    if state not in _TERMINAL_STATES and receipt is not None:
        _fail("nonterminal transport row cannot name terminal receipt")
    return {
        "schema_version": CODEX_TRANSPORT_PROJECTION_VERSION,
        "launch_id": _launch_id(item["launch_id"]),
        "intent_sha256": _sha(item["intent_sha256"], "transport intent SHA-256"),
        "reservation_sha256": _sha(
            item["reservation_sha256"], "transport reservation SHA-256"
        ),
        "state": state,
        "thread_id": thread_id,
        "turn_id": turn_id,
        "journal_sequence": sequence,
        "journal_head_sha256": _sha(
            item["journal_head_sha256"], "transport journal head SHA-256"
        ),
        "terminal_receipt_sha256": receipt,
    }


def launch_row_sha256(row: Mapping[str, Any]) -> str:
    """Return the canonical digest for the complete compact launch after-image."""

    if isinstance(row, Mapping) and set(row) == _SEALED_ROW_FIELDS:
        return validate_launch_row(row)["launch_row_sha256"]
    try:
        return semantic.canonical_sha256(
            _row_base(row), max_bytes=MAX_CODEX_TRANSPORT_NAMESPACE_BYTES
        )
    except semantic.SemanticEventError as exc:
        raise CodexTransportProjectionError("transport launch row is too large") from exc


def seal_launch_row(row: Mapping[str, Any]) -> dict[str, Any]:
    base = _row_base(row)
    return {
        **base,
        "launch_row_sha256": semantic.canonical_sha256(
            base, max_bytes=MAX_CODEX_TRANSPORT_NAMESPACE_BYTES
        ),
    }


def validate_launch_row(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a self-addressed row without inferring any stronger evidence."""

    if not isinstance(value, Mapping) or set(value) != _SEALED_ROW_FIELDS:
        _fail("sealed transport launch row schema is invalid")
    base = _row_base({field: value[field] for field in _ROW_FIELDS})
    supplied = _sha(value["launch_row_sha256"], "transport launch row SHA-256")
    expected = semantic.canonical_sha256(
        base, max_bytes=MAX_CODEX_TRANSPORT_NAMESPACE_BYTES
    )
    if supplied != expected:
        _fail("transport launch row digest does not match contents")
    return {**base, "launch_row_sha256": expected}


def validate_codex_transport_namespace(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate the bounded launch-index namespace stored in semantic state."""

    if value is None:
        return {
            "schema_version": CODEX_TRANSPORT_PROJECTION_VERSION,
            "launches": {},
        }
    if not isinstance(value, Mapping) or set(value) != _NAMESPACE_FIELDS:
        _fail("codex transport namespace schema is invalid")
    if value.get("schema_version") != CODEX_TRANSPORT_PROJECTION_VERSION:
        _fail("codex transport namespace version is invalid")
    launches = value.get("launches")
    if not isinstance(launches, Mapping) or len(launches) > MAX_CODEX_TRANSPORT_LAUNCHES:
        _fail("codex transport namespace launch index is invalid or over bound")
    checked: dict[str, dict[str, Any]] = {}
    for launch_id, row in launches.items():
        identity = _launch_id(launch_id)
        normalized = validate_launch_row(row)
        if normalized["launch_id"] != identity:
            _fail("codex transport launch index and row identity differ")
        checked[identity] = normalized
    namespace = {
        "schema_version": CODEX_TRANSPORT_PROJECTION_VERSION,
        "launches": {identity: checked[identity] for identity in sorted(checked)},
    }
    try:
        semantic.canonical_json_bytes(namespace, max_bytes=MAX_CODEX_TRANSPORT_NAMESPACE_BYTES)
    except semantic.SemanticEventError as exc:
        raise CodexTransportProjectionError(
            "codex transport namespace exceeds its byte bound"
        ) from exc
    return namespace


def codex_transport_namespace_from_projection(
    projection: Mapping[str, Any],
) -> dict[str, Any]:
    """Extract the transport namespace from a validated semantic projection."""

    try:
        domain = semantic.projection_domain(projection)
    except (semantic.SemanticEventError, TypeError, ValueError) as exc:
        raise CodexTransportProjectionError("semantic projection is invalid") from exc
    return validate_codex_transport_namespace(domain.get(CODEX_TRANSPORT_NAMESPACE_KEY))


def _checked_material(
    intent: Mapping[str, Any],
    reservation: Mapping[str, Any],
    journal: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], contracts.JournalState, list[dict[str, Any]]]:
    try:
        checked_intent = contracts.validate_launch_intent(intent)
        checked_reservation = contracts.validate_reservation(reservation)
        records = [contracts.validate_journal_event(event) for event in journal]
        journal_state = contracts.validate_transport_journal(records)
    except contracts.CodexTransportContractError as exc:
        raise CodexTransportProjectionError("transport contract material is invalid") from exc
    if checked_reservation["launch_intent_sha256"] != checked_intent["intent_sha256"]:
        _fail("transport reservation does not bind launch intent")
    if checked_reservation.get("runtime_pin") != checked_intent.get("runtime_pin"):
        _fail("transport reservation runtime pin differs from launch intent")
    first = records[0]
    if (
        first["launch_intent_sha256"] != checked_intent["intent_sha256"]
        or first["reservation_sha256"] != checked_reservation["reservation_sha256"]
    ):
        _fail("transport journal does not bind launch intent and reservation")
    return checked_intent, checked_reservation, journal_state, records


def _row_from_journal(
    launch_id: str,
    intent_sha256: str,
    reservation_sha256: str,
    state: contracts.JournalState,
    *,
    receipt_sha256: str | None,
) -> dict[str, Any]:
    correlation = state.correlation
    return seal_launch_row(
        {
            "schema_version": CODEX_TRANSPORT_PROJECTION_VERSION,
            "launch_id": launch_id,
            "intent_sha256": intent_sha256,
            "reservation_sha256": reservation_sha256,
            "state": state.state,
            "thread_id": correlation["thread_id"],
            "turn_id": correlation["turn_id"],
            "journal_sequence": state.next_sequence - 1,
            "journal_head_sha256": state.head_sha256,
            "terminal_receipt_sha256": receipt_sha256,
        }
    )


def advance_codex_transport_projection(
    base: Mapping[str, Any],
    *,
    launch_id: str,
    intent: Mapping[str, Any],
    reservation: Mapping[str, Any],
    journal: Sequence[Mapping[str, Any]],
    terminal_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Advance exactly one launch milestone in a detached semantic domain.

    The caller supplies the complete journal so the shared contract validator
    can verify its chain.  The compact row retains only its exact current head,
    thus no raw Codex output is copied into task state.  A new row must be the
    reserved event.  An existing row may gain exactly one next event, or may
    gain one terminal receipt after a separately persisted terminal event.
    """

    try:
        domain = semantic.projection_domain(base)
    except (semantic.SemanticEventError, TypeError, ValueError) as exc:
        raise CodexTransportProjectionError("semantic projection is invalid") from exc
    namespace = validate_codex_transport_namespace(domain.get(CODEX_TRANSPORT_NAMESPACE_KEY))
    identity = _launch_id(launch_id)
    checked_intent, checked_reservation, journal_state, records = _checked_material(
        intent, reservation, journal
    )
    current = namespace["launches"].get(identity)
    if current is None:
        if len(records) != 1 or journal_state.state != "reserved" or terminal_receipt is not None:
            _fail("new transport launch must persist exactly its reserved milestone")
        if len(namespace["launches"]) >= MAX_CODEX_TRANSPORT_LAUNCHES:
            _fail("codex transport launch count reached its bound")
        next_row = _row_from_journal(
            identity,
            checked_intent["intent_sha256"],
            checked_reservation["reservation_sha256"],
            journal_state,
            receipt_sha256=None,
        )
    else:
        if (
            current["intent_sha256"] != checked_intent["intent_sha256"]
            or current["reservation_sha256"] != checked_reservation["reservation_sha256"]
        ):
            _fail("transport launch material differs from committed row")
        if len(records) < current["journal_sequence"]:
            _fail("transport journal is behind committed row")
        prior = records[current["journal_sequence"] - 1]
        if prior["event_sha256"] != current["journal_head_sha256"]:
            _fail("transport journal does not contain committed head")
        if len(records) == current["journal_sequence"]:
            if terminal_receipt is None:
                _fail("transport milestone is an exact duplicate")
            if current["terminal_receipt_sha256"] is not None:
                _fail("transport terminal receipt is already committed")
            if current["state"] not in _TERMINAL_STATES:
                _fail("transport receipt requires terminal journal state")
            try:
                sealed_receipt = contracts.validate_terminal_receipt_against_journal(
                    terminal_receipt, records
                )
            except contracts.CodexTransportContractError as exc:
                raise CodexTransportProjectionError("terminal receipt is invalid") from exc
            next_row = _row_from_journal(
                identity,
                checked_intent["intent_sha256"],
                checked_reservation["reservation_sha256"],
                journal_state,
                receipt_sha256=sealed_receipt["receipt_sha256"],
            )
        else:
            if terminal_receipt is not None:
                _fail("transport receipt publication must be a separate milestone")
            if len(records) != current["journal_sequence"] + 1:
                _fail("transport advance must append exactly one journal event")
            if current["state"] in _TERMINAL_STATES:
                _fail("terminal transport state cannot be retried or advanced")
            if records[-1]["prev_event_sha256"] != current["journal_head_sha256"]:
                _fail("transport next journal event does not extend committed head")
            next_row = _row_from_journal(
                identity,
                checked_intent["intent_sha256"],
                checked_reservation["reservation_sha256"],
                journal_state,
                receipt_sha256=None,
            )
    namespace["launches"][identity] = next_row
    domain[CODEX_TRANSPORT_NAMESPACE_KEY] = validate_codex_transport_namespace(namespace)
    try:
        semantic.canonical_json_bytes(domain, max_bytes=semantic.MAX_CANONICAL_JSON_BYTES)
    except semantic.SemanticEventError as exc:
        raise CodexTransportProjectionError(
            "transport result projection exceeds semantic byte bound"
        ) from exc
    return domain


__all__ = [
    "CODEX_TRANSPORT_NAMESPACE_KEY",
    "CODEX_TRANSPORT_PROJECTION_VERSION",
    "CodexTransportProjectionError",
    "MAX_CODEX_TRANSPORT_LAUNCHES",
    "MAX_CODEX_TRANSPORT_NAMESPACE_BYTES",
    "advance_codex_transport_projection",
    "codex_transport_namespace_from_projection",
    "launch_row_sha256",
    "seal_launch_row",
    "validate_codex_transport_namespace",
    "validate_launch_row",
]
