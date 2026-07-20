"""Local-only, Chief-issued one-shot authorization for exact external exports.

This module does not upload anything.  A consumer first spends one permit under
the AOI state lock and may perform the named external action only when the
returned receipt says ``fresh_consumption=true``.  A response-loss retry returns
the durable receipt with ``fresh_consumption=false`` and therefore carries no
export authority.  This is conservative at-most-once authorization, not proof
that a remote service received the file.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, NoReturn
from urllib.parse import urlsplit

from . import harnesslib as h
from . import semantic_events as semantic


EXTERNAL_EXPORT_DIRECTORY = "external-exports-v1"
INTENT_CONTRACT_TYPE = "aoi.external_export_intent.v1"
PERMIT_CONTRACT_TYPE = "aoi.external_export_permit.v1"
ISSUANCE_CONTRACT_TYPE = "aoi.external_export_issuance.v1"
CONSUMPTION_CONTRACT_TYPE = "aoi.external_export_consumption_receipt.v1"
SCHEMA_VERSION = 1
MAX_CONTRACT_BYTES = 64 * 1024
MAX_DESTINATION_CHARS = 2_048
MAX_PURPOSE_CHARS = 1_024
MAX_SOURCE_NAME_CHARS = 255
MAX_EXPORT_TTL = timedelta(minutes=15)
FILE_CHUNK_BYTES = 1024 * 1024
MAX_EXPORT_RECORDS_PER_TASK = 1_024
MAX_EXPORT_RECORDS_TOTAL = 8_192

_SHA256 = re.compile(r"[0-9a-f]{64}")
_URI_SCHEME = re.compile(r"[a-z][a-z0-9+.-]{1,31}")
_INTENT_FIELDS = frozenset(
    {
        "schema_version",
        "contract_type",
        "task_id",
        "export_id",
        "config_sha256",
        "expected_task_state_sha256",
        "destination",
        "source_name",
        "source_path_sha256",
        "content_sha256",
        "content_size_bytes",
        "purpose",
        "expires_at",
        "intent_sha256",
    }
)
_PERMIT_FIELDS = frozenset(
    {
        "schema_version",
        "contract_type",
        "task_id",
        "export_id",
        "intent_sha256",
        "expected_task_state_sha256",
        "expires_at",
        "nonce",
        "chief_authority",
        "permit_sha256",
    }
)
_CHIEF_FIELDS = frozenset(
    {"session_id", "epoch", "authority_record_sha256"}
)
_ISSUANCE_FIELDS = frozenset(
    {
        "schema_version",
        "contract_type",
        "task_id",
        "export_id",
        "intent_sha256",
        "permit_sha256",
        "config_sha256",
        "expected_task_state_sha256",
        "issuance_sha256",
    }
)
_CONSUMPTION_FIELDS = frozenset(
    {
        "schema_version",
        "contract_type",
        "task_id",
        "export_id",
        "intent_sha256",
        "permit_sha256",
        "replay_marker",
        "destination",
        "source_name",
        "source_path_sha256",
        "content_sha256",
        "content_size_bytes",
        "purpose",
        "consumed_at",
        "publication_observed",
        "receipt_sha256",
    }
)


class ExternalExportError(h.HarnessError):
    """An external-export contract or one-shot transition is unsafe."""


def _fail(message: str) -> NoReturn:
    raise ExternalExportError(message)


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        _fail(f"{label} is not lowercase SHA-256")
    return value


def _id(value: Any, label: str) -> str:
    try:
        return h.validate_id(value, label)
    except h.HarnessError as exc:
        raise ExternalExportError(str(exc)) from exc


def _bounded_text(value: Any, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        _fail(f"{label} is invalid")
    return value


def validate_external_destination(value: Any) -> str:
    """Require one exact non-local URI without embedded credentials."""

    destination = _bounded_text(value, "external destination", MAX_DESTINATION_CHARS)
    if "\\" in destination:
        _fail("external destination must be an exact URI, not a path")
    try:
        parsed = urlsplit(destination)
    except ValueError as exc:
        raise ExternalExportError("external destination URI is invalid") from exc
    if (
        not parsed.scheme
        or destination.split(":", 1)[0] != parsed.scheme
        or not _URI_SCHEME.fullmatch(parsed.scheme)
        or parsed.scheme in {"file", "data"}
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        _fail(
            "external destination must be a credential-free absolute URI with "
            "lowercase scheme and no query or fragment"
        )
    return destination


def _parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        _fail(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
    except ValueError as exc:
        raise ExternalExportError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail(f"{label} needs a timezone")
    return parsed


def _canonical_time(value: Any, label: str) -> str:
    parsed = _parse_time(value, label).astimezone(timezone.utc)
    return parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _aware_now(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail("current_time needs a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _seal(base: Mapping[str, Any], digest_field: str) -> dict[str, Any]:
    result = dict(base)
    try:
        result[digest_field] = semantic.canonical_sha256(
            result, max_bytes=MAX_CONTRACT_BYTES
        )
        semantic.canonical_json_bytes(result, max_bytes=MAX_CONTRACT_BYTES)
    except semantic.SemanticEventError as exc:
        raise ExternalExportError(f"external-export contract is invalid: {exc}") from exc
    return result


def _validate_sealed(
    value: Mapping[str, Any],
    *,
    fields: frozenset[str],
    digest_field: str,
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(f"{label} schema is invalid")
    item = dict(value)
    actual = _sha256(item.pop(digest_field), f"{label} {digest_field}")
    expected = semantic.canonical_sha256(item, max_bytes=MAX_CONTRACT_BYTES)
    if actual != expected:
        _fail(f"{label} {digest_field} does not match its contract")
    return {**item, digest_field: actual}


def source_path_sha256(path: Path) -> str:
    """Hash the exact canonical path without publishing it into AOI state."""

    canonical = h.canonicalize_no_link_traversal(path, "external export source")
    normalized = os.path.normcase(str(canonical))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def snapshot_source_file(path: Path) -> dict[str, Any]:
    """Stream-hash one stable regular, single-link source file."""

    canonical = h.canonicalize_no_link_traversal(path, "external export source")
    h.validate_existing_regular_file(canonical, "external export source")
    try:
        before = canonical.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            _fail("external export source must be one regular non-linked file")
        digest = hashlib.sha256()
        size = 0
        with canonical.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                _fail("external export source changed while being opened")
            while True:
                chunk = handle.read(FILE_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
            finished = os.fstat(handle.fileno())
        after = canonical.lstat()
    except ExternalExportError:
        raise
    except OSError as exc:
        raise ExternalExportError(f"cannot read external export source: {exc}") from exc
    identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_nlink")
    if (
        any(getattr(before, field) != getattr(opened, field) for field in identity_fields)
        or any(getattr(before, field) != getattr(finished, field) for field in identity_fields)
        or any(getattr(before, field) != getattr(after, field) for field in identity_fields)
        or size != before.st_size
        or h.canonicalize_no_link_traversal(canonical, "external export source")
        != canonical
    ):
        _fail("external export source changed while being hashed")
    source_name = _bounded_text(canonical.name, "source name", MAX_SOURCE_NAME_CHARS)
    return {
        "source_name": source_name,
        "source_path_sha256": source_path_sha256(canonical),
        "content_sha256": digest.hexdigest(),
        "content_size_bytes": size,
    }


def _task_state_sha256(paths: h.HarnessPaths, task_id: str) -> str:
    h.load_task(paths, task_id)
    _identity, raw = h._read_regular_file_snapshot(
        h.task_state_path(paths, task_id),
        "external export task state",
        max_bytes=h.MANAGED_JSON_MAX_BYTES,
    )
    return hashlib.sha256(raw).hexdigest()


def seal_external_export_intent(
    *,
    task_id: str,
    export_id: str,
    config_sha256: str,
    expected_task_state_sha256: str,
    destination: str,
    source: Mapping[str, Any],
    purpose: str,
    expires_at: str,
) -> dict[str, Any]:
    size = source.get("content_size_bytes")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        _fail("content_size_bytes is invalid")
    base = {
        "schema_version": SCHEMA_VERSION,
        "contract_type": INTENT_CONTRACT_TYPE,
        "task_id": _id(task_id, "task id"),
        "export_id": _id(export_id, "external export id"),
        "config_sha256": _sha256(config_sha256, "configuration SHA-256"),
        "expected_task_state_sha256": _sha256(
            expected_task_state_sha256, "expected task state SHA-256"
        ),
        "destination": validate_external_destination(destination),
        "source_name": _bounded_text(
            source.get("source_name"), "source name", MAX_SOURCE_NAME_CHARS
        ),
        "source_path_sha256": _sha256(
            source.get("source_path_sha256"), "source path SHA-256"
        ),
        "content_sha256": _sha256(
            source.get("content_sha256"), "content SHA-256"
        ),
        "content_size_bytes": size,
        "purpose": _bounded_text(purpose, "external export purpose", MAX_PURPOSE_CHARS),
        "expires_at": _canonical_time(expires_at, "external export expiry"),
    }
    return _seal(base, "intent_sha256")


def validate_external_export_intent(value: Mapping[str, Any]) -> dict[str, Any]:
    item = _validate_sealed(
        value,
        fields=_INTENT_FIELDS,
        digest_field="intent_sha256",
        label="external export intent",
    )
    if (
        item.get("schema_version") != SCHEMA_VERSION
        or item.get("contract_type") != INTENT_CONTRACT_TYPE
    ):
        _fail("external export intent version or type is invalid")
    expected = seal_external_export_intent(
        task_id=item["task_id"],
        export_id=item["export_id"],
        config_sha256=item["config_sha256"],
        expected_task_state_sha256=item["expected_task_state_sha256"],
        destination=item["destination"],
        source=item,
        purpose=item["purpose"],
        expires_at=item["expires_at"],
    )
    if expected != item:
        _fail("external export intent canonical fields drifted")
    return expected


def _validate_chief_authority(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _CHIEF_FIELDS:
        _fail("external export Chief authority schema is invalid")
    epoch = value.get("epoch")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
        _fail("external export Chief epoch is invalid")
    return {
        "session_id": _id(value.get("session_id"), "external export Chief session"),
        "epoch": epoch,
        "authority_record_sha256": _sha256(
            value.get("authority_record_sha256"), "Chief authority record SHA-256"
        ),
    }


def seal_external_export_permit(
    intent: Mapping[str, Any], chief_authority: Mapping[str, Any]
) -> dict[str, Any]:
    checked_intent = validate_external_export_intent(intent)
    checked_chief = _validate_chief_authority(chief_authority)
    nonce = semantic.canonical_sha256(
        {
            "contract_type": PERMIT_CONTRACT_TYPE,
            "intent_sha256": checked_intent["intent_sha256"],
            "chief_authority": checked_chief,
        },
        max_bytes=MAX_CONTRACT_BYTES,
    )
    base = {
        "schema_version": SCHEMA_VERSION,
        "contract_type": PERMIT_CONTRACT_TYPE,
        "task_id": checked_intent["task_id"],
        "export_id": checked_intent["export_id"],
        "intent_sha256": checked_intent["intent_sha256"],
        "expected_task_state_sha256": checked_intent[
            "expected_task_state_sha256"
        ],
        "expires_at": checked_intent["expires_at"],
        "nonce": nonce,
        "chief_authority": checked_chief,
    }
    return _seal(base, "permit_sha256")


def validate_external_export_permit(value: Mapping[str, Any]) -> dict[str, Any]:
    item = _validate_sealed(
        value,
        fields=_PERMIT_FIELDS,
        digest_field="permit_sha256",
        label="external export permit",
    )
    chief = _validate_chief_authority(item["chief_authority"])
    base = {key: item[key] for key in item if key != "permit_sha256"}
    if (
        base.get("schema_version") != SCHEMA_VERSION
        or base.get("contract_type") != PERMIT_CONTRACT_TYPE
    ):
        _fail("external export permit version or type is invalid")
    for field in ("task_id", "export_id"):
        base[field] = _id(base[field], f"external export permit {field}")
    for field in (
        "intent_sha256",
        "expected_task_state_sha256",
        "nonce",
    ):
        base[field] = _sha256(base[field], f"external export permit {field}")
    base["expires_at"] = _canonical_time(
        base["expires_at"], "external export permit expiry"
    )
    base["chief_authority"] = chief
    expected = _seal(base, "permit_sha256")
    if expected["permit_sha256"] != item["permit_sha256"]:
        _fail("external export permit canonical fields drifted")
    return expected


def _seal_issuance(intent: Mapping[str, Any], permit: Mapping[str, Any]) -> dict[str, Any]:
    checked_intent = validate_external_export_intent(intent)
    checked_permit = validate_external_export_permit(permit)
    if (
        checked_permit["task_id"] != checked_intent["task_id"]
        or checked_permit["export_id"] != checked_intent["export_id"]
        or checked_permit["intent_sha256"] != checked_intent["intent_sha256"]
        or checked_permit["expected_task_state_sha256"]
        != checked_intent["expected_task_state_sha256"]
        or checked_permit["expires_at"] != checked_intent["expires_at"]
    ):
        _fail("external export permit does not bind the exact intent")
    base = {
        "schema_version": SCHEMA_VERSION,
        "contract_type": ISSUANCE_CONTRACT_TYPE,
        "task_id": checked_intent["task_id"],
        "export_id": checked_intent["export_id"],
        "intent_sha256": checked_intent["intent_sha256"],
        "permit_sha256": checked_permit["permit_sha256"],
        "config_sha256": checked_intent["config_sha256"],
        "expected_task_state_sha256": checked_intent[
            "expected_task_state_sha256"
        ],
    }
    return _seal(base, "issuance_sha256")


def validate_external_export_issuance(value: Mapping[str, Any]) -> dict[str, Any]:
    item = _validate_sealed(
        value,
        fields=_ISSUANCE_FIELDS,
        digest_field="issuance_sha256",
        label="external export issuance",
    )
    if item.get("schema_version") != SCHEMA_VERSION or item.get("contract_type") != ISSUANCE_CONTRACT_TYPE:
        _fail("external export issuance version or type is invalid")
    for field in ("task_id", "export_id"):
        _id(item[field], f"external export issuance {field}")
    for field in (
        "intent_sha256",
        "permit_sha256",
        "config_sha256",
        "expected_task_state_sha256",
        "issuance_sha256",
    ):
        _sha256(item[field], f"external export issuance {field}")
    return item


def _external_root(paths: h.HarnessPaths, task_id: str) -> Path:
    return h.task_dir(paths, _id(task_id, "task id")) / EXTERNAL_EXPORT_DIRECTORY


def _private_directory(path: Path, label: str, *, create: bool) -> Path:
    try:
        canonical = h.canonicalize_no_link_traversal(path, label)
        if not canonical.exists():
            if not create:
                raise FileNotFoundError(canonical)
            canonical.mkdir(mode=0o700)
            if os.name != "nt":
                canonical.chmod(0o700)
        h.validate_existing_regular_directory(canonical, label)
        metadata = canonical.lstat()
        if (
            canonical != path
            or h._path_is_link_like(canonical)
            or not stat.S_ISDIR(metadata.st_mode)
            or (os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077)
        ):
            _fail(f"{label} is unsafe")
        return canonical
    except ExternalExportError:
        raise
    except (OSError, h.HarnessError) as exc:
        raise ExternalExportError(f"cannot validate {label}: {exc}") from exc


def _directories(paths: h.HarnessPaths, task_id: str) -> dict[str, Path]:
    root = _private_directory(
        _external_root(paths, task_id), "external export root", create=True
    )
    return {
        name: _private_directory(root / name, f"external export {name}", create=True)
        for name in ("intents", "permits", "issuances", "consumptions")
    }


def _read_contract(path: Path, label: str) -> dict[str, Any]:
    try:
        _identity, raw = h._read_regular_file_snapshot(
            path, label, max_bytes=MAX_CONTRACT_BYTES
        )
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            _fail(f"{label} must be a JSON object")
        if raw != semantic.canonical_json_bytes(value, max_bytes=MAX_CONTRACT_BYTES):
            _fail(f"{label} is not canonical JSON")
        return value
    except ExternalExportError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, h.HarnessError, semantic.SemanticEventError) as exc:
        raise ExternalExportError(f"cannot read {label}: {exc}") from exc


def _publish_exact(path: Path, value: Mapping[str, Any], label: str) -> bool:
    raw = semantic.canonical_json_bytes(dict(value), max_bytes=MAX_CONTRACT_BYTES)
    if path.exists():
        existing = _read_contract(path, label)
        if semantic.canonical_json_bytes(existing, max_bytes=MAX_CONTRACT_BYTES) != raw:
            _fail(f"{label} already exists with different bytes")
        return False
    try:
        h.atomic_create_bytes(path, raw)
        return True
    except FileExistsError:
        existing = _read_contract(path, label)
        if semantic.canonical_json_bytes(existing, max_bytes=MAX_CONTRACT_BYTES) != raw:
            _fail(f"{label} raced with different bytes")
        return False


def _issuance_path(directory: Path, export_id: str) -> Path:
    digest = hashlib.sha256(_id(export_id, "external export id").encode("utf-8")).hexdigest()
    return directory / f"{digest}.json"


def issue_external_export_permit(
    paths: h.HarnessPaths,
    *,
    task_id: str,
    export_id: str,
    source_file: Path,
    expected_content_sha256: str,
    destination: str,
    purpose: str,
    expires_at: str,
    chief_authority: Mapping[str, Any],
    current_time: datetime,
) -> dict[str, Any]:
    """Chief-issue one exact local-only permit; no credential enters the record."""

    h._require_chief_lock(paths)
    if not paths.project.confidentiality.local_files:
        _fail("external export permits require confidentiality.mode=local_files")
    task_id = _id(task_id, "task id")
    export_id = _id(export_id, "external export id")
    state = h.load_task(paths, task_id)
    if state.get("status") != "active" or not state.get("plan_ready"):
        _fail("external export permit requires one active task with an approved plan")
    now = _aware_now(current_time)
    expiry = _parse_time(expires_at, "external export expiry").astimezone(timezone.utc)
    if not now < expiry <= now + MAX_EXPORT_TTL:
        _fail("external export permit expiry must be in the next 15 minutes")
    source = snapshot_source_file(source_file)
    expected = _sha256(expected_content_sha256, "expected content SHA-256")
    if source["content_sha256"] != expected:
        _fail("external export source content differs from expected SHA-256")
    task_state_sha = _task_state_sha256(paths, task_id)
    intent = seal_external_export_intent(
        task_id=task_id,
        export_id=export_id,
        config_sha256=paths.project.sha256,
        expected_task_state_sha256=task_state_sha,
        destination=destination,
        source=source,
        purpose=purpose,
        expires_at=expiry.isoformat(timespec="microseconds").replace("+00:00", "Z"),
    )
    permit = seal_external_export_permit(intent, chief_authority)
    issuance = _seal_issuance(intent, permit)
    directories = _directories(paths, task_id)
    issuance_path = _issuance_path(directories["issuances"], export_id)
    if issuance_path.exists():
        existing_issuance = validate_external_export_issuance(
            _read_contract(issuance_path, "external export issuance")
        )
        if existing_issuance != issuance:
            _fail("external export id is already assigned to another exact permit")
    _publish_exact(
        directories["intents"] / f"{intent['intent_sha256']}.json",
        intent,
        "external export intent",
    )
    _publish_exact(
        directories["permits"] / f"{permit['permit_sha256']}.json",
        permit,
        "external export permit",
    )
    fresh_issuance = _publish_exact(
        issuance_path,
        issuance,
        "external export issuance",
    )
    return {
        "task_id": task_id,
        "export_id": export_id,
        "intent_sha256": intent["intent_sha256"],
        "permit_sha256": permit["permit_sha256"],
        "expected_task_state_sha256": task_state_sha,
        "destination": intent["destination"],
        "source_name": intent["source_name"],
        "source_path_sha256": intent["source_path_sha256"],
        "content_sha256": intent["content_sha256"],
        "content_size_bytes": intent["content_size_bytes"],
        "purpose": intent["purpose"],
        "expires_at": intent["expires_at"],
        "idempotent_replay": not fresh_issuance,
        "publication_observed": False,
    }


def _load_issued_material(
    paths: h.HarnessPaths, task_id: str, permit_sha256: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Path]]:
    directories = _directories(paths, task_id)
    permit_sha256 = _sha256(permit_sha256, "external export permit SHA-256")
    permit = validate_external_export_permit(
        _read_contract(
            directories["permits"] / f"{permit_sha256}.json",
            "external export permit",
        )
    )
    if permit["task_id"] != task_id or permit["permit_sha256"] != permit_sha256:
        _fail("external export permit identity is invalid")
    intent = validate_external_export_intent(
        _read_contract(
            directories["intents"] / f"{permit['intent_sha256']}.json",
            "external export intent",
        )
    )
    issuance = validate_external_export_issuance(
        _read_contract(
            _issuance_path(directories["issuances"], permit["export_id"]),
            "external export issuance",
        )
    )
    expected_issuance = _seal_issuance(intent, permit)
    if issuance != expected_issuance:
        _fail("external export issuance does not bind its permit and intent")
    return intent, permit, issuance, directories


def _seal_consumption(
    intent: Mapping[str, Any], permit: Mapping[str, Any], consumed_at: str
) -> dict[str, Any]:
    replay_marker = semantic.canonical_sha256(
        {
            "contract_type": CONSUMPTION_CONTRACT_TYPE,
            "permit_sha256": permit["permit_sha256"],
            "nonce": permit["nonce"],
        },
        max_bytes=MAX_CONTRACT_BYTES,
    )
    base = {
        "schema_version": SCHEMA_VERSION,
        "contract_type": CONSUMPTION_CONTRACT_TYPE,
        "task_id": intent["task_id"],
        "export_id": intent["export_id"],
        "intent_sha256": intent["intent_sha256"],
        "permit_sha256": permit["permit_sha256"],
        "replay_marker": replay_marker,
        "destination": intent["destination"],
        "source_name": intent["source_name"],
        "source_path_sha256": intent["source_path_sha256"],
        "content_sha256": intent["content_sha256"],
        "content_size_bytes": intent["content_size_bytes"],
        "purpose": intent["purpose"],
        "consumed_at": _canonical_time(consumed_at, "external export consumption time"),
        "publication_observed": False,
    }
    return _seal(base, "receipt_sha256")


def validate_external_export_consumption(value: Mapping[str, Any]) -> dict[str, Any]:
    item = _validate_sealed(
        value,
        fields=_CONSUMPTION_FIELDS,
        digest_field="receipt_sha256",
        label="external export consumption receipt",
    )
    if item.get("schema_version") != SCHEMA_VERSION or item.get("contract_type") != CONSUMPTION_CONTRACT_TYPE:
        _fail("external export consumption receipt version or type is invalid")
    if item.get("publication_observed") is not False:
        _fail("external export consumption receipt cannot claim publication")
    _id(item.get("task_id"), "external export receipt task id")
    _id(item.get("export_id"), "external export receipt export id")
    validate_external_destination(item.get("destination"))
    _bounded_text(item.get("source_name"), "source name", MAX_SOURCE_NAME_CHARS)
    _bounded_text(item.get("purpose"), "external export purpose", MAX_PURPOSE_CHARS)
    for field in (
        "intent_sha256",
        "permit_sha256",
        "replay_marker",
        "source_path_sha256",
        "content_sha256",
        "receipt_sha256",
    ):
        _sha256(item.get(field), f"external export receipt {field}")
    size = item.get("content_size_bytes")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        _fail("external export receipt content size is invalid")
    _canonical_time(item.get("consumed_at"), "external export consumption time")
    return item


def _require_current_chief(
    paths: h.HarnessPaths, permit: Mapping[str, Any], current_time: datetime
) -> None:
    authority = h.load_chief_authority(paths)
    chief = permit["chief_authority"]
    if (
        authority.get("status") != "active"
        or authority.get("session_id") != chief["session_id"]
        or authority.get("epoch") != chief["epoch"]
    ):
        _fail("external export permit issuer is not the current Chief authority")
    chief_expiry = h.parse_tz_aware_time(authority.get("expires_at"))
    if chief_expiry is None or _aware_now(current_time) >= chief_expiry.astimezone(timezone.utc):
        _fail("external export permit issuer Chief lease is expired")


def consume_external_export_permit(
    paths: h.HarnessPaths,
    *,
    task_id: str,
    permit_sha256: str,
    source_file: Path,
    destination: str,
    purpose: str,
    current_time: datetime,
) -> dict[str, Any]:
    """Spend one permit before export; exact retry never re-authorizes export."""

    h._require_chief_lock(paths)
    if not paths.project.confidentiality.local_files:
        _fail("external export permits require confidentiality.mode=local_files")
    task_id = _id(task_id, "task id")
    intent, permit, _issuance, directories = _load_issued_material(
        paths, task_id, permit_sha256
    )
    if validate_external_destination(destination) != intent["destination"]:
        _fail("external export destination differs from the issued permit")
    if _bounded_text(purpose, "external export purpose", MAX_PURPOSE_CHARS) != intent["purpose"]:
        _fail("external export purpose differs from the issued permit")
    requested_path_sha = source_path_sha256(source_file)
    if requested_path_sha != intent["source_path_sha256"]:
        _fail("external export source path differs from the issued permit")
    receipt_path = directories["consumptions"] / f"{permit['permit_sha256']}.json"
    if receipt_path.exists():
        receipt = validate_external_export_consumption(
            _read_contract(receipt_path, "external export consumption receipt")
        )
        expected = _seal_consumption(intent, permit, receipt["consumed_at"])
        if receipt != expected:
            _fail("external export consumption receipt does not bind the issued permit")
        return {
            **receipt,
            "fresh_consumption": False,
            "authorization_status": "already_consumed_no_export_authority",
        }

    now = _aware_now(current_time)
    if now >= _parse_time(permit["expires_at"], "external export permit expiry").astimezone(timezone.utc):
        _fail("external export permit is expired")
    if paths.project.sha256 != intent["config_sha256"]:
        _fail("external export configuration binding drifted")
    if _task_state_sha256(paths, task_id) != intent["expected_task_state_sha256"]:
        _fail("external export task state drifted after permit issuance")
    _require_current_chief(paths, permit, now)
    source = snapshot_source_file(source_file)
    for field in (
        "source_name",
        "source_path_sha256",
        "content_sha256",
        "content_size_bytes",
    ):
        if source[field] != intent[field]:
            _fail(f"external export source {field} drifted after permit issuance")
    consumed_at = now.isoformat(timespec="microseconds").replace("+00:00", "Z")
    receipt = _seal_consumption(intent, permit, consumed_at)
    fresh = _publish_exact(
        receipt_path, receipt, "external export consumption receipt"
    )
    if not fresh:
        _fail("external export consumption raced; retry to inspect spent status")
    return {
        **receipt,
        "fresh_consumption": True,
        "authorization_status": "fresh_at_most_once_export_authorization",
    }


def inspect_external_export_records(
    state_dir: Path,
    task_ids: list[str],
    *,
    current_time: datetime,
) -> dict[str, Any]:
    """Read authenticated local issuance/consumption receipts for doctor.

    The caller decides how much of the exact destination to display.  No source
    path or credential value is stored in these records.
    """

    now = _aware_now(current_time)
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []
    for raw_task_id in task_ids:
        try:
            task_id = _id(raw_task_id, "external export doctor task id")
            root = state_dir / "tasks" / task_id / EXTERNAL_EXPORT_DIRECTORY
            if not root.exists():
                continue
            root = _private_directory(root, "external export root", create=False)
            directories = {
                name: _private_directory(
                    root / name, f"external export {name}", create=False
                )
                for name in ("intents", "permits", "issuances", "consumptions")
            }
            entries = sorted(directories["issuances"].iterdir(), key=lambda item: item.name)
            if len(entries) > MAX_EXPORT_RECORDS_PER_TASK:
                _fail("external export issuance count exceeds its per-task bound")
            for path in entries:
                if (
                    path.suffix != ".json"
                    or len(path.stem) != 64
                    or not _SHA256.fullmatch(path.stem)
                ):
                    _fail("external export issuance directory contains an unexpected entry")
                issuance = validate_external_export_issuance(
                    _read_contract(path, "external export issuance")
                )
                if issuance["task_id"] != task_id:
                    _fail("external export issuance belongs to another task")
                expected_name = hashlib.sha256(
                    issuance["export_id"].encode("utf-8")
                ).hexdigest()
                if path.name != f"{expected_name}.json":
                    _fail("external export issuance filename is not canonical")
                intent = validate_external_export_intent(
                    _read_contract(
                        directories["intents"]
                        / f"{issuance['intent_sha256']}.json",
                        "external export intent",
                    )
                )
                permit = validate_external_export_permit(
                    _read_contract(
                        directories["permits"]
                        / f"{issuance['permit_sha256']}.json",
                        "external export permit",
                    )
                )
                if _seal_issuance(intent, permit) != issuance:
                    _fail("external export issuance material is not exact")
                consumption_path = (
                    directories["consumptions"]
                    / f"{permit['permit_sha256']}.json"
                )
                receipt: dict[str, Any] | None = None
                if consumption_path.exists():
                    receipt = validate_external_export_consumption(
                        _read_contract(
                            consumption_path,
                            "external export consumption receipt",
                        )
                    )
                    if receipt != _seal_consumption(
                        intent, permit, receipt["consumed_at"]
                    ):
                        _fail(
                            "external export consumption receipt does not bind its issuance"
                        )
                expired = now >= _parse_time(
                    permit["expires_at"], "external export permit expiry"
                ).astimezone(timezone.utc)
                rows.append(
                    {
                        "task_id": task_id,
                        "export_id": intent["export_id"],
                        "intent_sha256": intent["intent_sha256"],
                        "permit_sha256": permit["permit_sha256"],
                        "config_sha256": intent["config_sha256"],
                        "destination": intent["destination"],
                        "source_name": intent["source_name"],
                        "source_path_sha256": intent["source_path_sha256"],
                        "content_sha256": intent["content_sha256"],
                        "content_size_bytes": intent["content_size_bytes"],
                        "purpose": intent["purpose"],
                        "expires_at": intent["expires_at"],
                        "status": "consumed" if receipt else (
                            "expired_unconsumed" if expired else "issued_unconsumed"
                        ),
                        "receipt_sha256": receipt["receipt_sha256"] if receipt else "",
                        "publication_observed": False,
                    }
                )
                if len(rows) > MAX_EXPORT_RECORDS_TOTAL:
                    _fail("external export record count exceeds its global bound")
        except (ExternalExportError, OSError) as exc:
            errors.append(f"task {raw_task_id}: {exc}")
    rows.sort(key=lambda item: (item["task_id"], item["export_id"]))
    return {
        "records": rows,
        "errors": list(dict.fromkeys(errors)),
        "warnings": list(dict.fromkeys(warnings)),
    }


__all__ = [
    "CONSUMPTION_CONTRACT_TYPE",
    "EXTERNAL_EXPORT_DIRECTORY",
    "ExternalExportError",
    "INTENT_CONTRACT_TYPE",
    "ISSUANCE_CONTRACT_TYPE",
    "MAX_EXPORT_TTL",
    "PERMIT_CONTRACT_TYPE",
    "consume_external_export_permit",
    "issue_external_export_permit",
    "inspect_external_export_records",
    "seal_external_export_intent",
    "seal_external_export_permit",
    "snapshot_source_file",
    "source_path_sha256",
    "validate_external_destination",
    "validate_external_export_consumption",
    "validate_external_export_intent",
    "validate_external_export_issuance",
    "validate_external_export_permit",
]
