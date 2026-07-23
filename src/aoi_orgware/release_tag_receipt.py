"""Content-addressed cooperative preflight and readback receipts for release tags."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import re
from typing import Any, NoReturn

from . import confidentiality, release_ci_receipt


MAX_RELEASE_TAG_RECEIPT_BYTES = 1024 * 1024
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_TAG = re.compile(
    r"v[0-9]+\.[0-9]+\.[0-9]+(?:[a-z]+[0-9]+)?(?:[.]post[0-9]+)?(?:[.]dev[0-9]+)?\Z"
)


class ReleaseTagReceiptError(ValueError):
    """A release-tag preflight or delivery receipt is invalid."""


def _fail(message: str) -> NoReturn:
    raise ReleaseTagReceiptError(message)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        _fail(f"{label} must be non-empty canonical text")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail(f"{label} must be one lowercase SHA-256")
    return value


def _oid(value: object, label: str) -> str:
    if not isinstance(value, str) or _OID.fullmatch(value) is None:
        _fail(f"{label} must be one lowercase Git object id")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _fail(f"{label} must be a positive integer")
    return value


def _canonical(value: Mapping[str, Any]) -> bytes:
    try:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _fail(f"release-tag receipt is not canonical JSON data: {exc}")
    if len(raw) > MAX_RELEASE_TAG_RECEIPT_BYTES:
        _fail("release-tag receipt exceeds its byte bound")
    return raw


def _seal(base: Mapping[str, Any]) -> dict[str, Any]:
    sealed = dict(base)
    sealed["receipt_sha256"] = hashlib.sha256(_canonical(base)).hexdigest()
    return sealed


def _validate_confidentiality_preflight(value: object) -> str:
    """Validate the embedded Git preflight and normalize its error surface."""

    if not isinstance(value, Mapping):
        _fail("confidentiality preflight must be an object")
    try:
        return confidentiality.validate_git_push_preflight_receipt_structure(value)
    except confidentiality.ConfidentialityError as exc:
        _fail(f"release-tag confidentiality preflight is invalid: {exc}")


def build_release_tag_preflight(
    *,
    task_id: str,
    task_plan_sha256: str,
    verification_index: int,
    verification_record_sha256: str,
    verification_artifact_sha256: str,
    exact_ci_receipt: Mapping[str, Any],
    tag: str,
    tag_object_oid: str,
    remote: str,
    push_transport: str,
    destination: str,
    confidentiality_preflight: Mapping[str, Any],
) -> dict[str, Any]:
    exact_ci = release_ci_receipt.validate_exact_ci_receipt(exact_ci_receipt)
    tag = _text(tag, "release tag")
    if _TAG.fullmatch(tag) is None:
        _fail("release tag is invalid")
    tag_object_oid = _oid(tag_object_oid, "release tag object")
    commit = _oid(exact_ci["commit"], "release peeled commit")
    if len(tag_object_oid) != len(commit) or tag_object_oid == commit:
        _fail("release tag must be one annotated tag object distinct from its commit")
    preflight_digest = _validate_confidentiality_preflight(
        confidentiality_preflight
    )
    base = {
        "schema_version": 1,
        "action": "release_tag_push_preflight",
        "boundary": "aoi_cooperative_preflight_not_system_dlp",
        "task_id": _text(task_id, "task id"),
        "task_plan_sha256": _sha256(task_plan_sha256, "task plan SHA-256"),
        "release_ci_verification": {
            "verification_index": _positive_int(
                verification_index, "release-CI verification index"
            ),
            "verification_record_sha256": _sha256(
                verification_record_sha256,
                "release-CI verification record SHA-256",
            ),
            "artifact_sha256": _sha256(
                verification_artifact_sha256,
                "release-CI verification artifact SHA-256",
            ),
            "receipt_sha256": exact_ci["receipt_sha256"],
        },
        "repository": exact_ci["repository"],
        "branch": exact_ci["branch"],
        "event": exact_ci["event"],
        "tag": tag,
        "tag_ref": f"refs/tags/{tag}",
        "tag_object_oid": tag_object_oid,
        "peeled_commit_oid": commit,
        "remote": _text(remote, "release remote"),
        # This is the exact credential-free transport string used for the
        # push/readback.  URL interpretation belongs in the command layer;
        # receipts only bind the supplied canonical text end-to-end.
        "push_transport": _text(push_transport, "release push transport"),
        "destination": _text(destination, "release destination"),
        "confidentiality_preflight": dict(confidentiality_preflight),
        "confidentiality_preflight_sha256": preflight_digest,
        "decision": "allowed",
    }
    return validate_release_tag_preflight(_seal(base), exact_ci_receipt=exact_ci)


def validate_release_tag_preflight(
    value: Mapping[str, Any],
    *,
    exact_ci_receipt: Mapping[str, Any],
    expected_task_id: str | None = None,
    expected_plan_sha256: str | None = None,
) -> dict[str, Any]:
    expected_keys = {
        "schema_version",
        "action",
        "boundary",
        "task_id",
        "task_plan_sha256",
        "release_ci_verification",
        "repository",
        "branch",
        "event",
        "tag",
        "tag_ref",
        "tag_object_oid",
        "peeled_commit_oid",
        "remote",
        "push_transport",
        "destination",
        "confidentiality_preflight",
        "confidentiality_preflight_sha256",
        "decision",
        "receipt_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != expected_keys:
        _fail("release-tag preflight receipt schema is invalid")
    exact_ci = release_ci_receipt.validate_exact_ci_receipt(exact_ci_receipt)
    task_id = _text(value.get("task_id"), "release-tag task id")
    plan_sha = _sha256(value.get("task_plan_sha256"), "release-tag task plan")
    tag = _text(value.get("tag"), "release tag")
    tag_ref = _text(value.get("tag_ref"), "release tag ref")
    tag_object = _oid(value.get("tag_object_oid"), "release tag object")
    peeled_commit = _oid(value.get("peeled_commit_oid"), "release peeled commit")
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("action") != "release_tag_push_preflight"
        or value.get("boundary") != "aoi_cooperative_preflight_not_system_dlp"
        or value.get("decision") != "allowed"
        or value.get("repository") != exact_ci["repository"]
        or value.get("branch") != exact_ci["branch"]
        or value.get("event") != exact_ci["event"]
        or peeled_commit != exact_ci["commit"]
        or _TAG.fullmatch(tag) is None
        or tag_ref != f"refs/tags/{tag}"
        or len(tag_object) != len(peeled_commit)
        or tag_object == peeled_commit
        or (expected_task_id is not None and task_id != expected_task_id)
        or (
            expected_plan_sha256 is not None
            and plan_sha != expected_plan_sha256
        )
    ):
        _fail("release-tag preflight receipt identity is invalid")
    verification = value.get("release_ci_verification")
    if not isinstance(verification, Mapping) or set(verification) != {
        "verification_index",
        "verification_record_sha256",
        "artifact_sha256",
        "receipt_sha256",
    }:
        _fail("release-tag preflight verification binding is invalid")
    _positive_int(
        verification.get("verification_index"), "release-CI verification index"
    )
    _sha256(
        verification.get("verification_record_sha256"),
        "release-CI verification record SHA-256",
    )
    _sha256(
        verification.get("artifact_sha256"),
        "release-CI verification artifact SHA-256",
    )
    if verification.get("receipt_sha256") != exact_ci["receipt_sha256"]:
        _fail("release-tag preflight binds another exact-CI receipt")
    confidentiality = value.get("confidentiality_preflight")
    validated_confidentiality_digest = _validate_confidentiality_preflight(
        confidentiality
    )
    confidentiality_digest = _sha256(
        value.get("confidentiality_preflight_sha256"),
        "release-tag confidentiality preflight SHA-256",
    )
    if validated_confidentiality_digest != confidentiality_digest:
        _fail("release-tag confidentiality preflight digest is inconsistent")
    _text(value.get("remote"), "release remote")
    _text(value.get("push_transport"), "release push transport")
    _text(value.get("destination"), "release destination")
    claimed = _sha256(value.get("receipt_sha256"), "release-tag receipt digest")
    base = dict(value)
    del base["receipt_sha256"]
    if claimed != hashlib.sha256(_canonical(base)).hexdigest():
        _fail("release-tag preflight receipt digest is invalid")
    return dict(value)


def build_release_tag_delivery(
    *,
    preflight: Mapping[str, Any],
    exact_ci_receipt: Mapping[str, Any],
    preflight_verification_index: int,
    preflight_verification_record_sha256: str,
    preflight_artifact_sha256: str,
    remote_tag_object_oid: str,
    remote_peeled_commit_oid: str,
    observed_destination: str,
) -> dict[str, Any]:
    validated = validate_release_tag_preflight(
        preflight, exact_ci_receipt=exact_ci_receipt
    )
    remote_tag_object_oid = _oid(
        remote_tag_object_oid, "remote release tag object"
    )
    remote_peeled_commit_oid = _oid(
        remote_peeled_commit_oid, "remote release peeled commit"
    )
    if (
        remote_tag_object_oid != validated["tag_object_oid"]
        or remote_peeled_commit_oid != validated["peeled_commit_oid"]
        or observed_destination != validated["destination"]
    ):
        _fail("remote release tag readback differs from its preflight")
    base = {
        "schema_version": 1,
        "action": "release_tag_delivery_verified",
        "boundary": "authenticated_remote_tag_readback_not_task_completion",
        "task_id": validated["task_id"],
        "task_plan_sha256": validated["task_plan_sha256"],
        "preflight_receipt_sha256": validated["receipt_sha256"],
        "preflight_verification": {
            "verification_index": _positive_int(
                preflight_verification_index,
                "release-tag preflight verification index",
            ),
            "verification_record_sha256": _sha256(
                preflight_verification_record_sha256,
                "release-tag preflight verification record SHA-256",
            ),
            "artifact_sha256": _sha256(
                preflight_artifact_sha256,
                "release-tag preflight artifact SHA-256",
            ),
            "receipt_sha256": validated["receipt_sha256"],
        },
        "release_ci_artifact_sha256": validated["release_ci_verification"][
            "artifact_sha256"
        ],
        "release_ci_receipt_sha256": validated["release_ci_verification"][
            "receipt_sha256"
        ],
        "repository": validated["repository"],
        "tag": validated["tag"],
        "tag_ref": validated["tag_ref"],
        "tag_object_oid": remote_tag_object_oid,
        "peeled_commit_oid": remote_peeled_commit_oid,
        "remote": validated["remote"],
        "push_transport": validated["push_transport"],
        "destination": observed_destination,
        "observation": "remote_ref_and_peeled_commit_match",
    }
    return validate_release_tag_delivery(
        _seal(base),
        preflight=validated,
        exact_ci_receipt=exact_ci_receipt,
        preflight_verification_index=preflight_verification_index,
        preflight_verification_record_sha256=preflight_verification_record_sha256,
        preflight_artifact_sha256=preflight_artifact_sha256,
    )


def validate_release_tag_delivery(
    value: Mapping[str, Any],
    *,
    preflight: Mapping[str, Any],
    exact_ci_receipt: Mapping[str, Any],
    preflight_verification_index: int,
    preflight_verification_record_sha256: str,
    preflight_artifact_sha256: str,
) -> dict[str, Any]:
    expected_keys = {
        "schema_version",
        "action",
        "boundary",
        "task_id",
        "task_plan_sha256",
        "preflight_receipt_sha256",
        "preflight_verification",
        "release_ci_artifact_sha256",
        "release_ci_receipt_sha256",
        "repository",
        "tag",
        "tag_ref",
        "tag_object_oid",
        "peeled_commit_oid",
        "remote",
        "push_transport",
        "destination",
        "observation",
        "receipt_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != expected_keys:
        _fail("release-tag delivery receipt schema is invalid")
    validated_preflight = validate_release_tag_preflight(
        preflight, exact_ci_receipt=exact_ci_receipt
    )
    verification = validated_preflight["release_ci_verification"]
    preflight_verification = value.get("preflight_verification")
    if not isinstance(preflight_verification, Mapping) or set(
        preflight_verification
    ) != {
        "verification_index",
        "verification_record_sha256",
        "artifact_sha256",
        "receipt_sha256",
    }:
        _fail("release-tag delivery preflight verification binding is invalid")
    _positive_int(
        preflight_verification.get("verification_index"),
        "release-tag preflight verification index",
    )
    _sha256(
        preflight_verification.get("verification_record_sha256"),
        "release-tag preflight verification record SHA-256",
    )
    observed_preflight_artifact_sha256 = _sha256(
        preflight_verification.get("artifact_sha256"),
        "release-tag preflight artifact SHA-256",
    )
    expected_preflight_artifact_sha256 = hashlib.sha256(
        _canonical(validated_preflight)
    ).hexdigest()
    expected_preflight_verification_index = _positive_int(
        preflight_verification_index,
        "expected release-tag preflight verification index",
    )
    expected_preflight_record_sha256 = _sha256(
        preflight_verification_record_sha256,
        "expected release-tag preflight verification record SHA-256",
    )
    supplied_preflight_artifact_sha256 = _sha256(
        preflight_artifact_sha256,
        "expected release-tag preflight artifact SHA-256",
    )
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("action") != "release_tag_delivery_verified"
        or value.get("boundary")
        != "authenticated_remote_tag_readback_not_task_completion"
        or value.get("observation") != "remote_ref_and_peeled_commit_match"
        or value.get("task_id") != validated_preflight.get("task_id")
        or value.get("task_plan_sha256")
        != validated_preflight.get("task_plan_sha256")
        or value.get("preflight_receipt_sha256")
        != validated_preflight.get("receipt_sha256")
        or preflight_verification.get("receipt_sha256")
        != validated_preflight.get("receipt_sha256")
        or preflight_verification.get("verification_index")
        != expected_preflight_verification_index
        or preflight_verification.get("verification_record_sha256")
        != expected_preflight_record_sha256
        or observed_preflight_artifact_sha256
        != supplied_preflight_artifact_sha256
        or observed_preflight_artifact_sha256
        != expected_preflight_artifact_sha256
        or value.get("release_ci_artifact_sha256")
        != verification.get("artifact_sha256")
        or value.get("release_ci_receipt_sha256")
        != verification.get("receipt_sha256")
        or value.get("repository") != validated_preflight.get("repository")
        or value.get("tag") != validated_preflight.get("tag")
        or value.get("tag_ref") != validated_preflight.get("tag_ref")
        or value.get("tag_object_oid")
        != validated_preflight.get("tag_object_oid")
        or value.get("peeled_commit_oid")
        != validated_preflight.get("peeled_commit_oid")
        or value.get("remote") != validated_preflight.get("remote")
        or value.get("push_transport")
        != validated_preflight.get("push_transport")
        or value.get("destination") != validated_preflight.get("destination")
    ):
        _fail("release-tag delivery receipt identity is invalid")
    _text(value.get("task_id"), "release-tag delivery task id")
    _sha256(
        value.get("task_plan_sha256"), "release-tag delivery task plan SHA-256"
    )
    _sha256(
        value.get("preflight_receipt_sha256"),
        "release-tag delivery preflight SHA-256",
    )
    _sha256(
        value.get("release_ci_artifact_sha256"),
        "release-tag delivery exact-CI artifact SHA-256",
    )
    _sha256(
        value.get("release_ci_receipt_sha256"),
        "release-tag delivery exact-CI receipt SHA-256",
    )
    _text(value.get("repository"), "release-tag delivery repository")
    _text(value.get("tag"), "release-tag delivery tag")
    _text(value.get("tag_ref"), "release-tag delivery tag ref")
    _oid(value.get("tag_object_oid"), "release-tag delivery object")
    _oid(value.get("peeled_commit_oid"), "release-tag delivery commit")
    _text(value.get("remote"), "release-tag delivery remote")
    _text(value.get("push_transport"), "release-tag delivery push transport")
    _text(value.get("destination"), "release-tag delivery destination")
    claimed = _sha256(value.get("receipt_sha256"), "release-tag delivery digest")
    base = dict(value)
    del base["receipt_sha256"]
    if claimed != hashlib.sha256(_canonical(base)).hexdigest():
        _fail("release-tag delivery receipt digest is invalid")
    return dict(value)


def canonical_release_tag_receipt_bytes(value: Mapping[str, Any]) -> bytes:
    """Serialize a previously validated preflight or delivery receipt."""

    action = value.get("action")
    if action == "release_tag_delivery_verified":
        # Full delivery validation requires its preflight; callers perform that
        # correlation before asking for canonical bytes. The self-digest still
        # prevents a different object from being serialized here.
        claimed = value.get("receipt_sha256")
        if not isinstance(claimed, str) or _SHA256.fullmatch(claimed) is None:
            _fail("release-tag delivery receipt digest is invalid")
        base = dict(value)
        del base["receipt_sha256"]
        if claimed != hashlib.sha256(_canonical(base)).hexdigest():
            _fail("release-tag delivery receipt digest is invalid")
    elif action == "release_tag_push_preflight":
        claimed = value.get("receipt_sha256")
        if not isinstance(claimed, str) or _SHA256.fullmatch(claimed) is None:
            _fail("release-tag preflight receipt digest is invalid")
        base = dict(value)
        del base["receipt_sha256"]
        if claimed != hashlib.sha256(_canonical(base)).hexdigest():
            _fail("release-tag preflight receipt digest is invalid")
    else:
        _fail("release-tag receipt action is invalid")
    return _canonical(value)


def parse_release_tag_receipt_bytes(raw: bytes) -> dict[str, Any]:
    """Strictly parse canonical receipt bytes without yet resolving CAS edges."""

    if (
        not isinstance(raw, bytes)
        or not raw
        or len(raw) > MAX_RELEASE_TAG_RECEIPT_BYTES
    ):
        _fail("release-tag receipt bytes are empty or exceed their bound")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                _fail(f"release-tag receipt contains duplicate JSON key: {key}")
            result[key] = item
        return result

    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"release-tag receipt is not strict UTF-8 JSON: {exc}")
    if not isinstance(parsed, Mapping):
        _fail("release-tag receipt root must be an object")
    if raw != _canonical(parsed):
        _fail("release-tag receipt bytes are not canonical JSON")
    return dict(parsed)


__all__ = [
    "MAX_RELEASE_TAG_RECEIPT_BYTES",
    "ReleaseTagReceiptError",
    "build_release_tag_delivery",
    "build_release_tag_preflight",
    "canonical_release_tag_receipt_bytes",
    "parse_release_tag_receipt_bytes",
    "validate_release_tag_delivery",
    "validate_release_tag_preflight",
]
