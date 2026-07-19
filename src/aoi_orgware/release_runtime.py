"""Chief-fenced semantic persistence for release promotions.

The pure release-manifest module says which bytes were tested and observed.
This module supplies the authority-bearing half: three immutable content objects,
one exact binding, one semantic event, and a projection that can be rebuilt
from those committed bindings.  The supported writer remains within AOI's
cooperative process/filesystem threat model; the detached bundle digest is a
trust-anchor input, not a digital signature.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from itertools import islice
import json
import re
from typing import Any, cast

from . import harnesslib as h
from . import release_artifacts as observations
from . import release_manifest as releases
from . import semantic_events as semantic
from . import semantic_objects as objects
from . import semantic_store as store


RELEASE_RUNTIME_SCHEMA_VERSION = 1
RELEASE_PROMOTION_TRANSACTION_SCHEMA_VERSION = 1
PROMOTION_BUNDLE_SCHEMA_VERSION = 1
PROMOTION_BUNDLE_PROOF_SCOPE = "release_namespace_delta_only"
RELEASE_ABANDONMENT_RECEIPT_SCHEMA_VERSION = 2
RELEASE_PROMOTION_INTENT_SCHEMA_VERSION = 1
RELEASE_ABANDONMENT_PROOF_SCOPE = "task_ledger_release_binding_abandonment"
RELEASE_NAMESPACE_KEY = "release_promotions"
RELEASE_EVENT_TYPE = "release_promoted"
RELEASE_ABANDONMENT_EVENT_TYPE = "release_promotion_abandoned"
RELEASE_BINDING_KIND = "release_promotion"
MAX_RELEASE_PROMOTIONS = 256
MAX_RELEASE_NAMESPACE_BYTES = 512 * 1024
MAX_RELEASE_TRANSACTION_BYTES = 2 * 1024 * 1024
MAX_PROMOTION_BUNDLE_BYTES = 2 * 1024 * 1024
MAX_RELEASE_ABANDONMENT_RECEIPT_BYTES = 2 * 1024 * 1024

_SHA256 = re.compile(r"[0-9a-f]{64}")
_AUTHORITY_REF = re.compile(
    r"chief:([A-Za-z0-9._-]{1,128}):e([1-9][0-9]*):release:([0-9a-f]{64})"
)
_ABANDON_AUTHORITY_REF = re.compile(
    r"chief:([A-Za-z0-9._-]{1,128}):e([1-9][0-9]*):release-abandon:([0-9a-f]{64})"
)
_NAMESPACE_FIELDS = {
    "schema_version",
    "active_promotion_receipt_sha256",
    "manifests",
    "promotions",
    "promotion_ids",
}
_PROMOTION_FIELDS = {
    "promotion_id",
    "distribution_name",
    "package_version",
    "manifest_sha256",
    "manifest_object_sha256",
    "observation_receipt_sha256",
    "observation_receipt_object_sha256",
    "promotion_receipt_object_sha256",
    "previous_active_promotion_receipt_sha256",
    "rollback_from_promotion_receipt_sha256",
}
_TRANSACTION_FIELDS = {
    "schema_version",
    "task_id",
    "event_type",
    "command_id",
    "recorded_at",
    "authority_ref",
    "expected_head_sha256",
    "result_state",
    "planned_event",
    "objects",
    "binding",
    "transaction_sha256",
}
_OBJECT_FIELDS = {
    "schema_version",
    "object_type",
    "task_id",
    "object_identity",
    "payload",
    "payload_sha256",
    "object_sha256",
}
_INTENT_FIELDS = {
    "schema_version",
    "command_id",
    "recorded_at",
    "authority_ref",
    "expected_head_sha256",
    "result_projection_sha256",
    "planned_event_sha256",
    "promotion_receipt_sha256",
}
_BINDING_FIELDS = {
    "schema_version",
    "binding_kind",
    "task_id",
    "binding_key",
    "expected_semantic_head_sha256",
    "planned_event_sha256",
    "result_projection_sha256",
    "object_sha256s",
    "binding_sha256",
}
_BUNDLE_FIELDS = {
    "schema_version",
    "proof_scope",
    "task_id",
    "manifest",
    "observation_receipt",
    "promotion_receipt",
    "prior_release_namespace",
    "semantic_binding",
    "semantic_event",
    "bundle_sha256",
}
_ABANDONMENT_RECEIPT_FIELDS = {
    "schema_version",
    "proof_scope",
    "task_id",
    "binding_sha256",
    "abandonment",
    "semantic_event",
    "receipt_sha256",
}


class ReleaseRuntimeError(h.HarnessError):
    """A release promotion transaction or persisted projection is unsafe."""


def _fail(message: str, exc: BaseException | None = None) -> ReleaseRuntimeError:
    return ReleaseRuntimeError(message if exc is None else f"{message}: {exc}")


def _clone(value: Any, *, maximum: int) -> Any:
    try:
        return json.loads(
            semantic.canonical_json_bytes(value, max_bytes=maximum).decode("utf-8")
        )
    except (semantic.SemanticEventError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise _fail("release runtime value is not bounded canonical JSON", exc) from exc


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ReleaseRuntimeError(f"{label} is not lowercase SHA-256")
    return value


def _exact_version(value: Any, expected: int, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value != expected:
        raise ReleaseRuntimeError(f"{label} is unsupported")


def _bounded_records(
    values: Iterable[Mapping[str, Any]], maximum: int, label: str
) -> list[Mapping[str, Any]]:
    if isinstance(values, (str, bytes, Mapping)):
        raise ReleaseRuntimeError(f"{label} must be an iterable of records")
    try:
        rows = list(islice(iter(values), maximum + 1))
    except TypeError as exc:
        raise _fail(f"{label} is not iterable", exc) from exc
    if not rows or len(rows) > maximum:
        raise ReleaseRuntimeError(f"{label} is empty or exceeds its count bound")
    return rows


def _freeze_event_chain(
    event_chain: Iterable[Mapping[str, Any]], task_id: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = _bounded_records(
        event_chain, semantic.MAX_LEDGER_EVENTS, "release semantic event chain"
    )
    try:
        replayed = semantic.replay_events(rows)
    except (semantic.SemanticEventError, TypeError, ValueError) as exc:
        raise _fail("release semantic event chain is invalid", exc) from exc
    domain = semantic.projection_domain(replayed)
    if domain.get("task_id") != task_id:
        raise ReleaseRuntimeError(
            "release semantic event chain belongs to another task"
        )
    return [
        _clone(row, maximum=semantic.MAX_EVENT_BYTES) for row in rows
    ], replayed


def _empty_namespace() -> dict[str, Any]:
    return {
        "schema_version": RELEASE_RUNTIME_SCHEMA_VERSION,
        "active_promotion_receipt_sha256": None,
        "manifests": {},
        "promotions": {},
        "promotion_ids": {},
    }


def validate_release_namespace(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate the bounded task-local promotion ownership projection."""

    if value is None:
        return _empty_namespace()
    if not isinstance(value, Mapping) or set(value) != _NAMESPACE_FIELDS:
        raise ReleaseRuntimeError("release promotion namespace schema is invalid")
    item = _clone(value, maximum=MAX_RELEASE_NAMESPACE_BYTES)
    _exact_version(
        item["schema_version"],
        RELEASE_RUNTIME_SCHEMA_VERSION,
        "release promotion namespace version",
    )
    manifests = item["manifests"]
    promotions = item["promotions"]
    promotion_ids = item["promotion_ids"]
    if (
        not isinstance(manifests, dict)
        or not isinstance(promotions, dict)
        or not isinstance(promotion_ids, dict)
        or len(manifests) > MAX_RELEASE_PROMOTIONS
        or len(promotions) > MAX_RELEASE_PROMOTIONS
        or len(promotion_ids) > MAX_RELEASE_PROMOTIONS
    ):
        raise ReleaseRuntimeError("release promotion namespace indexes are invalid")

    canonical_manifests: dict[str, str] = {}
    for manifest_sha, object_sha in manifests.items():
        canonical_manifests[_sha(manifest_sha, "release manifest index key")] = _sha(
            object_sha, "release manifest object SHA-256"
        )

    canonical_promotions: dict[str, dict[str, Any]] = {}
    seen_ids: set[str] = set()
    referenced_manifests: set[str] = set()
    for receipt_sha, raw in promotions.items():
        receipt_sha = _sha(receipt_sha, "promotion receipt index key")
        if not isinstance(raw, Mapping) or set(raw) != _PROMOTION_FIELDS:
            raise ReleaseRuntimeError("release promotion projection row is invalid")
        promotion_record = dict(raw)
        try:
            promotion_id = h.validate_id(
                promotion_record["promotion_id"], "promotion id"
            )
        except (h.HarnessError, TypeError) as exc:
            raise _fail("release promotion id is invalid", exc) from exc
        if promotion_id in seen_ids:
            raise ReleaseRuntimeError("release promotion ids are not unique")
        seen_ids.add(promotion_id)
        distribution_name = promotion_record["distribution_name"]
        package_version = promotion_record["package_version"]
        if not isinstance(distribution_name, str) or not distribution_name:
            raise ReleaseRuntimeError("release promotion distribution name is invalid")
        if not isinstance(package_version, str) or not package_version:
            raise ReleaseRuntimeError("release promotion package version is invalid")
        manifest_sha = _sha(
            promotion_record["manifest_sha256"], "promotion manifest SHA-256"
        )
        manifest_object_sha = _sha(
            promotion_record["manifest_object_sha256"],
            "promotion manifest object SHA-256",
        )
        observation_receipt_sha = _sha(
            promotion_record["observation_receipt_sha256"],
            "release observation receipt SHA-256",
        )
        observation_object_sha = _sha(
            promotion_record["observation_receipt_object_sha256"],
            "release observation object SHA-256",
        )
        receipt_object_sha = _sha(
            promotion_record["promotion_receipt_object_sha256"],
            "promotion receipt object SHA-256",
        )
        previous = promotion_record["previous_active_promotion_receipt_sha256"]
        rollback_from = promotion_record["rollback_from_promotion_receipt_sha256"]
        if previous is not None:
            previous = _sha(previous, "previous active promotion receipt SHA-256")
        if rollback_from is not None:
            rollback_from = _sha(rollback_from, "rollback source promotion receipt SHA-256")
            if rollback_from != previous:
                raise ReleaseRuntimeError(
                    "rollback source differs from the previous active promotion"
                )
        if canonical_manifests.get(manifest_sha) != manifest_object_sha:
            raise ReleaseRuntimeError(
                "release promotion references an unowned manifest object"
            )
        referenced_manifests.add(manifest_sha)
        canonical_promotions[receipt_sha] = {
            "promotion_id": promotion_id,
            "distribution_name": distribution_name,
            "package_version": package_version,
            "manifest_sha256": manifest_sha,
            "manifest_object_sha256": manifest_object_sha,
            "observation_receipt_sha256": observation_receipt_sha,
            "observation_receipt_object_sha256": observation_object_sha,
            "promotion_receipt_object_sha256": receipt_object_sha,
            "previous_active_promotion_receipt_sha256": previous,
            "rollback_from_promotion_receipt_sha256": rollback_from,
        }

    canonical_ids: dict[str, str] = {}
    for promotion_id, receipt_sha in promotion_ids.items():
        try:
            promotion_id = h.validate_id(promotion_id, "promotion id")
        except (h.HarnessError, TypeError) as exc:
            raise _fail("release promotion id index is invalid", exc) from exc
        receipt_sha = _sha(receipt_sha, "promotion id receipt SHA-256")
        indexed_record = canonical_promotions.get(receipt_sha)
        if indexed_record is None or indexed_record["promotion_id"] != promotion_id:
            raise ReleaseRuntimeError("release promotion id index is inconsistent")
        canonical_ids[promotion_id] = receipt_sha
    if set(canonical_ids) != seen_ids:
        raise ReleaseRuntimeError("release promotion id index is incomplete")
    if set(canonical_manifests) != referenced_manifests:
        raise ReleaseRuntimeError("release manifest projection contains no unique owner")

    active = item["active_promotion_receipt_sha256"]
    if active is not None:
        active = _sha(active, "active promotion receipt SHA-256")
        if active not in canonical_promotions:
            raise ReleaseRuntimeError("active promotion receipt is not projected")
    elif canonical_promotions:
        raise ReleaseRuntimeError("non-empty promotion projection has no active receipt")
    return {
        "schema_version": RELEASE_RUNTIME_SCHEMA_VERSION,
        "active_promotion_receipt_sha256": active,
        "manifests": {key: canonical_manifests[key] for key in sorted(canonical_manifests)},
        "promotions": {key: canonical_promotions[key] for key in sorted(canonical_promotions)},
        "promotion_ids": {key: canonical_ids[key] for key in sorted(canonical_ids)},
    }


def release_namespace_from_projection(
    projection: Mapping[str, Any]
) -> dict[str, Any]:
    try:
        domain = semantic.projection_domain(projection)
    except semantic.SemanticEventError as exc:
        raise _fail("release projection is invalid", exc) from exc
    return validate_release_namespace(domain.get(RELEASE_NAMESPACE_KEY))


def _contract_objects(
    task_id: str,
    manifest: Mapping[str, Any],
    observation_receipt: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> list[dict[str, Any]]:
    wrapped = [
        objects.create_semantic_object(
            object_type="release_manifest",
            task_id=task_id,
            object_identity=manifest["manifest_sha256"],
            payload=manifest,
        ),
        objects.create_semantic_object(
            object_type="release_observation",
            task_id=task_id,
            object_identity=observation_receipt["observation_receipt_sha256"],
            payload=observation_receipt,
        ),
        objects.create_semantic_object(
            object_type="promotion_receipt",
            task_id=task_id,
            object_identity=receipt["promotion_receipt_sha256"],
            payload=receipt,
        ),
    ]
    return sorted(wrapped, key=lambda row: row["object_type"])


def _promotion_intent_object(
    task_id: str, planned_event: Mapping[str, Any], receipt: Mapping[str, Any]
) -> dict[str, Any]:
    """Seal the exact promotion event before its binding can become pending."""

    payload = {
        "schema_version": RELEASE_PROMOTION_INTENT_SCHEMA_VERSION,
        "command_id": planned_event["command_id"],
        "recorded_at": planned_event["recorded_at"],
        "authority_ref": planned_event["authority_ref"],
        "expected_head_sha256": planned_event["prev_event_sha256"],
        "result_projection_sha256": planned_event["result_projection_sha256"],
        "planned_event_sha256": planned_event["event_sha256"],
        "promotion_receipt_sha256": receipt["promotion_receipt_sha256"],
    }
    return objects.create_semantic_object(
        object_type="release_promotion_intent",
        task_id=task_id,
        object_identity=payload["planned_event_sha256"],
        payload=payload,
    )


def _validate_promotion_intent(
    wrapped: Mapping[str, Any], task_id: str, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    try:
        object_value = objects.validate_semantic_object(wrapped)
    except objects.SemanticObjectError as exc:
        raise _fail("release promotion intent object is invalid", exc) from exc
    if object_value["task_id"] != task_id or object_value["object_type"] != "release_promotion_intent":
        raise ReleaseRuntimeError("release promotion intent object type or task is invalid")
    payload = object_value["payload"]
    if not isinstance(payload, Mapping) or set(payload) != _INTENT_FIELDS:
        raise ReleaseRuntimeError("release promotion intent payload schema is invalid")
    item = _clone(payload, maximum=objects.MAX_SMALL_OBJECT_BYTES)
    _exact_version(item["schema_version"], RELEASE_PROMOTION_INTENT_SCHEMA_VERSION, "release promotion intent version")
    try:
        h.validate_id(item["command_id"], "semantic command id")
        _instant(item["recorded_at"], "release promotion intent recorded_at")
        _parse_authority_ref(item["authority_ref"])
    except (h.HarnessError, ReleaseRuntimeError) as exc:
        raise _fail("release promotion intent identity is invalid", exc) from exc
    for key in (
        "expected_head_sha256",
        "result_projection_sha256",
        "planned_event_sha256",
        "promotion_receipt_sha256",
    ):
        _sha(item[key], f"release promotion intent {key}")
    if (
        object_value["object_identity"] != item["planned_event_sha256"]
        or item["promotion_receipt_sha256"] != receipt["promotion_receipt_sha256"]
    ):
        raise ReleaseRuntimeError("release promotion intent cross-binding is invalid")
    expected = _promotion_intent_object(task_id, item | {
        "prev_event_sha256": item["expected_head_sha256"],
        "event_sha256": item["planned_event_sha256"],
    }, receipt)
    if object_value != expected:
        raise ReleaseRuntimeError("release promotion intent wrapper is invalid")
    return item


def _contract_group(
    values: Any, task_id: str, *, require_intent: bool = True
) -> dict[str, Any]:
    expected_types = {
        "release_manifest",
        "release_observation",
        "promotion_receipt",
        *( {"release_promotion_intent"} if require_intent else set() ),
    }
    if not isinstance(values, list) or len(values) != len(expected_types):
        raise ReleaseRuntimeError(
            "release promotion semantic object count is invalid"
        )
    by_type: dict[str, dict[str, Any]] = {}
    for value in values:
        try:
            wrapped = objects.validate_semantic_object(value)
        except objects.SemanticObjectError as exc:
            raise _fail("release promotion semantic object is invalid", exc) from exc
        if wrapped["task_id"] != task_id or wrapped["object_type"] not in expected_types:
            raise ReleaseRuntimeError(
                "release promotion semantic object type or task is invalid"
            )
        if wrapped["object_type"] in by_type:
            raise ReleaseRuntimeError("release promotion semantic object type is duplicated")
        by_type[wrapped["object_type"]] = wrapped
    if set(by_type) != expected_types:
        raise ReleaseRuntimeError("release promotion semantic object set is incomplete")
    try:
        manifest = releases.validate_release_manifest(
            by_type["release_manifest"]["payload"]
        )
        observation_receipt = observations.validate_release_observation_receipt(
            by_type["release_observation"]["payload"], manifest
        )
        receipt = releases.validate_promotion_receipt(
            by_type["promotion_receipt"]["payload"], manifest
        )
    except (releases.ReleaseManifestError, observations.ReleaseArtifactError) as exc:
        raise _fail("release promotion object payload is invalid", exc) from exc
    if (
        by_type["release_manifest"]["object_identity"]
        != manifest["manifest_sha256"]
        or by_type["release_observation"]["object_identity"]
        != observation_receipt["observation_receipt_sha256"]
        or by_type["promotion_receipt"]["object_identity"]
        != receipt["promotion_receipt_sha256"]
        or receipt["artifact_observation_receipt_sha256"]
        != observation_receipt["observation_receipt_sha256"]
    ):
        raise ReleaseRuntimeError("release promotion object identity is invalid")
    expected = _contract_objects(
        task_id, manifest, observation_receipt, receipt
    )
    intent: dict[str, Any] | None = None
    if require_intent:
        intent = _validate_promotion_intent(
            by_type["release_promotion_intent"], task_id, receipt
        )
        expected.append(
            _promotion_intent_object(
                task_id,
                intent | {
                    "prev_event_sha256": intent["expected_head_sha256"],
                    "event_sha256": intent["planned_event_sha256"],
                },
                receipt,
            )
        )
        expected.sort(key=lambda row: row["object_type"])
    canonical = sorted(by_type.values(), key=lambda row: row["object_type"])
    if canonical != expected:
        raise ReleaseRuntimeError("release promotion semantic object wrapper is invalid")
    return {
        "manifest": manifest,
        "observation_receipt": observation_receipt,
        "receipt": receipt,
        "manifest_object": by_type["release_manifest"],
        "observation_object": by_type["release_observation"],
        "receipt_object": by_type["promotion_receipt"],
        **({"intent": intent, "intent_object": by_type["release_promotion_intent"]} if intent is not None else {}),
        "objects": canonical,
    }


def _group_from_binding_objects(
    by_digest: Mapping[str, Mapping[str, Any]],
    binding: Mapping[str, Any],
    task_id: str,
) -> dict[str, Any]:
    """Read the historical three-object binding or the current intent-bound form.

    New transactions are always four-object and are checked by
    ``validate_release_promotion_transaction``.  This narrow reader exists for
    already-committed historical bindings only; a three-object pending binding
    has no sealed preimage and is therefore never recoverable as pending work.
    """

    references = binding["object_sha256s"]
    if len(references) not in {3, 4}:
        raise ReleaseRuntimeError("release promotion binding object count is invalid")
    try:
        values = [by_digest[digest] for digest in references]
    except KeyError as exc:
        raise _fail("release binding references a missing object", exc) from exc
    return _contract_group(values, task_id, require_intent=len(references) == 4)


def _require_pending_intent(group: Mapping[str, Any]) -> Mapping[str, Any]:
    """Reject historical pending bindings: they have no sealed event preimage."""

    intent = group.get("intent")
    if not isinstance(intent, Mapping):
        raise ReleaseRuntimeError(
            "legacy pending release binding has no preimage intent and cannot be recovered"
        )
    return intent


def _advance_namespace(
    namespace: Mapping[str, Any] | None,
    manifest: Mapping[str, Any],
    observation_receipt: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    manifest_object_sha256: str,
    observation_receipt_object_sha256: str,
    promotion_receipt_object_sha256: str,
) -> dict[str, Any]:
    current = validate_release_namespace(namespace)
    manifest_sha = manifest["manifest_sha256"]
    receipt_sha = receipt["promotion_receipt_sha256"]
    promotion_id = receipt["promotion_id"]
    if receipt_sha in current["promotions"]:
        raise ReleaseRuntimeError("promotion receipt already exists")
    if promotion_id in current["promotion_ids"]:
        raise ReleaseRuntimeError("promotion id already exists")
    existing_manifest_object = current["manifests"].get(manifest_sha)
    if (
        existing_manifest_object is not None
        and existing_manifest_object != manifest_object_sha256
    ):
        raise ReleaseRuntimeError("release manifest ownership is divergent")
    if len(current["promotions"]) >= MAX_RELEASE_PROMOTIONS:
        raise ReleaseRuntimeError("release promotion projection exceeds its count bound")

    for dependency in manifest["dependencies"]:
        promoted = current["promotions"].get(
            dependency["promotion_receipt_sha256"]
        )
        if (
            promoted is None
            or promoted["distribution_name"] != dependency["name"]
            or promoted["manifest_sha256"]
            != dependency["release_manifest_sha256"]
        ):
            raise ReleaseRuntimeError(
                "release dependency does not name an already promoted exact manifest"
            )

    active = current["active_promotion_receipt_sha256"]
    rollback = receipt["rollback_provenance"]
    rollback_from: str | None = None
    if rollback is not None:
        rollback_from = rollback["from_promotion_receipt_sha256"]
        if active is None or rollback_from != active:
            raise ReleaseRuntimeError(
                "rollback source is not the current active promotion"
            )
        if rollback["mode"] == "prior_manifest":
            target_sha = rollback["target_promotion_receipt_sha256"]
            target = current["promotions"].get(target_sha)
            if target is None or target_sha == active:
                raise ReleaseRuntimeError(
                    "rollback prior target is absent or still current"
                )
            if target["manifest_sha256"] != manifest_sha:
                raise ReleaseRuntimeError(
                    "rollback manifest does not match its prior promotion target"
                )
        elif rollback["mode"] == "compensating_release":
            active_record = current["promotions"].get(active)
            if active_record is None or active_record["manifest_sha256"] == manifest_sha:
                raise ReleaseRuntimeError(
                    "compensating release must publish a different manifest"
                )
        else:  # The pure receipt validator should make this unreachable.
            raise ReleaseRuntimeError("rollback mode is unsupported")

    manifests = dict(current["manifests"])
    manifests[manifest_sha] = _sha(
        manifest_object_sha256, "release manifest object SHA-256"
    )
    promotions = dict(current["promotions"])
    promotions[receipt_sha] = {
        "promotion_id": promotion_id,
        "distribution_name": manifest["distribution_name"],
        "package_version": manifest["package_version"],
        "manifest_sha256": manifest_sha,
        "manifest_object_sha256": manifest_object_sha256,
        "observation_receipt_sha256": _sha(
            observation_receipt["observation_receipt_sha256"],
            "release observation receipt SHA-256",
        ),
        "observation_receipt_object_sha256": _sha(
            observation_receipt_object_sha256,
            "release observation object SHA-256",
        ),
        "promotion_receipt_object_sha256": _sha(
            promotion_receipt_object_sha256,
            "promotion receipt object SHA-256",
        ),
        "previous_active_promotion_receipt_sha256": active,
        "rollback_from_promotion_receipt_sha256": rollback_from,
    }
    promotion_ids = dict(current["promotion_ids"])
    promotion_ids[promotion_id] = receipt_sha
    return validate_release_namespace(
        {
            "schema_version": RELEASE_RUNTIME_SCHEMA_VERSION,
            "active_promotion_receipt_sha256": receipt_sha,
            "manifests": manifests,
            "promotions": promotions,
            "promotion_ids": promotion_ids,
        }
    )


def _advance_projection(
    projection: Mapping[str, Any], group: Mapping[str, Any]
) -> dict[str, Any]:
    try:
        domain = semantic.projection_domain(projection)
    except semantic.SemanticEventError as exc:
        raise _fail("release promotion base projection is invalid", exc) from exc
    domain[RELEASE_NAMESPACE_KEY] = _advance_namespace(
        domain.get(RELEASE_NAMESPACE_KEY),
        group["manifest"],
        group["observation_receipt"],
        group["receipt"],
        manifest_object_sha256=group["manifest_object"]["object_sha256"],
        observation_receipt_object_sha256=group["observation_object"][
            "object_sha256"
        ],
        promotion_receipt_object_sha256=group["receipt_object"]["object_sha256"],
    )
    return domain


def _reverse_transaction_namespace(
    result_state: Mapping[str, Any], group: Mapping[str, Any]
) -> dict[str, Any]:
    """Recover the exact release-only base encoded by one result projection."""

    try:
        result = semantic.projection_domain(result_state)
    except semantic.SemanticEventError as exc:
        raise _fail("release transaction result projection is invalid", exc) from exc
    namespace = validate_release_namespace(result.get(RELEASE_NAMESPACE_KEY))
    receipt_sha = group["receipt"]["promotion_receipt_sha256"]
    promotion_id = group["receipt"]["promotion_id"]
    record = namespace["promotions"].get(receipt_sha)
    if (
        record is None
        or namespace["active_promotion_receipt_sha256"] != receipt_sha
        or namespace["promotion_ids"].get(promotion_id) != receipt_sha
        or record["manifest_sha256"] != group["manifest"]["manifest_sha256"]
        or record["manifest_object_sha256"]
        != group["manifest_object"]["object_sha256"]
        or record["observation_receipt_sha256"]
        != group["observation_receipt"]["observation_receipt_sha256"]
        or record["observation_receipt_object_sha256"]
        != group["observation_object"]["object_sha256"]
        or record["promotion_receipt_object_sha256"]
        != group["receipt_object"]["object_sha256"]
    ):
        raise ReleaseRuntimeError(
            "release transaction promotion projection is invalid"
        )
    promotions = dict(namespace["promotions"])
    promotions.pop(receipt_sha)
    promotion_ids = dict(namespace["promotion_ids"])
    promotion_ids.pop(promotion_id)
    manifests = dict(namespace["manifests"])
    manifest_sha = group["manifest"]["manifest_sha256"]
    if not any(row["manifest_sha256"] == manifest_sha for row in promotions.values()):
        manifests.pop(manifest_sha, None)
    base_namespace = validate_release_namespace(
        {
            "schema_version": RELEASE_RUNTIME_SCHEMA_VERSION,
            "active_promotion_receipt_sha256": record[
                "previous_active_promotion_receipt_sha256"
            ],
            "manifests": manifests,
            "promotions": promotions,
            "promotion_ids": promotion_ids,
        }
    )
    base = dict(result)
    if base_namespace == _empty_namespace():
        base.pop(RELEASE_NAMESPACE_KEY, None)
    else:
        base[RELEASE_NAMESPACE_KEY] = base_namespace
    expected = _advance_projection(base, group)
    if expected != result:
        raise ReleaseRuntimeError(
            "release transaction namespace is not the exact promotion after-image"
        )
    return base


def _authority_identity(
    paths: h.HarnessPaths,
    receipt_sha256: str,
    supplied: object | None,
) -> tuple[str, int, str]:
    if supplied is None:
        try:
            record = h.load_chief_authority(paths)
        except h.HarnessError as exc:
            raise _fail("cannot bind release promotion to Chief authority", exc) from exc
        session_id = record["session_id"]
        epoch = record["epoch"]
    else:
        if not isinstance(supplied, Mapping) or set(supplied) != {
            "session_id",
            "epoch",
        }:
            raise ReleaseRuntimeError("release Chief authority reference is invalid")
        try:
            session_id = h.validate_id(supplied["session_id"], "Chief session id")
        except (h.HarnessError, TypeError) as exc:
            raise _fail("release Chief session id is invalid", exc) from exc
        epoch = supplied["epoch"]
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
        raise ReleaseRuntimeError("release Chief epoch is invalid")
    return session_id, epoch, f"chief:{session_id}:e{epoch}:release:{receipt_sha256}"


def _parse_authority_ref(value: Any) -> tuple[str, int, str]:
    if not isinstance(value, str):
        raise ReleaseRuntimeError("release event Chief authority reference is invalid")
    match = _AUTHORITY_REF.fullmatch(value)
    if match is None:
        raise ReleaseRuntimeError("release event Chief authority reference is invalid")
    return match.group(1), int(match.group(2)), match.group(3)


def _parse_abandon_authority_ref(value: Any) -> tuple[str, int, str]:
    if not isinstance(value, str):
        raise ReleaseRuntimeError("release abandonment Chief authority reference is invalid")
    match = _ABANDON_AUTHORITY_REF.fullmatch(value)
    if match is None:
        raise ReleaseRuntimeError("release abandonment Chief authority reference is invalid")
    return match.group(1), int(match.group(2)), match.group(3)


def _validate_abandonment_argument_text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value.encode("utf-8")) > 2048
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ReleaseRuntimeError(f"{label} is invalid")
    return value


def _retirement_proof(
    paths: h.HarnessPaths,
    recorded_at: str,
    supplied_authority: object | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a bounded proof from the current Chief record, never its audit tail."""

    try:
        record = h.load_chief_authority(paths)
        summary = h.chief_authority_summary(paths)
    except h.HarnessError as exc:
        raise _fail("cannot validate release abandonment Chief authority", exc) from exc
    if (
        record.get("status") != "active"
        or summary.get("expired") is not False
    ):
        raise ReleaseRuntimeError("release abandonment requires a live Chief authority")
    if supplied_authority is not None:
        if not isinstance(supplied_authority, Mapping) or set(supplied_authority) != {
            "session_id",
            "epoch",
        }:
            raise ReleaseRuntimeError("release abandonment Chief authority reference is invalid")
        if (
            supplied_authority.get("session_id") != record.get("session_id")
            or supplied_authority.get("epoch") != record.get("epoch")
        ):
            raise ReleaseRuntimeError("release abandonment Chief authority is not current")
    try:
        event_at = _instant(recorded_at, "release abandonment recorded_at")
        issued_at = _instant(record["issued_at"], "Chief issued_at")
        expires_at = _instant(record["expires_at"], "Chief expires_at")
    except (KeyError, h.HarnessError) as exc:
        raise _fail("cannot validate release abandonment Chief lease window", exc) from exc
    if not issued_at <= event_at < expires_at:
        raise ReleaseRuntimeError(
            "release abandonment is not within the current Chief lease"
        )
    proof = {
        "proof_kind": "monotonic_chief_epoch",
        "successor_session_id": record["session_id"],
        "successor_epoch": record["epoch"],
        "issued_at": record["issued_at"],
        "expires_at": record["expires_at"],
        "current_authority_record_sha256": semantic.canonical_sha256(record),
    }
    return dict(record), proof


def _seal_release_abandonment_receipt(
    task_id: str,
    binding_sha256: str,
    abandonment: Mapping[str, Any],
    event: Mapping[str, Any],
) -> dict[str, Any]:
    base = {
        "schema_version": RELEASE_ABANDONMENT_RECEIPT_SCHEMA_VERSION,
        "proof_scope": RELEASE_ABANDONMENT_PROOF_SCOPE,
        "task_id": task_id,
        "binding_sha256": binding_sha256,
        "abandonment": _clone(
            abandonment, maximum=objects.MAX_BINDING_DISPOSITION_BYTES
        ),
        "semantic_event": _clone(event, maximum=semantic.MAX_EVENT_BYTES),
    }
    base["receipt_sha256"] = semantic.canonical_sha256(
        base, max_bytes=MAX_RELEASE_ABANDONMENT_RECEIPT_BYTES
    )
    return validate_release_abandonment_receipt(base)


def validate_release_abandonment_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the stable receipt for one successor-owned abandonment event."""

    if not isinstance(value, Mapping) or set(value) != _ABANDONMENT_RECEIPT_FIELDS:
        raise ReleaseRuntimeError("release abandonment receipt schema is invalid")
    item = _clone(value, maximum=MAX_RELEASE_ABANDONMENT_RECEIPT_BYTES)
    if item["schema_version"] not in {1, RELEASE_ABANDONMENT_RECEIPT_SCHEMA_VERSION}:
        raise ReleaseRuntimeError("release abandonment receipt version is unsupported")
    if item["proof_scope"] != RELEASE_ABANDONMENT_PROOF_SCOPE:
        raise ReleaseRuntimeError("release abandonment receipt proof scope is invalid")
    try:
        task_id = h.validate_id(item["task_id"], "task id")
        binding_sha256 = _sha(
            item["binding_sha256"], "release abandonment binding SHA-256"
        )
        semantics = semantic.command_semantics(item["semantic_event"])
        row = objects._validate_release_abandonment_row(
            item["abandonment"],
            task_id=task_id,
            binding_sha256=binding_sha256,
            event=item["semantic_event"],
        )
    except (h.HarnessError, objects.SemanticObjectError, semantic.SemanticEventError) as exc:
        raise _fail("release abandonment receipt contract is invalid", exc) from exc
    if (
        semantics["event_type"] != RELEASE_ABANDONMENT_EVENT_TYPE
        or row["binding_sha256"] != binding_sha256
        or row["schema_version"] != item["schema_version"]
    ):
        raise ReleaseRuntimeError("release abandonment receipt cross-binding is invalid")
    preimage = {
        key: item[key]
        for key in _ABANDONMENT_RECEIPT_FIELDS
        if key != "receipt_sha256"
    }
    if item["receipt_sha256"] != semantic.canonical_sha256(
        preimage, max_bytes=MAX_RELEASE_ABANDONMENT_RECEIPT_BYTES
    ):
        raise ReleaseRuntimeError("release abandonment receipt SHA-256 is invalid")
    return item


def _validate_delta_scope(payload: Any) -> None:
    if not isinstance(payload, dict) or set(payload) != {"delta"}:
        raise ReleaseRuntimeError("release promotion event payload is invalid")
    delta = payload["delta"]
    if not isinstance(delta, dict) or set(delta) != {"delta_version", "operations"}:
        raise ReleaseRuntimeError("release promotion delta is invalid")
    operations = delta["operations"]
    if not isinstance(operations, list) or not operations:
        raise ReleaseRuntimeError("release promotion delta is empty")
    for operation in operations:
        path = operation.get("path") if isinstance(operation, dict) else None
        if not isinstance(path, list) or not path or path[0] != RELEASE_NAMESPACE_KEY:
            raise ReleaseRuntimeError(
                "release promotion delta mutates outside its namespace"
            )


def _instant(value: Any, label: str):
    if not isinstance(value, str):
        raise ReleaseRuntimeError(f"{label} is invalid")
    parsed = h.parse_time(value)
    if parsed is None or parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReleaseRuntimeError(f"{label} is invalid")
    return parsed


def _validate_observation_order(
    receipt: Mapping[str, Any], recorded_at: str
) -> None:
    readback_at = _instant(
        receipt["registry_readback"]["observed_at"],
        "registry readback observed_at",
    )
    installed_at = _instant(
        receipt["installed"]["observed_at"], "installed observation observed_at"
    )
    promoted_at = _instant(recorded_at, "release promotion recorded_at")
    if not readback_at <= installed_at <= promoted_at:
        raise ReleaseRuntimeError(
            "release promotion must follow registry readback and installed observation"
        )


def prepare_release_promotion_transaction(
    paths: h.HarnessPaths,
    task_id: str,
    manifest: Mapping[str, Any],
    observation_receipt: Mapping[str, Any],
    promotion_receipt: Mapping[str, Any],
    command_id: str,
    recorded_at: str,
    *,
    authority_ref: object | None = None,
) -> dict[str, Any]:
    """Prepare one exact release promotion against the current semantic head."""

    try:
        task_id = h.validate_id(task_id, "task id")
        command_id = h.validate_id(command_id, "semantic command id")
        checked_manifest = releases.validate_release_manifest(manifest)
        checked_observation = observations.validate_release_observation_receipt(
            observation_receipt, checked_manifest
        )
        checked_receipt = releases.validate_promotion_receipt(
            promotion_receipt, checked_manifest
        )
        records = store.load_semantic_events(paths, task_id)
    except (
        h.HarnessError,
        observations.ReleaseArtifactError,
        releases.ReleaseManifestError,
        store.SemanticStoreError,
    ) as exc:
        raise _fail("cannot prepare release promotion", exc) from exc
    records, replayed = _freeze_event_chain(records, task_id)
    base_objects = _contract_objects(
        task_id, checked_manifest, checked_observation, checked_receipt
    )
    base_group = _contract_group(base_objects, task_id, require_intent=False)
    result_state = _advance_projection(replayed, base_group)
    _session_id, _epoch, event_authority = _authority_identity(
        paths, checked_receipt["promotion_receipt_sha256"], authority_ref
    )
    try:
        planned = semantic.create_transition_event(
            records[-1],
            replayed,
            result_state,
            event_type=RELEASE_EVENT_TYPE,
            command_id=command_id,
            recorded_at=recorded_at,
            authority_ref=event_authority,
        )
        intent = _promotion_intent_object(task_id, planned, checked_receipt)
        sealed_objects = sorted(
            [*base_objects, intent], key=lambda row: row["object_type"]
        )
        group = _contract_group(sealed_objects, task_id)
        binding = objects.create_semantic_binding(
            binding_kind=RELEASE_BINDING_KIND,
            task_id=task_id,
            binding_key=checked_receipt["promotion_id"],
            expected_semantic_head_sha256=planned["prev_event_sha256"],
            planned_event_sha256=planned["event_sha256"],
            result_projection_sha256=planned["result_projection_sha256"],
            object_sha256s=sorted(
                wrapped["object_sha256"] for wrapped in sealed_objects
            ),
        )
    except (semantic.SemanticEventError, objects.SemanticObjectError) as exc:
        raise _fail("cannot seal release promotion event and binding", exc) from exc
    base = {
        "schema_version": RELEASE_PROMOTION_TRANSACTION_SCHEMA_VERSION,
        "task_id": task_id,
        "event_type": RELEASE_EVENT_TYPE,
        "command_id": planned["command_id"],
        "recorded_at": planned["recorded_at"],
        "authority_ref": event_authority,
        "expected_head_sha256": planned["prev_event_sha256"],
        "result_state": result_state,
        "planned_event": planned,
        "objects": sealed_objects,
        "binding": binding,
    }
    base["transaction_sha256"] = semantic.canonical_sha256(
        base, max_bytes=MAX_RELEASE_TRANSACTION_BYTES
    )
    return validate_release_promotion_transaction(base)


def validate_release_promotion_transaction(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a detached self-hashed promotion transaction."""

    if not isinstance(value, Mapping) or set(value) != _TRANSACTION_FIELDS:
        raise ReleaseRuntimeError("release promotion transaction schema is invalid")
    item = _clone(value, maximum=MAX_RELEASE_TRANSACTION_BYTES)
    _exact_version(
        item["schema_version"],
        RELEASE_PROMOTION_TRANSACTION_SCHEMA_VERSION,
        "release promotion transaction version",
    )
    try:
        task_id = h.validate_id(item["task_id"], "task id")
        h.validate_id(item["command_id"], "semantic command id")
    except (h.HarnessError, TypeError) as exc:
        raise _fail("release promotion transaction identity is invalid", exc) from exc
    group = _contract_group(item["objects"], task_id)
    _validate_observation_order(group["receipt"], item["recorded_at"])
    if item["objects"] != group["objects"]:
        raise ReleaseRuntimeError("release promotion objects are not canonical")
    try:
        binding = objects.validate_semantic_binding(item["binding"])
        semantics = semantic.command_semantics(item["planned_event"])
    except (objects.SemanticObjectError, semantic.SemanticEventError) as exc:
        raise _fail("release promotion binding or event is invalid", exc) from exc
    expected_refs = sorted(
        wrapped["object_sha256"] for wrapped in group["objects"]
    )
    receipt = group["receipt"]
    intent = group["intent"]
    _chief_session, _chief_epoch, receipt_from_authority = _parse_authority_ref(
        item["authority_ref"]
    )
    if receipt_from_authority != receipt["promotion_receipt_sha256"]:
        raise ReleaseRuntimeError(
            "release event authority names another promotion receipt"
        )
    if (
        binding["binding_kind"] != RELEASE_BINDING_KIND
        or binding["task_id"] != task_id
        or binding["binding_key"] != receipt["promotion_id"]
        or binding["object_sha256s"] != expected_refs
        or item["event_type"] != RELEASE_EVENT_TYPE
        or semantics["event_type"] != RELEASE_EVENT_TYPE
        or item["authority_ref"] != item["planned_event"]["authority_ref"]
        or item["command_id"] != item["planned_event"]["command_id"]
        or item["recorded_at"] != item["planned_event"]["recorded_at"]
        or item["expected_head_sha256"]
        != item["planned_event"]["prev_event_sha256"]
        or binding["expected_semantic_head_sha256"]
        != item["expected_head_sha256"]
        or binding["planned_event_sha256"]
        != item["planned_event"]["event_sha256"]
        or binding["result_projection_sha256"]
        != item["planned_event"]["result_projection_sha256"]
        or intent["command_id"] != item["command_id"]
        or intent["recorded_at"] != item["recorded_at"]
        or intent["authority_ref"] != item["authority_ref"]
        or intent["expected_head_sha256"] != item["expected_head_sha256"]
        or intent["result_projection_sha256"] != binding["result_projection_sha256"]
        or intent["planned_event_sha256"] != binding["planned_event_sha256"]
    ):
        raise ReleaseRuntimeError(
            "release promotion event and binding cross-contract is invalid"
        )
    _validate_delta_scope(semantics["payload"])
    if semantic.SEMANTIC_ENVELOPE_KEY in item["result_state"]:
        raise ReleaseRuntimeError(
            "release transaction result must be a domain projection"
        )
    result = semantic.projection_domain(item["result_state"])
    if result.get("task_id") != task_id:
        raise ReleaseRuntimeError("release promotion result belongs to another task")
    base_state = _reverse_transaction_namespace(result, group)
    try:
        expected_delta = semantic.build_delta(base_state, result)
    except semantic.SemanticEventError as exc:
        raise _fail("release promotion namespace delta is invalid", exc) from exc
    planned = item["planned_event"]
    if (
        semantics["payload"]["delta"] != expected_delta
        or planned["base_projection_sha256"] != semantic.canonical_sha256(base_state)
        or planned["result_projection_sha256"] != semantic.canonical_sha256(result)
        or binding["result_projection_sha256"] != semantic.canonical_sha256(result)
    ):
        raise ReleaseRuntimeError(
            "release promotion projection is not its exact namespace after-image"
        )
    preimage = {
        key: item[key]
        for key in _TRANSACTION_FIELDS
        if key != "transaction_sha256"
    }
    if item["transaction_sha256"] != semantic.canonical_sha256(
        preimage, max_bytes=MAX_RELEASE_TRANSACTION_BYTES
    ):
        raise ReleaseRuntimeError("release promotion transaction SHA-256 is invalid")
    return item


def _require_live_chief(
    paths: h.HarnessPaths, authority_ref: str, recorded_at: str
) -> None:
    session_id, epoch, _receipt_sha = _parse_authority_ref(authority_ref)
    try:
        record = h.load_chief_authority(paths)
    except h.HarnessError as exc:
        raise _fail("cannot validate release Chief authority", exc) from exc
    try:
        issued_at = _instant(record["issued_at"], "Chief issued_at")
        expires_at = _instant(record["expires_at"], "Chief expires_at")
        event_at = _instant(recorded_at, "release promotion recorded_at")
        summary = h.chief_authority_summary(paths)
    except (h.HarnessError, KeyError) as exc:
        raise _fail("cannot validate release Chief lease window", exc) from exc
    if (
        record["status"] != "active"
        or record["session_id"] != session_id
        or record["epoch"] != epoch
        or summary["expired"]
        or not issued_at <= event_at < expires_at
    ):
        raise ReleaseRuntimeError(
            "release promotion is not bound to the current Chief authority"
        )


def _transaction_from_parts(
    group: Mapping[str, Any],
    binding: Mapping[str, Any],
    event: Mapping[str, Any],
    result_state: Mapping[str, Any],
) -> dict[str, Any]:
    base = {
        "schema_version": RELEASE_PROMOTION_TRANSACTION_SCHEMA_VERSION,
        "task_id": binding["task_id"],
        "event_type": event["event_type"],
        "command_id": event["command_id"],
        "recorded_at": event["recorded_at"],
        "authority_ref": event["authority_ref"],
        "expected_head_sha256": event["prev_event_sha256"],
        "result_state": semantic.projection_domain(result_state),
        "planned_event": event,
        "objects": group["objects"],
        "binding": binding,
    }
    base["transaction_sha256"] = semantic.canonical_sha256(
        base, max_bytes=MAX_RELEASE_TRANSACTION_BYTES
    )
    return base


def _rebuild_abandoned_original_event(
    records: list[dict[str, Any]],
    binding: Mapping[str, Any],
    group: Mapping[str, Any],
    abandonment: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Rebuild the uncommitted original promotion from its sealed evidence."""

    event_index = {
        event["event_sha256"]: index for index, event in enumerate(records)
    }
    head_index = event_index.get(binding["expected_semantic_head_sha256"])
    if head_index is None:
        raise ReleaseRuntimeError("abandoned release binding expected head is absent")
    try:
        prefix = semantic.replay_events(records[: head_index + 1])
        expected_result = _advance_projection(prefix, group)
    except semantic.SemanticEventError as exc:
        raise _fail("abandoned release binding prefix is invalid", exc) from exc
    if semantic.canonical_sha256(expected_result) != binding["result_projection_sha256"]:
        raise ReleaseRuntimeError(
            "abandoned release binding result is not its exact promotion after-image"
        )
    original = abandonment.get("original_event")
    if not isinstance(original, Mapping):
        raise ReleaseRuntimeError("release abandonment original event proof is invalid")
    try:
        rebuilt = semantic.create_transition_event(
            records[head_index],
            prefix,
            expected_result,
            event_type=RELEASE_EVENT_TYPE,
            command_id=original["command_id"],
            recorded_at=original["recorded_at"],
            authority_ref=original["authority_ref"],
        )
    except (KeyError, semantic.SemanticEventError) as exc:
        raise _fail("cannot rebuild abandoned release promotion event", exc) from exc
    summary = {
        "event_type": rebuilt["event_type"],
        "command_id": rebuilt["command_id"],
        "recorded_at": rebuilt["recorded_at"],
        "authority_ref": rebuilt["authority_ref"],
        "event_sha256": rebuilt["event_sha256"],
    }
    _old_session, _old_epoch, authority_receipt = _parse_authority_ref(
        rebuilt["authority_ref"]
    )
    if (
        summary != dict(original)
        or rebuilt["event_sha256"] != binding["planned_event_sha256"]
        or authority_receipt != group["receipt"]["promotion_receipt_sha256"]
    ):
        raise ReleaseRuntimeError(
            "release abandonment does not prove the exact original promotion event"
        )
    return rebuilt, expected_result


def _release_group_from_generic_report(
    generic: Mapping[str, Any],
    binding: Mapping[str, Any],
    task_id: str,
) -> dict[str, Any]:
    rows = generic.get("objects")
    if not isinstance(rows, list):
        raise ReleaseRuntimeError("release semantic object report is invalid")
    by_digest: dict[str, dict[str, Any]] = {}
    for row in rows:
        try:
            wrapped = objects.validate_semantic_object(
                {key: row[key] for key in _OBJECT_FIELDS}
            )
        except (KeyError, objects.SemanticObjectError) as exc:
            raise _fail("release semantic object report row is invalid", exc) from exc
        by_digest[wrapped["object_sha256"]] = wrapped
    try:
        return _group_from_binding_objects(by_digest, binding, task_id)
    except objects.SemanticObjectError as exc:
        raise _fail("release binding object group is invalid", exc) from exc


def inspect_release_runtime(
    paths: h.HarnessPaths, task_id: str
) -> dict[str, Any]:
    """Authenticate release objects, bindings, events, and rebuilt namespace."""

    try:
        task_id = h.validate_id(task_id, "task id")
        records = store.load_semantic_events(paths, task_id)
        if store.semantic_projection_status(paths, task_id) != "current":
            raise ReleaseRuntimeError("release semantic projection is not current")
    except (h.HarnessError, store.SemanticStoreError) as exc:
        if isinstance(exc, ReleaseRuntimeError):
            raise
        raise _fail("cannot inspect release semantic state", exc) from exc
    records, replayed = _freeze_event_chain(records, task_id)
    # A durable abandonment event can outlive a failed projection write. Repair
    # before classifying the binding so an exact retry is also its crash recovery.
    try:
        store.repair_semantic_projection(paths, task_id)
    except store.SemanticStoreError as exc:
        raise _fail("cannot repair release abandonment projection", exc) from exc
    try:
        generic = objects.inspect_semantic_objects(paths, task_id, records)
    except objects.SemanticObjectError as exc:
        raise _fail("release semantic object store is invalid", exc) from exc
    object_rows = generic.get("objects")
    binding_rows = generic.get("bindings")
    if not isinstance(object_rows, list) or not isinstance(binding_rows, list):
        raise ReleaseRuntimeError("release semantic object report is invalid")
    by_digest: dict[str, dict[str, Any]] = {}
    release_object_digests: set[str] = set()
    manifests_by_identity: dict[str, dict[str, Any]] = {}
    stored_observations: list[dict[str, Any]] = []
    stored_receipts: list[dict[str, Any]] = []
    for row in object_rows:
        try:
            wrapped = objects.validate_semantic_object(
                {key: row[key] for key in _OBJECT_FIELDS}
            )
        except (KeyError, objects.SemanticObjectError) as exc:
            raise _fail("release semantic object report row is invalid", exc) from exc
        by_digest[wrapped["object_sha256"]] = wrapped
        if wrapped["object_type"] == "release_manifest":
            try:
                payload = releases.validate_release_manifest(wrapped["payload"])
            except releases.ReleaseManifestError as exc:
                raise _fail("stored release manifest is invalid", exc) from exc
            if wrapped["object_identity"] != payload["manifest_sha256"]:
                raise ReleaseRuntimeError("stored release manifest identity is invalid")
            if payload["manifest_sha256"] in manifests_by_identity:
                raise ReleaseRuntimeError("stored release manifest identity is not unique")
            manifests_by_identity[payload["manifest_sha256"]] = payload
            release_object_digests.add(wrapped["object_sha256"])
        elif wrapped["object_type"] == "promotion_receipt":
            stored_receipts.append(wrapped)
            release_object_digests.add(wrapped["object_sha256"])
        elif wrapped["object_type"] == "release_observation":
            stored_observations.append(wrapped)
            release_object_digests.add(wrapped["object_sha256"])
        elif wrapped["object_type"] == "release_promotion_intent":
            release_object_digests.add(wrapped["object_sha256"])

    observation_identities: set[str] = set()
    for wrapped in stored_observations:
        payload = wrapped["payload"]
        if not isinstance(payload, Mapping):
            raise ReleaseRuntimeError(
                "stored release observation payload is invalid"
            )
        manifest = manifests_by_identity.get(
            cast(str, payload.get("manifest_sha256"))
        )
        if manifest is None:
            raise ReleaseRuntimeError(
                "stored release observation has no exact manifest object"
            )
        try:
            observation = observations.validate_release_observation_receipt(
                payload, manifest
            )
        except observations.ReleaseArtifactError as exc:
            raise _fail("stored release observation is invalid", exc) from exc
        observation_sha = observation["observation_receipt_sha256"]
        if wrapped["object_identity"] != observation_sha:
            raise ReleaseRuntimeError(
                "stored release observation identity is invalid"
            )
        if observation_sha in observation_identities:
            raise ReleaseRuntimeError(
                "stored release observation identity is not unique"
            )
        observation_identities.add(observation_sha)

    receipt_identities: set[str] = set()
    for wrapped in stored_receipts:
        payload = wrapped["payload"]
        if not isinstance(payload, Mapping):
            raise ReleaseRuntimeError("stored promotion receipt payload is invalid")
        manifest = manifests_by_identity.get(
            cast(str, payload.get("manifest_sha256"))
        )
        if manifest is None:
            raise ReleaseRuntimeError(
                "stored promotion receipt has no exact release manifest object"
            )
        observation_sha = payload.get("artifact_observation_receipt_sha256")
        if observation_sha not in observation_identities:
            raise ReleaseRuntimeError(
                "stored promotion receipt has no exact observation object"
            )
        try:
            receipt = releases.validate_promotion_receipt(payload, manifest)
        except releases.ReleaseManifestError as exc:
            raise _fail("stored promotion receipt is invalid", exc) from exc
        if wrapped["object_identity"] != receipt["promotion_receipt_sha256"]:
            raise ReleaseRuntimeError("stored promotion receipt identity is invalid")
        if receipt["promotion_receipt_sha256"] in receipt_identities:
            raise ReleaseRuntimeError("stored promotion receipt identity is not unique")
        receipt_identities.add(receipt["promotion_receipt_sha256"])

    event_by_sha = {event["event_sha256"]: event for event in records}
    event_index = {event["event_sha256"]: index for index, event in enumerate(records)}
    release_rows: list[dict[str, Any]] = []
    owned_event_sha256s: set[str] = set()
    committed_order: list[tuple[int, dict[str, Any], dict[str, Any]]] = []
    for row in binding_rows:
        try:
            binding = objects.validate_semantic_binding(
                {key: row[key] for key in _BINDING_FIELDS}
            )
        except (KeyError, objects.SemanticObjectError) as exc:
            raise _fail("release semantic binding report row is invalid", exc) from exc
        references = set(binding["object_sha256s"])
        if references & release_object_digests and binding["binding_kind"] != RELEASE_BINDING_KIND:
            raise ReleaseRuntimeError(
                "release object is referenced by another binding kind"
            )
        if binding["binding_kind"] != RELEASE_BINDING_KIND:
            continue
        group = _group_from_binding_objects(by_digest, binding, task_id)
        if (
            binding["binding_key"] != group["receipt"]["promotion_id"]
            or binding["object_sha256s"]
            != sorted(item["object_sha256"] for item in group["objects"])
        ):
            raise ReleaseRuntimeError("release promotion binding contract is invalid")
        head_index = event_index.get(binding["expected_semantic_head_sha256"])
        if head_index is None:
            raise ReleaseRuntimeError("release binding expected head is absent")
        prefix_projection = semantic.replay_events(records[: head_index + 1])
        expected_result = _advance_projection(prefix_projection, group)
        if semantic.canonical_sha256(expected_result) != binding["result_projection_sha256"]:
            raise ReleaseRuntimeError(
                "release binding result is not its exact promotion after-image"
            )
        classification = row.get("classification")
        if classification == "committed":
            event = event_by_sha.get(binding["planned_event_sha256"])
            if event is None:
                raise ReleaseRuntimeError("committed release binding has no ledger event")
            if event_index[event["event_sha256"]] != head_index + 1:
                raise ReleaseRuntimeError(
                    "committed release event does not immediately follow its bound head"
                )
            if "intent" in group:
                transaction = _transaction_from_parts(
                    group, binding, event, expected_result
                )
                validate_release_promotion_transaction(transaction)
            else:
                # Historical committed bindings predate the sealed intent
                # object.  Their event is still fully authenticated below via
                # the same detached release-namespace proof used by recovery.
                _promotion_bundle_from_parts(
                    binding["task_id"], group, binding, event, expected_result
                )
            actual = semantic.replay_events(records[: head_index + 2])
            if semantic.projection_domain(actual) != expected_result:
                raise ReleaseRuntimeError(
                    "committed release event has an altered projection after-image"
                )
            owned_event_sha256s.add(event["event_sha256"])
            committed_order.append((head_index + 1, group, binding))
        elif classification == "abandoned":
            abandonment = row.get("abandonment")
            abandonment_event_sha256 = row.get("abandonment_event_sha256")
            if not isinstance(abandonment, Mapping):
                raise ReleaseRuntimeError(
                    "abandoned release binding has no disposition proof"
                )
            _rebuilt_original, _expected = _rebuild_abandoned_original_event(
                records, binding, group, abandonment
            )
            abandonment_event = event_by_sha.get(abandonment_event_sha256)
            if (
                abandonment_event is None
                or abandonment_event["event_type"] != RELEASE_ABANDONMENT_EVENT_TYPE
                or abandonment_event["prev_event_sha256"]
                != binding["expected_semantic_head_sha256"]
                or event_index[abandonment_event["event_sha256"]] != head_index + 1
            ):
                raise ReleaseRuntimeError(
                    "abandoned release binding has no exact successor event"
                )
        elif classification == "pending":
            _require_pending_intent(group)
            if records[-1]["event_sha256"] != binding["expected_semantic_head_sha256"]:
                raise ReleaseRuntimeError("pending release binding is stale")
        else:
            raise ReleaseRuntimeError("release binding classification is invalid")
        release_rows.append(
            {
                "promotion_receipt_sha256": group["receipt"][
                    "promotion_receipt_sha256"
                ],
                "manifest_sha256": group["manifest"]["manifest_sha256"],
                "promotion_id": group["receipt"]["promotion_id"],
                "binding": binding,
                "classification": classification,
                **(
                    {
                        "abandonment": row["abandonment"],
                        "abandonment_event_sha256": row[
                            "abandonment_event_sha256"
                        ],
                    }
                    if classification == "abandoned"
                    else {}
                ),
            }
        )

    for index, event in enumerate(records):
        if index == 0:
            genesis_domain = semantic.projection_domain(
                semantic.replay_events(records[:1])
            )
            if RELEASE_NAMESPACE_KEY in genesis_domain:
                raise ReleaseRuntimeError(
                    "release promotion namespace may not be injected at genesis"
                )
            continue
        semantics = semantic.command_semantics(event)
        payload = semantics["payload"]
        delta = payload.get("delta") if isinstance(payload, dict) else None
        operations = delta.get("operations") if isinstance(delta, dict) else None
        touches_release = bool(
            isinstance(operations, list)
            and any(
                isinstance(operation, dict)
                and isinstance(operation.get("path"), list)
                and operation["path"]
                and operation["path"][0] == RELEASE_NAMESPACE_KEY
                for operation in operations
            )
        )
        if touches_release and event["event_sha256"] not in owned_event_sha256s:
            raise ReleaseRuntimeError(
                "release projection mutation has no unique promotion binding owner"
            )
        if event["event_type"] == RELEASE_EVENT_TYPE and event["event_sha256"] not in owned_event_sha256s:
            raise ReleaseRuntimeError(
                "release promotion event has no unique binding owner"
            )

    rebuilt = _empty_namespace()
    for _sequence, group, _binding in sorted(committed_order, key=lambda row: row[0]):
        rebuilt = _advance_namespace(
            rebuilt,
            group["manifest"],
            group["observation_receipt"],
            group["receipt"],
            manifest_object_sha256=group["manifest_object"]["object_sha256"],
            observation_receipt_object_sha256=group["observation_object"][
                "object_sha256"
            ],
            promotion_receipt_object_sha256=group["receipt_object"]["object_sha256"],
        )
    projected = release_namespace_from_projection(replayed)
    if projected != rebuilt:
        raise ReleaseRuntimeError(
            "release promotion projection differs from committed binding ownership"
        )
    referenced_release = {
        digest
        for row in release_rows
        for digest in row["binding"]["object_sha256s"]
    }
    return {
        "task_id": task_id,
        "namespace": projected,
        "active_promotion_receipt_sha256": projected[
            "active_promotion_receipt_sha256"
        ],
        "promotions": sorted(
            release_rows, key=lambda row: (row["promotion_id"], row["promotion_receipt_sha256"])
        ),
        "release_binding_sha256s": sorted(
            row["binding"]["binding_sha256"] for row in release_rows
        ),
        "orphan_release_object_sha256s": sorted(
            release_object_digests - referenced_release
        ),
        "pending_binding_sha256s": sorted(
            row["binding"]["binding_sha256"]
            for row in release_rows
            if row["classification"] == "pending"
        ),
        "abandoned_binding_sha256s": sorted(
            row["binding"]["binding_sha256"]
            for row in release_rows
            if row["classification"] == "abandoned"
        ),
    }


def abandon_pending_release_promotion(
    paths: h.HarnessPaths,
    task_id: str,
    *,
    binding_sha256: str,
    expected_head_sha256: str,
    command_id: str,
    recorded_at: str,
    reason: str,
    authority_ref: object | None = None,
) -> dict[str, Any]:
    """Append a successor-owned terminal disposition for one pending release.

    This never completes the retired Chief's planned event and never deletes
    its immutable objects/binding.  Exact retries re-emit the same stable
    receipt from the authenticated ledger, including after later events or
    another Chief takeover.
    """

    h._require_chief_lock(paths)
    try:
        task_id = h.validate_id(task_id, "task id")
        binding_sha256 = _sha(
            binding_sha256, "release abandonment binding SHA-256"
        )
        expected_head_sha256 = _sha(
            expected_head_sha256, "release abandonment expected head SHA-256"
        )
        command_id = h.validate_id(command_id, "semantic command id")
        _instant(recorded_at, "release abandonment recorded_at")
        reason = _validate_abandonment_argument_text(
            reason, "release abandonment reason"
        )
        records = store.load_semantic_events(paths, task_id)
    except (h.HarnessError, store.SemanticStoreError, TypeError) as exc:
        if isinstance(exc, ReleaseRuntimeError):
            raise
        raise _fail("cannot prepare release abandonment", exc) from exc
    records, replayed = _freeze_event_chain(records, task_id)
    try:
        generic = objects.inspect_semantic_objects(paths, task_id, records)
    except objects.SemanticObjectError as exc:
        raise _fail("cannot inspect release abandonment target", exc) from exc
    candidates = [
        row
        for row in generic.get("bindings", [])
        if isinstance(row, Mapping)
        and row.get("binding_sha256") == binding_sha256
    ]
    if len(candidates) != 1:
        raise ReleaseRuntimeError(
            "release abandonment target is not one unique semantic binding"
        )
    row = candidates[0]
    try:
        binding = objects.validate_semantic_binding(
            {key: row[key] for key in _BINDING_FIELDS}
        )
    except (KeyError, objects.SemanticObjectError) as exc:
        raise _fail("release abandonment target binding is invalid", exc) from exc
    if binding["binding_kind"] != RELEASE_BINDING_KIND:
        raise ReleaseRuntimeError("only release-promotion bindings may be abandoned")
    if binding["expected_semantic_head_sha256"] != expected_head_sha256:
        raise ReleaseRuntimeError(
            "release abandonment expected head differs from its binding"
        )
    group = _release_group_from_generic_report(generic, binding, task_id)
    classification = row.get("classification")
    if classification == "committed":
        raise ReleaseRuntimeError("committed release promotion cannot be abandoned")
    if classification == "abandoned":
        abandonment = row.get("abandonment")
        abandonment_event_sha256 = row.get("abandonment_event_sha256")
        if not isinstance(abandonment, Mapping):
            raise ReleaseRuntimeError("stored release abandonment proof is invalid")
        if (
            abandonment.get("reason") != reason
            or abandonment.get("abandonment_command_id") != command_id
            or abandonment.get("abandonment_recorded_at") != recorded_at
        ):
            raise ReleaseRuntimeError(
                "release abandonment retry differs from its committed disposition"
            )
        _rebuild_abandoned_original_event(records, binding, group, abandonment)
        event = next(
            (
                item
                for item in records
                if item["event_sha256"] == abandonment_event_sha256
            ),
            None,
        )
        if event is None:
            raise ReleaseRuntimeError("stored release abandonment event is missing")
        receipt = _seal_release_abandonment_receipt(
            task_id, binding_sha256, abandonment, event
        )
        try:
            store.repair_semantic_projection(paths, task_id)
        except store.SemanticStoreError as exc:
            raise _fail("cannot repair release abandonment projection", exc) from exc
        inspect_release_runtime(paths, task_id)
        return receipt
    if classification != "pending":
        raise ReleaseRuntimeError("release abandonment target is not pending")
    if records[-1]["event_sha256"] != expected_head_sha256:
        raise ReleaseRuntimeError(
            "release abandonment expected head is no longer current"
        )

    intent = _require_pending_intent(group)
    old_session, old_epoch, intent_receipt = _parse_authority_ref(intent["authority_ref"])
    if intent_receipt != group["receipt"]["promotion_receipt_sha256"]:
        raise ReleaseRuntimeError("release promotion intent names another receipt")
    chief, retirement_proof = _retirement_proof(paths, recorded_at, authority_ref)
    if chief["epoch"] <= old_epoch:
        raise ReleaseRuntimeError(
            "release abandonment requires a successor Chief epoch"
        )
    expected_result = _advance_projection(replayed, group)
    try:
        original_event = semantic.create_transition_event(
            records[-1],
            replayed,
            expected_result,
            event_type=RELEASE_EVENT_TYPE,
            command_id=intent["command_id"],
            recorded_at=intent["recorded_at"],
            authority_ref=intent["authority_ref"],
        )
    except semantic.SemanticEventError as exc:
        raise _fail("cannot rebuild original release promotion", exc) from exc
    if (
        original_event["event_sha256"] != binding["planned_event_sha256"]
        or original_event["result_projection_sha256"]
        != binding["result_projection_sha256"]
    ):
        raise ReleaseRuntimeError(
            "supplied original release command does not match the pending binding"
        )
    original_summary = {
        "event_type": original_event["event_type"],
        "command_id": original_event["command_id"],
        "recorded_at": original_event["recorded_at"],
        "authority_ref": original_event["authority_ref"],
        "event_sha256": original_event["event_sha256"],
    }
    abandonment_authority = (
        f"chief:{chief['session_id']}:e{chief['epoch']}:"
        f"release-abandon:{binding_sha256}"
    )
    abandonment = {
        "schema_version": RELEASE_ABANDONMENT_RECEIPT_SCHEMA_VERSION,
        "task_id": task_id,
        "binding_sha256": binding_sha256,
        "binding_kind": binding["binding_kind"],
        "binding_key": binding["binding_key"],
        "expected_semantic_head_sha256": binding[
            "expected_semantic_head_sha256"
        ],
        "planned_event_sha256": binding["planned_event_sha256"],
        "result_projection_sha256": binding["result_projection_sha256"],
        "original_event": original_summary,
        "retirement_proof": retirement_proof,
        "reason": reason,
        "abandonment_command_id": command_id,
        "abandonment_recorded_at": recorded_at,
        "abandonment_authority_ref": abandonment_authority,
    }
    result_state = semantic.projection_domain(replayed)
    namespace = result_state.get(objects.BINDING_DISPOSITIONS_KEY)
    if namespace is None:
        result_state[objects.BINDING_DISPOSITIONS_KEY] = {
            "schema_version": objects.BINDING_DISPOSITION_SCHEMA_VERSION,
            "abandoned": {binding_sha256: abandonment},
        }
    else:
        if (
            not isinstance(namespace, Mapping)
            or namespace.get("schema_version")
            != objects.BINDING_DISPOSITION_SCHEMA_VERSION
            or not isinstance(namespace.get("abandoned"), Mapping)
            or binding_sha256 in namespace["abandoned"]
        ):
            raise ReleaseRuntimeError(
                "release abandonment disposition namespace is invalid"
            )
        result_state[objects.BINDING_DISPOSITIONS_KEY] = {
            "schema_version": objects.BINDING_DISPOSITION_SCHEMA_VERSION,
            "abandoned": {
                **dict(namespace["abandoned"]),
                binding_sha256: abandonment,
            },
        }
    try:
        planned = semantic.create_transition_event(
            records[-1],
            replayed,
            result_state,
            event_type=RELEASE_ABANDONMENT_EVENT_TYPE,
            command_id=command_id,
            recorded_at=recorded_at,
            authority_ref=abandonment_authority,
        )
        objects._validate_release_abandonment_row(
            abandonment,
            task_id=task_id,
            binding_sha256=binding_sha256,
            event=planned,
        )
        store.preflight_semantic_append(
            paths,
            task_id,
            command_id=command_id,
            expected_head_sha256=expected_head_sha256,
        )
        appended = store.append_semantic_transition(
            paths,
            task_id,
            result_state,
            event_type=RELEASE_ABANDONMENT_EVENT_TYPE,
            command_id=command_id,
            recorded_at=recorded_at,
            authority_ref=abandonment_authority,
            expected_head_sha256=expected_head_sha256,
        )
    except (
        objects.SemanticObjectError,
        semantic.SemanticEventError,
        store.SemanticStoreError,
    ) as exc:
        raise _fail("cannot publish release abandonment event", exc) from exc
    if appended.event["event_sha256"] != planned["event_sha256"]:
        raise ReleaseRuntimeError(
            "semantic append published a different release abandonment event"
        )
    report = inspect_release_runtime(paths, task_id)
    if binding_sha256 not in report["abandoned_binding_sha256s"]:
        raise ReleaseRuntimeError(
            "release abandonment event did not terminally classify its binding"
        )
    return _seal_release_abandonment_receipt(
        task_id, binding_sha256, abandonment, appended.event
    )


def commit_release_promotion_transaction(
    paths: h.HarnessPaths, transaction: Mapping[str, Any]
) -> dict[str, Any]:
    """Commit or recover one Chief-fenced release promotion transaction."""

    h._require_chief_lock(paths)
    tx = validate_release_promotion_transaction(transaction)
    try:
        records = store.load_semantic_events(paths, tx["task_id"])
        records, _replayed = _freeze_event_chain(records, tx["task_id"])
        generic = objects.require_no_pending_bindings(
            paths,
            tx["task_id"],
            records,
            expected_binding_sha256=tx["binding"]["binding_sha256"],
        )
    except (store.SemanticStoreError, objects.SemanticObjectError) as exc:
        raise _fail("cannot preflight release promotion commit", exc) from exc
    existing = next(
        (
            row
            for row in generic["bindings"]
            if row["binding_sha256"] == tx["binding"]["binding_sha256"]
        ),
        None,
    )
    same_slot = [
        row
        for row in generic["bindings"]
        if row["binding_kind"] == RELEASE_BINDING_KIND
        and row["binding_key"] == tx["binding"]["binding_key"]
    ]
    if existing is None and same_slot:
        raise ReleaseRuntimeError(
            "release promotion id CAS slot is already bound differently"
        )
    if existing is not None and existing.get("classification") == "committed":
        matching = [
            event
            for event in records
            if event["event_sha256"] == tx["planned_event"]["event_sha256"]
        ]
        if len(matching) != 1:
            raise ReleaseRuntimeError(
                "committed release binding has no unique ledger event"
            )
        projection = store.repair_semantic_projection(paths, tx["task_id"])
        report = inspect_release_runtime(paths, tx["task_id"])
        return {
            "task_id": tx["task_id"],
            "binding": tx["binding"],
            "event": matching[0],
            "projection": projection,
            "idempotent_replay": True,
            "release_report": report,
        }
    if existing is not None and existing.get("classification") == "abandoned":
        raise ReleaseRuntimeError(
            "release promotion binding was terminally abandoned by a successor Chief"
        )

    session_id, epoch, _receipt_sha = _parse_authority_ref(tx["authority_ref"])
    transaction_group = _contract_group(tx["objects"], tx["task_id"])
    rebuilt = prepare_release_promotion_transaction(
        paths,
        tx["task_id"],
        transaction_group["manifest"],
        transaction_group["observation_receipt"],
        transaction_group["receipt"],
        tx["command_id"],
        tx["recorded_at"],
        authority_ref={"session_id": session_id, "epoch": epoch},
    )
    if semantic.canonical_json_bytes(
        rebuilt, max_bytes=MAX_RELEASE_TRANSACTION_BYTES
    ) != semantic.canonical_json_bytes(
        tx, max_bytes=MAX_RELEASE_TRANSACTION_BYTES
    ):
        raise ReleaseRuntimeError(
            "release promotion transaction was not prepared from its exact semantic head"
        )
    # Publication authority is checked for every not-yet-committed append,
    # including a binding-only crash retry.  This preserves same-epoch recovery
    # but fails closed after Chief takeover instead of appending a new event as
    # the retired epoch.  A future successor-recovery protocol must record its
    # own ledger-bound provenance rather than silently impersonating the old
    # authority reference.
    _require_live_chief(paths, tx["authority_ref"], tx["recorded_at"])
    try:
        store.preflight_semantic_append(
            paths,
            tx["task_id"],
            command_id=tx["command_id"],
            expected_head_sha256=tx["expected_head_sha256"],
        )
        for wrapped in tx["objects"]:
            objects.publish_semantic_object(paths, wrapped)
        objects.publish_semantic_binding(paths, tx["binding"], records)
        appended = store.append_semantic_transition(
            paths,
            tx["task_id"],
            tx["result_state"],
            event_type=tx["event_type"],
            command_id=tx["command_id"],
            recorded_at=tx["recorded_at"],
            authority_ref=tx["authority_ref"],
            expected_head_sha256=tx["expected_head_sha256"],
        )
    except (store.SemanticStoreError, objects.SemanticObjectError) as exc:
        raise _fail("cannot publish release promotion transaction", exc) from exc
    if appended.event["event_sha256"] != tx["planned_event"]["event_sha256"]:
        raise ReleaseRuntimeError(
            "semantic append published a different release promotion event"
        )
    report = inspect_release_runtime(paths, tx["task_id"])
    return {
        "task_id": tx["task_id"],
        "binding": tx["binding"],
        "event": appended.event,
        "projection": appended.projection,
        "idempotent_replay": appended.idempotent_replay,
        "release_report": report,
    }


def recover_committed_promotion_bundle(
    paths: h.HarnessPaths,
    task_id: str,
    manifest: Mapping[str, Any],
    observation_receipt: Mapping[str, Any],
    promotion_receipt: Mapping[str, Any],
    *,
    command_id: str,
    recorded_at: str,
    expected_head_sha256: str,
) -> dict[str, Any]:
    """Re-emit the exact bundle for an already committed promotion.

    This is the crash boundary for a successful semantic commit followed by a
    lost stdout stream.  It never prepares or appends a new event: all supplied
    inputs must match one authenticated committed binding and its immediately
    following ledger event byte-for-byte.
    """

    try:
        task_id = h.validate_id(task_id, "task id")
        command_id = h.validate_id(command_id, "semantic command id")
        expected_head_sha256 = _sha(
            expected_head_sha256, "expected semantic head SHA-256"
        )
        checked_manifest = releases.validate_release_manifest(manifest)
        checked_observation = observations.validate_release_observation_receipt(
            observation_receipt, checked_manifest
        )
        checked_receipt = releases.validate_promotion_receipt(
            promotion_receipt, checked_manifest
        )
        records = store.load_semantic_events(paths, task_id)
    except (
        h.HarnessError,
        observations.ReleaseArtifactError,
        releases.ReleaseManifestError,
        store.SemanticStoreError,
    ) as exc:
        raise _fail("cannot recover committed release promotion", exc) from exc
    records, _replayed = _freeze_event_chain(records, task_id)
    # The ledger event is authoritative and may have been durably published
    # before its derived projection write failed. Repair from the authenticated
    # ledger before invoking the stricter complete-surface inspector.
    try:
        store.repair_semantic_projection(paths, task_id)
    except store.SemanticStoreError as exc:
        raise _fail("cannot repair release projection during recovery", exc) from exc
    # Authenticate the complete release surface before selecting a record.
    inspect_release_runtime(paths, task_id)
    try:
        generic = objects.inspect_semantic_objects(paths, task_id, records)
    except objects.SemanticObjectError as exc:
        raise _fail("cannot recover release semantic objects", exc) from exc
    object_rows = generic.get("objects")
    binding_rows = generic.get("bindings")
    if not isinstance(object_rows, list) or not isinstance(binding_rows, list):
        raise ReleaseRuntimeError("release semantic object report is invalid")
    by_digest: dict[str, dict[str, Any]] = {}
    for row in object_rows:
        try:
            wrapped = objects.validate_semantic_object(
                {key: row[key] for key in _OBJECT_FIELDS}
            )
        except (KeyError, objects.SemanticObjectError) as exc:
            raise _fail("release recovery object row is invalid", exc) from exc
        by_digest[wrapped["object_sha256"]] = wrapped
    candidates = [
        row
        for row in binding_rows
        if row.get("binding_kind") == RELEASE_BINDING_KIND
        and row.get("binding_key") == checked_receipt["promotion_id"]
    ]
    if len(candidates) != 1 or candidates[0].get("classification") != "committed":
        raise ReleaseRuntimeError(
            "no unique committed release promotion matches the recovery input"
        )
    try:
        binding = objects.validate_semantic_binding(
            {key: candidates[0][key] for key in _BINDING_FIELDS}
        )
        group = _group_from_binding_objects(by_digest, binding, task_id)
    except (KeyError, objects.SemanticObjectError) as exc:
        raise _fail("release recovery binding is invalid", exc) from exc
    expected_group = _contract_group(
        _contract_objects(
            task_id, checked_manifest, checked_observation, checked_receipt
        ),
        task_id,
        require_intent=False,
    )
    if (
        group["manifest_object"] != expected_group["manifest_object"]
        or group["observation_object"] != expected_group["observation_object"]
        or group["receipt_object"] != expected_group["receipt_object"]
        or binding["expected_semantic_head_sha256"] != expected_head_sha256
    ):
        raise ReleaseRuntimeError(
            "committed release promotion differs from recovery input"
        )
    event_by_sha = {event["event_sha256"]: event for event in records}
    event_index = {event["event_sha256"]: index for index, event in enumerate(records)}
    event = event_by_sha.get(binding["planned_event_sha256"])
    head_index = event_index.get(expected_head_sha256)
    if (
        event is None
        or head_index is None
        or event_index.get(event["event_sha256"]) != head_index + 1
        or event["command_id"] != command_id
        or event["recorded_at"] != recorded_at
    ):
        raise ReleaseRuntimeError(
            "committed release event differs from recovery command"
        )
    try:
        base_projection = semantic.replay_events(records[: head_index + 1])
    except semantic.SemanticEventError as exc:
        raise _fail("release recovery prefix is invalid", exc) from exc
    expected_result = _advance_projection(base_projection, group)
    return _promotion_bundle_from_parts(task_id, group, binding, event, expected_result)


def _promotion_bundle_from_parts(
    task_id: str,
    group: Mapping[str, Any],
    binding: Mapping[str, Any],
    event: Mapping[str, Any],
    result_state: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a bundle from an authenticated committed binding, including legacy."""

    prior_domain = _reverse_transaction_namespace(result_state, group)
    prior_namespace = validate_release_namespace(
        prior_domain.get(RELEASE_NAMESPACE_KEY)
    )
    base = {
        "schema_version": PROMOTION_BUNDLE_SCHEMA_VERSION,
        "proof_scope": PROMOTION_BUNDLE_PROOF_SCOPE,
        "task_id": task_id,
        "manifest": group["manifest"],
        "observation_receipt": group["observation_receipt"],
        "promotion_receipt": group["receipt"],
        "prior_release_namespace": prior_namespace,
        "semantic_binding": binding,
        "semantic_event": event,
    }
    base["bundle_sha256"] = semantic.canonical_sha256(
        base, max_bytes=MAX_PROMOTION_BUNDLE_BYTES
    )
    return validate_promotion_bundle(base)


def create_promotion_bundle(
    transaction: Mapping[str, Any]
) -> dict[str, Any]:
    """Seal a detached proof of the exact release-namespace transition.

    Unrelated task projection preimages are intentionally omitted. The bundle
    authenticates the release namespace delta and bound objects; full-task
    projection hashes remain a ledger/doctor responsibility.
    """

    tx = validate_release_promotion_transaction(transaction)
    group = _contract_group(tx["objects"], tx["task_id"])
    return _promotion_bundle_from_parts(
        tx["task_id"], group, tx["binding"], tx["planned_event"], tx["result_state"]
    )


def validate_promotion_bundle(
    value: Mapping[str, Any], expected_bundle_sha256: str | None = None
) -> dict[str, Any]:
    """Validate a detached release-namespace proof and optional approved digest."""

    if not isinstance(value, Mapping) or set(value) != _BUNDLE_FIELDS:
        raise ReleaseRuntimeError("promotion bundle schema is invalid")
    item = _clone(value, maximum=MAX_PROMOTION_BUNDLE_BYTES)
    _exact_version(
        item["schema_version"],
        PROMOTION_BUNDLE_SCHEMA_VERSION,
        "promotion bundle version",
    )
    if item["proof_scope"] != PROMOTION_BUNDLE_PROOF_SCOPE:
        raise ReleaseRuntimeError("promotion bundle proof scope is invalid")
    try:
        task_id = h.validate_id(item["task_id"], "task id")
        manifest = releases.validate_release_manifest(item["manifest"])
        observation_receipt = observations.validate_release_observation_receipt(
            item["observation_receipt"], manifest
        )
        receipt = releases.validate_promotion_receipt(
            item["promotion_receipt"], manifest
        )
        prior_namespace = validate_release_namespace(
            item["prior_release_namespace"]
        )
        binding = objects.validate_semantic_binding(item["semantic_binding"])
        semantics = semantic.command_semantics(item["semantic_event"])
    except (
        h.HarnessError,
        observations.ReleaseArtifactError,
        releases.ReleaseManifestError,
        objects.SemanticObjectError,
        semantic.SemanticEventError,
    ) as exc:
        raise _fail("promotion bundle contract is invalid", exc) from exc
    event = item["semantic_event"]
    legacy_binding = len(binding["object_sha256s"]) == 3
    if len(binding["object_sha256s"]) not in {3, 4}:
        raise ReleaseRuntimeError("promotion bundle binding object count is invalid")
    wrapped = _contract_objects(task_id, manifest, observation_receipt, receipt)
    if not legacy_binding:
        wrapped.append(_promotion_intent_object(task_id, event, receipt))
    wrapped.sort(key=lambda row: row["object_type"])
    group = _contract_group(wrapped, task_id, require_intent=not legacy_binding)
    expected_refs = sorted(row["object_sha256"] for row in wrapped)
    _chief_session, _chief_epoch, authority_receipt = _parse_authority_ref(
        event["authority_ref"]
    )
    if (
        authority_receipt != receipt["promotion_receipt_sha256"]
        or receipt["artifact_observation_receipt_sha256"]
        != observation_receipt["observation_receipt_sha256"]
        or binding["binding_kind"] != RELEASE_BINDING_KIND
        or binding["task_id"] != task_id
        or binding["binding_key"] != receipt["promotion_id"]
        or binding["object_sha256s"] != expected_refs
        or semantics["event_type"] != RELEASE_EVENT_TYPE
        or binding["expected_semantic_head_sha256"]
        != event["prev_event_sha256"]
        or binding["planned_event_sha256"] != event["event_sha256"]
        or binding["result_projection_sha256"]
        != event["result_projection_sha256"]
    ):
        raise ReleaseRuntimeError(
            "promotion bundle semantic cross-binding is invalid"
        )
    _validate_delta_scope(semantics["payload"])
    expected_namespace = _advance_namespace(
        prior_namespace,
        manifest,
        observation_receipt,
        receipt,
        manifest_object_sha256=group["manifest_object"]["object_sha256"],
        observation_receipt_object_sha256=group["observation_object"][
            "object_sha256"
        ],
        promotion_receipt_object_sha256=group["receipt_object"]["object_sha256"],
    )
    prior_domain: dict[str, Any] = {}
    if prior_namespace != _empty_namespace():
        prior_domain[RELEASE_NAMESPACE_KEY] = prior_namespace
    expected_domain = {RELEASE_NAMESPACE_KEY: expected_namespace}
    try:
        expected_delta = semantic.build_delta(prior_domain, expected_domain)
    except semantic.SemanticEventError as exc:
        raise _fail("promotion bundle release delta cannot be rebuilt", exc) from exc
    if semantics["payload"]["delta"] != expected_delta:
        raise ReleaseRuntimeError(
            "promotion bundle event is not the exact release namespace after-image"
        )
    _validate_observation_order(receipt, event["recorded_at"])
    base = {
        "schema_version": PROMOTION_BUNDLE_SCHEMA_VERSION,
        "proof_scope": PROMOTION_BUNDLE_PROOF_SCOPE,
        "task_id": task_id,
        "manifest": manifest,
        "observation_receipt": observation_receipt,
        "promotion_receipt": receipt,
        "prior_release_namespace": prior_namespace,
        "semantic_binding": binding,
        "semantic_event": event,
    }
    expected = semantic.canonical_sha256(
        base, max_bytes=MAX_PROMOTION_BUNDLE_BYTES
    )
    if item["bundle_sha256"] != expected:
        raise ReleaseRuntimeError("promotion bundle SHA-256 is invalid")
    if expected_bundle_sha256 is not None:
        if _sha(expected_bundle_sha256, "expected promotion bundle SHA-256") != expected:
            raise ReleaseRuntimeError(
                "promotion bundle digest differs from the trusted expected SHA-256"
            )
    return {**base, "bundle_sha256": expected}


__all__ = [
    "MAX_RELEASE_ABANDONMENT_RECEIPT_BYTES",
    "MAX_PROMOTION_BUNDLE_BYTES",
    "MAX_RELEASE_NAMESPACE_BYTES",
    "MAX_RELEASE_PROMOTIONS",
    "MAX_RELEASE_TRANSACTION_BYTES",
    "PROMOTION_BUNDLE_SCHEMA_VERSION",
    "PROMOTION_BUNDLE_PROOF_SCOPE",
    "RELEASE_BINDING_KIND",
    "RELEASE_ABANDONMENT_EVENT_TYPE",
    "RELEASE_ABANDONMENT_PROOF_SCOPE",
    "RELEASE_ABANDONMENT_RECEIPT_SCHEMA_VERSION",
    "RELEASE_EVENT_TYPE",
    "RELEASE_NAMESPACE_KEY",
    "RELEASE_PROMOTION_TRANSACTION_SCHEMA_VERSION",
    "RELEASE_RUNTIME_SCHEMA_VERSION",
    "ReleaseRuntimeError",
    "abandon_pending_release_promotion",
    "commit_release_promotion_transaction",
    "create_promotion_bundle",
    "inspect_release_runtime",
    "prepare_release_promotion_transaction",
    "recover_committed_promotion_bundle",
    "release_namespace_from_projection",
    "validate_promotion_bundle",
    "validate_release_abandonment_receipt",
    "validate_release_namespace",
    "validate_release_promotion_transaction",
]
