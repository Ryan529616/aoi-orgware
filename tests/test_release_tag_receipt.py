"""Falsification tests for exact-CI-bound release-tag receipts."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any

import pytest

from aoi_orgware import confidentiality
from aoi_orgware import release_ci_receipt
from aoi_orgware import release_tag_receipt


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sealed(base: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(base)
    result["receipt_sha256"] = hashlib.sha256(_canonical(result)).hexdigest()
    return result


def _exact_ci(*, commit: str = "a" * 40) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema_version": 1,
        "kind": "exact_release_ci_gate",
        "repository": release_ci_receipt.EXPECTED_REPOSITORY,
        "commit": commit,
        "branch": release_ci_receipt.EXPECTED_BRANCH,
        "event": "push",
        "workflows": [
            {
                "path": ".github/workflows/docs.yml",
                "response_sha256": "1" * 64,
                "runs": [
                    {"run_id": 101, "run_attempt": 1, "workflow_id": 1001}
                ],
            },
            {
                "path": ".github/workflows/test.yml",
                "response_sha256": "2" * 64,
                "runs": [
                    {"run_id": 202, "run_attempt": 1, "workflow_id": 2002}
                ],
            },
        ],
    }
    return _sealed(base)


def _confidentiality_preflight() -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema_version": 1,
        "action": "git_push_preflight",
        "mode": "standard",
        "config_sha256": "6" * 64,
        "boundary": "aoi_cooperative_preflight_not_system_dlp",
        "remote": "github",
        "destination": "https://github.com/Ryan529616/aoi-orgware.git",
        "updates": [
            {
                "local_ref": "refs/heads/main",
                "local_sha": "a" * 40,
                "remote_ref": "refs/heads/main",
                "remote_sha": "0" * 40,
            }
        ],
        "outgoing_commits": [],
        "protected_policy_sha256": "7" * 64,
        "protected_rule_count": 0,
        "protected_exposures": [],
        "rewrite_keys": [],
        "decision": "allowed",
    }
    base["receipt_sha256"] = hashlib.sha256(
        confidentiality.canonical_git_push_preflight_receipt_bytes(base)
    ).hexdigest()
    assert confidentiality.validate_git_push_preflight_receipt_structure(base) == (
        base["receipt_sha256"]
    )
    return base


def _preflight(
    *,
    exact_ci: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    exact = exact_ci or _exact_ci()
    receipt = release_tag_receipt.build_release_tag_preflight(
        task_id="release-task",
        task_plan_sha256="3" * 64,
        verification_index=7,
        verification_record_sha256="4" * 64,
        verification_artifact_sha256="5" * 64,
        exact_ci_receipt=exact,
        tag="v0.4.0a3",
        tag_object_oid="b" * 40,
        remote="github",
        push_transport="https://github.com/Ryan529616/aoi-orgware.git",
        destination="https://github.com/Ryan529616/aoi-orgware.git",
        confidentiality_preflight=_confidentiality_preflight(),
    )
    return receipt, exact


def _delivery(
    preflight: dict[str, Any],
    exact_ci: dict[str, Any],
    *,
    remote_tag_object_oid: str = "b" * 40,
    remote_peeled_commit_oid: str = "a" * 40,
) -> dict[str, Any]:
    return release_tag_receipt.build_release_tag_delivery(
        preflight=preflight,
        exact_ci_receipt=exact_ci,
        preflight_verification_index=11,
        preflight_verification_record_sha256="7" * 64,
        preflight_artifact_sha256=hashlib.sha256(_canonical(preflight)).hexdigest(),
        remote_tag_object_oid=remote_tag_object_oid,
        remote_peeled_commit_oid=remote_peeled_commit_oid,
        observed_destination=preflight["destination"],
    )


def _validate_delivery(
    delivery: dict[str, Any],
    preflight: dict[str, Any],
    exact_ci: dict[str, Any],
) -> dict[str, Any]:
    return release_tag_receipt.validate_release_tag_delivery(
        delivery,
        preflight=preflight,
        exact_ci_receipt=exact_ci,
        preflight_verification_index=11,
        preflight_verification_record_sha256="7" * 64,
        preflight_artifact_sha256=hashlib.sha256(_canonical(preflight)).hexdigest(),
    )


def _reseal(value: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(value)
    result.pop("receipt_sha256", None)
    return _sealed(result)


def test_preflight_and_delivery_round_trip_are_canonical() -> None:
    preflight, exact_ci = _preflight()
    raw = release_tag_receipt.canonical_release_tag_receipt_bytes(preflight)
    assert not raw.endswith(b"\n")
    parsed = release_tag_receipt.parse_release_tag_receipt_bytes(raw)
    assert (
        release_tag_receipt.validate_release_tag_preflight(
            parsed,
            exact_ci_receipt=exact_ci,
            expected_task_id="release-task",
            expected_plan_sha256="3" * 64,
        )
        == preflight
    )

    delivery = _delivery(preflight, exact_ci)
    assert delivery["push_transport"] == preflight["push_transport"]
    assert delivery["preflight_verification"] == {
        "verification_index": 11,
        "verification_record_sha256": "7" * 64,
        "artifact_sha256": hashlib.sha256(_canonical(preflight)).hexdigest(),
        "receipt_sha256": preflight["receipt_sha256"],
    }
    delivery_raw = release_tag_receipt.canonical_release_tag_receipt_bytes(
        delivery
    )
    assert release_tag_receipt.parse_release_tag_receipt_bytes(
        delivery_raw
    ) == delivery
    assert (
        _validate_delivery(delivery, preflight, exact_ci)
        == delivery
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("task_id", "other-task", "identity"),
        ("task_plan_sha256", "7" * 64, "identity"),
        ("tag", "release-0.4.0", "identity"),
        ("tag_ref", "refs/tags/other", "identity"),
        ("tag_object_oid", "a" * 40, "identity"),
        ("peeled_commit_oid", "c" * 40, "identity"),
        ("repository", "attacker/fork", "identity"),
        ("event", "workflow_dispatch", "identity"),
    ],
)
def test_preflight_rejects_resealed_identity_tamper(
    field: str, value: object, message: str
) -> None:
    preflight, exact_ci = _preflight()
    preflight[field] = value
    tampered = _reseal(preflight)
    with pytest.raises(
        release_tag_receipt.ReleaseTagReceiptError, match=message
    ):
        release_tag_receipt.validate_release_tag_preflight(
            tampered,
            exact_ci_receipt=exact_ci,
            expected_task_id="release-task",
            expected_plan_sha256="3" * 64,
        )


def test_preflight_rejects_wrong_ci_and_confidentiality_edges() -> None:
    preflight, exact_ci = _preflight()
    wrong_ci = _exact_ci(commit="c" * 40)
    with pytest.raises(
        release_tag_receipt.ReleaseTagReceiptError, match="identity"
    ):
        release_tag_receipt.validate_release_tag_preflight(
            preflight, exact_ci_receipt=wrong_ci
        )

    tampered = deepcopy(preflight)
    tampered["release_ci_verification"]["receipt_sha256"] = "7" * 64
    tampered = _reseal(tampered)
    with pytest.raises(
        release_tag_receipt.ReleaseTagReceiptError,
        match="another exact-CI receipt",
    ):
        release_tag_receipt.validate_release_tag_preflight(
            tampered, exact_ci_receipt=exact_ci
        )


def test_preflight_schema_requires_push_transport() -> None:
    preflight, exact_ci = _preflight()
    tampered = deepcopy(preflight)
    del tampered["push_transport"]
    with pytest.raises(
        release_tag_receipt.ReleaseTagReceiptError,
        match="preflight receipt schema",
    ):
        release_tag_receipt.validate_release_tag_preflight(
            tampered, exact_ci_receipt=exact_ci
        )

    tampered = deepcopy(preflight)
    tampered["confidentiality_preflight_sha256"] = "8" * 64
    tampered = _reseal(tampered)
    with pytest.raises(
        release_tag_receipt.ReleaseTagReceiptError,
        match="confidentiality preflight digest",
    ):
        release_tag_receipt.validate_release_tag_preflight(
            tampered, exact_ci_receipt=exact_ci
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda receipt: receipt.__setitem__("unexpected", "value"), "schema"),
        (
            lambda receipt: receipt.__setitem__("action", "git_push"),
            "identity",
        ),
        (
            lambda receipt: receipt.__setitem__("receipt_sha256", "8" * 64),
            "digest",
        ),
    ],
)
def test_preflight_and_delivery_reject_resealed_nested_confidentiality_tamper(
    mutate: Any, message: str
) -> None:
    preflight, exact_ci = _preflight()
    delivery = _delivery(preflight, exact_ci)
    tampered = deepcopy(preflight)
    mutate(tampered["confidentiality_preflight"])
    tampered = _reseal(tampered)

    with pytest.raises(
        release_tag_receipt.ReleaseTagReceiptError, match=message
    ):
        release_tag_receipt.validate_release_tag_preflight(
            tampered, exact_ci_receipt=exact_ci
        )
    with pytest.raises(
        release_tag_receipt.ReleaseTagReceiptError, match=message
    ):
        _validate_delivery(delivery, tampered, exact_ci)


def test_builders_reject_nonmapping_or_wrong_remote_delivery() -> None:
    exact_ci = _exact_ci()
    with pytest.raises(
        release_tag_receipt.ReleaseTagReceiptError,
        match="confidentiality preflight must be an object",
    ):
        release_tag_receipt.build_release_tag_preflight(
            task_id="release-task",
            task_plan_sha256="3" * 64,
            verification_index=1,
            verification_record_sha256="4" * 64,
            verification_artifact_sha256="5" * 64,
            exact_ci_receipt=exact_ci,
            tag="v0.4.0a3",
            tag_object_oid="b" * 40,
            remote="github",
            push_transport="https://example.invalid/repo.git",
            destination="https://example.invalid/repo.git",
            confidentiality_preflight=[],  # type: ignore[arg-type]
        )

    malformed = _confidentiality_preflight()
    del malformed["action"]
    with pytest.raises(
        release_tag_receipt.ReleaseTagReceiptError,
        match="release-tag confidentiality preflight is invalid: .*schema",
    ):
        release_tag_receipt.build_release_tag_preflight(
            task_id="release-task",
            task_plan_sha256="3" * 64,
            verification_index=1,
            verification_record_sha256="4" * 64,
            verification_artifact_sha256="5" * 64,
            exact_ci_receipt=exact_ci,
            tag="v0.4.0a3",
            tag_object_oid="b" * 40,
            remote="github",
            push_transport="https://example.invalid/repo.git",
            destination="https://example.invalid/repo.git",
            confidentiality_preflight=malformed,
        )

    preflight, exact_ci = _preflight(exact_ci=exact_ci)
    with pytest.raises(
        release_tag_receipt.ReleaseTagReceiptError, match="differs"
    ):
        _delivery(
            preflight,
            exact_ci,
            remote_tag_object_oid="c" * 40,
        )


def test_delivery_validator_rejects_malformed_preflight_without_traceback() -> None:
    preflight, exact_ci = _preflight()
    delivery = _delivery(preflight, exact_ci)
    with pytest.raises(
        release_tag_receipt.ReleaseTagReceiptError,
        match="preflight receipt schema",
    ):
        release_tag_receipt.validate_release_tag_delivery(
            delivery,
            preflight=[],  # type: ignore[arg-type]
            exact_ci_receipt=exact_ci,
            preflight_verification_index=11,
            preflight_verification_record_sha256="7" * 64,
            preflight_artifact_sha256=hashlib.sha256(
                _canonical(preflight)
            ).hexdigest(),
        )
    with pytest.raises(
        release_tag_receipt.ReleaseTagReceiptError,
        match="preflight receipt schema",
    ):
        release_tag_receipt.validate_release_tag_delivery(
            delivery,
            preflight={"release_ci_verification": []},
            exact_ci_receipt=exact_ci,
            preflight_verification_index=11,
            preflight_verification_record_sha256="7" * 64,
            preflight_artifact_sha256=hashlib.sha256(
                _canonical(preflight)
            ).hexdigest(),
        )


def test_delivery_rejects_resealed_correlation_tamper() -> None:
    preflight, exact_ci = _preflight()
    delivery = _delivery(preflight, exact_ci)
    for field, value in (
        ("preflight_receipt_sha256", "7" * 64),
        ("release_ci_artifact_sha256", "8" * 64),
        ("tag_object_oid", "c" * 40),
        ("peeled_commit_oid", "d" * 40),
        ("push_transport", "ssh://git@attacker.invalid/repo.git"),
        ("destination", "https://attacker.invalid/repo.git"),
    ):
        tampered = deepcopy(delivery)
        tampered[field] = value
        tampered = _reseal(tampered)
        with pytest.raises(
            release_tag_receipt.ReleaseTagReceiptError, match="identity"
        ):
            _validate_delivery(tampered, preflight, exact_ci)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("verification_index", 12),
        ("verification_record_sha256", "8" * 64),
        ("artifact_sha256", "9" * 64),
        ("receipt_sha256", "0" * 64),
    ],
)
def test_delivery_rejects_resealed_preflight_cas_edge_tamper(
    field: str, value: object
) -> None:
    preflight, exact_ci = _preflight()
    delivery = _delivery(preflight, exact_ci)
    tampered = deepcopy(delivery)
    tampered["preflight_verification"][field] = value
    tampered = _reseal(tampered)
    with pytest.raises(
        release_tag_receipt.ReleaseTagReceiptError,
        match="identity",
    ):
        _validate_delivery(tampered, preflight, exact_ci)


def test_delivery_validator_revalidates_preflight_digest() -> None:
    preflight, exact_ci = _preflight()
    delivery = _delivery(preflight, exact_ci)
    tampered_preflight = deepcopy(preflight)
    tampered_preflight["task_id"] = "other-task"
    tampered_delivery = deepcopy(delivery)
    tampered_delivery["task_id"] = "other-task"
    tampered_delivery["preflight_verification"]["artifact_sha256"] = hashlib.sha256(
        _canonical(tampered_preflight)
    ).hexdigest()
    tampered_delivery = _reseal(tampered_delivery)
    with pytest.raises(
        release_tag_receipt.ReleaseTagReceiptError,
        match="preflight receipt digest",
    ):
        release_tag_receipt.validate_release_tag_delivery(
            tampered_delivery,
            preflight=tampered_preflight,
            exact_ci_receipt=exact_ci,
            preflight_verification_index=11,
            preflight_verification_record_sha256="7" * 64,
            preflight_artifact_sha256=hashlib.sha256(
                _canonical(tampered_preflight)
            ).hexdigest(),
        )


def test_parser_rejects_duplicate_keys_and_noncanonical_bytes() -> None:
    preflight, _exact = _preflight()
    raw = release_tag_receipt.canonical_release_tag_receipt_bytes(preflight)
    with pytest.raises(
        release_tag_receipt.ReleaseTagReceiptError, match="duplicate JSON key"
    ):
        release_tag_receipt.parse_release_tag_receipt_bytes(
            raw[:-1] + b',"schema_version":1}'
        )
    with pytest.raises(
        release_tag_receipt.ReleaseTagReceiptError, match="not canonical"
    ):
        release_tag_receipt.parse_release_tag_receipt_bytes(raw + b"\n")


@pytest.mark.parametrize(
    "push_transport",
    [
        "",
        " https://example.invalid/repo.git",
        "https://example.invalid/repo.git ",
    ],
)
def test_preflight_rejects_noncanonical_push_transport(
    push_transport: str,
) -> None:
    exact_ci = _exact_ci()
    with pytest.raises(
        release_tag_receipt.ReleaseTagReceiptError,
        match="push transport must be non-empty canonical text",
    ):
        release_tag_receipt.build_release_tag_preflight(
            task_id="release-task",
            task_plan_sha256="3" * 64,
            verification_index=7,
            verification_record_sha256="4" * 64,
            verification_artifact_sha256="5" * 64,
            exact_ci_receipt=exact_ci,
            tag="v0.4.0a3",
            tag_object_oid="b" * 40,
            remote="github",
            push_transport=push_transport,
            destination="https://example.invalid/repo.git",
            confidentiality_preflight=_confidentiality_preflight(),
        )
