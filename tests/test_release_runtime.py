"""Adversarial integration tests for fenced release-promotion publication."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "src"))

from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import release_artifacts as observations  # noqa: E402
from aoi_orgware import release_manifest as manifests  # noqa: E402
from aoi_orgware import release_runtime as runtime  # noqa: E402
from aoi_orgware import semantic_events as semantic  # noqa: E402
from aoi_orgware import semantic_objects as objects  # noqa: E402
from aoi_orgware import semantic_store as store  # noqa: E402
from aoi_orgware.config import default_config_text  # noqa: E402


TASK = "release-task"
NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64


def _artifacts(version: str) -> list[dict[str, object]]:
    return [
        {
            "name": f"dist/aoi_orgware-{version}-py3-none-any.whl",
            "size_bytes": 1234,
            "sha256": SHA_A,
        },
        {
            "name": f"dist/aoi_orgware-{version}.tar.gz",
            "size_bytes": 2345,
            "sha256": SHA_B,
        },
    ]


def _manifest(
    *,
    name: str = "aoi-orgware",
    version: str = "0.4.0",
    dependencies: list[dict[str, str]] | None = None,
    commit_oid: str = "c" * 40,
) -> dict[str, object]:
    artifacts = _artifacts(version)
    return manifests.seal_release_manifest(
        {
            "schema_version": 1,
            "distribution_name": name,
            "tag": f"v{version}",
            "git_object_format": "sha1",
            "commit_oid": commit_oid,
            "tree_oid": "d" * 40,
            "package_version": version,
            "build_environment": {
                "platform": "ubuntu-24.04",
                "python_version": "3.13.1",
                "builder_environment_receipt_sha256": SHA_E,
            },
            "workflow": {"workflow_name": "release", "run_id": f"run-{version}", "run_attempt": 1},
            "artifacts": artifacts,
            "producer_results": [{"producer_id": "build-linux", "result_sha256": SHA_F}],
            "interfaces": {
                "console_entry_point": {"name": "aoi", "target": "aoi_orgware.cli:main"},
                "codex_hook_entry_point": {"name": "aoi-codex-hook", "target": "aoi_orgware.codex_hook:main"},
                "hook_protocol_version": 6,
                "installed_metadata_sha256": SHA_E,
            },
            "schema_versions": {"semantic-event": 2, "packet": 6},
            "dependencies": dependencies or [],
            "verification": {
                "matrix": [
                    {
                        "platform": "linux",
                        "gate_id": "release-test",
                        "check_contract_sha256": SHA_A,
                        "receipt_sha256": SHA_E,
                        "status": "pass",
                    },
                    {
                        "platform": "windows",
                        "gate_id": "release-test",
                        "check_contract_sha256": SHA_A,
                        "receipt_sha256": SHA_F,
                        "status": "pass",
                    },
                ],
                "tested_artifacts": copy.deepcopy(artifacts),
                "rebuild": {
                    "status": "reproducible",
                    "artifacts": copy.deepcopy(artifacts),
                },
            },
            "sbom": {"location": "artifacts/sbom.spdx.json", "sha256": SHA_A},
            "attestation": {"location": "artifacts/attestation.json", "sha256": SHA_B},
        }
    )


def _receipt(
    manifest: dict[str, object],
    *,
    promotion_id: str,
    rollback_provenance: dict[str, object] | None = None,
    registry_observed_at: str = "2026-07-19T12:00:00.000000Z",
    installed_observed_at: str = "2026-07-19T12:00:30.000000Z",
) -> dict[str, object]:
    dependencies = manifest["dependencies"]
    assert isinstance(dependencies, list)
    version = str(manifest["package_version"])
    artifacts = _artifacts(version)
    return manifests.seal_promotion_receipt(
        {
            "schema_version": 1,
            "promotion_id": promotion_id,
            "manifest_sha256": manifest["manifest_sha256"],
            "artifact_observation_receipt_sha256": _observation(manifest)[
                "observation_receipt_sha256"
            ],
            "registry_readback": {
                "registry": "https://pypi.org",
                "project": manifest["distribution_name"],
                "package_version": version,
                "observed_at": registry_observed_at,
                "artifacts": artifacts,
            },
            "installed": {
                "distribution_name": manifest["distribution_name"],
                "package_version": version,
                "observed_at": installed_observed_at,
                "installed_metadata_sha256": SHA_E,
                "console_entry_point": {"name": "aoi", "target": "aoi_orgware.cli:main"},
                "codex_hook_entry_point": {"name": "aoi-codex-hook", "target": "aoi_orgware.codex_hook:main"},
                "hook_protocol_version": 6,
            },
            "dependency_promotions": [
                {"name": item["name"], "promotion_receipt_sha256": item["promotion_receipt_sha256"]}
                for item in dependencies
            ],
            "rollback_provenance": rollback_provenance,
        },
        manifest,
    )


def _observation(manifest: dict[str, object]) -> dict[str, object]:
    rebuild = manifest["verification"]
    assert isinstance(rebuild, dict)
    rebuild = rebuild["rebuild"]
    assert isinstance(rebuild, dict)
    return observations._seal_release_observation_receipt(  # type: ignore[attr-defined]
        {
            "schema_version": 1,
            "manifest_sha256": manifest["manifest_sha256"],
            "git": {
                "git_object_format": manifest["git_object_format"],
                "commit_oid": manifest["commit_oid"],
                "tree_oid": manifest["tree_oid"],
                "tag": manifest["tag"],
                "package_version": manifest["package_version"],
            },
            "artifacts": manifest["artifacts"],
            "sbom_sha256": manifest["sbom"]["sha256"],  # type: ignore[index]
            "attestation_sha256": manifest["attestation"]["sha256"],  # type: ignore[index]
            "evidence_files": {
                "producer_results": {
                    row["producer_id"]: row["result_sha256"]
                    for row in manifest["producer_results"]  # type: ignore[union-attr]
                },
                "builder_environment_receipt_sha256": manifest[
                    "build_environment"
                ]["builder_environment_receipt_sha256"],  # type: ignore[index]
                "matrix": {
                    f"{row['platform']}/{row['gate_id']}": {
                        "check_contract_sha256": row["check_contract_sha256"],
                        "receipt_sha256": row["receipt_sha256"],
                    }
                    for row in manifest["verification"]["matrix"]  # type: ignore[index]
                },
                "installed_metadata_sha256": manifest["interfaces"][  # type: ignore[index]
                    "installed_metadata_sha256"
                ],
                "reviewed_exception_receipt_sha256": rebuild.get(
                    "review_receipt_sha256"
                ),
            },
            "dependencies": manifest["dependencies"],
            "rebuild_status": rebuild["status"],
        },
        manifest,
    )


@pytest.fixture()
def release_env(monkeypatch: pytest.MonkeyPatch) -> object:
    with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as credentials:
        root = Path(temp)
        root.joinpath("aoi.toml").write_text(default_config_text("Release runtime"), encoding="utf-8")
        paths = h.get_paths(root)
        credential_home = Path(credentials) / "credentials"
        with h.state_lock(paths, create_layout=True):
            h.task_dir(paths, TASK).mkdir(parents=True)
            store.initialize_semantic_task(
                paths,
                {"task_id": TASK, "stage": 0},
                command_id="release-runtime-genesis",
                recorded_at="2026-07-19T12:00:00Z",
                authority_ref="test",
            )
            chief, credential_path = h.acquire_chief_authority(
                paths,
                session_id="release-chief",
                ttl_seconds=3600,
                credential_home=credential_home,
                now=NOW,
            )
        # Production deliberately checks that the Chief lease is live at
        # commit time.  Freeze only that wall-clock observation so these
        # fixed-time transaction vectors remain hermetic after 2026-07-19.
        live_summary = h.chief_authority_summary

        def frozen_summary(
            current_paths: h.HarnessPaths, *, now: datetime | None = None
        ) -> dict[str, object]:
            return live_summary(
                current_paths,
                now=now or NOW.replace(minute=4),
            )

        monkeypatch.setattr(h, "chief_authority_summary", frozen_summary)
        yield {
            "paths": paths,
            "chief": chief,
            "credential_path": credential_path,
            "credential_home": credential_home,
        }


def _prepare(
    env: object,
    manifest: dict[str, object],
    receipt: dict[str, object],
    *,
    command_id: str = "promote-1",
    observation_receipt: dict[str, object] | None = None,
    authority_ref: object | None = None,
) -> dict[str, object]:
    paths = env["paths"]  # type: ignore[index]
    return runtime.prepare_release_promotion_transaction(
        paths,
        TASK,
        manifest,
        observation_receipt or _observation(manifest),
        receipt,
        command_id,
        "2026-07-19T12:01:00Z",
        authority_ref=authority_ref,
    )


def _commit(env: object, tx: dict[str, object]) -> dict[str, object]:
    paths = env["paths"]  # type: ignore[index]
    with h.state_lock(paths, create_layout=False):
        return runtime.commit_release_promotion_transaction(paths, tx)


def _publish_objects_only(env: object, tx: dict[str, object]) -> None:
    paths = env["paths"]  # type: ignore[index]
    with h.state_lock(paths, create_layout=False):
        for wrapped in tx["objects"]:  # type: ignore[index]
            objects.publish_semantic_object(paths, wrapped)


def _publish_pending_binding(env: object, tx: dict[str, object]) -> None:
    paths = env["paths"]  # type: ignore[index]
    with h.state_lock(paths, create_layout=False):
        for wrapped in tx["objects"]:  # type: ignore[index]
            objects.publish_semantic_object(paths, wrapped)
        objects.publish_semantic_binding(
            paths, tx["binding"], store.load_semantic_events(paths, TASK)  # type: ignore[index]
        )


def _legacy_three_object_binding(
    tx: dict[str, object],
) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Model a persisted pre-intent binding; never use this as a new writer."""

    legacy_objects = [
        item
        for item in tx["objects"]  # type: ignore[index]
        if item["object_type"] != "release_promotion_intent"
    ]
    planned = tx["planned_event"]  # type: ignore[index]
    binding = objects.create_semantic_binding(
        binding_kind=runtime.RELEASE_BINDING_KIND,
        task_id=TASK,
        binding_key=tx["binding"]["binding_key"],  # type: ignore[index]
        expected_semantic_head_sha256=planned["prev_event_sha256"],
        planned_event_sha256=planned["event_sha256"],
        result_projection_sha256=planned["result_projection_sha256"],
        object_sha256s=sorted(item["object_sha256"] for item in legacy_objects),
    )
    return legacy_objects, binding


def test_prepare_seals_exact_release_objects_binding_and_event(release_env: object) -> None:
    manifest = _manifest()
    receipt = _receipt(manifest, promotion_id="pypi-0.4.0")
    tx = _prepare(release_env, manifest, receipt)

    assert runtime.validate_release_promotion_transaction(tx) == tx
    assert tx["event_type"] == "release_promoted"
    assert tx["binding"]["binding_kind"] == "release_promotion"
    assert {item["object_type"] for item in tx["objects"]} == {
        "release_manifest",
        "release_observation",
        "release_promotion_intent",
        "promotion_receipt",
    }
    state = tx["result_state"]
    assert "release_promotions" in state
    assert tx["planned_event"]["event_type"] == "release_promoted"
    intent = next(
        item for item in tx["objects"] if item["object_type"] == "release_promotion_intent"
    )
    assert intent["payload"] == {
        "schema_version": 1,
        "command_id": tx["command_id"],
        "recorded_at": tx["recorded_at"],
        "authority_ref": tx["authority_ref"],
        "expected_head_sha256": tx["expected_head_sha256"],
        "result_projection_sha256": tx["planned_event"]["result_projection_sha256"],
        "planned_event_sha256": tx["planned_event"]["event_sha256"],
        "promotion_receipt_sha256": receipt["promotion_receipt_sha256"],
    }


def test_promotion_intent_is_required_and_tamper_evident(release_env: object) -> None:
    manifest = _manifest()
    tx = _prepare(release_env, manifest, _receipt(manifest, promotion_id="intent-contract"))
    missing = copy.deepcopy(tx)
    missing["objects"] = [
        item for item in missing["objects"] if item["object_type"] != "release_promotion_intent"
    ]
    with pytest.raises(runtime.ReleaseRuntimeError, match="object.*count|incomplete"):
        runtime.validate_release_promotion_transaction(missing)
    tampered = copy.deepcopy(tx)
    next(
        item for item in tampered["objects"] if item["object_type"] == "release_promotion_intent"
    )["payload"]["command_id"] = "intent-tampered"
    with pytest.raises(runtime.ReleaseRuntimeError, match="intent|payload|wrapper"):
        runtime.validate_release_promotion_transaction(tampered)


def test_inspect_and_recovery_dual_read_committed_legacy_three_object_binding(
    release_env: object,
) -> None:
    manifest = _manifest()
    receipt = _receipt(manifest, promotion_id="legacy-three-object")
    tx = _prepare(release_env, manifest, receipt)
    legacy_objects, legacy_binding = _legacy_three_object_binding(tx)
    paths = release_env["paths"]  # type: ignore[index]
    with h.state_lock(paths, create_layout=False):
        for wrapped in legacy_objects:
            objects.publish_semantic_object(paths, wrapped)
        objects.publish_semantic_binding(
            paths, legacy_binding, store.load_semantic_events(paths, TASK)
        )
        appended = store.append_semantic_transition(
            paths,
            TASK,
            tx["result_state"],  # type: ignore[index]
            event_type=tx["event_type"],  # type: ignore[index]
            command_id=tx["command_id"],  # type: ignore[index]
            recorded_at=tx["recorded_at"],  # type: ignore[index]
            authority_ref=tx["authority_ref"],  # type: ignore[index]
            expected_head_sha256=tx["expected_head_sha256"],  # type: ignore[index]
        )
    assert appended.event["event_sha256"] == tx["planned_event"]["event_sha256"]  # type: ignore[index]
    assert runtime.inspect_release_runtime(paths, TASK)["promotions"][0]["classification"] == "committed"
    bundle = runtime.recover_committed_promotion_bundle(
        paths,
        TASK,
        manifest,
        _observation(manifest),
        receipt,
        command_id=tx["command_id"],  # type: ignore[index]
        recorded_at=tx["recorded_at"],  # type: ignore[index]
        expected_head_sha256=tx["expected_head_sha256"],  # type: ignore[index]
    )
    assert len(bundle["semantic_binding"]["object_sha256s"]) == 3
    assert runtime.validate_promotion_bundle(bundle) == bundle


def test_legacy_pending_release_binding_fails_without_a_preimage_intent(
    release_env: object,
) -> None:
    manifest = _manifest()
    tx = _prepare(release_env, manifest, _receipt(manifest, promotion_id="legacy-pending"))
    legacy_objects, legacy_binding = _legacy_three_object_binding(tx)
    paths = release_env["paths"]  # type: ignore[index]
    with h.state_lock(paths, create_layout=False):
        for wrapped in legacy_objects:
            objects.publish_semantic_object(paths, wrapped)
        objects.publish_semantic_binding(
            paths, legacy_binding, store.load_semantic_events(paths, TASK)
        )
        with pytest.raises(runtime.ReleaseRuntimeError, match="legacy pending.*preimage intent"):
            runtime.abandon_pending_release_promotion(
                paths,
                TASK,
                binding_sha256=legacy_binding["binding_sha256"],
                expected_head_sha256=tx["expected_head_sha256"],  # type: ignore[index]
                command_id="abandon-legacy-pending",
                recorded_at="2026-07-19T12:03:00Z",
                reason="historical pending binding cannot prove its planned event",
            )
    with pytest.raises(runtime.ReleaseRuntimeError, match="legacy pending.*preimage intent"):
        runtime.inspect_release_runtime(paths, TASK)


def test_commit_is_idempotent_and_inspection_uses_real_semantic_ledger(release_env: object) -> None:
    manifest = _manifest()
    receipt = _receipt(manifest, promotion_id="pypi-0.4.0")
    tx = _prepare(release_env, manifest, receipt)
    first = _commit(release_env, tx)
    second = _commit(release_env, tx)
    paths = release_env["paths"]  # type: ignore[index]

    assert first["idempotent_replay"] is False
    assert second["idempotent_replay"] is True
    events = store.load_semantic_events(paths, TASK)
    assert sum(event["command_id"] == "promote-1" for event in events) == 1
    report = runtime.inspect_release_runtime(paths, TASK)
    assert len(report["promotions"]) == 1
    assert report["promotions"][0]["classification"] == "committed"

    recovered = runtime.recover_committed_promotion_bundle(
        paths,
        TASK,
        manifest,
        _observation(manifest),
        receipt,
        command_id=tx["command_id"],
        recorded_at=tx["recorded_at"],
        expected_head_sha256=tx["expected_head_sha256"],
    )
    assert recovered == runtime.create_promotion_bundle(tx)
    with pytest.raises(runtime.ReleaseRuntimeError, match="recovery command"):
        runtime.recover_committed_promotion_bundle(
            paths,
            TASK,
            manifest,
            _observation(manifest),
            receipt,
            command_id="different-command",
            recorded_at=tx["recorded_at"],
            expected_head_sha256=tx["expected_head_sha256"],
        )


def test_committed_bundle_recovery_repairs_a_behind_projection(release_env: object) -> None:
    manifest = _manifest()
    observation = _observation(manifest)
    receipt = _receipt(manifest, promotion_id="projection-crash")
    tx = _prepare(release_env, manifest, receipt, observation_receipt=observation)
    _commit(release_env, tx)
    paths = release_env["paths"]  # type: ignore[index]
    records = store.load_semantic_events(paths, TASK)
    h.task_state_path(paths, TASK).write_bytes(
        semantic.canonical_json_bytes(semantic.replay_events(records[:-1]))
    )
    assert store.semantic_projection_status(paths, TASK) == "behind"

    recovered = runtime.recover_committed_promotion_bundle(
        paths,
        TASK,
        manifest,
        observation,
        receipt,
        command_id=tx["command_id"],
        recorded_at=tx["recorded_at"],
        expected_head_sha256=tx["expected_head_sha256"],
    )
    assert recovered == runtime.create_promotion_bundle(tx)
    assert store.semantic_projection_status(paths, TASK) == "current"


def test_object_only_and_binding_only_crashes_recover(release_env: object) -> None:
    manifest = _manifest()
    objects_only = _prepare(release_env, manifest, _receipt(manifest, promotion_id="objects-only"))
    _publish_objects_only(release_env, objects_only)
    assert _commit(release_env, objects_only)["idempotent_replay"] is False

    manifest_two = _manifest(version="0.4.1", commit_oid="e" * 40)
    binding_only = _prepare(
        release_env, manifest_two, _receipt(manifest_two, promotion_id="binding-only"), command_id="promote-2"
    )
    _publish_pending_binding(release_env, binding_only)
    assert _commit(release_env, binding_only)["idempotent_replay"] is False


def test_binding_only_retry_fails_closed_after_chief_takeover(
    release_env: object,
) -> None:
    manifest = _manifest()
    tx = _prepare(
        release_env,
        manifest,
        _receipt(manifest, promotion_id="takeover-pending"),
    )
    _publish_pending_binding(release_env, tx)
    paths = release_env["paths"]  # type: ignore[index]
    with h.state_lock(paths, create_layout=False):
        h.takeover_chief_authority(
            paths,
            session_id="replacement-chief",
            expected_epoch=release_env["chief"]["epoch"],  # type: ignore[index]
            reason="exercise pending promotion takeover fence",
            force_live=True,
            credential_home=release_env["credential_home"],  # type: ignore[index]
            now=NOW.replace(minute=2),
        )
    with pytest.raises(runtime.ReleaseRuntimeError, match="current Chief"):
        _commit(release_env, tx)


def test_successor_abandons_pending_release_without_rewriting_history(
    release_env: object,
) -> None:
    manifest = _manifest()
    tx = _prepare(
        release_env,
        manifest,
        _receipt(manifest, promotion_id="takeover-abandon"),
    )
    _publish_pending_binding(release_env, tx)
    paths = release_env["paths"]  # type: ignore[index]
    with h.state_lock(paths, create_layout=False):
        replacement, _credential = h.takeover_chief_authority(
            paths,
            session_id=release_env["chief"]["session_id"],  # type: ignore[index]
            expected_epoch=release_env["chief"]["epoch"],  # type: ignore[index]
            reason="recover binding-only release publication",
            force_live=True,
            credential_home=release_env["credential_home"],  # type: ignore[index]
            now=NOW.replace(minute=2),
        )
        receipt = runtime.abandon_pending_release_promotion(
            paths,
            TASK,
            binding_sha256=tx["binding"]["binding_sha256"],  # type: ignore[index]
            expected_head_sha256=tx["expected_head_sha256"],
            command_id="abandon-promote-1",
            recorded_at="2026-07-19T12:03:00Z",
            reason="binding-only publication belongs to the retired Chief",
            authority_ref={
                "session_id": replacement["session_id"],
                "epoch": replacement["epoch"],
            },
        )
        replay = runtime.abandon_pending_release_promotion(
            paths,
            TASK,
            binding_sha256=tx["binding"]["binding_sha256"],  # type: ignore[index]
            expected_head_sha256=tx["expected_head_sha256"],
            command_id="abandon-promote-1",
            recorded_at="2026-07-19T12:03:00Z",
            reason="binding-only publication belongs to the retired Chief",
            authority_ref={
                "session_id": replacement["session_id"],
                "epoch": replacement["epoch"],
            },
        )
    assert runtime.validate_release_abandonment_receipt(receipt) == receipt
    assert replay == receipt
    events = store.load_semantic_events(paths, TASK)
    assert sum(event["event_type"] == "release_promotion_abandoned" for event in events) == 1
    report = runtime.inspect_release_runtime(paths, TASK)
    assert report["namespace"]["promotions"] == {}
    assert report["pending_binding_sha256s"] == []
    assert report["abandoned_binding_sha256s"] == [
        tx["binding"]["binding_sha256"]  # type: ignore[index]
    ]
    assert report["orphan_release_object_sha256s"] == []
    assert report["promotions"][0]["classification"] == "abandoned"
    with pytest.raises(runtime.ReleaseRuntimeError, match="abandoned"):
        _commit(release_env, tx)

    successor_receipt = _receipt(manifest, promotion_id="after-abandon")
    successor = runtime.prepare_release_promotion_transaction(
        paths,
        TASK,
        manifest,
        _observation(manifest),
        successor_receipt,
        "promote-after-abandon",
        "2026-07-19T12:04:00Z",
        authority_ref={
            "session_id": replacement["session_id"],
            "epoch": replacement["epoch"],
        },
    )
    with h.state_lock(paths, create_layout=False):
        committed = runtime.commit_release_promotion_transaction(paths, successor)
    assert committed["release_report"]["active_promotion_receipt_sha256"] == (
        successor_receipt["promotion_receipt_sha256"]
    )


def test_abandonment_survives_audit_tail_rollover_release_acquire_and_projection_crash(
    release_env: object,
) -> None:
    """The v2 proof stays bounded even after its origin has left the audit tail."""

    manifest = _manifest()
    tx = _prepare(
        release_env, manifest, _receipt(manifest, promotion_id="long-retirement")
    )
    _publish_pending_binding(release_env, tx)
    paths = release_env["paths"]  # type: ignore[index]
    original = release_env["chief"]  # type: ignore[index]
    with h.state_lock(paths, create_layout=False):
        token, _ = h.load_chief_credential(
            paths,
            session_id=original["session_id"],
            epoch=original["epoch"],
            credential_file=release_env["credential_path"],  # type: ignore[index]
        )
        current = original
        for offset in range(h.CHIEF_AUDIT_TAIL_MAX + 1):
            current = h.renew_chief_authority(
                paths,
                session_id=current["session_id"],
                epoch=current["epoch"],
                token=token,
                now=NOW.replace(minute=0, second=offset + 1),
            )
        h.release_chief_authority(
            paths,
            session_id=current["session_id"],
            epoch=current["epoch"],
            token=token,
            reason="exercise release acquire retirement path",
            now=NOW.replace(minute=2, second=0),
        )
        acquired, _ = h.acquire_chief_authority(
            paths,
            session_id="acquired-successor",
            credential_home=release_env["credential_home"],  # type: ignore[index]
            now=NOW.replace(minute=2, second=1),
        )
        successor, _ = h.takeover_chief_authority(
            paths,
            session_id="final-successor",
            expected_epoch=acquired["epoch"],
            reason="exercise multiple successor epochs",
            force_live=True,
            credential_home=release_env["credential_home"],  # type: ignore[index]
            now=NOW.replace(minute=2, second=2),
        )
        chief_record = h.load_chief_authority(paths)
        assert chief_record["omitted_transition_count"] > 0
        assert len(chief_record["audit_tail"]) == h.CHIEF_AUDIT_TAIL_MAX
        receipt = runtime.abandon_pending_release_promotion(
            paths,
            TASK,
            binding_sha256=tx["binding"]["binding_sha256"],  # type: ignore[index]
            expected_head_sha256=tx["expected_head_sha256"],
            command_id="abandon-long-retirement",
            recorded_at="2026-07-19T12:03:00Z",
            reason="retire a binding after the original Chief history rolled over",
            authority_ref={"session_id": successor["session_id"], "epoch": successor["epoch"]},
        )
    assert receipt["schema_version"] == 2
    proof = receipt["abandonment"]["retirement_proof"]
    assert set(proof) == {
        "proof_kind",
        "successor_session_id",
        "successor_epoch",
        "issued_at",
        "expires_at",
        "current_authority_record_sha256",
    }
    assert proof["successor_epoch"] > original["epoch"]
    assert "audit_tail" not in json.dumps(proof, sort_keys=True)

    # A later unrelated semantic transition must not make the terminal receipt
    # unrecoverable; retry is keyed to the sealed disposition, not current head.
    with h.state_lock(paths, create_layout=False):
        records = store.load_semantic_events(paths, TASK)
        state = semantic.projection_domain(semantic.replay_events(records))
        state["after_release_abandonment"] = "advanced"
        store.append_semantic_transition(
            paths,
            TASK,
            state,
            event_type="unrelated_test",
            command_id="advance-after-abandonment",
            recorded_at="2026-07-19T12:03:30Z",
            authority_ref="test",
            expected_head_sha256=records[-1]["event_sha256"],
        )
    records = store.load_semantic_events(paths, TASK)
    h.task_state_path(paths, TASK).write_bytes(
        semantic.canonical_json_bytes(semantic.replay_events(records[:-1]))
    )
    assert store.semantic_projection_status(paths, TASK) == "behind"
    with h.state_lock(paths, create_layout=False):
        replay = runtime.abandon_pending_release_promotion(
            paths,
            TASK,
            binding_sha256=tx["binding"]["binding_sha256"],  # type: ignore[index]
            expected_head_sha256=tx["expected_head_sha256"],
            command_id="abandon-long-retirement",
            recorded_at="2026-07-19T12:03:00Z",
            reason="retire a binding after the original Chief history rolled over",
            authority_ref={"session_id": successor["session_id"], "epoch": successor["epoch"]},
        )
    assert replay == receipt
    assert store.semantic_projection_status(paths, TASK) == "current"


def test_promotion_requires_the_exact_artifact_observation(
    release_env: object,
) -> None:
    manifest = _manifest()
    receipt = _receipt(manifest, promotion_id="observed-only")
    other_manifest = _manifest(version="0.4.1", commit_oid="e" * 40)
    with pytest.raises(runtime.ReleaseRuntimeError, match="observation|manifest"):
        _prepare(
            release_env,
            manifest,
            receipt,
            observation_receipt=_observation(other_manifest),
        )

    tampered = _observation(manifest)
    tampered["observation_receipt_sha256"] = "0" * 64
    with pytest.raises(runtime.ReleaseRuntimeError, match="observation"):
        _prepare(
            release_env,
            manifest,
            receipt,
            observation_receipt=tampered,
        )


def test_expected_head_race_rejects_a_new_promotion(release_env: object) -> None:
    manifest = _manifest()
    tx = _prepare(release_env, manifest, _receipt(manifest, promotion_id="stale"))
    paths = release_env["paths"]  # type: ignore[index]
    with h.state_lock(paths, create_layout=False):
        events = store.load_semantic_events(paths, TASK)
        state = semantic.projection_domain(semantic.replay_events(events))
        state["unrelated"] = "advanced"
        store.append_semantic_transition(
            paths,
            TASK,
            state,
            event_type="unrelated_test",
            command_id="advance-head",
            recorded_at="2026-07-19T12:02:00Z",
            authority_ref="test",
            expected_head_sha256=events[-1]["event_sha256"],
        )
    with pytest.raises(runtime.ReleaseRuntimeError, match="head|current|stale"):
        _commit(release_env, tx)


@pytest.mark.parametrize("damage", ["object", "binding", "event", "projection"])
def test_missing_or_tampered_release_artifacts_fail_closed(release_env: object, damage: str) -> None:
    manifest = _manifest()
    tx = _prepare(release_env, manifest, _receipt(manifest, promotion_id=f"damage-{damage}"))
    paths = release_env["paths"]  # type: ignore[index]
    _publish_pending_binding(release_env, tx)
    if damage == "object":
        objects.semantic_object_path(paths, TASK, tx["objects"][0]["object_sha256"]).unlink()
    elif damage == "binding":
        path = objects.semantic_binding_path(paths, TASK, "release_promotion", tx["binding"]["binding_key"])
        value = json.loads(path.read_text(encoding="utf-8"))
        value["planned_event_sha256"] = "f" * 64
        path.write_bytes(semantic.canonical_json_bytes(value))
    elif damage == "event":
        with h.state_lock(paths, create_layout=False):
            store.append_semantic_transition(
                paths,
                TASK,
                tx["result_state"],
                event_type="release_promoted",
                command_id=tx["command_id"],
                recorded_at=tx["recorded_at"],
                authority_ref=tx["authority_ref"],
                expected_head_sha256=tx["expected_head_sha256"],
            )
        event_path = store.semantic_event_directory(paths, TASK) / semantic.event_filename(2)
        value = json.loads(event_path.read_text(encoding="utf-8"))
        value["command_id"] = "tampered-event"
        event_path.write_bytes(semantic.canonical_json_bytes(value))
    else:
        h.task_state_path(paths, TASK).write_bytes(semantic.canonical_json_bytes({"wrong": "projection"}))
    with pytest.raises((runtime.ReleaseRuntimeError, store.SemanticStoreError, objects.SemanticObjectError)):
        runtime.inspect_release_runtime(paths, TASK)


def test_dependencies_must_already_be_promoted_and_exactly_match(release_env: object) -> None:
    dependency = _manifest(name="aoi-core", version="1.0.0")
    dependency_receipt = _receipt(dependency, promotion_id="aoi-core-1.0.0")
    dependent = _manifest(
        dependencies=[
            {
                "name": "aoi-core",
                "release_manifest_sha256": dependency["manifest_sha256"],
                "promotion_receipt_sha256": dependency_receipt["promotion_receipt_sha256"],
            }
        ]
    )
    dependent_receipt = _receipt(dependent, promotion_id="dependent-1")
    with pytest.raises(runtime.ReleaseRuntimeError, match="depend|promot"):
        _prepare(release_env, dependent, dependent_receipt)

    _commit(release_env, _prepare(release_env, dependency, dependency_receipt, command_id="promote-dependency"))
    _commit(release_env, _prepare(release_env, dependent, dependent_receipt, command_id="promote-dependent"))

    wrong_name = copy.deepcopy(dependent)
    wrong_name["dependencies"][0]["name"] = "other-core"
    wrong_name = manifests.seal_release_manifest({key: value for key, value in wrong_name.items() if key != "manifest_sha256"})
    with pytest.raises(runtime.ReleaseRuntimeError, match="depend|name|match"):
        _prepare(release_env, wrong_name, _receipt(wrong_name, promotion_id="wrong-name"), command_id="wrong-name")


def test_promotion_id_and_receipt_are_single_assignment(release_env: object) -> None:
    first_manifest = _manifest()
    first_receipt = _receipt(first_manifest, promotion_id="same-id")
    _commit(release_env, _prepare(release_env, first_manifest, first_receipt))
    second_manifest = _manifest(version="0.4.1", commit_oid="e" * 40)
    with pytest.raises(runtime.ReleaseRuntimeError, match="promotion.*id|unique|exists"):
        _prepare(release_env, second_manifest, _receipt(second_manifest, promotion_id="same-id"), command_id="same-id-2")
    with pytest.raises(runtime.ReleaseRuntimeError, match="receipt|unique|exists"):
        _prepare(release_env, first_manifest, first_receipt, command_id="same-receipt")


def test_commit_requires_current_chief_authority(release_env: object) -> None:
    manifest = _manifest()
    tx = _prepare(
        release_env,
        manifest,
        _receipt(manifest, promotion_id="wrong-chief"),
        authority_ref={"session_id": "other-chief", "epoch": 99},
    )
    with pytest.raises(runtime.ReleaseRuntimeError, match="Chief|authority"):
        _commit(release_env, tx)


def test_rollback_current_prior_compensating_noop_and_fork_rules(release_env: object) -> None:
    previous_manifest = _manifest(version="0.3.9", commit_oid="9" * 40)
    previous_receipt = _receipt(previous_manifest, promotion_id="previous")
    _commit(release_env, _prepare(release_env, previous_manifest, previous_receipt, command_id="previous"))

    current_manifest = _manifest()
    current_receipt = _receipt(current_manifest, promotion_id="current")
    _commit(release_env, _prepare(release_env, current_manifest, current_receipt, command_id="current"))

    rollback = _receipt(
        previous_manifest,
        promotion_id="rollback-prior",
        rollback_provenance={
            "from_promotion_receipt_sha256": current_receipt["promotion_receipt_sha256"],
            "mode": "prior_manifest",
            "target_promotion_receipt_sha256": previous_receipt["promotion_receipt_sha256"],
            "compensating_manifest_sha256": previous_manifest["manifest_sha256"],
            "reason": "return to known release",
        },
    )
    _commit(release_env, _prepare(release_env, previous_manifest, rollback, command_id="rollback-prior"))

    compensating_manifest = _manifest(version="0.4.2", commit_oid="2" * 40)
    compensating = _receipt(
        compensating_manifest,
        promotion_id="compensating",
        rollback_provenance={
            "from_promotion_receipt_sha256": rollback["promotion_receipt_sha256"],
            "mode": "compensating_release",
            "target_promotion_receipt_sha256": None,
            "compensating_manifest_sha256": compensating_manifest["manifest_sha256"],
            "reason": "repair current release",
        },
    )
    compensating_tx = _prepare(
        release_env,
        compensating_manifest,
        compensating,
        command_id="compensating",
    )
    _commit(release_env, compensating_tx)
    assert _commit(release_env, compensating_tx)["idempotent_replay"] is True

    fork = _receipt(
        current_manifest,
        promotion_id="fork",
        rollback_provenance={
            "from_promotion_receipt_sha256": current_receipt["promotion_receipt_sha256"],
            "mode": "prior_manifest",
            "target_promotion_receipt_sha256": previous_receipt["promotion_receipt_sha256"],
            "compensating_manifest_sha256": current_manifest["manifest_sha256"],
            "reason": "must not fork history",
        },
    )
    with pytest.raises(runtime.ReleaseRuntimeError, match="rollback|current|fork|prior"):
        _prepare(release_env, current_manifest, fork, command_id="fork")


def test_bundle_is_self_authenticating_and_expected_digest_is_enforced(release_env: object) -> None:
    manifest = _manifest()
    tx = _prepare(release_env, manifest, _receipt(manifest, promotion_id="bundle"))
    bundle = runtime.create_promotion_bundle(tx)
    assert bundle["proof_scope"] == "release_namespace_delta_only"
    assert "transaction" not in bundle
    assert "result_state" not in json.dumps(bundle, sort_keys=True)
    assert bundle["observation_receipt"]["observation_receipt_sha256"] == (
        _observation(manifest)["observation_receipt_sha256"]
    )
    assert runtime.validate_promotion_bundle(bundle) == bundle
    assert runtime.validate_promotion_bundle(bundle, bundle["bundle_sha256"]) == bundle
    with pytest.raises(runtime.ReleaseRuntimeError, match="SHA|digest|bundle"):
        runtime.validate_promotion_bundle(bundle, "f" * 64)
    tampered = copy.deepcopy(bundle)
    tampered["semantic_event"]["command_id"] = "tampered"
    with pytest.raises(runtime.ReleaseRuntimeError):
        runtime.validate_promotion_bundle(tampered)
    tampered_observation = copy.deepcopy(bundle)
    tampered_observation["observation_receipt"][
        "observation_receipt_sha256"
    ] = "0" * 64
    with pytest.raises(runtime.ReleaseRuntimeError, match="observation|bundle"):
        runtime.validate_promotion_bundle(tampered_observation)
    wrong_scope = copy.deepcopy(bundle)
    wrong_scope["proof_scope"] = "full_task_projection"
    with pytest.raises(runtime.ReleaseRuntimeError, match="proof scope"):
        runtime.validate_promotion_bundle(wrong_scope)


def test_release_promotion_namespace_injection_fails_closed(release_env: object) -> None:
    manifest = _manifest()
    tx = _prepare(release_env, manifest, _receipt(manifest, promotion_id="injection"))
    injected = copy.deepcopy(tx)
    injected["result_state"]["release_promotions"]["injected"] = {"not": "authorized"}
    with pytest.raises(runtime.ReleaseRuntimeError, match="namespace|promotion|projection"):
        runtime.validate_release_promotion_transaction(injected)


def test_promotion_follows_registry_install_and_chief_lease(
    release_env: object,
) -> None:
    manifest = _manifest()
    future = _receipt(
        manifest,
        promotion_id="future-observation",
        installed_observed_at="2026-07-19T12:02:00.000000Z",
    )
    with pytest.raises(runtime.ReleaseRuntimeError, match="follow registry"):
        _prepare(release_env, manifest, future)

    early = _receipt(
        manifest,
        promotion_id="before-chief",
        registry_observed_at="2026-07-19T11:58:00.000000Z",
        installed_observed_at="2026-07-19T11:58:30.000000Z",
    )
    paths = release_env["paths"]  # type: ignore[index]
    tx = runtime.prepare_release_promotion_transaction(
        paths,
        TASK,
        manifest,
        _observation(manifest),
        early,
        "before-chief",
        "2026-07-19T11:59:00Z",
    )
    with pytest.raises(runtime.ReleaseRuntimeError, match="current Chief"):
        _commit(release_env, tx)
