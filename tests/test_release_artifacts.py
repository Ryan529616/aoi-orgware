from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from aoi_orgware import release_artifacts as artifacts_module
from aoi_orgware.release_artifacts import (
    ReleaseArtifactError,
    observe_release_artifacts,
    validate_release_observation_receipt,
)
from aoi_orgware.release_manifest import seal_promotion_receipt, seal_release_manifest
from aoi_orgware import release_manifest as manifest_module


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _builder_receipt(**changes: object) -> bytes:
    value: dict[str, object] = {
        "schema_version": 1,
        "platform": "linux",
        "python_version": "3.13",
        "workflow_name": "release",
        "run_id": "run-1",
        "run_attempt": 1,
        "runner_os": "Linux",
        "runner_arch": "X64",
        "runner_image": "ubuntu-24.04",
        "build_frontend": "build",
        "build_frontend_version": "1.5.0",
        "source_date_epoch": 1,
    }
    value.update(changes)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _write(root: Path, name: str, data: bytes) -> dict[str, str]:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"path": name, "sha256": _sha(data)}


def _git(worktree: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(worktree), *args], text=True, capture_output=True, check=True)
    return result.stdout.strip()


def _manifest(*, artifact: dict[str, object], commit: str, tree: str, dependencies: list[dict[str, str]]) -> dict[str, object]:
    digest = str(artifact["sha256"])
    size = int(artifact["size_bytes"])
    return seal_release_manifest({
        "schema_version": 1,
        "distribution_name": "aoi-orgware",
        "tag": "v0.4.0",
        "git_object_format": "sha1",
        "commit_oid": commit,
        "tree_oid": tree,
        "package_version": "0.4.0",
        "build_environment": {"platform": "linux", "python_version": "3.13", "builder_environment_receipt_sha256": _sha(_builder_receipt())},
        "workflow": {"workflow_name": "release", "run_id": "run-1", "run_attempt": 1},
        "artifacts": [dict(artifact)],
        "producer_results": [{"producer_id": "build-linux", "result_sha256": _sha(b"producer")}],
        "interfaces": {"console_entry_point": {"name": "aoi", "target": "aoi_orgware.cli:main"}, "codex_hook_entry_point": {"name": "aoi-codex-hook", "target": "aoi_orgware.codex_hook:main"}, "hook_protocol_version": 6, "installed_metadata_sha256": _sha(b"metadata")},
        "schema_versions": {"packet": 6},
        "dependencies": dependencies,
        "verification": {
            "matrix": [
                {"platform": "linux", "gate_id": "unit", "check_contract_sha256": _sha(b"contract"), "receipt_sha256": _sha(b"linux"), "status": "pass"},
                {"platform": "windows", "gate_id": "unit", "check_contract_sha256": _sha(b"contract"), "receipt_sha256": _sha(b"windows"), "status": "pass"},
            ],
            "tested_artifacts": [dict(artifact)],
            "rebuild": {"status": "reproducible", "artifacts": [dict(artifact)]},
        },
        "sbom": {"location": "meta/sbom.json", "sha256": _sha(b"sbom")},
        "attestation": {"location": "meta/attestation.json", "sha256": _sha(b"attestation")},
    })


def _dependency_pair(root: Path) -> tuple[dict[str, str], dict[str, str]]:
    artifact = {"name": "dep.whl", "size_bytes": 1, "sha256": "b" * 64}
    dependency = seal_release_manifest({
        "schema_version": 1, "distribution_name": "aoi-core", "tag": "v1.0.0", "git_object_format": "sha1",
        "commit_oid": "c" * 40, "tree_oid": "d" * 40, "package_version": "1.0.0",
        "build_environment": {"platform": "linux", "python_version": "3.13", "builder_environment_receipt_sha256": "7" * 64},
        "workflow": {"workflow_name": "release", "run_id": "dep-1", "run_attempt": 1}, "artifacts": [dict(artifact)],
        "producer_results": [{"producer_id": "dep-build", "result_sha256": "e" * 64}],
        "interfaces": {"console_entry_point": {"name": "aoi-core", "target": "aoi_core.cli:main"}, "codex_hook_entry_point": {"name": "aoi-core-codex-hook", "target": "aoi_core.codex_hook:main"}, "hook_protocol_version": 6, "installed_metadata_sha256": "f" * 64},
        "schema_versions": {"packet": 6}, "dependencies": [],
        "verification": {"matrix": [
            {"platform": "linux", "gate_id": "unit", "check_contract_sha256": "1" * 64, "receipt_sha256": "2" * 64, "status": "pass"},
            {"platform": "windows", "gate_id": "unit", "check_contract_sha256": "1" * 64, "receipt_sha256": "3" * 64, "status": "pass"},
        ], "tested_artifacts": [dict(artifact)], "rebuild": {"status": "reproducible", "artifacts": [dict(artifact)]}},
        "sbom": {"location": "dep-sbom.json", "sha256": "4" * 64}, "attestation": {"location": "dep-attestation.json", "sha256": "5" * 64},
    })
    promotion = seal_promotion_receipt({
        "schema_version": 1, "promotion_id": "dep-pypi", "manifest_sha256": dependency["manifest_sha256"],
        "artifact_observation_receipt_sha256": "6" * 64,
        "registry_readback": {"registry": "https://pypi.org", "project": "aoi-core", "package_version": "1.0.0", "observed_at": "2026-07-19T00:00:00.000000Z", "artifacts": [dict(artifact)]},
        "installed": {"distribution_name": "aoi-core", "package_version": "1.0.0", "observed_at": "2026-07-19T00:00:01.000000Z", "installed_metadata_sha256": "f" * 64, "console_entry_point": {"name": "aoi-core", "target": "aoi_core.cli:main"}, "codex_hook_entry_point": {"name": "aoi-core-codex-hook", "target": "aoi_core.codex_hook:main"}, "hook_protocol_version": 6},
        "dependency_promotions": [], "rollback_provenance": None,
    }, dependency)
    _write(root, "deps/manifest.json", json.dumps(dependency, sort_keys=True, separators=(",", ":")).encode())
    _write(root, "deps/promotion.json", json.dumps(promotion, sort_keys=True, separators=(",", ":")).encode())
    return (
        {"name": "aoi-core", "release_manifest_sha256": dependency["manifest_sha256"], "promotion_receipt_sha256": promotion["promotion_receipt_sha256"]},
        {"aoi-core": {"release_manifest_path": "deps/manifest.json", "promotion_receipt_path": "deps/promotion.json"}},
    )


@pytest.fixture
def observation(tmp_path: Path) -> dict[str, object]:
    root = tmp_path / "artifacts"
    rebuilt = tmp_path / "rebuilt"
    worktree = tmp_path / "worktree"
    root.mkdir(); rebuilt.mkdir(); worktree.mkdir()
    (worktree / "src/aoi_orgware").mkdir(parents=True)
    (worktree / "src/aoi_orgware/_version.py").write_text('__version__ = "0.4.0"\n', encoding="utf-8")
    _git(worktree, "init"); _git(worktree, "config", "user.email", "test@example.invalid"); _git(worktree, "config", "user.name", "Test")
    _git(worktree, "add", "."); _git(worktree, "commit", "-m", "release"); _git(worktree, "tag", "v0.4.0")
    artifact_data = b"wheel bytes\n"
    artifact = {"name": "dist/aoi_orgware-0.4.0.whl", "size_bytes": len(artifact_data), "sha256": _sha(artifact_data)}
    _write(root, artifact["name"], artifact_data); _write(rebuilt, artifact["name"], artifact_data)
    _write(root, "meta/sbom.json", b"sbom"); _write(root, "meta/attestation.json", b"attestation")
    dependency, dependency_files = _dependency_pair(root)
    manifest = _manifest(artifact=artifact, commit=_git(worktree, "rev-parse", "HEAD"), tree=_git(worktree, "rev-parse", "HEAD^{tree}"), dependencies=[dependency])
    evidence = {
        "producer_results": {"build-linux": _write(root, "evidence/producer.json", b"producer")},
        "builder_environment": _write(root, "evidence/builder.json", _builder_receipt()),
        "matrix": {
            "linux/unit": {"check_contract": _write(root, "evidence/contract.json", b"contract"), "receipt": _write(root, "evidence/linux.json", b"linux")},
            "windows/unit": {"check_contract": _write(root, "evidence/contract-win.json", b"contract"), "receipt": _write(root, "evidence/windows.json", b"windows")},
        },
        "installed_metadata": _write(root, "evidence/installed.json", b"metadata"),
        "reviewed_exception_receipt": None,
    }
    return {"schema_version": 1, "manifest": manifest, "worktree": str(worktree), "artifact_root": str(root), "rebuild_root": str(rebuilt), "evidence_files": evidence, "dependency_files": dependency_files}


def test_observe_and_seal_exact_release(observation: dict[str, object]) -> None:
    result = observe_release_artifacts(observation)
    assert result["manifest"] == observation["manifest"]
    receipt = result["observation_receipt"]
    assert receipt["git"]["git_object_format"] == "sha1"  # type: ignore[index]
    assert len(receipt["observation_receipt_sha256"]) == 64  # type: ignore[index]
    assert validate_release_observation_receipt(
        receipt, result["manifest"]
    ) == receipt
    tampered = copy.deepcopy(receipt)
    tampered["artifacts"][0]["size_bytes"] += 1  # type: ignore[index]
    with pytest.raises(ReleaseArtifactError, match="artifacts|SHA-256"):
        validate_release_observation_receipt(tampered, result["manifest"])


def test_artifact_replacement_and_rebuild_substitution_fail(observation: dict[str, object]) -> None:
    root = Path(str(observation["artifact_root"])); rebuilt = Path(str(observation["rebuild_root"]))
    (root / "dist/aoi_orgware-0.4.0.whl").write_bytes(b"replacement")
    with pytest.raises(ReleaseArtifactError, match="artifact bytes"):
        observe_release_artifacts(observation)
    (root / "dist/aoi_orgware-0.4.0.whl").write_bytes(b"wheel bytes\n")
    (rebuilt / "dist/aoi_orgware-0.4.0.whl").write_bytes(b"replacement")
    with pytest.raises(ReleaseArtifactError, match="rebuild artifact"):
        observe_release_artifacts(observation)


def test_tag_tree_mismatch_and_source_version_fail(observation: dict[str, object]) -> None:
    changed = copy.deepcopy(observation)
    changed["manifest"]["tree_oid"] = "0" * 40  # type: ignore[index]
    changed["manifest"].pop("manifest_sha256")  # type: ignore[index]
    changed["manifest"] = seal_release_manifest(changed["manifest"])  # type: ignore[index]
    with pytest.raises(ReleaseArtifactError, match="Git HEAD, tree, or tag"):
        observe_release_artifacts(changed)
    worktree = Path(str(observation["worktree"]))
    (worktree / "src/aoi_orgware/_version.py").write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    with pytest.raises(ReleaseArtifactError, match="worktree must be clean"):
        observe_release_artifacts(observation)
    _git(worktree, "add", ".")
    _git(worktree, "commit", "-m", "wrong source version")
    _git(worktree, "tag", "-f", "v0.4.0")
    wrong_version = copy.deepcopy(observation)
    wrong_version["manifest"]["commit_oid"] = _git(worktree, "rev-parse", "HEAD")  # type: ignore[index]
    wrong_version["manifest"]["tree_oid"] = _git(worktree, "rev-parse", "HEAD^{tree}")  # type: ignore[index]
    wrong_version["manifest"].pop("manifest_sha256")  # type: ignore[index]
    wrong_version["manifest"] = seal_release_manifest(wrong_version["manifest"])  # type: ignore[index]
    with pytest.raises(ReleaseArtifactError, match="source _version"):
        observe_release_artifacts(wrong_version)


def test_git_ref_movement_during_observation_fails_closed(
    observation: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    original_run = subprocess.run
    moved = False

    def racing_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
        nonlocal moved
        result = original_run(*args, **kwargs)  # type: ignore[arg-type]
        command = args[0] if args else None
        if (
            not moved
            and isinstance(command, list)
            and command[-2:] == ["rev-parse", "HEAD^{tree}"]
        ):
            moved = True
            worktree = Path(str(observation["worktree"]))
            original_run(
                ["git", "-C", str(worktree), "commit", "--allow-empty", "-m", "move head"],
                check=True,
                capture_output=True,
            )
        return result

    monkeypatch.setattr(artifacts_module.subprocess, "run", racing_run)
    with pytest.raises(ReleaseArtifactError, match="Git refs changed"):
        observe_release_artifacts(observation)


def test_manifest_and_observer_artifact_bounds_are_compatible() -> None:
    assert (
        artifacts_module.MAX_OBSERVED_FILE_BYTES
        >= manifest_module.MAX_ARTIFACT_BYTES
    )
    assert artifacts_module.MAX_OBSERVED_TOTAL_BYTES > (
        4 * manifest_module.MAX_ARTIFACT_AGGREGATE_BYTES
    )


def test_missing_extra_evidence_and_path_escape_fail(observation: dict[str, object]) -> None:
    missing = copy.deepcopy(observation); del missing["evidence_files"]["matrix"]["windows/unit"]  # type: ignore[index]
    with pytest.raises(ReleaseArtifactError, match="matrix evidence"):
        observe_release_artifacts(missing)
    extra = copy.deepcopy(observation); extra["evidence_files"]["producer_results"]["extra"] = {"path": "x", "sha256": "a" * 64}  # type: ignore[index]
    with pytest.raises(ReleaseArtifactError, match="producer evidence"):
        observe_release_artifacts(extra)
    escape = copy.deepcopy(observation); escape["evidence_files"]["installed_metadata"]["path"] = "../escape"  # type: ignore[index]
    with pytest.raises(ReleaseArtifactError, match="safe relative"):
        observe_release_artifacts(escape)


def test_builder_environment_receipt_is_canonical_and_cross_bound(
    observation: dict[str, object],
) -> None:
    root = Path(str(observation["artifact_root"]))
    path = root / "evidence/builder.json"
    changed_bytes = _builder_receipt(platform="other-linux")
    path.write_bytes(changed_bytes)
    changed = copy.deepcopy(observation)
    changed["manifest"]["build_environment"][  # type: ignore[index]
        "builder_environment_receipt_sha256"
    ] = _sha(changed_bytes)
    changed["manifest"].pop("manifest_sha256")  # type: ignore[union-attr]
    changed["manifest"] = seal_release_manifest(changed["manifest"])  # type: ignore[arg-type]
    changed["evidence_files"]["builder_environment"]["sha256"] = _sha(  # type: ignore[index]
        changed_bytes
    )
    with pytest.raises(ReleaseArtifactError, match="builder environment.*manifest"):
        observe_release_artifacts(changed)

    pretty = json.dumps(
        json.loads(_builder_receipt()), indent=2, ensure_ascii=False
    ).encode("utf-8")
    path.write_bytes(pretty)
    noncanonical = copy.deepcopy(observation)
    noncanonical["manifest"]["build_environment"][  # type: ignore[index]
        "builder_environment_receipt_sha256"
    ] = _sha(pretty)
    noncanonical["manifest"].pop("manifest_sha256")  # type: ignore[union-attr]
    noncanonical["manifest"] = seal_release_manifest(  # type: ignore[arg-type]
        noncanonical["manifest"]
    )
    noncanonical["evidence_files"]["builder_environment"][  # type: ignore[index]
        "sha256"
    ] = _sha(pretty)
    with pytest.raises(ReleaseArtifactError, match="canonical JSON"):
        observe_release_artifacts(noncanonical)


def test_dependency_pair_mismatch_fails(observation: dict[str, object]) -> None:
    root = Path(str(observation["artifact_root"]))
    (root / "deps/promotion.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ReleaseArtifactError, match="dependency"):
        observe_release_artifacts(observation)


def test_dependency_files_require_canonical_json_and_exact_distribution(
    observation: dict[str, object],
) -> None:
    root = Path(str(observation["artifact_root"]))
    promotion_path = root / "deps/promotion.json"
    raw = promotion_path.read_text(encoding="utf-8")
    promotion_path.write_text(
        raw[:-1] + ',"schema_version":1}', encoding="utf-8"
    )
    with pytest.raises(ReleaseArtifactError, match="duplicate key|canonical JSON"):
        observe_release_artifacts(observation)

    promotion_path.write_text(raw, encoding="utf-8")
    changed = copy.deepcopy(observation)
    dependency = changed["manifest"]["dependencies"][0]  # type: ignore[index]
    dependency["name"] = "other-core"
    changed["manifest"].pop("manifest_sha256")  # type: ignore[index]
    changed["manifest"] = seal_release_manifest(changed["manifest"])  # type: ignore[index]
    changed["dependency_files"] = {
        "other-core": changed["dependency_files"]["aoi-core"]  # type: ignore[index]
    }
    with pytest.raises(ReleaseArtifactError, match="sealed pair"):
        observe_release_artifacts(changed)


def test_windows_unsafe_evidence_path_is_rejected(
    observation: dict[str, object],
) -> None:
    changed = copy.deepcopy(observation)
    changed["evidence_files"]["installed_metadata"]["path"] = "CON"  # type: ignore[index]
    with pytest.raises(ReleaseArtifactError, match="safe relative"):
        observe_release_artifacts(changed)


def test_link_path_is_rejected(observation: dict[str, object], tmp_path: Path) -> None:
    root = Path(str(observation["artifact_root"])); target = tmp_path / "target"
    target.write_bytes(b"metadata")
    link = root / "evidence/linked.json"
    try:
        link.symlink_to(target)
        match = "symlink|junction"
    except OSError:
        # Native Windows often denies symlink creation to ordinary users.  A
        # hard link still proves that the descriptor policy rejects aliases.
        link.hardlink_to(target)
        match = "bounded private regular file"
    changed = copy.deepcopy(observation)
    changed["evidence_files"]["installed_metadata"] = {"path": "evidence/linked.json", "sha256": _sha(b"metadata")}  # type: ignore[index]
    with pytest.raises(ReleaseArtifactError, match=match):
        observe_release_artifacts(changed)
