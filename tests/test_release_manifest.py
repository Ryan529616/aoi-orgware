from __future__ import annotations

import copy

import pytest

from aoi_orgware.release_manifest import (
    MAX_RELEASE_MANIFEST_BYTES,
    ReleaseManifestError,
    promotion_receipt_sha256,
    release_manifest_sha256,
    seal_promotion_receipt,
    seal_release_manifest,
    validate_promotion_receipt,
    validate_release_manifest,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64
OID_C = "c" * 40
OID_D = "d" * 40


def artifacts() -> list[dict[str, object]]:
    return [
        {"name": "dist/aoi_orgware-0.4.0-py3-none-any.whl", "size_bytes": 1234, "sha256": SHA_A},
        {"name": "dist/aoi_orgware-0.4.0.tar.gz", "size_bytes": 2345, "sha256": SHA_B},
    ]


def manifest_base(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": 1,
        "distribution_name": "aoi-orgware",
        "tag": "v0.4.0",
        "git_object_format": "sha1",
        "commit_oid": OID_C,
        "tree_oid": OID_D,
        "package_version": "0.4.0",
        "build_environment": {
            "platform": "ubuntu-24.04",
            "python_version": "3.13.1",
            "builder_environment_receipt_sha256": SHA_E,
        },
        "workflow": {"workflow_name": "release", "run_id": "run-100", "run_attempt": 1},
        "artifacts": artifacts(),
        "producer_results": [{"producer_id": "build-linux", "result_sha256": SHA_F}],
        "interfaces": {"console_entry_point": {"name": "aoi", "target": "aoi_orgware.cli:main"}, "codex_hook_entry_point": {"name": "aoi-codex-hook", "target": "aoi_orgware.codex_hook:main"}, "hook_protocol_version": 6, "installed_metadata_sha256": SHA_E},
        "schema_versions": {"semantic-event": 2, "packet": 6},
        "dependencies": [
            {"name": "aoi-core", "release_manifest_sha256": SHA_C, "promotion_receipt_sha256": SHA_D}
        ],
        "verification": {
            "matrix": [
                {"platform": "linux", "gate_id": "release-test", "check_contract_sha256": SHA_A, "receipt_sha256": SHA_E, "status": "pass"},
                {"platform": "windows", "gate_id": "release-test", "check_contract_sha256": SHA_A, "receipt_sha256": SHA_F, "status": "pass"},
            ],
            "tested_artifacts": artifacts(),
            "rebuild": {"status": "reproducible", "artifacts": artifacts()},
        },
        "sbom": {"location": "artifacts/sbom.spdx.json", "sha256": SHA_A},
        "attestation": {"location": "artifacts/attestation.json", "sha256": SHA_B},
    }
    value.update(changes)
    return value


def sealed_manifest(**changes: object) -> dict[str, object]:
    return seal_release_manifest(manifest_base(**changes))


def promotion_base(manifest: dict[str, object], **changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": 1,
        "promotion_id": "pypi-0.4.0",
        "manifest_sha256": manifest["manifest_sha256"],
        "artifact_observation_receipt_sha256": SHA_F,
        "registry_readback": {
            "registry": "https://pypi.org",
            "project": "aoi-orgware",
            "package_version": "0.4.0",
            "observed_at": "2026-07-18T12:34:56.000000Z",
            "artifacts": artifacts(),
        },
        "installed": {
            "distribution_name": "aoi-orgware",
            "package_version": "0.4.0",
            "observed_at": "2026-07-18T12:35:00.000000Z",
            "installed_metadata_sha256": SHA_E,
            "console_entry_point": {"name": "aoi", "target": "aoi_orgware.cli:main"},
            "codex_hook_entry_point": {"name": "aoi-codex-hook", "target": "aoi_orgware.codex_hook:main"},
            "hook_protocol_version": 6,
        },
        "dependency_promotions": [{"name": "aoi-core", "promotion_receipt_sha256": SHA_D}],
        "rollback_provenance": None,
    }
    value.update(changes)
    return value


def test_manifest_is_deterministic_and_sealed() -> None:
    first = sealed_manifest()
    second = sealed_manifest(producer_results=[{"result_sha256": SHA_F, "producer_id": "build-linux"}])

    assert first == second
    assert first["manifest_sha256"] == release_manifest_sha256(manifest_base())
    assert validate_release_manifest(first) == first


def test_keyed_release_collections_are_canonical_under_permutation() -> None:
    base = manifest_base()
    verification = copy.deepcopy(base["verification"])
    assert isinstance(verification, dict)
    verification["matrix"] = list(reversed(verification["matrix"]))
    verification["tested_artifacts"] = list(reversed(verification["tested_artifacts"]))
    rebuild = verification["rebuild"]
    assert isinstance(rebuild, dict)
    rebuild["artifacts"] = list(reversed(rebuild["artifacts"]))
    first = sealed_manifest(
        producer_results=[
            {"producer_id": "producer-z", "result_sha256": SHA_A},
            {"producer_id": "producer-a", "result_sha256": SHA_B},
        ],
        dependencies=[
            {"name": "z-dep", "release_manifest_sha256": SHA_A, "promotion_receipt_sha256": SHA_B},
            {"name": "a-dep", "release_manifest_sha256": SHA_C, "promotion_receipt_sha256": SHA_D},
        ],
    )
    second = sealed_manifest(
        artifacts=list(reversed(artifacts())),
        producer_results=list(reversed(first["producer_results"])),
        dependencies=list(reversed(first["dependencies"])),
        verification=verification,
    )
    assert first == second

    receipt_one = seal_promotion_receipt(
        promotion_base(first, dependency_promotions=list(reversed([
            {"name": "a-dep", "promotion_receipt_sha256": SHA_D},
            {"name": "z-dep", "promotion_receipt_sha256": SHA_B},
        ]))),
        first,
    )
    readback = copy.deepcopy(promotion_base(first)["registry_readback"])
    assert isinstance(readback, dict)
    readback["artifacts"] = list(reversed(artifacts()))
    receipt_two = seal_promotion_receipt(
        promotion_base(first, registry_readback=readback, dependency_promotions=[
            {"name": "a-dep", "promotion_receipt_sha256": SHA_D},
            {"name": "z-dep", "promotion_receipt_sha256": SHA_B},
        ]),
        first,
    )
    assert receipt_one == receipt_two


def test_manifest_tamper_tag_tree_artifact_and_receipt_fail_closed() -> None:
    manifest = sealed_manifest()
    for key, replacement in (("tag", "v0.4.1"), ("tree_oid", "a" * 40)):
        tampered = copy.deepcopy(manifest)
        tampered[key] = replacement
        with pytest.raises(ReleaseManifestError, match="manifest_sha256"):
            validate_release_manifest(tampered)
    tampered = copy.deepcopy(manifest)
    tampered["artifacts"][0]["sha256"] = SHA_C  # type: ignore[index]
    with pytest.raises(ReleaseManifestError, match="tested_artifacts|manifest_sha256"):
        validate_release_manifest(tampered)
    tampered = copy.deepcopy(manifest)
    tampered["verification"]["matrix"][0]["receipt_sha256"] = SHA_C  # type: ignore[index]
    with pytest.raises(ReleaseManifestError, match="manifest_sha256"):
        validate_release_manifest(tampered)
    tampered = copy.deepcopy(manifest)
    tampered["dependencies"][0]["promotion_receipt_sha256"] = SHA_A  # type: ignore[index]
    with pytest.raises(ReleaseManifestError, match="manifest_sha256"):
        validate_release_manifest(tampered)
    tampered = copy.deepcopy(manifest)
    tampered["unexpected"] = True
    with pytest.raises(ReleaseManifestError, match="schema"):
        validate_release_manifest(tampered)


def test_manifest_git_object_format_binds_exact_oid_width() -> None:
    sha256_manifest = sealed_manifest(
        git_object_format="sha256",
        commit_oid=SHA_C,
        tree_oid=SHA_D,
    )
    assert sha256_manifest["git_object_format"] == "sha256"
    assert sha256_manifest["commit_oid"] == SHA_C
    for changes in (
        {"git_object_format": "sha1", "commit_oid": SHA_C},
        {"git_object_format": "sha256", "tree_oid": OID_D},
        {"git_object_format": "md5", "commit_oid": OID_C, "tree_oid": OID_D},
        {"commit_oid": OID_C.upper()},
    ):
        with pytest.raises(ReleaseManifestError, match="Git object id|git_object_format"):
            sealed_manifest(**changes)


def test_manifest_rejects_duplicate_artifacts_bad_tag_missing_matrix_and_rebuild_substitution() -> None:
    duplicate = artifacts() + [copy.deepcopy(artifacts()[0])]
    with pytest.raises(ReleaseManifestError, match="duplicate artifact"):
        sealed_manifest(artifacts=duplicate)
    with pytest.raises(ReleaseManifestError, match="tag is invalid"):
        sealed_manifest(tag="refs/heads/main")
    for tag in (
        "v0.4.0.lock",
        "v1/x.lock",
        "release//v0.4.0",
        "v1//x",
        "release/.hidden",
        "v1/x..y",
        r"v1\\x",
        "v1 x",
        "v1~x",
        "v1^x",
        "v1:x",
        "v1?x",
        "v1*x",
        "v1[x",
        "@",
        "release\x7f",
    ):
        with pytest.raises(ReleaseManifestError, match="tag is invalid"):
            sealed_manifest(tag=tag)
    assert sealed_manifest(tag="v1/feature]")["tag"] == "v1/feature]"
    assert sealed_manifest(tag="v1/x@y")["tag"] == "v1/x@y"
    matrix = manifest_base()["verification"]
    assert isinstance(matrix, dict)
    matrix["matrix"] = matrix["matrix"][:1]
    with pytest.raises(ReleaseManifestError, match="linux and windows"):
        sealed_manifest(verification=matrix)
    verification = manifest_base()["verification"]
    assert isinstance(verification, dict)
    verification["rebuild"] = {"status": "reproducible", "artifacts": [{"name": "dist/aoi_orgware-0.4.0-py3-none-any.whl", "size_bytes": 1234, "sha256": SHA_C}]}
    with pytest.raises(ReleaseManifestError, match="rebuild artifacts"):
        sealed_manifest(verification=verification)


def test_manifest_requires_same_named_matrix_gates_and_safe_relative_paths() -> None:
    verification = manifest_base()["verification"]
    assert isinstance(verification, dict)
    verification["matrix"] = [
        {"platform": "linux", "gate_id": "unit", "check_contract_sha256": SHA_A, "receipt_sha256": SHA_E, "status": "pass"},
        {"platform": "windows", "gate_id": "integration", "check_contract_sha256": SHA_A, "receipt_sha256": SHA_F, "status": "pass"},
    ]
    with pytest.raises(ReleaseManifestError, match="same named gates"):
        sealed_manifest(verification=verification)
    verification = manifest_base()["verification"]
    assert isinstance(verification, dict)
    verification["matrix"][1]["check_contract_sha256"] = SHA_B
    with pytest.raises(ReleaseManifestError, match="same gate contracts"):
        sealed_manifest(verification=verification)
    for field, location in (
        ("artifacts", [{"name": "dist/../escape.whl", "size_bytes": 1, "sha256": SHA_A}]),
        ("sbom", {"location": "../sbom.spdx.json", "sha256": SHA_A}),
        ("attestation", {"location": "artifacts/attestation\x00.json", "sha256": SHA_B}),
    ):
        with pytest.raises(ReleaseManifestError, match="invalid"):
            sealed_manifest(**{field: location})


def test_windows_casefold_and_cross_role_location_collisions_fail_closed() -> None:
    with pytest.raises(ReleaseManifestError, match="duplicate artifact"):
        sealed_manifest(artifacts=[
            {"name": "dist/Release.whl", "size_bytes": 1, "sha256": SHA_A},
            {"name": "DIST/release.whl", "size_bytes": 2, "sha256": SHA_B},
        ])
    with pytest.raises(ReleaseManifestError, match="globally unique"):
        sealed_manifest(sbom={"location": "DIST/AOI_ORGWARE-0.4.0-PY3-NONE-ANY.WHL", "sha256": SHA_A})
    with pytest.raises(ReleaseManifestError, match="globally unique"):
        sealed_manifest(
            sbom={"location": "artifacts/shared.json", "sha256": SHA_A},
            attestation={"location": "ARTIFACTS/SHARED.JSON", "sha256": SHA_B},
        )
    with pytest.raises(ReleaseManifestError, match="non-overlapping"):
        sealed_manifest(
            artifacts=[
                {"name": "dist/release", "size_bytes": 1, "sha256": SHA_A},
                {"name": "DIST/release/metadata.json", "size_bytes": 2, "sha256": SHA_B},
            ]
        )
    with pytest.raises(ReleaseManifestError, match="non-overlapping"):
        sealed_manifest(sbom={"location": "dist/AOI_ORGWARE-0.4.0-PY3-NONE-ANY.WHL/sbom.json", "sha256": SHA_A})


@pytest.mark.parametrize(
    "field,location",
    (
        ("artifacts", [{"name": "C:/dist/release.whl", "size_bytes": 1, "sha256": SHA_A}]),
        ("artifacts", [{"name": "dist/release.whl:metadata", "size_bytes": 1, "sha256": SHA_A}]),
        ("artifacts", [{"name": "dist/CON.whl", "size_bytes": 1, "sha256": SHA_A}]),
        ("artifacts", [{"name": "dist/COM¹.whl", "size_bytes": 1, "sha256": SHA_A}]),
        ("artifacts", [{"name": "dist/LPT².whl", "size_bytes": 1, "sha256": SHA_A}]),
        ("artifacts", [{"name": "dist/CONIN$.whl", "size_bytes": 1, "sha256": SHA_A}]),
        ("artifacts", [{"name": "dist/CONOUT$.whl", "size_bytes": 1, "sha256": SHA_A}]),
        ("artifacts", [{"name": "dist/CLOCK$.whl", "size_bytes": 1, "sha256": SHA_A}]),
        ("sbom", {"location": "artifacts/AUX", "sha256": SHA_A}),
        ("attestation", {"location": "artifacts/report. ", "sha256": SHA_B}),
    ),
)
def test_manifest_rejects_windows_unsafe_artifact_and_metadata_paths(
    field: str, location: object
) -> None:
    with pytest.raises(ReleaseManifestError, match="invalid"):
        sealed_manifest(**{field: location})


def test_manifest_requires_promoted_unique_dependencies_and_bounds_bytes() -> None:
    with pytest.raises(ReleaseManifestError, match="lowercase SHA-256"):
        sealed_manifest(dependencies=[{"name": "aoi-core", "release_manifest_sha256": SHA_A, "promotion_receipt_sha256": ""}])
    with pytest.raises(ReleaseManifestError, match="duplicate names"):
        sealed_manifest(dependencies=[
            {"name": "aoi-core", "release_manifest_sha256": SHA_A, "promotion_receipt_sha256": SHA_B},
            {"name": "aoi-core", "release_manifest_sha256": SHA_C, "promotion_receipt_sha256": SHA_D},
        ])
    with pytest.raises(ReleaseManifestError, match="byte bound"):
        sealed_manifest(attestation={"location": "x" * MAX_RELEASE_MANIFEST_BYTES, "sha256": SHA_A})
    with pytest.raises(ReleaseManifestError, match="invalid"):
        sealed_manifest(artifacts=[{"name": "dist/" + "x" * 256, "size_bytes": 1, "sha256": SHA_A}])


def test_promotion_binds_manifest_registry_installed_interface_and_dependencies() -> None:
    manifest = sealed_manifest()
    receipt = seal_promotion_receipt(promotion_base(manifest), manifest)

    assert receipt["promotion_receipt_sha256"] == promotion_receipt_sha256(promotion_base(manifest))
    assert validate_promotion_receipt(receipt, manifest) == receipt
    readback = promotion_base(manifest)["registry_readback"]
    assert isinstance(readback, dict)
    wrong_readback = copy.deepcopy(readback)
    wrong_readback["project"] = "different-project"
    installed = promotion_base(manifest)["installed"]
    assert isinstance(installed, dict)
    wrong_installed = copy.deepcopy(installed)
    wrong_installed["console_entry_point"]["name"] = "other"
    wrong_metadata = copy.deepcopy(installed)
    wrong_metadata["installed_metadata_sha256"] = SHA_A
    for field, replacement, match in (
        ("registry_readback", wrong_readback, "registry readback"),
        ("installed", wrong_installed, "installed consumer"),
        ("dependency_promotions", [], "dependency promotions"),
        ("installed", wrong_metadata, "installed consumer"),
    ):
        changed = promotion_base(manifest)
        changed[field] = replacement
        with pytest.raises(ReleaseManifestError, match=match):
            seal_promotion_receipt(changed, manifest)


def test_promotion_tamper_and_compensating_rollback_are_separate_records() -> None:
    manifest = sealed_manifest()
    initial = seal_promotion_receipt(promotion_base(manifest), manifest)
    rollback = seal_promotion_receipt(
        promotion_base(
            manifest,
            promotion_id="pypi-0.4.0-rollback",
            rollback_provenance={
                "from_promotion_receipt_sha256": SHA_F,
                "mode": "prior_manifest",
                "target_promotion_receipt_sha256": initial["promotion_receipt_sha256"],
                "compensating_manifest_sha256": manifest["manifest_sha256"],
                "reason": "restore prior release after incident",
            },
        ),
        manifest,
    )
    assert rollback["promotion_receipt_sha256"] != initial["promotion_receipt_sha256"]
    assert rollback["rollback_provenance"]["target_promotion_receipt_sha256"] == initial["promotion_receipt_sha256"]  # type: ignore[index]
    tampered = copy.deepcopy(rollback)
    tampered["promotion_id"] = "rewritten-history"
    with pytest.raises(ReleaseManifestError, match="promotion_receipt_sha256"):
        validate_promotion_receipt(tampered, manifest)
    with pytest.raises(ReleaseManifestError, match="compensating manifest"):
        seal_promotion_receipt(
            promotion_base(manifest, rollback_provenance={"from_promotion_receipt_sha256": SHA_A, "mode": "compensating_release", "target_promotion_receipt_sha256": None, "compensating_manifest_sha256": SHA_B, "reason": "bad"}),
            manifest,
        )


def test_manifest_rejects_zero_artifact_and_zero_workflow_attempt() -> None:
    with pytest.raises(ReleaseManifestError, match="artifact.size_bytes"):
        sealed_manifest(
            artifacts=[
                {
                    "name": "dist/empty.whl",
                    "size_bytes": 0,
                    "sha256": SHA_A,
                }
            ]
        )
    workflow = copy.deepcopy(manifest_base()["workflow"])
    assert isinstance(workflow, dict)
    workflow["run_attempt"] = 0
    with pytest.raises(ReleaseManifestError, match="run_attempt"):
        sealed_manifest(workflow=workflow)


def test_rollback_provenance_is_discriminated() -> None:
    manifest = sealed_manifest()
    compensating = promotion_base(
        manifest,
        rollback_provenance={
            "from_promotion_receipt_sha256": SHA_A,
            "mode": "compensating_release",
            "target_promotion_receipt_sha256": None,
            "compensating_manifest_sha256": manifest["manifest_sha256"],
            "reason": "publish a fixed successor",
        },
    )
    assert seal_promotion_receipt(compensating, manifest)["rollback_provenance"][
        "mode"
    ] == "compensating_release"
    for provenance in (
        {
            "from_promotion_receipt_sha256": SHA_A,
            "mode": "prior_manifest",
            "target_promotion_receipt_sha256": None,
            "compensating_manifest_sha256": manifest["manifest_sha256"],
            "reason": "missing target",
        },
        {
            "from_promotion_receipt_sha256": SHA_A,
            "mode": "compensating_release",
            "target_promotion_receipt_sha256": SHA_B,
            "compensating_manifest_sha256": manifest["manifest_sha256"],
            "reason": "unexpected target",
        },
    ):
        with pytest.raises(ReleaseManifestError):
            seal_promotion_receipt(
                promotion_base(manifest, rollback_provenance=provenance),
                manifest,
            )


def test_promotion_validation_requires_the_bound_manifest() -> None:
    manifest = sealed_manifest()
    receipt = seal_promotion_receipt(promotion_base(manifest), manifest)
    with pytest.raises(TypeError):
        validate_promotion_receipt(receipt)  # type: ignore[call-arg]
    other_manifest = sealed_manifest(tag="v0.4.1")
    with pytest.raises(ReleaseManifestError, match="manifest_sha256"):
        validate_promotion_receipt(receipt, other_manifest)


def test_release_identity_and_registry_readback_are_exact() -> None:
    with pytest.raises(ReleaseManifestError, match="canonical distribution"):
        sealed_manifest(distribution_name="AOI_Orgware")
    for version in ("v0.4", "0.04.0", "0.4.0-rc1", "latest"):
        with pytest.raises(ReleaseManifestError, match="package_version"):
            sealed_manifest(package_version=version)

    manifest = sealed_manifest()
    for key, replacement, match in (
        ("project", "other-project", "registry readback"),
        ("package_version", "0.4.1", "registry readback"),
        ("observed_at", "2026-07-18T12:34:56Z", "canonical UTC"),
    ):
        receipt = promotion_base(manifest)
        readback = copy.deepcopy(receipt["registry_readback"])
        assert isinstance(readback, dict)
        readback[key] = replacement
        receipt["registry_readback"] = readback
        with pytest.raises(ReleaseManifestError, match=match):
            seal_promotion_receipt(receipt, manifest)

    receipt = promotion_base(manifest)
    installed = copy.deepcopy(receipt["installed"])
    assert isinstance(installed, dict)
    installed["distribution_name"] = "other-project"
    receipt["installed"] = installed
    with pytest.raises(ReleaseManifestError, match="installed consumer"):
        seal_promotion_receipt(receipt, manifest)

    receipt = promotion_base(manifest)
    installed = copy.deepcopy(receipt["installed"])
    assert isinstance(installed, dict)
    installed["observed_at"] = "2026-07-18T12:35:00Z"
    receipt["installed"] = installed
    with pytest.raises(ReleaseManifestError, match="canonical UTC"):
        seal_promotion_receipt(receipt, manifest)


def test_distribution_dependencies_and_promotion_ids_are_canonical() -> None:
    with pytest.raises(ReleaseManifestError, match="canonical distribution"):
        sealed_manifest(
            dependencies=[
                {
                    "name": "AOI_Core",
                    "release_manifest_sha256": SHA_A,
                    "promotion_receipt_sha256": SHA_B,
                }
            ]
        )
    manifest = sealed_manifest(dependencies=[])
    with pytest.raises(ReleaseManifestError, match="promotion_id"):
        seal_promotion_receipt(
            promotion_base(
                manifest,
                promotion_id="pypi/0.4.0",
                dependency_promotions=[],
            ),
            manifest,
        )
