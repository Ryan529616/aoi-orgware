from __future__ import annotations

import copy
import hashlib
import importlib.util
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from aoi_orgware.semantic_events import canonical_json_bytes, canonical_sha256
from aoi_orgware.release_artifacts import observe_release_artifacts


_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "release_rehearsal.py"
_SPEC = importlib.util.spec_from_file_location("release_rehearsal", _SCRIPT)
assert _SPEC and _SPEC.loader
rehearsal = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(rehearsal)


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value, max_bytes=1024 * 1024))
    return path


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _inventory(name: str, payload: bytes) -> dict[str, object]:
    base = {
        "schema_version": 1,
        "distribution_name": "aoi-orgware",
        "package_version": "0.4.0",
        "artifacts": [
            {"name": "aoi_orgware-0.4.0-py3-none-any.whl", "size_bytes": len(payload), "sha256": _sha(payload)},
            {"name": "aoi_orgware-0.4.0.tar.gz", "size_bytes": len(payload), "sha256": _sha(payload)},
        ],
    }
    # Inventory requires lexicographically ordered names; wheel is before tar.
    base["artifacts"] = sorted(base["artifacts"], key=lambda item: item["name"])  # type: ignore[index]
    return {**base, "inventory_sha256": canonical_sha256(base)}


def _root_with_inventory(root: Path, inventory: dict[str, object], data: bytes) -> None:
    root.mkdir(parents=True)
    for artifact in inventory["artifacts"]:  # type: ignore[index]
        (root / artifact["name"]).write_bytes(data)  # type: ignore[index]


def _release_toolchain() -> dict[str, object]:
    """Use the real, complete lock-derived fixture rather than a toy subset."""

    return copy.deepcopy(rehearsal._canonical_release_toolchain())


def _receipt_files(tmp_path: Path, inventory: dict[str, object]) -> dict[str, Path]:
    digest = str(inventory["inventory_sha256"])
    files = {
        "builder": _write(tmp_path / "builder.json", rehearsal.create_builder_environment_receipt(
            platform="linux", python_version="3.13", workflow_name="release", run_id="run-1", run_attempt=1,
            runner_os="Linux", runner_arch="X64", runner_image="ubuntu-24.04", build_frontend="hatchling", build_frontend_version="1.27", source_date_epoch=1,
        )),
        "producer": _write(tmp_path / "producer.json", rehearsal.create_producer_receipt(producer_id="build-linux", platform="linux", inventory_sha256=digest, result={"build": "pass", "release_toolchain": _release_toolchain()})),
        "contract": _write(tmp_path / "contract.json", rehearsal.create_gate_contract(gate_id="unit", contract={"command": "pytest"})),
        "installed": _write(tmp_path / "installed.json", rehearsal.create_installed_metadata_receipt(distribution_name="aoi-orgware", package_version="0.4.0", installed_metadata_sha256=_sha(b"metadata"), console_entry_point_name="aoi", console_entry_point_target="aoi_orgware.cli:main", codex_hook_entry_point_name="aoi-codex-hook", codex_hook_entry_point_target="aoi_orgware.codex_hook:main", hook_protocol_version=1)),
        "sbom": _write(tmp_path / "sbom-receipt.json", rehearsal.create_placeholder_receipt(kind="sbom", location="meta/sbom.json", input_bytes=b"sbom")),
        "attestation": _write(tmp_path / "attestation-receipt.json", rehearsal.create_placeholder_receipt(kind="attestation", location="meta/attestation.json", input_bytes=b"attestation")),
    }
    contract = rehearsal._read_canonical_json(files["contract"])
    files["linux_gate"] = _write(tmp_path / "linux-gate.json", rehearsal.create_platform_gate_receipt(platform="linux", gate_id="unit", check_contract_sha256=contract["check_contract_sha256"], inventory_sha256=digest, details={"result": "pass"}))
    files["windows_gate"] = _write(tmp_path / "windows-gate.json", rehearsal.create_platform_gate_receipt(platform="windows", gate_id="unit", check_contract_sha256=contract["check_contract_sha256"], inventory_sha256=digest, details={"result": "pass"}))
    return files


def _receipt_base(path: Path) -> bytes:
    value = rehearsal._read_canonical_json(path)
    return canonical_json_bytes(
        {key: item for key, item in value.items() if key != "receipt_sha256"}
    )


@pytest.fixture
def release_request(tmp_path: Path) -> dict[str, object]:
    data = b"same distribution bytes"
    inventory = _inventory("unused", data)
    artifact_root = tmp_path / "artifacts"; rebuild_root = tmp_path / "rebuild"; windows_root = tmp_path / "windows"
    _root_with_inventory(artifact_root / "dist", inventory, data)
    _root_with_inventory(rebuild_root / "dist", inventory, data)
    _root_with_inventory(windows_root, inventory, data)
    (artifact_root / "meta").mkdir(); (artifact_root / "meta/sbom.json").write_bytes(b"sbom"); (artifact_root / "meta/attestation.json").write_bytes(b"attestation")
    files = _receipt_files(tmp_path, inventory)
    (artifact_root / "evidence").mkdir()
    builder_bytes = files["builder"].read_bytes()
    producer_bytes = canonical_json_bytes(
        rehearsal.producer_binding(rehearsal._read_canonical_json(files["producer"]))
    )
    contract_bytes = canonical_json_bytes(
        {
            key: item
            for key, item in rehearsal._read_canonical_json(files["contract"]).items()
            if key not in {"receipt_sha256", "check_contract_sha256"}
        }
    )
    linux_bytes = _receipt_base(files["linux_gate"])
    windows_bytes = _receipt_base(files["windows_gate"])
    (artifact_root / "evidence/builder.json").write_bytes(builder_bytes)
    (artifact_root / "evidence/producer-binding.json").write_bytes(producer_bytes)
    (artifact_root / "evidence/linux-contract.json").write_bytes(contract_bytes)
    (artifact_root / "evidence/windows-contract.json").write_bytes(contract_bytes)
    (artifact_root / "evidence/linux.json").write_bytes(linux_bytes)
    (artifact_root / "evidence/windows.json").write_bytes(windows_bytes)
    (artifact_root / "evidence/installed.json").write_bytes(b"metadata")
    inventories = {name: _write(tmp_path / f"{name}-inventory.json", inventory) for name in ("linux", "windows", "rebuild")}
    evidence = {
        "producer_results": {"build-linux": {"path": "evidence/producer-binding.json", "sha256": _sha(producer_bytes)}},
        "builder_environment": {"path": "evidence/builder.json", "sha256": _sha(builder_bytes)},
        "matrix": {"linux/unit": {"check_contract": {"path": "evidence/linux-contract.json", "sha256": _sha(contract_bytes)}, "receipt": {"path": "evidence/linux.json", "sha256": _sha(linux_bytes)}}, "windows/unit": {"check_contract": {"path": "evidence/windows-contract.json", "sha256": _sha(contract_bytes)}, "receipt": {"path": "evidence/windows.json", "sha256": _sha(windows_bytes)}}},
        "installed_metadata": {"path": "evidence/installed.json", "sha256": _sha(b"metadata")}, "reviewed_exception_receipt": None,
    }
    return {
        "schema_version": 1,
        "manifest": {"distribution_name": "aoi-orgware", "tag": "v0.4.0", "git_object_format": "sha1", "commit_oid": "a" * 40, "tree_oid": "b" * 40, "package_version": "0.4.0", "workflow": {"workflow_name": "release", "run_id": "run-1", "run_attempt": 1}, "schema_versions": {"release": 1}, "dependencies": []},
        "inventory_paths": {name: str(path) for name, path in inventories.items()},
        "inventory_roots": {"linux": str(artifact_root / "dist"), "windows": str(windows_root), "rebuild": str(rebuild_root / "dist")},
        "builder_environment_receipt_path": str(files["builder"]), "producer_receipt_paths": {"build-linux": str(files["producer"])}, "gate_contract_paths": {"unit": str(files["contract"])}, "platform_gate_receipt_paths": {"linux": {"unit": str(files["linux_gate"])}, "windows": {"unit": str(files["windows_gate"])}}, "installed_metadata_receipt_path": str(files["installed"]), "sbom_receipt_path": str(files["sbom"]), "attestation_receipt_path": str(files["attestation"]),
        "worktree": str(tmp_path / "worktree"), "artifact_root": str(artifact_root), "rebuild_root": str(rebuild_root), "evidence_files": evidence, "dependency_files": {}, "outputs": {"release_manifest": str(tmp_path / "out" / "release-manifest.json"), "observation_request": str(tmp_path / "out" / "observation-request.json")},
    }


def test_assemble_exact_release_manifest_and_observation_request(release_request: dict[str, object]) -> None:
    result = rehearsal.assemble(release_request)
    assert result["manifest"]["artifacts"][0]["name"].startswith("dist/")
    binding = rehearsal._read_canonical_json(
        Path(release_request["artifact_root"]) / "evidence" / "producer-binding.json"
    )
    assert binding["platform"] == "linux"
    assert binding["inventory_sha256"] == rehearsal._read_canonical_json(
        Path(release_request["inventory_paths"]["linux"])
    )["inventory_sha256"]
    assert result["manifest"]["producer_results"] == [{
        "producer_id": binding["producer_id"],
        "result_sha256": canonical_sha256(binding),
    }]
    assert Path(release_request["outputs"]["release_manifest"]).is_file()  # type: ignore[index]
    assert Path(release_request["outputs"]["observation_request"]).is_file()  # type: ignore[index]


def test_missing_extra_or_replaced_artifact_fails(release_request: dict[str, object]) -> None:
    windows = Path(release_request["inventory_roots"]["windows"])  # type: ignore[index]
    (windows / "extra.whl").write_bytes(b"extra")
    with pytest.raises(rehearsal.RehearsalError, match="inventory root"):
        rehearsal.assemble(release_request)
    (windows / "extra.whl").unlink()
    linux = Path(release_request["inventory_roots"]["linux"])  # type: ignore[index]
    next(linux.iterdir()).write_bytes(b"replaced")
    with pytest.raises(rehearsal.RehearsalError, match="inventory root"):
        rehearsal.assemble(release_request)


def test_windows_other_inventory_and_gate_contract_mismatch_fail(release_request: dict[str, object], tmp_path: Path) -> None:
    changed = copy.deepcopy(release_request)
    other = _inventory("unused", b"different")
    other_path = _write(tmp_path / "other.json", other)
    changed["inventory_paths"]["windows"] = str(other_path)  # type: ignore[index]
    with pytest.raises(rehearsal.RehearsalError, match="inventories"):
        rehearsal.assemble(changed)
    changed = copy.deepcopy(release_request)
    contract = rehearsal.create_gate_contract(gate_id="unit", contract={"command": "other"})
    changed_path = _write(tmp_path / "other-contract.json", contract)
    changed["gate_contract_paths"]["unit"] = str(changed_path)  # type: ignore[index]
    with pytest.raises(rehearsal.RehearsalError, match="platform gate receipt"):
        rehearsal.assemble(changed)


def test_one_byte_rebuild_difference_noncanonical_duplicate_and_create_only_fail(release_request: dict[str, object]) -> None:
    rebuild = Path(release_request["inventory_roots"]["rebuild"])  # type: ignore[index]
    first = next(rebuild.iterdir()); first.write_bytes(first.read_bytes() + b"!")
    with pytest.raises(rehearsal.RehearsalError, match="inventory root"):
        rehearsal.assemble(release_request)
    first.write_bytes(b"same distribution bytes")
    request_path = Path(release_request["builder_environment_receipt_path"])  # type: ignore[index]
    raw = request_path.read_bytes(); request_path.write_bytes(raw + b"\n")
    with pytest.raises(rehearsal.RehearsalError, match="canonical"):
        rehearsal.assemble(release_request)
    request_path.write_bytes(raw[:-1] + b',"platform":"linux"}')
    with pytest.raises(rehearsal.RehearsalError, match="duplicate JSON key"):
        rehearsal.assemble(release_request)
    request_path.write_bytes(raw)
    result = rehearsal.assemble(release_request)
    assert result["manifest"]["manifest_sha256"]
    with pytest.raises(rehearsal.RehearsalError, match="create-only"):
        rehearsal.assemble(release_request)


def test_evidence_must_be_the_exact_manifest_input(release_request: dict[str, object]) -> None:
    builder = Path(release_request["artifact_root"]) / "evidence" / "builder.json"
    builder.write_bytes(b"different builder evidence")
    release_request["evidence_files"]["builder_environment"]["sha256"] = _sha(  # type: ignore[index]
        b"different builder evidence"
    )
    with pytest.raises(rehearsal.RehearsalError, match="descriptor used by the manifest"):
        rehearsal.assemble(release_request)


def test_windows_producer_cannot_claim_the_linux_build(release_request: dict[str, object]) -> None:
    producer_path = Path(release_request["producer_receipt_paths"]["build-linux"])  # type: ignore[index]
    inventory = rehearsal._read_canonical_json(
        Path(release_request["inventory_paths"]["linux"])  # type: ignore[index]
    )
    producer_path.write_bytes(
        canonical_json_bytes(
            rehearsal.create_producer_receipt(
                producer_id="build-linux",
                platform="windows",
                inventory_sha256=inventory["inventory_sha256"],
                result={"build": "pass"},
            )
        )
    )
    with pytest.raises(rehearsal.RehearsalError, match="Linux build inventory"):
        rehearsal.assemble(release_request)


def test_producer_binding_cannot_drop_receipt_platform_or_inventory(
    release_request: dict[str, object]
) -> None:
    evidence = Path(release_request["artifact_root"]) / "evidence" / "producer-binding.json"
    binding = rehearsal._read_canonical_json(evidence)
    for field, value in (
        ("producer_receipt_sha256", "0" * 64),
        ("platform", "windows"),
        ("inventory_sha256", "1" * 64),
    ):
        changed = dict(binding)
        changed[field] = value
        evidence.write_bytes(canonical_json_bytes(changed))
        release_request["evidence_files"]["producer_results"]["build-linux"]["sha256"] = _sha(  # type: ignore[index]
            canonical_json_bytes(changed)
        )
        with pytest.raises(
            rehearsal.RehearsalError,
            match="producer evidence is not the exact result|producer evidence does not bind",
        ):
            rehearsal.assemble(release_request)
    evidence.write_bytes(canonical_json_bytes(binding))


def test_linux_producer_receipt_requires_a_canonical_complete_toolchain() -> None:
    toolchain = _release_toolchain()
    assert len(toolchain["distributions"]) == 11
    assert {entry["name"] for entry in toolchain["distributions"]} == {
        "build", "colorama", "hatchling", "iniconfig", "packaging", "pathspec",
        "pluggy", "pygments", "pyproject-hooks", "pytest", "trove-classifiers",
    }
    receipt = rehearsal.create_producer_receipt(
        producer_id="build-linux",
        platform="linux",
        inventory_sha256="1" * 64,
        result={"release_toolchain": toolchain, "status": "pass"},
    )
    assert receipt["result"]["release_toolchain"] == toolchain
    with pytest.raises(rehearsal.RehearsalError, match="lacks release_toolchain"):
        rehearsal.create_producer_receipt(
            producer_id="build-linux",
            platform="linux",
            inventory_sha256="1" * 64,
            result={"status": "pass"},
        )
    missing = copy.deepcopy(toolchain)
    missing["distributions"].pop()  # type: ignore[index]
    with pytest.raises(rehearsal.RehearsalError, match="does not match canonical"):
        rehearsal.create_producer_receipt(
            producer_id="build-linux",
            platform="linux",
            inventory_sha256="1" * 64,
            result={"release_toolchain": missing},
        )
    extra = copy.deepcopy(toolchain)
    extra["distributions"].append({"name": "zzz", "version": "1.0", "artifact_sha256": "0" * 64})  # type: ignore[index]
    with pytest.raises(rehearsal.RehearsalError, match="does not match canonical"):
        rehearsal.create_producer_receipt(producer_id="build-linux", platform="linux", inventory_sha256="1" * 64, result={"release_toolchain": extra})
    wrong_version = copy.deepcopy(toolchain)
    wrong_version["distributions"][0]["version"] = "0"  # type: ignore[index]
    with pytest.raises(rehearsal.RehearsalError, match="does not match canonical"):
        rehearsal.create_producer_receipt(producer_id="build-linux", platform="linux", inventory_sha256="1" * 64, result={"release_toolchain": wrong_version})
    arbitrary_lock = copy.deepcopy(toolchain)
    arbitrary_lock["lock_sha256"] = "0" * 64
    with pytest.raises(rehearsal.RehearsalError, match="does not match canonical"):
        rehearsal.create_producer_receipt(producer_id="build-linux", platform="linux", inventory_sha256="1" * 64, result={"release_toolchain": arbitrary_lock})


def test_assemble_revalidates_the_complete_toolchain_not_just_its_count(
    release_request: dict[str, object],
) -> None:
    producer_path = Path(release_request["producer_receipt_paths"]["build-linux"])  # type: ignore[index]
    receipt = rehearsal._read_canonical_json(producer_path)
    invalid = copy.deepcopy(receipt)
    invalid["result"]["release_toolchain"]["distributions"][0]["version"] = "0"  # type: ignore[index]
    invalid["result_sha256"] = canonical_sha256(invalid["result"])
    invalid = rehearsal._seal({key: value for key, value in invalid.items() if key != "receipt_sha256"})
    producer_path.write_bytes(canonical_json_bytes(invalid))
    with pytest.raises(rehearsal.RehearsalError, match="does not match canonical"):
        rehearsal.assemble(release_request)


def test_rehearsal_reads_receipts_through_nofollow_descriptors(release_request: dict[str, object]) -> None:
    if not hasattr(rehearsal.os, "O_NOFOLLOW"):
        pytest.skip("platform has no no-follow descriptor flag")
    path = Path(release_request["builder_environment_receipt_path"])  # type: ignore[index]
    original_open = rehearsal.os.open
    flags: list[int] = []
    def checked_open(*args, **kwargs):
        flags.append(args[1])
        return original_open(*args, **kwargs)
    with mock.patch.object(rehearsal.os, "open", side_effect=checked_open):
        rehearsal._read_canonical_json(path)
    assert flags and all(flag & rehearsal.os.O_NOFOLLOW for flag in flags)


def test_assembled_request_is_accepted_by_observer(release_request: dict[str, object]) -> None:
    worktree = Path(release_request["worktree"])
    (worktree / "src" / "aoi_orgware").mkdir(parents=True)
    (worktree / "src" / "aoi_orgware" / "_version.py").write_text(
        '__version__ = "0.4.0"\n', encoding="utf-8"
    )

    def git(*arguments: str) -> str:
        result = subprocess.run(
            ["git", *arguments],
            cwd=worktree,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    git("init", "-q")
    git("add", "src/aoi_orgware/_version.py")
    git(
        "-c",
        "user.name=AOI Test",
        "-c",
        "user.email=aoi@example.invalid",
        "commit",
        "-q",
        "-m",
        "release fixture",
    )
    git("tag", "v0.4.0")
    release_request["manifest"]["git_object_format"] = git(  # type: ignore[index]
        "rev-parse", "--show-object-format"
    )
    release_request["manifest"]["commit_oid"] = git("rev-parse", "HEAD")  # type: ignore[index]
    release_request["manifest"]["tree_oid"] = git("rev-parse", "HEAD^{tree}")  # type: ignore[index]

    result = rehearsal.assemble(release_request)
    observed = observe_release_artifacts(result["observation_request"])
    assert observed["manifest"] == result["manifest"]
    assert observed["observation_receipt"]["manifest_sha256"] == result["manifest"]["manifest_sha256"]
