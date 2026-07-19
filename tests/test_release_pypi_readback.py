from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import copy
from unittest import mock
from pathlib import Path

import pytest

from aoi_orgware.release_artifacts import _seal_release_observation_receipt
from aoi_orgware.release_manifest import seal_release_manifest
from aoi_orgware.semantic_events import canonical_json_bytes


SCRIPT = Path(__file__).parents[1] / "scripts" / "release_pypi_readback.py"
SPEC = importlib.util.spec_from_file_location("release_pypi_readback", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
readback = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = readback
SPEC.loader.exec_module(readback)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def sealed() -> tuple[dict[str, object], dict[str, object], dict[str, bytes]]:
    wheel = b"wheel from pypi"
    sdist = b"sdist from pypi"
    artifacts = [
        {"name": "dist/aoi_orgware-0.4.0-py3-none-any.whl", "size_bytes": len(wheel), "sha256": _sha(wheel)},
        {"name": "dist/aoi_orgware-0.4.0.tar.gz", "size_bytes": len(sdist), "sha256": _sha(sdist)},
    ]
    manifest = seal_release_manifest({
        "schema_version": 1, "distribution_name": "aoi-orgware", "tag": "v0.4.0",
        "git_object_format": "sha1", "commit_oid": "a" * 40, "tree_oid": "b" * 40,
        "package_version": "0.4.0",
        "build_environment": {"platform": "linux", "python_version": "3.13", "builder_environment_receipt_sha256": "c" * 64},
        "workflow": {"workflow_name": "release", "run_id": "readback-test", "run_attempt": 1},
        "artifacts": copy.deepcopy(artifacts),
        "producer_results": [{"producer_id": "build", "result_sha256": "d" * 64}],
        "interfaces": {"console_entry_point": {"name": "aoi", "target": "aoi_orgware.cli:main"}, "codex_hook_entry_point": {"name": "aoi-codex-hook", "target": "aoi_orgware.codex_hook:main"}, "hook_protocol_version": 6, "installed_metadata_sha256": _sha(b"installed metadata")},
        "schema_versions": {"packet": 6}, "dependencies": [],
        "verification": {"matrix": [
            {"platform": "linux", "gate_id": "unit", "check_contract_sha256": "e" * 64, "receipt_sha256": "f" * 64, "status": "pass"},
            {"platform": "windows", "gate_id": "unit", "check_contract_sha256": "e" * 64, "receipt_sha256": "1" * 64, "status": "pass"},
        ], "tested_artifacts": copy.deepcopy(artifacts), "rebuild": {"status": "reproducible", "artifacts": copy.deepcopy(artifacts)}},
        "sbom": {"location": "meta/sbom.json", "sha256": "2" * 64},
        "attestation": {"location": "meta/attestation.json", "sha256": "3" * 64},
    })
    observation_base = {
        "schema_version": 1, "manifest_sha256": manifest["manifest_sha256"],
        "git": {"git_object_format": "sha1", "commit_oid": "a" * 40, "tree_oid": "b" * 40, "tag": "v0.4.0", "package_version": "0.4.0"},
        "artifacts": artifacts, "sbom_sha256": "2" * 64, "attestation_sha256": "3" * 64,
        "evidence_files": {"producer_results": {"build": "d" * 64}, "builder_environment_receipt_sha256": "c" * 64,
            "matrix": {"linux/unit": {"check_contract_sha256": "e" * 64, "receipt_sha256": "f" * 64}, "windows/unit": {"check_contract_sha256": "e" * 64, "receipt_sha256": "1" * 64}},
            "installed_metadata_sha256": _sha(b"installed metadata"), "reviewed_exception_receipt_sha256": None},
        "dependencies": [], "rebuild_status": "reproducible",
    }
    observation = _seal_release_observation_receipt(observation_base, manifest)
    return manifest, observation, {"aoi_orgware-0.4.0-py3-none-any.whl": wheel, "aoi_orgware-0.4.0.tar.gz": sdist}


def _document(manifest: dict[str, object], files: dict[str, bytes]) -> dict[str, object]:
    return {"info": {"name": manifest["distribution_name"], "version": manifest["package_version"]}, "urls": [
        {"filename": name, "size": len(raw), "digests": {"sha256": _sha(raw)}, "packagetype": "bdist_wheel" if name.endswith(".whl") else "sdist", "url": f"https://files.pythonhosted.org/packages/{name}"}
        for name, raw in files.items()
    ]}


def _provenance(filename: str, raw: bytes, *, repository: str = "Ryan529616/aoi-orgware", workflow: str = "publish.yml") -> dict[str, object]:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": filename, "digest": {"sha256": _sha(raw)}}],
        "predicateType": "https://docs.pypi.org/attestations/publish/v1",
        "predicate": None,
    }
    encoded = readback.base64.b64encode(
        json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return {
        "version": 1,
        "attestation_bundles": [{
            "publisher": {
                "kind": "GitHub",
                "repository": repository,
                "workflow": workflow,
                "environment": "pypi",
                "claims": None,
            },
            "attestations": [{
                "version": 1,
                "envelope": {"signature": "test-signature", "statement": encoded},
                "verification_material": {"certificate": "test-certificate"},
            }],
        }],
    }


def _fetcher(document: dict[str, object], files: dict[str, bytes], provenances: dict[str, dict[str, object]] | None = None):
    calls: list[str] = []
    provenances = provenances or {name: _provenance(name, raw) for name, raw in files.items()}
    def fetch(url: str, maximum: int) -> bytes:
        calls.append(url)
        if url.endswith("/json"):
            return json.dumps(document, sort_keys=True).encode("utf-8")
        if "/integrity/" in url and url.endswith("/provenance"):
            name = readback.urllib.parse.unquote(url.rsplit("/", 2)[-2])
            return json.dumps(provenances[name], sort_keys=True).encode("utf-8")
        name = url.rsplit("/", 1)[-1]
        return files[name]
    return fetch, calls


def _runner(metadata: bytes, *, hook_version: int = 6):
    commands: list[list[str]] = []
    environments: list[dict[str, str]] = []
    def runner(command, cwd, env):
        rendered = [str(part) for part in command]
        commands.append(rendered)
        environments.append(dict(env))
        if rendered[1:3] == ["-m", "venv"]:
            environment = Path(rendered[-1]); scripts = environment / ("Scripts" if readback.os.name == "nt" else "bin")
            scripts.mkdir(parents=True); (scripts / ("python.exe" if readback.os.name == "nt" else "python")).write_bytes(b"")
            (scripts / ("aoi.exe" if readback.os.name == "nt" else "aoi")).write_bytes(b"")
            (scripts / ("aoi-codex-hook.exe" if readback.os.name == "nt" else "aoi-codex-hook")).write_bytes(b"")
            metadata_path = environment / "Lib/site-packages/aoi_orgware-0.4.0.dist-info/METADATA"
            metadata_path.parent.mkdir(parents=True); metadata_path.write_bytes(metadata)
            return subprocess.CompletedProcess(rendered, 0, "", "")
        if "-c" in rendered:
            environment = Path(rendered[0]).parents[1]
            metadata_path = environment / "Lib/site-packages/aoi_orgware-0.4.0.dist-info/METADATA"
            output = json.dumps({"version": "0.4.0", "metadata_path": str(metadata_path), "hook_protocol_version": hook_version, "entry_points": {"aoi": "aoi_orgware.cli:main", "aoi-codex-hook": "aoi_orgware.codex_hook:main"}})
            return subprocess.CompletedProcess(rendered, 0, output, "")
        if rendered[-1] == "--version":
            return subprocess.CompletedProcess(rendered, 0, "AOI 0.4.0\n", "")
        return subprocess.CompletedProcess(rendered, 0, "", "")
    return runner, commands, environments


def test_full_readback_uses_mocked_network_and_subprocess(sealed: tuple[dict[str, object], dict[str, object], dict[str, bytes]]) -> None:
    manifest, observation, files = sealed
    document = _document(manifest, files)
    fetch, calls = _fetcher(document, files)
    runner, commands, environments = _runner(b"installed metadata")
    receipt = readback.readback_pypi_release(manifest, observation, promotion_id="pypi-0.4.0", observed_at="2026-07-19T01:02:03.000000Z", trusted_publisher_repository="Ryan529616/aoi-orgware", trusted_publisher_workflow="publish.yml", fetch=fetch, runner=runner)
    promotion = receipt["promotion_receipt"]
    assert promotion["artifact_observation_receipt_sha256"] == observation["observation_receipt_sha256"]
    assert promotion["registry_readback"]["artifacts"] == manifest["artifacts"]
    assert promotion["installed"]["installed_metadata_sha256"] == manifest["interfaces"]["installed_metadata_sha256"]
    assert receipt["attestation_evidence"]["evidence_strength"] == "presence_only"
    assert receipt["attestation_evidence"]["cryptographically_verified"] is False
    assert {item["artifact_sha256"] for item in receipt["attestation_evidence"]["artifacts"]} == {
        item["sha256"] for item in manifest["artifacts"]
    }
    assert calls[0] == "https://pypi.org/pypi/aoi-orgware/0.4.0/json"
    install = next(command for command in commands if "pip" in command and "install" in command)
    assert "--isolated" in install
    assert "--find-links" not in install
    assert Path(install[-1]).is_absolute()
    assert install[-1].endswith("aoi_orgware-0.4.0-py3-none-any.whl")
    assert all(env["PIP_CONFIG_FILE"] == os.devnull for env in environments)
    assert all(env["PYTHONNOUSERSITE"] == "1" and env["PIP_NO_INDEX"] == "1" for env in environments)
    assert all(not any(name.startswith("PIP_") and name not in {"PIP_CONFIG_FILE", "PIP_DISABLE_PIP_VERSION_CHECK", "PIP_NO_INDEX"} for name in env) for env in environments)
    assert canonical_json_bytes(receipt) == json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@pytest.mark.parametrize("change, error", [
    (lambda value: value["urls"].pop(), "exactly match"),
    (lambda value: value["urls"].append(dict(value["urls"][0], filename="extra.whl")), "exactly match"),
    (lambda value: value["urls"].__setitem__(0, dict(value["urls"][0], filename="renamed.whl")), "exactly match"),
    (lambda value: value["urls"][0]["digests"].__setitem__("sha256", "0" * 64), "SHA-256"),
    (lambda value: value["urls"][0].__setitem__("size", 999), "size or SHA-256"),
    (lambda value: value["urls"][0].__setitem__("packagetype", "bdist_egg"), "package type"),
    (lambda value: value["info"].__setitem__("name", "another-project"), "project"),
    (lambda value: value["info"].__setitem__("version", "9.9.9"), "version"),
])
def test_pypi_metadata_mismatches_fail_closed(sealed, change, error) -> None:
    manifest, _, files = sealed
    document = _document(manifest, files)
    change(document)
    with pytest.raises(readback.ReleaseReadbackError, match=error):
        readback.validate_pypi_document(manifest, document)


def test_download_hash_and_observation_binding_fail_closed(sealed) -> None:
    manifest, observation, files = sealed
    document = _document(manifest, files)
    good, calls = _fetcher(document, {**files, "aoi_orgware-0.4.0-py3-none-any.whl": b"wrong bytes!!!!"})
    parsed = readback.validate_pypi_document(manifest, document)
    with pytest.raises(readback.ReleaseReadbackError, match="wrong size|SHA-256"):
        readback.download_exact_artifacts(manifest, parsed, good)
    broken = dict(observation); broken["observation_receipt_sha256"] = "0" * 64
    with pytest.raises(readback.ReleaseReadbackError, match="observation_receipt_sha256"):
        readback.readback_pypi_release(manifest, broken, promotion_id="pypi-0.4.0", observed_at="2026-07-19T01:02:03.000000Z", trusted_publisher_repository="Ryan529616/aoi-orgware", trusted_publisher_workflow="publish.yml", fetch=good)
    assert calls


def test_installed_metadata_and_hook_protocol_mismatch_fail_closed(sealed) -> None:
    manifest, _, files = sealed
    runner, _, _ = _runner(b"wrong metadata")
    with pytest.raises(readback.ReleaseReadbackError, match="metadata SHA-256"):
        readback.verify_isolated_install(manifest, files, runner=runner)


def test_integrity_provenance_is_presence_only_and_binds_exact_subject_and_publisher(sealed) -> None:
    manifest, _, files = sealed
    filename, raw = next(iter(files.items()))
    good = _provenance(filename, raw)
    evidence = readback.validate_integrity_provenance_presence(
        good,
        filename=filename,
        sha256=_sha(raw),
        trusted_publisher_repository="Ryan529616/aoi-orgware",
        trusted_publisher_workflow="publish.yml",
    )
    assert evidence["artifact_sha256"] == _sha(raw)
    assert evidence["evidence_strength"] == "presence_only"
    assert evidence["cryptographically_verified"] is False
    assert len(evidence["provenance_sha256"]) == 64
    for changed, match in (
        (_provenance(filename, raw, repository="other/repo"), "trusted publisher"),
        (_provenance(filename, raw, workflow="other.yml"), "trusted publisher"),
        (_provenance(filename, b"other"), "trusted publisher"),
        ({"version": 1, "attestation_bundles": []}, "missing attestations"),
    ):
        with pytest.raises(readback.ReleaseReadbackError, match=match):
            readback.validate_integrity_provenance_presence(
                changed,
                filename=filename,
                sha256=_sha(raw),
                trusted_publisher_repository="Ryan529616/aoi-orgware",
                trusted_publisher_workflow="publish.yml",
            )
    for field, value in (
        ("environment", "testpypi"),
        ("_type", "https://in-toto.io/Statement/v0"),
        ("predicate", {"unexpected": True}),
    ):
        changed = _provenance(filename, raw)
        if field == "environment":
            changed["attestation_bundles"][0]["publisher"][field] = value  # type: ignore[index]
        else:
            encoded = changed["attestation_bundles"][0]["attestations"][0]["envelope"]["statement"]  # type: ignore[index]
            statement = json.loads(readback.base64.b64decode(encoded))
            statement[field] = value
            changed["attestation_bundles"][0]["attestations"][0]["envelope"]["statement"] = readback.base64.b64encode(  # type: ignore[index]
                json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).decode("ascii")
        with pytest.raises(readback.ReleaseReadbackError, match="trusted publisher"):
            readback.validate_integrity_provenance_presence(
                changed,
                filename=filename,
                sha256=_sha(raw),
                trusted_publisher_repository="Ryan529616/aoi-orgware",
                trusted_publisher_workflow="publish.yml",
            )
    runner, _, _ = _runner(b"installed metadata", hook_version=7)
    with pytest.raises(readback.ReleaseReadbackError, match="hook protocol"):
        readback.verify_isolated_install(manifest, files, runner=runner)


def test_canonical_input_rejects_noncanonical_bytes(tmp_path: Path, sealed) -> None:
    manifest, _, _ = sealed
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    with pytest.raises(readback.ReleaseReadbackError, match="exact canonical"):
        readback.read_canonical_json_file(path, "manifest")


def test_canonical_input_uses_nofollow_descriptor_when_available(tmp_path: Path, sealed) -> None:
    manifest, _, _ = sealed
    path = tmp_path / "manifest.json"
    path.write_bytes(canonical_json_bytes(manifest))
    if not hasattr(readback.os, "O_NOFOLLOW"):
        pytest.skip("platform has no no-follow descriptor flag")
    original_open = readback.os.open
    flags: list[int] = []
    def checked_open(*args, **kwargs):
        flags.append(args[1])
        return original_open(*args, **kwargs)
    with mock.patch.object(readback.os, "open", side_effect=checked_open):
        assert readback.read_canonical_json_file(path, "manifest") == manifest
    assert flags and all(flag & readback.os.O_NOFOLLOW for flag in flags)


def test_direct_cli_help_bootstraps_source_checkout() -> None:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        cwd=SCRIPT.parents[1],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "--observation-result-file" in result.stdout
    assert "--manifest-file" not in result.stdout
