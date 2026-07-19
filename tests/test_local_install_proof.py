from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any
import zipfile

import pytest

from aoi_orgware import local_install_proof as proof


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], text=True, capture_output=True, check=True).stdout.strip()


def _write_inventory(store: Path) -> None:
    artifacts = []
    for path in sorted((store / "dist").iterdir(), key=lambda item: item.name):
        raw = path.read_bytes()
        artifacts.append({"name": path.name, "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    base = {"schema_version": 1, "distribution_name": "aoi-orgware", "package_version": "0.4.0a1", "artifacts": artifacts}
    (store / "evidence/inventory.json").write_bytes(proof._canonical({**base, "inventory_sha256": hashlib.sha256(proof._canonical(base)).hexdigest()}))


def _write_report(source: Path, store: Path) -> None:
    report = proof.create_rehearsal_report(source_root=source, store_root=store, inventory_path="evidence/inventory.json", producer_test_summary="9 passed, 2 skipped")
    # The report deliberately is not canonical: subject binds its raw evidence
    # digest while accepting a producer's normal pretty JSON output.
    (store / "evidence/rehearsal.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def _write_wheel(path: Path, *, with_record: bool = True) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        prefix = "aoi_orgware-0.4.0a1.dist-info"
        archive.writestr(f"{prefix}/METADATA", "Metadata-Version: 2.1\nName: aoi-orgware\nVersion: 0.4.0a1\n")
        archive.writestr(f"{prefix}/entry_points.txt", "[console_scripts]\naoi = aoi_orgware.cli:main\naoi-codex-hook = aoi_orgware.codex_hook:main\naoi-claude-hook = aoi_orgware.claude_hook:main\n")
        if with_record:
            archive.writestr(f"{prefix}/RECORD", "aoi_orgware/cli.py,,\n")
        archive.writestr("aoi_orgware/cli.py", 'HOOK_PROTOCOL_VERSION = "6"\n')


@pytest.fixture
def prepared(tmp_path: Path) -> tuple[Path, Path]:
    source, store = tmp_path / "source", tmp_path / "store"
    (source / "src/aoi_orgware").mkdir(parents=True); (source / "requirements").mkdir(); (store / "dist").mkdir(parents=True); (store / "evidence").mkdir()
    (source / "src/aoi_orgware/_version.py").write_text('__version__ = "0.4.0a1"\n', encoding="utf-8")
    (source / "README.md").write_text("fixture\n", encoding="utf-8")
    (source / "requirements/release-tools.lock").write_text("tool==1\n", encoding="utf-8")
    _git(source, "init"); _git(source, "config", "user.email", "fixture@example.invalid"); _git(source, "config", "user.name", "Fixture"); _git(source, "config", "core.autocrlf", "false")
    bare = tmp_path / "origin.git"; _git(tmp_path, "init", "--bare", str(bare)); _git(source, "remote", "add", "origin", str(bare)); _git(source, "add", "."); _git(source, "commit", "-m", "fixture")
    _write_wheel(store / "dist/aoi_orgware-0.4.0a1-py3-none-any.whl")
    (store / "dist/aoi_orgware-0.4.0a1.tar.gz").write_bytes(b"fixture sdist")
    (store / "evidence/source-file-manifest.json").write_bytes(proof._canonical(proof.create_source_manifest(source)))
    _write_inventory(store); _write_report(source, store)
    return source, store


def _bundle(source: Path, store: Path) -> tuple[dict[str, Any], Path]:
    subject = proof.create_subject(source_root=source, store_root=store, inventory_path="evidence/inventory.json", rehearsal_path="evidence/rehearsal.json")
    review = proof.create_review_assertion(subject=subject, reviewer="reviewer", reviewed_at="2026-07-19T12:34:56.000000Z", outcome="PASS", clean=True, limitations=["cooperative evidence"])
    bundle = proof.seal_bundle(source_root=source, store_root=store, subject=subject, review_assertion=review, sealed_at="2026-07-19T12:35:56.000000Z")
    path = store / "records/bundle.json"; path.parent.mkdir(); path.write_bytes(proof._canonical(bundle))
    return bundle, path


def test_subject_bundle_loader_contract_and_source_recheck(prepared: tuple[Path, Path]) -> None:
    source, store = prepared; bundle, path = _bundle(source, store)
    assert proof.verify_bundle(source_root=source, store_root=store, bundle=bundle, expected_sha256=bundle["bundle_sha256"])["ok"] is True
    loaded = proof.load_local_install_bundle(path, bundle["bundle_sha256"])
    contract = proof.local_install_contract(loaded, bundle_path=path)
    assert contract["artifact_store_root"] == str(store.resolve())
    assert contract["wheel"]["path"] == str((store / "dist/aoi_orgware-0.4.0a1-py3-none-any.whl").resolve())
    source.rename(source.with_name("source-not-present"))
    assert proof.load_local_install_bundle(path, bundle["bundle_sha256"])["bundle_sha256"] == bundle["bundle_sha256"]
    with pytest.raises(proof.LocalInstallProofError, match="differs from expected"):
        proof.load_local_install_bundle(path, "0" * 64)
    moved = store.with_name("relocated-store"); store.rename(moved)
    with pytest.raises(proof.LocalInstallProofError, match="cannot inspect artifact_store_root"):
        proof.load_local_install_bundle(moved / "records/bundle.json", bundle["bundle_sha256"])


def test_manifest_and_clean_head_rules_fail_closed(prepared: tuple[Path, Path]) -> None:
    source, store = prepared; manifest_path = store / "evidence/source-file-manifest.json"; manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"] = manifest["files"][:-1]; manifest["source_file_count"] -= 1; manifest_path.write_bytes(proof._canonical(manifest))
    with pytest.raises(proof.LocalInstallProofError, match="count does not match"):
        proof.create_subject(source_root=source, store_root=store, inventory_path="evidence/inventory.json", rehearsal_path="evidence/rehearsal.json")
    manifest_path.write_bytes(proof._canonical(proof.create_source_manifest(source)))
    alias = source.parent / "store-alias"
    try:
        os.symlink(store, alias, target_is_directory=True)
    except OSError:
        pass
    else:
        with pytest.raises(proof.LocalInstallProofError, match="canonical non-linked"):
            proof.create_subject(source_root=source, store_root=alias, inventory_path="evidence/inventory.json", rehearsal_path="evidence/rehearsal.json")
    (source / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(proof.LocalInstallProofError, match="not clean"):
        proof.create_source_manifest(source)
    (source / "untracked.txt").unlink()
    version = source / "src/aoi_orgware/_version.py"; version.write_text('__version__ = "0.4.0a1"\n# changed\n', encoding="utf-8")
    with pytest.raises(proof.LocalInstallProofError, match="not clean|bytes do not match"):
        proof.create_subject(source_root=source, store_root=store, inventory_path="evidence/inventory.json", rehearsal_path="evidence/rehearsal.json")
    _git(source, "add", "src/aoi_orgware/_version.py"); _git(source, "commit", "-m", "changed source")
    with pytest.raises(proof.LocalInstallProofError, match="bytes do not match clean HEAD"):
        proof.create_subject(source_root=source, store_root=store, inventory_path="evidence/inventory.json", rehearsal_path="evidence/rehearsal.json")


def test_source_and_store_must_be_external_in_both_directions(prepared: tuple[Path, Path]) -> None:
    source, _store = prepared
    with pytest.raises(proof.LocalInstallProofError, match="must not contain source root"):
        proof.create_subject(
            source_root=source,
            store_root=source.parent,
            inventory_path="unused.json",
            rehearsal_path="unused.json",
        )
    nested_store = source / "nested-store"
    nested_store.mkdir()
    with pytest.raises(proof.LocalInstallProofError, match="must be outside source root"):
        proof.create_subject(
            source_root=source,
            store_root=nested_store,
            inventory_path="unused.json",
            rehearsal_path="unused.json",
        )


def test_report_raw_binding_and_wheel_interface_rejects_missing_record(prepared: tuple[Path, Path]) -> None:
    source, store = prepared; subject = proof.create_subject(source_root=source, store_root=store, inventory_path="evidence/inventory.json", rehearsal_path="evidence/rehearsal.json")
    report_path = store / "evidence/rehearsal.json"; report = json.loads(report_path.read_text(encoding="utf-8")); del report["observations"]["artifact_inventory_bytes"]; report_path.write_text(json.dumps(report, indent=3), encoding="utf-8")
    with pytest.raises(proof.LocalInstallProofError, match="unexpected or missing"):
        proof.create_subject(source_root=source, store_root=store, inventory_path="evidence/inventory.json", rehearsal_path="evidence/rehearsal.json")
    _write_report(source, store)
    report = json.loads((store / "evidence/rehearsal.json").read_text(encoding="utf-8")); (store / "evidence/rehearsal.json").write_text(json.dumps(report, indent=4) + "\n", encoding="utf-8")
    review = proof.create_review_assertion(subject=subject, reviewer="reviewer", reviewed_at="2026-07-19T12:34:56.000000Z", outcome="PASS", clean=True, limitations=["cooperative"])
    with pytest.raises(proof.LocalInstallProofError, match="changed since subject"):
        proof.seal_bundle(source_root=source, store_root=store, subject=subject, review_assertion=review, sealed_at="2026-07-19T12:35:56.000000Z")
    _write_wheel(store / "dist/aoi_orgware-0.4.0a1-py3-none-any.whl", with_record=False); _write_inventory(store); _write_report(source, store)
    with pytest.raises(proof.LocalInstallProofError, match="lacks unique"):
        proof.create_subject(source_root=source, store_root=store, inventory_path="evidence/inventory.json", rehearsal_path="evidence/rehearsal.json")


def test_wheel_interface_bounds_are_checked_before_extraction(prepared: tuple[Path, Path]) -> None:
    source, store = prepared
    wheel = store / "dist/aoi_orgware-0.4.0a1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        prefix = "aoi_orgware-0.4.0a1.dist-info"
        archive.writestr(f"{prefix}/METADATA", "Metadata-Version: 2.1\nName: aoi-orgware\nVersion: 0.4.0a1\n")
        archive.writestr(f"{prefix}/entry_points.txt", "[console_scripts]\naoi = aoi_orgware.cli:main\naoi-codex-hook = aoi_orgware.codex_hook:main\naoi-claude-hook = aoi_orgware.claude_hook:main\n")
        archive.writestr(f"{prefix}/RECORD", b"x" * (4 * 1024 * 1024 + 1))
        archive.writestr("aoi_orgware/cli.py", 'HOOK_PROTOCOL_VERSION = "6"\n')
    _write_inventory(store)
    _write_report(source, store)
    with pytest.raises(proof.LocalInstallProofError, match="interface member exceeds byte bound"):
        proof.create_subject(
            source_root=source,
            store_root=store,
            inventory_path="evidence/inventory.json",
            rehearsal_path="evidence/rehearsal.json",
        )


def test_strong_verify_requires_caller_trust_anchor(prepared: tuple[Path, Path]) -> None:
    source, store = prepared
    bundle, _path = _bundle(source, store)
    with pytest.raises(TypeError):
        proof.verify_bundle(  # type: ignore[call-arg]
            source_root=source,
            store_root=store,
            bundle=bundle,
        )


def test_cli_create_only_producers_and_verify_without_source(prepared: tuple[Path, Path]) -> None:
    source, store = prepared; script = Path(__file__).resolve().parents[1] / "scripts/local_install_bundle.py"; common = [sys.executable, str(script)]
    def run(*args: str) -> dict[str, Any]:
        return json.loads(subprocess.run([*common, *args], text=True, capture_output=True, check=True).stdout)
    manifest = store / "evidence/cli-source-manifest.json"
    assert run("source-manifest", "--source-root", str(source), "--output", str(manifest))["source_file_count"] > 0
    with pytest.raises(subprocess.CalledProcessError):
        run("source-manifest", "--source-root", str(source), "--output", str(manifest))
    records = store / "records"; subject = records / "subject.json"; review = records / "review.json"; bundle_path = records / "bundle.json"
    generated_report = records / "rehearsal-generated.json"
    generated = run("rehearsal-report", "--source-root", str(source), "--store-root", str(store), "--inventory", "evidence/inventory.json", "--producer-test-summary", "9 passed, 2 skipped", "--output", str(generated_report))
    assert generated["observations"]["artifact_inventory_bytes"] == "verified"
    assert generated["limitations"][1] == "source_identity_does_not_attest_source_to_wheel_derivation"
    observed_subject = run("subject", "--source-root", str(source), "--store-root", str(store), "--inventory", "evidence/inventory.json", "--rehearsal", "evidence/rehearsal.json", "--output", str(subject))
    run("review", "--subject-file", str(subject), "--reviewer", "reviewer", "--reviewed-at", "2026-07-19T12:34:56.000000Z", "--outcome", "PASS", "--clean", "--limitation", "cooperative", "--output", str(review))
    bundle = run("seal", "--source-root", str(source), "--store-root", str(store), "--subject-file", str(subject), "--review-file", str(review), "--sealed-at", "2026-07-19T12:35:56.000000Z", "--output", str(bundle_path))
    assert run("verify", "--bundle-file", str(bundle_path), "--expected-sha256", str(bundle["bundle_sha256"]))["subject_sha256"] == observed_subject["subject_sha256"]


def test_cli_create_only_rejects_linked_ancestor_before_mkdir(prepared: tuple[Path, Path]) -> None:
    source, store = prepared
    outside = store.parent / "outside"
    outside.mkdir()
    alias = store.parent / "output-link"
    try:
        os.symlink(outside, alias, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")
    output = alias / "must-not-be-created" / "manifest.json"
    script = Path(__file__).resolve().parents[1] / "scripts/local_install_bundle.py"
    completed = subprocess.run(
        [sys.executable, str(script), "source-manifest", "--source-root", str(source), "--output", str(output)],
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 1
    assert "canonical non-linked directory" in completed.stderr
    assert not (outside / "must-not-be-created").exists()
