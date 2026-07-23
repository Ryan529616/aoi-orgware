"""Focused tests for standalone publication-policy snapshots and gate receipts."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

import pytest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware.config import ConfidentialityConfig, ProtectedPathRule  # noqa: E402
from aoi_orgware.publication_gate import (  # noqa: E402
    PublicationGateError,
    preflight_publication_snapshot,
    validate_publication_receipt,
    verify_publication_receipt,
)
from aoi_orgware.publication_policy import (  # noqa: E402
    PublicationPolicyError,
    build_publication_policy_snapshot,
    canonical_publication_policy_snapshot_bytes,
    load_publication_policy_snapshot,
    require_current_publication_policy_snapshot,
    validate_publication_policy_snapshot,
)


CONFIG_SHA = hashlib.sha256(b"explicit config bytes").hexdigest()


def _policy(*rules: ProtectedPathRule) -> ConfidentialityConfig:
    return ConfidentialityConfig(
        mode="local_files",
        model_context="allowed",
        git_push="deny",
        remote_ci="deny",
        artifact_upload="deny",
        external_export="permit_required",
        local_cas=True,
        protected=rules,
    )


def _tar(path: Path, entries: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


def test_empty_snapshot_works_without_aoi_toml(tmp_path: Path) -> None:
    root = tmp_path / "clean"
    root.mkdir()
    subject = root / "artifact.txt"
    subject.write_bytes(b"public")
    snapshot = build_publication_policy_snapshot(root, _policy(), CONFIG_SHA)

    assert not (root / "aoi.toml").exists()
    receipt = preflight_publication_snapshot(
        snapshot=snapshot,
        root=root,
        action="package_publish",
        destination="https://upload.pypi.org/legacy/",
        subjects=[subject],
    )
    assert receipt["decision"] == "allowed"
    assert receipt["protected_exposures"] == []


def test_snapshot_resolves_ascii_case_variant_protected_origin(tmp_path: Path) -> None:
    root = tmp_path / "project"
    protected = root / "Private" / "Secret.bin"
    protected.parent.mkdir(parents=True)
    protected.write_bytes(b"ASCII case variant")

    snapshot = build_publication_policy_snapshot(
        root,
        _policy(ProtectedPathRule("private/secret.bin", "file", "local_only")),
        CONFIG_SHA,
    )
    assert snapshot["protected_content"] == [
        {
            "rule_path": "private/secret.bin",
            "path": "Private/Secret.bin",
            "sha256": hashlib.sha256(b"ASCII case variant").hexdigest(),
            "size_bytes": len(b"ASCII case variant"),
        }
    ]


def test_snapshot_keeps_non_ascii_case_expansions_distinct(tmp_path: Path) -> None:
    root = tmp_path / "project"
    private = root / "private"
    private.mkdir(parents=True)
    sharp_s = private / "Straße.bin"
    expanded = private / "STRASSE.bin"
    sharp_s.write_bytes(b"sharp-s")
    expanded.write_bytes(b"expanded")
    if sharp_s.samefile(expanded):
        pytest.skip("filesystem aliases the non-ASCII spellings")

    snapshot = build_publication_policy_snapshot(
        root,
        _policy(
            ProtectedPathRule("private/Straße.bin", "file", "local_only"),
            ProtectedPathRule("private/STRASSE.bin", "file", "local_only"),
        ),
        CONFIG_SHA,
    )
    assert {row["path"] for row in snapshot["protected_rules"]} == {
        "private/Straße.bin",
        "private/STRASSE.bin",
    }
    assert {row["path"] for row in snapshot["protected_content"]} == {
        "private/Straße.bin",
        "private/STRASSE.bin",
    }


@pytest.mark.parametrize(
    "rules",
    (
        (
            ProtectedPathRule("a", "tree", "local_only"),
            ProtectedPathRule("a-", "file", "local_only"),
            ProtectedPathRule("a/b", "file", "local_only"),
        ),
        (
            ProtectedPathRule("a", "file", "local_only"),
            ProtectedPathRule("a/b", "file", "local_only"),
        ),
    ),
)
def test_snapshot_rejects_every_config_overlapping_rule_pair(
    tmp_path: Path,
    rules: tuple[ProtectedPathRule, ...],
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    with pytest.raises(PublicationPolicyError, match="overlap or duplicate"):
        build_publication_policy_snapshot(root, _policy(*rules), CONFIG_SHA)


def test_publication_gate_does_not_unicode_casefold_rule_paths(tmp_path: Path) -> None:
    root = tmp_path / "project"
    private = root / "private"
    private.mkdir(parents=True)
    protected = private / "Straße.bin"
    public = private / "STRASSE.bin"
    protected.write_bytes(b"protected sharp-s")
    public.write_bytes(b"separate public bytes")
    if protected.samefile(public):
        pytest.skip("filesystem aliases the non-ASCII spellings")
    snapshot = build_publication_policy_snapshot(
        root,
        _policy(ProtectedPathRule("private/Straße.bin", "file", "local_only")),
        CONFIG_SHA,
    )

    receipt = preflight_publication_snapshot(
        snapshot=snapshot,
        root=root,
        action="artifact_upload",
        destination="https://example.invalid/upload",
        subjects=[public],
    )
    assert receipt["decision"] == "allowed"
    assert receipt["protected_exposures"] == []


def test_snapshot_and_gate_support_exact_cjk_protected_path(tmp_path: Path) -> None:
    root = tmp_path / "project"
    protected = root / "私密" / "檔案.bin"
    protected.parent.mkdir(parents=True)
    protected.write_bytes(b"exact CJK path")
    snapshot = build_publication_policy_snapshot(
        root,
        _policy(ProtectedPathRule("私密/檔案.bin", "file", "local_only")),
        CONFIG_SHA,
    )

    receipt = preflight_publication_snapshot(
        snapshot=snapshot,
        root=root,
        action="artifact_upload",
        destination=str(root / "local-destination"),
        subjects=[protected],
    )
    assert receipt["decision"] == "allowed"
    assert receipt["protected_exposures"][0]["rule_path"] == "私密/檔案.bin"


def test_renamed_archive_member_with_protected_digest_is_denied(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    private = root / "private"
    private.mkdir()
    secret = private / "secret.txt"
    secret.write_bytes(b"not for PyPI")
    snapshot = build_publication_policy_snapshot(
        root,
        _policy(ProtectedPathRule("private/secret.txt", "file", "local_only")),
        CONFIG_SHA,
    )
    archive = root / "package.tar.gz"
    _tar(archive, {"pkg-1.0/renamed.txt": secret.read_bytes()})

    with pytest.raises(PublicationGateError, match="protected"):
        preflight_publication_snapshot(
            snapshot=snapshot,
            root=root,
            action="package_publish",
            destination="https://upload.pypi.org/legacy/",
            subjects=[archive],
        )


def test_missing_malformed_stale_and_self_digest_snapshots_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    secret = root / "private.txt"
    secret.write_bytes(b"first")
    snapshot = build_publication_policy_snapshot(
        root,
        _policy(ProtectedPathRule("private.txt", "file", "local_only")),
        CONFIG_SHA,
    )
    with pytest.raises(PublicationPolicyError, match="cannot inspect"):
        load_publication_policy_snapshot(root / "missing.json")
    with pytest.raises(PublicationPolicyError, match="schema"):
        validate_publication_policy_snapshot({})
    tampered = dict(snapshot)
    tampered["mode"] = "standard"
    with pytest.raises(PublicationPolicyError, match="rules|digest"):
        validate_publication_policy_snapshot(tampered)
    boolean_version = dict(snapshot)
    boolean_version["schema_version"] = True
    with pytest.raises(PublicationPolicyError, match="version"):
        validate_publication_policy_snapshot(boolean_version)
    boolean_count = dict(snapshot)
    boolean_count["protected_content_count"] = False
    with pytest.raises(PublicationPolicyError, match="count"):
        validate_publication_policy_snapshot(boolean_count)

    secret.write_bytes(b"second")
    with pytest.raises(PublicationPolicyError, match="stale"):
        require_current_publication_policy_snapshot(
            root, _policy(ProtectedPathRule("private.txt", "file", "local_only")),
            CONFIG_SHA, snapshot,
        )


def test_remote_gate_uses_snapshot_when_local_only_origin_is_absent(
    tmp_path: Path,
) -> None:
    local = tmp_path / "local"
    local.mkdir()
    secret = local / "private.txt"
    secret.write_bytes(b"local-only")
    snapshot = build_publication_policy_snapshot(
        local,
        _policy(ProtectedPathRule("private.txt", "file", "local_only")),
        CONFIG_SHA,
    )
    remote = tmp_path / "clean-checkout"
    remote.mkdir()
    public = remote / "public.txt"
    public.write_bytes(b"public")
    assert not (remote / "private.txt").exists()

    receipt = preflight_publication_snapshot(
        snapshot=snapshot,
        root=remote,
        action="artifact_upload",
        destination="https://example.invalid/upload",
        subjects=[public],
    )
    assert receipt["decision"] == "allowed"


def test_protected_tree_entry_and_aggregate_byte_bounds_fail_before_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import aoi_orgware.publication_policy as policy_module

    root = tmp_path / "project"
    tree = root / "private"
    tree.mkdir(parents=True)
    (tree / "a.bin").write_bytes(b"aa")
    (tree / "b.bin").write_bytes(b"bb")
    rule = ProtectedPathRule("private", "tree", "local_only")

    monkeypatch.setattr(policy_module, "MAX_PROTECTED_TREE_ENTRIES", 1)
    with pytest.raises(PublicationPolicyError, match="entry-count"):
        build_publication_policy_snapshot(root, _policy(rule), CONFIG_SHA)

    monkeypatch.setattr(policy_module, "MAX_PROTECTED_TREE_ENTRIES", 10)
    monkeypatch.setattr(policy_module, "MAX_PROTECTED_TOTAL_BYTES", 3)
    with pytest.raises(PublicationPolicyError, match="total-byte"):
        build_publication_policy_snapshot(root, _policy(rule), CONFIG_SHA)

    snapshot = build_publication_policy_snapshot(
        root,
        _policy(),
        CONFIG_SHA,
    )
    oversized = dict(snapshot)
    oversized["protected_rules"] = [
        {
            "path": "private/a.bin",
            "kind": "file",
            "policy": "local_only",
            "home_remote": None,
            "home_destination": None,
        },
        {
            "path": "private/b.bin",
            "kind": "file",
            "policy": "local_only",
            "home_remote": None,
            "home_destination": None,
        },
    ]
    oversized["protected_rule_count"] = 2
    oversized["protected_policy_sha256"] = hashlib.sha256(
        json.dumps(
            {"protected_rules": oversized["protected_rules"]},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    oversized["protected_content"] = [
        {
            "rule_path": row["path"],
            "path": row["path"],
            "sha256": "0" * 64,
            "size_bytes": 2,
        }
        for row in oversized["protected_rules"]
    ]
    oversized["protected_content_count"] = 2
    base = {key: value for key, value in oversized.items() if key != "snapshot_sha256"}
    oversized["snapshot_sha256"] = hashlib.sha256(
        json.dumps(base, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    with pytest.raises(PublicationPolicyError, match="total-byte"):
        validate_publication_policy_snapshot(oversized)


def test_receipt_recompute_and_tamper_detection(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    subject = root / "artifact.bin"
    subject.write_bytes(b"exact artifact")
    snapshot = build_publication_policy_snapshot(root, _policy(), CONFIG_SHA)
    receipt = preflight_publication_snapshot(
        snapshot=snapshot,
        root=root,
        action="artifact_upload",
        destination="https://example.invalid/upload",
        subjects=[subject],
    )
    assert verify_publication_receipt(
        snapshot=snapshot,
        receipt=receipt,
        root=root,
        action="artifact_upload",
        destination="https://example.invalid/upload",
        subjects=[subject],
    ) == receipt
    tampered = dict(receipt)
    tampered["decision"] = "denied"
    with pytest.raises(PublicationGateError, match="identity|self-digest"):
        validate_publication_receipt(tampered)


def test_sidecar_receipt_survives_copy_and_exact_reverification(
    tmp_path: Path,
) -> None:
    producer = tmp_path / "producer"
    stage = producer / "stage"
    stage.mkdir(parents=True)
    (stage / "artifact.bin").write_bytes(b"exact payload")
    snapshot = build_publication_policy_snapshot(producer, _policy(), CONFIG_SHA)
    receipt = preflight_publication_snapshot(
        snapshot=snapshot,
        root=producer,
        action="artifact_upload",
        destination="https://example.invalid/upload",
        subjects=[stage],
    )
    # The sidecar is intentionally created only after payload inventory.  It is
    # transported with the envelope but is not recursively part of its own
    # content-addressed subject set.
    sidecar = stage / "publication-receipt.json"
    sidecar.write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    consumer = tmp_path / "consumer"
    shutil.copytree(stage, consumer / "stage")
    supplied = consumer / "publication-receipt.json"
    (consumer / "stage" / "publication-receipt.json").replace(supplied)
    assert verify_publication_receipt(
        snapshot=snapshot,
        receipt=json.loads(supplied.read_text(encoding="utf-8")),
        root=consumer,
        action="artifact_upload",
        destination="https://example.invalid/upload",
        subjects=[consumer / "stage"],
    ) == receipt


def test_local_only_and_home_remote_only_destination_semantics(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    local_file = root / "local.txt"
    home_file = root / "home.txt"
    local_file.write_bytes(b"local")
    home_file.write_bytes(b"home")
    local_snapshot = build_publication_policy_snapshot(
        root,
        _policy(ProtectedPathRule("local.txt", "file", "local_only")),
        CONFIG_SHA,
    )
    allowed = preflight_publication_snapshot(
        snapshot=local_snapshot,
        root=root,
        action="artifact_upload",
        destination=str(root / "local-destination"),
        subjects=[local_file],
    )
    assert allowed["protected_exposures"][0]["rule_policy"] == "local_only"
    with pytest.raises(PublicationGateError, match="protected"):
        preflight_publication_snapshot(
            snapshot=local_snapshot,
            root=root,
            action="artifact_upload",
            destination="https://example.invalid/upload",
            subjects=[local_file],
        )

    home_snapshot = build_publication_policy_snapshot(
        root,
        _policy(
            ProtectedPathRule(
                "home.txt", "file", "home_remote_only", "origin",
                "https://home.example/team/private.git",
            )
        ),
        CONFIG_SHA,
    )
    with pytest.raises(PublicationGateError, match="protected"):
        preflight_publication_snapshot(
            snapshot=home_snapshot,
            root=root,
            action="artifact_upload",
            # Caller-supplied repository metadata cannot relabel an artifact
            # upload as the separately governed outgoing-commit Git boundary.
            remote="origin",
            destination="https://home.example/team/private.git",
            subjects=[home_file],
        )
    with pytest.raises(PublicationGateError, match="action"):
        preflight_publication_snapshot(
            snapshot=home_snapshot,
            root=root,
            action="git_push",
            remote="origin",
            destination="https://home.example/team/private.git",
            subjects=[home_file],
        )


def test_snapshot_file_round_trip_is_strict(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    snapshot = build_publication_policy_snapshot(root, _policy(), CONFIG_SHA)
    path = root / "snapshot.json"
    path.write_bytes(canonical_publication_policy_snapshot_bytes(snapshot))
    assert load_publication_policy_snapshot(path) == snapshot
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    with pytest.raises(PublicationPolicyError, match="canonical"):
        load_publication_policy_snapshot(path)


def test_module_cli_preflight_and_verify(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    subject = root / "artifact.txt"
    subject.write_bytes(b"artifact")
    snapshot_path = root / "snapshot.json"
    snapshot_path.write_bytes(
        canonical_publication_policy_snapshot_bytes(
            build_publication_policy_snapshot(root, _policy(), CONFIG_SHA)
        )
    )
    command = [
        sys.executable, "-m", "aoi_orgware.publication_gate", "preflight",
        "--policy-snapshot", str(snapshot_path),
        "--expected-snapshot-sha256",
        build_publication_policy_snapshot(root, _policy(), CONFIG_SHA)["snapshot_sha256"],
        "--action", "artifact_upload",
        "--destination", "https://example.invalid/upload", "--subject", str(subject), "--json",
    ]
    environment = {**os.environ, "PYTHONPATH": str(HERE.parent / "src")}
    first = subprocess.run(command, cwd=root, env=environment, text=True, capture_output=True, check=True)
    receipt_path = root / "receipt.json"
    receipt_path.write_bytes(first.stdout.encode("utf-8"))
    verified = subprocess.run(
        [*command[:3], "verify", *command[4:], "--receipt", str(receipt_path)],
        cwd=root, env=environment, text=True, capture_output=True, check=True,
    )
    assert json.loads(verified.stdout) == json.loads(first.stdout)
