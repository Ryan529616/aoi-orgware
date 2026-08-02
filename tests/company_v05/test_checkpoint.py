from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from aoi_orgware.company.blobs import BlobStore
from aoi_orgware.company.checkpoint import (
    CompanyCheckpointError,
    verify_plain_checkpoint,
    write_plain_checkpoint,
)
from aoi_orgware.company.contracts import (
    ACTOR_AUTHORITY_V1,
    BLOB_REF_V1,
    COMPANY_EVENT_V1,
    COMPANY_MANIFEST_V1,
    COMPANY_TRANSACTION_REQUEST_V1,
    EXPECTED_HEAD_V1,
    EXPECTED_TRANSACTION_HEAD_V1,
    ZERO_SHA256,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.ledger import CompanyLedger
from aoi_orgware.company.state import CompanyStateOwner


T = "2026-07-27T00:00:00Z"


def manifest() -> dict[str, object]:
    return {
        "contract_type": COMPANY_MANIFEST_V1, "schema_version": 1,
        "company_id": "company-1", "company_incarnation": 1,
        "lock_domain_generation": 1, "git_common_dir_sha256": "a" * 64,
        "remote_fingerprint_sha256": "b" * 64, "configuration_sha256": "c" * 64,
        "state_root_sha256": "d" * 64, "lock_domain_id": "windows" if os.name == "nt" else "posix",
        "created_at": T, "observation": {"state": "known", "reason": "observed"},
    }


def authority() -> dict[str, object]:
    return {
        "contract_type": ACTOR_AUTHORITY_V1, "schema_version": 1,
        "company_id": "company-1", "company_incarnation": 1, "lock_domain_generation": 1,
        "actor_id": "chief-1", "actor_kind": "chief", "carrier_id": "carrier-1",
        "chief_epoch": 1, "term": 1, "authority_state": "active", "permissions": ["company.mutate"],
        "scope_sha256": "a" * 64, "authority_record_sha256": "b" * 64, "provenance": "AOI_verified",
    }


def request(owner: CompanyStateOwner, blob: dict[str, object], index: int = 1) -> dict[str, object]:
    heads = owner.heads()
    binding = {"company_id": "company-1", "company_incarnation": 1, "lock_domain_generation": 1}
    cursor, event_sha256 = heads.stream_heads.get("org", (0, ZERO_SHA256))
    event = {
        "contract_type": COMPANY_EVENT_V1, "schema_version": 1, **binding,
        "transaction_id": f"tx-{index}", "command_id": f"cmd-{index}", "event_id": f"event-{index}", "stream": "org",
        "event_type": "recorded", "recorded_at": T, "actor_authority": authority(), "provenance": "AOI_verified",
        "payload": manifest(), "payload_sha256": company_contract_sha256(manifest()),
    }
    value = {
        "contract_type": COMPANY_TRANSACTION_REQUEST_V1, "schema_version": 1, **binding,
        "transaction_id": f"tx-{index}", "command_id": f"cmd-{index}", "actor_authority": authority(),
        "expected_transaction_head": {
            "contract_type": EXPECTED_TRANSACTION_HEAD_V1, "schema_version": 1, **binding,
            "transaction_id": f"tx-{index}", "command_id": f"cmd-{index}", "global_sequence": heads.global_head.global_sequence,
            "transaction_sha256": heads.global_head.transaction_sha256,
        },
        "expected_heads": [{
            "contract_type": EXPECTED_HEAD_V1, "schema_version": 1, **binding,
            "transaction_id": f"tx-{index}", "command_id": f"cmd-{index}", "stream": "org", "cursor": cursor,
            "event_sha256": event_sha256,
        }], "events": [event],
    }
    value["request_sha256"] = company_contract_sha256(value)
    return value


def initialized(tmp_path: Path) -> CompanyStateOwner:
    owner = CompanyStateOwner.initialize(tmp_path / "company", manifest(), platform="windows" if os.name == "nt" else "posix")
    metadata = owner.blobs.put(b"checkpoint evidence")
    blob = {"contract_type": BLOB_REF_V1, "schema_version": 1, "sha256": metadata.sha256, "size_bytes": metadata.size_bytes, "media_type": "text/plain", "availability": "available"}
    owner.commit(request(owner, blob), evidence=[copy.deepcopy(blob)], recorded_at=T)
    return owner


def raw_write(
    owner: CompanyStateOwner,
    blobs: BlobStore,
    checkpoint_id: str,
    generated_at: str = T,
) -> str:
    with CompanyLedger(owner.resolved.incarnation.ledger) as ledger:
        return write_plain_checkpoint(lock=owner.lock, resolved=owner.resolved, ledger=ledger, blobs=blobs, checkpoint_id=checkpoint_id, generated_at=generated_at)


def write(owner: CompanyStateOwner, name: str = "cp-1", generated_at: str = T) -> str:
    return raw_write(owner, owner.blobs, name, generated_at)


def tree(path: Path) -> dict[str, str]:
    return {item.relative_to(path).as_posix(): company_contract_sha256({"bytes": item.read_bytes().hex()}) for item in path.rglob("*") if item.is_file()}


def test_reopen_continue(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    digest = write(owner)
    checkpoint = owner.resolved.incarnation.checkpoints / "cp-1"
    assert verify_plain_checkpoint(checkpoint).sha256 == digest
    assert not list(checkpoint.rglob("readmodel.sqlite3"))
    assert not [item for item in checkpoint.rglob("*") if item.name.endswith(("-wal", "-shm"))]
    owner.close()
    reopened = CompanyStateOwner.open(tmp_path / "company")
    assert reopened.heads().global_head.global_sequence == 1
    metadata = reopened.blobs.put(b"source remains writable")
    blob = {"contract_type": BLOB_REF_V1, "schema_version": 1, "sha256": metadata.sha256, "size_bytes": metadata.size_bytes, "media_type": "text/plain", "availability": "available"}
    reopened.commit(request(reopened, blob, 2), evidence=[copy.deepcopy(blob)], recorded_at=T)
    assert reopened.heads().global_head.global_sequence == 2
    reopened.close()


@pytest.mark.parametrize("member", ["ledger.sqlite3", "manifest.json", "current.json"])
def test_tamper_missing_and_extra_are_rejected_without_verifier_mutation(tmp_path: Path, member: str) -> None:
    owner = initialized(tmp_path)
    write(owner)
    checkpoint = owner.resolved.incarnation.checkpoints / "cp-1"
    before = tree(checkpoint)
    path = checkpoint / member
    path.unlink()
    with pytest.raises(CompanyCheckpointError):
        verify_plain_checkpoint(checkpoint)
    assert tree(checkpoint) == {key: value for key, value in before.items() if key != member}
    owner.close()


def test_extra_link_pointer_manifest_blob_and_collision_fail(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    digest = write(owner)
    assert write(owner) == digest
    checkpoint = owner.resolved.incarnation.checkpoints / "cp-1"
    (checkpoint / "extra").write_bytes(b"x")
    with pytest.raises(CompanyCheckpointError):
        verify_plain_checkpoint(checkpoint)
    with pytest.raises(CompanyCheckpointError):
        write(owner)
    owner.close()


def test_manifest_cannot_authorize_an_extra_ordinary_member(
    tmp_path: Path,
) -> None:
    owner = initialized(tmp_path)
    write(owner)
    checkpoint = owner.resolved.incarnation.checkpoints / "cp-1"
    extra = checkpoint / "operator-note.txt"
    extra.write_bytes(b"not part of the checkpoint contract")
    manifest_path = checkpoint / "checkpoint-manifest.json"
    document = json.loads(manifest_path.read_bytes())
    document["members"].append({
        "path": extra.name,
        "sha256": hashlib.sha256(extra.read_bytes()).hexdigest(),
        "size_bytes": extra.stat().st_size,
        "kind": extra.name,
    })
    document["members"].sort(key=lambda item: item["path"])
    manifest_path.write_bytes(canonical_company_json_bytes(document))
    with pytest.raises(
        CompanyCheckpointError,
        match="invalid member|ordinary member inventory",
    ):
        verify_plain_checkpoint(checkpoint)
    owner.close()


@pytest.mark.parametrize("member", ["ledger.sqlite3", "manifest.json", "current.json", "blob"])
def test_tamper_is_rejected_without_verifier_mutation(tmp_path: Path, member: str) -> None:
    owner = initialized(tmp_path)
    write(owner)
    checkpoint = owner.resolved.incarnation.checkpoints / "cp-1"
    path = next(checkpoint.glob("blobs/*/*/*")) if member == "blob" else checkpoint / member
    raw = path.read_bytes()
    path.write_bytes((raw[:-1] + bytes([raw[-1] ^ 1])) if raw else b"x")
    before = tree(checkpoint)
    with pytest.raises(CompanyCheckpointError):
        verify_plain_checkpoint(checkpoint)
    assert tree(checkpoint) == before
    owner.close()


def test_link_and_existing_empty_directory_collision_are_rejected(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    checkpoint_root = owner.resolved.incarnation.checkpoints
    checkpoint = checkpoint_root / "cp-link"
    digest = write(owner, "cp-link")
    assert digest
    try:
        os.symlink(checkpoint / "ledger.sqlite3", checkpoint / "ledger-link")
    except OSError as exc:
        pytest.skip(f"symlink privilege unavailable: {exc}")
    with pytest.raises(CompanyCheckpointError):
        verify_plain_checkpoint(checkpoint)
    existing = checkpoint_root / "cp-empty"
    existing.mkdir()
    with pytest.raises(CompanyCheckpointError):
        write(owner, "cp-empty")
    assert existing.is_dir() and not list(existing.iterdir())
    owner.close()


def test_divergent_checkpoint_id_collision_is_rejected(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    write(owner)
    with pytest.raises(CompanyCheckpointError):
        write(owner, generated_at="2026-07-27T00:00:01Z")
    owner.close()


def test_invalid_manifest_and_failure_cleanup(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    with pytest.raises(CompanyCheckpointError):
        raw_write(owner, BlobStore(tmp_path / "other-blobs"), "cp-bad")
    checkpoints = owner.resolved.incarnation.checkpoints
    assert not (checkpoints / "cp-bad").exists()
    assert not list(checkpoints.glob(".c-*"))
    owner.close()


def test_sources_require_active_incarnation(
    tmp_path: Path,
) -> None:
    owner = initialized(tmp_path)
    foreign_ledger = CompanyLedger(tmp_path / "foreign" / "ledger.sqlite3")
    try:
        with pytest.raises(
            CompanyCheckpointError,
            match="source storage differs",
        ):
            write_plain_checkpoint(
                lock=owner.lock,
                resolved=owner.resolved,
                ledger=foreign_ledger,
                blobs=owner.blobs,
                checkpoint_id="cp-foreign-ledger",
                generated_at=T,
            )
        with pytest.raises(
            CompanyCheckpointError,
            match="source storage differs",
        ):
            raw_write(
                owner, BlobStore(tmp_path / "foreign-blobs"), "cp-foreign-blobs",
            )
    finally:
        foreign_ledger.close()
        owner.close()


def test_company_genesis_is_required_before_checkpoint(
    tmp_path: Path,
) -> None:
    owner = CompanyStateOwner.initialize(
        tmp_path / "empty-company",
        manifest(),
        platform="windows" if os.name == "nt" else "posix",
    )
    try:
        with pytest.raises(
            CompanyCheckpointError,
            match="genesis transaction is required",
        ):
            raw_write(owner, owner.blobs, "cp-before-genesis")
    finally:
        owner.close()


def test_oversized_ledger_is_rejected_before_streaming(
    tmp_path: Path,
) -> None:
    owner = initialized(tmp_path)
    write(owner)
    ledger_path = (
        owner.resolved.incarnation.checkpoints
        / "cp-1"
        / "ledger.sqlite3"
    )
    with ledger_path.open("r+b") as handle:
        handle.truncate(512 * 1024 * 1024 + 1)
    try:
        with pytest.raises(
            CompanyCheckpointError,
            match="exceeds its byte bound",
        ):
            verify_plain_checkpoint(ledger_path.parent)
    finally:
        owner.close()


def test_huge_json_integer_uses_typed_verifier_error(
    tmp_path: Path,
) -> None:
    owner = initialized(tmp_path)
    write(owner)
    checkpoint = owner.resolved.incarnation.checkpoints / "cp-1"
    manifest_path = checkpoint / "checkpoint-manifest.json"
    manifest_path.write_bytes(
        b'{"schema_version":'
        + b"9" * 5000
        + b"}",
    )
    try:
        with pytest.raises(
            CompanyCheckpointError,
            match="not canonical JSON",
        ):
            verify_plain_checkpoint(checkpoint)
    finally:
        owner.close()
