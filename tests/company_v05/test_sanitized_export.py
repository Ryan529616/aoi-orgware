from __future__ import annotations

import json
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import shutil
from threading import Event

import pytest

import aoi_orgware.company.sanitized_export as sanitized_export_module
from aoi_orgware.company.checkpoint import verify_plain_checkpoint
from aoi_orgware.company.contracts import canonical_company_json_bytes
from aoi_orgware.company.sanitized_export import (
    CompanySanitizedExportError,
    MAX_SANITIZED_EXPORT_BYTES,
    _canonical_bundle,
    _sanitize,
    verify_sanitized_export,
    write_sanitized_export,
)
from aoi_orgware.company.registry import CompanyLockWitness
from aoi_orgware.company.state import CompanyStateOwner
from aoi_orgware.company.supervisor import CompanySupervisor
from tests.company_v05.test_checkpoint import (
    T,
    initialized,
    manifest,
    tree,
    write,
)


class _ConcurrentWitness:
    """Test-only witness: publication race is below the external lock layer."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def assert_owned(self) -> None:
        return None


def _checkpoint(owner: CompanyStateOwner) -> Path:
    return owner.resolved.incarnation.checkpoints / "cp-1"


def _write(
    owner: CompanyStateOwner,
    name: str = "export-1",
    *,
    lock: CompanyLockWitness | None = None,
) -> tuple[str, Path]:
    checkpoint = _checkpoint(owner)
    digest = write_sanitized_export(
        lock=owner.lock if lock is None else lock, resolved=owner.resolved,
        checkpoint_path=checkpoint, export_id=name, generated_at=T,
    )
    return digest, owner.resolved.incarnation.exports / f"{name}.json"


def test_checkpoint_bound_export_is_canonical_cursor_exact_and_nonmutating(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    write(owner)
    checkpoint = _checkpoint(owner)
    before = tree(checkpoint)
    digest, path = _write(owner)
    verified = verify_sanitized_export(path)
    assert verified.sha256 == digest
    assert verified.bundle["ledger"] == {"cursor": 1, "head_sha256": verify_plain_checkpoint(checkpoint).manifest["ledger"]["transaction_sha256"]}
    assert verified.bundle["checkpoint"]["checkpoint_id"] == "cp-1"
    assert "export" not in verified.bundle["snapshot"]
    assert tree(checkpoint) == before
    assert not list(checkpoint.rglob("*-wal"))
    assert not list(checkpoint.rglob("*-shm"))
    assert not list(owner.resolved.incarnation.exports.glob(".s-*"))
    owner.close()


def test_recursive_redaction_keeps_safe_raw_token_vector_only() -> None:
    raw = {
        "raw_prompt": "do not publish", "thread_id": "thread-1",
        "nested": {"native_handle": "native", "nonce_sha256": "x", "user_action_ref": "click", "raw_token_vector": {"input": {"present": True, "tokens": 3}}},
        "blob_bytes": "never", "blob_ref": {"sha256": "a" * 64, "size_bytes": 1},
        "raw_artifact": {"availability": "available", "sha256": "b" * 64, "size_bytes": 5, "media_type": "text/plain", "bytes": "never"},
    }
    result = _sanitize(raw)
    text = json.dumps(result, sort_keys=True)
    assert "do not publish" not in text and "thread-1" not in text and "native" not in text and "click" not in text and "never" not in text
    assert result["nested"]["raw_token_vector"]["input"]["tokens"] == 3
    assert result["blob_ref"]["sha256"] == "a" * 64
    assert result["raw_artifact"] == {
        "availability": "available", "sha256": "b" * 64,
        "size_bytes": 5, "media_type": "text/plain",
    }


def test_replay_collision_and_concurrent_publication_are_fail_closed(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    write(owner)
    first, _path = _write(owner)
    assert _write(owner)[0] == first
    with pytest.raises(CompanySanitizedExportError):
        write_sanitized_export(lock=owner.lock, resolved=owner.resolved, checkpoint_path=_checkpoint(owner), export_id="export-1", generated_at="2026-07-27T00:00:01Z")
    with ThreadPoolExecutor(max_workers=2) as pool:
        witness = _ConcurrentWitness(owner.resolved.slot.lock)
        results = list(pool.map(lambda _item: _write(owner, "race-1", lock=witness)[0], range(2)))
    assert results == [results[0], results[0]]
    owner.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX no-replace uses a two-link window")
def test_identical_collision_waits_for_link_window_and_fsyncs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = initialized(tmp_path)
    write(owner)
    linked = Event()
    settling = Event()
    release = Event()
    unlinked = Event()
    fsyncs: list[Path] = []
    original_publish = sanitized_export_module._publish_no_replace
    original_fsync = sanitized_export_module._fsync_directory

    def delayed_publish(stage: Path, target: Path) -> None:
        if target.name == "race-window.json" and not linked.is_set():
            os.link(stage, target)
            linked.set()
            assert release.wait(5)
            stage.unlink()
            unlinked.set()
            return
        original_publish(stage, target)

    def wait_for_release(_seconds: float) -> None:
        settling.set()
        assert release.wait(5)
        assert unlinked.wait(5)

    def record_fsync(path: Path) -> None:
        fsyncs.append(path)
        original_fsync(path)

    monkeypatch.setattr(sanitized_export_module, "_publish_no_replace", delayed_publish)
    monkeypatch.setattr(sanitized_export_module, "sleep", wait_for_release)
    monkeypatch.setattr(sanitized_export_module, "_fsync_directory", record_fsync)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            winner = pool.submit(lambda: _write(owner, "race-window", lock=_ConcurrentWitness(owner.resolved.slot.lock))[0])
            assert linked.wait(5)
            loser = pool.submit(lambda: _write(owner, "race-window", lock=_ConcurrentWitness(owner.resolved.slot.lock))[0])
            assert settling.wait(5)
            release.set()
            results = [winner.result(timeout=10), loser.result(timeout=10)]
        target = owner.resolved.incarnation.exports / "race-window.json"
        assert results == [results[0], results[0]]
        assert target.stat().st_nlink == 1
        assert fsyncs.count(target.parent) >= 2
        assert not list(target.parent.glob(".s-*"))
    finally:
        release.set()
        owner.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX no-replace uses a two-link window")
def test_divergent_collision_waits_then_rejects_without_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = initialized(tmp_path)
    write(owner)
    linked = Event()
    settling = Event()
    release = Event()
    unlinked = Event()
    original_publish = sanitized_export_module._publish_no_replace

    def delayed_publish(stage: Path, target: Path) -> None:
        if target.name == "divergent-race.json" and not linked.is_set():
            os.link(stage, target)
            linked.set()
            assert release.wait(5)
            stage.unlink()
            unlinked.set()
            return
        original_publish(stage, target)

    def wait_for_release(_seconds: float) -> None:
        settling.set()
        assert release.wait(5)
        assert unlinked.wait(5)

    def publish(generated_at: str) -> str:
        return write_sanitized_export(
            lock=_ConcurrentWitness(owner.resolved.slot.lock),
            resolved=owner.resolved,
            checkpoint_path=_checkpoint(owner),
            export_id="divergent-race",
            generated_at=generated_at,
        )

    monkeypatch.setattr(sanitized_export_module, "_publish_no_replace", delayed_publish)
    monkeypatch.setattr(sanitized_export_module, "sleep", wait_for_release)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            winner = pool.submit(publish, T)
            assert linked.wait(5)
            loser = pool.submit(publish, "2026-07-27T00:00:01Z")
            assert settling.wait(5)
            release.set()
            winner_digest = winner.result(timeout=10)
            with pytest.raises(CompanySanitizedExportError, match="divergent content"):
                loser.result(timeout=10)
        target = owner.resolved.incarnation.exports / "divergent-race.json"
        verified = verify_sanitized_export(target)
        assert verified.sha256 == winner_digest
        assert verified.bundle["generated_at"] == T
        assert target.stat().st_nlink == 1
        assert not list(target.parent.glob(".s-*"))
    finally:
        release.set()
        owner.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX hard-link settling is platform-specific")
@pytest.mark.parametrize("alias_name", ["external-alias.json", f".s-{'a' * 32}.json"])
def test_persistent_hardlink_never_becomes_an_idempotent_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    alias_name: str,
) -> None:
    owner = initialized(tmp_path)
    write(owner)
    _digest, target = _write(owner, "stuck")
    alias = target.with_name(alias_name)
    try:
        os.link(target, alias)
    except OSError as exc:
        owner.close()
        pytest.skip(f"hardlink unavailable: {exc}")
    monkeypatch.setattr(sanitized_export_module, "_EXISTING_EXPORT_RETRIES", 2)
    monkeypatch.setattr(sanitized_export_module, "sleep", lambda _seconds: None)
    try:
        with pytest.raises(
            CompanySanitizedExportError,
            match="did not settle",
        ):
            _write(owner, "stuck")
        with pytest.raises(CompanySanitizedExportError):
            verify_sanitized_export(target)
        assert alias.exists()
        assert target.stat().st_nlink == 2
    finally:
        alias.unlink()
        owner.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX hard-link settling is platform-specific")
def test_settling_identity_drift_is_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = initialized(tmp_path)
    write(owner)
    _digest, target = _write(owner, "drift")
    alias = target.with_name("drift-alias.json")
    os.link(target, alias)
    original_inode = target.stat().st_ino

    def replace_target(_seconds: float) -> None:
        raw = alias.read_bytes()
        target.unlink()
        target.write_bytes(raw)

    monkeypatch.setattr(sanitized_export_module, "sleep", replace_target)
    try:
        with pytest.raises(
            CompanySanitizedExportError,
            match="changed while settling",
        ):
            _write(owner, "drift")
        assert target.stat().st_ino != original_inode
        assert alias.exists()
    finally:
        alias.unlink()
        owner.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX no-replace unlinks its staging name")
def test_post_link_cleanup_failure_is_typed_and_replayable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = initialized(tmp_path)
    write(owner)
    original_unlink = Path.unlink
    failed = False

    def fail_once(path: Path, *args: object, **kwargs: object) -> None:
        nonlocal failed
        if path.name.startswith(".s-") and not failed:
            failed = True
            raise OSError("synthetic cleanup failure")
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_once)
    with pytest.raises(
        CompanySanitizedExportError,
        match="published export temporary cleanup failed",
    ):
        _write(owner, "cleanup")
    digest, target = _write(owner, "cleanup")
    assert verify_sanitized_export(target).sha256 == digest
    owner.close()


def test_tamper_extra_oversize_and_link_rejected_without_verifier_mutation(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    write(owner)
    _digest, path = _write(owner)
    before = path.read_bytes()
    path.write_bytes(before + b" ")
    with pytest.raises(CompanySanitizedExportError):
        verify_sanitized_export(path)
    assert path.read_bytes() == before + b" "
    path.write_bytes(b"{" + b"x" * MAX_SANITIZED_EXPORT_BYTES + b"}")
    with pytest.raises(CompanySanitizedExportError):
        verify_sanitized_export(path)
    path.write_bytes(before)
    payload = json.loads(before)
    payload["extra"] = True
    path.write_bytes(canonical_company_json_bytes(payload))
    with pytest.raises(CompanySanitizedExportError):
        verify_sanitized_export(path)
    path.write_bytes(before)
    link = path.with_name("linked.json")
    try:
        os.symlink(path, link)
    except OSError as exc:
        pytest.skip(f"symlink privilege unavailable: {exc}")
    with pytest.raises(CompanySanitizedExportError):
        verify_sanitized_export(link)
    hardlink = path.with_name("hardlinked.json")
    try:
        os.link(path, hardlink)
    except OSError as exc:
        pytest.skip(f"hardlink unavailable: {exc}")
    try:
        with pytest.raises(CompanySanitizedExportError):
            verify_sanitized_export(path)
    finally:
        hardlink.unlink()
    owner.close()


def test_checkpoint_id_and_traversal_binding_rejected(tmp_path: Path) -> None:
    owner = initialized(tmp_path)
    write(owner)
    _digest, path = _write(owner)
    payload = json.loads(path.read_bytes())
    payload["checkpoint"]["checkpoint_id"] = "../escape"
    path.write_bytes(canonical_company_json_bytes(payload))
    with pytest.raises(CompanySanitizedExportError):
        verify_sanitized_export(path)
    with pytest.raises(CompanySanitizedExportError):
        write_sanitized_export(lock=owner.lock, resolved=owner.resolved, checkpoint_path=Path("relative"), export_id="x", generated_at=T)
    with pytest.raises(CompanySanitizedExportError):
        write_sanitized_export(lock=owner.lock, resolved=owner.resolved, checkpoint_path=tmp_path / "other" / "cp", export_id="x", generated_at=T)
    owner.close()


def test_wrong_company_lock_and_foreign_checkpoint_are_rejected(
    tmp_path: Path,
) -> None:
    owner_b = initialized(tmp_path / "b")
    foreign_manifest = manifest()
    foreign_manifest["company_id"] = "company-foreign"
    foreign_manifest["configuration_sha256"] = "e" * 64
    foreign = CompanySupervisor.initialize(
        tmp_path / "foreign" / "company",
        foreign_manifest,
        bootstrap_at=T,
        grant_expires_at="2026-07-28T00:00:00Z",
        platform="windows" if os.name == "nt" else "posix",
    )
    foreign_state = foreign._state
    try:
        write(owner_b)
        write(foreign_state)
        with pytest.raises(
            CompanySanitizedExportError,
            match="lock witness differs",
        ):
            write_sanitized_export(
                lock=foreign_state.lock,
                resolved=owner_b.resolved,
                checkpoint_path=_checkpoint(owner_b),
                export_id="wrong-lock",
                generated_at=T,
            )
        foreign_checkpoint = (
            owner_b.resolved.incarnation.checkpoints / "foreign"
        )
        shutil.copytree(_checkpoint(foreign_state), foreign_checkpoint)
        with pytest.raises(
            CompanySanitizedExportError,
            match="active company incarnation",
        ):
            write_sanitized_export(
                lock=owner_b.lock,
                resolved=owner_b.resolved,
                checkpoint_path=foreign_checkpoint,
                export_id="foreign-checkpoint",
                generated_at=T,
            )
    finally:
        foreign.close()
        owner_b.close()


def test_verifier_reconstructs_snapshot_and_rejects_forged_status(
    tmp_path: Path,
) -> None:
    owner = initialized(tmp_path)
    write(owner)
    _digest, path = _write(owner)
    payload = json.loads(path.read_bytes())
    payload["snapshot"]["forged_status"] = "completed"
    path.write_bytes(
        canonical_company_json_bytes(
            payload,
            max_bytes=MAX_SANITIZED_EXPORT_BYTES,
        ),
    )
    with pytest.raises(
        CompanySanitizedExportError,
        match="snapshot differs",
    ):
        verify_sanitized_export(path)
    owner.close()


def test_declared_canonical_bound_exceeds_default_contract_bound() -> None:
    payload = {"payload": "x" * (300 * 1024)}
    raw = canonical_company_json_bytes(
        payload,
        max_bytes=MAX_SANITIZED_EXPORT_BYTES,
    )
    assert len(raw) > 256 * 1024
    assert _canonical_bundle(raw) == payload


@pytest.mark.parametrize(
    "key",
    ["access_token", "api_key", "password", "authorization", "private_key"],
)
def test_secret_bearing_keys_are_removed(key: str) -> None:
    assert key not in _sanitize({key: "never-export", "safe": "yes"})
