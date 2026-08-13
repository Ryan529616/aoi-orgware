from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from aoi_orgware.company.contracts import (
    COMPANY_MANIFEST_V1,
    canonical_company_json_bytes,
)
from aoi_orgware.company.registry import (
    CompanyIncarnationPaths,
    CompanyPointerConflictError,
    CompanyRegistry,
    CompanyRegistryError,
)


H = "a" * 64
T = "2026-07-27T00:00:00Z"


class LockWitness:
    def __init__(self, *, owned: bool = True) -> None:
        self.owned = owned

    def assert_owned(self) -> None:
        if not self.owned:
            raise RuntimeError("not owned")


def manifest(
    *,
    incarnation: int = 1,
    generation: int = 1,
    company_id: str = "company-1",
) -> dict[str, Any]:
    return {
        "contract_type": COMPANY_MANIFEST_V1,
        "schema_version": 1,
        "company_id": company_id,
        "company_incarnation": incarnation,
        "lock_domain_generation": generation,
        "git_common_dir_sha256": H,
        "remote_fingerprint_sha256": "b" * 64,
        "configuration_sha256": "c" * 64,
        "state_root_sha256": "d" * 64,
        "lock_domain_id": "windows" if os.name == "nt" else "posix",
        "created_at": T,
        "observation": {"state": "known", "reason": "observed"},
    }


def registry(tmp_path: Path) -> tuple[CompanyRegistry, LockWitness]:
    slot = tmp_path / "companies" / "company-1"
    slot.mkdir(parents=True)
    return CompanyRegistry(slot), LockWitness()


def test_initialize_resolve_and_exact_replay(tmp_path: Path) -> None:
    subject, lock = registry(tmp_path)
    first = subject.initialize(
        lock,
        manifest(),
        platform="windows" if os.name == "nt" else "posix",
    )
    replay = subject.initialize(
        lock,
        manifest(),
        platform="windows" if os.name == "nt" else "posix",
    )
    assert replay.pointer == first.pointer
    assert replay.manifest == first.manifest
    assert first.incarnation.ledger.name == "ledger.sqlite3"
    assert first.incarnation.readmodel.name == "readmodel.sqlite3"
    assert first.incarnation.blobs.is_dir()
    assert first.incarnation.checkpoints.is_dir()
    assert first.incarnation.exports.is_dir()
    assert first.incarnation.spool.is_dir()
    assert first.incarnation.manifest.read_bytes() == canonical_company_json_bytes(
        manifest(),
    )


def test_lock_witness_is_required_for_every_operation(tmp_path: Path) -> None:
    subject, _lock = registry(tmp_path)
    missing = LockWitness(owned=False)
    with pytest.raises(CompanyRegistryError):
        subject.initialize(
            missing,
            manifest(),
            platform="windows" if os.name == "nt" else "posix",
        )
    assert not subject.paths.current.exists()


def test_successor_prepare_and_pointer_cas_preserve_old_state(
    tmp_path: Path,
) -> None:
    subject, lock = registry(tmp_path)
    current = subject.initialize(
        lock,
        manifest(),
        platform="windows" if os.name == "nt" else "posix",
    )
    successor = subject.prepare_next(
        lock,
        manifest(incarnation=2, generation=2),
    )
    assert subject.resolve_current(lock).pointer == current.pointer
    assert successor.incarnation.manifest.exists()

    with pytest.raises(CompanyPointerConflictError):
        subject.compare_and_swap_current(
            lock,
            expected_pointer_sha256="f" * 64,
            successor=successor,
        )
    assert subject.resolve_current(lock).pointer == current.pointer

    malformed = replace(successor.pointer, pointer_sha256="e" * 64)
    with pytest.raises(CompanyRegistryError):
        subject.compare_and_swap_current(
            lock,
            expected_pointer_sha256=current.pointer.pointer_sha256,
            successor=replace(successor, pointer=malformed),
        )
    assert subject.resolve_current(lock).pointer == current.pointer

    activated = subject.compare_and_swap_current(
        lock,
        expected_pointer_sha256=current.pointer.pointer_sha256,
        successor=successor,
    )
    assert activated.pointer.company_incarnation == 2
    assert activated.pointer.lock_domain_generation == 2
    assert activated.pointer.previous_pointer_sha256 == (
        current.pointer.pointer_sha256
    )
    assert current.incarnation.manifest.exists()


def test_cas_rejects_noncanonical_successor_before_pointer_publication(
    tmp_path: Path,
) -> None:
    subject, lock = registry(tmp_path)
    current = subject.initialize(
        lock,
        manifest(),
        platform="windows" if os.name == "nt" else "posix",
    )
    successor = subject.prepare_next(
        lock,
        manifest(incarnation=2, generation=2),
    )
    outside_root = tmp_path / "external-incarnation"
    successor.incarnation.root.replace(outside_root)
    outside = CompanyIncarnationPaths(
        root=outside_root,
        manifest=outside_root / "manifest.json",
        ledger=outside_root / "ledger.sqlite3",
        readmodel=outside_root / "readmodel.sqlite3",
        blobs=outside_root / "blobs",
        checkpoints=outside_root / "checkpoints",
        exports=outside_root / "exports",
        spool=outside_root / "spool",
    )
    forged = replace(successor, incarnation=outside)
    pointer_before = subject.paths.current.read_bytes()

    with pytest.raises(CompanyRegistryError, match="canonical"):
        subject.compare_and_swap_current(
            lock,
            expected_pointer_sha256=current.pointer.pointer_sha256,
            successor=forged,
        )

    assert subject.paths.current.read_bytes() == pointer_before
    assert subject.resolve_current(lock).pointer == current.pointer


def test_cas_validates_platform_binding_before_pointer_publication(
    tmp_path: Path,
) -> None:
    subject, lock = registry(tmp_path)
    current = subject.initialize(
        lock,
        manifest(),
        platform="windows" if os.name == "nt" else "posix",
    )
    changed_domain = manifest(incarnation=2, generation=2)
    changed_domain["lock_domain_id"] = "different-domain"
    successor = subject.prepare_next(lock, changed_domain)
    pointer_before = subject.paths.current.read_bytes()

    with pytest.raises(CompanyRegistryError, match="matches its pointer"):
        subject.compare_and_swap_current(
            lock,
            expected_pointer_sha256=current.pointer.pointer_sha256,
            successor=successor,
        )

    assert subject.paths.current.read_bytes() == pointer_before
    assert subject.resolve_current(lock).pointer == current.pointer


def _replace_directory_with_link(path: Path, outside: Path) -> None:
    path.replace(outside)
    try:
        path.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")


def test_cas_rejects_linked_canonical_root_before_pointer_publication(
    tmp_path: Path,
) -> None:
    subject, lock = registry(tmp_path)
    current = subject.initialize(
        lock,
        manifest(),
        platform="windows" if os.name == "nt" else "posix",
    )
    successor = subject.prepare_next(
        lock,
        manifest(incarnation=2, generation=2),
    )
    _replace_directory_with_link(
        successor.incarnation.root,
        tmp_path / "outside-successor-root",
    )
    pointer_before = subject.paths.current.read_bytes()

    with pytest.raises(CompanyRegistryError, match="non-link directory"):
        subject.compare_and_swap_current(
            lock,
            expected_pointer_sha256=current.pointer.pointer_sha256,
            successor=successor,
        )

    assert subject.paths.current.read_bytes() == pointer_before
    assert subject.resolve_current(lock).pointer == current.pointer


@pytest.mark.parametrize(
    "member",
    ("blobs", "checkpoints", "exports", "spool"),
)
def test_cas_rejects_linked_required_subdirectory_before_publication(
    tmp_path: Path,
    member: str,
) -> None:
    subject, lock = registry(tmp_path)
    current = subject.initialize(
        lock,
        manifest(),
        platform="windows" if os.name == "nt" else "posix",
    )
    successor = subject.prepare_next(
        lock,
        manifest(incarnation=2, generation=2),
    )
    linked = getattr(successor.incarnation, member)
    _replace_directory_with_link(
        linked,
        tmp_path / f"outside-{member}",
    )
    pointer_before = subject.paths.current.read_bytes()

    with pytest.raises(CompanyRegistryError, match="non-link directory"):
        subject.compare_and_swap_current(
            lock,
            expected_pointer_sha256=current.pointer.pointer_sha256,
            successor=successor,
        )

    assert subject.paths.current.read_bytes() == pointer_before
    assert subject.resolve_current(lock).pointer == current.pointer


@pytest.mark.parametrize(
    ("incarnation", "generation"),
    ((1, 2), (2, 1), (3, 3)),
)
def test_successor_generation_must_be_exactly_next_incarnation(
    tmp_path: Path,
    incarnation: int,
    generation: int,
) -> None:
    subject, lock = registry(tmp_path)
    subject.initialize(
        lock,
        manifest(),
        platform="windows" if os.name == "nt" else "posix",
    )
    with pytest.raises(CompanyRegistryError):
        subject.prepare_next(
            lock,
            manifest(incarnation=incarnation, generation=generation),
        )


def test_pointer_and_manifest_tamper_fail_closed(tmp_path: Path) -> None:
    subject, lock = registry(tmp_path)
    state = subject.initialize(
        lock,
        manifest(),
        platform="windows" if os.name == "nt" else "posix",
    )
    pointer = json.loads(subject.paths.current.read_text(encoding="utf-8"))
    pointer["company_incarnation"] = 9
    subject.paths.current.write_bytes(canonical_company_json_bytes(pointer))
    with pytest.raises(CompanyRegistryError):
        subject.resolve_current(lock)

    subject.paths.current.write_bytes(
        canonical_company_json_bytes(state.pointer.as_dict()),
    )
    changed = manifest()
    changed["configuration_sha256"] = "e" * 64
    state.incarnation.manifest.write_bytes(canonical_company_json_bytes(changed))
    with pytest.raises(CompanyRegistryError):
        subject.resolve_current(lock)


def test_divergent_genesis_never_replaces_current(tmp_path: Path) -> None:
    subject, lock = registry(tmp_path)
    first = subject.initialize(
        lock,
        manifest(),
        platform="windows" if os.name == "nt" else "posix",
    )
    divergent = manifest()
    divergent["configuration_sha256"] = "e" * 64
    with pytest.raises(CompanyPointerConflictError):
        subject.initialize(
            lock,
            divergent,
            platform="windows" if os.name == "nt" else "posix",
        )
    assert subject.resolve_current(lock).pointer == first.pointer


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_linked_registry_member_is_rejected(tmp_path: Path) -> None:
    subject, lock = registry(tmp_path)
    subject.initialize(lock, manifest(), platform="posix")
    outside = tmp_path / "outside.json"
    outside.write_bytes(subject.paths.current.read_bytes())
    subject.paths.current.unlink()
    subject.paths.current.symlink_to(outside)
    with pytest.raises(CompanyRegistryError):
        subject.resolve_current(lock)


def test_hardlinked_registry_member_is_rejected(tmp_path: Path) -> None:
    subject, lock = registry(tmp_path)
    subject.initialize(
        lock,
        manifest(),
        platform="windows" if os.name == "nt" else "posix",
    )
    alias = tmp_path / "current-alias.json"
    try:
        os.link(subject.paths.current, alias)
    except OSError:
        pytest.skip("hardlinks unavailable on this filesystem")
    with pytest.raises(CompanyRegistryError):
        subject.resolve_current(lock)
