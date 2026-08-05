from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading

import pytest

import aoi_orgware.company.blobs as blobs_module
from aoi_orgware.company.blobs import (
    BlobIntegrityError,
    BlobPathError,
    BlobSizeError,
    BlobStoreError,
    BlobStore,
)


def test_put_uses_canonical_lowercase_sha256_fanout_and_verified_metadata(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "company-blobs")
    payload = b"company evidence\x00payload"
    expected = hashlib.sha256(payload).hexdigest()

    metadata = store.put(payload)

    assert metadata.sha256 == expected
    assert metadata.size_bytes == len(payload)
    assert metadata.path == tmp_path / "company-blobs" / expected[:2] / expected[2:4] / expected
    assert store.path_for_digest(expected) == metadata.path
    assert store.read(expected) == payload
    assert store.metadata(expected) == metadata


@pytest.mark.skipif(os.name != "nt", reason="native Windows long-path regression")
def test_native_windows_long_member_path_preserves_blob_semantics() -> None:
    base = Path(tempfile.mkdtemp(prefix="aoi-blob-long-", dir=Path.cwd().anchor))
    payload = b"native Windows long-path blob publication"
    digest = hashlib.sha256(payload).hexdigest()
    fixed_root = base / "root"
    padding = 209 - len(os.fspath(fixed_root)) - 1 - 1 - 2 - 1 - 2
    assert 1 <= padding <= 240
    root = fixed_root / ("r" * padding)
    expected_parent = root / digest[:2] / digest[2:4]
    assert len(os.fspath(expected_parent)) == 209

    try:
        store = BlobStore(root)
        first = store.put(payload)
        second = store.put(payload)

        assert len(os.fspath(first.path)) == 274
        assert not os.fspath(first.path).startswith("\\\\?\\")
        assert first == second
        assert store.read(digest) == payload
        assert store.metadata(digest) == first
        assert os.lstat(blobs_module._native_filesystem_path(first.path)).st_nlink == 1
        with os.scandir(
            blobs_module._native_filesystem_path(first.path.parent),
        ) as entries:
            assert not any(entry.name.startswith(".aoi-blob-v1.") for entry in entries)
    finally:
        shutil.rmtree(blobs_module._native_filesystem_path(base))


def test_root_is_explicit_and_digest_is_canonical(tmp_path: Path) -> None:
    with pytest.raises(BlobPathError, match="absolute"):
        BlobStore("relative-company-blobs")
    with pytest.raises(BlobPathError, match="parent traversal"):
        BlobStore(tmp_path / "company-blobs" / ".." / "alternate")

    store = BlobStore(tmp_path / "company-blobs")
    with pytest.raises(BlobPathError, match="canonical lowercase"):
        store.path_for_digest("A" * 64)
    with pytest.raises(BlobPathError, match="canonical lowercase"):
        store.read("../../not-a-digest")


def test_root_reached_through_a_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "actual-root"
    target.mkdir()
    linked_parent = tmp_path / "linked-parent"
    try:
        linked_parent.symlink_to(tmp_path, target_is_directory=True)
    except OSError as exc:  # Windows can deny symlink creation without privilege.
        pytest.skip(f"symlink setup unavailable: {exc}")

    with pytest.raises(BlobPathError, match="ancestor"):
        BlobStore(linked_parent / "actual-root" / "company-blobs")


def test_moved_first_fanout_replaced_by_symlink_is_rejected_for_existing_member_access(
    tmp_path: Path,
) -> None:
    store = BlobStore(tmp_path / "company-blobs")
    payload = b"fanout symlink must not escape the audited root"
    metadata = store.put(payload)
    first_fanout = metadata.path.parent.parent
    moved_fanout = tmp_path / "moved-first-fanout"
    first_fanout.rename(moved_fanout)
    try:
        first_fanout.symlink_to(moved_fanout, target_is_directory=True)
    except OSError as exc:  # Windows can deny symlink creation without privilege.
        pytest.skip(f"symlink setup unavailable: {exc}")

    with pytest.raises(BlobPathError, match="fanout directory.*link"):
        store.read(metadata.sha256)
    with pytest.raises(BlobPathError, match="fanout directory.*link"):
        store.metadata(metadata.sha256)
    with pytest.raises(BlobPathError, match="fanout directory.*link"):
        store.put(payload)


def test_constructor_audits_linked_parent_before_creating_through_it(tmp_path: Path) -> None:
    external = tmp_path / "external"
    external.mkdir()
    linked_parent = tmp_path / "linked-parent"
    try:
        linked_parent.symlink_to(external, target_is_directory=True)
    except OSError as exc:  # Windows can deny symlink creation without privilege.
        pytest.skip(f"symlink setup unavailable: {exc}")

    requested_root = linked_parent / "would-have-been-created" / "company-blobs"
    with pytest.raises(BlobPathError, match="ancestor"):
        BlobStore(requested_root)

    assert not (external / "would-have-been-created").exists()


def _create_native_windows_junction_or_skip(junction: Path, target: Path) -> None:
    """Create a local NTFS junction, or skip where this Windows feature is unavailable."""
    try:
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", os.fspath(junction), os.fspath(target)],
            capture_output=True,
            check=False,
            text=True,
        )
    except OSError as exc:
        pytest.skip(f"junction setup unavailable: {exc}")
    if completed.returncode != 0:
        pytest.skip(f"junction setup unavailable: {completed.stderr.strip() or completed.stdout.strip()}")


@pytest.mark.skipif(os.name != "nt", reason="native Windows junction regression")
def test_native_windows_junction_root_is_rejected_before_target_write(tmp_path: Path) -> None:
    target = tmp_path / "external-target"
    target.mkdir()
    junction = tmp_path / "company-blobs-junction"

    try:
        _create_native_windows_junction_or_skip(junction, target)
        metadata = junction.lstat()
        assert stat.S_ISDIR(metadata.st_mode)
        assert not stat.S_ISLNK(metadata.st_mode)
        assert getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        with pytest.raises(BlobPathError, match="reparse point"):
            BlobStore(junction)
        assert list(target.iterdir()) == []
    finally:
        # rmdir removes only the junction entry; it never recursively traverses target.
        if junction.exists():
            os.rmdir(junction)


@pytest.mark.skipif(os.name != "nt", reason="native Windows reparse-point regression")
def test_native_windows_constructor_rejects_without_reparse_point_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(blobs_module.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)

    with pytest.raises(BlobPathError, match="reparse-point inspection is unavailable"):
        BlobStore(tmp_path / "company-blobs")


@pytest.mark.skipif(os.name != "nt", reason="native Windows root-alias regression")
@pytest.mark.parametrize("suffix", (".", " "), ids=("trailing-dot", "trailing-space"))
def test_native_windows_root_component_aliases_are_rejected_before_use(
    tmp_path: Path,
    suffix: str,
) -> None:
    canonical_parent = tmp_path / "canonical-parent"
    canonical_root = canonical_parent / "company-blobs"
    BlobStore(canonical_root)
    parent_alias = tmp_path / f"canonical-parent{suffix}"
    root_alias = canonical_parent / f"company-blobs{suffix}"

    assert parent_alias.samefile(canonical_parent)
    assert root_alias.samefile(canonical_root)
    for alias in (root_alias, parent_alias / "company-blobs"):
        with pytest.raises(BlobPathError, match="non-canonical Win32 trailing-dot/space"):
            BlobStore(alias)
    assert list(canonical_root.iterdir()) == []

    missing_alias = tmp_path / f"must-not-create{suffix}"
    with pytest.raises(BlobPathError, match="non-canonical Win32 trailing-dot/space"):
        BlobStore(missing_alias)
    assert not missing_alias.exists()


@pytest.mark.parametrize(
    "alias",
    (
        r"\\?\C:\company-blobs",
        r"//?/C:/company-blobs",
        r"\\.\C:\company-blobs",
        r"//./C:/company-blobs",
        r"\\?\UNC\server\share\company-blobs",
        r"//?/UNC/server/share/company-blobs",
        r"\??\C:\company-blobs",
    ),
)
def test_windows_namespace_guard_rejects_device_extended_and_unc_forms(
    alias: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(blobs_module.os, "name", "nt")

    with pytest.raises(BlobPathError, match="Windows device or extended namespace"):
        blobs_module._reject_windows_namespace_root_alias(alias)


@pytest.mark.parametrize("root", (r"C:\company-blobs", r"\\server\share\company-blobs"))
def test_windows_namespace_guard_keeps_normal_drive_and_unc_forms(
    root: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(blobs_module.os, "name", "nt")

    blobs_module._reject_windows_namespace_root_alias(root)


@pytest.mark.parametrize(
    "root",
    (
        r"C:\company\store:stream",
        r"C:\company\file::$DATA",
        r"C:\company\D:\blobs",
        r"\\server\share\store:stream",
        r"\\server\share\file::$DATA",
        r"\\server:stream\share\blobs",
    ),
)
def test_windows_colon_guard_rejects_ads_and_malformed_components(
    root: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(blobs_module.os, "name", "nt")

    with pytest.raises(BlobPathError, match="colon outside its Windows drive anchor"):
        blobs_module._reject_windows_colon_root_component(root)


@pytest.mark.parametrize(
    "root",
    (
        r"C:\normal-parent\company-blobs",
        r"\\server\share\normal-parent\company-blobs",
    ),
)
def test_windows_colon_guard_preserves_normal_drive_and_unc_anchors(
    root: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(blobs_module.os, "name", "nt")

    blobs_module._reject_windows_colon_root_component(root)


def test_windows_colon_guard_runs_before_path_or_root_initialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(blobs_module.os, "name", "nt")
    monkeypatch.setattr(
        blobs_module,
        "Path",
        lambda _: pytest.fail("colon component reached Path construction"),
    )
    monkeypatch.setattr(
        BlobStore,
        "_initialize_root",
        lambda self: pytest.fail("colon component reached BlobStore filesystem initialization"),
    )

    with pytest.raises(BlobPathError, match="colon outside its Windows drive anchor"):
        BlobStore(r"C:\company\store:stream")


@pytest.mark.skipif(os.name != "nt", reason="native Windows ADS regression")
@pytest.mark.parametrize("component", ("store:stream", "file::$DATA"))
def test_native_windows_ads_root_component_is_rejected_before_initialize_or_write(
    tmp_path: Path,
    component: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "safe-parent" / component / "company-blobs"
    monkeypatch.setattr(
        BlobStore,
        "_initialize_root",
        lambda self: pytest.fail("ADS component reached BlobStore filesystem initialization"),
    )

    with pytest.raises(BlobPathError, match="colon outside its Windows drive anchor"):
        BlobStore(root)
    assert not (tmp_path / "safe-parent").exists()


@pytest.mark.skipif(os.name == "nt", reason="native Windows rejects colon path components")
def test_posix_colon_root_keeps_posix_put_and_read_semantics(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "company:blobs")
    payload = b"POSIX colon root"

    metadata = store.put(payload)

    assert metadata.path.is_file()
    assert store.read(metadata.sha256) == payload


@pytest.mark.parametrize(
    "component",
    (
        "con",
        "PRN.txt",
        "aux. ",
        "NUL...",
        "clock$.json",
        *(f"Com{number}.trace " for number in range(1, 10)),
        *(f"lPt{number}." for number in range(1, 10)),
    ),
)
def test_windows_reserved_device_guard_rejects_lexical_root_components_before_path_use(
    component: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(blobs_module.os, "name", "nt")

    with pytest.raises(BlobPathError, match="reserved Windows device component"):
        blobs_module._reject_windows_reserved_device_root_component(
            rf"C:\company\{component}\blobs"
        )


@pytest.mark.parametrize(
    "root",
    (
        r"C:\normal-parent\company-blobs",
        r"\\server\share\normal-parent\company-blobs",
        # UNC server/share names are anchors, not locally-resolved components.
        r"\\con\aux\normal-parent\company-blobs",
    ),
)
def test_windows_reserved_device_guard_preserves_drive_and_unc_anchors(
    root: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(blobs_module.os, "name", "nt")

    blobs_module._reject_windows_reserved_device_root_component(root)


@pytest.mark.skipif(os.name != "nt", reason="native Windows reserved-device regression")
@pytest.mark.parametrize(
    "component",
    (
        "CON",
        "prn.txt",
        "AUX. ",
        "nul...",
        "Clock$.json",
        "COM1.trace",
        "com9. ",
        "LPT1.capture",
        "lpt9.",
    ),
)
def test_native_windows_reserved_device_component_is_rejected_before_initialize_or_write(
    tmp_path: Path,
    component: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "safe-parent" / component / "company-blobs"
    monkeypatch.setattr(
        BlobStore,
        "_initialize_root",
        lambda self: pytest.fail("reserved device component reached BlobStore filesystem initialization"),
    )

    with pytest.raises(BlobPathError, match="reserved Windows device component"):
        BlobStore(root)
    assert not (tmp_path / "safe-parent").exists()


@pytest.mark.skipif(os.name == "nt", reason="native Windows normalizes trailing dot and space")
@pytest.mark.parametrize("suffix", (".", " "), ids=("trailing-dot", "trailing-space"))
def test_posix_trailing_dot_space_roots_keep_posix_semantics(tmp_path: Path, suffix: str) -> None:
    root = tmp_path / f"company-blobs{suffix}"
    store = BlobStore(root)
    payload = f"POSIX suffix {suffix!r}".encode()

    metadata = store.put(payload)

    assert metadata.path.is_file()
    assert store.read(metadata.sha256) == payload


@pytest.mark.skipif(os.name != "nt", reason="native Windows namespace-alias canary")
@pytest.mark.parametrize(
    ("prefix", "use_forward_slashes"),
    (
        ("\\\\?\\", False),
        ("//?/", True),
        ("\\\\.\\", False),
        ("//./", True),
    ),
    ids=("extended-backslash", "extended-slash", "device-backslash", "device-slash"),
)
def test_native_windows_namespace_aliases_are_rejected_before_initialize_or_write(
    tmp_path: Path,
    prefix: str,
    use_forward_slashes: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canonical_root = tmp_path / "company-blobs"
    BlobStore(canonical_root)
    canonical_text = os.fspath(canonical_root)
    if use_forward_slashes:
        canonical_text = canonical_text.replace("\\", "/")
    alias = prefix + canonical_text

    # The regression condition: each tested spelling reaches the normal root.
    assert Path(alias).samefile(canonical_root)
    monkeypatch.setattr(
        BlobStore,
        "_initialize_root",
        lambda self: pytest.fail("namespace alias reached BlobStore filesystem initialization"),
    )

    with pytest.raises(BlobPathError, match="Windows device or extended namespace"):
        BlobStore(alias)
    assert list(canonical_root.iterdir()) == []


@pytest.mark.skipif(os.name != "nt", reason="native Windows junction regression")
def test_native_windows_junction_fanout_is_rejected_before_target_write(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "company-blobs")
    payload = b"fanout junction must not escape the audited root"
    digest = hashlib.sha256(payload).hexdigest()
    target = tmp_path / "external-target"
    target.mkdir()
    junction = store.root / digest[:2]

    try:
        _create_native_windows_junction_or_skip(junction, target)
        with pytest.raises(BlobPathError, match="blob fanout directory.*reparse point"):
            store.put(payload)
        assert list(target.iterdir()) == []
    finally:
        # rmdir removes only the junction entry; it never recursively traverses target.
        if junction.exists():
            os.rmdir(junction)


@pytest.mark.skipif(os.name != "nt", reason="native Windows reparse-point regression")
def test_native_windows_reparse_point_member_is_rejected(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "company-blobs")
    payload = b"member reparse point must not be followed"
    digest = hashlib.sha256(payload).hexdigest()
    destination = store.path_for_digest(digest)
    destination.parent.mkdir(parents=True)
    target = tmp_path / "external-member"
    target.write_bytes(payload)
    try:
        destination.symlink_to(target)
    except OSError as exc:  # Windows can deny symlink creation without privilege.
        pytest.skip(f"member reparse-point setup unavailable: {exc}")

    try:
        metadata = destination.lstat()
        assert getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        with pytest.raises(BlobPathError, match="blob member.*reparse point"):
            store.read(digest)
        assert target.read_bytes() == payload
    finally:
        destination.unlink()


def test_maximum_size_applies_to_new_and_existing_members(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "company-blobs", max_bytes=3)
    with pytest.raises(BlobSizeError, match="configured maximum"):
        store.put(b"four")

    payload = b"oversized"
    digest = hashlib.sha256(payload).hexdigest()
    destination = store.path_for_digest(digest)
    destination.parent.mkdir(parents=True)
    destination.write_bytes(payload)
    with pytest.raises(BlobSizeError, match="configured maximum"):
        store.read(digest)


def test_oversized_mutable_payload_is_rejected_before_materialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = BlobStore(tmp_path / "company-blobs", max_bytes=3)
    monkeypatch.setattr(
        blobs_module,
        "_as_bytes",
        lambda _payload: pytest.fail("oversized payload was materialized"),
    )
    with pytest.raises(BlobSizeError, match="configured maximum"):
        store.put(bytearray(b"four"))
    with pytest.raises(BlobSizeError, match="configured maximum"):
        store.put(memoryview(b"four"))


def test_same_payload_is_idempotent_and_existing_tamper_is_not_overwritten(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "company-blobs")
    payload = b"immutable evidence"
    first = store.put(payload)
    second = store.put(payload)
    assert first == second

    tampered = b"tampered bytes"
    digest = hashlib.sha256(tampered).hexdigest()
    destination = store.path_for_digest(digest)
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"not what this digest names")
    with pytest.raises(BlobIntegrityError, match="SHA-256"):
        store.put(tampered)
    assert destination.read_bytes() == b"not what this digest names"


def test_external_hardlink_rejects_read_metadata_and_idempotent_publication(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "company-blobs")
    payload = b"member must not escape its store"
    metadata = store.put(payload)
    external_alias = tmp_path / "external-alias"
    os.link(metadata.path, external_alias)

    assert metadata.path.stat().st_nlink == 2
    with pytest.raises(BlobPathError, match="hard link"):
        store.read(metadata.sha256)
    with pytest.raises(BlobPathError, match="hard link"):
        store.metadata(metadata.sha256)
    with pytest.raises(BlobPathError, match="hard link"):
        store.put(payload)
    assert external_alias.read_bytes() == payload


def test_hard_exit_after_publish_link_is_recovered_by_read_and_put(
    tmp_path: Path,
) -> None:
    root = tmp_path / "company-blobs"
    payload = b"recover exact interrupted publication"
    script = f"""
import os
from aoi_orgware.company.blobs import BlobStore

root = {os.fspath(root)!r}
payload = {payload!r}
original_link = os.link

def crash_after_link(source, destination):
    original_link(source, destination)
    os._exit(91)

os.link = crash_after_link
BlobStore(root).put(payload)
"""
    completed = subprocess.run(
        [sys.executable, "-B", "-c", script],
        check=False,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert completed.returncode == 91

    digest = hashlib.sha256(payload).hexdigest()
    destination = root / digest[:2] / digest[2:4] / digest
    temporaries = list(destination.parent.glob(".aoi-blob-v1.*.tmp"))
    assert destination.is_file()
    assert destination.stat().st_nlink == 2
    assert len(temporaries) == 1

    restarted = BlobStore(root)
    assert restarted.read(digest) == payload
    assert destination.stat().st_nlink == 1
    assert list(destination.parent.glob(".aoi-blob-v1.*.tmp")) == []
    assert restarted.put(payload).sha256 == digest


def test_noncanonical_same_directory_external_hardlink_is_not_recovered(
    tmp_path: Path,
) -> None:
    store = BlobStore(tmp_path / "company-blobs")
    payload = b"external same-directory alias"
    metadata = store.put(payload)
    external_alias = metadata.path.parent / ".aoi-blob-v1.external.tmp"
    os.link(metadata.path, external_alias)

    with pytest.raises(BlobPathError, match="not a unique recoverable"):
        store.read(metadata.sha256)
    assert external_alias.read_bytes() == payload


def test_preexisting_temporary_symlink_is_never_followed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = BlobStore(tmp_path / "company-blobs")
    payload = b"temporary symlink must not be followed"
    digest = hashlib.sha256(payload).hexdigest()
    parent = store.path_for_digest(digest).parent
    parent.mkdir(parents=True)
    external = tmp_path / "external"
    external.write_bytes(b"unchanged")
    temporary = parent / ".aoi-blob-v1.fixed.tmp"
    try:
        temporary.symlink_to(external)
    except OSError as exc:  # Windows can deny symlink creation without privilege.
        pytest.skip(f"symlink setup unavailable: {exc}")
    monkeypatch.setattr(blobs_module.secrets, "token_hex", lambda _: "fixed")

    with pytest.raises(BlobStoreError, match="could not allocate private blob temporary"):
        store.put(payload)

    assert external.read_bytes() == b"unchanged"
    assert temporary.is_symlink()


def test_verified_read_rejects_a_member_changed_after_publication(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "company-blobs")
    metadata = store.put(b"original")
    metadata.path.write_bytes(b"changed!")

    with pytest.raises(BlobIntegrityError, match="SHA-256"):
        store.read(metadata.sha256)
    with pytest.raises(BlobIntegrityError, match="SHA-256"):
        store.metadata(metadata.sha256)


def test_concurrent_same_bytes_publication_is_single_immutable_member(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "company-blobs")
    payload = b"same durable packet" * 1024
    start = threading.Barrier(8)
    results: list[str] = []
    failures: list[BaseException] = []

    def publish() -> None:
        try:
            start.wait(timeout=5)
            results.append(store.put(payload).sha256)
        except BaseException as exc:  # pragma: no cover - checked below
            failures.append(exc)

    workers = [threading.Thread(target=publish) for _ in range(8)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)

    assert all(not worker.is_alive() for worker in workers)
    assert failures == []
    digest = hashlib.sha256(payload).hexdigest()
    assert results == [digest] * 8
    assert store.read(digest) == payload
    assert list((tmp_path / "company-blobs").rglob(".aoi-blob-v1.*.tmp")) == []


def test_private_temporary_name_is_never_a_valid_blob_member(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "company-blobs")
    metadata = store.put(b"complete only")
    temporary = metadata.path.parent / ".aoi-blob-v1.deadbeef.tmp"
    temporary.write_bytes(b"partial")

    assert temporary != store.path_for_digest(metadata.sha256)
    assert store.read(metadata.sha256) == b"complete only"
    with pytest.raises(BlobPathError):
        store.path_for_digest(temporary.name)


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership modes are not portable to native Windows")
def test_posix_created_directories_and_member_are_owner_only(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "company-blobs")
    payload = b"owner-only"
    metadata = store.put(payload)

    assert stat.S_IMODE(store.root.stat().st_mode) == 0o700
    assert stat.S_IMODE(metadata.path.parent.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(metadata.path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(metadata.path.stat().st_mode) == 0o600


def test_durability_boundary_is_explicit_for_the_native_platform(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "company-blobs")
    if os.name == "nt":
        assert store.durability_boundary == "file_fsync_only; Python stdlib has no portable Windows directory fsync"
    else:
        assert store.durability_boundary == "file_and_changed_directory_fsync"


@pytest.mark.skipif(os.name == "nt", reason="native Windows declares file-fsync-only durability")
def test_posix_publication_fsyncs_file_and_all_changed_directories_in_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = BlobStore(tmp_path / "company-blobs")
    payload = b"ordered durability"
    digest = hashlib.sha256(payload).hexdigest()
    first_fanout = store.root / digest[:2]
    second_fanout = first_fanout / digest[2:4]
    events: list[str] = []
    original_directory_fsync = BlobStore._fsync_directory
    original_fsync = os.fsync

    def record_directory_fsync(path: Path) -> None:
        events.append(f"directory:{path.relative_to(store.root)}")
        original_directory_fsync(path)

    def record_file_fsync(descriptor: int) -> None:
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            events.append("file")
        original_fsync(descriptor)

    monkeypatch.setattr(BlobStore, "_fsync_directory", staticmethod(record_directory_fsync))
    monkeypatch.setattr(os, "fsync", record_file_fsync)

    store.put(payload)

    assert events == [
        f"directory:{first_fanout.relative_to(store.root)}",
        "directory:.",
        f"directory:{second_fanout.relative_to(store.root)}",
        f"directory:{first_fanout.relative_to(store.root)}",
        "file",
        f"directory:{second_fanout.relative_to(store.root)}",
        f"directory:{second_fanout.relative_to(store.root)}",
        f"directory:{second_fanout.relative_to(store.root)}",
    ]


@pytest.mark.skipif(os.name == "nt", reason="native Windows advertises file-fsync-only durability")
def test_posix_directory_fsync_rejection_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = BlobStore(tmp_path / "company-blobs")
    original_fsync = os.fsync

    def reject_directory_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError(errno.EINVAL, "directory fsync unavailable")
        original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", reject_directory_fsync)

    with pytest.raises(OSError, match="directory fsync unavailable"):
        store.put(b"must not claim unsupported directory durability")
    assert store.durability_boundary == "file_and_changed_directory_fsync"
