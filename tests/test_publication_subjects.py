"""Focused tests for bounded publication-subject inventory."""

from __future__ import annotations

from collections.abc import Iterator
import hashlib
import io
from pathlib import Path
import sys
import tarfile
from typing import Callable
import zipfile

import pytest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware.publication_subjects import (  # noqa: E402
    PublicationSubjectError,
    PublicationSubjectLimits,
    inventory_publication_subjects,
)


def _zip(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, raw in entries.items():
            archive.writestr(name, raw)


def _tar_gz(path: Path, entries: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, raw in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))


def test_regular_files_directories_archives_and_manifest_are_deterministic(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "src").mkdir()
    (root / "src" / "plain.txt").write_bytes(b"plain")
    _zip(root / "dist.whl", {"pkg/__init__.py": b"version = 1\n"})
    _tar_gz(root / "source.tar.gz", {"pkg-1.0/private/secret.txt": b"secret"})

    first = inventory_publication_subjects(root, [root])
    second = inventory_publication_subjects(root, [root / "source.tar.gz", root / "dist.whl", root / "src"])

    assert first == second
    assert first["containers"] == sorted(first["containers"], key=lambda row: row["path"])
    subjects = {row["path"]: row["sha256"] for row in first["subjects"]}
    assert subjects["src/plain.txt"] == hashlib.sha256(b"plain").hexdigest()
    assert subjects["pkg/__init__.py"] == hashlib.sha256(b"version = 1\n").hexdigest()
    assert subjects["private/secret.txt"] == hashlib.sha256(b"secret").hexdigest()
    assert len(first["manifest_sha256"]) == 64


def test_wheel_and_sdist_may_repeat_the_same_member_identity(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    payload = b"same packaged source\n"
    _zip(root / "pkg.whl", {"pkg/module.py": payload})
    _tar_gz(root / "pkg.tar.gz", {"pkg-1.0/pkg/module.py": payload})

    inventory = inventory_publication_subjects(
        root, [root / "pkg.whl", root / "pkg.tar.gz"]
    )

    matching = [
        row for row in inventory["subjects"] if row["path"] == "pkg/module.py"
    ]
    assert matching == [
        {"path": "pkg/module.py", "sha256": hashlib.sha256(payload).hexdigest()}
    ]


@pytest.mark.parametrize("member", ["../escape", "/absolute"])
def test_unsafe_archive_member_fails_closed(tmp_path: Path, member: str) -> None:
    root = tmp_path / "project"
    root.mkdir()
    archive = root / "unsafe.zip"
    _zip(archive, {member: b"bad"})

    with pytest.raises(PublicationSubjectError, match="archive member path|traversal"):
        inventory_publication_subjects(root, [archive])


def test_duplicate_casefold_and_limits_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    archive = root / "duplicate.zip"
    _zip(archive, {"pkg/A.txt": b"A", "pkg/a.TXT": b"a"})
    with pytest.raises(PublicationSubjectError, match="case-colliding"):
        inventory_publication_subjects(root, [archive])

    file = root / "large.bin"
    file.write_bytes(b"1234")
    with pytest.raises(PublicationSubjectError, match="bytes exceed"):
        inventory_publication_subjects(
            root, [file], limits=PublicationSubjectLimits(max_total_bytes=7)
        )


def test_input_iterable_and_directory_walk_are_bounded_before_materialization(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    yielded = 0

    def endless_inputs() -> Iterator[Path]:
        nonlocal yielded
        while True:
            yielded += 1
            yield root / f"missing-{yielded}"

    with pytest.raises(PublicationSubjectError, match="1-2 paths"):
        inventory_publication_subjects(
            root,
            endless_inputs(),
            limits=PublicationSubjectLimits(max_inputs=2),
        )
    assert yielded == 3

    tree = root / "tree"
    tree.mkdir()
    for index in range(3):
        (tree / f"empty-{index}").mkdir()
    with pytest.raises(PublicationSubjectError, match="entry count"):
        inventory_publication_subjects(
            root,
            [tree],
            limits=PublicationSubjectLimits(max_filesystem_entries=2),
        )


def test_external_input_does_not_leak_absolute_path_and_preserves_digest(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    external = tmp_path / "outside.bin"
    external.write_bytes(b"outside")

    observed = inventory_publication_subjects(root, [external])

    row = observed["containers"][0]
    assert row["path"].startswith("external/")
    assert str(external) not in row["path"]
    assert row["sha256"] == hashlib.sha256(b"outside").hexdigest()
    assert observed["subjects"] == [{"path": row["path"], "sha256": row["sha256"]}]


def test_symlink_and_unstable_read_are_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "project"
    root.mkdir()
    target = root / "target.bin"
    target.write_bytes(b"target")
    linked = root / "linked.bin"
    try:
        linked.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    with pytest.raises(PublicationSubjectError, match="symlink, junction, or reparse"):
        inventory_publication_subjects(root, [linked])

    import aoi_orgware.publication_subjects as subjects

    original = subjects._same_identity
    calls = 0

    def changed(left: object, right: object) -> bool:
        nonlocal calls
        calls += 1
        return False if calls == 1 else original(left, right)  # type: ignore[arg-type]

    monkeypatch.setattr(subjects, "_same_identity", changed)
    with pytest.raises(PublicationSubjectError, match="changed while being opened"):
        inventory_publication_subjects(root, [target])


@pytest.mark.parametrize("suffix,writer", [(".zip", _zip), (".tar.gz", _tar_gz)])
def test_archive_inventory_never_calls_unbounded_member_list_apis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
    writer: Callable[[Path, dict[str, bytes]], None],
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    archive = root / f"package{suffix}"
    writer(archive, {"pkg/module.py": b"module\n"})

    def forbidden_member_list(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("unbounded member list API must not be called")

    if suffix == ".zip":
        monkeypatch.setattr(zipfile.ZipFile, "infolist", forbidden_member_list)
    else:
        monkeypatch.setattr(tarfile.TarFile, "getmembers", forbidden_member_list)

    inventory = inventory_publication_subjects(root, [archive])
    expected = "pkg/module.py" if suffix == ".zip" else "module.py"
    assert any(row["path"] == expected for row in inventory["subjects"])


def test_zip_declared_count_cannot_bypass_preparser_member_bound(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    archive = root / "forged.zip"
    _zip(archive, {f"pkg/{index}.txt": b"x" for index in range(5)})
    raw = bytearray(archive.read_bytes())
    eocd = raw.rfind(b"PK\x05\x06")
    assert eocd >= 0
    # Falsify both 16-bit entry counts while leaving the central directory.
    raw[eocd + 8 : eocd + 12] = b"\x00\x00\x00\x00"
    archive.write_bytes(raw)

    with pytest.raises(PublicationSubjectError, match="member count"):
        inventory_publication_subjects(
            root,
            [archive],
            limits=PublicationSubjectLimits(max_archive_members=1),
        )
