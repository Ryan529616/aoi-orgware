"""AOI-SYNTHETIC-FIXTURE-V1 native company filesystem tests."""
from __future__ import annotations

import os
from pathlib import Path
import stat

import pytest

from aoi_orgware.company.ledger import CompanyLedger
from aoi_orgware.company.native_filesystem import (
    NativeFilesystemIdentityError,
    _windows_extended_path,
    native_filesystem_path,
    unlink_identity_checked,
)
from aoi_orgware.company.readmodel import CompanyReadModel
from aoi_orgware.company.registry import (
    CompanyRegistryError,
    _ensure_private_directory,
)


def test_windows_extended_path_is_absolute_idempotent_and_unc_aware() -> None:
    drive = _windows_extended_path(r"C:\AOI-SYNTHETIC-FIXTURE-V1\state")
    unc = _windows_extended_path(
        r"\\server\share\AOI-SYNTHETIC-FIXTURE-V1\state",
    )

    assert drive == r"\\?\C:\AOI-SYNTHETIC-FIXTURE-V1\state"
    assert unc == r"\\?\UNC\server\share\AOI-SYNTHETIC-FIXTURE-V1\state"
    assert _windows_extended_path(drive) == drive
    assert _windows_extended_path(unc) == unc


def test_native_filesystem_path_preserves_public_identity() -> None:
    canonical = Path(os.path.abspath("AOI-SYNTHETIC-FIXTURE-V1"))
    observed = native_filesystem_path(canonical)

    if os.name == "nt":
        assert isinstance(observed, str)
        assert observed.startswith("\\\\?\\")
        assert native_filesystem_path(Path(observed)) == observed
    else:
        assert observed is canonical


@pytest.mark.skipif(os.name != "nt", reason="requires Windows handle deletion")
def test_unlink_identity_checked_is_handle_bound_and_fail_closed(
    tmp_path: Path,
) -> None:
    original = tmp_path / "original.bin"
    other = tmp_path / "other.bin"
    original.write_bytes(b"original")
    other.write_bytes(b"other")
    expected = os.lstat(native_filesystem_path(original))

    with pytest.raises(NativeFilesystemIdentityError):
        unlink_identity_checked(other, expected)
    assert other.read_bytes() == b"other"

    unlink_identity_checked(original, expected)
    assert not original.exists()


def test_database_objects_preserve_canonical_public_path(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    readmodel_path = tmp_path / "readmodel.sqlite3"

    with CompanyLedger(ledger_path) as ledger:
        assert ledger.path == ledger_path
    with CompanyReadModel(readmodel_path) as readmodel:
        assert readmodel.path == readmodel_path


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory mode regression")
def test_existing_non_directory_is_rejected_without_chmod(tmp_path: Path) -> None:
    occupied = tmp_path / "occupied"
    occupied.write_bytes(b"AOI-SYNTHETIC-FIXTURE-V1")
    os.chmod(occupied, 0o640)
    before = stat.S_IMODE(occupied.stat().st_mode)

    with pytest.raises(CompanyRegistryError, match="must be a non-link directory"):
        _ensure_private_directory(occupied, "synthetic private directory")

    assert stat.S_IMODE(occupied.stat().st_mode) == before
