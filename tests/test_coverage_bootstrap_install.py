"""Tests for the uniquely owned CI coverage bootstrap installer."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import coverage_bootstrap_install as bootstrap


def _roots(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    site = tmp_path / "site-packages"
    startup = tmp_path / "coverage-startup"
    dependency = tmp_path / "purelib"
    receipts = tmp_path / "receipts"
    for path in (site, startup, dependency, receipts):
        path.mkdir()
    for name in bootstrap.MODULE_NAMES:
        (startup / name).write_text("VALUE = 1\n", encoding="utf-8")
    return site, startup, dependency, receipts / "bootstrap.json"


def test_install_readback_is_deterministic_and_removable(tmp_path: Path) -> None:
    site, startup, dependency, receipt = _roots(tmp_path)
    record = bootstrap.install(
        site_root=str(site), startup_root=str(startup), receipt_path=str(receipt), dependency_roots=[str(dependency)]
    )
    target = site / bootstrap.PTH_NAME
    expected = f"{dependency.resolve()}\n{startup.resolve()}\nimport aoi_coverage_bootstrap\n".encode()
    assert target.read_bytes() == expected
    assert record["content_sha256"] == hashlib.sha256(expected).hexdigest()
    assert record["schema_version"] == 3
    assert set(record["target_identity"]) == {
        "device", "identity_time_ns", "inode", "mode", "nlink", "size", "uid",
    }
    assert record["target_identity"]["size"] == len(expected)
    assert receipt.read_bytes() == json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    bootstrap.remove(receipt_path=str(receipt))
    assert not target.exists()
    assert receipt.exists()


def test_install_has_no_dependency_root_and_never_uses_sitecustomize(tmp_path: Path) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    assert (site / bootstrap.PTH_NAME).read_text(encoding="utf-8") == f"{startup.resolve()}\nimport aoi_coverage_bootstrap\n"
    assert not (site / "sitecustomize.py").exists()


@pytest.mark.parametrize("kind", ("regular", "directory"))
def test_existing_target_fails_closed(tmp_path: Path, kind: str) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    target = site / bootstrap.PTH_NAME
    if kind == "regular":
        target.write_text("foreign", encoding="utf-8")
    else:
        target.mkdir()
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="already exists"):
        bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    assert target.exists()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_existing_symlink_fails_closed(tmp_path: Path) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    foreign = tmp_path / "foreign"
    foreign.write_text("foreign", encoding="utf-8")
    target = site / bootstrap.PTH_NAME
    try:
        target.symlink_to(foreign)
    except OSError as error:
        pytest.skip(f"symlink unavailable: {error}")
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="already exists"):
        bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    assert foreign.read_text(encoding="utf-8") == "foreign"


@pytest.mark.skipif(os.name != "posix", reason="hard link metadata is POSIX-qualified")
def test_hardlinked_target_fails_closed(tmp_path: Path) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    foreign = tmp_path / "foreign"
    foreign.write_text("foreign", encoding="utf-8")
    os.link(foreign, site / bootstrap.PTH_NAME)
    with pytest.raises(bootstrap.CoverageBootstrapInstallError):
        bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    assert foreign.read_text(encoding="utf-8") == "foreign"


@pytest.mark.parametrize("bad", ("relative", "line\nbreak", "nul\x00byte"))
def test_malformed_paths_and_duplicate_roots_are_rejected(tmp_path: Path, bad: str) -> None:
    site, startup, dependency, receipt = _roots(tmp_path)
    value = bad if bad == "relative" else str(tmp_path / bad)
    with pytest.raises(bootstrap.CoverageBootstrapInstallError):
        bootstrap.install(site_root=value, startup_root=str(startup), receipt_path=str(receipt))
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="duplicated"):
        bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt), dependency_roots=[str(dependency), str(dependency)])


def test_duplicate_install_and_receipt_collision_do_not_replace(tmp_path: Path) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="already exists"):
        bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    other_site = tmp_path / "other-site"
    other_site.mkdir()
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="receipt already exists"):
        bootstrap.install(site_root=str(other_site), startup_root=str(startup), receipt_path=str(receipt))
    assert not (other_site / bootstrap.PTH_NAME).exists()


def test_tampered_duplicate_or_deep_receipt_fails_without_deletion(tmp_path: Path) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    target = site / bootstrap.PTH_NAME
    original = target.read_bytes()
    receipt.write_bytes(b'{"schema_version":1,"schema_version":1}\n')
    with pytest.raises(bootstrap.CoverageBootstrapInstallError):
        bootstrap.remove(receipt_path=str(receipt))
    assert target.read_bytes() == original
    receipt.write_text("[" * 20 + "0" + "]" * 20, encoding="utf-8")
    with pytest.raises(bootstrap.CoverageBootstrapInstallError):
        bootstrap.remove(receipt_path=str(receipt))
    assert target.read_bytes() == original


def test_deep_receipt_never_leaks_recursion_error(tmp_path: Path) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    target = site / bootstrap.PTH_NAME
    original = target.read_bytes()
    receipt.write_text("[" * 1100 + "0" + "]" * 1100, encoding="utf-8")
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="receipt"):
        bootstrap.remove(receipt_path=str(receipt))
    assert target.read_bytes() == original

    nested: object = 0
    for _ in range(bootstrap.MAX_JSON_DEPTH):
        nested = [nested]
    assert not bootstrap._exceeds_json_depth(nested, bootstrap.MAX_JSON_DEPTH)
    nested = [nested]
    assert bootstrap._exceeds_json_depth(nested, bootstrap.MAX_JSON_DEPTH)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_receipt_leaf_symlink_is_rejected_before_removal(tmp_path: Path) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    target = site / bootstrap.PTH_NAME
    original = target.read_bytes()
    foreign = receipt.with_name("foreign-receipt.json")
    foreign.write_bytes(receipt.read_bytes())
    receipt.unlink()
    try:
        receipt.symlink_to(foreign)
    except OSError as error:
        pytest.skip(f"symlink unavailable: {error}")
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="non-link|reparse"):
        bootstrap.remove(receipt_path=str(receipt))
    assert target.read_bytes() == original
    assert foreign.is_file()


def test_receipt_leaf_reparse_metadata_and_post_read_change_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    target = site / bootstrap.PTH_NAME
    original = target.read_bytes()
    original_lstat = bootstrap.os.lstat

    class ReparseMetadata:
        def __init__(self, wrapped: os.stat_result) -> None:
            self._wrapped = wrapped
            self.st_file_attributes = 1

        def __getattr__(self, name: str) -> object:
            return getattr(self._wrapped, name)

    def reparse(path: str) -> object:
        value = original_lstat(path)
        if os.path.normcase(path) == os.path.normcase(str(receipt)):
            return ReparseMetadata(value)
        return value

    monkeypatch.setattr(bootstrap.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1, raising=False)
    monkeypatch.setattr(bootstrap.os, "lstat", reparse)
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="reparse"):
        bootstrap.remove(receipt_path=str(receipt))
    assert target.read_bytes() == original

    monkeypatch.setattr(bootstrap.os, "lstat", original_lstat)
    first = bootstrap._identity(str(receipt))
    changed = dict(first)
    changed["inode"] = int(changed["inode"] or 0) + 1
    identities = iter((first, changed))
    monkeypatch.setattr(bootstrap, "_identity", lambda _path: next(identities))
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="changed during read"):
        bootstrap.remove(receipt_path=str(receipt))
    assert target.read_bytes() == original


def test_receipt_open_swap_is_rejected_before_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    target = site / bootstrap.PTH_NAME
    original = target.read_bytes()
    foreign = receipt.with_name("foreign-receipt.json")
    foreign.write_bytes(receipt.read_bytes())
    original_open = bootstrap.os.open

    def open_foreign(path: str, flags: int, mode: int = 0o777) -> int:
        if os.path.normcase(path) == os.path.normcase(str(receipt)):
            return original_open(str(foreign), flags, mode)
        return original_open(path, flags, mode)

    monkeypatch.setattr(bootstrap.os, "open", open_foreign)
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="changed while it was opened"):
        bootstrap.remove(receipt_path=str(receipt))
    assert target.read_bytes() == original


def test_cleanup_refuses_replacement_or_missing_target(tmp_path: Path) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    target = site / bootstrap.PTH_NAME
    target.unlink()
    target.write_text("foreign", encoding="utf-8")
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="refusing removal"):
        bootstrap.remove(receipt_path=str(receipt))
    assert target.read_text(encoding="utf-8") == "foreign"
    target.unlink()
    with pytest.raises(bootstrap.CoverageBootstrapInstallError):
        bootstrap.remove(receipt_path=str(receipt))


def test_exact_type_checks_and_posix_mode(tmp_path: Path) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    with pytest.raises(bootstrap.CoverageBootstrapInstallError):
        bootstrap.install(site_root=True, startup_root=str(startup), receipt_path=str(receipt))
    with pytest.raises(bootstrap.CoverageBootstrapInstallError):
        bootstrap.bootstrap_content(str(startup), dependency_roots=(str(startup),))
    bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    if os.name == "posix":
        assert stat.S_IMODE((site / bootstrap.PTH_NAME).stat().st_mode) == 0o600


def test_cli_exit_codes(tmp_path: Path) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    command = [sys.executable, str(Path(bootstrap.__file__).resolve())]
    installed = subprocess.run(command + ["install", "--site-root", str(site), "--startup-root", str(startup), "--receipt", str(receipt)], text=True, capture_output=True)
    assert installed.returncode == 0
    assert json.loads(installed.stdout)["target_path"] == str(site / bootstrap.PTH_NAME)
    duplicate = subprocess.run(command + ["install", "--site-root", str(site), "--startup-root", str(startup), "--receipt", str(receipt)], text=True, capture_output=True)
    assert duplicate.returncode == 2
    removed = subprocess.run(command + ["remove", "--receipt", str(receipt)], text=True, capture_output=True)
    assert removed.returncode == 0


@pytest.mark.parametrize("failure", (OSError("fsync"), MemoryError(), SystemExit(9), KeyboardInterrupt()))
def test_first_target_fsync_failure_rolls_back_and_preserves_nonordinary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: BaseException
) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)

    def fail_fsync(_fd: int) -> None:
        raise failure

    monkeypatch.setattr(bootstrap.os, "fsync", fail_fsync)
    expected = bootstrap.CoverageBootstrapInstallError if isinstance(failure, OSError) else type(failure)
    with pytest.raises(expected):
        bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    assert not (site / bootstrap.PTH_NAME).exists()
    assert not receipt.exists()


def test_receipt_fsync_failure_removes_every_created_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    original = bootstrap.os.fsync
    calls = 0

    def fail_second_fsync(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("receipt fsync")
        original(fd)

    monkeypatch.setattr(bootstrap.os, "fsync", fail_second_fsync)
    with pytest.raises(bootstrap.CoverageBootstrapInstallError):
        bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    assert not (site / bootstrap.PTH_NAME).exists()
    assert not receipt.exists()


@pytest.mark.parametrize("root_name", ("site", "dependency"))
def test_import_collision_in_site_or_dependency_is_rejected(tmp_path: Path, root_name: str) -> None:
    site, startup, dependency, receipt = _roots(tmp_path)
    root = site if root_name == "site" else dependency
    (root / "aoi_coverage_bootstrap.py").write_text("foreign\n", encoding="utf-8")
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="collision"):
        bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt), dependency_roots=[str(dependency)])
    assert not (site / bootstrap.PTH_NAME).exists()


def test_remove_rejects_mutated_module_witness(tmp_path: Path) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    (startup / bootstrap.MODULE_NAMES[1]).write_text("MUTATED = 1\n", encoding="utf-8")
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="witnesses"):
        bootstrap.remove(receipt_path=str(receipt))
    assert (site / bootstrap.PTH_NAME).exists()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_ancestor_symlink_and_whitespace_component_are_rejected(tmp_path: Path) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(tmp_path, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlink unavailable: {error}")
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="link or reparse"):
        bootstrap.install(site_root=str(linked / site.name), startup_root=str(startup), receipt_path=str(receipt))
    spaced = tmp_path / "site "
    spaced.mkdir()
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="whitespace-safe"):
        bootstrap.install(site_root=str(spaced), startup_root=str(startup), receipt_path=str(receipt))


def test_windows_reparse_ancestor_is_rejected_by_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    site, _startup, _dependency, _receipt = _roots(tmp_path)
    original = bootstrap.os.lstat

    def reparse(path: str) -> object:
        value = original(path)
        if os.path.normcase(path) == os.path.normcase(str(site)):
            return SimpleNamespace(st_mode=value.st_mode, st_file_attributes=1)
        return value

    monkeypatch.setattr(bootstrap.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1, raising=False)
    monkeypatch.setattr(bootstrap.os, "lstat", reparse)
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="link or reparse"):
        bootstrap._canonical_directory(str(site), "site root")


def test_remove_rechecks_identity_after_content_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    target = site / bootstrap.PTH_NAME
    original_read = bootstrap._read_exact
    original_identity = bootstrap._identity
    installed_identity = original_identity(str(target))
    replacement = b"X" * target.stat().st_size
    replaced = False

    def replace_after_read(path: str, limit: int) -> bytes:
        nonlocal replaced
        if path == str(target) and replaced:
            # Model a reopened replacement whose path and open-handle identity
            # both alias the installed file despite carrying foreign bytes.
            return replacement
        result = original_read(path, limit)
        if path == str(target) and not replaced:
            replaced = True
            target.unlink()
            target.write_bytes(replacement)
        return result

    def reused_identity(path: str) -> dict[str, int | None]:
        if path == str(target):
            return installed_identity
        return original_identity(path)

    monkeypatch.setattr(bootstrap, "_read_exact", replace_after_read)
    # Model immediate inode/metadata reuse explicitly instead of depending on
    # the temporary filesystem allocator to reproduce it by chance.
    monkeypatch.setattr(bootstrap, "_identity", reused_identity)
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="refusing removal"):
        bootstrap.remove(receipt_path=str(receipt))
    assert target.read_bytes() == replacement


def test_remove_rejects_byte_identical_replacement_with_changed_identity_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    target = site / bootstrap.PTH_NAME
    original = target.read_bytes()
    original_read = bootstrap._read_exact
    original_identity = bootstrap._identity
    installed_identity = original_identity(str(target))
    replacement_identity = dict(installed_identity)
    replacement_identity["identity_time_ns"] = (
        int(replacement_identity["identity_time_ns"] or 0) + 1
    )
    replaced = False

    def replace_after_read(path: str, limit: int) -> bytes:
        nonlocal replaced
        result = original_read(path, limit)
        if path == str(target) and not replaced:
            replaced = True
            target.unlink()
            target.write_bytes(original)
        return result

    def changed_identity(path: str) -> dict[str, int | None]:
        if path == str(target) and replaced:
            return replacement_identity
        return original_identity(path)

    monkeypatch.setattr(bootstrap, "_read_exact", replace_after_read)
    monkeypatch.setattr(bootstrap, "_identity", changed_identity)
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="refusing removal"):
        bootstrap.remove(receipt_path=str(receipt))
    assert target.read_bytes() == original


def test_v2_receipt_is_not_silently_upgraded_for_removal(tmp_path: Path) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    target = site / bootstrap.PTH_NAME
    original = target.read_bytes()
    record = json.loads(receipt.read_text(encoding="utf-8"))
    record["schema_version"] = 2
    for identity in (
        record["target_identity"],
        *(item["identity"] for item in record["module_witnesses"].values()),
    ):
        identity.pop("size")
        identity.pop("identity_time_ns")
    receipt.write_bytes(
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        + b"\n"
    )

    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="schema"):
        bootstrap.remove(receipt_path=str(receipt))
    assert target.read_bytes() == original


def test_cli_permission_error_is_typed_and_exit_two(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    monkeypatch.setattr(bootstrap.os, "unlink", lambda _path: (_ for _ in ()).throw(PermissionError("blocked")))
    assert bootstrap.main(["remove", "--receipt", str(receipt)]) == 2
    assert "coverage bootstrap:" in capsys.readouterr().err


def test_partial_write_after_import_line_rolls_back_by_creation_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    original = bootstrap.os.write
    calls = 0

    def write_import_then_fail(fd: int, data: bytes) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            assert b"import aoi_coverage_bootstrap\n" in data
            original(fd, data)  # The active import line is physically present.
            return len(data) - 1
        raise PermissionError("second write")

    monkeypatch.setattr(bootstrap.os, "write", write_import_then_fail)
    with pytest.raises(bootstrap.CoverageBootstrapInstallError):
        bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    assert not (site / bootstrap.PTH_NAME).exists()
    assert not receipt.exists()


def test_rollback_unlink_failure_reports_effect_unknown_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    monkeypatch.setattr(bootstrap.os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError("fsync")))
    monkeypatch.setattr(bootstrap.os, "unlink", lambda _path: (_ for _ in ()).throw(PermissionError("locked")))
    with pytest.raises(bootstrap.CoverageBootstrapEffectUnknownError) as raised:
        bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    assert raised.value.paths == (str(site / bootstrap.PTH_NAME),)
    assert (site / bootstrap.PTH_NAME).exists()


def test_receipt_failure_with_unlink_failure_reports_both_residues(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    original = bootstrap.os.fsync
    calls = 0

    def fail_receipt_fsync(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("receipt fsync")
        original(fd)

    monkeypatch.setattr(bootstrap.os, "fsync", fail_receipt_fsync)
    monkeypatch.setattr(bootstrap.os, "unlink", lambda _path: (_ for _ in ()).throw(PermissionError("locked")))
    with pytest.raises(bootstrap.CoverageBootstrapEffectUnknownError) as raised:
        bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    assert raised.value.paths == (str(receipt), str(site / bootstrap.PTH_NAME))


def test_create_then_fstat_failure_reports_reconcile_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    original = bootstrap.os.fstat
    calls = 0

    def fail_target_fstat(fd: int) -> os.stat_result:
        nonlocal calls
        calls += 1
        if calls == len(bootstrap.MODULE_NAMES) + 1:
            raise OSError("fstat")
        return original(fd)

    monkeypatch.setattr(bootstrap.os, "fstat", fail_target_fstat)
    with pytest.raises(bootstrap.CoverageBootstrapEffectUnknownError) as raised:
        bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    assert raised.value.paths == (str(site / bootstrap.PTH_NAME),)
    assert (site / bootstrap.PTH_NAME).exists()


def test_forward_slash_windows_path_checks_reparse_ancestor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    site, _startup, _dependency, _receipt = _roots(tmp_path)
    original = bootstrap.os.lstat

    def reparse(path: str) -> object:
        value = original(path)
        if os.path.normcase(os.path.normpath(path)) == os.path.normcase(str(site)):
            return SimpleNamespace(st_mode=value.st_mode, st_file_attributes=1)
        return value

    monkeypatch.setattr(bootstrap.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1, raising=False)
    monkeypatch.setattr(bootstrap.os, "lstat", reparse)
    forward = str(site).replace("\\", "/")
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="link or reparse"):
        bootstrap._canonical_directory(forward, "site root")


def test_receipt_bound_is_inclusive_and_install_rolls_back_oversize(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bootstrap._require_receipt_bound(b"x" * bootstrap.MAX_RECEIPT_BYTES)
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="exceeds"):
        bootstrap._require_receipt_bound(b"x" * (bootstrap.MAX_RECEIPT_BYTES + 1))
    site, startup, _dependency, receipt = _roots(tmp_path)
    monkeypatch.setattr(bootstrap, "MAX_RECEIPT_BYTES", 1)
    with pytest.raises(bootstrap.CoverageBootstrapInstallError, match="exceeds"):
        bootstrap.install(site_root=str(site), startup_root=str(startup), receipt_path=str(receipt))
    assert not (site / bootstrap.PTH_NAME).exists()
    assert not receipt.exists()


def test_public_main_receipt_partial_write_leaves_no_residue(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    original = bootstrap.os.write
    calls = 0

    def partial_receipt_then_fail(fd: int, data: bytes) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return original(fd, data)
        if calls == 2:
            original(fd, data)
            return len(data) - 1
        raise OSError("receipt continuation")

    monkeypatch.setattr(bootstrap.os, "write", partial_receipt_then_fail)
    assert bootstrap.main(["install", "--site-root", str(site), "--startup-root", str(startup), "--receipt", str(receipt)]) == 2
    assert not (site / bootstrap.PTH_NAME).exists()
    assert not receipt.exists()


@pytest.mark.parametrize("failure", (KeyboardInterrupt(), SystemExit(7), MemoryError()))
def test_stdout_nonordinary_cleans_bootstrap_then_propagates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: BaseException) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    monkeypatch.setattr(bootstrap.sys, "stdout", SimpleNamespace(buffer=SimpleNamespace(write=lambda _data: (_ for _ in ()).throw(failure))))
    with pytest.raises(type(failure)):
        bootstrap.main(["install", "--site-root", str(site), "--startup-root", str(startup), "--receipt", str(receipt)])
    assert not (site / bootstrap.PTH_NAME).exists()
    assert receipt.exists()


def test_stdout_nonordinary_cleanup_failure_keeps_effect_unknown_note(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    failure = MemoryError()
    monkeypatch.setattr(bootstrap.sys, "stdout", SimpleNamespace(buffer=SimpleNamespace(write=lambda _data: (_ for _ in ()).throw(failure))))
    monkeypatch.setattr(bootstrap.os, "unlink", lambda _path: (_ for _ in ()).throw(PermissionError("locked")))
    with pytest.raises(MemoryError) as raised:
        bootstrap.main(["install", "--site-root", str(site), "--startup-root", str(startup), "--receipt", str(receipt)])
    assert any("effect_unknown" in note and str(site / bootstrap.PTH_NAME) in note for note in getattr(raised.value, "__notes__", ()))
    assert (site / bootstrap.PTH_NAME).exists()
    assert receipt.exists()


def test_stdout_oserror_cleanup_failure_reports_effect_unknown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    monkeypatch.setattr(bootstrap.sys, "stdout", SimpleNamespace(buffer=SimpleNamespace(write=lambda _data: (_ for _ in ()).throw(OSError("stdout")))))
    monkeypatch.setattr(bootstrap.os, "unlink", lambda _path: (_ for _ in ()).throw(PermissionError("locked")))
    assert bootstrap.main(["install", "--site-root", str(site), "--startup-root", str(startup), "--receipt", str(receipt)]) == 2
    assert "effect_unknown" in capsys.readouterr().err
    assert (site / bootstrap.PTH_NAME).exists()
    assert receipt.exists()


def test_stdout_cleanup_and_stderr_failure_preserves_effect_unknown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    monkeypatch.setattr(bootstrap.sys, "stdout", SimpleNamespace(buffer=SimpleNamespace(write=lambda _data: (_ for _ in ()).throw(OSError("stdout")))))
    monkeypatch.setattr(bootstrap.sys, "stderr", SimpleNamespace(write=lambda _data: (_ for _ in ()).throw(OSError("stderr"))))
    monkeypatch.setattr(bootstrap.os, "unlink", lambda _path: (_ for _ in ()).throw(PermissionError("locked")))
    with pytest.raises(bootstrap.CoverageBootstrapEffectUnknownError) as raised:
        bootstrap.main(["install", "--site-root", str(site), "--startup-root", str(startup), "--receipt", str(receipt)])
    assert raised.value.paths == (str(site / bootstrap.PTH_NAME),)
    assert any("stderr publication failed" in note for note in getattr(raised.value, "__notes__", ()))
    assert (site / bootstrap.PTH_NAME).exists()
    assert receipt.exists()


def test_stderr_failure_preserves_ordinary_typed_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _site, _startup, _dependency, receipt = _roots(tmp_path)
    monkeypatch.setattr(bootstrap.sys, "stderr", SimpleNamespace(write=lambda _data: (_ for _ in ()).throw(OSError("stderr"))))
    with pytest.raises(bootstrap.CoverageBootstrapInstallError) as raised:
        bootstrap.main(["remove", "--receipt", str(receipt)])
    assert not isinstance(raised.value, bootstrap.CoverageBootstrapEffectUnknownError)
    assert any("stderr publication failed" in note for note in getattr(raised.value, "__notes__", ()))


def test_closed_stderr_preserves_effect_unknown_reconcile_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    closed = io.StringIO()
    closed.close()
    monkeypatch.setattr(bootstrap.sys, "stdout", SimpleNamespace(buffer=SimpleNamespace(write=lambda _data: (_ for _ in ()).throw(OSError("stdout")))))
    monkeypatch.setattr(bootstrap.sys, "stderr", closed)
    monkeypatch.setattr(bootstrap.os, "unlink", lambda _path: (_ for _ in ()).throw(PermissionError("locked")))
    with pytest.raises(bootstrap.CoverageBootstrapEffectUnknownError) as raised:
        bootstrap.main(["install", "--site-root", str(site), "--startup-root", str(startup), "--receipt", str(receipt)])
    assert raised.value.paths == (str(site / bootstrap.PTH_NAME),)
    assert any("stderr publication failed" in note for note in getattr(raised.value, "__notes__", ()))


def test_ascii_stderr_preserves_effect_unknown_reconcile_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _site, startup, _dependency, receipt = _roots(tmp_path)
    site = tmp_path / "site-站點"
    site.mkdir()
    stderr = io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="strict")
    monkeypatch.setattr(bootstrap.sys, "stdout", SimpleNamespace(buffer=SimpleNamespace(write=lambda _data: (_ for _ in ()).throw(OSError("stdout")))))
    monkeypatch.setattr(bootstrap.sys, "stderr", stderr)
    monkeypatch.setattr(bootstrap.os, "unlink", lambda _path: (_ for _ in ()).throw(PermissionError("locked")))
    with pytest.raises(bootstrap.CoverageBootstrapEffectUnknownError) as raised:
        bootstrap.main(["install", "--site-root", str(site), "--startup-root", str(startup), "--receipt", str(receipt)])
    assert raised.value.paths == (str(site / bootstrap.PTH_NAME),)
    assert any("stderr publication failed" in note for note in getattr(raised.value, "__notes__", ()))


@pytest.mark.parametrize("failure", (MemoryError(), SystemExit(3), KeyboardInterrupt()))
def test_stderr_nonordinary_preserves_effect_unknown_reconcile_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: BaseException) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    monkeypatch.setattr(bootstrap.sys, "stdout", SimpleNamespace(buffer=SimpleNamespace(write=lambda _data: (_ for _ in ()).throw(OSError("stdout")))))
    monkeypatch.setattr(bootstrap.sys, "stderr", SimpleNamespace(write=lambda _data: (_ for _ in ()).throw(failure)))
    monkeypatch.setattr(bootstrap.os, "unlink", lambda _path: (_ for _ in ()).throw(PermissionError("locked")))
    with pytest.raises(type(failure)) as raised:
        bootstrap.main(["install", "--site-root", str(site), "--startup-root", str(startup), "--receipt", str(receipt)])
    assert raised.value is failure
    assert any("effect_unknown" in note and str(site / bootstrap.PTH_NAME) in note for note in getattr(raised.value, "__notes__", ()))
    assert (site / bootstrap.PTH_NAME).exists()
    assert receipt.exists()


def test_stderr_nonordinary_preserves_non_effect_typed_diagnostic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _site, _startup, _dependency, receipt = _roots(tmp_path)
    failure = MemoryError()
    monkeypatch.setattr(bootstrap.sys, "stderr", SimpleNamespace(write=lambda _data: (_ for _ in ()).throw(failure)))
    with pytest.raises(MemoryError) as raised:
        bootstrap.main(["remove", "--receipt", str(receipt)])
    assert raised.value is failure
    assert any("file open failed" in note and "effect_unknown" not in note for note in getattr(raised.value, "__notes__", ()))


@pytest.mark.parametrize("failure", (MemoryError(), SystemExit(3), KeyboardInterrupt()))
def test_nonordinary_stdout_with_closed_stderr_preserves_original_boundary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: BaseException) -> None:
    site, startup, _dependency, receipt = _roots(tmp_path)
    closed = io.StringIO()
    closed.close()
    monkeypatch.setattr(bootstrap.sys, "stdout", SimpleNamespace(buffer=SimpleNamespace(write=lambda _data: (_ for _ in ()).throw(failure))))
    monkeypatch.setattr(bootstrap.sys, "stderr", closed)
    monkeypatch.setattr(bootstrap.os, "unlink", lambda _path: (_ for _ in ()).throw(PermissionError("locked")))
    with pytest.raises(type(failure)) as raised:
        bootstrap.main(["install", "--site-root", str(site), "--startup-root", str(startup), "--receipt", str(receipt)])
    assert any("effect_unknown" in note for note in getattr(raised.value, "__notes__", ()))
