from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading

import pytest

_IDENTITY_PATH = Path(__file__).parents[1] / "src" / "aoi_orgware" / "company" / "identity.py"
_IDENTITY_SPEC = importlib.util.spec_from_file_location("company_identity_under_test", _IDENTITY_PATH)
assert _IDENTITY_SPEC is not None and _IDENTITY_SPEC.loader is not None
_IDENTITY_MODULE = importlib.util.module_from_spec(_IDENTITY_SPEC)
sys.modules[_IDENTITY_SPEC.name] = _IDENTITY_MODULE
_IDENTITY_SPEC.loader.exec_module(_IDENTITY_MODULE)

from company_identity_under_test import (
    CompanyBindingInput,
    CompanyIdentityError,
    LegacyStateSource,
    company_binding_input,
    company_state_root,
    compare_rebind,
    deduplicate_legacy_sources,
    git_common_dir_identity,
    git_worktree_inventory,
    legacy_aoi_state_candidates,
    normalized_remote_fingerprint,
    normalize_remote_url,
    observed_remote_fingerprint,
    parse_git_worktree_porcelain,
)


_NATIVE_PLATFORM = "windows" if os.name == "nt" else "posix"


def _canonical_native_path(path: Path) -> str:
    value = path.resolve().as_posix()
    return value[0].upper() + value[1:].casefold() if _NATIVE_PLATFORM == "windows" else value


def _synthetic_directory_instance(platform: str) -> dict[str, str]:
    if platform == "windows":
        return {
            "schema": "aoi.company.directory-instance.windows-file-id.v1",
            "method": "win32-file-id-info",
            "volume_serial_number": "0000000000000001",
            "file_id": "00000000000000000000000000000001",
        }
    return {
        "schema": "aoi.company.directory-instance.posix-dev-inode-generation.v1",
        "method": "linux-fs-ioc-getversion",
        "device_major": "0",
        "device_minor": "1",
        "inode": "1",
        "generation": "1",
    }


def _common_identity(path: Path) -> dict[str, str]:
    value = _canonical_native_path(path)
    instance = _synthetic_directory_instance(_NATIVE_PLATFORM)
    identity = {
        "schema": "aoi.company.git-common-dir.v5",
        "common_dir": value,
        "directory_instance": instance,
        "platform": _NATIVE_PLATFORM,
    }
    return {
        **identity,
        "common_dir_sha256": hashlib.sha256(
            json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }


def test_state_roots_require_explicit_platform_and_external_base() -> None:
    assert company_state_root("company-1", platform="windows", environ={"LOCALAPPDATA": r"C:\\S"}).as_posix().endswith("AOI/companies/company-1")
    assert company_state_root("company-1", platform="posix", environ={"XDG_STATE_HOME": "/var/state"}).as_posix() == "/var/state/aoi/companies/company-1"
    assert company_state_root("company-1", platform="posix", environ={"HOME": "/s"}).as_posix() == "/s/.local/state/aoi/companies/company-1"
    with pytest.raises(CompanyIdentityError, match="platform"):
        company_state_root("company-1", platform="", environ={})
    with pytest.raises(CompanyIdentityError, match="LOCALAPPDATA"):
        company_state_root("company-1", platform="windows", environ={})


@pytest.mark.parametrize("company_id", ["con", "prn", "aux", "nul", "com1", "com9", "lpt1", "lpt9"])
def test_windows_state_root_rejects_reserved_company_ids(company_id: str) -> None:
    with pytest.raises(CompanyIdentityError, match="reserved device"):
        company_state_root(company_id, platform="windows", environ={"LOCALAPPDATA": r"C:\\state"})
    assert company_state_root(company_id, platform="posix", environ={"XDG_STATE_HOME": "/state"}).name == company_id


@pytest.mark.parametrize(
    "base",
    [
        r"C:\Users\alice\..\state",
        r"\\server\share\state",
        "//server/share/state",
        "1:/state",
        "?:/state",
        r"C:\state\CON.txt",
        r"C:\state\reports?.tmp",
    ],
)
def test_windows_state_root_rejects_traversal_network_and_win32_component_aliases(base: str) -> None:
    with pytest.raises(CompanyIdentityError):
        company_state_root("company-1", platform="windows", environ={"LOCALAPPDATA": base})


def test_state_root_normalizes_valid_platform_bases_without_live_io() -> None:
    windows = company_state_root(
        "company-1",
        platform="windows",
        environ={"LOCALAPPDATA": r"c:\Users\Alice\AppData\Local. "},
    )
    assert windows.as_posix() == "C:/users/alice/appdata/local/AOI/companies/company-1"
    assert company_state_root(
        "company-1", platform="posix", environ={"XDG_STATE_HOME": "/var/state"}
    ).as_posix() == "/var/state/aoi/companies/company-1"
    with pytest.raises(CompanyIdentityError, match="traversal"):
        company_state_root("company-1", platform="posix", environ={"XDG_STATE_HOME": "/var/../state"})
    with pytest.raises(CompanyIdentityError, match="double-slash"):
        company_state_root("company-1", platform="posix", environ={"XDG_STATE_HOME": "//var/state"})


def test_windows_drive_anchor_requires_ascii_letter_and_posix_single_slash_remains_valid() -> None:
    assert company_state_root(
        "company-1", platform="windows", environ={"LOCALAPPDATA": "C:/state"}
    ).as_posix() == "C:/state/AOI/companies/company-1"
    assert company_state_root(
        "company-1", platform="posix", environ={"XDG_STATE_HOME": "/state"}
    ).as_posix() == "/state/aoi/companies/company-1"
    for invalid in ("1:/state", "?:/state"):
        with pytest.raises(CompanyIdentityError, match="LOCALAPPDATA"):
            company_state_root("company-1", platform="windows", environ={"LOCALAPPDATA": invalid})


@pytest.mark.parametrize("component", ["CON", "prn.txt", "AUX .", "NUL...", "CLOCK$.log", "com9.bak", "COM1 .txt", "lpt1 "])
def test_windows_component_validator_rejects_reserved_devices_even_when_aliased(component: str) -> None:
    with pytest.raises(CompanyIdentityError):
        parse_git_worktree_porcelain(
            f"worktree C:/repo/{component}\nHEAD {'a' * 40}\ndetached\n",
            platform="windows",
            lock_domain="windows",
        )


@pytest.mark.parametrize("component", ["bad<name", "bad>name", 'bad"name', "bad:name", "bad|name", "bad?name", "bad*name"])
def test_windows_component_validator_rejects_wildcards_and_illegal_characters(component: str) -> None:
    with pytest.raises(CompanyIdentityError):
        parse_git_worktree_porcelain(
            f"worktree C:/repo/{component}\nHEAD {'a' * 40}\ndetached\n",
            platform="windows",
            lock_domain="windows",
        )


def test_remote_fingerprint_normalizes_spelling_and_order() -> None:
    first = normalized_remote_fingerprint({"origin": ["git@GitHub.COM:Org/Repo.git/"], "backup": ["https://github.com/Org/Repo.git"]})
    second = normalized_remote_fingerprint({"backup": ["https://github.com/Org/Repo.git/"], "origin": ["ssh://git@github.com/Org/Repo.git"]})
    assert first["sha256"] == second["sha256"]
    assert first["remotes"] == [
        {"name": "backup", "fetch_urls": ["https://github.com/Org/Repo.git"], "push_urls": ["https://github.com/Org/Repo.git"], "pushurl_configured": False},
        {"name": "origin", "fetch_urls": ["ssh://git@github.com/Org/Repo.git"], "push_urls": ["ssh://git@github.com/Org/Repo.git"], "pushurl_configured": False},
    ]


def test_observed_remote_fingerprint_binds_fetch_push_and_unset_fallback(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", "https://example.invalid/fetch.git"], check=True)
    fallback = observed_remote_fingerprint(repo)
    assert fallback["remotes"] == [{"name": "origin", "fetch_urls": ["https://example.invalid/fetch.git"], "push_urls": ["https://example.invalid/fetch.git"], "pushurl_configured": False}]
    subprocess.run(["git", "-C", str(repo), "remote", "set-url", "--push", "origin", "https://example.invalid/fetch.git"], check=True)
    configured_fallback = observed_remote_fingerprint(repo)
    assert configured_fallback["remotes"][0]["pushurl_configured"] is True
    assert configured_fallback["sha256"] != fallback["sha256"]
    subprocess.run(["git", "-C", str(repo), "remote", "set-url", "--push", "origin", "ssh://git@example.invalid/push.git"], check=True)
    divergent = observed_remote_fingerprint(repo)
    assert divergent["remotes"] == [{"name": "origin", "fetch_urls": ["https://example.invalid/fetch.git"], "push_urls": ["ssh://git@example.invalid/push.git"], "pushurl_configured": True}]
    assert divergent["sha256"] != fallback["sha256"]


def test_remote_normalization_supports_local_paths_and_ipv6_without_drive_scp_confusion() -> None:
    assert normalize_remote_url(r"C:\\AOI\repo.git") == "file:///C:/aoi/repo.git"
    assert normalize_remote_url("/srv/aoi/repo.git") == "file:///srv/aoi/repo.git"
    assert normalize_remote_url("file:///C:/AOI/repo.git") == "file:///C:/aoi/repo.git"
    assert normalize_remote_url("ssh://git@[2001:DB8::1]:2222/Org/Repo.git") == "ssh://git@[2001:db8::1]:2222/Org/Repo.git"
    assert normalize_remote_url("git@[2001:DB8::1]:Org/Repo.git") == "ssh://git@[2001:db8::1]/Org/Repo.git"


def test_windows_local_remote_aliases_are_canonical_across_drive_and_unc_spellings() -> None:
    drive = normalize_remote_url(r"c:\\Repo.\\Project.git ")
    drive_url = normalize_remote_url("file:///C:/repo./PROJECT.git")
    unc = normalize_remote_url(r"\\SERVER.\Share \Project.git ")
    unc_slash = normalize_remote_url("//SERVER./Share /PROJECT.git ")
    unc_url = normalize_remote_url("file://server/share/PROJECT.git")
    assert drive == drive_url == "file:///C:/repo/project.git"
    assert unc == unc_slash == unc_url == "file://server/share/project.git"
    assert normalize_remote_url("file://server-two/share/project.git") != unc
    assert normalize_remote_url("/Srv/AOI/Repo.git") == "file:///Srv/AOI/Repo.git"
    assert normalize_remote_url("/srv/aoi/repo.git") == "file:///srv/aoi/repo.git"


def test_remote_fingerprint_preserves_semantic_git_suffix() -> None:
    plain = normalized_remote_fingerprint({"origin": ["https://example.invalid/team/project"]})
    bare = normalized_remote_fingerprint({"origin": ["https://example.invalid/team/project.git"]})
    assert plain["sha256"] != bare["sha256"]


def test_binding_revalidates_remote_rows_not_only_their_digest(tmp_path: Path) -> None:
    common = _common_identity(tmp_path)
    forged = {"schema": "aoi.company.remote-fingerprint.v3", "remotes": [{"name": "origin", "fetch_urls": ["https://EXAMPLE.invalid/org/repo.git/"], "push_urls": ["https://EXAMPLE.invalid/org/repo.git/"], "pushurl_configured": False}]}
    forged["sha256"] = hashlib.sha256(json.dumps(forged, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    with pytest.raises(CompanyIdentityError, match="canonical rows"):
        company_binding_input(common, forged, platform=_NATIVE_PLATFORM, lock_domain=_NATIVE_PLATFORM, config_sha256="c" * 64)
    foreign = "/tmp/foreign-common-dir" if os.name == "nt" else r"C:\\foreign-common-dir"
    foreign_common = _common_identity(Path(foreign))
    foreign_common["common_dir"] = foreign
    foreign_common["common_dir_sha256"] = hashlib.sha256(foreign.encode("utf-8")).hexdigest()
    with pytest.raises(CompanyIdentityError, match="common-dir identity"):
        company_binding_input(foreign_common, normalized_remote_fingerprint({"origin": ["https://example.invalid/org/repo"]}), platform=_NATIVE_PLATFORM, lock_domain=_NATIVE_PLATFORM, config_sha256="c" * 64)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("generation", "1" * 100_000),
        ("birthtime_ns", "-0"),
    ),
    ids=("oversized-generation", "negative-zero-birthtime"),
)
def test_posix_directory_instance_decimals_are_canonical_and_bounded(
    field: str, value: str,
) -> None:
    instance = {
        "schema": (
            "aoi.company.directory-instance.posix-dev-inode-generation.v1"
            if field == "generation"
            else "aoi.company.directory-instance.posix-dev-inode-birthtime.v1"
        ),
        "method": (
            "linux-fs-ioc-getversion"
            if field == "generation"
            else "linux-statx-btime"
        ),
        "device_major": "0",
        "device_minor": "1",
        "inode": "1",
        field: value,
    }
    common = {
        "schema": "aoi.company.git-common-dir.v5",
        "common_dir": "/repo",
        "directory_instance": instance,
        "platform": "posix",
    }
    common["common_dir_sha256"] = hashlib.sha256(
        json.dumps(
            common,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    with pytest.raises(CompanyIdentityError, match="native instance"):
        company_binding_input(
            common,
            normalized_remote_fingerprint(
                {"origin": ["https://example.invalid/org/repo"]}
            ),
            platform="posix",
            lock_domain="posix",
            config_sha256="c" * 64,
        )


def test_remote_count_url_count_and_aggregate_bytes_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_IDENTITY_MODULE, "_MAX_REMOTE_COUNT", 1)
    with pytest.raises(CompanyIdentityError, match="count"):
        normalized_remote_fingerprint({
            "origin": ["https://example.invalid/a"],
            "backup": ["https://example.invalid/b"],
        })

    monkeypatch.setattr(_IDENTITY_MODULE, "_MAX_REMOTE_COUNT", 4096)
    monkeypatch.setattr(_IDENTITY_MODULE, "_MAX_REMOTE_URLS_PER_DIRECTION", 1)
    with pytest.raises(CompanyIdentityError, match="URL count"):
        normalized_remote_fingerprint({
            "origin": [
                "https://example.invalid/a",
                "https://example.invalid/b",
            ],
        })

    monkeypatch.setattr(_IDENTITY_MODULE, "_MAX_REMOTE_URLS_PER_DIRECTION", 256)
    monkeypatch.setattr(_IDENTITY_MODULE, "_MAX_REMOTE_AGGREGATE_BYTES", 8)
    with pytest.raises(CompanyIdentityError, match="aggregate"):
        normalized_remote_fingerprint(
            {"origin": ["https://example.invalid/a"]}
        )


def test_git_subprocess_capture_is_memory_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_IDENTITY_MODULE, "_MAX_GIT_OUTPUT_BYTES", 64)
    with pytest.raises(CompanyIdentityError, match="output exceeds bound"):
        _IDENTITY_MODULE._run_bounded_command(
            [sys.executable, "-S", "-c", "import os; os.write(1, b'x' * 65)"],
            label="run bounded-output canary",
        )


def test_git_subprocess_reader_error_is_typed_and_terminates_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenPipe:
        def __init__(self) -> None:
            self.closed = False

        def read(self, _size: int) -> bytes:
            raise OSError("injected pipe read failure")

        def close(self) -> None:
            self.closed = True

    class FakeProcess:
        def __init__(self) -> None:
            self.stdout = BrokenPipe()
            self.stderr = BrokenPipe()
            self.returncode: int | None = None
            self.killed = threading.Event()

        def poll(self) -> int | None:
            return self.returncode

        def kill(self) -> None:
            self.killed.set()
            self.returncode = -9

        def wait(self) -> int:
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

    process = FakeProcess()
    monkeypatch.setattr(
        _IDENTITY_MODULE.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )

    with pytest.raises(
        CompanyIdentityError,
        match=r"output reader failed: OSError: injected pipe read failure",
    ):
        _IDENTITY_MODULE._run_bounded_command(
            ["injected-command"],
            label="read injected pipes",
        )
    assert process.killed.is_set()
    assert process.stdout.closed and process.stderr.closed


def test_remote_raw_aggregate_bound_precedes_normalization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    normalized: list[str] = []
    monkeypatch.setattr(_IDENTITY_MODULE, "_MAX_REMOTE_AGGREGATE_BYTES", 8)
    monkeypatch.setattr(
        _IDENTITY_MODULE,
        "normalize_remote_url",
        lambda value: normalized.append(value) or value,
    )

    with pytest.raises(CompanyIdentityError, match="aggregate"):
        normalized_remote_fingerprint({"origin": ["x" * 9]})
    assert normalized == []


def test_observed_remote_commands_share_one_early_output_budget(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    git_bounds: list[int | None] = []
    config_bounds: list[int | None] = []
    outputs = iter(
        (
            b"origin\n",
            b"https://a/x\n",
            b"https://a/x\n",
        )
    )

    def fake_git(
        _root: Path,
        _arguments: tuple[str, ...],
        *,
        maximum_output_bytes: int | None = None,
    ) -> bytes:
        git_bounds.append(maximum_output_bytes)
        output = next(outputs)
        assert maximum_output_bytes is not None
        assert len(output) <= maximum_output_bytes
        return output

    def fake_command(
        _command: list[str],
        *,
        label: str,
        timeout_seconds: float = 10,
        maximum_output_bytes: int | None = None,
    ) -> object:
        del label, timeout_seconds
        config_bounds.append(maximum_output_bytes)
        return _IDENTITY_MODULE._BoundedCommandResult(1, b"", b"")

    monkeypatch.setattr(_IDENTITY_MODULE, "_MAX_REMOTE_AGGREGATE_BYTES", 40)
    monkeypatch.setattr(_IDENTITY_MODULE, "_require_worktree", lambda _path: tmp_path)
    monkeypatch.setattr(_IDENTITY_MODULE, "_run_git", fake_git)
    monkeypatch.setattr(_IDENTITY_MODULE, "_run_bounded_command", fake_command)

    observed = observed_remote_fingerprint(tmp_path)
    assert observed["remotes"][0]["name"] == "origin"
    assert git_bounds == [40, 33, 21]
    assert config_bounds == [9]


def test_binding_rejects_remote_row_count_before_iteration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class IterationTrap(list[object]):
        def __iter__(self) -> object:
            raise AssertionError("oversized remote rows must not be iterated")

    monkeypatch.setattr(_IDENTITY_MODULE, "_MAX_REMOTE_COUNT", 1)
    remote = {
        "schema": "aoi.company.remote-fingerprint.v3",
        "remotes": IterationTrap([{}, {}]),
        "sha256": "a" * 64,
    }
    common = _common_identity(tmp_path)
    with pytest.raises(CompanyIdentityError, match="count"):
        company_binding_input(
            common,
            remote,
            platform=_NATIVE_PLATFORM,
            lock_domain=_NATIVE_PLATFORM,
            config_sha256="c" * 64,
        )


def test_porcelain_inventory_and_legacy_candidates_cover_all_worktrees(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    (repo / "README").write_text("x", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "init"], check=True, capture_output=True)
    linked = tmp_path / "linked"
    subprocess.run(["git", "-C", str(repo), "worktree", "add", "-b", "linked", str(linked)], check=True, capture_output=True)
    (repo / ".aoi").mkdir()
    common_primary = git_common_dir_identity(repo)
    common_linked = git_common_dir_identity(linked)
    assert common_primary == common_linked
    worktrees = git_worktree_inventory(repo)
    candidates = legacy_aoi_state_candidates(worktrees)
    assert [candidate.worktree for candidate in candidates] == sorted([_canonical_native_path(repo), _canonical_native_path(linked)])
    assert [candidate.exists for candidate in candidates] == [False, True]


def test_v5_common_dir_identity_rebinds_on_move_and_same_path_replacement(tmp_path: Path) -> None:
    """Exercise real Git state: no synthetic inode or remote observation."""

    repo = tmp_path / "repo"
    bare = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(bare)], check=True, capture_output=True)
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", str(bare)], check=True)
    first_common = git_common_dir_identity(repo)
    first = company_binding_input(
        first_common,
        observed_remote_fingerprint(repo),
        platform=_NATIVE_PLATFORM,
        lock_domain=_NATIVE_PLATFORM,
        config_sha256="c" * 64,
    )
    assert first_common["schema"] == "aoi.company.git-common-dir.v5"
    assert first_common["directory_instance"]["method"] in {
        "win32-file-id-info",
        "linux-fs-ioc-getversion",
        "linux-statx-btime",
        "native-st-birthtime-ns",
    }
    assert observed_remote_fingerprint(repo)["remotes"][0]["fetch_urls"] == [
        normalize_remote_url(str(bare))
    ]

    moved = tmp_path / "moved-repo"
    repo.rename(moved)
    moved_common = git_common_dir_identity(moved)
    moved_binding = company_binding_input(
        moved_common,
        observed_remote_fingerprint(moved),
        platform=_NATIVE_PLATFORM,
        lock_domain=_NATIVE_PLATFORM,
        config_sha256="c" * 64,
    )
    assert moved_common["directory_instance"] == first_common["directory_instance"]
    assert compare_rebind(first, moved_binding).changed_fields == ("common_dir", "common_dir_sha256")

    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", str(bare)], check=True)
    replacement_common = git_common_dir_identity(repo)
    replacement = company_binding_input(
        replacement_common,
        observed_remote_fingerprint(repo),
        platform=_NATIVE_PLATFORM,
        lock_domain=_NATIVE_PLATFORM,
        config_sha256="c" * 64,
    )
    assert replacement_common["common_dir"] == first_common["common_dir"]
    assert replacement_common["directory_instance"] != first_common["directory_instance"]
    assert compare_rebind(first, replacement).changed_fields == ("common_dir_sha256",)


def test_rmtree_recreate_rebinds_even_if_the_filesystem_reuses_the_inode(tmp_path: Path) -> None:
    """Exercise the real delete/recreate path rather than a synthetic inode row."""

    common_dir = tmp_path / "common-dir"
    common_dir.mkdir()
    original = _IDENTITY_MODULE._directory_instance_identity(common_dir, platform=_NATIVE_PLATFORM)
    original_inode = original.get("inode")
    observed_reuse = False
    for _ in range(32):
        shutil.rmtree(common_dir)
        common_dir.mkdir()
        replacement = _IDENTITY_MODULE._directory_instance_identity(common_dir, platform=_NATIVE_PLATFORM)
        assert replacement != original
        if _NATIVE_PLATFORM == "posix" and replacement.get("inode") == original_inode:
            observed_reuse = True
            break
    # Fresh ext4 WSL commonly reaches this branch immediately; filesystems that
    # do not recycle an inode still prove every observed replacement rebinds.
    if _NATIVE_PLATFORM == "posix":
        assert observed_reuse or original_inode is not None


def test_windows_file_id_record_is_fixed_width_and_uses_no_python_stat_fields(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        _IDENTITY_MODULE,
        "_windows_file_id_info",
        lambda _path: (0x12AB, bytes.fromhex("00112233445566778899aabbccddeeff")),
    )
    record = _IDENTITY_MODULE._windows_directory_instance_identity(tmp_path)
    assert record == {
        "schema": "aoi.company.directory-instance.windows-file-id.v1",
        "method": "win32-file-id-info",
        "volume_serial_number": "00000000000012ab",
        "file_id": "00112233445566778899aabbccddeeff",
    }


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows FileIdInfo")
def test_windows_file_id_info_directly_changes_after_rmtree_recreate(tmp_path: Path) -> None:
    common_dir = tmp_path / "common-dir"
    common_dir.mkdir()
    before = _IDENTITY_MODULE._windows_file_id_info(common_dir)
    for _ in range(32):
        shutil.rmtree(common_dir)
        common_dir.mkdir()
        after = _IDENTITY_MODULE._windows_file_id_info(common_dir)
        if after != before:
            return
    pytest.fail("native FileIdInfo did not change across delete/recreate")


def test_v5_directory_instance_shape_is_exact_and_digest_bound(tmp_path: Path) -> None:
    common = _common_identity(tmp_path)
    instance = common["directory_instance"]
    instance["unexpected"] = "field"
    canonical = {key: value for key, value in common.items() if key != "common_dir_sha256"}
    common["common_dir_sha256"] = hashlib.sha256(
        json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    with pytest.raises(CompanyIdentityError, match="native instance"):
        company_binding_input(
            common,
            normalized_remote_fingerprint({"origin": ["https://example.invalid/org/repo"]}),
            platform=_NATIVE_PLATFORM,
            lock_domain=_NATIVE_PLATFORM,
            config_sha256="c" * 64,
        )


def test_common_dir_raw_path_is_inspected_before_resolve_without_foreign_io(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The Git reply is inspected as-is; resolution must not erase a hop first."""

    root = tmp_path / "worktree"
    root.mkdir()
    foreign_common = "/foreign/common-dir" if _NATIVE_PLATFORM == "posix" else "C:/foreign/common-dir"
    inspected: list[tuple[Path, str]] = []

    monkeypatch.setattr(_IDENTITY_MODULE, "_require_worktree", lambda *_args, **_kwargs: root)
    monkeypatch.setattr(_IDENTITY_MODULE, "_run_git", lambda *_args, **_kwargs: foreign_common.encode("utf-8"))

    def reject_raw_path(path: Path, *, label: str) -> None:
        inspected.append((path, label))
        raise CompanyIdentityError("raw common-dir inspection stopped before filesystem resolution")

    def unexpected_resolve(*_args: object, **_kwargs: object) -> Path:
        raise AssertionError("common-dir resolved before raw-path inspection")

    monkeypatch.setattr(_IDENTITY_MODULE, "_assert_native_existing_path_safe", reject_raw_path)
    monkeypatch.setattr(Path, "resolve", unexpected_resolve)
    with pytest.raises(CompanyIdentityError, match="raw common-dir inspection"):
        git_common_dir_identity(root)
    assert inspected == [(Path(foreign_common), "Git common-dir")]


def test_common_dir_removes_only_one_git_line_ending_without_stripping_path_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    root = Path(r"C:\\worktree") if _NATIVE_PLATFORM == "windows" else Path("/worktree")
    raw_common = r"C:\\git\\common-dir " if _NATIVE_PLATFORM == "windows" else "/git/common-dir "
    inspected: list[tuple[Path, str]] = []

    monkeypatch.setattr(_IDENTITY_MODULE, "_require_worktree", lambda *_args, **_kwargs: root)
    monkeypatch.setattr(_IDENTITY_MODULE, "_run_git", lambda *_args, **_kwargs: raw_common.encode("utf-8") + b"\n")
    monkeypatch.setattr(
        _IDENTITY_MODULE,
        "_assert_native_existing_path_safe",
        lambda path, *, label: inspected.append((path, label)),
    )
    monkeypatch.setattr(Path, "resolve", lambda self, **_kwargs: self)
    monkeypatch.setattr(Path, "is_dir", lambda _self: True)
    monkeypatch.setattr(Path, "is_symlink", lambda _self: False)
    monkeypatch.setattr(
        _IDENTITY_MODULE,
        "_directory_instance_identity",
        lambda _path, *, platform: _synthetic_directory_instance(platform),
    )

    identity = git_common_dir_identity(root)

    assert str(inspected[0][0]).endswith(" ")
    assert inspected[0][1] == "Git common-dir"
    assert identity["common_dir"] == _IDENTITY_MODULE._path_key(
        raw_common, platform=_NATIVE_PLATFORM, absolute=True
    )


def test_common_dir_rejects_cr_path_byte_after_removing_only_git_lf(monkeypatch: pytest.MonkeyPatch) -> None:
    root = Path(r"C:\\worktree") if _NATIVE_PLATFORM == "windows" else Path("/worktree")

    monkeypatch.setattr(_IDENTITY_MODULE, "_require_worktree", lambda *_args, **_kwargs: root)
    monkeypatch.setattr(
        _IDENTITY_MODULE,
        "_run_git",
        lambda *_args, **_kwargs: b"/git/common-dir\r\n",
    )

    with pytest.raises(CompanyIdentityError, match="malformed"):
        git_common_dir_identity(root)


def test_native_path_inspector_checks_every_existing_ancestor_before_resolution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    raw_common = tmp_path / "existing" / "common-dir"
    raw_common.mkdir(parents=True)
    inspected: list[Path] = []
    original_lstat = Path.lstat

    def record_lstat(path: Path, *_args: object, **_kwargs: object) -> os.stat_result:
        inspected.append(path)
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", record_lstat)
    _IDENTITY_MODULE._assert_native_existing_path_safe(raw_common, label="Git common-dir")
    expected = [candidate for candidate in reversed((raw_common, *raw_common.parents)) if candidate.exists()]
    assert inspected == expected


def test_porcelain_rejects_ambiguous_or_missing_records(tmp_path: Path) -> None:
    worktree = str(tmp_path / "worktree")
    with pytest.raises(CompanyIdentityError, match="lacks HEAD"):
        parse_git_worktree_porcelain(f"worktree {worktree}\nbranch refs/heads/main\n")
    with pytest.raises(CompanyIdentityError, match="duplicate paths"):
        parse_git_worktree_porcelain(f"worktree {worktree}\nHEAD " + "a" * 40 + f"\ndetached\n\nworktree {worktree}\nHEAD " + "b" * 40 + "\ndetached\n")
    with pytest.raises(CompanyIdentityError, match="absolute"):
        parse_git_worktree_porcelain("worktree relative\nHEAD " + "a" * 40 + "\nbranch refs/heads/main\n")
    with pytest.raises(CompanyIdentityError, match="both branch and detached"):
        parse_git_worktree_porcelain(f"worktree {worktree}\nHEAD " + "a" * 40 + "\nbranch refs/heads/main\ndetached\n")
    with pytest.raises(CompanyIdentityError, match="bare"):
        parse_git_worktree_porcelain(f"worktree {worktree}\nHEAD " + "a" * 40 + "\nbare\n")
    with pytest.raises(CompanyIdentityError, match="locked and prunable"):
        parse_git_worktree_porcelain(f"worktree {worktree}\nHEAD " + "a" * 40 + "\ndetached\nlocked\nprunable stale\n")
    foreign = "/tmp/foreign-worktree" if os.name == "nt" else r"C:\\foreign-worktree"
    with pytest.raises(CompanyIdentityError, match="absolute"):
        parse_git_worktree_porcelain(f"worktree {foreign}\nHEAD " + "a" * 40 + "\ndetached\n")
    parsed = parse_git_worktree_porcelain(f"worktree {worktree}\nHEAD " + "a" * 40 + "\ndetached\n")
    assert parsed[0].path == _canonical_native_path(tmp_path / "worktree")


@pytest.mark.parametrize("head", ["a" * 40, "b" * 64])
def test_porcelain_accepts_only_supported_git_object_id_lengths(head: str) -> None:
    parsed = parse_git_worktree_porcelain(
        f"worktree /repo\nHEAD {head}\ndetached\n",
        platform="posix",
        lock_domain="posix",
    )
    assert parsed[0].head_sha == head


@pytest.mark.parametrize("head", ["a" * 41, "b" * 63])
def test_porcelain_rejects_unsupported_git_object_id_lengths(head: str) -> None:
    with pytest.raises(CompanyIdentityError, match="HEAD is invalid"):
        parse_git_worktree_porcelain(
            f"worktree /repo\nHEAD {head}\ndetached\n",
            platform="posix",
            lock_domain="posix",
        )


def test_porcelain_platform_keys_detect_windows_aliases_but_preserve_posix_case() -> None:
    head = "a" * 40
    windows = f"worktree C:/Repo./Work \r\nHEAD {head}\r\ndetached\r\n\r\nworktree c:/repo/work\r\nHEAD {head}\r\ndetached\r\n"
    with pytest.raises(CompanyIdentityError, match="duplicate paths"):
        parse_git_worktree_porcelain(windows, platform="windows", lock_domain="windows")
    posix = f"worktree /repo/Work\nHEAD {head}\ndetached\n\nworktree /repo/work\nHEAD {head}\ndetached\n"
    parsed = parse_git_worktree_porcelain(posix, platform="posix", lock_domain="posix")
    assert [entry.path for entry in parsed] == ["/repo/Work", "/repo/work"]


def test_porcelain_windows_unc_anchors_remain_distinct_and_normalize_aliases() -> None:
    head = "a" * 40
    one = r"\\server-one\share\repo"
    two = r"\\server-two\share\repo"
    parsed = parse_git_worktree_porcelain(
        f"worktree {one}\r\nHEAD {head}\r\nbranch refs/heads/feature/nested\r\n\r\n"
        f"worktree {two}\r\nHEAD {head}\r\ndetached\r\n",
        platform="windows",
        lock_domain="windows",
    )
    assert [entry.path for entry in parsed] == ["//server-one/share/repo", "//server-two/share/repo"]
    alias = r"\\SERVER-ONE.\SHARE \Repo. "
    aliases = (
        f"worktree {alias}\nHEAD {head}\ndetached\n\n"
        f"worktree {one}\nHEAD {head}\ndetached\n"
    )
    with pytest.raises(CompanyIdentityError, match="duplicate paths"):
        parse_git_worktree_porcelain(aliases, platform="windows", lock_domain="windows")
    with pytest.raises(CompanyIdentityError, match="device paths are unsupported"):
        extended_unc = r"\\?\UNC\server\share\repo"
        parse_git_worktree_porcelain(
            f"worktree {extended_unc}\nHEAD {head}\ndetached\n",
            platform="windows",
            lock_domain="windows",
        )


@pytest.mark.parametrize(
    "branch",
    [
        "refs/heads/bad:branch",
        "refs/heads/foo..bar",
        "refs/heads/foo bar",
        "refs/heads/foo~bar",
        "refs/heads/foo^bar",
        "refs/heads/foo?bar",
        "refs/heads/foo*bar",
        "refs/heads/foo[bar",
        "refs/heads/foo@{bar",
        "refs/heads/@",
        "refs/heads//foo",
        "refs/heads/foo/",
        "refs/heads/foo/./bar",
        "refs/heads/foo/.lock",
        "refs/heads/foo.",
    ],
)
def test_porcelain_rejects_invalid_branch_refnames(branch: str) -> None:
    with pytest.raises(CompanyIdentityError, match="branch is invalid"):
        parse_git_worktree_porcelain(
            f"worktree /repo\nHEAD {'a' * 40}\nbranch {branch}\n",
            platform="posix",
            lock_domain="posix",
        )


def test_legacy_windows_aliases_and_claim_scopes_fail_closed_by_domain() -> None:
    same = b"same"
    with pytest.raises(CompanyIdentityError, match="non-canonical alias"):
        deduplicate_legacy_sources(
            [
                LegacyStateSource("a", "task", "C:/Repo./Work ", "C:/Repo./Work /.aoi/a", same, platform="windows", lock_domain="windows"),
                LegacyStateSource("b", "task", "C:/repo/work", "C:/repo/work/.aoi/b", same, platform="windows", lock_domain="windows"),
            ]
        )
    dedup = deduplicate_legacy_sources(
        [
            LegacyStateSource("claim-a", "claim", "C:/wt-a", "C:/wt-a/.aoi/a", same, live=True, conflict_key="repo:file:Src/Foo.", platform="windows", lock_domain="winlock"),
            LegacyStateSource("claim-b", "claim", "C:/wt-b", "C:/wt-b/.aoi/b", same, live=True, conflict_key="repo:file:src/foo", platform="windows", lock_domain="winlock"),
            LegacyStateSource("claim-c", "claim", "/wt-c", "/wt-c/.aoi/c", same, live=True, conflict_key="repo:file:src/foo", platform="posix", lock_domain="posix"),
        ]
    )
    assert [(item.object_id, item.reason) for item in dedup.conflicts] == [
        ("repo:file:src/foo", "overlapping_live_claim_scopes"),
        ("repo:file:src/foo", "overlapping_live_claim_scopes"),
        ("repo:file:src/foo", "overlapping_live_claim_scopes"),
    ]


@pytest.mark.parametrize(
    "source",
    [
        LegacyStateSource(1, "task", "/wt", "/wt/.aoi/a", b"x"),
        LegacyStateSource("task", 1, "/wt", "/wt/.aoi/a", b"x"),
        LegacyStateSource("task", "task", "/wt", "/wt/.aoi/a", bytearray(b"x")),
        LegacyStateSource("task", "task", "/wt", "/wt/.aoi/a", memoryview(b"x")),
        LegacyStateSource("task", "task", "/wt", "/wt/.aoi/a", b"x", live=1),
        LegacyStateSource("task", "task", "/wt", "/wt/.aoi/a", b"x", conflict_key=1),
        LegacyStateSource("x" * 513, "task", "/wt", "/wt/.aoi/a", b"x"),
        LegacyStateSource("task", "x" * 129, "/wt", "/wt/.aoi/a", b"x"),
        LegacyStateSource("task", "task", "/wt", "/wt/.aoi/a", b"x", conflict_key="x" * 4097),
    ],
)
def test_legacy_source_untrusted_fields_fail_closed_as_identity_errors(source: LegacyStateSource) -> None:
    with pytest.raises(CompanyIdentityError):
        deduplicate_legacy_sources([source])


def test_foreign_pure_paths_never_invoke_native_link_or_reparse_inspection(monkeypatch: pytest.MonkeyPatch) -> None:
    foreign_platform = "posix" if _NATIVE_PLATFORM == "windows" else "windows"

    def unexpected_io(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("foreign pure-path normalization attempted live I/O")

    monkeypatch.setattr(_IDENTITY_MODULE, "_assert_native_existing_path_safe", unexpected_io)
    foreign_worktree = "/foreign/worktree" if foreign_platform == "posix" else "C:/foreign/worktree"
    parse_git_worktree_porcelain(
        f"worktree {foreign_worktree}\nHEAD {'a' * 40}\ndetached\n",
        platform=foreign_platform,
        lock_domain="foreign-domain",
        live_native=False,
    )
    result = deduplicate_legacy_sources(
        [
            LegacyStateSource(
                "task",
                "task",
                foreign_worktree,
                f"{foreign_worktree}/.aoi/task" if foreign_platform == "posix" else f"{foreign_worktree}/.aoi/task",
                b"x",
                platform=foreign_platform,
                lock_domain="foreign-domain",
            )
        ]
    )
    assert len(result.groups) == 1


def test_native_legacy_paths_reject_a_reparse_marked_existing_member(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    worktree = tmp_path / "worktree"
    source_dir = worktree / ".aoi"
    source_dir.mkdir(parents=True)
    source = source_dir / "task"
    source.write_bytes(b"x")
    native_worktree = _canonical_native_path(worktree)
    native_source = _canonical_native_path(source)
    monkeypatch.setattr(_IDENTITY_MODULE, "_is_windows_reparse_point", lambda _metadata: True)
    with pytest.raises(CompanyIdentityError, match="reparse point"):
        deduplicate_legacy_sources(
            [LegacyStateSource("task", "task", native_worktree, native_source, b"x", platform=_NATIVE_PLATFORM, lock_domain=_NATIVE_PLATFORM)]
        )


@pytest.mark.parametrize(
    "source_path",
    [
        "/wt/.aoi",
        "/wt/.aoi-sibling/item",
        "/other/.aoi/item",
        "/wt/.aoi/../escape",
    ],
)
def test_legacy_sources_must_be_strict_descendants_of_their_worktree_aoi_root(source_path: str) -> None:
    with pytest.raises(CompanyIdentityError):
        deduplicate_legacy_sources([LegacyStateSource("task", "task", "/wt", source_path, b"x")])


@pytest.mark.parametrize(
    "source_path",
    [
        "C:/repo/.aoi/claim. ",
        r"\\?\C:\repo\.aoi\claim",
    ],
)
def test_legacy_windows_source_aliases_and_devices_fail_closed(source_path: str) -> None:
    with pytest.raises(CompanyIdentityError):
        deduplicate_legacy_sources(
            [
                LegacyStateSource(
                    "task",
                    "task",
                    "C:/repo",
                    source_path,
                    b"x",
                    platform="windows",
                    lock_domain="windows",
                )
            ]
        )


@pytest.mark.parametrize(
    "ref",
    ["foo:bar", "foo..bar", "foo bar", "foo~bar", "foo^bar", "foo?bar", "foo*bar", "foo[bar", "foo@{bar", "@", "/foo", "foo/", "foo/./bar", "foo/.lock", "foo."],
)
def test_invalid_git_merge_refs_fail_closed(ref: str) -> None:
    dedup = deduplicate_legacy_sources(
        [LegacyStateSource("claim", "claim", "/wt", "/wt/.aoi/claim", b"x", live=True, conflict_key=f"git:merge:{ref}")]
    )
    assert [(item.object_id, item.reason) for item in dedup.conflicts] == [("claim", "missing_or_invalid_live_claim_scope")]


def test_valid_git_merge_ref_and_lock_domain_rebind_are_explicit(tmp_path: Path) -> None:
    dedup = deduplicate_legacy_sources(
        [LegacyStateSource("claim", "claim", "/wt", "/wt/.aoi/claim", b"x", live=True, conflict_key="git:merge:feature/topic")]
    )
    assert dedup.conflicts == ()
    before = company_binding_input(_common_identity(tmp_path), normalized_remote_fingerprint({"origin": ["https://example.invalid/org/repo"]}), platform=_NATIVE_PLATFORM, lock_domain="domain-a", config_sha256="c" * 64)
    changed = CompanyBindingInput(before.common_dir, before.common_dir_sha256, before.remote_fingerprint_sha256, before.platform, "domain-b", before.config_sha256)
    assert compare_rebind(before, changed).changed_fields == ("lock_domain",)


def test_legacy_dedup_reports_divergence_and_live_conflict_without_preference() -> None:
    same = b"same"
    dedup = deduplicate_legacy_sources(
        [
            LegacyStateSource("task-1", "task", "/wt-a", "/wt-a/.aoi/tasks/task-1", same),
            LegacyStateSource("task-1", "task", "/wt-b", "/wt-b/.aoi/tasks/task-1", same),
            LegacyStateSource("claim-1", "claim", "/wt-a", "/wt-a/.aoi/claims/claim-1", same, live=True),
            LegacyStateSource("claim-1", "claim", "/wt-b", "/wt-b/.aoi/claims/claim-1", same, live=True),
            LegacyStateSource("task-2", "task", "/wt-a", "/wt-a/.aoi/tasks/task-2", b"a"),
            LegacyStateSource("task-2", "task", "/wt-b", "/wt-b/.aoi/tasks/task-2", b"b"),
        ]
    )
    assert [(group.object_id, len(group.sources), group.payload_sha256) for group in dedup.groups] == [
        ("claim-1", 2, hashlib.sha256(same).hexdigest()),
        ("task-1", 2, hashlib.sha256(same).hexdigest()),
    ]
    assert [(conflict.object_id, conflict.reason) for conflict in dedup.conflicts] == [
        ("claim-1", "conflicting_live_records"),
        ("task-2", "divergent_bytes"),
        ("claim-1", "missing_or_invalid_live_claim_scope"),
        ("claim-1", "missing_or_invalid_live_claim_scope"),
    ]


def test_legacy_source_count_and_aggregate_bytes_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = LegacyStateSource(
        "task-1", "task", "/wt", "/wt/.aoi/task-1", b"12",
    )
    second = LegacyStateSource(
        "task-2", "task", "/wt", "/wt/.aoi/task-2", b"34",
    )
    monkeypatch.setattr(_IDENTITY_MODULE, "_MAX_LEGACY_SOURCES", 1)
    with pytest.raises(CompanyIdentityError, match="count"):
        deduplicate_legacy_sources([first, second])

    monkeypatch.setattr(_IDENTITY_MODULE, "_MAX_LEGACY_SOURCES", 65536)
    monkeypatch.setattr(_IDENTITY_MODULE, "_MAX_LEGACY_AGGREGATE_BYTES", 1)
    with pytest.raises(CompanyIdentityError, match="aggregate"):
        deduplicate_legacy_sources([first])


def test_live_claims_without_scope_or_with_overlapping_scopes_block_reconciliation() -> None:
    same = b"same"
    dedup = deduplicate_legacy_sources(
        [
            LegacyStateSource("claim-a", "claim", "/wt-a", "/wt-a/.aoi/claims/a", same, live=True, conflict_key="repo:tree:src"),
            LegacyStateSource("claim-b", "claim", "/wt-b", "/wt-b/.aoi/claims/b", same, live=True, conflict_key="repo:file:src/company/identity.py"),
            LegacyStateSource("claim-c", "claim", "/wt-c", "/wt-c/.aoi/claims/c", same, live=True),
        ]
    )
    assert [(conflict.object_id, conflict.reason) for conflict in dedup.conflicts] == [
        ("claim-c", "missing_or_invalid_live_claim_scope"),
        ("repo:file:src/company/identity.py", "overlapping_live_claim_scopes"),
    ]


def test_cross_domain_logical_claims_fail_closed_without_conflating_host_or_external_roots() -> None:
    same = b"same"
    dedup = deduplicate_legacy_sources(
        [
            LegacyStateSource("repo-posix", "claim", "/wt-posix", "/wt-posix/.aoi/claims/repo", same, live=True, conflict_key="repo:tree:src", platform="posix", lock_domain="posix"),
            LegacyStateSource("repo-windows", "claim", "C:/wt-windows", "C:/wt-windows/.aoi/claims/repo", same, live=True, conflict_key="repo:file:Src/Company/identity.py", platform="windows", lock_domain="windows"),
            LegacyStateSource("git-posix", "claim", "/wt-posix", "/wt-posix/.aoi/claims/git", same, live=True, conflict_key="git:merge:feature/topic", platform="posix", lock_domain="posix"),
            LegacyStateSource("git-windows", "claim", "C:/wt-windows", "C:/wt-windows/.aoi/claims/git", same, live=True, conflict_key="git:merge:feature/topic", platform="windows", lock_domain="windows"),
            LegacyStateSource("contract-posix", "claim", "/wt-posix", "/wt-posix/.aoi/claims/contract", same, live=True, conflict_key="contract:release", platform="posix", lock_domain="posix"),
            LegacyStateSource("contract-windows", "claim", "C:/wt-windows", "C:/wt-windows/.aoi/claims/contract", same, live=True, conflict_key="contract:release", platform="windows", lock_domain="windows"),
            LegacyStateSource("host-posix", "claim", "/wt-posix", "/wt-posix/.aoi/claims/host", same, live=True, conflict_key="host:file:/var/aoi/shared", platform="posix", lock_domain="posix"),
            LegacyStateSource("host-windows", "claim", "C:/wt-windows", "C:/wt-windows/.aoi/claims/host", same, live=True, conflict_key="host:file:C:/var/aoi/shared", platform="windows", lock_domain="windows"),
            LegacyStateSource("external-posix", "claim", "/wt-posix", "/wt-posix/.aoi/claims/external", same, live=True, conflict_key="external:file:/var/aoi/shared", platform="posix", lock_domain="posix"),
            LegacyStateSource("external-windows", "claim", "C:/wt-windows", "C:/wt-windows/.aoi/claims/external", same, live=True, conflict_key="external:file:C:/var/aoi/shared", platform="windows", lock_domain="windows"),
        ]
    )
    assert [(item.object_id, item.reason) for item in dedup.conflicts] == [
        ("repo:file:src/company/identity.py", "overlapping_live_claim_scopes"),
        ("git:merge:feature/topic", "overlapping_live_claim_scopes"),
        ("contract:release", "overlapping_live_claim_scopes"),
    ]


def test_cross_domain_repo_claims_apply_win32_aliases_to_both_logical_paths() -> None:
    same = b"same"
    dedup = deduplicate_legacy_sources(
        [
            LegacyStateSource("posix", "claim", "/wt-posix", "/wt-posix/.aoi/claims/a", same, live=True, conflict_key="repo:file:rtl/top.sv.", platform="posix", lock_domain="posix"),
            LegacyStateSource("windows", "claim", "C:/wt-windows", "C:/wt-windows/.aoi/claims/b", same, live=True, conflict_key="repo:file:rtl/top.sv", platform="windows", lock_domain="windows"),
        ]
    )
    assert [(item.object_id, item.reason) for item in dedup.conflicts] == [
        ("repo:file:rtl/top.sv", "overlapping_live_claim_scopes"),
    ]
    same_platform = deduplicate_legacy_sources(
        [
            LegacyStateSource("upper", "claim", "/wt-a", "/wt-a/.aoi/claims/a", same, live=True, conflict_key="repo:file:RTL/top.sv", platform="posix", lock_domain="posix"),
            LegacyStateSource("lower", "claim", "/wt-b", "/wt-b/.aoi/claims/b", same, live=True, conflict_key="repo:file:rtl/top.sv", platform="posix", lock_domain="posix"),
        ]
    )
    assert same_platform.conflicts == ()
    with pytest.raises(CompanyIdentityError, match="Windows path"):
        deduplicate_legacy_sources(
            [
                LegacyStateSource("posix-invalid-on-windows", "claim", "/wt-posix", "/wt-posix/.aoi/claims/a", same, live=True, conflict_key="repo:file:rtl/top:stream.sv", platform="posix", lock_domain="posix"),
                LegacyStateSource("windows", "claim", "C:/wt-windows", "C:/wt-windows/.aoi/claims/b", same, live=True, conflict_key="repo:file:rtl/top.sv", platform="windows", lock_domain="windows"),
            ]
        )


def test_rebind_comparison_requires_explicit_action_for_any_binding_change(tmp_path: Path) -> None:
    common = _common_identity(tmp_path)
    remote = normalized_remote_fingerprint({"origin": ["https://example.invalid/org/repo"]})
    before = company_binding_input(common, remote, platform=_NATIVE_PLATFORM, lock_domain=_NATIVE_PLATFORM, config_sha256="c" * 64)
    after = CompanyBindingInput(before.common_dir, before.common_dir_sha256, before.remote_fingerprint_sha256, "posix" if _NATIVE_PLATFORM == "windows" else "windows", before.lock_domain, before.config_sha256)
    comparison = compare_rebind(before, after)
    assert comparison.requires_rebind is True
    assert comparison.changed_fields == ("platform",)
