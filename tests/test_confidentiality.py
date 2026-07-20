from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import confidentiality
from aoi_orgware.confidentiality import (
    ConfidentialityError,
    inspect_confidentiality,
    require_local_storage_path_allowed,
    require_publication_action_allowed,
)
from aoi_orgware.config import (
    ConfidentialityConfig,
    default_config_text,
    parse_config_bytes,
)


LOCAL_FILES = ConfidentialityConfig(
    mode="local_files",
    model_context="allowed",
    git_push="deny",
    remote_ci="deny",
    artifact_upload="deny",
    external_export="permit_required",
    local_cas=True,
)


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def _repo(root: Path) -> Path:
    root.mkdir(parents=True)
    _git(root, "init")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "AOI Test")
    (root / ".aoi").mkdir()
    return root


def _report(
    root: Path,
    *,
    tasks: list[dict[str, object]] | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    return inspect_confidentiality(
        root=root,
        state_dir=root / ".aoi",
        policy=LOCAL_FILES,
        config_sha256="a" * 64,
        tasks=[] if tasks is None else tasks,
        environment={} if environment is None else environment,
    )


def test_local_files_config_is_exact_and_standard_is_backward_compatible(
    tmp_path: Path,
) -> None:
    base = default_config_text("confidentiality")
    standard = parse_config_bytes(tmp_path, base.encode(), tmp_path / "standard.toml")
    assert standard.confidentiality.mode == "standard"
    assert standard.confidentiality.git_push == "allow"
    local = parse_config_bytes(
        tmp_path,
        (
            base
            + '\n[confidentiality]\nmode = "local_files"\n'
            + 'model_context = "allowed"\ngit_push = "deny"\n'
            + 'remote_ci = "deny"\nartifact_upload = "deny"\n'
            + 'external_export = "permit_required"\nlocal_cas = true\n'
        ).encode(),
        tmp_path / "local.toml",
    )
    assert local.confidentiality == LOCAL_FILES


@pytest.mark.parametrize(
    "override",
    [
        'model_context = "denied"',
        'git_push = "allow"',
        'remote_ci = "allow"',
        'artifact_upload = "allow"',
        'external_export = "allow"',
        "local_cas = false",
    ],
)
def test_local_files_rejects_one_permissive_field(
    tmp_path: Path, override: str
) -> None:
    values = {
        "model_context": 'model_context = "allowed"',
        "git_push": 'git_push = "deny"',
        "remote_ci": 'remote_ci = "deny"',
        "artifact_upload": 'artifact_upload = "deny"',
        "external_export": 'external_export = "permit_required"',
        "local_cas": "local_cas = true",
    }
    key = override.split("=", 1)[0].strip()
    values[key] = override
    text = default_config_text("confidentiality") + "\n[confidentiality]\nmode = \"local_files\"\n" + "\n".join(values.values()) + "\n"
    with pytest.raises(ValueError, match="local_files requires"):
        parse_config_bytes(tmp_path, text.encode(), tmp_path / "bad.toml")


def test_external_push_and_publish_credentials_fail_closed_without_secret_echo(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    _git(root, "remote", "add", "origin", "https://token@example.invalid/repo.git")
    report = _report(
        root,
        environment={
            "GH_TOKEN": "do-not-echo",
            "GITHUB_PAT": "do-not-echo",
            "AZURE_DEVOPS_EXT_PAT": "do-not-echo",
            "DOCKER_AUTH_CONFIG": "do-not-echo",
        },
    )
    errors = "\n".join(report["errors"])
    assert "effective Git push URL is external" in errors
    assert "GH_TOKEN" in errors
    assert "GITHUB_PAT" in errors
    assert "AZURE_DEVOPS_EXT_PAT" in errors
    assert "DOCKER_AUTH_CONFIG" in errors
    assert "do-not-echo" not in json.dumps(report)
    assert report["git"]["remotes"][0]["push"][0]["destination"] == "https://example.invalid"


def test_local_filesystem_push_remote_is_allowed(tmp_path: Path) -> None:
    root = _repo(tmp_path / "project")
    bare = tmp_path / "local-remote.git"
    bare.mkdir()
    _git(bare, "init", "--bare")
    _git(root, "remote", "add", "local", str(bare))
    report = _report(root)
    assert not [item for item in report["errors"] if "push URL" in item]
    assert report["git"]["remotes"][0]["push"][0]["kind"] == "local_path"


def test_mapped_and_unverified_drive_destinations_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repo(tmp_path / "project")

    def classify(path: Path) -> str | None:
        folded = str(path).replace("/", "\\").casefold()
        if "z:\\aoi" in folded:
            return "network_path"
        if "y:\\aoi" in folded:
            return "unverified_local_path"
        return None

    monkeypatch.setattr(confidentiality, "_windows_volume_kind", classify)
    assert confidentiality._destination_kind("Z:\\AOI\\state", root) == "network_path"
    assert (
        confidentiality._destination_kind("file:///Z:/AOI/state", root)
        == "network_path"
    )
    assert (
        confidentiality._destination_kind("file:///Z%3A/AOI/state", root)
        == "network_path"
    )
    assert confidentiality._destination_kind("file:///Z%ZZ/AOI/state", root) == "invalid"
    assert confidentiality._redacted_destination("file:///Z%ZZ/AOI/state", root) == "<invalid>"
    assert confidentiality._destination_kind("file:///C%00/AOI/state", root) == "invalid"
    assert confidentiality._redacted_destination("file:///C%00/AOI/state", root) == "<invalid>"
    assert confidentiality._destination_kind("file://[::1/path", root) == "invalid"
    assert confidentiality._redacted_destination("file://[::1/path", root) == "<invalid>"
    assert (
        confidentiality._destination_kind("file://localhost:99999/C:/repo", root)
        == "invalid"
    )
    assert (
        confidentiality._redacted_destination("file://localhost:99999/C:/repo", root)
        == "<invalid>"
    )
    assert (
        confidentiality._destination_kind(
            "https://example.invalid:99999/repo", root
        )
        == "invalid"
    )
    assert (
        confidentiality._redacted_destination(
            "https://example.invalid:99999/repo", root
        )
        == "<invalid>"
    )
    assert (
        confidentiality._destination_kind("Y:\\AOI\\state", root)
        == "unverified_local_path"
    )
    with pytest.raises(ConfidentialityError, match="confirmed network storage"):
        require_local_storage_path_allowed(
            LOCAL_FILES, Path("Z:\\AOI\\state"), label="AOI artifact/CAS root"
        )
    with pytest.raises(ConfidentialityError, match="locality is unverified"):
        require_local_storage_path_allowed(
            LOCAL_FILES, Path("Y:\\AOI\\state"), label="workspaceWrite cwd"
        )


def test_doctor_grades_mapped_and_unverified_push_drives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repo(tmp_path / "project")
    _git(root, "remote", "add", "mapped", "Z:/AOI/repo.git")
    _git(root, "remote", "add", "encoded", "file:///Z%3A/AOI/repo.git")
    _git(root, "remote", "add", "malformed", "file://[::1/path")
    _git(root, "remote", "add", "bad-percent", "file:///C%ZZ/AOI/repo.git")
    _git(root, "remote", "add", "bad-nul", "file:///C%00/AOI/repo.git")
    _git(
        root,
        "remote",
        "add",
        "bad-file-port",
        "file://localhost:99999/C:/AOI/repo.git",
    )
    _git(
        root,
        "remote",
        "add",
        "bad-http-port",
        "https://example.invalid:99999/AOI/repo.git",
    )
    _git(root, "remote", "add", "unknown", "Y:/AOI/repo.git")

    def classify(path: Path) -> str | None:
        folded = str(path).replace("/", "\\").casefold()
        if "z:\\aoi" in folded:
            return "network_path"
        if "y:\\aoi" in folded:
            return "unverified_local_path"
        return None

    monkeypatch.setattr(confidentiality, "_windows_volume_kind", classify)
    report = _report(root)
    rows = {item["name"]: item for item in report["git"]["remotes"]}
    assert rows["mapped"]["push"][0]["kind"] == "network_path"
    assert rows["encoded"]["push"][0]["kind"] == "network_path"
    assert rows["malformed"]["push"][0]["kind"] == "invalid"
    assert rows["malformed"]["push"][0]["destination"] == "<invalid>"
    for name in ("bad-percent", "bad-nul", "bad-file-port", "bad-http-port"):
        assert rows[name]["push"][0]["kind"] == "invalid"
        assert rows[name]["push"][0]["destination"] == "<invalid>"
    assert rows["unknown"]["push"][0]["kind"] == "unverified_local_path"
    errors = "\n".join(report["errors"])
    assert (
        "external for remote(s): bad-file-port, bad-http-port, bad-nul, "
        "bad-percent, encoded, malformed, mapped" in errors
    )
    assert "could not be confirmed local for remote(s): unknown" in errors


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 drive metadata only")
def test_win32_drive_type_and_alias_classification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(confidentiality, "_win32_drive_type", lambda _root: 4)
    assert confidentiality._windows_volume_kind(tmp_path) == "network_path"

    monkeypatch.setattr(confidentiality, "_win32_drive_type", lambda _root: 1)
    assert confidentiality._windows_volume_kind(tmp_path) == "unverified_local_path"

    monkeypatch.setattr(confidentiality, "_win32_drive_type", lambda _root: 3)
    monkeypatch.setattr(
        confidentiality, "_win32_dos_device", lambda _drive: "\\??\\C:\\alias"
    )
    assert confidentiality._windows_volume_kind(tmp_path) == "unverified_local_path"

    monkeypatch.setattr(
        confidentiality,
        "_win32_dos_device",
        lambda _drive: "\\Device\\HarddiskVolume3",
    )
    assert confidentiality._windows_volume_kind(tmp_path) == "local_path"

    queried: list[str] = []

    def subst_target(drive: str) -> str:
        queried.append(drive)
        return "\\??\\C:\\backing" if drive == "S:" else "\\Device\\HarddiskVolume3"

    class LexicalAliasPath:
        def expanduser(self) -> "LexicalAliasPath":
            return self

        def is_absolute(self) -> bool:
            return True

        def resolve(self, *, strict: bool = False) -> Path:
            raise AssertionError("SUBST alias must be rejected before resolve")

        def __str__(self) -> str:
            return "S:\\AOI\\state"

    monkeypatch.setattr(confidentiality, "_win32_dos_device", subst_target)
    assert (
        confidentiality._windows_volume_kind(LexicalAliasPath())  # type: ignore[arg-type]
        == "unverified_local_path"
    )
    assert queried == ["S:"]

    monkeypatch.setattr(
        confidentiality, "_win32_dos_device", lambda _drive: "\\??\\UNC\\server\\share"
    )
    assert confidentiality._windows_path_kind("S:\\AOI") == "network_path"
    monkeypatch.setattr(
        confidentiality, "_win32_dos_device", lambda _drive: "\\??\\Volume{alias}"
    )
    assert confidentiality._windows_path_kind("S:\\AOI") == "unverified_local_path"
    monkeypatch.setattr(
        confidentiality,
        "_win32_dos_device",
        lambda _drive: "\\Device\\WebDavRedirector\\server\\share",
    )
    assert confidentiality._windows_path_kind("S:\\AOI") == "network_path"


def test_local_files_rejects_reparse_path_as_unverified(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "linked"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory symlink creation is unavailable")
    with pytest.raises(ConfidentialityError, match="link/reparse point"):
        require_local_storage_path_allowed(
            LOCAL_FILES, link / "state", label="AOI artifact/CAS root"
        )


def test_generic_windows_reparse_attribute_fails_confirmed_local_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repo(tmp_path / "project")
    state = (root / ".aoi").resolve()
    monkeypatch.setattr(
        confidentiality,
        "_path_has_windows_reparse_attribute",
        lambda path: path.resolve(strict=False) == state,
    )
    with pytest.raises(ConfidentialityError, match="link/reparse point"):
        require_local_storage_path_allowed(
            LOCAL_FILES, state, label="AOI artifact/CAS root"
        )


def test_generic_windows_reparse_attribute_reads_file_attribute_bit() -> None:
    class FakePath:
        def __init__(self, attributes: int) -> None:
            self.attributes = attributes

        def lstat(self) -> object:
            return type("Metadata", (), {"st_file_attributes": self.attributes})()

    assert confidentiality._path_has_windows_reparse_attribute(FakePath(0x0400))  # type: ignore[arg-type]
    assert not confidentiality._path_has_windows_reparse_attribute(FakePath(0))  # type: ignore[arg-type]


def test_lfs_endpoint_rewrite_workflow_and_sync_root_are_reported(tmp_path: Path) -> None:
    root = _repo(tmp_path / "OneDrive" / "project")
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "release.yml").write_text(
        "on: push\n", encoding="utf-8"
    )
    (root / ".gitattributes").write_text("*.bin filter=lfs diff=lfs\n", encoding="utf-8")
    _git(root, "add", ".gitattributes")
    _git(root, "config", "lfs.url", "https://lfs.example.invalid/repo")
    _git(
        root,
        "config",
        "url.https://mirror.example.invalid/.pushInsteadOf",
        "local:",
    )
    report = _report(root)
    errors = "\n".join(report["errors"])
    warnings = "\n".join(report["warnings"])
    assert "Git LFS endpoint lfs.url is external" in errors
    assert "pushinsteadof rewrites pushes" in errors
    assert "synchronized folder" in errors
    assert report["git"]["lfs"]["tracked"] is True
    assert "remote CI/release workflow files are present" in warnings


def test_push_receipts_distinguish_current_from_historical_config(tmp_path: Path) -> None:
    root = _repo(tmp_path / "project")
    tasks = [
        {
            "task_id": "current",
            "config_sha256": "a" * 64,
            "delivery": {"mode": "pushed", "commit": "b" * 40},
        },
        {
            "task_id": "old",
            "config_sha256": "c" * 64,
            "delivery": {"mode": "pushed", "commit": "d" * 40},
        },
    ]
    report = _report(root, tasks=tasks)
    assert any("current local_files task" in item for item in report["errors"])
    assert any("historical pushed delivery" in item for item in report["warnings"])


def test_publication_gate_denies_but_does_not_claim_model_air_gap() -> None:
    with pytest.raises(ConfidentialityError, match="denies git_push"):
        require_publication_action_allowed(LOCAL_FILES, "git_push")
    assert LOCAL_FILES.model_context == "allowed"
