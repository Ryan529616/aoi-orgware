from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import confidentiality
from aoi_orgware.confidentiality import (
    ConfidentialityError,
    confidentiality_policy_binding,
    git_url_rewrite_keys,
    inspect_confidentiality,
    load_git_push_preflight_receipt,
    preflight_git_push,
    preflight_publication_paths,
    require_local_storage_path_allowed,
    require_publication_action_allowed,
    validate_git_push_preflight_receipt,
    validate_git_push_preflight_receipt_binding,
    validate_git_push_preflight_receipt_structure,
)
from aoi_orgware.config import (
    ConfidentialityConfig,
    ProtectedPathRule,
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


def _protected_home(
    destination: str = "https://example.invalid/home.git",
) -> ConfidentialityConfig:
    return ConfidentialityConfig(
        mode="local_files",
        model_context="allowed",
        git_push="deny",
        remote_ci="deny",
        artifact_upload="deny",
        external_export="permit_required",
        local_cas=True,
        protected=(
            ProtectedPathRule(
                path="private/secret.bin",
                kind="file",
                policy="home_remote_only",
                home_remote="origin",
                home_destination=destination,
            ),
        ),
    )


def _protected_local() -> ConfidentialityConfig:
    return ConfidentialityConfig(
        mode="local_files",
        model_context="allowed",
        git_push="deny",
        remote_ci="deny",
        artifact_upload="deny",
        external_export="permit_required",
        local_cas=True,
        protected=(
            ProtectedPathRule(
                path="private",
                kind="tree",
                policy="local_only",
            ),
        ),
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
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "AOI Test")
    (root / ".aoi").mkdir()
    return root


def _bare_repo(root: Path) -> Path:
    root.mkdir(parents=True)
    _git(root, "init", "--bare")
    return root


def _commit(root: Path, message: str) -> str:
    _git(root, "add", "-A")
    _git(root, "commit", "-m", message)
    return _git(root, "rev-parse", "HEAD")


def _redigest_git_push_preflight_receipt(receipt: dict[str, object]) -> None:
    payload = dict(receipt)
    del payload["receipt_sha256"]
    receipt["receipt_sha256"] = hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


def _report(
    root: Path,
    *,
    tasks: list[dict[str, object]] | None = None,
    environment: dict[str, str] | None = None,
    policy: ConfidentialityConfig = LOCAL_FILES,
) -> dict[str, object]:
    return inspect_confidentiality(
        root=root,
        state_dir=root / ".aoi",
        policy=policy,
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


def test_local_files_parses_destination_aware_rules_and_rejects_ambiguity(
    tmp_path: Path,
) -> None:
    base = default_config_text("confidentiality")
    text = base + """
[confidentiality]
mode = "local_files"
protected = [
  { path = "private/secret.bin", kind = "file", policy = "home_remote_only", home_remote = "origin", home_destination = "https://example.invalid/home.git" },
  { path = "eda/private", kind = "tree", policy = "local_only" },
]
"""
    parsed = parse_config_bytes(tmp_path, text.encode(), tmp_path / "rules.toml")
    assert parsed.confidentiality.protected == (
        ProtectedPathRule(
            path="private/secret.bin",
            kind="file",
            policy="home_remote_only",
            home_remote="origin",
            home_destination="https://example.invalid/home.git",
        ),
        ProtectedPathRule(
            path="eda/private",
            kind="tree",
            policy="local_only",
        ),
    )

    overlap = text.replace(
        '{ path = "eda/private", kind = "tree", policy = "local_only" }',
        '{ path = "private", kind = "tree", policy = "local_only" }',
    )
    with pytest.raises(ValueError, match="overlapping paths"):
        parse_config_bytes(tmp_path, overlap.encode(), tmp_path / "overlap.toml")

    case_ambiguous = text.replace(
        '{ path = "eda/private", kind = "tree", policy = "local_only" }',
        '{ path = "PRIVATE", kind = "tree", policy = "local_only" }',
    )
    with pytest.raises(ValueError, match="overlapping paths"):
        parse_config_bytes(
            tmp_path,
            case_ambiguous.encode(),
            tmp_path / "case-ambiguous.toml",
        )

    credential = text.replace(
        "https://example.invalid/home.git",
        "https://token@example.invalid/home.git",
    )
    with pytest.raises(ValueError, match="userinfo"):
        parse_config_bytes(tmp_path, credential.encode(), tmp_path / "secret.toml")

    standard = text.replace('mode = "local_files"', 'mode = "standard"')
    with pytest.raises(ValueError, match="protected requires"):
        parse_config_bytes(tmp_path, standard.encode(), tmp_path / "standard.toml")


def test_empty_rules_allow_external_repo_and_redact_publish_credentials(
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
    assert report["errors"] == []
    warnings = "\n".join(report["warnings"])
    assert "GH_TOKEN" in warnings
    assert "GITHUB_PAT" in warnings
    assert "AZURE_DEVOPS_EXT_PAT" in warnings
    assert "DOCKER_AUTH_CONFIG" in warnings
    assert "do-not-echo" not in json.dumps(report)
    assert report["git"]["remotes"][0]["push"][0]["destination"] == "https://example.invalid"
    assert report["protected"]["rule_count"] == 0
    assert report["protected"]["empty_rules_allow_normal_publication"] is True


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
            _protected_local(),
            Path("Z:\\AOI\\state"),
            label="AOI artifact/CAS root",
        )
    with pytest.raises(ConfidentialityError, match="locality is unverified"):
        require_local_storage_path_allowed(
            _protected_local(), Path("Y:\\AOI\\state"), label="workspaceWrite cwd"
        )

    assert require_local_storage_path_allowed(
        LOCAL_FILES, Path("Z:\\AOI\\state"), label="unclassified AOI state"
    ) == []


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
    assert report["errors"] == []


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
            _protected_local(), link / "state", label="AOI artifact/CAS root"
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
            _protected_local(), state, label="AOI artifact/CAS root"
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
    protected = root / "private" / "secret.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"classified")
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
    report = _report(root, policy=_protected_home())
    errors = "\n".join(report["errors"])
    warnings = "\n".join(report["warnings"])
    assert "synchronized folder" in errors
    assert report["git"]["lfs"]["tracked"] is True
    assert "remote CI/release workflow files are present" in warnings

    empty_rules = _report(root)
    assert empty_rules["errors"] == []
    assert not any(
        "synchronized folder" in item for item in empty_rules["warnings"]
    )


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
    assert report["errors"] == []
    assert not any(
        "separate selective preflight" in item for item in report["warnings"]
    )
    assert [
        row["receipt_artifact_sha256"] for row in report["receipts"]["push"]
    ] == ["", ""]


def test_doctor_binds_protected_path_to_exact_home_destination(tmp_path: Path) -> None:
    root = _repo(tmp_path / "project")
    protected = root / "private" / "secret.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"classified")
    _commit(root, "protected")
    _git(root, "remote", "add", "origin", "https://example.invalid/home.git")

    report = _report(root, policy=_protected_home())
    assert report["errors"] == []
    row = report["protected"]["rules"][0]
    assert row["path"] == "private/secret.bin"
    assert row["home_destination_status"] == "exact"
    assert row["tracked_path_count"] == 1
    assert row["content_count"] == 1

    _git(root, "remote", "set-url", "origin", "https://example.invalid/other.git")
    drifted = _report(root, policy=_protected_home())
    assert any("destination drifted" in item for item in drifted["errors"])


def test_doctor_reports_case_variant_protected_file_as_present_and_tracked(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    protected = root / "Private" / "Secret.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"case-folded identity")
    _commit(root, "protected case variant")
    _git(root, "remote", "add", "origin", "https://example.invalid/home.git")

    report = _report(root, policy=_protected_home())
    assert report["errors"] == []
    assert not any(
        "not currently Git-tracked" in item for item in report["warnings"]
    )
    row = report["protected"]["rules"][0]
    assert row["exists"] is True
    assert row["tracked_path_count"] == 1
    assert row["content_count"] == 1


def test_doctor_rejects_protected_push_without_bound_preflight(tmp_path: Path) -> None:
    root = _repo(tmp_path / "project")
    protected = root / "private" / "secret.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"classified")
    head = _commit(root, "protected")
    _git(root, "remote", "add", "origin", "https://example.invalid/home.git")
    report = _report(
        root,
        policy=_protected_home(),
        tasks=[
            {
                "task_id": "unreceipted-push",
                "config_sha256": "a" * 64,
                "delivery": {"mode": "pushed", "commit": head},
            }
        ],
    )
    assert any(
        "protected-content pushed delivery lacks a bound preflight receipt"
        in item
        for item in report["errors"]
    )


def test_git_preflight_allows_home_and_denies_other_repo(tmp_path: Path) -> None:
    root = _repo(tmp_path / "project")
    home = _bare_repo(tmp_path / "home.git")
    protected = root / "private" / "secret.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"classified")
    head = _commit(root, "protected")
    _git(root, "remote", "add", "origin", home.as_posix())
    _git(root, "remote", "add", "mirror", "https://example.invalid/other.git")
    zeros = "0" * len(head)
    update = [("refs/heads/main", head, "refs/heads/main", zeros)]

    receipt = preflight_git_push(
        root=root,
        policy=_protected_home(home.as_posix()),
        config_sha256="a" * 64,
        remote="origin",
        destination=home.as_posix(),
        updates=update,
    )
    assert receipt["decision"] == "allowed"
    assert receipt["protected_exposures"]
    exposure = receipt["protected_exposures"][0]
    assert exposure["path"] == "private/secret.bin"
    assert exposure["content_sha256"] == hashlib.sha256(b"classified").hexdigest()
    assert len(receipt["receipt_sha256"]) == 64
    assert validate_git_push_preflight_receipt(
        receipt,
        root=root,
        policy=_protected_home(home.as_posix()),
        config_sha256="a" * 64,
        remote="origin",
        destination=home.as_posix(),
        commit=head,
        remote_ref="refs/heads/main",
    ) == receipt["receipt_sha256"]
    delivery_binding = confidentiality_policy_binding(
        _protected_home(home.as_posix()), "a" * 64
    )
    assert validate_git_push_preflight_receipt_binding(
        receipt,
        root=root,
        binding=delivery_binding,
        remote="origin",
        destination=home.as_posix(),
        commit=head,
        remote_ref="refs/heads/main",
    ) == receipt["receipt_sha256"]
    changed_current_policy = LOCAL_FILES
    assert changed_current_policy.protected == ()
    with pytest.raises(ConfidentialityError, match="identity is invalid|policy binding"):
        validate_git_push_preflight_receipt_binding(
            receipt,
            root=root,
            binding=confidentiality_policy_binding(
                changed_current_policy, "b" * 64
            ),
            remote="origin",
            destination=home.as_posix(),
            commit=head,
            remote_ref="refs/heads/main",
        )
    tampered = json.loads(json.dumps(receipt))
    tampered["decision"] = "denied"
    with pytest.raises(ConfidentialityError, match="identity is invalid"):
        validate_git_push_preflight_receipt(
            tampered,
            root=root,
            policy=_protected_home(home.as_posix()),
            config_sha256="a" * 64,
            remote="origin",
            destination=home.as_posix(),
            commit=head,
            remote_ref="refs/heads/main",
        )

    with pytest.raises(ConfidentialityError, match="outside its configured policy"):
        preflight_git_push(
            root=root,
            policy=_protected_home(),
            config_sha256="a" * 64,
            remote="mirror",
            destination="https://example.invalid/other.git",
            updates=update,
        )


def test_git_preflight_empty_rules_allow_aoi_publication(tmp_path: Path) -> None:
    root = _repo(tmp_path / "project")
    home = _bare_repo(tmp_path / "aoi.git")
    (root / "aoi.py").write_text("print('release')\n", encoding="utf-8")
    head = _commit(root, "release")
    _git(root, "remote", "add", "origin", home.as_posix())
    zeros = "0" * len(head)
    receipt = preflight_git_push(
        root=root,
        policy=LOCAL_FILES,
        config_sha256="a" * 64,
        remote="origin",
        destination=home.as_posix(),
        updates=[("refs/heads/main", head, "refs/heads/main", zeros)],
    )
    assert receipt["protected_rule_count"] == 0
    assert receipt["protected_exposures"] == []
    assert receipt["outgoing_commits"] == [head]


def test_git_url_rewrite_keys_are_bounded_sorted_and_credential_free(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    _git(
        root,
        "config",
        "url.ssh://git@mirror.example.invalid/team/.insteadOf",
        "https://example.invalid/team/",
    )
    _git(
        root,
        "config",
        "--add",
        "url.https://push.example.invalid/team/.pushInsteadOf",
        "ssh://git@example.invalid/team/",
    )
    _git(
        root,
        "config",
        "--add",
        "url.https://push.example.invalid/team/.pushInsteadOf",
        "https://example.invalid/team/",
    )

    assert git_url_rewrite_keys(root) == (
        "url.https://push.example.invalid/team/.pushinsteadof",
        "url.https://push.example.invalid/team/.pushinsteadof",
        "url.ssh://git@mirror.example.invalid/team/.insteadof",
    )


def test_git_url_rewrite_guard_uses_transport_config_authority_when_ambient_hides_system(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repo(tmp_path / "project")
    system_config = tmp_path / "hidden-system.gitconfig"
    rewrite_key = "url.https://alternate.example.invalid/.insteadOf"
    _git(
        root,
        "config",
        "--file",
        system_config.as_posix(),
        "--add",
        rewrite_key,
        "https://source.example.invalid/",
    )
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(system_config))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")

    ambient = subprocess.run(
        ["git", "-C", str(root), "config", "--null", "--list"],
        env=os.environ.copy(),
        check=True,
        capture_output=True,
    )
    assert rewrite_key.encode("ascii") not in ambient.stdout
    assert git_url_rewrite_keys(root) == (rewrite_key.casefold(),)


def test_git_push_preflight_rejects_rewrite_injected_at_remote_network_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repo(tmp_path / "project")
    destination = _bare_repo(tmp_path / "destination.git")
    (root / "aoi.py").write_text("print('release')\n", encoding="utf-8")
    head = _commit(root, "release")
    _git(root, "remote", "add", "origin", destination.as_posix())
    assert git_url_rewrite_keys(root) == ()

    original_git = confidentiality._git_confidentiality_bytes
    network_calls: list[tuple[str, ...]] = []
    transport_calls = 0

    original_transport = confidentiality.effective_git_push_transport

    def inject_rewrite_at_network_boundary(
        project: Path, remote: str
    ) -> tuple[str, str]:
        nonlocal transport_calls
        result = original_transport(project, remote)
        transport_calls += 1
        if transport_calls == 2:
            # The second lookup is the re-resolution adjacent to the remote
            # ref inspection, after the ordinary preflight audit passed.
            _git(
                root,
                "config",
                "url.https://rewrite.invalid/.insteadOf",
                "https://source.invalid/",
            )
        return result

    def observe_network(
        project: Path, arguments: object, **kwargs: object
    ) -> bytes:
        command = tuple(arguments)  # type: ignore[arg-type]
        if command[:2] == ("ls-remote", "--refs"):
            network_calls.append(command)
        return original_git(project, command, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        confidentiality,
        "effective_git_push_transport",
        inject_rewrite_at_network_boundary,
    )
    monkeypatch.setattr(confidentiality, "_git_confidentiality_bytes", observe_network)
    with pytest.raises(ConfidentialityError, match="network boundary|rewrites exist"):
        preflight_git_push(
            root=root,
            policy=LOCAL_FILES,
            config_sha256="a" * 64,
            remote="origin",
            destination=destination.as_posix(),
            updates=[
                ("refs/heads/main", head, "refs/heads/main", "0" * len(head))
            ],
            forbid_url_rewrites=True,
        )
    assert transport_calls >= 2
    assert network_calls == []


def test_git_push_preflight_receipt_structure_is_pure_and_strict(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    home = _bare_repo(tmp_path / "aoi.git")
    (root / "aoi.py").write_text("print('release')\n", encoding="utf-8")
    head = _commit(root, "release")
    _git(root, "remote", "add", "origin", home.as_posix())
    receipt = preflight_git_push(
        root=root,
        policy=LOCAL_FILES,
        config_sha256="a" * 64,
        remote="origin",
        destination=home.as_posix(),
        updates=[("refs/heads/main", head, "refs/heads/main", "0" * len(head))],
    )

    assert validate_git_push_preflight_receipt_structure(receipt) == receipt[
        "receipt_sha256"
    ]

    tampered = json.loads(json.dumps(receipt))
    tampered["mode"] = "offline"
    _redigest_git_push_preflight_receipt(tampered)
    with pytest.raises(ConfidentialityError, match="identity is invalid"):
        validate_git_push_preflight_receipt_structure(tampered)

    wrong_schema = json.loads(json.dumps(receipt))
    wrong_schema["unexpected"] = True
    _redigest_git_push_preflight_receipt(wrong_schema)
    with pytest.raises(ConfidentialityError, match="schema is invalid"):
        validate_git_push_preflight_receipt_structure(wrong_schema)

    wrong_digest = json.loads(json.dumps(receipt))
    wrong_digest["receipt_sha256"] = "0" * 64
    with pytest.raises(ConfidentialityError, match="digest is invalid"):
        validate_git_push_preflight_receipt_structure(wrong_digest)


def test_git_preflight_peels_lightweight_and_annotated_tag_objects(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    home = _bare_repo(tmp_path / "aoi.git")
    (root / "aoi.py").write_text("print('release')\n", encoding="utf-8")
    head = _commit(root, "release")
    _git(root, "remote", "add", "origin", home.as_posix())
    zeros = "0" * len(head)

    _git(root, "tag", "lightweight-v1", head)
    lightweight_object = _git(root, "rev-parse", "refs/tags/lightweight-v1")
    lightweight = preflight_git_push(
        root=root,
        policy=LOCAL_FILES,
        config_sha256="a" * 64,
        remote="origin",
        destination=home.as_posix(),
        updates=[
            (
                "refs/tags/lightweight-v1",
                lightweight_object,
                "refs/tags/lightweight-v1",
                zeros,
            )
        ],
    )
    assert lightweight["updates"][0]["local_sha"] == lightweight_object == head
    assert lightweight["outgoing_commits"] == [head]
    assert lightweight["protected_rule_count"] == 0
    assert validate_git_push_preflight_receipt(
        lightweight,
        root=root,
        policy=LOCAL_FILES,
        config_sha256="a" * 64,
        remote="origin",
        destination=home.as_posix(),
        commit=head,
        remote_ref="refs/tags/lightweight-v1",
    ) == lightweight["receipt_sha256"]

    _git(root, "tag", "-a", "annotated-v1", "-m", "release", head)
    annotated_object = _git(root, "rev-parse", "refs/tags/annotated-v1")
    annotated = preflight_git_push(
        root=root,
        policy=LOCAL_FILES,
        config_sha256="a" * 64,
        remote="origin",
        destination=home.as_posix(),
        updates=[
            (
                "refs/tags/annotated-v1",
                annotated_object,
                "refs/tags/annotated-v1",
                zeros,
            )
        ],
    )
    assert annotated_object != head
    assert annotated["updates"][0]["local_sha"] == annotated_object
    assert annotated["outgoing_commits"] == [head]
    assert annotated["protected_rule_count"] == 0
    assert validate_git_push_preflight_receipt(
        annotated,
        root=root,
        policy=LOCAL_FILES,
        config_sha256="a" * 64,
        remote="origin",
        destination=home.as_posix(),
        commit=head,
        remote_ref="refs/tags/annotated-v1",
    ) == annotated["receipt_sha256"]


def test_git_preflight_receipt_validator_rejects_wrong_tag_binding(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    home = _bare_repo(tmp_path / "aoi.git")
    (root / "aoi.py").write_text("print('release')\n", encoding="utf-8")
    head = _commit(root, "release")
    _git(root, "remote", "add", "origin", home.as_posix())
    _git(root, "tag", "-a", "release-v1", "-m", "release", head)
    tag_object = _git(root, "rev-parse", "refs/tags/release-v1")
    receipt = preflight_git_push(
        root=root,
        policy=LOCAL_FILES,
        config_sha256="a" * 64,
        remote="origin",
        destination=home.as_posix(),
        updates=[
            (
                "refs/tags/release-v1",
                tag_object,
                "refs/tags/release-v1",
                "0" * len(head),
            )
        ],
    )

    (root / "aoi.py").write_text("print('next release')\n", encoding="utf-8")
    next_head = _commit(root, "next release")
    _git(root, "tag", "-a", "other-v1", "-m", "other", next_head)
    wrong_tag_object = _git(root, "rev-parse", "refs/tags/other-v1")
    wrong_tag_receipt = json.loads(json.dumps(receipt))
    wrong_tag_receipt["updates"][0]["local_sha"] = wrong_tag_object
    wrong_tag_payload = dict(wrong_tag_receipt)
    del wrong_tag_payload["receipt_sha256"]
    wrong_tag_receipt["receipt_sha256"] = hashlib.sha256(
        json.dumps(
            wrong_tag_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    with pytest.raises(ConfidentialityError, match="does not bind the delivered commit"):
        validate_git_push_preflight_receipt(
            wrong_tag_receipt,
            root=root,
            policy=LOCAL_FILES,
            config_sha256="a" * 64,
            remote="origin",
            destination=home.as_posix(),
            commit=head,
            remote_ref="refs/tags/release-v1",
        )

    tree = _git(root, "rev-parse", "HEAD^{tree}")
    _git(root, "tag", "-a", "tree-v1", "-m", "not a commit", tree)
    noncommit_tag_object = _git(root, "rev-parse", "refs/tags/tree-v1")
    noncommit_receipt = json.loads(json.dumps(receipt))
    noncommit_receipt["updates"][0]["local_sha"] = noncommit_tag_object
    noncommit_payload = dict(noncommit_receipt)
    del noncommit_payload["receipt_sha256"]
    noncommit_receipt["receipt_sha256"] = hashlib.sha256(
        json.dumps(
            noncommit_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    with pytest.raises(ConfidentialityError, match="receipt local commit inspection"):
        validate_git_push_preflight_receipt(
            noncommit_receipt,
            root=root,
            policy=LOCAL_FILES,
            config_sha256="a" * 64,
            remote="origin",
            destination=home.as_posix(),
            commit=head,
            remote_ref="refs/tags/release-v1",
        )

    with pytest.raises(ConfidentialityError, match="does not bind the delivered commit"):
        validate_git_push_preflight_receipt(
            receipt,
            root=root,
            policy=LOCAL_FILES,
            config_sha256="a" * 64,
            remote="origin",
            destination=home.as_posix(),
            commit=next_head,
            remote_ref="refs/tags/release-v1",
        )
    with pytest.raises(ConfidentialityError, match="does not bind the delivered commit/ref"):
        validate_git_push_preflight_receipt(
            receipt,
            root=root,
            policy=LOCAL_FILES,
            config_sha256="a" * 64,
            remote="origin",
            destination=home.as_posix(),
            commit=head,
            remote_ref="refs/tags/missing-v1",
        )


def test_git_preflight_fails_closed_for_tag_delete_noncommit_and_force_update(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    home = _bare_repo(tmp_path / "aoi.git")
    (root / "aoi.py").write_text("print('release')\n", encoding="utf-8")
    head = _commit(root, "release")
    _git(root, "remote", "add", "origin", home.as_posix())
    zeros = "0" * len(head)

    with pytest.raises(ConfidentialityError, match="tag deletion is denied"):
        preflight_git_push(
            root=root,
            policy=LOCAL_FILES,
            config_sha256="a" * 64,
            remote="origin",
            destination=home.as_posix(),
            updates=[("refs/tags/v1", zeros, "refs/tags/v1", head)],
        )

    tree = _git(root, "rev-parse", "HEAD^{tree}")
    _git(root, "tag", "-a", "tree-v1", "-m", "not a commit", tree)
    noncommit_object = _git(root, "rev-parse", "refs/tags/tree-v1")
    with pytest.raises(ConfidentialityError, match="local commit inspection"):
        preflight_git_push(
            root=root,
            policy=LOCAL_FILES,
            config_sha256="a" * 64,
            remote="origin",
            destination=home.as_posix(),
            updates=[
                ("refs/tags/tree-v1", noncommit_object, "refs/tags/tree-v1", zeros)
            ],
        )

    _git(root, "tag", "-a", "force-v1", "-m", "first", head)
    _git(root, "push", "origin", "refs/tags/force-v1")
    old_tag_object = _git(root, "rev-parse", "refs/tags/force-v1")
    (root / "aoi.py").write_text("print('next release')\n", encoding="utf-8")
    next_head = _commit(root, "next release")
    _git(root, "tag", "-f", "-a", "force-v1", "-m", "replacement", next_head)
    new_tag_object = _git(root, "rev-parse", "refs/tags/force-v1")
    with pytest.raises(ConfidentialityError, match="tag updates after creation are denied"):
        preflight_git_push(
            root=root,
            policy=LOCAL_FILES,
            config_sha256="a" * 64,
            remote="origin",
            destination=home.as_posix(),
            updates=[
                (
                    "refs/tags/force-v1",
                    new_tag_object,
                    "refs/tags/force-v1",
                    old_tag_object,
                )
            ],
        )


def test_git_preflight_rejects_retroactive_receipt_for_existing_remote_tip(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    home = _bare_repo(tmp_path / "home.git")
    protected = root / "private" / "secret.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"already remote")
    head = _commit(root, "already delivered")
    _git(root, "remote", "add", "origin", home.as_posix())
    _git(root, "push", "origin", "main:refs/heads/main")

    with pytest.raises(ConfidentialityError, match="delivered commit was outgoing"):
        preflight_git_push(
            root=root,
            policy=_protected_home(home.as_posix()),
            config_sha256="a" * 64,
            remote="origin",
            destination=home.as_posix(),
            updates=[("refs/heads/main", head, "refs/heads/main", head)],
        )


def test_member_level_publication_preflight_is_selective_and_destination_aware(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    protected = root / "private" / "secret.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"classified package member")
    public_archive = root / "dist" / "public.whl"
    public_archive.parent.mkdir()
    with zipfile.ZipFile(public_archive, "w") as archive:
        archive.writestr("pkg/public.bin", b"public")

    allowed = preflight_publication_paths(
        root=root,
        policy=_protected_home(),
        config_sha256="a" * 64,
        action="package_publish",
        destination="https://pypi.org/project/example",
        subject_paths=[public_archive],
    )
    assert allowed["decision"] == "allowed"
    assert allowed["protected_exposures"] == []

    protected_archive = root / "dist" / "protected.whl"
    with zipfile.ZipFile(protected_archive, "w") as archive:
        archive.writestr("pkg/copied.bin", protected.read_bytes())
    with pytest.raises(ConfidentialityError, match="outside its configured policy"):
        preflight_publication_paths(
            root=root,
            policy=_protected_home(),
            config_sha256="a" * 64,
            action="package_publish",
            destination="https://pypi.org/project/example",
            subject_paths=[protected_archive],
        )

    path_matched_archive = root / "dist" / "path-matched.whl"
    with zipfile.ZipFile(path_matched_archive, "w") as archive:
        archive.writestr("private/secret.bin", b"transformed protected content")
    with pytest.raises(ConfidentialityError, match="outside its configured policy"):
        preflight_publication_paths(
            root=root,
            policy=_protected_home(),
            config_sha256="a" * 64,
            action="artifact_upload",
            destination="https://github.com/example/project/actions/artifacts",
            subject_paths=[path_matched_archive],
        )


def test_empty_rules_allow_member_level_package_publication(tmp_path: Path) -> None:
    root = _repo(tmp_path / "project")
    archive_path = root / "dist.whl"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("aoi_orgware/__init__.py", b"published AOI bytes")

    receipt = preflight_publication_paths(
        root=root,
        policy=LOCAL_FILES,
        config_sha256="a" * 64,
        action="package_publish",
        destination="https://pypi.org/project/aoi-orgware",
        subject_paths=[archive_path],
    )

    assert receipt["decision"] == "allowed"
    assert receipt["protected_rule_count"] == 0
    assert receipt["containers"][0]["sha256"] == hashlib.sha256(
        archive_path.read_bytes()
    ).hexdigest()
    assert len(receipt["receipt_sha256"]) == 64


def test_git_preflight_rejects_forged_or_stale_remote_pre_state(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    home = _bare_repo(tmp_path / "aoi.git")
    (root / "base.txt").write_text("base\n", encoding="utf-8")
    base = _commit(root, "base")
    (root / "aoi.py").write_text("print('release')\n", encoding="utf-8")
    head = _commit(root, "release")
    zeros = "0" * len(head)
    _git(root, "branch", "other", base)
    _git(root, "remote", "add", "origin", home.as_posix())

    with pytest.raises(ConfidentialityError, match="local ref.*differs"):
        preflight_git_push(
            root=root,
            policy=LOCAL_FILES,
            config_sha256="a" * 64,
            remote="origin",
            destination=home.as_posix(),
            updates=[("refs/heads/other", head, "refs/heads/main", zeros)],
        )

    with pytest.raises(ConfidentialityError, match="exact pre-push remote state"):
        preflight_git_push(
            root=root,
            policy=LOCAL_FILES,
            config_sha256="a" * 64,
            remote="origin",
            destination=home.as_posix(),
            updates=[("refs/heads/main", head, "refs/heads/main", head)],
        )

    _git(root, "push", "origin", "HEAD:refs/heads/main")
    with pytest.raises(ConfidentialityError, match="exact pre-push remote state"):
        preflight_git_push(
            root=root,
            policy=LOCAL_FILES,
            config_sha256="a" * 64,
            remote="origin",
            destination=home.as_posix(),
            updates=[("refs/heads/main", head, "refs/heads/main", zeros)],
        )


def test_git_preflight_treats_git_metacharacters_as_literal_paths(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    home = _bare_repo(tmp_path / "home.git")
    protected = root / "private" / "[secret].bin"
    protected.parent.mkdir()
    protected.write_bytes(b"literal path")
    head = _commit(root, "protected literal path")
    _git(root, "remote", "add", "origin", home.as_posix())
    policy = ConfidentialityConfig(
        mode="local_files",
        model_context="allowed",
        git_push="deny",
        remote_ci="deny",
        artifact_upload="deny",
        external_export="permit_required",
        local_cas=True,
        protected=(
            ProtectedPathRule(
                path="private/[secret].bin",
                kind="file",
                policy="home_remote_only",
                home_remote="origin",
                home_destination=home.as_posix(),
            ),
        ),
    )
    receipt = preflight_git_push(
        root=root,
        policy=policy,
        config_sha256="a" * 64,
        remote="origin",
        destination=home.as_posix(),
        updates=[("refs/heads/main", head, "refs/heads/main", "0" * len(head))],
    )
    assert [row["path"] for row in receipt["protected_exposures"]] == [
        "private/[secret].bin"
    ]


def test_git_preflight_protects_case_variant_path_identity(tmp_path: Path) -> None:
    root = _repo(tmp_path / "project")
    protected = root / "Private" / "Secret.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"case-folded identity")
    head = _commit(root, "protected case variant")
    _git(root, "remote", "add", "mirror", "https://example.invalid/other.git")
    policy = ConfidentialityConfig(
        mode="local_files",
        model_context="allowed",
        git_push="deny",
        remote_ci="deny",
        artifact_upload="deny",
        external_export="permit_required",
        local_cas=True,
        protected=(
            ProtectedPathRule(
                path="private/secret.bin",
                kind="file",
                policy="home_remote_only",
                home_remote="origin",
                home_destination="https://example.invalid/home.git",
            ),
        ),
    )
    with pytest.raises(ConfidentialityError, match="outside its configured policy"):
        preflight_git_push(
            root=root,
            policy=policy,
            config_sha256="a" * 64,
            remote="mirror",
            destination="https://example.invalid/other.git",
            updates=[
                ("refs/heads/main", head, "refs/heads/main", "0" * len(head))
            ],
        )


def test_git_preflight_keeps_non_ascii_path_identity_exact(tmp_path: Path) -> None:
    root = _repo(tmp_path / "project")
    protected = root / "private" / "Straße.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"unicode spelling")
    head = _commit(root, "non-ASCII protected spelling")
    _git(root, "remote", "add", "mirror", "https://example.invalid/other.git")
    policy = ConfidentialityConfig(
        mode="local_files",
        model_context="allowed",
        git_push="deny",
        remote_ci="deny",
        artifact_upload="deny",
        external_export="permit_required",
        local_cas=True,
        protected=(
            ProtectedPathRule(
                path="private/STRASSE.bin",
                kind="file",
                policy="home_remote_only",
                home_remote="origin",
                home_destination="https://example.invalid/home.git",
            ),
        ),
    )
    with pytest.raises(ConfidentialityError, match="protected path is missing"):
        preflight_git_push(
            root=root,
            policy=policy,
            config_sha256="a" * 64,
            remote="mirror",
            destination="https://example.invalid/other.git",
            updates=[
                ("refs/heads/main", head, "refs/heads/main", "0" * len(head))
            ],
        )


def test_git_preflight_supports_exact_non_ascii_protected_path(tmp_path: Path) -> None:
    root = _repo(tmp_path / "project")
    home = _bare_repo(tmp_path / "home.git")
    protected = root / "私密" / "檔案.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"exact unicode path")
    head = _commit(root, "exact non-ASCII protected path")
    _git(root, "remote", "add", "origin", home.as_posix())
    policy = ConfidentialityConfig(
        mode="local_files",
        model_context="allowed",
        git_push="deny",
        remote_ci="deny",
        artifact_upload="deny",
        external_export="permit_required",
        local_cas=True,
        protected=(
            ProtectedPathRule(
                path="私密/檔案.bin",
                kind="file",
                policy="home_remote_only",
                home_remote="origin",
                home_destination=home.as_posix(),
            ),
        ),
    )
    receipt = preflight_git_push(
        root=root,
        policy=policy,
        config_sha256="a" * 64,
        remote="origin",
        destination=home.as_posix(),
        updates=[("refs/heads/main", head, "refs/heads/main", "0" * len(head))],
    )
    assert [row["path"] for row in receipt["protected_exposures"]] == [
        "私密/檔案.bin"
    ]


def test_git_preflight_rejects_ambiguous_casefold_path_identity(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    parent = root / "private"
    parent.mkdir()
    upper = parent / "Secret.bin"
    lower = parent / "secret.bin"
    upper.write_bytes(b"upper spelling")
    lower.write_bytes(b"lower spelling")
    if upper.samefile(lower):
        pytest.skip("filesystem does not permit case-distinct path identities")
    head = _commit(root, "ambiguous protected case variants")
    _git(root, "remote", "add", "mirror", "https://example.invalid/other.git")
    policy = ConfidentialityConfig(
        mode="local_files",
        model_context="allowed",
        git_push="deny",
        remote_ci="deny",
        artifact_upload="deny",
        external_export="permit_required",
        local_cas=True,
        protected=(
            ProtectedPathRule(
                path="private/secret.bin",
                kind="file",
                policy="home_remote_only",
                home_remote="origin",
                home_destination="https://example.invalid/home.git",
            ),
        ),
    )
    with pytest.raises(ConfidentialityError, match="ambiguous case-fold identity"):
        preflight_git_push(
            root=root,
            policy=policy,
            config_sha256="a" * 64,
            remote="mirror",
            destination="https://example.invalid/other.git",
            updates=[
                ("refs/heads/main", head, "refs/heads/main", "0" * len(head))
            ],
        )


@pytest.mark.parametrize(
    "ambient_pathspec_mode",
    (
        None,
        "GIT_LITERAL_PATHSPECS",
        "GIT_GLOB_PATHSPECS",
        "GIT_NOGLOB_PATHSPECS",
        "GIT_ICASE_PATHSPECS",
    ),
)
def test_git_preflight_follows_case_variant_historical_blob_after_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ambient_pathspec_mode: str | None,
) -> None:
    root = _repo(tmp_path / "project")
    home = _bare_repo(tmp_path / "home.git")
    protected = root / "Private" / "Secret.bin"
    protected.parent.mkdir()
    old_bytes = b"historical protected bytes"
    protected.write_bytes(old_bytes)
    base = _commit(root, "protected case-variant base")
    _git(root, "remote", "add", "origin", home.as_posix())
    _git(root, "push", "origin", "HEAD:refs/heads/main")

    protected.write_bytes(b"current protected bytes")
    copied = root / "public" / "renamed.bin"
    copied.parent.mkdir()
    copied.write_bytes(old_bytes)
    head = _commit(root, "copy historical bytes and revise protected origin")
    if ambient_pathspec_mode is not None:
        monkeypatch.setenv(ambient_pathspec_mode, "1")

    receipt = preflight_git_push(
        root=root,
        policy=_protected_home(home.as_posix()),
        config_sha256="a" * 64,
        remote="origin",
        destination=home.as_posix(),
        updates=[("refs/heads/main", head, "refs/heads/main", base)],
    )
    historical = [
        row
        for row in receipt["protected_exposures"]
        if row["path"] == "public/renamed.bin"
    ]
    assert len(historical) == 1
    assert historical[0]["content_sha256"] == hashlib.sha256(old_bytes).hexdigest()
    assert historical[0]["rule_path"] == "private/secret.bin"


def test_git_preflight_bounds_aggregate_unfiltered_history_trees(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repo(tmp_path / "project")
    home = _bare_repo(tmp_path / "home.git")
    protected = root / "private" / "secret.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"base protected bytes")
    (root / "public.txt").write_text("public\n", encoding="utf-8")
    base = _commit(root, "two-entry protected base")
    _git(root, "remote", "add", "origin", home.as_posix())
    _git(root, "push", "origin", "HEAD:refs/heads/main")
    protected.write_bytes(b"revised protected bytes")
    head = _commit(root, "two-entry protected successor")
    monkeypatch.setattr(confidentiality, "MAX_GIT_TREE_ENTRIES", 3)

    with pytest.raises(ConfidentialityError, match="aggregate tree inspection"):
        preflight_git_push(
            root=root,
            policy=_protected_home(home.as_posix()),
            config_sha256="a" * 64,
            remote="origin",
            destination=home.as_posix(),
            updates=[("refs/heads/main", head, "refs/heads/main", base)],
        )


def test_git_preflight_loads_one_tree_once_across_history_and_outgoing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repo(tmp_path / "project")
    home = _bare_repo(tmp_path / "home.git")
    protected = root / "private" / "secret.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"one protected entry")
    head = _commit(root, "one-entry protected tree")
    _git(root, "remote", "add", "origin", home.as_posix())
    monkeypatch.setattr(confidentiality, "MAX_GIT_TREE_ENTRIES", 1)
    original = confidentiality._git_tree_entries
    calls: list[str] = []

    def observed_tree_entries(project: Path, commit: str) -> list[dict[str, str]]:
        calls.append(commit)
        return original(project, commit)

    monkeypatch.setattr(confidentiality, "_git_tree_entries", observed_tree_entries)
    receipt = preflight_git_push(
        root=root,
        policy=_protected_home(home.as_posix()),
        config_sha256="a" * 64,
        remote="origin",
        destination=home.as_posix(),
        updates=[("refs/heads/main", head, "refs/heads/main", "0" * len(head))],
    )
    assert receipt["decision"] == "allowed"
    assert calls == [head]


def test_cli_git_preflight_emits_bound_receipt_and_denies_other_repo(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    home = _bare_repo(tmp_path / "home.git")
    config = default_config_text("selective") + f"""
[confidentiality]
mode = "local_files"
protected = [
  {{ path = "private/secret.bin", kind = "file", policy = "home_remote_only", home_remote = "origin", home_destination = "{home.as_posix()}" }},
]
"""
    (root / ".aoi").rmdir()
    candidate = tmp_path / "candidate.toml"
    candidate.write_text(config, encoding="utf-8")
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(HERE.parent / "src")
    initialized = subprocess.run(
        [
            sys.executable,
            "-m",
            "aoi_orgware.cli",
            "init",
            "--config",
            str(candidate),
            "--expected-config-sha256",
            hashlib.sha256(candidate.read_bytes()).hexdigest(),
            "--json",
        ],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert initialized.returncode == 0, initialized.stderr
    checked = subprocess.run(
        [
            sys.executable,
            "-m",
            "aoi_orgware.cli",
            "config-check",
            "--file",
            str(root / "aoi.toml"),
            "--json",
        ],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert checked.returncode == 0, checked.stderr
    checked_payload = json.loads(checked.stdout)
    assert checked_payload["confidentiality"]["protected"][0]["path"] == (
        "private/secret.bin"
    )
    protected = root / "private" / "secret.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"classified")
    head = _commit(root, "protected")
    zeros = "0" * len(head)
    _git(root, "remote", "add", "origin", home.as_posix())
    _git(root, "remote", "add", "mirror", "https://example.invalid/other.git")
    base = [
        sys.executable,
        "-m",
        "aoi_orgware.cli",
        "confidentiality-git-push-preflight",
    ]
    update = [
        "--update",
        "refs/heads/main",
        head,
        "refs/heads/main",
        zeros,
        "--json",
    ]
    allowed = subprocess.run(
        base
        + [
            "--remote",
            "origin",
            "--destination",
            home.as_posix(),
        ]
        + update,
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert allowed.returncode == 0, allowed.stderr
    receipt = json.loads(allowed.stdout)
    assert receipt["decision"] == "allowed"
    assert len(receipt["config_sha256"]) == 64

    denied = subprocess.run(
        base
        + [
            "--remote",
            "mirror",
            "--destination",
            "https://example.invalid/other.git",
        ]
        + update,
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert denied.returncode == 2
    assert "outside its configured policy" in denied.stderr

    public_archive = root / "public.whl"
    with zipfile.ZipFile(public_archive, "w") as archive:
        archive.writestr("pkg/public.bin", b"public")
    publication = subprocess.run(
        [
            sys.executable,
            "-m",
            "aoi_orgware.cli",
            "confidentiality-publication-preflight",
            "--action",
            "package_publish",
            "--destination",
            "https://pypi.org/project/example",
            "--subject",
            str(public_archive),
            "--json",
        ],
        cwd=root,
        env=environment,
        capture_output=True,
        check=False,
    )
    assert publication.returncode == 0, publication.stderr.decode(errors="replace")
    publication_receipt = json.loads(publication.stdout)
    assert publication.stdout == json.dumps(
        publication_receipt,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    assert publication_receipt["decision"] == "allowed"


def test_git_preflight_follows_protected_blob_across_delete_and_copy(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    protected = root / "private" / "secret.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"classified")
    base = _commit(root, "protected base")
    copied = root / "public" / "renamed.bin"
    copied.parent.mkdir()
    copied.write_bytes(protected.read_bytes())
    protected.unlink()
    head = _commit(root, "copy and delete")
    _git(root, "remote", "add", "mirror", "https://example.invalid/other.git")

    with pytest.raises(ConfidentialityError, match="protected path is missing"):
        preflight_git_push(
            root=root,
            policy=_protected_home(),
            config_sha256="a" * 64,
            remote="mirror",
            destination="https://example.invalid/other.git",
            updates=[("refs/heads/main", head, "refs/heads/main", base)],
        )


def test_git_preflight_follows_untracked_protected_bytes_copied_elsewhere(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    protected = root / "private" / "secret.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"never tracked at the protected path")
    copied = root / "public" / "renamed.bin"
    copied.parent.mkdir()
    copied.write_bytes(protected.read_bytes())
    _git(root, "add", "public/renamed.bin")
    _git(root, "commit", "-m", "copy untracked protected bytes")
    head = _git(root, "rev-parse", "HEAD")
    zeros = "0" * len(head)
    _git(root, "remote", "add", "mirror", "https://example.invalid/other.git")

    with pytest.raises(ConfidentialityError, match="outside its configured policy"):
        preflight_git_push(
            root=root,
            policy=_protected_home(),
            config_sha256="a" * 64,
            remote="mirror",
            destination="https://example.invalid/other.git",
            updates=[("refs/heads/main", head, "refs/heads/main", zeros)],
        )


def test_git_preflight_fails_closed_after_untracked_protected_origin_is_deleted(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    protected = root / "private" / "secret.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"never tracked before deletion")
    copied = root / "public" / "renamed.bin"
    copied.parent.mkdir()
    copied.write_bytes(protected.read_bytes())
    protected.unlink()
    _git(root, "add", "public/renamed.bin")
    _git(root, "commit", "-m", "copy after deleting protected origin")
    head = _git(root, "rev-parse", "HEAD")
    zeros = "0" * len(head)
    _git(root, "remote", "add", "mirror", "https://example.invalid/other.git")

    with pytest.raises(ConfidentialityError, match="protected path is missing"):
        preflight_git_push(
            root=root,
            policy=_protected_home(),
            config_sha256="a" * 64,
            remote="mirror",
            destination="https://example.invalid/other.git",
            updates=[("refs/heads/main", head, "refs/heads/main", zeros)],
        )


def test_git_preflight_local_only_allows_local_bare_and_denies_external(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    protected = root / "private" / "secret.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"classified")
    head = _commit(root, "protected")
    zeros = "0" * len(head)
    bare = tmp_path / "local.git"
    bare.mkdir()
    _git(bare, "init", "--bare")
    _git(root, "remote", "add", "local", str(bare))
    _git(root, "remote", "add", "external", "https://example.invalid/other.git")

    receipt = preflight_git_push(
        root=root,
        policy=_protected_local(),
        config_sha256="a" * 64,
        remote="local",
        destination=str(bare),
        updates=[("refs/heads/main", head, "refs/heads/main", zeros)],
    )
    assert receipt["decision"] == "allowed"
    with pytest.raises(ConfidentialityError, match="outside its configured policy"):
        preflight_git_push(
            root=root,
            policy=_protected_local(),
            config_sha256="a" * 64,
            remote="external",
            destination="https://example.invalid/other.git",
            updates=[("refs/heads/main", head, "refs/heads/main", zeros)],
        )


def test_git_preflight_fails_closed_on_rewrite_lfs_and_duplicate_update(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    protected = root / "private" / "secret.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"classified")
    (root / ".gitattributes").write_text(
        "private/secret.bin filter=lfs diff=lfs merge=lfs -text\n",
        encoding="utf-8",
    )
    head = _commit(root, "protected lfs")
    lfs_head = head
    zeros = "0" * len(head)
    _git(root, "remote", "add", "origin", "https://example.invalid/home.git")
    update = ("refs/heads/main", head, "refs/heads/main", zeros)

    with pytest.raises(ConfidentialityError, match="LFS upload route"):
        preflight_git_push(
            root=root,
            policy=_protected_home(),
            config_sha256="a" * 64,
            remote="origin",
            destination="https://example.invalid/home.git",
            updates=[update],
        )
    with pytest.raises(ConfidentialityError, match="duplicate remote ref"):
        preflight_git_push(
            root=root,
            policy=LOCAL_FILES,
            config_sha256="a" * 64,
            remote="origin",
            destination="https://example.invalid/home.git",
            updates=[update, update],
        )

    (root / ".gitattributes").unlink()
    head = _commit(root, "remove lfs")
    _git(
        root,
        "config",
        "url.https://mirror.example.invalid/.pushInsteadOf",
        "https://example.invalid/",
    )
    with pytest.raises(ConfidentialityError, match="rewrites exist"):
        preflight_git_push(
            root=root,
            policy=_protected_home("https://mirror.example.invalid/home.git"),
            config_sha256="a" * 64,
            remote="origin",
            destination="https://mirror.example.invalid/home.git",
            updates=[("refs/heads/main", head, "refs/heads/main", lfs_head)],
        )


def test_publication_gate_is_subject_aware_and_does_not_claim_model_air_gap(
    tmp_path: Path,
) -> None:
    require_publication_action_allowed(LOCAL_FILES, "git_push")
    root = _repo(tmp_path / "project")
    protected = root / "private" / "secret.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"classified")
    digest = hashlib.sha256(protected.read_bytes()).hexdigest()
    policy = _protected_home()
    with pytest.raises(ConfidentialityError, match="requires an exact root"):
        require_publication_action_allowed(policy, "git_push")
    with pytest.raises(ConfidentialityError, match="outside its configured policy"):
        require_publication_action_allowed(
            policy,
            "artifact_upload",
            root=root,
            remote="origin",
            destination="https://example.invalid/home.git",
            subjects=[{"path": "private/secret.bin", "sha256": digest}],
        )
    with pytest.raises(ConfidentialityError, match="outside its configured policy"):
        require_publication_action_allowed(
            policy,
            "artifact_upload",
            root=root,
            remote="mirror",
            destination="https://example.invalid/other.git",
            subjects=[{"path": "renamed.bin", "sha256": digest}],
        )
    assert LOCAL_FILES.model_context == "allowed"


@pytest.mark.parametrize(
    "action",
    (
        "remote_ci",
        "release_publish",
        "package_publish",
        "artifact_upload",
        "attachment_publish",
        "connector_publish",
    ),
)
def test_local_files_empty_rules_allow_normal_non_git_publication(
    action: str,
) -> None:
    require_publication_action_allowed(LOCAL_FILES, action)


def test_protected_tree_rejects_linked_content(tmp_path: Path) -> None:
    root = _repo(tmp_path / "project")
    private = root / "private"
    private.mkdir()
    target = root / "target.bin"
    target.write_bytes(b"classified")
    linked = private / "linked.bin"
    try:
        linked.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    with pytest.raises(ConfidentialityError, match="link/reparse point"):
        require_publication_action_allowed(
            _protected_local(),
            "artifact_upload",
            root=root,
            destination=str(root),
            subjects=[
                {
                    "path": "target.bin",
                    "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                }
            ],
        )


def test_git_preflight_rejects_casefold_collision_inside_protected_tree(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "project")
    private = root / "Private"
    private.mkdir()
    upper = private / "Secret.bin"
    lower = private / "secret.bin"
    upper.write_bytes(b"upper spelling")
    lower.write_bytes(b"lower spelling")
    if upper.samefile(lower):
        pytest.skip("filesystem does not permit case-distinct path identities")
    head = _commit(root, "ambiguous protected tree descendants")
    _git(root, "remote", "add", "external", "https://example.invalid/other.git")

    with pytest.raises(ConfidentialityError, match="ambiguous case-fold identity"):
        preflight_git_push(
            root=root,
            policy=_protected_local(),
            config_sha256="a" * 64,
            remote="external",
            destination="https://example.invalid/other.git",
            updates=[
                ("refs/heads/main", head, "refs/heads/main", "0" * len(head))
            ],
        )


def test_preflight_receipt_loader_rejects_duplicate_keys_and_hardlinks(
    tmp_path: Path,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(
        '{"schema_version":1,"schema_version":1}',
        encoding="utf-8",
    )
    with pytest.raises(ConfidentialityError, match="duplicate key"):
        load_git_push_preflight_receipt(receipt_path)

    receipt_path.write_text('{"schema_version":1}', encoding="utf-8")
    hardlink = tmp_path / "receipt-hardlink.json"
    try:
        os.link(receipt_path, hardlink)
    except OSError as exc:
        pytest.skip(f"hardlink creation unavailable: {exc}")
    with pytest.raises(ConfidentialityError, match="regular non-linked file"):
        load_git_push_preflight_receipt(receipt_path)
