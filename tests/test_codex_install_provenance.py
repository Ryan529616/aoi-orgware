from __future__ import annotations

import base64
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
from typing import Any
import venv
import zipfile

import pytest

from aoi_orgware import cli as cli_impl
from aoi_orgware import codex_install_provenance as provenance
from aoi_orgware import local_install_proof
from aoi_orgware._version import __version__
from aoi_orgware.semantic_events import canonical_json_bytes, canonical_sha256
from tests.provenance_subprocess import create_pth_clean_pip_venv as _create_pth_clean_pip_venv, run_python_checked as _run_python_checked


def _row(path: Path, root: Path) -> list[str]:
    raw = path.read_bytes()
    return [os.path.relpath(path, root).replace("\\", "/"), "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("="), str(len(raw))]


def _fixture_wheel(site: Path, dist: Path, package: Path, wheel: Path) -> None:
    """Build a minimal non-relocating wheel for the hand-built install fixture."""

    members = {
        path.relative_to(site).as_posix(): path.read_bytes()
        for path in [dist / "METADATA", *sorted(package.rglob("*"))]
        if path.is_file()
    }
    record_name = f"{dist.name}/RECORD"
    rows = []
    for name, raw in sorted(members.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        rows.append([name, "sha256=" + digest, str(len(raw))])
    rows.append([record_name, "", ""])
    record = "\n".join(",".join(row) for row in rows).encode("utf-8") + b"\n"
    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, raw in sorted(members.items()):
            archive.writestr(name, raw)
        archive.writestr(record_name, record)


def _site_packages(prefix: Path) -> Path:
    if os.name == "nt":
        return prefix / "Lib" / "site-packages"
    return prefix / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"


def _scripts(prefix: Path) -> Path:
    return prefix / ("Scripts" if os.name == "nt" else "bin")


def _launcher(prefix: Path, name: str) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    return _scripts(prefix) / f"{name}{suffix}"


def _write_launcher(prefix: Path, name: str, target: str, *, with_companion: bool) -> None:
    launcher = _launcher(prefix, name)
    if os.name == "nt":
        launcher.write_bytes(b"recorded-launcher")
        if with_companion:
            module, function = target.split(":", 1)
            (launcher.parent / f"{name}-script.py").write_text(
                f"from {module} import {function}\n", encoding="utf-8"
            )
        return
    module, function = target.split(":", 1)
    launcher.write_text(
        f"#!/usr/bin/env python3\nfrom {module} import {function}\n{function}()\n",
        encoding="utf-8",
    )
    launcher.chmod(0o755)


def _environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, with_companion: bool = True
) -> tuple[Path, Path, dict[str, object]]:
    prefix = tmp_path / "venv"; site = _site_packages(prefix); dist = site / "aoi_orgware-1.2.3.dist-info"; package = site / "aoi_orgware"; scripts = _scripts(prefix)
    for path in (dist, package, scripts): path.mkdir(parents=True, exist_ok=True)
    (prefix / "pyvenv.cfg").write_text(
        "home = /isolated-python\ninclude-system-site-packages = false\n",
        encoding="utf-8",
    )
    python = prefix / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    python.write_bytes(b"fixture-isolated-python")
    if os.name != "nt":
        python.chmod(0o755)
    (dist / "METADATA").write_text("Name: aoi-orgware\nVersion: 1.2.3\n", encoding="utf-8")
    for name in (
        "__init__.py",
        "_version.py",
        "cli.py",
        "codex_hook.py",
        "codex_transport_cli.py",
        "helper.py",
    ):
        (package / name).write_text("# wheel\n", encoding="utf-8")
    skill = package / "resources" / "codex" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# packaged AOI Codex client skill\n", encoding="utf-8")
    for name, target in (
        ("aoi", "aoi_orgware.cli:main"),
        ("aoi-codex-hook", "aoi_orgware.codex_hook:main"),
        ("aoi-codex-bridge", "aoi_orgware.codex_transport_cli:main"),
    ):
        _write_launcher(prefix, name, target, with_companion=with_companion)
    rows = [_row(p, site) for p in [dist / "METADATA", *(package / x for x in ("__init__.py", "_version.py", "cli.py", "codex_hook.py", "codex_transport_cli.py", "helper.py")), skill, *sorted(scripts.glob("aoi*"))]]
    (dist / "RECORD").write_text("\n".join(",".join(row) for row in rows) + "\n" + str((dist / "RECORD").relative_to(site)).replace("\\", "/") + ",,\n", encoding="utf-8")
    entries = [SimpleNamespace(group="console_scripts", name="aoi", value="aoi_orgware.cli:main"), SimpleNamespace(group="console_scripts", name="aoi-codex-hook", value="aoi_orgware.codex_hook:main"), SimpleNamespace(group="console_scripts", name="aoi-codex-bridge", value="aoi_orgware.codex_transport_cli:main")]
    fake_dist = SimpleNamespace(_path=dist, metadata={"Name": "aoi-orgware"}, version="1.2.3", entry_points=entries)
    modules = {"aoi_orgware": SimpleNamespace(__file__=str(package / "__init__.py"), __version__="1.2.3"), "aoi_orgware._version": SimpleNamespace(__file__=str(package / "_version.py"), __version__="1.2.3"), "aoi_orgware.cli": SimpleNamespace(__file__=str(package / "cli.py")), "aoi_orgware.codex_hook": SimpleNamespace(__file__=str(package / "codex_hook.py")), "aoi_orgware.codex_transport_cli": SimpleNamespace(__file__=str(package / "codex_transport_cli.py"))}
    monkeypatch.setattr(provenance.metadata, "distribution", lambda _: fake_dist)
    monkeypatch.setattr(provenance.importlib, "import_module", lambda name: modules[name])
    monkeypatch.setattr(provenance.sys, "prefix", str(prefix))
    monkeypatch.setattr(provenance.sys, "exec_prefix", str(prefix))
    monkeypatch.setattr(provenance.sys, "executable", str(python))
    monkeypatch.setattr(
        provenance.sys,
        "path",
        [
            *(
                entry
                for entry in sys.path
                if Path(entry).name.lower() not in {"site-packages", "dist-packages"}
            ),
            str(site),
        ],
    )
    bundle = {"bundle_sha256": "a" * 64, "manifest": {"distribution_name": "aoi-orgware", "package_version": "1.2.3", "artifacts": [{"name": "aoi-orgware-1.2.3-py3-none-any.whl", "sha256": "b" * 64}], "interfaces": {"installed_metadata_sha256": hashlib.sha256((dist / "METADATA").read_bytes()).hexdigest(), "console_entry_point": {"name": "aoi", "target": "aoi_orgware.cli:main"}, "codex_hook_entry_point": {"name": "aoi-codex-hook", "target": "aoi_orgware.codex_hook:main"}, "hook_protocol_version": 6}}}
    monkeypatch.setattr(provenance.release_runtime, "validate_promotion_bundle", lambda value, expected: bundle)
    bundle_file = tmp_path / "bundle.json"; bundle_file.write_text("{}", encoding="utf-8")
    return prefix, bundle_file, bundle


def _local_v2_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    prefix: Path,
    bundle_file: Path,
    invoked_console: str | os.PathLike[str] | None = None,
) -> dict[str, object]:
    site = _site_packages(prefix)
    dist = next(site.glob("*.dist-info"))
    wheel = tmp_path / "store" / "aoi_orgware-1.2.3-py3-none-any.whl"
    wheel.parent.mkdir(parents=True)
    _fixture_wheel(site, dist, site / "aoi_orgware", wheel)
    wheel_sha = hashlib.sha256(wheel.read_bytes()).hexdigest()
    direct = dist / "direct_url.json"
    direct.write_text(
        json.dumps({"url": wheel.as_uri(), "archive_info": {"hash": "sha256=" + wheel_sha, "hashes": {"sha256": wheel_sha}}}),
        encoding="utf-8",
    )
    record = dist / "RECORD"
    record.write_text(
        record.read_text(encoding="utf-8") + ",".join(_row(direct, site)) + "\n",
        encoding="utf-8",
    )
    metadata_sha = hashlib.sha256((dist / "METADATA").read_bytes()).hexdigest()
    contract: dict[str, object] = {
        "distribution_name": "aoi-orgware", "package_version": "1.2.3",
        "wheel": {"path": str(wheel), "name": wheel.name, "size_bytes": wheel.stat().st_size, "sha256": wheel_sha},
        "interfaces": {
            "installed_metadata_sha256": metadata_sha,
            "console_entry_point": {"name": "aoi", "target": "aoi_orgware.cli:main"},
            "codex_hook_entry_point": {"name": "aoi-codex-hook", "target": "aoi_orgware.codex_hook:main"},
            "codex_bridge_entry_point": {"name": "aoi-codex-bridge", "target": "aoi_orgware.codex_transport_cli:main"},
            "hook_protocol_version": 6,
        },
        "artifact_store_root": str(wheel.parent), "source_commit_oid": "c" * 40,
        "source_tree_oid": "d" * 40, "source_manifest_sha256": "e" * 64,
        "rehearsal_report_sha256": "f" * 64, "inventory_sha256": "0" * 64,
        "bundle_sha256": "a" * 64,
    }

    def local_contract(_path: object, _expected: object) -> tuple[dict[str, object], dict[str, object], Path]:
        if hashlib.sha256(wheel.read_bytes()).hexdigest() != wheel_sha:
            raise provenance.CodexInstallProvenanceError("proof wheel changed")
        return {}, contract, bundle_file

    monkeypatch.setattr(provenance, "_local_install_contract", local_contract)
    return provenance.validate_codex_local_install_provenance(
        bundle_file, "a" * 64, invoked_console or _launcher(prefix, "aoi")
    )


def _runtime_kwargs(prefix: Path) -> dict[str, Any]:
    return {
        "runtime_python": provenance.sys.executable,
        "runtime_module_path": _site_packages(prefix) / "aoi_orgware" / "codex_hook.py",
        "runtime_argv_prefix": list(provenance.CODEX_HOOK_RUNTIME_ARGV_PREFIX),
    }


@pytest.mark.skipif(os.name != "nt", reason="distlib's extensionless argv alias is Windows-only")
def test_windows_distlib_extensionless_console_alias_is_record_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    launcher = _launcher(prefix, "aoi")

    receipt = provenance.validate_codex_install_provenance(
        bundle_file, "a" * 64, launcher.with_suffix("")
    )

    assert receipt["console_entry_point"]["path"] == str(launcher.resolve())


@pytest.mark.skipif(os.name != "nt", reason="distlib's extensionless argv alias is Windows-only")
def test_windows_local_proof_accepts_distlib_extensionless_console_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    launcher = _launcher(prefix, "aoi")

    receipt = _local_v2_receipt(
        tmp_path, monkeypatch, prefix, bundle_file, launcher.with_suffix("")
    )

    assert receipt["console_entry_point"]["path"] == str(launcher.resolve())


@pytest.mark.skipif(os.name != "nt", reason="distlib's extensionless argv alias is Windows-only")
def test_windows_distlib_alias_requires_exact_canonical_components(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, _bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    launcher = _launcher(prefix, "aoi").resolve()
    alternate_spelling = str(launcher.with_suffix("")).upper().replace("\\", "/")
    traversal = str(launcher.parent / "missing") + "\\..\\" + launcher.stem

    assert provenance._invoked_launcher(
        alternate_spelling, launcher, "invoked console launcher"
    ) == launcher
    with pytest.raises(provenance.CodexInstallProvenanceError, match="parent traversal"):
        provenance._invoked_launcher(traversal, launcher, "invoked console launcher")


@pytest.mark.skipif(os.name != "nt", reason="distlib's extensionless argv alias is Windows-only")
def test_windows_public_provenance_rejects_distlib_alias_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    launcher = _launcher(prefix, "aoi")
    traversal = str(launcher.parent / "missing") + "\\..\\" + launcher.stem

    with pytest.raises(provenance.CodexInstallProvenanceError, match="invoked console launcher"):
        provenance.validate_codex_install_provenance(bundle_file, "a" * 64, traversal)


@pytest.mark.skipif(os.name != "nt", reason="distlib's extensionless argv alias is Windows-only")
def test_windows_local_proof_rejects_distlib_alias_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    launcher = _launcher(prefix, "aoi")
    traversal = str(launcher.parent / "missing") + "\\..\\" + launcher.stem

    with pytest.raises(provenance.CodexInstallProvenanceError, match="invoked console launcher"):
        _local_v2_receipt(tmp_path, monkeypatch, prefix, bundle_file, traversal)


@pytest.mark.skipif(os.name != "nt", reason="distlib's extensionless argv alias is Windows-only")
@pytest.mark.parametrize(
    "variant", ["missing", "wrong_launcher", "suffix_drift", "path_shadow"]
)
def test_windows_distlib_alias_rejects_non_expected_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    if variant == "missing":
        invoked = tmp_path / "shadow" / "aoi"
    elif variant == "wrong_launcher":
        invoked = _launcher(prefix, "aoi-codex-hook")
    elif variant == "path_shadow":
        invoked = tmp_path / "shadow" / "aoi.exe"
        invoked.parent.mkdir()
        invoked.write_bytes(_launcher(prefix, "aoi").read_bytes())
    else:
        invoked = _launcher(prefix, "aoi").with_suffix(".cmd")

    with pytest.raises(provenance.CodexInstallProvenanceError, match="invoked console launcher"):
        provenance.validate_codex_install_provenance(bundle_file, "a" * 64, invoked)


@pytest.mark.skipif(os.name == "nt", reason="Windows distlib alias is intentionally admitted")
def test_posix_rejects_missing_extensionless_console_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)

    with pytest.raises(provenance.CodexInstallProvenanceError, match="cannot inspect invoked") as error:
        provenance.validate_codex_install_provenance(bundle_file, "a" * 64, _launcher(prefix, "aoi").with_suffix(".missing"))
    assert isinstance(error.value.__cause__, FileNotFoundError)


def test_validates_real_recorded_native_launchers_and_returns_deterministic_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    receipt = provenance.validate_codex_install_provenance(bundle_file, "a" * 64, _launcher(prefix, "aoi"))
    again = provenance.validate_codex_install_provenance(bundle_file, "a" * 64, _launcher(prefix, "aoi"))
    assert receipt == again
    assert receipt["codex_hook_entry_point"]["path"] == str(_launcher(prefix, "aoi-codex-hook").resolve())
    if os.name == "nt":
        assert receipt["codex_hook_generated_script"]["path"].endswith(
            "aoi-codex-hook-script.py"
        )
    else:
        assert receipt["codex_hook_generated_script"] == {
            "path": None,
            "record_sha256": None,
        }
    assert receipt["promotion_wheel_artifact"]["sha256"] == "b" * 64
    assert receipt["installed_distribution_identity"]["name"] == "aoi-orgware"
    assert receipt["installed_mapping_strength"] == "record_package_only"
    assert receipt["package_runtime_manifest"]["count"] == 7


def _reseal_v3(receipt: dict[str, object]) -> dict[str, object]:
    candidate = json.loads(json.dumps(receipt))
    candidate.pop("provenance_receipt_sha256")
    return {
        **candidate,
        "provenance_receipt_sha256": canonical_sha256(
            candidate, max_bytes=64 * 1024
        ),
    }


def test_v1_remains_valid_but_client_skill_is_legacy_unbound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    receipt = provenance.validate_codex_install_provenance(
        bundle_file, "a" * 64, _launcher(prefix, "aoi")
    )
    assert receipt["schema_version"] == 1
    assert provenance.validate_codex_install_provenance_receipt(receipt) == receipt
    report = provenance.inspect_codex_client_skill(receipt)
    assert report["status"] == "legacy_unbound"
    assert report["expected_sha256"] is None
    with pytest.raises(
        provenance.CodexInstallProvenanceError,
        match="requires local-v2 exact-wheel proof",
    ):
        provenance.bind_codex_client_skill(
            receipt, (tmp_path / "skills" / "aoi" / "SKILL.md").resolve()
        )


def test_v3_wrapped_public_v1_cannot_become_current_hook_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    public = provenance.validate_codex_install_provenance(
        bundle_file, "a" * 64, _launcher(prefix, "aoi")
    )
    local = _local_v2_receipt(tmp_path, monkeypatch, prefix, bundle_file)
    current = provenance.bind_codex_client_skill(
        local, (tmp_path / "user-skills" / "aoi" / "SKILL.md").resolve()
    )
    wrapped = {
        **public,
        "schema_version": provenance.CODEX_INSTALL_PROVENANCE_SCHEMA_VERSION,
        "install_provenance_schema_version": 1,
        "install_provenance_receipt_sha256": public[
            "provenance_receipt_sha256"
        ],
        "codex_client_skill": current["codex_client_skill"],
        "codex_hook_runtime": current["codex_hook_runtime"],
    }
    wrapped = _reseal_v3(wrapped)

    with pytest.raises(
        provenance.CodexInstallProvenanceError,
        match="requires local-v2 exact-wheel proof",
    ):
        provenance.validate_codex_install_provenance_receipt(wrapped)
    with pytest.raises(
        provenance.CodexInstallProvenanceError,
        match="requires local-v2 exact-wheel proof",
    ):
        cli_impl._codex_hook_commands_for_receipt(wrapped, tmp_path)


def test_v3_binds_exact_recorded_package_resource_and_installed_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    legacy = _local_v2_receipt(tmp_path, monkeypatch, prefix, bundle_file)
    installed = (tmp_path / "user-skills" / "aoi" / "SKILL.md").resolve()
    receipt = provenance.bind_codex_client_skill(legacy, installed)
    binding = receipt["codex_client_skill"]
    assert receipt["schema_version"] == 3
    assert receipt["install_provenance_schema_version"] == 2
    assert (
        receipt["install_provenance_receipt_sha256"]
        == legacy["provenance_receipt_sha256"]
    )
    assert binding["provider"] == "codex"
    assert binding["client_contract_version"] == 1
    assert binding["role"] == "client_adapter_only"
    assert binding["package_version"] == legacy["package_version"]
    assert (
        binding["package_resource"]["relative_path"]
        == "resources/codex/SKILL.md"
    )
    package_skill = (
        _site_packages(prefix)
        / "aoi_orgware"
        / "resources"
        / "codex"
        / "SKILL.md"
    )
    expected_sha = hashlib.sha256(package_skill.read_bytes()).hexdigest()
    assert binding["package_resource"] == {
        "relative_path": "resources/codex/SKILL.md",
        "path": str(package_skill.resolve()),
        "record_sha256": expected_sha,
    }
    assert binding["installed_skill"] == {
        "path": str(installed),
        "expected_sha256": expected_sha,
    }
    runtime = receipt["codex_hook_runtime"]
    assert runtime["contract_version"] == 1
    assert runtime["kind"] == "python_isolated_module"
    assert runtime["python_invocation"] == str(
        (prefix / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
    )
    assert runtime["module"] == "aoi_orgware.codex_hook"
    assert runtime["module_path"] == str(
        (_site_packages(prefix) / "aoi_orgware" / "codex_hook.py").resolve()
    )
    assert runtime["argv_prefix"] == ["-I", "-B", "-m", "aoi_orgware.codex_hook"]
    assert provenance.validate_codex_install_provenance_receipt(receipt) == receipt
    assert provenance.read_recorded_codex_client_skill(receipt).encode(
        "utf-8"
    ) == package_skill.read_bytes()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("provider", "binding identity"),
        ("expected_sha", "digest differs"),
        ("package_path", "path differs from package root"),
        ("runtime_kind", "runtime binding identity"),
        ("runtime_module_path", "runtime module path differs"),
        ("runtime_hash", "runtime python_resolved_sha256"),
        ("runtime_cache_tag", "runtime cache tag"),
        ("unexpected_field", "receipt fields"),
        ("install_proof", "distribution identity"),
    ],
)
def test_v3_strict_schema_rejects_resealed_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    message: str,
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    legacy = _local_v2_receipt(tmp_path, monkeypatch, prefix, bundle_file)
    receipt = provenance.bind_codex_client_skill(
        legacy, (tmp_path / "skills" / "aoi" / "SKILL.md").resolve()
    )
    tampered = json.loads(json.dumps(receipt))
    if mutation == "provider":
        tampered["codex_client_skill"]["provider"] = "claude"
    elif mutation == "expected_sha":
        tampered["codex_client_skill"]["installed_skill"]["expected_sha256"] = (
            "f" * 64
        )
    elif mutation == "package_path":
        tampered["codex_client_skill"]["package_resource"]["path"] = str(
            (tmp_path / "other" / "SKILL.md").resolve()
        )
    elif mutation == "runtime_kind":
        tampered["codex_hook_runtime"]["kind"] = "console_script"
    elif mutation == "runtime_module_path":
        tampered["codex_hook_runtime"]["module_path"] = str(
            (tmp_path / "other" / "codex_hook.py").resolve()
        )
    elif mutation == "runtime_hash":
        tampered["codex_hook_runtime"]["python_resolved_sha256"] = "F" * 64
    elif mutation == "runtime_cache_tag":
        tampered["codex_hook_runtime"]["python_cache_tag"] = ""
    elif mutation == "unexpected_field":
        tampered["unexpected"] = True
    else:
        tampered["package_version"] = "9.9.9"
    tampered = _reseal_v3(tampered)
    with pytest.raises(provenance.CodexInstallProvenanceError, match=message):
        provenance.validate_codex_install_provenance_receipt(tampered)


def test_v3_client_skill_classifies_exact_missing_drifted_and_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    legacy = _local_v2_receipt(tmp_path, monkeypatch, prefix, bundle_file)
    installed = (tmp_path / "skills" / "aoi" / "SKILL.md").resolve()
    receipt = provenance.bind_codex_client_skill(legacy, installed)
    installed.parent.mkdir(parents=True)
    installed.write_text(
        provenance.read_recorded_codex_client_skill(receipt),
        encoding="utf-8",
        newline="",
    )
    exact = provenance.inspect_codex_client_skill(receipt)
    assert exact["status"] == "exact"
    assert exact["actual_sha256"] == exact["expected_sha256"]

    installed.write_text("drifted\n", encoding="utf-8", newline="")
    drifted = provenance.inspect_codex_client_skill(receipt)
    assert drifted["status"] == "drifted"
    assert drifted["actual_sha256"] != drifted["expected_sha256"]

    installed.unlink()
    missing = provenance.inspect_codex_client_skill(receipt)
    assert missing["status"] == "missing"
    assert missing["actual_sha256"] is None

    package_skill = (
        _site_packages(prefix)
        / "aoi_orgware"
        / "resources"
        / "codex"
        / "SKILL.md"
    )
    try:
        installed.symlink_to(package_skill)
    except OSError as exc:
        pytest.skip(f"this host cannot create a file symlink: {exc}")
    linked = provenance.inspect_codex_client_skill(receipt)
    assert linked["status"] == "uninspectable"
    assert linked["reason"] == "installed_skill_is_link"


def test_v3_client_skill_never_reports_exact_after_package_record_rewrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    legacy = _local_v2_receipt(tmp_path, monkeypatch, prefix, bundle_file)
    installed = (tmp_path / "skills" / "aoi" / "SKILL.md").resolve()
    receipt = provenance.bind_codex_client_skill(legacy, installed)
    installed.parent.mkdir(parents=True)
    installed.write_text(
        provenance.read_recorded_codex_client_skill(receipt),
        encoding="utf-8",
        newline="",
    )
    site = _site_packages(prefix)
    package_skill = site / "aoi_orgware" / "resources" / "codex" / "SKILL.md"
    package_skill.write_text("# cooperatively rewritten\\n", encoding="utf-8")
    record = next(site.glob("*.dist-info")) / "RECORD"
    relative = package_skill.relative_to(site).as_posix()
    replacement = ",".join(_row(package_skill, site))
    record.write_text(
        "\n".join(
            replacement if line.startswith(relative + ",") else line
            for line in record.read_text(encoding="utf-8").splitlines()
        )
        + "\n",
        encoding="utf-8",
    )
    report = provenance.inspect_codex_client_skill(receipt)
    assert report["status"] == "uninspectable"
    assert report["reason"] == (
        "packaged_skill_provenance_uninspectable:CodexInstallProvenanceError"
    )


def test_v3_client_skill_linked_parent_is_uninspectable_not_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    legacy = _local_v2_receipt(tmp_path, monkeypatch, prefix, bundle_file)
    linked = tmp_path / "linked-skills"
    installed = linked / "aoi" / "SKILL.md"
    receipt = provenance.bind_codex_client_skill(legacy, installed)
    real = tmp_path / "real-skills"
    real.mkdir()
    try:
        linked.symlink_to(real, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"this host cannot create a directory symlink: {exc}")
    report = provenance.inspect_codex_client_skill(receipt)
    assert report["status"] == "uninspectable"
    assert report["reason"].startswith("installed_skill_path_uninspectable:")


def test_v3_client_skill_read_fault_is_uninspectable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    legacy = _local_v2_receipt(tmp_path, monkeypatch, prefix, bundle_file)
    installed = (tmp_path / "skills" / "aoi" / "SKILL.md").resolve()
    receipt = provenance.bind_codex_client_skill(legacy, installed)
    installed.parent.mkdir(parents=True)
    installed.write_text(
        provenance.read_recorded_codex_client_skill(receipt),
        encoding="utf-8",
        newline="",
    )
    original = provenance._stable_read

    def fail_installed(
        path: Path, label: str, *, max_bytes: int = provenance._MAX_FILE_BYTES
    ) -> bytes:
        if path == installed:
            raise provenance.CodexInstallProvenanceError("injected read fault")
        return original(path, label, max_bytes=max_bytes)

    monkeypatch.setattr(provenance, "_stable_read", fail_installed)
    report = provenance.inspect_codex_client_skill(receipt)
    assert report["status"] == "uninspectable"
    assert report["actual_sha256"] is None
    assert report["reason"] == (
        "installed_skill_read_failed:CodexInstallProvenanceError"
    )


@pytest.mark.parametrize("rewrite_record", [False, True])
def test_v3_binding_rejects_package_skill_or_record_cooperating_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rewrite_record: bool,
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    legacy = _local_v2_receipt(tmp_path, monkeypatch, prefix, bundle_file)
    site = _site_packages(prefix)
    package_skill = (
        site / "aoi_orgware" / "resources" / "codex" / "SKILL.md"
    )
    package_skill.write_text("# drifted package skill\n", encoding="utf-8")
    if rewrite_record:
        record = next(site.glob("*.dist-info")) / "RECORD"
        relative = package_skill.relative_to(site).as_posix()
        replacement = ",".join(_row(package_skill, site))
        lines = record.read_text(encoding="utf-8").splitlines()
        record.write_text(
            "\n".join(
                replacement if line.startswith(relative + ",") else line
                for line in lines
            )
            + "\n",
            encoding="utf-8",
        )
    expected = (
        "runtime package manifest differs"
        if rewrite_record
        else "bytes differ from wheel RECORD"
    )
    with pytest.raises(provenance.CodexInstallProvenanceError, match=expected):
        provenance.bind_codex_client_skill(
            legacy, (tmp_path / "skills" / "aoi" / "SKILL.md").resolve()
        )


def test_runtime_v3_rechecks_package_but_not_user_scope_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    legacy = _local_v2_receipt(tmp_path, monkeypatch, prefix, bundle_file)
    installed = (tmp_path / "skills" / "aoi" / "SKILL.md").resolve()
    receipt = provenance.bind_codex_client_skill(legacy, installed)
    project = tmp_path / "project"
    target = project / provenance.CODEX_INSTALL_PROVENANCE_RECEIPT
    target.parent.mkdir(parents=True)
    target.write_bytes(canonical_json_bytes(receipt))
    # The client adapter may be absent without granting or revoking hook
    # authority. Doctor reports that absence; runtime authorization remains
    # bound to the package/launcher/provenance receipt.
    assert not installed.exists()
    assert provenance.verify_runtime_hook_provenance(
        project,
        receipt["provenance_receipt_sha256"],
        _launcher(prefix, "aoi-codex-hook"),
        **_runtime_kwargs(prefix),
    ) == receipt


def test_v3_runtime_requires_explicit_current_python_module_and_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    receipt = provenance.bind_codex_client_skill(
        _local_v2_receipt(tmp_path, monkeypatch, prefix, bundle_file),
        (tmp_path / "skills" / "aoi" / "SKILL.md").resolve(),
    )
    project = tmp_path / "project"
    target = project / provenance.CODEX_INSTALL_PROVENANCE_RECEIPT
    target.parent.mkdir(parents=True)
    target.write_bytes(canonical_json_bytes(receipt))
    hook = _launcher(prefix, "aoi-codex-hook")
    with pytest.raises(
        provenance.CodexInstallProvenanceError,
        match="requires explicit Python and module identity",
    ):
        provenance.verify_runtime_hook_provenance(
            project, receipt["provenance_receipt_sha256"], hook
        )
    for key, value, message in (
        ("runtime_python", str(prefix / "bin" / "other-python"), "runtime Python invocation differs"),
        ("runtime_module_path", tmp_path / "other.py", "explicit runtime Codex hook module"),
        ("runtime_argv_prefix", ["-m", "aoi_orgware.codex_hook"], "argv prefix"),
    ):
        kwargs = _runtime_kwargs(prefix)
        kwargs[key] = value
        with pytest.raises(provenance.CodexInstallProvenanceError, match=message):
            provenance.verify_runtime_hook_provenance(
                project, receipt["provenance_receipt_sha256"], hook, **kwargs
            )
    monkeypatch.setattr(provenance.sys, "implementation", SimpleNamespace(cache_tag="wrong-tag"))
    with pytest.raises(provenance.CodexInstallProvenanceError, match="Python/module runtime differs"):
        provenance.verify_runtime_hook_provenance(
            project, receipt["provenance_receipt_sha256"], hook,
            **_runtime_kwargs(prefix),
        )


def test_v3_runtime_rechecks_recorded_python_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    receipt = provenance.bind_codex_client_skill(
        _local_v2_receipt(tmp_path, monkeypatch, prefix, bundle_file),
        (tmp_path / "skills" / "aoi" / "SKILL.md").resolve(),
    )
    wrong = json.loads(json.dumps(receipt))
    wrong["codex_hook_runtime"]["python_resolved_sha256"] = "f" * 64
    wrong = _reseal_v3(wrong)
    project = tmp_path / "project"
    target = project / provenance.CODEX_INSTALL_PROVENANCE_RECEIPT
    target.parent.mkdir(parents=True)
    target.write_bytes(canonical_json_bytes(wrong))
    with pytest.raises(provenance.CodexInstallProvenanceError, match="Python/module runtime differs"):
        provenance.verify_runtime_hook_provenance(
            project, wrong["provenance_receipt_sha256"],
            _launcher(prefix, "aoi-codex-hook"), **_runtime_kwargs(prefix),
        )


def test_v3_runtime_does_not_make_pip_launcher_hook_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    receipt = provenance.bind_codex_client_skill(
        _local_v2_receipt(tmp_path, monkeypatch, prefix, bundle_file),
        (tmp_path / "skills" / "aoi" / "SKILL.md").resolve(),
    )
    project = tmp_path / "project"
    receipt_path = project / provenance.CODEX_INSTALL_PROVENANCE_RECEIPT
    receipt_path.parent.mkdir(parents=True)
    receipt_path.write_bytes(canonical_json_bytes(receipt))
    site = _site_packages(prefix)
    launcher = _launcher(prefix, "aoi-codex-hook")
    launcher.write_bytes(b"rewritten-pip-launcher")
    record = next(site.glob("*.dist-info")) / "RECORD"
    relative = os.path.relpath(launcher, site).replace("\\", "/")
    replacement = ",".join(_row(launcher, site))
    record.write_text(
        "\n".join(
            replacement if line.startswith(relative + ",") else line
            for line in record.read_text(encoding="utf-8").splitlines()
        ) + "\n",
        encoding="utf-8",
    )
    # Current v3 hook authority is ``python -I -B -m aoi_orgware.codex_hook``;
    # it neither accepts nor dereferences this mutable pip console launcher.
    assert provenance.verify_runtime_hook_provenance(
        project, receipt["provenance_receipt_sha256"], **_runtime_kwargs(prefix)
    ) == receipt


@pytest.mark.skipif(os.name == "nt", reason="POSIX venv leaf symlink contract")
def test_v3_records_posix_venv_python_leaf_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    python = Path(provenance.sys.executable)
    target = python.with_name("python-base")
    target.write_bytes(python.read_bytes())
    target.chmod(0o755)
    python.unlink()
    python.symlink_to(target.name)
    receipt = provenance.bind_codex_client_skill(
        _local_v2_receipt(tmp_path, monkeypatch, prefix, bundle_file),
        (tmp_path / "skills" / "aoi" / "SKILL.md").resolve(),
    )
    runtime = receipt["codex_hook_runtime"]
    assert runtime["python_invocation"] == str(python)
    assert runtime["python_resolved_path"] == str(target)


def test_v3_runtime_allows_bounded_python_executable_larger_than_general_file_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    python = Path(provenance.sys.executable)
    python.write_bytes(b"p" * (provenance._MAX_FILE_BYTES + 1))
    if os.name != "nt":
        python.chmod(0o755)

    receipt = provenance.bind_codex_client_skill(
        _local_v2_receipt(tmp_path, monkeypatch, prefix, bundle_file),
        (tmp_path / "skills" / "aoi" / "SKILL.md").resolve(),
    )

    assert receipt["codex_hook_runtime"]["python_resolved_sha256"] == hashlib.sha256(
        python.read_bytes()
    ).hexdigest()


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable permissions only")
@pytest.mark.parametrize("mode", [0o644, 0o001, 0o010])
def test_rejects_non_executable_native_console_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    console = _launcher(prefix, "aoi")
    console.chmod(mode)
    with pytest.raises(
        provenance.CodexInstallProvenanceError,
        match="console launcher is not executable",
    ):
        provenance.validate_codex_install_provenance(
            bundle_file, "a" * 64, console
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable permissions only")
@pytest.mark.parametrize("mode", [0o644, 0o001, 0o010])
def test_runtime_hook_rejects_executable_permission_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    receipt = provenance.validate_codex_install_provenance(
        bundle_file, "a" * 64, _launcher(prefix, "aoi")
    )
    project = tmp_path / "project"
    target = project / provenance.CODEX_INSTALL_PROVENANCE_RECEIPT
    target.parent.mkdir(parents=True)
    target.write_bytes(canonical_json_bytes(receipt))
    hook = _launcher(prefix, "aoi-codex-hook")
    hook.chmod(mode)
    with pytest.raises(
        provenance.CodexInstallProvenanceError,
        match="recorded Codex hook launcher is not executable",
    ):
        provenance.verify_runtime_hook_provenance(
            project, receipt["provenance_receipt_sha256"], hook
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows launcher companions do not exist on POSIX")
def test_windows_launcher_without_recorded_script_companion_is_admissible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch, with_companion=False)
    receipt = provenance.validate_codex_install_provenance(
        bundle_file, "a" * 64, _launcher(prefix, "aoi")
    )
    assert receipt["codex_hook_generated_script"] == {
        "path": None,
        "record_sha256": None,
    }
    receipt_path = tmp_path / "project" / provenance.CODEX_INSTALL_PROVENANCE_RECEIPT
    receipt_path.parent.mkdir(parents=True)
    receipt_path.write_bytes(canonical_json_bytes(receipt))
    assert provenance.verify_runtime_hook_provenance(
        receipt_path.parents[1],
        receipt["provenance_receipt_sha256"],
        receipt["codex_hook_entry_point"]["path"],
    ) == receipt


@pytest.mark.parametrize(
    "relative",
    [
        "aoi_orgware/__pycache__/evil.py",
        "aoi_orgware/__pycache__/nested/payload.bin",
    ],
)
def test_hashless_non_bytecode_cache_record_rows_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    site = _site_packages(prefix)
    candidate = site.joinpath(*relative.split("/"))
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_bytes(b"untrusted")
    record = next(site.glob("*.dist-info")) / "RECORD"
    record.write_text(
        record.read_text(encoding="utf-8") + f"{relative},,\n",
        encoding="utf-8",
    )

    with pytest.raises(
        provenance.CodexInstallProvenanceError,
        match="lacks a verifiable SHA-256 and size",
    ):
        provenance.validate_codex_install_provenance(
            bundle_file, "a" * 64, _launcher(prefix, "aoi")
        )


@pytest.mark.parametrize("fault", ["metadata", "launcher", "editable", "pth", "wrong_console"])
def test_failures_do_not_mutate_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    project = tmp_path / "project"; state = project / ".aoi"; state.mkdir(parents=True); sentinel = state / "sentinel.json"; sentinel.write_text('{"unchanged":true}', encoding="utf-8")
    site = _site_packages(prefix); dist = next(site.glob("*.dist-info"))
    invoked = _launcher(prefix, "aoi")
    if fault == "metadata": (dist / "METADATA").write_text("tampered", encoding="utf-8")
    elif fault == "launcher": invoked.write_bytes(b"tampered")
    elif fault == "editable": (dist / "direct_url.json").write_text('{"dir_info":{"editable":true}}', encoding="utf-8")
    elif fault == "pth": (site / "shadow.pth").write_text("import os\n", encoding="utf-8")
    elif fault == "wrong_console": invoked = _launcher(prefix, "aoi-codex-hook")
    before = {p.relative_to(project): p.read_bytes() for p in project.rglob("*") if p.is_file()}
    expected = {
        "launcher": "console launcher bytes differ",
        "wrong_console": "invoked console launcher is not the promoted launcher",
    }.get(fault)
    with pytest.raises(provenance.CodexInstallProvenanceError, match=expected): provenance.validate_codex_install_provenance(bundle_file, "a" * 64, invoked)
    after = {p.relative_to(project): p.read_bytes() for p in project.rglob("*") if p.is_file()}
    assert after == before


def test_real_setuptools_distutils_precedence_pth_is_not_allowlisted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    (_site_packages(prefix) / "distutils-precedence.pth").write_text(
        (
            "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; "
            "enabled = os.environ.get(var, 'local') == 'local'; "
            "enabled and __import__('_distutils_hack').add_shim();\n"
        ),
        encoding="utf-8",
    )
    with pytest.raises(
        provenance.CodexInstallProvenanceError,
        match="executable .pth shadow is not admissible",
    ):
        provenance.validate_codex_install_provenance(
            bundle_file, "a" * 64, _launcher(prefix, "aoi")
        )


def test_runtime_hook_rejects_executable_pth_added_after_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    receipt = provenance.validate_codex_install_provenance(
        bundle_file, "a" * 64, _launcher(prefix, "aoi")
    )
    project = tmp_path / "project"
    target = project / provenance.CODEX_INSTALL_PROVENANCE_RECEIPT
    target.parent.mkdir(parents=True)
    target.write_bytes(canonical_json_bytes(receipt))
    (_site_packages(prefix) / "late-shadow.pth").write_text(
        "import os\n", encoding="utf-8"
    )
    with pytest.raises(
        provenance.CodexInstallProvenanceError,
        match="executable .pth shadow is not admissible",
    ):
        provenance.verify_runtime_hook_provenance(
            project,
            receipt["provenance_receipt_sha256"],
            _launcher(prefix, "aoi-codex-hook"),
        )


def test_runtime_hook_rejects_executable_pth_for_mappingless_v1_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    receipt = provenance.validate_codex_install_provenance(
        bundle_file, "a" * 64, _launcher(prefix, "aoi")
    )
    legacy = {
        key: value
        for key, value in receipt.items()
        if key not in {
            "promotion_wheel_artifact",
            "installed_distribution_identity",
            "installed_mapping_strength",
            "installed_mapping_evidence",
            "provenance_receipt_sha256",
        }
    }
    legacy["provenance_receipt_sha256"] = canonical_sha256(legacy)
    assert provenance.validate_codex_install_provenance_receipt(legacy) == legacy
    project = tmp_path / "project"
    target = project / provenance.CODEX_INSTALL_PROVENANCE_RECEIPT
    target.parent.mkdir(parents=True)
    target.write_bytes(canonical_json_bytes(legacy))
    (_site_packages(prefix) / "legacy-shadow.pth").write_text(
        "import os\n", encoding="utf-8"
    )
    with pytest.raises(
        provenance.CodexInstallProvenanceError,
        match="executable .pth shadow is not admissible",
    ):
        provenance.verify_runtime_hook_provenance(
            project,
            legacy["provenance_receipt_sha256"],
            _launcher(prefix, "aoi-codex-hook"),
        )


def test_rejects_active_external_site_package_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    external = tmp_path / "external" / "site-packages"
    external.mkdir(parents=True)
    monkeypatch.setattr(
        provenance.sys, "path", [_site_packages(prefix).as_posix(), external.as_posix()]
    )
    with pytest.raises(
        provenance.CodexInstallProvenanceError,
        match="active external site-package root is not admissible",
    ):
        provenance.validate_codex_install_provenance(
            bundle_file, "a" * 64, _launcher(prefix, "aoi")
        )


def test_runtime_hook_receipt_is_exact_canonical_and_rechecks_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    receipt = provenance.validate_codex_install_provenance(bundle_file, "a" * 64, _launcher(prefix, "aoi"))
    project = tmp_path / "project"; target = project / provenance.CODEX_INSTALL_PROVENANCE_RECEIPT; target.parent.mkdir(parents=True); target.write_bytes(canonical_json_bytes(receipt))
    assert provenance.verify_runtime_hook_provenance(project, receipt["provenance_receipt_sha256"], _launcher(prefix, "aoi-codex-hook")) == receipt
    _launcher(prefix, "aoi-codex-hook").write_bytes(b"changed")
    with pytest.raises(provenance.CodexInstallProvenanceError, match="bytes"):
        provenance.verify_runtime_hook_provenance(project, receipt["provenance_receipt_sha256"], _launcher(prefix, "aoi-codex-hook"))


def test_local_v2_receipt_binds_exact_wheel_direct_url_and_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The local route cannot silently degrade to v1's weaker mapping proof."""
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    site = _site_packages(prefix)
    dist = next(site.glob("*.dist-info"))
    store = tmp_path / "store"; wheel = store / "dist" / "aoi_orgware-1.2.3-py3-none-any.whl"
    wheel.parent.mkdir(parents=True)
    _fixture_wheel(site, dist, site / "aoi_orgware", wheel)
    wheel_raw = wheel.read_bytes()
    direct = dist / "direct_url.json"
    wheel_sha = hashlib.sha256(wheel.read_bytes()).hexdigest()
    direct.write_text(json.dumps({"url": wheel.as_uri(), "archive_info": {"hash": "sha256=" + wheel_sha, "hashes": {"sha256": wheel_sha}}}), encoding="utf-8")
    record = dist / "RECORD"
    record.write_text(record.read_text(encoding="utf-8") + ",".join(_row(direct, site)) + "\n", encoding="utf-8")
    metadata_sha = hashlib.sha256((dist / "METADATA").read_bytes()).hexdigest()
    contract = {
        "distribution_name": "aoi-orgware", "package_version": "1.2.3",
        "wheel": {"path": str(wheel), "name": wheel.name, "size_bytes": wheel.stat().st_size, "sha256": wheel_sha},
        "interfaces": {
            "installed_metadata_sha256": metadata_sha,
            "console_entry_point": {"name": "aoi", "target": "aoi_orgware.cli:main"},
            "codex_hook_entry_point": {"name": "aoi-codex-hook", "target": "aoi_orgware.codex_hook:main"},
            "codex_bridge_entry_point": {"name": "aoi-codex-bridge", "target": "aoi_orgware.codex_transport_cli:main"},
            "hook_protocol_version": 6,
        },
        "artifact_store_root": str(store), "source_commit_oid": "c" * 40,
        "source_tree_oid": "d" * 40, "source_manifest_sha256": "e" * 64,
        "rehearsal_report_sha256": "f" * 64, "inventory_sha256": "0" * 64,
        "bundle_sha256": "a" * 64,
    }
    def local_contract(_path: object, _expected: object) -> tuple[dict[str, object], dict[str, object], Path]:
        if hashlib.sha256(wheel.read_bytes()).hexdigest() != contract["wheel"]["sha256"]:
            raise provenance.CodexInstallProvenanceError("proof wheel changed")
        return {}, contract, bundle_file

    monkeypatch.setattr(provenance, "_local_install_contract", local_contract)
    receipt = provenance.validate_codex_local_install_provenance(
        bundle_file, "a" * 64, _launcher(prefix, "aoi")
    )
    assert set(receipt) == provenance._LOCAL_RECEIPT_FIELDS
    assert receipt["schema_version"] == 2
    assert receipt["installed_mapping_strength"] == "direct_url_archive_sha256"
    assert receipt["installed_mapping_evidence"]["direct_url"]["archive_path"] == str(wheel)
    assert receipt["installed_record"]["path"] == str(record)
    assert receipt["codex_bridge_entry_point"]["path"] == str(
        _launcher(prefix, "aoi-codex-bridge").resolve()
    )
    assert provenance.validate_codex_install_provenance_receipt(receipt) == receipt
    wrong_bridge = json.loads(json.dumps(receipt))
    wrong_bridge["codex_bridge_entry_point"]["target"] = "aoi_orgware.cli:main"
    wrong_bridge["provenance_receipt_sha256"] = canonical_sha256(
        {
            key: value
            for key, value in wrong_bridge.items()
            if key != "provenance_receipt_sha256"
        }
    )
    with pytest.raises(
        provenance.CodexInstallProvenanceError,
        match="entry point is invalid",
    ):
        provenance.validate_codex_install_provenance_receipt(wrong_bridge)
    project = tmp_path / "project"; target = project / provenance.CODEX_INSTALL_PROVENANCE_RECEIPT
    target.parent.mkdir(parents=True); target.write_bytes(canonical_json_bytes(receipt))
    assert provenance.verify_runtime_hook_provenance(
        project, receipt["provenance_receipt_sha256"], _launcher(prefix, "aoi-codex-hook")
    ) == receipt
    bridge_script = receipt["codex_bridge_generated_script"]
    if bridge_script["path"] is not None:
        bridge_script_path = Path(bridge_script["path"])
        original_bridge_script = bridge_script_path.read_bytes()
        bridge_script_path.write_text("changed\n", encoding="utf-8")
        with pytest.raises(
            provenance.CodexInstallProvenanceError,
            match="bytes differ",
        ):
            provenance.verify_runtime_hook_provenance(
                project,
                receipt["provenance_receipt_sha256"],
                _launcher(prefix, "aoi-codex-hook"),
            )
        bridge_script_path.write_bytes(original_bridge_script)

    # A cooperating attacker can update RECORD after changing direct_url.json;
    # the v2 receipt must still bind the direct_url bytes, not merely RECORD.
    direct.write_text(
        json.dumps(json.loads(direct.read_text(encoding="utf-8")), indent=2),
        encoding="utf-8",
    )
    record_lines = record.read_text(encoding="utf-8").splitlines()
    record_lines[-1] = ",".join(_row(direct, site))
    record.write_text("\n".join(record_lines) + "\n", encoding="utf-8")
    mapping_drift = json.loads(json.dumps(receipt))
    mapping_drift["installed_record"]["sha256"] = hashlib.sha256(record.read_bytes()).hexdigest()
    mapping_drift["provenance_receipt_sha256"] = canonical_sha256(
        {key: value for key, value in mapping_drift.items() if key != "provenance_receipt_sha256"}
    )
    target.write_bytes(canonical_json_bytes(mapping_drift))
    with pytest.raises(provenance.CodexInstallProvenanceError, match="mapping differs"):
        provenance.verify_runtime_hook_provenance(
            project, mapping_drift["provenance_receipt_sha256"], _launcher(prefix, "aoi-codex-hook")
        )
    wrong_record = json.loads(json.dumps(receipt))
    wrong_record["installed_record"]["path"] = str(record) + ".wrong"
    wrong_record["provenance_receipt_sha256"] = canonical_sha256(
        {key: value for key, value in wrong_record.items() if key != "provenance_receipt_sha256"}
    )
    target.write_bytes(canonical_json_bytes(wrong_record))
    with pytest.raises(provenance.CodexInstallProvenanceError, match="RECORD path"):
        provenance.verify_runtime_hook_provenance(
            project, wrong_record["provenance_receipt_sha256"], _launcher(prefix, "aoi-codex-hook")
        )
    # Restore the original receipt and direct-url/RECORD pair before testing
    # proof-wheel replacement separately.
    direct.write_text(json.dumps({"url": wheel.as_uri(), "archive_info": {"hash": "sha256=" + wheel_sha, "hashes": {"sha256": wheel_sha}}}), encoding="utf-8")
    record_lines[-1] = ",".join(_row(direct, site))
    record.write_text("\n".join(record_lines) + "\n", encoding="utf-8")
    target.write_bytes(canonical_json_bytes(receipt))
    wheel.write_bytes(b"substituted-wheel")
    with pytest.raises(provenance.CodexInstallProvenanceError, match="proof"):
        provenance.verify_runtime_hook_provenance(
            project, receipt["provenance_receipt_sha256"], _launcher(prefix, "aoi-codex-hook")
        )
    wheel.write_bytes(wheel_raw)
    _launcher(prefix, "aoi-codex-bridge").unlink()
    with pytest.raises(
        provenance.CodexInstallProvenanceError,
        match="Codex bridge launcher",
    ):
        provenance.validate_codex_local_install_provenance(
            bundle_file, "a" * 64, _launcher(prefix, "aoi")
        )


@pytest.mark.parametrize(
    ("mutated", "expected"),
    [
        ("codex_hook.py", "bytes differ"),
        ("codex_transport_cli.py", "bytes differ"),
        ("helper.py", "bytes differ"),
        pytest.param(
            "aoi-codex-hook-script.py",
            "bytes differ",
            marks=pytest.mark.skipif(
                os.name != "nt", reason="Windows launcher companion only"
            ),
        ),
        ("RECORD", "wheel RECORD"),
        ("extra_module.py", "absent from wheel RECORD"),
    ],
)
def test_runtime_hook_rejects_package_and_generated_script_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutated: str,
    expected: str,
) -> None:
    prefix, bundle_file, _bundle = _environment(tmp_path, monkeypatch)
    receipt = provenance.validate_codex_install_provenance(
        bundle_file, "a" * 64, _launcher(prefix, "aoi")
    )
    project = tmp_path / "project"
    target = project / provenance.CODEX_INSTALL_PROVENANCE_RECEIPT
    target.parent.mkdir(parents=True)
    target.write_bytes(canonical_json_bytes(receipt))
    site = _site_packages(prefix)
    if mutated == "RECORD":
        record = next(site.glob("*.dist-info")) / "RECORD"
        record.write_text("tampered\n", encoding="utf-8")
    elif mutated == "aoi-codex-hook-script.py":
        (_scripts(prefix) / mutated).write_text("changed\n", encoding="utf-8")
    elif mutated == "extra_module.py":
        (site / "aoi_orgware" / mutated).write_text("# unrecorded\n", encoding="utf-8")
    else:
        (site / "aoi_orgware" / mutated).write_text("# changed\n", encoding="utf-8")
    with pytest.raises(provenance.CodexInstallProvenanceError, match=expected):
        provenance.verify_runtime_hook_provenance(
            project,
            receipt["provenance_receipt_sha256"],
            _launcher(prefix, "aoi-codex-hook"),
        )


def test_real_built_wheel_isolated_pip_install_emits_runtime_receipt(tmp_path: Path) -> None:
    """Exercise pip's actual launcher/RECORD output, not a hand-made script."""

    repository = Path(__file__).resolve().parents[1]
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    evidence_root = tmp_path / "child-evidence"
    _run_python_checked(
        sys.executable, "-m", "pip", "wheel", "--isolated", "--no-deps",
        "--wheel-dir", str(wheelhouse), str(repository), cache_root=tmp_path / "python-cache" / "wheel-build",
        evidence_root=evidence_root, label="wheel-build",
    )
    wheels = list(wheelhouse.glob("aoi_orgware-*.whl"))
    assert len(wheels) == 1
    wheel = wheels[0]
    prefix = tmp_path / "isolated"
    python = _create_pth_clean_pip_venv(prefix)
    _run_python_checked(
        python,
        "-m",
        "pip",
        "install",
        "--isolated",
        "--no-index",
        "--no-deps", "--no-compile",
        str(wheel),
        cache_root=tmp_path / "python-cache" / "wheel-install",
        evidence_root=evidence_root,
        label="wheel-install",
    )
    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text("{}", encoding="utf-8")
    expected = "a" * 64
    script = """
import hashlib
from importlib import metadata
import json
from pathlib import Path
import sys
from aoi_orgware import codex_install_provenance as provenance

wheel = Path(sys.argv[1])
bundle_file = Path(sys.argv[2])
expected = sys.argv[3]
dist = metadata.distribution('aoi-orgware')
metadata_path = Path(dist._path) / 'METADATA'
bundle = {
    'bundle_sha256': expected,
    'manifest': {
        'distribution_name': 'aoi-orgware',
        'package_version': dist.version,
        'artifacts': [{'name': wheel.name, 'sha256': hashlib.sha256(wheel.read_bytes()).hexdigest()}],
        'interfaces': {
            'installed_metadata_sha256': hashlib.sha256(metadata_path.read_bytes()).hexdigest(),
            'console_entry_point': {'name': 'aoi', 'target': 'aoi_orgware.cli:main'},
            'codex_hook_entry_point': {'name': 'aoi-codex-hook', 'target': 'aoi_orgware.codex_hook:main'},
            'hook_protocol_version': 6,
        },
    },
}
# Release-bundle sealing is covered separately; this isolates the installed
# wheel provenance path while retaining pip's real RECORD and launchers.
provenance.release_runtime.validate_promotion_bundle = lambda value, digest: bundle
scripts = Path(sys.prefix) / ('Scripts' if __import__('os').name == 'nt' else 'bin')
receipt = provenance.validate_codex_install_provenance(bundle_file, expected, scripts / ('aoi.exe' if __import__('os').name == 'nt' else 'aoi'))
print(json.dumps(receipt, sort_keys=True))
"""
    completed = _run_python_checked(
        python,
        "-I",
        "-c",
        script,
        str(wheel),
        str(bundle_file),
        expected,
        cache_root=tmp_path / "python-cache" / "runtime-receipt",
        evidence_root=evidence_root,
        label="runtime-receipt",
        cwd=tmp_path,
    )
    receipt = json.loads(completed.stdout)
    wheel_sha256 = hashlib.sha256(wheel.read_bytes()).hexdigest()
    assert receipt["promotion_wheel_artifact"] == {
        "name": wheel.name,
        "sha256": wheel_sha256,
    }
    assert receipt["installed_distribution_identity"]["version"] == __version__
    assert receipt["installed_mapping_strength"] == "direct_url_archive_sha256"
    assert (
        receipt["installed_mapping_evidence"]["direct_url"]["archive_sha256"]
        == wheel_sha256
    )
    hook_script = receipt["codex_hook_generated_script"]
    if hook_script["path"] is not None:
        assert hook_script["record_sha256"]


def test_real_isolated_wheel_install_emits_local_v2_receipt(tmp_path: Path) -> None:
    """Exercise the local proof loader against pip's real direct_url/RECORD."""
    repository = Path(__file__).resolve().parents[1]
    wheelhouse = tmp_path / "wheelhouse"; wheelhouse.mkdir()
    evidence_root = tmp_path / "child-evidence"
    _run_python_checked(
        sys.executable,
        "-m",
        "pip",
        "wheel",
        "--isolated",
        "--no-deps",
        "--wheel-dir",
        str(wheelhouse),
        str(repository),
        cache_root=tmp_path / "python-cache" / "wheel-build",
        evidence_root=evidence_root,
        label="wheel-build",
    )
    built = next(wheelhouse.glob("aoi_orgware-*.whl"))
    version = built.name.removeprefix("aoi_orgware-").split("-", 1)[0]
    source = tmp_path / "source"; store = tmp_path / "store"; (source / "src/aoi_orgware").mkdir(parents=True); (source / "requirements").mkdir(); (store / "dist").mkdir(parents=True); (store / "evidence").mkdir()
    (source / "src/aoi_orgware/_version.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    (source / "requirements/release-tools.lock").write_text("tool==1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(source), "init"], check=True, capture_output=True, text=True)
    subprocess.run(["git", "-C", str(source), "config", "core.autocrlf", "false"], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.email", "fixture@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "Fixture"], check=True)
    origin = tmp_path / "origin.git"; subprocess.run(["git", "init", "--bare", str(origin)], check=True, capture_output=True, text=True)
    subprocess.run(["git", "-C", str(source), "remote", "add", "origin", str(origin)], check=True)
    subprocess.run(["git", "-C", str(source), "add", "."], check=True); subprocess.run(["git", "-C", str(source), "commit", "-m", "fixture"], check=True, capture_output=True, text=True)
    wheel = store / "dist" / built.name; shutil.copy2(built, wheel)
    sdist = store / "dist" / f"aoi_orgware-{version}.tar.gz"; sdist.write_bytes(b"fixture-sdist")
    artifacts = []
    for artifact in sorted((wheel, sdist), key=lambda path: path.name):
        raw = artifact.read_bytes(); artifacts.append({"name": artifact.name, "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    inventory_base = {"schema_version": 1, "distribution_name": "aoi-orgware", "package_version": version, "artifacts": artifacts}
    inventory = {**inventory_base, "inventory_sha256": local_install_proof._digest(inventory_base)}
    (store / "evidence/inventory.json").write_bytes(local_install_proof._canonical(inventory))
    manifest = local_install_proof.create_source_manifest(source)
    (store / "evidence/source-file-manifest.json").write_bytes(local_install_proof._canonical(manifest))
    rehearsal = local_install_proof.create_rehearsal_report(source_root=source, store_root=store, inventory_path="evidence/inventory.json", producer_test_summary="1 passed, 0 skipped")
    (store / "evidence/rehearsal.json").write_bytes(local_install_proof._canonical(rehearsal))
    subject = local_install_proof.create_subject(source_root=source, store_root=store, inventory_path="evidence/inventory.json", rehearsal_path="evidence/rehearsal.json")
    review = local_install_proof.create_review_assertion(subject=subject, reviewer="independent-reviewer", reviewed_at="2026-07-19T12:34:56.000000Z", outcome="PASS", clean=True, limitations=["cooperative assertion"])
    bundle = local_install_proof.seal_bundle(source_root=source, store_root=store, subject=subject, review_assertion=review, sealed_at="2026-07-19T12:35:56.000000Z")
    bundle_file = store / "evidence/local-install-bundle.json"; bundle_file.write_bytes(local_install_proof._canonical(bundle))
    prefix = tmp_path / "isolated"
    python = _create_pth_clean_pip_venv(prefix)
    _run_python_checked(
        python,
        "-m",
        "pip",
        "install",
        "--isolated",
        "--no-index",
        "--no-deps", "--no-compile",
        str(wheel),
        cache_root=tmp_path / "python-cache" / "wheel-install",
        evidence_root=evidence_root,
        label="wheel-install",
    )
    script = """
import base64
import hashlib
import json
from pathlib import Path
import sys
import sysconfig
from aoi_orgware import codex_install_provenance as provenance
from aoi_orgware.semantic_events import canonical_json_bytes
bundle, expected, project = map(Path, sys.argv[1:4])
scripts = Path(sys.prefix) / ('Scripts' if __import__('os').name == 'nt' else 'bin')
receipt = provenance.validate_codex_local_install_provenance(bundle, expected.read_text().strip(), scripts / ('aoi.exe' if __import__('os').name == 'nt' else 'aoi'))
target = project / provenance.CODEX_INSTALL_PROVENANCE_RECEIPT; target.parent.mkdir(parents=True); target.write_bytes(canonical_json_bytes(receipt))
provenance.verify_runtime_hook_provenance(project, receipt['provenance_receipt_sha256'], scripts / ('aoi-codex-hook.exe' if __import__('os').name == 'nt' else 'aoi-codex-hook'))
# Rewriting both an installed package member and the installed RECORD cannot
# substitute for the reviewed wheel's embedded RECORD/member bytes.
site = Path(sysconfig.get_paths()['purelib'])
member = site / 'aoi_orgware' / 'codex_hook.py'
member.write_bytes(member.read_bytes() + b'\\n# coordinated tamper\\n')
record = next(site.glob('aoi_orgware-*.dist-info')) / 'RECORD'
relative = member.relative_to(site).as_posix()
raw = member.read_bytes()
digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')
replacement = ','.join((relative, 'sha256=' + digest, str(len(raw))))
record.write_text('\\n'.join(replacement if line.startswith(relative + ',') else line for line in record.read_text(encoding='utf-8').splitlines()) + '\\n', encoding='utf-8')
try:
    provenance.validate_codex_local_install_provenance(bundle, expected.read_text().strip(), scripts / ('aoi.exe' if __import__('os').name == 'nt' else 'aoi'))
except provenance.CodexInstallProvenanceError as exc:
    if 'proved wheel' not in str(exc):
        raise
else:
    raise AssertionError('coordinated package and RECORD tamper passed receipt creation')
try:
    provenance.verify_runtime_hook_provenance(project, receipt['provenance_receipt_sha256'], scripts / ('aoi-codex-hook.exe' if __import__('os').name == 'nt' else 'aoi-codex-hook'))
except provenance.CodexInstallProvenanceError:
    pass
else:
    raise AssertionError('coordinated package and RECORD tamper passed runtime verification')
print(json.dumps(receipt, sort_keys=True))
"""
    expected_file = tmp_path / "expected.txt"; expected_file.write_text(bundle["bundle_sha256"], encoding="utf-8")
    completed = _run_python_checked(
        python,
        "-I",
        "-c",
        script,
        str(bundle_file),
        str(expected_file),
        str(tmp_path / "project"),
        cache_root=tmp_path / "python-cache" / "local-v2-receipt",
        evidence_root=evidence_root,
        label="local-v2-receipt",
    )
    receipt = json.loads(completed.stdout)
    assert receipt["schema_version"] == 2
    assert receipt["install_wheel_artifact"]["path"] == str(wheel)
    assert receipt["installed_mapping_strength"] == "direct_url_archive_sha256"
