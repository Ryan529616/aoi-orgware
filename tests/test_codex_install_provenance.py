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
import venv

import pytest

from aoi_orgware import codex_install_provenance as provenance
from aoi_orgware import local_install_proof
from aoi_orgware._version import __version__
from aoi_orgware.semantic_events import canonical_json_bytes, canonical_sha256


def _row(path: Path, root: Path) -> list[str]:
    raw = path.read_bytes()
    return [os.path.relpath(path, root).replace("\\", "/"), "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("="), str(len(raw))]


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
    for name, target in (
        ("aoi", "aoi_orgware.cli:main"),
        ("aoi-codex-hook", "aoi_orgware.codex_hook:main"),
        ("aoi-codex-bridge", "aoi_orgware.codex_transport_cli:main"),
    ):
        _write_launcher(prefix, name, target, with_companion=with_companion)
    rows = [_row(p, site) for p in [dist / "METADATA", *(package / x for x in ("__init__.py", "_version.py", "cli.py", "codex_hook.py", "codex_transport_cli.py", "helper.py")), *sorted(scripts.iterdir())]]
    (dist / "RECORD").write_text("\n".join(",".join(row) for row in rows) + "\n" + str((dist / "RECORD").relative_to(site)).replace("\\", "/") + ",,\n", encoding="utf-8")
    entries = [SimpleNamespace(group="console_scripts", name="aoi", value="aoi_orgware.cli:main"), SimpleNamespace(group="console_scripts", name="aoi-codex-hook", value="aoi_orgware.codex_hook:main"), SimpleNamespace(group="console_scripts", name="aoi-codex-bridge", value="aoi_orgware.codex_transport_cli:main")]
    fake_dist = SimpleNamespace(_path=dist, metadata={"Name": "aoi-orgware"}, version="1.2.3", entry_points=entries)
    modules = {"aoi_orgware": SimpleNamespace(__file__=str(package / "__init__.py"), __version__="1.2.3"), "aoi_orgware._version": SimpleNamespace(__file__=str(package / "_version.py"), __version__="1.2.3"), "aoi_orgware.cli": SimpleNamespace(__file__=str(package / "cli.py")), "aoi_orgware.codex_hook": SimpleNamespace(__file__=str(package / "codex_hook.py")), "aoi_orgware.codex_transport_cli": SimpleNamespace(__file__=str(package / "codex_transport_cli.py"))}
    monkeypatch.setattr(provenance.metadata, "distribution", lambda _: fake_dist)
    monkeypatch.setattr(provenance.importlib, "import_module", lambda name: modules[name])
    monkeypatch.setattr(provenance.sys, "prefix", str(prefix))
    bundle = {"bundle_sha256": "a" * 64, "manifest": {"distribution_name": "aoi-orgware", "package_version": "1.2.3", "artifacts": [{"name": "aoi-orgware-1.2.3-py3-none-any.whl", "sha256": "b" * 64}], "interfaces": {"installed_metadata_sha256": hashlib.sha256((dist / "METADATA").read_bytes()).hexdigest(), "console_entry_point": {"name": "aoi", "target": "aoi_orgware.cli:main"}, "codex_hook_entry_point": {"name": "aoi-codex-hook", "target": "aoi_orgware.codex_hook:main"}, "hook_protocol_version": 6}}}
    monkeypatch.setattr(provenance.release_runtime, "validate_promotion_bundle", lambda value, expected: bundle)
    bundle_file = tmp_path / "bundle.json"; bundle_file.write_text("{}", encoding="utf-8")
    return prefix, bundle_file, bundle


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
    assert receipt["package_runtime_manifest"]["count"] == 6


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
    wheel.parent.mkdir(parents=True); wheel.write_bytes(b"reviewed-wheel")
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
    wheel.write_bytes(b"reviewed-wheel")
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
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--isolated",
            "--no-deps",
            "--wheel-dir",
            str(wheelhouse),
            str(repository),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = list(wheelhouse.glob("aoi_orgware-*.whl"))
    assert len(wheels) == 1
    wheel = wheels[0]
    prefix = tmp_path / "isolated"
    venv.EnvBuilder(with_pip=True).create(prefix)
    python = prefix / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--isolated",
            "--no-index",
            "--no-deps",
            str(wheel),
        ],
        check=True,
        capture_output=True,
        text=True,
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
    completed = subprocess.run(
        [str(python), "-I", "-c", script, str(wheel), str(bundle_file), expected],
        check=True,
        capture_output=True,
        text=True,
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
    subprocess.run([sys.executable, "-m", "pip", "wheel", "--isolated", "--no-deps", "--wheel-dir", str(wheelhouse), str(repository)], check=True, capture_output=True, text=True)
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
    prefix = tmp_path / "isolated"; venv.EnvBuilder(with_pip=True).create(prefix)
    python = prefix / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run([str(python), "-m", "pip", "install", "--isolated", "--no-index", "--no-deps", str(wheel)], check=True, capture_output=True, text=True)
    script = """
import json
from pathlib import Path
import sys
from aoi_orgware import codex_install_provenance as provenance
from aoi_orgware.semantic_events import canonical_json_bytes
bundle, expected, project = map(Path, sys.argv[1:4])
scripts = Path(sys.prefix) / ('Scripts' if __import__('os').name == 'nt' else 'bin')
receipt = provenance.validate_codex_local_install_provenance(bundle, expected.read_text().strip(), scripts / ('aoi.exe' if __import__('os').name == 'nt' else 'aoi'))
target = project / provenance.CODEX_INSTALL_PROVENANCE_RECEIPT; target.parent.mkdir(parents=True); target.write_bytes(canonical_json_bytes(receipt))
provenance.verify_runtime_hook_provenance(project, receipt['provenance_receipt_sha256'], scripts / ('aoi-codex-hook.exe' if __import__('os').name == 'nt' else 'aoi-codex-hook'))
print(json.dumps(receipt, sort_keys=True))
"""
    expected_file = tmp_path / "expected.txt"; expected_file.write_text(bundle["bundle_sha256"], encoding="utf-8")
    completed = subprocess.run([str(python), "-I", "-c", script, str(bundle_file), str(expected_file), str(tmp_path / "project")], check=True, capture_output=True, text=True)
    receipt = json.loads(completed.stdout)
    assert receipt["schema_version"] == 2
    assert receipt["install_wheel_artifact"]["path"] == str(wheel)
    assert receipt["installed_mapping_strength"] == "direct_url_archive_sha256"
