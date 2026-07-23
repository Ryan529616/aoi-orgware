#!/usr/bin/env python3
"""Tests for the one-command Codex onboarding path."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from harness_case import HarnessTestCase  # noqa: E402
from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware.commands import codex_onboarding as co  # noqa: E402
from aoi_orgware.semantic_events import canonical_sha256  # noqa: E402


TEST_HOOK_LAUNCHER = "/opt/aoi/bin/aoi-codex-hook"
TEST_PROJECT_ROOT = "/work/aoi-project"
TEST_PROVENANCE_SHA256 = "a" * 64
CURRENT_HOOK_COMMAND = co.build_codex_hook_command(
    TEST_HOOK_LAUNCHER,
    TEST_PROJECT_ROOT,
    TEST_PROVENANCE_SHA256,
)
CURRENT_HOOK_KWARGS = {
    "command": CURRENT_HOOK_COMMAND,
    "command_windows": CURRENT_HOOK_COMMAND,
}


def _test_site_root(prefix: Path) -> Path:
    if os.name == "nt":
        return prefix / "Lib" / "site-packages"
    return (
        prefix
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )


def _test_scripts(prefix: Path) -> Path:
    return prefix / ("Scripts" if os.name == "nt" else "bin")


def _test_launcher(scripts: Path, name: str) -> Path:
    return scripts / (f"{name}.exe" if os.name == "nt" else name)


def fake_provenance_receipt(root: Path, *, salt: str = "a") -> dict:
    prefix = root / "test-promoted-install"
    site_root = _test_site_root(prefix)
    dist_info = site_root / "aoi_orgware-0.4.0a1.dist-info"
    scripts = _test_scripts(prefix)
    package = site_root / "aoi_orgware"
    for path in (dist_info, scripts, package):
        path.mkdir(parents=True, exist_ok=True)
    console = _test_launcher(scripts, "aoi")
    hook = _test_launcher(scripts, "aoi-codex-hook")
    metadata = dist_info / "METADATA"
    package_init = package / "__init__.py"
    hook_script: Path | None = None
    if os.name == "nt":
        console.write_bytes(f"console-{salt}".encode())
        hook.write_bytes(f"hook-{salt}".encode())
        hook_script = scripts / "aoi-codex-hook-script.py"
        hook_script.write_text(
            "from aoi_orgware.codex_hook import main\n",
            encoding="utf-8",
        )
    else:
        console.write_text(
            "#!/usr/bin/env python3\n"
            "from aoi_orgware.cli import main\n"
            "main()\n",
            encoding="utf-8",
        )
        hook.write_text(
            "#!/usr/bin/env python3\n"
            "from aoi_orgware.codex_hook import main\n"
            "main()\n",
            encoding="utf-8",
        )
        console.chmod(0o755)
        hook.chmod(0o755)
    metadata.write_bytes(f"metadata-{salt}".encode())
    package_init.write_bytes(f"package-{salt}".encode())
    record = dist_info / "RECORD"

    def record_row(path: Path) -> str:
        raw = path.read_bytes()
        digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode(
            "ascii"
        ).rstrip("=")
        relative = os.path.relpath(path, site_root).replace("\\", "/")
        return f"{relative},sha256={digest},{len(raw)}"

    record_relative = os.path.relpath(record, site_root).replace("\\", "/")
    recorded = [metadata, package_init, console, hook]
    if hook_script is not None:
        recorded.append(hook_script)
    record.write_text(
        "\n".join([*(record_row(path) for path in recorded), f"{record_relative},,"])
        + "\n",
        encoding="utf-8",
    )
    package_manifest = {
        "files": [
            {
                "path": "__init__.py",
                "sha256": hashlib.sha256(package_init.read_bytes()).hexdigest(),
            }
        ]
    }
    base = {
        "schema_version": 1,
        "promotion_bundle_sha256": hashlib.sha256(
            f"bundle-{salt}".encode()
        ).hexdigest(),
        "distribution_name": "aoi-orgware",
        "package_version": "0.4.0a1",
        "installed_metadata_sha256": hashlib.sha256(
            metadata.read_bytes()
        ).hexdigest(),
        "metadata_path": str(metadata.resolve()),
        "package_root": str(package.resolve()),
        "console_entry_point": {
            "name": "aoi",
            "target": "aoi_orgware.cli:main",
            "path": str(console.resolve()),
            "record_sha256": hashlib.sha256(console.read_bytes()).hexdigest(),
        },
        "codex_hook_entry_point": {
            "name": "aoi-codex-hook",
            "target": "aoi_orgware.codex_hook:main",
            "path": str(hook.resolve()),
            "record_sha256": hashlib.sha256(hook.read_bytes()).hexdigest(),
        },
        "hook_protocol_version": 6,
        "codex_hook_generated_script": (
            {
                "path": str(hook_script.resolve()),
                "record_sha256": hashlib.sha256(
                    hook_script.read_bytes()
                ).hexdigest(),
            }
            if hook_script is not None
            else {"path": None, "record_sha256": None}
        ),
        "package_runtime_manifest": {
            "count": 1,
            "sha256": canonical_sha256(package_manifest, max_bytes=64 * 1024),
        },
    }
    return {
        **base,
        "provenance_receipt_sha256": canonical_sha256(base, max_bytes=64 * 1024),
    }


def fake_local_provenance_receipt(root: Path, *, salt: str = "a") -> dict:
    """Return the exact schema-v2 shape emitted by the local proof validator.

    This remains a mocked validator result, but its sealed receipt is deliberately
    strict so codex-init persists and archives the same local-proof contract that
    a real reviewed wheel install supplies.
    """

    public = fake_provenance_receipt(root, salt=salt)
    prefix = root / "test-promoted-install"
    site_root = _test_site_root(prefix)
    dist_info = site_root / "aoi_orgware-0.4.0a1.dist-info"
    scripts = _test_scripts(prefix)
    bridge = _test_launcher(scripts, "aoi-codex-bridge")
    bridge_script: Path | None = None
    if os.name == "nt":
        bridge.write_bytes(f"bridge-{salt}".encode())
        bridge_script = scripts / "aoi-codex-bridge-script.py"
        bridge_script.write_text(
            "from aoi_orgware.codex_transport_cli import main\n",
            encoding="utf-8",
        )
    else:
        bridge.write_text(
            "#!/usr/bin/env python3\n"
            "from aoi_orgware.codex_transport_cli import main\n"
            "main()\n",
            encoding="utf-8",
        )
        bridge.chmod(0o755)
    store_root = root / "reviewed-local-artifact-store"
    store_root.mkdir(parents=True, exist_ok=True)
    bundle = store_root / "aoi-local-install.json"
    wheel = store_root / "aoi_orgware-0.4.0a1-py3-none-any.whl"
    bundle.write_bytes(f"local-bundle-{salt}".encode())
    wheel.write_bytes(f"wheel-{salt}".encode())
    direct_url = dist_info / "direct_url.json"
    direct_url.write_text(
        json.dumps(
            {
                "url": wheel.resolve().as_uri(),
                "archive_info": {
                    "hash": f"sha256={hashlib.sha256(wheel.read_bytes()).hexdigest()}"
                },
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    record = dist_info / "RECORD"
    bridge_record_path = os.path.relpath(bridge, site_root).replace("\\", "/")
    extra_record_rows = [
        f"{bridge_record_path},"
        + "sha256="
        + base64.urlsafe_b64encode(hashlib.sha256(bridge.read_bytes()).digest())
        .decode("ascii")
        .rstrip("=")
        + f",{bridge.stat().st_size}",
    ]
    if bridge_script is not None:
        bridge_script_record_path = os.path.relpath(bridge_script, site_root).replace(
            "\\", "/"
        )
        extra_record_rows.append(
            f"{bridge_script_record_path},"
            + "sha256="
            + base64.urlsafe_b64encode(
                hashlib.sha256(bridge_script.read_bytes()).digest()
            )
            .decode("ascii")
            .rstrip("=")
            + f",{bridge_script.stat().st_size}"
        )
    direct_url_record_path = os.path.relpath(direct_url, site_root).replace("\\", "/")
    record.write_text(
        record.read_text(encoding="utf-8").replace(
            "\n" + os.path.relpath(record, site_root).replace("\\", "/") + ",,\n",
            "\n"
            + "\n".join(extra_record_rows)
            + "\n"
            + f"{direct_url_record_path},"
            + "sha256="
            + base64.urlsafe_b64encode(
                hashlib.sha256(direct_url.read_bytes()).digest()
            ).decode("ascii").rstrip("=")
            + f",{direct_url.stat().st_size}\n"
            + os.path.relpath(record, site_root).replace("\\", "/")
            + ",,\n",
        ),
        encoding="utf-8",
    )
    wheel_sha256 = hashlib.sha256(wheel.read_bytes()).hexdigest()
    metadata_sha256 = public["installed_metadata_sha256"]
    base = {
        "schema_version": 2,
        "install_proof": {
            "kind": "reviewed_local_install_bundle",
            "proof_scope": "exact_local_wheel_install_only",
            "bundle_path": str(bundle.resolve()),
            "bundle_sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
            "artifact_store_root": str(store_root.resolve()),
            "source_commit_oid": "a" * 40,
            "source_tree_oid": "b" * 40,
            "source_manifest_sha256": "c" * 64,
            "rehearsal_report_sha256": "d" * 64,
            "inventory_sha256": "e" * 64,
        },
        "distribution_name": "aoi-orgware",
        "package_version": "0.4.0a1",
        "installed_metadata_sha256": metadata_sha256,
        "metadata_path": public["metadata_path"],
        "package_root": public["package_root"],
        "console_entry_point": public["console_entry_point"],
        "codex_hook_entry_point": public["codex_hook_entry_point"],
        "codex_hook_generated_script": public["codex_hook_generated_script"],
        "codex_bridge_entry_point": {
            "name": "aoi-codex-bridge",
            "target": "aoi_orgware.codex_transport_cli:main",
            "path": str(bridge.resolve()),
            "record_sha256": hashlib.sha256(bridge.read_bytes()).hexdigest(),
        },
        "codex_bridge_generated_script": (
            {
                "path": str(bridge_script.resolve()),
                "record_sha256": hashlib.sha256(
                    bridge_script.read_bytes()
                ).hexdigest(),
            }
            if bridge_script is not None
            else {"path": None, "record_sha256": None}
        ),
        "package_runtime_manifest": public["package_runtime_manifest"],
        "hook_protocol_version": 6,
        "install_wheel_artifact": {
            "name": wheel.name,
            "path": str(wheel.resolve()),
            "sha256": wheel_sha256,
            "size_bytes": wheel.stat().st_size,
        },
        "installed_distribution_identity": {
            "name": "aoi-orgware",
            "version": "0.4.0a1",
            "metadata_sha256": metadata_sha256,
        },
        "installed_mapping_strength": "direct_url_archive_sha256",
        "installed_mapping_evidence": {
            "direct_url": {
                "path": str(direct_url.resolve()),
                "record_sha256": hashlib.sha256(direct_url.read_bytes()).hexdigest(),
                "archive_sha256": wheel_sha256,
                "archive_path": str(wheel.resolve()),
            }
        },
        "installed_record": {
            "path": str(record.resolve()),
            "sha256": hashlib.sha256(record.read_bytes()).hexdigest(),
        },
    }
    return {
        **base,
        "provenance_receipt_sha256": canonical_sha256(base, max_bytes=64 * 1024),
    }


def make_directory_symlink_or_skip(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        raise unittest.SkipTest(f"directory symlink is unavailable: {exc}") from exc


class HookMergeTests(unittest.TestCase):
    def test_required_events_have_exact_status_messages(self) -> None:
        self.assertEqual(
            co.CODEX_HOOK_EVENTS,
            (
                "SessionStart",
                "UserPromptSubmit",
                "SubagentStart",
                "SubagentStop",
                "PreToolUse",
                "PostToolUse",
                "Stop",
            ),
        )
        merged, _ = co.merge_codex_hook_settings({}, **CURRENT_HOOK_KWARGS)
        self.assertEqual(
            {
                event: merged["hooks"][event][0]["hooks"][0]["statusMessage"]
                for event in co.CODEX_HOOK_EVENTS
            },
            {
                "SessionStart": "Loading AOI state",
                "UserPromptSubmit": "Checking AOI task binding",
                "SubagentStart": "Loading AOI packet contract",
                "SubagentStop": "Checking AOI subagent completion",
                "PreToolUse": "Checking AOI claim gate",
                "PostToolUse": "Recording AOI tool receipt",
                "Stop": "Checking AOI checkpoint state",
            },
        )

    def test_merges_required_events_and_preserves_other_hooks(self) -> None:
        existing = {
            "hooks": {
                "SessionStart": [
                    {"hooks": [{"type": "command", "command": "other-tool --x"}]}
                ],
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "guard"}]}
                ],
            },
            "vendor": {"kept": True},
        }
        merged, added = co.merge_codex_hook_settings(existing, **CURRENT_HOOK_KWARGS)
        self.assertEqual(added, list(co.CODEX_HOOK_EVENTS))
        self.assertTrue(merged["vendor"]["kept"])
        self.assertIn("PreToolUse", merged["hooks"])
        self.assertEqual(len(merged["hooks"]["SessionStart"]), 2)
        aoi_entry = merged["hooks"]["SessionStart"][1]
        self.assertEqual(aoi_entry["matcher"], co.SESSION_START_MATCHER)
        handler = aoi_entry["hooks"][0]
        self.assertEqual(handler["command"], CURRENT_HOOK_COMMAND)
        self.assertEqual(handler["commandWindows"], CURRENT_HOOK_COMMAND)
        self.assertEqual(handler["timeout"], co.HOOK_TIMEOUT_SECONDS)

    def test_merge_is_idempotent(self) -> None:
        once, _ = co.merge_codex_hook_settings({}, **CURRENT_HOOK_KWARGS)
        twice, added = co.merge_codex_hook_settings(once, **CURRENT_HOOK_KWARGS)
        self.assertEqual(added, [])
        self.assertEqual(once, twice)

    def test_merge_rejects_invalid_event_shape(self) -> None:
        with self.assertRaises(co.CodexOnboardingError):
            co.merge_codex_hook_settings({"hooks": {"Stop": {}}}, **CURRENT_HOOK_KWARGS)
        for malformed in (None, "not-an-array", {}, [None], [{"command": 7}]):
            with self.subTest(malformed=malformed):
                with self.assertRaises(co.CodexOnboardingError):
                    co.merge_codex_hook_settings(
                        {"hooks": {"Stop": [{"hooks": malformed}]}},
                        **CURRENT_HOOK_KWARGS,
                    )

    def test_pair_rejects_individually_current_but_cross_bound_commands(self) -> None:
        windows = co.build_codex_hook_command(
            r"C:\\AOI Tools\\aoi-codex-hook.exe",
            r"C:\\work\\aoi-project",
            "b" * 64,
        )
        with self.assertRaisesRegex(co.CodexOnboardingError, "bind one exact"):
            co.merge_codex_hook_settings(
                {},
                command=CURRENT_HOOK_COMMAND,
                command_windows=windows,
            )

    def test_wsl_command_pair_is_canonical_and_exact(self) -> None:
        environment = {
            "WSL_DISTRO_NAME": "Ubuntu",
            "WSL_INTEROP": "/run/WSL/123_interop",
        }
        command, command_windows = co.build_codex_hook_commands(
            TEST_HOOK_LAUNCHER,
            TEST_PROJECT_ROOT,
            TEST_PROVENANCE_SHA256,
            environment=environment,
            kernel_release="6.6.0-microsoft-standard-WSL2",
            host_os_name="posix",
            wsl_user="tester",
        )
        self.assertEqual(command, CURRENT_HOOK_COMMAND)
        self.assertEqual(
            command_windows,
            'wsl.exe --distribution "Ubuntu" --user "tester" '
            '--cd "/work/aoi-project" --exec "/opt/aoi/bin/aoi-codex-hook" '
            '--hook-version 6 --project-root "/work/aoi-project" '
            f'--provenance-sha256 "{TEST_PROVENANCE_SHA256}"',
        )
        self.assertTrue(co.is_aoi_codex_hook_command(command_windows))
        self.assertTrue(
            co.is_current_codex_hook_command_pair(
                command,
                command_windows,
                expected_launcher=TEST_HOOK_LAUNCHER,
                expected_project_root=TEST_PROJECT_ROOT,
                expected_provenance_sha256=TEST_PROVENANCE_SHA256,
                environment=environment,
                kernel_release="6.6.0-microsoft-standard-WSL2",
                host_os_name="posix",
                wsl_user="tester",
            )
        )

    def test_wsl_command_pair_preserves_spaced_tokens(self) -> None:
        launcher = "/opt/AOI Tools/bin/aoi-codex-hook"
        root = "/work/Project Alpha"
        environment = {
            "WSL_DISTRO_NAME": "Ubuntu 24.04",
            "WSL_INTEROP": "/run/WSL/123_interop",
        }
        command, command_windows = co.build_codex_hook_commands(
            launcher,
            root,
            TEST_PROVENANCE_SHA256,
            environment=environment,
            kernel_release="6.6.0-microsoft-standard-WSL2",
            host_os_name="posix",
            wsl_user="tester",
        )
        self.assertNotEqual(command, command_windows)
        self.assertEqual(
            shlex.split(command_windows, posix=True),
            [
                "wsl.exe",
                "--distribution",
                "Ubuntu 24.04",
                "--user",
                "tester",
                "--cd",
                root,
                "--exec",
                launcher,
                "--hook-version",
                "6",
                "--project-root",
                root,
                "--provenance-sha256",
                TEST_PROVENANCE_SHA256,
            ],
        )
        self.assertTrue(
            co.is_current_codex_hook_command_pair(
                command,
                command_windows,
                expected_launcher=launcher,
                expected_project_root=root,
                expected_provenance_sha256=TEST_PROVENANCE_SHA256,
                environment=environment,
                kernel_release="6.6.0-microsoft-standard-WSL2",
                host_os_name="posix",
                wsl_user="tester",
            )
        )

    def test_wsl_command_rejects_posix_backslash_quoting_ambiguity(self) -> None:
        cases = (
            ("/opt/aoi/bin/aoi-codex-hook\\", TEST_PROJECT_ROOT),
            (TEST_HOOK_LAUNCHER, "/work/aoi-project\\"),
        )
        for launcher, root in cases:
            with self.subTest(launcher=launcher, root=root):
                with self.assertRaisesRegex(
                    co.CodexOnboardingError, "safe absolute POSIX path"
                ):
                    co.build_codex_windows_wsl_hook_command(
                        launcher,
                        root,
                        TEST_PROVENANCE_SHA256,
                        distribution="Ubuntu",
                        user="tester",
                    )

    def test_wsl_current_wrapper_rejects_shape_and_pair_drift(self) -> None:
        environment = {
            "WSL_DISTRO_NAME": "Ubuntu",
            "WSL_INTEROP": "/run/WSL/123_interop",
        }
        command, command_windows = co.build_codex_hook_commands(
            TEST_HOOK_LAUNCHER,
            TEST_PROJECT_ROOT,
            TEST_PROVENANCE_SHA256,
            environment=environment,
            kernel_release="6.6.0-microsoft-standard-WSL2",
            host_os_name="posix",
            wsl_user="tester",
        )
        malformed = (
            command_windows.replace(
                '--cd "/work/aoi-project"', '--cd "/work/other"'
            ),
            command_windows.replace("--exec", "--exec --exec", 1),
            command_windows.replace("--user", "--cd", 1),
            command_windows + " --extra",
            "bash -lc " + command_windows,
        )
        for candidate in malformed:
            with self.subTest(candidate=candidate):
                self.assertFalse(co.is_aoi_codex_hook_command(candidate))
        for old, new in (("Ubuntu", "Other"), ("tester", "other")):
            drifted = command_windows.replace(old, new, 1)
            self.assertTrue(co.is_aoi_codex_hook_command(drifted))
            self.assertFalse(
                co.is_current_codex_hook_command_pair(
                    command,
                    drifted,
                    expected_launcher=TEST_HOOK_LAUNCHER,
                    expected_project_root=TEST_PROJECT_ROOT,
                    expected_provenance_sha256=TEST_PROVENANCE_SHA256,
                    environment=environment,
                    kernel_release="6.6.0-microsoft-standard-WSL2",
                    host_os_name="posix",
                    wsl_user="tester",
                )
            )

    def test_merge_rejects_partial_or_route_drifted_current_pair(self) -> None:
        environment = {
            "WSL_DISTRO_NAME": "Ubuntu",
            "WSL_INTEROP": "/run/WSL/123_interop",
        }
        command, command_windows = co.build_codex_hook_commands(
            TEST_HOOK_LAUNCHER,
            TEST_PROJECT_ROOT,
            TEST_PROVENANCE_SHA256,
            environment=environment,
            kernel_release="6.6.0-microsoft-standard-WSL2",
            host_os_name="posix",
            wsl_user="tester",
        )
        other_digest = "b" * 64
        cases = (
            {"command": command},
            {"commandWindows": command_windows},
            {
                "command": command,
                "commandWindows": command_windows.replace("Ubuntu", "Other", 1),
            },
            {
                "command": command,
                "commandWindows": command_windows.replace("tester", "other", 1),
            },
            {
                "command": command,
                "commandWindows": command_windows.replace(
                    TEST_HOOK_LAUNCHER, "/srv/aoi/aoi-codex-hook"
                ),
            },
            {
                "command": command,
                "commandWindows": command_windows.replace(
                    TEST_PROJECT_ROOT, "/work/other"
                ),
            },
            {
                "command": command.replace(TEST_PROVENANCE_SHA256, other_digest),
                "commandWindows": command_windows.replace(
                    TEST_PROVENANCE_SHA256, other_digest
                ),
            },
            {
                "command": (
                    f'"{TEST_HOOK_LAUNCHER}" --project-root '
                    f'"{TEST_PROJECT_ROOT}" --hook-version 6 '
                    f'--provenance-sha256 "{TEST_PROVENANCE_SHA256}"'
                ),
                "commandWindows": command_windows.replace(
                    '--distribution "Ubuntu" --user "tester"',
                    '--user "tester" --distribution "Ubuntu"',
                ),
            },
        )
        for handler in cases:
            with self.subTest(handler=handler):
                settings = {
                    "hooks": {"Stop": [{"hooks": [handler]}]},
                    "preserve": {"sentinel": True},
                }
                with self.assertRaisesRegex(
                    co.CodexOnboardingError,
                    "(?:partial|malformed) or route-drifted",
                ):
                    co.merge_codex_hook_settings(
                        settings,
                        command=command,
                        command_windows=command_windows,
                    )
                self.assertEqual(settings["preserve"], {"sentinel": True})

    def test_wsl_detection_is_fail_closed_and_native_unc_is_rejected(self) -> None:
        cases = (
            ({"WSL_DISTRO_NAME": "Ubuntu"}, "6.6.0-linux", "posix"),
            ({"WSL_INTEROP": "/run/WSL/1"}, "6.6.0-linux", "posix"),
            ({}, "6.6.0-microsoft-standard-WSL2", "posix"),
            (
                {
                    "WSL_DISTRO_NAME": "Ubuntu",
                    "WSL_INTEROP": "/run/WSL/1",
                },
                "6.6.0-microsoft-standard-WSL2",
                "nt",
            ),
        )
        for environment, release, os_name in cases:
            with self.subTest(environment=environment, release=release):
                with self.assertRaisesRegex(
                    co.CodexOnboardingError, "signals are partial|contradict"
                ):
                    co.build_codex_hook_commands(
                        TEST_HOOK_LAUNCHER,
                        TEST_PROJECT_ROOT,
                        TEST_PROVENANCE_SHA256,
                        environment=environment,
                        kernel_release=release,
                        host_os_name=os_name,
                        wsl_user="tester",
                    )
        with self.assertRaisesRegex(co.CodexOnboardingError, "safe WSL identity"):
            co.build_codex_windows_wsl_hook_command(
                TEST_HOOK_LAUNCHER,
                TEST_PROJECT_ROOT,
                TEST_PROVENANCE_SHA256,
                distribution="-Ubuntu",
                user="tester",
            )
        with self.assertRaisesRegex(co.CodexOnboardingError, "WSL UNC"):
            co.build_codex_hook_commands(
                r"C:\AOI\aoi-codex-hook.exe",
                r"\\wsl$\Ubuntu\home\tester\project",
                TEST_PROVENANCE_SHA256,
                environment={},
                kernel_release="10.0.0",
                host_os_name="nt",
            )

    def test_existing_aoi_handler_is_upgraded_without_dropping_other_hook(self) -> None:
        old_command = "/opt/aoi-0.2.1/bin/aoi-codex-hook --hook-version 6"
        existing = {
            "hooks": {
                "Stop": [
                    {
                        "hooks": [
                            {"type": "command", "command": "other-stop"},
                            {
                                "type": "command",
                                "command": old_command,
                                "commandWindows": old_command,
                                "timeout": 30,
                            },
                        ]
                    }
                ]
            }
        }
        merged, added = co.merge_codex_hook_settings(existing, **CURRENT_HOOK_KWARGS)
        self.assertEqual(
            added,
            [
                "SessionStart", "UserPromptSubmit", "SubagentStart",
                "SubagentStop", "PreToolUse", "PostToolUse",
            ],
        )
        stop_entries = merged["hooks"]["Stop"]
        self.assertEqual(
            stop_entries[0]["hooks"],
            [{"type": "command", "command": "other-stop"}],
        )
        self.assertEqual(stop_entries[1]["hooks"][0]["command"], CURRENT_HOOK_COMMAND)

    def test_legacy_wsl_handler_upgrades_to_exact_pair_without_dropping_foreign_hook(
        self,
    ) -> None:
        old_launcher = "/opt/aoi-0.3/bin/aoi-codex-hook"
        old_root = "/home/tester/project/ARISE"
        old_command = f'"{old_launcher}" --hook-version 6'
        old_windows = (
            f'wsl.exe -d Ubuntu --cd "{old_root}" "{old_launcher}" '
            "--hook-version 6"
        )
        environment = {
            "WSL_DISTRO_NAME": "Ubuntu",
            "WSL_INTEROP": "/run/WSL/123_interop",
        }
        command, command_windows = co.build_codex_hook_commands(
            TEST_HOOK_LAUNCHER,
            old_root,
            TEST_PROVENANCE_SHA256,
            environment=environment,
            kernel_release="6.6.0-microsoft-standard-WSL2",
            host_os_name="posix",
            wsl_user="tester",
        )
        existing = {
            "hooks": {
                "Stop": [
                    {
                        "hooks": [
                            {"type": "command", "command": "other-stop"},
                            {
                                "type": "command",
                                "command": old_command,
                                "commandWindows": old_windows,
                                "timeout": 30,
                            },
                        ]
                    }
                ]
            }
        }
        merged, added = co.merge_codex_hook_settings(
            existing, command=command, command_windows=command_windows
        )
        self.assertEqual(
            added,
            [
                "SessionStart",
                "UserPromptSubmit",
                "SubagentStart",
                "SubagentStop",
                "PreToolUse",
                "PostToolUse",
            ],
        )
        stop_entries = merged["hooks"]["Stop"]
        self.assertEqual(
            stop_entries[0]["hooks"],
            [{"type": "command", "command": "other-stop"}],
        )
        self.assertEqual(
            (
                stop_entries[1]["hooks"][0]["command"],
                stop_entries[1]["hooks"][0]["commandWindows"],
            ),
            (command, command_windows),
        )

    def test_current_command_requires_exact_bound_absolute_command(self) -> None:
        self.assertTrue(co.is_aoi_codex_hook_command(CURRENT_HOOK_COMMAND))
        self.assertTrue(
            co.is_aoi_codex_hook_command(
                CURRENT_HOOK_COMMAND,
                expected_launcher=TEST_HOOK_LAUNCHER,
                expected_project_root=TEST_PROJECT_ROOT,
                expected_provenance_sha256=TEST_PROVENANCE_SHA256,
            )
        )
        self.assertFalse(
            co.is_aoi_codex_hook_command(
                "echo aoi-codex-hook --hook-version 6"
            )
        )
        with self.assertRaises(co.CodexOnboardingError):
            co.is_aoi_codex_hook_command(
                CURRENT_HOOK_COMMAND,
                expected_launcher=TEST_HOOK_LAUNCHER,
            )
        self.assertFalse(
            co.is_aoi_codex_hook_command(
                '"C:\\Program Files\\AOI\\aoi-codex-hook.exe" --hook-version 6'
            )
        )
        self.assertTrue(
            co.is_aoi_codex_hook_command(
                '"C:\\Program Files\\AOI\\aoi-codex-hook.exe" --hook-version 6',
                require_current=False,
            )
        )
        self.assertTrue(
            co.is_aoi_codex_hook_command(
                "wsl --exec aoi-codex-hook --hook-version 6"
                , require_current=False
            )
        )
        self.assertFalse(
            co.is_aoi_codex_hook_command(
                CURRENT_HOOK_COMMAND.replace(TEST_PROVENANCE_SHA256, "b" * 64),
                expected_launcher=TEST_HOOK_LAUNCHER,
                expected_project_root=TEST_PROJECT_ROOT,
                expected_provenance_sha256=TEST_PROVENANCE_SHA256,
            )
        )
        for command in (
            "echo",
            "echo aoi-codex-hook --hook-version 6",
            "aoi-codex-hook --hook-version 5",
            "aoi-codex-hook --hook-version 6 && echo forged",
            "wsl -d && aoi-codex-hook --hook-version 6",
            "wsl -d --exec aoi-codex-hook --hook-version 6",
            "wsl --cd= aoi-codex-hook --hook-version 6",
            "wsl -d $(echo-pwn) aoi-codex-hook --hook-version 6",
            "wsl -d (group) aoi-codex-hook --hook-version 6",
        ):
            with self.subTest(command=command):
                with self.assertRaises(co.CodexOnboardingError):
                    co.merge_codex_hook_settings(
                        {}, command=command, command_windows=CURRENT_HOOK_COMMAND
                    )

    def test_builder_rejects_relative_launcher_noncanonical_digest_and_unsafe_path(self) -> None:
        for launcher, root, digest in (
            ("aoi-codex-hook", TEST_PROJECT_ROOT, TEST_PROVENANCE_SHA256),
            (TEST_HOOK_LAUNCHER, "relative-root", TEST_PROVENANCE_SHA256),
            (TEST_HOOK_LAUNCHER, TEST_PROJECT_ROOT, "A" * 64),
            ('/opt/"bad/aoi-codex-hook', TEST_PROJECT_ROOT, TEST_PROVENANCE_SHA256),
        ):
            with self.subTest(launcher=launcher, root=root, digest=digest):
                with self.assertRaises(co.CodexOnboardingError):
                    co.build_codex_hook_command(launcher, root, digest)

    def test_current_recognition_rejects_unquoted_or_reordered_fields(self) -> None:
        unquoted = CURRENT_HOOK_COMMAND.replace('"/opt/aoi/bin/aoi-codex-hook"', "/opt/aoi/bin/aoi-codex-hook")
        reordered = CURRENT_HOOK_COMMAND.replace(
            "--hook-version 6 --project-root", "--project-root"
        )
        self.assertFalse(co.is_aoi_codex_hook_command(unquoted))
        self.assertFalse(co.is_aoi_codex_hook_command(reordered))
        with self.assertRaises(co.CodexOnboardingError):
            co.merge_codex_hook_settings(
                {},
                command=f" {CURRENT_HOOK_COMMAND}",
                command_windows=CURRENT_HOOK_COMMAND,
            )

    def test_malformed_existing_aoi_reference_blocks_onboarding(self) -> None:
        spoof = "aoi-codex-hook --hook-version 5 && echo keep-me"
        with self.assertRaisesRegex(
            co.CodexOnboardingError, "malformed or route-drifted"
        ):
            co.merge_codex_hook_settings(
                {"hooks": {"Stop": [{"hooks": [{"command": spoof}]}]}},
                **CURRENT_HOOK_KWARGS,
            )

    def test_known_shell_command_operands_cannot_hide_aoi_hook(self) -> None:
        wrappers = (
            f"bash -lc '{CURRENT_HOOK_COMMAND}'",
            f"sh -c '{CURRENT_HOOK_COMMAND}'",
            "cmd.exe /c 'aoi-codex-hook.exe --hook-version 6'",
            "powershell.exe -Command '& aoi-codex-hook.exe --hook-version 6'",
        )
        for wrapper in wrappers:
            with self.subTest(wrapper=wrapper):
                self.assertTrue(co.references_aoi_codex_hook(wrapper))
                with self.assertRaisesRegex(
                    co.CodexOnboardingError, "malformed or route-drifted"
                ):
                    co.merge_codex_hook_settings(
                        {
                            "hooks": {
                                "Stop": [
                                    {
                                        "hooks": [
                                            {
                                                "command": wrapper,
                                                "commandWindows": wrapper,
                                            }
                                        ]
                                    }
                                ]
                            }
                        },
                        **CURRENT_HOOK_KWARGS,
                    )
        self.assertFalse(
            co.references_aoi_codex_hook(
                'python -c \'print("aoi-codex-hook")\''
            )
        )

    def test_malformed_quote_and_cmd_caret_aoi_references_fail_closed(self) -> None:
        candidates = (
            'aoi-codex-hook --hook-version 6 "unterminated',
            "cmd.exe /c aoi-codex-^hook.exe --hook-version 6",
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                settings = {
                    "hooks": {
                        "Stop": [
                            {
                                "hooks": [
                                    {
                                        "command": candidate,
                                        "commandWindows": candidate,
                                    }
                                ]
                            }
                        ]
                    }
                }
                before = json.dumps(settings, sort_keys=True)
                self.assertTrue(co.references_aoi_codex_hook(candidate))
                with self.assertRaisesRegex(
                    co.CodexOnboardingError, "malformed or route-drifted"
                ):
                    co.merge_codex_hook_settings(
                        settings,
                        **CURRENT_HOOK_KWARGS,
                    )
                self.assertEqual(json.dumps(settings, sort_keys=True), before)

    def test_mixed_platform_ownership_is_rejected_without_data_loss(self) -> None:
        mixed = {
            "hooks": {
                "Stop": [
                    {
                        "hooks": [
                            {
                                "command": "foreign-posix --keep",
                                "commandWindows": (
                                    "aoi-codex-hook --hook-version 5"
                                ),
                            }
                        ]
                    }
                ]
            }
        }
        with self.assertRaisesRegex(co.CodexOnboardingError, "mixes"):
            co.merge_codex_hook_settings(mixed, **CURRENT_HOOK_KWARGS)


class ConfigMergeTests(unittest.TestCase):
    def test_adds_features_table_without_rewriting_existing_toml(self) -> None:
        original = 'model = "gpt-test"\n# keep me\n'
        merged, changed = co.merge_codex_config_toml(original)
        self.assertTrue(changed)
        self.assertTrue(merged.startswith(original))
        self.assertTrue(tomllib.loads(merged)["features"]["hooks"])

    def test_updates_existing_false_and_preserves_comment(self) -> None:
        merged, changed = co.merge_codex_config_toml(
            "[features]\nhooks = false # explicit\nplugins = true\n"
        )
        self.assertTrue(changed)
        self.assertIn("hooks = true # explicit", merged)
        self.assertTrue(tomllib.loads(merged)["features"]["plugins"])

    def test_existing_true_is_byte_stable(self) -> None:
        original = "[features]\nhooks = true\n"
        merged, changed = co.merge_codex_config_toml(original)
        self.assertFalse(changed)
        self.assertEqual(merged, original)

    def test_nested_feature_table_can_receive_parent_table(self) -> None:
        merged, _ = co.merge_codex_config_toml("[features.multi_agent_v2]\nenabled = false\n")
        parsed = tomllib.loads(merged)
        self.assertTrue(parsed["features"]["hooks"])
        self.assertFalse(parsed["features"]["multi_agent_v2"]["enabled"])

    def test_inline_features_refuses_lossy_rewrite(self) -> None:
        with self.assertRaises(co.CodexOnboardingError):
            co.merge_codex_config_toml("features = { plugins = true }\n")

    def test_aoi_policy_flip_changes_only_one_boolean(self) -> None:
        original = "[hooks.codex]\nenabled = false\n\n[legacy]\nenabled = false\n"
        merged, changed = co.enable_aoi_codex_hooks_policy(original)
        self.assertTrue(changed)
        self.assertEqual(
            merged,
            "[hooks.codex]\nenabled = true\n\n[legacy]\nenabled = false\n",
        )


class InstallHelperTests(unittest.TestCase):
    def test_hooks_config_and_skill_install_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_hooks = co.install_codex_hooks(
                root / ".codex" / "hooks.json", **CURRENT_HOOK_KWARGS
            )
            self.assertEqual(first_hooks["events_added"], list(co.CODEX_HOOK_EVENTS))
            second_hooks = co.install_codex_hooks(
                root / ".codex" / "hooks.json", **CURRENT_HOOK_KWARGS
            )
            self.assertEqual(second_hooks["events_added"], [])
            self.assertEqual(second_hooks["events_updated"], [])
            self.assertFalse(second_hooks["changed"])
            config = co.install_codex_config(root / ".codex" / "config.toml")
            self.assertTrue(config["hooks_feature_enabled"])
            parsed = tomllib.loads(
                (root / ".codex" / "config.toml").read_text(encoding="utf-8")
            )
            self.assertTrue(parsed["features"]["hooks"])
            skill = co.install_codex_user_skill(
                root / "user-skills", "# AOI\n"
            )
            self.assertFalse(skill["updated"])
            self.assertEqual(
                (root / "user-skills" / "aoi" / "SKILL.md").read_text(
                    encoding="utf-8"
                ),
                "# AOI\n",
            )

    def test_semantic_noop_does_not_rewrite_hooks_or_skill(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            hooks_path = root / ".codex" / "hooks.json"
            co.install_codex_hooks(hooks_path, **CURRENT_HOOK_KWARGS)
            skills_root = root / "skills"
            co.install_codex_user_skill(skills_root, "# AOI\n")
            with mock.patch.object(co, "_atomic_write_text") as writer:
                hooks = co.install_codex_hooks(hooks_path, **CURRENT_HOOK_KWARGS)
                skill = co.install_codex_user_skill(skills_root, "# AOI\n")
            writer.assert_not_called()
            self.assertFalse(hooks["changed"])
            self.assertFalse(skill["changed"])
            self.assertFalse(skill["updated"])

    def test_user_skill_requires_digest_to_replace_different_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            skills_root = Path(temporary) / ".agents" / "skills"
            skill_path = skills_root / "aoi" / "SKILL.md"
            skill_path.parent.mkdir(parents=True)
            skill_path.write_text("# local customization\n", encoding="utf-8")
            digest = co.preflight_codex_user_skill(
                skills_root, "# local customization\n"
            )["existing_sha256"]
            with self.assertRaises(co.CodexOnboardingError):
                co.install_codex_user_skill(skills_root, "# packaged\n")
            result = co.install_codex_user_skill(
                skills_root,
                "# packaged\n",
                replace_sha256=digest,
            )
            self.assertTrue(result["updated"])
            self.assertEqual(skill_path.read_text(encoding="utf-8"), "# packaged\n")

    def test_invalid_hook_json_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "hooks.json"
            path.write_text("{broken", encoding="utf-8")
            with self.assertRaises(co.CodexOnboardingError):
                co.install_codex_hooks(path, **CURRENT_HOOK_KWARGS)
            self.assertEqual(path.read_text(encoding="utf-8"), "{broken")

    def test_install_reports_existing_aoi_hook_upgrade(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "hooks.json"
            old_command = "/opt/aoi-0.2.1/bin/aoi-codex-hook --hook-version 6"
            payload = {
                "hooks": {
                    event: [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": old_command,
                                    "commandWindows": old_command,
                                    "timeout": 30,
                                }
                            ]
                        }
                    ]
                    for event in co.CODEX_HOOK_EVENTS
                }
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            result = co.install_codex_hooks(path, **CURRENT_HOOK_KWARGS)
            self.assertEqual(result["events_added"], [])
            self.assertEqual(result["events_updated"], list(co.CODEX_HOOK_EVENTS))


class FilesystemBoundaryTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "this regression uses POSIX openat/renameat")
    def test_atomic_publish_stays_with_verified_parent_after_symlink_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "codex"
            parent.mkdir()
            target = parent / "hooks.json"
            target.write_text('{"inside": "old"}\n', encoding="utf-8")
            outside = root / "outside"
            outside.mkdir()
            outside_target = outside / "hooks.json"
            outside_target.write_text('{"outside": "unchanged"}\n', encoding="utf-8")
            before = outside_target.read_bytes()
            parked = root / "verified-parent"

            def switch_parent(path: Path) -> None:
                self.assertEqual(path, target)
                parent.rename(parked)
                os.symlink(outside, parent, target_is_directory=True)

            with mock.patch.object(co, "_atomic_publish_test_hook", switch_parent):
                co._atomic_write_text(target, '{"inside": "new"}\n')

            self.assertEqual(outside_target.read_bytes(), before)
            self.assertEqual(
                (parked / "hooks.json").read_text(encoding="utf-8"),
                '{"inside": "new"}\n',
            )

    @unittest.skipUnless(os.name == "nt", "junctions are native Windows-only")
    def test_atomic_publish_stays_with_verified_parent_after_junction_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "codex"
            parent.mkdir()
            target = parent / "hooks.json"
            target.write_text('{"inside": "old"}\n', encoding="utf-8")
            outside = root / "outside"
            outside.mkdir()
            outside_target = outside / "hooks.json"
            outside_target.write_text('{"outside": "unchanged"}\n', encoding="utf-8")
            before = outside_target.read_bytes()
            parked = root / "verified-parent"

            def switch_parent(path: Path) -> None:
                self.assertEqual(path, target)
                parent.rename(parked)
                created = subprocess.run(
                    ["cmd", "/d", "/c", "mklink", "/J", str(parent), str(outside)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if created.returncode != 0:
                    raise unittest.SkipTest(
                        f"junction creation is unavailable: {created.stderr}"
                    )

            with mock.patch.object(co, "_atomic_publish_test_hook", switch_parent):
                co._atomic_write_text(target, '{"inside": "new"}\n')

            self.assertEqual(outside_target.read_bytes(), before)
            self.assertEqual(
                (parked / "hooks.json").read_text(encoding="utf-8"),
                '{"inside": "new"}\n',
            )

    def test_repo_codex_parent_symlink_is_rejected_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            outside = Path(temporary) / "outside"
            outside.mkdir()
            hooks = outside / "hooks.json"
            hooks.write_text('{"outside": true}\n', encoding="utf-8")
            make_directory_symlink_or_skip(root / ".codex", outside)

            before = hooks.read_bytes()
            with self.assertRaisesRegex(co.CodexOnboardingError, "linked directory"):
                co.preflight_codex_onboarding(root, **CURRENT_HOOK_KWARGS)
            self.assertEqual(hooks.read_bytes(), before)
            self.assertFalse((outside / "config.toml").exists())

    def test_repo_hook_leaf_symlink_is_rejected_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            codex_root = root / ".codex"
            codex_root.mkdir()
            outside = root / "outside-hooks.json"
            outside.write_text('{"outside": true}\n', encoding="utf-8")
            hooks = codex_root / "hooks.json"
            try:
                os.symlink(outside, hooks)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"file symlink is unavailable: {exc}")

            before = outside.read_bytes()
            with self.assertRaisesRegex(co.CodexOnboardingError, "linked Codex file"):
                co.install_codex_hooks(hooks, **CURRENT_HOOK_KWARGS)
            self.assertEqual(outside.read_bytes(), before)
            self.assertTrue(hooks.is_symlink())
            self.assertEqual(list(codex_root.glob(".hooks.json.aoi-*.tmp")), [])

    def test_user_skill_root_symlink_is_rejected_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside-skills"
            outside.mkdir()
            skills_root = root / "user-skills"
            make_directory_symlink_or_skip(skills_root, outside)

            with self.assertRaisesRegex(co.CodexOnboardingError, "linked directory"):
                co.install_codex_user_skill(skills_root, "# AOI\n")
            self.assertFalse((outside / "aoi" / "SKILL.md").exists())
            self.assertTrue(skills_root.is_symlink())

    @unittest.skipUnless(os.name == "nt", "junctions are native Windows-only")
    def test_repo_codex_junction_is_rejected_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            outside = Path(temporary) / "outside"
            outside.mkdir()
            junction = root / ".codex"
            created = subprocess.run(
                ["cmd", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
                capture_output=True,
                text=True,
                check=False,
            )
            if created.returncode != 0:
                self.skipTest(f"junction creation is unavailable: {created.stderr}")

            with self.assertRaisesRegex(co.CodexOnboardingError, "linked directory"):
                co.preflight_codex_onboarding(root, **CURRENT_HOOK_KWARGS)
            with self.assertRaisesRegex(co.CodexOnboardingError, "linked directory"):
                co.install_codex_config(junction / "config.toml")
            with self.assertRaisesRegex(co.CodexOnboardingError, "linked directory"):
                co.install_codex_hooks(junction / "hooks.json", **CURRENT_HOOK_KWARGS)
            self.assertFalse((outside / "config.toml").exists())
            self.assertFalse((outside / "hooks.json").exists())

    @unittest.skipUnless(os.name == "nt", "junctions are native Windows-only")
    def test_user_skill_root_junction_is_rejected_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside-skills"
            outside.mkdir()
            skills_root = root / "user-skills"
            created = subprocess.run(
                ["cmd", "/d", "/c", "mklink", "/J", str(skills_root), str(outside)],
                capture_output=True,
                text=True,
                check=False,
            )
            if created.returncode != 0:
                self.skipTest(f"junction creation is unavailable: {created.stderr}")

            with self.assertRaisesRegex(co.CodexOnboardingError, "linked directory"):
                co.preflight_codex_user_skill(skills_root, "# AOI\n")
            with self.assertRaisesRegex(co.CodexOnboardingError, "linked directory"):
                co.install_codex_user_skill(skills_root, "# AOI\n")
            self.assertFalse((outside / "aoi" / "SKILL.md").exists())


class WiringTests(unittest.TestCase):
    def test_parser_wires_codex_init_handler(self) -> None:
        parser = cli_impl.build_parser()
        sub = next(
            action
            for action in parser._actions
            if action.__class__.__name__ == "_SubParsersAction"
        )
        self.assertIs(
            sub.choices["codex-init"].get_default("handler"), cli_impl.cmd_codex_init
        )

    def test_codex_init_matches_init_chief_fencing(self) -> None:
        self.assertFalse(cli_impl.command_requires_chief("codex-init", initialized=False))
        self.assertTrue(cli_impl.command_requires_chief("codex-init", initialized=True))

    def test_parser_accepts_one_of_the_two_proof_pairs_and_has_no_hook_override(self) -> None:
        parser = cli_impl.build_parser()
        empty = parser.parse_args(["codex-init"])
        self.assertIsNone(empty.promotion_bundle_file)
        self.assertIsNone(empty.local_artifact_bundle_file)
        parsed = parser.parse_args(
            [
                "codex-init",
                "--promotion-bundle-file",
                "C:/release/promotion.json",
                "--expected-promotion-bundle-sha256",
                "a" * 64,
            ]
        )
        self.assertEqual(parsed.promotion_bundle_file, "C:/release/promotion.json")
        self.assertEqual(parsed.expected_promotion_bundle_sha256, "a" * 64)
        self.assertIsNone(parsed.local_artifact_bundle_file)
        local = parser.parse_args(
            [
                "codex-init",
                "--local-artifact-bundle-file",
                "C:/reviewed/aoi-local-install.json",
                "--expected-local-artifact-bundle-sha256",
                "b" * 64,
            ]
        )
        self.assertEqual(local.local_artifact_bundle_file, "C:/reviewed/aoi-local-install.json")
        self.assertEqual(local.expected_local_artifact_bundle_sha256, "b" * 64)
        self.assertIsNone(local.promotion_bundle_file)
        self.assertFalse(hasattr(parsed, "hook_command"))
        self.assertFalse(hasattr(parsed, "hook_command_windows"))


class FreshCodexInitCliTests(unittest.TestCase):
    def test_incomplete_or_ambiguous_proof_pairs_fail_before_any_onboarding_mutation(self) -> None:
        cases = (
            (None, None, None, None, "exactly one complete proof pair"),
            ("C:/release/promotion.json", None, None, None, "must be supplied together"),
            (None, None, "C:/reviewed/local.json", None, "must be supplied together"),
            (
                "C:/release/promotion.json",
                "a" * 64,
                "C:/reviewed/local.json",
                "b" * 64,
                "exactly one complete proof pair",
            ),
        )
        for (
            promotion_bundle_file,
            expected_promotion_bundle_sha256,
            local_artifact_bundle_file,
            expected_local_artifact_bundle_sha256,
            error,
        ) in cases:
            with self.subTest(error=error):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    subprocess.run(
                        ["git", "init", "-b", "main", str(root)],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    args = argparse.Namespace(
                        project_name=None,
                        promotion_bundle_file=promotion_bundle_file,
                        expected_promotion_bundle_sha256=expected_promotion_bundle_sha256,
                        local_artifact_bundle_file=local_artifact_bundle_file,
                        expected_local_artifact_bundle_sha256=(
                            expected_local_artifact_bundle_sha256
                        ),
                        user_skills_root=str(root / "user-skills"),
                        replace_user_skill_sha256=None,
                        json=True,
                    )
                    with self.assertRaisesRegex(h.HarnessError, error):
                        cli_impl.cmd_codex_init(args, h.get_paths(root))
                    self.assertFalse((root / "aoi.toml").exists())
                    self.assertFalse((root / ".aoi").exists())
                    self.assertFalse((root / ".codex").exists())
                    self.assertFalse((root / "user-skills").exists())

    def test_post_init_failure_explains_and_completes_chief_fenced_resume(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            tempfile.TemporaryDirectory() as credential_home,
        ):
            root = Path(temporary)
            subprocess.run(
                ["git", "init", "-b", "main", str(root)],
                check=True,
                capture_output=True,
                text=True,
            )
            skills_root = root / "user-skills"
            args = argparse.Namespace(
                project_name=None,
                promotion_bundle_file="unused-by-this-failure-injection",
                expected_promotion_bundle_sha256="a" * 64,
                user_skills_root=str(skills_root),
                replace_user_skill_sha256=None,
                json=True,
            )
            provenance = fake_provenance_receipt(root)
            with (
                mock.patch.object(
                    cli_impl.codex_install_provenance_impl,
                    "validate_codex_install_provenance",
                    return_value=provenance,
                ),
                mock.patch.object(
                    co, "install_codex_user_skill", side_effect=OSError("disk fault")
                ),
                mock.patch.object(sys, "stdout", new=io.StringIO()),
            ):
                with self.assertRaisesRegex(h.HarnessError, "chief-acquire"):
                    cli_impl.cmd_codex_init(args, h.get_paths(root))
            self.assertTrue((root / "aoi.toml").is_file())

            env = os.environ.copy()
            for name in (
                "AOI_ROOT",
                "AOI_CHIEF_SESSION_ID",
                "AOI_CHIEF_EPOCH",
                "AOI_CHIEF_TOKEN",
                "AOI_CHIEF_CREDENTIAL_FILE",
            ):
                env.pop(name, None)
            env["PYTHONPATH"] = str(HERE.parent / "src")
            env["AOI_CHIEF_CREDENTIAL_HOME"] = credential_home
            acquired = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "aoi_orgware.cli",
                    "chief-acquire",
                    "--session-id",
                    "codex-resume-chief",
                    "--json",
                ],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            authority = json.loads(acquired.stdout)
            env["AOI_CHIEF_SESSION_ID"] = "codex-resume-chief"
            env["AOI_CHIEF_EPOCH"] = str(authority["authority"]["epoch"])
            env["AOI_CHIEF_CREDENTIAL_FILE"] = authority["credential_file"]
            env["AOI_ROOT"] = str(root)
            captured = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
                cli_impl.codex_install_provenance_impl,
                "validate_codex_install_provenance",
                return_value=provenance,
            ), mock.patch.object(sys, "stdout", captured):
                returncode = cli_impl.main(
                    [
                    "codex-init",
                    "--promotion-bundle-file",
                    str(root / "promotion-bundle.json"),
                    "--expected-promotion-bundle-sha256",
                    "a" * 64,
                    "--user-skills-root",
                    str(skills_root),
                    "--json",
                    ]
                )
            self.assertEqual(returncode, 0)
            self.assertTrue(json.loads(captured.getvalue())["resumable"])

    def test_invalid_hook_command_fails_preflight_before_aoi_init(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(
                ["git", "init", "-b", "main", str(root)],
                check=True,
                capture_output=True,
                text=True,
            )
            env = os.environ.copy()
            env["PYTHONPATH"] = str(HERE.parent / "src")
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "aoi_orgware.cli",
                    "codex-init",
                    "--promotion-bundle-file",
                    str(root / "promotion-bundle.json"),
                    "--expected-promotion-bundle-sha256",
                    "a" * 64,
                    "--hook-command",
                    "echo aoi-codex-hook --hook-version 6",
                    "--user-skills-root",
                    str(root / "user-skills"),
                    "--json",
                ],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse((root / "aoi.toml").exists())
            self.assertFalse((root / ".codex").exists())

    def test_fresh_repo_initializes_aoi_and_codex_layers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(
                ["git", "init", "-b", "main", str(root)],
                check=True,
                capture_output=True,
                text=True,
            )
            (root / "README.md").write_text("# Fresh\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "-c",
                    "user.name=Harness Test",
                    "-c",
                    "user.email=harness@test.invalid",
                    "commit",
                    "-m",
                    "initial",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            env = os.environ.copy()
            env["PYTHONPATH"] = str(HERE.parent / "src")
            provenance = fake_provenance_receipt(root)
            args = argparse.Namespace(
                project_name="Fresh AOI",
                promotion_bundle_file=str(root / "promotion-bundle.json"),
                expected_promotion_bundle_sha256="a" * 64,
                user_skills_root=str(root / "user-skills"),
                replace_user_skill_sha256=None,
                json=True,
            )
            captured = io.StringIO()
            with mock.patch.object(
                cli_impl.codex_install_provenance_impl,
                "validate_codex_install_provenance",
                return_value=provenance,
            ), mock.patch.object(
                cli_impl.confidentiality_impl,
                "require_publication_action_allowed",
                side_effect=AssertionError(
                    "inbound AOI installation is not project-file publication"
                ),
            ), mock.patch.object(sys, "stdout", captured):
                self.assertEqual(cli_impl.cmd_codex_init(args, h.get_paths(root)), 0)
            payload = json.loads(captured.getvalue())
            self.assertTrue(payload["created_config"])
            self.assertTrue(payload["aoi_hook_policy_changed"])
            self.assertTrue(
                tomllib.loads((root / "aoi.toml").read_text(encoding="utf-8"))[
                    "hooks"
                ]["codex"]["enabled"]
            )
            self.assertTrue((root / ".codex" / "hooks.json").is_file())
            self.assertTrue(
                (root / "user-skills" / "aoi" / "SKILL.md").is_file()
            )
            self.assertFalse((root / ".agents" / "skills" / "aoi").exists())


class CodexInitCliTests(HarnessTestCase):
    def codex_init(
        self, *args: str, ok: bool = True
    ) -> subprocess.CompletedProcess[str]:
        self.provenance_receipt = fake_provenance_receipt(self.root)
        (
            self.expected_hook_command,
            self.expected_hook_command_windows,
        ) = co.build_codex_hook_commands(
            self.provenance_receipt["codex_hook_entry_point"]["path"],
            self.root,
            self.provenance_receipt["provenance_receipt_sha256"],
        )
        with mock.patch.object(
            cli_impl.codex_install_provenance_impl,
            "validate_codex_install_provenance",
            return_value=self.provenance_receipt,
        ):
            return self.cli_in_process(
                "codex-init",
                "--promotion-bundle-file",
                str(self.root / "promotion-bundle.json"),
                "--expected-promotion-bundle-sha256",
                "a" * 64,
                "--user-skills-root",
                str(self.root / "user-skills"),
                *args,
                ok=ok,
            )

    def test_codex_init_wires_policy_hooks_config_and_skill(self) -> None:
        result = json.loads(self.codex_init("--json").stdout)
        self.assertTrue(result["codex_init"])
        self.assertTrue(result["aoi_hook_policy_enabled"])
        self.assertTrue(result["aoi_hook_policy_changed"])
        aoi_config = tomllib.loads(
            (self.root / "aoi.toml").read_text(encoding="utf-8")
        )
        self.assertTrue(aoi_config["hooks"]["codex"]["enabled"])
        codex_config = tomllib.loads(
            (self.root / ".codex" / "config.toml").read_text(encoding="utf-8")
        )
        self.assertTrue(codex_config["features"]["hooks"])
        hooks = json.loads(
            (self.root / ".codex" / "hooks.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            hooks["hooks"]["SubagentStart"][0]["hooks"][0]["command"],
            self.expected_hook_command,
        )
        self.assertEqual(
            hooks["hooks"]["SubagentStart"][0]["hooks"][0]["commandWindows"],
            self.expected_hook_command_windows,
        )
        self.assertEqual(
            result["install_provenance"]["provenance_receipt_sha256"],
            self.provenance_receipt["provenance_receipt_sha256"],
        )
        skill_text = (
            self.root / "user-skills" / "aoi" / "SKILL.md"
        ).read_text(encoding="utf-8")
        self.assertIn("Govern work with AOI", skill_text)
        self.assertEqual(result["skill"]["scope"], "user")
        self.assertFalse((self.root / ".agents" / "skills" / "aoi").exists())
        with mock.patch.object(
            cli_impl.codex_install_provenance_impl,
            "verify_runtime_hook_provenance",
            return_value=self.provenance_receipt,
        ):
            doctor = json.loads(self.cli_in_process("doctor", "--json").stdout)
        self.assertTrue(doctor["ok"], doctor)

    def test_codex_init_is_idempotent(self) -> None:
        first = json.loads(self.codex_init("--json").stdout)
        second = json.loads(self.codex_init("--json").stdout)
        self.assertTrue(first["aoi_hook_policy_changed"])
        self.assertFalse(second["aoi_hook_policy_changed"])
        self.assertEqual(second["hooks"]["events_added"], [])

    def test_local_proof_dispatches_only_to_local_validator(self) -> None:
        receipt = fake_local_provenance_receipt(self.root, salt="local")
        local_bundle = self.root / "reviewed-local-install.json"
        expected_sha256 = "b" * 64
        invoked_console = Path(sys.argv[0]).resolve()
        with (
            mock.patch.object(
                cli_impl.codex_install_provenance_impl,
                "validate_codex_install_provenance",
            ) as public_validator,
            mock.patch.object(
                cli_impl.codex_install_provenance_impl,
                "validate_codex_local_install_provenance",
                return_value=receipt,
            ) as local_validator,
        ):
            result = self.cli_in_process(
                "codex-init",
                "--local-artifact-bundle-file",
                str(local_bundle),
                "--expected-local-artifact-bundle-sha256",
                expected_sha256,
                "--user-skills-root",
                str(self.root / "user-skills"),
                "--json",
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        public_validator.assert_not_called()
        local_validator.assert_called_once_with(
            str(local_bundle), expected_sha256, invoked_console
        )
        persisted = json.loads(
            (self.root / ".aoi" / "codex-install-provenance-v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(persisted, receipt)
        self.assertEqual(persisted["schema_version"], 2)
        self.assertEqual(
            persisted["install_proof"]["proof_scope"],
            "exact_local_wheel_install_only",
        )

    def test_public_to_local_proof_change_archives_without_release_promotion_state(self) -> None:
        public = fake_provenance_receipt(self.root, salt="public")
        local = fake_local_provenance_receipt(self.root, salt="local")
        with mock.patch.object(
            cli_impl.codex_install_provenance_impl,
            "validate_codex_install_provenance",
            return_value=public,
        ):
            first = self.cli_in_process(
                "codex-init",
                "--promotion-bundle-file",
                str(self.root / "promotion.json"),
                "--expected-promotion-bundle-sha256",
                "a" * 64,
                "--user-skills-root",
                str(self.root / "user-skills"),
                "--json",
            )
        self.assertEqual(first.returncode, 0, first.stderr)
        with (
            mock.patch.object(
                cli_impl.codex_install_provenance_impl,
                "validate_codex_install_provenance",
            ) as public_validator,
            mock.patch.object(
                cli_impl.codex_install_provenance_impl,
                "validate_codex_local_install_provenance",
                return_value=local,
            ) as local_validator,
        ):
            second = self.cli_in_process(
                "codex-init",
                "--local-artifact-bundle-file",
                str(self.root / "local.json"),
                "--expected-local-artifact-bundle-sha256",
                "b" * 64,
                "--user-skills-root",
                str(self.root / "user-skills"),
                "--json",
            )
        self.assertEqual(second.returncode, 0, second.stderr)
        public_validator.assert_not_called()
        local_validator.assert_called_once()
        history = self.root / ".aoi" / "codex-install-provenance-history-v1"
        self.assertTrue(
            (history / f"{public['provenance_receipt_sha256']}.json").is_file()
        )
        self.assertFalse((self.root / ".aoi" / "release_promotions").exists())
        current = json.loads(
            (self.root / ".aoi" / "codex-install-provenance-v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(current, local)
        self.assertEqual(current["schema_version"], 2)

    def test_proof_rotation_receipt_write_failure_is_resumable(self) -> None:
        public = fake_provenance_receipt(self.root, salt="public-crash")
        local = fake_local_provenance_receipt(self.root, salt="local-crash")
        with mock.patch.object(
            cli_impl.codex_install_provenance_impl,
            "validate_codex_install_provenance",
            return_value=public,
        ):
            first = self.cli_in_process(
                "codex-init",
                "--promotion-bundle-file",
                str(self.root / "promotion.json"),
                "--expected-promotion-bundle-sha256",
                "a" * 64,
                "--user-skills-root",
                str(self.root / "user-skills"),
                "--json",
            )
        self.assertEqual(first.returncode, 0, first.stderr)

        local_args = (
            "codex-init",
            "--local-artifact-bundle-file",
            str(self.root / "local.json"),
            "--expected-local-artifact-bundle-sha256",
            "b" * 64,
            "--user-skills-root",
            str(self.root / "user-skills"),
            "--json",
        )
        with (
            mock.patch.object(
                cli_impl.codex_install_provenance_impl,
                "validate_codex_local_install_provenance",
                return_value=local,
            ),
            mock.patch.object(
                cli_impl,
                "_install_codex_provenance_receipt",
                side_effect=OSError("receipt disk fault"),
            ),
        ):
            failed = self.cli_in_process(*local_args, ok=False)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("rerun the same command", failed.stderr)
        persisted = json.loads(
            (self.root / ".aoi" / "codex-install-provenance-v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(persisted, public)
        expected_local_pair = co.build_codex_hook_commands(
            local["codex_hook_entry_point"]["path"],
            self.root,
            local["provenance_receipt_sha256"],
        )
        handler = json.loads(
            (self.root / ".codex" / "hooks.json").read_text(encoding="utf-8")
        )["hooks"]["Stop"][0]["hooks"][0]
        self.assertEqual(
            (handler["command"], handler["commandWindows"]),
            expected_local_pair,
        )

        with mock.patch.object(
            cli_impl.codex_install_provenance_impl,
            "validate_codex_local_install_provenance",
            return_value=local,
        ):
            resumed = self.cli_in_process(*local_args)
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        final_receipt = json.loads(
            (self.root / ".aoi" / "codex-install-provenance-v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(final_receipt, local)

    def test_fresh_policy_flip_refuses_a_chief_acquired_after_bootstrap(self) -> None:
        paths = h.get_paths(self.root)
        self.assertFalse(paths.project.codex_hooks_enabled)
        with self.assertRaisesRegex(h.HarnessError, "Chief authority appeared"):
            cli_impl._enable_codex_hook_policy(
                paths,
                fresh_unauthenticated_init=True,
            )
        self.assertFalse(h.get_paths(self.root).project.codex_hooks_enabled)

    def test_partial_atomic_write_failure_is_reported_and_resumable(self) -> None:
        args = argparse.Namespace(
            project_name=None,
            promotion_bundle_file="unused-by-this-failure-injection",
            expected_promotion_bundle_sha256="a" * 64,
            user_skills_root=str(self.root / "user-skills"),
            replace_user_skill_sha256=None,
            json=True,
        )
        provenance = fake_provenance_receipt(self.root)
        with (
            mock.patch.object(
                cli_impl.codex_install_provenance_impl,
                "validate_codex_install_provenance",
                return_value=provenance,
            ),
            mock.patch.object(
                co, "install_codex_user_skill", side_effect=OSError("disk fault")
            ),
            mock.patch.object(sys, "stdout", new=io.StringIO()),
        ):
            with self.assertRaisesRegex(h.HarnessError, "rerun the same command"):
                cli_impl.cmd_codex_init(args, h.get_paths(self.root))
        self.assertTrue((self.root / ".codex" / "config.toml").is_file())
        self.assertTrue((self.root / ".codex" / "hooks.json").is_file())

        resumed = json.loads(self.codex_init("--json").stdout)
        self.assertTrue(resumed["resumable"])
        self.assertFalse(resumed["aoi_hook_policy_changed"])
        self.assertEqual(resumed["hooks"]["events_added"], [])
        self.assertTrue((self.root / "user-skills" / "aoi" / "SKILL.md").is_file())

    def test_policy_post_write_failure_is_reported_and_resumable(self) -> None:
        args = argparse.Namespace(
            project_name=None,
            promotion_bundle_file="unused-by-this-failure-injection",
            expected_promotion_bundle_sha256="a" * 64,
            user_skills_root=str(self.root / "user-skills"),
            replace_user_skill_sha256=None,
            json=True,
        )
        provenance = fake_provenance_receipt(self.root)
        with (
            mock.patch.object(
                cli_impl.codex_install_provenance_impl,
                "validate_codex_install_provenance",
                return_value=provenance,
            ),
            mock.patch.object(cli_impl, "write_index", side_effect=OSError("disk fault")),
            mock.patch.object(sys, "stdout", new=io.StringIO()),
        ):
            with self.assertRaisesRegex(h.HarnessError, "current Chief credential"):
                cli_impl.cmd_codex_init(args, h.get_paths(self.root))
        self.assertTrue(h.get_paths(self.root).project.codex_hooks_enabled)

        resumed = json.loads(self.codex_init("--json").stdout)
        self.assertFalse(resumed["aoi_hook_policy_changed"])
        self.assertTrue(resumed["resumable"])

    def test_codex_init_refuses_profile_change_with_active_task(self) -> None:
        self.init_task("active-config-digest")
        result = self.codex_init("--json", ok=False)
        self.assertIn("active AOI tasks", result.stderr)
        self.assertFalse((self.root / ".codex" / "hooks.json").exists())

    def test_doctor_allows_unrelated_codex_hooks(self) -> None:
        self.codex_init("--json")
        path = self.root / ".codex" / "hooks.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["hooks"]["PreToolUse"].insert(
            0,
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "guard"}]},
        )
        payload["hooks"]["Stop"].insert(
            0, {"hooks": [{"type": "command", "command": "other-stop"}]}
        )
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        with mock.patch.object(
            cli_impl.codex_install_provenance_impl,
            "verify_runtime_hook_provenance",
            return_value=self.provenance_receipt,
        ):
            doctor = json.loads(self.cli_in_process("doctor", "--json").stdout)
        self.assertTrue(doctor["ok"], doctor)

    def test_doctor_rejects_platform_command_pair_drift(self) -> None:
        self.codex_init("--json")
        path = self.root / ".codex" / "hooks.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        handler = payload["hooks"]["Stop"][0]["hooks"][0]
        windows = handler["commandWindows"]
        if windows.startswith("wsl.exe "):
            handler["commandWindows"] = windows.replace(
                '--distribution "', '--distribution "wrong-', 1
            )
        else:
            handler["commandWindows"] = windows.replace(
                self.provenance_receipt["provenance_receipt_sha256"],
                "b" * 64,
            )
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-m", "aoi_orgware.cli", "doctor", "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        doctor = json.loads(result.stdout)
        self.assertTrue(
            any(
                "Stop commandWindows must invoke the exact platform-specific"
                in item
                for item in doctor["errors"]
            ),
            doctor,
        )

    def test_doctor_rejects_spoofed_aoi_command_string(self) -> None:
        self.codex_init("--json")
        path = self.root / ".codex" / "hooks.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        handler = payload["hooks"]["Stop"][0]["hooks"][0]
        handler["command"] = "echo aoi-codex-hook --hook-version 6"
        handler["commandWindows"] = "echo aoi-codex-hook --hook-version 6"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-m", "aoi_orgware.cli", "doctor", "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        doctor = json.loads(result.stdout)
        self.assertFalse(doctor["ok"])
        self.assertTrue(
            any("exactly one AOI handler for Stop" in item for item in doctor["errors"]),
            doctor,
        )


if __name__ == "__main__":
    unittest.main()
