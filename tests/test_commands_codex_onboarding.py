#!/usr/bin/env python3
"""Tests for the one-command Codex onboarding path."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from harness_case import HarnessTestCase  # noqa: E402
from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware.commands import codex_onboarding as co  # noqa: E402


class HookMergeTests(unittest.TestCase):
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
        merged, added = co.merge_codex_hook_settings(existing)
        self.assertEqual(added, list(co.CODEX_HOOK_EVENTS))
        self.assertTrue(merged["vendor"]["kept"])
        self.assertIn("PreToolUse", merged["hooks"])
        self.assertEqual(len(merged["hooks"]["SessionStart"]), 2)
        aoi_entry = merged["hooks"]["SessionStart"][1]
        self.assertEqual(aoi_entry["matcher"], co.SESSION_START_MATCHER)
        handler = aoi_entry["hooks"][0]
        self.assertEqual(handler["command"], co.HOOK_COMMAND)
        self.assertEqual(handler["commandWindows"], co.HOOK_COMMAND)
        self.assertEqual(handler["timeout"], co.HOOK_TIMEOUT_SECONDS)

    def test_merge_is_idempotent(self) -> None:
        once, _ = co.merge_codex_hook_settings({})
        twice, added = co.merge_codex_hook_settings(once)
        self.assertEqual(added, [])
        self.assertEqual(once, twice)

    def test_merge_rejects_invalid_event_shape(self) -> None:
        with self.assertRaises(co.CodexOnboardingError):
            co.merge_codex_hook_settings({"hooks": {"Stop": {}}})

    def test_custom_windows_command_is_kept(self) -> None:
        merged, _ = co.merge_codex_hook_settings(
            {},
            command="aoi-codex-hook --hook-version 6",
            command_windows="wsl aoi-codex-hook --hook-version 6",
        )
        handler = merged["hooks"]["Stop"][0]["hooks"][0]
        self.assertEqual(
            handler["commandWindows"], "wsl aoi-codex-hook --hook-version 6"
        )


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
            first_hooks = co.install_codex_hooks(root / ".codex" / "hooks.json")
            self.assertEqual(first_hooks["events_added"], list(co.CODEX_HOOK_EVENTS))
            second_hooks = co.install_codex_hooks(root / ".codex" / "hooks.json")
            self.assertEqual(second_hooks["events_added"], [])
            config = co.install_codex_config(root / ".codex" / "config.toml")
            self.assertTrue(config["hooks_feature_enabled"])
            parsed = tomllib.loads(
                (root / ".codex" / "config.toml").read_text(encoding="utf-8")
            )
            self.assertTrue(parsed["features"]["hooks"])
            skill = co.install_codex_skill(root / ".agents" / "skills", "# AOI\n")
            self.assertFalse(skill["updated"])
            self.assertEqual(
                (root / ".agents" / "skills" / "aoi" / "SKILL.md").read_text(
                    encoding="utf-8"
                ),
                "# AOI\n",
            )

    def test_invalid_hook_json_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "hooks.json"
            path.write_text("{broken", encoding="utf-8")
            with self.assertRaises(co.CodexOnboardingError):
                co.install_codex_hooks(path)
            self.assertEqual(path.read_text(encoding="utf-8"), "{broken")


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


class FreshCodexInitCliTests(unittest.TestCase):
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
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "aoi_orgware.cli",
                    "codex-init",
                    "--project-name",
                    "Fresh AOI",
                    "--json",
                ],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["created_config"])
            self.assertTrue(payload["aoi_hook_policy_changed"])
            self.assertTrue(
                tomllib.loads((root / "aoi.toml").read_text(encoding="utf-8"))[
                    "hooks"
                ]["codex"]["enabled"]
            )
            self.assertTrue((root / ".codex" / "hooks.json").is_file())
            self.assertTrue((root / ".agents" / "skills" / "aoi" / "SKILL.md").is_file())


class CodexInitCliTests(HarnessTestCase):
    def test_codex_init_wires_policy_hooks_config_and_skill(self) -> None:
        result = json.loads(self.cli("codex-init", "--json").stdout)
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
            co.HOOK_COMMAND,
        )
        skill_text = (
            self.root / ".agents" / "skills" / "aoi" / "SKILL.md"
        ).read_text(encoding="utf-8")
        self.assertIn("Operating under AOI in Codex", skill_text)
        doctor = json.loads(self.cli("doctor", "--json").stdout)
        self.assertTrue(doctor["ok"], doctor)

    def test_codex_init_is_idempotent(self) -> None:
        first = json.loads(self.cli("codex-init", "--json").stdout)
        second = json.loads(self.cli("codex-init", "--json").stdout)
        self.assertTrue(first["aoi_hook_policy_changed"])
        self.assertFalse(second["aoi_hook_policy_changed"])
        self.assertEqual(second["hooks"]["events_added"], [])

    def test_codex_init_refuses_profile_change_with_active_task(self) -> None:
        self.init_task("active-config-digest")
        result = self.cli("codex-init", "--json", ok=False)
        self.assertIn("active AOI tasks", result.stderr)
        self.assertFalse((self.root / ".codex" / "hooks.json").exists())

    def test_doctor_allows_unrelated_codex_hooks(self) -> None:
        self.cli("codex-init", "--json")
        path = self.root / ".codex" / "hooks.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["hooks"]["PreToolUse"] = [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "guard"}]}
        ]
        payload["hooks"]["Stop"].insert(
            0, {"hooks": [{"type": "command", "command": "other-stop"}]}
        )
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        doctor = json.loads(self.cli("doctor", "--json").stdout)
        self.assertTrue(doctor["ok"], doctor)


if __name__ == "__main__":
    unittest.main()
