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
        merged, added = co.merge_codex_hook_settings(existing)
        self.assertEqual(
            added, ["SessionStart", "UserPromptSubmit", "SubagentStart"]
        )
        stop_entries = merged["hooks"]["Stop"]
        self.assertEqual(
            stop_entries[0]["hooks"],
            [{"type": "command", "command": "other-stop"}],
        )
        self.assertEqual(stop_entries[1]["hooks"][0]["command"], co.HOOK_COMMAND)


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
            self.assertEqual(second_hooks["events_updated"], [])
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
                co.install_codex_hooks(path)
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
            result = co.install_codex_hooks(path)
            self.assertEqual(result["events_added"], [])
            self.assertEqual(result["events_updated"], list(co.CODEX_HOOK_EVENTS))


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
            self.assertTrue(
                (root / "user-skills" / "aoi" / "SKILL.md").is_file()
            )
            self.assertFalse((root / ".agents" / "skills" / "aoi").exists())


class CodexInitCliTests(HarnessTestCase):
    def codex_init(
        self, *args: str, ok: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return self.cli(
            "codex-init",
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
            co.HOOK_COMMAND,
        )
        skill_text = (
            self.root / "user-skills" / "aoi" / "SKILL.md"
        ).read_text(encoding="utf-8")
        self.assertIn("Govern work with AOI", skill_text)
        self.assertEqual(result["skill"]["scope"], "user")
        self.assertFalse((self.root / ".agents" / "skills" / "aoi").exists())
        doctor = json.loads(self.cli("doctor", "--json").stdout)
        self.assertTrue(doctor["ok"], doctor)

    def test_codex_init_is_idempotent(self) -> None:
        first = json.loads(self.codex_init("--json").stdout)
        second = json.loads(self.codex_init("--json").stdout)
        self.assertTrue(first["aoi_hook_policy_changed"])
        self.assertFalse(second["aoi_hook_policy_changed"])
        self.assertEqual(second["hooks"]["events_added"], [])

    def test_codex_init_refuses_profile_change_with_active_task(self) -> None:
        self.init_task("active-config-digest")
        result = self.codex_init("--json", ok=False)
        self.assertIn("active AOI tasks", result.stderr)
        self.assertFalse((self.root / ".codex" / "hooks.json").exists())

    def test_doctor_allows_unrelated_codex_hooks(self) -> None:
        self.codex_init("--json")
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
