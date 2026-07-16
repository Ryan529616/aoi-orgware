#!/usr/bin/env python3
"""Tests for `aoi claude-init` onboarding: settings.json wiring + skill install."""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from harness_case import HarnessTestCase  # noqa: E402
from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware.commands import claude_onboarding as co  # noqa: E402


class MergeSettingsTests(unittest.TestCase):
    def test_merges_all_events_into_empty_settings(self) -> None:
        merged, added = co.merge_claude_hook_settings({})
        self.assertEqual(added, list(co.CLAUDE_HOOK_EVENTS))
        self.assertEqual(sorted(merged["hooks"].keys()), sorted(co.CLAUDE_HOOK_EVENTS))
        # Every event routes to the AOI hook command.
        for event in co.CLAUDE_HOOK_EVENTS:
            entry = merged["hooks"][event][0]
            self.assertEqual(entry["hooks"][0]["command"], co.HOOK_COMMAND)
        # PreToolUse is scoped to the sub-agent dispatch tool.
        self.assertEqual(merged["hooks"]["PreToolUse"][0]["matcher"], co.PRETOOLUSE_MATCHER)
        self.assertNotIn("matcher", merged["hooks"]["SessionStart"][0])

    def test_merge_is_idempotent(self) -> None:
        once, _ = co.merge_claude_hook_settings({})
        twice, added = co.merge_claude_hook_settings(once)
        self.assertEqual(added, [])
        self.assertEqual(once, twice)
        # No duplicate entries introduced on the second pass.
        self.assertEqual(len(twice["hooks"]["SessionStart"]), 1)

    def test_merge_preserves_unrelated_settings_and_hooks(self) -> None:
        existing = {
            "model": "claude-opus",
            "hooks": {
                "SessionStart": [
                    {"hooks": [{"type": "command", "command": "other-tool --x"}]}
                ]
            },
        }
        merged, added = co.merge_claude_hook_settings(existing)
        self.assertEqual(merged["model"], "claude-opus")
        # The pre-existing non-AOI SessionStart hook survives; AOI is appended.
        session_entries = merged["hooks"]["SessionStart"]
        self.assertEqual(len(session_entries), 2)
        self.assertEqual(session_entries[0]["hooks"][0]["command"], "other-tool --x")
        self.assertTrue(co._entry_carries_aoi_hook(session_entries[1]))
        self.assertIn("SessionStart", added)

    def test_merge_rejects_malformed_hooks_without_discarding_them(self) -> None:
        with self.assertRaises(co.ClaudeOnboardingError):
            co.merge_claude_hook_settings({"hooks": ["not-an-object"]})
        with self.assertRaises(co.ClaudeOnboardingError):
            co.merge_claude_hook_settings({"hooks": {"Stop": {"bad": True}}})
        for malformed in (None, "not-an-array", {}, [None], [{"command": 7}]):
            with self.subTest(malformed=malformed):
                with self.assertRaises(co.ClaudeOnboardingError):
                    co.merge_claude_hook_settings(
                        {"hooks": {"Stop": [{"hooks": malformed}]}}
                    )

    def test_old_absolute_aoi_handler_is_upgraded_but_spoof_is_preserved(self) -> None:
        old = '"C:\\AOI Tools\\aoi-claude-hook.exe" --hook-version 0'
        spoof = "echo aoi-claude-hook --hook-version 1"
        chained = "aoi-claude-hook --hook-version 0 && echo keep-me"
        settings = {
            "hooks": {
                "Stop": [
                    {
                        "hooks": [
                            {"command": spoof},
                            {"command": chained},
                            {"command": old},
                        ]
                    },
                ]
            }
        }
        merged, _ = co.merge_claude_hook_settings(settings)
        stop = merged["hooks"]["Stop"]
        self.assertEqual(
            stop[0]["hooks"], [{"command": spoof}, {"command": chained}]
        )
        self.assertEqual(stop[1]["hooks"][0]["command"], co.HOOK_COMMAND)


class InstallHelpersTests(unittest.TestCase):
    def test_install_hooks_round_trips_and_is_merge_safe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Path(tmp) / ".claude" / "settings.json"
            result = co.install_claude_hooks(settings, governed_agent_types="general-purpose,explorer")
            self.assertEqual(result["events_added"], list(co.CLAUDE_HOOK_EVENTS))
            on_disk = json.loads(settings.read_text(encoding="utf-8"))
            self.assertEqual(
                on_disk["env"][co.GOVERNED_AGENT_TYPES_ENV], "general-purpose,explorer"
            )
            # Second install adds nothing new.
            again = co.install_claude_hooks(settings)
            self.assertEqual(again["events_added"], [])

    def test_install_hooks_rejects_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Path(tmp) / "settings.json"
            settings.write_text("{ not json", encoding="utf-8")
            with self.assertRaises(co.ClaudeOnboardingError):
                co.install_claude_hooks(settings)

    def test_install_hooks_rejects_non_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Path(tmp) / "settings.json"
            settings.write_text("[1, 2, 3]", encoding="utf-8")
            with self.assertRaises(co.ClaudeOnboardingError):
                co.install_claude_hooks(settings)

    def test_install_hooks_is_atomic_and_skips_semantic_noop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Path(tmp) / "settings.json"
            first = co.install_claude_hooks(settings)
            self.assertTrue(first["changed"])
            with mock.patch.object(co, "_atomic_write_text") as writer:
                second = co.install_claude_hooks(settings)
            writer.assert_not_called()
            self.assertFalse(second["changed"])

    def test_preflight_rejects_bad_shape_without_mutating_and_empty_env_clears(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Path(tmp) / "settings.json"
            settings.write_text('{"hooks": [], "keep": true}\n', encoding="utf-8")
            before = settings.read_bytes()
            with self.assertRaises(co.ClaudeOnboardingError):
                co.preflight_claude_onboarding(settings)
            self.assertEqual(settings.read_bytes(), before)

            settings.write_text(
                json.dumps(
                    {
                        "env": {co.GOVERNED_AGENT_TYPES_ENV: "explorer", "KEEP": "1"}
                    }
                ),
                encoding="utf-8",
            )
            co.install_claude_hooks(settings, governed_agent_types="")
            payload = json.loads(settings.read_text(encoding="utf-8"))
            self.assertNotIn(co.GOVERNED_AGENT_TYPES_ENV, payload["env"])
            self.assertEqual(payload["env"]["KEEP"], "1")

    def test_install_skill_writes_named_user_skill_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skills_root = Path(tmp) / ".claude" / "skills"
            result = co.install_claude_user_skill(skills_root, "# skill body\n")
            skill_path = Path(result["skill_path"])
            self.assertTrue(skill_path.exists())
            self.assertEqual(skill_path.name, "SKILL.md")
            self.assertEqual(skill_path.parent.name, "aoi")
            self.assertEqual(result["scope"], "user")
            self.assertFalse(result["updated"])
            second = co.install_claude_user_skill(skills_root, "# skill body\n")
            self.assertFalse(second["changed"])
            self.assertFalse(second["updated"])

    def test_user_skill_requires_digest_to_replace_different_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skills_root = Path(tmp) / ".claude" / "skills"
            skill_path = skills_root / "aoi" / "SKILL.md"
            skill_path.parent.mkdir(parents=True)
            skill_path.write_text("# local customization\n", encoding="utf-8")
            digest = co.preflight_claude_user_skill(
                skills_root, "# local customization\n"
            )["existing_sha256"]
            with self.assertRaises(co.ClaudeOnboardingError):
                co.install_claude_user_skill(skills_root, "# packaged\n")
            result = co.install_claude_user_skill(
                skills_root,
                "# packaged\n",
                replace_sha256=digest,
            )
            self.assertTrue(result["updated"])
            self.assertEqual(skill_path.read_text(encoding="utf-8"), "# packaged\n")


class WiringTests(unittest.TestCase):
    def test_parser_wires_claude_init_handler(self) -> None:
        parser = cli_impl.build_parser()
        sub = next(
            action
            for action in parser._actions
            if action.__class__.__name__ == "_SubParsersAction"
        )
        self.assertIs(
            sub.choices["claude-init"].get_default("handler"), cli_impl.cmd_claude_init
        )

    def test_claude_init_matches_init_chief_fencing(self) -> None:
        # First install (uninitialized) needs no Chief; re-run (initialized) is fenced.
        self.assertFalse(cli_impl.command_requires_chief("claude-init", initialized=False))
        self.assertTrue(cli_impl.command_requires_chief("claude-init", initialized=True))


class FreshClaudeInitCliTests(unittest.TestCase):
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
                governed_agent_types=None,
                user_skills_root=str(skills_root),
                replace_user_skill_sha256=None,
                json=True,
            )
            with (
                mock.patch.object(
                    co, "install_claude_user_skill", side_effect=OSError("disk fault")
                ),
                mock.patch.object(sys, "stdout", new=io.StringIO()),
            ):
                with self.assertRaisesRegex(h.HarnessError, "chief-acquire"):
                    cli_impl.cmd_claude_init(args, h.get_paths(root))
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
                    "claude-resume-chief",
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
            env["AOI_CHIEF_SESSION_ID"] = "claude-resume-chief"
            env["AOI_CHIEF_EPOCH"] = str(authority["authority"]["epoch"])
            env["AOI_CHIEF_CREDENTIAL_FILE"] = authority["credential_file"]
            resumed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "aoi_orgware.cli",
                    "claude-init",
                    "--user-skills-root",
                    str(skills_root),
                    "--json",
                ],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            self.assertTrue(json.loads(resumed.stdout)["resumable"])

    def test_invalid_settings_fail_preflight_before_aoi_init(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(
                ["git", "init", "-b", "main", str(root)],
                check=True,
                capture_output=True,
                text=True,
            )
            settings = root / ".claude" / "settings.json"
            settings.parent.mkdir(parents=True)
            original = '{"hooks": ["invalid"]}\n'
            settings.write_text(original, encoding="utf-8")
            env = os.environ.copy()
            env["PYTHONPATH"] = str(HERE.parent / "src")
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "aoi_orgware.cli",
                    "claude-init",
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
            self.assertEqual(settings.read_text(encoding="utf-8"), original)

    def test_fresh_repo_uses_user_skill_scope(self) -> None:
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
                    "claude-init",
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
            self.assertTrue((root / ".claude" / "settings.json").is_file())
            self.assertTrue(
                (root / "user-skills" / "aoi" / "SKILL.md").is_file()
            )
            self.assertFalse((root / ".claude" / "skills" / "aoi").exists())


class ClaudeInitCliTests(HarnessTestCase):
    def claude_init(self, *args: str, ok: bool = True):
        return self.cli(
            "claude-init",
            "--user-skills-root",
            str(self.root / "user-skills"),
            *args,
            ok=ok,
        )

    def test_claude_init_wires_hooks_and_skill(self) -> None:
        # HarnessTestCase.setUp already ran `aoi init` + chief-acquire, so this
        # exercises the Chief-fenced re-run path on an initialized project.
        result = json.loads(self.claude_init("--json").stdout)
        self.assertTrue(result["claude_init"])
        self.assertEqual(result["hooks"]["events_added"], list(co.CLAUDE_HOOK_EVENTS))
        settings = json.loads(
            (self.root / ".claude" / "settings.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"], co.HOOK_COMMAND
        )
        skill_text = (self.root / "user-skills" / "aoi" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("Operating under AOI", skill_text)
        self.assertEqual(result["skill"]["scope"], "user")
        self.assertFalse((self.root / ".claude" / "skills" / "aoi").exists())

    def test_partial_atomic_write_failure_is_reported_and_resumable(self) -> None:
        args = argparse.Namespace(
            project_name=None,
            governed_agent_types=None,
            user_skills_root=str(self.root / "user-skills"),
            replace_user_skill_sha256=None,
            json=True,
        )
        with (
            mock.patch.object(
                co, "install_claude_user_skill", side_effect=OSError("disk fault")
            ),
            mock.patch.object(sys, "stdout", new=io.StringIO()),
        ):
            with self.assertRaisesRegex(h.HarnessError, "rerun the same command"):
                cli_impl.cmd_claude_init(args, h.get_paths(self.root))
        self.assertTrue((self.root / ".claude" / "settings.json").is_file())

        resumed = json.loads(self.claude_init("--json").stdout)
        self.assertTrue(resumed["resumable"])
        self.assertEqual(resumed["hooks"]["events_added"], [])
        self.assertTrue((self.root / "user-skills" / "aoi" / "SKILL.md").is_file())


if __name__ == "__main__":
    unittest.main()
