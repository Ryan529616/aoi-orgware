#!/usr/bin/env python3
"""Tests for `aoi claude-init` onboarding: settings.json wiring + skill install."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from harness_case import HarnessTestCase  # noqa: E402
from aoi_orgware import cli as cli_impl  # noqa: E402
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


class InstallHelpersTests(unittest.TestCase):
    def test_install_hooks_round_trips_and_is_merge_safe(self) -> None:
        import tempfile

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
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            settings = Path(tmp) / "settings.json"
            settings.write_text("{ not json", encoding="utf-8")
            with self.assertRaises(co.ClaudeOnboardingError):
                co.install_claude_hooks(settings)

    def test_install_hooks_rejects_non_object(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            settings = Path(tmp) / "settings.json"
            settings.write_text("[1, 2, 3]", encoding="utf-8")
            with self.assertRaises(co.ClaudeOnboardingError):
                co.install_claude_hooks(settings)

    def test_install_skill_writes_named_skill(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            result = co.install_claude_skill(Path(tmp) / "skills", "# skill body\n")
            skill_path = Path(result["skill_path"])
            self.assertTrue(skill_path.exists())
            self.assertEqual(skill_path.name, "SKILL.md")
            self.assertEqual(skill_path.parent.name, "aoi")
            self.assertFalse(result["updated"])
            second = co.install_claude_skill(Path(tmp) / "skills", "# v2\n")
            self.assertTrue(second["updated"])


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


class ClaudeInitCliTests(HarnessTestCase):
    def test_claude_init_wires_hooks_and_skill(self) -> None:
        # HarnessTestCase.setUp already ran `aoi init` + chief-acquire, so this
        # exercises the Chief-fenced re-run path on an initialized project.
        result = json.loads(self.cli("claude-init", "--json").stdout)
        self.assertTrue(result["claude_init"])
        self.assertEqual(result["hooks"]["events_added"], list(co.CLAUDE_HOOK_EVENTS))
        settings = json.loads(
            (self.root / ".claude" / "settings.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"], co.HOOK_COMMAND
        )
        skill_text = (self.root / ".claude" / "skills" / "aoi" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("Operating under AOI", skill_text)


if __name__ == "__main__":
    unittest.main()
