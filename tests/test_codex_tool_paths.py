"""Focused adversarial tests for the bounded Codex tool target parser."""

from __future__ import annotations

import sys
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import codex_tool_paths as paths  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402
from tests.harness_case import HarnessTestCase  # noqa: E402


def test_apply_patch_add_update_delete_and_rename_target_every_path() -> None:
    result = paths.parse_apply_patch_targets(
        """*** Begin Patch
*** Add File: docs/new.md
+new
*** Update File: src/old.py
*** Move to: src/renamed.py
@@
*** Delete File: obsolete.txt
*** End Patch"""
    )
    assert result.to_dict() == {
        "status": "supported",
        "targets": [
            "repo:file:docs/new.md",
            "repo:file:obsolete.txt",
            "repo:file:src/old.py",
            "repo:file:src/renamed.py",
        ],
        "reason": "covered",
    }

    official_hook_payload = paths.parse_codex_tool_targets(
        "apply_patch",
        {
            "command": "*** Begin Patch\n*** Add File: docs/hook.md\n+x\n*** End Patch"
        },
    )
    assert official_hook_payload.targets == ("repo:file:docs/hook.md",)


def test_apply_patch_rejects_unpaired_move_and_aoi_or_traversal_targets() -> None:
    for patch, reason in (
        ("*** Begin Patch\n*** Move to: x.py\n*** End Patch", paths.AMBIGUOUS_APPLY_PATCH),
        ("*** Begin Patch\n*** Add File: .aoi/tasks/state.json\n*** End Patch", paths.UNSAFE_TARGET),
        ("*** Begin Patch\n*** Delete File: ../outside.py\n*** End Patch", paths.UNSAFE_TARGET),
    ):
        result = paths.parse_apply_patch_targets(patch)
        assert result.status == "ambiguous"
        assert result.reason == reason
        assert not result.targets


def test_shell_accepts_only_one_small_literal_grammar() -> None:
    assert paths.parse_shell_targets("mkdir build/output").targets == ("repo:tree:build/output",)
    assert paths.parse_shell_targets("copy src/a.py src/b.py").targets == (
        "repo:file:src/a.py",
        "repo:file:src/b.py",
    )
    assert paths.parse_shell_targets("move old.py new.py").targets == (
        "repo:file:new.py",
        "repo:file:old.py",
    )
    for command in (
        "rm x.py",
        "Remove-Item x.py",
        "touch 'x.py'",
        "touch *.py",
        "touch $(whoami)",
        "touch a.py && touch b.py",
        "python tool.py",
        "git apply x.patch",
    ):
        result = paths.parse_shell_targets(command)
        assert result.status == "ambiguous"
        assert result.reason == paths.AMBIGUOUS_SHELL

    official_hook_payload = paths.parse_codex_tool_targets(
        "Bash", {"command": "touch build/receipt.json"}
    )
    assert official_hook_payload.targets == ("repo:file:build/receipt.json",)


def test_mcp_requires_exact_registered_name_and_declared_top_level_paths() -> None:
    registry = {
        "mcp__files__write": paths.McpToolSchema({"destination": "file"}),
    }
    result = paths.parse_codex_tool_targets(
        "mcp__files__write", {"destination": "pkg/out.py", "nested": {"path": "escape.py"}}, mcp_registry=registry
    )
    assert result.to_dict() == {
        "status": "ambiguous",
        "targets": [],
        "reason": paths.AMBIGUOUS_MCP,
    }
    unknown = paths.parse_codex_tool_targets("mcp__files__unknown", {"path": "x.py"}, mcp_registry=registry)
    assert unknown.status == "unsupported"
    malformed = paths.parse_codex_tool_targets("mcp__files__write", {"nested": {"destination": "x.py"}}, mcp_registry=registry)
    assert malformed.status == "ambiguous"
    assert malformed.reason == paths.AMBIGUOUS_MCP
    runtime = paths.parse_codex_tool_targets(
        "mcp__files__write", {"destination": "pkg/out.py"}
    )
    assert runtime.status == "unsupported"
    assert runtime.reason == paths.UNSUPPORTED_TOOL


class ClaimGateTests(HarnessTestCase):
    def _state(self, task_id: str) -> dict:
        return json.loads((self.root / ".aoi" / "tasks" / task_id / "state.json").read_text(encoding="utf-8"))

    def _claim(self, task_id: str, token: str, lock: str) -> None:
        self.cli(
            "claim", "--task", task_id, "--token", token, "--owner", "test-root",
            "--kind", "implementation", "--intent", "claim parser target",
            "--validation", "target belongs to live claim", "--expires-at", "2099-01-01T00:00:00+00:00",
            "--allow-nonexistent", "--lock", lock,
        )

    def test_exact_mapping_and_healthy_claims_cover_but_missing_target_denies(self) -> None:
        task_id = "tool-path-gate"
        self.init_task(task_id, session_id="harness-test-chief")
        self._claim(task_id, "tool-path-claim", "repo:tree:src/pkg")
        parsed = paths.parse_shell_targets("touch src/pkg/out.py")
        covered = paths.claim_gate_decision(
            h.get_paths(self.root), self._state(task_id), parsed,
            mapping_status="valid", mapping_task_id=task_id,
        )
        self.assertEqual(covered.to_dict()["decision"], "allow")
        self.assertTrue(covered.covered)
        missing = paths.claim_gate_decision(
            h.get_paths(self.root), self._state(task_id), paths.parse_shell_targets("touch src/other.py"),
            mapping_status="valid", mapping_task_id=task_id,
        )
        self.assertEqual(missing.to_dict()["decision"], "deny")
        self.assertEqual(missing.reason, paths.TARGET_MISSING)

    def test_missing_or_v2_mapping_never_claims_containment(self) -> None:
        task_id = "tool-path-uncovered"
        self.init_task(task_id, session_id="harness-test-chief")
        self._claim(task_id, "tool-path-uncovered-claim", "repo:file:src/owned.py")
        parsed = paths.parse_shell_targets("touch src/owned.py")
        missing = paths.claim_gate_decision(h.get_paths(self.root), self._state(task_id), parsed, mapping_status="unbound", mapping_task_id=None)
        self.assertEqual((missing.decision, missing.covered, missing.reason), ("allow", False, paths.MAPPING_MISSING))
        v2 = paths.claim_gate_decision(h.get_paths(self.root), self._state(task_id), parsed, mapping_status="v2", mapping_task_id=task_id)
        self.assertEqual((v2.decision, v2.covered, v2.reason), ("allow", False, paths.MAPPING_V2))
