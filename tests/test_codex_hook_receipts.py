#!/usr/bin/env python3
"""Isolated SessionStart startup-receipt integration tests."""

from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import session_receipts as receipts  # noqa: E402
from tests.harness_case import HarnessTestCase  # noqa: E402


class CodexSessionStartReceiptTests(HarnessTestCase):
    def startup_payload(self, **overrides: object) -> dict[str, object]:
        payload: dict[str, object] = {
            "hook_event_name": "SessionStart",
            "session_id": "codex-startup-receipt-1",
            "source": "startup",
            "cwd": str(self.root),
            # These are official hook-input context only.  They must never be
            # elevated into a startup receipt runtime claim.
            "model": "untrusted-hook-model",
            "permission_mode": "workspace-write",
            "provider": "untrusted-hook-provider",
            "profile": "untrusted-hook-profile",
            "sandbox": "untrusted-hook-sandbox",
        }
        payload.update(overrides)
        return payload

    def context(self, result: dict[str, object]) -> str:
        return str(result["hookSpecificOutput"]["additionalContext"])  # type: ignore[index]

    def test_exact_startup_persists_current_binding_without_runtime_overclaim(self) -> None:
        result = self.hook(self.startup_payload())
        stored = receipts.load_startup_receipt(
            h.get_paths(self.root), "codex-startup-receipt-1"
        )
        self.assertEqual(
            set(stored),
            {
                "schema_version",
                "hook_protocol_version",
                "session_id",
                "source",
                "observed_at",
                "cwd",
                "project_root",
                "aoi_config_sha256",
                "startup_receipt_sha256",
            },
        )
        self.assertEqual(stored["schema_version"], 1)
        self.assertEqual(stored["hook_protocol_version"], 6)
        self.assertEqual(stored["session_id"], "codex-startup-receipt-1")
        self.assertEqual(stored["source"], "startup")
        self.assertEqual(stored["cwd"], str(self.root))
        self.assertEqual(stored["project_root"], str(self.root))
        self.assertEqual(stored["aoi_config_sha256"], h.get_paths(self.root).project.sha256)
        self.assertIsNotNone(dt.datetime.fromisoformat(stored["observed_at"]))
        for field in ("model", "permission_mode", "provider", "profile", "sandbox"):
            self.assertNotIn(field, stored)
        self.assertIn("No unambiguous task mapping", self.context(result))
        self.assertNotIn("Fresh-session registration is unavailable", self.context(result))

    def test_only_exact_startup_source_can_create_a_receipt_store(self) -> None:
        sources: list[object] = ["resume", "clear", "compact", None, 6, {"source": "startup"}]
        for source in sources:
            with self.subTest(source=source):
                self.hook(self.startup_payload(source=source))
                self.assertFalse(receipts.startup_receipts_dir(h.get_paths(self.root)).exists())
        self.hook(
            {
                "hook_event_name": "SessionStart",
                "session_id": "codex-missing-source",
                "cwd": str(self.root),
            }
        )
        self.assertFalse(receipts.startup_receipts_dir(h.get_paths(self.root)).exists())

    def test_invalid_startup_inputs_warn_without_losing_existing_context(self) -> None:
        missing_session = self.startup_payload()
        del missing_session["session_id"]
        missing_cwd = self.startup_payload()
        del missing_cwd["cwd"]
        invalid_payloads = (
            missing_session,
            missing_cwd,
            self.startup_payload(session_id=None),
            self.startup_payload(session_id=17),
            self.startup_payload(cwd=None),
            self.startup_payload(cwd=str(self.root / "does-not-exist")),
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                result = self.hook(payload)
                context = self.context(result)
                self.assertIn("AOI is active", context)
                self.assertIn(
                    "Fresh-session registration is unavailable until a valid startup.",
                    context,
                )
                self.assertFalse(receipts.startup_receipts_dir(h.get_paths(self.root)).exists())

    def test_bound_task_context_survives_startup_receipt_failure(self) -> None:
        self.init_task("receipt-hook-bound", session_id="receipt-bound-session")
        result = self.hook(
            self.startup_payload(
                session_id="receipt-bound-session",
                cwd=str(self.root / "missing-startup-cwd"),
            )
        )
        context = self.context(result)
        self.assertIn("This session is bound to task receipt-hook-bound", context)
        self.assertIn(
            "Fresh-session registration is unavailable until a valid startup.", context
        )
        self.assertFalse(receipts.startup_receipts_dir(h.get_paths(self.root)).exists())

    def test_non_string_session_id_cannot_select_string_bound_task(self) -> None:
        self.init_task("receipt-hook-string-17", session_id="17")
        result = self.hook(self.startup_payload(session_id=17))
        context = self.context(result)
        self.assertIn("No unambiguous task mapping exists", context)
        self.assertNotIn("This session is bound to task receipt-hook-string-17", context)
        self.assertIn(
            "Fresh-session registration is unavailable until a valid startup.", context
        )
        self.assertFalse(receipts.startup_receipts_dir(h.get_paths(self.root)).exists())

        prompt = self.hook(
            {"hook_event_name": "UserPromptSubmit", "session_id": 17}
        )
        prompt_context = self.context(prompt)
        self.assertIn("not bound to a valid harness task", prompt_context)
        self.assertNotIn("Continue task receipt-hook-string-17", prompt_context)

        stopped = self.hook(
            {
                "hook_event_name": "Stop",
                "session_id": 17,
                "stop_hook_active": False,
            }
        )
        self.assertTrue(stopped["continue"])

    def test_startup_replay_retains_original_receipt_identity(self) -> None:
        payload = self.startup_payload()
        self.hook(payload)
        first = receipts.load_startup_receipt(
            h.get_paths(self.root), "codex-startup-receipt-1"
        )
        self.hook(payload)
        second = receipts.load_startup_receipt(
            h.get_paths(self.root), "codex-startup-receipt-1"
        )
        self.assertEqual(second, first)
        directory = receipts.startup_receipts_dir(h.get_paths(self.root))
        self.assertEqual(len(list(directory.iterdir())), 1)

    def test_corrupt_prior_receipt_warns_but_preserves_hook_context(self) -> None:
        payload = self.startup_payload()
        self.hook(payload)
        path = receipts.startup_receipt_path(
            h.get_paths(self.root), "codex-startup-receipt-1"
        )
        path.write_bytes(b"{corrupt-startup-receipt")

        result = self.hook(payload)
        context = self.context(result)
        self.assertIn("No unambiguous task mapping", context)
        self.assertIn(
            "Fresh-session registration is unavailable until a valid startup.", context
        )
        self.assertIn("hookSpecificOutput", result)


if __name__ == "__main__":
    import unittest

    unittest.main()
