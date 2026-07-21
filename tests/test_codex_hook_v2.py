"""Runtime composition tests for Codex hook protocol v6 receipts and gates."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import sys
import tempfile
from contextlib import contextmanager
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import codex_adapter_contracts as contracts  # noqa: E402
from aoi_orgware import codex_hook  # noqa: E402
from aoi_orgware import codex_hook_receipts as receipts  # noqa: E402
from aoi_orgware import codex_install_provenance as provenance  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware.semantic_events import canonical_json_bytes, canonical_sha256  # noqa: E402
from tests.harness_case import HarnessTestCase  # noqa: E402


def _record_row(path: Path, root: Path) -> list[str]:
    raw = path.read_bytes()
    return [
        os.path.relpath(path, root).replace("\\", "/"),
        "sha256="
        + base64.urlsafe_b64encode(hashlib.sha256(raw).digest())
        .decode()
        .rstrip("="),
        str(len(raw)),
    ]


def _site_packages(prefix: Path) -> Path:
    if os.name == "nt":
        return prefix / "Lib" / "site-packages"
    return prefix / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"


def _scripts(prefix: Path) -> Path:
    return prefix / ("Scripts" if os.name == "nt" else "bin")


def _launcher(prefix: Path, name: str) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    return _scripts(prefix) / f"{name}{suffix}"


def _write_launcher(prefix: Path, name: str, target: str) -> None:
    launcher = _launcher(prefix, name)
    if os.name == "nt":
        launcher.write_bytes(b"recorded launcher")
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


@contextmanager
def _strict_local_v2_runtime(project: Path):
    """Yield a real schema-v2 runtime fixture backed by RECORD/direct_url."""

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary).resolve()
        prefix = root / "venv"
        site = _site_packages(prefix)
        dist = site / "aoi_orgware-1.2.3.dist-info"
        package = site / "aoi_orgware"
        scripts = _scripts(prefix)
        for path in (dist, package, scripts):
            path.mkdir(parents=True, exist_ok=True)
        (dist / "METADATA").write_text(
            "Name: aoi-orgware\nVersion: 1.2.3\n", encoding="utf-8"
        )
        package_files = (
            "__init__.py",
            "_version.py",
            "cli.py",
            "codex_hook.py",
            "codex_transport_cli.py",
        )
        for name in package_files:
            (package / name).write_text("# reviewed wheel\n", encoding="utf-8")
        for name, target in (
            ("aoi", "aoi_orgware.cli:main"),
            ("aoi-codex-hook", "aoi_orgware.codex_hook:main"),
            ("aoi-codex-bridge", "aoi_orgware.codex_transport_cli:main"),
        ):
            _write_launcher(prefix, name, target)
        store = root / "reviewed-store"
        wheel = store / "dist" / "aoi_orgware-1.2.3-py3-none-any.whl"
        wheel.parent.mkdir(parents=True)
        wheel.write_bytes(b"reviewed local wheel")
        wheel_sha = hashlib.sha256(wheel.read_bytes()).hexdigest()
        direct = dist / "direct_url.json"
        direct.write_text(
            json.dumps(
                {
                    "url": wheel.as_uri(),
                    "archive_info": {
                        "hash": "sha256=" + wheel_sha,
                        "hashes": {"sha256": wheel_sha},
                    },
                }
            ),
            encoding="utf-8",
        )
        recorded = [
            dist / "METADATA",
            *(package / name for name in package_files),
            *sorted(scripts.iterdir()),
            direct,
        ]
        record = dist / "RECORD"
        record.write_text(
            "\n".join(",".join(_record_row(path, site)) for path in recorded)
            + "\n"
            + str(record.relative_to(site)).replace("\\", "/")
            + ",,\n",
            encoding="utf-8",
        )
        metadata_sha = hashlib.sha256((dist / "METADATA").read_bytes()).hexdigest()
        hook = _launcher(prefix, "aoi-codex-hook")
        bundle = root / "local-install-bundle.json"
        bundle.write_text("{}", encoding="utf-8")
        contract = {
            "distribution_name": "aoi-orgware",
            "package_version": "1.2.3",
            "wheel": {
                "path": str(wheel),
                "name": wheel.name,
                "size_bytes": wheel.stat().st_size,
                "sha256": wheel_sha,
            },
            "interfaces": {
                "installed_metadata_sha256": metadata_sha,
                "console_entry_point": {
                    "name": "aoi",
                    "target": "aoi_orgware.cli:main",
                },
                "codex_hook_entry_point": {
                    "name": "aoi-codex-hook",
                    "target": "aoi_orgware.codex_hook:main",
                },
                "codex_bridge_entry_point": {
                    "name": "aoi-codex-bridge",
                    "target": "aoi_orgware.codex_transport_cli:main",
                },
                "hook_protocol_version": 6,
            },
            "artifact_store_root": str(store),
            "source_commit_oid": "c" * 40,
            "source_tree_oid": "d" * 40,
            "source_manifest_sha256": "e" * 64,
            "rehearsal_report_sha256": "f" * 64,
            "inventory_sha256": "0" * 64,
            "bundle_sha256": "a" * 64,
        }
        entries = [
            SimpleNamespace(
                group="console_scripts", name="aoi", value="aoi_orgware.cli:main"
            ),
            SimpleNamespace(
                group="console_scripts",
                name="aoi-codex-hook",
                value="aoi_orgware.codex_hook:main",
            ),
            SimpleNamespace(
                group="console_scripts",
                name="aoi-codex-bridge",
                value="aoi_orgware.codex_transport_cli:main",
            ),
        ]
        fake_distribution = SimpleNamespace(
            _path=dist,
            metadata={"Name": "aoi-orgware"},
            version="1.2.3",
            entry_points=entries,
        )
        modules = {
            "aoi_orgware": SimpleNamespace(
                __file__=str(package / "__init__.py"), __version__="1.2.3"
            ),
            "aoi_orgware._version": SimpleNamespace(
                __file__=str(package / "_version.py"), __version__="1.2.3"
            ),
            "aoi_orgware.cli": SimpleNamespace(__file__=str(package / "cli.py")),
            "aoi_orgware.codex_hook": SimpleNamespace(
                __file__=str(package / "codex_hook.py")
            ),
            "aoi_orgware.codex_transport_cli": SimpleNamespace(
                __file__=str(package / "codex_transport_cli.py")
            ),
        }

        def local_contract(_path: object, _expected: object):
            if hashlib.sha256(wheel.read_bytes()).hexdigest() != wheel_sha:
                raise provenance.CodexInstallProvenanceError("proof wheel changed")
            return {}, contract, bundle

        with (
            mock.patch.object(
                provenance.metadata, "distribution", lambda _: fake_distribution
            ),
            mock.patch.object(
                provenance.importlib,
                "import_module",
                side_effect=lambda name: modules[name],
            ),
            mock.patch.object(provenance.sys, "prefix", str(prefix)),
            mock.patch.object(provenance, "_local_install_contract", local_contract),
        ):
            receipt = provenance.validate_codex_local_install_provenance(
                bundle, "a" * 64, _launcher(prefix, "aoi")
            )
            target = project / provenance.CODEX_INSTALL_PROVENANCE_RECEIPT
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(canonical_json_bytes(receipt))
            yield receipt, hook, direct, record


class CodexHookV2Tests(HarnessTestCase):
    SESSION = "codex-hook-v2-session"
    TASK = "codex-hook-v2-task"

    def call(self, handler, payload: dict) -> dict:
        output = io.StringIO()
        with redirect_stdout(output):
            handler(self.root, payload)
        return json.loads(output.getvalue())

    def tool_payload(self, path: str = "src/owned.py") -> dict:
        return {
            "session_id": self.SESSION,
            "turn_id": "turn-1",
            "transcript_path": str(self.root / "rollout.jsonl"),
            "cwd": str(self.root),
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.6-terra",
            "permission_mode": "default",
            "tool_name": "apply_patch",
            "tool_input": {
                "command": (
                    "*** Begin Patch\n"
                    f"*** Add File: {path}\n"
                    "+content\n"
                    "*** End Patch"
                )
            },
            "tool_use_id": "tool-use-1",
        }

    def init_claimed_task(self) -> None:
        self.init_task(self.TASK, session_id=self.SESSION)
        self.cli(
            "claim",
            "--task",
            self.TASK,
            "--token",
            "codex-hook-v2-claim",
            "--owner",
            "test-root",
            "--kind",
            "implementation",
            "--intent",
            "exercise Codex cooperative claim gate",
            "--validation",
            "exact hook target is covered by the live claim",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            "--allow-nonexistent",
            "--lock",
            "repo:tree:src",
        )

    def test_pre_and_post_pair_on_stable_tool_identity_despite_optional_agent_drift(self) -> None:
        self.init_claimed_task()
        payload = self.tool_payload()
        payload["agent_id"] = "agent-before"
        payload["event_id"] = "event-before"
        self.assertEqual(self.call(codex_hook.pre_tool_use, payload), {"continue": True})

        identity = codex_hook._tool_event_identity(payload)
        self.assertEqual(
            identity,
            {
                "session_id": self.SESSION,
                "turn_id": "turn-1",
                "tool_use_id": "tool-use-1",
            },
        )
        pre = receipts.load_codex_hook_receipt_by_identity(
            h.get_paths(self.root),
            receipt_type=contracts.CODEX_PRETOOL_CLAIM_DECISION_V1,
            event_identity=identity,
        )
        self.assertEqual(pre["claim_coverage"], "covered")
        self.assertEqual(pre["decision"], "allow")
        self.assertEqual(pre["targets"], ["repo:file:src/owned.py"])
        self.assertEqual(pre["session_mapping"]["status"], "mapped")
        self.assertEqual(pre["provider_verification"], "unavailable")

        post_payload = {
            **payload,
            "hook_event_name": "PostToolUse",
            "agent_id": "agent-after",
            "event_id": "event-after",
            "tool_response": {"content": "applied", "exit_code": 0},
        }
        self.assertEqual(
            self.call(codex_hook.post_tool_use, post_payload), {"continue": True}
        )
        post = receipts.load_codex_hook_receipt_by_identity(
            h.get_paths(self.root),
            receipt_type=contracts.CODEX_POSTTOOL_MUTATION_OBSERVATION_V1,
            event_identity=identity,
        )
        self.assertEqual(post["pre_receipt_sha256"], pre["receipt_sha256"])
        self.assertTrue(post["tool_completion_observed"])
        self.assertEqual(post["mutation_effect_verified"], {"status": "unavailable"})
        self.assertEqual(
            receipts.inspect_codex_hook_receipt_store(h.get_paths(self.root))[
                "receipt_type_counts"
            ],
            {
                contracts.CODEX_POSTTOOL_MUTATION_OBSERVATION_V1: 1,
                contracts.CODEX_PRETOOL_CLAIM_DECISION_V1: 1,
            },
        )

    @mock.patch.object(receipts, "MAX_CODEX_HOOK_RECEIPT_ENTRIES", 1)
    def test_pretool_store_full_is_fixed_nested_deny(self) -> None:
        self.init_claimed_task()
        first = self.tool_payload("docs/unclaimed-first.md")
        first["tool_use_id"] = "tool-use-first"
        first_deny = self.call(codex_hook.pre_tool_use, first)
        self.assertEqual(first_deny["hookSpecificOutput"]["permissionDecision"], "deny")

        second = self.tool_payload("docs/unclaimed-second.md")
        second["tool_use_id"] = "tool-use-second"
        full_deny = self.call(codex_hook.pre_tool_use, second)
        self.assertEqual(
            full_deny,
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": codex_hook.RECEIPT_STORE_DENY_MESSAGE,
                }
            },
        )

    def test_pretool_internal_faults_are_fixed_nested_denials(self) -> None:
        self.init_claimed_task()
        payload = self.tool_payload()
        expected = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": codex_hook.PRETOOL_FAIL_CLOSED_DENY_MESSAGE,
            }
        }

        def fail(*_args, **_kwargs):
            raise RuntimeError("private internal detail")

        from aoi_orgware import codex_tool_paths

        fault_points = (
            ("identity", mock.patch.object(codex_hook, "_tool_event_identity", fail)),
            (
                "schema",
                mock.patch.object(
                    contracts, "seal_codex_pretool_claim_decision_receipt", fail
                ),
            ),
            (
                "parser",
                mock.patch.object(codex_tool_paths, "parse_codex_tool_targets", fail),
            ),
            (
                "claim_target",
                mock.patch.object(codex_tool_paths, "claim_gate_decision", fail),
            ),
            ("store", mock.patch.object(receipts, "store_codex_hook_receipt", fail)),
        )
        for label, fault in fault_points:
            with self.subTest(fault=label), fault:
                output = self.call(codex_hook.pre_tool_use, payload)
                self.assertEqual(output, expected)
                self.assertNotIn("private", json.dumps(output))

    def test_main_pretool_dispatch_fault_is_not_reclassified_as_allow(self) -> None:
        argv = [
            str(_launcher(self.root, "aoi-codex-hook")),
            "--hook-version",
            "6",
            "--project-root",
            str(self.root),
            "--provenance-sha256",
            "a" * 64,
        ]
        output = io.StringIO()
        with mock.patch.object(sys, "argv", argv), mock.patch(
            "aoi_orgware.codex_install_provenance.verify_runtime_hook_provenance",
            return_value={},
        ), mock.patch.object(codex_hook, "read_input", return_value=self.tool_payload()), mock.patch.object(
            codex_hook, "pre_tool_use", side_effect=RuntimeError("private dispatch detail")
        ), redirect_stdout(output):
            self.assertEqual(codex_hook.main(), 0)
        self.assertEqual(
            json.loads(output.getvalue()),
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": codex_hook.PRETOOL_FAIL_CLOSED_DENY_MESSAGE,
                }
            },
        )

    def test_missing_claim_and_direct_aoi_mutation_are_denied_with_receipts(self) -> None:
        self.init_claimed_task()
        missing = self.tool_payload("docs/unclaimed.md")
        denied = self.call(codex_hook.pre_tool_use, missing)
        specific = denied["hookSpecificOutput"]
        self.assertEqual(specific["hookEventName"], "PreToolUse")
        self.assertEqual(specific["permissionDecision"], "deny")
        self.assertIn("target_missing", specific["permissionDecisionReason"])

        aoi_payload = self.tool_payload(".aoi/tasks/forged.json")
        aoi_payload["session_id"] = "unbound-session"
        aoi_payload["tool_use_id"] = "tool-use-aoi"
        denied_aoi = self.call(codex_hook.pre_tool_use, aoi_payload)
        self.assertEqual(
            denied_aoi["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.assertIn(
            "direct_aoi_state_mutation_denied",
            denied_aoi["hookSpecificOutput"]["permissionDecisionReason"],
        )
        receipt = receipts.load_codex_hook_receipt_by_identity(
            h.get_paths(self.root),
            receipt_type=contracts.CODEX_PRETOOL_CLAIM_DECISION_V1,
            event_identity=codex_hook._tool_event_identity(aoi_payload),
        )
        self.assertEqual(receipt["session_mapping"]["status"], "missing")
        self.assertEqual(receipt["claim_coverage"], "unclaimed")

    def test_unsupported_tool_is_observed_but_never_claimed_contained(self) -> None:
        self.init_claimed_task()
        payload = self.tool_payload()
        payload["tool_name"] = "view_image"
        payload["tool_input"] = {"path": "src/owned.py"}
        self.assertEqual(self.call(codex_hook.pre_tool_use, payload), {"continue": True})
        receipt = receipts.load_codex_hook_receipt_by_identity(
            h.get_paths(self.root),
            receipt_type=contracts.CODEX_PRETOOL_CLAIM_DECISION_V1,
            event_identity=codex_hook._tool_event_identity(payload),
        )
        self.assertEqual(receipt["targets"], [])
        self.assertEqual(receipt["claim_coverage"], "uncovered")
        self.assertEqual(receipt["decision"], "allow")

    def test_subagent_stop_is_honest_and_exact_replay_is_idempotent(self) -> None:
        payload = {
            "session_id": "child-session",
            "turn_id": "child-turn",
            "transcript_path": str(self.root / "parent.jsonl"),
            "agent_transcript_path": str(self.root / "child.jsonl"),
            "cwd": str(self.root),
            "hook_event_name": "SubagentStop",
            "model": "gpt-5.6-terra",
            "permission_mode": "default",
            "stop_hook_active": False,
            "agent_id": "child-agent",
            "agent_type": "reviewer",
            "last_assistant_message": "bounded conclusion",
        }
        self.assertEqual(self.call(codex_hook.subagent_stop, payload), {"continue": True})
        self.assertEqual(self.call(codex_hook.subagent_stop, payload), {"continue": True})
        receipt = receipts.load_codex_hook_receipt_by_identity(
            h.get_paths(self.root),
            receipt_type=contracts.CODEX_SUBAGENT_STOP_V1,
            event_identity=codex_hook._stop_event_identity(payload),
        )
        self.assertEqual(
            receipt["transcript_path_observation"],
            {"status": "observed", "value": str(self.root / "child.jsonl")},
        )
        self.assertEqual(receipt["start_correlation"]["status"], "missing")
        self.assertFalse(receipt["no_material_work_verified"])
        self.assertEqual(
            receipts.inspect_codex_hook_receipt_store(h.get_paths(self.root))[
                "entry_count"
            ],
            1,
        )

    def test_subagent_stop_validates_agent_identity_before_receipt_work(self) -> None:
        payload = {
            "session_id": "child-session",
            "turn_id": "child-turn",
            "hook_event_name": "SubagentStop",
            "agent_id": "/root/reviewer",
        }
        self.assertEqual(
            codex_hook._stop_event_identity(payload)["agent_id"],
            "/root/reviewer",
        )
        payload["agent_id"] = "/" + "a" * 511
        self.assertEqual(
            codex_hook._stop_event_identity(payload)["agent_id"],
            payload["agent_id"],
        )
        for agent_id in (
            "agent identity",
            "agent+identity",
            "agent\nidentity",
            "代理者",
            "/" + "a" * 512,
        ):
            payload["agent_id"] = agent_id
            with self.subTest(agent_id=agent_id), mock.patch.object(
                receipts, "store_codex_hook_receipt"
            ) as store:
                with pytest.raises(ValueError, match="1-512 ASCII"):
                    codex_hook.subagent_stop(self.root, payload)
                store.assert_not_called()

    def test_subagent_stop_replays_existing_legacy_identity_receipt(self) -> None:
        payload = {
            "session_id": "child-session",
            "turn_id": "child-turn",
            "hook_event_name": "SubagentStop",
            "stop_hook_active": False,
            "agent_id": "legacy reviewer",
        }
        missing = lambda: {"status": "missing", "value": None}
        legacy_base = {
            "receipt_type": contracts.CODEX_SUBAGENT_STOP_V1,
            "event_identity": codex_hook._stop_event_identity(
                payload, strict_agent_id=False
            ),
            "observed_at": "2026-07-19T01:02:03Z",
            "transcript_path_observation": missing(),
            "last_assistant_message": {
                "sha256": missing(),
                "size_bytes": missing(),
                "presence": {"status": "observed", "value": "absent"},
            },
            "model_observation": missing(),
            "permission_mode_observation": missing(),
            "start_correlation": {
                "status": "missing",
                "start_receipt_sha256": missing(),
            },
            "no_material_work_verified": False,
        }
        legacy = {
            **legacy_base,
            "receipt_sha256": canonical_sha256(legacy_base),
        }
        paths = h.get_paths(self.root)
        directory = receipts.codex_hook_receipts_dir(paths)
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)
        path = receipts.codex_hook_receipt_path(paths, legacy)
        h.atomic_create_bytes(path, canonical_json_bytes(legacy))
        before = path.read_bytes()

        self.assertEqual(self.call(codex_hook.subagent_stop, payload), {"continue": True})
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(receipts.inspect_codex_hook_receipt_store(paths)["entry_count"], 1)

    def test_main_verifies_provenance_before_reading_stdin_and_fails_open(self) -> None:
        argv = [
            str(_launcher(self.root, "aoi-codex-hook")),
            "--hook-version",
            "6",
            "--project-root",
            str(self.root),
            "--provenance-sha256",
            "a" * 64,
        ]
        order: list[str] = []

        def verified(*_args) -> dict:
            order.append("verify")
            return {}

        def read() -> dict:
            order.append("read")
            return {"hook_event_name": "unknown"}

        output = io.StringIO()
        with mock.patch.object(sys, "argv", argv), mock.patch(
            "aoi_orgware.codex_install_provenance.verify_runtime_hook_provenance",
            side_effect=verified,
        ), mock.patch.object(codex_hook, "read_input", side_effect=read), redirect_stdout(
            output
        ):
            self.assertEqual(codex_hook.main(), 0)
        self.assertEqual(order, ["verify", "read"])
        self.assertEqual(json.loads(output.getvalue()), {"continue": True})

        output = io.StringIO()
        with mock.patch.object(sys, "argv", argv), mock.patch(
            "aoi_orgware.codex_install_provenance.verify_runtime_hook_provenance",
            side_effect=ValueError("tampered provenance"),
        ), mock.patch.object(codex_hook, "read_input") as read_mock, redirect_stdout(
            output
        ):
            self.assertEqual(codex_hook.main(), 0)
        read_mock.assert_not_called()
        self.assertEqual(json.loads(output.getvalue()), {"continue": True})

    def test_main_accepts_strict_local_v2_and_fails_open_on_mapping_drift(self) -> None:
        """The hook consumes schema-v2 receipts through the real runtime verifier."""

        with _strict_local_v2_runtime(self.root) as (receipt, hook, direct, record):
            self.assertEqual(receipt["schema_version"], 2)
            self.assertEqual(
                provenance.validate_codex_install_provenance_receipt(receipt), receipt
            )
            argv = [
                str(hook),
                "--hook-version",
                "6",
                "--project-root",
                str(self.root),
                "--provenance-sha256",
                receipt["provenance_receipt_sha256"],
            ]
            output = io.StringIO()
            with mock.patch.object(sys, "argv", argv), mock.patch.object(
                codex_hook, "read_input", return_value={"hook_event_name": "unknown"}
            ) as read_mock, redirect_stdout(output):
                self.assertEqual(codex_hook.main(), 0)
            read_mock.assert_called_once()
            self.assertEqual(json.loads(output.getvalue()), {"continue": True})

            target = self.root / provenance.CODEX_INSTALL_PROVENANCE_RECEIPT
            direct_original = direct.read_bytes()
            record_original = record.read_bytes()
            direct.write_text(
                json.dumps(json.loads(direct_original), indent=2), encoding="utf-8"
            )
            site = record.parent.parent
            direct_record_path = os.path.relpath(direct, site).replace("\\", "/")
            record_lines = record.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(record_lines):
                if line.split(",", 1)[0] == direct_record_path:
                    record_lines[index] = ",".join(_record_row(direct, site))
                    break
            else:
                self.fail("direct_url.json is absent from the fixture RECORD")
            record.write_text("\n".join(record_lines) + "\n", encoding="utf-8")
            mapping_drift = json.loads(json.dumps(receipt))
            mapping_drift["installed_record"]["sha256"] = hashlib.sha256(
                record.read_bytes()
            ).hexdigest()
            mapping_drift["provenance_receipt_sha256"] = canonical_sha256(
                {
                    key: value
                    for key, value in mapping_drift.items()
                    if key != "provenance_receipt_sha256"
                }
            )
            target.write_bytes(canonical_json_bytes(mapping_drift))
            drift_argv = [
                *argv[:-1],
                mapping_drift["provenance_receipt_sha256"],
            ]
            with self.assertRaisesRegex(
                provenance.CodexInstallProvenanceError,
                "current local installed wheel mapping differs from provenance receipt",
            ):
                provenance.verify_runtime_hook_provenance(
                    self.root, mapping_drift["provenance_receipt_sha256"], hook
                )
            output = io.StringIO()
            with mock.patch.object(sys, "argv", drift_argv), mock.patch.object(
                codex_hook, "read_input"
            ) as read_mock, redirect_stdout(output):
                self.assertEqual(codex_hook.main(), 0)
            read_mock.assert_not_called()
            self.assertEqual(json.loads(output.getvalue()), {"continue": True})

            direct.write_bytes(direct_original)
            record.write_bytes(record_original)
            target.write_bytes(canonical_json_bytes(receipt))
            record.write_text("tampered\\n", encoding="utf-8")
            with self.assertRaises(provenance.CodexInstallProvenanceError):
                provenance.verify_runtime_hook_provenance(
                    self.root, receipt["provenance_receipt_sha256"], hook
                )
            output = io.StringIO()
            with mock.patch.object(sys, "argv", argv), mock.patch.object(
                codex_hook, "read_input"
            ) as read_mock, redirect_stdout(output):
                self.assertEqual(codex_hook.main(), 0)
            read_mock.assert_not_called()
            self.assertEqual(json.loads(output.getvalue()), {"continue": True})


def test_read_input_rejects_duplicate_authority_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = b'{"session_id":"one","session_id":"two"}'
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(payload)))
    with pytest.raises(ValueError, match="duplicate"):
        codex_hook.read_input()
