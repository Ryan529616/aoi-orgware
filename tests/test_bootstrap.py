#!/usr/bin/env python3
"""AOI profile bootstrap and first-party skill tests."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
SKILL = REPO / "skills" / "aoi-bootstrap"
INSPECTOR = SKILL / "scripts" / "inspect_project.py"
sys.path.insert(0, str(SRC))

from aoi_orgware.config import default_config_text  # noqa: E402
from aoi_orgware.harnesslib import runtime_lock_domain  # noqa: E402


CLI_MODULE = "aoi_orgware.cli"


def init_git(root: Path) -> None:
    subprocess.run(
        ["git", "init", "-b", "main", str(root)],
        check=True,
        text=True,
        capture_output=True,
    )


class BootstrapCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.credential_temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        init_git(self.root)
        self.env = os.environ.copy()
        self.env["AOI_ROOT"] = str(self.root)
        self.env["PYTHONPATH"] = str(SRC)
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"
        self.env["AOI_CHIEF_CREDENTIAL_HOME"] = str(
            Path(self.credential_temp.name) / "credentials"
        )

    def tearDown(self) -> None:
        self.temp.cleanup()
        self.credential_temp.cleanup()

    def cli(self, *args: str, ok: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, *args],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if ok and result.returncode != 0:
            self.fail(
                f"CLI failed ({result.returncode}): {' '.join(args)}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        if not ok:
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn("Traceback", result.stderr)
        return result

    def candidate(self, name: str = "Bootstrap Test", *, state_dir: str = ".aoi") -> Path:
        candidate = self.root / f"candidate-{len(list(self.root.glob('candidate-*')))}.toml"
        text = default_config_text(name).replace('state_dir = ".aoi"', f'state_dir = "{state_dir}"')
        if state_dir != ".aoi":
            text = text.replace(
                'high_risk_paths = [".aoi/",',
                f'high_risk_paths = ["{state_dir}/",',
            )
        candidate.write_text(text, encoding="utf-8", newline="")
        return candidate

    def init_candidate(
        self, candidate: Path, *extra: str, ok: bool = True
    ) -> subprocess.CompletedProcess[str]:
        approved = hashlib.sha256(candidate.read_bytes()).hexdigest()
        return self.cli(
            "init",
            "--config",
            str(candidate),
            "--expected-config-sha256",
            approved,
            *extra,
            ok=ok,
        )

    def test_config_check_works_before_initialization(self) -> None:
        candidate = self.candidate()
        payload = json.loads(
            self.cli("config-check", "--file", str(candidate), "--json").stdout
        )
        self.assertTrue(payload["valid"])
        self.assertEqual(payload["project"], "Bootstrap Test")
        self.assertEqual(
            payload["config_sha256"], hashlib.sha256(candidate.read_bytes()).hexdigest()
        )
        self.assertFalse((self.root / "aoi.toml").exists())
        self.assertFalse((self.root / ".aoi").exists())

    def test_approved_candidate_digest_is_enforced_by_init(self) -> None:
        candidate = self.candidate()
        approved = hashlib.sha256(candidate.read_bytes()).hexdigest()
        candidate.write_bytes(candidate.read_bytes() + b"\n")
        result = self.cli(
            "init",
            "--config",
            str(candidate),
            "--expected-config-sha256",
            approved,
            ok=False,
        )
        self.assertIn("differs from the approved digest", result.stderr)
        self.assertFalse((self.root / "aoi.toml").exists())
        self.assertFalse((self.root / ".aoi").exists())

    def test_config_init_requires_approved_digest(self) -> None:
        candidate = self.candidate()

        result = self.cli("init", "--config", str(candidate), ok=False)

        self.assertIn("--config requires --expected-config-sha256", result.stderr)
        self.assertFalse((self.root / "aoi.toml").exists())
        self.assertFalse((self.root / ".aoi").exists())

    def test_config_check_ignores_broken_installed_config(self) -> None:
        candidate = self.candidate("Recovery Candidate")
        (self.root / "aoi.toml").write_text("this is not = [valid TOML", "utf-8")
        payload = json.loads(
            self.cli("config-check", "--file", str(candidate), "--json").stdout
        )
        self.assertTrue(payload["valid"])
        self.assertEqual(payload["project"], "Recovery Candidate")

    def test_invalid_candidate_fails_without_project_mutation(self) -> None:
        candidate = self.root / "invalid.toml"
        candidate.write_text(
            default_config_text("Invalid").replace(
                'schema_version = 1', 'schema_version = 1\nunknown = "nope"'
            ),
            encoding="utf-8",
        )
        result = self.init_candidate(candidate, "--json", ok=False)
        self.assertIn("unknown AOI config key", result.stderr)
        self.assertFalse((self.root / "aoi.toml").exists())
        self.assertFalse((self.root / ".aoi").exists())

    def test_default_init_rejects_config_directory_without_state_write(self) -> None:
        (self.root / "aoi.toml").mkdir()

        result = self.cli("init", "--json", ok=False)

        self.assertIn("regular non-linked file", result.stderr)
        self.assertTrue((self.root / "aoi.toml").is_dir())
        self.assertFalse((self.root / ".aoi").exists())

    def test_explicit_config_directory_is_rejected_without_state_write(self) -> None:
        candidate = self.root / "candidate-directory"
        candidate.mkdir()

        result = self.cli(
            "init",
            "--config",
            str(candidate),
            "--expected-config-sha256",
            "0" * 64,
            "--json",
            ok=False,
        )

        self.assertIn("not a regular file", result.stderr)
        self.assertFalse((self.root / "aoi.toml").exists())
        self.assertFalse((self.root / ".aoi").exists())

    def test_default_init_rejects_dangling_config_link_without_state_write(self) -> None:
        installed = self.root / "aoi.toml"
        try:
            installed.symlink_to(self.root / "missing-installed.toml")
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")

        result = self.cli("init", "--json", ok=False)

        self.assertIn("symlink or junction", result.stderr)
        self.assertTrue(installed.is_symlink())
        self.assertFalse((self.root / ".aoi").exists())

    def test_explicit_dangling_config_link_is_rejected_without_state_write(self) -> None:
        candidate = self.root / "dangling-candidate.toml"
        try:
            candidate.symlink_to(self.root / "missing-candidate.toml")
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")

        result = self.cli(
            "init",
            "--config",
            str(candidate),
            "--expected-config-sha256",
            "0" * 64,
            "--json",
            ok=False,
        )

        self.assertIn("symlink or junction", result.stderr)
        self.assertFalse((self.root / "aoi.toml").exists())
        self.assertFalse((self.root / ".aoi").exists())

    def test_governance_schema_rejects_weak_or_unsafe_profiles(self) -> None:
        base = default_config_text("Unsafe Governance")
        close_line = next(
            line for line in base.splitlines() if line.startswith("close_qualifying = ")
        )
        cases = (
            (
                "weak-close",
                base.replace(close_line, 'close_qualifying = ["engineering_inference"]'),
                "non-qualifying evidence",
            ),
            (
                "provider-tier",
                base.replace('architect = "frontier"', 'architect = "gpt-foo"'),
                "model-agnostic capability tier",
            ),
            (
                "unsafe-risk-path",
                base.replace(
                    'high_risk_paths = [".aoi/", "infra/", "security/", "deploy/"]',
                    'high_risk_paths = ["../rtl/"]',
                ),
                "safe project-relative POSIX path",
            ),
            (
                "uncovered-state",
                base.replace('state_dir = ".aoi"', 'state_dir = ".governance"'),
                "must cover state_dir",
            ),
        )
        for name, text, expected in cases:
            with self.subTest(name=name):
                candidate = self.root / f"{name}.toml"
                candidate.write_text(text, encoding="utf-8")
                result = self.cli(
                    "config-check", "--file", str(candidate), ok=False
                )
                self.assertIn(expected, result.stderr)
                self.assertFalse((self.root / "aoi.toml").exists())
                self.assertFalse((self.root / ".aoi").exists())

    def test_cross_platform_state_path_escapes_fail_without_mutation(self) -> None:
        unsafe_values = (
            "C:/outside",
            "C:outside",
            "//server/share",
            ".GIT/objects",
            "CON",
            "foo:bar",
            "foo//bar",
            "foo/.",
            "trailing.",
        )
        for index, state_dir in enumerate(unsafe_values):
            with self.subTest(state_dir=state_dir):
                candidate = self.root / f"unsafe-{index}.toml"
                candidate.write_text(
                    default_config_text("Unsafe").replace(
                        'state_dir = ".aoi"', f'state_dir = "{state_dir}"'
                    ),
                    encoding="utf-8",
                )
                result = self.init_candidate(candidate, ok=False)
                self.assertIn("safe project-relative POSIX path", result.stderr)
                self.assertFalse((self.root / "aoi.toml").exists())
                self.assertFalse((self.root / ".aoi").exists())

    def test_init_from_validated_config_preserves_bytes_and_custom_state(self) -> None:
        candidate = self.candidate(state_dir=".governance")
        expected = candidate.read_bytes()
        approved = hashlib.sha256(expected).hexdigest()
        payload = json.loads(
            self.cli(
                "init",
                "--config",
                str(candidate),
                "--expected-config-sha256",
                approved,
                "--json",
            ).stdout
        )
        self.assertTrue(payload["initialized"])
        self.assertTrue(payload["created_config"])
        self.assertEqual((self.root / "aoi.toml").read_bytes(), expected)
        self.assertTrue((self.root / ".governance" / "platform.json").is_file())
        self.assertFalse((self.root / ".aoi").exists())
        self.assertIn("/.governance/", (self.root / ".gitignore").read_text("utf-8"))
        doctor = json.loads(self.cli("doctor", "--json").stdout)
        self.assertTrue(doctor["ok"])

    def test_incompatible_existing_lock_domain_fails_before_config_write(self) -> None:
        candidate = self.candidate()
        state = self.root / ".aoi"
        state.mkdir()
        incompatible = "posix-flock-v1" if os.name == "nt" else "windows-msvcrt-v1"
        (state / "platform.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "lock_domain": incompatible,
                    "lock_backend": "test",
                    "created_at": "2026-01-01T00:00:00+00:00",
                }
            ),
            encoding="utf-8",
        )
        result = self.init_candidate(candidate, ok=False)
        self.assertIn("lock domain", result.stderr)
        self.assertFalse((self.root / "aoi.toml").exists())

    def test_managed_child_link_fails_before_config_write(self) -> None:
        candidate = self.candidate()
        state = self.root / ".aoi"
        state.mkdir()
        (state / "platform.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "lock_domain": runtime_lock_domain(),
                    "lock_backend": "test",
                    "created_at": "2026-01-01T00:00:00+00:00",
                }
            ),
            encoding="utf-8",
        )
        outside = self.root / "outside"
        outside.mkdir()
        managed_link = state / "templates"
        try:
            managed_link.symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            if os.name != "nt":
                self.skipTest(f"directory symlink creation unavailable: {exc}")
            junction = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(managed_link), str(outside)],
                text=True,
                capture_output=True,
                check=False,
            )
            if junction.returncode != 0:
                self.skipTest(
                    "directory symlink/junction creation unavailable: "
                    + (junction.stderr.strip() or junction.stdout.strip())
                )
        result = self.init_candidate(candidate, ok=False)
        self.assertIn("symlink or junction", result.stderr)
        self.assertFalse((self.root / "aoi.toml").exists())
        self.assertEqual(list(outside.iterdir()), [])

    def test_invalid_gitignore_fails_before_any_initialization_write(self) -> None:
        candidate = self.candidate()
        (self.root / ".gitignore").mkdir()
        result = self.init_candidate(candidate, ok=False)
        self.assertIn("regular non-linked file", result.stderr)
        self.assertFalse((self.root / "aoi.toml").exists())
        self.assertFalse((self.root / ".aoi").exists())

    def test_existing_different_config_is_not_overwritten(self) -> None:
        original = self.candidate("Original")
        self.init_candidate(original)
        installed = (self.root / "aoi.toml").read_bytes()
        acquired = json.loads(
            self.cli(
                "chief-acquire",
                "--session-id",
                "bootstrap-config-chief",
                "--json",
            ).stdout
        )
        self.env["AOI_CHIEF_SESSION_ID"] = "bootstrap-config-chief"
        self.env["AOI_CHIEF_EPOCH"] = str(acquired["authority"]["epoch"])
        self.env["AOI_CHIEF_CREDENTIAL_FILE"] = acquired["credential_file"]
        replacement = self.candidate("Replacement")
        result = self.init_candidate(replacement, ok=False)
        self.assertIn("different configuration", result.stderr)
        self.assertEqual((self.root / "aoi.toml").read_bytes(), installed)

    def test_concurrent_different_initializers_cannot_overwrite_each_other(self) -> None:
        first = self.candidate("Concurrent First")
        second = self.candidate("Concurrent Second")
        processes = [
            subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    CLI_MODULE,
                    "init",
                    "--config",
                    str(candidate),
                    "--expected-config-sha256",
                    hashlib.sha256(candidate.read_bytes()).hexdigest(),
                    "--json",
                ],
                cwd=self.root,
                env=self.env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for candidate in (first, second)
        ]
        results = [process.communicate(timeout=30) for process in processes]
        returncodes = [process.returncode for process in processes]
        self.assertEqual(sorted(returncodes), [0, 2], results)
        installed = (self.root / "aoi.toml").read_bytes()
        self.assertIn(installed, {first.read_bytes(), second.read_bytes()})
        self.assertTrue(json.loads(self.cli("doctor", "--json").stdout)["ok"])

    def test_init_sources_are_mutually_exclusive(self) -> None:
        candidate = self.candidate()
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                CLI_MODULE,
                "init",
                "--project-name",
                "No",
                "--config",
                str(candidate),
            ],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("not allowed with argument", result.stderr)
        self.assertFalse((self.root / "aoi.toml").exists())

    def test_linked_candidate_is_rejected_when_supported(self) -> None:
        candidate = self.candidate()
        linked = self.root / "linked.toml"
        try:
            linked.symlink_to(candidate)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        result = self.cli("config-check", "--file", str(linked), ok=False)
        self.assertIn("symlink or junction", result.stderr)


class BootstrapInspectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        init_git(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def inspect(
        self, root: Path | None = None, *extra: str, ok: bool = True
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, str(INSPECTOR), "--root", str(root or self.root), *extra],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if ok and result.returncode != 0:
            self.fail(f"inspector failed: {result.stderr}")
        return result

    def test_inventory_is_deterministic_and_read_only(self) -> None:
        (self.root / "src").mkdir()
        (self.root / "tests").mkdir()
        (self.root / "docs").mkdir()
        (self.root / "src" / "app.py").write_text("print('secret')\n", "utf-8")
        (self.root / "tests" / "test_app.py").write_text("pass\n", "utf-8")
        (self.root / "README.md").write_text("project\n", "utf-8")
        (self.root / "pyproject.toml").write_text("[project]\nname='x'\n", "utf-8")
        before = sorted(item.relative_to(self.root).as_posix() for item in self.root.rglob("*"))
        first = self.inspect().stdout
        second = self.inspect().stdout
        self.assertEqual(first, second)
        payload = json.loads(first)
        self.assertEqual(payload["schema_version"], 1)
        self.assertFalse(payload["aoi"]["state_exists"])
        self.assertFalse(payload["aoi"]["state_linked"])
        self.assertIn({"id": "python", "files": 2}, payload["inventory"]["languages"])
        self.assertIn("tests/test_app.py", payload["inventory"]["test_markers"])
        self.assertIn("pyproject.toml", payload["inventory"]["manifests"])
        after = sorted(item.relative_to(self.root).as_posix() for item in self.root.rglob("*"))
        self.assertEqual(before, after)
        self.assertNotIn("secret", first)

    def test_multi_root_and_external_risk_signals(self) -> None:
        for directory in ("frontend", "backend", "infra/terraform"):
            (self.root / directory).mkdir(parents=True)
        (self.root / "frontend" / "package.json").write_text("{}\n", "utf-8")
        (self.root / "backend" / "pyproject.toml").write_text("[project]\n", "utf-8")
        (self.root / "infra" / "terraform" / "main.tf").write_text("resource {}\n", "utf-8")
        payload = json.loads(self.inspect().stdout)
        inventory = payload["inventory"]
        self.assertTrue(inventory["monorepo_signals"])
        self.assertTrue(inventory["risk_markers"])
        self.assertTrue(inventory["external_system_markers"])

    def test_existing_custom_state_is_detected_and_excluded(self) -> None:
        (self.root / "aoi.toml").write_text(
            default_config_text("Custom State").replace(
                'state_dir = ".aoi"', 'state_dir = ".state"'
            ),
            encoding="utf-8",
        )
        state = self.root / ".state"
        state.mkdir()
        (state / "platform.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "lock_domain": "posix-flock-v1",
                }
            ),
            encoding="utf-8",
        )
        (state / "private.py").write_text("do_not_inventory = True\n", "utf-8")
        (self.root / "public.py").write_text("public = True\n", "utf-8")
        payload = json.loads(self.inspect().stdout)
        self.assertEqual(payload["aoi"]["config_status"], "parsed")
        self.assertEqual(payload["aoi"]["state_dir"], ".state")
        self.assertTrue(payload["aoi"]["state_exists"])
        self.assertEqual(payload["aoi"]["lock_domain"], "posix-flock-v1")
        self.assertIn({"id": "python", "files": 1}, payload["inventory"]["languages"])

    def test_linked_state_is_not_read_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as external_raw:
            external = Path(external_raw)
            (external / "platform.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "lock_domain": "outside-read-proof",
                    }
                ),
                encoding="utf-8",
            )
            linked = self.root / ".aoi"
            try:
                linked.symlink_to(external, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            payload_text = self.inspect().stdout
        payload = json.loads(payload_text)
        self.assertTrue(payload["aoi"]["state_linked"])
        self.assertFalse(payload["aoi"]["state_exists"])
        self.assertIsNone(payload["aoi"]["lock_domain"])
        self.assertNotIn("outside-read-proof", payload_text)

    def test_non_git_and_nested_root_fail_closed(self) -> None:
        other = self.root / "nested"
        other.mkdir()
        nested = self.inspect(other, ok=False)
        self.assertEqual(nested.returncode, 2)
        self.assertIn("exact Git worktree root", nested.stderr)
        with tempfile.TemporaryDirectory() as raw:
            non_git = self.inspect(Path(raw), ok=False)
        self.assertEqual(non_git.returncode, 2)
        self.assertIn("not a git repository", non_git.stderr.lower())

    def test_explicit_root_through_link_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as parent_raw:
            linked = Path(parent_raw) / "linked-root"
            try:
                linked.symlink_to(self.root, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlink creation unavailable: {exc}")
            result = self.inspect(linked, ok=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("may not", result.stderr)

    def test_scan_limit_is_bounded(self) -> None:
        source = self.root / "generated"
        source.mkdir()
        for index in range(110):
            (source / f"item-{index:03}.py").write_text("pass\n", "utf-8")
        payload = json.loads(self.inspect(None, "--max-files", "100").stdout)
        self.assertEqual(payload["inventory"]["scanned_files"], 100)
        self.assertTrue(payload["inventory"]["truncated"])
        self.assertTrue(payload["warnings"])

    def test_linked_entries_are_skipped_when_supported(self) -> None:
        target = self.root / "outside.txt"
        target.write_text("do not follow\n", "utf-8")
        linked = self.root / "linked.py"
        try:
            linked.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        payload = json.loads(self.inspect().stdout)
        self.assertIn("linked.py", payload["inventory"]["skipped_links"])
        self.assertIn("linked filesystem entries", " ".join(payload["warnings"]))


class BootstrapSkillPackageTests(unittest.TestCase):
    def test_skill_has_complete_metadata_and_no_scaffold_markers(self) -> None:
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("---\nname: aoi-bootstrap\n"))
        self.assertIn("inspect -> draft -> validate -> preview -> approve -> apply -> doctor", text)
        self.assertIn("explicitly approves the exact candidate SHA-256", text)
        self.assertIn("Immediately rerun `config-check`", text)
        self.assertIn("remain in review-only mode", text)
        self.assertNotIn("TODO", text)
        self.assertNotIn("Structuring This Skill", text)
        self.assertTrue((SKILL / "agents" / "openai.yaml").is_file())
        self.assertTrue((SKILL / "references" / "profile-schema.md").is_file())
        self.assertTrue((SKILL / "references" / "organization-heuristics.md").is_file())


if __name__ == "__main__":
    unittest.main()
