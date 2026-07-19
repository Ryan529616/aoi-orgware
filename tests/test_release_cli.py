"""Focused CLI contracts for release observation and promotion."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(SRC))

from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import release_artifacts  # noqa: E402
from aoi_orgware import release_runtime  # noqa: E402
from aoi_orgware import semantic_events as semantic  # noqa: E402
from aoi_orgware import semantic_store as store  # noqa: E402
from aoi_orgware.config import default_config_text  # noqa: E402
from tests.test_release_artifacts import (  # noqa: E402
    _dependency_pair,
    _builder_receipt,
    _git,
    _manifest as artifact_manifest,
    _sha,
    _write,
)
from tests.test_release_runtime import (  # noqa: E402
    _manifest as promotion_manifest,
    _observation as promotion_observation,
    _receipt as promotion_receipt,
)


CLI_MODULE = "aoi_orgware.cli"
TASK = "release-cli-task"


class ReleaseCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.credentials = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.credential_home = Path(self.credentials.name) / "credentials"
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        (self.root / "aoi.toml").write_text(
            default_config_text("Release CLI"), encoding="utf-8"
        )
        self.paths = h.get_paths(self.root)
        with h.state_lock(self.paths, create_layout=True):
            h.task_dir(self.paths, TASK).mkdir(parents=True)
            store.initialize_semantic_task(
                self.paths,
                {"task_id": TASK, "stage": 0},
                command_id="release-cli-genesis",
                recorded_at=self.iso(self.now - timedelta(minutes=1)),
                authority_ref="test",
            )
            self.chief, self.credential_path = h.acquire_chief_authority(
                self.paths,
                session_id="release-cli-chief",
                ttl_seconds=3600,
                credential_home=self.credential_home,
                now=self.now,
            )
        self.env = os.environ.copy()
        self.env.update(
            {
                "AOI_ROOT": str(self.root),
                "PYTHONPATH": str(SRC),
                "PYTHONDONTWRITEBYTECODE": "1",
                "AOI_CHIEF_SESSION_ID": self.chief["session_id"],
                "AOI_CHIEF_EPOCH": str(self.chief["epoch"]),
                "AOI_CHIEF_CREDENTIAL_FILE": str(self.credential_path),
            }
        )

    def tearDown(self) -> None:
        self.credentials.cleanup()
        self.temp.cleanup()

    @staticmethod
    def iso(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")

    def cli(
        self, *arguments: str, env: dict[str, str] | None = None, ok: bool = True
    ) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, *arguments],
            cwd=self.root,
            env=env or self.env,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if ok and result.returncode != 0:
            self.fail(
                f"CLI failed ({result.returncode}): {' '.join(arguments)}\\n"
                f"stdout={result.stdout.decode(errors='replace')}\\n"
                f"stderr={result.stderr.decode(errors='replace')}"
            )
        if not ok:
            self.assertEqual(result.returncode, 2, result.stderr.decode())
            self.assertNotIn(b"Traceback", result.stderr)
        return result

    def no_chief_env(self) -> dict[str, str]:
        environment = self.env.copy()
        for name in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
            "AOI_CHIEF_TOKEN",
        ):
            environment.pop(name, None)
        return environment

    def write_canonical(self, name: str, value: object) -> Path:
        path = self.root / name
        path.write_bytes(semantic.canonical_json_bytes(value))
        return path

    def observation_request(self) -> dict[str, object]:
        artifacts = self.root / "artifacts"
        rebuilt = self.root / "rebuilt"
        worktree = self.root / "worktree"
        artifacts.mkdir()
        rebuilt.mkdir()
        (worktree / "src/aoi_orgware").mkdir(parents=True)
        (worktree / "src/aoi_orgware/_version.py").write_text(
            '__version__ = "0.4.0"\n', encoding="utf-8"
        )
        _git(worktree, "init")
        _git(worktree, "config", "user.email", "test@example.invalid")
        _git(worktree, "config", "user.name", "Release CLI")
        _git(worktree, "add", ".")
        _git(worktree, "commit", "-m", "release")
        _git(worktree, "tag", "v0.4.0")
        payload = b"wheel bytes\\n"
        artifact = {
            "name": "dist/aoi_orgware-0.4.0.whl",
            "size_bytes": len(payload),
            "sha256": _sha(payload),
        }
        _write(artifacts, artifact["name"], payload)
        _write(rebuilt, artifact["name"], payload)
        _write(artifacts, "meta/sbom.json", b"sbom")
        _write(artifacts, "meta/attestation.json", b"attestation")
        dependency, dependency_files = _dependency_pair(artifacts)
        manifest = artifact_manifest(
            artifact=artifact,
            commit=_git(worktree, "rev-parse", "HEAD"),
            tree=_git(worktree, "rev-parse", "HEAD^{tree}"),
            dependencies=[dependency],
        )
        evidence = {
            "producer_results": {
                "build-linux": _write(artifacts, "evidence/producer.json", b"producer")
            },
            "builder_environment": _write(
                artifacts, "evidence/builder.json", _builder_receipt()
            ),
            "matrix": {
                "linux/unit": {
                    "check_contract": _write(artifacts, "evidence/contract.json", b"contract"),
                    "receipt": _write(artifacts, "evidence/linux.json", b"linux"),
                },
                "windows/unit": {
                    "check_contract": _write(artifacts, "evidence/contract-win.json", b"contract"),
                    "receipt": _write(artifacts, "evidence/windows.json", b"windows"),
                },
            },
            "installed_metadata": _write(artifacts, "evidence/installed.json", b"metadata"),
            "reviewed_exception_receipt": None,
        }
        return {
            "schema_version": 1,
            "manifest": manifest,
            "worktree": str(worktree),
            "artifact_root": str(artifacts),
            "rebuild_root": str(rebuilt),
            "evidence_files": evidence,
            "dependency_files": dependency_files,
        }

    def test_manifest_observation_stdout_is_exact_canonical_without_newline(self) -> None:
        request = self.observation_request()
        path = self.write_canonical("request.json", request)

        result = self.cli("release-manifest-observe", "--request-file", str(path))
        expected = semantic.canonical_json_bytes(
            release_artifacts.observe_release_artifacts(request)
        )
        self.assertEqual(result.stdout, expected)
        self.assertFalse(result.stdout.endswith(b"\n"))
        self.assertEqual(result.stderr, b"")

    def test_manifest_observation_rejects_noncanonical_and_duplicate_json(self) -> None:
        request = self.observation_request()
        pretty = self.root / "pretty-request.json"
        pretty.write_text(json.dumps(request, indent=2), encoding="utf-8")
        noncanonical = self.cli(
            "release-manifest-observe", "--request-file", str(pretty), ok=False
        )
        self.assertIn(b"canonical JSON", noncanonical.stderr)

        raw = semantic.canonical_json_bytes(request)
        duplicate = self.root / "duplicate-request.json"
        duplicate.write_bytes(raw[:-1] + b',"schema_version":1}')
        rejected = self.cli(
            "release-manifest-observe", "--request-file", str(duplicate), ok=False
        )
        self.assertIn(b"duplicate JSON key", rejected.stderr)

    def test_promotion_requires_chief_exact_inputs_and_current_semantic_head(self) -> None:
        manifest = promotion_manifest()
        receipt = promotion_receipt(
            manifest,
            promotion_id="release-cli-promotion",
            registry_observed_at=self.iso(self.now - timedelta(seconds=20)),
            installed_observed_at=self.iso(self.now - timedelta(seconds=10)),
        )
        observation_result_path = self.write_canonical(
            "observation-result.json",
            {
                "manifest": manifest,
                "observation_receipt": promotion_observation(manifest),
            },
        )
        receipt_path = self.write_canonical("receipt.json", receipt)
        head = store.semantic_head(self.paths, TASK)["event_sha256"]
        common = (
            "release-promote",
            "--task", TASK,
            "--observation-result-file", str(observation_result_path),
            "--promotion-receipt-file", str(receipt_path),
            "--command-id", "release-cli-promote",
            "--recorded-at", self.iso(self.now),
            "--expected-semantic-head-sha256",
        )

        missing_chief = self.cli(*common, head, env=self.no_chief_env(), ok=False)
        self.assertIn(b"Chief", missing_chief.stderr)
        self.assertEqual(store.semantic_head(self.paths, TASK)["event_sha256"], head)

        stale = self.cli(*common, "f" * 64, ok=False)
        self.assertIn(b"expected semantic head", stale.stderr)
        self.assertEqual(store.semantic_head(self.paths, TASK)["event_sha256"], head)

        pretty_observation = self.root / "pretty-observation.json"
        pretty_observation.write_text(
            json.dumps(
                {
                    "manifest": manifest,
                    "observation_receipt": promotion_observation(manifest),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        noncanonical = self.cli(
            "release-promote", "--task", TASK,
            "--observation-result-file", str(pretty_observation),
            "--promotion-receipt-file", str(receipt_path),
            "--command-id", "release-cli-noncanonical",
            "--recorded-at", self.iso(self.now),
            "--expected-semantic-head-sha256", head,
            ok=False,
        )
        self.assertIn(b"canonical JSON", noncanonical.stderr)

        duplicate_receipt = self.root / "duplicate-receipt.json"
        raw_receipt = semantic.canonical_json_bytes(receipt)
        duplicate_receipt.write_bytes(raw_receipt[:-1] + b',"schema_version":1}')
        duplicate = self.cli(
            "release-promote", "--task", TASK,
            "--observation-result-file", str(observation_result_path),
            "--promotion-receipt-file", str(duplicate_receipt),
            "--command-id", "release-cli-duplicate",
            "--recorded-at", self.iso(self.now),
            "--expected-semantic-head-sha256", head,
            ok=False,
        )
        self.assertIn(b"duplicate JSON key", duplicate.stderr)

        result = self.cli(*common, head)
        bundle = json.loads(result.stdout)
        self.assertEqual(result.stdout, semantic.canonical_json_bytes(bundle))
        self.assertFalse(result.stdout.endswith(b"\n"))
        self.assertNotIn("result_state", bundle)
        self.assertNotIn("task", bundle)
        self.assertEqual(
            set(bundle),
            {
                "schema_version",
                "proof_scope",
                "task_id",
                "manifest",
                "observation_receipt",
                "promotion_receipt",
                "prior_release_namespace",
                "semantic_binding",
                "semantic_event",
                "bundle_sha256",
            },
        )
        self.assertEqual(bundle["semantic_event"]["event_type"], "release_promoted")
        self.assertEqual(
            store.semantic_head(self.paths, TASK)["event_sha256"],
            bundle["semantic_event"]["event_sha256"],
        )
        self.assertEqual(
            release_runtime.validate_promotion_bundle(bundle), bundle
        )
        recovered = self.cli(*common, head)
        self.assertEqual(recovered.stdout, result.stdout)
        self.assertEqual(
            store.semantic_head(self.paths, TASK)["event_sha256"],
            bundle["semantic_event"]["event_sha256"],
        )

    def test_release_promotion_rejects_stale_and_expired_chief_credentials(self) -> None:
        head = store.semantic_head(self.paths, TASK)["event_sha256"]
        common = (
            "release-promote",
            "--task", TASK,
            "--observation-result-file", str(self.root / "not-read-before-chief.json"),
            "--promotion-receipt-file", str(self.root / "not-read-before-chief-receipt.json"),
            "--command-id", "chief-credential-fence",
            "--recorded-at", self.iso(self.now),
            "--expected-semantic-head-sha256", head,
        )
        with h.state_lock(self.paths, create_layout=False):
            successor, successor_credential = h.takeover_chief_authority(
                self.paths,
                session_id="release-cli-successor",
                expected_epoch=self.chief["epoch"],
                reason="exercise stale release credential rejection",
                force_live=True,
                credential_home=self.credential_home,
                now=self.now + timedelta(seconds=1),
            )
        stale = self.cli(*common, ok=False)
        self.assertIn(b"does not match the current authority", stale.stderr)

        current_env = self.env.copy()
        current_env.update(
            {
                "AOI_CHIEF_SESSION_ID": successor["session_id"],
                "AOI_CHIEF_EPOCH": str(successor["epoch"]),
                "AOI_CHIEF_CREDENTIAL_FILE": str(successor_credential),
            }
        )
        with h.state_lock(self.paths, create_layout=False):
            expired = h.load_chief_authority(self.paths)
            first_at = self.now - timedelta(minutes=3)
            second_at = self.now - timedelta(minutes=2)
            expired["audit_tail"][0]["at"] = self.iso(first_at)
            expired["audit_tail"][1]["at"] = self.iso(second_at)
            expired["issued_at"] = self.iso(second_at)
            expired["renewed_at"] = self.iso(second_at)
            expired["expires_at"] = self.iso(self.now - timedelta(minutes=1))
            expired["updated_at"] = self.iso(second_at)
            h.validate_chief_authority_record(self.paths, expired)
            h.atomic_write_json(self.paths.chief_authority, expired)
        expired_result = self.cli(*common, env=current_env, ok=False)
        self.assertIn(b"Chief lease is expired", expired_result.stderr)

    def test_release_show_is_no_chief_read_only_and_release_commands_are_classified(self) -> None:
        before = store.semantic_head(self.paths, TASK)
        missing_chief = self.cli(
            "release-abandon-pending",
            "--task", TASK,
            "--binding-sha256", "a" * 64,
            "--expected-semantic-head-sha256", before["event_sha256"],
            "--command-id", "abandon-release",
            "--recorded-at", self.iso(self.now),
            "--reason", "successor disposition for a binding-only release crash",
            env=self.no_chief_env(),
            ok=False,
        )
        self.assertIn(b"Chief", missing_chief.stderr)
        self.assertEqual(store.semantic_head(self.paths, TASK), before)
        result = self.cli(
            "release-show", "--task", TASK, "--json", env=self.no_chief_env()
        )
        report = json.loads(result.stdout)
        self.assertEqual(report["task_id"], TASK)
        self.assertEqual(report["promotions"], [])
        self.assertEqual(store.semantic_head(self.paths, TASK), before)

        self.assertIn("release-manifest-observe", cli_impl.CHIEF_PROJECT_READ_ONLY_COMMANDS)
        self.assertIn("release-show", cli_impl.CHIEF_PROJECT_READ_ONLY_COMMANDS)
        self.assertFalse(cli_impl.command_requires_chief("release-manifest-observe", initialized=True))
        self.assertFalse(cli_impl.command_requires_chief("release-show", initialized=True))
        self.assertTrue(cli_impl.command_requires_chief("release-promote", initialized=True))
        self.assertTrue(
            cli_impl.command_requires_chief(
                "release-abandon-pending", initialized=True
            )
        )
        self.assertTrue(
            {
                "release-manifest-observe",
                "release-promote",
                "release-abandon-pending",
                "release-show",
            }
            <= cli_impl._SEMANTIC_V2_STAGE1_TARGET_COMMANDS
        )


if __name__ == "__main__":
    unittest.main()
