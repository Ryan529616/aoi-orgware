"""CLI integration tests for exact-CI-gated annotated release-tag delivery."""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any
from unittest import mock

from aoi_orgware import confidentiality
from aoi_orgware import evidence_artifacts
from aoi_orgware import release_ci_receipt
from aoi_orgware import release_tag_receipt
from aoi_orgware import harnesslib as h
from aoi_orgware.commands import release as release_commands
from tests.harness_case import HarnessTestCase


TASK = "release-tag-cli-task"
TAG = "v0.4.0a3"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sealed(base: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(base)
    result["receipt_sha256"] = hashlib.sha256(_canonical(result)).hexdigest()
    return result


class ReleaseTagCliTests(HarnessTestCase):
    def setUp(self) -> None:
        super().setUp()
        config = self.root / "aoi.toml"
        config.write_text(
            config.read_text(encoding="utf-8")
            + """

[confidentiality]
mode = "local_files"
model_context = "allowed"
git_push = "deny"
remote_ci = "deny"
artifact_upload = "deny"
external_export = "permit_required"
local_cas = true
""",
            encoding="utf-8",
        )
        self.git("add", "aoi.toml")
        self.git("commit", "-m", "configure local-files profile")
        self.remote = Path(self.backup_temp.name) / "release-remote.git"
        subprocess.run(
            ["git", "init", "--bare", "-q", str(self.remote)],
            check=True,
            capture_output=True,
        )
        self.git("remote", "add", "github", str(self.remote))
        self.init_task(TASK)
        self.head = self.git("rev-parse", "HEAD").strip().lower()
        self.exact_ci_path, self.exact_ci_sha256 = self._record_exact_ci()

    def git(self, *arguments: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=True,
            text=True,
            capture_output=True,
        ).stdout

    def _without_chief(self, *arguments: str, ok: bool = True):
        names = (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
            "AOI_CHIEF_TOKEN",
        )
        saved = {name: self.env.pop(name, None) for name in names}
        try:
            return self.cli(*arguments, ok=ok)
        finally:
            for name, value in saved.items():
                if value is not None:
                    self.env[name] = value

    def _exact_ci(self) -> dict[str, Any]:
        return _sealed(
            {
                "schema_version": 1,
                "kind": "exact_release_ci_gate",
                "repository": release_ci_receipt.EXPECTED_REPOSITORY,
                "commit": self.head,
                "branch": release_ci_receipt.EXPECTED_BRANCH,
                "event": "push",
                "workflows": [
                    {
                        "path": ".github/workflows/docs.yml",
                        "response_sha256": "1" * 64,
                        "runs": [
                            {
                                "run_id": 101,
                                "run_attempt": 1,
                                "workflow_id": 1001,
                            }
                        ],
                    },
                    {
                        "path": ".github/workflows/test.yml",
                        "response_sha256": "2" * 64,
                        "runs": [
                            {
                                "run_id": 202,
                                "run_attempt": 1,
                                "workflow_id": 2002,
                            }
                        ],
                    },
                ],
            }
        )

    def _record_artifact(
        self, name: str, raw: bytes, *, evidence: str
    ) -> tuple[int, Path, str]:
        source = self.root / "release-test-inputs" / name
        source.parent.mkdir(exist_ok=True)
        source.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        self.add_passing_verification(
            TASK,
            category="delivery_check",
            evidence=evidence,
            command=f"offline verify {name}",
            boundary="Only the exact content-addressed release handoff artifact",
            artifact_refs=(f"{source}={digest}",),
            asserts_completion_boundary=False,
        )
        state = h.load_task(h.get_paths(self.root), TASK)
        return len(state["verification"]), source, digest

    def _record_exact_ci(self) -> tuple[Path, str]:
        receipt = self._exact_ci()
        raw = release_ci_receipt.canonical_exact_ci_receipt_bytes(receipt)
        index, source, digest = self._record_artifact(
            "exact-ci.json",
            raw,
            evidence="Exact canonical main-push test/docs CI receipt passed",
        )
        self.assertEqual(index, 1)
        return source, digest

    def _replace_artifact_with_legacy_live_ref(self, index: int) -> None:
        """Downgrade an otherwise byte-identical task-CAS ref to a live ref."""

        paths = h.get_paths(self.root)
        state = h.load_task(paths, TASK)
        artifact = state["verification"][index - 1]["artifact_refs"][0]
        artifact["snapshot_version"] = 0
        artifact["path"] = artifact["source_path"]
        h.atomic_write_json(h.task_state_path(paths, TASK), state)

    def _create_preflight(
        self,
        *,
        tag: str = TAG,
        annotated: bool = True,
        destination: Path | None = None,
    ) -> tuple[dict[str, Any], int, str]:
        if annotated:
            self.git("tag", "-a", tag, "-m", "release", self.head)
        else:
            self.git("tag", tag, self.head)
        result = self._without_chief(
            "release-tag-push-preflight",
            "--task",
            TASK,
            "--verification-index",
            "1",
            "--artifact-sha256",
            self.exact_ci_sha256,
            "--tag",
            tag,
            "--remote",
            "github",
            "--destination",
            (destination or self.remote).as_posix(),
        )
        self.assertFalse(result.stdout.endswith("\n"))
        receipt = json.loads(result.stdout)
        raw = release_tag_receipt.canonical_release_tag_receipt_bytes(receipt)
        index, _source, digest = self._record_artifact(
            f"{tag}-preflight.json",
            raw,
            evidence="Exact CI, task plan, tag object, and confidentiality preflight bound",
        )
        return receipt, index, digest

    def _split_push_remote(self) -> Path:
        push_remote = Path(self.backup_temp.name) / "release-push-remote.git"
        subprocess.run(
            ["git", "init", "--bare", "-q", str(push_remote)],
            check=True,
            capture_output=True,
        )
        self.git(
            "remote",
            "set-url",
            "--add",
            "--push",
            "github",
            str(push_remote),
        )
        self.assertEqual(
            self.git("remote", "get-url", "--push", "--all", "github").splitlines(),
            [str(push_remote)],
        )
        return push_remote

    def _configure_chained_url_rewrites(self) -> None:
        self.git(
            "config",
            "--local",
            "--add",
            "url.https://first.invalid/.insteadOf",
            "https://source.invalid/",
        )
        self.git(
            "config",
            "--local",
            "--add",
            "url.https://second.invalid/.pushInsteadOf",
            "https://first.invalid/",
        )

    def _preflight_namespace(self) -> argparse.Namespace:
        return argparse.Namespace(
            task=TASK,
            verification_index=1,
            artifact_sha256=self.exact_ci_sha256,
            tag=TAG,
            remote="github",
            destination=self.remote.as_posix(),
            recorded_preflight_verification_index=None,
            recorded_preflight_artifact_sha256=None,
        )

    def _push_exact_preflight(self, preflight: dict[str, Any]) -> None:
        self.git(
            "push",
            "-q",
            f"--force-with-lease={preflight['tag_ref']}:",
            "--",
            preflight["push_transport"],
            f"{preflight['tag_object_oid']}:{preflight['tag_ref']}",
        )

    def _verify_namespace(
        self,
        *,
        preflight_index: int,
        preflight_sha256: str,
    ) -> argparse.Namespace:
        return argparse.Namespace(
            task=TASK,
            preflight_verification_index=preflight_index,
            preflight_artifact_sha256=preflight_sha256,
            tag=TAG,
            expected_commit=self.head,
            remote="github",
            destination=self.remote.as_posix(),
        )

    def test_complete_preflight_push_readback_and_local_cas_recording(
        self,
    ) -> None:
        preflight, preflight_index, preflight_sha256 = (
            self._create_preflight()
        )
        self._push_exact_preflight(preflight)
        result = self._without_chief(
            "release-tag-push-verify",
            "--task",
            TASK,
            "--preflight-verification-index",
            str(preflight_index),
            "--preflight-artifact-sha256",
            preflight_sha256,
            "--tag",
            TAG,
            "--expected-commit",
            self.head,
            "--remote",
            "github",
            "--destination",
            self.remote.as_posix(),
        )
        self.assertFalse(result.stdout.endswith("\n"))
        delivery = json.loads(result.stdout)
        state = h.load_task(h.get_paths(self.root), TASK)
        preflight_record_sha256 = evidence_artifacts.canonical_record_sha256(
            state["verification"][preflight_index - 1]
        )
        self.assertEqual(
            release_tag_receipt.validate_release_tag_delivery(
                delivery,
                preflight=preflight,
                exact_ci_receipt=self._exact_ci(),
                preflight_verification_index=preflight_index,
                preflight_verification_record_sha256=preflight_record_sha256,
                preflight_artifact_sha256=preflight_sha256,
            ),
            delivery,
        )
        self.assertEqual(
            delivery["preflight_verification"],
            {
                "verification_index": preflight_index,
                "verification_record_sha256": preflight_record_sha256,
                "artifact_sha256": preflight_sha256,
                "receipt_sha256": preflight["receipt_sha256"],
            },
        )
        delivery_raw = release_tag_receipt.canonical_release_tag_receipt_bytes(
            delivery
        )
        delivery_index, _path, delivery_sha256 = self._record_artifact(
            f"{TAG}-delivery.json",
            delivery_raw,
            evidence="Remote annotated tag object and peeled commit readback matched",
        )
        self.assertEqual(delivery_index, 3)
        state = h.load_task(h.get_paths(self.root), TASK)
        for index, expected_sha in (
            (1, self.exact_ci_sha256),
            (2, preflight_sha256),
            (3, delivery_sha256),
        ):
            artifact = state["verification"][index - 1]["artifact_refs"][0]
            self.assertEqual(artifact["sha256"], expected_sha)
            self.assertIsNone(
                evidence_artifacts.artifact_ref_integrity_error(
                    h.get_paths(self.root),
                    state,
                    artifact,
                    require_origin=False,
                )
            )

    def test_preflight_cas_recheck_requires_exact_recorded_bytes(self) -> None:
        first, index, digest = self._create_preflight()
        result = self._without_chief(
            "release-tag-push-preflight",
            "--task",
            TASK,
            "--verification-index",
            "1",
            "--artifact-sha256",
            self.exact_ci_sha256,
            "--tag",
            TAG,
            "--remote",
            "github",
            "--destination",
            self.remote.as_posix(),
            "--recorded-preflight-verification-index",
            str(index),
            "--recorded-preflight-artifact-sha256",
            digest,
        )
        self.assertEqual(json.loads(result.stdout), first)
        self.assertEqual(
            hashlib.sha256(result.stdout.encode("utf-8")).hexdigest(), digest
        )

    def test_preflight_rejects_legacy_live_exact_ci_before_remote_mutation(
        self,
    ) -> None:
        self.git("tag", "-a", TAG, "-m", "release", self.head)
        self._replace_artifact_with_legacy_live_ref(1)
        result = self._without_chief(
            "release-tag-push-preflight",
            "--task",
            TASK,
            "--verification-index",
            "1",
            "--artifact-sha256",
            self.exact_ci_sha256,
            "--tag",
            TAG,
            "--remote",
            "github",
            "--destination",
            self.remote.as_posix(),
            ok=False,
        )
        self.assertIn("canonical task-CAS snapshot required", result.stderr)
        self.assertEqual(
            self.git("ls-remote", "github", f"refs/tags/{TAG}").strip(), ""
        )

    def test_preflight_recheck_rejects_legacy_live_preflight_before_remote_mutation(
        self,
    ) -> None:
        _first, index, digest = self._create_preflight()
        self._replace_artifact_with_legacy_live_ref(index)
        result = self._without_chief(
            "release-tag-push-preflight",
            "--task",
            TASK,
            "--verification-index",
            "1",
            "--artifact-sha256",
            self.exact_ci_sha256,
            "--tag",
            TAG,
            "--remote",
            "github",
            "--destination",
            self.remote.as_posix(),
            "--recorded-preflight-verification-index",
            str(index),
            "--recorded-preflight-artifact-sha256",
            digest,
            ok=False,
        )
        self.assertIn("canonical task-CAS snapshot required", result.stderr)
        self.assertEqual(
            self.git("ls-remote", "github", f"refs/tags/{TAG}").strip(), ""
        )

    def test_preflight_cas_recheck_requires_paired_arguments(self) -> None:
        self.git("tag", "-a", TAG, "-m", "release", self.head)
        base = (
            "release-tag-push-preflight",
            "--task",
            TASK,
            "--verification-index",
            "1",
            "--artifact-sha256",
            self.exact_ci_sha256,
            "--tag",
            TAG,
            "--remote",
            "github",
            "--destination",
            self.remote.as_posix(),
        )
        missing_sha = self._without_chief(
            *base,
            "--recorded-preflight-verification-index",
            "1",
            ok=False,
        )
        self.assertIn("must be supplied together", missing_sha.stderr)
        missing_index = self._without_chief(
            *base,
            "--recorded-preflight-artifact-sha256",
            "0" * 64,
            ok=False,
        )
        self.assertIn("must be supplied together", missing_index.stderr)

    def test_preflight_cas_recheck_rejects_tampered_or_wrong_record(self) -> None:
        _first, index, digest = self._create_preflight()
        wrong = self._without_chief(
            "release-tag-push-preflight",
            "--task",
            TASK,
            "--verification-index",
            "1",
            "--artifact-sha256",
            self.exact_ci_sha256,
            "--tag",
            TAG,
            "--remote",
            "github",
            "--destination",
            self.remote.as_posix(),
            "--recorded-preflight-verification-index",
            "1",
            "--recorded-preflight-artifact-sha256",
            self.exact_ci_sha256,
            ok=False,
        )
        self.assertIn("does not exactly match", wrong.stderr)

        state = h.load_task(h.get_paths(self.root), TASK)
        artifact = state["verification"][index - 1]["artifact_refs"][0]
        Path(str(artifact["path"])).write_bytes(b"tampered recorded preflight")
        tampered = self._without_chief(
            "release-tag-push-preflight",
            "--task",
            TASK,
            "--verification-index",
            "1",
            "--artifact-sha256",
            self.exact_ci_sha256,
            "--tag",
            TAG,
            "--remote",
            "github",
            "--destination",
            self.remote.as_posix(),
            "--recorded-preflight-verification-index",
            str(index),
            "--recorded-preflight-artifact-sha256",
            digest,
            ok=False,
        )
        self.assertIn("verification artifact", tampered.stderr)

    def test_preflight_cas_recheck_rereads_record_after_network_preflight(
        self,
    ) -> None:
        _first, index, digest = self._create_preflight()
        state = h.load_task(h.get_paths(self.root), TASK)
        artifact = state["verification"][index - 1]["artifact_refs"][0]
        artifact_path = Path(str(artifact["path"]))
        original = confidentiality.preflight_git_push

        def tamper_recorded_preflight(**kwargs: Any) -> dict[str, Any]:
            receipt = original(**kwargs)
            artifact_path.write_bytes(b"tampered after remote preflight")
            return receipt

        namespace = self._preflight_namespace()
        namespace.recorded_preflight_verification_index = index
        namespace.recorded_preflight_artifact_sha256 = digest
        with mock.patch.object(
            release_commands.confidentiality,
            "preflight_git_push",
            side_effect=tamper_recorded_preflight,
        ):
            with self.assertRaisesRegex(h.HarnessError, "verification artifact"):
                release_commands.cmd_release_tag_push_preflight(
                    namespace,
                    h.get_paths(self.root),
                )

    def test_preflight_rejects_lightweight_or_preexisting_remote_tag(
        self,
    ) -> None:
        self.git("tag", TAG, self.head)
        lightweight = self._without_chief(
            "release-tag-push-preflight",
            "--task",
            TASK,
            "--verification-index",
            "1",
            "--artifact-sha256",
            self.exact_ci_sha256,
            "--tag",
            TAG,
            "--remote",
            "github",
            "--destination",
            self.remote.as_posix(),
            ok=False,
        )
        self.assertIn("annotated tag object", lightweight.stderr)

        self.git("tag", "-d", TAG)
        self.git("tag", "-a", TAG, "-m", "release", self.head)
        self.git("push", "-q", "github", f"refs/tags/{TAG}")
        existing = self._without_chief(
            "release-tag-push-preflight",
            "--task",
            TASK,
            "--verification-index",
            "1",
            "--artifact-sha256",
            self.exact_ci_sha256,
            "--tag",
            TAG,
            "--remote",
            "github",
            "--destination",
            self.remote.as_posix(),
            ok=False,
        )
        self.assertIn("pre-push remote state", existing.stderr)

    def test_preflight_remote_state_uses_push_url_not_fetch_url(self) -> None:
        push_remote = self._split_push_remote()
        self.git("tag", "-a", TAG, "-m", "release", self.head)
        local_tag = self.git("rev-parse", f"refs/tags/{TAG}").strip()
        self.git(
            "push",
            "-q",
            push_remote.as_posix(),
            f"{local_tag}:refs/tags/{TAG}",
        )
        result = self._without_chief(
            "release-tag-push-preflight",
            "--task",
            TASK,
            "--verification-index",
            "1",
            "--artifact-sha256",
            self.exact_ci_sha256,
            "--tag",
            TAG,
            "--remote",
            "github",
            "--destination",
            push_remote.as_posix(),
            ok=False,
        )
        self.assertIn("pre-push remote state", result.stderr)

    def test_preflight_binds_raw_push_transport_not_fetch_url(self) -> None:
        push_remote = self._split_push_remote()
        preflight, _index, _digest = self._create_preflight(
            destination=push_remote
        )
        self.assertEqual(preflight["push_transport"], str(push_remote))

    def test_preflight_rejects_any_url_rewrite_before_transport_or_network(
        self,
    ) -> None:
        self.git("tag", "-a", TAG, "-m", "release", self.head)
        self._configure_chained_url_rewrites()
        with (
            mock.patch.object(
                release_commands.confidentiality,
                "effective_git_push_transport",
            ) as effective_transport,
            mock.patch.object(
                release_commands.confidentiality,
                "preflight_git_push",
            ) as network_preflight,
        ):
            with self.assertRaisesRegex(
                h.HarnessError, "Git URL rewrites exist"
            ):
                release_commands.cmd_release_tag_push_preflight(
                    self._preflight_namespace(),
                    h.get_paths(self.root),
                )
        effective_transport.assert_not_called()
        network_preflight.assert_not_called()
        self.assertEqual(
            self.git(
                "ls-remote", self.remote.as_posix(), f"refs/tags/{TAG}"
            ).strip(),
            "",
        )

    def test_verify_rejects_push_transport_drift(self) -> None:
        preflight, preflight_index, preflight_sha = self._create_preflight()
        self._push_exact_preflight(preflight)
        # The file URI names the same canonical destination but is a distinct
        # credential-free raw transport string.  The verifier must reject it
        # before treating the remote readback as correlated with the receipt.
        self.git("remote", "set-url", "--push", "github", self.remote.as_uri())
        result = self._without_chief(
            "release-tag-push-verify",
            "--task",
            TASK,
            "--preflight-verification-index",
            str(preflight_index),
            "--preflight-artifact-sha256",
            preflight_sha,
            "--tag",
            TAG,
            "--expected-commit",
            self.head,
            "--remote",
            "github",
            "--destination",
            self.remote.as_posix(),
            ok=False,
        )
        self.assertIn("push transport differs", result.stderr)

    def test_verify_rejects_any_url_rewrite_before_remote_readback(self) -> None:
        preflight, preflight_index, preflight_sha = self._create_preflight()
        self._push_exact_preflight(preflight)
        remote_before = self.git(
            "ls-remote", self.remote.as_posix(), preflight["tag_ref"]
        ).strip()
        self._configure_chained_url_rewrites()
        with (
            mock.patch.object(
                release_commands.confidentiality,
                "effective_git_push_transport",
            ) as effective_transport,
            mock.patch.object(
                release_commands.git_plumbing,
                "remote_annotated_tag_snapshot",
            ) as remote_readback,
        ):
            with self.assertRaisesRegex(
                h.HarnessError, "Git URL rewrites exist"
            ):
                release_commands.cmd_release_tag_push_verify(
                    self._verify_namespace(
                        preflight_index=preflight_index,
                        preflight_sha256=preflight_sha,
                    ),
                    h.get_paths(self.root),
                )
        effective_transport.assert_not_called()
        remote_readback.assert_not_called()
        self.assertEqual(
            self.git(
                "ls-remote", self.remote.as_posix(), preflight["tag_ref"]
            ).strip(),
            remote_before,
        )

    def test_verify_does_not_accept_tag_present_only_at_fetch_url(self) -> None:
        push_remote = self._split_push_remote()
        preflight, preflight_index, preflight_sha = self._create_preflight(
            destination=push_remote
        )
        self.git(
            "push",
            "-q",
            self.remote.as_posix(),
            f"{preflight['tag_object_oid']}:{preflight['tag_ref']}",
        )
        result = self._without_chief(
            "release-tag-push-verify",
            "--task",
            TASK,
            "--preflight-verification-index",
            str(preflight_index),
            "--preflight-artifact-sha256",
            preflight_sha,
            "--tag",
            TAG,
            "--expected-commit",
            self.head,
            "--remote",
            "github",
            "--destination",
            push_remote.as_posix(),
            ok=False,
        )
        self.assertIn("remote annotated release tag readback", result.stderr)

    def test_repeated_preflight_changes_when_local_tag_ref_moves(self) -> None:
        first, _index, _digest = self._create_preflight()
        self.git(
            "tag",
            "-f",
            "-a",
            TAG,
            "-m",
            "release tag object changed",
            self.head,
        )
        result = self._without_chief(
            "release-tag-push-preflight",
            "--task",
            TASK,
            "--verification-index",
            "1",
            "--artifact-sha256",
            self.exact_ci_sha256,
            "--tag",
            TAG,
            "--remote",
            "github",
            "--destination",
            self.remote.as_posix(),
        )
        second = json.loads(result.stdout)
        self.assertNotEqual(first["tag_object_oid"], second["tag_object_oid"])
        self.assertNotEqual(
            release_tag_receipt.canonical_release_tag_receipt_bytes(first),
            release_tag_receipt.canonical_release_tag_receipt_bytes(second),
        )

    def test_exact_object_push_empty_lease_rejects_competing_tag(self) -> None:
        preflight, _index, _digest = self._create_preflight()
        self.git("tag", "-a", "competitor", "-m", "competitor", self.head)
        competitor_oid = self.git(
            "rev-parse", "refs/tags/competitor"
        ).strip()
        self.git(
            "push",
            "-q",
            self.remote.as_posix(),
            f"{competitor_oid}:{preflight['tag_ref']}",
        )
        attempted = subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "push",
                "--porcelain",
                f"--force-with-lease={preflight['tag_ref']}:",
                self.remote.as_posix(),
                f"{preflight['tag_object_oid']}:{preflight['tag_ref']}",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(attempted.returncode, 0)
        observed = subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "ls-remote",
                self.remote.as_posix(),
                preflight["tag_ref"],
            ],
            check=True,
            text=True,
            capture_output=True,
        ).stdout
        self.assertEqual(observed.split("\t", 1)[0], competitor_oid)

    def test_preflight_rejects_plan_bytes_changed_after_approval(self) -> None:
        self.git("tag", "-a", TAG, "-m", "release", self.head)
        plan = self.root / ".aoi" / "tasks" / TASK / "plan.md"
        plan.write_text(
            plan.read_text(encoding="utf-8") + "\nUnapproved release drift.\n",
            encoding="utf-8",
        )
        result = self._without_chief(
            "release-tag-push-preflight",
            "--task",
            TASK,
            "--verification-index",
            "1",
            "--artifact-sha256",
            self.exact_ci_sha256,
            "--tag",
            TAG,
            "--remote",
            "github",
            "--destination",
            self.remote.as_posix(),
            ok=False,
        )
        self.assertIn("plan changed after approval", result.stderr)

    def test_preflight_rechecks_config_after_network_preflight(self) -> None:
        self.git("tag", "-a", TAG, "-m", "release", self.head)
        original = confidentiality.preflight_git_push

        def drift_config(**kwargs: Any) -> dict[str, Any]:
            receipt = original(**kwargs)
            config = self.root / "aoi.toml"
            config.write_text(
                config.read_text(encoding="utf-8") + "\n# concurrent drift\n",
                encoding="utf-8",
            )
            return receipt

        with mock.patch.object(
            release_commands.confidentiality,
            "preflight_git_push",
            side_effect=drift_config,
        ):
            with self.assertRaisesRegex(h.HarnessError, "aoi.toml changed"):
                release_commands.cmd_release_tag_push_preflight(
                    self._preflight_namespace(),
                    h.get_paths(self.root),
                )

    def test_preflight_rechecks_plan_after_network_preflight(self) -> None:
        self.git("tag", "-a", TAG, "-m", "release", self.head)
        original = confidentiality.preflight_git_push

        def drift_plan(**kwargs: Any) -> dict[str, Any]:
            receipt = original(**kwargs)
            plan = self.root / ".aoi" / "tasks" / TASK / "plan.md"
            plan.write_text(
                plan.read_text(encoding="utf-8") + "\nConcurrent plan drift.\n",
                encoding="utf-8",
            )
            return receipt

        with mock.patch.object(
            release_commands.confidentiality,
            "preflight_git_push",
            side_effect=drift_plan,
        ):
            with self.assertRaisesRegex(
                h.HarnessError, "plan changed after approval"
            ):
                release_commands.cmd_release_tag_push_preflight(
                    self._preflight_namespace(),
                    h.get_paths(self.root),
                )

    def test_verify_rechecks_config_after_remote_readback(self) -> None:
        preflight, preflight_index, preflight_sha = self._create_preflight()
        self._push_exact_preflight(preflight)
        original = release_commands.git_plumbing.remote_annotated_tag_snapshot

        def drift_config(*args: Any, **kwargs: Any) -> dict[str, str]:
            snapshot = original(*args, **kwargs)
            config = self.root / "aoi.toml"
            config.write_text(
                config.read_text(encoding="utf-8") + "\n# verify drift\n",
                encoding="utf-8",
            )
            return snapshot

        with mock.patch.object(
            release_commands.git_plumbing,
            "remote_annotated_tag_snapshot",
            side_effect=drift_config,
        ):
            with self.assertRaisesRegex(h.HarnessError, "aoi.toml changed"):
                release_commands.cmd_release_tag_push_verify(
                    self._verify_namespace(
                        preflight_index=preflight_index,
                        preflight_sha256=preflight_sha,
                    ),
                    h.get_paths(self.root),
                )

    def test_verify_before_network_rejects_rewrite_injected_after_outer_audit(
        self,
    ) -> None:
        preflight, preflight_index, preflight_sha = self._create_preflight()
        self._push_exact_preflight(preflight)
        original_snapshot = release_commands.git_plumbing.remote_annotated_tag_snapshot
        original_bounded = release_commands.git_plumbing._run_git_bytes_bounded
        network_commands: list[tuple[str, ...]] = []

        def inject_rewrite_then_readback(*args: Any, **kwargs: Any) -> dict[str, str]:
            # The command performed its last outer rewrite audit immediately
            # before entering the snapshot helper.  The callback supplied to
            # that helper must still reject this race before ls-remote starts.
            self._configure_chained_url_rewrites()
            return original_snapshot(*args, **kwargs)

        def observe_bounded(
            worktree: Path, arguments: Any, **kwargs: Any
        ) -> bytes:
            command = tuple(arguments)
            if command and command[0] == "ls-remote":
                network_commands.append(command)
            return original_bounded(worktree, command, **kwargs)

        with (
            mock.patch.object(
                release_commands.git_plumbing,
                "remote_annotated_tag_snapshot",
                side_effect=inject_rewrite_then_readback,
            ),
            mock.patch.object(
                release_commands.git_plumbing,
                "_run_git_bytes_bounded",
                side_effect=observe_bounded,
            ),
        ):
            with self.assertRaisesRegex(h.HarnessError, "Git URL rewrites exist"):
                release_commands.cmd_release_tag_push_verify(
                    self._verify_namespace(
                        preflight_index=preflight_index,
                        preflight_sha256=preflight_sha,
                    ),
                    h.get_paths(self.root),
                )
        self.assertEqual(network_commands, [])

    def test_verify_rechecks_plan_after_remote_readback(self) -> None:
        preflight, preflight_index, preflight_sha = self._create_preflight()
        self._push_exact_preflight(preflight)
        original = release_commands.git_plumbing.remote_annotated_tag_snapshot

        def drift_plan(*args: Any, **kwargs: Any) -> dict[str, str]:
            snapshot = original(*args, **kwargs)
            plan = self.root / ".aoi" / "tasks" / TASK / "plan.md"
            plan.write_text(
                plan.read_text(encoding="utf-8") + "\nVerify plan drift.\n",
                encoding="utf-8",
            )
            return snapshot

        with mock.patch.object(
            release_commands.git_plumbing,
            "remote_annotated_tag_snapshot",
            side_effect=drift_plan,
        ):
            with self.assertRaisesRegex(
                h.HarnessError, "plan changed after approval"
            ):
                release_commands.cmd_release_tag_push_verify(
                    self._verify_namespace(
                        preflight_index=preflight_index,
                        preflight_sha256=preflight_sha,
                    ),
                    h.get_paths(self.root),
                )

    def test_verify_rechecks_local_tag_after_remote_readback(self) -> None:
        preflight, preflight_index, preflight_sha = self._create_preflight()
        self._push_exact_preflight(preflight)
        original = release_commands.git_plumbing.remote_annotated_tag_snapshot

        def move_tag(*args: Any, **kwargs: Any) -> dict[str, str]:
            snapshot = original(*args, **kwargs)
            self.git(
                "tag",
                "-f",
                "-a",
                TAG,
                "-m",
                "moved during verify",
                self.head,
            )
            return snapshot

        with mock.patch.object(
            release_commands.git_plumbing,
            "remote_annotated_tag_snapshot",
            side_effect=move_tag,
        ):
            with self.assertRaisesRegex(
                h.HarnessError,
                "task, source, evidence, or destination changed",
            ):
                release_commands.cmd_release_tag_push_verify(
                    self._verify_namespace(
                        preflight_index=preflight_index,
                        preflight_sha256=preflight_sha,
                    ),
                    h.get_paths(self.root),
                )

    def test_verify_rejects_non_integer_nested_binding_without_traceback(
        self,
    ) -> None:
        preflight, _index, _digest = self._create_preflight()
        tampered = deepcopy(preflight)
        tampered["release_ci_verification"]["verification_index"] = "1"
        tampered.pop("receipt_sha256")
        tampered = _sealed(tampered)
        malformed_index, _source, malformed_sha = self._record_artifact(
            "malformed-preflight.json",
            release_tag_receipt.canonical_release_tag_receipt_bytes(tampered),
            evidence="Adversarial malformed preflight fixture",
        )
        result = self._without_chief(
            "release-tag-push-verify",
            "--task",
            TASK,
            "--preflight-verification-index",
            str(malformed_index),
            "--preflight-artifact-sha256",
            malformed_sha,
            "--tag",
            TAG,
            "--expected-commit",
            self.head,
            "--remote",
            "github",
            "--destination",
            self.remote.as_posix(),
            ok=False,
        )
        self.assertIn("verification binding is invalid", result.stderr)

    def test_verify_rejects_wrong_expected_commit_before_remote_claim(
        self,
    ) -> None:
        _preflight, preflight_index, preflight_sha = self._create_preflight()
        result = self._without_chief(
            "release-tag-push-verify",
            "--task",
            TASK,
            "--preflight-verification-index",
            str(preflight_index),
            "--preflight-artifact-sha256",
            preflight_sha,
            "--tag",
            TAG,
            "--expected-commit",
            "b" * 40,
            "--remote",
            "github",
            "--destination",
            self.remote.as_posix(),
            ok=False,
        )
        self.assertIn("expected delivery identity", result.stderr)
