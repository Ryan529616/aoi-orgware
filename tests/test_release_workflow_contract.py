"""Static safety contract for the manually dispatched release workflow."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path


WORKFLOW = (
    Path(__file__).resolve().parents[1] / ".github" / "workflows" / "publish.yml"
)
TEST_WORKFLOW = (
    Path(__file__).resolve().parents[1] / ".github" / "workflows" / "test.yml"
)
DOCS_WORKFLOW = (
    Path(__file__).resolve().parents[1] / ".github" / "workflows" / "docs.yml"
)
RELEASE_RUNBOOK = Path(__file__).resolve().parents[1] / "docs" / "RELEASE.md"
CHANGELOG = Path(__file__).resolve().parents[1] / "CHANGELOG.md"
V04_PLAN = Path(__file__).resolve().parents[1] / "docs" / "v0.4-plan.md"
RELEASE_TOOLS_LOCK = Path(__file__).resolve().parents[1] / "requirements" / "release-tools.lock"


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _test_workflow() -> str:
    return TEST_WORKFLOW.read_text(encoding="utf-8")


def _docs_workflow() -> str:
    return DOCS_WORKFLOW.read_text(encoding="utf-8")


def _release_runbook() -> str:
    return RELEASE_RUNBOOK.read_text(encoding="utf-8")


def _release_history() -> str:
    return CHANGELOG.read_text(encoding="utf-8") + V04_PLAN.read_text(encoding="utf-8")


def _job(text: str, name: str) -> str:
    match = re.search(
        rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]+:\n|\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match, f"job {name!r} is absent"
    return match.group("body")


def test_release_workflow_is_manual_and_requires_tag_and_intent() -> None:
    text = _workflow()
    assert "workflow_dispatch:" in text
    assert "  release:" not in text
    assert "      tag:" in text
    assert "      intent:" in text
    assert "          - rehearsal" in text
    assert "          - publish" in text


def test_release_dag_has_one_linux_producer_then_windows_rebuild_observe() -> None:
    text = _workflow()
    assert "  producer-linux:" in text
    assert "  verify-windows:" in text
    assert "    needs: producer-linux" in _job(text, "verify-windows")
    assert "  rebuild-linux:" in text
    assert "    needs: producer-linux" in _job(text, "rebuild-linux")
    observe = _job(text, "assemble-observe")
    assert "needs: [producer-linux, verify-windows, rebuild-linux]" in observe
    assert "release-manifest-observe" in observe
    assert "release_inventory.py stage" in observe
    stage = _job(text, "verify-pypi-stage")
    assert "needs: [assemble-observe, producer-linux]" in stage
    exact_ci = _job(text, "verify-exact-ci")
    assert "needs: producer-linux" in exact_ci
    github_release = _job(text, "publish-github-release")
    assert (
        "needs: [verify-pypi-stage, producer-linux, verify-exact-ci]"
        in github_release
    )
    release_readback = _job(text, "verify-github-release")
    assert (
        "needs: [publish-github-release, verify-pypi-stage, producer-linux]"
        in release_readback
    )
    publish = _job(text, "publish-pypi")
    assert (
        "needs: [verify-pypi-stage, verify-github-release, producer-linux]"
        in publish
    )


def test_windows_and_rebuild_bind_to_the_producer_inventory_bytes() -> None:
    text = _workflow()
    windows = _job(text, "verify-windows")
    assert "ref: ${{ needs.producer-linux.outputs.exact-commit }}" in windows
    assert "name: release-producer" in windows
    assert "release_inventory.py verify --inventory release/inventory-linux.json" in windows
    assert "release_inventory.py capture --dist-dir windows/dist" in windows
    assert "scripts/verify_dist.py --dist-dir windows/dist" in windows
    rebuild = _job(text, "rebuild-linux")
    assert "ref: ${{ needs.producer-linux.outputs.exact-commit }}" in rebuild
    assert "name: release-producer" in rebuild
    assert "cmp release/inventory-linux.json \"$RUNNER_TEMP/rebuild/inventory-rebuild.json\"" in rebuild
    assert "release_inventory.py verify --inventory release/inventory-linux.json --root \"$RUNNER_TEMP/rebuild/dist\"" in rebuild


def test_producer_gate_uses_pinned_pytest_and_honest_sdist_derivation() -> None:
    text = _workflow()
    producer = _job(text, "producer-linux")
    for module in (
        "tests/test_release_artifacts.py",
        "tests/test_release_cli.py",
        "tests/test_release_inventory.py",
        "tests/test_release_manifest.py",
        "tests/test_release_metadata.py",
        "tests/test_release_pypi_readback.py",
        "tests/test_release_rehearsal.py",
        "tests/test_release_runtime.py",
        "tests/test_release_tag_cli.py",
        "tests/test_release_tag_receipt.py",
        "tests/test_release_workflow_contract.py",
        "tests/test_verify_release_ci.py",
    ):
        assert module in producer
    assert ".release-tools/bin/python -I -m pytest -q" in producer
    assert "requirements/release-tools.lock" in producer
    assert "--require-hashes" in producer
    assert "--no-index --find-links" in producer
    assert "release-toolchain.json" in producer
    assert '"release_toolchain"' in producer
    assert "--no-isolation --outdir release/dist" in producer
    assert "--build-python \"$GITHUB_WORKSPACE/.release-tools/bin/python\"" in producer
    assert '"sdist_verification":"derived-wheel-offline-install"' in producer
    assert "unittest discover" not in producer


def test_producer_installs_the_single_inventory_bound_wheel_before_isolated_tests() -> None:
    producer = _job(_workflow(), "producer-linux")
    build_at = producer.index("-m build --sdist --wheel --no-isolation --outdir release/dist")
    capture_at = producer.index("release_inventory.py capture --dist-dir release/dist")
    verify_at = producer.index("release_inventory.py verify --inventory release/inventory-linux.json --root release/dist")
    select_at = producer.index("inventory must identify exactly one wheel and one sdist")
    install_at = producer.index("-m pip install --isolated --disable-pip-version-check --no-cache-dir --no-index --no-deps \"$wheel\"")
    test_at = producer.index(".release-tools/bin/python -I -m pytest -q")
    assert build_at < capture_at < verify_at < select_at < install_at < test_at
    assert "len(artifacts) != 2 or len(wheels) != 1" in producer
    assert "inventory-selected wheel bytes do not match" in producer
    assert "installed distribution version does not match exact inventory wheel" in producer
    assert "installed distribution entry points do not match release contract" in producer
    assert '"aoi": "aoi_orgware.cli:main"' in producer
    assert '"aoi-codex-hook": "aoi_orgware.codex_hook:main"' in producer
    assert "--editable" not in producer
    assert "PYTHONPATH" not in producer


def test_release_tools_lock_is_complete_hashed_and_used_offline_everywhere() -> None:
    lock = RELEASE_TOOLS_LOCK.read_text(encoding="utf-8")
    expected = {
        "build==1.5.0",
        "hatchling==1.27.0",
        "pytest==8.4.2",
        "colorama==0.4.6",
        "iniconfig==2.3.0",
        "packaging==26.2",
        "pathspec==1.1.1",
        "pluggy==1.6.0",
        "pygments==2.20.0",
        "pyproject-hooks==1.2.0",
        "trove-classifiers==2026.6.1.19",
    }
    assert "--only-binary=:all:" in lock
    assert "aoi-orgware" not in lock
    assert all(item in lock for item in expected)
    assert len(re.findall(r"--hash=sha256:[0-9a-f]{64}", lock)) == len(expected)
    text = _workflow()
    for job_name in ("producer-linux", "verify-windows", "rebuild-linux"):
        job = _job(text, job_name)
        assert "pip download --isolated" in job
        assert "--require-hashes --only-binary=:all:" in job
        assert "--no-index --find-links" in job
        assert "requirements/release-tools.lock" in job
    producer = _job(text, "producer-linux")
    assert '"release_toolchain"' in producer
    toolchain_start = producer.index("release/evidence/release-toolchain.json")
    toolchain_end = producer.index("toolchain_json=", toolchain_start)
    assert "aoi-orgware" not in producer[toolchain_start:toolchain_end]


def test_producer_requires_an_annotated_exact_tag_and_all_checkouts_use_its_commit() -> None:
    text = _workflow()
    producer = _job(text, "producer-linux")
    assert 'test "$GITHUB_SERVER_URL" = "https://github.com"' in producer
    assert 'test "$GITHUB_REPOSITORY" = "Ryan529616/aoi-orgware"' in producer
    assert "ref: refs/tags/${{ inputs.tag }}" in producer
    assert 'exact_tag_ref="refs/tags/$RELEASE_TAG"' in producer
    assert 'git cat-file -t "$exact_tag_object"' in producer
    assert 'test "$(git cat-file -t "$exact_tag_object")" = tag' in producer
    assert 'test "${tag_header[0]}" = "object $exact_commit"' in producer
    assert 'test "${tag_header[1]}" = "type commit"' in producer
    assert 'test "${tag_header[2]}" = "tag $RELEASE_TAG"' in producer
    assert 'test "$GITHUB_SHA" = "$exact_commit"' in producer
    assert "exact-commit: ${{ steps.bind-source.outputs.exact-commit }}" in producer
    assert "exact-tag-object: ${{ steps.bind-source.outputs.exact-tag-object }}" in producer
    assert "EXACT_TAG_OBJECT: ${{ steps.bind-source.outputs.exact-tag-object }}" in producer
    assert "release/evidence/source-tag-binding.json" in producer
    assert '"kind": "annotated_tag_binding"' in producer
    assert "annotated tag object does not peel to the exact source commit" in _job(text, "assemble-observe")
    assert (
        "annotated tag object does not directly name the exact tag and commit"
        in _job(text, "assemble-observe")
    )
    assert text.count('json.load(open(sys.argv[1]))["tag"]') >= 2
    assert 'tag.get("tag") != os.environ["RELEASE_TAG"]' in text
    for job_name in (
        "verify-windows",
        "rebuild-linux",
        "assemble-observe",
        "verify-pypi-stage",
        "verify-github-release",
        "post-pypi-readback",
    ):
        assert "ref: ${{ needs.producer-linux.outputs.exact-commit }}" in _job(text, job_name)
    assert "ref: ${{ inputs.tag }}" not in text


def test_release_tag_runbook_fails_closed_before_exact_object_push() -> None:
    text = _release_runbook()
    assert (
        'test "$(sha256sum "$tag_preflight" | awk \'{print $1}\')" = \\\n'
        '  "$tag_preflight_sha256" || exit 1'
    ) in text
    assert (
        'test "$(sha256sum "$tag_preflight_recheck" | awk \'{print $1}\')" = \\\n'
        '  "$tag_preflight_sha256" || exit 1'
    ) in text
    assert (
        'cmp --silent "$tag_preflight" "$tag_preflight_recheck" || exit 1'
        in text
    )
    assert (
        "--recorded-preflight-verification-index "
        "<tag-preflight-verification-index>"
    ) in text
    assert (
        '--recorded-preflight-artifact-sha256 "$tag_preflight_sha256"'
        in text
    )
    extraction_start = text.index('tag_object_oid="$(python -I -c')
    extraction_end = text.index("git push --porcelain")
    extraction = text[extraction_start:extraction_end]
    assert extraction.count('"$tag_preflight_recheck"') == 3
    assert '"$tag_preflight")' not in extraction
    assert '["push_transport"]' in extraction
    assert '--force-with-lease="$tag_ref:"' in text
    assert '  -- \\\n  "$transport_alias" \\\n' in text
    assert '"$tag_object_oid:$tag_ref"' in text
    assert '"$receipt_destination"' not in text
    assert 'git push github "refs/tags/$tag:refs/tags/$tag"' not in text


def test_v131_release_tag_runbook_preserves_route_cas_and_receipt_boundaries() -> None:
    runbook = _release_runbook()
    history = _release_history()

    assert "Any configured Git `insteadOf` or `pushInsteadOf` rewrite" in runbook
    assert "before network observation or push" in runbook
    assert "legacy live artifact references" in runbook
    assert "canonical task-CAS snapshots" in runbook
    assert "embedded confidentiality\npreflight's exact schema and canonical self-digest" in runbook
    assert "v130 focused `205 passed, 8 skipped, 2 subtests` result is superseded" in history
    assert "Fresh v131 targeted and expanded focused matrices" in history
    assert "`215 passed, 8 skipped, 2 subtests`" in history
    assert "formal review rejected" in history


def test_v132_release_tag_runbook_pins_transport_and_states_rewrite_race_boundary() -> None:
    runbook = _release_runbook()
    history = _release_history()
    normalized_runbook = " ".join(runbook.split())

    assert 'transport_alias="aoi-transport://' in runbook
    assert 'transport_system_config="$(mktemp)"' in runbook
    assert '"url.${push_transport}.insteadOf" "$transport_alias"' in runbook
    assert '"url.${push_transport}.pushInsteadOf" "$transport_alias"' in runbook
    assert 'GIT_CONFIG_SYSTEM="$transport_system_config"' in runbook
    assert 'GIT_CONFIG_COUNT=0 \\' in runbook
    assert '"$transport_alias" \\' in runbook
    assert 'include.path "$existing_system_config"' in runbook
    assert "command-scope identity rule could lose to an exact\nrepository rewrite" in history
    assert (
        "ambient rewrite observed before the network boundary is a failure "
        "before network access"
    ) in normalized_runbook
    assert (
        "post-guard race cannot redirect the already pinned subprocess away "
        "from the exact endpoint"
    ) in normalized_runbook
    assert (
        "must not be described as, an atomic lock over Git configuration"
        in normalized_runbook
    )
    assert (
        "14e2f9db8ce9506068bad456ce901bcec86d34a1403043de49e4ccfb81835e89"
        in history
    )
    assert "P0=0/P1=1/P2=0" in history
    assert "109 passed, 2 subtests passed" in history
    assert (
        "931ef80a342310e298f7f3fe2d3f3b48e94a943ae7d5e62b05ffe304149bcfbe"
        in history
    )
    assert "220 passed, 8 skipped, 2 subtests passed" in history
    assert (
        "31c1230cb449fb248114d910ab56791917805655b1ae865fe6c6d28dd5637ae2"
        in history
    )
    assert "Formal review" in history


def test_v133_release_guard_and_network_use_same_normalized_config_authority() -> None:
    runbook = _release_runbook()
    history = _release_history()
    normalized_runbook = " ".join(runbook.split())
    normalized_history = " ".join(history.split())

    assert "same normalized config authority as that subprocess" in normalized_runbook
    assert (
        "ambient command-count, parameter, no-system, and system-file selectors "
        "are scrubbed"
    ) in normalized_runbook
    assert "temporary endpoint pins themselves are removed" in normalized_runbook
    assert (
        "`GIT_CONFIG_NOSYSTEM=1` cannot hide a system rewrite"
        in normalized_runbook
    )
    assert (
        "cacfc7726af7680888f26bec4ef8deb76d30456cf3c416e5d37fae824ad18a2f"
        in history
    )
    assert "P0=0/P1=0/P2=1" in history
    assert "v133 normalized transport-config authority successor" in normalized_history
    assert "preserving any identical real entries" in normalized_history
    assert "112 passed, 2 subtests passed" in normalized_history
    assert (
        "d5cbcb2de77484ff99195fbc45fbea928939af394be631a4cec7fad58868c113"
        in normalized_history
    )
    assert "224 passed, 8 skipped, 2 subtests passed" in normalized_history
    assert (
        "6f0c2b28efbd2ab938e2e21ee895aca676a6f1403266aa634d0a682d9c091eab"
        in normalized_history
    )
    assert (
        "f148f8733dd6a2ec95d03619e38b8d2af3bab1c8cbdb174fe9e3824d61b05655"
        in normalized_history
    )
    assert "P0=0/P1=0/P2=0" in normalized_history
    assert (
        "permits full Windows/fresh-ext4 WSL qualification"
        in normalized_history
    )
    assert "later exact-candidate review" in normalized_history


def test_v134_full_qualification_failure_is_not_reused_as_acceptance() -> None:
    history = " ".join(_release_history().split())

    assert "v134 full-qualification fixture/contract repair" in history
    assert "Five WSL failures exposed" in history
    assert "Four WSL failures exposed" not in history
    assert "1899 passed, 29 skipped, 401 subtests passed, 5 failed" in history
    assert (
        "a8b1d723389e8965f290f27eee2f158fb6289c2238eda3baeb6f2e48d734a022"
        in history
    )
    assert "ended `-1` after partial progress" in history
    assert (
        "2ebcbe1e41704abcd2713ea34bc61ac0906266542c1f5612703cb95046d14b08"
        in history
    )
    assert "Production behavior is unchanged" in history
    assert "96 passed, 1 skipped, 57 subtests passed" in history
    assert (
        "d7b686ef301280ed0971e99970c9ab51774bf9a2403857d2a563a2e2a910db7e"
        in history
    )
    assert (
        "complete sequential Windows/WSL evidence was still pending at that "
        "checkpoint"
        in history
    )


def test_v135_records_the_rejected_review_and_exact_command_correction() -> None:
    history = " ".join(_release_history().split())

    assert "v135 review-evidence correction" in history
    assert (
        "716bbc1af8c08168a595c30ccaa2504b1db843c3683a5017df0c829de4e20fe7"
        in history
    )
    assert "P0=0/P1=0/P2=2" in history
    assert "supplemental task-CAS verification" in history
    assert "exact Python 3.14 interpreter, four module selectors" in history
    assert "The old record remains intact" in history
    assert (
        "a311e27d47b7ddcf60df70e92b49415fd68c1476e0b956494225dfa793009794"
        in history
    )
    assert "P0=0/P1=0/P2=0" in history
    assert "permits sequential full Windows" in history
    assert "does not establish full-suite acceptance" in history


def test_v136_records_exact_native_full_qualification_without_promotion() -> None:
    history = " ".join(_release_history().split())

    assert "v136 sequential Windows/WSL qualification" in history
    assert "620810f9e75cdf6df70ea5e1ea1fb3f91d2483c0" in history
    assert "1913 passed, 22 skipped, 401 subtests passed in 2021.60s" in history
    assert (
        "fbba27af8ccc15ad29731125165e05c475dc3600defb3b6b9f41575c0c385e0d"
        in history
    )
    assert "1906 passed, 29 skipped in 1426.14s" in history
    assert (
        "95308a8eb4855d2afe07aaab1bbbfb1ce7a17cb67f25f9bdd1dac622fdb65563"
        in history
    )
    assert "WSL_CLEAN_DRIVER_EXIT=0" in history
    assert "Codex nested-cell wrapper surfaced status `1`" in history
    assert "direct `wsl.exe` native readback" in history
    assert "reconciled native WSL runtime verdict" in history
    assert (
        "do not establish independent review, integrity-v2 sealing, "
        "package/install acceptance, remote CI, tag creation, publication, "
        "promotion, or ARISE installation"
        in history
    )


def test_verify_stage_seals_a_minimal_exact_envelope_before_oidc_publish() -> None:
    text = _workflow()
    verify = _job(text, "verify-pypi-stage")
    publish = _job(text, "publish-pypi")
    assert "if: ${{ inputs.intent == 'publish' }}" in verify
    assert "Verify the staged artifact-upload receipt without self-inclusion" in verify
    assert "uses: actions/checkout@" in verify
    assert 'python-version: "3.11"' in verify
    assert "staged artifact does not match inventory" in verify
    assert "release manifest producer chain does not match receipt and inventory" in verify
    assert "publication policy snapshot self-digest is invalid" in verify
    assert "load_publication_policy_snapshot" in verify
    assert 'PYTHONPATH="$GITHUB_WORKSPACE/src" python - <<\'PY\'' in verify
    assert "staged publication policy snapshot does not equal the trusted candidate snapshot" in verify
    assert "staged publication policy snapshot must use canonical JSON plus one LF" in verify
    assert "snapshot[\"snapshot_sha256\"] != os.environ[\"PUBLICATION_POLICY_SHA256\"]" in verify
    assert "staged publication policy snapshot does not match the trusted expected digest" in verify
    assert "PyPI package preflight receipt containers do not bind the exact inventory artifacts" in verify
    assert "name: pypi-publish-envelope" in verify
    assert "--subject \"dist/$wheel_name\" --subject \"dist/$sdist_name\" --subject evidence/pypi-package-preflight.json" in verify
    assert 'cp "$stage/evidence/pypi-package-preflight.json" "$envelope/evidence/pypi-package-preflight.json"' in verify
    assert "--expected-snapshot-sha256 \"$PUBLICATION_POLICY_SHA256\"" in verify
    for output in ("artifact-id", "artifact-digest", "wheel-name", "wheel-sha256", "sdist-name", "sdist-sha256", "package-preflight-sha256"):
        assert f"{output}: ${{{{" in verify
    assert "if: ${{ inputs.intent == 'publish' }}" in publish
    assert "artifact-ids: ${{ needs.verify-pypi-stage.outputs.artifact-id }}" in publish
    assert "Verify the exact envelope file set and SHA-256 values" in publish
    assert "sha256sum" in publish
    assert "evidence/pypi-package-preflight.json" in publish
    assert "PACKAGE_PREFLIGHT_SHA256" in publish
    assert "packages-dir: ${{ runner.temp }}/pypi-upload" in publish
    assert "uses: actions/checkout@" not in publish
    assert "contents: read" not in publish
    assert "PYTHONPATH" not in publish
    assert "aoi_orgware" not in publish
    stage = _job(text, "assemble-observe")
    assert 'destination-root "$RUNNER_TEMP/publish-stage/dist"' in stage
    assert 'cp "$ARTIFACT_ROOT/inventory-linux.json" "$RUNNER_TEMP/publish-stage/inventory-linux.json"' in stage
    assert 'cp "$ARTIFACT_ROOT/release-manifest.json" "$RUNNER_TEMP/publish-stage/release-manifest.json"' in stage
    assert 'cp release/publication-policy.json "$RUNNER_TEMP/publish-stage/release/publication-policy.json"' in stage
    assert "aoi_orgware.publication_gate preflight" in stage
    assert "--action package_publish" in stage
    assert "--destination https://pypi.org/project/aoi-orgware" in stage
    assert '"${preflight_args[@]}"' in stage
    assert "> evidence/pypi-package-preflight.json" in stage
    assert "path: ${{ runner.temp }}/publish-stage/" in stage
    assert 'cp "$ARTIFACT_ROOT/observation-result.json" "$RUNNER_TEMP/artifact/observation-result.json"' in stage


def test_github_release_is_gated_exact_and_verified_before_pypi() -> None:
    text = _workflow()
    verify = _job(text, "verify-pypi-stage")
    publisher = _job(text, "publish-github-release")
    readback = _job(text, "verify-github-release")
    pypi = _job(text, "publish-pypi")

    for output in (
        "github-release-artifact-id",
        "github-release-artifact-digest",
        "release-checksums-sha256",
        "release-preflight-sha256",
        "release-envelope-preflight-sha256",
    ):
        assert f"{output}: ${{{{" in verify
    assert "--action release_publish" in verify
    assert "--destination https://github.com/Ryan529616/aoi-orgware/releases" in verify
    assert "github-release-publication-preflight.json" in verify
    assert "github-release-envelope-publication-receipt.json" in verify
    assert "name: github-release-publish-envelope" in verify

    assert "contents: write" in publisher
    assert "id-token: write" not in publisher
    assert "uses: actions/checkout@" not in publisher
    assert (
        "artifact-ids: ${{ needs.verify-pypi-stage.outputs.github-release-artifact-id }}"
        in publisher
    )
    assert "git/ref/tags/$RELEASE_TAG" in publisher
    assert "git/tags/$EXACT_TAG_OBJECT" in publisher
    assert 'test "$(python -c' in publisher
    assert '" = "$EXACT_TAG_OBJECT"' in publisher
    assert '" = "$EXACT_COMMIT"' in publisher
    assert 'gh_api_json --method POST "repos/$GITHUB_REPOSITORY/releases"' in publisher
    assert "-F draft=true" in publisher
    assert "-F prerelease=true" in publisher
    assert "AOI-Release-Contract: v1" in publisher
    assert "release_envelope_preflight_sha256=$RELEASE_ENVELOPE_PREFLIGHT_SHA256" in publisher
    assert "release_artifact_digest=" not in publisher
    assert 'https://uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$release_id/assets?name=$encoded_name' in publisher
    assert "gh release create" not in publisher
    assert "gh release upload" not in publisher
    assert "--clobber" not in publisher
    assert "gh_api_json --paginate --slurp" in publisher
    assert "X-GitHub-Api-Version: $GH_API_VERSION" in publisher
    assert 'test "$fetch_status" -eq 3' in publisher
    assert 'return 2' in publisher
    assert publisher.count("assert_tag_binding") >= 7
    assert "GitHub Release contains duplicate or unexpected assets" in publisher
    assert "GitHub Release asset names or sizes do not match the sealed envelope" in publisher
    assert "Published GitHub Release is incomplete; refusing to mutate public release state" in publisher
    assert 'rows[0].get("state")=="starter" and rows[0].get("size")==0' in publisher
    assert 'gh_api_json --method DELETE --silent "repos/$GITHUB_REPOSITORY/releases/assets/$starter_id"' in publisher
    assert "Accept: application/octet-stream" in publisher
    assert "gh release download" not in publisher
    assert "SHA256SUMS.txt" in publisher
    verify_existing_at = publisher.index("missing_assets=()")
    stable_state_at = publisher.index(
        'test "$release_state_after" = "$release_state_before"'
    )
    tag_recheck_at = publisher.index("assert_tag_binding", stable_state_at)
    upload_missing_at = publisher.index(
        'for name in "${missing_assets[@]}"; do'
    )
    assert verify_existing_at < stable_state_at < tag_recheck_at < upload_missing_at
    draft_readback_at = publisher.index('ready_state_before="$(release_state_sha)"')
    publish_draft_at = publisher.index(
        'gh_api_json --method PATCH "repos/$GITHUB_REPOSITORY/releases/$release_id"'
    )
    published_validation_at = publisher.index(
        "GitHub Release was not published as a prerelease"
    )
    final_download_at = publisher.index(
        'final_readback="$RUNNER_TEMP/github-release-published-readback"'
    )
    assert (
        upload_missing_at
        < draft_readback_at
        < publish_draft_at
        < published_validation_at
        < final_download_at
    )

    assert "contents: read" in readback
    assert "contents: write" not in readback
    assert "id-token: write" not in readback
    assert "ref: ${{ needs.producer-linux.outputs.exact-commit }}" in readback
    assert "aoi_orgware.publication_gate verify" in readback
    assert "--action release_publish" in readback
    assert "github-release-readback.json" in readback
    assert "release_envelope_artifact_id" in readback
    assert "release_publication_preflight_sha256" in readback
    assert "github-release-readback-publication-receipt.json" in readback
    assert "AOI-Release-Contract: v1" in readback
    assert 'release.get("body") != os.environ["RELEASE_NOTES"]' in readback
    assert "X-GitHub-Api-Version: $GH_API_VERSION" in readback

    assert (
        "needs: [verify-pypi-stage, verify-github-release, producer-linux]"
        in pypi
    )
    recheck_at = pypi.index("Recheck the exact GitHub Release immediately before PyPI")
    publish_at = pypi.index("Publish the exact missing files with Trusted Publishing")
    assert recheck_at < publish_at
    assert "https://api.github.com/repos/Ryan529616/aoi-orgware" in pypi
    assert "GitHub tag object changed before PyPI publication" in pypi
    assert "GitHub Release asset set changed before PyPI publication" in pypi
    assert "AOI-Release-Contract: v1" in pypi
    assert 'release.get("body") != os.environ["RELEASE_NOTES"]' in pypi
    assert "X-GitHub-Api-Version: 2026-03-10" in pypi
    assert "verify-pypi-state.py" in pypi
    assert "PyPI provenance does not bind the trusted publisher and artifact" in pypi
    assert "continue-on-error: true" in pypi
    assert "Reconcile the exact PyPI state after the publication attempt" in pypi
    assert "--require-complete" in pypi
    assert "skip-existing" not in pypi
    assert text.index("  publish-github-release:") < text.index("  publish-pypi:")


def test_release_mutation_requires_exact_successful_main_push_test_and_docs() -> None:
    text = _workflow()
    gate = _job(text, "verify-exact-ci")
    publisher = _job(text, "publish-github-release")

    assert "if: ${{ inputs.intent == 'publish' }}" in gate
    assert "needs: producer-linux" in gate
    assert "actions: read" in gate
    assert "contents: read" in gate
    assert "contents: write" not in gate
    assert "id-token: write" not in gate
    assert "ref: ${{ needs.producer-linux.outputs.exact-commit }}" in gate
    assert "persist-credentials: false" in gate
    assert "EXACT_COMMIT: ${{ needs.producer-linux.outputs.exact-commit }}" in gate
    assert 'test "$GITHUB_API_URL" = "https://api.github.com"' in gate
    assert 'test "$GITHUB_REPOSITORY" = "Ryan529616/aoi-orgware"' in gate
    assert "Authorization: Bearer $GITHUB_TOKEN" in gate
    assert "X-GitHub-Api-Version: $GH_API_VERSION" in gate
    assert '--data-urlencode "head_sha=$EXACT_COMMIT"' in gate
    assert '--data-urlencode "branch=main"' in gate
    assert '--data-urlencode "event=push"' in gate
    assert '--data-urlencode "status=success"' in gate
    assert "actions/workflows/$workflow/runs" in gate
    assert "fetch_workflow_runs test.yml" in gate
    assert "fetch_workflow_runs docs.yml" in gate
    assert "python -I scripts/verify_release_ci.py" in gate
    assert (
        '--workflow ".github/workflows/test.yml=$RUNNER_TEMP/test-runs.json"'
        in gate
    )
    assert (
        '--workflow ".github/workflows/docs.yml=$RUNNER_TEMP/docs-runs.json"'
        in gate
    )
    assert (
        "needs: [verify-pypi-stage, producer-linux, verify-exact-ci]"
        in publisher
    )
    assert text.index("  verify-exact-ci:") < text.index(
        "  publish-github-release:"
    )


def test_full_ci_timeouts_cover_the_observed_long_matrix_runtime() -> None:
    text = _test_workflow()
    assert "timeout-minutes: 90" in _job(text, "unit")
    assert "timeout-minutes: 120" in _job(text, "coverage")


def test_complete_pypi_retry_emits_no_phantom_missing_filename() -> None:
    emitter = (
        'import json,sys; rows=json.loads(sys.stdin.read())["missing"]; '
        'sys.stdout.write("" if not rows else "\\n".join(rows)+"\\n")'
    )
    assert emitter in _job(_workflow(), "publish-pypi")
    complete = subprocess.run(
        [sys.executable, "-c", emitter],
        input='{"missing":[]}',
        text=True,
        capture_output=True,
        check=True,
    )
    assert complete.stdout == ""
    partial = subprocess.run(
        [sys.executable, "-c", emitter],
        input='{"missing":["one.whl"]}',
        text=True,
        capture_output=True,
        check=True,
    )
    assert partial.stdout == "one.whl\n"

    bash = shutil.which("bash")
    if bash is not None:
        shell = subprocess.run(
            [
                bash,
                "-c",
                f'readarray -t missing < <("{sys.executable}" -c \'{emitter}\' <<< \'{{"missing":[]}}\'); printf "%s" "${{#missing[@]}}"',
            ],
            text=True,
            capture_output=True,
            check=True,
        )
        assert shell.stdout == "0"


def test_every_artifact_upload_has_an_immediately_preceding_preflight() -> None:
    text = _workflow()
    expected_uploads = {
        "Preflight producer artifact publication": "Upload producer bytes and receipts",
        "Preflight Windows artifact publication": "Upload Windows evidence",
        "Preflight rebuild artifact publication": "Upload clean rebuild bytes",
        "Preflight rehearsal observation artifact publication": "Upload rehearsal observation candidate",
        "Preflight staged publication artifact upload": "Upload the exact staged publication evidence",
        "Build the exact PyPI publication envelope": "Upload the sealed PyPI publication envelope",
        "Build the exact GitHub Release publication envelope": "Upload the sealed GitHub Release publication envelope",
        "Preflight GitHub Release readback artifact publication": "Upload the GitHub Release readback candidate",
        "Preflight readback artifact publication": "Upload the readback candidate",
    }
    assert text.count("uses: actions/upload-artifact@") == len(expected_uploads)
    for preflight_name, upload_name in expected_uploads.items():
        match = re.search(
            rf"^      - name: {re.escape(preflight_name)}\n"
            rf"(?P<body>.*?)"
            rf"^      - name: {re.escape(upload_name)}\n"
            rf"(?:        (?:if|id): .*\n)*"
            rf"        uses: actions/upload-artifact@",
            text,
            flags=re.MULTILINE | re.DOTALL,
        )
        assert match, f"{upload_name!r} lacks its immediately preceding preflight"
        body = match.group("body")
        assert "aoi_orgware.publication_gate preflight" in body
        assert "--policy-snapshot" in body
        assert "release/publication-policy.json" in body
        assert "--action artifact_upload" in body
        assert "--destination https://github.com/Ryan529616/aoi-orgware/actions/artifacts" in body
        assert "--subject" in body
        assert "--json" in body
        assert "publication-receipt.json" in body


def test_release_workflow_uses_no_ignored_root_aoi_config() -> None:
    text = _workflow()
    assert "aoi.toml" not in text
    assert text.count("aoi_orgware.publication_gate preflight") == 11
    assert text.count("--expected-snapshot-sha256") >= 11
    snapshot = json.loads(
        (Path(__file__).resolve().parents[1] / "release" / "publication-policy.json")
        .read_text(encoding="utf-8")
    )
    assert f"PUBLICATION_POLICY_SHA256: {snapshot['snapshot_sha256']}" in text


def test_normal_ci_package_upload_is_snapshot_gated_and_reverified() -> None:
    text = _test_workflow()
    snapshot = json.loads(
        (Path(__file__).resolve().parents[1] / "release" / "publication-policy.json")
        .read_text(encoding="utf-8")
    )
    assert f"PUBLICATION_POLICY_SHA256: {snapshot['snapshot_sha256']}" in text
    package = _job(text, "package")
    preflight_at = package.index("Preflight verified distribution artifact upload")
    upload_at = package.index("Upload verified distributions")
    assert preflight_at < upload_at
    assert "aoi_orgware.publication_gate preflight" in package[preflight_at:upload_at]
    assert "--policy-snapshot release/publication-policy.json" in package
    assert '--expected-snapshot-sha256 "$PUBLICATION_POLICY_SHA256"' in package
    assert "--action artifact_upload" in package
    assert '--destination "https://github.com/$GITHUB_REPOSITORY/actions/artifacts"' in package
    assert "--subject dist/" in package
    assert "> ci-package-publication-receipt.json" in package
    assert "ci-package-publication-receipt.json" in package[upload_at:]
    windows = _job(text, "package-windows-smoke")
    assert "path: package-artifact" in windows
    assert "aoi_orgware.publication_gate verify" in windows
    assert "--receipt ci-package-publication-receipt.json" in windows
    assert "--subject dist/" in windows
    assert '--destination "https://github.com/$env:GITHUB_REPOSITORY/actions/artifacts"' in windows
    assert "--dist-dir package-artifact/dist" in windows


def test_docs_pages_artifact_upload_is_snapshot_gated() -> None:
    text = _docs_workflow()
    snapshot = json.loads(
        (Path(__file__).resolve().parents[1] / "release" / "publication-policy.json")
        .read_text(encoding="utf-8")
    )
    assert f"PUBLICATION_POLICY_SHA256: {snapshot['snapshot_sha256']}" in text
    build = _job(text, "build")
    preflight_at = build.index("Preflight GitHub Pages artifact publication")
    upload_at = build.index("uses: actions/upload-pages-artifact@")
    assert preflight_at < upload_at
    boundary = build[preflight_at:upload_at]
    assert "aoi_orgware.publication_gate preflight" in boundary
    assert "--policy-snapshot release/publication-policy.json" in boundary
    assert '--expected-snapshot-sha256 "$PUBLICATION_POLICY_SHA256"' in boundary
    assert "--action artifact_upload" in boundary
    assert '--destination "https://github.com/$GITHUB_REPOSITORY/actions/artifacts"' in boundary
    assert "--subject site/" in boundary
    assert "docs-pages-publication-receipt.json" in boundary
    deploy = _job(text, "deploy")
    assert "uses: actions/checkout@" not in deploy
    assert "aoi_orgware" not in deploy


def test_standalone_gate_runs_from_a_clean_tracked_checkout_without_aoi_toml(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[1]
    archive = subprocess.run(
        ["git", "-C", str(root), "archive", "--format=tar", "HEAD"],
        check=True,
        capture_output=True,
    ).stdout
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as contents:
        contents.extractall(checkout, filter="data")
    assert not (checkout / "aoi.toml").exists()
    policy = checkout / "release" / "publication-policy.json"
    assert policy.is_file(), "the exact tag must carry its reviewed publication snapshot"
    snapshot_sha256 = json.loads(policy.read_text(encoding="utf-8"))[
        "snapshot_sha256"
    ]
    subject = checkout / "sample.txt"
    subject.write_text("public sample\n", encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "aoi_orgware.publication_gate",
            "preflight",
            "--policy-snapshot",
            "release/publication-policy.json",
            "--expected-snapshot-sha256",
            snapshot_sha256,
            "--action",
            "artifact_upload",
            "--destination",
            "https://example.invalid/artifacts",
            "--subject",
            "sample.txt",
            "--json",
        ],
        cwd=checkout,
        env={**os.environ, "PYTHONPATH": str(checkout / "src")},
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(result.stdout)["decision"] == "allowed"


def test_oidc_is_exclusive_to_protected_publish_job_and_readback_is_post_publish() -> None:
    text = _workflow()
    assert text.count("id-token: write") == 1
    publish = _job(text, "publish-pypi")
    assert "id-token: write" in publish
    assert "environment:\n      name: pypi" in publish
    assert "attestations: true" in publish
    assert (
        "needs: [verify-pypi-stage, verify-github-release, producer-linux]"
        in publish
    )
    readback = _job(text, "post-pypi-readback")
    assert "needs: [publish-pypi, producer-linux]" in readback
    assert "ref: ${{ needs.producer-linux.outputs.exact-commit }}" in readback
    assert "scripts/release_pypi_readback.py" in readback
    assert "pypi-readback-candidate" in readback
    assert "--trusted-publisher-repository Ryan529616/aoi-orgware" in readback
    assert "--trusted-publisher-workflow publish.yml" in readback


def test_workflow_has_no_chief_authority_or_promotion_surface_and_pins_actions() -> None:
    text = _workflow()
    assert "AOI_CHIEF_" not in text
    assert "release-promote" not in text
    assert "Chief" not in text
    refs = re.findall(r"^\s*uses:\s*[^@\s]+@([^\s#]+)", text, flags=re.MULTILINE)
    assert refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in refs)
