"""Static safety contract for the manual release workflow."""

from __future__ import annotations

import re
from pathlib import Path


WORKFLOW = (
    Path(__file__).resolve().parents[1] / ".github" / "workflows" / "publish.yml"
)
RELEASE_TOOLS_LOCK = Path(__file__).resolve().parents[1] / "requirements" / "release-tools.lock"


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


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


def test_windows_and_rebuild_bind_to_the_producer_inventory_bytes() -> None:
    text = _workflow()
    windows = _job(text, "verify-windows")
    assert "name: release-producer" in windows
    assert "release_inventory.py verify --inventory producer/inventory-linux.json" in windows
    assert "release_inventory.py capture --dist-dir windows/dist" in windows
    assert "scripts/verify_dist.py --dist-dir windows/dist" in windows
    rebuild = _job(text, "rebuild-linux")
    assert "name: release-producer" in rebuild
    assert "cmp \"$RUNNER_TEMP/producer/inventory-linux.json\" \"$RUNNER_TEMP/rebuild/inventory-rebuild.json\"" in rebuild
    assert "release_inventory.py verify --inventory \"$RUNNER_TEMP/producer/inventory-linux.json\" --root \"$RUNNER_TEMP/rebuild/dist\"" in rebuild


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
        "tests/test_release_workflow_contract.py",
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


def test_publish_is_intent_gated_and_only_receives_exact_stage() -> None:
    text = _workflow()
    publish = _job(text, "publish-pypi")
    assert "if: ${{ inputs.intent == 'publish' }}" in publish
    assert "name: pypi-exact-stage" in publish
    assert "path: publish-input" in publish
    assert "uses: actions/checkout@" not in publish
    assert "packages-dir: publish-input/dist" in publish
    assert "inventory-linux.json" in publish
    assert "release-manifest.json" in publish
    assert "evidence/producer-receipt.json" in publish
    assert "staged artifact does not match inventory" in publish
    assert "release manifest distribution/version does not match inventory" in publish
    assert "producer receipt does not bind the Linux inventory" in publish
    assert "release manifest producer chain does not match receipt and inventory" in publish
    stage = _job(text, "assemble-observe")
    assert 'destination-root "$RUNNER_TEMP/publish-stage/dist"' in stage
    assert 'cp "$ARTIFACT_ROOT/inventory-linux.json" "$RUNNER_TEMP/publish-stage/inventory-linux.json"' in stage
    assert 'cp "$ARTIFACT_ROOT/release-manifest.json" "$RUNNER_TEMP/publish-stage/release-manifest.json"' in stage
    assert "path: ${{ runner.temp }}/publish-stage/" in stage


def test_oidc_is_exclusive_to_protected_publish_job_and_readback_is_post_publish() -> None:
    text = _workflow()
    assert text.count("id-token: write") == 1
    publish = _job(text, "publish-pypi")
    assert "id-token: write" in publish
    assert "environment:\n      name: pypi" in publish
    assert "attestations: true" in publish
    readback = _job(text, "post-pypi-readback")
    assert "needs: publish-pypi" in readback
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
