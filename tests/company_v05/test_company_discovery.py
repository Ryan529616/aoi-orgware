from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Any

import pytest

from aoi_orgware.company.contracts import (
    COMPANY_MANIFEST_V1,
    canonical_company_json_bytes,
)
from aoi_orgware.company.discovery import (
    CompanyDiscoveryAmbiguousError,
    CompanyDiscoveryBindingMismatchError,
    CompanyDiscoveryNotFoundError,
    CompanyDiscoveryOverboundError,
    CompanyDiscoveryUnknownWriterError,
    CompanyDiscoveryUnsafePathError,
    resolve_bound_company,
)
from aoi_orgware.company.identity import (
    company_state_root,
    git_common_dir_identity,
    observed_remote_fingerprint,
)
from aoi_orgware.company.process_lock import CompanyProcessLock
from aoi_orgware.company.service import service_status, stop_service
from aoi_orgware.company.supervisor import CompanySupervisor


T = "2026-07-27T00:00:00Z"
EXPIRY = "2026-07-28T00:00:00Z"


def _platform() -> str:
    return "windows" if os.name == "nt" else "posix"


def _environment(tmp_path: Path) -> dict[str, str]:
    if os.name == "nt":
        return {"LOCALAPPDATA": str(tmp_path)}
    return {
        "XDG_STATE_HOME": str(tmp_path),
        "XDG_RUNTIME_DIR": str(tmp_path / "runtime"),
        "HOME": str(tmp_path),
    }


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://example.invalid/aoi/discovery.git"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    return repo


def _slot(company_id: str, environment: dict[str, str]) -> Path:
    return Path(str(company_state_root(company_id, platform=_platform(), environ=environment)))


def _manifest(repo: Path, company_id: str, *, remote: str | None = None) -> dict[str, Any]:
    observed_remote = observed_remote_fingerprint(repo)["sha256"]
    return {
        "contract_type": COMPANY_MANIFEST_V1,
        "schema_version": 1,
        "company_id": company_id,
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "git_common_dir_sha256": git_common_dir_identity(repo)["common_dir_sha256"],
        "remote_fingerprint_sha256": observed_remote if remote is None else remote,
        "configuration_sha256": "c" * 64,
        "state_root_sha256": "d" * 64,
        "lock_domain_id": _platform(),
        "created_at": T,
        "observation": {"state": "known", "reason": "observed"},
    }


def _initialize(slot: Path, manifest: dict[str, Any]) -> None:
    with CompanySupervisor.initialize(
        slot,
        manifest,
        bootstrap_at=T,
        grant_expires_at=EXPIRY,
        platform=_platform(),
    ):
        pass


def _resident_process(slot: Path) -> subprocess.Popen[bytes]:
    source = Path(__file__).resolve().parents[2] / "src"
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(source)
    code = (
        "from aoi_orgware.company.service import run_service_foreground; "
        f"raise SystemExit(run_service_foreground({str(slot)!r}))"
    )
    return subprocess.Popen(
        [sys.executable, "-c", code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )


def _await_running(slot: Path, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if service_status(slot, timeout_seconds=0.3).get("state") == "running":
            return
        if process.poll() is not None:
            _stdout, stderr = process.communicate(timeout=1.0)
            raise AssertionError(f"resident service exited: {stderr.decode('utf-8', 'replace')}")
        time.sleep(0.05)
    raise AssertionError("resident service did not become ready")


def test_resolve_bound_company_reads_real_git_and_stopped_registry(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    environment = _environment(tmp_path)
    slot = _slot("discovery-one", environment)
    _initialize(slot, _manifest(repo, "discovery-one"))

    target = resolve_bound_company(repo, environ=environment)

    assert target.slot_root == slot.resolve()
    assert target.company_id == "discovery-one"
    assert target.service_state == "stopped"
    assert target.dashboard_url is None
    assert target.manifest_sha256 == hashlib.sha256(
        canonical_company_json_bytes(target.manifest),
    ).hexdigest()
    assert target.configuration_digest_observation == "manifest_only_not_live_observed"
    assert target.warnings == ("configuration_digest_manifest_only_not_live_observed",)


def test_resolve_bound_company_distinguishes_not_found_related_mismatch_and_multiple(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    environment = _environment(tmp_path)
    with pytest.raises(CompanyDiscoveryNotFoundError):
        resolve_bound_company(repo, environ=environment)

    mismatch = _slot("discovery-mismatch", environment)
    _initialize(mismatch, _manifest(repo, "discovery-mismatch", remote="e" * 64))
    with pytest.raises(CompanyDiscoveryBindingMismatchError):
        resolve_bound_company(repo, environ=environment)

    # Use a fresh inventory for the ambiguity fact, rather than relying on
    # ordering between a related-but-invalid slot and exact candidates.
    environment = _environment(tmp_path / "second")
    _initialize(_slot("discovery-two", environment), _manifest(repo, "discovery-two"))
    _initialize(_slot("discovery-three", environment), _manifest(repo, "discovery-three"))
    with pytest.raises(CompanyDiscoveryAmbiguousError):
        resolve_bound_company(repo, environ=environment)


def test_slot_basename_must_equal_manifest_company_id_without_filter(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    environment = _environment(tmp_path)
    _initialize(
        _slot("slot-name", environment),
        _manifest(repo, "manifest-name"),
    )
    with pytest.raises(
        CompanyDiscoveryBindingMismatchError,
        match="slot name and manifest company ID differ",
    ):
        resolve_bound_company(repo, environ=environment)


def test_discovery_rejects_overbound_inventory_before_opening_candidates(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    environment = _environment(tmp_path)
    inventory = _slot("placeholder", environment).parent
    inventory.mkdir(parents=True)
    (inventory / "one").mkdir()
    (inventory / "two").mkdir()
    with pytest.raises(CompanyDiscoveryOverboundError):
        resolve_bound_company(repo, environ=environment, max_candidates=1)


def test_discovery_rejects_linked_state_root(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    environment = _environment(tmp_path)
    inventory = _slot("placeholder", environment).parent
    inventory.parent.mkdir(parents=True)
    outside = tmp_path / "outside-inventory"
    outside.mkdir()
    try:
        inventory.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink is unavailable on this host: {exc}")
    with pytest.raises(CompanyDiscoveryUnsafePathError):
        resolve_bound_company(repo, environ=environment)


def test_discovery_rejects_linked_company_slot(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    environment = _environment(tmp_path)
    inventory = _slot("placeholder", environment).parent
    inventory.mkdir(parents=True)
    outside = tmp_path / "outside-slot"
    outside.mkdir()
    linked_slot = inventory / "linked-slot"
    try:
        linked_slot.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink is unavailable on this host: {exc}")
    with pytest.raises(CompanyDiscoveryUnsafePathError):
        resolve_bound_company(repo, environ=environment)


def test_busy_slot_without_verified_resident_service_is_unknown_writer(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    environment = _environment(tmp_path)
    slot = _slot("discovery-busy", environment)
    _initialize(slot, _manifest(repo, "discovery-busy"))
    ready = threading.Event()
    release = threading.Event()

    def holder() -> None:
        lock = CompanyProcessLock(slot / "company.lock", create_if_missing=False)
        with lock:
            ready.set()
            release.wait(timeout=5.0)

    thread = threading.Thread(target=holder)
    thread.start()
    assert ready.wait(timeout=5.0)
    try:
        with pytest.raises(CompanyDiscoveryUnknownWriterError):
            resolve_bound_company(repo, environ=environment)
    finally:
        release.set()
        thread.join(timeout=5.0)
        assert not thread.is_alive()


def test_busy_slot_uses_verified_resident_dashboard_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    environment = _environment(tmp_path)
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    slot = _slot("discovery-resident", environment)
    _initialize(slot, _manifest(repo, "discovery-resident"))
    process = _resident_process(slot)
    try:
        _await_running(slot, process)
        target = resolve_bound_company(repo, environ=environment)
        assert target.service_state == "running"
        assert target.dashboard_url is not None
        assert target.manifest_sha256 == service_status(slot)["descriptor"]["company"]["manifest_sha256"]
    finally:
        if process.poll() is None:
            stop_service(slot)
            assert process.wait(timeout=10.0) == 0
