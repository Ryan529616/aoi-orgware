from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace

import pytest

from aoi_orgware.company import legacy_bridge_init as bridge
from aoi_orgware.company.contracts import (
    DISPATCH_REQUEST_V1,
    EXECUTION_NODE_V1,
    EXTERNAL_JOB_V1,
    MUTATION_INTENT_V1,
)
from aoi_orgware.company.discovery import BoundCompanyTarget
from aoi_orgware.company.legacy_bridge import normalize_legacy_bridge_snapshot
from aoi_orgware.company.legacy_bridge_contract import build_legacy_bridge_observation
from aoi_orgware.company.legacy_bridge_health import (
    build_legacy_bridge_coverage,
    legacy_bridge_attempt_id,
)
from aoi_orgware.company.legacy_bridge_publisher import publish_legacy_bridge_snapshot
from aoi_orgware.company.supervisor import CompanySupervisor
from aoi_orgware.company.transactions import (
    CompanyEventDraft,
    build_company_transaction_request,
)
from aoi_orgware.harnesslib import get_paths
from tests.company_v05.test_legacy_bridge import H, _identity_digest, _raw, _snapshot


T = datetime(2026, 8, 5, 12, 34, 56, tzinfo=UTC)


def _environment(state_root: Path) -> dict[str, str]:
    if os.name == "nt":
        return {"LOCALAPPDATA": str(state_root / "local")}
    return {"XDG_STATE_HOME": str(state_root / "state"), "HOME": str(state_root / "home")}


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://example.invalid/synthetic/bridge.git"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    (repo / "aoi.toml").write_text(
        (Path(__file__).resolve().parents[2] / "aoi.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return repo


def _paths(tmp_path: Path):
    return get_paths(_repo(tmp_path))


@pytest.fixture
def short_state_root(tmp_path: Path):
    """Avoid a test-only Windows MAX_PATH artefact in the blob store."""

    parent = tmp_path.anchor if os.name == "nt" else str(tmp_path)
    with tempfile.TemporaryDirectory(prefix="aoi-lb-", dir=parent) as directory:
        yield Path(directory)


def test_pure_id_time_state_root_and_native_overlap_rules() -> None:
    digest = "a" * 64
    assert bridge.legacy_bridge_company_id(digest) == bridge.legacy_bridge_company_id(digest)
    assert bridge.utc_second(T) == "2026-08-05T12:34:56Z"
    assert bridge.grant_expiry("2026-08-05T12:34:56Z") == "2026-09-04T12:34:56Z"
    assert bridge.state_root_identity_sha256(platform="posix", state_root="/state/aoi") == bridge.state_root_identity_sha256(platform="posix", state_root="/state/aoi")
    bridge.validate_legacy_bridge_state_root(
        "/state/aoi/companies/x",
        platform="posix",
        protected_paths=("/repo", "/repo-linked"),
    )
    with pytest.raises(bridge.LegacyBridgeCompanyInitError):
        bridge.validate_legacy_bridge_state_root("/repo/.state", platform="posix", protected_paths=("/repo",))
    with pytest.raises(bridge.LegacyBridgeCompanyInitError):
        bridge.validate_legacy_bridge_state_root(r"\\server\state", platform="windows", protected_paths=(r"C:\repo",))
    with pytest.raises(bridge.LegacyBridgeCompanyInitError):
        bridge.validate_legacy_bridge_state_root(r"C:\repo\state", platform="windows", protected_paths=(r"C:\repo",))


def test_fresh_genesis_is_exactly_reopenable_and_has_no_work(
    tmp_path: Path,
    short_state_root: Path,
) -> None:
    paths = _paths(tmp_path)
    environment = _environment(short_state_root)
    created = bridge.initialize_legacy_bridge_company(paths.root, environ=environment, now=T)
    reopened = bridge.initialize_legacy_bridge_company(paths.root, environ=environment, now=T)

    assert created.action == "created"
    assert reopened.action == "existing_exact"
    assert created.company_id == reopened.company_id
    assert created.chief_carrier_state == "unknown"
    assert created.departments == ("rtl", "dv", "pd")
    assert "company.mutate" in created.authority_boundary
    with CompanySupervisor.open(created.state_root) as supervisor:
        assert supervisor.objects(contract_type=EXECUTION_NODE_V1) == ()
        assert supervisor.objects(contract_type=DISPATCH_REQUEST_V1) == ()
        assert supervisor.objects(contract_type=EXTERNAL_JOB_V1) == ()
        assert supervisor.objects(contract_type=MUTATION_INTENT_V1) == ()


def test_stopped_exact_reopen_accepts_later_legacy_snapshot(
    tmp_path: Path,
    short_state_root: Path,
) -> None:
    paths = _paths(tmp_path)
    environment = _environment(short_state_root)
    created = bridge.initialize_legacy_bridge_company(paths.root, environ=environment, now=T)
    with CompanySupervisor.open(created.state_root) as supervisor:
        published = publish_legacy_bridge_snapshot(
            supervisor,
            _raw(_snapshot()),
            task_identity_digest=_identity_digest("task", "dense-k"),
            legacy_archive_sha256=H,
            received_at="2026-08-05T12:35:00Z",
        )
        assert published.global_sequence == 2
    reopened = bridge.initialize_legacy_bridge_company(paths.root, environ=environment, now=T)
    assert reopened.action == "existing_exact"


def test_stopped_exact_reopen_accepts_degraded_coverage_only_publication(
    tmp_path: Path,
    short_state_root: Path,
) -> None:
    paths = _paths(tmp_path)
    environment = _environment(short_state_root)
    created = bridge.initialize_legacy_bridge_company(paths.root, environ=environment, now=T)
    with CompanySupervisor.open(created.state_root) as supervisor:
        published = publish_legacy_bridge_snapshot(
            supervisor,
            b"{}",
            task_identity_digest=_identity_digest("task", "dense-k"),
            legacy_archive_sha256=H,
            received_at="2026-08-05T12:35:00Z",
        )
        assert published.ingest_state == "degraded"
        assert published.observation_id is None
    reopened = bridge.initialize_legacy_bridge_company(paths.root, environ=environment, now=T)
    assert reopened.action == "existing_exact"


def test_stopped_reopen_rejects_actual_split_timestamp_publication(
    tmp_path: Path,
    short_state_root: Path,
) -> None:
    paths = _paths(tmp_path)
    environment = _environment(short_state_root)
    created = bridge.initialize_legacy_bridge_company(paths.root, environ=environment, now=T)
    raw_snapshot = _snapshot()
    with CompanySupervisor.open(created.state_root) as supervisor:
        manifest = next(item.payload for item in supervisor.objects(contract_type="company_manifest_v1"))
        for field in ("company_id", "company_incarnation", "lock_domain_generation"):
            raw_snapshot[field] = manifest[field]
        raw = _raw(raw_snapshot)
        projection = normalize_legacy_bridge_snapshot(raw)
        observation = build_legacy_bridge_observation(
            projection,
            ingested_at="2026-08-05T12:35:00Z",
        )
        coverage = build_legacy_bridge_coverage(
            projection.key,
            legacy_archive_sha256=H,
            task_identity_digest=_identity_digest("task", "dense-k"),
            source_document_sha256=hashlib.sha256(raw).hexdigest(),
            source_document_size_bytes=len(raw),
            ingest_state="observed",
            reason="provider_runtime_unavailable",
            assessed_at="2026-08-05T12:36:00Z",
            observation_id=str(observation["observation_id"]),
        )
        attempt = legacy_bridge_attempt_id(
            str(coverage["bridge_scope_id"]),
            source_document_sha256=str(coverage["source_document_sha256"]),
            source_document_size_bytes=int(coverage["source_document_size_bytes"]),
        )
        request = build_company_transaction_request(
            supervisor.heads(),
            supervisor._supervisor_authority(),
            transaction_id=f"legacy-bridge-transaction-{attempt}",
            command_id=f"legacy-bridge-command-{attempt}",
            events=(
                CompanyEventDraft(f"legacy-bridge-event-1-{attempt}", "legacy.bridge.observation", "2026-08-05T12:35:00Z", observation, provenance="adapter_receipt_persisted"),
                CompanyEventDraft(f"legacy-bridge-event-2-{attempt}", "legacy.bridge.coverage", "2026-08-05T12:36:00Z", coverage, provenance="adapter_receipt_persisted"),
            ),
        )
        supervisor.commit(request, recorded_at="2026-08-05T12:36:00Z")
    with pytest.raises(bridge.LegacyBridgeCompanyInitError, match="cannot be verified"):
        bridge.initialize_legacy_bridge_company(paths.root, environ=environment, now=T)


def test_stopped_reopen_rejects_receipt_timestamp_mismatch(
    tmp_path: Path,
    short_state_root: Path,
) -> None:
    paths = _paths(tmp_path)
    environment = _environment(short_state_root)
    created = bridge.initialize_legacy_bridge_company(paths.root, environ=environment, now=T)
    raw_snapshot = _snapshot()
    event_time = "2026-08-05T12:35:00Z"
    with CompanySupervisor.open(created.state_root) as supervisor:
        manifest = next(
            item.payload
            for item in supervisor.objects(contract_type="company_manifest_v1")
        )
        for field in ("company_id", "company_incarnation", "lock_domain_generation"):
            raw_snapshot[field] = manifest[field]
        raw = _raw(raw_snapshot)
        projection = normalize_legacy_bridge_snapshot(raw)
        observation = build_legacy_bridge_observation(
            projection,
            ingested_at=event_time,
        )
        coverage = build_legacy_bridge_coverage(
            projection.key,
            legacy_archive_sha256=H,
            task_identity_digest=_identity_digest("task", "dense-k"),
            source_document_sha256=hashlib.sha256(raw).hexdigest(),
            source_document_size_bytes=len(raw),
            ingest_state="observed",
            reason="provider_runtime_unavailable",
            assessed_at=event_time,
            observation_id=str(observation["observation_id"]),
        )
        attempt = legacy_bridge_attempt_id(
            str(coverage["bridge_scope_id"]),
            source_document_sha256=str(coverage["source_document_sha256"]),
            source_document_size_bytes=int(coverage["source_document_size_bytes"]),
        )
        request = build_company_transaction_request(
            supervisor.heads(),
            supervisor._supervisor_authority(),
            transaction_id=f"legacy-bridge-transaction-{attempt}",
            command_id=f"legacy-bridge-command-{attempt}",
            events=(
                CompanyEventDraft(
                    f"legacy-bridge-event-1-{attempt}",
                    "legacy.bridge.observation",
                    event_time,
                    observation,
                    provenance="adapter_receipt_persisted",
                ),
                CompanyEventDraft(
                    f"legacy-bridge-event-2-{attempt}",
                    "legacy.bridge.coverage",
                    event_time,
                    coverage,
                    provenance="adapter_receipt_persisted",
                ),
            ),
        )
        supervisor.commit(request, recorded_at="2026-08-05T12:36:00Z")
    with pytest.raises(bridge.LegacyBridgeCompanyInitError, match="cannot be verified"):
        bridge.initialize_legacy_bridge_company(paths.root, environ=environment, now=T)


@pytest.mark.parametrize("contract_type", ("carrier_binding_v1", EXECUTION_NODE_V1))
def test_stopped_replay_with_unrepresentable_control_fact_fails_closed(
    tmp_path: Path,
    short_state_root: Path,
    contract_type: str,
) -> None:
    created = bridge.initialize_legacy_bridge_company(
        _paths(tmp_path).root,
        environ=_environment(short_state_root),
        now=T,
    )
    with CompanySupervisor.open(created.state_root) as supervisor:
        manifest = next(item.payload for item in supervisor.objects(contract_type="company_manifest_v1"))
        record = SimpleNamespace(
            global_sequence=2,
            events=(SimpleNamespace(event={
                "event_type": "synthetic.control.mutation",
                "payload": {"contract_type": contract_type},
            }),),
        )
        fake = SimpleNamespace(
            heads=lambda: SimpleNamespace(global_head=SimpleNamespace(global_sequence=2)),
            _state=SimpleNamespace(records_after=lambda _cursor, *, limit: (record,)),
        )
        with pytest.raises(bridge.LegacyBridgeCompanyInitError, match="cannot be verified"):
            bridge._assert_current_state_is_representable(fake, manifest)


def test_config_or_remote_drift_and_partial_residue_fail_closed(
    tmp_path: Path,
    short_state_root: Path,
) -> None:
    paths = _paths(tmp_path)
    environment = _environment(short_state_root)
    result = bridge.initialize_legacy_bridge_company(paths.root, environ=environment, now=T)
    changed = paths.config.read_text(encoding="utf-8").replace(
        'name = "aoi-v05-company-core"',
        'name = "synthetic-changed"',
    )
    (paths.config).write_text(changed, encoding="utf-8")
    with pytest.raises(bridge.LegacyBridgeCompanyInitError, match="differs"):
        bridge.initialize_legacy_bridge_company(paths.root, environ=environment, now=T)

    residue_paths = _paths(tmp_path / "residue")
    manifest, slot, _platform = bridge._expected_slot(
        residue_paths.root,
        environ=_environment(short_state_root / "residue"),
        bootstrap_at=bridge.utc_second(T),
    )
    del manifest
    slot.mkdir(parents=True)
    (slot / "partial.txt").write_text("synthetic", encoding="utf-8")
    with pytest.raises(bridge.LegacyBridgeCompanyInitError):
        bridge.initialize_legacy_bridge_company(
            residue_paths.root,
            environ=_environment(short_state_root / "residue"),
            now=T,
        )
    assert result.action == "created"


def test_running_target_is_checked_without_opening_or_restarting(
    tmp_path: Path,
    short_state_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    environment = _environment(short_state_root)
    created = bridge.initialize_legacy_bridge_company(paths.root, environ=environment, now=T)
    expected, slot, platform = bridge._expected_slot(paths.root, environ=environment, bootstrap_at=bridge.utc_second(T))
    target = BoundCompanyTarget(
        slot_root=slot,
        company_id=created.company_id,
        manifest_sha256=created.manifest_sha256,
        manifest=expected,
        service_state="running",
        dashboard_url="http://127.0.0.1:1/",
        warnings=(),
    )
    monkeypatch.setattr(bridge, "service_status", lambda _slot: {"state": "running", "descriptor": {"company": {"company_id": created.company_id, "manifest_sha256": created.manifest_sha256}}})
    monkeypatch.setattr(bridge.CompanySupervisor, "open", classmethod(lambda *_args, **_kwargs: pytest.fail("running target opened")))
    with pytest.raises(bridge.LegacyBridgeCompanyInitError, match="running legacy bridge"):
        bridge._existing_result(target, expected, slot_root=slot, platform=platform)


def test_existing_state_root_symlink_is_rejected_before_initialization(tmp_path: Path) -> None:
    target = tmp_path / "outside"
    target.mkdir()
    alias = tmp_path / "state-alias"
    try:
        os.symlink(target, alias, target_is_directory=True)
    except OSError:
        pytest.skip("native symlink/reparse creation is unavailable")
    environment = _environment(alias)
    with pytest.raises(bridge.LegacyBridgeCompanyInitError, match="state root cannot be safely inspected"):
        bridge.initialize_legacy_bridge_company(_paths(tmp_path / "repo-root").root, environ=environment, now=T)


def test_initialize_rechecks_native_state_root_immediately_before_genesis(
    tmp_path: Path,
    short_state_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    calls: list[Path] = []
    original_check = bridge._assert_native_state_root_safe

    def checked(root: Path, *, platform: str) -> None:
        calls.append(root)
        original_check(root, platform=platform)

    def fail_after_check(cls, *args, **kwargs):
        del cls, args, kwargs
        assert len(calls) == 2
        raise MemoryError("synthetic post-safety allocation failure")

    monkeypatch.setattr(bridge, "_assert_native_state_root_safe", checked)
    monkeypatch.setattr(bridge.CompanySupervisor, "initialize", classmethod(fail_after_check))
    with pytest.raises(MemoryError, match="synthetic post-safety"):
        bridge.initialize_legacy_bridge_company(paths.root, environ=_environment(short_state_root), now=T)
    assert calls[0] == calls[1]


def test_initialize_loss_accepts_only_an_exact_concurrent_winner(
    tmp_path: Path,
    short_state_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    environment = _environment(short_state_root)
    original = bridge.CompanySupervisor.initialize.__func__

    def winner_then_raise(cls, *args, **kwargs):
        supervisor = original(cls, *args, **kwargs)
        supervisor.close()
        raise bridge.CompanySupervisorError("synthetic winner response loss")

    monkeypatch.setattr(bridge.CompanySupervisor, "initialize", classmethod(winner_then_raise))
    result = bridge.initialize_legacy_bridge_company(paths.root, environ=environment, now=T)
    assert result.action == "existing_exact"


def test_related_existing_target_never_becomes_a_new_company(
    tmp_path: Path,
    short_state_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    environment = _environment(short_state_root)
    monkeypatch.setattr(
        bridge,
        "resolve_bound_company",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            bridge.CompanyDiscoveryError("synthetic related binding mismatch"),
        ),
    )
    with pytest.raises(bridge.LegacyBridgeCompanyInitError, match="not safe"):
        bridge.initialize_legacy_bridge_company(paths.root, environ=environment, now=T)


def test_memory_error_during_initialize_is_not_reconciled(
    tmp_path: Path,
    short_state_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        bridge.CompanySupervisor,
        "initialize",
        classmethod(lambda *_args, **_kwargs: (_ for _ in ()).throw(MemoryError("synthetic"))),
    )
    with pytest.raises(MemoryError, match="synthetic"):
        bridge.initialize_legacy_bridge_company(
            _paths(tmp_path).root,
            environ=_environment(short_state_root),
            now=T,
        )


def test_memory_error_during_concurrent_winner_reconcile_propagates(
    tmp_path: Path,
    short_state_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def absent_then_memory(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise bridge.CompanyDiscoveryNotFoundError("synthetic absent slot")
        raise MemoryError("synthetic reconcile allocation failure")

    monkeypatch.setattr(bridge, "resolve_bound_company", absent_then_memory)
    monkeypatch.setattr(
        bridge.CompanySupervisor,
        "initialize",
        classmethod(lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("synthetic init failure"))),
    )
    with pytest.raises(MemoryError, match="synthetic reconcile allocation failure"):
        bridge.initialize_legacy_bridge_company(
            _paths(tmp_path).root,
            environ=_environment(short_state_root),
            now=T,
        )
    assert calls == 2
