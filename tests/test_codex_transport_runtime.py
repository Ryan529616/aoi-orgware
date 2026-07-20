from __future__ import annotations

import copy
from datetime import UTC, datetime
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import codex_transport_contracts as contracts
from aoi_orgware import codex_transport_runtime as runtime
from aoi_orgware import harnesslib as h
from aoi_orgware import semantic_events as semantic
from aoi_orgware import semantic_store as store
from aoi_orgware import transition_permits as permits
from aoi_orgware.config import default_config_text


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
NOW = datetime(2026, 7, 20, tzinfo=UTC)


def launch_authority_for(sealed_intent: dict[str, object]) -> dict[str, object]:
    return contracts.seal_launch_authority(
        {
            "contract_type": contracts.CODEX_LAUNCH_AUTHORITY_V1,
            "task_id": "task-1",
            "packet_id": "packet-1",
            "packet_contract_sha256": SHA_B,
            "attempt_number": 1,
            "arm_id": "packet-1-a1",
            "armed_at": "2026-07-19T23:59:00Z",
            "expires_at": "2026-07-21T00:00:00Z",
            "dispatch_attempt_authority_sha256": SHA_C,
            "chief_authority_sha256": SHA_D,
            "parent_session_id": "chief-1",
            "expected_agent_type": "worker",
            "routing_binding": sealed_intent["routing_binding"],
            "expected_semantic_head_sha256": sealed_intent[
                "expected_semantic_head_sha256"
            ],
            "launch_intent_sha256": sealed_intent["intent_sha256"],
        }
    )


def task_domain() -> dict[str, object]:
    return {
        "task_id": "task-1",
        "stage": 0,
        "revision": 1,
        "updated_at": "2026-07-19T23:59:00Z",
        "checkpoint_required": False,
        "packets": [
            {
                "packet_id": "packet-1",
                "packet_contract_sha256": SHA_B,
                "status": "armed",
                "dispatch_provenance": "none",
                "dispatch_attempts": [
                    {
                        "attempt": 1,
                        "arm_id": "packet-1-a1",
                        "status": "armed",
                        "armed_at": "2026-07-19T23:59:00Z",
                        "expires_at": "2026-07-21T00:00:00Z",
                        "arm_authority_sha256": SHA_C,
                        "authority_sha256": SHA_D,
                        "parent_session_id": "chief-1",
                        "expected_agent_type": "worker",
                        "observation": None,
                        "closed_at": "",
                        "reason": "",
                    }
                ],
            }
        ],
    }


@pytest.fixture(autouse=True)
def _stub_canonical_launch_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runtime.launch_authority,
        "require_canonical_launch_authority",
        lambda *args, **kwargs: launch_authority_for(dict(kwargs["intent"])),
    )


def pin() -> dict[str, object]:
    return {**contracts.pinned_runtime_binding(), "executable_path": "C:/AOI/codex-app-server.exe"}


def intent() -> dict[str, object]:
    return contracts.seal_launch_intent({
        "contract_type": contracts.CODEX_TRANSPORT_LAUNCH_INTENT_V1, "task_id": "task-1", "packet_id": "packet-1",
        "routing_binding": {"kind": "cohort", "cohort_id": "cohort-1", "cohort_sha256": SHA_A, "wave_index": 0, "transport_slot_sha256": SHA_B, "routing_authority_sha256": SHA_C, "transport": "codex", "parent_session_id": "chief-1", "expected_agent_type": "worker"},
        "expected_semantic_head_sha256": SHA_D, "prompt_sha256": SHA_A, "prompt_size_bytes": 1, "cwd": "C:/scratch/aoi",
        "requested_model": "gpt-5.6", "requested_effort": "high", "sandbox": "readOnly", "approval": "never", "runtime_pin": pin(),
        "pre_git_binding": {"git_head_sha256": SHA_A, "git_tree_sha256": SHA_B, "git_status_sha256": SHA_C, "claim_coverage_sha256": SHA_D},
    })


def chain() -> list[dict[str, object]]:
    genesis = semantic.create_genesis_event(task_domain(), command_id="genesis", recorded_at="2026-07-20T00:00:00Z", authority_ref="test")
    # The intent's semantic head is deliberately rebound below.
    return [genesis]


def decision_and_permit(
    head: str,
    sealed_intent: dict[str, object],
    *,
    chief_authority: dict[str, object] | None = None,
    launch_id: str = "launch-1",
    nonce: str = "nonce-0000000001",
) -> tuple[dict[str, object], dict[str, object]]:
    params = {"launch_id": launch_id, "launch_intent_sha256": sealed_intent["intent_sha256"], "packet_id": "packet-1", "routing_binding": sealed_intent["routing_binding"]}
    decision = permits.seal_transition_decision({"schema_version": 1, "task_id": "task-1", "action": "codex.launch", "target_ids": [launch_id], "parameters": params, "technical_payload_sha256": sealed_intent["intent_sha256"]})
    permit = permits.seal_transition_permit({"schema_version": 1, "task_id": "task-1", "expected_semantic_head_sha256": head, "decision_sha256": decision["decision_sha256"], "action": "codex.launch", "target_ids": [launch_id], "parameters": params, "expires_at": "2026-07-21T00:00:00Z", "nonce": nonce, "chief_authority": chief_authority or {"session_id": "chief-1", "epoch": 1}})
    return decision, permit


def test_prepare_binds_exact_cohort_route_and_one_reserved_event() -> None:
    events = chain()
    head = str(events[-1]["event_sha256"])
    raw = intent(); raw["expected_semantic_head_sha256"] = head
    sealed = contracts.seal_launch_intent({key: raw[key] for key in raw if key != "intent_sha256"})
    decision, permit = decision_and_permit(head, sealed)
    tx = runtime.prepare_codex_launch_transaction(task_id="task-1", event_chain=events, intent=sealed, decision=decision, permit=permit, launch_authority_contract=launch_authority_for(sealed), launch_id="launch-1", command_id="reserve-1", recorded_at="2026-07-20T00:01:00Z", current_time=NOW)
    assert tx["journal"][0]["event_type"] == "reserved"
    assert tx["reservation"]["permit_sha256"] == permit["permit_sha256"]
    assert tx["binding"]["binding_kind"] == "codex_launch_reservation"
    assert tx["result_domain"]["dispatch_model_version"] == 2
    assert tx["result_domain"]["packets"][0]["dispatch_version"] == 2


def test_prepare_fails_closed_for_head_drift_and_permit_replay_shape() -> None:
    events = chain(); head = str(events[-1]["event_sha256"])
    raw = intent(); raw["expected_semantic_head_sha256"] = head
    sealed = contracts.seal_launch_intent({key: raw[key] for key in raw if key != "intent_sha256"})
    decision, permit = decision_and_permit(head, sealed)
    with pytest.raises(runtime.CodexTransportRuntimeError, match="head drifted"):
        changed = dict(sealed); changed["expected_semantic_head_sha256"] = SHA_A
        changed = contracts.seal_launch_intent({key: changed[key] for key in changed if key != "intent_sha256"})
        runtime.prepare_codex_launch_transaction(task_id="task-1", event_chain=events, intent=changed, decision=decision, permit=permit, launch_authority_contract=launch_authority_for(changed), launch_id="launch-1", command_id="reserve-1", recorded_at="2026-07-20T00:01:00Z", current_time=NOW)


def test_pending_thread_start_requires_exact_request_and_unknown_is_not_retryable() -> None:
    sealed = intent()
    reservation = contracts.seal_reservation({"contract_type": contracts.CODEX_TRANSPORT_RESERVATION_V1, "reservation_id": "r-1", "launch_intent_sha256": sealed["intent_sha256"], "permit_sha256": SHA_A, "runtime_pin": pin(), "state": "reserved", "correlation": {"thread_id": None, "turn_id": None, "item_id": None}})
    with pytest.raises(runtime.CodexTransportRuntimeError, match="request milestone"):
        runtime._event_for(sealed, reservation, event_id="x", sequence=1, previous=contracts.ZERO_SHA256, event_type="thread_start_send_pending", correlation={"thread_id": None, "turn_id": None, "item_id": None})


def _filesystem_runtime() -> tuple[tempfile.TemporaryDirectory[str], tempfile.TemporaryDirectory[str], h.HarnessPaths, dict[str, Any], Path]:
    temp = tempfile.TemporaryDirectory()
    root = Path(temp.name)
    (root / "aoi.toml").write_text(default_config_text("Codex transport runtime"), encoding="utf-8")
    paths = h.get_paths(root)
    credential_temp = tempfile.TemporaryDirectory()
    credential_home = Path(credential_temp.name) / "credentials"
    with h.state_lock(paths, create_layout=True):
        h.task_dir(paths, "task-1").mkdir(parents=True)
        store.initialize_semantic_task(paths, task_domain(), command_id="runtime-genesis", recorded_at="2026-07-20T00:00:00Z", authority_ref="test")
        chief, credential_path = h.acquire_chief_authority(paths, session_id="chief-1", ttl_seconds=3600, credential_home=credential_home, now=NOW)
    return temp, credential_temp, paths, chief, credential_path


def _live_transaction(
    paths: h.HarnessPaths,
    chief: dict[str, Any],
    *,
    authority: dict[str, object] | None = None,
    launch_id: str = "launch-1",
    command_id: str = "reserve-1",
    nonce: str = "nonce-0000000001",
) -> dict[str, Any]:
    events = store.load_semantic_events(paths, "task-1")
    head = str(events[-1]["event_sha256"])
    raw = intent(); raw["expected_semantic_head_sha256"] = head
    sealed = contracts.seal_launch_intent({key: raw[key] for key in raw if key != "intent_sha256"})
    decision, permit = decision_and_permit(
        head,
        sealed,
        chief_authority=authority
        or {"session_id": chief["session_id"], "epoch": chief["epoch"]},
        launch_id=launch_id,
        nonce=nonce,
    )
    return runtime.prepare_codex_launch_transaction(task_id="task-1", event_chain=events, intent=sealed, decision=decision, permit=permit, launch_authority_contract=launch_authority_for(sealed), launch_id=launch_id, command_id=command_id, recorded_at="2026-07-20T00:01:00Z", current_time=NOW)


def _issue(paths: h.HarnessPaths, chief: dict[str, Any], credential_path: Path, transaction: dict[str, Any]) -> dict[str, Any]:
    with h.state_lock(paths, create_layout=False):
        token, _ = h.load_chief_credential(paths, session_id=chief["session_id"], epoch=chief["epoch"], credential_file=credential_path)
        return runtime.issue_codex_launch_transaction(paths, transaction, store.load_semantic_events(paths, "task-1"), chief_session_id=chief["session_id"], chief_epoch=chief["epoch"], chief_token=token, current_time=NOW, packet_integrity_services=object())  # type: ignore[arg-type]


def test_filesystem_issue_rejects_permit_from_wrong_live_chief() -> None:
    temp, credential_temp, paths, chief, credential_path = _filesystem_runtime()
    try:
        tx = _live_transaction(paths, chief, authority={"session_id": "other-chief", "epoch": 1})
        with pytest.raises(runtime.CodexTransportRuntimeError, match="differs from the live Chief"):
            _issue(paths, chief, credential_path, tx)
    finally:
        credential_temp.cleanup()
        temp.cleanup()


def test_filesystem_issue_cannot_bypass_canonical_launch_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    temp, credential_temp, paths, chief, credential_path = _filesystem_runtime()
    try:
        tx = _live_transaction(paths, chief)

        def reject(*args: object, **kwargs: object) -> dict[str, object]:
            raise runtime.launch_authority.CodexTransportAuthorityError(
                "noncanonical routing authority"
            )

        monkeypatch.setattr(
            runtime.launch_authority,
            "require_canonical_launch_authority",
            reject,
        )
        with pytest.raises(
            runtime.launch_authority.CodexTransportAuthorityError,
            match="noncanonical",
        ):
            _issue(paths, chief, credential_path, tx)
        assert not runtime._issuance_path(
            paths, "task-1", tx["permit"]["permit_sha256"]
        ).exists()
    finally:
        credential_temp.cleanup()
        temp.cleanup()


def test_filesystem_reserve_rebuilds_issued_transaction_and_replays_exactly() -> None:
    temp, credential_temp, paths, chief, credential_path = _filesystem_runtime()
    try:
        tx = _live_transaction(paths, chief)
        issued = _issue(paths, chief, credential_path, tx)
        marker = runtime._issuance_path(paths, "task-1", tx["permit"]["permit_sha256"]).read_text(encoding="utf-8")
        with h.state_lock(paths, create_layout=False):
            token, _ = h.load_chief_credential(paths, session_id=chief["session_id"], epoch=chief["epoch"], credential_file=credential_path)
        assert token not in marker
        assert "chief_token" not in marker
        assert token not in str(issued)

        tampered = copy.deepcopy(tx)
        tampered["result_domain"]["task_id"] = "different-task"
        with h.state_lock(paths, create_layout=False):
            with pytest.raises(runtime.CodexTransportRuntimeError, match="differs from authenticated"):
                runtime.reserve_codex_launch(paths, tampered, store.load_semantic_events(paths, "task-1"), current_time=NOW, packet_integrity_services=object())  # type: ignore[arg-type]

        with h.state_lock(paths, create_layout=False):
            first = runtime.reserve_codex_launch(paths, tx, store.load_semantic_events(paths, "task-1"), current_time=NOW, packet_integrity_services=object())  # type: ignore[arg-type]
        with h.state_lock(paths, create_layout=False):
            second = runtime.reserve_codex_launch(
                paths,
                tx,
                store.load_semantic_events(paths, "task-1"),
                current_time=datetime(2026, 7, 22, tzinfo=UTC),
                packet_integrity_services=object(),  # type: ignore[arg-type]
            )
        assert first["idempotent_replay"] is False
        assert second["idempotent_replay"] is True
        assert first["semantic_event_sha256"] == second["semantic_event_sha256"]
        marker = runtime.inspect_codex_launch_issuance(
            paths,
            task_id="task-1",
            permit_sha256=tx["permit"]["permit_sha256"],
        )
        assert marker["launch_id"] == "launch-1"
    finally:
        credential_temp.cleanup()
        temp.cleanup()


def test_same_arm_different_launches_have_one_semantic_reservation_winner() -> None:
    temp, credential_temp, paths, chief, credential_path = _filesystem_runtime()
    try:
        first = _live_transaction(paths, chief)
        second = _live_transaction(
            paths,
            chief,
            launch_id="launch-2",
            command_id="reserve-2",
            nonce="nonce-0000000002",
        )
        _issue(paths, chief, credential_path, first)
        _issue(paths, chief, credential_path, second)
        with h.state_lock(paths, create_layout=False):
            runtime.reserve_codex_launch(
                paths,
                first,
                store.load_semantic_events(paths, "task-1"),
                current_time=NOW,
                packet_integrity_services=object(),  # type: ignore[arg-type]
            )
        with h.state_lock(paths, create_layout=False):
            with pytest.raises(
                runtime.CodexTransportRuntimeError,
                match="no longer the terminal semantic transition",
            ):
                runtime.reserve_codex_launch(
                    paths,
                    second,
                    store.load_semantic_events(paths, "task-1"),
                    current_time=NOW,
                    packet_integrity_services=object(),  # type: ignore[arg-type]
                )
        state = semantic.replay_events(store.load_semantic_events(paths, "task-1"))
        packet = state["packets"][0]
        assert packet["transport_ownership"]["launch_id"] == "launch-1"
    finally:
        credential_temp.cleanup()
        temp.cleanup()


def test_process_start_window_uses_earliest_permit_or_arm_expiry() -> None:
    events = chain()
    head = str(events[-1]["event_sha256"])
    raw = intent()
    raw["expected_semantic_head_sha256"] = head
    sealed = contracts.seal_launch_intent(
        {key: raw[key] for key in raw if key != "intent_sha256"}
    )
    decision, original_permit = decision_and_permit(head, sealed)
    permit_base = {
        key: value
        for key, value in original_permit.items()
        if key != "permit_sha256"
    }
    permit_base["expires_at"] = "2026-07-20T00:02:00Z"
    short_permit = permits.seal_transition_permit(permit_base)
    reservation = contracts.seal_reservation(
        {
            "contract_type": contracts.CODEX_TRANSPORT_RESERVATION_V1,
            "reservation_id": "launch-1",
            "launch_intent_sha256": sealed["intent_sha256"],
            "permit_sha256": short_permit["permit_sha256"],
            "runtime_pin": sealed["runtime_pin"],
            "state": "reserved",
            "correlation": {
                "thread_id": None,
                "turn_id": None,
                "item_id": None,
            },
        }
    )
    launch = {
        "task_id": "task-1",
        "launch_id": "launch-1",
        "launch_authority": launch_authority_for(sealed),
        "launch_permit": short_permit,
        "reservation": reservation,
    }
    runtime.require_codex_process_start_window(
        launch,
        current_time=datetime(2026, 7, 20, 0, 1, tzinfo=UTC),
    )
    with pytest.raises(runtime.CodexTransportRuntimeError, match="permit or packet arm"):
        runtime.require_codex_process_start_window(
            launch,
            current_time=datetime(2026, 7, 20, 0, 2, tzinfo=UTC),
        )


def test_process_start_authority_rejects_packet_and_ownership_only_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del tmp_path
    temp, credential_temp, paths, chief, credential_path = _filesystem_runtime()
    try:
        tx = _live_transaction(paths, chief)
        _issue(paths, chief, credential_path, tx)
        with h.state_lock(paths, create_layout=False):
            runtime.reserve_codex_launch(
                paths,
                tx,
                store.load_semantic_events(paths, "task-1"),
                current_time=NOW,
                packet_integrity_services=object(),  # type: ignore[arg-type]
            )
        events = store.load_semantic_events(paths, "task-1")
        launch = runtime.load_codex_transport_launch(
            paths, "task-1", "launch-1", events
        )
        with h.state_lock(paths, create_layout=False):
            runtime.require_codex_process_start_authority(
                paths, launch, events, current_time=NOW
            )
        records, state, head = runtime._live_records(paths, "task-1", events)

        dispatch_model_drift = copy.deepcopy(state)
        dispatch_model_drift["dispatch_model_version"] = 1
        monkeypatch.setattr(
            runtime,
            "_live_records",
            lambda *args, **kwargs: (records, dispatch_model_drift, head),
        )
        with h.state_lock(paths, create_layout=False):
            with pytest.raises(
                runtime.CodexTransportRuntimeError,
                match="no longer bridge-owned dispatched",
            ):
                runtime.require_codex_process_start_authority(
                    paths, launch, events, current_time=NOW
                )

        packet_dispatch_drift = copy.deepcopy(state)
        packet_dispatch_drift["packets"][0]["dispatch_version"] = 1
        packet_dispatch_drift["dispatch_model_version"] = 1
        monkeypatch.setattr(
            runtime,
            "_live_records",
            lambda *args, **kwargs: (records, packet_dispatch_drift, head),
        )
        with h.state_lock(paths, create_layout=False):
            with pytest.raises(
                runtime.CodexTransportRuntimeError,
                match="no longer bridge-owned dispatched",
            ):
                runtime.require_codex_process_start_authority(
                    paths, launch, events, current_time=NOW
                )

        packet_contract_drift = copy.deepcopy(state)
        packet_contract_drift["packets"][0]["packet_contract_sha256"] = SHA_A
        monkeypatch.setattr(
            runtime,
            "_live_records",
            lambda *args, **kwargs: (records, packet_contract_drift, head),
        )
        with h.state_lock(paths, create_layout=False):
            with pytest.raises(
                runtime.CodexTransportRuntimeError,
                match="no longer bridge-owned dispatched",
            ):
                runtime.require_codex_process_start_authority(
                    paths, launch, events, current_time=NOW
                )

        ownership_drift = copy.deepcopy(state)
        original = ownership_drift["packets"][0]["transport_ownership"]
        ownership_base = {
            key: value for key, value in original.items() if key != "ownership_sha256"
        }
        ownership_base["reservation_effective_at"] = "2026-07-20T00:01:01Z"
        changed = contracts.seal_packet_transport_ownership(ownership_base)
        ownership_drift["packets"][0]["transport_ownership"] = changed
        ownership_drift["packets"][0]["dispatch_attempts"][0][
            "transport_ownership"
        ] = changed
        ownership_drift["packets"][0]["dispatch_attempts"][0][
            "closed_at"
        ] = ownership_base["reservation_effective_at"]
        ownership_drift["packets"][0]["dispatch_recorded_at"] = ownership_base[
            "reservation_effective_at"
        ]
        monkeypatch.setattr(
            runtime,
            "_live_records",
            lambda *args, **kwargs: (records, ownership_drift, head),
        )
        with h.state_lock(paths, create_layout=False):
            with pytest.raises(
                runtime.CodexTransportRuntimeError,
                match="semantic projection is invalid|ownership differs",
            ):
                runtime.require_codex_process_start_authority(
                    paths, launch, events, current_time=NOW
                )
    finally:
        credential_temp.cleanup()
        temp.cleanup()


def test_launch_process_lock_serializes_independent_os_processes() -> None:
    temp, credential_temp, paths, chief, credential_path = _filesystem_runtime()
    try:
        tx = _live_transaction(paths, chief)
        _issue(paths, chief, credential_path, tx)
        root = paths.root
        log_path = root / "lock-order.log"
        entered_path = root / "first-entered"
        release_path = root / "release-first"
        script = "\n".join(
            [
                "from pathlib import Path",
                "import sys, time",
                "from aoi_orgware import codex_transport_runtime as runtime",
                "from aoi_orgware import harnesslib as h",
                "root, name, log, entered, release = sys.argv[1:]",
                "paths = h.get_paths(Path(root))",
                "with runtime.codex_launch_process_lock(paths, task_id='task-1', launch_id='launch-1'):",
                "    with Path(log).open('a', encoding='utf-8') as stream:",
                "        stream.write(name + '\\n')",
                "        stream.flush()",
                "    if name == 'first':",
                "        Path(entered).write_text('entered', encoding='utf-8')",
                "        deadline = time.monotonic() + 15",
                "        while not Path(release).exists():",
                "            if time.monotonic() >= deadline:",
                "                raise SystemExit('release timeout')",
                "            time.sleep(0.02)",
            ]
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = str(HERE.parent / "src")
        common = [
            str(root),
            "",
            str(log_path),
            str(entered_path),
            str(release_path),
        ]
        first_args = [sys.executable, "-c", script, *common]
        first_args[-4] = "first"
        second_args = [sys.executable, "-c", script, *common]
        second_args[-4] = "second"
        first = subprocess.Popen(
            first_args,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 10
        while not entered_path.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert entered_path.exists()
        second = subprocess.Popen(
            second_args,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.5)
        assert second.poll() is None
        assert log_path.read_text(encoding="utf-8") == "first\n"
        release_path.write_text("release", encoding="utf-8")
        first_stdout, first_stderr = first.communicate(timeout=15)
        second_stdout, second_stderr = second.communicate(timeout=15)
        assert (first.returncode, first_stdout, first_stderr) == (0, "", "")
        assert (second.returncode, second_stdout, second_stderr) == (0, "", "")
        assert log_path.read_text(encoding="utf-8") == "first\nsecond\n"
    finally:
        credential_temp.cleanup()
        temp.cleanup()


def test_launch_process_lock_rejects_sentinel_and_hardlink_tamper() -> None:
    temp, credential_temp, paths, chief, credential_path = _filesystem_runtime()
    try:
        tx = _live_transaction(paths, chief)
        _issue(paths, chief, credential_path, tx)
        lock_path = runtime._run_lock_path(paths, "task-1", "launch-1")
        lock_path.write_bytes(b"x")
        with pytest.raises(runtime.CodexTransportRuntimeError, match="unsafe|sentinel"):
            with runtime.codex_launch_process_lock(
                paths, task_id="task-1", launch_id="launch-1"
            ):
                pass
        lock_path.write_bytes(b"\0")
        hardlink = lock_path.with_suffix(".hardlink")
        try:
            os.link(lock_path, hardlink)
        except OSError:
            pytest.skip("host filesystem does not permit hardlink falsification")
        with pytest.raises(runtime.CodexTransportRuntimeError, match="unsafe"):
            with runtime.codex_launch_process_lock(
                paths, task_id="task-1", launch_id="launch-1"
            ):
                pass
    finally:
        credential_temp.cleanup()
        temp.cleanup()


def test_filesystem_milestone_and_terminal_publication_recover_exactly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    temp, credential_temp, paths, chief, credential_path = _filesystem_runtime()
    try:
        tx = _live_transaction(paths, chief)
        _issue(paths, chief, credential_path, tx)
        with h.state_lock(paths, create_layout=False):
            rebuilt = runtime.reconstruct_issued_launch_transaction(
                paths,
                task_id="task-1",
                permit_sha256=tx["permit"]["permit_sha256"],
                event_chain=store.load_semantic_events(paths, "task-1"),
                current_time=NOW,
            )
            reserved = runtime.reserve_codex_launch(
                paths,
                rebuilt,
                store.load_semantic_events(paths, "task-1"),
                current_time=NOW,
                packet_integrity_services=object(),  # type: ignore[arg-type]
            )
        assert reserved["idempotent_replay"] is False

        loaded = runtime.load_codex_transport_launch(
            paths, "task-1", "launch-1", store.load_semantic_events(paths, "task-1")
        )
        assert loaded["journal"] == tx["journal"]
        assert loaded["pending_journal_event"] is None
        assert loaded["task_completion"] == "not_inferred"

        prior = loaded["journal"]
        pending = runtime._event_for(
            loaded["intent"],
            loaded["reservation"],
            event_id="launch-1:2:process-start-pending",
            sequence=2,
            previous=prior[-1]["event_sha256"],
            event_type="process_start_pending",
            correlation={"thread_id": None, "turn_id": None, "item_id": None},
            request_id="process:launch-1",
            request_bytes_sha256=SHA_A,
            payload_size_bytes=42,
        )

        original_append = store.append_semantic_transition

        def crash_before_semantic_event(*args: object, **kwargs: object) -> object:
            raise store.SemanticStoreError("simulated response-loss boundary")

        monkeypatch.setattr(store, "append_semantic_transition", crash_before_semantic_event)
        with h.state_lock(paths, create_layout=False):
            with pytest.raises(store.SemanticStoreError, match="simulated"):
                runtime.record_milestone(
                    paths,
                    task_id="task-1",
                    launch_id="launch-1",
                    intent=loaded["intent"],
                    reservation=loaded["reservation"],
                    journal=prior,
                    milestone=pending,
                    event_chain=store.load_semantic_events(paths, "task-1"),
                )
        after_object_crash = runtime.load_codex_transport_launch(
            paths, "task-1", "launch-1", store.load_semantic_events(paths, "task-1")
        )
        assert after_object_crash["journal"] == prior
        assert after_object_crash["pending_journal_event"] == pending

        monkeypatch.setattr(store, "append_semantic_transition", original_append)
        with h.state_lock(paths, create_layout=False):
            committed_pending = runtime.record_milestone(
                paths,
                task_id="task-1",
                launch_id="launch-1",
                intent=loaded["intent"],
                reservation=loaded["reservation"],
                journal=prior,
                milestone=pending,
                event_chain=store.load_semantic_events(paths, "task-1"),
            )
        with h.state_lock(paths, create_layout=False):
            replayed_pending = runtime.record_milestone(
                paths,
                task_id="task-1",
                launch_id="launch-1",
                intent=loaded["intent"],
                reservation=loaded["reservation"],
                journal=prior,
                milestone=pending,
                event_chain=store.load_semantic_events(paths, "task-1"),
            )
        assert committed_pending["idempotent_replay"] is False
        assert replayed_pending["idempotent_replay"] is True
        assert committed_pending["semantic_event_sha256"] == replayed_pending["semantic_event_sha256"]

        journal = committed_pending["journal"]
        failed = runtime._event_for(
            loaded["intent"],
            loaded["reservation"],
            event_id="launch-1:3:failed",
            sequence=3,
            previous=journal[-1]["event_sha256"],
            event_type="failed",
            correlation={"thread_id": None, "turn_id": None, "item_id": None},
            fault_kind="RuntimeDisconnected",
            fault_evidence_sha256=SHA_B,
            fault_evidence_size_bytes=19,
            payload_size_bytes=19,
        )
        assert failed["wire_event_sha256"] is None
        assert failed["response_sha256"] is None
        with h.state_lock(paths, create_layout=False):
            committed_failed = runtime.record_milestone(
                paths,
                task_id="task-1",
                launch_id="launch-1",
                intent=loaded["intent"],
                reservation=loaded["reservation"],
                journal=journal,
                milestone=failed,
                event_chain=store.load_semantic_events(paths, "task-1"),
            )
        terminal_journal = committed_failed["journal"]
        terminal_state = contracts.validate_transport_journal(terminal_journal)
        receipt = contracts.seal_terminal_receipt(
            {
                "contract_type": contracts.CODEX_TRANSPORT_TERMINAL_RECEIPT_V1,
                "reservation_sha256": loaded["reservation"]["reservation_sha256"],
                "journal_head_sha256": terminal_state.head_sha256,
                "terminal_state": "failed",
                "correlation": terminal_state.correlation,
                "evidence_level": "codex_runtime_observed",
                "mutation_verification": {"status": "unavailable", "object_sha256": None},
            }
        )

        monkeypatch.setattr(store, "append_semantic_transition", crash_before_semantic_event)
        with h.state_lock(paths, create_layout=False):
            with pytest.raises(store.SemanticStoreError, match="simulated"):
                runtime.publish_terminal_receipt(
                    paths,
                    task_id="task-1",
                    launch_id="launch-1",
                    intent=loaded["intent"],
                    reservation=loaded["reservation"],
                    journal=terminal_journal,
                    receipt=receipt,
                    event_chain=store.load_semantic_events(paths, "task-1"),
                )
        after_terminal_object_crash = runtime.load_codex_transport_launch(
            paths, "task-1", "launch-1", store.load_semantic_events(paths, "task-1")
        )
        assert after_terminal_object_crash["terminal_receipt"] is None
        assert after_terminal_object_crash["pending_terminal_receipt"] == receipt

        monkeypatch.setattr(store, "append_semantic_transition", original_append)
        with h.state_lock(paths, create_layout=False):
            committed_receipt = runtime.publish_terminal_receipt(
                paths,
                task_id="task-1",
                launch_id="launch-1",
                intent=loaded["intent"],
                reservation=loaded["reservation"],
                journal=terminal_journal,
                receipt=receipt,
                event_chain=store.load_semantic_events(paths, "task-1"),
            )
        with h.state_lock(paths, create_layout=False):
            replayed_receipt = runtime.publish_terminal_receipt(
                paths,
                task_id="task-1",
                launch_id="launch-1",
                intent=loaded["intent"],
                reservation=loaded["reservation"],
                journal=terminal_journal,
                receipt=receipt,
                event_chain=store.load_semantic_events(paths, "task-1"),
            )
        assert committed_receipt["idempotent_replay"] is False
        assert replayed_receipt["idempotent_replay"] is True
        assert committed_receipt["semantic_event_sha256"] == replayed_receipt["semantic_event_sha256"]

        final = runtime.load_codex_transport_launch(
            paths, "task-1", "launch-1", store.load_semantic_events(paths, "task-1")
        )
        assert final["terminal_receipt"] == receipt
        assert final["pending_terminal_receipt"] is None
        assert final["task_completion"] == "not_inferred"
    finally:
        credential_temp.cleanup()
        temp.cleanup()
