from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

import pytest

from aoi_orgware import checkpoint_compaction as compaction
from aoi_orgware import harnesslib as h


def _state(facts: list[str]) -> dict[str, object]:
    return {
        "task_id": "checkpoint-fact-tail",
        "revision": 1,
        "updated_at": "2026-08-02T00:00:00Z",
        "status": "active",
        "phase": "implementing",
        "plan_ready": True,
        "plan_sha256": "a" * 64,
        "objective": "Preserve checkpoint truth.",
        "completion_boundary": "Only a bounded fact tail may be omitted.",
        "claims": [],
        "facts": facts,
        "decisions": [],
        "rejected_paths": [],
        "changed_files": [],
        "verification": [],
        "jobs": [],
        "packets": [],
        "subagent_incidents": [],
        "blockers": [],
        "risks": [],
        "delivery": {"mode": "pending", "detail": "", "commit": ""},
        "next_action": "Continue from the exact checkpoint.",
    }


def _paths(tmp_path: Path) -> h.HarnessPaths:
    root = tmp_path / "repo"
    root.mkdir()
    return h.get_paths(root)


def _install_durable_stub(paths: h.HarnessPaths, task_id: str) -> None:
    h.ensure_layout(paths)
    directory = h.task_dir(paths, task_id)
    directory.mkdir(parents=True)
    (directory / "state.json").write_text("{}", encoding="utf-8")


def _fact_digest(facts: list[str]) -> str:
    payload = json.dumps(
        facts,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _field_history_digest(field: str, entries: list[str]) -> str:
    payload = json.dumps(
        ["aoi-checkpoint-string-history-v1", field, entries],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize("field", compaction.CHECKPOINT_STRING_HISTORY_FIELDS)
def test_string_history_tail_zero_keeps_both_digests_without_verbatim_entries(
    field: str,
) -> None:
    entries = [f"entry-{index}" for index in range(16)]
    summary = compaction.compact_string_history(
        entries,
        field=field,
        minimum_count=16,
        recent_tail=0,
        state_record_ref=f"tasks/t/state.json#{field}",
    )

    assert summary is not None
    assert summary.recent == ()
    assert f"count=16; history_sha256={_fact_digest(entries)}" in summary.marker
    assert f"record=tasks/t/state.json#{field}; recent_verbatim=0" in summary.marker
    assert "format=aoi-checkpoint-string-history-v1" in summary.marker
    assert f"field={field}; total_count=16; omitted_source_entries=16" in summary.marker
    assert f"field_history_sha256={_field_history_digest(field, entries)}" in summary.marker
    assert summary.marker.endswith("recent_source_entries=0")


def test_field_history_digest_is_domain_separated() -> None:
    entries = ["same-entry"]
    assert len(
        {
            _field_history_digest(field, entries)
            for field in compaction.CHECKPOINT_STRING_HISTORY_FIELDS
        }
    ) == len(compaction.CHECKPOINT_STRING_HISTORY_FIELDS)


def _field_digest_from_marker(marker: str) -> str:
    return marker.split("field_history_sha256=", 1)[1].split(";", 1)[0]


def test_string_history_digest_binds_order_unicode_whitespace_and_marker_text() -> None:
    original = ["alpha", "é", "omega"]
    mutations = [
        ["omega", "é", "alpha"],
        ["alpha", "e\u0301", "omega"],
        ["alpha ", "é", "omega"],
        ["alpha", "é", "field=facts; history_sha256=" + "0" * 64],
    ]
    base = compaction.compact_string_history(
        original,
        field="decisions",
        minimum_count=0,
        recent_tail=0,
        state_record_ref="tasks/t/state.json#decisions",
    )
    assert base is not None
    observed = {_field_digest_from_marker(base.marker)}
    for entries in mutations:
        summary = compaction.compact_string_history(
            entries,
            field="decisions",
            minimum_count=0,
            recent_tail=0,
            state_record_ref="tasks/t/state.json#decisions",
        )
        assert summary is not None
        observed.add(_field_digest_from_marker(summary.marker))
    assert len(observed) == len(mutations) + 1


def test_string_history_rejects_open_fields_mismatched_refs_and_open_maps() -> None:
    with pytest.raises(ValueError, match="field is not allowed"):
        compaction.compact_string_history(
            ["entry"],
            field="blockers",
            minimum_count=0,
            recent_tail=0,
            state_record_ref="tasks/t/state.json#blockers",
        )
    with pytest.raises(ValueError, match="record reference"):
        compaction.compact_string_history(
            ["entry"],
            field="facts",
            minimum_count=0,
            recent_tail=0,
            state_record_ref="tasks/t/state.json#decisions",
        )
    with pytest.raises(ValueError, match="closed field set"):
        compaction.project_checkpoint_string_histories(
            {"facts": (["entry"], "tasks/t/state.json#facts")},
            compact=True,
            minimum_count=0,
            recent_tail=0,
        )
    histories = {
        field: (["entry"], f"tasks/t/state.json#{field}")
        for field in compaction.CHECKPOINT_STRING_HISTORY_FIELDS
    }
    with pytest.raises(ValueError, match="required checkpoint history tail"):
        compaction.project_checkpoint_string_histories(
            histories,
            compact=True,
            minimum_count=16,
            recent_tail=0,
            policy=compaction.CheckpointStringHistoryPolicy(
                frozenset(), (2, 0, 0, 0)
            ),
        )


def test_fact_history_reports_only_tail_entries_rendered_verbatim() -> None:
    facts = [
        *(f"fact-{index}" for index in range(12)),
        "clean",
        " padded ",
        "   ",
        "line-one\nline-two",
    ]
    summary = compaction.compact_fact_history(
        facts,
        minimum_count=16,
        recent_tail=4,
        state_record_ref="tasks/t/state.json#facts",
    )

    assert summary is not None
    assert summary.recent == (
        "clean",
        " padded ",
        "   ",
        "line-one\nline-two",
    )
    assert "recent_source_entries=4" in summary.marker
    assert "recent_verbatim=2" in summary.marker


def test_fact_history_rejects_string_subclasses_before_rendering() -> None:
    class MisleadingString(str):
        def strip(self, chars: str | None = None) -> str:
            del chars
            return "clean"

    facts = ["fact"] * 15 + [MisleadingString(" padded ")]
    with pytest.raises(TypeError, match="exact strings"):
        compaction.compact_fact_history(
            facts,
            minimum_count=16,
            recent_tail=1,
            state_record_ref="tasks/t/state.json#facts",
        )


def test_prepare_checkpoint_rejects_string_subclass_before_formatting(
    tmp_path: Path,
) -> None:
    calls = 0

    class SpoofedString(str):
        def __str__(self) -> str:
            nonlocal calls
            calls += 1
            return "spoofed-checkpoint-fact"

    state = _state([SpoofedString("underlying-state-fact")])
    with pytest.raises(h.HarnessError, match="exact JSON builtins"):
        h.prepare_checkpoint(_paths(tmp_path), state)
    assert calls == 0


def test_prepare_checkpoint_selects_largest_fitting_fact_tail(tmp_path: Path) -> None:
    facts = [f"[FACT-{index:02d}]" + "x" * 4100 for index in range(16)]
    state = _state(facts)
    before = copy.deepcopy(state)
    paths = _paths(tmp_path)

    tail_eight = h._render_checkpoint_snapshot(
        paths, state, compact_terminal_detail=True
    )
    tail_seven = h._render_checkpoint_snapshot(
        paths,
        state,
        compact_terminal_detail=True,
        history_tail=7,
    )
    assert len(tail_eight.encode("utf-8")) > h.CHECKPOINT_MAX_BYTES
    assert len(tail_seven.encode("utf-8")) <= h.CHECKPOINT_MAX_BYTES

    _, prepared, digest = h.prepare_checkpoint(paths, state)
    _, repeated, repeated_digest = h.prepare_checkpoint(paths, state)

    assert prepared == tail_seven
    assert repeated == prepared
    assert repeated_digest == digest == hashlib.sha256(prepared.encode()).hexdigest()
    assert f"history_sha256={_fact_digest(facts)}" in prepared
    assert "recent_source_entries=7" in prepared
    assert "recent_verbatim=7" in prepared
    assert "[FACT-08]" not in prepared
    for index in range(9, 16):
        assert f"[FACT-{index:02d}]" in prepared
    assert state == before

    changed = copy.deepcopy(state)
    changed["facts"][0] = "changed-non-tail-fact"  # type: ignore[index]
    assert h.prepare_checkpoint(paths, changed)[1] != prepared


def test_prepare_checkpoint_can_select_zero_fact_tail(tmp_path: Path) -> None:
    facts = [f"[FACT-{index:02d}]" + "z" * 34000 for index in range(16)]
    state = _state(facts)
    before = copy.deepcopy(state)
    paths = _paths(tmp_path)

    tail_one = h._render_checkpoint_snapshot(
        paths,
        state,
        compact_terminal_detail=True,
        history_tail=1,
    )
    assert len(tail_one.encode("utf-8")) > h.CHECKPOINT_MAX_BYTES

    _, prepared, _ = h.prepare_checkpoint(paths, state)

    assert len(prepared.encode("utf-8")) <= h.CHECKPOINT_MAX_BYTES
    assert "recent_source_entries=0" in prepared
    assert "recent_verbatim=0" in prepared
    assert "[FACT-" not in prepared
    assert f"history_sha256={_fact_digest(facts)}" in prepared
    assert state == before


@pytest.mark.parametrize("field", compaction.CHECKPOINT_STRING_HISTORY_FIELDS)
def test_low_count_oversized_history_is_forced_to_zero_tail(
    tmp_path: Path,
    field: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state([])
    sentinel = f"[{field}-PRIVATE]" + "x" * 40_000
    state[field] = [sentinel]
    before = copy.deepcopy(state)
    paths = _paths(tmp_path)
    _install_durable_stub(paths, str(state["task_id"]))
    monkeypatch.setattr(h, "load_task", lambda _paths, _task_id: copy.deepcopy(state))

    with pytest.raises(h.HarnessError, match="checkpoint exceeds 32 KiB"):
        h.prepare_checkpoint(paths, state)
    with h.state_lock(paths):
        _, prepared, _ = h.prepare_checkpoint(paths, state)

    assert len(prepared.encode("utf-8")) <= h.CHECKPOINT_MAX_BYTES
    assert f"field={field}; total_count=1; omitted_source_entries=1" in prepared
    assert "recent_source_entries=0" in prepared
    assert sentinel not in prepared
    assert state == before


@pytest.mark.parametrize("field", compaction.CHECKPOINT_STRING_HISTORY_FIELDS)
def test_new_low_count_oversized_history_is_not_force_compacted(
    tmp_path: Path,
    field: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    durable = _state([])
    candidate = copy.deepcopy(durable)
    candidate[field] = [f"[{field}-NEW]" + "x" * 40_000]
    paths = _paths(tmp_path)
    _install_durable_stub(paths, str(candidate["task_id"]))
    monkeypatch.setattr(h, "load_task", lambda _paths, _task_id: durable)

    with h.state_lock(paths), pytest.raises(
        h.HarnessError, match="checkpoint exceeds 32 KiB"
    ):
        h.prepare_checkpoint(paths, candidate)


def test_durable_prefix_policy_preserves_new_suffix_per_field(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    durable = _state([])
    old = "[DURABLE-FACT]" + "x" * 40_000
    durable["facts"] = [old]
    candidate = copy.deepcopy(durable)
    candidate["facts"].append("NEW-FACT-MUST-REMAIN")  # type: ignore[union-attr]
    candidate["decisions"] = ["NEW-DECISION-MUST-REMAIN"]
    paths = _paths(tmp_path)
    _install_durable_stub(paths, str(candidate["task_id"]))
    monkeypatch.setattr(h, "load_task", lambda _paths, _task_id: durable)

    with h.state_lock(paths):
        _, prepared, _ = h.prepare_checkpoint(paths, candidate)

    assert old not in prepared
    assert "NEW-FACT-MUST-REMAIN" in prepared
    assert "NEW-DECISION-MUST-REMAIN" in prepared
    assert "field=facts; total_count=2; omitted_source_entries=1" in prepared
    assert "field=decisions; total_count=1; omitted_source_entries=0" in prepared


def test_soft_compaction_preserves_every_new_suffix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    durable = _state(["DURABLE-OLD"])
    candidate = copy.deepcopy(durable)
    added = [f"NEW-{index:02d}-" + "x" * 1_200 for index in range(15)]
    candidate["facts"].extend(added)  # type: ignore[union-attr]
    paths = _paths(tmp_path)
    _install_durable_stub(paths, str(candidate["task_id"]))
    monkeypatch.setattr(h, "load_task", lambda _paths, _task_id: durable)
    full = h._render_checkpoint_snapshot(paths, candidate)
    assert h.CHECKPOINT_COMPACT_THRESHOLD_BYTES < len(full.encode("utf-8"))
    assert len(full.encode("utf-8")) <= h.CHECKPOINT_MAX_BYTES

    with h.state_lock(paths):
        _, prepared, _ = h.prepare_checkpoint(paths, candidate)

    assert "field=facts; total_count=16; omitted_source_entries=1" in prepared
    assert all(item in prepared for item in added)


def test_durable_history_policy_rejects_nonappend_changes() -> None:
    durable = _state(["alpha", "beta"])
    for facts in (["beta", "alpha"], ["alpha"], ["alpha", "changed"]):
        candidate = copy.deepcopy(durable)
        candidate["facts"] = facts
        with pytest.raises(ValueError, match="durable prefix"):
            compaction.derive_durable_string_history_policy(
                candidate, durable, minimum_count=16
            )

    duplicate = copy.deepcopy(durable)
    duplicate["facts"].append("beta")  # type: ignore[union-attr]
    policy = compaction.derive_durable_string_history_policy(
        duplicate, durable, minimum_count=16
    )
    assert policy.required_tails == (1, 0, 0, 0)


def test_combined_histories_use_one_largest_fitting_shared_tail(tmp_path: Path) -> None:
    state = _state([])
    for field in compaction.CHECKPOINT_STRING_HISTORY_FIELDS:
        state[field] = [
            f"[{field}-{index:02d}]" + chr(97 + index % 26) * 1_100
            for index in range(16)
        ]
    before = copy.deepcopy(state)
    paths = _paths(tmp_path)

    default = h._render_checkpoint_snapshot(
        paths,
        state,
        compact_terminal_detail=True,
        policy=compaction.CheckpointStringHistoryPolicy(
            frozenset(compaction.CHECKPOINT_STRING_HISTORY_FIELDS),
            (0, 0, 0, 0),
        ),
    )
    assert len(default.encode("utf-8")) > h.CHECKPOINT_MAX_BYTES
    _, prepared, digest = h.prepare_checkpoint(paths, state)
    _, repeated, repeated_digest = h.prepare_checkpoint(paths, state)

    lines = [
        line
        for line in prepared.splitlines()
        if "format=aoi-checkpoint-string-history-v1" in line
    ]
    counts = {
        int(re.search(r"recent_source_entries=(\d+)$", line).group(1))
        for line in lines
    }
    assert len(lines) == len(compaction.CHECKPOINT_STRING_HISTORY_FIELDS)
    assert len(counts) == 1
    (shared_tail,) = counts
    assert 0 <= shared_tail < h.COMPACT_FACT_RECENT_TAIL
    if shared_tail < h.COMPACT_FACT_RECENT_TAIL - 1:
        larger = h._render_checkpoint_snapshot(
            paths,
            state,
            compact_terminal_detail=True,
            history_tail=shared_tail + 1,
            policy=compaction.CheckpointStringHistoryPolicy(
                frozenset(compaction.CHECKPOINT_STRING_HISTORY_FIELDS),
                (0, 0, 0, 0),
            ),
        )
        assert len(larger.encode("utf-8")) > h.CHECKPOINT_MAX_BYTES
    assert len(prepared.encode("utf-8")) <= h.CHECKPOINT_MAX_BYTES
    assert repeated == prepared
    assert repeated_digest == digest
    assert state == before


def test_compaction_preserves_blockers_open_risks_and_running_jobs(tmp_path: Path) -> None:
    state = _state([])
    state["decisions"] = ["decision-" + "d" * 2_000 for _ in range(24)]
    state["blockers"] = ["BLOCKER-SENTINEL"]
    state["risks"] = ["OPEN-RISK-SENTINEL"]
    state["jobs"] = [
        {
            "run_id": "protected-running-job",
            "status": "running",
            "host": "local",
            "tool": "pytest",
            "log": "PROTECTED-JOB-LOG",
            "pid": "42",
            "tmux": "n/a",
            "stop_condition": "PROTECTED-JOB-STOP",
            "source_sha": "c" * 64,
            "source_scope": "PROTECTED-JOB-SCOPE",
            "evidence": "PROTECTED-JOB-EVIDENCE",
        }
    ]

    _, prepared, _ = h.prepare_checkpoint(_paths(tmp_path), state)

    for sentinel in (
        "BLOCKER: BLOCKER-SENTINEL",
        "RISK: OPEN-RISK-SENTINEL",
        "protected-running-job [running]",
        "PROTECTED-JOB-STOP",
        "PROTECTED-JOB-EVIDENCE",
    ):
        assert sentinel in prepared


def test_zero_fact_tail_does_not_hide_oversized_active_detail(tmp_path: Path) -> None:
    facts = [f"fact-{index}" for index in range(16)]
    state = _state(facts)
    sentinel = "ACTIVE-EVIDENCE-" + "q" * 36000
    state["jobs"] = [
        {
            "run_id": "active-job",
            "status": "running",
            "host": "local",
            "tool": "pytest",
            "log": "run.log",
            "pid": "1234",
            "tmux": "n/a",
            "stop_condition": sentinel,
            "source_sha": "c" * 64,
            "source_scope": "current source",
            "evidence": "still active",
        }
    ]
    before = copy.deepcopy(state)
    paths = _paths(tmp_path)

    zero_tail = h._render_checkpoint_snapshot(
        paths,
        state,
        compact_terminal_detail=True,
        history_tail=0,
    )
    assert sentinel in zero_tail
    assert len(zero_tail.encode("utf-8")) > h.CHECKPOINT_MAX_BYTES

    with pytest.raises(h.HarnessError, match="checkpoint exceeds 32 KiB"):
        h.prepare_checkpoint(paths, state)
    assert state == before


def test_compact_checkpoint_keeps_every_engaged_lane(tmp_path: Path) -> None:
    facts = [f"fact-{index}-" + "x" * 2100 for index in range(16)]
    state = _state(facts)
    state["lanes"] = [
        {
            "lane_id": f"lane-{index:02d}",
            "status": "active",
            "revision": 1,
            "owner": f"owner-{index:02d}",
            "next_action": f"continue-lane-{index:02d}",
        }
        for index in range(12)
    ]
    paths = _paths(tmp_path)

    _, prepared, _ = h.prepare_checkpoint(paths, state)

    assert len(prepared.encode("utf-8")) <= h.CHECKPOINT_MAX_BYTES
    assert "additional engaged lanes omitted" not in prepared
    for index in range(12):
        assert f"lane-{index:02d} [active]" in prepared
        assert f"owner=owner-{index:02d}" in prepared
        assert f"next=continue-lane-{index:02d}" in prepared


@pytest.mark.parametrize("full_size", (32_183, 32_184, h.CHECKPOINT_MAX_BYTES))
def test_valid_full_checkpoint_survives_oversized_compact_render(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    full_size: int,
) -> None:
    full = "f" * full_size
    compact = "c" * (h.CHECKPOINT_MAX_BYTES + 1)
    calls: list[tuple[bool, int | None, compaction.CheckpointStringHistoryPolicy]] = []

    def render(
        paths: h.HarnessPaths,
        state: dict[str, object],
        *,
        compact_terminal_detail: bool = False,
        history_tail: int | None = None,
        policy: compaction.CheckpointStringHistoryPolicy = (
            compaction.EMPTY_CHECKPOINT_STRING_HISTORY_POLICY
        ),
    ) -> str:
        del paths, state
        calls.append((compact_terminal_detail, history_tail, policy))
        return compact if compact_terminal_detail else full

    monkeypatch.setattr(h, "_render_checkpoint_snapshot", render)
    _, prepared, digest = h.prepare_checkpoint(_paths(tmp_path), _state(["fact"]))

    assert prepared == full
    assert digest == hashlib.sha256(full.encode()).hexdigest()
    assert calls == [
        (False, None, compaction.EMPTY_CHECKPOINT_STRING_HISTORY_POLICY),
        (True, 8, compaction.EMPTY_CHECKPOINT_STRING_HISTORY_POLICY),
    ]


def test_first_fitting_text_uses_descending_tail_order() -> None:
    observed: list[int] = []

    def render(recent_tail: int) -> str:
        observed.append(recent_tail)
        return "x" * (recent_tail + 1)

    assert compaction.first_fitting_text(
        render=render,
        highest_recent_tail=3,
        max_bytes=3,
    ) == "xxx"
    assert observed == [3, 2]


def test_public_renderer_cannot_select_compaction(tmp_path: Path) -> None:
    state = _state([f"fact-{index}" for index in range(16)])
    paths = _paths(tmp_path)

    full = h.render_checkpoint(paths, state)

    assert "fact-0" in full
    assert "Established fact history:" not in full
    with pytest.raises(TypeError, match="unexpected keyword"):
        h.render_checkpoint(  # type: ignore[call-arg]
            paths,
            state,
            compact_terminal_detail=True,
        )


def test_write_checkpoint_preserves_state_object_and_state_file_bytes(
    tmp_path: Path,
) -> None:
    state = _state([])
    state["changed_files"] = ["changed-" + "c" * 3_000 for _ in range(16)]
    before = copy.deepcopy(state)
    paths = _paths(tmp_path)
    directory = h.task_dir(paths, str(state["task_id"]))
    directory.mkdir(parents=True)
    state_path = directory / "state.json"
    state_bytes = (json.dumps(state, ensure_ascii=False, indent=2) + "\n").encode()
    state_path.write_bytes(state_bytes)
    destination = h.write_checkpoint(paths, state)

    assert destination.is_file()
    assert len(destination.read_bytes()) <= h.CHECKPOINT_MAX_BYTES
    assert state == before
    assert state_path.read_bytes() == state_bytes


def test_checkpoint_matches_is_hash_only_and_missing_or_corrupt_is_false(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state = _state(["fact"])
    paths = _paths(tmp_path)
    directory = h.task_dir(paths, str(state["task_id"]))
    directory.mkdir(parents=True)
    destination, prepared, digest = h.prepare_checkpoint(paths, state)
    destination.write_bytes(prepared.encode("utf-8"))
    state.update(
        checkpoint_required=False,
        checkpoint_revision=state["revision"],
        checkpoint_sha256=digest,
    )

    def fail_renderer(*args: object, **kwargs: object) -> str:
        del args, kwargs
        raise AssertionError("checkpoint_matches must not re-render")

    monkeypatch.setattr(h, "_render_checkpoint_snapshot", fail_renderer)
    assert h.checkpoint_matches(paths, state) == (True, "current")
    destination.unlink()
    assert h.checkpoint_matches(paths, state) == (False, "checkpoint file is missing")
    destination.write_text("corrupt", encoding="utf-8")
    assert h.checkpoint_matches(paths, state) == (
        False,
        "checkpoint file SHA-256 differs from state",
    )


def test_prepare_rejects_nonfact_subclasses_before_callbacks(tmp_path: Path) -> None:
    calls = 0

    class CallbackList(list[object]):
        def __iter__(self):  # type: ignore[no-untyped-def]
            nonlocal calls
            calls += 1
            return super().__iter__()

    state = _state(["fact"])
    state["verification"] = CallbackList()

    with pytest.raises(h.HarnessError, match="exact JSON builtins"):
        h.prepare_checkpoint(_paths(tmp_path), state)
    assert calls == 0


def test_prepare_rejects_state_and_scalar_subclasses_before_callbacks(
    tmp_path: Path,
) -> None:
    state_calls = 0
    scalar_calls = 0

    class CallbackState(dict[str, object]):
        def __getitem__(self, key: str) -> object:
            nonlocal state_calls
            state_calls += 1
            return super().__getitem__(key)

    class CallbackString(str):
        def __str__(self) -> str:
            nonlocal scalar_calls
            scalar_calls += 1
            return "changed-identity"

    plain = _state(["fact"])
    paths = _paths(tmp_path)
    with pytest.raises(h.HarnessError, match="exact JSON builtins"):
        h.prepare_checkpoint(paths, CallbackState(plain))
    assert state_calls == 0

    plain["task_id"] = CallbackString("checkpoint-fact-tail")
    with pytest.raises(h.HarnessError, match="exact JSON builtins"):
        h.prepare_checkpoint(paths, plain)
    assert scalar_calls == 0


def test_prepare_rejects_cycles_and_excessive_nesting_as_typed_errors(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    cyclic = _state(["fact"])
    cycle: list[object] = []
    cycle.append(cycle)
    cyclic["decisions"] = cycle
    with pytest.raises(h.HarnessError, match="must not contain cycles"):
        h.prepare_checkpoint(paths, cyclic)

    deep = _state(["fact"])
    nested: list[object] = []
    deep["decisions"] = nested
    for _ in range(1200):
        child: list[object] = []
        nested.append(child)
        nested = child
    with pytest.raises(h.HarnessError, match="nesting exceeds the safe limit"):
        h.prepare_checkpoint(paths, deep)


def test_prepare_uses_one_detached_snapshot_across_render_passes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sentinel = "PENDING-VERIFICATION-MUST-REMAIN"
    state = _state([f"fact-{index}-" + "x" * 1600 for index in range(16)])
    state["verification"] = [
        {
            "category": "runtime",
            "status": "pending",
            "evidence": sentinel,
            "command": "pending-command",
            "boundary": "not terminal",
        }
    ]
    original = h._render_checkpoint_snapshot
    calls = 0

    def render(
        paths: h.HarnessPaths,
        snapshot: dict[str, object],
        *,
        compact_terminal_detail: bool = False,
        history_tail: int | None = None,
        policy: compaction.CheckpointStringHistoryPolicy = (
            compaction.EMPTY_CHECKPOINT_STRING_HISTORY_POLICY
        ),
    ) -> str:
        nonlocal calls
        text = original(
            paths,
            snapshot,
            compact_terminal_detail=compact_terminal_detail,
            history_tail=history_tail,
            policy=policy,
        )
        calls += 1
        if calls == 1:
            state["verification"] = []
            state["task_id"] = "changed-after-snapshot"
        return text

    monkeypatch.setattr(h, "_render_checkpoint_snapshot", render)
    destination, prepared, _ = h.prepare_checkpoint(_paths(tmp_path), state)

    assert calls >= 2
    assert destination.parent.name == "checkpoint-fact-tail"
    assert prepared.startswith("# Checkpoint — checkpoint-fact-tail\n")
    assert "record=tasks/checkpoint-fact-tail/state.json#facts" in prepared
    assert "changed-after-snapshot" not in prepared
    assert sentinel in prepared
