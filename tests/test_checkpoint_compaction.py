from __future__ import annotations

import copy
import hashlib
import json
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


def _fact_digest(facts: list[str]) -> str:
    payload = json.dumps(
        facts,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def test_fact_history_tail_zero_keeps_digest_without_verbatim_facts() -> None:
    facts = [f"fact-{index}" for index in range(16)]
    summary = compaction.compact_fact_history(
        facts,
        minimum_count=16,
        recent_tail=0,
        state_record_ref="tasks/t/state.json#facts",
    )

    assert summary is not None
    assert summary.recent == ()
    assert summary.marker == (
        "Established fact history: count=16; "
        f"history_sha256={_fact_digest(facts)}; "
        "record=tasks/t/state.json#facts; recent_verbatim=0; "
        "recent_source_entries=0"
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
        compact_fact_recent_tail=7,
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
        compact_fact_recent_tail=1,
    )
    assert len(tail_one.encode("utf-8")) > h.CHECKPOINT_MAX_BYTES

    _, prepared, _ = h.prepare_checkpoint(paths, state)

    assert len(prepared.encode("utf-8")) <= h.CHECKPOINT_MAX_BYTES
    assert "recent_source_entries=0" in prepared
    assert "recent_verbatim=0" in prepared
    assert "[FACT-" not in prepared
    assert f"history_sha256={_fact_digest(facts)}" in prepared
    assert state == before


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
        compact_fact_recent_tail=0,
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
    calls: list[tuple[bool, int | None]] = []

    def render(
        paths: h.HarnessPaths,
        state: dict[str, object],
        *,
        compact_terminal_detail: bool = False,
        compact_fact_recent_tail: int | None = None,
    ) -> str:
        del paths, state
        calls.append((compact_terminal_detail, compact_fact_recent_tail))
        return compact if compact_terminal_detail else full

    monkeypatch.setattr(h, "_render_checkpoint_snapshot", render)
    _, prepared, digest = h.prepare_checkpoint(_paths(tmp_path), _state(["fact"]))

    assert prepared == full
    assert digest == hashlib.sha256(full.encode()).hexdigest()
    assert calls == [(False, None), (True, None)]


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
        compact_fact_recent_tail: int | None = None,
    ) -> str:
        nonlocal calls
        text = original(
            paths,
            snapshot,
            compact_terminal_detail=compact_terminal_detail,
            compact_fact_recent_tail=compact_fact_recent_tail,
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
