from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aoi_orgware.resource_config import make_resource_receipt, resource_plan_sha256
from aoi_orgware import cli as cli_impl
from aoi_orgware import dispatch_protocol
from aoi_orgware import resource_config as rc
from aoi_orgware.config import load_config
from aoi_orgware.routing_authority import (
    MAX_RECORD_BYTES,
    RoutingAuthorityError,
    authority_sha256,
    build_arm_authority,
    build_dispatch_outcome,
    build_legacy_outcome,
    capacity_routing_view,
    codex_observation_event_id,
    outcome_sha256,
    resource_files_manifest_sha256,
    seal_session_registration,
    seal_startup_receipt,
    validate_arm_authority,
    validate_dispatch_outcome,
)
from aoi_orgware.semantic_events import canonical_json_bytes, canonical_sha256
from tests.harness_case import HarnessTestCase


def sha(char: str) -> str:
    return char * 64


def assignment(
    model: str,
    profile: str,
    *,
    source: bytes,
) -> dict[str, str]:
    return {
        "capability_tier": "standard",
        "profile": profile,
        "model": model,
        "model_reasoning_effort": "high",
        "profile_source_kind": "user_template",
        "profile_source_sha256": hashlib.sha256(source).hexdigest(),
    }


def real_resource(
    event_id: str = "event-1",
    *,
    config_after: bytes = b"max_threads = 2\n",
) -> tuple[dict, dict, dict]:
    review_source = b"name = 'review'\nmodel = 'gpt-old'\n"
    build_source = b"name = 'build'\nmodel = 'gpt-old'\n"
    agents = {
        "explorer": assignment("gpt-sol", "review", source=review_source),
        "worker": assignment("gpt-terra", "build", source=build_source),
    }
    files = [
        {
            "relative_path": ".codex/config.toml",
            "before": None,
            "after": config_after,
            "source_kind": "generated",
            "source_sha256": hashlib.sha256(b"").hexdigest(),
        },
        {
            "relative_path": ".codex/agents/review.toml",
            "before": None,
            "after": b"name = 'review'\nmodel = 'gpt-sol'\n",
            "source_kind": "user_template",
            "source_sha256": hashlib.sha256(review_source).hexdigest(),
        },
        {
            "relative_path": ".codex/agents/build.toml",
            "before": None,
            "after": b"name = 'build'\nmodel = 'gpt-terra'\n",
            "source_kind": "user_template",
            "source_sha256": hashlib.sha256(build_source).hexdigest(),
        },
    ]
    view = [
        {
            "relative_path": item["relative_path"],
            "before_exists": False,
            "before_sha256": hashlib.sha256(b"").hexdigest(),
            "after_sha256": hashlib.sha256(item["after"]).hexdigest(),
            "source_kind": item["source_kind"],
            "source_sha256": item["source_sha256"],
        }
        for item in files
    ]
    plan = {
        "schema_version": 1,
        "event_id": event_id,
        "task_id": "task-1",
        "approved_task_plan_sha256": sha("b"),
        "project_root": "C:/work",
        "aoi_config_sha256": sha("9"),
        "demand": {"engaged_lanes": [], "active_packets": [], "requested_depth": 2},
        "resolved": {"max_threads": 2, "max_depth": 2, "agents": agents},
        "dynamic_envelope": {
            "max_active_total_agents": 2,
            "max_delegation_depth": 2,
            "execution_selection_id": "",
        },
        "policy_ceiling": {"max_threads": 12, "max_depth": 2},
        "override_id": "",
        "selection_role_settings": {},
        "override_settings": {},
        "required_locks": [f"repo:file:{item['relative_path']}" for item in files],
        "files": view,
        "restart_required": True,
        "config_applicability": "applicable",
        "applicability_basis": "invocation C:/work is within target C:/work",
        "invocation_cwd": "C:/work",
        "codex_home": "C:/Users/test/.codex",
        "routing_evidence_boundary": "requested configuration only",
        "non_overridable_guardrails": ["Chief lease"],
    }
    plan["plan_sha256"] = resource_plan_sha256(plan)
    receipt = make_resource_receipt(
        event_id=event_id,
        plan=plan,
        files=files,
        applied_at="2026-01-01T00:00:00Z",
        root_session_id="chief-1",
    )
    receipt_payload = (json.dumps(receipt, indent=2, ensure_ascii=False) + "\n").encode()
    receipt_file_sha = hashlib.sha256(receipt_payload).hexdigest()
    event = {
        "integrity_version": 1,
        "event_id": event_id,
        "status": "applied",
        "plan_sha256": plan["plan_sha256"],
        "task_plan_sha256": sha("b"),
        "override_id": "",
        "receipt_path": f"C:/work/.aoi/tasks/task-1/results/resource-config-{event_id}.json",
        "receipt_sha256": receipt_file_sha,
        "resolved": plan["resolved"],
        "dynamic_envelope": plan["dynamic_envelope"],
        "execution_selection_id": "",
        "required_locks": plan["required_locks"],
        "restart_required": True,
        "config_applicability": "applicable",
        "applicability_basis": plan["applicability_basis"],
        "inapplicable_acknowledged": False,
        "root_session_id": "chief-1",
        "applied_at": "2026-01-01T00:00:00Z",
        "rollback": None,
    }
    envelope = {
        "receipt": receipt,
        "receipt_relative_path": f"results/resource-config-{event_id}.json",
        "receipt_file_sha256": receipt_file_sha,
    }
    return event, envelope, plan


def registration_for(event: dict, plan: dict) -> dict:
    project_sha = next(
        item["after_sha256"]
        for item in plan["files"]
        if item["relative_path"] == ".codex/config.toml"
    )
    startup = seal_startup_receipt(
        {
            "schema_version": 1,
            "hook_protocol_version": 6,
            "session_id": "session-1",
            "source": "startup",
            "observed_at": "2026-01-01T00:00:01Z",
            "cwd": "C:/work",
            "project_root": "C:/work",
            "aoi_config_sha256": plan["aoi_config_sha256"],
        }
    )
    return seal_session_registration(
        {
            "registration_schema_version": 1,
            "session_id": "session-1",
            "startup_receipt_snapshot": startup,
            "startup_receipt_sha256": startup["startup_receipt_sha256"],
            "resource_config_event_id": event["event_id"],
            "resource_event_sha256": canonical_sha256(event),
            "resource_receipt_sha256": event["receipt_sha256"],
            "aoi_config_sha256": plan["aoi_config_sha256"],
            "project_config_sha256": project_sha,
            "resource_files_manifest_sha256": resource_files_manifest_sha256(plan),
            "task_worktree": "C:/work",
            "config_ancestry_verified": True,
            "resource_files_verified": True,
            "observed_after_apply": True,
            "freshness_verdict": "registered_only",
            "config_loaded_verified": "unavailable",
            "registered_at": "2026-01-01T00:00:02Z",
        }
    )


def root_arm(
    packet_id: str = "packet-root",
    expected_agent_type: str = "explorer",
    *,
    config_after: bytes = b"max_threads = 2\n",
) -> dict:
    event, receipt, plan = real_resource(config_after=config_after)
    registration = registration_for(event, plan)
    parent = {
        "session_id": "session-1",
        "mapping_kind": "root",
        "parent_packet_id": "",
        "root_registration_snapshot": registration,
        "parent_authority_preimage": None,
        "parent_dispatch_outcome_preimage": None,
        "inherited_parent_routing_authority_sha256": None,
        "inherited_parent_routing_outcome_sha256": None,
    }
    packet = {
        "task_id": "task-1",
        "packet_id": packet_id,
        "packet_contract_sha256": sha("a"),
        "task_plan_sha256": sha("b"),
        "delegation_depth": 1,
        "parent_packet_id": "",
        "agent_role": "explorer",
    }
    topology = {
        "delegation_depth": 1,
        "parent_packet_id": "",
        "parent_resource_event_id": "",
        "parent_routing_authority_sha256": "",
    }
    return build_arm_authority(
        packet=packet,
        attempt_identity={
            "attempt": 1,
            "arm_id": f"arm-{packet_id}",
            "armed_at": "2026-01-01T00:00:03Z",
            "expires_at": "2026-01-01T00:10:03Z",
            "expected_agent_type": expected_agent_type,
        },
        chief_authority={"session_id": "chief-1", "epoch": 1, "authority_sha256": sha("5")},
        parent_authority=parent,
        resource_event_snapshot=event,
        resource_receipt=receipt,
        session_registration=registration,
        resource_envelope={
            "snapshot": event["dynamic_envelope"],
            "snapshot_sha256": canonical_sha256(event["dynamic_envelope"]),
        },
        topology_authority={"snapshot": topology, "snapshot_sha256": canonical_sha256(topology)},
    )


def observation(
    model: str = "gpt-sol",
    *,
    agent_type: str = "explorer",
    parent_session_id: str = "session-1",
    agent_id: str = "agent-1",
    when: str = "2026-01-01T00:01:00Z",
    protocol: int | str = 6,
    permission_mode: str = "default",
) -> dict:
    value = {
        "hook_protocol_version": protocol,
        "parent_session_id": parent_session_id,
        "turn_id": "",
        "agent_id": agent_id,
        "agent_type": agent_type,
        "permission_mode": permission_mode,
        "model": model,
        "observed_at": when,
    }
    value["event_id"] = codex_observation_event_id(value)
    value["observation_sha256"] = canonical_sha256(value)
    return value


def child_arm() -> dict:
    parent_arm = root_arm()
    parent_outcome = build_dispatch_outcome(
        parent_arm,
        dispatch_provenance="codex_subagent_start_observed",
        observation=observation(agent_id="parent-agent", when="2026-01-01T00:00:04Z"),
        recorded_at="2026-01-01T00:00:05Z",
    )
    event, receipt, plan = real_resource()
    registration = registration_for(event, plan)
    parent_sha = authority_sha256(parent_arm)
    parent = {
        "session_id": "parent-agent",
        "mapping_kind": "subagent_parent",
        "parent_packet_id": "packet-root",
        "root_registration_snapshot": registration,
        "parent_authority_preimage": parent_arm,
        "parent_dispatch_outcome_preimage": parent_outcome,
        "inherited_parent_routing_authority_sha256": parent_sha,
        "inherited_parent_routing_outcome_sha256": outcome_sha256(parent_outcome),
    }
    packet = {
        "task_id": "task-1",
        "packet_id": "packet-child",
        "packet_contract_sha256": sha("c"),
        "task_plan_sha256": sha("b"),
        "delegation_depth": 2,
        "parent_packet_id": "packet-root",
        "agent_role": "worker",
    }
    topology = {
        "delegation_depth": 2,
        "parent_packet_id": "packet-root",
        "parent_resource_event_id": "event-1",
        "parent_routing_authority_sha256": parent_sha,
    }
    return build_arm_authority(
        packet=packet,
        attempt_identity={
            "attempt": 1,
            "arm_id": "arm-child",
            "armed_at": "2026-01-01T00:00:06Z",
            "expires_at": "2026-01-01T00:10:06Z",
            "expected_agent_type": "*",
        },
        chief_authority={"session_id": "chief-1", "epoch": 1, "authority_sha256": sha("5")},
        parent_authority=parent,
        resource_event_snapshot=event,
        resource_receipt=receipt,
        session_registration=registration,
        resource_envelope={
            "snapshot": event["dynamic_envelope"],
            "snapshot_sha256": canonical_sha256(event["dynamic_envelope"]),
        },
        topology_authority={"snapshot": topology, "snapshot_sha256": canonical_sha256(topology)},
    )


def reseal_registration(arm: dict, key: str, value: str) -> dict:
    changed = copy.deepcopy(arm)
    base = {
        name: current
        for name, current in changed["session_registration"].items()
        if name != "registration_sha256"
    }
    base[key] = value
    if key == "aoi_config_sha256":
        startup_base = {
            name: current
            for name, current in base["startup_receipt_snapshot"].items()
            if name != "startup_receipt_sha256"
        }
        startup_base["aoi_config_sha256"] = value
        startup = seal_startup_receipt(startup_base)
        base["startup_receipt_snapshot"] = startup
        base["startup_receipt_sha256"] = startup["startup_receipt_sha256"]
    registration = seal_session_registration(base)
    changed["session_registration"] = registration
    changed["parent_authority"]["root_registration_snapshot"] = registration
    return changed


def terminal_row(
    arm: dict,
    outcome: dict,
    *,
    status: str = "done",
    typed: str = "accepted",
) -> dict:
    return {
        "authority": arm,
        "outcome": outcome,
        "terminal_status": status,
        "typed_outcome": typed,
    }


def test_real_receipt_profile_mapping_and_distinct_startup_hashes() -> None:
    arm = root_arm()
    validated = validate_arm_authority(arm)
    assert authority_sha256(arm) == authority_sha256(validated)
    resource = arm["resource_authority"]
    registration = arm["session_registration"]
    assert resource["role_profile_relative_path"] == ".codex/agents/review.toml"
    assert set(resource["event_snapshot"]["resolved"]["agents"]) == {"explorer", "worker"}
    assert registration["startup_receipt_sha256"] != registration["resource_receipt_sha256"]
    assert registration["registration_sha256"] != registration["startup_receipt_sha256"]
    assert registration["aoi_config_sha256"] != registration["project_config_sha256"]
    assert "receipt" not in resource["receipt_authority"]


def test_observation_event_id_matches_production_dispatch_policy() -> None:
    payload = {
        "session_id": "session-1",
        "turn_id": "",
        "agent_id": "agent-1",
        "agent_type": "explorer",
    }
    policy = cli_impl._dispatch_protocol_policy()
    observed = observation()
    assert policy.hook_protocol_version == 6
    assert observed["event_id"] == dispatch_protocol.subagent_event_id(payload, policy=policy)


def test_large_real_receipt_is_validated_then_compacted() -> None:
    large = b"#" * (450 * 1024)
    _event, envelope, _plan = real_resource(config_after=large)
    raw_receipt = (json.dumps(envelope["receipt"], indent=2) + "\n").encode()
    assert len(raw_receipt) > MAX_RECORD_BYTES
    arm = root_arm(config_after=large)
    assert len(canonical_json_bytes(arm, max_bytes=MAX_RECORD_BYTES)) < MAX_RECORD_BYTES
    bad = copy.deepcopy(envelope)
    bad["receipt_file_sha256"] = sha("f")
    with pytest.raises(RoutingAuthorityError, match="exact file"):
        build_arm_authority(
            packet=arm["packet_authority"],
            attempt_identity={**arm["attempt_identity"], "expected_agent_type": "explorer"},
            chief_authority=arm["chief_authority"],
            parent_authority=arm["parent_authority"],
            resource_event_snapshot=arm["resource_authority"]["event_snapshot"],
            resource_receipt=bad,
            session_registration=arm["session_registration"],
            resource_envelope=arm["resource_envelope"],
            topology_authority=arm["topology_authority"],
        )


def test_depth_two_binds_observed_parent_session_and_wildcard() -> None:
    arm = child_arm()
    assert arm["parent_authority"]["session_id"] == "parent-agent"
    assert arm["parent_authority"]["session_id"] != arm["session_registration"]["session_id"]
    assert arm["transport_authority"]["expected_agent_type"] == "*"
    outcome = build_dispatch_outcome(
        arm,
        dispatch_provenance="codex_subagent_start_observed",
        observation=observation(
            "gpt-terra",
            agent_type="claude",
            parent_session_id="parent-agent",
            agent_id="child-agent",
        ),
        recorded_at="2026-01-01T00:02:00Z",
    )
    assert outcome["verdict"] == "observed_model_slug_match"
    assert outcome["fresh_session_evidence"] == "inherited_root_registration"
    bad = copy.deepcopy(arm)
    bad["parent_authority"]["session_id"] = "session-1"
    with pytest.raises(RoutingAuthorityError, match="parent preimages"):
        validate_arm_authority(bad)


def test_model_verdicts_are_slug_only_and_unavailable_boundaries_stay_explicit() -> None:
    arm = root_arm()
    manual = build_dispatch_outcome(
        arm,
        dispatch_provenance="manual_unverified",
        observation=None,
        recorded_at="2026-01-01T00:02:00Z",
    )
    assert manual["verdict"] == "manual_unverified"
    unobserved = build_dispatch_outcome(
        arm,
        dispatch_provenance="codex_subagent_start_observed",
        observation=observation(""),
        recorded_at="2026-01-01T00:02:00Z",
    )
    assert unobserved["verdict"] == "actual_model_unobserved"
    mismatch = build_dispatch_outcome(
        arm,
        dispatch_provenance="codex_subagent_start_observed",
        observation=observation("other", permission_mode="future-mode"),
        recorded_at="2026-01-01T00:02:00Z",
    )
    assert mismatch["verdict"] == "observed_model_slug_mismatch"
    for key in (
        "config_loaded_verified",
        "provider_route_verified",
        "runtime_profile_verified",
        "runtime_sandbox_profile_verified",
    ):
        assert mismatch[key] == "unavailable"


def test_timeline_protocol_and_forged_authority_links_fail_closed() -> None:
    arm = root_arm()
    for path, value in [
        (("attempt_identity", "expires_at"), "2026-01-01T00:20:04Z"),
        (("session_registration", "startup_receipt_snapshot", "observed_at"), "2026-01-01T00:00:00Z"),
        (("resource_authority", "event_snapshot", "rollback"), {"bad": True}),
        (("resource_authority", "event_snapshot", "dynamic_envelope"), {"forged": True}),
        (("resource_envelope", "snapshot"), {"forged": True}),
        (("parent_authority", "root_registration_snapshot", "startup_receipt_snapshot", "source"), "resume"),
    ]:
        bad = copy.deepcopy(arm)
        target = bad
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        with pytest.raises(RoutingAuthorityError):
            validate_arm_authority(bad)
    with pytest.raises(RoutingAuthorityError, match="AOI/Codex"):
        validate_arm_authority(reseal_registration(arm, "aoi_config_sha256", sha("8")))
    with pytest.raises(RoutingAuthorityError, match="AOI/Codex"):
        validate_arm_authority(reseal_registration(arm, "project_config_sha256", sha("7")))
    for bad_observation in [
        observation(protocol="6"),
        observation(when="2026-01-01T00:10:04Z"),
        observation(parent_session_id="other-session"),
        {**observation(), "event_id": "spawn-forged"},
    ]:
        bad_observation["observation_sha256"] = canonical_sha256(
            {
                key: value
                for key, value in bad_observation.items()
                if key != "observation_sha256"
            }
        )
        with pytest.raises(RoutingAuthorityError):
            build_dispatch_outcome(
                arm,
                dispatch_provenance="codex_subagent_start_observed",
                observation=bad_observation,
                recorded_at="2026-01-01T00:10:03Z",
            )


def test_one_arm_has_one_cas_slot_and_observation_cannot_cross_packets() -> None:
    observed = observation()
    arm_a = root_arm("packet-a")
    arm_b = root_arm("packet-b")
    first = build_dispatch_outcome(
        arm_a,
        dispatch_provenance="codex_subagent_start_observed",
        observation=observed,
        recorded_at="2026-01-01T00:02:00Z",
    )
    second = build_dispatch_outcome(
        arm_b,
        dispatch_provenance="codex_subagent_start_observed",
        observation=observed,
        recorded_at="2026-01-01T00:02:00Z",
    )
    manual = build_dispatch_outcome(
        arm_a,
        dispatch_provenance="manual_unverified",
        observation=None,
        recorded_at="2026-01-01T00:02:00Z",
    )
    assert first["outcome_slot_sha256"] == manual["outcome_slot_sha256"]
    assert first["outcome_slot_sha256"] != second["outcome_slot_sha256"]
    with pytest.raises(RoutingAuthorityError, match="cannot bind"):
        capacity_routing_view([terminal_row(arm_a, first), terminal_row(arm_b, second)])
    with pytest.raises(RoutingAuthorityError, match="CAS slot"):
        capacity_routing_view([terminal_row(arm_a, first), terminal_row(arm_a, manual)])
    conflicting = copy.deepcopy(first)
    conflicting["verdict"] = "observed_model_slug_mismatch"
    assert conflicting["outcome_slot_sha256"] == first["outcome_slot_sha256"]
    assert outcome_sha256(first) == first["routing_outcome_sha256"]
    with pytest.raises(RoutingAuthorityError):
        validate_dispatch_outcome(arm_a, conflicting)


def test_capacity_preserves_all_terminal_rows_and_honest_eligibility() -> None:
    arm = root_arm()
    outcome = build_dispatch_outcome(
        arm,
        dispatch_provenance="codex_subagent_start_observed",
        observation=observation(),
        recorded_at="2026-01-01T00:02:00Z",
    )
    accepted = capacity_routing_view([terminal_row(arm, outcome)])
    row = accepted["rows"][0]
    assert row["technical_outcome_eligible"]
    assert row["model_slug_attribution_eligible"]
    assert row["model_quality_eligible"]
    assert row["profile"] == "review"
    procedural = capacity_routing_view(
        [terminal_row(arm, outcome, status="failed", typed="procedural_failure")]
    )["rows"][0]
    assert not procedural["technical_outcome_eligible"]
    assert procedural["model_slug_attribution_eligible"]
    assert not procedural["model_quality_eligible"]
    rejected = capacity_routing_view(
        [terminal_row(arm, outcome, status="done", typed="rejected")]
    )
    assert accepted["input_fingerprint"] != rejected["input_fingerprint"]

    legacy = build_legacy_outcome(
        {
            "packet_schema_version": 5,
            "status": "failed",
            "typed_outcome": "procedural_failure",
            "packet_id": "old",
        },
        recorded_at="2026-01-01T00:02:00Z",
    )
    legacy_row = capacity_routing_view([{"legacy_outcome": legacy}])["rows"][0]
    assert legacy_row["typed_outcome"] == "procedural_failure"
    assert not legacy_row["technical_outcome_eligible"]
    unclassified = build_legacy_outcome(
        {"packet_schema_version": 5, "status": "done", "packet_id": "old-unclassified"},
        recorded_at="2026-01-01T00:02:00Z",
    )
    assert capacity_routing_view([{"legacy_outcome": unclassified}])["rows"][0][
        "typed_outcome"
    ] == "unclassified"
    with pytest.raises(RoutingAuthorityError):
        build_legacy_outcome(
            {"packet_schema_version": 5, "status": "dispatched", "packet_id": "live"},
            recorded_at="2026-01-01T00:02:00Z",
        )


def test_capacity_order_is_deterministic_and_duplicate_identities_reject() -> None:
    arm_a = root_arm("packet-a")
    arm_b = root_arm("packet-b")
    outcome_a = build_dispatch_outcome(
        arm_a,
        dispatch_provenance="codex_subagent_start_observed",
        observation=observation(agent_id="agent-a"),
        recorded_at="2026-01-01T00:02:00Z",
    )
    outcome_b = build_dispatch_outcome(
        arm_b,
        dispatch_provenance="codex_subagent_start_observed",
        observation=observation(agent_id="agent-b"),
        recorded_at="2026-01-01T00:02:00Z",
    )
    first = capacity_routing_view([terminal_row(arm_a, outcome_a), terminal_row(arm_b, outcome_b)])
    second = capacity_routing_view([terminal_row(arm_b, outcome_b), terminal_row(arm_a, outcome_a)])
    assert first == second

    legacy = build_legacy_outcome(
        {"packet_schema_version": 5, "status": "done", "packet_id": "old"},
        recorded_at="2026-01-01T00:02:00Z",
    )
    same_snapshot = build_legacy_outcome(
        {"packet_schema_version": 5, "status": "done", "packet_id": "old"},
        recorded_at="2026-01-01T00:03:00Z",
    )
    with pytest.raises(RoutingAuthorityError, match="snapshot identity"):
        capacity_routing_view(
            [{"legacy_outcome": legacy}, {"legacy_outcome": same_snapshot}]
        )


class RealPlannerRoutingIntegrationTests(HarnessTestCase):
    def test_actual_resource_planner_receipt_builds_one_compact_arm(self) -> None:
        codex_home = Path(self.env["CODEX_HOME"])
        agents = codex_home / "agents"
        agents.mkdir(parents=True)
        (agents / "explorer.toml").write_text(
            "\n".join(
                [
                    'name = "explorer"',
                    'description = "Read-only exploration"',
                    'developer_instructions = "Inspect only."',
                    'model = "gpt-5.6-terra"',
                    'model_reasoning_effort = "medium"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        state = {
            "task_id": "real-planner-task",
            "plan_sha256": sha("b"),
            "lanes": [{"status": "active", "role": "explorer"}],
            "packets": [],
            "execution_selections": [],
        }
        plan, files = rc.build_codex_resource_plan(
            event_id="real-planner-event",
            root=self.root,
            config=load_config(self.root),
            state=state,
            codex_home=codex_home,
            managed_roles=["explorer"],
            invocation_cwd=self.root,
        )
        receipt = make_resource_receipt(
            event_id="real-planner-event",
            plan=plan,
            files=files,
            applied_at="2026-01-01T00:00:00Z",
            root_session_id="config-chief",
        )
        receipt_payload = (json.dumps(receipt, indent=2, ensure_ascii=False) + "\n").encode()
        receipt_sha = hashlib.sha256(receipt_payload).hexdigest()
        event = {
            "integrity_version": 1,
            "event_id": "real-planner-event",
            "status": "applied",
            "plan_sha256": plan["plan_sha256"],
            "task_plan_sha256": sha("b"),
            "override_id": "",
            "receipt_path": str(
                self.root
                / ".aoi"
                / "tasks"
                / "real-planner-task"
                / "results"
                / "resource-config-real-planner-event.json"
            ),
            "receipt_sha256": receipt_sha,
            "resolved": plan["resolved"],
            "dynamic_envelope": plan["dynamic_envelope"],
            "execution_selection_id": "",
            "required_locks": plan["required_locks"],
            "restart_required": True,
            "config_applicability": "applicable",
            "applicability_basis": plan["applicability_basis"],
            "inapplicable_acknowledged": False,
            "root_session_id": "config-chief",
            "applied_at": "2026-01-01T00:00:00Z",
            "rollback": None,
        }
        startup = seal_startup_receipt(
            {
                "schema_version": 1,
                "hook_protocol_version": 6,
                "session_id": "fresh-session",
                "source": "startup",
                "observed_at": "2026-01-01T00:00:01Z",
                "cwd": str(self.root),
                "project_root": str(self.root),
                "aoi_config_sha256": plan["aoi_config_sha256"],
            }
        )
        registration = seal_session_registration(
            {
                "registration_schema_version": 1,
                "session_id": "fresh-session",
                "startup_receipt_snapshot": startup,
                "startup_receipt_sha256": startup["startup_receipt_sha256"],
                "resource_config_event_id": event["event_id"],
                "resource_event_sha256": canonical_sha256(event),
                "resource_receipt_sha256": receipt_sha,
                "aoi_config_sha256": plan["aoi_config_sha256"],
                "project_config_sha256": next(
                    item["after_sha256"]
                    for item in plan["files"]
                    if item["relative_path"] == ".codex/config.toml"
                ),
                "resource_files_manifest_sha256": resource_files_manifest_sha256(plan),
                "task_worktree": str(self.root),
                "config_ancestry_verified": True,
                "resource_files_verified": True,
                "observed_after_apply": True,
                "freshness_verdict": "registered_only",
                "config_loaded_verified": "unavailable",
                "registered_at": "2026-01-01T00:00:02Z",
            }
        )
        parent = {
            "session_id": "fresh-session",
            "mapping_kind": "root",
            "parent_packet_id": "",
            "root_registration_snapshot": registration,
            "parent_authority_preimage": None,
            "parent_dispatch_outcome_preimage": None,
            "inherited_parent_routing_authority_sha256": None,
            "inherited_parent_routing_outcome_sha256": None,
        }
        packet = {
            "task_id": "real-planner-task",
            "packet_id": "real-packet",
            "packet_contract_sha256": sha("a"),
            "task_plan_sha256": sha("b"),
            "delegation_depth": 1,
            "parent_packet_id": "",
            "agent_role": "explorer",
        }
        topology = {
            "delegation_depth": 1,
            "parent_packet_id": "",
            "parent_resource_event_id": "",
            "parent_routing_authority_sha256": "",
        }
        arm = build_arm_authority(
            packet=packet,
            attempt_identity={
                "attempt": 1,
                "arm_id": "real-arm",
                "armed_at": "2026-01-01T00:00:03Z",
                "expires_at": "2026-01-01T00:10:03Z",
                "expected_agent_type": "explorer",
            },
            chief_authority={
                "session_id": "fresh-session",
                "epoch": 1,
                "authority_sha256": sha("5"),
            },
            parent_authority=parent,
            resource_event_snapshot=event,
            resource_receipt={
                "receipt": receipt,
                "receipt_relative_path": "results/resource-config-real-planner-event.json",
                "receipt_file_sha256": receipt_sha,
            },
            session_registration=registration,
            resource_envelope={
                "snapshot": event["dynamic_envelope"],
                "snapshot_sha256": canonical_sha256(event["dynamic_envelope"]),
            },
            topology_authority={
                "snapshot": topology,
                "snapshot_sha256": canonical_sha256(topology),
            },
        )
        self.assertEqual(
            arm["resource_authority"]["role_profile_relative_path"],
            ".codex/agents/explorer.toml",
        )
        self.assertNotIn("receipt", arm["resource_authority"]["receipt_authority"])
        self.assertLess(len(canonical_json_bytes(arm, max_bytes=MAX_RECORD_BYTES)), MAX_RECORD_BYTES)
