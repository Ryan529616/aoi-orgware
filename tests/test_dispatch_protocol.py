from __future__ import annotations

import ast
import datetime as dt
import inspect
import re
import unittest

from aoi_orgware import dispatch_protocol as dispatch


def protocol_policy(version: int = 6) -> dispatch.DispatchProtocolPolicy:
    return dispatch.DispatchProtocolPolicy(
        hook_protocol_version=version,
        hook_id_re=re.compile(r"^[A-Za-z0-9._:/-]{1,512}$"),
        executing_packet_statuses=frozenset({"armed", "dispatched"}),
    )


def armed_packet(
    *,
    packet_id: str = "review-packet",
    packet_role: str = "reviewer",
    expected_transport_type: str = "default",
    parent_session_id: str = "chief-session",
    expires_at: str = "2099-01-01T00:00:00+00:00",
) -> dict:
    return {
        "packet_id": packet_id,
        "agent_role": packet_role,
        "status": "armed",
        "dispatch_attempts": [
            {
                "status": "armed",
                "parent_session_id": parent_session_id,
                "expected_agent_type": expected_transport_type,
                "expires_at": expires_at,
            }
        ],
    }


class DispatchProtocolTests(unittest.TestCase):
    def test_policy_snapshots_mutable_status_input(self) -> None:
        statuses = {"armed", "dispatched"}
        policy = dispatch.DispatchProtocolPolicy(
            hook_protocol_version=6,
            hook_id_re=re.compile(r"^[a-z]+$"),
            executing_packet_statuses=statuses,
        )
        statuses.add("done")
        self.assertEqual(policy.executing_packet_statuses, {"armed", "dispatched"})

    def test_arm_matching_uses_transport_type_not_packet_role(self) -> None:
        packet = armed_packet(
            packet_role="reviewer",
            expected_transport_type="default",
        )
        state = {"packets": [packet]}

        matches = dispatch.matching_armed_packets(
            state,
            parent_session_id="chief-session",
            transport_agent_type="default",
        )
        role_named_transport = dispatch.matching_armed_packets(
            state,
            parent_session_id="chief-session",
            transport_agent_type="reviewer",
        )

        self.assertEqual(len(matches), 1)
        self.assertIs(matches[0][0], packet)
        self.assertEqual(packet["agent_role"], "reviewer")
        self.assertEqual(role_named_transport, [])

    def test_expiry_reports_transport_coordinates_and_reopens_packet(self) -> None:
        current = dt.datetime(2026, 7, 15, 2, 0, tzinfo=dt.timezone.utc)
        packet = armed_packet(
            expires_at="2026-07-15T01:59:59+00:00",
            expected_transport_type="default",
        )
        state = {"packets": [packet]}

        expired = dispatch.expire_dispatch_arms(state, current=current)

        self.assertEqual(
            expired,
            [
                {
                    "packet_id": "review-packet",
                    "parent_session_id": "chief-session",
                    "expected_agent_type": "default",
                }
            ],
        )
        self.assertEqual(packet["status"], "ready")
        self.assertEqual(packet["dispatch_attempts"][0]["status"], "expired")

    def test_event_identity_is_stable_sanitized_and_protocol_scoped(self) -> None:
        payload = {
            "session_id": "chief-session",
            "turn_id": "turn-1",
            "agent_id": "/root/reviewer",
            "agent_type": "default",
        }
        first = dispatch.subagent_event_id(payload, policy=protocol_policy(6))
        replay = dispatch.subagent_event_id(dict(payload), policy=protocol_policy(6))
        next_protocol = dispatch.subagent_event_id(payload, policy=protocol_policy(7))
        unsafe = dispatch.safe_hook_observation_text(
            "line-one\nline-two", policy=protocol_policy()
        )

        self.assertEqual(first, replay)
        self.assertNotEqual(first, next_protocol)
        self.assertRegex(first, r"^spawn-[0-9a-f]{32}$")
        self.assertEqual(unsafe, "")

    def test_incident_recording_is_idempotent_and_canonicalizes_candidates(self) -> None:
        payload = {
            "session_id": "chief-session",
            "turn_id": "turn-incident",
            "agent_id": "/root/unmanaged",
            "agent_type": "default",
        }
        state: dict = {}
        first = dispatch.record_subagent_incident(
            state,
            payload,
            reason_code="no_matching_arm",
            candidate_packet_ids=["packet-b", "packet-a", "packet-b"],
            observed_at="2026-07-15T02:00:00+00:00",
            policy=protocol_policy(),
        )
        replay = dispatch.record_subagent_incident(
            state,
            payload,
            reason_code="different-replay-reason",
            candidate_packet_ids=[],
            observed_at="2026-07-15T02:01:00+00:00",
            policy=protocol_policy(),
        )

        self.assertIs(first, replay)
        self.assertEqual(len(state["subagent_incidents"]), 1)
        self.assertEqual(first["candidate_packet_ids"], ["packet-a", "packet-b"])
        self.assertEqual(first["reason_code"], "no_matching_arm")

    def test_initial_rejection_reason_preserves_fail_closed_precedence(self) -> None:
        packet = armed_packet()
        candidate = (packet, packet["dispatch_attempts"][0])
        policy = protocol_policy()
        cases = (
            (False, "new-agent", [], [], "invalid_event"),
            (True, "new-agent", [], [], "no_matching_arm"),
            (True, "new-agent", [], ["expired"], "expired_arm"),
            (True, "new-agent", [candidate, candidate], [], "ambiguous_arm"),
        )
        for valid_event, agent_id, candidates, expired, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(
                    dispatch.initial_rejection_reason(
                        {"packets": []},
                        valid_event=valid_event,
                        agent_id=agent_id,
                        candidates=candidates,
                        matched_expired_packet_ids=expired,
                        policy=policy,
                    ),
                    expected,
                )

        self.assertEqual(
            dispatch.initial_rejection_reason(
                {
                    "packets": [
                        {
                            "status": "dispatched",
                            "agent_id": "/root/already-running",
                        }
                    ]
                },
                valid_event=True,
                agent_id="/root/already-running",
                candidates=[candidate],
                matched_expired_packet_ids=[],
                policy=policy,
            ),
            "duplicate_agent",
        )

    def test_module_has_no_cli_import(self) -> None:
        tree = ast.parse(inspect.getsource(dispatch))
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module or "")
        self.assertNotIn("aoi_orgware.cli", imports)
        self.assertNotIn(".cli", imports)


if __name__ == "__main__":
    unittest.main()
