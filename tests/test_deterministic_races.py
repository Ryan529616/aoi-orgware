#!/usr/bin/env python3
"""Deterministic release-gate tests for AOI's core linearization points."""

from __future__ import annotations

import base64
import datetime as dt
import json
import socket
import subprocess
import sys
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
RACE_WORKER = HERE / "state_lock_race_worker.py"
sys.path.insert(0, str(SRC))

from aoi_orgware import harnesslib as h  # noqa: E402
from tests.harness_case import HarnessTestCase  # noqa: E402


RaceActor = tuple[
    str,
    str,
    list[str],
    dict[str, str],
    bytes | None,
    str,
]


class DeterministicRaceTests(HarnessTestCase):
    def run_state_lock_race(
        self,
        actors: list[RaceActor],
        *,
        release_groups: list[list[str]] | None = None,
        expect_blocked_after_release: list[str] | None = None,
    ) -> list[subprocess.CompletedProcess[str]]:
        """Release actors only after all reach their selected lock boundary."""

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(len(actors))
        listener.settimeout(0.1)
        host, port = listener.getsockname()
        processes: dict[str, subprocess.Popen[bytes]] = {}
        connections: dict[str, socket.socket] = {}
        events: dict[str, dict[str, object]] = {}
        try:
            for (
                actor_id,
                mode,
                command,
                actor_env,
                hook_payload,
                gate_stage,
            ) in actors:
                env = actor_env.copy()
                worker_command = [
                    sys.executable,
                    str(RACE_WORKER),
                    "--host",
                    str(host),
                    "--port",
                    str(port),
                    "--actor",
                    actor_id,
                    "--mode",
                    mode,
                    "--gate-stage",
                    gate_stage,
                ]
                if hook_payload is not None:
                    worker_command.extend(
                        [
                            "--hook-payload-b64",
                            base64.b64encode(hook_payload).decode("ascii"),
                        ]
                    )
                if command:
                    worker_command.extend(["--", *command])
                processes[actor_id] = subprocess.Popen(
                    worker_command,
                    cwd=self.root,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

            deadline = time.monotonic() + 10
            while len(connections) < len(actors):
                try:
                    connection, _address = listener.accept()
                except TimeoutError:
                    exited = [
                        (actor_id, process)
                        for actor_id, process in processes.items()
                        if process.poll() is not None and actor_id not in connections
                    ]
                    if exited:
                        actor_id, process = exited[0]
                        stdout, stderr = process.communicate(timeout=5)
                        raise AssertionError(
                            f"race actor {actor_id!r} exited before the lock boundary: "
                            f"rc={process.returncode}\nstdout={stdout!r}\nstderr={stderr!r}"
                        )
                    if time.monotonic() >= deadline:
                        raise AssertionError(
                            "race actors did not all reach the state-lock boundary"
                        )
                    continue
                connection.settimeout(10)
                event_bytes = bytearray()
                while not event_bytes.endswith(b"\n"):
                    chunk = connection.recv(1)
                    if not chunk:
                        raise AssertionError("race actor disconnected before ready")
                    event_bytes.extend(chunk)
                    if len(event_bytes) > 4096:
                        raise AssertionError("race actor event exceeded the test bound")
                event = json.loads(event_bytes.decode("utf-8"))
                actor_id = event.get("actor")
                if (
                    not isinstance(actor_id, str)
                    or actor_id not in processes
                    or actor_id in connections
                ):
                    raise AssertionError(f"unexpected race actor id: {actor_id!r}")
                connections[actor_id] = connection
                events[actor_id] = event

            expected_lock = str((self.root / ".aoi" / ".state.lock").resolve())
            expected_stages = {
                actor_id: gate_stage
                for actor_id, *_rest, gate_stage in actors
            }
            self.assertTrue(
                all(
                    event.get("stage") == expected_stages[actor_id]
                    for actor_id, event in events.items()
                ),
                events,
            )
            self.assertEqual(
                {event.get("path") for event in events.values()},
                {expected_lock},
            )
            identities = {
                (event.get("st_dev"), event.get("st_ino"))
                for event in events.values()
            }
            self.assertTrue(
                all(
                    isinstance(st_dev, int) and isinstance(st_ino, int)
                    for st_dev, st_ino in identities
                ),
                events,
            )
            self.assertEqual(len(identities), 1)

            actor_ids = [actor[0] for actor in actors]
            groups = release_groups or [actor_ids]
            flattened = [actor_id for group in groups for actor_id in group]
            if len(flattened) != len(set(flattened)) or set(flattened) != set(actor_ids):
                raise AssertionError("release groups must cover every actor exactly once")
            pre_released = set(expect_blocked_after_release or [])
            if not pre_released.issubset(actor_ids):
                raise AssertionError(
                    "blocked actors must be members of the race actor set"
                )
            for actor_id in pre_released:
                connections[actor_id].sendall(b"G")
            for actor_id in pre_released:
                process = processes[actor_id]
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    continue
                stdout, stderr = process.communicate(timeout=5)
                raise AssertionError(
                    f"race actor {actor_id!r} exited while another actor held "
                    f"the state lock: rc={process.returncode}\n"
                    f"stdout={stdout!r}\nstderr={stderr!r}"
                )

            results: dict[str, subprocess.CompletedProcess[str]] = {}
            for group in groups:
                for actor_id in group:
                    if actor_id not in pre_released:
                        connections[actor_id].sendall(b"G")
                for actor_id in group:
                    process = processes[actor_id]
                    stdout, stderr = process.communicate(timeout=40)
                    results[actor_id] = subprocess.CompletedProcess(
                        process.args,
                        process.returncode,
                        stdout.decode("utf-8", errors="replace"),
                        stderr.decode("utf-8", errors="replace"),
                    )
            return [results[actor_id] for actor_id in actor_ids]
        finally:
            listener.close()
            for connection in connections.values():
                connection.close()
            for process in processes.values():
                if process.poll() is None:
                    process.kill()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)

    def test_concurrent_chief_acquisition_has_one_linearized_winner(self) -> None:
        self.cli("chief-release", "--reason", "prepare deterministic Chief race")
        paths = h.get_paths(self.root)
        self.assertEqual(paths.lock.read_bytes(), b"\0")
        race_env = self.env.copy()
        for name in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
            "AOI_CHIEF_TOKEN",
        ):
            race_env.pop(name, None)
        actors = [
            (
                actor_id,
                "cli",
                [
                    "chief-acquire",
                    "--session-id",
                    actor_id,
                    "--json",
                ],
                race_env,
                None,
                "before_acquire",
            )
            for actor_id in ("race-chief-a", "race-chief-b")
        ]

        results = self.run_state_lock_race(actors)

        self.assertEqual(sorted(result.returncode for result in results), [0, 2])
        winner = next(
            json.loads(result.stdout) for result in results if result.returncode == 0
        )
        loser = next(result for result in results if result.returncode == 2)
        self.assertEqual(loser.stdout, "")
        self.assertIn("an active Chief lease already exists", loser.stderr)
        authority = h.load_chief_authority(paths)
        self.assertIsNotNone(authority)
        self.assertEqual(authority["status"], "active")
        self.assertEqual(authority["session_id"], winner["authority"]["session_id"])
        self.assertNotIn("chief_token", winner)
        self.assertEqual(paths.lock.read_bytes(), b"\0")
        credential_files = sorted(
            path.resolve()
            for path in Path(self.env["AOI_CHIEF_CREDENTIAL_HOME"]).rglob("*.json")
            if path.is_file()
        )
        self.assertEqual(
            credential_files,
            [Path(winner["credential_file"]).resolve()],
        )
        self.assertTrue(
            all("Traceback" not in result.stderr for result in results), results
        )

    def test_chief_contender_waits_behind_acquired_holder(self) -> None:
        self.cli("chief-release", "--reason", "prepare acquired-lock Chief race")
        paths = h.get_paths(self.root)
        self.assertEqual(paths.lock.read_bytes(), b"\0")
        race_env = self.env.copy()
        for name in (
            "AOI_CHIEF_SESSION_ID",
            "AOI_CHIEF_EPOCH",
            "AOI_CHIEF_CREDENTIAL_FILE",
            "AOI_CHIEF_TOKEN",
        ):
            race_env.pop(name, None)
        actors = [
            (
                "chief-holder",
                "cli",
                [
                    "chief-acquire",
                    "--session-id",
                    "chief-holder",
                    "--json",
                ],
                race_env,
                None,
                "acquired",
            ),
            (
                "chief-contender",
                "cli",
                [
                    "chief-acquire",
                    "--session-id",
                    "chief-contender",
                    "--json",
                ],
                race_env,
                None,
                "before_acquire",
            ),
        ]

        results = self.run_state_lock_race(
            actors,
            expect_blocked_after_release=["chief-contender"],
        )

        self.assertEqual([result.returncode for result in results], [0, 2])
        holder = json.loads(results[0].stdout)
        self.assertEqual(holder["authority"]["session_id"], "chief-holder")
        self.assertEqual(results[1].stdout, "")
        self.assertIn("an active Chief lease already exists", results[1].stderr)
        self.assertNotIn("PermissionError", results[1].stderr)
        self.assertTrue(
            all("Traceback" not in result.stderr for result in results), results
        )
        authority = h.load_chief_authority(paths)
        self.assertIsNotNone(authority)
        self.assertEqual(authority["session_id"], "chief-holder")
        self.assertEqual(paths.lock.read_bytes(), b"\0")

    def test_overlapping_claims_publish_one_consistent_winner(self) -> None:
        task_id = "deterministic-claim-race"
        self.init_task(task_id)
        expiry = (
            dt.datetime.now().astimezone() + dt.timedelta(minutes=5)
        ).isoformat()
        shared_lock = "repo:file:.harness-test-root"
        actors = []
        for suffix in ("a", "b"):
            token = f"overlap-{suffix}"
            actors.append(
                (
                    token,
                    "cli",
                    [
                        "claim",
                        "--task",
                        task_id,
                        "--token",
                        token,
                        "--owner",
                        f"agent-{suffix}",
                        "--kind",
                        "implementation",
                        "--lock",
                        shared_lock,
                        "--intent",
                        "Exercise one exact overlapping ownership decision",
                        "--validation",
                        "Inspect the surviving claim and task backlink",
                        "--expires-at",
                        expiry,
                        "--json",
                    ],
                    self.env,
                    None,
                    "before_acquire",
                )
            )

        results = self.run_state_lock_race(actors)

        self.assertEqual(sorted(result.returncode for result in results), [0, 2])
        winner = next(
            json.loads(result.stdout) for result in results if result.returncode == 0
        )
        winner_token = winner["token"]
        loser = next(result for result in results if result.returncode == 2)
        self.assertEqual(loser.stdout, "")
        self.assertIn("claim conflict(s)", loser.stderr)
        self.assertIn(winner_token, loser.stderr)
        paths = h.get_paths(self.root)
        state = h.load_task(paths, task_id)
        self.assertEqual(state["claims"], [winner_token])
        active_claims = sorted(paths.claims_active.glob("*.json"))
        self.assertEqual([path.stem for path in active_claims], [winner_token])
        claim = h.load_claim_file(active_claims[0])
        self.assertEqual(claim["token"], winner_token)
        self.assertEqual(claim["task_id"], task_id)
        self.assertEqual(claim["locks"], [shared_lock])
        self.assertTrue(
            all("Traceback" not in result.stderr for result in results), results
        )

    def test_one_packet_arm_is_consumed_once_under_released_hook_race(self) -> None:
        task_id = "deterministic-packet-race"
        packet_id = "one-permit"
        self.init_task(task_id, session_id="harness-test-chief")
        self.cli(
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--agent-role",
            "explorer",
            "--model-tier",
            "standard",
            "--objective",
            "Inspect one bounded source question under a raced dispatch",
            "--scope",
            "Read-only packet with no harness mutation authority",
            "--deliverable",
            "One evidence-backed conclusion",
            "--validation",
            "The parent checks the exact consumed arm and incident",
        )
        self.arm_packet(
            task_id,
            packet_id,
            expected_agent_type="explorer",
            parent_session_id="harness-test-chief",
        )
        actors = []
        payloads: dict[str, dict[str, str]] = {}
        for suffix in ("a", "b"):
            actor_id = f"packet-hook-{suffix}"
            payload = {
                "hook_event_name": "SubagentStart",
                "session_id": "harness-test-chief",
                "turn_id": f"deterministic-turn-{suffix}",
                "agent_id": f"/root/deterministic-{suffix}",
                "agent_type": "explorer",
            }
            payloads[actor_id] = payload
            actors.append(
                (
                    actor_id,
                    "hook",
                    [],
                    self.env,
                    json.dumps(payload).encode("utf-8"),
                    "before_acquire",
                )
            )

        results = self.run_state_lock_race(actors)

        self.assertTrue(all(result.returncode == 0 for result in results), results)
        contexts = {
            actor[0]: json.loads(result.stdout)["hookSpecificOutput"][
                "additionalContext"
            ]
            for actor, result in zip(actors, results, strict=True)
        }
        self.assertEqual(
            sum(
                "valid pre-armed dispatch" in item
                for item in contexts.values()
            ),
            1,
        )
        self.assertEqual(
            sum(
                "without one valid, unique pre-armed packet" in item
                for item in contexts.values()
            ),
            1,
        )
        authorized_actor = next(
            actor_id
            for actor_id, context in contexts.items()
            if "valid pre-armed dispatch" in context
        )
        incident_actor = next(
            actor_id
            for actor_id, context in contexts.items()
            if "without one valid, unique pre-armed packet" in context
        )
        state = h.load_task(h.get_paths(self.root), task_id)
        packet = state["packets"][0]
        self.assertEqual(packet["status"], "dispatched")
        self.assertEqual(len(packet["dispatch_attempts"]), 1)
        self.assertEqual(packet["agent_id"], payloads[authorized_actor]["agent_id"])
        self.assertEqual(
            packet["dispatch_attempts"][0]["observation"]["turn_id"],
            payloads[authorized_actor]["turn_id"],
        )
        self.assertEqual(len(state["subagent_incidents"]), 1)
        self.assertEqual(state["subagent_incidents"][0]["reason_code"], "no_matching_arm")
        self.assertEqual(
            state["subagent_incidents"][0]["agent_id"],
            payloads[incident_actor]["agent_id"],
        )
        self.assertEqual(
            state["subagent_incidents"][0]["turn_id"],
            payloads[incident_actor]["turn_id"],
        )


if __name__ == "__main__":
    import unittest

    unittest.main(verbosity=2)
