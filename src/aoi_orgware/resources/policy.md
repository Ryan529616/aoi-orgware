# AOI operating policy

This document defines the default v0.1 governance contract. `aoi.toml` may
change the vocabulary and capability tiers, but it must not silently erase the
authority and evidence boundaries below.

## Authority

1. The **user** owns goals, risk preferences, budgets, and irreversible choices.
2. The **Chief** owns formal technical arbitration and integrated reporting.
3. The **Steward** owns procedural coordination and the system of record. It
   may validate, correlate, deduplicate, distribute, and track; it may not make
   a technical decision or declare an implementation correct.
4. **Specialist lanes** own bounded execution and evidence production inside
   their recorded contracts.

Only the root/Chief process writes AOI state. Delegated agents return bounded
results to root; they do not edit `.aoi/`.

## Task lifecycle

Before material writes, external jobs, or mutable delegation, root must:

1. initialize or resume a task;
2. record a completion boundary and approve a concrete plan;
3. acquire the minimum non-overlapping claims;
4. select a task-appropriate execution topology;
5. delegate only bounded, independent work;
6. record evidence without upgrading its strength;
7. checkpoint after material state changes;
8. account for packets, jobs, delivery, claims, and verification before close.

Task status (`active`, `blocked`, `done`, `cancelled`) is separate from phase
(`planning`, `gathering`, `diagnosing`, `implementing`, `waiting_external`,
`verifying`, `reviewing`, `closing`).

`acknowledged` means a directive was received. Resolution additionally requires
implementation evidence against the selected baseline and verification by a
different lane against an explicit oracle.

## Claims and locks

Supported lock forms are:

```text
repo:file:<project-relative-path>
repo:tree:<project-relative-path>
host:file:<canonical-drive-path>
host:tree:<canonical-drive-path>
<external-namespace>:file:<absolute-path>
<external-namespace>:tree:<absolute-path>
contract:<slug>
git:merge:<branch>
```

File/tree ancestry conflicts are rejected. Traversal and glob syntax are
rejected. Exact project-file claims record a SHA-256 baseline. Expiry is a
warning, not automatic release: an expired claim reserves scope until it is
explicitly marked terminal.

Locks coordinate cooperative agents. They cannot stop an unrelated process
from changing a file.

## Delegation

A packet has one objective, scope, deliverable, validation boundary, requested
role/tier, and optional covered locks. Root must choose the least expensive tier
that is plausibly sufficient. A packet's requested route is not proof of the
model actually used; actual routing needs separate evidence.

Depth two is reserved for bounded leaf work. A depth-two agent may not spawn
further agents, arbitrate, mutate AOI state, or report directly to the user.

## Execution topology

Choose per work unit:

- `single`: one causal chain or dense shared context;
- `centralized_parallel`: independently verifiable lanes coordinated through
  the Steward;
- `hybrid`: central control plus one bounded direct technical session.

Hybrid communication does not create private authority. The Steward records the
baseline, participants, topic, evidence boundary, expiry, conclusion, dissent,
and blockers. Decision-relevant results return to the system of record.

## Evidence and closure

Evidence categories and close-qualifying categories come from `aoi.toml`.
Inference must remain inference. Compilation is not runtime correctness; a
proxy is not direct system evidence; acknowledgement is not verification.

A successful close requires at least one passing close-qualifying verification,
an approved plan, a current checkpoint, terminal claims/packets/jobs, resolved
coordination and user escalations, a valid delivery disposition, and intact
Git worktree identity.

## Capacity Planning

Capacity Planning is an on-demand analysis function, not an autonomous
scheduler. It consumes steward-validated task-class outcomes, retries, latency,
intervention, and cost data. Missing telemetry remains missing.

It may recommend a model-agnostic capability tier for a named depth-two
lane/task-class/role combination. The Chief approves or rejects; the Steward
records and distributes. v0.1 never auto-tunes routes or pins model brands.

## Improvement Pipeline

Reusable skills originate from observed pain, not top-down guesses. A normal
proposal requires durable recurrence; a critical one-off may enter review only
through explicit Chief arbitration.

Before release, a skill must have a bounded scope, representative and
adversarial fixtures, blind forward checks, permission review, independent
review, versioned immutable artifacts, rollback, canary monitoring, and a
maintenance owner. Adoption and efficiency claims require structurally bound
pre/post evidence. Unused or harmful skills should be revised or deprecated.

## Human escalation

Create `needs_user` when work changes a goal, quality/budget boundary, risk
preference, irreversible state, or unresolved high-confidence dissent. The user
need not approve each implementation step, but the organization must not invent
the user's preferences.

## Optional Codex hooks

Hooks are disabled by default. When explicitly enabled and installed, they can
restore checkpoints and warn about lifecycle violations. They are fail-open
procedural guardrails, not a sandbox or security boundary.

## Configuration drift

Every task records `profile_id` and the exact `aoi.toml` SHA-256. Governance
changes during an active task fail closed. Finish or deliberately migrate work
under an explicit future migration procedure; do not silently reinterpret old
records with new policy.
