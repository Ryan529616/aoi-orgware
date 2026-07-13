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

This authority model is cooperative. A task/session binding demonstrates task
association only; it does not authenticate the caller or prove that the caller
is the Chief. Actor and lane fields are auditable assertions. Deployments with
mutually untrusted controlling processes need an external identity,
authorization, or OS-isolation boundary.

The runtime state lock serializes one CLI transaction; it is not a Chief lease
across commands or turns. Two overlapping root turns that share a session can
still interleave source work unless the deployment provides a separate
per-turn fencing credential and an all-write enforcement boundary. Until that
facility exists and is trusted, overlapping Chief turns are prohibited and
source preservation is verified by exact snapshots rather than claimed as
physically prevented.

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

Cancellation is not an escape hatch from user authority. A task with an open
`needs_user` escalation cannot be cancelled until the bound user disposition is
recorded.

## Checkpoint bounds

A checkpoint is a semantic reconstruction aid, not a transcript. The renderer
targets at most 12 KiB and switches to a deterministic compact terminal-history
projection when the full form exceeds that threshold. Required active and
semantic detail is never hidden: the compact form may grow to a 24 KiB hard
ceiling, after which checkpoint creation fails without changing state or the
previous checkpoint. Raw logs remain outside state. The separate critical-status
projection remains capped at 12 KiB.

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
rejected. Existing file targets must be regular, non-linked files. Existing
tree targets are recursively identity-audited without following links; a tree
containing a symlink, junction, hard-linked file, special node, or more than
100,000 entries fails closed. Exact project-file claims record a SHA-256
baseline. Nonexistent planned trees have no filesystem identity to audit and
therefore retain only the cooperative path boundary. Expiry is a warning, not
automatic release: an expired claim reserves scope until it is explicitly
marked terminal.

Locks coordinate cooperative agents. They cannot stop an unrelated process
from changing a file.

Each state tree is tagged with one runtime lock domain. POSIX/WSL and native
Windows locks are intentionally incompatible, so a domain mismatch fails
closed before mutation. Native Windows support excludes UNC/network shares and
case-sensitive NTFS in the v0.1 line. Benign NTFS 8.3 spellings are
canonicalized after component-level reparse inspection; real symlink or
junction traversal remains rejected. In the native-Windows domain, project
paths and Git merge branch locks are case-folded before conflict comparison.

## Delegation

A packet has one objective, scope, deliverable, validation boundary, requested
role/tier, and optional covered locks. Root must choose the least expensive tier
that is plausibly sufficient. A packet's requested route is not proof of the
model actually used; actual routing needs separate evidence.

Packet schema v4 copies every SHA-bound input into a task-local,
content-addressed blob and SHA-binds the packet contract Markdown. The original
`source_path` must remain exact through first dispatch; after dispatch the
canonical snapshot is the authority, allowing legitimate source evolution
without rewriting history. Snapshot/contract tamper blocks dispatch, `done`,
review/capacity consumption, doctor, and close. Exact-command identity uses the
same authority gate at dispatch, `done`, review/capacity consumption, doctor,
and close. Blob bytes are completed and fsynced before atomic no-replace
publication; every managed blob ancestor must be a real directory. Legacy
failed/cancelled live inputs are retained as explicit digest-only warnings
rather than permanently re-hashing mutable origins, but any canonical snapshot
they cite remains physically validated. They cannot qualify evidence.

A drifted legacy `done` packet remains an error unless its exact bytes are
recovered. `packet-input-recover-from-tar` is the narrow recovery path: it
requires the exact packet-result SHA, target-input SHA, and a distinct carrier
archive that was itself an exact packet input. It reads one canonical regular
tar member without extracting it and applies one task-wide replay budget for
compressed/decompressed bytes, member count, per-member and aggregate declared
size. It then checks exact SHA and size and records carrier/member provenance in
a state-bound receipt associated with the immutable blob. Pre-seal receipts
created by an older harness remain explicit warnings and are accepted only
after the same archive/SHA/size replay. Receipt fields are tamper-evident while
present, but the cooperative v0.1 state model has no external receipt root;
wholesale receipt removal is outside that detection boundary. Recovery never
rewrites the evolved source tree or silently changes the reviewed identity.

Verification artifact refs use the same snapshot store. `materialize-artifacts`
upgrades only legacy `done` packet inputs and selected verification refs; it
cannot rewrite ready/dispatched authority and applies count/aggregate bounds to
the whole transaction. `verification-supersede` requires a canonical,
physically valid later passing replacement and seals both source and
replacement record identities as supersession schema v2. Doctor follows the
SHA-bound chain to a passing leaf and rejects dangling links or cycles. The
one-time `verification-supersession-seal` command either preserves an already
canonical legacy replacement identity directly or records an exact migration
receipt when the replacement was materialized after supersession. Supersession
never waives canonical snapshot integrity. On a terminal task, the command
preflights the physical checkpoint and binds pending/final state plus target
checkpoint identities so an exact interrupted command can resume or replay
idempotently.

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
