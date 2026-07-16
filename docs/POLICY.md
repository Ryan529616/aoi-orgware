# AOI operating policy

This document defines the default v0.2 governance contract. `aoi.toml` may
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

Only the current Chief writes AOI lifecycle state. Delegated agents return
bounded results to the Chief; they do not edit `.aoi/`.

Each initialized project has one durable Chief authority record. At most one
lease is active. An acquire or takeover increments its monotonic epoch; renew
and release preserve the epoch. Every lifecycle mutation not on the explicit
read-only/bootstrap allowlist is fenced by the exact session id, epoch,
high-entropy token digest, and unexpired lease while the project state lock is
held. A stale, mismatched, inactive, or expired credential fails before the
handler runs. New commands are fenced by default.

The plaintext token is never stored in shared AOI state or printed by
acquire/takeover. It is staged before the authority commit in a repo-external
per-user credential file. POSIX requires owner-only directories/files; native
Windows encrypts the secret with CurrentUser DPAPI. Subsequent processes use
the non-secret session id, epoch, and credential-file reference. The legacy
`AOI_CHIEF_TOKEN`/`--chief-token` input remains a deprecated compatibility
boundary; AOI removes those values from its environment before launching child
processes, but command-line tokens can still be exposed by the operating
system. Credentials must never enter packets, checkpoints, hooks, backups,
shell history, or shared artifacts.

First `aoi init` is the sole unauthenticated mutation and only accepts a
pristine state location. Re-initialization of an existing project is fenced.
`chief-acquire` is used for an uninitialized or explicitly released authority;
expired leases require `chief-takeover --expected-epoch` with an audit reason.
Replacing a live lease additionally requires `--force-live`. There is no
silent auto-steal. Wall-clock jitter up to five seconds is clamped to the last
renewal timestamp; a larger rollback fails closed.

Pilot validation is standalone and read-only. Pilot writers remain standalone
only when their complete write set does not overlap an initialized AOI project.
An overlapping write set requires that exact project's Chief lease; project
roots, orphan managed state, and multi-project write sets are always refused.
Every destination is revalidated immediately before publication, and
non-force writes use atomic no-replace publication.

This authority model remains cooperative. A session id is an auditable
assertion, not caller authentication, and a process under the same OS account
may be able to read the user's credential store. The exact-path state lock
serializes the full fenced CLI command and is reentrant only in the same thread
for that exact lock file. It does not stop a process from bypassing AOI and
writing source, Git, EDA, or state files directly. Mutually untrusted writers
need an external identity/authorization service, trusted all-write hook, OS
sandbox, or broker.

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
targets at most 16 KiB and switches to a deterministic compact terminal-history
projection when the full form exceeds that threshold. Required active and
semantic detail is never hidden: the compact form may grow to a 32 KiB hard
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
case-sensitive NTFS in the v0.2 line. Benign NTFS aliases in project roots and
artifact paths are canonicalized after component-level reparse inspection;
real symlink or junction traversal remains rejected. Structured `repo:` and
`host:` lock URIs must use canonical long spelling; alternate short spellings
and unresolved 8.3-style components fail closed rather than becoming a second
lock identity. In the native-Windows domain, project paths and Git merge branch
locks are case-folded before conflict comparison. A WSL repository below the
configured Windows drive mount likewise uses case-folded `repo:` lock
and `git:merge:` identities; case-sensitive Windows-backed mounts are
unsupported in v0.2.

## Delegation

A packet has one objective, scope, deliverable, validation boundary, requested
role/tier, and optional covered locks. Root must choose the least expensive tier
that is plausibly sufficient. A packet's requested route is not proof of the
model actually used; actual routing needs separate evidence.

Packet schema v5 retains the v4 content-addressed input and contract authority,
then adds dispatch provenance. Every SHA-bound input is copied into a task-local,
content-addressed blob and the packet contract Markdown is SHA-bound. The original
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

A new packet starts `ready`. Before a Codex sub-agent is launched, the Chief may
issue one short-lived `packet-arm` permit bound to the current Chief epoch,
parent session, expected Codex `agent_type`, plan, packet contract, lane, and
execution selection. At most one arm may occupy the same parent-session/type
slot because the `SubagentStart` payload does not identify an AOI packet. A
trusted protocol-v6 hook can only consume one exact current arm or write an
incident; it cannot create packets, choose an ambiguous candidate, resolve an
incident, or obtain Chief authority.

Hook consumption records the transport-specific provenance
(`codex_subagent_start_observed` or `claude_subagent_start_observed`) and the
actual event identity. This proves only that the permit existed before AOI
observed the start. Codex creates the sub-agent before `SubagentStart`, and hook
output cannot terminate that agent; the Claude Code adapter additionally denies
an unarmed governed spawn at `PreToolUse` before the sub-agent exists, but
non-cooperating or workflow-orchestrated spawns still reach `SubagentStart`
unblocked. A start with no unique valid arm therefore
creates an idempotent open `unmanaged_subagent_start` incident and instructs the
agent to stop without material work. Open incidents are visible in checkpoints,
are doctor errors, and block close/cancel until the Chief records one of the
explicit accounting dispositions. Accounting never upgrades the incident into
verification or hook-observed dispatch.

When hooks are unavailable or untrusted, a schema-v5 packet must still be armed
before `packet-update --status dispatched` can register the truthful fallback.
The fallback consumes that prior permit, records `manual_unverified`, the
registration time, and a reason; it never calls that time the agent start time.
Before consuming it, AOI revalidates expiry, Chief epoch, plan and packet
identity, execution topology, lane/Steward snapshots, and skill authority. An
expired or stale permit is rejected and may be re-armed only after the expired
attempt is durably closed.
Direct `ready -> dispatched` registration is rejected for new packets, so work
cannot be completed first and registered as an ordinary dispatch afterward. A
ready v4 packet retains one explicit migration exception only when its immutable
contract lacks the native-v5 origin marker and its task is sealed as pre-marker
legacy provenance; a native policy-v2 task cannot use that exception. The
migration is marked as such; legacy terminal timing remains `legacy_unverified`
and is never rewritten as observed.

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
present, but the cooperative v0.2 state model has no external receipt root;
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

New tasks seal task-execution schema v2 plus task-global execution policy v2,
an independent `legacy_execution_policy=false` provenance bit, and selection
schema v2. Missing or downgraded generation fields fail closed while that bit or
other v2 artifacts remain. A clean pre-marker task is sealed
`legacy_execution_policy=true` when it consumes the v4 migration path. A
quiescent legacy task with no prior execution selections adopts the v2 markers
before creating new v0.2 packets, selections, or jobs; a task with legacy
selections must finish already-authorized work or start a new task. With no
selection, execution is an auditable
implicit `single`: only one depth-one packet chain may run. An explicit
`single` also occupies the whole task execution epoch; creating several single
selections or work units cannot make them run concurrently. Concurrent chains
are legal only when they belong to the same `centralized_parallel` or `hybrid`
selection, which requires at least two specialist lanes plus an exact engaged
Steward snapshot and permits at most one active chain per specialist lane.
`ready` packets may be prepared ahead of time; only `armed` and `dispatched`
packets consume concurrency. A queued/running/unknown external job is also a
chain. It either occupies a standalone lane/selection slot or names one exact
dispatched depth-one mutation packet with `--owner-packet-id`; the packet locks
must cover the job outputs and an exact-command owner must bind the same command.
An owned job is nested in that packet's chain, and the packet cannot become
terminal first. AOI recomputes the physical owner contract identity, mode,
depth, status, lane/selection, canonical output-lock namespace and paths, and
exact-command SHA at queued creation, every transition to running, and doctor.
A depth-two
child likewise belongs to its dispatched depth-one parent chain in the same
lane/selection, and only one child may be active for that parent. These rules are
revalidated at arm, hook consumption, manual dispatch, job start/running, packet
terminal transitions, and doctor. Tasks created before the policy marker retain
explicit legacy cooperative behavior only for their existing work. Because the
state tree is cooperative rather than externally witnessed, deleting every
provenance field and artifact as the same OS user remains outside monotonic
downgrade detection.

Zero coordination requests, dependencies, or direct sessions are legal when
centralized-parallel questions are genuinely independent. AOI must not create
fake coordination records merely to raise control-plane counters. Use `hybrid`
only when bounded direct technical exchange is actually required.

Parallel/hybrid result consolidation is nevertheless formal and sequential.
After every selected specialist packet is terminal, root creates and dispatches
one dedicated read-only Steward synthesis packet with
`--steward-synthesis-for-selection-id`. Its contract binds the selected and
current Steward authority snapshots plus every specialist result SHA-256. No
new specialist packet or external job may be created for that selection once a
live or successful synthesis packet exists, and no other chain may run while
the synthesis packet is armed/dispatched. Failed or cancelled synthesis reopens
the selection for an explicit retry. The final
`execution-brief-record` must bind the done synthesis packet/result through
`--steward-packet-id` as well as the complete specialist packet/result set,
summary, dissent, blockers, and recommendation. Centralized-parallel evidence
must cover every selected specialist lane. Hybrid briefs must additionally
reference at least one exact closed cross-lane session. This proves that a
bounded Steward artifact exists; it remains control-plane evidence, not a
technical decision, and does not make independent lanes invent direct
communication.

Hybrid communication does not create private authority. The Steward records the
baseline, participants, topic, evidence boundary, expiry, conclusion, dissent,
and blockers. Decision-relevant results return to the system of record.

## Optional context providers

Context-provider receipts use a separate immutable ledger. They are not
external-job source receipts and never create technical verification records.
Provider health may be system evidence in the descriptive sense, but AOI must
not automatically place it in a configured close-qualifying `system_evidence`
category. Query and benchmark output is always `engineering_inference` with
`close_qualifying=false`.

The Phase 1 codebase-memory adapter is optional and fail-open. Only the Chief
may import an exact SHA-bound receipt. Import does not launch or prove Chief
authority over the earlier refresh, so the record remains
`refresh_authority=external_unverified`. Specialists may use only read-only
graph queries. Steward validates and summarizes receipt integrity, supported
version, provider health, freshness, missingness, and dissent; Steward cannot
modify the index or issue a technical PASS.

Live provider-health validation rechecks the exact provider binary, graph
artifact, store/config databases, and recorded client configurations. A client
configuration that drifts from the receipt cannot remain healthy, including a
change that removes the Specialist-side `index_repository` disablement.

AOI never guesses a receipt's hash algorithm. `receipt-only` freshness is
unverifiable. The explicit `codebase-memory-git-v1` profile defines the branch,
HEAD, NUL-delimited porcelain status, indexed manifest, discovery-input, binary,
store, and graph-artifact comparisons. Optional stale, degraded, unavailable,
or unverifiable context produces warnings and falls back to repository truth.
Only an active receipt explicitly recorded as required may make provider health
or freshness a doctor, brief, or close-gate error. Terminal task receipts remain
integrity-checked but are not reclassified when the external source later
evolves.

Navigation A/B records are externally measured and mutation-free. The `rg_open`
baseline cannot query the graph; neither arm can index, watch, or mutate the
provider; a non-fresh graph arm must fail open before querying. Summaries retain
missing telemetry and denominators, report descriptive paired differences, and
make no technical or general-superiority claim.

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
records and distributes. Capacity Planning does not infer a provider route,
token usage, price, or cheapest sufficient model.

## Codex resource control and Chief-approved override

Every new execution selection carries a SHA-sealed dynamic resource envelope.
`single` permits one active first-level agent. Parallel/hybrid work defaults to
at most four active first-level agents and may never exceed the selected lane
count or the twelve-thread hard ceiling. The default total-agent cap across both
depths is twice the first-level wave and never above twelve. Delegation remains
hard-capped at depth two, and existing topology, parent/child, role,
capacity-decision, claim, and dispatch gates still apply. Every selected packet
binds the exact envelope; creation validates role/depth authority and
arm/dispatch revalidates both first-level and total active-agent counts. Older
selections do not receive retroactive authority.

A User may propose a typed resource exception, but the proposal has no
execution authority. It must name one exact future selection or project config
event, bind the exact deterministic target-contract SHA-256, carry direct-User
rationale/evidence, a Chief preliminary assessment, alternatives, and an
expiry. `execution-select-plan` binds the task plan, work unit, topology,
lane/Steward authority snapshots, scope, task characteristics, rationale, and
decision conditions. A proposed config plan binds its event, task plan,
settings, and before/after file view. The Chief alone approves or rejects exact
settings and the same contract with rationale, risk boundary, rollback
condition, and compensating controls. Approval uses version CAS and is consumed
once by the matching selection or config apply. Semantic target mismatch,
stale snapshots, replay, expiry, or changed version fails closed.
Phase-one arbitration is exact accept/reject: changing any requested setting
requires a new target contract and override request.
Chief lease, task-bound session, approved plan, claim coverage,
dispatch-before-work, packet/result integrity, evidence strength, project
trust/sandbox/provider limits, twelve threads, and depth two are not
overridable.

AOI may plan and apply project-scoped `.codex/config.toml` concurrency/depth
ceilings and `.codex/agents/*.toml` model/reasoning defaults under exact claims,
reviewed plan SHA-256, and a before/after byte receipt. It never edits user-level
Codex configuration. The receipt retains the full reviewed plan preimage so
event model/reasoning/envelope claims remain verifiable. Apply requires a fresh
trusted Codex session and is not evidence of actual routing. Rollback
preflights every target, restores exact prior bytes, refuses drift, and probes
or exactly reapplies the receipt when task-state publication fails. Provider
model, token, cost, and availability telemetry remain
unavailable unless independently observed.

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

Hooks are disabled by default. When explicitly enabled, installed, and trusted
through Codex `/hooks`, they can restore checkpoints, warn about lifecycle
violations, consume Chief-issued one-time packet arms, and record task-local
unmanaged-start incidents. All other hook failures remain fail-open. Hooks are
procedural guardrails and narrow dispatch observers, not a sandbox, identity
provider, or pre-spawn security boundary.

## Configuration drift

Every task records `profile_id` and the exact `aoi.toml` SHA-256. Governance
changes during an active task fail closed. The Chief authority intentionally
does not bind one config digest, so a reviewed same-state-directory config
change does not strand lease recovery; each command reloads and pins the config
while taking the lock. Changing `state_dir` is a separate state migration and
must not be simulated by replacing `aoi.toml` under a live authority.

The managed `POLICY.md` must match the packaged contract. `doctor` reports a
different digest as an error. Authenticated `aoi init` automatically replaces
known AOI-managed predecessor policies; an unrecognized/custom policy requires
`--replace-policy-sha256 <exact-current-digest>` after review. Existing task
records are never silently reinterpreted.
