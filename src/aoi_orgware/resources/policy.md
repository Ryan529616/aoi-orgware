# AOI operating policy

This document defines the default governance contract for the v0.3 alpha line.
`aoi.toml` may change the vocabulary and capability tiers, but it must not
silently erase the authority and evidence boundaries below.

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

Repo-external credential publication is outside state-tree temporary recovery.
Process termination may leave a credential temporary, a published credential
whose authority commit did not complete, or an obsolete credential after
takeover, including under a custom credential root. A stale project/session/
epoch/token tuple cannot authorize the current authority, but these files may
still contain secrets at rest and require separate audit and cleanup.

First `aoi init` is the sole unauthenticated operation that creates a project
and only accepts a pristine state location. Re-initialization of an existing
project is fenced. Automatic Chief bootstrap accepts only an existing
`.state.lock` that is one private regular non-linked file containing exactly one
NUL byte. AOI takes that platform lock, reloads the same configuration binding,
and accepts only a complete layout or the exact existing-NUL interrupted-init
prefix before publishing first-Chief authority. It does not create, rewrite, or
unlink the root config or state-lock object as part of this bootstrap.

A missing or empty state lock, any state-lock alias, any root `aoi.toml` alias,
or any other linked or ambiguous bootstrap object is rejected with zero
automatic bootstrap mutation on POSIX and Windows. Root config temporaries left
before link publication are outside `.aoi/` recovery as well. The blocking
states require explicit offline/manual audit and recovery. A pre-link root
config temporary does not block the identical `init`, but remains manual root
residue for audit and cleanup.

`chief-acquire` is used for an uninitialized or explicitly released authority;
expired leases require
`chief-takeover --expected-epoch` with an audit reason. Replacing a live lease
additionally requires `--force-live`. There is no silent auto-steal. Wall-clock
jitter up to five seconds is clamped to the last renewal timestamp; a larger
rollback fails closed.

`recover-temporaries` has no pre-authentication deletion exception and accepts
no caller-supplied path. It requires the normal canonical NUL state lock. Every
state-tree temporary deletion requires an under-lock configuration reload
matching the original digest, state root, and lock path, followed by
current-Chief validation. Recovery may unlink only a current-schema AOI
temporary whose private regular-file, device, inode, link count, and target-name
binding still match. Any ambiguous or malformed current entry, or any legacy
temporary, prevents all ordinary cleanup. A create alias at the established
Chief-authority path is not a bootstrap exception: authority validation fails
closed and may require manual repair. No semantic task, claim, packet,
verification, or delivery state may be inferred or deleted by this recovery.

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

Closing is an honesty boundary, not a formality. Every close declares an
explicit outcome: `achieved`, `scope_changed`, `partial`, or `superseded`.
An `achieved` close requires at least one passing, close-qualifying
verification that explicitly asserts coverage of the registered completion
boundary; a non-achieved close records a boundary disposition stating why the
registered boundary was not met and where that scope now lives. Closing
`achieved` over recorded blockers requires an explicit blockers disposition.

The registered scope (title, objective, completion boundary) is mutable only
through an explicit retarget, which appends an immutable `scope_revisions`
entry (old, new, reason) and invalidates plan approval until the plan is
re-approved against the new scope. Plan approvals accumulate as history;
replacing an approved plan after packets or jobs already ran requires a
coverage note stating which work the superseded plan governed.

Risks are typed records (`open`, `retired`, `materialized`), never
append-only prose: a risk leaves the active picture only through an explicit
retirement with a reason, and checkpoints render open risks only.

`start-mini` publishes its plan, claim, task, checkpoint, session binding, and
index while holding the project state lock. If an ordinary `Exception` escapes,
it attempts to remove the newly created task, claim, and session artifacts and
rebuild the index before re-raising. This is best-effort ordinary-exception
rollback, not a multi-file transaction. Process termination,
`KeyboardInterrupt`, or cleanup failure may leave partial semantic artifacts
requiring explicit audit. Atomic-temporary recovery does not authorize guessing
that rollback.

Cancellation is not an escape hatch from user authority. A task with an open
`needs_user` escalation cannot be cancelled until the bound user disposition is
recorded. Cancelling a task that recorded changed files requires an explicit
disposition for those mutations.

## Checkpoint bounds

A checkpoint is a semantic reconstruction aid, not a transcript. The renderer
targets at most 16 KiB and switches to a deterministic compact terminal-history
projection when the full form exceeds that threshold. Required active and
semantic detail is never hidden: the compact form may grow to a 32 KiB hard
ceiling, after which checkpoint creation fails without changing state or the
previous checkpoint. Raw logs remain outside state. The separate critical-status
projection remains capped at 12 KiB.

## Atomic publication and temporary recovery

One-file publication writes a private same-directory temporary, flushes and
fsyncs its complete bytes, and then performs atomic replacement or no-replace
creation. POSIX additionally fsyncs the parent directory after publication or
recovery unlink. Native Windows has no portable parent-directory fsync through
the Python standard library. This gives one-file atomic visibility; it does not
make task, checkpoint, claim, session, and index updates one transaction.
Atomic visibility is not seamless read availability: successful raw reads see
complete old or new bytes, while a managed read that detects replacement-time
identity drift—or a transient native-Windows sharing failure—fails closed and
may be retried.

Current temporaries carry a version, operation, SHA-256 of the destination
basename, and random nonce. Ordinary exceptions attempt to remove the
temporary. A terminated process may leave an unpublished temporary or, on the
POSIX no-replace path, a two-link publication alias.

The only automatic Chief-bootstrap lock state is the existing private regular
`nlink=1` canonical NUL file. After acquiring it, AOI revalidates the exact config
binding and accepts either the complete layout or the exact existing-NUL
interrupted prefix. Missing and empty locks are never created or upgraded;
state-lock aliases and root-config aliases are never unlinked. All such states
remain unchanged for explicit offline/manual recovery.

Bounded exact pre-link state-lock temporaries may be classified as inert members
of an otherwise exact existing-NUL interrupted prefix. They are never consumed
or removed before Chief authentication. After first-Chief acquisition, the
current Chief may run `recover-temporaries`. Root `aoi.toml` temporaries and
aliases, plus repo-external credential residues, are outside this scan.

`doctor` scans for residues only while holding the same project state lock used
by cooperative writers. It therefore uses no age heuristic: a live cooperative
writer finishes or releases the lock before scanning proceeds. Recoverable
current residues are errors, ambiguous current residues are errors, legacy
private regular-file residues are manual-audit warnings, and structurally
ambiguous legacy entries are errors. Non-cooperating same-account writers remain
outside this guarantee.

Codex startup resource observations use the same cooperative-lock boundary.
Managed files are read twice and accepted only when the byte streams, descriptor
identity, and final pathname identity agree. This detects ordinary concurrent
mutation and replacement; it is not an OS-atomic filesystem snapshot against a
hostile same-account writer that deliberately restores metadata or times writes
around both reads. Registration therefore proves only managed-byte-state
equivalence to the current reviewed plan, not exact resource-event chronology or
that Codex loaded the observed bytes.

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

Path remainders in `repo:` and external-namespace locks may not contain `:`
(a `host:` path carries exactly its drive colon); a colon typo would otherwise
mint a second lock identity that never collides with the real path, silently
disabling mutual exclusion. New file claims are admitted against the
filesystem: a missing target whose parent directory also does not exist is
rejected as a probable typo, and a genuinely planned file must be admitted
explicitly (`--allow-nonexistent`), which records a `planned` baseline instead
of a silent `exists: false`.

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
parent session, expected transport `agent_type` (or an explicit any-type
wildcard that owns the whole parent slot), plan, packet contract, lane, and
execution selection. At most one arm may occupy the same parent-session/type
slot because the `SubagentStart` payload does not identify an AOI packet; a
wildcard arm collides with every other arm for its parent. The AOI role label
is never a transport label: arming by role instead of the observed transport
type produces a permit nothing can consume, so when the transport label is not
known in advance the wildcard is the correct permit. A
trusted protocol-v6 hook can only consume one exact current arm or write an
incident; it cannot create packets, choose an ambiguous candidate, resolve an
incident, or obtain Chief authority.

For a migrated semantic-v2 task, standalone packet activation uses detached
transaction schema v3. `packet-arm-prepare` binds one canonical `ready` packet,
routing arm, transition decision, one-shot permit, exact semantic head, and the
resulting routing, permit, and packet delta roots. Chief issuance and the first
unreserved consumption both apply the complete core packet contract, open-task,
approved-plan, parent/root-session mapping, canonical current resource event,
bound receipt, exact session registration, topology, resource-envelope, and
skill-canary authority gate.
The no-Chief consumer then commits routing authority, permit projection, and
canonical `ready -> armed` state in one semantic compare-and-append. A terminal
task can never be armed. Cohort transaction schema v2 remains separate and does
not claim this standalone packet-owning transition.

An exact replay of an already committed arm is historical ledger/projection
recovery, not a new authorization. It may return the one prior event before
rechecking mutable external packet-contract bytes because it consumes no new
permit and creates no new arm. Packet/receipt tamper still blocks initial
issuance, first unreserved consumption, and every later Bridge authority
transition; a committed replay cannot by itself launch Codex or complete work.

A start whose agent identity matches an already-dispatched packet from the
same parent session is a resume of that packet's thread, recorded on the
packet, not a new unmanaged agent; the same identity under a different parent
remains an incident. The Chief may grant a packet a bounded depth-two helper
budget at creation; budgeted helper starts under that packet are recorded and
bounded read-only support whose output is the packet agent's working material,
never independent packet evidence. Every denial incident records the live-arm
snapshot for its parent slot, and incident accounting may classify the guard
outcome (`true_positive`, `false_positive_guard`, `benign_no_work`,
`unverified`) so the guard's false-positive rate is measurable instead of
anecdotal.

Hook consumption records the transport-specific provenance
(`codex_subagent_start_observed` or `claude_subagent_start_observed`) and the
actual event identity. This proves only that the permit existed before AOI
observed the start. Codex creates the sub-agent before `SubagentStart`, and hook
output cannot terminate that agent. For supported Codex tool handlers,
`PreToolUse` can synchronously deny a governed tool request before invocation;
the local `codex-cli 0.144.0` canary confirmed this for Bash. That is a narrow
tool gate, not a collaboration pre-spawn gate: handler coverage is not complete,
and agent spawning still relies on the prior arm plus `SubagentStart` accounting.
The Claude Code adapter can likewise deny its governed pre-tool requests, but
neither adapter turns non-cooperating or workflow-orchestrated spawning into a
pre-spawn hard block. For any `PreToolUse` event, any internal adapter fault
returns the fixed deny response (fail-closed); only non-`PreToolUse`
lifecycle adapters remain fail-open. This is not a security boundary;
classified mapping, arm, and authority failures deny normally. A start with no
unique valid arm therefore
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
Git worktree identity. An `achieved` close additionally requires a passing
close-qualifying verification that explicitly asserts coverage of the
registered completion boundary; verification boundaries that exclude the
boundary's own claim cannot close it.

A packet result may not cite itself as its only evidence: completion requires
at least one evidence reference outside the packet's own result file, and
packets sealed under the evidence gate are re-validated at close. External
jobs record their registration time separately from the observed physical
launch; a registration lag is a computed, visible quantity, and a launch that
preceded registration by more than the tolerance requires an explicit
retroactive reason. Lane closure is derived, not narrated: a lane closes with
an explicit closure kind checked against its own packet ledger, so a lane that
owns completed work cannot close as `no_work`.

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

## Local-files confidentiality

The optional `local_files` profile means **model context allowed, file
publication denied**. It does not promise that the model provider cannot see
prompt or project context, and it is not DLP, an air gap, or an offline-model
profile. Fully offline/self-hosted execution is a separate future profile.

Local Git remains normal: branch, status, diff, commit, local bundles, local
CAS, receipts, and seals are allowed. AOI-managed Git push/LFS upload, remote
CI, GitHub Release, package publication, external artifact storage, and
attachment/connector publication fail closed. An intentional export requires a
Chief-issued one-shot permit bound to the exact task/state head, destination,
content SHA-256 and size, purpose, nonce, and expiry. The exporter receives no
reusable Chief credential, and permit consumption is authorization only; it
does not claim that AOI performed or observed an upload.

Under this profile, `doctor` reports effective fetch/push URLs, URL rewrites,
LFS endpoints, remote workflow files, local/synchronized artifact storage,
known publish-credential variable names or helpers without values, and
authenticated push/export receipts. Credential-name matching is a finite
detector, not secret discovery; an unlisted credential can remain invisible.
Confirmed external or synchronized publication paths are errors. Windows drive
letters are checked with `GetDriveTypeW` and DOS-device alias inspection:
mapped drives are network paths, while a missing root, metadata failure, SUBST
alias, or link/reparse traversal is explicitly unverified and fails the
confirmed-local storage/launch gate. File-URI paths are strictly percent-decoded
before drive classification, and the generic Windows reparse attribute is
checked in addition to symlink/junction helpers. Caller-visible and resolved
drives are both classified so resolving a path cannot erase a DOS-device alias;
malformed URLs become redacted invalid findings. Latent workflow detection remains a
warning rather than proof that the workflow ran.
Bridge issue, pre-reserve, and process-pending boundaries also preflight the AOI
artifact/CAS root and any writable cwd. A confirmed network/sync root is denied
before state publication or Popen; unverified locality is also denied without
being mislabeled confirmed danger. This is a bounded AOI-managed enforcement
slice; a same-user process or ungoverned shell can still bypass it.

Promotion is profile-aware. A publication-enabled profile may require exact
final-SHA remote-main CI. `local_files` forbids that route and instead requires
an exact local commit/tree, complete Windows and WSL suites, applicable
authorized local EDA evidence only when the project completion boundary names
it, independent review, integrity-v2 seal, package/isolated-install smoke, an
encrypted local bundle, and then stop. A remote PASS from another profile or
older SHA is historical only.

## Optional Codex Transport Bridge

`aoi-codex-bridge` is a separate, stdlib-only finite adapter; AOI core remains
dependency-free. Chief-fenced `issue` publishes an immutable launch intent,
one-shot permit, exact canonical packet-arm authority, and pinned Codex
executable/version/schema binding. `run` receives only the permit SHA and
issuance marker. It must not receive or retain a reusable Chief credential.

The Bridge accepts only that canonical armed packet. Launch-permit consumption
is one further semantic compare-and-append: the exact arm becomes
`transport_reserved`, the packet becomes bridge-owned `dispatched`, and a
sealed ownership object binds the task, packet contract, arm, launch, intent,
permit, reservation, and routing authority. This transition upgrades packet
and task dispatch generation to v2 and does not fabricate `SubagentStart`, an
agent id, thread id, turn id, or runtime observation. Ordinary packet lifecycle
commands cannot cancel or re-dispatch a nonterminal bridge owner. Known runtime
terminals map exactly to packet status (`completed -> done`, `failed -> failed`,
`interrupted -> cancelled`); `launch_unknown` and `runtime_unknown` cannot
become terminal packets until explicit reconciliation proves a new verdict.

One Chief-created per-launch OS lock serializes the complete controller
lifetime for a cooperative AOI platform lock domain. Same-arm/different-launch
competition is resolved separately by the packet/head semantic CAS. The lock
is not adversarial same-user protection and does not promise cross-Windows/WSL
mutual exclusion.

Immediately before the durable `process_start_pending` milestone, AOI
revalidates the earlier permit/arm expiry, exact live ownership and dispatch-v2
markers, fresh reserved namespace, confidentiality storage boundary, and any
writable pre-Git/claim endpoint. That durable pending milestone authorizes the
bounded exact-binary `--version` probe and the following App Server Popen; no
child process executes before it. A crash after it is `launch_unknown` and must
never trigger an automatic restart. `reservation_effective_at` is the
Chief-sealed semantic event time, not a measured wall-clock consumption
timestamp. Process-start claims derive only from journal evidence.

A terminal App Server turn remains `codex_runtime_observed`. Only a separate
exact pre/post Git tree and claim binding may add `verified_mutation`; neither
receipt implies packet or task completion. `turn/interrupt` acknowledgement
is nonterminal until correlated `turn/completed` arrives.

## Optional Codex hooks

Hooks are disabled by default. When explicitly enabled, installed, and trusted
through Codex `/hooks`, they can restore checkpoints, warn about lifecycle
violations, consume Chief-issued one-time packet arms, and record task-local
unmanaged-start incidents. For supported tool handlers, `PreToolUse` can also
synchronously deny a governed tool request before it executes; the Bash canary
proves that narrow path only. Tool-handler coverage is not complete, and
collaboration spawn is not a pre-spawn hook path: it remains governed by an arm
and later `SubagentStart` accounting. Any internal `PreToolUse` fault is
fail-closed deny; only non-`PreToolUse` lifecycle adapters remain fail-open.
Hooks are procedural guardrails, not a sandbox, identity provider, or pre-spawn
security boundary.

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

## v0.4 integrity adoption, upgrade, and offboarding

New eligible tasks use `integrity-adopt` to create the one-way `required_v2`
integrity contract with an exact baseline head. `required_v1` is historical and
frozen: its validator, candidate-only seal semantics, and sealed-task readback
remain unchanged. A sealed v1 contract is immutable, read-only, and cannot be
reinterpreted or upgraded.

Any unsealed, valid v1 contract, including a valid empty record set, may use the
explicit one-way `integrity-upgrade-v2` migration. It must supply the expected
canonical v1 contract digest. The migration preserves the canonical source v1
contract as a task-local CAS artifact and writes a receipt that binds its
schema/mode, digest, task, worktree, baseline, anchor record, and every
outstanding finding obligation. The frozen v1 validator continues to validate
that source artifact on later v2 read, doctor, and close paths; no migration may
silently reinterpret, drop, or weaken a v1 obligation.

`required_v2` is one unified ordered record ledger. Every record has a
continuous `integrity_seq` and a unique record SHA. A mutation snapshot's
content SHA may legitimately repeat when the same bytes are observed again,
but each observation has a distinct record SHA/attempt identity. Review,
finding, fix, verification, migration, and seal edges therefore use record
identity, never a snapshot content SHA as a unique key.

Review is iterative: a review with findings creates obligations; each finding's
latest fix must be independently reverified `PASS` against the exact terminal
snapshot attempt. The final review is one clean review of that terminal attempt
before seal. Its review basis must contain exactly the current passing
verification record for every prior finding—no omissions, substitutions, or
stale attempts. A terminal seal binds that exact snapshot-record SHA, final
clean-review SHA, and current live-claim scope digest. Incomplete, stale,
tampered, duplicate, self-reviewing, or out-of-order graphs fail closed.

The mutation snapshot is a NUL-safe Git observation that includes tracked,
untracked, rename, case-only, and deletion states. It is compared with the
task's live cooperative claims, so the seal says which claimed scope was
examined. It does not prove that every filesystem mutation was observed, nor
does it make claims an operating-system access-control mechanism. A reviewer
identity must differ from all recorded producer identities, but identities are
cooperative agent assertions, not authenticated humans or independent security
principals. A same-OS-user process can bypass AOI, edit source or state, and
manufacture evidence outside this boundary.

`offboard` is preview-first and applies only a reviewed
`aoi-owned-only-offboard` plan. It verifies each current preimage before change,
archives exact backups and a receipt outside the repository, removes only
AOI-owned hook/wiring fragments, and rolls back changed client files if apply
or receipt publication fails. It preserves user/foreign hook definitions and
leaves `aoi.toml` and `.aoi/` as an inert archive by default. It neither deletes
project evidence nor claims to revoke an already trusted hook or protect a
same-user environment.
