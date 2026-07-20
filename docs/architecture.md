# Architecture

AOI separates organization policy from agent execution. It can sit above Codex,
an Agents SDK application, a custom supervisor, or a human-operated workflow.

## Planes

| Plane | Responsibility | Authority |
|---|---|---|
| Goal | objectives, risk, budget, irreversible choices | user |
| Decision | architecture, contracts, cross-lane trade-offs | Chief |
| Control | versions, evidence index, directives, acknowledgements | Steward |
| Execution | bounded implementation and investigation | specialist lanes |
| Improvement | capability analysis and reusable-skill lifecycle | Chief-approved projects |

## Durable objects

- `Chief authority`: active/inactive lease, monotonic epoch, token digest,
  bounded transition audit, renewal and expiry timestamps
- `Task`: objective, plan digest, worktree identity, configuration digest,
  phase, and task-global execution-policy generation
- `Claim`: cooperative ownership over exact project/host/external/contract scope
- `Checkpoint`: bounded semantic reconstruction of current state
- `Lane`: owner, role, revision, authority commit, contract, next action
- `Packet`: delegated objective, scope, route request, purpose, one-time
  dispatch arms, dispatch provenance, evidence, terminal result; a Steward
  synthesis packet additionally binds every specialist result
- `Sub-agent incident`: idempotent record of an observed start without one
  current, unique arm and its later Chief accounting disposition
- `External job`: exact command, source receipt, optional depth-one packet owner,
  standalone-or-nested execution-chain identity, log, and terminal evidence
- `Context-provider receipt`: immutable provider/source-set identity, explicit
  freshness profile, optional/required policy, and a non-close-qualifying
  health boundary; it is separate from external-job source identity and normal
  technical verification
- `Context-provider benchmark`: immutable paired navigation observations and a
  deterministic `engineering_inference` summary; it cannot satisfy closure
- `Coordination request`: cross-lane question, Chief decision, directives,
  acknowledgements, implementation evidence, independent verification
- `Execution brief`: exact specialist result set plus a terminal Steward
  synthesis packet/result, dissent, blockers, and recommendation for a
  parallel/hybrid selection; a live/successful synthesis freezes new specialist
  packets and jobs in that selection so its immutable input set cannot drift
- `Execution resource envelope`: topology-derived active-agent/depth limits,
  role/tier policy, optional approved role configuration, and a digest copied
  into every packet under the selection
- `Override request`: typed User proposal, exact target and expiry, versioned
  Chief decision, and one-time consumption or revocation evidence
- `Resource config event`: reviewed plan digest, exact selection/envelope,
  project file set, immutable before/after receipt, requested routing boundary,
  and rollback disposition
- `Capacity review`: observed demand and single-use routing recommendation
- `Improvement request`: observed pain through qualified skill adoption or reject
- `Needs-user escalation`: explicit boundary that AI authority cannot cross

AOI stores project configuration in `aoi.toml`. Downstream managed projects
track their own `aoi.toml` in their repositories; this repository's root
`aoi.toml` is a local dogfood config and is intentionally untracked. Operational state lives
under the configured private state directory (default `.aoi/`) and is ignored by
Git. Backups are deterministic, hash-verified snapshots of configuration and
state, not substitutes for source control.

## Configuration binding

Task records include the exact configuration SHA-256. This prevents a task from
being interpreted under a different role map, evidence vocabulary, receipt
contract, or risk policy after it starts.

Chief authority is deliberately bound to the project root, state directory,
and lock domain rather than one configuration digest. A reviewed configuration
change therefore does not strand lease recovery, while every task still fails
closed on digest drift. Changing `state_dir` remains an explicit state migration.

## Chief fencing

The first initialization of a pristine project is the sole unauthenticated
project-creation path. Acquisition stages a high-entropy credential in a
repo-external user store before atomically publishing authority. Every
non-exempt project mutation then holds the exact project state lock, reloads
`aoi.toml`, validates session/epoch/token/expiry, and only then enters its
handler. Acquire/takeover increment the epoch; renew/release do not. Expired
takeover uses expected-epoch CAS, and live takeover additionally requires an
explicit force acknowledgement and audit reason.

Automatic Chief bootstrap has no publication-repair exception. It accepts only
an existing `.state.lock` that is one private regular non-linked file containing
exactly one NUL byte. After taking that platform lock, AOI revalidates the exact
configuration binding and accepts either a complete layout or the exact
existing-NUL interrupted-init prefix before publishing first-Chief authority.

Missing or empty state locks, every state-lock alias, every root `aoi.toml`
alias, and every other linked or ambiguous bootstrap object fail closed with
zero automatic bootstrap mutation on POSIX and Windows. They require explicit
offline/manual audit and recovery. `recover-temporaries` likewise requires the
normal canonical NUL lock, and every state-tree residue deletion occurs only
after an under-lock config reload and current-Chief validation.

The outer command lock is reentrant only for the same thread and exact lock-file
identity so existing transactional handlers can nest safely. A five-second
wall-clock jitter allowance is clamped to the previous renewal timestamp;
larger rollback fails rather than producing a backward audit chain.

## Resource-control binding

Resource control deliberately splits static Codex configuration from dynamic
AOI execution authority. Project `.codex/config.toml` holds platform ceilings;
project `.codex/agents/*.toml` holds requested role model/reasoning defaults.
The execution selection holds the smaller active-agent/depth envelope. Packet
creation binds its digest, while arm, hook consumption, manual dispatch,
doctor, and closure revalidate it against current state.

The normal envelope is derived from topology without provider telemetry:
single is one first-level agent; parallel/hybrid is the selected specialist
lane count capped at four by default and twelve absolutely. The total active
count across first- and second-level agents defaults to twice that wave and is
also hard-capped at twelve. Depth two is only a ceiling here; the independent
Capacity Planning decision and parent/leaf gates remain mandatory.

User/Chief override authority is a separate state machine. The User proposal
is a task-bound attestation, not authenticated human identity and not direct
execution authority. Chief arbitration uses expected-version CAS and records
exact approved settings. Only `execution-select` or `codex-config-apply` can
consume the matching target once. The resulting envelope/event points back to
the consumed authority, so removing either side is an integrity error.
Execution-resource approval additionally binds a deterministic selection
proposal covering the task plan, topology, lane/Steward authority snapshots,
scope, task characteristics, and decision conditions. Config approval binds
the exact event/task-plan/file plan digest. Consumers recompute these contracts
before mutation; semantic reuse of an approved identifier fails closed.

Config apply requires claim coverage and the exact reviewed plan SHA. It writes
a task-local receipt containing the full plan preimage before changing project
files, applies each file with exact-state transition recovery, then publishes
the event.
A resource event is effective-current only when strict replay leaves it on top
of the apply stack and its receipt/live after-bytes validate. Replay requires
timezone-aware unique transition instants, apply transitions in event append
order, and every rollback to pop the current stack top. Writers serialize up to
five seconds of cross-process wall-clock jitter one microsecond after the latest
causal resource/registration record; larger rollback fails before mutation.
A startup-only Codex hook receipt is registered later by the same task-bound
Chief session. Registration v2 seals the startup and applied-event snapshots,
receipt/plan/config/profile-manifest hashes, task plan/worktree, and Chief
session/epoch. Startup receipt schema v2 records managed project-file SHA-256
identities under the state lock using two matching bounded reads plus stable
descriptor/path metadata; registration requires every reviewed
after-image in that observation and requires the event to remain
effective-current at registration. Wall-clock comparison is not causal
authority across Windows/WSL processes. Byte-identical events are deliberately
indistinguishable at startup; current event/plan/Chief authority is selected at
registration without claiming that startup followed that exact event. This
establishes only `registered_byte_state_equivalent_only`; actual config loading,
provider route, runtime profile, and sandbox remain unavailable without
independent receipts. The stored Chief record hash is a command-time opaque
attestation, not a reconstructable append-only history after lease renewal.
These read checks are not an OS-atomic snapshot against a hostile same-account
writer, which remains outside the cooperative state-lock guarantee. Historical
schema-v1 receipts remain hash-validated but cannot satisfy v2 registration or
be silently rewritten; they do not block unrelated v2 creation.
A post-publication durability error retains the consistent event/files for
doctor/reconcile instead of rolling back behind an already-published state.
Explicit rollback preflights all unchanged applied bytes, restores the
receipt's exact prior bytes, and reconciles a failed state publication by
probing the published event or reapplying the exact postimage. No operation
edits user-level Codex configuration or hot-reloads the current session.

## Bootstrap boundary

The optional `aoi-bootstrap` skill is an inference and onboarding layer, not a
new authority plane. It may inspect repository structure and propose departments,
capability tiers, evidence gates, and risk paths. Its output remains an
untrusted candidate until:

1. the strict CLI validates the complete TOML outside project state;
2. the user reviews assumptions and the exact write preview;
3. the user explicitly approves application;
4. `aoi init --config` applies the exact validated bytes without clobbering;
5. `aoi doctor` verifies the resulting state and lock domain.

This keeps natural-language interpretation outside the deterministic state
transition boundary. The skill never creates always-running agents, installs
hooks, chooses a provider-specific model, or changes user-owned goals and risk
decisions.

## State safety

- Project root is an explicit `AOI_ROOT`, an explicit library argument, or the
  nearest `aoi.toml`/Git root.
- Explicit roots do not walk upward into a parent project.
- filesystem root, the user's home directory, explicit roots crossing real
  symlink/reparse components, path traversal, and malformed lock URIs fail
  closed; benign Windows aliases in roots/artifact paths are canonicalized
  after component checks, while structured lock URIs must use canonical long
  spelling and reject alternate short spellings or unresolved 8.3-style
  components; WSL repositories below the configured Windows drive mount use a
  case-folded `repo:` and `git:merge:` authority domain.
- configured state paths are validated under both POSIX and Windows path
  semantics and must resolve inside the project root;
- state writes use same-directory replacement after flushing the new file;
- writers are serialized with `fcntl.flock` on POSIX/WSL or a one-byte
  `msvcrt` lock on native Windows;
- project mutations hold that lock across Chief validation and the complete
  handler; lock path/inode changes fail before nested layout repair;
- immutable packet/verification blobs are completed and flushed before atomic
  no-replace publication, and every managed ancestor is checked for links;
- `.aoi/platform.json` permanently binds the tree to one lock domain so
  alternating WSL/native writers fail closed;
- existing repo/host tree claims receive a bounded recursive identity audit;
  nested links, hard-linked files, special nodes, and oversized scans fail
  closed before ownership is recorded;
- generated state is private (`0700` directories, `0600` files where
  supported). Native Windows ACL equivalence is reported as unverified.
- Chief secrets live outside the repository. POSIX validates owner-only
  directories/files and safe ancestors; native Windows uses CurrentUser DPAPI.
  Process termination can leave credential temporaries, published-but-orphaned
  credentials, or obsolete takeover/custom-root credentials. Stale tuples
  cannot authorize current authority, but state-tree recovery does not remove
  these secret-at-rest residues.

## Crash consistency and recovery boundary

Atomic publication uses an identifiable private temporary in the destination
directory. The file is completed and fsynced before no-replace creation or
replacement; POSIX then fsyncs the parent directory. Native Windows has no
portable parent-directory fsync in the Python standard library.

The a2 resilience suite contains a process-local observation hook rather than a
production environment kill switch. A parent process can pause a worker after
temporary fsync or after publication but before directory fsync, terminate it,
and inspect the resulting bytes. The asserted single-file contract is that a
kill before replacement leaves the complete old destination and one complete
named temporary, while a kill after replacement leaves the complete new
destination. Successful raw concurrent reads must contain a complete old or
new JSON generation. This is atomic visibility, not seamless availability:
`load_json` fails closed if it detects replacement-time identity drift, and a
native-Windows reader may transiently fail on file sharing; callers may retry
those bounded failures. Linux and Windows receipts remain release evidence, not
an inference from the test design.

The deterministic Chief, claim, and one-time packet-arm races pause workers at
the actual state-lock acquisition boundary, rather than at a nearby test-only
barrier. Passing local platform runs are development receipts only; the
Linux/Windows CI release receipts remain pending.

The state-lock bootstrap is deliberately non-constructive. POSIX `flock` and
native-Windows `msvcrt` operate only on the already canonical private `nlink=1`
NUL lock; AOI does not create a missing lock, upgrade an empty lock, or unlink
an alias. The locked revalidation accepts a complete layout or the narrow
existing-NUL interrupted prefix. Bounded exact pre-link state-lock temporaries
may be inert members of that prefix, but they remain untouched until a later
current-Chief `recover-temporaries` run.

Checkpoint publication remains an ordered multi-file operation, not a
transaction. The suite exercises a checkpoint published before task state as a
detectable mismatch repaired by retrying the exact checkpoint command, and
task state published before the index as a rebuildable stale index. Those cases
do not establish recovery for every command or persistence boundary.

`doctor` and `recover-temporaries` scan under the project state lock, so they do
not classify an active cooperative writer's temporary by age. Recovery
reloads `aoi.toml` after acquisition and refuses a changed digest, state root, or
lock path before scanning. It preflights every selected entry, refuses all
ordinary cleanup when any entry is ambiguous or legacy, revalidates filesystem
identity before each unlink, and is retryable after termination during cleanup.
There is no pre-authentication deletion exception: every state-tree residue
deletion requires the current Chief. A linked state lock prevents the command
from acquiring its lock and therefore requires offline/manual recovery. Any
create alias at the established Chief authority path likewise fails authority
validation and is left for manual audit and repair.

This state-tree scan intentionally excludes every root `aoi.toml` temporary or
alias and all repo-external Chief credential files. A root alias blocks normal
loading and requires offline/manual recovery. A pre-link root temporary does not
block the identical `init`, but remains manual residue for audit and cleanup.
Credential residue cannot authenticate after its tuple becomes stale, but may
still expose a secret at rest; automated credential garbage collection is an a2
follow-up.

Process termination does not simulate storage power loss, controller-cache
loss, or filesystem-journal failure. POSIX directory fsync improves the intended
durability ordering but is not power-loss evidence. Native Windows provides
atomic visibility and flushed file contents, not POSIX-equivalent directory-
entry durability. AOI therefore makes no power-loss-durability claim.

### Future bootstrap protocol — not implemented

A future C→S protocol would enforce the fixed lock order `stable root-scoped
bootstrap lease → project state lock` for every cooperating AOI actor. An
ownership ledger would record only inodes and empty directories created by that
attempt. Rollback would run in reverse order only when exact identity and
unchanged payload still match, and would never chmod or delete a pre-existing
entry. This is a roadmap requirement, not current behavior or evidence. Even if
implemented, it would govern cooperating AOI actors only; external same-user
mutation, process-crash recovery, and power-loss durability would still require
separate evidence and boundaries.

## Integrations

The core has no provider dependency. Optional protocol-v6 `aoi-codex-hook`
integration translates Codex lifecycle events into checkpoint reminders and
guardrails. On `SubagentStart`, it also performs one narrow state mutation: it
atomically consumes one exact Chief-issued packet arm or records an unmanaged
start incident. The hook never receives a Chief secret and cannot create a
packet, choose an ambiguous arm, resolve an incident, or terminalize work.

`SubagentStart` is an observation after Codex has created the sub-agent. Hook
output cannot terminate that agent, so AOI records provenance and injects a
stop-without-work instruction rather than claiming a pre-spawn hard block.
Manual dispatch remains available as explicit `manual_unverified` provenance,
but a schema-v5 fallback must consume a permit that was armed before the CLI
registration and is still current for expiry, Chief epoch, plan, packet,
topology, lane/Steward, and skill authority. Direct ready-to-dispatched
registration is rejected. A native-v5 marker is sealed into the packet contract,
so changing only state schema to v4 cannot invoke the legacy exception; the task
must also carry pre-marker legacy provenance. Other runtimes should integrate
through equivalent observed-event adapters or the CLI/JSON contract without
bypassing AOI authority rules.

The `aoi codex-init` composition path keeps project integration repository-local
while installing the generic AOI operating skill once at Codex user scope. It
non-destructively merges hook definitions and the stable hook feature under
`.codex/`, installs the skill under `$HOME/.agents/skills/`, and enables the AOI
policy flag only when no active task binds the previous digest. Project-specific
instructions remain in that repository. It never edits global `CODEX_HOME`
settings or bypasses Codex's exact-definition `/hooks` trust review.

The optional codebase-memory Phase 1 adapter is a second, deliberately narrower
integration. A Chief-fenced command imports an exact reviewed receipt into a
task-local immutable snapshot. `doctor` and a Steward execution brief may
recompute provider health and, only under an explicit AOI freshness profile,
repository freshness. Specialists remain outside this mutation path and use
only read-only graph tools supplied by their runtime. AOI never invokes
`index_repository`, starts a watcher, copies the graph store into `.aoi/`, or
turns graph output into technical evidence.

An imported receipt records `refresh_authority=external_unverified`: receipt
integrity does not prove that the Chief launched the original index operation.
The optional provider fails open. Only a task that explicitly records the
active receipt as required treats non-healthy/non-fresh status as a doctor,
Steward-brief, and close-gate error. See
[the codebase-memory contract](codebase-memory.md).

### Codex hook provenance and mutation receipts (v0.4)

The optional Codex adapter records bounded, sealed observations and can deny a
governed request on supported `PreToolUse` handlers; it does not turn hook
delivery into a security boundary. Installation provenance binds the
resolved hook launcher, package version and distribution metadata, the promoted
wheel identity, generated launcher, and a bounded manifest of every non-cache
runtime package file checked against `RECORD`. The unpublished local schema-v2
route additionally requires and rechecks the installed `aoi-codex-bridge`
entry point, launcher, optional generated script, and transport CLI module.
Its clean source manifest includes ordinary tracked dotfiles and
dot-directories; safe leading-dot paths are not confused with traversal or
absolute paths.
Pip-generated, hashless
`__pycache__/*.pyc` files are an explicit cooperative-runtime exclusion; other
files under `__pycache__` are rejected. At hook execution, AOI's provenance
validator rechecks that receipt against the invoked launcher and current
installed package bytes, and `doctor` reports any mismatch.
Editable/source-checkout installs, link traversal, `.pth` shadows, mixed
site-package resolution, entry-point mismatch, and any covered package or
launcher drift are rejected by that validator. Any internal `PreToolUse` fault
returns the fixed deny response (fail-closed); only non-`PreToolUse` lifecycle
adapters remain fail-open. This is not a pre-import or OS security boundary. A
`RECORD`/installed-package comparison is not always a
cryptographic proof that the original wheel archive was installed: without a
matching `direct_url` archive digest the receipt reports only its weaker
package-and-installer mapping.

PreToolUse and PostToolUse correlate only the exact stable triple
`(session_id, turn_id, tool_use_id)`; optional agent/event fields are
attribution, not correlation authority. The PreToolUse receipt records parser,
input digest, sorted targets, session mapping, claim snapshot and the decision.
For supported Codex tool handlers, a deny is synchronous before tool execution;
the local `codex-cli 0.144.0` canary proved this for Bash. It deliberately keeps
provider, profile, and sandbox verification `unavailable`, and does not prove
coverage for every tool handler. PostToolUse binds that pre-receipt digest plus
input and response digests, targets, and completion observation. A mutation is
verified only when it has paired, distinct before/after SHA-256 values;
otherwise it remains `unavailable`. PreToolUse is therefore a narrow,
cooperative supported-tool gate; PostToolUse is an observation/receipt. Neither
is rollback, a general write monitor, or a collaboration pre-spawn gate:
spawning remains governed by the arm and later `SubagentStart` accounting.

Receipts are canonical, create-only records keyed by receipt type and event
identity under the AOI state lock. The store accepts at most 1,024 records and
16 MiB total (each record at most 64 KiB); a same-identity byte difference,
corruption, link/identity anomaly, or capacity exhaustion fails closed rather
than overwriting, evicting, or partially accounting for an event. Supported,
parseable paths can be `covered`, `unclaimed`, or `uncovered`. An unavailable
MCP registry is explicitly **uncovered**, not trusted or implicitly covered.

Close/doctor mutation snapshots bind NUL-safe Git status, including untracked,
renamed, case-only, and deleted paths, to the live task claims. New
`integrity-adopt` creates `required_v2`. `required_v1` is a frozen, read-only
compatibility reader: its candidate-only seal and sealed contracts do not
change. Any unsealed valid v1 contract, including a valid empty record set, may
explicitly migrate through `integrity-upgrade-v2`, preserving a canonical v1 CAS
source receipt and all its finding obligations.

The `required_v2` ledger is one sequence of records with continuous
`integrity_seq`. A snapshot content SHA identifies observed bytes and may recur;
its record SHA uniquely identifies that observation/attempt. Every graph edge
uses the record SHA. Seal targets one exact terminal snapshot record, whose
final clean review has an exact basis of `PASS` re-verifications for every prior
finding's latest fix on that same attempt. Those records are cooperative
evidence: reviewer identity must differ from recorded producer identities, but
it is not authenticated human identity or protection from a same-OS-user writer
that bypasses AOI.

## Local-files confidentiality boundary

`local_files` is an AOI publication policy, not a model-isolation claim. Model
context remains allowed, while governed Git/file/artifact/package/attachment
publication is denied. State/CAS/receipts remain local. Exact external export
uses a one-shot Chief permit and never hands reusable Chief credentials to the
consumer.

The doctor and launch-time checks share the same storage classifier. Confirmed
network or common sync roots fail closed. Windows drive-letter paths use
`GetDriveTypeW` and DOS-device inspection so mapped drives cannot masquerade as
local; missing roots, metadata failure, SUBST aliases, and link/reparse
traversal are separately labelled unverified and also fail a confirmed-local
gate. File-URI percent decoding precedes drive classification, and the generic
Windows reparse attribute is inspected at each existing path ancestor.
Caller-visible drive classification precedes resolution; the resolved target is
then checked separately, so DOS-device aliases cannot disappear at the trust
boundary. Malformed URLs are fail-closed invalid findings.
Environment checks cover a finite set of known credential names and
cannot prove that an unlisted secret is absent. This does not intercept an
ungoverned same-user shell and does not replace OS DLP. Profile-selected
promotion makes remote CI mandatory only for a publication-enabled route; it
is forbidden/not applicable for `local_files`.


## Optional Codex Transport Bridge

`aoi-codex-bridge` is an optional stdlib-only adapter, not a second AOI state
model and not a resident scheduler. `issue` is Chief-fenced and writes an
immutable issuance marker. `run` receives only its exact permit SHA, starts at
most one local pinned App Server process over stdio, and persists a milestone
before each uncertain process/request boundary. `inspect` is read-only.
`verify-mutation` is a separate Git/CAS/claim evidence transition.

The reservation transition atomically consumes the exact canonical packet arm
without inventing a hook observation. The attempt becomes
`transport_reserved`; the packet becomes bridge-owned `dispatched`; and a
content-addressed ownership object binds packet contract, arm, launch, intent,
permit, reservation, and routing authority. Packet/task dispatch generation
v2 makes the new wire semantics explicit and downgrade-detectable. A known
runtime terminal has one packet mapping (`completed/done`, `failed/failed`, or
`interrupted/cancelled`); unknown launch/runtime outcomes remain nonterminal at
the packet layer until reconciled. Completed, failed, and interrupted terminal
receipts require every started item to have completed; `runtime_unknown` may
retain an outstanding item as explicit incomplete-stream evidence.

A Chief-created per-launch OS lock covers reserve/load, controller execution,
and terminal publication. It supplies cooperative same-platform at-most-one
process ownership for one launch id; semantic packet/head CAS arbitrates
different launch ids contending for one arm. Neither mechanism is adversarial
same-user isolation or cross-Windows/WSL mutual exclusion.

The `process_start_pending` callback is the durable runtime-process
authorization boundary. It revalidates permit/arm expiry, the complete live
ownership and dispatch generation, fresh namespace state, `local_files`
storage, and the writable Git/claim pre-image immediately before commit. The
same milestone authorizes the bounded exact-binary version probe and subsequent
App Server Popen; neither child may execute before it. After pending commits,
failure becomes `launch_unknown` and no invocation may automatically start a
replacement process. `reservation_effective_at` is a sealed semantic event
time, not observed consumption wall time. CLI start fields are derived only
from the durable journal; `app_server_start_durably_observed` deliberately does
not infer an unpersisted physical Popen.

The runtime projection preserves the original `codex_runtime_observed`
terminal receipt. A writable turn can gain a second, binding-backed
`verified_mutation` record only after exact pre/post Git endpoints, tree
objects, and claim coverage materialize from CAS. The mutation index is a
separate semantic namespace; neither receipt changes the AOI task completion
state. A start request with an uncertain response becomes `launch_unknown` and
cannot be resent. A known active turn lost mid-stream becomes
`runtime_unknown`. `turn/interrupt` acknowledgement remains nonterminal until
the correlated `turn/completed` notification arrives.

## Known v0.3 alpha boundaries

- One state tree may be written from POSIX/WSL or native Windows, not both.
  WSL support assumes its native filesystem or a mount that reliably exposes
  POSIX ownership and mode bits. Metadata-less DrvFs mounts fail closed on the
  required `0700`/`0600` checks; move the project under the WSL distribution or
  enable and verify DrvFs metadata before migration.
- Native Windows support is limited to ordinary local filesystems; UNC/network
  shares and case-sensitive NTFS are unsupported. Project-file and Git-branch
  locks therefore use case-insensitive canonical identities in that domain.
- Native Windows provides atomic visibility and flushed file contents, but AOI
  cannot claim POSIX-equivalent parent-directory metadata durability or private
  ACL enforcement through the Python standard library.
- Nonexistent planned trees have no filesystem identity to inspect and retain
  only AOI's cooperative lexical reservation until a later claim/release audit.
- The Chief lease fences cooperative AOI CLI lifecycle writes, including pilot
  writers that overlap an initialized project. It cannot stop the same OS user
  from bypassing AOI and directly changing source, Git, EDA, or `.aoi/` files.
- Session IDs are assertions, not authenticated identities. A process under the
  same OS account may be able to use that account's credential store; mutually
  untrusted writers require an external broker, sandbox, or identity boundary.
- Initialization is resumable and non-clobbering, but its multiple filesystem
  writes are not one atomic transaction. `chief-acquire` can resume only a
  complete layout or exact interrupted prefix that already has the canonical
  private `nlink=1` NUL state lock. Missing/empty/aliased locks and all root-config
  aliases remain unchanged and require offline/manual recovery. After a valid
  first-Chief acquisition, rerun the identical profile with that credential.
- Capability tiers are policy labels, not calibrated cross-provider scores.
- Project Codex model/reasoning settings and packet model tiers are requested
  routes, not observations. AOI has no authoritative per-spawn token/price
  telemetry and cannot select or prove the cheapest sufficient provider model.
- Hook-observed dispatch authenticates a permit/epoch/state transition, not the
  human identity behind a session id or the provider's actual model routing.
- Legacy execution-selection v1 records are not silently reinterpreted and
  cannot authorize new v0.2 packet activation. Finish already-authorized legacy
  work and start a new task; legacy terminal packet timing remains
  `legacy_unverified`.
- New tasks bind `task_execution_schema_version=2` to
  `execution_policy_version=2` plus `legacy_execution_policy=false`; that
  independent provenance and remaining v2 artifacts prevent ordinary missing
  markers from being interpreted as legacy. Existing legacy work retains
  cooperative concurrency, but only a quiescent task without legacy selections
  can adopt v2 for new packets/selections/jobs. Under v2, unselected work is implicit single,
  explicit single is task-global, and concurrency exists only within one exact
  centralized/hybrid selection. Standalone active jobs consume the same epoch;
  an owned job stays inside one dispatched depth-one mutation-packet chain,
  whose physical contract and canonical locks/command authority are recomputed
  at creation, running, and doctor.
- AOI has no external append-only witness for task execution provenance. A
  same-OS writer that removes every policy/provenance field and v2 artifact can
  still manufacture a legacy-looking cooperative state.
- Legacy import exists for the originating harness but is disabled by default.
- The Phase 1 codebase-memory adapter supports one reviewed v0.9.0 receipt
  schema and an explicit Git freshness profile. It is not a general MCP
  integration layer, refresh scheduler, watcher, or dependency declaration.
- No proof yet that AOI's added process pays for itself on every workload.
