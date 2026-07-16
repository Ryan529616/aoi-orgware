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
lifecycle write. Acquisition stages a high-entropy credential in a repo-external
user store before atomically publishing authority. Every non-exempt project
mutation then holds the exact project state lock, reloads `aoi.toml`, validates
session/epoch/token/expiry, and only then enters its handler. Acquire/takeover
increment the epoch; renew/release do not. Expired takeover uses expected-epoch
CAS, and live takeover additionally requires an explicit force acknowledgement
and audit reason.

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

## Known v0.2 boundaries

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
  writes are not one atomic transaction. If `aoi.toml` was published before the
  first lock, `chief-acquire` repairs only an exact structural prefix with no
  authority, lifecycle payload, managed resource, or unknown entry. It then
  acquires the first Chief; rerun the identical profile with that credential.
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
