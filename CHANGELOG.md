# Changelog

All notable changes to AOI (`aoi-orgware`) are recorded here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project aims to follow [Semantic Versioning](https://semver.org/) once it
leaves the alpha line. Until then, minor versions may still change behavior.

## [Unreleased]

### v0.4.0a2 (unreleased)

- **O1 — semantic commit v2.** Event-authoritative task state, replayable
  projections, exact retry, and recovery are covered by focused semantic tests.
- **O2 — legacy migration.** Byte-preserving legacy snapshots, quiescence
  checks, migration receipts, and pre-transition rollback are covered by
  focused migration tests.
- **O3 — dispatch v6.** Immutable arm-time routing authority, startup receipt
  registration, and explicit `unavailable` runtime-routing fields are covered
  by focused packet and hook-receipt tests. Dispatch, routing, and integrity
  now share one bounded agent-identity grammar, including canonical Codex
  identities such as `/root/reviewer`.
- **O4 — permits.** One-shot, Chief-authorized transition permits and exact
  consumption/replay checks are covered by focused semantic-object tests.
- **O5 — cohorts.** Deterministic manual waves and no-launch-overclaim receipts
  are covered by focused cohort/permit tests; this does not claim a transport
  launch.
- **O6 — Codex adapter.** Provenance-bound hook definitions, bounded hook
  receipts, and cooperative tool-path coverage reporting are covered by focused
  adapter tests. Hook installation remains distinct from runtime trust; live
  Codex `/hooks` delivery and user trust remain unproven in this checkpoint.
  WSL onboarding now emits a direct Linux `command` plus one canonical no-shell
  `wsl.exe --distribution ... --user ... --cd ... --exec ...`
  `commandWindows`, both bound to the same absolute launcher, project root, and
  provenance digest. Complete Microsoft-kernel/distro/interop/passwd signals
  are required; partial WSL detection and native-Windows WSL UNC onboarding
  fail before mutation. Doctor and offboard validate the complete expected
  platform pair, so a structurally valid but wrong distro/user/route cannot be
  accepted or silently removed. Onboarding likewise rejects missing fields and
  non-exact current pairs. The sole current-to-current upgrade exception is an
  exact old pair reconstructed from the currently persisted validated
  provenance receipt during a proof-changing rotation; mixed old/new pairs
  and individually canonical but cross-bound identities still fail. Desired
  hook bytes precede replacement-receipt publication, so a failure in that
  cross-file window remains fail-closed and can be retried. A bounded
  direct-token/known-shell detector blocks malformed or reordered AOI-hook
  references, including tokenizer quote failure with an AOI signature and CMD
  caret-normalized executable names, instead of preserving them as foreign.
  It is not an exhaustive shell parser or DLP boundary. The tolerant WSL
  parser remains legacy ownership recognition only.
- **O7 — release promotion.** Exact artifact inventory, release manifest,
  promotion bundle, and local rehearsal contracts are covered by focused release
  tests. This is not a claim of GitHub Actions, PyPI publication/readback, or a
  live canary.
- **Reviewed local install proof.** `reviewed_local_install_bundle` v2 is a
  separate, unpublished route with
  `proof_scope=exact_local_wheel_install_only`, not a release or promotion.
  It cross-binds a caller-approved bundle SHA and external store with clean
  source commit/tree/manifest, inventory/rehearsal, exact wheel bytes, PEP 610
  archive evidence, installed `RECORD`, and runtime bytes. Its local schema-v2
  receipt now also requires and rechecks the `aoi-codex-bridge` entry point,
  launcher, optional generated script, and transport CLI module. Full tracked
  source manifests accept safe dotfiles and dot-directories such as
  `.gitignore` and `.github/`, while still rejecting traversal and noncanonical
  paths. It does not claim a tag, GitHub Release, PyPI publication, or live
  Codex `/hooks` trust. The
  source identity is reviewed context, not an independent source-to-wheel,
  builder-toolchain, or test-execution attestation; the test summary is
  explicitly caller-supplied.
- **O8 — integrity v2 and adoption (implementation candidate; promotion
  pending).** New `integrity-adopt` creates `required_v2`. `required_v1` is
  frozen and read-only for compatibility: its validator, candidate-only seal
  semantics, and sealed contracts remain unchanged. Any unsealed valid v1
  contract, including a valid empty record set, may make the explicit
  `integrity-upgrade-v2` transition with an expected canonical v1-contract
  digest; its receipt retains
  the canonical v1 CAS source and every finding obligation rather than silently
  reinterpreting history.
  `required_v2` uses one ordered `integrity_seq` ledger. Snapshot content SHA
  may repeat, while record SHA/attempt identity is unique and is used by every
  review, finding, fix, verification, and seal edge. A terminal seal requires
  an exact final clean review and a complete basis of current `PASS`
  re-verifications for every prior finding on its exact terminal attempt.
  The post-fix dogfood dead-end (duplicate content SHA) and v1
  verification loop-variable bug were recorded as P1 findings. Exact
  post-commit independent review and seal, GitHub CI, local bundle, and
  installed-package validation remain pending; no promotion, release, or
  downstream installation/execution result is claimed. Manual reviewer identity
  remains a cooperative assertion, and unavailable MCP registry paths are
  reported as uncovered.
- **O9 — optional Codex Transport Bridge (implementation candidate; promotion
  pending).** The dependency-free core now ships a separate finite
  `aoi-codex-bridge` entry point for one packet/thread/turn over local App
  Server stdio. Chief issuance binds an exact one-shot permit, stable Codex
  `0.145.0` executable/schema set, prompt/cwd/model/effort/sandbox, and—for both
  read-only and writable turns—a pre-turn Git endpoint preserved in task CAS.
  The current repair candidate also binds an isolated exact-policy
  `CODEX_HOME`, disables web/apps/remote-plugin/multi-agent/remote-control
  surfaces at process and thread levels, and inserts a bounded live
  `model/list` gate before `thread/start`; only one visible exact model with the
  requested supported effort and no remaining page can proceed.
  `model/rerouted` is now a forbidden exact-model contract breach rather than
  an auxiliary observation: at stdout method recognition, before main-queue
  enqueue or reading a later line, every recognized exact bounded notification
  publishes an in-flight consumer barrier and is synchronously written to
  controller-owned task-local CAS. Queue reads and terminal-candidate return
  wait for already recognized callbacks, but an instantaneous wait is not
  completion authority. Before a `turn/completed` observation can produce its
  terminal journal append, the one-shot controller closes stdin and requires
  natural exit zero, full stdout/stderr drain/join, zero callback inflight, and
  no reader fault. Forced cleanup, nonzero exit, process I/O/wait failure,
  partial output, or timeout aborts that irreversible stream seal and can never
  publish `completed`. Exact-CAS reroutes may instead append typed `failed`, and
  other owned faults may append `runtime_unknown`, without claiming a clean
  seal; bounded cleanup then follows. A reroute serialized after the earlier
  completion candidate is therefore still persisted and preempts it.
  Successful persistence retains a typed reader fault over later reader,
  backpressure, process, and cleanup errors, so queued completion, callback
  latency, and duplicate ordering cannot bypass it. Failure paths settle any
  already in-flight reroute callback within the same absolute deadline before
  selecting the terminal fault. Owned cleanup now isolates poll, terminate,
  wait, and kill so one failed step cannot skip later kill fallback, and it
  retains the child handle until exit is confirmed. Reader join/liveness faults
  are fixed transport errors rather than raw escapes, with symmetric stdout and
  stderr accounting; an unknown receipt with a live reader is explicitly not a
  full-quiescence claim. Ambiguous durable journal/CAS sink errors remain
  outside that bounded cleanup catch. All
  malformed, wrongly correlated, wrong-model, and schema-valid forms raise one
  redacted typed fault. The callback receives only method, exact wire bytes,
  and digest; it is mandatory, cannot synthesize evidence when absent, and
  controller defense persists raw test-double bytes before parsed-field
  consistency checks.
  AOI re-captures that endpoint under the issue lock, before reservation, and
  at process-pending. The endpoint now binds a separate full live task-claim
  authority as well as mutation-path coverage, so clean Git status cannot hide
  claim add/remove/owner/status/worktree/lock drift. Historical null-CAS or v1
  endpoints fail closed before process start; only writable turns may
  separately elevate the post-image.
  Runtime milestones
  are semantic transactions with explicit `launch_unknown`/`runtime_unknown`
  reconciliation and no automatic resend. Initial execution, replay, and
  reconciliation now derive the same process-start evidence from the complete
  durable journal instead of describing only the current CLI invocation. A
  completed runtime receipt remains
  `codex_runtime_observed`; Git/tree/claim materialization is a separate
  binding-backed `verified_mutation` projection and neither implies AOI task
  completion. A migrated semantic-v2 task can now reach that arm without a
  legacy write: `packet-arm-prepare` emits standalone transaction schema v3,
  Chief issuance applies the complete core packet, parent/root-session, and
  canonical resource event/receipt/registration authority gate; first
  unreserved no-Chief consumption repeats it and commits routing, permit
  projection, and canonical `ready -> armed` packet state in one semantic CAS.
  The CLI composition root injects that validator into the semantic command
  handlers; the handlers fail closed without it and never reverse-import the
  CLI module.
  Before that first commit, terminal tasks, missing packet delta roots,
  stale/tampered authority, and old-schema substitution fail closed. Exact
  committed replay is historical event/projection recovery, not renewed packet
  or launch authorization; cohort schema v2 remains separate. Bridge
  reservation then atomically consumes one exact packet arm without
  fabricating `SubagentStart`; dispatch generation v2, complete ownership
  binding, a per-launch OS lock, consume/pending-time expiry checks, and
  issue-to-Popen Git/claim recapture close duplicate-launch and stale-source
  races. If a crash lands the exact marker-bound reservation binding before its
  semantic event, that authenticated pending binding is the sole witness that
  allows the same still-terminal command to recover after permit expiry;
  absent, different, or head-drifted witnesses fail closed. The process-start
  boundary now also rereads the immutable issuance marker and the
  canonical Chief record under the state lock. Popen requires that record to be
  inactive at the marker's exact issuing epoch with its latest non-forced
  release event naming the exact issuing session and epoch. A still-active
  issuer, a different active or released Chief (including another credential
  root), a wrong release audit identity, or a missing/malformed record fails
  before `process_start_pending`; credential-home emptiness remains only
  defense in depth. Once that pending milestone is durable, later Chief changes
  do not retroactively revoke it and crash ambiguity still forbids automatic
  restart. The pinned 0.145.0
  wire dialect is now enforced directly: requests and
  notifications omit `jsonrpc`, `initialized` is method-only, tagged or
  malformed error envelopes fail closed, and lifecycle digests bind exact raw
  wire bytes. Response-derived milestones retain the actual request method from
  the contract's single event-method table and cannot masquerade as lifecycle
  notifications. Successful initialize/thread/
  turn results are checked against the pinned 0.145.0 required shape before
  the journal callback; thread context is rebound to the sealed cwd/model/
  approval/sandbox, and the supported lifecycle subset checks pinned required
  Thread/Turn/item fields. Journal evidence now distinguishes request
  responses, process/notification observations, exact rejected-response fault
  evidence, and synthetic faults with finite redacted reason codes; a fault can
  never claim `response_sha256` or `wire_event_sha256`. Correlated responses
  rejected by schema or sealed policy are synchronously retained and verified
  in task-local non-Git CAS before their digest/size fault evidence is
  journaled. Schema-valid App Server error envelopes use that same fault path
  and cannot publish a success milestone. A first real read-only canary
  exposed the former framing defect and failed explicitly at initialize; it was
  not retried and is not a live PASS. Local fake-runtime tests and that failed
  diagnostic canary are not release, package-install, or downstream ARISE
  evidence. The selected release target is exact final-SHA GitHub CI, immutable
  tag/Release readback, and exact wheel/sdist PyPI Trusted Publishing with
  remote hash/install readback. The same sealed task owns those gates and the
  released ARISE install; no confidentiality-profile migration is required.
- **Selective local-files confidentiality (implementation candidate; promotion
  pending).** `mode = "local_files"` means model context allowed and
  user-designated file/tree publication constrained by destination. An omitted
  or empty `protected` list classifies nothing, so AOI itself can update, push,
  run remote CI, and publish GitHub/PyPI releases normally.
  `home_remote_only` binds protected bytes to one exact named home remote and
  credential-free destination; `local_only` denies every external destination
  absent an exact Chief one-shot destination/content/purpose/expiry export
  permit. The Git preflight binds config, exact ref updates, read-only observed
  remote pre-state OIDs, outgoing commits, protected history/blob/content
  identities, and rejects other destinations,
  rewrite/LFS ambiguity, delete/copy bypasses, missing protected origins, or
  rule drift. Delivery persists the exact policy binding with the receipt, so
  later config evolution cannot reinterpret historical evidence; a later
  unreceipted remote tip also cannot borrow an older receipt. Other publication
  gates inventory exact regular files plus bounded wheel/ZIP/gzip-tar members.
  Local snapshot generation binds ignored `aoi.toml`, normalized rules, and
  exact protected content into tracked `release/publication-policy.json`; clean
  runners consume that snapshot with an independent expected-digest pin and
  without requiring or uploading local-only origins. The release workflow
  invokes that gate before every Actions artifact upload, transports
  non-recursive receipt sidecars, and revalidates the exact package-container
  pair before PyPI. It also seals a separate GitHub Release envelope, gives one
  no-checkout job only `contents: write`, stages or resumes the exact
  annotated-tag Release as a non-public draft, verifies all three assets before
  publishing the complete prerelease, and rejects an incomplete already-public
  Release. Authenticated paginated discovery, a deterministic
  source/content/policy contract marker, exact Release-ID mutations, bounded zero-byte starter
  recovery, and per-mutation tag rechecks keep draft crash recovery fail closed.
  An independent read-only API/download/hash readback must then pass before the
  no-checkout OIDC PyPI job can start.
  Protected current-byte lookup, Git history/index/tree correlation, tracked
  publication snapshots, artifact gates, and doctor now use one
  ASCII-case-folded, non-ASCII-exact path identity on Windows and POSIX, while
  rejecting multiple case-distinct spellings as ambiguous instead of selecting
  one. Exact non-ASCII paths remain supported without relying on Python-only
  multi-codepoint folds that Git history cannot prove.
  Ambient Git pathspec modes are scrubbed, and cached unfiltered history trees
  share one aggregate bound so hostile environment or repository shape cannot
  silently weaken lineage inspection.
  Doctor reports rules,
  remotes, rewrites, LFS, workflows, sync/network storage, credential
  names/helpers, and receipts without exposing credential values; external
  capability alone is warning/inventory, not a profile-wide error. The Bridge
  enforces local storage/cwd preflight at issue, pre-reserve, and process pending
  and requests `networkAccess=false`. App Server launch requires a non-linked
  exact three-file `CODEX_HOME`, rechecks its closed policy binding immediately
  before Popen, uses strict process overrides, and repeats publication-surface
  denials in `thread/start.config`. Windows mapped drives are rejected through
  volume/DOS-device inspection; missing roots, aliases, and reparse uncertainty
  also fail confirmed-local gates when protected rules exist, while an empty
  rule set leaves the launch-storage gate inactive. Terminal transport receipts cannot close
  while an item remains started, except that `runtime_unknown` preserves it as
  incomplete evidence. This is not DLP, an air gap, or a claim that model
  providers cannot see prompt/context. With the AOI repo's empty protected-rule
  set, the active promotion route includes exact final-SHA GitHub and PyPI gates
  after local Windows/WSL, review, seal, package/install, and canary evidence.
- **Deterministic cross-process timestamp fixtures.** Synthetic verification
  supersession now makes each replacement timestamp strictly later than its
  source before hashing; the manual-dispatch expiry test uses a fixed valid
  far-past window; and permit fixtures derive arm time from the persisted
  subprocess registration plus one microsecond rather than a parent-process
  clock. Successful permit issue/consume integration now runs the full CLI in a
  `tests/`-only subprocess driver at an exact post-plan time, while a direct
  runtime regression proves that pre-plan issuance publishes nothing. These
  fixtures strip all reusable Chief credential locators, reject them again in
  the consumer child, and prove a fresh child cannot resolve the live Chief
  credential. The Bridge reachability fixture now anchors arm time strictly
  after both the migrated semantic head and resource registration, applies the
  same persisted-time discipline to permit issue/consume, then invokes Codex transport
  `issue` through a separate tests-only driver that patches only its existing
  `_now` seam. The driver accepts one canonical UTC instant and only the
  `issue` command; invalid clock input fails before CLI work. These test-only
  repairs remove host/WSL wall-clock-step flakes without weakening production
  relationship, live-arm, permit, or expiry validation.
  The prior exact WSL failures remain recorded; a fresh clean-successor full
  run is required.

### Added
- **Codex startup byte-state registration and strict resource timeline.**
  Startup-only hook receipts now persist bounded managed project-file SHA-256
  observations, with CurrentUser DPAPI storage on Windows and private-mode
  validation on POSIX. A Chief-fenced registration binds that receipt to the
  current reviewed resource plan, immutable applied-event snapshot, task plan,
  worktree, and Chief epoch without claiming provider routing, config loading,
  runtime profile, or sandbox facts. The resource lifecycle now replays a
  strict timezone-aware LIFO apply/rollback timeline and serializes at most five
  seconds of cross-process clock jitter after every validated resource
  transition, registration, and already-persisted startup observation. This
  prevents a later apply from sorting before a startup that causally preceded
  it when Windows and WSL wall clocks step backwards. Registration explicitly
  proves only
  `registered_byte_state_equivalent_only`: byte-identical events cannot be
  ordered by filesystem evidence. Historical schema-v1 receipts remain
  hash-validated but are never silently upgraded and do not block unrelated v2
  startups.
- **Claude claim-write gate (opt-in).** With `AOI_CLAUDE_CLAIM_WRITE_GATE=warn`
  or `deny`, the Claude `PreToolUse` hook checks `Write`/`Edit`/`MultiEdit`/
  `NotebookEdit` targets against the bound session's live `repo:file:`/
  `repo:tree:` claims and warns or blocks a repo write outside them before it
  lands — upgrading the claim ledger from a record to a pre-write gate on the
  cooperative tool path. Default off is an exact pass-through. Writes under
  `.aoi/`, outside the repo, from unbound sessions, and every `Bash` command
  pass through; it gates only the cooperating tool path and is not an OS
  sandbox.
- **Claude model-tier dispatch gate.** The Claude `PreToolUse` pre-spawn gate
  now enforces the armed packet's `model_tier` against the dispatch request's
  `model`: a governed dispatch without an explicit model is denied (omission
  would inherit the Chief session's model), and a model outside the tier's
  allowed families is denied before the sub-agent exists. Depth-two helper
  spawns are capped at the parent packet's tier. The tier→family table is
  env-overridable (`AOI_CLAUDE_TIER_MODELS`, JSON); the shipped default maps
  frontier→opus, expert→opus/sonnet, advanced→sonnet, standard→sonnet/haiku,
  economical→haiku, and deliberately places the session's top-price model in
  no tier. This converts the previously declarative tier ledger into a
  dispatch-request gate on the Claude host; it does not observe actual model
  routing, and Workflow-orchestrated spawns still bypass `PreToolUse`.
- **Typed package and deterministic CI tooling.** The full `src/aoi_orgware`
  surface has a clean mypy gate, with `mypy==2.3.0` and its toolchain
  hash-locked. Test and documentation Actions use SHA-pinned inputs rather
  than floating action revisions. The package ships a PEP 561 `py.typed` marker
  with a `Typing :: Typed` classifier.
- **Python 3.14** added to the CI matrix and trove classifiers.
- **Coverage gate.** Subprocess-aware coverage job (the suite drives the
  CLI through real subprocesses; naive measurement understates by ~30
  points) with an enforced 80% floor — measured 83% at this baseline.
- **Documentation site.** mkdocs-material site built from `docs/` with a
  strict-mode local build and configured for GitHub Pages deployment; no remote
  deployment result is claimed here.
- **Community files.** CONTRIBUTING, bug-report and PR templates, and a
  Dependabot config watching the SHA-pinned GitHub Actions.


## [0.3.0a3] - 2026-07-17 (alpha)

Observability / last-mile line. Every change traces to the 2026-07-17
evidence audit of AOI 0.3.0a2 governing ARISE: `routing_verified` was
settable from CLI free text; the SubagentStart observation discarded the
transport model; profile resolution hard-coupled AOI role names to Codex
profile filenames (4 ARISE roles hard-failed on pure name drift);
`codex-config-apply` hid inapplicable targets behind `restart_required=true`;
helper budgets had never been exercised (81/81 packets budget 0) with the
direct-parent transport question unverified; and 22% of terminal packets
died of ceremony while `status` was the only outcome signal.

### Added
- **Hook-observed routing records (WS1).** SubagentStart observations,
  helper spawns, resumptions, and incidents now persist the
  transport-reported `model` (empty when not exposed). `routing_verified`
  is DERIVED — true only when a consumed hook observation carries a model
  that matches the packet-role binding of a current applied resource-config
  event; `--actual-role/--actual-model-tier/--routing-evidence` are stored
  as an explicit `routing_claim` (`provenance="cli_claimed"`) and can no
  longer flip the flag.
- **Role→profile mapping (WS2).** New optional `[codex.profiles]` aoi.toml
  table maps AOI roles to Codex agent profile names; absent table preserves
  the identity mapping byte-for-byte. Profile TOMLs declaring a `name` must
  match the profile they resolve as (fail closed); resolved agents,
  plans, and receipts now record the `profile` alongside role, tier, and
  model.
- **Config-ancestry applicability (WS3).** `codex-config-plan/apply`
  relate the target worktree to the invoking session's working directory:
  plans carry `config_applicability` (`applicable` / `not_applicable` /
  `unknown`) with an explicit basis; apply fails closed on
  `not_applicable` unless `--allow-inapplicable` records the
  acknowledgement in the event and receipt.
- **Helper transport canary (WS4).** Budget refusals now carry distinct
  incident reason codes (`no_helper_budget`, `helper_budget_exhausted`)
  instead of folding into `no_matching_arm`. New Chief-fenced
  `codex-helper-canary` command classifies a live canary window into a
  typed `transport_probes` verdict (`supported`,
  `supported_budget_enforced`, `unsupported_root_parent_only`, `unknown`);
  the live procedure is documented in `docs/helper-canary-runbook.md`.
  Helper capability may only be claimed from a recorded probe.
- **Typed technical outcomes (WS5).** Terminal `packet-update` accepts
  `--typed-outcome` (accepted, rejected, procedural_failure,
  transport_failure, cancelled, superseded, no_material_work) with
  per-status validity; absent means `unclassified`. Capacity records and
  the (now v2) capacity dataset export `typed_outcome` and
  `model_quality_eligible`; only explicit accepted/rejected outcomes enter
  a model-quality denominator — transport status never does.
- **Recommendation-only phase gate (WS6).** `capacity-recommend` requires
  `--min-eligible-records` and fails closed below it; recommendations
  record `phase="recommendation_only"` and a typed `sample_boundary`,
  enforced by portfolio-integrity invariants. New
  `[policy] capacity_recommendation_only` (default true) pins the phase:
  while true, a capacity decision may only be consumed when its
  recommendation records that phase. No code path applies a capacity
  recommendation to dispatch-time profile/model selection.

### Hardened after independent adversarial review (12 confirmed findings)
- Routing observations carry a tamper-evidence digest
  (`observation_sha256`); editing the observed model after consumption —
  or retrofitting a model onto a legacy observation — fails packet
  integrity.
- Capacity records re-derive routing verification at export time instead
  of trusting the stored boolean, and doctor flags any stored
  `routing_verified=true` that the hook+binding derivation cannot
  reproduce (this includes legacy operator-attested flags and packets
  whose binding was later rolled back: an unprovable claim is surfaced,
  not grandfathered).
- The resource plan digest excludes ambient invocation context
  (`invocation_cwd`, applicability verdict/basis), so the Chief-review
  anchor is a pure function of the reviewed content and a plan/apply pair
  from different directories no longer misreports "plan changed".
- Helper budget refusal incidents record `helper_parent_packet_id`; the
  canary only counts refusals scoped to its own parent packet.
- Typed outcomes are integrity-checked (value/status validity); the
  sample-boundary contract is anchored to the sha-pinned dataset file so
  deleting the fields is as detectable as falsifying them.

## [0.3.0a2] - 2026-07-17 (alpha)

Governance-honesty pre-release on the v0.3 line. Every change traces to a
defect found by the 2026-07 evidence audit of AOI 0.2.1 governing the ARISE
RTL project (12/12 subagent incidents were guard friendly fire; a task closed
`achieved` beside an unmet completion boundary; a lock-URI typo silently
disabled mutual exclusion for 31 hours; reviewer results cited themselves as
evidence).

### Added
- **Honest close outcomes.** `close-task --outcome
  {achieved,scope_changed,partial,superseded}` is required; `achieved`
  additionally requires a passing close-qualifying verification recorded with
  `--asserts-completion-boundary`, non-achieved outcomes require
  `--boundary-disposition`, and closing `achieved` over recorded blockers
  requires `--blockers-disposition`.
- **Scope retargeting.** `retarget-task` re-anchors title / objective /
  completion boundary on an open task, appends an immutable
  `scope_revisions[]` entry (old/new/reason), and invalidates plan approval
  until re-approval. `approve-plan` now accumulates `plan_approvals[]`
  history; replacing an approved plan after packets/jobs ran requires
  `--coverage-note`.
- **Typed, retirable risks.** `checkpoint --risk` records
  `{id,text,status}` entries; `retire-risk` retires or marks a risk
  materialized (legacy string risks retire via `--text-exact`); checkpoints
  render open risks only plus an accounted summary line.
- **Expressive dispatch match model.** `packet-arm --any-agent-type`
  wildcard arms own the whole parent slot (AOI role labels are never
  transport labels); a SubagentStart whose agent identity matches an
  already-dispatched packet from the same parent is a recorded resume, not a
  `duplicate_agent` incident; `create-packet --helper-spawn-budget N` grants
  bounded depth-two read-only helper spawns (recorded on the packet, contract-
  sealed); incidents carry a `live_arms` snapshot and
  `subagent-incident-account --disposition-kind` classifies guard outcomes,
  surfaced in `task_summary.subagent_guard`.
- **Lock-URI admission gates.** `:` in `repo:`/external path remainders is
  rejected (the ARISE typo class); new file claims check the filesystem —
  missing target with a missing parent is rejected, and planned files require
  `--allow-nonexistent`, recording a `planned` baseline.
- **Evidence self-reference gate.** A packet result cannot cite itself as
  its only evidence; gated packets are re-validated at close/cancel.
- **Job launch/registration split.** `job-start --observed-start-at` records
  the physical launch separately from `registered_at`, computes
  `registration_lag_seconds`, and demands `--retroactive-reason` past the
  tolerance; `task_summary` surfaces the worst lag.
- **Derived lane closure.** Closing a lane requires `--closure-kind
  {completed_work,no_work,aborted,superseded}` checked against the lane's own
  packet ledger with `packet_terminal_stats` stored on the terminal event.
- **Cancel/record cross-checks.** `cancel-task` with recorded changed files
  requires `--changed-files-disposition`; `checkpoint --changed-file` rejects
  absolute paths outside the bound worktree without
  `--allow-outside-worktree`.

### Changed
- The managed policy template documents the close-honesty contract, the
  wildcard/resume/helper dispatch semantics, lock admission gates, and
  derived lane closure.

## [0.3.0a1] - 2026-07-16 (alpha)

### Added

- **Constrained mini completion** (`aoi finish-mini`). After explicit passing,
  close-qualifying verification exists, it automates delivery disposition,
  claim release, checkpointing, and closure through the existing fail-closed
  gates. It accepts only the mini profile and exact `repo:file` claims. An
  argument-bound receipt supports fail-closed retries; tests cover interruption
  after claim release and after terminal state publication, not process-kill or
  power-loss durability. Its `pushed` mode requires the full 40–64-hex commit
  ID rather than an ambiguous short SHA.
- **Evidence-first v0.3 plan.** The `0.3.0a1` line prioritizes lower ceremony,
  command/domain boundaries, reproducible package artifacts, deterministic
  resilience testing, and a separate A/B/C evaluation protocol.
- **Reliability test infrastructure.** Parent-released subprocess harnesses and
  process-local atomic-I/O observation points cover the intended Chief, claim,
  packet-arm, publication, reader, checkpoint, index, and interrupted-cleanup
  boundaries. Chief, claim, and packet-arm race workers now pause at the actual
  state-lock acquisition boundary. Passing local runs are development receipts;
  Linux/Windows CI release receipts remain pending.
- **Fail-closed interrupted bootstrap.** `chief-acquire` now accepts only an
  existing private regular `nlink=1` canonical `.state.lock` containing exactly
  one NUL byte. It takes that lock, reloads the same config binding, and accepts
  only a complete layout or the exact existing-NUL interrupted-init prefix
  before publishing first-Chief authority. Missing or empty locks, every
  state-lock alias, every root `aoi.toml` alias, and other ambiguous bootstrap
  objects are rejected with zero automatic bootstrap mutation on POSIX and
  Windows. They require explicit offline/manual recovery; the former
  alias-repair receipt fields were removed.
- **Authenticated atomic-temporary recovery**
  (`aoi recover-temporaries`). AOI state writes use identifiable private
  same-directory temporaries. Recovery accepts no arbitrary path, refuses all
  ordinary cleanup when any entry is ambiguous or legacy, and is retryable.
  It requires the normal canonical NUL state lock; every state-tree residue
  deletion requires an under-lock config reload and the current Chief. Eligible
  pre-link state-lock temporaries remain inert until authenticated cleanup;
  pre-link root-config residue is outside the state scan and remains manual.

### Changed

- Package and runtime metadata now share one PEP 440 version source
  (`0.3.0a1`). The CI workflow targets Python 3.11–3.13 on Linux and Windows and
  includes separate jobs to build, strictly check, and isolated-install test
  both wheel and sdist.
- Status, resume, and index command bodies moved out of the CLI composition
  root. AST boundary tests reject reverse imports and ratchet the remaining
  local `cmd_*` body allowlist.
- `start-mini` now records its actual boundary: best-effort rollback on ordinary
  exceptions while holding the state lock, not a multi-file atomic transaction.
  Hard process termination may require explicit audit and recovery.

### Notes

- Process-termination tests may support only a process-crash claim on the
  operating systems and filesystems where they pass. Successful raw reads must
  be complete old or new bytes, but managed reads may transiently fail closed;
  this is atomic visibility, not seamless availability. The tests do not prove
  power-loss durability. POSIX fsyncs the parent directory; native Windows
  cannot provide equivalent directory-entry durability through the Python
  standard library.
- State-tree recovery does not scan repo-external Chief credential
  temporaries, published-but-orphaned credentials, obsolete takeover
  credentials, or custom credential roots. Stale tuples cannot authorize the
  current authority, but secret-at-rest cleanup remains an a2 follow-up.

## [0.2.3] - 2026-07-16 (alpha)

### Added

- **One-command Codex onboarding** (`aoi codex-init`). It initializes AOI when
  needed, enables the explicit Codex-hook policy, non-destructively merges the
  protocol-v6 lifecycle hooks and stable hook feature, and installs the
  cross-project AOI user skill under `$HOME/.agents/skills/aoi`. Project-specific
  instructions remain repository-owned. It preserves unrelated project
  hooks/settings and leaves exact-definition trust to Codex `/hooks`.
- **Claude Code lifecycle hook adapter** (`aoi-claude-hook`,
  `aoi_orgware.claude_hook`). It shares the runtime-neutral
  `SessionStart` / `UserPromptSubmit` / `Stop` handlers with the Codex adapter
  and adds a `PreToolUse` **pre-spawn gate** on the `Agent` tool: for governed
  agent types (default `general-purpose`, overridable via
  `AOI_CLAUDE_GOVERNED_AGENT_TYPES`) it denies a sub-agent spawn that has no
  exact live packet arm, before the sub-agent exists. `SubagentStart` consumes
  the arm and records `claude_subagent_start_observed` provenance.
- Dispatch protocol now carries a transport-specific `dispatch_provenance`
  label so Codex- and Claude-observed dispatches stay independently auditable.
- Packaging metadata for a public release: `[project.urls]`, richer trove
  classifiers, and this changelog.

### Changed

- Terminal-task doctor checks now preserve the complete packet graph while
  classifying each packet's integrity independently, so valid Steward synthesis
  bindings no longer become false stale-binding errors after task close while
  real binding tamper remains an error. Duplicate packet IDs are reported as
  global integrity errors instead of crossing legacy/v1 classifications.
- Claude's `PreToolUse` gate now validates the full live arm authority before
  allowing a governed spawn: Chief epoch, plan and packet digests, execution
  topology, lane snapshots, and resource authority must all still match.
- Claude and Codex onboarding now preflight existing destinations, preserve
  malformed/foreign settings by refusing unsafe rewrites, publish each changed
  file atomically, skip semantic no-op writes, and are idempotently resumable
  after a later destination fails.
- Hook command ownership is conservative. AOI upgrades only a direct AOI-owned
  entry point (plus the documented structured WSL launcher for Codex); embedded
  strings, mixed-platform handlers, shell chains, and malformed inner hook
  shapes are preserved or rejected without unsafe rewrites. A fresh partial
  install that already initialized AOI gives the exact Chief-acquire/rerun
  recovery sequence.

### Notes

- First public PyPI release. It rolls up the internal 0.2.1 and 0.2.2 alpha
  milestones in addition to the onboarding and integrity changes above.
- The hook adapter remains a cooperative procedural guardrail, not a security
  sandbox. Any internal `PreToolUse` failure is fail-closed deny; only
  non-`PreToolUse` lifecycle adapters are fail-open. Workflow-orchestrated
  spawns bypass this tool gate, and `SubagentStart` still accounts for them.
- Codex onboarding does not install Codex, edit global `CODEX_HOME` settings,
  or bypass hook trust. Existing AOI projects require the Chief credential and
  no active task before the configuration digest can change.

## [0.2.2] - internal alpha (not published)

- Single durable Chief lease per project with monotonic epochs, explicit
  takeover, and default fencing of lifecycle mutations.
- Continued extraction of command bodies out of the monolithic CLI into
  `aoi_orgware/commands/` and integrity modules.
- This internal milestone had no tag, GitHub Release, or PyPI distribution.

## [0.2.1] - internal alpha (not published)

- Task-global execution epochs, dispatch provenance, and resource-envelope
  hardening.
- This internal milestone had no tag, GitHub Release, or PyPI distribution.

## [0.1.2-alpha]

- First packaged alpha. Includes the Windows path-canonicalization fix for the
  symlink-traversal false positive. See the GitHub release for details.

[Unreleased]: https://github.com/Ryan529616/aoi-orgware/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/Ryan529616/aoi-orgware/compare/v0.1.2-alpha...v0.2.3
[0.2.2]: https://github.com/Ryan529616/aoi-orgware/commit/8ea308046f37e4cb73e7b0f0e56c1c80d71a8da4
[0.2.1]: https://github.com/Ryan529616/aoi-orgware/commit/a56a20e5bdb9cf1fb6cba0483e4c82678d10d5cf
[0.1.2-alpha]: https://github.com/Ryan529616/aoi-orgware/releases/tag/v0.1.2-alpha
