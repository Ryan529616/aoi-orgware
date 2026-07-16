# Changelog

All notable changes to AOI (`aoi-orgware`) are recorded here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project aims to follow [Semantic Versioning](https://semver.org/) once it
leaves the alpha line. Until then, minor versions may still change behavior.

## [Unreleased]

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
- The hook adapter remains a cooperative, fail-open procedural guardrail, not a
  security sandbox. Workflow-orchestrated spawns bypass `PreToolUse`; the
  `SubagentStart` observation still accounts for them.
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
