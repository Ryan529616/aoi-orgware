# Changelog

All notable changes to AOI (`aoi-orgware`) are recorded here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project aims to follow [Semantic Versioning](https://semver.org/) once it
leaves the alpha line. Until then, minor versions may still change behavior.

## [Unreleased]

## [0.2.4] - 2026-07-17 (alpha)

Governance-honesty release. Every change traces to a defect found by the
2026-07 evidence audit of AOI 0.2.1 governing the ARISE RTL project (12/12
subagent incidents were guard friendly fire; a task closed `achieved` beside
an unmet completion boundary; a lock-URI typo silently disabled mutual
exclusion for 31 hours; reviewer results cited themselves as evidence).

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
  install that already initialized AOI now gives the exact Chief-acquire/rerun
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

## [0.1.2] - alpha

- First packaged alpha. Includes the Windows path-canonicalization fix for the
  symlink-traversal false positive. See the GitHub release for details.

[Unreleased]: https://github.com/Ryan529616/aoi-orgware/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/Ryan529616/aoi-orgware/compare/v0.1.2-alpha...v0.2.3
[0.2.2]: https://github.com/Ryan529616/aoi-orgware/commit/8ea308046f37e4cb73e7b0f0e56c1c80d71a8da4
[0.2.1]: https://github.com/Ryan529616/aoi-orgware/commit/a56a20e5bdb9cf1fb6cba0483e4c82678d10d5cf
[0.1.2]: https://github.com/Ryan529616/aoi-orgware/releases/tag/v0.1.2-alpha
