# Changelog

All notable changes to AOI (`aoi-orgware`) are recorded here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project aims to follow [Semantic Versioning](https://semver.org/) once it
leaves the alpha line. Until then, minor versions may still change behavior.

## [Unreleased]

### Added
- **One-command Codex onboarding** (`aoi codex-init`). It initializes AOI when
  needed, enables the explicit Codex-hook policy, non-destructively merges the
  protocol-v6 lifecycle hooks and stable hook feature, and installs the
  repo-local AOI skill under `.agents/skills/aoi`. It preserves unrelated
  project hooks/settings and leaves exact-definition trust to Codex `/hooks`.
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

### Notes
- The hook adapter remains a cooperative, fail-open procedural guardrail, not a
  security sandbox. Workflow-orchestrated spawns bypass `PreToolUse`; the
  `SubagentStart` observation still accounts for them.
- Codex onboarding does not install Codex, edit global `CODEX_HOME` settings,
  or bypass hook trust. Existing AOI projects require the Chief credential and
  no active task before the configuration digest can change.

## [0.2.2] - alpha

- Single durable Chief lease per project with monotonic epochs, explicit
  takeover, and default fencing of lifecycle mutations.
- Continued extraction of command bodies out of the monolithic CLI into
  `aoi_orgware/commands/` and integrity modules.

## [0.2.1] - alpha

- Task-global execution epochs, dispatch provenance, and resource-envelope
  hardening. See the GitHub release for details.

## [0.1.2] - alpha

- First packaged alpha. Includes the Windows path-canonicalization fix for the
  symlink-traversal false positive. See the GitHub release for details.

[Unreleased]: https://github.com/Ryan529616/aoi-orgware/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/Ryan529616/aoi-orgware/releases
[0.2.1]: https://github.com/Ryan529616/aoi-orgware/releases
[0.1.2]: https://github.com/Ryan529616/aoi-orgware/releases
