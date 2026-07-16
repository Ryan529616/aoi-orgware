# AOI

**Git-native governance for coding-agent teams.**

Run Codex or Claude Code normally. AOI keeps ownership, delegation, decisions,
checkpoints, and verification accountable when the work becomes parallel,
long-running, or evidence-sensitive.

[![CI](https://github.com/Ryan529616/aoi-orgware/actions/workflows/test.yml/badge.svg)](https://github.com/Ryan529616/aoi-orgware/actions/workflows/test.yml)
![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Status: alpha](https://img.shields.io/badge/status-alpha-orange)

AOI is not another agent runtime. It sits between a coding-agent client and the
repository:

```text
you set the goal
       |
Codex / Claude Code          reasoning, tools, implementation
       |
AOI skill + hooks            lifecycle context and runtime observations
       |
AOI core                     authority, ownership, evidence, recovery
       |
Git + tests + build / EDA    source of truth
```

It targets a recurring failure mode: delegation succeeds, several agents become
busy, and nobody can later prove who owned a file, which result used the current
baseline, or whether “tests passed” meant that a test actually ran.

> **Alpha status:** AOI's lifecycle and integrity rules are tested, but AOI has
> not established general superiority over a strong single agent or a simpler
> supervisor. It is a cooperative procedural guardrail, not a security sandbox.
> Test it on your own workload before making it the default.

## Install it with your coding agent

From the repository you want to govern, paste this into Codex or Claude Code:

> Inspect https://github.com/Ryan529616/aoi-orgware and my current repository
> without modifying my project. Resolve AOI `main` to an exact commit and show
> me the proposed AOI revision, project files, user-scope files, hooks, and trust
> boundary. Wait for my approval. Then install that exact commit in an isolated
> tool environment, use AOI's bootstrap flow when a project-specific profile is
> justified, bind this repository to the current coding-agent client, preserve
> unrelated settings, run AOI doctor and the integration smoke checks, and use
> AOI for future material work. Do not claim that hooks are trusted or that a
> model route was observed unless the runtime provides evidence for it.

That is the intended onboarding experience. The coding agent operates AOI's
deterministic CLI internally; the user should not have to memorize lifecycle
commands. The approval is deliberate because installing code from a URL and
adding persistent project hooks is a supply-chain and trust decision.

### Manual source install

AOI is not published to PyPI yet. Until the next tagged release includes the
current onboarding work, pin a reviewed commit instead of installing a moving
branch:

```bash
# With uv:
uv tool install "git+https://github.com/Ryan529616/aoi-orgware.git@<reviewed-commit-sha>"

# Or inside an activated virtual environment:
python -m pip install "git+https://github.com/Ryan529616/aoi-orgware.git@<reviewed-commit-sha>"

# Run one of these from the repository you want to govern.
aoi codex-init --project-name "My Project" --json
# or
aoi claude-init --project-name "My Project" --json
```

The onboarding commands initialize AOI when needed, preserve unrelated client
settings, install the generic AOI skill once at user scope, and wire the
repository-local lifecycle hooks. Re-running is idempotently resumable. Existing
AOI projects—and interrupted first runs that already published `aoi.toml`—
require the current Chief credential before the command is rerun.

| Client | Repository-local integration | User-scope skill |
|---|---|---|
| Codex | `.codex/config.toml` and `.codex/hooks.json` | `$HOME/.agents/skills/aoi/SKILL.md` |
| Claude Code | `.claude/settings.json` | `$HOME/.claude/skills/aoi/SKILL.md` |

Codex still requires the user to review and trust the exact hook definitions in
its own `/hooks` UI. AOI does not cross that boundary on the user's behalf.
For a Windows-hosted Codex client with AOI in WSL, `codex-init` may need both
an explicit Windows hook launcher and a Windows user-skill path. `claude-init`
exposes only the user-skill-root override for its supported cross-host setup.
See each command's `--help` output and the
[configuration guide](docs/configuration.md).

Requirements:

- Python 3.11+
- Git
- Linux/WSL with reliable POSIX metadata, or native Windows on an ordinary
  local filesystem

Do not alternate WSL and native-Windows writers against one AOI state tree; the
two lock domains do not interoperate.

## Daily use

After binding, ask for work normally:

```text
Fix the intermittent refresh-token race and add a regression test.
```

For material work, the coding agent should detect the AOI-bound repository and
perform the governed lifecycle itself: reconstruct or create the task, choose a
task-appropriate topology, claim the exact mutation scope, dispatch bounded
work, record real verification, checkpoint, and close only when every gate is
accounted for.

Read-only questions do not need lifecycle ceremony. Small edits stay single;
parallel lanes are used only when the work is genuinely independent.

| Work shape | AOI execution |
|---|---|
| Read-only explanation | No task required |
| Low-risk edit to 1–3 exact files | Mini / governed single |
| Coupled implementation | Single causal chain |
| Independent investigation or verification | Centralized parallel |
| Cross-lane contract work with bounded coordination | Hybrid |

The user keeps authority over goals, budgets, preferences, and irreversible
risk. AOI should add organizational complexity only when the task earns it.

## What AOI is for

### Prevent overlapping cooperative work

AOI claims exact files, trees, contracts, Git merge surfaces, or external output
roots before mutation. Overlapping ownership is rejected, and exact-file claims
retain a SHA-256 baseline.

### Make delegation inspectable

Delegated work receives a bounded packet: objective, scope, deliverable,
validation boundary, capability tier, and a short-lived dispatch permit. AOI
keeps requested routing separate from runtime-observed routing. A manual
fallback remains explicitly unverified.

### Refuse unsupported “done” claims

AOI distinguishes acknowledgement, engineering inference, compile acceptance,
runtime evidence, independent review, and other configured evidence classes.
Task closure requires current qualifying evidence plus complete accounting for
claims, packets, jobs, delivery, escalations, and checkpoints.

### Recover across sessions

Tasks bind the Git worktree, branch, configuration digest, plan, claims,
decisions, dissent, verification, and a bounded semantic checkpoint. A resumed
session reconstructs from the checkpoint and current repository state instead
of relying on conversational memory.

## Core capabilities

| Area | What AOI records or enforces |
|---|---|
| Authority | One durable Chief lease, monotonic epochs, explicit handoff/takeover, repo-external credentials |
| Ownership | Exact file/tree/contract/external locks, conflict detection, baseline hashes |
| Delegation | Bounded packets, one-time arms, dispatch provenance, unmanaged-start incidents |
| Organization | Lanes, dependencies, Steward synthesis, decisions, directives, dissent, user escalations |
| Evidence | Content-addressed artifacts, evidence-strength boundaries, independent verification, close gates |
| Recovery | Durable checkpoints, configuration binding, deterministic backup and integrity checks |
| Resource control | Task-global execution envelopes, bounded depth, requested role/model policy without invented telemetry |
| Improvement | Qualification, canary, rollback, adoption, and deprecation records for reusable skills |

The complete semantics live in the [operating policy](docs/POLICY.md) and
[architecture](docs/architecture.md), not in marketing copy.

## Runtime truth boundary

AOI is strict about distinguishing control from observation:

| Surface | Current boundary |
|---|---|
| Post-initialization lifecycle writes | Deterministic and Chief-fenced, except narrowly pre-authorized hook consumption and incident recording |
| Cooperative file ownership | Conflicts are rejected through AOI; AOI is not an OS sandbox |
| Codex sub-agent start | Observed after creation when the trusted hook runs; not a pre-spawn boundary |
| Claude governed `Agent` dispatch | `PreToolUse` can reject a missing or stale arm before that tool runs |
| Claude paths that bypass `PreToolUse` | Observed and accounted for at `SubagentStart` when that hook runs successfully; not hard-blocked |
| Model and capability tier | Requested policy unless the runtime exposes qualifying observation |

AOI does not launch a model, store provider API keys, or replace the client's
sandbox, permissions, worktrees, conversation UI, provider routing, or billing.
It also cannot stop a non-cooperating process under the same OS account from
editing source, Git, tools, or AOI state directly.

Read [SECURITY.md](SECURITY.md) before relying on AOI for sensitive workflows.

## When AOI should pay for itself

AOI is most likely to help when work is:

- parallel enough for ownership or baseline conflicts to matter;
- long-running enough to cross sessions or context compaction;
- risky enough to require independent verification or explicit user decisions;
- expensive enough that failed delegation, duplicate work, or false completion
  is worth measuring.

For a typo, a tightly coupled local edit, or a read-only question, a strong
single agent is often the better tool. “More agents” is not a success metric.

## Test whether it actually helps

AOI ships a closed-alpha A/C kit for comparing a strong single agent with the
AOI-governed path under matched tasks, tools, models, time limits, and external
oracles:

```bash
aoi pilot-init --output ./aoi-pilot-kit --json
```

On native Windows, the standard library cannot verify a POSIX-style private
permission boundary. Review the destination ACL, then acknowledge that boundary
explicitly:

```powershell
aoi pilot-init --output .\aoi-pilot-kit --allow-unverified-windows-acl --json
```

Measure avoided ownership/baseline incidents, independent-review findings,
regressions, rework, human intervention, tokens, cost, and wall time. Failed and
abandoned runs stay in the denominator. A useful result is a better
quality/cost frontier, not a larger state ledger.

See the [evaluation protocol](docs/evaluation.md) and
[closed-alpha guide](docs/PILOT.md).

## Documentation

- [Architecture](docs/architecture.md)
- [Operating policy](docs/POLICY.md)
- [Configuration](docs/configuration.md)
- [Resource control](docs/resource_control.md)
- [v0.2 migration](docs/v0.2-migration.md)
- [Release runbook](docs/RELEASE.md)
- [Security boundary](SECURITY.md)
- [Changelog](CHANGELOG.md)

The full CLI remains available as a deterministic action surface for agent
adapters, CI, recovery, audit, and power users:

```bash
aoi --help
aoi status --json
aoi doctor --json
```

## Development

```bash
git clone https://github.com/Ryan529616/aoi-orgware.git
cd aoi-orgware
python -m venv .venv

# PowerShell: .\.venv\Scripts\Activate.ps1
# POSIX:      . .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

AOI is pure Python with no runtime dependencies. CI covers Linux and Windows on
Python 3.11 and 3.12.

## License

MIT. See [LICENSE](LICENSE).
