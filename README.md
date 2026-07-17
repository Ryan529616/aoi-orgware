# AOI

**Git-native governance for coding-agent teams.**

Run Codex or Claude Code normally. AOI keeps ownership, delegation, decisions,
checkpoints, and verification accountable when the work becomes parallel,
long-running, or evidence-sensitive.

[![CI](https://github.com/Ryan529616/aoi-orgware/actions/workflows/test.yml/badge.svg)](https://github.com/Ryan529616/aoi-orgware/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/aoi-orgware)](https://pypi.org/project/aoi-orgware/)
[![Docs](https://img.shields.io/badge/docs-github.io-blue)](https://ryan529616.github.io/aoi-orgware/)
![Coverage floor](https://img.shields.io/badge/coverage-%E2%89%A580%25_enforced-brightgreen)
![Typed](https://img.shields.io/badge/typing-py.typed-informational)
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

> Inspect https://github.com/Ryan529616/aoi-orgware, the latest published release
> at https://pypi.org/project/aoi-orgware/, and my current repository without
> modifying my project. Resolve that AOI release to an exact version, tag, and
> commit, then show me the proposed AOI revision, project files, user-scope files,
> hooks, and trust boundary. Wait for my approval. Install that exact published
> version in an isolated tool environment, use AOI's bootstrap flow when a
> project-specific profile is justified, bind this repository to the current
> coding-agent client, preserve unrelated settings, run AOI doctor and the
> integration smoke checks, and use AOI for future material work. Do not claim
> that hooks are trusted or that a model route was observed unless the runtime
> provides evidence for it.

That is the intended onboarding experience. The coding agent operates AOI's
deterministic CLI internally; the user should not have to memorize lifecycle
commands. The approval is deliberate because installing a package and adding
persistent project hooks is a supply-chain and trust decision.

### Direct install

AOI publishes alpha releases on PyPI. Install the current release as an isolated
tool, or install it in an activated virtual environment:

```bash
uv tool install aoi-orgware
# or
pipx install aoi-orgware

# Inside an activated virtual environment:
python -m pip install aoi-orgware

# Run one of these from the repository you want to govern.
aoi codex-init --project-name "My Project" --json
# or
aoi claude-init --project-name "My Project" --json
```

For a repeatable deployment, pin the reviewed release as
`aoi-orgware==<reviewed-version>` instead of accepting a future update.

The onboarding commands initialize AOI when needed, preserve unrelated client
settings, install the generic AOI skill once at user scope, and wire the
repository-local lifecycle hooks. Re-running is idempotently resumable. Existing
AOI projects require the current Chief credential before the command is rerun.
An interrupted first run can acquire that Chief automatically only when it
already has the exact private, non-linked, one-byte-NUL canonical state lock and
matches either a complete layout or the narrow interrupted-init prefix; every
other bootstrap state needs explicit offline/manual recovery first.

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

For a bounded mini task, the agent records verification explicitly and then
uses `finish-mini` to perform the mechanical delivery, claim-release,
checkpoint, and close transitions through the existing gates. The command does
not run a verifier or create evidence on the agent's behalf. Its `pushed` mode
requires the full 40–64-hex commit ID so an interrupted request can be retried
without an ambiguous SHA prefix.

`start-mini` is not a multi-file atomic transaction. While the project state
lock is held, an ordinary Python exception triggers best-effort removal of the
new task, claim, and session artifacts plus an index rebuild. Hard process
termination, `KeyboardInterrupt`, or cleanup failure may leave partial semantic
artifacts that require audit; `recover-temporaries` repairs only atomic-I/O
residues, not an inferred mini-task rollback.

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

### Recover interrupted atomic publication

AOI deliberately does not auto-repair bootstrap publication. `chief-acquire`
accepts only an existing canonical `.state.lock` that is one private regular
non-linked file containing exactly one NUL byte. After taking that platform
lock, it reloads the same configuration and accepts either a complete layout or
the exact existing-NUL interrupted-init prefix before publishing first-Chief
authority. The returned credential can then authorize the identical `init`
retry.

A missing or empty state lock, any state-lock alias, any root `aoi.toml` alias,
or any other linked/ambiguous bootstrap object is rejected without automatically
mutating those objects on either POSIX or Windows. These blocking states require
explicit offline/manual audit and recovery; AOI does not guess ownership or
rollback another writer's inode. A root config temporary left before link
publication is non-stranding—the identical `init` can still proceed—but it is
outside `.aoi/` scanning and remains manual root residue for audit and cleanup.

After a writer process terminates, the current Chief can explicitly remove
eligible state-tree temporaries and then re-audit the state tree:

```bash
aoi recover-temporaries --json
aoi doctor --json
```

The command accepts no target path and requires the normal canonical NUL state
lock. Every state-tree residue deletion occurs only after an under-lock
`aoi.toml` reload and current-Chief validation. Any malformed, ambiguous, or
legacy entry prevents all ordinary deletion. A create alias at
`chief-authority.json` is not a bootstrap exception and may require manual
repair because it blocks authority validation.

Repo-external Chief credential temporaries, published-but-orphaned credentials,
obsolete credential files, and custom credential roots are not scanned by
`recover-temporaries`. Stale credentials cannot authorize a current authority
tuple, but secret-at-rest cleanup remains a separate follow-up.

This bounded cleanup addresses process-crash residue; it is not evidence of
power-loss durability or automatic bootstrap repair.

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
| Post-initialization lifecycle writes | Chief-fenced, except narrowly pre-authorized hook consumption and incident recording; temporary recovery performs no pre-authentication state-tree deletion |
| Interrupted project bootstrap | `chief-acquire` accepts only an existing private `nlink=1` canonical NUL lock plus a complete layout or exact existing-NUL interrupted prefix. Missing/empty/aliased locks and root-config aliases require offline/manual recovery with zero automatic bootstrap mutation |
| Cooperative file ownership | Conflicts are rejected through AOI; AOI is not an OS sandbox |
| State-file publication | Successful raw reads see complete old or new bytes; managed reads may transiently fail closed on replacement identity drift or native-Windows sharing. This is not seamless availability, a multi-file transaction, or power-loss proof |
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

- [v0.3 development plan](docs/v0.3-plan.md)
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

AOI is pure Python with no runtime dependencies and requires Python 3.11 or
newer. The CI workflow targets Linux and Windows on Python 3.11, 3.12, and
3.13. A separate packaging job is configured to build the wheel and sdist,
check their metadata, and smoke-test both artifacts in isolated Linux and
Windows environments. The publication workflow repeats those checks on its
same-run release artifacts and publishes exactly that verified pair.

## License

MIT. See [LICENSE](LICENSE).
