# AOI

**Git-native governance for coding-agent teams.**

Run Codex or Claude Code normally. AOI keeps ownership, delegation, decisions,
checkpoints, and verification accountable when the work becomes parallel,
long-running, or evidence-sensitive. The core is generic; it is developed
against a digital-IC workload — an RTL project whose external tool jobs run for
hours on a remote host — because that is where an unproven "done" costs the
most. Whether governing that flow this way actually pays is undetermined; see
below.

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

## The failure mode

Delegation succeeds, several agents become busy, and nobody can later prove who
owned a file, which result used the current baseline, or whether "tests passed"
meant a test actually ran. Concretely:

- Agent B "fixes" a file against a baseline agent A already replaced. Both
  report success. The regression surfaces a day later.
- A simulation passed. Nobody kept the command, the tool version, or the source
  the binary was built from, so the result cannot be reproduced or trusted.
- A six-hour job on a remote host died at hour five. The next session cannot say
  what ran, where its work root was, or whether resuming is safe.
- The agent that wrote the change also reviewed it, and cited its own run as the
  independent evidence.
- A task closed `achieved` next to a completion boundary nobody met.

The last two are not hypotheticals: they are defects AOI's own audit found in
AOI.

> **Alpha status:** AOI's lifecycle and integrity rules are tested, but AOI has
> not established general superiority over a strong single agent or a simpler
> supervisor. It is a cooperative procedural guardrail, not a security sandbox.
> Test it on your own workload before making it the default.

## AOI's own audit convicted AOI

AOI 0.2.1 governed the maintainer's private RTL project. A 2026-07 evidence
audit of what that deployment recorded produced these four public findings — the
governance did not catch them at the time; the ledger was auditable enough that
an audit could. Every change in [0.3.0a2](CHANGELOG.md) traces to one of them:

| Audit finding | What it means | Shipped gate |
|---|---|---|
| Reviewer results cited themselves as evidence | The "independent review" was the agent reviewing its own work | Evidence self-reference gate; commit `6e55f5c` also collapsed NTFS 8.3 alias spellings so a rename could not defeat it |
| A task closed `achieved` beside an unmet completion boundary | Governance recorded success that never happened | `close-task --outcome {achieved,scope_changed,partial,superseded}`; `achieved` now requires a passing close-qualifying verification recorded with `--asserts-completion-boundary` |
| A lock-URI typo silently disabled mutual exclusion for 31 hours | Ownership was believed, not enforced | Lock-URI admission gates: `:` in `repo:`/external path remainders is rejected (the exact typo class); new file claims are checked against the filesystem |
| 12/12 subagent incidents were guard friendly fire | The guard cried wolf every time it fired | A SubagentStart matching an already-dispatched packet from the same parent is a recorded resume, not a `duplicate_agent` incident; `subagent-incident-account --disposition-kind` classifies guard outcomes into `task_summary.subagent_guard` |

Scope this honestly. It is evidence that AOI records enough to make its own
false claims findable in an audit, that the audit was run against the
maintainer's own tool, and that he publishes the defects rather than hiding
them. The gates above did not exist when the defects occurred — they are the
response. It is **not** evidence that AOI improves outcomes in general. That
question is unmeasured — see
[Test whether it actually helps](#test-whether-it-actually-helps).

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

That is the intended onboarding experience: the coding agent operates AOI's
deterministic CLI internally, so the user need not memorize lifecycle commands.
The approval is deliberate because installing a package and adding persistent
project hooks is a supply-chain and trust decision.

### Direct install

> **This README documents the v0.3 alpha line.** The default install resolves to
> the latest *stable* release (0.2.x), which does not have the governance-honesty
> gates described below — `close-task --outcome`, `retarget-task`, and the
> evidence self-reference gate are v0.3 only. Pass `--pre` to get the line this
> page describes, and expect alpha breakage.

```bash
uv tool install --prerelease=allow aoi-orgware   # or: pipx install --pip-args=--pre aoi-orgware
                                                 # or: python -m pip install --pre aoi-orgware

# Run one of these from the repository you want to govern.
aoi codex-init  --project-name "My Project" --json
aoi claude-init --project-name "My Project" --json
```

For a repeatable deployment, pin the reviewed release as
`aoi-orgware==<reviewed-version>` instead of accepting a future update.

| Client | Repository-local integration | User-scope skill |
|---|---|---|
| Codex | `.codex/config.toml` and `.codex/hooks.json` | `$HOME/.agents/skills/aoi/SKILL.md` |
| Claude Code | `.claude/settings.json` | `$HOME/.claude/skills/aoi/SKILL.md` |

Codex still requires the user to review and trust the exact hook definitions in
its own `/hooks` UI; AOI does not cross that boundary on the user's behalf. See
each command's `--help` and the [configuration guide](docs/configuration.md).

Requires Python 3.11+, Git, and Linux/WSL with reliable POSIX metadata or native
Windows on an ordinary local filesystem. Do not alternate WSL and native-Windows
writers against one AOI state tree; the two lock domains do not interoperate.

## Daily use

After binding, ask for work normally:

```text
Fix the intermittent refresh-token race and add a regression test.
```

For material work, the coding agent detects the AOI-bound repository and performs
the governed lifecycle itself: reconstruct or create the task, choose a topology,
claim the exact mutation scope, dispatch bounded work, record real verification,
checkpoint, and close only when every gate is accounted for. Read-only questions
need no lifecycle ceremony. Small edits stay single; parallel lanes are used only
when the work is genuinely independent.

| Work shape | AOI execution |
|---|---|
| Read-only explanation | No task required |
| Low-risk edit to 1–3 exact files | Mini / governed single |
| Coupled implementation | Single causal chain |
| Independent investigation or verification | Centralized parallel |
| Cross-lane contract work with bounded coordination | Hybrid |

The user keeps authority over goals, budgets, preferences, and irreversible
risk. AOI should add organizational complexity only when the task earns it.

## Recovery and interrupted bootstrap

AOI deliberately does not auto-repair an interrupted bootstrap publication:
`chief-acquire` accepts only an intact canonical state lock plus a recognized
layout, and every other state requires explicit offline audit rather than a guess
about who owns which inode. After a writer crashes, the current Chief can run
`aoi recover-temporaries --json` then `aoi doctor --json` to clear eligible
residue. See the [recovery runbook](docs/recovery.md) for the exact accepted
states, rejected aliases, and what stays manual, and the
[operating policy](docs/POLICY.md) for the authoritative semantics.

## What AOI knows about IC/EDA work

Stated at exactly its true strength — this is a generic core that happens to
model long-running external tool jobs well, not a vendor integration.

**Project recognition.** The bootstrap inspector
([`skills/aoi-bootstrap/scripts/inspect_project.py`](skills/aoi-bootstrap/scripts/inspect_project.py))
maps `.sv`/`.svh`/`.v`/`.vhd` to their languages, treats `rtl/`, `tb/`, `verif/`
as hardware context, and recognizes flow directories (`apr`, `sta`, `synthesis`,
`pnr`, `dc-rm*`, `fc-rm*`, `rtl2gds`), tool tokens (`vcs`, `verdi`, `primetime`,
`icc2`, `formality`, `tmax`, `spyglass`), and artifacts (`.gds`, `.lef`, `.def`,
`.saif`). Fixtures in
[`tests/test_bootstrap_inspector.py`](tests/test_bootstrap_inspector.py) cover
`rtl/standalone_tb.sv`, `rtl/compile.f`, and `scripts/run/vcs.sh`. This is what
the inspector proposes as a starting profile before you review it. Nothing more.

**External job provenance.** This is the part designed for long external tool
jobs. `job-start`
([`src/aoi_orgware/commands/jobs.py`](src/aoi_orgware/commands/jobs.py))
requires `--host`, `--tool`, `--tool-path`, `--tool-version`, `--command`,
`--work-root`, `--log`, `--stop-condition`, and a `--source-manifest` pinned by
its 64-hex `--source-sha`. `validate_source_receipt`
([`src/aoi_orgware/job_integrity.py`](src/aoi_orgware/job_integrity.py))
rejects the job if the receipt's recorded tool path, version, and command differ
from the job arguments. `job-start` admits only `--status queued`. Registering
after the physical launch is allowed but not free: pass `--observed-start-at`
and AOI records the lag; beyond 120s (`JOB_REGISTRATION_LAG_LIMIT_SECONDS`) the job is
rejected unless `--retroactive-reason` accounts for the gap, and an observed
start dated later than its own registration is refused outright.

In IC terms: a run cannot record a tool version or source set that disagrees
with its own receipt, and "the sim passed" stays attached to the command string
and source SHA recorded for it. AOI cross-checks what the caller records; it
does not observe the remote process, so this catches drift and omission, not a
caller determined to record a falsehood consistently. Remote work roots are
held with external tree locks (`external_lock_namespace`,
[`aoi.toml`](aoi.toml)); a mini task may not launch external jobs at all.

**The boundary, in the same breath.** AOI ships no Synopsys, Cadence, or Siemens
adapter. It holds no licenses, launches no tools, parses no vendor log format,
and encodes no process knowledge. It does not touch signoff authority and has no
opinion about whether your design is correct. The real-world efficacy of
governing an EDA flow this way is **undetermined** — the maintainer's own
2026-07-17 audit says so. What exists is the list above. Read the cited files
before believing any of it.

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
| Post-initialization lifecycle writes | Chief-fenced, except narrowly pre-authorized hook consumption and incident recording |
| Interrupted project bootstrap | Only an intact canonical lock plus a recognized layout is accepted; everything else requires offline recovery with zero automatic mutation |
| Cooperative file ownership | Conflicts are rejected through AOI; AOI is not an OS sandbox |
| State-file publication | Successful raw reads see complete old or new bytes; managed reads may transiently fail closed. Not seamless availability, not a multi-file transaction, not power-loss proof |
| External tool jobs | Provenance is what the caller records and AOI cross-checks; AOI does not observe the remote process itself |
| Codex sub-agent start | Observed after creation when the trusted hook runs; not a pre-spawn boundary |
| Claude governed `Agent` dispatch | `PreToolUse` can reject a missing or stale arm before that tool runs |
| Claude paths that bypass `PreToolUse` | Observed and accounted for at `SubagentStart`; not hard-blocked |
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
single agent is often the better tool. "More agents" is not a success metric.

## Test whether it actually helps

No comparative results have been published. AOI ships the kit so you can produce
your own, comparing a strong single agent with the AOI-governed path under
matched tasks, tools, models, time limits, and external oracles:

```bash
aoi pilot-init --output ./aoi-pilot-kit --json
```

On native Windows the standard library cannot verify a POSIX-style private
permission boundary; review the destination ACL and pass
`--allow-unverified-windows-acl` to acknowledge that explicitly.

Measure avoided ownership/baseline incidents, independent-review findings,
regressions, rework, human intervention, tokens, cost, and wall time. Failed and
abandoned runs stay in the denominator. A useful result is a better quality/cost
frontier, not a larger state ledger.

See the [evaluation protocol](docs/evaluation.md) and
[closed-alpha guide](docs/PILOT.md).

## Documentation

- [Architecture](docs/architecture.md)
- [Operating policy](docs/POLICY.md)
- [Configuration](docs/configuration.md)
- [Recovery and interrupted bootstrap](docs/recovery.md)
- [Resource control](docs/resource_control.md)
- [v0.3 development plan](docs/v0.3-plan.md)
- [v0.2 migration](docs/v0.2-migration.md)
- [Release runbook](docs/RELEASE.md)
- [Security boundary](SECURITY.md)
- [Changelog](CHANGELOG.md)

The full CLI remains a deterministic action surface for agent adapters, CI,
recovery, audit, and power users: `aoi --help`, `aoi status --json`,
`aoi doctor --json`.

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

AOI is pure Python with no runtime dependencies. CI targets Linux and Windows on
Python 3.11, 3.12, 3.13, and 3.14; a separate packaging job builds the wheel and sdist,
checks their metadata, and smoke-tests both in isolated Linux and Windows
environments. The publication workflow repeats those checks on its same-run
artifacts and publishes exactly that verified pair.

## License

MIT. See [LICENSE](LICENSE).
