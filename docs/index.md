# AOI — Agent Organization Infrastructure

**Git-native governance for coding-agent teams.**

Run Codex or Claude Code normally. AOI keeps ownership, delegation, decisions,
checkpoints, and verification accountable when the work becomes parallel,
long-running, or evidence-sensitive.

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

AOI targets a recurring failure mode: delegation succeeds, several agents
become busy, and nobody can later prove who owned a file, which result used
the current baseline, or whether "tests passed" meant that a test actually
ran.

!!! warning "Alpha status"
    AOI's lifecycle and integrity rules are tested, but AOI has not
    established general superiority over a strong single agent or a simpler
    supervisor. It is a cooperative procedural guardrail, not a security
    sandbox. Test it on your own workload before making it the default.

## Install

```bash
uv tool install aoi-orgware        # or: pipx install aoi-orgware

# from the repository you want to govern:
aoi codex-init  --project-name "My Project" --json   # Codex
aoi claude-init --project-name "My Project" --json   # Claude Code
```

Alpha releases ship on [PyPI](https://pypi.org/project/aoi-orgware/). For a
repeatable deployment, pin the reviewed release as
`aoi-orgware==<reviewed-version>`.

## What AOI records

- **Authority** — one Chief lease at a time, epoch-fenced, with repo-external
  credentials; sub-agents return bounded results and never write state.
- **Ownership** — explicit claims over exact file/tree locks before mutation.
- **Evidence** — verifications carry a category, an explicit boundary, and —
  for a task to close `achieved` — an assertion that the registered
  completion boundary was actually covered.
- **Routing honesty** — a model-routing claim is only `verified` when a hook
  observation matches an applied configuration binding; operator free text is
  recorded as a claim, never as verification.
- **Recovery** — crash-consistent state with fail-closed recovery paths and a
  doctor that treats unprovable claims as errors.

## Where to go next

- [Architecture](architecture.md) — planes, authority model, and how AOI sits
  beside a coding-agent client.
- [Configuration](configuration.md) — the strict `aoi.toml` schema.
- [Operating policy](POLICY.md) — the full governance contract.
- [Resource control](resource_control.md) — governed Codex model/concurrency
  configuration.
- [Release runbook](RELEASE.md) and the
  [helper-budget live canary](helper-canary-runbook.md).
