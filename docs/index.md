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

!!! warning "These docs describe the v0.4 alpha line"

    This checkpoint supports either a public release-promotion bundle or an
    independent reviewed local-install bundle. It does not claim a tag, GitHub
    Release, PyPI publication, or live Codex hook trust.

For a reviewed local install, create a repository-external venv, install the
exact bundle-bound wheel with `--no-index --no-deps`, then run the venv's exact
`aoi` console launcher. `codex-init` needs one complete proof pair:

```bash
<venv>/bin/aoi codex-init --project-name "My Project" \
  --local-artifact-bundle-file /absolute/reviewed-local-install-bundle.json \
  --expected-local-artifact-bundle-sha256 '<approved-local-install-bundle-sha256>' \
  --json
```

The local `reviewed_local_install_bundle` has
`proof_scope=exact_local_wheel_install_only`: it is neither a release nor a
promotion. Public releases instead use
`--promotion-bundle-file` with `--expected-promotion-bundle-sha256`. Half a
pair, both pairs, or no pair fails before mutation. See the full
[v0.4 quickstart](quickstart.md).

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
