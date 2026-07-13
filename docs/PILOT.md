# Closed-alpha pilot guide

AOI v0.1.1 includes an executable pilot kit for letting 3–5 classmates try the
workflow without turning their private Codex traces into public data. This is a
feasibility and onboarding study, not a benchmark result.

## Generate the kit

Install the exact wheel under test, save its SHA-256, then run:

```bash
aoi --version
aoi pilot-init --output ./aoi-pilot-kit --json
```

`pilot-init` performs a complete collision preflight and refuses to overwrite
its files unless `--force` is explicit. `MANIFEST.json` binds the generated
files and AOI version.

The kit is portable and contains:

- the exact A/C protocol and privacy boundary;
- an `AGENTS.md` that Codex reads inside a run worktree;
- assignment, run-brief, structured record, and private-feedback templates;
- an intentionally broken onboarding sample that must not enter the results.

## Prepare the study

Use two different but difficulty-matched tasks for each tester. Randomly map one
to `single` and the other to `aoi`, and counterbalance whether the participant
runs single→AOI or AOI→single. Do not have the same person solve the same task
twice: learned solutions would dominate the harness effect.

For every run freeze the model, tools, context availability, time limit,
stopping rule, human intervention policy, dependencies, and oracle quality.
Use a fresh baseline for each task. Store only an opaque baseline ID in the
shareable record.

Serialize the fixed context, dependency, stop-rule, and intervention policy in
a private control-profile file and record its SHA-256. The summary rejects a
complete pair if that hash or its visible model/runtime/tool/time/package
controls differ.

Pre-register an external oracle before opening Codex. It may be a test suite,
lint/compile plus runtime test, reference output comparison, or a bounded human
rubric scored independently of the agent. “Codex says complete” is not an
oracle.

Copy the kit's `AGENTS.md` and a completed `RUN_BRIEF.md` into each fresh
worktree. The brief selects the variant:

- `single`: one agent, no sub-agents and no AOI commands;
- `aoi`: use AOI's governance lifecycle, but choose execution topology based on
  the task instead of forcing unnecessary parallelism.

## Record and validate

After each run, copy `run-record.template.json` to a unique filename and enter
measured values. Failed, timed-out, and abandoned runs remain records. Missing
telemetry uses `null`, a source of `unavailable`, and a missing reason—not zero
or a guess.

The shipped record template is intentionally invalid until its SHA placeholders
are replaced. This prevents an untouched placeholder from entering a summary.

```bash
aoi pilot-validate --record records/run-001.json --json
```

Validation is strict: unknown fields, missing measurement provenance, absent
pre-registration, invalid timestamps, and common privacy leaks fail closed.
Free-text feedback stays in the separate private form.

## Summarize

Only records with both `consent.share_with_coordinator: true` and
`consent.aggregate: true` can enter a summary:

```bash
aoi pilot-summary \
  --record records/run-001.json \
  --record records/run-002.json \
  --output summary.json \
  --format json \
  --json
```

Use `--format csv` for a tabular export. Output is deterministic, reports
missingness and denominators, and omits participant IDs. Paired figures are
defined as `AOI - single`, so lower-is-better metrics favor AOI when negative.

At 3–5 participants, report setup failures, descriptive oracle counts,
means/medians, complete-pair deltas, and qualitative workflow problems. Do not
claim significance, causal superiority, or generality. The decision after this
pilot is whether the protocol and product are usable enough for a larger study.

## What classmates should send back

Ask each tester for:

1. validated JSON records through a private channel only when they consented to
   coordinator sharing and aggregate use;
2. the `pilot-validate` success output;
3. private free-text feedback through an agreed private channel;
4. no repo, `.aoi/`, prompt, diff, path, command, log, or commit history.

Never publish individual run records. Public reporting is aggregate-only. Copy
the kit's `withdrawal-private.template.csv` to the unmanaged
`withdrawal-private.csv`, fill it with high-entropy random codes, and keep that
private mapping separate from records and analysis output. If a participant
withdraws before the analysis freeze, resolve their opaque participant ID from
that mapping, delete every matching record, and regenerate every aggregate.
