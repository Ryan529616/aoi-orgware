# Evaluation protocol

AOI adds coordination cost. Evaluate whether that cost buys reliability on the
actual workload rather than assuming that a larger organization is better.

## Variants

- **A — Single:** one high-capability agent with the same tools and context.
- **B — Supervisor:** conventional supervisor with specialist delegation.
- **C — AOI:** Chief, Steward, governed specialist lanes, persistent decisions,
  task-aware routing, and verification gates.

Use the same task corpus, repository baseline, tool permissions, stopping
conditions, model catalog, and human availability. Randomize task order when
possible. Record failed and abandoned runs.

## Suggested task corpus

Include at least:

- a tightly coupled single-chain bug;
- two or more independently investigable problems;
- a cross-lane contract mismatch;
- a long-running external command with delayed evidence;
- a repeated pain point that may or may not justify a reusable skill.

## Metrics

Quality:

- task completion against an external oracle;
- regressions introduced or reintroduced;
- stale-baseline and contract-mismatch incidents;
- incorrect summary or lost-dissent incidents;
- independent-review findings after claimed completion.

Cost and flow:

- total input/output tokens and provider cost;
- high-capability model token share;
- wall-clock and active compute time;
- human intervention minutes;
- rework/retry count;
- decision and blocker latency;
- unacknowledged or unverified directives.

## Optional codebase-memory navigation A/B

Evaluate codebase-memory separately from the AOI topology variants. Pair an
`rg_open` baseline with a `codebase_memory_assisted` arm under the same corpus,
pre-registered navigation oracle, assignment, source-set, receipt, runtime,
model, and time limit. Neither arm may mutate the provider; the baseline may not
query the graph. A non-fresh graph arm must fail open without a graph query.

Report descriptive paired differences for time to first relevant source, time
to final answer, wrong paths before the first relevant source, fallback calls,
checked/stale/uncheckable graph results, and tokens/cost. Keep timeout and failed
runs in the operational denominator. Missing latency or token telemetry remains
`null` with provenance and a reason; never substitute zero. Do not collapse the
metrics into a technical score.

These records and summaries are `engineering_inference` about navigation
efficiency. They do not establish compile, simulation, numeric, synthesis,
physical, signoff, or general AOI superiority. See
[the codebase-memory integration contract](codebase-memory.md).

## Reporting

Publish consented, sanitized aggregates and bounded failure-case descriptions.
Do not publish `.aoi/`, raw prompts, diffs, paths, commands, logs, commit IDs,
private project material, or non-consenting per-participant records. Report
denominators and missingness; never encode unavailable telemetry as zero or an
estimate. Keep configuration/model changes separate from harness changes. AOI
is supported only when variant C improves the chosen quality/cost frontier—not
merely when it generates more records.

For an initial 3–5 person feasibility study, use the exact A/C protocol in
[PILOT.md](PILOT.md) and report descriptive paired differences only. A closed
alpha cannot establish statistical significance or general superiority.

The hardware project that motivated AOI can be one case study. It must not be
the only workload used to claim generality.
