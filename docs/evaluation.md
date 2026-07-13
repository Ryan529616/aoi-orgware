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

## Reporting

Publish raw per-task observations, the aggregate, failure cases, and confidence
limits. Keep configuration/model changes separate from harness changes. AOI is
supported only when variant C improves the chosen quality/cost frontier—not
merely when it generates more records.

The hardware project that motivated AOI can be one case study. It must not be
the only workload used to claim generality.
