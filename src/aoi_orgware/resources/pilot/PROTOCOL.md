# Closed-alpha protocol

## Purpose and boundary

This protocol checks onboarding, record integrity, and whether a larger
evaluation is worth running. With only 3–5 testers, report descriptive paired
differences and failure cases. Do not claim statistical significance,
generality, causality, or AOI superiority.

The closed alpha compares two variants:

- `single`: one agent, no delegation, no AOI workflow.
- `aoi`: AOI governance is used for the task. AOI does not imply that every
  task must use multiple agents; its topology selection may still be single.

## Assignment

Each participant receives two different, difficulty-matched tasks. Randomly
assign one task to `single` and the other to `aoi`; counterbalance run order
across participants (`single→aoi` and `aoi→single`). Never run the same task in
one variant and then repeat it in the other.

For both runs keep these controls fixed:

- runtime and model label;
- tool permissions and available context;
- time limit and stopping condition;
- human availability and intervention policy;
- dependency versions;
- external-oracle quality.

Before assignment, serialize the fixed context policy, dependency versions,
stopping rule, and human-intervention policy in a private control-profile file.
Record its SHA-256 in both runs. The summary rejects a pair when this hash or
any visible model/runtime/tool/time/package control differs.

Start each task from its own fresh, immutable baseline. Record an opaque
baseline ID in the run record; do not publish the repository path or commit ID.

## Before each run

1. Record the assignment in `assignment.csv`.
2. Pre-register one external oracle and its exact command or inspection method
   privately. The agent's own completion statement is not an oracle.
3. Create a fresh worktree/clone from the assigned baseline.
4. Create `RUN_BRIEF.md` from the template and set the assigned variant, task,
   time limit, stopping rule, and oracle ID.
5. Confirm the participant understands consent and withdrawal in `PRIVACY.md`.

## During and after each run

Do not alter the variant after starting. Record interventions only when the
human changes the agent's direction, supplies missing task information, grants
new authority, or repairs a blocked workflow. Do not count passive observation.

Preserve all terminal outcomes:

- `completed`: work stopped normally and the oracle was run;
- `failed`: work stopped with an oracle failure;
- `timeout`: the pre-registered time limit expired;
- `abandoned`: the run ended for another documented reason.

For `completed` and `failed`, the oracle must be `pass` or `fail`. Timeout and
abandoned records remain in the result set and may have `not_run` when the
oracle could not be executed.

Measured event taxonomy:

- intervention: human changes direction, information, or authority;
- retry: another attempt at the same immediate action after failure;
- rework: previously accepted work is changed because it was inadequate;
- regression: an external oracle detects broken previously working behavior;
- baseline mismatch: work or evidence used the wrong baseline;
- contract mismatch: components used incompatible interface/requirement terms;
- verification omission: claimed completion lacked the required oracle step;
- unresolved directive: an AOI directive remained unverified at stop time.

Enter telemetry only from provider export, runtime UI, or exact manual
transcription. When unavailable, use JSON `null`, `source: "unavailable"`, and
one allowed non-free-text `missing_reason` code from the record template. Never
enter zero, a guess, or a private detail for missing data.

## Analysis

The summary tool reports per-variant descriptive counts and means/medians plus
paired `aoi - single` differences for complete pairs. It reports denominators
and missingness, including questionnaire values. JSON and CSV both preserve
run-status and oracle counts. The tool does not calculate significance or hide
failed, timed-out, or abandoned runs.

The coordinator should inspect failure cases separately and keep any free-text
feedback private unless separately sanitized and consented.
