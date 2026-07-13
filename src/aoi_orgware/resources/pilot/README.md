# AOI Closed Alpha Kit

This kit supports a small, controlled feasibility study of AOI. It is not a
benchmark result and it is not evidence that AOI is generally better.

## Before a measured run

1. Read `PROTOCOL.md` and `PRIVACY.md`.
2. Use the sample project only to learn the procedure. Do not include it in the
   result set.
3. Have the coordinator assign two different but matched tasks. One runs as
   `single`; the other runs as `aoi`. Use fresh baselines and the assigned order.
4. Copy `RUN_BRIEF.template.md` to `RUN_BRIEF.md` in each fresh worktree and
   replace every placeholder before opening Codex.
5. Pre-register the external oracle and stopping rule before the run.
6. Copy `run-record.template.json` after the run and enter only measured data.

Validate one record:

```bash
aoi pilot-validate --record records/run-001.json --json
```

Create a de-identified descriptive summary from consented records:

```bash
aoi pilot-summary \
  --record records/run-001.json \
  --record records/run-002.json \
  --output summary.json \
  --format json \
  --json
```

Never share `.aoi/`, raw prompts, diffs, paths, commands, logs, commit IDs,
credentials, `feedback-private.md`, or `withdrawal-private.csv`. Create those
two unmanaged private files from their `.template` files before collection. A
validated structured record may go only to the coordinator and only with
explicit consent. Public reporting is aggregate-only.
