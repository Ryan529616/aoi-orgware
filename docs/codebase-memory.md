# Optional codebase-memory context provider

AOI Phase 1 treats codebase-memory as an optional, read-only navigation aid. It
is not AOI's system of record, a correctness gate, or a required runtime
dependency. AOI does not start the provider, refresh an index, watch a
repository, or expose a mutating graph command in this phase.

## Authority and evidence

| Role | Allowed | Forbidden |
|---|---|---|
| Chief | Review and import an exact receipt; decide whether graph context is useful | Promote graph output to technical proof; imply import proves the original refresh was Chief-run |
| Specialist | Read-only search, query, trace, schema, architecture, and snippet access | `index_repository`, watcher setup, or provider mutation |
| Steward | Validate receipt integrity, supported tool version, provider health, freshness, missingness, and dissent; bind those facts into a brief | Technical verdict, graph PASS, index mutation, or evidence promotion |

Provider binary/index/artifact checks describe provider health. Graph search,
trace, architecture, and benchmark results are always
`engineering_inference`. They cannot replace compile, simulation, runtime,
numeric, synthesis, physical, or signoff evidence.

AOI intentionally stores provider health in `context_provider_receipts`, not in
the normal `verification` ledger. A project's configured `system_evidence` may
be close-qualifying, so automatically writing provider health there would be an
unsafe evidence upgrade.

## Receipt import

The supported Phase 1 adapter accepts
`codebase-memory-arise-receipt/v1` produced for codebase-memory-mcp v0.9.0. The
receipt is size-bounded, parsed strictly for required identity and boundary
fields, and copied byte-for-byte into the task's private `results/` directory.
The caller must bind review to its full SHA-256.

```bash
aoi context-receipt-record \
  --task TASK --provider codebase-memory \
  --receipt-id RECEIPT_ID \
  --receipt /absolute/path/receipt.json \
  --receipt-sha256 SHA256 \
  --requirement optional \
  --freshness-profile codebase-memory-git-v1 \
  --session-id ROOT_SESSION --json
```

The command is protected by the project Chief lease, an approved task plan, and
the bound root session. Import records `refresh_authority=external_unverified`:
the receipt may describe a valid prior refresh, but importing it does not prove
AOI or the current Chief launched that refresh. Refresh/index authority remains
a later, separately versioned external-job integration.

One receipt is active at a time. A replacement must explicitly name the exact
active receipt with `--supersedes-receipt-id`; historical snapshots remain
immutable and integrity-checked.

## Freshness profiles

The receipt supplied to Phase 1 contains hashes but does not itself name the
canonical algorithms for every hash. AOI therefore never guesses:

- `receipt-only` validates structure and immutable identity but reports
  `freshness=unverifiable`;
- `codebase-memory-git-v1` is an explicit AOI adapter profile. It checks branch,
  HEAD, the raw bytes from
  `git status --porcelain=v1 -z --untracked-files=all -- <indexed-scope>`, every
  indexed file path/size/SHA, discovery-input hashes, global-exclude presence,
  provider binary, store/config databases, graph artifact, and both recorded
  client configurations.

The adapter accepts one literal top-level indexed scope and requires every
manifest path to remain below it. Client-config drift, including a change that
removes `index_repository` from the disabled-tool set, degrades provider health
even when source freshness remains valid.

The whole-worktree status hash is diagnostic. A change outside the indexed
scope does not by itself make the graph stale. `detect_changes` is not accepted
as an authoritative graph-snapshot comparison on a dirty worktree.

For active tasks, `doctor --json` reports separate `provider_health` and
`freshness` fields. Optional degraded, stale, unavailable, or unverifiable
providers produce warnings and fail open to normal repository inspection.
Explicitly required providers produce doctor, Steward-brief, and close-gate
errors until healthy and fresh. Terminal tasks retain immutable receipt
integrity checks but do not become historical failures merely because the
external repository later evolves.

## Steward brief binding

When a parallel/hybrid execution brief is recorded, AOI evaluates every active
context receipt and binds its receipt SHA, source-set ID, requirement, health,
freshness, and findings. The binding states
`technical_verdict_authority=none`, uses
`query_evidence_category=engineering_inference`, and is not close-qualifying.
The Chief remains the technical arbitrator.

## Navigation A/B benchmark

The benchmark is deliberately separate from the closed-alpha AOI topology
pilot. It consumes externally recorded, mutation-free observations for paired
variants:

- `rg_open` baseline;
- `codebase_memory_assisted` graph-assisted navigation.

Both arms bind the same corpus, oracle, assignment, source-set, receipt, model,
runtime, time limit, and shared control profile. The baseline may not call the
graph. Neither arm may call a mutating provider operation. A non-fresh graph arm
must fail open without querying the graph.

Cross-field checks require trace events to cover every recorded tool call,
matched navigation to include first-relevant metrics and an open call, final
latency not to precede first-relevant latency, and a completed graph arm that
did not query the graph to record an actual fallback episode.

Records distinguish measured values from missing values. Unavailable latency,
tokens, or cost use `value=null`, `source=unavailable`, and a non-empty
`missing_reason`; zero is never used as a substitute. The deterministic summary
reports denominators and descriptive paired differences for latency, wrong
paths, fallback, checked/stale/uncheckable graph results, tokens, and cost. It
does not calculate a composite technical score.

```bash
aoi codebase-memory-benchmark-validate --record RUN.json --json

aoi codebase-memory-benchmark-record \
  --task TASK --benchmark-id BENCHMARK_ID --receipt-id RECEIPT_ID \
  --record RG.json --record GRAPH.json \
  --record-sha256 RG_SHA256 --record-sha256 GRAPH_SHA256 \
  --session-id ROOT_SESSION --json
```

The summary remains descriptive `engineering_inference`. One project or one RTL
corpus cannot establish general AOI superiority.

## Deferred work

Phase 1 intentionally excludes:

- automatic or watcher-driven refresh;
- an AOI config table that makes the provider mandatory;
- a Specialist-facing AOI query facade;
- a Chief-fenced external refresh job and exclusive store writer lock;
- incremental indexing.

Those changes require a versioned receipt schema with self-described hashing
algorithms, refresh authority receipts, and benchmark evidence that the added
complexity improves the real workload.
