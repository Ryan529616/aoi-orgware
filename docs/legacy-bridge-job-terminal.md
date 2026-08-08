# Legacy bridge job terminal truth

AOI keeps legacy v0.4 inventory and runtime truth separate. A
`LegacyBridgeObservationV1` remains an inventory observation: without an
additional receipt, a terminal-looking legacy job still projects runtime and
effect as `unknown` with `degraded` coverage.

## Exact-command ownership

`aoi job-start` requires one explicit owner packet in `exact_command` mode.
Packet creation and job registration use the same
`terminal-whitespace-lf-v1` normalizer:

- CRLF and CR become LF;
- terminal spaces, tabs, and blank lines collapse to one final LF;
- line-body bytes remain significant.

The job stores the canonical bytes, byte count, SHA-256, normalization ID,
owner packet ID, and owner packet contract SHA-256. A missing, ambiguous,
non-exact, tampered, or command-mismatched owner is rejected before the job is
registered. This does not introduce parent inference: historical jobs without
an explicit owner remain orphaned.

## Additive terminal contracts

The repair adds two append-only company contracts:

- `LegacyBridgeJobTerminalSourceV1` seals the exact reconciliation input.
- `LegacyBridgeJobTerminalReceiptV1` binds the company incarnation and
  generation, bridge scope and observation, task, packet, job/run, canonical
  command, the builder-recomputed canonical request-evidence digest, host and
  registered-process fingerprints, non-zero exit code, and exact artifact
  references.

V1 deliberately supports only an evidence-complete non-zero process exit.
When the receipt exactly joins the current durable observation, the same
Dashboard entity is enriched as:

| Axis | Value |
| --- | --- |
| engineering | `blocked` |
| runtime | `stopped` |
| coverage | `degraded` |
| effect | `failed_known` |

This receipt proves only that the registered job process ended with the sealed
non-zero exit and artifacts. It does **not** prove provider closure, process
tree quiescence, numeric correctness, task completion, or complete provider
coverage. Coverage therefore stays degraded.

## Reconciliation interface

The authenticated resident control route is:

```text
POST /control/v1/legacy-bridge/job-terminal/reconcile
```

The corresponding operator command is:

```text
aoi legacy-bridge reconcile-job-terminal-v04 ...
```

The request carries all five bounded artifact payloads (`command`,
`legacy_state`, `primary_log`, `process_exit`, and `terminal_manifest`). The
resident stores and reads back each CAS object, parses the canonical legacy
state, process-exit record, and terminal manifest, then recomputes the task,
packet, job, owner contract, bridge entity IDs, command, fingerprints, exit
semantics, and record hashes before attempting the ledger append. A matching
role, size, or SHA-256 alone is not sufficient. The manifest bytes must match
the digest already sealed in the durable job record; its exact version,
failed-job authority field, command path, primary-log role/origin, capture
metadata, and exit semantics are revalidated.

`observed_at` is the sealed process-exit `terminal_at`, not the CLI retry time.
An operator retry therefore reconstructs the same publication identity. The
raw legacy state is local sensitive reconciliation evidence: it is not part of
a sanitized export, provider proof, or a hostile same-user integrity claim.

The browser Dashboard remains GET/SSE-only. Browser POST requests are rejected
and cannot reach the authenticated resident control route.

The receipt ID is a deterministic child of the terminal key and the canonical
request-evidence digest. The control client derives that expected receipt ID
from its original request, then derives the expected transaction and command
IDs. A stale success for divergent evidence therefore cannot be decoded as the
new request's result. The returned cursor is still a resident observation, not
standalone proof; authoritative use requires ledger or Dashboard readback at
that cursor.

## Replay, conflicts, and history

The deterministic publication identity gives these rules:

- exact replay returns the existing receipt and does not advance the cursor;
- a second or divergent terminal receipt fails closed both at state-owner
  append and during independent reducer/replay;
- at publication time, missing CAS bytes, source drift, or any join mismatch
  produces no terminal overlay; replay independently rechecks the durable
  contract and append-once logical identity, not the raw local CAS join;
- a durable receipt never regresses during a temporary legacy query outage;
- a later current-source conflict remains visible as critical attention while
  the original legacy entity keeps its conservative V1 truth;
- historical snapshots before the receipt retain the original
  `unknown/degraded` projection, while later cursors show the exact enrichment.

## Runtime compatibility

The ledger extension is additive, but older binaries do not know its contract
type. Before the first terminal receipt is written, checkpoint the company and
preserve the old registry pointer. After upgrade, an older binary must not open
the upgraded ledger; rollback switches to the preserved company state instead
of rewriting or downgrading events in place.

Pre-acceptance development receipts that lack the required canonical
request-evidence digest are not compatible inputs and must not be carried into
the accepted company state.
