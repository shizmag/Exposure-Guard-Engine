# ExposureGuard Cloud Integration Contract

Cloud spawns Engine locally in a worker. Engine receives a request, executes and exits. Engine has no Cloud persistence, scheduling, retry queue, users, billing or database knowledge. Cloud owns authorization/ownership verification, idempotency, scheduling, retries and persistence.

## Single scan vs. batch

Use `scan` v1 for manual/public and latency-sensitive UI work:

```sh
exposureguard scan --request-json - --format jsonl
```

Use `batch` v1 for scheduled monitoring/background execution:

```sh
exposureguard batch --request-json - --format jsonl
```

Batch accepts one `BatchRequest` (schema `schemas/protocol-v1/batch-request.schema.json`). Items are the existing `ScanRequest` v1. Each item takes only `profile` and `mode` as ordinary policy inputs; Engine resolves native checks and integrations. Cloud should not set integration overrides. A BatchRequest accepts 16 workloads by default (`max_batch_size`), hard maximum 20. Default scan concurrency is 4, hard scan concurrency is 4. Workload count and active workers are independent. Inline `previous_snapshot` is optional and self-contained (4 MiB per snapshot); Cloud must not pass cross-process filesystem paths.

## JSONL contract

stdin is request JSON. stdout is only JSONL, one flushed JSON object per line. stderr carries diagnostics. Batch `seq` is global and monotonically increasing; item events preserve Scan Protocol v1 `schema_version`/types and add `batch_protocol_version`, `batch_id`, global `seq`, and per-scan `scan_seq`. Each scan starts at `scan_seq=1`, emits exactly one terminal event, and scan events can interleave nondeterministically. `batch.started` is first (`seq=1`); one batch terminal event is last; output after it is forbidden. Event ordering across scans is not deterministic, but each scan's sequence/semantics are.

Each terminal item has its own `ScanResult`/Snapshot. BatchResult aggregates statuses/counts, start/finish/duration and Engine provenance. It does not merge Snapshots.

| Item statuses | BatchResult.status | Batch terminal event | Process exit |
| --- | --- | --- | ---: |
| all `complete` | `complete` | `batch.completed` | 0 |
| mixture of complete/partial/failed, not all failed | `partial` | `batch.completed` | 0 |
| all `failed` | `failed` | `batch.failed` | 0 |
| all `cancelled` | `cancelled` | `batch.cancelled` | 0 |
| any mixed cancellation | `partial` | `batch.completed` | 0 |

Each scan terminal status matches its `ScanResult.status`: `scan.completed` with `complete` or `partial`, `scan.failed` with `failed`, and `scan.cancelled` with `cancelled`. Cancellation is a workload outcome. Invalid BatchRequest exits 2 before `batch.started`. Policy/semantic item failures after acceptance exit 0. Internal/runtime/protocol/output/stdout failures exit 1; stream may be truncated if stdout fails. Cloud uses each item's terminal/result for item handling; process exit is not a per-item retry signal.

For valid accepted requests, `batch.started` is first, every accepted scan has exactly one terminal, and exactly one batch terminal is last with no later events. Once stdout/protocol transport fails, a terminal cannot be guaranteed physically. SIGINT/SIGTERM stops assigning queued work, cancels active contexts and child process groups, and emits per-item cancellation terminals where stdout remains writable. The aggregate follows the table; an early normal parent cancellation can result in all-cancelled items. There is no individual in-batch cancellation in v1.

## Limits and security

Defaults: max 20 items; 4 active scans; 4 concurrent external processes; 256 MiB aggregate temp budget; 64 MiB aggregate output budget. Request input is limited to 8 MiB. A JSONL event line is capped at 64 MiB; total stream/BatchResult output is bounded by `max_output_bytes`. `max_parallel_scans = 4` remains the conservative configured ceiling and has **not been performance-validated**. Do not interpret the current setting as production concurrency tuning. Native concurrency per scan is capped at 2, per-host request rate at 1/sec. Each item passes existing target/profile/mode/netguard policy. External tools have independent network stacks: production Cloud workers MUST enforce egress isolation for `httpx`, Katana and Nuclei in addition to Go netguard. Batch limits are not egress security.

## TypeScript child-process example

```ts
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const child = spawn("/opt/exposureguard/bin/exposureguard",
  ["batch", "--request-json", "-", "--format", "jsonl"],
  { stdio: ["pipe", "pipe", "pipe"] });
const byScan = new Map<string, unknown[]>();
const lines = createInterface({ input: child.stdout });
lines.on("line", line => {
  const event = JSON.parse(line);
  if (event.scan_id) {
    const events = byScan.get(event.scan_id) ?? [];
    events.push(event);
    byScan.set(event.scan_id, events);
    if (["scan.completed", "scan.failed", "scan.cancelled"].includes(event.type)) {
      finalizeScan(event.scan_id, events);
    }
  } else if (["batch.completed", "batch.failed", "batch.cancelled"].includes(event.type)) {
    finalizeBatch(event.batch_id, event.data);
  }
});
child.stderr.pipe(process.stderr);
child.stdin.end(JSON.stringify(batchRequest));
```

Cloud MUST drain both pipes, detect premature child exit/malformed lines, and use process exit for protocol/process health only.

## Distribution and local development

Cloud MUST reject Engine distributions whose identity algorithm or Snapshot contract differs from the release lock. Cloud MUST NOT migrate legacy stable IDs. Snapshot JSON Schema v2 and Identity Algorithm v1 are separate version dimensions. Snapshot v2 coverage and v1→v2 lineage rules are documented in `snapshot-v2.md`; pre-Identity-v1 ID rebaseline policy remains in `identity-v1.md`.

Production uses `/opt/exposureguard`; Engine local development uses `exposureguard-engine/.dev/dist`. Both have identical internal layout: `bin/exposureguard`, external pinned binaries in `bin/`, templates in `share/nuclei-templates/`, curated rules in `profiles/nuclei/v1/`, `tools.lock.json`, and `distribution-manifest.json`.

Engine repository:

```bash
cd exposureguard-engine
make dev-dist
make dist-check DIST=.dev/dist
```

Cloud repository:

```bash
cd ../exposureguard-cloud
EXPOSUREGUARD_ENGINE_HOME=../exposureguard-engine/.dev/dist npm run worker:dev
```

Cloud must spawn that packaged Engine using its normal Engine home configuration. Cloud must not call `go run` or `go build`. Canonical protocol fixtures are under `testdata/cloud/`, including `batch-all-failed-*`, `batch-partial-*`, and `batch-cancelled-*`.
