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

stdin is request JSON. stdout is only JSONL, one flushed JSON object per line. stderr carries diagnostics. Batch `seq` is global and monotonically increasing; item events preserve Scan Protocol v1 `schema_version`/types and add `batch_protocol_version`, `batch_id`, `seq`, `scan_seq`. Each scan starts at `scan_seq=1`, emits exactly one terminal event, and scan events can interleave nondeterministically. `batch.started` is first (`seq=1`); one batch terminal event is last; output after it is forbidden. Event ordering across scans is not deterministic, but each scan's sequence/semantics are.

Each terminal item has its own `ScanResult`/Snapshot. BatchResult aggregates statuses/counts, start/finish/duration and Engine provenance. It does not merge Snapshots. Item failure is isolated; if all items terminate, normal item failures do not make protocol execution fail. Cloud retries per item. Nonzero process status indicates invalid request, irrecoverable controller/process failure or stdout protocol failure, not vulnerability results.

SIGINT/SIGTERM stops dequeuing, cancels active item contexts and child process groups, emits item cancellation terminals where stdout remains writable, then `batch.cancelled`. No individual in-batch cancellation in v1.

## Limits and security

Defaults: max 20 items; 4 active scans; 4 concurrent external processes; 256 MiB aggregate temp budget; 64 MiB aggregate output/event budget. Hard concurrency ceilings are 4. Native concurrency is capped at 4 and per-host request rate at 2/sec. Each item passes existing target/profile/mode/netguard policy. External tools have independent network stacks: production Cloud worker MUST enforce egress isolation for `httpx`, Katana, and Nuclei in addition to Go netguard. Do not rely on batch controls as egress security.

## TypeScript child-process example

```ts
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const child = spawn("/opt/exposureguard/bin/exposureguard",
  ["batch", "--request-json", "-", "--format", "jsonl"],
  { stdio: ["pipe", "pipe", "pipe"] });
const byScan = new Map<string, unknown[]>();
const lines = createInterface({ input: child.stdout });
lines.on("line", (line) => {
  const event = JSON.parse(line);
  if (event.scan_id) {
    const events = byScan.get(event.scan_id) ?? [];
    events.push(event);
    byScan.set(event.scan_id, events);
    if (["scan.completed", "scan.failed", "scan.cancelled"].includes(event.type)) {
      finalizeScan(event.scan_id, events); // Cloud persistence/retry policy
    }
  } else if (["batch.completed", "batch.failed", "batch.cancelled"].includes(event.type)) {
    finalizeBatch(event.batch_id, event.data);
  }
});
child.stderr.pipe(process.stderr);
child.stdin.end(JSON.stringify(batchRequest));
```

Cloud MUST drain stdout and stderr, detect premature child exit/malformed lines, and treat child exit status as protocol/process health. Batch result fixtures for Cloud contract tests live at `testdata/cloud/batch-request.json`, `batch-events.jsonl`, and `batch-result.json`.
