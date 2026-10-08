# Batch Protocol v1

Status: stable for ExposureGuard Cloud v0.1. Batch is a stateless process invocation. It performs independent ScanRequest v1 workloads and does not create/merge project Snapshots.

## Command and transport

```sh
exposureguard batch --request-json - --format jsonl
```

stdin contains exactly one `BatchRequest` object. JSONL is the production transport; `--format json` emits a `BatchResult`. Diagnostics are stderr-only. A batch is limited to 8 MiB request bytes and defaults to 16 workloads (`max_batch_size`), hard maximum 20. `scans[]` items are the existing `ScanRequest` v1 type, including optional inline `previous_snapshot`; each Snapshot payload is limited to 4 MiB. Cloud sends only profile/mode as normal policy inputs. Engine owns integration selection. Do not use integration overrides in Cloud requests.

```json
{
  "batch_protocol_version": "1",
  "batch_id": "b1000000-0000-4000-8000-000000000001",
  "limits": {"max_parallel_scans": 4, "max_parallel_external_processes": 4,
    "max_temp_bytes": 268435456, "max_output_bytes": 67108864},
  "scans": [
    {"schema_version":"1", "scan_id":"c1000000-0000-4000-8000-000000000011",
     "target":"https://one.example.com", "mode":"public", "profile":"standard"},
    {"schema_version":"1", "scan_id":"c1000000-0000-4000-8000-000000000012",
     "target":"https://two.example.com", "mode":"owned", "profile":"deep"}
  ]
}
```

`batch_protocol_version` is required and must be `"1"`; `batch_id` and every `scan_id` are UUIDs; scan IDs are unique within a batch. The envelope, count, duplicates, version and basic scan structure are rejected before starting work. Semantic target/profile/policy failures are per-item `scan.failed` events; remaining items run.

## Limits and scheduling

- Default batch size: 16; hard batch size: 20 workloads. Workloads are not concurrency.
- Default scan concurrency: 4; hard ceiling: 4. 1, 2 or 4 may be requested. Per-scan native concurrency is capped at 2.
- Default `max_parallel_external_processes` is `min(max_parallel_scans, 4)`; never above scan concurrency or hard ceiling 4. Slots are shared by the Engine instance.
- Native per-scan HTTP/crawler concurrency is clamped to 2 and per-host rate to 1 request/sec; this conservative per-scan ceiling is used with the 4-scan batch ceiling.
- Aggregate external stdout/stderr is budgeted at 64 MiB; aggregate temporary output budget is 256 MiB. `max_output_bytes` and `max_temp_bytes` may lower those defaults, not raise them. The BatchRequest input limit is 8 MiB; each emitted JSONL event line is capped at 64 MiB, and aggregate JSONL/BatchResult output is capped by `max_output_bytes` (default 64 MiB).
- Work is submitted FIFO to a fixed worker pool; each completion frees a slot for the next queued scan. Each scan gets a separate Snapshot; only result summaries are aggregated.

Cancellation stops assigning queued work and cancels active contexts/child process groups; every accepted item is still driven to a terminal `scan.cancelled` where stdout remains writable. The aggregate then follows the normal status table (`cancelled` + `batch.cancelled` only if all items cancelled; otherwise `partial` + `batch.completed`). A CLI parent context that is cancelled before event streaming starts can yield all item cancellation terminals. Engine child processes are directly managed; there is no queue/daemon.

`max_parallel_scans = 4` remains the conservative configured ceiling/default; it has not been performance-validated. Do not interpret this as production concurrency tuning.

## JSONL envelope and ordering

The first line is `batch.started` with `batch_protocol_version`, `batch_id`, `seq:1`, `timestamp`, and data. Every item event preserves scan v1 fields/types and adds `batch_protocol_version`, `batch_id`, global `seq`, and per-scan `scan_seq`. Global sequence increases monotonically over stdout. Per-scan sequence starts at 1 on `scan.started`, increases without gaps, and has exactly one terminal `scan.completed`, `scan.failed` or `scan.cancelled`. Different scans interleave nondeterministically. The one terminal batch event (`batch.completed`, `batch.failed`, or `batch.cancelled`) is the last line; no subsequent write is allowed. Per-scan snapshot content is deterministic independent of interleaving. When a terminal event is emitted, the terminal status agrees with the embedded item/result status.

A scan failure does not stop siblings. Every valid accepted request emits `batch.started` first, exactly one terminal event for each accepted scan, then exactly one batch terminal event last. If stdout/protocol transport fails, a terminal event may be physically impossible; Engine exits 1 and Cloud must treat stream as incomplete.

Aggregate status is determined only by item terminal statuses:

| Item statuses | BatchResult.status | Batch terminal event | Process exit |
| --- | --- | --- | ---: |
| all `complete` | `complete` | `batch.completed` | 0 |
| any mixture of `complete`/`partial`/`failed`, with no cancellation and not all failed | `partial` | `batch.completed` | 0 |
| all `failed` | `failed` | `batch.failed` | 0 |
| all `cancelled` | `cancelled` | `batch.cancelled` | 0 |
| any mixture containing cancellation | `partial` | `batch.completed` | 0 |

`scan.cancelled` carries `result.status = cancelled`; a terminal cancellation discovered before a ScanResult can be produced has the same status in event data and BatchScanResult. `scan.completed` carries `result.status` `complete` or `partial`; `scan.failed` carries `failed`. Cancellation is a normal workload outcome and never selects process exit status.

Invalid/malformed BatchRequest, unsupported protocol, and invalid limits exit 2 before `batch.started`. Policy/semantic rejection after acceptance is an item `scan.failed` and exits 0. Internal/runtime, protocol encoding, output-budget or stdout failures exit 1; stdout failure can truncate stream. Exit code is not a retry signal for individual scans. Cloud uses each scan terminal/result.

`BatchResult` contains each independent `ScanResult`, aggregate status/counts/timestamps/duration and Engine provenance. No Snapshots are merged.

## Cloud process example (TypeScript)

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
  if (event.type.startsWith("scan." ) || event.scan_id) {
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

`finalizeScan`/`finalizeBatch` represent Cloud-owned persistence and scheduling. Use `scan` v1 for manual/latency-sensitive public scans; use `batch` for scheduled background monitoring. Cloud owns retries, idempotency, authorization and persistence.

Deep/owned subprocesses `httpx`, Katana, and Nuclei have independent network stacks and bypass Go `netguard`; production workers MUST have egress isolation as specified in `deployment-security.md`.
