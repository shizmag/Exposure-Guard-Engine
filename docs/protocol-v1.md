# ExposureGuard Engine — Scan Protocol v1

**Status:** Stable, backward-compatible. **Protocol version:** `1`. **Request/event schemas:** `schemas/protocol-v1/`.

## Compatibility

The existing command remains supported:

```bash
exposureguard scan --request-json - --format jsonl
```

`ScanRequest` fields are unchanged; existing consumers keep working. Unknown JSON fields are ignored. Additive optional ScanRequest fields remain compatible. Scan JSONL has `schema_version: "1"`, per-process monotonic `seq`, `scan_id`, `type`, timestamp and event-specific data. stdout is JSONL only; diagnostics go to stderr.

Cloud sends one request per manual/latency-sensitive scan. Scheduled/background work may use Batch Protocol v1 (`exposureguard batch`), whose items reuse this exact ScanRequest type; see `docs/batch-protocol-v1.md`.

## ScanRequest

Schema: `schemas/protocol-v1/scan-request.schema.json`.

```json
{
  "schema_version": "1",
  "scan_id": "8f8b3c9b-6401-4475-b66a-49339e083656",
  "target": "https://example.com",
  "profile": "standard",
  "mode": "public",
  "limits": {"total_timeout_seconds": 120, "max_concurrency": 8}
}
```

`schema_version` defaults to 1; missing `scan_id` is generated as UUIDv4. `target` is required. Profiles: quick, standard, deep. Mode: public or owned. Optional `previous_snapshot` embeds prior Snapshot v1 (4 MiB Cloud payload ceiling); CLI `--previous-snapshot` remains supported.

Cloud proof-of-ownership remains Cloud-owned. `mode: owned` is an authorization assertion after Cloud verification, not a substitute for it. Engine enforces profile/mode policy and network restrictions.

## Events and result

Existing event types and semantics remain stable: scan.started, stage.started/completed, asset.discovered, observation, finding, change, warning, scan.summary, scan.completed/failed. `scan.cancelled` and `ScanResult.status = cancelled` are frozen together for cancellation; the event and result statuses MUST match. `ScanResult.status` is one of `complete`, `partial`, `failed`, `cancelled`. Exactly one scan terminal event is emitted when output remains writable.

`ScanResult` schema: `schemas/protocol-v1/scan-result.schema.json`. Human, `--format json`, and `--format jsonl` remain supported. JSONL starts/streams events; JSON returns a complete result. Snapshot schema version and Identity Algorithm version are separate compatibility dimensions; Cloud v0.1 accepts only Engine distributions reporting `identity_algorithm_version: "1"`. See [Identity Algorithm v1](identity-v1.md) for pre-v1 rebaseline policy. Snapshot v1 is separately versioned.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Protocol execution completed; findings/changes do not affect status |
| 1 | Internal/runtime error |
| 2 | Usage/request validation error |
| 3 | Netguard security policy blocked target |
| 4 | Timeout or cancellation for standalone `scan` invocation; in Batch, `cancelled` is a workload status and normal batch cancellation exits 0 |

Batch process/aggregate status uses Batch Protocol v1 rules, not these scan findings semantics.
