# ExposureGuard Engine — Protocol v1 Specification

**Status**: Frozen (v0.1.0)  
**Protocol Version**: `1`  
**Schema Identifier**: `protocol_version = 1`

This document defines the formal communication contract between ExposureGuard Engine and its consumers (CLI, CI runners, and ExposureGuard Cloud workers).

---

## 1. Compatibility Philosophy

1. **Unknown Fields**: Consumers and ingestion pipelines **MUST** ignore unknown fields in JSON/JSONL payloads.
2. **Additive Changes**: Introducing new optional fields to existing schemas is backwards compatible and does not increment `protocol_version`.
3. **Breaking Changes**: Modifying field semantics, removing fields, renaming fields, or altering sequence ordering constitutes a breaking change and requires incrementing `protocol_version` (`protocol_version = 2`).
4. **Snapshot Compatibility**: The Snapshot schema adheres to a separate, versioned schema contract (`snapshot_version = 1`).

---

## 2. Inbound Contract: `ScanRequest`

Scans are initiated via CLI flags or by supplying a structured JSON request via `--request-json <path>` or stdin (`--request-json -`).

### Schema Definition
Located at: `schemas/protocol-v1/scan-request.schema.json`

### Example
```json
{
  "schema_version": "1",
  "scan_id": "8f8b3c9b-6401-4475-b66a-49339e083656",
  "target": "https://example.com",
  "profile": "standard",
  "mode": "public",
  "integrations": "auto",
  "limits": {
    "total_timeout_seconds": 120,
    "max_concurrency": 10,
    "max_pages": 50,
    "max_depth": 2
  }
}
```

### Fields
| Field | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `schema_version` | string | No | Protocol version (defaults to `"1"`). |
| `scan_id` | string | No | Unique execution trace ID. Auto-generated as UUIDv4 if omitted. |
| `target` | string | **Yes** | Domain, hostname, or full URL to inspect. |
| `profile` | string | No | Preset scan profile: `quick`, `standard` (default), or `deep`. |
| `mode` | string | No | Authorization tier: `public` (safe) or `owned` (authorized active probes). |
| `modules` | []string | No | Explicit list of native modules to execute. |
| `disable_modules`| []string | No | Native modules to skip. |
| `integrations` | string | No | External integration rule: `"auto"`, `"none"`, or comma-separated names. |
| `disable_integrations` | []string | No | Specific integrations to disable. |
| `require_integrations` | []string | No | Integrations that must be installed and compatible, or scan aborts. |
| `limits` | object | No | Resource bounds and rate limits (clamped to hard limits). |

---

## 3. Streaming Contract: JSONL Events

When executed with `--format jsonl`, the engine writes line-delimited JSON envelopes to `stdout`.

### Envelope Schema
Located at: `schemas/protocol-v1/event.schema.json`

Every JSON line is an `Envelope`:
```json
{
  "schema_version": "1",
  "seq": 1,
  "timestamp": "2025-03-01T12:00:00.000000Z",
  "scan_id": "8f8b3c9b-6401-4475-b66a-49339e083656",
  "type": "scan.started",
  "data": { ... }
}
```

### Event Lifecycle & Ordering Invariants
1. **Monotonic Sequences**: `seq` begins at `1` and increments strictly monotonically (`seq = N + 1`) without gaps or out-of-order delivery.
2. **First Event**: `scan.started` is **always** emitted as `seq = 1`.
3. **Stage Boundaries**: Every stage emits `stage.started` followed eventually by `stage.completed`.
4. **Intermediate Events**: `asset.discovered`, `observation`, `finding`, `change`, and `warning` stream in real-time as they occur.
5. **Terminal Event**: Exactly one terminal event concludes the stream:
   - `scan.completed`: Scan finished successfully (even if warnings or findings were present).
   - `scan.failed`: Scan aborted due to unrecoverable error, timeout, or policy violation.
6. **No Events After Terminal**: No event is ever written after a terminal event. Any subsequent write attempt raises an error.

### Event Types
| Event Type | Category | Data Payload |
| :--- | :--- | :--- |
| `scan.started` | Lifecycle | Target URL, Scan ID, Mode |
| `stage.started` | Progress | Stage name (`dns`, `tls`, `http`, `crawl`, etc.) |
| `stage.completed` | Progress | Stage name |
| `asset.discovered` | Inventory | Discovered `Asset` object |
| `observation` | Telemetry | Recorded `Observation` object |
| `finding` | Detection | Actionable `Finding` object |
| `change` | State Diff | Calculated `Change` transition object |
| `warning` | Notice | Non-fatal diagnostic warning |
| `scan.summary` | Metrics | Final `ScanStats` counts |
| `scan.completed` | Terminal | Final status (`complete` / `partial`), total findings count |
| `scan.failed` | Terminal | Failure errors array |

---

## 4. Outbound Contract: `ScanResult`

When executed with `--format json`, or upon parsing completed run outputs, the engine produces a complete `ScanResult`.

### Schema Definition
Located at: `schemas/protocol-v1/scan-result.schema.json`

### Example
```json
{
  "schema_version": "1",
  "status": "complete",
  "scan_id": "8f8b3c9b-6401-4475-b66a-49339e083656",
  "target": {
    "raw": "example.com",
    "url": "https://example.com/",
    "scheme": "https",
    "host": "example.com",
    "domain": "example.com",
    "port": 443
  },
  "snapshot": { ... },
  "changes": [ ... ],
  "summary": {
    "total_duration": 4800000000,
    "assets_discovered": 18,
    "total_observations": 25,
    "total_findings": 2,
    "total_changes": 1
  },
  "started_at": "2025-03-01T12:00:00.000000Z",
  "completed_at": "2025-03-01T12:00:04.800000Z",
  "errors": []
}
```

---

## 5. Exit Code Standards

CLI and automated invocations strictly follow predictable exit codes:

| Exit Code | Semantic Meaning | Description |
| :---: | :--- | :--- |
| **`0`** | **Success** | Scan completed normally (even if findings or changes were identified). |
| **`1`** | **General Error** | Internal runtime failure or unexpected exception. |
| **`2`** | **Usage Error** | Invalid flags, malformed JSON input, unknown profile, or plan validation error. |
| **`3`** | **Security Violation** | NetGuard blocked target (SSRF prevention, private IP without escape hatch, metadata host). |
| **`4`** | **Timeout / Cancel** | Total scan execution timeout reached or canceled via SIGINT/SIGTERM. |
