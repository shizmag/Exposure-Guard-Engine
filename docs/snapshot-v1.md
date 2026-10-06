# ExposureGuard Engine — Snapshot v1 Specification

**Status**: Frozen (v0.1.0)  
**Schema Identifier**: `snapshot_version = 1`  
**JSON Schema**: `schemas/snapshot-v1.schema.json`

A Snapshot is ExposureGuard's canonical, normalized inventory of a target's external attack surface at a point in time. It serves as the baseline for all temporal diffing and drift detection.

---

## 1. Core Principles

1. **Determinism**: Given identical target state, two independent scan executions must produce identical normalized snapshots and canonical fingerprints regardless of goroutine concurrency, worker completion order, network latency, or runtime environment (local vs. Docker).
2. **Low Noise**: Volatile runtime telemetry (response times, TTLs, ephemeral timestamps, volatile headers) are explicitly isolated from identity and comparison logic to prevent false-positive diff alerts.
3. **Immutability & Stability**: Asset, Observation, and Finding identifiers are derived purely from stable content hashes rather than random UUIDs.

---

## 2. Model Structure

A complete Snapshot consists of:
```json
{
  "schema_version": "1",
  "fingerprint": "a3b1c8f492e071...",
  "target": { ... },
  "captured_at": "2025-03-01T12:00:00Z",
  "assets": [ ... ],
  "observations": [ ... ],
  "findings": [ ... ],
  "summary": { ... }
}
```

### Top-Level Fields
| Field | Type | Description |
| :--- | :--- | :--- |
| `schema_version` | string | Constant `"1"` for Snapshot Schema v1. |
| `fingerprint` | string | Canonical SHA-256 hex digest of normalized state. |
| `target` | Target | Fully parsed target URL, host, domain, and scheme. |
| `captured_at` | RFC3339 string | Wall-clock timestamp when snapshot was captured. |
| `assets` | []Asset | Deterministically sorted list of discovered surface items. |
| `observations` | []Observation | Deterministically sorted list of raw telemetry and checks. |
| `findings` | []Finding | Deterministically sorted list of actionable security issues. |
| `summary` | SnapshotSummary | Counts of assets, observations, and findings by severity. |

---

## 3. Stable Identity Computation

### Assets
- **Asset ID**: First 16 hex characters of `SHA-256(Kind + ":" + Value)`
- **Kinds**: `hostname`, `url`, `javascript`, `source_map`, `endpoint_candidate`, `external_reference`.
- **Deduplication**: Assets with identical IDs are merged. Multiple sources are concatenated deterministically.

### Observations
- **Observation ID**: First 16 hex characters of `SHA-256(Kind + ":" + Subject + ":" + StableDataJSON)`
- **Volatile Field Suppression**: Keys such as `response_time_ms`, `ttl`, `timestamp`, and `captured_at` are stripped before hashing.

### Findings
- **Finding ID**: First 16 hex characters of `SHA-256(RuleID + ":" + Asset + ":" + Fingerprint)`
- **Stability Guarantee**: If evidence varies slightly in line number or timestamps, the structural `Fingerprint` preserves issue identity across repeated runs.

---

## 4. Sorting & Ordering Invariants

Snapshots strictly enforce deterministic sort order:
1. **Assets**: Ordered by `Kind` ascending, then `Value` ascending, then `ID` ascending.
2. **Observations**: Ordered by `Kind` ascending, then `Subject` ascending, then `ID` ascending.
3. **Findings**: Ordered by `Severity` descending (`critical` > `high` > `medium` > `low` > `info`), then `RuleID` ascending, then `Asset` ascending, then `ID` ascending.

---

## 5. Canonical Fingerprint (`ComputeCanonicalHash`)

The `fingerprint` field is calculated over a canonical, stripped representation of the snapshot:
$$\text{fingerprint} = \text{SHA-256}(\text{CanonicalJSON})$$

### Invariance Guarantees
The canonical hash **does not depend on**:
- `captured_at` timestamp
- Total scan duration or stage latencies
- Goroutine scheduling or network packet order
- Local host vs. Docker container execution
- DNS TTL variations

You can verify the fingerprint of any snapshot file via the CLI:
```bash
exposureguard snapshot hash snapshot.json
```

---

## 6. Diffing & Noise Reduction Contract

When executing `exposureguard diff <old.json> <new.json>`:
1. **Zero-Change Guarantee**: Identical semantic states produce zero changes, even if item orderings or timestamps in the files differ.
2. **Suppressed Volatile Fields**: Dynamic HTTP headers (`Date`, `ETag`, `Set-Cookie` values, `X-Request-Id`, `CF-Ray`) and DNS TTL fluctuations never generate false-positive changes.
3. **Change Identity**: Every `Change` struct possesses a deterministic `ID` computed as `SHA-256(Type + ":" + Subject)[:16]`.

---

## 7. Migration Stance

- ExposureGuard v0.1.0 exclusively produces and accepts `schema_version = "1"`.
- If an older or newer schema version is detected, the engine emits a clear validation error.
- Future schema iterations (v2+) will introduce automated migration adapters where feasible.
