# ExposureGuard Cloud Integration Contract

This document specifies the process execution contract for running **ExposureGuard Engine** as an isolated worker subprocess inside ExposureGuard Cloud or CI/CD pipelines.

---

## 1. Execution Model

ExposureGuard Cloud invokes the `exposureguard` binary as an ephemeral worker process:

```bash
exposureguard scan \
  --request-json - \
  --format jsonl
```

### Streams Contract
- **stdin**: Accepts structured `ScanRequest` JSON.
- **stdout**: Strictly emits line-delimited JSON (`JSONL` / `NDJSON`) protocol events. Every line is a self-contained JSON object terminated by `\n`. Flushed immediately after every event.
- **stderr**: Diagnostic logs only. Diagnostic messages are never mixed into stdout.

---

## 2. ScanRequest Schema (stdin)

```json
{
  "schema_version": "1",
  "scan_id": "019488a0-7b2c-7412-a1b2-c3d4e5f67890",
  "target": "https://example.com",
  "profile": "website",
  "mode": "public",
  "modules": [
    "dns",
    "tls",
    "http",
    "crawl",
    "javascript"
  ],
  "limits": {
    "total_timeout_seconds": 120,
    "request_timeout_seconds": 10,
    "dns_timeout_seconds": 5,
    "tls_handshake_timeout_seconds": 7,
    "max_redirects": 8,
    "max_depth": 2,
    "max_pages": 100,
    "max_assets": 500,
    "max_response_bytes": 4194304,
    "max_total_download_bytes": 52428800,
    "max_concurrency": 8,
    "max_per_host_concurrency": 4,
    "requests_per_second_per_host": 2.0
  }
}
```

All fields are validated by the engine upon startup. Clamping ensures safety bounds cannot be bypassed.

### Mode Authorization Contract
- `mode: "public"`: Default safe outside-in scanning. Only native modules and passive discovery (`subfinder`) execute.
- `mode: "owned"`: Authorizes extended active discovery (`httpx`, `katana`, `nuclei`).
- **Cloud Obligation**: ExposureGuard Cloud **MUST** complete authoritative proof-of-ownership (e.g. DNS TXT record challenge or HTTP token validation) before dispatching a request with `"mode": "owned"` to any engine worker. The engine worker executes in an unprivileged runtime and cannot independently verify domain ownership.

---

## 3. Streaming Event Protocol (stdout JSONL)

Every event adheres to the standard `Envelope`:

```json
{
  "schema_version": "1",
  "seq": 1,
  "timestamp": "2026-10-06T12:00:00.123Z",
  "scan_id": "019488a0-7b2c-7412-a1b2-c3d4e5f67890",
  "type": "scan.started",
  "data": { ... }
}
```

- `seq`: Monotonically increasing sequence number per scan run.
- `timestamp`: UTC ISO-8601 (RFC 3339).

### Lifecycle Sequence:
1. `scan.started`
2. `stage.started` (`stage: dns`)
3. `observation` (`kind: dns_record`)
4. `asset.discovered` (`kind: hostname`)
5. `stage.completed` (`stage: dns`)
6. `stage.started` (`stage: tls`)
7. `observation` (`kind: tls_certificate`)
8. `finding` (if certificate expires or mismatch occurs)
9. `stage.completed` (`stage: tls`)
10. `stage.started` (`stage: http`)
11. `observation` (`kind: http_response`, `kind: security_headers`, `kind: cookie_metadata`)
12. `finding` (e.g. `http.missing_hsts`)
13. `stage.completed` (`stage: http`)
14. `stage.started` (`stage: crawl`)
15. `observation` (`kind: crawled_page`)
16. `asset.discovered` (`kind: javascript`)
17. `stage.completed` (`stage: crawl`)
18. `stage.started` (`stage: javascript`)
19. `observation` (`kind: source_map_detected`)
20. `finding` (`rule_id: frontend.public_source_map`)
21. `stage.completed` (`stage: javascript`)
22. `change` (if `--previous-snapshot` was supplied)
23. `scan.summary`
24. `scan.completed` (or `scan.failed`)

---

## 4. Exit Codes

| Exit Code | Meaning | Cloud Action |
|---|---|---|
| `0` | Scan executed successfully | Parse snapshot and persist results. Findings do NOT cause non-zero exit code. |
| `1` | Operational / Network failure | Mark scan as failed or retry if transient. |
| `2` | Invalid request / bad parameters | Reject job without retry. |
| `3` | Security policy rejected target (SSRF attempt) | Mark target as rejected by security policy. |
| `4` | Scan aborted / cancelled | Mark job as cancelled. |

---

## 5. Cancellation & Graceful Shutdown

When cancelling a scan job:
1. ExposureGuard Cloud sends `SIGTERM` or `SIGINT` to the process.
2. The engine catches the signal, cancels active HTTP/crawl connections, and attempts to emit `scan.failed` with status `cancelled` to stdout before exiting.
3. If the process does not terminate within the grace period (e.g. 5 seconds), send `SIGKILL`.

---

## 6. Versioning & Schema Compatibility

- `protocol_version`: Current value is `"1"`.
- `snapshot_schema_version`: Current value is `"1"`.
- Query engine versions dynamically using:
  ```bash
  exposureguard version --json
  ```
