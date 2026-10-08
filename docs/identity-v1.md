# Identity Algorithm v1

**Status:** frozen for ExposureGuard Engine v0.1.0. Do not change formulas without a demonstrated correctness bug and a new identity algorithm version.

## Stable-ID primitive

All IDs below are the full SHA-256 digest rendered as 64 lowercase hexadecimal characters. Strings are UTF-8; byte length, not rune count, is framed.

```text
H(domain, fields...) = SHA256(
  UTF8("exposureguard:stable-id:v1\0") ||
  uint64_be(length(UTF8(domain))) || UTF8(domain) ||
  for each field in order:
    uint64_be(length(UTF8(field))) || UTF8(field)
)
```

The domain is the first length-framed field after the fixed prefix. Distinct domains separate identity purposes. Length framing prevents delimiter/concatenation ambiguity.

## Exact formulas

| Identity | Inputs |
| --- | --- |
| Asset ID | `H("asset", kind, trim_space(value))`; `kind` is its serialized value. |
| Observation ID | `H("observation", kind, subject, JSON(data_without_volatile_keys))`; remove keys matching case-insensitively `{response_time_ms, ttl, timestamp, captured_at}`. Preserve remaining keys/values exactly for ID calculation. Go `encoding/json.Marshal` output is used. |
| Finding ID | `H("finding", rule_id, asset_locator, evidence_fingerprint)`; use exact producer-provided `Finding.Asset` and fingerprint strings. |
| Change key | `H("change-key", change_type, subject_id)` |
| Change ID | `H("change", change_key, H("change-value", old_json), H("change-value", new_json))`; old/new values are Go `encoding/json.Marshal` output (`nil` → `null`); marshal failure fallback is `fmt.Sprintf("%T:%v", value, value)`. |
| Snapshot fingerprint | `SHA256(UTF8("exposureguard:snapshot-fingerprint:v1\0") || JSON(representation))`. Representation is `{target,assets,observations,findings}`. Target=`scheme://host:port`; assets retain kind + trimmed value; observations lowercase keys, trim string values, drop volatile keys; findings retain rule_id, severity, trimmed asset, evidence fingerprint. Entity IDs are excluded. Arrays sorted: assets by kind/value, observations by kind/subject, findings by rule/asset/fingerprint. JSON is Go `encoding/json.Marshal` output. |

For change values A→B and B→C, `change_key` is same and `change_id` differs. Cloud occurrence key remains `(scan_run_id, change_id)`.

## Version dimensions and compatibility

```text
Snapshot JSON schema version = 1
Identity algorithm version = 1
```

These are separate version dimensions. Machine metadata and valid distributions report `identity_algorithm_version: "1"`. ExposureGuard Cloud v0.1 MUST reject Engine distributions with another/missing identity version; Cloud MUST NOT auto-migrate IDs.

## Pre-v1 data policy

Snapshots/state created before Identity Algorithm v1 are development/pre-release artifacts and MUST be rebaselined. Old 16-hex IDs are not matched or migrated. For local development, drop/rebaseline old dev DB snapshots/findings/assets and capture a new baseline with Identity v1 Engine. No automatic destructive migration is provided.
