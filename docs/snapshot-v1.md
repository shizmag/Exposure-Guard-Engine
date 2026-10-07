# ExposureGuard Engine — Snapshot v1

**Schema:** `schemas/snapshot-v1.schema.json`. Snapshots represent one target at one capture time. Batch never merges Snapshots; every scan has its own.

## Stable Identity Algorithm v1

All persistent asset, observation, finding, change-key, and change IDs are 64 lowercase hex SHA-256 values. Each digest is domain-separated and versioned:

```text
H(domain, fields...) = SHA256(
  "exposureguard:stable-id:v1\0" ||
  for each UTF-8 field: uint64_be(byte_length(field)) || field
)
```

Length-prefixing avoids concatenation/delimiter ambiguity. Domains include `asset`, `observation`, `finding`, `change-key`, `change-value`, and `change`. Asset inputs are `(kind, canonical_value)`. Observation inputs are `(kind, subject, canonical JSON stable data)` excluding documented volatile fields. Finding inputs are `(rule_id, asset_id, semantic fingerprint)`. Values are lowercase hex. This v1 identity freeze replaces prior truncated/non-domain-separated identities; Cloud must not assume old fixture IDs remain stable.

`change_key = H(change-key, type, subject_id)` identifies type+subject. `change_id = H(change, change_key, H(change-value, canonical_old), H(change-value, canonical_new))` identifies one transition. Thus A→B and B→C share key but have distinct IDs; Cloud occurrence key is `(scan_run_id, change_id)`.

## Snapshot fingerprint

Snapshot fingerprint is SHA-256 over deterministic canonical JSON prefixed by `exposureguard:snapshot-fingerprint:v1\0`. Capture time, durations, TTL, and other volatile fields remain excluded. Assets/observations/findings are normalized and deterministically sorted. Verify with `exposureguard snapshot hash file.json`.

Snapshot schema version remains `1`; stable ID contents are intentionally frozen now before v0.1 broad adoption. See `docs/batch-protocol-v1.md` for inline previous snapshots in BatchRequest.
