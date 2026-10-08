# Snapshot v2 Contract

Snapshot v2 keeps the v1 entity identity algorithm and adds explicit successful-stage coverage for safe mixed-profile lifecycle comparisons. `schema_version` is `"2"`; top-level `coverage` is always present, including `[]` when no stage completed successfully. An Asset, Observation, or Finding in a v2 Snapshot has a non-empty `coverage` array listing the stages that have produced that item. Provenance can include stages not present in top-level coverage when the item is retained from an earlier same-profile Snapshot.

Coverage names a completed Engine stage, not a requested profile. Current names include `dns`, `tls`, `http`, `crawl`, `javascript`, `integration.subfinder`, `integration.httpx`, `integration.katana`, and `integration.nuclei`. Skipped, failed, cancelled, or not-started stages are absent. If discovery completed and found no JavaScript candidates, the Engine records successful JavaScript analysis coverage; if JavaScript discovery or analysis failed, it does not.

When Snapshot building deduplicates an entity reported by more than one stage, the entity keeps the union of its provenance. Its stable ID remains based on the pre-existing identity fields and is not profile- or coverage-dependent. Adding provenance therefore does not fork a stable identity. `carried_forward: true` means the item was absent from this run but remains in the profile baseline because at least one provenance stage did not complete. If an item is positively observed again, the marker is omitted and its prior provenance is retained.

## Comparison rules

`pkg/diff.Compare` remains the only semantic Change generator:

- v1→v1 uses the legacy comparison rules.
- v1→v2 and v2→v1 emit no semantic Changes. A v1 Snapshot has no reliable stage provenance, so treating its missing entities as removed would be unsafe.
- v2→v2 surfaces newly observed entities as positive evidence. It treats a missing old entity as removed/resolved only when the new Snapshot successfully covers **every** stage in that entity's provenance.
- A partial Snapshot can support a negative result for an item only after every stage in its provenance completed; omitted or failed stages cannot support one.
- An entity discovered by multiple stages remains present until a later Snapshot covers all of those stages and no longer reports it. This conservative union avoids false removals, and can keep records active longer if a producer is never run again.
- Before diffing, Engine carries forward absent v2 items whose provenance was not fully covered. This preserves the comparison baseline across partial runs, so a later complete same-profile run can emit the Engine-owned resolution. Cloud does not update `last_seen_at` for carried items.

Cloud persists the Engine's Snapshot and Change IDs. It does not synthesize semantic IDs. For a Project scan, Cloud supplies the latest Snapshot for the same profile as `previous_snapshot`; Quick, Standard, and Deep each have an independent comparison lineage. The complete Snapshot history remains chronological in PostgreSQL. Same-profile lineage is necessary for a Deep→Quick→Quick→Standard→Deep sequence: the final Deep result must still compare against the earlier Deep result to emit a confirmed Nuclei Finding resolution.

## Migration from v1

No Snapshot, ScanRun, Finding, Change, or Asset history is dropped or rewritten automatically. For each profile, the first v2 scan establishes a new comparison baseline. Engine emits no semantic Changes between v1 and v2. Subsequent v2 scans use same-profile carry-forward and coverage-aware comparison.

Legacy PostgreSQL Finding/Asset rows without provenance remain open/active when absent from v2 scans. If an old entity is observed again, Cloud's normal upsert replaces its stored metadata with the v2 item and its provenance. Cloud does not infer missing source stages from display names or incomplete legacy source fields: historical deduplication may have discarded the full set of producers, particularly for multi-source Assets. Guessing that information could create false resolutions.

This policy preserves history and avoids false “resolved” outcomes, but it does not automatically retire legacy entities that never reappear. Before enabling v2 comparison for an installation with existing data, operators must inspect its persisted rows and either keep unprovenanced entities open for review or run a separately reviewed, auditable rebaseline/migration that records its scope and retains the old history. The development/pre-production data-empty assumption was not verified in the release audit, so automatic destructive rebaseline is not enabled.

## Rollback

The database additions for scan policies are additive; rollback must not drop Snapshot or Finding history. A Cloud version that requires Snapshot v2 fails closed when paired with an Engine that reports Snapshot v1. The compatible rollback is to deploy a mutually compatible Cloud/Engine pair together and stop workers during the transition. Do not allow an older Engine to write new v1 Snapshots while the Cloud continues to claim v2 compatibility. Existing v2 JSON remains stored and readable as historical data.

Before release, validate the Linux/amd64 Engine artifact and immutable OCI image together, then verify `version --json`, `doctor`, the complete distribution manifest, and Cloud preflight against the exact image digest. A local Darwin binary or a standalone Linux binary checksum does not establish the identity of the production image.
