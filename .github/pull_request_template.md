## Summary

<!-- Briefly describe the purpose and impact of this change. -->

## Changes

- [ ] Core engine / CLI update
- [ ] Native check modification
- [ ] Integration adapter update
- [ ] Protocol / Schema update
- [ ] Documentation / Tooling

## Impact Assessment

- **Security Impact**: Does this introduce new network activity, file operations, or privilege requirements?
- **Protocol Impact**: Does this modify or break Protocol v1 contracts?
- **Snapshot Impact**: Does this alter normalized snapshot representation or canonical hashing?
- **Network Boundaries**: Does this respect NetGuard and mode boundaries (`public` vs `owned`)?

## Verification Checklist

- [ ] `make test` passes locally
- [ ] `make test-race` passes without data races
- [ ] `make manifest-check` passes (if tools.lock.json changed)
- [ ] `make release-smoke` passes
- [ ] New unit and/or invariant tests added
- [ ] Documentation updated in `docs/`
