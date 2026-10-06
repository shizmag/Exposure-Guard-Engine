---
name: New Check Proposal
about: Propose a new native security check or misconfiguration detection rule
title: "[CHECK] "
labels: ["check-proposal"]
assignees: []
---

## Proposed Check Identifier
`module.<name>` (e.g. `http.security_header_x`)

## Target Exposure
<!-- What specific exposure or misconfiguration does this detect? -->

## Severity & Confidence Rationale
- Proposed Severity: `Critical` / `High` / `Medium` / `Low` / `Info`
- Confidence Level: `High` / `Medium`
- False-Positive Risks:

## Network Activity & Safety
- Requests Generated: (e.g. 1 GET request to root, bounded header inspection)
- Active vs. Passive:
- Applicable Modes: `public` or `owned` only
- Credential Handling:
