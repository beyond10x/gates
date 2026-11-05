---
format: aep.planning-md/3
id: approval-record:wave-2026-11-05-gates-go
kind: approval-record
status: draft
title: Orchestrator's go for wave-2026-11-05-gates and release 0.1.27
relations:
- decides: story:bot-git-ssl-env
- decides: story:token-env-error-value
- decides: story:api-writes-no-redirect
revision: 1
---
## Who decided

The coordinating session `b10x-chef-orchestrator`, under the grant in the workspace instructions,
with the host monitor's build terms. Its message on 2026-11-05:

> go for gates 0.1.27, U1–U4 as proposed.
> - Order: U2 and U3 first, U4 after one of them merges, merges in the order U2, U3, U4.
> - Each code unit gets an adversary pass and a security review, with at most 3 sub-agents at
>   once.
> - Gate G1–G5 per your table, with BUILD_SLOTS=2, discards between stages, floor 45G, stop at
>   / < 40G.
> - The PR body states that U1 is not exercised by its own PR's CI (shared-gates.yml pins
>   common.yml@c949e63), and gives the hand check of URL and sha256.
> - One bot PR, then merge, release, verify and announce on green; a red check means stop and
>   report.

## Decided

Implement U1 (the `common.yml` download of 0.1.26) and the stories `story:bot-git-ssl-env`,
`story:token-env-error-value` and `story:api-writes-no-redirect` in `wave-2026-11-05-gates`,
review each code unit twice, run the staged gate, open one bot pull request, and on green
merge it and release 0.1.27 through this repository's process.
