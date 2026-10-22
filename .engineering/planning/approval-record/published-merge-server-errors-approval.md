---
format: aep.planning-md/3
id: approval-record:published-merge-server-errors-approval
kind: approval-record
status: draft
title: Orchestrator approved the published-merge 5xx fix and 0.1.23
relations:
- decides: story:published-merge-server-errors
revision: 2
---
## Who decided

The monitoring session `b10x-chef-orchestrator`, under the grant in the workspace instructions
(a message from it naming a class-C item counts as the operator's approval). Its message to the
`gates` session on 2026-10-22:

> fix the published-merge check that blocks bot pushes. Approved under the grant in
> ~/beyond10x/CLAUDE.md: commit, PR, merge through the bot, and a gates patch release through
> gates' own process.

> Wanted: (1) bounded retry with backoff on 5xx for GETs; (2) the failing method and path named
> in the error; (3) when commits/<sha>/pulls keeps returning 5xx, prove the merge's PR another way
> that is just as strict (for example, the PR number from the merge commit message, then GET
> /pulls/<n> and check merge_commit_sha == <merge>); it must stay fail-closed, with no
> admit-on-error; (4) adversary cases for each path.

## Decided

Implement `story:published-merge-server-errors` on `fix/published-merge-5xx`, merge it into
`main` through the bot route, and release 0.1.23 through this repository's process.

Taken by the `gates` session inside the item: 5 attempts (0.5/1/2/4 s), because one URL answered
500 four times in a row on 2026-10-22; only 5xx is retried; the subject number is a lookup key,
proved by the `/pulls/<n>` record.
