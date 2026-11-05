---
format: aep.planning-md/3
id: approval-record:wave-2026-11-04-gates-approval
kind: approval-record
status: draft
title: Orchestrator accepted the wave-2026-11-04-gates stories and release 0.1.26
relations:
- decides: story:scan-bounded-batches
- decides: story:ci-fetch-head-by-sha
- decides: story:published-merge-review-followups
- decides: story:bot-delete-branch-atomic
revision: 2
---
## Who decided

The coordinating session `b10x-chef-orchestrator`, under the grant in the workspace instructions
(a message from it naming a class-C item counts as the operator's approval; it accepts proposed
stories, the wave lead never does). Its message on 2026-11-04:

> Accepted: scan-bounded-batches (new), ci-fetch-head-by-sha, published-merge-review-followups,
> bot-delete-branch-atomic.
> Kept as drafts: published-merge-custom-subject-fallback, ess-inner-workings.
> Close the 4 delivered stories as R1.
> R2 and R3 ride as proposed, including dropping R3 if its check goes red on history alone.
> The release is 0.1.26. The common.yml pin to 0.1.26 is a follow-up PR after release.
> Keeping target/ between gate stages is fine at a 5G peak.

## Decided

Wave `wave-2026-11-04-gates` on the integration branch of that name:

- U1 `story:scan-bounded-batches`, U2 `story:ci-fetch-head-by-sha`,
  U3 `story:published-merge-review-followups`, U4 `story:bot-delete-branch-atomic`, moved to
  active.
- R1: close `story:ci-compressed-policy` (04b0ddb, released 0.1.21),
  `story:github-update-branch-provenance` (47c0686, released 0.1.12),
  `story:release-artifact-validation` (824f18d, released 0.1.12) and
  `story:public-shared-gates` (e74ec42, released 0.1.1) as implemented, without code changes.
- R2: a test that a policy exception admits a historical `personal-paths` finding, and a README
  sentence saying exceptions reach every rule while allowances never reach `personal-paths`.
- R3: the repository's own `shared-gates.yml` moves from the `common.yml` that downloads 0.1.3
  to the one that downloads 0.1.24; dropped if its check fails on history alone.
- One local full gate in stages, one bot PR, merge on green, release 0.1.26. Moving
  `common.yml` to download 0.1.26 is a follow-up pull request after the release.
