---
format: aep.planning-md/3
id: approval-record:wave-2026-11-04-gates-release-go
kind: approval-record
status: draft
title: Orchestrator's go for the staged gate, the bot PR and release 0.1.26
relations:
- decides: story:scan-bounded-batches
- decides: story:ci-fetch-head-by-sha
- decides: story:published-merge-review-followups
- decides: story:bot-delete-branch-atomic
revision: 1
---
## Who decided

The coordinating session `b10x-chef-orchestrator`, under the grant in the workspace instructions,
with the build terms of the host monitor. Its message on 2026-11-05:

> go for G3–G5 as stated (3G/8, 3G/8, 1.5G/5). Stop lines: 5G or 16 cargo-min, 5G or 16, 3.5G
> or 10. Then:
> 1. One bot PR with a ci-waits row; end your turn.
> 2. On CI-DONE all green: merge through the bot and release 0.1.26 through gates' own process.
> 3. Run verify-release.sh […] with an EXIT= line, write the announcement file, and send me
>    both paths.
> A red check: stop and send me the job and its log lines, with no rerun.

## Decided

Run gate stages G3 to G5 of `wave-2026-11-04-gates` within those limits, open one bot pull
request, merge it through the bot when every check is green, and release 0.1.26 through this
repository's process. A red check stops the release without a rerun.

## Outcome of the gate (996794f)

G1 fmt and G2 clippy clean; G3 255 passed, G4 415 passed, 0 failed; G5 musl release build
validated by `scan-artifact`. Pull request https://github.com/beyond10x/gates/pull/50.
