---
format: aep.planning-md/3
id: approval-record:merge-baseline-wave-proposal
kind: approval-record
status: draft
title: Wave proposal accepted with no operator present
tags:
- non-interactive
relations:
- decides: story:api-merge-push-admitted
- decides: story:bot-delete-branch-defaults
revision: 1
---
## Wave proposal accepted with no operator present

- Stop: the wave proposal of `runbook:merge-baseline-wave` (aep implementing, stage 1).
- Reason: non-interactive. The request approved this wave in advance and asked that it run
  without waiting for an answer.
- Decided: run wave 1 with `story:api-merge-push-admitted` and `story:bot-delete-branch-defaults`
  in separate trees, integrate on `wave/merge-baseline`, one pull request, release 0.1.18.
- The operator would have been asked: whether to run these two units together as one wave, and
  whether `story:bot-delete-branch-atomic` stays out of it (it does: it needs a compare-and-delete
  primitive that the REST route does not offer).
