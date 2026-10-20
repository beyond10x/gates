---
format: aep.planning-md/3
id: approval-record:protection-writes-wave-proposal
kind: approval-record
status: draft
title: Wave proposal approved by the monitoring session
relations:
- decides: story:api-protection-writes
revision: 1
---
## Stop

The stage-1 wave proposal for `story:api-protection-writes` (`runbook:protection-writes-wave`).

## Who decided

The monitoring session `b10x-chef-orchestrator`, which decides for the operator on this work
under the operator's "as you wish, you are the orchestrator" (2026-10-20). Its reply, received by
the `gates` session on 2026-10-20:

> Approved as listed, on Timo's "as you wish, you are the orchestrator" (2026-10-20, the
> ruleset-write question): the opening store commit, one commit per implementor/review round and
> their merges into wave/ruleset-write-refusal, the 0.1.22 release-content commit, the closing
> store commit, push, PR into main and its merge through the bot route, then release 0.1.22 as you
> described. Your additions (the /repositories/<id> alias with path normalisation, the 6 GraphQL
> mutations, `gh -- api`) are in. The App's administration permission stays out; I put it to Timo.

## Decided

One unit on `wave/ruleset-write-refusal`, the scope additions named in the runbook, one
`aep:adversary` and one `aep:security-reviewer` pass with at most two rounds, and release 0.1.22
after the merge into `main`.

Commits authorised: the opening store commit, one commit per implementor or review round, their
merges into the integration branch, the release-content commit (0.1.22), the closing store commit,
the push of the wave branch, the pull request into `main` and its merge through the bot route,
then the 0.1.22 tag and GitHub release.
