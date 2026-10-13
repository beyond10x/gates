---
format: aep.planning-md/3
id: runbook:merge-baseline-wave
kind: runbook
status: draft
title: 'Wave: API merges need no baseline move; delete-branch deletes merged wave branches'
relations:
- informed_by: story:api-merge-push-admitted
- informed_by: story:bot-delete-branch-defaults
revision: 1
---
## Wave: API merges need no baseline move; delete-branch deletes merged wave branches

Non-interactive run: the request approved this wave up front ("propose it on your wave page and
run it without waiting for an answer"); the stage-1 stop is recorded as
`approval-record:merge-baseline-wave-proposal`. Selection: two units, chosen by the request.
`aep plan artifact waves --status active` places both in wave 1 with no collision between them
(both scopes inferred). The plan-critic panel is skipped: the two stories derive from different
parents, so no artifact has two items under it.

| unit | story | owns |
|---|---|---|
| 1 | `story:api-merge-push-admitted` | `tests/published_merge.rs`, and `src/published_merge.rs` only if a refusal is found |
| 2 | `story:bot-delete-branch-defaults` | `ess/domains/delivery.yaml`, `src/bot_args.rs`, `src/delivery.rs`, the `Action::Bot` block of `src/main.rs`, `tests/bot_delete_branch.rs` |

`README.md`, `CHANGELOG.md`, `Cargo.toml` and `Cargo.lock` are the coordinator's.

Commits: the opening store commit, one commit per unit or review round, the merge of each unit
into the integration branch, the release-content commit, the closing store commit, and the pull
request's merge into `main` through the bot route. Release 0.1.18 follows the merge.

Reviews: one adversary pass and one security-reviewer pass over the integrated wave.

Pre-flight: `/` 35G free at the start, 1-minute load 24; earlier wave pages measured about 1G
per tree. ESS specification valid with ess 0.59.0 before any change.

## Integration

| field | value |
|---|---|
| branch | `wave/merge-baseline` from `main` `c268705` |
| tree id | `gates-wave-merge-baseline` |
| build dir | each tree's own `target/` |

## Units

| unit | branch | tree id | stage |
|---|---|---|---|
| 1 | `impl/api-merge-push-admitted` | `gates-unit-api-merge` | dispatched |
| 2 | `impl/bot-delete-branch-defaults` | `gates-unit-delete-defaults` | dispatched |
