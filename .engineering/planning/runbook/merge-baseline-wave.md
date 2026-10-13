---
format: aep.planning-md/3
id: runbook:merge-baseline-wave
kind: runbook
status: draft
title: 'Wave: API merges need no baseline move; delete-branch deletes merged wave branches'
relations:
- informed_by: story:api-merge-push-admitted
- informed_by: story:bot-delete-branch-defaults
revision: 2
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

## Units

| unit | branch | commits | tree id | stage |
|---|---|---|---|---|
| 1 | `impl/api-merge-push-admitted` | `d39db66` | `gates-unit-api-merge` | merged `9fa978d`; tree finished, archived |
| 2 | `impl/bot-delete-branch-defaults` | `185e1b7` | `gates-unit-delete-defaults` | merged `e588927`; tree finished, archived |
| adversary 1 | `review/merge-baseline-adversary` | `4589441` | `gates-review-adversary-mb` | merged into the fix round; tree finished, archived |
| security 1 | `review/merge-baseline-security` | `b42d3d1` | `gates-review-security-mb` | merged into the fix round; tree finished, archived |
| fix 1 | `fix/merge-baseline` | `89efff6` | `gates-fix-mb` | merged `1bb83d8`; tree finished, archived |

Unit 1 verdict: admitted. The pre-push proof and `check` admit a branch and an annotated tag cut
from a bot API merge one past the baseline, on public and private repositories, with no source
change. Unit 2 cause, observed read-only on this repository: every branch lists
`protected: true` while `/branches/main/protection` answers 404 "Branch not protected".

## Reviews

| pass | findings | outcome |
|---|---|---|
| `review-result:merge-baseline-adversary-1` | 1 note: a shallow repository with installed hooks reported as uninstalled | fixed in `89efff6` |
| `review-result:merge-baseline-security-1` | 1 warning: rulesets judged by type only, so a second ruleset of admitted types was passed | fixed in `89efff6` |

Release content: `92fc61d` (0.1.18). Measured build: about 1.1G per tree (1129 MiB discarded at
unit 2's finish).
