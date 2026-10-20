---
format: aep.planning-md/3
id: runbook:protection-writes-wave
kind: runbook
status: draft
title: 'Wave: the bot cannot write rulesets or branch protection'
relations:
- informed_by: story:api-protection-writes
revision: 1
---
## Wave: the bot cannot write rulesets or branch protection

Stage 1 proposal, sent to the monitoring session `b10x-chef-orchestrator`, which decides for the
operator on this work ("as you wish, you are the orchestrator", 2026-10-20). The wave runs after
its approval; the approval is recorded as an `approval-record` before the first dispatch.
Skill: aep implementing 0.23.2. aep 0.74.0.

Selection: one unit, chosen by the request. `aep plan artifact waves --status proposed` printed:

```
wave 1
  story:api-protection-writes (inferred)
1 wave(s), 0 collision(s), 0 unassessed
```

N is one: the request names one story. The plan-critic panel is skipped: the story derives from
no artifact in this store, so no artifact has two items under it.

Scope beyond the request's draft, taken by the coordinator: the draft names `b10x-gates api`
REST paths only. The story adds `POST /graphql` with a ruleset or branch-protection mutation,
`b10x-gates gh -- api`, and the path spellings GitHub normalises, because each reaches the same
write with the same token.

| unit | story | owns |
|---|---|---|
| 1 | `story:api-protection-writes` | the `Action::Api` and `Action::Gh` blocks of `src/main.rs`, `src/delivery.rs`, `tests/api_protection_writes.rs`, `ess/domains/delivery.yaml` |

`README.md`, `CHANGELOG.md`, `Cargo.toml` and `Cargo.lock` are the coordinator's.

Agents: `aep:implementor` for the unit; `aep:adversary` and `aep:security-reviewer` over the
integrated unit, at most two attack rounds.

Commits this wave makes: the opening store commit, one commit per implementor or review round,
the merge of each into the integration branch, the release-content commit (0.1.22), the closing
store commit, the pull request into `main` and its merge through the bot route. Release 0.1.22
follows the merge through this repository's process: bare annotated tag, musl binary validated
with `scan-artifact`, `SHA256SUMS`, GitHub release by the bot, assets downloaded and verified.
Nothing else.

Pre-flight: `/` 48G free (`df -h /`, 2026-10-20), 1-minute load 69; earlier wave pages measured
about 1.1G per tree. ESS specification `gates v1 — 3 file(s), valid` with ess 0.60.0. The primary
checkout is 113 commits behind `origin/main` and carries another session's uncommitted edits to
`src/git.rs`, `src/published_merge.rs` and `tests/published_merge.rs`; no unit touches it, and
every tree starts from `origin/main`. Builds run one at a time, under a watch that stops a build
below 20G free; no build starts below 25G free.

## Integration

| field | value |
|---|---|
| branch | `wave/ruleset-write-refusal` from `main` `04b0ddb` |
| tree id | `gates-ruleset-writes` |
| build dir | the tree's own `target/` |
| scratch | `~/.cache/gates-wave-ruleset-writes/` |

## Units

| unit | branch | commits | tree id | stage |
|---|---|---|---|---|
| 1 | `impl/api-protection-writes` | | `gates-unit-protection-writes` | proposed |
