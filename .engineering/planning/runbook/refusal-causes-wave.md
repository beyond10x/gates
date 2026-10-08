---
format: aep.planning-md/3
id: runbook:refusal-causes-wave
kind: runbook
status: draft
title: 'Wave: delivery refusals name their cause and route'
relations:
- informed_by: story:bot-refusal-causes
- informed_by: story:bot-supported-routes
revision: 1
---
## Wave: delivery refusals name their cause and their route

Non-interactive run: the request came as a dispatch with no operator turn; the stage-1 stop is
recorded as `approval-record:refusal-causes-wave-proposal`. Skill: aep implementing 0.21.2.
Selection: two units, chosen by the request. `aep plan artifact waves --status draft` printed:

```
wave 1
  story:bot-refusal-causes
wave 2
  story:bot-supported-routes
collision: story:bot-refusal-causes story:bot-supported-routes src/main.rs
2 wave(s), 1 collision(s), 0 unassessed
```

The collision is split by function: unit 1 owns the `Action::Api` and `Action::Gh` blocks of
`src/main.rs`, unit 2 owns the `Action::Bot` block. Before the first unit merges the coordinator
runs `git merge-tree --write-tree` on the two unit heads. `README.md`, `CHANGELOG.md`,
`Cargo.toml`, `Cargo.lock` and the design note `design:bot-verbs` are the coordinator's.

Commits this wave makes: the opening store commit, the unit commits (one per implementor or
adversary round), the merge of each unit into the integration branch, the release-content commit,
the closing store commit, and the merge of the pull request into `main` through the bot route.

Pre-flight: `/` 60G free at the start; no earlier gates trees on disk; no measured build for this
repository is recorded, earlier pages record sub-1G trees; ess spec validated unchanged with ess
0.56.0. The primary checkout carries uncommitted 2026-09-22 edits that `main` supersedes; they
are archived as a patch and left in place, and no unit touches the primary checkout.

## Integration

| field | value |
|---|---|
| branch | `wave/refusal-causes` from `main` `d53a081` |
| tree id | `gates-refusal-causes` |
| build dir | the tree's own `target/`; used only for the package gate before the push |
| scratch | the tree's `target/scratch/` |

## Units

| unit | story | branch | tree id | build dir | scratch | stage |
|---|---|---|---|---|---|---|
| 1 | `story:bot-refusal-causes` | `impl/bot-refusal-causes` | `gates-unit-causes` | tree `target/` | tree `target/scratch/` | planned |
| 2 | `story:bot-supported-routes` | `impl/bot-supported-routes` | `gates-unit-routes` | tree `target/` | tree `target/scratch/` | planned |

## Reviews

Unit 1 changes what leaves the process on a failed API call: one security-reviewer pass.
Unit 2 adds a check that runs before a credential is minted: covered by the same pass.
