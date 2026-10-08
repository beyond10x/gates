---
format: aep.planning-md/3
id: runbook:refusal-causes-wave
kind: runbook
status: draft
title: 'Wave: delivery refusals name their cause and route'
relations:
- informed_by: story:bot-refusal-causes
- informed_by: story:bot-supported-routes
revision: 2
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

| unit | story | branch | commits | tree id | stage |
|---|---|---|---|---|---|
| 1 | `story:bot-refusal-causes` | `impl/bot-refusal-causes` | `33cb228` | `gates-unit-causes` | merged `a641169`; tree finished, archived |
| 2 | `story:bot-supported-routes` | `impl/bot-supported-routes` | `1d04735` | `gates-unit-routes` | merged `3bf4987`; tree finished, archived |
| fix 1 | both | `review/refusal-causes` | `46778b5` | `gates-review-causes` | merged `dd18130`; tree finished, archived |

`git merge-tree --write-tree --merge-base=2671c7d 33cb228 1d04735` wrote a clean tree before the
first merge. Measured build: about 1G per tree (974M and 945M).

## Reviews

| pass | findings | outcome |
|---|---|---|
| `review-result:refusal-causes-security-1` | 3 introduced (push `--m` is `--mirror`; two false "nothing staged"), 3 pre-existing guard bypasses (`-nm`, `--no-verif`, `--receive-pack`/`--upload-pack`/`--e=`), 2 INFEASIBLE | all 6 fixed in `46778b5` with the reviewer's 10 tests; repository-config deletion documented in the README as outside an argument check; a 2xx non-JSON body is now a success |

## Gate

Package gate on `9ee5a9b` (release content): `cargo fmt --all --check` 0, `cargo clippy -p
b10x-gates --all-targets --locked -- -D warnings` 0, `cargo test -p b10x-gates --locked` 259
passed, 6 ignored, 265 listed. The closing store commit changes only `.engineering/`.
