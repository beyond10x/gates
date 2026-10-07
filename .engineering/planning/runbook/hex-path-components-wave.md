---
format: aep.planning-md/3
id: runbook:hex-path-components-wave
kind: runbook
status: draft
title: 'Wave: hex-encoded path components'
relations:
- informed_by: story:hex-path-components
- informed_by: story:update-branch-chain
revision: 2
---
## Wave: hex-encoded path components and repeated update-branch commits

Approved with one wave, one pull request and a release. Skill: aep implementing 0.20.1.
Selection: two units, chosen by the request rather than computed. Their surfaces are disjoint by
file (unit 1 `src/scan.rs`, `tests/security.rs`; unit 2 `src/published_merge.rs`,
`tests/published_merge.rs`), cited from each story's Scope section. `README.md`, `CHANGELOG.md`,
`Cargo.toml` and `Cargo.lock` are the coordinator's.

Commits this wave makes: the opening store commit, one commit per unit, the merge of each unit
into the integration branch, the closing store and release-version commit, and the merge of the
pull request into `main` through the bot route. Nothing else.

## Integration

| field | value |
|---|---|
| branch | `wave/hex-path-components` from `main` `0f59bdb` |
| tree id | `gates-hex-paths` |
| tree | `~/.local/state/worktree/trees/b10x/gates/gates-hex-paths` |
| build dir | none: the integration tree does not build |
| scratch | the tree's `target/scratch/` |

## Units

| unit | story | branch | tree id | build dir | scratch | stage |
|---|---|---|---|---|---|---|
| 1 | `story:hex-path-components` | `impl/hex-path-components` | `gates-hex-unit1` | tree `target/` | tree `target/scratch/` | planned |
| 2 | `story:update-branch-chain` | `impl/update-branch-chain` | `gates-update-unit2` | tree `target/` | tree `target/scratch/` | planned |

Agents: `aep:implementor` per unit, then `aep:adversary` per green unit (both are security
checks that run on every organization delivery).

## Disk

`/` had 30G free before the first build. Only the unit trees build. The full gate runs once in
unit 1's tree, detached at the integration head after both units merge, and unit 2's tree is
finished with its cache discarded first. Under 20G free, the wave pauses.

## Gate

`cargo run --locked -- gate`, once, on the integration head, with `B10X_GATES_GITLEAKS` pointing
at the pinned Gitleaks 8.30.1.
