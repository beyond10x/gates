---
format: aep.planning-md/3
id: runbook:hex-path-components-wave
kind: runbook
status: draft
title: 'Wave: hex-encoded path components'
relations:
- informed_by: story:hex-path-components
- informed_by: story:update-branch-chain
revision: 3
---
## Wave: hex-encoded path components and repeated update-branch commits

Approved with one wave, one pull request and a release. Skill: aep implementing 0.20.1.
Selection: two units, chosen by the request rather than computed. Their surfaces are disjoint by
file (unit 1 `src/scan.rs`, `tests/security.rs`; unit 2 `src/published_merge.rs`,
`tests/published_merge.rs`), cited from each story's Scope section. `README.md`, `CHANGELOG.md`,
`Cargo.toml` and `Cargo.lock` are the coordinator's.

Commits this wave makes: the opening store commit, the unit commits (one per implementor or
adversary round), the merge of each unit into the integration branch, the release-content commit,
the closing store commit, and the merge of the pull request into `main` through the bot route.

## Integration

| field | value |
|---|---|
| branch | `wave/hex-path-components` from `main` `0f59bdb` |
| tree id | `gates-hex-paths` |
| tree | `~/.local/state/worktree/trees/b10x/gates/gates-hex-paths` |
| build dir | none: the integration tree does not build |
| scratch | the tree's `target/scratch/` |
| merges | unit 2 `393876a`, unit 1 `1079556`; release content `e397cb6` |

## Units

| unit | story | branch | commits | tree id | stage |
|---|---|---|---|---|---|
| 1 | `story:hex-path-components` | `impl/hex-path-components` | `7e2dccb`, `a9413a7`, `450c821` | `gates-hex-unit1` | merged; tree holds the gate build |
| 2 | `story:update-branch-chain` | `impl/update-branch-chain` | `9b05c62`, `208c296` | `gates-update-unit2` | merged; tree finished, archived, removed |

## Reviews

| unit | pass | findings | outcome |
|---|---|---|---|
| 1 | `review-result:hex-path-components-adversary-1` | 2 introduced: quadratic lookups (CONFIRMED), relative array refused (INFEASIBLE) | fixed in `a9413a7`; refusal kept on purpose and asserted |
| 1 | `review-result:hex-path-components-adversary-2` | 1 introduced: per-line list memory; 1 pre-existing: ignored soft-wrap test | fixed in `450c821`, reviewed by the coordinator, no third pass |
| 2 | `review-result:update-branch-chain-adversary-1` | 2 weak-test (CONFIRMED), 1 reversed-parent shape (INFEASIBLE) | covered by 9 adversary cases in `208c296`; shape left |

Unit 2's implementor stopped red on `unsupported_update_branch_shapes_refuse`, which asserted
refusal for the multiple-update shape this wave admits. The two shapes moved to an admission test;
squash, rebase-shaped and advanced-final-base merges still refuse.

## Gate

`cargo run --locked -- gate` on `e397cb6` in unit 1's tree: exit 0; 223 passed, 6 ignored;
`cargo test -- --list` lists 229 in that tree.

## Cost per agent (as the harness reported them)

| agent | tokens | tool uses | wall |
|---|---|---|---|
| implementor unit 1, round 1 / 2 / 3 | 136,025 / 168,839 / 201,411 | 83 / 30 / 26 | 813 s / 1,044 s / 223 s |
| implementor unit 2 | 167,680 | 65 | 790 s |
| adversary unit 1, pass 1 / 2 | 175,331 / 242,077 | 62 / 40 | 1,366 s / 844 s |
| adversary unit 2 (and findings re-serialisation) | 191,475 (194,790) | 61 (0) | 1,061 s (21 s) |

## Lesson

Creating `target/scratch/` before cargo's first build leaves `target/` without cargo's
`CACHEDIR.TAG`, and `worktree discard-cache` then keeps the whole profile as "not recognised
cache". Unit 2's tree needed the standard tag written before its 745 MiB profile could be
discarded. Create scratch after the first build, or under a directory cargo does not own.
