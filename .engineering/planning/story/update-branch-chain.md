---
format: aep.planning-md/3
id: story:update-branch-chain
kind: story
status: active
title: Admit an earlier GitHub update commit of a pull request updated more than once
summary: verify_update_branch binds an update that is not the final head through the first-parent line to the merged head.
relations:
- derived_from: story:github-update-branch-provenance
scope:
- confidence: cited
  path: src/published_merge.rs
- confidence: cited
  path: tests/published_merge.rs
revision: 5
transitions:
- {from: "draft", to: "proposed", at: "2026-10-07T06:22:45Z", actor: "human:timo", revision: 2}
- {from: "proposed", to: "active", at: "2026-10-07T06:22:45Z", actor: "human:timo", revision: 3}
---
## Problem

A pull request updated twice through GitHub's "update branch" cannot be delivered past. Observed
on `beyond10x/connectors` pull request 126 (read through the GitHub API on 2026-10-07):

| commit | author / committer | parents |
|---|---|---|
| `6a0fa5a5de` update 1 | `b10x-bot[bot]` / GitHub, verified | `4543c82471` (prior head), `fac31be0b2` (base) |
| `f7efee0f9f` update 2 | `b10x-bot[bot]` / GitHub, verified | `6a0fa5a5de`, `055956e3c0` (base) |
| `8d511078ad` merge | `b10x-bot[bot]` / GitHub, verified | `055956e3c0`, `f7efee0f9f` |

The pull request's head is `f7efee0f9f`. `verify_update_branch`
(`src/published_merge.rs:431-435`) requires the merged pull request's `head.sha` to equal the
update commit, so update 1 refuses with "updated pull request summary does not bind this accepted
head", and every bot push whose range contains it fails.

## Contract

- An update commit that is the pull request's final head keeps today's proof unchanged.
- An update commit `U` that is not the final head `H` is admitted only when all of these hold:
  - `U` has two distinct parents, its tree is Git's clean local merge of them
    (`merge-tree --write-tree`), and it passes the existing remote checks (exact bot author,
    exact GitHub committer, verified signature, parents and tree equal to the local object);
  - exactly one completed pull request is associated with `U`; it is same-repository, targets
    the default branch, was merged by the exact bot, and its authenticated head is `H`;
  - `U` lies on the first-parent line from `H`: following first parents from `H` reaches `U`;
  - every commit on that line after `U` up to and including `H` is either an exact direct-bot
    commit, or a GitHub update commit (exact bot author, exact GitHub committer, two distinct
    parents) associated with the same completed pull request and no other;
  - the pull request's merge commit has parents (base, `H`), is published on the default branch,
    and passes the existing terminal-merge proof for that pull request number, including the
    recomputed clean local merge.
- Every other non-bot commit that no merged pull request accounts for still refuses. Each commit
  on the line is also proved on its own by the delivery walk; this check binds `U` to the pull
  request and adds no exemption.
- No policy field or receipt format changes.

## Specification

`ess/` models the signed receipt only. This changes which historical GitHub commits the delivery
walk admits; it adds no entity, field, command or outcome to the specification, which is validated
unchanged with the newest `ess`.

## Acceptance

Tests in `tests/published_merge.rs` (synthetic Git objects, injected authenticated reads, no
network), each failing before the change where it asserts admission:

- `twice_updated_pull_request_admits_the_earlier_update`: the shape above is admitted.
- `earlier_update_with_bot_commit_between_is_admitted`: update 1, a direct-bot commit, update 2.
- `earlier_update_off_the_first_parent_line_refuses`: `U` reachable from `H` only through a base
  parent.
- `earlier_update_tied_to_another_pull_request_refuses`: `U` associated with a different merged
  pull request than the one whose head is `H`.
- `intermediate_non_bot_commit_refuses`: a commit on the line that is neither exact bot nor a
  GitHub update of the same pull request.
- `earlier_update_with_its_own_change_refuses`: `U`'s tree differs from the local merge of its
  parents.
- `intermediate_update_tied_to_another_pull_request_refuses`.

`cargo test --locked`, `cargo fmt --all --check` and
`cargo clippy --all-targets --locked -- -D warnings` pass. Removing the first-parent-line check
and the same-pull-request check each makes a refusal test fail (mutation evidence).

## Scope

- `src/published_merge.rs`: `verify_update_branch` and a helper for the first-parent line.
- `tests/published_merge.rs`: the tests above.
- `CHANGELOG.md` entry (the coordinator's).
