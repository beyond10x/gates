---
format: aep.planning-md/3
id: story:ci-committer-pr-bound
kind: story
status: draft
title: ci admits committers exactly and bounds pull requests by the fetched default branch
summary: Committer admitted only as the exact bot or exact GitHub; every event but a default-branch push bounded by the fetched default branch; default-branch push keeps the baseline range
revision: 1
---
# Story: `ci` admits committers exactly and bounds pull requests by the fetched default branch

## Outcome

The common check is fit to be trusted on the default branch:

- It refuses a commit whose committer is neither exactly the bot nor exactly GitHub.
- It judges a pull request, a merge group, a tag and any branch other than the default against the
  default branch it fetches itself, never against a base the event names.
- On a push of the default branch it keeps checking everything since the baseline.

Story 1 of `design:push-range` (revision 2); `story:push-range` builds on it.

## Context

The adversary review of revision 1 (findings G2, G3, G4) showed:

- `ci` has never checked the committer (`src/git.rs:48-62`).
- A pull-request range bounded by `pull_request.base.sha` lets a commit land under a green check that
  never covered it (stacked pull requests, base changed after the check).
- Narrowing the default-branch run would stop its green check from covering that branch's history.

A read-only count on 2026-11-24 over 2,179 commits since the baselines of six repositories found no
committer other than exactly the bot or exactly GitHub (design, "G4 on existing history").

## Acceptance

- **Committer rule.** `ci` refuses a commit whose committer is not exactly `b10x-bot[bot]
  <316511680+b10x-bot[bot]@users.noreply.github.com>` or exactly `GitHub <noreply@github.com>`. Name
  and email are compared as raw bytes, with no mailmap. It is a finding `commit-committer` at
  `commit:<oid>` with the raw commit object's SHA-256, and the refusal line names the commit id.
  - A test with the bot email and a person's name is refused.
  - A test with the bot name and a person's email is refused.
  - A spindle-shaped commit (bot author, GitHub committer, one parent) is admitted.
- **Exception.** An exact policy exception for that repository, rule, location and digest admits the
  commit. The same exception with another digest does not.
- **Pull request bound.** `ci` on `pull_request(_target)` checks `rev-list <head> --not <D>`, where
  `D` is `refs/heads/<repository.default_branch>` fetched by name from the repository in the same
  fetch.
  - With a test event whose `base.sha` is the head's parent and whose `D` lies further back, the
    commits between them are scanned.
  - A stacked pull request F→E scans E's commits that are not on `D`.
  - The same holds for `merge_group`, tag, other-branch and `workflow_dispatch` events.
  - When there is no `D` or its fetch fails, the baseline is used.
- **Default-branch push.** `ci` on a push of the default branch checks `<baseline>..<head>`, as
  0.1.28 does. A test proves `before` is not used.
- **Count before release.** A read-only count over all qualifying consumers lists every commit since
  its baseline that the committer rule refuses. Each hit has an exception prepared for the owner, or
  the list is empty.
- **Gates.** Every new guard test fails when its guard is removed, with mutation evidence recorded.
  `cargo test --locked`, `cargo fmt --all --check` and `cargo clippy --all-targets --locked -- -D
  warnings` pass.

## Out of Scope

- Local push paths, receipts, the trusted bound (`story:push-range`).
- Moving consumer pins (`story:consumer-pins-trusted`).
