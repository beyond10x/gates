---
format: aep.planning-md/3
id: story:push-range
kind: story
status: draft
title: A push is judged on the commits it adds to the published default branch
summary: Bound the checked range by the authenticated default-branch head where both bot rulesets hold, keep refusing unacceptable commits on the candidate's line, report history through audit
revision: 1
---
# Story: A push is judged on the commits it adds to the published default branch

## Outcome

A repository whose default branch holds a commit the gate would not accept today can still push new
work through the bot, without anyone editing the trusted policy. The gate judges the commits a push
adds on top of the published default branch, read through an authenticated call, and keeps refusing
any unacceptable commit on the candidate's own line. History already on the default branch is
reported by `audit --history` instead of stopping every push.

## Context

Design: `design:push-range`. The owner picked "A: check only new commits" on 2026-11-24.

In 0.1.28 every push re-judges every commit from the enrolled baseline (`src/git.rs:801-946`,
`src/published_merge.rs:54-95`), so one commit on the default branch that the gate does not accept
stops every later push until the policy baseline is moved by hand (36 moves since 2026-10-05). The
latest case: three API-written single-parent commits on spindle's `main` (bot author, not bot
committer) made the push of a new branch refuse with "a commit on the pull request head line is
neither the bot's nor a branch update".

The design limits the new bound to repositories whose default branch is held by both the exact
`b10x-bot-branch-authority` ruleset and a no-bypass required `common / Security and privacy` check
from GitHub Actions; every other repository keeps the baseline range (open question Q1 of the
design).

## Acceptance

- On a qualifying repository (fake API with both rulesets), a default branch holding the spindle
  shape (three single-parent commits, bot author, GitHub committer) lets the pre-push hook and
  `publish` admit a new bot commit on top, with the policy unchanged; the same test fails on 0.1.28.
- On the same repository, a commit on the candidate's own line that is not on the published default
  branch and is not the bot's own commit (a person as author; or GitHub as committer with one parent)
  is refused, and the refusal line names that commit's id. The same holds for such a commit on a side
  branch merged into the candidate.
- Setting a local remote-tracking ref of the default branch to the candidate head changes no
  outcome above: the bound comes only from the authenticated read.
- Each failed bound condition (no required-check ruleset, a bypass actor, another integration or
  context, enforcement not active, default branch excluded, a private repository) keeps today's
  range from the baseline and today's refusal of the spindle shape; one test each.
- A default ref answering 404 or 409 uses the baseline; any other read failure refuses; a bound
  object missing locally refuses naming it before any scan; a bound that does not descend from the
  baseline refuses.
- A new branch on top of a default branch that holds a secret finding is scanned over exactly the new
  commit's units (counting scanner).
- Receipts bind `base`, carry version 2 under domain `b10x.gates.receipt/2`; a 0.1.28 receipt and a
  receipt for another `base` do not verify; ancestor reuse with an older `base` scans exactly the
  uncovered commits.
- `ci` takes its bound from the event: `pull_request.base.sha`, `merge_group.base_sha`, `before` for a
  push of the default branch (the baseline when it is zero or cannot be fetched), the fetched default
  ref for any other push, tag or dispatch.
- `audit --history` reports an inadmissible author and a finding in commits on the default branch
  after the baseline, writes them to the protected report and exits 0.
- Every new guard test fails when its guard is removed; mutation evidence recorded.
- `README.md` (lines 19, 23, 49, 57, 83) and `CHANGELOG.md` say what the range is now.
- `cargo test --locked`, `cargo fmt --all --check`, `cargo clippy --all-targets --locked -- -D
  warnings`.

## Out of Scope

- Editing the trusted policy, moving any baseline, adding or changing rulesets.
- Re-scanning or rewriting history already on any default branch.
- Units of a merge commit computed against more than its first parent.
- Moving consumers' `common.yml` pins; that follows the release.

## Open Questions

- Q1 of `design:push-range`: what repositories without both rulesets get. Default A: today's range.
