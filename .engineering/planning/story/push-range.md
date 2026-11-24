---
format: aep.planning-md/3
id: story:push-range
kind: story
status: draft
title: A push is judged on the commits it adds above a default-branch commit the trusted check proved
summary: Trust a default-branch commit only by the provenance of its check run (canonical caller, trusted Gates pin, baseline-range push run); otherwise the baseline range with a one-line reason; receipts version 2
relations:
- depends_on: story:ci-committer-pr-bound
revision: 3
---
# Story: A push is judged on the commits it adds above a default-branch commit the trusted check proved

## Outcome

A repository can push new work through the bot without anyone editing the trusted policy when:

- its default branch holds a GitHub-written commit that the local merge proof cannot prove; and
- the trusted common check proved that branch clean.

An unacceptable commit on the candidate's own line is still refused by id. A repository that does
not qualify behaves exactly as in 0.1.28 and prints one line saying why.

Story 2 of `design:push-range` (revision 2). Depends on `story:ci-committer-pr-bound` being released
in the binary the trusted `common.yml` downloads.

## Context

In 0.1.28 every push re-judges every commit since the enrolled baseline, and one commit the local
proof rejects stops the repository until its baseline is moved by hand. Spindle's case: three
single-parent commits by the bot, committed by GitHub, refused with "a commit on the pull request
head line is neither the bot's nor a branch update".

Revision 2 trusts a default-branch commit `B` only by the provenance of its check run. The owner
decided Q1 = A on 2026-11-24.

## Acceptance

- **Spindle case.** On a fake API where the default branch qualifies (rulesets, a check run from
  the canonical caller at a trusted pin, push of the default branch, success), the default branch
  holds the spindle shape, and the policy is unchanged:
  - pre-push and `publish` admit a new bot commit on top;
  - the same test fails on 0.1.28.
- **Refused by id.**
  - A commit on the candidate's line, not under `B` and not the bot's own, is refused. The line names
    its id. Two cases: a person as author, and a GitHub-committed single parent.
  - A bot merge of a side branch carrying such a commit is refused naming it.
- **No local ref decides.** Setting the local remote-tracking ref of the default branch to the
  candidate head changes no outcome.
- **Baseline selected, with today's refusal of the spindle shape, one test each:**
  - no required common check;
  - `bypass_actors` absent;
  - a bypass actor present;
  - another integration or context;
  - an include or exclude pattern that leaves the default branch out;
  - two rulesets with the same check where only the one carrying the check has a bypass;
  - a check run with that name from another workflow path;
  - a check run from another app;
  - a pin not on the trusted list;
  - two referenced workflows;
  - a caller with a second job, another job id, a `with:` or a `secrets:` value that is not
    `${{ secrets.<same name> }}`;
  - only a tag or merge-group run succeeded;
  - a tag named like the default branch;
  - a private repository;
  - a 404, 409, 403 or 5xx on any read;
  - a trusted list missing or empty;
  - no App credential for `check`.
- **The reason line.** On fallback, the session sees exactly one line `b10x-gates: bound=baseline for
  <owner>/<repo>: <reason>`. For an untrusted pin it names the pin to move and the newest trusted id.
- **Pending tip.** With the tip's run pending and its parent qualified, `B` is the parent, and the
  commits between are proved as today.
- **Fetching `B`.** When `B` is absent locally, it is fetched by id. A failed fetch selects the
  baseline. Neither writes a ref.
- **Rewritten branch.** A default branch rewritten past the baseline selects the baseline, and does
  not refuse every push.
- **Second read.** A rewind between the first and second read of the tip repeats the walk with the
  baseline.
- **Receipts.** Receipts carry version 2, domain `b10x.gates.receipt/2` and `base`.
  - A receipt whose `base` is an ancestor of the current bound and descends from the baseline is
    accepted after a full rebuild with its own `base`. `publish` after the default branch moved keeps
    the `check` receipt.
  - A 0.1.28 receipt does not verify.
  - A version 2 payload signed under domain 1 does not verify.
  - Ancestor reuse scans exactly the uncovered commits.
- **Read count.** On a qualifying repository, one push makes at most 6 + 3 × (candidates walked) API
  reads, counted in a test.
- **Documentation.** `README.md` (lines 19, 23, 49, 57, 83, and the release procedure: adding a
  Gates commit to the trusted list) and `CHANGELOG.md` say what the range is now.
- **Gates.** Mutation evidence is recorded for every guard. `cargo test --locked`, `cargo fmt --all
  --check` and `cargo clippy --all-targets --locked -- -D warnings` pass.

## Out of Scope

- Editing the trusted policy or the trusted list (the owner's), and moving any baseline.
- `ci` changes (`story:ci-committer-pr-bound`), the scheduled audit
  (`story:history-audit-schedule`), and consumer pins (`story:consumer-pins-trusted`).

## Open Questions

- Q2 and Q3 of `design:push-range`: the App's secrets permission, and its installation on the policy
  repository.
