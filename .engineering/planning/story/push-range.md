---
format: aep.planning-md/3
id: story:push-range
kind: story
status: draft
title: A push is judged on the commits it adds above a default-branch commit the trusted check proved
summary: 'Trust a default-branch commit only by its check''s provenance: canonical allowlisted caller, trusted pin, every annotated default-branch push run green with base=baseline, reused=false and the local policy digest, a fresh green audit; else the baseline with a reason; receipts version 2; read cache'
relations:
- depends_on: story:ci-committer-pr-bound
- informed_by: story:history-audit-schedule
revision: 5
---
# Story: A push is judged on the commits it adds above a default-branch commit the trusted check proved

## Outcome

A repository can push new work through the bot without anyone editing the trusted policy when:

- its default branch holds a GitHub-written commit that the local merge proof cannot prove; and
- the trusted common check proved that branch clean, by a green push run of the default branch
  whose range annotation says it scanned the baseline range without reusing a receipt, under the
  local policy; and
- the repository's history audit is green and younger than 48 hours.

An unacceptable commit on the candidate's own line is still refused by id. A repository that does
not qualify behaves exactly as in 0.1.28 and prints one line saying why.

Story 2 of `design:push-range` (revision 3). Depends on `story:ci-committer-pr-bound` being released
in the binary the trusted `common.yml` downloads. Ships inert: while the trusted list is empty,
every repository selects the baseline.

## Context

In 0.1.28 every push re-judges every commit since the enrolled baseline, and one commit the local
proof rejects stops the repository until its baseline is moved by hand. Spindle's case: three
single-parent commits by the bot, committed by GitHub, refused with "a commit on the pull request
head line is neither the bot's nor a branch update".

The design trusts a default-branch commit `B` only by the provenance of its check run. The owner
decided Q1 = A on 2026-11-24. The second adversary review added the range annotation (N1, N2, N9),
the allowlist shape (N6), audit freshness (N3) and a corrected read bound with a cache (N7).

## Acceptance

- **Spindle case.** On a fake API where the default branch qualifies (rulesets, a check run from
  the canonical caller at a trusted pin, a green push run annotated `ref=refs/heads/<default>
  base=<baseline> reused=false` with the local policy digest, a fresh green audit), the default
  branch holds the spindle shape, and the policy is unchanged:
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
  - a caller whose job has any key besides `uses` and `secrets` (one test each for `with`, `if`,
    `name`, `needs`, `strategy`, `concurrency`, `permissions`), a second job, another job id, or a
    `secrets:` value that is not `${{ secrets.<same name> }}` (N6);
  - only a tag or merge-group run succeeded;
  - **a tag named like the default branch (N1):** a red push run annotated `refs/heads/<default>` and
    a green run annotated `refs/tags/<default>` on the same commit, the tag already deleted;
  - **two annotated default-branch push runs on the same commit, one green and one red** (newest
    attempt of each);
  - an annotated default-branch run that is still pending;
  - a check run with no range annotation;
  - an annotation with `reused=true` (N2), or with `base` other than the local baseline;
  - an annotation whose policy digest differs from the local policy's (N9), with its own reason line;
  - **audit freshness (N3):** no audit run; an audit run older than 48 hours; a red audit job for the
    repository; an audit run whose workflow blob differs from the one at a trusted Gates commit; an
    audit annotation whose `head` is not an ancestor of `B`;
  - a private repository;
  - a 404, 409, 403 or 5xx on any read;
  - a trusted list missing or empty;
  - no App credential for `check`.
- **The reason line.** On fallback, the session sees exactly one line `b10x-gates: bound=baseline for
  <owner>/<repo>: <reason>`. For an untrusted pin it names the pin to move and the newest trusted id.
  The reasons are those listed in the design.
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
- **Read count (N7).** On a qualifying repository, a test counts the reads of one push on a fake API
  and asserts at most `3 + r + 4 + Σ (1 + 2·k_C)` plus one per extra page: 3 for the repository, its
  branch rules and the default ref; `r` for the rulesets the rules name; at most 4 for the audit run,
  its job, its annotation and its workflow blob; and for each candidate `C` one check-run list plus a
  workflow run and an annotation read for each of its `k_C` check runs with the check's name.
- **Verdict cache (N7).** A verdict for (repository, `C`, trusted-list digest, policy digest) is cached
  in an owner-only file for 5 minutes.
  - A second push within 5 minutes with no newer run on `T` makes one read of `T`'s check runs and no
    other provenance read.
  - A newer run on `T` invalidates the entry; an entry older than 5 minutes is not used; a missing or
    unreadable cache reads again.
- **Documentation.** `README.md` (lines 19, 23, 49, 57, 83, and the release procedure: adding a
  Gates commit to the trusted list) and `CHANGELOG.md` say what the range is now.
- **Gates.** Mutation evidence is recorded for every guard. `cargo test --locked`, `cargo fmt --all
  --check` and `cargo clippy --all-targets --locked -- -D warnings` pass.

## Out of Scope

- Editing the trusted policy or the trusted list (the owner's), and moving any baseline.
- `ci` changes and the range annotation (`story:ci-committer-pr-bound`), the scheduled audit and its
  annotation (`story:history-audit-schedule`), writes to the policy repository
  (`story:api-policy-repository-writes`), and consumer pins (`story:consumer-pins-trusted`).

## Open Questions

- Q2, Q3 and Q4 of `design:push-range`: the App's secrets permission, the App's installation on the
  policy repository, and what the boundary is for keys and the owner's login.
