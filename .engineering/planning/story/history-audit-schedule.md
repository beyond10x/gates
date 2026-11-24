---
format: aep.planning-md/3
id: story:history-audit-schedule
kind: story
status: draft
title: A scheduled history audit turns red on any unacceptable commit on a default branch
summary: audit --history over baseline..default tip, daily, for the list the policy yields; per-repository annotation that push-range reads as freshness; issue naming commit and rule ids only
relations:
- depends_on: story:ci-committer-pr-bound
revision: 3
---
# Story: A scheduled history audit turns red on any unacceptable commit on a default branch

## Outcome

Every day, a run that candidate repositories cannot edit audits each qualifying repository's
default branch from its baseline. It fails loudly when a commit there breaks a rule or the
authorship rules. Its repository list comes from the policy, not from a file the bot edits, and each
repository's result is written as an annotation that `story:push-range` reads: a repository whose
audit is not green and younger than 48 hours falls back to the baseline range. So an audit that is
muted, emptied or stopped becomes a fallback, not silence.

Story 3 of `design:push-range` (revision 3), findings G6 and N3. Its first green run is one of the
owner's conditions for the first entry on the trusted list.

## Context

Today `audit` reports only the baseline tree (`src/main.rs:658-666`, `src/git.rs:982-991`). Nothing
runs it on a schedule. A red default-branch check blocks nothing.

The second adversary review (N3) found that revision 2's schedule could be muted by the bot:

- the workflow and its repository list live in this repository, and a bot pull request that passes
  the required checks can drop a repository from the list or add `continue-on-error`;
- GitHub notifies the user who last edited the `cron` line of a failed scheduled run, which is then
  the bot, not the owner (inferred from GitHub's documentation, not verified);
- the App can close the issue.

## Acceptance

- **The command.** `b10x-gates audit --history --output <protected-report>`:
  - covers every commit in `rev-list <T> --not <baseline>`, where `T` is the default branch read
    through an authenticated call;
  - reports the author, committer and rule findings;
  - writes details only to the protected report;
  - prints counts and coordinates (repository, commit id, rule), never matched text;
  - prints one line `::notice title=b10x-gates audit::repo=<owner>/<repo> base=<baseline id> head=<T id> findings=<n> policy=<private policy digest>`;
  - exits non-zero when anything is found.
  - Tests: a finding, an inadmissible author and an inadmissible committer each exit non-zero and
    print `findings=` greater than 0. A clean history exits 0 with `findings=0`.
- **The list comes from the policy.** `b10x-gates audit --list` prints the enrolled repositories that
  are public and qualify (the rulesets of the design's precondition), one per line, from the policy
  secret.
  - No file in this repository names the audited repositories.
  - A test: a policy with a public qualifying repository, a private one and one without the rulesets
    lists only the first.
- **The schedule.** `.github/workflows/history-audit.yml` in this repository:
  - runs daily on `schedule` and on `workflow_dispatch`;
  - pins its actions and declares its permissions;
  - uses the organization policy secret;
  - derives its matrix from `audit --list` in a first job, then runs one job per repository named
    `history audit: <owner>/<repo>`;
  - fetches each repository's objects as data into a fresh bare store, as `ci` does;
  - runs the released binary at a fixed checksum;
  - has no `continue-on-error`.
- **Who sees the red.**
  - A finding fails the job, and with it the run.
  - The run opens or updates one issue per repository, titled `history audit: <owner>/<repo>`,
    naming commit ids and rule ids only. The next green run for that repository closes it.
  - The control is freshness, not notification: `story:push-range` makes a repository whose audit job
    is red, missing or older than 48 hours fall back, and every session's push prints the reason
    line `history audit for <owner>/<repo> is not green or older than 48 hours`.
- **Clean output.** No private term, path or matched text reaches the log, the annotation or the
  issue. A test feeds a finding with a private literal and asserts none of them holds it.
- **Gates.** Every new guard test fails when its guard is removed, with mutation evidence recorded.
  `cargo test --locked`, `cargo fmt --all --check` and `cargo clippy --all-targets --locked -- -D
  warnings` pass.

## Out of Scope

- Changing what any rule matches.
- Reading the audit's result for the local bound (`story:push-range`).
- Repositories that do not qualify. Their local pushes still judge the whole history.
