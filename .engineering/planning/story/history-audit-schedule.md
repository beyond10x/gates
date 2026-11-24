---
format: aep.planning-md/3
id: story:history-audit-schedule
kind: story
status: draft
title: A scheduled history audit turns red on any unacceptable commit on a default branch
summary: audit --history over baseline..default tip, run daily from this repository, failing the run and opening an issue naming commit and rule ids only
relations:
- depends_on: story:ci-committer-pr-bound
revision: 1
---
# Story: A scheduled history audit turns red on any unacceptable commit on a default branch

## Outcome

Every day, a run that candidate repositories cannot edit audits each qualifying repository's
default branch from its baseline. It fails loudly when a commit there breaks a rule or the
authorship rules. A commit can no longer sit on a default branch unreported.

Story 3 of `design:push-range` (revision 2), finding G6. Its first green run is the owner's
condition for the first entry on the trusted list.

## Context

Today `audit` reports only the baseline tree (`src/main.rs:658-666`, `src/git.rs:982-991`). Nothing
runs it on a schedule. A red default-branch check blocks nothing.

## Acceptance

- **The command.** `b10x-gates audit --history --output <protected-report>`:
  - covers every commit in `rev-list <T> --not <baseline>`, where `T` is the default branch read
    through an authenticated call;
  - reports the author, committer and rule findings;
  - writes details only to the protected report;
  - prints counts and coordinates (repository, commit id, rule), never matched text;
  - exits non-zero when anything is found.
  - Tests: a finding, an inadmissible author and an inadmissible committer each exit non-zero. A
    clean history exits 0.
- **The schedule.** `.github/workflows/history-audit.yml` in this repository:
  - runs daily on `schedule` and on `workflow_dispatch`;
  - pins its actions and declares its permissions;
  - uses the organization policy secret;
  - runs one matrix job per repository named in a list kept in this repository;
  - fetches each repository's objects as data into a fresh bare store, as `ci` does;
  - runs the released binary at a fixed checksum.
- **Who sees the red.**
  - A finding fails the job, and with it the run.
  - The run opens or updates one issue per repository, titled `history audit: <owner>/<repo>`,
    naming commit ids and rule ids only.
  - The issue is closed by the next green run for that repository.
  - The owner is notified of the failed scheduled run (as the actor of the schedule) and through the
    issue.
- **Clean output.** No private term, path or matched text reaches the log or the issue. A test
  feeds a finding with a private literal and asserts the issue text and the log do not hold it.

## Out of Scope

- Changing what any rule matches.
- Repositories that do not qualify. Their local pushes still judge the whole history.
