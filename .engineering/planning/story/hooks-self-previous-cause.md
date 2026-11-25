---
format: aep.planning-md/3
id: story:hooks-self-previous-cause
kind: story
status: draft
title: Find what left the installed hooks as their own preserved hooks
summary: install 0.1.29 left config.json previous = the hooks' own paths in one repository; the cause is not reproduced
revision: 1
---
## Problem

On 2026-11-25 about 01:50 CET `b10x-gates install` (0.1.29), run once in the main checkout of the
runbook repository, left `<git common dir>/b10x-gates-hooks/config.json` with `previous.<hook>`
set to the hook's own path for all 13 hooks. The first commit after it started about 19,300
processes. The repository's `core.hooksPath` was already the installed directory, by the same
string, before the install, and `.git/hooks` held no hook that is not a sample.

Version 0.1.30 (`fix/hooks-self-previous`) closes the cases the code allowed (another spelling of
`core.hooksPath`; a link into the directory), repairs a configuration that holds such entries on
every install, and makes a hook skip such an entry and refuse a chain deeper than 4. The cause in
this repository is not reproduced: 0.1.29 changed neither `src/hooks.rs` nor `install` (diff
0.1.28..0.1.29 touches `src/git.rs` and `src/published_merge.rs` only), and by the code a
`core.hooksPath` equal to the installed directory keeps the held `previous` and does not read
`.git/hooks`.

## Goal

The state that produced the entries is known, or shown not to be recoverable, and a test holds
the cause.

## Open questions

- What did `<runbook>/.git/b10x-gates-hooks/config.json` hold before the 01:50 install? Only the
  file after it is kept (`config.json.before-previous-reset`, `installed_version` 0.1.29).
- Did `<runbook>/.git/hooks` hold links into the hook directory then? It was empty of non-sample
  hooks afterwards.
- Did an earlier install of an older version leave the entries (a hook run since would have
  started itself)? Which version of `b10x-gates` last installed there before 01:50?
- Is `core.hooksPath` written by something other than `install` (an editor, a plugin, a
  `git worktree` command)?

## Constraints

- No policy file read or changed. No hand edit of a hook configuration outside the owner's repair.

## Acceptance

- The open questions are answered from a record, or marked unanswerable, in this story.
- A test fails on the version that produced the entries and passes on the fix, or the story says
  why none exists.
