---
format: aep.planning-md/3
id: review-result:ci-fetch-security-1
kind: review-result
status: active
title: 'Security review 1: ci fetches the head by id'
relations:
- reviews: story:ci-fetch-head-by-sha
revision: 1
---
verdict: CONFIRMED, 2 notes (INFEASIBLE)
cases: executed 24→27, red 2
origin: introduced 1, pre-existing 0, undecided 1

Unit diff c7343c2..ce90661. Cases in `tests/security_ci_fetch.rs`.

- Note: a pull request head id naming an annotated tag object was peeled to its commit, so
  the candidate was not the event's id. GitHub always sends a commit id. Fixed in 09f788c:
  the pull request head must be a commit object.
- Note: the credential check compared lossy-decoded text, so a token split by an invalid
  byte was printed. Fixed in 09f788c: git's raw output is reduced to the token's alphabet
  before the check, and any 12-byte run of the token withholds the message.
- Held: refspecs write no ref; the token reaches git only through the environment; event
  fields are checked before any git call; with no trusted matchers nothing is shown.
- Outside the diff, pre-existing: a push or dispatch head naming a tag object is peeled the
  same way.
