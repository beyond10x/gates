---
format: aep.planning-md/3
id: story:ci-fetch-head-by-sha
kind: story
status: draft
title: ci fetches the pull request head commit by its id and names the refspec git refused
summary: A pull request whose refs/pull/<n>/head GitHub does not advertise fails ci with no cause; fetch the head by id and name the refused refspec and git's message.
scope:
- confidence: inferred
  path: README.md
- confidence: inferred
  path: src/delivery.rs
- confidence: inferred
  path: tests/ci_policy.rs
revision: 2
---
## Problem

On 2026-10-20 `common / Security and privacy` failed on beyond10x/loom pull request 93 (head
`24ff8f2`) three times, run 39432692696, with only `b10x-gates: candidate object fetch failed`
about 0.5 s into `ci`. Observed from this repository the same day:

- `git ls-remote https://github.com/beyond10x/loom` advertised `refs/pull/93/merge` and
  `refs/heads/record/w2-u6-escape` at `24ff8f2`, and no `refs/pull/93/head`
  (`refs/pull/90/head` to `refs/pull/92/head` were there). Why GitHub had not written it is not
  known.
- The fetch `ci` makes, run anonymously into an empty bare repository,
  `git fetch <loom> refs/pull/93/head <baseline>`, failed with
  `fatal: couldn't find remote ref refs/pull/93/head`, exit 128. The baseline was not the cause:
  it exists and is an ancestor of loom's `main`.
- The same fetch naming the head commit by its id, `git fetch <loom> 24ff8f2… <baseline>`,
  exited 0.

`ci_candidate_from` (`src/delivery.rs`) fetches `refs/pull/<n>/head` for a pull request event and
discards git's standard error, so the refusal names neither the refspec nor git's message.

## Proposal

- For a pull request event, fetch `pull_request.head.sha` by its id; keep `refs/pull/<n>/head`
  only as a fallback if the id cannot be fetched, and bind the candidate to the id either way.
- When the fetch fails, name each refspec git refused and git's own message line, after the
  private-rule matchers (as API refusals already are), never the token.

## Acceptance

- A test double for the remote that does not advertise `refs/pull/<n>/head` but serves the head
  commit: `ci` fetches it and scans; the same test is red at the current code.
- A failed fetch names the refspec git refused (`refs/pull/<n>/head` or the baseline id) and
  git's message line; a message matching a private rule is withheld and the refspec still named.
- Fork pull requests: whether GitHub serves a fork's head commit by id from the base repository
  is not verified (only the same-repository case above was). The story either verifies it
  against a public fork pull request, read-only, or keeps the `refs/pull/<n>/head` fallback for
  `isCrossRepository` pull requests and says so in the README.
