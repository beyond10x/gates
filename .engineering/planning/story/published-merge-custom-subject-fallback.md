---
format: aep.planning-md/3
id: story:published-merge-custom-subject-fallback
kind: story
status: draft
title: Prove a custom-subject GitHub merge while its association list answers 5xx
summary: 'Caveat left by 0.1.23: a merge whose subject names no pull request relies on retries alone.'
relations:
- derived_from: story:published-merge-server-errors
revision: 1
---
## Problem

0.1.23 proves a historical GitHub merge through the pull request its subject names when
`commits/<merge>/pulls` keeps answering 5xx. A merge whose subject the merger replaced (GitHub
lets the merger edit the merge commit title) names no pull request, so only the 5 retries stand
between a transient 500 and a refused push. On 2026-10-22 the 0.1.23 push of `main` in this
repository was refused once that way, on merge `49838df9` ("Admit published merges whose stale
basis added nothing"), and went through on the second try.

## Contract

- A GitHub merge whose subject names no pull request can still be proved while the association
  list answers 5xx, through another authenticated read that binds one pull request to the merge
  as strictly as the list does (for example the pull request whose head is the merge's second
  parent, `merge_commit_sha == <merge>`), or the refusal says the merge needs the list.
- Fail closed: no read that answers 5xx is ever treated as absence, and no candidate pull
  request is admitted without its record naming the merge.

## Acceptance

Adversary cases in `tests/published_merge.rs`: a custom-subject merge with a failing list is
proved through the stand-in read; the stand-in naming another commit refuses; the stand-in read
failing refuses and names both reads.
