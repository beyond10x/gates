---
format: aep.planning-md/3
id: story:ci-push-head-commit
kind: story
status: draft
title: Bind a push or dispatch candidate to exactly the object its event names
tags:
- from-finding
relations:
- informed_by: review-result:ci-fetch-security-1
revision: 1
---
## Problem

Found by `review-result:ci-fetch-security-1` (pre-existing, outside that unit's diff). For a
push or dispatch event, a head id naming an annotated tag object is peeled to its commit, so
the candidate is not the event's id. The pull request path now requires a commit object;
the push path was left alone because a pushed annotated tag can carry a tag object id as
`after`, and refusing it could break tag-push CI (inferred, not verified).

## Proposal

Decide per event what the head id may name: a commit for branch pushes and dispatches, a tag
object only for a tag push, bound to that tag. Refuse everything else.

## Acceptance

Tests: a branch push whose `after` names a tag object is refused; a tag push of an annotated
tag is scanned with its tag object; a dispatch naming a tag object is refused.
