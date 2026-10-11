---
format: aep.planning-md/3
id: story:bot-delete-branch-atomic
kind: story
status: draft
title: Delete a remote branch only if its tip is still the one checked
summary: Close the one-request window between the last tip read and the ref deletion with a server-checked compare-and-delete.
relations:
- derived_from: story:bot-delete-branch
- informed_by: review-result:bot-verbs-adversary-1
revision: 1
---
## Problem

`b10x-gates bot -- delete-branch` re-reads the branch tip and then deletes the ref through
`DELETE /repos/<repo>/git/refs/heads/<branch>`. That call carries no expected tip, so a push that
lands between the re-read and the delete is deleted with the branch. The window is one request.
`review-result:bot-verbs-adversary-1` (finding D) judged it acceptable for now and named safer
primitives.

## Proposal

Delete with a compare-and-delete that the server checks atomically: either a Git protocol
deletion carrying the expected old object (`git push --force-with-lease=refs/heads/<b>:<tip>
<url> :refs/heads/<b>`, run internally by the verb and never exposed as a push option), or a
GitHub API that takes the expected object id, once it is verified that one exists and behaves so.

## Acceptance

A test in which the tip moves after the last read and before the deletion shows the branch kept
and the deletion refused, naming the moved tip.
