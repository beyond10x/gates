---
format: aep.planning-md/3
id: story:bounded-reads-and-scanner-index
kind: story
status: draft
title: Bound every read while reading and refuse an out-of-range scanner index
tags:
- from-finding
relations:
- informed_by: review-result:scan-batches-security-1
revision: 1
---
## Problem

Found by `review-result:scan-batches-security-1` (pre-existing, outside that unit's diff):

- `Git::read` and `tree` (`src/git.rs`) read all of git's output into memory before the
  output size check.
- The commit-msg hook (`src/hooks.rs`) reads the message file with no size limit.
- `&units[leak.unit]` (`src/scan.rs`) panics when a scanner other than Gitleaks returns an
  out-of-range unit index.

## Proposal

Bound each read while reading (refuse at the limit, do not collect first), bound the message
file, and refuse an out-of-range scanner index as a scanner error.

## Acceptance

Tests: a git command whose output exceeds the bound is refused without holding more than the
bound; an oversized message file is refused; a scanner returning an index past the units is
refused, not a panic.
