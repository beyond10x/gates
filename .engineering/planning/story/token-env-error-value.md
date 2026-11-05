---
format: aep.planning-md/3
id: story:token-env-error-value
kind: story
status: draft
title: Name the token variable, never its value, when it cannot be read
tags:
- from-finding
relations:
- informed_by: story:published-merge-review-followups
revision: 1
---
## Problem

Found during `story:published-merge-review-followups` (pre-existing). When `B10X_BOT_TOKEN`
is not valid Unicode, the standard library's `VarError::NotUnicode` message includes the
variable's value, so the full error output (`{:#}` and `{:?}`) of a refused push evidence read
shows it. The one line `main` prints does not.

## Proposal

Map a missing or non-Unicode token variable to an error that names the variable and never its
value, wherever the token is read.

## Acceptance

A test sets the variable to a non-Unicode value and asserts that no form of the resulting
error (`{}`, `{:#}`, `{:?}`) contains any byte of it.
