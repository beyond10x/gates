---
format: aep.planning-md/3
id: story:token-env-error-value
kind: story
status: active
title: Name the token variable, never its value, when it cannot be read
tags:
- from-finding
relations:
- informed_by: story:published-merge-review-followups
scope:
- confidence: inferred
  path: src/delivery.rs
- confidence: inferred
  path: src/main.rs
- confidence: inferred
  path: tests/token_env_error_value.rs
revision: 5
transitions:
- {from: "draft", to: "proposed", at: "2026-11-05T02:57:28Z", actor: "human:timo", revision: 2}
- {from: "proposed", to: "active", at: "2026-11-05T02:57:28Z", actor: "human:timo", revision: 3}
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
