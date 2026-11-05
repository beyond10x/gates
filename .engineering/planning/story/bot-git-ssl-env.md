---
format: aep.planning-md/3
id: story:bot-git-ssl-env
kind: story
status: active
title: Keep the caller's TLS-weakening Git variables out of the bot's Git
tags:
- from-finding
relations:
- informed_by: review-result:delete-branch-lease-adversary-1
scope:
- confidence: inferred
  path: src/delivery.rs
- confidence: inferred
  path: tests/bot_git_ssl_env.rs
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-11-05T02:57:28Z", actor: "human:timo", revision: 2}
- {from: "proposed", to: "active", at: "2026-11-05T02:57:28Z", actor: "human:timo", revision: 3}
---
## Problem

Found by `review-result:delete-branch-lease-adversary-1` (pre-existing, outside that unit's
acceptance, not tested): the caller's `GIT_SSL_NO_VERIFY` and other `GIT_SSL_*` variables
reach every bot push and fetch, so a caller environment can turn off certificate checks for
a git operation that carries the App token.

## Proposal

The bot's git environment removes `GIT_SSL_NO_VERIFY` and the `GIT_SSL_*` overrides that
weaken verification (and `http.sslVerify` through any config path the bot still reads).

## Acceptance

A test sets `GIT_SSL_NO_VERIFY=1` for a bot push and asserts the child git's environment does
not carry it.
