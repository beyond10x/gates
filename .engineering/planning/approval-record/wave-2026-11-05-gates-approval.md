---
format: aep.planning-md/3
id: approval-record:wave-2026-11-05-gates-approval
kind: approval-record
status: draft
title: Orchestrator accepted three security drafts for wave-2026-11-05-gates
relations:
- decides: story:bot-git-ssl-env
- decides: story:token-env-error-value
- decides: story:api-writes-no-redirect
revision: 1
---
## Who decided

The coordinating session `b10x-chef-orchestrator`, under the grant in the workspace instructions
(it accepts proposed stories; the wave lead never does). Its message on 2026-11-05:

> propose the next gates wave now. Its first unit is the common.yml pin to 0.1.26, because
> callers get the batched scanner only through it. With it come the go record and up to 3 of
> the 5 from-finding drafts, which I accept: api-writes-no-redirect, token-env-error-value,
> ci-push-head-commit, bounded-reads-and-scanner-index, bot-git-ssl-env. Pick by risk; the
> security ones go first.

## Decided

Wave `wave-2026-11-05-gates`: the `common.yml` download moves to the 0.1.26 release, and the
three security stories are accepted and moved to active:

- `story:bot-git-ssl-env` (the caller's TLS-weakening Git variables reach a token push),
- `story:token-env-error-value` (an unreadable secret variable's value in error output),
- `story:api-writes-no-redirect` (a write re-sent along a redirect).

`story:ci-push-head-commit` and `story:bounded-reads-and-scanner-index` stay drafts for a later
wave: neither carries a credential, and the first needs a decision on tag-push events.
