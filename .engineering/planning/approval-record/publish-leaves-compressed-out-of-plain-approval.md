---
format: aep.planning-md/3
id: approval-record:publish-leaves-compressed-out-of-plain-approval
kind: approval-record
status: draft
title: Orchestrator approved leaving compressed repositories out of the plain secret and release 0.1.25
relations:
- decides: story:publish-leaves-compressed-out-of-plain
revision: 1
---
## Who decided

The monitoring session `b10x-chef-orchestrator`, under the grant in the workspace instructions
(a message from it naming a class-C item counts as the operator's approval). Its message on
2026-10-31 (item D329):

> Approved under the grant in ~/beyond10x/CLAUDE.md as D329. This is a fix that consumers are
> blocked on today, so it goes alone.

> In publish.rs (around :310), leave repositories listed under `compressed` out of the org
> plain secret too, as `sliced` ones already are.

> Open a bot PR, merge it on green, then release gates through its own process (next patch
> after 0.1.24; the commits since 0.1.24 ride along).

> Do not --apply; b10x-atlas does that.

## Decided

Implement `story:publish-leaves-compressed-out-of-plain`, merge it into `main` through the bot
route, and release 0.1.25 through this repository's process.
