---
format: aep.planning-md/3
id: approval-record:refusal-causes-wave-proposal
kind: approval-record
status: draft
title: Wave proposal accepted with no operator present
tags:
- non-interactive
relations:
- decides: story:bot-refusal-causes
- decides: story:bot-supported-routes
revision: 1
---
## Stop

The stage-1 wave proposal for `story:bot-refusal-causes` and `story:bot-supported-routes`.

## Why non-interactive

The work arrived as a dispatch to a background controller session with no operator turn. The
dispatch named both items, one wave, one pull request and a release.

## Decided

Run both units in one wave on `wave/refusal-causes`; split the one shared file (`src/main.rs`) by
function; one security-reviewer pass. Commits authorised: the opening store commit, one commit per
implementor or reviewer round, the unit merges, the release-content commit, the closing store
commit, and the pull request merge through the bot route.

## What the operator would have been asked

Whether to run the two units in parallel despite the `src/main.rs` collision, or in two waves.
