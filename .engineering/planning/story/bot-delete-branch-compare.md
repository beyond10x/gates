---
format: aep.planning-md/3
id: story:bot-delete-branch-compare
kind: story
status: active
title: delete-branch reads the comparison through a path the API client admits
scope:
- confidence: inferred
  path: ess/domains/delivery.yaml
- confidence: inferred
  path: src/delivery.rs
- confidence: inferred
  path: tests/bot_delete_branch.rs
revision: 6
transitions:
- {from: "draft", to: "proposed", at: "2026-10-13T18:25:13Z", actor: "human:timo", revision: 5}
- {from: "proposed", to: "active", at: "2026-10-13T18:25:13Z", actor: "human:timo", revision: 6}
---
## Problem

`b10x-gates bot -- delete-branch <branch>` (0.1.18) refuses every branch that reaches the
ancestry check with "could not read the comparison with the default branch of <repo>: invalid
GitHub API path". Observed 2026-10-13 on beyond10x/loom for `wave/2026-10-13-w3`.

Cause, observed at runtime: `delete_remote_branch` reads
`/repos/<repo>/compare/<tip>...<default>`, and `Github::api_response` refuses any path that
contains `..` before sending it. `b10x-gates api --method GET --path
/repos/beyond10x/gates/compare/<sha>...main` answers "invalid GitHub API path"; the same path
with the three dots percent-encoded (`%2E%2E%2E`) is sent and GitHub answers `status: ahead`.
The branch name's `/` is not the cause: `GET branches/wave/2026-10-13-w3` and
`GET rules/branches/wave/2026-10-13-w3` both succeed. The existing tests did not see it because
their API double does not apply the path guard.

## Proposal

- Build the comparison path so the guard admits it: the `...` separator percent-encoded
  (`%2E%2E%2E`), base and head encoded as today. The `..` guard itself stays: no path a caller
  of `b10x-gates api` passes gains anything.
- The test double used by the delete-branch tests applies the same path guard as
  `Github::api_response`, so a path the real client refuses fails the test.

Spec first: `gates.delivery.DeleteBranch` names the comparison read in its comment; add a
`comparison_readable` input and a `comparison-unreadable` outcome (an unreadable comparison is
refused and nothing is deleted), validated with the newest `ess`.

## Acceptance

- A test that drives `delete_remote_branch` against a double applying the real path guard
  deletes a merged branch named `wave/2026-10-13-w3`; it fails on 0.1.18's path.
- A test shows every path `delete_remote_branch` requests passes the guard.
- A comparison the API cannot answer is still refused with nothing deleted.
