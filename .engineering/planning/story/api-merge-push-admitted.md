---
format: aep.planning-md/3
id: story:api-merge-push-admitted
kind: story
status: active
title: A push cut from an API merge needs no baseline move
summary: Prove with tests that the pre-push proof and check admit a branch and a tag cut from an App pull-request merge one past the baseline, and refuse a merge with an unbound parent.
relations:
- derived_from: story:github-update-branch-provenance
scope:
- confidence: inferred
  path: src/published_merge.rs
- confidence: inferred
  path: tests/published_merge.rs
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-10-13T11:19:51Z", actor: "human:timo", revision: 3}
- {from: "proposed", to: "active", at: "2026-10-13T11:19:51Z", actor: "human:timo", revision: 4}
---
## Problem

Repositories that merge pull requests through the API move their gates baseline to each new
merge before they push a branch cut from `main` or a tag, on the stated belief that "the merge
is committed by `GitHub`, and until the baseline moves the push guard refuses every branch cut
from `main` and every tag". No refusal was observed: the moves were preemptive. Each one held a
release push for 61-90 s.

`published_merge::verify` (pre-push and publication) admits a two-parent merge committed by
GitHub when its pull request was merged by the exact bot, its head is the second parent and its
tree is the local clean merge of its parents. `check` builds the candidate from the baseline and
admits a commit by its author alone. Neither path is shown by a test against exactly this
shape: a baseline one merge behind, a branch and an annotated tag cut from the merge.

## Proposal

Prove or refute the claim with tests, through both entrypoints that see a push:

- the pre-push hook's ancestry proof (`hooks::verify_pre_push`) and `b10x-gates check`, on a
  new bot commit whose ancestry since the baseline is one GitHub-committed App merge whose
  parents are the baseline (first) and a bot-authored pull-request head (second);
- the same with an annotated tag on that bot commit;
- the refused case: a GitHub-committed merge with a parent that is neither the walked
  ancestry's base nor a bot-authored, pull-request-bound head is refused, naming the cause.

If both entrypoints admit the shape, the tests are the deliverable and the README states that a
merge through the API needs no baseline move. If either refuses, change the guard so it admits a
merge commit whose parents are the current baseline and a receipt-checked head, and no other.

## Acceptance

- `tests/published_merge.rs` holds a test in which the pre-push proof and `check` both admit a
  bot commit, and an annotated tag on it, descending from an App merge one past the baseline.
- A test in which a merge parent is neither the baseline line nor a bound pull-request head is
  refused by the pre-push proof.
- Each new test fails when the guard it relies on is removed (mutation recorded).
