---
format: aep.planning-md/3
id: review-result:bot-verbs-plan-design-1
kind: review-result
status: active
title: 'Plan critic (design), round 1: bot verbs stories'
relations:
- reviews: story:bot-merge-revert
- reviews: story:bot-delete-branch
revision: 1
---
approve

What I read: 3 artifacts (`story:bot-merge-revert`, `story:bot-delete-branch`, `design:bot-verbs`) with `aep plan artifact show`. I also ran `aep plan artifact relations`, `graph` and `validate`, and read `src/bot_args.rs`, `src/main.rs` and `src/delivery.rs` under `~/.local/state/worktree/trees/b10x/gates/gates-bot-verbs`. I walked all 38 edges of the store's graph, including those outside the set (`story:public-shared-gates`, `story:bot-supported-routes`).
- The set has no cycle. The one ordering edge is `story:bot-delete-branch` depends_on `story:bot-merge-revert`, and nothing runs back.
- That edge is not a serialising chain. It is two items, and it records a real shared surface: `ess/domains/delivery.yaml` (created by the first, extended by the second), `src/bot_args.rs`, `src/main.rs`, `src/delivery.rs` and `tests/bot_routes.rs`.
- I traced 3 acceptance reads to a producer in the set, and the one edge records all 3: the `gates.delivery` domain file, the `bot_args::check` verb dispatch, and `tests/bot_routes.rs`.
- Each story is a vertical slice with its own specification, implementation and tests. Neither is a split abstraction: merge and revert share one no-commit-then-bot-commit mechanism inside one story, and delete-branch is a separate REST path.
- `aep plan artifact validate` reports `valid`. Its only note is the unrecorded outcome of `review-result:published-merge-correction`, which is not a finding.

What I could not establish (out of my lane, not setting the verdict):
- The `story:bot-merge-revert` contract step 5 says to keep Git's prepared message "unless `-m <msg>` or `-F <file>` was given to the verb". `git revert -m` means mainline parent, and `git revert` has no `-F`. The contract does not say how `revert -m <parent>` is told apart from a message option. That is for the acceptance and scope critics.
- `-n` means different things to `git merge` (`--no-stat`) and `git revert` (`--no-commit`). The refused-option list says "`-n` where it means no-verify", and the acceptance names no per-verb case for it. That is also for the acceptance critic.

```findings
[]
```
