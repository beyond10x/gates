---
format: aep.planning-md/3
id: review-result:bot-verbs-plan-design-2
kind: review-result
status: active
title: 'Plan critic (design), round 2: bot verbs stories'
relations:
- reviews: story:bot-merge-revert
- reviews: story:bot-delete-branch
revision: 1
---
approve

```findings
[]
```

**What I read:** 3 artifacts, `story:bot-merge-revert`, `story:bot-delete-branch` and `design:bot-verbs`, plus `review-result:bot-verbs-plan-design-1`, each with `aep plan artifact show`. I also ran `aep plan artifact relations`, `graph` and `validate` from `~/.local/state/worktree/trees/b10x/gates/gates-bot-verbs`.

- **Edges:** I walked all declared edges in the graph, including those outside the set (`story:public-shared-gates` and `design:bot-verbs`). There is no cycle. The only ordering edge is `story:bot-delete-branch` depends_on `story:bot-merge-revert`, and nothing runs back.
- **Chain:** the edge is not a serialising chain. The two stories share `ess/domains/delivery.yaml`, `src/bot_args.rs`, `src/delivery.rs`, `src/main.rs` and `tests/bot_routes.rs`, so the edge records a real shared surface. Splitting that surface is the alternative, and I would not ask for it.
- **Acceptance reads:** I traced 3 reads to a producer in the set, and the one edge records all 3.
  - The `gates.delivery` domain, which `story:bot-delete-branch` extends and `story:bot-merge-revert` creates. The tree has only `ess/system.yaml` and `ess/domains/evidence.yaml`, so the 3-file count in the `story:bot-merge-revert` acceptance counts the new domain.
  - The `bot_args` verb dispatch.
  - `tests/bot_routes.rs`.
- **Slices:** each story is a vertical slice with its own specification, implementation and tests. Merge and revert share one no-commit-then-bot-commit mechanism inside one story. Delete-branch is a separate REST path, so there is no split abstraction.
- **Validate:** `aep plan artifact validate` reports `valid`. Its only note is the unrecorded outcome of `review-result:published-merge-correction`, which is not a finding.

**What I could not establish:** none that affects the verdict. Out of my lane, for the acceptance and parallel-safety critics: the `-n` handling and the `revert -m` mainline-versus-message distinction in `story:bot-merge-revert` contract steps 1 and 5. This revision states both explicitly.
