---
format: aep.planning-md/3
id: review-result:bot-verbs-plan-parallel-2
kind: review-result
status: active
title: 'Plan critic (parallel-safety), round 2: bot verbs stories'
relations:
- reviews: story:bot-merge-revert
- reviews: story:bot-delete-branch
revision: 1
---
approve

What I read: 3 artifacts (`story:bot-merge-revert` and `story:bot-delete-branch`, both revision 5, and `design:bot-verbs`). I ran `aep plan artifact show` on each, then `aep plan artifact waves`, `graph` and `relations`, and the round 1 record `review-result:bot-verbs-plan-parallel-1`. I also checked in `~/.local/state/worktree/trees/b10x/gates/gates-bot-verbs` that each cited path and symbol exists.

- **Surfaces:** 2 items placed cited, 0 inferred, 0 unplaceable.
- **Shared files:** the stories share five files: `ess/domains/delivery.yaml`, `src/bot_args.rs`, `src/delivery.rs`, `src/main.rs` and `tests/bot_routes.rs`.
- **Citations:** both bodies cite every shared file in their `scope` and `## Scope` lists.
- **Ordering:** `story:bot-delete-branch` has `relations depends_on story:bot-merge-revert`, which still holds at revision 5. `waves` puts them in wave 7 and wave 2, so the collision is named and ordered. Their new test files differ: `tests/bot_verbs.rs` and `tests/bot_delete_branch.rs`.
- **Acceptance reads:** I traced 1 to a producer in the set, and 1 of 1 is recorded by a `depends_on` edge. `story:bot-delete-branch` extends the `gates.delivery` domain and runs `ess specify validate` on it. `story:bot-merge-revert` creates `ess/domains/delivery.yaml`, and the file is not in the tree yet. Both bodies mark it new or planned.
- **Cited code:** `Github::git` (`src/delivery.rs:196`) and the existing `Github::api` calls sit on files both stories cite. `src/bot_args.rs:19`, the `--repository` option (`src/main.rs:29`) and `Action::Bot` (`src/main.rs:227`) are also on cited files, so no uncited surface turned up.

What I could not establish:
- `story:release-artifact-validation` and other items outside the set share `src/main.rs` with both stories in the `waves` output (inferred in the release-artifact case). They are outside the set I was given, so I did not assess them.
- The `depends_on` relation carries no stated reason, and neither body says in prose that the edge exists for the shared files. This is unchanged from round 1 and does not change my verdict.
- Whether the split is right, and whether each acceptance is checkable, are outside my lane (design and acceptance critics).

```findings
[]
```
