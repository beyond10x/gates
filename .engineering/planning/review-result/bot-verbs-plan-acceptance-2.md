---
format: aep.planning-md/3
id: review-result:bot-verbs-plan-acceptance-2
kind: review-result
status: active
title: 'Plan critic (acceptance), round 2: bot verbs stories'
relations:
- reviews: story:bot-merge-revert
- reviews: story:bot-delete-branch
revision: 1
---
needs-revision
story:bot-merge-revert — contract items 3 and 6 apply to `revert` as well (in-progress refusal; conflict route ending in `git revert --abort`), but the only tests for them are `merge_refuses_when_an_operation_is_in_progress` and `merge_conflict_prints_the_finish_route_and_leaves_the_index`, so a revert that skips the guard or prints the wrong route passes every listed test — .engineering/planning/story/bot-merge-revert.md:81-86 (contract items 3 and 6 at lines 33 and 45-47)

All four round 1 findings are fixed:
- **Merge/revert check that `gates.delivery` exists:** now named at line 91-92. `ess specify validate --path ess` prints `gates v1 — 2 file(s), valid` today, so "3 file(s)" after the new `delivery.yaml` is a real before/after change.
- **Delete-branch check that the entity and command exist:** now named at the "`ess specify inspect` finds the `RemoteBranch` entity and the `DeleteBranch` command" sentence.
- **Item 5 hooks and message:** now covered by `merge_commit_runs_the_commit_hooks` and `merge_keeps_the_prepared_message_unless_one_is_given`.
- **Argument shape:** now covered by `refuses_extra_arguments_and_options`.

What I read: 2 of 2 artifacts in full plus `review-result:bot-verbs-plan-acceptance-1`, via `aep plan artifact show` for each, `aep plan artifact kinds`, `aep plan artifact lifecycle story`, `ess specify validate --path ess` (ess 0.59.0) and `ls`/`git grep` of `ess/`, `tests/` and `src/bot_args.rs`.

What I could not establish:
- Whether `merge -F <file>` (item 5) is observed. `merge_keeps_the_prepared_message_unless_one_is_given` names only `-m`, and I did not count that as a finding.
- Out of my lane: the `-n` ambiguity and the Scope header saying `cited` for `ess/domains/delivery.yaml` while the body says `planned`. Both belong to design or scope.

```findings
- file: .engineering/planning/story/bot-merge-revert.md
  line: 81
  category: acceptance
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: "contract items 3 and 6 apply to revert as well (in-progress refusal; conflict route ending in git revert --abort), but the only tests for them are merge_refuses_when_an_operation_is_in_progress and merge_conflict_prints_the_finish_route_and_leaves_the_index, so a revert that skips the guard or prints the wrong route passes every listed test"
```
