---
format: aep.planning-md/3
id: review-result:bot-verbs-plan-acceptance-1
kind: review-result
status: active
title: 'Plan critic (acceptance), round 1: bot verbs stories'
relations:
- reviews: story:bot-merge-revert
- reviews: story:bot-delete-branch
revision: 1
---
needs-revision
story:bot-merge-revert — the acceptance names no check that `gates.delivery` exists and validates, so the `ess/domains/delivery.yaml` and `ess/system.yaml` work in Scope and Specification can never be shown done (`ess/` holds only `evidence.yaml` today, and the repository has no Taskfile or `ess` gate) — .engineering/planning/story/bot-merge-revert.md:71
story:bot-merge-revert — contract item 5 (the bot commit runs `pre-commit` and `commit-msg`, and keeps `MERGE_MSG` unless `-m` or `-F` is given) is observed by no listed test, because `merge_creates_one_bot_commit_with_two_parents` asserts only author and committer — .engineering/planning/story/bot-merge-revert.md:76
story:bot-delete-branch — the acceptance names no check that the `RemoteBranch` entity and `DeleteBranch` command exist in `gates.delivery` and validate with the newest `ess`, though the Specification requires it — .engineering/planning/story/bot-delete-branch.md:67
story:bot-delete-branch — contract item 1 (exactly one argument after the verb, no options) is observed by no listed test, since `refuses_without_repository` covers only the missing `--repository` — .engineering/planning/story/bot-delete-branch.md:76

What I read: 2 of 2 artifacts, in full, with `aep plan artifact show story:bot-merge-revert` and `aep plan artifact show story:bot-delete-branch`. I also read `design:bot-verbs` for context, ran `aep plan artifact lifecycle story`, and grepped the tree for `ess/`, `tests/` and `bot_routes.rs`.
What I could not establish:
- `aep plan artifact kinds` exited non-zero in a combined command and I did not re-run it alone. This does not affect the verdict.
- Whether `tests/bot_verbs.rs` and `tests/bot_delete_branch.rs` already exist. Neither is in `tests/`, which is consistent with "new".
- Out of my lane: the Scope sections mark `ess/domains/delivery.yaml` as `cited` in the header while the body says `planned`. That belongs to scope or design.

```findings
- file: .engineering/planning/story/bot-merge-revert.md
  line: 71
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "the acceptance names no check that gates.delivery exists and validates, so the ess/domains/delivery.yaml and ess/system.yaml work in Scope and Specification can never be shown done"
- file: .engineering/planning/story/bot-merge-revert.md
  line: 76
  category: acceptance
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: "contract item 5 (the bot commit runs pre-commit and commit-msg, and keeps MERGE_MSG unless -m or -F is given) is observed by no listed test, because merge_creates_one_bot_commit_with_two_parents asserts only author and committer"
- file: .engineering/planning/story/bot-delete-branch.md
  line: 67
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "the acceptance names no check that the RemoteBranch entity and DeleteBranch command exist in gates.delivery and validate with the newest ess, though the Specification requires it"
- file: .engineering/planning/story/bot-delete-branch.md
  line: 76
  category: acceptance
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: "contract item 1 (exactly one argument after the verb, no options) is observed by no listed test, since refuses_without_repository covers only the missing --repository"
```
