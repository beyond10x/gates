---
format: aep.planning-md/3
id: review-result:bot-verbs-plan-scope-2
kind: review-result
status: active
title: 'Plan critic (scope), round 2: bot verbs stories'
relations:
- reviews: story:bot-merge-revert
- reviews: story:bot-delete-branch
revision: 1
---
needs-revision
story:bot-merge-revert — the Contract admits `merge <revision>…` (several revisions, so an octopus merge), but the design adds `git merge --no-ff --no-commit <rev>` with one revision, so an octopus merge is work the owner's Decision did not ask for; the body should say `merge` takes exactly one revision, or record that octopus is intended — `.engineering/planning/story/bot-merge-revert.md` Contract line 1 (`b10x-gates bot -- merge [<options>] <revision>…`) against `design:bot-verbs` Proposals row `merge` (`<rev>`)

What I read: 3 artifacts in full (`design:bot-verbs`, `story:bot-merge-revert`, `story:bot-delete-branch`), plus `aep plan artifact graph` and the round-1 `review-result:bot-verbs-plan-scope-1`. I extracted 8 promises from the Decision section and traced all 8 to an item. Merge and revert in `--no-commit` form with a bot commit, and the five option refusals plus the merge-driver refusal, are claimed by `story:bot-merge-revert`. Delete-branch with the ancestor, default-branch, protected-branch, tag and App-REST guards is claimed by `story:bot-delete-branch`. Never adding rebase, cherry-pick or pull is claimed by `story:bot-merge-revert`. Never adding force push, tag deletion or a remote reset is claimed by both stories. Nothing is claimed twice, and nothing in the graph claims any part of the parent elsewhere.

The other extras are not reach beyond the parent. These are the extra forbidden options, the in-progress refusal, the tip re-read, the name validation, `am` staying refused, `-c merge.renormalize=false`, and the `ess/` work required by the repository's ESS rule. They follow from the design's invariants and Proposals table. The set has not narrowed anything.

What I could not establish: nothing in my lane. Out of my lane:
- Acceptance: the named test `merge_refuses_each_forbidden_option` and its `revert_` twin cover the refusals, but no test covers the "never force push, tag deletion or remote reset" promise.
- Parallel safety: both stories scope `src/bot_args.rs`, `src/delivery.rs`, `src/main.rs`, `tests/bot_routes.rs` and `ess/domains/delivery.yaml`, with an ordering `depends_on` edge between them.

```findings
- file: .engineering/planning/story/bot-merge-revert.md
  line: 25
  category: scope
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: "the Contract admits `merge <revision>…` (several revisions, so an octopus merge) while design:bot-verbs adds `git merge --no-ff --no-commit <rev>` with one revision; the body should say merge takes exactly one revision or record that octopus is intended"
```
