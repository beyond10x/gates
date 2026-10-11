---
format: aep.planning-md/3
id: review-result:bot-verbs-plan-scope-1
kind: review-result
status: active
title: 'Plan critic (scope), round 1: bot verbs stories'
relations:
- reviews: story:bot-merge-revert
- reviews: story:bot-delete-branch
revision: 1
---
approve

What I read: 4 artifacts (`design:bot-verbs`, both stories, `story:public-shared-gates`) plus the graph, with `aep plan artifact show` and `aep plan artifact graph`. I took 8 promises from the `## Decision` section and traced all 8 to an item.

1. `merge` and `revert` in `--no-commit` form followed by the bot's own commit: claimed by `story:bot-merge-revert` Contract items 4–5.
2. The refusal list `-s`/`--strategy`, `-X`, `--squash`, `--ff-only`, `--allow-unrelated-histories`: claimed by Contract item 1.
3. Refusal when `.git/config` names a merge driver: claimed by Contract item 2.
4. `delete-branch <branch>` removes only a remote branch whose tip is an ancestor of the default branch: claimed by `story:bot-delete-branch` Contract items 3–5.
5. It never deletes the default branch, a protected branch or a tag: claimed by Contract items 2–4 and the closing paragraph of that Contract.
6. The deletion goes through the REST API as the App: claimed by Contract item 7.
7. Never add `rebase`, `cherry-pick` or `pull`: claimed by `story:bot-merge-revert` ("stay refused with their route").
8. Never add force push, tag deletion or a remote reset: claimed by `story:bot-merge-revert` ("stay out of reach") and `story:bot-delete-branch` (never forces, addresses only `refs/heads/`).

Nothing is claimed twice. The only overlap is `gates.delivery`, which `story:bot-merge-revert` creates and `story:bot-delete-branch` extends, and the `depends_on` edge orders them. No other store item already claims part of the parent: the graph shows only `story:bot-supported-routes`, which is `informed_by` the design.

The extras in the stories are not reach beyond the parent. These are the extra forbidden options (`--ff`, `--commit`, `--edit`, `--continue`, `--abort`, `--quit`, `--skip`), the in-progress-operation refusal, the tip re-read, the name validation, and `am` staying refused. They follow from the design's invariants 1, 3 and 4 and its Proposals table (`-c merge.renormalize=false`). The `ess/` specification work follows the repository's ESS rule in `AGENTS.md`. The `story:public-shared-gates` scope already lists `ess/`.

What I could not establish, both out of my lane:
- Acceptance: `story:bot-merge-revert` tests refusals only through `merge_refuses_each_forbidden_option`, so the same refusals on `revert` have no named test.
- Design: `-c merge.renormalize=false` is passed internally while `-c` is refused from the caller, which is coherent but worth a design critic's glance.

```findings
[]
```
