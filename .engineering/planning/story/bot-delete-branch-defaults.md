---
format: aep.planning-md/3
id: story:bot-delete-branch-defaults
kind: story
status: active
title: delete-branch runs from the installed configuration and deletes a merged ruleset-only branch
summary: Default the repository from the installed hooks and judge classic protection by protection.enabled, so a merged wave branch under the bot-authority ruleset can be deleted.
relations:
- derived_from: story:bot-delete-branch
scope:
- confidence: inferred
  path: ess/domains/delivery.yaml
- confidence: inferred
  path: src/bot_args.rs
- confidence: inferred
  path: src/delivery.rs
- confidence: inferred
  path: src/main.rs
- confidence: inferred
  path: tests/bot_delete_branch.rs
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-10-13T11:19:51Z", actor: "human:timo", revision: 3}
- {from: "proposed", to: "active", at: "2026-10-13T11:19:51Z", actor: "human:timo", revision: 4}
---
## Problem

Two things stop `b10x-gates bot -- delete-branch` from deleting a merged wave branch:

1. It needs `--repository <owner>/<repo>`, while `commit` and `push` run with neither
   `--repository` nor `--policy`: the installed hooks' `config.json` names the repository.
2. It refuses every branch whose `GET /repos/<repo>/branches/<branch>` answer says
   `"protected": true`. GitHub sets that flag for a branch under any ruleset, so every branch of
   a repository with the organization's bot-authority ruleset reads as protected. Observed
   2026-10-13 on beyond10x/gates: every branch lists `protected: true`, while
   `GET /branches/main/protection` and `GET /branches/release/0.1.2/protection` answer 404
   "Branch not protected", and `release/0.1.2` carries `"protection": {"enabled": false}` and
   only the rule types `creation`, `update`, `deletion`, `non_fast_forward`,
   `commit_author_email_pattern` and `committer_email_pattern`.

## Proposal

- Without `--repository`, read the repository from the installed hooks' protected
  `config.json` (`<git common dir>/b10x-gates-hooks/config.json`), as the hooks do; with
  neither, refuse naming both routes. An explicit `--repository` still wins.
- Judge classic branch protection by the branch's `protection.enabled`, a boolean; refuse when
  it is true or missing. Rulesets stay judged by `rules/branches/<branch>` as now: any rule type
  outside the bot-authority set, or a second `deletion` rule, is refused.
- The default branch, an unmerged tip and a moved tip stay refused. `story:bot-delete-branch-atomic`
  (the one-request window) is not part of this story.

Spec first: `gates.delivery.DeleteBranch` in `ess/domains/delivery.yaml` changes its
`no-repository` outcome (the repository comes from the flag or the installed configuration) and
its `protected` field's meaning (classic protection enabled), validated with the newest `ess`.

## Acceptance

- A test deletes a merged branch whose answer says `protected: true` with
  `protection.enabled: false` and only admitted rule types.
- A test refuses a branch with `protection.enabled: true`, and one whose answer has no
  `protection.enabled`.
- A test resolves the repository from an installed `config.json` when `--repository` is absent,
  and refuses naming both routes when neither is present.
