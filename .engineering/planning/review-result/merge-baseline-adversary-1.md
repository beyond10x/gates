---
format: aep.planning-md/3
id: review-result:merge-baseline-adversary-1
kind: review-result
status: active
title: 'Adversary pass 1: API merge proof and delete-branch defaults'
relations:
- reviews: story:api-merge-push-admitted
- reviews: story:bot-delete-branch-defaults
revision: 1
---
```
unit: merge-baseline / delete-branch defaults wave (28aa460..9fa978d) in gates-review-adversary-mb; findings cover 4589441
verdict: CONFIRMED (one note-severity defect; no steering or bypass found)
cases: executed 315→316, red 1
origin: introduced 1 / pre-existing 0 / undecided 0
```

Case added: `tests/adversary_merge_baseline.rs::a_shallow_repository_with_installed_hooks_is_not_reported_as_uninstalled`
(red at review time: an installed, trusted configuration was reported as absent).

Attacked without a break: a symlinked `config.json` (refused by `regular()`), wrong mode, another
owner, a group-writable directory (refused by `protected_read`), linked worktree versus common
directory, path tricks in the configured repository (refused by `repository_shaped`),
`--repository` and the configuration disagreeing (the flag wins), credential order (the
repository is resolved before `check()` and `Github::bot()`), `protection` absent, null or `{}`,
`enabled` as the string "false" or `0` (refused), `protected:false` with `protection.enabled:true`
(refused); for the merge proof, a non-bot commit on the first-parent line, an octopus, swapped
parents and a tag on the merge itself are refused or bind only proved commits.

Outcome: fixed in fix round 1 (`common_directory` returns none only for "not a git repository").

```findings
- file: src/bot_args.rs
  line: 468
  category: boundary
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: delete_branch_repository swallows Git::new's shallow/graft refusal as "not a repository" and returns None for a present trusted hook configuration, so the refusal tells the operator to run an install that refuses the same repository
```
