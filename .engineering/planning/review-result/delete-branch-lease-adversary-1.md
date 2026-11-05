---
format: aep.planning-md/3
id: review-result:delete-branch-lease-adversary-1
kind: review-result
status: active
title: 'Adversary pass 1: delete-branch with an expected tip'
relations:
- reviews: story:bot-delete-branch-atomic
revision: 1
---
verdict: NEEDS-CHANGE
cases: executed 0→7, red 3
origin: introduced 3, pre-existing 0, undecided 0

Unit diff ab62350..b8f4b8e, attacked at 8c53213. Cases in
`tests/adversary_delete_branch_lease.rs`.

- Blocker: the caller's `GIT_TEMPLATE_DIR` overrode `-c init.templateDir=`, so a template
  `pushInsteadOf` sent the deletion to a repository that was never checked (reported
  deleted) and a template `pre-push` hook ran with the token in its environment.
- Warning: a deletion the remote applied whose report was lost was printed as "the bot
  deleted nothing".
- Note: the `bot_git` refusal, the `bot_args` doc and the supported-verb text still said
  delete-branch never runs through Git.
- Held (4 regression cases): a push landing in the remote's pre-receive after the
  advertisement keeps the branch; option- and refspec-shaped names delete only themselves;
  the scratch directory is empty on every path; default-branch and ruleset refusals delete
  nothing.
- Outside the acceptance, pre-existing: `GIT_SSL_*` variables reach every bot push.
