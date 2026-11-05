---
format: aep.planning-md/3
id: review-result:delete-branch-lease-security-1
kind: review-result
status: active
title: 'Security review 1: delete-branch with an expected tip'
relations:
- reviews: story:bot-delete-branch-atomic
revision: 1
---
verdict: NEEDS-CHANGE
cases: executed 78→81, red 2
origin: introduced 1, pre-existing 1, undecided 0

Unit diff ab62350..b8f4b8e, reviewed at 24a68d8. Cases in
`tests/security_delete_branch_lease.rs`.

- Warning, introduced: the caller's `GIT_TEMPLATE_DIR` installs hooks and a `pushInsteadOf`
  in the scratch repository (same finding as the adversary's blocker).
- Note, pre-existing: `bot_command` inherits the caller's `GIT_TRACE2_ENV_VARS`, so naming
  the token variable writes it into git's trace, for delete-branch and `bot -- fetch`.
- Held: the token reaches git only through the environment and never argv, URL, output or
  refusal; global, XDG and system configuration are not read; `GIT_CONFIG_*` are removed;
  the scratch repository is removed on every return; the push deletes exactly
  `refs/heads/<branch>` of the resolved repository; every refusal runs before the push.
- Not verifiable locally: whether GitHub compares the expected old object on a deletion and
  whether the App's ruleset bypass covers a deletion by push. Checked live after the release
  build.
