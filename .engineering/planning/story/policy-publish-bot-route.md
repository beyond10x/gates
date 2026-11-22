---
format: aep.planning-md/3
id: story:policy-publish-bot-route
kind: story
status: draft
title: Write the CI policy secrets through the bot App, not a keyring account
summary: policy publish --apply sets secrets through the organization bot App installation token, never the gh keyring login
revision: 2
---
# Story: Write the CI policy secrets through the bot App, not a keyring account

## Outcome

An operator who changes the trusted policy publishes it to CI with `b10x-gates policy publish
--apply` and every secret is written by the organization bot App, as `b10x-gates bot`, `gh`, `api` and
`publish` already act. No person's personal administrator login is needed, or used, to move a policy
change into CI.

## Context

`policy publish` without `--apply` is a dry run that lists the targets. With `--apply` it calls plain
`gh secret set` (`src/publish.rs`), so it acts as whatever account is active in the `gh` keyring,
which has to be an organization administrator. It has no bot route, unlike `bot`, `gh`, `api` and
`publish`. Observed with b10x-gates 0.1.27 on 2026-11-22: the targets file lists 2 organization
secrets (`B10X_GATES_POLICY`, `B10X_GATES_POLICY_GZ`) and 8 repository secrets, all copies of the
policy, and a policy change (new exceptions for one repository) cannot reach CI without using a
personal administrator login.

The operator chose this route on 2026-11-22 over keeping the keyring path: wait for a bot route.

## Acceptance

- `policy publish --apply` writes every target (organization and repository secrets, and the
  read-back that follows each write) with the bot App's installation token, minted as the other bot
  verbs mint it and held only in the child environment. It never uses the account in the `gh`
  keyring, and it refuses with a named cause, writing nothing, when the App cannot write a target.
  A test proves it: with a `gh` keyring account configured and a stub GitHub endpoint, every secret
  write and read-back arrives with the bot token and none with the keyring account, and the test
  fails when the plain `gh secret set` path is restored.

## Out of Scope

- The dry run, the targets file format, the 48,000-byte limit and the marker file stay as they are.
- Granting the App permission to write organization and repository secrets is an administrator's
  change to the App, made once; this story does not make it.
- Reading or printing a secret value or a token.

## Open Questions

- Does the App's current installation hold the secrets permission at both organization and
  repository scope? The steward of the App answers; the answer decides whether the acceptance test
  also needs a refusal case for a missing permission.
