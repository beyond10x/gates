---
format: aep.planning-md/3
id: story:bot-credential-exact-repository
kind: story
status: draft
title: Answer the bot's credential only for the repository it was minted for
tags:
- from-finding
relations:
- informed_by: review-result:bot-git-ssl-env-security-1
revision: 1
---
## Problem

Found by `review-result:bot-git-ssl-env-security-1`, outside that unit's acceptance. The bot's
credential helper answers every request for a repository on `github.com`, not only for the
repository the installation token was minted for, because `bot_git` does not know that
repository for push or fetch (`--repository` is optional). The App's installation scope is
the only limit today.

## Proposal

Resolve the target repository before minting (from `--repository` or the installed hooks'
configuration, as `delete-branch` does) and have the helper answer only for
`path=<owner>/<repo>.git` or `path=<owner>/<repo>`, case-insensitively as GitHub matches.

## Acceptance

Tests: a bot push to another repository on github.com gets no credential; a push to the
named repository, from an HTTPS and from both SSH origin forms, still gets it.
