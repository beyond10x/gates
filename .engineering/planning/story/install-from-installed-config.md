---
format: aep.planning-md/3
id: story:install-from-installed-config
kind: story
status: implemented
title: install reuses the installed repository and policy when no flag names them
scope:
- confidence: inferred
  path: ess/domains/delivery.yaml
- confidence: inferred
  path: src/bot_args.rs
- confidence: inferred
  path: src/hooks.rs
- confidence: inferred
  path: src/main.rs
- confidence: inferred
  path: tests/install_defaults.rs
revision: 9
transitions:
- {from: "draft", to: "proposed", at: "2026-10-13T18:25:13Z", actor: "human:timo", revision: 7}
- {from: "proposed", to: "active", at: "2026-10-13T18:25:13Z", actor: "human:timo", revision: 8}
- {from: "active", to: "implemented", at: "2026-10-13T19:05:51Z", actor: "human:timo", revision: 9, decided_on: {"recorded":{"test_result":1,"review_outcome":2}}}
---
## Problem

`b10x-gates install` needs `--policy` (or `B10X_GATES_POLICY`) and `--repository` on every run,
also in a repository whose hooks are already installed and whose protected
`<git common dir>/b10x-gates-hooks/config.json` names both. Observed 2026-10-13 in beyond10x/loom
on 0.1.18: `b10x-gates --repo <loom> install` refuses "trusted policy at
~/.config/b10x/gates/policy.json: protected file ... unavailable: not found; pass --policy or
set B10X_GATES_POLICY". Every gates release asks each repository to reinstall its hooks, so the
reinstall is the common case. `bot -- commit|push` and `bot -- delete-branch` already run with
neither flag (verified the same day: `bot -- delete-branch` without flags resolved
beyond10x/loom from the installed configuration).

## Proposal

- When `install` is given no `--repository`, read it from the installed configuration; when it
  is given no `--policy` and no `B10X_GATES_POLICY`, use the installed configuration's `policy`
  path. A flag or the environment still wins.
- The installed configuration is read through the same protected read as the hooks
  (`policy::protected_read`): a file that is not owner-only, unparsable or names a repository
  that is not `<owner>/<repo>` is refused with its cause, never silently skipped.
- With no flag and no installed configuration, the refusal names both routes.
- The policy that is loaded must still admit the repository (`policy.repository`), as today.

Spec first: model the reinstall in `ess/domains/delivery.yaml` (an install command with the
repository and policy resolution outcomes), validated with the newest `ess`.

## Acceptance

- A test reinstalls hooks in a repository with an installed configuration and neither flag,
  and the new configuration names the same repository and policy.
- A test shows an explicit `--repository`/`--policy` wins over the installed configuration.
- A test refuses an installed configuration that is not owner-only, and one naming a repository
  that is not `<owner>/<repo>`; a test refuses naming both routes when neither exists.
