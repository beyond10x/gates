---
format: aep.planning-md/3
id: story:bot-delete-branch
kind: story
status: active
title: The bot deletes a remote branch only when its tip is merged
summary: delete-branch deletes a non-default, unprotected remote branch whose tip is an ancestor of the default branch, through the App.
relations:
- implements: design:bot-verbs
- derived_from: story:public-shared-gates
- depends_on: story:bot-merge-revert
scope:
- confidence: cited
  path: ess/domains/delivery.yaml
- confidence: cited
  path: src/bot_args.rs
- confidence: cited
  path: src/delivery.rs
- confidence: cited
  path: src/main.rs
- confidence: cited
  path: tests/bot_delete_branch.rs
- confidence: cited
  path: tests/bot_routes.rs
revision: 6
transitions:
- {from: "draft", to: "proposed", at: "2026-10-11T22:31:25Z", actor: "human:timo", revision: 4}
- {from: "proposed", to: "active", at: "2026-10-11T22:34:11Z", actor: "human:timo", revision: 6, decided_on: {"recorded":{"review_outcome":1}}}
---
## Problem

`b10x-gates bot -- push --delete` is refused, and the printed route is an unguarded
`b10x-gates api --method DELETE …/git/refs/heads/<branch>`. A merged wave branch is then left on
the remote, or deleted through a route with no check that its work is merged. The owner decided
(`design:bot-verbs`) to add a guarded verb.

## Contract

`b10x-gates bot --repository <owner>/<repo> -- delete-branch <branch>`:

1. Exactly one argument after the verb; no options. The repository comes from `--repository`;
   without it the verb is refused naming the option.
2. Refuse a name that is empty, starts with `refs/` other than `refs/heads/`, contains `..`,
   `:`, `~`, `^`, `?`, `*`, `[`, a space or a control character, or ends with `.lock` or `/`.
3. With the App token: read `GET /repos/<repo>` for `default_branch`; refuse when the branch is
   the default branch.
4. Read `GET /repos/<repo>/branches/<branch>`; refuse when it does not exist (404, naming it) or
   when `protected` is true.
5. Read `GET /repos/<repo>/compare/<tip>...<default_branch>` with the tip SHA from step 4; refuse
   unless `status` is `ahead` or `identical` (the tip is an ancestor of the default branch).
6. Re-read the branch tip; refuse when it changed since step 4.
7. `DELETE /repos/<repo>/git/refs/heads/<branch>`; print `deleted <branch> at <tip>`.

It never deletes a tag (only `refs/heads/` is addressed) and never forces anything. Every refusal
names its cause, as the other delivery refusals do. The `push --delete` refusal prints this verb
as the route; the raw API route stays the only way for an unmerged branch.

Risk left: GitHub's ref deletion carries no expected-SHA precondition, so a push between step 6
and step 7 can still be deleted. The window is one request; the adversary pass judges it.

## Specification

Extend `gates.delivery` in `ess/` with the `RemoteBranch` entity (name, tip, protected, whether
it is the default) and the `DeleteBranch` command: guards for default, protected, unmerged, moved
tip and an unknown branch, and the accepted outcome that moves it to `Deleted`. Validate with the
newest `ess`.

## Acceptance

New tests in `tests/bot_delete_branch.rs`, each failing before the change; the GitHub reads and
the delete go through a trait the tests fake, so no token is minted:

- `deletes_a_merged_branch` (tip ancestor of the default branch: one DELETE of `refs/heads/<b>`).
- `refuses_the_default_branch`, `refuses_a_protected_branch`, `refuses_an_unmerged_branch`
  (`status: diverged` and `behind`), `refuses_a_moved_tip`, `refuses_an_unknown_branch`.
- `refuses_tag_and_invalid_names` (`refs/tags/v1`, `a..b`, `x:y`, empty, `foo.lock`).
- `refuses_without_repository`.
- `refuses_extra_arguments_and_options` (`delete-branch a b`, `delete-branch --force a`,
  `delete-branch -f a`, `delete-branch`).
- `push_delete_refusal_names_delete_branch`.

`ess specify validate --path ess` with the newest `ess` prints `valid`, and `ess specify inspect`
finds the `RemoteBranch` entity and the `DeleteBranch` command in `gates.delivery`.

`cargo test --locked`, `cargo fmt --all --check` and `cargo clippy --all-targets --locked -- -D
warnings` pass.

## Scope

- `ess/domains/delivery.yaml`: planned
- `src/bot_args.rs` (admit `delete-branch`, update the push-deletion route): cited
- `src/delivery.rs` (the guarded deletion over a reads/delete trait): cited
- `src/main.rs` (`Action::Bot` dispatch of `delete-branch`): cited
- `tests/bot_delete_branch.rs` (new), `tests/bot_routes.rs`: cited
