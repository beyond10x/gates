---
format: aep.planning-md/3
id: story:bot-merge-revert
kind: story
status: active
title: The bot runs merge and revert and commits the result as itself
summary: merge and revert run in their no-commit form with forbidden options refused, then the bot commits.
relations:
- implements: design:bot-verbs
- derived_from: story:public-shared-gates
scope:
- confidence: cited
  path: ess/domains/delivery.yaml
- confidence: cited
  path: ess/system.yaml
- confidence: cited
  path: src/bot_args.rs
- confidence: cited
  path: src/delivery.rs
- confidence: cited
  path: src/main.rs
- confidence: cited
  path: tests/bot_routes.rs
- confidence: cited
  path: tests/bot_verbs.rs
revision: 7
transitions:
- {from: "draft", to: "proposed", at: "2026-10-11T22:31:25Z", actor: "human:timo", revision: 4}
- {from: "proposed", to: "active", at: "2026-10-11T22:34:11Z", actor: "human:timo", revision: 7, decided_on: {"recorded":{"review_outcome":4}}}
---
## Problem

`b10x-gates bot` refuses `merge` and `revert` and prints the two-command route
(`git merge --no-ff --no-commit <branch>`, then `b10x-gates bot -- commit -F -`). The owner
decided (`design:bot-verbs`) that the bot runs both verbs itself, so the merge or revert commit is
the bot's without a second command.

## Contract

`b10x-gates bot -- merge [<options>] <revision>` and `b10x-gates bot -- revert [<options>]
<revision>`, each with exactly one revision (no octopus merge, no revert of a range; a second
revision is refused), after the argument check and before minting a credential where possible:

1. Refuse, naming the option, any of: `-s`/`--strategy` (and `--strategy=`), `-X`/`--strategy-option`,
   `--squash`, `--ff-only`, `--ff`, `--allow-unrelated-histories`, `--commit`, `-e`/`--edit`,
   `--continue`, `--abort`, `--quit`, `--skip`, `--no-verify`, `-n`, `-c`, `--config-env`,
   `--exec`, for both verbs. `-n` is refused for both even though it is `--no-stat` to `merge`
   and `--no-commit` to `revert`: the bot adds `--no-commit` itself, and one rule per letter is
   easier to audit than one per verb. Long options are matched by every unique prefix Git
   accepts, as the existing guard does.
2. Refuse, naming the driver, when the repository's own `.git/config` (read as data, never through
   Git configuration expansion of the candidate tree) declares any `merge.<driver>.driver` key.
3. Refuse when a merge, revert, cherry-pick or rebase is already in progress.
4. Run `git merge --no-ff --no-commit -c merge.renormalize=false …` (or
   `git revert --no-commit …`) in the same bot environment `Github::git` uses
   (`GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, bot author and committer).
5. On success, commit with the bot through the existing commit path. For `merge`, the message is
   `-m <msg>` or `-F <file>` when given, else Git's prepared `MERGE_MSG`. For `revert`, `-m
   <parent>` (`--mainline`) is passed to Git as the mainline parent and the message is always
   Git's prepared one. The resulting commit's author and committer are the bot identity, and
   `pre-commit` and `commit-msg` run.
6. On a conflict, stop with the conflict left in the index, and print the route to finish:
   resolve, `git add`, then `b10x-gates bot -- commit -F -`; or `git merge --abort`
   (`git revert --abort`).

`rebase`, `cherry-pick`, `pull` and `am` stay refused with their route. Force push, tag deletion
and a remote reset stay out of reach.

## Specification

Model the bot's delivery verbs in a new domain `gates.delivery` in `ess/` (newest format): the
`Merge` and `Revert` commands with their refused outcomes (forbidden option, merge driver
configured, operation in progress, conflict) and the accepted outcome (one bot-authored commit).
Validate with the newest `ess`. The repository consumes no generated code today; the
implementation is held to the model by tests named after its outcomes.

## Acceptance

New tests in `tests/bot_verbs.rs`, each failing before the change; tests run Git in a temporary
repository with neutral identities (user name `example`) and never mint a token:

- `merge_creates_one_bot_commit_with_two_parents`: author and committer are the bot.
- `merge_keeps_the_prepared_message_unless_one_is_given`: no option gives Git's `Merge branch …`
  message; `-m <msg>` gives `<msg>`.
- `merge_commit_runs_the_commit_hooks`: a `pre-commit` and a `commit-msg` hook in the temporary
  repository each leave a marker file.
- `revert_creates_one_bot_commit_reverting_the_target`: bot author and committer, Git's
  `Revert "…"` message; `revert -m 1 <merge>` reverts a merge commit.
- `merge_refuses_each_forbidden_option` and `revert_refuses_each_forbidden_option` (each option
  above, plus a unique prefix of each long one).
- `merge_refuses_a_configured_merge_driver`.
- `merge_refuses_when_an_operation_is_in_progress` and
  `revert_refuses_when_an_operation_is_in_progress`.
- `merge_conflict_prints_the_finish_route_and_leaves_the_index` and
  `revert_conflict_prints_the_finish_route_and_leaves_the_index` (the latter names
  `git revert --abort`).
- `merge_keeps_the_prepared_message_unless_one_is_given` also covers `-F <file>`.
- `merge_and_revert_refuse_a_second_revision` (also `revert a..b`).
- `rebase_cherry_pick_pull_still_refused`.

`ess specify validate --path ess` with the newest `ess` prints `gates v1 — 3 file(s), valid`, and
`ess specify inspect` finds the `Merge` and `Revert` commands in `gates.delivery`.

`cargo test --locked`, `cargo fmt --all --check` and `cargo clippy --all-targets --locked -- -D
warnings` pass.

## Scope

- `ess/system.yaml`, `ess/domains/delivery.yaml` (new): planned
- `src/bot_args.rs` (argument check: admit `merge`/`revert`, refuse their forbidden options): cited
- `src/delivery.rs` (`Github::git`: run the no-commit form, then the bot commit): cited
- `src/main.rs` (`Action::Bot`): cited
- `tests/bot_verbs.rs` (new), `tests/bot_routes.rs` (the merge refusal tests change): cited
