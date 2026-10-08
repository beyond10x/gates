---
format: aep.planning-md/3
id: story:bot-supported-routes
kind: story
status: implemented
title: Print the supported route when the bot refuses merge, rebase or a branch deletion
summary: The bot argument check names the merge route and the API deletion route before minting a token.
relations:
- derived_from: story:public-shared-gates
scope:
- confidence: cited
  path: src/bot_args.rs
- confidence: cited
  path: src/lib.rs
- confidence: cited
  path: src/main.rs
- confidence: cited
  path: tests/bot_routes.rs
revision: 5
transitions:
- {from: "draft", to: "proposed", at: "2026-10-08T09:41:15Z", actor: "human:timo", revision: 3}
- {from: "proposed", to: "active", at: "2026-10-08T09:41:15Z", actor: "human:timo", revision: 4}
- {from: "active", to: "implemented", at: "2026-10-08T10:13:46Z", actor: "human:timo", revision: 5, decided_on: {"recorded":{"test_result":1,"review_outcome":1}}}
---
## Problem

`b10x-gates bot` runs only `commit`, `tag`, `push` and `fetch`. On 2026-10-08 seven repositories
hit that wall: six `merge` refusals, a `rebase` whose rewritten commits the pre-push check then
refused, and a `push --delete` that failed, leaving a remote branch behind. The refusal named the
allowed verbs and nothing else, so each agent found the workaround on its own.

## Contract

Before any credential is minted, `bot -- <args>` checks its arguments and refuses these with the
supported route in the text:

| asked | refusal names |
|---|---|
| `merge …` | `git merge --no-ff --no-commit <branch>`, then `b10x-gates bot -- commit -F -` (no pathspec: a merge commits the whole index) |
| `pull …` | `b10x-gates bot -- fetch origin`, then the merge route above |
| `rebase …`, `cherry-pick …`, `am …` | they rewrite or re-create commits the pre-push check then refuses; use the merge route above |
| `push` with `--delete`, `-d`, `--prune`, `--mirror`, or a refspec starting with `:` | `b10x-gates api --method DELETE --path /repos/<owner>/<repo>/git/refs/heads/<branch> --output <file>`, admitted only where the policy admits that API write |
| any other verb | the supported verbs and the routes above |

Where the asked branch is known from the arguments (the refspec after `:`, or the argument after
`--delete`/`-d`), the printed route carries it; `<owner>/<repo>` is printed as a placeholder
unless `--repository` was given.

`commit`, `tag`, `push` (without a deletion form) and `fetch` keep running as today, under the
same hook and configuration-injection guards. No new verb is added.

A design note proposes which verbs the bot could add later, with the security argument for each:
`.engineering` design artifact `design:bot-verbs`.

## Specification

`ess/` models the signed receipt only; this change adds no entity, field, command or outcome to
the modelled surface (refusal text before a credential is minted). Validated unchanged with ess
0.56.0.

## Acceptance

New tests in `tests/bot_routes.rs`, each failing before the change; they call the argument check
directly and never mint a token:

- `merge_refusal_prints_no_commit_route`: contains `git merge --no-ff --no-commit` and
  `b10x-gates bot -- commit`.
- `pull_refusal_prints_fetch_then_merge`.
- `rebase_refusal_prints_merge_route` (also `cherry-pick`, `am`).
- `push_delete_forms_are_refused_with_api_route`: `push --delete origin x`, `push -d origin x`,
  `push origin :x`, `push --prune origin`, `push --mirror origin` are refused; the first three
  print `/git/refs/heads/x`.
- `supported_verbs_pass_the_check`: `commit -F - -- a`, `tag -a v -m m`, `push origin main`,
  `fetch origin` pass.
- `existing_guards_still_refuse`: `--no-verify`, `-c`, `--exec=…` still refused.

`cargo test --locked`, `cargo fmt --all --check` and `cargo clippy --all-targets --locked -- -D
warnings` pass.

## Scope

- `src/bot_args.rs` (new: the pure argument check and refusal text): planned
- `src/lib.rs` (`pub mod bot_args`): planned
- `src/delivery.rs`: not touched; `Github::git` keeps its own verb guard as a second check
- `src/main.rs` (the `Action::Bot` block: call the check before `Github::bot()`): cited
- `tests/bot_routes.rs` (new)
