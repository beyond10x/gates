---
format: aep.planning-md/3
id: story:api-protection-writes
kind: story
status: active
title: b10x-gates api refuses writes to rulesets and branch protection
summary: Refuse a bot write to a repository's or organization's rulesets or branch protection, through api, gh api and GraphQL, before a token is minted; reads stay.
scope:
- confidence: inferred
  path: CHANGELOG.md
- confidence: inferred
  path: README.md
- confidence: inferred
  path: ess/domains/delivery.yaml
- confidence: inferred
  path: src/delivery.rs
- confidence: inferred
  path: src/main.rs
- confidence: inferred
  path: tests/api_protection_writes.rs
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-10-20T08:08:59Z", actor: "human:timo", revision: 3}
- {from: "proposed", to: "active", at: "2026-10-20T08:10:43Z", actor: "human:timo", revision: 4}
---
## Problem

On 2026-10-20 a session changed the `harness` repository's ruleset 23511241 (required check
"MSRV 1.97" to "MSRV 1.98") through `b10x-gates api` with the bot token,
and the delivery policy admitted it. The bot can therefore loosen the protection that limits the
bot. Source: the draft handed to this repository by the orchestrating session on 2026-10-20.

`b10x-gates api` (`src/main.rs`, `Action::Api`) checks only the path shape
(`delivery::api_path_admitted`: absolute, no `..`, no `#`) and scans the input file for private
rules. It mints the installation token (`Github::bot()`) before `api_response` checks the path.
`b10x-gates gh -- api …` reaches the same endpoints through `gh` with the token in the child
environment, and `POST /graphql` reaches the GraphQL ruleset and branch-protection mutations.

## Proposal

One guard, applied before any token is minted, that refuses a write to a protection surface:

- REST, any method other than GET or HEAD, on
  `/repos/<o>/<r>/rulesets`, `/repos/<o>/<r>/rulesets/<id>` and below,
  `/repos/<o>/<r>/branches/<b>/protection` and below (branch names may contain `/`),
  `/orgs/<o>/rulesets` and below, and the same repository paths under the
  `/repositories/<id>/` alias.
- The path is judged after the normalisation GitHub applies: case of the fixed segments,
  percent-encoding, repeated `/`, a trailing `/`, a query string.
- GraphQL: a request to `/graphql` whose body names `createRepositoryRuleset`,
  `updateRepositoryRuleset`, `deleteRepositoryRuleset`, `createBranchProtectionRule`,
  `updateBranchProtectionRule` or `deleteBranchProtectionRule`.
- `b10x-gates gh -- api …`: any argument, or file an argument names, that carries a protected
  REST path or one of the GraphQL mutation names above is refused whatever the method; reads go
  through `b10x-gates api --method GET`.

The refusal names the path (or the mutation) and says "ruleset and branch protection changes are
the owner's". It is a cause in the existing refusal vocabulary (`gates.delivery.*`).

## Acceptance

- `b10x-gates api` with method PUT, PATCH, POST or DELETE on each REST family above is refused
  before a token is minted, the refusal naming the path and "ruleset and branch protection
  changes are the owner's". A test per method and path family, red before the change. "Before a
  token is minted" is shown by a run with no bot configuration whose error is the refusal.
- GET on the same paths is not refused by the guard (a test reaches the token step).
- A test per normalisation case (case, percent-encoding, `//`, trailing `/`, query string,
  `/repositories/<id>/`) is refused.
- `POST /graphql` with each of the six mutation names in the body is refused; a GraphQL query
  that names none of them is not.
- `b10x-gates gh -- api` naming a protected path, inline or in an `--input` file, is refused.
- Each new test fails when the guard is removed (mutation recorded).
- README and CHANGELOG state the refusal; the ESS delivery domain gains the refusal error.

## Non-goals

- The bot App's `administration` permission. Holding the App key is enough to call the API
  without `b10x-gates`; only the owner can withdraw the permission, outside this repository.
- Repository settings that change which branch a ruleset targets (`PATCH /repos/<o>/<r>`
  default branch, `POST …/branches/<b>/rename`) and environment protection rules.
- Any change to a live ruleset or branch protection.
