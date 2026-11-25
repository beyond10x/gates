---
format: aep.planning-md/3
id: story:api-policy-repository-writes
kind: story
status: draft
title: b10x-gates api, gh api and bot push refuse writes to the policy repository
summary: Refuse every non-GET write whose decoded path names the policy repository (both path forms), every GraphQL mutation naming it or createCommitOnBranch, and a bot push to it; first in the push-range order of work
revision: 1
---
# Story: `api`, `gh -- api` and `bot -- push` refuse writes to the policy repository

## Outcome

No guarded `b10x-gates` verb can change the policy repository:

- `api` and `gh -- api` refuse every request other than GET or HEAD whose decoded path names the
  policy repository, in both path forms (`/repos/<owner>/<name>/…` and `/repositories/<id>/…`);
- they refuse every GraphQL mutation that names the policy repository, by owner and name or by its
  node id, and every `createCommitOnBranch`, whose branch id cannot be bound to a repository without
  a read;
- `bot -- push` refuses a push whose destination is the policy repository.

Reads stay admitted, and writes to every other repository behave as today. The refusal happens
before a token reaches the request, as the protection-write guard does.

First in the order of work of `design:push-range` (revision 3). The first entry on the trusted list
waits for this story; stories 1 and 2 may ship before it only because story 1 does not read the list
and story 2 does nothing while the list is empty.

## Context

The second adversary review of `design:push-range` (section "C2 today") found:

- the `api` verb passes `--path` through with no binding to a repository; its only refusal is
  `protection_write` (`src/protection.rs:40`, `src/main.rs:346-398`);
- `Github::bot()` mints the installation token with an empty body, so it covers every repository of
  the installation (`src/delivery.rs:708-765`);
- the installation includes the policy repository, its contents are readable and its default branch
  is unprotected (bot reads, 2026-11-24). A content write to `policy.json` through `api` passes the
  verb today; it was not sent.

The trusted list of `story:push-range` lives in the policy repository beside `policy.json`, so this
route would let a session put any Gates commit on it.

`readings()` and `protection_prefix()` (`src/protection.rs:665`, `:709`) already decode both path
forms, percent-encoding and case; the new guard reuses them.

**Identifying the policy repository.** Its owner and name come from the GitHub remote of the Git
clone that holds the `--policy` file. A policy file outside such a clone refuses every write through
these verbs. A write through the `/repositories/<id>/` alias is admitted only after a GET of
`/repositories/<id>` resolves it to another repository; a failed resolution refuses. The remote is a
session-writable file, which gives a session nothing beyond the boundary of the design (N4, Q4).

## Acceptance

The tests below are written first and fail on the current code; each guard is then added until they
pass.

- **Failing tests first, `api`:**
  - `PUT /repos/<owner>/<policy>/contents/policy.json` is refused, and no token is minted (the fake
    minter counts zero);
  - the same write through `/repositories/<id>/contents/policy.json` is refused;
  - percent-encoded and mixed-case forms of both paths are refused;
  - `POST`, `PATCH` and `DELETE` on `/repos/<owner>/<policy>/git/refs…` are refused;
  - a write through `/repositories/<id>/…` whose id cannot be resolved is refused;
  - `GET` on the policy repository is admitted;
  - a `PUT` to another repository's contents is admitted, as today.
- **Failing tests first, `gh -- api`:**
  - `-X PUT` and `--method PUT` on the policy repository's contents are refused, in both path forms;
  - `graphql` with a mutation naming `<owner>/<policy>` is refused;
  - `graphql` with a mutation naming the repository's node id is refused, also when the id is only in
    a variable;
  - `graphql` with `createCommitOnBranch` is refused for any branch;
  - a GraphQL query (not a mutation) naming the repository is admitted.
- **Failing tests first, `bot -- push`:**
  - a push whose remote resolves to the policy repository is refused before any token is minted;
  - a push to another repository is admitted, as today.
- **The refusal line** names the verb and "the policy repository", never the repository's name or any
  policy content.
- **Missing identity.** With the `--policy` file outside a Git clone with a GitHub remote, every
  write through the three verbs is refused; reads are admitted.
- **Gates.** Every new guard test fails when its guard is removed, with mutation evidence recorded.
  `cargo test --locked`, `cargo fmt --all --check` and `cargo clippy --all-targets --locked -- -D
  warnings` pass. `README.md` and `CHANGELOG.md` name the new refusal.

## Out of Scope

- Taking the policy repository out of the App's installation (the owner's, Q3).
- Tokens minted with the App key outside the verbs, the signing key, the local policy clone as a
  file, and the owner's `gh` login (the boundary, Q4).
- Branch protection of the policy repository.
