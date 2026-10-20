---
format: aep.planning-md/3
id: runbook:protection-writes-wave
kind: runbook
status: draft
title: 'Wave: the bot cannot write rulesets or branch protection'
relations:
- informed_by: story:api-protection-writes
revision: 4
---
## Wave: the bot cannot write rulesets or branch protection

Stage 1 proposal, sent to the monitoring session `b10x-chef-orchestrator`, which decides for the
operator on this work ("as you wish, you are the orchestrator", 2026-10-20). The wave runs after
its approval; the approval is recorded as an `approval-record` before the first dispatch.
Skill: aep implementing 0.23.2. aep 0.74.0.

Selection: one unit, chosen by the request. `aep plan artifact waves --status proposed` printed:

```
wave 1
  story:api-protection-writes (inferred)
1 wave(s), 0 collision(s), 0 unassessed
```

N is one: the request names one story. The plan-critic panel is skipped: the story derives from
no artifact in this store, so no artifact has two items under it.

Scope beyond the request's draft, taken by the coordinator: the draft names `b10x-gates api`
REST paths only. The story adds `POST /graphql` with a ruleset or branch-protection mutation,
`b10x-gates gh -- api`, and the path spellings GitHub normalises, because each reaches the same
write with the same token.

| unit | story | owns |
|---|---|---|
| 1 | `story:api-protection-writes` | the `Action::Api` and `Action::Gh` blocks of `src/main.rs`, `src/delivery.rs`, `tests/api_protection_writes.rs`, `ess/domains/delivery.yaml` |

`README.md`, `CHANGELOG.md`, `Cargo.toml` and `Cargo.lock` are the coordinator's.

Agents: `aep:implementor` for the unit; `aep:adversary` and `aep:security-reviewer` over the
integrated unit, at most two attack rounds.

Commits this wave makes: the opening store commit, one commit per implementor or review round,
the merge of each into the integration branch, the release-content commit (0.1.22), the closing
store commit, the pull request into `main` and its merge through the bot route. Release 0.1.22
follows the merge through this repository's process: bare annotated tag, musl binary validated
with `scan-artifact`, `SHA256SUMS`, GitHub release by the bot, assets downloaded and verified.
Nothing else.

Pre-flight: `/` 48G free (`df -h /`, 2026-10-20), 1-minute load 69; earlier wave pages measured
about 1.1G per tree. ESS specification `gates v1 — 3 file(s), valid` with ess 0.60.0. The primary
checkout is 113 commits behind `origin/main` and carries another session's uncommitted edits to
`src/git.rs`, `src/published_merge.rs` and `tests/published_merge.rs`; no unit touches it, and
every tree starts from `origin/main`. Builds run one at a time, under a watch that stops a build
below 20G free; no build starts below 25G free.

## Integration

| field | value |
|---|---|
| branch | `wave/ruleset-write-refusal` from `main` `04b0ddb` |
| tree id | `gates-ruleset-writes` |
| build dir | the tree's own `target/` |
| scratch | `~/.cache/gates-wave-ruleset-writes/` |

## Units

| unit | branch | commits | tree id | stage |
|---|---|---|---|---|
| 1 | `impl/api-protection-writes` | `9e9a677` | `gates-unit-protection-writes` | merged `921f617`; tree finished, archived; build 1391 MiB discarded |
| security 1 | `review/protection-writes` | `7581ca3` | `gates-review-protection-writes` | 33 conformance cases; merged with fix 1; tree finished, archived |
| fix 1 | `fix/protection-writes` | `fb1c3c1` | `gates-fix-protection-writes` | merged `bab833e` |
| adversary 1 | `review/protection-writes-adversary` | `3e6985a` | same tree | 12 cases, 8 red; merged with fix 2 |
| fix 2 | `fix/protection-writes-2` | `b40f3a1` | same tree | merged `f4aa077` |
| adversary 2 | `review/protection-writes-adversary-2` | `3df7b72` | same tree | 3 cases, 2 red; merged with fix 3 |
| fix 3 | `fix/protection-writes-3` | `1673aa5` | same tree | merged `0f3ef2d`; tree finished, archived; build 1490 MiB discarded |

Unit 1: 89 cases; claim VERIFIED (`~/.cache/gates-wave-ruleset-writes/unit-1/verify.sh`, no bot
configuration): 0.1.21 reached the token step on PUT and DELETE ruleset/protection paths, POST
org rulesets and `gh -- api -X PATCH`; the unit build refused all five naming the path, and GET
still reached the token step.

Agents, from the harness completion reports:

| agent | dispatches | tokens | tool uses | wall |
|---|---|---|---|---|
| `aep:implementor` (unit, fixes 1–3, resumed) | 1 | 575,621 | 45 in its last round | 1,183 s in its last round; earlier rounds 1,924 s, 3,449 s, 5,623 s |
| `aep:security-reviewer` pass 1 (stopped by a safety classifier, no case) | 1 | 94,529 | 17 | 525 s |
| `aep:security-reviewer` pass 1 retry (fixed table of rows) | 1 | 114,124 | 18 | 506 s |
| `aep:adversary` passes 1 and 2 (resumed) | 1 | 172,265 | 14 in pass 2 | 786 s in pass 2; pass 1 2,255 s |

Two agents stopped once each on HTTP 429 and were resumed with their context.

## Reviews

| pass | findings | outcome |
|---|---|---|
| `review-result:protection-writes-security-1-aborted` | none; stopped before any case | re-dispatched with a fixed table of conformance rows |
| `review-result:protection-writes-security-1-verbatim` | 4: a JSON escape test with its escape decoded by the file-writing tool; `gh api` `Content-Encoding`; mutation names in a `/graphql` query string; the file re-read by `gh` (non-goal) | 3 fixed in `fb1c3c1`, 1 no-op (story non-goal, README states it) |
| `review-result:protection-writes-adversary-1` | 7, no write admitted: 4 over-refusals, file text echoed in a refusal, outcome order, quadratic memory on nested `%25` | all fixed in `b40f3a1` (A3 by aligning the ESS to the refusal) |
| `review-result:protection-writes-adversary-2` | 2, no write admitted: quadratic time on a constructed file, standard-input order | both fixed in `1673aa5`; the coordinator read the diff (no assertion dropped, no reviewer file touched) |

`aep plan artifact findings --from adversary-1 --to adversary-2`: carried 0, new 2, resolved 7.

Two edits to the records, made by the coordinator before the first commit that held them:

- The home directory is written `~` in all four. The closing commit's pre-commit check refused
  the reviewers' absolute home paths (20 findings), and the kind is immutable, so the four
  uncommitted files were removed and re-created under the same ids.
- A first transcription of the security report had two JSON escapes decoded by the file-writing
  tool; it was dropped before any commit, and `-verbatim` holds the report's bytes.

## Gate

Whole gate on `ff9b904` (release content), one exit status per step
(`~/.cache/gates-wave-ruleset-writes/gate.sh`): `cargo test --locked --no-fail-fast` 0
(556 passed, 0 failed, 6 ignored, 30 test binaries), `cargo fmt --all --check` 0,
`cargo clippy --all-targets --locked -- -D warnings` 0, `ess specify validate --path ess` 0
(`gates v1 — 3 file(s), valid`). Compiling steps ran through `b10x-build-slot`. The disk watch
named in the pre-flight was stopped at 08:51 UTC on the monitoring session's instruction.
